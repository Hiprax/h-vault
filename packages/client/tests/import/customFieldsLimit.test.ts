// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import {
  MAX_NOTE_CONTENT_LENGTH,
  MAX_SECRET_DESCRIPTION_LENGTH,
  deriveRowId,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { buildImportOperations, validateImportItems } from '../../src/services/import';
import type { ResolvableImportItem } from '../../src/services/import';
import { buildNote } from '../../src/services/import/itemBuilders';
import { resolveImport } from '../../src/services/import/resolve';
import { decryptVaultField } from '../../src/services/crypto/vaultField';
import {
  limitImportItem,
  limitImportItems,
  prepareLimitedUpdates,
  summariseLimitReports,
  type LimitReport,
} from '../../src/services/import/customFieldsLimit';

/**
 * The custom-field limit on import (`CUSTOM_FIELDS_LIMIT`).
 *
 * What it owes the user, each pinned below: a row within the limit is untouched
 * (a native one sealed byte for byte); a row over it keeps its first fields and
 * writes the rest into its free text, as far as that text's bound allows; a hidden
 * value is never written anywhere, only its name; every cut is reported, by name;
 * and an overwrite never shrinks a stored entry below the fields it already has.
 */

interface Field {
  name: string;
  value: string;
  type: string;
}

const text = (name: string, value = `value of ${name}`): Field => ({ name, value, type: 'text' });
const flag = (name: string, value = 'true'): Field => ({ name, value, type: 'boolean' });
const hidden = (name: string, value: string): Field => ({ name, value, type: 'hidden' });

/** A value no other input here contains, so finding it anywhere proves a leak. */
const secretValue = (label: string): string => `\uE000${label}\uE001`;

const heading = (cap: number): string => `Custom fields beyond the import limit of ${String(cap)}:`;

function row(
  itemType: ItemType,
  data: Record<string, unknown>,
  extra: Partial<ResolvableImportItem> = {},
): ResolvableImportItem {
  return { itemType, name: 'Row', data, tags: ['tag'], favorite: true, ...extra };
}

const fieldsNamed = (prefix: string, count: number): Field[] =>
  Array.from({ length: count }, (_, i) => text(`${prefix}${String(i)}`));

describe('limitImportItem — a row within the limit', () => {
  it('is returned as the same object, with no untrimmed copy and no report, at exactly the limit', () => {
    const item = row('login', { username: 'u', customFields: [text('a'), text('b')] });
    const result = limitImportItem(item, 2);
    expect(result.item).toBe(item);
    expect('untrimmed' in result).toBe(false);
    expect(result.report).toBeNull();
    expect(item.data.customFields).toEqual([text('a'), text('b')]);
  });

  it('keeps a native row’s stored data string, so it is still sealed byte for byte', () => {
    const native = { dataJson: '{"content":"c","customFields":[]}' };
    const item = row('note', { content: 'c', customFields: [] }, { native });
    const result = limitImportItem(item, 1);
    expect(result.item).toBe(item);
    expect(result.item.native).toBe(native);
  });

  it('leaves a row with no custom-field list alone, whatever its type', () => {
    for (const data of [{ content: 'c' }, { _raw: 'undecodable' }, { customFields: 'nope' }]) {
      const item = row('note', data);
      expect(limitImportItem(item, 1)).toEqual({ item, report: null });
      expect(limitImportItem(item, 1).item).toBe(item);
    }
  });

  it('still reports what the parser’s own clamp cut, without changing the row', () => {
    const item = row(
      'login',
      { customFields: [text('a')] },
      { importNotices: { hiddenDropped: ['PIN'], movedToNotes: ['Long'] } },
    );
    const result = limitImportItem(item, 5);
    expect(result.item).toBe(item);
    expect(result.report).toEqual({
      itemName: 'Row',
      itemType: 'login',
      movedToNotes: ['Long'],
      hiddenDropped: ['PIN'],
      notWritten: [],
    });
  });
});

describe('limitImportItem — a row over the limit, per type', () => {
  it('moves a login’s text and boolean overflow into its notes under a heading', () => {
    const fields = [text('a'), text('b'), text('c'), flag('d')];
    const item = row('login', {
      username: 'u',
      password: 'p',
      notes: '  login note \n',
      customFields: fields,
    });

    const result = limitImportItem(item, 2);

    expect(result.item.data).toEqual({
      username: 'u',
      password: 'p',
      notes: `login note\n\n${heading(2)}\nc: value of c\nd: true`,
      customFields: [text('a'), text('b')],
    });
    expect(result.report).toEqual({
      itemName: 'Row',
      itemType: 'login',
      movedToNotes: ['c', 'd'],
      hiddenDropped: [],
      notWritten: [],
    });
    expect(result.untrimmed).toBe(item);
    // The original is not touched: it is what resolution matches the full form by.
    expect(item.data.customFields).toBe(fields);
    expect(item.data.notes).toBe('  login note \n');
  });

  it('writes a note’s overflow into its content, keeping its format', () => {
    const item = row('note', {
      content: 'body',
      format: 'markdown',
      customFields: [text('a'), text('b')],
    });
    const result = limitImportItem(item, 1);
    expect(result.item.data).toEqual({
      content: `body\n\n${heading(1)}\nb: value of b`,
      format: 'markdown',
      customFields: [text('a')],
    });
  });

  it('writes a secret’s overflow into its description, creating one when it had none', () => {
    const item = row('secret', { value: 's3cret', customFields: [text('a'), text('b')] });
    const result = limitImportItem(item, 1);
    expect(result.item.data).toEqual({
      value: 's3cret',
      description: `${heading(1)}\nb: value of b`,
      customFields: [text('a')],
    });
  });

  it.each(['card', 'identity'] as const)('writes a %s’s overflow into its notes', (itemType) => {
    const result = limitImportItem(row(itemType, { customFields: [text('a'), text('b')] }), 1);
    expect(result.item.data.notes).toBe(`${heading(1)}\nb: value of b`);
    expect(result.item.data.customFields).toEqual([text('a')]);
    expect(result.report?.itemType).toBe(itemType);
  });

  it('keeps the row’s identity and placement, and drops nothing else', () => {
    const item = row(
      'login',
      { customFields: [text('a'), text('b')] },
      {
        name: 'Placed',
        tags: ['work', 'mail'],
        favorite: true,
        folderId: '507f1f77bcf86cd799439011',
        previousPasswords: [{ password: 'old', changedAt: '2026-01-02T03:04:05.000Z' }],
      },
    );
    const { item: cut } = limitImportItem(item, 1);
    expect(cut).toEqual({
      itemType: 'login',
      name: 'Placed',
      data: { customFields: [text('a')], notes: `${heading(1)}\nb: value of b` },
      tags: ['work', 'mail'],
      favorite: true,
      folderId: '507f1f77bcf86cd799439011',
      previousPasswords: [{ password: 'old', changedAt: '2026-01-02T03:04:05.000Z' }],
    });
  });

  it('carries no folder or history key on a cut row whose original had none', () => {
    const { item: cut } = limitImportItem(row('note', { customFields: [text('a'), text('b')] }), 1);
    expect('folderId' in cut).toBe(false);
    expect('previousPasswords' in cut).toBe(false);
    expect('importNotices' in cut).toBe(false);
  });
});

describe('limitImportItem — hidden fields', () => {
  it('drops a hidden field past the limit, names it, and writes its value nowhere', () => {
    const item = row('login', {
      notes: 'base',
      customFields: [
        text('a'),
        hidden('PIN', secretValue('pin')),
        text('b'),
        hidden('API key', secretValue('api')),
      ],
    });

    const result = limitImportItem(item, 1);

    expect(result.item.data.notes).toBe(
      `base\n\n${heading(1)}\nb: value of b\n\n` +
        '2 hidden custom field(s) were not imported: PIN, API key',
    );
    expect(result.report).toEqual({
      itemName: 'Row',
      itemType: 'login',
      movedToNotes: ['b'],
      hiddenDropped: ['PIN', 'API key'],
      notWritten: [],
    });
    expect(JSON.stringify(result.item)).not.toContain('\uE000');
    expect(JSON.stringify(result.report)).not.toContain('\uE000');
  });

  it('keeps a hidden field WITHIN the limit as a hidden field', () => {
    const result = limitImportItem(
      row('note', { content: '', customFields: [hidden('PIN', '1234'), text('b')] }),
      1,
    );
    expect(result.item.data.customFields).toEqual([hidden('PIN', '1234')]);
    expect(result.item.data.content).toBe(`${heading(1)}\nb: value of b`);
  });

  it('writes only the names-only line when every field past the limit is hidden', () => {
    const result = limitImportItem(
      row('card', { notes: 'n', customFields: [text('a'), hidden('PIN', secretValue('x'))] }),
      1,
    );
    expect(result.item.data.notes).toBe('n\n\n1 hidden custom field(s) were not imported: PIN');
    expect(result.report?.movedToNotes).toEqual([]);
  });

  it('treats an entry it cannot read, or a type it does not know, as hidden', () => {
    // A native row's data is not validated again before the limit runs.
    const item = row('login', {
      customFields: [
        text('a'),
        null,
        { name: 7, value: 9, type: 'text' },
        { name: 'Future', value: secretValue('future'), type: 'one-time-code' },
      ],
    });
    const result = limitImportItem(item, 1);
    expect(result.report?.hiddenDropped).toEqual(['', 'Future']);
    // The numeric name and value are not strings, so the line carries neither.
    expect(result.report?.movedToNotes).toEqual(['']);
    expect(JSON.stringify(result.item)).not.toContain('\uE000');
  });
});

describe('limitImportItem — the free text’s own bound', () => {
  const smallLine = 'small: v';
  // A note's content filled so the heading and `smallLine` fit EXACTLY.
  const fillTo = (room: number): string =>
    'n'.repeat(MAX_NOTE_CONTENT_LENGTH - '\n\n'.length - heading(1).length - 1 - room);

  it('writes the lines that fit, names the ones that do not, and keeps trying after a miss', () => {
    const content = fillTo(smallLine.length);
    const item = row('note', {
      content,
      customFields: [text('kept'), text('big', 'x'.repeat(100)), text('small', 'v')],
    });

    const result = limitImportItem(item, 1);

    const written = String(result.item.data.content);
    expect(written).toBe(`${content}\n\n${heading(1)}\n${smallLine}`);
    expect(written).toHaveLength(MAX_NOTE_CONTENT_LENGTH);
    expect(result.report?.movedToNotes).toEqual(['small']);
    expect(result.report?.notWritten).toEqual(['big']);
    expect(written).not.toContain('x'.repeat(100));
  });

  it('leaves the text byte-for-byte as it was when not even one character more fits', () => {
    const content = `${fillTo(smallLine.length)}n`;
    const item = row('note', { content, customFields: [text('kept'), text('small', 'v')] });

    const result = limitImportItem(item, 1);

    expect(result.item.data.content).toBe(content);
    expect(result.item.data.customFields).toEqual([text('kept')]);
    expect(result.report?.notWritten).toEqual(['small']);
    expect(result.report?.movedToNotes).toEqual([]);
  });

  it('bounds a secret’s description by its own, smaller cap', () => {
    const description = 'd'.repeat(MAX_SECRET_DESCRIPTION_LENGTH - 10);
    const item = row('secret', {
      description,
      customFields: [text('kept'), text('extra', 'e'.repeat(20))],
    });
    const result = limitImportItem(item, 1);
    expect(result.item.data.description).toBe(description);
    expect(result.report?.notWritten).toEqual(['extra']);
  });

  it('omits the hidden-name line when it alone does not fit, and still reports the field', () => {
    const content = fillTo(smallLine.length);
    const item = row('note', {
      content,
      customFields: [text('kept'), text('small', 'v'), hidden('PIN', secretValue('pin'))],
    });

    const result = limitImportItem(item, 1);

    expect(result.item.data.content).toBe(`${content}\n\n${heading(1)}\n${smallLine}`);
    expect(String(result.item.data.content)).not.toContain('hidden custom field');
    expect(result.report?.hiddenDropped).toEqual(['PIN']);
  });
});

describe('limitImportItem — a parser notice and a cut on one row', () => {
  it('reports the parser’s names first, then the limit’s', () => {
    const item = row(
      'login',
      { customFields: [text('a'), text('b'), hidden('PIN', secretValue('pin'))] },
      { importNotices: { hiddenDropped: ['Too long'], movedToNotes: ['Truncated'] } },
    );
    const result = limitImportItem(item, 1);
    expect(result.report).toEqual({
      itemName: 'Row',
      itemType: 'login',
      movedToNotes: ['Truncated', 'b'],
      hiddenDropped: ['Too long', 'PIN'],
      notWritten: [],
    });
  });
});

describe('limitImportItem — sealing a cut native row', () => {
  const USER_ID = '64b7f0c2a1d3e4f5a6b7c8d9';
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
  });

  async function sealedData(item: ResolvableImportItem): Promise<string> {
    const { inserts, failedCount } = await buildImportOperations({
      inserts: [item],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(failedCount).toBe(0);
    const [insert] = inserts;
    if (insert?.idNonce === undefined) throw new Error('no insert was built');
    const rowId = await deriveRowId(USER_ID, insert.idNonce);
    return decryptVaultField(
      { encrypted: insert.encryptedData, iv: insert.dataIv, tag: insert.dataTag },
      { role: 'item.data', rowId, itemType: item.itemType },
      vaultKey,
    );
  }

  // A stored note as a NEWER release might have written it: an extra key this
  // release does not know, and keys in an order a re-serialisation would change.
  const data = {
    format: 'plaintext',
    content: 'c',
    customFields: [text('a'), text('b')],
    fromTheFuture: true,
  };
  const dataJson = JSON.stringify(data);

  it('seals an UNCUT native row from its stored string, byte for byte', async () => {
    const item = row('note', data, { native: { dataJson } });
    const { item: limited } = limitImportItem(item, 2);
    expect(await sealedData(limited)).toBe(dataJson);
  });

  it('seals a CUT native row from its validated data, keeping its folder and history', async () => {
    const item = row('note', data, {
      native: { dataJson },
      folderId: '507f1f77bcf86cd799439011',
      previousPasswords: [{ password: 'old', changedAt: '2026-01-02T03:04:05.000Z' }],
    });

    const { item: cut } = limitImportItem(item, 1);
    expect('native' in cut).toBe(false);

    const sealed = JSON.parse(await sealedData(cut)) as Record<string, unknown>;
    expect(sealed).toEqual({
      format: 'plaintext',
      content: `c\n\n${heading(1)}\nb: value of b`,
      customFields: [text('a')],
    });
    const { inserts } = await buildImportOperations({
      inserts: [cut],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(inserts[0]?.folderId).toBe('507f1f77bcf86cd799439011');
    expect(inserts[0]?.passwordHistory).toHaveLength(1);
  });

  it('never puts a parser notice on the wire or into the sealed data', async () => {
    const item = row(
      'note',
      { content: 'c' },
      { importNotices: { hiddenDropped: ['notice-only-name'], movedToNotes: ['moved-name'] } },
    );
    const { inserts } = await buildImportOperations({
      inserts: [item],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(JSON.stringify(inserts)).not.toMatch(/importNotices|notice-only-name|moved-name/);
    expect(await sealedData(item)).toBe('{"content":"c","format":"markdown"}');
  });
});

describe('limitImportItems', () => {
  it('cuts each row and answers the two lookups resolution and reporting need', () => {
    const within = row('note', { content: 'w', customFields: [text('a')] }, { name: 'Within' });
    const over = row(
      'note',
      { content: 'o', customFields: [text('a'), text('b')] },
      { name: 'Over' },
    );
    const noticed = row(
      'note',
      { content: 'n', customFields: [] },
      { name: 'Noticed', importNotices: { hiddenDropped: ['X'], movedToNotes: [] } },
    );

    const limited = limitImportItems([within, over, noticed], 1);

    expect(limited.items).toHaveLength(3);
    expect(limited.items[0]).toBe(within);
    expect(limited.items[2]).toBe(noticed);
    const cut = limited.items[1]!;
    expect(cut).not.toBe(over);
    expect(limited.untrimmedOf(cut)).toBe(over);
    expect(limited.untrimmedOf(within)).toBeUndefined();
    expect(limited.untrimmedOf(over)).toBeUndefined();
    expect(limited.reportOf(cut)?.movedToNotes).toEqual(['b']);
    expect(limited.reportOf(noticed)?.hiddenDropped).toEqual(['X']);
    expect(limited.reportOf(within)).toBeNull();
  });
});

describe('prepareLimitedUpdates — the limit never shrinks a stored entry', () => {
  const existing = (count: number | undefined) => ({
    id: 'e1',
    itemType: 'note' as const,
    name: 'Row',
    data:
      count === undefined
        ? { content: 'c' }
        : { content: 'c', customFields: fieldsNamed('s', count) },
  });

  it('re-cuts from the full row at the stored entry’s own field count when that is larger', () => {
    const full = row('note', { content: 'c', customFields: fieldsNamed('f', 45) });
    const limited = limitImportItems([full], 30);
    const target = existing(40);

    const { updates, reports } = prepareLimitedUpdates(
      [{ incoming: limited.items[0]!, existing: target }],
      30,
      limited.untrimmedOf,
    );

    expect(updates).toHaveLength(1);
    expect(updates[0]!.existing).toBe(target);
    expect(updates[0]!.incoming.data.customFields).toEqual(fieldsNamed('f', 40));
    expect(reports).toEqual([
      {
        itemName: 'Row',
        itemType: 'note',
        movedToNotes: ['f40', 'f41', 'f42', 'f43', 'f44'],
        hiddenDropped: [],
        notWritten: [],
      },
    ]);
  });

  it('writes the full row, native content and all, when it fits under the stored count', () => {
    const native = { dataJson: '{"content":"c"}' };
    const full = row('note', { content: 'c', customFields: fieldsNamed('f', 35) }, { native });
    const limited = limitImportItems([full], 30);

    const { updates, reports } = prepareLimitedUpdates(
      [{ incoming: limited.items[0]!, existing: existing(40) }],
      30,
      limited.untrimmedOf,
    );

    expect(updates[0]!.incoming).toBe(full);
    expect(updates[0]!.incoming.native).toBe(native);
    expect(reports).toEqual([]);
  });

  it('cuts at the limit when the stored entry has fewer fields, or none', () => {
    for (const stored of [undefined, 3]) {
      const full = row('note', { content: 'c', customFields: fieldsNamed('f', 35) });
      const limited = limitImportItems([full], 30);
      const { updates, reports } = prepareLimitedUpdates(
        [{ incoming: limited.items[0]!, existing: existing(stored) }],
        30,
        limited.untrimmedOf,
      );
      expect(updates[0]!.incoming.data.customFields).toEqual(fieldsNamed('f', 30));
      expect(updates[0]!.incoming).toEqual(limited.items[0]);
      expect(reports[0]?.movedToNotes).toHaveLength(5);
    }
  });

  it('passes an update the limit never cut through as it is, reporting only a parser notice', () => {
    const plain = row('note', { content: 'p', customFields: [text('a')] });
    const noticed = row(
      'note',
      { content: 'n' },
      { importNotices: { hiddenDropped: ['PIN'], movedToNotes: [] } },
    );

    const { updates, reports } = prepareLimitedUpdates(
      [
        { incoming: plain, existing: existing(undefined) },
        { incoming: noticed, existing: existing(undefined) },
      ],
      1,
      () => undefined,
    );

    expect(updates.map((u) => u.incoming)).toEqual([plain, noticed]);
    expect(updates[0]!.incoming).toBe(plain);
    expect(reports.map((r) => r.hiddenDropped)).toEqual([['PIN']]);
  });
});

describe('summariseLimitReports', () => {
  const report = (itemName: string, over: Partial<LimitReport> = {}): LimitReport => ({
    itemName,
    itemType: 'login',
    movedToNotes: [],
    hiddenDropped: [],
    notWritten: [],
    ...over,
  });

  it('counts every row and every field, but lists only the first entries and names', () => {
    const reports = [
      report('A', { movedToNotes: ['a1', 'a2', 'a3'], hiddenDropped: ['ah'] }),
      null,
      report('B', { notWritten: ['b1'] }),
      report('C', { movedToNotes: ['c1'], hiddenDropped: ['ch1', 'ch2'] }),
    ];

    const summary = summariseLimitReports(reports, {
      merges: [],
      reportOf: () => null,
      maxEntries: 2,
      maxNames: 2,
    });

    expect(summary).toEqual({
      rowCount: 3,
      movedToNotesCount: 4,
      hiddenDroppedCount: 3,
      notWrittenCount: 1,
      mergedCount: 0,
      entries: [
        {
          itemName: 'A',
          itemType: 'login',
          movedToNotes: { names: ['a1', 'a2'], more: 1 },
          hiddenDropped: { names: ['ah'], more: 0 },
          notWritten: { names: [], more: 0 },
        },
        {
          itemName: 'B',
          itemType: 'login',
          movedToNotes: { names: [], more: 0 },
          hiddenDropped: { names: [], more: 0 },
          notWritten: { names: ['b1'], more: 0 },
        },
      ],
      merged: [],
    });
  });

  it('names each row merged by the cut, with what only it held, bounded like the rest', () => {
    const kept = row('note', {}, { name: 'Kept' });
    const absorbed = row('note', {}, { name: 'Absorbed' });
    const unreported = row('note', {}, { name: 'Unreported' });
    const third = row('note', {}, { name: 'Third' });
    const absorbedReport = report('Absorbed', {
      itemType: 'note',
      hiddenDropped: ['h1', 'h2', 'h3'],
      notWritten: ['n1'],
    });

    const summary = summariseLimitReports([], {
      merges: [
        { kept, absorbed },
        { kept, absorbed: unreported },
        { kept, absorbed: third },
      ],
      reportOf: (item) => (item === absorbed ? absorbedReport : null),
      maxEntries: 2,
      maxNames: 2,
    });

    expect(summary.rowCount).toBe(0);
    expect(summary.mergedCount).toBe(3);
    expect(summary.merged).toEqual([
      {
        itemName: 'Absorbed',
        itemType: 'note',
        keptName: 'Kept',
        hiddenDropped: { names: ['h1', 'h2'], more: 1 },
        notWritten: { names: ['n1'], more: 0 },
      },
      {
        itemName: 'Unreported',
        itemType: 'note',
        keptName: 'Kept',
        hiddenDropped: { names: [], more: 0 },
        notWritten: { names: [], more: 0 },
      },
    ]);
  });
});

describe('the limit and resolution together: a re-import never duplicates', () => {
  // A note with 35 fields, five of them hidden, imported at a limit of 30, the
  // way the import page runs it: validate, limit, then resolve.
  const sourceFields = [
    ...fieldsNamed('f', 30),
    hidden('PIN', '1111'),
    text('extra'),
    hidden('Alarm', '2222'),
    flag('pets'),
    hidden('Safe', '3333'),
  ];
  const parsed = (): ResolvableImportItem => {
    const [validated] = validateImportItems([
      buildNote({ name: 'House', content: 'body', customFields: sourceFields }),
    ]).items;
    if (!validated) throw new Error('the note did not validate');
    return validated;
  };

  it.each([
    ['in full, as stored before the limit existed', 'full'],
    ['cut, as an earlier import at this limit stored it', 'cut'],
  ] as const)('matches the entry stored %s, under skip and overwrite', async (_label, form) => {
    const full = parsed();
    const limited = limitImportItems([full], 30);
    const stored = form === 'full' ? full : limited.items[0]!;
    const existing = [
      { id: 'e1', itemType: stored.itemType, name: stored.name, data: stored.data },
    ];

    const skip = await resolveImport({
      existing,
      incoming: limited.items,
      strategy: 'skip',
      alternateOf: limited.untrimmedOf,
    });
    expect(skip.duplicateSkipped).toEqual(limited.items);
    expect(skip.inserts).toEqual([]);

    const overwrite = await resolveImport({
      existing,
      incoming: limited.items,
      strategy: 'overwrite',
      alternateOf: limited.untrimmedOf,
    });
    expect(overwrite.unchanged).toEqual(limited.items);
    expect(overwrite.inserts).toEqual([]);
    expect(overwrite.updates).toEqual([]);
  });

  it('collapses two rows differing only in hidden fields past the limit, and says so', async () => {
    const twin = (pin: string): ResolvableImportItem => {
      const [validated] = validateImportItems([
        buildNote({
          name: 'Twin',
          content: 'body',
          customFields: [...fieldsNamed('f', 30), hidden('PIN', pin)],
        }),
      ]).items;
      if (!validated) throw new Error('the note did not validate');
      return validated;
    };
    const limited = limitImportItems([twin('1111'), twin('2222')], 30);

    const resolution = await resolveImport({
      existing: [],
      incoming: limited.items,
      strategy: 'skip',
      alternateOf: limited.untrimmedOf,
    });
    expect(resolution.inserts).toEqual([limited.items[0]]);
    expect(resolution.duplicateInFile).toEqual([limited.items[1]]);

    const summary = summariseLimitReports(resolution.inserts.map(limited.reportOf), {
      merges: resolution.mergedByLimit ?? [],
      reportOf: limited.reportOf,
      maxEntries: 10,
      maxNames: 10,
    });
    expect(summary.rowCount).toBe(1);
    expect(summary.merged).toEqual([
      {
        itemName: 'Twin',
        itemType: 'note',
        keptName: 'Twin',
        hiddenDropped: { names: ['PIN'], more: 0 },
        notWritten: { names: [], more: 0 },
      },
    ]);
    expect(JSON.stringify(summary)).not.toMatch(/1111|2222/);
  });
});
