import { describe, it, expect, vi } from 'vitest';
import type { ItemType } from '@hvault/shared';
import { resolveImport, type ConflictStrategy } from '../../src/services/import/resolve';

/**
 * `resolveImport`'s optional `alternateOf`: the second identity a row carries once
 * the custom-field limit has cut it.
 *
 * A cut row no longer hashes like the entry it came from, so without a second key
 * a re-import of the same file would duplicate every entry stored in full before
 * the limit existed, and two rows that only became identical through the cut would
 * merge without anyone being told. These tests pin the four promises the import
 * relies on: a row matches on either form, is up to date on either content, the
 * file collapses on the CUT keys with the merges named, and one stored entry never
 * receives two updates. They drive the REAL Web Crypto digest.
 */

// Purity guard, as in resolve.test.ts: the resolver must never pull in the auth store.
vi.mock('../../src/stores/authStore', () => {
  throw new Error('resolve.ts must not import authStore, directly or transitively');
});

type Data = Record<string, unknown>;

interface Inc {
  itemType: ItemType;
  name: string;
  data: Data;
  tags: string[];
  favorite: boolean;
}

interface VaultItem {
  id: string;
  itemType: ItemType;
  name: string;
  data: Data;
}

const inc = (itemType: ItemType, name: string, data: Data, tags: string[] = []): Inc => ({
  itemType,
  name,
  data,
  tags,
  favorite: false,
});

const ex = (id: string, row: Inc): VaultItem => ({
  id,
  itemType: row.itemType,
  name: row.name,
  data: row.data,
});

const field = (name: string, type = 'text'): Data => ({ name, value: `value of ${name}`, type });

const note = (fields: Data[], content = 'body'): Data => ({
  content,
  format: 'plaintext',
  customFields: fields,
});

const login = (password: string, fields: Data[], username = 'octocat'): Data => ({
  username,
  password,
  uris: [{ uri: 'https://github.com', match: 'domain' }],
  customFields: fields,
});

/** The pairing the limiter produces: each cut row mapped to the row it was cut from. */
function pairs(...entries: [cut: Inc, full: Inc][]): (item: Inc) => Inc | undefined {
  const map = new Map(entries);
  return (item) => map.get(item);
}

// A note with three fields, and the same note cut to two with the third moved to
// its content: exactly the shape `limitImportItem` produces.
const FULL_NOTE = inc('note', 'House', note([field('a'), field('b'), field('c')]));
const CUT_NOTE = inc('note', 'House', note([field('a'), field('b')], 'body\n\nc: value of c'));

describe('resolveImport with alternateOf — matching on either form', () => {
  it('skips a cut row whose FULL form the vault already holds', async () => {
    const existing = [ex('e1', FULL_NOTE)];
    const alternateOf = pairs([CUT_NOTE, FULL_NOTE]);

    const r = await resolveImport({
      existing,
      incoming: [CUT_NOTE],
      strategy: 'skip',
      alternateOf,
    });
    expect(r.duplicateSkipped).toEqual([CUT_NOTE]);
    expect(r.inserts).toEqual([]);

    // The control: without the second key the same row is a new entry.
    const without = await resolveImport({ existing, incoming: [CUT_NOTE], strategy: 'skip' });
    expect(without.inserts).toEqual([CUT_NOTE]);
  });

  it('skips a cut row whose CUT form the vault already holds', async () => {
    const r = await resolveImport({
      existing: [ex('e1', CUT_NOTE)],
      incoming: [CUT_NOTE],
      strategy: 'skip',
      alternateOf: pairs([CUT_NOTE, FULL_NOTE]),
    });
    expect(r.duplicateSkipped).toEqual([CUT_NOTE]);
    expect(r.inserts).toEqual([]);
  });

  it('reports overwrite as already up to date when EITHER content is stored', async () => {
    for (const stored of [FULL_NOTE, CUT_NOTE]) {
      const r = await resolveImport({
        existing: [ex('e1', stored)],
        incoming: [CUT_NOTE],
        strategy: 'overwrite',
        alternateOf: pairs([CUT_NOTE, FULL_NOTE]),
      });
      expect(r.unchanged).toEqual([CUT_NOTE]);
      expect(r.updates).toEqual([]);
      expect(r.inserts).toEqual([]);
    }
  });

  it('updates a login matched by host and username only when it differs from BOTH forms', async () => {
    const full = inc('login', 'GitHub', login('pw', [field('a'), field('b'), field('c')]));
    const cut = inc('login', 'GitHub', { ...login('pw', [field('a'), field('b')]), notes: 'c' });
    const alternateOf = pairs([cut, full]);

    const same = await resolveImport({
      existing: [ex('e1', full)],
      incoming: [cut],
      strategy: 'overwrite',
      alternateOf,
    });
    expect(same.unchanged).toEqual([cut]);
    expect(same.updates).toEqual([]);

    const storedOld = inc('login', 'GitHub', login('old-pw', [field('a')]));
    const changed = await resolveImport({
      existing: [ex('e1', storedOld)],
      incoming: [cut],
      strategy: 'overwrite',
      alternateOf,
    });
    // The update carries the CUT row; widening it to the stored entry's own field
    // count is `prepareLimitedUpdates`' job, not the resolver's.
    expect(changed.updates.map((u) => [u.existing.id, u.incoming])).toEqual([['e1', cut]]);
    expect(changed.unchanged).toEqual([]);
    expect(changed.inserts).toEqual([]);
  });

  it('inserts a cut row that matches neither form', async () => {
    const r = await resolveImport({
      existing: [ex('e1', inc('note', 'Other', note([field('z')])))],
      incoming: [CUT_NOTE],
      strategy: 'overwrite',
      alternateOf: pairs([CUT_NOTE, FULL_NOTE]),
    });
    expect(r.inserts).toEqual([CUT_NOTE]);
    expect(r.unchanged).toEqual([]);
  });
});

describe('resolveImport with alternateOf — rows merged by the cut', () => {
  // Two rows that differ only in a HIDDEN field past the limit: the hidden field is
  // dropped by the cut, so their cut forms are identical and they collapse.
  const fullA = inc('note', 'Twin', note([field('a'), field('pin-a', 'hidden')]), ['first']);
  const fullB = inc('note', 'Twin', note([field('a'), field('pin-b', 'hidden')]), ['last']);
  const cutA = inc('note', 'Twin', note([field('a')], 'body\n\n1 hidden'), ['first']);
  const cutB = inc('note', 'Twin', note([field('a')], 'body\n\n1 hidden'), ['last']);
  const alternateOf = pairs([cutA, fullA], [cutB, fullB]);

  it('collapses them on the cut keys and names the merge (skip keeps the first)', async () => {
    const r = await resolveImport({
      existing: [],
      incoming: [cutA, cutB],
      strategy: 'skip',
      alternateOf,
    });
    expect(r.inserts).toEqual([cutA]);
    expect(r.duplicateInFile).toEqual([cutB]);
    expect(r.mergedByLimit).toEqual([{ kept: cutA, absorbed: cutB }]);
  });

  it('names the merge the other way round under overwrite, which keeps the last', async () => {
    const r = await resolveImport({
      existing: [],
      incoming: [cutA, cutB],
      strategy: 'overwrite',
      alternateOf,
    });
    expect(r.inserts).toEqual([cutB]);
    expect(r.duplicateInFile).toEqual([cutA]);
    expect(r.mergedByLimit).toEqual([{ kept: cutB, absorbed: cutA }]);
  });

  it('does not report a true duplicate, identical before the cut too, as a merge', async () => {
    const twinOfA = inc('note', 'Twin', note([field('a')], 'body\n\n1 hidden'), ['first']);
    const r = await resolveImport({
      existing: [],
      incoming: [cutA, twinOfA],
      strategy: 'skip',
      alternateOf: pairs([cutA, fullA], [twinOfA, fullA]),
    });
    expect(r.duplicateInFile).toEqual([twinOfA]);
    expect(r.mergedByLimit).toEqual([]);
  });

  it('does not report two uncut duplicates as a merge either', async () => {
    const plain = inc('note', 'Plain', note([field('a')]));
    const plainTwin = inc('note', 'Plain', note([field('a')]));
    const r = await resolveImport({
      existing: [],
      incoming: [plain, plainTwin],
      strategy: 'skip',
      alternateOf: () => undefined,
    });
    expect(r.duplicateInFile).toEqual([plainTwin]);
    expect(r.mergedByLimit).toEqual([]);
  });

  it('reports an empty merge list under keep_both, which never collapses', async () => {
    const r = await resolveImport({
      existing: [],
      incoming: [cutA, cutB],
      strategy: 'keep_both',
      alternateOf,
    });
    expect(r.inserts).toEqual([cutA, cutB]);
    expect(r.mergedByLimit).toEqual([]);
  });
});

describe('resolveImport with alternateOf — one stored entry, one update', () => {
  it('gives the slot to the LAST row reaching an entry, whichever key it reached it by', async () => {
    // A row reaching the stored login by its own key, and a later row reaching the
    // SAME login only through its alternate. The limiter never pairs rows this way
    // (a cut keeps a login's host and username), but the resolver must hold the
    // invariant on its own: were the slot keyed by each row's own identity, both
    // rows would win one and the stored entry would be overwritten twice.
    const stored = inc('login', 'GitHub', login('stored-pw', []));
    const direct = inc('login', 'Direct', login('direct-pw', []));
    const viaAlternate = inc('login', 'Via alternate', login('other-pw', [], 'someone-else'));
    const alternate = inc('login', 'Via alternate', login('alternate-pw', []));

    const r = await resolveImport({
      existing: [ex('e1', stored)],
      incoming: [direct, viaAlternate],
      strategy: 'overwrite',
      alternateOf: pairs([viaAlternate, alternate]),
    });
    expect(r.updates.map((u) => [u.existing.id, u.incoming.name])).toEqual([
      ['e1', 'Via alternate'],
    ]);
    expect(r.inserts).toEqual([direct]);
    expect(r.unchanged).toEqual([]);
  });
});

describe('resolveImport without alternateOf', () => {
  it('carries no mergedByLimit key at all', async () => {
    for (const strategy of ['skip', 'overwrite', 'keep_both'] satisfies ConflictStrategy[]) {
      const r = await resolveImport({ existing: [], incoming: [CUT_NOTE], strategy });
      expect('mergedByLimit' in r).toBe(false);
      expect(r.inserts).toEqual([CUT_NOTE]);
    }
  });
});
