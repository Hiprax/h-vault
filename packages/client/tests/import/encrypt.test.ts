// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import {
  MAX_IMPORT_WARNINGS,
  buildImportOperations,
  parseImportData,
  validateImportItems,
} from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';
import { cryptoService } from '../../src/services/crypto/cryptoService';

let vaultKey: CryptoKey;

beforeAll(async () => {
  vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
});

describe('buildImportOperations — validate + encrypt', () => {
  it('encrypts valid items (all six ciphertext fields + searchHash) and round-trips', async () => {
    const parsed: ParsedImportItem[] = [
      {
        itemType: 'login',
        name: 'GitHub',
        data: {
          username: 'octocat',
          password: 'hunter2',
          uris: [{ uri: 'https://github.com', match: 'domain' }],
        },
        tags: ['Work'],
        favorite: true,
      },
    ];
    const { inserts: items, failedCount: skipped } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    for (const f of [
      'encryptedName',
      'nameIv',
      'nameTag',
      'encryptedData',
      'dataIv',
      'dataTag',
    ] as const) {
      expect(item[f].length).toBeGreaterThan(0);
    }
    expect(item.searchHash).toMatch(/^[a-f0-9]{64}$/);
    expect(item.tags).toEqual(['Work']);
    expect(item.favorite).toBe(true);

    const name = await cryptoService.decryptData(
      item.encryptedName,
      item.nameIv,
      item.nameTag,
      vaultKey,
    );
    expect(name).toBe('GitHub');
    const data = JSON.parse(
      await cryptoService.decryptData(item.encryptedData, item.dataIv, item.dataTag, vaultKey),
    ) as { username: string; uris: { uri: string }[] };
    expect(data.username).toBe('octocat');
    expect(data.uris[0]?.uri).toBe('https://github.com');
  });

  it('skips items whose data fails schema validation and counts them', async () => {
    const parsed: ParsedImportItem[] = [
      { itemType: 'login', name: 'ok', data: { username: 'a' }, tags: [], favorite: false },
      {
        itemType: 'login',
        name: 'bad',
        data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] },
        tags: [],
        favorite: false,
      },
    ];
    const {
      inserts: items,
      failedCount: skipped,
      failureReasons: warnings,
    } = await buildImportOperations({ inserts: parsed, updates: [], vaultKey });
    expect(items).toHaveLength(1);
    expect(skipped).toBe(1);
    expect(warnings).toHaveLength(1);
  });

  it('validateImportItems keeps the transformed data and caps its warning list', () => {
    // The parse-time counterpart of the seal-time cap. Its warnings are spread
    // UNBOUNDED into the import report, so this bound is the only thing keeping
    // a wholly invalid file from building an enormous toast description.
    const good = (i: number): ParsedImportItem => ({
      itemType: 'login',
      name: `ok-${String(i)}`,
      // Deliberately raw: the survivor's data must come back schema-TRANSFORMED
      // (bare domain normalized, defaults filled), which is what makes a
      // re-import of the same file hash identically and stay a no-op.
      data: { username: 'a', uris: [{ uri: 'github.com', match: 'domain' }] },
      tags: [],
      favorite: false,
    });
    const bad = (i: number): ParsedImportItem => ({
      itemType: 'login',
      name: `bad-${String(i)}`,
      data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] },
      tags: [],
      favorite: false,
    });

    const result = validateImportItems([
      good(0),
      ...Array.from({ length: MAX_IMPORT_WARNINGS + 2 }, (_, i) => bad(i)),
    ]);

    expect(result.items).toHaveLength(1);
    expect(result.items[0]?.data).toMatchObject({
      username: 'a',
      uris: [{ uri: 'https://github.com', match: 'domain' }],
    });
    expect(result.skipped).toBe(MAX_IMPORT_WARNINGS + 2);
    expect(result.warnings).toHaveLength(MAX_IMPORT_WARNINGS);
  });

  it('skips an item whose data is not an object at all (root-level validation error)', async () => {
    const parsed = [
      {
        itemType: 'login' as const,
        name: 'bad',
        data: 'i-am-a-string' as unknown as Record<string, unknown>,
        tags: [],
        favorite: false,
      },
    ];
    const {
      inserts: items,
      failedCount: skipped,
      failureReasons: warnings,
    } = await buildImportOperations({ inserts: parsed, updates: [], vaultKey });
    expect(items).toHaveLength(0);
    expect(skipped).toBe(1);
    expect(warnings[0]).toContain('bad');
  });

  it('produces a deterministic search hash for the same name', async () => {
    const parsed: ParsedImportItem[] = [
      { itemType: 'note', name: 'Same', data: { content: 'x' }, tags: [], favorite: false },
    ];
    const a = await buildImportOperations({ inserts: parsed, updates: [], vaultKey });
    const b = await buildImportOperations({ inserts: parsed, updates: [], vaultKey });
    expect(a.inserts[0]!.searchHash).toBe(b.inserts[0]!.searchHash);
  });

  it('keeps a Bitwarden identity whose source email/phone fail the shared schema', async () => {
    // End-to-end of the parse→validate→encrypt path: the parser folds the
    // schema-invalid email/phone into notes, so the identity survives instead of
    // being skipped wholesale (which would lose name, address, passport, …).
    const bw = JSON.stringify({
      items: [
        {
          type: 4,
          name: 'Weird Identity',
          identity: {
            firstName: 'A',
            lastName: 'B',
            passportNumber: 'X1',
            email: 'a@b..c',
            phone: '+1 555 CALL-NOW',
          },
        },
      ],
    });
    const { items: parsed } = parseImportData('bitwarden', bw);
    const { inserts: items, failedCount: skipped } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(items).toHaveLength(1);
    expect(items[0]?.itemType).toBe('identity');
  });

  it('never emits plaintext: ciphertext differs from the source name/data', async () => {
    const parsed: ParsedImportItem[] = [
      {
        itemType: 'login',
        name: 'PlaintextName',
        data: { password: 'PlaintextSecret' },
        tags: [],
        favorite: false,
      },
    ];
    const { inserts: items } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      vaultKey,
    });
    const item = items[0]!;
    expect(item.encryptedName).not.toContain('PlaintextName');
    expect(item.encryptedData).not.toContain('PlaintextSecret');
  });
});
