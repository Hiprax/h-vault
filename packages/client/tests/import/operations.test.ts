// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import {
  buildImportOperations,
  chunkImportOperations,
  IMPORT_BATCH_MAX_BYTES,
  MAX_IMPORT_WARNINGS,
} from '../../src/services/import';
import type { ResolvableImportItem } from '../../src/services/import';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import {
  MAX_ENCRYPTED_DATA_LENGTH,
  importInsertItemSchema,
  importUpdateItemSchema,
} from '@hvault/shared';
import type { ImportInsertItem, ImportUpdateItem } from '@hvault/shared';

/**
 * `buildImportOperations` turns a RESOLVED import into the wire payload, and
 * `chunkImportOperations` slices that payload into requests. Between them they
 * own three guarantees worth proving directly: a native row's ciphertext is
 * forwarded rather than re-encrypted, an overwrite keeps the previous password,
 * and batching is transport only.
 */

let vaultKey: CryptoKey;

beforeAll(async () => {
  vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
});

function loginRow(overrides: Partial<ResolvableImportItem> = {}): ResolvableImportItem {
  return {
    itemType: 'login',
    name: 'GitHub',
    data: {
      username: 'octocat',
      password: 'hunter2',
      uris: [{ uri: 'https://github.com', match: 'domain' }],
    },
    tags: [],
    favorite: false,
    ...overrides,
  };
}

/** A minimal existing-item stand-in with the fields the builder reads. */
function existingItem(
  id: string,
  data: Record<string, unknown>,
  passwordHistory?: { encryptedPassword: string; iv: string; tag: string; changedAt: string }[],
) {
  return {
    id,
    itemType: 'login' as const,
    name: 'GitHub',
    data,
    _raw: { ...(passwordHistory !== undefined ? { passwordHistory } : {}) },
  };
}

describe('buildImportOperations', () => {
  it('encrypts a parsed row into a schema-valid insert carrying no plaintext', async () => {
    const row = loginRow();
    const built = await buildImportOperations({ inserts: [row], updates: [], vaultKey });

    expect(built.failedCount).toBe(0);
    expect(built.inserts).toHaveLength(1);
    expect(importInsertItemSchema.safeParse(built.inserts[0]).success).toBe(true);

    // Nothing the user typed survives into the payload.
    const serialized = JSON.stringify(built.inserts[0]);
    expect(serialized).not.toContain('octocat');
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('github.com');

    // …but it round-trips under the vault key.
    const insert = built.inserts[0] as ImportInsertItem;
    const name = await cryptoService.decryptData(
      insert.encryptedName,
      insert.nameIv,
      insert.nameTag,
      vaultKey,
    );
    expect(name).toBe('GitHub');
  });

  it('forwards a native row ciphertext verbatim instead of re-encrypting it', async () => {
    const cipher = {
      encryptedName: 'already-encrypted-name',
      nameIv: 'name-iv',
      nameTag: 'name-tag',
      encryptedData: 'already-encrypted-data',
      dataIv: 'data-iv',
      dataTag: 'data-tag',
    };
    const built = await buildImportOperations({
      inserts: [loginRow({ cipher })],
      updates: [],
      vaultKey,
    });

    expect(built.inserts[0]).toMatchObject(cipher);
    // The search hash is the one thing recomputed — an export may not carry one,
    // and it is a deterministic HMAC of the name under the same key.
    expect(built.inserts[0]?.searchHash).toBe(
      await cryptoService.generateSearchHash('GitHub', vaultKey),
    );
  });

  it('carries a native row password history through to the insert', async () => {
    const passwordHistory = [
      { encryptedPassword: 'old-cipher', iv: 'iv', tag: 'tag', changedAt: '2026-01-01T00:00:00Z' },
    ];
    const built = await buildImportOperations({
      inserts: [
        loginRow({
          cipher: {
            encryptedName: 'en',
            nameIv: 'ni',
            nameTag: 'nt',
            encryptedData: 'ed',
            dataIv: 'di',
            dataTag: 'dt',
          },
          passwordHistory,
        }),
      ],
      updates: [],
      vaultKey,
    });

    expect(built.inserts[0]?.passwordHistory).toEqual(passwordHistory);
    expect(importInsertItemSchema.safeParse(built.inserts[0]).success).toBe(true);
  });

  it('retains the previous password when an update changes it', async () => {
    const existing = existingItem('507f1f77bcf86cd799439011', {
      username: 'octocat',
      password: 'old-password',
    });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        { incoming: loginRow({ data: { username: 'octocat', password: 'new' } }), existing },
      ],
      vaultKey,
    });

    expect(built.updates).toHaveLength(1);
    const update = built.updates[0] as ImportUpdateItem;
    expect(update.id).toBe('507f1f77bcf86cd799439011');
    expect(importUpdateItemSchema.safeParse(update).success).toBe(true);
    expect(update.passwordHistory).toHaveLength(1);

    const recovered = await cryptoService.decryptData(
      update.passwordHistory?.[0]?.encryptedPassword ?? '',
      update.passwordHistory?.[0]?.iv ?? '',
      update.passwordHistory?.[0]?.tag ?? '',
      vaultKey,
    );
    expect(recovered).toBe('old-password');
  });

  it('omits password history when the password is unchanged', async () => {
    const existing = existingItem('507f1f77bcf86cd799439011', {
      username: 'octocat',
      password: 'same',
    });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        { incoming: loginRow({ data: { username: 'octocat', password: 'same' } }), existing },
      ],
      vaultKey,
    });

    expect(built.updates[0]?.passwordHistory).toBeUndefined();
  });

  it('reports an unsealable UPDATE as a counted failure and emits no operation', async () => {
    const existing = existingItem('507f1f77bcf86cd799439011', { username: 'octocat' });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        {
          incoming: loginRow({ data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] } }),
          existing,
        },
      ],
      vaultKey,
    });

    expect(built.updates).toEqual([]);
    expect(built.failedCount).toBe(1);
    // An unsent update must be accounted for, not written off as a no-op.
    expect(built.failureReasons).toHaveLength(1);
  });

  it('reports a row whose ciphertext would exceed the field cap', async () => {
    // 100 custom fields of 50k each all satisfy the schema individually, yet the
    // encrypted payload lands far past MAX_ENCRYPTED_DATA_LENGTH.
    const huge = loginRow({
      name: 'Huge',
      data: {
        username: 'octocat',
        customFields: Array.from({ length: 100 }, (_, i) => ({
          name: `field-${String(i)}`,
          value: 'x'.repeat(50_000),
          type: 'text',
        })),
      },
    });

    const built = await buildImportOperations({ inserts: [huge], updates: [], vaultKey });

    expect(built.inserts).toEqual([]);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/too large/i);
  });

  it('reports an over-large NATIVE row without re-encrypting or sending it', async () => {
    // A native row skips encryption entirely — its ciphertext is forwarded
    // verbatim — so the plaintext size check above never sees it. This separate
    // guard is what turns a hand-edited export into ONE reported row instead of
    // a server-side 400 that kills the whole batch it rides in.
    const oversized = loginRow({
      name: 'Tampered export row',
      cipher: {
        encryptedName: 'en',
        nameIv: 'ni',
        nameTag: 'nt',
        encryptedData: 'x'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1),
        dataIv: 'di',
        dataTag: 'dt',
      },
    });

    const built = await buildImportOperations({
      inserts: [oversized, loginRow()],
      updates: [],
      vaultKey,
    });

    // The healthy row still goes; only the offending one is withheld.
    expect(built.inserts).toHaveLength(1);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/too large/i);
    expect(built.failureReasons[0]).toMatch(/Tampered export row/);
  });

  it('stops collecting failure reasons at MAX_IMPORT_WARNINGS but keeps counting', async () => {
    // The reasons feed a toast description and the caller spreads them
    // UNBOUNDED, so this cap is the only thing standing between a wholly
    // invalid file and a multi-hundred-kilobyte string rendered into the DOM.
    const bad = (i: number): ResolvableImportItem => ({
      itemType: 'card',
      name: `Overlong ${String(i)}`,
      data: { number: '4'.repeat(60) },
      tags: [],
      favorite: false,
    });
    const rows = Array.from({ length: MAX_IMPORT_WARNINGS + 2 }, (_, i) => bad(i));

    const built = await buildImportOperations({ inserts: rows, updates: [], vaultKey });

    expect(built.failedCount).toBe(MAX_IMPORT_WARNINGS + 2);
    expect(built.failureReasons).toHaveLength(MAX_IMPORT_WARNINGS);
  });

  it('reports an unsealable row as a counted failure rather than dropping it silently', async () => {
    // A card number far past its schema cap fails validation for the whole item.
    const bad: ResolvableImportItem = {
      itemType: 'card',
      name: 'Overlong',
      data: { number: '4'.repeat(60) },
      tags: [],
      favorite: false,
    };
    const built = await buildImportOperations({
      inserts: [bad, loginRow()],
      updates: [],
      vaultKey,
    });

    expect(built.inserts).toHaveLength(1);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/Overlong/);
  });
});

describe('chunkImportOperations', () => {
  const insert = (n: number): ImportInsertItem => ({
    itemType: 'login',
    encryptedName: `en${String(n)}`,
    nameIv: 'ni',
    nameTag: 'nt',
    encryptedData: `ed${String(n)}`,
    dataIv: 'di',
    dataTag: 'dt',
    searchHash: 'a'.repeat(64),
    tags: [],
    favorite: false,
  });

  const update = (n: number): ImportUpdateItem => ({
    id: '507f1f77bcf86cd7994390'.padEnd(22, '0') + String(n).padStart(2, '0'),
    encryptedName: `uen${String(n)}`,
    nameIv: 'ni',
    nameTag: 'nt',
    encryptedData: `ued${String(n)}`,
    dataIv: 'di',
    dataTag: 'dt',
    searchHash: 'b'.repeat(64),
  });

  it('keeps everything in one batch when it fits', () => {
    const batches = chunkImportOperations([insert(1), insert(2)], [update(1)]);
    expect(batches).toHaveLength(1);
    expect(batches[0]?.inserts).toHaveLength(2);
    expect(batches[0]?.updates).toHaveLength(1);
  });

  it('sends every operation exactly once, in order, however it is split', () => {
    const inserts = Array.from({ length: 7 }, (_, i) => insert(i));
    const updates = Array.from({ length: 5 }, (_, i) => update(i));

    for (const maxCount of [1, 2, 3, 5, 12, 100]) {
      const batches = chunkImportOperations(inserts, updates, IMPORT_BATCH_MAX_BYTES, maxCount);
      expect(batches.flatMap((b) => b.inserts)).toEqual(inserts);
      expect(batches.flatMap((b) => b.updates)).toEqual(updates);
    }
  });

  it('splits on the byte budget as well as the count', () => {
    const inserts = Array.from({ length: 4 }, (_, i) => insert(i));
    // Each serialized operation is well over 40 bytes, so the budget alone forces
    // one operation per request.
    const batches = chunkImportOperations(inserts, [], 40);
    expect(batches).toHaveLength(4);
    expect(batches.flatMap((b) => b.inserts)).toEqual(inserts);
  });

  it('produces no batches when there is nothing to send', () => {
    expect(chunkImportOperations([], [])).toEqual([]);
  });
});
