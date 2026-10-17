/**
 * F-12: no request or response schema carries a keyed hash of a name any more.
 *
 * Every write envelope that used to accept `searchHash` now strips it (Zod's
 * default for an unknown key), so an older client that still sends one is
 * accepted and the value never reaches a handler; the two import schemas that
 * REQUIRED it accept a row without it; the response schemas drop it; and the
 * subkey's HKDF label is gone with the hash it derived.
 */
import { describe, expect, it } from 'vitest';
import * as shared from '../src/index.js';
import {
  bulkReEncryptSchema,
  createVaultItemSchema,
  folderResponseSchema,
  updateVaultItemSchema,
  vaultItemResponseSchema,
} from '../src/schemas/vault.js';
import { createFolderSchema, updateFolderSchema } from '../src/schemas/folder.js';
import { importInsertItemSchema, importUpdateItemSchema } from '../src/schemas/user.js';

const HASH = 'a'.repeat(64);
const ID = '507f1f77bcf86cd799439011';

const NAME = { encryptedName: 'enc-name', nameIv: 'name-iv', nameTag: 'name-tag' };
const DATA = { encryptedData: 'enc-data', dataIv: 'data-iv', dataTag: 'data-tag' };

describe('F-12: write schemas strip a name hash and never require one', () => {
  it('createVaultItemSchema accepts a hash from an older client and drops it', () => {
    const parsed = createVaultItemSchema.parse({
      itemType: 'login',
      ...NAME,
      ...DATA,
      searchHash: HASH,
    });
    expect(parsed).not.toHaveProperty('searchHash');
    expect(parsed.encryptedName).toBe('enc-name');
  });

  it('updateVaultItemSchema drops it', () => {
    const parsed = updateVaultItemSchema.parse({ ...NAME, searchHash: HASH });
    expect(parsed).not.toHaveProperty('searchHash');
    expect(parsed.encryptedName).toBe('enc-name');
  });

  it("bulkReEncryptSchema's items leg drops it", () => {
    const parsed = bulkReEncryptSchema.parse({
      authHash: 'proof',
      newEncryptedVaultKey: 'k',
      newVaultKeyIv: 'iv',
      newVaultKeyTag: 'tag',
      items: [{ id: ID, ...NAME, ...DATA, searchHash: HASH }],
      folders: [{ id: ID.replace(/1$/, '2'), ...NAME, searchHash: HASH }],
    });
    expect(parsed.items[0]).not.toHaveProperty('searchHash');
    expect(parsed.folders[0]).not.toHaveProperty('searchHash');
    expect(parsed.items[0]?.encryptedData).toBe('enc-data');
  });

  it('createFolderSchema and updateFolderSchema drop it', () => {
    const created = createFolderSchema.parse({ ...NAME, searchHash: HASH });
    const updated = updateFolderSchema.parse({ ...NAME, searchHash: HASH });
    expect(created).not.toHaveProperty('searchHash');
    expect(updated).not.toHaveProperty('searchHash');
    expect(created.encryptedName).toBe('enc-name');
  });

  it('an import insert and update WITHOUT a hash are accepted', () => {
    const insert = importInsertItemSchema.safeParse({ itemType: 'login', ...NAME, ...DATA });
    const update = importUpdateItemSchema.safeParse({ id: ID, ...NAME, ...DATA });
    expect(insert.success).toBe(true);
    expect(update.success).toBe(true);
  });

  it('an import row WITH a hash is accepted and the hash dropped, whatever its shape', () => {
    for (const searchHash of [HASH, 'not-a-hash']) {
      const insert = importInsertItemSchema.parse({
        itemType: 'login',
        ...NAME,
        ...DATA,
        searchHash,
      });
      const update = importUpdateItemSchema.parse({ id: ID, ...NAME, ...DATA, searchHash });
      expect(insert).not.toHaveProperty('searchHash');
      expect(update).not.toHaveProperty('searchHash');
    }
    // Negative control: the import schemas still refuse a row missing a field
    // they DO require.
    expect(importInsertItemSchema.safeParse({ itemType: 'login', ...NAME }).success).toBe(false);
  });
});

describe('F-12: response schemas carry no hash', () => {
  const TIMES = { createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' };

  it('an item response from an older server is read and the hash dropped', () => {
    const parsed = vaultItemResponseSchema.parse({
      _id: ID,
      itemType: 'login',
      tags: [],
      favorite: false,
      ...NAME,
      ...DATA,
      searchHash: HASH,
      ...TIMES,
    });
    expect(parsed).not.toHaveProperty('searchHash');
    expect(parsed._id).toBe(ID);
  });

  it('a folder response from an older server is read and the hash dropped', () => {
    const parsed = folderResponseSchema.parse({
      _id: ID,
      ...NAME,
      sortOrder: 0,
      searchHash: HASH,
      ...TIMES,
    });
    expect(parsed).not.toHaveProperty('searchHash');
    expect(parsed.sortOrder).toBe(0);
  });
});

describe('F-12: the search subkey label is gone', () => {
  it('shared no longer exports VAULT_SEARCH_KEY_INFO', () => {
    expect(Object.keys(shared)).not.toContain('VAULT_SEARCH_KEY_INFO');
    // Negative control: the barrel is the real one.
    expect(Object.keys(shared)).toContain('createVaultItemSchema');
  });
});
