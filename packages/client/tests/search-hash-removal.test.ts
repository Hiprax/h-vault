/**
 * F-12: the browser computes and sends no keyed hash of a name any more.
 *
 * Every writer that used to attach `searchHash` (item create, update and rename,
 * import sealing) now sends the name only as ciphertext, and `cryptoService` no
 * longer has the function or the HKDF subkey that produced the hash. Folder writes
 * never sent one; they are pinned here too, so neither kind can start again.
 *
 * Everything below the API module is REAL — Web Crypto, the vault-field sealer, the
 * stores — and only the transport (`vaultApi`) and browser storage are replaced:
 * the property under test is what leaves the page.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { deriveRowId } from '@hvault/shared';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

/** Every body the store handed the transport, by function. */
const sent = new Map<string, Record<string, unknown>[]>();

/** The server's answer to every write: a refusal, so the store stops after sending. */
function refuse(name: string) {
  return (...args: unknown[]) => {
    const body = args.find(
      (arg): arg is Record<string, unknown> => typeof arg === 'object' && arg !== null,
    );
    const bodies = sent.get(name) ?? [];
    bodies.push(body ?? {});
    sent.set(name, bodies);
    return Promise.resolve({ data: { success: false, message: 'refused' } });
  };
}

vi.mock('../src/services/api/vaultApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/api/vaultApi')>()),
  createItemApi: vi.fn(refuse('createItemApi')),
  updateItemApi: vi.fn(refuse('updateItemApi')),
  createFolderApi: vi.fn(refuse('createFolderApi')),
  updateFolderApi: vi.fn(refuse('updateFolderApi')),
}));

import { cryptoService } from '../src/services/crypto/cryptoService.js';
import { sealImportItem } from '../src/services/import/encrypt.js';
import { useAuthStore } from '../src/stores/authStore.js';
import { useVaultStore } from '../src/stores/vaultStore.js';

const USER_ID = '507f1f77bcf86cd799439011';
const ITEM_ID = '507f1f77bcf86cd799439012';
const FOLDER_ID = '507f1f77bcf86cd799439013';

let vaultKey: CryptoKey;

beforeEach(async () => {
  sent.clear();
  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  useAuthStore.setState({
    accessToken: 'access-token',
    vaultKey,
    vaultKeyVersion: 0,
    isAuthenticated: true,
    user: { userId: USER_ID, email: 'owner@example.com' } as never,
  });
});

/** The one body sent through `fn`, after asserting there was exactly one. */
function onlyBody(fn: string): Record<string, unknown> {
  const bodies = sent.get(fn) ?? [];
  expect(bodies).toHaveLength(1);
  return bodies[0] ?? {};
}

describe('F-12: no writer sends a name hash', () => {
  it('cryptoService has no name-hash function any more', () => {
    expect('generateSearchHash' in cryptoService).toBe(false);
    // Negative control: the object is the real service.
    expect(typeof cryptoService.encryptData).toBe('function');
  });

  it('creating an item sends the sealed name and no hash', async () => {
    await useVaultStore
      .getState()
      .createItem('login', 'GitHub', { username: 'octo', password: 'pw' })
      .catch(() => undefined);

    const body = onlyBody('createItemApi');
    expect(body).not.toHaveProperty('searchHash');
    expect(typeof body.encryptedName).toBe('string');
    expect(String(body.encryptedName)).not.toContain('GitHub');
    // Sealed to the id the server will derive, as before: the removal took the
    // hash and nothing else.
    expect(body.idNonce).toMatch(/^[0-9a-f]{40}$/);
    expect(await deriveRowId(USER_ID, String(body.idNonce))).toMatch(/^[0-9a-f]{24}$/);
  });

  it('updating and renaming an item send no hash', async () => {
    // The row the update is for, so the store knows its stored type without a read.
    useVaultStore.setState({
      items: [
        {
          id: ITEM_ID,
          itemType: 'login',
          name: 'GitHub',
          data: { username: 'octo', password: 'pw' },
          tags: [],
          favorite: false,
          _raw: {},
        } as never,
      ],
    });
    await useVaultStore
      .getState()
      .updateItem(ITEM_ID, 'login', 'GitLab', { username: 'octo', password: 'pw2' })
      .catch(() => undefined);
    await useVaultStore
      .getState()
      .renameItem(ITEM_ID, 'Renamed')
      .catch(() => undefined);

    const bodies = sent.get('updateItemApi') ?? [];
    expect(bodies).toHaveLength(2);
    for (const body of bodies) {
      expect(body).not.toHaveProperty('searchHash');
      expect(typeof body.encryptedName).toBe('string');
    }
  });

  it('creating and renaming a folder send no hash', async () => {
    await useVaultStore
      .getState()
      .createFolder('Work')
      .catch(() => undefined);
    await useVaultStore
      .getState()
      .updateFolder(FOLDER_ID, 'Home')
      .catch(() => undefined);

    expect(onlyBody('createFolderApi')).not.toHaveProperty('searchHash');
    expect(onlyBody('updateFolderApi')).not.toHaveProperty('searchHash');
  });

  it('an import row is sealed without a hash', async () => {
    const result = await sealImportItem(
      {
        itemType: 'note',
        name: 'Recovery kit',
        data: { content: 'keep me' },
        tags: [],
        favorite: false,
      },
      { rowId: ITEM_ID, itemType: 'note' },
      vaultKey,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.sealed).not.toHaveProperty('searchHash');
    expect(Object.keys(result.sealed).sort()).toEqual([
      'dataIv',
      'dataTag',
      'encryptedData',
      'encryptedName',
      'nameIv',
      'nameTag',
    ]);
  });
});
