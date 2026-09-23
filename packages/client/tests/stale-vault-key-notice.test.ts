/**
 * Every write that seals ciphertext under the vault key NAMES the generation it
 * sealed it with, and a refusal raises a notice instead of adopting the
 * generation the server reported.
 *
 * ## The defect the generation closes
 *
 * A vault-key rotation performed on another device revokes no session and
 * refreshes no key. This tab can therefore hold a superseded key indefinitely:
 * it still decrypts everything it loaded, it still encrypts, and it has no way
 * to notice. Every row it wrote after that point landed sealed under a key the
 * account had already replaced — stranded on arrival, because the rotation
 * enumerated the vault before the row existed and no later rotation can decrypt
 * it either. Sending the generation is what lets the server refuse the row
 * instead of storing one nothing can ever open.
 *
 * ## Why the refusal is not recovered from here
 *
 * The server's 409 carries the generation it is on, and that number is an
 * instruction from a party this application does not trust (§ the zero-knowledge
 * premise: the server never holds a key and is assumed hostile). Re-deriving the
 * vault key to match it would be taking a key the server chose, on a session
 * whose every loaded item was decrypted under the old one. So the store raises
 * the app-wide notice, re-throws, and changes nothing — a reload re-reads
 * everything from one consistent starting point, and is the only remedy offered.
 *
 * The negative in nearly every case below is therefore the same: no retry, no
 * local mutation, and `authStore.vaultKeyVersion` exactly where it was.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError } from 'axios';

vi.hoisted(() => {
  // jsdom has no matchMedia and `uiStore` reads it at module scope.
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    encryptData: vi.fn(),
    encryptDataWithAad: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  getItemApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
}));

vi.mock('../src/services/offlineCache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/offlineCache')>()),
  offlineCache: {
    // `logout()` calls this; without it the store logs a swallowed failure that
    // makes a passing run look broken.
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue({ data: { success: true } }),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/client', () => ({ clearCsrfToken: vi.fn() }));
vi.mock('../src/hooks/useUserSettings', () => ({ clearSettingsCache: vi.fn() }));

import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  createFolderApi,
  createItemApi,
  updateFolderApi,
  updateItemApi,
} from '../src/services/api/vaultApi';
import type { DecryptedVaultItem } from '../src/stores/vaultStore';

/** The generation this session believes it holds, in every case below. */
const HELD_GENERATION = 3;

/** The generation the server reports when it refuses a write. */
const SERVER_GENERATION = 4;

const mockVaultKey = {} as CryptoKey;

/**
 * Row and account ids are ObjectIds in production, and a v2 field is bound to
 * its row id, so a fixture id that is not one is refused before anything is sealed.
 */
const USER_ID = '64b7f0c2a1d3e4f5a6b7c8d9';
const ITEM_ID = '65a1b2c3d4e5f60718293a4b';
const FOLDER_ID = '65a1b2c3d4e5f60718293a4c';

/** The recoverable 409: a conflict whose body carries a generation. */
function staleVaultKeyRejection(vaultKeyVersion = SERVER_GENERATION): AxiosError {
  return new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, {
    status: 409,
    statusText: 'Conflict',
    headers: {},
    config: { headers: {} } as never,
    data: { success: false, message: 'rotated elsewhere', data: { vaultKeyVersion } },
  });
}

/** A 409 with no generation: the rotation fence, a duplicate name, a busy import. */
function bareConflict(): AxiosError {
  return new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, {
    status: 409,
    statusText: 'Conflict',
    headers: {},
    config: { headers: {} } as never,
    data: { success: false, message: 'Vault key rotation is in progress. Please wait and retry.' },
  });
}

function existingItem(): DecryptedVaultItem {
  return {
    id: ITEM_ID,
    itemType: 'login',
    tags: [],
    favorite: false,
    name: 'Before',
    data: { username: 'u' },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    _raw: {
      _id: ITEM_ID,
      itemType: 'login',
      encryptedName: 'original-name-ciphertext',
      nameIv: 'n-iv',
      nameTag: 'n-tag',
      encryptedData: 'original-data-ciphertext',
      dataIv: 'd-iv',
      dataTag: 'd-tag',
      tags: [],
      favorite: false,
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
    } as unknown as DecryptedVaultItem['_raw'],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  useVaultStore.setState({ items: [existingItem()], folders: [], trashItems: [] });
  // A create derives the new row's id from this session's own user id.
  useAuthStore.setState({
    vaultKey: mockVaultKey,
    vaultKeyVersion: HELD_GENERATION,
    user: { userId: USER_ID, email: 'user@example.com' },
  });
  useUIStore.setState({ staleVaultKeyVersion: null });
  vi.mocked(cryptoService.encryptData).mockResolvedValue({
    encrypted: 'fresh-ciphertext',
    iv: 'fresh-iv',
    tag: 'fresh-tag',
  });
  vi.mocked(cryptoService.encryptDataWithAad).mockResolvedValue({
    encrypted: 'fresh-bound-ciphertext',
    iv: 'fresh-bound-iv',
    tag: 'fresh-bound-tag',
  });
  vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('f'.repeat(64));
  vi.mocked(cryptoService.decryptData).mockResolvedValue(JSON.stringify({ username: 'u' }));
});

// ── The generation is on every ciphertext write ──────────────────────────

describe('every vault write names the generation it sealed its ciphertext with', () => {
  it('createItem', async () => {
    vi.mocked(createItemApi).mockRejectedValue(new Error('stop after the request'));

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    expect(vi.mocked(createItemApi).mock.calls[0]?.[0]).toMatchObject({
      vaultKeyVersion: HELD_GENERATION,
      idNonce: expect.stringMatching(/^[0-9a-f]{40}$/) as unknown,
    });
  });

  it('updateItem', async () => {
    vi.mocked(updateItemApi).mockRejectedValue(new Error('stop after the request'));

    await expect(
      useVaultStore.getState().updateItem(ITEM_ID, 'login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    expect(vi.mocked(updateItemApi).mock.calls[0]?.[1]).toMatchObject({
      vaultKeyVersion: HELD_GENERATION,
    });
  });

  it('renameItem', async () => {
    vi.mocked(updateItemApi).mockRejectedValue(new Error('stop after the request'));

    await expect(useVaultStore.getState().renameItem(ITEM_ID, 'Renamed')).rejects.toThrow();

    expect(vi.mocked(updateItemApi).mock.calls[0]?.[1]).toMatchObject({
      vaultKeyVersion: HELD_GENERATION,
    });
  });

  it('createFolder', async () => {
    vi.mocked(createFolderApi).mockRejectedValue(new Error('stop after the request'));

    await expect(useVaultStore.getState().createFolder('Work')).rejects.toThrow();

    expect(vi.mocked(createFolderApi).mock.calls[0]?.[0]).toMatchObject({
      vaultKeyVersion: HELD_GENERATION,
      idNonce: expect.stringMatching(/^[0-9a-f]{40}$/) as unknown,
    });
  });

  it('updateFolder', async () => {
    vi.mocked(updateFolderApi).mockRejectedValue(new Error('stop after the request'));

    await expect(useVaultStore.getState().updateFolder(FOLDER_ID, 'Work')).rejects.toThrow();

    expect(vi.mocked(updateFolderApi).mock.calls[0]?.[1]).toMatchObject({
      vaultKeyVersion: HELD_GENERATION,
    });
  });

  it('updateItemMeta, which encrypts nothing and holds no key', async () => {
    // It posts to the same endpoint as a full update, and that endpoint is
    // guarded as a whole — the server does not decide a security control from
    // which fields the caller happened to send. Reading the generation needs no
    // vault key, which is what lets this path keep its promise never to hold one.
    vi.mocked(updateItemApi).mockRejectedValue(new Error('stop after the request'));
    useAuthStore.setState({ vaultKey: null });

    await expect(
      useVaultStore.getState().updateItemMeta(ITEM_ID, { favorite: true }),
    ).rejects.toThrow();

    expect(vi.mocked(updateItemApi).mock.calls[0]?.[1]).toEqual({
      favorite: true,
      vaultKeyVersion: HELD_GENERATION,
    });
    // The negative that keeps this path safe: it never encrypted anything, so it
    // cannot have overwritten the item's real ciphertext with a placeholder.
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    // Row fields are now sealed through the bound (v2) path, so that is the one
    // that proves nothing was sealed.
    expect(cryptoService.encryptDataWithAad).not.toHaveBeenCalled();
  });

  it('does not turn an EMPTY metadata update into a request carrying only a generation', async () => {
    await useVaultStore.getState().updateItemMeta(ITEM_ID, {});

    expect(updateItemApi).not.toHaveBeenCalled();
  });
});

// ── The refusal ─────────────────────────────────────────────────────────

describe('a refused write raises the reload notice and changes nothing', () => {
  it('records the generation the SERVER reported, not the one it holds', async () => {
    vi.mocked(createItemApi).mockRejectedValue(staleVaultKeyRejection());

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    expect(useUIStore.getState().staleVaultKeyVersion).toBe(SERVER_GENERATION);
  });

  it('never adopts that generation as this session’s own', async () => {
    vi.mocked(createItemApi).mockRejectedValue(staleVaultKeyRejection());

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    // The whole point. Adopting it would silently move this session onto a key
    // the server chose, with every loaded item still decrypted under the old one.
    expect(useAuthStore.getState().vaultKeyVersion).toBe(HELD_GENERATION);
  });

  it('does not retry, and adds nothing to the local store', async () => {
    vi.mocked(createItemApi).mockRejectedValue(staleVaultKeyRejection());
    const before = useVaultStore.getState().items;

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    expect(createItemApi).toHaveBeenCalledTimes(1);
    expect(useVaultStore.getState().items).toEqual(before);
  });

  it('leaves an updated item exactly as it was', async () => {
    vi.mocked(updateItemApi).mockRejectedValue(staleVaultKeyRejection());
    const before = useVaultStore.getState().items[0];

    await expect(
      useVaultStore.getState().updateItem(ITEM_ID, 'login', 'New name', { username: 'v' }),
    ).rejects.toThrow();

    expect(updateItemApi).toHaveBeenCalledTimes(1);
    expect(useVaultStore.getState().items[0]).toEqual(before);
    expect(useUIStore.getState().staleVaultKeyVersion).toBe(SERVER_GENERATION);
  });

  it.each([
    ['renameItem', () => useVaultStore.getState().renameItem(ITEM_ID, 'Renamed')],
    ['updateItemMeta', () => useVaultStore.getState().updateItemMeta(ITEM_ID, { favorite: true })],
  ])('raises the notice from %s too', async (_name, run) => {
    vi.mocked(updateItemApi).mockRejectedValue(staleVaultKeyRejection());

    await expect(run()).rejects.toThrow();

    expect(useUIStore.getState().staleVaultKeyVersion).toBe(SERVER_GENERATION);
  });

  it.each([
    ['createFolder', () => useVaultStore.getState().createFolder('Work'), createFolderApi],
    [
      'updateFolder',
      () => useVaultStore.getState().updateFolder(FOLDER_ID, 'Work'),
      updateFolderApi,
    ],
  ])('raises the notice from %s too', async (_name, run, api) => {
    vi.mocked(api).mockRejectedValue(staleVaultKeyRejection());

    await expect(run()).rejects.toThrow();

    expect(useUIStore.getState().staleVaultKeyVersion).toBe(SERVER_GENERATION);
    expect(useVaultStore.getState().folders).toEqual([]);
  });

  it('stays silent for a 409 that carries no generation', async () => {
    // The rotation fence, a duplicate folder name and a busy import all answer
    // 409 with no `data`, and each has its own remedy. Telling the user to
    // reload for a rotation that will be over in seconds would be wrong advice.
    vi.mocked(createItemApi).mockRejectedValue(bareConflict());

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();

    expect(useUIStore.getState().staleVaultKeyVersion).toBeNull();
  });

  it('stays silent for an ordinary failure', async () => {
    vi.mocked(createItemApi).mockRejectedValue(new Error('network down'));

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow('network down');

    expect(useUIStore.getState().staleVaultKeyVersion).toBeNull();
  });

  it('re-throws the refusal so the caller still reports the save as failed', async () => {
    // Swallowing it would raise the banner AND leave the form looking saved,
    // which is the one outcome worse than no notice at all.
    vi.mocked(createItemApi).mockRejectedValue(staleVaultKeyRejection());

    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toMatchObject({ response: { status: 409 } });
  });
});

// ── The one transition the derivation cannot handle by itself ────────────

describe('signing out clears the recorded refusal', () => {
  it('does not carry the notice into a different account', async () => {
    // The derivation self-clears on a re-login to the SAME account: the session
    // lands back on the generation the server reported and the two agree. An
    // account SWITCH is the case it cannot see — `logout()` resets this session
    // to generation 0 while the recorded number is whatever the previous account
    // was on, so `0 !== 4` would put an undismissable "reload to continue" over
    // a session in which every save works.
    vi.mocked(createItemApi).mockRejectedValue(staleVaultKeyRejection());
    await expect(
      useVaultStore.getState().createItem('login', 'New', { username: 'u' }),
    ).rejects.toThrow();
    expect(useUIStore.getState().staleVaultKeyVersion).toBe(SERVER_GENERATION);

    await useAuthStore.getState().logout();

    expect(useUIStore.getState().staleVaultKeyVersion).toBeNull();
    // The negative: the reset is what clears it, not a coincidence of the two
    // numbers agreeing.
    expect(useAuthStore.getState().vaultKeyVersion).toBe(0);
  });
});
