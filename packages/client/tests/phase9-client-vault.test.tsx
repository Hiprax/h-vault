/**
 * Phase 9 tests: client vault-store correctness.
 *
 * 9.1 — Fetch dedup-guard unwedge (#14).
 *   `getVaultKey()` throws when the vault is locked. It used to run OUTSIDE the
 *   try/finally that owns `fetchXInFlight`, so the guard was left holding a
 *   permanently-rejected promise and every later fetch re-threw it without ever
 *   hitting the network — until clearStore(), which unlock() does not call.
 *
 * 9.2 — Metadata-only `updateItemMeta` (#17).
 *   `decryptItem` keeps a PLACEHOLDER in `item.data` when the decrypted payload
 *   fails schema validation (`_validationError`) or JSON parsing (`_raw`).
 *   Routing a favorite toggle / folder move through `updateItem` re-encrypted
 *   that placeholder OVER the item's real ciphertext — destroying the only copy
 *   of the user's data. `updateItemMeta` sends only the plaintext metadata and
 *   encrypts nothing.
 */

import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Polyfill matchMedia — uiStore (imported by vaultStore) reads it at module
// evaluation time.
// ---------------------------------------------------------------------------

vi.hoisted(() => {
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

const { mockToast } = vi.hoisted(() => ({ mockToast: vi.fn() }));

// ---------------------------------------------------------------------------
// Mocks (before the store/component imports)
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: () => false,
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    generateVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
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

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
  clearSettingsCache: vi.fn(),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({ startCountdown: vi.fn(), cancelCountdown: vi.fn() }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock('react-markdown', () => ({
  default: ({ children }: { children: string }) => React.createElement('div', null, children),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore, type DecryptedVaultItem } from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  listItemsApi,
  listTrashApi,
  listFoldersApi,
  updateItemApi,
} from '../src/services/api/vaultApi';
import { VaultItemDetail } from '../src/components/vault/VaultItemDetail';
import type { IVaultItemResponse } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORIGINAL_CIPHERTEXT = 'the-original-encrypted-payload';

function makeRaw(overrides: Partial<IVaultItemResponse> = {}): IVaultItemResponse {
  return {
    _id: 'item-1',
    itemType: 'login',
    tags: [],
    favorite: false,
    encryptedName: 'enc-name',
    nameIv: 'n-iv',
    nameTag: 'n-tag',
    encryptedData: ORIGINAL_CIPHERTEXT,
    dataIv: 'd-iv',
    dataTag: 'd-tag',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeItem(overrides: Partial<DecryptedVaultItem> = {}): DecryptedVaultItem {
  return {
    id: 'item-1',
    itemType: 'login',
    tags: [],
    favorite: false,
    name: 'My Login',
    data: { username: 'u', password: 'p', uris: [], customFields: [] },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    _raw: makeRaw(),
    ...overrides,
  };
}

/** An item whose decrypted payload failed Zod validation (vaultStore flags it). */
function makeUndecodableItem(): DecryptedVaultItem {
  return makeItem({
    // No `uris` / `customFields` — exactly the un-defaulted shape the store
    // keeps when the schema rejects the payload.
    data: { username: 'u', _validationError: true },
  });
}

/** An item whose decrypted payload was not even a JSON object. */
function makeRawFallbackItem(): DecryptedVaultItem {
  return makeItem({ data: { _raw: 'not-json-at-all' } });
}

const emptyItemsPage = {
  data: {
    success: true,
    data: [],
    pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
  },
};

const mockVaultKey = {} as CryptoKey;

function unlock(): void {
  useAuthStore.setState({ vaultKey: mockVaultKey });
}

function lock(): void {
  useAuthStore.setState({ vaultKey: null });
}

beforeEach(() => {
  vi.clearAllMocks();
  // clearStore() nulls the module-level in-flight guards, so each test starts
  // from a clean dedup state regardless of what the previous one left behind.
  useVaultStore.getState().clearStore();
  lock();
});

// ===========================================================================
// 9.1 — locked-vault fetch must not wedge the dedup guard
// ===========================================================================

describe('vaultStore — fetch dedup guard survives a locked vault (#14)', () => {
  it('fetchItems: rejects when locked, then works after unlock (guard was reset)', async () => {
    await expect(useVaultStore.getState().fetchItems()).rejects.toThrow('Vault is locked');
    expect(listItemsApi).not.toHaveBeenCalled();
    // The loading flags must not be stuck on either — no permanent spinner.
    expect(useVaultStore.getState().itemsLoading).toBe(false);
    expect(useVaultStore.getState().loading).toBe(false);

    unlock();
    vi.mocked(listItemsApi).mockResolvedValue(
      emptyItemsPage as unknown as Awaited<ReturnType<typeof listItemsApi>>,
    );

    // Pre-fix this re-threw the stale rejection from `fetchItemsInFlight` and
    // never issued a request.
    await useVaultStore.getState().fetchItems();
    expect(listItemsApi).toHaveBeenCalledTimes(1);
  });

  it('fetchTrashItems: rejects when locked, then works after unlock', async () => {
    await expect(useVaultStore.getState().fetchTrashItems()).rejects.toThrow('Vault is locked');
    expect(listTrashApi).not.toHaveBeenCalled();
    expect(useVaultStore.getState().trashLoading).toBe(false);
    expect(useVaultStore.getState().loading).toBe(false);

    unlock();
    vi.mocked(listTrashApi).mockResolvedValue(
      emptyItemsPage as unknown as Awaited<ReturnType<typeof listTrashApi>>,
    );

    await useVaultStore.getState().fetchTrashItems();
    expect(listTrashApi).toHaveBeenCalledTimes(1);
  });

  it('fetchFolders: rejects when locked, then works after unlock', async () => {
    await expect(useVaultStore.getState().fetchFolders()).rejects.toThrow('Vault is locked');
    expect(listFoldersApi).not.toHaveBeenCalled();

    unlock();
    vi.mocked(listFoldersApi).mockResolvedValue({
      data: { success: true, data: [] },
    } as unknown as Awaited<ReturnType<typeof listFoldersApi>>);

    await useVaultStore.getState().fetchFolders();
    expect(listFoldersApi).toHaveBeenCalledTimes(1);
  });

  it('a locked fetch does not wedge repeated retries either', async () => {
    // Three consecutive locked attempts each reject independently — none of
    // them is a memoized replay of the first (which is what "wedged" looked
    // like), and each one gets the chance to hit the network once unlocked.
    for (let i = 0; i < 3; i++) {
      await expect(useVaultStore.getState().fetchItems()).rejects.toThrow('Vault is locked');
    }

    unlock();
    vi.mocked(listItemsApi).mockResolvedValue(
      emptyItemsPage as unknown as Awaited<ReturnType<typeof listItemsApi>>,
    );
    await useVaultStore.getState().fetchItems();
    expect(listItemsApi).toHaveBeenCalledTimes(1);
  });
});

// ===========================================================================
// 9.2 — updateItemMeta: metadata-only, never re-encrypts
// ===========================================================================

describe('vaultStore.updateItemMeta — metadata-only update (#17)', () => {
  beforeEach(() => {
    unlock();
  });

  it('sends ONLY the metadata fields and encrypts nothing', async () => {
    useVaultStore.setState({ items: [makeItem()] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ favorite: true, updatedAt: '2024-06-01T00:00:00Z' }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { favorite: true });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { favorite: true });

    // No ciphertext field may appear in the payload — that is the invariant.
    const payload = vi.mocked(updateItemApi).mock.calls[0]![1];
    for (const field of [
      'encryptedData',
      'dataIv',
      'dataTag',
      'encryptedName',
      'nameIv',
      'nameTag',
      'searchHash',
      'passwordHistory',
    ]) {
      expect(payload).not.toHaveProperty(field);
    }

    // ...and no crypto ran at all (neither encrypting the request nor
    // decrypting the response).
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(cryptoService.generateSearchHash).not.toHaveBeenCalled();
    expect(cryptoService.decryptData).not.toHaveBeenCalled();
  });

  it('applies the new metadata locally and mirrors it into _raw', async () => {
    useVaultStore.setState({ items: [makeItem({ tags: ['old'] })] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ updatedAt: '2024-06-01T00:00:00Z' }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore
      .getState()
      .updateItemMeta('item-1', { favorite: true, folderId: 'folder-9', tags: ['a', 'b'] });

    const item = useVaultStore.getState().items[0]!;
    expect(item.favorite).toBe(true);
    expect(item.folderId).toBe('folder-9');
    expect(item.tags).toEqual(['a', 'b']);
    expect(item.updatedAt).toBe('2024-06-01T00:00:00Z');

    expect(item._raw.favorite).toBe(true);
    expect(item._raw.folderId).toBe('folder-9');
    expect(item._raw.tags).toEqual(['a', 'b']);
    expect(item._raw.updatedAt).toBe('2024-06-01T00:00:00Z');
  });

  it('folderId: null clears the folder; an omitted field is left untouched', async () => {
    useVaultStore.setState({
      items: [makeItem({ folderId: 'folder-1', favorite: true, tags: ['keep'] })],
    });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw() },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { folderId: null });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { folderId: null });
    const item = useVaultStore.getState().items[0]!;
    expect(item.folderId).toBeUndefined();
    // Fields not named in the update keep their previous values.
    expect(item.favorite).toBe(true);
    expect(item.tags).toEqual(['keep']);
  });

  it('leaves the ciphertext of a _validationError item byte-identical', async () => {
    const broken = makeUndecodableItem();
    useVaultStore.setState({ items: [broken] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ favorite: true }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { favorite: true });

    const item = useVaultStore.getState().items[0]!;
    expect(item.favorite).toBe(true);
    // The real ciphertext survives, and the placeholder payload was neither
    // encrypted nor overwritten by a (doomed) response decrypt.
    expect(item._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
    expect(item._raw.dataIv).toBe('d-iv');
    expect(item._raw.dataTag).toBe('d-tag');
    expect(item.data).toEqual({ username: 'u', _validationError: true });
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
  });

  it('leaves the ciphertext of a _raw (unparseable) item byte-identical', async () => {
    useVaultStore.setState({ items: [makeRawFallbackItem()] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ folderId: 'folder-3' }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { folderId: 'folder-3' });

    const item = useVaultStore.getState().items[0]!;
    expect(item.folderId).toBe('folder-3');
    expect(item._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
    expect(item.data).toEqual({ _raw: 'not-json-at-all' });
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
  });

  it('needs no vault key — nothing is encrypted (works while locked)', async () => {
    lock();
    useVaultStore.setState({ items: [makeItem()] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ favorite: true }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await expect(
      useVaultStore.getState().updateItemMeta('item-1', { favorite: true }),
    ).resolves.toBeUndefined();
    expect(useVaultStore.getState().items[0]!.favorite).toBe(true);
  });

  it('skips the request entirely when no metadata field is supplied', async () => {
    useVaultStore.setState({ items: [makeItem()] });

    await useVaultStore.getState().updateItemMeta('item-1', {});

    expect(updateItemApi).not.toHaveBeenCalled();
  });

  it('leaves other items untouched', async () => {
    useVaultStore.setState({
      items: [makeItem({ id: 'item-1' }), makeItem({ id: 'item-2', name: 'Other' })],
    });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ favorite: true }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { favorite: true });

    const { items } = useVaultStore.getState();
    expect(items[0]!.favorite).toBe(true);
    expect(items[1]!.favorite).toBe(false);
    expect(items[1]!.name).toBe('Other');
  });

  it('does not mutate state when the API reports success: false', async () => {
    useVaultStore.setState({ items: [makeItem()] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: false, error: { code: 'NOT_FOUND', message: 'gone' } },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    await useVaultStore.getState().updateItemMeta('item-1', { favorite: true });

    expect(useVaultStore.getState().items[0]!.favorite).toBe(false);
  });

  it('propagates API errors to the caller', async () => {
    useVaultStore.setState({ items: [makeItem()] });
    vi.mocked(updateItemApi).mockRejectedValue(new Error('Network error'));

    await expect(
      useVaultStore.getState().updateItemMeta('item-1', { favorite: true }),
    ).rejects.toThrow('Network error');
    expect(useVaultStore.getState().items[0]!.favorite).toBe(false);
  });

  it('does not write back into a store cleared by a mid-flight lock/logout', async () => {
    useVaultStore.setState({ items: [makeItem()] });

    let resolveApi!: (value: unknown) => void;
    vi.mocked(updateItemApi).mockReturnValue(
      new Promise((resolve) => {
        resolveApi = resolve;
      }) as unknown as ReturnType<typeof updateItemApi>,
    );

    const promise = useVaultStore.getState().updateItemMeta('item-1', { favorite: true });

    // Lock/logout lands while the request is in flight: the store is emptied
    // and the mutation generation bumped.
    useVaultStore.getState().clearStore();
    // A fresh session repopulates the same id.
    useVaultStore.setState({ items: [makeItem({ favorite: false })] });

    resolveApi({ data: { success: true, data: makeRaw({ favorite: true }) } });
    await promise;

    // The superseded update must not touch the fresh-session item.
    expect(useVaultStore.getState().items[0]!.favorite).toBe(false);
  });
});

// ===========================================================================
// 9.2 (end-to-end) — VaultItemDetail routes favorite/move through the
// metadata-only path, against the REAL store.
// ===========================================================================

describe('VaultItemDetail — favorite/move never re-encrypt (#17)', () => {
  const CIPHERTEXT_FIELDS = [
    'encryptedData',
    'dataIv',
    'dataTag',
    'encryptedName',
    'nameIv',
    'nameTag',
    'searchHash',
  ] as const;

  function renderDetail(item: DecryptedVaultItem) {
    return render(
      <MemoryRouter>
        <VaultItemDetail item={item} onEdit={vi.fn()} />
      </MemoryRouter>,
    );
  }

  beforeEach(() => {
    unlock();
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ favorite: true }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);
  });

  it('favoriting an undecodable item sends a metadata-only payload', async () => {
    const broken = makeUndecodableItem();
    useVaultStore.setState({ items: [broken], folders: [] });

    renderDetail(broken);
    // The item is shown as degraded, but the action bar stays usable.
    expect(screen.getByText('This item could not be fully decoded.')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByText('Favorite'));
    });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { favorite: true });
    const payload = vi.mocked(updateItemApi).mock.calls[0]![1];
    for (const field of CIPHERTEXT_FIELDS) expect(payload).not.toHaveProperty(field);

    // The decisive assertion: the placeholder was never encrypted, so the
    // item's real ciphertext on the server was never overwritten.
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(useVaultStore.getState().items[0]!._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Added to favorites', type: 'success' }),
    );
  });

  it('moving an undecodable item to a folder sends a metadata-only payload', async () => {
    const broken = makeRawFallbackItem();
    useVaultStore.setState({
      items: [broken],
      folders: [
        {
          id: 'folder-7',
          name: 'Work',
          sortOrder: 0,
          createdAt: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-01T00:00:00Z',
          _raw: {} as never,
        },
      ],
    });

    renderDetail(broken);

    // Open the move-to-folder menu and pick a folder.
    fireEvent.click(screen.getByText('No folder'));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Work' }));
    });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { folderId: 'folder-7' });
    const payload = vi.mocked(updateItemApi).mock.calls[0]![1];
    for (const field of CIPHERTEXT_FIELDS) expect(payload).not.toHaveProperty(field);

    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(useVaultStore.getState().items[0]!._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Item moved', type: 'success' }),
    );
  });

  it('favoriting a healthy item is metadata-only too (no needless re-encrypt)', async () => {
    const healthy = makeItem();
    useVaultStore.setState({ items: [healthy], folders: [] });

    renderDetail(healthy);

    await act(async () => {
      fireEvent.click(screen.getByText('Favorite'));
    });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { favorite: true });
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(useVaultStore.getState().items[0]!.favorite).toBe(true);
  });
});

// ===========================================================================
// The same defect lived in VaultList's BULK TAG action — a metadata-only change
// (tags) routed through the re-encrypting updateItem(). PLAN.md did not name it,
// but it is the same construction site and strictly worse: one click applies to
// every selected item, so a single bulk-tag could destroy the ciphertext of
// every undecodable item in the selection.
// ===========================================================================

describe('VaultList bulk tag — metadata-only, never re-encrypts (#17)', () => {
  it('applies a tag to an undecodable item without touching its ciphertext', async () => {
    unlock();
    const broken = makeUndecodableItem();
    useVaultStore.setState({ items: [broken] });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ tags: ['urgent'] }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    // Drive the store action the bulk-tag handler calls, with the tag list it
    // computes (existing tags + the new one).
    await useVaultStore.getState().updateItemMeta('item-1', { tags: ['urgent'] });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { tags: ['urgent'] });
    const payload = vi.mocked(updateItemApi).mock.calls[0]![1];
    expect(payload).not.toHaveProperty('encryptedData');
    expect(cryptoService.encryptData).not.toHaveBeenCalled();

    const item = useVaultStore.getState().items[0]!;
    expect(item.tags).toEqual(['urgent']);
    expect(item._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
    expect(item.data).toEqual({ username: 'u', _validationError: true });
  });

  it('bulk-tagging an undecodable item through the UI sends no ciphertext', async () => {
    unlock();
    const broken = makeUndecodableItem();
    useVaultStore.setState({ items: [broken], folders: [], showTrash: false });
    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRaw({ tags: ['urgent'] }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    const { VaultList } = await import('../src/components/vault/VaultList');
    render(
      <MemoryRouter>
        <VaultList onCreateNew={vi.fn()} />
      </MemoryRouter>,
    );

    // Select the item, open the Tag menu, enter a tag and apply it.
    fireEvent.click(screen.getByLabelText('Select item'));
    fireEvent.click(screen.getByText('Tag'));
    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), {
      target: { value: 'urgent' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Apply'));
    });

    expect(updateItemApi).toHaveBeenCalledWith('item-1', { tags: ['urgent'] });
    const payload = vi.mocked(updateItemApi).mock.calls[0]![1];
    for (const field of ['encryptedData', 'dataIv', 'dataTag', 'encryptedName', 'searchHash']) {
      expect(payload).not.toHaveProperty(field);
    }
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(useVaultStore.getState().items[0]!._raw.encryptedData).toBe(ORIGINAL_CIPHERTEXT);
  });
});
