/**
 * The offline-cache warning, end to end: `offlineCache` classifies a failure,
 * `vaultStore` records the cause, `uiStore` holds it, and `AppLayout` turns it
 * into something the user can act on.
 *
 * Before this, `OfflineCacheErrorType` was a discriminant nothing discriminated
 * on: both `vaultStore` call sites collapsed every cause to one boolean, and no
 * component ever read that boolean. Two properties are pinned here that a bare
 * boolean could not express:
 *
 *  - the CAUSE survives the trip from the storage layer to the UI store, so
 *    "storage is full" and "your browser is blocking this" can read differently
 *    (the banner itself is asserted in `coverage-auth-layout.test.tsx`, beside
 *    the other two AppLayout banners);
 *  - the warning CLEARS on the next successful write. Nothing used to set it
 *    back, so one transient failure stated something false for the rest of the
 *    session.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useUIStore } from '../src/stores/uiStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useAuthStore } from '../src/stores/authStore';
import { listItemsApi, listFoldersApi } from '../src/services/api/vaultApi';
import { offlineCache, OfflineCacheError } from '../src/services/offlineCache';
import type { OfflineCacheErrorType } from '../src/services/offlineCache';

vi.mock('../src/services/api/vaultApi');
vi.mock('../src/services/offlineCache', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/offlineCache')>();
  return {
    ...actual,
    offlineCache: {
      setUser: vi.fn().mockResolvedValue(undefined),
      cacheItems: vi.fn().mockResolvedValue(undefined),
      cacheFolders: vi.fn().mockResolvedValue(undefined),
      getCachedItems: vi.fn().mockResolvedValue([]),
      getCachedFolders: vi.fn().mockResolvedValue([]),
      getLastSync: vi.fn().mockResolvedValue(null),
      clear: vi.fn().mockResolvedValue(undefined),
    },
  };
});

/** Let the fire-and-forget cache write settle. */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 10));
}

const EMPTY_ITEMS_PAGE = {
  data: {
    success: true,
    data: [],
    pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
  },
};

describe('vaultStore records WHY the offline cache failed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUIStore.setState({ offlineCacheError: null });
    useAuthStore.setState({ vaultKey: {} as CryptoKey });
    vi.mocked(listItemsApi).mockResolvedValue(EMPTY_ITEMS_PAGE as never);
    vi.mocked(listFoldersApi).mockResolvedValue({ data: { success: true, data: [] } } as never);
    vi.mocked(offlineCache.cacheItems).mockResolvedValue(undefined);
    vi.mocked(offlineCache.cacheFolders).mockResolvedValue(undefined);
  });

  const CAUSES: readonly OfflineCacheErrorType[] = [
    'quota_exceeded',
    'permission_denied',
    'version_conflict',
    'unavailable',
    'unknown',
  ];

  it.each(CAUSES)('carries `%s` from a failed item cache write into the UI store', async (type) => {
    vi.mocked(offlineCache.cacheItems).mockRejectedValue(
      new OfflineCacheError('storage said no', type),
    );

    await useVaultStore.getState().fetchItems();
    await settle();

    expect(useUIStore.getState().offlineCacheError).toBe(type);
  });

  it.each(CAUSES)(
    'carries `%s` from a failed folder cache write into the UI store',
    async (type) => {
      vi.mocked(offlineCache.cacheFolders).mockRejectedValue(
        new OfflineCacheError('storage said no', type),
      );

      await useVaultStore.getState().fetchFolders();
      await settle();

      expect(useUIStore.getState().offlineCacheError).toBe(type);
    },
  );

  it('degrades a rejection that is not an OfflineCacheError to `unknown`', async () => {
    // A `.catch` must not throw a second time trying to read `.type` off
    // something that has none.
    vi.mocked(offlineCache.cacheItems).mockRejectedValue('a bare string');

    await useVaultStore.getState().fetchItems();
    await settle();

    expect(useUIStore.getState().offlineCacheError).toBe('unknown');
  });

  it('clears the warning when a later item cache write succeeds', async () => {
    vi.mocked(offlineCache.cacheItems).mockRejectedValueOnce(
      new OfflineCacheError('full', 'quota_exceeded'),
    );
    await useVaultStore.getState().fetchItems();
    await settle();
    expect(useUIStore.getState().offlineCacheError).toBe('quota_exceeded');

    // The user freed some space; the next sync writes cleanly.
    vi.mocked(offlineCache.cacheItems).mockResolvedValue(undefined);
    await useVaultStore.getState().fetchItems();
    await settle();

    expect(useUIStore.getState().offlineCacheError).toBeNull();
  });

  it('clears the warning when a later folder cache write succeeds', async () => {
    vi.mocked(offlineCache.cacheFolders).mockRejectedValueOnce(
      new OfflineCacheError('blocked', 'permission_denied'),
    );
    await useVaultStore.getState().fetchFolders();
    await settle();
    expect(useUIStore.getState().offlineCacheError).toBe('permission_denied');

    vi.mocked(offlineCache.cacheFolders).mockResolvedValue(undefined);
    await useVaultStore.getState().fetchFolders();
    await settle();

    expect(useUIStore.getState().offlineCacheError).toBeNull();
  });

  it('leaves the warning alone when the fetch itself fails before any cache write', async () => {
    // The listing request failing is a different condition with its own
    // reporting; it must not be blamed on offline storage.
    useUIStore.setState({ offlineCacheError: null });
    vi.mocked(listItemsApi).mockRejectedValue(new Error('network down'));

    await useVaultStore
      .getState()
      .fetchItems()
      .catch(() => undefined);
    await settle();

    expect(useUIStore.getState().offlineCacheError).toBeNull();
    expect(offlineCache.cacheItems).not.toHaveBeenCalled();
  });
});
