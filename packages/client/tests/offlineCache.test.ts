/**
 * Tests for the offlineCache IndexedDB service.
 *
 * Verifies caching, retrieval, clearing, and per-user data isolation.
 * Uses fake-indexeddb to provide a real IndexedDB implementation in Node.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import 'fake-indexeddb/auto';

// Reset IndexedDB between tests by re-importing the module fresh
async function freshImport() {
  vi.resetModules();
  const mod = await import('../src/services/offlineCache');
  return mod;
}

// ---------------------------------------------------------------------------
// Sample data
// ---------------------------------------------------------------------------

const sampleItems = [
  { _id: 'item1', itemType: 'login', encryptedData: 'enc1' },
  { _id: 'item2', itemType: 'note', encryptedData: 'enc2' },
  { _id: 'item3', itemType: 'secret', encryptedData: 'enc3' },
];

const sampleFolders = [
  { _id: 'folder1', encryptedName: 'encFolder1' },
  { _id: 'folder2', encryptedName: 'encFolder2' },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('offlineCache', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  // -------------------------------------------------------------------------
  // cacheItems + getCachedItems
  // -------------------------------------------------------------------------

  it('cacheItems stores items that can be retrieved with getCachedItems', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-123');

    await offlineCache.cacheItems(sampleItems);
    const cached = await offlineCache.getCachedItems();

    expect(cached).toHaveLength(3);
    expect(cached).toEqual(expect.arrayContaining(sampleItems));
  });

  it('cacheItems replaces existing cache on subsequent calls', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-replace');

    await offlineCache.cacheItems(sampleItems);
    const newItems = [{ _id: 'item4', itemType: 'card', encryptedData: 'enc4' }];
    await offlineCache.cacheItems(newItems);

    const cached = await offlineCache.getCachedItems();
    expect(cached).toHaveLength(1);
    expect(cached).toEqual(newItems);
  });

  // -------------------------------------------------------------------------
  // getCachedItems with no cache
  // -------------------------------------------------------------------------

  it('getCachedItems returns empty array when no cache exists', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-empty');

    const cached = await offlineCache.getCachedItems();
    expect(cached).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // cacheFolders + getCachedFolders
  // -------------------------------------------------------------------------

  it('cacheFolders stores folders that can be retrieved', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-folders');

    await offlineCache.cacheFolders(sampleFolders);
    const cached = await offlineCache.getCachedFolders();

    expect(cached).toHaveLength(2);
    expect(cached).toEqual(expect.arrayContaining(sampleFolders));
  });

  it('getCachedFolders returns empty array when no cache exists', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-no-folders');

    const cached = await offlineCache.getCachedFolders();
    expect(cached).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // clearCache
  // -------------------------------------------------------------------------

  it('clear removes all cached items, folders, and metadata', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-clear');

    await offlineCache.cacheItems(sampleItems);
    await offlineCache.cacheFolders(sampleFolders);

    // Verify data exists
    expect(await offlineCache.getCachedItems()).toHaveLength(3);
    expect(await offlineCache.getCachedFolders()).toHaveLength(2);

    await offlineCache.clear();

    expect(await offlineCache.getCachedItems()).toEqual([]);
    expect(await offlineCache.getCachedFolders()).toEqual([]);
    expect(await offlineCache.getLastSync('items')).toBeNull();
    expect(await offlineCache.getLastSync('folders')).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Per-user data isolation
  // -------------------------------------------------------------------------

  it('different users see different data (scoped databases)', async () => {
    const { offlineCache } = await freshImport();

    // User A caches items
    await offlineCache.setUser('user-A');
    await offlineCache.cacheItems([{ _id: 'A-item', data: 'user-a-data' }]);

    // User B caches different items
    await offlineCache.setUser('user-B');
    await offlineCache.cacheItems([{ _id: 'B-item', data: 'user-b-data' }]);

    // User B should only see their own items
    const userBItems = await offlineCache.getCachedItems<{ _id: string; data: string }>();
    expect(userBItems).toHaveLength(1);
    expect(userBItems[0]!.data).toBe('user-b-data');

    // Switch back to User A — should see only User A's items
    await offlineCache.setUser('user-A');
    const userAItems = await offlineCache.getCachedItems<{ _id: string; data: string }>();
    expect(userAItems).toHaveLength(1);
    expect(userAItems[0]!.data).toBe('user-a-data');
  });

  it('setUser(null) resets to default unscoped database', async () => {
    const { offlineCache } = await freshImport();

    await offlineCache.setUser('user-scoped');
    await offlineCache.cacheItems(sampleItems);

    // Reset to unscoped
    await offlineCache.setUser(null);
    // Unscoped database should be empty
    const items = await offlineCache.getCachedItems();
    expect(items).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Last sync metadata
  // -------------------------------------------------------------------------

  it('getLastSync returns null when no sync has occurred', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-no-sync');

    expect(await offlineCache.getLastSync('items')).toBeNull();
    expect(await offlineCache.getLastSync('folders')).toBeNull();
  });

  it('cacheItems updates lastItemsSync timestamp', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-sync');

    const before = Date.now();
    await offlineCache.cacheItems(sampleItems);
    const after = Date.now();

    const lastSync = await offlineCache.getLastSync('items');
    expect(lastSync).not.toBeNull();
    expect(lastSync).toBeGreaterThanOrEqual(before);
    expect(lastSync).toBeLessThanOrEqual(after);
  });

  it('cacheFolders updates lastFoldersSync timestamp', async () => {
    const { offlineCache } = await freshImport();
    await offlineCache.setUser('user-folder-sync');

    const before = Date.now();
    await offlineCache.cacheFolders(sampleFolders);
    const after = Date.now();

    const lastSync = await offlineCache.getLastSync('folders');
    expect(lastSync).not.toBeNull();
    expect(lastSync).toBeGreaterThanOrEqual(before);
    expect(lastSync).toBeLessThanOrEqual(after);
  });

  // -------------------------------------------------------------------------
  // OfflineCacheError
  // -------------------------------------------------------------------------

  it('OfflineCacheError has correct type and name', async () => {
    const { OfflineCacheError } = await freshImport();
    const err = new OfflineCacheError('test error', 'unavailable');
    expect(err.name).toBe('OfflineCacheError');
    expect(err.type).toBe('unavailable');
    expect(err.message).toBe('test error');
  });
});

// ---------------------------------------------------------------------------
// Task 3.8 — deriveUserHash entropy on both SubtleCrypto and FNV fallback
// paths. The motivating concern is that the previous 32-bit FNV fallback hit
// 50% birthday collision probability around ~65k user IDs. After widening to
// 64 bits, 10k random IDs must collide zero times in practice.
// ---------------------------------------------------------------------------

describe('deriveUserHash entropy (Task 3.8)', () => {
  it('SubtleCrypto path returns 32 hex chars (128 bits)', async () => {
    const { deriveUserHash } = await freshImport();
    const hash = await deriveUserHash('507f1f77bcf86cd799439011');
    expect(hash).toMatch(/^[0-9a-f]{32}$/);
  });

  it('SubtleCrypto path: 500 random IDs produce 500 unique hashes', async () => {
    const { deriveUserHash } = await freshImport();
    const ids = Array.from({ length: 500 }, (_, i) => `user-${i}-${Math.random().toString(36)}`);
    const seen = new Set<string>();
    for (const id of ids) {
      seen.add(await deriveUserHash(id));
    }
    expect(seen.size).toBe(ids.length);
  }, 30_000);

  it('FNV-1a fallback path returns 16 hex chars (64 bits)', async () => {
    const { deriveUserHash } = await freshImport();
    // Force the SubtleCrypto path to fail so the fallback runs
    const originalDigest = crypto.subtle.digest;
    const stub = vi.spyOn(crypto.subtle, 'digest').mockImplementation(() => {
      throw new Error('SubtleCrypto unavailable');
    });
    try {
      const hash = await deriveUserHash('507f1f77bcf86cd799439011');
      expect(hash).toMatch(/^[0-9a-f]{16}$/);
    } finally {
      stub.mockRestore();
      // Sanity check the stub really restored
      expect(crypto.subtle.digest).toBe(originalDigest);
    }
  });

  it('FNV-1a fallback: 5000 distinct IDs hash to 5000 distinct outputs', async () => {
    // FNV path is pure JS (no SubtleCrypto await) so a wider sample is
    // affordable. 5000 sequential IDs comfortably fit under the 64-bit
    // birthday-collision threshold (~5.4M for 50%).
    const { deriveUserHash } = await freshImport();
    const stub = vi.spyOn(crypto.subtle, 'digest').mockImplementation(() => {
      throw new Error('SubtleCrypto unavailable');
    });
    try {
      const ids = Array.from(
        { length: 5000 },
        (_, i) => `kiosk-user-${i.toString().padStart(6, '0')}`,
      );
      const seen = new Set<string>();
      for (const id of ids) {
        seen.add(await deriveUserHash(id));
      }
      expect(seen.size).toBe(ids.length);
    } finally {
      stub.mockRestore();
    }
  }, 30_000);

  it('FNV-1a fallback is deterministic (same input → same output)', async () => {
    const { deriveUserHash } = await freshImport();
    const stub = vi.spyOn(crypto.subtle, 'digest').mockImplementation(() => {
      throw new Error('SubtleCrypto unavailable');
    });
    try {
      const a = await deriveUserHash('507f1f77bcf86cd799439011');
      const b = await deriveUserHash('507f1f77bcf86cd799439011');
      expect(a).toBe(b);
    } finally {
      stub.mockRestore();
    }
  });

  it('FNV-1a fallback: the second accumulator (upper half) carries full entropy', async () => {
    // Regression guard for the broken `hashB = (hashB * 0x100000001b3) >>> 0`
    // multiply: the 64-bit FNV prime overflowed IEEE-754's 53-bit mantissa,
    // collapsing the upper 32-bit half to ~4 distinct values across thousands
    // of inputs (its low hex digits were always zero). The `Math.imul` fix
    // restores a full 32-bit range, so the upper half should be (almost)
    // entirely distinct. This test FAILS on the old arithmetic, PASSES on the
    // fix — the existing "5000 distinct outputs" test could not catch it
    // because the lower half (hashA) alone kept the full outputs distinct.
    const { deriveUserHash } = await freshImport();
    const stub = vi.spyOn(crypto.subtle, 'digest').mockImplementation(() => {
      throw new Error('SubtleCrypto unavailable');
    });
    try {
      const N = 2000;
      const upperHalves = new Set<string>();
      for (let i = 0; i < N; i++) {
        const hash = await deriveUserHash(`entropy-user-${i}`);
        // hash = hashA(8 hex) + hashB(8 hex); slice off the upper half.
        upperHalves.add(hash.slice(8, 16));
      }
      // Broken arithmetic yields a tiny handful here; the fix yields ~N.
      expect(upperHalves.size).toBeGreaterThan(N * 0.9);
    } finally {
      stub.mockRestore();
    }
  }, 30_000);
});
