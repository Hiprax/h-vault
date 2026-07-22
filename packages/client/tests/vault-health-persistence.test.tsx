/**
 * Vault Health result PERSISTENCE (encrypted, per-user) — proves results survive
 * a refresh / browser-close: persist after a fully-successful scan, hydrate on a
 * fresh mount without re-checking, keep the previous result on a failed re-scan,
 * prime the strength cache from persisted scores, and suppress a persist that was
 * superseded by a lock (generation gate). Uses REAL cryptoService + healthResultsStore
 * + IndexedDB (fake-indexeddb), mocking only the router, react-window, and the APIs.
 */
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act, fireEvent, cleanup } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

const { mockCheckBreachBatchApi, mockNavigate, mockGetZxcvbn } = vi.hoisted(() => ({
  mockCheckBreachBatchApi: vi.fn(),
  mockNavigate: vi.fn(),
  mockGetZxcvbn: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('react-window', () => ({
  List: ({
    rowComponent: RowComponent,
    rowCount,
    rowHeight,
    rowProps,
  }: {
    rowComponent: React.ComponentType<Record<string, unknown>>;
    rowCount: number;
    rowHeight: number;
    rowProps: Record<string, unknown>;
  }) => {
    const rows = [];
    for (let i = 0; i < Math.min(rowCount, 20); i++) {
      rows.push(
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: { height: rowHeight },
          ...rowProps,
        }),
      );
    }
    return React.createElement('div', { role: 'list' }, ...rows);
  },
}));

vi.mock('../src/services/api/userApi', () => ({
  checkBreachApi: vi.fn(),
  checkBreachBatchApi: (...args: unknown[]) => mockCheckBreachBatchApi(...args),
}));

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: (...args: unknown[]) => mockGetZxcvbn(...args),
}));

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
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

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    defaults: { headers: { common: {} } },
  },
}));

// Imports after mocks. cryptoService, offlineCache, healthResultsStore, the stores
// and strengthCache are all REAL here — that is the point of this suite.
import VaultHealthPage, {
  formatLastChecked,
  reconstructBreachResult,
} from '../src/pages/VaultHealthPage';
import {
  useVaultStore,
  getHealthGeneration,
  type DecryptedVaultItem,
} from '../src/stores/vaultStore';
import { useAuthStore } from '../src/stores/authStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  loadHealthResults,
  saveBreachResults,
  saveStrengthScores,
} from '../src/services/health/healthResultsStore';
import { clearScoreCache } from '../src/services/health/strengthCache';

// ---------------------------------------------------------------------------
// Pure-helper unit tests (deterministic branch coverage)
// ---------------------------------------------------------------------------

function login(id: string, updatedAt: string, password = 'pw'): DecryptedVaultItem {
  return {
    id,
    name: id,
    itemType: 'login',
    favorite: false,
    tags: [],
    createdAt: updatedAt,
    updatedAt,
    data: { username: 'u', password },
  } as DecryptedVaultItem;
}

describe('formatLastChecked', () => {
  it('formats sub-minute as "just now"', () => {
    expect(formatLastChecked(Date.now())).toBe('just now');
  });
  it('formats minutes', () => {
    expect(formatLastChecked(Date.now() - 5 * 60_000)).toBe('5 min ago');
  });
  it('formats hours', () => {
    expect(formatLastChecked(Date.now() - 3 * 3_600_000)).toBe('3 h ago');
  });
  it('formats days', () => {
    expect(formatLastChecked(Date.now() - 2 * 86_400_000)).toBe('2 d ago');
  });
});

describe('reconstructBreachResult', () => {
  it('returns null when no scan has completed', () => {
    expect(
      reconstructBreachResult({ perItem: {}, scanCompletedAt: null, breachFailedCount: 0 }, []),
    ).toBeNull();
  });
  it('includes a version-matched breached item', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'v1', breach: 7 } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1')],
    );
    expect(r?.checkedCount).toBe(1);
    expect(r?.breached).toHaveLength(1);
    expect(r?.breached[0]?.count).toBe(7);
  });
  it('counts a version-matched clean item as checked, not breached', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'v1' } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1')],
    );
    expect(r?.checkedCount).toBe(1);
    expect(r?.breached).toEqual([]);
  });
  it('does not reuse the stored verdict of an item whose version changed', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'OLD', breach: 7 } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1')],
    );
    expect(r?.checkedCount).toBe(0);
    expect(r?.breached).toEqual([]);
  });
  it('reports an edited item as unverified rather than dropping it', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'OLD', breach: 7 } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1')],
    );
    expect(r?.failedCount).toBe(1);
    expect(r?.totalCount).toBe(1);
  });
  it('counts a password the snapshot never covered as unverified, never as safe', () => {
    // The snapshot checked one login clean; 3 more were imported afterwards. The
    // three new ones must surface as unverified so the page cannot render the
    // green "No breached passwords found" all-clear over unchecked credentials.
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'v1' } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1'), login('b', 'v1'), login('c', 'v1'), login('d', 'v1')],
    );
    expect(r?.checkedCount).toBe(1);
    expect(r?.breached).toEqual([]);
    expect(r?.failedCount).toBe(3);
    expect(r?.totalCount).toBe(4);
  });
  it('adds the stored failure count to the unverified count', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'v1' } }, scanCompletedAt: 1, breachFailedCount: 2 },
      [login('a', 'v1'), login('b', 'v1')],
    );
    expect(r?.failedCount).toBe(3);
    expect(r?.totalCount).toBe(4);
  });
  it('skips an item with no password', () => {
    const r = reconstructBreachResult(
      { perItem: { a: { v: 'v1', breach: 7 } }, scanCompletedAt: 1, breachFailedCount: 0 },
      [login('a', 'v1', '')],
    );
    expect(r?.checkedCount).toBe(0);
    expect(r?.failedCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Integration: render the page with real crypto + IndexedDB
// ---------------------------------------------------------------------------

let uidSeq = 0;
let userId: string;
let vaultKey: CryptoKey;
let itemSeq = 0;

function makeLogin(id: string, name: string, password: string): DecryptedVaultItem {
  const now = new Date(Date.now() + itemSeq++).toISOString();
  return {
    id,
    name,
    itemType: 'login',
    favorite: false,
    tags: [],
    createdAt: now,
    updatedAt: now,
    data: { username: 'u', password },
  } as DecryptedVaultItem;
}

function setItems(items: DecryptedVaultItem[]): void {
  useVaultStore.setState({
    items,
    loading: false,
    itemsLoading: false,
    trashLoading: false,
    fetchItems: vi.fn().mockResolvedValue(undefined),
  });
}

async function sha1Hex(password: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function batchBody(
  ranges: Record<string, string>,
  errors: string[] = [],
): { data: { success: boolean; data: Record<string, string>; errors: string[] } } {
  return { data: { success: true, data: ranges, errors } };
}

function renderPage(): { unmount: () => void } {
  return render(
    <MemoryRouter>
      <VaultHealthPage />
    </MemoryRouter>,
  );
}

async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function clickCheck(): Promise<void> {
  const button = screen.getByRole('button', { name: /Check for Breaches/i });
  await act(async () => {
    fireEvent.click(button);
    await Promise.resolve();
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  clearScoreCache();
  userId = `pu-${String(++uidSeq)}`;
  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  useAuthStore.setState({
    user: { userId, email: 'user@example.com' },
    vaultKey,
    isAuthenticated: true,
    isLocked: false,
  });
  // Strong by default so the weak check never interferes unless a test wants it.
  mockGetZxcvbn.mockResolvedValue((_pw: string) => ({ score: 4 }));
  setItems([]);
});

afterEach(() => {
  cleanup();
  useVaultStore.setState({ items: [], loading: false, itemsLoading: false, trashLoading: false });
});

describe('VaultHealthPage — encrypted result persistence', () => {
  it('persists a fully-successful scan and hydrates it on a fresh mount without re-checking', async () => {
    const breachedPw = 'breached-secret-1';
    const cleanPw = 'clean-secret-2';
    const breached = makeLogin('item-breached', 'Breached Site', breachedPw);
    const clean = makeLogin('item-clean', 'Clean Site', cleanPw);
    setItems([breached, clean]);

    const bh = await sha1Hex(breachedPw);
    const ch = await sha1Hex(cleanPw);
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({
        [bh.slice(0, 5)]: `${bh.slice(5)}:5`,
        // The clean password's prefix is present but its suffix is absent → clean.
        [ch.slice(0, 5)]: `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1`,
      }),
    );

    const { unmount } = renderPage();
    await flush();
    await clickCheck();
    await waitFor(() => {
      expect(screen.getByText(/Found in 5 data breach/i)).toBeTruthy();
    });

    // Wait for the fire-and-forget persist to land in IndexedDB.
    await waitFor(async () => {
      const p = await loadHealthResults(userId, vaultKey);
      expect(p?.perItem['item-breached']?.breach).toBe(5);
    });

    unmount();
    clearScoreCache();
    mockCheckBreachBatchApi.mockClear();

    // Fresh mount hydrates the persisted result — no re-check.
    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/Found in 5 data breach/i)).toBeTruthy();
    });
    expect(screen.getByText(/Last checked/i)).toBeTruthy();
    expect(mockCheckBreachBatchApi).not.toHaveBeenCalled();
  });

  it('keeps the previous persisted result when a re-scan fails entirely', async () => {
    const item = makeLogin('item-1', 'Site', 'pw-x');
    setItems([item]);
    // Seed a good persisted scan directly.
    await saveBreachResults(
      userId,
      vaultKey,
      [{ id: 'item-1', v: item.updatedAt, breach: 9 }],
      0,
      Date.now(),
    );
    mockCheckBreachBatchApi.mockRejectedValue(new Error('network down'));

    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/Found in 9 data breach/i)).toBeTruthy();
    });

    await clickCheck();
    await waitFor(() => {
      expect(screen.getByText(/could not be checked/i)).toBeTruthy();
    });

    // Persisted snapshot is unchanged (failed scan does not overwrite).
    const persisted = await loadHealthResults(userId, vaultKey);
    expect(persisted?.perItem['item-1']?.breach).toBe(9);
  });

  it('hydrates the strength cache so a weak finding shows without re-scoring', async () => {
    const item = makeLogin('item-1', 'Weak Site', 'weak');
    await saveStrengthScores(userId, vaultKey, [{ id: 'item-1', v: item.updatedAt, strength: 0 }]);
    setItems([item]);
    // If the cache priming fails, analyzeStrength would call this and throw.
    mockGetZxcvbn.mockRejectedValue(new Error('zxcvbn must not run'));

    renderPage();
    await waitFor(() => {
      expect(screen.getByText(/Password strength: Very weak/i)).toBeTruthy();
    });
  });

  it('shows the un-checked state when only strength (no breach scan) was persisted', async () => {
    const item = makeLogin('item-1', 'Site', 'pw');
    await saveStrengthScores(userId, vaultKey, [{ id: 'item-1', v: item.updatedAt, strength: 4 }]);
    setItems([item]);

    renderPage();
    await flush();
    expect(screen.getByText(/Click .*Check for Breaches/i)).toBeTruthy();
  });

  it('bumps the health generation on clearStore', () => {
    const before = getHealthGeneration();
    act(() => {
      useVaultStore.getState().clearStore();
    });
    expect(getHealthGeneration()).toBe(before + 1);
  });

  it('does not persist a scan superseded by clearStore (lock) mid-flight', async () => {
    const pw = 'gen-secret';
    const item = makeLogin('item-1', 'Site', pw);
    setItems([item]);
    const h = await sha1Hex(pw);

    let resolveBatch: (value: unknown) => void = () => undefined;
    mockCheckBreachBatchApi.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveBatch = resolve;
        }),
    );

    renderPage();
    await flush();
    await clickCheck();

    // A lock lands mid-scan → clearStore bumps the health generation.
    act(() => {
      useVaultStore.getState().clearStore();
    });

    await act(async () => {
      resolveBatch(batchBody({ [h.slice(0, 5)]: `${h.slice(5)}:5` }));
      await Promise.resolve();
      await Promise.resolve();
    });
    await flush();

    // The superseded scan must NOT have written anything.
    const persisted = await loadHealthResults(userId, vaultKey);
    expect(persisted).toBeNull();
  });
});
