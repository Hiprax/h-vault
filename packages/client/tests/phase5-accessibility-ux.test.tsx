/**
 * Phase 5: Accessibility & UX Improvements tests
 *
 * 5.1 — ARIA roles on virtualized vault list (role="listitem", aria-setsize, aria-posinset, aria-label)
 * 5.2 — Base32 validation for TOTP display (stricter regex, length validation)
 * 5.3 — Offline-to-online re-fetch mechanism (toast notifications, vault re-sync)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';
import { readFileSync } from 'node:fs';
import { resolve as pathResolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const clientSrcDir = pathResolve(__dirname, '../src');

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom + hoisted mock references
// ---------------------------------------------------------------------------

const { mockToast } = vi.hoisted(() => {
  if (typeof globalThis.window !== 'undefined') {
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
  }
  return { mockToast: vi.fn() };
});

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
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

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
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
  reorderFolderApi: vi.fn(),
  bulkDeleteApi: vi.fn(),
  bulkMoveApi: vi.fn(),
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: vi.fn(),
  updateSettingsApi: vi.fn(),
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
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { headers: { common: {} } },
  },
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: vi.fn().mockReturnValue({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
  clearSettingsCache: vi.fn(),
}));

vi.mock('../src/hooks/useAutoLock', () => ({
  useAutoLock: vi.fn(),
}));

vi.mock('../src/hooks/useKeyboardShortcuts', () => ({
  useKeyboardShortcuts: vi.fn(),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: vi.fn().mockReturnValue({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

vi.mock('../src/hooks/useClipboardGuard', () => ({
  useClipboardGuard: vi.fn(),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({
    toast: mockToast,
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('@hvault/shared', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@hvault/shared');
  return {
    ...actual,
    KDF_ITERATIONS: 600_000,
    KDF_ALGORITHM: 'PBKDF2',
    ENCRYPTION_VERSION: 1,
  };
});

vi.mock('../src/components/layout/OnboardingGuide', () => ({
  OnboardingGuide: () => null,
}));

// Mock react-window — passes ariaAttributes to row component
vi.mock('react-window', () => ({
  List: ({
    rowComponent: RowComponent,
    rowCount,
    rowProps,
    role,
    'aria-label': ariaLabel,
    id,
  }: {
    rowComponent: React.ComponentType<Record<string, unknown>>;
    rowCount: number;
    rowHeight: number;
    rowProps: Record<string, unknown>;
    style?: Record<string, unknown>;
    overscanCount?: number;
    role?: string;
    'aria-label'?: string;
    id?: string;
  }) =>
    React.createElement(
      'div',
      { role, 'aria-label': ariaLabel, id },
      Array.from({ length: rowCount }, (_, i) =>
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: {},
          ariaAttributes: {
            role: 'listitem',
            'aria-posinset': i + 1,
            'aria-setsize': rowCount,
          },
          ...rowProps,
        }),
      ),
    ),
}));

// ---------------------------------------------------------------------------
// Store imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { isStorageDegraded } from '../src/stores/encryptedStorage';
import { AppLayout } from '../src/components/layout/AppLayout';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDecryptedItem(
  overrides: Partial<{
    id: string;
    name: string;
    itemType: 'login' | 'secret' | 'note' | 'card' | 'identity';
    favorite: boolean;
    tags: string[];
    folderId: string;
    data: Record<string, unknown>;
  }> = {},
) {
  const now = new Date().toISOString();
  const id = overrides.id ?? 'item-1';
  return {
    id,
    itemType: overrides.itemType ?? ('login' as const),
    name: overrides.name ?? 'Test Item',
    favorite: overrides.favorite ?? false,
    tags: overrides.tags ?? [],
    folderId: overrides.folderId,
    data: overrides.data ?? {
      username: 'user@example.com',
      password: 'secret123',
      uris: [{ uri: 'https://example.com', match: 'domain' }],
      totp: '',
      notes: '',
      customFields: [],
    },
    searchHash: 'abc',
    createdAt: now,
    updatedAt: now,
    _raw: {
      _id: id,
      userId: 'u1',
      itemType: overrides.itemType ?? 'login',
      encryptedData: 'enc',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: overrides.tags ?? [],
      favorite: overrides.favorite ?? false,
      passwordHistory: [],
      createdAt: now,
      updatedAt: now,
    },
  };
}

// ---------------------------------------------------------------------------
// Global store resets
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();

  useAuthStore.setState({
    accessToken: 'test-token',
    user: { userId: 'u1', email: 'test@example.com' },
    isAuthenticated: true,
    isLocked: false,
    vaultKey: null,
    mek: null,
    encryptedVaultKeyData: null,
    twoFactorRequired: false,
    tempToken: null,
  });

  useVaultStore.setState({
    items: [],
    trashItems: [],
    folders: [],
    selectedFolder: null,
    selectedType: null,
    showFavorites: false,
    showTrash: false,
    searchQuery: '',
    sortBy: 'name',
    sortOrder: 'asc',
    loading: false,
    itemsLoading: false,
    trashLoading: false,
  });

  vi.mocked(isStorageDegraded).mockReturnValue(false);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ==========================================================================
// 5.1 — ARIA Roles on Virtualized Vault List
// ==========================================================================

describe('5.1 — ARIA roles on virtualized vault list', () => {
  let VaultList: React.ComponentType<{ onCreateNew: () => void }>;

  beforeEach(async () => {
    const mod = await import('../src/components/vault/VaultList');
    VaultList = mod.VaultList;
  });

  function renderVaultList() {
    return render(
      <MemoryRouter>
        <Routes>
          <Route path="*" element={<VaultList onCreateNew={vi.fn()} />} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it('virtualized list has role="list" and aria-label', () => {
    // Create enough items to trigger virtualization (> VIRTUALIZATION_THRESHOLD = 50)
    const items = Array.from({ length: 60 }, (_, i) =>
      makeDecryptedItem({ id: `item-${String(i)}`, name: `Item ${String(i)}` }),
    );
    useVaultStore.setState({ items });

    renderVaultList();

    const list = document.querySelector('[role="list"]');
    expect(list).toBeInTheDocument();
    expect(list).toHaveAttribute('aria-label', 'Vault items list');
  });

  it('virtualized items have role="listitem" with aria-posinset and aria-setsize', () => {
    const items = Array.from({ length: 60 }, (_, i) =>
      makeDecryptedItem({ id: `item-${String(i)}`, name: `Item ${String(i)}` }),
    );
    useVaultStore.setState({ items });

    renderVaultList();

    const listItems = document.querySelectorAll('[role="listitem"]');
    expect(listItems.length).toBe(60);

    // Check first item
    expect(listItems[0]).toHaveAttribute('aria-posinset', '1');
    expect(listItems[0]).toHaveAttribute('aria-setsize', '60');

    // Check last item
    expect(listItems[59]).toHaveAttribute('aria-posinset', '60');
    expect(listItems[59]).toHaveAttribute('aria-setsize', '60');
  });

  it('non-virtualized list has role="list" and aria-label', () => {
    // Use fewer items than VIRTUALIZATION_THRESHOLD
    const items = [
      makeDecryptedItem({ id: 'item-1', name: 'Item 1' }),
      makeDecryptedItem({ id: 'item-2', name: 'Item 2' }),
    ];
    useVaultStore.setState({ items });

    renderVaultList();

    const list = document.querySelector('[role="list"]');
    expect(list).toBeInTheDocument();
    expect(list).toHaveAttribute('aria-label', 'Vault items list');
  });

  it('non-virtualized items have role="listitem" with aria-posinset and aria-setsize', () => {
    const items = [
      makeDecryptedItem({ id: 'item-1', name: 'Item 1' }),
      makeDecryptedItem({ id: 'item-2', name: 'Item 2' }),
      makeDecryptedItem({ id: 'item-3', name: 'Item 3' }),
    ];
    useVaultStore.setState({ items });

    renderVaultList();

    const listItems = document.querySelectorAll('[role="listitem"]');
    expect(listItems.length).toBe(3);

    expect(listItems[0]).toHaveAttribute('aria-posinset', '1');
    expect(listItems[0]).toHaveAttribute('aria-setsize', '3');

    expect(listItems[2]).toHaveAttribute('aria-posinset', '3');
    expect(listItems[2]).toHaveAttribute('aria-setsize', '3');
  });
});

// ==========================================================================
// 5.2 — Base32 Validation for TOTP Display
// ==========================================================================
//
// The former "5.2 — Base32 validation for TOTP display" block was removed here.
// It re-implemented the production `isValidBase32` helper locally and tested that
// hand-rolled copy (10 tests), plus one source-grep test asserting the regex text
// appears in VaultItemDetail.tsx — neither of which executes production code, so
// disabling the real guard (accepting any secret) would leave them all green.
// The REAL production behaviour is covered behaviourally by
// coverage-vault-item-detail.test.tsx, which renders VaultItemDetail's TotpDisplay
// with the real otpauth library and asserts: a valid base32 secret renders a live
// TOTP code, lower-case/whitespace secrets normalise, a length-not-multiple-of-8
// secret ('JBSWY3DP2') surfaces the "Invalid TOTP secret (not valid base32)" error
// panel with no copy button, and a non-base32-character secret ('JBSWY3D1') is
// likewise rejected.

// ==========================================================================
// 5.3 — Offline-to-Online Re-Fetch Mechanism
// ==========================================================================

describe('5.3 — Offline-to-online re-fetch mechanism', () => {
  function renderAppLayout(route = '/vault') {
    return render(
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/vault" element={<div>Vault Content</div>} />
          </Route>
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it('shows sync toast when going from offline to online', () => {
    renderAppLayout();

    act(() => {
      window.dispatchEvent(new Event('offline'));
    });

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Back online. Syncing your vault...',
        type: 'info',
      }),
    );
  });

  it('calls fetchItems and fetchFolders when coming back online', () => {
    const mockFetchItems = vi.fn().mockResolvedValue(undefined);
    const mockFetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      fetchItems: mockFetchItems,
      fetchFolders: mockFetchFolders,
    });

    renderAppLayout();

    act(() => {
      window.dispatchEvent(new Event('offline'));
    });

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(mockFetchItems).toHaveBeenCalled();
    expect(mockFetchFolders).toHaveBeenCalled();
  });

  it('does not re-fetch when vault is locked', () => {
    const mockFetchItems = vi.fn().mockResolvedValue(undefined);
    const mockFetchFolders = vi.fn().mockResolvedValue(undefined);
    useAuthStore.setState({ isLocked: true });
    useVaultStore.setState({
      fetchItems: mockFetchItems,
      fetchFolders: mockFetchFolders,
    });

    renderAppLayout();

    act(() => {
      window.dispatchEvent(new Event('offline'));
    });

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(mockFetchItems).not.toHaveBeenCalled();
    expect(mockFetchFolders).not.toHaveBeenCalled();
  });

  it('shows success toast after successful sync', async () => {
    const mockFetchItems = vi.fn().mockResolvedValue(undefined);
    const mockFetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      fetchItems: mockFetchItems,
      fetchFolders: mockFetchFolders,
    });

    renderAppLayout();

    await act(async () => {
      window.dispatchEvent(new Event('online'));
      // Allow the promise to resolve
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Vault synced successfully',
        type: 'success',
      }),
    );
  });

  it('shows error toast when sync fails', async () => {
    const mockFetchItems = vi.fn().mockRejectedValue(new Error('Network error'));
    const mockFetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      fetchItems: mockFetchItems,
      fetchFolders: mockFetchFolders,
    });

    renderAppLayout();

    await act(async () => {
      window.dispatchEvent(new Event('online'));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Failed to sync vault data',
        type: 'error',
      }),
    );
  });

  it('source code contains online re-fetch logic', () => {
    const src = readFileSync(pathResolve(clientSrcDir, 'components/layout/AppLayout.tsx'), 'utf8');
    expect(src).toContain('Back online. Syncing your vault...');
    expect(src).toContain('Vault synced successfully');
    expect(src).toContain('Failed to sync vault data');
    expect(src).toContain('fetchItems()');
    expect(src).toContain('fetchFolders()');
  });
});
