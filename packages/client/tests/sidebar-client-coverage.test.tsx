/**
 * Comprehensive coverage tests for:
 *
 * 1 - FolderSidebar.tsx (tree building, selection, expand/collapse, context menu,
 *     create/rename/delete folder, drag-and-drop, keyboard reorder, color change)
 * 2 - client.ts (CSRF management, request/response interceptors, token refresh,
 *     queuing, cross-tab CSRF invalidation, force logout)
 * 3 - AppLayout.tsx (sidebar toggle, mobile responsive, lock/logout, offline,
 *     degraded storage cross-tab, keyboard shortcuts integration)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom
// ---------------------------------------------------------------------------

vi.hoisted(() => {
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
});

// ---------------------------------------------------------------------------
// Hoisted mock references
// ---------------------------------------------------------------------------

const { mockReorderFolderApi } = vi.hoisted(() => ({
  mockReorderFolderApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

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
  reorderFolderApi: (...args: unknown[]) => mockReorderFolderApi(...args),
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

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({
    toast: vi.fn(),
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

// ---------------------------------------------------------------------------
// Store imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useUIStore } from '../src/stores/uiStore';
import { isStorageDegraded } from '../src/stores/encryptedStorage';
import { useAutoLock } from '../src/hooks/useAutoLock';
import { useKeyboardShortcuts } from '../src/hooks/useKeyboardShortcuts';
import { useToast } from '../src/components/ui/Toast';

// ---------------------------------------------------------------------------
// Component imports
// ---------------------------------------------------------------------------

import { FolderSidebar } from '../src/components/vault/FolderSidebar';
import { AppLayout } from '../src/components/layout/AppLayout';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement, { route = '/' } = {}) {
  return render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>);
}

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

function makeFolder(
  overrides: Partial<{
    id: string;
    name: string;
    sortOrder: number;
    parentId: string;
    color: string;
    icon: string;
  }> = {},
) {
  const now = new Date().toISOString();
  const id = overrides.id ?? 'f1';
  return {
    id,
    name: overrides.name ?? 'Test Folder',
    sortOrder: overrides.sortOrder ?? 0,
    parentId: overrides.parentId,
    color: overrides.color,
    icon: overrides.icon,
    createdAt: now,
    updatedAt: now,
    _raw: {
      _id: id,
      userId: 'u1',
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: overrides.sortOrder ?? 0,
      parentId: overrides.parentId,
      color: overrides.color,
      icon: overrides.icon,
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
// 1 - FolderSidebar
// ==========================================================================

describe('FolderSidebar - tree building and nested hierarchy', () => {
  it('builds a tree from a flat list of folders with parent-child relationships', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Root A', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Child of A', sortOrder: 0, parentId: 'f1' }),
        makeFolder({ id: 'f3', name: 'Root B', sortOrder: 1 }),
        makeFolder({ id: 'f4', name: 'Grandchild', sortOrder: 0, parentId: 'f2' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('Root A')).toBeInTheDocument();
    expect(screen.getByText('Child of A')).toBeInTheDocument();
    expect(screen.getByText('Root B')).toBeInTheDocument();
    expect(screen.getByText('Grandchild')).toBeInTheDocument();
  });

  it('sorts root folders by sortOrder', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Second', sortOrder: 1 }),
        makeFolder({ id: 'f2', name: 'First', sortOrder: 0 }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderButtons = screen
      .getAllByRole('button')
      .filter((btn) => btn.textContent?.includes('First') || btn.textContent?.includes('Second'));
    expect(folderButtons.length).toBe(2);
    // First should come before Second in DOM order
    const allText = document.body.textContent ?? '';
    expect(allText.indexOf('First')).toBeLessThan(allText.indexOf('Second'));
  });

  it('treats folders with missing parentId reference as root folders', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Orphan', sortOrder: 0, parentId: 'nonexistent' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('Orphan')).toBeInTheDocument();
  });
});

describe('FolderSidebar - folder selection and highlighting', () => {
  it('highlights the selected folder with aria-current="page"', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      selectedFolder: 'f1',
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button');
    expect(folderBtn).toHaveAttribute('aria-current', 'page');
  });

  it('highlights "All Items" when no folder, type, favorite, or trash is selected', () => {
    renderWithRouter(<FolderSidebar />);

    const allItemsBtn = screen.getByText('All Items').closest('button');
    expect(allItemsBtn).toHaveAttribute('aria-current', 'page');
  });

  it('does not highlight "All Items" when a folder is selected', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      selectedFolder: 'f1',
    });

    renderWithRouter(<FolderSidebar />);

    const allItemsBtn = screen.getByText('All Items').closest('button');
    expect(allItemsBtn).not.toHaveAttribute('aria-current');
  });

  it('calls onClose callback when a folder is selected', () => {
    const onClose = vi.fn();
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar onClose={onClose} />);

    fireEvent.click(screen.getByText('Work'));

    expect(onClose).toHaveBeenCalled();
  });
});

describe('FolderSidebar - expand/collapse nested folders', () => {
  it('shows children of a folder by default (expanded)', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Parent', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Child', sortOrder: 0, parentId: 'f1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('Child')).toBeInTheDocument();
  });

  it('collapses children when the expand/collapse chevron is clicked', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Parent', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Child', sortOrder: 0, parentId: 'f1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('Child')).toBeInTheDocument();

    const collapseBtn = screen.getByLabelText('Collapse folder');
    fireEvent.click(collapseBtn);

    expect(screen.queryByText('Child')).not.toBeInTheDocument();
  });

  it('re-expands children when the expand chevron is clicked again', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Parent', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Child', sortOrder: 0, parentId: 'f1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const collapseBtn = screen.getByLabelText('Collapse folder');
    fireEvent.click(collapseBtn);
    expect(screen.queryByText('Child')).not.toBeInTheDocument();

    const expandBtn = screen.getByLabelText('Expand folder');
    fireEvent.click(expandBtn);
    expect(screen.getByText('Child')).toBeInTheDocument();
  });
});

describe('FolderSidebar - type filter buttons', () => {
  it('highlights type filter with aria-current when selected', () => {
    useVaultStore.setState({ selectedType: 'note' });

    renderWithRouter(<FolderSidebar />);

    const noteBtn = screen.getByText('Notes').closest('button');
    expect(noteBtn).toHaveAttribute('aria-current', 'page');
  });

  it('shows correct type counts for each type', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', itemType: 'login' }),
        makeDecryptedItem({ id: 'i2', itemType: 'login' }),
        makeDecryptedItem({ id: 'i3', itemType: 'card' }),
        makeDecryptedItem({ id: 'i4', itemType: 'identity' }),
        makeDecryptedItem({ id: 'i5', itemType: 'secret' }),
        makeDecryptedItem({ id: 'i6', itemType: 'note' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    // Scope each count to its own type-filter row so a mis-mapped count (e.g.
    // Cards showing 2 and Logins showing 1) is caught — a free-floating
    // getByText('2') / getAllByText('1') passes for ANY assignment that keeps
    // one "2" and four "1"s.
    const row = (label: string) => within(screen.getByText(label).closest('button')!);

    expect(row('Logins').getByText('2')).toBeInTheDocument();
    expect(row('Secrets').getByText('1')).toBeInTheDocument();
    expect(row('Notes').getByText('1')).toBeInTheDocument();
    expect(row('Cards').getByText('1')).toBeInTheDocument();
    expect(row('Identities').getByText('1')).toBeInTheDocument();
  });

  it('calls onClose when a type filter is clicked', () => {
    const onClose = vi.fn();
    renderWithRouter(<FolderSidebar onClose={onClose} />);

    fireEvent.click(screen.getByText('Notes'));

    expect(onClose).toHaveBeenCalled();
  });
});

describe('FolderSidebar - favorites toggle', () => {
  it('highlights Favorites when showFavorites is true', () => {
    useVaultStore.setState({ showFavorites: true });

    renderWithRouter(<FolderSidebar />);

    const favBtn = screen.getByText('Favorites').closest('button');
    expect(favBtn).toHaveAttribute('aria-current', 'page');
  });

  it('does not show favorites badge when count is 0', () => {
    useVaultStore.setState({ items: [] });

    renderWithRouter(<FolderSidebar />);

    // All Items shows "0", but Favorites should not show a badge
    const favBtn = screen.getByText('Favorites').closest('button');
    const badges = favBtn?.querySelectorAll('.rounded-full');
    // There should be no badge child (the badge only renders when count > 0)
    const badgesWithNumber = Array.from(badges ?? []).filter(
      (el) => el.textContent && Number(el.textContent) > 0,
    );
    expect(badgesWithNumber.length).toBe(0);
  });

  it('calls onClose when favorites is toggled', () => {
    const onClose = vi.fn();
    renderWithRouter(<FolderSidebar onClose={onClose} />);

    fireEvent.click(screen.getByText('Favorites'));

    expect(onClose).toHaveBeenCalled();
  });
});

describe('FolderSidebar - trash toggle', () => {
  it('highlights Trash when showTrash is true', () => {
    useVaultStore.setState({ showTrash: true });

    renderWithRouter(<FolderSidebar />);

    const trashBtn = screen.getByText('Trash').closest('button');
    expect(trashBtn).toHaveAttribute('aria-current', 'page');
  });

  it('shows trash count badge', () => {
    useVaultStore.setState({
      trashItems: [
        makeDecryptedItem({ id: 'i1', name: 'Trash1' }),
        makeDecryptedItem({ id: 'i2', name: 'Trash2' }),
        makeDecryptedItem({ id: 'i3', name: 'Trash3' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('calls onClose when trash is toggled', () => {
    const onClose = vi.fn();
    renderWithRouter(<FolderSidebar onClose={onClose} />);

    fireEvent.click(screen.getByText('Trash'));

    expect(onClose).toHaveBeenCalled();
  });
});

describe('FolderSidebar - item count badges per folder', () => {
  it('shows item count for folders that contain items', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      items: [
        makeDecryptedItem({ id: 'i1', folderId: 'f1' }),
        makeDecryptedItem({ id: 'i2', folderId: 'f1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    // The folder should show count badge = 2
    // (All items = 2 also shows 2, so there should be two "2" badges)
    const twos = screen.getAllByText('2');
    expect(twos.length).toBeGreaterThanOrEqual(1);
  });

  it('does not show count badge when folder has 0 items', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Empty' })] as never[],
      items: [],
    });

    renderWithRouter(<FolderSidebar />);

    // The folder button exists but must render NO count badge at all. The badge
    // is the only `.rounded-full` descendant of a folder row, so querying for it
    // and expecting null catches a regression that renders the badge
    // unconditionally (even showing "0") for empty folders.
    const folderBtn = screen.getByText('Empty').closest('button');
    expect(folderBtn).toBeInTheDocument();
    expect(folderBtn!.querySelector('.rounded-full')).toBeNull();
  });
});

describe('FolderSidebar - create folder dialog', () => {
  it('creates a folder when name is entered and Create is clicked', async () => {
    const createFolder = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ createFolder });
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    const input = screen.getByPlaceholderText('Folder name');
    fireEvent.change(input, { target: { value: 'New Folder' } });
    fireEvent.click(screen.getByText('Create'));

    await waitFor(() => {
      expect(createFolder).toHaveBeenCalledWith('New Folder');
    });
  });

  it('does not create folder when name is empty', async () => {
    const createFolder = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ createFolder });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    // Leave the input empty
    fireEvent.click(screen.getByText('Create'));

    // createFolder should not be called because the button is disabled
    expect(createFolder).not.toHaveBeenCalled();
  });

  it('shows error toast when creating a folder with duplicate name', async () => {
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Existing' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    const input = screen.getByPlaceholderText('Folder name');
    fireEvent.change(input, { target: { value: 'existing' } }); // case-insensitive match
    fireEvent.click(screen.getByText('Create'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'A folder with this name already exists', type: 'error' }),
      );
    });
  });

  it('creates folder when Enter is pressed in the input', async () => {
    const createFolder = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ createFolder });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    const input = screen.getByPlaceholderText('Folder name');
    fireEvent.change(input, { target: { value: 'Quick Folder' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    await waitFor(() => {
      expect(createFolder).toHaveBeenCalledWith('Quick Folder');
    });
  });

  it('closes dialog when Escape is pressed in the input', () => {
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    expect(screen.getByPlaceholderText('Folder name')).toBeInTheDocument();

    fireEvent.keyDown(screen.getByPlaceholderText('Folder name'), { key: 'Escape' });

    expect(screen.queryByPlaceholderText('Folder name')).not.toBeInTheDocument();
  });

  it('shows error toast when createFolder throws', async () => {
    const createFolder = vi.fn().mockRejectedValue(new Error('Network error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({ createFolder });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    fireEvent.change(screen.getByPlaceholderText('Folder name'), { target: { value: 'New' } });
    fireEvent.click(screen.getByText('Create'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to create folder', type: 'error' }),
      );
    });
  });
});

describe('FolderSidebar - context menu', () => {
  it('opens context menu on right-click of a folder', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 200, clientY: 300 });

    expect(screen.getByText('Rename')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
    expect(screen.getByText('Color')).toBeInTheDocument();
  });

  it('closes context menu when clicking outside', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 200, clientY: 300 });
    expect(screen.getByText('Rename')).toBeInTheDocument();

    // Click outside (on document body)
    fireEvent.mouseDown(document.body);

    expect(screen.queryByText('Rename')).not.toBeInTheDocument();
  });

  it('closes context menu on Escape key', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 200, clientY: 300 });
    expect(screen.getByText('Rename')).toBeInTheDocument();

    const menu = screen.getByRole('menu');
    fireEvent.keyDown(menu, { key: 'Escape' });

    expect(screen.queryByText('Rename')).not.toBeInTheDocument();
  });

  it('navigates context menu items with ArrowDown/ArrowUp', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 200, clientY: 300 });

    const menu = screen.getByRole('menu');
    const menuItems = screen.getAllByRole('menuitem');
    expect(menuItems.length).toBe(2); // Rename and Delete

    // Navigate down
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    // Navigate up
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    // These should not throw and menu should still be open
    expect(screen.getByText('Rename')).toBeInTheDocument();
  });
});

describe('FolderSidebar - edit/rename folder', () => {
  it('opens rename dialog from context menu and renames a folder', async () => {
    const updateFolder = vi.fn().mockResolvedValue(undefined);
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      updateFolder,
    });

    renderWithRouter(<FolderSidebar />);

    // Right-click to open context menu
    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });

    // Click Rename
    fireEvent.click(screen.getByText('Rename'));

    // Rename dialog should open
    expect(screen.getByText('Rename Folder')).toBeInTheDocument();
    const renameInput = screen.getByPlaceholderText('New name');
    expect(renameInput).toHaveValue('Work');

    // Change name and submit
    fireEvent.change(renameInput, { target: { value: 'Personal' } });
    fireEvent.click(screen.getByText('Rename'));

    await waitFor(() => {
      expect(updateFolder).toHaveBeenCalledWith('f1', 'Personal');
    });
  });

  it('closes rename dialog when Cancel is clicked', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Rename'));

    expect(screen.getByText('Rename Folder')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel'));

    expect(screen.queryByText('Rename Folder')).not.toBeInTheDocument();
  });

  it('submits rename when Enter is pressed', async () => {
    const updateFolder = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      updateFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Rename'));

    const renameInput = screen.getByPlaceholderText('New name');
    fireEvent.change(renameInput, { target: { value: 'Updated' } });
    fireEvent.keyDown(renameInput, { key: 'Enter' });

    await waitFor(() => {
      expect(updateFolder).toHaveBeenCalledWith('f1', 'Updated');
    });
  });

  it('closes rename dialog when Escape is pressed', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Rename'));

    const renameInput = screen.getByPlaceholderText('New name');
    fireEvent.keyDown(renameInput, { key: 'Escape' });

    expect(screen.queryByText('Rename Folder')).not.toBeInTheDocument();
  });

  it('shows error toast when renaming to a duplicate name', async () => {
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Work' }),
        makeFolder({ id: 'f2', name: 'Personal', sortOrder: 1 }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Rename'));

    const renameInput = screen.getByPlaceholderText('New name');
    fireEvent.change(renameInput, { target: { value: 'personal' } }); // case-insensitive
    fireEvent.click(screen.getByText('Rename'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'A folder with this name already exists', type: 'error' }),
      );
    });
  });

  it('shows error toast when rename API throws', async () => {
    const updateFolder = vi.fn().mockRejectedValue(new Error('API error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      updateFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Rename'));

    fireEvent.change(screen.getByPlaceholderText('New name'), { target: { value: 'Updated' } });
    fireEvent.click(screen.getByText('Rename'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rename folder', type: 'error' }),
      );
    });
  });
});

describe('FolderSidebar - delete folder', () => {
  it('deletes a folder from context menu', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      deleteFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Delete'));

    // Confirm in the confirmation dialog
    const dialog = screen.getByRole('alertdialog');
    expect(dialog).toBeInTheDocument();
    fireEvent.click(screen.getAllByText('Delete').find((el) => dialog.contains(el))!);

    await waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('f1', 'move');
    });
  });

  it('clears selectedFolder when the deleted folder was selected', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    const setSelectedFolder = vi.fn();
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      deleteFolder,
      setSelectedFolder,
      selectedFolder: 'f1',
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Delete'));

    // Confirm in the confirmation dialog
    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(screen.getAllByText('Delete').find((el) => dialog.contains(el))!);

    await waitFor(() => {
      expect(setSelectedFolder).toHaveBeenCalledWith(null);
    });
  });

  it('shows error toast when deleteFolder throws', async () => {
    const deleteFolder = vi.fn().mockRejectedValue(new Error('Server error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      deleteFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });
    fireEvent.click(screen.getByText('Delete'));

    // Confirm in the confirmation dialog
    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(screen.getAllByText('Delete').find((el) => dialog.contains(el))!);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to delete folder', type: 'error' }),
      );
    });
  });
});

describe('FolderSidebar - folder color change', () => {
  it('applies color to a folder via context menu color picker', async () => {
    const updateFolder = vi.fn().mockResolvedValue(undefined);
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      updateFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });

    // Click a color swatch
    const colorButton = screen.getByLabelText('Set folder color to #3b82f6');
    fireEvent.click(colorButton);

    await waitFor(() => {
      expect(updateFolder).toHaveBeenCalledWith('f1', 'Work', { color: '#3b82f6' });
    });
  });

  it('displays folder color as left border on the folder button', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Colored', color: '#ef4444' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Colored').closest('button')!;
    // Browser normalizes hex to rgb format
    expect(folderBtn.style.borderLeft).toContain('3px solid');
  });
});

describe('FolderSidebar - drag-and-drop reordering', () => {
  it('handles dragStart, dragOver, and drop events on folder items', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
      fetchFolders,
    });

    renderWithRouter(<FolderSidebar />);

    const firstBtn = screen.getByText('First').closest('button')!;
    const secondBtn = screen.getByText('Second').closest('button')!;

    // Mock dataTransfer
    const dataTransfer = {
      effectAllowed: '',
      dropEffect: '',
      setData: vi.fn(),
      getData: vi.fn(),
    };

    fireEvent.dragStart(firstBtn, { dataTransfer });
    fireEvent.dragOver(secondBtn, { dataTransfer });
    fireEvent.drop(secondBtn, { dataTransfer });

    await waitFor(() => {
      expect(mockReorderFolderApi).toHaveBeenCalled();
    });
  });

  it('clears drag state on dragEnd (drop-target highlight is removed)', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const firstBtn = screen.getByText('First').closest('button')!;
    const secondBtn = screen.getByText('Second').closest('button')!;
    const dataTransfer = {
      effectAllowed: '',
      dropEffect: '',
      setData: vi.fn(),
      getData: vi.fn(),
    };

    // Begin dragging First over Second -> Second becomes the drop target and
    // gains the highlight ring (dragOverId === 'f2').
    fireEvent.dragStart(firstBtn, { dataTransfer });
    fireEvent.dragOver(secondBtn, { dataTransfer });
    expect(secondBtn.className).toContain('ring-2');

    // dragEnd (no drop) must clear dragOverId, removing the highlight. Without the
    // onDragEnd handler the ring would stick forever.
    const foldersSection = screen.getByText('Folders').closest('.flex-1');
    expect(foldersSection).toBeInTheDocument();
    fireEvent.dragEnd(foldersSection!);

    expect(secondBtn.className).not.toContain('ring-2');
  });
});

describe('FolderSidebar - keyboard reorder (Ctrl+Up/Down)', () => {
  it('reorders a folder up on Ctrl+ArrowUp', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
      fetchFolders,
    });

    renderWithRouter(<FolderSidebar />);

    const secondBtn = screen.getByText('Second').closest('button')!;
    fireEvent.keyDown(secondBtn, { key: 'ArrowUp', ctrlKey: true });

    await waitFor(() => {
      expect(mockReorderFolderApi).toHaveBeenCalled();
    });
  });

  it('reorders a folder down on Ctrl+ArrowDown', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
      fetchFolders,
    });

    renderWithRouter(<FolderSidebar />);

    const firstBtn = screen.getByText('First').closest('button')!;
    fireEvent.keyDown(firstBtn, { key: 'ArrowDown', ctrlKey: true });

    await waitFor(() => {
      expect(mockReorderFolderApi).toHaveBeenCalled();
    });
  });

  it('does not reorder when at the top and pressing Ctrl+ArrowUp', async () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'First', sortOrder: 0 })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const firstBtn = screen.getByText('First').closest('button')!;
    fireEvent.keyDown(firstBtn, { key: 'ArrowUp', ctrlKey: true });

    // Should not call reorder
    expect(mockReorderFolderApi).not.toHaveBeenCalled();
  });

  it('does not reorder when at the bottom and pressing Ctrl+ArrowDown', async () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Last', sortOrder: 0 })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const lastBtn = screen.getByText('Last').closest('button')!;
    fireEvent.keyDown(lastBtn, { key: 'ArrowDown', ctrlKey: true });

    expect(mockReorderFolderApi).not.toHaveBeenCalled();
  });
});

describe('FolderSidebar - "All Items" selection clears all filters', () => {
  it('clears selectedFolder, selectedType, showFavorites, showTrash on "All Items" click', () => {
    const setSelectedFolder = vi.fn();
    const setSelectedType = vi.fn();
    const setShowFavorites = vi.fn();
    const setShowTrash = vi.fn();

    useVaultStore.setState({
      selectedFolder: 'f1',
      selectedType: 'login',
      showFavorites: true,
      showTrash: true,
      setSelectedFolder,
      setSelectedType,
      setShowFavorites,
      setShowTrash,
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('All Items'));

    expect(setSelectedFolder).toHaveBeenCalledWith(null);
    expect(setSelectedType).toHaveBeenCalledWith(null);
    expect(setShowFavorites).toHaveBeenCalledWith(false);
    expect(setShowTrash).toHaveBeenCalledWith(false);
  });
});

describe('FolderSidebar - className and empty state', () => {
  it('accepts and applies a custom className', () => {
    const { container } = renderWithRouter(<FolderSidebar className="my-custom-class" />);

    const root = container.firstElementChild;
    expect(root?.classList.contains('my-custom-class')).toBe(true);
  });

  it('shows "No folders yet" message when folders array is empty', () => {
    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('No folders yet')).toBeInTheDocument();
  });
});

// ==========================================================================
// 2 - API Client (client.ts)
//
// NOTE: A "mocked module verification" describe block was removed here. This
// file mocks `../src/services/api/client` wholesale at the top, so those tests
// imported the vi.fn() stubs and asserted the STUBS were defined/callable —
// they never touched the real client.ts and could not fail if clearCsrfToken,
// the 401 refresh interceptor, or the whole module were deleted. The real
// interceptor behavior is covered by services-functional.test.ts and
// refresh-multitab.test.ts (neither mocks the client module).
// ==========================================================================

// Additional FolderSidebar tests targeting uncovered lines
describe('FolderSidebar - additional edge cases', () => {
  it('does not call onClose when onClose is not provided', () => {
    const setSelectedFolder = vi.fn();
    const setSelectedType = vi.fn();
    const setShowFavorites = vi.fn();
    const setShowTrash = vi.fn();

    useVaultStore.setState({
      setSelectedFolder,
      setSelectedType,
      setShowFavorites,
      setShowTrash,
    });

    // Render without onClose prop - should not throw
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('All Items'));
    expect(setSelectedFolder).toHaveBeenCalledWith(null);
  });

  it('handles drag-and-drop where source and target are the same folder (no-op)', async () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Only', sortOrder: 0 })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Only').closest('button')!;
    const dataTransfer = {
      effectAllowed: '',
      dropEffect: '',
      setData: vi.fn(),
      getData: vi.fn(),
    };

    // Drag and drop on the same element
    fireEvent.dragStart(folderBtn, { dataTransfer });
    fireEvent.dragOver(folderBtn, { dataTransfer });
    fireEvent.drop(folderBtn, { dataTransfer });

    // Should not call reorder since source === target
    expect(mockReorderFolderApi).not.toHaveBeenCalled();
  });

  it('shows correct allItemCount in the All Items badge', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', itemType: 'login' }),
        makeDecryptedItem({ id: 'i2', itemType: 'note' }),
        makeDecryptedItem({ id: 'i3', itemType: 'card' }),
        makeDecryptedItem({ id: 'i4', itemType: 'secret' }),
        makeDecryptedItem({ id: 'i5', itemType: 'identity' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    // All Items badge should show 5
    expect(screen.getByText('5')).toBeInTheDocument();
  });

  it('type filter click clears showFavorites and showTrash', () => {
    const setSelectedType = vi.fn();
    const setSelectedFolder = vi.fn();
    const setShowFavorites = vi.fn();
    const setShowTrash = vi.fn();

    useVaultStore.setState({
      showFavorites: true,
      showTrash: true,
      setSelectedType,
      setSelectedFolder,
      setShowFavorites,
      setShowTrash,
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Secrets'));

    expect(setShowFavorites).toHaveBeenCalledWith(false);
    expect(setShowTrash).toHaveBeenCalledWith(false);
    expect(setSelectedFolder).toHaveBeenCalledWith(null);
    expect(setSelectedType).toHaveBeenCalledWith('secret');
  });

  it('selecting a folder also clears selectedType', () => {
    const setSelectedFolder = vi.fn();
    const setSelectedType = vi.fn();

    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      selectedType: 'login',
      setSelectedFolder,
      setSelectedType,
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Work'));

    expect(setSelectedFolder).toHaveBeenCalledWith('f1');
    expect(setSelectedType).toHaveBeenCalledWith(null);
  });

  it('handles keyboard reorder error gracefully', async () => {
    mockReorderFolderApi.mockRejectedValueOnce(new Error('Server error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    const fetchFolders = vi.fn().mockResolvedValue(undefined);

    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
      fetchFolders,
    });

    renderWithRouter(<FolderSidebar />);

    const secondBtn = screen.getByText('Second').closest('button')!;
    fireEvent.keyDown(secondBtn, { key: 'ArrowUp', ctrlKey: true });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to reorder', type: 'error' }),
      );
    });
  });

  it('handles drag-and-drop reorder error gracefully', async () => {
    mockReorderFolderApi.mockRejectedValueOnce(new Error('Server error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    const fetchFolders = vi.fn().mockResolvedValue(undefined);

    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'First', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Second', sortOrder: 1 }),
      ] as never[],
      fetchFolders,
    });

    renderWithRouter(<FolderSidebar />);

    const firstBtn = screen.getByText('First').closest('button')!;
    const secondBtn = screen.getByText('Second').closest('button')!;

    const dataTransfer = {
      effectAllowed: '',
      dropEffect: '',
      setData: vi.fn(),
      getData: vi.fn(),
    };

    fireEvent.dragStart(firstBtn, { dataTransfer });
    fireEvent.dragOver(secondBtn, { dataTransfer });
    fireEvent.drop(secondBtn, { dataTransfer });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to reorder', type: 'error' }),
      );
    });
  });

  it('handles color change error gracefully', async () => {
    const updateFolder = vi.fn().mockRejectedValue(new Error('Server error'));
    const mockToast = vi.fn();
    vi.mocked(useToast).mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() });
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      updateFolder,
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });

    const colorButton = screen.getByLabelText('Set folder color to #ef4444');
    fireEvent.click(colorButton);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to update color', type: 'error' }),
      );
    });
  });

  it('renders all 8 color swatches in context menu', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    fireEvent.contextMenu(folderBtn, { clientX: 100, clientY: 100 });

    const colors = [
      '#3b82f6',
      '#ef4444',
      '#22c55e',
      '#f59e0b',
      '#8b5cf6',
      '#ec4899',
      '#06b6d4',
      '#f97316',
    ];
    for (const color of colors) {
      expect(screen.getByLabelText(`Set folder color to ${color}`)).toBeInTheDocument();
    }
  });

  it('folder with no children does not show expand/collapse button', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Leaf' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.queryByLabelText('Collapse folder')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Expand folder')).not.toBeInTheDocument();
  });

  it('folder button has aria-description for reorder hint', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    const folderBtn = screen.getByText('Work').closest('button')!;
    expect(folderBtn).toHaveAttribute('aria-description', 'Use Ctrl+Up or Ctrl+Down to reorder');
  });
});

// ==========================================================================
// 3 - AppLayout
// ==========================================================================

describe('AppLayout - comprehensive coverage', () => {
  function renderAppLayout(route = '/vault') {
    return render(
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/vault" element={<div>Vault Content</div>} />
            <Route path="/generator" element={<div>Generator Content</div>} />
            <Route path="/settings" element={<div>Settings Content</div>} />
          </Route>
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it('renders all navigation links', () => {
    renderAppLayout();

    expect(screen.getByText('Vault')).toBeInTheDocument();
    expect(screen.getByText('Password Generator')).toBeInTheDocument();
    expect(screen.getByText('File Encryption')).toBeInTheDocument();
    expect(screen.getByText('Vault Health')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('renders the File Encryption nav link pointing at /tools/file-encryption', () => {
    renderAppLayout();

    const link = screen.getByText('File Encryption').closest('a');
    expect(link).toHaveAttribute('href', '/tools/file-encryption');
  });

  it('renders the Outlet content for the current route', () => {
    renderAppLayout('/vault');
    expect(screen.getByText('Vault Content')).toBeInTheDocument();
  });

  it('displays user email when user is set', () => {
    renderAppLayout();

    const emailElements = screen.getAllByText('test@example.com');
    expect(emailElements.length).toBeGreaterThanOrEqual(1);
  });

  it('does not display user section when user is null', () => {
    useAuthStore.setState({ user: null });

    renderAppLayout();

    expect(screen.queryByText('test@example.com')).not.toBeInTheDocument();
  });

  it('renders Lock Vault and Logout buttons', () => {
    renderAppLayout();

    expect(screen.getByText('Lock Vault')).toBeInTheDocument();
    expect(screen.getByText('Logout')).toBeInTheDocument();
  });

  it('opens mobile sidebar when hamburger menu is clicked', () => {
    renderAppLayout();

    const hamburger = screen.getByLabelText('Open sidebar');
    fireEvent.click(hamburger);

    // When sidebar is open, a close button and overlay should appear
    const closeButtons = screen.getAllByLabelText('Close sidebar');
    expect(closeButtons.length).toBeGreaterThanOrEqual(1);
  });

  // The mobile sidebar's open/closed state is reflected by the <aside> translate
  // class: `translate-x-0` when open, `-translate-x-full` when closed. The overlay
  // (a button with aria-label "Close sidebar" and class `fixed inset-0`) only
  // renders while open. These helpers let each close test assert the actual result.
  const getAside = () => screen.getByText('H-Vault').closest('aside')!;
  const getOverlay = () =>
    screen.queryAllByLabelText('Close sidebar').find((b) => b.className.includes('fixed'));
  const getCloseX = () =>
    screen.getAllByLabelText('Close sidebar').find((b) => !b.className.includes('fixed'))!;

  it('closes mobile sidebar when the close (X) button is clicked', () => {
    renderAppLayout();

    fireEvent.click(screen.getByLabelText('Open sidebar'));
    expect(getAside().className).not.toContain('-translate-x-full');
    expect(getOverlay()).toBeDefined();

    fireEvent.click(getCloseX());

    // Sidebar is closed: aside slid off-screen and the overlay is gone.
    expect(getAside().className).toContain('-translate-x-full');
    expect(getOverlay()).toBeUndefined();
  });

  it('closes mobile sidebar when overlay is clicked', () => {
    renderAppLayout();

    fireEvent.click(screen.getByLabelText('Open sidebar'));
    const overlay = getOverlay();
    expect(overlay).toBeDefined();

    fireEvent.click(overlay!);

    expect(getAside().className).toContain('-translate-x-full');
    expect(getOverlay()).toBeUndefined();
  });

  it('closes mobile sidebar when Escape is pressed on overlay', () => {
    renderAppLayout();

    fireEvent.click(screen.getByLabelText('Open sidebar'));
    const overlay = getOverlay();
    expect(overlay).toBeDefined();

    fireEvent.keyDown(overlay!, { key: 'Escape' });

    expect(getAside().className).toContain('-translate-x-full');
    expect(getOverlay()).toBeUndefined();
  });

  it('shows Online indicator by default', () => {
    renderAppLayout();
    expect(screen.getByText('Online')).toBeInTheDocument();
  });

  it('shows Offline indicator when offline event fires', () => {
    renderAppLayout();

    act(() => {
      window.dispatchEvent(new Event('offline'));
    });

    expect(screen.getByText('Offline')).toBeInTheDocument();
  });

  it('shows Online again only once the server health probe succeeds', async () => {
    // Recovery is NOT driven by the browser's `online` event alone: that event just
    // triggers a probe of /api/v1/health, and the indicator flips back only when the
    // server actually answers. Going offline stays immediate, because an explicit
    // browser-offline signal supersedes any in-flight probe.
    renderAppLayout();

    act(() => {
      window.dispatchEvent(new Event('offline'));
    });
    expect(screen.getByText('Offline')).toBeInTheDocument();

    const healthOk = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 200 }));

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(await screen.findByText('Online')).toBeInTheDocument();
    healthOk.mockRestore();
  });

  it('shows degraded storage warning when isStorageDegraded returns true', () => {
    vi.mocked(isStorageDegraded).mockReturnValue(true);
    renderAppLayout();

    expect(screen.getByText(/does not support secure storage/i)).toBeInTheDocument();
  });

  it('does not show degraded storage warning when isStorageDegraded returns false', () => {
    vi.mocked(isStorageDegraded).mockReturnValue(false);
    renderAppLayout();

    expect(screen.queryByText(/does not support secure storage/i)).not.toBeInTheDocument();
  });

  it('updates storageDegraded state on cross-tab storage event', () => {
    vi.mocked(isStorageDegraded).mockReturnValue(false);
    renderAppLayout();

    expect(screen.queryByText(/does not support secure storage/i)).not.toBeInTheDocument();

    // Simulate cross-tab storage event setting degraded flag
    act(() => {
      const storageEvent = new StorageEvent('storage', {
        key: '__hv_storage_degraded',
        newValue: 'true',
      });
      window.dispatchEvent(storageEvent);
    });

    expect(screen.getByText(/does not support secure storage/i)).toBeInTheDocument();
  });

  it('calls useAutoLock hook', () => {
    renderAppLayout();
    expect(useAutoLock).toHaveBeenCalled();
  });

  it('calls useKeyboardShortcuts hook with lock shortcut', () => {
    renderAppLayout();
    expect(useKeyboardShortcuts).toHaveBeenCalled();
    const call = vi.mocked(useKeyboardShortcuts).mock.calls[0];
    expect(call?.[0]).toHaveProperty('l');
  });

  it('renders H-Vault brand text', () => {
    renderAppLayout();
    expect(screen.getByText('H-Vault')).toBeInTheDocument();
  });

  it('closes sidebar when a nav link is clicked', () => {
    renderAppLayout();

    // Open sidebar first
    fireEvent.click(screen.getByLabelText('Open sidebar'));
    expect(getAside().className).not.toContain('-translate-x-full');

    // Click a nav link -> navigates AND closes the mobile sidebar.
    fireEvent.click(screen.getByText('Settings'));

    expect(getAside().className).toContain('-translate-x-full');
    expect(getOverlay()).toBeUndefined();
  });

  it('calls lock() when Lock Vault button is clicked', () => {
    const lock = vi.fn().mockResolvedValue(undefined);
    useAuthStore.setState({ lock });

    renderAppLayout();
    fireEvent.click(screen.getByText('Lock Vault'));

    expect(lock).toHaveBeenCalled();
  });

  it('calls logout() and navigates to /login when Logout button is clicked', async () => {
    const logout = vi.fn().mockResolvedValue(undefined);
    useAuthStore.setState({ logout });

    renderAppLayout();
    fireEvent.click(screen.getByText('Logout'));

    expect(logout).toHaveBeenCalled();
    // handleLogout navigates to /login once logout() settles; the test router
    // renders "Login Page" for that route. Without the navigate('/login') call the
    // user would be stranded on the vault, so assert the redirect actually happens.
    expect(await screen.findByText('Login Page')).toBeInTheDocument();
  });

  it('hides collapse toggle button when sidebar is collapsed and not hovered', () => {
    useUIStore.setState({ sidebarCollapsed: true });
    renderAppLayout();

    const toggleButton = screen.getByLabelText('Expand sidebar');
    expect(toggleButton.className).toContain('opacity-0');
    expect(toggleButton.className).toContain('pointer-events-none');
  });

  it('shows collapse toggle button when sidebar is expanded', () => {
    useUIStore.setState({ sidebarCollapsed: false });
    renderAppLayout();

    const toggleButton = screen.getByLabelText('Collapse sidebar');
    expect(toggleButton.className).toContain('opacity-100');
    expect(toggleButton.className).not.toContain('pointer-events-none');
  });

  it('shows collapse toggle button when sidebar is collapsed but hovered', () => {
    useUIStore.setState({ sidebarCollapsed: true });
    renderAppLayout();

    // Hover over the sidebar to trigger temporary expansion
    const sidebar = screen.getByText('H-Vault').closest('aside')!;
    fireEvent.mouseEnter(sidebar);

    // aria-label remains "Expand sidebar" (based on sidebarCollapsed state),
    // but the button should be visible (opacity-100) because expanded = true on hover
    const toggleButton = screen.getByLabelText('Expand sidebar');
    expect(toggleButton.className).toContain('opacity-100');
    expect(toggleButton.className).not.toContain('pointer-events-none');
  });
});
