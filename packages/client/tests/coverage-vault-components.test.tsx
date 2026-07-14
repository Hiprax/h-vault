/**
 * Behavioural coverage for the vault UI components, targeting the branches the
 * existing suites never reach:
 *
 * 1 - VaultList: the REAL react-window virtualized path (>50 items), row-click
 *     selection while in multi-select mode, bulk move/tag/delete error paths,
 *     the sort menu (dateModified / type) and the sort-order toggle, the trash
 *     bulk-permanent-delete path and the empty-trash failure path.
 * 2 - FolderSidebar: the delete-folder "move vs delete items" choice, the
 *     context-menu roving focus, the upward drag-reorder direction and the
 *     type-filter toggle-off.
 * 3 - PasswordGenerator: clipboard failure paths (main + history) and using a
 *     history entry.
 * 4 - SearchBar: debounce coalescing and the external store→input clear sync.
 *
 * Unlike tests/vault-display-coverage.test.tsx this file deliberately does NOT
 * mock `react-window`: the virtualized branch is the one that ships to users
 * with a large vault, and a stub would never catch a regression in the aria
 * bookkeeping react-window supplies.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Hoisted mock fns
// ---------------------------------------------------------------------------

const {
  mockBulkDeleteApi,
  mockBulkMoveApi,
  mockPermanentDeleteApi,
  mockReorderFolderApi,
  mockToast,
  mockWriteText,
} = vi.hoisted(() => ({
  mockBulkDeleteApi: vi.fn().mockResolvedValue(undefined),
  mockBulkMoveApi: vi.fn().mockResolvedValue(undefined),
  mockPermanentDeleteApi: vi.fn().mockResolvedValue(undefined),
  mockReorderFolderApi: vi.fn().mockResolvedValue(undefined),
  mockToast: vi.fn(),
  mockWriteText: vi.fn().mockResolvedValue(undefined),
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
  permanentDeleteApi: (...args: unknown[]) => mockPermanentDeleteApi(...args),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
  reorderFolderApi: (...args: unknown[]) => mockReorderFolderApi(...args),
  bulkDeleteApi: (...args: unknown[]) => mockBulkDeleteApi(...args),
  bulkMoveApi: (...args: unknown[]) => mockBulkMoveApi(...args),
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
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
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

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: vi.fn().mockReturnValue({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

// ---------------------------------------------------------------------------
// jsdom polyfills required by the REAL react-window List
// ---------------------------------------------------------------------------

class StubResizeObserver {
  constructor(private readonly callback: ResizeObserverCallback) {}
  observe(target: Element): void {
    this.callback(
      [
        {
          target,
          contentRect: { height: 600, width: 400 },
          borderBoxSize: [{ blockSize: 600, inlineSize: 400 }],
          contentBoxSize: [{ blockSize: 600, inlineSize: 400 }],
          devicePixelContentBoxSize: [{ blockSize: 600, inlineSize: 400 }],
        } as unknown as ResizeObserverEntry,
      ],
      this as unknown as ResizeObserver,
    );
  }
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver = StubResizeObserver as unknown as typeof ResizeObserver;

Object.defineProperty(navigator, 'clipboard', {
  value: { writeText: mockWriteText, readText: vi.fn().mockResolvedValue('') },
  writable: true,
  configurable: true,
});

// ---------------------------------------------------------------------------
// Imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useVaultStore, type DecryptedVaultItem } from '../src/stores/vaultStore';
import { VaultList } from '../src/components/vault/VaultList';
import { FolderSidebar } from '../src/components/vault/FolderSidebar';
import { PasswordGenerator } from '../src/components/vault/PasswordGenerator';
import { SearchBar } from '../src/components/vault/SearchBar';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ItemType = DecryptedVaultItem['itemType'];

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter initialEntries={['/vault']}>{ui}</MemoryRouter>);
}

function makeItem(
  overrides: {
    id?: string;
    name?: string;
    itemType?: ItemType;
    favorite?: boolean;
    tags?: string[];
    folderId?: string;
    createdAt?: string;
    updatedAt?: string;
  } = {},
): DecryptedVaultItem {
  const now = '2024-01-01T00:00:00.000Z';
  const id = overrides.id ?? 'item-1';
  return {
    id,
    itemType: overrides.itemType ?? 'login',
    name: overrides.name ?? 'Test Item',
    favorite: overrides.favorite ?? false,
    tags: overrides.tags ?? [],
    folderId: overrides.folderId,
    data: { username: 'u', password: 'p', uris: [], customFields: [] },
    searchHash: 'abc',
    createdAt: overrides.createdAt ?? now,
    updatedAt: overrides.updatedAt ?? now,
  } as unknown as DecryptedVaultItem;
}

function makeFolder(overrides: { id?: string; name?: string; sortOrder?: number } = {}) {
  const now = '2024-01-01T00:00:00.000Z';
  const id = overrides.id ?? 'f1';
  return {
    id,
    name: overrides.name ?? 'Folder',
    sortOrder: overrides.sortOrder ?? 0,
    createdAt: now,
    updatedAt: now,
  };
}

// The store is a module-level singleton, so a test that swaps an action for a
// spy would leak it into every later test. Snapshot the pristine actions once
// and restore them on every reset.
const pristineVaultState = useVaultStore.getState();

/** Reset the real store to a clean, deterministic baseline. */
function resetVaultStore(patch: Record<string, unknown> = {}) {
  useVaultStore.setState({
    ...pristineVaultState,
    // The list eagerly re-fetches after a bulk mutation; without a vault key the
    // real fetch rejects, so stub the network-backed refreshes.
    fetchItems: vi.fn().mockResolvedValue(undefined),
    fetchTrashItems: vi.fn().mockResolvedValue(undefined),
    fetchFolders: vi.fn().mockResolvedValue(undefined),
    items: [],
    trashItems: [],
    folders: [],
    selectedFolder: null,
    selectedType: null,
    showFavorites: false,
    showTrash: false,
    searchQuery: '',
    filteredItemCount: null,
    sortBy: 'name',
    sortOrder: 'asc',
    loading: false,
    itemsLoading: false,
    trashLoading: false,
    itemsLoaded: 0,
    itemsTotal: null,
    ...patch,
  } as never);
}

/** Names of the rendered vault rows, in DOM order. */
function renderedItemNames(): string[] {
  return screen
    .getAllByRole('listitem')
    .map((li) => within(li).getByRole('button').textContent ?? '');
}

beforeEach(() => {
  vi.clearAllMocks();
  mockBulkDeleteApi.mockResolvedValue(undefined);
  mockBulkMoveApi.mockResolvedValue(undefined);
  mockPermanentDeleteApi.mockResolvedValue(undefined);
  mockReorderFolderApi.mockResolvedValue(undefined);
  mockWriteText.mockResolvedValue(undefined);
  resetVaultStore();
});

afterEach(() => {
  vi.useRealTimers();
});

// ===========================================================================
// VaultList — virtualized path (>50 items), driven through the REAL react-window
// ===========================================================================

describe('VaultList — virtualized rendering above the 50-item threshold', () => {
  function seedManyItems(count: number) {
    resetVaultStore({
      items: Array.from({ length: count }, (_, i) =>
        makeItem({ id: `i${String(i)}`, name: `Item ${String(i).padStart(3, '0')}` }),
      ),
    });
  }

  it('renders the rows inside a labelled list with the full aria-setsize/posinset bookkeeping', () => {
    seedManyItems(60);
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const list = screen.getByRole('list', { name: 'Vault items list' });
    expect(list).toHaveAttribute('id', 'vault-search-results');

    const rows = within(list).getAllByRole('listitem');
    // The virtualized window renders a subset — but every rendered row must
    // still advertise the FULL set size, or a screen reader announces
    // "1 of 9" for a 60-item vault.
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThan(60);
    for (const row of rows) {
      expect(row).toHaveAttribute('aria-setsize', '60');
    }
    const positions = rows.map((r) => Number(r.getAttribute('aria-posinset')));
    expect(positions[0]).toBe(1);
    // Positions are 1-based, contiguous and ascending.
    expect(positions).toEqual(positions.map((_, i) => i + 1));
  });

  it('shows the item content of the virtualized rows (first row is the first sorted item)', () => {
    seedManyItems(60);
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const rows = screen.getAllByRole('listitem');
    expect(within(rows[0]!).getByText('Item 000')).toBeInTheDocument();
  });

  it('stays on the non-virtualized path at exactly the 50-item threshold', () => {
    seedManyItems(50);
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    // Non-virtualized renders EVERY row; virtualization would render only a window.
    expect(screen.getAllByRole('listitem')).toHaveLength(50);
  });

  it('supports selecting a virtualized row via its checkbox', async () => {
    seedManyItems(60);
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);

    expect(await screen.findByText('1 selected')).toBeInTheDocument();
  });
});

// ===========================================================================
// VaultList — selection semantics
// ===========================================================================

describe('VaultList — multi-select mode', () => {
  beforeEach(() => {
    resetVaultStore({
      items: [
        makeItem({ id: 'a', name: 'Alpha' }),
        makeItem({ id: 'b', name: 'Bravo' }),
        makeItem({ id: 'c', name: 'Charlie' }),
      ],
    });
  });

  it('clicking a row body toggles selection instead of opening the item once multi-select is active', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    // Enter multi-select via the first row's checkbox.
    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    expect(screen.getByText('1 selected')).toBeInTheDocument();

    // Now a plain click on ANOTHER row must select it, not navigate away.
    fireEvent.click(screen.getByText('Bravo').closest('[role="button"]')!);

    expect(screen.getByText('2 selected')).toBeInTheDocument();
    expect(screen.getByText('Bravo')).toBeInTheDocument();
  });

  it('deselects a selected row and leaves multi-select mode when the last selection is cleared', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    expect(screen.getByText('1 selected')).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Deselect item'));

    expect(screen.queryByText(/selected$/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Move' })).not.toBeInTheDocument();
  });

  it('select-all selects every filtered row, and toggling it again clears the selection', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByLabelText('Select all'));
    expect(screen.getByText('3 selected')).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Deselect all'));
    expect(screen.queryByText(/selected$/)).not.toBeInTheDocument();
  });

  it('the Clear button drops the whole selection', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));

    expect(screen.queryByText(/selected$/)).not.toBeInTheDocument();
  });
});

// ===========================================================================
// VaultList — bulk actions
// ===========================================================================

describe('VaultList — bulk move', () => {
  beforeEach(() => {
    resetVaultStore({
      items: [makeItem({ id: 'a', name: 'Alpha' })],
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never,
    });
  });

  function selectFirstAndOpenMoveMenu() {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);
    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByRole('button', { name: 'Move' }));
  }

  it('moves the selection into the chosen folder and reports it by name', async () => {
    selectFirstAndOpenMoveMenu();

    fireEvent.click(screen.getByRole('menuitem', { name: 'Work' }));

    await waitFor(() => {
      expect(mockBulkMoveApi).toHaveBeenCalledWith(['a'], 'f1');
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Items moved to Work', type: 'success' }),
    );
  });

  it('moves the selection to the vault root when "No folder" is chosen', async () => {
    selectFirstAndOpenMoveMenu();

    fireEvent.click(screen.getByRole('menuitem', { name: 'No folder' }));

    await waitFor(() => {
      expect(mockBulkMoveApi).toHaveBeenCalledWith(['a'], null);
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Items moved', type: 'success' }),
    );
  });

  it('surfaces an error toast and keeps the selection when the move request fails', async () => {
    mockBulkMoveApi.mockRejectedValueOnce(new Error('network'));
    selectFirstAndOpenMoveMenu();

    fireEvent.click(screen.getByRole('menuitem', { name: 'Work' }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to move items', type: 'error' }),
      );
    });
    // The selection must survive a failure so the user can retry.
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('surfaces an error toast when the move-to-root request fails', async () => {
    mockBulkMoveApi.mockRejectedValueOnce(new Error('network'));
    selectFirstAndOpenMoveMenu();

    fireEvent.click(screen.getByRole('menuitem', { name: 'No folder' }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to move items', type: 'error' }),
      );
    });
  });

  it('closes the folder menu when focus leaves it', () => {
    selectFirstAndOpenMoveMenu();
    const moveButton = screen.getByRole('button', { name: 'Move' });
    expect(moveButton).toHaveAttribute('aria-expanded', 'true');

    // Blur out of the menu container entirely (relatedTarget outside it).
    fireEvent.blur(screen.getByRole('menu', { name: 'Move to folder' }), {
      relatedTarget: document.body,
    });

    expect(screen.queryByRole('menu', { name: 'Move to folder' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Move' })).toHaveAttribute('aria-expanded', 'false');
    expect(mockBulkMoveApi).not.toHaveBeenCalled();
  });
});

describe('VaultList — bulk tag', () => {
  const updateItemMeta = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    updateItemMeta.mockReset();
    updateItemMeta.mockResolvedValue(undefined);
    resetVaultStore({
      items: [
        makeItem({ id: 'a', name: 'Alpha', tags: ['existing'] }),
        makeItem({ id: 'b', name: 'Bravo', tags: [] }),
      ],
      updateItemMeta,
    });
  });

  function selectAllAndOpenTagMenu() {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);
    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByLabelText('Select all'));
    fireEvent.click(screen.getByRole('button', { name: 'Tag' }));
  }

  it('appends the tag only where it is missing — an item that already carries it is not duplicated', async () => {
    selectAllAndOpenTagMenu();

    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), {
      target: { value: '  existing  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

    await waitFor(() => {
      expect(updateItemMeta).toHaveBeenCalledTimes(2);
    });
    // Trimmed, and NOT appended twice to the item that already had it.
    expect(updateItemMeta).toHaveBeenCalledWith('a', { tags: ['existing'] });
    expect(updateItemMeta).toHaveBeenCalledWith('b', { tags: ['existing'] });
  });

  it('does not submit a whitespace-only tag', () => {
    selectAllAndOpenTagMenu();

    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), { target: { value: '   ' } });

    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    expect(updateItemMeta).not.toHaveBeenCalled();
  });

  it('surfaces an error toast when tagging fails', async () => {
    updateItemMeta.mockRejectedValueOnce(new Error('boom'));
    selectAllAndOpenTagMenu();

    fireEvent.change(screen.getByPlaceholderText('Enter tag name'), { target: { value: 'work' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to apply tags', type: 'error' }),
      );
    });
  });

  it('closes the tag popover when focus leaves it, applying nothing', () => {
    selectAllAndOpenTagMenu();
    const tagButton = screen.getByRole('button', { name: 'Tag' });
    expect(tagButton).toHaveAttribute('aria-expanded', 'true');

    fireEvent.blur(screen.getByPlaceholderText('Enter tag name').closest('.relative')!, {
      relatedTarget: document.body,
    });

    expect(screen.queryByPlaceholderText('Enter tag name')).not.toBeInTheDocument();
    expect(updateItemMeta).not.toHaveBeenCalled();
  });
});

describe('VaultList — bulk delete', () => {
  it('cancelling the confirmation dialog deletes nothing', () => {
    resetVaultStore({ items: [makeItem({ id: 'a', name: 'Alpha' })] });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

    const dialog = screen.getByRole('alertdialog', { name: 'Bulk delete confirmation' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(mockBulkDeleteApi).not.toHaveBeenCalled();
    expect(screen.getByText('1 selected')).toBeInTheDocument();
  });

  it('surfaces an error toast when the soft-delete request fails', async () => {
    mockBulkDeleteApi.mockRejectedValueOnce(new Error('nope'));
    resetVaultStore({ items: [makeItem({ id: 'a', name: 'Alpha' })] });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(within(dialog).getAllByRole('button', { name: 'Delete' })[0]!);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to delete items', type: 'error' }),
      );
    });
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('permanently deletes each selected item (one request per id) in the trash view', async () => {
    resetVaultStore({
      showTrash: true,
      trashItems: [makeItem({ id: 'a', name: 'Alpha' }), makeItem({ id: 'b', name: 'Bravo' })],
    });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    fireEvent.click(screen.getByLabelText('Select all'));
    // In trash the bulk button is labelled "Delete Forever".
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete Forever' })[0]!);

    const dialog = screen.getByRole('alertdialog', { name: 'Bulk delete confirmation' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete Forever' }));

    await waitFor(() => {
      expect(mockPermanentDeleteApi).toHaveBeenCalledTimes(2);
    });
    expect(mockPermanentDeleteApi).toHaveBeenCalledWith('a');
    expect(mockPermanentDeleteApi).toHaveBeenCalledWith('b');
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: '2 items permanently deleted', type: 'success' }),
    );
  });
});

describe('VaultList — empty trash', () => {
  it('surfaces an error toast and keeps the trash rows when emptying fails', async () => {
    const emptyTrash = vi.fn().mockRejectedValue(new Error('server'));
    resetVaultStore({
      showTrash: true,
      trashItems: [makeItem({ id: 'a', name: 'Alpha' })],
      emptyTrash,
    });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Empty Trash/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete All Forever' }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to empty trash', type: 'error' }),
      );
    });
    // The dialog stays open on failure so the user can retry.
    expect(
      screen.getByRole('alertdialog', { name: 'Empty trash confirmation' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Alpha')).toBeInTheDocument();
  });

  it('closes the confirmation dialog when the backdrop is clicked, without emptying', () => {
    const emptyTrash = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({
      showTrash: true,
      trashItems: [makeItem({ id: 'a', name: 'Alpha' })],
      emptyTrash,
    });
    const { container } = renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Empty Trash/ }));
    const backdrop = container.querySelector('.fixed.inset-0')!;
    fireEvent.click(backdrop);

    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(emptyTrash).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// VaultList — sorting
// ===========================================================================

describe('VaultList — sorting', () => {
  beforeEach(() => {
    resetVaultStore({
      items: [
        makeItem({
          id: 'a',
          name: 'Alpha',
          itemType: 'secret',
          createdAt: '2024-01-03T00:00:00.000Z',
          updatedAt: '2024-01-01T00:00:00.000Z',
        }),
        makeItem({
          id: 'b',
          name: 'Bravo',
          itemType: 'card',
          createdAt: '2024-01-01T00:00:00.000Z',
          updatedAt: '2024-01-03T00:00:00.000Z',
        }),
        makeItem({
          id: 'c',
          name: 'Charlie',
          itemType: 'login',
          createdAt: '2024-01-02T00:00:00.000Z',
          updatedAt: '2024-01-02T00:00:00.000Z',
        }),
      ],
    });
  });

  it('orders rows by last-modified date when "Date Modified" is picked', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Name/ }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Date Modified' }));

    // updatedAt: Alpha 01-01, Charlie 01-02, Bravo 01-03
    const names = renderedItemNames();
    expect(names[0]).toContain('Alpha');
    expect(names[1]).toContain('Charlie');
    expect(names[2]).toContain('Bravo');
  });

  it('orders rows by creation date when "Date Created" is picked', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Name/ }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Date Created' }));

    // createdAt: Bravo 01-01, Charlie 01-02, Alpha 01-03
    const names = renderedItemNames();
    expect(names[0]).toContain('Bravo');
    expect(names[1]).toContain('Charlie');
    expect(names[2]).toContain('Alpha');
  });

  it('orders rows by item type when "Type" is picked', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Name/ }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Type' }));

    // itemType asc: card (Bravo), login (Charlie), secret (Alpha)
    const names = renderedItemNames();
    expect(names[0]).toContain('Bravo');
    expect(names[1]).toContain('Charlie');
    expect(names[2]).toContain('Alpha');
  });

  it('closes the sort menu when focus leaves it, leaving the sort unchanged', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    fireEvent.click(screen.getByRole('button', { name: /Name/ }));
    expect(screen.getByRole('menu', { name: 'Sort options' })).toBeInTheDocument();

    fireEvent.blur(screen.getByRole('menu', { name: 'Sort options' }), {
      relatedTarget: document.body,
    });

    expect(screen.queryByRole('menu', { name: 'Sort options' })).not.toBeInTheDocument();
    expect(useVaultStore.getState().sortBy).toBe('name');
    expect(renderedItemNames()[0]).toContain('Alpha');
  });

  it('reverses the order when the sort-direction button is toggled to descending', () => {
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    expect(renderedItemNames()[0]).toContain('Alpha');

    fireEvent.click(screen.getByRole('button', { name: 'Sort descending' }));

    const names = renderedItemNames();
    expect(names[0]).toContain('Charlie');
    expect(names[2]).toContain('Alpha');
    // The control now offers the way back.
    expect(screen.getByRole('button', { name: 'Sort ascending' })).toBeInTheDocument();
  });
});

// ===========================================================================
// VaultList — type badges/icons + progress badge
// ===========================================================================

describe('VaultList — item type presentation', () => {
  it('labels every item type with its own badge', () => {
    resetVaultStore({
      items: [
        makeItem({ id: '1', name: 'L', itemType: 'login' }),
        makeItem({ id: '2', name: 'N', itemType: 'note' }),
        makeItem({ id: '3', name: 'C', itemType: 'card' }),
        makeItem({ id: '4', name: 'I', itemType: 'identity' }),
        makeItem({ id: '5', name: 'S', itemType: 'secret' }),
      ],
    });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    for (const label of ['Login', 'Note', 'Card', 'Identity', 'Secret']) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });
});

describe('VaultList — progressive loading badge', () => {
  it('announces decrypt progress while later pages are still arriving', () => {
    resetVaultStore({
      items: [makeItem({ id: 'a', name: 'Alpha' })],
      loading: true,
      itemsLoading: true,
      itemsLoaded: 1,
      itemsTotal: 5,
    });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    // Rows are already visible (no skeleton) AND the badge reports progress.
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByTestId('vault-loading-progress')).toHaveTextContent('Loading 1 / 5');
  });

  it('hides the badge once loading finishes', () => {
    resetVaultStore({
      items: [makeItem({ id: 'a', name: 'Alpha' })],
      itemsLoading: false,
      itemsLoaded: 5,
      itemsTotal: 5,
    });
    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    expect(screen.queryByTestId('vault-loading-progress')).not.toBeInTheDocument();
  });
});

// ===========================================================================
// FolderSidebar
// ===========================================================================

describe('FolderSidebar — delete folder "move vs delete items" choice', () => {
  function openDeleteDialog() {
    renderWithRouter(<FolderSidebar />);
    fireEvent.contextMenu(screen.getByText('Work').closest('button')!, {
      clientX: 10,
      clientY: 10,
    });
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    return screen.getByRole('alertdialog', { name: 'Delete folder confirmation' });
  }

  it('deletes the folder items too when the destructive radio is chosen', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ folders: [makeFolder({ id: 'f1', name: 'Work' })] as never, deleteFolder });

    const dialog = openDeleteDialog();
    // Default is the non-destructive "move to root".
    expect(within(dialog).getByLabelText('Move items to root (no folder)')).toBeChecked();

    fireEvent.click(within(dialog).getByLabelText('Delete items with the folder'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('f1', 'delete');
    });
  });

  it('moves the items to the root by default', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ folders: [makeFolder({ id: 'f1', name: 'Work' })] as never, deleteFolder });

    const dialog = openDeleteDialog();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('f1', 'move');
    });
  });

  it('cancelling the dialog deletes nothing', () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ folders: [makeFolder({ id: 'f1', name: 'Work' })] as never, deleteFolder });

    const dialog = openDeleteDialog();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(deleteFolder).not.toHaveBeenCalled();
  });

  it('lets the user change their mind back from the destructive option', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ folders: [makeFolder({ id: 'f1', name: 'Work' })] as never, deleteFolder });

    const dialog = openDeleteDialog();
    fireEvent.click(within(dialog).getByLabelText('Delete items with the folder'));
    fireEvent.click(within(dialog).getByLabelText('Move items to root (no folder)'));

    expect(within(dialog).getByLabelText('Delete items with the folder')).not.toBeChecked();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('f1', 'move');
    });
  });

  it('resets the destructive choice back to "move" for the next folder', async () => {
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({
      folders: [
        makeFolder({ id: 'f1', name: 'Work' }),
        makeFolder({ id: 'f2', name: 'Home', sortOrder: 1 }),
      ] as never,
      deleteFolder,
    });

    renderWithRouter(<FolderSidebar />);

    // First delete: choose the destructive option.
    fireEvent.contextMenu(screen.getByText('Work').closest('button')!, { clientX: 1, clientY: 1 });
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    let dialog = screen.getByRole('alertdialog');
    fireEvent.click(within(dialog).getByLabelText('Delete items with the folder'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('f1', 'delete');
    });

    // Second delete: the destructive choice must NOT be sticky.
    fireEvent.contextMenu(screen.getByText('Home').closest('button')!, { clientX: 1, clientY: 1 });
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    dialog = screen.getByRole('alertdialog');
    expect(within(dialog).getByLabelText('Move items to root (no folder)')).toBeChecked();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(deleteFolder).toHaveBeenLastCalledWith('f2', 'move');
    });
  });
});

describe('FolderSidebar — nested tree ordering', () => {
  it('renders a parent’s children in sortOrder, independent of the array order', () => {
    resetVaultStore({
      folders: [
        makeFolder({ id: 'p', name: 'Parent', sortOrder: 0 }),
        { ...makeFolder({ id: 'c2', name: 'Zulu', sortOrder: 1 }), parentId: 'p' },
        { ...makeFolder({ id: 'c1', name: 'Yankee', sortOrder: 0 }), parentId: 'p' },
      ] as never,
    });
    renderWithRouter(<FolderSidebar />);

    const body = document.body.textContent ?? '';
    // Yankee (sortOrder 0) must precede Zulu (sortOrder 1) even though the
    // flat list holds them the other way round.
    expect(body.indexOf('Yankee')).toBeGreaterThan(-1);
    expect(body.indexOf('Yankee')).toBeLessThan(body.indexOf('Zulu'));
  });
});

describe('FolderSidebar — context menu roving focus', () => {
  beforeEach(() => {
    resetVaultStore({ folders: [makeFolder({ id: 'f1', name: 'Work' })] as never });
  });

  function openMenu() {
    renderWithRouter(<FolderSidebar />);
    fireEvent.contextMenu(screen.getByText('Work').closest('button')!, { clientX: 5, clientY: 5 });
    return screen.getByRole('menu');
  }

  it('focuses the first menu item on open', () => {
    openMenu();
    expect(document.activeElement).toHaveTextContent('Rename');
  });

  it('ArrowDown moves to the next item and wraps back to the first', () => {
    const menu = openMenu();

    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toHaveTextContent('Delete');

    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toHaveTextContent('Rename');
  });

  it('ArrowUp from the first item wraps to the last', () => {
    const menu = openMenu();

    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(document.activeElement).toHaveTextContent('Delete');
  });
});

describe('FolderSidebar — drag reorder direction', () => {
  it('dragging a folder UP inserts it before the drop target', async () => {
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({
      folders: [
        makeFolder({ id: 'f1', name: 'One', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Two', sortOrder: 1 }),
        makeFolder({ id: 'f3', name: 'Three', sortOrder: 2 }),
      ] as never,
      fetchFolders,
    });
    renderWithRouter(<FolderSidebar />);

    const dataTransfer = { effectAllowed: '', dropEffect: '', setData: vi.fn(), getData: vi.fn() };
    fireEvent.dragStart(screen.getByText('Three').closest('button')!, { dataTransfer });
    fireEvent.dragOver(screen.getByText('One').closest('button')!, { dataTransfer });
    fireEvent.drop(screen.getByText('One').closest('button')!, { dataTransfer });

    // Result order must be Three, One, Two.
    await waitFor(() => {
      expect(mockReorderFolderApi).toHaveBeenCalledTimes(3);
    });
    expect(mockReorderFolderApi).toHaveBeenCalledWith('f3', 0);
    expect(mockReorderFolderApi).toHaveBeenCalledWith('f1', 1);
    expect(mockReorderFolderApi).toHaveBeenCalledWith('f2', 2);
    expect(fetchFolders).toHaveBeenCalled();
  });

  it('dropping onto a folder that is not a sibling is a no-op', () => {
    resetVaultStore({
      folders: [
        makeFolder({ id: 'f1', name: 'Root', sortOrder: 0 }),
        { ...makeFolder({ id: 'f2', name: 'Child', sortOrder: 0 }), parentId: 'f1' },
      ] as never,
    });
    renderWithRouter(<FolderSidebar />);

    const dataTransfer = { effectAllowed: '', dropEffect: '', setData: vi.fn(), getData: vi.fn() };
    // Root is not in Child's sibling set, so the insertion index cannot be found.
    fireEvent.dragStart(screen.getByText('Child').closest('button')!, { dataTransfer });
    fireEvent.drop(screen.getByText('Root').closest('button')!, { dataTransfer });

    expect(mockReorderFolderApi).not.toHaveBeenCalled();
  });
});

describe('FolderSidebar — filter toggles', () => {
  it('clicking the already-active type filter clears it', () => {
    const setSelectedType = vi.fn();
    resetVaultStore({ selectedType: 'login', setSelectedType });
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Logins'));

    expect(setSelectedType).toHaveBeenCalledWith(null);
  });

  it('shows the favourites badge only once at least one item is starred', () => {
    resetVaultStore({
      items: [
        makeItem({ id: 'a', name: 'A', favorite: true }),
        makeItem({ id: 'b', name: 'B', favorite: true }),
        makeItem({ id: 'c', name: 'C', favorite: false }),
      ],
    });
    renderWithRouter(<FolderSidebar />);

    const favBtn = screen.getByText('Favorites').closest('button')!;
    expect(within(favBtn).getByText('2')).toBeInTheDocument();
  });
});

describe('FolderSidebar — new folder dialog dismissal', () => {
  it('closes and discards the typed name when the backdrop is clicked', () => {
    const createFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ createFolder });
    const { container } = renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    fireEvent.change(screen.getByPlaceholderText('Folder name'), { target: { value: 'Draft' } });

    fireEvent.click(container.querySelector('.fixed.inset-0')!);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(createFolder).not.toHaveBeenCalled();

    // Re-opening starts from an empty field, not the discarded draft.
    fireEvent.click(screen.getByLabelText('Create folder'));
    expect(screen.getByPlaceholderText('Folder name')).toHaveValue('');
  });

  it('Cancel discards the typed name', () => {
    const createFolder = vi.fn().mockResolvedValue(undefined);
    resetVaultStore({ createFolder });
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    fireEvent.change(screen.getByPlaceholderText('Folder name'), { target: { value: 'Draft' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(createFolder).not.toHaveBeenCalled();
    fireEvent.click(screen.getByLabelText('Create folder'));
    expect(screen.getByPlaceholderText('Folder name')).toHaveValue('');
  });
});

// ===========================================================================
// PasswordGenerator
// ===========================================================================

describe('PasswordGenerator — clipboard failures and history reuse', () => {
  async function renderGenerator(props: Parameters<typeof PasswordGenerator>[0] = {}) {
    vi.useFakeTimers();
    await act(async () => {
      render(<PasswordGenerator {...props} />);
    });
    await act(async () => {
      vi.advanceTimersByTime(100);
    });
  }

  it('surfaces an error toast when the clipboard write is rejected', async () => {
    mockWriteText.mockRejectedValueOnce(new Error('denied'));
    await renderGenerator();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy password' }));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to copy', type: 'error' }),
    );
  });

  it('surfaces an error toast when copying a history entry is rejected', async () => {
    await renderGenerator();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^History \(/ }));
    });

    mockWriteText.mockRejectedValueOnce(new Error('denied'));
    const copyButtons = screen.getAllByRole('button', { name: 'Copy password' });
    await act(async () => {
      fireEvent.click(copyButtons[copyButtons.length - 1]!);
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to copy', type: 'error' }),
    );
  });

  it('hands the exact history entry back to onSelect when its "Use" button is pressed', async () => {
    const onSelect = vi.fn();
    await renderGenerator({ onSelect });

    // Regenerate so the history holds an entry that is NOT the current password.
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Regenerate password' }));
    });
    await act(async () => {
      vi.advanceTimersByTime(100);
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^History \(2\)/ }));
    });

    const historyRows = screen.getAllByRole('button', { name: 'Use' });
    const olderEntry = historyRows[1]!.closest('div')!.querySelector('code')!.textContent!;

    await act(async () => {
      fireEvent.click(historyRows[1]!);
    });

    expect(onSelect).toHaveBeenCalledWith(olderEntry);
  });
});

// ===========================================================================
// SearchBar
// ===========================================================================

describe('SearchBar — debounce and external clear', () => {
  it('coalesces rapid keystrokes into a single store update carrying the last value', () => {
    vi.useFakeTimers();
    resetVaultStore();

    render(<SearchBar />);
    const input = screen.getByLabelText('Search vault items');

    fireEvent.change(input, { target: { value: 'gi' } });
    act(() => {
      vi.advanceTimersByTime(200);
    });
    fireEvent.change(input, { target: { value: 'git' } });
    act(() => {
      vi.advanceTimersByTime(200);
    });
    fireEvent.change(input, { target: { value: 'github' } });

    // Nothing has reached the store yet — each keystroke cancelled the pending timer,
    // so the 300 ms window never elapsed despite 400 ms of typing.
    expect(useVaultStore.getState().searchQuery).toBe('');

    act(() => {
      vi.advanceTimersByTime(300);
    });

    expect(useVaultStore.getState().searchQuery).toBe('github');
  });

  it('mirrors the store query into the input on mount, and clears it when the store is cleared', () => {
    resetVaultStore({ searchQuery: 'github' });

    render(<SearchBar />);
    const input = screen.getByLabelText('Search vault items');
    expect(input).toHaveValue('github');

    act(() => {
      useVaultStore.getState().setSearchQuery('');
    });

    expect(input).toHaveValue('');
    expect(screen.queryByLabelText('Clear search')).not.toBeInTheDocument();
  });

  it('renders the filtered result count published by VaultList', () => {
    resetVaultStore({ searchQuery: 'a', filteredItemCount: 0 });
    render(<SearchBar />);

    expect(screen.getByText('0 results')).toBeInTheDocument();
  });
});
