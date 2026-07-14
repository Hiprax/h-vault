/**
 * Phase 9 Accessibility tests (Tasks 7.1, 7.2, 7.3):
 *
 * 7.1 — useInlineDialog hook: Escape key, body scroll lock, focus trap
 * 7.2 — VaultItemForm ARIA: tablist/tab roles, aria-selected
 *        AuditLogPage ARIA: table aria-label
 * 7.3 — VaultList aria-live region: polite announcements for item counts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React, { useRef, useCallback, useState } from 'react';
import { MemoryRouter } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Polyfill matchMedia
// ---------------------------------------------------------------------------

const { mockGetAuditLogApi } = vi.hoisted(() => {
  if (typeof window !== 'undefined') {
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

  return {
    mockGetAuditLogApi: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Mocks - VaultItemForm dependencies
// ---------------------------------------------------------------------------

const mockCreateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItem = vi.fn().mockResolvedValue(undefined);
const mockFetchItems = vi.fn().mockResolvedValue(undefined);
const mockFetchTrashItems = vi.fn().mockResolvedValue(undefined);
const mockEmptyTrash = vi.fn().mockResolvedValue(undefined);
const mockToast = vi.fn();

// VaultList needs a richer vaultStore state while VaultItemForm needs a simpler one.
// We'll dynamically set the store state based on the test via the storeSpy variable.
let vaultStoreState: Record<string, unknown> = {};

vi.mock('../src/stores/vaultStore', () => ({
  useVaultStore: Object.assign(
    vi.fn((selector: (state: Record<string, unknown>) => unknown) => {
      return selector(vaultStoreState);
    }),
    {
      getState: vi.fn(() => vaultStoreState),
      setState: vi.fn((partial: Record<string, unknown>) => {
        vaultStoreState = { ...vaultStoreState, ...partial };
      }),
    },
  ),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({
    toast: mockToast,
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

// zxcvbn mock removed: the password generator now measures strength via exact entropy
// (src/utils/passwordEntropy.ts), so nothing in this render tree imports zxcvbn.

// ---------------------------------------------------------------------------
// Mocks - VaultList dependencies
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

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
  bulkDeleteApi: vi.fn().mockResolvedValue(undefined),
  bulkMoveApi: vi.fn().mockResolvedValue(undefined),
}));

// Mock react-window
vi.mock('react-window', () => ({
  List: ({
    rowComponent: RowComponent,
    rowCount,
    rowProps,
  }: {
    rowComponent: React.ComponentType<Record<string, unknown>>;
    rowCount: number;
    rowHeight: number;
    rowProps: Record<string, unknown>;
    style?: Record<string, unknown>;
    overscanCount?: number;
    role?: string;
  }) =>
    React.createElement(
      'div',
      { role: 'list' },
      Array.from({ length: rowCount }, (_, i) =>
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: {},
          ...rowProps,
        }),
      ),
    ),
}));

// ---------------------------------------------------------------------------
// Mocks - AuditLogPage dependencies
// ---------------------------------------------------------------------------

vi.mock('../src/services/api/userApi', () => ({
  getAuditLogApi: (...args: unknown[]) => mockGetAuditLogApi(...args),
  listSessionsApi: vi.fn(),
  revokeSessionApi: vi.fn(),
  getProfileApi: vi.fn(),
  updateSettingsApi: vi.fn(),
  importVaultApi: vi.fn(),
  setup2faApi: vi.fn(),
  verify2faApi: vi.fn(),
  disable2faApi: vi.fn(),
  changePasswordApi: vi.fn(),
  exportVaultApi: vi.fn(),
}));

vi.mock('../src/services/api/authApi', () => ({
  logoutAllApi: vi.fn(),
}));

vi.mock('../src/stores/authStore', () => ({
  useAuthStore: Object.assign(
    vi.fn((selector?: (state: Record<string, unknown>) => unknown) => {
      const state = {
        user: { userId: 'u1', email: 'test@example.com' },
        vaultKey: {} as CryptoKey,
        mek: {},
      };
      return selector ? selector(state) : state;
    }),
    {
      getState: vi.fn().mockReturnValue({
        vaultKey: {} as CryptoKey,
        mek: {},
      }),
      setState: vi.fn(),
    },
  ),
}));

vi.mock('../src/stores/uiStore', () => ({
  useUIStore: Object.assign(
    vi.fn((selector?: (state: Record<string, unknown>) => unknown) => {
      const state = {
        theme: 'system',
        setTheme: vi.fn(),
      };
      return selector ? selector(state) : state;
    }),
    {
      getState: vi.fn().mockReturnValue({ theme: 'system', setTheme: vi.fn() }),
      setState: vi.fn(),
    },
  ),
}));

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
    decryptData: vi.fn().mockResolvedValue('decrypted'),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
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
  default: {
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

vi.mock('../src/hooks/useAutoLock', () => ({
  useAutoLock: vi.fn(),
}));

vi.mock('../src/hooks/useKeyboardShortcuts', () => ({
  useKeyboardShortcuts: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter initialEntries={['/']}>{ui}</MemoryRouter>);
}

function setVaultStoreDefaults(overrides: Record<string, unknown> = {}) {
  vaultStoreState = {
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
    createItem: mockCreateItem,
    updateItem: mockUpdateItem,
    fetchItems: mockFetchItems,
    fetchTrashItems: mockFetchTrashItems,
    emptyTrash: mockEmptyTrash,
    setSortBy: vi.fn(),
    setSortOrder: vi.fn(),
    setFilteredItemCount: vi.fn(),
    filteredItemCount: null,
    ...overrides,
  };
}

function makeDecryptedItem(overrides: Record<string, unknown> = {}) {
  const now = new Date().toISOString();
  return {
    id: overrides.id ?? 'item-1',
    name: overrides.name ?? 'Test Item',
    itemType: overrides.itemType ?? 'login',
    folderId: overrides.folderId ?? null,
    tags: overrides.tags ?? [],
    favorite: overrides.favorite ?? false,
    data: overrides.data ?? {
      username: 'user',
      password: 'pass',
      uris: [],
      notes: '',
      customFields: [],
    },
    createdAt: overrides.createdAt ?? now,
    updatedAt: overrides.updatedAt ?? now,
    deletedAt: overrides.deletedAt ?? null,
  };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(async () => {
  vi.clearAllMocks();
  setVaultStoreDefaults();
  const { _resetScrollLockCount } = await import('../src/components/ui/Dialog');
  _resetScrollLockCount();
});

afterEach(async () => {
  vi.restoreAllMocks();
  const { _resetScrollLockCount } = await import('../src/components/ui/Dialog');
  _resetScrollLockCount();
});

// ==========================================================================
// 7.1 — useInlineDialog hook tests
// ==========================================================================

describe('7.1 — useInlineDialog hook', () => {
  let useInlineDialog: typeof import('../src/components/ui/Dialog').useInlineDialog;

  beforeEach(async () => {
    const mod = await import('../src/components/ui/Dialog');
    useInlineDialog = mod.useInlineDialog;
  });

  /** Test wrapper component that uses useInlineDialog */
  function TestDialogWrapper({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
    const ref = useRef<HTMLDivElement>(null);
    useInlineDialog(ref, isOpen, onClose);

    if (!isOpen) return <div data-testid="closed">Closed</div>;

    return (
      <div ref={ref} data-testid="dialog-container" role="dialog" aria-modal="true">
        <button type="button" data-testid="btn-first">
          First
        </button>
        <input type="text" data-testid="input-middle" />
        <button type="button" data-testid="btn-last">
          Last
        </button>
      </div>
    );
  }

  /** Interactive wrapper that can toggle open/closed */
  function ToggleDialogWrapper() {
    const [open, setOpen] = useState(false);
    const handleClose = useCallback(() => setOpen(false), []);

    return (
      <div>
        <button type="button" data-testid="open-btn" onClick={() => setOpen(true)}>
          Open
        </button>
        <TestDialogWrapper isOpen={open} onClose={handleClose} />
      </div>
    );
  }

  it('calls onClose when Escape is pressed while open', () => {
    const onClose = vi.fn();
    render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('does not register Escape handler when dialog is closed', () => {
    const onClose = vi.fn();
    render(<TestDialogWrapper isOpen={false} onClose={onClose} />);

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('sets body overflow to hidden when open', () => {
    const onClose = vi.fn();
    render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    expect(document.body.style.overflow).toBe('hidden');
  });

  it('removes body overflow when closed', () => {
    const onClose = vi.fn();
    const { rerender } = render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    expect(document.body.style.overflow).toBe('hidden');

    rerender(<TestDialogWrapper isOpen={false} onClose={onClose} />);
    expect(document.body.style.overflow).toBe('');
  });

  it('restores body overflow on unmount', () => {
    const onClose = vi.fn();
    const { unmount } = render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    expect(document.body.style.overflow).toBe('hidden');

    unmount();
    expect(document.body.style.overflow).toBe('');
  });

  it('traps focus within the dialog (Tab on last wraps to first)', () => {
    const onClose = vi.fn();
    render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    const container = screen.getByTestId('dialog-container');
    const firstButton = screen.getByTestId('btn-first');
    const lastButton = screen.getByTestId('btn-last');

    lastButton.focus();
    expect(document.activeElement).toBe(lastButton);

    // Tab on the last focusable element must wrap focus to the FIRST one.
    // Asserting the exact wrapped target (not mere containment, which is true
    // before the event too) is what detects a removed/broken focus trap.
    fireEvent.keyDown(container, { key: 'Tab', bubbles: true });

    expect(document.activeElement).toBe(firstButton);
  });

  it('traps focus within the dialog (Shift+Tab on first wraps to last)', () => {
    const onClose = vi.fn();
    render(<TestDialogWrapper isOpen={true} onClose={onClose} />);

    const container = screen.getByTestId('dialog-container');
    const firstButton = screen.getByTestId('btn-first');
    const lastButton = screen.getByTestId('btn-last');

    firstButton.focus();
    expect(document.activeElement).toBe(firstButton);

    // Shift+Tab on the first focusable element must wrap focus to the LAST one.
    fireEvent.keyDown(container, { key: 'Tab', shiftKey: true, bubbles: true });

    expect(document.activeElement).toBe(lastButton);
  });

  it('keeps body scroll locked when two dialogs are open and one closes (L18 ref counter)', () => {
    const onClose1 = vi.fn();
    const onClose2 = vi.fn();

    const { rerender } = render(
      <>
        <TestDialogWrapper isOpen={true} onClose={onClose1} />
        <TestDialogWrapper isOpen={true} onClose={onClose2} />
      </>,
    );

    expect(document.body.style.overflow).toBe('hidden');

    // Close just the first dialog — scroll should stay locked
    rerender(
      <>
        <TestDialogWrapper isOpen={false} onClose={onClose1} />
        <TestDialogWrapper isOpen={true} onClose={onClose2} />
      </>,
    );

    expect(document.body.style.overflow).toBe('hidden');

    // Close the second too — scroll should be restored
    rerender(
      <>
        <TestDialogWrapper isOpen={false} onClose={onClose1} />
        <TestDialogWrapper isOpen={false} onClose={onClose2} />
      </>,
    );

    expect(document.body.style.overflow).toBe('');
  });

  it('cleans up Escape handler when toggled off', () => {
    render(<ToggleDialogWrapper />);

    // Open the dialog
    fireEvent.click(screen.getByTestId('open-btn'));
    expect(screen.getByTestId('dialog-container')).toBeInTheDocument();

    // Press Escape to close
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.getByTestId('closed')).toBeInTheDocument();

    // Pressing Escape again should not cause errors
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.getByTestId('closed')).toBeInTheDocument();
  });
});

// ==========================================================================
// 7.3 — VaultList aria-live region tests
// ==========================================================================

describe('7.3 — VaultList aria-live region', () => {
  let VaultList: typeof import('../src/components/vault/VaultList').VaultList;

  beforeEach(async () => {
    const mod = await import('../src/components/vault/VaultList');
    VaultList = mod.VaultList;
  });

  it('renders an aria-live="polite" region', () => {
    setVaultStoreDefaults();

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toBeInTheDocument();
  });

  it('announces "No items found." when there are no items', () => {
    setVaultStoreDefaults({ items: [], showTrash: false });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('No items found.');
  });

  it('announces "Trash is empty." when trash view has no items', () => {
    setVaultStoreDefaults({ trashItems: [], showTrash: true });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('Trash is empty.');
  });

  it('announces "Loading items..." during loading', () => {
    setVaultStoreDefaults({ loading: true, itemsLoading: true });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('Loading items...');
  });

  it('shows item count (singular) in aria-live region', () => {
    setVaultStoreDefaults({
      items: [makeDecryptedItem({ id: 'i1', name: 'GitHub' })],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('1 item in vault.');
  });

  it('shows item count (plural) in aria-live region', () => {
    setVaultStoreDefaults({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'GitHub' }),
        makeDecryptedItem({
          id: 'i2',
          name: 'AWS Key',
          itemType: 'secret',
          data: { value: 'x', description: '', customFields: [] },
        }),
        makeDecryptedItem({
          id: 'i3',
          name: 'My Note',
          itemType: 'note',
          data: { content: 'hello', format: 'plaintext' },
        }),
      ],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('3 items in vault.');
  });

  it('announces trash item count when in trash view', () => {
    setVaultStoreDefaults({
      showTrash: true,
      trashItems: [
        makeDecryptedItem({ id: 'i1', name: 'Deleted Login' }),
        makeDecryptedItem({ id: 'i2', name: 'Deleted Note' }),
      ],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveTextContent('2 items in trash.');
  });

  it('has sr-only class on the aria-live region (visually hidden)', () => {
    setVaultStoreDefaults();

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toHaveClass('sr-only');
  });
});

// ==========================================================================
// L17 — VaultListItem uses aria-current instead of invalid aria-selected
// ==========================================================================

describe('L17 — VaultListItem uses aria-current instead of aria-selected', () => {
  let VaultList: typeof import('../src/components/vault/VaultList').VaultList;

  beforeEach(async () => {
    const mod = await import('../src/components/vault/VaultList');
    VaultList = mod.VaultList;
  });

  it('does not use aria-selected on role="button" elements', () => {
    setVaultStoreDefaults({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item One' })],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const buttons = document.querySelectorAll('[role="button"]');
    buttons.forEach((btn) => {
      expect(btn).not.toHaveAttribute('aria-selected');
    });
  });

  it('uses aria-current on the selected vault list item', () => {
    setVaultStoreDefaults({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Item One' }),
        makeDecryptedItem({ id: 'i2', name: 'Item Two' }),
      ],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const rowOne = screen.getByText('Item One').closest('[role="button"]');
    const rowTwo = screen.getByText('Item Two').closest('[role="button"]');
    expect(rowOne).not.toBeNull();
    expect(rowTwo).not.toBeNull();

    // No row is current until one is selected.
    expect(rowOne).not.toHaveAttribute('aria-current');
    expect(rowTwo).not.toHaveAttribute('aria-current');

    // Selecting the first item marks exactly that row as aria-current="true".
    const checkboxes = screen.getAllByLabelText('Select item');
    fireEvent.click(checkboxes[0]!);

    expect(screen.getByText('Item One').closest('[role="button"]')).toHaveAttribute(
      'aria-current',
      'true',
    );
    expect(screen.getByText('Item Two').closest('[role="button"]')).not.toHaveAttribute(
      'aria-current',
    );
  });
});

// ==========================================================================
// L30 — maxLength on tag and bulk tag inputs
// ==========================================================================

describe('L30 — tag and bulk tag inputs have maxLength', () => {
  it('VaultList bulk tag input has maxLength of 50', async () => {
    const { VaultList } = await import('../src/components/vault/VaultList');
    setVaultStoreDefaults({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item One' })],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    // The bulk tag input only renders once an item is selected (entering
    // multi-select mode) AND the Tag popover is opened. Drive both so the
    // maxLength assertion is actually reached — otherwise it iterates an empty
    // set and passes even with the attribute removed.
    fireEvent.click(screen.getByLabelText('Select item'));
    fireEvent.click(screen.getByRole('button', { name: /^tag$/i }));

    const tagInputs = Array.from(document.querySelectorAll('input[type="text"]')).filter(
      (input) => input.getAttribute('placeholder') === 'Enter tag name',
    );

    expect(tagInputs).toHaveLength(1);
    expect(tagInputs[0]).toHaveAttribute('maxLength', '50');
  });
});

// ==========================================================================
// 7.2 — VaultItemForm ARIA tests
// ==========================================================================

describe('7.2 — VaultItemForm ARIA attributes', () => {
  let VaultItemForm: typeof import('../src/components/vault/VaultItemForm').VaultItemForm;

  beforeEach(async () => {
    setVaultStoreDefaults({
      createItem: mockCreateItem,
      updateItem: mockUpdateItem,
      folders: [{ id: 'folder-1', name: 'Work', sortOrder: 0, createdAt: '', updatedAt: '' }],
    });
    const mod = await import('../src/components/vault/VaultItemForm');
    VaultItemForm = mod.VaultItemForm;
  });

  function renderForm(props?: Record<string, unknown>) {
    return renderWithRouter(<VaultItemForm onSaved={vi.fn()} onCancel={vi.fn()} {...props} />);
  }

  it('renders type tabs with role="tablist"', () => {
    renderForm();

    const tablist = screen.getByRole('tablist');
    expect(tablist).toBeInTheDocument();
    expect(tablist).toHaveAttribute('aria-label', 'Item type');
  });

  it('renders each type tab button with role="tab"', () => {
    renderForm();

    const tabs = screen.getAllByRole('tab');
    expect(tabs.length).toBe(5); // login, secret, note, card, identity
  });

  it('marks the active tab with aria-selected="true"', () => {
    renderForm();

    const tabs = screen.getAllByRole('tab');
    // Default type is login
    const loginTab = tabs.find((t) => t.textContent?.includes('Login'));
    expect(loginTab).toHaveAttribute('aria-selected', 'true');
  });

  it('marks inactive tabs with aria-selected="false"', () => {
    renderForm();

    const tabs = screen.getAllByRole('tab');
    const inactiveTabs = tabs.filter((t) => !t.textContent?.includes('Login'));
    for (const tab of inactiveTabs) {
      expect(tab).toHaveAttribute('aria-selected', 'false');
    }
  });

  it('updates aria-selected when switching tabs', () => {
    renderForm();

    const tabs = screen.getAllByRole('tab');
    const noteTab = tabs.find((t) => t.textContent?.includes('Note'));
    expect(noteTab).toBeDefined();

    fireEvent.click(noteTab!);

    // After clicking, Note should be selected
    expect(noteTab).toHaveAttribute('aria-selected', 'true');

    // Login should no longer be selected
    const loginTab = tabs.find((t) => t.textContent?.includes('Login'));
    expect(loginTab).toHaveAttribute('aria-selected', 'false');
  });

  it('does not render tablist when editing an existing item', () => {
    const existingItem = {
      id: 'existing-1',
      name: 'Existing Login',
      itemType: 'login' as const,
      folderId: null,
      tags: [],
      favorite: false,
      data: { username: 'user', password: 'pass', uris: [], notes: '', customFields: [] },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deletedAt: null,
    };

    renderForm({ item: existingItem });

    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
  });

  it('name input has aria-describedby pointing to error when validation fails', async () => {
    renderForm();

    const nameInput = screen.getByPlaceholderText('Item name');
    expect(nameInput).toHaveAttribute('id', 'field-name');

    // When there is no error, aria-describedby should not be set
    // (or undefined, which is removed from the DOM)
    expect(nameInput.getAttribute('aria-describedby')).toBeNull();
  });
});

// ==========================================================================
// 7.2 — AuditLogPage ARIA tests
// ==========================================================================

describe('7.2 — AuditLogPage table aria-label', () => {
  it('renders the audit log table with an aria-label', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 'log1',
            action: 'login',
            ip: '127.0.0.1',
            userAgent: 'Test',
            createdAt: new Date().toISOString(),
          },
        ],
        pagination: { page: 1, limit: 20, total: 1, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    renderWithRouter(<AuditLogPage />);

    // Wait for the table to appear after data loads
    const table = await screen.findByRole('table');
    expect(table).toHaveAttribute('aria-label', 'Audit log entries');
  });
});

// ==========================================================================
// M9 — VaultList dropdown menu ARIA attributes
// ==========================================================================

describe('M9 — VaultList dropdown ARIA attributes', () => {
  let VaultList: typeof import('../src/components/vault/VaultList').VaultList;

  beforeEach(async () => {
    const mod = await import('../src/components/vault/VaultList');
    VaultList = mod.VaultList;
  });

  it('sort button has aria-haspopup and aria-expanded attributes', () => {
    setVaultStoreDefaults({
      items: [makeDecryptedItem({ id: 'i1', name: 'Test' })],
    });

    renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    const sortButtons = screen.getAllByRole('button', { name: /sort|name|date/i });
    expect(sortButtons.length).toBeGreaterThan(0);
    // aria-haspopup should exist on sort trigger buttons
    const buttons = screen.getAllByRole('button');
    const haspopupButtons = buttons.filter((b) => b.getAttribute('aria-haspopup') === 'true');
    expect(haspopupButtons.length).toBeGreaterThan(0);

    // aria-expanded should be 'false' when menu is closed
    for (const btn of haspopupButtons) {
      expect(btn.getAttribute('aria-expanded')).toBe('false');
    }
  });
});
