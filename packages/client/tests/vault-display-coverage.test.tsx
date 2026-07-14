/**
 * Deep coverage tests for vault display components with low or zero coverage.
 *
 * Covers:
 * 1 - VaultItemDetail (login, secret, note, card, identity rendering;
 *     copy/clipboard, masking, password history, favorite toggle, delete flow,
 *     restore flow, move-to-folder, tags, timestamps)
 * 2 - VaultList (empty state, item rendering, click-to-select, sort options,
 *     multi-select mode, bulk delete, bulk move, bulk tag, search filtering,
 *     type/favorites/folder/trash filtering, empty trash, FAB)
 * 3 - VaultItemPage (loading, not found, item display, edit mode)
 * 4 - GeneratorPage (heading, renders PasswordGenerator)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom
// ---------------------------------------------------------------------------

// vi.hoisted runs before test environment init. matchMedia is already polyfilled
// by tests/setup.ts. Guard with typeof to avoid ReferenceError in some runtimes.
vi.hoisted(() => {
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
});

// ---------------------------------------------------------------------------
// Hoisted mock fns
// ---------------------------------------------------------------------------

const {
  mockDeleteItem,
  mockPermanentDeleteItem,
  mockRestoreItem,
  mockUpdateItem,
  mockUpdateItemMeta,
  mockFetchItems,
  mockFetchTrashItems,
  mockEmptyTrash,
  mockBulkDeleteApi,
  mockBulkMoveApi,
  mockPermanentDeleteApi,
  mockToast,
} = vi.hoisted(() => ({
  mockDeleteItem: vi.fn().mockResolvedValue(undefined),
  mockPermanentDeleteItem: vi.fn().mockResolvedValue(undefined),
  mockRestoreItem: vi.fn().mockResolvedValue(undefined),
  mockUpdateItem: vi.fn().mockResolvedValue(undefined),
  mockUpdateItemMeta: vi.fn().mockResolvedValue(undefined),
  mockFetchItems: vi.fn().mockResolvedValue(undefined),
  mockFetchTrashItems: vi.fn().mockResolvedValue(undefined),
  mockEmptyTrash: vi.fn().mockResolvedValue(undefined),
  mockBulkDeleteApi: vi.fn().mockResolvedValue(undefined),
  mockBulkMoveApi: vi.fn().mockResolvedValue(undefined),
  mockPermanentDeleteApi: vi.fn().mockResolvedValue(undefined),
  mockToast: vi.fn(),
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
    decryptData: vi.fn().mockResolvedValue('decrypted-password'),
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
  permanentDeleteApi: (...args: unknown[]) => mockPermanentDeleteApi(...args),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
  reorderFolderApi: vi.fn(),
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

// Mock react-window
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
    const items = [];
    for (let i = 0; i < Math.min(rowCount, 20); i++) {
      items.push(
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: { height: rowHeight },
          ...rowProps,
        }),
      );
    }
    return React.createElement('div', { role: 'list', 'data-testid': 'virtual-list' }, ...items);
  },
}));

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 8) return { score: 2, feedback: { warning: '', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

vi.mock('../src/components/auth/UnlockScreen', () => ({
  UnlockScreen: () =>
    React.createElement('div', { 'data-testid': 'unlock-screen' }, 'Unlock Screen'),
}));

vi.mock('react-markdown', () => ({
  default: ({ children }: { children: string }) =>
    React.createElement('div', { 'data-testid': 'markdown-content' }, children),
}));

vi.mock('../src/components/layout/OnboardingGuide', () => ({
  OnboardingGuide: () => null,
}));

// Mock VaultItemForm for VaultItemPage tests
vi.mock('../src/components/vault/VaultItemForm', () => ({
  VaultItemForm: ({ onCancel, onSaved }: { onCancel?: () => void; onSaved?: () => void }) =>
    React.createElement(
      'div',
      { 'data-testid': 'vault-item-form' },
      React.createElement('button', { onClick: onCancel }, 'Cancel Form'),
      React.createElement('button', { onClick: onSaved }, 'Save Form'),
    ),
}));

// Mock PasswordGenerator for GeneratorPage
vi.mock('../src/components/vault/PasswordGenerator', () => ({
  PasswordGenerator: () =>
    React.createElement(
      'div',
      { 'data-testid': 'password-generator' },
      'Password Generator Component',
    ),
}));

// ---------------------------------------------------------------------------
// Store imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Component imports
// ---------------------------------------------------------------------------

import { VaultItemDetail } from '../src/components/vault/VaultItemDetail';
import { VaultList } from '../src/components/vault/VaultList';

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
    updatedAt: string;
    createdAt: string;
    passwordHistory: {
      encryptedPassword: string;
      iv: string;
      tag: string;
      changedAt: string;
    }[];
  }> = {},
) {
  const now = overrides.updatedAt ?? '2025-06-15T12:00:00.000Z';
  const created = overrides.createdAt ?? '2025-01-01T00:00:00.000Z';
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
    createdAt: created,
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
      passwordHistory: overrides.passwordHistory ?? [],
      createdAt: created,
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
  }> = {},
) {
  const now = new Date().toISOString();
  const id = overrides.id ?? 'f1';
  return {
    id,
    name: overrides.name ?? 'Test Folder',
    sortOrder: overrides.sortOrder ?? 0,
    parentId: overrides.parentId,
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
      createdAt: now,
      updatedAt: now,
    },
  };
}

// ---------------------------------------------------------------------------
// Store reset
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();

  useAuthStore.setState({
    accessToken: 'test-token',
    user: { userId: 'u1', email: 'test@example.com' },
    isAuthenticated: true,
    isLocked: false,
    vaultKey: {} as CryptoKey,
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
    deleteItem: mockDeleteItem,
    permanentDeleteItem: mockPermanentDeleteItem,
    restoreItem: mockRestoreItem,
    updateItem: mockUpdateItem,
    updateItemMeta: mockUpdateItemMeta,
    fetchItems: mockFetchItems,
    fetchTrashItems: mockFetchTrashItems,
    emptyTrash: mockEmptyTrash,
  });

  // Mock clipboard API
  Object.assign(navigator, {
    clipboard: {
      writeText: vi.fn().mockResolvedValue(undefined),
      readText: vi.fn().mockResolvedValue(''),
    },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ==========================================================================
// 1 - VaultItemDetail
// ==========================================================================

describe('VaultItemDetail', () => {
  const onEdit = vi.fn();

  beforeEach(() => {
    onEdit.mockClear();
  });

  // -----------------------------------------------------------------------
  // Login item rendering
  // -----------------------------------------------------------------------

  describe('Login item rendering', () => {
    it('renders username and password fields', () => {
      const item = makeDecryptedItem({
        name: 'GitHub Login',
        itemType: 'login',
        data: {
          username: 'octocat',
          password: 'gh-secret',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Username')).toBeInTheDocument();
      expect(screen.getByText('Password')).toBeInTheDocument();
      expect(screen.getByText('octocat')).toBeInTheDocument();
    });

    it('renders URIs as links', () => {
      const item = makeDecryptedItem({
        name: 'Multi URI',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [
            { uri: 'https://example.com', match: 'domain' },
            { uri: 'https://app.example.com', match: 'domain' },
          ],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('URI 1')).toBeInTheDocument();
      expect(screen.getByText('URI 2')).toBeInTheDocument();

      const links = screen.getAllByRole('link');
      expect(links.length).toBe(2);
      expect(links[0]).toHaveAttribute('href', 'https://example.com');
      expect(links[1]).toHaveAttribute('href', 'https://app.example.com');
    });

    it('renders unsafe URIs as plain text instead of links', () => {
      const item = makeDecryptedItem({
        name: 'Unsafe URI',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [
            { uri: 'javascript:alert(1)', match: 'domain' },
            { uri: 'data:text/html,<script>alert(1)</script>', match: 'domain' },
            { uri: 'https://safe.example.com', match: 'domain' },
          ],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Safe URI should be a link
      const links = screen.getAllByRole('link');
      expect(links.length).toBe(1);
      expect(links[0]).toHaveAttribute('href', 'https://safe.example.com');

      // Unsafe URIs should be rendered as plain text (not links)
      expect(screen.getByText('URI 1')).toBeInTheDocument();
      expect(screen.getByText('URI 2')).toBeInTheDocument();
    });

    it('renders mailto: URIs as safe links', () => {
      const item = makeDecryptedItem({
        name: 'Mailto URI',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [{ uri: 'mailto:user@example.com', match: 'domain' }],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const links = screen.getAllByRole('link');
      expect(links.length).toBe(1);
      expect(links[0]).toHaveAttribute('href', 'mailto:user@example.com');
    });

    it('renders vbscript: and ftp: URIs as plain text', () => {
      const item = makeDecryptedItem({
        name: 'Other Unsafe URIs',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [
            { uri: 'vbscript:MsgBox("XSS")', match: 'domain' },
            { uri: 'ftp://files.example.com', match: 'domain' },
            { uri: 'http://safe.example.com', match: 'domain' },
          ],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Only http: URI should be a link
      const links = screen.getAllByRole('link');
      expect(links.length).toBe(1);
      expect(links[0]).toHaveAttribute('href', 'http://safe.example.com');

      // vbscript and ftp should be plain text
      expect(screen.getByText('URI 1')).toBeInTheDocument();
      expect(screen.getByText('URI 2')).toBeInTheDocument();
    });

    it('renders TOTP display when totp is provided', () => {
      const item = makeDecryptedItem({
        name: 'TOTP Login',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: 'JBSWY3DPEHPK3PXP',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('TOTP Code')).toBeInTheDocument();
    });

    it('renders notes when provided', () => {
      const item = makeDecryptedItem({
        name: 'Notes Login',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: 'Remember to rotate this password monthly',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Notes')).toBeInTheDocument();
    });

    it('renders custom fields of type text', () => {
      const item = makeDecryptedItem({
        name: 'Custom Fields Login',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [{ name: 'Recovery Email', value: 'recovery@test.com', type: 'text' }],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Recovery Email')).toBeInTheDocument();
      expect(screen.getByText('recovery@test.com')).toBeInTheDocument();
    });

    it('renders custom fields of type hidden as masked', () => {
      const item = makeDecryptedItem({
        name: 'Hidden Field Login',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [{ name: 'Secret Token', value: 'abc123', type: 'hidden' }],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Secret Token')).toBeInTheDocument();
      // Hidden fields have a reveal button
      expect(screen.getAllByLabelText('Reveal value').length).toBeGreaterThanOrEqual(1);
    });

    it('renders boolean custom fields with Yes/No text', () => {
      const item = makeDecryptedItem({
        name: 'Bool Fields Login',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [
            { name: 'Is Admin', value: 'true', type: 'boolean' },
            { name: 'Is Active', value: 'false', type: 'boolean' },
          ],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Is Admin')).toBeInTheDocument();
      expect(screen.getByText('Yes')).toBeInTheDocument();
      expect(screen.getByText('Is Active')).toBeInTheDocument();
      expect(screen.getByText('No')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Secret item rendering
  // -----------------------------------------------------------------------

  describe('Secret item rendering', () => {
    it('renders value and description', () => {
      const item = makeDecryptedItem({
        name: 'API Key',
        itemType: 'secret',
        data: {
          value: 'sk-12345abcdef',
          description: 'OpenAI API Key',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Value')).toBeInTheDocument();
      expect(screen.getByText('Description')).toBeInTheDocument();
      expect(screen.getByText('OpenAI API Key')).toBeInTheDocument();
    });

    it('renders expiry date when provided', () => {
      const item = makeDecryptedItem({
        name: 'Expiring Secret',
        itemType: 'secret',
        data: {
          value: 'secret-val',
          description: '',
          expiresAt: '2026-12-31T23:59:59.000Z',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Expires')).toBeInTheDocument();
    });

    it('does not render description when empty', () => {
      const item = makeDecryptedItem({
        name: 'No Desc Secret',
        itemType: 'secret',
        data: {
          value: 'val',
          description: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.queryByText('Description')).not.toBeInTheDocument();
    });

    it('renders secret custom fields', () => {
      const item = makeDecryptedItem({
        name: 'Secret With Fields',
        itemType: 'secret',
        data: {
          value: 'val',
          description: '',
          customFields: [
            { name: 'Environment', value: 'production', type: 'text' },
            { name: 'Rotated Key', value: 'old-key', type: 'hidden' },
          ],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Environment')).toBeInTheDocument();
      expect(screen.getByText('production')).toBeInTheDocument();
      expect(screen.getByText('Rotated Key')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Note item rendering
  // -----------------------------------------------------------------------

  describe('Note item rendering', () => {
    it('renders plaintext note content directly', () => {
      const item = makeDecryptedItem({
        name: 'Plain Note',
        itemType: 'note',
        data: {
          content: 'This is a plain text note with some content.',
          format: 'plaintext',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('This is a plain text note with some content.')).toBeInTheDocument();
    });

    it('renders markdown note using ReactMarkdown mock', () => {
      const item = makeDecryptedItem({
        name: 'MD Note',
        itemType: 'note',
        data: {
          content: '# Heading\n\nParagraph text',
          format: 'markdown',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByTestId('markdown-content')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Card item rendering
  // -----------------------------------------------------------------------

  describe('Card item rendering', () => {
    it('renders card details with masked number', () => {
      const item = makeDecryptedItem({
        name: 'My Visa',
        itemType: 'card',
        data: {
          cardholderName: 'John Smith',
          number: '4111111111111111',
          expMonth: '12',
          expYear: '2028',
          cvv: '456',
          brand: 'Visa',
          notes: '',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Cardholder Name')).toBeInTheDocument();
      expect(screen.getByText('John Smith')).toBeInTheDocument();
      expect(screen.getByText('Card Number')).toBeInTheDocument();
      expect(screen.getByText('Expiry')).toBeInTheDocument();
      expect(screen.getByText('12/2028')).toBeInTheDocument();
      expect(screen.getByText('CVV')).toBeInTheDocument();
      expect(screen.getByText('Brand')).toBeInTheDocument();
      expect(screen.getByText('Visa')).toBeInTheDocument();
    });

    it('renders card with notes', () => {
      const item = makeDecryptedItem({
        name: 'Card With Notes',
        itemType: 'card',
        data: {
          cardholderName: 'Jane',
          number: '5500',
          expMonth: '01',
          expYear: '2030',
          cvv: '789',
          brand: '',
          notes: 'Business card for travel',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Notes')).toBeInTheDocument();
    });

    it('does not render brand when empty', () => {
      const item = makeDecryptedItem({
        name: 'No Brand Card',
        itemType: 'card',
        data: {
          cardholderName: 'Test',
          number: '1234567890123456',
          expMonth: '06',
          expYear: '2027',
          cvv: '321',
          brand: '',
          notes: '',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.queryByText('Brand')).not.toBeInTheDocument();
    });

    it('renders billing address when present', () => {
      const item = makeDecryptedItem({
        name: 'Card With Address',
        itemType: 'card',
        data: {
          cardholderName: 'John Doe',
          number: '4111111111111111',
          expMonth: '12',
          expYear: '2028',
          cvv: '456',
          brand: 'Visa',
          notes: '',
          billingAddress: {
            street: '123 Main St',
            city: 'Springfield',
            state: 'IL',
            zip: '62701',
            country: 'US',
          },
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Billing Address')).toBeInTheDocument();
      expect(screen.getByText('Street')).toBeInTheDocument();
      expect(screen.getByText('123 Main St')).toBeInTheDocument();
      expect(screen.getByText('City / State')).toBeInTheDocument();
      expect(screen.getByText('Springfield, IL')).toBeInTheDocument();
      expect(screen.getByText('ZIP')).toBeInTheDocument();
      expect(screen.getByText('62701')).toBeInTheDocument();
      expect(screen.getByText('Country')).toBeInTheDocument();
      expect(screen.getByText('US')).toBeInTheDocument();
    });

    it('does not render billing address section when not present', () => {
      const item = makeDecryptedItem({
        name: 'No Address Card',
        itemType: 'card',
        data: {
          cardholderName: 'Test',
          number: '4111111111111111',
          expMonth: '01',
          expYear: '2030',
          cvv: '123',
          brand: '',
          notes: '',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.queryByText('Billing Address')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Identity item rendering
  // -----------------------------------------------------------------------

  describe('Identity item rendering', () => {
    it('renders identity with all address fields', () => {
      const item = makeDecryptedItem({
        name: 'Full Identity',
        itemType: 'identity',
        data: {
          firstName: 'Alice',
          lastName: 'Carroll',
          email: 'alice@wonder.land',
          phone: '+15551234567',
          address: {
            street: '42 Rabbit Hole Lane',
            city: 'Springfield',
            state: 'WL',
            zip: '00001',
            country: 'Fantasy',
          },
          notes: 'Main identity',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('First Name')).toBeInTheDocument();
      expect(screen.getByText('Alice')).toBeInTheDocument();
      expect(screen.getByText('Last Name')).toBeInTheDocument();
      expect(screen.getByText('Carroll')).toBeInTheDocument();
      expect(screen.getByText('Email')).toBeInTheDocument();
      expect(screen.getByText('Phone')).toBeInTheDocument();
      expect(screen.getByText('Street')).toBeInTheDocument();
      expect(screen.getByText('City')).toBeInTheDocument();
      expect(screen.getByText('State')).toBeInTheDocument();
      expect(screen.getByText('ZIP')).toBeInTheDocument();
      expect(screen.getByText('Country')).toBeInTheDocument();
      expect(screen.getByText('Notes')).toBeInTheDocument();
    });

    it('renders identity without optional fields', () => {
      const item = makeDecryptedItem({
        name: 'Minimal Identity',
        itemType: 'identity',
        data: {
          firstName: 'Bob',
          lastName: 'Builder',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('First Name')).toBeInTheDocument();
      expect(screen.getByText('Last Name')).toBeInTheDocument();
      expect(screen.queryByText('Email')).not.toBeInTheDocument();
      expect(screen.queryByText('Phone')).not.toBeInTheDocument();
      expect(screen.queryByText('Street')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Copy to clipboard
  // -----------------------------------------------------------------------

  describe('Copy to clipboard', () => {
    it('copies field value when copy button is clicked', async () => {
      const item = makeDecryptedItem({
        name: 'Copy Test',
        itemType: 'login',
        data: {
          username: 'copyuser',
          password: 'copypass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const copyButtons = screen.getAllByLabelText(/^Copy /);
      expect(copyButtons.length).toBeGreaterThan(0);

      await act(async () => {
        fireEvent.click(copyButtons[0]!);
      });

      expect(navigator.clipboard.writeText).toHaveBeenCalled();
    });

    it('shows success toast on copy', async () => {
      const item = makeDecryptedItem({
        name: 'Toast Copy Test',
        itemType: 'login',
        data: {
          username: 'testuser',
          password: 'testpass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const copyBtn = screen.getByLabelText('Copy Username');

      await act(async () => {
        fireEvent.click(copyBtn);
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Username copied', type: 'success' }),
      );
    });

    it('shows error toast when clipboard write fails', async () => {
      (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Clipboard unavailable'),
      );

      const item = makeDecryptedItem({
        name: 'Fail Copy Test',
        itemType: 'login',
        data: {
          username: 'failuser',
          password: 'failpass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const copyBtn = screen.getByLabelText('Copy Username');

      await act(async () => {
        fireEvent.click(copyBtn);
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to copy', type: 'error' }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Field masking (reveal/hide)
  // -----------------------------------------------------------------------

  describe('Field masking', () => {
    it('password field is masked by default and can be revealed', () => {
      const item = makeDecryptedItem({
        name: 'Mask Test',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'mysecretpass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Password is masked - should not show the actual value initially
      expect(screen.queryByText('mysecretpass')).not.toBeInTheDocument();

      // Click reveal
      const revealButtons = screen.getAllByLabelText('Reveal value');
      fireEvent.click(revealButtons[0]!);

      // Now the password should be visible
      expect(screen.getByText('mysecretpass')).toBeInTheDocument();
    });

    it('clicking reveal again hides the value', () => {
      const item = makeDecryptedItem({
        name: 'Toggle Mask',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'togglepass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Reveal
      const revealBtn = screen.getAllByLabelText('Reveal value')[0]!;
      fireEvent.click(revealBtn);
      expect(screen.getByText('togglepass')).toBeInTheDocument();

      // Hide
      const hideBtn = screen.getByLabelText('Hide value');
      fireEvent.click(hideBtn);
      expect(screen.queryByText('togglepass')).not.toBeInTheDocument();
    });

    it('masked field shows proportional dots capped at 32', () => {
      const longPassword = 'a'.repeat(50);
      const item = makeDecryptedItem({
        name: 'Long Mask',
        itemType: 'login',
        data: {
          username: 'user',
          password: longPassword,
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Password is 50 chars, masked display should show 32 bullet dots (the cap)
      const bullets32 = '\u2022'.repeat(32);
      const bullets50 = '\u2022'.repeat(50);
      expect(screen.getByText(bullets32)).toBeInTheDocument();
      expect(screen.queryByText(bullets50)).not.toBeInTheDocument();
    });

    it('masked field shows exact length dots for short values', () => {
      const shortPassword = 'abc';
      const item = makeDecryptedItem({
        name: 'Short Mask',
        itemType: 'login',
        data: {
          username: 'user',
          password: shortPassword,
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Password is 3 chars, masked display should show exactly 3 bullet dots
      const bullets3 = '\u2022'.repeat(3);
      expect(screen.getByText(bullets3)).toBeInTheDocument();
    });

    it('CVV field on card items is masked by default', () => {
      const item = makeDecryptedItem({
        name: 'CVV Mask',
        itemType: 'card',
        data: {
          cardholderName: 'Test',
          number: '4111111111111111',
          expMonth: '01',
          expYear: '2030',
          cvv: '999',
          brand: '',
          notes: '',
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // CVV is masked
      expect(screen.queryByText('999')).not.toBeInTheDocument();

      // Reveal it
      const revealButtons = screen.getAllByLabelText('Reveal value');
      // Find the one next to CVV (there might be multiple masked fields)
      const lastReveal = revealButtons[revealButtons.length - 1]!;
      fireEvent.click(lastReveal);

      expect(screen.getByText('999')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Password history
  // -----------------------------------------------------------------------

  describe('Password history', () => {
    it('renders password history section when entries exist', () => {
      const item = makeDecryptedItem({
        name: 'History Item',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'currentpass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
        passwordHistory: [
          {
            encryptedPassword: 'enc1',
            iv: 'iv1',
            tag: 'tag1',
            changedAt: '2025-03-01T00:00:00.000Z',
          },
          {
            encryptedPassword: 'enc2',
            iv: 'iv2',
            tag: 'tag2',
            changedAt: '2025-02-01T00:00:00.000Z',
          },
        ],
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Password History (2)')).toBeInTheDocument();
    });

    it('expands password history and shows decrypted passwords', async () => {
      const item = makeDecryptedItem({
        name: 'Expand History',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'currentpass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
        passwordHistory: [
          {
            encryptedPassword: 'enc1',
            iv: 'iv1',
            tag: 'tag1',
            changedAt: '2025-03-01T00:00:00.000Z',
          },
        ],
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const historyButton = screen.getByText('Password History (1)');

      await act(async () => {
        fireEvent.click(historyButton);
      });

      await waitFor(() => {
        // Password history now renders via CopyField with masked prop; look for the label
        expect(screen.getByText(/Previous password/)).toBeInTheDocument();
      });
    });

    it('collapses password history when clicked again', async () => {
      const item = makeDecryptedItem({
        name: 'Collapse History',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
        passwordHistory: [
          {
            encryptedPassword: 'enc1',
            iv: 'iv1',
            tag: 'tag1',
            changedAt: '2025-03-01T00:00:00.000Z',
          },
        ],
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      const historyButton = screen.getByText('Password History (1)');

      // Expand
      await act(async () => {
        fireEvent.click(historyButton);
      });

      await waitFor(() => {
        // Password history now renders via CopyField with masked prop; look for the label
        expect(screen.getByText(/Previous password/)).toBeInTheDocument();
      });

      // Collapse
      await act(async () => {
        fireEvent.click(historyButton);
      });

      expect(screen.queryByText(/Previous password/)).not.toBeInTheDocument();
    });

    it('does not render password history section when no entries', () => {
      const item = makeDecryptedItem({
        name: 'No History',
        itemType: 'login',
        data: {
          username: 'user',
          password: 'pass',
          uris: [],
          totp: '',
          notes: '',
          customFields: [],
        },
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.queryByText(/Password History/)).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Favorite toggle
  // -----------------------------------------------------------------------

  describe('Favorite toggle', () => {
    it('shows "Favorite" button for non-favorite items', () => {
      const item = makeDecryptedItem({ name: 'Not Fav', favorite: false });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Favorite')).toBeInTheDocument();
    });

    it('shows "Favorited" button for favorite items', () => {
      const item = makeDecryptedItem({ name: 'Is Fav', favorite: true });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Favorited')).toBeInTheDocument();
    });

    it('calls updateItemMeta (metadata-only, no re-encryption) to toggle favorite', async () => {
      const item = makeDecryptedItem({ name: 'Toggle Fav', favorite: false, tags: ['tag1'] });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      await act(async () => {
        fireEvent.click(screen.getByText('Favorite'));
      });

      expect(mockUpdateItemMeta).toHaveBeenCalledWith('item-1', { favorite: true });
      // The re-encrypting path must NOT be used: it would encrypt item.data
      // over the item's ciphertext (fatal for an undecodable item).
      expect(mockUpdateItem).not.toHaveBeenCalled();
    });

    it('shows success toast when favorite is toggled', async () => {
      const item = makeDecryptedItem({ name: 'Toast Fav', favorite: false });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      await act(async () => {
        fireEvent.click(screen.getByText('Favorite'));
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Added to favorites', type: 'success' }),
      );
    });

    it('shows error toast when favorite toggle fails', async () => {
      mockUpdateItemMeta.mockRejectedValueOnce(new Error('Update failed'));

      const item = makeDecryptedItem({ name: 'Fail Fav', favorite: false });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      await act(async () => {
        fireEvent.click(screen.getByText('Favorite'));
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to update favorite', type: 'error' }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Edit button
  // -----------------------------------------------------------------------

  describe('Edit button', () => {
    it('calls onEdit callback when clicked', () => {
      const item = makeDecryptedItem({ name: 'Edit Me' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('Edit'));
      expect(onEdit).toHaveBeenCalledOnce();
    });

    it('does not show Edit button for trashed items', () => {
      const item = makeDecryptedItem({ name: 'Trashed' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />);

      expect(screen.queryByText('Edit')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Delete flow
  // -----------------------------------------------------------------------

  describe('Delete flow', () => {
    it('opens confirmation dialog on Delete click', () => {
      const item = makeDecryptedItem({ name: 'Delete Confirm' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('Delete'));

      expect(screen.getByRole('alertdialog')).toBeInTheDocument();
      expect(screen.getByText('Delete Item')).toBeInTheDocument();
    });

    it('closes confirmation dialog on Cancel', () => {
      const item = makeDecryptedItem({ name: 'Cancel Delete' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('Delete'));
      expect(screen.getByRole('alertdialog')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Cancel'));
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    });

    it('calls deleteItem and shows toast on soft delete confirmation', async () => {
      const item = makeDecryptedItem({ name: 'Soft Delete' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      // Open dialog
      fireEvent.click(screen.getByText('Delete'));

      // Confirm delete within dialog
      const deleteButtons = screen.getAllByText('Delete');
      const confirmBtn = deleteButtons[deleteButtons.length - 1]!;

      await act(async () => {
        fireEvent.click(confirmBtn);
      });

      expect(mockDeleteItem).toHaveBeenCalledWith('item-1');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item moved to trash', type: 'success' }),
      );
    });

    it('calls permanentDeleteItem for trashed items', async () => {
      const item = makeDecryptedItem({ name: 'Perm Delete' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />);

      fireEvent.click(screen.getByText('Delete Forever'));

      const confirmBtn = screen.getAllByText('Delete').pop()!;

      await act(async () => {
        fireEvent.click(confirmBtn);
      });

      expect(mockPermanentDeleteItem).toHaveBeenCalledWith('item-1');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item permanently deleted', type: 'success' }),
      );
    });

    it('shows error toast when delete fails', async () => {
      mockDeleteItem.mockRejectedValueOnce(new Error('Delete error'));

      const item = makeDecryptedItem({ name: 'Fail Delete' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('Delete'));
      const confirmBtn = screen.getAllByText('Delete').pop()!;

      await act(async () => {
        fireEvent.click(confirmBtn);
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to delete item', type: 'error' }),
      );
    });

    it('shows "Permanently Delete Item" heading for trashed items', () => {
      const item = makeDecryptedItem({ name: 'Perm Delete Heading' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />);

      fireEvent.click(screen.getByText('Delete Forever'));

      expect(screen.getByText('Permanently Delete Item')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Restore flow (trashed items)
  // -----------------------------------------------------------------------

  describe('Restore flow', () => {
    it('calls restoreItem and shows toast on Restore click', async () => {
      const item = makeDecryptedItem({ name: 'Restore Me' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />);

      await act(async () => {
        fireEvent.click(screen.getByText('Restore'));
      });

      expect(mockRestoreItem).toHaveBeenCalledWith('item-1');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item restored', type: 'success' }),
      );
    });

    it('shows error toast when restore fails', async () => {
      mockRestoreItem.mockRejectedValueOnce(new Error('Restore error'));

      const item = makeDecryptedItem({ name: 'Fail Restore' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />);

      await act(async () => {
        fireEvent.click(screen.getByText('Restore'));
      });

      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to restore item', type: 'error' }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Folder badge and move-to-folder
  // -----------------------------------------------------------------------

  describe('Folder badge and move-to-folder', () => {
    it('displays "No folder" when item has no folderId', () => {
      const item = makeDecryptedItem({ name: 'No Folder' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('No folder')).toBeInTheDocument();
    });

    it('displays folder name when item has a folderId', () => {
      useVaultStore.setState({
        folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      });

      const item = makeDecryptedItem({ name: 'Folder Item', folderId: 'f1' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Work')).toBeInTheDocument();
    });

    it('opens folder menu on click and shows available folders', () => {
      useVaultStore.setState({
        folders: [
          makeFolder({ id: 'f1', name: 'Work' }),
          makeFolder({ id: 'f2', name: 'Personal' }),
        ] as never[],
      });

      const item = makeDecryptedItem({ name: 'Move Item' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('No folder'));

      // Menu options
      // "No folder" appears twice: in button and in menu
      const noFolderElements = screen.getAllByText('No folder');
      expect(noFolderElements.length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText('Work')).toBeInTheDocument();
      expect(screen.getByText('Personal')).toBeInTheDocument();
    });

    it('moves item to a folder when folder is selected', async () => {
      useVaultStore.setState({
        folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      });

      const item = makeDecryptedItem({ name: 'Move To Work', tags: ['tag1'] });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('No folder'));

      await act(async () => {
        fireEvent.click(screen.getByText('Work'));
      });

      // Metadata-only: the move sends just the folderId and re-encrypts nothing.
      expect(mockUpdateItemMeta).toHaveBeenCalledWith('item-1', { folderId: 'f1' });
      expect(mockUpdateItem).not.toHaveBeenCalled();
    });

    it('moves item to no folder when "No folder" is selected', async () => {
      useVaultStore.setState({
        folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      });

      const item = makeDecryptedItem({ name: 'Remove Folder', folderId: 'f1' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      fireEvent.click(screen.getByText('Work'));

      // Click "No folder" in the dropdown
      const noFolderOptions = screen.getAllByText('No folder');
      await act(async () => {
        fireEvent.click(noFolderOptions[0]!);
      });

      expect(mockUpdateItemMeta).toHaveBeenCalledWith('item-1', { folderId: null });
      expect(mockUpdateItem).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Tags display
  // -----------------------------------------------------------------------

  describe('Tags display', () => {
    it('renders all tags as badges', () => {
      const item = makeDecryptedItem({
        name: 'Tagged',
        tags: ['work', 'important', 'urgent'],
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('work')).toBeInTheDocument();
      expect(screen.getByText('important')).toBeInTheDocument();
      expect(screen.getByText('urgent')).toBeInTheDocument();
    });

    it('does not render tags section when no tags', () => {
      const item = makeDecryptedItem({ name: 'No Tags', tags: [] });

      const { container } = renderWithRouter(
        <VaultItemDetail item={item as never} onEdit={onEdit} />,
      );

      // Tags section uses flex-wrap gap-1.5 container
      const tagContainers = container.querySelectorAll('.rounded-full');
      // No tag badges rendered
      const tagBadges = Array.from(tagContainers).filter((el) =>
        el.classList.contains('bg-[hsl(var(--secondary))]'),
      );
      expect(tagBadges.length).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Timestamps
  // -----------------------------------------------------------------------

  describe('Timestamps', () => {
    it('renders Created and Modified labels', () => {
      const item = makeDecryptedItem({
        name: 'Timestamp Item',
        createdAt: '2025-01-15T10:00:00.000Z',
        updatedAt: '2025-06-20T14:30:00.000Z',
      });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Modified')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // "Unnamed item" fallback
  // -----------------------------------------------------------------------

  describe('Unnamed item fallback', () => {
    it('displays "Unnamed item" when name is empty', () => {
      const item = makeDecryptedItem({ name: '' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByText('Unnamed item')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Back to vault button
  // -----------------------------------------------------------------------

  describe('Back to vault button', () => {
    it('renders the back button with correct aria-label', () => {
      const item = makeDecryptedItem({ name: 'Back Test' });

      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

      expect(screen.getByLabelText('Back to vault')).toBeInTheDocument();
    });
  });
});

// ==========================================================================
// 2 - VaultList
// ==========================================================================

describe('VaultList', () => {
  const onCreateNew = vi.fn();

  beforeEach(() => {
    onCreateNew.mockClear();
  });

  // -----------------------------------------------------------------------
  // Empty state
  // -----------------------------------------------------------------------

  describe('Empty state', () => {
    it('shows "No items found" when vault is empty', () => {
      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('No items found')).toBeInTheDocument();
    });

    it('shows "Trash is empty" in trash view', () => {
      useVaultStore.setState({ showTrash: true });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Trash is empty')).toBeInTheDocument();
    });

    it('shows Create Item button in empty state (non-trash)', () => {
      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Create Item')).toBeInTheDocument();
    });

    it('does not show Create Item button in empty trash view', () => {
      useVaultStore.setState({ showTrash: true });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.queryByText('Create Item')).not.toBeInTheDocument();
    });

    it('calls onCreateNew when Create Item button is clicked', () => {
      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Create Item'));
      expect(onCreateNew).toHaveBeenCalledOnce();
    });
  });

  // -----------------------------------------------------------------------
  // Loading state
  // -----------------------------------------------------------------------

  describe('Loading state', () => {
    it('shows loading skeleton when loading is true', () => {
      useVaultStore.setState({ loading: true, itemsLoading: true });

      const { container } = renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const pulsingElements = container.querySelectorAll('.animate-pulse');
      expect(pulsingElements.length).toBeGreaterThan(0);
    });
  });

  // -----------------------------------------------------------------------
  // Item rendering
  // -----------------------------------------------------------------------

  describe('Item rendering', () => {
    it('renders items with correct names', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'GitHub', itemType: 'login' }),
          makeDecryptedItem({
            id: 'i2',
            name: 'AWS Key',
            itemType: 'secret',
            data: { value: 'x', description: '', customFields: [] },
          }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('GitHub')).toBeInTheDocument();
      expect(screen.getByText('AWS Key')).toBeInTheDocument();
    });

    it('renders type badges for each item', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'L', itemType: 'login' }),
          makeDecryptedItem({
            id: 'i2',
            name: 'N',
            itemType: 'note',
            data: { content: 'x', format: 'plaintext' },
          }),
          makeDecryptedItem({
            id: 'i3',
            name: 'C',
            itemType: 'card',
            data: {
              cardholderName: 'x',
              number: '1234',
              expMonth: '01',
              expYear: '25',
              cvv: '123',
            },
          }),
          makeDecryptedItem({
            id: 'i4',
            name: 'I',
            itemType: 'identity',
            data: { firstName: 'x', lastName: 'y' },
          }),
          makeDecryptedItem({
            id: 'i5',
            name: 'S',
            itemType: 'secret',
            data: { value: 'x', description: '', customFields: [] },
          }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Login')).toBeInTheDocument();
      expect(screen.getByText('Note')).toBeInTheDocument();
      expect(screen.getByText('Card')).toBeInTheDocument();
      expect(screen.getByText('Identity')).toBeInTheDocument();
      expect(screen.getByText('Secret')).toBeInTheDocument();
    });

    it('shows star icon for favorite items', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Fav', favorite: true }),
          makeDecryptedItem({ id: 'i2', name: 'Not Fav', favorite: false }),
        ] as never[],
      });

      const { container } = renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      // Favorite items have fill-yellow-400 star
      const filledStars = container.querySelectorAll('.fill-yellow-400');
      expect(filledStars.length).toBe(1);
    });

    it('shows "Unnamed item" for items with empty name', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: '' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Unnamed item')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Sort functionality
  // -----------------------------------------------------------------------

  describe('Sort functionality', () => {
    it('opens sort menu when sort button is clicked', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Name'));

      expect(screen.getByText('Date Created')).toBeInTheDocument();
      expect(screen.getByText('Date Modified')).toBeInTheDocument();
      expect(screen.getByText('Type')).toBeInTheDocument();
    });

    it('selects a sort option when clicked', () => {
      const setSortBy = vi.fn();
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        setSortBy,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Name'));
      fireEvent.click(screen.getByText('Date Created'));

      expect(setSortBy).toHaveBeenCalledWith('dateCreated');
    });

    it('toggles sort order when order button is clicked', () => {
      const setSortOrder = vi.fn();
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        sortOrder: 'asc',
        setSortOrder,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByLabelText('Sort descending'));
      expect(setSortOrder).toHaveBeenCalledWith('desc');
    });

    it('shows ascending button when sort order is desc', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        sortOrder: 'desc',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByLabelText('Sort ascending')).toBeInTheDocument();
    });

    it('sorts items by name ascending', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Zebra' }),
          makeDecryptedItem({ id: 'i2', name: 'Alpha' }),
        ] as never[],
        sortBy: 'name',
        sortOrder: 'asc',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const buttons = screen.getAllByRole('button');
      const texts = buttons
        .map((b) => b.textContent)
        .filter((t) => t?.includes('Alpha') || t?.includes('Zebra'));
      expect(texts[0]).toContain('Alpha');
      expect(texts[1]).toContain('Zebra');
    });

    it('sorts items by name descending', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Alpha' }),
          makeDecryptedItem({ id: 'i2', name: 'Zebra' }),
        ] as never[],
        sortBy: 'name',
        sortOrder: 'desc',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const buttons = screen.getAllByRole('button');
      const texts = buttons
        .map((b) => b.textContent)
        .filter((t) => t?.includes('Alpha') || t?.includes('Zebra'));
      expect(texts[0]).toContain('Zebra');
      expect(texts[1]).toContain('Alpha');
    });

    it('sorts items by date created', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Old', createdAt: '2024-01-01T00:00:00Z' }),
          makeDecryptedItem({ id: 'i2', name: 'New', createdAt: '2025-06-01T00:00:00Z' }),
        ] as never[],
        sortBy: 'dateCreated',
        sortOrder: 'asc',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const buttons = screen.getAllByRole('button');
      const texts = buttons
        .map((b) => b.textContent)
        .filter((t) => t?.includes('Old') || t?.includes('New'));
      expect(texts[0]).toContain('Old');
      expect(texts[1]).toContain('New');
    });

    it('sorts items by type', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({
            id: 'i1',
            name: 'S',
            itemType: 'secret',
            data: { value: 'x', description: '', customFields: [] },
          }),
          makeDecryptedItem({ id: 'i2', name: 'L', itemType: 'login' }),
        ] as never[],
        sortBy: 'type',
        sortOrder: 'asc',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const buttons = screen.getAllByRole('button');
      const texts = buttons
        .map((b) => b.textContent)
        .filter((t) => t?.includes('S') || t?.includes('L'));
      // 'login' < 'secret' alphabetically
      expect(texts[0]).toContain('L');
    });
  });

  // -----------------------------------------------------------------------
  // Multi-select mode
  // -----------------------------------------------------------------------

  describe('Multi-select mode', () => {
    it('enters multi-select mode when a checkbox is clicked', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
          makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      expect(screen.getByText('1 selected')).toBeInTheDocument();
      expect(screen.getByText('Clear')).toBeInTheDocument();
    });

    it('clears selection when Clear button is clicked', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
          makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);
      expect(screen.getByText('1 selected')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Clear'));
      expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('selects all when Select All checkbox is clicked', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
          makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
          makeDecryptedItem({ id: 'i3', name: 'Item 3' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      // Select first item to enter multi-select mode
      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);
      expect(screen.getByText('1 selected')).toBeInTheDocument();

      // Click "Select all"
      const selectAll = screen.getByLabelText('Select all');
      fireEvent.click(selectAll);

      expect(screen.getByText('3 selected')).toBeInTheDocument();
    });

    it('deselects all when Select All is clicked while all selected', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
          makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      // Select both items
      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);
      fireEvent.click(checkboxes[1]!);
      expect(screen.getByText('2 selected')).toBeInTheDocument();

      // Click "Deselect all"
      const deselectAll = screen.getByLabelText('Deselect all');
      fireEvent.click(deselectAll);

      expect(screen.queryByText('2 selected')).not.toBeInTheDocument();
    });

    it('shows bulk delete button in selection bar', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item 1' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      // In non-trash, button says "Delete"
      expect(screen.getAllByText('Delete').length).toBeGreaterThanOrEqual(1);
    });

    it('shows "Delete Forever" in trash multi-select', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      expect(screen.getByText('Delete Forever')).toBeInTheDocument();
    });

    it('shows Move and Tag buttons in non-trash selection bar', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item 1' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      expect(screen.getByText('Move')).toBeInTheDocument();
      expect(screen.getByText('Tag')).toBeInTheDocument();
    });

    it('hides Move and Tag buttons in trash selection bar', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      expect(screen.queryByText('Move')).not.toBeInTheDocument();
      expect(screen.queryByText('Tag')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Bulk delete
  // -----------------------------------------------------------------------

  describe('Bulk delete', () => {
    it('calls bulkDeleteApi for non-trash items', async () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
          makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      // Select items
      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);
      fireEvent.click(checkboxes[1]!);

      // Click Delete (opens confirmation dialog)
      const deleteBtn =
        screen.getAllByText('Delete').find((el) => el.closest('.ml-auto')) ??
        screen.getAllByText('Delete')[0]!;

      await act(async () => {
        fireEvent.click(deleteBtn);
      });

      // Confirm in the confirmation dialog
      const dialog = screen.getByRole('alertdialog');
      await act(async () => {
        fireEvent.click(screen.getAllByText('Delete').find((el) => dialog.contains(el))!);
      });

      await waitFor(() => {
        expect(mockBulkDeleteApi).toHaveBeenCalled();
      });
    });

    it('calls permanentDeleteApi for trash items', async () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed 1' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      // Click Delete Forever (opens confirmation dialog)
      await act(async () => {
        fireEvent.click(screen.getByText('Delete Forever'));
      });

      // Confirm in the confirmation dialog
      const dialog = screen.getByRole('alertdialog');
      await act(async () => {
        fireEvent.click(screen.getAllByText('Delete Forever').find((el) => dialog.contains(el))!);
      });

      await waitFor(() => {
        expect(mockPermanentDeleteApi).toHaveBeenCalledWith('i1');
      });
    });
  });

  // -----------------------------------------------------------------------
  // Bulk move
  // -----------------------------------------------------------------------

  describe('Bulk move', () => {
    it('opens move menu and shows folders', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        folders: [
          makeFolder({ id: 'f1', name: 'Work' }),
          makeFolder({ id: 'f2', name: 'Personal' }),
        ] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      fireEvent.click(screen.getByText('Move'));

      expect(screen.getAllByText('No folder').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Work')).toBeInTheDocument();
      expect(screen.getByText('Personal')).toBeInTheDocument();
    });

    it('calls bulkMoveApi when a folder is selected', async () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      fireEvent.click(screen.getByText('Move'));

      await act(async () => {
        fireEvent.click(screen.getByText('Work'));
      });

      await waitFor(() => {
        expect(mockBulkMoveApi).toHaveBeenCalledWith(['i1'], 'f1');
      });
    });

    it('calls bulkMoveApi with null when "No folder" is selected', async () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
        folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      const checkboxes = screen.getAllByLabelText('Select item');
      fireEvent.click(checkboxes[0]!);

      fireEvent.click(screen.getByText('Move'));

      // Click "No folder" in the move menu
      const noFolderButtons = screen.getAllByText('No folder');
      await act(async () => {
        fireEvent.click(noFolderButtons[noFolderButtons.length - 1]!);
      });

      await waitFor(() => {
        expect(mockBulkMoveApi).toHaveBeenCalledWith(['i1'], null);
      });
    });
  });

  // -----------------------------------------------------------------------
  // Search filtering
  // -----------------------------------------------------------------------

  describe('Search filtering', () => {
    it('filters items by search query matching name', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'GitHub Login' }),
          makeDecryptedItem({
            id: 'i2',
            name: 'AWS Secret',
            itemType: 'secret',
            data: { value: 'x', description: '', customFields: [] },
          }),
        ] as never[],
        searchQuery: 'github',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('GitHub Login')).toBeInTheDocument();
      expect(screen.queryByText('AWS Secret')).not.toBeInTheDocument();
    });

    it('filters items by search query matching tags', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Item A', tags: ['production'] }),
          makeDecryptedItem({ id: 'i2', name: 'Item B', tags: ['staging'] }),
        ] as never[],
        searchQuery: 'production',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Item A')).toBeInTheDocument();
      expect(screen.queryByText('Item B')).not.toBeInTheDocument();
    });

    it('filters items by search query matching type label', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'My Item', itemType: 'login' }),
          makeDecryptedItem({
            id: 'i2',
            name: 'Other',
            itemType: 'note',
            data: { content: 'x', format: 'plaintext' },
          }),
        ] as never[],
        searchQuery: 'login',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('My Item')).toBeInTheDocument();
      expect(screen.queryByText('Other')).not.toBeInTheDocument();
    });

    it('filters items by search query matching data fields', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({
            id: 'i1',
            name: 'Item A',
            data: {
              username: 'specialuser@test.com',
              password: 'pass',
              uris: [],
              totp: '',
              notes: '',
              customFields: [],
            },
          }),
          makeDecryptedItem({ id: 'i2', name: 'Item B' }),
        ] as never[],
        searchQuery: 'specialuser',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Item A')).toBeInTheDocument();
      expect(screen.queryByText('Item B')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Filtering
  // -----------------------------------------------------------------------

  describe('Filtering', () => {
    it('filters by type', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'My Login Entry', itemType: 'login' }),
          makeDecryptedItem({
            id: 'i2',
            name: 'My Note Entry',
            itemType: 'note',
            data: { content: 'x', format: 'plaintext' },
          }),
        ] as never[],
        selectedType: 'note',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('My Note Entry')).toBeInTheDocument();
      expect(screen.queryByText('My Login Entry')).not.toBeInTheDocument();
    });

    it('filters by favorites', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'Fav', favorite: true }),
          makeDecryptedItem({ id: 'i2', name: 'Normal', favorite: false }),
        ] as never[],
        showFavorites: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Fav')).toBeInTheDocument();
      expect(screen.queryByText('Normal')).not.toBeInTheDocument();
    });

    it('filters by folder', () => {
      useVaultStore.setState({
        items: [
          makeDecryptedItem({ id: 'i1', name: 'In Folder', folderId: 'f1' }),
          makeDecryptedItem({ id: 'i2', name: 'No Folder' }),
        ] as never[],
        selectedFolder: 'f1',
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('In Folder')).toBeInTheDocument();
      expect(screen.queryByText('No Folder')).not.toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Trash view
  // -----------------------------------------------------------------------

  describe('Trash view', () => {
    it('shows trash items instead of regular items', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Active' })] as never[],
        trashItems: [makeDecryptedItem({ id: 'i2', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Trashed')).toBeInTheDocument();
      expect(screen.queryByText('Active')).not.toBeInTheDocument();
    });

    it('shows Empty Trash button in trash view with items', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('Empty Trash')).toBeInTheDocument();
    });

    it('hides floating create button in trash view', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.queryByLabelText('Create new item')).not.toBeInTheDocument();
    });

    it('opens empty trash confirmation dialog', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Empty Trash'));

      expect(screen.getByRole('alertdialog')).toBeInTheDocument();
      expect(screen.getByText(/permanently delete all/i)).toBeInTheDocument();
    });

    it('cancels empty trash dialog', () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Empty Trash'));
      expect(screen.getByRole('alertdialog')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Cancel'));
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    });

    it('empties trash when confirmed', async () => {
      useVaultStore.setState({
        trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
        showTrash: true,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByText('Empty Trash'));

      await act(async () => {
        fireEvent.click(screen.getByText('Delete All Forever'));
      });

      expect(mockEmptyTrash).toHaveBeenCalled();
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Trash emptied', type: 'success' }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Floating action button
  // -----------------------------------------------------------------------

  describe('Floating action button', () => {
    it('renders FAB with correct aria-label in normal view', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByLabelText('Create new item')).toBeInTheDocument();
    });

    it('calls onCreateNew when FAB is clicked', () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      fireEvent.click(screen.getByLabelText('Create new item'));
      expect(onCreateNew).toHaveBeenCalledOnce();
    });
  });

  // -----------------------------------------------------------------------
  // Keyboard navigation
  // -----------------------------------------------------------------------

  describe('Keyboard navigation', () => {
    // Render the list at /vault with a sibling /vault/:id route so we can observe
    // the navigation the keyDown handler triggers (navigate(`/vault/${item.id}`)),
    // rather than merely asserting the row element exists.
    function renderListWithDetailRoute() {
      return render(
        <MemoryRouter initialEntries={['/vault']}>
          <Routes>
            <Route path="/vault" element={<VaultList onCreateNew={onCreateNew} />} />
            <Route path="/vault/:id" element={<div data-testid="detail-route">Detail</div>} />
          </Routes>
        </MemoryRouter>,
      );
    }

    it('navigates to the item detail route on Enter key press', async () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Key Nav Item' })] as never[],
      });

      renderListWithDetailRoute();

      const itemButton = screen.getByRole('button', { name: /Key Nav Item/i });
      expect(screen.queryByTestId('detail-route')).not.toBeInTheDocument();
      fireEvent.keyDown(itemButton, { key: 'Enter' });

      // Enter must route to /vault/i1 — deleting the row's onKeyDown handler
      // leaves the detail route unmounted and fails this.
      expect(await screen.findByTestId('detail-route')).toBeInTheDocument();
    });

    it('navigates to the item detail route on Space key press', async () => {
      useVaultStore.setState({
        items: [makeDecryptedItem({ id: 'i1', name: 'Space Nav' })] as never[],
      });

      renderListWithDetailRoute();

      const itemButton = screen.getByRole('button', { name: /Space Nav/i });
      expect(screen.queryByTestId('detail-route')).not.toBeInTheDocument();
      fireEvent.keyDown(itemButton, { key: ' ' });

      expect(await screen.findByTestId('detail-route')).toBeInTheDocument();
    });
  });

  // -----------------------------------------------------------------------
  // Memoized subcomponents
  // -----------------------------------------------------------------------

  describe('Memoized subcomponents', () => {
    it('renders loading skeleton (memoized SkeletonRow)', () => {
      useVaultStore.setState({ loading: true, itemsLoading: true, trashLoading: false });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      // Loading skeleton renders multiple shimmer rows via SkeletonRow
      const pulseElements = document.querySelectorAll('.animate-pulse');
      expect(pulseElements.length).toBeGreaterThan(0);
    });

    it('renders empty state component (memoized EmptyState)', () => {
      useVaultStore.setState({
        items: [],
        showTrash: false,
        itemsLoading: false,
        trashLoading: false,
      });

      renderWithRouter(<VaultList onCreateNew={onCreateNew} />);

      expect(screen.getByText('No items found')).toBeInTheDocument();
    });
  });
});

// ==========================================================================
// 3 - VaultItemPage
// ==========================================================================

describe('VaultItemPage', () => {
  it('shows loading spinner when loading with no item', async () => {
    useVaultStore.setState({ loading: true, itemsLoading: true });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    const { container } = render(
      <MemoryRouter initialEntries={['/vault/item-1']}>
        <Routes>
          <Route path="/vault/:id" element={<VaultItemPage />} />
        </Routes>
      </MemoryRouter>,
    );

    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('shows "Item Not Found" when item does not exist and not loading', async () => {
    useVaultStore.setState({
      items: [],
      trashItems: [],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/nonexistent']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
            <Route path="/vault" element={<div>Vault List</div>} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(screen.getByText('Item Not Found')).toBeInTheDocument();
    expect(screen.getByText('Back to Vault')).toBeInTheDocument();
  });

  it('displays item detail when item is found', async () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'item-42', name: 'Found Item' })] as never[],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/item-42']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(screen.getByText('Found Item')).toBeInTheDocument();
    expect(screen.getByText('Edit')).toBeInTheDocument();
  });

  it('identifies trashed items correctly', async () => {
    useVaultStore.setState({
      items: [],
      trashItems: [makeDecryptedItem({ id: 'trash-1', name: 'Trashed Item' })] as never[],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/trash-1']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(screen.getByText('Trashed Item')).toBeInTheDocument();
    expect(screen.getByText('Restore')).toBeInTheDocument();
    expect(screen.getByText('Delete Forever')).toBeInTheDocument();
  });

  it('switches to edit mode when Edit is clicked', async () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'edit-1', name: 'Editable Item' })] as never[],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/edit-1']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    fireEvent.click(screen.getByText('Edit'));

    expect(screen.getByTestId('vault-item-form')).toBeInTheDocument();
  });

  it('exits edit mode when Cancel is clicked in form', async () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'cancel-1', name: 'Cancel Edit' })] as never[],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/cancel-1']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    fireEvent.click(screen.getByText('Edit'));
    expect(screen.getByTestId('vault-item-form')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel Form'));

    expect(screen.queryByTestId('vault-item-form')).not.toBeInTheDocument();
    expect(screen.getByText('Cancel Edit')).toBeInTheDocument();
  });

  it('exits edit mode and re-fetches after Save', async () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'save-1', name: 'Save Test' })] as never[],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/save-1']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    fireEvent.click(screen.getByText('Edit'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Form'));
    });

    expect(screen.queryByTestId('vault-item-form')).not.toBeInTheDocument();
    expect(mockFetchItems).toHaveBeenCalled();
  });

  it('navigates to /vault from not found page', async () => {
    useVaultStore.setState({
      items: [],
      trashItems: [],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/missing-id']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
            <Route path="/vault" element={<div>Vault List</div>} />
          </Routes>
        </MemoryRouter>,
      );
    });

    // Not found page shows "Back to Vault" button
    expect(screen.getByText('Item Not Found')).toBeInTheDocument();
    expect(screen.getByText('Back to Vault')).toBeInTheDocument();
  });

  it('fetches items when items array is empty and not loading', async () => {
    useVaultStore.setState({
      items: [],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });

    const { default: VaultItemPage } = await import('../src/pages/VaultItemPage');

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/item-1']}>
          <Routes>
            <Route path="/vault/:id" element={<VaultItemPage />} />
          </Routes>
        </MemoryRouter>,
      );
    });

    expect(mockFetchItems).toHaveBeenCalled();
  });
});

// ==========================================================================
// 1.5 - VaultItemDetail: Secret remaining time / expiry
// ==========================================================================

describe('VaultItemDetail - Secret remaining time', () => {
  const onEdit = vi.fn();
  let dateNowSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    onEdit.mockClear();
  });

  afterEach(() => {
    if (dateNowSpy) dateNowSpy.mockRestore();
  });

  function setCurrentTime(isoDate: string) {
    const ts = new Date(isoDate).getTime();
    dateNowSpy = vi.spyOn(Date, 'now').mockReturnValue(ts);
  }

  it('shows remaining time in days and hours for a future expiry', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const futureExpiry = new Date(nowTs + 3 * 24 * 60 * 60 * 1000 + 5 * 60 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Future Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: futureExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Expires')).toBeInTheDocument();
    expect(screen.getByText('3d 5h remaining')).toBeInTheDocument();
  });

  it('shows remaining time in hours and minutes when less than a day', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const futureExpiry = new Date(nowTs + 5 * 60 * 60 * 1000 + 30 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Hours Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: futureExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('5h 30m remaining')).toBeInTheDocument();
  });

  it('shows remaining time in minutes only when less than an hour', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const futureExpiry = new Date(nowTs + 42 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Minutes Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: futureExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('42m remaining')).toBeInTheDocument();
  });

  it('shows "Less than a minute remaining" when under 60 seconds left', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const futureExpiry = new Date(nowTs + 30 * 1000); // 30 seconds
    const item = makeDecryptedItem({
      name: 'Almost Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: futureExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Less than a minute remaining')).toBeInTheDocument();
  });

  it('shows "Expired just now" when just past expiry (under 1 minute)', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const pastExpiry = new Date(nowTs - 10 * 1000); // 10 seconds ago
    const item = makeDecryptedItem({
      name: 'Just Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: pastExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Expired just now')).toBeInTheDocument();
  });

  it('shows expired with minutes when expired less than an hour ago', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const pastExpiry = new Date(nowTs - 15 * 60 * 1000); // 15 minutes ago
    const item = makeDecryptedItem({
      name: 'Recently Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: pastExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Expired 15m ago')).toBeInTheDocument();
  });

  it('shows expired with hours and minutes when expired less than a day ago', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const pastExpiry = new Date(nowTs - 3 * 60 * 60 * 1000 - 20 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Hours Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: pastExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Expired 3h 20m ago')).toBeInTheDocument();
  });

  it('shows expired with days and hours when expired more than a day ago', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const pastExpiry = new Date(nowTs - 5 * 24 * 60 * 60 * 1000 - 8 * 60 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Long Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: pastExpiry.toISOString(),
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.getByText('Expired 5d 8h ago')).toBeInTheDocument();
  });

  it('applies red styling classes for expired secrets', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const pastExpiry = new Date(nowTs - 60 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Styled Expired Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: pastExpiry.toISOString(),
        customFields: [],
      },
    });

    const { container } = renderWithRouter(
      <VaultItemDetail item={item as never} onEdit={onEdit} />,
    );

    // The expired container should have the red border class
    const expiredContainer = container.querySelector('.border-red-500\\/30');
    expect(expiredContainer).toBeTruthy();
  });

  it('does not apply red styling for non-expired secrets', () => {
    const nowTs = new Date('2025-06-15T12:00:00.000Z').getTime();
    setCurrentTime('2025-06-15T12:00:00.000Z');

    const futureExpiry = new Date(nowTs + 24 * 60 * 60 * 1000);
    const item = makeDecryptedItem({
      name: 'Active Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        expiresAt: futureExpiry.toISOString(),
        customFields: [],
      },
    });

    const { container } = renderWithRouter(
      <VaultItemDetail item={item as never} onEdit={onEdit} />,
    );

    // The non-expired container should NOT have the red border class
    const expiredContainer = container.querySelector('.border-red-500\\/30');
    expect(expiredContainer).toBeNull();
  });

  it('does not show remaining time when expiresAt is not provided', () => {
    const item = makeDecryptedItem({
      name: 'No Expiry Secret',
      itemType: 'secret',
      data: {
        value: 'secret-val',
        description: '',
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.queryByText('Expires')).not.toBeInTheDocument();
    expect(screen.queryByText(/remaining/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Expired/)).not.toBeInTheDocument();
  });
});

// ==========================================================================
// 4 - GeneratorPage
// ==========================================================================

describe('GeneratorPage', () => {
  it('renders the "Password Generator" heading', async () => {
    const { default: GeneratorPage } = await import('../src/pages/GeneratorPage');

    renderWithRouter(<GeneratorPage />);

    expect(screen.getByText('Password Generator')).toBeInTheDocument();
  });

  it('renders the PasswordGenerator component', async () => {
    const { default: GeneratorPage } = await import('../src/pages/GeneratorPage');

    renderWithRouter(<GeneratorPage />);

    expect(screen.getByTestId('password-generator')).toBeInTheDocument();
  });
});

// ==========================================================================
// VaultItemDetail — resilience to schema-invalid decrypted items (T25)
//
// When decryption succeeds but Zod validation fails, vaultStore keeps the raw,
// un-defaulted payload (flagged `_validationError`, or wrapped in `_raw` for a
// non-object). The type views iterate `uris`/`customFields` unguarded, so such
// an item would throw and (with no local ErrorBoundary on VaultItemPage)
// escalate to the app-wide crash screen — stranding delete/restore. These
// tests assert the item degrades gracefully and the action bar stays reachable.
// ==========================================================================

describe('VaultItemDetail — schema-invalid item resilience', () => {
  const onEdit = vi.fn();

  beforeEach(() => {
    onEdit.mockClear();
  });

  it('degrades a _validationError login (missing uris/customFields) instead of crashing', () => {
    const item = makeDecryptedItem({
      name: 'Broken Login',
      itemType: 'login',
      tags: ['important'],
      // Raw, un-defaulted payload the store keeps on a Zod failure: no
      // `uris`/`customFields`, so the type view would do `undefined.map(...)`.
      data: { username: 'still-here', _validationError: true },
    });

    expect(() =>
      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />),
    ).not.toThrow();

    expect(screen.getByText(/could not be fully decoded/i)).toBeInTheDocument();
    // Identity + remediation actions remain reachable.
    expect(screen.getByText('Broken Login')).toBeInTheDocument();
    expect(screen.getByText('important')).toBeInTheDocument();
    expect(screen.getByText('Edit')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
  });

  it('degrades a _validationError secret (missing customFields) instead of crashing', () => {
    const item = makeDecryptedItem({
      name: 'Broken Secret',
      itemType: 'secret',
      data: { value: 'partial', _validationError: true },
    });

    expect(() =>
      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />),
    ).not.toThrow();

    expect(screen.getByText(/could not be fully decoded/i)).toBeInTheDocument();
  });

  it('degrades a non-object (_raw) decrypted payload instead of crashing', () => {
    const item = makeDecryptedItem({
      name: 'Raw Payload',
      itemType: 'login',
      data: { _raw: 'not-an-object' },
    });

    expect(() =>
      renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />),
    ).not.toThrow();

    expect(screen.getByText(/could not be fully decoded/i)).toBeInTheDocument();
  });

  it('the local ErrorBoundary contains an unforeseen render throw and keeps the action bar', () => {
    // Not flagged, but the data is missing the arrays the login view iterates,
    // so the type view throws. The boundary degrades just this section; the
    // header/action bar above stay mounted (delete/restore still usable).
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const item = makeDecryptedItem({
        name: 'Unflagged Broken',
        itemType: 'login',
        data: { username: 'x', password: 'y' }, // no uris / customFields, no flags
      });

      expect(() =>
        renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />),
      ).not.toThrow();

      expect(screen.getByText(/could not be fully decoded/i)).toBeInTheDocument();
      expect(screen.getByText('Edit')).toBeInTheDocument();
      expect(screen.getByText('Delete')).toBeInTheDocument();
    } finally {
      consoleError.mockRestore();
    }
  });

  it('still renders a well-formed item normally (no false-positive degradation)', () => {
    const item = makeDecryptedItem({
      name: 'Healthy Login',
      itemType: 'login',
      data: {
        username: 'octocat',
        password: 'gh-secret',
        uris: [],
        totp: '',
        notes: '',
        customFields: [],
      },
    });

    renderWithRouter(<VaultItemDetail item={item as never} onEdit={onEdit} />);

    expect(screen.queryByText(/could not be fully decoded/i)).not.toBeInTheDocument();
    expect(screen.getByText('octocat')).toBeInTheDocument();
  });
});
