/**
 * Comprehensive rendering and behavior tests for page and vault components
 * with 0% or low coverage.
 *
 * Covers:
 * 1 - App.tsx (LoadingSpinner, route structure)
 * 2 - ForgotPasswordPage (form, submission, success/error states)
 * 3 - VaultList (empty state, items, sort, type badges, search filtering)
 * 4 - VaultItemDetail (all item types, copy, masking, favorite, trashed)
 * 5 - FolderSidebar (folder tree, selection, type filters, favorites)
 * 6 - SettingsPage (sections rendering, theme selector, profile)
 * 7 - SessionsPage (session list, current session marker, error/empty states)
 * 8 - AuditLogPage (table rendering, pagination, filter)
 * 9 - VaultHealthPage (health score, sections, score cards)
 * 10 - VaultPage (layout, sidebar, create dialog)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom
// ---------------------------------------------------------------------------

// vi.hoisted runs before vi.mock hoisting, ensuring matchMedia exists
// before any module code executes (e.g. uiStore top-level matchMedia call).
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

// ---------------------------------------------------------------------------
// Mock variables (hoisted)
// ---------------------------------------------------------------------------

const {
  mockForgotPasswordApi,
  mockVerifyEmailApi,
  mockResetPasswordApi,
  mockUnlockAccountApi,
  mockListSessionsApi,
  mockRevokeSessionApi,
  mockLogoutAllApi,
  mockGetAuditLogApi,
  mockGetProfileApi,
  mockUpdateSettingsApi,
  mockCheckBreachApi,
} = vi.hoisted(() => ({
  mockForgotPasswordApi: vi.fn(),
  mockVerifyEmailApi: vi.fn(),
  mockResetPasswordApi: vi.fn(),
  mockUnlockAccountApi: vi.fn(),
  mockListSessionsApi: vi.fn(),
  mockRevokeSessionApi: vi.fn(),
  mockLogoutAllApi: vi.fn(),
  mockGetAuditLogApi: vi.fn(),
  mockGetProfileApi: vi.fn(),
  mockUpdateSettingsApi: vi.fn(),
  mockCheckBreachApi: vi.fn(),
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
  logoutAllApi: (...args: unknown[]) => mockLogoutAllApi(...args),
  forgotPasswordApi: (...args: unknown[]) => mockForgotPasswordApi(...args),
  verifyEmailApi: (...args: unknown[]) => mockVerifyEmailApi(...args),
  resetPasswordApi: (...args: unknown[]) => mockResetPasswordApi(...args),
  unlockAccountApi: (...args: unknown[]) => mockUnlockAccountApi(...args),
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
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
  updateSettingsApi: (...args: unknown[]) => mockUpdateSettingsApi(...args),
  changePasswordApi: vi.fn(),
  setup2faApi: vi.fn(),
  verify2faApi: vi.fn(),
  disable2faApi: vi.fn(),
  exportVaultApi: vi.fn(),
  importVaultApi: vi.fn(),
  listSessionsApi: (...args: unknown[]) => mockListSessionsApi(...args),
  revokeSessionApi: (...args: unknown[]) => mockRevokeSessionApi(...args),
  getAuditLogApi: (...args: unknown[]) => mockGetAuditLogApi(...args),
  checkBreachApi: (...args: unknown[]) => mockCheckBreachApi(...args),
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
    // Simulate realistic strength scoring for tests
    if (password.length <= 5)
      return { score: 0, feedback: { warning: 'Very weak', suggestions: [] } };
    if (password.length <= 8) return { score: 2, feedback: { warning: 'Fair', suggestions: [] } };
    if (password.length <= 12) return { score: 3, feedback: { warning: '', suggestions: [] } };
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

// Mock QRCode for SettingsPage
vi.mock('qrcode', () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,mock'),
  },
}));

// Mock VaultItemForm to avoid pulling in form complexity
vi.mock('../src/components/vault/VaultItemForm', () => ({
  VaultItemForm: ({ onCancel }: { onCancel?: () => void }) =>
    React.createElement(
      'div',
      { 'data-testid': 'vault-item-form' },
      React.createElement('button', { onClick: onCancel }, 'Cancel Form'),
    ),
}));

// ---------------------------------------------------------------------------
// Store imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useUIStore } from '../src/stores/uiStore';

// ---------------------------------------------------------------------------
// Component imports
// ---------------------------------------------------------------------------

import { FolderSidebar } from '../src/components/vault/FolderSidebar';
import { VaultItemDetail } from '../src/components/vault/VaultItemDetail';
import { VaultList } from '../src/components/vault/VaultList';
import { ForgotPasswordPage } from '../src/components/auth/ForgotPasswordPage';
import VerifyEmailPage from '../src/pages/VerifyEmailPage';
import UnlockAccountPage from '../src/pages/UnlockAccountPage';
import ResetPasswordPage from '../src/pages/ResetPasswordPage';

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
  }> = {},
) {
  const now = overrides.updatedAt ?? new Date().toISOString();
  const created = overrides.createdAt ?? now;
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
      passwordHistory: [],
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
    color: string;
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
      createdAt: now,
      updatedAt: now,
    },
  };
}

// Reset stores before each test
beforeEach(() => {
  vi.clearAllMocks();

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

  useUIStore.setState({
    theme: 'system',
    sidebarOpen: true,
    commandPaletteOpen: false,
    offlineCacheAvailable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ==========================================================================
// 1 - App.tsx
// ==========================================================================
//
// The former describe('App') block (three tests) was removed as vacuous: one
// asserted only `expect(container).toBeTruthy()` (true for any render), one
// rendered a locally-built <div>Loading...</div> that touched no production
// code, and one asserted `expect(mod.App).toBeDefined()` (true by construction).
// The REAL App component — its lazy route table, ProtectedRoute/PublicOnlyRoute/
// AppLayout wrapping, "/" → /vault redirect, NotFound, and the ReloadPrompt — is
// exercised behaviorally by the "App route table" describe in
// coverage-services-stores.test.ts, which renders the real App at each route.

// ==========================================================================
// 2 - ForgotPasswordPage
// ==========================================================================

describe('ForgotPasswordPage', () => {
  it('renders the form with email input and submit button', () => {
    renderWithRouter(<ForgotPasswordPage />);

    expect(screen.getByText('Forgot Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('you@example.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument();
  });

  it('renders "Back to sign in" link pointing to /login', () => {
    renderWithRouter(<ForgotPasswordPage />);

    const link = screen.getByText('Back to sign in');
    expect(link).toBeInTheDocument();
    expect(link.closest('a')).toHaveAttribute('href', '/login');
  });

  it('shows validation error when email is empty on submit', async () => {
    renderWithRouter(<ForgotPasswordPage />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    await waitFor(() => {
      expect(screen.getByText('Email is required')).toBeInTheDocument();
    });
  });

  it('does not submit when email field is empty', async () => {
    renderWithRouter(<ForgotPasswordPage />);

    // Leave the email empty and click submit
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    // The form should not navigate to success view - it stays on the form
    await waitFor(() => {
      expect(screen.getByText('Forgot Password')).toBeInTheDocument();
    });

    // The API should NOT have been called
    expect(mockForgotPasswordApi).not.toHaveBeenCalled();
  });

  it('shows success view after successful submission', async () => {
    mockForgotPasswordApi.mockResolvedValue({ data: { success: true, data: { emailSent: true } } });

    renderWithRouter(<ForgotPasswordPage />);

    const input = screen.getByPlaceholderText('you@example.com');
    await act(async () => {
      fireEvent.change(input, { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    await waitFor(() => {
      expect(screen.getByText('Check Your Email')).toBeInTheDocument();
    });
    expect(mockForgotPasswordApi).toHaveBeenCalledWith({ email: 'test@example.com' });
  });

  it('shows error message on API failure', async () => {
    mockForgotPasswordApi.mockRejectedValue(new Error('Server error'));

    renderWithRouter(<ForgotPasswordPage />);

    const input = screen.getByPlaceholderText('you@example.com');
    await act(async () => {
      fireEvent.change(input, { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  it('shows warning when email could not be sent', async () => {
    mockForgotPasswordApi.mockResolvedValue({
      data: { success: true, data: { emailSent: false } },
    });

    renderWithRouter(<ForgotPasswordPage />);

    const input = screen.getByPlaceholderText('you@example.com');
    await act(async () => {
      fireEvent.change(input, { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    await waitFor(() => {
      expect(screen.getByText('Email Could Not Be Sent')).toBeInTheDocument();
    });
  });

  it('success view has back to sign in link', async () => {
    mockForgotPasswordApi.mockResolvedValue({ data: { success: true, data: { emailSent: true } } });

    renderWithRouter(<ForgotPasswordPage />);

    const input = screen.getByPlaceholderText('you@example.com');
    await act(async () => {
      fireEvent.change(input, { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));
    });

    await waitFor(() => {
      expect(screen.getByText('Check Your Email')).toBeInTheDocument();
    });

    const link = screen.getByText('Back to sign in');
    expect(link.closest('a')).toHaveAttribute('href', '/login');
  });
});

// ==========================================================================
// 2b - VerifyEmailPage
// ==========================================================================

describe('VerifyEmailPage', () => {
  beforeEach(() => {
    mockVerifyEmailApi.mockReset();
  });

  it('shows loading state initially when token is present', () => {
    mockVerifyEmailApi.mockReturnValue(new Promise(() => {})); // never resolves
    renderWithRouter(<VerifyEmailPage />, { route: '/verify-email?token=test-token' });

    expect(screen.getByText('Verifying Email')).toBeInTheDocument();
  });

  it('shows success after verifying email', async () => {
    mockVerifyEmailApi.mockResolvedValue({
      data: { success: true, message: 'Email verified successfully' },
    });
    renderWithRouter(<VerifyEmailPage />, { route: '/verify-email?token=test-token' });

    await waitFor(() => {
      expect(screen.getByText('Email Verified')).toBeInTheDocument();
    });
    expect(mockVerifyEmailApi).toHaveBeenCalledWith({ token: 'test-token' });
  });

  it('shows error when verification fails', async () => {
    mockVerifyEmailApi.mockRejectedValue(new Error('Token expired'));
    renderWithRouter(<VerifyEmailPage />, { route: '/verify-email?token=bad-token' });

    await waitFor(() => {
      expect(screen.getByText('Verification Failed')).toBeInTheDocument();
    });
  });

  it('shows error when no token is provided', () => {
    renderWithRouter(<VerifyEmailPage />, { route: '/verify-email' });

    expect(screen.getByText('Verification Failed')).toBeInTheDocument();
    expect(screen.getByText(/no verification token/i)).toBeInTheDocument();
    expect(mockVerifyEmailApi).not.toHaveBeenCalled();
  });

  it('has link to sign in after verification', async () => {
    mockVerifyEmailApi.mockResolvedValue({ data: { success: true, message: 'OK' } });
    renderWithRouter(<VerifyEmailPage />, { route: '/verify-email?token=test-token' });

    await waitFor(() => {
      expect(screen.getByText('Email Verified')).toBeInTheDocument();
    });
    expect(screen.getByText('Go to sign in').closest('a')).toHaveAttribute('href', '/login');
  });
});

// ==========================================================================
// 2c - UnlockAccountPage
// ==========================================================================

describe('UnlockAccountPage', () => {
  beforeEach(() => {
    mockUnlockAccountApi.mockReset();
  });

  it('shows loading state initially when token is present', () => {
    mockUnlockAccountApi.mockReturnValue(new Promise(() => {}));
    renderWithRouter(<UnlockAccountPage />, { route: '/unlock-account?token=test-token' });

    expect(screen.getByText('Unlocking Account')).toBeInTheDocument();
  });

  it('shows success after unlocking account', async () => {
    mockUnlockAccountApi.mockResolvedValue({
      data: { success: true, message: 'Account unlocked' },
    });
    renderWithRouter(<UnlockAccountPage />, { route: '/unlock-account?token=test-token' });

    await waitFor(() => {
      expect(screen.getByText('Account Unlocked')).toBeInTheDocument();
    });
    expect(mockUnlockAccountApi).toHaveBeenCalledWith({ token: 'test-token' });
  });

  it('shows error when unlock fails', async () => {
    mockUnlockAccountApi.mockRejectedValue(new Error('Token expired'));
    renderWithRouter(<UnlockAccountPage />, { route: '/unlock-account?token=bad-token' });

    await waitFor(() => {
      expect(screen.getByText('Unlock Failed')).toBeInTheDocument();
    });
  });

  it('shows error when no token is provided', () => {
    renderWithRouter(<UnlockAccountPage />, { route: '/unlock-account' });

    expect(screen.getByText('Unlock Failed')).toBeInTheDocument();
    expect(mockUnlockAccountApi).not.toHaveBeenCalled();
  });
});

// ==========================================================================
// 2d - ResetPasswordPage
// ==========================================================================

describe('ResetPasswordPage', () => {
  beforeEach(() => {
    mockResetPasswordApi.mockReset();
  });

  it('shows invalid link message when no token is provided', () => {
    renderWithRouter(<ResetPasswordPage />, { route: '/reset-password' });

    expect(screen.getByText('Invalid Link')).toBeInTheDocument();
    expect(screen.getByText('Request new reset link').closest('a')).toHaveAttribute(
      'href',
      '/forgot-password',
    );
  });

  it('renders the password reset form when token is present', () => {
    renderWithRouter(<ResetPasswordPage />, { route: '/reset-password?token=test-token' });

    expect(screen.getByRole('heading', { name: /reset password/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('New Master Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm New Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /reset password/i })).toBeInTheDocument();
  });

  it('shows data loss warning', () => {
    renderWithRouter(<ResetPasswordPage />, { route: '/reset-password?token=test-token' });

    expect(screen.getByText(/vault items will become unrecoverable/i)).toBeInTheDocument();
  });

  it('shows validation error for mismatched passwords', async () => {
    renderWithRouter(<ResetPasswordPage />, { route: '/reset-password?token=test-token' });

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'test@example.com' } });
      fireEvent.change(screen.getByLabelText('New Master Password'), {
        target: { value: 'SecurePassword12' },
      });
      fireEvent.change(screen.getByLabelText('Confirm New Password'), {
        target: { value: 'DifferentPass12' },
      });
      fireEvent.click(screen.getByRole('button', { name: /reset password/i }));
    });

    await waitFor(() => {
      expect(screen.getByText('Passwords do not match')).toBeInTheDocument();
    });
  });

  it('has back to sign in link', () => {
    renderWithRouter(<ResetPasswordPage />, { route: '/reset-password?token=test-token' });

    expect(screen.getByText('Back to sign in').closest('a')).toHaveAttribute('href', '/login');
  });
});

// ==========================================================================
// 3 - VaultList (additional coverage beyond components-rendering.test.tsx)
// ==========================================================================

describe('VaultList - additional coverage', () => {
  const onCreateNew = vi.fn();

  beforeEach(() => {
    onCreateNew.mockClear();
  });

  it('filters items by search query', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Github Login', itemType: 'login' }),
        makeDecryptedItem({ id: 'i2', name: 'Work Email', itemType: 'login' }),
      ] as never[],
      searchQuery: 'github',
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Github Login')).toBeInTheDocument();
    expect(screen.queryByText('Work Email')).not.toBeInTheDocument();
  });

  it('filters items by selected type', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'My Login', itemType: 'login' }),
        makeDecryptedItem({
          id: 'i2',
          name: 'My Note',
          itemType: 'note',
          data: { content: 'hello', format: 'plaintext' },
        }),
      ] as never[],
      selectedType: 'note',
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('My Note')).toBeInTheDocument();
    expect(screen.queryByText('My Login')).not.toBeInTheDocument();
  });

  it('filters items by favorites', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Fav Item', favorite: true }),
        makeDecryptedItem({ id: 'i2', name: 'Regular Item', favorite: false }),
      ] as never[],
      showFavorites: true,
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Fav Item')).toBeInTheDocument();
    expect(screen.queryByText('Regular Item')).not.toBeInTheDocument();
  });

  it('filters items by selected folder', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Folder Item', folderId: 'f1' }),
        makeDecryptedItem({ id: 'i2', name: 'No Folder Item' }),
      ] as never[],
      selectedFolder: 'f1',
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Folder Item')).toBeInTheDocument();
    expect(screen.queryByText('No Folder Item')).not.toBeInTheDocument();
  });

  it('shows trash items when in trash view', () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Active Item' })] as never[],
      trashItems: [makeDecryptedItem({ id: 'i2', name: 'Trashed Item' })] as never[],
      showTrash: true,
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Trashed Item')).toBeInTheDocument();
    expect(screen.queryByText('Active Item')).not.toBeInTheDocument();
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

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    const itemElements = screen.getAllByRole('button');
    const itemTexts = itemElements
      .map((el) => el.textContent)
      .filter((t) => t?.includes('Alpha') || t?.includes('Zebra'));
    expect(itemTexts[0]).toContain('Alpha');
    expect(itemTexts[1]).toContain('Zebra');
  });

  it('shows "Empty Trash" button when in trash view with items', () => {
    useVaultStore.setState({
      trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
      showTrash: true,
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Empty Trash')).toBeInTheDocument();
  });

  it('hides floating create button in trash view', () => {
    useVaultStore.setState({
      trashItems: [makeDecryptedItem({ id: 'i1', name: 'Trashed' })] as never[],
      showTrash: true,
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.queryByLabelText('Create new item')).not.toBeInTheDocument();
  });

  it('renders all item type badges', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'L', itemType: 'login' }),
        makeDecryptedItem({
          id: 'i2',
          name: 'S',
          itemType: 'secret',
          data: { value: 'x', description: '', customFields: [] },
        }),
        makeDecryptedItem({
          id: 'i3',
          name: 'N',
          itemType: 'note',
          data: { content: 'x', format: 'plaintext' },
        }),
        makeDecryptedItem({
          id: 'i4',
          name: 'C',
          itemType: 'card',
          data: {
            cardholderName: 'x',
            number: '1234',
            expMonth: '01',
            expYear: '25',
            cvv: '123',
            brand: '',
          },
        }),
        makeDecryptedItem({
          id: 'i5',
          name: 'I',
          itemType: 'identity',
          data: { firstName: 'x', lastName: 'y' },
        }),
      ] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.getByText('Secret')).toBeInTheDocument();
    expect(screen.getByText('Note')).toBeInTheDocument();
    expect(screen.getByText('Card')).toBeInTheDocument();
    expect(screen.getByText('Identity')).toBeInTheDocument();
  });

  it('opens sort menu when sort button is clicked', () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    // Click the sort button (shows current sort "Name")
    fireEvent.click(screen.getByText('Name'));

    // Menu should show sort options
    expect(screen.getByText('Date Created')).toBeInTheDocument();
    expect(screen.getByText('Date Modified')).toBeInTheDocument();
    expect(screen.getByText('Type')).toBeInTheDocument();
  });

  it('toggles sort order when sort order button is clicked', () => {
    const setSortOrder = vi.fn();
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item' })] as never[],
      sortOrder: 'asc',
      setSortOrder,
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    const orderButton = screen.getByLabelText('Sort descending');
    fireEvent.click(orderButton);

    expect(setSortOrder).toHaveBeenCalledWith('desc');
  });

  it('shows selection bar when items are selected via checkbox', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Item 1' }),
        makeDecryptedItem({ id: 'i2', name: 'Item 2' }),
      ] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    // Find the checkboxes
    const checkboxes = screen.getAllByLabelText('Select item');
    fireEvent.click(checkboxes[0]!);

    expect(screen.getByText('1 selected')).toBeInTheDocument();
    expect(screen.getByText('Clear')).toBeInTheDocument();
  });
});

// ==========================================================================
// 4 - VaultItemDetail (additional coverage)
// ==========================================================================

describe('VaultItemDetail - additional coverage', () => {
  const onEdit = vi.fn();

  beforeEach(() => {
    onEdit.mockClear();
  });

  it('renders secret item details with value and description', () => {
    const item = makeDecryptedItem({
      name: 'API Key',
      itemType: 'secret',
      data: {
        value: 'sk-12345',
        description: 'My API Key',
        customFields: [],
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('API Key')).toBeInTheDocument();
    expect(screen.getByText('Value')).toBeInTheDocument();
    expect(screen.getByText('Description')).toBeInTheDocument();
  });

  it('renders card item details with cardholder and masked number', () => {
    const item = makeDecryptedItem({
      name: 'My Card',
      itemType: 'card',
      data: {
        cardholderName: 'John Doe',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2027',
        cvv: '123',
        brand: 'Visa',
        notes: '',
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('My Card')).toBeInTheDocument();
    expect(screen.getByText('Cardholder Name')).toBeInTheDocument();
    expect(screen.getByText('Expiry')).toBeInTheDocument();
    expect(screen.getByText('CVV')).toBeInTheDocument();
    expect(screen.getByText('Brand')).toBeInTheDocument();
  });

  it('renders identity item details with first and last name', () => {
    const item = makeDecryptedItem({
      name: 'My Identity',
      itemType: 'identity',
      data: {
        firstName: 'Jane',
        lastName: 'Doe',
        email: 'jane@example.com',
        phone: '+1234567890',
        notes: '',
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('My Identity')).toBeInTheDocument();
    expect(screen.getByText('First Name')).toBeInTheDocument();
    expect(screen.getByText('Last Name')).toBeInTheDocument();
    expect(screen.getByText('Email')).toBeInTheDocument();
    expect(screen.getByText('Phone')).toBeInTheDocument();
  });

  it('renders identity item with address fields', () => {
    const item = makeDecryptedItem({
      name: 'Full Identity',
      itemType: 'identity',
      data: {
        firstName: 'Jane',
        lastName: 'Doe',
        address: {
          street: '123 Main St',
          city: 'Anytown',
          state: 'CA',
          zip: '90210',
          country: 'US',
        },
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Street')).toBeInTheDocument();
    expect(screen.getByText('City')).toBeInTheDocument();
    expect(screen.getByText('State')).toBeInTheDocument();
    expect(screen.getByText('ZIP')).toBeInTheDocument();
    expect(screen.getByText('Country')).toBeInTheDocument();
  });

  it('renders note item with plaintext format', () => {
    const item = makeDecryptedItem({
      name: 'Plain Note',
      itemType: 'note',
      data: {
        content: 'This is a plain text note',
        format: 'plaintext',
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('This is a plain text note')).toBeInTheDocument();
  });

  it('renders note item with markdown format using ReactMarkdown', () => {
    const item = makeDecryptedItem({
      name: 'Markdown Note',
      itemType: 'note',
      data: {
        content: '# Hello World',
        format: 'markdown',
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByTestId('markdown-content')).toBeInTheDocument();
  });

  it('renders secret item with expiry date', () => {
    const item = makeDecryptedItem({
      name: 'Expiring Secret',
      itemType: 'secret',
      data: {
        value: 'secret-value',
        description: '',
        expiresAt: '2026-12-31T00:00:00.000Z',
        customFields: [],
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Expires')).toBeInTheDocument();
  });

  it('renders login item with custom fields', () => {
    const item = makeDecryptedItem({
      name: 'Custom Login',
      itemType: 'login',
      data: {
        username: 'user',
        password: 'pass',
        uris: [],
        totp: '',
        notes: '',
        customFields: [
          { name: 'API Key', value: 'key123', type: 'text' },
          { name: 'Secret Key', value: 'secret456', type: 'hidden' },
          { name: 'Active', value: 'true', type: 'boolean' },
        ],
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('API Key')).toBeInTheDocument();
    expect(screen.getByText('Secret Key')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Yes')).toBeInTheDocument();
  });

  it('shows "No folder" when item has no folder', () => {
    const item = makeDecryptedItem({ name: 'No Folder Item' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('No folder')).toBeInTheDocument();
  });

  it('shows folder name when item is in a folder', () => {
    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
    });

    const item = makeDecryptedItem({ name: 'Work Item', folderId: 'f1' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Work')).toBeInTheDocument();
  });

  it('shows delete confirmation dialog when Delete is clicked', () => {
    const item = makeDecryptedItem({ name: 'Delete Me' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText('Delete'));

    expect(screen.getByText('Delete Item')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('shows permanent delete dialog for trashed items', () => {
    const item = makeDecryptedItem({ name: 'Perm Delete' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText('Delete Forever'));

    expect(screen.getByText('Permanently Delete Item')).toBeInTheDocument();
  });

  it('shows Created and Modified metadata', () => {
    const item = makeDecryptedItem({
      name: 'Metadata Item',
      createdAt: '2025-01-01T00:00:00.000Z',
      updatedAt: '2025-06-15T12:00:00.000Z',
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Created')).toBeInTheDocument();
    expect(screen.getByText('Modified')).toBeInTheDocument();
  });

  it('opens move folder menu when folder button is clicked', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Work' }),
        makeFolder({ id: 'f2', name: 'Personal' }),
      ] as never[],
    });

    const item = makeDecryptedItem({ name: 'Move Me' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText('No folder'));

    // Folder menu should show options
    expect(screen.getByText('Work')).toBeInTheDocument();
    expect(screen.getByText('Personal')).toBeInTheDocument();
  });
});

// ==========================================================================
// 5 - FolderSidebar (additional coverage)
// ==========================================================================

describe('FolderSidebar - additional coverage', () => {
  it('calls setSelectedFolder(null) and clears filters when "All Items" is clicked', () => {
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

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('All Items'));

    expect(setSelectedFolder).toHaveBeenCalledWith(null);
    expect(setSelectedType).toHaveBeenCalledWith(null);
    expect(setShowFavorites).toHaveBeenCalledWith(false);
    expect(setShowTrash).toHaveBeenCalledWith(false);
  });

  it('toggles Favorites filter when clicked', () => {
    const toggleFavorites = vi.fn();
    const setSelectedType = vi.fn();
    useVaultStore.setState({ toggleFavorites, setSelectedType });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Favorites'));

    expect(toggleFavorites).toHaveBeenCalled();
  });

  it('toggles Trash filter when clicked', () => {
    const toggleTrash = vi.fn();
    const setSelectedType = vi.fn();
    useVaultStore.setState({ toggleTrash, setSelectedType });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Trash'));

    expect(toggleTrash).toHaveBeenCalled();
  });

  it('selects a type filter when clicked', () => {
    const setSelectedType = vi.fn();
    const setSelectedFolder = vi.fn();
    const setShowFavorites = vi.fn();
    const setShowTrash = vi.fn();

    useVaultStore.setState({ setSelectedType, setSelectedFolder, setShowFavorites, setShowTrash });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Logins'));

    expect(setSelectedType).toHaveBeenCalledWith('login');
    expect(setSelectedFolder).toHaveBeenCalledWith(null);
  });

  it('deselects type filter when same type is clicked again', () => {
    const setSelectedType = vi.fn();
    const setSelectedFolder = vi.fn();
    const setShowFavorites = vi.fn();
    const setShowTrash = vi.fn();

    useVaultStore.setState({
      selectedType: 'login',
      setSelectedType,
      setSelectedFolder,
      setShowFavorites,
      setShowTrash,
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Logins'));

    expect(setSelectedType).toHaveBeenCalledWith(null);
  });

  it('renders folder tree with nested children', () => {
    useVaultStore.setState({
      folders: [
        makeFolder({ id: 'f1', name: 'Parent', sortOrder: 0 }),
        makeFolder({ id: 'f2', name: 'Child', sortOrder: 0, parentId: 'f1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    expect(screen.getByText('Parent')).toBeInTheDocument();
    expect(screen.getByText('Child')).toBeInTheDocument();
  });

  it('shows trash count when there are trash items', () => {
    useVaultStore.setState({
      trashItems: [
        makeDecryptedItem({ id: 'i1', name: 'Trashed 1' }),
        makeDecryptedItem({ id: 'i2', name: 'Trashed 2' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    // The trash count badge should show 2
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('shows favorite count when there are favorite items', () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Fav', favorite: true })] as never[],
    });

    renderWithRouter(<FolderSidebar />);

    // All Items count = 1, favorites count = 1
    const badges = screen.getAllByText('1');
    expect(badges.length).toBeGreaterThanOrEqual(1);
  });

  it('selects a folder when folder is clicked', () => {
    const setSelectedFolder = vi.fn();
    const setSelectedType = vi.fn();

    useVaultStore.setState({
      folders: [makeFolder({ id: 'f1', name: 'Work' })] as never[],
      setSelectedFolder,
      setSelectedType,
    });

    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByText('Work'));

    expect(setSelectedFolder).toHaveBeenCalledWith('f1');
  });

  it('cancels new folder dialog when Cancel is clicked', () => {
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));
    expect(screen.getByText('New Folder')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByPlaceholderText('Folder name')).not.toBeInTheDocument();
  });
});

// ==========================================================================
// 6 - SettingsPage
// ==========================================================================

// ==========================================================================
// 6 - SettingsPage
// ==========================================================================
//
// The former describe('SettingsPage') block (nine static-render smoke tests:
// heading, loading spinner, profile email, Verified/Not verified, Security/
// Appearance/Data sections) was removed as a strict, redundant subset of
// settings-pages.test.tsx, which owns SettingsPage coverage with a far richer
// mock surface and asserts the same strings (Settings heading, animate-spin
// spinner, test@example.com, Verified/Not verified, Appearance + Light/Dark/
// System, Export Vault/Import Vault) PLUS the section behaviors (change
// password, 2FA enable/verify/disable, theme switching, export/import flows,
// vault key rotation). Keeping both only duplicated runtime with no added signal.

// ==========================================================================
// 7 - SessionsPage
// ==========================================================================

describe('SessionsPage', () => {
  it('shows loading spinner initially', async () => {
    mockListSessionsApi.mockReturnValue(new Promise(() => {}));

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    const { container } = render(
      <MemoryRouter>
        <SessionsPage />
      </MemoryRouter>,
    );

    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('renders "Active Sessions" heading', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: { success: true, data: [] },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Active Sessions')).toBeInTheDocument();
    });
  });

  it('shows "No active sessions found" when sessions list is empty', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: { success: true, data: [] },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('No active sessions found.')).toBeInTheDocument();
    });
  });

  it('renders session list with browser and OS info', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: {
              userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',
              ip: '192.168.1.1',
            },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
          {
            _id: 's2',
            current: false,
            deviceInfo: {
              userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604',
              ip: '10.0.0.1',
            },
            createdAt: '2025-02-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
      expect(screen.getByText('Safari on iOS')).toBeInTheDocument();
    });
  });

  it('marks the current session with "Current" badge', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: {
              userAgent: 'Chrome/120 Windows',
              ip: '192.168.1.1',
            },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Current')).toBeInTheDocument();
    });
  });

  it('does not show Revoke button for current session', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: { userAgent: 'Chrome', ip: '127.0.0.1' },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Current')).toBeInTheDocument();
    });

    expect(screen.queryByText('Revoke')).not.toBeInTheDocument();
  });

  it('shows Revoke button for non-current sessions', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: { userAgent: 'Chrome', ip: '127.0.0.1' },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
          {
            _id: 's2',
            current: false,
            deviceInfo: { userAgent: 'Firefox', ip: '10.0.0.1' },
            createdAt: '2025-02-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Revoke')).toBeInTheDocument();
    });
  });

  it('shows error state with retry button on failure', async () => {
    mockListSessionsApi.mockRejectedValue(new Error('Network error'));

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Failed to load sessions')).toBeInTheDocument();
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });
  });

  it('shows "Revoke All Other Sessions" button when more than 1 session', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: { userAgent: 'Chrome', ip: '127.0.0.1' },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
          {
            _id: 's2',
            current: false,
            deviceInfo: { userAgent: 'Firefox', ip: '10.0.0.1' },
            createdAt: '2025-02-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Revoke All Other Sessions')).toBeInTheDocument();
    });
  });

  it('renders back to settings button', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: { success: true, data: [] },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByLabelText('Back to settings')).toBeInTheDocument();
    });
  });

  it('displays revocation latency notice', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: { success: true, data: [] },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(
        screen.getByText(/active sessions may take up to 5 minutes to fully terminate/i),
      ).toBeInTheDocument();
    });
  });

  it('displays session IP address', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: { userAgent: 'Chrome', ip: '192.168.1.100' },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
        ],
      },
    });

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
    });
  });

  it('disables revoke buttons while a session revoke is in progress', async () => {
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 's1',
            current: true,
            deviceInfo: { userAgent: 'Chrome', ip: '127.0.0.1' },
            createdAt: '2025-01-01T00:00:00.000Z',
          },
          {
            _id: 's2',
            current: false,
            deviceInfo: { userAgent: 'Firefox', ip: '10.0.0.1' },
            createdAt: '2025-02-01T00:00:00.000Z',
          },
        ],
      },
    });

    // Make revoke hang indefinitely to test loading state
    mockRevokeSessionApi.mockReturnValue(new Promise(() => {}));

    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    await act(async () => {
      renderWithRouter(<SessionsPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Revoke')).toBeInTheDocument();
    });

    const revokeBtn = screen.getByText('Revoke').closest('button')!;
    expect(revokeBtn).not.toBeDisabled();

    await act(async () => {
      fireEvent.click(revokeBtn);
    });

    await waitFor(() => {
      expect(screen.getByText('Revoking...')).toBeInTheDocument();
    });
  });
});

// ==========================================================================
// 8 - AuditLogPage
// ==========================================================================

describe('AuditLogPage', () => {
  it('renders "Audit Log" heading', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Audit Log')).toBeInTheDocument();
    });
  });

  it('shows loading spinner initially', async () => {
    mockGetAuditLogApi.mockReturnValue(new Promise(() => {}));

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    const { container } = render(
      <MemoryRouter>
        <AuditLogPage />
      </MemoryRouter>,
    );

    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('shows "No audit log entries found" when empty', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('No audit log entries found.')).toBeInTheDocument();
    });
  });

  it('renders audit log table with entries', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 'a1',
            action: 'login',
            ipAddress: '192.168.1.1',
            userAgent: 'Chrome/120',
            timestamp: '2025-06-01T12:00:00.000Z',
          },
          {
            _id: 'a2',
            action: 'item_create',
            ipAddress: '192.168.1.2',
            userAgent: 'Firefox/115',
            timestamp: '2025-06-02T14:00:00.000Z',
          },
        ],
        pagination: { page: 1, limit: 20, total: 2, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      // Action labels appear in both the table rows and the filter dropdown options
      const loginElements = screen.getAllByText('Login');
      expect(loginElements.length).toBeGreaterThanOrEqual(2); // table + dropdown
      const itemCreatedElements = screen.getAllByText('Item Created');
      expect(itemCreatedElements.length).toBeGreaterThanOrEqual(2); // table + dropdown
    });
  });

  it('renders pagination controls', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 'a1',
            action: 'login',
            ipAddress: '192.168.1.1',
            userAgent: 'Chrome',
            timestamp: '2025-06-01T12:00:00.000Z',
          },
        ],
        pagination: { page: 1, limit: 20, total: 40, totalPages: 2 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
      expect(screen.getByText('Prev')).toBeInTheDocument();
      expect(screen.getByText('Next')).toBeInTheDocument();
    });
  });

  it('disables Prev button on first page', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 'a1',
            action: 'login',
            ipAddress: '192.168.1.1',
            userAgent: 'Chrome',
            timestamp: '2025-06-01T12:00:00.000Z',
          },
        ],
        pagination: { page: 1, limit: 20, total: 40, totalPages: 2 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      const prevButton = screen.getByText('Prev').closest('button');
      expect(prevButton).toBeDisabled();
    });
  });

  it('renders filter dropdown with "All Actions" option', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      const select = screen.getByLabelText('Filter by action type');
      expect(select).toBeInTheDocument();
    });

    expect(screen.getByText('All Actions')).toBeInTheDocument();
  });

  it('shows error state with retry on failure', async () => {
    mockGetAuditLogApi.mockRejectedValue(new Error('Network error'));

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Failed to load audit log')).toBeInTheDocument();
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });
  });

  it('renders back to settings button', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByLabelText('Back to settings')).toBeInTheDocument();
    });
  });

  it('renders table headers', async () => {
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            _id: 'a1',
            action: 'login',
            ipAddress: '192.168.1.1',
            userAgent: 'Chrome',
            timestamp: '2025-06-01T12:00:00.000Z',
          },
        ],
        pagination: { page: 1, limit: 20, total: 1, totalPages: 1 },
      },
    });

    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    await act(async () => {
      renderWithRouter(<AuditLogPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('Action')).toBeInTheDocument();
      expect(screen.getByText('Time')).toBeInTheDocument();
    });
  });
});

// ==========================================================================
// 9 - VaultHealthPage
// ==========================================================================

describe('VaultHealthPage', () => {
  beforeEach(() => {
    useVaultStore.setState({
      fetchItems: vi.fn().mockResolvedValue(undefined),
    });
  });

  it('renders "Vault Health" heading and description', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    expect(screen.getByText('Vault Health')).toBeInTheDocument();
    expect(screen.getByText('Security analysis of your vault items')).toBeInTheDocument();
  });

  it('shows health score of 100 when no items exist', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    expect(screen.getByText('100')).toBeInTheDocument();
    expect(screen.getByText('Health Score')).toBeInTheDocument();
  });

  it('renders all health check sections', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    expect(screen.getByText('Weak Passwords')).toBeInTheDocument();
    expect(screen.getByText('Reused Passwords')).toBeInTheDocument();
    expect(screen.getByText('Old Passwords')).toBeInTheDocument();
    expect(screen.getByText('Missing 2FA')).toBeInTheDocument();
    expect(screen.getByText('Breached Passwords')).toBeInTheDocument();
  });

  it('renders score cards', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    expect(screen.getByText('Weak')).toBeInTheDocument();
    expect(screen.getByText('Reused')).toBeInTheDocument();
    expect(screen.getByText('Old')).toBeInTheDocument();
    expect(screen.getByText('No 2FA')).toBeInTheDocument();
  });

  it('renders "Check for Breaches" button', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    expect(screen.getByText('Check for Breaches')).toBeInTheDocument();
  });

  it('shows breach check description when not yet checked', async () => {
    const { default: VaultHealthPage } = await import('../src/pages/VaultHealthPage');

    await act(async () => {
      renderWithRouter(<VaultHealthPage />);
    });

    // The hint text about k-anonymity model
    expect(screen.getByText(/k-anonymity model/)).toBeInTheDocument();
  });

  // Three detection tests were removed as vacuous and are superseded by
  // coverage-vault-health.test.tsx, which asserts the ACTUAL findings inside
  // each section rather than a static heading or an unrelated number:
  //   • weak-password detection ("detects weak…" only checked the score was not
  //     100) → "flags only passwords scoring below 3 and labels them by score"
  //     + "ignores non-login items and passwordless logins".
  //   • missing-TOTP detection ("detects missing TOTP…" only asserted the static
  //     'Missing 2FA' heading, which renders even with zero items) → "flags
  //     logins without a TOTP secret and skips those with one" (asserts the item
  //     name is listed under the section and a TOTP-having login is NOT).
  //   • "0 count badge" (satisfied by any '0' anywhere on the page) → the
  //     health-score describe ("scores 100 with no login items", etc.).
});

// ==========================================================================
// 10 - VaultPage
// ==========================================================================

describe('VaultPage', () => {
  beforeEach(() => {
    useVaultStore.setState({
      fetchItems: vi.fn().mockResolvedValue(undefined),
      fetchTrashItems: vi.fn().mockResolvedValue(undefined),
      fetchFolders: vi.fn().mockResolvedValue(undefined),
    });
  });

  it('renders VaultList component', async () => {
    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    // The VaultList should render its empty state
    expect(screen.getByText('No items found')).toBeInTheDocument();
  });

  it('renders the search bar', async () => {
    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    expect(screen.getByLabelText('Search vault items')).toBeInTheDocument();
  });

  it('renders sidebar toggle button', async () => {
    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    // Desktop sidebar toggle (may show Close sidebar or Open sidebar)
    const toggleButtons = screen.getAllByLabelText(/sidebar/i);
    expect(toggleButtons.length).toBeGreaterThan(0);
  });

  // "toggles sidebar when sidebar toggle is clicked" was removed: its assertion
  // was conditional (if no 'Close sidebar' button existed it silently degraded
  // to asserting an 'Open sidebar' button, so the toggle it was named for was
  // only verified when it already worked). The deterministic mobile-sidebar
  // open/close flow is covered by "VaultPage - mobile sidebar" in
  // coverage-pages-misc.test.tsx (open → backdrop appears; dismiss via backdrop
  // click, Escape, and the in-panel Close button).

  it('opens create item dialog when "Create Item" is clicked', async () => {
    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    fireEvent.click(screen.getByText('Create Item'));

    expect(screen.getByTestId('vault-item-form')).toBeInTheDocument();
  });

  it('closes create item dialog when form cancel is clicked', async () => {
    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    fireEvent.click(screen.getByText('Create Item'));
    expect(screen.getByTestId('vault-item-form')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel Form'));
    expect(screen.queryByTestId('vault-item-form')).not.toBeInTheDocument();
  });

  // "renders mobile sidebar trigger button" was removed: its assertion
  // `expect(triggers.length).toBeGreaterThanOrEqual(0)` is true for every value
  // and can never fail. The mobile trigger is exercised for real by
  // coverage-pages-misc.test.tsx's "VaultPage - mobile sidebar", which clicks
  // 'Open sidebar' and asserts the backdrop panel actually appears.

  it('calls fetchItems, fetchFolders, and fetchTrashItems on mount', async () => {
    const fetchItems = vi.fn().mockResolvedValue(undefined);
    const fetchFolders = vi.fn().mockResolvedValue(undefined);
    const fetchTrashItems = vi.fn().mockResolvedValue(undefined);

    useVaultStore.setState({ fetchItems, fetchFolders, fetchTrashItems });

    const { default: VaultPage } = await import('../src/pages/VaultPage');

    await act(async () => {
      renderWithRouter(<VaultPage />);
    });

    expect(fetchItems).toHaveBeenCalled();
    expect(fetchFolders).toHaveBeenCalled();
    expect(fetchTrashItems).toHaveBeenCalled();
  });
});
