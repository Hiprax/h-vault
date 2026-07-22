/**
 * Comprehensive tests for SettingsPage and BackupSettingsPage.
 *
 * SettingsPage (~1171 lines, ~38% coverage):
 *  - Profile section (email, verified status)
 *  - Security section (change password, 2FA enable/disable)
 *  - Vault section (auto-lock, clipboard clear, vault key rotation)
 *  - Appearance section (theme selector)
 *  - Data section (export, import with JSON/CSV)
 *  - Account section (backup link)
 *  - Save Settings button
 *
 * BackupSettingsPage (~611 lines, ~35% coverage):
 *  - Loading state
 *  - Backup encryption setup (when not configured)
 *  - Backup configuration (auto-backup toggle, schedule, email)
 *  - Action buttons (save, trigger, download)
 *  - Restore from backup flow
 *  - Change backup password flow
 *  - Backup history display
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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
// Mock variables (hoisted so they can be referenced in vi.mock factories)
// ---------------------------------------------------------------------------

const {
  mockGetProfileApi,
  mockUpdateSettingsApi,
  mockChangePasswordApi,
  mockSetup2faApi,
  mockVerify2faApi,
  mockDisable2faApi,
  mockRegenerateBackupCodesApi,
  mockExportVaultApi,
  mockImportVaultApi,
  mockToast,
  mockSetTheme,
  mockApiGet,
  mockApiPost,
  mockApiPut,
} = vi.hoisted(() => ({
  mockGetProfileApi: vi.fn(),
  mockUpdateSettingsApi: vi.fn(),
  mockChangePasswordApi: vi.fn(),
  mockSetup2faApi: vi.fn(),
  mockVerify2faApi: vi.fn(),
  mockDisable2faApi: vi.fn(),
  mockRegenerateBackupCodesApi: vi.fn(),
  mockExportVaultApi: vi.fn(),
  mockImportVaultApi: vi.fn(),
  mockToast: vi.fn(),
  mockSetTheme: vi.fn(),
  mockApiGet: vi.fn(),
  mockApiPost: vi.fn(),
  mockApiPut: vi.fn(),
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
    deriveKeys: vi.fn().mockResolvedValue({
      masterEncryptionKey: new Uint8Array(32),
      authKey: new Uint8Array(32),
    }),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    generateVaultKey: vi.fn(),
    encryptVaultKey: vi.fn().mockResolvedValue({
      encrypted: 'enc',
      iv: 'iv',
      tag: 'tag',
    }),
    decryptVaultKey: vi.fn(),
    importVaultKey: vi.fn().mockResolvedValue(new Uint8Array(32)),
    vaultKeyEqualsRaw: vi.fn().mockResolvedValue(true),
    encryptData: vi.fn().mockResolvedValue({
      encrypted: 'enc',
      iv: 'iv',
      tag: 'tag',
    }),
    decryptData: vi.fn().mockResolvedValue('decrypted'),
    generateSearchHash: vi.fn().mockResolvedValue('hash'),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
    rotateVaultKey: vi.fn().mockResolvedValue({
      newVaultKey: new Uint8Array(32),
      encrypted: 'newEnc',
      iv: 'newIv',
      tag: 'newTag',
    }),
    generateSalt: vi.fn().mockReturnValue(new Uint8Array(16)),
    deriveBEK: vi.fn().mockResolvedValue(new Uint8Array(32)),
    generateBWK: vi.fn().mockReturnValue(new Uint8Array(32)),
    encryptBWK: vi.fn().mockResolvedValue({
      encrypted: 'encBWK',
      iv: 'bwkIv',
      tag: 'bwkTag',
    }),
    encryptVaultKeyWithBWK: vi.fn().mockResolvedValue({
      encrypted: 'bwkEncVK',
      iv: 'bwkVKIv',
      tag: 'bwkVKTag',
    }),
    decryptVaultKeyWithBWK: vi.fn().mockResolvedValue(new Uint8Array(32)),
    decryptBWK: vi.fn().mockResolvedValue(new Uint8Array(32)),
    computeBackupHmac: vi.fn().mockResolvedValue('mock-integrity-hmac'),
    base64ToArrayBuffer: vi.fn().mockReturnValue(new Uint8Array(16)),
    arrayBufferToBase64: vi.fn().mockReturnValue('base64salt'),
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
  bulkReEncryptApi: vi.fn(),
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
  updateSettingsApi: (...args: unknown[]) => mockUpdateSettingsApi(...args),
  changePasswordApi: (...args: unknown[]) => mockChangePasswordApi(...args),
  setup2faApi: (...args: unknown[]) => mockSetup2faApi(...args),
  verify2faApi: (...args: unknown[]) => mockVerify2faApi(...args),
  disable2faApi: (...args: unknown[]) => mockDisable2faApi(...args),
  regenerateBackupCodesApi: (...args: unknown[]) => mockRegenerateBackupCodesApi(...args),
  exportVaultApi: (...args: unknown[]) => mockExportVaultApi(...args),
  importVaultApi: (...args: unknown[]) => mockImportVaultApi(...args),
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
    get: (...args: unknown[]) => mockApiGet(...args),
    post: (...args: unknown[]) => mockApiPost(...args),
    put: (...args: unknown[]) => mockApiPut(...args),
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
    toast: (...args: unknown[]) => mockToast(...args),
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

vi.mock('qrcode', () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,mockqr'),
  },
}));

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 5)
      return { score: 0, feedback: { warning: 'Very weak', suggestions: [] } };
    if (password.length <= 8) return { score: 2, feedback: { warning: 'Fair', suggestions: [] } };
    if (password.length <= 12) return { score: 3, feedback: { warning: '', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

// ---------------------------------------------------------------------------
// Store imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { clearSettingsCache } from '../src/hooks/useUserSettings';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const defaultProfile = {
  email: 'test@example.com',
  emailVerified: true,
  twoFactorEnabled: false,
  settings: {
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system' as const,
    backup: {
      enabled: false,
      scheduleHour: 3,
      backupEmails: [],
      isConfigured: false,
    },
  },
};

function setupDefaultProfileMock(overrides: Record<string, unknown> = {}) {
  mockGetProfileApi.mockResolvedValue({
    data: {
      success: true,
      data: { ...defaultProfile, ...overrides },
    },
  });
}

// ==========================================================================
// 1 - SettingsPage
// ==========================================================================

/** An empty, well-formed first page — enough for `fetchItems()` to complete. */
const EMPTY_ITEMS_PAGE = {
  data: {
    success: true,
    data: [],
    pagination: { page: 1, limit: 200, total: 0, totalPages: 1 },
  },
};

describe('SettingsPage', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    setupDefaultProfileMock();
    // Import resolves conflicts client-side against the WHOLE vault, so it loads
    // the item list before deciding anything. Without a well-formed page here the
    // load fails and the import aborts before sending — by design.
    const { listItemsApi } = await import('../src/services/api/vaultApi');
    vi.mocked(listItemsApi).mockResolvedValue(EMPTY_ITEMS_PAGE as never);
    mockRegenerateBackupCodesApi.mockResolvedValue({
      data: { success: true, data: { backupCodes: [] } },
    });

    useAuthStore.setState({
      accessToken: 'test-token',
      user: { userId: 'u1', email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: new Uint8Array(32) as unknown as CryptoKey,
      mek: new Uint8Array(32) as unknown as CryptoKey,
      encryptedVaultKeyData: null,
      twoFactorRequired: false,
      tempToken: null,
    });

    // Store setTheme mock - do not delegate to real implementation to avoid recursion
    useUIStore.setState({ theme: 'system', setTheme: mockSetTheme });
  });

  async function renderSettings() {
    const { default: SettingsPage } = await import('../src/pages/SettingsPage');
    let result: ReturnType<typeof render>;
    await act(async () => {
      result = renderWithRouter(<SettingsPage />);
    });
    return result!;
  }

  // ---- Rendering / Smoke Tests ----

  it('renders the Settings heading after loading', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument();
    });
  });

  it('shows loading spinner while profile is being fetched', async () => {
    mockGetProfileApi.mockReturnValue(new Promise(() => {}));
    const { default: SettingsPage } = await import('../src/pages/SettingsPage');

    const { container } = render(
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>,
    );

    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('shows error toast when profile fetch fails', async () => {
    mockGetProfileApi.mockRejectedValue(new Error('Network error'));
    await renderSettings();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to load profile', type: 'error' }),
      );
    });
  });

  // ---- Profile Section ----

  it('displays profile email after loading', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
    });
  });

  it('displays "Verified" when email is verified', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Verified')).toBeInTheDocument();
    });
  });

  it('displays "Not verified" when email is not verified', async () => {
    setupDefaultProfileMock({ emailVerified: false });
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Not verified')).toBeInTheDocument();
    });
  });

  // ---- Security Section: Change Password ----

  it('reveals the change password form when Change is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));

    expect(screen.getByPlaceholderText('Current master password')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('New master password')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Confirm new password')).toBeInTheDocument();
  });

  it('shows password strength indicator when new password is typed', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'StrongPassword1!' },
    });

    await waitFor(() => {
      expect(screen.getByText('Very strong')).toBeInTheDocument();
    });
  });

  it('calls changePasswordApi with the correctly-derived payload on successful password change', async () => {
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });

    // Make key derivation password/MEK-dependent (the shared mock otherwise
    // returns identical fixed values for every call, so current vs new authHash
    // and old vs new MEK would be indistinguishable). `Once` variants auto-revert
    // to the default impl afterward, so no other test is contaminated.
    // Call order in handleChangePassword: deriveKeys(current) → deriveKeys(new);
    // getAuthHash(currentAuthKey) → getAuthHash(newAuthKey);
    // encryptVaultKey(vaultKey, newMek).
    vi.mocked(cryptoService.deriveKeys)
      .mockResolvedValueOnce({
        masterEncryptionKey: 'mek-old' as unknown as CryptoKey,
        authKey: 'ak-old' as unknown as CryptoKey,
      })
      .mockResolvedValueOnce({
        masterEncryptionKey: 'mek-new' as unknown as CryptoKey,
        authKey: 'ak-new' as unknown as CryptoKey,
      });
    vi.mocked(cryptoService.getAuthHash)
      .mockReturnValueOnce('hash-old')
      .mockReturnValueOnce('hash-new');
    vi.mocked(cryptoService.encryptVaultKey).mockImplementationOnce(
      async (_vaultKey: CryptoKey, mek: CryptoKey) => ({
        encrypted: `enc-${String(mek)}`,
        iv: 'new-iv',
        tag: 'new-tag',
      }),
    );

    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'OldPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'NewStrongPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'NewStrongPass1!' },
    });

    fireEvent.click(screen.getByText('Change Password'));

    await waitFor(() => {
      expect(mockChangePasswordApi).toHaveBeenCalledTimes(1);
    });

    // currentAuthHash MUST come from the OLD password, newAuthHash from the NEW,
    // and the vault key MUST be re-wrapped with the NEW MEK. Swapping the auth
    // hashes, or wrapping with the old MEK, now fails here.
    expect(mockChangePasswordApi).toHaveBeenCalledWith({
      currentAuthHash: 'hash-old',
      newAuthHash: 'hash-new',
      newEncryptedVaultKey: 'enc-mek-new',
      newVaultKeyIv: 'new-iv',
      newVaultKeyTag: 'new-tag',
    });
  });

  it('shows error toast when passwords do not match', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'OldPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'NewStrongPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'DifferentPass1!' },
    });

    fireEvent.click(screen.getByText('Change Password'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Passwords do not match', type: 'error' }),
      );
    });
  });

  it('shows error toast when new password is too weak', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'old' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'short' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'short' },
    });

    fireEvent.click(screen.getByText('Change Password'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: expect.stringContaining('too weak') as string }),
      );
    });
  });

  it('hides change password form when Cancel is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    expect(screen.getByPlaceholderText('Current master password')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByPlaceholderText('Current master password')).not.toBeInTheDocument();
  });

  it('shows error toast when changePasswordApi fails', async () => {
    mockChangePasswordApi.mockRejectedValue(new Error('Server error'));
    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'OldPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'NewStrongPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'NewStrongPass1!' },
    });
    fireEvent.click(screen.getByText('Change Password'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to change password', type: 'error' }),
      );
    });
  });

  // ---- Security Section: 2FA ----

  it('shows 2FA as Disabled when twoFactorEnabled is false', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Disabled')).toBeInTheDocument();
    });
  });

  it('shows Enable button when 2FA is disabled', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Enable')).toBeInTheDocument();
    });
  });

  it('shows 2FA as Enabled and Disable button when twoFactorEnabled is true', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Enabled')).toBeInTheDocument();
      expect(screen.getByText('Disable')).toBeInTheDocument();
    });
  });

  it('opens 2FA setup dialog when Enable is clicked', async () => {
    mockSetup2faApi.mockResolvedValue({
      data: {
        success: true,
        data: { secret: 'JBSWY3DPEHPK3PXP', qrCodeDataUrl: 'otpauth://totp/test' },
      },
    });
    await renderSettings();
    await waitFor(() => screen.getByText('Enable'));

    // Click Enable — now shows password prompt first (Task 1.3)
    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });

    // Enter master password and click Continue
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'test-password' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });

    await waitFor(() => {
      expect(screen.getByText(/Scan the QR code/)).toBeInTheDocument();
      expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument();
    });
  });

  it('shows error toast when 2FA setup fails', async () => {
    mockSetup2faApi.mockRejectedValue(new Error('Setup failed'));
    await renderSettings();
    await waitFor(() => screen.getByText('Enable'));

    // Click Enable — now shows password prompt first (Task 1.3)
    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });

    // Enter master password and click Continue
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'test-password' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Incorrect password or failed to start 2FA setup',
          type: 'error',
        }),
      );
    });
  });

  it('verifies 2FA code successfully', async () => {
    mockSetup2faApi.mockResolvedValue({
      data: {
        success: true,
        data: { secret: 'JBSWY3DPEHPK3PXP', qrCodeDataUrl: 'otpauth://totp/test' },
      },
    });
    mockVerify2faApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          backupCodes: [
            'code1111',
            'code2222',
            'code3333',
            'code4444',
            'code5555',
            'code6666',
            'code7777',
            'code8888',
          ],
        },
      },
    });
    // After verification, profile is reloaded with 2FA enabled
    const reloadProfile = { ...defaultProfile, twoFactorEnabled: true };
    mockGetProfileApi
      .mockResolvedValueOnce({ data: { success: true, data: defaultProfile } })
      .mockResolvedValueOnce({ data: { success: true, data: reloadProfile } });

    await renderSettings();
    await waitFor(() => screen.getByText('Enable'));

    // Click Enable — now shows password prompt first (Task 1.3)
    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });

    // Enter master password and click Continue
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'test-password' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });

    await waitFor(() => screen.getByPlaceholderText('6-digit code'));

    fireEvent.change(screen.getByPlaceholderText('6-digit code'), {
      target: { value: '123456' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Verify'));
    });

    await waitFor(() => {
      expect(mockVerify2faApi).toHaveBeenCalledWith({ code: '123456' });
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: '2FA enabled successfully', type: 'success' }),
      );
    });

    // Backup codes dialog should be displayed
    await waitFor(() => {
      expect(screen.getByText('Save Your Backup Codes')).toBeInTheDocument();
      expect(screen.getByText('code1111')).toBeInTheDocument();
      expect(screen.getByText('code8888')).toBeInTheDocument();
    });
  });

  it('shows disable 2FA form when Disable is clicked', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Disable'));

    fireEvent.click(screen.getByText('Disable'));

    expect(
      screen.getByText(/Enter your master password and a 2FA code to disable/),
    ).toBeInTheDocument();
  });

  it('calls disable2faApi with entered code and password', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    setupDefaultProfileMock({ twoFactorEnabled: true });
    mockDisable2faApi.mockResolvedValue({ data: { success: true } });
    mockGetProfileApi
      .mockResolvedValueOnce({
        data: { success: true, data: { ...defaultProfile, twoFactorEnabled: true } },
      })
      .mockResolvedValueOnce({ data: { success: true, data: defaultProfile } });

    await renderSettings();
    await waitFor(() => screen.getByText('Disable'));

    fireEvent.click(screen.getByText('Disable'));

    const passwordInput = screen.getByPlaceholderText('Master password');
    fireEvent.change(passwordInput, { target: { value: 'mypassword' } });

    const codeInputs = screen.getAllByPlaceholderText('6-digit code');
    fireEvent.change(codeInputs[0]!, { target: { value: '654321' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Disable 2FA'));
    });

    await waitFor(() => {
      expect(mockDisable2faApi).toHaveBeenCalledWith({
        code: '654321',
        password: 'mock-auth-hash',
      });
    });

    // The derived auth key must be zeroed after the hash is computed
    // (parity with every other key-deriving handler).
    expect(cryptoService.clearKey).toHaveBeenCalled();
  });

  it('hides disable 2FA form when Cancel is clicked', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Disable'));

    fireEvent.click(screen.getByText('Disable'));
    expect(
      screen.getByText(/Enter your master password and a 2FA code to disable/),
    ).toBeInTheDocument();

    // There may be multiple Cancel buttons, pick the one in the 2FA section
    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[cancelButtons.length - 1]!);

    expect(
      screen.queryByText(/Enter your master password and a 2FA code to disable/),
    ).not.toBeInTheDocument();
  });

  // ---- Security Section: Links ----

  it('renders Active Sessions link', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Active Sessions')).toBeInTheDocument();
    });
  });

  it('renders Audit Log link', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Audit Log')).toBeInTheDocument();
    });
  });

  // ---- Vault Section ----

  it('renders auto-lock timeout input', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Auto-lock timeout (minutes)')).toBeInTheDocument();
    });
  });

  it('renders clipboard clear timeout input', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Clipboard clear (seconds)')).toBeInTheDocument();
    });
  });

  it('renders Rotate Vault Key button', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Rotate Key')).toBeInTheDocument();
    });
  });

  it('opens vault key rotation confirmation dialog', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));

    await waitFor(() => {
      // "Rotate Vault Key" appears both in the page section heading and in the dialog title
      const matches = screen.getAllByText('Rotate Vault Key');
      expect(matches.length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText(/This will generate a new vault key/)).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Master password')).toBeInTheDocument();
    });
  });

  it('shows backup password field in rotation dialog when backup is configured', async () => {
    setupDefaultProfileMock({
      settings: {
        autoLockTimeout: 15,
        clipboardClearTimeout: 30,
        theme: 'system',
        backup: {
          enabled: true,
          scheduleHour: 3,
          backupEmails: [],
          isConfigured: true,
          encryptedBWK: 'bwk',
          bwkIv: 'iv',
          bwkTag: 'tag',
          bwkSalt: 'salt',
        },
      },
    });
    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Backup password')).toBeInTheDocument();
      expect(
        screen.getByText(/Enter your backup password to maintain cross-account restore/),
      ).toBeInTheDocument();
    });
  });

  it('does not show backup password field when backup is not configured', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Master password')).toBeInTheDocument();
    });
    expect(screen.queryByPlaceholderText('Backup password')).not.toBeInTheDocument();
  });

  it('vault key rotation includes authHash in backup setup call', async () => {
    const { listItemsApi, listTrashApi, listFoldersApi, bulkReEncryptApi } =
      await import('../src/services/api/vaultApi');

    (listItemsApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listTrashApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listFoldersApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [] },
    });
    (bulkReEncryptApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true },
    });

    // Profile with backup configured (returned when rotation checks backup state)
    const backupProfile = {
      success: true,
      data: {
        ...defaultProfile,
        settings: {
          ...defaultProfile.settings,
          backup: {
            enabled: true,
            scheduleHour: 3,
            backupEmails: [],
            isConfigured: true,
            encryptedBWK: 'bwk',
            bwkIv: 'iv',
            bwkTag: 'tag',
            bwkSalt: 'salt',
          },
        },
      },
    };

    // First call: page load, second call: during rotation step 5
    mockGetProfileApi
      .mockResolvedValueOnce({ data: { success: true, data: defaultProfile } })
      .mockResolvedValueOnce({ data: backupProfile });

    mockApiPost.mockResolvedValue({ data: { success: true } });

    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'TestPassword123!' },
    });
    fireEvent.click(screen.getByText('Confirm Rotation'));

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ authHash: 'mock-auth-hash' }),
      );
    });
  });

  it('vault key rotation re-encrypts vault key with BWK when backup password provided', async () => {
    const { listItemsApi, listTrashApi, listFoldersApi, bulkReEncryptApi } =
      await import('../src/services/api/vaultApi');
    const { cryptoService } = await import('../src/services/crypto/cryptoService');

    (listItemsApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listTrashApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listFoldersApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [] },
    });
    (bulkReEncryptApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true },
    });

    const backupProfile = {
      success: true,
      data: {
        ...defaultProfile,
        settings: {
          ...defaultProfile.settings,
          backup: {
            enabled: true,
            scheduleHour: 3,
            backupEmails: [],
            isConfigured: true,
            encryptedBWK: 'bwk',
            bwkIv: 'iv',
            bwkTag: 'tag',
            bwkSalt: 'salt',
          },
        },
      },
    };

    mockGetProfileApi
      .mockResolvedValueOnce({ data: backupProfile })
      .mockResolvedValueOnce({ data: backupProfile });

    mockApiPost.mockResolvedValue({ data: { success: true } });

    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Backup password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'TestPassword123!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass123!' },
    });
    fireEvent.click(screen.getByText('Confirm Rotation'));

    await waitFor(() => {
      expect(cryptoService.deriveBEK).toHaveBeenCalled();
      expect(cryptoService.decryptBWK).toHaveBeenCalled();
      expect(cryptoService.encryptVaultKeyWithBWK).toHaveBeenCalled();
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({
          authHash: 'mock-auth-hash',
          bwkEncryptedVaultKey: 'bwkEncVK',
          bwkVaultKeyIv: 'bwkVKIv',
          bwkVaultKeyTag: 'bwkVKTag',
        }),
      );
    });
  });

  it('vault key rotation without backup password clears bwkEncryptedVaultKey and warns', async () => {
    const { listItemsApi, listTrashApi, listFoldersApi, bulkReEncryptApi } =
      await import('../src/services/api/vaultApi');

    (listItemsApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listTrashApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [], pagination: { totalPages: 1 } },
    });
    (listFoldersApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true, data: [] },
    });
    (bulkReEncryptApi as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { success: true },
    });

    const backupProfile = {
      success: true,
      data: {
        ...defaultProfile,
        settings: {
          ...defaultProfile.settings,
          backup: {
            enabled: true,
            scheduleHour: 3,
            backupEmails: [],
            isConfigured: true,
            encryptedBWK: 'bwk',
            bwkIv: 'iv',
            bwkTag: 'tag',
            bwkSalt: 'salt',
          },
        },
      },
    };

    mockGetProfileApi
      .mockResolvedValueOnce({ data: backupProfile })
      .mockResolvedValueOnce({ data: backupProfile });

    mockApiPost.mockResolvedValue({ data: { success: true } });

    await renderSettings();
    await waitFor(() => screen.getByText('Rotate Key'));

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'TestPassword123!' },
    });
    // Do NOT fill backup password
    fireEvent.click(screen.getByText('Confirm Rotation'));

    await waitFor(() => {
      // Should send without bwkEncryptedVaultKey fields
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ authHash: 'mock-auth-hash' }),
      );
      // Verify bwkEncryptedVaultKey is NOT in the call
      const setupCall = mockApiPost.mock.calls.find((c: unknown[]) => c[0] === '/backup/setup');
      expect(setupCall?.[1]).not.toHaveProperty('bwkEncryptedVaultKey');
    });

    // Should show warning toast about needing to update backup password
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('update your backup password') as unknown,
          type: 'warning',
        }),
      );
    });
  });

  // ---- Appearance Section ----

  it('renders theme options (Light, Dark, System)', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Appearance')).toBeInTheDocument();
      expect(screen.getByText('Light')).toBeInTheDocument();
      expect(screen.getByText('Dark')).toBeInTheDocument();
      expect(screen.getByText('System')).toBeInTheDocument();
    });
  });

  it('calls setTheme when a theme button is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Dark'));

    fireEvent.click(screen.getByText('Dark'));

    expect(mockSetTheme).toHaveBeenCalledWith('dark');
  });

  // ---- Data Section ----

  it('renders Export Vault and Import Vault buttons', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Export Vault')).toBeInTheDocument();
      expect(screen.getByText('Import Vault')).toBeInTheDocument();
    });
  });

  it('shows export warning dialog when Export Vault is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Export Vault'));

    fireEvent.click(screen.getByText('Export Vault'));

    await waitFor(() => {
      expect(screen.getByText('Important: Export Limitations')).toBeInTheDocument();
      expect(screen.getByText('I Understand, Export')).toBeInTheDocument();
      expect(screen.getByText(/Rotate your vault key/)).toBeInTheDocument();
      expect(screen.getByText(/Create a new account/)).toBeInTheDocument();
    });
  });

  it('calls exportVaultApi after confirming export warning', async () => {
    mockExportVaultApi.mockResolvedValue({
      data: { success: true, data: { items: [], folders: [] } },
    });
    await renderSettings();
    await waitFor(() => screen.getByText('Export Vault'));

    // Mock URL.createObjectURL and the download anchor's click for download.
    // Without the click stub, jsdom treats the <a href="blob:..."> click as a
    // real navigation and prints "Not implemented: navigation to another
    // Document" to the console.
    const mockUrl = 'blob:mock';
    const origCreateObjectURL = URL.createObjectURL;
    const origRevokeObjectURL = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn().mockReturnValue(mockUrl);
    URL.revokeObjectURL = vi.fn();
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    fireEvent.click(screen.getByText('Export Vault'));
    await waitFor(() => screen.getByText('I Understand, Export'));

    // Fill in master password for re-authentication
    const exportPasswordInput = screen.getByPlaceholderText('Enter your master password');
    fireEvent.change(exportPasswordInput, { target: { value: 'test-password' } });

    await act(async () => {
      fireEvent.click(screen.getByText('I Understand, Export'));
    });

    await waitFor(() => {
      expect(mockExportVaultApi).toHaveBeenCalled();
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Vault exported', type: 'success' }),
      );
    });

    // The export flow actually triggered the file download.
    expect(anchorClick).toHaveBeenCalled();

    anchorClick.mockRestore();
    URL.createObjectURL = origCreateObjectURL;
    URL.revokeObjectURL = origRevokeObjectURL;
  });

  it('dismisses export warning when Cancel is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Export Vault'));

    fireEvent.click(screen.getByText('Export Vault'));
    await waitFor(() => screen.getByText('Important: Export Limitations'));

    // Find Cancel button in the export warning section
    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[0]!);

    await waitFor(() => {
      expect(screen.queryByText('Important: Export Limitations')).not.toBeInTheDocument();
    });
  });

  it('shows error toast when export fails', async () => {
    mockExportVaultApi.mockRejectedValue(new Error('Export failed'));
    await renderSettings();
    await waitFor(() => screen.getByText('Export Vault'));

    fireEvent.click(screen.getByText('Export Vault'));
    await waitFor(() => screen.getByText('I Understand, Export'));

    // Fill in master password for re-authentication
    const exportPasswordInput = screen.getByPlaceholderText('Enter your master password');
    fireEvent.change(exportPasswordInput, { target: { value: 'test-password' } });

    await act(async () => {
      fireEvent.click(screen.getByText('I Understand, Export'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Failed to export vault. Check your password.',
          type: 'error',
        }),
      );
    });
  });

  it('disables export button while export is in progress', async () => {
    // Make the export API hang indefinitely to test disabled state
    mockExportVaultApi.mockReturnValue(new Promise(() => {}));
    await renderSettings();
    await waitFor(() => screen.getByText('Export Vault'));

    fireEvent.click(screen.getByText('Export Vault'));
    await waitFor(() => screen.getByText('I Understand, Export'));

    const exportPasswordInput = screen.getByPlaceholderText('Enter your master password');
    fireEvent.change(exportPasswordInput, { target: { value: 'test-password' } });

    const exportBtn = screen.getByText('I Understand, Export').closest('button')!;
    expect(exportBtn).not.toBeDisabled();

    await act(async () => {
      fireEvent.click(exportBtn);
    });

    // The dialog is dismissed but the handler is now running;
    // clicking Export Vault again should show a disabled button
    fireEvent.click(screen.getByText('Export Vault'));
    await waitFor(() => {
      expect(screen.getByText('Exporting...')).toBeInTheDocument();
    });
  });

  it('opens import panel when Import Vault is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    expect(screen.getByDisplayValue('H-Vault (.enc / JSON)')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Paste exported data here...')).toBeInTheDocument();
  });

  it('shows format options in the import panel', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const select = screen.getByDisplayValue('H-Vault (.enc / JSON)');
    expect(select).toBeInTheDocument();
    // json, bitwarden, lastpass, keepass, chrome, firefox, onepassword, csv.
    expect(select.querySelectorAll('option')).toHaveLength(8);
  });

  it('re-sends the ORIGINAL ciphertext of a native item rather than re-encrypting it', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));
    // A native item carrying all six ciphertext fields (mocked decrypt never throws).
    const nativeItem = {
      itemType: 'login',
      encryptedData: 'ed',
      dataIv: 'di',
      dataTag: 'dt',
      encryptedName: 'en',
      nameIv: 'ni',
      nameTag: 'nt',
    };
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeItem] }) },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalledWith(
        expect.objectContaining({ format: 'json', conflictStrategy: 'skip' }),
      );
    });
    const payload = mockImportVaultApi.mock.calls[0]?.[0] as {
      operations: { inserts: Record<string, string>[]; updates: unknown[] };
    };
    expect(payload.operations.inserts).toHaveLength(1);
    expect(payload.operations.updates).toEqual([]);
    // The row is already encrypted under the current vault key, so its bytes are
    // forwarded verbatim (a re-encrypt would show the mocked `enc:` prefix).
    expect(payload.operations.inserts[0]).toMatchObject(nativeItem);
    // Only the search hash is recomputed — it is a deterministic HMAC of the name.
    expect(payload.operations.inserts[0]?.searchHash).toBe('hash');
  });

  it('shows CSV field mapping UI when CSV format is selected', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    // Switch to CSV
    fireEvent.change(screen.getByDisplayValue('H-Vault (.enc / JSON)'), {
      target: { value: 'csv' },
    });

    // Enter CSV data
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Name,Username,Password\nTest,user1,pass1' },
    });

    await waitFor(() => {
      expect(screen.getByText('Map CSV Columns')).toBeInTheDocument();
    });
  });

  it('shows an error when a generic CSV maps no identifying column', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    fireEvent.change(screen.getByDisplayValue('H-Vault (.enc / JSON)'), {
      target: { value: 'csv' },
    });

    // CSV data with columns that won't auto-map to name/url/username
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Foo,Bar\nval1,val2' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('Map at least one of Name, URL, or Username') as string,
        }),
      );
    });
  });

  it('hides import panel when Cancel is clicked', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));
    expect(screen.getByPlaceholderText('Paste exported data here...')).toBeInTheDocument();

    // Find the Cancel button in the import section
    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[cancelButtons.length - 1]!);

    expect(screen.queryByPlaceholderText('Paste exported data here...')).not.toBeInTheDocument();
  });

  // ---- File Upload Import ----

  it('shows Upload File button and helper text when import panel is open', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    expect(screen.getByText('Upload File')).toBeInTheDocument();
    expect(screen.getByText(/H-Vault \(\.enc\), JSON, or CSV \(max\s*8MB\)/)).toBeInTheDocument();
    expect(screen.getByText('Or paste data below:')).toBeInTheDocument();
  });

  it('renders a hidden file input that accepts .enc, .json and .csv', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeInTheDocument();
    expect(fileInput.accept).toBe('.enc,.json,.csv');
    expect(fileInput.className).toContain('hidden');
  });

  it('populates textarea when a JSON file is uploaded', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const jsonContent = '{"items":[{"name":"test"}]}';
    const file = new File([jsonContent], 'vault.json', { type: 'application/json' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    // Wait on the OBSERVABLE result (the FileReader-populated textarea) rather
    // than a fixed wall-clock sleep, which is both flaky under load and masks a
    // slowed-down read.
    await waitFor(() => {
      const textarea = screen.getByPlaceholderText(
        'Paste exported data here...',
      ) as HTMLTextAreaElement;
      expect(textarea.value).toBe(jsonContent);
    });
  });

  it('populates textarea when a CSV file is uploaded and switches format to csv', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const csvContent = 'Name,Username,Password\nTest,user1,pass1';
    const file = new File([csvContent], 'export.csv', { type: 'text/csv' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    await waitFor(() => {
      const textarea = screen.getByPlaceholderText(
        'Paste exported data here...',
      ) as HTMLTextAreaElement;
      expect(textarea.value).toBe(csvContent);
    });

    // Format should have switched to the generic CSV option (no signature match).
    const select = screen.getByDisplayValue('Generic CSV (map columns)') as HTMLSelectElement;
    expect(select).toBeInTheDocument();
  });

  it('shows error toast for unsupported file types', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(['data'], 'vault.txt', { type: 'text/plain' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Only H-Vault (.enc), JSON, and CSV files are supported',
        type: 'error',
      }),
    );
  });

  it('shows error toast for files exceeding the size cap', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    // Create a file that exceeds the 8MB cap. `File.size` reflects the byte length.
    const largeContent = 'x'.repeat(8_388_609);
    const file = new File([largeContent], 'big.json', { type: 'application/json' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'File too large (max 8MB)', type: 'error' }),
    );
  });

  it('auto-detects Bitwarden format from JSON file content', async () => {
    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const bitwardenContent = JSON.stringify({
      folders: [{ id: '1', name: 'test' }],
      items: [{ type: 1, login: { username: 'u', password: 'p' } }],
    });
    const file = new File([bitwardenContent], 'bitwarden.json', { type: 'application/json' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
    });

    // Format auto-detection runs after the FileReader resolves; wait on that
    // observable rather than a fixed sleep.
    await waitFor(() => {
      const select = screen.getByDisplayValue('Bitwarden (JSON or CSV)') as HTMLSelectElement;
      expect(select).toBeInTheDocument();
    });
  });

  // ---- Account Section ----

  it('renders Backup Settings link', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Backup Settings')).toBeInTheDocument();
    });
  });

  // ---- Save Settings ----

  it('renders Save Settings button', async () => {
    await renderSettings();
    await waitFor(() => {
      expect(screen.getByText('Save Settings')).toBeInTheDocument();
    });
  });

  it('calls updateSettingsApi with the full settings payload and invalidates the cache', async () => {
    mockUpdateSettingsApi.mockResolvedValue({ data: { success: true } });
    // The profile mock provides autoLockTimeout:15, clipboardClearTimeout:30 —
    // the form initializes from these.
    await renderSettings();
    await waitFor(() => screen.getByText('Save Settings'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockUpdateSettingsApi).toHaveBeenCalledTimes(1);
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Settings saved', type: 'success' }),
      );
    });

    // Assert the actual payload — dropping any of these fields (a regression the
    // old bare toHaveBeenCalled() would miss) fails here because objectContaining
    // requires each key to be present with the loaded value.
    expect(mockUpdateSettingsApi).toHaveBeenCalledWith(
      expect.objectContaining({
        autoLockTimeout: 15,
        clipboardClearTimeout: 30,
        theme: expect.any(String) as unknown as string,
      }),
    );
    // The settings cache MUST be invalidated so consumers (useAutoLock, CopyField)
    // pick up the new values without a reload.
    expect(vi.mocked(clearSettingsCache)).toHaveBeenCalled();
  });

  it('shows error toast when saving settings fails', async () => {
    mockUpdateSettingsApi.mockRejectedValue(new Error('Save failed'));
    await renderSettings();
    await waitFor(() => screen.getByText('Save Settings'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to save settings', type: 'error' }),
      );
    });
  });

  it('shows "Saving..." text while settings are being saved', async () => {
    mockUpdateSettingsApi.mockReturnValue(new Promise(() => {}));
    await renderSettings();
    await waitFor(() => screen.getByText('Save Settings'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    expect(screen.getByText('Saving...')).toBeInTheDocument();
  });

  it('shows error toast when user email not available for password change', async () => {
    useAuthStore.setState({
      user: null,
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Master Password'));

    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'OldPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: 'StrongNewPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'StrongNewPass1!' },
    });

    fireEvent.click(screen.getByText('Change Password'));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'User email not available', type: 'error' }),
      );
    });
  });

  // ---- Security Section: Regenerate Backup Codes ----

  it('shows Regenerate Codes button when 2FA is enabled', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();

    await waitFor(() => {
      expect(screen.getByText('Regenerate Codes')).toBeInTheDocument();
    });
  });

  it('does not show Regenerate Codes button when 2FA is disabled', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: false });
    await renderSettings();

    await waitFor(() => screen.getByText('Enable'));

    expect(screen.queryByText('Regenerate Codes')).not.toBeInTheDocument();
  });

  it('shows password prompt when Regenerate Codes is clicked', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();

    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));

    expect(screen.getByPlaceholderText('Master password')).toBeInTheDocument();
    expect(
      screen.getByText(/Enter your master password.*to regenerate backup codes/),
    ).toBeInTheDocument();
  });

  it('calls regenerateBackupCodesApi with derived authHash and 2FA code on successful regeneration', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    mockRegenerateBackupCodesApi.mockResolvedValue({
      data: {
        success: true,
        data: { backupCodes: ['newcode1', 'newcode2', 'newcode3', 'newcode4'] },
      },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));

    await waitFor(() => screen.getByPlaceholderText('Master password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'my-master-password' },
    });

    fireEvent.change(screen.getByPlaceholderText('6-digit 2FA code'), {
      target: { value: '123456' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Regenerate'));
    });

    await waitFor(() => {
      expect(mockRegenerateBackupCodesApi).toHaveBeenCalledWith({
        password: 'mock-auth-hash',
        code: '123456',
      });
    });
  });

  it('shows backup codes dialog after successful regeneration', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    mockRegenerateBackupCodesApi.mockResolvedValue({
      data: {
        success: true,
        data: { backupCodes: ['regen1111', 'regen2222', 'regen3333', 'regen4444'] },
      },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'my-master-password' },
    });
    fireEvent.change(screen.getByPlaceholderText('6-digit 2FA code'), {
      target: { value: '654321' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Regenerate'));
    });

    await waitFor(() => {
      expect(screen.getByText('Save Your Backup Codes')).toBeInTheDocument();
      expect(screen.getByText('regen1111')).toBeInTheDocument();
      expect(screen.getByText('regen4444')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Backup codes regenerated', type: 'success' }),
      );
    });
  });

  it('shows error toast when regeneration fails', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    mockRegenerateBackupCodesApi.mockRejectedValue(new Error('Wrong password'));

    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'wrong-password' },
    });
    fireEvent.change(screen.getByPlaceholderText('6-digit 2FA code'), {
      target: { value: '123456' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Regenerate'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Failed to regenerate backup codes. Check your password.',
          type: 'error',
        }),
      );
    });
  });

  it('disables Regenerate button when password is empty', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    const regenerateBtn = screen.getByText('Regenerate');
    expect(regenerateBtn).toBeDisabled();
  });

  it('disables Regenerate button when 2FA is enabled but code is missing', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    // Enter password but no 2FA code
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'my-password' },
    });

    const regenerateBtn = screen.getByText('Regenerate');
    expect(regenerateBtn).toBeDisabled();
  });

  it('hides regenerate form when Cancel is clicked', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    expect(screen.getByText(/Enter your master password.*to regenerate/)).toBeInTheDocument();

    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[cancelButtons.length - 1]!);

    expect(screen.queryByText(/Enter your master password.*to regenerate/)).not.toBeInTheDocument();
  });

  it('triggers regeneration on Enter key in password field', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    mockRegenerateBackupCodesApi.mockResolvedValue({
      data: {
        success: true,
        data: { backupCodes: ['enter1111', 'enter2222'] },
      },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    const passwordInput = screen.getByPlaceholderText('Master password');
    fireEvent.change(passwordInput, { target: { value: 'my-password' } });
    fireEvent.change(screen.getByPlaceholderText('6-digit 2FA code'), {
      target: { value: '123456' },
    });

    await act(async () => {
      fireEvent.keyDown(passwordInput, { key: 'Enter' });
    });

    await waitFor(() => {
      expect(mockRegenerateBackupCodesApi).toHaveBeenCalled();
    });
  });

  it('shows 2FA code input in regenerate dialog when 2FA is enabled', async () => {
    setupDefaultProfileMock({ twoFactorEnabled: true });
    await renderSettings();
    await waitFor(() => screen.getByText('Regenerate Codes'));

    fireEvent.click(screen.getByText('Regenerate Codes'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));

    expect(screen.getByPlaceholderText('6-digit 2FA code')).toBeInTheDocument();
    expect(screen.getByText(/and 2FA code/)).toBeInTheDocument();
  });

  // NOTE: a second copy of 'does not show Regenerate Codes button when 2FA is
  // disabled' lived here. It duplicated the identically-named test in the
  // "Security Section: Regenerate Backup Codes" block (which asserts the same
  // thing) and only differed by waiting on the 'Disabled' status label first.
  // Removed as a redundant duplicate.

  // ---- Import Validation: Undecryptable Items ----

  it('shows warning toast when some JSON items are undecryptable', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');

    // First call succeeds (data), second call succeeds (name),
    // Third call fails (data for second item)
    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('decrypted-data') // item 1 data
      .mockResolvedValueOnce('decrypted-name') // item 1 name
      .mockRejectedValueOnce(new Error('Decryption failed')); // item 2 data fails

    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const importData = JSON.stringify({
      items: [
        {
          itemType: 'login',
          encryptedData: 'enc1',
          dataIv: 'iv1',
          dataTag: 'tag1',
          encryptedName: 'encN1',
          nameIv: 'niv1',
          nameTag: 'ntag1',
        },
        {
          itemType: 'login',
          encryptedData: 'enc2',
          dataIv: 'iv2',
          dataTag: 'tag2',
          encryptedName: 'encN2',
          nameIv: 'niv2',
          nameTag: 'ntag2',
        },
      ],
    });

    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: importData },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalled();
      // Should show warning type because some items were filtered
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'warning' }));
    });
  });

  it('shows error and prevents import when all JSON items are undecryptable', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');

    // All decryption attempts fail
    vi.mocked(cryptoService.decryptData)
      .mockRejectedValueOnce(new Error('Decryption failed')) // item 1 data fails
      .mockRejectedValueOnce(new Error('Decryption failed')); // item 2 data fails

    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const importData = JSON.stringify({
      items: [
        {
          itemType: 'login',
          encryptedData: 'enc1',
          dataIv: 'iv1',
          dataTag: 'tag1',
          encryptedName: 'encN1',
          nameIv: 'niv1',
          nameTag: 'ntag1',
        },
        {
          itemType: 'login',
          encryptedData: 'enc2',
          dataIv: 'iv2',
          dataTag: 'tag2',
          encryptedName: 'encN2',
          nameIv: 'niv2',
          nameTag: 'ntag2',
        },
      ],
    });

    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: importData },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      // The title counts the rejected rows; the per-row reasons name the cause,
      // rather than blaming decryption for every kind of rejection.
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'All 2 items were rejected and nothing was imported.',
          description: expect.stringContaining('could not be decrypted') as string,
          type: 'error',
        }),
      );
      // Import API should NOT have been called
      expect(mockImportVaultApi).not.toHaveBeenCalled();
    });
  });

  it('filters items missing required encryption fields from JSON import', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');

    // The valid item will pass decryption
    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('decrypted-data')
      .mockResolvedValueOnce('decrypted-name');

    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    const importData = JSON.stringify({
      items: [
        // Valid item with all fields
        {
          itemType: 'login',
          encryptedData: 'enc1',
          dataIv: 'iv1',
          dataTag: 'tag1',
          encryptedName: 'encN1',
          nameIv: 'niv1',
          nameTag: 'ntag1',
        },
        // Missing dataIv
        {
          itemType: 'login',
          encryptedData: 'enc2',
          dataTag: 'tag2',
          encryptedName: 'encN2',
          nameIv: 'niv2',
          nameTag: 'ntag2',
        },
        // Missing encryptedName
        {
          itemType: 'login',
          encryptedData: 'enc3',
          dataIv: 'iv3',
          dataTag: 'tag3',
          nameIv: 'niv3',
          nameTag: 'ntag3',
        },
      ],
    });

    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: importData },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalled();
      // Should be warning due to filtered items
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'warning' }));
    });
  });

  it('imports all valid JSON items with success toast when all pass decryption', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    // Distinguishable plaintext per row: two rows that decrypt to the SAME
    // content are exact duplicates and collapse to one operation, which would
    // make a two-row assertion pass for the wrong reason.
    vi.mocked(cryptoService.decryptData).mockImplementation((encrypted: string) =>
      Promise.resolve(`plain:${encrypted}`),
    );

    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 2, updatedCount: 0 } },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));
    fireEvent.click(screen.getByText('Import Vault'));

    const importData = JSON.stringify({
      items: [
        {
          itemType: 'login',
          encryptedData: 'e1',
          dataIv: 'i1',
          dataTag: 't1',
          encryptedName: 'n1',
          nameIv: 'ni1',
          nameTag: 'nt1',
        },
        {
          itemType: 'login',
          encryptedData: 'e2',
          dataIv: 'i2',
          dataTag: 't2',
          encryptedName: 'n2',
          nameIv: 'ni2',
          nameTag: 'nt2',
        },
      ],
    });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: importData },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalled();
      expect(mockToast).toHaveBeenCalledWith({ title: 'Imported 2 items', type: 'success' });
    });
    const payload = mockImportVaultApi.mock.calls[0]?.[0] as {
      operations: { inserts: unknown[] };
    };
    expect(payload.operations.inserts).toHaveLength(2);
  });

  it('skips validation for non-JSON import formats', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });

    await renderSettings();
    await waitFor(() => screen.getByText('Import Vault'));

    fireEvent.click(screen.getByText('Import Vault'));

    // Switch to bitwarden format
    fireEvent.change(screen.getByDisplayValue('H-Vault (.enc / JSON)'), {
      target: { value: 'bitwarden' },
    });

    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: '{"items":[{"type":1,"login":{"username":"u","password":"p"}}]}' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalledWith(
        expect.objectContaining({ format: 'bitwarden' }),
      );
      expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'success' }));
    });
  });
});

// ==========================================================================
// 2 - BackupSettingsPage
// ==========================================================================

describe('BackupSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useAuthStore.setState({
      accessToken: 'test-token',
      user: { userId: 'u1', email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: new Uint8Array(32) as unknown as CryptoKey,
      mek: new Uint8Array(32) as unknown as CryptoKey,
      encryptedVaultKeyData: null,
      twoFactorRequired: false,
      tempToken: null,
    });

    // Default: backup configured
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: {
              enabled: true,
              scheduleHour: 3,
              backupEmails: ['backup@example.com'],
              isConfigured: true,
            },
          },
        },
      },
    });

    // History endpoint
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') {
        return Promise.resolve({
          data: {
            data: [
              {
                _id: 'h1',
                status: 'success',
                timestamp: '2026-02-20T03:00:00Z',
                itemCount: 42,
                fileSizeBytes: 10240,
                sentTo: ['backup@example.com'],
              },
              {
                _id: 'h2',
                status: 'failed',
                timestamp: '2026-02-19T03:00:00Z',
                errorMessage: 'SMTP timeout',
                sentTo: ['backup@example.com'],
              },
            ],
          },
        });
      }
      if (url === '/backup/download') {
        return Promise.resolve({ data: new Blob(['backup-data']) });
      }
      return Promise.resolve({ data: {} });
    });
  });

  async function renderBackup() {
    const { default: BackupSettingsPage } = await import('../src/pages/BackupSettingsPage');
    let result: ReturnType<typeof render>;
    await act(async () => {
      result = renderWithRouter(<BackupSettingsPage />);
    });
    return result!;
  }

  // ---- Loading State ----

  it('shows loading spinner while data is being fetched', async () => {
    mockGetProfileApi.mockReturnValue(new Promise(() => {}));
    const { default: BackupSettingsPage } = await import('../src/pages/BackupSettingsPage');

    const { container } = render(
      <MemoryRouter>
        <BackupSettingsPage />
      </MemoryRouter>,
    );

    const spinner = container.querySelector('.animate-spin');
    expect(spinner).toBeTruthy();
  });

  it('shows error toast when profile load fails', async () => {
    mockGetProfileApi.mockRejectedValue(new Error('Network error'));
    await renderBackup();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to load backup settings', type: 'error' }),
      );
    });
  });

  // ---- Heading ----

  it('renders the Backup Settings heading', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Backup Settings')).toBeInTheDocument();
    });
  });

  it('renders Back to settings button', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByLabelText('Back to settings')).toBeInTheDocument();
    });
  });

  // ---- Backup Configuration ----

  it('renders Backup Configuration section', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Backup Configuration')).toBeInTheDocument();
    });
  });

  it('renders auto-backup toggle', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Auto-backup')).toBeInTheDocument();
      expect(screen.getByRole('switch')).toBeInTheDocument();
    });
  });

  it('toggles auto-backup on click', async () => {
    await renderBackup();
    await waitFor(() => screen.getByRole('switch'));

    const toggle = screen.getByRole('switch');
    expect(toggle).toHaveAttribute('aria-checked', 'true');

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-checked', 'false');
  });

  it('renders schedule hour input', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Schedule (UTC hour)')).toBeInTheDocument();
    });
  });

  it('renders backup email input', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Backup Emails')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Add backup email')).toBeInTheDocument();
    });
  });

  // ---- Action Buttons ----

  it('renders Save Settings, Backup Now, and Download Latest buttons', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Save Settings')).toBeInTheDocument();
      expect(screen.getByText('Backup Now')).toBeInTheDocument();
      expect(screen.getByText('Download Latest')).toBeInTheDocument();
    });
  });

  it('calls save settings API when Save Settings is clicked', async () => {
    mockApiPut.mockResolvedValue({ data: { success: true } });
    await renderBackup();
    await waitFor(() => screen.getByText('Save Settings'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockApiPut).toHaveBeenCalledWith('/backup/settings', expect.any(Object));
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Backup settings saved', type: 'success' }),
      );
    });
  });

  it('shows error toast when save settings fails', async () => {
    mockApiPut.mockRejectedValue(new Error('Save failed'));
    await renderBackup();
    await waitFor(() => screen.getByText('Save Settings'));

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to save backup settings', type: 'error' }),
      );
    });
  });

  it('triggers backup when Backup Now is clicked', async () => {
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        message: 'Backup created and sent successfully',
        data: { emailSent: true },
      },
    });
    await renderBackup();
    await waitFor(() => screen.getByText('Backup Now'));

    await act(async () => {
      fireEvent.click(screen.getByText('Backup Now'));
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/trigger');
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Backup triggered successfully', type: 'success' }),
      );
    });
  });

  it('shows warning toast when backup email was not sent', async () => {
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        message: 'Backup created successfully (email not configured)',
        data: { emailSent: false },
      },
    });
    await renderBackup();
    await waitFor(() => screen.getByText('Backup Now'));

    await act(async () => {
      fireEvent.click(screen.getByText('Backup Now'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Backup created successfully (email not configured)',
          type: 'warning',
        }),
      );
    });
  });

  it('shows error toast when trigger backup fails', async () => {
    mockApiPost.mockRejectedValue(new Error('Trigger failed'));
    await renderBackup();
    await waitFor(() => screen.getByText('Backup Now'));

    await act(async () => {
      fireEvent.click(screen.getByText('Backup Now'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to trigger backup', type: 'error' }),
      );
    });
  });

  it('downloads a signed backup (HMAC integrity) when Download Latest is submitted', async () => {
    const origCreateObjectURL = URL.createObjectURL;
    const origRevokeObjectURL = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn().mockReturnValue('blob:mock');
    URL.revokeObjectURL = vi.fn();
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    // FULL backup-encryption metadata so handleDownload proceeds PAST the
    // "Backup encryption is not configured" guard and runs the real download +
    // BWK decrypt + HMAC-sign + blob path. Without bwkSalt/encryptedBWK/bwkIv/
    // bwkTag the flow short-circuits at the guard and this test would assert
    // nothing about the download (the original bug).
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: {
              enabled: true,
              scheduleHour: 3,
              backupEmails: ['backup@example.com'],
              isConfigured: true,
              bwkSalt: 'salt',
              encryptedBWK: 'ebwk',
              bwkIv: 'biv',
              bwkTag: 'btag',
            },
          },
        },
      },
    });
    // The server returns the backup document as text; handleDownload parses,
    // canonicalizes, HMAC-signs, and re-serializes it.
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') return Promise.resolve({ data: { data: [] } });
      if (url === '/backup/download')
        return Promise.resolve({ data: JSON.stringify({ items: [], folders: [] }) });
      return Promise.resolve({ data: {} });
    });

    await renderBackup();
    await waitFor(() => screen.getByText('Download Latest'));

    await act(async () => {
      fireEvent.click(screen.getByText('Download Latest'));
    });
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Backup password')).toBeInTheDocument();
    });
    await act(async () => {
      fireEvent.change(screen.getByPlaceholderText('Backup password'), {
        target: { value: 'test-backup-password' },
      });
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    // The success toast is only emitted at the very END of the real path.
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Backup downloaded with integrity signature',
          type: 'success',
        }),
      );
    });

    // The whole download contract actually ran: server fetch, BWK decrypt, HMAC
    // signing, and a Blob → anchor download. Any of these being broken now fails.
    expect(mockApiGet).toHaveBeenCalledWith(
      '/backup/download',
      expect.objectContaining({ responseType: 'text' }),
    );
    expect(cryptoService.decryptBWK).toHaveBeenCalled();
    expect(cryptoService.computeBackupHmac).toHaveBeenCalled();
    expect(URL.createObjectURL).toHaveBeenCalled();
    expect(anchorClick).toHaveBeenCalled();

    // The downloaded blob carries the integrity signature field.
    const blobArg = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0]![0] as Blob;
    const blobText = await blobArg.text();
    expect(JSON.parse(blobText)).toHaveProperty('integrity', 'mock-integrity-hmac');

    anchorClick.mockRestore();
    URL.createObjectURL = origCreateObjectURL;
    URL.revokeObjectURL = origRevokeObjectURL;
  });

  it('shows the download-failed error toast when the server download request rejects', async () => {
    // Full BWK metadata so the flow reaches api.get('/backup/download') — the
    // point of failure under test — instead of short-circuiting at the config
    // guard (whose 'Backup encryption is not configured' error toast the old
    // loose `type: 'error'` matcher accepted, masking a broken download path).
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: {
              enabled: true,
              scheduleHour: 3,
              backupEmails: ['backup@example.com'],
              isConfigured: true,
              bwkSalt: 'salt',
              encryptedBWK: 'ebwk',
              bwkIv: 'biv',
              bwkTag: 'btag',
            },
          },
        },
      },
    });
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/download') {
        return Promise.reject(new Error('Download failed'));
      }
      if (url === '/backup/history') {
        return Promise.resolve({ data: { data: [] } });
      }
      return Promise.resolve({ data: {} });
    });

    await renderBackup();
    await waitFor(() => screen.getByText('Download Latest'));

    // Click Download Latest — shows password prompt
    await act(async () => {
      fireEvent.click(screen.getByText('Download Latest'));
    });

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Backup password')).toBeInTheDocument();
    });

    // Enter password and submit
    await act(async () => {
      fireEvent.change(screen.getByPlaceholderText('Backup password'), {
        target: { value: 'test-backup-password' },
      });
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    // The EXACT catch-block toast — not just "some error toast" — so the config
    // guard's error cannot satisfy it and deleting the catch would fail here.
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to download backup', type: 'error' }),
      );
    });
    // The download really was attempted (proves we passed the config guard).
    expect(mockApiGet).toHaveBeenCalledWith(
      '/backup/download',
      expect.objectContaining({ responseType: 'text' }),
    );
  });

  // ---- Restore from Backup ----

  it('renders Restore from Backup section', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Restore from Backup')).toBeInTheDocument();
    });
  });

  it('shows Restore from File button initially', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Restore from File')).toBeInTheDocument();
    });
  });

  it('opens restore form when Restore from File is clicked', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    expect(screen.getByText('Backup File')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Backup encryption password')).toBeInTheDocument();
    expect(screen.getByText('Restore')).toBeInTheDocument();
  });

  it('hides restore form when Cancel is clicked', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));
    expect(screen.getByText('Backup File')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByText('Backup File')).not.toBeInTheDocument();
  });

  it('shows Restore button as disabled when no file or password provided', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    const restoreBtn = screen.getByText('Restore');
    expect(restoreBtn).toBeDisabled();
  });

  it('shows conflict strategy selector in restore form', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    expect(screen.getByText('Conflict Strategy')).toBeInTheDocument();
    expect(screen.getByText('Skip')).toBeInTheDocument();
    expect(screen.getByText('Overwrite')).toBeInTheDocument();
    expect(screen.getByText('Keep Both')).toBeInTheDocument();
  });

  it('defaults to skip conflict strategy', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    const skipRadio = screen.getByDisplayValue('skip') as HTMLInputElement;
    expect(skipRadio.checked).toBe(true);
  });

  it('allows changing conflict strategy', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    const overwriteRadio = screen.getByDisplayValue('overwrite') as HTMLInputElement;
    fireEvent.click(overwriteRadio);
    expect(overwriteRadio.checked).toBe(true);

    const skipRadio = screen.getByDisplayValue('skip') as HTMLInputElement;
    expect(skipRadio.checked).toBe(false);
  });

  it('shows description text for each conflict strategy option', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    expect(screen.getByText('Keep existing items, skip duplicates')).toBeInTheDocument();
    expect(screen.getByText('Replace existing items with backup data')).toBeInTheDocument();
    expect(screen.getByText('Keep existing and create copies from backup')).toBeInTheDocument();
  });

  // ---- Restore: re-encrypt (never adopt) the backup's rows ----

  // A H-Vault-produced backup always carries the vault-key fields. When the
  // backup's vault key differs from the current in-memory key the client
  // RE-ENCRYPTS the rows to the current key (never replaces the account key and
  // never requires a master password); when they match the rows are sent as-is.
  const backupFileWithVaultKey = {
    items: [],
    folders: [],
    encryptedVaultKey: 'evk',
    vaultKeyIv: 'vkiv',
    vaultKeyTag: 'vktag',
    backupEncryption: {
      encryptedBWK: 'ebwk',
      bwkIv: 'biv',
      bwkTag: 'btag',
      bwkSalt: 'bsalt',
      bwkEncryptedVaultKey: 'bevk',
      bwkVaultKeyIv: 'bvkiv',
      bwkVaultKeyTag: 'bvktag',
    },
  };

  // A backup carrying one item + one folder, used to prove re-encryption and
  // verbatim _id forwarding.
  const backupFileWithRows = {
    items: [
      {
        _id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
        encryptedData: 'd',
        dataIv: 'di',
        dataTag: 'dt',
        encryptedName: 'n',
        nameIv: 'ni',
        nameTag: 'nt',
      },
    ],
    folders: [
      {
        _id: 'bbbbbbbbbbbbbbbbbbbbbbbb',
        encryptedName: 'fn',
        nameIv: 'fi',
        nameTag: 'ft',
      },
    ],
    encryptedVaultKey: 'evk',
    vaultKeyIv: 'vkiv',
    vaultKeyTag: 'vktag',
    backupEncryption: backupFileWithVaultKey.backupEncryption,
  };

  async function performRestore(fileData: Record<string, unknown> = backupFileWithVaultKey) {
    const { container } = await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));
    fireEvent.click(screen.getByText('Restore from File'));

    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
    const backupFile = new File([JSON.stringify(fileData)], 'backup.json', {
      type: 'application/json',
    });
    fireEvent.change(fileInput, { target: { files: [backupFile] } });
    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Restore'));
    });
  }

  function restoreBody() {
    const call = mockApiPost.mock.calls.find((c) => c[0] === '/backup/restore');
    return (call?.[1] ?? {}) as Record<string, unknown>;
  }

  it('same-account un-rotated restore sends no adoptVaultKey/authHash and does not re-encrypt', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32));
    // Backup vault key matches the current key -> rows already under it.
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(true);
    vi.mocked(cryptoService.encryptData).mockClear();
    mockApiPost.mockResolvedValue({
      data: {
        data: { itemsRestored: 1, itemsSkipped: 0, foldersRestored: 1, foldersSkipped: 0 },
      },
    });

    await performRestore(backupFileWithRows);

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    const body = restoreBody();
    expect(body).not.toHaveProperty('adoptVaultKey');
    expect(body).not.toHaveProperty('authHash');
    // Rows are already under the current key -> not re-encrypted, not re-authed.
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    expect(cryptoService.getAuthHash).not.toHaveBeenCalled();
    const parsed = JSON.parse(body.data as string) as { items: Record<string, unknown>[] };
    expect(parsed.items[0]!.encryptedData).toBe('d');
  });

  it('cross-account/rotated restore re-encrypts rows to the current key and sends no adoptVaultKey/authHash', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32));
    // Backup vault key DIFFERS -> re-encrypt to the current key, never adopt.
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);
    vi.mocked(cryptoService.encryptData).mockClear();
    mockApiPost.mockResolvedValue({
      data: {
        data: { itemsRestored: 1, itemsSkipped: 0, foldersRestored: 1, foldersSkipped: 0 },
      },
    });

    await performRestore(backupFileWithRows);

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    const body = restoreBody();
    // The account's vault key is never replaced; no master-password re-auth.
    expect(body).not.toHaveProperty('adoptVaultKey');
    expect(body).not.toHaveProperty('authHash');
    expect(cryptoService.getAuthHash).not.toHaveBeenCalled();
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Master password required' }),
    );
    // Rows were re-encrypted with the current key (mock returns 'enc').
    expect(cryptoService.encryptData).toHaveBeenCalled();
    const parsed = JSON.parse(body.data as string) as {
      items: Record<string, unknown>[];
      folders: Record<string, unknown>[];
    };
    expect(parsed.items[0]!.encryptedData).toBe('enc');
    expect(parsed.folders[0]!.encryptedName).toBe('enc');
  });

  it('drops only a single undecryptable passwordHistory entry, not the whole item', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32));
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);
    // One history entry fails to decrypt; data/name and the other entry succeed.
    vi.mocked(cryptoService.decryptData).mockImplementation((enc: string) =>
      enc === 'bad-pw' ? Promise.reject(new Error('corrupt')) : Promise.resolve('decrypted'),
    );
    mockApiPost.mockResolvedValue({
      data: {
        data: { itemsRestored: 1, itemsSkipped: 0, foldersRestored: 0, foldersSkipped: 0 },
      },
    });

    const fixture = {
      items: [
        {
          _id: 'cccccccccccccccccccccccc',
          encryptedData: 'd',
          dataIv: 'di',
          dataTag: 'dt',
          encryptedName: 'n',
          nameIv: 'ni',
          nameTag: 'nt',
          passwordHistory: [
            {
              encryptedPassword: 'bad-pw',
              iv: 'i1',
              tag: 't1',
              changedAt: '2026-01-01T00:00:00.000Z',
            },
            {
              encryptedPassword: 'good-pw',
              iv: 'i2',
              tag: 't2',
              changedAt: '2026-01-02T00:00:00.000Z',
            },
          ],
        },
      ],
      folders: [],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: backupFileWithVaultKey.backupEncryption,
    };

    await performRestore(fixture);

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    const parsed = JSON.parse(restoreBody().data as string) as {
      items: { passwordHistory?: unknown[] }[];
    };
    // The item survived (not dropped) and only the good history entry remains.
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0]!.passwordHistory).toHaveLength(1);

    // Restore the shared decryptData mock default for later tests.
    vi.mocked(cryptoService.decryptData).mockResolvedValue('decrypted');
  });

  it('forwards item and folder _id values verbatim (client never strips ids)', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32));
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(true);
    mockApiPost.mockResolvedValue({
      data: {
        data: { itemsRestored: 1, itemsSkipped: 0, foldersRestored: 1, foldersSkipped: 0 },
      },
    });

    await performRestore(backupFileWithRows);

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    const parsed = JSON.parse(restoreBody().data as string) as {
      items: Record<string, unknown>[];
      folders: Record<string, unknown>[];
    };
    expect(parsed.items[0]!._id).toBe('aaaaaaaaaaaaaaaaaaaaaaaa');
    expect(parsed.folders[0]!._id).toBe('bbbbbbbbbbbbbbbbbbbbbbbb');
  });

  it('surfaces the server error message when a restore is rejected', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32));
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);
    mockApiPost.mockRejectedValue(new Error('Restore failed on server'));

    await performRestore(backupFileWithRows);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Failed to restore backup',
          description: 'Restore failed on server',
          type: 'error',
        }),
      );
    });
  });

  // ---- Setup Encryption (when not configured) ----

  it('shows Setup Backup Encryption card when not configured', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: {
              enabled: false,
              scheduleHour: 3,
              backupEmails: [],
              isConfigured: false,
            },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Setup Backup Encryption')).toBeInTheDocument();
    });
  });

  it('does not show Setup Backup Encryption card when already configured', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Backup Configuration'));

    expect(screen.queryByText('Setup Backup Encryption')).not.toBeInTheDocument();
  });

  it('shows password strength indicator when backup password is entered', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Backup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'SuperStrongPass!' },
    });

    await waitFor(() => {
      expect(screen.getByText('Very strong')).toBeInTheDocument();
    });
  });

  it('shows error toast when backup passwords do not match', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Backup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'SuperStrongPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'DifferentPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'TestMasterPw!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Passwords do not match', type: 'error' }),
      );
    });
  });

  it('calls setup API when encryption is configured correctly', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });
    mockApiPost.mockResolvedValue({ data: { success: true } });

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Backup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'SuperStrongPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'SuperStrongPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'TestMasterPw!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ authHash: 'mock-auth-hash' }),
      );
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Backup encryption configured', type: 'success' }),
      );
    });
  });

  it('shows error toast when setup encryption fails', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });
    mockApiPost.mockRejectedValue(new Error('Setup failed'));

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Backup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'SuperStrongPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'SuperStrongPass!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'TestMasterPw!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to setup backup encryption', type: 'error' }),
      );
    });
  });

  it('shows Setup Encryption button as disabled when password is too weak', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Backup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'weak' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'weak' },
    });

    const setupBtn = screen.getByText('Setup Encryption');
    expect(setupBtn).toBeDisabled();
  });

  // ---- Change Backup Password (when configured) ----

  it('shows Change Backup Password section when configured', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Change Backup Password')).toBeInTheDocument();
    });
  });

  it('shows "Change backup encryption password" link', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Change backup encryption password')).toBeInTheDocument();
    });
  });

  it('opens change password form when link is clicked', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));

    expect(screen.getByPlaceholderText('New backup password')).toBeInTheDocument();
    expect(screen.getByText('Change Password')).toBeInTheDocument();
  });

  it('hides change password form when Cancel is clicked', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    expect(screen.getByPlaceholderText('New backup password')).toBeInTheDocument();

    // Find the Cancel buttons, pick the one from change password section
    const cancelButtons = screen.getAllByText('Cancel');
    fireEvent.click(cancelButtons[cancelButtons.length - 1]!);

    expect(screen.queryByPlaceholderText('New backup password')).not.toBeInTheDocument();
  });

  it('shows password strength for new backup password', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));

    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'AnotherStrongPw!' },
    });

    await waitFor(() => {
      expect(screen.getByText('Very strong')).toBeInTheDocument();
    });
  });

  it('calls change password API with new backup password', async () => {
    mockApiPut.mockResolvedValue({ data: { success: true } });
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MyMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'NewStrongBackup!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });

    await waitFor(() => {
      expect(mockApiPut).toHaveBeenCalledWith('/backup/change-password', expect.any(Object));
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Backup password changed', type: 'success' }),
      );
    });
  });

  it('derives authHash from master password before sending change backup password request', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    mockApiPut.mockResolvedValue({ data: { success: true } });
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MyMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'NewStrongBackup!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });

    await waitFor(() => {
      // Verify deriveKeys was called with the master password and user email
      expect(cryptoService.deriveKeys).toHaveBeenCalledWith(
        'MyMasterPassword1!',
        'test@example.com',
      );
      // Verify getAuthHash was called with the derived authKey
      expect(cryptoService.getAuthHash).toHaveBeenCalled();
      // Verify the API receives the derived authHash, not the raw password
      expect(mockApiPut).toHaveBeenCalledWith(
        '/backup/change-password',
        expect.objectContaining({ password: 'mock-auth-hash' }),
      );
      // Verify authKey was cleaned up
      expect(cryptoService.clearKey).toHaveBeenCalled();
    });
  });

  it('shows error toast when change backup password fails', async () => {
    mockApiPut.mockRejectedValue(new Error('Change failed'));
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MyMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'NewStrongBackup!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to change backup password', type: 'error' }),
      );
    });
  });

  it('shows error when new backup password is too weak', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'weak' },
    });

    // Button should be disabled
    const changeBtn = screen.getByText('Change Password');
    expect(changeBtn).toBeDisabled();
  });

  // ---- Backup History ----

  it('renders Backup History section', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('Backup History')).toBeInTheDocument();
      expect(screen.getByText('Last 30 backup entries')).toBeInTheDocument();
    });
  });

  it('displays backup history entries with success and failed statuses', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('success')).toBeInTheDocument();
      expect(screen.getByText('failed')).toBeInTheDocument();
    });
  });

  it('displays error message for failed backup entries', async () => {
    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('SMTP timeout')).toBeInTheDocument();
    });
  });

  it('displays sent-to email in history entries', async () => {
    await renderBackup();
    await waitFor(() => {
      const emails = screen.getAllByText('backup@example.com');
      // At least in the history entries
      expect(emails.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('shows "No backup history" when history is empty', async () => {
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') {
        return Promise.resolve({ data: { data: [] } });
      }
      return Promise.resolve({ data: {} });
    });

    await renderBackup();
    await waitFor(() => {
      expect(screen.getByText('No backup history')).toBeInTheDocument();
    });
  });

  it('handles history endpoint failure gracefully', async () => {
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') {
        return Promise.reject(new Error('History not available'));
      }
      return Promise.resolve({ data: {} });
    });

    await renderBackup();

    // Page should still render without crashing
    await waitFor(() => {
      expect(screen.getByText('Backup Settings')).toBeInTheDocument();
      // History should show no entries
      expect(screen.getByText('No backup history')).toBeInTheDocument();
    });
  });

  it('shows restore button even when backup is not configured (for restoring from backup file with embedded metadata)', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Backup Settings'));

    // Restore should be available even without backup configuration
    expect(screen.getByText('Restore from File')).toBeInTheDocument();
  });

  it('disables download button when not configured', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Download Latest'));

    const downloadBtn = screen.getByText('Download Latest').closest('button');
    expect(downloadBtn).toBeDisabled();
  });

  it('does not show Change Backup Password section when not configured', async () => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });

    await renderBackup();
    await waitFor(() => screen.getByText('Backup Settings'));

    expect(screen.queryByText('Change Backup Password')).not.toBeInTheDocument();
  });

  it('encrypts vault key with BWK during backup setup', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          ...defaultProfile,
          settings: {
            ...defaultProfile.settings,
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockApiGet.mockResolvedValue({ data: { data: [] } });
    mockApiPost.mockResolvedValue({ data: { success: true } });

    await renderBackup();
    await waitFor(() => screen.getByText('Setup Encryption'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'StrongBackupPw1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'StrongBackupPw1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'TestMasterPw!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(cryptoService.encryptVaultKeyWithBWK).toHaveBeenCalled();
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ authHash: 'mock-auth-hash', bwkEncryptedVaultKey: 'bwkEncVK' }),
      );
    });
  });

  it('includes BWK vault key data in backup password change', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    mockApiPut.mockResolvedValue({ data: { success: true } });

    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MyMasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'NewStrongBackup!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });

    await waitFor(() => {
      expect(cryptoService.encryptVaultKeyWithBWK).toHaveBeenCalled();
      expect(mockApiPut).toHaveBeenCalledWith(
        '/backup/change-password',
        expect.objectContaining({ newBwkEncryptedVaultKey: 'bwkEncVK' }),
      );
    });
  });

  // ---- Restore no longer needs a master password (re-encrypt, not adopt) ----

  it('does not render a master password field in the restore form', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));

    fireEvent.click(screen.getByText('Restore from File'));

    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));
    // The vault key is never replaced, so no master-password re-auth is needed.
    expect(screen.queryByPlaceholderText('Your current master password')).toBeNull();
    expect(screen.queryByLabelText(/Master Password/)).toBeNull();
  });
});
