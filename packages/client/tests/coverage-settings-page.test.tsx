/**
 * SettingsPage — branch / error-path coverage.
 *
 * Complements tests/settings-pages.test.tsx (happy paths) by driving the
 * behaviors that only surface on the failure and edge branches:
 *  - master password change: locked vault guard, and the exact crypto wiring
 *    (authHash from the CURRENT password, vault key re-wrapped with the NEW MEK)
 *  - 2FA: wrong verify code, wrong disable code, Enter-to-submit, cancel,
 *    secret + backup-code clipboard copy
 *  - vault key rotation: the real re-encryption loop (paginated items + trash +
 *    password history + folders), the per-item / per-folder abort paths, the
 *    locked-vault guard and the server-failure path
 *  - import/export: CSV mapping payload, duplicate reporting, failure toasts
 *  - the settings form: edited values reach the API and the settings cache is
 *    invalidated
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

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
  mockApiPost,
  mockClearSettingsCache,
  mockWriteText,
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
  mockApiPost: vi.fn(),
  mockClearSettingsCache: vi.fn(),
  mockWriteText: vi.fn(),
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
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
    rotateVaultKey: vi.fn(),
    deriveBEK: vi.fn(),
    decryptBWK: vi.fn(),
    encryptVaultKeyWithBWK: vi.fn(),
    base64ToArrayBuffer: vi.fn(),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue({ data: { success: true } }),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  listTrashApi: vi.fn(),
  listFoldersApi: vi.fn(),
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
    get: vi.fn(),
    post: (...args: unknown[]) => mockApiPost(...args),
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
  clearSettingsCache: (...args: unknown[]) => mockClearSettingsCache(...args),
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

vi.mock('qrcode', () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,mockqr'),
  },
}));

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 8) return { score: 2, feedback: { warning: 'Fair', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  listItemsApi,
  listTrashApi,
  listFoldersApi,
  bulkReEncryptApi,
} from '../src/services/api/vaultApi';

// ---------------------------------------------------------------------------
// Typed handles on the mocks
// ---------------------------------------------------------------------------

const cs = cryptoService as unknown as Record<string, Mock>;
const mockListItems = listItemsApi as unknown as Mock;
const mockListTrash = listTrashApi as unknown as Mock;
const mockListFolders = listFoldersApi as unknown as Mock;
const mockBulkReEncrypt = bulkReEncryptApi as unknown as Mock;

/** Sentinel objects standing in for opaque CryptoKeys. */
const OLD_VAULT_KEY = { key: 'old-vault-key' } as unknown as CryptoKey;
const NEW_VAULT_KEY = { key: 'new-vault-key' } as unknown as CryptoKey;
const MEK = { key: 'mek' } as unknown as CryptoKey;

/**
 * Deterministic, *distinguishable* crypto stubs: every derived value carries the
 * input it came from, so a test can prove WHICH password / WHICH key was used.
 */
function installCryptoStubs() {
  cs.deriveKeys.mockImplementation((password: string) =>
    Promise.resolve({
      masterEncryptionKey: { mek: password },
      authKey: { ak: password },
    }),
  );
  cs.getAuthHash.mockImplementation((k: { ak: string }) => `hash:${k.ak}`);
  cs.encryptVaultKey.mockImplementation((_vk: unknown, mek: { mek: string }) =>
    Promise.resolve({ encrypted: `vk-wrapped-with:${mek.mek}`, iv: 'vkIv', tag: 'vkTag' }),
  );
  cs.decryptData.mockImplementation((enc: string) => Promise.resolve(`plain:${enc}`));
  cs.encryptData.mockImplementation((plain: string, key: { key: string }) =>
    Promise.resolve({ encrypted: `enc:${plain}`, iv: `iv:${key.key}`, tag: `tag:${key.key}` }),
  );
  cs.generateSearchHash.mockImplementation((name: string) => Promise.resolve(`sh:${name}`));
  cs.rotateVaultKey.mockResolvedValue({
    newVaultKey: NEW_VAULT_KEY,
    encrypted: 'newEnc',
    iv: 'newIv',
    tag: 'newTag',
  });
  cs.clearKey.mockReturnValue(undefined);
  cs.clearCryptoKey.mockResolvedValue(undefined);
  cs.deriveBEK.mockResolvedValue({ key: 'bek' });
  cs.decryptBWK.mockResolvedValue(new Uint8Array(32));
  cs.encryptVaultKeyWithBWK.mockResolvedValue({
    encrypted: 'bwkEncVK',
    iv: 'bwkVKIv',
    tag: 'bwkVKTag',
  });
  cs.base64ToArrayBuffer.mockReturnValue(new Uint8Array(16));
  cs.importVaultKey.mockResolvedValue(NEW_VAULT_KEY);
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

function setProfile(overrides: Record<string, unknown> = {}) {
  mockGetProfileApi.mockResolvedValue({
    data: { success: true, data: { ...defaultProfile, ...overrides } },
  });
}

async function renderSettings() {
  const { default: SettingsPage } = await import('../src/pages/SettingsPage');
  await act(async () => {
    render(
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>,
    );
  });
  await waitFor(() => {
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });
}

/** Rotation with an empty vault, unless a test overrides these. */
function installEmptyVaultRotationApis() {
  mockListItems.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
  mockListTrash.mockResolvedValue({
    data: { success: true, data: [], pagination: { totalPages: 1 } },
  });
  mockListFolders.mockResolvedValue({ data: { success: true, data: [] } });
  mockBulkReEncrypt.mockResolvedValue({ data: { success: true } });
}

describe('SettingsPage — error paths and branches', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    installCryptoStubs();
    installEmptyVaultRotationApis();
    setProfile();

    useAuthStore.setState({
      accessToken: 'test-token',
      user: { userId: 'u1', email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: OLD_VAULT_KEY,
      mek: MEK,
      encryptedVaultKeyData: null,
    } as never);
    useUIStore.setState({ theme: 'dark', setTheme: mockSetTheme });

    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: mockWriteText.mockResolvedValue(undefined) },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Master password change
  // -------------------------------------------------------------------------

  async function openChangePassword(current: string, next: string, confirm = next) {
    fireEvent.click(screen.getByText('Change'));
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: current },
    });
    fireEvent.change(screen.getByPlaceholderText('New master password'), {
      target: { value: next },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: confirm },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });
  }

  it('sends the authHash of the CURRENT password and a vault key re-wrapped with the NEW MEK', async () => {
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockChangePasswordApi).toHaveBeenCalledWith({
        currentAuthHash: 'hash:OldMasterPassword1!',
        newAuthHash: 'hash:NewMasterPassword1!',
        newEncryptedVaultKey: 'vk-wrapped-with:NewMasterPassword1!',
        newVaultKeyIv: 'vkIv',
        newVaultKeyTag: 'vkTag',
      });
    });
    // The existing vault key (not a freshly generated one) is re-wrapped.
    expect(cs.encryptVaultKey).toHaveBeenCalledWith(OLD_VAULT_KEY, { mek: 'NewMasterPassword1!' });
  });

  it('refuses to change the master password while the vault is locked', async () => {
    mockChangePasswordApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    act(() => {
      useAuthStore.setState({ vaultKey: null });
    });

    await openChangePassword('OldMasterPassword1!', 'NewMasterPassword1!');

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Vault is locked', type: 'error' }),
      );
    });
    expect(mockChangePasswordApi).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // 2FA
  // -------------------------------------------------------------------------

  async function startSetup2fa() {
    mockSetup2faApi.mockResolvedValue({
      data: {
        success: true,
        data: { secret: 'JBSWY3DPEHPK3PXP', qrCodeDataUrl: 'otpauth://totp/test' },
      },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
  }

  it('starts 2FA setup when Enter is pressed in the password prompt', async () => {
    await renderSettings();
    await startSetup2fa();

    await act(async () => {
      fireEvent.keyDown(screen.getByPlaceholderText('Master password'), { key: 'Enter' });
    });

    await waitFor(() => {
      expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument();
    });
    // The server is re-authenticated with the derived hash, never the raw password.
    expect(mockSetup2faApi).toHaveBeenCalledWith({ password: 'hash:MasterPassword1!' });
  });

  it('dismisses the 2FA prompt without calling the API, and re-opens it with an empty password', async () => {
    await renderSettings();
    await startSetup2fa();

    fireEvent.click(screen.getByText('Cancel'));

    expect(screen.queryByPlaceholderText('Master password')).not.toBeInTheDocument();
    expect(mockSetup2faApi).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByText('Enable'));
    });
    expect((screen.getByPlaceholderText('Master password') as HTMLInputElement).value).toBe('');
  });

  it('copies the manual-entry 2FA secret to the clipboard', async () => {
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByText('JBSWY3DPEHPK3PXP'));

    await act(async () => {
      fireEvent.click(screen.getByText('JBSWY3DPEHPK3PXP'));
    });

    expect(mockWriteText).toHaveBeenCalledWith('JBSWY3DPEHPK3PXP');
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Secret copied', type: 'success' }),
      );
    });
  });

  it('keeps the setup form open and reports "Invalid code" when 2FA verification is rejected', async () => {
    mockVerify2faApi.mockRejectedValue(new Error('bad code'));
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));

    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '000000' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Verify'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Invalid code', type: 'error' }),
      );
    });
    // No backup codes are revealed and the user can retry.
    expect(screen.queryByText('Save Your Backup Codes')).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText('6-digit code')).toBeInTheDocument();
  });

  it('hides the 2FA setup form when its Cancel is clicked', async () => {
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));

    const cancels = screen.getAllByText('Cancel');
    fireEvent.click(cancels[cancels.length - 1]!);

    expect(screen.queryByPlaceholderText('6-digit code')).not.toBeInTheDocument();
  });

  it('copies all backup codes as newline-separated text and hides them once acknowledged', async () => {
    mockVerify2faApi.mockResolvedValue({
      data: { success: true, data: { backupCodes: ['aaaa1111', 'bbbb2222'] } },
    });
    await renderSettings();
    await startSetup2fa();
    await act(async () => {
      fireEvent.click(screen.getByText('Continue'));
    });
    await waitFor(() => screen.getByPlaceholderText('6-digit code'));
    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '123456' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Verify'));
    });
    await waitFor(() => screen.getByText('Save Your Backup Codes'));

    await act(async () => {
      fireEvent.click(screen.getByText('Copy All'));
    });
    expect(mockWriteText).toHaveBeenCalledWith('aaaa1111\nbbbb2222');

    fireEvent.click(screen.getByText("I've Saved These Codes"));
    await waitFor(() => {
      expect(screen.queryByText('Save Your Backup Codes')).not.toBeInTheDocument();
    });
  });

  it('reports "Invalid code or password" and leaves 2FA enabled when disabling is rejected', async () => {
    setProfile({ twoFactorEnabled: true });
    mockDisable2faApi.mockRejectedValue(new Error('wrong code'));
    await renderSettings();

    fireEvent.click(screen.getByText('Disable'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('6-digit code'), { target: { value: '000000' } });
    await act(async () => {
      fireEvent.click(screen.getByText('Disable 2FA'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Invalid code or password', type: 'error' }),
      );
    });
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    // The form stays open so the user can correct the code.
    expect(screen.getByText('Disable 2FA')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Vault key rotation
  // -------------------------------------------------------------------------

  function vaultItem(id: string, withHistory = false) {
    return {
      _id: id,
      encryptedName: `${id}-name`,
      nameIv: `${id}-nameIv`,
      nameTag: `${id}-nameTag`,
      encryptedData: `${id}-data`,
      dataIv: `${id}-dataIv`,
      dataTag: `${id}-dataTag`,
      ...(withHistory
        ? {
            passwordHistory: [
              {
                encryptedPassword: `${id}-pw`,
                iv: `${id}-pwIv`,
                tag: `${id}-pwTag`,
                changedAt: '2026-01-01T00:00:00.000Z',
              },
            ],
          }
        : {}),
    };
  }

  async function confirmRotation(password = 'MasterPassword1!') {
    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Master password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: password },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Confirm Rotation'));
    });
  }

  it('re-encrypts every paginated item, trash item, password-history entry and folder under the NEW key', async () => {
    mockListItems
      .mockResolvedValueOnce({
        data: { success: true, data: [vaultItem('i1', true)], pagination: { totalPages: 2 } },
      })
      .mockResolvedValueOnce({
        data: { success: true, data: [vaultItem('i2')], pagination: { totalPages: 2 } },
      });
    mockListTrash.mockResolvedValue({
      data: { success: true, data: [vaultItem('t1')], pagination: { totalPages: 1 } },
    });
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'f1-iv', nameTag: 'f1-tag' }],
      },
    });

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockBulkReEncrypt).toHaveBeenCalledTimes(1);
    });
    const payload = mockBulkReEncrypt.mock.calls[0]![0] as {
      authHash: string;
      idempotencyKey: string;
      newEncryptedVaultKey: string;
      newVaultKeyIv: string;
      newVaultKeyTag: string;
      items: Record<string, unknown>[];
      folders: Record<string, unknown>[];
    };

    expect(payload.authHash).toBe('hash:MasterPassword1!');
    expect(payload.idempotencyKey).toEqual(expect.any(String));
    expect(payload.newEncryptedVaultKey).toBe('newEnc');
    expect(payload.newVaultKeyIv).toBe('newIv');
    expect(payload.newVaultKeyTag).toBe('newTag');

    // Page 2 and the trash are both enumerated.
    expect(payload.items.map((i) => i.id)).toEqual(['i1', 'i2', 't1']);
    expect(payload.items[0]).toEqual({
      id: 'i1',
      encryptedName: 'enc:plain:i1-name',
      nameIv: 'iv:new-vault-key',
      nameTag: 'tag:new-vault-key',
      encryptedData: 'enc:plain:i1-data',
      dataIv: 'iv:new-vault-key',
      dataTag: 'tag:new-vault-key',
      searchHash: 'sh:plain:i1-name',
      passwordHistory: [
        {
          encryptedPassword: 'enc:plain:i1-pw',
          iv: 'iv:new-vault-key',
          tag: 'tag:new-vault-key',
          changedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
    });
    expect(payload.folders).toEqual([
      {
        id: 'f1',
        encryptedName: 'enc:plain:f1-name',
        nameIv: 'iv:new-vault-key',
        nameTag: 'tag:new-vault-key',
      },
    ]);

    // Ciphertext is read with the OLD key and written with the NEW one.
    expect(cs.decryptData).toHaveBeenCalledWith(
      'i1-name',
      'i1-nameIv',
      'i1-nameTag',
      OLD_VAULT_KEY,
    );
    expect(cs.encryptData).toHaveBeenCalledWith('plain:i1-name', NEW_VAULT_KEY);

    // The client now holds the new key.
    await waitFor(() => {
      expect(useAuthStore.getState().vaultKey).toBe(NEW_VAULT_KEY);
    });
    expect(useAuthStore.getState().encryptedVaultKeyData).toEqual({
      encrypted: 'newEnc',
      iv: 'newIv',
      tag: 'newTag',
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Vault key rotated successfully', type: 'success' }),
    );
  });

  it('aborts the whole rotation without touching the server when one item cannot be re-encrypted', async () => {
    mockListItems.mockResolvedValue({
      data: {
        success: true,
        data: [vaultItem('good'), vaultItem('bad')],
        pagination: { totalPages: 1 },
      },
    });
    cs.decryptData.mockImplementation((enc: string) =>
      enc.startsWith('bad')
        ? Promise.reject(new Error('GCM tag mismatch'))
        : Promise.resolve(`plain:${enc}`),
    );

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Rotation aborted: failed to re-encrypt item 2 of 2',
          type: 'error',
        }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    // The new key is destroyed and the client keeps decrypting with the old one.
    expect(cs.clearCryptoKey).toHaveBeenCalledWith(NEW_VAULT_KEY);
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('aborts the rotation when a folder cannot be re-encrypted', async () => {
    mockListFolders.mockResolvedValue({
      data: {
        success: true,
        data: [{ _id: 'f1', encryptedName: 'f1-name', nameIv: 'iv', nameTag: 'tag' }],
      },
    });
    cs.decryptData.mockRejectedValue(new Error('GCM tag mismatch'));

    await renderSettings();
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Rotation aborted: failed to re-encrypt folder 1 of 1',
          type: 'error',
        }),
      );
    });
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
  });

  it('refuses to rotate while the vault is locked', async () => {
    await renderSettings();

    act(() => {
      useAuthStore.setState({ vaultKey: null, mek: null });
    });
    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Vault is locked', type: 'error' }),
      );
    });
    expect(cs.rotateVaultKey).not.toHaveBeenCalled();
    expect(mockBulkReEncrypt).not.toHaveBeenCalled();
  });

  it('keeps the old vault key when the server rejects the bulk re-encrypt', async () => {
    mockBulkReEncrypt.mockRejectedValue(new Error('500'));
    await renderSettings();

    await confirmRotation();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to rotate vault key', type: 'error' }),
      );
    });
    expect(useAuthStore.getState().vaultKey).toBe(OLD_VAULT_KEY);
    // The dialog stays open so the user can retry.
    expect(screen.getByText('Confirm Rotation')).toBeInTheDocument();
  });

  it('discards the typed passwords when the rotation dialog is cancelled', async () => {
    setProfile({
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
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Backup password'));
    fireEvent.change(screen.getByPlaceholderText('Master password'), {
      target: { value: 'MasterPassword1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPassword1!' },
    });

    const cancels = screen.getAllByText('Cancel');
    fireEvent.click(cancels[cancels.length - 1]!);

    fireEvent.click(screen.getByText('Rotate Key'));
    await waitFor(() => screen.getByPlaceholderText('Backup password'));
    expect((screen.getByPlaceholderText('Master password') as HTMLInputElement).value).toBe('');
    expect((screen.getByPlaceholderText('Backup password') as HTMLInputElement).value).toBe('');
  });

  // -------------------------------------------------------------------------
  // Export / import
  // -------------------------------------------------------------------------

  it('does not export when the account email is unavailable', async () => {
    await renderSettings();
    fireEvent.click(screen.getByText('Export Vault'));
    fireEvent.change(screen.getByPlaceholderText('Enter your master password'), {
      target: { value: 'MasterPassword1!' },
    });

    act(() => {
      useAuthStore.setState({ user: null });
    });
    await act(async () => {
      fireEvent.click(screen.getByText('I Understand, Export'));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Password is required to export', type: 'error' }),
    );
    expect(mockExportVaultApi).not.toHaveBeenCalled();
  });

  it('reports a failed import and leaves the import panel open', async () => {
    mockImportVaultApi.mockRejectedValue(new Error('400'));
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: '{"items":[]}' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to import vault data', type: 'error' }),
      );
    });
    expect(screen.getByPlaceholderText('Paste exported data here...')).toBeInTheDocument();
  });

  it('reports duplicates handled alongside imported and skipped counts', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { importedCount: 2, skippedCount: 1, duplicateCount: 3 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: '{"noItems":true}' },
    });
    fireEvent.change(screen.getByDisplayValue('Skip duplicates'), {
      target: { value: 'overwrite' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Imported 2 items, 3 duplicates handled, 1 undecryptable skipped',
        type: 'success',
      });
    });
    expect(mockImportVaultApi).toHaveBeenCalledWith(
      expect.objectContaining({ conflictStrategy: 'overwrite' }),
    );
    // Panel closes on success.
    expect(screen.queryByPlaceholderText('Paste exported data here...')).not.toBeInTheDocument();
  });

  it('auto-maps CSV headers and sends the (user-adjusted) mapping with the import', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { importedCount: 1, skippedCount: 0 } },
    });
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue('JSON'), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Title,Website,OTP,Comment\nGithub,https://gh.com,SEC,hi' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    // Auto-detection: title→name, website→url, otp→totp, comment→notes.
    expect(screen.getByDisplayValue('Name')).toBeInTheDocument();
    expect(screen.getByDisplayValue('URL')).toBeInTheDocument();
    expect(screen.getByDisplayValue('TOTP Secret')).toBeInTheDocument();

    // The user re-points the "Comment" column at Username.
    fireEvent.change(screen.getByDisplayValue('Notes'), { target: { value: 'username' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Import'));
    });

    await waitFor(() => {
      expect(mockImportVaultApi).toHaveBeenCalledWith({
        format: 'csv',
        data: 'Title,Website,OTP,Comment\nGithub,https://gh.com,SEC,hi',
        conflictStrategy: 'skip',
        csvMapping: {
          Title: 'name',
          Website: 'url',
          OTP: 'totp',
          Comment: 'username',
        },
      });
    });
  });

  it('parses quoted CSV fields containing commas and escaped quotes as single cells', async () => {
    await renderSettings();

    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue('JSON'), { target: { value: 'csv' } });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: 'Name,Notes\nAcme,"one, two ""quoted"""' },
    });

    await waitFor(() => screen.getByText('Map CSV Columns'));
    // A naive split(',') would render "one" and " two" as two cells.
    expect(screen.getByText('one, two "quoted"')).toBeInTheDocument();
    expect(screen.getByText('Preview (1 of 1 rows)')).toBeInTheDocument();
  });

  it('treats an uploaded .enc export as JSON and loads its contents', async () => {
    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue('JSON'), { target: { value: 'csv' } });

    const fileInput = document.querySelector('input[type="file"]')!;
    const content = JSON.stringify({ items: [{ encryptedData: 'abc' }] });
    const file = new File([content], 'hvault-export.enc', { type: '' });

    await act(async () => {
      fireEvent.change(fileInput, { target: { files: [file] } });
      await new Promise((r) => setTimeout(r, 50));
    });

    expect(
      (screen.getByPlaceholderText('Paste exported data here...') as HTMLTextAreaElement).value,
    ).toBe(content);
    expect(screen.getByDisplayValue('JSON')).toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Settings form
  // -------------------------------------------------------------------------

  it('saves the edited timeouts with the active theme and invalidates the settings cache', async () => {
    mockUpdateSettingsApi.mockResolvedValue({ data: { success: true } });
    await renderSettings();

    fireEvent.change(screen.getByDisplayValue('15'), { target: { value: '45' } });
    fireEvent.change(screen.getByDisplayValue('30'), { target: { value: '90' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockUpdateSettingsApi).toHaveBeenCalledWith({
        autoLockTimeout: 45,
        clipboardClearTimeout: 90,
        theme: 'dark',
      });
    });
    // Without this, every other consumer keeps the stale cached timeouts.
    expect(mockClearSettingsCache).toHaveBeenCalled();
  });
});
