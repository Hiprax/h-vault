/**
 * BackupSettingsPage — branch/error-path coverage.
 *
 * Complements tests/settings-pages.test.tsx (which covers the happy-path
 * rendering, the save/trigger basics, the setup form and the same-account vs
 * cross-account re-encryption decision). This file targets the behaviors that
 * suite leaves untested:
 *
 *  - the backup-email editor (add / duplicate / remove / Enter key / cap)
 *  - trigger partial-email-failure reporting (emailsFailed + failedEmails)
 *  - the real DOWNLOAD path: BEK derivation, BWK decryption, the HMAC
 *    integrity signature embedded in the downloaded file, wrong-password
 *  - RESTORE: profile fallback when the file carries no encryption metadata,
 *    integrity verification (valid + TAMPERED), cross-account vault-key
 *    recovery via the BWK-wrapped copy, undecryptable-row filtering, the
 *    all-rows-failed abort, and the trashed-auto-restored notice
 *  - the "no user in store" guards on setup and change-password
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
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

const { mockGetProfileApi, mockToast, mockApiGet, mockApiPost, mockApiPut } = vi.hoisted(() => ({
  mockGetProfileApi: vi.fn(),
  mockToast: vi.fn(),
  mockApiGet: vi.fn(),
  mockApiPost: vi.fn(),
  mockApiPut: vi.fn(),
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
    deriveKeys: vi.fn().mockResolvedValue({
      masterEncryptionKey: new Uint8Array(32),
      authKey: new Uint8Array(32),
    }),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    importVaultKey: vi.fn().mockResolvedValue(new Uint8Array(32)),
    decryptVaultKey: vi.fn(),
    vaultKeyEqualsRaw: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn().mockResolvedValue('hash'),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
    generateSalt: vi.fn().mockReturnValue(new Uint8Array(16)),
    deriveBEK: vi.fn(),
    generateBWK: vi.fn().mockReturnValue(new Uint8Array(32)),
    encryptBWK: vi.fn().mockResolvedValue({ encrypted: 'encBWK', iv: 'bwkIv', tag: 'bwkTag' }),
    encryptVaultKeyWithBWK: vi
      .fn()
      .mockResolvedValue({ encrypted: 'bwkEncVK', iv: 'bwkVKIv', tag: 'bwkVKTag' }),
    decryptVaultKeyWithBWK: vi.fn(),
    decryptBWK: vi.fn(),
    computeBackupHmac: vi.fn(),
    verifyBackupHmac: vi.fn(),
    base64ToArrayBuffer: vi.fn().mockReturnValue(new Uint8Array(16)),
    arrayBufferToBase64: vi.fn().mockReturnValue('base64salt'),
  },
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: (...args: unknown[]) => mockApiGet(...args),
    post: (...args: unknown[]) => mockApiPost(...args),
    put: (...args: unknown[]) => mockApiPut(...args),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    defaults: { headers: { common: {} } },
  },
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

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 8) return { score: 1, feedback: { warning: 'Weak', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

import { useAuthStore } from '../src/stores/authStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { MAX_BACKUP_EMAILS } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Fixtures / helpers
// ---------------------------------------------------------------------------

type BackupSettings = Record<string, unknown>;

const CONFIGURED_BACKUP: BackupSettings = {
  enabled: true,
  scheduleHour: 3,
  backupEmails: ['backup@example.com'],
  isConfigured: true,
  encryptedBWK: 'server-ebwk',
  bwkIv: 'server-biv',
  bwkTag: 'server-btag',
  bwkSalt: 'server-bsalt',
};

function profileWith(backup: BackupSettings) {
  return {
    data: {
      success: true,
      data: {
        email: 'test@example.com',
        emailVerified: true,
        twoFactorEnabled: false,
        settings: {
          autoLockTimeout: 15,
          clipboardClearTimeout: 30,
          theme: 'system' as const,
          backup,
        },
      },
    },
  };
}

/** A backup file that carries its own encryption metadata + BWK-wrapped VK. */
const FILE_ENCRYPTION_META = {
  encryptedBWK: 'file-ebwk',
  bwkIv: 'file-biv',
  bwkTag: 'file-btag',
  bwkSalt: 'file-bsalt',
  bwkEncryptedVaultKey: 'file-bevk',
  bwkVaultKeyIv: 'file-bvkiv',
  bwkVaultKeyTag: 'file-bvktag',
};

const SAMPLE_ITEM = {
  _id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
  encryptedData: 'd',
  dataIv: 'di',
  dataTag: 'dt',
  encryptedName: 'n',
  nameIv: 'ni',
  nameTag: 'nt',
};

const SAMPLE_FOLDER = {
  _id: 'bbbbbbbbbbbbbbbbbbbbbbbb',
  encryptedName: 'fn',
  nameIv: 'fi',
  nameTag: 'ft',
};

async function renderBackup() {
  const { default: BackupSettingsPage } = await import('../src/pages/BackupSettingsPage');
  let result: ReturnType<typeof render>;
  await act(async () => {
    result = render(
      <MemoryRouter initialEntries={['/settings/backup']}>
        <Routes>
          <Route path="/settings" element={<div>Settings Home</div>} />
          <Route path="/settings/backup" element={<BackupSettingsPage />} />
        </Routes>
      </MemoryRouter>,
    );
  });
  return result!;
}

function restoreBody(): Record<string, unknown> {
  const call = mockApiPost.mock.calls.find((c) => c[0] === '/backup/restore');
  return (call?.[1] ?? {}) as Record<string, unknown>;
}

function restoredPayload(): {
  items?: Record<string, unknown>[];
  folders?: Record<string, unknown>[];
} {
  return JSON.parse(String(restoreBody().data)) as {
    items?: Record<string, unknown>[];
    folders?: Record<string, unknown>[];
  };
}

/** Opens the restore form, attaches `fileData` as the backup file and submits. */
async function performRestore(
  fileData: Record<string, unknown>,
  opts: { sizeOverride?: number } = {},
) {
  const { container } = await renderBackup();
  await waitFor(() => screen.getByText('Restore from File'));
  fireEvent.click(screen.getByText('Restore from File'));

  const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
  const file = new File([JSON.stringify(fileData)], 'backup.enc', { type: 'application/json' });
  if (opts.sizeOverride !== undefined) {
    Object.defineProperty(file, 'size', { value: opts.sizeOverride });
  }
  fireEvent.change(fileInput, { target: { files: [file] } });
  // Scoped by id: the (unconfigured) setup card uses the same placeholder.
  const passwordInput = container.querySelector('#restore-password') as HTMLInputElement;
  fireEvent.change(passwordInput, { target: { value: 'BackupPass!' } });
  await act(async () => {
    fireEvent.click(screen.getByText('Restore'));
  });
}

// ---------------------------------------------------------------------------

describe('BackupSettingsPage — emails, download, restore branches', () => {
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

    mockGetProfileApi.mockResolvedValue(profileWith(CONFIGURED_BACKUP));
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') return Promise.resolve({ data: { data: [] } });
      return Promise.resolve({ data: {} });
    });
    mockApiPut.mockResolvedValue({ data: { success: true } });
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        message: 'ok',
        data: { itemsRestored: 1, itemsSkipped: 0, foldersRestored: 0, foldersSkipped: 0 },
      },
    });

    // Crypto defaults: correct password, valid integrity, same-account key.
    vi.mocked(cryptoService.deriveBEK).mockResolvedValue(
      new Uint8Array(32) as unknown as CryptoKey,
    );
    vi.mocked(cryptoService.decryptBWK).mockResolvedValue(new Uint8Array(32).buffer);
    vi.mocked(cryptoService.verifyBackupHmac).mockResolvedValue(true);
    vi.mocked(cryptoService.computeBackupHmac).mockResolvedValue('hmac-signature');
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32).buffer);
    vi.mocked(cryptoService.decryptVaultKeyWithBWK).mockResolvedValue(new Uint8Array(32).buffer);
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(true);
    vi.mocked(cryptoService.decryptData).mockResolvedValue('plaintext');
    vi.mocked(cryptoService.encryptData).mockResolvedValue({
      encrypted: 'reenc',
      iv: 'reiv',
      tag: 'retag',
    });
  });

  // =========================================================================
  // Load
  // =========================================================================

  it('surfaces a load failure when the profile response is not successful', async () => {
    mockGetProfileApi.mockResolvedValue({ data: { success: false } });
    await renderBackup();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to load backup settings', type: 'error' }),
      );
    });
  });

  it('navigates back to /settings from the back button', async () => {
    await renderBackup();
    await waitFor(() => screen.getByLabelText('Back to settings'));

    fireEvent.click(screen.getByLabelText('Back to settings'));

    await waitFor(() => {
      expect(screen.getByText('Settings Home')).toBeInTheDocument();
    });
  });

  // =========================================================================
  // Backup email editor
  // =========================================================================

  it('adds a backup email, lowercasing and trimming it, and persists it on save', async () => {
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Add backup email'));

    fireEvent.change(screen.getByPlaceholderText('Add backup email'), {
      target: { value: '  Second@Example.COM  ' },
    });
    fireEvent.click(screen.getByText('Add'));

    // Normalized in the list and the input reset.
    expect(screen.getByText('second@example.com')).toBeInTheDocument();
    expect((screen.getByPlaceholderText('Add backup email') as HTMLInputElement).value).toBe('');

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockApiPut).toHaveBeenCalledWith('/backup/settings', {
        enabled: true,
        scheduleHour: 3,
        backupEmails: ['backup@example.com', 'second@example.com'],
      });
    });
  });

  it('adds the email on Enter without submitting the form', async () => {
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Add backup email'));

    fireEvent.change(screen.getByPlaceholderText('Add backup email'), {
      target: { value: 'enter@example.com' },
    });
    fireEvent.keyDown(screen.getByPlaceholderText('Add backup email'), { key: 'Enter' });

    expect(screen.getByText('enter@example.com')).toBeInTheDocument();
  });

  it('rejects a duplicate backup email and leaves the list unchanged', async () => {
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Add backup email'));

    fireEvent.change(screen.getByPlaceholderText('Add backup email'), {
      target: { value: 'BACKUP@example.com' },
    });
    fireEvent.click(screen.getByText('Add'));

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Email already added', type: 'error' }),
    );
    expect(screen.getAllByText('backup@example.com')).toHaveLength(1);
    // Still 1 of MAX in the counter.
    expect(screen.getByText(`(1/${String(MAX_BACKUP_EMAILS)})`)).toBeInTheDocument();
  });

  it('hides the add-email input once MAX_BACKUP_EMAILS are configured', async () => {
    const emails = Array.from({ length: MAX_BACKUP_EMAILS }, (_, i) => `u${String(i)}@example.com`);
    mockGetProfileApi.mockResolvedValue(
      profileWith({ ...CONFIGURED_BACKUP, backupEmails: emails }),
    );

    await renderBackup();
    await waitFor(() =>
      screen.getByText(`(${String(MAX_BACKUP_EMAILS)}/${String(MAX_BACKUP_EMAILS)})`),
    );

    expect(screen.queryByPlaceholderText('Add backup email')).not.toBeInTheDocument();
  });

  it('removes a backup email and saves the shortened list', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ ...CONFIGURED_BACKUP, backupEmails: ['a@example.com', 'b@example.com'] }),
    );
    await renderBackup();
    await waitFor(() => screen.getByLabelText('Remove a@example.com'));

    fireEvent.click(screen.getByLabelText('Remove a@example.com'));
    expect(screen.queryByText('a@example.com')).not.toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockApiPut).toHaveBeenCalledWith(
        '/backup/settings',
        expect.objectContaining({ backupEmails: ['b@example.com'] }),
      );
    });
  });

  it('saves the edited schedule hour', async () => {
    const { container } = await renderBackup();
    await waitFor(() => screen.getByText('Save Settings'));

    const hourInput = container.querySelector('input[type="number"]') as HTMLInputElement;
    fireEvent.change(hourInput, { target: { value: '17' } });

    await act(async () => {
      fireEvent.click(screen.getByText('Save Settings'));
    });

    await waitFor(() => {
      expect(mockApiPut).toHaveBeenCalledWith(
        '/backup/settings',
        expect.objectContaining({ scheduleHour: 17 }),
      );
    });
  });

  // =========================================================================
  // Trigger — partial email failure
  // =========================================================================

  it('warns with the failed recipients when some backup emails could not be sent', async () => {
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        message: 'Backup sent to 1 of 3 recipients',
        data: { emailsSent: 1, emailsFailed: 2, failedEmails: ['a@x.com', 'b@x.com'] },
      },
    });

    await renderBackup();
    await waitFor(() => screen.getByText('Backup Now'));

    await act(async () => {
      fireEvent.click(screen.getByText('Backup Now'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup sent to 1 of 3 recipients. Failed: a@x.com, b@x.com',
        type: 'warning',
      });
    });
  });

  it('reports "unknown" recipients when the server omits failedEmails', async () => {
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        message: 'Partial delivery',
        data: { emailsSent: 0, emailsFailed: 1 },
      },
    });

    await renderBackup();
    await waitFor(() => screen.getByText('Backup Now'));

    await act(async () => {
      fireEvent.click(screen.getByText('Backup Now'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Partial delivery. Failed: unknown',
        type: 'warning',
      });
    });
  });

  // =========================================================================
  // Download
  // =========================================================================

  async function openDownloadPrompt() {
    await renderBackup();
    await waitFor(() => screen.getByText('Download Latest'));
    await act(async () => {
      fireEvent.click(screen.getByText('Download Latest'));
    });
    await waitFor(() => screen.getByPlaceholderText('Backup password'));
  }

  it('signs the downloaded backup with an HMAC integrity field computed over the unsigned payload', async () => {
    const serverBackup = { items: [SAMPLE_ITEM], folders: [], version: 1 };
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') return Promise.resolve({ data: { data: [] } });
      if (url === '/backup/download')
        return Promise.resolve({ data: JSON.stringify(serverBackup) });
      return Promise.resolve({ data: {} });
    });

    const blobs: Blob[] = [];
    const origCreate = URL.createObjectURL;
    const origRevoke = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn((b: Blob) => {
      blobs.push(b);
      return 'blob:mock';
    }) as unknown as typeof URL.createObjectURL;
    URL.revokeObjectURL = vi.fn();
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup downloaded with integrity signature',
        type: 'success',
      });
    });

    // The HMAC is computed over the canonical payload WITHOUT the integrity field...
    expect(cryptoService.computeBackupHmac).toHaveBeenCalledWith(
      JSON.stringify(serverBackup),
      expect.anything(),
    );
    // ...and the downloaded file is that payload plus the signature.
    expect(blobs).toHaveLength(1);
    const written = JSON.parse(await blobs[0]!.text()) as Record<string, unknown>;
    expect(written.integrity).toBe('hmac-signature');
    expect(written.items).toEqual([SAMPLE_ITEM]);
    expect(anchorClick).toHaveBeenCalled();

    // The prompt is dismissed and the password cleared on success.
    expect(screen.queryByPlaceholderText('Backup password')).not.toBeInTheDocument();

    anchorClick.mockRestore();
    URL.createObjectURL = origCreate;
    URL.revokeObjectURL = origRevoke;
  });

  it('reports an incorrect backup password and never requests the backup when BWK decryption fails', async () => {
    vi.mocked(cryptoService.decryptBWK).mockRejectedValue(new Error('GCM tag mismatch'));

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'WrongPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Incorrect backup password',
        type: 'error',
      });
    });
    expect(mockApiGet).not.toHaveBeenCalledWith('/backup/download', expect.anything());
  });

  it('refuses to download when backup encryption metadata is missing from the profile', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({
        enabled: true,
        scheduleHour: 3,
        backupEmails: [],
        isConfigured: true,
        // bwk* fields intentionally absent
      }),
    );

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup encryption is not configured',
        type: 'error',
      });
    });
    expect(cryptoService.deriveBEK).not.toHaveBeenCalled();
  });

  it('triggers the download from the Enter key in the password prompt', async () => {
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') return Promise.resolve({ data: { data: [] } });
      if (url === '/backup/download') return Promise.resolve({ data: '{"items":[]}' });
      return Promise.resolve({ data: {} });
    });
    const origCreate = URL.createObjectURL;
    const origRevoke = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn().mockReturnValue('blob:mock');
    URL.revokeObjectURL = vi.fn();
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.keyDown(screen.getByPlaceholderText('Backup password'), { key: 'Enter' });
    });

    await waitFor(() => {
      expect(mockApiGet).toHaveBeenCalledWith('/backup/download', { responseType: 'text' });
    });

    anchorClick.mockRestore();
    URL.createObjectURL = origCreate;
    URL.revokeObjectURL = origRevoke;
  });

  it('reports a download failure when the backup endpoint rejects', async () => {
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history') return Promise.resolve({ data: { data: [] } });
      if (url === '/backup/download') return Promise.reject(new Error('500'));
      return Promise.resolve({ data: {} });
    });

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({ title: 'Failed to download backup', type: 'error' });
    });
    // The prompt stays open so the user can retry.
    expect(screen.getByPlaceholderText('Backup password')).toBeInTheDocument();
  });

  it('reports a download failure when the profile response is unsuccessful', async () => {
    mockGetProfileApi
      .mockResolvedValueOnce(profileWith(CONFIGURED_BACKUP))
      .mockResolvedValueOnce({ data: { success: false } });

    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Download$/ }));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({ title: 'Failed to download backup', type: 'error' });
    });
    expect(cryptoService.deriveBEK).not.toHaveBeenCalled();
  });

  it('clears the entered password when the download prompt is cancelled', async () => {
    await openDownloadPrompt();
    fireEvent.change(screen.getByPlaceholderText('Backup password'), {
      target: { value: 'BackupPass!' },
    });

    fireEvent.click(screen.getByText('Cancel'));
    expect(screen.queryByPlaceholderText('Backup password')).not.toBeInTheDocument();

    // Re-opening shows an empty field — the previous password was not retained.
    await act(async () => {
      fireEvent.click(screen.getByText('Download Latest'));
    });
    expect((screen.getByPlaceholderText('Backup password') as HTMLInputElement).value).toBe('');
    expect(cryptoService.deriveBEK).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Restore
  // =========================================================================

  it('rejects a backup file larger than 25 MB before reading it', async () => {
    await performRestore({ items: [], folders: [] }, { sizeOverride: 26 * 1024 * 1024 });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup file too large',
        description: 'Maximum file size is 25 MB. Selected file is 26 MB.',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('falls back to the account profile encryption metadata when the file carries none', async () => {
    await performRestore({ items: [SAMPLE_ITEM], folders: [] });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    // The account's stored BWK ciphertext (not a file-embedded one) was unwrapped.
    expect(cryptoService.decryptBWK).toHaveBeenCalledWith(
      'server-ebwk',
      'server-biv',
      'server-btag',
      expect.anything(),
    );
  });

  it('aborts the restore when neither the file nor the account has encryption metadata', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );

    await performRestore({ items: [SAMPLE_ITEM], folders: [] });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup encryption is not configured and backup file has no encryption metadata',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('rejects an incorrect backup password on restore without sending anything', async () => {
    vi.mocked(cryptoService.decryptBWK).mockRejectedValue(new Error('GCM tag mismatch'));

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Incorrect backup password',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('verifies a signed backup against the payload with the integrity field stripped', async () => {
    const fileData = {
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
      integrity: 'sig-from-download',
    };

    await performRestore(fileData);

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });

    const { integrity: _omit, ...unsigned } = fileData;
    expect(cryptoService.verifyBackupHmac).toHaveBeenCalledWith(
      JSON.stringify(unsigned),
      'sig-from-download',
      expect.anything(),
    );
    // A signed backup does NOT get the "older backup" warning.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: expect.stringContaining('no integrity signature') }),
    );
  });

  it('rejects a tampered backup whose integrity signature does not verify', async () => {
    vi.mocked(cryptoService.verifyBackupHmac).mockResolvedValue(false);

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
      integrity: 'forged',
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup integrity check failed. The file may have been tampered with.',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('warns when an old backup carries no integrity signature but still restores it', async () => {
    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'This backup has no integrity signature. It may be an older backup.',
        type: 'warning',
      });
    });
    expect(cryptoService.verifyBackupHmac).not.toHaveBeenCalled();
    expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('recovers a cross-account vault key from the BWK-wrapped copy and re-encrypts the rows', async () => {
    // The current MEK cannot decrypt a foreign backup's vault key...
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('MEK mismatch'));
    // ...so the BWK-wrapped copy in the file is used, and it differs from ours.
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [SAMPLE_FOLDER],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(cryptoService.decryptVaultKeyWithBWK).toHaveBeenCalledWith(
      'file-bevk',
      'file-bvkiv',
      'file-bvktag',
      expect.anything(),
    );

    const payload = restoredPayload();
    expect(payload.items?.[0]!.encryptedData).toBe('reenc');
    expect(payload.folders?.[0]!.encryptedName).toBe('reenc');
    // Server-only key material is never forwarded.
    const raw = restoreBody().data as string;
    expect(raw).not.toContain('encryptedVaultKey');
    expect(raw).not.toContain('backupEncryption');
  });

  it('warns when the backup carries no BWK-wrapped vault key to recover', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('MEK mismatch'));
    const {
      bwkEncryptedVaultKey: _a,
      bwkVaultKeyIv: _b,
      bwkVaultKeyTag: _c,
      ...noWrappedVk
    } = FILE_ENCRYPTION_META;

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: noWrappedVk,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('Could not recover the backup') as string,
          type: 'warning',
        }),
      );
    });
    expect(cryptoService.decryptVaultKeyWithBWK).not.toHaveBeenCalled();
  });

  it('warns when unwrapping the BWK-wrapped vault key itself fails', async () => {
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('MEK mismatch'));
    vi.mocked(cryptoService.decryptVaultKeyWithBWK).mockRejectedValue(new Error('corrupt'));

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: expect.stringContaining('Items may fail to decrypt') as string,
          type: 'warning',
        }),
      );
    });
  });

  it('fails the restore when the profile fallback lookup is unsuccessful', async () => {
    mockGetProfileApi
      .mockResolvedValueOnce(profileWith(CONFIGURED_BACKUP))
      .mockResolvedValueOnce({ data: { success: false } });

    // No file-embedded metadata -> the profile is consulted, and it fails.
    await performRestore({ items: [SAMPLE_ITEM], folders: [] });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to restore backup', type: 'error' }),
      );
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('drops a malformed passwordHistory entry while keeping the item', async () => {
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);

    await performRestore({
      items: [
        {
          ...SAMPLE_ITEM,
          passwordHistory: [
            { iv: 'i1', tag: 't1', changedAt: '2026-01-01T00:00:00.000Z' }, // no encryptedPassword
            {
              encryptedPassword: 'p2',
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
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });

    const items = restoredPayload().items ?? [];
    expect(items).toHaveLength(1);
    const history = items[0]!.passwordHistory as Record<string, unknown>[];
    expect(history).toHaveLength(1);
    expect(history[0]!.changedAt).toBe('2026-01-02T00:00:00.000Z');
    expect(history[0]!.encryptedPassword).toBe('reenc');
  });

  it('drops rows missing encryption fields and reports how many were skipped', async () => {
    await performRestore({
      items: [SAMPLE_ITEM, { _id: 'dddddddddddddddddddddddd', encryptedData: 'only-data' }],
      folders: [SAMPLE_FOLDER, { _id: 'eeeeeeeeeeeeeeeeeeeeeeee' }],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });

    const payload = restoredPayload();
    expect(payload.items).toHaveLength(1);
    expect(payload.folders).toHaveLength(1);
    expect(mockToast).toHaveBeenCalledWith({
      title: 'Backup restored. 2 undecryptable item(s)/folder(s) were skipped.',
      type: 'warning',
    });
  });

  it('aborts when every item and folder fails to decrypt', async () => {
    vi.mocked(cryptoService.decryptData).mockRejectedValue(new Error('GCM tag mismatch'));

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [SAMPLE_FOLDER],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title:
          'All items and folders failed decryption. The backup may use a different encryption key.',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('tells the user that trashed items were auto-restored despite the skip strategy', async () => {
    mockApiPost.mockResolvedValue({
      data: {
        success: true,
        data: {
          itemsRestored: 1,
          itemsSkipped: 1,
          foldersRestored: 0,
          foldersSkipped: 0,
          itemSkipReasons: [
            { itemId: 'i1', reason: 'trashed_auto_restored' },
            { itemId: 'i2', reason: 'conflict_skipped' },
          ],
        },
      },
    });

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title:
          'Backup restored. 1 trashed item(s) were auto-restored regardless of the conflict strategy.',
        type: 'warning',
      });
    });
    // The restore form closes on success.
    expect(screen.queryByPlaceholderText('Backup encryption password')).not.toBeInTheDocument();
  });

  it('reports a plain success when nothing was skipped or auto-restored', async () => {
    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Backup restored successfully',
        type: 'success',
      });
    });
  });

  // =========================================================================
  // Guards that depend on the auth store
  // =========================================================================

  it('refuses to set up backup encryption when no user is loaded', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));

    useAuthStore.setState({ user: null });

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'StrongBackupPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'StrongBackupPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MasterPass1!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Master password is required',
        type: 'error',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/setup', expect.anything());
  });

  it('errors when the backup setup passwords do not match and sends nothing', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));

    fireEvent.change(screen.getByPlaceholderText('Backup encryption password'), {
      target: { value: 'StrongBackupPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Confirm backup password'), {
      target: { value: 'DifferentPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MasterPass1!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Setup Encryption'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({ title: 'Passwords do not match', type: 'error' });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/setup', expect.anything());
  });

  it('refuses to change the backup password when no user is loaded', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));

    useAuthStore.setState({ user: null });

    fireEvent.change(screen.getByPlaceholderText('Current master password'), {
      target: { value: 'MasterPass1!' },
    });
    fireEvent.change(screen.getByPlaceholderText('New backup password'), {
      target: { value: 'BrandNewBackupPass1!' },
    });

    await act(async () => {
      fireEvent.click(screen.getByText('Change Password'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({ title: 'User not found', type: 'error' });
    });
    expect(mockApiPut).not.toHaveBeenCalledWith('/backup/change-password', expect.anything());
  });
});
