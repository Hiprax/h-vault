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
import { AxiosError } from 'axios';
import { render, screen, fireEvent, waitFor, act, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router';
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

// Mock the LAZY LOADER as well as the library, delegating to whatever this file
// mocked `zxcvbn` to be. `lazyZxcvbn` caches the resolved library in a
// module-level binding, and the pages that gate on strength call `getZxcvbn()`
// from both a mount effect and a submit handler — two concurrent cold dynamic
// imports racing for one cache slot, where a win by the unmocked module makes
// every later assertion in the file score against the REAL zxcvbn. Order used to
// hide it; `sequence.shuffle` does not.
vi.mock('../src/lib/lazyZxcvbn', async () => {
  const zxcvbn = await import('zxcvbn');
  return { getZxcvbn: () => Promise.resolve(zxcvbn.default) };
});

vi.mock('zxcvbn', () => ({
  default: (password?: string) => {
    if (!password) return { score: 0, feedback: { warning: '', suggestions: [] } };
    if (password.length <= 8) return { score: 1, feedback: { warning: 'Weak', suggestions: [] } };
    return { score: 4, feedback: { warning: '', suggestions: [] } };
  },
}));

import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
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

/**
 * DISTINGUISHABLE stand-ins for the two unwrapped backup wrapping keys, keyed on
 * the wrapper ciphertext — the only field that differs between the account's
 * block and the file's.
 *
 * Load-bearing, and the reason is a defect this suite could not previously see.
 * Restore unwraps BOTH wrappers and hands them to different consumers: the
 * account's decides the integrity verdict, the file's opens the file's own
 * BWK-wrapped vault key. A `decryptBWK` that resolved one buffer for every input
 * — which is what this file used to mock — passes whichever key the page plumbs
 * wherever, so the cross-account plumbing could be wrong and still green.
 *
 * ASSERT ON THESE BY IDENTITY (`toBe`), NEVER WITH `toHaveBeenCalledWith` OR
 * `toEqual`. Measured: Vitest's structural equality reports two same-length
 * `ArrayBuffer`s as equal whatever bytes they hold, so
 * `toHaveBeenCalledWith(…, ACCOUNT_BWK)` passes when the FILE's key was used —
 * which is precisely the defect these two constants exist to catch. Read the key
 * out of `mock.calls` and compare it with `toBe`.
 */
const ACCOUNT_BWK = new Uint8Array([0xa0, 0xa1]).buffer;
const FILE_BWK = new Uint8Array([0xf0, 0xf1]).buffer;

/**
 * Every buffer handed to `cryptoService.clearKey`, BY REFERENCE.
 *
 * Returned as a raw array rather than asserted with `toHaveBeenCalledWith`, for
 * the reason in the note above: `ArrayBuffer`s compare equal to each other under
 * Vitest's structural equality, so only `toContain`/`toBe` — which use identity
 * — can say WHICH key was zeroed. The mocked salt goes through here too, which
 * is exactly why counting calls would prove nothing.
 */
function zeroedKeys(): unknown[] {
  return vi.mocked(cryptoService.clearKey).mock.calls.map(([buffer]) => buffer);
}

function bwkFor(encryptedBWK: unknown): ArrayBuffer {
  if (encryptedBWK === CONFIGURED_BACKUP.encryptedBWK) return ACCOUNT_BWK;
  if (encryptedBWK === FILE_ENCRYPTION_META.encryptedBWK) return FILE_BWK;
  // A wrapper this file did not name: still its own buffer, so an unexpected
  // third key cannot be mistaken for either of the two above.
  return new Uint8Array([0x99]).buffer;
}

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

/** The label of the control that carries an unverifiable restore past the prompt. */
const CONFIRM_UNVERIFIED = 'Restore Unverified Backup';
const CANCEL_UNVERIFIED = 'Cancel Restore';

/**
 * Opens the restore form, attaches `fileData` as the backup file and submits.
 *
 * A file whose signature this account cannot verify — which, since the policy
 * changed, is every unsigned file and every foreign one — stops at a prompt, and
 * this helper ANSWERS IT AFFIRMATIVELY by default. That is deliberate: the cases
 * below are about re-encryption, row filtering and the notices, not about the
 * gate, and a gate answered in the helper keeps them saying what they were
 * written to say. The gate itself is pinned by its own cases further down, which
 * pass `unverified: 'cancel'` or `'leave'` and assert the negative, so a
 * regression that stopped raising the prompt at all still fails there.
 */
async function performRestore(
  fileData: Record<string, unknown>,
  opts: { sizeOverride?: number; unverified?: 'confirm' | 'cancel' | 'leave' } = {},
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

  const answer = opts.unverified ?? 'confirm';
  if (answer === 'leave') return;
  const control = screen.queryByText(answer === 'confirm' ? CONFIRM_UNVERIFIED : CANCEL_UNVERIFIED);
  if (control) {
    await act(async () => {
      fireEvent.click(control);
    });
  }
}

/**
 * The recoverable refusal the two vault-key-sealing backup writes answer with:
 * a 409 whose `data` carries the account's CURRENT generation. Discriminated on
 * the presence of that number and never on the message, which is what
 * `staleVaultKeyVersion` does.
 */
function staleVaultKeyRejection(): AxiosError {
  // A REAL `AxiosError`, because `staleVaultKeyVersion` gates on `isAxiosError`
  // before it looks at anything else — a hand-rolled `{ response: … }` would be
  // ignored and this case would assert that the notice stays silent while
  // believing it asserts the opposite.
  return new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, {
    status: 409,
    statusText: 'Conflict',
    headers: {},
    config: { headers: {} } as never,
    data: {
      success: false,
      message: 'The vault key was rotated elsewhere. Reload to pick up vault key version 9.',
      data: { vaultKeyVersion: 9 },
    },
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
      // Deliberately NOT zero: every restored row is re-encrypted to THIS key,
      // and the request names the generation that goes with it. A base of zero
      // would let a hardcoded default pass as the real number.
      vaultKeyVersion: 7,
    });
    // The notice is app-wide state that no mock reset clears, so it is reset
    // here: a case that leaves it set would decide the next case's assertion.
    useUIStore.setState({ staleVaultKeyVersion: null });

    mockGetProfileApi.mockResolvedValue(profileWith(CONFIGURED_BACKUP));
    mockApiGet.mockImplementation((url: string) => {
      if (url === '/backup/history')
        return Promise.resolve({
          data: {
            success: true,
            data: [],
            pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
          },
        });
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
    vi.mocked(cryptoService.decryptBWK).mockImplementation((encryptedBWK: string) =>
      Promise.resolve(bwkFor(encryptedBWK)),
    );
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
      if (url === '/backup/history')
        return Promise.resolve({
          data: {
            success: true,
            data: [],
            pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
          },
        });
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
      if (url === '/backup/history')
        return Promise.resolve({
          data: {
            success: true,
            data: [],
            pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
          },
        });
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
      if (url === '/backup/history')
        return Promise.resolve({
          data: {
            success: true,
            data: [],
            pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
          },
        });
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

  it('names the generation every restored row was re-encrypted to', async () => {
    // A restore never replaces the account's vault key: the client re-encrypts
    // every backup row to the key it currently holds. Which is exactly why the
    // generation matters here as much as on a create — a rotation that commits
    // between that re-encryption and this request strands every row it sends.
    await performRestore({ items: [SAMPLE_ITEM], folders: [] });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(restoreBody()).toMatchObject({ vaultKeyVersion: 7 });
    // The negative this endpoint has always carried: no vault-key adoption and
    // no master-password re-auth ride along with it.
    expect(restoreBody()).not.toHaveProperty('adoptVaultKey');
    expect(restoreBody()).not.toHaveProperty('authHash');
  });

  it('raises the reload notice when the restore is refused for a superseded key', async () => {
    mockApiPost.mockRejectedValue({
      isAxiosError: true,
      response: {
        status: 409,
        data: {
          success: false,
          message: 'The vault key was rotated elsewhere.',
          data: { vaultKeyVersion: 11 },
        },
      },
    });

    await performRestore({ items: [SAMPLE_ITEM], folders: [] });

    await waitFor(() => {
      expect(useUIStore.getState().staleVaultKeyVersion).toBe(11);
    });
    // The negatives: the failure is reported rather than swallowed, nothing is
    // retried, and this session's generation is untouched — adopting the number
    // the server named would move the whole session onto a key it chose.
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to restore backup' }),
    );
    expect(mockApiPost.mock.calls.filter((c) => c[0] === '/backup/restore')).toHaveLength(1);
    expect(useAuthStore.getState().vaultKeyVersion).toBe(7);
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

  it('treats a wrapper missing any one of its four fields as no wrapper at all', async () => {
    // A partial block is not a usable key, and the completeness test has to be
    // all-or-nothing on every field individually — a wrapper accepted without
    // its tag or its salt would be carried to a derivation that cannot work.
    // Driven one dropped field at a time, so no single field can stop being
    // checked without this failing.
    for (const dropped of ['encryptedBWK', 'bwkIv', 'bwkTag', 'bwkSalt'] as const) {
      vi.clearAllMocks();
      mockGetProfileApi.mockResolvedValue(
        profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
      );
      // Rebuilt without the field rather than deleted from a copy: a dynamic
      // `delete` is a lint error here, and omission is what a real partial
      // block looks like anyway.
      const partial = Object.fromEntries(
        Object.entries(FILE_ENCRYPTION_META).filter(([field]) => field !== dropped),
      );

      await performRestore({ items: [SAMPLE_ITEM], folders: [], backupEncryption: partial });

      await waitFor(() => {
        expect(mockToast, `dropped ${dropped}`).toHaveBeenCalledWith({
          title: 'Backup encryption is not configured and backup file has no encryption metadata',
          type: 'error',
        });
      });
      // Never carried to a derivation, and never sent.
      expect(cryptoService.deriveBEK, `dropped ${dropped}`).not.toHaveBeenCalled();
      expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
      cleanup();
    }
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

    // `unverified: 'leave'` so the helper does not answer a prompt on the way
    // out: without it, "the prompt is absent" below could equally mean "the
    // prompt appeared for a misclassified verdict and the helper clicked it
    // away", which is the one thing this case must be able to tell apart.
    await performRestore(
      {
        items: [SAMPLE_ITEM],
        folders: [],
        backupEncryption: FILE_ENCRYPTION_META,
        integrity: 'forged',
      },
      { unverified: 'leave' },
    );

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'This backup’s integrity signature does not match its contents.',
          type: 'error',
        }),
      );
    });
    // BOTH available keys were asked, so the refusal means "nothing here agrees
    // with it" rather than "the first key I tried disagreed".
    expect(cryptoService.verifyBackupHmac).toHaveBeenCalledTimes(2);
    // A refusal is not a question: the prompt must not be offered as a way past it.
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('does not accuse a signature no key agrees with of being tampered with', async () => {
    // The old copy asserted tampering as fact. It cannot be known here: a file
    // signed under a backup password other than the one entered fails in exactly
    // the same way, and telling a user their own file was tampered with is a lie
    // they have no way to check.
    vi.mocked(cryptoService.verifyBackupHmac).mockResolvedValue(false);

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
      integrity: 'signed-under-another-password',
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: expect.stringContaining(
            'signed under a different backup password',
          ) as string,
        }),
      );
    });
    const refusal = mockToast.mock.calls.find(
      (call) =>
        (call[0] as { title?: string }).title ===
        'This backup’s integrity signature does not match its contents.',
    );
    // Case-INSENSITIVE, and on the stem rather than one inflection: "Tampered"
    // at the start of a sentence, or "tampering", is the same accusation and a
    // `toContain('tampered')` would let either through.
    expect(String((refusal?.[0] as { description?: string }).description)).not.toMatch(/tamper/i);
  });

  // ---- The restore-signature gate -----------------------------------------
  //
  // These cases replace one that asserted the opposite: an unsigned backup used
  // to raise a warning toast and RESTORE ANYWAY, and that test pinned the
  // fall-through as intended behaviour. `SECURITY.md` documented the opposite,
  // and a notice the reader does not have to answer is not a control, so the
  // expectation is what changed rather than the code being bent to fit it.

  it('does not restore an unsigned backup while the prompt is still unanswered', async () => {
    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'leave' },
    );

    // The prompt is up, and names the reason it is up.
    expect(screen.getByText(CONFIRM_UNVERIFIED)).toBeInTheDocument();
    expect(screen.getByText(/carries no integrity signature at all/)).toBeInTheDocument();
    // Nothing was verified, because there was nothing to verify...
    expect(cryptoService.verifyBackupHmac).not.toHaveBeenCalled();
    // ...and, the whole point, nothing was sent.
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
    // The passive notice this replaced is gone; one event, one notice.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: expect.stringContaining('no integrity signature') }),
    );
  });

  it('sends nothing when an unsigned restore is cancelled, and says nothing was changed', async () => {
    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'cancel' },
    );

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Restore cancelled. Nothing was changed.',
        type: 'info',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
  });

  it('restores an unsigned backup once the prompt is answered, and only then', async () => {
    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
  });

  it('dismissing the prompt with Escape cancels the restore', async () => {
    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'leave' },
    );

    await act(async () => {
      fireEvent.keyDown(document, { key: 'Escape' });
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Restore cancelled. Nothing was changed.',
        type: 'info',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it("dismissing the prompt with the dialog's own close control cancels the restore", async () => {
    // The third way out of this prompt, and each way is its OWN function:
    // Escape and the overlay go through `onOpenChange`, `Cancel Restore` has its
    // own inline handler, and the corner control is `DialogContent`'s `onClose`
    // — a prop the component renders NOTHING for when it is absent. Only this
    // case reaches the third, so a prompt that silently lost its close control,
    // or gained one wired to something that does not answer, is visible here
    // and nowhere else.
    //
    // And the assertion that carries the weight is not "no request was sent" —
    // a promise nobody settles sends nothing either, so that passes on the
    // broken version. It is that the awaiting `handleRestore` REACHED ITS
    // `finally` and released both wrapping keys.
    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'leave' },
    );
    expect(zeroedKeys()).not.toContain(FILE_BWK);

    await act(async () => {
      fireEvent.click(screen.getByLabelText('Close'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Restore cancelled. Nothing was changed.',
        type: 'info',
      });
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
    expect(zeroedKeys()).toContain(FILE_BWK);
    expect(zeroedKeys()).toContain(ACCOUNT_BWK);
  });

  it('zeroes the wrapping keys when the page is unmounted with the prompt still open', async () => {
    // An auto-lock unmounts this route. The assertion that matters is NOT "no
    // request was sent" — that passes whether or not the resolver exists, since
    // a promise nobody settles sends nothing either. What the resolver actually
    // buys is that `handleRestore` REACHES ITS `finally`, so the unwrapped
    // wrapping keys are zeroed instead of being held for the life of the tab.
    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'leave' },
    );
    expect(screen.getByText(CONFIRM_UNVERIFIED)).toBeInTheDocument();
    // Still held while the question stands.
    expect(zeroedKeys()).not.toContain(FILE_BWK);

    await act(async () => {
      cleanup();
    });

    expect(zeroedKeys()).toContain(FILE_BWK);
    expect(zeroedKeys()).toContain(ACCOUNT_BWK);
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('zeroes the wrapping keys when the page is unmounted BEFORE the prompt is raised', async () => {
    // The window the resolver ref cannot see. Registration happens late — after
    // a profile read and up to two 600k-iteration derivations — so an auto-lock
    // landing inside it unmounts the page while the ref is still null. The
    // cleanup then has nothing to settle, and a resolver registered a moment
    // later is one nothing can ever reach: the promise never settles, the
    // `finally` never runs, and both wrapping keys stay in memory with no
    // outcome reported. Held open here by stalling the profile read, then
    // unmounting, then letting it through.
    let releaseProfile: (() => void) | undefined;
    mockGetProfileApi.mockResolvedValueOnce(profileWith(CONFIGURED_BACKUP)).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          releaseProfile = () => resolve(profileWith(CONFIGURED_BACKUP));
        }),
    );

    const { container } = await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));
    fireEvent.click(screen.getByText('Restore from File'));
    fireEvent.change(container.querySelector('input[type="file"]') as HTMLInputElement, {
      target: {
        files: [
          new File(
            [
              JSON.stringify({
                items: [SAMPLE_ITEM],
                folders: [],
                backupEncryption: FILE_ENCRYPTION_META,
              }),
            ],
            'backup.enc',
            { type: 'application/json' },
          ),
        ],
      },
    });
    fireEvent.change(container.querySelector('#restore-password') as HTMLInputElement, {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Restore'));
    });

    // Unmounted while the restore is still inside the profile read.
    await act(async () => {
      cleanup();
    });
    await act(async () => {
      releaseProfile?.();
      await Promise.resolve();
    });

    // No prompt was ever raised, and the restore still finished and cleaned up.
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
    await waitFor(() => expect(zeroedKeys()).toContain(FILE_BWK));
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('restores a backup signed under the ACCOUNT’s key with no prompt at all', async () => {
    // What a same-account restore looks like: the server copies the account's own
    // block into every download, so the file's wrapper and the account's are the
    // same wrapper and the signature verifies under key material the file did not
    // supply. This is the only arrangement that restores unremarked.
    await performRestore(
      {
        items: [SAMPLE_ITEM],
        folders: [],
        backupEncryption: {
          encryptedBWK: CONFIGURED_BACKUP.encryptedBWK,
          bwkIv: CONFIGURED_BACKUP.bwkIv,
          bwkTag: CONFIGURED_BACKUP.bwkTag,
          bwkSalt: CONFIGURED_BACKUP.bwkSalt,
        },
        integrity: 'sig-from-download',
      },
      { unverified: 'leave' },
    );

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(screen.queryByText(CONFIRM_UNVERIFIED)).toBeNull();
    // Identical wrappers are one key, derived once: the common path did not pay
    // for a second 600k-iteration derivation.
    expect(cryptoService.deriveBEK).toHaveBeenCalledTimes(1);
    expect(cryptoService.verifyBackupHmac).toHaveBeenCalledTimes(1);
    const [signedPayload, signature, keyUsed] = vi.mocked(cryptoService.verifyBackupHmac).mock
      .calls[0]!;
    expect(signature).toBe('sig-from-download');
    expect(signedPayload).not.toContain('integrity');
    expect(keyUsed).toBe(ACCOUNT_BWK);
  });

  it('checks a signature against the ACCOUNT’s key before the file’s own, never after', async () => {
    // The finding: preferring the file's own block let anyone handing you a file
    // plus "its" backup password supply the message AND the key that
    // authenticates it. The order is the control, so it is asserted directly.
    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
      integrity: 'sig',
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    const firstKeyTried = vi.mocked(cryptoService.verifyBackupHmac).mock.calls[0]?.[2];
    expect(firstKeyTried).toBe(ACCOUNT_BWK);
    expect(firstKeyTried).not.toBe(FILE_BWK);
  });

  it('asks before restoring a file whose signature only its OWN key could check', async () => {
    // A foreign backup: the account's key disagrees, the file's own agrees. The
    // signature is real and proves only that the file agrees with itself, so the
    // restore is offered rather than refused — and offered, not performed.
    vi.mocked(cryptoService.verifyBackupHmac).mockImplementation((_data, _hmac, bwk) =>
      Promise.resolve(bwk === FILE_BWK),
    );

    await performRestore(
      {
        items: [SAMPLE_ITEM],
        folders: [],
        backupEncryption: FILE_ENCRYPTION_META,
        integrity: 'signed-by-the-other-account',
      },
      { unverified: 'leave' },
    );

    expect(screen.getByText(CONFIRM_UNVERIFIED)).toBeInTheDocument();
    expect(
      screen.getByText(/could only be checked against key material the file itself/),
    ).toBeInTheDocument();
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('opens the file’s own wrapped vault key with the FILE’s key, not the account’s', async () => {
    // The two unwrapped keys have different jobs. `bwkEncryptedVaultKey` lives in
    // the file and is sealed under the FILE's key by construction, so plumbing
    // the account's key here would fail to recover the backup's vault key and
    // drop every row of a legitimate cross-account restore behind a warning.
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('MEK mismatch'));
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(cryptoService.decryptVaultKeyWithBWK).toHaveBeenCalledTimes(1);
    const [wrapped, wrappedIv, wrappedTag, keyUsed] = vi.mocked(
      cryptoService.decryptVaultKeyWithBWK,
    ).mock.calls[0]!;
    expect([wrapped, wrappedIv, wrappedTag]).toEqual(['file-bevk', 'file-bvkiv', 'file-bvktag']);
    // Identity, not equality: the two stand-ins are the same length and Vitest
    // would call them equal. See the note beside their declarations.
    expect(keyUsed).toBe(FILE_BWK);
    expect(keyUsed).not.toBe(ACCOUNT_BWK);
    // ...and the rows survived, which is what the wrong key would have cost.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: expect.stringContaining('Could not recover') }),
    );
  });

  it('still offers the restore when the profile cannot be read but the file carries a wrapper', async () => {
    // The profile read is the TRUST ANCHOR and is unconditional now. A profile
    // that will not load costs the restore its anchor — answered by the prompt —
    // and must not cost it the restore itself, which it did not before.
    mockGetProfileApi
      .mockResolvedValueOnce(profileWith(CONFIGURED_BACKUP))
      .mockRejectedValueOnce(new Error('network down'));

    await performRestore(
      { items: [SAMPLE_ITEM], folders: [], backupEncryption: FILE_ENCRYPTION_META },
      { unverified: 'leave' },
    );

    expect(screen.getByText(CONFIRM_UNVERIFIED)).toBeInTheDocument();
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to restore backup' }),
    );
  });

  it('reports a key-derivation failure as a failure, never as a wrong backup password', async () => {
    // `deriveBEK` throwing is Web Crypto refusing, or a hostile file's
    // unparseable salt. Only a wrapper that will not OPEN means a wrong password,
    // and conflating the two would tell a user to retype a correct password.
    vi.mocked(cryptoService.deriveBEK).mockRejectedValue(new Error('SubtleCrypto unavailable'));

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Failed to restore backup' }),
      );
    });
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Incorrect backup password' }),
    );
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('abandons a confirmed restore whose vault key changed while the prompt was open', async () => {
    // The answer has no time limit. A rotation in another tab does not unmount
    // this page, and every row below would be re-encrypted to the key captured
    // AFTER the answer — so the key is re-read rather than assumed.
    const rotatedKey = new Uint8Array(32) as unknown as CryptoKey;
    const { container } = await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));
    fireEvent.click(screen.getByText('Restore from File'));
    const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: {
        files: [
          new File(
            [
              JSON.stringify({
                items: [SAMPLE_ITEM],
                folders: [],
                backupEncryption: FILE_ENCRYPTION_META,
              }),
            ],
            'backup.enc',
            { type: 'application/json' },
          ),
        ],
      },
    });
    fireEvent.change(container.querySelector('#restore-password') as HTMLInputElement, {
      target: { value: 'BackupPass!' },
    });
    await act(async () => {
      fireEvent.click(screen.getByText('Restore'));
    });

    useAuthStore.setState({ vaultKey: rotatedKey });
    await act(async () => {
      fireEvent.click(screen.getByText(CONFIRM_UNVERIFIED));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Your vault key changed while the restore was waiting to be confirmed.',
        }),
      );
    });
    expect(mockApiPost).not.toHaveBeenCalledWith('/backup/restore', expect.anything());
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

  it('re-encrypts a restored row without altering one byte of its plaintext', async () => {
    // The cross-key restore loop is the ONE restore path that touches the decrypted
    // blob at all: it decrypts every row and re-encrypts it under this account's key.
    // The assertion is on the EXACT argument handed to `encryptData`, so a future
    // "helpful" reshape (re-parse, re-serialize, strip unknown keys) fails here rather
    // than silently dropping whichever field that build does not know about. The
    // payload names the two new address fields to make the intent concrete.
    const PLAINTEXT = JSON.stringify({
      firstName: 'Ada',
      address: {
        street: '1 Main St',
        street2: 'Flat 2',
        city: 'London',
        state: '',
        zip: 'E1',
        country: 'UK',
        deliveryNotes: 'Ring twice',
      },
    });
    // The same arrangement as the cross-account case above, which is what actually
    // puts the restore on its re-encrypting path.
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('MEK mismatch'));
    vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(false);
    vi.mocked(cryptoService.decryptData).mockResolvedValue(PLAINTEXT);

    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'vkiv',
      vaultKeyTag: 'vktag',
      backupEncryption: FILE_ENCRYPTION_META,
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
    });
    expect(cryptoService.encryptData).toHaveBeenCalledWith(PLAINTEXT, expect.anything());
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
  // The backup boundary: documents are not in a backup, and the user is told
  // =========================================================================
  //
  // A restore that returns every item and folder looks complete. If the account
  // it was taken from held documents, it is not — their bytes were never in the
  // file, and no amount of restoring will bring them back. The server writes a
  // `documentSummary` breadcrumb into the payload for exactly this moment, and
  // these cases pin that the notice is raised from it, that it is raised
  // ALONGSIDE the ordinary result rather than instead of it, and that it stays
  // silent when there is nothing to say.

  it('warns that the backup account held documents, alongside the ordinary success notice', async () => {
    await performRestore({
      items: [SAMPLE_ITEM],
      folders: [],
      backupEncryption: FILE_ENCRYPTION_META,
      documentSummary: { count: 3, totalBytes: 4096 },
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title:
          'This backup was taken from an account holding 3 document(s); documents are not part of a backup.',
        description: 'Re-upload them from the Documents page to restore them.',
        type: 'warning',
      });
    });
    // ALONGSIDE, not instead of: the restore itself still reports its outcome,
    // so a user does not have to infer success from the absence of an error.
    expect(mockToast).toHaveBeenCalledWith({
      title: 'Backup restored successfully',
      type: 'success',
    });
    // …and LAST, so it is the notice sitting on top of the stack rather than the
    // one buried under a green success message.
    const titles = mockToast.mock.calls.map((call) =>
      String((call[0] as { title?: unknown }).title),
    );
    expect(titles.at(-1)).toContain('documents are not part of a backup');
    // And the restore really happened.
    expect(mockApiPost).toHaveBeenCalledWith('/backup/restore', expect.anything());
  });

  it('says nothing about documents when the summary is zero or absent', async () => {
    // The two payload shapes that must stay quiet: a server that has the feature
    // reporting an account with no documents, and a pre-0.10.0 server that has no
    // field at all. Interrupting either would train users to dismiss the notice
    // that matters.
    for (const extra of [{ documentSummary: { count: 0, totalBytes: 0 } }, {}]) {
      vi.clearAllMocks();
      await performRestore({
        items: [SAMPLE_ITEM],
        folders: [],
        backupEncryption: FILE_ENCRYPTION_META,
        ...extra,
      });

      await waitFor(() => {
        expect(mockToast).toHaveBeenCalledWith({
          title: 'Backup restored successfully',
          type: 'success',
        });
      });
      expect(
        mockToast.mock.calls.some((call) =>
          String((call[0] as { title?: unknown }).title).includes('documents are not part of a'),
        ),
      ).toBe(false);
      cleanup();
    }
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

  /**
   * Both of these endpoints store the account's VAULT KEY, wrapped under the
   * backup key — the copy a cross-account restore unwraps. The server refuses
   * either unless the request says which vault key it sealed, so a session on a
   * superseded generation cannot silently replace the re-wrap a rotation
   * performed. The number must come from the SAME `getState()` read as the key.
   */
  it('names the vault-key generation when it configures backup encryption', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));

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
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ vaultKeyVersion: 7 }),
      );
    });
    // And the wrapper it guards really is in the same body, so this is not a
    // number attached to a request that seals nothing.
    const body = mockApiPost.mock.calls.find((call) => call[0] === '/backup/setup')?.[1] as Record<
      string,
      unknown
    >;
    expect(body.bwkEncryptedVaultKey).toBeDefined();
  });

  it('names the vault-key generation when it re-keys backup encryption', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));

    fireEvent.click(screen.getByText('Change backup encryption password'));

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
      expect(mockApiPut).toHaveBeenCalledWith(
        '/backup/change-password',
        expect.objectContaining({ vaultKeyVersion: 7 }),
      );
    });
    const body = mockApiPut.mock.calls.find(
      (call) => call[0] === '/backup/change-password',
    )?.[1] as Record<string, unknown> | undefined;
    expect(body?.newBwkEncryptedVaultKey).toBeDefined();
  });

  it('names the generation even when this session holds no key and the wrapper is CLEARED', async () => {
    // The `$unset` branch: a body with no wrapper triple clears the stored one,
    // which is how a client legitimately drops a wrapper a rotation superseded.
    // It is the same guarded address, so it carries the generation too — and the
    // guard must not be decided from which fields the body happens to carry.
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));

    useAuthStore.setState({ vaultKey: null });

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
      expect(mockApiPost).toHaveBeenCalledWith(
        '/backup/setup',
        expect.objectContaining({ vaultKeyVersion: 7 }),
      );
    });
    const body = mockApiPost.mock.calls.find((call) => call[0] === '/backup/setup')?.[1] as Record<
      string,
      unknown
    >;
    expect(body).not.toHaveProperty('bwkEncryptedVaultKey');
  });

  /**
   * The refusal has to REACH the user, and on this page nothing else can tell
   * them: `authStore.vaultKeyVersion` is never refreshed here, so a naive retry
   * resends the same stale number for ever. The restore driver on this same page
   * already raises the app-wide notice; these two now do too.
   */
  it('raises the reload notice when backup setup is refused for a superseded key', async () => {
    mockGetProfileApi.mockResolvedValue(
      profileWith({ enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false }),
    );
    await renderBackup();
    await waitFor(() => screen.getByPlaceholderText('Backup encryption password'));
    expect(useUIStore.getState().staleVaultKeyVersion).toBeNull();

    mockApiPost.mockRejectedValueOnce(staleVaultKeyRejection());
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
      // The NUMBER the server reported, not a boolean: the banner is DERIVED by
      // comparing it against this session's own generation, so a re-login or a
      // rotation driven here clears it with nothing to remember.
      expect(useUIStore.getState().staleVaultKeyVersion).toBe(9);
    });
    // And the server's own sentence reaches the user rather than a generic one.
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Failed to setup backup encryption',
        description: expect.stringMatching(/rotated elsewhere/i) as unknown as string,
        type: 'error',
      }),
    );
  });

  it('raises the reload notice when a backup re-key is refused for a superseded key', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Change backup encryption password'));
    expect(useUIStore.getState().staleVaultKeyVersion).toBeNull();

    mockApiPut.mockRejectedValueOnce(staleVaultKeyRejection());
    fireEvent.click(screen.getByText('Change backup encryption password'));
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
      expect(useUIStore.getState().staleVaultKeyVersion).toBe(9);
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Failed to change backup password',
        description: expect.stringMatching(/rotated elsewhere/i) as unknown as string,
        type: 'error',
      }),
    );
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

/**
 * The three controls on this page that reached a screen reader unnamed.
 *
 * All three are `test:a11y`'s `backup-settings` view now, which is what found
 * them — but that gate needs a container, a dev server and two 600k-iteration
 * key derivations, so the accessible names are pinned here as well, where they
 * cost milliseconds. The queries below are by ROLE AND NAME, which is the point:
 * `getByRole('switch', { name: 'Auto-backup' })` cannot pass unless the browser's
 * accessible-name computation produces that string, so deleting the
 * `aria-labelledby`, dropping the `id` it points at, or replacing the `<label
 * htmlFor>` with the `<span>` that used to sit there each turns one of them red.
 */
describe('BackupSettingsPage — every control has an accessible name', () => {
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
      if (url === '/backup/history')
        return Promise.resolve({
          data: {
            success: true,
            data: [],
            pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
          },
        });
      return Promise.resolve({ data: {} });
    });
  });

  it('names the auto-backup switch from the words already on screen', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Auto-backup'));

    const toggle = screen.getByRole('switch', { name: 'Auto-backup' });
    // Its content is a sliding knob, so there is nothing else the name could
    // come from — and the description must reach the reader too, because the
    // words "daily via email" are the only place the schedule is explained.
    expect(toggle).toHaveAccessibleDescription('Send encrypted backup daily via email');
    // The state, which is the other half of a switch's contract: a control that
    // is named but never reports on/off is no more usable than an unnamed one.
    expect(toggle).toHaveAttribute('aria-checked', 'true');
  });

  it('names the schedule-hour field, which has no placeholder to fall back on', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Backup Configuration'));

    // `getByLabelText`, not a `container.querySelector`: this is the one field
    // on the page with neither a label nor a placeholder, so before the fix
    // there was no accessible name for any query to match.
    const hour = screen.getByLabelText('Schedule (UTC hour)');
    expect(hour).toHaveAttribute('type', 'number');
    // The profile's `scheduleHour`, so the label is proved to be attached to the
    // field that actually carries the setting rather than to some other spinner.
    // `CONFIGURED_BACKUP` is a `Record<string, unknown>` by design, so the value
    // is narrowed here rather than the fixture being retyped for one assertion.
    expect(hour).toHaveValue(Number(CONFIGURED_BACKUP['scheduleHour']));
  });

  it('names the restore file picker, whose label used to be a mere sibling', async () => {
    await renderBackup();
    await waitFor(() => screen.getByText('Restore from File'));
    fireEvent.click(screen.getByText('Restore from File'));

    const picker = screen.getByLabelText('Backup File');
    expect(picker).toHaveAttribute('type', 'file');
    expect(picker).toHaveAttribute('accept', '.enc');
  });
});
