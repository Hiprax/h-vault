/**
 * The Backup page's full backup (0.22.0): the "What each option does" list, the
 * Full Backup button and panel, and a full backup's restore through the SAME
 * Restore form.
 *
 * The engines themselves are pinned by `full-backup-create.test.ts` and
 * `full-backup-restore.test.ts`; here they are stand-ins behind the page's ONE lazy
 * loader, so each case can say what the page does with what they answer: which
 * file a restore takes which path for, which signature check it uses, when keys and
 * the password are let go, and that nothing runs twice.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
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

const {
  mockGetProfileApi,
  mockToast,
  mockApiGet,
  mockApiPost,
  mockUsage,
  mockLoadJob,
  job,
  docsConfig,
} = vi.hoisted(() => {
  class FormatError extends Error {}
  return {
    mockGetProfileApi: vi.fn(),
    mockToast: vi.fn(),
    mockApiGet: vi.fn(),
    mockApiPost: vi.fn(),
    mockUsage: vi.fn(),
    mockLoadJob: vi.fn(),
    job: {
      createFullBackup: vi.fn(),
      openFullBackupTarget: vi.fn(),
      hasSaveDialog: vi.fn(),
      deriveFullBackupSigningKey: vi.fn(),
      openFullBackupFile: vi.fn(),
      verifyFullBackupManifest: vi.fn(),
      restoreFullBackupDocuments: vi.fn(),
      FullBackupFormatError: FormatError,
    },
    docsConfig: { current: { enabled: true } as { enabled: boolean } | null },
  };
});

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
    importVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    vaultKeyEqualsRaw: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    decryptDataWithAad: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
    deriveBEK: vi.fn(),
    decryptBWK: vi.fn(),
    decryptVaultKeyWithBWK: vi.fn(),
    computeBackupHmac: vi.fn(),
    verifyBackupHmac: vi.fn(),
    base64ToArrayBuffer: vi.fn(),
    arrayBufferToBase64: vi.fn().mockReturnValue('b64'),
  },
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
}));

vi.mock('../src/services/api/documentsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/api/documentsApi')>()),
  getDocumentUsageApi: () => mockUsage(),
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: (...args: unknown[]) => mockApiGet(...args),
    post: (...args: unknown[]) => mockApiPost(...args),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    defaults: { headers: { common: {} } },
  },
}));

vi.mock('../src/services/backup/loadFullBackupJob', () => ({
  loadFullBackupJob: () => mockLoadJob(),
}));

vi.mock('../src/hooks/useDocumentsConfig', () => ({
  useDocumentsConfig: () => docsConfig.current,
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

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: () =>
    Promise.resolve(() => ({ score: 4, feedback: { warning: '', suggestions: [] } })),
}));

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useDocumentsStore } from '../src/stores/documentsStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { FULL_BACKUP_MAGIC } from '../src/services/backup/fullBackupMagic';
import type { DocumentRestoreReport } from '../src/services/backup/restoreFullBackupDocuments';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BACKUP_BLOCK = {
  encryptedBWK: 'account-ebwk',
  bwkIv: 'account-biv',
  bwkTag: 'account-btag',
  bwkSalt: 'account-bsalt',
};

/** The unwrapped backup wrapping key, compared BY IDENTITY (see the coverage suite). */
const BWK = new Uint8Array([0xb0, 0xb1]).buffer;
const SIGNING_KEY = { kind: 'signing-key' } as unknown as CryptoKey;
const BACKUP_VAULT_KEY = { kind: 'backup-vault-key' } as unknown as CryptoKey;
const LIVE_VAULT_KEY = { kind: 'live-vault-key' } as unknown as CryptoKey;

function profile(settings: Record<string, unknown> = {}) {
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
          theme: 'system',
          lockOnHidden: false,
          backup: {
            enabled: false,
            scheduleHour: 3,
            backupRecipients: [],
            isConfigured: true,
            ...BACKUP_BLOCK,
          },
          ...settings,
        },
      },
    },
  };
}

const SAVED = {
  saved: true as const,
  fileName: 'hvault-full-backup-2026-10-23.hvbackup',
  kind: 'file' as const,
  bytes: 2048,
  itemCount: 3,
  folderCount: 1,
  documentCount: 2,
  leftOut: [
    { name: 'broken.pdf', reason: 'It could not be read and verified, so it was left out.' },
  ],
  unlisted: 1,
};

function report(overrides: Partial<DocumentRestoreReport> = {}): DocumentRestoreReport {
  return {
    total: 2,
    uploaded: 2,
    restoredFromTrash: 0,
    updated: 0,
    alreadyPresent: 0,
    notRestored: [],
    notAttempted: 0,
    notes: [],
    missingFromBackup: 0,
    leftOutOfBackup: 0,
    ...overrides,
  };
}

/** A file whose first bytes are a full backup's magic. */
function fullBackupFile(): File {
  return new File([new Uint8Array([...FULL_BACKUP_MAGIC, 0, 0, 0, 1, 0, 0, 0, 0])], 'b.hvbackup');
}

/**
 * A full backup as the reader hands it over. A FRESH one per call: the page
 * restores the vault part the way it always restored a vault backup, deleting
 * the fields the server never takes from that very object.
 */
function openedBackup() {
  return {
    manifest: {
      vault: {
        items: [
          {
            _id: 'aaaaaaaaaaaaaaaaaaaaaaaa',
            itemType: 'login',
            encryptedData: 'd',
            dataIv: 'di',
            dataTag: 'dt',
            encryptedName: 'n',
            nameIv: 'ni',
            nameTag: 'nt',
          },
        ],
        folders: [],
        encryptedVaultKey: 'evk',
        vaultKeyIv: 'vki',
        vaultKeyTag: 'vkt',
        backupEncryption: { ...BACKUP_BLOCK },
        documentSummary: { count: 2 },
      },
      documents: [],
      omitted: [],
      unlisted: 0,
    },
    signature: 'f'.repeat(64),
    signedPayload: '{"signed":true}',
    readSegment: vi.fn(),
  };
}
type OpenedBackup = ReturnType<typeof openedBackup>;

/** The backup the reader handed the page in this case. */
async function lastOpened(): Promise<OpenedBackup> {
  return (await job.openFullBackupFile.mock.results.at(-1)?.value) as OpenedBackup;
}

const FOLDER_MAP = [{ backupId: 'cccccccccccccccccccccccc', folderId: 'dddddddddddddddddddddddd' }];

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
  await waitFor(() => screen.getByText('Restore from File'));
  return result!;
}

function historyReads(): number {
  return mockApiGet.mock.calls.filter(([url]) => url === '/backup/history').length;
}

async function openPanelAndContinue(password = 'BackupPass!') {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Full Backup' }));
  });
  fireEvent.change(screen.getByLabelText('Backup password for the full backup'), {
    target: { value: password },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  });
}

async function startRestore(file: File, strategy?: 'overwrite') {
  const { container } = { container: document.body };
  fireEvent.click(screen.getByText('Restore from File'));
  const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(fileInput, { target: { files: [file] } });
  fireEvent.change(container.querySelector('#restore-password') as HTMLInputElement, {
    target: { value: 'BackupPass!' },
  });
  if (strategy) fireEvent.click(screen.getByDisplayValue(strategy));
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
  });
}

function restorePostCount(): number {
  return mockApiPost.mock.calls.filter(([url]) => url === '/backup/restore').length;
}

beforeEach(() => {
  vi.clearAllMocks();
  docsConfig.current = { enabled: true };
  useAuthStore.setState({
    accessToken: 'test-token',
    user: { userId: 'u1', email: 'test@example.com' },
    isAuthenticated: true,
    isLocked: false,
    vaultKey: LIVE_VAULT_KEY,
    mek: { kind: 'mek' } as unknown as CryptoKey,
    vaultKeyVersion: 7,
  });
  useVaultStore.setState({
    fetchFolders: vi.fn().mockResolvedValue(undefined),
    fetchItems: vi.fn().mockResolvedValue(undefined),
  });

  mockLoadJob.mockResolvedValue(job);
  job.hasSaveDialog.mockReturnValue(true);
  job.deriveFullBackupSigningKey.mockResolvedValue(SIGNING_KEY);
  job.openFullBackupTarget.mockResolvedValue({ kind: 'file', name: 'x', limitBytes: 1 });
  job.createFullBackup.mockResolvedValue(SAVED);
  job.openFullBackupFile.mockImplementation(() => Promise.resolve(openedBackup()));
  job.verifyFullBackupManifest.mockResolvedValue(true);
  job.restoreFullBackupDocuments.mockResolvedValue(report());

  mockGetProfileApi.mockResolvedValue(profile());
  mockUsage.mockResolvedValue({
    data: {
      success: true,
      data: {
        documentCount: 2,
        usedBytes: 3 * 1024 * 1024,
        quotaBytes: 1e12,
        maxDocumentSizeBytes: 1e9,
      },
    },
  });
  mockApiGet.mockImplementation((url: string) =>
    Promise.resolve(
      url === '/backup/history'
        ? {
            data: {
              success: true,
              data: [],
              pagination: { page: 1, limit: 10, total: 0, totalPages: 1 },
            },
          }
        : { data: {} },
    ),
  );
  mockApiPost.mockResolvedValue({
    data: {
      success: true,
      data: {
        itemsRestored: 1,
        itemsSkipped: 0,
        foldersRestored: 0,
        foldersSkipped: 0,
        itemSkipReasons: [],
        folderSkipReasons: [],
        folderIdMap: FOLDER_MAP,
      },
    },
  });

  vi.mocked(cryptoService.base64ToArrayBuffer).mockReturnValue(new Uint8Array(16).buffer);
  vi.mocked(cryptoService.deriveBEK).mockResolvedValue({} as CryptoKey);
  vi.mocked(cryptoService.decryptBWK).mockResolvedValue(BWK);
  vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new Uint8Array(32).buffer);
  vi.mocked(cryptoService.importVaultKey).mockResolvedValue(BACKUP_VAULT_KEY);
  vi.mocked(cryptoService.vaultKeyEqualsRaw).mockResolvedValue(true);
  vi.mocked(cryptoService.decryptData).mockResolvedValue('{}');
});

// ---------------------------------------------------------------------------

describe('Backup Configuration explains every option', () => {
  it('lists what each control does, each line its own sentence that names the control first', async () => {
    await renderBackup();
    const guide = screen.getByTestId('backup-options-guide');
    const lines = within(guide)
      .getAllByRole('listitem')
      .map((li) => li.textContent);
    expect(lines.map((line) => line?.split(' ').slice(0, 2).join(' '))).toEqual([
      'Save Settings',
      'Backup Now,',
      'Download Latest',
      'Full Backup',
      'Settings, backup',
      'Save Recipients',
      'Change Backup',
      'Restore from',
      'Browsers without',
    ]);
    expect(lines.join(' ')).toContain('Documents are never emailed.');
    expect(lines.join(' ')).toContain('Documents in the trash are left out.');
    // Each line is ONE text node, so an exact query still finds only the button.
    expect(screen.getAllByText('Download Latest')).toHaveLength(1);
    expect(screen.getAllByText('Full Backup')).toHaveLength(1);
    // The restore dialog bolds "Overwrite"; the list never names it that way.
    expect(lines.some((line) => line?.includes('Overwrite'))).toBe(false);
  });
});

describe('the Full Backup button', () => {
  it('is held, with the reason said, when this server stores no documents', async () => {
    docsConfig.current = { enabled: false };
    await renderBackup();
    expect(screen.getByRole('button', { name: 'Full Backup' })).toBeDisabled();
    expect(
      screen.getByText(/Full Backup needs a server that stores documents/),
    ).toBeInTheDocument();
  });

  it('is held, saying nothing yet, until the server has answered', async () => {
    docsConfig.current = null;
    await renderBackup();
    expect(screen.getByRole('button', { name: 'Full Backup' })).toBeDisabled();
    expect(screen.queryByText(/Full Backup needs a server that stores documents/)).toBeNull();
  });

  it('is held until backup encryption is set up', async () => {
    mockGetProfileApi.mockResolvedValue(
      profile({
        backup: { enabled: false, scheduleHour: 3, backupRecipients: [], isConfigured: false },
      }),
    );
    await renderBackup();
    expect(screen.getByRole('button', { name: 'Full Backup' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Full Backup' })).toHaveAttribute(
      'title',
      'Set up backup encryption first',
    );
  });

  it('never shows its panel beside the download prompt', async () => {
    await renderBackup();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Download Latest' }));
    });
    expect(screen.getByPlaceholderText('Backup password')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Full Backup' }));
    });
    expect(screen.getByTestId('full-backup-panel')).toBeInTheDocument();
    expect(screen.getAllByPlaceholderText('Backup password')).toHaveLength(1);
    expect(screen.getByLabelText('Backup password for the full backup')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Download Latest' }));
    });
    expect(screen.queryByTestId('full-backup-panel')).toBeNull();
    expect(screen.getByPlaceholderText('Backup password')).not.toHaveAttribute('aria-label');
  });
});

describe('the Full Backup panel', () => {
  it('derives the signing key, zeroes the wrapping key and clears the password at Continue', async () => {
    let zeroedBeforeEstimate = false;
    mockUsage.mockImplementation(() => {
      // The estimate's request can hang; the wrapping key must not wait for it.
      zeroedBeforeEstimate = vi
        .mocked(cryptoService.clearKey)
        .mock.calls.some(([buffer]) => buffer === BWK);
      return Promise.resolve({
        data: {
          success: true,
          data: {
            documentCount: 2,
            usedBytes: 3 * 1024 * 1024,
            quotaBytes: 1e12,
            maxDocumentSizeBytes: 1e9,
          },
        },
      });
    });
    await renderBackup();
    await openPanelAndContinue();
    expect(zeroedBeforeEstimate).toBe(true);

    expect(job.deriveFullBackupSigningKey).toHaveBeenCalledTimes(1);
    expect(job.deriveFullBackupSigningKey.mock.calls[0]?.[0]).toBe(BWK);
    const zeroed = vi.mocked(cryptoService.clearKey).mock.calls.map(([buffer]) => buffer);
    expect(zeroed).toContain(BWK);
    expect(screen.getByText(/Your documents take up to 3 MB/)).toBeInTheDocument();
    expect(screen.getByText(/this tab will not lock by itself/)).toBeInTheDocument();
    expect(screen.queryByText(/no save dialog/)).toBeNull();
    expect(screen.queryByText(/locks when this tab stays hidden/)).toBeNull();
    expect(screen.queryByLabelText('Backup password for the full backup')).toBeNull();
    // Zeroed exactly once: the `finally` does not zero it a second time.
    expect(
      vi.mocked(cryptoService.clearKey).mock.calls.filter(([buffer]) => buffer === BWK),
    ).toHaveLength(1);
  });

  it('refuses a wrong backup password, deriving nothing and keeping no password', async () => {
    vi.mocked(cryptoService.decryptBWK).mockRejectedValue(new Error('bad tag'));
    await renderBackup();
    await openPanelAndContinue('wrong');

    expect(mockToast).toHaveBeenCalledWith({ title: 'Incorrect backup password', type: 'error' });
    expect(job.deriveFullBackupSigningKey).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Backup password for the full backup')).toHaveValue('');
    expect(screen.queryByRole('button', { name: /Save full backup/ })).toBeNull();
  });

  it('warns about the in-memory limit and the hidden-tab lock where they apply', async () => {
    job.hasSaveDialog.mockReturnValue(false);
    mockGetProfileApi.mockResolvedValue(profile({ lockOnHidden: true }));
    mockUsage.mockRejectedValue(new Error('offline'));
    await renderBackup();
    await openPanelAndContinue();

    expect(
      screen.getByText(/no save dialog, so the backup is built in memory/),
    ).toBeInTheDocument();
    expect(screen.getByText(/locks when this tab stays hidden/)).toBeInTheDocument();
    expect(screen.queryByText(/Your documents take up to/)).toBeNull();
    expect(screen.getByRole('button', { name: /Save full backup/ })).toBeInTheDocument();
  });

  it('says why it could not prepare, when the full backup code does not load', async () => {
    mockLoadJob.mockRejectedValue(
      new Error('Part of H-Vault needed for full backups did not load.'),
    );
    await renderBackup();
    await openPanelAndContinue();
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Could not prepare the full backup',
        description: 'Part of H-Vault needed for full backups did not load.',
      }),
    );
    expect(cryptoService.decryptBWK).not.toHaveBeenCalled();
  });

  it('opens the save dialog on the Save click itself, then saves and reports the file', async () => {
    await renderBackup();
    // Nothing to say yet: the always-mounted region is out of sight.
    await openPanelAndContinue();
    expect(screen.getByTestId('full-backup-status')).toHaveClass('sr-only');
    // The password field is gone; the focus is on the next step's one control.
    expect(screen.getByRole('button', { name: /Save full backup/ })).toHaveFocus();
    const readsBefore = historyReads();

    let settleRun: (value: typeof SAVED) => void = () => {};
    job.createFullBackup.mockReturnValue(
      new Promise((resolve) => {
        settleRun = resolve;
      }),
    );
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    // Synchronously, within the click: the dialog needs the click's activation.
    expect(job.openFullBackupTarget).toHaveBeenCalledTimes(1);

    await waitFor(() => expect(job.createFullBackup).toHaveBeenCalledTimes(1));
    expect(job.createFullBackup.mock.calls[0]?.[1]).toMatchObject({ signingKey: SIGNING_KEY });
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent(
      'Making a full backup. Keep this page open until it finishes.',
    );
    expect(screen.getByRole('button', { name: 'Download Latest' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Full Backup' })).toBeDisabled();

    await act(async () => {
      settleRun(SAVED);
    });
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent(
      'Full backup saved as hvault-full-backup-2026-10-23.hvbackup (2 KB): 3 item(s), 1 folder(s) and 2 document(s).',
    );
    expect(screen.getByTestId('full-backup-status')).not.toHaveClass('sr-only');
    expect(
      within(screen.getByTestId('full-backup-left-out')).getByText('broken.pdf'),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/1 document row\(s\) the server listed could not be read/),
    ).toBeInTheDocument();
    expect(historyReads()).toBe(readsBefore + 1);
    expect(screen.getByRole('button', { name: 'Download Latest' })).toBeEnabled();

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByTestId('full-backup-panel')).toBeNull();
    // The control that had the focus went with the panel; it comes back here.
    expect(screen.getByRole('button', { name: 'Full Backup' })).toHaveFocus();
  });

  it('says backup encryption is not configured when the account no longer has it at Continue', async () => {
    mockGetProfileApi.mockResolvedValueOnce(profile()).mockResolvedValue(
      profile({
        backup: { enabled: false, scheduleHour: 3, backupRecipients: [], isConfigured: false },
      }),
    );
    await renderBackup();
    await openPanelAndContinue();
    expect(mockToast).toHaveBeenCalledWith({
      title: 'Backup encryption is not configured',
      type: 'error',
    });
    expect(cryptoService.decryptBWK).not.toHaveBeenCalled();
    expect(job.deriveFullBackupSigningKey).not.toHaveBeenCalled();
  });

  it('drops the file, unwritten, when the page goes away while the save dialog is open', async () => {
    let openTarget: (target: unknown) => void = () => {};
    job.openFullBackupTarget.mockReturnValue(
      new Promise((resolve) => {
        openTarget = resolve;
      }),
    );
    const { unmount } = await renderBackup();
    await openPanelAndContinue();
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    unmount();
    const discard = vi.fn().mockResolvedValue(undefined);
    await act(async () => {
      openTarget({
        kind: 'file',
        name: 'x',
        limitBytes: 1,
        write: vi.fn(),
        commit: vi.fn(),
        discard,
      });
    });
    expect(discard).toHaveBeenCalledTimes(1);
    expect(job.createFullBackup).not.toHaveBeenCalled();
  });

  it('counts down a pause the server asked for while the backup runs', async () => {
    job.createFullBackup.mockImplementation(
      (_target: unknown, options: { onProgress: (p: unknown) => void }) => {
        options.onProgress({ phase: 'vault', waitUntil: Date.now() + 30_000 });
        return new Promise(() => {});
      },
    );
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(screen.getByTestId('full-backup-current')).toHaveTextContent('Downloading your vault…');
    expect(screen.getByText(/as the server asked/)).toBeInTheDocument();
  });

  it('says where a backup handed to the browser’s downloads went', async () => {
    job.createFullBackup.mockResolvedValue({
      ...SAVED,
      kind: 'download',
      leftOut: [],
      unlisted: 0,
    });
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent(
      "Full backup handed to your browser's downloads as hvault-full-backup-2026-10-23.hvbackup",
    );
    expect(screen.getByText(/its downloads list shows where it went/)).toBeInTheDocument();
    expect(screen.queryByTestId('full-backup-left-out')).toBeNull();
  });

  it('closes a Stop question still open when the run ends by itself', async () => {
    let finish: (value: typeof SAVED) => void = () => {};
    job.createFullBackup.mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    fireEvent.click(screen.getByRole('button', { name: 'Stop' }));
    expect(screen.getByRole('dialog', { name: 'Stop the full backup?' })).toBeInTheDocument();
    await act(async () => {
      finish(SAVED);
    });
    expect(screen.queryByRole('dialog', { name: 'Stop the full backup?' })).toBeNull();
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent('Full backup saved as');
  });

  it('starts nothing when the save dialog is dismissed, and can be saved again', async () => {
    job.openFullBackupTarget.mockResolvedValueOnce(null);
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(job.createFullBackup).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(job.createFullBackup).toHaveBeenCalledTimes(1);
  });

  it('runs once for a double press on Save', async () => {
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      const save = screen.getByRole('button', { name: /Save full backup/ });
      fireEvent.click(save);
      fireEvent.click(save);
    });
    expect(job.openFullBackupTarget).toHaveBeenCalledTimes(1);
    expect(job.createFullBackup).toHaveBeenCalledTimes(1);
  });

  it('stops only after the Stop is confirmed, then says nothing was saved and offers a retry', async () => {
    await renderBackup();
    await openPanelAndContinue();
    job.createFullBackup.mockImplementation(
      (_target: unknown, options: { signal: AbortSignal; onProgress: (p: unknown) => void }) => {
        options.onProgress({
          phase: 'documents',
          index: 2,
          total: 4,
          name: 'scan.pdf',
          bytesRead: 1024,
        });
        return new Promise((resolve) => {
          options.signal.addEventListener('abort', () =>
            resolve({ saved: false, stop: 'stopped', message: 'You stopped it.' }),
          );
        });
      },
    );
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(screen.getByTestId('full-backup-current')).toHaveTextContent(
      'Reading document 2 of 4: scan.pdf (1 KB read so far)',
    );
    expect(screen.getByRole('progressbar', { name: 'Full backup progress' })).toHaveAttribute(
      'aria-valuenow',
      '1',
    );

    fireEvent.click(screen.getByRole('button', { name: 'Stop' }));
    fireEvent.click(screen.getByRole('button', { name: 'Keep going' }));
    const signal = (job.createFullBackup.mock.calls[0]?.[1] as { signal: AbortSignal }).signal;
    expect(signal.aborted).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Stop' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Stop backup' }));
    });
    expect(signal.reason).toBe('stopped');
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent(
      'You stopped it. Nothing was saved.',
    );
    expect(
      screen.getByText(
        'If it got as far as downloading your vault, Backup History lists that download.',
      ),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(screen.getByLabelText('Backup password for the full backup')).toBeInTheDocument();
  });

  it('reports a save dialog the browser refused, without starting a run', async () => {
    job.openFullBackupTarget.mockRejectedValueOnce(new Error('The browser refused the file.'));
    await renderBackup();
    await openPanelAndContinue();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    expect(job.createFullBackup).not.toHaveBeenCalled();
    expect(screen.getByTestId('full-backup-status')).toHaveTextContent(
      'The browser refused the file. Nothing was saved.',
    );
    // No run started, so there is no download to point at.
    expect(screen.queryByText(/Backup History lists that download/)).toBeNull();
  });

  it('ends a running backup when the page goes away, as left', async () => {
    const { unmount } = await renderBackup();
    await openPanelAndContinue();
    job.createFullBackup.mockReturnValue(new Promise(() => {}));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Save full backup/ }));
    });
    const signal = (job.createFullBackup.mock.calls[0]?.[1] as { signal: AbortSignal }).signal;
    unmount();
    expect(signal.reason).toBe('left');
  });
});

describe('restoring a full backup through the same form', () => {
  it('opens it with the full backup reader, checks its signature, and restores its vault, then its documents', async () => {
    await renderBackup();
    await startRestore(fullBackupFile());

    expect(job.openFullBackupFile).toHaveBeenCalledTimes(1);
    // Its own verifier, never the vault backup's.
    expect(job.verifyFullBackupManifest).toHaveBeenCalledWith(
      '{"signed":true}',
      'f'.repeat(64),
      BWK,
    );
    expect(cryptoService.verifyBackupHmac).not.toHaveBeenCalled();
    // The vault part went to the server as a vault backup always has.
    const body = mockApiPost.mock.calls.find(([url]) => url === '/backup/restore')?.[1] as {
      data: string;
      vaultKeyVersion: number;
    };
    const sent = JSON.parse(body.data) as Record<string, unknown>;
    expect(sent.items).toHaveLength(1);
    expect(sent).not.toHaveProperty('backupEncryption');
    expect(sent).not.toHaveProperty('encryptedVaultKey');
    expect(body.vaultKeyVersion).toBe(7);

    expect(job.restoreFullBackupDocuments).toHaveBeenCalledTimes(1);
    const options = job.restoreFullBackupDocuments.mock.calls[0]?.[0] as {
      backup: unknown;
      backupVaultKey: CryptoKey;
      folderIdMap: unknown;
      conflictStrategy: string;
    };
    expect(options.backup).toBe(await lastOpened());
    expect(options.backupVaultKey).toBe(BACKUP_VAULT_KEY);
    // The backup's vault key is let go of AFTER its documents were restored.
    const cleared = vi
      .mocked(cryptoService.clearCryptoKey)
      .mock.calls.findIndex(([key]) => key === BACKUP_VAULT_KEY);
    expect(cleared).toBeGreaterThanOrEqual(0);
    expect(
      vi.mocked(cryptoService.clearCryptoKey).mock.invocationCallOrder[cleared],
    ).toBeGreaterThan(job.restoreFullBackupDocuments.mock.invocationCallOrder[0]!);
    expect(options.folderIdMap).toEqual(FOLDER_MAP);
    expect(options.conflictStrategy).toBe('skip');
    // The rail learns the folders the documents are filed into.
    expect(useVaultStore.getState().fetchFolders).toHaveBeenCalled();

    expect(screen.getByTestId('document-restore-status')).toHaveTextContent(
      'Documents restored: 2 in the backup. 2 uploaded, 0 taken out of the trash, 0 updated, 0 already here.',
    );
    // The vault backup's "documents are not in a backup" notice is not raised.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({
        title: expect.stringContaining('documents are not part of a backup'),
      }),
    );
    // The form is reset once the documents are done, and the summary stays.
    expect(screen.queryByLabelText('Backup File')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByTestId('document-restore-status')).toBeNull();
  });

  it('lets go of the password and both wrapping keys before the documents are restored', async () => {
    let finishDocuments: (value: DocumentRestoreReport) => void = () => {};
    job.restoreFullBackupDocuments.mockReturnValue(
      new Promise((resolve) => {
        finishDocuments = resolve;
      }),
    );
    await renderBackup();
    await startRestore(fullBackupFile(), 'overwrite');

    // The documents are still being restored here.
    expect(screen.getByRole('button', { name: 'Stop restoring documents' })).toBeInTheDocument();
    expect(document.querySelector('#restore-password')).toHaveValue('');
    expect(vi.mocked(cryptoService.clearKey).mock.calls.map(([b]) => b)).toContain(BWK);
    await act(async () => {
      finishDocuments(report());
    });
    expect(
      (job.restoreFullBackupDocuments.mock.calls[0]?.[0] as { conflictStrategy: string })
        .conflictStrategy,
    ).toBe('overwrite');
    // Zeroed once, never a second time by the `finally`.
    expect(
      vi.mocked(cryptoService.clearKey).mock.calls.filter(([buffer]) => buffer === BWK),
    ).toHaveLength(1);
  });

  it('takes a full backup larger than a vault backup may be', async () => {
    const big = fullBackupFile();
    Object.defineProperty(big, 'size', { value: 300 * 1024 * 1024 });
    await renderBackup();
    await startRestore(big);
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Backup file too large' }),
    );
    expect(restorePostCount()).toBe(1);
  });

  it('never loads the full backup code for a vault backup', async () => {
    await renderBackup();
    const vaultBackup = new File(
      [JSON.stringify({ ...openedBackup().manifest.vault, backupEncryption: undefined })],
      'backup.enc',
    );
    await startRestore(vaultBackup);
    await act(async () => {
      const confirm = screen.queryByText('Restore Unverified Backup');
      if (confirm) fireEvent.click(confirm);
    });
    expect(mockLoadJob).not.toHaveBeenCalled();
    expect(job.restoreFullBackupDocuments).not.toHaveBeenCalled();
    expect(restorePostCount()).toBe(1);
  });

  it('refuses a file the reader refuses, sending nothing', async () => {
    job.openFullBackupFile.mockRejectedValue(
      new job.FullBackupFormatError(
        'This file is not a full backup this version of H-Vault can read: it is too short. Nothing was restored.',
      ),
    );
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Failed to restore backup',
        description:
          'This file is not a full backup this version of H-Vault can read: it is too short. Nothing was restored.',
      }),
    );
    expect(restorePostCount()).toBe(0);
    expect(cryptoService.decryptBWK).not.toHaveBeenCalled();
  });

  it('starts one restore for a double click', async () => {
    let finishRead: (value: OpenedBackup) => void = () => {};
    job.openFullBackupFile.mockReturnValue(
      new Promise((resolve) => {
        finishRead = resolve;
      }),
    );
    await renderBackup();
    fireEvent.click(screen.getByText('Restore from File'));
    fireEvent.change(document.querySelector('input[type="file"]') as HTMLInputElement, {
      target: { files: [fullBackupFile()] },
    });
    fireEvent.change(document.querySelector('#restore-password') as HTMLInputElement, {
      target: { value: 'BackupPass!' },
    });
    const restoreButton = screen.getByRole('button', { name: 'Restore' });
    await act(async () => {
      fireEvent.click(restoreButton);
      fireEvent.click(restoreButton);
    });
    await act(async () => {
      finishRead(openedBackup());
    });
    expect(job.openFullBackupFile).toHaveBeenCalledTimes(1);
    expect(restorePostCount()).toBe(1);
  });

  it('shows the documents phase as it runs, holds the form, and stops it on request', async () => {
    job.restoreFullBackupDocuments.mockImplementation(
      (options: { signal: AbortSignal; onProgress: (p: unknown) => void }) => {
        options.onProgress({
          index: 1,
          total: 2,
          name: 'passport.pdf',
          waitUntil: Date.now() + 30_000,
        });
        return new Promise((resolve) => {
          options.signal.addEventListener('abort', () =>
            resolve(
              report({
                uploaded: 0,
                notAttempted: 2,
                stopped: { stop: 'stopped', message: 'You stopped it.' },
              }),
            ),
          );
        });
      },
    );
    await renderBackup();
    await startRestore(fullBackupFile());

    expect(screen.getByTestId('document-restore-status')).toHaveTextContent(
      'Restoring document 1 of 2: passport.pdf',
    );
    expect(screen.getByTestId('document-restore-announcement')).toHaveTextContent(
      'Restoring the documents of a full backup. Keep this page open until it finishes.',
    );
    expect(screen.getByText(/as the server asked/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Stop restoring documents' }));
    });
    const signal = (job.restoreFullBackupDocuments.mock.calls[0]?.[0] as { signal: AbortSignal })
      .signal;
    expect(signal.reason).toBe('stopped');
    expect(screen.getByTestId('document-restore-status')).toHaveTextContent(
      'Restoring documents stopped: You stopped it. 0 uploaded, 0 taken out of the trash, 0 updated, 0 already here. 2 not reached; run the same restore again with Skip to finish.',
    );
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'warning', title: expect.stringContaining('stopped') }),
    );
    expect(screen.getByTestId('document-restore-announcement')).toHaveTextContent(
      'Restoring the documents of a full backup has ended.',
    );
  });

  it('shows the bytes sent of the document being uploaded', async () => {
    job.restoreFullBackupDocuments.mockImplementation(
      (options: { onProgress: (p: unknown) => void }) => {
        useDocumentsStore.setState({
          uploads: {
            'up-1': {
              id: 'up-1',
              fileName: 'passport.pdf',
              totalBytes: 2048,
              sentBytes: 1024,
              status: 'uploading',
            },
          },
        });
        options.onProgress({ index: 1, total: 2, name: 'passport.pdf', uploadId: 'up-1' });
        return new Promise(() => {});
      },
    );
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(screen.getByTestId('document-restore-status')).toHaveTextContent('1 KB of 2 KB sent');
    act(() => {
      useDocumentsStore.setState({ uploads: {} });
    });
    expect(screen.queryByText(/KB sent/)).toBeNull();
  });

  it('never starts the documents when the page went away while the vault part was being restored', async () => {
    let answerRestore: (value: unknown) => void = () => {};
    mockApiPost.mockImplementation((url: string) =>
      url === '/backup/restore'
        ? new Promise((resolve) => {
            answerRestore = resolve;
          })
        : Promise.resolve({ data: { success: true } }),
    );
    let signalAtStart: AbortSignal | null = null;
    job.restoreFullBackupDocuments.mockImplementation((options: { signal: AbortSignal }) => {
      signalAtStart = options.signal;
      return Promise.resolve(
        report({
          uploaded: 0,
          notAttempted: 2,
          stopped: { stop: 'left', message: 'You left the page.' },
        }),
      );
    });
    const { unmount } = await renderBackup();
    await startRestore(fullBackupFile());
    expect(restorePostCount()).toBe(1);
    unmount();
    await act(async () => {
      answerRestore({
        data: {
          success: true,
          data: {
            itemsRestored: 1,
            itemsSkipped: 0,
            foldersRestored: 0,
            foldersSkipped: 0,
            itemSkipReasons: [],
            folderSkipReasons: [],
            folderIdMap: FOLDER_MAP,
          },
        },
      });
    });
    // Aborted, as left, before the documents phase was ever asked to start.
    expect(signalAtStart).not.toBeNull();
    expect(signalAtStart!.aborted).toBe(true);
    expect(signalAtStart!.reason).toBe('left');
  });

  it('stops restoring documents when the page goes away', async () => {
    job.restoreFullBackupDocuments.mockImplementation(
      (options: { signal: AbortSignal }) =>
        new Promise((resolve) => {
          options.signal.addEventListener('abort', () =>
            resolve(report({ stopped: { stop: 'left', message: 'You left the page.' } })),
          );
        }),
    );
    const { unmount } = await renderBackup();
    await startRestore(fullBackupFile());
    const signal = (job.restoreFullBackupDocuments.mock.calls[0]?.[0] as { signal: AbortSignal })
      .signal;
    await act(async () => {
      unmount();
    });
    expect(signal.reason).toBe('left');
  });

  it('says it is getting ready before the first document', async () => {
    job.restoreFullBackupDocuments.mockReturnValue(new Promise(() => {}));
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(screen.getByTestId('document-restore-status')).toHaveTextContent(
      'Getting ready to restore the documents…',
    );
  });

  it('warns, rather than reporting success, when the backup could not include every document', async () => {
    job.restoreFullBackupDocuments.mockResolvedValue(report({ leftOutOfBackup: 1 }));
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'warning',
        title: expect.stringContaining(
          '1 document(s) could not be included when this backup was made.',
        ),
      }),
    );
  });

  it('reports success when every document came back', async () => {
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'success',
        title: expect.stringContaining('Documents restored: 2 in the backup.'),
      }),
    );
    // Dismissing the summary gives the focus to the control that opens the form.
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.getByRole('button', { name: 'Restore from File' })).toHaveFocus();
  });

  it('warns when the account held documents the backup does not carry', async () => {
    job.restoreFullBackupDocuments.mockResolvedValue(report({ missingFromBackup: 2 }));
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({ type: 'warning' }));
  });

  it('lists what was not restored, and the notes about what was', async () => {
    job.restoreFullBackupDocuments.mockResolvedValue(
      report({
        uploaded: 1,
        notRestored: [{ name: 'huge.iso', reason: 'There is not enough storage left for it.' }],
        notes: ['scan.pdf: its folder no longer exists, so it was restored outside any folder.'],
        missingFromBackup: 3,
        leftOutOfBackup: 2,
      }),
    );
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(
      within(screen.getByTestId('document-restore-not-restored')).getByText('huge.iso'),
    ).toBeInTheDocument();
    expect(screen.getByTestId('document-restore-notes')).toHaveTextContent(
      'scan.pdf: its folder no longer exists, so it was restored outside any folder.',
    );
    expect(screen.getByTestId('document-restore-status')).toHaveTextContent(
      '1 not restored. 2 document(s) could not be included when this backup was made. 3 document(s) the account held were not in this backup.',
    );
  });

  it('asks first about a self-signed full backup, naming its documents', async () => {
    // The account's key does not verify it; the file's own block does.
    job.verifyFullBackupManifest.mockImplementation(
      (_payload: string, _sig: string, bwk: ArrayBuffer) => Promise.resolve(bwk !== BWK),
    );
    job.openFullBackupFile.mockImplementation(() => {
      const opened = openedBackup();
      opened.manifest.vault.backupEncryption = { ...BACKUP_BLOCK, encryptedBWK: 'file-ebwk' };
      return Promise.resolve(opened);
    });
    vi.mocked(cryptoService.decryptBWK).mockImplementation((encrypted: string) =>
      Promise.resolve(encrypted === 'file-ebwk' ? new Uint8Array([1]).buffer : BWK),
    );
    await renderBackup();
    await startRestore(fullBackupFile());
    expect(
      screen.getByText(/could only be checked against key material the file itself/),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Its documents are added to your account the same way.'),
    ).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByText('Cancel Restore'));
    });
    expect(restorePostCount()).toBe(0);
    expect(job.restoreFullBackupDocuments).not.toHaveBeenCalled();
  });

  it('states the auto-lock pause in the restore form', async () => {
    await renderBackup();
    fireEvent.click(screen.getByText('Restore from File'));
    expect(screen.getByText(/A full backup also restores its documents/)).toBeInTheDocument();
    expect(screen.getByLabelText('Backup File')).toHaveAttribute('accept', '.enc,.hvbackup');
  });
});
