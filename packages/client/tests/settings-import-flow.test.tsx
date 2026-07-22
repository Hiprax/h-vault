/**
 * The import flow end-to-end through the Settings page: parse → load the whole
 * vault → resolve → confirm → send → account for every row.
 *
 * These are the guarantees the flow exists to provide, so they are asserted on
 * observable behaviour (what reaches `importVaultApi`, what the toast says)
 * rather than on internals:
 *
 *  - an import that would MODIFY existing items sends nothing until the user
 *    confirms a summary, and cancelling sends nothing at all;
 *  - the reported outcome counts sum to the number of rows the file held;
 *  - the request body carries `operations` and NO plaintext;
 *  - an overwrite keeps the previous password in the item's history;
 *  - a vault that is locked, or that could not be fully loaded, refuses rather
 *    than resolving against an incomplete list.
 */
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { importInsertItemSchema, importUpdateItemSchema } from '@hvault/shared';

const mockToast = vi.fn();
const mockGetProfileApi = vi.fn();
const mockImportVaultApi = vi.fn();
const mockListItemsApi = vi.fn();

/**
 * Reversible stand-ins for AES-GCM. Base64 rather than a `plain:` prefix on
 * purpose: the ciphertext must not literally contain the plaintext, or the
 * "no plaintext on the wire" assertion below would pass vacuously.
 */
const seal = (plain: string): string => `enc:${Buffer.from(plain, 'utf8').toString('base64')}`;
const open = (encrypted: string): string =>
  Buffer.from(encrypted.replace(/^enc:/, ''), 'base64').toString('utf8');

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    encryptData: vi.fn((plain: string) =>
      Promise.resolve({ encrypted: seal(plain), iv: 'iv', tag: 'tag' }),
    ),
    decryptData: vi.fn((encrypted: string) => Promise.resolve(open(encrypted))),
    generateSearchHash: vi.fn(() => Promise.resolve('a'.repeat(64))),
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
    encryptVaultKey: vi.fn(),
    rotateVaultKey: vi.fn(),
    deriveBEK: vi.fn(),
    decryptBWK: vi.fn(),
    encryptVaultKeyWithBWK: vi.fn(),
    base64ToArrayBuffer: vi.fn(),
  },
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
  importVaultApi: (...args: unknown[]) => mockImportVaultApi(...args),
  updateSettingsApi: vi.fn(),
  changePasswordApi: vi.fn(),
  setup2faApi: vi.fn(),
  verify2faApi: vi.fn(),
  disable2faApi: vi.fn(),
  regenerateBackupCodesApi: vi.fn(),
  exportVaultApi: vi.fn(),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: (...args: unknown[]) => mockListItemsApi(...args),
  listTrashApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  reorderFolderApi: vi.fn(),
  bulkDeleteApi: vi.fn(),
  bulkMoveApi: vi.fn(),
  bulkReEncryptApi: vi.fn(),
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
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

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({ toast: (...a: unknown[]) => mockToast(...a) }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: vi.fn().mockReturnValue({ autoLockTimeout: 15, clipboardClearTimeout: 30 }),
  clearSettingsCache: vi.fn(),
}));

vi.mock('qrcode', () => ({ default: { toDataURL: vi.fn().mockResolvedValue('data:image/png') } }));

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: vi.fn().mockResolvedValue(() => ({ score: 4, feedback: {} })),
}));

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EXISTING_ID = '507f1f77bcf86cd799439011';
const OLD_PASSWORD = 'old-github-password';

/** The vault already holds this GitHub login for `octocat`. */
function existingGithubItem() {
  return {
    _id: EXISTING_ID,
    userId: '507f1f77bcf86cd799439000',
    itemType: 'login',
    tags: [],
    favorite: false,
    encryptedName: seal('Work GitHub'),
    nameIv: 'iv',
    nameTag: 'tag',
    encryptedData: seal(
      JSON.stringify({
        username: 'octocat',
        password: OLD_PASSWORD,
        uris: [{ uri: 'https://github.com', match: 'domain' }],
      }),
    ),
    dataIv: 'iv',
    dataTag: 'tag',
    searchHash: 'a'.repeat(64),
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
}

function itemsPage(items: unknown[]) {
  return {
    data: {
      success: true,
      data: items,
      pagination: { page: 1, limit: 200, total: items.length, totalPages: 1 },
    },
  };
}

/**
 * Three Firefox rows: one is the GitHub account the vault already holds with a
 * NEW password, and the other two are the same brand-new GitLab account listed
 * twice. Every outcome bucket the flow can report is therefore exercised at once.
 */
const FIREFOX_CSV = [
  'url,username,password',
  'https://github.com,octocat,brand-new-secret',
  'https://gitlab.com,newuser,gitlab-secret',
  'https://gitlab.com,newuser,gitlab-secret',
].join('\n');

async function renderSettings() {
  const { default: SettingsPage } = await import('../src/pages/SettingsPage');
  await act(async () => {
    render(
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>,
    );
  });
  await waitFor(() => expect(screen.getByText('Settings')).toBeInTheDocument());
}

/** Open the import panel, pick Firefox, and paste the CSV. */
function startFirefoxImport(csv: string = FIREFOX_CSV, strategy = 'overwrite') {
  fireEvent.click(screen.getByText('Import Vault'));
  fireEvent.change(screen.getByDisplayValue('H-Vault (.enc / JSON)'), {
    target: { value: 'firefox' },
  });
  fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
    target: { value: csv },
  });
  fireEvent.change(screen.getByDisplayValue('Skip duplicates'), { target: { value: strategy } });
}

function lastImportBody() {
  return mockImportVaultApi.mock.calls[0]?.[0] as {
    format: string;
    conflictStrategy: string;
    operations: {
      inserts: Record<string, unknown>[];
      updates: Record<string, unknown>[];
    };
  };
}

describe('SettingsPage import flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetProfileApi.mockResolvedValue({
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
            backup: { enabled: false, scheduleHour: 3, backupEmails: [], isConfigured: false },
          },
        },
      },
    });
    mockListItemsApi.mockResolvedValue(itemsPage([existingGithubItem()]));
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 1 } },
    });

    useAuthStore.setState({
      accessToken: 'token',
      user: { userId: 'u1', email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: { name: 'vault-key' } as unknown as CryptoKey,
      mek: null,
      encryptedVaultKeyData: null,
    } as never);
    useVaultStore.setState({ items: [] });
  });

  it('sends nothing until an import that modifies existing items is confirmed', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    // The dialog is up and NOTHING has been sent.
    await waitFor(() => expect(screen.getByText('Confirm import changes')).toBeInTheDocument());
    expect(mockImportVaultApi).not.toHaveBeenCalled();

    // It states what will change, including that names are replaced too.
    expect(screen.getByText(/will modify 1 existing item\b/)).toBeInTheDocument();
    expect(screen.getByText(/1 password.* will change/)).toBeInTheDocument();
    expect(screen.getByText(/name is replaced/)).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByText('Apply Changes'));
    });
    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalledTimes(1));
  });

  it('cancelling the confirmation sends nothing and says so', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });
    await waitFor(() => expect(screen.getByText('Confirm import changes')).toBeInTheDocument());

    await act(async () => {
      fireEvent.click(screen.getByText('Cancel Import'));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Import cancelled. Nothing was changed.' }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('sends nothing if the vault was locked while the confirmation was open', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });
    await waitFor(() => screen.getByText('Confirm import changes'));

    // The prompt has no time limit; a key that changed under it invalidates the
    // answer, however long ago the user gave it.
    useAuthStore.setState({ vaultKey: null } as never);
    await act(async () => {
      fireEvent.click(screen.getByText('Apply Changes'));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Your vault was locked while the import was waiting to be confirmed.',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('reports every row exactly once, in counts that sum to the rows parsed', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });
    await waitFor(() => screen.getByText('Confirm import changes'));
    await act(async () => {
      fireEvent.click(screen.getByText('Apply Changes'));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const summary = mockToast.mock.calls
      .map(([arg]) => arg as { title: string })
      .find((arg) => arg.title.startsWith('Imported'));
    expect(summary?.title).toBe('Imported 1 items, 1 updated, 1 duplicate rows in file (3 rows)');

    // The stated buckets account for the file exactly: 1 + 1 + 1 = 3 rows.
    const counts = [...(summary?.title.matchAll(/(\d+)\s(?:items|updated|duplicate)/g) ?? [])].map(
      (m) => Number(m[1]),
    );
    expect(counts.reduce((a, b) => a + b, 0)).toBe(3);
  });

  it('puts operations — and no plaintext — on the wire', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });
    await waitFor(() => screen.getByText('Confirm import changes'));
    await act(async () => {
      fireEvent.click(screen.getByText('Apply Changes'));
    });
    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());

    const body = lastImportBody();
    expect(body.format).toBe('firefox');
    expect(body.conflictStrategy).toBe('overwrite');
    expect(body).not.toHaveProperty('data');
    expect(body.operations.inserts).toHaveLength(1);
    expect(body.operations.updates).toHaveLength(1);

    // Every operation satisfies the server's schema, so a 400 cannot come from
    // a payload the client itself built.
    expect(importInsertItemSchema.safeParse(body.operations.inserts[0]).success).toBe(true);
    expect(importUpdateItemSchema.safeParse(body.operations.updates[0]).success).toBe(true);

    // No credential, username, URL or item name appears anywhere in the body.
    const serialized = JSON.stringify(body);
    for (const secret of [
      'brand-new-secret',
      'gitlab-secret',
      OLD_PASSWORD,
      'octocat',
      'newuser',
      'github.com',
      'gitlab.com',
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it('overwrites the matched item in place and keeps its previous password', async () => {
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });
    await waitFor(() => screen.getByText('Confirm import changes'));
    await act(async () => {
      fireEvent.click(screen.getByText('Apply Changes'));
    });
    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());

    const update = lastImportBody().operations.updates[0] as {
      id: string;
      encryptedData: string;
      passwordHistory?: { encryptedPassword: string }[];
    };
    // It targets the matched item, not a new row.
    expect(update.id).toBe(EXISTING_ID);
    // The new content is what lands…
    expect(JSON.parse(open(update.encryptedData))).toMatchObject({
      username: 'octocat',
      password: 'brand-new-secret',
    });
    // …and the password it replaced is recoverable from history.
    expect(update.passwordHistory).toHaveLength(1);
    expect(open(update.passwordHistory?.[0]?.encryptedPassword ?? '')).toBe(OLD_PASSWORD);
  });

  it('never asks for confirmation when nothing existing would be modified', async () => {
    mockImportVaultApi.mockResolvedValue({
      data: { success: true, data: { insertedCount: 1, updatedCount: 0 } },
    });
    await renderSettings();
    // `skip` never updates: the matching row is reported instead.
    startFirefoxImport(FIREFOX_CSV, 'skip');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    expect(screen.queryByText('Confirm import changes')).not.toBeInTheDocument();
    const body = lastImportBody();
    expect(body.operations.updates).toEqual([]);
    expect(body.operations.inserts).toHaveLength(1);
    const summary = mockToast.mock.calls
      .map(([arg]) => arg as { title: string })
      .find((arg) => arg.title.startsWith('Imported'));
    expect(summary?.title).toBe(
      'Imported 1 items, 1 duplicates skipped, 1 duplicate rows in file (3 rows)',
    );
  });

  it('reports what committed when a later batch fails, and says a re-run is safe', async () => {
    // A whole-vault import is split into several requests. If one fails, the
    // earlier ones are already committed: the user must be told what landed
    // rather than left with a bare error, and re-running must be safe (it
    // re-resolves against the now-updated vault).
    //
    // Two batches are forced by SIZE, the way a real migration hits the limit:
    // native rows carry their ciphertext verbatim, so a dozen large rows exceed
    // the per-request byte budget without needing thousands of items.
    const bigRows = Array.from({ length: 12 }, (_, i) => ({
      itemType: 'login',
      encryptedData: `${'QUJDREVG'.repeat(12_500)}${String(i)}`,
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: seal(`Item ${String(i)}`),
      nameIv: 'iv',
      nameTag: 'tag',
    }));
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi
      .mockResolvedValueOnce({
        data: { success: true, data: { insertedCount: 9, updatedCount: 0 } },
      })
      .mockRejectedValueOnce(new Error('server said no'));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: bigRows }) },
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalledTimes(2));
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: expect.stringContaining('Imported 9 and updated 0 items, then stopped') as string,
        description: 'Nothing else was changed. Running the import again is safe.',
        type: 'error',
      }),
    );
    // The committed rows are pulled back in so they appear in the vault.
    await waitFor(() => expect(mockListItemsApi.mock.calls.length).toBeGreaterThan(1));
    // The panel stays open so the user can retry without re-pasting.
    expect(screen.getByPlaceholderText('Paste exported data here...')).toBeInTheDocument();
  });

  it('does not call a re-run safe after a partial "keep both" import', async () => {
    // `keep_both` never matches anything, so a re-run re-inserts whatever the
    // failed run already committed. Advising "running the import again is safe"
    // there would talk the user into duplicating every landed row.
    const bigRows = Array.from({ length: 12 }, (_, i) => ({
      itemType: 'login',
      encryptedData: `${'QUJDREVG'.repeat(12_500)}${String(i)}`,
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: seal(`Item ${String(i)}`),
      nameIv: 'iv',
      nameTag: 'tag',
    }));
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi
      .mockResolvedValueOnce({
        data: { success: true, data: { insertedCount: 9, updatedCount: 0 } },
      })
      .mockRejectedValueOnce(new Error('server said no'));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByDisplayValue('Skip duplicates'), {
      target: { value: 'keep_both' },
    });
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: bigRows }) },
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalledTimes(2));
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        description: expect.stringContaining('re-run with "skip"') as string,
        type: 'error',
      }),
    );
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Nothing else was changed. Running the import again is safe.',
      }),
    );
  });

  it('refuses to import while the vault is locked', async () => {
    await renderSettings();
    useAuthStore.setState({ vaultKey: null } as never);
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    expect(mockToast).toHaveBeenCalledWith({
      title: 'Unlock your vault before importing',
      type: 'error',
    });
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('aborts rather than resolving against a vault it could not load', async () => {
    mockListItemsApi.mockRejectedValue(new Error('network down'));
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Could not load your vault to check for duplicates. Nothing was imported.',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('aborts when a lock empties the vault while the item list is still loading', async () => {
    // `clearStore()` empties `items` and bumps the fetch generation; the awaited
    // fetch then RESOLVES rather than rejecting. Resolving the import against
    // that empty list would classify the whole file as new and duplicate the
    // vault, so the flow must notice and refuse.
    mockListItemsApi.mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            useVaultStore.getState().clearStore();
            resolve(itemsPage([]));
          }, 0);
        }),
    );
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Your vault was locked or reloaded while the import was preparing.',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('aborts when the vault key is dropped while the item list is loading', async () => {
    // The belt to the generation check's braces: a key that changed under us
    // means the list we just read is not this vault's.
    mockListItemsApi.mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            useAuthStore.setState({ vaultKey: null } as never);
            resolve(itemsPage([]));
          }, 0);
        }),
    );
    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Your vault was locked or reloaded while the import was preparing.',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('refuses to resolve against the offline cache', async () => {
    // Offline, `fetchItems` falls back to IndexedDB, which is cleared on lock and
    // may be empty or stale — not a vault to decide duplicates against.
    const onLine = vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    try {
      await renderSettings();
      startFirefoxImport();

      await act(async () => {
        fireEvent.click(screen.getByRole('button', { name: 'Import' }));
      });

      await waitFor(() =>
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({
            title: 'You appear to be offline, so your vault list could not be verified.',
          }),
        ),
      );
      expect(mockImportVaultApi).not.toHaveBeenCalled();
    } finally {
      onLine.mockRestore();
    }
  });
});
