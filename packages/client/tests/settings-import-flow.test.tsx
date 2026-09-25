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
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, cleanup } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { createHash } from 'node:crypto';
import {
  MAX_ENCRYPTED_PASSWORD_HISTORY_LENGTH,
  PASSWORD_HISTORY_MAX,
  deriveRowId,
  importInsertItemSchema,
  importUpdateItemSchema,
} from '@hvault/shared';

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

/**
 * The same reversible stand-in for a format-v2 field. Its TAG is a digest of the
 * additional data it was sealed with, so the mocked open below REFUSES a field
 * presented under any other binding (the one property of AES-GCM these cases
 * depend on), and, like real AES-GCM, the ciphertext is exactly as long as a v1
 * seal of the same plaintext, so the size bounds the flow enforces mean the same.
 */
const aadTag = (aad: string): string =>
  createHash('sha256').update(aad, 'utf8').digest('hex').slice(0, 32);
const sealBound = (plain: string, aad: string): { encrypted: string; tag: string } => ({
  encrypted: seal(plain),
  tag: aadTag(aad),
});
const openBound = (encrypted: string, tag: string, aad: Uint8Array): Promise<string> =>
  tag === aadTag(new TextDecoder().decode(aad))
    ? Promise.resolve(open(encrypted))
    : Promise.reject(new Error('OperationError'));

/** The exact additional data a v2 field of `rowId` is sealed with. */
const AAD_PREFIX = 'hvault/vault-field/v2|';
const nameAad = (rowId: string): string => `${AAD_PREFIX}item.name|${rowId}`;
const dataAad = (itemType: string, rowId: string): string =>
  `${AAD_PREFIX}item.data|${itemType}|${rowId}`;
const historyAad = (rowId: string): string => `${AAD_PREFIX}item.password-history|${rowId}`;

/**
 * Opens a field the flow put on the wire, asserting it is format v2 (the `v2:`
 * IV marker) AND sealed to exactly `aad`: a field sealed to any other row, role
 * or type fails here rather than decoding.
 */
function openBoundField(
  field: { encrypted: string; iv: string; tag: string } | undefined,
  aad: string,
): string {
  expect(field?.iv).toBe('v2:iv');
  expect(field?.tag).toBe(aadTag(aad));
  return open(field?.encrypted ?? '');
}

interface SentHistoryEntry {
  encryptedPassword: string;
  iv: string;
  tag: string;
  changedAt: string;
}

/** {@link openBoundField} for one retained password, bound to `rowId`'s history. */
function openHistoryEntry(entry: SentHistoryEntry | undefined, rowId: string): string {
  return openBoundField(
    entry && { encrypted: entry.encryptedPassword, iv: entry.iv, tag: entry.tag },
    historyAad(rowId),
  );
}

/** {@link openBoundField} for a row's name or data triple, as the wire names them. */
function openSentField(row: Record<string, unknown>, field: 'name' | 'data', aad: string): string {
  const cap = field === 'name' ? 'Name' : 'Data';
  return openBoundField(
    {
      encrypted: row[`encrypted${cap}`] as string,
      iv: row[`${field}Iv`] as string,
      tag: row[`${field}Tag`] as string,
    },
    aad,
  );
}

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    encryptData: vi.fn((plain: string) =>
      Promise.resolve({ encrypted: seal(plain), iv: 'iv', tag: 'tag' }),
    ),
    decryptData: vi.fn((encrypted: string) => Promise.resolve(open(encrypted))),
    decryptDataWithAad: vi.fn(
      (encrypted: string, _iv: string, tag: string, _key: CryptoKey, aad: Uint8Array) =>
        openBound(encrypted, tag, aad),
    ),
    encryptDataWithAad: vi.fn((plain: string, _key: CryptoKey, aad: Uint8Array) =>
      Promise.resolve({ ...sealBound(plain, new TextDecoder().decode(aad)), iv: 'iv' }),
    ),
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

vi.mock('../src/services/offlineCache', async (importOriginal) => ({
  // Spread the real module so exports it grows (the error class, the
  // classifier) stay real; only the IndexedDB-backed singleton is faked.
  ...(await importOriginal<typeof import('../src/services/offlineCache')>()),
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
import { settleImportFlow } from './support/settleImport';
import { cryptoService } from '../src/services/crypto/cryptoService';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EXISTING_ID = '507f1f77bcf86cd799439011';
/** This session's own account: every insert's id is derived from it. */
const USER_ID = '507f1f77bcf86cd799439000';

/** The id an insert is stored under: the one its nonce derives for this account. */
function insertRowId(insert: Record<string, unknown>): Promise<string> {
  expect(typeof insert.idNonce).toBe('string');
  return deriveRowId(USER_ID, insert.idNonce as string);
}

/**
 * A server that stores every insert where its nonce says, answering with the ids
 * `deriveRowId` gives them, in insert order, exactly as the real one does.
 */
function acceptImport(counts: { insertedCount: number; updatedCount: number }) {
  return async (body: { operations: { inserts: Record<string, unknown>[] } }) => ({
    data: {
      success: true,
      data: { ...counts, insertedIds: await Promise.all(body.operations.inserts.map(insertRowId)) },
    },
  });
}
const OLD_PASSWORD = 'old-github-password';

/** The vault already holds this GitHub login for `octocat`. */
function existingGithubItem() {
  return {
    _id: EXISTING_ID,
    userId: USER_ID,
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

/**
 * The import's summary toast, once it has been raised. Waited for rather than
 * read the instant the request is sent: the server answer is awaited (and the
 * insert ids checked against it) before the summary is written.
 */
async function importSummary(): Promise<{ title: string } | undefined> {
  const find = () =>
    mockToast.mock.calls
      .map(([arg]) => arg as { title: string })
      .find((arg) => arg.title.startsWith('Imported'));
  await waitFor(() => expect(find()).toBeDefined());
  return find();
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
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 1 }));

    useAuthStore.setState({
      accessToken: 'token',
      user: { userId: USER_ID, email: 'test@example.com' },
      isAuthenticated: true,
      isLocked: false,
      vaultKey: { name: 'vault-key' } as unknown as CryptoKey,
      mek: null,
      encryptedVaultKeyData: null,
    } as never);
    useVaultStore.setState({ items: [] });
  });

  // An import's tail (summary toast, `fetchItems()`) must run inside the test that
  // started it, never inside the next one: see `settleImportFlow`.
  afterEach(settleImportFlow);

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

  it('reports an outcome when the page is unmounted BEFORE the confirmation is raised', async () => {
    // The window a resolver ref cannot see. The confirmation is registered LATE
    // — after the whole vault has been loaded and resolved — so an auto-lock
    // landing inside that load unmounts the page while the ref is still null.
    // The unmount cleanup then has nothing to settle, and a resolver registered
    // a moment later is one nothing can ever reach: the promise never settles,
    // the accounting below it never runs, and the user is told NOTHING about an
    // import they started. Held open here by stalling the vault load, then
    // unmounting, then letting it through.
    let releaseVault: (() => void) | undefined;
    mockListItemsApi.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          releaseVault = () => resolve(itemsPage([existingGithubItem()]));
        }),
    );

    await renderSettings();
    startFirefoxImport();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    // Unmounted while the import is still inside the vault load.
    await act(async () => {
      cleanup();
    });
    await act(async () => {
      releaseVault?.();
      await Promise.resolve();
    });

    // No summary was ever shown, and the import still said what happened.
    expect(screen.queryByText('Confirm import changes')).toBeNull();
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
    const summary = await importSummary();
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

    // Every field is sealed (format v2) to the row it will be stored as: the insert
    // to the id its nonce derives for this account, the update to the matched row.
    const insert = body.operations.inserts[0] ?? {};
    // The page's post-import tail settles first, so nothing of it runs
    // outside act() while this test does its own asynchronous work.
    await settleImportFlow();
    const insertId = await insertRowId(insert);
    expect(openSentField(insert, 'name', nameAad(insertId))).toBe('gitlab.com (newuser)');
    expect(JSON.parse(openSentField(insert, 'data', dataAad('login', insertId)))).toMatchObject({
      username: 'newuser',
      password: 'gitlab-secret',
    });
    const update = body.operations.updates[0] ?? {};
    expect(update.id).toBe(EXISTING_ID);
    expect(update).not.toHaveProperty('idNonce');
    expect(openSentField(update, 'name', nameAad(EXISTING_ID))).toBe('github.com (octocat)');
    // The AAD reaches the cipher as bytes spelling exactly that binding, and no
    // row field is sealed unbound (v1).
    const aadsSealed = vi
      .mocked(cryptoService.encryptDataWithAad)
      .mock.calls.map(([, , aad]) => new TextDecoder().decode(aad));
    expect(aadsSealed).toEqual(
      expect.arrayContaining([
        nameAad(insertId),
        dataAad('login', insertId),
        nameAad(EXISTING_ID),
        dataAad('login', EXISTING_ID),
        historyAad(EXISTING_ID),
      ]),
    );
    expect(cryptoService.encryptData).not.toHaveBeenCalled();

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

    const update = lastImportBody().operations.updates[0] ?? {};
    const history = update.passwordHistory as SentHistoryEntry[] | undefined;
    // It targets the matched item, not a new row.
    expect(update.id).toBe(EXISTING_ID);
    // The new content is what lands, sealed to the matched row and its STORED type…
    expect(JSON.parse(openSentField(update, 'data', dataAad('login', EXISTING_ID)))).toMatchObject({
      username: 'octocat',
      password: 'brand-new-secret',
    });
    // …and the password it replaced is recoverable from history, bound to that row.
    expect(history).toHaveLength(1);
    expect(openHistoryEntry(history?.[0], EXISTING_ID)).toBe(OLD_PASSWORD);
  });

  it('never asks for confirmation when nothing existing would be modified', async () => {
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 0 }));
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
    const summary = await importSummary();
    expect(summary?.title).toBe(
      'Imported 1 items, 1 duplicates skipped, 1 duplicate rows in file (3 rows)',
    );
  });

  it('carries a native export’s password history, tags and folder back onto the item', async () => {
    // Re-importing your own H-Vault export must not quietly strip the item down
    // to its ciphertext. `packages/shared/src/schemas/user.ts` states the
    // guarantee — "re-importing a native H-Vault export must not erase the
    // history of an item it restores" — and this is the only test that drives
    // the code which extracts those fields from the file. Every other native
    // fixture in the suite is a bare six-ciphertext-field row, so without this
    // the whole extraction block could be deleted and the suite would stay green.
    const FOLDER_ID = '507f1f77bcf86cd799439013';
    const entry = (encryptedPassword: string, changedAt: string) => ({
      encryptedPassword,
      iv: 'iv',
      tag: 'tag',
      changedAt,
    });
    const nativeRow = {
      itemType: 'login',
      encryptedName: seal('Work GitHub'),
      nameIv: 'iv',
      nameTag: 'tag',
      encryptedData: seal(JSON.stringify({ username: 'octocat', password: 'p', uris: [] })),
      dataIv: 'iv',
      dataTag: 'tag',
      folderId: FOLDER_ID,
      // Two survive; the rest are each rejected by a DIFFERENT arm of the
      // validation chain, so no single arm can be deleted unnoticed.
      tags: ['  Work  ', '', 42, 'x'.repeat(200)],
      passwordHistory: [
        entry(seal('older'), '2026-01-02T03:04:05.000Z'),
        entry(seal('non-iso-but-parseable'), 'Tue, 02 Jan 2026 03:04:05 GMT'),
        { encryptedPassword: seal('no-changedAt'), iv: 'iv', tag: 'tag' },
        entry(seal('bad-date'), 'not-a-date'),
        entry('', '2026-01-02T03:04:05.000Z'),
        'not-an-object',
      ],
    };
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 0 }));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeRow] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const insert = lastImportBody().operations.inserts[0] ?? {};
    const history = insert.passwordHistory as SentHistoryEntry[] | undefined;
    // The page's post-import tail settles first, so nothing of it runs
    // outside act() while this test does its own asynchronous work.
    await settleImportFlow();
    const insertId = await insertRowId(insert);

    expect(insert.folderId).toBe(FOLDER_ID);
    // Trimmed, and the empty / non-string / over-long entries dropped.
    expect(insert.tags).toEqual(['Work']);

    // Only the two well-formed entries survive, in file order, each sealed to the
    // NEW row (its history is read as that row's from now on), and the non-ISO
    // timestamp is re-serialized so the wire schema accepts it.
    expect(history).toHaveLength(2);
    expect(openHistoryEntry(history?.[0], insertId)).toBe('older');
    expect(openHistoryEntry(history?.[1], insertId)).toBe('non-iso-but-parseable');
    expect(history?.[1]?.changedAt).toBe('2026-01-02T03:04:05.000Z');

    // And the whole row still satisfies the contract the server enforces.
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
  });

  it('re-seals a native row’s fields to the NEW row it is inserted as, never re-sending them', async () => {
    // Premise changed: imports now write format v2, so a native row is no longer
    // re-sealed as v1 (nor a v1 field sent verbatim); every field is sealed to the
    // id the insert's nonce derives.
    // A bound field is sealed to the row it was exported from. An import sends
    // the row as an INSERT under a fresh id, so a field sent verbatim would be
    // stored where it can never open again. Each one is opened against the row's
    // OWN recorded id and sealed again to the new row; a v1 field is opened and
    // sealed again the same way; a field bound to another row is refused like any
    // other field that will not open.
    const ROW_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
    const OTHER_ID = '66c0f1a2b3c4d5e6f7a8b9c1';
    const data = JSON.stringify({ username: 'octocat', password: 'current', uris: [] });
    const boundName = sealBound('Bound GitHub', nameAad(ROW_ID));
    const boundData = sealBound(data, dataAad('login', ROW_ID));
    const boundOlder = sealBound('bound-older', historyAad(ROW_ID));
    const movedHere = sealBound('moved-here', historyAad(OTHER_ID));
    const boundRow = {
      _id: ROW_ID,
      itemType: 'login',
      encryptedName: boundName.encrypted,
      nameIv: 'v2:iv',
      nameTag: boundName.tag,
      encryptedData: boundData.encrypted,
      dataIv: 'v2:iv',
      dataTag: boundData.tag,
      passwordHistory: [
        {
          encryptedPassword: boundOlder.encrypted,
          iv: 'v2:iv',
          tag: boundOlder.tag,
          changedAt: '2026-01-02T03:04:05.000Z',
        },
        {
          encryptedPassword: movedHere.encrypted,
          iv: 'v2:iv',
          tag: movedHere.tag,
          changedAt: '2026-01-03T03:04:05.000Z',
        },
        {
          encryptedPassword: seal('legacy-older'),
          iv: 'iv',
          tag: 'tag',
          changedAt: '2026-01-04T03:04:05.000Z',
        },
      ],
    };
    // Its data triple was bound to ANOTHER row: it must not import at all.
    const movedData = sealBound(data, dataAad('login', OTHER_ID));
    const movedRow = {
      _id: ROW_ID,
      itemType: 'login',
      encryptedName: seal('Moved'),
      nameIv: 'iv',
      nameTag: 'tag',
      encryptedData: movedData.encrypted,
      dataIv: 'v2:iv',
      dataTag: movedData.tag,
    };
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 0 }));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [boundRow, movedRow] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const inserts = lastImportBody().operations.inserts;

    expect(inserts).toHaveLength(1);
    const insert = inserts[0] ?? {};
    // The page's post-import tail settles first, so nothing of it runs
    // outside act() while this test does its own asynchronous work.
    await settleImportFlow();
    const insertId = await insertRowId(insert);
    // Not the exported row's id: the insert is a new row.
    expect(insertId).not.toBe(ROW_ID);
    // Sealed to the new row, of exactly the plaintext the vault stored.
    expect(openSentField(insert, 'name', nameAad(insertId))).toBe('Bound GitHub');
    expect(openSentField(insert, 'data', dataAad('login', insertId))).toBe(data);
    // A field still bound to the exported row would fail the new row's binding.
    expect(insert.nameTag).not.toBe(boundName.tag);
    expect(insert.dataTag).not.toBe(boundData.tag);
    // The bound entry and the v1 entry both sealed to the new row, in file order;
    // the foreign one dropped.
    const history = insert.passwordHistory as SentHistoryEntry[] | undefined;
    expect(history?.map((e) => e.changedAt)).toEqual([
      '2026-01-02T03:04:05.000Z',
      '2026-01-04T03:04:05.000Z',
    ]);
    expect(openHistoryEntry(history?.[0], insertId)).toBe('bound-older');
    expect(openHistoryEntry(history?.[1], insertId)).toBe('legacy-older');
    // Nothing is sealed unbound, and nothing of the moved row reaches the wire.
    expect(cryptoService.encryptData).not.toHaveBeenCalled();
    const wire = JSON.stringify(lastImportBody());
    expect(wire).not.toContain(seal('Moved'));
    expect(wire).not.toContain(movedData.tag);
    expect(wire).not.toContain(movedHere.tag);
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
  });

  it('keeps at most PASSWORD_HISTORY_MAX entries from a native export', async () => {
    const nativeRow = {
      itemType: 'login',
      encryptedName: seal('Overfull'),
      nameIv: 'iv',
      nameTag: 'tag',
      encryptedData: seal(JSON.stringify({ username: 'u', password: 'p', uris: [] })),
      dataIv: 'iv',
      dataTag: 'tag',
      passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX + 5 }, (_, i) => ({
        encryptedPassword: seal(`pw-${String(i)}`),
        iv: 'iv',
        tag: 'tag',
        changedAt: '2026-01-02T03:04:05.000Z',
      })),
    };
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 0 }));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeRow] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const insert = lastImportBody().operations.inserts[0] as {
      passwordHistory?: unknown[];
    };
    // Truncated to the cap the wire schema enforces, so an over-full export
    // cannot 400 the whole batch it rides in.
    expect(insert.passwordHistory).toHaveLength(PASSWORD_HISTORY_MAX);
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
  });

  it('keeps a native history entry exactly at the stored bound and drops one past it', async () => {
    // The bound is what the server stores for one retained password; an entry
    // past it would 400 the whole batch, so extraction drops that ENTRY alone.
    // The kept entry is now opened and sealed again to the new row, so it is a
    // real (stand-in) ciphertext of exactly the bound's length: `seal` of 29,997
    // bytes is `enc:` plus 39,996 base64 characters. Sealing again keeps the
    // length, as AES-GCM does, so the re-sealed entry still sits exactly on it.
    const atBound = 'p'.repeat(((MAX_ENCRYPTED_PASSWORD_HISTORY_LENGTH - 4) / 4) * 3);
    expect(seal(atBound)).toHaveLength(MAX_ENCRYPTED_PASSWORD_HISTORY_LENGTH);
    const entry = (encryptedPassword: string, changedAt: string) => ({
      encryptedPassword,
      iv: 'iv',
      tag: 'tag',
      changedAt,
    });
    const nativeRow = {
      itemType: 'login',
      encryptedName: seal('Long history'),
      nameIv: 'iv',
      nameTag: 'tag',
      encryptedData: seal(JSON.stringify({ username: 'u', password: 'p', uris: [] })),
      dataIv: 'iv',
      dataTag: 'tag',
      passwordHistory: [
        entry(seal(atBound), '2026-01-02T03:04:05.000Z'),
        entry(`${seal(atBound)}=`, '2026-01-03T03:04:05.000Z'),
      ],
    };
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi.mockImplementation(acceptImport({ insertedCount: 1, updatedCount: 0 }));

    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: [nativeRow] }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() => expect(mockImportVaultApi).toHaveBeenCalled());
    const insert = lastImportBody().operations.inserts[0] ?? {};
    const history = insert.passwordHistory as SentHistoryEntry[] | undefined;
    expect(history?.map((e) => [e.encryptedPassword.length, e.changedAt])).toEqual([
      [MAX_ENCRYPTED_PASSWORD_HISTORY_LENGTH, '2026-01-02T03:04:05.000Z'],
    ]);
    // The page's post-import tail settles first, so nothing of it runs
    // outside act() while this test does its own asynchronous work.
    await settleImportFlow();
    expect(openHistoryEntry(history?.[0], await insertRowId(insert))).toBe(atBound);
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
  });

  it('surfaces the parse error for a native file that is not usable JSON', async () => {
    // `handleImport`'s outer catch is the only thing that turns an
    // ImportParseError into a message a user can act on; without it a malformed
    // paste produces a generic failure, or none at all.
    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: '{not json' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Invalid H-Vault export: the file is not valid JSON.',
          type: 'error',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('surfaces the parse error for a native file with no items array', async () => {
    await renderSettings();
    fireEvent.click(screen.getByText('Import Vault'));
    fireEvent.change(screen.getByPlaceholderText('Paste exported data here...'), {
      target: { value: JSON.stringify({ items: 3 }) },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    });

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Invalid H-Vault export: expected an object with an "items" array.',
          type: 'error',
        }),
      ),
    );
    expect(mockImportVaultApi).not.toHaveBeenCalled();
  });

  it('reports what committed when a later batch fails, and says a re-run is safe', async () => {
    // A whole-vault import is split into several requests. If one fails, the
    // earlier ones are already committed: the user must be told what landed
    // rather than left with a bare error, and re-running must be safe (it
    // re-resolves against the now-updated vault).
    //
    // Two batches are forced by SIZE, the way a real migration hits the limit:
    // a native row is sealed again at the size it was stored at (~100 KB each
    // here), so a dozen large rows exceed the per-request byte budget without
    // needing thousands of items.
    const bigRows = Array.from({ length: 12 }, (_, i) => ({
      itemType: 'login',
      encryptedData: seal(`${'ABCDEF'.repeat(12_500)}${String(i)}`),
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: seal(`Item ${String(i)}`),
      nameIv: 'iv',
      nameTag: 'tag',
    }));
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi
      .mockImplementationOnce(acceptImport({ insertedCount: 9, updatedCount: 0 }))
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
      encryptedData: seal(`${'ABCDEF'.repeat(12_500)}${String(i)}`),
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: seal(`Item ${String(i)}`),
      nameIv: 'iv',
      nameTag: 'tag',
    }));
    mockListItemsApi.mockResolvedValue(itemsPage([]));
    mockImportVaultApi
      .mockImplementationOnce(acceptImport({ insertedCount: 9, updatedCount: 0 }))
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
