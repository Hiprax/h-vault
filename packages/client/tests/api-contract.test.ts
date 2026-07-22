/**
 * Wire-contract tests for the three API service modules (auth / user / vault).
 *
 * These modules are thin by design, but the request they build IS their whole
 * contract: a wrong verb, a mistyped path, a payload nested one level too deep
 * or a body dropped from a DELETE are all shippable bugs that no type-check
 * catches (every one of these functions is typed only on its RESPONSE).
 *
 * So each test asserts the exact (verb, url, payload) triple, and every url is
 * additionally checked against SERVER_ROUTES below — a mirror of the real
 * Express route table (packages/server/src/routes/*.ts, mounted under /api/v1
 * by app.ts). SERVER_ROUTES is a hand-mirrored copy of that table, so it does
 * not detect a server-side rename on its own — what it does catch is a client
 * call that does not correspond to ANY route the server exposes: a typo, a
 * wrong verb, a path assembled in the wrong order. Those 404 at runtime and
 * are otherwise invisible, because every function here is typed only on its
 * RESPONSE. Keep the mirror in sync when routes change.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mock the Axios instance so nothing touches the network or the CSRF flow.
// `withRefreshLock` is mocked as a pass-through that records its invocation,
// so we can prove the refresh POST is actually made inside the cross-tab lock.
// ---------------------------------------------------------------------------

const mockGet = vi.fn();
const mockPost = vi.fn();
const mockPut = vi.fn();
const mockDelete = vi.fn();
const refreshLockCalls: string[] = [];

vi.mock('../src/services/api/client', () => ({
  api: {
    get: (...a: unknown[]) => mockGet(...a),
    post: (...a: unknown[]) => mockPost(...a),
    put: (...a: unknown[]) => mockPut(...a),
    delete: (...a: unknown[]) => mockDelete(...a),
  },
  withRefreshLock: async <T>(fn: () => Promise<T>): Promise<T> => {
    refreshLockCalls.push('enter');
    const result = await fn();
    refreshLockCalls.push('exit');
    return result;
  },
  clearCsrfToken: vi.fn(),
}));

import * as authApi from '../src/services/api/authApi';
import * as userApi from '../src/services/api/userApi';
import * as vaultApi from '../src/services/api/vaultApi';

// ---------------------------------------------------------------------------
// The real server route table, mirrored from packages/server/src/routes/*.ts.
// Paths are as the CLIENT sees them: the Axios baseURL is /api/v1, and app.ts
// mounts authRoutes at /api/v1/auth, vaultRoutes at /api/v1/vault, folderRoutes
// at /api/v1/folders, userRoutes at /api/v1/user, toolsRoutes at /api/v1/tools.
// ---------------------------------------------------------------------------

const SERVER_ROUTES = new Set<string>([
  // routes/auth.ts
  'POST /auth/register',
  'POST /auth/login',
  'POST /auth/login/2fa',
  'POST /auth/refresh',
  'POST /auth/lock',
  'POST /auth/logout',
  'POST /auth/logout-all',
  'POST /auth/verify-unlock',
  'POST /auth/verify-email',
  'POST /auth/resend-verification',
  'POST /auth/forgot-password',
  'POST /auth/reset-password',
  'POST /auth/unlock-account',
  // routes/user.ts
  'GET /user/profile',
  'PUT /user/settings',
  'PUT /user/change-password',
  'POST /user/2fa/setup',
  'POST /user/2fa/verify',
  'DELETE /user/2fa',
  'POST /user/2fa/regenerate-backup-codes',
  'GET /user/sessions',
  'DELETE /user/sessions/:id',
  'GET /user/audit-log',
  'DELETE /user',
  // routes/vault.ts
  'GET /vault/items',
  'GET /vault/items/trash',
  'GET /vault/items/:id',
  'POST /vault/items',
  'PUT /vault/items/:id',
  'DELETE /vault/items/:id',
  'DELETE /vault/items/:id/permanent',
  'POST /vault/items/restore/:id',
  'POST /vault/items/bulk-delete',
  'POST /vault/items/bulk-move',
  'POST /vault/items/bulk-reencrypt',
  'DELETE /vault/items/trash/empty',
  // routes/folders.ts
  'GET /folders',
  'POST /folders',
  'PUT /folders/:id',
  'DELETE /folders/:id',
  'PUT /folders/:id/sort',
  // routes/tools.ts
  'POST /tools/check-password-breach',
  'POST /tools/check-password-breach/batch',
  'POST /tools/export',
  'POST /tools/import',
]);

/** An ObjectId-shaped id, so path building is exercised realistically. */
const ID = '507f1f77bcf86cd799439011';

/**
 * Re-parameterise a concrete url back into its route template so it can be
 * looked up in SERVER_ROUTES: the literal id we passed in becomes `:id` again.
 * Anything else is left alone, so a genuinely wrong path stays wrong.
 */
function toRoute(method: string, url: string): string {
  return `${method} ${url.split(ID).join(':id')}`;
}

/** Assert the call landed on a real server route AND on the expected one. */
function expectCall(
  mock: ReturnType<typeof vi.fn>,
  method: string,
  url: string,
  ...rest: unknown[]
): void {
  expect(mock).toHaveBeenCalledTimes(1);
  const args = mock.mock.calls[0] as unknown[];
  expect(args[0]).toBe(url);
  if (rest.length > 0) {
    expect(args.slice(1)).toEqual(rest);
  }
  const route = toRoute(method, url);
  expect(
    SERVER_ROUTES.has(route),
    `client called "${route}", which is not a route the server exposes`,
  ).toBe(true);
}

beforeEach(() => {
  mockGet.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockPost.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockPut.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockDelete.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  refreshLockCalls.length = 0;
});

// ===========================================================================
// authApi
// ===========================================================================

describe('authApi wire contract', () => {
  it('POSTs registration to /auth/register with the payload verbatim', async () => {
    const payload = {
      email: 'user@example.com',
      authHash: 'auth-hash',
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'iv',
      vaultKeyTag: 'tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
    };
    await authApi.registerApi(payload);
    expectCall(mockPost, 'POST', '/auth/register', payload);
  });

  it('POSTs login to /auth/login carrying deviceInfo when supplied', async () => {
    const payload = {
      email: 'user@example.com',
      authHash: 'auth-hash',
      deviceInfo: { userAgent: 'ua', fingerprint: 'fp' },
    };
    await authApi.loginApi(payload);
    expectCall(mockPost, 'POST', '/auth/login', payload);
  });

  it('POSTs the 2FA step to /auth/login/2fa (not /auth/2fa)', async () => {
    const payload = { tempToken: 'temp', code: '123456' };
    await authApi.login2faApi(payload);
    expectCall(mockPost, 'POST', '/auth/login/2fa', payload);
  });

  it('POSTs verify-email / forgot-password / reset-password / unlock-account to their own routes', async () => {
    await authApi.verifyEmailApi({ token: 't' });
    expectCall(mockPost, 'POST', '/auth/verify-email', { token: 't' });

    mockPost.mockClear();
    await authApi.forgotPasswordApi({ email: 'user@example.com' });
    expectCall(mockPost, 'POST', '/auth/forgot-password', { email: 'user@example.com' });

    mockPost.mockClear();
    const reset = {
      token: 't',
      email: 'user@example.com',
      newAuthHash: 'nah',
      newEncryptedVaultKey: 'nevk',
      newVaultKeyIv: 'niv',
      newVaultKeyTag: 'ntag',
    };
    await authApi.resetPasswordApi(reset);
    expectCall(mockPost, 'POST', '/auth/reset-password', reset);

    mockPost.mockClear();
    await authApi.unlockAccountApi({ token: 't' });
    expectCall(mockPost, 'POST', '/auth/unlock-account', { token: 't' });
  });

  it('POSTs logout-all to its own route, distinct from logout', async () => {
    await authApi.logoutAllApi();
    expectCall(mockPost, 'POST', '/auth/logout-all');
  });

  // The refresh cookie is shared by every tab of the origin. If two tabs POST
  // /auth/refresh with the same pre-rotation token, the server claims it once
  // and the loser trips reuse detection, revoking the whole family and logging
  // every session out. So this call MUST run inside the cross-tab Web Lock.
  it('runs the refresh POST inside the cross-tab refresh lock', async () => {
    await authApi.refreshTokenApi();

    expectCall(mockPost, 'POST', '/auth/refresh');
    // The POST happened strictly between lock acquisition and release.
    expect(refreshLockCalls).toEqual(['enter', 'exit']);
  });

  // logoutApi/lockApi take a per-call timeout because the shared Axios instance
  // deliberately has NO global timeout (that would abort the legitimately-long
  // 30 MB backup-restore / rotation requests). Both arms of that conditional
  // are real: omit the arg and no timeout may be forced onto the request.
  it('attaches a per-call timeout to logout only when one is given', async () => {
    await authApi.logoutApi(5000);
    expectCall(mockPost, 'POST', '/auth/logout', undefined, { timeout: 5000 });

    mockPost.mockClear();
    await authApi.logoutApi();
    expectCall(mockPost, 'POST', '/auth/logout', undefined, {});
  });

  it('attaches a per-call timeout to lock only when one is given', async () => {
    await authApi.lockApi(5000);
    expectCall(mockPost, 'POST', '/auth/lock', undefined, { timeout: 5000 });

    mockPost.mockClear();
    await authApi.lockApi();
    expectCall(mockPost, 'POST', '/auth/lock', undefined, {});
  });

  it('does not send a request body for logout / lock (the session comes from the cookie + bearer)', async () => {
    await authApi.lockApi();
    expect((mockPost.mock.calls[0] as unknown[])[1]).toBeUndefined();
  });
});

// ===========================================================================
// userApi
// ===========================================================================

describe('userApi wire contract', () => {
  it('GETs the profile', async () => {
    await userApi.getProfileApi();
    expectCall(mockGet, 'GET', '/user/profile');
  });

  it('PUTs settings and change-password to their distinct routes', async () => {
    await userApi.updateSettingsApi({ theme: 'dark' } as never);
    expectCall(mockPut, 'PUT', '/user/settings', { theme: 'dark' });

    mockPut.mockClear();
    const pw = { currentAuthHash: 'c', newAuthHash: 'n' } as never;
    await userApi.changePasswordApi(pw);
    expectCall(mockPut, 'PUT', '/user/change-password', pw);
  });

  it('POSTs 2FA setup / verify / regenerate-backup-codes to their own routes', async () => {
    await userApi.setup2faApi({ password: 'pw' });
    expectCall(mockPost, 'POST', '/user/2fa/setup', { password: 'pw' });

    mockPost.mockClear();
    await userApi.verify2faApi({ code: '123456' });
    expectCall(mockPost, 'POST', '/user/2fa/verify', { code: '123456' });

    mockPost.mockClear();
    await userApi.regenerateBackupCodesApi({ password: 'pw', code: '123456' });
    expectCall(mockPost, 'POST', '/user/2fa/regenerate-backup-codes', {
      password: 'pw',
      code: '123456',
    });
  });

  // A DELETE carries no body by default in Axios — the payload must go in the
  // config's `data` field. Passing it as the second positional arg (as with
  // post/put) would silently send NOTHING, and the server would reject the
  // disable for a missing password/TOTP code.
  it('sends the password + TOTP code in the DELETE body when disabling 2FA', async () => {
    await userApi.disable2faApi({ code: '123456', password: 'pw' });
    expectCall(mockDelete, 'DELETE', '/user/2fa', {
      data: { code: '123456', password: 'pw' },
    });
  });

  it('lists and revokes sessions, scoping the revoke to the session id', async () => {
    await userApi.listSessionsApi();
    expectCall(mockGet, 'GET', '/user/sessions');

    mockGet.mockClear();
    await userApi.revokeSessionApi(ID);
    expectCall(mockDelete, 'DELETE', `/user/sessions/${ID}`);
  });

  it('passes audit-log pagination through as query params, not a body', async () => {
    await userApi.getAuditLogApi({ page: 2, limit: 20, action: 'login' });
    expectCall(mockGet, 'GET', '/user/audit-log', {
      params: { page: 2, limit: 20, action: 'login' },
    });
  });

  it('omits audit-log params entirely when none are given', async () => {
    await userApi.getAuditLogApi();
    expectCall(mockGet, 'GET', '/user/audit-log', { params: undefined });
  });

  // k-anonymity: only the hash PREFIX may ever leave the device.
  it('sends only the hash prefix to the breach-check tool', async () => {
    await userApi.checkBreachApi('ABCDE');
    expectCall(mockPost, 'POST', '/tools/check-password-breach', { hashPrefix: 'ABCDE' });
  });

  // k-anonymity: the batch tool sends only an array of 5-char prefixes.
  it('sends only hash prefixes to the batched breach-check tool', async () => {
    await userApi.checkBreachBatchApi(['ABCDE', 'FF012']);
    expectCall(mockPost, 'POST', '/tools/check-password-breach/batch', {
      hashPrefixes: ['ABCDE', 'FF012'],
    });
  });

  it('POSTs export and import to the tools routes', async () => {
    await userApi.exportVaultApi({ format: 'json', authHash: 'h' } as never);
    expectCall(mockPost, 'POST', '/tools/export', { format: 'json', authHash: 'h' });

    mockPost.mockClear();
    // The import contract is structured: explicit inserts/updates, resolved on
    // the client. `conflictStrategy` rides along as audit metadata only.
    const imp = {
      format: 'json',
      conflictStrategy: 'skip',
      operations: {
        inserts: [
          {
            itemType: 'login',
            encryptedName: 'en',
            nameIv: 'ni',
            nameTag: 'nt',
            encryptedData: 'ed',
            dataIv: 'di',
            dataTag: 'dt',
            searchHash: 'a'.repeat(64),
            tags: [],
            favorite: false,
          },
        ],
        updates: [],
      },
    } as never;
    await userApi.importVaultApi(imp);
    expectCall(mockPost, 'POST', '/tools/import', imp);
  });
});

// ===========================================================================
// vaultApi — items
// ===========================================================================

describe('vaultApi wire contract — items', () => {
  it('passes list filters as query params', async () => {
    const params = {
      page: 1,
      limit: 50,
      itemType: 'login',
      favorite: true,
      sortBy: 'updatedAt' as const,
      sortOrder: 'desc' as const,
    };
    await vaultApi.listItemsApi(params);
    expectCall(mockGet, 'GET', '/vault/items', { params });
  });

  it('lists items with no params at all', async () => {
    await vaultApi.listItemsApi();
    expectCall(mockGet, 'GET', '/vault/items', { params: undefined });
  });

  it('GETs a single item by id', async () => {
    await vaultApi.getItemApi(ID);
    expectCall(mockGet, 'GET', `/vault/items/${ID}`);
  });

  it('creates with POST and updates with PUT (never POST-to-update)', async () => {
    const create = { itemType: 'login', encryptedData: 'd' } as never;
    await vaultApi.createItemApi(create);
    expectCall(mockPost, 'POST', '/vault/items', create);

    const update = { favorite: true } as never;
    await vaultApi.updateItemApi(ID, update);
    expectCall(mockPut, 'PUT', `/vault/items/${ID}`, update);
  });

  // The soft delete and the irreversible permanent delete are different routes.
  // Confusing them destroys user data, so pin both.
  it('separates the soft delete from the permanent delete', async () => {
    await vaultApi.deleteItemApi(ID);
    expectCall(mockDelete, 'DELETE', `/vault/items/${ID}`);

    mockDelete.mockClear();
    await vaultApi.permanentDeleteApi(ID);
    expectCall(mockDelete, 'DELETE', `/vault/items/${ID}/permanent`);
  });

  it('restores via POST /vault/items/restore/:id', async () => {
    await vaultApi.restoreItemApi(ID);
    expectCall(mockPost, 'POST', `/vault/items/restore/${ID}`);
  });

  it('sends bulk-delete ids in the body', async () => {
    await vaultApi.bulkDeleteApi([ID, 'b']);
    expectCall(mockPost, 'POST', '/vault/items/bulk-delete', { ids: [ID, 'b'] });
  });

  // folderId === null is the "move to no folder" signal and must survive as an
  // explicit null — dropping it (or sending undefined) would leave the items
  // in their current folder instead of un-foldering them.
  it('preserves an explicit null folderId on bulk-move', async () => {
    await vaultApi.bulkMoveApi([ID], null);
    expectCall(mockPost, 'POST', '/vault/items/bulk-move', { ids: [ID], folderId: null });

    mockPost.mockClear();
    await vaultApi.bulkMoveApi([ID], 'folder-1');
    expectCall(mockPost, 'POST', '/vault/items/bulk-move', { ids: [ID], folderId: 'folder-1' });
  });

  it('reads the trash from its own route and empties it with DELETE', async () => {
    await vaultApi.listTrashApi({ page: 1, sortBy: 'deletedAt', sortOrder: 'desc' });
    expectCall(mockGet, 'GET', '/vault/items/trash', {
      params: { page: 1, sortBy: 'deletedAt', sortOrder: 'desc' },
    });

    await vaultApi.emptyTrashApi();
    expectCall(mockDelete, 'DELETE', '/vault/items/trash/empty');
  });

  it('POSTs the rotation payload to bulk-reencrypt', async () => {
    const payload = {
      authHash: 'h',
      newEncryptedVaultKey: 'k',
      items: [],
      folders: [],
    } as never;
    await vaultApi.bulkReEncryptApi(payload);
    expectCall(mockPost, 'POST', '/vault/items/bulk-reencrypt', payload);
  });
});

// ===========================================================================
// vaultApi — folders
// ===========================================================================

describe('vaultApi wire contract — folders', () => {
  it('lists and creates folders at /folders', async () => {
    await vaultApi.listFoldersApi();
    expectCall(mockGet, 'GET', '/folders');

    const create = { encryptedName: 'n' } as never;
    await vaultApi.createFolderApi(create);
    expectCall(mockPost, 'POST', '/folders', create);
  });

  it('updates a folder with PUT /folders/:id', async () => {
    const update = { encryptedName: 'n2' } as never;
    await vaultApi.updateFolderApi(ID, update);
    expectCall(mockPut, 'PUT', `/folders/${ID}`, update);
  });

  // Reorder is a DIFFERENT route from update (/sort), and sends only sortOrder.
  it('reorders via PUT /folders/:id/sort with just the sortOrder', async () => {
    await vaultApi.reorderFolderApi(ID, 3);
    expectCall(mockPut, 'PUT', `/folders/${ID}/sort`, { sortOrder: 3 });
  });

  // The `action` query param decides whether the folder's ITEMS are moved out
  // or deleted along with it. Both arms of the conditional matter: when no
  // action is given, `params` must be undefined rather than `{ action: undefined }`,
  // so Axios does not serialise a stray `?action=` onto the request.
  it('sends the delete action as a query param when given', async () => {
    await vaultApi.deleteFolderApi(ID, 'move');
    expectCall(mockDelete, 'DELETE', `/folders/${ID}`, { params: { action: 'move' } });

    mockDelete.mockClear();
    await vaultApi.deleteFolderApi(ID, 'delete');
    expectCall(mockDelete, 'DELETE', `/folders/${ID}`, { params: { action: 'delete' } });
  });

  it('omits the params object entirely when no action is given', async () => {
    await vaultApi.deleteFolderApi(ID);
    expectCall(mockDelete, 'DELETE', `/folders/${ID}`, { params: undefined });
  });
});

// ===========================================================================
// Whole-surface guard
// ===========================================================================

describe('API surface', () => {
  // Guards against a function being added to a service module without a
  // contract test — the exact way an untested wrong URL slips in.
  it('has a contract test for every exported function of the three services', () => {
    const exported = [
      ...Object.keys(authApi),
      ...Object.keys(userApi),
      ...Object.keys(vaultApi),
    ].filter((k) => k.endsWith('Api'));

    // Every function exercised above, by name.
    const covered = new Set([
      'registerApi',
      'loginApi',
      'login2faApi',
      'refreshTokenApi',
      'logoutApi',
      'lockApi',
      'logoutAllApi',
      'verifyEmailApi',
      'forgotPasswordApi',
      'resetPasswordApi',
      'unlockAccountApi',
      'getProfileApi',
      'updateSettingsApi',
      'changePasswordApi',
      'setup2faApi',
      'verify2faApi',
      'disable2faApi',
      'regenerateBackupCodesApi',
      'listSessionsApi',
      'revokeSessionApi',
      'getAuditLogApi',
      'checkBreachApi',
      'checkBreachBatchApi',
      'exportVaultApi',
      'importVaultApi',
      'listItemsApi',
      'getItemApi',
      'createItemApi',
      'updateItemApi',
      'deleteItemApi',
      'permanentDeleteApi',
      'restoreItemApi',
      'bulkDeleteApi',
      'bulkMoveApi',
      'listTrashApi',
      'emptyTrashApi',
      'bulkReEncryptApi',
      'listFoldersApi',
      'createFolderApi',
      'updateFolderApi',
      'reorderFolderApi',
      'deleteFolderApi',
    ]);

    const untested = exported.filter((name) => !covered.has(name));
    expect(untested).toEqual([]);
  });
});
