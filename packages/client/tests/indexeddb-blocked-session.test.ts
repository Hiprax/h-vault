/**
 * Signing in, locking and signing out against the first IndexedDB schema bump.
 *
 * Four session transitions AWAIT an IndexedDB operation and carry on afterwards:
 * `login` and `verify2fa` scope and clear the offline cache before the session
 * state is written, `lock` clears it, and `logout` clears it and then the
 * encrypted health snapshot, with five teardown steps after those awaits. Every
 * one of them opens its database with `indexedDB.open(name, version)`, and an
 * open that asks for a higher version than another tab's live connection holds
 * is `blocked`: the engine fires that event and then WAITS, with no timeout, for
 * the other connection to close. A tab still running an older bundle never
 * closes it on request, so a handler that listens only for `success` and `error`
 * leaves the open pending for ever, and the transition with it: a sign-in that
 * never completes, a logout that never tears the session down.
 *
 * Nothing here substitutes the unit under test or either storage module. The
 * stores, `offlineCache` and `healthResultsStore` are real and run on the real
 * `fake-indexeddb` engine; the only change at the storage boundary is
 * `watchBlockedOpens`, which forwards every open to that engine one version
 * up, i.e. this bundle as it will behave once `DB_VERSION` is bumped.
 * The blocking connection is a genuine one held open at the current version
 * with no `versionchange` handler, the way an older tab holds it. What is mocked
 * is the network, the key derivation (a real 600,000-iteration PBKDF2 per case
 * would dominate the file and is pinned elsewhere) and the modules whose
 * teardown is asserted as a side effect. Only `setTimeout` is faked, so the
 * grace period can be run out without waiting for it; the engine runs on
 * `setImmediate` and keeps real time.
 */

import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  expectToSettle,
  openRawDatabase,
  outlastGracePeriod,
  watchBlockedOpens,
  withIndexedDB,
} from './indexeddbFailures.js';

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
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    decryptVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue(undefined),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  clearSettingsCache: vi.fn(),
}));

const mockLoggerWarn = vi.fn();
vi.mock('../src/lib/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: (...args: unknown[]) => mockLoggerWarn(...args),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

import { useAuthStore } from '../src/stores/authStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { loginApi, login2faApi } from '../src/services/api/authApi';
import { clearCsrfToken } from '../src/services/api/client';
import { clearSettingsCache } from '../src/hooks/useUserSettings';
import {
  BLOCKED_OPEN_GRACE_MS,
  deriveUserHash,
  offlineCache,
  OfflineCacheError,
} from '../src/services/offlineCache';

const OFFLINE_STORES = [
  { name: 'items', keyPath: '_id' },
  { name: 'folders', keyPath: '_id' },
  { name: 'meta', keyPath: 'key' },
] as const;
const HEALTH_STORES = [{ name: 'results', keyPath: 'key' }] as const;

const mockMek = {} as CryptoKey;
const mockVaultKey = {} as CryptoKey;

let userSeq = 0;
let held: IDBDatabase[] = [];

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  localStorage.removeItem('__hv_logout_event');
  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: mockMek,
    authKey: new ArrayBuffer(32),
  });
  vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new ArrayBuffer(32));
  vi.mocked(cryptoService.importVaultKey).mockResolvedValue(mockVaultKey);
});

afterEach(() => {
  vi.useRealTimers();
  // Release the "older tab", so the upgrades this file left waiting can finish.
  for (const db of held) db.close();
  held = [];
});

interface TestUser {
  userId: string;
  email: string;
  offlineDb: string;
  healthDb: string;
}

async function nextUser(): Promise<TestUser> {
  userSeq += 1;
  const userId = `blocked-session-user-${String(userSeq)}`;
  const hash = await deriveUserHash(userId);
  return {
    userId,
    email: `${userId}@example.com`,
    offlineDb: `hvault-offline-${hash}`,
    healthDb: `hvault-health-${hash}`,
  };
}

/** Put a user in the signed-in, unlocked state, with the offline cache scoped to them. */
async function signIn(user: TestUser): Promise<void> {
  await offlineCache.setUser(user.userId);
  useAuthStore.setState({
    isAuthenticated: true,
    isLocked: false,
    accessToken: 'access-token',
    user: { userId: user.userId, email: user.email },
    vaultKey: mockVaultKey,
    mek: mockMek,
  });
}

/** Hold a connection at the current version, the way a tab on an older bundle does. */
async function holdAsOlderTab(
  name: string,
  stores: readonly { name: string; keyPath: string }[],
): Promise<IDBDatabase> {
  const db = await openRawDatabase(name, 1, stores);
  held.push(db);
  return db;
}

/** An access token whose `sub` is `userId`, the only claim the store reads. */
function accessTokenFor(userId: string): string {
  return `${btoa(JSON.stringify({ alg: 'HS256' }))}.${btoa(JSON.stringify({ sub: userId }))}.sig`;
}

function loginResponseFor(userId: string) {
  return {
    data: {
      success: true,
      data: {
        accessToken: accessTokenFor(userId),
        encryptedVaultKey: 'enc-vk',
        vaultKeyIv: 'vk-iv',
        vaultKeyTag: 'vk-tag',
        kdfIterations: 600_000,
        kdfAlgorithm: 'PBKDF2-SHA256',
      },
    },
  };
}

/**
 * Start `transition` with this bundle one schema version ahead, run out one
 * grace period for each of the `blockedOpens` opens the engine reports blocked
 * in turn, and require the transition to settle.
 */
async function completeThroughBlockedOpens(
  transition: () => Promise<void>,
  blockedOpens: number,
  what: string,
): Promise<void> {
  const watch = watchBlockedOpens(indexedDB, { versionsAhead: 1 });
  await withIndexedDB(watch.factory, async () => {
    const running = transition();
    const settled = expectToSettle(running, what);
    for (let i = 0; i < blockedOpens; i++) await outlastGracePeriod(watch, BLOCKED_OPEN_GRACE_MS);
    await settled;
    await running;
  });
  // Exactly the opens expected were held up: a transition that skipped one of its
  // awaits entirely would reach the same end state without ever being tested.
  expect(watch.blocked).toBe(blockedOpens);
}

/** The error a given warning was logged with, asserting it was logged exactly once. */
function loggedCause(message: string): OfflineCacheError {
  const calls = mockLoggerWarn.mock.calls.filter((call) => call[0] === message);
  expect(calls).toHaveLength(1);
  const cause: unknown = calls[0]?.[1];
  expect(cause).toBeInstanceOf(OfflineCacheError);
  return cause as OfflineCacheError;
}

describe('logout while an older tab holds both IndexedDB databases open', () => {
  it('still returns, and still runs every teardown step after the two awaits', async () => {
    const user = await nextUser();
    await signIn(user);
    await holdAsOlderTab(user.offlineDb, OFFLINE_STORES);
    await holdAsOlderTab(user.healthDb, HEALTH_STORES);

    // Two opens are held up: the offline cache clear, then the health clear.
    await completeThroughBlockedOpens(() => useAuthStore.getState().logout(), 2, 'logout');

    // The session is gone and the steps AFTER the IndexedDB awaits all ran: a
    // bare "logout returned" would also pass if they had been skipped.
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().user).toBeNull();
    expect(clearSettingsCache).toHaveBeenCalledTimes(1);
    expect(clearCsrfToken).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem('__hv_logout_event')).not.toBeNull();

    // The offline cache refusal is reported as its classified cause, and the
    // health clear (which swallows by contract) does not surface at all.
    expect(loggedCause('Failed to clear offline cache during logout').type).toBe(
      'version_conflict',
    );
    expect(mockLoggerWarn).not.toHaveBeenCalledWith(
      'Failed to clear health results during logout',
      expect.anything(),
    );
  });

  it('leaves the older tab connection working: it is asked, never broken', async () => {
    const user = await nextUser();
    await signIn(user);
    const older = await holdAsOlderTab(user.offlineDb, OFFLINE_STORES);

    await completeThroughBlockedOpens(() => useAuthStore.getState().logout(), 1, 'logout');

    // The older tab still reads its own database: nothing here force-closed it,
    // and the upgrade did not run underneath it.
    expect(older.version).toBe(1);
    const read = await new Promise<unknown[]>((resolve, reject) => {
      const request = older.transaction('items').objectStore('items').getAll();
      request.onsuccess = () => resolve(request.result as unknown[]);
      request.onerror = () => reject(request.error ?? new Error('read failed'));
    });
    expect(read).toEqual([]);
  });
});

describe('signing in while an older tab holds the offline cache open', () => {
  it('login completes, and reports the cache it could not clear', async () => {
    const user = await nextUser();
    await holdAsOlderTab(user.offlineDb, OFFLINE_STORES);
    vi.mocked(loginApi).mockResolvedValue(loginResponseFor(user.userId) as never);

    await completeThroughBlockedOpens(
      () => useAuthStore.getState().login(user.email, 'Master123!'),
      1,
      'login',
    );

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLoading).toBe(false);
    expect(state.user).toEqual({ userId: user.userId, email: user.email });
    expect(state.vaultKey).toBe(mockVaultKey);
    expect(loggedCause('Failed to clear offline cache during login').type).toBe('version_conflict');
  });

  it('verify2fa completes, and reports the cache it could not clear', async () => {
    const user = await nextUser();
    await holdAsOlderTab(user.offlineDb, OFFLINE_STORES);
    useAuthStore.setState({
      isAuthenticated: false,
      isLocked: false,
      accessToken: null,
      twoFactorRequired: true,
      tempToken: 'temp-token',
      mek: mockMek,
      vaultKey: null,
      user: { userId: '', email: user.email },
    });
    vi.mocked(login2faApi).mockResolvedValue(loginResponseFor(user.userId) as never);

    await completeThroughBlockedOpens(
      () => useAuthStore.getState().verify2fa('123456'),
      1,
      'verify2fa',
    );

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLoading).toBe(false);
    expect(state.twoFactorRequired).toBe(false);
    expect(state.user).toEqual({ userId: user.userId, email: user.email });
    expect(loggedCause('Failed to clear offline cache during 2FA login').type).toBe(
      'version_conflict',
    );
  });
});

describe('locking while an older tab holds the offline cache open', () => {
  it('lock completes with the keys gone, and reports the cache it could not clear', async () => {
    const user = await nextUser();
    await signIn(user);
    await holdAsOlderTab(user.offlineDb, OFFLINE_STORES);

    await completeThroughBlockedOpens(() => useAuthStore.getState().lock(), 1, 'lock');

    const state = useAuthStore.getState();
    expect(state.isLocked).toBe(true);
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    // A lock keeps the session: it must not have been turned into a logout.
    expect(state.isAuthenticated).toBe(true);
    expect(clearCsrfToken).not.toHaveBeenCalled();
    expect(loggedCause('Failed to clear offline cache during lock').type).toBe('version_conflict');
  });
});
