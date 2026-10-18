/**
 * A session that finds rows it cannot open asks whether the key it holds is still
 * the account's (`stores/heldVaultKey.ts`).
 *
 * The defect behind it: a rotation made in another session re-wraps a NEW vault
 * key under the same master key and signs nothing out, so a session that was open
 * at the time keeps decrypting with the superseded key. Every row the rotation
 * rewrote then fails to open, the vault reads as empty, and "Re-sync" refetches
 * under the same key. Nothing told the session why, or what would fix it.
 *
 * Real crypto throughout: the verdict is a comparison of real key bytes under a
 * real master key, and a mocked comparison would test the mock. The store is the
 * real `authStore`, so the lock that a superseded key triggers is the real lock.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

const mockGetProfileApi = vi.fn();
vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args) as unknown,
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue(undefined),
  lockApi: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../src/services/offlineCache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/offlineCache')>()),
  offlineCache: {
    setUser: vi.fn().mockResolvedValue(undefined),
    clear: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/health/healthResultsStore', () => ({
  clearHealthResults: vi.fn().mockResolvedValue(undefined),
}));

import { cryptoService } from '../src/services/crypto/cryptoService';
import { useAuthStore } from '../src/stores/authStore';
import { useUIStore } from '../src/stores/uiStore';
import { useDocumentsStore } from '../src/stores/documentsStore';
import { logger } from '../src/lib/logger';
import {
  HELD_KEY_RECHECK_MS,
  beginOwnRotation,
  checkHeldVaultKey,
  endOwnRotation,
  resetHeldVaultKeyChecks,
  setHeldVaultKeyClock,
  settleHeldVaultKeyChecks,
} from '../src/stores/heldVaultKey';

/** A real master key, without paying for PBKDF2. */
async function freshMek(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function freshVaultKey(): Promise<CryptoKey> {
  return cryptoService.importVaultKey(cryptoService.generateVaultKey());
}

/** The profile answer for an account whose stored wrapper is `key` under `mek`. */
async function profileHolding(
  key: CryptoKey,
  mek: CryptoKey,
  extra: Record<string, unknown> = {},
): Promise<unknown> {
  const wrapped = await cryptoService.encryptVaultKey(key, mek);
  return {
    data: {
      success: true,
      data: {
        encryptedVaultKey: wrapped.encrypted,
        vaultKeyIv: wrapped.iv,
        vaultKeyTag: wrapped.tag,
        vaultKeyVersion: 5,
        interruptedRotation: false,
        ...extra,
      },
    },
  };
}

let now = 1_000_000;
let mek: CryptoKey;
let heldKey: CryptoKey;

function unlockedSession(key: CryptoKey): void {
  useAuthStore.setState({
    user: { userId: 'user-1', email: 'vault@example.com' },
    isAuthenticated: true,
    isLocked: false,
    vaultKey: key,
    mek,
    accessToken: null,
    vaultKeyVersion: 3,
    lockReason: null,
  });
}

beforeEach(async () => {
  now = 1_000_000;
  setHeldVaultKeyClock(() => now);
  mek = await freshMek();
  heldKey = await freshVaultKey();
  unlockedSession(heldKey);
  useUIStore.setState({
    staleVaultKeyVersion: null,
    interruptedRotationNotice: false,
    unreadableEntriesNotice: false,
  });
  useDocumentsStore.setState({ uploads: {} });
  mockGetProfileApi.mockReset();
});

afterEach(async () => {
  await settleHeldVaultKeyChecks();
  resetHeldVaultKeyChecks();
  vi.restoreAllMocks();
});

describe('a session whose key the account has replaced', () => {
  it('locks itself with the reason, once, for three fetches failing together', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));

    checkHeldVaultKey(heldKey);
    checkHeldVaultKey(heldKey);
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(mockGetProfileApi).toHaveBeenCalledTimes(1);
    const state = useAuthStore.getState();
    expect(state.isLocked).toBe(true);
    expect(state.lockReason).toBe('vault-key-replaced');
    // A lock, never an adoption: no key is taken from the server mid-session.
    expect(state.vaultKey).toBeNull();
  });

  it('locks itself when its master key cannot open the account wrapper at all', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(heldKey, await freshMek()));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('does not lock the tab whose OWN rotation is out, and checks again once it is over', async () => {
    // Between the server's commit and this tab adopting the key it minted, a fetch
    // can see rows under the new key while the store still holds the old one.
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));

    beginOwnRotation();
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().isLocked).toBe(false);
    // Not even a profile read: nothing can be concluded while the tab is rotating.
    expect(mockGetProfileApi).not.toHaveBeenCalled();

    endOwnRotation();
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('does not lock when the session moved on while the profile was being read', async () => {
    const other = await freshVaultKey();
    mockGetProfileApi.mockImplementation(async () => {
      unlockedSession(other);
      return profileHolding(await freshVaultKey(), mek);
    });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().isLocked).toBe(false);
    expect(useAuthStore.getState().vaultKey).toBe(other);
  });

  it('raises the banner instead of locking while a document upload is running, and locks after it', async () => {
    // A lock aborts the upload, and its completion already recovers from a
    // rotation by itself, so the lock waits for it.
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    useDocumentsStore.setState({
      uploads: {
        u1: { id: 'u1', fileName: 'a.pdf', totalBytes: 10, sentBytes: 5, status: 'uploading' },
      },
    });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().isLocked).toBe(false);
    expect(useUIStore.getState().staleVaultKeyVersion).toBe(5);

    useDocumentsStore.setState({ uploads: {} });
    now += HELD_KEY_RECHECK_MS;
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('does not lock a second time for the same account wrapper; it shows the banner instead', async () => {
    // A guard against a loop: an unlock that could not read the live wrapper falls
    // back to the cached one, finds the same superseded key, and would lock again.
    const live = await profileHolding(await freshVaultKey(), mek);
    mockGetProfileApi.mockResolvedValue(live);

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');

    const reDerived = await freshVaultKey();
    unlockedSession(reDerived);
    checkHeldVaultKey(reDerived);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().isLocked).toBe(false);
    expect(useUIStore.getState().staleVaultKeyVersion).toBe(5);
  });

  it('forgets that guard on logout, so a later session can lock again', async () => {
    const live = await profileHolding(await freshVaultKey(), mek);
    mockGetProfileApi.mockResolvedValue(live);
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');

    await useAuthStore.getState().logout();
    const next = await freshVaultKey();
    unlockedSession(next);
    checkHeldVaultKey(next);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });
});

describe('the guards around the answer', () => {
  it('does not lock when this tab starts a rotation of its own while the profile is being read', async () => {
    const live = await profileHolding(await freshVaultKey(), mek);
    mockGetProfileApi.mockImplementationOnce(async () => {
      beginOwnRotation();
      return live;
    });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().isLocked).toBe(false);

    // Not remembered: once that rotation is over, the next failure asks again.
    endOwnRotation();
    mockGetProfileApi.mockResolvedValue(live);
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('never lets an unmatched end take the count below zero', async () => {
    // A spare `endOwnRotation` (a double `finally`) must not cancel the next
    // rotation's mark and let a check lock the tab that is rotating.
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    endOwnRotation();
    endOwnRotation();
    beginOwnRotation();

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().isLocked).toBe(false);

    endOwnRotation();
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('shows generation 0 in the banner for an account that stores none', async () => {
    const live = (await profileHolding(await freshVaultKey(), mek)) as {
      data: { data: Record<string, unknown> };
    };
    delete live.data.data['vaultKeyVersion'];
    mockGetProfileApi.mockResolvedValue(live);
    useDocumentsStore.setState({
      uploads: {
        u1: { id: 'u1', fileName: 'a.pdf', totalBytes: 10, sentBytes: 5, status: 'finalizing' },
      },
    });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useUIStore.getState().staleVaultKeyVersion).toBe(0);
    expect(useAuthStore.getState().isLocked).toBe(false);
  });

  it('raises no interrupted-rotation notice for a session that moved on while the profile was read', async () => {
    // Signed out (or switched) meanwhile: the answer is about a session that no
    // longer exists, and must not paint a notice over the next one.
    const other = await freshVaultKey();
    const answer = await profileHolding(heldKey, mek, { interruptedRotation: true });
    mockGetProfileApi.mockImplementation(async () => {
      unlockedSession(other);
      return answer;
    });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useUIStore.getState().interruptedRotationNotice).toBe(false);
  });

  it('survives a lock that fails, and after the window shows the banner rather than locking again', async () => {
    const realLock = useAuthStore.getState().lock;
    const failingLock = vi.fn().mockRejectedValue(new Error('the lock could not complete'));
    useAuthStore.setState({ lock: failingLock });
    try {
      mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));

      const warn = vi.spyOn(logger, 'warn');
      checkHeldVaultKey(heldKey);
      // Settles without an unhandled rejection: the failure is caught and logged.
      await settleHeldVaultKeyChecks();
      expect(warn).toHaveBeenCalledWith(
        'Could not check whether the vault key was replaced',
        expect.any(Error),
      );
      expect(failingLock).toHaveBeenCalledTimes(1);
      expect(failingLock).toHaveBeenCalledWith('vault-key-replaced');

      // The guard was set BEFORE the lock (whose first write locks the vault), so
      // the same account wrapper is never locked for twice: the next answer, once
      // the window has passed, raises the banner instead.
      now += HELD_KEY_RECHECK_MS;
      checkHeldVaultKey(heldKey);
      await settleHeldVaultKeyChecks();
      expect(mockGetProfileApi).toHaveBeenCalledTimes(2);
      expect(failingLock).toHaveBeenCalledTimes(1);
      expect(useUIStore.getState().staleVaultKeyVersion).toBe(5);
    } finally {
      useAuthStore.setState({ lock: realLock });
    }
  });
});

describe('the clock answers are dated by', () => {
  it('is the wall clock unless a test replaces it, and a reset restores it', async () => {
    resetHeldVaultKeyChecks();
    let wall = 5_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => wall);
    mockGetProfileApi.mockResolvedValue(await profileHolding(heldKey, mek));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    wall += HELD_KEY_RECHECK_MS - 1;
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(mockGetProfileApi).toHaveBeenCalledTimes(1);

    wall += 1;
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(mockGetProfileApi).toHaveBeenCalledTimes(2);
  });
});

describe('a session that holds the account key', () => {
  it('stays unlocked, and reads the profile again only after the recheck window', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(heldKey, mek));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().isLocked).toBe(false);
    expect(mockGetProfileApi).toHaveBeenCalledTimes(1);

    // One corrupt row must not cost a profile read on every fetch...
    now += HELD_KEY_RECHECK_MS - 1;
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(mockGetProfileApi).toHaveBeenCalledTimes(1);

    // ...but a rotation committed after the verdict must still be caught.
    now += 1;
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(mockGetProfileApi).toHaveBeenCalledTimes(2);
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('points at Finish Rotation when an interrupted rotation explains the failures, and clears it later', async () => {
    mockGetProfileApi.mockResolvedValue(
      await profileHolding(heldKey, mek, { interruptedRotation: true }),
    );
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useUIStore.getState().interruptedRotationNotice).toBe(true);
    // The rows may open under the key that rotation was moving to: they are not
    // offered for review as unreadable while it is outstanding.
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(false);
    expect(useAuthStore.getState().isLocked).toBe(false);

    now += HELD_KEY_RECHECK_MS;
    mockGetProfileApi.mockResolvedValue(await profileHolding(heldKey, mek));
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useUIStore.getState().interruptedRotationNotice).toBe(false);
  });

  it('offers the unreadable entries for review when the key is the account’s and nothing explains the failures', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(heldKey, mek));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useUIStore.getState().unreadableEntriesNotice).toBe(true);
    expect(useUIStore.getState().interruptedRotationNotice).toBe(false);
    expect(useAuthStore.getState().isLocked).toBe(false);
  });

  it('never offers the review for a key that was replaced elsewhere', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(false);
  });
});

describe('when the question cannot be answered', () => {
  it('does nothing on a failed profile read, and asks again at the next failure', async () => {
    mockGetProfileApi.mockRejectedValueOnce(new Error('offline'));

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();
    expect(useAuthStore.getState().isLocked).toBe(false);

    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(mockGetProfileApi).toHaveBeenCalledTimes(2);
    expect(useAuthStore.getState().lockReason).toBe('vault-key-replaced');
  });

  it('reads nothing while the session has no master key to judge with', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    useAuthStore.setState({ mek: null });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(mockGetProfileApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isLocked).toBe(false);
  });

  it('reads nothing for an unlocked session that already holds another key', async () => {
    mockGetProfileApi.mockResolvedValue(await profileHolding(await freshVaultKey(), mek));
    unlockedSession(await freshVaultKey());

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(mockGetProfileApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isLocked).toBe(false);
  });

  it('reads nothing for a locked session or one that no longer holds the key', async () => {
    useAuthStore.setState({ isLocked: true, vaultKey: null, mek: null });

    checkHeldVaultKey(heldKey);
    await settleHeldVaultKeyChecks();

    expect(mockGetProfileApi).not.toHaveBeenCalled();
  });
});
