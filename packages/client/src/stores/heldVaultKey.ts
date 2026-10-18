/**
 * heldVaultKey: when rows will not open, is it because this session's vault key
 * was REPLACED?
 *
 * A rotation made in another session (another browser, a phone, a second tab)
 * re-wraps a NEW vault key under the same master key and signs nothing out. A
 * session that was open at the time keeps the superseded key in memory, so every
 * row the rotation rewrote fails to open: the vault reads as empty, "Re-sync"
 * refetches under the same key, and nothing says why. The unlock now loads the
 * account's live wrapper, so the remedy is to unlock again; this module is what
 * notices the condition while the session is still unlocked.
 *
 * ## What it does, and what it deliberately does not
 *
 * After a fetch reports rows it could not decrypt, `checkHeldVaultKey(failedKey)`
 * reads the profile, opens the account's wrapper with the master key this session
 * holds, and compares the key inside with the one that failed:
 *
 *   - the same key: the failures are genuine (a damaged row), and nothing changes,
 *     except that an INTERRUPTED rotation the profile reports raises a notice
 *     pointing at Settings, Finish Rotation, the one control that can help;
 *   - a different key, or a wrapper the master key cannot open: the session is
 *     holding a superseded key, so the vault LOCKS itself with the reason
 *     `vault-key-replaced`, and the unlock that follows loads the current key.
 *
 * It never adopts a key mid-session. Everything in memory was decrypted under the
 * held key, and re-deriving is a decision about the whole session (the doctrine at
 * `uiStore.noteStaleVaultKey`): the unlock is the one consistent starting point.
 *
 * Two exceptions raise the existing "sign in again" banner instead of locking. A
 * running document upload, because a lock aborts it and its completion already
 * recovers from a rotation by itself; and a second superseded verdict for the same
 * account wrapper, which would otherwise be a lock loop (an unlock that could not
 * read the live wrapper falls back to the cached one and finds the same key).
 *
 * ## Cost
 *
 * One profile read per held key at a time, shared by every fetch that fails
 * meanwhile, and a settled answer is reused for {@link HELD_KEY_RECHECK_MS}: a
 * damaged row costs at most one read a minute, while a rotation that commits after
 * a "same key" answer is still caught. An answer that could not be reached (the
 * read failed, the session had already moved on, this tab's own rotation is out)
 * is not kept; one reached for a key the session no longer holds is kept but never
 * acted on.
 */
import { isLiveTransfer, useDocumentsStore } from './documentsStore.js';
import { useAuthStore } from './authStore.js';
import { useUIStore } from './uiStore.js';
import { getProfileApi } from '../services/api/userApi.js';
import { holdsAccountVaultKey } from '../services/crypto/accountVaultKey.js';
import { logger } from '../lib/logger.js';

/** How long a reached answer about one held key is reused before it is asked again. */
export const HELD_KEY_RECHECK_MS = 60_000;

type Verdict =
  | { kind: 'unknown' }
  | { kind: 'current'; interruptedRotation: boolean }
  | { kind: 'superseded'; liveWrapper: string; liveVaultKeyVersion: number };

/** The wall clock, which dates every answer unless a test replaces it. */
const wallClock = (): number => Date.now();

/** The clock answers are dated by; replaceable so the recheck window is testable. */
let clock: () => number = wallClock;

/** Checks still running, so a caller (a test) can wait for every one of them. */
const running = new Set<Promise<void>>();

/** The check in flight for each held key, so concurrent failures share one read. */
let inFlight = new WeakMap<CryptoKey, Promise<void>>();

/** When a reached answer about each held key was given. */
let answeredAt = new WeakMap<CryptoKey, number>();

/** The account wrapper this session last locked itself for (the loop guard). */
let lockedForWrapper: string | null = null;

/** How many rotations this tab has out; while any is, no answer is reached. */
let ownRotations = 0;

/**
 * Asks, in the background, whether `failedKey` (the key a fetch just failed to
 * open rows with) is still the account's, and acts on the answer. Never throws.
 */
export function checkHeldVaultKey(failedKey: CryptoKey): void {
  if (inFlight.has(failedKey)) return;
  const answered = answeredAt.get(failedKey);
  if (answered !== undefined && clock() - answered < HELD_KEY_RECHECK_MS) return;

  const check = judge(failedKey)
    .then(async (verdict) => {
      if (verdict.kind !== 'unknown') answeredAt.set(failedKey, clock());
      await act(failedKey, verdict);
    })
    .catch((error: unknown) => {
      logger.warn('Could not check whether the vault key was replaced', error);
    })
    .finally(() => {
      inFlight.delete(failedKey);
      running.delete(check);
    });
  inFlight.set(failedKey, check);
  running.add(check);
}

/** Whether the store is still unlocked and holding exactly `key`. */
function stillHolding(key: CryptoKey): boolean {
  const { vaultKey, isLocked } = useAuthStore.getState();
  return vaultKey === key && !isLocked;
}

async function judge(failedKey: CryptoKey): Promise<Verdict> {
  const { mek } = useAuthStore.getState();
  if (ownRotations > 0 || !mek || !stillHolding(failedKey)) return { kind: 'unknown' };

  let profile;
  try {
    const body = (await getProfileApi()).data;
    if (!body.success) return { kind: 'unknown' };
    profile = body.data;
  } catch {
    return { kind: 'unknown' };
  }

  const wrapper = {
    encrypted: profile.encryptedVaultKey,
    iv: profile.vaultKeyIv,
    tag: profile.vaultKeyTag,
  };
  let holds: boolean;
  try {
    holds = await holdsAccountVaultKey(failedKey, wrapper, mek);
  } catch {
    // This session's master key no longer opens the account's key (the master
    // password changed elsewhere): nothing this session reads can be opened.
    holds = false;
  }
  // A rotation this tab started while the profile was being read makes the
  // comparison meaningless: the account may already be on the key it minted.
  if (ownRotations > 0) return { kind: 'unknown' };

  if (holds) return { kind: 'current', interruptedRotation: profile.interruptedRotation === true };
  return {
    kind: 'superseded',
    liveWrapper: `${wrapper.encrypted}|${wrapper.iv}|${wrapper.tag}`,
    // An account that has never rotated stores no generation, and is on 0.
    liveVaultKeyVersion: profile.vaultKeyVersion ?? 0,
  };
}

async function act(failedKey: CryptoKey, verdict: Verdict): Promise<void> {
  // An answer about a session that is gone (signed out, switched, locked while the
  // profile was being read) says nothing about the one now on screen.
  if (verdict.kind === 'unknown' || !stillHolding(failedKey)) return;
  const ui = useUIStore.getState();
  if (verdict.kind === 'current') {
    ui.setInterruptedRotationNotice(verdict.interruptedRotation);
    return;
  }

  const uploading = Object.values(useDocumentsStore.getState().uploads).some(isLiveTransfer);
  if (uploading || lockedForWrapper === verdict.liveWrapper) {
    ui.setStaleVaultKeyVersion(verdict.liveVaultKeyVersion);
    return;
  }
  lockedForWrapper = verdict.liveWrapper;
  await useAuthStore.getState().lock('vault-key-replaced');
}

/** Called by the rotation driver for as long as this tab's own rotation is out. */
export function beginOwnRotation(): void {
  ownRotations += 1;
}

/** Pairs {@link beginOwnRotation}, in a `finally`, on every way out. */
export function endOwnRotation(): void {
  ownRotations = Math.max(0, ownRotations - 1);
}

/**
 * Forgets every answer and guard. Called by logout, so the next session, on this
 * account or another, starts with nothing carried over.
 */
export function resetHeldVaultKeyChecks(): void {
  clock = wallClock;
  inFlight = new WeakMap();
  answeredAt = new WeakMap();
  lockedForWrapper = null;
  ownRotations = 0;
}

/** Waits for every check still running. For tests, which must not end mid-check. */
export async function settleHeldVaultKeyChecks(): Promise<void> {
  while (running.size > 0) {
    await Promise.allSettled([...running]);
  }
}

/** Replaces the clock answers are dated by. For tests of the recheck window. */
export function setHeldVaultKeyClock(next: () => number): void {
  clock = next;
}
