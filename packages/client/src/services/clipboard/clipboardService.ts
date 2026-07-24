import {
  CLIPBOARD_CLEAR_MAX_SECONDS,
  CLIPBOARD_CLEAR_MIN_SECONDS,
  CLIPBOARD_CLEAR_SECONDS,
} from '@hvault/shared';

/**
 * App-wide clipboard hygiene for secrets copied out of the vault.
 *
 * ## Why this module exists, and the rule it must never break again
 *
 * A password manager's copy button only has value if the user can then LEAVE the
 * page to paste. Backgrounding the tab is therefore part of the happy path, not
 * a threat signal. An earlier implementation erased the clipboard on every
 * `visibilityState === 'hidden'` transition, which is exactly the gesture the
 * user makes to go and paste, so copying a password and switching tabs
 * destroyed it before it could be used.
 *
 * **Invariant 1: backgrounding never erases and never cancels the deadline.**
 * The only things that erase a copied secret are (a) its configured deadline
 * elapsing, (b) an explicit vault lock or logout, (c) the page being discarded
 * for good. Hiding, minimising, occlusion and OS lock screens do nothing here.
 *
 * ## The platform constraint that makes this non-trivial
 *
 * Chromium rejects `navigator.clipboard.writeText()` with `NotAllowedError`
 * ("Document is not focused.") whenever the document does not hold focus; the
 * check is in Blink's `ClipboardPromise::ValidatePreconditions`. So the one moment
 * we most want to erase, while the user is away in another application, is
 * precisely the moment the browser refuses to let us.
 *
 * Firefox and Safari are stricter still: they require transient user activation
 * for EVERY clipboard write, so on those engines a write issued from a timer or
 * from a `focus` handler can never succeed at all. That is why the retry is also
 * wired to a user gesture (see `useClipboardGuard`): a gesture-scoped retry is
 * the only one those engines will accept.
 *
 * The previous implementation issued the erase as fire-and-forget and marked the
 * clipboard clean BEFORE the write, so a refused erase silently became a
 * permanent leak: the deadline was already cancelled and the "clean" flag made
 * every later lock, logout and page-close a no-op, leaving the plaintext secret
 * on the OS clipboard indefinitely.
 *
 * **Invariant 2: state is only settled on a CONFIRMED erase.** A refused erase
 * keeps the secret pending, marks it `overdue`, and is retried at the next
 * moment the document can actually write: regaining focus, becoming visible, or
 * being discarded. Nothing is ever assumed to have worked.
 *
 * **Invariant 3: a copy and an erase are mutually exclusive, in both directions.**
 * A copy waits for an in-flight erase, and an erase defers to an in-flight copy.
 * Both halves are needed, because `pendingGeneration` still names the OLD secret
 * until a copy's write resolves: an erase started in that window passes its own
 * generation check and could land its empty string AFTER the new value. Deferred
 * work is never dropped: a copy that fails hands back the erase it deferred, and
 * an "erase now" that arrived mid-copy is honoured when the copy settles.
 *
 * ## Deliberate boundaries
 *
 * - **No cross-tab coordination.** State is per document, on purpose. Only the
 *   focused tab can write to the clipboard, the tab that made the copy may
 *   already be closed, and a tab that never copied anything has no deadline to
 *   honour and no way to know the clipboard still holds a secret. So a broadcast
 *   would have to be acted on by a tab with strictly less information than the
 *   one that armed the erase. The narrow gap this leaves (a secret copied in tab
 *   A while the user locks tab B) is documented in SECURITY.md rather than
 *   papered over.
 * - **The erase is unconditional, never conditional on a readback.** Confirming
 *   that the clipboard still holds our secret would require `clipboard-read`,
 *   which prompts the user and would leak the ability to read arbitrary
 *   clipboard contents. Writing an empty string blind needs write access only.
 * - **An overdue erase is retried for as long as the page lives.** It is flushed
 *   the instant the document can write again, which in practice is the moment the
 *   user comes back to H-Vault. Abandoning it after a timeout was considered and
 *   rejected: leaving a plaintext credential on the OS clipboard is the exact
 *   outcome this control exists to prevent.
 */

/** Snapshot of the guard, consumed by the countdown UI. */
export interface ClipboardGuardState {
  /** True while a secret copied through this service may still be on the clipboard. */
  pending: boolean;
  /** Epoch ms at which the secret is due to be erased; null when nothing is pending. */
  deadlineAt: number | null;
  /** True once an erase has been attempted and refused by the browser. */
  overdue: boolean;
}

type ClipboardGuardListener = (state: ClipboardGuardState) => void;

const MIN_CLEAR_MS = CLIPBOARD_CLEAR_MIN_SECONDS * 1_000;
const MAX_CLEAR_MS = CLIPBOARD_CLEAR_MAX_SECONDS * 1_000;
const DEFAULT_CLEAR_MS = CLIPBOARD_CLEAR_SECONDS * 1_000;

/**
 * Upper bound on a single clipboard write.
 *
 * A real write settles in milliseconds, so this never fires in practice. It
 * exists because an in-flight write gates the state machine in both directions:
 * an erase defers to a running copy and a copy defers to a running erase. A
 * promise that neither resolved nor rejected would therefore wedge BOTH paths
 * permanently and silently. A timed-out write is treated exactly like a refused
 * one: the secret stays pending and is retried later.
 */
const WRITE_TIMEOUT_MS = 10_000;

/** Monotonic id for each copy, so stale async outcomes can be recognised. */
let generation = 0;
/** Generation of the secret currently on the clipboard; null means clean. */
let pendingGeneration: number | null = null;
let deadlineAt: number | null = null;
let overdue = false;
let timer: ReturnType<typeof setTimeout> | null = null;
/**
 * The erase currently in flight, or null. Never rejects, so it is safe to await.
 * Doubles as a coalescing guard (one erase at a time) and as the barrier a new
 * copy waits on so an empty string cannot land after a freshly copied value.
 */
let eraseInFlight: Promise<void> | null = null;
/**
 * How many copies are mid-write. An erase must not run concurrently with a copy:
 * `pendingGeneration` still names the OLD secret until the copy's write resolves,
 * so an erase issued in that window passes its own generation check and can land
 * its empty string AFTER the new value, emptying the clipboard the user just
 * filled. A counter rather than a boolean because two copy controls can be
 * clicked in quick succession.
 */
let copiesInFlight = 0;
/**
 * An `eraseCopiedSecretNow()` (a lock, a logout, a terminal unload) that arrived
 * while a copy was mid-write and must be honoured once that copy settles.
 */
let eraseRequested = false;

const listeners = new Set<ClipboardGuardListener>();
let snapshot: ClipboardGuardState = { pending: false, deadlineAt: null, overdue: false };

/**
 * The DOM lib types `navigator.clipboard` as always present, but it is absent in
 * insecure contexts and in jsdom. Availability is probed with `'clipboard' in
 * navigator` inside a `try` around the `navigator` access, the same idiom
 * `getLockManager()` uses in the API client: an optional chain or a `typeof`
 * check would be reported as an unnecessary condition by the type-aware lint
 * rules.
 */
function getClipboardApi(): Clipboard | undefined {
  try {
    return 'clipboard' in navigator ? navigator.clipboard : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Raised when a write is abandoned at {@link WRITE_TIMEOUT_MS}. Distinct from a
 * refusal because the outcome is genuinely UNKNOWN: the browser may still land
 * the write afterwards, so the caller must assume the value reached the
 * clipboard. A refusal, by contrast, means the clipboard was definitely not
 * touched.
 */
class ClipboardWriteTimeoutError extends Error {
  constructor() {
    super('Clipboard write timed out');
    this.name = 'ClipboardWriteTimeoutError';
  }
}

async function writeClipboard(text: string): Promise<void> {
  const clipboard = getClipboardApi();
  if (!clipboard) throw new Error('Clipboard API is unavailable in this context');

  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      clipboard.writeText(text),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => {
          reject(new ClipboardWriteTimeoutError());
        }, WRITE_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

/**
 * Clamp the erase delay to the same bounds the wire schema enforces.
 *
 * The delay arrives from the profile response by way of `useUserSettings`, which
 * does not validate it. An out-of-range value would arm a real timer: `0` or a
 * negative number would erase the secret the user just copied on the next tick,
 * and a non-finite value would make `setTimeout` fire immediately. Both are
 * indistinguishable from the bug this module was written to fix, so the
 * scheduler refuses to trust the number.
 */
function clampClearDelay(ms: number): number {
  if (!Number.isFinite(ms)) return DEFAULT_CLEAR_MS;
  return Math.min(MAX_CLEAR_MS, Math.max(MIN_CLEAR_MS, Math.trunc(ms)));
}

function publish(): void {
  snapshot = { pending: pendingGeneration !== null, deadlineAt, overdue };
  for (const listener of listeners) {
    // A throwing subscriber must not reject the erase promise a copy awaits, nor
    // surface as a bogus copy failure.
    try {
      listener(snapshot);
    } catch {
      // A UI subscriber's failure is not the guard's problem.
    }
  }
}

function cancelTimer(): void {
  if (timer !== null) {
    clearTimeout(timer);
    timer = null;
  }
}

/**
 * Forget the pending secret. Only ever reached from a CONFIRMED successful
 * erase (invariant 2) or from an explicit test reset: never from a refused
 * write, a hidden transition, or an unload.
 */
function settleClean(): void {
  cancelTimer();
  pendingGeneration = null;
  deadlineAt = null;
  overdue = false;
  publish();
}

/**
 * Record that the browser refused an erase. The secret stays pending so the next
 * writable moment retries it. A still-armed deadline timer is deliberately left
 * running: it is a free extra retry.
 */
function markOverdue(): void {
  if (overdue) return;
  overdue = true;
  publish();
}

function attemptErase(): void {
  const target = pendingGeneration;
  if (target === null) return;
  if (eraseInFlight !== null) return;
  // A copy is mid-write. It is about to replace the clipboard contents and arm its
  // own deadline, so erasing now would destroy the value the user just asked for.
  // Skipping is correct rather than merely safe: whatever this erase was for is no
  // longer what the clipboard holds. If that copy FAILS, `copySecretToClipboard`
  // re-flushes so the erase this skipped is still honoured.
  if (copiesInFlight > 0) return;

  eraseInFlight = (async () => {
    let erased = false;
    try {
      await writeClipboard('');
      erased = true;
    } catch {
      // Refused (typically because the document is not focused) or the API is
      // unavailable. Either way the secret must be assumed to be still there.
      erased = false;
    }
    eraseInFlight = null;
    // Generation guard: a copy made while this erase was in flight owns the
    // clipboard now, and its own deadline must stand.
    //
    // Defense in depth, and currently unreachable: the two barriers above
    // (`copiesInFlight` here, `await running` in `copySecretToClipboard`) make the
    // two writes mutually exclusive, so `pendingGeneration` cannot change while an
    // erase is in flight. Kept deliberately rather than deleted, because it is the
    // check that keeps this correct if either barrier is ever relaxed. Not covered
    // by a test: a test that reached it would have to defeat the barriers, which is
    // the contrived-mock pattern this project avoids.
    if (pendingGeneration !== target) return;
    if (erased) settleClean();
    else markOverdue();
  })();
}

/** Whether a pending secret is past due and should be erased at the first chance. */
function isDue(): boolean {
  if (pendingGeneration === null) return false;
  if (overdue) return true;
  return deadlineAt !== null && Date.now() >= deadlineAt;
}

/**
 * Write a secret to the clipboard and arm its erase deadline.
 *
 * Every copy of vault-derived secret material must go through this function.
 * Writing to `navigator.clipboard` directly is what let the 2FA secret and the
 * backup codes on the settings page escape the guard entirely: they were never
 * auto-erased and lock/logout did not clear them.
 *
 * Rejects when the browser refuses the write, so the caller can surface a
 * "failed to copy" message. Nothing is marked pending unless the write resolved.
 */
export async function copySecretToClipboard(value: string, clearAfterMs: number): Promise<void> {
  // Do not race a running erase: an empty string landing after our value would
  // wipe the secret the user just asked for. In the common case nothing is in
  // flight, so this adds no delay and keeps the write inside the user gesture
  // that Firefox and Safari require.
  const running = eraseInFlight;
  if (running !== null) await running;

  copiesInFlight += 1;
  try {
    await writeClipboard(value);
  } catch (error) {
    copiesInFlight = Math.max(0, copiesInFlight - 1);
    if (error instanceof ClipboardWriteTimeoutError) {
      // The outcome is UNKNOWN: the browser may land this write after we stopped
      // waiting. Track it as though it succeeded. An untracked secret on the
      // clipboard, with no deadline and a lock/logout that no longer sees it, is
      // the exact failure this module exists to prevent; an erase of something
      // that never arrived is the already-accepted trade-off.
      armDeadline(clearAfterMs);
    } else {
      // A refusal means the clipboard was definitely not touched, so it still
      // holds whatever it held before. A previous secret may still be on it with
      // an erase that `attemptErase` skipped while this copy was in flight.
      settleDeferredErase();
    }
    throw error;
  }
  copiesInFlight = Math.max(0, copiesInFlight - 1);

  armDeadline(clearAfterMs);
}

/** Take ownership of the clipboard for a fresh secret and arm its deadline. */
function armDeadline(clearAfterMs: number): void {
  generation += 1;
  pendingGeneration = generation;
  overdue = false;
  cancelTimer();
  const delay = clampClearDelay(clearAfterMs);
  deadlineAt = Date.now() + delay;
  timer = setTimeout(() => {
    timer = null;
    attemptErase();
  }, delay);
  publish();
  settleDeferredErase();
}

/**
 * Run an erase that the copy barrier deferred.
 *
 * `eraseCopiedSecretNow()` is imperative: a lock or a logout means "the clipboard
 * must not keep holding a secret". If it arrives while a copy is mid-write the
 * barrier makes it a no-op, so it is recorded and honoured here instead. On the
 * success path that erases the value the copy just wrote, which is precisely what
 * a lock should do; downgrading it to "erase at the deadline" would leave a fresh
 * secret sitting behind the lock screen for up to five minutes.
 */
function settleDeferredErase(): void {
  if (!eraseRequested) {
    flushDueErase();
    return;
  }
  eraseRequested = false;
  eraseCopiedSecretNow();
}

/**
 * Erase a copied secret right now, ahead of its deadline.
 *
 * Used by vault lock, logout, and the terminal page-hide. Safe to call
 * unconditionally: it is a no-op when nothing was copied. If the browser refuses
 * the write, the secret stays pending and is retried at the next writable
 * moment rather than being forgotten.
 */
export function eraseCopiedSecretNow(): void {
  if (pendingGeneration === null) return;
  if (copiesInFlight > 0) {
    // The barrier would drop this write. Remember the request so the copy honours
    // it the moment it settles, instead of silently downgrading an explicit
    // "erase now" to "erase at the deadline".
    eraseRequested = true;
    return;
  }
  attemptErase();
}

/**
 * Retry an erase that is due but has not been performed.
 *
 * Called when the document regains focus or becomes visible, which is when the
 * browser will finally accept the write. Also covers the case where heavy
 * background-timer throttling delayed the deadline timer past its nominal fire
 * time while the tab was hidden.
 */
export function flushDueErase(): void {
  if (!isDue()) return;
  attemptErase();
}

export function getClipboardGuardState(): ClipboardGuardState {
  return snapshot;
}

export function subscribeClipboardGuard(listener: ClipboardGuardListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Test seam: drop all module state between cases. Mirrors the
 * `__setStrengthWorkerFactory` convention used by the vault-health analyzer.
 */
export function __resetClipboardGuardForTests(): void {
  cancelTimer();
  generation = 0;
  pendingGeneration = null;
  deadlineAt = null;
  overdue = false;
  eraseInFlight = null;
  copiesInFlight = 0;
  eraseRequested = false;
  listeners.clear();
  snapshot = { pending: false, deadlineAt: null, overdue: false };
}
