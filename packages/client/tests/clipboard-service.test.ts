import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { advanceClockBy } from './clock.js';
import {
  copySecretToClipboard,
  eraseCopiedSecretNow,
  flushDueErase,
  getClipboardGuardState,
  subscribeClipboardGuard,
  __resetClipboardGuardForTests,
} from '../src/services/clipboard/clipboardService';

// ---------------------------------------------------------------------------
// The clipboard guard state machine.
//
// The bug this module replaces: the clipboard was erased on every transition to
// `visibilityState === 'hidden'`, i.e. on the exact gesture a user makes to go
// and paste, and the erase was fire-and-forget with the state marked clean
// BEFORE the write. So the same action either destroyed the password the user
// had just copied, or (when the browser refused the write, which it does for an
// unfocused document) silently abandoned the erase forever.
//
// These tests pin both halves: nothing erases early, and nothing is ever assumed
// to have been erased.
// ---------------------------------------------------------------------------

const writeText = vi.fn<(text: string) => Promise<void>>();

function setClipboard(value: unknown): void {
  Object.defineProperty(navigator, 'clipboard', {
    value,
    writable: true,
    configurable: true,
  });
}

function installClipboard(): void {
  setClipboard({ writeText });
}

/** Simulate an insecure context / a browser without the Async Clipboard API. */
function removeClipboard(): void {
  setClipboard(undefined);
}

/**
 * Drain the microtask queue. The erase is an async IIFE that awaits the write, so
 * its outcome lands a few ticks after the promise settles. Deliberately does not
 * advance fake timers: several tests must observe state WITHOUT letting a pending
 * deadline fire.
 */
async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 6; i++) await Promise.resolve();
}

const NOT_FOCUSED = new DOMException('Document is not focused.', 'NotAllowedError');

beforeEach(() => {
  vi.useFakeTimers();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  installClipboard();
  __resetClipboardGuardForTests();
});

afterEach(() => {
  __resetClipboardGuardForTests();
  vi.useRealTimers();
});

describe('clipboardService', () => {
  // -------------------------------------------------------------------------
  // Copy
  // -------------------------------------------------------------------------
  describe('copySecretToClipboard', () => {
    it('writes the secret and arms the configured deadline', async () => {
      await copySecretToClipboard('s3cret', 30_000);

      expect(writeText).toHaveBeenCalledExactlyOnceWith('s3cret');
      expect(getClipboardGuardState()).toEqual({
        pending: true,
        deadlineAt: Date.now() + 30_000,
        overdue: false,
      });
    });

    it('rejects and marks nothing pending when the write fails', async () => {
      writeText.mockRejectedValueOnce(NOT_FOCUSED);

      await expect(copySecretToClipboard('s3cret', 30_000)).rejects.toBe(NOT_FOCUSED);
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('rejects when the clipboard API is unavailable (insecure context)', async () => {
      removeClipboard();

      await expect(copySecretToClipboard('s3cret', 30_000)).rejects.toThrow(
        /Clipboard API is unavailable/,
      );
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('does not throw when reading navigator.clipboard itself throws', async () => {
      Object.defineProperty(navigator, 'clipboard', {
        get() {
          throw new Error('blocked by policy');
        },
        configurable: true,
      });

      await expect(copySecretToClipboard('s3cret', 30_000)).rejects.toThrow(
        /Clipboard API is unavailable/,
      );
    });

    it('the most recent copy owns the single deadline', async () => {
      // Copy A at t=0 with a 30s window.
      await copySecretToClipboard('A', 30_000);

      // Copy B at t=10s, also 30s → B must survive until t=40s.
      await vi.advanceTimersByTimeAsync(10_000);
      await copySecretToClipboard('B', 30_000);
      writeText.mockClear();

      // A's original deadline (t=30s) must not erase B ten seconds early.
      await vi.advanceTimersByTimeAsync(20_000);
      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);

      // B's own deadline (t=40s).
      await vi.advanceTimersByTimeAsync(10_000);
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('a copy waits for an in-flight erase so the empty string cannot land after it', async () => {
      await copySecretToClipboard('A', 5_000);

      const order: string[] = [];
      let releaseErase: (() => void) | undefined;
      writeText.mockImplementation((text: string) => {
        if (text === '') {
          order.push('erase');
          return new Promise<void>((resolve) => {
            releaseErase = resolve;
          });
        }
        order.push('copy');
        return Promise.resolve();
      });

      // A's deadline fires and the erase hangs mid-flight.
      await vi.advanceTimersByTimeAsync(5_000);
      expect(order).toEqual(['erase']);

      // A copy issued now must NOT write until that erase has settled, otherwise
      // the erase's empty string could land on top of the new secret.
      const copyB = copySecretToClipboard('B', 30_000);
      await flushMicrotasks();
      expect(order).toEqual(['erase']);

      releaseErase?.();
      await copyB;
      expect(order).toEqual(['erase', 'copy']);
      expect(getClipboardGuardState().pending).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Delay clamping.
  //
  // The delay comes from the profile response by way of useUserSettings, which
  // does not validate it. An unclamped 0 / NaN would erase the secret the user
  // just copied on the next tick, which is indistinguishable from the original
  // bug.
  // -------------------------------------------------------------------------
  describe('erase delay clamping', () => {
    it.each([
      ['below the minimum', 0, 5_000],
      ['a negative value', -60_000, 5_000],
      ['above the maximum', 1_000_000_000, 300_000],
      ['not a number', Number.NaN, 30_000],
      ['infinite', Number.POSITIVE_INFINITY, 30_000],
    ])('clamps %s to %ims', async (_label, given, expected) => {
      const start = Date.now();
      await copySecretToClipboard('s3cret', given);

      expect(getClipboardGuardState().deadlineAt).toBe(start + expected);
    });

    it('accepts an in-range delay unchanged', async () => {
      const start = Date.now();
      await copySecretToClipboard('s3cret', 45_000);

      expect(getClipboardGuardState().deadlineAt).toBe(start + 45_000);
    });
  });

  // -------------------------------------------------------------------------
  // The deadline
  // -------------------------------------------------------------------------
  describe('deadline erase', () => {
    it('erases exactly when the deadline elapses, not before', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await vi.advanceTimersByTimeAsync(29_999);
      expect(writeText).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState()).toEqual({
        pending: false,
        deadlineAt: null,
        overdue: false,
      });
    });

    it('does not erase again after the deadline has been served', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      await vi.advanceTimersByTimeAsync(30_000);
      writeText.mockClear();

      await vi.advanceTimersByTimeAsync(120_000);
      flushDueErase();
      eraseCopiedSecretNow();
      await flushMicrotasks();

      expect(writeText).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // A refused erase must never be mistaken for a completed one.
  //
  // This is the mirror-image half of the original defect: the state was marked
  // clean and the deadline cancelled BEFORE the write, so a refusal left the
  // plaintext secret on the OS clipboard with every later cleanup path
  // short-circuiting on a flag that claimed it was already gone.
  // -------------------------------------------------------------------------
  describe('refused erase', () => {
    it('keeps the secret pending and marks it overdue', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();
      writeText.mockRejectedValueOnce(NOT_FOCUSED);

      await vi.advanceTimersByTimeAsync(30_000);

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState()).toEqual({
        pending: true,
        deadlineAt: expect.any(Number) as number,
        overdue: true,
      });
    });

    it('is retried on the next flush and then settles clean', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockRejectedValueOnce(NOT_FOCUSED);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(getClipboardGuardState().overdue).toBe(true);
      writeText.mockClear();

      // The document regains focus: the browser will accept the write now.
      flushDueErase();
      await flushMicrotasks();

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('stays retriable across repeated refusals', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockRejectedValue(NOT_FOCUSED);
      await vi.advanceTimersByTimeAsync(30_000);

      flushDueErase();
      await flushMicrotasks();
      flushDueErase();
      await flushMicrotasks();

      // Still pending after three refusals — never silently abandoned.
      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });

      writeText.mockReset();
      writeText.mockResolvedValue(undefined);
      flushDueErase();
      await flushMicrotasks();
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('marks overdue when the clipboard API disappears before the deadline', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      removeClipboard();

      await vi.advanceTimersByTimeAsync(30_000);

      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });
    });

    it('notifies subscribers once when it becomes overdue, not on every retry', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockRejectedValue(NOT_FOCUSED);
      const listener = vi.fn();
      subscribeClipboardGuard(listener);

      await vi.advanceTimersByTimeAsync(30_000);
      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenLastCalledWith(
        expect.objectContaining({ pending: true, overdue: true }),
      );

      flushDueErase();
      await flushMicrotasks();
      expect(listener).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // flushDueErase — the retry entry point wired to focus / visible.
  //
  // The critical property is the negative one: coming BACK to the tab before the
  // deadline must not erase anything. That is what makes "copy, switch tab,
  // switch back, paste" work.
  // -------------------------------------------------------------------------
  describe('flushDueErase', () => {
    it('does nothing while the deadline is still in the future', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await vi.advanceTimersByTimeAsync(10_000);
      flushDueErase();
      await flushMicrotasks();

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    it('does nothing when no secret was copied', async () => {
      flushDueErase();
      await flushMicrotasks();

      expect(writeText).not.toHaveBeenCalled();
    });

    it('erases when the deadline passed while the deadline timer was throttled', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      // Chromium throttles timers in hidden tabs (once per minute under intensive
      // throttling), so the wall clock can pass the deadline before the timer
      // runs. Move the clock WITHOUT running the timer queue.
      advanceClockBy(31_000);
      flushDueErase();
      await flushMicrotasks();

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('coalesces concurrent flushes into a single write', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockRejectedValueOnce(NOT_FOCUSED);
      await vi.advanceTimersByTimeAsync(30_000);
      writeText.mockClear();

      let release: (() => void) | undefined;
      writeText.mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            release = resolve;
          }),
      );

      flushDueErase();
      flushDueErase();
      flushDueErase();
      await flushMicrotasks();

      expect(writeText).toHaveBeenCalledTimes(1);
      release?.();
      await flushMicrotasks();
      expect(getClipboardGuardState().pending).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // eraseCopiedSecretNow — vault lock, logout, terminal page-hide.
  // -------------------------------------------------------------------------
  describe('eraseCopiedSecretNow', () => {
    it('erases ahead of the deadline and cancels it', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      eraseCopiedSecretNow();
      await flushMicrotasks();

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);

      // The superseded deadline must not fire and clobber a later copy.
      writeText.mockClear();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(writeText).not.toHaveBeenCalled();
    });

    it('is a no-op when nothing was copied', async () => {
      eraseCopiedSecretNow();
      await flushMicrotasks();

      expect(writeText).not.toHaveBeenCalled();
    });

    it('keeps the secret pending when the browser refuses (auto-lock in a hidden tab)', async () => {
      await copySecretToClipboard('s3cret', 300_000);
      writeText.mockClear();
      writeText.mockRejectedValueOnce(NOT_FOCUSED);

      eraseCopiedSecretNow();
      await flushMicrotasks();

      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });

      // ...and the retry on return still erases it.
      writeText.mockClear();
      flushDueErase();
      await flushMicrotasks();
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Copy/erase mutual exclusion.
  //
  // `pendingGeneration` still names the OLD secret until a copy's write resolves,
  // so an erase started in that window passes its own generation check. Without a
  // symmetric barrier its empty string can land AFTER the freshly copied value,
  // emptying the clipboard the user just filled while the guard reports the new
  // secret as pending.
  // -------------------------------------------------------------------------
  describe('copy/erase mutual exclusion', () => {
    it('an erase triggered while a copy is mid-write does not run', async () => {
      await copySecretToClipboard('A', 5_000);

      const written: string[] = [];
      let releaseCopyB: (() => void) | undefined;
      writeText.mockImplementation((text: string) => {
        written.push(text);
        if (text === 'B') {
          return new Promise<void>((resolve) => {
            releaseCopyB = resolve;
          });
        }
        return Promise.resolve();
      });

      // Copy B starts and hangs mid-write.
      const copyB = copySecretToClipboard('B', 30_000);
      await flushMicrotasks();
      expect(written).toEqual(['B']);

      // A's deadline fires while B is still in flight. It must NOT issue an erase:
      // B is about to own the clipboard, so an empty string here would destroy it.
      await vi.advanceTimersByTimeAsync(5_000);
      expect(written).toEqual(['B']);

      releaseCopyB?.();
      await copyB;

      // B is pending with its own deadline, and nothing was erased.
      expect(written).toEqual(['B']);
      expect(getClipboardGuardState().pending).toBe(true);
      expect(getClipboardGuardState().overdue).toBe(false);
    });

    // A lock or logout is imperative: "the clipboard must not keep holding a
    // secret". The barrier must not silently downgrade that to "erase at the
    // deadline", which would leave a freshly copied secret behind the lock screen
    // for up to five minutes.
    it('an erase-now that arrives mid-copy is honoured once the copy lands', async () => {
      const written: string[] = [];
      let releaseCopy: (() => void) | undefined;
      writeText.mockImplementation((text: string) => {
        written.push(text);
        if (text === 'B') {
          return new Promise<void>((resolve) => {
            releaseCopy = resolve;
          });
        }
        return Promise.resolve();
      });
      await copySecretToClipboard('A', 300_000);

      const copyB = copySecretToClipboard('B', 300_000);
      await flushMicrotasks();
      expect(written).toEqual(['A', 'B']);

      // The vault locks while B's write is still in flight.
      eraseCopiedSecretNow();
      await flushMicrotasks();
      expect(written).toEqual(['A', 'B']);

      releaseCopy?.();
      await copyB;
      await flushMicrotasks();

      // B is erased, not left sitting behind the lock screen until its deadline.
      expect(written).toEqual(['A', 'B', '']);
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('an erase-now that arrives mid-copy is honoured when the copy FAILS', async () => {
      const written: string[] = [];
      let rejectCopy: ((error: Error) => void) | undefined;
      writeText.mockImplementation((text: string) => {
        written.push(text);
        if (text === 'B') {
          return new Promise<void>((_resolve, reject) => {
            rejectCopy = reject;
          });
        }
        return Promise.resolve();
      });
      await copySecretToClipboard('A', 300_000);

      const copyB = copySecretToClipboard('B', 300_000);
      await flushMicrotasks();
      eraseCopiedSecretNow();
      await flushMicrotasks();

      rejectCopy?.(new Error('refused'));
      await expect(copyB).rejects.toThrow('refused');
      await flushMicrotasks();

      // A is still on the clipboard and the lock's erase is still honoured.
      expect(written).toEqual(['A', 'B', '']);
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('a skipped erase is still honoured when the copy that deferred it FAILS', async () => {
      await copySecretToClipboard('A', 5_000);

      const written: string[] = [];
      let rejectCopyB: ((error: Error) => void) | undefined;
      writeText.mockImplementation((text: string) => {
        written.push(text);
        if (text === 'B') {
          return new Promise<void>((_resolve, reject) => {
            rejectCopyB = reject;
          });
        }
        return Promise.resolve();
      });

      const copyB = copySecretToClipboard('B', 30_000);
      await flushMicrotasks();

      // A's deadline is skipped because B is mid-write.
      await vi.advanceTimersByTimeAsync(5_000);
      expect(written).toEqual(['B']);

      // B fails, so the clipboard still holds A and A's erase is still owed.
      rejectCopyB?.(new Error('refused'));
      await expect(copyB).rejects.toThrow('refused');
      await flushMicrotasks();

      expect(written).toEqual(['B', '']);
      expect(getClipboardGuardState().pending).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Liveness: an in-flight write gates the state machine in both directions, so a
  // never-settling write must not wedge it permanently and silently.
  // -------------------------------------------------------------------------
  describe('write timeout', () => {
    it('treats a never-settling erase as a refusal instead of wedging', async () => {
      await copySecretToClipboard('s3cret', 5_000);
      writeText.mockClear();
      writeText.mockImplementationOnce(() => new Promise<void>(() => {}));

      await vi.advanceTimersByTimeAsync(5_000);
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      // Still wedged at this point: the write has neither resolved nor rejected.
      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: false });

      await vi.advanceTimersByTimeAsync(10_000);
      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });

      // And the machine is live again: a retry proceeds rather than being blocked
      // by the abandoned write.
      writeText.mockClear();
      writeText.mockResolvedValue(undefined);
      flushDueErase();
      await flushMicrotasks();
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    // A timed-out COPY is not a refusal: the browser may still land the write
    // after we stop waiting. Treating it as "nothing happened" would leave the
    // secret on the clipboard with no deadline and invisible to lock/logout.
    it('tracks a timed-out copy as pending, because the write may still land', async () => {
      writeText.mockImplementationOnce(() => new Promise<void>(() => {}));

      const copy = copySecretToClipboard('s3cret', 30_000);
      // Attach the rejection handler BEFORE advancing timers: the advance is what
      // rejects the promise, and an unhandled rejection in that tick would be
      // reported as a test-run error.
      const rejects = expect(copy).rejects.toThrow(/timed out/);
      await vi.advanceTimersByTimeAsync(10_000);
      await rejects;

      // The secret is tracked, so the deadline and lock/logout still cover it.
      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: false });
      writeText.mockClear();
      writeText.mockResolvedValue(undefined);
      eraseCopiedSecretNow();
      await flushMicrotasks();
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
    });

    it('a copy is not blocked forever by an abandoned erase', async () => {
      await copySecretToClipboard('A', 5_000);
      writeText.mockImplementationOnce(() => new Promise<void>(() => {}));
      await vi.advanceTimersByTimeAsync(5_000);

      // The copy awaits the in-flight erase; the timeout releases it.
      const copyB = copySecretToClipboard('B', 30_000);
      await vi.advanceTimersByTimeAsync(10_000);
      await expect(copyB).resolves.toBeUndefined();
      expect(getClipboardGuardState().pending).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Subscriber isolation
  // -------------------------------------------------------------------------
  describe('publish', () => {
    it('a throwing subscriber does not break the copy or the erase', async () => {
      subscribeClipboardGuard(() => {
        throw new Error('subscriber blew up');
      });

      await expect(copySecretToClipboard('s3cret', 5_000)).resolves.toBeUndefined();
      expect(getClipboardGuardState().pending).toBe(true);

      await vi.advanceTimersByTimeAsync(5_000);
      expect(getClipboardGuardState().pending).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Subscriptions
  // -------------------------------------------------------------------------
  describe('subscribeClipboardGuard', () => {
    it('publishes on copy and on a confirmed erase, and stops after unsubscribe', async () => {
      const listener = vi.fn();
      const unsubscribe = subscribeClipboardGuard(listener);

      await copySecretToClipboard('s3cret', 30_000);
      expect(listener).toHaveBeenLastCalledWith(
        expect.objectContaining({ pending: true, overdue: false }),
      );

      await vi.advanceTimersByTimeAsync(30_000);
      expect(listener).toHaveBeenLastCalledWith({
        pending: false,
        deadlineAt: null,
        overdue: false,
      });

      const callsBefore = listener.mock.calls.length;
      unsubscribe();
      await copySecretToClipboard('again', 30_000);
      expect(listener).toHaveBeenCalledTimes(callsBefore);
    });

    it('getClipboardGuardState returns a stable snapshot between changes', async () => {
      await copySecretToClipboard('s3cret', 30_000);

      expect(getClipboardGuardState()).toBe(getClipboardGuardState());
    });
  });
});
