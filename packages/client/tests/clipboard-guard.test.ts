import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

import { useClipboardGuard } from '../src/hooks/useClipboardGuard';
import {
  copySecretToClipboard,
  getClipboardGuardState,
  __resetClipboardGuardForTests,
} from '../src/services/clipboard/clipboardService';

// ---------------------------------------------------------------------------
// useClipboardGuard wires browser events to the clipboard guard. These tests
// run against the REAL service, because the contract worth protecting is the
// combination: which event does what to the pending secret.
//
// The regression these tests exist for: the guard used to erase the clipboard on
// every `visibilityState === 'hidden'` transition. Switching tabs or minimising
// is how a user goes to paste a password, so the app destroyed the value it had
// just given them. Hidden must now be inert.
// ---------------------------------------------------------------------------

const writeText = vi.fn<(text: string) => Promise<void>>();

const NOT_FOCUSED = new DOMException('Document is not focused.', 'NotAllowedError');

function setVisibility(state: DocumentVisibilityState): void {
  Object.defineProperty(document, 'visibilityState', {
    value: state,
    configurable: true,
  });
}

/**
 * `persisted` is defined on the event object rather than using
 * `new PageTransitionEvent(...)` so the test does not depend on jsdom shipping
 * that constructor.
 */
function pagehideEvent(persisted: boolean): Event {
  const event = new Event('pagehide');
  Object.defineProperty(event, 'persisted', { value: persisted, configurable: true });
  return event;
}

async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 6; i++) await Promise.resolve();
}

/** Copy a secret, then let its deadline lapse with the browser refusing the erase. */
async function copyAndLetDeadlineLapse(): Promise<void> {
  await copySecretToClipboard('s3cret', 30_000);
  writeText.mockRejectedValueOnce(NOT_FOCUSED);
  await vi.advanceTimersByTimeAsync(30_000);
  expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });
  writeText.mockClear();
}

beforeEach(() => {
  vi.useFakeTimers();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText },
    writable: true,
    configurable: true,
  });
  setVisibility('visible');
  __resetClipboardGuardForTests();
});

afterEach(() => {
  __resetClipboardGuardForTests();
  setVisibility('visible');
  vi.useRealTimers();
});

describe('useClipboardGuard', () => {
  // -------------------------------------------------------------------------
  // The regression: backgrounding the tab must be completely inert.
  // -------------------------------------------------------------------------
  describe('page hidden', () => {
    it('does NOT erase the clipboard when the tab is hidden', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        setVisibility('hidden');
        document.dispatchEvent(new Event('visibilitychange'));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    it('does NOT cancel the erase deadline when the tab is hidden', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      const deadlineAt = getClipboardGuardState().deadlineAt;

      await act(async () => {
        setVisibility('hidden');
        document.dispatchEvent(new Event('visibilitychange'));
        await flushMicrotasks();
      });
      expect(getClipboardGuardState().deadlineAt).toBe(deadlineAt);
      writeText.mockClear();

      // The secret is still erased on its own schedule, even though the tab was
      // backgrounded in the meantime. The old implementation cancelled this timer.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('survives repeated hide/show cycles before the deadline', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      for (let i = 0; i < 3; i++) {
        await act(async () => {
          setVisibility('hidden');
          document.dispatchEvent(new Event('visibilitychange'));
          setVisibility('visible');
          document.dispatchEvent(new Event('visibilitychange'));
          window.dispatchEvent(new Event('focus'));
          await flushMicrotasks();
        });
      }

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Retry when the document can write again.
  // -------------------------------------------------------------------------
  describe('regaining the ability to write', () => {
    it('retries a refused erase when the tab becomes visible', async () => {
      renderHook(() => useClipboardGuard());
      await copyAndLetDeadlineLapse();

      await act(async () => {
        setVisibility('visible');
        document.dispatchEvent(new Event('visibilitychange'));
        await flushMicrotasks();
      });

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('retries a refused erase when the window regains focus', async () => {
      renderHook(() => useClipboardGuard());
      await copyAndLetDeadlineLapse();

      await act(async () => {
        window.dispatchEvent(new Event('focus'));
        await flushMicrotasks();
      });

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    // The gap this closes: the guard used to be mounted inside AppLayout, which
    // ProtectedRoute unmounts the instant the vault locks. An auto-lock in a hidden
    // tab both refuses the erase and tears the listeners down, and after unlocking
    // no focus/visibilitychange fires because the document is already focused and
    // visible — so the overdue erase had no retry path left for the whole session.
    it('flushes an already-overdue erase on mount', async () => {
      // Deadline lapses and is refused with NO guard mounted (the lock screen).
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockRejectedValueOnce(NOT_FOCUSED);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(getClipboardGuardState()).toMatchObject({ pending: true, overdue: true });
      writeText.mockClear();

      // Mounting the guard (the remount after unlocking) must retry immediately
      // rather than waiting for an event that will never come.
      await act(async () => {
        renderHook(() => useClipboardGuard());
        await flushMicrotasks();
      });

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('does not erase on mount when nothing is due', async () => {
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        renderHook(() => useClipboardGuard());
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    // Firefox and Safari require transient user activation for EVERY clipboard
    // write, so a timer-driven or focus-driven erase can never succeed there. A
    // gesture-scoped retry is the only one those engines accept.
    it.each([
      ['pointerdown', () => document.dispatchEvent(new Event('pointerdown'))],
      ['keydown', () => document.dispatchEvent(new Event('keydown'))],
    ])(
      'retries a refused erase on %s (the only trigger Firefox/Safari accept)',
      async (_label, dispatch) => {
        renderHook(() => useClipboardGuard());
        await copyAndLetDeadlineLapse();

        await act(async () => {
          dispatch();
          await flushMicrotasks();
        });

        expect(writeText).toHaveBeenCalledExactlyOnceWith('');
        expect(getClipboardGuardState().pending).toBe(false);
      },
    );

    it('a gesture does not erase while the deadline is still in the future', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        document.dispatchEvent(new Event('pointerdown'));
        document.dispatchEvent(new Event('keydown'));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    it('does not erase on focus while the deadline is still in the future', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        await vi.advanceTimersByTimeAsync(10_000);
        window.dispatchEvent(new Event('focus'));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    it('ignores a visibilitychange that does not resolve to visible', async () => {
      renderHook(() => useClipboardGuard());
      await copyAndLetDeadlineLapse();

      await act(async () => {
        setVisibility('hidden');
        document.dispatchEvent(new Event('visibilitychange'));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // pagehide. Only the TERMINAL one erases: a bfcache entry may be restored
  // with its timers intact, so erasing there is the same premature wipe.
  // -------------------------------------------------------------------------
  describe('pagehide', () => {
    it('erases when the page is being discarded (persisted false)', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        window.dispatchEvent(pagehideEvent(false));
        await flushMicrotasks();
      });

      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      expect(getClipboardGuardState().pending).toBe(false);
    });

    it('does NOT erase when the page enters the back/forward cache (persisted true)', async () => {
      renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      writeText.mockClear();

      await act(async () => {
        window.dispatchEvent(pagehideEvent(true));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
      expect(getClipboardGuardState().pending).toBe(true);
    });

    it('does nothing on pagehide when no secret was copied', async () => {
      renderHook(() => useClipboardGuard());

      await act(async () => {
        window.dispatchEvent(pagehideEvent(false));
        await flushMicrotasks();
      });

      expect(writeText).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // Listener lifecycle
  // -------------------------------------------------------------------------
  describe('cleanup', () => {
    it('removes every listener on unmount', async () => {
      const { unmount } = renderHook(() => useClipboardGuard());
      await copySecretToClipboard('s3cret', 30_000);
      unmount();
      writeText.mockClear();

      // A pending secret is deliberately still there. With the listeners torn
      // down, none of the guard's events may reach the service.
      await act(async () => {
        window.dispatchEvent(pagehideEvent(false));
        window.dispatchEvent(new Event('focus'));
        document.dispatchEvent(new Event('pointerdown'));
        document.dispatchEvent(new Event('keydown'));
        setVisibility('visible');
        document.dispatchEvent(new Event('visibilitychange'));
        await flushMicrotasks();
      });
      expect(writeText).not.toHaveBeenCalled();

      // Control: the same event on a freshly mounted hook IS handled, which rules
      // out this passing merely because there was nothing to erase.
      const second = renderHook(() => useClipboardGuard());
      await act(async () => {
        window.dispatchEvent(pagehideEvent(false));
        await flushMicrotasks();
      });
      expect(writeText).toHaveBeenCalledExactlyOnceWith('');
      second.unmount();
    });
  });
});
