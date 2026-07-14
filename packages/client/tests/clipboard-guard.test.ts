import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { act } from '@testing-library/react';

// ── Module under test ─────────────────────────────────────────────────

// Import the hook and helper functions
import {
  useClipboardGuard,
  markClipboardDirty,
  markClipboardClean,
  clearClipboardIfDirty,
  scheduleClipboardClear,
} from '../src/hooks/useClipboardGuard';

// ── Mock clipboard ────────────────────────────────────────────────────

const mockWriteText = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: mockWriteText },
    writable: true,
    configurable: true,
  });
});

afterEach(() => {
  // Cancel any timer a test armed on the module-level scheduler before the next
  // test runs (and wipe the dirty flag it may have left behind).
  clearClipboardIfDirty();
  markClipboardClean();
  mockWriteText.mockClear();
});

// ── Tests ─────────────────────────────────────────────────────────────

describe('useClipboardGuard', () => {
  describe('markClipboardDirty / markClipboardClean', () => {
    it('should mark clipboard as dirty then clean', () => {
      // Start clean — visibilitychange should not trigger clear
      renderHook(() => useClipboardGuard());

      act(() => {
        Object.defineProperty(document, 'visibilityState', {
          value: 'hidden',
          configurable: true,
        });
        document.dispatchEvent(new Event('visibilitychange'));
      });
      expect(mockWriteText).not.toHaveBeenCalled();

      // Mark dirty — visibilitychange should trigger clear
      markClipboardDirty();
      act(() => {
        document.dispatchEvent(new Event('visibilitychange'));
      });
      expect(mockWriteText).toHaveBeenCalledWith('');

      mockWriteText.mockClear();

      // Mark clean — should not trigger clear again
      markClipboardClean();
      act(() => {
        document.dispatchEvent(new Event('visibilitychange'));
      });
      expect(mockWriteText).not.toHaveBeenCalled();

      // Restore
      Object.defineProperty(document, 'visibilityState', {
        value: 'visible',
        configurable: true,
      });
    });
  });

  describe('visibilitychange listener', () => {
    it('should clear clipboard when page becomes hidden and clipboard is dirty', () => {
      renderHook(() => useClipboardGuard());
      markClipboardDirty();

      act(() => {
        Object.defineProperty(document, 'visibilityState', {
          value: 'hidden',
          configurable: true,
        });
        document.dispatchEvent(new Event('visibilitychange'));
      });

      expect(mockWriteText).toHaveBeenCalledWith('');

      // Restore
      Object.defineProperty(document, 'visibilityState', {
        value: 'visible',
        configurable: true,
      });
    });

    it('should NOT clear clipboard when page becomes visible', () => {
      renderHook(() => useClipboardGuard());
      markClipboardDirty();

      act(() => {
        Object.defineProperty(document, 'visibilityState', {
          value: 'visible',
          configurable: true,
        });
        document.dispatchEvent(new Event('visibilitychange'));
      });

      expect(mockWriteText).not.toHaveBeenCalled();
    });

    it('should NOT clear clipboard when clipboard is clean', () => {
      renderHook(() => useClipboardGuard());
      // Not calling markClipboardDirty

      act(() => {
        Object.defineProperty(document, 'visibilityState', {
          value: 'hidden',
          configurable: true,
        });
        document.dispatchEvent(new Event('visibilitychange'));
      });

      expect(mockWriteText).not.toHaveBeenCalled();

      // Restore
      Object.defineProperty(document, 'visibilityState', {
        value: 'visible',
        configurable: true,
      });
    });
  });

  describe('pagehide listener', () => {
    it('should clear clipboard on pagehide when dirty', () => {
      renderHook(() => useClipboardGuard());
      markClipboardDirty();

      act(() => {
        window.dispatchEvent(new Event('pagehide'));
      });

      expect(mockWriteText).toHaveBeenCalledWith('');
    });

    it('should NOT clear clipboard on pagehide when clean', () => {
      renderHook(() => useClipboardGuard());

      act(() => {
        window.dispatchEvent(new Event('pagehide'));
      });

      expect(mockWriteText).not.toHaveBeenCalled();
    });
  });

  describe('cleanup', () => {
    it('should remove event listeners on unmount', () => {
      const { unmount } = renderHook(() => useClipboardGuard());
      markClipboardDirty();
      unmount();

      mockWriteText.mockClear();

      // The dirty flag is STILL set. A pagehide now must do NOTHING: the only
      // listener was the unmounted hook's, and its cleanup removed it. If the
      // hook leaked its listener (no removeEventListener on unmount), this
      // dispatch would fire the leaked handler and wipe the clipboard — so this
      // assertion is what actually proves the listener was torn down.
      act(() => {
        window.dispatchEvent(new Event('pagehide'));
      });
      expect(mockWriteText).not.toHaveBeenCalled();

      // Control: the dirty flag is genuinely still set and the mechanism works —
      // a freshly mounted hook DOES handle the same event. This rules out the
      // assertion above passing merely because the clipboard was already clean.
      const { unmount: unmount2 } = renderHook(() => useClipboardGuard());
      act(() => {
        window.dispatchEvent(new Event('pagehide'));
      });
      expect(mockWriteText).toHaveBeenCalledWith('');
      unmount2();
    });
  });

  describe('error handling', () => {
    it('should not throw if clipboard.writeText rejects', () => {
      mockWriteText.mockRejectedValueOnce(new Error('NotAllowedError'));
      renderHook(() => useClipboardGuard());
      markClipboardDirty();

      expect(() => {
        act(() => {
          window.dispatchEvent(new Event('pagehide'));
        });
      }).not.toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // clearClipboardIfDirty — imperative wipe used by vault lock / logout.
  // The visibility/pagehide events never fire while the lock screen is shown
  // in a still-visible tab, so lock()/logout() must wipe on demand.
  // -----------------------------------------------------------------------
  describe('clearClipboardIfDirty', () => {
    it('wipes the clipboard when dirty, then is a no-op once clean', () => {
      markClipboardDirty();
      clearClipboardIfDirty();
      expect(mockWriteText).toHaveBeenCalledTimes(1);
      expect(mockWriteText).toHaveBeenCalledWith('');

      // Second call (clipboard now clean) must not write again.
      mockWriteText.mockClear();
      clearClipboardIfDirty();
      expect(mockWriteText).not.toHaveBeenCalled();
    });

    it('does nothing when the clipboard was never marked dirty', () => {
      clearClipboardIfDirty();
      expect(mockWriteText).not.toHaveBeenCalled();
    });

    it('does not throw when navigator.clipboard is unavailable (non-secure context)', () => {
      const original = navigator.clipboard;
      Object.defineProperty(navigator, 'clipboard', {
        value: undefined,
        writable: true,
        configurable: true,
      });
      try {
        markClipboardDirty();
        expect(() => clearClipboardIfDirty()).not.toThrow();
      } finally {
        Object.defineProperty(navigator, 'clipboard', {
          value: original,
          writable: true,
          configurable: true,
        });
      }
    });
  });

  // -----------------------------------------------------------------------
  // scheduleClipboardClear — the single app-wide auto-clear timer.
  //
  // Every copy control (CopyField, TotpDisplay, PasswordGenerator) schedules
  // through this one timer. When each owned its own, an earlier field's timer
  // survived a later copy and wiped the newer value ahead of its own deadline.
  // -----------------------------------------------------------------------
  describe('scheduleClipboardClear', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('wipes the clipboard when the scheduled delay elapses', () => {
      markClipboardDirty();
      scheduleClipboardClear(30_000);

      vi.advanceTimersByTime(29_999);
      expect(mockWriteText).not.toHaveBeenCalled();

      vi.advanceTimersByTime(1);
      expect(mockWriteText).toHaveBeenCalledTimes(1);
      expect(mockWriteText).toHaveBeenCalledWith('');
    });

    it('copying field A then field B leaves B on the clipboard until B’s own deadline', () => {
      // Copy A at t=0 with a 30s clear window.
      markClipboardDirty();
      scheduleClipboardClear(30_000);

      // Copy B at t=10s, also with a 30s window → B must survive until t=40s.
      vi.advanceTimersByTime(10_000);
      markClipboardDirty();
      scheduleClipboardClear(30_000);

      // A's original deadline (t=30s) passes: the old behavior wiped B here,
      // 10 seconds early. The shared timer must NOT fire.
      vi.advanceTimersByTime(20_000);
      expect(mockWriteText).not.toHaveBeenCalled();

      // B's own deadline (t=40s) — now it is wiped, exactly once.
      vi.advanceTimersByTime(10_000);
      expect(mockWriteText).toHaveBeenCalledTimes(1);
      expect(mockWriteText).toHaveBeenCalledWith('');
    });

    it('a shorter window scheduled after a longer one takes over the deadline', () => {
      markClipboardDirty();
      scheduleClipboardClear(60_000);

      // The most recent copy always owns the deadline — even a shorter one.
      scheduleClipboardClear(5_000);

      vi.advanceTimersByTime(5_000);
      expect(mockWriteText).toHaveBeenCalledTimes(1);

      // The superseded 60s timer must never fire.
      vi.advanceTimersByTime(60_000);
      expect(mockWriteText).toHaveBeenCalledTimes(1);
    });

    it('clearClipboardIfDirty cancels a pending scheduled clear (lock/logout)', () => {
      markClipboardDirty();
      scheduleClipboardClear(30_000);

      // Vault lock wipes immediately...
      clearClipboardIfDirty();
      expect(mockWriteText).toHaveBeenCalledTimes(1);

      // ...and the pending timer is cancelled, so it cannot wipe a value the
      // user copies after unlocking.
      mockWriteText.mockClear();
      vi.advanceTimersByTime(60_000);
      expect(mockWriteText).not.toHaveBeenCalled();
    });

    it('does not re-wipe a clipboard the guard already cleaned', () => {
      markClipboardDirty();
      scheduleClipboardClear(30_000);

      // The page-hidden guard wipes early and marks the clipboard clean.
      renderHook(() => useClipboardGuard());
      act(() => {
        window.dispatchEvent(new Event('pagehide'));
      });
      expect(mockWriteText).toHaveBeenCalledTimes(1);

      // The clear is dirty-gated, so nothing the user copied afterwards outside
      // the app gets clobbered by a stale timer.
      mockWriteText.mockClear();
      vi.advanceTimersByTime(60_000);
      expect(mockWriteText).not.toHaveBeenCalled();
    });
  });
});
