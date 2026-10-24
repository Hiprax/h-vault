/**
 * The auto-lock pause a full backup or full restore takes (0.22.0, the operator's
 * decision): forward progress recorded with `noteAutoLockProgress()` counts as
 * activity, but only progress made in a VISIBLE tab, and only while the page is
 * demonstrably alive (consecutive evaluations under a minute apart).
 *
 * Every test asserts the positive edge (the lock does fire, on time) next to the
 * negative one, so a hook that simply stopped locking could not pass.
 */
import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { renderHook, act } from '@testing-library/react';

const settings = { autoLockTimeout: 15, lockOnHidden: false, lockOnHiddenDelay: 1 };
vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => settings,
}));

import { useAuthStore } from '../src/stores/authStore';
import { noteAutoLockProgress, useAutoLock } from '../src/hooks/useAutoLock';

const MINUTE = 60_000;
const TIMEOUT = 15 * MINUTE;

function setHidden(hidden: boolean): void {
  Object.defineProperty(document, 'hidden', { value: hidden, configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
}

describe('noteAutoLockProgress', () => {
  let mockLock: Mock<() => Promise<void>>;

  // Each test starts a year after the one before, so progress a previous test
  // recorded is always older than this test's own start and cannot leak into it.
  let year = 2030;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.UTC(year, 0, 1)));
    year += 1;
    mockLock = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
    settings.lockOnHidden = false;
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });
  });

  afterEach(() => {
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
    vi.useRealTimers();
  });

  /** Advance `ms` in steps of `step`, recording progress at each step. */
  function progressFor(ms: number, step = 10_000): void {
    for (let elapsed = 0; elapsed < ms; elapsed += step) {
      act(() => {
        vi.advanceTimersByTime(step);
        noteAutoLockProgress();
      });
    }
  }

  it('keeps a visible tab unlocked while the job progresses, then locks one timeout after the last progress', () => {
    renderHook(() => useAutoLock());

    // Three whole timeouts of progress and no input at all.
    progressFor(3 * TIMEOUT);
    expect(mockLock).not.toHaveBeenCalled();

    // The job stops making progress: one timeout later, and not before, it locks.
    act(() => {
      vi.advanceTimersByTime(TIMEOUT - 30_000);
    });
    expect(mockLock).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('ignores progress recorded while the tab is hidden', () => {
    renderHook(() => useAutoLock());
    act(() => {
      setHidden(true);
    });

    progressFor(TIMEOUT - 10_000);
    expect(mockLock).not.toHaveBeenCalled();
    // The idle deadline was never moved, so it fires exactly on schedule.
    progressFor(10_000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('does not credit progress across a gap the page did not live through (a sleep)', () => {
    renderHook(() => useAutoLock());
    act(() => {
      vi.advanceTimersByTime(MINUTE);
    });

    // The machine sleeps past the deadline: the clock moves, no timer runs.
    vi.setSystemTime(Date.now() + TIMEOUT + MINUTE);
    // On wake the job's pending request completes first and records progress,
    // and only then does the page get its focus event.
    act(() => {
      noteAutoLockProgress();
      window.dispatchEvent(new Event('focus'));
    });

    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('still locks a hidden tab on the lock-on-hidden delay, whatever the job is doing', () => {
    settings.lockOnHidden = true;
    renderHook(() => useAutoLock());
    progressFor(MINUTE);

    act(() => {
      setHidden(true);
    });
    act(() => {
      vi.advanceTimersByTime(MINUTE - 20_000);
      noteAutoLockProgress();
    });
    expect(mockLock).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(20_000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('ignores progress stamped later than now (the clock was set back)', () => {
    renderHook(() => useAutoLock());
    // Five quiet minutes, then the job records progress, and before any evaluation
    // has merged it the clock is set back an hour.
    act(() => {
      vi.advanceTimersByTime(5 * MINUTE);
    });
    act(() => {
      noteAutoLockProgress();
      vi.setSystemTime(Date.now() - 60 * MINUTE);
      window.dispatchEvent(new Event('focus'));
    });

    // The deadline stays at the mount plus one timeout, which is now 70 minutes
    // away (the hook's activity mark itself predates the jump, as it always has).
    // Merging the future-stamped progress would have moved it to 75.
    act(() => {
      vi.advanceTimersByTime(70 * MINUTE - 20_000);
    });
    expect(mockLock).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(20_000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('counts progress made just before the tab is hidden, and nothing after it', () => {
    renderHook(() => useAutoLock());
    // No input for 10 minutes; then the job records progress and the tab is hidden.
    act(() => {
      vi.advanceTimersByTime(10 * MINUTE);
      noteAutoLockProgress();
      setHidden(true);
    });

    // The deadline is now that progress plus one timeout: 25 minutes in.
    act(() => {
      vi.advanceTimersByTime(TIMEOUT - 20_000);
    });
    expect(mockLock).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(20_000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);
  });
});
