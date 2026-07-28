/**
 * Functional renderHook tests for all four custom hooks.
 *
 * Hooks tested:
 * 1. useAutoLock       - Inactivity timer, activity reset, visibility change
 * 2. useKeyboardShortcuts - Ctrl/Cmd+key dispatch, input suppression
 * 3. useClipboardCountdown - Countdown toast with interval updates
 * 4. useUserSettings   - Fetch, cache, and reset user settings
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom (required by Zustand / stores)
// ---------------------------------------------------------------------------

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    generateVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: vi.fn(),
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn(),
}));

vi.mock('@hvault/shared', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@hvault/shared');
  return {
    ...actual,
    KDF_ITERATIONS: 600_000,
    KDF_ALGORITHM: 'PBKDF2',
    ENCRYPTION_VERSION: 1,
  };
});

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { getProfileApi } from '../src/services/api/userApi';
import { useToast } from '../src/components/ui/Toast';
import { useAutoLock } from '../src/hooks/useAutoLock';
import { useKeyboardShortcuts } from '../src/hooks/useKeyboardShortcuts';
import { useClipboardCountdown } from '../src/hooks/useClipboardCountdown';
import {
  copySecretToClipboard,
  flushDueErase,
  __resetClipboardGuardForTests,
} from '../src/services/clipboard/clipboardService';
import {
  useUserSettings,
  clearSettingsCache,
  onSettingsInvalidated,
} from '../src/hooks/useUserSettings';
import {
  AUTO_LOCK_TIMEOUT_MINUTES,
  CLIPBOARD_CLEAR_SECONDS,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
} from '@hvault/shared';

// ===========================================================================
// 1. useAutoLock
// ===========================================================================

describe('useAutoLock', () => {
  const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
  /** The delay the OLD unconditional hidden lock used, kept only to prove it is gone. */
  const OLD_HIDDEN_DELAY_MS = 30_000;
  // Typed to the store's own `lock` signature so setState() accepts it.
  let mockLock: Mock<() => Promise<void>>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockLock = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);

    // Reset store to a clean unauthenticated state
    useAuthStore.setState({
      isAuthenticated: false,
      isLocked: false,
      lock: mockLock,
      vaultKey: null,
      mek: null,
      accessToken: null,
      user: null,
    });

    // useAutoLock now reads the timeout from the shared useUserSettings cache,
    // which is module-level — drop it so each test starts on a cold cache.
    // (Called while unauthenticated, so its listeners cannot trigger a fetch.)
    clearSettingsCache();

    // Default: getProfileApi rejects (so timeoutMsRef keeps default)
    vi.mocked(getProfileApi).mockRejectedValue(new Error('not configured'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should not set timer when not authenticated', () => {
    useAuthStore.setState({ isAuthenticated: false, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Advance past default timeout - lock should NOT be called
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS + 1000);
    expect(mockLock).not.toHaveBeenCalled();
  });

  it('should not set timer when locked', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: true, lock: mockLock });

    renderHook(() => useAutoLock());

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS + 1000);
    expect(mockLock).not.toHaveBeenCalled();
  });

  it('arms the inactivity timer at the correct duration when authenticated and not locked', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch so the timer is armed.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Just before the deadline it must NOT have fired (proves it's the full window)…
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 1000);
    expect(mockLock).not.toHaveBeenCalled();

    // …and exactly at the deadline it MUST fire. Asserting the positive edge is
    // what proves a timer was actually armed — the old test only checked the
    // not-yet-fired half, which stays green even if `resetTimer()` were removed
    // and no timer existed at all.
    vi.advanceTimersByTime(1000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should call lock() when timer expires', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should reset timer on mousemove activity', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Advance most of the way
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 2000);
    expect(mockLock).not.toHaveBeenCalled();

    // Trigger activity - this should reset the timer
    act(() => {
      document.dispatchEvent(new Event('mousemove'));
    });

    // Advance another DEFAULT_TIMEOUT_MS - 2000 - should NOT fire yet
    // because the timer was reset
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 2000);
    expect(mockLock).not.toHaveBeenCalled();

    // Advance the remaining 2000ms to expire the reset timer
    vi.advanceTimersByTime(2000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should reset timer on click activity', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 1000);

    act(() => {
      document.dispatchEvent(new Event('click'));
    });

    // Should not fire immediately after reset
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 1000);
    expect(mockLock).not.toHaveBeenCalled();

    // Now fire
    vi.advanceTimersByTime(1000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should reset timer on keydown activity', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);

    act(() => {
      document.dispatchEvent(new Event('keydown'));
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);
    expect(mockLock).not.toHaveBeenCalled();

    vi.advanceTimersByTime(500);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should reset timer on scroll activity', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);

    act(() => {
      document.dispatchEvent(new Event('scroll'));
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);
    expect(mockLock).not.toHaveBeenCalled();

    vi.advanceTimersByTime(500);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should reset timer on touchstart activity', async () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the settings fetch promise so the timer starts
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);

    act(() => {
      document.dispatchEvent(new Event('touchstart'));
    });

    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS - 500);
    expect(mockLock).not.toHaveBeenCalled();

    vi.advanceTimersByTime(500);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  /**
   * This test used to assert the bug. Hiding the tab armed a lock of
   * `Math.min(30_000, autoLockTimeout / 2)` — a flat 30 SECONDS for any timeout
   * above a minute — so switching tabs to look something up locked the vault,
   * whatever the user had configured. Hidden-tab locking is now opt-in
   * (`lockOnHidden`, default off) and carries its own delay; the idle deadline
   * alone governs otherwise, and it keeps running while hidden because nothing
   * generates activity events there.
   */
  it('does NOT lock a briefly hidden tab (the accelerated hidden lock is opt-in)', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    expect(mockLock).not.toHaveBeenCalled();

    // Four times the old hardcoded delay, and still nothing.
    act(() => {
      vi.advanceTimersByTime(OLD_HIDDEN_DELAY_MS * 4);
    });
    expect(mockLock).not.toHaveBeenCalled();

    // The idle deadline is untouched by hiding, so it still fires on schedule.
    act(() => {
      vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);

    // Restore
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });

  /**
   * These two tests used to assert `mockLock` was never called after hiding the
   * tab, in a world where hiding ARMED a 30-second lock. With hidden-tab locking
   * now opt-in and OFF by default, nothing arms a hidden lock at all — so those
   * assertions could no longer fail: they passed with `handleVisibilityChange`
   * deleted outright, which is the "assertion that cannot fail" anti-pattern.
   *
   * Retargeted at what the default path actually promises: hiding and revealing
   * must neither lock early NOR disturb the idle deadline, and the positive edge
   * is asserted so a timer really is still armed. The opt-in path's own behaviour
   * (including that a tab hidden past the delay locks on RETURN) is covered in
   * `coverage-auth-crypto.test.ts`, which can vary the setting.
   */
  it('hiding and revealing the tab does not lock, and does not reset the idle deadline', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    act(() => {
      vi.advanceTimersByTime(10 * 60 * 1000);
    });

    // Hide and reveal, well past the old 30-second hidden delay.
    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(mockLock).not.toHaveBeenCalled();

    act(() => {
      Object.defineProperty(document, 'hidden', { value: false, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(mockLock).not.toHaveBeenCalled();

    // The idle deadline was NOT reset by either transition: 11 minutes have now
    // passed with no activity, so the remaining 4 must still lock on schedule.
    // This is the positive edge that makes the negatives above meaningful.
    act(() => {
      vi.advanceTimersByTime(4 * 60 * 1000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('activity while the tab is hidden pushes the idle deadline out', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    act(() => {
      vi.advanceTimersByTime(14 * 60 * 1000);
    });
    act(() => {
      document.dispatchEvent(new Event('mousemove'));
    });

    // Past the ORIGINAL 15-minute deadline, short of the refreshed one.
    act(() => {
      vi.advanceTimersByTime(14 * 60 * 1000);
    });
    expect(mockLock).not.toHaveBeenCalled();

    // And it does still fire once the refreshed deadline arrives.
    act(() => {
      vi.advanceTimersByTime(2 * 60 * 1000);
    });
    expect(mockLock).toHaveBeenCalledTimes(1);

    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });

  it('should cleanup timers on unmount', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    const { unmount } = renderHook(() => useAutoLock());

    // Unmount the hook
    unmount();

    // Advance past timeout - lock should NOT fire since cleanup removed the timer
    vi.advanceTimersByTime(DEFAULT_TIMEOUT_MS + 5000);
    expect(mockLock).not.toHaveBeenCalled();
  });

  it('should apply the configured auto-lock timeout from user settings', async () => {
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: {
            autoLockTimeout: 5, // 5 minutes
          },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the profile fetch the settings cache issues
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(getProfileApi).toHaveBeenCalled();

    // The 5-minute timeout (not the 15-minute default) is now armed.
    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // Phase 10 (#16) — useAutoLock reuses the deduplicated useUserSettings cache
  // instead of issuing its own GET /profile calls.
  // -------------------------------------------------------------------------

  it('does not issue its own GET /profile — it shares the settings cache fetch', async () => {
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 5, clipboardClearTimeout: 30, theme: 'system' },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    // Call history accumulates across tests in this suite — start from a clean count.
    vi.mocked(getProfileApi).mockClear();

    // A settings consumer (e.g. a CopyField) and useAutoLock mounted together.
    // Before, useAutoLock fetched the profile itself on top of the shared cache;
    // now the cold-cache fetch is deduplicated into exactly one request.
    renderHook(() => {
      useUserSettings();
      useAutoLock();
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  it('issues NO fetch at all when the settings cache is already warm', async () => {
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 5, clipboardClearTimeout: 30, theme: 'system' },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    // Warm the shared cache with a settings consumer, then drop it.
    const warm = renderHook(() => useUserSettings());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    warm.unmount();

    vi.mocked(getProfileApi).mockClear();

    renderHook(() => useAutoLock());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // The cached value is used directly — no extra profile round-trip.
    expect(getProfileApi).not.toHaveBeenCalled();

    // ...and it is the cached 5-minute timeout, not the 15-minute default.
    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should re-fetch timeout when settings are invalidated (same-tab)', async () => {
    // Clear mock call history before this test
    vi.mocked(getProfileApi).mockReset();

    // Initial fetch returns 15 minutes
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 15 },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the initial settings fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const callCountAfterInit = vi.mocked(getProfileApi).mock.calls.length;

    // Now mock a new timeout value for the re-fetch
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 5 },
        },
      },
    } as never);

    // Trigger same-tab settings invalidation
    act(() => {
      clearSettingsCache();
    });

    // Flush the re-fetch promise
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Should have fetched again due to invalidation
    expect(vi.mocked(getProfileApi).mock.calls.length).toBeGreaterThan(callCountAfterInit);

    // The new 5-minute timeout should be active
    // Advance 5 minutes - should lock
    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('should re-fetch timeout on cross-tab storage event', async () => {
    // Clear mock call history before this test
    vi.mocked(getProfileApi).mockReset();

    // Initial fetch returns 15 minutes
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 15 },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the initial settings fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const callCountAfterInit = vi.mocked(getProfileApi).mock.calls.length;

    // Mock a new timeout for re-fetch
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 2 },
        },
      },
    } as never);

    // Simulate cross-tab storage event
    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: '__hv_settings_invalidated',
          newValue: Date.now().toString(),
        }),
      );
    });

    // Flush the re-fetch promise
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Should have re-fetched (at least one more call than after init)
    expect(vi.mocked(getProfileApi).mock.calls.length).toBeGreaterThan(callCountAfterInit);
  });

  it('should not re-fetch on unrelated storage events', async () => {
    // Clear mock call history before this test
    vi.mocked(getProfileApi).mockReset();

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: {
          settings: { autoLockTimeout: 15 },
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Flush the initial settings fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    const callCountAfterInit = vi.mocked(getProfileApi).mock.calls.length;

    // Simulate unrelated storage event
    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: 'some_other_key',
          newValue: 'something',
        }),
      );
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    // Should NOT have re-fetched - call count should remain the same
    expect(vi.mocked(getProfileApi).mock.calls.length).toBe(callCountAfterInit);
  });
});

// ===========================================================================
// 2. useKeyboardShortcuts
// ===========================================================================

describe('useKeyboardShortcuts', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should call callback on Ctrl+key', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }),
      );
    });

    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('should call callback on Meta+key (Cmd on Mac)', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ l: callback }));

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'l', metaKey: true, bubbles: true }),
      );
    });

    expect(callback).toHaveBeenCalledTimes(1);
  });

  it('should NOT call callback without modifier key', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: false, metaKey: false, bubbles: true }),
      );
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it('should NOT call callback when target is INPUT', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    const input = document.createElement('input');
    document.body.appendChild(input);

    act(() => {
      input.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }));
    });

    expect(callback).not.toHaveBeenCalled();
    document.body.removeChild(input);
  });

  it('should NOT call callback when target is TEXTAREA', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    const textarea = document.createElement('textarea');
    document.body.appendChild(textarea);

    act(() => {
      textarea.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }),
      );
    });

    expect(callback).not.toHaveBeenCalled();
    document.body.removeChild(textarea);
  });

  it('should NOT call callback when target is SELECT', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    const select = document.createElement('select');
    document.body.appendChild(select);

    act(() => {
      select.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }),
      );
    });

    expect(callback).not.toHaveBeenCalled();
    document.body.removeChild(select);
  });

  it('should NOT call callback when target is contentEditable', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    const div = document.createElement('div');
    div.contentEditable = 'true';
    // jsdom does not implement isContentEditable, so we define it manually
    Object.defineProperty(div, 'isContentEditable', { value: true, configurable: true });
    document.body.appendChild(div);

    act(() => {
      div.dispatchEvent(new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }));
    });

    expect(callback).not.toHaveBeenCalled();
    document.body.removeChild(div);
  });

  it('should call preventDefault when shortcut matches', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ k: callback }));

    const event = new KeyboardEvent('keydown', {
      key: 'k',
      ctrlKey: true,
      bubbles: true,
      cancelable: true,
    });
    const preventSpy = vi.spyOn(event, 'preventDefault');

    act(() => {
      document.dispatchEvent(event);
    });

    expect(preventSpy).toHaveBeenCalledTimes(1);
  });

  it('should NOT call preventDefault when shortcut does not match', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ k: callback }));

    const event = new KeyboardEvent('keydown', {
      key: 'z',
      ctrlKey: true,
      bubbles: true,
      cancelable: true,
    });
    const preventSpy = vi.spyOn(event, 'preventDefault');

    act(() => {
      document.dispatchEvent(event);
    });

    expect(preventSpy).not.toHaveBeenCalled();
  });

  it('should cleanup listener on unmount', () => {
    const callback = vi.fn();
    const { unmount } = renderHook(() => useKeyboardShortcuts({ n: callback }));

    unmount();

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }),
      );
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it('should handle multiple shortcuts simultaneously', () => {
    const callbackN = vi.fn();
    const callbackL = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callbackN, l: callbackL }));

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'n', ctrlKey: true, bubbles: true }),
      );
    });
    expect(callbackN).toHaveBeenCalledTimes(1);
    expect(callbackL).not.toHaveBeenCalled();

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'l', ctrlKey: true, bubbles: true }),
      );
    });
    expect(callbackL).toHaveBeenCalledTimes(1);
  });

  it('should match keys case-insensitively', () => {
    const callback = vi.fn();
    renderHook(() => useKeyboardShortcuts({ n: callback }));

    act(() => {
      document.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'N', ctrlKey: true, bubbles: true }),
      );
    });

    expect(callback).toHaveBeenCalledTimes(1);
  });
});

// ===========================================================================
// 3. useClipboardCountdown
// ===========================================================================
//
// The countdown is derived state: it subscribes to the clipboard guard rather
// than being started imperatively by each copy control. That is the fix for two
// defects. Copying two fields used to leave two independent countdowns running,
// and neither was cancelled when the clipboard was actually erased, so the UI
// kept promising a deadline for a clipboard that was already empty. These tests
// drive the REAL service so the number on screen is pinned to the real deadline.

describe('useClipboardCountdown', () => {
  // Typed off the real hook's contract so mockReturnValue() satisfies it.
  type ToastApi = ReturnType<typeof useToast>;
  let mockToast: Mock<ToastApi['toast']>;
  let mockDismiss: Mock<ToastApi['dismiss']>;
  let mockUpdate: Mock<ToastApi['update']>;
  let toastCounter = 0;
  const writeText = vi.fn<(text: string) => Promise<void>>();

  const NOT_FOCUSED = new DOMException('Document is not focused.', 'NotAllowedError');

  beforeEach(() => {
    vi.useFakeTimers();
    toastCounter = 0;
    mockToast = vi.fn<ToastApi['toast']>().mockImplementation(() => `toast-${++toastCounter}`);
    mockDismiss = vi.fn<ToastApi['dismiss']>();
    mockUpdate = vi.fn<ToastApi['update']>();
    vi.mocked(useToast).mockReturnValue({
      toast: mockToast,
      dismiss: mockDismiss,
      update: mockUpdate,
    });
    writeText.mockReset();
    writeText.mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    });
    __resetClipboardGuardForTests();
  });

  afterEach(() => {
    __resetClipboardGuardForTests();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('shows nothing until a secret is copied', () => {
    renderHook(() => useClipboardCountdown());

    expect(mockToast).not.toHaveBeenCalled();
  });

  it('opens one countdown toast when a secret is copied', async () => {
    renderHook(() => useClipboardCountdown());

    await act(async () => {
      await copySecretToClipboard('s3cret', 30_000);
    });

    expect(mockToast).toHaveBeenCalledTimes(1);
    expect(mockToast).toHaveBeenCalledWith({
      title: 'Clipboard will clear in 30s',
      type: 'info',
      duration: 31_000,
    });
  });

  it('updates the countdown every second', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 5_000);
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(mockUpdate).toHaveBeenLastCalledWith('toast-1', {
      title: 'Clipboard will clear in 4s',
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(mockUpdate).toHaveBeenLastCalledWith('toast-1', {
      title: 'Clipboard will clear in 3s',
    });
  });

  it('dismisses the countdown when the erase is confirmed', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 5_000);
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });

    expect(mockDismiss).toHaveBeenCalledWith('toast-1');
  });

  it('never counts down past zero', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 5_000);
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    const titles = mockUpdate.mock.calls.map((call) => (call[1] as { title: string }).title);
    expect(titles).not.toContain('Clipboard will clear in 0s');
  });

  it('a second copy replaces the countdown with the new deadline', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('A', 30_000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    await act(async () => {
      await copySecretToClipboard('B', 30_000);
    });

    // The stale countdown is torn down rather than left running alongside.
    expect(mockDismiss).toHaveBeenCalledWith('toast-1');
    expect(mockToast).toHaveBeenCalledTimes(2);
    expect(mockToast).toHaveBeenLastCalledWith({
      title: 'Clipboard will clear in 30s',
      type: 'info',
      duration: 31_000,
    });
  });

  it('replaces the countdown with a notice when the browser refuses the erase', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 5_000);
    });
    writeText.mockRejectedValueOnce(NOT_FOCUSED);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });

    expect(mockDismiss).toHaveBeenCalledWith('toast-1');
    expect(mockToast).toHaveBeenLastCalledWith({
      title: 'Clipboard not cleared yet — it will be cleared on your next action here',
      type: 'info',
      duration: 8_000,
    });
  });

  it('does not stack notices while the erase stays refused', async () => {
    renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 5_000);
    });
    writeText.mockRejectedValue(NOT_FOCUSED);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    const afterFirstRefusal = mockToast.mock.calls.length;

    // Drive the retry DIRECTLY rather than dispatching `focus`: useClipboardGuard is
    // not mounted here, so a focus event would reach no listener and the assertion
    // would hold whether or not the overdue guard works.
    await act(async () => {
      flushDueErase();
      await vi.advanceTimersByTimeAsync(1_000);
    });

    // The retry was genuinely attempted and refused again...
    expect(writeText.mock.calls.filter((call) => call[0] === '').length).toBeGreaterThan(1);
    // ...and it did not stack a second notice.
    expect(mockToast).toHaveBeenCalledTimes(afterFirstRefusal);
  });

  it('stops ticking and dismisses its toast on unmount', async () => {
    const { unmount } = renderHook(() => useClipboardCountdown());
    await act(async () => {
      await copySecretToClipboard('s3cret', 30_000);
    });
    mockUpdate.mockClear();

    unmount();

    expect(mockDismiss).toHaveBeenCalledWith('toast-1');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(mockUpdate).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// 4. useUserSettings
// ===========================================================================

describe('useUserSettings', () => {
  // Every default is the SHARED constant, not a literal restated here — the hook
  // sources them from `@hvault/shared` precisely so the client fallback and the
  // server model default cannot drift, and asserting against a hand-copied number
  // would defeat that.
  const DEFAULT_SETTINGS = {
    autoLockTimeout: AUTO_LOCK_TIMEOUT_MINUTES,
    lockOnHidden: LOCK_ON_HIDDEN_DEFAULT,
    lockOnHiddenDelay: LOCK_ON_HIDDEN_DELAY_MINUTES,
    clipboardClearTimeout: CLIPBOARD_CLEAR_SECONDS,
    theme: 'system',
  };

  /**
   * A profile response as the server actually sends one.
   *
   * `getProfile` normalises settings through `withSettingsDefaults` before
   * responding, so every field `IUserSettings` declares is present even for an
   * account created before it existed — a lean read returns raw BSON and does not
   * apply Mongoose defaults, which is why that normalisation exists. Fixtures here
   * mirror that, rather than omitting fields the API never omits.
   */
  function withNewDefaults(settings: Record<string, unknown>) {
    return {
      lockOnHidden: LOCK_ON_HIDDEN_DEFAULT,
      lockOnHiddenDelay: LOCK_ON_HIDDEN_DELAY_MINUTES,
      ...settings,
    };
  }

  beforeEach(() => {
    // Always clear the module-level cache between tests
    clearSettingsCache();

    // Reset store to clean state
    useAuthStore.setState({
      isAuthenticated: false,
      isLocked: false,
      lock: vi.fn().mockResolvedValue(undefined),
      vaultKey: null,
      mek: null,
      accessToken: null,
      user: null,
    });

    vi.mocked(getProfileApi).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return default settings initially', () => {
    useAuthStore.setState({ isAuthenticated: false, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    expect(result.current).toEqual(DEFAULT_SETTINGS);
  });

  it('passes a stored lockOnHidden through unchanged', async () => {
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: withNewDefaults({
            autoLockTimeout: 15,
            clipboardClearTimeout: 30,
            theme: 'system',
            lockOnHidden: true,
            lockOnHiddenDelay: 3,
          }),
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result.current.lockOnHidden).toBe(true);
    });
    expect(result.current.lockOnHiddenDelay).toBe(3);
  });

  it.each([
    ['zero', 0],
    ['negative', -5],
    ['above the maximum', 100_000],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('falls back to the default for a %s minutes value', async (_label, bad) => {
    // These arm REAL timers. The wire is validated on write, so this should never
    // fire — but the failure mode of a bad value is SILENT, not loud: `NaN`
    // compares false against every deadline test, so an auto-lock the user
    // configured would simply never happen, and `0` would lock on the next tick.
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: withNewDefaults({
            autoLockTimeout: bad,
            lockOnHiddenDelay: bad,
            clipboardClearTimeout: 30,
            theme: 'system',
          }),
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(getProfileApi).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(result.current.autoLockTimeout).toBe(AUTO_LOCK_TIMEOUT_MINUTES);
    });
    expect(result.current.lockOnHiddenDelay).toBe(LOCK_ON_HIDDEN_DELAY_MINUTES);
  });

  it('should fetch settings when authenticated and not locked', async () => {
    const customSettings = {
      autoLockTimeout: 30,
      clipboardClearTimeout: 60,
      theme: 'dark',
    };
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: withNewDefaults(customSettings),
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(customSettings));
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  it('should NOT fetch when not authenticated', () => {
    useAuthStore.setState({ isAuthenticated: false, isLocked: false });

    renderHook(() => useUserSettings());

    expect(getProfileApi).not.toHaveBeenCalled();
  });

  it('should NOT fetch when locked', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: true });

    renderHook(() => useUserSettings());

    expect(getProfileApi).not.toHaveBeenCalled();
  });

  it('should use cached settings on subsequent renders', async () => {
    const customSettings = {
      autoLockTimeout: 10,
      clipboardClearTimeout: 45,
      theme: 'light',
    };
    vi.mocked(getProfileApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          settings: withNewDefaults(customSettings),
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    // First render - fetches from API
    const { result: result1 } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result1.current).toEqual(withNewDefaults(customSettings));
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);

    // Second render - should use cached settings without fetching again
    const { result: result2 } = renderHook(() => useUserSettings());

    expect(result2.current).toEqual(withNewDefaults(customSettings));
    // Should still be 1 call total (no new fetch)
    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  // Phase 10 (#16): a same-tab `clearSettingsCache()` (a SettingsPage save) must
  // refresh consumers that are ALREADY MOUNTED. The cold-cache effect does not
  // re-run for them and the originating tab never receives its own `storage`
  // event, so the hook subscribes to `onSettingsInvalidated` and re-fetches.
  // useAutoLock relies on this — it no longer subscribes on its own behalf.
  it('clearSettingsCache should make an already-mounted consumer re-fetch and re-render', async () => {
    const firstSettings = {
      autoLockTimeout: 10,
      clipboardClearTimeout: 45,
      theme: 'light',
    };
    const secondSettings = {
      autoLockTimeout: 20,
      clipboardClearTimeout: 90,
      theme: 'dark',
    };

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: { settings: withNewDefaults(firstSettings) },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(firstSettings));
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: { settings: withNewDefaults(secondSettings) },
      },
    } as never);

    // Same-tab invalidation — no unmount/remount, no storage event.
    await act(async () => {
      clearSettingsCache();
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(secondSettings));
    });

    expect(getProfileApi).toHaveBeenCalledTimes(2);
  });

  it('does not re-fetch on same-tab invalidation once logged out', async () => {
    const settings = { autoLockTimeout: 10, clipboardClearTimeout: 45, theme: 'light' };
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings: withNewDefaults(settings) } },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());
    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(settings));
    });
    expect(getProfileApi).toHaveBeenCalledTimes(1);

    // `logout()` nulls the session BEFORE calling clearSettingsCache(); the
    // listener reads the store live, so it must not fire a doomed GET /profile.
    await act(async () => {
      useAuthStore.setState({ isAuthenticated: false, isLocked: false });
      clearSettingsCache();
      await Promise.resolve();
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  it('should keep default settings when API call fails', async () => {
    vi.mocked(getProfileApi).mockRejectedValue(new Error('Network error'));

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    // Wait for the effect to finish (the rejection is caught internally)
    await act(async () => {
      // Flush microtasks
      await Promise.resolve();
    });

    expect(result.current).toEqual(DEFAULT_SETTINGS);
  });

  it('onSettingsInvalidated should call listeners when clearSettingsCache is called', () => {
    const listener = vi.fn();
    const unsubscribe = onSettingsInvalidated(listener);

    clearSettingsCache();

    expect(listener).toHaveBeenCalledTimes(1);

    // Calling again should fire again
    clearSettingsCache();
    expect(listener).toHaveBeenCalledTimes(2);

    // After unsubscribe, should not be called
    unsubscribe();
    clearSettingsCache();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('clearSettingsCache should not throw when localStorage.setItem fails', () => {
    const orig = Storage.prototype.setItem;
    Storage.prototype.setItem = () => {
      throw new Error('quota exceeded');
    };
    try {
      expect(() => clearSettingsCache()).not.toThrow();
    } finally {
      Storage.prototype.setItem = orig;
    }
  });

  it('onSettingsInvalidated should support multiple listeners', () => {
    const listener1 = vi.fn();
    const listener2 = vi.fn();
    const unsub1 = onSettingsInvalidated(listener1);
    const unsub2 = onSettingsInvalidated(listener2);

    clearSettingsCache();

    expect(listener1).toHaveBeenCalledTimes(1);
    expect(listener2).toHaveBeenCalledTimes(1);

    // Unsubscribe only first
    unsub1();
    clearSettingsCache();
    expect(listener1).toHaveBeenCalledTimes(1);
    expect(listener2).toHaveBeenCalledTimes(2);

    unsub2();
  });

  // -------------------------------------------------------------------------
  // T23 — in-flight request dedup
  // -------------------------------------------------------------------------

  it('dedups concurrent first-mount consumers into a single GET /profile', async () => {
    const customSettings = {
      autoLockTimeout: 30,
      clipboardClearTimeout: 60,
      theme: 'dark',
    };

    // Deferred so both consumers mount on a cold cache before it resolves.
    let resolveProfile: (v: unknown) => void = () => {};
    const deferred = new Promise<unknown>((resolve) => {
      resolveProfile = resolve;
    });
    vi.mocked(getProfileApi).mockReturnValue(deferred as never);

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      user: { userId: 'u-dedup', email: 'a@b.c' },
    });

    // Two consumers mounted in the SAME commit (mirrors a vault item detail
    // that renders several CopyFields, each calling useUserSettings()).
    const { result } = renderHook(() => {
      const a = useUserSettings();
      const b = useUserSettings();
      return { a, b };
    });

    // Cold cache + concurrent mount must collapse to exactly one request.
    expect(getProfileApi).toHaveBeenCalledTimes(1);

    await act(async () => {
      resolveProfile({
        data: { success: true, data: { settings: withNewDefaults(customSettings) } },
      });
      await deferred;
    });

    // Both consumers receive the fetched settings off the single request.
    expect(result.current.a).toEqual(withNewDefaults(customSettings));
    expect(result.current.b).toEqual(withNewDefaults(customSettings));
    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  it('re-fetches once on cross-tab settings invalidation and updates the consumer', async () => {
    const first = { autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' };
    const second = { autoLockTimeout: 5, clipboardClearTimeout: 10, theme: 'dark' };

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings: withNewDefaults(first) } },
    } as never);

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      user: { userId: 'u-cross', email: 'a@b.c' },
    });

    const { result } = renderHook(() => useUserSettings());
    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(first));
    });
    const callsAfterInit = vi.mocked(getProfileApi).mock.calls.length;

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings: withNewDefaults(second) } },
    } as never);

    await act(async () => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: '__hv_settings_invalidated',
          newValue: '1',
        }),
      );
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(result.current).toEqual(withNewDefaults(second));
    });
    // The invalidation drops the in-flight pointer so exactly one re-fetch runs.
    expect(vi.mocked(getProfileApi).mock.calls.length).toBe(callsAfterInit + 1);
  });
});
