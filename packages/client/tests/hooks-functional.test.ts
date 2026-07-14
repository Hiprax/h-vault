/**
 * Functional renderHook tests for all four custom hooks.
 *
 * Hooks tested:
 * 1. useAutoLock       - Inactivity timer, activity reset, visibility change
 * 2. useKeyboardShortcuts - Ctrl/Cmd+key dispatch, input suppression
 * 3. useClipboardCountdown - Countdown toast with interval updates
 * 4. useUserSettings   - Fetch, cache, and reset user settings
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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
  useUserSettings,
  clearSettingsCache,
  onSettingsInvalidated,
} from '../src/hooks/useUserSettings';

// ===========================================================================
// 1. useAutoLock
// ===========================================================================

describe('useAutoLock', () => {
  const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
  const VISIBILITY_DELAY_MS = 30_000; // 30 seconds
  let mockLock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockLock = vi.fn().mockResolvedValue(undefined);

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

  it('should start 30s delayed lock on visibility hidden', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Simulate tab going hidden
    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    // Should NOT lock immediately
    expect(mockLock).not.toHaveBeenCalled();

    // Should NOT lock at 29 seconds
    vi.advanceTimersByTime(VISIBILITY_DELAY_MS - 1000);
    expect(mockLock).not.toHaveBeenCalled();

    // Should lock at 30 seconds
    vi.advanceTimersByTime(1000);
    expect(mockLock).toHaveBeenCalledTimes(1);

    // Restore
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });

  it('should cancel visibility lock timer when tab becomes visible', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Tab goes hidden
    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    // Advance partway through the 30s delay
    vi.advanceTimersByTime(15_000);
    expect(mockLock).not.toHaveBeenCalled();

    // Tab becomes visible again - should cancel the visibility timer
    act(() => {
      Object.defineProperty(document, 'hidden', { value: false, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    // Advance past the original 30s - should NOT lock
    vi.advanceTimersByTime(20_000);
    expect(mockLock).not.toHaveBeenCalled();

    // Restore
    Object.defineProperty(document, 'hidden', { value: false, configurable: true });
  });

  it('should cancel visibility lock timer on user activity', () => {
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });

    renderHook(() => useAutoLock());

    // Tab goes hidden
    act(() => {
      Object.defineProperty(document, 'hidden', { value: true, configurable: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });

    vi.advanceTimersByTime(10_000);

    // User interacts (e.g., mousemove) - should cancel visibility timer
    act(() => {
      document.dispatchEvent(new Event('mousemove'));
    });

    // Advance past the 30s visibility delay - should NOT lock from visibility timer
    vi.advanceTimersByTime(25_000);
    expect(mockLock).not.toHaveBeenCalled();

    // Restore
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

describe('useClipboardCountdown', () => {
  let mockToast: ReturnType<typeof vi.fn>;
  let mockDismiss: ReturnType<typeof vi.fn>;
  let mockUpdate: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockToast = vi.fn().mockReturnValue('toast-1');
    mockDismiss = vi.fn();
    mockUpdate = vi.fn();
    vi.mocked(useToast).mockReturnValue({
      toast: mockToast,
      dismiss: mockDismiss,
      update: mockUpdate,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // NOTE: a "should return startCountdown and stopCountdown functions" test was
  // removed here. It asserted only `typeof === 'function'` for both returns and
  // exercised no behavior — and it is fully subsumed by the behavioral tests
  // below, which CALL both functions (startCountdown at every it(), stopCountdown
  // in "stopCountdown should clear interval and dismiss toast"): if either were
  // not a function those tests would throw. The smoke test added runtime and no
  // signal.

  it('startCountdown should call toast with initial message', () => {
    const { result } = renderHook(() => useClipboardCountdown());

    act(() => {
      result.current.startCountdown(10);
    });

    expect(mockToast).toHaveBeenCalledTimes(1);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Clipboard will clear in 10s',
        type: 'info',
      }),
    );
  });

  it('startCountdown should update toast each second', () => {
    const { result } = renderHook(() => useClipboardCountdown());

    act(() => {
      result.current.startCountdown(5);
    });

    // After 1 second: remaining = 4
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-1', { title: 'Clipboard will clear in 4s' });

    // After 2 seconds: remaining = 3
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-1', { title: 'Clipboard will clear in 3s' });

    // After 3 seconds: remaining = 2
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-1', { title: 'Clipboard will clear in 2s' });
  });

  it('startCountdown should stop when remaining reaches 0', () => {
    const { result } = renderHook(() => useClipboardCountdown());

    act(() => {
      result.current.startCountdown(3);
    });

    // Advance 1s: remaining = 2 -> update
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-1', { title: 'Clipboard will clear in 2s' });

    // Advance 1s: remaining = 1 -> update
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-1', { title: 'Clipboard will clear in 1s' });

    // Advance 1s: remaining = 0 -> stopCountdown is called (dismiss)
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockDismiss).toHaveBeenCalledWith('toast-1');

    // No more updates should occur
    const updateCallCount = mockUpdate.mock.calls.length;
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(mockUpdate).toHaveBeenCalledTimes(updateCallCount);
  });

  it('stopCountdown should clear interval and dismiss toast', () => {
    const { result } = renderHook(() => useClipboardCountdown());

    act(() => {
      result.current.startCountdown(10);
    });

    act(() => {
      vi.advanceTimersByTime(2000);
    });

    act(() => {
      result.current.stopCountdown();
    });

    expect(mockDismiss).toHaveBeenCalledWith('toast-1');

    // No more updates after stop
    const updateCallCount = mockUpdate.mock.calls.length;
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(mockUpdate).toHaveBeenCalledTimes(updateCallCount);
  });

  it('starting a new countdown should clear the previous one', () => {
    mockToast.mockReturnValueOnce('toast-1').mockReturnValueOnce('toast-2');

    const { result } = renderHook(() => useClipboardCountdown());

    // Start first countdown
    act(() => {
      result.current.startCountdown(10);
    });

    act(() => {
      vi.advanceTimersByTime(2000);
    });

    // Start second countdown - should dismiss the first toast
    act(() => {
      result.current.startCountdown(5);
    });

    // The first toast should have been dismissed
    expect(mockDismiss).toHaveBeenCalledWith('toast-1');
    // A new toast was created
    expect(mockToast).toHaveBeenCalledTimes(2);
    expect(mockToast).toHaveBeenLastCalledWith(
      expect.objectContaining({
        title: 'Clipboard will clear in 5s',
      }),
    );

    // Now updates should reference 'toast-2'
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(mockUpdate).toHaveBeenCalledWith('toast-2', { title: 'Clipboard will clear in 4s' });
  });
});

// ===========================================================================
// 4. useUserSettings
// ===========================================================================

describe('useUserSettings', () => {
  const DEFAULT_SETTINGS = {
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  };

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
          settings: customSettings,
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result.current).toEqual(customSettings);
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
          settings: customSettings,
        },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    // First render - fetches from API
    const { result: result1 } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result1.current).toEqual(customSettings);
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);

    // Second render - should use cached settings without fetching again
    const { result: result2 } = renderHook(() => useUserSettings());

    expect(result2.current).toEqual(customSettings);
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
        data: { settings: firstSettings },
      },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());

    await waitFor(() => {
      expect(result.current).toEqual(firstSettings);
    });

    expect(getProfileApi).toHaveBeenCalledTimes(1);

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: { settings: secondSettings },
      },
    } as never);

    // Same-tab invalidation — no unmount/remount, no storage event.
    await act(async () => {
      clearSettingsCache();
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(result.current).toEqual(secondSettings);
    });

    expect(getProfileApi).toHaveBeenCalledTimes(2);
  });

  it('does not re-fetch on same-tab invalidation once logged out', async () => {
    const settings = { autoLockTimeout: 10, clipboardClearTimeout: 45, theme: 'light' };
    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings } },
    } as never);

    useAuthStore.setState({ isAuthenticated: true, isLocked: false });

    const { result } = renderHook(() => useUserSettings());
    await waitFor(() => {
      expect(result.current).toEqual(settings);
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
      resolveProfile({ data: { success: true, data: { settings: customSettings } } });
      await deferred;
    });

    // Both consumers receive the fetched settings off the single request.
    expect(result.current.a).toEqual(customSettings);
    expect(result.current.b).toEqual(customSettings);
    expect(getProfileApi).toHaveBeenCalledTimes(1);
  });

  it('re-fetches once on cross-tab settings invalidation and updates the consumer', async () => {
    const first = { autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' };
    const second = { autoLockTimeout: 5, clipboardClearTimeout: 10, theme: 'dark' };

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings: first } },
    } as never);

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      user: { userId: 'u-cross', email: 'a@b.c' },
    });

    const { result } = renderHook(() => useUserSettings());
    await waitFor(() => {
      expect(result.current).toEqual(first);
    });
    const callsAfterInit = vi.mocked(getProfileApi).mock.calls.length;

    vi.mocked(getProfileApi).mockResolvedValueOnce({
      data: { success: true, data: { settings: second } },
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
      expect(result.current).toEqual(second);
    });
    // The invalidation drops the in-flight pointer so exactly one re-fetch runs.
    expect(vi.mocked(getProfileApi).mock.calls.length).toBe(callsAfterInit + 1);
  });
});
