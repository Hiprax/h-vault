import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { UnlockScreen } from '../src/components/auth/UnlockScreen';
import { useAuthStore } from '../src/stores/authStore';
import { api } from '../src/services/api/client';
import { cryptoService } from '../src/services/crypto/cryptoService';

// The client-side lockout (getLockoutDuration / applyLockout / persisted state)
// is module-scoped inside UnlockScreen and cannot be imported. It is exercised
// here by driving the REAL component through failed unlock attempts and
// asserting the rendered cooldown + persisted `__hv_unlock_lockout_until`, so a
// regression in the backoff (removing lockout, changing the base or the cap)
// turns these tests red.

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => vi.fn(),
  };
});

vi.mock('../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), {
    getState: vi.fn(),
    setState: vi.fn(),
  }),
}));

vi.mock('../src/services/api/client', () => ({
  api: {
    post: vi.fn(),
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
  // Matches the real fallback: with no Web Locks API (jsdom) the refresh runs
  // directly. Cross-tab serialization is covered by `refresh-multitab.test.ts`.
  withRefreshLock: <T,>(run: () => Promise<T>): Promise<T> => run(),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

describe('unlock rate limiting — client-side lockout (real component)', () => {
  const fakeMek = { __cryptoKey: 'mek' } as unknown as CryptoKey;
  const fakeAuthKey = new ArrayBuffer(32);
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();
  const mockSetAccessToken = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();

    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          user: { userId: 'user-1', email: 'vault@example.com' },
          unlock: mockUnlock,
          logout: mockLogout,
        };
        return selector ? selector(state) : state;
      },
    );
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: mockSetAccessToken,
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(useAuthStore.setState).mockImplementation(() => {});
    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: fakeMek,
      authKey: fakeAuthKey,
    });
    vi.mocked(cryptoService.getAuthHash).mockReturnValue('mock-auth-hash');
    vi.mocked(cryptoService.clearKey).mockReturnValue();
    vi.mocked(cryptoService.clearCryptoKey).mockResolvedValue();
    mockUnlock.mockResolvedValue(undefined);
  });

  /**
   * Submit one failed unlock: /auth/refresh succeeds so verify-unlock is
   * reached, then /auth/verify-unlock rejects (wrong master password). This is
   * the branch that increments the failure counter and calls applyLockout.
   */
  function submitFailedUnlock() {
    vi.mocked(api.post)
      .mockResolvedValueOnce({ data: { data: { accessToken: 'tok' } } })
      .mockRejectedValueOnce(new Error('Incorrect master password'));
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'wrong-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));
  }

  it('locks out for 2s the moment the failure threshold (5) is reached', async () => {
    // Seed 4 prior failures so the next one crosses the threshold: attempts = 5
    // → getLockoutDuration(5) = 2^0 * 2 = 2s.
    localStorage.setItem('__hv_unlock_failed_attempts', '4');

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    // Bracket the instant the component computes `until` (Date.now() + 2000
    // inside applyLockout, which runs asynchronously after the click). Asserting
    // against these captured bounds — rather than a fresh Date.now() read at
    // assertion time — makes the check robust to however long the async unlock
    // flow and re-render take under load, instead of silently budgeting a fixed
    // slack that a slow CI run can blow (a real wall-clock-timing flake).
    const before = Date.now();
    submitFailedUnlock();

    // The submit button reflects the real cooldown and is disabled.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /locked \(2s\)/i })).toBeInTheDocument();
    });
    const after = Date.now();

    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('5');
    expect(screen.getByRole('button', { name: /locked \(2s\)/i })).toBeDisabled();
    expect(localStorage.getItem('__hv_unlock_lockout_until')).not.toBeNull();

    // 2s lockout: `until` = T + 2000 for some T in [before, after].
    const until = Number(localStorage.getItem('__hv_unlock_lockout_until'));
    expect(until).toBeGreaterThanOrEqual(before + 2000);
    expect(until).toBeLessThanOrEqual(after + 2000);
  });

  it('caps the cooldown at 600s for a high failure count', async () => {
    // attempts = 14 → 2^(14-5) * 2 = 1024, capped at 600.
    localStorage.setItem('__hv_unlock_failed_attempts', '13');

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    // Bracket the instant the component computes `until` (Date.now() + 600_000
    // inside applyLockout). Asserting against these captured bounds — not a
    // fresh Date.now() at assertion time — is what keeps this deterministic:
    // the previous `until > Date.now() + 599_000` left only ~1s of budget for
    // the async unlock flow + re-render, which a loaded CI run exceeded, turning
    // a correct cap into a spurious failure.
    const before = Date.now();
    submitFailedUnlock();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /locked \(600s\)/i })).toBeInTheDocument();
    });
    const after = Date.now();

    // Capped at exactly 600s: `until` = T + 600_000 for some T in [before, after].
    // A larger cooldown (e.g. the uncapped 1024s) would exceed after+600_000; a
    // smaller one would fall below before+600_000.
    const until = Number(localStorage.getItem('__hv_unlock_lockout_until'));
    expect(until).toBeGreaterThanOrEqual(before + 600_000);
    expect(until).toBeLessThanOrEqual(after + 600_000);
  });

  it('does not lock out below the threshold (shows attempts-remaining instead)', async () => {
    // attempts = 3 → getLockoutDuration(3) = 0, so no cooldown is armed.
    localStorage.setItem('__hv_unlock_failed_attempts', '2');

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    submitFailedUnlock();

    await waitFor(() => {
      expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('3');
    });

    // No lockout persisted and the button is still actionable.
    expect(localStorage.getItem('__hv_unlock_lockout_until')).toBeNull();
    expect(screen.getByRole('button', { name: /unlock vault/i })).not.toBeDisabled();
    // 5 - 3 = 2 attempts remaining is surfaced to the user.
    expect(screen.getByText(/2 attempts remaining/i)).toBeInTheDocument();
  });
});

describe('unlock rate limiting — server-side API ordering', () => {
  const fakeMek = { __cryptoKey: 'mek' } as unknown as CryptoKey;
  const fakeAuthKey = new ArrayBuffer(32);
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();
  const mockSetAccessToken = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.removeItem('__hv_unlock_failed_attempts');
    localStorage.removeItem('__hv_unlock_lockout_until');

    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          user: { userId: 'user-1', email: 'vault@example.com' },
          unlock: mockUnlock,
          logout: mockLogout,
        };
        return selector ? selector(state) : state;
      },
    );

    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: mockSetAccessToken,
    } as unknown as ReturnType<typeof useAuthStore.getState>);

    vi.mocked(useAuthStore.setState).mockImplementation(() => {});

    vi.mocked(api.post).mockResolvedValue({
      data: { data: { accessToken: 'new-token-123' } },
    });

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: fakeMek,
      authKey: fakeAuthKey,
    });
    vi.mocked(cryptoService.getAuthHash).mockReturnValue('mock-auth-hash');
    vi.mocked(cryptoService.clearKey).mockReturnValue();
    vi.mocked(cryptoService.clearCryptoKey).mockResolvedValue();
  });

  it('hits /auth/verify-unlock before invoking the local vault key decrypt', async () => {
    mockUnlock.mockResolvedValue(undefined);

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'whatever-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/auth/verify-unlock',
        { authHash: 'mock-auth-hash' },
        { _skipAuthRefresh: true },
      );
    });

    await waitFor(() => {
      expect(mockUnlock).toHaveBeenCalled();
    });

    const apiPostMock = vi.mocked(api.post);
    const verifyCallIdx = apiPostMock.mock.calls.findIndex((c) => c[0] === '/auth/verify-unlock');
    const verifyOrder = apiPostMock.mock.invocationCallOrder[verifyCallIdx] ?? Infinity;
    const unlockOrder = mockUnlock.mock.invocationCallOrder[0] ?? 0;

    // Server-side rate limiter must see every wrong-password attempt — that
    // requires verify-unlock to fire BEFORE the local decryptVaultKey path.
    expect(verifyOrder).toBeLessThan(unlockOrder);
  });

  it('skips the local decrypt when verify-unlock returns 429', async () => {
    mockUnlock.mockResolvedValue(undefined);
    vi.mocked(api.post)
      .mockResolvedValueOnce({ data: { data: { accessToken: 'tok' } } })
      .mockRejectedValueOnce(new Error('Too Many Requests'));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'whatever' },
    });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/auth/verify-unlock',
        { authHash: 'mock-auth-hash' },
        { _skipAuthRefresh: true },
      );
    });

    expect(mockUnlock).not.toHaveBeenCalled();
  });
});
