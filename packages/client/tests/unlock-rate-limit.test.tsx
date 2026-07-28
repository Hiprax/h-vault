import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { AxiosError, AxiosHeaders } from 'axios';
import { UnlockScreen } from '../src/components/auth/UnlockScreen';
import { useAuthStore } from '../src/stores/authStore';
import { api, performTokenRefresh } from '../src/services/api/client';
import { cryptoService } from '../src/services/crypto/cryptoService';

/**
 * Build a real `AxiosError` carrying `status`, so the component's failure
 * classification (`isSessionGone` / `describeTransientFailure`) runs against the
 * same shape it sees in production. A bare `new Error()` is NOT interchangeable
 * here: `isAxiosError` returns false for it, so every classifier would report
 * "not transient, not session-gone" and the test would pass through the default
 * branch regardless of what the code does.
 */
function axiosStatusError(status: number, headers: Record<string, string> = {}): AxiosError {
  const err = new AxiosError('Request failed with status code ' + String(status));
  err.response = {
    status,
    statusText: '',
    data: {},
    headers: new AxiosHeaders(headers),
    config: { headers: new AxiosHeaders() },
  };
  return err;
}

/** An Axios error with no `response` at all — the offline / DNS-failure shape. */
function axiosNetworkError(): AxiosError {
  return new AxiosError('Network Error');
}

// The client-side lockout (getLockoutDuration / applyLockout / persisted state)
// is module-scoped inside UnlockScreen and cannot be imported. It is exercised
// here by driving the REAL component through failed unlock attempts and
// asserting the rendered cooldown + persisted `__hv_unlock_lockout_until`, so a
// regression in the backoff (removing lockout, changing the base or the cap)
// turns these tests red.

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
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
  // `performTokenRefresh` is the ONE refresh path; the unlock screen calls it
  // directly instead of hand-rolling a locked POST. Cross-tab serialization,
  // envelope validation and CSRF invalidation are its concern and are covered by
  // `refresh-multitab.test.ts`.
  performTokenRefresh: vi.fn(),
  withRefreshLock: <T,>(run: () => Promise<T>): Promise<T> => run(),
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

// The store's own `AuthState` is module-private, so derive it: the hook is
// called with a selector over the FULL state and nothing narrower type-checks.
type AuthState = ReturnType<typeof useAuthStore.getState>;

describe('unlock rate limiting — client-side lockout (real component)', () => {
  const fakeMek = { __cryptoKey: 'mek' } as unknown as CryptoKey;
  const fakeAuthKey = new ArrayBuffer(32);
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();
  const mockSetAccessToken = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();

    vi.mocked(useAuthStore).mockImplementation((selector?: (state: AuthState) => unknown) => {
      // Only the three members UnlockScreen reads are stubbed.
      const state = {
        user: { userId: 'user-1', email: 'vault@example.com' },
        unlock: mockUnlock,
        logout: mockLogout,
      } as unknown as AuthState;
      return selector ? selector(state) : state;
    });
    // No access token in the store, so `isAccessTokenUsable` is false and the
    // unlock flow takes the refresh branch — the case these tests exercise.
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: mockSetAccessToken,
      accessToken: null,
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
   * Submit one failed unlock: the token refresh succeeds so verify-unlock is
   * reached, then verify-unlock rejects with a genuine 401 (wrong master
   * password). This is the ONLY branch that increments the failure counter and
   * calls applyLockout — a 429 or a network error deliberately does not.
   */
  function submitFailedUnlock() {
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('tok');
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(401));
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

    vi.mocked(useAuthStore).mockImplementation((selector?: (state: AuthState) => unknown) => {
      // Only the three members UnlockScreen reads are stubbed.
      const state = {
        user: { userId: 'user-1', email: 'vault@example.com' },
        unlock: mockUnlock,
        logout: mockLogout,
      } as unknown as AuthState;
      return selector ? selector(state) : state;
    });

    // No access token in the store, so `isAccessTokenUsable` is false and the
    // unlock flow takes the refresh branch — the case these tests exercise.
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: mockSetAccessToken,
      accessToken: null,
    } as unknown as ReturnType<typeof useAuthStore.getState>);

    vi.mocked(useAuthStore.setState).mockImplementation(() => {});

    vi.mocked(performTokenRefresh).mockResolvedValue('new-token-123');
    vi.mocked(api.post).mockResolvedValue({ data: { success: true } });

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
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('tok');
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(429));

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

/**
 * The failures that are NOT the user's fault.
 *
 * Every one of these used to be indistinguishable from a wrong master password —
 * or worse, from a dead session. A 429 raised the local backoff on top of the
 * server's, so the user was locked out twice over for the same event; and any
 * refresh failure at all called `logout()`, which (because `lock()` keeps the
 * access token) reaches `POST /auth/logout` and DELETES a refresh token that was
 * still perfectly valid. A momentary rate limit permanently ended the session and
 * dumped the user on a login page with no explanation.
 */
describe('unlock — transient failures must not cost the user their session', () => {
  const fakeMek = { __cryptoKey: 'mek' } as unknown as CryptoKey;
  const fakeAuthKey = new ArrayBuffer(32);
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();

    vi.mocked(useAuthStore).mockImplementation((selector?: (state: AuthState) => unknown) => {
      const state = {
        user: { userId: 'user-1', email: 'vault@example.com' },
        unlock: mockUnlock,
        logout: mockLogout,
      } as unknown as AuthState;
      return selector ? selector(state) : state;
    });
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: null,
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

  function submit(password = 'whatever') {
    fireEvent.change(screen.getByLabelText('Master Password'), { target: { value: password } });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));
  }

  it('a 429 from verify-unlock reports the wait and does NOT count as a failed attempt', async () => {
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('tok');
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(429, { 'retry-after': '45' }));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/try again in 45 seconds/i)).toBeInTheDocument();
    });

    // The local backoff counter is untouched: the server already told us to wait,
    // and stacking a second cooldown on top of it punishes the user twice.
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
    expect(localStorage.getItem('__hv_unlock_lockout_until')).toBeNull();
    expect(mockLogout).not.toHaveBeenCalled();
    expect(mockUnlock).not.toHaveBeenCalled();
  });

  it('a 429 with no Retry-After still explains itself', async () => {
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('tok');
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(429));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/too many attempts/i)).toBeInTheDocument();
    });
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
  });

  it('a rate-limited REFRESH keeps the user on the unlock screen and the session alive', async () => {
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosStatusError(429));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/too many attempts/i)).toBeInTheDocument();
    });

    // The critical assertion: no logout. `logout()` here would revoke a valid
    // refresh token server-side, so a transient 429 would cost the whole session.
    expect(mockLogout).not.toHaveBeenCalled();
    // Still on the unlock screen, ready to retry.
    expect(screen.getByRole('button', { name: /unlock vault/i })).toBeInTheDocument();
    // And it did not burn an attempt either.
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
  });

  it('an offline REFRESH keeps the session alive', async () => {
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosNetworkError());

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/could not reach the server/i)).toBeInTheDocument();
    });
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it('a 500 from the REFRESH keeps the session alive', async () => {
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosStatusError(503));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/temporarily unavailable/i)).toBeInTheDocument();
    });
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it('a 401 from the REFRESH does end the session — that one really is gone', async () => {
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosStatusError(401));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(mockLogout).toHaveBeenCalled();
    });
    // Not counted as a wrong password: the password was never checked.
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
  });

  it('does not refresh at all when the access token is still usable', async () => {
    // A JWT whose `exp` is comfortably in the future. `lock()` keeps the access
    // token, so after a short auto-lock this is the NORMAL case — and refreshing
    // anyway cost a rate-limit slot, rotated the refresh cookie and invalidated
    // the CSRF token on every single unlock.
    const exp = Math.floor(Date.now() / 1000) + 600;
    const payload = btoa(JSON.stringify({ sub: 'user-1', exp })).replace(/=+$/, '');
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: `header.${payload}.sig`,
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(api.post).mockResolvedValue({ data: { success: true } });

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(mockUnlock).toHaveBeenCalled();
    });
    expect(performTokenRefresh).not.toHaveBeenCalled();
  });

  /**
   * The trap that skipping the refresh would otherwise open.
   *
   * With a locally-fresh token the client sends verify-unlock straight away, and a
   * 401 back is ambiguous: either the master password is wrong, or the token the
   * server sees is no longer valid (the password was changed on another device and
   * bumped `passwordChangedAt`, the account was deleted, verification was
   * revoked). Only `exp` is visible to the client; the rest is server state.
   *
   * Calling the second case a wrong password has no exit — every retry fails
   * identically and the local backoff climbs toward ten minutes while nothing ever
   * says "sign in again". So a 401 on the skipped-refresh path is disambiguated by
   * doing the refresh and asking once more.
   */
  function usableToken() {
    const exp = Math.floor(Date.now() / 1000) + 600;
    const payload = btoa(JSON.stringify({ sub: 'user-1', exp })).replace(/=+$/, '');
    return `header.${payload}.sig`;
  }

  it('a 401 on a locally-fresh token is retried after a refresh, then reported as a wrong password', async () => {
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: usableToken(),
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    // Both attempts refuse; the refresh in between succeeds, so the token was
    // never the problem — the password is genuinely wrong.
    vi.mocked(api.post)
      .mockRejectedValueOnce(axiosStatusError(401))
      .mockRejectedValueOnce(axiosStatusError(401));
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('fresh');

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('1');
    });
    expect(performTokenRefresh).toHaveBeenCalledTimes(1);
    expect(api.post).toHaveBeenCalledTimes(2);
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it('disambiguates at most ONCE, so a second wrong password costs a single slot', async () => {
    // `unlockLimiter` is 5 per user per 5 minutes. A second opinion on every wrong
    // password would spend two slots per visible attempt, and the server would
    // start refusing while the UI still promised the user attempts remaining.
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: usableToken(),
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(performTokenRefresh).mockResolvedValue('fresh');
    vi.mocked(api.post).mockRejectedValue(axiosStatusError(401));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    // First wrong password: verify (401) -> refresh -> verify (401) = 2 calls.
    submit('wrong-one');
    await waitFor(() => {
      expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('1');
    });
    expect(api.post).toHaveBeenCalledTimes(2);
    expect(performTokenRefresh).toHaveBeenCalledTimes(1);

    // Second wrong password: the question is already settled, so ONE call.
    submit('wrong-two');
    await waitFor(() => {
      expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('2');
    });
    expect(api.post).toHaveBeenCalledTimes(3);
    expect(performTokenRefresh).toHaveBeenCalledTimes(1);

    // Third, likewise — the extra cost is paid once, not per attempt.
    submit('wrong-three');
    await waitFor(() => {
      expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBe('3');
    });
    expect(api.post).toHaveBeenCalledTimes(4);
  });

  it('a 401 on a locally-fresh token ends the session when the refresh is also rejected', async () => {
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: usableToken(),
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(401));
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosStatusError(401));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(mockLogout).toHaveBeenCalled();
    });
    // The password was never actually judged, so it must not be blamed.
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
  });

  it('a 401 on a locally-fresh token keeps the session when the refresh fails transiently', async () => {
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: usableToken(),
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(api.post).mockRejectedValueOnce(axiosStatusError(401));
    vi.mocked(performTokenRefresh).mockRejectedValueOnce(axiosStatusError(503));

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(screen.getByText(/temporarily unavailable/i)).toBeInTheDocument();
    });
    expect(mockLogout).not.toHaveBeenCalled();
    expect(localStorage.getItem('__hv_unlock_failed_attempts')).toBeNull();
  });

  it('still refreshes when the access token is expiring within the safety margin', async () => {
    // 30 s of life left is inside ACCESS_TOKEN_FRESHNESS_MARGIN_MS (60 s), so the
    // token could expire mid-flight. Fails closed: refresh.
    const exp = Math.floor(Date.now() / 1000) + 30;
    const payload = btoa(JSON.stringify({ sub: 'user-1', exp })).replace(/=+$/, '');
    vi.mocked(useAuthStore.getState).mockReturnValue({
      setAccessToken: vi.fn(),
      accessToken: `header.${payload}.sig`,
    } as unknown as ReturnType<typeof useAuthStore.getState>);
    vi.mocked(performTokenRefresh).mockResolvedValueOnce('fresh');
    vi.mocked(api.post).mockResolvedValue({ data: { success: true } });

    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );
    submit();

    await waitFor(() => {
      expect(performTokenRefresh).toHaveBeenCalled();
    });
  });
});
