/**
 * Tests for the ProtectedRoute auth guard component.
 *
 * Verifies: redirect when unauthenticated, child rendering when authenticated,
 * UnlockScreen when locked, and token refresh on mount.
 */

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { ProtectedRoute } from '../../src/components/layout/ProtectedRoute';
import { useAuthStore } from '../../src/stores/authStore';

/**
 * A real `AxiosError` carrying a status. Required, not cosmetic: the guard
 * classifies failures with `isSessionGone`, which calls `isAxiosError` — a bare
 * `new Error()` is never session-gone, so using one would make every status case
 * pass for the wrong reason.
 */
function axiosStatusError(status: number): AxiosError {
  const err = new AxiosError('Request failed with status code ' + String(status));
  err.response = {
    status,
    statusText: '',
    data: {},
    headers: new AxiosHeaders(),
    config: { headers: new AxiosHeaders() },
  };
  return err;
}

/** No `response` at all — the offline shape. */
function axiosNetworkError(): AxiosError {
  return new AxiosError('Network Error');
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockRefreshTokenApi = vi.fn();

vi.mock('../../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), {
    getState: vi.fn(),
    setState: vi.fn(),
  }),
}));

vi.mock('../../src/services/api/authApi', () => ({
  refreshTokenApi: (...args: unknown[]) => mockRefreshTokenApi(...args),
}));

vi.mock('../../src/components/auth/UnlockScreen', () => ({
  UnlockScreen: () => <div data-testid="unlock-screen">Unlock Screen</div>,
}));

vi.mock('../../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockUseAuthStore = vi.mocked(useAuthStore);

function setupAuthStore(overrides: {
  isAuthenticated?: boolean;
  isLocked?: boolean;
  accessToken?: string | null;
}) {
  const defaults = {
    isAuthenticated: false,
    isLocked: false,
    accessToken: null,
    setAccessToken: vi.fn(),
    logout: vi.fn().mockResolvedValue(undefined),
  };

  const state = { ...defaults, ...overrides };

  // useAuthStore() returns the full state
  mockUseAuthStore.mockImplementation((selector?: unknown) => {
    if (typeof selector === 'function') {
      return (selector as (s: typeof state) => unknown)(state);
    }
    return state as unknown;
  });

  return state;
}

/**
 * Render ProtectedRoute inside a router with a login route to detect redirects.
 */
function renderProtected(children?: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={['/vault']}>
      <Routes>
        <Route path="/login" element={<div data-testid="login-page">Login Page</div>} />
        <Route
          path="/vault"
          element={
            <ProtectedRoute>
              {children ?? <div data-testid="protected-content">Protected Content</div>}
            </ProtectedRoute>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRefreshTokenApi.mockReset();
  });

  // -------------------------------------------------------------------------
  // Unauthenticated redirect
  // -------------------------------------------------------------------------

  it('redirects unauthenticated users to /login', () => {
    setupAuthStore({ isAuthenticated: false });

    renderProtected();

    expect(screen.getByTestId('login-page')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Authenticated user sees content
  // -------------------------------------------------------------------------

  it('renders child content for authenticated users', () => {
    setupAuthStore({ isAuthenticated: true, accessToken: 'valid-token' });

    renderProtected();

    expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Locked user sees UnlockScreen
  // -------------------------------------------------------------------------

  it('shows UnlockScreen when user is locked', () => {
    setupAuthStore({ isAuthenticated: true, isLocked: true, accessToken: null });

    renderProtected();

    expect(screen.getByTestId('unlock-screen')).toBeInTheDocument();
    expect(screen.queryByTestId('protected-content')).not.toBeInTheDocument();
    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();
  });

  // -------------------------------------------------------------------------
  // Token refresh on mount
  // -------------------------------------------------------------------------

  it('attempts token refresh when authenticated without access token', async () => {
    setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    // Resolves to the token; storing it is `performTokenRefresh`'s job, so the
    // component no longer calls `setAccessToken` itself.
    mockRefreshTokenApi.mockResolvedValue('new-token');

    renderProtected();

    await waitFor(() => {
      expect(mockRefreshTokenApi).toHaveBeenCalledTimes(1);
    });

    // Refresh succeeded, so the guard renders its children rather than a spinner
    // or an error.
    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });
  });

  it('logs out when the refresh is authoritatively rejected (401)', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(axiosStatusError(401));

    renderProtected();

    await waitFor(() => {
      expect(mockRefreshTokenApi).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  it('logs out on a 403 too', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(axiosStatusError(403));

    renderProtected();

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  /**
   * The regression this guards. `logout()` is not a local teardown — the access
   * token is still set on the lock/refresh path, so it reaches
   * `POST /auth/logout` and DELETES the refresh-token row. Logging out on a 429 or
   * a dropped connection therefore destroyed a session that had days left, and
   * bounced the user to a login page that was itself rate-limited.
   */
  it.each([
    ['a rate limit (429)', () => axiosStatusError(429)],
    ['a server error (503)', () => axiosStatusError(503)],
    ['a network failure', () => axiosNetworkError()],
    ['a non-Axios throw', () => new Error('boom')],
  ])('does NOT log out on %s — it offers a retry instead', async (_label, makeError) => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(makeError());

    renderProtected();

    await waitFor(() => {
      expect(screen.getByText(/could not reach the server/i)).toBeInTheDocument();
    });

    expect(state.logout).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('retries the refresh when the user asks it to', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi
      .mockRejectedValueOnce(axiosStatusError(503))
      .mockResolvedValueOnce('recovered-token');

    renderProtected();

    const retry = await screen.findByRole('button', { name: /try again/i });
    fireEvent.click(retry);

    await waitFor(() => {
      expect(mockRefreshTokenApi).toHaveBeenCalledTimes(2);
    });
    await waitFor(() => {
      expect(screen.getByTestId('protected-content')).toBeInTheDocument();
    });
    expect(state.logout).not.toHaveBeenCalled();
  });

  it('does not attempt refresh when access token exists', () => {
    setupAuthStore({ isAuthenticated: true, accessToken: 'existing-token' });

    renderProtected();

    expect(mockRefreshTokenApi).not.toHaveBeenCalled();
  });

  it('does not attempt refresh when locked', () => {
    setupAuthStore({ isAuthenticated: true, isLocked: true, accessToken: null });

    renderProtected();

    expect(mockRefreshTokenApi).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Outlet rendering
  // -------------------------------------------------------------------------

  it('renders Outlet when no children provided', () => {
    setupAuthStore({ isAuthenticated: true, accessToken: 'token' });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route element={<ProtectedRoute />}>
            <Route path="/vault" element={<div data-testid="outlet-content">Outlet</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByTestId('outlet-content')).toBeInTheDocument();
  });
});
