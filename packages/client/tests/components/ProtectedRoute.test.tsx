/**
 * Tests for the ProtectedRoute auth guard component.
 *
 * Verifies: redirect when unauthenticated, child rendering when authenticated,
 * UnlockScreen when locked, and token refresh on mount.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ProtectedRoute } from '../../src/components/layout/ProtectedRoute';
import { useAuthStore } from '../../src/stores/authStore';

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
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockResolvedValue({
      data: { success: true, data: { accessToken: 'new-token' } },
    });

    renderProtected();

    await waitFor(() => {
      expect(mockRefreshTokenApi).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(state.setAccessToken).toHaveBeenCalledWith('new-token');
    });
  });

  it('logs out when token refresh fails', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(new Error('Network error'));

    renderProtected();

    await waitFor(() => {
      expect(mockRefreshTokenApi).toHaveBeenCalledTimes(1);
    });

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  it('logs out when refresh returns unsuccessful response', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockResolvedValue({
      data: { success: false },
    });

    renderProtected();

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
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
