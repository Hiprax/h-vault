/**
 * Phase 4 tests: Robustness & Error Handling Improvements
 *
 * 4.1 - API response validation with Zod (vaultItemResponseSchema / folderResponseSchema)
 * 4.2 - Session expiry user feedback in ProtectedRoute
 * 4.3 - Decryption failure UI notification banner
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { AxiosError, AxiosHeaders } from 'axios';

// ---------------------------------------------------------------------------
// Polyfill matchMedia (needed for stores that reference it at module load)
// ---------------------------------------------------------------------------

const { mockRefreshTokenApi } = vi.hoisted(() => {
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

  return {
    mockRefreshTokenApi: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), {
    getState: vi.fn(),
    setState: vi.fn(),
  }),
}));

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: () => false,
}));

vi.mock('../src/services/api/authApi', () => ({
  refreshTokenApi: (...args: unknown[]) => mockRefreshTokenApi(...args),
}));

vi.mock('../src/components/auth/UnlockScreen', () => ({
  UnlockScreen: () => <div data-testid="unlock-screen">Unlock Screen</div>,
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { ProtectedRoute } from '../src/components/layout/ProtectedRoute';

// =========================================================================
// 4.1 - API Response Validation with Zod
// =========================================================================

describe('4.1 — vaultItemResponseSchema', () => {
  let vaultItemResponseSchema: typeof import('@hvault/shared').vaultItemResponseSchema;
  let folderResponseSchema: typeof import('@hvault/shared').folderResponseSchema;

  beforeEach(async () => {
    const shared = await import('@hvault/shared');
    vaultItemResponseSchema = shared.vaultItemResponseSchema;
    folderResponseSchema = shared.folderResponseSchema;
  });

  const validItem = {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    itemType: 'login',
    tags: ['tag1'],
    favorite: false,
    encryptedData: 'base64data',
    dataIv: 'ivdata',
    dataTag: 'tagdata',
    encryptedName: 'base64name',
    nameIv: 'nameiv',
    nameTag: 'nametag',
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt: '2025-01-01T00:00:00Z',
  };

  it('accepts a valid vault item response', () => {
    expect(vaultItemResponseSchema.safeParse(validItem).success).toBe(true);
  });

  it('accepts with optional fields', () => {
    const result = vaultItemResponseSchema.safeParse({
      ...validItem,
      folderId: '507f1f77bcf86cd799439013',
      searchHash: 'abc123',
      deletedAt: '2025-06-01T00:00:00Z',
      passwordHistory: [
        {
          encryptedPassword: 'enc',
          iv: 'iv',
          tag: 'tag',
          changedAt: '2025-01-01T00:00:00Z',
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing required encryption fields', () => {
    const { encryptedData: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects empty encryptedName', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, encryptedName: '' }).success).toBe(
      false,
    );
  });

  it('rejects missing _id', () => {
    const { _id: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects invalid itemType', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, itemType: 'unknown' }).success).toBe(
      false,
    );
  });

  it('rejects missing dataIv', () => {
    const { dataIv: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  // Folder response schema
  it('accepts a valid folder response', () => {
    expect(
      folderResponseSchema.safeParse({
        _id: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        encryptedName: 'encname',
        nameIv: 'nameiv',
        nameTag: 'nametag',
        sortOrder: 0,
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
      }).success,
    ).toBe(true);
  });

  it('rejects folder with empty encryptedName', () => {
    expect(
      folderResponseSchema.safeParse({
        _id: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        encryptedName: '',
        nameIv: 'nameiv',
        nameTag: 'nametag',
        sortOrder: 0,
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
      }).success,
    ).toBe(false);
  });

  it('rejects folder missing sortOrder', () => {
    expect(
      folderResponseSchema.safeParse({
        _id: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        encryptedName: 'name',
        nameIv: 'iv',
        nameTag: 'tag',
        createdAt: '2025-01-01T00:00:00Z',
        updatedAt: '2025-01-01T00:00:00Z',
      }).success,
    ).toBe(false);
  });
});

// =========================================================================
// 4.2 — Session Expiry User Feedback in ProtectedRoute
// =========================================================================

describe('4.2 — ProtectedRoute session expiry feedback', () => {
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

    mockUseAuthStore.mockImplementation((selector?: unknown) => {
      if (typeof selector === 'function') {
        return (selector as (s: typeof state) => unknown)(state);
      }
      return state as unknown;
    });

    return state;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    mockRefreshTokenApi.mockReset();
  });

  /**
   * A real AxiosError with a status, which is what `isSessionGone` requires:
   * it classifies via axios' own `isAxiosError`, so a bare `new Error()` is
   * transient by construction and must never drive a logout.
   */
  function axiosStatusError(status: number): AxiosError {
    const error = new AxiosError(`Request failed with status code ${status}`);
    error.response = {
      status,
      statusText: '',
      data: {},
      headers: new AxiosHeaders(),
      config: { headers: new AxiosHeaders() },
    };
    return error;
  }

  function renderProtected() {
    return render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route path="/login" element={<div data-testid="login-page">Login</div>} />
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div data-testid="protected-content">Protected</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>,
    );
  }

  it('calls logout when the server rejects the refresh token with 401', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(axiosStatusError(401));

    renderProtected();

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  it('calls logout when the refresh is rejected with 403', async () => {
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

  // These two replace a test that asserted "any refresh failure logs out". That
  // rule was itself the bug: `logout()` is not a local teardown, it POSTs
  // /auth/logout and DELETES a refresh token that was still valid, so a momentary
  // network blip or a rate limit permanently destroyed a live session.
  it('does not log out on a network error and offers a retry instead', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    // A network failure has no `response` at all.
    mockRefreshTokenApi.mockRejectedValue(new AxiosError('Network Error'));

    renderProtected();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not reach the server');
    expect(state.logout).not.toHaveBeenCalled();
    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();

    // The retry re-runs the refresh; on success the protected children render.
    mockRefreshTokenApi.mockReset();
    mockRefreshTokenApi.mockResolvedValue('new-token');
    fireEvent.click(screen.getByRole('button', { name: /try again/i }));

    expect(await screen.findByTestId('protected-content')).toBeInTheDocument();
    expect(mockRefreshTokenApi).toHaveBeenCalled();
    expect(state.logout).not.toHaveBeenCalled();
  });

  it('does not log out when the refresh is rate limited (429)', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(axiosStatusError(429));

    renderProtected();

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not reach the server');
    expect(state.logout).not.toHaveBeenCalled();
  });

  // The old "refresh returns unsuccessful response" case no longer exists at this
  // layer: the `{ success: false }` envelope check moved into
  // `performTokenRefresh`, which REJECTS rather than resolving a bad body. What
  // reaches ProtectedRoute is therefore a plain (non-Axios) Error, which is
  // transient -- a malformed 2xx is not proof that the session is gone.
  it('treats a rejected malformed refresh envelope as transient, not as a dead session', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(
      new Error('Token refresh returned an unexpected response'),
    );

    renderProtected();

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not reach the server');
    expect(state.logout).not.toHaveBeenCalled();
  });

  it('renders the protected children when the refresh succeeds', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    // `refreshTokenApi` now resolves to the token string itself, and storing it is
    // `performTokenRefresh`'s job -- ProtectedRoute no longer calls
    // setAccessToken, so the observable outcome is the rendered children.
    mockRefreshTokenApi.mockResolvedValue('new-token');

    renderProtected();

    expect(await screen.findByTestId('protected-content')).toBeInTheDocument();
    expect(state.logout).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('redirects unauthenticated users to /login with location state', () => {
    // Held in an object: a bare `let` written only from the render callback is
    // narrowed back to its initializer by control-flow analysis.
    const captured: { loginState: Record<string, unknown> | null } = { loginState: null };

    setupAuthStore({ isAuthenticated: false });

    function CaptureState() {
      const location = useLocation();
      captured.loginState = location.state as Record<string, unknown>;
      return <div data-testid="login-page">Login</div>;
    }

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route path="/login" element={<CaptureState />} />
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByTestId('login-page')).toBeInTheDocument();
    // When not session-expired, the sessionExpired flag should not be present
    expect(captured.loginState?.sessionExpired).toBeUndefined();
  });
});

// The LoginPage session-expired banner and the AppLayout decryption-failure
// banner (markup, event listener wiring, and Re-sync → fetchItems/fetchFolders)
// are covered by RENDERING the real components in coverage-auth-layout.test.tsx,
// and the store-side `reportDecryptionFailures` → `window.dispatchEvent` path is
// covered against the real store in phase8-vault-store.test.ts. The former
// source-text (readFileSync + toContain) assertions here executed no component
// code and passed even when the banner never rendered; the CustomEvent round-trip
// tests exercised only the DOM API, never the store. They were removed as
// worse-than-nothing duplicates in favour of the behavioural coverage above.
