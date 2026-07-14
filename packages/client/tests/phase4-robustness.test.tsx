/**
 * Phase 4 tests: Robustness & Error Handling Improvements
 *
 * 4.1 - API response validation with Zod (vaultItemResponseSchema / folderResponseSchema)
 * 4.2 - Session expiry user feedback in ProtectedRoute
 * 4.3 - Decryption failure UI notification banner
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';

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

  it('calls logout when refresh fails with network error', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockRejectedValue(new Error('Network error'));

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route path="/login" element={<div data-testid="login-page">Login</div>} />
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

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  it('calls logout when refresh returns unsuccessful response', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockResolvedValue({
      data: { success: false },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route path="/login" element={<div data-testid="login-page">Login</div>} />
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

    await waitFor(() => {
      expect(state.logout).toHaveBeenCalled();
    });
  });

  it('does not call logout when refresh succeeds', async () => {
    const state = setupAuthStore({
      isAuthenticated: true,
      accessToken: null,
      isLocked: false,
    });

    mockRefreshTokenApi.mockResolvedValue({
      data: { success: true, data: { accessToken: 'new-token' } },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
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

    await waitFor(() => {
      expect(state.setAccessToken).toHaveBeenCalledWith('new-token');
    });

    expect(state.logout).not.toHaveBeenCalled();
  });

  it('redirects unauthenticated users to /login with location state', () => {
    let loginState: Record<string, unknown> | null = null;

    setupAuthStore({ isAuthenticated: false });

    function CaptureState() {
      const location = useLocation();
      loginState = location.state as Record<string, unknown>;
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
    expect(loginState?.sessionExpired).toBeUndefined();
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
