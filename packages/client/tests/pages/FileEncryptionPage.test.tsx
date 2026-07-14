/**
 * Tests for FileEncryptionPage (Phase 8 — page, route, navigation).
 *
 * Covers:
 *  - the page renders both Encrypt and Decrypt tabs and switches between them
 *    (only the active tab's lazily-loaded panel is mounted at a time);
 *  - the page is reachable only behind ProtectedRoute: an unauthenticated user
 *    hitting `/tools/file-encryption` is redirected to `/login`, while an
 *    authenticated user sees the tool.
 *
 * The two panels are mocked with lightweight markers — they have their own
 * dedicated tests and transitively pull in `@hiprax/crypto` / `hash-wasm` /
 * axios / zxcvbn, none of which this page-level test needs. The ProtectedRoute
 * collaborators are mocked exactly as in ProtectedRoute's own test.
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../../src/components/tools/FileEncryptPanel', () => ({
  FileEncryptPanel: () => <div data-testid="encrypt-panel">Encrypt Panel</div>,
}));

vi.mock('../../src/components/tools/FileDecryptPanel', () => ({
  FileDecryptPanel: () => <div data-testid="decrypt-panel">Decrypt Panel</div>,
}));

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

import FileEncryptionPage from '../../src/pages/FileEncryptionPage';
import { ProtectedRoute } from '../../src/components/layout/ProtectedRoute';
import { useAuthStore } from '../../src/stores/authStore';

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

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

describe('FileEncryptionPage — tabs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the heading and both Encrypt/Decrypt tabs', async () => {
    render(<FileEncryptionPage />);

    expect(screen.getByRole('heading', { name: 'File Encryption' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Encrypt' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Decrypt' })).toBeInTheDocument();

    // Encrypt is the default tab — its (lazy) panel mounts, Decrypt's does not.
    expect(await screen.findByTestId('encrypt-panel')).toBeInTheDocument();
    expect(screen.queryByTestId('decrypt-panel')).not.toBeInTheDocument();
  });

  it('switches to the Decrypt tab and back to Encrypt', async () => {
    render(<FileEncryptionPage />);

    // Start on Encrypt.
    expect(await screen.findByTestId('encrypt-panel')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Encrypt' })).toHaveAttribute('aria-selected', 'true');

    // Switch to Decrypt: its panel mounts, Encrypt's unmounts.
    fireEvent.click(screen.getByRole('tab', { name: 'Decrypt' }));
    expect(await screen.findByTestId('decrypt-panel')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByTestId('encrypt-panel')).not.toBeInTheDocument();
    });
    expect(screen.getByRole('tab', { name: 'Decrypt' })).toHaveAttribute('aria-selected', 'true');

    // Switch back to Encrypt.
    fireEvent.click(screen.getByRole('tab', { name: 'Encrypt' }));
    expect(await screen.findByTestId('encrypt-panel')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByTestId('decrypt-panel')).not.toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// Protected route
// ---------------------------------------------------------------------------

describe('FileEncryptionPage — protected route', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRefreshTokenApi.mockReset();
  });

  /**
   * Render the tool at `/tools/file-encryption` behind ProtectedRoute, mirroring
   * the App.tsx wiring (`<Route element={<ProtectedRoute />}>`), with a `/login`
   * marker route to detect redirects.
   */
  function renderRouted() {
    return render(
      <MemoryRouter initialEntries={['/tools/file-encryption']}>
        <Routes>
          <Route path="/login" element={<div data-testid="login-page">Login Page</div>} />
          <Route element={<ProtectedRoute />}>
            <Route path="/tools/file-encryption" element={<FileEncryptionPage />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }

  it('redirects unauthenticated users to /login', () => {
    setupAuthStore({ isAuthenticated: false });

    renderRouted();

    expect(screen.getByTestId('login-page')).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Encrypt' })).not.toBeInTheDocument();
  });

  it('renders the tool for authenticated users', async () => {
    setupAuthStore({ isAuthenticated: true, accessToken: 'valid-token' });

    renderRouted();

    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();
    expect(await screen.findByRole('tab', { name: 'Encrypt' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Decrypt' })).toBeInTheDocument();
  });
});
