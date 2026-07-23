/**
 * Tests for the cold-start "remember me" session resume
 * (`services/auth/sessionResume.ts`) and the app-root render gating in
 * `App.tsx`.
 *
 * Two layers are exercised:
 *   1. `resumeSession()` / `shouldAttemptResume()` behavior against the REAL
 *      auth store with the two network calls mocked — success, absent hint,
 *      already-authenticated, authoritative rejection (401/403 → hint cleared),
 *      and transient failure (network / 5xx / non-Axios → hint kept).
 *   2. The `<App/>` boot path — a hint renders a neutral loading state until the
 *      attempt settles, then the Unlock screen (success) or the login screen
 *      (rejection), so neither route guard can redirect a resuming user first.
 */

import { render, screen, waitFor } from '@testing-library/react';
import { createElement } from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KDF_ITERATIONS } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Mocks — declared before importing the store/services under test.
// ---------------------------------------------------------------------------

// The auth store persists through the encrypted storage adapter; stub it so no
// real (de)serialization happens and rehydration is a no-op.
vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

// The real auth store imports these heavy modules only for actions we never
// invoke here (login / logout / lock). Stub them so importing the real store is
// cheap and side-effect free.
vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    generateVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    setUser: vi.fn().mockResolvedValue(undefined),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/health/healthResultsStore', () => ({
  clearHealthResults: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  clearSettingsCache: vi.fn(),
}));

vi.mock('../src/hooks/useClipboardGuard', () => ({
  clearClipboardIfDirty: vi.fn(),
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

// The two calls the resume actually makes.
const mockRefreshTokenApi = vi.fn();
const mockGetProfileApi = vi.fn();

vi.mock('../src/services/api/authApi', () => ({
  refreshTokenApi: (...args: unknown[]) => mockRefreshTokenApi(...args),
  // Present so the real auth store's import destructuring succeeds; unused here.
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn(),
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
}));

// ---------------------------------------------------------------------------
// Imports under test (real modules) — after the mocks above.
// ---------------------------------------------------------------------------

import { resumeSession, shouldAttemptResume } from '../src/services/auth/sessionResume';
import { useAuthStore, REMEMBER_HINT_KEY } from '../src/stores/authStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface FakeAxiosError extends Error {
  isAxiosError: true;
  response?: { status: number };
}

/** A response-less error mimics a network failure; a status mimics an HTTP error. */
function axiosError(status?: number): FakeAxiosError {
  const err = new Error(status ? `HTTP ${status}` : 'Network Error') as FakeAxiosError;
  err.isAxiosError = true;
  if (status !== undefined) err.response = { status };
  return err;
}

function refreshOk(accessToken = 'access-token') {
  return { data: { success: true, data: { accessToken } } };
}

const PROFILE = {
  _id: 'user-1',
  email: 'user@example.com',
  encryptedVaultKey: 'enc-vk',
  vaultKeyIv: 'vk-iv',
  vaultKeyTag: 'vk-tag',
  kdfIterations: 700_000,
};

function profileOk(profile: Record<string, unknown> = PROFILE) {
  return { data: { success: true, data: profile } };
}

function resetStore(): void {
  useAuthStore.setState({
    accessToken: null,
    user: null,
    isAuthenticated: false,
    isLocked: false,
    vaultKey: null,
    mek: null,
    encryptedVaultKeyData: null,
    kdfIterations: KDF_ITERATIONS,
  });
}

function setHint(): void {
  localStorage.setItem(REMEMBER_HINT_KEY, '1');
}

function getHint(): string | null {
  return localStorage.getItem(REMEMBER_HINT_KEY);
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  resetStore();
  window.history.pushState({}, '', '/');
});

// ---------------------------------------------------------------------------
// resumeSession behavior
// ---------------------------------------------------------------------------

describe('resumeSession', () => {
  it('resumes to an authenticated-but-locked session and keeps the hint on success', async () => {
    setHint();
    mockRefreshTokenApi.mockResolvedValue(refreshOk());
    mockGetProfileApi.mockResolvedValue(profileOk());

    const result = await resumeSession();

    expect(result).toBe(true);
    expect(mockRefreshTokenApi).toHaveBeenCalledTimes(1);
    expect(mockGetProfileApi).toHaveBeenCalledTimes(1);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLocked).toBe(true);
    expect(state.user).toEqual({ userId: 'user-1', email: 'user@example.com' });
    expect(state.accessToken).toBe('access-token');
    expect(state.encryptedVaultKeyData).toEqual({
      encrypted: 'enc-vk',
      iv: 'vk-iv',
      tag: 'vk-tag',
    });
    expect(state.kdfIterations).toBe(700_000);
    // Crypto material is NEVER set by the resume path.
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    // A successful resume keeps the hint for future boots.
    expect(getHint()).toBe('1');
  });

  it('returns false and makes no network call when the hint is absent', async () => {
    mockRefreshTokenApi.mockResolvedValue(refreshOk());

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(mockRefreshTokenApi).not.toHaveBeenCalled();
    expect(mockGetProfileApi).not.toHaveBeenCalled();
  });

  it('returns false and makes no network call when already authenticated', async () => {
    setHint();
    useAuthStore.setState({ isAuthenticated: true });

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(mockRefreshTokenApi).not.toHaveBeenCalled();
    expect(mockGetProfileApi).not.toHaveBeenCalled();
  });

  it('returns false and makes no network call when localStorage access throws', async () => {
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage disabled');
    });
    try {
      const result = await resumeSession();
      expect(result).toBe(false);
      expect(mockRefreshTokenApi).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('clears the hint and returns false on a 401 from refresh (session gone)', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError(401));

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBeNull();
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('clears the hint and returns false on a 403 from the profile fetch', async () => {
    setHint();
    mockRefreshTokenApi.mockResolvedValue(refreshOk());
    mockGetProfileApi.mockRejectedValue(axiosError(403));

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBeNull();
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('KEEPS the hint on a network error (offline cold boot)', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError()); // no response -> network error

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBe('1');
  });

  it('KEEPS the hint on a 5xx from refresh (brief server restart)', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError(503));

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBe('1');
  });

  it('KEEPS the hint on a non-Axios error', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(new Error('boom'));

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBe('1');
  });

  it('KEEPS the hint when refresh resolves a non-success envelope', async () => {
    setHint();
    mockRefreshTokenApi.mockResolvedValue({ data: { success: false } });

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBe('1');
    expect(mockGetProfileApi).not.toHaveBeenCalled();
  });

  it('KEEPS the hint when the profile resolves a non-success envelope', async () => {
    setHint();
    mockRefreshTokenApi.mockResolvedValue(refreshOk());
    mockGetProfileApi.mockResolvedValue({ data: { success: false } });

    const result = await resumeSession();

    expect(result).toBe(false);
    expect(getHint()).toBe('1');
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('never throws even when clearing the hint fails on an authoritative rejection', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError(401));
    const spy = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new Error('storage disabled');
    });
    try {
      await expect(resumeSession()).resolves.toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('shouldAttemptResume', () => {
  it('is true only with a hint and an unauthenticated store', () => {
    expect(shouldAttemptResume()).toBe(false); // no hint
    setHint();
    expect(shouldAttemptResume()).toBe(true);
    useAuthStore.setState({ isAuthenticated: true });
    expect(shouldAttemptResume()).toBe(false); // hint but already authenticated
  });
});

// ---------------------------------------------------------------------------
// App boot-path gating
// ---------------------------------------------------------------------------

vi.mock('../src/hooks/useFavicon', () => ({ useFavicon: () => undefined }));
vi.mock('../src/components/layout/ReloadPrompt', () => ({
  ReloadPrompt: () => createElement('div', { 'data-testid': 'reload-prompt' }),
}));
vi.mock('../src/components/layout/AppLayout', async () => {
  const { Outlet } = await import('react-router-dom');
  return {
    AppLayout: () => createElement('div', { 'data-testid': 'app-layout' }, createElement(Outlet)),
  };
});
vi.mock('../src/components/auth/UnlockScreen', () => ({
  UnlockScreen: () => createElement('div', { 'data-testid': 'unlock-screen' }, 'Unlock'),
}));

function pageStub(name: string) {
  return { default: () => createElement('div', { 'data-testid': `page-${name}` }, name) };
}
vi.mock('../src/pages/LoginPage', () => pageStub('login'));
vi.mock('../src/pages/RegisterPage', () => pageStub('register'));
vi.mock('../src/pages/ForgotPasswordPage', () => pageStub('forgot'));
vi.mock('../src/pages/VaultPage', () => pageStub('vault'));
vi.mock('../src/pages/VaultItemPage', () => pageStub('vault-item'));
vi.mock('../src/pages/VaultHealthPage', () => pageStub('vault-health'));
vi.mock('../src/pages/GeneratorPage', () => pageStub('generator'));
vi.mock('../src/pages/FileEncryptionPage', () => pageStub('file-encryption'));
vi.mock('../src/pages/SettingsPage', () => pageStub('settings'));
vi.mock('../src/pages/BackupSettingsPage', () => pageStub('backup'));
vi.mock('../src/pages/SessionsPage', () => pageStub('sessions'));
vi.mock('../src/pages/AuditLogPage', () => pageStub('audit'));
vi.mock('../src/pages/ExportDataPage', () => pageStub('export-data'));
vi.mock('../src/pages/VerifyEmailPage', () => pageStub('verify-email'));
vi.mock('../src/pages/ResetPasswordPage', () => pageStub('reset-password'));
vi.mock('../src/pages/UnlockAccountPage', () => pageStub('unlock-account'));
vi.mock('../src/pages/NotFoundPage', () => pageStub('not-found'));

async function renderAppAt(path: string): Promise<void> {
  window.history.pushState({}, '', path);
  const { App } = await import('../src/App');
  render(createElement(App));
}

describe('App resume gating', () => {
  it('renders the routes immediately when there is no hint', async () => {
    await renderAppAt('/login');
    expect(await screen.findByTestId('page-login')).toBeInTheDocument();
    expect(mockRefreshTokenApi).not.toHaveBeenCalled();
  });

  it('gates on a hint, then lands on the Unlock screen after a successful resume', async () => {
    setHint();
    mockRefreshTokenApi.mockResolvedValue(refreshOk());
    mockGetProfileApi.mockResolvedValue(profileOk());

    await renderAppAt('/vault');

    expect(await screen.findByTestId('unlock-screen')).toBeInTheDocument();
    expect(screen.queryByTestId('page-login')).not.toBeInTheDocument();
    expect(getHint()).toBe('1');
    expect(useAuthStore.getState().vaultKey).toBeNull();
  });

  it('gates on a hint, then lands on the login screen and clears the hint on a 401', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError(401));

    await renderAppAt('/vault');

    expect(await screen.findByTestId('page-login')).toBeInTheDocument();
    expect(screen.queryByTestId('unlock-screen')).not.toBeInTheDocument();
    expect(getHint()).toBeNull();
  });

  it('lands on the login screen but KEEPS the hint on a transient network failure', async () => {
    setHint();
    mockRefreshTokenApi.mockRejectedValue(axiosError());

    await renderAppAt('/vault');

    expect(await screen.findByTestId('page-login')).toBeInTheDocument();
    expect(getHint()).toBe('1');
  });

  it('does not settle the render state after the app unmounts mid-resume', async () => {
    setHint();
    let resolveRefresh: (value: unknown) => void = () => undefined;
    mockRefreshTokenApi.mockReturnValue(
      new Promise((resolve) => {
        resolveRefresh = resolve;
      }),
    );
    mockGetProfileApi.mockResolvedValue(profileOk());

    window.history.pushState({}, '', '/vault');
    const { App } = await import('../src/App');
    const { unmount } = render(createElement(App));

    // The loading state is shown while the resume is in flight.
    expect(useAuthStore.getState().isAuthenticated).toBe(false);

    // Unmount before the resume settles, then let it finish. The guarded
    // `finally` must not call setState on the unmounted component (no throw).
    unmount();
    resolveRefresh(refreshOk());
    await waitFor(() => {
      expect(mockGetProfileApi).toHaveBeenCalled();
    });
  });
});
