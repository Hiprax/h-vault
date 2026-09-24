/**
 * The page outline: every screen has exactly one `main` landmark, one `h1`, no
 * two landmarks a landmark menu cannot tell apart, and no skipped heading level.
 *
 * These are the structural rules `test:a11y` gates at `moderate` (`region`,
 * `landmark-one-main`, `landmark-unique`, `page-has-heading-one`,
 * `heading-order`). That gate scans the running application; this suite pins the
 * same structure per screen at unit speed, including screens its walk does not
 * reach (the 2FA step, the reset link's invalid-token card, the two
 * session-recovery screens `ProtectedRoute` draws in place of the app).
 *
 * The one structural decision worth stating: the application sidebar is the
 * page's BANNER (`<header>`), not a second `<aside>`. It holds the product mark,
 * the primary navigation and the account controls, which is site-oriented
 * content by definition; as an `<aside>` it was a second unnamed complementary
 * landmark beside the folder rail on `/vault` and `/documents`.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import React from 'react';
import {
  duplicateLandmarks,
  firstSkippedHeadingLevel,
  headingLevels,
} from '../support/documentOutline';

/* -------------------------------------------------------------------------- */
/*  Mocks: I/O and heavy children only, never the page under test              */
/* -------------------------------------------------------------------------- */

const { mockVerifyEmail, mockUnlockAccount, mockRefreshToken } = vi.hoisted(() => ({
  mockVerifyEmail: vi.fn(),
  mockUnlockAccount: vi.fn(),
  mockRefreshToken: vi.fn(),
}));

vi.mock('../../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), { getState: vi.fn(), setState: vi.fn() }),
}));

vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: Object.assign(vi.fn(), { getState: vi.fn(), setState: vi.fn() }),
}));

vi.mock('../../src/services/api/authApi', () => ({
  verifyEmailApi: mockVerifyEmail,
  unlockAccountApi: mockUnlockAccount,
  refreshTokenApi: mockRefreshToken,
  forgotPasswordApi: vi.fn(),
  resetPasswordApi: vi.fn(),
}));

vi.mock('../../src/services/api/client', () => ({
  api: { post: vi.fn(), get: vi.fn(), put: vi.fn(), delete: vi.fn() },
  performTokenRefresh: vi.fn(),
  clearCsrfToken: vi.fn(),
  withRefreshLock: <T,>(run: () => Promise<T>): Promise<T> => run(),
}));

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

vi.mock('../../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: () =>
    Promise.resolve(() => ({ score: 0, feedback: { warning: '', suggestions: [] } })),
}));

vi.mock('../../src/services/api/configApi', () => ({
  getDocumentsConfig: () => Promise.resolve({ enabled: false }),
  getFileEncryptionMaxBytes: vi.fn(),
}));

vi.mock('../../src/stores/encryptedStorage', () => ({
  isStorageDegraded: () => false,
  encryptedStorage: { getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn() },
}));

vi.mock('../../src/hooks/useAutoLock', () => ({ useAutoLock: vi.fn() }));
vi.mock('../../src/hooks/useClipboardCountdown', () => ({ useClipboardCountdown: vi.fn() }));
vi.mock('../../src/hooks/useKeyboardShortcuts', () => ({ useKeyboardShortcuts: vi.fn() }));
vi.mock('../../src/hooks/useConnectionStatus', () => ({
  useConnectionStatus: () => ({ isOnline: true }),
}));
vi.mock('../../src/components/layout/OnboardingGuide', () => ({ OnboardingGuide: () => null }));

// The vault page's two panes are covered by their own suites; here they only
// have to occupy their slots, so the outline measured is the PAGE's.
vi.mock('../../src/components/folders/FolderRail', () => ({
  FolderRail: () => (
    <ul>
      <li>All items</li>
    </ul>
  ),
}));
vi.mock('../../src/components/vault/VaultList', () => ({
  VaultList: () => <p>vault rows</p>,
}));
vi.mock('../../src/components/vault/VaultItemForm', () => ({ VaultItemForm: () => null }));
vi.mock('../../src/hooks/useVaultFolderScope', () => ({ useVaultFolderScope: () => ({}) }));

/* -------------------------------------------------------------------------- */
/*  Imports (after the mocks)                                                  */
/* -------------------------------------------------------------------------- */

import { LoginPage } from '../../src/components/auth/LoginPage';
import { RegisterPage } from '../../src/components/auth/RegisterPage';
import { ForgotPasswordPage } from '../../src/components/auth/ForgotPasswordPage';
import { UnlockScreen } from '../../src/components/auth/UnlockScreen';
import ResetPasswordPage from '../../src/pages/ResetPasswordPage';
import VerifyEmailPage from '../../src/pages/VerifyEmailPage';
import UnlockAccountPage from '../../src/pages/UnlockAccountPage';
import NotFoundPage from '../../src/pages/NotFoundPage';
import VaultPage from '../../src/pages/VaultPage';
import { LoadingSpinner } from '../../src/App';
import { AppLayout } from '../../src/components/layout/AppLayout';
import { ProtectedRoute } from '../../src/components/layout/ProtectedRoute';
import { useAuthStore } from '../../src/stores/authStore';
import { useVaultStore } from '../../src/stores/vaultStore';
import { ToastProvider } from '../../src/components/ui/Toast';

/* -------------------------------------------------------------------------- */
/*  Harness                                                                    */
/* -------------------------------------------------------------------------- */

type AuthState = ReturnType<typeof useAuthStore.getState>;
type VaultState = ReturnType<typeof useVaultStore.getState>;

/** The store slice each screen reads; the cast is the mock's shape, not a claim. */
function stubAuthStore(partial: Partial<AuthState>): void {
  const state = {
    user: { userId: 'user-1', email: 'vault@example.com' },
    isAuthenticated: false,
    isLocked: false,
    accessToken: null,
    vaultKeyVersion: 0,
    twoFactorRequired: false,
    login: vi.fn(),
    verify2fa: vi.fn(),
    register: vi.fn(),
    unlock: vi.fn(),
    logout: vi.fn(() => Promise.resolve()),
    lock: vi.fn(() => Promise.resolve()),
    ...partial,
  } as unknown as AuthState;
  vi.mocked(useAuthStore).mockImplementation(((selector?: (s: AuthState) => unknown) =>
    selector ? selector(state) : state) as typeof useAuthStore);
  vi.mocked(useAuthStore.getState).mockReturnValue(state);
}

function stubVaultStore(): void {
  const state = {
    fetchItems: vi.fn(() => Promise.resolve()),
    fetchFolders: vi.fn(() => Promise.resolve()),
    fetchTrashItems: vi.fn(() => Promise.resolve()),
    showTrash: false,
    selectedType: null,
    selectedFolder: null,
    searchQuery: '',
    setSearchQuery: vi.fn(),
    filteredItemCount: null,
  } as unknown as VaultState;
  vi.mocked(useVaultStore).mockImplementation(((selector?: (s: VaultState) => unknown) =>
    selector ? selector(state) : state) as typeof useVaultStore);
}

/** Every landmark the rendered document exposes, by the role a menu lists it under. */
function landmarks(): { role: string; element: Element }[] {
  return [...LANDMARK_ROLES].flatMap((role) =>
    screen.queryAllByRole(role).map((element) => ({ role, element })),
  );
}

/**
 * The outline every screen must have: one `main`, one `h1` inside it, no skipped
 * heading level, and no two indistinguishable landmarks.
 */
function expectSoundOutline(h1: string | RegExp): HTMLElement {
  const main = screen.getByRole('main');
  const headingsOne = screen.getAllByRole('heading', { level: 1 });
  expect(headingsOne).toHaveLength(1);
  expect(headingsOne[0]).toHaveTextContent(h1);
  expect(main).toContainElement(headingsOne[0] ?? null);
  expect(firstSkippedHeadingLevel(headingLevels())).toBeNull();
  expect(duplicateLandmarks(landmarks())).toEqual([]);
  return main;
}

const LANDMARK_ROLES = new Set([
  'banner',
  'navigation',
  'main',
  'complementary',
  'contentinfo',
  'region',
  'search',
]);

/**
 * The elements `container` renders at its top level that are NOT landmarks.
 *
 * `ToastProvider` draws its named `Notifications` region beside the page, as it
 * does in the application, so the page is one of several top-level elements
 * rather than the only one; what `region` requires is that each of them is a
 * landmark, so that no content sits outside every landmark.
 */
function unlandmarkedTopLevel(container: HTMLElement): Element[] {
  return [...container.children].filter((element) => {
    const role = element.getAttribute('role') ?? implicitLandmarkRole(element);
    return role === null || !LANDMARK_ROLES.has(role);
  });
}

function implicitLandmarkRole(element: Element): string | null {
  switch (element.tagName) {
    case 'MAIN':
      return 'main';
    case 'HEADER':
      return 'banner';
    case 'NAV':
      return 'navigation';
    case 'ASIDE':
      return 'complementary';
    case 'FOOTER':
      return 'contentinfo';
    default:
      return null;
  }
}

/**
 * A standalone screen owns the whole viewport, so NOTHING it draws may sit
 * outside its landmark: its root element must be the `main` itself. This is the
 * `region` rule, stated as structure rather than scanned for.
 */
function expectStandaloneScreen(container: HTMLElement, h1: string | RegExp): void {
  const main = expectSoundOutline(h1);
  expect(container.children).toContain(main);
  expect(unlandmarkedTopLevel(container)).toEqual([]);
  // A standalone screen is not the application shell.
  expect(screen.queryByRole('banner')).toBeNull();
  expect(screen.queryByRole('complementary')).toBeNull();
}

function renderAt(path: string, ui: React.ReactElement) {
  // The real provider, whose named `Notifications` region renders INLINE beside
  // the page, as in the application; `unlandmarkedTopLevel` accepts it because
  // it is a landmark, and nothing else may sit beside the page.
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </ToastProvider>,
  );
}

function httpError(status: number, message: string): AxiosError {
  return new AxiosError('failed', 'ERR_BAD_RESPONSE', undefined, undefined, {
    status,
    statusText: 'x',
    headers: {},
    config: { headers: new AxiosHeaders() },
    data: { success: false, message, statusCode: status, statusText: 'x' },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  stubAuthStore({});
  stubVaultStore();
});

/* -------------------------------------------------------------------------- */
/*  Standalone screens                                                         */
/* -------------------------------------------------------------------------- */

describe('standalone screens are one main landmark with the card title as the h1', () => {
  it('the sign-in page', () => {
    const { container } = renderAt('/login', <LoginPage />);
    expectStandaloneScreen(container, 'Welcome Back');
    // The form is inside the landmark, not merely the heading.
    expect(screen.getByRole('main')).toContainElement(screen.getByLabelText('Email'));
  });

  it('the sign-in page at its two-factor step', () => {
    stubAuthStore({ twoFactorRequired: true });
    const { container } = renderAt('/login', <LoginPage />);
    expectStandaloneScreen(container, 'Two-Factor Authentication');
  });

  it('the registration page', () => {
    const { container } = renderAt('/register', <RegisterPage />);
    expectStandaloneScreen(container, 'Create Account');
  });

  it('the forgot-password page', () => {
    const { container } = renderAt('/forgot-password', <ForgotPasswordPage />);
    expectStandaloneScreen(container, 'Forgot Password');
  });

  it('the reset-password form, reached with a token', () => {
    const { container } = renderAt('/reset-password?token=abc', <ResetPasswordPage />);
    expectStandaloneScreen(container, 'Reset Password');
  });

  it('the reset-password page without a token, on its invalid-link card', () => {
    const { container } = renderAt('/reset-password', <ResetPasswordPage />);
    expectStandaloneScreen(container, 'Invalid Link');
  });

  it('the email-verification page while it waits, and after the server refuses', async () => {
    let refuse: (error: unknown) => void = () => {};
    mockVerifyEmail.mockReturnValue(
      new Promise((_resolve, reject) => {
        refuse = reject;
      }),
    );
    const { container } = renderAt('/verify-email?token=abc', <VerifyEmailPage />);
    expectStandaloneScreen(container, 'Verifying Email');

    refuse(httpError(400, 'Invalid or expired verification token'));
    await screen.findByRole('heading', { level: 1, name: 'Verification Failed' });
    expectStandaloneScreen(container, 'Verification Failed');
  });

  it('the account-unlock page after the server refuses', async () => {
    mockUnlockAccount.mockRejectedValue(httpError(400, 'Invalid or expired unlock token'));
    const { container } = renderAt('/unlock-account?token=abc', <UnlockAccountPage />);
    await screen.findByRole('heading', { level: 1, name: 'Unlock Failed' });
    expectStandaloneScreen(container, 'Unlock Failed');
  });

  it('the 404 page, whose subtitle stays one level below its h1', () => {
    const { container } = renderAt('/nowhere', <NotFoundPage />);
    expectStandaloneScreen(container, '404');
    expect(headingLevels()).toEqual([1, 2]);
  });

  it('the unlock screen', () => {
    stubAuthStore({ isAuthenticated: true, isLocked: true });
    const { container } = renderAt('/vault', <UnlockScreen />);
    expectStandaloneScreen(container, 'Vault Locked');
  });
});

/* -------------------------------------------------------------------------- */
/*  The screens ProtectedRoute draws in place of the application               */
/* -------------------------------------------------------------------------- */

describe('the session-recovery screens are standalone screens too', () => {
  function renderGuarded() {
    stubAuthStore({ isAuthenticated: true, isLocked: false, accessToken: null });
    return renderAt(
      '/vault',
      <Routes>
        <Route element={<ProtectedRoute />}>
          <Route path="/vault" element={<p>the vault</p>} />
        </Route>
      </Routes>,
    );
  }

  it('while the session is being resumed', () => {
    mockRefreshToken.mockReturnValue(new Promise(() => {}));
    const { container } = renderGuarded();
    expect(container.children).toContain(screen.getByRole('main'));
    expect(unlandmarkedTopLevel(container)).toEqual([]);
    expect(screen.queryByText('the vault')).toBeNull();
  });

  it('when the server cannot be reached', async () => {
    mockRefreshToken.mockRejectedValue(new AxiosError('Network Error', 'ERR_NETWORK'));
    const { container } = renderGuarded();
    await screen.findByRole('heading', { level: 1, name: 'Could not reach the server' });
    expectStandaloneScreen(container, 'Could not reach the server');
    // Still the recoverable screen: the session was kept, not ended.
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });

  it('when the account is locked', async () => {
    mockRefreshToken.mockRejectedValue(httpError(403, 'ACCOUNT_LOCKED'));
    const { container } = renderGuarded();
    await screen.findByRole('heading', { level: 1, name: 'Account temporarily locked' });
    expectStandaloneScreen(container, 'Account temporarily locked');
  });

  it('the loading screen shown while a session resumes or a route loads', () => {
    const { container } = render(<LoadingSpinner />);
    const main = screen.getByRole('main');
    expect(container.firstElementChild).toBe(main);
    expect(unlandmarkedTopLevel(container)).toEqual([]);
    expect(main).toHaveTextContent('Loading...');
    // A transient screen with nothing to name yet: no banner, no rail.
    expect(screen.queryByRole('banner')).toBeNull();
  });
});

/* -------------------------------------------------------------------------- */
/*  The application shell                                                      */
/* -------------------------------------------------------------------------- */

describe('the application shell', () => {
  function renderShell(path: string, page: React.ReactElement) {
    stubAuthStore({ isAuthenticated: true, isLocked: false, accessToken: 'token' });
    return renderAt(
      path,
      <Routes>
        <Route element={<AppLayout />}>
          <Route path={path} element={page} />
        </Route>
      </Routes>,
    );
  }

  it('makes the sidebar the banner: brand, primary navigation and account controls', () => {
    renderShell('/generator', <h1>Password Generator</h1>);
    const banner = screen.getByRole('banner');
    expect(banner.tagName).toBe('HEADER');
    expect(banner).toContainElement(screen.getByRole('navigation'));
    expect(banner).toContainElement(screen.getByRole('link', { name: 'Vault' }));
    expect(banner).toContainElement(screen.getByRole('button', { name: 'Lock Vault' }));
    expect(banner).toContainElement(screen.getByRole('button', { name: 'Logout' }));
    // The page itself is NOT in the banner.
    expect(banner).not.toContainElement(screen.getByRole('main'));
    // And the shell alone contributes no complementary landmark at all.
    expect(screen.queryByRole('complementary')).toBeNull();
    expectSoundOutline('Password Generator');
  });

  it('gives the vault page an h1 and one complementary landmark, the folder rail', async () => {
    renderShell('/vault', <VaultPage />);
    const main = expectSoundOutline('Vault');
    const rail = screen.getByRole('complementary');
    expect(main).toContainElement(rail);
    expect(rail).toHaveTextContent('All items');
    // The h1 names the page, and it is outside the rail it sits beside.
    expect(rail).not.toContainElement(screen.getByRole('heading', { level: 1 }));
    await waitFor(() => expect(screen.getByText('vault rows')).toBeInTheDocument());
  });
});
