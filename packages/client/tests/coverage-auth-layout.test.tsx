/**
 * Behavioural coverage for the auth + layout surface that the existing suites
 * leave untested:
 *
 *  - UnlockScreen: the client-side unlock rate limiter (exponential backoff,
 *    localStorage persistence across remounts, the cooldown countdown, the
 *    locked-out submit guard) and the missing-email refusal.
 *  - LoginPage: the sessionExpired banner, the short-OTP guard and the
 *    backup-code -> authenticator hand-back.
 *  - RegisterPage: the zxcvbn feedback (warning + suggestions) and the two
 *    independent password-visibility toggles.
 *  - AppLayout: the vault-decryption-failure banner (re-sync + dismiss) and the
 *    offline -> online auto-refetch (success / failure / locked).
 *  - FileDecryptPanel: Enter-to-submit and the remaining describeFileCryptoError
 *    kinds (too-large, engine-unavailable).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, cleanup } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';
import { CryptoError, CryptoErrorType } from '@hiprax/crypto';

/* -------------------------------------------------------------------------- */
/*  Hoisted mock handles                                                       */
/* -------------------------------------------------------------------------- */

const {
  mockNavigate,
  mockToast,
  mockZxcvbn,
  mockDecryptFile,
  mockGetMaxBytes,
  mockIsStorageDegraded,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockToast: vi.fn(),
  mockZxcvbn: vi.fn(),
  mockDecryptFile: vi.fn(),
  mockGetMaxBytes: vi.fn(),
  mockIsStorageDegraded: vi.fn(() => false),
}));

/* -------------------------------------------------------------------------- */
/*  Module mocks                                                               */
/* -------------------------------------------------------------------------- */

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), { getState: vi.fn(), setState: vi.fn() }),
}));

vi.mock('../src/stores/vaultStore', () => ({
  useVaultStore: vi.fn(),
}));

vi.mock('../src/services/api/client', () => ({
  api: { post: vi.fn(), get: vi.fn(), put: vi.fn(), delete: vi.fn() },
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

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: () => Promise.resolve(mockZxcvbn),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('../src/stores/encryptedStorage', () => ({
  isStorageDegraded: mockIsStorageDegraded,
  encryptedStorage: { getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn() },
}));

vi.mock('../src/hooks/useAutoLock', () => ({ useAutoLock: vi.fn() }));
vi.mock('../src/hooks/useClipboardGuard', () => ({
  useClipboardGuard: vi.fn(),
  markClipboardDirty: vi.fn(),
  markClipboardClean: vi.fn(),
  clearClipboardIfDirty: vi.fn(),
  scheduleClipboardClear: vi.fn(),
}));
vi.mock('../src/hooks/useKeyboardShortcuts', () => ({ useKeyboardShortcuts: vi.fn() }));
vi.mock('../src/hooks/useConnectionStatus', () => ({
  useConnectionStatus: () => ({ isOnline: true }),
}));
vi.mock('../src/components/layout/OnboardingGuide', () => ({ OnboardingGuide: () => null }));

vi.mock('../src/services/api/configApi', () => ({
  getFileEncryptionMaxBytes: mockGetMaxBytes,
}));

vi.mock('../src/services/crypto/fileCryptoService', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/crypto/fileCryptoService')>();
  return { ...actual, decryptFile: mockDecryptFile };
});

/* -------------------------------------------------------------------------- */
/*  Imports (after the mocks)                                                  */
/* -------------------------------------------------------------------------- */

import { UnlockScreen } from '../src/components/auth/UnlockScreen';
import { LoginPage } from '../src/components/auth/LoginPage';
import { RegisterPage } from '../src/components/auth/RegisterPage';
import { AppLayout } from '../src/components/layout/AppLayout';
import { FileDecryptPanel } from '../src/components/tools/FileDecryptPanel';
import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { api } from '../src/services/api/client';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { FileTooLargeError } from '../src/services/crypto/fileCryptoService';

/* -------------------------------------------------------------------------- */
/*  Shared store harness                                                       */
/* -------------------------------------------------------------------------- */

const ATTEMPTS_KEY = '__hv_unlock_failed_attempts';
const LOCKOUT_KEY = '__hv_unlock_lockout_until';

type AnyState = Record<string, unknown>;

let authState: AnyState = {};
let vaultState: AnyState = {};

function installStores(): void {
  vi.mocked(useAuthStore).mockImplementation((selector?: (s: AnyState) => unknown) =>
    selector ? selector(authState) : authState,
  );
  vi.mocked(useAuthStore.getState).mockImplementation(
    () => authState as unknown as ReturnType<typeof useAuthStore.getState>,
  );
  vi.mocked(useVaultStore).mockImplementation((selector?: (s: AnyState) => unknown) =>
    selector ? selector(vaultState) : vaultState,
  );
}

/** A zxcvbn result strong enough to pass the score >= 3 submission gate. */
function zxcvbnResult(score: number, warning = '', suggestions: string[] = []) {
  return { score, feedback: { warning, suggestions } };
}

function renderRouted(ui: React.ReactElement, state?: Record<string, unknown>) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: '/', state: state ?? null }]}>{ui}</MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  authState = {};
  vaultState = {};
  installStores();
  mockZxcvbn.mockReturnValue(zxcvbnResult(4));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

/* ========================================================================== */
/*  UnlockScreen — client-side unlock rate limiting                            */
/* ========================================================================== */

describe('UnlockScreen — client-side unlock rate limiting', () => {
  const fakeMek = { __k: 'mek' } as unknown as CryptoKey;
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();

  function setupUnlock({ email = 'vault@example.com' }: { email?: string | null } = {}): void {
    authState = {
      user: email === null ? null : { userId: 'u1', email },
      unlock: mockUnlock,
      logout: mockLogout,
      setAccessToken: vi.fn(),
    };
    installStores();

    vi.mocked(api.post).mockResolvedValue({ data: { data: { accessToken: 'tok' } } });
    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: fakeMek,
      authKey: new ArrayBuffer(32),
    });
    vi.mocked(cryptoService.getAuthHash).mockReturnValue('hash');
    vi.mocked(cryptoService.clearKey).mockReturnValue();
    vi.mocked(cryptoService.clearCryptoKey).mockResolvedValue();
  }

  async function submitPassword(pw = 'some-password'): Promise<void> {
    fireEvent.change(screen.getByLabelText('Master Password'), { target: { value: pw } });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));
  }

  it('warns with the remaining attempts after a failed unlock', async () => {
    setupUnlock();
    mockUnlock.mockRejectedValue(new Error('Incorrect master password'));

    renderRouted(<UnlockScreen />);
    await submitPassword('wrong');

    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(
        /4 attempts remaining before temporary lockout/,
      );
    });
    // Still usable — a single failure must not lock the form.
    expect(screen.getByRole('button', { name: /unlock vault/i })).not.toBeDisabled();
  });

  it('locks the form for the exponential-backoff cooldown after 5 failures and persists it', async () => {
    setupUnlock();
    mockUnlock.mockRejectedValue(new Error('Incorrect master password'));

    renderRouted(<UnlockScreen />);

    // Bracket the instant the 5th failure's applyLockout computes `until`
    // (Date.now() + 2000). `before` is captured just before that final submit
    // and `after` just after the cooldown renders, so asserting `until` against
    // these captured bounds — rather than a fresh Date.now() at assertion time —
    // is robust to however long the async flow takes under load (the old
    // `until > Date.now()` left only a 2s budget that a slow CI run can blow).
    let before = 0;
    for (let i = 1; i <= 5; i++) {
      if (i === 5) before = Date.now();
      await submitPassword('wrong');
      await waitFor(() => {
        expect(mockUnlock).toHaveBeenCalledTimes(i);
      });
    }

    // 5 attempts => 2^(5-5) * 2 = 2 seconds.
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/Too many failed attempts.*2s/s);
    });
    expect(screen.getByRole('button', { name: /Locked \(2s\)/ })).toBeDisabled();
    const after = Date.now();

    // Persisted to localStorage (not sessionStorage) so a new tab cannot bypass it.
    expect(localStorage.getItem(ATTEMPTS_KEY)).toBe('5');
    // 2s lockout: `until` = T + 2000 for some T in [before, after].
    const until = Number(localStorage.getItem(LOCKOUT_KEY));
    expect(until).toBeGreaterThanOrEqual(before + 2000);
    expect(until).toBeLessThanOrEqual(after + 2000);
  });

  it('refuses to submit — and hits no endpoint — while a lockout is active', async () => {
    setupUnlock();
    mockUnlock.mockResolvedValue(undefined);
    localStorage.setItem(ATTEMPTS_KEY, '6');
    localStorage.setItem(LOCKOUT_KEY, String(Date.now() + 60_000));

    renderRouted(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'correct-password' },
    });
    // Force the submit past the disabled button, as a scripted/keyboard submit would.
    fireEvent.submit(screen.getByLabelText('Master Password').closest('form')!);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/Too many failed attempts/);
    });
    expect(api.post).not.toHaveBeenCalled();
    expect(mockUnlock).not.toHaveBeenCalled();
  });

  it('restores an in-progress lockout from localStorage across a remount', () => {
    setupUnlock();
    localStorage.setItem(ATTEMPTS_KEY, '7');
    localStorage.setItem(LOCKOUT_KEY, String(Date.now() + 8_000));

    renderRouted(<UnlockScreen />);

    // Countdown seeded from the persisted deadline, not reset to zero.
    expect(screen.getByRole('alert')).toHaveTextContent(/Too many failed attempts/);
    expect(screen.getByRole('button', { name: /Locked \(8s\)/ })).toBeDisabled();
  });

  it('ignores a lockout deadline that has already passed', () => {
    setupUnlock();
    localStorage.setItem(ATTEMPTS_KEY, '5');
    localStorage.setItem(LOCKOUT_KEY, String(Date.now() - 1_000));

    renderRouted(<UnlockScreen />);

    expect(screen.queryByText(/Too many failed attempts/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /unlock vault/i })).not.toBeDisabled();
  });

  it('re-enables the form once the cooldown elapses', () => {
    vi.useFakeTimers();
    setupUnlock();
    localStorage.setItem(ATTEMPTS_KEY, '5');
    localStorage.setItem(LOCKOUT_KEY, String(Date.now() + 2_000));

    renderRouted(<UnlockScreen />);
    expect(screen.getByRole('button', { name: /Locked \(2s\)/ })).toBeDisabled();

    act(() => {
      vi.advanceTimersByTime(2_100);
    });

    expect(screen.queryByText(/Too many failed attempts/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /unlock vault/i })).not.toBeDisabled();
  });

  it('treats a corrupt persisted attempt count as zero rather than locking out', async () => {
    setupUnlock();
    localStorage.setItem(ATTEMPTS_KEY, 'not-a-number');
    mockUnlock.mockRejectedValue(new Error('Incorrect master password'));

    renderRouted(<UnlockScreen />);
    expect(screen.getByRole('button', { name: /unlock vault/i })).not.toBeDisabled();

    await submitPassword('wrong');

    // Counted from 0, so the first failure leaves 4 attempts — not an instant lockout.
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(/4 attempts remaining/);
    });
  });

  it('clears the persisted rate-limit state on a successful unlock', async () => {
    setupUnlock();
    localStorage.setItem(ATTEMPTS_KEY, '3');
    mockUnlock.mockResolvedValue(undefined);

    renderRouted(<UnlockScreen />);
    await submitPassword('right-password');

    await waitFor(() => {
      expect(useAuthStore.setState).toHaveBeenCalledWith({ isLocked: false });
    });
    expect(localStorage.getItem(ATTEMPTS_KEY)).toBeNull();
    expect(localStorage.getItem(LOCKOUT_KEY)).toBeNull();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('refuses to unlock and never derives keys when the session has no email', async () => {
    setupUnlock({ email: null });

    renderRouted(<UnlockScreen />);
    await submitPassword('whatever');

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Cannot unlock: user email is not available',
      );
    });
    expect(api.post).not.toHaveBeenCalled();
    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/*  LoginPage                                                                  */
/* ========================================================================== */

describe('LoginPage — session expiry and the 2FA hand-off', () => {
  const mockLogin = vi.fn();
  const mockVerify2fa = vi.fn();

  function setupLogin(twoFactorRequired = false): void {
    authState = {
      login: mockLogin,
      verify2fa: mockVerify2fa,
      twoFactorRequired,
      isAuthenticated: !twoFactorRequired,
    };
    installStores();
  }

  it('shows the session-expired banner when ProtectedRoute redirected here', () => {
    setupLogin();

    renderRouted(<LoginPage />, { sessionExpired: true });

    expect(screen.getByRole('status')).toHaveTextContent(
      'Your session has expired. Please sign in again.',
    );
  });

  it('does not show the session-expired banner on a normal visit', () => {
    setupLogin();

    renderRouted(<LoginPage />);

    expect(screen.queryByText(/session has expired/i)).not.toBeInTheDocument();
  });

  it('rejects a forced 2FA submit with fewer than 6 digits without calling verify2fa', async () => {
    setupLogin(true);

    renderRouted(<LoginPage />);

    // The Verify button is disabled below 6 digits — force the submit anyway.
    const form = screen.getByRole('button', { name: /verify/i }).closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Code must be at least 6 digits');
    });
    expect(mockVerify2fa).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('clears the error and restores the authenticator input when leaving backup-code mode', async () => {
    setupLogin(true);
    mockVerify2fa.mockRejectedValue(new Error('Invalid backup code'));

    renderRouted(<LoginPage />);

    fireEvent.click(screen.getByText('Use a backup code'));
    fireEvent.change(screen.getByLabelText('Backup Code'), {
      target: { value: 'abcdef1234567890' },
    });
    fireEvent.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid backup code');
    });

    fireEvent.click(screen.getByText('Use authenticator code instead'));

    expect(screen.queryByLabelText('Backup Code')).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: /verification code/i })).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

/* ========================================================================== */
/*  RegisterPage                                                               */
/* ========================================================================== */

describe('RegisterPage — strength feedback and visibility toggles', () => {
  beforeEach(() => {
    authState = { register: vi.fn().mockResolvedValue({ emailSent: true }) };
    installStores();
  });

  it('surfaces the zxcvbn warning and suggestions for a weak master password', async () => {
    mockZxcvbn.mockReturnValue(
      zxcvbnResult(1, 'This is a top-10 common password', [
        'Add another word or two.',
        'Avoid repeated words and characters.',
      ]),
    );

    renderRouted(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'password1234' },
    });

    await waitFor(() => {
      expect(screen.getByText('Weak')).toBeInTheDocument();
    });
    expect(screen.getByText('This is a top-10 common password')).toBeInTheDocument();
    expect(screen.getByText('Add another word or two.')).toBeInTheDocument();
    expect(screen.getByText('Avoid repeated words and characters.')).toBeInTheDocument();
  });

  it('toggles each password field independently', () => {
    renderRouted(<RegisterPage />);

    const master = screen.getByLabelText('Master Password');
    const confirm = screen.getByLabelText('Confirm Master Password');
    expect(master).toHaveAttribute('type', 'password');
    expect(confirm).toHaveAttribute('type', 'password');

    // Two "Show password" buttons — the second belongs to the confirm field.
    const [masterToggle, confirmToggle] = screen.getAllByLabelText('Show password');
    fireEvent.click(confirmToggle!);

    expect(confirm).toHaveAttribute('type', 'text');
    expect(master).toHaveAttribute('type', 'password');

    fireEvent.click(masterToggle!);
    expect(master).toHaveAttribute('type', 'text');

    // Hiding the confirm field again must not re-hide the master field.
    fireEvent.click(screen.getAllByLabelText('Hide password')[1]!);
    expect(confirm).toHaveAttribute('type', 'password');
    expect(master).toHaveAttribute('type', 'text');
  });
});

/* ========================================================================== */
/*  AppLayout                                                                  */
/* ========================================================================== */

describe('AppLayout — decryption-failure banner and reconnect sync', () => {
  const fetchItems = vi.fn();
  const fetchFolders = vi.fn();
  const mockLock = vi.fn();
  const mockLogout = vi.fn();

  function setupLayout({ isLocked = false }: { isLocked?: boolean } = {}): void {
    authState = {
      user: { userId: 'u1', email: 'test@example.com' },
      logout: mockLogout,
      lock: mockLock,
      isLocked,
    };
    vaultState = { fetchItems, fetchFolders };
    installStores();
    fetchItems.mockResolvedValue(undefined);
    fetchFolders.mockResolvedValue(undefined);
  }

  function renderLayout() {
    return render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/vault" element={<div>Vault Content</div>} />
          </Route>
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );
  }

  function emitDecryptionFailures(count: number): void {
    act(() => {
      window.dispatchEvent(new CustomEvent('vault-decryption-failures', { detail: { count } }));
    });
  }

  it('shows the decryption-failure banner with the reported count', () => {
    setupLayout();
    renderLayout();

    expect(screen.queryByTestId('decryption-failure-banner')).not.toBeInTheDocument();

    emitDecryptionFailures(3);

    expect(screen.getByTestId('decryption-failure-banner')).toHaveTextContent(
      '3 item(s) could not be decrypted',
    );
  });

  it('re-syncs the vault and hides the banner when Re-sync is clicked', () => {
    setupLayout();
    renderLayout();
    emitDecryptionFailures(2);

    fireEvent.click(screen.getByRole('button', { name: /re-sync/i }));

    expect(fetchItems).toHaveBeenCalledTimes(1);
    expect(fetchFolders).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('decryption-failure-banner')).not.toBeInTheDocument();
  });

  it('dismisses the banner without refetching', () => {
    setupLayout();
    renderLayout();
    emitDecryptionFailures(2);

    fireEvent.click(screen.getByLabelText('Dismiss decryption warning'));

    expect(screen.queryByTestId('decryption-failure-banner')).not.toBeInTheDocument();
    expect(fetchItems).not.toHaveBeenCalled();
    expect(fetchFolders).not.toHaveBeenCalled();
  });

  it('refetches the vault and toasts success when the browser comes back online', async () => {
    setupLayout();
    renderLayout();

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(mockToast).toHaveBeenCalledWith({
      title: 'Back online. Syncing your vault...',
      type: 'info',
    });
    expect(fetchItems).toHaveBeenCalledTimes(1);
    expect(fetchFolders).toHaveBeenCalledTimes(1);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Vault synced successfully',
        type: 'success',
      });
    });
  });

  it('toasts a sync failure when the reconnect refetch rejects', async () => {
    setupLayout();
    fetchItems.mockRejectedValue(new Error('network down'));
    renderLayout();

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Failed to sync vault data',
        type: 'error',
      });
    });
    expect(mockToast).not.toHaveBeenCalledWith({
      title: 'Vault synced successfully',
      type: 'success',
    });
  });

  it('does not sync on reconnect while the vault is locked', () => {
    setupLayout({ isLocked: true });
    renderLayout();

    act(() => {
      window.dispatchEvent(new Event('online'));
    });

    expect(fetchItems).not.toHaveBeenCalled();
    expect(fetchFolders).not.toHaveBeenCalled();
    expect(mockToast).not.toHaveBeenCalled();
  });

  it('still leaves the app for /login when logout rejects', async () => {
    setupLayout();
    mockLogout.mockRejectedValue(new Error('server unreachable'));
    renderLayout();

    fireEvent.click(screen.getByText('Logout'));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });
});

/* ========================================================================== */
/*  FileDecryptPanel                                                           */
/* ========================================================================== */

describe('FileDecryptPanel — keyboard submit and error classification', () => {
  const BIG_LIMIT = 100 * 1024 * 1024;

  beforeEach(() => {
    mockGetMaxBytes.mockResolvedValue(BIG_LIMIT);
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn(() => 'blob:mock'),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function selectFile(name = 'report.pdf.enc', bytes = 400): void {
    const file = new File([new Uint8Array(bytes)], name, { type: 'application/octet-stream' });
    fireEvent.change(screen.getByLabelText('Encrypted file'), { target: { files: [file] } });
  }

  function pressEnterInPassword(): void {
    fireEvent.keyDown(screen.getByLabelText('Decryption password'), { key: 'Enter' });
  }

  it('decrypts on Enter in the password field', async () => {
    mockDecryptFile.mockResolvedValue({
      blob: new Blob(['plain']),
      filename: 'report.pdf',
      mime: 'application/pdf',
    });

    render(<FileDecryptPanel />);
    selectFile();
    fireEvent.change(screen.getByLabelText('Decryption password'), {
      target: { value: 'a-good-password' },
    });
    pressEnterInPassword();

    await waitFor(() => {
      expect(mockDecryptFile).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'success', title: 'File decrypted' }),
      );
    });
  });

  it('ignores Enter while the form is not submittable', () => {
    render(<FileDecryptPanel />);
    selectFile();
    // No password typed => canSubmit is false.
    pressEnterInPassword();

    expect(mockDecryptFile).not.toHaveBeenCalled();
  });

  it('surfaces the "too large" toast when the service rejects an oversized container', async () => {
    mockDecryptFile.mockRejectedValue(new FileTooLargeError(999, 100));

    render(<FileDecryptPanel />);
    selectFile();
    fireEvent.change(screen.getByLabelText('Decryption password'), {
      target: { value: 'a-good-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        type: 'error',
        title: 'This file is too large to process in your browser.',
      });
    });
  });

  it('reports an engine failure (not a wrong password) when Argon2 cannot start', async () => {
    // The decrypt path re-types a KDF failure to DECRYPTION_FAILED while keeping
    // code === 'KEY_DERIVATION_FAILED' — keying on `.type` would misreport a
    // blocked-WASM browser as "incorrect password".
    mockDecryptFile.mockRejectedValue(
      new CryptoError('wasm blocked', CryptoErrorType.DECRYPTION_FAILED, 'KEY_DERIVATION_FAILED'),
    );

    render(<FileDecryptPanel />);
    selectFile();
    fireEvent.change(screen.getByLabelText('Decryption password'), {
      target: { value: 'a-good-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: /decrypt & download/i }));

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        type: 'error',
        title:
          'The encryption engine could not start in this browser. Try a newer browser over HTTPS.',
      });
    });
  });
});
