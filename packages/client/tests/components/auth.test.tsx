import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LoginPage } from '../../src/components/auth/LoginPage';
import { RegisterPage } from '../../src/components/auth/RegisterPage';
import { UnlockScreen } from '../../src/components/auth/UnlockScreen';
import { useAuthStore } from '../../src/stores/authStore';
import { api } from '../../src/services/api/client';
import { cryptoService } from '../../src/services/crypto/cryptoService';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), {
    getState: vi.fn(),
    setState: vi.fn(),
  }),
}));

vi.mock('../../src/services/api/client', () => ({
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

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

// Provide a lightweight mock for zxcvbn so we don't need the full dictionary
vi.mock('zxcvbn', () => ({
  default: (password: string) => {
    let score = 0;
    if (password.length >= 8) score = 1;
    if (password.length >= 12) score = 2;
    if (password.length >= 16) score = 3;
    if (password.length >= 20) score = 4;
    return {
      score,
      feedback: {
        warning: '',
        suggestions: [],
      },
    };
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

// ---------------------------------------------------------------------------
// LoginPage
// ---------------------------------------------------------------------------

describe('LoginPage', () => {
  const mockLogin = vi.fn();
  const mockVerify2fa = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          login: mockLogin,
          verify2fa: mockVerify2fa,
          twoFactorRequired: false,
        };
        return selector ? selector(state) : state;
      },
    );

    vi.mocked(useAuthStore.getState).mockReturnValue({
      twoFactorRequired: false,
      isAuthenticated: true,
    } as unknown as ReturnType<typeof useAuthStore.getState>);
  });

  it('renders the login form with title and fields', () => {
    renderWithRouter(<LoginPage />);

    expect(screen.getByText('Welcome Back')).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Master Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('renders the "Forgot password?" link', () => {
    renderWithRouter(<LoginPage />);

    expect(screen.getByText('Forgot password?')).toBeInTheDocument();
  });

  it('renders the "Create account" link', () => {
    renderWithRouter(<LoginPage />);

    expect(screen.getByText('Create account')).toBeInTheDocument();
  });

  it('shows validation errors when submitting empty form', async () => {
    renderWithRouter(<LoginPage />);

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText('Email is required')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText('Master password is required')).toBeInTheDocument();
    });
  });

  it('shows email validation error for invalid email', async () => {
    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'not-an-email' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'somepassword' },
    });

    // Use fireEvent.submit to bypass native HTML5 email validation in jsdom
    const form = screen.getByLabelText('Email').closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByText('Enter a valid email address')).toBeInTheDocument();
    });
  });

  it('toggles password visibility', () => {
    renderWithRouter(<LoginPage />);

    const passwordInput = screen.getByLabelText('Master Password');
    expect(passwordInput).toHaveAttribute('type', 'password');

    const toggleButton = screen.getByLabelText('Show password');
    fireEvent.click(toggleButton);

    expect(passwordInput).toHaveAttribute('type', 'text');
    expect(screen.getByLabelText('Hide password')).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Hide password'));
    expect(passwordInput).toHaveAttribute('type', 'password');
  });

  it('calls login with email and password on valid submit', async () => {
    mockLogin.mockResolvedValue(undefined);

    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('user@example.com', 'myMasterPassword123');
    });
  });

  it('navigates to /vault after successful login when not 2FA', async () => {
    mockLogin.mockResolvedValue(undefined);
    vi.mocked(useAuthStore.getState).mockReturnValue({
      twoFactorRequired: false,
      isAuthenticated: true,
    } as unknown as ReturnType<typeof useAuthStore.getState>);

    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/vault', { replace: true });
    });
  });

  it('does not navigate when 2FA is required after login', async () => {
    mockLogin.mockResolvedValue(undefined);
    vi.mocked(useAuthStore.getState).mockReturnValue({
      twoFactorRequired: true,
      isAuthenticated: false,
    } as unknown as ReturnType<typeof useAuthStore.getState>);

    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalled();
    });

    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('displays an API error on login failure', async () => {
    mockLogin.mockRejectedValue(new Error('Invalid credentials'));

    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid credentials');
    });
  });

  it('displays a generic error when login throws a non-Error', async () => {
    mockLogin.mockRejectedValue('something went wrong');

    renderWithRouter(<LoginPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Login failed. Please try again.');
    });
  });

  // -- 2FA view --
  // These tests set up twoFactorRequired inline (not via a nested beforeEach)
  // to avoid a jsdom 28 + Vitest 4 compatibility issue where `document` can
  // become unavailable inside nested describe/beforeEach blocks.

  function setup2FA() {
    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          login: mockLogin,
          verify2fa: mockVerify2fa,
          twoFactorRequired: true,
        };
        return selector ? selector(state) : state;
      },
    );
  }

  /** Fill all 6 OTP digit boxes by pasting `code` into the first box. */
  function fillOtpCode(code: string) {
    const inputs = screen.getAllByRole('textbox');
    fireEvent.paste(inputs[0]!, {
      clipboardData: { getData: () => code },
    });
  }

  it('renders the 2FA form when twoFactorRequired is true', () => {
    setup2FA();
    renderWithRouter(<LoginPage />);

    expect(screen.getByText('Two-Factor Authentication')).toBeInTheDocument();
    // OTP input renders a role="group" container with individual digit boxes
    expect(
      screen.getByRole('group', { name: /verification code|one-time password/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /verify/i })).toBeInTheDocument();
  });

  it('disables verify button when OTP code is incomplete', () => {
    setup2FA();
    renderWithRouter(<LoginPage />);

    // Button is disabled when fewer than 6 digits are entered
    expect(screen.getByRole('button', { name: /verify/i })).toBeDisabled();

    // Enter only 3 digits — button should still be disabled
    fillOtpCode('123');
    expect(screen.getByRole('button', { name: /verify/i })).toBeDisabled();
  });

  it('calls verify2fa and navigates on valid OTP code', async () => {
    setup2FA();
    mockVerify2fa.mockResolvedValue(undefined);

    renderWithRouter(<LoginPage />);

    fillOtpCode('123456');

    fireEvent.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => {
      expect(mockVerify2fa).toHaveBeenCalledWith('123456');
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/vault', { replace: true });
    });
  });

  it('displays an API error on 2FA OTP failure', async () => {
    setup2FA();
    mockVerify2fa.mockRejectedValue(new Error('Invalid 2FA code'));

    renderWithRouter(<LoginPage />);

    fillOtpCode('000000');

    fireEvent.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid 2FA code');
    });
  });

  it('displays a generic error on 2FA OTP non-Error rejection', async () => {
    setup2FA();
    mockVerify2fa.mockRejectedValue('unknown error');

    renderWithRouter(<LoginPage />);

    fillOtpCode('123456');

    fireEvent.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid code. Please try again.');
    });
  });

  it('switches to backup code input and validates submission', async () => {
    setup2FA();
    mockVerify2fa.mockResolvedValue(undefined);

    renderWithRouter(<LoginPage />);

    // Switch to backup code mode
    fireEvent.click(screen.getByText('Use a backup code'));

    // Backup code input should now be visible
    expect(screen.getByLabelText('Backup Code')).toBeInTheDocument();

    // Submit with a valid backup code
    fireEvent.change(screen.getByLabelText('Backup Code'), {
      target: { value: 'abcdef1234567890' },
    });
    fireEvent.click(screen.getByRole('button', { name: /verify/i }));

    await waitFor(() => {
      expect(mockVerify2fa).toHaveBeenCalledWith('abcdef1234567890');
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/vault', { replace: true });
    });
  });

  it('shows green registration success banner when navigated from register with emailSent', () => {
    render(
      <MemoryRouter
        initialEntries={[{ pathname: '/login', state: { registered: true, emailSent: true } }]}
      >
        <LoginPage />
      </MemoryRouter>,
    );

    expect(screen.getByRole('status')).toHaveTextContent(/account created/i);
    expect(screen.getByRole('status')).toHaveTextContent(/check your email/i);
  });

  it('shows yellow warning banner when registration succeeded but email failed', () => {
    render(
      <MemoryRouter
        initialEntries={[{ pathname: '/login', state: { registered: true, emailSent: false } }]}
      >
        <LoginPage />
      </MemoryRouter>,
    );

    expect(screen.getByRole('alert')).toHaveTextContent(/could not send/i);
  });
});

// ---------------------------------------------------------------------------
// RegisterPage
// ---------------------------------------------------------------------------

describe('RegisterPage', () => {
  const mockRegister = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          register: mockRegister,
        };
        return selector ? selector(state) : state;
      },
    );
  });

  it('renders the registration form with title and all fields', () => {
    renderWithRouter(<RegisterPage />);

    expect(screen.getByRole('heading', { name: /create account/i })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Master Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm Master Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument();
  });

  it('renders the "Sign in" link', () => {
    renderWithRouter(<RegisterPage />);

    expect(screen.getByText('Sign in')).toBeInTheDocument();
  });

  it('renders the password recovery warning', () => {
    renderWithRouter(<RegisterPage />);

    expect(screen.getByText(/your master password cannot be recovered/i)).toBeInTheDocument();
  });

  it('renders the terms checkbox text', () => {
    renderWithRouter(<RegisterPage />);

    expect(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    ).toBeInTheDocument();
  });

  it('shows validation errors when submitting empty form', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByText('Email is required')).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(
        screen.getByText('Master password must be at least 12 characters'),
      ).toBeInTheDocument();
    });
  });

  it('shows email validation error for invalid email', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'bad-email' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'longEnoughPass12' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'longEnoughPass12' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    // Use fireEvent.submit to bypass native HTML5 email validation in jsdom
    const form = screen.getByLabelText('Email').closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByText('Enter a valid email address')).toBeInTheDocument();
    });
  });

  it('shows error when password is shorter than 12 characters', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'short' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'short' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(
        screen.getByText('Master password must be at least 12 characters'),
      ).toBeInTheDocument();
    });
  });

  it('shows error when passwords do not match', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'longEnoughPass12' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'differentPass999' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByText('Passwords do not match')).toBeInTheDocument();
    });
  });

  it('shows error when terms are not accepted', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'longEnoughPass12' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'longEnoughPass12' },
    });

    // Do NOT click the terms checkbox

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByText('You must acknowledge this to continue')).toBeInTheDocument();
    });
  });

  it('shows password strength indicator when typing a password', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'short' },
    });

    // Our mock zxcvbn returns score 0 for < 8 chars => "Very weak"
    // zxcvbn loads asynchronously so wait for the indicator to appear
    await waitFor(() => {
      expect(screen.getByText('Very weak')).toBeInTheDocument();
    });
  });

  it('updates the strength label as the password gets stronger', async () => {
    renderWithRouter(<RegisterPage />);

    // 8 chars => score 1 => "Weak"
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: '12345678' },
    });
    await waitFor(() => {
      expect(screen.getByText('Weak')).toBeInTheDocument();
    });

    // 12 chars => score 2 => "Fair"
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: '123456789012' },
    });
    await waitFor(() => {
      expect(screen.getByText('Fair')).toBeInTheDocument();
    });

    // 16 chars => score 3 => "Strong"
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: '1234567890123456' },
    });
    await waitFor(() => {
      expect(screen.getByText('Strong')).toBeInTheDocument();
    });

    // 20 chars => score 4 => "Very strong"
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: '12345678901234567890' },
    });
    await waitFor(() => {
      expect(screen.getByText('Very strong')).toBeInTheDocument();
    });
  });

  it('calls register and navigates to /login on successful submit', async () => {
    mockRegister.mockResolvedValue({ emailSent: true });

    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'newuser@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith('newuser@example.com', 'superStrongPass1');
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login', {
        replace: true,
        state: { registered: true, emailSent: true },
      });
    });
  });

  it('displays an API error on registration failure', async () => {
    mockRegister.mockRejectedValue(new Error('Email already registered'));

    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'existing@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Email already registered');
    });
  });

  it('displays a generic error on non-Error rejection', async () => {
    mockRegister.mockRejectedValue('unknown error');

    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Registration failed. Please try again.');
    });
  });

  // ── zxcvbn strength enforcement ────────────────────────────────────────────
  // The mock zxcvbn returns score 2 ("Fair") for 12-15 chars, score 3 ("Strong")
  // for 16-19 chars, and score 4 ("Very strong") for 20+ chars. The form
  // schema allows any password >= 12 chars, but submission must additionally
  // be gated on score >= 3 to mirror the change-password flow in SettingsPage.

  it('rejects submission when zxcvbn score is below 3 (weak password)', async () => {
    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    // 12 chars => mock score 2 ("Fair") — passes the schema length check
    // but should be rejected by the zxcvbn gate.
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'password1234' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'password1234' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'New password is too weak. Please choose a stronger password.',
      );
    });

    // The register function must NOT have been called for a weak password
    expect(mockRegister).not.toHaveBeenCalled();
  });

  it('accepts submission when zxcvbn score is >= 3 (strong password)', async () => {
    mockRegister.mockResolvedValue({ emailSent: true });

    renderWithRouter(<RegisterPage />);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    // 16 chars => mock score 3 ("Strong")
    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.change(screen.getByLabelText('Confirm Master Password'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.click(
      screen.getByText(/I understand that H-Vault cannot recover my master password/),
    );

    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    await waitFor(() => {
      expect(mockRegister).toHaveBeenCalledWith('user@example.com', 'superStrongPass1');
    });
  });
});

// ---------------------------------------------------------------------------
// UnlockScreen
// ---------------------------------------------------------------------------

describe('UnlockScreen', () => {
  const mockUnlock = vi.fn();
  const mockLogout = vi.fn();
  const mockSetAccessToken = vi.fn();
  const fakeMek = { __cryptoKey: 'mek' } as unknown as CryptoKey;
  const fakeAuthKey = new ArrayBuffer(32);

  beforeEach(() => {
    vi.clearAllMocks();
    // Clear persisted rate-limiting state so tests start fresh
    sessionStorage.removeItem('__hv_unlock_failed_attempts');
    sessionStorage.removeItem('__hv_unlock_lockout_until');
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

  it('renders the unlock form with title', () => {
    renderWithRouter(<UnlockScreen />);

    expect(screen.getByText('Vault Locked')).toBeInTheDocument();
    expect(screen.getByLabelText('Master Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /unlock vault/i })).toBeInTheDocument();
  });

  it('displays the user email when available', () => {
    renderWithRouter(<UnlockScreen />);

    expect(screen.getByText('Signed in as vault@example.com')).toBeInTheDocument();
  });

  it('shows fallback text when user has no email', () => {
    vi.mocked(useAuthStore).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          user: null,
          unlock: mockUnlock,
          logout: mockLogout,
        };
        return selector ? selector(state) : state;
      },
    );

    renderWithRouter(<UnlockScreen />);

    expect(screen.getByText('Enter your master password to unlock')).toBeInTheDocument();
  });

  it('renders the logout button', () => {
    renderWithRouter(<UnlockScreen />);

    expect(screen.getByRole('button', { name: /logout/i })).toBeInTheDocument();
  });

  it('shows validation error when submitting empty password', async () => {
    renderWithRouter(<UnlockScreen />);

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(screen.getByText('Master password is required')).toBeInTheDocument();
    });
  });

  it('calls verify-unlock before unlock and refreshes session on valid submit', async () => {
    mockUnlock.mockResolvedValue(undefined);

    renderWithRouter(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword' },
    });

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/auth/refresh');
    });

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/auth/verify-unlock',
        { authHash: 'mock-auth-hash' },
        { _skipAuthRefresh: true },
      );
    });

    await waitFor(() => {
      expect(mockUnlock).toHaveBeenCalledWith('myMasterPassword', fakeMek);
    });

    // verify-unlock must be invoked BEFORE the local unlock/decrypt step.
    const apiPostMock = vi.mocked(api.post);
    const verifyCallIdx = apiPostMock.mock.calls.findIndex((c) => c[0] === '/auth/verify-unlock');
    const unlockCallIdx = mockUnlock.mock.invocationCallOrder[0] ?? 0;
    const verifyOrder = apiPostMock.mock.invocationCallOrder[verifyCallIdx] ?? Infinity;
    expect(verifyOrder).toBeLessThan(unlockCallIdx);

    await waitFor(() => {
      expect(mockSetAccessToken).toHaveBeenCalledWith('new-token-123');
    });

    await waitFor(() => {
      expect(useAuthStore.setState).toHaveBeenCalledWith({
        isLocked: false,
      });
    });
  });

  it('does not run local decrypt when server rejects verify-unlock', async () => {
    mockUnlock.mockResolvedValue(undefined);

    // First call: /auth/refresh succeeds. Second call: /auth/verify-unlock returns 429.
    vi.mocked(api.post)
      .mockResolvedValueOnce({
        data: { data: { accessToken: 'new-token-123' } },
      })
      .mockRejectedValueOnce(new Error('Too many unlock attempts'));

    renderWithRouter(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'wrongPassword' },
    });

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/auth/verify-unlock',
        { authHash: 'mock-auth-hash' },
        { _skipAuthRefresh: true },
      );
    });

    // Must not proceed to the local vault key decrypt step
    expect(mockUnlock).not.toHaveBeenCalled();
    expect(useAuthStore.setState).not.toHaveBeenCalledWith({ isLocked: false });
  });

  it('logs out and navigates to /login when session refresh fails', async () => {
    mockUnlock.mockResolvedValue(undefined);
    mockLogout.mockResolvedValue(undefined);
    vi.mocked(api.post).mockRejectedValue(new Error('Session expired'));

    renderWithRouter(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'myMasterPassword' },
    });

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(mockLogout).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login', {
        replace: true,
      });
    });
  });

  it('displays an API error when unlock itself fails', async () => {
    mockUnlock.mockRejectedValue(new Error('Incorrect master password'));

    renderWithRouter(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'wrongPassword' },
    });

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Incorrect master password');
    });
  });

  it('displays a generic error when unlock throws a non-Error', async () => {
    mockUnlock.mockRejectedValue('unknown failure');

    renderWithRouter(<UnlockScreen />);

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'wrongPassword' },
    });

    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Incorrect master password. Please try again.',
      );
    });
  });

  it('calls logout and navigates to /login when clicking the Logout button', async () => {
    mockLogout.mockResolvedValue(undefined);

    renderWithRouter(<UnlockScreen />);

    fireEvent.click(screen.getByRole('button', { name: /logout/i }));

    await waitFor(() => {
      expect(mockLogout).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/login', {
        replace: true,
      });
    });
  });

  it('toggles password visibility', () => {
    renderWithRouter(<UnlockScreen />);

    const passwordInput = screen.getByLabelText('Master Password');
    expect(passwordInput).toHaveAttribute('type', 'password');

    fireEvent.click(screen.getByLabelText('Show password'));
    expect(passwordInput).toHaveAttribute('type', 'text');

    fireEvent.click(screen.getByLabelText('Hide password'));
    expect(passwordInput).toHaveAttribute('type', 'password');
  });
});
