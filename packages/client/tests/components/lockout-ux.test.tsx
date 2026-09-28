/**
 * F-03 — what a user is told once a lockout answers exactly like a wrong password.
 *
 * During a password lockout the server now answers every unproven sign-in with
 * the ordinary 401, whether or not the password was right (a distinct answer
 * would confirm a guessed password to whoever sent it). The owner, too, therefore
 * sees only "Invalid email or password", and needs to be told where the way back
 * in is without being told the account is locked:
 *
 *   - a CONSTANT hint under every 401 from the sign-in form, pointing at the
 *     unlock link in their inbox (constant, so it reveals nothing about the
 *     account either);
 *   - the same note on the forgot-password page, saying the link is the remedy
 *     and that a password reset erases the vault (it mints a new vault key).
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import { LoginPage } from '../../src/components/auth/LoginPage';
import { ForgotPasswordPage } from '../../src/components/auth/ForgotPasswordPage';
import { useAuthStore } from '../../src/stores/authStore';

vi.mock('../../src/stores/authStore', () => ({
  useAuthStore: Object.assign(vi.fn(), { getState: vi.fn() }),
}));

vi.mock('../../src/services/api/authApi', () => ({
  forgotPasswordApi: vi.fn(),
}));

const HINT = 'If this keeps failing, check your inbox for an unlock link.';

type AuthState = ReturnType<typeof useAuthStore.getState>;

function axiosErrorWithStatus(status: number, message: string): AxiosError {
  const error = new AxiosError(message);
  error.response = {
    status,
    statusText: '',
    data: { success: false, message, statusCode: status, statusText: '' },
    headers: new AxiosHeaders(),
    config: { headers: new AxiosHeaders() },
  };
  return error;
}

const mockLogin = vi.fn();

function renderLogin() {
  vi.mocked(useAuthStore).mockImplementation((selector?: (state: AuthState) => unknown) => {
    const state = {
      login: mockLogin,
      verify2fa: vi.fn(),
      twoFactorRequired: false,
    } as unknown as AuthState;
    return selector ? selector(state) : state;
  });
  vi.mocked(useAuthStore.getState).mockReturnValue({
    twoFactorRequired: false,
    isAuthenticated: false,
  } as unknown as AuthState);
  render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>,
  );
}

function submitLogin() {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.com' } });
  fireEvent.change(screen.getByLabelText('Master Password'), {
    target: { value: 'correct horse battery staple' },
  });
  fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
}

describe('LoginPage — the constant unlock-link hint', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset, not just clear: a queued `mockImplementationOnce` left by one test
    // must not answer the next test's submit.
    mockLogin.mockReset();
  });

  it('shows the hint under a 401, beside the generic error', async () => {
    mockLogin.mockRejectedValue(axiosErrorWithStatus(401, 'Invalid email or password'));
    renderLogin();
    submitLogin();

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid email or password');
    });
    expect(screen.getByText(HINT)).toBeInTheDocument();
    // The hint is advice, not an error: it never names a lockout.
    expect(screen.queryByText(/locked/i)).toBeNull();
  });

  it('does not show the hint for a failure that is not a refused sign-in', async () => {
    mockLogin.mockRejectedValue(axiosErrorWithStatus(429, 'Too many authentication attempts'));
    renderLogin();
    submitLogin();

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
    expect(screen.queryByText(HINT)).toBeNull();
  });

  it('clears the hint when the form is submitted again', async () => {
    mockLogin
      .mockRejectedValueOnce(axiosErrorWithStatus(401, 'Invalid email or password'))
      .mockImplementationOnce(() => new Promise(() => {}));
    renderLogin();
    submitLogin();
    await screen.findByText(HINT);

    submitLogin();
    await waitFor(() => {
      expect(screen.queryByText(HINT)).toBeNull();
    });
  });
});

describe('ForgotPasswordPage — the lockout note', () => {
  it('names the unlock link as the remedy and says a reset erases the vault', () => {
    render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    );

    const note = screen.getByText(/unlock link/i);
    expect(note).toHaveTextContent(
      'Locked out after too many attempts? Use the unlock link we emailed you instead.',
    );
    expect(note).toHaveTextContent(
      'Resetting your master password erases everything in your vault.',
    );
  });
});
