import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resetPasswordApi } from '../../src/services/api/authApi';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../../src/services/api/authApi', () => ({
  resetPasswordApi: vi.fn(),
}));

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn().mockResolvedValue({
      masterEncryptionKey: {},
      authKey: new ArrayBuffer(32),
    }),
    getAuthHash: vi.fn().mockReturnValue('hash'),
    generateVaultKey: vi.fn().mockReturnValue(new ArrayBuffer(32)),
    importVaultKey: vi.fn().mockResolvedValue({}),
    clearKey: vi.fn(),
    encryptVaultKey: vi.fn().mockResolvedValue({
      encrypted: 'enc',
      iv: 'iv',
      tag: 'tag',
    }),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock zxcvbn with a lightweight score function
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
        warning: score < 2 ? 'Too short' : '',
        suggestions: score < 2 ? ['Add more characters'] : [],
      },
    };
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithToken(token = 'valid-token') {
  return render(
    <MemoryRouter initialEntries={[`/reset-password?token=${token}`]}>
      <ResetPasswordPage />
    </MemoryRouter>,
  );
}

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import ResetPasswordPage from '../../src/pages/ResetPasswordPage';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ResetPasswordPage - Password Strength Meter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('displays a strength indicator when a password is typed', async () => {
    renderWithToken();

    const passwordInput = screen.getByPlaceholderText('At least 12 characters');
    fireEvent.change(passwordInput, { target: { value: 'short' } });

    await waitFor(() => {
      expect(screen.getByTestId('password-strength-meter')).toBeInTheDocument();
    });
  });

  it('shows "Very weak" for a very short password', async () => {
    renderWithToken();

    const passwordInput = screen.getByPlaceholderText('At least 12 characters');
    fireEvent.change(passwordInput, { target: { value: 'abc' } });

    await waitFor(() => {
      expect(screen.getByText('Very weak')).toBeInTheDocument();
    });
  });

  it('updates strength label for a longer password', async () => {
    renderWithToken();

    const passwordInput = screen.getByPlaceholderText('At least 12 characters');

    // First type a weak password
    fireEvent.change(passwordInput, { target: { value: 'abc' } });
    await waitFor(() => {
      expect(screen.getByText('Very weak')).toBeInTheDocument();
    });

    // Now type a strong password (20+ chars → score 4)
    fireEvent.change(passwordInput, {
      target: { value: 'aVeryStrongP@ssw0rd!!' },
    });
    await waitFor(() => {
      expect(screen.getByText('Very strong')).toBeInTheDocument();
    });
  });

  it('shows warning and suggestions for weak passwords', async () => {
    renderWithToken();

    const passwordInput = screen.getByPlaceholderText('At least 12 characters');
    fireEvent.change(passwordInput, { target: { value: 'short' } });

    await waitFor(() => {
      expect(screen.getByText('Too short')).toBeInTheDocument();
      expect(screen.getByText('Add more characters')).toBeInTheDocument();
    });
  });

  it('does not show the strength meter when the password field is empty', async () => {
    renderWithToken();

    // Wait for lazy zxcvbn to load (triggers state update)
    await waitFor(() => {
      expect(screen.queryByTestId('password-strength-meter')).not.toBeInTheDocument();
    });
  });

  it('renders strength bar segments', async () => {
    renderWithToken();

    const passwordInput = screen.getByPlaceholderText('At least 12 characters');
    fireEvent.change(passwordInput, { target: { value: 'test' } });

    await waitFor(() => {
      const meter = screen.getByTestId('password-strength-meter');
      // 5 bar segments
      const bars = meter.querySelectorAll('.rounded-full');
      expect(bars.length).toBe(5);
    });
  });
});

// ---------------------------------------------------------------------------
// zxcvbn strength enforcement (matches SettingsPage and RegisterPage).
// The mock zxcvbn above returns score 2 for 12-15 chars and score 3 for 16-19.
// Submission must be blocked when score < 3 even though the schema only
// requires min(12) length.
// ---------------------------------------------------------------------------

describe('ResetPasswordPage - zxcvbn strength enforcement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects submission when zxcvbn score is below 3 (weak password)', async () => {
    renderWithToken();

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    // 12 chars => mock score 2 ("Fair") — passes schema but blocked by gate
    fireEvent.change(screen.getByPlaceholderText('At least 12 characters'), {
      target: { value: 'password1234' },
    });
    fireEvent.change(screen.getByPlaceholderText('Re-enter your new password'), {
      target: { value: 'password1234' },
    });

    fireEvent.click(screen.getByRole('button', { name: /reset password/i }));

    await waitFor(() => {
      expect(
        screen.getByText('New password is too weak. Please choose a stronger password.'),
      ).toBeInTheDocument();
    });

    expect(resetPasswordApi).not.toHaveBeenCalled();
  });

  it('accepts submission when zxcvbn score is >= 3 (strong password)', async () => {
    vi.mocked(resetPasswordApi).mockResolvedValue(undefined);

    renderWithToken();

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'user@example.com' },
    });
    // 16 chars => mock score 3 ("Strong")
    fireEvent.change(screen.getByPlaceholderText('At least 12 characters'), {
      target: { value: 'superStrongPass1' },
    });
    fireEvent.change(screen.getByPlaceholderText('Re-enter your new password'), {
      target: { value: 'superStrongPass1' },
    });

    fireEvent.click(screen.getByRole('button', { name: /reset password/i }));

    await waitFor(() => {
      expect(resetPasswordApi).toHaveBeenCalled();
    });
  });
});
