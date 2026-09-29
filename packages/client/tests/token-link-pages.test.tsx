/**
 * The three pages an emailed one-time link opens (F-27): `/verify-email`,
 * `/reset-password` and `/unlock-account`.
 *
 * The link carries its token in the URL FRAGMENT (`#token=…`), which a browser
 * never sends to a server, so the token reaches no access log and no `Referer`.
 * Pinned for each page: the fragment token is read and used exactly as a query
 * token was; the token is then removed from the address bar (and so from the
 * history entry and any bookmark); a link from the previous release, with the token
 * in the query, still works for this transition release and is stripped too; a
 * link with neither shows the page's existing error state and sends nothing.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode, type ReactElement } from 'react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router';

const { mockVerifyEmail, mockUnlock, mockReset } = vi.hoisted(() => ({
  mockVerifyEmail: vi.fn(),
  mockUnlock: vi.fn(),
  mockReset: vi.fn(),
}));

vi.mock('../src/services/api/authApi', () => ({
  verifyEmailApi: mockVerifyEmail,
  unlockAccountApi: mockUnlock,
  resetPasswordApi: mockReset,
}));

// The reset page derives keys before it POSTs; the derivation is not what these
// cases are about, so it is replaced by fixed outputs.
vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn().mockResolvedValue({
      masterEncryptionKey: {} as CryptoKey,
      authKey: new ArrayBuffer(32),
    }),
    getAuthHash: vi.fn().mockReturnValue('derived-auth-hash'),
    generateVaultKey: vi.fn().mockReturnValue(new ArrayBuffer(32)),
    importVaultKey: vi.fn().mockResolvedValue({} as CryptoKey),
    encryptVaultKey: vi.fn().mockResolvedValue({ encrypted: 'wrapped', iv: 'iv', tag: 'tag' }),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: () =>
    Promise.resolve(() => ({ score: 4, feedback: { warning: '', suggestions: [] } })),
}));

import VerifyEmailPage from '../src/pages/VerifyEmailPage';
import UnlockAccountPage from '../src/pages/UnlockAccountPage';
import ResetPasswordPage from '../src/pages/ResetPasswordPage';

/** A JWT-shaped token, the kind the server mails. */
const TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJwdXJwb3NlIjoieCJ9.c2lnbmF0dXJl';

/** Shows where the router is, so a test can see the token leave the URL. */
function LocationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="location">{`${location.pathname}${location.search}${location.hash}`}</output>
      {/* Stands in for pasting a SECOND emailed link into the same tab: the path is
          unchanged, so the browser performs a hash-only navigation, not a reload. */}
      <button
        type="button"
        onClick={() => void navigate(`${location.pathname}#token=second.link.token`)}
      >
        open a second link
      </button>
    </>
  );
}

function renderAt(path: string, entry: string, page: ReactElement) {
  return render(
    <StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route
            path={path}
            element={
              <>
                {page}
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </StrictMode>,
  );
}

function location(): string {
  return screen.getByTestId('location').textContent ?? '';
}

beforeEach(() => {
  mockVerifyEmail.mockReset().mockResolvedValue({ data: { success: true, message: 'Verified.' } });
  mockUnlock.mockReset().mockResolvedValue({ data: { success: true, message: 'Unlocked.' } });
  mockReset.mockReset().mockResolvedValue({ data: { success: true } });
});

describe.each([
  {
    name: 'VerifyEmailPage',
    path: '/verify-email',
    page: () => <VerifyEmailPage />,
    api: () => mockVerifyEmail,
    success: 'Email Verified',
    missing: /No verification token found/,
  },
  {
    name: 'UnlockAccountPage',
    path: '/unlock-account',
    page: () => <UnlockAccountPage />,
    api: () => mockUnlock,
    success: 'Account Unlocked',
    missing: /No unlock token found/,
  },
])('$name', ({ path, page, api, success, missing }) => {
  it('uses a fragment token once, then removes it from the address bar', async () => {
    renderAt(path, `${path}#token=${TOKEN}`, page());

    expect(await screen.findByRole('heading', { level: 1, name: success })).toBeInTheDocument();
    expect(api()).toHaveBeenCalledTimes(1);
    expect(api()).toHaveBeenCalledWith({ token: TOKEN });
    expect(location()).toBe(path);
  });

  it('still accepts a query token from a link mailed before this release, and strips it', async () => {
    renderAt(path, `${path}?token=${TOKEN}&from=mail`, page());

    expect(await screen.findByRole('heading', { level: 1, name: success })).toBeInTheDocument();
    expect(api()).toHaveBeenCalledWith({ token: TOKEN });
    // The token leaves the URL; an unrelated parameter stays.
    expect(location()).toBe(`${path}?from=mail`);
  });

  it('prefers the fragment when a link somehow carries both, and removes both', async () => {
    renderAt(path, `${path}?token=stale.query.token#token=${TOKEN}`, page());

    await screen.findByRole('heading', { level: 1, name: success });
    expect(api()).toHaveBeenCalledTimes(1);
    expect(api()).toHaveBeenCalledWith({ token: TOKEN });
    expect(location()).toBe(path);
  });

  it('uses a second link opened in the same tab, which arrives as a hash-only navigation', async () => {
    renderAt(path, `${path}#token=${TOKEN}`, page());
    await screen.findByRole('heading', { level: 1, name: success });
    await waitFor(() => expect(location()).toBe(path));

    fireEvent.click(screen.getByRole('button', { name: 'open a second link' }));

    await waitFor(() => expect(api()).toHaveBeenCalledTimes(2));
    expect(api()).toHaveBeenLastCalledWith({ token: 'second.link.token' });
    await waitFor(() => expect(location()).toBe(path));
  });

  it('ignores a late answer for a token a second link has superseded', async () => {
    let failFirst: (reason: unknown) => void = () => undefined;
    api()
      .mockReset()
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            failFirst = reject;
          }),
      )
      .mockResolvedValueOnce({ data: { success: true, message: 'Second link worked.' } });
    renderAt(path, `${path}#token=${TOKEN}`, page());
    await waitFor(() => expect(api()).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: 'open a second link' }));
    expect(await screen.findByRole('heading', { level: 1, name: success })).toBeInTheDocument();
    await act(async () => {
      failFirst(new Error('the first token had expired'));
      await Promise.resolve();
    });

    // The superseded request's failure must not replace the newer success.
    expect(screen.getByRole('heading', { level: 1, name: success })).toBeInTheDocument();
    expect(screen.getByText('Second link worked.')).toBeInTheDocument();
  });

  it('ignores a late SUCCESS for a superseded token too, keeping the newer refusal', async () => {
    let passFirst: (value: unknown) => void = () => undefined;
    api()
      .mockReset()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            passFirst = resolve;
          }),
      )
      .mockRejectedValueOnce(new Error('the second link had expired'));
    renderAt(path, `${path}#token=${TOKEN}`, page());
    await waitFor(() => expect(api()).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: 'open a second link' }));
    await waitFor(() => expect(api()).toHaveBeenCalledTimes(2));
    const failure = await screen.findByRole('heading', { level: 1, name: /failed/i });
    await act(async () => {
      passFirst({ data: { success: true, message: 'Stale success.' } });
      await Promise.resolve();
    });

    expect(failure).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 1, name: success })).not.toBeInTheDocument();
    expect(screen.queryByText('Stale success.')).not.toBeInTheDocument();
  });

  it.each([
    ['no token at all', ''],
    ['an empty fragment token', '#token='],
    ['an undecodable fragment token', '#token=%E0%A4%A'],
    ['an over-long fragment token', `#token=${'a'.repeat(2001)}`],
    ['a fragment that is not a token', '#section-2'],
  ])('shows the error state and sends nothing for %s', async (_label, suffix) => {
    renderAt(path, `${path}${suffix}`, page());

    expect(await screen.findByText(missing)).toBeInTheDocument();
    expect(api()).not.toHaveBeenCalled();
  });
});

describe('ResetPasswordPage', () => {
  async function submitNewPassword(): Promise<void> {
    await act(async () => {
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'owner@example.com' } });
      fireEvent.change(screen.getByLabelText('New Master Password'), {
        target: { value: 'correct horse battery staple' },
      });
      fireEvent.change(screen.getByLabelText('Confirm New Password'), {
        target: { value: 'correct horse battery staple' },
      });
      fireEvent.click(screen.getByRole('button', { name: /reset password/i }));
    });
  }

  it('completes from a fragment token, which is gone from the address bar before anything is typed', async () => {
    renderAt('/reset-password', `/reset-password#token=${TOKEN}`, <ResetPasswordPage />);

    expect(await screen.findByLabelText('New Master Password')).toBeInTheDocument();
    await waitFor(() => expect(location()).toBe('/reset-password'));

    await submitNewPassword();

    await waitFor(() => expect(mockReset).toHaveBeenCalledTimes(1));
    expect(mockReset).toHaveBeenCalledWith(
      expect.objectContaining({ token: TOKEN, email: 'owner@example.com' }),
    );
  });

  it('still completes from a query token during the transition, and strips it', async () => {
    renderAt('/reset-password', `/reset-password?token=${TOKEN}`, <ResetPasswordPage />);

    expect(await screen.findByLabelText('New Master Password')).toBeInTheDocument();
    await waitFor(() => expect(location()).toBe('/reset-password'));

    await submitNewPassword();

    await waitFor(() =>
      expect(mockReset).toHaveBeenCalledWith(expect.objectContaining({ token: TOKEN })),
    );
  });

  it('shows the invalid-link state for a link with no token, and offers a new one', async () => {
    renderAt('/reset-password', '/reset-password', <ResetPasswordPage />);

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Invalid Link' }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText('New Master Password')).not.toBeInTheDocument();
    expect(mockReset).not.toHaveBeenCalled();
  });
});
