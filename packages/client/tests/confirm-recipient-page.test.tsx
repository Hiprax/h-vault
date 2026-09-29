/**
 * `/backup/confirm-recipient` (F-05): the page a backup recipient opens from its
 * confirmation email.
 *
 * Pinned: the token is taken from the URL FRAGMENT and nowhere else (a fragment
 * never reaches a server, so it lands in no access log); the fragment is removed
 * from the address bar straight away; the token is sent exactly once, with no
 * session; a link without a fragment token shows the error state and sends
 * nothing; a refusal shows the server's sentence.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { renderToString } from 'react-dom/server';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { AxiosError, AxiosHeaders } from 'axios';

const { mockConfirm } = vi.hoisted(() => ({ mockConfirm: vi.fn() }));

vi.mock('../src/services/api/backupApi', () => ({
  confirmBackupRecipientApi: mockConfirm,
}));

import ConfirmRecipientPage from '../src/pages/ConfirmRecipientPage';

/** Shows where the router is, so a test can see the fragment leave. */
function LocationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <output data-testid="location">{`${location.pathname}${location.search}${location.hash}`}</output>
      {/* A second confirmation link pasted into the same tab: a hash-only navigation. */}
      <button
        type="button"
        onClick={() => void navigate('/backup/confirm-recipient#token=second.link.token')}
      >
        open a second link
      </button>
      <button type="button" onClick={() => void navigate('/backup/confirm-recipient#token=')}>
        open a broken link
      </button>
    </>
  );
}

function renderAt(entry: string) {
  return render(
    <StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route
            path="/backup/confirm-recipient"
            element={
              <>
                <ConfirmRecipientPage />
                <LocationProbe />
              </>
            }
          />
        </Routes>
      </MemoryRouter>
    </StrictMode>,
  );
}

function refusal(status: number, message: string): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError(message, String(status), undefined, undefined, {
    status,
    statusText: 'Bad Request',
    headers,
    config: { headers },
    data: { success: false, message, statusCode: status, statusText: 'Bad Request' },
  });
}

beforeEach(() => {
  mockConfirm.mockReset();
});

describe('ConfirmRecipientPage', () => {
  it('completes from a fragment token: sends it once, removes it from the address bar, shows success', async () => {
    mockConfirm.mockResolvedValue({
      data: { success: true, message: 'This address will now receive the encrypted backups.' },
    });

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' }),
    ).toBeInTheDocument();
    expect(
      screen.getByText('This address will now receive the encrypted backups.'),
    ).toBeInTheDocument();
    // Once, even under StrictMode's double effects, and with exactly the token.
    expect(mockConfirm).toHaveBeenCalledTimes(1);
    expect(mockConfirm).toHaveBeenCalledWith({ token: 'aaa.bbb.ccc' });
    // The fragment is gone; the page itself stayed.
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/backup\/confirm-recipient$/);
    expect(screen.getByRole('link', { name: 'Go to H-Vault' })).toHaveAttribute('href', '/login');
  });

  it('shows the confirming state while the request is in flight', async () => {
    mockConfirm.mockReturnValue(new Promise(() => {}));

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Confirming Address' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Confirmation Failed' })).not.toBeInTheDocument();
    // The way out is offered once there is an outcome, not while it is pending.
    expect(screen.queryByRole('link', { name: 'Go to H-Vault' })).not.toBeInTheDocument();
  });

  it('survives a network failure with no response, and says so', async () => {
    mockConfirm.mockRejectedValue(new AxiosError('Network Error', 'ERR_NETWORK'));

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' });
    expect(screen.queryByText(/may have expired, been used already/)).not.toBeInTheDocument();
  });

  it('never shows a message a reply marked unsuccessful carries', async () => {
    mockConfirm.mockResolvedValue({ data: { success: false, message: 'not for display' } });

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' });
    expect(screen.queryByText('not for display')).not.toBeInTheDocument();
  });

  it('decodes a percent-encoded token', async () => {
    mockConfirm.mockResolvedValue({ data: { success: true, message: 'ok' } });

    renderAt('/backup/confirm-recipient#token=a%2Eb%2Ec');

    await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' });
    expect(mockConfirm).toHaveBeenCalledWith({ token: 'a.b.c' });
  });

  it('shows the error state and sends NOTHING when the link carries no fragment token', async () => {
    renderAt('/backup/confirm-recipient');

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/link is incomplete/i)).toBeInTheDocument();
    expect(mockConfirm).not.toHaveBeenCalled();
  });

  it('never reads a token from the query string', async () => {
    renderAt('/backup/confirm-recipient?token=aaa.bbb.ccc');

    await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' });
    expect(mockConfirm).not.toHaveBeenCalled();
  });

  it('refuses a malformed fragment without sending it', async () => {
    renderAt('/backup/confirm-recipient#token=%E0%A4%A');

    await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' });
    expect(mockConfirm).not.toHaveBeenCalled();
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/backup\/confirm-recipient$/);
  });

  it.each([
    ['an empty fragment token', '/backup/confirm-recipient#token='],
    [
      'a token longer than the server accepts',
      `/backup/confirm-recipient#token=${'a'.repeat(2001)}`,
    ],
  ])('shows the error state and sends nothing for %s', async (_label, entry) => {
    renderAt(entry);

    await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' });
    expect(mockConfirm).not.toHaveBeenCalled();
  });

  it('accepts a token of exactly the maximum length', async () => {
    mockConfirm.mockResolvedValue({ data: { success: true, message: 'ok' } });

    renderAt(`/backup/confirm-recipient#token=${'a'.repeat(2000)}`);

    await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' });
    expect(mockConfirm).toHaveBeenCalledWith({ token: 'a'.repeat(2000) });
  });

  it('falls back to its own sentence when the reply carries none', async () => {
    mockConfirm.mockResolvedValue({ data: { success: false } });

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' });
    expect(
      screen.getByText(
        'This address will now receive the encrypted backups it was asked to receive.',
      ),
    ).toBeInTheDocument();
  });

  it('explains a refused (400) link in its own words, never showing the server code', async () => {
    mockConfirm.mockRejectedValue(refusal(400, 'TOKEN_INVALID'));

    renderAt('/backup/confirm-recipient#token=spent.token.value');

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/may have expired, been used already/)).toBeInTheDocument();
    expect(screen.queryByText('TOKEN_INVALID')).not.toBeInTheDocument();
    expect(mockConfirm).toHaveBeenCalledTimes(1);
  });

  it("shows the server's sentence for any other refusal, such as the rate limit", async () => {
    mockConfirm.mockRejectedValue(
      refusal(429, 'Too many verification attempts, please try again later'),
    );

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');

    await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' });
    expect(
      screen.getByText('Too many verification attempts, please try again later'),
    ).toBeInTheDocument();
  });

  it('confirms a second link opened in the same tab, and ignores the late answer for the first', async () => {
    let failFirst: (reason: unknown) => void = () => undefined;
    mockConfirm
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            failFirst = reject;
          }),
      )
      .mockResolvedValueOnce({ data: { success: true, message: 'Second link confirmed.' } });

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');
    await waitFor(() => expect(mockConfirm).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: 'open a second link' }));

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Address Confirmed' }),
    ).toBeInTheDocument();
    expect(mockConfirm).toHaveBeenLastCalledWith({ token: 'second.link.token' });
    await act(async () => {
      failFirst(refusal(400, 'TOKEN_INVALID'));
      await Promise.resolve();
    });

    expect(
      screen.getByRole('heading', { level: 1, name: 'Address Confirmed' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Second link confirmed.')).toBeInTheDocument();
  });

  it("shows the incomplete-link state for a broken second link, and drops the first link's late answer", async () => {
    let passFirst: (value: unknown) => void = () => undefined;
    mockConfirm.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          passFirst = resolve;
        }),
    );

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');
    await waitFor(() => expect(mockConfirm).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: 'open a broken link' }));

    expect(await screen.findByText(/This confirmation link is incomplete/)).toBeInTheDocument();
    await act(async () => {
      passFirst({ data: { success: true, message: 'Stale confirmation.' } });
      await Promise.resolve();
    });
    expect(screen.queryByText('Stale confirmation.')).not.toBeInTheDocument();
    expect(mockConfirm).toHaveBeenCalledTimes(1);
  });

  it('replaces a finished outcome with the incomplete-link sentence when a broken link follows it', async () => {
    mockConfirm.mockResolvedValueOnce({
      data: { success: true, message: 'First link confirmed.' },
    });

    renderAt('/backup/confirm-recipient#token=aaa.bbb.ccc');
    expect(await screen.findByText('First link confirmed.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'open a broken link' }));

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Confirmation Failed' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/This confirmation link is incomplete/)).toBeInTheDocument();
    expect(screen.queryByText('First link confirmed.')).not.toBeInTheDocument();
    expect(mockConfirm).toHaveBeenCalledTimes(1);
  });

  it.each([
    [
      'a link with a token',
      '/backup/confirm-recipient#token=aaa.bbb.ccc',
      'Confirming Address',
      false,
    ],
    ['a link without one', '/backup/confirm-recipient', 'Confirmation Failed', true],
  ] as const)(
    'paints the right state for %s BEFORE any effect runs, with its heading and no premature way out',
    (_label, entry, heading, footer) => {
      // `renderToString` runs no effects, so this is the first commit a browser
      // paints before the page's effect has done anything.
      const html = renderToString(
        <MemoryRouter initialEntries={[entry]}>
          <Routes>
            <Route path="/backup/confirm-recipient" element={<ConfirmRecipientPage />} />
          </Routes>
        </MemoryRouter>,
      );

      expect(html).toMatch(new RegExp(`<h1[^>]*>${heading}</h1>`));
      expect(html.includes('Go to H-Vault')).toBe(footer);
      expect(html.includes('This confirmation link is incomplete')).toBe(footer);
      expect(mockConfirm).not.toHaveBeenCalled();
    },
  );
});
