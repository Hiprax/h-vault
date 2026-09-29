/**
 * The Settings card an inviting account mints invitations with.
 *
 * It must prove the master password the way every other sensitive action does
 * (derive, hash, zero the derived key), send exactly the invitee's address and
 * that proof, show the link ONCE with a way to copy it through the clipboard
 * service (the one path a secret may take to the clipboard), and forget the
 * password field afterwards. A refusal shows the server's message and no link.
 */
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

vi.mock('../../src/services/api/authApi', () => ({
  createInvitationApi: vi.fn(),
}));

vi.mock('../../src/services/clipboard/clipboardService', () => ({
  copySecretToClipboard: vi.fn(),
}));

const toast = vi.fn();
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast }),
}));

import { InviteCard } from '../../src/components/settings/InviteCard';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import { createInvitationApi } from '../../src/services/api/authApi';
import { copySecretToClipboard } from '../../src/services/clipboard/clipboardService';

const AUTH_KEY = new ArrayBuffer(32);
const MEK = {} as CryptoKey;
const LINK = 'https://vault.example.org/register#invite=abcDEF_123-xyz';

function refusal(status: number, message: string): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError(message, 'ERR_BAD_REQUEST', { headers }, null, {
    status,
    statusText: 'Refused',
    headers: {},
    config: { headers },
    data: { success: false, message, statusCode: status, statusText: 'Refused' },
  });
}

function fillAndSubmit(invitee = 'friend@example.org', password = 'my master password') {
  fireEvent.change(screen.getByLabelText('Invitee email'), { target: { value: invitee } });
  fireEvent.change(screen.getByLabelText('Your master password'), {
    target: { value: password },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Create invitation' }));
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: MEK,
    authKey: AUTH_KEY,
  } as never);
  vi.mocked(cryptoService.getAuthHash).mockReturnValue('proof-hash');
});

describe('InviteCard', () => {
  it('mints an invitation with the master-password proof, shows the link once and forgets the password', async () => {
    vi.mocked(createInvitationApi).mockResolvedValue({
      data: { success: true, data: { link: LINK, expiresAt: '2026-10-06T08:00:00.000Z' } },
    } as never);

    render(<InviteCard email="inviter@example.org" clipboardClearSeconds={30} />);
    fillAndSubmit();

    expect(await screen.findByDisplayValue(LINK)).toBeInTheDocument();
    // Derived from the INVITER's password and address, then zeroed.
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith(
      'my master password',
      'inviter@example.org',
    );
    expect(cryptoService.clearKey).toHaveBeenCalledWith(AUTH_KEY);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(MEK);
    expect(createInvitationApi).toHaveBeenCalledWith({
      authHash: 'proof-hash',
      email: 'friend@example.org',
    });
    // The password never outlives the request.
    expect(screen.getByLabelText('Your master password')).toHaveValue('');
    expect(screen.getByText(/shown once/i)).toBeInTheDocument();
  });

  it('copies the link through the clipboard service with the account clear delay', async () => {
    vi.mocked(createInvitationApi).mockResolvedValue({
      data: { success: true, data: { link: LINK, expiresAt: '2026-10-06T08:00:00.000Z' } },
    } as never);
    vi.mocked(copySecretToClipboard).mockResolvedValue();

    render(<InviteCard email="inviter@example.org" clipboardClearSeconds={45} />);
    fillAndSubmit();
    await screen.findByDisplayValue(LINK);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy invitation link' }));
      await Promise.resolve();
    });
    expect(copySecretToClipboard).toHaveBeenCalledWith(LINK, 45_000);
    await waitFor(() => {
      expect(toast).toHaveBeenCalledWith({
        title: 'Invitation link copied',
        type: 'success',
        duration: 2000,
      });
    });
  });

  it('says so when the clipboard refuses the copy', async () => {
    vi.mocked(createInvitationApi).mockResolvedValue({
      data: { success: true, data: { link: LINK, expiresAt: '2026-10-06T08:00:00.000Z' } },
    } as never);
    vi.mocked(copySecretToClipboard).mockRejectedValue(new Error('denied'));

    render(<InviteCard email="inviter@example.org" clipboardClearSeconds={30} />);
    fillAndSubmit();
    await screen.findByDisplayValue(LINK);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy invitation link' }));
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(toast).toHaveBeenCalledWith({
        title: 'Failed to copy the invitation link',
        type: 'error',
      });
    });
    expect(toast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Invitation link copied' }),
    );
  });

  it('shows the server refusal and no link when the mint is refused', async () => {
    vi.mocked(createInvitationApi).mockRejectedValue(
      refusal(403, 'This account is not allowed to create invitations.'),
    );

    render(<InviteCard email="inviter@example.org" clipboardClearSeconds={30} />);
    fillAndSubmit();

    expect(
      await screen.findByText('This account is not allowed to create invitations.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Copy invitation link' })).toBeNull();
    expect(cryptoService.clearKey).toHaveBeenCalledWith(AUTH_KEY);
  });

  it('asks for both fields before deriving anything', async () => {
    render(<InviteCard email="inviter@example.org" clipboardClearSeconds={30} />);
    fireEvent.click(screen.getByRole('button', { name: 'Create invitation' }));

    await waitFor(() => {
      expect(
        screen.getByText('Enter the address to invite and your master password.'),
      ).toBeInTheDocument();
    });
    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
    expect(createInvitationApi).not.toHaveBeenCalled();
  });
});
