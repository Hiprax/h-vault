/**
 * The Settings card that chooses which security emails the account receives
 * (F-26).
 *
 * An optional email, or turning any email back ON, is saved through
 * `PUT /user/settings` with exactly that one change and no password. Turning OFF
 * one of the critical emails never goes there: it asks for the master password,
 * proves it the way every other sensitive action does (derive, hash, zero the
 * derived key) and sends only that proof and that one change to
 * `PUT /user/notifications`, then forgets the password. A refusal shows the
 * server's message and leaves the switch as it was.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import {
  CRITICAL_SECURITY_NOTIFICATION_EVENTS,
  SECURITY_NOTIFICATION_PREFERENCE_EVENTS,
  type SecurityNotificationPreferences,
} from '@hvault/shared';

vi.mock('../../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn(),
  },
}));

vi.mock('../../src/services/api/userApi', () => ({
  updateSettingsApi: vi.fn(),
  updateNotificationPreferencesApi: vi.fn(),
}));

const toast = vi.fn();
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast }),
}));

import { SecurityNotificationsCard } from '../../src/components/settings/SecurityNotificationsCard';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import {
  updateNotificationPreferencesApi,
  updateSettingsApi,
} from '../../src/services/api/userApi';

const AUTH_KEY = new ArrayBuffer(32);
const MEK = {} as CryptoKey;
const EMAIL = 'owner@example.org';

const allOn = (): SecurityNotificationPreferences =>
  Object.fromEntries(
    SECURITY_NOTIFICATION_PREFERENCE_EVENTS.map((event) => [event, true]),
  ) as SecurityNotificationPreferences;

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

const switchFor = (label: RegExp) => screen.getByRole('checkbox', { name: label });

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: MEK,
    authKey: AUTH_KEY,
  } as never);
  vi.mocked(cryptoService.getAuthHash).mockReturnValue('proof-hash');
});

describe('SecurityNotificationsCard', () => {
  it('lists one switch per email the owner may choose, marks the critical ones, and treats a missing preference as on', () => {
    render(<SecurityNotificationsCard email={EMAIL} initial={{ trusted_device_granted: false }} />);

    const boxes = screen.getAllByRole('checkbox');
    expect(boxes).toHaveLength(SECURITY_NOTIFICATION_PREFERENCE_EVENTS.length);
    expect(switchFor(/A browser trusted to skip two-factor sign-in/)).not.toBeChecked();
    expect(switchFor(/^Master password changed/)).toBeChecked();
    expect(screen.getAllByText('(master password needed to turn off)')).toHaveLength(
      CRITICAL_SECURITY_NOTIFICATION_EVENTS.length,
    );
    // An account deletion is not a choice.
    expect(screen.queryByRole('checkbox', { name: /delet/i })).toBeNull();
  });

  it('a profile with no preferences at all (an older server) shows every email on', () => {
    render(<SecurityNotificationsCard email={EMAIL} initial={undefined} />);
    for (const box of screen.getAllByRole('checkbox')) expect(box).toBeChecked();
  });

  it('saves an optional email off through the settings route, with that one change and no password', async () => {
    vi.mocked(updateSettingsApi).mockResolvedValue({
      data: { success: true, data: { notifications: { ...allOn(), backup_not_sent: false } } },
    } as never);
    render(<SecurityNotificationsCard email={EMAIL} initial={allOn()} />);

    fireEvent.click(switchFor(/A backup that could not be sent/));

    await waitFor(() => expect(switchFor(/A backup that could not be sent/)).not.toBeChecked());
    expect(updateSettingsApi).toHaveBeenCalledWith({ notifications: { backup_not_sent: false } });
    expect(updateNotificationPreferencesApi).not.toHaveBeenCalled();
    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
    expect(screen.queryByLabelText(/Your master password/)).toBeNull();
  });

  it('turns a critical email back on without a password', async () => {
    vi.mocked(updateSettingsApi).mockResolvedValue({
      data: { success: true, data: { notifications: allOn() } },
    } as never);
    render(
      <SecurityNotificationsCard email={EMAIL} initial={{ ...allOn(), password_changed: false }} />,
    );

    fireEvent.click(switchFor(/^Master password changed/));

    await waitFor(() => expect(switchFor(/^Master password changed/)).toBeChecked());
    expect(updateSettingsApi).toHaveBeenCalledWith({ notifications: { password_changed: true } });
    expect(updateNotificationPreferencesApi).not.toHaveBeenCalled();
  });

  it('turning a critical email off asks for the master password, sends only the proof and that change, and forgets the password', async () => {
    vi.mocked(updateNotificationPreferencesApi).mockResolvedValue({
      data: { success: true, data: { notifications: { ...allOn(), token_reuse_detected: false } } },
    } as never);
    render(<SecurityNotificationsCard email={EMAIL} initial={allOn()} />);

    fireEvent.click(switchFor(/A copied session detected/));
    // Nothing is sent and the switch has not moved until the password is given.
    expect(updateSettingsApi).not.toHaveBeenCalled();
    expect(switchFor(/A copied session detected/)).toBeChecked();
    const field = screen.getByLabelText(/Your master password, to turn off: A copied session/);

    fireEvent.click(screen.getByRole('button', { name: 'Turn off' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Enter your master password to turn this email off.',
    );
    expect(updateNotificationPreferencesApi).not.toHaveBeenCalled();

    fireEvent.change(field, { target: { value: 'my master password' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn off' }));

    await waitFor(() => expect(switchFor(/A copied session detected/)).not.toBeChecked());
    expect(cryptoService.deriveKeys).toHaveBeenCalledWith('my master password', EMAIL);
    expect(cryptoService.clearKey).toHaveBeenCalledWith(AUTH_KEY);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(MEK);
    expect(updateNotificationPreferencesApi).toHaveBeenCalledWith({
      authHash: 'proof-hash',
      notifications: { token_reuse_detected: false },
    });
    expect(updateSettingsApi).not.toHaveBeenCalled();
    expect(screen.queryByLabelText(/Your master password/)).toBeNull();
  });

  it('shows the refusal of a wrong password, keeps the email on and clears the field', async () => {
    vi.mocked(updateNotificationPreferencesApi).mockRejectedValue(
      refusal(401, 'Current password is incorrect'),
    );
    render(<SecurityNotificationsCard email={EMAIL} initial={allOn()} />);

    fireEvent.click(switchFor(/^Master password reset/));
    const field = screen.getByLabelText(/Your master password, to turn off/);
    fireEvent.change(field, { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Turn off' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect');
    expect(switchFor(/^Master password reset/)).toBeChecked();
    expect(screen.getByLabelText(/Your master password, to turn off/)).toHaveValue('');
  });

  it('cancelling the password prompt sends nothing and leaves the email on', () => {
    render(<SecurityNotificationsCard email={EMAIL} initial={allOn()} />);

    fireEvent.click(switchFor(/Two-factor sign-in locked/));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByLabelText(/Your master password/)).toBeNull();
    expect(switchFor(/Two-factor sign-in locked/)).toBeChecked();
    expect(updateNotificationPreferencesApi).not.toHaveBeenCalled();
    expect(updateSettingsApi).not.toHaveBeenCalled();
  });

  it('shows the refusal of a settings save and keeps the switch where it was', async () => {
    vi.mocked(updateSettingsApi).mockRejectedValue(refusal(400, 'Something was refused'));
    render(<SecurityNotificationsCard email={EMAIL} initial={allOn()} />);

    fireEvent.click(switchFor(/New two-factor backup codes/));

    expect(await screen.findByRole('alert')).toHaveTextContent('Something was refused');
    expect(switchFor(/New two-factor backup codes/)).toBeChecked();
  });
});
