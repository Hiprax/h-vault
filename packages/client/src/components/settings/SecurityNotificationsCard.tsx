import { useState } from 'react';
import { MailWarning } from 'lucide-react';
import {
  CRITICAL_SECURITY_NOTIFICATION_EVENTS,
  SECURITY_NOTIFICATION_PREFERENCE_EVENTS,
  type SecurityNotificationPreferenceEvent,
  type SecurityNotificationPreferences,
} from '@hvault/shared';
import { proveMasterPassword } from '../../lib/masterPasswordProof';
import { updateNotificationPreferencesApi, updateSettingsApi } from '../../services/api/userApi';
import { getApiErrorMessage } from '../../lib/utils';
import { useToast } from '../ui/Toast';
import { FormAlert } from '../ui/FormAlert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/Card';
import { Label } from '../ui/Label';
import { Input } from '../ui/Input';
import { Button } from '../ui/Button';

/** What each security email is about, as the list shows it. */
const EVENT_LABELS: Record<SecurityNotificationPreferenceEvent, string> = {
  locked_sign_in_correct_password: 'Your correct master password entered during a lockout',
  password_reset: 'Master password reset',
  password_changed: 'Master password changed',
  two_factor_enabled: 'Two-factor authentication turned on',
  two_factor_disabled: 'Two-factor authentication turned off',
  backup_codes_regenerated: 'New two-factor backup codes',
  trusted_device_granted: 'A browser trusted to skip two-factor sign-in',
  device_proof_revoked: 'A browser no longer recognised after wrong passwords',
  second_factor_lockout: 'Two-factor sign-in locked',
  backup_recipients_changed: 'Backup recipients changed',
  backup_recipients_suspended: 'Backup recipients suspended',
  token_reuse_detected: 'A copied session detected',
  backup_not_sent: 'A backup that could not be sent',
};

const CRITICAL: readonly SecurityNotificationPreferenceEvent[] =
  CRITICAL_SECURITY_NOTIFICATION_EVENTS;

interface SecurityNotificationsCardProps {
  /** This account's address: the salt its master-password proof is derived with. */
  email: string;
  /**
   * The preferences as the profile reported them. Partial or absent only from a
   * server older than this client (a rolling update): every event it does not name
   * is on, which is what such a server does.
   */
  initial: Partial<SecurityNotificationPreferences> | undefined;
}

function withEveryEvent(
  stored: Partial<SecurityNotificationPreferences> | undefined,
): SecurityNotificationPreferences {
  return Object.fromEntries(
    SECURITY_NOTIFICATION_PREFERENCE_EVENTS.map((event) => [event, stored?.[event] !== false]),
  ) as SecurityNotificationPreferences;
}

/**
 * Which security emails the account receives (F-26). Each switch saves at once.
 * Turning one on, or an optional one off, needs nothing more; turning off one that
 * would tell the owner about a stolen password or session needs the master
 * password, proven the way every other sensitive action proves it (derived in the
 * browser, hashed, the derived key zeroed), and the server then emails the owner
 * once to say so. An account deletion, and that email, are always sent.
 */
export function SecurityNotificationsCard({ email, initial }: SecurityNotificationsCardProps) {
  const { toast } = useToast();
  const [preferences, setPreferences] = useState<SecurityNotificationPreferences>(() =>
    withEveryEvent(initial),
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A critical email the owner asked to turn off, waiting for the master password.
  const [pending, setPending] = useState<SecurityNotificationPreferenceEvent | null>(null);
  const [password, setPassword] = useState('');

  const saveWithoutPassword = async (event: SecurityNotificationPreferenceEvent, on: boolean) => {
    setError(null);
    setSaving(true);
    try {
      const res = await updateSettingsApi({ notifications: { [event]: on } });
      // A 2xx reply is always the success envelope, and its `data` is the settings
      // object (see `PUT /user/settings`), every preference filled in.
      const settings = res.data as unknown as {
        data: { notifications?: Partial<SecurityNotificationPreferences> };
      };
      setPreferences(withEveryEvent(settings.data.notifications));
      toast({ title: 'Security emails saved', type: 'success', duration: 2000 });
    } catch (err) {
      setError(getApiErrorMessage(err, 'The change could not be saved.'));
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = (event: SecurityNotificationPreferenceEvent, on: boolean) => {
    if (!on && CRITICAL.includes(event)) {
      setError(null);
      setPassword('');
      setPending(event);
      return;
    }
    void saveWithoutPassword(event, on);
  };

  const confirmTurnOff = async (event: SecurityNotificationPreferenceEvent) => {
    setError(null);
    if (password.length === 0) {
      setError('Enter your master password to turn this email off.');
      return;
    }
    setSaving(true);
    try {
      const authHash = await proveMasterPassword(password, email);
      const res = await updateNotificationPreferencesApi({
        authHash,
        notifications: { [event]: false },
      });
      const stored = res.data as unknown as {
        data: { notifications: SecurityNotificationPreferences };
      };
      setPreferences(withEveryEvent(stored.data.notifications));
      setPending(null);
      toast({ title: 'Security emails saved', type: 'success', duration: 2000 });
    } catch (err) {
      setError(getApiErrorMessage(err, 'The change could not be saved.'));
    } finally {
      // The password never outlives the request, whatever its outcome.
      setPassword('');
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MailWarning className="h-5 w-5" />
          Security emails
        </CardTitle>
        <CardDescription>
          H-Vault emails you when something security-related happens to your account. Emails marked
          as needing your master password can be turned off only with it, and you are told when they
          are. An account deletion is always emailed to your verified address.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && <FormAlert message={error} />}
        <ul className="space-y-2">
          {SECURITY_NOTIFICATION_PREFERENCE_EVENTS.map((event) => {
            const id = `security-email-${event}`;
            const critical = CRITICAL.includes(event);
            return (
              <li key={event} className="flex items-center justify-between gap-4">
                <label htmlFor={id} className="text-sm">
                  {EVENT_LABELS[event]}
                  {critical && (
                    <span className="ml-1 text-xs text-[hsl(var(--muted-foreground))]">
                      (master password needed to turn off)
                    </span>
                  )}
                </label>
                <input
                  id={id}
                  type="checkbox"
                  checked={preferences[event]}
                  disabled={saving || pending !== null}
                  onChange={(e) => handleToggle(event, e.target.checked)}
                  className="h-4 w-4 rounded border-[hsl(var(--input))] accent-[hsl(var(--primary))]"
                />
              </li>
            );
          })}
        </ul>

        {pending !== null && (
          <div className="space-y-2 rounded-md border border-[hsl(var(--border))] p-3">
            <Label htmlFor="security-email-password">
              Your master password, to turn off: {EVENT_LABELS[pending]}
            </Label>
            <Input
              id="security-email-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="flex gap-2">
              <Button type="button" loading={saving} onClick={() => void confirmTurnOff(pending)}>
                Turn off
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={saving}
                onClick={() => {
                  setPending(null);
                  setPassword('');
                  setError(null);
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
