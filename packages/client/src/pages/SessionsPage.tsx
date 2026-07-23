import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Monitor,
  Smartphone,
  ArrowLeft,
  Trash2,
  Globe,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Info,
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useToast } from '../components/ui/Toast';
import {
  listSessionsApi,
  revokeSessionApi,
  listTrustedDevicesApi,
  revokeTrustedDeviceApi,
  revokeAllTrustedDevicesApi,
} from '../services/api/userApi';
import { logoutAllApi } from '../services/api/authApi';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../components/ui/Dialog';
import type { ISessionInfo, ITrustedDeviceInfo } from '@hvault/shared';

// ---------------------------------------------------------------------------
// User agent parser
// ---------------------------------------------------------------------------

function parseUserAgent(ua: string): { browser: string; os: string; icon: typeof Monitor } {
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';

  if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari')) browser = 'Safari';
  else if (ua.includes('Opera') || ua.includes('OPR')) browser = 'Opera';

  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  const isMobile = ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone');
  const icon = isMobile ? Smartphone : Monitor;

  return { browser, os, icon };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function SessionsPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [sessions, setSessions] = useState<ISessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [revokingAll, setRevokingAll] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<string | null>(null);

  // Trusted devices (allowed to skip the 2FA step at login).
  const [trustedDevices, setTrustedDevices] = useState<ITrustedDeviceInfo[]>([]);
  const [trustedLoading, setTrustedLoading] = useState(true);
  const [trustedError, setTrustedError] = useState(false);
  const [revokingTrustedId, setRevokingTrustedId] = useState<string | null>(null);
  const [revokingAllTrusted, setRevokingAllTrusted] = useState(false);
  const [showRevokeAllTrustedDialog, setShowRevokeAllTrustedDialog] = useState(false);

  const loadSessions = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await listSessionsApi();
      const sessionsResult = res.data;
      if (!sessionsResult.success) throw new Error('Failed to load sessions');
      setSessions(sessionsResult.data);
    } catch {
      setError(true);
      toast({ title: 'Failed to load sessions', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const loadTrustedDevices = useCallback(async () => {
    setTrustedLoading(true);
    setTrustedError(false);
    try {
      const res = await listTrustedDevicesApi();
      const result = res.data;
      if (!result.success) throw new Error('Failed to load trusted devices');
      setTrustedDevices(result.data);
    } catch {
      setTrustedError(true);
    } finally {
      setTrustedLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSessions();
    void loadTrustedDevices();
  }, [loadSessions, loadTrustedDevices]);

  const handleRevoke = useCallback(
    async (sessionId: string) => {
      setRevokingSessionId(sessionId);
      try {
        await revokeSessionApi(sessionId);
        setSessions((prev) => prev.filter((s) => s._id !== sessionId));
        toast({ title: 'Session revoked', type: 'success' });
      } catch {
        toast({ title: 'Failed to revoke session', type: 'error' });
      } finally {
        setRevokingSessionId(null);
      }
    },
    [toast],
  );

  const handleRevokeAll = useCallback(async () => {
    setRevokingAll(true);
    try {
      await logoutAllApi();
      toast({ title: 'All other sessions revoked', type: 'success' });
      // Re-fetch sessions to get the updated list with only current session
      await loadSessions();
    } catch {
      toast({ title: 'Failed to revoke sessions', type: 'error' });
    } finally {
      setRevokingAll(false);
    }
  }, [toast, loadSessions]);

  const handleRevokeTrusted = useCallback(
    async (deviceId: string) => {
      setRevokingTrustedId(deviceId);
      try {
        await revokeTrustedDeviceApi(deviceId);
        setTrustedDevices((prev) => prev.filter((d) => d._id !== deviceId));
        toast({ title: 'Trusted device revoked', type: 'success' });
      } catch {
        toast({ title: 'Failed to revoke trusted device', type: 'error' });
      } finally {
        setRevokingTrustedId(null);
      }
    },
    [toast],
  );

  const handleRevokeAllTrusted = useCallback(async () => {
    setRevokingAllTrusted(true);
    try {
      await revokeAllTrustedDevicesApi();
      setTrustedDevices([]);
      setShowRevokeAllTrustedDialog(false);
      toast({ title: 'All trusted devices revoked', type: 'success' });
    } catch {
      toast({ title: 'Failed to revoke trusted devices', type: 'error' });
    } finally {
      setRevokingAllTrusted(false);
    }
  }, [toast]);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={() => void navigate('/settings')}
          className="rounded-md p-2 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label="Back to settings"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">Active Sessions</h1>
      </div>

      {/* Revoke all button */}
      {sessions.length > 1 && (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={() => void handleRevokeAll()}
            disabled={revokingAll}
            className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
          >
            <ShieldAlert className="h-4 w-4" />
            {revokingAll ? 'Revoking...' : 'Revoke All Other Sessions'}
          </button>
        </div>
      )}

      {/* Revocation latency notice */}
      <div className="flex items-start gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.3)] px-4 py-3 text-xs text-[hsl(var(--muted-foreground))]">
        <Info className="mt-0.5 h-4 w-4 shrink-0" />
        <p>Note: Active sessions may take up to 5 minutes to fully terminate after revocation.</p>
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--primary))]" />
        </div>
      )}

      {/* Error with retry */}
      {!loading && error && (
        <div className="flex flex-col items-center justify-center rounded-lg border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-12 text-center">
          <p className="text-sm font-medium text-[hsl(var(--destructive))]">
            Failed to load sessions
          </p>
          <button
            type="button"
            onClick={() => void loadSessions()}
            className="mt-3 inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Retry
          </button>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && sessions.length === 0 && (
        <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-12 text-center">
          <p className="text-[hsl(var(--muted-foreground))]">No active sessions found.</p>
        </div>
      )}

      {/* Sessions list */}
      {!loading && sessions.length > 0 && (
        <div className="space-y-3">
          {sessions.map((session) => {
            const { browser, os, icon: DeviceIcon } = parseUserAgent(session.deviceInfo.userAgent);
            return (
              <div
                key={session._id}
                className={cn(
                  'flex items-center justify-between rounded-lg border p-4',
                  session.current
                    ? 'border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.05)]'
                    : 'border-[hsl(var(--border))] bg-[hsl(var(--card))]',
                )}
              >
                <div className="flex items-center gap-4">
                  <DeviceIcon className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                        {browser} on {os}
                      </p>
                      {session.current && (
                        <span className="rounded-full bg-[hsl(var(--primary))] px-2 py-0.5 text-xs font-medium text-[hsl(var(--primary-foreground))]">
                          Current
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-3 text-xs text-[hsl(var(--muted-foreground))]">
                      <span className="flex items-center gap-1">
                        <Globe className="h-3 w-3" /> {session.deviceInfo.ip}
                      </span>
                      <span>Since {new Date(session.createdAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>
                {!session.current && (
                  <button
                    type="button"
                    onClick={() => void handleRevoke(session._id)}
                    disabled={revokingSessionId !== null}
                    className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
                  >
                    {revokingSessionId === session._id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                    {revokingSessionId === session._id ? 'Revoking...' : 'Revoke'}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* --------------------------------------------------------------- */}
      {/* Trusted devices                                                 */}
      {/* --------------------------------------------------------------- */}
      <section className="space-y-4 pt-4" aria-labelledby="trusted-devices-heading">
        <div className="flex items-center justify-between gap-4">
          <h2
            id="trusted-devices-heading"
            className="flex items-center gap-2 text-xl font-bold text-[hsl(var(--foreground))]"
          >
            <ShieldCheck className="h-5 w-5 text-[hsl(var(--primary))]" />
            Trusted Devices
          </h2>
          {trustedDevices.length > 0 && (
            <button
              type="button"
              onClick={() => setShowRevokeAllTrustedDialog(true)}
              disabled={revokingAllTrusted}
              className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
            >
              <ShieldAlert className="h-4 w-4" />
              Revoke All Trusted Devices
            </button>
          )}
        </div>

        {/* Explanatory copy */}
        <div className="flex items-start gap-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.3)] px-4 py-3 text-xs text-[hsl(var(--muted-foreground))]">
          <Info className="mt-0.5 h-4 w-4 shrink-0" />
          <p>
            Trusted devices can skip the two-factor authentication step when you sign in. Revoking a
            device forces it to complete two-factor authentication again on its next sign-in. Your
            master password is always required either way.
          </p>
        </div>

        {/* Loading */}
        {trustedLoading && (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--primary))]" />
          </div>
        )}

        {/* Error with retry */}
        {!trustedLoading && trustedError && (
          <div className="flex flex-col items-center justify-center rounded-lg border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-8 text-center">
            <p className="text-sm font-medium text-[hsl(var(--destructive))]">
              Failed to load trusted devices
            </p>
            <button
              type="button"
              onClick={() => void loadTrustedDevices()}
              className="mt-3 inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
              Retry
            </button>
          </div>
        )}

        {/* Empty */}
        {!trustedLoading && !trustedError && trustedDevices.length === 0 && (
          <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-8 text-center">
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              No trusted devices. When you check &ldquo;Remember me on this device&rdquo; at login
              and complete two-factor authentication, that device appears here.
            </p>
          </div>
        )}

        {/* Trusted-device list */}
        {!trustedLoading && !trustedError && trustedDevices.length > 0 && (
          <div className="space-y-3">
            {trustedDevices.map((device) => {
              const { browser, os, icon: DeviceIcon } = parseUserAgent(device.deviceInfo.userAgent);
              return (
                <div
                  key={device._id}
                  className="flex items-center justify-between rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4"
                >
                  <div className="flex items-center gap-4">
                    <DeviceIcon className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
                    <div>
                      <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                        {browser} on {os}
                      </p>
                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[hsl(var(--muted-foreground))]">
                        <span className="flex items-center gap-1">
                          <Globe className="h-3 w-3" /> {device.deviceInfo.ip}
                        </span>
                        <span>Trusted {new Date(device.createdAt).toLocaleDateString()}</span>
                        {device.lastUsedAt && (
                          <span>Last used {new Date(device.lastUsedAt).toLocaleDateString()}</span>
                        )}
                        <span>Expires {new Date(device.expiresAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleRevokeTrusted(device._id)}
                    disabled={revokingTrustedId !== null}
                    className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
                  >
                    {revokingTrustedId === device._id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                    {revokingTrustedId === device._id ? 'Revoking...' : 'Revoke'}
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Revoke-all-trusted-devices confirmation */}
      <Dialog
        open={showRevokeAllTrustedDialog}
        onOpenChange={(open) => {
          if (!open && !revokingAllTrusted) setShowRevokeAllTrustedDialog(false);
        }}
      >
        <DialogContent
          className="max-w-md"
          onClose={() => {
            if (!revokingAllTrusted) setShowRevokeAllTrustedDialog(false);
          }}
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-[hsl(var(--destructive))]">
              <ShieldAlert className="h-5 w-5 shrink-0" /> Revoke all trusted devices?
            </DialogTitle>
            <DialogDescription>
              Every trusted device will need to complete two-factor authentication again on its next
              sign-in. This does not sign out any active sessions, and your master password is still
              required to unlock the vault.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button
              type="button"
              onClick={() => setShowRevokeAllTrustedDialog(false)}
              disabled={revokingAllTrusted}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void handleRevokeAllTrusted()}
              disabled={revokingAllTrusted}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:bg-[hsl(var(--destructive)/0.9)] disabled:opacity-50"
            >
              {revokingAllTrusted ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldAlert className="h-4 w-4" />
              )}
              {revokingAllTrusted ? 'Revoking...' : 'Revoke all'}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
