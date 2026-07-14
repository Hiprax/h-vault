import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Lock, Eye, EyeOff, LogOut, AlertCircle, Shield, Clock } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { api, withRefreshLock } from '../../services/api/client';
import { cryptoService } from '../../services/crypto/cryptoService';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../ui/Card';

/* -------------------------------------------------------------------------- */
/*  Schema                                                                    */
/* -------------------------------------------------------------------------- */

const unlockSchema = z.object({
  masterPassword: z.string().min(1, 'Master password is required'),
});

type UnlockFormValues = z.infer<typeof unlockSchema>;

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/*  Unlock rate-limiting helpers                                              */
/* -------------------------------------------------------------------------- */

const MAX_ATTEMPTS_BEFORE_LOCKOUT = 5;
const UNLOCK_FAILED_ATTEMPTS_KEY = '__hv_unlock_failed_attempts';
const UNLOCK_LOCKOUT_UNTIL_KEY = '__hv_unlock_lockout_until';

/**
 * Returns the cooldown duration in seconds for a given attempt count.
 * Uses exponential backoff: 2^(attempts - threshold) seconds, capped at 600s (10 min).
 */
function getLockoutDuration(attempts: number): number {
  if (attempts < MAX_ATTEMPTS_BEFORE_LOCKOUT) return 0;
  const exponent = attempts - MAX_ATTEMPTS_BEFORE_LOCKOUT;
  return Math.min(Math.pow(2, exponent) * 2, 600);
}

/**
 * Read persisted failed attempts count from localStorage.
 * Uses localStorage (not sessionStorage) so that lockout state survives
 * tab closure and cannot be bypassed by opening a new tab.
 */
function readPersistedAttempts(): number {
  try {
    const stored = localStorage.getItem(UNLOCK_FAILED_ATTEMPTS_KEY);
    if (stored === null) return 0;
    const parsed = parseInt(stored, 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
  } catch {
    return 0;
  }
}

/** Read persisted lockout timestamp from localStorage. */
function readPersistedLockout(): number | null {
  try {
    const stored = localStorage.getItem(UNLOCK_LOCKOUT_UNTIL_KEY);
    if (stored === null) return null;
    const parsed = parseInt(stored, 10);
    if (!Number.isFinite(parsed)) return null;
    // Only return if the lockout is still in the future
    return parsed > Date.now() ? parsed : null;
  } catch {
    return null;
  }
}

/** Persist rate-limiting state to localStorage. */
function persistRateLimitState(attempts: number, lockoutUntil: number | null): void {
  try {
    localStorage.setItem(UNLOCK_FAILED_ATTEMPTS_KEY, String(attempts));
    if (lockoutUntil !== null) {
      localStorage.setItem(UNLOCK_LOCKOUT_UNTIL_KEY, String(lockoutUntil));
    } else {
      localStorage.removeItem(UNLOCK_LOCKOUT_UNTIL_KEY);
    }
  } catch {
    // localStorage unavailable — rate limiting still works in-memory
  }
}

/** Clear persisted rate-limiting state from localStorage. */
function clearPersistedRateLimitState(): void {
  try {
    localStorage.removeItem(UNLOCK_FAILED_ATTEMPTS_KEY);
    localStorage.removeItem(UNLOCK_LOCKOUT_UNTIL_KEY);
  } catch {
    // Ignore
  }
}

export function UnlockScreen() {
  const navigate = useNavigate();
  const { user, unlock, logout } = useAuthStore();

  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  /* ---- Rate-limiting state (persisted to sessionStorage) ---- */
  const [failedAttempts, setFailedAttempts] = useState(() => readPersistedAttempts());
  const [lockoutUntil, setLockoutUntil] = useState<number | null>(() => readPersistedLockout());
  const [cooldownRemaining, setCooldownRemaining] = useState(0);

  const isLockedOut = cooldownRemaining > 0;

  /* Countdown timer for active lockout */
  useEffect(() => {
    if (lockoutUntil === null) return;

    const tick = () => {
      const remaining = Math.max(0, Math.ceil((lockoutUntil - Date.now()) / 1000));
      setCooldownRemaining(remaining);
      if (remaining <= 0) {
        setLockoutUntil(null);
      }
    };

    tick();
    const interval = setInterval(tick, 500);
    return () => clearInterval(interval);
  }, [lockoutUntil]);

  const applyLockout = useCallback((attempts: number) => {
    const duration = getLockoutDuration(attempts);
    if (duration > 0) {
      const until = Date.now() + duration * 1000;
      setLockoutUntil(until);
      persistRateLimitState(attempts, until);
    } else {
      persistRateLimitState(attempts, null);
    }
  }, []);

  const form = useForm<UnlockFormValues>({
    resolver: zodResolver(unlockSchema),
    defaultValues: {
      masterPassword: '',
    },
  });

  const handleUnlock = async (values: UnlockFormValues) => {
    /* Prevent submission while locked out */
    if (isLockedOut) return;

    setIsSubmitting(true);
    setApiError(null);
    try {
      const userEmail = user?.email;
      if (!userEmail) {
        throw new Error('Cannot unlock: user email is not available');
      }

      // Step 1: Refresh the access token so the verify-unlock endpoint is
      // reachable. /auth/verify-unlock is authenticated, and the in-memory
      // access token is empty after a vault lock. Held under the cross-tab
      // refresh lock like every other refresh call site — a tab unlocking while
      // a sibling rotates the shared cookie would otherwise present the same
      // pre-rotation token and trip the server's reuse detection.
      try {
        const refreshRes = await withRefreshLock(() =>
          api.post<{ data: { accessToken: string } }>('/auth/refresh'),
        );
        const newToken = refreshRes.data.data.accessToken;
        useAuthStore.getState().setAccessToken(newToken);
      } catch {
        // Session expired — log the user out completely
        await logout();
        void navigate('/login', { replace: true });
        return;
      }

      // Step 2: Run PBKDF2 once to obtain both the MEK (used to decrypt the
      // vault key locally) and the auth hash (sent to the server for rate-
      // limited verification). Caching both halves avoids a second PBKDF2
      // round for the local decrypt step.
      const { masterEncryptionKey, authKey } = await cryptoService.deriveKeys(
        values.masterPassword,
        userEmail,
      );
      const authHash = cryptoService.getAuthHash(authKey);
      cryptoService.clearKey(authKey);

      // Step 3: Verify the auth hash server-side BEFORE doing any local
      // crypto with the master password. This ensures every wrong-password
      // attempt is counted by the server-side unlockLimiter, including
      // attempts that would otherwise fail locally and never reach the API.
      try {
        // `_skipAuthRefresh` tells the Axios 401 interceptor that a 401 here
        // means "wrong master password", not "expired access token", so it
        // surfaces the error directly instead of firing a second /auth/refresh
        // and replaying this request — which would otherwise consume two
        // server-side unlockLimiter slots per visible attempt and churn the
        // refresh token.
        await api.post('/auth/verify-unlock', { authHash }, { _skipAuthRefresh: true });
      } catch (err) {
        await cryptoService.clearCryptoKey(masterEncryptionKey);
        throw err;
      }

      // Step 4: Decrypt the vault key locally using the cached MEK.
      try {
        await unlock(values.masterPassword, masterEncryptionKey);
      } catch (err) {
        await cryptoService.clearCryptoKey(masterEncryptionKey);
        throw err;
      }

      // Step 5: Now that the token is available, unlock the UI so children render.
      useAuthStore.setState({ isLocked: false });

      // Reset rate-limiting on successful unlock
      setFailedAttempts(0);
      setLockoutUntil(null);
      clearPersistedRateLimitState();
    } catch (err) {
      const newAttempts = failedAttempts + 1;
      setFailedAttempts(newAttempts);
      applyLockout(newAttempts);

      setApiError(
        err instanceof Error ? err.message : 'Incorrect master password. Please try again.',
      );
      form.setFocus('masterPassword');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    void navigate('/login', { replace: true });
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
            <Lock className="h-6 w-6 text-[hsl(var(--primary))]" />
          </div>
          <CardTitle>Vault Locked</CardTitle>
          <CardDescription>
            {user?.email ? `Signed in as ${user.email}` : 'Enter your master password to unlock'}
          </CardDescription>
        </CardHeader>

        <form onSubmit={(e) => void form.handleSubmit(handleUnlock)(e)}>
          <CardContent className="space-y-4">
            {isLockedOut && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-md border border-[hsl(var(--warning,40_96%_40%)/0.3)] bg-[hsl(var(--warning,40_96%_40%)/0.05)] p-3 text-sm text-[hsl(var(--warning,40_96%_40%))]"
              >
                <Clock className="h-4 w-4 shrink-0" />
                <span>
                  Too many failed attempts. Please wait <strong>{cooldownRemaining}s</strong> before
                  trying again.
                </span>
              </div>
            )}

            {!isLockedOut && failedAttempts > 0 && failedAttempts < MAX_ATTEMPTS_BEFORE_LOCKOUT && (
              <div
                role="status"
                className="flex items-center gap-2 rounded-md border border-[hsl(var(--warning,40_96%_40%)/0.3)] bg-[hsl(var(--warning,40_96%_40%)/0.05)] p-3 text-sm text-[hsl(var(--warning,40_96%_40%))]"
              >
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>
                  {MAX_ATTEMPTS_BEFORE_LOCKOUT - failedAttempts} attempt
                  {MAX_ATTEMPTS_BEFORE_LOCKOUT - failedAttempts === 1 ? '' : 's'} remaining before
                  temporary lockout.
                </span>
              </div>
            )}

            {apiError && !isLockedOut && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-3 text-sm text-[hsl(var(--destructive))]"
              >
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{apiError}</span>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="unlock-password" error={!!form.formState.errors.masterPassword}>
                Master Password
              </Label>
              <div className="relative">
                <Input
                  id="unlock-password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your master password"
                  autoComplete="current-password"
                  autoFocus
                  error={!!form.formState.errors.masterPassword}
                  className="pr-10"
                  {...form.register('masterPassword')}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {form.formState.errors.masterPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.masterPassword.message}
                </p>
              )}
            </div>
          </CardContent>

          <CardFooter className="flex-col gap-3">
            <Button type="submit" className="w-full" loading={isSubmitting} disabled={isLockedOut}>
              <Shield className="h-4 w-4" />
              {isLockedOut ? `Locked (${cooldownRemaining}s)` : 'Unlock Vault'}
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="w-full text-[hsl(var(--destructive))]"
              onClick={() => void handleLogout()}
            >
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
