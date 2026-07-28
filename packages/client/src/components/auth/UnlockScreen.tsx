import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Lock, Eye, EyeOff, LogOut, AlertCircle, Shield, Clock } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { api, performTokenRefresh } from '../../services/api/client';
import { isSessionGone, describeTransientFailure } from '../../services/auth/sessionFailure';
import { isAccessTokenUsable } from '../../lib/accessToken';
import { getApiErrorMessage } from '../../lib/utils';
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

/**
 * Thrown to unwind out of the unlock flow once the failure has ALREADY been
 * reported — a transient message shown, or the session torn down. The outer catch
 * recognises it and does nothing further: in particular it does not charge the
 * user a failed attempt, and it does not overwrite the message just shown.
 *
 * A real `Error` subclass rather than a sentinel value so that anything which
 * inspects a thrown object (a logger, an error boundary, `only-throw-error`) still
 * sees something well-formed.
 */
class HandledUnlockFailure extends Error {
  constructor() {
    super('Unlock failure already reported');
    this.name = 'HandledUnlockFailure';
  }
}
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

  /**
   * Whether the ambiguous-401 disambiguation below has already run.
   *
   * It costs an extra `verify-unlock`, and `unlockLimiter` is a per-user budget —
   * so doing it on EVERY wrong password would spend two slots per visible attempt
   * and the server would refuse the user while the UI still promised them
   * attempts. Once we have refreshed and re-asked, we know the access token was
   * never the problem, so every later 401 in this session is a credential
   * rejection and needs no second opinion.
   */
  const disambiguatedRef = useRef(false);

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

  /** The session is authoritatively over: tear down and explain why on /login. */
  const endSession = async () => {
    await logout();
    // Carry the reason. Without this the user lands on a bare login form with no
    // idea why they were moved, which is exactly how a transient failure used to
    // present — indistinguishable from "your password is wrong".
    void navigate('/login', { replace: true, state: { sessionExpired: true } });
  };

  /**
   * Report a non-credential failure and unwind. Every caller `throw`s the result,
   * so the control flow reads the same everywhere.
   *
   * A failure that is not evidence of a wrong master password — a rate limit, a
   * 5xx, a dropped connection — must NOT touch `failedAttempts`. That counter
   * drives the local exponential backoff, and inflating it with failures the user
   * did not cause locks them out of their own vault for minutes over a momentary
   * network blip.
   */
  const handled = (message: string): HandledUnlockFailure => {
    setApiError(message);
    form.setFocus('masterPassword');
    return new HandledUnlockFailure();
  };

  /** Best-effort user-facing text for a failure that is not a wrong password. */
  const describeFailure = (err: unknown): string =>
    describeTransientFailure(err) ??
    getApiErrorMessage(err, 'Could not reach the server. Please try again.');

  /**
   * `POST /auth/verify-unlock`.
   *
   * `_skipAuthRefresh` tells the Axios 401 interceptor that a 401 here means
   * "wrong master password", not "expired access token", so it surfaces the error
   * directly instead of firing a second `/auth/refresh` and replaying — which
   * would consume two server-side unlock slots per visible attempt and churn the
   * refresh token.
   */
  const verifyUnlock = (authHash: string) =>
    api.post('/auth/verify-unlock', { authHash }, { _skipAuthRefresh: true });

  /**
   * Refresh, mapping every failure onto the right outcome: a genuine 401/403 ends
   * the session, anything else is transient and keeps it.
   */
  const refreshOrUnwind = async (): Promise<void> => {
    try {
      await performTokenRefresh();
    } catch (err) {
      // ONLY a 401/403 means the session is genuinely gone. Every other failure —
      // a 429, a 5xx, offline — leaves a valid session we simply could not reach,
      // and `logout()` here is not a local teardown: it calls POST /auth/logout
      // and deletes a refresh token with days left on it. Doing that on any error
      // is what turned a brief rate limit into a permanently destroyed session and
      // an unexplained trip to /login.
      if (isSessionGone(err)) {
        await endSession();
        throw new HandledUnlockFailure();
      }
      throw handled(describeFailure(err));
    }
  };

  const handleUnlock = async (values: UnlockFormValues) => {
    /* Prevent submission while locked out */
    if (isLockedOut) return;

    setIsSubmitting(true);
    setApiError(null);

    let masterEncryptionKey: CryptoKey | null = null;

    try {
      const userEmail = user?.email;
      if (!userEmail) {
        // Not a wrong password, so it must not burn an attempt.
        throw handled('Cannot unlock: your session details are unavailable. Please sign in again.');
      }

      // Step 1: make sure a usable access token is in hand, since
      // /auth/verify-unlock is authenticated.
      //
      // Only refresh when we actually need to. `lock()` does NOT clear
      // `accessToken` — a lock zeroes key material and keeps the session alive —
      // so after a short auto-lock the token is usually still valid for minutes.
      // This used to refresh unconditionally on every attempt, which cost a
      // rate-limit slot, rotated the refresh-token cookie, invalidated the CSRF
      // token and so forced an extra 403-and-replay, all to obtain a token no
      // better than the one already held. `isAccessTokenUsable` fails closed, so
      // anything unparseable or near expiry still refreshes.
      const skippedRefresh = isAccessTokenUsable(useAuthStore.getState().accessToken);
      if (!skippedRefresh) {
        await refreshOrUnwind();
      }

      // Step 2: Run PBKDF2 once to obtain both the MEK (used to decrypt the
      // vault key locally) and the auth hash (sent to the server for rate-
      // limited verification). Caching both halves avoids a second PBKDF2
      // round for the local decrypt step.
      const derived = await cryptoService.deriveKeys(values.masterPassword, userEmail);
      masterEncryptionKey = derived.masterEncryptionKey;
      const authHash = cryptoService.getAuthHash(derived.authKey);
      cryptoService.clearKey(derived.authKey);

      // Step 3: Verify the auth hash server-side BEFORE doing any local crypto
      // with the master password, so every wrong-password attempt is counted by
      // the server-side `unlockLimiter` — including attempts that would fail
      // locally and never reach the API.
      try {
        await verifyUnlock(authHash);
      } catch (err) {
        // A 429 from `unlockLimiter` is the server saying "too many tries, wait".
        // It is not a verdict on this password and must not count as a failed
        // attempt — that would stack the local backoff on top of the server's and
        // lock the user out twice over. Same for a 5xx or an offline error.
        const transient = describeTransientFailure(err);
        if (transient !== null) throw handled(transient);

        // A 401 is AMBIGUOUS when we skipped the refresh above. It means either
        // "wrong master password" (the common case) or "this access token is no
        // longer valid" — the password was changed on another device and bumped
        // `passwordChangedAt`, the account was deleted, verification was revoked.
        // The token looked fine locally because `exp` is all the client can see;
        // only the server knows the rest.
        //
        // Reporting that second case as a wrong password is a trap with no exit:
        // every retry fails identically, the local backoff climbs toward ten
        // minutes, and nothing ever tells the user to sign in again. Disambiguate
        // by doing the refresh we skipped and asking once more — if the refresh is
        // rejected the session really is gone; if it succeeds and the verify still
        // fails, the password really is wrong.
        //
        // ONCE per mounted lock screen, though. `unlockLimiter` is 5 per user per
        // 5 minutes, so a second opinion on every wrong password would spend two
        // slots per visible attempt and the server would start refusing while the
        // UI still said "3 attempts remaining". After the first disambiguation the
        // question is settled: the token was fine, so every later 401 here is a
        // credential rejection and needs no extra request.
        if (!skippedRefresh || !isSessionGone(err) || disambiguatedRef.current) throw err;
        disambiguatedRef.current = true;

        await refreshOrUnwind();
        try {
          await verifyUnlock(authHash);
        } catch (retryErr) {
          const retryTransient = describeTransientFailure(retryErr);
          if (retryTransient !== null) throw handled(retryTransient);
          throw retryErr;
        }
      }

      // Step 4: Decrypt the vault key locally using the cached MEK. `unlock`
      // takes ownership of the key on success, so it must not be zeroed after.
      await unlock(values.masterPassword, masterEncryptionKey);
      masterEncryptionKey = null;

      // Step 5: Now that the token is available, unlock the UI so children render.
      useAuthStore.setState({ isLocked: false });

      // Reset rate-limiting on successful unlock
      setFailedAttempts(0);
      setLockoutUntil(null);
      clearPersistedRateLimitState();
    } catch (err) {
      // Zero the derived key on every failing path, from one place, so no branch
      // can leave master-password-derived material resident.
      if (masterEncryptionKey) {
        await cryptoService.clearCryptoKey(masterEncryptionKey);
      }

      // Already reported (transient, or the session was torn down): say no more,
      // and above all do not charge the user a failed attempt for it.
      if (err instanceof HandledUnlockFailure) return;

      const newAttempts = failedAttempts + 1;
      setFailedAttempts(newAttempts);
      applyLockout(newAttempts);

      setApiError(getApiErrorMessage(err, 'Incorrect master password. Please try again.'));
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
