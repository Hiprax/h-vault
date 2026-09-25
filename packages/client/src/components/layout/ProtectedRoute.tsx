import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';
import { useAuthStore } from '../../stores/authStore';
import { refreshTokenApi } from '../../services/api/authApi';
import { isAccountLocked, isSessionGone } from '../../services/auth/sessionFailure';
import { UnlockScreen } from '../auth/UnlockScreen';
import { StandalonePage } from './StandalonePage';
import { Button } from '../ui/Button';
import { Loader2, LockKeyhole, WifiOff } from 'lucide-react';

interface ProtectedRouteProps {
  children?: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLocked, accessToken } = useAuthStore();
  const logout = useAuthStore((s) => s.logout);
  const location = useLocation();

  const needsRefresh = isAuthenticated && !accessToken && !isLocked;
  const [isRefreshing, setIsRefreshing] = useState(needsRefresh);
  // Bumped by the Try again button to re-run the refresh effect. A counter rather
  // than a boolean so repeated retries each trigger a fresh attempt.
  const [retryToken, setRetryToken] = useState(0);
  const [refreshStalled, setRefreshStalled] = useState(false);
  // A locked account is its OWN outcome, not a stalled connection. Both keep the
  // session and both offer the same retry, but telling someone to "check your
  // connection" when the server has told us exactly what is wrong sends them to
  // debug their network instead of to the unlock link in their inbox.
  const [accountLocked, setAccountLocked] = useState(false);
  const sessionExpiredRef = useRef(false);

  useEffect(() => {
    if (!needsRefresh) {
      setIsRefreshing(false);
      return;
    }

    let cancelled = false;
    setIsRefreshing(true);
    setRefreshStalled(false);
    setAccountLocked(false);

    const doRefresh = async () => {
      try {
        // Resolves to the access token and stores it; rejects on a non-success
        // envelope, so there is no separate `success` branch to get wrong.
        await refreshTokenApi();
        if (!cancelled) setIsRefreshing(false);
      } catch (error) {
        if (cancelled) return;
        // Only an authoritative rejection ends the session. A 429, a 5xx or a
        // dropped connection must NOT log the user out: `logout()` calls
        // `POST /auth/logout` and deletes a refresh token that is still perfectly
        // good, so a momentary blip here used to cost the whole session. Offer a
        // retry and keep everything intact instead.
        if (isSessionGone(error)) {
          sessionExpiredRef.current = true;
          await logout();
          return;
        }
        setIsRefreshing(false);
        // A lockout is temporary by construction and the refresh handler refuses
        // it WITHOUT claiming the presented token, so the cookie behind this
        // screen is still good: the retry below succeeds the moment the account
        // is unlocked. Logging out instead would delete that session for real.
        if (isAccountLocked(error)) {
          setAccountLocked(true);
          return;
        }
        setRefreshStalled(true);
      }
    };
    void doRefresh();
    return () => {
      cancelled = true;
    };
  }, [needsRefresh, logout, retryToken]);

  const handleRetry = useCallback(() => {
    setRetryToken((n) => n + 1);
  }, []);

  if (!isAuthenticated) {
    const state: Record<string, unknown> = { from: location };
    if (sessionExpiredRef.current) {
      state.sessionExpired = true;
      sessionExpiredRef.current = false;
    }
    return <Navigate to="/login" state={state} replace />;
  }

  if (isLocked) {
    return <UnlockScreen />;
  }

  if (accountLocked) {
    return (
      <StandalonePage>
        <div
          role="alert"
          className="flex max-w-sm flex-col items-center gap-4 text-center text-[hsl(var(--foreground))]"
        >
          <LockKeyhole className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
          <div className="space-y-1">
            <h1 className="text-sm font-medium">Account temporarily locked</h1>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Your session is still active. Use the unlock link we emailed you, or try again later.
            </p>
          </div>
          <Button type="button" onClick={handleRetry}>
            Try again
          </Button>
        </div>
      </StandalonePage>
    );
  }

  if (refreshStalled) {
    return (
      <StandalonePage>
        <div
          role="alert"
          className="flex max-w-sm flex-col items-center gap-4 text-center text-[hsl(var(--foreground))]"
        >
          <WifiOff className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
          <div className="space-y-1">
            <h1 className="text-sm font-medium">Could not reach the server</h1>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Your session is still active. Check your connection and try again.
            </p>
          </div>
          <Button type="button" onClick={handleRetry}>
            Try again
          </Button>
        </div>
      </StandalonePage>
    );
  }

  if (isRefreshing) {
    return (
      <StandalonePage className="px-0">
        <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--muted-foreground))]" />
      </StandalonePage>
    );
  }

  return children ? <>{children}</> : <Outlet />;
}
