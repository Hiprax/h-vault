import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';
import { useAuthStore } from '../../stores/authStore';
import { refreshTokenApi } from '../../services/api/authApi';
import { isSessionGone } from '../../services/auth/sessionFailure';
import { UnlockScreen } from '../auth/UnlockScreen';
import { Button } from '../ui/Button';
import { Loader2, WifiOff } from 'lucide-react';

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
  const sessionExpiredRef = useRef(false);

  useEffect(() => {
    if (!needsRefresh) {
      setIsRefreshing(false);
      return;
    }

    let cancelled = false;
    setIsRefreshing(true);
    setRefreshStalled(false);

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

  if (refreshStalled) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
        <div
          role="alert"
          className="flex max-w-sm flex-col items-center gap-4 text-center text-[hsl(var(--foreground))]"
        >
          <WifiOff className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
          <div className="space-y-1">
            <p className="text-sm font-medium">Could not reach the server</p>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Your session is still active. Check your connection and try again.
            </p>
          </div>
          <Button type="button" onClick={handleRetry}>
            Try again
          </Button>
        </div>
      </div>
    );
  }

  if (isRefreshing) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))]">
        <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--muted-foreground))]" />
      </div>
    );
  }

  return children ? <>{children}</> : <Outlet />;
}
