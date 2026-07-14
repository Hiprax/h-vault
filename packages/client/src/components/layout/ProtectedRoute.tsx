import { useState, useEffect, useRef, type ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import { refreshTokenApi } from '../../services/api/authApi';
import { UnlockScreen } from '../auth/UnlockScreen';
import { Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children?: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLocked, accessToken } = useAuthStore();
  const setAccessToken = useAuthStore((s) => s.setAccessToken);
  const logout = useAuthStore((s) => s.logout);
  const location = useLocation();

  const needsRefresh = isAuthenticated && !accessToken && !isLocked;
  const [isRefreshing, setIsRefreshing] = useState(needsRefresh);
  const sessionExpiredRef = useRef(false);

  useEffect(() => {
    if (!needsRefresh) {
      setIsRefreshing(false);
      return;
    }

    let cancelled = false;
    const doRefresh = async () => {
      try {
        const response = await refreshTokenApi();
        if (!cancelled) {
          const result = response.data;
          if (!result.success) {
            sessionExpiredRef.current = true;
            await logout();
            return;
          }
          const newToken = result.data.accessToken;
          setAccessToken(newToken);
          setIsRefreshing(false);
        }
      } catch {
        if (!cancelled) {
          // Refresh failed -- session is unrecoverable; force logout.
          sessionExpiredRef.current = true;
          await logout();
        }
      }
    };
    void doRefresh();
    return () => {
      cancelled = true;
    };
  }, [needsRefresh, setAccessToken, logout]);

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

  if (isRefreshing) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))]">
        <Loader2 className="h-8 w-8 animate-spin text-[hsl(var(--muted-foreground))]" />
      </div>
    );
  }

  return children ? <>{children}</> : <Outlet />;
}
