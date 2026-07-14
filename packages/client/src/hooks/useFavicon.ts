import { useEffect } from 'react';
import { useAuthStore } from '../stores/authStore';
import { faviconStateFor, setFaviconState } from '../utils/favicon';

/**
 * Keeps the browser-tab favicon in sync with the vault state: green/open when
 * the vault is authenticated and unlocked, red/closed otherwise (logged out or
 * locked). Mount once near the app root so it also updates on the public
 * (logged-out) routes.
 */
export function useFavicon(): void {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLocked = useAuthStore((s) => s.isLocked);

  useEffect(() => {
    setFaviconState(faviconStateFor(isAuthenticated, isLocked));
  }, [isAuthenticated, isLocked]);
}
