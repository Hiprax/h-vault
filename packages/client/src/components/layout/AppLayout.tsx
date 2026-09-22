import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';
import {
  Shield,
  Key,
  FileLock2,
  ScanLine,
  Files,
  Settings,
  Lock,
  LogOut,
  Menu,
  X,
  Activity,
  Wifi,
  WifiOff,
  AlertTriangle,
  RefreshCw,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { isHoldingSupersededVaultKey, useUIStore } from '../../stores/uiStore';
import { useVaultStore } from '../../stores/vaultStore';
import { useToast } from '../ui/Toast';
import { cn } from '../../lib/utils';
import { useAutoLock } from '../../hooks/useAutoLock';
import { useDocumentsConfig } from '../../hooks/useDocumentsConfig';
import { useClipboardCountdown } from '../../hooks/useClipboardCountdown';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { OnboardingGuide } from './OnboardingGuide';
import { isStorageDegraded } from '../../stores/encryptedStorage';
import { BrandLogo } from '../ui/BrandLogo';
import { useConnectionStatus } from '../../hooks/useConnectionStatus';
import type { OfflineCacheErrorType } from '../../services/offlineCache';

interface NavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  /** Optional active predicate; defaults to exact-or-descendant path matching. */
  match?: (pathname: string) => boolean;
}

/**
 * "Vault" is active on the list (`/vault`) and on an individual item
 * (`/vault/:id`), but NOT on the sibling `/vault/health` route — that page has its
 * own nav item. The default descendant match cannot express this (it would light
 * up "Vault" on `/vault/health` too), which is the double-highlight bug this
 * replaces.
 */
export function isVaultSectionActive(pathname: string): boolean {
  if (pathname === '/vault') return true;
  // Any /vault/* item page, EXCEPT the Vault Health route (and any future child of
  // it), which owns its own nav item.
  if (pathname === '/vault/health' || pathname.startsWith('/vault/health/')) return false;
  return pathname.startsWith('/vault/');
}

/**
 * Whether a nav item is active for the given pathname. Default: the item's exact
 * path or any descendant of it (so `/settings` stays highlighted on
 * `/settings/backup`, `/settings/sessions`, etc.). An item may override with its
 * own `match`.
 */
export function isNavItemActive(item: Pick<NavItem, 'to' | 'match'>, pathname: string): boolean {
  if (item.match) return item.match(pathname);
  return pathname === item.to || pathname.startsWith(`${item.to}/`);
}

const VAULT_NAV_ITEM: NavItem = {
  label: 'Vault',
  to: '/vault',
  icon: Shield,
  match: isVaultSectionActive,
};

const REMAINING_NAV_ITEMS: NavItem[] = [
  { label: 'Password Generator', to: '/generator', icon: Key },
  { label: 'File Encryption', to: '/tools/file-encryption', icon: FileLock2 },
  { label: 'Import from Authenticator', to: '/tools/totp-import', icon: ScanLine },
  { label: 'Vault Health', to: '/vault/health', icon: Activity },
  { label: 'Settings', to: '/settings', icon: Settings },
];

/**
 * The document store's entry, rendered ONLY where the server says the feature is
 * available.
 *
 * It carries no `match` of its own: the default exact-or-descendant rule already
 * lights it on `/documents` and on `/documents/:id` and on nothing else, which is
 * exactly right here. `/vault`'s override exists because that section has a
 * sibling route with its own nav item; this one has no sibling to disambiguate,
 * and a `match` that restated the default would be a second copy of it.
 *
 * It sits after "Vault" because that is where a reader looks for the OTHER thing
 * the vault holds, rather than at the end beside the tools.
 */
const DOCUMENTS_NAV_ITEM: NavItem = { label: 'Documents', to: '/documents', icon: Files };

/**
 * The navigation, with the document store's entry spliced in when this server
 * offers it.
 *
 * Two explicit lists rather than one list filtered by a predicate, because the
 * predicate would have to be evaluated for every entry in order to hide exactly
 * one of them, and a `hidden` flag on `NavItem` would be a field five entries
 * carry for the sake of the sixth. Exported so the entry's presence and its
 * position can be pinned without rendering the whole layout.
 */
/**
 * What the user is told when the encrypted offline copy of their vault cannot be
 * written. Offline read access is a shipped feature, so a silent write failure
 * is discovered at the worst possible moment: an empty vault with no network to
 * recover from. The notice is raised while the user is still ONLINE and able to
 * act.
 *
 * The four classified causes collapse to three messages because only two of them
 * have a remedy the user owns. `unavailable` (no IndexedDB at all) and `unknown`
 * share one honest, non-prescriptive sentence rather than inviting the user to
 * distinguish situations they cannot act on differently.
 *
 * Canned copy, keyed on the discriminant — never the underlying `message`, which
 * is engine-specific text this project has not reviewed.
 */
const OFFLINE_CACHE_UNAVAILABLE =
  'Offline access is unavailable: offline storage is not working in this browser.';

const OFFLINE_CACHE_NOTICES: Record<OfflineCacheErrorType, string> = {
  quota_exceeded:
    'Offline access is unavailable: offline storage is full. Free up browser storage, then reload.',
  permission_denied:
    'Offline access is unavailable: your browser is blocking offline storage. Allow site data for this site, or leave private browsing, then reload.',
  unavailable: OFFLINE_CACHE_UNAVAILABLE,
  unknown: OFFLINE_CACHE_UNAVAILABLE,
};

export function navItemsFor(documentsEnabled: boolean): NavItem[] {
  if (!documentsEnabled) return [VAULT_NAV_ITEM, ...REMAINING_NAV_ITEMS];
  return [VAULT_NAV_ITEM, DOCUMENTS_NAV_ITEM, ...REMAINING_NAV_ITEMS];
}

export function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [storageDegraded, setStorageDegraded] = useState(isStorageDegraded());
  const [decryptionFailureCount, setDecryptionFailureCount] = useState(0);
  // Dismissal is remembered per CAUSE, not as a bare boolean: a user who
  // dismissed "storage is full" should still be told when the cause changes to
  // "your browser is blocking this", which is a different remedy.
  const [dismissedOfflineCacheError, setDismissedOfflineCacheError] =
    useState<OfflineCacheErrorType | null>(null);
  const { user, logout, lock, isLocked, vaultKeyVersion } = useAuthStore();
  // `null` until the server has answered, and the entry is rendered only for an
  // explicit `true`: an entry that appeared and then vanished would be worse than
  // one that appeared a beat late.
  const documentsConfig = useDocumentsConfig();
  const { sidebarCollapsed, toggleSidebarCollapsed, offlineCacheError, staleVaultKeyVersion } =
    useUIStore();
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchFolders = useVaultStore((s) => s.fetchFolders);
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  // Reflects real server reachability (a lightweight /health poll), not just
  // navigator.onLine — so the indicator turns Offline when the server is down.
  const { isOnline } = useConnectionStatus();

  // The cause to announce, or `null` when there is nothing to say. Derived rather
  // than a bare boolean so the notice lookup and the dismiss handler both narrow
  // to a real cause without a non-null assertion.
  const offlineCacheNotice =
    offlineCacheError !== null && offlineCacheError !== dismissedOfflineCacheError
      ? offlineCacheError
      : null;

  // Whether this session is still holding a vault key the account has replaced.
  // DERIVED from the generation the server last refused a write with and the one
  // this session believes it holds, so it clears itself the moment those agree —
  // see `isHoldingSupersededVaultKey`. No write anywhere has to remember to
  // reset it, which is what stops a missed reset leaving a permanent notice in
  // front of a healthy session.
  const holdingSupersededVaultKey = isHoldingSupersededVaultKey(
    staleVaultKeyVersion,
    vaultKeyVersion,
  );

  // Whether the sidebar should visually appear expanded
  const expanded = !sidebarCollapsed || hovered;

  // Lock the vault after a period of inactivity
  useAutoLock();

  // The one app-wide clipboard countdown notice, derived from the guard's state.
  // The guard ITSELF is mounted in App, above the lock boundary — see its docblock.
  useClipboardCountdown();

  // Global keyboard shortcut: Ctrl+L to lock vault
  const globalShortcuts = useMemo(
    () => ({
      l: () => void lock(),
    }),
    [lock],
  );
  useKeyboardShortcuts(globalShortcuts);

  useEffect(() => {
    // Re-fetch vault data when the browser reconnects (only if vault is
    // unlocked). The Online/Offline *display* is driven by useConnectionStatus.
    const handleOnline = () => {
      if (!isLocked) {
        toast({ title: 'Back online. Syncing your vault...', type: 'info' });
        Promise.all([fetchItems(), fetchFolders()]).then(
          () => {
            toast({ title: 'Vault synced successfully', type: 'success' });
          },
          () => {
            toast({ title: 'Failed to sync vault data', type: 'error' });
          },
        );
      }
    };
    window.addEventListener('online', handleOnline);
    return () => {
      window.removeEventListener('online', handleOnline);
    };
  }, [isLocked, fetchItems, fetchFolders, toast]);

  // Listen for vault decryption failures and show a persistent banner
  useEffect(() => {
    const handler = (e: Event) => {
      const count = (e as CustomEvent<{ count: number }>).detail.count;
      setDecryptionFailureCount(count);
    };
    window.addEventListener('vault-decryption-failures', handler);
    return () => window.removeEventListener('vault-decryption-failures', handler);
  }, []);

  const handleResync = useCallback(() => {
    setDecryptionFailureCount(0);
    void fetchItems();
    void fetchFolders();
  }, [fetchItems, fetchFolders]);

  // Re-check storage degraded flag when localStorage changes (e.g. from another tab)
  useEffect(() => {
    const handleStorage = (e: StorageEvent) => {
      if (e.key === '__hv_storage_degraded') {
        setStorageDegraded(e.newValue === 'true');
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  const handleLogout = () => {
    void logout().then(
      () => {
        void navigate('/login');
      },
      () => {
        void navigate('/login');
      },
    );
  };

  const handleLock = () => {
    void lock();
  };

  const closeSidebar = () => {
    setSidebarOpen(false);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[hsl(var(--background))]">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <button
          type="button"
          className="fixed inset-0 z-30 bg-black/50 lg:hidden cursor-default"
          onClick={closeSidebar}
          onKeyDown={(e) => {
            if (e.key === 'Escape') closeSidebar();
          }}
          aria-label="Close sidebar"
        />
      )}

      {/* Sidebar */}
      <aside
        onMouseEnter={() => {
          if (sidebarCollapsed) setHovered(true);
        }}
        onMouseLeave={() => setHovered(false)}
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex flex-col border-r border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] transition-all duration-200 ease-in-out overflow-hidden',
          // Mobile: slide in/out
          sidebarOpen ? 'translate-x-0' : '-translate-x-full',
          // Desktop: always visible, width changes based on collapsed/hovered
          'lg:static lg:translate-x-0',
          expanded ? 'w-64' : 'w-16',
        )}
      >
        {/* Logo */}
        <div className="flex h-16 items-center gap-2 border-b border-[hsl(var(--sidebar-border))] px-4">
          <BrandLogo className="h-6 w-6 shrink-0 text-[hsl(var(--primary))]" />
          <span
            className={cn(
              'text-lg font-bold text-[hsl(var(--sidebar-foreground))] whitespace-nowrap transition-opacity duration-200',
              expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden',
            )}
          >
            H-Vault
          </span>

          {/* Desktop collapse toggle */}
          <button
            type="button"
            onClick={toggleSidebarCollapsed}
            className={cn(
              'hidden lg:flex shrink-0 cursor-pointer rounded-md p-1 text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))] ml-auto transition-all duration-200',
              expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden pointer-events-none',
            )}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? (
              <PanelLeftOpen className="h-4 w-4" />
            ) : (
              <PanelLeftClose className="h-4 w-4" />
            )}
          </button>

          {/* Mobile close button */}
          <button
            type="button"
            onClick={closeSidebar}
            className="ml-auto cursor-pointer rounded-md p-1 text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))] lg:hidden"
            aria-label="Close sidebar"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
          {navItemsFor(documentsConfig?.enabled === true).map((item) => {
            const active = isNavItemActive(item, location.pathname);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={closeSidebar}
                title={!expanded ? item.label : undefined}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  expanded ? 'gap-3' : 'justify-center',
                  active
                    ? 'bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]'
                    : 'text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))]',
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                <span
                  className={cn(
                    'whitespace-nowrap transition-opacity duration-200',
                    expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden',
                  )}
                >
                  {item.label}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Online/offline indicator */}
        <div
          className={cn(
            'mx-3 mb-1 flex items-center rounded-md px-3 py-1.5 text-xs font-medium',
            expanded ? 'gap-2' : 'justify-center',
            // The 800 shades, not 600: this is 12px text on the sidebar's own
            // background, where green-600 measured 2.92:1 and yellow-600 2.67:1
            // against a 4.5:1 requirement. The dark-theme shades are unchanged
            // — they are light text on a near-black surface.
            isOnline
              ? 'text-green-800 dark:text-green-400'
              : 'text-yellow-800 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
          )}
        >
          {isOnline ? (
            <Wifi className="h-3 w-3 shrink-0" />
          ) : (
            <WifiOff className="h-3 w-3 shrink-0" />
          )}
          <span
            className={cn(
              'whitespace-nowrap transition-opacity duration-200',
              expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden',
            )}
          >
            {isOnline ? 'Online' : 'Offline'}
          </span>
        </div>

        {/* User section */}
        <div className="border-t border-[hsl(var(--sidebar-border))] p-3 space-y-1">
          {user && (
            <div
              className={cn(
                'px-3 py-2 transition-opacity duration-200',
                expanded ? 'opacity-100' : 'opacity-0 h-0 overflow-hidden',
              )}
            >
              <p className="text-sm font-medium text-[hsl(var(--sidebar-foreground))] truncate">
                {user.email}
              </p>
            </div>
          )}

          <button
            type="button"
            onClick={handleLock}
            title={!expanded ? 'Lock Vault' : undefined}
            className={cn(
              'flex w-full cursor-pointer items-center rounded-md px-3 py-2 text-sm font-medium text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))] transition-colors',
              expanded ? 'gap-3' : 'justify-center',
            )}
          >
            <Lock className="h-4 w-4 shrink-0" />
            <span
              className={cn(
                'whitespace-nowrap transition-opacity duration-200',
                expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden',
              )}
            >
              Lock Vault
            </span>
          </button>

          <button
            type="button"
            onClick={handleLogout}
            title={!expanded ? 'Logout' : undefined}
            className={cn(
              'flex w-full cursor-pointer items-center rounded-md px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors',
              expanded ? 'gap-3' : 'justify-center',
            )}
          >
            <LogOut className="h-4 w-4 shrink-0" />
            <span
              className={cn(
                'whitespace-nowrap transition-opacity duration-200',
                expanded ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden',
              )}
            >
              Logout
            </span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Mobile hamburger (visible only on small screens) */}
        <div className="flex h-12 items-center px-4 lg:hidden">
          <button
            type="button"
            onClick={() => setSidebarOpen(true)}
            className="cursor-pointer rounded-md p-2 text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            aria-label="Open sidebar"
          >
            <Menu className="h-5 w-5" />
          </button>
        </div>

        {/* Degraded storage warning */}
        {storageDegraded && (
          <div className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-yellow-300 bg-yellow-50 px-4 py-2 text-sm text-yellow-800 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300 lg:mx-6">
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span>
              Your browser does not support secure storage. Data is stored unencrypted. Use HTTPS
              for full security.
            </span>
          </div>
        )}

        {/*
          Offline cache warning.

          The live region is MOUNTED UNCONDITIONALLY and only its CONTENT changes.
          A region that is inserted into the document already holding its message
          is frequently not announced at all: the special handling that survives
          that is defined for `role="alert"`, not for `role="status"`. Rendering
          the whole `<div role="status">…message…</div>` behind the condition
          would therefore have left this notice silent for exactly the users who
          cannot see it — the failure the notice exists to prevent, one layer
          down. `alert` is the wrong politeness here (a degraded-mode notice must
          not interrupt), so the region is empty until there is something to say.

          When empty it is `sr-only`, so it occupies no layout; the visible box
          and its spacing live on the child.
        */}
        <div
          role="status"
          data-testid="offline-cache-region"
          className={offlineCacheNotice !== null ? 'mx-4 mt-2 lg:mx-6' : 'sr-only'}
        >
          {offlineCacheNotice !== null && (
            <div
              data-testid="offline-cache-banner"
              className="flex items-center gap-2 rounded-md border border-yellow-300 bg-yellow-50 px-4 py-2 text-sm text-yellow-800 dark:border-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300"
            >
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              <span className="flex-1">{OFFLINE_CACHE_NOTICES[offlineCacheNotice]}</span>
              <button
                type="button"
                onClick={() => setDismissedOfflineCacheError(offlineCacheNotice)}
                className="cursor-pointer rounded p-1 text-yellow-700 hover:bg-yellow-100 dark:text-yellow-400 dark:hover:bg-yellow-800/30"
                aria-label="Dismiss offline storage warning"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* The session is holding a vault key the account has replaced.

            `role="alert"` rather than the `status` region above, and rendered
            conditionally rather than as an always-mounted live region: this is
            an interrupting condition — every save from this tab is being
            refused — and `alert` is the role whose announcement survives being
            inserted along with its message.

            The server has told this session which generation it is on;
            ADOPTING that number, or re-deriving the vault key to match it,
            would be taking a key the server chose on a session whose in-memory
            data was all decrypted under the old one. So the remedy is to start
            again from one consistent state. It is not dismissible for the same
            reason: dismissing it would leave a session in which nothing can be
            saved and nothing says so.

            That remedy is a SIGN-OUT and not a reload, and the difference is
            not cosmetic. A reload rehydrates `isAuthenticated` from persisted
            state, so `shouldAttemptResume()` is false and no profile is read;
            the Unlock screen then re-derives the vault key from the PERSISTED
            `encryptedVaultKeyData`, which moves with the key this session holds
            and is therefore exactly as superseded as the writes that were just
            refused. The banner came straight back, and the button that promised
            to fix it was the thing that could not. Signing in reads the live
            wrapper and the live generation from the server unconditionally,
            which is the only path that does. */}
        {holdingSupersededVaultKey && (
          <div
            role="alert"
            data-testid="stale-vault-key-banner"
            className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-red-300 bg-red-50 px-4 py-2 text-sm text-red-800 dark:border-red-700 dark:bg-red-900/20 dark:text-red-300 lg:mx-6"
          >
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span className="flex-1">
              Your vault key was changed on another device, so changes from this tab can no longer
              be saved. Sign in again to continue.
            </span>
            <button
              type="button"
              onClick={() => {
                void logout();
              }}
              className="inline-flex cursor-pointer items-center gap-1 rounded px-2 py-1 text-xs font-medium text-red-700 hover:bg-red-100 dark:text-red-300 dark:hover:bg-red-800/30"
            >
              <RefreshCw className="h-3 w-3" />
              Sign out
            </button>
          </div>
        )}

        {/* Decryption failure warning */}
        {decryptionFailureCount > 0 && (
          <div
            role="alert"
            data-testid="decryption-failure-banner"
            className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-red-300 bg-red-50 px-4 py-2 text-sm text-red-800 dark:border-red-700 dark:bg-red-900/20 dark:text-red-300 lg:mx-6"
          >
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span className="flex-1">
              {decryptionFailureCount} item(s) could not be decrypted. This may indicate data
              corruption or a key mismatch.
            </span>
            <button
              type="button"
              onClick={handleResync}
              className="inline-flex cursor-pointer items-center gap-1 rounded px-2 py-1 text-xs font-medium text-red-700 hover:bg-red-100 dark:text-red-300 dark:hover:bg-red-800/30"
            >
              <RefreshCw className="h-3 w-3" />
              Re-sync
            </button>
            <button
              type="button"
              onClick={() => setDecryptionFailureCount(0)}
              className="cursor-pointer rounded p-1 text-red-600 hover:bg-red-100 dark:text-red-400 dark:hover:bg-red-800/30"
              aria-label="Dismiss decryption warning"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>

        {/* First-time onboarding guide */}
        <OnboardingGuide />
      </div>
    </div>
  );
}
