import { useCallback, useEffect, useMemo, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Shield,
  Key,
  FileLock2,
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
import { useUIStore } from '../../stores/uiStore';
import { useVaultStore } from '../../stores/vaultStore';
import { useToast } from '../ui/Toast';
import { cn } from '../../lib/utils';
import { useAutoLock } from '../../hooks/useAutoLock';
import { useClipboardGuard } from '../../hooks/useClipboardGuard';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';
import { OnboardingGuide } from './OnboardingGuide';
import { isStorageDegraded } from '../../stores/encryptedStorage';
import { BrandLogo } from '../ui/BrandLogo';
import { useConnectionStatus } from '../../hooks/useConnectionStatus';

interface NavItem {
  label: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { label: 'Vault', to: '/vault', icon: Shield },
  { label: 'Password Generator', to: '/generator', icon: Key },
  { label: 'File Encryption', to: '/tools/file-encryption', icon: FileLock2 },
  { label: 'Vault Health', to: '/vault/health', icon: Activity },
  { label: 'Settings', to: '/settings', icon: Settings },
];

export function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [storageDegraded, setStorageDegraded] = useState(isStorageDegraded());
  const [decryptionFailureCount, setDecryptionFailureCount] = useState(0);
  const { user, logout, lock, isLocked } = useAuthStore();
  const { sidebarCollapsed, toggleSidebarCollapsed } = useUIStore();
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchFolders = useVaultStore((s) => s.fetchFolders);
  const navigate = useNavigate();
  const { toast } = useToast();

  // Reflects real server reachability (a lightweight /health poll), not just
  // navigator.onLine — so the indicator turns Offline when the server is down.
  const { isOnline } = useConnectionStatus();

  // Whether the sidebar should visually appear expanded
  const expanded = !sidebarCollapsed || hovered;

  // Lock the vault after a period of inactivity
  useAutoLock();

  // Clear clipboard on page hide / unload if sensitive data was copied
  useClipboardGuard();

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
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={closeSidebar}
              title={!expanded ? item.label : undefined}
              className={({ isActive }) =>
                cn(
                  'flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  expanded ? 'gap-3' : 'justify-center',
                  isActive
                    ? 'bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]'
                    : 'text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))]',
                )
              }
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
            </NavLink>
          ))}
        </nav>

        {/* Online/offline indicator */}
        <div
          className={cn(
            'mx-3 mb-1 flex items-center rounded-md px-3 py-1.5 text-xs font-medium',
            expanded ? 'gap-2' : 'justify-center',
            isOnline
              ? 'text-green-600 dark:text-green-400'
              : 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
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
