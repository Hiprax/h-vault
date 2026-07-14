/**
 * Rendering tests for untested components.
 *
 * Covers:
 * 1 - NotFoundPage (static rendering, link target)
 * 2 - ProtectedRoute (redirect, unlock, children)
 * 3 - OnboardingGuide (visibility, step navigation, close)
 * 4 - AppLayout (nav links, user email, lock/logout buttons, degraded storage)
 * 5 - FolderSidebar (All Items, Favorites, Trash, type filters, New Folder dialog)
 * 6 - VaultItemDetail (item name, action buttons, type-specific fields)
 * 7 - VaultList (empty state, item rendering, loading skeleton)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom
// ---------------------------------------------------------------------------

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn(),
    generateVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
  refreshTokenApi: vi.fn(),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
  reorderFolderApi: vi.fn(),
  bulkDeleteApi: vi.fn(),
  bulkMoveApi: vi.fn(),
}));

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: vi.fn(),
  updateSettingsApi: vi.fn(),
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { headers: { common: {} } },
  },
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: vi.fn().mockReturnValue({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
  clearSettingsCache: vi.fn(),
}));

vi.mock('../src/hooks/useAutoLock', () => ({
  useAutoLock: vi.fn(),
}));

vi.mock('../src/hooks/useKeyboardShortcuts', () => ({
  useKeyboardShortcuts: vi.fn(),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: vi.fn().mockReturnValue({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({
    toast: vi.fn(),
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

vi.mock('@hvault/shared', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@hvault/shared');
  return {
    ...actual,
    KDF_ITERATIONS: 600_000,
    KDF_ALGORITHM: 'PBKDF2',
    ENCRYPTION_VERSION: 1,
  };
});

// Mock react-window — VaultList imports `List` (not FixedSizeList)
vi.mock('react-window', () => ({
  List: ({
    rowComponent: RowComponent,
    rowCount,
    rowHeight,
    rowProps,
  }: {
    rowComponent: React.ComponentType<Record<string, unknown>>;
    rowCount: number;
    rowHeight: number;
    rowProps: Record<string, unknown>;
  }) => {
    const items = [];
    for (let i = 0; i < Math.min(rowCount, 20); i++) {
      items.push(
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: { height: rowHeight },
          ...rowProps,
        }),
      );
    }
    return React.createElement('div', { role: 'list', 'data-testid': 'virtual-list' }, ...items);
  },
}));

vi.mock('zxcvbn', () => ({
  default: () => ({ score: 3, feedback: { warning: '', suggestions: [] } }),
}));

// Mock UnlockScreen so ProtectedRoute tests don't pull in the real component
vi.mock('../src/components/auth/UnlockScreen', () => ({
  UnlockScreen: () =>
    React.createElement('div', { 'data-testid': 'unlock-screen' }, 'Unlock Screen'),
}));

// Mock react-markdown for VaultItemDetail
vi.mock('react-markdown', () => ({
  default: ({ children }: { children: string }) =>
    React.createElement('div', { 'data-testid': 'markdown-content' }, children),
}));

// Mock OnboardingGuide for AppLayout tests to avoid interference
// (We test OnboardingGuide separately.)
vi.mock('../src/components/layout/OnboardingGuide', () => ({
  OnboardingGuide: () => null,
}));

// ---------------------------------------------------------------------------
// Store imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useUIStore } from '../src/stores/uiStore';
import { isStorageDegraded } from '../src/stores/encryptedStorage';

// ---------------------------------------------------------------------------
// Component imports
// ---------------------------------------------------------------------------

import NotFoundPage from '../src/pages/NotFoundPage';
import { ProtectedRoute } from '../src/components/layout/ProtectedRoute';
import { PublicOnlyRoute } from '../src/components/layout/PublicOnlyRoute';
import { AppLayout } from '../src/components/layout/AppLayout';
import { FolderSidebar } from '../src/components/vault/FolderSidebar';
import { VaultItemDetail } from '../src/components/vault/VaultItemDetail';
import { VaultList } from '../src/components/vault/VaultList';

// Import OnboardingGuide from the REAL module (unmock for its own tests)
// We use a dynamic import trick: import the actual component for standalone tests
// and define a helper that renders the real implementation.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement, { route = '/' } = {}) {
  return render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>);
}

function makeDecryptedItem(
  overrides: Partial<{
    id: string;
    name: string;
    itemType: 'login' | 'secret' | 'note' | 'card' | 'identity';
    favorite: boolean;
    tags: string[];
    folderId: string;
    data: Record<string, unknown>;
  }> = {},
) {
  const now = new Date().toISOString();
  const id = overrides.id ?? 'item-1';
  return {
    id,
    itemType: overrides.itemType ?? ('login' as const),
    name: overrides.name ?? 'Test Item',
    favorite: overrides.favorite ?? false,
    tags: overrides.tags ?? [],
    folderId: overrides.folderId,
    data: overrides.data ?? {
      username: 'user@example.com',
      password: 'secret123',
      uris: [{ uri: 'https://example.com', match: 'domain' }],
      totp: '',
      notes: '',
      customFields: [],
    },
    searchHash: 'abc',
    createdAt: now,
    updatedAt: now,
    _raw: {
      _id: id,
      userId: 'u1',
      itemType: overrides.itemType ?? 'login',
      encryptedData: 'enc',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: overrides.tags ?? [],
      favorite: overrides.favorite ?? false,
      passwordHistory: [],
      createdAt: now,
      updatedAt: now,
    },
  };
}

// ==========================================================================
// 1 - NotFoundPage
// ==========================================================================

describe('NotFoundPage', () => {
  it('renders the 404 heading', () => {
    renderWithRouter(<NotFoundPage />);
    expect(screen.getByText('404')).toBeInTheDocument();
  });

  it('renders the "Page Not Found" text', () => {
    renderWithRouter(<NotFoundPage />);
    expect(screen.getByText('Page Not Found')).toBeInTheDocument();
  });

  it('renders a description message', () => {
    renderWithRouter(<NotFoundPage />);
    expect(
      screen.getByText('The page you are looking for does not exist or has been moved.'),
    ).toBeInTheDocument();
  });

  it('has a link pointing to /login with "Back to Login" text when unauthenticated', () => {
    useAuthStore.setState({ isAuthenticated: false });
    renderWithRouter(<NotFoundPage />);
    const link = screen.getByRole('link', { name: /back to login/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute('href', '/login');
  });

  it('has a link pointing to /vault with "Back to Vault" text when authenticated', () => {
    useAuthStore.setState({ isAuthenticated: true });
    renderWithRouter(<NotFoundPage />);
    const link = screen.getByRole('link', { name: /back to vault/i });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute('href', '/vault');
  });
});

// ==========================================================================
// 2 - ProtectedRoute
// ==========================================================================

describe('ProtectedRoute', () => {
  beforeEach(() => {
    useAuthStore.setState({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLocked: false,
      vaultKey: null,
      mek: null,
      encryptedVaultKeyData: null,
      twoFactorRequired: false,
      tempToken: null,
    });
  });

  it('redirects to /login when not authenticated', () => {
    useAuthStore.setState({ isAuthenticated: false, isLocked: false });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected Content</div>
              </ProtectedRoute>
            }
          />
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('Login Page')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('shows UnlockScreen when authenticated but locked', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: true,
      user: { userId: 'u1', email: 'test@example.com' },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected Content</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByTestId('unlock-screen')).toBeInTheDocument();
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('renders children when authenticated and not locked', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      accessToken: 'mock-token',
      user: { userId: 'u1', email: 'test@example.com' },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected Content</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('renders Outlet when no children are provided', () => {
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      accessToken: 'mock-token',
      user: { userId: 'u1', email: 'test@example.com' },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route element={<ProtectedRoute />}>
            <Route path="/vault" element={<div>Outlet Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('Outlet Content')).toBeInTheDocument();
  });

  it('shows loading state and refreshes token when authenticated without accessToken', async () => {
    const { refreshTokenApi } = (await import('../src/services/api/authApi')) as {
      refreshTokenApi: ReturnType<typeof vi.fn>;
    };
    refreshTokenApi.mockResolvedValueOnce({
      data: { success: true, data: { accessToken: 'new-token' } },
    });

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      accessToken: null,
      user: { userId: 'u1', email: 'test@example.com' },
    });

    const { container } = render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected Content</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    // Should show loading spinner initially
    expect(container.querySelector('.animate-spin')).toBeTruthy();
    expect(refreshTokenApi).toHaveBeenCalled();

    // Let the async refresh settle inside act() so the post-resolution state
    // updates (setAccessToken + setIsRefreshing) are flushed and the protected
    // children render -- otherwise the update lands outside act() and React
    // warns about an un-wrapped update after the test completes.
    await screen.findByText('Protected Content');
  });

  it('logs out when token refresh fails after page reload', async () => {
    const { refreshTokenApi } = (await import('../src/services/api/authApi')) as {
      refreshTokenApi: ReturnType<typeof vi.fn>;
    };
    refreshTokenApi.mockRejectedValueOnce(new Error('refresh failed'));

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      accessToken: null,
      user: { userId: 'u1', email: 'test@example.com' },
    });

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <Routes>
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <div>Protected Content</div>
              </ProtectedRoute>
            }
          />
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    // The refresh fails and triggers logout
    expect(refreshTokenApi).toHaveBeenCalled();

    // Await the resulting logout + redirect so the floating async (which clears
    // auth state and calls offlineCache.setUser during teardown) settles inside
    // act() and the navigation to /login completes before the test ends.
    await screen.findByText('Login Page');
  });
});

// ==========================================================================
// 3 - OnboardingGuide
// ==========================================================================

// For OnboardingGuide we need to import the REAL implementation (not the mock
// used by AppLayout). We dynamically require it to bypass the module-level mock.
describe('OnboardingGuide', () => {
  let OnboardingGuideReal: React.ComponentType;

  beforeEach(async () => {
    localStorage.clear();
    // Use importActual to get the real module instead of the mock
    const mod = await vi.importActual<{ OnboardingGuide: React.ComponentType }>(
      '../src/components/layout/OnboardingGuide',
    );
    OnboardingGuideReal = mod.OnboardingGuide;
  });

  it('shows the first step on first visit (no localStorage flag)', () => {
    render(<OnboardingGuideReal />);
    expect(screen.getByText('Welcome to H-Vault')).toBeInTheDocument();
  });

  it('does not show when localStorage flag is already set', () => {
    localStorage.setItem('hvault_onboarding_completed', 'true');
    render(<OnboardingGuideReal />);
    expect(screen.queryByText('Welcome to H-Vault')).not.toBeInTheDocument();
  });

  it('navigates to the next step when Next is clicked', () => {
    render(<OnboardingGuideReal />);
    expect(screen.getByText('Welcome to H-Vault')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Next'));
    expect(screen.getByText('Zero-Knowledge Architecture')).toBeInTheDocument();
  });

  it('navigates back when Back is clicked', () => {
    render(<OnboardingGuideReal />);
    // Go forward
    fireEvent.click(screen.getByText('Next'));
    expect(screen.getByText('Zero-Knowledge Architecture')).toBeInTheDocument();

    // Go back
    fireEvent.click(screen.getByText('Back'));
    expect(screen.getByText('Welcome to H-Vault')).toBeInTheDocument();
  });

  it('closes and sets localStorage flag when Close is clicked', () => {
    render(<OnboardingGuideReal />);
    expect(screen.getByText('Welcome to H-Vault')).toBeInTheDocument();

    const closeButton = screen.getByLabelText('Close onboarding');
    fireEvent.click(closeButton);

    expect(screen.queryByText('Welcome to H-Vault')).not.toBeInTheDocument();
    expect(localStorage.getItem('hvault_onboarding_completed')).toBe('true');
  });

  it('shows "Get Started" on the last step and closes on click', () => {
    render(<OnboardingGuideReal />);
    // Navigate to the last step (5 steps total: indices 0-4)
    for (let i = 0; i < 4; i++) {
      fireEvent.click(screen.getByText(i < 3 ? 'Next' : 'Next'));
    }
    expect(screen.getByText("You're All Set!")).toBeInTheDocument();
    expect(screen.getByText('Get Started')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Get Started'));
    expect(screen.queryByText("You're All Set!")).not.toBeInTheDocument();
    expect(localStorage.getItem('hvault_onboarding_completed')).toBe('true');
  });
});

// ==========================================================================
// 4 - AppLayout
// ==========================================================================

describe('AppLayout', () => {
  beforeEach(() => {
    localStorage.clear();
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      user: { userId: 'u1', email: 'test@example.com' },
      accessToken: 'token',
      vaultKey: null,
      mek: null,
    });
    vi.mocked(isStorageDegraded).mockReturnValue(false);
  });

  function renderAppLayout(route = '/vault') {
    return render(
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/vault" element={<div>Vault Content</div>} />
            <Route path="/generator" element={<div>Generator Content</div>} />
            <Route path="/settings" element={<div>Settings Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
  }

  it('renders navigation links', () => {
    renderAppLayout();

    expect(screen.getByText('Vault')).toBeInTheDocument();
    expect(screen.getByText('Password Generator')).toBeInTheDocument();
    expect(screen.getByText('Vault Health')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('displays the user email exactly once', () => {
    renderAppLayout();

    const emailElements = screen.getAllByText('test@example.com');
    expect(emailElements).toHaveLength(1);
  });

  it('renders the Lock Vault button', () => {
    renderAppLayout();
    expect(screen.getByText('Lock Vault')).toBeInTheDocument();
  });

  it('renders the Logout button', () => {
    renderAppLayout();
    expect(screen.getByText('Logout')).toBeInTheDocument();
  });

  it('shows the online indicator by default', () => {
    renderAppLayout();
    expect(screen.getByText('Online')).toBeInTheDocument();
  });

  it('shows degraded storage warning when isStorageDegraded returns true', () => {
    vi.mocked(isStorageDegraded).mockReturnValue(true);
    renderAppLayout();
    expect(screen.getByText(/does not support secure storage/i)).toBeInTheDocument();
  });

  it('does not show degraded storage warning when isStorageDegraded returns false', () => {
    vi.mocked(isStorageDegraded).mockReturnValue(false);
    renderAppLayout();
    expect(screen.queryByText(/does not support secure storage/i)).not.toBeInTheDocument();
  });

  it('renders the Outlet child content', () => {
    renderAppLayout('/vault');
    expect(screen.getByText('Vault Content')).toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Collapsible sidebar
  // -----------------------------------------------------------------------

  describe('Collapsible sidebar', () => {
    beforeEach(() => {
      useUIStore.setState({ sidebarCollapsed: false });
    });

    it('renders the sidebar collapse toggle button with correct aria-label', () => {
      renderAppLayout();
      const toggleBtn = screen.getByLabelText('Collapse sidebar');
      expect(toggleBtn).toBeInTheDocument();
    });

    it('hides navigation labels when sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      // When collapsed and not hovered, labels have opacity-0 class
      const vaultLabel = screen.getByText('Vault');
      expect(vaultLabel.className).toContain('opacity-0');
      const generatorLabel = screen.getByText('Password Generator');
      expect(generatorLabel.className).toContain('opacity-0');
      const settingsLabel = screen.getByText('Settings');
      expect(settingsLabel.className).toContain('opacity-0');
    });

    it('hides user email when sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      const emailContainer = screen
        .getByText('test@example.com')
        .closest('div[class*="transition-opacity"]')!;
      expect(emailContainer.className).toContain('opacity-0');
    });

    it('hides Lock Vault and Logout text labels when sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      // Button text is visually hidden with opacity-0 when collapsed
      const lockLabel = screen.getByText('Lock Vault');
      expect(lockLabel.className).toContain('opacity-0');
      const logoutLabel = screen.getByText('Logout');
      expect(logoutLabel.className).toContain('opacity-0');
    });

    it('shows Expand sidebar label when sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      const expandBtn = screen.getByLabelText('Expand sidebar');
      expect(expandBtn).toBeInTheDocument();
    });

    it('toggles sidebar collapsed state when toggle button is clicked', () => {
      renderAppLayout();

      expect(useUIStore.getState().sidebarCollapsed).toBe(false);

      const toggleBtn = screen.getByLabelText('Collapse sidebar');
      fireEvent.click(toggleBtn);

      expect(useUIStore.getState().sidebarCollapsed).toBe(true);
    });

    it('shows navigation labels when sidebar is expanded (not collapsed)', () => {
      useUIStore.setState({ sidebarCollapsed: false });
      renderAppLayout();

      expect(screen.getByText('Vault')).toBeInTheDocument();
      expect(screen.getByText('Password Generator')).toBeInTheDocument();
      expect(screen.getByText('Settings')).toBeInTheDocument();
      expect(screen.getByText('Lock Vault')).toBeInTheDocument();
      expect(screen.getByText('Logout')).toBeInTheDocument();
    });

    it('shows H-Vault branding text when sidebar is expanded', () => {
      useUIStore.setState({ sidebarCollapsed: false });
      renderAppLayout();

      expect(screen.getByText('H-Vault')).toBeInTheDocument();
    });

    it('hides H-Vault branding text when sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      const branding = screen.getByText('H-Vault');
      expect(branding.className).toContain('opacity-0');
    });

    it('expands sidebar temporarily on hover when collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      // Before hover: labels have opacity-0
      const vaultLabel = screen.getByText('Vault');
      expect(vaultLabel.className).toContain('opacity-0');

      // Simulate mouseEnter on the sidebar
      const sidebar = screen.getByLabelText('Expand sidebar').closest('aside')!;
      fireEvent.mouseEnter(sidebar);

      // After hover: labels should have opacity-100
      expect(vaultLabel.className).toContain('opacity-100');
      const generatorLabel = screen.getByText('Password Generator');
      expect(generatorLabel.className).toContain('opacity-100');
    });

    it('collapses sidebar again on mouseLeave when collapsed mode is on', () => {
      useUIStore.setState({ sidebarCollapsed: true });
      renderAppLayout();

      const sidebar = screen.getByLabelText('Expand sidebar').closest('aside')!;
      const vaultLabel = screen.getByText('Vault');

      // Hover to expand
      fireEvent.mouseEnter(sidebar);
      expect(vaultLabel.className).toContain('opacity-100');

      // Leave to collapse again
      fireEvent.mouseLeave(sidebar);
      expect(vaultLabel.className).toContain('opacity-0');
    });

    it('shows Online indicator text only when expanded', () => {
      useUIStore.setState({ sidebarCollapsed: false });
      renderAppLayout();

      const onlineText = screen.getByText('Online');
      expect(onlineText.className).toContain('opacity-100');

      // Toggle to collapsed
      fireEvent.click(screen.getByLabelText('Collapse sidebar'));
      expect(onlineText.className).toContain('opacity-0');
    });
  });
});

// ==========================================================================
// 5 - FolderSidebar
// ==========================================================================

describe('FolderSidebar', () => {
  beforeEach(() => {
    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
      selectedFolder: null,
      selectedType: null,
      showFavorites: false,
      showTrash: false,
      searchQuery: '',
      sortBy: 'name',
      sortOrder: 'asc',
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });
  });

  it('renders "All Items" button', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('All Items')).toBeInTheDocument();
  });

  it('renders "Favorites" button', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('Favorites')).toBeInTheDocument();
  });

  it('renders "Trash" button', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('Trash')).toBeInTheDocument();
  });

  it('renders type filter buttons', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('Logins')).toBeInTheDocument();
    expect(screen.getByText('Secrets')).toBeInTheDocument();
    expect(screen.getByText('Notes')).toBeInTheDocument();
    expect(screen.getByText('Cards')).toBeInTheDocument();
    expect(screen.getByText('Identities')).toBeInTheDocument();
  });

  it('renders "Folders" heading and "Create folder" button', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('Folders')).toBeInTheDocument();
    expect(screen.getByLabelText('Create folder')).toBeInTheDocument();
  });

  it('shows "No folders yet" when there are no folders', () => {
    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('No folders yet')).toBeInTheDocument();
  });

  it('opens the "New Folder" dialog when the create button is clicked', () => {
    renderWithRouter(<FolderSidebar />);

    fireEvent.click(screen.getByLabelText('Create folder'));

    expect(screen.getByText('New Folder')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Folder name')).toBeInTheDocument();
    expect(screen.getByText('Create')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });

  it('renders folder names when folders exist', () => {
    const now = new Date().toISOString();
    useVaultStore.setState({
      folders: [
        {
          id: 'f1',
          name: 'Work',
          sortOrder: 0,
          createdAt: now,
          updatedAt: now,
          _raw: {
            _id: 'f1',
            userId: 'u1',
            encryptedName: 'enc',
            nameIv: 'iv',
            nameTag: 'tag',
            sortOrder: 0,
            createdAt: now,
            updatedAt: now,
          },
        },
        {
          id: 'f2',
          name: 'Personal',
          sortOrder: 1,
          createdAt: now,
          updatedAt: now,
          _raw: {
            _id: 'f2',
            userId: 'u1',
            encryptedName: 'enc',
            nameIv: 'iv',
            nameTag: 'tag',
            sortOrder: 1,
            createdAt: now,
            updatedAt: now,
          },
        },
      ],
    });

    renderWithRouter(<FolderSidebar />);
    expect(screen.getByText('Work')).toBeInTheDocument();
    expect(screen.getByText('Personal')).toBeInTheDocument();
    expect(screen.queryByText('No folders yet')).not.toBeInTheDocument();
  });

  it('shows item counts next to type filters', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', itemType: 'login', name: 'Login 1' }),
        makeDecryptedItem({ id: 'i2', itemType: 'login', name: 'Login 2' }),
        makeDecryptedItem({ id: 'i3', itemType: 'note', name: 'Note 1' }),
      ] as never[],
    });

    renderWithRouter(<FolderSidebar />);
    // All Items count = 3
    expect(screen.getByText('3')).toBeInTheDocument();
    // Logins count = 2
    expect(screen.getByText('2')).toBeInTheDocument();
  });
});

// ==========================================================================
// 6 - VaultItemDetail
// ==========================================================================

describe('VaultItemDetail', () => {
  const onEdit = vi.fn();

  beforeEach(() => {
    onEdit.mockClear();
    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
      selectedFolder: null,
      selectedType: null,
      showFavorites: false,
      showTrash: false,
    });
  });

  it('displays the item name', () => {
    const item = makeDecryptedItem({ name: 'My Login Item' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('My Login Item')).toBeInTheDocument();
  });

  it('displays "Unnamed item" when name is empty', () => {
    const item = makeDecryptedItem({ name: '' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Unnamed item')).toBeInTheDocument();
  });

  it('renders Edit, Favorite, and Delete buttons for non-trashed items', () => {
    const item = makeDecryptedItem({ name: 'Item 1' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Edit')).toBeInTheDocument();
    expect(screen.getByText('Favorite')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
  });

  it('renders Restore and Delete Forever buttons for trashed items', () => {
    const item = makeDecryptedItem({ name: 'Trashed Item' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={true} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Restore')).toBeInTheDocument();
    expect(screen.getByText('Delete Forever')).toBeInTheDocument();
    expect(screen.queryByText('Edit')).not.toBeInTheDocument();
  });

  it('shows "Favorited" text when item is a favorite', () => {
    const item = makeDecryptedItem({ name: 'Fav Item', favorite: true });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Favorited')).toBeInTheDocument();
  });

  it('calls onEdit when Edit button is clicked', () => {
    const item = makeDecryptedItem({ name: 'Item 1' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText('Edit'));
    expect(onEdit).toHaveBeenCalledOnce();
  });

  it('renders login-specific fields (username label)', () => {
    const item = makeDecryptedItem({
      name: 'Login Item',
      itemType: 'login',
      data: {
        username: 'testuser',
        password: 'pass123',
        uris: [],
        totp: '',
        notes: '',
        customFields: [],
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Username')).toBeInTheDocument();
    expect(screen.getByText('Password')).toBeInTheDocument();
  });

  it('renders note content for note items', () => {
    const item = makeDecryptedItem({
      name: 'My Note',
      itemType: 'note',
      data: {
        content: 'This is note content',
        format: 'plaintext',
      },
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('This is note content')).toBeInTheDocument();
  });

  it('renders tags when present', () => {
    const item = makeDecryptedItem({
      name: 'Tagged Item',
      tags: ['work', 'important'],
    });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByText('work')).toBeInTheDocument();
    expect(screen.getByText('important')).toBeInTheDocument();
  });

  it('renders the back to vault button', () => {
    const item = makeDecryptedItem({ name: 'Item' });

    render(
      <MemoryRouter>
        <VaultItemDetail item={item as never} onEdit={onEdit} />
      </MemoryRouter>,
    );

    expect(screen.getByLabelText('Back to vault')).toBeInTheDocument();
  });
});

// ==========================================================================
// 7 - VaultList
// ==========================================================================

describe('VaultList', () => {
  const onCreateNew = vi.fn();

  beforeEach(() => {
    onCreateNew.mockClear();
    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
      selectedFolder: null,
      selectedType: null,
      showFavorites: false,
      showTrash: false,
      searchQuery: '',
      sortBy: 'name',
      sortOrder: 'asc',
      loading: false,
      itemsLoading: false,
      trashLoading: false,
    });
  });

  it('renders empty state with "No items found" when there are no items', () => {
    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('No items found')).toBeInTheDocument();
    expect(screen.getByText('Create Item')).toBeInTheDocument();
  });

  it('renders "Trash is empty" when in trash view with no items', () => {
    useVaultStore.setState({ showTrash: true });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Trash is empty')).toBeInTheDocument();
  });

  it('calls onCreateNew when "Create Item" is clicked in empty state', () => {
    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText('Create Item'));
    expect(onCreateNew).toHaveBeenCalledOnce();
  });

  it('renders items when present', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'Github Login', itemType: 'login' }),
        makeDecryptedItem({ id: 'i2', name: 'API Secret', itemType: 'secret' }),
      ] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Github Login')).toBeInTheDocument();
    expect(screen.getByText('API Secret')).toBeInTheDocument();
  });

  it('renders type badges for items', () => {
    useVaultStore.setState({
      items: [
        makeDecryptedItem({ id: 'i1', name: 'My Login', itemType: 'login' }),
        makeDecryptedItem({ id: 'i2', name: 'My Note', itemType: 'note' }),
      ] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByText('Login')).toBeInTheDocument();
    expect(screen.getByText('Note')).toBeInTheDocument();
  });

  it('shows the floating "Create new item" button when not in trash', () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item 1' })] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    expect(screen.getByLabelText('Create new item')).toBeInTheDocument();
  });

  it('renders sort controls', () => {
    useVaultStore.setState({
      items: [makeDecryptedItem({ id: 'i1', name: 'Item 1' })] as never[],
    });

    render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    // Default sort is 'name' so the button should display 'Name'
    expect(screen.getByText('Name')).toBeInTheDocument();
  });

  it('shows loading skeleton when loading is true', () => {
    useVaultStore.setState({ loading: true, itemsLoading: true });

    const { container } = render(
      <MemoryRouter>
        <VaultList onCreateNew={onCreateNew} />
      </MemoryRouter>,
    );

    // The skeleton renders divs with animate-pulse class
    const pulsingElements = container.querySelectorAll('.animate-pulse');
    expect(pulsingElements.length).toBeGreaterThan(0);
  });
});

// ==========================================================================
// PublicOnlyRoute
// ==========================================================================

describe('PublicOnlyRoute', () => {
  beforeEach(() => {
    useAuthStore.setState({
      isAuthenticated: false,
      isLocked: false,
      accessToken: null,
    });
  });

  it('renders outlet for unauthenticated users', () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<div data-testid="login-page">Login</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByTestId('login-page')).toBeInTheDocument();
  });

  it('redirects authenticated users to /vault', () => {
    useAuthStore.setState({ isAuthenticated: true, accessToken: 'token' });

    render(
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<div data-testid="login-page">Login</div>} />
          </Route>
          <Route path="/vault" element={<div data-testid="vault-page">Vault</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();
    expect(screen.getByTestId('vault-page')).toBeInTheDocument();
  });
});
