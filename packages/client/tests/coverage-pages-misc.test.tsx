/**
 * Behavior tests for the "misc" pages whose interactive/error branches were
 * previously unexercised:
 *
 * - SessionsPage : revoke (success + failure), revoke-all (success + failure),
 *                  retry after load failure, unsuccessful envelope,
 *                  back navigation, user-agent -> browser/OS/device mapping.
 * - AuditLogPage : action filter (request shape + page reset), pagination
 *                  (request shape + button enablement), unknown-action label
 *                  fallback, retry after failure, unsuccessful envelope.
 * - VaultPage    : mount-fetch failure toasts, decryption-failure event toast,
 *                  trash-view refetch, Ctrl+N shortcut, dialog defaults from
 *                  the active filters, save -> close + refetch, mobile overlay.
 * - VerifyEmailPage / UnlockAccountPage : default-message branch, API error
 *                  message surfacing, single-call guard under StrictMode.
 * - VaultItemPage: "Back to Vault" navigation from the not-found state.
 *
 * Toasts are asserted through the REAL ToastProvider so the assertions are on
 * what the user actually sees, not on a spy.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom';
import React, { StrictMode } from 'react';

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
// Hoisted API mocks
// ---------------------------------------------------------------------------

const {
  mockListSessionsApi,
  mockRevokeSessionApi,
  mockLogoutAllApi,
  mockGetAuditLogApi,
  mockVerifyEmailApi,
  mockUnlockAccountApi,
} = vi.hoisted(() => ({
  mockListSessionsApi: vi.fn(),
  mockRevokeSessionApi: vi.fn(),
  mockLogoutAllApi: vi.fn(),
  mockGetAuditLogApi: vi.fn(),
  mockVerifyEmailApi: vi.fn(),
  mockUnlockAccountApi: vi.fn(),
}));

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
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
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

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: vi.fn(),
  updateSettingsApi: vi.fn(),
  listSessionsApi: (...args: unknown[]) => mockListSessionsApi(...args),
  revokeSessionApi: (...args: unknown[]) => mockRevokeSessionApi(...args),
  getAuditLogApi: (...args: unknown[]) => mockGetAuditLogApi(...args),
  checkBreachApi: vi.fn(),
  checkBreachBatchApi: vi.fn(),
}));

vi.mock('../src/services/api/authApi', () => ({
  logoutAllApi: (...args: unknown[]) => mockLogoutAllApi(...args),
  verifyEmailApi: (...args: unknown[]) => mockVerifyEmailApi(...args),
  unlockAccountApi: (...args: unknown[]) => mockUnlockAccountApi(...args),
  logoutApi: vi.fn(),
  lockApi: vi.fn(),
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

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: vi.fn().mockReturnValue({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
  clearSettingsCache: vi.fn(),
  onSettingsInvalidated: vi.fn().mockReturnValue(() => {}),
}));

// The create-item form itself is exhaustively tested elsewhere; here we only
// care that VaultPage mounts it with the right defaults and reacts to it.
vi.mock('../src/components/vault/VaultItemForm', () => ({
  VaultItemForm: ({
    defaultType,
    defaultFolderId,
    onSaved,
    onCancel,
  }: {
    defaultType?: string;
    defaultFolderId?: string;
    onSaved?: () => void;
    onCancel?: () => void;
  }) =>
    React.createElement(
      'div',
      { 'data-testid': 'vault-item-form' },
      React.createElement('span', { 'data-testid': 'form-default-type' }, defaultType ?? 'none'),
      React.createElement(
        'span',
        { 'data-testid': 'form-default-folder' },
        defaultFolderId ?? 'none',
      ),
      React.createElement('button', { type: 'button', onClick: onSaved }, 'Save Form'),
      React.createElement('button', { type: 'button', onClick: onCancel }, 'Cancel Form'),
    ),
}));

// ---------------------------------------------------------------------------
// Imports AFTER mocks
// ---------------------------------------------------------------------------

import { ToastProvider } from '../src/components/ui/Toast';
import { useVaultStore } from '../src/stores/vaultStore';
import SessionsPage from '../src/pages/SessionsPage';
import AuditLogPage from '../src/pages/AuditLogPage';
import VaultPage from '../src/pages/VaultPage';
import VaultItemPage from '../src/pages/VaultItemPage';
import VerifyEmailPage from '../src/pages/VerifyEmailPage';
import UnlockAccountPage from '../src/pages/UnlockAccountPage';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname}</div>;
}

/** Renders `ui` inside a real ToastProvider + router, with a location probe. */
function renderPage(ui: React.ReactElement, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <ToastProvider>
        {ui}
        <LocationProbe />
      </ToastProvider>
    </MemoryRouter>,
  );
}

interface SessionFixture {
  _id: string;
  current: boolean;
  deviceInfo: { userAgent: string; ip: string };
  createdAt: string;
}

function session(overrides: Partial<SessionFixture> = {}): SessionFixture {
  return {
    _id: overrides._id ?? 's1',
    current: overrides.current ?? false,
    deviceInfo: overrides.deviceInfo ?? {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120',
      ip: '1.2.3.4',
    },
    createdAt: overrides.createdAt ?? '2025-01-01T00:00:00.000Z',
  };
}

function sessionsOk(data: SessionFixture[]) {
  return { data: { success: true, data } };
}

function auditOk(
  entries: {
    _id: string;
    action: string;
    ipAddress: string;
    userAgent: string;
    timestamp: string;
  }[],
  totalPages = 1,
) {
  return {
    data: {
      success: true,
      data: entries,
      pagination: { page: 1, limit: 20, total: entries.length, totalPages },
    },
  };
}

const auditEntry = {
  _id: 'a1',
  action: 'login',
  ipAddress: '10.0.0.9',
  userAgent: 'Chrome/120',
  timestamp: '2025-06-01T12:00:00.000Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  // mockClear() does not drain a queued `mockResolvedValueOnce`, so reset the
  // API doubles fully to keep tests independent.
  for (const m of [
    mockListSessionsApi,
    mockRevokeSessionApi,
    mockLogoutAllApi,
    mockGetAuditLogApi,
    mockVerifyEmailApi,
    mockUnlockAccountApi,
  ]) {
    m.mockReset();
  }
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

afterEach(() => {
  vi.restoreAllMocks();
});

// ===========================================================================
// SessionsPage
// ===========================================================================

describe('SessionsPage - revoking a single session', () => {
  it('removes the revoked row from the list and confirms with a success toast', async () => {
    mockListSessionsApi.mockResolvedValue(
      sessionsOk([
        session({ _id: 's-current', current: true }),
        session({
          _id: 's-other',
          deviceInfo: { userAgent: 'Mozilla/5.0 (X11; Linux) Firefox/130', ip: '9.9.9.9' },
        }),
      ]),
    );
    mockRevokeSessionApi.mockResolvedValue({ data: { success: true, data: null } });

    renderPage(<SessionsPage />);

    await screen.findByText('Firefox on Linux');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
    });

    expect(mockRevokeSessionApi).toHaveBeenCalledWith('s-other');
    await waitFor(() => {
      expect(screen.queryByText('Firefox on Linux')).not.toBeInTheDocument();
    });
    expect(await screen.findByText('Session revoked')).toBeInTheDocument();
    // The current session survives.
    expect(screen.getByText('Current')).toBeInTheDocument();
  });

  it('keeps the session in the list and shows an error toast when revocation fails', async () => {
    mockListSessionsApi.mockResolvedValue(
      sessionsOk([
        session({ _id: 's-current', current: true }),
        session({
          _id: 's-other',
          deviceInfo: { userAgent: 'Mozilla/5.0 (Macintosh; Mac OS X) Safari/17', ip: '9.9.9.9' },
        }),
      ]),
    );
    mockRevokeSessionApi.mockRejectedValue(new Error('boom'));

    renderPage(<SessionsPage />);
    await screen.findByText('Safari on macOS');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }));
    });

    expect(await screen.findByText('Failed to revoke session')).toBeInTheDocument();
    // The row must NOT be optimistically removed on failure.
    expect(screen.getByText('Safari on macOS')).toBeInTheDocument();
    // And the button becomes usable again (the in-flight lock is released).
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /^revoke$/i })).not.toBeDisabled();
    });
  });
});

describe('SessionsPage - revoking all other sessions', () => {
  it('calls logout-all and re-fetches, leaving only the current session', async () => {
    mockListSessionsApi
      .mockResolvedValueOnce(
        sessionsOk([
          session({ _id: 's-current', current: true }),
          session({
            _id: 's-other',
            deviceInfo: { userAgent: 'Mozilla/5.0 (Android 14; Mobile) Chrome/120', ip: '5.5.5.5' },
          }),
        ]),
      )
      .mockResolvedValueOnce(sessionsOk([session({ _id: 's-current', current: true })]));
    mockLogoutAllApi.mockResolvedValue({ data: { success: true, data: null } });

    renderPage(<SessionsPage />);
    await screen.findByText('Chrome on Android');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /revoke all other sessions/i }));
    });

    expect(mockLogoutAllApi).toHaveBeenCalledTimes(1);
    expect(await screen.findByText('All other sessions revoked')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.queryByText('Chrome on Android')).not.toBeInTheDocument();
    });
    // Only one session left, so the bulk-revoke control disappears.
    expect(
      screen.queryByRole('button', { name: /revoke all other sessions/i }),
    ).not.toBeInTheDocument();
    expect(mockListSessionsApi).toHaveBeenCalledTimes(2);
  });

  it('shows an error toast and does not re-fetch when logout-all fails', async () => {
    mockListSessionsApi.mockResolvedValue(
      sessionsOk([session({ _id: 's-current', current: true }), session({ _id: 's-other' })]),
    );
    mockLogoutAllApi.mockRejectedValue(new Error('nope'));

    renderPage(<SessionsPage />);
    await screen.findByRole('button', { name: /revoke all other sessions/i });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /revoke all other sessions/i }));
    });

    expect(await screen.findByText('Failed to revoke sessions')).toBeInTheDocument();
    // Failure must not trigger the success re-fetch.
    expect(mockListSessionsApi).toHaveBeenCalledTimes(1);
    // Both sessions are still listed.
    expect(screen.getByText('Current')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^revoke$/i })).toBeInTheDocument();
  });
});

describe('SessionsPage - load failures', () => {
  it('renders the error state when the API resolves with success:false', async () => {
    mockListSessionsApi.mockResolvedValue({ data: { success: false, error: { code: 'X' } } });

    renderPage(<SessionsPage />);

    expect(await screen.findByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.getAllByText('Failed to load sessions').length).toBeGreaterThan(0);
    expect(screen.queryByText('No active sessions found.')).not.toBeInTheDocument();
  });

  it('recovers and renders the sessions when Retry succeeds', async () => {
    mockListSessionsApi
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce(sessionsOk([session({ _id: 's-current', current: true })]));

    renderPage(<SessionsPage />);
    const retry = await screen.findByRole('button', { name: /retry/i });

    await act(async () => {
      fireEvent.click(retry);
    });

    await waitFor(() => {
      expect(screen.getByText('Chrome on Windows')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });
});

describe('SessionsPage - device rendering', () => {
  it('maps user agents to browser + OS labels and shows the IP and start date', async () => {
    mockListSessionsApi.mockResolvedValue(
      sessionsOk([
        session({
          _id: 's-edge',
          deviceInfo: {
            // Edge UAs also contain "Chrome" — Edge must win.
            userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537 Edg/120',
            ip: '203.0.113.7',
          },
          createdAt: '2025-03-04T00:00:00.000Z',
        }),
        session({
          _id: 's-opera',
          deviceInfo: { userAgent: 'Opera/9.8 (X11; Linux x86_64)', ip: '198.51.100.2' },
        }),
        session({
          _id: 's-unknown',
          deviceInfo: { userAgent: 'curl/8.5.0', ip: '192.0.2.3' },
        }),
      ]),
    );

    renderPage(<SessionsPage />);

    expect(await screen.findByText('Edge on Windows')).toBeInTheDocument();
    expect(screen.getByText('Opera on Linux')).toBeInTheDocument();
    expect(screen.getByText('Unknown Browser on Unknown OS')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument();
    expect(
      screen.getByText(`Since ${new Date('2025-03-04T00:00:00.000Z').toLocaleDateString()}`),
    ).toBeInTheDocument();
  });

  it('navigates back to /settings from the back button', async () => {
    mockListSessionsApi.mockResolvedValue(sessionsOk([]));

    renderPage(<SessionsPage />, '/settings/sessions');
    await screen.findByText('No active sessions found.');

    fireEvent.click(screen.getByLabelText('Back to settings'));

    expect(screen.getByTestId('location')).toHaveTextContent('/settings');
  });
});

// ===========================================================================
// AuditLogPage
// ===========================================================================

describe('AuditLogPage - filtering', () => {
  it('requests only the selected action and resets to page 1', async () => {
    mockGetAuditLogApi.mockResolvedValue(auditOk([auditEntry], 3));

    renderPage(<AuditLogPage />);
    await screen.findByRole('table');

    // Go to page 2 first so we can prove the filter resets it.
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /next/i }));
    });
    await waitFor(() => {
      expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    });
    expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({ page: 2, limit: 20 });

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Filter by action type'), {
        target: { value: 'item_delete' },
      });
    });

    await waitFor(() => {
      expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({
        page: 1,
        limit: 20,
        action: 'item_delete',
      });
    });
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
  });

  it('omits the action param when the filter is cleared back to "All Actions"', async () => {
    mockGetAuditLogApi.mockResolvedValue(auditOk([auditEntry], 1));

    renderPage(<AuditLogPage />);
    await screen.findByRole('table');

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Filter by action type'), {
        target: { value: 'export' },
      });
    });
    await waitFor(() => {
      expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({ page: 1, limit: 20, action: 'export' });
    });

    await act(async () => {
      fireEvent.change(screen.getByLabelText('Filter by action type'), { target: { value: '' } });
    });

    await waitFor(() => {
      expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({ page: 1, limit: 20 });
    });
  });
});

describe('AuditLogPage - pagination', () => {
  it('walks forward and back, clamping at both ends', async () => {
    mockGetAuditLogApi.mockResolvedValue(auditOk([auditEntry], 2));

    renderPage(<AuditLogPage />);
    await screen.findByRole('table');

    const prev = screen.getByRole('button', { name: /prev/i });
    const next = screen.getByRole('button', { name: /next/i });

    expect(prev).toBeDisabled();
    expect(next).not.toBeDisabled();

    await act(async () => {
      fireEvent.click(next);
    });
    await waitFor(() => {
      expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({ page: 2, limit: 20 });
    });
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
    // On the last page Next is clamped off, Prev becomes available.
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /prev/i })).not.toBeDisabled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /prev/i }));
    });
    await waitFor(() => {
      expect(mockGetAuditLogApi).toHaveBeenLastCalledWith({ page: 1, limit: 20 });
    });
    expect(screen.getByText('Page 1 of 2')).toBeInTheDocument();
  });
});

describe('AuditLogPage - row rendering', () => {
  it('renders the mapped label for a known action and the raw action for an unknown one', async () => {
    mockGetAuditLogApi.mockResolvedValue(
      auditOk([
        {
          _id: 'a1',
          action: 'backup_restored',
          ipAddress: '10.0.0.1',
          userAgent: 'Chrome/120',
          timestamp: '2025-06-01T12:00:00.000Z',
        },
        {
          _id: 'a2',
          // Not present in ACTION_LABELS / ACTION_COLORS -> raw fallback.
          action: 'rotation_recovery',
          ipAddress: '10.0.0.2',
          userAgent: 'Firefox/130',
          timestamp: '2025-06-02T08:30:00.000Z',
        },
      ]),
    );

    renderPage(<AuditLogPage />);

    const table = await screen.findByRole('table');
    const rows = within(table).getAllByRole('row').slice(1); // drop the header row
    expect(rows).toHaveLength(2);

    const first = within(rows[0]!);
    expect(first.getByText('Backup Restored')).toBeInTheDocument();
    expect(first.getByText('10.0.0.1')).toBeInTheDocument();
    expect(first.getByText('Chrome/120')).toBeInTheDocument();
    expect(
      first.getByText(new Date('2025-06-01T12:00:00.000Z').toLocaleString()),
    ).toBeInTheDocument();

    const second = within(rows[1]!);
    expect(second.getByText('rotation_recovery')).toBeInTheDocument();
    expect(
      second.getByText(new Date('2025-06-02T08:30:00.000Z').toLocaleString()),
    ).toBeInTheDocument();
  });
});

describe('AuditLogPage - load failures', () => {
  it('renders the error state when the API resolves with success:false', async () => {
    mockGetAuditLogApi.mockResolvedValue({ data: { success: false, error: { code: 'X' } } });

    renderPage(<AuditLogPage />);

    expect(await screen.findByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText('No audit log entries found.')).not.toBeInTheDocument();
  });

  it('renders the table after a successful Retry', async () => {
    mockGetAuditLogApi
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce(auditOk([auditEntry], 1));

    renderPage(<AuditLogPage />);
    const retry = await screen.findByRole('button', { name: /retry/i });

    await act(async () => {
      fireEvent.click(retry);
    });

    expect(await screen.findByRole('table')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('navigates back to /settings from the back button', async () => {
    mockGetAuditLogApi.mockResolvedValue(auditOk([], 1));

    renderPage(<AuditLogPage />, '/settings/audit');
    await screen.findByText('No audit log entries found.');

    fireEvent.click(screen.getByLabelText('Back to settings'));

    expect(screen.getByTestId('location')).toHaveTextContent('/settings');
  });
});

// ===========================================================================
// VaultPage
// ===========================================================================

function primeVaultStore(overrides: Record<string, unknown> = {}) {
  useVaultStore.setState({
    fetchItems: vi.fn().mockResolvedValue(undefined),
    fetchFolders: vi.fn().mockResolvedValue(undefined),
    fetchTrashItems: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as never);
}

describe('VaultPage - mount fetching', () => {
  it('toasts when the items fetch fails', async () => {
    primeVaultStore({ fetchItems: vi.fn().mockRejectedValue(new Error('down')) });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    expect(await screen.findByText('Failed to load vault items')).toBeInTheDocument();
  });

  it('toasts when the folders fetch fails', async () => {
    primeVaultStore({ fetchFolders: vi.fn().mockRejectedValue(new Error('down')) });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    expect(await screen.findByText('Failed to load folders')).toBeInTheDocument();
  });

  it('stays silent when the (non-critical) trash fetch fails', async () => {
    primeVaultStore({ fetchTrashItems: vi.fn().mockRejectedValue(new Error('down')) });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    await waitFor(() => {
      expect(screen.getByText('No items found')).toBeInTheDocument();
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('re-fetches the trash when the trash view is active', async () => {
    const fetchTrashItems = vi.fn().mockResolvedValue(undefined);
    primeVaultStore({ fetchTrashItems, showTrash: true });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    // Once from the mount effect, once from the showTrash effect.
    expect(fetchTrashItems).toHaveBeenCalledTimes(2);
  });
});

describe('VaultPage - decryption failure notifications', () => {
  it('surfaces a warning toast carrying the failure count from the store event', async () => {
    primeVaultStore();

    await act(async () => {
      renderPage(<VaultPage />);
    });

    await act(async () => {
      window.dispatchEvent(new CustomEvent('vault-decryption-failures', { detail: { count: 3 } }));
    });

    expect(await screen.findByText('3 item(s) could not be decrypted')).toBeInTheDocument();
    expect(
      screen.getByText('These items may be corrupted or encrypted with a different key.'),
    ).toBeInTheDocument();
  });

  it('stops listening after unmount', async () => {
    primeVaultStore();

    const view = await act(async () => renderPage(<VaultPage />));
    view.unmount();

    // Dispatching after unmount must not throw (listener removed).
    expect(() => {
      window.dispatchEvent(new CustomEvent('vault-decryption-failures', { detail: { count: 1 } }));
    }).not.toThrow();
    expect(screen.queryByText('1 item(s) could not be decrypted')).not.toBeInTheDocument();
  });
});

describe('VaultPage - create-item dialog', () => {
  it('opens on Ctrl+N and seeds the form with the active type and folder filters', async () => {
    primeVaultStore({ selectedType: 'note', selectedFolder: 'folder-9' });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await act(async () => {
      fireEvent.keyDown(document, { key: 'n', ctrlKey: true });
    });

    const dialog = await screen.findByRole('dialog', { name: 'Create new vault item' });
    expect(within(dialog).getByTestId('form-default-type')).toHaveTextContent('note');
    expect(within(dialog).getByTestId('form-default-folder')).toHaveTextContent('folder-9');
  });

  it('closes and re-fetches items when the form reports a save', async () => {
    const fetchItems = vi.fn().mockResolvedValue(undefined);
    primeVaultStore({ fetchItems });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create Item' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const fetchesBeforeSave = fetchItems.mock.calls.length;

    await act(async () => {
      fireEvent.click(screen.getByText('Save Form'));
    });

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(fetchItems.mock.calls.length).toBe(fetchesBeforeSave + 1);
  });

  it('closes on Escape without re-fetching', async () => {
    const fetchItems = vi.fn().mockResolvedValue(undefined);
    primeVaultStore({ fetchItems });

    await act(async () => {
      renderPage(<VaultPage />);
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create Item' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const fetchesBeforeEscape = fetchItems.mock.calls.length;

    await act(async () => {
      fireEvent.keyDown(document, { key: 'Escape' });
    });

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(fetchItems.mock.calls.length).toBe(fetchesBeforeEscape);
  });
});

describe('VaultPage - mobile sidebar', () => {
  /** The backdrop is the only `z-30` element VaultPage renders. */
  const backdrop = (container: HTMLElement) => container.querySelector('.z-30');

  async function openMobileSidebar() {
    primeVaultStore();
    const { container } = await act(async () => renderPage(<VaultPage />));
    expect(backdrop(container)).toBeNull();

    fireEvent.click(screen.getByLabelText('Open sidebar'));
    expect(backdrop(container)).not.toBeNull();
    return container;
  }

  it('dismisses the mobile sidebar when the backdrop is clicked', async () => {
    const container = await openMobileSidebar();

    fireEvent.click(backdrop(container)!);

    expect(backdrop(container)).toBeNull();
  });

  it('dismisses the mobile sidebar when Escape is pressed on the backdrop', async () => {
    const container = await openMobileSidebar();

    fireEvent.keyDown(backdrop(container)!, { key: 'Escape' });

    expect(backdrop(container)).toBeNull();
  });

  it('dismisses the mobile sidebar from the in-panel close button', async () => {
    const container = await openMobileSidebar();

    const panelClose = container.querySelector<HTMLButtonElement>(
      'aside button[aria-label="Close sidebar"]',
    );
    expect(panelClose).not.toBeNull();
    fireEvent.click(panelClose!);

    expect(backdrop(container)).toBeNull();
  });
});

// ===========================================================================
// VaultItemPage
// ===========================================================================

describe('VaultItemPage - not found', () => {
  it('navigates back to /vault from the "Back to Vault" button', async () => {
    useVaultStore.setState({
      items: [],
      trashItems: [],
      loading: false,
      fetchItems: vi.fn().mockResolvedValue(undefined),
      fetchTrashItems: vi.fn().mockResolvedValue(undefined),
    } as never);

    await act(async () => {
      render(
        <MemoryRouter initialEntries={['/vault/does-not-exist']}>
          <ToastProvider>
            <Routes>
              <Route path="/vault/:id" element={<VaultItemPage />} />
              <Route path="/vault" element={<div>Vault Home</div>} />
            </Routes>
            <LocationProbe />
          </ToastProvider>
        </MemoryRouter>,
      );
    });

    expect(screen.getByText('Item Not Found')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Back to Vault' }));
    });

    expect(screen.getByTestId('location')).toHaveTextContent('/vault');
    expect(screen.getByText('Vault Home')).toBeInTheDocument();
  });
});

// ===========================================================================
// Token pages
// ===========================================================================

describe('VerifyEmailPage', () => {
  it('falls back to a default success message when the API returns none', async () => {
    mockVerifyEmailApi.mockResolvedValue({ data: { success: true } });

    renderPage(<VerifyEmailPage />, '/verify-email?token=t1');

    expect(await screen.findByText('Email Verified')).toBeInTheDocument();
    expect(screen.getByText('Email verified successfully.')).toBeInTheDocument();
  });

  it('surfaces the server error message when verification fails', async () => {
    mockVerifyEmailApi.mockRejectedValue({
      isAxiosError: true,
      message: 'Request failed with status code 400',
      response: { data: { message: 'Verification token has expired' } },
    });

    renderPage(<VerifyEmailPage />, '/verify-email?token=expired');

    expect(await screen.findByText('Verification Failed')).toBeInTheDocument();
    expect(screen.getByText('Verification token has expired')).toBeInTheDocument();
  });

  it('verifies the token exactly once even when the effect is invoked twice', async () => {
    mockVerifyEmailApi.mockResolvedValue({ data: { success: true, message: 'ok' } });

    await act(async () => {
      render(
        <StrictMode>
          <MemoryRouter initialEntries={['/verify-email?token=t1']}>
            <VerifyEmailPage />
          </MemoryRouter>
        </StrictMode>,
      );
    });

    await screen.findByText('Email Verified');
    expect(mockVerifyEmailApi).toHaveBeenCalledTimes(1);
  });
});

describe('UnlockAccountPage', () => {
  it('falls back to a default success message when the API returns none', async () => {
    mockUnlockAccountApi.mockResolvedValue({ data: { success: true } });

    renderPage(<UnlockAccountPage />, '/unlock-account?token=t1');

    expect(await screen.findByText('Account Unlocked')).toBeInTheDocument();
    expect(
      screen.getByText('Account unlocked successfully. You can now log in.'),
    ).toBeInTheDocument();
  });

  it('surfaces the server error message when the unlock token is rejected', async () => {
    mockUnlockAccountApi.mockRejectedValue({
      isAxiosError: true,
      message: 'Request failed with status code 400',
      response: { data: { message: 'Unlock token is invalid' } },
    });

    renderPage(<UnlockAccountPage />, '/unlock-account?token=bad');

    expect(await screen.findByText('Unlock Failed')).toBeInTheDocument();
    expect(screen.getByText('Unlock token is invalid')).toBeInTheDocument();
  });

  it('unlocks exactly once even when the effect is invoked twice', async () => {
    mockUnlockAccountApi.mockResolvedValue({ data: { success: true, message: 'ok' } });

    await act(async () => {
      render(
        <StrictMode>
          <MemoryRouter initialEntries={['/unlock-account?token=t1']}>
            <UnlockAccountPage />
          </MemoryRouter>
        </StrictMode>,
      );
    });

    await screen.findByText('Account Unlocked');
    expect(mockUnlockAccountApi).toHaveBeenCalledTimes(1);
  });
});
