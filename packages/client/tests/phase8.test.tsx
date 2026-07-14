/**
 * Phase 8 tests:
 *
 * 8.1 - Boolean custom field UI in VaultItemForm (checkbox rendering and toggling)
 * 8.2 - Form label accessibility associations (htmlFor/id) in VaultItemForm
 * 8.4 - Error recovery with retry buttons in AuditLogPage and SessionsPage
 * 8.5 - Password history tracking in vaultStore
 * 8.6 - CSV import field validation in SettingsPage
 * 8.9 - Client-side unlock attempt rate limiting feedback
 * 8.10 - Accessibility fixes (context menu, overlay, checkboxes)
 * 8.11 - Loading states for download and favorite operations
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Polyfill matchMedia (needed for stores that reference it at module load)
// ---------------------------------------------------------------------------

const {
  mockGetAuditLogApi,
  mockListSessionsApi,
  mockLogoutAllApi,
  mockRevokeSessionApi,
  mockGetProfileApi,
  mockUpdateSettingsApi,
  mockImportVaultApi,
} = vi.hoisted(() => {
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

  return {
    mockGetAuditLogApi: vi.fn(),
    mockListSessionsApi: vi.fn(),
    mockLogoutAllApi: vi.fn(),
    mockRevokeSessionApi: vi.fn(),
    mockGetProfileApi: vi.fn(),
    mockUpdateSettingsApi: vi.fn(),
    mockImportVaultApi: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Mocks - VaultItemForm dependencies
// ---------------------------------------------------------------------------

const mockCreateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItemMeta = vi.fn().mockResolvedValue(undefined);

vi.mock('../src/stores/vaultStore', () => ({
  useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) => {
    const state = {
      createItem: mockCreateItem,
      updateItem: mockUpdateItem,
      updateItemMeta: mockUpdateItemMeta,
      folders: [{ id: 'folder-1', name: 'Work', sortOrder: 0, createdAt: '', updatedAt: '' }],
    };
    return selector(state);
  }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

// zxcvbn mock removed: the password generator now measures strength via exact entropy
// (src/utils/passwordEntropy.ts), so nothing in this render tree imports zxcvbn.

// ---------------------------------------------------------------------------
// Mocks - AuditLogPage and SessionsPage dependencies
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../src/services/api/userApi', () => ({
  getAuditLogApi: (...args: unknown[]) => mockGetAuditLogApi(...args),
  listSessionsApi: (...args: unknown[]) => mockListSessionsApi(...args),
  revokeSessionApi: (...args: unknown[]) => mockRevokeSessionApi(...args),
  getProfileApi: (...args: unknown[]) => mockGetProfileApi(...args),
  updateSettingsApi: (...args: unknown[]) => mockUpdateSettingsApi(...args),
  importVaultApi: (...args: unknown[]) => mockImportVaultApi(...args),
  setup2faApi: vi.fn(),
  verify2faApi: vi.fn(),
  disable2faApi: vi.fn(),
  changePasswordApi: vi.fn(),
  exportVaultApi: vi.fn(),
}));

vi.mock('../src/services/api/authApi', () => ({
  logoutAllApi: (...args: unknown[]) => mockLogoutAllApi(...args),
}));

vi.mock('../src/services/api/client', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    post: vi.fn().mockResolvedValue({
      data: { data: { accessToken: 'mock-access-token' } },
    }),
  },
  // Matches the real fallback: with no Web Locks API (jsdom) the refresh runs
  // directly. Cross-tab serialization is covered by `refresh-multitab.test.ts`.
  withRefreshLock: <T,>(run: () => Promise<T>): Promise<T> => run(),
}));

vi.mock('../src/stores/authStore', () => ({
  useAuthStore: Object.assign(
    vi.fn((selector?: (state: Record<string, unknown>) => unknown) => {
      const state = {
        user: { userId: 'u1', email: 'test@example.com' },
        vaultKey: {} as CryptoKey,
        mek: {},
      };
      return selector ? selector(state) : state;
    }),
    {
      getState: vi.fn().mockReturnValue({
        vaultKey: {} as CryptoKey,
        mek: {},
        setAccessToken: vi.fn(),
        accessToken: 'mock-access-token',
        user: { email: 'test@example.com' },
      }),
      setState: vi.fn(),
    },
  ),
}));

vi.mock('../src/stores/uiStore', () => ({
  useUIStore: Object.assign(
    vi.fn((selector?: (state: Record<string, unknown>) => unknown) => {
      const state = {
        theme: 'system',
        setTheme: vi.fn(),
      };
      return selector ? selector(state) : state;
    }),
    {
      getState: vi.fn().mockReturnValue({ theme: 'system', setTheme: vi.fn() }),
      setState: vi.fn(),
    },
  ),
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn().mockResolvedValue({
      masterEncryptionKey: {} as CryptoKey,
      authKey: new ArrayBuffer(32),
    }),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    generateVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
    rotateVaultKey: vi.fn(),
  },
}));

vi.mock('qrcode', () => ({
  default: { toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,...') },
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

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { VaultItemForm } from '../src/components/vault/VaultItemForm';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithRouter(ui: React.ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const defaultFormProps = {
  onSaved: vi.fn(),
  onCancel: vi.fn(),
};

function renderForm(overrides: Partial<Parameters<typeof VaultItemForm>[0]> = {}) {
  return render(<VaultItemForm {...defaultFormProps} {...overrides} />);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

// ==========================================================================
// 8.1 - Boolean custom field in VaultItemForm
// ==========================================================================

describe('Phase 8.1: VaultItemForm boolean custom field', () => {
  it('renders a checkbox when custom field type is "boolean"', async () => {
    const existingItem = {
      id: 'item-1',
      itemType: 'login' as const,
      tags: [],
      favorite: false,
      name: 'Test Login',
      data: {
        username: 'user',
        password: 'pass',
        uris: [],
        totp: '',
        notes: '',
        customFields: [{ name: 'Active', value: 'false', type: 'boolean' }],
      },
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      _raw: {} as unknown,
    };

    renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

    // A checkbox input should be rendered for the boolean custom field
    const checkboxes = screen.getAllByRole('checkbox');
    expect(checkboxes.length).toBeGreaterThanOrEqual(1);

    // Should display "False" text when value is 'false'
    expect(screen.getByText('False')).toBeInTheDocument();
  });

  it('toggling the boolean custom field checkbox updates value display', async () => {
    const existingItem = {
      id: 'item-1',
      itemType: 'login' as const,
      tags: [],
      favorite: false,
      name: 'Test Login',
      data: {
        username: 'user',
        password: 'pass',
        uris: [],
        totp: '',
        notes: '',
        customFields: [{ name: 'Active', value: 'false', type: 'boolean' }],
      },
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      _raw: {} as unknown,
    };

    renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

    const checkbox = screen
      .getAllByRole('checkbox')
      .find(
        (el) =>
          el.closest('label')?.textContent?.includes('False') ||
          el.closest('label')?.textContent?.includes('True'),
      );
    expect(checkbox).toBeDefined();

    // Initially it should say "False"
    expect(screen.getByText('False')).toBeInTheDocument();

    // Click the checkbox to toggle it
    fireEvent.click(checkbox!);

    // After toggling, it should now say "True"
    await waitFor(() => {
      expect(screen.getByText('True')).toBeInTheDocument();
    });
  });

  it('renders boolean option in the custom field type dropdown', () => {
    renderForm(); // default login type

    // Click "+ Add Field" to add a custom field
    const addFieldButton = screen.getByText('+ Add Field');
    fireEvent.click(addFieldButton);

    // The type select should have a "Boolean" option
    const typeSelects = screen.getAllByRole('combobox');
    const cfTypeSelect = typeSelects.find((s) => {
      const options = s.querySelectorAll('option');
      return Array.from(options).some((o) => o.textContent === 'Boolean');
    });

    expect(cfTypeSelect).toBeDefined();
    expect(
      Array.from(cfTypeSelect!.querySelectorAll('option')).some((o) => o.textContent === 'Boolean'),
    ).toBe(true);
  });
});

// ==========================================================================
// 8.2 - Form label accessibility (htmlFor/id)
// ==========================================================================

describe('Phase 8.2: VaultItemForm accessibility', () => {
  it('labels have htmlFor attributes matching input ids for login fields', () => {
    renderForm();

    // Name field
    const nameLabel = screen.getByText('Name');
    expect(nameLabel.tagName).toBe('LABEL');
    expect(nameLabel).toHaveAttribute('for', 'field-name');
    const nameInput = screen.getByPlaceholderText('Item name');
    expect(nameInput).toHaveAttribute('id', 'field-name');

    // Username field
    const usernameLabel = screen.getByText('Username');
    expect(usernameLabel.tagName).toBe('LABEL');
    expect(usernameLabel).toHaveAttribute('for', 'field-username');
    const usernameInput = screen.getByPlaceholderText('Username or email');
    expect(usernameInput).toHaveAttribute('id', 'field-username');

    // Password field
    const passwordLabel = screen.getByText('Password');
    expect(passwordLabel.tagName).toBe('LABEL');
    expect(passwordLabel).toHaveAttribute('for', 'field-password');
    const passwordInput = screen.getByPlaceholderText('Password');
    expect(passwordInput).toHaveAttribute('id', 'field-password');
  });

  it('labels have htmlFor attributes matching input ids for card fields', () => {
    renderForm({ defaultType: 'card' });

    const cardholderLabel = screen.getByText('Cardholder Name');
    expect(cardholderLabel.tagName).toBe('LABEL');
    expect(cardholderLabel).toHaveAttribute('for', 'field-cardholderName');
    const cardholderInput = screen.getByPlaceholderText('Name on card');
    expect(cardholderInput).toHaveAttribute('id', 'field-cardholderName');

    const numberLabel = screen.getByText('Card Number');
    expect(numberLabel.tagName).toBe('LABEL');
    expect(numberLabel).toHaveAttribute('for', 'field-number');
    const numberInput = screen.getByPlaceholderText('1234 5678 9012 3456');
    expect(numberInput).toHaveAttribute('id', 'field-number');
  });

  it('labels have htmlFor attributes matching input ids for identity fields', () => {
    renderForm({ defaultType: 'identity' });

    const firstNameLabel = screen.getByText('First Name');
    expect(firstNameLabel.tagName).toBe('LABEL');
    expect(firstNameLabel).toHaveAttribute('for', 'field-firstName');
    const firstNameInput = screen.getByPlaceholderText('First name');
    expect(firstNameInput).toHaveAttribute('id', 'field-firstName');

    const lastNameLabel = screen.getByText('Last Name');
    expect(lastNameLabel.tagName).toBe('LABEL');
    expect(lastNameLabel).toHaveAttribute('for', 'field-lastName');
    const lastNameInput = screen.getByPlaceholderText('Last name');
    expect(lastNameInput).toHaveAttribute('id', 'field-lastName');
  });

  it('Folder FormField label has htmlFor matching the select id', () => {
    renderForm();

    const folderLabel = screen.getByText('Folder');
    expect(folderLabel.tagName).toBe('LABEL');
    expect(folderLabel).toHaveAttribute('for', 'field-folder');

    // The folder select element
    const folderSelect = screen.getByDisplayValue('No folder');
    expect(folderSelect).toHaveAttribute('id', 'field-folder');
  });
});

// ==========================================================================
// 8.4 - Error recovery with retry in AuditLogPage and SessionsPage
// ==========================================================================

describe('Phase 8.4: AuditLogPage error recovery with retry', () => {
  beforeEach(() => {
    mockGetAuditLogApi.mockRejectedValue(new Error('Network error'));
  });

  it('shows error message and retry button when audit log fails to load', async () => {
    // Dynamic import to avoid mock ordering issues
    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    renderWithRouter(<AuditLogPage />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load audit log')).toBeInTheDocument();
    });

    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('clicking retry re-fetches the audit log and can show data on success', async () => {
    const { default: AuditLogPage } = await import('../src/pages/AuditLogPage');

    renderWithRouter(<AuditLogPage />);

    await waitFor(() => {
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });

    // Now make the retry succeed with an empty result
    mockGetAuditLogApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 1 },
      },
    });

    fireEvent.click(screen.getByText('Retry'));

    // After a successful retry, the error message and retry button should disappear
    // and the empty state should appear instead
    await waitFor(() => {
      expect(screen.getByText('No audit log entries found.')).toBeInTheDocument();
    });

    // The error state should no longer be showing
    expect(screen.queryByText('Failed to load audit log')).not.toBeInTheDocument();
  });
});

describe('Phase 8.4: SessionsPage error recovery with retry', () => {
  beforeEach(() => {
    mockListSessionsApi.mockRejectedValue(new Error('Network error'));
  });

  it('shows error message and retry button when sessions fail to load', async () => {
    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    renderWithRouter(<SessionsPage />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load sessions')).toBeInTheDocument();
    });

    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('clicking retry re-fetches sessions and can show data on success', async () => {
    const { default: SessionsPage } = await import('../src/pages/SessionsPage');

    renderWithRouter(<SessionsPage />);

    await waitFor(() => {
      expect(screen.getByText('Retry')).toBeInTheDocument();
    });

    // Make the retry succeed with an empty result
    mockListSessionsApi.mockResolvedValue({
      data: {
        success: true,
        data: [],
      },
    });

    fireEvent.click(screen.getByText('Retry'));

    // After a successful retry, the error should disappear and show the empty state
    await waitFor(() => {
      expect(screen.getByText('No active sessions found.')).toBeInTheDocument();
    });

    expect(screen.queryByText('Failed to load sessions')).not.toBeInTheDocument();
  });
});

// ==========================================================================
// 8.5 - Password history tracking in vaultStore
//
// REMOVED: the former two tests here mocked vaultStore wholesale (see the
// top-level `vi.mock('../src/stores/vaultStore', …)`) and only asserted that
// VaultItemForm forwarded a password string into a vi.fn() — they exercised
// none of the real updateItem password-history logic they were named for, so
// deleting that logic left them green.
//
// The behavior is now covered where it actually lives:
//   * The real store's password-history construction (built when a login
//     password changes, skipped when unchanged or for non-login items, capped
//     at MAX_PASSWORD_HISTORY) is exercised against the UNMOCKED store in
//     tests/stores-services-coverage.test.ts ("updateItem — password history").
//   * VaultItemForm's submit-forwarding to updateItem (id / name / data /
//     options) is exercised in tests/coverage-vault-item-form.test.tsx
//     ("VaultItemForm — update and error handling").
// ==========================================================================

// ==========================================================================
// 8.6 - CSV import field validation
// ==========================================================================

describe('Phase 8.6: CSV import validation in SettingsPage', () => {
  beforeEach(() => {
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          email: 'test@example.com',
          emailVerified: true,
          twoFactorEnabled: false,
          settings: {
            autoLockTimeout: 15,
            clipboardClearTimeout: 30,
            theme: 'system',
            backup: {
              enabled: false,
              scheduleHour: 3,
              backupEmails: [],
              isConfigured: false,
            },
          },
        },
      },
    });
  });

  it('shows error toast when CSV import is attempted without mapping the "name" field', async () => {
    const { default: SettingsPage } = await import('../src/pages/SettingsPage');

    renderWithRouter(<SettingsPage />);

    // Wait for profile to load
    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument();
    });

    // Click "Import Vault" to show the import form
    fireEvent.click(screen.getByText('Import Vault'));

    // Select CSV format
    const formatSelect = screen.getAllByRole('combobox').find((s) => {
      const options = s.querySelectorAll('option');
      return Array.from(options).some((o) => o.textContent === 'CSV');
    });
    expect(formatSelect).toBeDefined();
    fireEvent.change(formatSelect!, { target: { value: 'csv' } });

    // Paste CSV data
    const textarea = screen.getByPlaceholderText('Paste exported data here...');
    fireEvent.change(textarea, {
      target: { value: 'title,user,pass\nMySite,admin,secret' },
    });

    // Wait for CSV headers to be parsed and mapping UI to appear
    await waitFor(() => {
      expect(screen.getByText('Map CSV Columns')).toBeInTheDocument();
    });

    // Manually clear all mappings to ensure "name" is not mapped
    // The auto-mapper might have mapped "title" to "name" based on heuristics.
    // We need to set all column mappings to "-- Skip --" (value: '')
    const mappingSelects = screen
      .getByText('Map CSV Columns')
      .closest('.space-y-3')!
      .querySelectorAll('select');
    for (const sel of mappingSelects) {
      fireEvent.change(sel, { target: { value: '' } });
    }

    // Click the Import button
    const importButton = screen.getByRole('button', { name: 'Import' });
    fireEvent.click(importButton);

    // The importVaultApi should NOT have been called since validation should fail
    await waitFor(() => {
      expect(mockImportVaultApi).not.toHaveBeenCalled();
    });
  });
});

// ==========================================================================
// 8.9 - Client-side unlock attempt rate limiting feedback
// ==========================================================================

describe('Phase 8.9: UnlockScreen rate limiting feedback', () => {
  let UnlockScreen: React.ComponentType;

  beforeEach(async () => {
    vi.clearAllMocks();
    // Clear persisted rate-limiting state so tests start fresh.
    // UnlockScreen uses localStorage (more durable than sessionStorage)
    // for rate-limit persistence.
    localStorage.removeItem('__hv_unlock_failed_attempts');
    localStorage.removeItem('__hv_unlock_lockout_until');
    // Dynamic import to pick up mocks
    const mod = await import('../src/components/auth/UnlockScreen');
    UnlockScreen = mod.UnlockScreen;
  });

  it('renders the unlock form without lockout warnings initially', () => {
    renderWithRouter(<UnlockScreen />);

    expect(screen.getByText('Vault Locked')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter your master password')).toBeInTheDocument();
    // No lockout/attempt warnings should be visible
    expect(screen.queryByText(/attempt/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/wait/i)).not.toBeInTheDocument();
  });

  it('shows remaining attempts warning after failed unlock (before lockout threshold)', async () => {
    // Configure the mock unlock to reject
    const mockUnlock = vi.fn().mockRejectedValue(new Error('Incorrect master password'));
    const { useAuthStore } = await import('../src/stores/authStore');
    (useAuthStore as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          user: { email: 'test@example.com' },
          unlock: mockUnlock,
          logout: vi.fn(),
        };
        return selector ? selector(state) : state;
      },
    );

    renderWithRouter(<UnlockScreen />);

    const input = screen.getByPlaceholderText('Enter your master password');
    const submitButton = screen.getByRole('button', { name: /unlock/i });

    // Submit a wrong password
    fireEvent.change(input, { target: { value: 'wrongpass' } });
    fireEvent.click(submitButton);

    // After failure, should show remaining attempts
    await waitFor(() => {
      expect(screen.getByText(/attempt/i)).toBeInTheDocument();
    });
  });

  it('disables the unlock button text with lockout duration after 5+ failures', async () => {
    // Configure the mock unlock to always reject
    const mockUnlock = vi.fn().mockRejectedValue(new Error('Incorrect'));
    const { useAuthStore } = await import('../src/stores/authStore');
    (useAuthStore as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (selector?: (state: Record<string, unknown>) => unknown) => {
        const state = {
          user: { email: 'test@example.com' },
          unlock: mockUnlock,
          logout: vi.fn(),
        };
        return selector ? selector(state) : state;
      },
    );

    renderWithRouter(<UnlockScreen />);

    const input = screen.getByPlaceholderText('Enter your master password');

    // Make 5 failed attempts
    for (let i = 0; i < 5; i++) {
      fireEvent.change(input, { target: { value: `wrong${i}` } });
      fireEvent.click(screen.getByRole('button', { name: /unlock|locked/i }));
      // Wait for each attempt to process
      await waitFor(() => {
        expect(mockUnlock).toHaveBeenCalledTimes(i + 1);
      });
    }

    // After 5 failures, button should show lockout text
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /locked/i })).toBeInTheDocument();
    });
  });
});

// ==========================================================================
// 8.10 - Accessibility fixes
// ==========================================================================

describe('Phase 8.10: Accessibility fixes', () => {
  // REMOVED: the former "AppLayout / VaultPage mobile overlay uses <button>"
  // tests were `readFileSync + toContain` source greps — they never executed a
  // line of component code. A whole-file `not.toContain('role="button"')` both
  // false-fails on any unrelated role="button" added elsewhere and false-passes
  // if the overlay regressed to a `<div role="button">`/`<div aria-label=...>`
  // (no `role="button"` substring, aria-label intact). The overlay is instead
  // rendered and exercised behaviorally (open sidebar, click overlay, Escape)
  // in tests/sidebar-client-coverage.test.tsx ("closes mobile sidebar when
  // overlay is clicked" / "...when Escape is pressed on overlay"), which drives
  // the real AppLayout through its full mock harness.

  it('VaultList uses native checkbox inputs instead of button-based checkboxes', async () => {
    // Import the VaultList component
    const { VaultList } = await import('../src/components/vault/VaultList');

    // Mock the store to return items
    const { useVaultStore } = await import('../src/stores/vaultStore');
    (useVaultStore as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (selector: (state: Record<string, unknown>) => unknown) => {
        const state = {
          items: [
            {
              id: 'test-1',
              name: 'Test Item',
              itemType: 'login',
              tags: [],
              favorite: false,
              folderId: null,
              data: {
                username: 'user',
                password: 'pass',
                uris: [],
                totp: '',
                notes: '',
                customFields: [],
              },
              createdAt: '2024-01-01T00:00:00Z',
              updatedAt: '2024-01-01T00:00:00Z',
              _raw: {},
            },
          ],
          trashItems: [],
          loading: false,
          searchQuery: '',
          selectedFolder: null,
          selectedType: null,
          showFavorites: false,
          showTrash: false,
          fetchItems: vi.fn(),
          fetchTrashItems: vi.fn(),
          emptyTrash: vi.fn(),
          folders: [],
          sortBy: 'name',
          sortOrder: 'asc',
          setSortBy: vi.fn(),
          setSortOrder: vi.fn(),
          setFilteredItemCount: vi.fn(),
          filteredItemCount: null,
          createItem: vi.fn(),
          updateItem: vi.fn(),
        };
        return selector(state);
      },
    );

    const { container } = renderWithRouter(<VaultList onCreateNew={vi.fn()} />);

    // Look for native checkbox inputs
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    expect(checkboxes.length).toBeGreaterThanOrEqual(1);

    // Each checkbox must be inside a <label> element. `closest()` returns null
    // when there is no matching ancestor, and `expect(null).toBeDefined()`
    // PASSES — so assert `.not.toBeNull()` to actually catch a checkbox that
    // escaped its wrapping label.
    checkboxes.forEach((checkbox) => {
      const label = checkbox.closest('label');
      expect(label).not.toBeNull();
    });
  });
});

// ==========================================================================
// 8.11 - Loading states for download and favorite operations
// ==========================================================================

describe('Phase 8.11: Loading states for download and favorite', () => {
  it('BackupSettingsPage download button has disabled attribute during download', async () => {
    // Mock the profile API for BackupSettingsPage
    mockGetProfileApi.mockResolvedValue({
      data: {
        success: true,
        data: {
          email: 'test@example.com',
          emailVerified: true,
          twoFactorEnabled: false,
          settings: {
            autoLockTimeout: 15,
            clipboardClearTimeout: 30,
            theme: 'system',
            backup: {
              enabled: false,
              scheduleHour: 3,
              backupEmails: [],
              isConfigured: true,
            },
          },
        },
      },
    });

    const { default: BackupSettingsPage } = await import('../src/pages/BackupSettingsPage');

    renderWithRouter(<BackupSettingsPage />);

    // Wait for the page to load
    await waitFor(() => {
      expect(screen.getByText('Download Latest')).toBeInTheDocument();
    });

    // Capture the button node up front — once a download is in flight its text
    // changes to "Downloading...", so a later getByText('Download Latest') would
    // miss it.
    const downloadButton = screen.getByText('Download Latest').closest('button')!;
    expect(downloadButton).not.toBeDisabled();

    // Clicking "Download Latest" with no backup password only reveals the
    // password prompt (handleDownload early-returns before setDownloading).
    fireEvent.click(downloadButton);
    const pwInput = await screen.findByPlaceholderText('Backup password');
    fireEvent.change(pwInput, { target: { value: 'backup-pass-123' } });

    // Hold the download in flight: handleDownload awaits getProfileApi first, so
    // a never-resolving profile fetch parks the handler with downloading === true.
    let resolveProfile!: (value: unknown) => void;
    mockGetProfileApi.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveProfile = resolve;
      }),
    );

    // The prompt's own "Download" button (first button beside the password input).
    const promptDownloadButton = pwInput.parentElement!.querySelector('button')!;
    expect(promptDownloadButton).toHaveTextContent('Download');
    fireEvent.click(promptDownloadButton);

    // While the request is in flight both download controls are disabled — this
    // is the loading state the test is named for. Removing `downloading`/the
    // `disabled` prop leaves the button click-spammable and fails this.
    await waitFor(() => {
      expect(downloadButton).toBeDisabled();
    });
    expect(promptDownloadButton).toBeDisabled();

    // Settle the in-flight promise so the handler can unwind cleanly. The
    // profile payload is missing bwk fields, so handleDownload toasts and
    // re-enables the buttons without touching real crypto.
    resolveProfile({
      data: { success: true, data: { settings: { backup: { isConfigured: true } } } },
    });
    await waitFor(() => {
      expect(downloadButton).not.toBeDisabled();
    });
  });

  it('VaultItemDetail favorite button shows spinner and is disabled during toggle', async () => {
    const { VaultItemDetail } = await import('../src/components/vault/VaultItemDetail');

    // Pin the store mock implementation for this test: the 8.10 VaultList test
    // replaces useVaultStore's implementation via mockImplementation, and
    // vi.clearAllMocks() (mockClear) does NOT restore implementations — so
    // without this the leaked VaultList state (which has no updateItemMeta)
    // would make the favorite handler call undefined and never enter its
    // loading state. Re-establish a state that exposes the controllable
    // updateItemMeta the toggle awaits.
    const { useVaultStore } = await import('../src/stores/vaultStore');
    (useVaultStore as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (selector: (state: Record<string, unknown>) => unknown) =>
        selector({
          folders: [],
          deleteItem: vi.fn(),
          permanentDeleteItem: vi.fn(),
          restoreItem: vi.fn(),
          updateItemMeta: mockUpdateItemMeta,
        }),
    );

    const mockItem = {
      id: 'item-1',
      name: 'Test Item',
      itemType: 'login' as const,
      tags: [],
      favorite: false,
      folderId: null,
      data: { username: 'user', password: 'pass', uris: [], totp: '', notes: '', customFields: [] },
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      _raw: { _id: 'item-1', passwordHistory: [] },
    };

    // Hold updateItemMeta in flight so favoriteLoading stays true.
    let resolveMeta!: () => void;
    mockUpdateItemMeta.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        resolveMeta = resolve;
      }),
    );

    renderWithRouter(
      <VaultItemDetail
        item={mockItem as unknown as Parameters<typeof VaultItemDetail>[0]['item']}
        onEdit={vi.fn()}
      />,
    );

    const favoriteButton = screen.getByRole('button', { name: /favorite/i });
    expect(favoriteButton).not.toBeDisabled();

    // Toggling favorite sets favoriteLoading -> the button must disable while the
    // async updateItemMeta is pending. Dropping favoriteLoading/the disabled prop
    // (the regression this guards) leaves it enabled and fails the waitFor.
    fireEvent.click(favoriteButton);
    await waitFor(() => {
      expect(favoriteButton).toBeDisabled();
    });

    // Once the toggle settles the button re-enables.
    resolveMeta();
    await waitFor(() => {
      expect(favoriteButton).not.toBeDisabled();
    });
  });
});
