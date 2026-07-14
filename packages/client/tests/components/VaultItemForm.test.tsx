import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { VaultItemForm } from '../../src/components/vault/VaultItemForm';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockCreateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItem = vi.fn().mockResolvedValue(undefined);

vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) => {
    const state = {
      createItem: mockCreateItem,
      updateItem: mockUpdateItem,
      folders: [
        { id: 'folder-1', name: 'Work', sortOrder: 0, createdAt: '', updatedAt: '' },
        { id: 'folder-2', name: 'Personal', sortOrder: 1, createdAt: '', updatedAt: '' },
      ],
    };
    return selector(state);
  }),
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({
    toast: vi.fn(),
    dismiss: vi.fn(),
    update: vi.fn(),
  }),
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
  }),
}));

vi.mock('../../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({
    startCountdown: vi.fn(),
    stopCountdown: vi.fn(),
  }),
}));

// zxcvbn mock removed: the password generator now measures strength via exact entropy
// (src/utils/passwordEntropy.ts), so nothing in this render tree imports zxcvbn.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const defaultProps = {
  onSaved: vi.fn(),
  onCancel: vi.fn(),
};

function renderForm(overrides: Partial<Parameters<typeof VaultItemForm>[0]> = {}) {
  return render(<VaultItemForm {...defaultProps} {...overrides} />);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe('VaultItemForm', () => {
  // -------------------------------------------------------------------------
  // 1. Renders with default login type
  // -------------------------------------------------------------------------
  describe('renders with default login type', () => {
    it('shows type tabs for all 5 item types', () => {
      renderForm();

      expect(screen.getByText('Login')).toBeInTheDocument();
      expect(screen.getByText('Secret')).toBeInTheDocument();
      expect(screen.getByText('Note')).toBeInTheDocument();
      expect(screen.getByText('Card')).toBeInTheDocument();
      expect(screen.getByText('Identity')).toBeInTheDocument();
    });

    it('shows the Name field', () => {
      renderForm();
      expect(screen.getByPlaceholderText('Item name')).toBeInTheDocument();
    });

    it('shows login-specific fields: Username and Password', () => {
      renderForm();
      expect(screen.getByPlaceholderText('Username or email')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
    });

    it('shows the "Create" submit button for new items', () => {
      renderForm();
      expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
    });

    it('shows the heading "New Item"', () => {
      renderForm();
      expect(screen.getByText('New Item')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 2. Type tab switching
  // -------------------------------------------------------------------------
  describe('type tab switching', () => {
    it('clicking "Note" tab shows content and format fields', () => {
      renderForm();

      fireEvent.click(screen.getByText('Note'));

      // Note type should show a format dropdown and content textarea
      expect(screen.getByPlaceholderText('Write your note...')).toBeInTheDocument();
      expect(screen.getByText('Markdown')).toBeInTheDocument();

      // Login-specific fields should be gone
      expect(screen.queryByPlaceholderText('Username or email')).not.toBeInTheDocument();
      expect(screen.queryByPlaceholderText('Password')).not.toBeInTheDocument();
    });

    it('clicking "Card" tab shows card-specific fields', () => {
      renderForm();

      fireEvent.click(screen.getByText('Card'));

      expect(screen.getByPlaceholderText('Name on card')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('1234 5678 9012 3456')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('MM')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('YYYY')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('CVV')).toBeInTheDocument();
    });

    it('clicking "Identity" tab shows identity-specific fields', () => {
      renderForm();

      fireEvent.click(screen.getByText('Identity'));

      expect(screen.getByPlaceholderText('First name')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Last name')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Email address')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Phone number')).toBeInTheDocument();
    });

    it('clicking "Secret" tab shows secret-specific fields', () => {
      renderForm();

      fireEvent.click(screen.getByText('Secret'));

      expect(
        screen.getByPlaceholderText('Secret value (API key, token, etc.)'),
      ).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Description (optional)')).toBeInTheDocument();
    });

    it('clicking "Secret" tab shows separate date and time expiry fields', () => {
      renderForm();

      fireEvent.click(screen.getByText('Secret'));

      const dateInput = document.getElementById('field-expiryDate') as HTMLInputElement;
      const timeInput = document.getElementById('field-expiryTime') as HTMLInputElement;

      expect(dateInput).toBeInTheDocument();
      expect(dateInput.type).toBe('date');
      expect(timeInput).toBeInTheDocument();
      expect(timeInput.type).toBe('time');

      // The old datetime-local field should no longer exist
      expect(document.getElementById('field-expiresAt')).not.toBeInTheDocument();
    });

    it('switching from Card back to Login shows login fields again', () => {
      renderForm();

      fireEvent.click(screen.getByText('Card'));
      expect(screen.getByPlaceholderText('1234 5678 9012 3456')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Login'));
      expect(screen.getByPlaceholderText('Username or email')).toBeInTheDocument();
      expect(screen.queryByPlaceholderText('1234 5678 9012 3456')).not.toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 3. Login form validation
  // -------------------------------------------------------------------------
  describe('login form validation', () => {
    it('submitting empty form shows "Name is required"', async () => {
      renderForm();

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(screen.getByText('Name is required')).toBeInTheDocument();
      });
    });

    it('URI input fields are rendered with correct placeholder', () => {
      renderForm();
      // Login form should have a default URI field
      const uriInputs = screen.getAllByPlaceholderText('example.com');
      expect(uriInputs.length).toBeGreaterThanOrEqual(1);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Note form validation
  // -------------------------------------------------------------------------
  describe('note form validation', () => {
    it('submitting empty note form shows errors for name and content', async () => {
      renderForm({ defaultType: 'note' });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(screen.getByText('Name is required')).toBeInTheDocument();
        expect(screen.getByText('Content is required')).toBeInTheDocument();
      });
    });
  });

  // -------------------------------------------------------------------------
  // 5. Card form validation
  // -------------------------------------------------------------------------
  describe('card form validation', () => {
    it('submitting empty card form shows errors only for required fields (not exp/cvv)', async () => {
      renderForm({ defaultType: 'card' });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(screen.getByText('Name is required')).toBeInTheDocument();
        expect(screen.getByText('Cardholder name is required')).toBeInTheDocument();
        expect(screen.getByText('Card number is required')).toBeInTheDocument();
        // expMonth, expYear, cvv are now optional — no errors when empty
        expect(screen.queryByText('Invalid month (01-12)')).not.toBeInTheDocument();
        expect(screen.queryByText('Invalid year')).not.toBeInTheDocument();
        expect(screen.queryByText('Must be 3-4 digits')).not.toBeInTheDocument();
      });
    });

    it('formats card number with 4-digit groups as user types', () => {
      renderForm({ defaultType: 'card' });

      const cardInput = screen.getByPlaceholderText('1234 5678 9012 3456') as HTMLInputElement;
      fireEvent.change(cardInput, { target: { value: '4111111111111111' } });

      expect(cardInput.value).toBe('4111 1111 1111 1111');
    });

    it('strips non-digit characters from card number input', () => {
      renderForm({ defaultType: 'card' });

      const cardInput = screen.getByPlaceholderText('1234 5678 9012 3456') as HTMLInputElement;
      fireEvent.change(cardInput, { target: { value: '4111-1111-1111-1111' } });

      expect(cardInput.value).toBe('4111 1111 1111 1111');
    });

    it('shows "+ Add billing address" button by default for new card', () => {
      renderForm({ defaultType: 'card' });

      expect(screen.getByText('+ Add billing address')).toBeInTheDocument();
    });

    it('clicking "+ Add billing address" shows billing address fields', () => {
      renderForm({ defaultType: 'card' });

      fireEvent.click(screen.getByText('+ Add billing address'));

      expect(screen.getByText('Billing Address')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Street address')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('City')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('State')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('ZIP code')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Country')).toBeInTheDocument();
    });

    it('clicking "Remove" hides billing address section', () => {
      renderForm({ defaultType: 'card' });

      fireEvent.click(screen.getByText('+ Add billing address'));
      expect(screen.getByText('Billing Address')).toBeInTheDocument();

      fireEvent.click(screen.getByText('Remove'));
      expect(screen.queryByText('Billing Address')).not.toBeInTheDocument();
      expect(screen.getByText('+ Add billing address')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 6. Identity form validation
  // -------------------------------------------------------------------------
  describe('identity form validation', () => {
    it('submitting empty identity form shows errors for name, firstName, lastName', async () => {
      renderForm({ defaultType: 'identity' });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(screen.getByText('Name is required')).toBeInTheDocument();
        // firstName and lastName both show "Required"
        const requiredErrors = screen.getAllByText('Required');
        expect(requiredErrors.length).toBeGreaterThanOrEqual(2);
      });
    });

    it('renders the identity email validation error and wires aria-describedby to it', async () => {
      renderForm({ defaultType: 'identity' });

      // Satisfy the other required fields so only the email error is in play.
      fireEvent.change(screen.getByPlaceholderText('Item name'), { target: { value: 'Me' } });
      fireEvent.change(screen.getByPlaceholderText('First name'), { target: { value: 'Ada' } });
      fireEvent.change(screen.getByPlaceholderText('Last name'), { target: { value: 'Lovelace' } });

      const emailInput = screen.getByPlaceholderText('Email address');
      expect(emailInput.getAttribute('type')).toBe('email');
      // 'foo@bar' passes the input's native HTML5 email constraint (so the form
      // actually submits) but fails the app's stricter zod regex, which requires a
      // dotted TLD — this is what exercises the FormField error plumbing.
      fireEvent.change(emailInput, { target: { value: 'foo@bar' } });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      // The error text must render AND the input must point at it via
      // aria-describedby (the FormField error plumbing) — a screen-reader contract
      // that a plain "input exists / type is email" assertion never checked.
      const errorEl = await screen.findByText('Invalid email address');
      expect(errorEl).toBeInTheDocument();
      expect(errorEl.getAttribute('id')).toBe('field-email-error');
      expect(emailInput.getAttribute('aria-describedby')).toBe('field-email-error');
      expect(emailInput.getAttribute('aria-invalid')).toBe('true');
    });

    it('renders the identity phone validation error and wires aria-describedby to it', async () => {
      renderForm({ defaultType: 'identity' });

      fireEvent.change(screen.getByPlaceholderText('Item name'), { target: { value: 'Me' } });
      fireEvent.change(screen.getByPlaceholderText('First name'), { target: { value: 'Ada' } });
      fireEvent.change(screen.getByPlaceholderText('Last name'), { target: { value: 'Lovelace' } });

      const phoneInput = screen.getByPlaceholderText('Phone number');
      expect(phoneInput.getAttribute('type')).toBe('tel');
      // Letters are outside the allowed phone character class -> validation error.
      fireEvent.change(phoneInput, { target: { value: 'abc' } });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      const errorEl = await screen.findByText('Invalid phone number (3-30 characters)');
      expect(errorEl).toBeInTheDocument();
      expect(errorEl.getAttribute('id')).toBe('field-phone-error');
      expect(phoneInput.getAttribute('aria-describedby')).toBe('field-phone-error');
      expect(phoneInput.getAttribute('aria-invalid')).toBe('true');
    });
  });

  // -------------------------------------------------------------------------
  // 7. Cancel button
  // -------------------------------------------------------------------------
  describe('cancel button', () => {
    it('clicking cancel calls onCancel callback', () => {
      const onCancel = vi.fn();
      renderForm({ onCancel });

      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

      expect(onCancel).toHaveBeenCalledTimes(1);
    });
  });

  // -------------------------------------------------------------------------
  // 8. Favorite toggle
  // -------------------------------------------------------------------------
  describe('favorite toggle', () => {
    it('clicking star toggles the favorite state', () => {
      renderForm();

      // Find the favorite toggle by its aria-pressed attribute.
      const starButton = screen.getByRole('button', { pressed: false });
      expect(starButton).toHaveAttribute('aria-pressed', 'false');

      fireEvent.click(starButton);

      expect(starButton).toHaveAttribute('aria-pressed', 'true');
    });

    it('clicking star twice toggles back to not favorite', () => {
      renderForm();

      const starButton = screen.getByRole('button', { pressed: false });

      fireEvent.click(starButton);
      expect(starButton).toHaveAttribute('aria-pressed', 'true');

      fireEvent.click(starButton);
      expect(starButton).toHaveAttribute('aria-pressed', 'false');
    });
  });

  // -------------------------------------------------------------------------
  // 9. When editing
  // -------------------------------------------------------------------------
  describe('when editing an existing item', () => {
    const existingItem = {
      id: 'item-1',
      itemType: 'login' as const,
      folderId: 'folder-1',
      tags: ['important'],
      favorite: true,
      name: 'GitHub Account',
      data: {
        username: 'octocat',
        password: 'secret123',
        uris: [{ uri: 'https://github.com', match: 'domain' }],
        totp: '',
        notes: '',
        customFields: [],
      },
      searchHash: undefined,
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      deletedAt: undefined,
      _raw: undefined as unknown,
    };

    it('does not show type tabs when editing', () => {
      renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

      // The type tab buttons should not be present
      // Note: "Login" text might appear in other contexts, so check for tab container
      const secretTab = screen.queryByText('Secret');
      const noteTab = screen.queryByText('Note');
      const cardTab = screen.queryByText('Card');
      const identityTab = screen.queryByText('Identity');

      // When editing, none of the type tab buttons should exist
      expect(secretTab).not.toBeInTheDocument();
      expect(noteTab).not.toBeInTheDocument();
      expect(cardTab).not.toBeInTheDocument();
      expect(identityTab).not.toBeInTheDocument();
    });

    it('shows "Update" button instead of "Create"', () => {
      renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

      expect(screen.getByRole('button', { name: 'Update' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Create' })).not.toBeInTheDocument();
    });

    it('shows "Edit Item" heading', () => {
      renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

      expect(screen.getByText('Edit Item')).toBeInTheDocument();
    });

    it('populates the form with existing item data', () => {
      renderForm({ item: existingItem as unknown as Parameters<typeof VaultItemForm>[0]['item'] });

      const nameInput = screen.getByPlaceholderText('Item name') as HTMLInputElement;
      expect(nameInput.value).toBe('GitHub Account');

      const usernameInput = screen.getByPlaceholderText('Username or email') as HTMLInputElement;
      expect(usernameInput.value).toBe('octocat');
    });
  });

  // -------------------------------------------------------------------------
  // 10. Folder selection
  // -------------------------------------------------------------------------
  describe('folder selection', () => {
    it('renders folder dropdown with available folders', () => {
      renderForm();

      // The folder select should have the "No folder" option plus the two mocked folders
      const folderLabel = screen.getByText('Folder');
      expect(folderLabel).toBeInTheDocument();

      // Check for folder options by looking at the select
      const options = screen.getAllByRole('option');
      const folderOptions = options.filter(
        (opt) =>
          opt.textContent === 'No folder' ||
          opt.textContent === 'Work' ||
          opt.textContent === 'Personal',
      );

      expect(folderOptions.some((o) => o.textContent === 'No folder')).toBe(true);
      expect(folderOptions.some((o) => o.textContent === 'Work')).toBe(true);
      expect(folderOptions.some((o) => o.textContent === 'Personal')).toBe(true);
    });

    it('defaults to "No folder" when no defaultFolderId is provided', () => {
      renderForm();

      // Find the folder select element -- it's the one containing "No folder" option
      const selects = screen.getAllByRole('combobox');
      const folderSelect = selects.find((s) => {
        const options = s.querySelectorAll('option');
        return Array.from(options).some((o) => o.textContent === 'No folder');
      }) as HTMLSelectElement | undefined;

      expect(folderSelect).toBeDefined();
      expect(folderSelect!.value).toBe('');
    });

    it('pre-selects the folder when defaultFolderId is provided', () => {
      renderForm({ defaultFolderId: 'folder-1' });

      const selects = screen.getAllByRole('combobox');
      const folderSelect = selects.find((s) => {
        const options = s.querySelectorAll('option');
        return Array.from(options).some((o) => o.textContent === 'No folder');
      }) as HTMLSelectElement | undefined;

      expect(folderSelect).toBeDefined();
      expect(folderSelect!.value).toBe('folder-1');
    });
  });

  // -------------------------------------------------------------------------
  // 11. Secret expiry date/time split fields
  // -------------------------------------------------------------------------
  describe('secret expiry date/time split fields', () => {
    it('splits ISO expiresAt into separate date and time when editing', () => {
      const existingSecret = {
        id: 'secret-1',
        itemType: 'secret' as const,
        tags: [],
        favorite: false,
        name: 'API Key',
        data: {
          value: 'sk-abc123',
          description: 'Test key',
          expiresAt: '2026-12-31T23:59:00.000Z',
          customFields: [],
        },
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as unknown,
      };

      renderForm({
        item: existingSecret as unknown as Parameters<typeof VaultItemForm>[0]['item'],
      });

      const dateInput = document.getElementById('field-expiryDate') as HTMLInputElement;
      const timeInput = document.getElementById('field-expiryTime') as HTMLInputElement;

      expect(dateInput).toBeInTheDocument();
      expect(dateInput.value).toBe('2026-12-31');
      expect(timeInput).toBeInTheDocument();
      expect(timeInput.value).toBe('23:59');
    });

    it('splits datetime-local format expiresAt into separate date and time', () => {
      const existingSecret = {
        id: 'secret-2',
        itemType: 'secret' as const,
        tags: [],
        favorite: false,
        name: 'Token',
        data: {
          value: 'tok-xyz',
          description: '',
          expiresAt: '2025-06-15T14:30',
          customFields: [],
        },
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as unknown,
      };

      renderForm({
        item: existingSecret as unknown as Parameters<typeof VaultItemForm>[0]['item'],
      });

      const dateInput = document.getElementById('field-expiryDate') as HTMLInputElement;
      const timeInput = document.getElementById('field-expiryTime') as HTMLInputElement;

      expect(dateInput.value).toBe('2025-06-15');
      expect(timeInput.value).toBe('14:30');
    });

    it('leaves both fields empty when expiresAt is not set', () => {
      const existingSecret = {
        id: 'secret-3',
        itemType: 'secret' as const,
        tags: [],
        favorite: false,
        name: 'No Expiry Secret',
        data: {
          value: 'val',
          description: '',
          customFields: [],
        },
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as unknown,
      };

      renderForm({
        item: existingSecret as unknown as Parameters<typeof VaultItemForm>[0]['item'],
      });

      const dateInput = document.getElementById('field-expiryDate') as HTMLInputElement;
      const timeInput = document.getElementById('field-expiryTime') as HTMLInputElement;

      expect(dateInput.value).toBe('');
      expect(timeInput.value).toBe('');
    });

    it('renders "Expiry Date" and "Time (optional)" labels for secret type', () => {
      renderForm({ defaultType: 'secret' });

      expect(screen.getByText('Expiry Date')).toBeInTheDocument();
      expect(screen.getByText('Time (optional)')).toBeInTheDocument();
    });
  });

  // -------------------------------------------------------------------------
  // 12. Markdown preview link sanitization
  // -------------------------------------------------------------------------
  describe('markdown preview link sanitization', () => {
    it('renders safe https links with correct href in preview', async () => {
      renderForm({ defaultType: 'note' });

      const textarea = screen.getByPlaceholderText('Write your note...');
      fireEvent.change(textarea, { target: { value: '[Safe](https://example.com)' } });

      fireEvent.click(screen.getByText('Preview'));

      await waitFor(() => {
        const link = screen.getByText('Safe');
        expect(link.tagName).toBe('A');
        expect(link).toHaveAttribute('href', 'https://example.com');
        expect(link).toHaveAttribute('target', '_blank');
        expect(link).toHaveAttribute('rel', 'noopener noreferrer');
      });
    });

    it('renders safe mailto links with correct href in preview', async () => {
      renderForm({ defaultType: 'note' });

      const textarea = screen.getByPlaceholderText('Write your note...');
      fireEvent.change(textarea, { target: { value: '[Email](mailto:user@example.com)' } });

      fireEvent.click(screen.getByText('Preview'));

      await waitFor(() => {
        const link = screen.getByText('Email');
        expect(link.tagName).toBe('A');
        expect(link).toHaveAttribute('href', 'mailto:user@example.com');
      });
    });

    it('sanitizes javascript: URLs to "#" in preview', async () => {
      renderForm({ defaultType: 'note' });

      const textarea = screen.getByPlaceholderText('Write your note...');
      fireEvent.change(textarea, { target: { value: '[XSS](javascript:alert(1))' } });

      fireEvent.click(screen.getByText('Preview'));

      await waitFor(() => {
        const link = screen.getByText('XSS');
        expect(link.tagName).toBe('A');
        expect(link).toHaveAttribute('href', '#');
      });
    });

    it('sanitizes data: URLs to "#" in preview', async () => {
      renderForm({ defaultType: 'note' });

      const textarea = screen.getByPlaceholderText('Write your note...');
      fireEvent.change(textarea, {
        target: { value: '[Data](data:text/html,<script>alert(1)</script>)' },
      });

      fireEvent.click(screen.getByText('Preview'));

      await waitFor(() => {
        const link = screen.getByText('Data');
        expect(link.tagName).toBe('A');
        expect(link).toHaveAttribute('href', '#');
      });
    });
  });

  // -------------------------------------------------------------------------
  // 13. Custom field name sanitization (blank names stripped before encryption)
  // -------------------------------------------------------------------------
  describe('custom field name sanitization', () => {
    it('drops a custom field with a blank name but keeps a named field (login)', async () => {
      renderForm();

      fireEvent.change(screen.getByPlaceholderText('Item name'), {
        target: { value: 'My Login' },
      });

      // Add two custom-field rows.
      fireEvent.click(screen.getByText('+ Add Field'));
      fireEvent.click(screen.getByText('+ Add Field'));

      const nameInputs = screen.getAllByPlaceholderText('Field name');
      const valueInputs = screen.getAllByPlaceholderText('Value');
      expect(nameInputs).toHaveLength(2);
      expect(valueInputs).toHaveLength(2);

      // Row 0: blank name + a real value  -> must be stripped.
      fireEvent.change(valueInputs[0]!, { target: { value: 'orphan-value' } });
      // Row 1: real name + an empty value -> must be kept.
      fireEvent.change(nameInputs[1]!, { target: { value: 'API Key' } });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(mockCreateItem).toHaveBeenCalledTimes(1);
      });

      const data = mockCreateItem.mock.calls[0]![2] as { customFields: { name: string }[] };
      expect(data.customFields).toHaveLength(1);
      expect(data.customFields[0]!.name).toBe('API Key');
      // The blank-named entry never reaches encryption.
      expect(data.customFields.some((f) => f.name.trim() === '')).toBe(false);
    });

    it('drops a whitespace-only custom field name (secret)', async () => {
      renderForm({ defaultType: 'secret' });

      fireEvent.change(screen.getByPlaceholderText('Item name'), {
        target: { value: 'My Secret' },
      });
      fireEvent.change(screen.getByPlaceholderText('Secret value (API key, token, etc.)'), {
        target: { value: 'sk-value' },
      });

      fireEvent.click(screen.getByText('+ Add Field'));
      const nameInputs = screen.getAllByPlaceholderText('Field name');
      const valueInputs = screen.getAllByPlaceholderText('Value');
      // Whitespace-only name + a value -> stripped (trim().length === 0).
      fireEvent.change(nameInputs[0]!, { target: { value: '   ' } });
      fireEvent.change(valueInputs[0]!, { target: { value: 'ignored' } });

      fireEvent.click(screen.getByRole('button', { name: 'Create' }));

      await waitFor(() => {
        expect(mockCreateItem).toHaveBeenCalledTimes(1);
      });

      const data = mockCreateItem.mock.calls[0]![2] as { customFields: unknown[] };
      expect(data.customFields).toHaveLength(0);
    });
  });
});
