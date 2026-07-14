import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { VaultItemForm } from '../src/components/vault/VaultItemForm';
import { EncryptedFieldTooLargeError, type DecryptedVaultItem } from '../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Mocks
//
// The vault store is partially mocked: the real module is kept so the REAL
// `EncryptedFieldTooLargeError` class is used (the form branches on
// `err instanceof EncryptedFieldTooLargeError`), while the hook itself serves a
// fixed state with spy-backed mutators.
// ---------------------------------------------------------------------------

const mockCreateItem = vi.fn<(...args: unknown[]) => Promise<void>>();
const mockUpdateItem = vi.fn<(...args: unknown[]) => Promise<void>>();
const mockToast = vi.fn();

vi.mock('../src/stores/vaultStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/stores/vaultStore')>();
  return {
    ...actual,
    useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) =>
      selector({
        createItem: mockCreateItem,
        updateItem: mockUpdateItem,
        folders: [
          { id: 'folder-1', name: 'Work', sortOrder: 0, createdAt: '', updatedAt: '' },
          { id: 'folder-2', name: 'Personal', sortOrder: 1, createdAt: '', updatedAt: '' },
        ],
      }),
    ),
  };
});

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({ startCountdown: vi.fn(), stopCountdown: vi.fn() }),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const onSaved = vi.fn();
const onCancel = vi.fn();

function renderForm(overrides: Partial<Parameters<typeof VaultItemForm>[0]> = {}) {
  return render(<VaultItemForm onSaved={onSaved} onCancel={onCancel} {...overrides} />);
}

function asItem(partial: Record<string, unknown>): DecryptedVaultItem {
  return partial as unknown as DecryptedVaultItem;
}

/** The decrypted `data` payload handed to createItem. */
function createdData(): Record<string, unknown> {
  const call = mockCreateItem.mock.calls[0];
  expect(call).toBeDefined();
  return call![2] as Record<string, unknown>;
}

/** The options object (folderId/tags/favorite) handed to createItem. */
function createdOptions(): Record<string, unknown> {
  return mockCreateItem.mock.calls[0]![3] as Record<string, unknown>;
}

function submit(label: 'Create' | 'Update' = 'Create') {
  fireEvent.click(screen.getByRole('button', { name: label }));
}

function typeIn(placeholder: string, value: string) {
  fireEvent.change(screen.getByPlaceholderText(placeholder), { target: { value } });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockCreateItem.mockResolvedValue(undefined);
  mockUpdateItem.mockResolvedValue(undefined);
});

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

describe('VaultItemForm — login payload', () => {
  it('sends a normalized URI, and omits blank totp/notes rather than sending empty strings', async () => {
    renderForm();

    typeIn('Item name', 'GitHub');
    typeIn('Username or email', 'octocat');
    typeIn('Password', 'hunter2');
    typeIn('example.com', 'github.com');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));

    const data = createdData();
    expect(data.username).toBe('octocat');
    expect(data.password).toBe('hunter2');
    // A scheme-less URI is normalized to https:// before encryption.
    expect(data.uris).toEqual([{ uri: 'https://github.com', match: 'domain' }]);
    // Empty optional strings become undefined (they must not be persisted as '').
    expect(data.totp).toBeUndefined();
    expect(data.notes).toBeUndefined();
    expect(onSaved).toHaveBeenCalledTimes(1);
  });

  it('keeps non-empty totp and notes on the payload', async () => {
    renderForm();

    typeIn('Item name', 'GitHub');
    typeIn('TOTP secret key (optional)', 'JBSWY3DPEHPK3PXP');
    typeIn('Additional notes', 'recovery codes in safe');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    const data = createdData();
    expect(data.totp).toBe('JBSWY3DPEHPK3PXP');
    expect(data.notes).toBe('recovery codes in safe');
  });

  it('rejects a URI whose scheme is not http/https/mailto', async () => {
    renderForm();

    typeIn('Item name', 'FTP box');
    typeIn('example.com', 'ftp://files.example.com');

    submit();

    await waitFor(() => {
      expect(
        screen.getByText('URI must start with http://, https://, or mailto:'),
      ).toBeInTheDocument();
    });
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('accepts a mailto URI', async () => {
    renderForm();

    typeIn('Item name', 'Support');
    typeIn('example.com', 'mailto:support@example.com');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().uris).toEqual([{ uri: 'mailto:support@example.com', match: 'domain' }]);
  });

  it('skips scheme normalization and scheme validation for a regex match type', async () => {
    const { container } = renderForm();

    typeIn('Item name', 'Regex site');
    typeIn('example.com', '^https://.*\\.example\\.com/.*$');
    const matchSelect = container.querySelector<HTMLSelectElement>('select[name="uris.0.match"]');
    expect(matchSelect).not.toBeNull();
    fireEvent.change(matchSelect!, { target: { value: 'regex' } });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    // Left verbatim: a regex pattern must not be prefixed with https:// nor rejected.
    expect(createdData().uris).toEqual([
      { uri: '^https://.*\\.example\\.com/.*$', match: 'regex' },
    ]);
  });

  it('rejects a URI longer than 2048 characters', async () => {
    renderForm();

    typeIn('Item name', 'Long');
    typeIn('example.com', `https://e.com/${'a'.repeat(2048)}`);

    submit();

    await waitFor(() => expect(screen.getByText('URI too long')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('adds and removes URI rows', async () => {
    renderForm();

    fireEvent.click(screen.getByText('+ Add URI'));
    expect(screen.getAllByPlaceholderText('example.com')).toHaveLength(2);

    fireEvent.click(screen.getAllByLabelText('Remove URI')[1]!);
    expect(screen.getAllByPlaceholderText('example.com')).toHaveLength(1);

    // The removed row is gone from the submitted payload too.
    typeIn('Item name', 'One URI');
    fireEvent.change(screen.getByPlaceholderText('example.com'), {
      target: { value: 'https://a.com' },
    });
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().uris).toHaveLength(1);
  });

  it('toggles the password field between masked and revealed', () => {
    renderForm();

    const password = screen.getByPlaceholderText('Password') as HTMLInputElement;
    expect(password.type).toBe('password');

    fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
    expect(password.type).toBe('text');

    fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
    expect(password.type).toBe('password');
  });

  it('fills the password field from the generator and closes it', async () => {
    const { container } = renderForm();

    fireEvent.click(screen.getByRole('button', { name: 'Generate' }));

    // The generator produces its first password on a short timer.
    await waitFor(() => {
      expect(container.querySelector('code')?.textContent ?? '').not.toBe('');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Use Password' }));

    const password = screen.getByPlaceholderText('Password') as HTMLInputElement;
    // The default generator profile produces a 20-character password.
    expect(password.value).toHaveLength(20);
    expect(screen.queryByRole('button', { name: 'Use Password' })).not.toBeInTheDocument();
  });

  it('stores a boolean custom field as the string "true" when checked', async () => {
    const { container } = renderForm();

    typeIn('Item name', 'Login');
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByPlaceholderText('Field name'), { target: { value: 'Verified' } });

    const typeSelect = container.querySelector<HTMLSelectElement>(
      'select[name="customFields.0.type"]',
    );
    fireEvent.change(typeSelect!, { target: { value: 'boolean' } });

    // The value input is replaced by a checkbox that starts as False.
    expect(screen.queryByPlaceholderText('Value')).not.toBeInTheDocument();
    expect(screen.getByText('False')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByText('True')).toBeInTheDocument();

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().customFields).toEqual([
      { name: 'Verified', value: 'true', type: 'boolean' },
    ]);
  });

  it('removes a custom field row so it is not encrypted', async () => {
    renderForm();

    typeIn('Item name', 'Login');
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByPlaceholderText('Field name'), { target: { value: 'Doomed' } });

    fireEvent.click(screen.getByLabelText('Remove custom field'));
    expect(screen.queryByPlaceholderText('Field name')).not.toBeInTheDocument();

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().customFields).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

describe('VaultItemForm — secret payload', () => {
  function fillSecret() {
    typeIn('Item name', 'API key');
    typeIn('Secret value (API key, token, etc.)', 'sk-123');
  }

  it('defaults the time to midnight when only an expiry date is given', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2026-01-15' },
    });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().expiresAt).toBe('2026-01-15T00:00');
  });

  it('combines the date and time inputs into a single ISO-ish string', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2026-01-15' },
    });
    fireEvent.change(document.getElementById('field-expiryTime')!, {
      target: { value: '09:30' },
    });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().expiresAt).toBe('2026-01-15T09:30');
  });

  it('omits expiresAt entirely when no date is given, even if a time is set', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryTime')!, {
      target: { value: '09:30' },
    });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    const data = createdData();
    expect(data.expiresAt).toBeUndefined();
    expect(data.description).toBeUndefined();
  });

  it('requires a value', async () => {
    renderForm({ defaultType: 'secret' });

    typeIn('Item name', 'API key');
    submit();

    await waitFor(() => expect(screen.getByText('Value is required')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('removes a secret custom field row', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByPlaceholderText('Field name'), { target: { value: 'Env' } });
    fireEvent.click(screen.getByLabelText('Remove custom field'));

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().customFields).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Note
// ---------------------------------------------------------------------------

describe('VaultItemForm — note payload', () => {
  it('persists the chosen plaintext format with the content', async () => {
    const { container } = renderForm({ defaultType: 'note' });

    typeIn('Item name', 'Journal');
    typeIn('Write your note...', 'plain body');
    fireEvent.change(container.querySelector<HTMLSelectElement>('select[name="format"]')!, {
      target: { value: 'plaintext' },
    });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData()).toMatchObject({
      name: 'Journal',
      content: 'plain body',
      format: 'plaintext',
    });
  });

  it('falls back to the editor when Preview is toggled on with empty content', () => {
    renderForm({ defaultType: 'note' });

    fireEvent.click(screen.getByText('Preview'));

    // No content -> the preview pane is not rendered; the textarea stays.
    expect(screen.getByPlaceholderText('Write your note...')).toBeInTheDocument();
    // The toggle still flipped, so it now offers to go back to Edit.
    expect(screen.getByText('Edit')).toBeInTheDocument();
  });

  it('returns to the editor when the preview is toggled back off', () => {
    renderForm({ defaultType: 'note' });

    typeIn('Write your note...', '# Heading');
    fireEvent.click(screen.getByText('Preview'));
    expect(screen.queryByPlaceholderText('Write your note...')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Edit'));
    expect(screen.getByPlaceholderText('Write your note...')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

describe('VaultItemForm — card payload and validation', () => {
  function fillCard(number = '4111111111111111') {
    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada Lovelace');
    typeIn('1234 5678 9012 3456', number);
  }

  it('strips the display spaces from the card number and omits an empty brand', async () => {
    renderForm({ defaultType: 'card' });

    fillCard();
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    const data = createdData();
    expect(data.number).toBe('4111111111111111');
    expect(data.brand).toBeUndefined();
    expect(data).not.toHaveProperty('billingAddress');
  });

  it('includes a billingAddress object when any billing field is filled', async () => {
    renderForm({ defaultType: 'card' });

    fillCard();
    typeIn('Visa, Mastercard, etc.', 'Visa');
    fireEvent.click(screen.getByText('+ Add billing address'));
    typeIn('City', 'London');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    const data = createdData();
    expect(data.brand).toBe('Visa');
    expect(data.billingAddress).toEqual({
      street: '',
      city: 'London',
      state: '',
      zip: '',
      country: '',
    });
  });

  it('drops the billing address again when the section is removed', async () => {
    renderForm({ defaultType: 'card' });

    fillCard();
    fireEvent.click(screen.getByText('+ Add billing address'));
    typeIn('City', 'London');
    fireEvent.click(screen.getByText('Remove'));

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    // Removing the section clears the fields, so no stale billing data is encrypted.
    expect(createdData()).not.toHaveProperty('billingAddress');
  });

  it('expands the billing section on mount when editing a card that has one', () => {
    renderForm({
      item: asItem({
        id: 'card-1',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          billingAddress: { street: '1 Main St', city: '', state: '', zip: '', country: '' },
        },
        createdAt: '',
        updatedAt: '',
      }),
    });

    expect(screen.getByText('Billing Address')).toBeInTheDocument();
    expect((screen.getByPlaceholderText('Street address') as HTMLInputElement).value).toBe(
      '1 Main St',
    );
    // A stored number is re-formatted into 4-digit groups for display.
    expect((screen.getByPlaceholderText('1234 5678 9012 3456') as HTMLInputElement).value).toBe(
      '4111 1111 1111 1111',
    );
  });

  it('warns inline and blocks submit when the card number fails the Luhn check', async () => {
    renderForm({ defaultType: 'card' });

    fillCard('4111111111111112');

    expect(screen.getByText('Card number does not pass Luhn check')).toBeInTheDocument();

    submit();

    await waitFor(() => {
      expect(
        screen.getByText('Card number fails Luhn check — verify the number'),
      ).toBeInTheDocument();
    });
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('shows no Luhn warning for a partial number or a valid one', () => {
    renderForm({ defaultType: 'card' });

    // Fewer than 13 digits: too early to judge.
    typeIn('1234 5678 9012 3456', '411111');
    expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();

    typeIn('1234 5678 9012 3456', '4111111111111111');
    expect(screen.queryByText('Card number does not pass Luhn check')).not.toBeInTheDocument();
  });

  it('rejects a card number shorter than 13 digits', async () => {
    renderForm({ defaultType: 'card' });

    fillCard('411111111111');
    submit();

    await waitFor(() => expect(screen.getByText('Must be at least 13 digits')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('rejects an out-of-range expiry month, a short year and a 2-digit CVV', async () => {
    renderForm({ defaultType: 'card' });

    fillCard();
    typeIn('MM', '13');
    typeIn('YYYY', '20');
    typeIn('CVV', '12');

    submit();

    await waitFor(() => {
      expect(screen.getByText('Invalid month (01-12)')).toBeInTheDocument();
      expect(screen.getByText('Invalid year')).toBeInTheDocument();
      expect(screen.getByText('Must be 3-4 digits')).toBeInTheDocument();
    });
    expect(mockCreateItem).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

describe('VaultItemForm — identity payload and validation', () => {
  function fillIdentity() {
    typeIn('Item name', 'Passport');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
  }

  it('nests the address fields and omits blank email/phone', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Street address', '1 Main St');
    typeIn('City', 'London');
    typeIn('Country', 'UK');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    const data = createdData();
    expect(data.email).toBeUndefined();
    expect(data.phone).toBeUndefined();
    expect(data.address).toEqual({
      street: '1 Main St',
      city: 'London',
      state: '',
      zip: '',
      country: 'UK',
    });
  });

  it('keeps a valid email and phone on the payload', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Email address', 'ada@example.com');
    typeIn('Phone number', '+44 20 7946 0958');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData()).toMatchObject({
      email: 'ada@example.com',
      phone: '+44 20 7946 0958',
    });
  });

  it('rejects a malformed email address', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Email address', 'ada@example');

    submit();

    await waitFor(() => expect(screen.getByText('Invalid email address')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('rejects a phone number with illegal characters', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Phone number', 'call me');

    submit();

    await waitFor(() => {
      expect(screen.getByText('Invalid phone number (3-30 characters)')).toBeInTheDocument();
    });
    expect(mockCreateItem).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Tags, folder, favorite (shared footer)
// ---------------------------------------------------------------------------

describe('VaultItemForm — tags and folder', () => {
  it('adds a tag on Enter, ignores an exact duplicate, and removes it again', async () => {
    renderForm();

    const tagInput = screen.getByPlaceholderText('Add a tag...');

    fireEvent.change(tagInput, { target: { value: 'work' } });
    fireEvent.keyDown(tagInput, { key: 'Enter' });
    expect(screen.getByLabelText('Remove tag work')).toBeInTheDocument();
    expect((tagInput as HTMLInputElement).value).toBe('');

    // A duplicate does not create a second chip.
    fireEvent.change(tagInput, { target: { value: 'work' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(screen.getAllByLabelText(/^Remove tag/)).toHaveLength(1);

    // A second, distinct tag is added via the Add button.
    fireEvent.change(tagInput, { target: { value: 'personal' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(screen.getAllByLabelText(/^Remove tag/)).toHaveLength(2);

    fireEvent.click(screen.getByLabelText('Remove tag work'));
    expect(screen.queryByLabelText('Remove tag work')).not.toBeInTheDocument();

    typeIn('Item name', 'Tagged');
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdOptions().tags).toEqual(['personal']);
  });

  it('refuses to add a tag beyond MAX_TAGS_PER_ITEM', () => {
    const tags = Array.from({ length: 20 }, (_, i) => `t${String(i)}`);
    renderForm({
      item: asItem({
        id: 'i1',
        itemType: 'login',
        tags,
        favorite: false,
        name: 'Full',
        data: {},
        createdAt: '',
        updatedAt: '',
      }),
    });

    expect(screen.getAllByLabelText(/^Remove tag/)).toHaveLength(20);

    const tagInput = screen.getByPlaceholderText('Add a tag...');
    fireEvent.change(tagInput, { target: { value: 'overflow' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));

    expect(screen.getAllByLabelText(/^Remove tag/)).toHaveLength(20);
    expect(screen.queryByLabelText('Remove tag overflow')).not.toBeInTheDocument();
  });

  it('sends the selected folder and favorite flag with a new item', async () => {
    renderForm();

    typeIn('Item name', 'Filed');
    fireEvent.change(document.getElementById('field-folder')!, { target: { value: 'folder-2' } });
    fireEvent.click(screen.getByRole('button', { pressed: false }));

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdOptions()).toEqual({ folderId: 'folder-2', tags: [], favorite: true });
  });

  it('omits folderId entirely for a new item with no folder selected', async () => {
    renderForm();

    typeIn('Item name', 'Unfiled');
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdOptions()).not.toHaveProperty('folderId');
  });
});

// ---------------------------------------------------------------------------
// Update path & error handling
// ---------------------------------------------------------------------------

describe('VaultItemForm — update and error handling', () => {
  const existing = asItem({
    id: 'item-1',
    itemType: 'login',
    folderId: 'folder-1',
    tags: ['important'],
    favorite: true,
    name: 'GitHub',
    data: { username: 'octocat', password: 'pw', uris: [], customFields: [] },
    createdAt: '',
    updatedAt: '',
  });

  it('updates the existing item and sends folderId: null when the folder is cleared', async () => {
    renderForm({ item: existing });

    fireEvent.change(document.getElementById('field-folder')!, { target: { value: '' } });
    typeIn('Item name', 'GitHub (renamed)');

    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const [id, name, , options] = mockUpdateItem.mock.calls[0]!;
    expect(id).toBe('item-1');
    expect(name).toBe('GitHub (renamed)');
    expect(options).toEqual({ folderId: null, tags: ['important'], favorite: true });
    expect(mockCreateItem).not.toHaveBeenCalled();
    expect(mockToast).toHaveBeenCalledWith({ title: 'Item updated', type: 'success' });
    expect(onSaved).toHaveBeenCalledTimes(1);
  });

  it('surfaces an oversize payload with a dedicated toast and does not close the form', async () => {
    mockCreateItem.mockRejectedValueOnce(new EncryptedFieldTooLargeError('data', 600_000, 500_000));
    renderForm();

    typeIn('Item name', 'Huge');
    submit();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Item too large to save',
        description: expect.stringContaining('too large to save') as unknown as string,
        type: 'error',
      });
    });
    expect(onSaved).not.toHaveBeenCalled();
    // The submit button is re-enabled so the user can shrink the item and retry.
    expect(screen.getByRole('button', { name: 'Create' })).not.toBeDisabled();
  });

  it('surfaces a generic save failure with the underlying message', async () => {
    mockCreateItem.mockRejectedValueOnce(new Error('Network unreachable'));
    renderForm();

    typeIn('Item name', 'Doomed');
    submit();

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Failed to save item',
        description: 'Network unreachable',
        type: 'error',
      });
    });
    expect(onSaved).not.toHaveBeenCalled();
  });

  it('disables the submit button while a save is in flight', async () => {
    let release: (() => void) | undefined;
    mockCreateItem.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    renderForm();

    typeIn('Item name', 'Slow');
    submit();

    const saving = await screen.findByRole('button', { name: 'Saving...' });
    expect(saving).toBeDisabled();

    release!();
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
  });

  it('keeps type tabs interactive for new items and resets fields on a type switch', async () => {
    renderForm();

    typeIn('Username or email', 'octocat');
    const tablist = screen.getByRole('tablist', { name: 'Item type' });
    fireEvent.click(within(tablist).getByRole('tab', { name: 'Note' }));
    fireEvent.click(within(tablist).getByRole('tab', { name: 'Login' }));

    // Switching type resets the form to that type's defaults, so the stale
    // username must not survive back into the login payload.
    expect((screen.getByPlaceholderText('Username or email') as HTMLInputElement).value).toBe('');

    typeIn('Item name', 'Fresh');
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(mockCreateItem.mock.calls[0]![0]).toBe('login');
    expect(createdData().username).toBe('');
  });
});
