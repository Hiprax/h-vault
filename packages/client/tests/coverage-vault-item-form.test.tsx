import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { VaultItemForm, sanitizeBackupCodes } from '../src/components/vault/VaultItemForm';
import {
  EncryptedFieldTooLargeError,
  VaultItemDataInvalidError,
  type DecryptedVaultItem,
} from '../src/stores/vaultStore';
import { computeItemIdentity } from '../src/services/import/identity';

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

/**
 * The store's `items`, mutable so a suite can stock the vault before rendering.
 *
 * Read fresh inside the selector on every call rather than captured, because the
 * card form derives its saved-address options from it; `beforeEach` empties it so
 * a suite that does not stock the vault sees the real store's initial value.
 */
let mockItems: DecryptedVaultItem[] = [];

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
        items: mockItems,
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

/** An identity item carrying an address, for the saved-address picker suites. */
function identityWithAddress(
  id: string,
  name: string,
  data: Record<string, unknown>,
): DecryptedVaultItem {
  return asItem({ id, itemType: 'identity', name, data, tags: [], favorite: false });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockItems = [];
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

  /**
   * Assert that a stored `expiresAt` is an ABSOLUTE instant whose LOCAL reading is
   * the given wall-clock time.
   *
   * Deliberately not a string comparison: the string depends on the machine's UTC
   * offset, and pinning one would either only pass in a single timezone or (in UTC)
   * pass against the pre-fix code too. Asserting the instant's local components is
   * both timezone-independent and exactly the contract — `formatRemainingTime` and
   * `formatDate` both read the value through `new Date()`.
   */
  function expectLocalInstant(
    value: unknown,
    parts: { year: number; month: number; day: number; hours: number; minutes: number },
  ) {
    expect(typeof value).toBe('string');
    // A full instant, not a zone-less wall-clock reading: the `Z` is what stops the
    // deadline from moving by the browser's offset on the next open-and-save.
    expect(value as string).toMatch(/Z$/);
    const instant = new Date(value as string);
    expect(instant.getFullYear()).toBe(parts.year);
    expect(instant.getMonth()).toBe(parts.month - 1);
    expect(instant.getDate()).toBe(parts.day);
    expect(instant.getHours()).toBe(parts.hours);
    expect(instant.getMinutes()).toBe(parts.minutes);
    expect(instant.getSeconds()).toBe(0);
  }

  it('stores LOCAL midnight as an absolute instant when only an expiry date is given', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2026-01-15' },
    });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    // An empty time control means local midnight of the chosen date — the stated
    // decision, and what picking a bare calendar date means to the person picking it.
    expectLocalInstant(createdData().expiresAt, {
      year: 2026,
      month: 1,
      day: 15,
      hours: 0,
      minutes: 0,
    });
  });

  it('combines the date and time inputs into a single absolute instant', async () => {
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
    expectLocalInstant(createdData().expiresAt, {
      year: 2026,
      month: 1,
      day: 15,
      hours: 9,
      minutes: 30,
    });
  });

  it('REFUSES the save for a year the vault cannot store, rather than dropping the expiry', async () => {
    const value = '275760-09-13';
    // The silent-drop this replaces was reachable: Chrome's date picker accepts years
    // up to 275760, `EXPIRY_DATE_PATTERN` did not match, `combineExpiry` returned
    // `undefined`, and `omitUndefined` removed the key — so a save reported success
    // and deleted the deadline. Now the local schema refuses it with a message on the
    // control, which is also where a store-side `expiresAt` rejection lands.
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, { target: { value } });

    submit();

    await waitFor(() =>
      expect(
        screen.getByText('Enter a date between 0001-01-01 and 9999-12-31'),
      ).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('still omits expiresAt when the date control is simply empty', async () => {
    renderForm({ defaultType: 'secret' });

    fillSecret();
    fireEvent.change(document.getElementById('field-expiryTime')!, { target: { value: '09:30' } });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect('expiresAt' in createdData()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // The round-trip guarantee: an untouched expiry is written back BYTE-IDENTICALLY.
  //
  // The first four rows are the regression tests for the offset shift, verified to
  // fail against the pre-fix `getDefaultValues`/`buildModelledFields` — which captured
  // only the date and `HH:mm` and recombined them as a zone-less `${date}T${time}`,
  // producing a DIFFERENT string in every timezone, UTC included, so they fail
  // everywhere rather than only where the offset happens to be non-zero.
  //
  // The FIFTH row is honestly not one of them: a legacy zone-less `2026-06-15T14:30`
  // is exactly what the old code reconstructed, so it passed before this change too.
  // It is kept as a forward guard — the new code must not "upgrade" such a value to a
  // fresh instant behind the user's back — not as evidence of the defect.
  // -------------------------------------------------------------------------

  it.each([
    ['a UTC instant', '2026-12-31T23:59:00.000Z'],
    ['sub-minute precision', '2026-12-31T23:59:30.500Z'],
    ['a +HH:MM offset', '2026-12-31T18:59:00+02:00'],
    ['a date-only value', '2026-12-31'],
    ['a legacy zone-less datetime', '2026-06-15T14:30'],
  ])('leaves %s untouched when the expiry controls are not edited', async (_label, stored) => {
    renderForm({
      item: asItem({
        id: 'secret-rt',
        itemType: 'secret',
        tags: [],
        favorite: false,
        name: 'API key',
        data: { value: 'sk-123', expiresAt: stored, customFields: [] },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    typeIn('Item name', 'API key (renamed)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    // Byte-identical, not merely "the same instant": that is what keeps seconds, keeps
    // a date-only value date-only, and keeps a re-import of the same file a no-op.
    expect(data.expiresAt).toBe(stored);
  });

  it('shows the stored instant in LOCAL time across the two controls', async () => {
    // A property assertion, not a string one: reading the two control values back as
    // LOCAL time must reproduce the stored instant exactly. Note this particular test
    // is offset-sensitive — under TZ=UTC it holds for the pre-fix code too, which is
    // why the byte-identity cases above are the ones that pin the defect everywhere.
    const stored = '2026-12-31T23:59:00.000Z';
    renderForm({
      item: asItem({
        id: 'secret-local',
        itemType: 'secret',
        tags: [],
        favorite: false,
        name: 'API key',
        data: { value: 'sk-123', expiresAt: stored, customFields: [] },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    const date = (document.getElementById('field-expiryDate') as HTMLInputElement).value;
    const time = (document.getElementById('field-expiryTime') as HTMLInputElement).value;
    const [year, month, day] = date.split('-').map(Number) as [number, number, number];
    const [hours, minutes] = time.split(':').map(Number) as [number, number];
    const asLocal = new Date(0);
    asLocal.setFullYear(year, month - 1, day);
    asLocal.setHours(hours, minutes, 0, 0);
    expect(asLocal.getTime()).toBe(new Date(stored).getTime());
  });

  it('writes a fresh absolute instant once the expiry IS edited', async () => {
    renderForm({
      item: asItem({
        id: 'secret-edit',
        itemType: 'secret',
        tags: [],
        favorite: false,
        name: 'API key',
        data: { value: 'sk-123', expiresAt: '2026-12-31T23:59:00.000Z', customFields: [] },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    fireEvent.change(document.getElementById('field-expiryTime')!, { target: { value: '08:15' } });
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.expiresAt).not.toBe('2026-12-31T23:59:00.000Z');
    expect(data.expiresAt as string).toMatch(/Z$/);
    const instant = new Date(data.expiresAt as string);
    expect(instant.getHours()).toBe(8);
    expect(instant.getMinutes()).toBe(15);
  });

  it('deletes the expiry when the date control is cleared', async () => {
    renderForm({
      item: asItem({
        id: 'secret-clear',
        itemType: 'secret',
        tags: [],
        favorite: false,
        name: 'API key',
        data: { value: 'sk-123', expiresAt: '2026-12-31T23:59:00.000Z', customFields: [] },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    fireEvent.change(document.getElementById('field-expiryDate')!, { target: { value: '' } });
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    // Gone, not `undefined`: `omitUndefined` removes the key so the merge cannot put
    // the old deadline back.
    expect('expiresAt' in data).toBe(false);
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
    expect(createdData()).toEqual({ content: 'plain body', format: 'plaintext' });
    // No `name` inside `data`: the item name is encrypted separately as
    // `encryptedName`, no decrypted data schema declares a `name` key, and every one
    // of them strips it on read-back — so it was dead weight in the ciphertext. The
    // name is still sent, as `createItem`'s own second argument.
    expect(mockCreateItem.mock.calls[0]![1]).toBe('Journal');
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
      street2: '',
      city: 'London',
      state: '',
      zip: '',
      country: '',
    });
  });

  it('includes a billingAddress when the second street line is the ONLY field filled', async () => {
    // `hasBilling` is a disjunction over every billing field. A field appended to it
    // that is never the deciding operand leaves that arm untested AND lets a
    // regression drop a street2-only address (an apartment, a PO box) with no error.
    renderForm({ defaultType: 'card' });

    fillCard();
    fireEvent.click(screen.getByText('+ Add billing address'));
    typeIn('Apartment, suite, unit', 'Apt 4B');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().billingAddress).toEqual({
      street: '',
      street2: 'Apt 4B',
      city: '',
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

  it('clears the second street line too when the section is removed', async () => {
    // Remove() clears each field by name. A field missing from that list keeps its
    // value in form state, so `hasBilling` stays truthy and the NEXT save silently
    // re-encrypts an address the user explicitly deleted.
    renderForm({ defaultType: 'card' });

    fillCard();
    fireEvent.click(screen.getByText('+ Add billing address'));
    typeIn('Apartment, suite, unit', 'Apt 4B');
    fireEvent.click(screen.getByText('Remove'));

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData()).not.toHaveProperty('billingAddress');
  });

  it('expands the billing section for a card whose street line is empty but city is set', () => {
    // The regression test for the collapse defect: the initializer used a `??` chain,
    // and a stored `street: ''` is not nullish, so it short-circuited on the first
    // field and hid a populated address behind "+ Add billing address". The existing
    // test above passes only because its fixture fills `street` first.
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
          billingAddress: {
            street: '',
            street2: '',
            city: 'London',
            state: '',
            zip: '',
            country: '',
          },
        },
        createdAt: '',
        updatedAt: '',
      }),
    });

    expect(screen.getByText('Billing Address')).toBeInTheDocument();
    expect((screen.getByPlaceholderText('City') as HTMLInputElement).value).toBe('London');
  });

  it('expands the billing section for a card whose only billing field is the second line', () => {
    renderForm({
      item: asItem({
        id: 'card-2',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          billingAddress: {
            street: '',
            street2: 'Apt 4B',
            city: '',
            state: '',
            zip: '',
            country: '',
          },
        },
        createdAt: '',
        updatedAt: '',
      }),
    });

    expect(screen.getByText('Billing Address')).toBeInTheDocument();
    expect((screen.getByPlaceholderText('Apartment, suite, unit') as HTMLInputElement).value).toBe(
      'Apt 4B',
    );
  });

  it('keeps a stored second street line through an edit that only renames the card', async () => {
    // The zodResolver trap: the resolver hands `onSubmit` the PARSED values, so a
    // field the local form schema does not declare is stripped and a rename would
    // destroy the stored line with no warning and nothing in password history.
    renderForm({
      item: asItem({
        id: 'card-3',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          expMonth: '12',
          expYear: '2030',
          cvv: '123',
          billingAddress: {
            street: '1 Main St',
            street2: 'Apt 4B',
            city: 'London',
            state: '',
            zip: '',
            country: 'UK',
          },
        },
        createdAt: '',
        updatedAt: '',
      }),
    });

    typeIn('Item name', 'Visa (personal)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.billingAddress).toEqual({
      street: '1 Main St',
      street2: 'Apt 4B',
      city: 'London',
      state: '',
      zip: '',
      country: 'UK',
    });
  });

  it('blocks the save and shows an inline error for an over-long second street line', async () => {
    // The failure this prevents is not a rejected save, it is a SUCCESSFUL one: an
    // over-cap value encrypts fine and then fails `cardDataSchema` on the next
    // decrypt, replacing the whole card (number, CVV and all) with the "could not be
    // fully decoded" notice. And a bound with no VISIBLE message is worse than none:
    // react-hook-form simply never calls onSubmit, so Save becomes a dead button.
    renderForm({ defaultType: 'card' });

    fillCard();
    fireEvent.click(screen.getByText('+ Add billing address'));
    typeIn('Apartment, suite, unit', 'a'.repeat(501));

    submit();

    await waitFor(() =>
      expect(
        screen.getByText('Street address line 2 must be 500 characters or fewer'),
      ).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
    const input = screen.getByPlaceholderText('Apartment, suite, unit');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAttribute('aria-describedby', 'field-billingStreet2-error');
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
          billingAddress: {
            street: '1 Main St',
            street2: '',
            city: '',
            state: '',
            zip: '',
            country: '',
          },
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
      street2: '',
      city: 'London',
      state: '',
      zip: '',
      country: 'UK',
      deliveryNotes: '',
    });
  });

  it('nests the second street line and the delivery notes inside the address', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Street address', '1 Main St');
    typeIn('Apartment, suite, unit', 'Flat 2');
    typeIn('City', 'London');
    typeIn('e.g. leave with the concierge, ring twice', 'Ring twice, gate code 1234');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().address).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: '',
      zip: '',
      country: '',
      deliveryNotes: 'Ring twice, gate code 1234',
    });
  });

  it('keeps a stored second street line and delivery notes through an unrelated edit', async () => {
    renderForm({
      item: asItem({
        id: 'id-1',
        itemType: 'identity',
        tags: [],
        favorite: false,
        name: 'Passport',
        data: {
          firstName: 'Ada',
          lastName: 'Lovelace',
          address: {
            street: '1 Main St',
            street2: 'Flat 2',
            city: 'London',
            state: '',
            zip: 'E1',
            country: 'UK',
            deliveryNotes: 'Ring twice',
          },
        },
        createdAt: '',
        updatedAt: '',
      }),
    });

    // Both inputs are pre-filled from the stored address...
    expect((screen.getByPlaceholderText('Apartment, suite, unit') as HTMLInputElement).value).toBe(
      'Flat 2',
    );
    expect(
      (
        screen.getByPlaceholderText(
          'e.g. leave with the concierge, ring twice',
        ) as HTMLTextAreaElement
      ).value,
    ).toBe('Ring twice');

    // ...and an edit that touches neither preserves both.
    typeIn('Item name', 'Passport (renewed)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.address).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: '',
      zip: 'E1',
      country: 'UK',
      deliveryNotes: 'Ring twice',
    });
  });

  it('gives every address control a maxLength matching its stored bound', () => {
    // `AddressInput` spreads its own attributes and THEN `register(name)`. If a future
    // react-hook-form returned a `maxLength` key of its own (it does when native
    // validation is enabled), the later spread would silently overwrite these and the
    // browser would stop stopping the user before the cap. The schema bound would still
    // block the save, but the first line of defence would be gone with no test noticing.
    renderForm({ defaultType: 'identity' });

    expect(screen.getByPlaceholderText('Street address')).toHaveAttribute('maxlength', '500');
    expect(screen.getByPlaceholderText('Apartment, suite, unit')).toHaveAttribute(
      'maxlength',
      '500',
    );
    expect(screen.getByPlaceholderText('City')).toHaveAttribute('maxlength', '200');
    expect(screen.getByPlaceholderText('State')).toHaveAttribute('maxlength', '200');
    expect(screen.getByPlaceholderText('ZIP code')).toHaveAttribute('maxlength', '20');
    expect(screen.getByPlaceholderText('Country')).toHaveAttribute('maxlength', '100');
    expect(
      screen.getByPlaceholderText('e.g. leave with the concierge, ring twice'),
    ).toHaveAttribute('maxlength', '1000');
  });

  it('blocks the save and shows inline errors for over-long address fields', async () => {
    renderForm({ defaultType: 'identity' });

    fillIdentity();
    typeIn('Apartment, suite, unit', 'a'.repeat(501));
    typeIn('e.g. leave with the concierge, ring twice', 'b'.repeat(1001));

    submit();

    await waitFor(() => {
      expect(
        screen.getByText('Street address line 2 must be 500 characters or fewer'),
      ).toBeInTheDocument();
      expect(
        screen.getByText('Delivery notes must be 1000 characters or fewer'),
      ).toBeInTheDocument();
    });
    expect(mockCreateItem).not.toHaveBeenCalled();
    // The multiline control gets the same error plumbing as the single-line ones.
    const textarea = screen.getByPlaceholderText('e.g. leave with the concierge, ring twice');
    expect(textarea).toHaveAttribute('aria-invalid', 'true');
    expect(textarea).toHaveAttribute('aria-describedby', 'field-deliveryNotes-error');
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
      expect(screen.getByText('Invalid phone number')).toBeInTheDocument();
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
    const [id, type, name, , options] = mockUpdateItem.mock.calls[0]!;
    expect(id).toBe('item-1');
    // Passed explicitly, mirroring `createItem`, so the store's pre-flight schema
    // check no longer depends on finding the row in its own `items` array.
    expect(type).toBe('login');
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

// ---------------------------------------------------------------------------
// Fields the form stores but renders NO control for
//
// `vaultStore.updateItem` encrypts `JSON.stringify(data)` wholesale with no merge
// of its own, so anything `buildDataPayload` omits is destroyed — and in a
// zero-knowledge vault there is no server-side plaintext to recover it from.
// `zodResolver` hands `onSubmit` only the keys the LOCAL form schema declares, so
// before the merge every one of these fields was silently and permanently erased
// by an edit as small as fixing a typo in the city.
//
// Every field below is real: `identityDataSchema` / `cardDataSchema` store them,
// `parsers/bitwarden.ts` populates them on import, and `VaultItemDetail` renders
// `notes`.
// ---------------------------------------------------------------------------

describe('VaultItemForm — preserves fields it renders no control for', () => {
  const IDENTITY_EXTRAS = {
    company: 'Analytical Engines Ltd',
    ssn: '078-05-1120',
    passport: 'X1234567',
    notes: 'Imported from Bitwarden\nTitle: Ms\nMiddle name: Augusta',
    customFields: [{ name: 'Driving licence', value: 'LOVEL753116AA9AB', type: 'text' as const }],
  };

  function identityItem(extra: Record<string, unknown> = {}): DecryptedVaultItem {
    return asItem({
      id: 'identity-1',
      itemType: 'identity',
      tags: [],
      favorite: false,
      name: 'Ada Lovelace',
      data: {
        firstName: 'Ada',
        lastName: 'Lovelace',
        address: {
          street: '12 Analytical Way',
          street2: '',
          city: 'Lodnon',
          state: '',
          zip: 'E1',
          country: 'UK',
          deliveryNotes: '',
        },
        ...IDENTITY_EXTRAS,
        ...extra,
      },
      createdAt: '',
      updatedAt: '',
      _raw: {},
    });
  }

  it('keeps company, ssn, passport, notes and customFields through a rename', async () => {
    renderForm({ item: identityItem() });

    typeIn('Item name', 'Ada Lovelace (work)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.company).toBe(IDENTITY_EXTRAS.company);
    expect(data.ssn).toBe(IDENTITY_EXTRAS.ssn);
    expect(data.passport).toBe(IDENTITY_EXTRAS.passport);
    expect(data.notes).toBe(IDENTITY_EXTRAS.notes);
    expect(data.customFields).toEqual(IDENTITY_EXTRAS.customFields);
  });

  it('keeps them through an edit of a field the form DOES render', async () => {
    // The reported scenario, verbatim: correct a typo in the city and press Update.
    renderForm({ item: identityItem() });

    typeIn('City', 'London');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect((data.address as Record<string, string>).city).toBe('London');
    expect(data.ssn).toBe(IDENTITY_EXTRAS.ssn);
    expect(data.passport).toBe(IDENTITY_EXTRAS.passport);
    expect(data.company).toBe(IDENTITY_EXTRAS.company);
  });

  it("keeps a card's notes, which no card control edits", async () => {
    renderForm({
      item: asItem({
        id: 'card-9',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          expMonth: '12',
          expYear: '2030',
          cvv: '123',
          notes: 'PIN reminder is in the safe',
        },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    typeIn('Item name', 'Visa (personal)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.notes).toBe('PIN reminder is in the safe');
  });

  it('still DELETES a billing address when the section is removed on an edit', async () => {
    // The other half of the merge: a branch that wants a key gone emits `undefined`,
    // and the payload builder drops it. Without that, the merge would put the
    // removed address straight back.
    //
    // Unlike the three above, this one also passed BEFORE the merge existed — there
    // was nothing to put the address back. It guards the merge's blast radius, not
    // the original defect.
    renderForm({
      item: asItem({
        id: 'card-10',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          billingAddress: {
            street: '1 Main St',
            street2: '',
            city: '',
            state: '',
            zip: '',
            country: '',
          },
        },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    fireEvent.click(screen.getByText('Remove'));
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect('billingAddress' in data).toBe(false);
  });

  it('never merges an UNDECODABLE placeholder into the payload', async () => {
    // Unreachable through the UI — `VaultItemDetail` marks Edit unavailable for such
    // an item and `VaultItemPage` refuses to mount the form — so this drives the
    // guard directly. Merging the placeholder would re-encrypt `_validationError`
    // over the item's real ciphertext, which is exactly what `updateItemMeta` exists
    // to prevent.
    //
    // Like the billing-address case above, this passed before the merge existed too
    // (nothing was merged, so nothing leaked). It exists to keep the guard on the
    // merge, which is now the thing that could reintroduce the placeholder.
    renderForm({
      item: asItem({
        id: 'broken-1',
        itemType: 'identity',
        tags: [],
        favorite: false,
        name: 'Broken',
        data: { firstName: 'Ada', notes: 'kept by a control now', _validationError: true },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    typeIn('Item name', 'Broken (renamed)');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    // The marker itself is the thing that must never be re-encrypted. `notes` DOES
    // survive, but through the form control that now renders it, not through the
    // spread — which is why the fixture no longer relies on an unmodelled field to
    // demonstrate the guard.
    expect('_validationError' in data).toBe(false);
  });

  it("blocks the save when a placeholder's stored value exceeds the field's bound", async () => {
    // The other half, and a strictly better outcome than before: an over-cap stored
    // value is now caught INLINE by the mirrored bound, so it cannot be re-encrypted
    // at all. It used to reach `updateItem` and only fail on the next read.
    renderForm({
      item: asItem({
        id: 'broken-2',
        itemType: 'identity',
        tags: [],
        favorite: false,
        name: 'Broken',
        data: { firstName: 'Ada', ssn: 'x'.repeat(500), _validationError: true },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    typeIn('Item name', 'Broken (renamed)');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    submit('Update');

    await waitFor(() =>
      expect(
        screen.getByText('Social Security number must be 20 characters or fewer'),
      ).toBeInTheDocument(),
    );
    expect(mockUpdateItem).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Backup codes — payload level
// ---------------------------------------------------------------------------

describe('VaultItemForm — login backup codes', () => {
  const CODES = ['AAAA-1111', 'BBBB-2222', 'CCCC-3333'];

  function loginItem(data: Record<string, unknown>): DecryptedVaultItem {
    return asItem({
      id: 'item-1',
      itemType: 'login',
      name: 'GitHub',
      tags: [],
      favorite: false,
      data: { username: 'octocat', password: 'p', uris: [], customFields: [], ...data },
      _raw: {},
    });
  }

  function openSection() {
    fireEvent.click(screen.getByRole('button', { name: '+ Add backup codes' }));
  }

  it('sends the pasted codes on the login payload', async () => {
    renderForm();
    typeIn('Item name', 'GitHub');
    openSection();
    typeIn('Paste your backup codes', 'AAAA-1111\nBBBB-2222');
    fireEvent.click(screen.getByRole('button', { name: 'Add codes' }));
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().backupCodes).toEqual(['AAAA-1111', 'BBBB-2222']);
  });

  it('omits the key entirely when the section was never opened', async () => {
    renderForm();
    typeIn('Item name', 'GitHub');
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    // Absent, not `[]` and not `undefined`: an untouched login's ciphertext stays
    // byte-identical to what it was before this field existed.
    expect('backupCodes' in createdData()).toBe(false);
  });

  it('omits the key entirely when every code was deleted before saving', async () => {
    renderForm();
    typeIn('Item name', 'GitHub');
    openSection();
    typeIn('Paste your backup codes', 'AAAA-1111 BBBB-2222');
    fireEvent.click(screen.getByRole('button', { name: 'Add codes' }));
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect('backupCodes' in createdData()).toBe(false);
  });

  it('keeps the stored codes on an update that never touches the section', async () => {
    // The highest-value case here. zodResolver hands `onSubmit` the PARSED values, so
    // if the form schema did not declare `backupCodes` this update would silently
    // destroy every stored code.
    renderForm({ item: loginItem({ backupCodes: CODES }) });
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.backupCodes).toEqual(CODES);
  });

  it('opens the section already expanded when the login being edited has codes', () => {
    renderForm({ item: loginItem({ backupCodes: CODES }) });
    expect(screen.getByRole('list', { name: 'Backup codes' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '+ Add backup codes' })).toBeNull();
  });

  it('keeps the section collapsed when the login being edited has none', () => {
    renderForm({ item: loginItem({}) });
    expect(screen.getByRole('button', { name: '+ Add backup codes' })).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: 'Backup codes' })).toBeNull();
  });

  it('drops the codes from the payload when the section is removed', async () => {
    // Collapsing alone would hide codes that would still be saved.
    renderForm({ item: loginItem({ backupCodes: CODES }) });
    fireEvent.click(screen.getByRole('button', { name: 'Clear all' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect('backupCodes' in data).toBe(false);
  });

  it('returns focus to the add link after the empty section is removed', () => {
    renderForm();
    openSection();
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '+ Add backup codes' }));
  });

  it('offers no backup-codes section for a non-login type', () => {
    renderForm();
    const tablist = screen.getByRole('tablist', { name: 'Item type' });
    fireEvent.click(within(tablist).getByRole('tab', { name: 'Secret' }));
    expect(screen.queryByRole('button', { name: '+ Add backup codes' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// sanitizeBackupCodes — the last line of defence
//
// Unreachable through the editor by design (it refuses anything out of bounds), so
// its bounds are driven directly. A stored value the shared schema rejects would
// make the detail view replace the WHOLE item with the "could not be decoded"
// notice, costing the user UI access to a working account's password.
// ---------------------------------------------------------------------------

describe('sanitizeBackupCodes', () => {
  it('passes valid codes through untouched', () => {
    expect(sanitizeBackupCodes(['AAAA-1111', 'BBBB-2222'])).toEqual(['AAAA-1111', 'BBBB-2222']);
  });

  it('drops empty entries', () => {
    expect(sanitizeBackupCodes(['AAAA-1111', ''])).toEqual(['AAAA-1111']);
  });

  it('drops a code longer than the schema allows', () => {
    expect(sanitizeBackupCodes(['AAAA-1111', 'a'.repeat(129)])).toEqual(['AAAA-1111']);
  });

  it('keeps a code at exactly the length limit', () => {
    expect(sanitizeBackupCodes(['a'.repeat(128)])).toHaveLength(1);
  });

  it('caps the list at the schema maximum', () => {
    expect(sanitizeBackupCodes(Array.from({ length: 60 }, (_, i) => `c${i}`))).toHaveLength(50);
  });

  it('drops non-string entries', () => {
    expect(sanitizeBackupCodes(['AAAA-1111', 42, null, undefined, {}])).toEqual(['AAAA-1111']);
  });

  it('returns an empty list for anything that is not an array', () => {
    expect(sanitizeBackupCodes(undefined)).toEqual([]);
    expect(sanitizeBackupCodes('AAAA-1111')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// An identity's address is emitted ONLY when it has content (P1-B)
//
// `identityDataSchema.address` is `.optional()` with NO default, so an ABSENT
// address and a present all-empty one parse to different objects and therefore
// hash differently. The Bitwarden importer omits the key entirely for a source
// entry with no address (`clampAddress` is reached only when the key exists), so
// emitting it unconditionally changed such an identity's IMPORT IDENTITY on its
// first save — and re-importing the same file then inserted a duplicate.
//
// The first two cases fail against the pre-fix `buildModelledFields`, which
// emitted `address` unconditionally.
// ---------------------------------------------------------------------------

describe('VaultItemForm — identity address is conditional', () => {
  function addressLessIdentity(): DecryptedVaultItem {
    return asItem({
      id: 'identity-noaddr',
      itemType: 'identity',
      tags: [],
      favorite: false,
      name: 'Ada Lovelace',
      // Exactly what `parsers/bitwarden.ts` produces for a source entry with no
      // address: no `address` key at all.
      data: { firstName: 'Ada', lastName: 'Lovelace', customFields: [] },
      createdAt: '',
      updatedAt: '',
      _raw: {},
    });
  }

  it('emits NO address key when an address-less identity is renamed', async () => {
    renderForm({ item: addressLessIdentity() });

    typeIn('Item name', 'Ada Lovelace (work)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect('address' in data).toBe(false);
  });

  it('leaves the import identity of an address-less identity UNCHANGED across an edit', async () => {
    // The consequence, asserted end to end rather than inferred: the key the import
    // resolver matches on has to survive an ordinary rename, or the next import of
    // the same file stops matching and inserts a duplicate identity.
    const item = addressLessIdentity();
    const before = await computeItemIdentity({
      itemType: 'identity',
      name: item.name,
      data: item.data,
    });

    renderForm({ item });
    typeIn('Item name', 'Ada Lovelace');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    const after = await computeItemIdentity({ itemType: 'identity', name: item.name, data });
    expect(after).toBe(before);
  });

  // The MECHANISM the two tests above rest on — that an absent `address` and an
  // all-empty one hash differently, while an absent and an empty `customFields` do
  // not — is pinned on its own in `tests/import/identity.test.ts`, where the
  // identity-hash tests live.

  it('DELETES a stored address when every address field is cleared', async () => {
    renderForm({
      item: asItem({
        id: 'identity-addr',
        itemType: 'identity',
        tags: [],
        favorite: false,
        name: 'Ada',
        data: {
          firstName: 'Ada',
          lastName: 'Lovelace',
          address: {
            street: '1 Main St',
            street2: '',
            city: 'London',
            state: '',
            zip: '',
            country: '',
            deliveryNotes: '',
          },
          customFields: [],
        },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      }),
    });

    typeIn('Street address', '');
    typeIn('City', '');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    // Gone, not an empty husk: `undefined` plus `omitUndefined` is what deletes it,
    // where an omitted key would have let the merge put the old address back.
    expect('address' in data).toBe(false);
  });

  it('still emits the address when a single field has content', async () => {
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    typeIn('e.g. leave with the concierge, ring twice', 'Ring twice');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().address).toEqual({
      street: '',
      street2: '',
      city: '',
      state: '',
      zip: '',
      country: '',
      deliveryNotes: 'Ring twice',
    });
  });
});

// ---------------------------------------------------------------------------
// The six fields that were preserved but neither editable nor visible (P2-C)
//
// NEW BEHAVIOUR, not a regression fix: no control for any of these existed before,
// so these tests could not have failed against the previous code — they assert a
// capability that did not exist. What they DO guard is the trap the capability
// introduces: declaring a field in the local form schema transfers ownership of it
// from `buildDataPayload`'s merge to the form, so a field declared without also
// being read in `getDefaultValues` would be fed back as an empty string and
// destroyed by the first save. Each field therefore gets all three assertions.
// ---------------------------------------------------------------------------

describe('VaultItemForm — newly editable stored fields', () => {
  const IDENTITY_DATA = {
    firstName: 'Ada',
    lastName: 'Lovelace',
    company: 'Analytical Engines Ltd',
    ssn: '078-05-1120',
    passport: 'X1234567',
    notes: 'Imported from Bitwarden',
    customFields: [{ name: 'Driving licence', value: 'LOVEL753116AA9AB', type: 'text' as const }],
  };

  function identityItem(): DecryptedVaultItem {
    return asItem({
      id: 'identity-1',
      itemType: 'identity',
      tags: [],
      favorite: false,
      name: 'Ada Lovelace',
      data: { ...IDENTITY_DATA },
      createdAt: '',
      updatedAt: '',
      _raw: {},
    });
  }

  it.each([
    ['Company', 'Employer or organization', 'Analytical Engines Ltd'],
    ['Social Security Number', 'SSN or national ID', '078-05-1120'],
    ['Passport Number', 'Passport number', 'X1234567'],
    ['Notes', 'Additional notes', 'Imported from Bitwarden'],
  ])('populates the identity %s control from the stored value', (_label, placeholder, value) => {
    renderForm({ item: identityItem() });
    expect((screen.getByPlaceholderText(placeholder) as HTMLInputElement).value).toBe(value);
  });

  it('populates the identity custom-field row from the stored value', () => {
    renderForm({ item: identityItem() });
    expect((screen.getByPlaceholderText('Field name') as HTMLInputElement).value).toBe(
      'Driving licence',
    );
    expect((screen.getByPlaceholderText('Value') as HTMLInputElement).value).toBe(
      'LOVEL753116AA9AB',
    );
  });

  it('round-trips every identity extra through an unrelated edit', async () => {
    renderForm({ item: identityItem() });

    typeIn('Item name', 'Ada Lovelace (work)');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.company).toBe(IDENTITY_DATA.company);
    expect(data.ssn).toBe(IDENTITY_DATA.ssn);
    expect(data.passport).toBe(IDENTITY_DATA.passport);
    expect(data.notes).toBe(IDENTITY_DATA.notes);
    expect(data.customFields).toEqual(IDENTITY_DATA.customFields);
  });

  it.each([
    ['company', 'Employer or organization'],
    ['ssn', 'SSN or national ID'],
    ['passport', 'Passport number'],
    ['notes', 'Additional notes'],
  ])('CLEARING the identity %s removes the key entirely', async (key, placeholder) => {
    renderForm({ item: identityItem() });

    typeIn(placeholder, '');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    // `emptyToUndefined` + `omitUndefined`: an omitted key would let the merge put
    // the old value straight back, so clearing the field would appear to do nothing.
    expect(key in data).toBe(false);
  });

  it('removing the identity custom-field row empties the list', async () => {
    renderForm({ item: identityItem() });

    fireEvent.click(screen.getByLabelText('Remove custom field'));
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.customFields).toEqual([]);
  });

  it('edits an identity extra without disturbing the others', async () => {
    renderForm({ item: identityItem() });

    typeIn('SSN or national ID', '123-45-6789');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.ssn).toBe('123-45-6789');
    expect(data.passport).toBe(IDENTITY_DATA.passport);
    expect(data.company).toBe(IDENTITY_DATA.company);
  });

  it('masks the identity SSN and passport behind a reveal toggle', () => {
    renderForm({ item: identityItem() });

    const ssn = screen.getByPlaceholderText('SSN or national ID') as HTMLInputElement;
    const passport = screen.getByPlaceholderText('Passport number') as HTMLInputElement;
    expect(ssn.type).toBe('password');
    expect(passport.type).toBe('password');

    fireEvent.click(screen.getByRole('button', { name: 'Show Social Security Number' }));
    expect(ssn.type).toBe('text');
    fireEvent.click(screen.getByRole('button', { name: 'Hide Social Security Number' }));
    expect(ssn.type).toBe('password');
  });

  it('round-trips and clears a card note', async () => {
    const card = () =>
      asItem({
        id: 'card-notes',
        itemType: 'card',
        tags: [],
        favorite: false,
        name: 'Visa',
        data: {
          cardholderName: 'Ada',
          number: '4111111111111111',
          notes: 'PIN reminder is in the safe',
        },
        createdAt: '',
        updatedAt: '',
        _raw: {},
      });

    const first = renderForm({ item: card() });
    expect((screen.getByPlaceholderText('Additional notes') as HTMLInputElement).value).toBe(
      'PIN reminder is in the safe',
    );
    typeIn('Item name', 'Visa (personal)');
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect((mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>).notes).toBe(
      'PIN reminder is in the safe',
    );

    first.unmount();
    mockUpdateItem.mockClear();

    renderForm({ item: card() });
    typeIn('Additional notes', '');
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect('notes' in (mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>)).toBe(false);
  });

  it('offers a Boolean custom-field type on an identity but not on a secret', () => {
    const { unmount } = renderForm({ defaultType: 'identity' });
    fireEvent.click(screen.getByText('+ Add Field'));
    expect(screen.getByRole('option', { name: 'Boolean' })).toBeInTheDocument();
    unmount();

    // A secret keeps the narrower two-value enum its local schema has always had,
    // because `SecretDetail` renders no boolean control.
    renderForm({ defaultType: 'secret' });
    fireEvent.click(screen.getByText('+ Add Field'));
    expect(screen.queryByRole('option', { name: 'Boolean' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Stored bounds and formats mirrored into the local schemas (P2-D, first half)
//
// Every one of these used to be enforced ONLY on the way out, so the value was
// accepted, encrypted, and then rejected on the next decrypt — degrading the whole
// item to the "could not be fully decoded" notice. Since the store's write-side
// pre-flight landed they produce a toast instead, which is safe but puts the message
// nowhere near the field. These assert the message is now inline.
// ---------------------------------------------------------------------------

describe('VaultItemForm — stored bounds enforced inline', () => {
  it.each([
    ['Username or email', 'Username must be 500 characters or fewer', 501],
    ['TOTP secret key (optional)', 'TOTP secret must be 500 characters or fewer', 501],
  ])('rejects an over-long login %s inline', async (placeholder, message, length) => {
    renderForm();

    typeIn('Item name', 'GitHub');
    // `maxLength` stops a human typing past the cap, so the value is set directly —
    // which is also how a paste or an autofill can arrive.
    fireEvent.change(screen.getByPlaceholderText(placeholder), {
      target: { value: 'a'.repeat(length) },
    });

    submit();

    await waitFor(() => expect(screen.getByText(message)).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('rejects an over-long card brand inline', async () => {
    renderForm({ defaultType: 'card' });

    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    fireEvent.change(screen.getByPlaceholderText('Visa, Mastercard, etc.'), {
      target: { value: 'b'.repeat(51) },
    });

    submit();

    await waitFor(() =>
      expect(screen.getByText('Brand must be 50 characters or fewer')).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it.each([
    ['a plus sign that is not leading', '12+34'],
    ['punctuation with no digit at all', '(.)'],
  ])('now rejects a phone with %s, which the old local regex admitted', async (_label, value) => {
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    fireEvent.change(screen.getByPlaceholderText('Phone number'), { target: { value } });

    submit();

    await waitFor(() => expect(screen.getByText('Invalid phone number')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('accepts a single-digit phone number, which the stored schema also accepts', async () => {
    // The alignment cuts both ways: the form must not reject what the store accepts,
    // or the user is blocked from saving a value that is perfectly valid. The old
    // local regex required 3+ characters; the shared predicate does not.
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    typeIn('Phone number', '5');

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().phone).toBe('5');
  });

  it('now rejects an email the old local regex admitted', async () => {
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    // Consecutive dots in the local part. It contains no space or stray `@`, so the
    // old `^[^\s@]+@[^\s@]+\.[^\s@]{2,}$` accepted it, and the browser's own
    // `type="email"` check accepts it too — while `identityDataSchema` rejects it.
    // That asymmetry is the whole defect: the value was encrypted and only failed on
    // the next decrypt, degrading the entire identity.
    //
    // (A quoted local part, `"ada"@example.com`, is another such value but cannot be
    // driven through this control: the browser marks it natively invalid and blocks
    // the submit before any of our validation runs.)
    fireEvent.change(screen.getByPlaceholderText('Email address'), {
      target: { value: 'a..b@example.com' },
    });

    submit();

    await waitFor(() => expect(screen.getByText('Invalid email address')).toBeInTheDocument());
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('rejects an over-long custom-field value inline, on the offending row', async () => {
    renderForm();

    typeIn('Item name', 'GitHub');
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByPlaceholderText('Field name'), { target: { value: 'Recovery' } });
    fireEvent.change(screen.getByPlaceholderText('Value'), {
      target: { value: 'c'.repeat(50_001) },
    });

    submit();

    await waitFor(() =>
      expect(screen.getByText('Field value must be 50000 characters or fewer')).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
    expect(screen.getByPlaceholderText('Value')).toHaveAttribute('aria-invalid', 'true');
  });
});

// ---------------------------------------------------------------------------
// A STORE-side rejection lands on its control (P2-D, second half)
//
// `assertValidItemData` throws from the store, not from `zodResolver`, so
// `formState.errors` is empty and nothing was highlighted: the user got only a
// toast, truncated at 200 characters. The mapping has to be explicit because the
// issue paths are STORED-schema paths — binding `address.city` verbatim would
// attach to nothing and render nothing, which is worse than the toast it replaced.
// ---------------------------------------------------------------------------

describe('VaultItemForm — store-side validation errors reach the right control', () => {
  function rejectWith(itemType: 'login' | 'identity' | 'card' | 'secret', path: string) {
    mockCreateItem.mockRejectedValueOnce(
      new VaultItemDataInvalidError(
        itemType,
        [`${path}: Too long`],
        [{ path, message: 'Too long' }],
      ),
    );
  }

  it('puts a top-level issue on that field', async () => {
    rejectWith('login', 'username');
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    const error = await screen.findByText('Too long');
    expect(error.getAttribute('id')).toBe('field-username-error');
    expect(screen.getByPlaceholderText('Username or email')).toHaveAttribute(
      'aria-describedby',
      'field-username-error',
    );
    // Fully accounted for inline, so the toast would be redundant noise.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Item could not be saved' }),
    );
  });

  it('maps a nested identity address path onto the flat control', async () => {
    // Stored `address.city` is the form's `city`. Binding the stored path verbatim
    // would render nothing at all.
    rejectWith('identity', 'address.city');
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    submit();

    const error = await screen.findByText('Too long');
    expect(error.getAttribute('id')).toBe('field-city-error');
    expect(screen.getByPlaceholderText('City')).toHaveAttribute('aria-invalid', 'true');
  });

  it('maps a card billingAddress path onto the prefixed control', async () => {
    rejectWith('card', 'billingAddress.city');
    renderForm({ defaultType: 'card' });

    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    fireEvent.click(screen.getByText('+ Add billing address'));
    submit();

    const error = await screen.findByText('Too long');
    expect(error.getAttribute('id')).toBe('field-billingCity-error');
  });

  it('maps a secret expiresAt onto the date control, which owns the message', async () => {
    rejectWith('secret', 'expiresAt');
    renderForm({ defaultType: 'secret' });

    typeIn('Item name', 'API key');
    typeIn('Secret value (API key, token, etc.)', 'sk-123');
    submit();

    const error = await screen.findByText('Too long');
    expect(error.getAttribute('id')).toBe('field-expiryDate-error');
  });

  it('maps an indexed custom-field path onto that row', async () => {
    rejectWith('login', 'customFields.0.value');
    renderForm();

    typeIn('Item name', 'GitHub');
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByPlaceholderText('Field name'), { target: { value: 'Recovery' } });
    submit();

    await waitFor(() => expect(screen.getByText('Too long')).toBeInTheDocument());
    expect(screen.getByPlaceholderText('Value')).toHaveAttribute('aria-invalid', 'true');
  });

  it('falls back to the toast for a path with no control, rather than failing silently', async () => {
    // A nested address key the form models no control for. Binding it would swallow
    // the message; the toast is the honest channel.
    rejectWith('identity', 'address.somethingElse');
    renderForm({ defaultType: 'identity' });

    typeIn('Item name', 'Ada');
    typeIn('First name', 'Ada');
    typeIn('Last name', 'Lovelace');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
    expect(screen.queryByText('Too long')).toBeNull();
  });

  it('falls back to the toast for a card path outside the billing address', async () => {
    // `billingAddress.deliveryNotes` cannot arise (the base address schema strips the
    // key) and the card form has no `billingDeliveryNotes` control, so one must not
    // be manufactured.
    rejectWith('card', 'billingAddress.deliveryNotes');
    renderForm({ defaultType: 'card' });

    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
  });

  it('maps a top-level path the local schema does not declare to nothing', async () => {
    // `ssn` is not a LOGIN field, so it must not be bound on a login form.
    rejectWith('login', 'ssn');
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
  });

  it('toasts as well when only SOME issues could be mapped', async () => {
    mockCreateItem.mockRejectedValueOnce(
      new VaultItemDataInvalidError(
        'login',
        ['username: Too long'],
        [
          { path: 'username', message: 'Too long' },
          { path: 'nowhere', message: 'Unmappable' },
        ],
      ),
    );
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    // The mappable one is highlighted...
    const error = await screen.findByText('Too long');
    expect(error.getAttribute('id')).toBe('field-username-error');
    // ...and the toast still carries the rest, so nothing is lost.
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Item could not be saved' }),
    );
  });

  it('toasts when the error carries no structured issues at all', async () => {
    // An error constructed without `fieldIssues` (the parameter is optional, so a
    // hand-built instance can produce one).
    mockCreateItem.mockRejectedValueOnce(new VaultItemDataInvalidError('login', ['bad']));
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
  });

  it('caps how many issues it maps and keeps the toast for the overflow', async () => {
    const paths = ['username', 'password', 'totp', 'notes', 'uris', 'customFields'];
    mockCreateItem.mockRejectedValueOnce(
      new VaultItemDataInvalidError(
        'login',
        ['too many'],
        paths.map((path) => ({ path, message: `bad ${path}` })),
      ),
    );
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    // The first five are mapped; the sixth is past the cap, so the toast stays.
    await waitFor(() => expect(screen.getByText('bad username')).toBeInTheDocument());
    expect(screen.queryByText('bad customFields')).toBeNull();
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Item could not be saved' }),
    );
  });
});

// ---------------------------------------------------------------------------
// The mapping must never CLAIM a path it cannot render
//
// Returning a field name for a path with no control is strictly worse than the
// toast it replaces: `setError` on an unbound path swallows the message AND the
// caller then treats the failure as fully reported, so the user gets a Save that
// does nothing and says nothing. The array-length caps are the reachable case —
// they are deliberately not mirrored into the local schemas (no control could show
// an array-level message), so the store's pre-flight is the only thing that reports
// them.
// ---------------------------------------------------------------------------

describe('VaultItemForm — unrenderable issue paths keep the toast', () => {
  function rejectWith(itemType: 'login' | 'secret', path: string) {
    mockCreateItem.mockRejectedValueOnce(
      new VaultItemDataInvalidError(
        itemType,
        [`${path}: Too many`],
        [{ path, message: 'Too many' }],
      ),
    );
  }

  it.each(['customFields', 'uris', 'backupCodes'])(
    'keeps the toast for an array-level issue on %s',
    async (path) => {
      rejectWith('login', path);
      renderForm();

      typeIn('Item name', 'GitHub');
      submit();

      await waitFor(() =>
        expect(mockToast).toHaveBeenCalledWith(
          expect.objectContaining({ title: 'Item could not be saved' }),
        ),
      );
      expect(screen.queryByText('Too many')).toBeNull();
    },
  );

  it('keeps the toast for a leaf below an array that renders no message', async () => {
    // A URI row's `match` and a custom field's `type` are `<select>`s with no error
    // line, so a message bound to one would vanish.
    rejectWith('login', 'uris.0.match');
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
  });

  it('maps an indexed URI issue onto that row, which DOES render one', async () => {
    rejectWith('login', 'uris.0.uri');
    renderForm();

    typeIn('Item name', 'GitHub');
    submit();

    await waitFor(() => expect(screen.getByText('Too many')).toBeInTheDocument());
    // Fully accounted for inline, so no toast.
    expect(mockToast).not.toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Item could not be saved' }),
    );
  });

  it('keeps the toast for a dotted path below a SCALAR the form models flat', async () => {
    rejectWith('secret', 'value.something');
    renderForm({ defaultType: 'secret' });

    typeIn('Item name', 'API key');
    typeIn('Secret value (API key, token, etc.)', 'sk-123');
    submit();

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Item could not be saved' }),
      ),
    );
  });

  it('rejects an uncompilable regex URI inline, as the stored schema would', async () => {
    // `uriEntrySchema` carries a regex-compiles refine that the local schema did not:
    // the pattern passed the form, was encrypted, and only failed on the next decrypt
    // — degrading the whole login to the "could not be fully decoded" notice.
    const { container } = renderForm();

    typeIn('Item name', 'Regex site');
    typeIn('example.com', '^https://[');
    const matchSelect = container.querySelector<HTMLSelectElement>('select[name="uris.0.match"]');
    fireEvent.change(matchSelect!, { target: { value: 'regex' } });

    submit();

    await waitFor(() =>
      expect(screen.getByText('Invalid regular expression pattern')).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('still accepts a VALID regex URI verbatim', async () => {
    const { container } = renderForm();

    typeIn('Item name', 'Regex site');
    typeIn('example.com', '^https://.*\\.example\\.com/');
    const matchSelect = container.querySelector<HTMLSelectElement>('select[name="uris.0.match"]');
    fireEvent.change(matchSelect!, { target: { value: 'regex' } });

    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().uris).toEqual([{ uri: '^https://.*\\.example\\.com/', match: 'regex' }]);
  });
});

// ---------------------------------------------------------------------------
// The AMBIGUOUS hour of a fall-back DST transition
//
// Two distinct instants render to the SAME date + time pair during the repeated
// hour. The "untouched" test therefore compares the CONTROL STRINGS, not the
// instants: an instant comparison can be satisfied by at most one of the two, so
// the other was silently rewritten an hour earlier by a save that touched nothing
// but the name — which also moved the item's import content hash.
//
// This test is written to be meaningful in ANY timezone: it derives the ambiguous
// pair from the running zone rather than hard-coding one, and skips its assertion
// only where no such hour exists (a zone with no DST, e.g. TZ=UTC). Even there the
// no-op assertions below still hold.
// ---------------------------------------------------------------------------

describe('VaultItemForm — a repeated local hour is still untouched', () => {
  /**
   * Two instants one hour apart that render to the same local date and time, or
   * `null` when the running timezone has no such hour in the search window.
   *
   * Scans forward hour by hour looking for a backward jump in the UTC offset; the
   * hour before that jump is repeated. Nothing here duplicates production logic —
   * it only locates an input.
   */
  function findRepeatedHour(): { earlier: Date; later: Date } | null {
    const HOUR = 3_600_000;
    const start = Date.UTC(2026, 0, 1);
    for (let i = 0; i < 365 * 24 * 2; i++) {
      const a = new Date(start + i * HOUR);
      const b = new Date(start + (i + 1) * HOUR);
      // A backward offset jump means b's local reading repeats an earlier one.
      if (b.getTimezoneOffset() > a.getTimezoneOffset()) {
        const earlier = new Date(b.getTime() - HOUR);
        const later = b;
        const sameLocal =
          earlier.getHours() === later.getHours() &&
          earlier.getMinutes() === later.getMinutes() &&
          earlier.getDate() === later.getDate();
        return sameLocal ? { earlier, later } : null;
      }
    }
    return null;
  }

  function secretWith(expiresAt: string): DecryptedVaultItem {
    return asItem({
      id: 'secret-dst',
      itemType: 'secret',
      tags: [],
      favorite: false,
      name: 'API key',
      data: { value: 'sk-123', expiresAt, customFields: [] },
      createdAt: '',
      updatedAt: '',
      _raw: {},
    });
  }

  async function saveUntouched(stored: string): Promise<unknown> {
    const view = renderForm({ item: secretWith(stored) });
    typeIn('Item name', 'API key (renamed)');
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    view.unmount();
    mockUpdateItem.mockClear();
    return data.expiresAt;
  }

  it('writes BOTH readings of a repeated hour back byte-identically', async () => {
    const repeated = findRepeatedHour();
    if (repeated === null) {
      // No DST in this zone (TZ=UTC and friends): there is no ambiguous hour to
      // exercise, and the byte-identity cases elsewhere already cover the rest.
      expect(repeated).toBeNull();
      return;
    }

    // Both instants render to the same controls...
    const { earlier, later } = repeated;
    expect(earlier.getTime()).not.toBe(later.getTime());

    // ...and BOTH must survive an untouched save unchanged. Under an instant
    // comparison one of the two necessarily shifted by an hour.
    expect(await saveUntouched(earlier.toISOString())).toBe(earlier.toISOString());
    expect(await saveUntouched(later.toISOString())).toBe(later.toISOString());
  });
});

// ---------------------------------------------------------------------------
// Filling a card's billing address from an address saved on an identity
//
// The picker's own behaviour (ARIA, keyboard, search, the visible cap) lives in
// `tests/components/SavedAddressPicker.test.tsx`. What is asserted HERE is the
// wiring, which is where a destructive mistake would live: which identities are
// offered at all, which controls are written, which field is deliberately NOT
// written, and what the encrypted payload ends up as.
// ---------------------------------------------------------------------------

/**
 * The picker's own listbox.
 *
 * Every option query has to be scoped through this: the form also renders native
 * `<select>` controls (folder, URI match, custom-field type), and a `<select>`
 * exposes the `combobox` role while its children expose `option` — so an
 * unscoped `getAllByRole('option')` silently counts the folder list too, and an
 * unscoped `getByRole('combobox')` is ambiguous.
 */
function savedAddressListbox(): HTMLElement {
  return screen.getByRole('listbox', { name: 'Saved addresses' });
}

function savedAddressOptions(): HTMLElement[] {
  return within(savedAddressListbox()).getAllByRole('option');
}

function savedAddressSearch(): HTMLElement {
  return screen.getByRole('combobox', { name: 'Search saved addresses' });
}

function openSavedAddressPicker() {
  fireEvent.click(screen.getByRole('button', { name: /use a saved address/i }));
}

/** Open the card form's saved-address picker and choose the named option. */
function fillFromSavedAddress(optionName: RegExp) {
  openSavedAddressPicker();
  fireEvent.click(within(savedAddressListbox()).getByRole('option', { name: optionName }));
}

/** A billing control by its `field-billing*` id, as the address suites do. */
function billingInput(field: string): HTMLInputElement {
  const element = document.getElementById(`field-billing${field}`);
  expect(element).not.toBeNull();
  return element as HTMLInputElement;
}

describe('VaultItemForm — the saved-address picker is offered only when it can help', () => {
  it('is absent for a card when the vault holds no identity at all', () => {
    renderForm({ defaultType: 'card' });

    expect(screen.queryByRole('button', { name: /use a saved address/i })).not.toBeInTheDocument();
  });

  it('is absent when every identity has no address worth copying', () => {
    mockItems = [
      identityWithAddress('i-1', 'Ada', { firstName: 'Ada', lastName: 'Lovelace' }),
      identityWithAddress('i-2', 'Empty', { address: { street: '', city: '' } }),
      // Whitespace is not an address anyone would want copied.
      identityWithAddress('i-3', 'Blank', { address: { street: '   ' } }),
      // Delivery notes alone leave nothing a card can hold.
      identityWithAddress('i-4', 'Notes only', { address: { deliveryNotes: 'Ring twice' } }),
    ];
    renderForm({ defaultType: 'card' });

    expect(screen.queryByRole('button', { name: /use a saved address/i })).not.toBeInTheDocument();
  });

  it('is absent on every item type other than a card', () => {
    mockItems = [identityWithAddress('i-1', 'Home', { address: { street: '1 Main St' } })];

    for (const defaultType of ['login', 'secret', 'note', 'identity'] as const) {
      const { unmount } = renderForm({ defaultType });
      expect(
        screen.queryByRole('button', { name: /use a saved address/i }),
      ).not.toBeInTheDocument();
      unmount();
    }
  });

  it('appears for a card once one identity has an address', () => {
    mockItems = [identityWithAddress('i-1', 'Home', { address: { city: 'London' } })];
    renderForm({ defaultType: 'card' });

    expect(screen.getByRole('button', { name: /use a saved address/i })).toBeInTheDocument();
  });

  it('excludes an identity whose data could not be decoded', () => {
    mockItems = [
      identityWithAddress('i-ok', 'Readable', { address: { city: 'London' } }),
      // `_validationError` marks a placeholder: its `address` is the unvalidated
      // original, so copying it could write a value the card cannot store.
      identityWithAddress('i-bad', 'Unreadable', {
        address: { city: 'Nowhere' },
        _validationError: true,
      }),
      identityWithAddress('i-raw', 'Raw', { _raw: '{"address":{"city":"Nowhere"}}' }),
    ];
    renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    expect(savedAddressOptions()).toHaveLength(1);
    expect(
      within(savedAddressListbox()).getByRole('option', { name: /Readable/ }),
    ).toBeInTheDocument();
  });

  it('offers only identities, never another card that has a billing address', () => {
    mockItems = [
      identityWithAddress('i-1', 'Home', { address: { city: 'London' } }),
      asItem({
        id: 'c-1',
        itemType: 'card',
        name: 'Other Visa',
        data: { billingAddress: { city: 'Paris' } },
        tags: [],
        favorite: false,
      }),
    ];
    renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    expect(savedAddressOptions()).toHaveLength(1);
    expect(within(savedAddressListbox()).getByRole('option', { name: /Home/ })).toBeInTheDocument();
  });

  it('lists the options alphabetically rather than in store order', () => {
    mockItems = [
      identityWithAddress('i-3', 'Zurich flat', { address: { city: 'Zurich' } }),
      identityWithAddress('i-1', 'Amsterdam flat', { address: { city: 'Amsterdam' } }),
      identityWithAddress('i-2', 'Madrid flat', { address: { city: 'Madrid' } }),
    ];
    renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    expect(screen.getAllByTestId('saved-address-option-title').map((el) => el.textContent)).toEqual(
      ['Amsterdam flat', 'Madrid flat', 'Zurich flat'],
    );
  });

  it('falls back to a placeholder title for an identity with a blank name', () => {
    mockItems = [identityWithAddress('i-1', '   ', { address: { city: 'London' } })];
    renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    expect(screen.getByTestId('saved-address-option-title')).toHaveTextContent('Untitled identity');
  });
});

describe('VaultItemForm — filling a card billing address', () => {
  const FULL_IDENTITY = {
    firstName: 'Ada',
    lastName: 'Lovelace',
    address: {
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: 'Greater London',
      zip: 'EC1A 1BB',
      country: 'United Kingdom',
      deliveryNotes: 'Door code 4821',
    },
  };

  beforeEach(() => {
    mockItems = [identityWithAddress('i-home', 'Home address', FULL_IDENTITY)];
  });

  it('opens the collapsed section and writes all six controls', () => {
    renderForm({ defaultType: 'card' });
    expect(screen.queryByPlaceholderText('City')).not.toBeInTheDocument();

    fillFromSavedAddress(/Home address/);

    expect(billingInput('Street')).toHaveValue('1 Main St');
    expect(billingInput('Street2')).toHaveValue('Flat 2');
    expect(billingInput('City')).toHaveValue('London');
    expect(billingInput('State')).toHaveValue('Greater London');
    expect(billingInput('Zip')).toHaveValue('EC1A 1BB');
    expect(billingInput('Country')).toHaveValue('United Kingdom');
  });

  it('confirms the fill and names the identity it came from', () => {
    renderForm({ defaultType: 'card' });

    fillFromSavedAddress(/Home address/);

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: 'Billing address filled',
        type: 'success',
      }),
    );
    const description = (mockToast.mock.calls[0]?.[0] as { description?: string } | undefined)
      ?.description;
    expect(description).toContain('Home address');
    expect(description).toContain('Delivery notes');
  });

  it('never renders the identity delivery notes anywhere in the card form', () => {
    const { container } = renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    expect(container.textContent).not.toContain('Door code');
    expect(container.textContent).not.toContain('4821');

    fireEvent.click(within(savedAddressListbox()).getByRole('option', { name: /Home address/ }));
    expect(container.textContent).not.toContain('Door code');
    expect(container.textContent).not.toContain('4821');
    expect(document.getElementById('field-billingDeliveryNotes')).toBeNull();
  });

  it('is not searchable by the delivery notes either', () => {
    renderForm({ defaultType: 'card' });

    openSavedAddressPicker();
    fireEvent.change(savedAddressSearch(), { target: { value: '4821' } });

    expect(within(savedAddressListbox()).queryAllByRole('option')).toHaveLength(0);
  });

  it('encrypts exactly the six base fields, with no deliveryNotes key', async () => {
    renderForm({ defaultType: 'card' });

    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada Lovelace');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    fillFromSavedAddress(/Home address/);
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));

    const billing = createdData().billingAddress as Record<string, unknown>;
    expect(billing).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: 'Greater London',
      zip: 'EC1A 1BB',
      country: 'United Kingdom',
    });
    expect(billing).not.toHaveProperty('deliveryNotes');
  });

  it('copies a partial address without inventing values for the missing fields', () => {
    mockItems = [
      identityWithAddress('i-partial', 'PO Box', {
        address: { street2: 'PO Box 17', country: 'Ireland' },
      }),
    ];
    renderForm({ defaultType: 'card' });

    fillFromSavedAddress(/PO Box/);

    expect(billingInput('Street')).toHaveValue('');
    expect(billingInput('Street2')).toHaveValue('PO Box 17');
    expect(billingInput('City')).toHaveValue('');
    expect(billingInput('Country')).toHaveValue('Ireland');
  });

  it('replaces what was already typed, including clearing a field the source lacks', () => {
    mockItems = [identityWithAddress('i-partial', 'PO Box', { address: { street2: 'PO Box 17' } })];
    renderForm({ defaultType: 'card' });

    fireEvent.click(screen.getByText('+ Add billing address'));
    fireEvent.change(billingInput('City'), { target: { value: 'Typed by hand' } });

    fillFromSavedAddress(/PO Box/);

    expect(billingInput('Street2')).toHaveValue('PO Box 17');
    expect(billingInput('City')).toHaveValue('');
  });

  it('clears a stale inline error left over from what the user had typed', async () => {
    renderForm({ defaultType: 'card' });

    fireEvent.click(screen.getByText('+ Add billing address'));
    fireEvent.change(billingInput('City'), { target: { value: 'x'.repeat(5_000) } });
    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada Lovelace');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    submit();
    await screen.findByText(/City must be \d+ characters or fewer/);

    fillFromSavedAddress(/Home address/);

    await waitFor(() =>
      expect(screen.queryByText(/City must be \d+ characters or fewer/)).not.toBeInTheDocument(),
    );
    expect(billingInput('City')).toHaveValue('London');
  });

  it('overwrites the billing address of a card being edited, and saves the new one', async () => {
    const card = asItem({
      id: 'card-1',
      itemType: 'card',
      name: 'Visa',
      tags: [],
      favorite: false,
      data: {
        cardholderName: 'Ada Lovelace',
        number: '4111111111111111',
        billingAddress: { street: 'Old Street', city: 'Oldtown' },
      },
    });
    renderForm({ item: card });

    // The section is already open for a card that has an address.
    expect(billingInput('Street')).toHaveValue('Old Street');
    fillFromSavedAddress(/Home address/);
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));

    const data = mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
    expect(data.billingAddress).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: 'Greater London',
      zip: 'EC1A 1BB',
      country: 'United Kingdom',
    });
  });
});

describe('VaultItemForm — keyboard focus follows the billing section', () => {
  /**
   * Both arms of the billing ternary are unkeyed, so switching between them
   * destroys every fiber from index 1 on — including whichever control the user
   * just activated. Left alone, focus falls to `<body>`; inside the create dialog
   * the focus trap listens on the dialog CONTAINER, so a Tab raised on `body`
   * never reaches it and the next Tab escapes the modal entirely.
   */
  beforeEach(() => {
    mockItems = [
      identityWithAddress('i-home', 'Home address', {
        address: { street: '1 Main St', city: 'London' },
      }),
    ];
  });

  it('moves focus into the fields a fill just revealed, never to the body', () => {
    renderForm({ defaultType: 'card' });

    fillFromSavedAddress(/Home address/);

    expect(document.activeElement).toBe(billingInput('Street'));
    expect(document.activeElement).not.toBe(document.body);
  });

  it('moves focus to the street line for a fill into an already-open section too', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));
    // Revealing the section already lands focus on the street line, so move it
    // away first — otherwise this could pass without the fill re-homing anything.
    billingInput('City').focus();
    expect(document.activeElement).toBe(billingInput('City'));

    fillFromSavedAddress(/Home address/);

    expect(document.activeElement).toBe(billingInput('Street'));
  });

  it('moves focus into the section that "+ Add billing address" just revealed', () => {
    renderForm({ defaultType: 'card' });

    fireEvent.click(screen.getByText('+ Add billing address'));

    // That button is in the arm being replaced, so it unmounts itself.
    expect(document.activeElement).toBe(billingInput('Street'));
  });

  it('re-homes focus when an Undo leaves the section open', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));
    fillFromSavedAddress(/Home address/);

    const undo = screen.getByRole('button', { name: /undo fill/i });
    // jsdom does not focus a button on click, so put focus where a real browser
    // would have it — otherwise the assertion below could pass without the fix.
    undo.focus();
    expect(document.activeElement).toBe(undo);

    fireEvent.click(undo);

    // The section stays open, but clearing the fill withdraws the Undo button,
    // which was holding focus.
    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
    expect(document.activeElement).toBe(billingInput('Street'));
  });

  it('hands focus to the reveal link when Remove collapses the section', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));

    fireEvent.click(screen.getByText('Remove'));

    expect(document.activeElement).toBe(screen.getByText('+ Add billing address'));
  });

  it('hands focus to the reveal link when Undo collapses the section', () => {
    renderForm({ defaultType: 'card' });
    fillFromSavedAddress(/Home address/);

    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));

    expect(document.activeElement).toBe(screen.getByText('+ Add billing address'));
  });
});

describe('VaultItemForm — undoing a billing address fill', () => {
  beforeEach(() => {
    mockItems = [
      identityWithAddress('i-home', 'Home address', {
        address: { street: '1 Main St', city: 'London' },
      }),
      identityWithAddress('i-work', 'Work address', {
        address: { street: '10 Tech Park', city: 'Cambridge' },
      }),
    ];
  });

  it('is not offered before any fill has happened', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));

    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
  });

  it('restores exactly what the six controls held beforehand', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));
    fireEvent.change(billingInput('Street'), { target: { value: 'Typed by hand' } });
    fireEvent.change(billingInput('Zip'), { target: { value: '90210' } });

    fillFromSavedAddress(/Home address/);
    expect(billingInput('Street')).toHaveValue('1 Main St');

    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));

    expect(billingInput('Street')).toHaveValue('Typed by hand');
    expect(billingInput('Zip')).toHaveValue('90210');
    expect(billingInput('City')).toHaveValue('');
    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
  });

  it('closes the section again when the fill was what opened it', () => {
    renderForm({ defaultType: 'card' });
    expect(screen.queryByPlaceholderText('City')).not.toBeInTheDocument();

    fillFromSavedAddress(/Home address/);
    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));

    // A true inverse: an empty billing panel the user never asked for would be a
    // leftover, not an undo.
    expect(screen.queryByPlaceholderText('City')).not.toBeInTheDocument();
    expect(screen.getByText('+ Add billing address')).toBeInTheDocument();
  });

  it('leaves the section open when it was already open before the fill', () => {
    renderForm({ defaultType: 'card' });
    fireEvent.click(screen.getByText('+ Add billing address'));
    fireEvent.change(billingInput('Zip'), { target: { value: '90210' } });

    fillFromSavedAddress(/Home address/);
    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));

    expect(billingInput('Zip')).toHaveValue('90210');
  });

  it('withdraws itself the moment the user edits any billing field', () => {
    renderForm({ defaultType: 'card' });
    fillFromSavedAddress(/Home address/);
    expect(screen.getByRole('button', { name: /undo fill/i })).toBeInTheDocument();

    fireEvent.change(billingInput('City'), { target: { value: 'Londonderry' } });

    // The snapshot no longer describes what is on screen, so restoring it would
    // silently discard an edit the user made deliberately.
    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
  });

  it('follows a second fill rather than the first', () => {
    renderForm({ defaultType: 'card' });

    fillFromSavedAddress(/Home address/);
    fillFromSavedAddress(/Work address/);
    expect(billingInput('City')).toHaveValue('Cambridge');

    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));

    expect(billingInput('Street')).toHaveValue('1 Main St');
    expect(billingInput('City')).toHaveValue('London');
  });

  it('marks the applied option in the picker, and stops once it is edited', () => {
    renderForm({ defaultType: 'card' });
    fillFromSavedAddress(/Home address/);

    openSavedAddressPicker();
    expect(
      within(within(savedAddressListbox()).getByRole('option', { name: /Home address/ })).getByText(
        'Currently applied',
      ),
    ).toBeInTheDocument();
    fireEvent.keyDown(savedAddressSearch(), { key: 'Escape' });

    fireEvent.change(billingInput('City'), { target: { value: 'Elsewhere' } });
    openSavedAddressPicker();
    expect(screen.queryByText('Currently applied')).not.toBeInTheDocument();
  });

  it('is forgotten when the section is removed, so re-opening cannot resurrect it', () => {
    renderForm({ defaultType: 'card' });
    fillFromSavedAddress(/Home address/);

    fireEvent.click(screen.getByText('Remove'));
    fireEvent.click(screen.getByText('+ Add billing address'));

    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
    expect(billingInput('Street')).toHaveValue('');
  });

  it('leaves no billingAddress in the payload after a fill is undone', async () => {
    renderForm({ defaultType: 'card' });

    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada Lovelace');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    fillFromSavedAddress(/Home address/);
    fireEvent.click(screen.getByRole('button', { name: /undo fill/i }));
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData()).not.toHaveProperty('billingAddress');
  });

  it('drops the fill when the item type is switched away and back', () => {
    renderForm({ defaultType: 'card' });
    fillFromSavedAddress(/Home address/);
    expect(screen.getByRole('button', { name: /undo fill/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: 'Login' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Card' }));

    expect(screen.queryByRole('button', { name: /undo fill/i })).not.toBeInTheDocument();
  });
});
