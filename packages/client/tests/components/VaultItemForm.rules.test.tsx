/**
 * The item editor's 0.18.0 rules, each pinned through the rendered form:
 *
 *  - untouched stored values never block a save, and round-trip byte for byte
 *    (card number, expiry, CVV, cardholder, an empty note);
 *  - an incomplete date or time control is refused instead of reading as "none";
 *  - notes and cards carry custom fields, stored as `undefined` when there are none;
 *  - the custom-field limit (counter, a non-adding Add, the over-limit notice);
 *  - the TOTP value is checked by the app's own parser;
 *  - the item name rules, the tag messages, the summary and the DOM-order focus.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MAX_ITEM_NAME_BYTES, MAX_TAGS_PER_ITEM } from '@hvault/shared';
import { VaultItemForm } from '../../src/components/vault/VaultItemForm';
import type { DecryptedVaultItem } from '../../src/stores/vaultStore';

const mockCreateItem = vi.fn<(...args: unknown[]) => Promise<void>>();
const mockUpdateItem = vi.fn<(...args: unknown[]) => Promise<void>>();
const mockToast = vi.fn();

vi.mock('../../src/stores/vaultStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/stores/vaultStore')>();
  return {
    ...actual,
    useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) =>
      selector({
        createItem: mockCreateItem,
        updateItem: mockUpdateItem,
        folders: [],
        items: [],
      }),
    ),
  };
});

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
}));

vi.mock('../../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({
    autoLockTimeout: 15,
    clipboardClearTimeout: 30,
    theme: 'system',
    defaultPasswordOptions: {
      length: 20,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: false,
      minUppercase: 0,
      minLowercase: 0,
      minNumbers: 1,
      minSymbols: 1,
    },
  }),
}));

vi.mock('../../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({ startCountdown: vi.fn(), stopCountdown: vi.fn() }),
}));

const onSaved = vi.fn();
const onCancel = vi.fn();

function renderForm(overrides: Partial<Parameters<typeof VaultItemForm>[0]> = {}) {
  return render(<VaultItemForm onSaved={onSaved} onCancel={onCancel} {...overrides} />);
}

function stored(
  itemType: string,
  data: Record<string, unknown>,
  name = 'Stored',
): DecryptedVaultItem {
  return {
    id: '507f1f77bcf86cd799439011',
    itemType,
    name,
    data,
    tags: [],
    favorite: false,
    createdAt: '',
    updatedAt: '',
    _raw: {},
  } as unknown as DecryptedVaultItem;
}

function typeIn(placeholder: string, value: string) {
  fireEvent.change(screen.getByPlaceholderText(placeholder), { target: { value } });
}

function submit(label: 'Create' | 'Update' = 'Create') {
  fireEvent.click(screen.getByRole('button', { name: label }));
}

function createdData(): Record<string, unknown> {
  return mockCreateItem.mock.calls[0]![2] as Record<string, unknown>;
}

function updatedData(): Record<string, unknown> {
  return mockUpdateItem.mock.calls[0]![3] as Record<string, unknown>;
}

/**
 * Let every pending check finish: react-hook-form validates asynchronously, so a
 * message that WOULD appear needs a turn of the event loop before its absence means
 * anything.
 */
async function settle() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

const NAME_THIS_FIELD = 'Give this field a name, or remove it';
const WRITE_THE_NOTE = 'Write the note, or add a custom field';
const BAD_EMAIL = 'Enter a valid email address, like name@example.com';

/** Mark a date or time control as holding a half-typed value, as a browser does. */
function makeIncomplete(element: HTMLElement) {
  Object.defineProperty(element, 'validity', {
    configurable: true,
    value: { badInput: true },
  });
}

beforeEach(() => {
  mockCreateItem.mockReset().mockResolvedValue(undefined);
  mockUpdateItem.mockReset().mockResolvedValue(undefined);
  mockToast.mockReset();
  onSaved.mockReset();
});

describe('card number: untouched stored values round-trip byte for byte', () => {
  it.each([
    ['a 20-digit number the formatter used to cut to 19', '41111111111111111234'],
    ['a dashed number', '4111-1111-1111-1111'],
    ['a spaced number', '4111 1111 1111 1111'],
    ['a number with trailing text', '4111111111111111 old'],
  ])('keeps %s when only the notes change', async (_label, number) => {
    renderForm({
      item: stored('card', {
        cardholderName: 'Ada Lovelace',
        number,
        expMonth: '',
        expYear: '',
        cvv: '',
      }),
    });

    fireEvent.change(screen.getByPlaceholderText('Additional notes'), {
      target: { value: 'renewed' },
    });
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().number).toBe(number);
    expect(updatedData().notes).toBe('renewed');
  });

  it('shows a clean stored number grouped, and a messy one exactly as stored', () => {
    const { unmount } = renderForm({
      item: stored('card', { cardholderName: 'A', number: '4111111111111111' }),
    });
    expect(screen.getByPlaceholderText('1234 5678 9012 3456')).toHaveValue('4111 1111 1111 1111');
    unmount();

    renderForm({ item: stored('card', { cardholderName: 'A', number: '41111111111111111234' }) });
    expect(screen.getByPlaceholderText('1234 5678 9012 3456')).toHaveValue('41111111111111111234');
  });

  it('stores the digits of a number the person changed', async () => {
    renderForm({ item: stored('card', { cardholderName: 'A', number: '4111-1111-1111-1111' }) });

    typeIn('1234 5678 9012 3456', '5500 0000 0000 0004');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().number).toBe('5500000000000004');
  });
});

describe('untouched stored values never block a save', () => {
  it('saves an imported card with only a month, no cardholder and a 2-digit CVV', async () => {
    renderForm({
      item: stored('card', {
        cardholderName: '',
        number: '4111111111111111',
        expMonth: '7',
        expYear: '',
        cvv: '12',
      }),
    });

    // Rename only.
    typeIn('Item name', 'Renamed card');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = updatedData();
    expect(data.expMonth).toBe('7');
    expect(data.expYear).toBe('');
    expect(data.cvv).toBe('12');
    expect(data.cardholderName).toBe('');
    expect(screen.queryByText('Add the expiry year too')).not.toBeInTheDocument();
  });

  it('keeps an untouched stored 2-digit year as it is', async () => {
    renderForm({
      item: stored('card', {
        cardholderName: 'A',
        number: '4111111111111111',
        expMonth: '01',
        expYear: '27',
      }),
    });
    const year = screen.getByPlaceholderText('YYYY');
    // Visiting the field without changing it does not rewrite it.
    fireEvent.focus(year);
    fireEvent.blur(year);
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().expYear).toBe('27');
    expect(year).toHaveValue('27');
  });

  it('still applies the rules to a value the person changes', async () => {
    renderForm({
      item: stored('card', {
        cardholderName: 'A',
        number: '4111111111111111',
        expMonth: '7',
        cvv: '12',
      }),
    });

    typeIn('CVV', '1');
    submit('Update');

    expect(await screen.findByText('CVV must be 3 or 4 digits')).toBeInTheDocument();
    expect(mockUpdateItem).not.toHaveBeenCalled();
  });

  it('saves a stored note that is nothing but custom fields when it is renamed', async () => {
    renderForm({
      item: stored('note', {
        content: '',
        format: 'plaintext',
        customFields: [{ name: 'PIN', value: '1234', type: 'hidden' }],
      }),
    });

    typeIn('Item name', 'Renamed note');
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().customFields).toEqual([{ name: 'PIN', value: '1234', type: 'hidden' }]);
    expect(updatedData().content).toBe('');
  });

  it('saves an untouched empty stored note, but not a new one', async () => {
    const { unmount } = renderForm({ item: stored('note', { content: '', format: 'markdown' }) });
    typeIn('Item name', 'Renamed');
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect('customFields' in updatedData()).toBe(false);
    unmount();

    renderForm({ defaultType: 'note' });
    typeIn('Item name', 'Empty');
    submit();
    expect(await screen.findByText(WRITE_THE_NOTE)).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('lets an untouched stored blank name be saved, but refuses a typed blank one', async () => {
    const { unmount } = renderForm({ item: stored('login', { username: 'ada' }, '   ') });
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    unmount();

    renderForm({ item: stored('login', { username: 'ada' }, 'Bank') });
    typeIn('Item name', '   ');
    submit('Update');
    expect(await screen.findByText('Name is required')).toBeInTheDocument();
    expect(mockUpdateItem).toHaveBeenCalledTimes(1);
  });
});

describe('item name', () => {
  it('refuses a whitespace-only name on a new item', async () => {
    renderForm();
    typeIn('Item name', '   ');
    submit();

    expect(await screen.findByText('Name is required')).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('refuses a name whose UTF-8 bytes exceed what its ciphertext can hold, and accepts the limit', async () => {
    renderForm();
    const input = screen.getByPlaceholderText('Item name');
    expect(input).toHaveAttribute('maxlength', String(MAX_ITEM_NAME_BYTES));

    // 376 two-byte characters: 752 bytes, two over.
    fireEvent.change(input, { target: { value: 'é'.repeat(376) } });
    submit();
    expect(
      await screen.findByText('Name is too long. Shorten it to save this item.'),
    ).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();

    // Exactly the limit is fine.
    fireEvent.change(input, { target: { value: 'é'.repeat(375) } });
    submit();
    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
  });
});

describe('incomplete date and time controls', () => {
  function fillSecret() {
    typeIn('Item name', 'API key');
    typeIn('Secret value (API key, token, etc.)', 'sk-123');
  }

  it('refuses a half-typed date when the control is left, instead of saving no expiry', async () => {
    renderForm({ defaultType: 'secret' });
    fillSecret();

    const date = document.getElementById('field-expiryDate')!;
    makeIncomplete(date);
    fireEvent.blur(date);

    expect(await screen.findByText('Enter a complete date, or clear it')).toBeInTheDocument();
    submit();
    await waitFor(() =>
      expect(screen.getByText(/1 field needs your attention/)).toBeInTheDocument(),
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('refuses a half-typed time as soon as the control is left', async () => {
    renderForm({ defaultType: 'secret' });
    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2030-01-02' },
    });
    const time = document.getElementById('field-expiryTime')!;
    makeIncomplete(time);
    fireEvent.blur(time);

    expect(await screen.findByText('Enter a complete time, or clear it')).toBeInTheDocument();
    expect(time).toHaveAttribute('aria-invalid', 'true');
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('refuses a half-typed time on save even when the control was never left', async () => {
    renderForm({ defaultType: 'secret' });
    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2030-01-02' },
    });
    makeIncomplete(document.getElementById('field-expiryTime')!);

    submit();

    expect(await screen.findByText('Enter a complete time, or clear it')).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('withdraws the refusal once the half-typed control is cleared', async () => {
    renderForm({ defaultType: 'secret' });
    fillSecret();
    const date = document.getElementById('field-expiryDate')! as HTMLInputElement;
    makeIncomplete(date);
    fireEvent.blur(date);
    await screen.findByText('Enter a complete date, or clear it');

    // Cleared: no longer a bad input, and its value is empty again.
    Object.defineProperty(date, 'validity', { configurable: true, value: { badInput: false } });
    fireEvent.blur(date);
    await waitFor(() =>
      expect(screen.queryByText('Enter a complete date, or clear it')).not.toBeInTheDocument(),
    );

    submit();
    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect('expiresAt' in createdData()).toBe(false);
  });

  it('removes a stored expiry when only its date is cleared', async () => {
    renderForm({
      item: stored('secret', {
        value: 'sk',
        expiresAt: '2030-06-15T09:30:00.000Z',
        customFields: [],
      }),
    });
    fireEvent.change(document.getElementById('field-expiryDate')!, { target: { value: '' } });
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect('expiresAt' in updatedData()).toBe(false);
  });

  it('says when a secret expiry is already in the past, and still saves', async () => {
    renderForm({ defaultType: 'secret' });
    fillSecret();
    fireEvent.change(document.getElementById('field-expiryDate')!, {
      target: { value: '2001-01-01' },
    });

    expect(
      screen.getByText('This date has passed, so the secret will show as expired.'),
    ).toBeInTheDocument();
    submit();
    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
  });
});

describe('custom fields on notes and cards', () => {
  it('saves a note with custom fields, booleans included', async () => {
    renderForm({ defaultType: 'note' });
    typeIn('Item name', 'Wi-Fi');
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByLabelText('Custom field 1 name'), { target: { value: 'SSID' } });
    fireEvent.change(screen.getByLabelText('Custom field 1 value'), { target: { value: 'home' } });
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByLabelText('Custom field 2 name'), { target: { value: 'Guest' } });
    fireEvent.change(screen.getByLabelText('Custom field 2 type'), {
      target: { value: 'boolean' },
    });
    fireEvent.click(screen.getByRole('checkbox'));
    // A note may be nothing but its fields.
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().customFields).toEqual([
      { name: 'SSID', value: 'home', type: 'text' },
      { name: 'Guest', value: 'true', type: 'boolean' },
    ]);
    expect(createdData().content).toBe('');
  });

  it('stores no customFields key for a card without fields', async () => {
    renderForm({ defaultType: 'card' });
    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada');
    typeIn('1234 5678 9012 3456', '4111111111111111');
    submit();

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect('customFields' in createdData()).toBe(false);
  });

  it('deletes a card list whose last field was removed', async () => {
    renderForm({
      item: stored('card', {
        cardholderName: 'A',
        number: '4111111111111111',
        customFields: [{ name: 'Branch', value: 'Main', type: 'text' }],
      }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Remove custom field' }));
    submit('Update');

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect('customFields' in updatedData()).toBe(false);
  });
});

describe('the custom-field limit', () => {
  it('counts the fields against the limit and stops adding at it', () => {
    renderForm({ customFieldsLimit: 2 });

    expect(screen.getByText('(0 of 2)')).toBeInTheDocument();
    const add = screen.getByText('+ Add Field');
    fireEvent.click(add);
    fireEvent.click(add);
    expect(screen.getByText('(2 of 2)')).toBeInTheDocument();
    expect(add).toHaveAttribute('aria-disabled', 'true');
    expect(add).toHaveAttribute('aria-describedby', 'custom-fields-limit-help');
    expect(screen.getByText('An entry can have up to 2 custom fields.')).toBeInTheDocument();

    // Pressing it does nothing; it stays focusable so the reason stays reachable.
    fireEvent.click(add);
    expect(screen.getAllByPlaceholderText('Field name')).toHaveLength(2);
    expect(add).not.toHaveAttribute('disabled');
  });

  it('keeps every field of an entry already over the limit, and says so', async () => {
    const fields = [1, 2, 3].map((n) => ({ name: `F${String(n)}`, value: 'v', type: 'text' }));
    renderForm({
      customFieldsLimit: 2,
      item: stored('login', { username: 'ada', customFields: fields }),
    });

    expect(screen.getByText('(3 of 2)')).toBeInTheDocument();
    expect(
      screen.getByText(
        'This entry has 3 custom fields, more than the limit of 2. It keeps all of them, but no more can be added until it has fewer than 2.',
      ),
    ).toBeInTheDocument();

    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().customFields).toEqual(fields);
  });

  it('enables adding again once the entry is under the limit', () => {
    const fields = [1, 2].map((n) => ({ name: `F${String(n)}`, value: 'v', type: 'text' }));
    renderForm({ customFieldsLimit: 2, item: stored('login', { customFields: fields }) });

    const add = screen.getByText('+ Add Field');
    expect(add).toHaveAttribute('aria-disabled', 'true');
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove custom field' })[0]!);
    expect(add).not.toHaveAttribute('aria-disabled');
    expect(screen.queryByText(/custom fields\.$/)).not.toBeInTheDocument();
  });

  it('applies the documented default when the host passes none', () => {
    renderForm();
    expect(screen.getByText('(0 of 30)')).toBeInTheDocument();
  });

  it('clears a nameless-field error as soon as the row has no content again', async () => {
    renderForm();
    typeIn('Item name', 'X');
    fireEvent.click(screen.getByText('+ Add Field'));
    const value = screen.getByLabelText('Custom field 1 value');
    fireEvent.change(value, { target: { value: 'orphan' } });
    submit();
    await screen.findByText('Give this field a name, or remove it');

    fireEvent.change(value, { target: { value: '' } });
    await waitFor(() =>
      expect(screen.queryByText('Give this field a name, or remove it')).not.toBeInTheDocument(),
    );
  });
});

describe('TOTP', () => {
  it('refuses a new value the TOTP parser cannot use, with its reason', async () => {
    renderForm();
    typeIn('Item name', 'Site');
    typeIn('TOTP secret key (optional)', 'not base32!');
    submit();

    expect(await screen.findByText('Invalid TOTP secret (not valid base32)')).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it.each([
    ['a base32 secret', 'JBSWY3DPEHPK3PXP'],
    ['an otpauth link', 'otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP'],
  ])('accepts %s', async (_label, totp) => {
    renderForm();
    typeIn('Item name', 'Site');
    typeIn('TOTP secret key (optional)', totp);
    submit();
    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().totp).toBe(totp);
  });

  it('warns about, but saves, an untouched stored TOTP that cannot generate codes', async () => {
    renderForm({ item: stored('login', { username: 'ada', totp: 'bad secret' }) });

    expect(
      screen.getByText(
        'Invalid TOTP secret (not valid base32), so no codes can be generated from it.',
      ),
    ).toBeInTheDocument();
    submit('Update');
    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    expect(updatedData().totp).toBe('bad secret');
  });
});

describe('tags', () => {
  it('says why a duplicate tag was not added, and clears the note on typing', () => {
    renderForm();
    const input = screen.getByPlaceholderText('Add a tag...');
    fireEvent.change(input, { target: { value: 'work' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    fireEvent.change(input, { target: { value: 'work' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(screen.getByText('That tag is already on this item.')).toBeInTheDocument();
    expect(input).toHaveAttribute('aria-describedby', 'field-tags-notice');
    expect(screen.getAllByText('work')).toHaveLength(1);

    fireEvent.change(input, { target: { value: 'home' } });
    expect(screen.queryByText('That tag is already on this item.')).not.toBeInTheDocument();
  });

  it('says so at the tag limit instead of silently dropping the tag', () => {
    renderForm({
      item: {
        ...stored('login', { username: 'a' }),
        tags: Array.from({ length: MAX_TAGS_PER_ITEM }, (_, i) => `t${String(i)}`),
      } as DecryptedVaultItem,
    });
    const input = screen.getByPlaceholderText('Add a tag...');
    fireEvent.change(input, { target: { value: 'one-more' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));

    expect(
      screen.getByText(`An item can have up to ${String(MAX_TAGS_PER_ITEM)} tags.`),
    ).toBeInTheDocument();
    expect(screen.queryByText('one-more')).not.toBeInTheDocument();
    // The typed tag is kept, so nothing the person typed is lost.
    expect(input).toHaveValue('one-more');
  });
});

describe('the summary and focus after a refused save', () => {
  it('counts one field in the singular and focuses it', async () => {
    renderForm();
    submit();

    expect(
      await screen.findByText('1 field needs your attention before this item can be saved.'),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByPlaceholderText('Item name')),
    );
  });

  it('focuses the first invalid control in SCREEN order, not registration order', async () => {
    renderForm({ defaultType: 'card' });
    typeIn('Item name', 'Visa');
    typeIn('Name on card', 'Ada');
    // The number is registered LAST (its own controller), but comes before the month
    // on screen.
    typeIn('1234 5678 9012 3456', '4111');
    typeIn('MM', '13');
    submit();

    await screen.findByText('Card numbers have 12 to 19 digits');
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByPlaceholderText('1234 5678 9012 3456')),
    );
  });

  it('focuses the first problem on the form, not a field already flagged when it was left', async () => {
    // The order a real browser produces: the email is changed and left (it is
    // flagged right then), and only afterwards is Create pressed.
    renderForm({ defaultType: 'identity' });
    const email = screen.getByPlaceholderText('Email address');
    fireEvent.change(email, { target: { value: 'not-an-email' } });
    fireEvent.blur(email);
    await screen.findByText('Enter a valid email address, like name@example.com');

    submit();

    await screen.findByText('Name is required');
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByPlaceholderText('Item name')),
    );
    expect(document.activeElement).not.toBe(email);
  });

  it('hides the summary once every problem is fixed', async () => {
    renderForm();
    submit();
    await screen.findByText(/1 field needs your attention/);

    typeIn('Item name', 'Fixed');
    await waitFor(() => expect(screen.queryByText(/needs your attention/)).not.toBeInTheDocument());
  });
});

describe('when a field is checked before a save', () => {
  it('keeps focus in the field while a button or checkbox is pressed, and nowhere else', () => {
    // Taking focus at the press would check the field being left between the press
    // and its release, and what that check shows can move the pressed button out
    // from under the pointer. `fireEvent` answers false when the default action (the
    // focus move) was prevented.
    renderForm({ defaultType: 'note' });
    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByLabelText('Custom field 1 type'), {
      target: { value: 'boolean' },
    });

    expect(fireEvent.mouseDown(screen.getByRole('button', { name: 'Create' }))).toBe(false);
    expect(fireEvent.mouseDown(screen.getByText('+ Add Field'))).toBe(false);
    expect(fireEvent.mouseDown(screen.getByRole('checkbox'))).toBe(false);
    // The text beside the checkbox, inside its label.
    expect(fireEvent.mouseDown(screen.getByText('False'))).toBe(false);
    // A label around a button: "Mark as favorite" is pressed as often as its star.
    expect(fireEvent.mouseDown(screen.getByText('Mark as favorite'))).toBe(false);
    // A label naming a field does not keep focus: pressing it moves to its field.
    expect(fireEvent.mouseDown(screen.getByText('Tags'))).toBe(true);
    // Fields and lists take focus as usual.
    expect(fireEvent.mouseDown(screen.getByPlaceholderText('Item name'))).toBe(true);
    expect(fireEvent.mouseDown(screen.getByLabelText('Custom field 1 type'))).toBe(true);
    expect(fireEvent.mouseDown(screen.getByLabelText('Custom field 1 name'))).toBe(true);
  });

  it('checks a changed field as soon as it is left by the keyboard', async () => {
    renderForm({ defaultType: 'identity' });
    const email = screen.getByPlaceholderText('Email address');
    fireEvent.change(email, { target: { value: 'not-an-email' } });
    fireEvent.blur(email);
    expect(await screen.findByText(BAD_EMAIL)).toBeInTheDocument();
  });

  it('does not ask for the expiry year when only the month was typed and left', async () => {
    renderForm({ defaultType: 'card' });
    const month = screen.getByPlaceholderText('MM');
    fireEvent.change(month, { target: { value: '1' } });
    fireEvent.blur(month);
    const year = screen.getByPlaceholderText('YYYY');
    fireEvent.focus(year);
    fireEvent.blur(year);
    await settle();
    expect(screen.queryByText('Add the expiry year too')).not.toBeInTheDocument();

    submit();
    expect(await screen.findByText('Add the expiry year too')).toBeInTheDocument();
  });

  it('does not ask for a row name while its value is still being typed', async () => {
    renderForm();
    typeIn('Item name', 'Site');
    fireEvent.click(screen.getByText('+ Add Field'));
    // Adding the row focused its name; the person moves on to the value.
    fireEvent.blur(screen.getByLabelText('Custom field 1 name'));
    fireEvent.change(screen.getByLabelText('Custom field 1 value'), {
      target: { value: 'orphan' },
    });
    await settle();
    expect(screen.queryByText(NAME_THIS_FIELD)).not.toBeInTheDocument();

    submit();
    expect(await screen.findByText(NAME_THIS_FIELD)).toBeInTheDocument();
    expect(mockCreateItem).not.toHaveBeenCalled();
  });

  it('clears "write the note" as soon as a custom field is named', async () => {
    renderForm({ defaultType: 'note' });
    typeIn('Item name', 'Wi-Fi');
    submit();
    await screen.findByText(WRITE_THE_NOTE);

    fireEvent.click(screen.getByText('+ Add Field'));
    fireEvent.change(screen.getByLabelText('Custom field 1 name'), { target: { value: 'SSID' } });

    await waitFor(() => expect(screen.queryByText(WRITE_THE_NOTE)).not.toBeInTheDocument());
    expect(screen.queryByText(/needs your attention/)).not.toBeInTheDocument();
  });
});

describe('card number length, as typed', () => {
  function fillCard(number: string) {
    typeIn('Item name', 'Card');
    typeIn('Name on card', 'Ada Lovelace');
    typeIn('1234 5678 9012 3456', number);
  }

  it('saves a 19-digit number', async () => {
    renderForm({ defaultType: 'card' });
    fillCard('4111111111111111110');
    submit();
    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(createdData().number).toBe('4111111111111111110');
  });

  it('refuses a 20-digit number, keeping every digit typed', async () => {
    renderForm({ defaultType: 'card' });
    fillCard('41111111111111111115');
    submit();
    expect(await screen.findByText('Card numbers have 12 to 19 digits')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('1234 5678 9012 3456')).toHaveValue(
      '4111 1111 1111 1111 1115',
    );
    expect(mockCreateItem).not.toHaveBeenCalled();
  });
});

describe('the editor expiry hint', () => {
  it('waits for a whole year instead of reading "20" as 2020 mid-typing', () => {
    renderForm({ defaultType: 'card' });
    typeIn('MM', '1');
    typeIn('YYYY', '20');
    expect(screen.queryByTestId('card-expiry-hint')).not.toBeInTheDocument();

    typeIn('YYYY', '2020');
    expect(screen.getByTestId('card-expiry-hint')).toHaveTextContent(
      'This card expired at the end of January 2020. You can still save it.',
    );
  });

  it('reads a stored two-digit year the person has not touched', () => {
    renderForm({
      item: stored('card', {
        cardholderName: 'A',
        number: '4111111111111111',
        expMonth: '01',
        expYear: '20',
      }),
    });
    expect(screen.getByTestId('card-expiry-hint')).toHaveTextContent(
      'This card expired at the end of January 2020. You can still save it.',
    );
  });
});
