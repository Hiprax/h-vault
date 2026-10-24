/**
 * An identity's phone numbers (0.22.0): up to ten, each with an optional label,
 * edited like custom fields.
 *
 * Pinned at every place the numbers pass through: the ONE reader and writer
 * (`lib/identityPhones.ts`), the form that edits them, the detail view that shows
 * them, and the Bitwarden export, whose identity has a single phone.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MAX_IDENTITY_PHONES, identityDataSchema } from '@hvault/shared';
import {
  identityPhoneRows,
  phoneDisplayLabel,
  readIdentityPhones,
  writeIdentityPhones,
} from '../src/lib/identityPhones';
import { VaultItemForm } from '../src/components/vault/VaultItemForm';
import type { DecryptedVaultItem } from '../src/stores/vaultStore';
import { toPortableItems } from '../src/services/export/portableItem';
import { toBitwardenJson } from '../src/services/export/formats/bitwardenJson';
import { PORTABLE_EXPORT_FORMATS } from '../src/services/export';

const mockCreateItem = vi.fn<(...args: unknown[]) => Promise<void>>();
const mockUpdateItem = vi.fn<(...args: unknown[]) => Promise<void>>();

vi.mock('../src/stores/vaultStore', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/stores/vaultStore')>();
  return {
    ...actual,
    useVaultStore: vi.fn((selector: (state: Record<string, unknown>) => unknown) =>
      selector({ createItem: mockCreateItem, updateItem: mockUpdateItem, folders: [], items: [] }),
    ),
  };
});

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: vi.fn(), dismiss: vi.fn(), update: vi.fn() }),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
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

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({ startCountdown: vi.fn(), stopCountdown: vi.fn() }),
}));

function identity(data: Record<string, unknown>): DecryptedVaultItem {
  return {
    id: '66c0f1a2b3c4d5e6f7a8b9c0',
    itemType: 'identity',
    name: 'Me',
    data: { firstName: 'Ada', lastName: 'Lovelace', customFields: [], ...data },
    tags: [],
    favorite: false,
    createdAt: '',
    updatedAt: '',
    _raw: {},
  } as unknown as DecryptedVaultItem;
}

function renderForm(item?: DecryptedVaultItem) {
  return render(
    <VaultItemForm
      onSaved={vi.fn()}
      onCancel={vi.fn()}
      {...(item === undefined ? { defaultType: 'identity' as const } : { item })}
    />,
  );
}

function typeIn(element: HTMLElement, value: string) {
  fireEvent.change(element, { target: { value } });
}

function phoneInput(position: number, part: 'label' | 'number'): HTMLElement {
  return screen.getByLabelText(`Phone ${String(position)} ${part}`);
}

function savedData(mock: typeof mockCreateItem, index: 2 | 3): Record<string, unknown> {
  return mock.mock.calls[0]![index] as Record<string, unknown>;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockCreateItem.mockResolvedValue(undefined);
  mockUpdateItem.mockResolvedValue(undefined);
});

// ---------------------------------------------------------------------------

describe('readIdentityPhones / writeIdentityPhones', () => {
  it('reads the list when there is one, else the single phone, else nothing', () => {
    expect(
      readIdentityPhones({ phone: '1', phones: [{ label: 'Work', number: '1' }, { number: '2' }] }),
    ).toEqual([{ label: 'Work', number: '1' }, { number: '2' }]);
    expect(readIdentityPhones({ phone: '555 0100' })).toEqual([{ number: '555 0100' }]);
    expect(readIdentityPhones({ phone: '', phones: [] })).toEqual([]);
    expect(readIdentityPhones({})).toEqual([]);
  });

  it('gives the form one empty row for an identity with no number', () => {
    expect(identityPhoneRows({})).toEqual([{ label: '', number: '' }]);
    expect(
      identityPhoneRows({ phones: [{ number: '1' }, { label: 'Home', number: '2' }] }),
    ).toEqual([
      { label: '', number: '1' },
      { label: 'Home', number: '2' },
    ]);
  });

  it('stores one unlabelled number as it always was, and ALWAYS names both keys', () => {
    const one = writeIdentityPhones([{ label: '', number: '555 0100' }]);
    expect(one).toEqual({ phone: '555 0100', phones: undefined });
    expect(Object.keys(one).sort()).toEqual(['phone', 'phones']);
  });

  it('stores a labelled or second number in the list, with the first also in `phone`', () => {
    expect(writeIdentityPhones([{ label: ' Work ', number: '1' }])).toEqual({
      phone: '1',
      phones: [{ label: 'Work', number: '1' }],
    });
    expect(
      writeIdentityPhones([
        { label: '', number: '1' },
        { label: '', number: '' },
        { label: '  ', number: '2' },
      ]),
    ).toEqual({ phone: '1', phones: [{ number: '1' }, { number: '2' }] });
  });

  it('deletes both keys when every row is empty', () => {
    expect(writeIdentityPhones([{ label: '', number: '' }])).toEqual({
      phone: undefined,
      phones: undefined,
    });
    expect(writeIdentityPhones([])).toEqual({ phone: undefined, phones: undefined });
  });

  it('writes only what the stored schema takes back unchanged', () => {
    const written = writeIdentityPhones([
      { label: 'Work', number: '+1 (555) 010-0100' },
      { label: '', number: '555.0101' },
    ]);
    const parsed = identityDataSchema.parse({ firstName: 'A', lastName: 'B', ...written });
    expect(parsed.phone).toBe('+1 (555) 010-0100');
    expect(parsed.phones).toEqual(written.phones);
  });

  it('names a number as the detail view does', () => {
    expect(phoneDisplayLabel({}, 0)).toBe('Phone');
    expect(phoneDisplayLabel({}, 1)).toBe('Phone 2');
    expect(phoneDisplayLabel({ label: 'Work' }, 0)).toBe('Phone (Work)');
    expect(phoneDisplayLabel({ label: 'Home' }, 4)).toBe('Phone (Home)');
  });
});

describe('the identity form', () => {
  it('saves three labelled numbers, the first also as the phone an older client reads', async () => {
    renderForm();
    typeIn(screen.getByPlaceholderText('Item name'), 'Me');
    typeIn(screen.getByPlaceholderText('First name'), 'Ada');
    typeIn(screen.getByPlaceholderText('Last name'), 'Lovelace');
    typeIn(phoneInput(1, 'label'), 'Work');
    typeIn(phoneInput(1, 'number'), '+44 20 7946 0958');
    fireEvent.click(screen.getByRole('button', { name: '+ Add Phone' }));
    typeIn(phoneInput(2, 'label'), 'Mobile');
    typeIn(phoneInput(2, 'number'), '07700 900123');
    fireEvent.click(screen.getByRole('button', { name: '+ Add Phone' }));
    typeIn(phoneInput(3, 'number'), '555 0100');

    fireEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => expect(mockCreateItem).toHaveBeenCalledTimes(1));
    expect(savedData(mockCreateItem, 2)).toMatchObject({
      phone: '+44 20 7946 0958',
      phones: [
        { label: 'Work', number: '+44 20 7946 0958' },
        { label: 'Mobile', number: '07700 900123' },
        { number: '555 0100' },
      ],
    });
  });

  it('opens an identity with its numbers in rows', () => {
    renderForm(identity({ phone: '1', phones: [{ label: 'Work', number: '1' }, { number: '2' }] }));
    expect(phoneInput(1, 'label')).toHaveValue('Work');
    expect(phoneInput(1, 'number')).toHaveValue('1');
    expect(phoneInput(2, 'label')).toHaveValue('');
    expect(phoneInput(2, 'number')).toHaveValue('2');
    expect(screen.queryByLabelText('Phone 3 number')).toBeNull();
    expect(screen.getByText('(2 of 10)')).toBeInTheDocument();
  });

  it('removes the list it had once one unlabelled number is left', async () => {
    renderForm(identity({ phone: '1', phones: [{ label: 'Work', number: '1' }, { number: '2' }] }));
    fireEvent.click(screen.getByRole('button', { name: 'Remove phone 2' }));
    typeIn(phoneInput(1, 'label'), '');
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = savedData(mockUpdateItem, 3);
    expect(data.phone).toBe('1');
    expect(data).not.toHaveProperty('phones');
  });

  it('removes both keys when the last number is removed', async () => {
    renderForm(identity({ phone: '1', phones: [{ label: 'Work', number: '1' }] }));
    fireEvent.click(screen.getByRole('button', { name: 'Remove phone 1' }));
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = savedData(mockUpdateItem, 3);
    expect(data).not.toHaveProperty('phone');
    expect(data).not.toHaveProperty('phones');
  });

  it('keeps an older identity’s single number byte for byte when it is not touched', async () => {
    renderForm(identity({ phone: '555 0100' }));
    expect(phoneInput(1, 'number')).toHaveValue('555 0100');
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(mockUpdateItem).toHaveBeenCalledTimes(1));
    const data = savedData(mockUpdateItem, 3);
    expect(data.phone).toBe('555 0100');
    expect(data).not.toHaveProperty('phones');
  });

  it('refuses a label with no number, on the number, saving nothing', async () => {
    renderForm(identity({}));
    typeIn(phoneInput(1, 'label'), 'Work');
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));

    const message = await screen.findByText('Enter the number, or remove this row');
    expect(message).toHaveAttribute('id', 'field-phones-0-number-error');
    expect(phoneInput(1, 'number')).toHaveAttribute('aria-invalid', 'true');
    expect(phoneInput(1, 'label')).not.toHaveAttribute('aria-invalid');
    expect(mockUpdateItem).not.toHaveBeenCalled();
  });

  it('refuses a label over the bound, on the label', async () => {
    renderForm(identity({}));
    typeIn(phoneInput(1, 'label'), 'x'.repeat(51));
    typeIn(phoneInput(1, 'number'), '1');
    fireEvent.click(screen.getByRole('button', { name: 'Update' }));

    const message = await screen.findByText('Label too long');
    expect(message).toHaveAttribute('id', 'field-phones-0-label-error');
    expect(mockUpdateItem).not.toHaveBeenCalled();
  });

  it(`stops adding at ${String(MAX_IDENTITY_PHONES)} numbers, saying why, and keeps the control reachable`, () => {
    renderForm(
      identity({
        phone: '1',
        phones: Array.from({ length: MAX_IDENTITY_PHONES - 1 }, (_, i) => ({
          number: String(i + 1),
        })),
      }),
    );
    const add = screen.getByRole('button', { name: '+ Add Phone' });
    expect(add).not.toHaveAttribute('aria-disabled');
    expect(add).not.toHaveClass('cursor-not-allowed');
    fireEvent.click(add);
    expect(
      screen.getByLabelText(`Phone ${String(MAX_IDENTITY_PHONES)} number`),
    ).toBeInTheDocument();
    expect(add).toHaveAttribute('aria-disabled', 'true');
    // And it looks unavailable, not only to assistive technology.
    expect(add).toHaveClass('cursor-not-allowed');
    expect(add).toHaveAttribute('aria-describedby', 'phone-numbers-limit-help');
    expect(screen.getByText('An identity can have up to 10 phone numbers.')).toBeInTheDocument();
    fireEvent.click(add);
    expect(screen.queryByLabelText(`Phone ${String(MAX_IDENTITY_PHONES + 1)} number`)).toBeNull();
  });
});

describe('the Bitwarden export', () => {
  it('carries the first number as the phone and the rest as custom fields, after every other field', async () => {
    const { portable } = await toPortableItems({
      items: [
        identity({
          phone: '1',
          phones: [{ label: 'Work', number: '1' }, { label: 'Home', number: '2' }, { number: '3' }],
          customFields: [{ name: 'Badge', value: '42', type: 'text' }],
        }),
      ],
      folders: [],
      vaultKey: {} as CryptoKey,
    });
    const exported = JSON.parse(toBitwardenJson(portable).content) as {
      items: {
        identity: { phone: string };
        fields: { name: string; value: string; type: number }[];
      }[];
    };
    const [item] = exported.items;
    expect(item!.identity.phone).toBe('1');
    expect(item!.fields).toEqual([
      { name: 'Badge', value: '42', type: 0 },
      { name: 'Phone (Home)', value: '2', type: 0 },
      { name: 'Phone 3', value: '3', type: 0 },
    ]);
  });

  it('adds no field for an identity with one number', async () => {
    const { portable } = await toPortableItems({
      items: [identity({ phone: '1' })],
      folders: [],
      vaultKey: {} as CryptoKey,
    });
    const exported = JSON.parse(toBitwardenJson(portable).content) as {
      items: { identity: { phone: string }; fields?: unknown[] }[];
    };
    expect(exported.items[0]!.identity.phone).toBe('1');
    expect(exported.items[0]!.fields).toBeUndefined();
  });

  it('says what happens to the extra numbers', () => {
    const meta = PORTABLE_EXPORT_FORMATS.find((format) => format.value === 'bitwarden-json');
    expect(meta?.lossNote).toContain(
      'extra phone numbers travel as custom fields and stay custom fields when this file is imported back',
    );
  });
});
