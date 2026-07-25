/**
 * Behavioural coverage for VaultItemDetail's untested branches.
 *
 * Deliberately NOT duplicated from tests/vault-display-coverage.test.tsx (happy-path
 * rendering of the five type views, masking, favourite/delete/restore success paths)
 * or tests/phase9-client-vault.test.tsx (updateItemMeta wiring in the store).
 *
 * What is covered here:
 *  - TotpDisplay driven by the REAL otpauth library: the rendered code is the actual
 *    TOTP for the secret, whitespace/lower-case secrets are normalised, an invalid
 *    base32 secret surfaces the error panel instead of a code, and copying puts the
 *    raw (unspaced) code on the clipboard.
 *  - SecretDetail expiry countdown: expired vs. remaining wording, and the 60s tick.
 *  - CopyField em-dash fallback for an empty value.
 *  - NoteDetail markdown link sanitisation (REAL react-markdown — a javascript: href
 *    is neutralised to "#").
 *  - Card billing-address branch matrix (all-empty → no section; single field → only
 *    that field).
 *  - Password history: no vault key, and a partially-failing decrypt (allSettled).
 *  - Degraded / undecodable items: the notice renders and the action bar stays usable;
 *    the local ErrorBoundary catches a type view that throws on malformed data.
 *  - Error/edge paths of the action bar: move-to-folder failure, un-favouriting,
 *    Escape / backdrop dismissal of the delete dialog, and the back button.
 */

import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { TOTP } from 'otpauth';

// ---------------------------------------------------------------------------
// Polyfill matchMedia — uiStore (imported by vaultStore) reads it at module load.
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

const { mockToast, mockDecryptData } = vi.hoisted(() => ({
  mockToast: vi.fn(),
  mockDecryptData: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Mocks (must precede the store/component imports)
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: () => false,
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    decryptData: mockDecryptData,
    encryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    defaults: { headers: { common: {} } },
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

vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
  clearSettingsCache: vi.fn(),
}));

vi.mock('../src/hooks/useClipboardCountdown', () => ({
  useClipboardCountdown: () => ({ startCountdown: vi.fn(), stopCountdown: vi.fn() }),
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

// ---------------------------------------------------------------------------
// Imports AFTER the mocks
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { VaultItemDetail } from '../src/components/vault/VaultItemDetail';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type ItemType = 'login' | 'secret' | 'note' | 'card' | 'identity';

interface ItemOverrides {
  id?: string;
  name?: string;
  itemType?: ItemType;
  favorite?: boolean;
  tags?: string[];
  folderId?: string;
  data?: Record<string, unknown>;
  passwordHistory?: { encryptedPassword: string; iv: string; tag: string; changedAt: string }[];
}

function makeItem(overrides: ItemOverrides = {}) {
  const id = overrides.id ?? 'item-1';
  const itemType = overrides.itemType ?? 'login';
  const created = '2025-01-01T00:00:00.000Z';
  const updated = '2025-06-15T12:00:00.000Z';
  return {
    id,
    itemType,
    name: overrides.name ?? 'Test Item',
    favorite: overrides.favorite ?? false,
    tags: overrides.tags ?? [],
    folderId: overrides.folderId,
    data: overrides.data ?? {
      username: 'user@example.com',
      password: 'secret123',
      uris: [],
      totp: '',
      notes: '',
      customFields: [],
    },
    searchHash: 'abc',
    createdAt: created,
    updatedAt: updated,
    _raw: {
      _id: id,
      userId: 'u1',
      itemType,
      encryptedData: 'enc',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: overrides.tags ?? [],
      favorite: overrides.favorite ?? false,
      passwordHistory: overrides.passwordHistory ?? [],
      createdAt: created,
      updatedAt: updated,
    },
  };
}

function makeFolder(id: string, name: string) {
  const now = '2025-01-01T00:00:00.000Z';
  return {
    id,
    name,
    sortOrder: 0,
    parentId: undefined,
    createdAt: now,
    updatedAt: now,
    _raw: {
      _id: id,
      userId: 'u1',
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: 0,
      createdAt: now,
      updatedAt: now,
    },
  };
}

const mockUpdateItem = vi.fn().mockResolvedValue(undefined);
const mockUpdateItemMeta = vi.fn().mockResolvedValue(undefined);
const mockDeleteItem = vi.fn().mockResolvedValue(undefined);
const mockPermanentDeleteItem = vi.fn().mockResolvedValue(undefined);
const mockRestoreItem = vi.fn().mockResolvedValue(undefined);
const onEdit = vi.fn();

function renderDetail(item: ReturnType<typeof makeItem>, isTrashed = false) {
  return render(
    <MemoryRouter initialEntries={['/vault/item-1']}>
      <Routes>
        <Route
          path="/vault/item-1"
          element={<VaultItemDetail item={item as never} onEdit={onEdit} isTrashed={isTrashed} />}
        />
        <Route path="/vault" element={<div>VAULT LIST PAGE</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockUpdateItem.mockResolvedValue(undefined);
  mockUpdateItemMeta.mockResolvedValue(undefined);
  mockDeleteItem.mockResolvedValue(undefined);
  mockPermanentDeleteItem.mockResolvedValue(undefined);
  mockRestoreItem.mockResolvedValue(undefined);
  mockDecryptData.mockResolvedValue('decrypted');

  useAuthStore.setState({
    accessToken: 'token',
    user: { userId: 'u1', email: 'test@example.com' },
    isAuthenticated: true,
    isLocked: false,
    vaultKey: {} as CryptoKey,
    mek: null,
  } as never);

  useVaultStore.setState({
    items: [],
    trashItems: [],
    folders: [],
    updateItem: mockUpdateItem,
    updateItemMeta: mockUpdateItemMeta,
    deleteItem: mockDeleteItem,
    permanentDeleteItem: mockPermanentDeleteItem,
    restoreItem: mockRestoreItem,
  } as never);

  Object.assign(navigator, {
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.useRealTimers();
});

// ===========================================================================
// TotpDisplay — real otpauth
// ===========================================================================

describe('VaultItemDetail / TotpDisplay', () => {
  const SECRET = 'JBSWY3DPEHPK3PXP';

  function totpItem(totp: string) {
    return makeItem({
      itemType: 'login',
      data: {
        username: 'u',
        password: 'p',
        uris: [],
        totp,
        notes: '',
        customFields: [],
      },
    });
  }

  function expectedCodes(secret: string): string[] {
    // Independently derived with the same library the component uses, so a
    // regression in the component's TOTP parameters (period/digits/algorithm)
    // or in its base32 normalisation makes this assertion fail.
    const totp = new TOTP({ secret, digits: 6, period: 30, algorithm: 'SHA1' });
    const now = Date.now();
    // Accept the neighbouring step too, in case the 30s window rolls over
    // between the component's generate() and this assertion.
    return [
      totp.generate({ timestamp: now }),
      totp.generate({ timestamp: now + 30_000 }),
      totp.generate({ timestamp: now - 30_000 }),
    ];
  }

  it('renders the live TOTP code for a valid base32 secret, grouped 3+3', async () => {
    renderDetail(totpItem(SECRET));

    const codes = expectedCodes(SECRET);
    await waitFor(() => {
      const rendered = screen.getByLabelText('Copy TOTP code').textContent ?? '';
      const digits = rendered.replace(/\s/g, '');
      expect(digits).not.toBe('------');
      expect(codes).toContain(digits);
    });

    // The display groups the six digits as "123 456".
    const shown = screen.getByLabelText('Copy TOTP code').textContent ?? '';
    expect(shown).toMatch(/\d{3}\s\d{3}/);
  });

  it('normalises a lower-case, space-separated secret before generating', async () => {
    renderDetail(totpItem('jbsw y3dp ehpk 3pxp'));

    const codes = expectedCodes(SECRET);
    await waitFor(() => {
      const digits = (screen.getByLabelText('Copy TOTP code').textContent ?? '').replace(/\s/g, '');
      expect(codes).toContain(digits);
    });
  });

  it('copies the raw six-digit code (not the spaced display form) to the clipboard', async () => {
    renderDetail(totpItem(SECRET));

    await waitFor(() => {
      expect(
        (screen.getByLabelText('Copy TOTP code').textContent ?? '').replace(/\s/g, ''),
      ).not.toBe('------');
    });

    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy TOTP code'));
    });

    const written = (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mock
      .calls[0]?.[0] as string;
    expect(written).toMatch(/^\d{6}$/);
    expect(expectedCodes(SECRET)).toContain(written);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'TOTP code copied', type: 'success' }),
    );
  });

  it('surfaces a copy failure as an error toast', async () => {
    (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('denied'),
    );
    renderDetail(totpItem(SECRET));

    await waitFor(() => {
      expect(
        (screen.getByLabelText('Copy TOTP code').textContent ?? '').replace(/\s/g, ''),
      ).not.toBe('------');
    });

    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy TOTP code'));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to copy', type: 'error' }),
    );
  });

  it('shows an error panel (and no copy button) for a secret whose length is not a base32 multiple of 8', async () => {
    renderDetail(totpItem('JBSWY3DP2'));

    expect(await screen.findByText('Invalid TOTP secret (not valid base32)')).toBeInTheDocument();
    expect(screen.queryByLabelText('Copy TOTP code')).not.toBeInTheDocument();
  });

  it('rejects a secret containing non-base32 characters', async () => {
    renderDetail(totpItem('JBSWY3D1'));

    expect(await screen.findByText('Invalid TOTP secret (not valid base32)')).toBeInTheDocument();
  });

  it('rejects a whitespace-only secret (normalises to the empty string)', async () => {
    renderDetail(totpItem('    '));

    expect(await screen.findByText('Invalid TOTP secret (not valid base32)')).toBeInTheDocument();
  });
});

// ===========================================================================
// SecretDetail — expiry countdown
// ===========================================================================

describe('VaultItemDetail / SecretDetail expiry', () => {
  function secretItem(expiresAt?: string) {
    return makeItem({
      itemType: 'secret',
      data: {
        value: 'sk-1',
        description: '',
        ...(expiresAt ? { expiresAt } : {}),
        customFields: [],
      },
    });
  }

  const inMs = (ms: number) => new Date(Date.now() + ms).toISOString();

  it('reports days and hours remaining for a far-future expiry', () => {
    renderDetail(secretItem(inMs(2 * 86_400_000 + 3 * 3_600_000 + 5_000)));
    expect(screen.getByText('2d 3h remaining')).toBeInTheDocument();
  });

  it('reports hours and minutes remaining when under a day', () => {
    renderDetail(secretItem(inMs(2 * 3_600_000 + 30 * 60_000 + 5_000)));
    expect(screen.getByText('2h 30m remaining')).toBeInTheDocument();
  });

  it('reports minutes remaining when under an hour', () => {
    renderDetail(secretItem(inMs(5 * 60_000 + 5_000)));
    expect(screen.getByText('5m remaining')).toBeInTheDocument();
  });

  it('reports "Less than a minute remaining" when under a minute', () => {
    renderDetail(secretItem(inMs(30_000)));
    expect(screen.getByText('Less than a minute remaining')).toBeInTheDocument();
  });

  it('reports an expired secret in days and hours', () => {
    renderDetail(secretItem(inMs(-(3 * 86_400_000 + 4 * 3_600_000 + 5_000))));
    expect(screen.getByText('Expired 3d 4h ago')).toBeInTheDocument();
  });

  it('reports an expired secret in hours and minutes', () => {
    renderDetail(secretItem(inMs(-(5 * 3_600_000 + 10 * 60_000 + 5_000))));
    expect(screen.getByText('Expired 5h 10m ago')).toBeInTheDocument();
  });

  it('reports an expired secret in minutes', () => {
    renderDetail(secretItem(inMs(-(7 * 60_000 + 5_000))));
    expect(screen.getByText('Expired 7m ago')).toBeInTheDocument();
  });

  it('reports "Expired just now" within the first minute past expiry', () => {
    renderDetail(secretItem(inMs(-5_000)));
    expect(screen.getByText('Expired just now')).toBeInTheDocument();
  });

  it('re-computes the countdown on the 60s tick', () => {
    vi.useFakeTimers();
    try {
      renderDetail(secretItem(new Date(Date.now() + 90_000).toISOString()));
      expect(screen.getByText('1m remaining')).toBeInTheDocument();

      act(() => {
        vi.advanceTimersByTime(60_000);
      });

      expect(screen.queryByText('1m remaining')).not.toBeInTheDocument();
      expect(screen.getByText('Less than a minute remaining')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('renders no expiry panel when the secret has no expiresAt', () => {
    renderDetail(secretItem());
    expect(screen.queryByText('Expires')).not.toBeInTheDocument();
  });
});

// ===========================================================================
// CopyField — empty value fallback
// ===========================================================================

describe('VaultItemDetail / CopyField', () => {
  it('renders an em-dash placeholder for an empty (unmasked) value', () => {
    renderDetail(
      makeItem({
        itemType: 'card',
        data: {
          cardholderName: '',
          number: '4111111111111111',
          expMonth: '12',
          expYear: '2030',
          cvv: '123',
          brand: '',
          notes: '',
        },
      }),
    );

    expect(screen.getByText('Cardholder Name')).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});

// ===========================================================================
// NoteDetail — markdown link sanitisation (real react-markdown)
// ===========================================================================

describe('VaultItemDetail / NoteDetail markdown', () => {
  it('neutralises an unsafe markdown link href to "#" while keeping its text', async () => {
    renderDetail(
      makeItem({
        itemType: 'note',
        data: {
          content: '[click me](javascript:alert(1))',
          format: 'markdown',
        },
      }),
    );

    const link = await screen.findByRole('link', { name: 'click me' });
    expect(link).toHaveAttribute('href', '#');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('keeps a safe markdown link href intact', async () => {
    renderDetail(
      makeItem({
        itemType: 'note',
        data: {
          content: '[docs](https://example.com/docs)',
          format: 'markdown',
        },
      }),
    );

    const link = await screen.findByRole('link', { name: 'docs' });
    expect(link).toHaveAttribute('href', 'https://example.com/docs');
  });
});

// ===========================================================================
// CardDetail — billing address branch matrix
// ===========================================================================

describe('VaultItemDetail / CardDetail billing address', () => {
  function cardItem(billingAddress: Record<string, string>) {
    return makeItem({
      itemType: 'card',
      data: {
        cardholderName: 'Jane',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2030',
        cvv: '123',
        brand: '',
        notes: '',
        billingAddress,
      },
    });
  }

  it('omits the section entirely when every billing field is empty', () => {
    renderDetail(cardItem({ street: '', city: '', state: '', zip: '', country: '' }));
    expect(screen.queryByText('Billing Address')).not.toBeInTheDocument();
  });

  it('renders only the populated field when just the country is set', () => {
    renderDetail(cardItem({ street: '', city: '', state: '', zip: '', country: 'US' }));

    expect(screen.getByText('Billing Address')).toBeInTheDocument();
    expect(screen.getByText('Country')).toBeInTheDocument();
    expect(screen.getByText('US')).toBeInTheDocument();
    expect(screen.queryByText('Street')).not.toBeInTheDocument();
    expect(screen.queryByText('City / State')).not.toBeInTheDocument();
    expect(screen.queryByText('ZIP')).not.toBeInTheDocument();
  });

  it('renders the City / State line with only the city when the state is empty', () => {
    renderDetail(cardItem({ street: '', city: 'Springfield', state: '', zip: '', country: '' }));

    expect(screen.getByText('City / State')).toBeInTheDocument();
    expect(screen.getByText('Springfield')).toBeInTheDocument();
  });
});

// ===========================================================================
// Password history
// ===========================================================================

describe('VaultItemDetail / password history', () => {
  const entries = [
    { encryptedPassword: 'e1', iv: 'i1', tag: 't1', changedAt: '2025-03-01T00:00:00.000Z' },
    { encryptedPassword: 'e2', iv: 'i2', tag: 't2', changedAt: '2025-02-01T00:00:00.000Z' },
  ];

  it('keeps the still-decryptable entries when one entry fails to decrypt', async () => {
    mockDecryptData.mockRejectedValueOnce(new Error('GCM tag mismatch'));
    mockDecryptData.mockResolvedValueOnce('older-password');

    renderDetail(makeItem({ passwordHistory: entries }));

    await act(async () => {
      fireEvent.click(screen.getByText('Password History (2)'));
    });

    await waitFor(() => {
      expect(screen.getAllByText(/Previous password/)).toHaveLength(1);
    });
  });

  it('does not attempt decryption while the vault key is absent', async () => {
    useAuthStore.setState({ vaultKey: null } as never);

    renderDetail(makeItem({ passwordHistory: entries }));

    await act(async () => {
      fireEvent.click(screen.getByText('Password History (2)'));
    });

    expect(mockDecryptData).not.toHaveBeenCalled();
    expect(screen.queryByText(/Previous password/)).not.toBeInTheDocument();
  });

  it('is not rendered for non-login item types', () => {
    renderDetail(
      makeItem({
        itemType: 'note',
        data: { content: 'hi', format: 'plaintext' },
        passwordHistory: entries,
      }),
    );

    expect(screen.queryByText(/Password History/)).not.toBeInTheDocument();
  });
});

// ===========================================================================
// Degraded / undecodable items
// ===========================================================================

describe('VaultItemDetail / undecodable items', () => {
  it('shows the degraded notice and keeps edit/favourite/delete reachable for a _validationError item', () => {
    renderDetail(
      makeItem({
        name: 'Broken',
        data: { username: 'u', _validationError: true },
      }),
    );

    expect(screen.getByRole('alert')).toHaveTextContent('This item could not be fully decoded.');
    // The type view is NOT rendered...
    expect(screen.queryByText('Username')).not.toBeInTheDocument();
    // ...but the header + action bar (outside the ErrorBoundary) still are.
    expect(screen.getByText('Broken')).toBeInTheDocument();
    expect(screen.getByText('Edit')).toBeInTheDocument();
    expect(screen.getByText('Favorite')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
  });

  it('shows the degraded notice for a _raw (unparseable) payload', () => {
    renderDetail(makeItem({ data: { _raw: 'not-json' } }));

    expect(screen.getByRole('alert')).toHaveTextContent('This item could not be fully decoded.');
  });

  it('keeps Restore and Delete Forever reachable for a trashed undecodable item', async () => {
    renderDetail(makeItem({ data: { _validationError: true } }), true);

    expect(screen.getByRole('alert')).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(screen.getByText('Restore'));
    });

    expect(mockRestoreItem).toHaveBeenCalledWith('item-1');
  });

  it('degrades to the notice via the ErrorBoundary when a type view throws on malformed data', () => {
    // Not flagged as undecodable, but `uris` is missing, so LoginDetail's
    // `data.uris.map(...)` throws. The ErrorBoundary must contain the failure to
    // the content section and leave the action bar usable.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      renderDetail(makeItem({ name: 'Throwing', data: { username: 'u', password: 'p' } }));

      expect(screen.getByRole('alert')).toHaveTextContent('This item could not be fully decoded.');
      expect(screen.getByText('Edit')).toBeInTheDocument();
      expect(screen.getByText('Delete')).toBeInTheDocument();
    } finally {
      consoleError.mockRestore();
    }
  });
});

// ===========================================================================
// Action bar edge/error paths
// ===========================================================================

describe('VaultItemDetail / action bar', () => {
  it('un-favouriting sends favorite:false and reports it, without re-encrypting', async () => {
    renderDetail(makeItem({ favorite: true }));

    await act(async () => {
      fireEvent.click(screen.getByText('Favorited'));
    });

    expect(mockUpdateItemMeta).toHaveBeenCalledWith('item-1', { favorite: false });
    expect(mockUpdateItem).not.toHaveBeenCalled();
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Removed from favorites', type: 'success' }),
    );
  });

  it('surfaces a move failure and leaves the folder menu open', async () => {
    mockUpdateItemMeta.mockRejectedValueOnce(new Error('409'));
    useVaultStore.setState({ folders: [makeFolder('f1', 'Work')] } as never);

    renderDetail(makeItem());

    fireEvent.click(screen.getByText('No folder'));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Work' }));
    });

    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to move item', type: 'error' }),
    );
    // The menu is only closed on success, so the user can retry.
    expect(screen.getByRole('menu', { name: 'Move to folder' })).toBeInTheDocument();
  });

  it('closes the folder menu after a successful move', async () => {
    useVaultStore.setState({ folders: [makeFolder('f1', 'Work')] } as never);

    renderDetail(makeItem());

    fireEvent.click(screen.getByText('No folder'));
    await act(async () => {
      fireEvent.click(screen.getByRole('menuitem', { name: 'Work' }));
    });

    expect(mockUpdateItemMeta).toHaveBeenCalledWith('item-1', { folderId: 'f1' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('navigates back to the vault list from the back button', async () => {
    renderDetail(makeItem());

    await act(async () => {
      fireEvent.click(screen.getByLabelText('Back to vault'));
    });

    expect(screen.getByText('VAULT LIST PAGE')).toBeInTheDocument();
  });

  it('navigates back to the vault list after a successful delete', async () => {
    renderDetail(makeItem());

    fireEvent.click(screen.getByText('Delete'));
    await act(async () => {
      fireEvent.click(screen.getAllByText('Delete').pop()!);
    });

    expect(mockDeleteItem).toHaveBeenCalledWith('item-1');
    expect(screen.getByText('VAULT LIST PAGE')).toBeInTheDocument();
  });

  it('stays on the item (dialog closed) when the delete fails', async () => {
    mockDeleteItem.mockRejectedValueOnce(new Error('network'));

    renderDetail(makeItem({ name: 'Stay Put' }));

    fireEvent.click(screen.getByText('Delete'));
    await act(async () => {
      fireEvent.click(screen.getAllByText('Delete').pop()!);
    });

    expect(screen.queryByText('VAULT LIST PAGE')).not.toBeInTheDocument();
    expect(screen.getByText('Stay Put')).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('dismisses the delete dialog on Escape without deleting', async () => {
    renderDetail(makeItem());

    fireEvent.click(screen.getByText('Delete'));
    expect(screen.getByRole('alertdialog')).toBeInTheDocument();

    await act(async () => {
      fireEvent.keyDown(document, { key: 'Escape' });
    });

    await waitFor(() => {
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    });
    expect(mockDeleteItem).not.toHaveBeenCalled();
  });

  it('dismisses the delete dialog on a backdrop click but not on a click inside it', () => {
    const { container } = renderDetail(makeItem());

    fireEvent.click(screen.getByText('Delete'));
    const dialog = screen.getByRole('alertdialog');
    const backdrop = container.querySelector('.fixed.inset-0');
    expect(backdrop).not.toBeNull();

    // Clicking the dialog itself must not close it.
    fireEvent.click(dialog);
    expect(screen.getByRole('alertdialog')).toBeInTheDocument();

    fireEvent.click(backdrop!);
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(mockDeleteItem).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Backup codes section
//
// The whole point of putting a delete here rather than only in the edit form is
// that this is where a code is USED, so the write has to persist immediately —
// which brings an optimistic update, a rollback and an Undo with it.
// ---------------------------------------------------------------------------

describe('VaultItemDetail — backup codes', () => {
  const CODES = ['AAAA-1111', 'BBBB-2222', 'CCCC-3333'];

  function loginWithCodes(codes: string[] = CODES) {
    return makeItem({
      data: {
        username: 'user@example.com',
        password: 'secret123',
        uris: [],
        totp: '',
        notes: '',
        customFields: [],
        backupCodes: codes,
      },
    });
  }

  function writtenClipboard(): unknown {
    return (navigator.clipboard.writeText as ReturnType<typeof vi.fn>).mock.calls[0]?.[0];
  }

  function updateCall(index: number) {
    const call = mockUpdateItem.mock.calls[index];
    expect(call).toBeDefined();
    return call!;
  }

  function updatedData(index: number): Record<string, unknown> {
    return updateCall(index)[2] as Record<string, unknown>;
  }

  it('renders a masked row per code with positional controls', () => {
    renderDetail(loginWithCodes());
    expect(screen.getByRole('list', { name: 'Backup codes' })).toBeInTheDocument();
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByLabelText('Copy backup code 3')).toBeInTheDocument();
    expect(screen.queryByText('AAAA-1111')).toBeNull();
  });

  it('renders no section for a login with no codes', () => {
    renderDetail(makeItem());
    expect(screen.queryByRole('heading', { name: 'Backup codes' })).toBeNull();
  });

  it('renders no section for an undecodable login', () => {
    // LoginDetail only renders inside the `isUndecodableData` false branch, so the
    // section can never mount for a placeholder payload and `updateItem` can never
    // be reached for one. That gate is what makes a defensive re-check inside the
    // section structurally unreachable.
    renderDetail(makeItem({ data: { _validationError: true, backupCodes: ['AAAA-1111'] } }));
    expect(screen.getByRole('alert').textContent).toContain('could not be fully decoded');
    expect(screen.queryByRole('list', { name: 'Backup codes' })).toBeNull();
  });

  it('copies one code through the clipboard guard', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy backup code 2'));
    });
    expect(writtenClipboard()).toBe('BBBB-2222');
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Backup code 2 copied', type: 'success' }),
    );
  });

  it('copies every code newline-joined', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Copy all backup codes'));
    });
    expect(writtenClipboard()).toBe(CODES.join('\n'));
  });

  it('removes one code and re-encrypts the item without it', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    expect(mockUpdateItem).toHaveBeenCalledTimes(1);
    const call = updateCall(0);
    expect(call[0]).toBe('item-1');
    expect(call[1]).toBe('Test Item');
    expect(updatedData(0).backupCodes).toEqual(['AAAA-1111', 'CCCC-3333']);
    // No `options` argument, so folder, tags and favorite are left untouched.
    expect(call).toHaveLength(3);
    // The rest of the payload has to survive: the whole blob is replaced.
    expect(updatedData(0).password).toBe('secret123');
  });

  it('drops the key entirely when the last code is removed', async () => {
    renderDetail(loginWithCodes(['AAAA-1111']));
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    });
    expect('backupCodes' in updatedData(0)).toBe(false);
  });

  it('announces the removal without ever echoing the code', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    expect(screen.getByText(/Backup code 2 removed/).textContent).toContain('2 remaining');
    expect(document.body.textContent).not.toContain('BBBB-2222');
  });

  it('rolls the row back and offers a dismiss when the save fails', async () => {
    mockUpdateItem.mockRejectedValueOnce(new Error('network down'));
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to remove backup code', type: 'error' }),
    );
    expect(screen.getByRole('button', { name: 'Dismiss' })).toBeInTheDocument();
  });

  it('keeps focus on a row when a failed delete rolls the list back', async () => {
    // The rollback is a SECOND codes transition, after the post-delete focus move
    // has already been consumed. With content-keyed rows React unmounted the
    // focused button here and focus fell to <body>.
    mockUpdateItem.mockRejectedValueOnce(new Error('network down'));
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement).toBe(screen.getByLabelText('Remove backup code 2'));
  });

  it('hands focus back to the restored row after a successful Undo', async () => {
    // The strip unmounts with the Undo button the user just pressed, so something
    // has to catch focus.
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    });
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement).toBe(screen.getByLabelText('Remove backup code 2'));
  });

  it('does not let an unrelated store refresh revert the list mid-delete', async () => {
    // The online-event refetch redecrypts every item and hands down a new array
    // identity even when nothing changed. Landing mid-write, that used to clear the
    // optimistic view and flash the removed code back into the list.
    let release: (() => void) | undefined;
    mockUpdateItem.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    const item = loginWithCodes();
    const { rerender } = renderDetail(item);
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    expect(screen.getAllByRole('listitem')).toHaveLength(2);

    // Same content, brand-new array identity — exactly what a redecrypt produces.
    const refreshed = {
      ...item,
      data: { ...item.data, backupCodes: [...(item.data.backupCodes as string[])] },
    };
    rerender(
      <MemoryRouter initialEntries={['/vault/item-1']}>
        <Routes>
          <Route
            path="/vault/item-1"
            element={
              <VaultItemDetail item={refreshed as never} onEdit={onEdit} isTrashed={false} />
            }
          />
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getAllByRole('listitem')).toHaveLength(2);

    await act(async () => {
      release?.();
    });
  });

  it('clears the failure strip on dismiss', async () => {
    mockUpdateItem.mockRejectedValueOnce(new Error('network down'));
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
  });

  it('puts a removed code back at its original position with Undo', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    });
    expect(mockUpdateItem).toHaveBeenCalledTimes(2);
    // Back where it was, not appended.
    expect(updatedData(1).backupCodes).toEqual(CODES);
  });

  it('reports a failed Undo without claiming the code was restored', async () => {
    renderDetail(loginWithCodes());
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 2'));
    });
    mockUpdateItem.mockRejectedValueOnce(new Error('still down'));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    });
    expect(mockToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Failed to restore backup code' }),
    );
    expect(screen.getByText(/Could not restore backup code 2/)).toBeInTheDocument();
  });

  it('marks the remaining deletes inert while a save is in flight and ignores clicks', async () => {
    let release: (() => void) | undefined;
    mockUpdateItem.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    renderDetail(loginWithCodes());
    fireEvent.click(screen.getByLabelText('Remove backup code 2'));

    expect(screen.getByLabelText('Remove backup code 1')).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText(/Removing backup code 2/)).toBeInTheDocument();
    // A second optimistic delete racing the first would make the rollback ambiguous.
    fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    // Clicking Undo mid-save is inert too.
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    expect(mockUpdateItem).toHaveBeenCalledTimes(1);

    await act(async () => {
      release?.();
    });
  });

  it('keeps focus inside the section when the last code is removed', async () => {
    renderDetail(loginWithCodes(['AAAA-1111']));
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Remove backup code 1'));
    });
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Backup codes' }));
  });

  it('offers copy but no delete for a trashed login', () => {
    renderDetail(loginWithCodes(), true);
    expect(screen.getByLabelText('Copy backup code 1')).toBeInTheDocument();
    expect(screen.queryByLabelText('Remove backup code 1')).toBeNull();
  });
});
