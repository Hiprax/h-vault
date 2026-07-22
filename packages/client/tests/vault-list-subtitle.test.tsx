/**
 * The vault list's distinguishing subtitle, and the total ordering that goes
 * with it.
 *
 * A row used to render the item NAME alone, so ten imported
 * `accounts.google.com` logins were visually identical and, because the sort
 * comparator returned 0 for all of them, arrived in whatever order the fetch
 * happened to produce. This file pins both halves of the fix:
 *
 * 1 - `getItemSubtitle` derives the second label, and never exposes a secret.
 * 2 - `VaultList` renders it in BOTH branches — the plain list and, above the
 *     50-item threshold, the `react-window` virtualized one — without losing the
 *     `role="list"` / `listitem` / `aria-setsize` / `aria-posinset` bookkeeping.
 * 3 - `sortItems` breaks ties on name, then subtitle, then id, so the order is
 *     total and identical on every render.
 *
 * Like tests/coverage-vault-components.test.tsx and unlike
 * tests/vault-display-coverage.test.tsx, the virtualized case here runs the REAL
 * `react-window`: a stub would render rows the library never would and would
 * never catch a regression in the aria attributes it supplies.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Hoisted mock fns
// ---------------------------------------------------------------------------

const { mockToast } = vi.hoisted(() => ({ mockToast: vi.fn() }));

// ---------------------------------------------------------------------------
// Mocks — the store pulls in crypto, storage and the network on import
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
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn().mockResolvedValue(undefined),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
  reorderFolderApi: vi.fn().mockResolvedValue(undefined),
  bulkDeleteApi: vi.fn().mockResolvedValue(undefined),
  bulkMoveApi: vi.fn().mockResolvedValue(undefined),
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
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    defaults: { headers: { common: {} } },
  },
}));

vi.mock('../src/components/ui/Toast', () => ({
  useToast: vi.fn().mockReturnValue({ toast: mockToast, dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  Toaster: () => null,
}));

// ---------------------------------------------------------------------------
// jsdom polyfill required by the REAL react-window List
// ---------------------------------------------------------------------------

class StubResizeObserver {
  constructor(private readonly callback: ResizeObserverCallback) {}
  observe(target: Element): void {
    this.callback(
      [
        {
          target,
          contentRect: { height: 600, width: 400 },
          borderBoxSize: [{ blockSize: 600, inlineSize: 400 }],
          contentBoxSize: [{ blockSize: 600, inlineSize: 400 }],
          devicePixelContentBoxSize: [{ blockSize: 600, inlineSize: 400 }],
        } as unknown as ResizeObserverEntry,
      ],
      this as unknown as ResizeObserver,
    );
  }
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver = StubResizeObserver as unknown as typeof ResizeObserver;

// ---------------------------------------------------------------------------
// Imports (AFTER mocks)
// ---------------------------------------------------------------------------

import { getItemSubtitle } from '../src/lib/vaultDisplay';
import { useVaultStore, type DecryptedVaultItem } from '../src/stores/vaultStore';
import { VaultList } from '../src/components/vault/VaultList';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ItemType = DecryptedVaultItem['itemType'];

function makeItem(overrides: {
  id: string;
  name: string;
  itemType?: ItemType;
  data?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
}): DecryptedVaultItem {
  const now = '2024-01-01T00:00:00.000Z';
  return {
    id: overrides.id,
    itemType: overrides.itemType ?? 'login',
    name: overrides.name,
    favorite: false,
    tags: [],
    data: overrides.data ?? {},
    searchHash: 'abc',
    createdAt: overrides.createdAt ?? now,
    updatedAt: overrides.updatedAt ?? now,
  } as unknown as DecryptedVaultItem;
}

/** A login as `vaultStore.decryptItem` stores it: schema-transformed data. */
function makeLogin(id: string, name: string, username: string, uri?: string): DecryptedVaultItem {
  return makeItem({
    id,
    name,
    itemType: 'login',
    data: {
      username,
      password: 'never-render-me',
      uris: uri === undefined ? [] : [{ uri, match: 'domain' }],
      customFields: [],
    },
  });
}

const pristineVaultState = useVaultStore.getState();

function seedItems(items: DecryptedVaultItem[], patch: Record<string, unknown> = {}) {
  useVaultStore.setState({
    ...pristineVaultState,
    fetchItems: vi.fn().mockResolvedValue(undefined),
    fetchTrashItems: vi.fn().mockResolvedValue(undefined),
    fetchFolders: vi.fn().mockResolvedValue(undefined),
    items,
    trashItems: [],
    folders: [],
    selectedFolder: null,
    selectedType: null,
    showFavorites: false,
    showTrash: false,
    searchQuery: '',
    filteredItemCount: null,
    sortBy: 'name',
    sortOrder: 'asc',
    loading: false,
    itemsLoading: false,
    trashLoading: false,
    itemsLoaded: 0,
    itemsTotal: null,
    ...patch,
  } as never);
}

function renderList() {
  return render(
    <MemoryRouter initialEntries={['/vault']}>
      <VaultList onCreateNew={vi.fn()} />
    </MemoryRouter>,
  );
}

/** Subtitle text of every rendered row, in DOM order. */
function renderedSubtitles(): string[] {
  return screen.getAllByTestId('vault-item-subtitle').map((el) => el.textContent ?? '');
}

beforeEach(() => {
  vi.clearAllMocks();
  seedItems([]);
});

// ===========================================================================
// getItemSubtitle — the label itself
// ===========================================================================

describe('getItemSubtitle', () => {
  it('uses a login username, which is what tells accounts on one site apart', () => {
    const data = { username: 'alice@example.com', password: 'p', uris: [], customFields: [] };
    expect(getItemSubtitle({ itemType: 'login', data })).toBe('alice@example.com');
  });

  it('trims a padded username rather than rendering the padding', () => {
    const data = { username: '  alice  ', password: 'p', uris: [], customFields: [] };
    expect(getItemSubtitle({ itemType: 'login', data })).toBe('alice');
  });

  it('falls back to the first URI host when a login has no username', () => {
    const data = {
      username: '',
      password: 'p',
      uris: [
        { uri: 'https://www.Amazon.com/gp/cart', match: 'domain' },
        { uri: 'https://other.example', match: 'domain' },
      ],
      customFields: [],
    };
    // Normalized the same way the import resolver normalizes it: lowercased,
    // `www.` stripped, first URI only.
    expect(getItemSubtitle({ itemType: 'login', data })).toBe('amazon.com');
  });

  it('returns nothing for a login with neither a username nor a usable host', () => {
    const data = {
      username: '',
      password: 'p',
      uris: [{ uri: 'mailto:someone@example.com', match: 'domain' }],
      customFields: [],
    };
    expect(getItemSubtitle({ itemType: 'login', data })).toBe('');
  });

  it('NEVER exposes a login password, TOTP seed or custom-field value', () => {
    const data = {
      username: '',
      password: 'SuperSecret1!',
      totp: 'JBSWY3DPEHPK3PXP',
      notes: 'recovery code 12345',
      uris: [{ uri: 'https://github.com', match: 'domain' }],
      customFields: [{ name: 'PIN', value: '9182', type: 'hidden' }],
    };
    const subtitle = getItemSubtitle({ itemType: 'login', data });
    expect(subtitle).toBe('github.com');
    expect(subtitle).not.toContain('SuperSecret1!');
    expect(subtitle).not.toContain('JBSWY3DPEHPK3PXP');
    expect(subtitle).not.toContain('12345');
    expect(subtitle).not.toContain('9182');
  });

  it('masks a card down to its last four digits, ignoring grouping characters', () => {
    const spaced = { number: '4111 1111 1111 1234', cvv: '987', expMonth: '01' };
    expect(getItemSubtitle({ itemType: 'card', data: spaced })).toBe('•••• 1234');
    const dashed = { number: '4111-1111-1111-1234', cvv: '987' };
    expect(getItemSubtitle({ itemType: 'card', data: dashed })).toBe('•••• 1234');
  });

  it('never renders most of a short card number, and never the whole of one', () => {
    // The detail view masks `number` behind a reveal control, so the list must
    // never show most of it. Below eight digits the last four would be half the
    // value or more, so nothing is shown; every real card (12-19 digits) still
    // gets its tail.
    expect(getItemSubtitle({ itemType: 'card', data: { number: '1234' } })).toBe('');
    expect(getItemSubtitle({ itemType: 'card', data: { number: '12345' } })).toBe('');
    expect(getItemSubtitle({ itemType: 'card', data: { number: '1234567' } })).toBe('');
    expect(getItemSubtitle({ itemType: 'card', data: { number: '' } })).toBe('');
    expect(getItemSubtitle({ itemType: 'card', data: { number: '12345678' } })).toBe('•••• 5678');
    // The CVV is never a source for the label.
    expect(getItemSubtitle({ itemType: 'card', data: { number: '', cvv: '987' } })).toBe('');
  });

  it('uses an identity full name, falling back to the email address', () => {
    const named = { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.com', ssn: '123' };
    expect(getItemSubtitle({ itemType: 'identity', data: named })).toBe('Ada Lovelace');

    const firstOnly = { firstName: 'Ada', lastName: '' };
    expect(getItemSubtitle({ itemType: 'identity', data: firstOnly })).toBe('Ada');

    const emailOnly = { firstName: '', lastName: '', email: 'ada@example.com', ssn: '123-45-6789' };
    const subtitle = getItemSubtitle({ itemType: 'identity', data: emailOnly });
    expect(subtitle).toBe('ada@example.com');
    expect(subtitle).not.toContain('123-45-6789');
  });

  it('gives notes and secrets no subtitle, and never leaks their content', () => {
    expect(
      getItemSubtitle({ itemType: 'note', data: { content: 'private', format: 'markdown' } }),
    ).toBe('');
    expect(
      getItemSubtitle({ itemType: 'secret', data: { value: 'sk-live-abc', description: 'API' } }),
    ).toBe('');
  });

  it('gives an undecodable item no subtitle, because its data is a placeholder', () => {
    // `vaultStore.decryptItem` keeps one of these two shapes when a decrypted
    // payload fails schema validation or JSON parsing. Either way `data` is not
    // the item's real content, so a label derived from it would be a lie.
    expect(
      getItemSubtitle({
        itemType: 'login',
        data: { username: 'stale@example.com', _validationError: true },
      }),
    ).toBe('');
    expect(getItemSubtitle({ itemType: 'login', data: { _raw: 'not json' } })).toBe('');
  });

  it('tolerates missing or wrongly-typed fields instead of throwing', () => {
    expect(getItemSubtitle({ itemType: 'login', data: {} })).toBe('');
    expect(getItemSubtitle({ itemType: 'login', data: { username: 42, uris: 'nope' } })).toBe('');
    expect(getItemSubtitle({ itemType: 'card', data: { number: 4111 } })).toBe('');
    expect(getItemSubtitle({ itemType: 'identity', data: { firstName: null } })).toBe('');
  });
});

// ===========================================================================
// VaultList — the plain (non-virtualized) branch, at or below 50 items
// ===========================================================================

describe('VaultList subtitles — non-virtualized branch', () => {
  it('renders a distinguishing subtitle for two logins that share a name', () => {
    seedItems([
      makeLogin('a', 'accounts.google.com', 'alice@example.com', 'https://accounts.google.com'),
      makeLogin('b', 'accounts.google.com', 'bob@example.com', 'https://accounts.google.com'),
    ]);
    renderList();

    const rows = screen.getAllByRole('listitem');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByTestId('vault-item-subtitle')).toHaveTextContent(
      'alice@example.com',
    );
    expect(within(rows[1]!).getByTestId('vault-item-subtitle')).toHaveTextContent(
      'bob@example.com',
    );
  });

  it('labels the name and the subtitle as separate elements', () => {
    // Two rows on one host share a name, so any assertion about "the host" has
    // to be able to say WHICH element it means. `vault-item-name` is that hook:
    // without it a host-scoped query matches both the name and — for a login
    // with no username — the subtitle, and the two become indistinguishable.
    seedItems([makeLogin('a', 'accounts.google.com (alice)', 'alice@example.com')]);
    renderList();

    const row = screen.getByRole('listitem');
    expect(within(row).getByTestId('vault-item-name')).toHaveTextContent(
      'accounts.google.com (alice)',
    );
    expect(within(row).getByTestId('vault-item-name')).not.toHaveTextContent('alice@example.com');
    expect(within(row).getByTestId('vault-item-subtitle')).toHaveTextContent('alice@example.com');
  });

  it('exposes the full value through `title`, so a truncated subtitle stays readable', () => {
    const long = `${'user-with-a-very-long-address'.repeat(3)}@example.com`;
    seedItems([makeLogin('a', 'Long', long, 'https://example.com')]);
    renderList();

    expect(screen.getByTestId('vault-item-subtitle')).toHaveAttribute('title', long);
  });

  it('never renders a stored password in the list', () => {
    seedItems([makeLogin('a', 'GitHub', 'octocat', 'https://github.com')]);
    renderList();

    const row = screen.getByRole('listitem');
    expect(within(row).getByTestId('vault-item-subtitle')).toHaveTextContent('octocat');
    expect(row.textContent ?? '').not.toContain('never-render-me');
  });

  it('shows a card as its masked tail, never the stored number', () => {
    seedItems([
      makeItem({
        id: 'c',
        name: 'Travel Card',
        itemType: 'card',
        data: { number: '4111111111111234', cvv: '987', cardholderName: 'Ada Lovelace' },
      }),
    ]);
    renderList();

    const row = screen.getByRole('listitem');
    expect(within(row).getByTestId('vault-item-subtitle')).toHaveTextContent('•••• 1234');
    expect(row.textContent ?? '').not.toContain('4111111111111234');
    expect(row.textContent ?? '').not.toContain('987');
  });

  it('omits the subtitle element entirely for a type that has none', () => {
    seedItems([
      makeItem({ id: 'n', name: 'Recovery Codes', itemType: 'note', data: { content: 'x' } }),
    ]);
    renderList();

    expect(screen.getByText('Recovery Codes')).toBeInTheDocument();
    expect(screen.queryByTestId('vault-item-subtitle')).not.toBeInTheDocument();
  });

  it('keeps the list a11y bookkeeping intact alongside the subtitle', () => {
    seedItems([
      makeLogin('a', 'One', 'alice', 'https://example.com'),
      makeLogin('b', 'Two', 'bob', 'https://example.com'),
      makeLogin('c', 'Three', 'carol', 'https://example.com'),
    ]);
    renderList();

    const list = screen.getByRole('list', { name: 'Vault items list' });
    const rows = within(list).getAllByRole('listitem');
    expect(rows).toHaveLength(3);
    rows.forEach((row, index) => {
      expect(row).toHaveAttribute('aria-setsize', '3');
      expect(row).toHaveAttribute('aria-posinset', String(index + 1));
    });
  });
});

// ===========================================================================
// VaultList — the REAL react-window branch, above the 50-item threshold
// ===========================================================================

describe('VaultList subtitles — virtualized branch', () => {
  /** 60 same-named logins, so only the subtitle can tell a row apart. */
  function seedSameNamedLogins(count: number) {
    seedItems(
      Array.from({ length: count }, (_, i) =>
        makeLogin(
          `i${String(i).padStart(3, '0')}`,
          'accounts.google.com',
          `user${String(i).padStart(3, '0')}@example.com`,
          'https://accounts.google.com',
        ),
      ),
    );
  }

  it('renders a subtitle on every virtualized row, keeping the aria bookkeeping', () => {
    seedSameNamedLogins(60);
    renderList();

    const list = screen.getByRole('list', { name: 'Vault items list' });
    const rows = within(list).getAllByRole('listitem');

    // The window renders a subset — that IS the virtualized branch.
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThan(60);

    for (const row of rows) {
      expect(row).toHaveAttribute('aria-setsize', '60');
      expect(within(row).getByTestId('vault-item-subtitle')).toBeInTheDocument();
    }
    const positions = rows.map((r) => Number(r.getAttribute('aria-posinset')));
    expect(positions).toEqual(positions.map((_, i) => i + 1));
  });

  it('gives every rendered row a DIFFERENT subtitle even though all names match', () => {
    seedSameNamedLogins(60);
    renderList();

    const subtitles = renderedSubtitles();
    expect(subtitles.length).toBeGreaterThan(1);
    expect(new Set(subtitles).size).toBe(subtitles.length);
    expect(subtitles[0]).toBe('user000@example.com');
  });

  it('stays on the plain branch at exactly the 50-item threshold, still with subtitles', () => {
    seedSameNamedLogins(50);
    renderList();

    // Non-virtualized renders EVERY row; virtualization renders only a window.
    expect(screen.getAllByRole('listitem')).toHaveLength(50);
    expect(renderedSubtitles()).toHaveLength(50);
  });

  it('never renders a password on a virtualized row', () => {
    seedSameNamedLogins(60);
    renderList();

    expect(screen.getByRole('list', { name: 'Vault items list' }).textContent ?? '').not.toContain(
      'never-render-me',
    );
  });
});

// ===========================================================================
// sortItems — the total order
// ===========================================================================

describe('VaultList ordering — subtitle-then-id tiebreaker', () => {
  /** Ten identically-named logins, seeded in an order unrelated to username. */
  function seedTenGoogleAccounts() {
    const usernames = [
      'zoe@example.com',
      'carol@example.com',
      'alice@example.com',
      'trent@example.com',
      'bob@example.com',
      'peggy@example.com',
      'dave@example.com',
      'mallory@example.com',
      'erin@example.com',
      'frank@example.com',
    ];
    seedItems(
      usernames.map((username, i) =>
        makeLogin(`id${String(i)}`, 'accounts.google.com', username, 'https://accounts.google.com'),
      ),
    );
    return [...usernames].sort((a, b) => a.localeCompare(b));
  }

  it('orders ten same-named logins by username instead of by fetch order', () => {
    const expected = seedTenGoogleAccounts();
    renderList();

    expect(renderedSubtitles()).toEqual(expected);
  });

  it('reverses that order exactly when the sort direction is flipped', () => {
    const expected = seedTenGoogleAccounts();
    renderList();

    fireEvent.click(screen.getByRole('button', { name: 'Sort descending' }));

    expect(renderedSubtitles()).toEqual([...expected].reverse());
  });

  it('falls through to the id when name AND subtitle are identical, whatever the input order', () => {
    // Same name, same username: only the id can separate these three, and the
    // result must not depend on the order the store happened to load them in —
    // a paged fetch, an offline-cache read and a re-fetch all differ there.
    //
    // Selection is keyed by id, so a selected row is an observable identity
    // marker: re-seed the SAME items in a different order and the selected row
    // must still be in the same position.
    const rows = [
      makeLogin('ccc', 'Shared', 'same@example.com', 'https://example.com'),
      makeLogin('aaa', 'Shared', 'same@example.com', 'https://example.com'),
      makeLogin('bbb', 'Shared', 'same@example.com', 'https://example.com'),
    ];
    seedItems(rows);
    renderList();

    fireEvent.click(screen.getAllByLabelText('Select item')[0]!);
    expect(screen.getByText('1 selected')).toBeInTheDocument();

    // Reshuffle the source order; nothing about the items themselves changed.
    act(() => {
      useVaultStore.setState({ items: [rows[1]!, rows[2]!, rows[0]!] });
    });

    const listRows = screen.getAllByRole('listitem');
    expect(listRows).toHaveLength(3);
    expect(within(listRows[0]!).getByLabelText('Deselect item')).toBeInTheDocument();
    expect(within(listRows[1]!).getByLabelText('Select item')).toBeInTheDocument();
    expect(within(listRows[2]!).getByLabelText('Select item')).toBeInTheDocument();
  });

  it('leaves the other sort options behaving as before', () => {
    // Bravo and Charlie are built to isolate the NAME tiebreaker: they tie on
    // createdAt AND on itemType AND on subtitle, Charlie is seeded first (so a
    // stable sort would keep it first), and their ids run the OTHER way
    // (`z-bravo` > `a-charlie`, so the id fallback would also put Charlie
    // first). Only the name comparison can produce Bravo, Charlie — every other
    // link in the chain votes the opposite way.
    seedItems([
      makeItem({
        id: 'm-alpha',
        name: 'Alpha',
        itemType: 'secret',
        data: { value: 'v' },
        createdAt: '2024-01-03T00:00:00.000Z',
        updatedAt: '2024-01-01T00:00:00.000Z',
      }),
      makeLogin('a-charlie', 'Charlie', 'carol@example.com', 'https://example.com'),
      makeLogin('z-bravo', 'Bravo', 'carol@example.com', 'https://example.com'),
    ]);
    renderList();

    const names = () =>
      screen.getAllByRole('listitem').map((row) => within(row).getByRole('button').textContent);

    // Name (default), ascending.
    expect(names()[0]).toContain('Alpha');
    expect(names()[2]).toContain('Charlie');

    fireEvent.click(screen.getByRole('button', { name: /Name/ }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Date Created' }));
    // createdAt: Bravo 01-01, Charlie 01-01, Alpha 01-03 — the two tie on the
    // date, so the NAME tiebreaker settles them.
    expect(names()[0]).toContain('Bravo');
    expect(names()[1]).toContain('Charlie');
    expect(names()[2]).toContain('Alpha');

    fireEvent.click(screen.getByRole('button', { name: /Date Created/ }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Type' }));
    // itemType asc: the two logins, then the secret — and again only the name
    // settles Bravo before Charlie.
    expect(names()[0]).toContain('Bravo');
    expect(names()[1]).toContain('Charlie');
    expect(names()[2]).toContain('Alpha');
  });
});
