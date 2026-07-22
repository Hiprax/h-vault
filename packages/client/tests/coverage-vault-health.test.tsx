/**
 * VaultHealthPage behavior coverage.
 *
 * Exercises each health detector independently (weak / reused / old / missing
 * TOTP / breached), the health-score arithmetic, the batched breach-check flow
 * (hit, miss, partial failure surfaced honestly, determinate progress, in-flight
 * state), the loading state, the initial fetch branch, finding-list virtualization
 * above the threshold, section expand/collapse and navigation from a finding to
 * its item.
 *
 * Weak-password scoring now runs through the strength analyzer, which in jsdom
 * (no `Worker`) takes its main-thread fallback and calls the mocked `getZxcvbn`.
 * Findings therefore arrive asynchronously via an effect, so they are asserted
 * with `waitFor`.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within, act, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------

const { mockCheckBreachBatchApi, mockNavigate, mockGetZxcvbn, zxcvbnScores } = vi.hoisted(() => ({
  mockCheckBreachBatchApi: vi.fn(),
  mockNavigate: vi.fn(),
  mockGetZxcvbn: vi.fn(),
  zxcvbnScores: new Map<string, number>(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

// Render every virtualized row deterministically so the >50-finding branch is
// assertable in jsdom (the real react-window renders 0 rows against a 0-height
// layout).
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
    const rows = [];
    for (let i = 0; i < Math.min(rowCount, 20); i++) {
      rows.push(
        React.createElement(RowComponent, {
          key: i,
          index: i,
          style: { height: rowHeight },
          ...rowProps,
        }),
      );
    }
    return React.createElement('div', { role: 'list', 'data-testid': 'virtual-list' }, ...rows);
  },
}));

vi.mock('../src/services/api/userApi', () => ({
  checkBreachApi: vi.fn(),
  checkBreachBatchApi: (...args: unknown[]) => mockCheckBreachBatchApi(...args),
}));

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: (...args: unknown[]) => mockGetZxcvbn(...args),
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
    decryptData: vi.fn(),
    encryptData: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
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
    getCachedItems: vi.fn().mockResolvedValue([]),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

// Keep these detector-focused tests hermetic: no real IndexedDB hydration/persist.
// (The persistence behavior has its own suite in vault-health-persistence.test.tsx.)
vi.mock('../src/services/health/healthResultsStore', () => ({
  loadHealthResults: vi.fn().mockResolvedValue(null),
  saveBreachResults: vi.fn().mockResolvedValue(undefined),
  saveStrengthScores: vi.fn().mockResolvedValue(undefined),
  clearHealthResults: vi.fn().mockResolvedValue(undefined),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import VaultHealthPage from '../src/pages/VaultHealthPage';
import { useVaultStore, type DecryptedVaultItem } from '../src/stores/vaultStore';
import { clearScoreCache } from '../src/services/health/strengthCache';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

/** Fake zxcvbn: score comes from `zxcvbnScores`, defaulting to a strong 4. */
interface FakeResult {
  score: number;
}
const fakeZxcvbn = (password: string): FakeResult => ({
  score: zxcvbnScores.get(password) ?? 4,
});

let itemSeq = 0;
function makeLogin(
  overrides: Partial<DecryptedVaultItem> & { id: string; name: string },
): DecryptedVaultItem {
  // Unique timestamps keep the strength cache keyed by `id:updatedAt` from ever
  // colliding across items/tests.
  const now = new Date(Date.now() + itemSeq++).toISOString();
  return {
    itemType: 'login',
    favorite: false,
    tags: [],
    createdAt: now,
    updatedAt: now,
    data: { username: 'u', password: 'StrongPassword!1', totp: 'JBSWY3DPEHPK3PXP' },
    ...overrides,
  } as DecryptedVaultItem;
}

function setItems(items: DecryptedVaultItem[], loading = false): void {
  useVaultStore.setState({
    items,
    itemsLoading: loading,
    trashLoading: false,
    loading,
    fetchItems: vi.fn().mockResolvedValue(undefined),
  });
}

async function renderPage(): Promise<void> {
  render(
    <MemoryRouter>
      <VaultHealthPage />
    </MemoryRouter>,
  );
  await act(async () => {
    // Two microtask flushes: the first lets the hydration effect settle
    // (`hydrated` flips true), the second lets the now-ungated weak-strength
    // effect run.
    await Promise.resolve();
    await Promise.resolve();
  });
}

/** The collapsible section whose header button carries `title`. */
function section(title: string): HTMLElement {
  const heading = screen.getByText(title);
  const container = heading.closest('div.rounded-lg');
  if (!container) throw new Error(`section ${title} not found`);
  return container as HTMLElement;
}

/** Click and flush the resulting state updates. */
async function clickAsync(el: HTMLElement): Promise<void> {
  await act(async () => {
    fireEvent.click(el);
    await Promise.resolve();
  });
}

async function sha1Hex(password: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** Build a batch response body keyed by full-hash prefixes. */
function batchBody(
  ranges: Record<string, string>,
  errors: string[] = [],
): { data: { success: boolean; data: Record<string, string>; errors: string[] } } {
  return { data: { success: true, data: ranges, errors } };
}

beforeEach(() => {
  vi.clearAllMocks();
  zxcvbnScores.clear();
  clearScoreCache();
  mockGetZxcvbn.mockResolvedValue(fakeZxcvbn);
  setItems([]);
});

afterEach(() => {
  useVaultStore.setState({ items: [], loading: false, itemsLoading: false, trashLoading: false });
});

// ---------------------------------------------------------------------------
// Loading / initial fetch
// ---------------------------------------------------------------------------

describe('VaultHealthPage - loading and initial fetch', () => {
  it('renders only the loading spinner while the vault is loading', async () => {
    setItems([], true);
    await renderPage();

    expect(screen.getByText('Loading vault items...')).toBeInTheDocument();
    expect(screen.queryByText('Health Score')).not.toBeInTheDocument();
  });

  it('fetches items on mount when the vault is empty and idle', async () => {
    const fetchItems = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ items: [], loading: false, fetchItems });

    await renderPage();

    expect(fetchItems).toHaveBeenCalledTimes(1);
  });

  it('does not re-fetch when items are already loaded', async () => {
    const fetchItems = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({
      items: [makeLogin({ id: 'a', name: 'A' })],
      loading: false,
      fetchItems,
    });

    await renderPage();

    expect(fetchItems).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

describe('VaultHealthPage - weak password detection', () => {
  it('flags only passwords scoring below the threshold and labels them by score', async () => {
    zxcvbnScores.set('pw-very-weak', 0);
    zxcvbnScores.set('pw-fair', 2);
    zxcvbnScores.set('pw-good', 3);
    setItems([
      makeLogin({ id: 'w0', name: 'Very Weak Site', data: { password: 'pw-very-weak' } }),
      makeLogin({ id: 'w2', name: 'Fair Site', data: { password: 'pw-fair' } }),
      makeLogin({ id: 'ok', name: 'Good Site', data: { password: 'pw-good' } }),
    ]);

    await renderPage();

    const weak = section('Weak Passwords');
    await waitFor(() => expect(within(weak).getByText('Very Weak Site')).toBeInTheDocument());
    expect(within(weak).getByText('Password strength: Very weak')).toBeInTheDocument();
    expect(within(weak).getByText('Fair Site')).toBeInTheDocument();
    expect(within(weak).getByText('Password strength: Fair')).toBeInTheDocument();
    // score 3 is the healthy boundary and must not be reported
    expect(within(weak).queryByText('Good Site')).not.toBeInTheDocument();
  });

  it('ignores non-login items and passwordless logins', async () => {
    zxcvbnScores.set('leaky', 0);
    setItems([
      makeLogin({ id: 'n1', name: 'A Note', itemType: 'note', data: { password: 'leaky' } }),
      makeLogin({ id: 'l1', name: 'No Password Login', data: { username: 'u' } }),
    ]);

    await renderPage();

    const weak = section('Weak Passwords');
    expect(within(weak).queryByText('A Note')).not.toBeInTheDocument();
    expect(within(weak).queryByText('No Password Login')).not.toBeInTheDocument();
    // The note is not a login, so only the one login counts toward the total.
    expect(screen.getAllByText('of 1 items').length).toBe(4);
  });

  it('shows an Analyzing state and no findings until scoring resolves', async () => {
    zxcvbnScores.set('pw-very-weak', 0);
    mockGetZxcvbn.mockReturnValue(new Promise<never>(() => {})); // never resolves
    setItems([makeLogin({ id: 'w0', name: 'Very Weak Site', data: { password: 'pw-very-weak' } })]);

    await renderPage();

    // The Weak score card shows a spinner while analysis is pending.
    expect(screen.getByLabelText('Analyzing Weak')).toBeInTheDocument();
    const weak = section('Weak Passwords');
    expect(within(weak).queryByText('Very Weak Site')).not.toBeInTheDocument();
    // Other detectors still run synchronously: the item has no TOTP.
    expect(within(section('Missing 2FA')).getByText('Very Weak Site')).toBeInTheDocument();
  });

  it('surfaces a strength-analysis failure and never a false "No issues found"', async () => {
    // Both the worker (absent in jsdom) and the lazy zxcvbn fallback fail.
    mockGetZxcvbn.mockRejectedValue(new Error('chunk load failed'));
    setItems([makeLogin({ id: 'x', name: 'Some Site', data: { password: 'whatever' } })]);

    await renderPage();

    // The Weak score card shows a failure indicator, not a (misleading) zero.
    await waitFor(() => expect(screen.getByLabelText('Weak analysis failed')).toBeInTheDocument());

    const weak = section('Weak Passwords');
    await clickAsync(within(weak).getByRole('button', { name: /Weak Passwords/ }));
    expect(within(weak).getByText(/Could not analyze password strength/)).toBeInTheDocument();
    // The critical guarantee: a failed analysis must NOT read as "all clear".
    expect(within(weak).queryByText('No issues found')).not.toBeInTheDocument();
  });

  it('does not flag an undecodable item (no password) as weak or reused', async () => {
    setItems([
      makeLogin({ id: 'bad', name: 'Corrupt Item', data: { _raw: 'undecryptable-blob' } }),
      makeLogin({ id: 'bad2', name: 'Corrupt Item 2', data: { _raw: 'undecryptable-blob' } }),
    ]);

    await renderPage();

    expect(within(section('Weak Passwords')).queryByText('Corrupt Item')).not.toBeInTheDocument();
    expect(within(section('Reused Passwords')).queryByText('Corrupt Item')).not.toBeInTheDocument();
    expect(within(section('Old Passwords')).queryByText('Corrupt Item')).not.toBeInTheDocument();
  });
});

describe('VaultHealthPage - reused password detection', () => {
  it('flags every item sharing a password and counts the duplicates', async () => {
    setItems([
      makeLogin({ id: 'r1', name: 'Site One', data: { password: 'shared-pw' } }),
      makeLogin({ id: 'r2', name: 'Site Two', data: { password: 'shared-pw' } }),
      makeLogin({ id: 'r3', name: 'Site Three', data: { password: 'shared-pw' } }),
      makeLogin({ id: 'u1', name: 'Unique Site', data: { password: 'unique-pw' } }),
    ]);

    await renderPage();

    const reused = section('Reused Passwords');
    expect(within(reused).getByText('Site One')).toBeInTheDocument();
    expect(within(reused).getByText('Site Two')).toBeInTheDocument();
    expect(within(reused).getByText('Site Three')).toBeInTheDocument();
    expect(within(reused).queryByText('Unique Site')).not.toBeInTheDocument();
    expect(within(reused).getAllByText('Password shared with 2 other item(s)')).toHaveLength(3);
  });

  it('reports no reuse when every password is distinct', async () => {
    setItems([
      makeLogin({ id: 'a', name: 'Alpha', data: { password: 'pw-a' } }),
      makeLogin({ id: 'b', name: 'Beta', data: { password: 'pw-b' } }),
    ]);

    await renderPage();

    const reused = section('Reused Passwords');
    // Empty sections start collapsed; expanding shows the healthy state.
    await clickAsync(within(reused).getByRole('button', { name: /Reused Passwords/ }));
    expect(within(reused).getByText('No issues found')).toBeInTheDocument();
  });

  it('virtualizes the finding list above the threshold', async () => {
    const items = Array.from({ length: 51 }, (_, i) =>
      makeLogin({ id: `dup-${i}`, name: `Dup Site ${i}`, data: { password: 'one-shared-pw' } }),
    );
    setItems(items);

    await renderPage();

    const reused = section('Reused Passwords');
    expect(within(reused).getByTestId('virtual-list')).toBeInTheDocument();
    // The mocked window renders the first rows; the first finding is present.
    expect(within(reused).getByText('Dup Site 0')).toBeInTheDocument();
  });
});

describe('VaultHealthPage - old password detection', () => {
  it('flags logins untouched for more than 90 days with their exact age', async () => {
    setItems([
      makeLogin({
        id: 'old',
        name: 'Stale Login',
        data: { password: 'pw-old' },
        updatedAt: new Date(Date.now() - 100 * DAY_MS).toISOString(),
      }),
      makeLogin({
        id: 'fresh',
        name: 'Recent Login',
        data: { password: 'pw-fresh' },
        updatedAt: new Date(Date.now() - 89 * DAY_MS).toISOString(),
      }),
    ]);

    await renderPage();

    const old = section('Old Passwords');
    expect(within(old).getByText('Stale Login')).toBeInTheDocument();
    expect(within(old).getByText('Last updated 100 days ago')).toBeInTheDocument();
    expect(within(old).queryByText('Recent Login')).not.toBeInTheDocument();
  });
});

describe('VaultHealthPage - missing TOTP detection', () => {
  it('flags logins without a TOTP secret and skips those with one', async () => {
    setItems([
      makeLogin({ id: 't1', name: 'No 2FA Site', data: { password: 'p', totp: '' } }),
      makeLogin({ id: 't2', name: 'With 2FA Site', data: { password: 'p2', totp: 'ABCDEFGH' } }),
    ]);

    await renderPage();

    const totp = section('Missing 2FA');
    expect(within(totp).getByText('No 2FA Site')).toBeInTheDocument();
    expect(within(totp).getByText('No 2FA/TOTP configured')).toBeInTheDocument();
    expect(within(totp).queryByText('With 2FA Site')).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Health score
// ---------------------------------------------------------------------------

describe('VaultHealthPage - health score', () => {
  it('scores 100 with no login items', async () => {
    setItems([]);
    await renderPage();
    expect(screen.getByText('100')).toBeInTheDocument();
  });

  it('scores 100 when every login is healthy', async () => {
    setItems([
      makeLogin({ id: 'h1', name: 'Healthy One', data: { password: 'strong-1', totp: 'AA' } }),
      makeLogin({ id: 'h2', name: 'Healthy Two', data: { password: 'strong-2', totp: 'BB' } }),
    ]);

    await renderPage();

    await waitFor(() => expect(screen.getByText('100')).toBeInTheDocument());
    const weak = section('Weak Passwords');
    await clickAsync(within(weak).getByRole('button', { name: /Weak Passwords/ }));
    expect(within(weak).getByText('No issues found')).toBeInTheDocument();
  });

  it('derives the score from weak+reused+old over 3 categories before a breach check', async () => {
    zxcvbnScores.set('shared-weak', 0);
    setItems([
      makeLogin({ id: 's1', name: 'Site One', data: { password: 'shared-weak' } }),
      makeLogin({ id: 's2', name: 'Site Two', data: { password: 'shared-weak' } }),
    ]);

    await renderPage();

    // weak 2 + reused 2 + old 0 = 4 issues over (2 items x 3 categories) = 6 -> 33
    await waitFor(() => expect(screen.getByText('33')).toBeInTheDocument());
  });

  it('adds breached items as a 4th category once the breach check has run', async () => {
    zxcvbnScores.set('shared-weak', 0);
    const hash = await sha1Hex('shared-weak');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({ [hash.substring(0, 5)]: `${hash.substring(5)}:5000` }),
    );
    setItems([
      makeLogin({ id: 's1', name: 'Site One', data: { password: 'shared-weak' } }),
      makeLogin({ id: 's2', name: 'Site Two', data: { password: 'shared-weak' } }),
    ]);

    await renderPage();
    await waitFor(() => expect(screen.getByText('33')).toBeInTheDocument());
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    // weak 2 + reused 2 + breached 2 = 6 over (2 items x 4 categories) = 8 -> 25
    await waitFor(() => expect(screen.getByText('25')).toBeInTheDocument(), { timeout: 5000 });
  });
});

// ---------------------------------------------------------------------------
// Breach check
// ---------------------------------------------------------------------------

describe('VaultHealthPage - breach check', () => {
  it('sends only 5-char prefixes and reports a matching suffix as breached', async () => {
    const hash = await sha1Hex('pwned-password');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({
        [hash.substring(0, 5)]:
          `0000000000000000000000000000000000000:1\r\n${hash.substring(5)}:1234`,
      }),
    );
    setItems([
      makeLogin({ id: 'b1', name: 'Breached Site', data: { password: 'pwned-password' } }),
    ]);

    await renderPage();
    expect(screen.getByText(/Click .* to scan your passwords/)).toBeInTheDocument();

    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() =>
      expect(screen.getByText('Found in 1,234 data breach(es)')).toBeInTheDocument(),
    );
    // k-anonymity: exactly the 5-char prefix is sent, never the full hash.
    const sentPrefixes = mockCheckBreachBatchApi.mock.calls[0]?.[0] as string[];
    expect(sentPrefixes).toEqual([hash.substring(0, 5)]);
    expect(sentPrefixes.every((p) => p.length === 5)).toBe(true);
    const breachSection = section('Breached Passwords');
    expect(within(breachSection).getByText('Breached Site')).toBeInTheDocument();
  });

  it('reports no breaches when the range response contains no matching suffix', async () => {
    const hash = await sha1Hex('clean-password');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({ [hash.substring(0, 5)]: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\r\nAAAAA:2' }),
    );
    setItems([makeLogin({ id: 'c1', name: 'Clean Site', data: { password: 'clean-password' } })]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() =>
      expect(screen.getByText('No breached passwords found')).toBeInTheDocument(),
    );
    expect(within(section('Breached Passwords')).queryByText('Clean Site')).not.toBeInTheDocument();
  });

  it('surfaces passwords that could not be checked instead of calling them safe', async () => {
    const hashOk = await sha1Hex('pwned-password');
    const hashFail = await sha1Hex('network-error-password');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({ [hashOk.substring(0, 5)]: `${hashOk.substring(5)}:7` }, [
        hashFail.substring(0, 5),
      ]),
    );
    setItems([
      makeLogin({ id: 'f1', name: 'Failing Site', data: { password: 'network-error-password' } }),
      makeLogin({ id: 'b1', name: 'Breached Site', data: { password: 'pwned-password' } }),
    ]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() => expect(screen.getByText('Found in 7 data breach(es)')).toBeInTheDocument());
    // The unresolved password is reported as unchecked, NOT as "no breach".
    expect(screen.getByText(/1 password\(s\) could not be checked/)).toBeInTheDocument();
    const breachSection = section('Breached Passwords');
    expect(within(breachSection).getByText('Breached Site')).toBeInTheDocument();
    expect(within(breachSection).queryByText('Failing Site')).not.toBeInTheDocument();
  });

  it('marks the whole batch unchecked when the request itself fails', async () => {
    mockCheckBreachBatchApi.mockRejectedValue(new Error('network down'));
    setItems([makeLogin({ id: 'x1', name: 'Some Site', data: { password: 'a-password' } })]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() =>
      expect(screen.getByText(/1 password\(s\) could not be checked/)).toBeInTheDocument(),
    );
    // Nothing is reported breached, and the misleading "no breaches" line is hidden.
    expect(screen.queryByText('No breached passwords found')).not.toBeInTheDocument();
  });

  it('shows a determinate progress indicator while a scan is in flight', async () => {
    const hash = await sha1Hex('pw');
    let resolveApi: (value: ReturnType<typeof batchBody>) => void = () => {};
    mockCheckBreachBatchApi.mockReturnValue(
      new Promise<ReturnType<typeof batchBody>>((resolve) => {
        resolveApi = resolve;
      }),
    );
    setItems([makeLogin({ id: 'b1', name: 'Some Site', data: { password: 'pw' } })]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    const checking = await screen.findByRole('button', { name: /Checking/ });
    expect(checking).toBeDisabled();
    expect(await screen.findByRole('progressbar')).toBeInTheDocument();
    expect(screen.getByText('0 / 1')).toBeInTheDocument();

    await act(async () => {
      resolveApi(batchBody({ [hash.substring(0, 5)]: `${hash.substring(5)}:1` }));
    });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Check for Breaches/ })).toBeEnabled(),
    );
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });

  it('checks each unique password once even when several items share it', async () => {
    const hash = await sha1Hex('reused-pw');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({ [hash.substring(0, 5)]: `${hash.substring(5)}:3` }),
    );
    setItems([
      makeLogin({ id: 'a', name: 'Site A', data: { password: 'reused-pw' } }),
      makeLogin({ id: 'b', name: 'Site B', data: { password: 'reused-pw' } }),
    ]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() => expect(screen.getAllByText('Found in 3 data breach(es)')).toHaveLength(2));
    // One request, one unique prefix — not one per item.
    expect(mockCheckBreachBatchApi).toHaveBeenCalledTimes(1);
    expect(mockCheckBreachBatchApi.mock.calls[0]?.[0]).toEqual([hash.substring(0, 5)]);
  });

  it('does not call the breach API when no login has a password', async () => {
    setItems([
      makeLogin({ id: 'n1', name: 'A Note', itemType: 'note', data: { password: 'pw' } }),
      makeLogin({ id: 'l1', name: 'Passwordless', data: { username: 'u' } }),
    ]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));

    await waitFor(() =>
      expect(screen.getByText('No breached passwords found')).toBeInTheDocument(),
    );
    expect(mockCheckBreachBatchApi).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Sections & navigation
// ---------------------------------------------------------------------------

describe('VaultHealthPage - sections and navigation', () => {
  it('navigates to the item when a finding is clicked', async () => {
    zxcvbnScores.set('pw-weak', 1);
    setItems([makeLogin({ id: 'item-42', name: 'Weak Site', data: { password: 'pw-weak' } })]);

    await renderPage();
    const weak = section('Weak Passwords');
    await waitFor(() => expect(within(weak).getByText('Weak Site')).toBeInTheDocument());
    await clickAsync(within(weak).getByText('Weak Site'));

    expect(mockNavigate).toHaveBeenCalledWith('/vault/item-42');
  });

  it('navigates to the item when a breached finding is clicked', async () => {
    const hash = await sha1Hex('pwned');
    mockCheckBreachBatchApi.mockResolvedValue(
      batchBody({ [hash.substring(0, 5)]: `${hash.substring(5)}:3` }),
    );
    setItems([makeLogin({ id: 'item-99', name: 'Breached Site', data: { password: 'pwned' } })]);

    await renderPage();
    await clickAsync(screen.getByRole('button', { name: /Check for Breaches/ }));
    const breachSection = section('Breached Passwords');
    await within(breachSection).findByText('Breached Site');

    await clickAsync(within(breachSection).getByText('Breached Site'));

    expect(mockNavigate).toHaveBeenCalledWith('/vault/item-99');
  });

  it('collapses an expanded section, hiding its findings', async () => {
    zxcvbnScores.set('pw-weak', 1);
    setItems([makeLogin({ id: 'w1', name: 'Weak Site', data: { password: 'pw-weak' } })]);

    await renderPage();
    const weak = section('Weak Passwords');
    await waitFor(() => expect(within(weak).getByText('Weak Site')).toBeInTheDocument());

    await clickAsync(within(weak).getByRole('button', { name: /Weak Passwords/ }));

    expect(within(weak).queryByText('Weak Site')).not.toBeInTheDocument();
  });

  it('auto-expands the Weak Passwords section once async scoring produces findings', async () => {
    zxcvbnScores.set('pw-weak', 1);
    let resolveZxcvbn: (fn: typeof fakeZxcvbn) => void = () => {};
    mockGetZxcvbn.mockReturnValue(
      new Promise<typeof fakeZxcvbn>((resolve) => {
        resolveZxcvbn = resolve;
      }),
    );
    setItems([makeLogin({ id: 'w1', name: 'Weak Site', data: { password: 'pw-weak' } })]);

    await renderPage();
    const weak = section('Weak Passwords');
    expect(within(weak).queryByText('Weak Site')).not.toBeInTheDocument();

    await act(async () => {
      resolveZxcvbn(fakeZxcvbn);
      await Promise.resolve();
    });

    await waitFor(() => expect(within(weak).getByText('Weak Site')).toBeInTheDocument());
  });
});
