/**
 * The Settings card that finds the entries a master password reset left
 * unreadable, and offers to recover them with the backup password or to delete
 * them for good.
 *
 * What it must never do: offer an action while the check is blocked or found only
 * damaged rows; call the vault clean while anything at all is reported; send a
 * deletion before the master password has been checked in this browser, or without
 * the acknowledgement when a backup copy could still recover the rows; or act on a
 * result judged under a key the session no longer holds.
 */
import { StrictMode } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Link } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import type { IUserProfile } from '@hvault/shared';

const mockScan = vi.fn();
const mockProve = vi.fn();
const mockPurge = vi.fn();
const mockCheckHeld = vi.fn();
const mockFetchItems = vi.fn();
const mockFetchTrashItems = vi.fn();
const mockFetchFolders = vi.fn();
const toast = vi.fn();

vi.mock('../../src/services/vault/unreadableEntries', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/services/vault/unreadableEntries')>()),
  scanUnreadableEntries: (...args: unknown[]) => mockScan(...args) as unknown,
}));
vi.mock('../../src/lib/masterPasswordProof', () => ({
  proveMasterPasswordForHeldKey: (...args: unknown[]) => mockProve(...args) as unknown,
}));
vi.mock('../../src/services/api/vaultApi', () => ({
  purgeUnreadableApi: (...args: unknown[]) => mockPurge(...args) as unknown,
}));
vi.mock('../../src/stores/heldVaultKey', () => ({
  checkHeldVaultKey: (...args: unknown[]) => mockCheckHeld(...args) as unknown,
}));
vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: {
    getState: () => ({
      fetchItems: mockFetchItems,
      fetchTrashItems: mockFetchTrashItems,
      fetchFolders: mockFetchFolders,
    }),
  },
}));
vi.mock('../../src/stores/authStore', async () => {
  const { create } = await import('zustand');
  return {
    useAuthStore: create(() => ({
      vaultKey: null as CryptoKey | null,
      mek: null as CryptoKey | null,
      user: null as { email: string } | null,
    })),
  };
});
vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast }),
}));

import { UnreadableEntriesCard } from '../../src/components/settings/UnreadableEntriesCard';
import { useAuthStore } from '../../src/stores/authStore';
import { useUIStore } from '../../src/stores/uiStore';
import type { UnreadableScan } from '../../src/services/vault/unreadableEntries';

const HELD_KEY = { held: true } as unknown as CryptoKey;
const MEK = { mek: true } as unknown as CryptoKey;
const WRAPPER = { encrypted: 'wrapped', iv: 'wrap-iv', tag: 'wrap-tag' };
const CREATED = '2026-01-02T00:00:00.000Z';
const DATE = new Date(CREATED).toLocaleDateString();

const ITEM_A = {
  id: 'a'.repeat(24),
  nameIv: 'n-a',
  dataIv: 'd-a',
  itemType: 'login' as const,
  createdAt: CREATED,
  inTrash: false,
};
const ITEM_B = {
  ...ITEM_A,
  id: 'b'.repeat(24),
  nameIv: 'n-b',
  dataIv: 'd-b',
  itemType: 'note' as const,
  inTrash: true,
};
const FOLDER = { id: 'c'.repeat(24), nameIv: 'n-c', createdAt: CREATED };

function scanOf(overrides: Partial<UnreadableScan> = {}): UnreadableScan {
  return {
    wrapper: WRAPPER,
    items: [ITEM_A, ITEM_B],
    folders: [FOLDER],
    damaged: { items: 0, folders: 0 },
    documents: 0,
    ...overrides,
  };
}

const CLEAN = scanOf({ items: [], folders: [] });

/** A profile whose backup does, or does not, hold a copy of a vault key. */
function profileWith(copy: boolean): IUserProfile {
  return {
    email: 'ada@example.com',
    settings: {
      backup: {
        enabled: true,
        scheduleHour: 3,
        isConfigured: true,
        encryptedBWK: 'bwk',
        bwkIv: 'bwk-iv',
        bwkTag: 'bwk-tag',
        bwkSalt: 'salt',
        ...(copy
          ? { bwkEncryptedVaultKey: 'copy', bwkVaultKeyIv: 'copy-iv', bwkVaultKeyTag: 'copy-tag' }
          : {}),
      },
    },
  } as unknown as IUserProfile;
}

function refusal(status: number, message: string, data: Record<string, unknown> = {}): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError(message, 'ERR_BAD_REQUEST', { headers }, null, {
    status,
    statusText: 'Refused',
    headers: {},
    config: { headers },
    data: { success: false, message, statusCode: status, statusText: 'Refused', ...data },
  });
}

interface Options {
  copy?: boolean;
  path?: string;
  onRecover?: () => void;
  recoveryAttempts?: number;
  strict?: boolean;
}

function card({ copy = false, onRecover = vi.fn(), recoveryAttempts = 0 }: Options = {}) {
  return (
    <UnreadableEntriesCard
      profile={profileWith(copy)}
      onProfile={vi.fn()}
      onRecover={onRecover}
      busy={false}
      recoveryAttempts={recoveryAttempts}
    />
  );
}

function renderCard(options: Options = {}) {
  const tree = (
    <MemoryRouter initialEntries={[options.path ?? '/settings']}>
      {card(options)}
      <Link to="/settings#unreadable-entries">Review</Link>
    </MemoryRouter>
  );
  return render(options.strict ? <StrictMode>{tree}</StrictMode> : tree);
}

async function check() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Check entries' }));
  });
}

async function openDelete() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }));
  });
  return screen.getByRole('dialog');
}

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({
    vaultKey: HELD_KEY,
    mek: MEK,
    user: { userId: 'u1', email: 'ada@example.com' },
  });
  useUIStore.setState({ unreadableEntriesNotice: false, staleVaultKeyVersion: null });
  mockScan.mockResolvedValue({ kind: 'scanned', scan: scanOf() });
  mockProve.mockResolvedValue('proof');
  mockPurge.mockResolvedValue({
    data: {
      success: true,
      data: { deletedItems: 2, deletedFolders: 1, skippedItems: 0, skippedFolders: 0 },
    },
  });
  for (const fetch of [mockFetchItems, mockFetchTrashItems, mockFetchFolders]) {
    fetch.mockResolvedValue(undefined);
  }
});

describe('UnreadableEntriesCard: the check', () => {
  it('starts idle: a titled section with one control and no action', () => {
    renderCard();

    expect(
      screen.getByRole('heading', { level: 2, name: /Unreadable Entries/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check entries' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: /Delete permanently|Recover/ })).toBeNull();
    expect(mockScan).not.toHaveBeenCalled();
  });

  it('checks under the key and master key the store holds', async () => {
    renderCard();
    await check();

    expect(mockScan).toHaveBeenCalledWith(HELD_KEY, MEK, expect.any(Function));
  });

  it('lists what it found, by type, date and place, and raises the review flag', async () => {
    renderCard();
    await check();

    expect(
      screen.getByText('3 entries cannot be opened with your current vault key:'),
    ).toBeInTheDocument();
    const list = screen.getByRole('list');
    expect(
      within(list)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual([
      `Login, added ${DATE}`,
      `Note, added ${DATE}, in the trash`,
      `Folder, added ${DATE}`,
    ]);
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(true);
    // Without a stored copy there is nothing to recover with here; the other way back is named.
    expect(screen.queryByRole('button', { name: 'Recover with backup password' })).toBeNull();
    expect(screen.getByText(/No backup copy of an earlier key is stored/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete permanently' })).toBeEnabled();
  });

  it('offers recovery only when the backup holds a copy, and hands it to the page', async () => {
    const onRecover = vi.fn();
    renderCard({ copy: true, onRecover });
    await check();

    expect(screen.queryByText(/No backup copy of an earlier key is stored/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Recover with backup password' }));
    expect(onRecover).toHaveBeenCalledTimes(1);
  });

  it('calls the vault clean only when nothing at all is reported, lowering the flag and the banner', async () => {
    useUIStore.setState({ unreadableEntriesNotice: true });
    mockScan.mockResolvedValue({ kind: 'scanned', scan: CLEAN });
    const counts: number[] = [];
    const listener = (event: Event) =>
      counts.push((event as CustomEvent<{ count: number }>).detail.count);
    window.addEventListener('vault-decryption-failures', listener);
    renderCard();
    await check();
    window.removeEventListener('vault-decryption-failures', listener);

    expect(screen.getByText('Every entry opens with your current key.')).toBeInTheDocument();
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(false);
    expect(counts).toEqual([0]);
    expect(screen.queryByRole('button', { name: /Delete permanently|Recover/ })).toBeNull();
  });

  it('reports damaged rows without offering any action, and keeps the flag up', async () => {
    mockScan.mockResolvedValue({
      kind: 'scanned',
      scan: scanOf({ items: [], folders: [], damaged: { items: 1, folders: 1 } }),
    });
    const counts: number[] = [];
    const listener = (event: Event) =>
      counts.push((event as CustomEvent<{ count: number }>).detail.count);
    window.addEventListener('vault-decryption-failures', listener);
    renderCard({ copy: true });
    await check();
    window.removeEventListener('vault-decryption-failures', listener);

    expect(screen.getByText(/2 entries are damaged/)).toBeInTheDocument();
    expect(screen.queryByText('Every entry opens with your current key.')).toBeNull();
    expect(screen.queryByRole('button', { name: /Delete permanently|Recover/ })).toBeNull();
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(true);
    expect(counts).toEqual([]);
  });

  it('points unopenable documents at the Documents page, and offers recovery for them', async () => {
    mockScan.mockResolvedValue({
      kind: 'scanned',
      scan: scanOf({ items: [], folders: [], documents: 2 }),
    });
    renderCard({ copy: true });
    await check();

    expect(screen.getByText(/2 documents cannot be opened either/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Documents page' })).toHaveAttribute(
      'href',
      '/documents',
    );
    expect(
      screen.getByRole('button', { name: 'Recover with backup password' }),
    ).toBeInTheDocument();
    // Documents are deleted on their own page, never here.
    expect(screen.queryByRole('button', { name: 'Delete permanently' })).toBeNull();
  });

  it('refuses to judge during an interrupted rotation, offering nothing', async () => {
    mockScan.mockResolvedValue({ kind: 'interrupted-rotation' });
    renderCard({ copy: true });
    await check();

    expect(screen.getByText(/Choose Finish Rotation above first/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Delete permanently|Recover/ })).toBeNull();
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(false);
  });

  it('asks the held-key check about a key that is not the account’s, offering nothing', async () => {
    mockScan.mockResolvedValue({ kind: 'key-not-current' });
    renderCard();
    await check();

    expect(screen.getByText(/Lock the vault and unlock it, then check again/)).toBeInTheDocument();
    expect(mockCheckHeld).toHaveBeenCalledWith(HELD_KEY);
    expect(screen.queryByRole('button', { name: /Delete permanently|Recover/ })).toBeNull();
  });

  it('lists at most 100 entries, items first, and says so, while counting them all', async () => {
    const many = Array.from({ length: 99 }, (_, n) => ({
      ...ITEM_A,
      id: n.toString(16).padStart(24, '0'),
    }));
    const folders = [FOLDER, { ...FOLDER, id: 'd'.repeat(24) }];
    mockScan.mockResolvedValue({ kind: 'scanned', scan: scanOf({ items: many, folders }) });
    renderCard();
    await check();

    expect(
      screen.getByText('101 entries cannot be opened with your current vault key:'),
    ).toBeInTheDocument();
    const list = screen.getByRole('list', { name: 'Entries that cannot be opened' });
    const rows = within(list).getAllByRole('listitem');
    expect(rows).toHaveLength(100);
    // 99 items, then as many folders as fit: one.
    expect(rows.at(-1)?.textContent).toBe(`Folder, added ${DATE}`);
    expect(rows.filter((row) => row.textContent?.startsWith('Folder'))).toHaveLength(1);
    expect(screen.getByText('The first 100 are listed.')).toBeInTheDocument();
    // Reachable from the keyboard, since it scrolls.
    expect(list).toHaveAttribute('tabindex', '0');
  });

  it('names one entry, one damaged entry and one document in the singular', async () => {
    mockScan.mockResolvedValue({
      kind: 'scanned',
      scan: scanOf({
        items: [ITEM_A],
        folders: [],
        damaged: { items: 1, folders: 0 },
        documents: 1,
      }),
    });
    renderCard();
    await check();

    expect(
      screen.getByText('1 entry cannot be opened with your current vault key:'),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/^1 entry is damaged: part of it opens, or it is malformed\./),
    ).toBeInTheDocument();
    expect(screen.getByText(/^1 document cannot be opened either/)).toBeInTheDocument();
    expect(screen.queryByText(/The first 100 are listed/)).toBeNull();
  });

  it('asks for an unlocked vault when the master key is gone, though a vault key is held', async () => {
    useAuthStore.setState({ mek: null });
    renderCard();
    await check();

    expect(screen.getByRole('alert')).toHaveTextContent('Unlock the vault first.');
    expect(mockScan).not.toHaveBeenCalled();
  });

  it('asks for an unlocked vault rather than checking without a key', async () => {
    useAuthStore.setState({ vaultKey: null });
    renderCard();
    await check();

    expect(screen.getByRole('alert')).toHaveTextContent('Unlock the vault first.');
    expect(mockScan).not.toHaveBeenCalled();
  });

  it('says a check failed, and calls nothing clean', async () => {
    mockScan.mockRejectedValue(refusal(429, 'Too many requests, try again later'));
    renderCard();
    await check();

    expect(screen.getByRole('alert')).toHaveTextContent('Too many requests, try again later');
    expect(screen.queryByText('Every entry opens with your current key.')).toBeNull();
  });

  it('drops a result the moment the store holds another key', async () => {
    renderCard();
    await check();
    expect(screen.getByRole('list')).toBeInTheDocument();

    act(() => {
      useAuthStore.setState({ vaultKey: null });
    });

    expect(screen.queryByRole('list')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete permanently' })).toBeNull();
  });

  it('discards a check whose key changed while it ran', async () => {
    mockScan.mockImplementation(() => {
      useAuthStore.setState({ vaultKey: { other: true } as unknown as CryptoKey });
      return Promise.resolve({ kind: 'scanned', scan: scanOf() });
    });
    renderCard();
    await check();

    expect(screen.queryByRole('list')).toBeNull();
    expect(useUIStore.getState().unreadableEntriesNotice).toBe(false);
  });

  it('checks once when opened from the banner’s Review link, StrictMode included, and again on the next click', async () => {
    await act(async () => {
      renderCard({ path: '/settings#unreadable-entries', strict: true });
    });
    await waitFor(() => {
      expect(screen.getByRole('list')).toBeInTheDocument();
    });
    expect(mockScan).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(screen.getByRole('heading', { level: 2 }));

    await act(async () => {
      fireEvent.click(screen.getByRole('link', { name: 'Review' }));
    });
    await waitFor(() => {
      expect(mockScan).toHaveBeenCalledTimes(2);
    });
  });

  it('checks again when the page reports a recovery was sent', async () => {
    const { rerender } = renderCard();
    expect(mockScan).not.toHaveBeenCalled();

    await act(async () => {
      rerender(<MemoryRouter>{card({ recoveryAttempts: 1 })}</MemoryRouter>);
    });

    expect(mockScan).toHaveBeenCalledTimes(1);
  });
});

describe('UnreadableEntriesCard: deleting', () => {
  it('sends nothing until the master password is typed and confirmed', async () => {
    renderCard();
    await check();
    const dialog = await openDelete();

    expect(within(dialog).getByText(/no key this account stores can open/)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Delete permanently' })).toBeDisabled();
    expect(within(dialog).queryByRole('checkbox')).toBeNull();
    expect(mockPurge).not.toHaveBeenCalled();
  });

  it('closes without sending, by Escape or by its close button, forgetting the password', async () => {
    renderCard({ copy: true });
    await check();

    let dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'typed' },
    });
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();

    dialog = await openDelete();
    expect(within(dialog).getByLabelText('Your master password')).toHaveValue('');
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /I tried Recover/ }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('dialog')).toBeNull();

    dialog = await openDelete();
    expect(within(dialog).getByRole('checkbox', { name: /I tried Recover/ })).not.toBeChecked();
    expect(mockProve).not.toHaveBeenCalled();
    expect(mockPurge).not.toHaveBeenCalled();
  });

  it('checks the master password here first, and sends nothing for a wrong one', async () => {
    mockProve.mockResolvedValue(null);
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'typo' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(mockProve).toHaveBeenCalledWith('typo', 'ada@example.com', HELD_KEY, WRAPPER);
    expect(within(dialog).getByRole('alert')).toHaveTextContent(
      'The master password is incorrect. Nothing was deleted.',
    );
    expect(mockPurge).not.toHaveBeenCalled();
    // Nothing was sent, so nothing is read again.
    expect(mockScan).toHaveBeenCalledTimes(1);
    expect(mockFetchItems).not.toHaveBeenCalled();
  });

  it('deletes exactly the rows judged, with their IVs, then reads everything again', async () => {
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'Master-Password-1!' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(mockPurge).toHaveBeenCalledTimes(1);
    expect(mockPurge).toHaveBeenCalledWith({
      authHash: 'proof',
      encryptedVaultKey: 'wrapped',
      vaultKeyIv: 'wrap-iv',
      vaultKeyTag: 'wrap-tag',
      items: [
        { id: ITEM_A.id, nameIv: 'n-a', dataIv: 'd-a' },
        { id: ITEM_B.id, nameIv: 'n-b', dataIv: 'd-b' },
      ],
      folders: [{ id: FOLDER.id, nameIv: 'n-c' }],
    });
    expect(toast).toHaveBeenCalledWith({ title: 'Deleted 3 unreadable entries', type: 'success' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(mockFetchItems).toHaveBeenCalledTimes(1);
    expect(mockFetchTrashItems).toHaveBeenCalledTimes(1);
    expect(mockFetchFolders).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(mockScan).toHaveBeenCalledTimes(2);
    });
  });

  it('names the entries kept because they changed since the check', async () => {
    mockPurge.mockResolvedValue({
      data: {
        success: true,
        data: { deletedItems: 1, deletedFolders: 0, skippedItems: 1, skippedFolders: 1 },
      },
    });
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(toast).toHaveBeenCalledWith({
      title: 'Deleted 1 unreadable entry',
      description: '2 entries changed since the check and were kept.',
      type: 'warning',
    });
  });

  it('names a single entry kept because it changed since the check in the singular', async () => {
    mockPurge.mockResolvedValue({
      data: {
        success: true,
        data: { deletedItems: 2, deletedFolders: 0, skippedItems: 0, skippedFolders: 1 },
      },
    });
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(toast).toHaveBeenCalledWith({
      title: 'Deleted 2 unreadable entries',
      description: '1 entry changed since the check and was kept.',
      type: 'warning',
    });
  });

  it('requires the acknowledgement when a backup copy could still recover them', async () => {
    renderCard({ copy: true });
    await check();
    const dialog = await openDelete();
    expect(within(dialog).getByText(/after a recovery, the backup copy opens/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    const confirm = within(dialog).getByRole('button', { name: 'Delete permanently' });
    expect(confirm).toBeDisabled();

    fireEvent.click(
      within(dialog).getByRole('checkbox', { name: /I tried Recover with backup password/ }),
    );
    expect(confirm).toBeEnabled();
  });

  it('shows a refusal verbatim, raises the stale-key notice, and checks again', async () => {
    mockPurge.mockRejectedValue(
      refusal(409, 'Your vault key was changed on another device.', {
        data: { vaultKeyVersion: 9 },
      }),
    );
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(within(dialog).getByRole('alert')).toHaveTextContent(
      'Your vault key was changed on another device.',
    );
    expect(useUIStore.getState().staleVaultKeyVersion).toBe(9);
    expect(toast).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(mockScan).toHaveBeenCalledTimes(2);
    });
  });

  it('reports a reply that did not succeed in its own words', async () => {
    mockPurge.mockResolvedValue({ data: { success: false } });
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(within(dialog).getByRole('alert')).toHaveTextContent(
      'The entries could not be deleted.',
    );
    expect(toast).not.toHaveBeenCalled();
  });

  it('closes the dialog when a lost reply’s re-check finds nothing left to delete', async () => {
    // The answer never came, but the rows went: the re-check comes back clean.
    mockPurge.mockRejectedValue(new Error('Network Error'));
    renderCard();
    await check();
    mockScan.mockResolvedValue({ kind: 'scanned', scan: CLEAN });
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
    expect(screen.getByText('Every entry opens with your current key.')).toBeInTheDocument();
    expect(mockPurge).toHaveBeenCalledTimes(1);
  });

  it('shows a server failure in its own words, never the server’s', async () => {
    mockPurge.mockRejectedValue(refusal(500, 'Internal Server Error'));
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete permanently' }));
    });

    expect(within(dialog).getByRole('alert')).toHaveTextContent(
      'The entries could not be deleted.',
    );
  });

  it('refuses to delete a result judged under a key the session no longer holds', async () => {
    renderCard();
    await check();
    const dialog = await openDelete();
    fireEvent.change(within(dialog).getByLabelText('Your master password'), {
      target: { value: 'pw' },
    });
    // Another key arrives, but this click was already on its way.
    const confirm = within(dialog).getByRole('button', { name: 'Delete permanently' });
    act(() => {
      useAuthStore.setState({ vaultKey: { other: true } as unknown as CryptoKey });
    });
    await act(async () => {
      fireEvent.click(confirm);
    });

    expect(mockProve).not.toHaveBeenCalled();
    expect(mockPurge).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith({
      title: 'Check the entries again before deleting them.',
      type: 'error',
    });
  });
});
