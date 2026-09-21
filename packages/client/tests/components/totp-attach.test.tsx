import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import type { ScannedEntry } from '../../src/services/totpImport/scanSession';

/**
 * Choosing where a scanned code goes.
 *
 * The rules here are the ones that stop this feature doing damage: it never
 * guesses which login a code belongs to, it refuses to offer an item that
 * cannot be written to safely, and replacing a code keeps the old one.
 */

const vaultState = { items: [] as unknown[] };
vi.mock('../../src/stores/vaultStore', () => ({
  useVaultStore: Object.assign(
    (selector: (state: typeof vaultState) => unknown) => selector(vaultState),
    { getState: () => vaultState },
  ),
}));

const { TotpAttachDialog } = await import('../../src/components/tools/TotpAttachDialog');

const ENTRY: ScannedEntry = {
  id: 'scan-1',
  type: 'totp',
  issuer: 'Acme',
  account: 'alice@example.com',
  algorithm: 'SHA1',
  digits: 6,
  counter: null,
  generatable: true,
  labelTruncated: false,
};

function login(overrides: Record<string, unknown> = {}) {
  return {
    id: 'item-1',
    name: 'Acme',
    itemType: 'login',
    data: { username: 'alice@example.com', password: 'p', uris: [], customFields: [] },
    ...overrides,
  };
}

beforeEach(() => {
  vaultState.items = [];
});

describe('the login picker', () => {
  it('lists logins with their username, so duplicates at one provider are distinguishable', () => {
    vaultState.items = [
      login({ id: 'a', name: 'Google', data: { username: 'one@example.com' } }),
      login({ id: 'b', name: 'Google', data: { username: 'two@example.com' } }),
    ];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);

    expect(screen.getAllByRole('option')).toHaveLength(2);
    expect(screen.getByText('one@example.com')).toBeInTheDocument();
    expect(screen.getByText('two@example.com')).toBeInTheDocument();
  });

  it('offers only logins, never another item type', () => {
    vaultState.items = [login(), login({ id: 'n', name: 'A note', itemType: 'note', data: {} })];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);
    expect(screen.getAllByRole('option')).toHaveLength(1);
  });

  it('EXCLUDES an item whose data could not be decoded, and says how many', () => {
    // Excluded rather than disabled: writing to one would re-encrypt the
    // placeholder the store kept and destroy the real ciphertext.
    vaultState.items = [login(), login({ id: 'bad', name: 'Broken', data: { _raw: 'x' } })];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);

    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(screen.getByText(/1 login is not listed because/)).toBeInTheDocument();
  });

  it('filters by name and by username', () => {
    vaultState.items = [
      login({ id: 'a', name: 'GitHub', data: { username: 'dev@example.com' } }),
      login({ id: 'b', name: 'Bank', data: { username: 'money@example.com' } }),
    ];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);

    fireEvent.change(screen.getByPlaceholderText('Search logins'), { target: { value: 'money' } });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(screen.getByText('Bank')).toBeInTheDocument();
  });

  it('says so when nothing matches', () => {
    vaultState.items = [login()];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);
    fireEvent.change(screen.getByPlaceholderText('Search logins'), { target: { value: 'zzz' } });
    expect(screen.getByText('No matching logins.')).toBeInTheDocument();
  });

  it('cannot confirm until a login has actually been chosen', () => {
    // The whole feature rests on the choice being explicit.
    vaultState.items = [login()];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);
    expect(screen.getByRole('button', { name: /add code/i })).toBeDisabled();
  });
});

describe('replacing an existing code', () => {
  it('warns, names what is already there, and defaults to keeping it', () => {
    vaultState.items = [
      login({
        data: {
          username: 'alice@example.com',
          totp: 'otpauth://totp/Old:bob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Old',
        },
      }),
    ];
    const onConfirm = vi.fn();
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={onConfirm} />);

    fireEvent.click(screen.getByRole('option'));
    expect(screen.getByText(/That login already has a code/)).toBeInTheDocument();
    // Named, so the user can tell whether they are about to replace the right one.
    expect(screen.getByText(/Old · bob@example.com/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /add code/i }));
    // A TOTP key cannot be recovered once overwritten, so the safe option is the
    // default rather than the one you have to notice.
    expect(onConfirm).toHaveBeenCalledWith(expect.objectContaining({ keepExisting: true }));
  });

  it('lets the old code be discarded deliberately', () => {
    vaultState.items = [login({ data: { username: 'a', totp: 'JBSWY3DPEHPK3PXP' } })];
    const onConfirm = vi.fn();
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={onConfirm} />);

    fireEvent.click(screen.getByRole('option'));
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /add code/i }));
    expect(onConfirm).toHaveBeenCalledWith(expect.objectContaining({ keepExisting: false }));
  });

  it('does not warn about a login that has no code yet', () => {
    vaultState.items = [login()];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);
    fireEvent.click(screen.getByRole('option'));
    expect(screen.queryByText(/already has a code/)).not.toBeInTheDocument();
  });

  it('falls back to a neutral description when the stored code cannot be read', () => {
    vaultState.items = [login({ data: { username: 'a', totp: 'not-a-valid-secret!!' } })];
    render(<TotpAttachDialog entry={ENTRY} onCancel={vi.fn()} onConfirm={vi.fn()} />);
    fireEvent.click(screen.getByRole('option'));
    expect(screen.getByText(/an existing code/)).toBeInTheDocument();
  });

  it('cancels without confirming anything', () => {
    const onCancel = vi.fn();
    const onConfirm = vi.fn();
    vaultState.items = [login()];
    render(<TotpAttachDialog entry={ENTRY} onCancel={onCancel} onConfirm={onConfirm} />);
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
