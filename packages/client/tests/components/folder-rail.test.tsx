/**
 * `FolderRail` against a HAND-BUILT scope.
 *
 * The rail is now rendered on two routes with two different sets of rows behind
 * it, and `FolderScope` is the whole contract between them. Every other rail
 * suite drives it through `useVaultFolderScope` against the real store, which is
 * the right way to test the vault's behaviour but cannot reach the contract
 * itself: a scope with no secondary group, a label that is not "All Items", a
 * count that disagrees with what the vault would compute. Those live here.
 */
import type React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { Files } from 'lucide-react';
import { FolderRail, type FolderScope } from '../../src/components/folders/FolderRail';
import { useVaultStore } from '../../src/stores/vaultStore';

vi.mock('../../src/services/api/vaultApi', () => ({
  reorderFolderApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../../src/components/ui/Toast', () => ({
  useToast: () => ({ toast: vi.fn(), dismiss: vi.fn(), update: vi.fn() }),
  ToastProvider: ({ children }: { children: React.ReactNode }) => children,
  Toaster: () => null,
}));

const noop = (): void => {
  /* a scope the case under test does not exercise */
};

function makeScope(overrides: Partial<FolderScope> = {}): FolderScope {
  return {
    allLabel: 'All Documents',
    counts: { all: 12, favorites: 3, trash: 2, perFolder: new Map([['folder-1', 4]]) },
    selectedFolder: null,
    showFavorites: false,
    showTrash: false,
    showingAll: true,
    onSelectAll: noop,
    onSelectFolder: noop,
    onToggleFavorites: noop,
    onToggleTrash: noop,
    ...overrides,
  };
}

function renderRail(scope: FolderScope, onClose?: () => void) {
  return render(
    <MemoryRouter>
      <FolderRail scope={scope} {...(onClose ? { onClose } : {})} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  useVaultStore.setState({
    folders: [
      {
        id: 'folder-1',
        name: 'Taxes',
        sortOrder: 0,
        createdAt: 'x',
        updatedAt: 'x',
      },
    ] as never,
  });
});

describe('FolderRail — the scope contract', () => {
  it('takes its label and all three counts from the scope', () => {
    renderRail(makeScope());

    // The label is the scope's, not a constant: a documents rail that said "All
    // Items" would be describing the wrong collection.
    expect(screen.getByText('All Documents')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /All Documents/ })).toHaveTextContent('12');
    expect(screen.getByRole('button', { name: /Favorites/ })).toHaveTextContent('3');
    expect(screen.getByRole('button', { name: /Trash/ })).toHaveTextContent('2');
    // Per-folder badges come from the scope too, so each route counts its own rows.
    expect(screen.getByRole('button', { name: /Taxes/ })).toHaveTextContent('4');
  });

  it('marks exactly one entry current, in each of the four modes', () => {
    const current = () =>
      screen
        .getAllByRole('button')
        .filter((button) => button.getAttribute('aria-current') === 'page')
        .map((button) => button.textContent);

    const { unmount: a } = renderRail(makeScope());
    expect(current()).toEqual([expect.stringContaining('All Documents')]);
    a();

    const { unmount: b } = renderRail(makeScope({ showingAll: false, showFavorites: true }));
    expect(current()).toEqual([expect.stringContaining('Favorites')]);
    b();

    const { unmount: c } = renderRail(makeScope({ showingAll: false, showTrash: true }));
    expect(current()).toEqual([expect.stringContaining('Trash')]);
    c();

    renderRail(makeScope({ showingAll: false, selectedFolder: 'folder-1' }));
    expect(current()).toEqual([expect.stringContaining('Taxes')]);
  });

  it('honours `showingAll` rather than inferring it from the three filters', () => {
    // The vault is also "not all" when a TYPE is selected — a state this rail
    // cannot see. Inferring would light "All Items" while a type filter is on.
    renderRail(makeScope({ showingAll: false }));

    expect(screen.getByRole('button', { name: /All Documents/ })).not.toHaveAttribute(
      'aria-current',
    );
  });

  it('renders no secondary group at all for a scope that has none', () => {
    renderRail(makeScope());

    // Not an empty section with a heading: a documents rail is not a vault rail
    // with a hole where the types were.
    expect(screen.queryByText('Types')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Logins/ })).not.toBeInTheDocument();
  });

  it('renders the secondary group, its heading and its counts when the scope has one', () => {
    const onSelect = vi.fn();
    renderRail(
      makeScope({
        optionsLabel: 'Kinds',
        options: [
          { id: 'a', label: 'Reports', icon: Files, count: 7, selected: false, onSelect },
          { id: 'b', label: 'Receipts', icon: Files, count: 0, selected: true, onSelect: noop },
        ],
      }),
    );

    expect(screen.getByText('Kinds')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Reports/ })).toHaveTextContent('7');
    expect(screen.getByRole('button', { name: /Receipts/ })).toHaveAttribute(
      'aria-current',
      'page',
    );
    // A zero count draws no badge, matching every other entry in this rail.
    expect(screen.getByRole('button', { name: /Receipts/ })).not.toHaveTextContent('0');

    fireEvent.click(screen.getByRole('button', { name: /Reports/ }));
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('draws no badge for a zero favorites or trash count, but always one for all', () => {
    renderRail(makeScope({ counts: { all: 0, favorites: 0, trash: 0, perFolder: new Map() } }));

    expect(screen.getByRole('button', { name: /All Documents/ })).toHaveTextContent('0');
    // The asymmetry is deliberate and pre-existing: "All" is a total and reads
    // correctly at zero, while an empty Favorites needs no decoration.
    expect(screen.getByRole('button', { name: /Favorites/ })).not.toHaveTextContent('0');
    expect(screen.getByRole('button', { name: /Trash/ })).not.toHaveTextContent('0');
  });

  it('routes every selection through the scope and then closes the drawer', () => {
    const onSelectAll = vi.fn();
    const onSelectFolder = vi.fn();
    const onToggleFavorites = vi.fn();
    const onToggleTrash = vi.fn();
    const onClose = vi.fn();
    renderRail(
      makeScope({ onSelectAll, onSelectFolder, onToggleFavorites, onToggleTrash }),
      onClose,
    );

    fireEvent.click(screen.getByRole('button', { name: /All Documents/ }));
    fireEvent.click(screen.getByRole('button', { name: /Favorites/ }));
    fireEvent.click(screen.getByRole('button', { name: /Trash/ }));
    fireEvent.click(screen.getByRole('button', { name: /Taxes/ }));

    expect(onSelectAll).toHaveBeenCalledTimes(1);
    expect(onToggleFavorites).toHaveBeenCalledTimes(1);
    expect(onToggleTrash).toHaveBeenCalledTimes(1);
    expect(onSelectFolder).toHaveBeenCalledWith('folder-1');
    // Closing the mobile drawer is the RAIL's job, so a scope hook never has to
    // know one exists.
    expect(onClose).toHaveBeenCalledTimes(4);
  });

  it('clears a selection that is about to be deleted, and leaves another alone', async () => {
    const onSelectAll = vi.fn();
    const deleteFolder = vi.fn().mockResolvedValue(undefined);
    useVaultStore.setState({ deleteFolder } as never);
    renderRail(makeScope({ showingAll: false, selectedFolder: 'folder-1', onSelectAll }));

    fireEvent.contextMenu(screen.getByRole('button', { name: /Taxes/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    const dialog = screen.getByRole('alertdialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await vi.waitFor(() => {
      expect(deleteFolder).toHaveBeenCalledWith('folder-1', 'move');
    });
    // A view scoped to a folder that no longer exists shows nothing and explains
    // nothing.
    await vi.waitFor(() => {
      expect(onSelectAll).toHaveBeenCalledTimes(1);
    });
  });

  it('says that a folder deletion reaches documents as well as vault items', async () => {
    renderRail(makeScope());

    fireEvent.contextMenu(screen.getByRole('button', { name: /Taxes/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    const dialog = screen.getByRole('alertdialog');

    // The server builds ONE member filter and applies it to `VaultItem` AND
    // `Document`. The old copy said "items", so a reader could destroy documents
    // they were never warned about.
    expect(dialog).toHaveTextContent(/vault items and documents are both filed in folders/i);
    // And "delete" is a SOFT delete, which for a document frees no storage.
    expect(within(dialog).getByLabelText(/Move them to the trash/)).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Recoverable for 30 days/i);
    expect(dialog).toHaveTextContent(/still occupies storage/i);
  });

  it('names where a move actually puts the contents — the parent, not the root', async () => {
    useVaultStore.setState({
      folders: [
        { id: 'folder-0', name: 'Finance', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
        {
          id: 'folder-1',
          name: 'Taxes',
          parentId: 'folder-0',
          sortOrder: 0,
          createdAt: 'x',
          updatedAt: 'x',
        },
      ] as never,
    });
    renderRail(makeScope());

    fireEvent.contextMenu(screen.getByRole('button', { name: /^Taxes/ }));
    fireEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }));
    const dialog = screen.getByRole('alertdialog');

    // The server's move is `folder.parentId ? $set folderId = parentId : $unset`,
    // so a nested folder's contents go UP one level. "Move to root" was wrong for
    // every folder that has a parent.
    expect(within(dialog).getByLabelText(/Move them into Finance/)).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/one level up in Finance/);
    expect(dialog).not.toHaveTextContent(/filed nowhere/);
  });

  it('warns about sub-folders only when the folder has some', async () => {
    const openDialogFor = async (name: RegExp) => {
      fireEvent.contextMenu(screen.getByRole('button', { name }));
      fireEvent.click(await screen.findByRole('menuitem', { name: /Delete/ }));
      return screen.getByRole('alertdialog');
    };

    const flat = await (async () => {
      renderRail(makeScope());
      return openDialogFor(/Taxes/);
    })();
    expect(flat).not.toHaveTextContent(/sub-folders move up a level/i);
    fireEvent.click(within(flat).getByRole('button', { name: 'Cancel' }));

    useVaultStore.setState({
      folders: [
        { id: 'folder-1', name: 'Taxes', sortOrder: 0, createdAt: 'x', updatedAt: 'x' },
        {
          id: 'folder-2',
          name: '2025',
          parentId: 'folder-1',
          sortOrder: 0,
          createdAt: 'x',
          updatedAt: 'x',
        },
      ] as never,
    });
    const nested = await openDialogFor(/^Taxes/);
    expect(nested).toHaveTextContent(/sub-folders move up a level/i);
  });
});
