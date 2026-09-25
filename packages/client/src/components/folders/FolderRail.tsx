import { useCallback, useMemo, useState, useRef, useEffect } from 'react';
import {
  Folder,
  FolderPlus,
  Star,
  Trash2,
  ChevronRight,
  Inbox,
  Pencil,
  Palette,
  GripVertical,
  Loader2,
  type LucideIcon,
} from 'lucide-react';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import { cn } from '../../lib/utils';
import { sendPaced, useVaultStore, type DecryptedFolder } from '../../stores/vaultStore';
import { reorderFolderApi } from '../../services/api/vaultApi';
import { useToast } from '../ui/Toast';
import { useInlineDialog } from '../ui/Dialog';

/**
 * The navigation rail, rendered on BOTH `/vault` and `/documents`.
 *
 * ---------------------------------------------------------------------------
 * ONE RAIL, TWO SCOPES, AND THE SEAM BETWEEN THEM
 * ---------------------------------------------------------------------------
 *
 * The seam is one sentence: **the scope answers "which rows am I counting and
 * filtering"; `vaultStore` answers "what folders exist".**
 *
 * Folders are a SINGLE collection shared by vault items and documents —
 * `folderController.deleteFolder` builds one member filter and applies it to
 * both models — so a rail rendered on either route has to be able to create,
 * rename, recolour, reorder and delete the same folders. That half stays bound
 * to `vaultStore` here. Everything that differs between the two routes — the
 * counts, which filter is active, what selecting one does — arrives pre-computed
 * and pre-bound in {@link FolderScope}, so this component holds no business
 * logic and each scope hook is the only place its store is touched.
 *
 * It is ONE component rather than two on purpose. A second rail would be the
 * same buttons, the same tree, the same drag-and-drop, the same three dialogs
 * and the same context menu, written twice — and two copies of a navigation
 * surface drift into two different interaction models for one idea.
 */

/** One entry in the rail's optional secondary filter group (the vault's item types). */
export interface FolderScopeOption {
  id: string;
  label: string;
  icon: LucideIcon;
  count: number;
  selected: boolean;
  /** Bound by the scope's own hook, so the rail never learns what an `ItemType` is. */
  onSelect: () => void;
}

/** What one route's rows look like to the rail. */
export interface FolderScope {
  /** The first button's label: "All Items" / "All Documents". */
  allLabel: string;
  counts: {
    all: number;
    favorites: number;
    trash: number;
    /**
     * ACTIVE rows per folder id — trashed rows excluded.
     *
     * A badge that counted the trash would tell a reader a folder holds five
     * things and then show them three.
     */
    perFolder: ReadonlyMap<string, number>;
  };
  selectedFolder: string | null;
  showFavorites: boolean;
  showTrash: boolean;
  /**
   * Whether nothing at all is filtered.
   *
   * Supplied rather than derived, because the rail cannot compute it: the vault
   * is also "not all" when a TYPE is selected, and the documents scope has no
   * types.
   */
  showingAll: boolean;
  onSelectAll: () => void;
  onSelectFolder: (folderId: string) => void;
  onToggleFavorites: () => void;
  onToggleTrash: () => void;
  /** Absent for a scope with no secondary group. */
  options?: readonly FolderScopeOption[] | undefined;
  /** Heading above that group. Required whenever `options` is present. */
  optionsLabel?: string | undefined;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FolderTreeNode extends DecryptedFolder {
  children: FolderTreeNode[];
}

interface ContextMenuState {
  folderId: string;
  x: number;
  y: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FOLDER_COLORS = [
  '#3b82f6',
  '#ef4444',
  '#22c55e',
  '#f59e0b',
  '#8b5cf6',
  '#ec4899',
  '#06b6d4',
  '#f97316',
];

// ---------------------------------------------------------------------------
// Helper: apply a reorder
// ---------------------------------------------------------------------------

/**
 * Sends one reorder, waits for every re-sort request in it to SETTLE, re-reads
 * the folders whatever happened, and reports the outcome in one toast. The
 * requests are paced and a short 429 is waited out (`sendPaced`): a drag across a
 * long list moves every folder between the two positions, and fired all at once
 * those requests outran a rate-limiting proxy in front of the app.
 *
 * A reorder is one request per folder whose position moved, and any of them can
 * be refused on its own: the folder-write budget running out part-way through a
 * large drag, or a dropped connection. `Promise.all` would reject on the first
 * refusal while the rest were still in flight, and the order read back then
 * could still be changing; so every request is waited out first. The server's
 * order may then be HALF applied, which is why it is re-read on failure as well
 * as on success: otherwise the rail keeps showing an order the server does not
 * have.
 *
 * `sendUpdates` lists the requests rather than issuing them, so they can be paced,
 * and a request that cannot even be issued is reported like one the server
 * refused.
 */
async function applyFolderReorder(
  sendUpdates: () => readonly (() => Promise<unknown>)[],
  toast: ReturnType<typeof useToast>['toast'],
): Promise<void> {
  try {
    const results = await sendPaced(sendUpdates());
    await useVaultStore.getState().fetchFolders();
    toast(
      results.every((result) => result.status === 'fulfilled')
        ? { title: 'Folder reordered', type: 'success' }
        : { title: 'Failed to reorder', type: 'error' },
    );
  } catch {
    toast({ title: 'Failed to reorder', type: 'error' });
  }
}

// ---------------------------------------------------------------------------
// Helper: build tree
// ---------------------------------------------------------------------------

function buildTree(folders: DecryptedFolder[]): FolderTreeNode[] {
  const map = new Map<string, FolderTreeNode>();
  const roots: FolderTreeNode[] = [];

  for (const f of folders) {
    map.set(f.id, { ...f, children: [] });
  }

  for (const f of folders) {
    const node = map.get(f.id);
    if (!node) continue;
    if (f.parentId && map.has(f.parentId)) {
      map.get(f.parentId)?.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots.sort((a, b) => a.sortOrder - b.sortOrder);
}

// ---------------------------------------------------------------------------
// Folder tree item component
// ---------------------------------------------------------------------------

interface FolderTreeItemProps {
  node: FolderTreeNode;
  depth: number;
  selectedFolder: string | null;
  onSelect: (id: string) => void;
  onContextMenu: (e: React.MouseEvent, id: string) => void;
  itemCounts: ReadonlyMap<string, number>;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onDragOver: (e: React.DragEvent, id: string) => void;
  onDrop: (e: React.DragEvent, id: string) => void;
  dragOverId: string | null;
  onKeyboardReorder: (id: string, direction: 'up' | 'down') => void;
}

function FolderTreeItem({
  node,
  depth,
  selectedFolder,
  onSelect,
  onContextMenu,
  itemCounts,
  onDragStart,
  onDragOver,
  onDrop,
  dragOverId,
  onKeyboardReorder,
}: FolderTreeItemProps) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children.length > 0;
  const isActive = selectedFolder === node.id;
  const isDragOver = dragOverId === node.id;
  const count = itemCounts.get(node.id) ?? 0;

  return (
    <div>
      {/*
        THE ROW IS A CONTAINER, AND THE TWO CONTROLS ARE SIBLINGS INSIDE IT.

        The expand/collapse control used to sit INSIDE the row's own `<button>`,
        which is invalid HTML — `button` admits no interactive descendant — and is
        axe's `nested-interactive`, graded SERIOUS against WCAG 4.1.2. `button`
        carries `childrenPresentational: true`, so assistive technology is told the
        whole row is one flat control: a keyboard user could still tab to the
        chevron, and nothing described what they had landed on. React reported the
        nesting on every render of a folder that had children; the accessibility
        gate did not, and never could, because `e2e/a11y.spec.ts` creates no folder
        at all, so no folder row has ever been through axe in any state.

        Only the chevron moved out. Everything else the row does — selection, the
        context menu, drag and drop, the keyboard reorder, the grip, the icon, the
        name and the count — stays on ONE button, which is what keeps the row a
        single tab stop with the accessible name "<folder> <count>" it already had
        (a nested control's `aria-label` is suppressed during name-from-content, so
        that name is unchanged by this and every `getByRole` query still resolves
        to the same element).

        The wrapper takes the things that belong to the ROW rather than to either
        control: the depth indent, the colour bar, the selected background and the
        drop-target ring, so all four still span the chevron exactly as they did.
        `group` is here for the same reason — the grip reveals on hovering the row,
        not on hovering the button.
      */}
      <div
        data-testid="folder-row"
        data-folder-id={node.id}
        // On the ROW, not on either button: a drop is aimed at the folder, and the
        // pointer may well be over the chevron when it lands. `onDragStart` is the
        // exception and stays on the button below, so the drag SOURCE is the
        // interactive element the user grabbed rather than a plain container.
        onDragOver={(e) => onDragOver(e, node.id)}
        onDrop={(e) => onDrop(e, node.id)}
        // Both of these reach the row from EITHER control by bubbling, which is
        // what they did when the chevron was a descendant: right-clicking the
        // chevron opens the folder's menu, and Ctrl+Arrow reorders while either
        // button holds focus.
        onContextMenu={(e) => onContextMenu(e, node.id)}
        onKeyDown={(e) => {
          if ((e.ctrlKey || e.metaKey) && e.key === 'ArrowUp') {
            e.preventDefault();
            onKeyboardReorder(node.id, 'up');
          } else if ((e.ctrlKey || e.metaKey) && e.key === 'ArrowDown') {
            e.preventDefault();
            onKeyboardReorder(node.id, 'down');
          }
        }}
        className={cn(
          'group flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
          isActive
            ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
            : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          isDragOver && 'ring-2 ring-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.1)]',
        )}
        style={{
          paddingLeft: `${depth * 16 + 8}px`,
          ...(node.color ? { borderLeft: `3px solid ${node.color}` } : {}),
        }}
      >
        {/* Expand/collapse */}
        {hasChildren ? (
          <button
            type="button"
            onClick={(e) => {
              // Kept even though selection now lives on a SIBLING rather than an
              // ancestor: the row above carries `onContextMenu` and `onKeyDown`,
              // so it is a click handler away from re-coupling the two controls.
              e.stopPropagation();
              setExpanded((prev) => !prev);
            }}
            className="shrink-0 rounded p-0.5 hover:bg-[hsl(var(--muted))]"
            aria-label={expanded ? 'Collapse folder' : 'Expand folder'}
          >
            <ChevronRight className={cn('h-3 w-3 transition-transform', expanded && 'rotate-90')} />
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}

        <button
          type="button"
          onClick={() => onSelect(node.id)}
          draggable
          onDragStart={(e) => onDragStart(e, node.id)}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
          aria-current={isActive ? 'page' : undefined}
          aria-description="Use Ctrl+Up or Ctrl+Down to reorder"
        >
          {/* Drag handle */}
          <GripVertical className="h-3 w-3 shrink-0 opacity-0 group-hover:opacity-40 transition-opacity cursor-grab" />

          <Folder
            className="h-4 w-4 shrink-0"
            style={node.color ? { color: node.color } : undefined}
          />
          <span className="min-w-0 flex-1 truncate text-left">{node.name}</span>
          {count > 0 && (
            <span className="shrink-0 rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
              {count}
            </span>
          )}
        </button>
      </div>

      {hasChildren && expanded && (
        <div>
          {node.children
            .sort((a, b) => a.sortOrder - b.sortOrder)
            .map((child) => (
              <FolderTreeItem
                key={child.id}
                node={child}
                depth={depth + 1}
                selectedFolder={selectedFolder}
                onSelect={onSelect}
                onContextMenu={onContextMenu}
                itemCounts={itemCounts}
                onDragStart={onDragStart}
                onDragOver={onDragOver}
                onDrop={onDrop}
                dragOverId={dragOverId}
                onKeyboardReorder={onKeyboardReorder}
              />
            ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main sidebar component
// ---------------------------------------------------------------------------

interface FolderRailProps {
  scope: FolderScope;
  className?: string;
  /**
   * Closes the mobile drawer. The RAIL calls it after every selection, so no
   * scope hook has to know a drawer exists.
   */
  onClose?: () => void;
}

export function FolderRail({ scope, className, onClose }: FolderRailProps) {
  // Folders themselves, and only folders: what is filed IN them arrives through
  // `scope`. See the docblock at the top of this file.
  const folders = useVaultStore((s) => s.folders);
  const createFolder = useVaultStore((s) => s.createFolder);
  const updateFolder = useVaultStore((s) => s.updateFolder);
  const deleteFolder = useVaultStore((s) => s.deleteFolder);
  const { toast } = useToast();

  const { selectedFolder, showFavorites, showTrash } = scope;

  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [showNewFolderDialog, setShowNewFolderDialog] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [renamingFolder, setRenamingFolder] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [savingRename, setSavingRename] = useState(false);
  const [deletingFolderId, setDeletingFolderId] = useState<string | null>(null);
  const [deletingFolder, setDeletingFolder] = useState(false);
  const [deleteFolderAction, setDeleteFolderAction] = useState<'move' | 'delete'>('move');
  const contextMenuRef = useRef<HTMLDivElement>(null);

  const newFolderDialogRef = useRef<HTMLDivElement>(null);
  const closeNewFolderDialog = useCallback(() => {
    setShowNewFolderDialog(false);
    setNewFolderName('');
  }, []);
  useInlineDialog(newFolderDialogRef, showNewFolderDialog, closeNewFolderDialog);

  const renameDialogRef = useRef<HTMLDivElement>(null);
  const closeRenameDialog = useCallback(() => {
    setRenamingFolder(null);
    setRenameValue('');
  }, []);
  useInlineDialog(renameDialogRef, renamingFolder !== null, closeRenameDialog);

  // Where `move` actually puts this folder's contents: its own parent, or the
  // root when it has none. Read here so the dialog can name the destination.
  const deletingParentName = useMemo(() => {
    if (deletingFolderId === null) return undefined;
    const parentId = folders.find((f) => f.id === deletingFolderId)?.parentId;
    if (parentId === undefined) return undefined;
    return folders.find((f) => f.id === parentId)?.name;
  }, [deletingFolderId, folders]);

  const deleteFolderDialogRef = useRef<HTMLDivElement>(null);
  const closeDeleteFolderDialog = useCallback(() => setDeletingFolderId(null), []);
  useInlineDialog(deleteFolderDialogRef, deletingFolderId !== null, closeDeleteFolderDialog);

  // Build folder tree
  const tree = useMemo(() => buildTree(folders), [folders]);

  // Close context menu on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    }
    if (contextMenu) {
      document.addEventListener('mousedown', handleClick);
      return () => document.removeEventListener('mousedown', handleClick);
    }
    return undefined;
  }, [contextMenu]);

  // Auto-focus first menu item when context menu opens
  useEffect(() => {
    if (contextMenu && contextMenuRef.current) {
      const firstItem = contextMenuRef.current.querySelector<HTMLElement>('[role="menuitem"]');
      firstItem?.focus();
    }
  }, [contextMenu]);

  // Every selection is `scope` doing the work and the RAIL closing the drawer.
  // Keeping `onClose` here is what lets a scope hook stay a pure binding to its
  // store, with no knowledge of how the rail happens to be presented.
  const handleSelectAllItems = useCallback(() => {
    scope.onSelectAll();
    onClose?.();
  }, [scope, onClose]);

  const handleSelectFolder = useCallback(
    (id: string) => {
      scope.onSelectFolder(id);
      onClose?.();
    },
    [scope, onClose],
  );

  const handleSelectOption = useCallback(
    (option: FolderScopeOption) => {
      option.onSelect();
      onClose?.();
    },
    [onClose],
  );

  const handleToggleFavorites = useCallback(() => {
    scope.onToggleFavorites();
    onClose?.();
  }, [scope, onClose]);

  const handleToggleTrash = useCallback(() => {
    scope.onToggleTrash();
    onClose?.();
  }, [scope, onClose]);

  const handleContextMenu = useCallback((e: React.MouseEvent, folderId: string) => {
    e.preventDefault();
    setContextMenu({ folderId, x: e.clientX, y: e.clientY });
  }, []);

  const handleCreateFolder = useCallback(async () => {
    const name = newFolderName.trim();
    if (!name) return;
    if (folders.some((f) => f.name.toLowerCase() === name.toLowerCase())) {
      toast({ title: 'A folder with this name already exists', type: 'error' });
      return;
    }
    setCreatingFolder(true);
    try {
      await createFolder(name);
      setNewFolderName('');
      setShowNewFolderDialog(false);
      toast({ title: 'Folder created', type: 'success' });
    } catch {
      toast({ title: 'Failed to create folder', type: 'error' });
    } finally {
      setCreatingFolder(false);
    }
  }, [newFolderName, createFolder, folders, toast]);

  const handleRenameFolder = useCallback(async () => {
    if (!renamingFolder || !renameValue.trim()) return;
    const name = renameValue.trim();
    if (
      folders.some((f) => f.id !== renamingFolder && f.name.toLowerCase() === name.toLowerCase())
    ) {
      toast({ title: 'A folder with this name already exists', type: 'error' });
      return;
    }
    setSavingRename(true);
    try {
      await updateFolder(renamingFolder, name);
      setRenamingFolder(null);
      setRenameValue('');
      toast({ title: 'Folder renamed', type: 'success' });
    } catch {
      toast({ title: 'Failed to rename folder', type: 'error' });
    } finally {
      setSavingRename(false);
    }
  }, [renamingFolder, renameValue, updateFolder, folders, toast]);

  const handleRequestDeleteFolder = useCallback((id: string) => {
    setDeletingFolderId(id);
    setContextMenu(null);
  }, []);

  const handleConfirmDeleteFolder = useCallback(async () => {
    if (!deletingFolderId) return;
    setDeletingFolder(true);
    try {
      await deleteFolder(deletingFolderId, deleteFolderAction);
      // A view scoped to a folder that no longer exists shows nothing and
      // explains nothing, so the selection goes with it.
      if (selectedFolder === deletingFolderId) scope.onSelectAll();
      toast({ title: 'Folder deleted', type: 'success' });
    } catch {
      toast({ title: 'Failed to delete folder', type: 'error' });
    } finally {
      setDeletingFolder(false);
      setDeletingFolderId(null);
      setDeleteFolderAction('move');
    }
  }, [deletingFolderId, deleteFolderAction, deleteFolder, selectedFolder, scope, toast]);

  // Drag and drop state
  const [dragOverId, setDragOverId] = useState<string | null>(null);
  const dragSourceIdRef = useRef<string | null>(null);

  const handleDragStart = useCallback((e: React.DragEvent, id: string) => {
    dragSourceIdRef.current = id;
    e.dataTransfer.effectAllowed = 'move';
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent, id: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragSourceIdRef.current !== id) {
      setDragOverId(id);
    }
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent, targetId: string) => {
      e.preventDefault();
      setDragOverId(null);
      const sourceId = dragSourceIdRef.current;
      dragSourceIdRef.current = null;
      if (!sourceId || sourceId === targetId) return;

      const sourceFolder = folders.find((f) => f.id === sourceId);
      const targetFolder = folders.find((f) => f.id === targetId);
      if (!sourceFolder || !targetFolder) return;

      // Get sibling folders (same parent) sorted by current sortOrder
      const siblings = folders
        .filter((f) => f.parentId === sourceFolder.parentId)
        .sort((a, b) => a.sortOrder - b.sortOrder);

      // Determine drag direction to fix insertion index
      const sourceIdx = siblings.findIndex((f) => f.id === sourceId);
      const targetIdx = siblings.findIndex((f) => f.id === targetId);
      const isDraggingDown = sourceIdx < targetIdx;

      // Remove source from its current position
      const reordered = siblings.filter((f) => f.id !== sourceId);
      const newTargetIndex = reordered.findIndex((f) => f.id === targetId);
      if (newTargetIndex === -1) return;

      // Insert after target when dragging down, before target when dragging up
      const insertIndex = isDraggingDown ? newTargetIndex + 1 : newTargetIndex;
      reordered.splice(insertIndex, 0, sourceFolder);

      await applyFolderReorder(() => {
        // Update sortOrder for all folders whose position changed
        const updates: (() => Promise<unknown>)[] = [];
        for (let i = 0; i < reordered.length; i++) {
          const folder = reordered[i];
          if (folder && folder.sortOrder !== i) {
            updates.push(() => reorderFolderApi(folder.id, i));
          }
        }
        return updates;
      }, toast);
    },
    [folders, toast],
  );

  const handleDragEnd = useCallback(() => {
    setDragOverId(null);
    dragSourceIdRef.current = null;
  }, []);

  // Keyboard alternative for folder reordering (Ctrl+ArrowUp/Down)
  const handleKeyboardReorder = useCallback(
    async (folderId: string, direction: 'up' | 'down') => {
      const folder = folders.find((f) => f.id === folderId);
      if (!folder) return;

      // Get sibling folders (same parent) sorted by current sortOrder
      const siblings = folders
        .filter((f) => f.parentId === folder.parentId)
        .sort((a, b) => a.sortOrder - b.sortOrder);

      const currentIndex = siblings.findIndex((f) => f.id === folderId);
      if (currentIndex === -1) return;

      const swapIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
      if (swapIndex < 0 || swapIndex >= siblings.length) return;

      const swapFolder = siblings[swapIndex];
      if (!swapFolder) return;

      // Swap sortOrder values
      await applyFolderReorder(
        () => [
          () => reorderFolderApi(folderId, swapFolder.sortOrder),
          () => reorderFolderApi(swapFolder.id, folder.sortOrder),
        ],
        toast,
      );
    },
    [folders, toast],
  );

  const handleChangeColor = useCallback(
    async (id: string, color: string) => {
      const folder = folders.find((f) => f.id === id);
      if (!folder) return;
      try {
        await updateFolder(id, folder.name, { color });
        toast({ title: 'Color updated', type: 'success' });
      } catch {
        toast({ title: 'Failed to update color', type: 'error' });
      }
      setContextMenu(null);
    },
    [folders, updateFolder, toast],
  );

  return (
    <div className={cn('flex flex-col h-full overflow-y-auto', className)}>
      {/* All Items */}
      <div className="space-y-1 p-3">
        <button
          type="button"
          onClick={handleSelectAllItems}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            scope.showingAll
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={scope.showingAll ? 'page' : undefined}
        >
          <Inbox className="h-4 w-4" />
          <span className="flex-1 text-left">{scope.allLabel}</span>
          <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
            {scope.counts.all}
          </span>
        </button>

        {/* Favorites */}
        <button
          type="button"
          onClick={handleToggleFavorites}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            showFavorites
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={showFavorites ? 'page' : undefined}
        >
          <Star className="h-4 w-4" />
          <span className="flex-1 text-left">Favorites</span>
          {scope.counts.favorites > 0 && (
            <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
              {scope.counts.favorites}
            </span>
          )}
        </button>

        {/* Trash */}
        <button
          type="button"
          onClick={handleToggleTrash}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            showTrash
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={showTrash ? 'page' : undefined}
        >
          <Trash2 className="h-4 w-4" />
          <span className="flex-1 text-left">Trash</span>
          {scope.counts.trash > 0 && (
            <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
              {scope.counts.trash}
            </span>
          )}
        </button>
      </div>

      {/* Divider */}
      <div className="mx-3 border-t border-[hsl(var(--border))]" />

      {/* The scope's own secondary group — the vault's item types. Absent for a
          scope that has none, along with its divider, so the documents rail is
          not a vault rail with a hole in it. */}
      {scope.options !== undefined && scope.options.length > 0 && (
        <>
          <div className="space-y-1 p-3">
            <p className="px-3 text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
              {scope.optionsLabel}
            </p>
            {scope.options.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => handleSelectOption(option)}
                className={cn(
                  'flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors',
                  option.selected
                    ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
                    : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
                )}
                aria-current={option.selected ? 'page' : undefined}
              >
                <option.icon className="h-4 w-4" />
                <span className="flex-1 text-left">{option.label}</span>
                {option.count > 0 && (
                  <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
                    {option.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Divider */}
          <div className="mx-3 border-t border-[hsl(var(--border))]" />
        </>
      )}

      {/* Folders */}
      <div className="flex-1 space-y-1 p-3" onDragEnd={handleDragEnd}>
        <div className="flex items-center justify-between px-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            Folders
          </p>
          <button
            type="button"
            onClick={() => setShowNewFolderDialog(true)}
            className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
            aria-label="Create folder"
          >
            <FolderPlus className="h-4 w-4" />
          </button>
        </div>

        {tree.map((node) => (
          <FolderTreeItem
            key={node.id}
            node={node}
            depth={0}
            selectedFolder={selectedFolder}
            onSelect={handleSelectFolder}
            onContextMenu={handleContextMenu}
            itemCounts={scope.counts.perFolder}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDrop={(e, id) => void handleDrop(e, id)}
            dragOverId={dragOverId}
            onKeyboardReorder={(id, dir) => void handleKeyboardReorder(id, dir)}
          />
        ))}

        {folders.length === 0 && (
          <p className="px-3 py-2 text-xs text-[hsl(var(--muted-foreground))]">No folders yet</p>
        )}
      </div>

      {/* New folder dialog */}
      {showNewFolderDialog && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeNewFolderDialog();
          }}
        >
          <div
            ref={newFolderDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="dialog"
            aria-modal="true"
            aria-label="Create new folder"
          >
            <h2 className="mb-4 text-lg font-semibold text-[hsl(var(--card-foreground))]">
              New Folder
            </h2>
            <input
              type="text"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleCreateFolder();
                if (e.key === 'Escape') setShowNewFolderDialog(false);
              }}
              placeholder="Folder name"
              maxLength={100}
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              autoFocus
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowNewFolderDialog(false);
                  setNewFolderName('');
                }}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleCreateFolder()}
                disabled={creatingFolder || !newFolderName.trim()}
                className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {creatingFolder ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rename dialog */}
      {renamingFolder && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeRenameDialog();
          }}
        >
          <div
            ref={renameDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="dialog"
            aria-modal="true"
            aria-label="Rename folder"
          >
            <h2 className="mb-4 text-lg font-semibold text-[hsl(var(--card-foreground))]">
              Rename Folder
            </h2>
            <input
              type="text"
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleRenameFolder();
                if (e.key === 'Escape') {
                  setRenamingFolder(null);
                  setRenameValue('');
                }
              }}
              placeholder="New name"
              maxLength={100}
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              autoFocus
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setRenamingFolder(null);
                  setRenameValue('');
                }}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleRenameFolder()}
                disabled={savingRename || !renameValue.trim()}
                className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {savingRename ? 'Renaming...' : 'Rename'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete folder confirmation dialog */}
      {deletingFolderId && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeDeleteFolderDialog();
          }}
        >
          <div
            ref={deleteFolderDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="alertdialog"
            aria-modal="true"
            aria-label="Delete folder confirmation"
          >
            <h2 className="text-lg font-semibold text-[hsl(var(--destructive))]">Delete Folder</h2>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              Are you sure you want to delete the folder{' '}
              <strong>&quot;{folders.find((f) => f.id === deletingFolderId)?.name}&quot;</strong>?
            </p>
            {/* The copy names BOTH kinds, because the server does: `deleteFolder`
                builds one member filter and applies it to vault items and to
                documents alike. A dialog that said "items" let a reader delete
                documents they were never warned about — and "delete" here is a
                SOFT delete, which for a document frees no storage at all. */}
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              Vault items and documents are both filed in folders, so this choice applies to both.
              {folders.some((f) => f.parentId === deletingFolderId) &&
                ' Its sub-folders move up a level; what is filed inside them is not affected.'}
            </p>
            <fieldset className="mt-3 space-y-2">
              <legend className="text-sm font-medium text-[hsl(var(--foreground))]">
                What should happen to everything filed in this folder?
              </legend>
              <label className="flex items-start gap-2 cursor-pointer text-sm text-[hsl(var(--foreground))]">
                <input
                  type="radio"
                  name="deleteFolderAction"
                  value="move"
                  checked={deleteFolderAction === 'move'}
                  onChange={() => setDeleteFolderAction('move')}
                  className="mt-1 accent-[hsl(var(--primary))]"
                />
                <span>
                  {deletingParentName === undefined
                    ? 'Move them out of the folder'
                    : `Move them into ${deletingParentName}`}
                  {/* Named, because the server does not move them to the root: its
                      update is `folder.parentId ? $set folderId = parentId :
                      $unset folderId`, so a nested folder's contents go UP one
                      level. Copy that said "to root" was wrong for every folder
                      that has a parent. */}
                  <span className="block text-xs text-[hsl(var(--muted-foreground))]">
                    {deletingParentName === undefined
                      ? 'They stay in your vault and in your documents, filed nowhere.'
                      : `They stay in your vault and in your documents, filed one level up in ${deletingParentName}.`}
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 cursor-pointer text-sm text-[hsl(var(--destructive))]">
                <input
                  type="radio"
                  name="deleteFolderAction"
                  value="delete"
                  checked={deleteFolderAction === 'delete'}
                  onChange={() => setDeleteFolderAction('delete')}
                  className="mt-1 accent-[hsl(var(--destructive))]"
                />
                <span>
                  Move them to the trash
                  <span className="block text-xs text-[hsl(var(--muted-foreground))]">
                    Recoverable for {TRASH_AUTO_PURGE_DAYS} days. A trashed document still occupies
                    storage until it is deleted for good.
                  </span>
                </span>
              </label>
            </fieldset>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeletingFolderId(null)}
                disabled={deletingFolder}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmDeleteFolder()}
                disabled={deletingFolder}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {deletingFolder && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          className="fixed z-[60] min-w-[160px] rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 shadow-lg"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          role="menu"
          onKeyDown={(e) => {
            const items =
              contextMenuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]');
            if (!items?.length) return;
            const active = document.activeElement as HTMLElement;
            const currentIndex = Array.from(items).indexOf(active);

            if (e.key === 'ArrowDown') {
              e.preventDefault();
              const next = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
              items[next]?.focus();
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              const prev = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
              items[prev]?.focus();
            } else if (e.key === 'Escape') {
              setContextMenu(null);
            }
          }}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              const folder = folders.find((f) => f.id === contextMenu.folderId);
              if (folder) {
                setRenamingFolder(folder.id);
                setRenameValue(folder.name);
              }
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <Pencil className="h-3.5 w-3.5" />
            Rename
          </button>

          {/* Color submenu */}
          <div className="px-2 py-1.5">
            <div className="flex items-center gap-1 text-sm text-[hsl(var(--popover-foreground))]">
              <Palette className="h-3.5 w-3.5 mr-1" />
              Color
            </div>
            <div className="mt-1 flex gap-1">
              {FOLDER_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  onClick={() => void handleChangeColor(contextMenu.folderId, color)}
                  className="h-5 w-5 rounded-full border border-[hsl(var(--border))] transition-transform hover:scale-110"
                  style={{ backgroundColor: color }}
                  aria-label={`Set folder color to ${color}`}
                />
              ))}
            </div>
          </div>

          <div className="my-1 border-t border-[hsl(var(--border))]" />

          <button
            type="button"
            role="menuitem"
            onClick={() => handleRequestDeleteFolder(contextMenu.folderId)}
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </button>
        </div>
      )}
    </div>
  );
}
