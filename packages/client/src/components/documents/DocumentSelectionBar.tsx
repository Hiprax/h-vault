import { useState } from 'react';
import { FolderOpen, Loader2, RotateCcw, Trash2 } from 'lucide-react';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import { useVaultStore } from '../../stores/vaultStore';
import type { DocumentListMode } from '../../hooks/useDocumentsFilterView';
import type { DocumentSelection } from '../../hooks/useDocumentSelection';
import {
  describeBulkOutcome,
  describeTagOutcome,
  moveRow,
  purgeRow,
  restoreRow,
  runDocumentBulk,
  tagRow,
  trashRow,
  type BulkReport,
  type DocumentBulkOutcome,
  type RowResult,
} from '../../lib/documentBulk';
import { useToast } from '../ui/Toast';
import { BulkTagPopover } from '../ui/BulkTagPopover';
import { ConfirmDialog } from '../ui/ConfirmDialog';
import { SelectionCheckbox } from '../ui/SelectionCheckbox';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/DropdownMenu';

/** The folder choice a document already has when it is in none. */
const NO_FOLDER_LABEL = 'No folder';

const outlineButton =
  'inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50';

const destructiveButton =
  'inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-1.5 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50';

/**
 * Whether a bulk action is running. Owned by the PAGE rather than the bar: the
 * bar unmounts whenever no selected row is visible (Clear, a search, a re-read),
 * and a bar mounted again mid-run must still know, or it could start a second,
 * overlapping run.
 */
export interface BulkRunGuard {
  readonly busy: boolean;
  /** Claims the run synchronously; `false` when one is already running. */
  start: () => boolean;
  finish: () => void;
}

interface DocumentSelectionBarProps {
  readonly mode: DocumentListMode;
  readonly selection: DocumentSelection;
  readonly run: BulkRunGuard;
  /** A permanent delete released storage, so the allowance bar should be re-read. */
  readonly onStorageReleased: () => void;
}

/**
 * What can be done to the selected documents, above the list they were picked
 * from: Delete, Move and Tag, as on the vault list; in the trash, Restore and
 * Delete forever.
 *
 * Every action is one request per document, paced (`lib/documentBulk.ts`), and
 * reports exactly what happened: the rows that changed, or were already as asked,
 * leave the selection; the ones that did not stay selected for another try, and
 * the toast counts them all and says why.
 */
export function DocumentSelectionBar({
  mode,
  selection,
  run,
  onStorageReleased,
}: DocumentSelectionBarProps) {
  const folders = useVaultStore((s) => s.folders);
  const { toast } = useToast();
  // Which confirmation is open, and for how many documents: captured when it
  // opens, so the sentence does not count down while the rows are being removed.
  const [confirming, setConfirming] = useState<{ kind: 'trash' | 'purge'; count: number } | null>(
    null,
  );

  const inTrash = mode.kind === 'trash';
  const count = selection.rows.length;
  const confirmCount = confirming?.count ?? count;
  const confirmWord = confirmCount === 1 ? 'document' : 'documents';
  const one = confirmCount === 1;

  async function execute(
    perRow: (id: string) => Promise<RowResult>,
    describe: (outcome: DocumentBulkOutcome) => BulkReport,
  ): Promise<DocumentBulkOutcome | null> {
    if (!run.start()) return null;
    try {
      const ids = selection.rows.map((row) => row.id);
      const outcome = await runDocumentBulk(ids, perRow);
      selection.remove([...outcome.done, ...outcome.unchanged]);
      const report = describe(outcome);
      toast({
        title: report.title,
        type: report.type,
        ...(report.description === undefined ? {} : { description: report.description }),
        ...(report.duration === undefined ? {} : { duration: report.duration }),
      });
      return outcome;
    } finally {
      run.finish();
    }
  }

  // A press refused because a run is already going (`execute` answers `null`)
  // leaves the dialog alone: it belongs to that run, which closes it.
  const confirmTrash = (): void => {
    void execute(trashRow, (outcome) => describeBulkOutcome(outcome, 'moved to the trash')).then(
      (outcome) => {
        if (outcome !== null) setConfirming(null);
      },
    );
  };

  const confirmPurge = (): void => {
    void execute(purgeRow, (outcome) => describeBulkOutcome(outcome, 'permanently deleted')).then(
      (outcome) => {
        if (outcome === null) return;
        if (outcome.done.length > 0) onStorageReleased();
        setConfirming(null);
      },
    );
  };

  const restore = (): void => {
    void execute(restoreRow, (outcome) => describeBulkOutcome(outcome, 'restored'));
  };

  const move = (folderId: string | null, folderName: string): void => {
    void execute(moveRow(folderId), (outcome) =>
      folderId === null
        ? describeBulkOutcome(outcome, 'moved out of any folder', {
            some: 'had no folder',
            all: 'Every selected document is already outside any folder',
          })
        : describeBulkOutcome(outcome, `moved to ${folderName}`, {
            some: `in ${folderName}`,
            all: `Every selected document is already in ${folderName}`,
          }),
    );
  };

  const applyTag = async (tag: string): Promise<boolean> => {
    const outcome = await execute(tagRow(tag), (result) => describeTagOutcome(result, tag));
    return outcome !== null && outcome.failed.length === 0 && outcome.notSent.length === 0;
  };

  // `Dialog` asks only to CLOSE (Escape, the overlay, Cancel); it never opens itself.
  const closeConfirmation = (): void => {
    setConfirming(null);
  };

  return (
    <div
      data-testid="documents-selection-bar"
      className="flex flex-wrap items-center gap-3 rounded-lg border border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.05)] p-3"
    >
      <SelectionCheckbox
        tone="all"
        checked={selection.allSelected}
        onChange={selection.allSelected ? selection.clear : selection.selectAll}
        label={selection.allSelected ? 'Deselect all' : 'Select all'}
      />
      <span className="text-sm font-medium text-[hsl(var(--foreground))]">{count} selected</span>
      <button
        type="button"
        onClick={selection.clear}
        className="text-sm text-[hsl(var(--primary))] hover:underline"
      >
        Clear
      </button>

      <div className="ml-auto flex flex-wrap items-center gap-2">
        {run.busy && (
          <Loader2 className="h-4 w-4 animate-spin text-[hsl(var(--muted-foreground))]" />
        )}
        {inTrash ? (
          <>
            <button type="button" disabled={run.busy} onClick={restore} className={outlineButton}>
              <RotateCcw className="h-4 w-4" />
              Restore
            </button>
            <button
              type="button"
              disabled={run.busy}
              onClick={() => setConfirming({ kind: 'purge', count })}
              className={destructiveButton}
            >
              <Trash2 className="h-4 w-4" />
              Delete forever
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              disabled={run.busy}
              onClick={() => setConfirming({ kind: 'trash', count })}
              className={destructiveButton}
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
            {/* The shared menu, as on a document's own page: it implements the
                interaction `role="menu"` promises (focus moves in, arrows rove,
                Escape returns focus to the trigger). */}
            <DropdownMenu>
              <DropdownMenuTrigger disabled={run.busy} className={outlineButton}>
                <FolderOpen className="h-4 w-4" />
                Move
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" aria-label="Move to folder" className="w-48">
                {[{ id: null, name: NO_FOLDER_LABEL }, ...folders].map((folder) => (
                  <DropdownMenuItem
                    key={folder.id ?? 'none'}
                    onClick={() => move(folder.id, folder.name)}
                  >
                    {folder.name}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <BulkTagPopover disabled={run.busy} onApply={applyTag} />
          </>
        )}
      </div>

      <ConfirmDialog
        open={confirming?.kind === 'trash'}
        onOpenChange={closeConfirmation}
        holdWhileBusy
        title={`Move ${String(confirmCount)} ${confirmWord} to the trash`}
        description={`${one ? 'It stays' : 'They stay'} in the trash for ${String(TRASH_AUTO_PURGE_DAYS)} days and can be restored until then. Until ${one ? 'it is' : 'they are'} permanently deleted, ${one ? 'it still occupies' : 'they still occupy'} storage and still ${one ? 'counts' : 'count'} against your allowance.`}
        confirmLabel="Move to trash"
        onConfirm={confirmTrash}
        busy={run.busy}
      />
      <ConfirmDialog
        open={confirming?.kind === 'purge'}
        onOpenChange={closeConfirmation}
        holdWhileBusy
        title={`Delete ${String(confirmCount)} ${confirmWord} for good`}
        description={`Each stored file is removed from object storage and the only copy of the key that decrypts it is destroyed with it. Nothing can bring ${one ? 'it' : 'them'} back. The storage ${one ? 'it occupies' : 'they occupy'} is released.`}
        confirmLabel="Delete forever"
        onConfirm={confirmPurge}
        busy={run.busy}
      />
    </div>
  );
}
