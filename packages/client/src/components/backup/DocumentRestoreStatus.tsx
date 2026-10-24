import { Loader2 } from 'lucide-react';
import { formatBytes } from '@hvault/shared';
import type {
  DocumentRestoreProgress,
  DocumentRestoreReport,
} from '../../services/backup/restoreFullBackupDocuments';
import { useDocumentsStore } from '../../stores/documentsStore';
import { WaitNotice } from './WaitNotice';

/** Where the documents phase of a full restore is. */
export type DocumentRestoreState =
  | { kind: 'running'; progress: DocumentRestoreProgress | null }
  | { kind: 'done'; report: DocumentRestoreReport };

/** What the restore card says before a full restore, about the auto-lock and about leaving. */
export const FULL_RESTORE_PAUSE_STATEMENT =
  'A full backup also restores its documents. While it does, this tab will not lock by itself as long as it stays open in front of you and the restore keeps making progress; locking the vault yourself, or leaving this page, stops restoring the documents, and running the same restore again with Skip finishes it.';

/** The one sentence a finished documents phase is reported with. */
export function documentRestoreSummary(report: DocumentRestoreReport): string {
  const parts = [
    `${String(report.uploaded)} uploaded`,
    `${String(report.restoredFromTrash)} taken out of the trash`,
    `${String(report.updated)} updated`,
    `${String(report.alreadyPresent)} already here`,
  ];
  const lead =
    report.stopped === undefined
      ? `Documents restored: ${String(report.total)} in the backup.`
      : `Restoring documents stopped: ${report.stopped.message}`;
  const unrestored =
    report.notRestored.length === 0 ? '' : ` ${String(report.notRestored.length)} not restored.`;
  const unreached =
    report.notAttempted === 0
      ? ''
      : ` ${String(report.notAttempted)} not reached; run the same restore again with Skip to finish.`;
  const leftOut =
    report.leftOutOfBackup === 0
      ? ''
      : ` ${String(report.leftOutOfBackup)} document(s) could not be included when this backup was made.`;
  const missing =
    report.missingFromBackup === 0
      ? ''
      : ` ${String(report.missingFromBackup)} document(s) the account held were not in this backup.`;
  return `${lead} ${parts.join(', ')}.${unrestored}${unreached}${leftOut}${missing}`;
}

interface DocumentRestoreStatusProps {
  state: DocumentRestoreState;
  onStop: () => void;
  onDismiss: () => void;
}

/**
 * The documents phase of a full restore: its progress and Stop while it runs, and
 * what it did once it ends. Rendered outside the restore form, so the card does not
 * collapse under a running restore.
 */
export function DocumentRestoreStatus({ state, onStop, onDismiss }: DocumentRestoreStatusProps) {
  const uploadId = state.kind === 'running' ? state.progress?.uploadId : undefined;
  const transfer = useDocumentsStore((store) =>
    uploadId === undefined ? undefined : store.uploads[uploadId],
  );

  if (state.kind === 'running') {
    const { progress } = state;
    return (
      <div data-testid="document-restore-status" className="mt-4 space-y-2">
        <p className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
          <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
          {progress === null
            ? 'Getting ready to restore the documents…'
            : `Restoring document ${String(progress.index)} of ${String(progress.total)}: ${progress.name}`}
        </p>
        {transfer !== undefined && (
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            {`${formatBytes(transfer.sentBytes)} of ${formatBytes(transfer.totalBytes)} sent`}
          </p>
        )}
        {progress?.waitUntil !== undefined && (
          <WaitNotice key={progress.waitUntil} until={progress.waitUntil} />
        )}
        <button
          type="button"
          onClick={onStop}
          className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
        >
          Stop restoring documents
        </button>
      </div>
    );
  }

  const { report } = state;
  return (
    <div
      data-testid="document-restore-status"
      className="mt-4 space-y-2 text-xs text-[hsl(var(--muted-foreground))]"
    >
      <p className="text-sm text-[hsl(var(--foreground))]">{documentRestoreSummary(report)}</p>
      {report.notRestored.length > 0 && (
        <ul data-testid="document-restore-not-restored" className="space-y-1">
          {report.notRestored.map((doc, index) => (
            <li key={`${String(index)}-${doc.name}`}>
              <span className="font-medium text-[hsl(var(--foreground))]">{doc.name}</span>
              {`: ${doc.reason}`}
            </li>
          ))}
        </ul>
      )}
      {report.notes.length > 0 && (
        <ul data-testid="document-restore-notes" className="space-y-1">
          {report.notes.map((note, index) => (
            <li key={`${String(index)}-${note}`}>{note}</li>
          ))}
        </ul>
      )}
      <button
        type="button"
        onClick={onDismiss}
        className="rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
      >
        Dismiss
      </button>
    </div>
  );
}
