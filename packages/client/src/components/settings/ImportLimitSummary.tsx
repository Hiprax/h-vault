import { X } from 'lucide-react';
import type { LimitSummary } from '../../services/import/customFieldsLimit';

interface ImportLimitSummaryProps {
  summary: LimitSummary;
  /** The custom-field limit the import applied (`CUSTOM_FIELDS_LIMIT`). */
  limit: number;
}

/** `A, B and 3 more`, from a bounded list of field names. */
function listNames({ names, more }: { names: string[]; more: number }): string {
  const shown = names.map((name) => (name === '' ? '(unnamed)' : name)).join(', ');
  return more > 0 ? `${shown} and ${String(more)} more` : shown;
}

/** `1 entry`, `2 entries`. */
function entries(count: number): string {
  return count === 1 ? '1 entry' : `${String(count)} entries`;
}

/**
 * Exactly what the custom-field limit does to an import: shown in the
 * confirmation BEFORE anything is saved, and again in the import report after.
 *
 * Names only, never a value: a hidden field's value is the one thing the import
 * refuses to write anywhere, and this text is rendered in the page. The counts
 * cover every row; the lists are bounded by the caller.
 */
function ImportLimitSummary({ summary, limit }: ImportLimitSummaryProps) {
  return (
    <div className="space-y-2 text-sm text-[hsl(var(--foreground))]">
      <p>
        {summary.rowCount > 0 &&
          `In ${entries(summary.rowCount)}, some custom fields are moved or left out. `}
        {`The limit is ${String(limit)} custom fields per entry. `}
        Text and yes/no fields beyond it are added to the entry&apos;s notes while they fit; hidden
        fields beyond it, and hidden values too long to store, are not imported, so their values are
        never written anywhere.
      </p>
      <ul className="list-disc space-y-1 pl-5">
        {summary.entries.map((entry, index) => (
          <li key={`entry-${String(index)}`}>
            <span className="font-medium">{entry.itemName || 'Unnamed item'}</span>
            {entry.movedToNotes.names.length > 0 &&
              `: moved to its notes: ${listNames(entry.movedToNotes)}`}
            {entry.hiddenDropped.names.length > 0 &&
              `; hidden, not imported: ${listNames(entry.hiddenDropped)}`}
            {entry.notWritten.names.length > 0 &&
              `; did not fit in its notes, not imported: ${listNames(entry.notWritten)}`}
          </li>
        ))}
        {summary.merged.map((merge, index) => (
          <li key={`merge-${String(index)}`}>
            <span className="font-medium">{merge.itemName || 'Unnamed item'}</span>
            {` became identical to ${merge.keptName || 'Unnamed item'} once its extra fields were cut, so it is imported once`}
            {merge.hiddenDropped.names.length > 0 &&
              `; hidden, not imported: ${listNames(merge.hiddenDropped)}`}
            {merge.notWritten.names.length > 0 && `; not imported: ${listNames(merge.notWritten)}`}
          </li>
        ))}
      </ul>
      {summary.entries.length + summary.merged.length < summary.rowCount + summary.mergedCount && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          {`And ${entries(summary.rowCount + summary.mergedCount - summary.entries.length - summary.merged.length)} more.`}
        </p>
      )}
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        An administrator can raise the limit (CUSTOM_FIELDS_LIMIT) to keep more fields.
      </p>
    </div>
  );
}

/**
 * The confirmation's list of what the limit will cut: a labelled, focusable scroll
 * region, so a long list can be read and scrolled by keyboard inside the dialog.
 */
export function ImportLimitCuts(props: ImportLimitSummaryProps) {
  return (
    <div
      role="region"
      aria-label="Custom fields this import will move or leave out"
      tabIndex={0}
      className="max-h-60 overflow-y-auto rounded-md border border-[hsl(var(--border))] p-3"
    >
      <ImportLimitSummary {...props} />
    </div>
  );
}

/**
 * The import report: the same list, kept on the Settings page after the import
 * has closed, until it is closed or the next import starts. A labelled section,
 * not a live region: the result toast has already announced it.
 */
export function ImportLimitReport({
  onClose,
  ...props
}: ImportLimitSummaryProps & { onClose: () => void }) {
  return (
    <section
      aria-labelledby="import-limit-report-title"
      className="space-y-2 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-700 dark:bg-amber-900/20"
    >
      <div className="flex items-start justify-between gap-2">
        <h3
          id="import-limit-report-title"
          className="text-sm font-medium text-[hsl(var(--foreground))]"
        >
          Import report
        </h3>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))]"
          aria-label="Close import report"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
      <ImportLimitSummary {...props} />
    </section>
  );
}
