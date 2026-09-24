import { memo } from 'react';
import { Link } from 'react-router';
import { List } from 'react-window';
import type { RowComponentProps } from 'react-window';
import {
  AlertTriangle,
  FileText,
  FileWarning,
  Folder,
  RefreshCw,
  Star,
  Trash2,
  Upload,
} from 'lucide-react';
import { TRASH_AUTO_PURGE_DAYS, formatBytes } from '@hvault/shared';
import { cn } from '../../lib/utils';
import { UNOPENABLE_DOCUMENT_NAME } from '../../services/documents/downloadAll';
import type { DecryptedDocument } from '../../stores/documentsStore';
import type { DocumentListMode } from '../../hooks/useDocumentsFilterView';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The rendered height of ONE {@link DocumentRow}, in pixels, which `react-window`
 * takes as a FIXED row height because it cannot measure. It is the same 78 the
 * vault list rows are, because the row is built to the same recipe:
 *
 *   border (`border`, 1px x 2)                              2
 * + vertical padding (`p-4`, 16px x 2)                      32
 * + name line (`text-sm`, line-height 1.25rem)              20
 * + column gap (`gap-1`, 0.25rem)                           4
 * + badge line (`text-xs` 1rem + `py-0.5` 2px x 2)          20
 *                                                        = 78
 *
 * The FOLDER CHIP shares the badge line deliberately — same `text-xs`, same
 * `py-0.5` — so it costs nothing here. Anything that gives this row a third line
 * has to change this number with it, or the virtualized branch clips its rows
 * while the plain branch looks fine: jsdom performs no layout, so nothing in this
 * package can catch it.
 */
const ROW_HEIGHT = 78;

/** Vertical gap between rows, matching the plain branch's `space-y-2`. */
const ROW_GAP = 8;

/**
 * Above this many rows the list virtualizes, matching the vault list.
 *
 * The two lists are read the same way and hold comparable numbers of rows, so
 * they switch at the same point; a different threshold here would be a second
 * number to justify with no second reason behind it.
 */
const VIRTUALIZATION_THRESHOLD = 50;

/** What a document with no extension is labelled, so the badge is never blank. */
const NO_EXTENSION_LABEL = 'FILE';

/** The badge and subtitle of a row whose metadata could not be opened. */
const DEGRADED_LABEL = 'Unopenable';

/** What the list is called, per mode, for anyone reading it through a screen reader. */
function listLabelFor(mode: DocumentListMode, folderNames: ReadonlyMap<string, string>): string {
  switch (mode.kind) {
    case 'favorites':
      return 'Favorite documents';
    case 'trash':
      return 'Documents in the trash';
    case 'folder':
      return `Documents in ${folderNames.get(mode.id) ?? 'this folder'}`;
    case 'all':
    default:
      return 'Documents list';
  }
}

// ---------------------------------------------------------------------------
// Row
// ---------------------------------------------------------------------------

interface DocumentRowProps {
  doc: DecryptedDocument;
  /**
   * The document's folder NAME, resolved by the caller.
   *
   * A string rather than the map, so the memo comparison below stays a scalar
   * compare across five thousand rows — and so a row never subscribes to the
   * folder list itself, which would re-render every row whenever any folder
   * changed.
   */
  folderName: string | undefined;
}

/**
 * One document, as a single link.
 *
 * A real `<Link>` rather than the vault list's `role="button"` div, and the
 * difference is a consequence rather than an inconsistency: a vault row hosts a
 * selection checkbox and changes what a click means in multi-select mode, so its
 * activator cannot be an anchor without nesting one interactive element inside
 * another. A document row has neither, so the anchor is available — and it brings
 * keyboard activation, middle-click and "open in a new tab" without a line of
 * event handling to write or to get wrong.
 *
 * THE TRASH ADDS NO CONTROLS HERE, and that is what preserves the property. A
 * trashed row links to the same detail route, which already resolves it from the
 * trash list and already offers Restore and Delete Forever behind confirmations.
 */
const DocumentRow = memo(function DocumentRow({ doc, folderName }: DocumentRowProps) {
  const { meta } = doc;
  const degraded = meta === null;
  // Derived from the DATA, never from the mode: a row carries `deletedAt` because
  // the server said so, and a presentation keyed on which list it happened to
  // arrive in would be right by coincidence.
  const deletedAt = doc.deletedAt;
  const trashed = deletedAt !== undefined;
  // The shared constant, not a second literal: a bulk export's failure summary
  // names a degraded row by the same words, and a reader has to be able to match
  // the two — it is the only name such a row has, its real one being sealed
  // inside the blob that would not open.
  const name = degraded ? UNOPENABLE_DOCUMENT_NAME : meta.name;
  const badge = degraded ? DEGRADED_LABEL : meta.ext.toUpperCase() || NO_EXTENSION_LABEL;
  const subtitle = degraded ? '' : formatBytes(meta.plaintextBytes);
  const stamp = new Date(deletedAt ?? doc.updatedAt).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  return (
    <div
      // The element whose rendered height must equal `ROW_HEIGHT`. Named so an
      // end-to-end measurement can find the CARD rather than the link inside it.
      data-testid="document-row"
      className="flex items-center gap-4 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 transition-colors hover:bg-[hsl(var(--accent))]"
    >
      <Link
        to={`/documents/${doc.id}`}
        title={name}
        className="flex min-w-0 flex-1 items-center gap-4"
      >
        <span
          className={cn(
            'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
            degraded
              ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300'
              : trashed
                ? 'bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]'
                : 'bg-sky-100 text-sky-800 dark:bg-sky-900/30 dark:text-sky-300',
          )}
        >
          {degraded ? <FileWarning className="h-5 w-5" /> : <FileText className="h-5 w-5" />}
        </span>

        <span className="flex min-w-0 flex-1 flex-col gap-1">
          <span
            data-testid="document-name"
            className="truncate text-sm font-medium text-[hsl(var(--card-foreground))]"
          >
            {name}
          </span>
          <span className="flex min-w-0 items-center gap-2">
            <span className="inline-flex shrink-0 rounded-full bg-[hsl(var(--muted))] px-2 py-0.5 text-xs font-medium text-[hsl(var(--muted-foreground))]">
              {badge}
            </span>
            {subtitle !== '' && (
              <span className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                {subtitle}
              </span>
            )}
            {/* Where the document is filed, shown wherever it resolves — including
                inside a folder view, where it is redundant but consistent, and in
                the trash, where it says where a restore will put it back. An id
                that resolves to nothing renders nothing, which is the right answer
                for a folder that has been deleted. */}
            {folderName !== undefined && (
              <span
                data-testid="document-folder"
                className="inline-flex min-w-0 shrink items-center gap-1 rounded-full bg-[hsl(var(--muted))] px-2 py-0.5 text-xs font-medium text-[hsl(var(--muted-foreground))]"
              >
                <Folder className="h-3 w-3 shrink-0" />
                <span className="truncate">{folderName}</span>
              </span>
            )}
          </span>
        </span>

        {doc.favorite && <Star className="h-4 w-4 shrink-0 fill-yellow-400 text-yellow-400" />}

        <span className="hidden shrink-0 text-xs text-[hsl(var(--muted-foreground))] sm:block">
          {/* A row already being destroyed says so rather than showing a date it
              will not outlive. `purgePending` became reachable the moment this
              list gained an Empty-trash control. */}
          {doc.purgePending === true ? 'Being deleted' : trashed ? `Deleted ${stamp}` : stamp}
        </span>
      </Link>
    </div>
  );
});

// ---------------------------------------------------------------------------
// Virtualized row wrapper
// ---------------------------------------------------------------------------

interface RowData {
  documents: DecryptedDocument[];
  folderNames: ReadonlyMap<string, string>;
}

function VirtualizedRow(props: RowComponentProps<RowData>) {
  const { index, style, ariaAttributes, documents, folderNames } = props;
  const doc = documents[index];
  if (!doc) return null;
  return (
    <div style={{ ...style, paddingBottom: ROW_GAP }} {...ariaAttributes}>
      {/* Resolved to a STRING here, so the memoised row compares a scalar. */}
      <DocumentRow
        doc={doc}
        folderName={doc.folderId === undefined ? undefined : folderNames.get(doc.folderId)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// The four states
// ---------------------------------------------------------------------------

function LoadingSkeleton() {
  return (
    <div className="space-y-2" data-testid="documents-skeleton">
      {Array.from({ length: 4 }, (_, index) => (
        <div
          key={index}
          className="flex items-center gap-4 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 animate-pulse"
        >
          <div className="h-10 w-10 rounded-lg bg-[hsl(var(--muted))]" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-1/3 rounded bg-[hsl(var(--muted))]" />
            <div className="h-3 w-1/5 rounded bg-[hsl(var(--muted))]" />
          </div>
        </div>
      ))}
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div
      role="alert"
      data-testid="documents-error"
      className="flex flex-col items-center justify-center gap-3 rounded-lg border border-red-300 bg-red-50 py-12 text-center dark:border-red-700 dark:bg-red-900/20"
    >
      <AlertTriangle className="h-8 w-8 text-red-700 dark:text-red-300" />
      <p className="max-w-sm text-sm text-red-800 dark:text-red-200">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex items-center gap-2 rounded-md border border-red-300 px-3 py-1.5 text-sm font-medium text-red-800 hover:bg-red-100 dark:border-red-700 dark:text-red-200 dark:hover:bg-red-800/30"
      >
        <RefreshCw className="h-4 w-4" />
        Try again
      </button>
    </div>
  );
}

/**
 * Nothing to show, and WHY there is nothing to show.
 *
 * One frame with a copy table rather than four components: an empty favorites
 * view that repeated "Drop a file onto the panel above" would be answering a
 * question the reader did not ask, and four separate components would be four
 * places for the frame to drift.
 */
function EmptyState({
  mode,
  folderNames,
  searching,
}: {
  mode: DocumentListMode;
  folderNames: ReadonlyMap<string, string>;
  searching: boolean;
}) {
  const copy = ((): { icon: typeof Upload; heading: string; body: string } => {
    if (searching) {
      return {
        icon: FileText,
        heading: 'No documents match',
        body: 'Nothing here matches what you typed. Search looks at a document’s name, its type, its tags and its note — all of which are decrypted in your browser.',
      };
    }
    switch (mode.kind) {
      case 'favorites':
        return {
          icon: Star,
          heading: 'No favorite documents',
          body: 'Open a document and press Favorite to keep it here.',
        };
      case 'trash':
        return {
          icon: Trash2,
          heading: 'The trash is empty',
          body: `Documents you delete appear here and are permanently removed after ${String(TRASH_AUTO_PURGE_DAYS)} days. Until then they still occupy storage and still count against your allowance.`,
        };
      case 'folder':
        return {
          icon: Folder,
          heading: `Nothing in “${folderNames.get(mode.id) ?? 'this folder'}”`,
          body: 'Move a document into this folder from its own page, or upload a file while this folder is selected.',
        };
      case 'all':
      default:
        return {
          icon: Upload,
          heading: 'No documents yet',
          body: 'Drop a file onto the panel above, or choose one. It is encrypted in your browser before any of it is sent, so the server never sees its name, its type or a byte of its contents.',
        };
    }
  })();
  const Icon = copy.icon;

  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[hsl(var(--muted))]">
        <Icon className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
      </div>
      <h2 className="mt-4 text-lg font-semibold text-[hsl(var(--foreground))]">{copy.heading}</h2>
      <p className="mt-1 max-w-sm text-sm text-[hsl(var(--muted-foreground))]">{copy.body}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

interface DocumentListProps {
  documents: DecryptedDocument[];
  loading: boolean;
  /** The message from a failed load, or `null` when the last load succeeded. */
  error: string | null;
  onRetry: () => void;
  mode: DocumentListMode;
  folderNames: ReadonlyMap<string, string>;
  /** Whether a search is narrowing the list, which changes what "empty" means. */
  searching: boolean;
  /** So the search field can name this list as the thing it controls. */
  id?: string;
}

/**
 * The document list, in its four states: loading, failed, empty and populated.
 *
 * The failed state is a state of the LIST rather than a toast, because a toast
 * that has been dismissed leaves an empty list that is indistinguishable from an
 * account with no documents — which is the one reading a user must never be given
 * when the truth is that the request failed.
 */
export function DocumentList({
  documents,
  loading,
  error,
  onRetry,
  mode,
  folderNames,
  searching,
  id,
}: DocumentListProps) {
  if (loading) return <LoadingSkeleton />;
  if (error !== null) return <ErrorState message={error} onRetry={onRetry} />;
  if (documents.length === 0) {
    return <EmptyState mode={mode} folderNames={folderNames} searching={searching} />;
  }

  const label = listLabelFor(mode, folderNames);

  if (documents.length > VIRTUALIZATION_THRESHOLD) {
    return (
      <List<RowData>
        aria-label={label}
        style={{ height: 'calc(100vh - 420px)', minHeight: 300, maxHeight: 800 }}
        rowComponent={VirtualizedRow}
        rowCount={documents.length}
        rowHeight={ROW_HEIGHT + ROW_GAP}
        rowProps={{ documents, folderNames }}
        overscanCount={5}
        role="list"
        {...(id === undefined ? {} : { id })}
      />
    );
  }

  return (
    <div className="space-y-2" role="list" aria-label={label} {...(id === undefined ? {} : { id })}>
      {documents.map((doc, index) => (
        <div key={doc.id} role="listitem" aria-setsize={documents.length} aria-posinset={index + 1}>
          <DocumentRow
            doc={doc}
            folderName={doc.folderId === undefined ? undefined : folderNames.get(doc.folderId)}
          />
        </div>
      ))}
    </div>
  );
}
