import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Loader2, Trash2, WifiOff } from 'lucide-react';
import { formatBytes } from '@hvault/shared';
import type { DocumentUsageResponse } from '@hvault/shared';
import { getApiErrorMessage } from '../lib/utils';
import { useConnectionStatus } from '../hooks/useConnectionStatus';
import { useDocumentsConfig } from '../hooks/useDocumentsConfig';
import { useDocumentsFilterView } from '../hooks/useDocumentsFilterView';
import { useDocumentsStore } from '../stores/documentsStore';
import { useToast } from '../components/ui/Toast';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../components/ui/Dialog';
import { DOCUMENT_SEARCH_RESULTS_ID, SearchBar } from '../components/vault/SearchBar';
import { FolderRail } from '../components/folders/FolderRail';
import { RailLayout } from '../components/layout/RailLayout';
import { DocumentList } from '../components/documents/DocumentList';
import { DocumentTransfers } from '../components/documents/DocumentTransfers';
import { DocumentUploadPanel } from '../components/documents/DocumentUploadPanel';
import { StorageUnavailable } from '../components/documents/StorageUnavailable';
import type { DocumentsConfig } from '../services/api/configApi';

// ---------------------------------------------------------------------------
// Quota
// ---------------------------------------------------------------------------

interface QuotaBarProps {
  usage: DocumentUsageResponse;
  /** The document ceiling this server advertises, absent on a server that omits it. */
  maxDocuments: number | undefined;
}

/**
 * How much of the account's storage allowance is spoken for.
 *
 * The percentage is CLAMPED rather than trusted: the quota is checked when a
 * transfer opens and again on the bytes that arrive, so documents already stored
 * can legitimately put an account over a quota an operator has since lowered, and
 * a bar drawn past its own track is not how a user should find that out.
 *
 * The division's denominator comes from `DOCUMENT_STORAGE_QUOTA_MB_PER_USER`,
 * which the server's own configuration schema bounds at 1 or more, so a zero can
 * only arrive from a server that is not this one. That is a statement about the
 * server rather than about this client: `fetchUsage` does not run the response
 * through `documentUsageResponseSchema`, unlike every row read in the same store,
 * so nothing here would catch one.
 */
function QuotaBar({ usage, maxDocuments }: QuotaBarProps) {
  const percent = Math.min(100, Math.round((usage.usedBytes / usage.quotaBytes) * 100));

  return (
    <section aria-labelledby="documents-quota-heading" className="space-y-1">
      <h2
        id="documents-quota-heading"
        className="text-sm font-semibold text-[hsl(var(--foreground))]"
      >
        Storage used
      </h2>
      <div
        role="progressbar"
        aria-label="Document storage used"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        className="h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
      >
        <div className="h-full bg-[hsl(var(--primary))]" style={{ width: `${String(percent)}%` }} />
      </div>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">
        {formatBytes(usage.usedBytes)} of {formatBytes(usage.quotaBytes)} used ·{' '}
        {maxDocuments === undefined
          ? `${String(usage.documentCount)} documents`
          : `${String(usage.documentCount)} of ${String(maxDocuments)} documents`}
        . A document in the trash still occupies storage and still counts here until it is
        permanently deleted.
      </p>
    </section>
  );
}

// ---------------------------------------------------------------------------
// The page's three top-level states
// ---------------------------------------------------------------------------

function ConfigPending() {
  return (
    <div className="flex items-center justify-center py-20" role="status" aria-label="Loading">
      <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--muted-foreground))]" />
    </div>
  );
}

interface DocumentsViewProps {
  config: DocumentsConfig;
}

function DocumentsView({ config }: DocumentsViewProps) {
  const view = useDocumentsFilterView(true);
  const usage = useDocumentsStore((s) => s.usage);
  const trashCount = useDocumentsStore((s) => s.trashDocuments.length);
  const liveTransferCount = useDocumentsStore((s) => Object.keys(s.uploads).length);
  const searchQuery = useDocumentsStore((s) => s.searchQuery);
  const setSearchQuery = useDocumentsStore((s) => s.setSearchQuery);
  const fetchDocuments = useDocumentsStore((s) => s.fetchDocuments);
  const fetchTrash = useDocumentsStore((s) => s.fetchTrash);
  const fetchUsage = useDocumentsStore((s) => s.fetchUsage);
  const emptyTrash = useDocumentsStore((s) => s.emptyTrash);
  const { isOnline } = useConnectionStatus();
  const { toast } = useToast();

  const [loadError, setLoadError] = useState<string | null>(null);
  const [showEmptyTrash, setShowEmptyTrash] = useState(false);
  const [emptying, setEmptying] = useState(false);

  const inTrash = view.mode.kind === 'trash';

  const readUsage = useCallback((): void => {
    void fetchUsage().catch(() => {
      /* The quota bar is a nicety; its absence must not read as the list failing. */
    });
  }, [fetchUsage]);

  const load = useCallback((): void => {
    setLoadError(null);
    void fetchDocuments().catch((error: unknown) => {
      setLoadError(getApiErrorMessage(error, 'Your documents could not be loaded.'));
    });
    // The trash is read on mount as well as on demand, so the rail's count is
    // right from the first paint and a delete has a list to move its row into.
    void fetchTrash().catch(() => {
      /* Its own view reports its own failure; the count simply stays at zero. */
    });
    readUsage();
  }, [fetchDocuments, fetchTrash, readUsage]);

  useEffect(() => {
    load();
  }, [load]);

  // Re-read the trash whenever the reader switches INTO it, so another tab's
  // restore or purge is reconciled rather than shown from a stale local copy.
  useEffect(() => {
    if (!inTrash) return;
    void fetchTrash().catch(() => {
      /* see `load` */
    });
  }, [inTrash, fetchTrash]);

  // Re-read the allowance whenever the number of transfers in flight FALLS. A
  // transfer that has left the registry either committed its bytes or released
  // them, and both move the number this bar draws — without this the bar keeps
  // reporting the count and the bytes it was given on mount while the list beside
  // it shows a document that is not in them.
  const previousTransferCount = useRef(liveTransferCount);
  useEffect(() => {
    const fell = liveTransferCount < previousTransferCount.current;
    previousTransferCount.current = liveTransferCount;
    if (fell) readUsage();
  }, [liveTransferCount, readUsage]);

  const handleEmptyTrash = useCallback(() => {
    setEmptying(true);
    void emptyTrash()
      .then((result) => {
        toast({
          title:
            result.failedCount > 0
              ? // Deliberately says nothing about what becomes of the residue.
                // The server's walk stops once the storage engine has refused
                // several deletes in a row, so `failedCount` counts only what it
                // ATTEMPTED: on that path a whole trash can still be there behind
                // five reported failures. The old wording promised those would
                // "be cleaned up automatically", which is true of the rows the
                // server marked and false of every row it never reached — the
                // collector only ever looks at `purgePending`. So this points at
                // the one thing that is authoritative and has just been re-read.
                `${String(result.deletedCount)} deleted. ${String(result.failedCount)} could not be removed — the trash has been refreshed to show what is still there.`
              : `${String(result.deletedCount)} document(s) permanently deleted`,
          type: result.failedCount > 0 ? 'warning' : 'success',
        });
        // The quota bar's own sentence says a trashed document still counts, so
        // leaving it stale here would contradict the text beside it.
        readUsage();
      })
      .catch((error: unknown) => {
        toast({
          title: getApiErrorMessage(error, 'The trash could not be emptied'),
          type: 'error',
        });
      })
      .finally(() => {
        setEmptying(false);
        setShowEmptyTrash(false);
      });
  }, [emptyTrash, readUsage, toast]);

  return (
    <>
      <RailLayout
        rail={(close) => <FolderRail scope={view.scope} className="flex-1" onClose={close} />}
        toolbar={
          <>
            <SearchBar
              query={searchQuery}
              onQueryChange={setSearchQuery}
              resultCount={searchQuery.trim() === '' ? null : view.rows.length}
              placeholder="Search documents... (Ctrl+K)"
              label="Search documents"
              controlsId={DOCUMENT_SEARCH_RESULTS_ID}
              className="max-w-lg flex-1"
            />
            {/* Pinned at the top of the pane rather than under the rows: with the
                list virtualized at 800px a reader may never scroll to the bottom,
                and a destructive control they cannot find is no better than one
                that is not there. */}
            {inTrash && trashCount > 0 && (
              <button
                type="button"
                onClick={() => setShowEmptyTrash(true)}
                className="ml-auto inline-flex shrink-0 items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive))] transition-colors hover:bg-[hsl(var(--destructive)/0.1)]"
              >
                <Trash2 className="h-4 w-4" />
                Empty trash
              </button>
            )}
          </>
        }
      >
        <div className="space-y-6">
          <div className="space-y-1">
            <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">Documents</h1>
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              Any file, encrypted in your browser before a byte of it is sent. The server stores
              ciphertext and never learns a document&apos;s name, its type, its tags or its
              contents.
            </p>
          </div>

          {!isOnline && (
            <p
              data-testid="documents-offline"
              className="flex items-center gap-2 rounded-md border border-yellow-400 bg-yellow-50 p-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
            >
              <WifiOff className="h-4 w-4 shrink-0" />
              You are offline. Documents are deliberately not kept in the offline cache, so
              uploading and opening one both need a connection.
            </p>
          )}

          {usage !== null && <QuotaBar usage={usage} maxDocuments={config.maxDocuments} />}

          {/* The picker is not drawn over a view of deleted files — but the
              transfers are, always, because a transfer outlives the page that
              started it and one that vanished would read as a cancelled upload. */}
          {inTrash ? (
            <DocumentTransfers />
          ) : (
            <DocumentUploadPanel config={config} folder={view.uploadFolder} />
          )}

          {(view.degradedCount > 0 || view.invalidCount > 0) && (
            <p
              role="alert"
              data-testid="documents-degraded"
              className="flex items-start gap-2 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              {/* Counted over the list this mode reads, and it says so: in a
                  folder or favorites view those rows may not be on screen at all,
                  so claiming they are "listed below" would be wrong. */}
              <span>
                {view.degradedCount > 0 &&
                  `${String(view.degradedCount)} document(s) in ${inTrash ? 'the trash' : 'your documents'} could not be opened with this vault key, so they are shown without their details. They can still be moved, favorited and deleted. `}
                {view.invalidCount > 0 &&
                  `${String(view.invalidCount)} row(s) did not match the expected shape and were left out entirely.`}
              </span>
            </p>
          )}

          <DocumentList
            id={DOCUMENT_SEARCH_RESULTS_ID}
            documents={view.rows}
            loading={view.loading}
            error={loadError}
            onRetry={load}
            mode={view.mode}
            folderNames={view.folderNames}
            searching={searchQuery.trim() !== ''}
          />
        </div>
      </RailLayout>

      <Dialog open={showEmptyTrash} onOpenChange={setShowEmptyTrash}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Empty the document trash</DialogTitle>
            <DialogDescription>
              This permanently deletes all {trashCount} document(s) in the trash. Each stored file
              is removed from object storage and the only copy of the key that decrypts it is
              destroyed with it. Nothing can bring them back. The storage they occupy is released.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button
              type="button"
              onClick={() => setShowEmptyTrash(false)}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleEmptyTrash}
              disabled={emptying}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {emptying && <Loader2 className="h-4 w-4 animate-spin" />}
              Delete all forever
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/**
 * The Documents route.
 *
 * The feature flag is answered before anything else is rendered or requested, so
 * the page never asks a server that has no document store for a list it cannot
 * produce. `null` from the hook is "not answered yet" rather than "disabled",
 * which is why it gets its own state instead of collapsing into the unavailable
 * one: a page that showed "not available" and then replaced it with the feature
 * would be worse than one that showed a spinner for a beat.
 */
export default function DocumentsPage() {
  const config = useDocumentsConfig();

  if (config === null) return <ConfigPending />;
  if (!config.enabled) return <StorageUnavailable />;
  return <DocumentsView config={config} />;
}
