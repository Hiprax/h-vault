import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Loader2, WifiOff } from 'lucide-react';
import { formatBytes } from '@hvault/shared';
import type { DocumentUsageResponse } from '@hvault/shared';
import { getApiErrorMessage } from '../lib/utils';
import { useConnectionStatus } from '../hooks/useConnectionStatus';
import { useDocumentsConfig } from '../hooks/useDocumentsConfig';
import { useDocumentsStore } from '../stores/documentsStore';
import { DocumentList } from '../components/documents/DocumentList';
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
  const documents = useDocumentsStore((s) => s.documents);
  const documentsLoading = useDocumentsStore((s) => s.documentsLoading);
  const degradedCount = useDocumentsStore((s) => s.degradedCount);
  const invalidCount = useDocumentsStore((s) => s.invalidCount);
  const usage = useDocumentsStore((s) => s.usage);
  const liveTransferCount = useDocumentsStore((s) => Object.keys(s.uploads).length);
  const fetchDocuments = useDocumentsStore((s) => s.fetchDocuments);
  const fetchUsage = useDocumentsStore((s) => s.fetchUsage);
  const { isOnline } = useConnectionStatus();

  const [loadError, setLoadError] = useState<string | null>(null);

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
    readUsage();
  }, [fetchDocuments, readUsage]);

  useEffect(() => {
    load();
  }, [load]);

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

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">Documents</h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Any file, encrypted in your browser before a byte of it is sent. The server stores
          ciphertext and never learns a document&apos;s name, its type, its tags or its contents.
        </p>
      </div>

      {!isOnline && (
        <p
          data-testid="documents-offline"
          className="flex items-center gap-2 rounded-md border border-yellow-400 bg-yellow-50 p-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
        >
          <WifiOff className="h-4 w-4 shrink-0" />
          You are offline. Documents are deliberately not kept in the offline cache, so uploading
          and opening one both need a connection.
        </p>
      )}

      {usage !== null && <QuotaBar usage={usage} maxDocuments={config.maxDocuments} />}

      <DocumentUploadPanel config={config} />

      {(degradedCount > 0 || invalidCount > 0) && (
        <p
          role="alert"
          data-testid="documents-degraded"
          className="flex items-start gap-2 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            {degradedCount > 0 &&
              `${String(degradedCount)} document(s) could not be opened with this vault key, so they are listed without their details. They can still be moved, favorited and deleted. `}
            {invalidCount > 0 &&
              `${String(invalidCount)} row(s) did not match the expected shape and were left out of the list entirely.`}
          </span>
        </p>
      )}

      <DocumentList
        documents={documents}
        loading={documentsLoading}
        error={loadError}
        onRetry={load}
      />
    </div>
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
