import { useCallback, useState } from 'react';
import { Loader2, RefreshCw, X } from 'lucide-react';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, documentChunkCountFor, formatBytes } from '@hvault/shared';
import { cn, getApiErrorMessage } from '../../lib/utils';
import { useToast } from '../ui/Toast';
import {
  UploadCancelledError,
  isLiveTransfer,
  useDocumentsStore,
  type DocumentUploadProgress,
} from '../../stores/documentsStore';

// ---------------------------------------------------------------------------
// One transfer in progress
// ---------------------------------------------------------------------------

/** The sentence under one transfer's bar, for each of the three states it has. */
function describeTransfer(upload: DocumentUploadProgress): string {
  if (upload.status === 'failed') {
    return `Upload failed. ${upload.error ?? 'Retry to send only the parts the server does not already hold.'}`;
  }
  if (upload.status === 'finalizing') return 'Sealing the file details and finishing…';

  // One crypto segment is one uploaded part, so the part numbers are DERIVED
  // from the byte counts the store already keeps rather than reported beside
  // them: a second field carrying the same fact is a second field that can
  // disagree with the first.
  //
  // Nothing is clamped here. `documentChunkCountFor` is already
  // `max(1, ceil(bytes / chunk))`, and that floor is part of the FRAMING rather
  // than presentation: a zero-byte document is one segment holding a tag and no
  // plaintext, which is what the container format stores and what every other
  // caller of that helper derives. Re-flooring it here would be a second copy of
  // a rule the shared helper documents as having exactly one — and a copy that
  // would go on quietly reporting "Part 1 of 1" if the real one were ever
  // removed, hiding a framing change behind a sentence that still read correctly.
  const totalParts = documentChunkCountFor(upload.totalBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES);
  const currentPart = Math.min(
    totalParts,
    Math.floor(upload.sentBytes / DOCUMENT_PLAINTEXT_CHUNK_BYTES) + 1,
  );
  return `Part ${String(currentPart)} of ${String(totalParts)} — ${formatBytes(upload.sentBytes)} of ${formatBytes(upload.totalBytes)}`;
}

interface UploadRowProps {
  upload: DocumentUploadProgress;
  onCancel: (id: string) => void;
  /** Resolves when the resume has been prepared or refused; never rejects. */
  onRetry: (id: string) => Promise<void>;
}

function UploadRow({ upload, onCancel, onRetry }: UploadRowProps) {
  // A zero-byte document has nothing to send, so it is complete the moment it
  // starts; dividing by its size would report NaN and render an empty bar.
  const percent =
    upload.totalBytes === 0 ? 100 : Math.round((upload.sentBytes / upload.totalBytes) * 100);
  const failed = upload.status === 'failed';

  /**
   * Whether this row's resume is being prepared.
   *
   * `status` cannot answer this. The store's flip to `'uploading'` happens only
   * once the staging ledger has answered, which is a full round trip, and a
   * second click inside it used to start a SECOND transfer over the same parts —
   * the defect the store now refuses outright. The refusal is the guarantee; this
   * is the affordance, so the reader is told what is happening rather than left
   * clicking a button that answers with an error toast.
   *
   * Local to the row rather than lifted into the store, because it describes this
   * button between a click and its answer and nothing else reads it.
   *
   * `retryUpload` settles only when the whole transfer does, so this outlives the
   * preparation it names — harmlessly, because every other status unmounts the
   * button. The one case where the row is `'failed'` again by the time it settles
   * is a resume that ran and then failed, and there it clears a microtask after
   * the status write rather than a render later: a zustand `set` schedules React's
   * render as a task, while the rejection travelling out of `runTransfer` to the
   * `finally` below is microtasks, so the commit already sees `false`. No
   * mounted-ref guard: a state update on an unmounted component is a no-op in
   * React 19, and one added to avoid it would be ceremony around a non-event.
   */
  const [retrying, setRetrying] = useState(false);

  const retryName = retrying
    ? `Retrying upload of ${upload.fileName}`
    : `Retry upload of ${upload.fileName}`;

  return (
    <li
      data-testid="upload-row"
      className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3"
    >
      <div className="flex items-center gap-3">
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-[hsl(var(--card-foreground))]">
          {upload.fileName}
        </span>
        {failed && (
          /* The accessible name carries the file name, like the Cancel button
             beside it: two failed transfers otherwise offer two controls called
             "Retry" and nothing distinguishes them. The visible label stays a
             prefix of it in BOTH states, so speech input still reaches the
             control by what is written on it (WCAG 2.5.3). */
          <button
            type="button"
            disabled={retrying}
            aria-label={retryName}
            onClick={() => {
              setRetrying(true);
              void onRetry(upload.id).finally(() => {
                setRetrying(false);
              });
            }}
            className="inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-xs font-medium text-[hsl(var(--primary))] hover:bg-[hsl(var(--accent))] disabled:opacity-60 disabled:hover:bg-transparent"
          >
            {retrying ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3" />
            )}
            {retrying ? 'Retrying' : 'Retry'}
          </button>
        )}
        <button
          type="button"
          onClick={() => onCancel(upload.id)}
          aria-label={`Cancel upload of ${upload.fileName}`}
          className="shrink-0 rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--destructive))]"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div
        role="progressbar"
        aria-label={`Upload progress for ${upload.fileName}`}
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
      >
        <div
          className={cn(
            'h-full transition-all',
            failed ? 'bg-red-500' : 'bg-[hsl(var(--primary))]',
          )}
          style={{ width: `${String(percent)}%` }}
        />
      </div>

      <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">{describeTransfer(upload)}</p>
    </li>
  );
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/**
 * Every transfer currently in flight, wherever the reader happens to be.
 *
 * Lifted out of the upload panel because the two have different lifetimes. The
 * panel is the place a transfer STARTS, and it has no business being drawn over
 * a view of deleted documents; a transfer, once started, lives in a module-level
 * registry precisely so it survives navigation. Rendering the progress rows only
 * inside the panel meant a live upload disappeared the moment someone opened the
 * trash and reappeared when they came back — which reads as a cancelled upload.
 *
 * It renders nothing at all when there is nothing in flight, so the page can mount
 * it unconditionally.
 */
export function DocumentTransfers() {
  const uploads = useDocumentsStore((s) => s.uploads);
  const cancelUpload = useDocumentsStore((s) => s.cancelUpload);
  const retryUpload = useDocumentsStore((s) => s.retryUpload);
  const { toast } = useToast();
  const transfers = Object.values(uploads);
  const anyLive = transfers.some(isLiveTransfer);

  // Returns a promise that always RESOLVES, so the row's pending state settles on
  // a refusal exactly as it does on a success. Reporting stays here, because the
  // row has no toast and no business deciding which failures are worth saying.
  const handleRetry = useCallback(
    (uploadId: string): Promise<void> =>
      retryUpload(uploadId).then(
        () => undefined,
        (error: unknown) => {
          // A cancellation is never reported: `clearStore()` aborts every transfer
          // on a lock and on a logout, and a user who has just locked their vault
          // on purpose does not need an error about it.
          if (error instanceof UploadCancelledError) return;
          toast({
            title: getApiErrorMessage(error, 'The upload could not be resumed.'),
            type: 'error',
          });
        },
      ),
    [retryUpload, toast],
  );

  if (transfers.length === 0) return null;

  return (
    <div className="space-y-2">
      <ul aria-label="Uploads in progress" className="space-y-2">
        {transfers.map((transfer) => (
          <UploadRow
            key={transfer.id}
            upload={transfer}
            onCancel={cancelUpload}
            onRetry={handleRetry}
          />
        ))}
      </ul>

      {anyLive && (
        <p className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
          <Loader2 className="h-3 w-3 animate-spin" />
          Moving to another page keeps the transfer running; closing the tab does not.
        </p>
      )}
    </div>
  );
}
