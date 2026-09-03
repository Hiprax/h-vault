import { useState } from 'react';
import { AlertTriangle, Loader2, RefreshCw, Upload, X } from 'lucide-react';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  documentChunkCountFor,
  documentExtension,
  formatBytes,
} from '@hvault/shared';
import { cn, getApiErrorMessage } from '../../lib/utils';
import {
  DocumentTransformControls,
  TransformFailurePanel,
  TransformReviewPanel,
  TransformRunning,
  transformAvailability,
} from './DocumentTransformControls';
import {
  transformDocument,
  type TransformFailure,
  type TransformReview,
} from '../../services/documents/transform';
import { useUserSettings } from '../../hooks/useUserSettings';
import { useToast } from '../ui/Toast';
import {
  UploadCancelledError,
  isLiveTransfer,
  useDocumentsStore,
  type DocumentUploadProgress,
} from '../../stores/documentsStore';
import type { DocumentsConfig } from '../../services/api/configApi';

const BYTES_PER_MB = 1024 * 1024;
const SECONDS_PER_MINUTE = 60;

/**
 * The throughput the transfer estimate assumes, in bytes per second.
 *
 * A quarter of a mebibyte per second, roughly a two-megabit uplink — deliberately
 * pessimistic rather than typical, because the two ways of being wrong do not
 * cost the same. Assuming a fast connection means the warning never appears for
 * the user who most needs it, whose upload is then cancelled part-way by a lock;
 * assuming a slow one costs a sentence that a user on fibre can ignore. It is not
 * a promise about how long an upload will take, nothing is timed against it, and
 * its only job is to decide whether to raise the warning below. The
 * unconditional note beside it, which does not depend on this number at all, is
 * what carries the actual guarantee.
 */
const ESTIMATED_UPLOAD_BYTES_PER_SECOND = 256 * 1024;

/** `count` minutes, pluralised, so a one-minute setting does not read as "1 minutes". */
function minutesPhrase(count: number): string {
  return count === 1 ? '1 minute' : `${String(count)} minutes`;
}

/** Round `seconds` up into a phrase, never claiming a precision the estimate lacks. */
function describeDuration(seconds: number): string {
  return `about ${minutesPhrase(Math.ceil(seconds / SECONDS_PER_MINUTE))}`;
}

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
  onRetry: (id: string) => void;
}

function UploadRow({ upload, onCancel, onRetry }: UploadRowProps) {
  // A zero-byte document has nothing to send, so it is complete the moment it
  // starts; dividing by its size would report NaN and render an empty bar.
  const percent =
    upload.totalBytes === 0 ? 100 : Math.round((upload.sentBytes / upload.totalBytes) * 100);
  const failed = upload.status === 'failed';

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
          <button
            type="button"
            onClick={() => onRetry(upload.id)}
            className="inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-xs font-medium text-[hsl(var(--primary))] hover:bg-[hsl(var(--accent))]"
          >
            <RefreshCw className="h-3 w-3" />
            Retry
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
// The panel
// ---------------------------------------------------------------------------

/**
 * The one way a transfer's failure reaches the user, whichever call raised it.
 *
 * A cancellation is never reported: `clearStore()` aborts every transfer on a
 * lock and on a logout, so treating that as a failure would put an error in front
 * of a user who has just locked their vault on purpose.
 *
 * Everything else IS reported, even when the transfer's own row is already
 * showing the same message. That redundancy is deliberate and it replaced a
 * cleverer rule that tried to report each failure exactly once by watching
 * whether a new row had appeared. The rejection carries no upload id, so that
 * rule could only INFER which transfer it belonged to — and with two transfers
 * overlapping it inferred wrongly: a second upload refused at initiation, while
 * the first was still registering, saw the first one's brand-new row, concluded
 * it was already on screen, and said nothing at all. A duplicated message is a
 * small annoyance; a refused upload that vanishes without a word is the failure
 * this whole panel exists to prevent.
 */
function reportFailure(
  fallback: string,
  toast: ReturnType<typeof useToast>['toast'],
): (error: unknown) => void {
  return (error: unknown) => {
    if (error instanceof UploadCancelledError) return;
    toast({ title: getApiErrorMessage(error, fallback), type: 'error' });
  };
}

/**
 * Where the optional transforms have got to for the currently selected file.
 *
 * A state machine rather than three booleans, because the states are mutually
 * exclusive and the one that matters most is the one that must never be
 * skipped: while a review is open the Upload button is GONE, and the only ways
 * forward are the two the review offers.
 */
type TransformPhase =
  | { status: 'idle' }
  | { status: 'running' }
  | { status: 'ready'; review: TransformReview }
  | { status: 'failed'; failure: TransformFailure };

interface DocumentUploadPanelProps {
  /** The server's advertisement, already known to carry `enabled: true`. */
  config: DocumentsConfig;
}

/**
 * Pick or drop a file, check it here, and send it.
 *
 * ## Two guardrails, both applied before a byte is read
 *
 * The size check and the file-type check both run on the `File` handle alone —
 * on its `size` and its `name` — so a refusal costs nothing and, in particular,
 * nothing is read, hashed or encrypted. They are not the same KIND of rule
 * though, and the copy says which is which rather than flattening them: the
 * server enforces the size cap itself, on the size a transfer declares AND on
 * the bytes that actually arrive, so the check here only saves a wasted
 * transfer; the file-type list can only ever be applied here, because the server
 * receives ciphertext and never learns a filename.
 *
 * ## Auto-lock is not modified, and the panel says so
 *
 * An in-flight upload does not extend the auto-lock deadline: auto-lock exists to
 * protect an unattended unlocked vault, and a long background transfer is exactly
 * when an attacker benefits from it not firing. So a lock DURING a transfer
 * cancels it, and that is stated unconditionally before the user starts — ahead
 * of the estimate, which can be wrong, rather than inside it.
 */
export function DocumentUploadPanel({ config }: DocumentUploadPanelProps) {
  const startUpload = useDocumentsStore((s) => s.startUpload);
  const cancelUpload = useDocumentsStore((s) => s.cancelUpload);
  const retryUpload = useDocumentsStore((s) => s.retryUpload);
  const uploads = useDocumentsStore((s) => s.uploads);
  const { toast } = useToast();
  const { autoLockTimeout, lockOnHidden, lockOnHiddenDelay } = useUserSettings();

  const [file, setFile] = useState<File | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  // The two optional transforms, and whatever the last run of them produced.
  // Both are reset by `select`, because a new file is a new question: a `.png`
  // picked after a `.json` must not inherit a ticked Format box, and a review of
  // the file before it must never be confirmable against the file after it.
  const [transforms, setTransforms] = useState({ format: false, repair: false });
  const [phase, setPhase] = useState<TransformPhase>({ status: 'idle' });
  // Bumped to remount the file input, which is how a file input is cleared: a
  // `value` prop is illegal on one, and without the reset, re-picking the SAME
  // file after an upload fires no `change` event at all because the control's
  // value has not moved. Remounting rather than writing `''` through a ref keeps
  // the component free of a ref whose null case cannot happen while it renders.
  const [pickerGeneration, setPickerGeneration] = useState(0);

  const maxSizeBytes = config.maxSizeMB === undefined ? null : config.maxSizeMB * BYTES_PER_MB;
  const allowedExtensions = config.allowedExtensions ?? [];

  const transfers = Object.values(uploads);
  // The store's own definition of "still moving bytes", shared with the unload
  // guard so the note below and the confirmation dialog cannot disagree. The
  // confirmation ITSELF lives in `useUploadUnloadGuard`, mounted in `App`: a
  // transfer outlives this panel, so a guard armed here would be disarmed by
  // exactly the navigation the store is module-level to permit.
  const anyLive = transfers.some(isLiveTransfer);

  /**
   * Why this file cannot be uploaded, or `null` when it can.
   *
   * Reads only the handle's metadata. Returning the reason rather than a boolean
   * is what lets the message name the limit that was hit, which is the difference
   * between a refusal a user can act on and one they can only be annoyed by.
   */
  function refusalFor(candidate: File): string | null {
    if (maxSizeBytes !== null && candidate.size > maxSizeBytes) {
      return `That file is ${formatBytes(candidate.size)}. This server accepts documents up to ${formatBytes(maxSizeBytes)}.`;
    }
    if (
      allowedExtensions.length > 0 &&
      !allowedExtensions.includes(documentExtension(candidate.name))
    ) {
      return `This server asks for these file types only: ${allowedExtensions.join(', ')}.`;
    }
    return null;
  }

  function select(candidate: File | null): void {
    setFile(candidate);
    setRefusal(candidate === null ? null : refusalFor(candidate));
    setTransforms({ format: false, repair: false });
    setPhase({ status: 'idle' });
  }

  function clearSelection(): void {
    setFile(null);
    setRefusal(null);
    setTransforms({ format: false, repair: false });
    setPhase({ status: 'idle' });
    setPickerGeneration((generation) => generation + 1);
  }

  /**
   * Send the selected file.
   *
   * Takes the file as an ARGUMENT rather than reading the state it was called
   * beside, because the button that calls it renders only inside
   * `file !== null && refusal === null` — so the narrowing is already done at the
   * call site, and a defensive re-check here would be a branch nothing could ever
   * take.
   */
  /**
   * Send bytes, under the picked file's NAME.
   *
   * `source` and `name` are separate arguments to the store for exactly this
   * reason: a transformed upload is a `Blob` held in memory, and the store
   * deliberately never reads `File.name`, so a rewritten document cannot end up
   * named after the file it no longer is. The MIME type comes from the picked
   * file either way — a formatter changes a document's bytes, never its type.
   */
  function send(picked: File, source: Blob, transform?: TransformReview['transform']): void {
    clearSelection();
    void startUpload({
      source,
      name: picked.name,
      mime: picked.type,
      ...(transform === undefined ? {} : { transform }),
    }).catch(reportFailure('The upload could not be started.', toast));
  }

  /**
   * The Upload button.
   *
   * With no transform ticked this is the whole of it: the file goes as it is.
   * With one ticked it does NOT upload — it runs the transform and shows the
   * result, and the upload waits for a confirmation that names what changed.
   * That ordering is the guarantee: nothing this panel rewrites is ever sent
   * without the user having seen the difference.
   */
  function handleUpload(picked: File): void {
    if (!transforms.format && !transforms.repair) {
      send(picked, picked);
      return;
    }
    setPhase({ status: 'running' });
    void transformDocument(picked, {
      ext: documentExtension(picked.name),
      format: transforms.format,
      repair: transforms.repair,
    }).then(
      (attempt) => {
        setPhase(
          attempt.status === 'ready'
            ? { status: 'ready', review: attempt.review }
            : { status: 'failed', failure: attempt.failure },
        );
      },
      // `transformDocument` resolves on every failure it can name; a rejection
      // here is something it could not — the file could not be read at all.
      // Refusing to upload silently would be the one unacceptable outcome, so
      // this lands in the same panel as every other failure.
      () => {
        setPhase({
          status: 'failed',
          failure: {
            message: 'This file could not be read, so it was not changed or uploaded.',
            line: null,
            column: null,
            excerpt: '',
          },
        });
      },
    );
  }

  function handleRetry(id: string): void {
    void retryUpload(id).catch(reportFailure('The upload could not be resumed.', toast));
  }

  // WHICH deadline the transfer is racing, not just how long it is. `useAutoLock`
  // locks at `min(lastActivity + autoLockTimeout, hiddenSince + lockOnHiddenDelay)`,
  // and at the moment of the click the tab is visible, so the hidden clock has not
  // started: the soonest a lock can land is `lockOnHiddenDelay` from the instant
  // the user switches away. Taking the smaller of the two is therefore the worst
  // case rather than the expected one, which is the right bias for a warning — but
  // it is only half the answer, because the two deadlines are avoided by opposite
  // actions and named by different settings. A warning that reported a one-minute
  // hidden delay as "the vault locks after 1 minute without activity" would be
  // describing behaviour this account does not have, and would send the user to
  // the wrong setting to change it.
  //
  // The comparison is STRICT: when the two settings are equal the idle deadline
  // is the one that binds, because hiding the tab does not count as activity, so
  // `lastActivity <= hiddenSince` always holds and `lastActivity + timeout` is
  // therefore never the later of the two.
  const hiddenDeadlineBinds = lockOnHidden && lockOnHiddenDelay < autoLockTimeout;
  const idleBudgetMinutes = hiddenDeadlineBinds ? lockOnHiddenDelay : autoLockTimeout;
  const estimateSeconds = file === null ? 0 : file.size / ESTIMATED_UPLOAD_BYTES_PER_SECOND;
  // A refused file is not going to be transferred at all, so warning about how
  // long its transfer would take would be a second complaint about a file the
  // user has already been told cannot be sent.
  const transferOutlastsIdleBudget =
    refusal === null && estimateSeconds > idleBudgetMinutes * SECONDS_PER_MINUTE;

  // A transfer long enough to outrun the hidden-tab delay can also be long enough
  // to outrun the idle timeout behind it, and then BOTH deadlines will fire. The
  // remedy has to say so: telling that user to keep the tab in front and raise
  // the hidden-tab delay is advice they can follow exactly and still lose the
  // upload, which is worse than no advice.
  const bothDeadlinesOutlasted =
    hiddenDeadlineBinds && estimateSeconds > autoLockTimeout * SECONDS_PER_MINUTE;
  const lockDeadlineSentence = hiddenDeadlineBinds
    ? `the vault locks ${minutesPhrase(idleBudgetMinutes)} after you switch away from this tab`
    : `the vault locks after ${minutesPhrase(idleBudgetMinutes)} without activity`;
  const lockRemedySentence = bothDeadlinesOutlasted
    ? `Keep this tab in front and keep using the app while it runs — the idle timeout runs out in ${minutesPhrase(autoLockTimeout)} too — or raise both settings first.`
    : hiddenDeadlineBinds
      ? 'Keep this tab in front while it runs, or raise the hidden-tab delay in Settings first.'
      : 'Keep using the app while it runs, or raise the auto-lock timeout in Settings first.';

  return (
    <section aria-labelledby="documents-upload-heading" className="space-y-3">
      <h2
        id="documents-upload-heading"
        className="text-sm font-semibold text-[hsl(var(--foreground))]"
      >
        Add a document
      </h2>

      <div
        data-testid="document-dropzone"
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          select(event.dataTransfer.files[0] ?? null);
        }}
        className={cn(
          'rounded-lg border-2 border-dashed bg-[hsl(var(--background))] p-6 text-center transition-colors',
          dragging
            ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.05)]'
            : 'border-[hsl(var(--border))]',
        )}
      >
        <Upload className="mx-auto h-8 w-8 text-[hsl(var(--muted-foreground))]" />
        <p className="mt-2 text-sm text-[hsl(var(--foreground))]">
          Drop a file here, or choose one below.
        </p>
        <div className="mt-3">
          <label
            htmlFor="document-upload-input"
            className="mb-1 block text-sm font-medium text-[hsl(var(--foreground))]"
          >
            File to upload
          </label>
          <input
            id="document-upload-input"
            key={pickerGeneration}
            type="file"
            onChange={(event) => select(event.target.files?.[0] ?? null)}
            className="block w-full text-sm text-[hsl(var(--foreground))] file:mr-4 file:rounded-md file:border-0 file:bg-[hsl(var(--primary))] file:px-4 file:py-2 file:text-sm file:font-medium file:text-[hsl(var(--primary-foreground))]"
          />
        </div>
      </div>

      <p
        data-testid="upload-guardrail-note"
        className="text-xs text-[hsl(var(--muted-foreground))]"
      >
        {maxSizeBytes === null
          ? 'Every file is encrypted in your browser before any of it is sent.'
          : `Up to ${formatBytes(maxSizeBytes)} per document, checked here before the file is read. Every file is encrypted in your browser before any of it is sent.`}
        {allowedExtensions.length > 0 &&
          ` This server asks for ${allowedExtensions.join(', ')} only — a request your browser applies on its own, because the server receives ciphertext and never learns a file's name.`}
      </p>

      {refusal !== null && (
        <p
          role="alert"
          data-testid="upload-refusal"
          className="text-xs text-red-700 dark:text-red-300"
        >
          {refusal}
        </p>
      )}

      {file !== null && refusal === null && (
        <>
          <div className="flex items-center justify-between gap-3 rounded-md border border-[hsl(var(--border))] px-3 py-2">
            <span className="min-w-0 truncate text-sm text-[hsl(var(--foreground))]">
              {file.name} ({formatBytes(file.size)})
            </span>
            <div className="flex shrink-0 items-center gap-2">
              <button
                type="button"
                onClick={clearSelection}
                aria-label="Clear selected file"
                className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--destructive))]"
              >
                <X className="h-4 w-4" />
              </button>
              {/*
                The Upload button is ABSENT while a transform is running or its
                result is unconfirmed, rather than merely disabled. A disabled
                button beside an open review reads as "something else is wrong";
                its absence reads as "answer this first", which is what the
                review is for.
              */}
              {phase.status === 'idle' && (
                <button
                  type="button"
                  onClick={() => {
                    handleUpload(file);
                  }}
                  className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90"
                >
                  <Upload className="h-4 w-4" />
                  {transforms.format || transforms.repair ? 'Prepare and review' : 'Upload'}
                </button>
              )}
            </div>
          </div>

          <DocumentTransformControls
            availability={transformAvailability(file.name, file.size)}
            format={transforms.format}
            repair={transforms.repair}
            onChange={setTransforms}
            locked={phase.status !== 'idle'}
          />

          {phase.status === 'running' && <TransformRunning />}

          {phase.status === 'ready' && (
            <TransformReviewPanel
              review={phase.review}
              onConfirm={() => {
                send(file, phase.review.blob, phase.review.transform);
              }}
              onUploadOriginal={() => {
                send(file, file);
              }}
              onCancel={() => {
                setPhase({ status: 'idle' });
              }}
            />
          )}

          {phase.status === 'failed' && (
            <TransformFailurePanel
              failure={phase.failure}
              onUploadOriginal={() => {
                send(file, file);
              }}
              onCancel={() => {
                setPhase({ status: 'idle' });
              }}
            />
          )}
        </>
      )}

      <p
        data-testid="upload-lock-note"
        className="flex items-start gap-2 text-xs text-[hsl(var(--muted-foreground))]"
      >
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          Locking the vault cancels an upload in progress. Uploading is not activity, so the
          auto-lock countdown keeps running while a transfer is underway.
        </span>
      </p>

      {transferOutlastsIdleBudget && (
        <p
          role="alert"
          data-testid="upload-lock-warning"
          className="rounded-md border border-yellow-400 bg-yellow-50 p-2 text-xs text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
        >
          This file will take {describeDuration(estimateSeconds)} to upload on a modest connection,
          and {lockDeadlineSentence}. {lockRemedySentence}
        </p>
      )}

      {transfers.length > 0 && (
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
      )}

      {anyLive && (
        <p className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
          <Loader2 className="h-3 w-3 animate-spin" />
          Moving to another page keeps the transfer running; closing the tab does not.
        </p>
      )}
    </section>
  );
}
