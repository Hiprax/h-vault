import { useRef, useState } from 'react';
import { AlertTriangle, Upload, X } from 'lucide-react';
import { documentExtension, formatBytes } from '@hvault/shared';
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
import { DocumentTransfers } from './DocumentTransfers';
import { UploadCancelledError, useDocumentsStore } from '../../stores/documentsStore';
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
 * Where the optional transforms have got to, and WHICH FILE they got there for.
 *
 * A state machine rather than three booleans, because the states are mutually
 * exclusive and the one that matters most is the one that must never be
 * skipped: while a review is open the Upload button is GONE, and the only ways
 * forward are the two the review offers.
 *
 * Every state but `idle` carries the `source` file it was computed FROM, and
 * that field is half the fix for a defect this panel shipped. A transform is an
 * in-flight promise that NOTHING cancels: picking a second file while the first
 * was still being prepared left the first one's answer to land afterwards, and
 * it landed as a review of a file that was no longer selected. Confirming it
 * called the store with the CURRENT file's name and MIME type and the STALE
 * file's bytes and provenance — so the document was stored under the wrong name,
 * and the `originalSha256` sealed into its metadata described a file nobody had
 * uploaded.
 *
 * Carrying the source is what lets the confirmation take the name from the
 * review's OWN file rather than from the panel's `file` state. They are the same
 * file, and that is the point: one value instead of a pair means there is
 * nothing left for a later change to let drift apart. The other half of the fix,
 * which keeps a stale answer from being recorded at all, is the generation token
 * in {@link DocumentUploadPanel}.
 */
type TransformPhase =
  | { status: 'idle' }
  | { status: 'running'; source: File }
  | { status: 'ready'; source: File; review: TransformReview }
  | { status: 'failed'; source: File; failure: TransformFailure };

/** The one `idle` value, so every place that returns to it agrees by construction. */
const IDLE_PHASE: TransformPhase = { status: 'idle' };

interface DocumentUploadPanelProps {
  /** The server's advertisement, already known to carry `enabled: true`. */
  config: DocumentsConfig;
  /**
   * Where a new upload is filed, or `undefined` for the root.
   *
   * The NAME travels with the id, deliberately unlike `VaultItemForm`'s
   * `defaultFolderId`: that form renders a folder picker, so the id alone is
   * enough to preselect a control the reader can see. This panel has no picker,
   * so it has to SAY where the file is going or the destination is invisible.
   */
  folder?: { id: string; name: string } | undefined;
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
export function DocumentUploadPanel({ config, folder }: DocumentUploadPanelProps) {
  const startUpload = useDocumentsStore((s) => s.startUpload);
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
  const [phase, setPhase] = useState<TransformPhase>(IDLE_PHASE);
  /**
   * Which SELECTION is current, so an answer for an older one can be dropped.
   *
   * Bumped by both of the two functions that move the selection on — `select`
   * and `clearSelection` — which between them are the ONLY callers of `setFile`,
   * so there is no third way for the selection to change without this moving. A
   * ref rather than state because it is read from a promise callback that has
   * long since closed over its render: state would give that callback the value
   * it was created with, which is the stale one, and refs are never read here
   * during rendering.
   *
   * Deliberately NOT `pickerGeneration` below, though the two are bumped
   * together in `clearSelection`: that one is the file input's `key`, and
   * bumping it on every `select` would remount the control mid-selection and
   * blank the file name the browser had just put in it.
   */
  const transformGeneration = useRef(0);
  // Bumped to remount the file input, which is how a file input is cleared: a
  // `value` prop is illegal on one, and without the reset, re-picking the SAME
  // file after an upload fires no `change` event at all because the control's
  // value has not moved. Remounting rather than writing `''` through a ref keeps
  // the component free of a ref whose null case cannot happen while it renders.
  const [pickerGeneration, setPickerGeneration] = useState(0);

  const maxSizeBytes = config.maxSizeMB === undefined ? null : config.maxSizeMB * BYTES_PER_MB;
  const allowedExtensions = config.allowedExtensions ?? [];

  // The transfers themselves — their rows, their progress, their retry and their
  // cancel — live in `DocumentTransfers`, which this panel renders below and the
  // Documents page also renders on its own in trash mode. A transfer outlives
  // this panel, so the registry it reads is module-level and the confirmation
  // that guards a tab close lives in `useUploadUnloadGuard`, mounted in `App`.

  /**
   * Why `size` bytes cannot be uploaded to this server, or `null` when they can.
   *
   * Its own function because the cap has to be applied TWICE, to two different
   * things. The picked file is measured below; the bytes a transform PRODUCES
   * are measured beside the review, because THOSE are what `send` uploads.
   * Formatting a minified document routinely doubles it, so a file comfortably
   * inside the cap when it was chosen can be outside it by the time it would be
   * sent. Before this the only thing that noticed was the server, which refused
   * the request with its own size sentence — but only AFTER the user had
   * confirmed the rewrite, and `send` clears the selection before it starts, so
   * that answer arrived beside no file and no comparison, naming the limit but
   * not the size that broke it.
   *
   * One sentence, so the limit is named the same way whichever check refuses;
   * only the SUBJECT is the caller's, and it has to be, because the review shows
   * both numbers at once. Telling a reader "that file is 2 MB" directly beneath
   * a summary reading `500 B → 2 MB` would name the file they picked and quote
   * the size of the one they did not, which is the only reading of that sentence
   * they can act on wrongly.
   *
   * `maxSizeBytes` is genuinely nullable — a server need not advertise a cap at
   * all — and the null guard is FIRST for that reason: `size > null` coerces to
   * `size > 0`, which would refuse every transformed upload on such a server.
   */
  function oversizeRefusal(subject: string, size: number): string | null {
    if (maxSizeBytes === null || size <= maxSizeBytes) return null;
    return `${subject} is ${formatBytes(size)}. This server accepts documents up to ${formatBytes(maxSizeBytes)}.`;
  }

  /**
   * Why this file cannot be uploaded, or `null` when it can.
   *
   * Reads only the handle's metadata. Returning the reason rather than a boolean
   * is what lets the message name the limit that was hit, which is the difference
   * between a refusal a user can act on and one they can only be annoyed by.
   */
  function refusalFor(candidate: File): string | null {
    const oversize = oversizeRefusal('That file', candidate.size);
    if (oversize !== null) return oversize;
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
    setPhase(IDLE_PHASE);
    transformGeneration.current += 1;
  }

  function clearSelection(): void {
    setFile(null);
    setRefusal(null);
    setTransforms({ format: false, repair: false });
    setPhase(IDLE_PHASE);
    transformGeneration.current += 1;
    setPickerGeneration((generation) => generation + 1);
  }

  /**
   * Send bytes, under the picked file's NAME.
   *
   * Takes the file as an ARGUMENT rather than reading the `file` state it sits
   * beside, and both kinds of caller now depend on that. The button that sends
   * an untouched file renders only inside `file !== null && refusal === null`,
   * so its narrowing is already done at the call site and a defensive re-check
   * here would be a branch nothing could ever take. The review's two buttons
   * pass `phase.source` — the file the review was computed FROM — so the bytes
   * and the name they are stored under come from one value rather than a pair.
   *
   * `source` and `name` are separate arguments to the store for the matching
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
      // The folder the rail has open. The store and the server have always
      // accepted this; nothing was ever sending it, so every upload landed
      // outside every folder and had to be moved by hand.
      ...(folder === undefined ? {} : { folderId: folder.id }),
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
    // The selection this run belongs to, read BEFORE the promise starts and
    // compared against the live counter when it answers. Nothing cancels a
    // transform, so an answer can arrive at any time after the user has moved
    // on; this is what makes such an answer nothing at all rather than a review
    // of one file offered against another.
    const started = transformGeneration.current;
    setPhase({ status: 'running', source: picked });

    void transformDocument(picked, {
      ext: documentExtension(picked.name),
      format: transforms.format,
      repair: transforms.repair,
    }).then(
      (attempt) => {
        if (transformGeneration.current !== started) return;
        setPhase(
          attempt.status === 'ready'
            ? { status: 'ready', source: picked, review: attempt.review }
            : { status: 'failed', source: picked, failure: attempt.failure },
        );
      },
      // `transformDocument` resolves on every failure it can name; a rejection
      // here is something it could not — the file could not be read at all.
      // Refusing to upload silently would be the one unacceptable outcome, so
      // this lands in the same panel as every other failure. It is bound to its
      // selection exactly as the answer above is: "this file could not be read"
      // is a sentence about a particular file, and reported against the file
      // that replaced it, it would simply be untrue.
      () => {
        if (transformGeneration.current !== started) return;
        setPhase({
          status: 'failed',
          source: picked,
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

      {/* Said out loud, because this panel has no folder picker: without a
          sentence the destination would be invisible and a reader would have no
          way to know their upload was about to be filed somewhere. */}
      {folder !== undefined && (
        <p
          data-testid="upload-target-folder"
          className="text-xs text-[hsl(var(--muted-foreground))]"
        >
          This file will be filed in <strong>{folder.name}</strong>.
        </p>
      )}

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
              // Measured on the bytes that would be UPLOADED, not on the ones
              // that were picked. A `null` here is what offers the confirm.
              refusal={oversizeRefusal('The formatted file', phase.review.blob.size)}
              onConfirm={() => {
                send(phase.source, phase.review.blob, phase.review.transform);
              }}
              onUploadOriginal={() => {
                send(phase.source, phase.source);
              }}
              onCancel={() => {
                setPhase(IDLE_PHASE);
              }}
            />
          )}

          {phase.status === 'failed' && (
            <TransformFailurePanel
              failure={phase.failure}
              onUploadOriginal={() => {
                send(phase.source, phase.source);
              }}
              onCancel={() => {
                setPhase(IDLE_PHASE);
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

      {/* The transfers themselves are rendered by `DocumentTransfers`, which the
          Documents page ALSO renders on its own in trash mode — where this panel
          is not drawn, because uploading into a view of deleted files is
          incoherent, but a transfer already running must not become invisible
          just because someone glanced at the trash. */}
      <DocumentTransfers />
    </section>
  );
}
