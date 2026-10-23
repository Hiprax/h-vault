import { useCallback, useEffect, useRef, useState } from 'react';
import { Download, Loader2, Square } from 'lucide-react';
import { useBeforeUnloadWarning } from '../../hooks/useBeforeUnloadWarning';
import { ArchivePathAllocator } from '../../services/documents/archiveNames';
import { archiveFileName, openArchiveTarget } from '../../services/documents/archiveTarget';
import {
  archiveDocuments,
  type BulkDownloadCandidate,
  type DocumentArchiveResult,
  type DocumentDownloadStop,
} from '../../services/documents/downloadAll';
import { getApiErrorMessage } from '../../lib/utils';
import { useVaultStore } from '../../stores/vaultStore';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';

/**
 * The one control that takes a whole document library out of this instance, as
 * ONE ZIP archive, and the report of what happened to it.
 *
 * A document is the only thing in this vault the encrypted backup does not
 * carry, so before this existed the only way out was one download at a time. The
 * work itself is `services/documents/downloadAll.ts`; this is its surface.
 *
 * ## Five things about it are load-bearing
 *
 *   * **The save dialog opens on the click itself.** `openArchiveTarget` is
 *     called synchronously from the Start (or Continue) click, before any await,
 *     because the browser opens `showSaveFilePicker` only on a click's transient
 *     activation. The run's controller exists from that same click, so a page
 *     left while the dialog is still open aborts it, and the target it then
 *     resolves to is dropped unused.
 *   * **The live region is mounted unconditionally** and only its CONTENT
 *     changes, exactly as `AppLayout`'s offline-cache notice is: a `role="status"`
 *     region inserted already holding its message is frequently never announced.
 *   * **What it says is COARSE**: one sentence when a run starts and one when it
 *     ends. The document being read is a plain paragraph beside the bar, and the
 *     bar's `aria-valuetext` carries the count; the failure list is outside the
 *     region too, read on demand rather than announced.
 *   * **Leaving ends the run, and keeps what is verified.** Unmounting (navigating
 *     away, or a lock, which swaps this route out) aborts the run, and the
 *     service finishes and saves the archive with the documents already in it,
 *     as the separate files of the earlier design stayed saved. While a run is
 *     active, closing the tab asks first.
 *   * **A continuation is one more archive, never a reopened one.** Continue
 *     starts a new archive for the rows the last one did not settle, with the
 *     same path allocator, so every archive of one run extracts into one folder
 *     without a name colliding.
 */

interface DocumentBulkDownloadProps {
  /**
   * The rows to archive: whatever the list below is showing.
   *
   * Deliberately what is LISTED rather than "every document that exists". The
   * panel sits above a list, so a reader's expectation is set by the rows they
   * can see — and it makes the folder, favorites, trash and search filters part
   * of the export without a second control to explain.
   */
  documents: readonly BulkDownloadCandidate[];
  /**
   * Rows the current view's fetch dropped for not matching the expected shape,
   * named here because this panel is the one place that makes a claim about
   * completeness.
   */
  invalidCount: number;
  /**
   * `documents` is the rows the reader SELECTED rather than the whole list, so
   * the panel says so and its button reads "Download selected".
   */
  selected?: boolean;
}

/** Everything one run has done, across every archive its continuations added. */
interface RunSummary {
  total: number;
  savedCount: number;
  failures: DocumentArchiveResult['failures'];
  stopped: DocumentDownloadStop;
  stoppedDetail?: string;
  /** Every archive the run has saved, in order. */
  archives: NonNullable<DocumentArchiveResult['archive']>[];
  /** Whether the latest archive was saved, which decides how a further leg is offered. */
  latestSaved: boolean;
  /** The run's path allocator, which every continuation reuses. */
  allocator: ArchivePathAllocator;
}

/** Where the panel is. */
type RunState =
  | { kind: 'idle' }
  | { kind: 'running'; total: number; completed: number; current: string; finishing: boolean }
  | {
      kind: 'done';
      summary: RunSummary;
      /** What the run has not settled yet, so it can be continued. */
      remaining: readonly BulkDownloadCandidate[];
    };

/**
 * How each ending introduces itself. A lookup rather than a chain of ternaries,
 * so a new way for a run to stop is a compile error here instead of a summary
 * that silently reads as though the export had finished.
 */
const STOP_LEAD: Record<DocumentDownloadStop, string> = {
  complete: '',
  stopped: 'Stopped. ',
  'vault-locked': 'The vault locked, so the archive was finished early. ',
  'rate-limited':
    'The server limited how quickly documents could be read, so the archive was finished early. ',
  'archive-full': 'The archive reached its size limit. ',
  'save-failed': 'Your browser could not save the archive. ',
};

/**
 * How a leg that archived NOTHING introduces itself. The usual lead would say an
 * archive was finished early, which reads as false when this leg's archive was
 * never begun; "nothing more" stays true after earlier legs saved archives too.
 */
const NOTHING_ARCHIVED_LEAD: Record<DocumentDownloadStop, string> = {
  complete: '',
  stopped: 'Stopped. ',
  'vault-locked': 'The vault locked, so nothing more was archived. ',
  'rate-limited':
    'The server limited how quickly documents could be read, so nothing more was archived. ',
  'archive-full': 'The archive reached its size limit. ',
  'save-failed': 'Your browser could not save the archive. ',
};

/** The one sentence that says how a finished run ended. */
function summarize(summary: RunSummary): string {
  // Not a field. It is exactly `total - saved - failed`, and a second field
  // carrying a fact already on the object is a second field that can disagree.
  const notReached = summary.total - summary.savedCount - summary.failures.length;
  const names = summary.archives.map((archive) => archive.name).join(', ');
  const [first] = summary.archives;
  const saved =
    first === undefined
      ? 'Nothing was saved.'
      : `${String(summary.savedCount)} of ${String(summary.total)} document(s) verified and ${
          first.kind === 'file'
            ? `saved as ${names}`
            : `handed to your browser's downloads as ${names}`
        }.`;
  const refused =
    summary.failures.length === 0 ? '' : ` ${String(summary.failures.length)} could not be saved.`;
  const missed = notReached === 0 ? '' : ` ${String(notReached)} not reached.`;
  const detail = summary.stoppedDetail === undefined ? '' : ` ${summary.stoppedDetail}`;
  const lead = summary.latestSaved
    ? STOP_LEAD[summary.stopped]
    : NOTHING_ARCHIVED_LEAD[summary.stopped];
  return `${lead}${saved}${refused}${missed}${detail}`;
}

/** One leg's result folded into the run so far. */
function merge(
  carried: RunSummary | null,
  result: DocumentArchiveResult,
  allocator: ArchivePathAllocator,
): RunSummary {
  return {
    total: carried === null ? result.total : carried.total,
    savedCount: (carried?.savedCount ?? 0) + result.savedCount,
    failures: [...(carried?.failures ?? []), ...result.failures],
    stopped: result.stopped,
    // THIS leg's detail, never a carried one: it describes how the leg in front
    // of the reader ended. Spread, because `exactOptionalPropertyTypes`
    // distinguishes an absent key from an explicit `undefined`.
    ...(result.stoppedDetail === undefined ? {} : { stoppedDetail: result.stoppedDetail }),
    archives: [...(carried?.archives ?? []), ...(result.archive === null ? [] : [result.archive])],
    latestSaved: result.archive !== null,
    allocator,
  };
}

export function DocumentBulkDownload({
  documents,
  invalidCount,
  selected = false,
}: DocumentBulkDownloadProps) {
  const [confirming, setConfirming] = useState(false);
  const [run, setRun] = useState<RunState>({ kind: 'idle' });
  const controllerRef = useRef<AbortController | null>(null);
  // Set from the click that starts a leg until that leg has settled, so a second
  // click (a double press, or Continue pressed again) cannot start a second one.
  const busyRef = useRef(false);

  /**
   * End the run, wherever the end came from: the Stop button, or unmounting.
   * The service then finishes the archive with what it holds.
   */
  const abortRun = useCallback(() => {
    controllerRef.current?.abort();
  }, []);

  useEffect(() => abortRun, [abortRun]);

  useBeforeUnloadWarning(run.kind === 'running');

  /**
   * Start one leg over `targets`, adding to `carried` when this is a
   * continuation. Called from a click, and everything up to `openArchiveTarget`
   * is synchronous on purpose (see this module's header).
   */
  const begin = useCallback(
    (targets: readonly BulkDownloadCandidate[], carried: RunSummary | null) => {
      if (busyRef.current) return;
      busyRef.current = true;
      setConfirming(false);
      const controller = new AbortController();
      controllerRef.current = controller;
      // A fresh run names its paths against the folders as they are now; a
      // continuation keeps the run's allocator, so its names never collide.
      const allocator =
        carried?.allocator ?? new ArchivePathAllocator(useVaultStore.getState().folders);
      const total = carried === null ? targets.length : carried.total;
      const already = carried === null ? 0 : carried.savedCount + carried.failures.length;
      const part = (carried?.archives.length ?? 0) + 1;

      const settle = (result: DocumentArchiveResult): void => {
        busyRef.current = false;
        setRun({
          kind: 'done',
          summary: merge(carried, result, allocator),
          remaining: targets.slice(result.savedCount + result.failures.length),
        });
      };

      void openArchiveTarget(archiveFileName(new Date(), part)).then(
        async (target) => {
          if (target === null) {
            // The save dialog was dismissed: nothing started, nothing changes.
            busyRef.current = false;
            return;
          }
          if (controller.signal.aborted) {
            // The page was left while the dialog was open. The guard is not
            // reset: this panel is gone, and nothing will read it again.
            await target.discard();
            return;
          }
          setRun({ kind: 'running', total, completed: already, current: '', finishing: false });
          settle(
            await archiveDocuments(targets, target, {
              signal: controller.signal,
              allocator,
              onProgress: (progress) => {
                setRun({
                  kind: 'running',
                  total,
                  // The document being read is not yet archived, so the bar
                  // shows the ones behind it.
                  completed: already + progress.index - 1,
                  current: progress.name,
                  finishing: false,
                });
              },
              onFinishing: () => {
                setRun((state) =>
                  state.kind === 'running' ? { ...state, finishing: true } : state,
                );
              },
            }),
          );
        },
        (error: unknown) => {
          // The browser refused the dialog or the file: no archive was begun.
          settle({
            total: targets.length,
            savedCount: 0,
            failures: [],
            stopped: 'save-failed',
            stoppedDetail: getApiErrorMessage(error, 'The save dialog could not be opened.'),
            archive: null,
          });
        },
      );
    },
    [],
  );

  const start = useCallback(() => {
    // Snapshotted, so a filter changed while the run is in flight cannot quietly
    // redefine what the reader agreed to.
    begin([...documents], null);
  }, [begin, documents]);

  const dismiss = useCallback(() => {
    setRun({ kind: 'idle' });
  }, []);

  const status =
    run.kind === 'idle'
      ? ''
      : run.kind === 'running'
        ? `Archiving ${String(run.total)} document(s). Keep this page open: Stop, or leaving it, saves the documents already verified.`
        : summarize(run.summary);

  // Nothing to offer and nothing to report. The panel disappears rather than
  // explaining a button it is not showing.
  if (documents.length === 0 && run.kind === 'idle') return null;

  return (
    <section
      aria-labelledby="documents-download-all-heading"
      data-testid="documents-download-all"
      className="space-y-3 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2
            id="documents-download-all-heading"
            className="text-sm font-semibold text-[hsl(var(--card-foreground))]"
          >
            Download your documents
          </h2>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Documents are deliberately not part of the encrypted backup, so this is how a copy of
            them leaves the server. Saves the {documents.length}{' '}
            {selected ? 'selected document(s)' : 'document(s) listed below'} to this device as one
            ZIP archive.
            {!selected &&
              invalidCount > 0 &&
              ` ${String(invalidCount)} row(s) in this view could not be read at all and are not included.`}
          </p>
        </div>

        {run.kind === 'running' ? (
          <button
            type="button"
            onClick={abortRun}
            disabled={run.finishing}
            className="inline-flex shrink-0 items-center gap-2 rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))] disabled:opacity-50"
          >
            <Square className="h-4 w-4" />
            Stop
          </button>
        ) : run.kind === 'done' ? (
          <div className="flex shrink-0 items-center gap-2">
            {run.remaining.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  begin(run.remaining, run.summary);
                }}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
              >
                <Download className="h-4 w-4" />
                {run.summary.latestSaved ? 'Continue in a new archive' : 'Try again'}
              </button>
            )}
            <button
              type="button"
              onClick={dismiss}
              className="rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Dismiss
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => {
              setConfirming(true);
            }}
            className="inline-flex shrink-0 items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
          >
            <Download className="h-4 w-4" />
            {selected ? 'Download selected' : 'Download all'}
          </button>
        )}
      </div>

      {/* Mounted from the panel's first render; only the text inside it changes. */}
      <p
        role="status"
        data-testid="documents-download-all-status"
        className={status === '' ? 'sr-only' : 'text-sm font-medium text-[hsl(var(--foreground))]'}
      >
        {status}
      </p>

      {run.kind === 'running' && (
        <>
          <div
            role="progressbar"
            aria-label="Download progress"
            aria-valuemin={0}
            aria-valuemax={run.total}
            aria-valuenow={run.completed}
            aria-valuetext={`${String(run.completed)} of ${String(run.total)} documents`}
            className="h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
          >
            <div
              className="h-full bg-[hsl(var(--primary))]"
              style={{ width: `${String(percentOf(run.completed, run.total))}%` }}
            />
          </div>
          {/* Outside the live region on purpose — see this module's header. */}
          <p
            data-testid="documents-download-all-current"
            className="flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]"
          >
            <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
            {run.finishing
              ? 'Finishing the archive…'
              : `Reading ${String(run.completed + 1)} of ${String(run.total)}: ${run.current}`}
          </p>
        </>
      )}

      {run.kind === 'done' && run.summary.archives[0]?.kind === 'download' && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          Your browser saves the archive wherever it normally saves downloads; its downloads list
          shows where it went.
        </p>
      )}

      {run.kind === 'done' && run.summary.failures.length > 0 && (
        <ul
          data-testid="documents-download-all-failures"
          className="space-y-1 text-xs text-[hsl(var(--muted-foreground))]"
        >
          {run.summary.failures.map((failure) => (
            <li key={failure.id}>
              <span className="font-medium text-[hsl(var(--foreground))]">{failure.name}</span>
              {' — '}
              {failure.reason}
            </li>
          ))}
        </ul>
      )}

      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Download {documents.length} document(s)</DialogTitle>
            <DialogDescription>
              They are saved as one ZIP archive. Each document is decrypted in this browser and
              checked against the checksum sealed inside it before it is added; nothing is
              compressed and nothing is sent anywhere. Folders become folders in the archive, so
              their names appear in it; a document whose folder cannot be read, or lies more than 50
              levels deep, goes at the top level. A large library can reach the server&apos;s read
              limit or the archive&apos;s size limit: the archive is then saved with what it holds,
              and Continue saves the rest in another one. Keep this page open and your vault
              unlocked until it finishes; Stop, a lock or leaving the page saves the documents
              already verified. Anything that could not be saved is listed at the end, with the
              reason.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button
              type="button"
              onClick={() => {
                setConfirming(false);
              }}
              className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={start}
              className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
            >
              <Download className="h-4 w-4" />
              Start download
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

/**
 * How full the bar is drawn. The denominator is floored at one rather than
 * branched on: a run always has at least one document, so a zero would be
 * unreachable, and an unreachable ternary is a branch no honest test can cover.
 */
function percentOf(completed: number, total: number): number {
  return Math.round((completed / Math.max(total, 1)) * 100);
}
