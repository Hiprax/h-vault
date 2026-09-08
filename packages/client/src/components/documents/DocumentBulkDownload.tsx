import { useCallback, useEffect, useRef, useState } from 'react';
import { Download, Loader2, X } from 'lucide-react';
import {
  saveAllDocuments,
  type BulkDownloadCandidate,
  type DocumentDownloadAllResult,
  type DocumentDownloadStop,
} from '../../services/documents/downloadAll';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';

/**
 * The one control that takes a whole document library out of this instance, and
 * the report of what happened to it.
 *
 * A document is the only thing in this vault the encrypted backup does not
 * carry, so before this existed the only way out was one download at a time. The
 * work itself is `services/documents/downloadAll.ts`; this is its surface.
 *
 * ## Four things about it are load-bearing
 *
 *   * **The live region is mounted unconditionally** and only its CONTENT
 *     changes, exactly as `AppLayout`'s offline-cache notice is. A `role="status"`
 *     region inserted into the document already holding its message is
 *     frequently never announced at all: the special handling that survives that
 *     shape is defined for `role="alert"`, which is the wrong politeness for a
 *     progress line. So the region is here from the panel's first render and
 *     empty (`sr-only`, occupying no layout) until there is something to say.
 *   * **What it says is COARSE, and the per-document line is outside it.** The
 *     region carries one sentence when a run starts and one when it ends. A
 *     region announcing every document would queue five thousand polite
 *     announcements on an account holding five thousand documents, which is not
 *     a progress report — it is a denial of service delivered politely. The
 *     document being read is a plain paragraph beside the bar, and the bar's
 *     `aria-valuetext` carries the count for anyone who asks for it.
 *   * **The failure list is outside the region too**, for the same reason: it is
 *     read on demand, not announced over the sentence that says how the run
 *     ended.
 *   * **Unmounting ends the run.** A bulk export is page-scoped exactly as a
 *     single download is — the state lives here rather than in `documentsStore`,
 *     which is where an UPLOAD lives precisely because an upload must survive
 *     navigation. Navigating away, or locking the vault (which swaps this whole
 *     route out), ends it rather than letting it decrypt on into a closed vault.
 */

interface DocumentBulkDownloadProps {
  /**
   * The rows to save: whatever the list below is showing.
   *
   * Deliberately what is LISTED rather than "every document that exists". The
   * panel sits above a list, so a reader's expectation is set by the rows they
   * can see — and it makes the folder, favorites, trash and search filters part
   * of the export without a second control to explain. It is also the only way
   * to break an export too large for one run into pieces.
   */
  documents: readonly BulkDownloadCandidate[];
  /**
   * Rows the current view's fetch dropped for not matching the expected shape.
   *
   * Named here rather than left to the page's own banner, because this panel is
   * the one place that makes a claim about completeness: "the 12 document(s)
   * listed below" counts what survived validation, and a reader deciding whether
   * they have everything needs to know that a number was subtracted.
   */
  invalidCount: number;
}

/** Where the panel is. */
type RunState =
  | { kind: 'idle' }
  | { kind: 'running'; total: number; completed: number; current: string }
  | {
      kind: 'done';
      result: DocumentDownloadAllResult;
      /** What a run that stopped early never reached, so it can be resumed. */
      remaining: readonly BulkDownloadCandidate[];
    };

/**
 * How each ending introduces itself.
 *
 * A lookup rather than a chain of ternaries: the type makes it exhaustive, so a
 * fifth way for a run to stop is a compile error here instead of a summary that
 * silently reads as though the export had finished.
 */
const STOP_LEAD: Record<DocumentDownloadStop, string> = {
  complete: '',
  cancelled: 'Download cancelled. ',
  'rate-limited':
    'The server limited how quickly documents could be read, so the download stopped. ',
  'vault-locked': 'The vault locked, so the download stopped. ',
};

/**
 * The one sentence that says how a finished run ended.
 *
 * It says "sent to your browser's downloads", never "saved", and the distinction
 * is the honest one: a bulk save hands each file to the browser through an
 * anchor and an object URL, which reports nothing back — Chromium in particular
 * queues or refuses the second and later downloads of a single action until the
 * reader allows them, and no API tells a page that it did. What this code can
 * observe is that the document was fetched, every segment authenticated and the
 * whole-file digest matched. Where the file landed is between the reader and
 * their browser, so the note below the summary points them at the one thing that
 * is authoritative — the same rule the empty-trash toast on this page follows.
 */
function summarize(result: DocumentDownloadAllResult): string {
  // Not a field on the result. It is exactly `total - saved - failed`, and a
  // second field carrying a fact already on the object is a second field that
  // can disagree with it.
  const notReached = result.total - result.savedCount - result.failures.length;
  const sent = `${String(result.savedCount)} of ${String(result.total)} document(s) verified and sent to your browser's downloads.`;
  const refused =
    result.failures.length === 0 ? '' : ` ${String(result.failures.length)} could not be saved.`;
  const missed = notReached === 0 ? '' : ` ${String(notReached)} not reached.`;
  // What the STOP itself had to say, when it had anything. Only a rate limit does
  // today, and it is the wait quoted from `Retry-After` — the one actionable part
  // of that answer. It used to reach the reader as the offending document's
  // failure line; that is what took the document out of the resume, so the
  // sentence moved onto the result and is appended here instead.
  const detail = result.stoppedDetail === undefined ? '' : ` ${result.stoppedDetail}`;
  return `${STOP_LEAD[result.stopped]}${sent}${refused}${missed}${detail}`;
}

export function DocumentBulkDownload({ documents, invalidCount }: DocumentBulkDownloadProps) {
  const [confirming, setConfirming] = useState(false);
  const [run, setRun] = useState<RunState>({ kind: 'idle' });
  const controllerRef = useRef<AbortController | null>(null);

  /**
   * End the run, wherever the end came from.
   *
   * ONE function for the Cancel button and for unmounting, rather than two
   * copies of the same optional call: the button can only be pressed while a
   * controller exists and an unmount can happen before one ever does, so a
   * single definition is the only arrangement in which both halves of that
   * optional chain are ever exercised.
   */
  const abortRun = useCallback(() => {
    controllerRef.current?.abort();
  }, []);

  useEffect(() => abortRun, [abortRun]);

  /**
   * Run over `targets`, adding to `carried` when this is a continuation.
   *
   * The counts a continuation reports are the counts of the WHOLE export, not of
   * the leg: a reader who resumed after a rate limit wants to know how much of
   * their library is out, and "3 of 4" from a second leg over four documents
   * would tell them nothing about the ninety before it.
   */
  const begin = useCallback(
    (targets: readonly BulkDownloadCandidate[], carried: DocumentDownloadAllResult | null) => {
      setConfirming(false);
      const controller = new AbortController();
      controllerRef.current = controller;
      const total = carried === null ? targets.length : carried.total;
      const already = carried === null ? 0 : carried.savedCount + carried.failures.length;
      // `current` is empty for no rendered frame: `saveAllDocuments` reports its
      // first document before it reaches its first await, so both writes land in
      // this click's own tick and React commits the second of them.
      setRun({ kind: 'running', total, completed: already, current: '' });

      void saveAllDocuments(targets, {
        signal: controller.signal,
        onProgress: (progress) => {
          setRun({
            kind: 'running',
            total,
            // The document being read is not yet saved, so the bar shows the
            // ones behind it. A bar that filled on the way in would read 100 %
            // while the last document was still being decrypted.
            completed: already + progress.index - 1,
            current: progress.name,
          });
        },
      }).then((result) => {
        const merged: DocumentDownloadAllResult =
          carried === null
            ? result
            : {
                total,
                savedCount: carried.savedCount + result.savedCount,
                failures: [...carried.failures, ...result.failures],
                stopped: result.stopped,
                // THIS leg's detail, never the carried one: it describes how the
                // run in front of the reader ended. Dropping it would make a
                // second rate limit silently quieter than the first, which is
                // the leg where the wait matters most. Spread rather than
                // assigned, because `exactOptionalPropertyTypes` distinguishes an
                // absent key from an explicit `undefined`.
                ...(result.stoppedDetail === undefined
                  ? {}
                  : { stoppedDetail: result.stoppedDetail }),
              };
        setRun({
          kind: 'done',
          result: merged,
          remaining: targets.slice(result.savedCount + result.failures.length),
        });
      });
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
        ? `Downloading ${String(run.total)} document(s). This page must stay open.`
        : summarize(run.result);

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
            them leaves the server. Saves the {documents.length} document(s) listed below to this
            device, one at a time.
            {invalidCount > 0 &&
              ` ${String(invalidCount)} row(s) in this view could not be read at all and are not included.`}
          </p>
        </div>

        {run.kind === 'running' ? (
          <button
            type="button"
            onClick={abortRun}
            className="inline-flex shrink-0 items-center gap-2 rounded-md border border-[hsl(var(--border))] px-3 py-2 text-sm font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
          >
            <X className="h-4 w-4" />
            Cancel
          </button>
        ) : run.kind === 'done' ? (
          <div className="flex shrink-0 items-center gap-2">
            {run.remaining.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  begin(run.remaining, run.result);
                }}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] transition-opacity hover:opacity-90"
              >
                <Download className="h-4 w-4" />
                Continue
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
            Download all
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
            Reading {run.completed + 1} of {run.total}: {run.current}
          </p>
        </>
      )}

      {run.kind === 'done' && run.result.savedCount > 0 && (
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          Your browser decides where these files land, and can refuse several downloads from one
          action. If they stopped appearing, check its downloads list and allow them, then use
          Continue or run this again.
        </p>
      )}

      {run.kind === 'done' && run.result.failures.length > 0 && (
        <ul
          data-testid="documents-download-all-failures"
          className="space-y-1 text-xs text-[hsl(var(--muted-foreground))]"
        >
          {run.result.failures.map((failure) => (
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
              Each document is decrypted in this browser, checked against the checksum sealed inside
              it, and handed to your browser as its own file. Nothing is combined into an archive
              and nothing is sent anywhere. They go one at a time, so a large library takes a while
              — keep this page open and your vault unlocked until it finishes. Your browser saves
              them wherever it normally saves downloads, and may first ask permission to download
              several files at once. Anything that could not be saved is listed at the end, with the
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
 * How full the bar is drawn.
 *
 * The denominator is floored at one rather than branched on. A run always has at
 * least one document — the panel offers no button without one — so a zero would
 * be unreachable, and an unreachable ternary is a branch no honest test can
 * cover sitting in front of an `NaN%` width nobody would notice until it was in
 * front of a user. `Math.max` is neither.
 */
function percentOf(completed: number, total: number): number {
  return Math.round((completed / Math.max(total, 1)) * 100);
}
