/**
 * Taking every stored document out of the vault as one ZIP archive.
 *
 * Documents are absent from the server-built vault backup, which carries a
 * `documentSummary` breadcrumb and not a byte of any document. Two user-level ways
 * out exist: the full backup (`services/backup/`), which keeps every document
 * ENCRYPTED for a later restore, and this module, which writes READABLE copies:
 * the same verified read the detail view performs, run over a list, into one
 * archive.
 *
 * ## Why an archive is acceptable here
 *
 * The constraint that governs everything about documents in this application is
 * that **no untrusted document byte is ever parsed in the app origin**, the one
 * holding the unlocked vault key. An earlier version refused to build an archive
 * on that ground, reading a ZIP writer as a format implementation fed
 * attacker-chosen bytes. A STORED-only writer is not one: `zipArchive.ts` copies
 * each verified file verbatim, frames it with headers built from numbers it was
 * handed, and computes a CRC-32, which branches on no byte value, exactly like
 * the AES-GCM and SHA-256 that already run over the same bytes here. It is a few
 * hundred lines in this repository, with no dependency, no compressor and no
 * parser. Names, the one part a document's author controls that becomes
 * structure, are made safe segment by segment first (`archiveNames.ts`).
 *
 * ## What "honest" means here, precisely
 *
 *   1. **A document enters the archive only after it has verified.** Each read
 *      runs the four checks in `download.ts`, and its bytes are written only
 *      once the whole-file digest has matched, so the archive never holds a
 *      partial or altered file. A document refused at any check is named in the
 *      summary with its reason, and the run goes on.
 *   2. **Nothing read after a lock or a sign-out enters the archive.** The run
 *      records the documents store's mutation generation when it starts, which
 *      `clearStore()` moves on lock and on sign-out, and re-checks it before each
 *      document, inside each segment write and after each rate-limit wait: the
 *      moment it moves, the document in flight is dropped and nothing more is
 *      read.
 *   3. **An early end keeps what is verified.** Stop, a lock or sign-out,
 *      leaving the page, the server's read limit, a full archive: each one
 *      FINISHES the archive with the documents already in it and saves it, as
 *      the separate files of the earlier design stayed saved, and the summary
 *      offers to continue the rest in a new archive. Only a failure of the save
 *      target itself throws the archive away, since it can no longer be
 *      finished; nothing in that archive is then counted as saved.
 *   4. **`savedCount + failures.length` is exactly the rows consumed**, for
 *      every way a run ends, so a continuation starts at the first row this run
 *      did not settle. A row interrupted mid-read, or refused by the rate
 *      limit, is left unconsumed rather than recorded as a failure, because the
 *      one answer for it is to try it again.
 *
 * ## The request budget
 *
 * The run reads each document with the row the list already holds, so it spends
 * no request on `GET /documents/:id`, which shares a per-account bucket with lock
 * and sign-out. Segment reads have a budget of their own; a short `Retry-After`
 * (a rate-limiting proxy's seconds) is waited out, as every paced bulk action in
 * this application does, and a long one (the account's own window, up to fifteen
 * minutes) ends the run as `rate-limited`, quoting the wait.
 */

import type { DocumentMeta, DocumentResponse } from '@hvault/shared';
import { getApiErrorMessage } from '../../lib/utils.js';
import { useAuthStore } from '../../stores/authStore.js';
import { documentsMutationGeneration } from '../../stores/documentsStore.js';
import { MAX_BULK_RETRIES, MAX_BULK_RETRY_AFTER_SECONDS } from '../../stores/vaultStore.js';
import {
  describeTransientFailure,
  isRateLimited,
  retryAfterSeconds,
} from '../auth/sessionFailure.js';
import type { ArchivePathAllocator } from './archiveNames.js';
import type { ArchiveTarget } from './archiveTarget.js';
import { UNOPENABLE_DOCUMENT_NAME } from './documentNames.js';
import {
  DocumentDownloadCancelledError,
  streamDocumentPlaintext,
  waitAbortably,
} from './download.js';
import { StoredZipWriter, crc32 } from './zipArchive.js';

/** What a degraded row's summary line says, since no read of it was attempted. */
const DEGRADED_REASON =
  'Its details could not be opened with this vault key, so there was nothing to download.';

/** What a row already being permanently deleted says, since its file may be gone. */
const PURGE_PENDING_REASON =
  'It is being permanently deleted, so its stored file may already have been removed.';

/** The reason used when a rejection carries no message of its own. */
const UNKNOWN_REASON = 'It could not be downloaded.';

/** The reason used when the save target refused without saying why. */
const UNKNOWN_SAVE_REASON = 'Your browser could not write the archive.';

/**
 * One row the run was asked to archive.
 *
 * A structural minimum rather than `DecryptedDocument`, so this module does not
 * import a store to describe its own input; every field of it is one the store's
 * row already has, so a `DecryptedDocument[]` is passed straight in.
 */
export interface BulkDownloadCandidate {
  id: string;
  /** The opened metadata, or `null` when the row is degraded. */
  meta: DocumentMeta | null;
  /** The folder the row is filed in, which becomes its directory in the archive. */
  folderId?: string | undefined;
  /**
   * Whether the row is already claimed for permanent deletion.
   *
   * Set when an empty-trash walk marked the row and then could not finish it —
   * the storage engine refused, the breaker tripped, and the hourly collector
   * owns it now. Its object may or may not still exist, and a read of it is a
   * 404 the reader would have no way to interpret, so the run says what is
   * really happening instead of relaying a status code.
   */
  purgePending?: boolean | undefined;
  /** The validated row as the list received it: the read uses it instead of fetching it. */
  _raw: DocumentResponse;
}

/**
 * One document the run could not archive, and why.
 *
 * Not exported, because nothing outside this module names it: a caller reaches
 * it through {@link DocumentArchiveResult.failures}, which is exported and
 * carries the shape with it.
 */
interface DocumentDownloadFailure {
  id: string;
  /** As the list names it: the sealed name, or {@link UNOPENABLE_DOCUMENT_NAME}. */
  name: string;
  /** A sentence the reader can act on. Never a status code on its own. */
  reason: string;
}

/**
 * Why a run ended.
 *
 * `complete` read every row. `stopped` is the reader's own Stop, or the page
 * going away; `vault-locked` is a lock or sign-out (usually the auto-lock, which
 * a long run cannot postpone because a loop generates no input); `rate-limited`
 * is the server asking for a wait too long to sit through; `archive-full` is
 * this archive reaching its size limit. Each of those still saves the archive.
 * `save-failed` is the one that does not: the browser refused to write or save
 * it.
 */
export type DocumentDownloadStop =
  'complete' | 'stopped' | 'vault-locked' | 'rate-limited' | 'archive-full' | 'save-failed';

/** Where a run got to. */
export interface DocumentArchiveResult {
  /** How many documents the run set out to archive. */
  total: number;
  /** How many were decrypted, verified and written into the archive that was saved. */
  savedCount: number;
  /** Every document that was refused, in the order it was reached. */
  failures: DocumentDownloadFailure[];
  /** Why the run ended. */
  stopped: DocumentDownloadStop;
  /**
   * One sentence about the STOP, when it has something to say that
   * {@link DocumentDownloadStop} does not carry: the wait a rate limit quoted
   * from `Retry-After`, or what the browser said when it refused the archive.
   */
  stoppedDetail?: string;
  /** The archive that was saved, or `null` when none was (nothing verified, or `save-failed`). */
  archive: { name: string; kind: ArchiveTarget['kind'] } | null;
}

/** The document a run is working on, for a progress line. */
export interface DocumentDownloadProgress {
  /** 1-based position of the document now being read. */
  index: number;
  /** How many documents the run set out to archive. */
  total: number;
  /** What the list calls the document now being read. */
  name: string;
}

export interface ArchiveDocumentsOptions {
  /**
   * Ends the run between documents and cancels the segment request in flight;
   * the archive is then finished with what it holds.
   */
  signal: AbortSignal;
  /** Names the paths of every archive of one run, across continuations. */
  allocator: ArchivePathAllocator;
  /** Called once per document, BEFORE it is read, so a reader sees what is next. */
  onProgress?: (progress: DocumentDownloadProgress) => void;
  /** Called once, when the reading is over and the archive is being finished and saved. */
  onFinishing?: () => void;
  /** How a short rate-limit wait is waited out. A seam for tests; the default is a timer. */
  wait?: (ms: number, signal: AbortSignal) => Promise<void>;
}

/**
 * The sentence one refusal is reported with.
 *
 * `describeTransientFailure` FIRST, because it owns the failures whose raw
 * message is useless to a reader — a rate limit (which it can even quote a wait
 * from), an unreachable server, and a 5xx, which this deployment redacts in
 * production anyway. Everything else falls through to the error's own message,
 * which for an integrity refusal is the sentence written for exactly that
 * situation and for a 404 is what the server said.
 */
function describeFailure(error: unknown): string {
  return describeTransientFailure(error) ?? getApiErrorMessage(error, UNKNOWN_REASON);
}

/** The name this run reports a candidate by, degraded or not. */
function displayName(candidate: BulkDownloadCandidate): string {
  return candidate.meta === null ? UNOPENABLE_DOCUMENT_NAME : candidate.meta.name;
}

/** How one document's read ended. */
type ReadOutcome =
  | { kind: 'read'; meta: DocumentMeta; chunks: Blob[]; crc: number }
  | { kind: 'failed'; reason: string }
  | { kind: 'stop'; stop: 'stopped' | 'vault-locked' | 'rate-limited'; detail?: string };

/**
 * Read one document, verified, collecting its bytes for the archive.
 *
 * Each attempt gets its OWN collector, so a retry after a short rate-limit wait
 * starts from nothing: the segments a refused attempt had already collected can
 * never be written in front of the ones a later attempt reads. Each segment's
 * CRC-32 is taken as it arrives and the segment is moved into a `Blob` at once,
 * so the script heap holds about one segment, whatever the document's size.
 */
async function readForArchive(
  candidate: BulkDownloadCandidate,
  options: ArchiveDocumentsOptions,
  interrupted: () => boolean,
): Promise<ReadOutcome> {
  const wait = options.wait ?? waitAbortably;
  for (let retries = 0; ; retries += 1) {
    const chunks: Blob[] = [];
    const checksum = { crc: 0 };
    try {
      const meta = await streamDocumentPlaintext(
        candidate.id,
        {
          write: (segment) => {
            // A lock or sign-out landing while this document was being read:
            // nothing of it is kept, and the read stops here.
            if (interrupted()) return Promise.reject(new DocumentDownloadCancelledError());
            checksum.crc = crc32(segment, checksum.crc);
            chunks.push(new Blob([segment]));
            return Promise.resolve();
          },
          discard: () => {
            chunks.length = 0;
            return Promise.resolve();
          },
        },
        { signal: options.signal, row: candidate._raw },
      );
      // No second check is needed here. The last segment's write above is the
      // last point a lock could have reached: what follows it (the whole-file
      // digest, the key zeroed, this function resuming) runs without yielding to
      // the event loop, and a lock is an event.
      return { kind: 'read', meta, chunks, crc: checksum.crc };
    } catch (error) {
      if (error instanceof DocumentDownloadCancelledError) {
        return { kind: 'stop', stop: interrupted() ? 'vault-locked' : 'stopped' };
      }
      if (!isRateLimited(error)) return { kind: 'failed', reason: describeFailure(error) };
      const seconds = retryAfterSeconds(error);
      if (
        seconds === null ||
        seconds > MAX_BULK_RETRY_AFTER_SECONDS ||
        retries >= MAX_BULK_RETRIES
      ) {
        return { kind: 'stop', stop: 'rate-limited', detail: describeFailure(error) };
      }
      await wait(seconds * 1000, options.signal);
      if (options.signal.aborted) return { kind: 'stop', stop: 'stopped' };
      if (interrupted()) return { kind: 'stop', stop: 'vault-locked' };
    }
  }
}

/**
 * Archive every candidate, in order, into `target`, and report what happened to
 * each.
 *
 * Resolves — always. A rejection would be a run whose partial outcome the caller
 * could not render, and the outcome is the entire product.
 */
export async function archiveDocuments(
  documents: readonly BulkDownloadCandidate[],
  target: ArchiveTarget,
  options: ArchiveDocumentsOptions,
): Promise<DocumentArchiveResult> {
  const total = documents.length;
  const failures: DocumentDownloadFailure[] = [];
  let savedCount = 0;
  let stopped: DocumentDownloadStop = 'complete';
  // `undefined` rather than `''`, and spread rather than assigned at the return:
  // `exactOptionalPropertyTypes` makes `{ stoppedDetail: undefined }` a different
  // type from an absent key, and an empty string would render as a blank line.
  let stoppedDetail: string | undefined;

  const generation = documentsMutationGeneration();
  const interrupted = (): boolean =>
    generation !== documentsMutationGeneration() || useAuthStore.getState().vaultKey === null;
  const writer = new StoredZipWriter(target, target.limitBytes);
  const { allocator } = options;

  try {
    for (const [position, candidate] of documents.entries()) {
      if (options.signal.aborted) {
        stopped = 'stopped';
        break;
      }
      if (interrupted()) {
        stopped = 'vault-locked';
        break;
      }

      const name = displayName(candidate);
      options.onProgress?.({ index: position + 1, total, name });

      // Refused rather than attempted: the row's real problem is already known
      // here, and it is the one worth telling the reader.
      if (candidate.meta === null) {
        failures.push({ id: candidate.id, name, reason: DEGRADED_REASON });
        continue;
      }
      if (candidate.purgePending === true) {
        failures.push({ id: candidate.id, name, reason: PURGE_PENDING_REASON });
        continue;
      }

      // Planned from the listed metadata, which is authenticated, and whose size
      // the read's framing check ties to the bytes it will produce.
      const placement = allocator.place(candidate.meta.name, candidate.folderId);
      if (!writer.fits(placement.pathBytes, candidate.meta.plaintextBytes)) {
        stopped = 'archive-full';
        break;
      }

      const outcome = await readForArchive(candidate, options, interrupted);
      if (outcome.kind === 'stop') {
        stopped = outcome.stop;
        stoppedDetail = outcome.detail;
        break;
      }
      if (outcome.kind === 'failed') {
        failures.push({ id: candidate.id, name, reason: outcome.reason });
        continue;
      }

      allocator.reserve(placement);
      await writer.addFile({
        path: placement.path,
        modified: new Date(outcome.meta.capturedAt),
        chunks: outcome.chunks,
        crc: outcome.crc,
      });
      savedCount += 1;
    }

    const detail = stoppedDetail === undefined ? {} : { stoppedDetail };
    if (writer.entryCount === 0) {
      // Nothing verified: no archive at all, rather than an empty one. The
      // refusals still stand, and the rows they consumed stay consumed.
      await target.discard();
      return { total, savedCount, failures, stopped, ...detail, archive: null };
    }
    options.onFinishing?.();
    await writer.finish();
    await target.commit();
    allocator.keepArchive();
    return {
      total,
      savedCount,
      failures,
      stopped,
      ...detail,
      archive: { name: target.name, kind: target.kind },
    };
  } catch (error) {
    // Every read failure is classified inside `readForArchive`, so what reaches
    // here is the target refusing a write or the save. The archive cannot be
    // finished: it is dropped, its names are given back, and the whole leg counts
    // as unconsumed so a retry covers it again.
    await target.discard();
    allocator.dropArchive();
    return {
      total,
      savedCount: 0,
      failures: [],
      stopped: 'save-failed',
      stoppedDetail: getApiErrorMessage(error, UNKNOWN_SAVE_REASON),
      archive: null,
    };
  }
}
