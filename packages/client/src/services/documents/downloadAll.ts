/**
 * Taking every stored document out of the vault, one at a time.
 *
 * Documents are deliberately absent from the encrypted backup — that file
 * carries a `documentSummary` breadcrumb and not a byte of any document — so the
 * operator's copy of the storage volume was, until this module existed, the only
 * way a whole document store could leave the server. That is a fine answer for
 * whoever runs the instance and no answer at all for whoever uses one they do
 * not run. This is the user-level half: the same verified read the detail view
 * performs, run over a list.
 *
 * ## Why it is a loop and not an archive
 *
 * The obvious shape is one ZIP. It is refused on the constraint that governs
 * everything about documents in this application: **no untrusted document byte
 * is ever parsed, or assembled, in the app origin**. A ZIP writer is a format
 * implementation fed entirely by attacker-chosen bytes and names, running in the
 * one origin that holds the unlocked vault key, and it would arrive as a
 * dependency nobody in this project has read. A sequential loop over
 * {@link saveDocument} adds no library, no parser and no format: every document
 * goes through the same four integrity checks, in the same order, as a download
 * of one.
 *
 * ## What "honest" means here, precisely
 *
 * Three rules, and each of them is the difference between a summary a user can
 * act on and one they cannot:
 *
 *   1. **One failure never ends the run.** A document whose object the storage
 *      engine has lost stops that document and nothing else. The alternative —
 *      abandoning the export on the first refusal — is what makes a user of a
 *      shared instance unable to leave it.
 *   2. **Nothing that failed is presented as saved.** The bulk path takes
 *      {@link saveDocument}'s blob branch, which writes nothing anywhere until
 *      the whole-file digest has been compared, so a document that fails
 *      verification produces NO file rather than a truncated one. The count of
 *      saved documents is therefore a count of files that exist and verified.
 *   3. **Every refusal is named, with its own reason.** A summary saying "3
 *      failed" tells a user to try the whole thing again; one naming three
 *      documents and saying which lost its object, which would not open under
 *      this vault key and which the network dropped tells them what to do about
 *      each.
 */

import type { DocumentMeta } from '@hvault/shared';
import { getApiErrorMessage } from '../../lib/utils.js';
import { useAuthStore } from '../../stores/authStore.js';
import { describeTransientFailure, isRateLimited } from '../auth/sessionFailure.js';
import {
  DocumentDownloadCancelledError,
  saveDocument,
  type SaveDocumentOptions,
} from './download.js';

/**
 * What the list calls a row whose sealed metadata would not open.
 *
 * THE definition, and `components/documents/DocumentList.tsx` reads it from
 * here rather than repeating the words. A failure summary has to name a document
 * exactly as the list beside it does, or the reader cannot tell which of the
 * rows in front of them the reason belongs to — and a degraded row has no other
 * name to be identified by, because the only copy of its name is inside the blob
 * that would not open.
 */
export const UNOPENABLE_DOCUMENT_NAME = 'Unopenable document';

/** What a degraded row's summary line says, since no read of it was attempted. */
const DEGRADED_REASON =
  'Its details could not be opened with this vault key, so there was nothing to download.';

/** What a row already being permanently deleted says, since its file may be gone. */
const PURGE_PENDING_REASON =
  'It is being permanently deleted, so its stored file may already have been removed.';

/** The reason used when a rejection carries no message of its own. */
const UNKNOWN_REASON = 'It could not be downloaded.';

/**
 * One row the run was asked to save.
 *
 * A structural minimum rather than `DecryptedDocument`, so this module does not
 * import a store to describe its own input; every field of it is one the store's
 * row already has, so a `DecryptedDocument[]` is passed straight in.
 */
export interface BulkDownloadCandidate {
  id: string;
  /** The opened metadata, or `null` when the row is degraded. */
  meta: DocumentMeta | null;
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
}

/**
 * One document the run could not save, and why.
 *
 * Not exported, because nothing outside this module names it: a caller reaches
 * it through {@link DocumentDownloadAllResult.failures}, which is exported and
 * carries the shape with it. The dead-code gate is answered by removing an
 * `export` keyword, never by an entry in an ignore list.
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
 * Four states rather than a `cancelled` boolean, because a run that stopped
 * early has to say WHICH early: "cancelled" is something the reader did and
 * needs no advice, a rate limit is something the server did whose only answer is
 * to wait, and a locked vault is neither — it is the auto-lock timer, which a
 * long run cannot avoid because a loop generates none of the input events that
 * postpone it. Collapsing them would leave the last two reported as the first,
 * which reads as "your export finished" for a library that is mostly still on
 * the server.
 */
export type DocumentDownloadStop = 'complete' | 'cancelled' | 'rate-limited' | 'vault-locked';

/**
 * Where a run got to.
 *
 * There is deliberately no "not reached" field. It is `total - savedCount -
 * failures.length` and nothing else, and a second field carrying a fact already
 * on the object is a second field that can disagree with it — the same rule the
 * upload rows apply to their part numbers.
 */
export interface DocumentDownloadAllResult {
  /** How many documents the run set out to save. */
  total: number;
  /**
   * How many were decrypted, verified and handed to the browser as a file.
   *
   * "Handed to", never "written to disk", and the distinction is real on this
   * path: the bulk save goes through the anchor-and-object-URL helper, which the
   * browser answers asynchronously and silently — Chromium in particular will
   * queue or refuse the second and later downloads of one gesture until the
   * reader allows them, and no API tells a page that it did. What this number
   * promises is exactly what this code can observe: the document was fetched,
   * every segment authenticated, the whole-file digest matched, and the bytes
   * were handed to the browser as a download. Where they landed is between the
   * reader and their browser, and the summary says so.
   */
  savedCount: number;
  /** Every document that was refused, in the order it was reached. */
  failures: DocumentDownloadFailure[];
  /** Why the run ended. */
  stopped: DocumentDownloadStop;
}

/** The document a run is working on, for a progress line. */
export interface DocumentDownloadProgress {
  /** 1-based position of the document now being read. */
  index: number;
  /** How many documents the run set out to save. */
  total: number;
  /** What the list calls the document now being read. */
  name: string;
}

export interface SaveAllDocumentsOptions {
  /**
   * Ends the run between documents and cancels the segment request in flight.
   *
   * The same page scoping a single download has: a bulk export exists to put
   * files in front of the person watching it, so navigating away, locking the
   * vault or pressing Cancel ends it rather than letting it run on.
   */
  signal?: AbortSignal;
  /** Called once per document, BEFORE it is read, so a reader sees what is next. */
  onProgress?: (progress: DocumentDownloadProgress) => void;
}

/**
 * Whether the run has been cancelled, read through a CALL.
 *
 * The same two words, and the same reason, as `download.ts`'s own predicate: a
 * bare `signal.aborted` is narrowed by the type checker after the first read in
 * a function, so every later re-check looks redundant to
 * `no-unnecessary-condition` — while the value changes underneath the reader,
 * which is the entire point of re-reading it.
 */
function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

/**
 * The sentence one refusal is reported with.
 *
 * `describeTransientFailure` FIRST, because it owns the three failures whose raw
 * message is useless to a reader — a rate limit (which it can even quote a wait
 * from), an unreachable server, and a 5xx, which this deployment redacts to
 * "Internal Server Error" in production anyway. Everything else falls through to
 * the error's own message, which for an integrity refusal is the sentence
 * written for exactly that situation and for a 404 is what the server said. A
 * generic string in either place would throw away the only part of the summary a
 * reader can act on.
 */
function describeFailure(error: unknown): string {
  return describeTransientFailure(error) ?? getApiErrorMessage(error, UNKNOWN_REASON);
}

/** The name this run reports a candidate by, degraded or not. */
function displayName(candidate: BulkDownloadCandidate): string {
  return candidate.meta === null ? UNOPENABLE_DOCUMENT_NAME : candidate.meta.name;
}

/**
 * Save every candidate, in order, and report what happened to each.
 *
 * Resolves — always. A rejection would be a run whose partial outcome the caller
 * could not render, and the outcome is the entire product: this function's
 * contract is that it comes back with an answer for every document it reached
 * and an honest count of the ones it did not.
 */
export async function saveAllDocuments(
  documents: readonly BulkDownloadCandidate[],
  options: SaveAllDocumentsOptions = {},
): Promise<DocumentDownloadAllResult> {
  const total = documents.length;
  const failures: DocumentDownloadFailure[] = [];
  let savedCount = 0;
  let stopped: DocumentDownloadStop = 'complete';

  // Built once, and the branch is `exactOptionalPropertyTypes` rather than
  // style: `{ signal: undefined }` is not a `{ signal?: AbortSignal }` under this
  // project's compiler settings.
  //
  // The dialog is off for the reason `SaveDocumentOptions.useSaveDialog`
  // records: it needs transient activation, and the one click that started this
  // run cannot supply it to a document read minutes later.
  const readOptions: SaveDocumentOptions = options.signal
    ? { signal: options.signal, useSaveDialog: false }
    : { useSaveDialog: false };

  for (const [position, candidate] of documents.entries()) {
    if (isAborted(options.signal)) {
      stopped = 'cancelled';
      break;
    }

    // The vault, re-read every time round. `requireVaultKey` throws a PLAIN
    // `Error` on a locked vault, so without this check a lock landing mid-run
    // would be recorded as an ordinary failure — once for the document in
    // flight and once more for every document after it, producing a summary
    // that blamed the documents for the reader's own auto-lock. The route
    // unmounting is what usually stops a run first, but it is a UI lifetime and
    // this is a service: the guarantee belongs here.
    if (useAuthStore.getState().vaultKey === null) {
      stopped = 'vault-locked';
      break;
    }

    const name = displayName(candidate);
    options.onProgress?.({ index: position + 1, total, name });

    // Refused rather than attempted, and the difference is not pedantry: the
    // read needs a `DocumentMeta` to suggest a name from and this row has none,
    // so an attempt would fail on a technicality several layers below and report
    // whatever that layer happened to say. The row's real problem is already
    // known here, and it is the one worth telling the user.
    if (candidate.meta === null) {
      failures.push({ id: candidate.id, name, reason: DEGRADED_REASON });
      continue;
    }

    // Refused for the same reason and one step later: the row is real and its
    // metadata opened, but the object behind it has been handed to the garbage
    // collector. Reading it would spend a request to be told 404, which names
    // the wrong problem.
    if (candidate.purgePending === true) {
      failures.push({ id: candidate.id, name, reason: PURGE_PENDING_REASON });
      continue;
    }

    try {
      await saveDocument({ id: candidate.id, meta: candidate.meta }, readOptions);
      savedCount += 1;
    } catch (error) {
      // A cancellation is not a failure and is never listed as one. It can only
      // arrive from the signal on this path — the blob branch opens no dialog to
      // be dismissed — so it ends the run rather than skipping one document.
      if (error instanceof DocumentDownloadCancelledError) {
        stopped = 'cancelled';
        break;
      }
      failures.push({ id: candidate.id, name, reason: describeFailure(error) });
      // A rate limit ENDS the run, and it is the one refusal that does.
      //
      // Reading a document costs a request for the row and one per segment, and
      // both routes are user-keyed and bounded — the row read against 60 a
      // minute, the segments against a budget derived from the operator's size
      // cap. An export of a large library is the one legitimate thing in this
      // application that reaches either. Carrying on would spend the whole list
      // against a closed window, turn a hundred documents into a hundred
      // identical refusals, and keep the window open by attempting more; and the
      // reader's answer is the same for all of them, which is to wait. So the
      // run stops here with the count it really achieved, and the summary says
      // to run it again.
      if (isRateLimited(error)) {
        stopped = 'rate-limited';
        break;
      }
    }
  }

  return { total, savedCount, failures, stopped };
}
