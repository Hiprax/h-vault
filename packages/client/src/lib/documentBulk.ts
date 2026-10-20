/**
 * The documents page's bulk actions: one per-row request per selected document,
 * paced as the vault's bulk tag and purge are, through the documents store's own
 * per-row actions (which keep both lists, the in-flight suppression sets and the
 * lock generation coherent, row by row).
 *
 * Per-row rather than a bulk endpoint on purpose. A document's tags are sealed
 * under that document's own key, so only the browser can retag one; a permanent
 * delete has to keep the server's claim, delete-object, delete-row order for
 * each document; and the routes these use carry `documentWriteLimiter`, a budget
 * sized for two passes over every document an account can hold.
 *
 * Imported only by the documents page's lazy chunk: nothing here reaches the
 * initial payload.
 */
import { isAxiosError } from 'axios';
import { MAX_DOCUMENT_TAGS } from '@hvault/shared';
import {
  describeTransientFailure,
  isRateLimited,
  retryAfterSeconds,
} from '../services/auth/sessionFailure';
import {
  BULK_ABANDONED_MESSAGE,
  MAX_BULK_RETRIES,
  MAX_BULK_RETRY_AFTER_SECONDS,
  sendPaced,
} from '../stores/vaultStore';
import { documentsMutationGeneration, useDocumentsStore } from '../stores/documentsStore';
import { documentMetaRefusal } from './documentDetails';
import { getApiErrorMessage } from './utils';

/** What one row came to: changed, or already as asked (nothing was sent). */
export type RowResult = 'done' | 'unchanged';

/** Every selected row, sorted by what became of it. */
export interface DocumentBulkOutcome {
  readonly done: readonly string[];
  readonly unchanged: readonly string[];
  readonly failed: readonly { readonly id: string; readonly reason: string }[];
  /** Never sent: the run stopped (a lock, or the server stopped answering). */
  readonly notSent: readonly string[];
  /** Why the run stopped, when it did. */
  readonly stopReason: string | null;
}

/** The run stopped before this row, so it was never sent. */
class NotSentError extends Error {}

/** Said of a row the server stopped answering for, and of the rows after it. */
export const SERVER_STOPPED_MESSAGE =
  'The server stopped answering, so the rest were not sent. Try again in a moment.';

/**
 * Whether a failure means the server, not the row, is the problem: no answer at
 * all, a 5xx, or a 429 `sendPaced` will not wait out. Every later request would
 * fail the same way, and a permanent delete marks its row as being deleted BEFORE
 * it reaches the storage engine, so carrying on against a broken engine would
 * leave each remaining row stranded there. The run stops at the first one, as
 * emptying the trash does.
 *
 * A SHORT 429 (a `Retry-After` of at most {@link MAX_BULK_RETRY_AFTER_SECONDS},
 * as the host nginx sends) is not one: `sendPaced` waits it out and sends the row
 * again, through this same wrapper, up to {@link MAX_BULK_RETRIES} times, so it
 * stops the run only once those are spent (`shortWaits` counts them per row).
 */
function stopsTheRun(error: unknown, shortWaits: number): boolean {
  if (isRateLimited(error)) {
    const seconds = retryAfterSeconds(error);
    return (
      seconds === null || seconds > MAX_BULK_RETRY_AFTER_SECONDS || shortWaits > MAX_BULK_RETRIES
    );
  }
  if (!isAxiosError(error)) return false;
  return error.response === undefined || error.response.status >= 500;
}

/**
 * Runs `perRow` over `ids`, paced and at most a few at a time, and sorts every
 * row into the outcome. Nothing is thrown: a refusal is reported for its row.
 */
export async function runDocumentBulk(
  ids: readonly string[],
  perRow: (id: string) => Promise<RowResult>,
): Promise<DocumentBulkOutcome> {
  let stopReason: string | null = null;
  const results = await sendPaced(
    ids.map((id) => {
      // How many 429s this row has had: `sendPaced` calls this same function
      // again after waiting out a short one.
      let rateLimited = 0;
      return async () => {
        if (stopReason !== null) throw new NotSentError(stopReason);
        try {
          return await perRow(id);
        } catch (error: unknown) {
          if (isRateLimited(error)) rateLimited += 1;
          if (stopsTheRun(error, rateLimited)) stopReason ??= SERVER_STOPPED_MESSAGE;
          throw error;
        }
      };
    }),
    undefined,
    documentsMutationGeneration,
  );

  const done: string[] = [];
  const unchanged: string[] = [];
  const failed: { id: string; reason: string }[] = [];
  const notSent: string[] = [];
  // `sendPaced` settles one result per request, in order, so `results[i]` is the
  // answer for `ids[i]`.
  ids.forEach((id, index) => {
    const result = results[index];
    if (result === undefined) return;
    if (result.status === 'fulfilled') {
      (result.value === 'done' ? done : unchanged).push(id);
      return;
    }
    const reason: unknown = result.reason;
    if (reason instanceof NotSentError) {
      notSent.push(id);
    } else if (reason instanceof Error && reason.message === BULK_ABANDONED_MESSAGE) {
      stopReason ??= BULK_ABANDONED_MESSAGE;
      notSent.push(id);
    } else {
      // A transient failure in the app's own words ("Could not reach the server…",
      // "Too many attempts. Please try again in 15 minutes."), anything else in the
      // server's, cut to the length a toast shows whole.
      failed.push({
        id,
        reason:
          describeTransientFailure(reason) ??
          getApiErrorMessage(reason, 'It could not be changed.'),
      });
    }
  });
  return { done, unchanged, failed, notSent, stopReason };
}

// ---------------------------------------------------------------------------
// The five actions, one row at a time
// ---------------------------------------------------------------------------

const store = () => useDocumentsStore.getState();

/** A restore of a row the server is already destroying would answer 404. */
export const BEING_DELETED_MESSAGE = 'It is already being deleted, so it cannot be restored.';
/** A degraded row's tags are sealed in the blob that would not open. */
export const UNOPENABLE_TAG_MESSAGE =
  'It could not be opened with this vault key, so it cannot be tagged.';
/** The row left the list (another tab, a lock) between the selection and its turn. */
export const ROW_GONE_MESSAGE = 'It is no longer in this list.';

export const trashRow = async (id: string): Promise<RowResult> => {
  await store().deleteDocument(id);
  return 'done';
};

export const restoreRow = async (id: string): Promise<RowResult> => {
  if (store().trashDocuments.find((doc) => doc.id === id)?.purgePending === true) {
    throw new Error(BEING_DELETED_MESSAGE);
  }
  await store().restoreDocument(id);
  return 'done';
};

export const purgeRow = async (id: string): Promise<RowResult> => {
  await store().purgeDocument(id);
  return 'done';
};

export function moveRow(folderId: string | null): (id: string) => Promise<RowResult> {
  return async (id) => {
    const row = store().documents.find((doc) => doc.id === id);
    if (row !== undefined && (row.folderId ?? null) === folderId) return 'unchanged';
    await store().moveToFolder(id, folderId);
    return 'done';
  };
}

export function tagRow(tag: string): (id: string) => Promise<RowResult> {
  return async (id) => {
    const row = store().documents.find((doc) => doc.id === id);
    if (row === undefined) throw new Error(ROW_GONE_MESSAGE);
    if (row.meta === null) throw new Error(UNOPENABLE_TAG_MESSAGE);
    if (row.meta.tags.includes(tag)) return 'unchanged';
    if (row.meta.tags.length >= MAX_DOCUMENT_TAGS) {
      throw new Error(
        `It already has ${String(MAX_DOCUMENT_TAGS)} tags, the most a document can have.`,
      );
    }
    const tags = [...row.meta.tags, tag];
    const refusal = documentMetaRefusal({ ...row.meta, tags });
    if (refusal !== null) throw new Error(refusal);
    await store().updateDocumentMeta(id, { tags });
    return 'done';
  };
}

// ---------------------------------------------------------------------------
// What the person is told
// ---------------------------------------------------------------------------

/** How long a report that needs reading stays up (a success keeps the default). */
export const BULK_REPORT_DURATION_MS = 12_000;

export interface BulkReport {
  readonly title: string;
  readonly description?: string;
  readonly type: 'success' | 'warning' | 'error';
  readonly duration?: number;
}

const documentsWord = (count: number): string => (count === 1 ? 'document' : 'documents');

/**
 * How a report names the rows that were already as asked (nothing was sent for
 * them): `some` completes "N already …" ("in Taxes", "had it"), and `all` is the
 * whole title when every selected row was.
 */
interface AlreadyWording {
  readonly some: string;
  readonly all: string;
}

/**
 * The toast for a finished run. `pastTense` completes "N documents …" ("moved to
 * the trash", "restored"). Every selected row is accounted for: changed, already
 * as asked (`already`; never reported as "0 moved"), refused, or not sent. A run
 * where nothing was refused or held back is a success; otherwise a warning (some
 * rows are as asked now) or an error (none are), with the first refusal's reason
 * underneath (already cut to the length a toast shows whole) and, when rows were
 * held back, why the run stopped.
 */
export function describeBulkOutcome(
  outcome: DocumentBulkOutcome,
  pastTense: string,
  already?: AlreadyWording,
): BulkReport {
  const changed = outcome.done.length;
  const unchanged = outcome.unchanged.length;
  const total = changed + unchanged + outcome.failed.length + outcome.notSent.length;
  const alreadyClause =
    unchanged > 0 && already !== undefined ? `, ${String(unchanged)} already ${already.some}` : '';
  if (outcome.failed.length === 0 && outcome.notSent.length === 0) {
    if (changed === 0 && already !== undefined) return { title: already.all, type: 'success' };
    return {
      title: `${String(changed)} ${documentsWord(changed)} ${pastTense}${alreadyClause}`,
      type: 'success',
    };
  }
  const missed: string[] = [];
  if (outcome.failed.length > 0) missed.push(`${String(outcome.failed.length)} could not be`);
  if (outcome.notSent.length > 0) missed.push(`${String(outcome.notSent.length)} were not sent`);
  const reasons: string[] = [];
  const firstRefusal = outcome.failed[0]?.reason;
  if (firstRefusal !== undefined) reasons.push(firstRefusal);
  if (outcome.notSent.length > 0 && outcome.stopReason !== null) {
    if (outcome.stopReason !== firstRefusal) reasons.push(outcome.stopReason);
  }
  return {
    title: `${String(changed)} of ${String(total)} ${documentsWord(total)} ${pastTense}${alreadyClause}; ${missed.join(' and ')}.`,
    ...(reasons.length === 0 ? {} : { description: reasons.join(' ') }),
    type: changed + unchanged > 0 ? 'warning' : 'error',
    duration: BULK_REPORT_DURATION_MS,
  };
}

/** The bulk tag's report: rows that already had the tag are said to have it, never counted as tagged. */
export function describeTagOutcome(outcome: DocumentBulkOutcome, tag: string): BulkReport {
  const already: AlreadyWording = {
    some: 'had it',
    all: `Every selected document already has the tag "${tag}"`,
  };
  if (outcome.failed.length === 0 && outcome.notSent.length === 0 && outcome.done.length > 0) {
    const changed = outcome.done.length;
    const unchanged = outcome.unchanged.length;
    return {
      title: `Tag "${tag}" added to ${String(changed)} ${documentsWord(changed)}${
        unchanged === 0 ? '' : `; ${String(unchanged)} already had it`
      }`,
      type: 'success',
    };
  }
  return describeBulkOutcome(outcome, `tagged "${tag}"`, already);
}
