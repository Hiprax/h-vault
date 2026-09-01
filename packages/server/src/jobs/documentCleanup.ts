import cron, { type ScheduledTask } from 'node-cron';
import mongoose, { Types } from 'mongoose';
import { createModuleLogger } from '../utils/logger.js';
import { config, storageConfigured } from '../config/index.js';
import { AuditLog } from '../models/AuditLog.js';
import { Document } from '../models/Document.js';
import { DocumentUpload } from '../models/DocumentUpload.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { getStorage, isStorageNotFound } from '../services/storage/index.js';
import { parseObjectKey } from '../utils/documentObjects.js';
import type { StorageProvider } from '../services/storage/types.js';

const logger = createModuleLogger('jobs/documentCleanup');

/**
 * The garbage collector for object storage — the only thing in this system that
 * reclaims bytes nothing in MongoDB can still name.
 *
 * ## Why it has to exist at all
 *
 * Every path that writes an object has a primary reclamation path beside it: a
 * purge deletes the object before the row, an account cascade sweeps the user's
 * whole prefix, a failed completion deletes what it just wrote. This job is the
 * backstop for the cases where that primary path did not finish, and there are
 * three genuinely different ones, which is why there are three sweeps rather than
 * one:
 *
 *   1. **Abandoned engine-side multipart uploads.** `document_uploads` carries a
 *      TTL index on `expiresAt`, and that index deletes the ROW and nothing else —
 *      not the parts already written, and not the engine's open multipart handle.
 *      By the time this sweep looks, the row that named them is gone, so it has to
 *      reason from the engine's own `Initiated` dates instead. That is exactly why
 *      the threshold is `DOCUMENT_UPLOAD_TTL_HOURS` plus an hour: the extra hour is
 *      the margin in which the TTL monitor is expected to have run.
 *   2. **Interrupted purges.** A permanent delete marks `purgePending`, deletes the
 *      object, then deletes the row. A crash or a storage failure between the
 *      marker and the row leaves a marker whose whole purpose is to be found here.
 *   3. **Orphaned objects.** Anything else: an object whose row was lost, or one an
 *      account erasure could not reach because storage was down while it committed.
 *
 * ## The rule every sweep is subordinate to
 *
 * A live document's object is never deleted. Not one in the trash, not one marked
 * `purgePending`, not one whose upload is still in flight. Deleting an object is
 * irreversible AND unrecoverable — the row holds the only wrapped copy of the key
 * that opens it, and documents are deliberately absent from backups — so every
 * test here is written so that the negative fails loudly, and every ambiguous case
 * in the code below resolves to LEAVING THE OBJECT ALONE. An orphan that survives
 * an extra hour costs storage; a live object deleted by mistake costs the user
 * their file, permanently.
 *
 * ## Two bounds worth knowing before reading a sweep
 *
 * `listMultipartUploads` returns ONE page in the engine's own order, and the port
 * exposes no key/upload marker, so sweep 1 can only ever see the head of that
 * listing. Claimed uploads at the head therefore shadow anything deeper. The shadow
 * is small by construction — a user may hold at most
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` open transfers, and within a user the
 * older ObjectId sorts first — so the "a backlog drains over successive runs" claim
 * the port makes holds only because the head does in fact drain. If that ever stops
 * being true, the fix is a marker on the port, not a bigger page here.
 *
 * Sweep 3 is the ONLY reclamation path for objects an account erasure could not
 * delete: `cascadeDelete`'s prefix sweep logs and swallows a storage failure
 * because the account is already erased, and its stated justification is that this
 * job finishes the job. Those objects have neither a `documents` row nor a
 * `document_uploads` row (both are deleted by userId first), so they satisfy every
 * condition below as soon as they are a day old.
 *
 * ## Why it does not run at all without storage
 *
 * There is no bucket to sweep and `getStorage()` would throw 503 into a cron tick
 * that has nobody to answer to. `startDocumentCleanupJob` therefore schedules
 * NOTHING on a deployment with no `S3_*` configured, rather than scheduling an
 * hourly tick whose only act is to notice it should not have run.
 */

/**
 * Long enough that a sweep of a thousand keys against a slow engine finishes
 * inside it, short enough that a wedged run is retried the same day.
 */
const DOCUMENT_CLEANUP_LOCK_TTL_MS = 15 * 60 * 1000;

/**
 * The margin added to `DOCUMENT_UPLOAD_TTL_HOURS` before an engine-side upload is
 * treated as abandoned. It is the window in which MongoDB's TTL monitor (which
 * runs every 60 seconds, and only deletes the staging ROW) is expected to have
 * caught up, so this sweep never races a row that is about to disappear.
 */
const ABANDONED_UPLOAD_GRACE_MS = 60 * 60 * 1000;

/**
 * How old an object must be before the orphan sweep will consider deleting it.
 *
 * This number is load-bearing in a way its size disguises, so it must never be
 * lowered: it is what makes the completion path's brief bare-object window safe.
 * `completeUpload` deletes the staging row before it inserts the `documents` row,
 * so for the length of one request an object exists that NEITHER collection names.
 * That window is milliseconds; a day is astronomically larger than it. Shrink this
 * to minutes and the sweep starts racing live completions.
 */
const ORPHAN_MIN_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * The orphan sweep's budget: how many keys it may EXAMINE in one run.
 *
 * A bound rather than a full listing because this runs against the whole bucket
 * across every account, and an unbounded walk on an hourly schedule is how one
 * large deployment turns a backstop into a load generator.
 */
const ORPHAN_SWEEP_MAX_KEYS_PER_RUN = 1_000;

/** One page of the orphan listing, so a run is a handful of requests, not one per key. */
const ORPHAN_SWEEP_PAGE_SIZE = 250;

/**
 * A hard ceiling on the listing requests one run may issue, and the reason it is
 * not simply `ORPHAN_SWEEP_MAX_KEYS_PER_RUN / ORPHAN_SWEEP_PAGE_SIZE`.
 *
 * The key budget alone does NOT bound this loop, because a page can come back
 * carrying no keys while still reporting that more follow — a listing is allowed to
 * return an empty page and a continuation token, and `ListObjectsV2` says nothing
 * that forbids it. On such a page the key budget does not move and neither does the
 * cursor, so a loop bounded only by keys would re-issue the same request for ever,
 * inside a lock, at whatever rate the engine answers. This ceiling is what makes
 * termination a property of the code rather than of the engine's good behaviour.
 *
 * Four pages is the ordinary run (a thousand keys at two hundred and fifty each), so
 * the number below is deliberately far above the normal case: it is a backstop, not
 * a second budget, and a run that reaches it has already been told something odd.
 */
const ORPHAN_SWEEP_MAX_PAGES_PER_RUN = 32;

/** How many `purgePending` rows one run will finish, and the page it reads them in. */
const PURGE_PENDING_MAX_PER_RUN = 1_000;
const PURGE_PENDING_PAGE_SIZE = 500;

/**
 * How many storage calls may fail BACK TO BACK before the run gives up.
 *
 * The account-cascade helper makes this argument for its own sweep and it is the
 * same argument here: an engine that refuses one delete is almost always refusing
 * all of them. Without a breaker the arithmetic is unforgiving — the S3 client is
 * pinned to a 5-second connect timeout and three attempts, so a thousand doomed
 * deletes is over four hours, which blows the fifteen-minute lock TTL, lets the
 * next tick start a second concurrent run, and buries the log in a thousand copies
 * of one message. Whatever is left is reclaimed on the next run, which is what a
 * backstop is for.
 *
 * The counter is shared across all three sweeps and reset by any success, so it
 * measures "the engine is down right now" rather than "this run has had a bad day".
 */
const MAX_CONSECUTIVE_STORAGE_FAILURES = 5;

/**
 * The prefix every object this system writes lives under (`u/<userId>/d/<id>`).
 *
 * Both listing sweeps are scoped to it so that an object some other tool put in
 * the bucket is never even considered — the sweep would refuse it anyway, because
 * its key does not parse, but not asking for it at all is cheaper and is one fewer
 * thing that has to stay true.
 */
const OBJECT_KEY_ROOT_PREFIX = 'u/';

/** Totals for one run's single log line, plus the run's circuit breaker. */
interface CleanupTotals {
  uploadsAborted: number;
  purgesFinished: number;
  orphansDeleted: number;
  keysExamined: number;
  failures: number;
  /** Reset by every storage call that succeeds; see {@link MAX_CONSECUTIVE_STORAGE_FAILURES}. */
  consecutiveFailures: number;
}

/** Records a storage failure against the breaker. */
function recordFailure(totals: CleanupTotals): void {
  totals.failures += 1;
  totals.consecutiveFailures += 1;
}

/** Whether the engine has refused often enough in a row to abandon this run. */
function engineIsRefusing(totals: CleanupTotals): boolean {
  return totals.consecutiveFailures >= MAX_CONSECUTIVE_STORAGE_FAILURES;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown error';
}

/**
 * Sweep 1 — abandon the engine-side multipart uploads that no staging row claims.
 *
 * Three properties, each of which the storage port explicitly warns about:
 *
 *   * The listing is ONE page in the ENGINE's order, which is by key and only then
 *     by initiation time. So this FILTERS on `initiated` and never breaks early: a
 *     sweep that stopped at the first upload younger than the threshold would leave
 *     older ones unreclaimed for ever. A backlog drains over successive hourly runs.
 *   * An upload whose `initiated` the engine did not report is LEFT ALONE. The
 *     field is optional in the port precisely so that "I cannot establish this
 *     upload's age" is representable, and an unknown age is not an old age.
 *   * The claim check keys on the staging row's `_id`, which IS the document id the
 *     object key names, and is therefore MongoDB's own primary index. Keying on
 *     `s3UploadId` — the obvious choice, since that is the value being compared —
 *     would be a collection scan every hour, because that field is deliberately
 *     unindexed.
 *
 * A 404 from the abort is success, not failure: the engine has already forgotten
 * the upload. That case is routine rather than exotic, because a lock whose TTL
 * expires mid-run lets the next tick sweep the same candidates.
 */
async function abortAbandonedUploads(
  storage: StorageProvider,
  now: Date,
  totals: CleanupTotals,
): Promise<void> {
  const ttlMs = config.DOCUMENT_UPLOAD_TTL_HOURS * 60 * 60 * 1000;
  const abandonedBefore = now.getTime() - ttlMs - ABANDONED_UPLOAD_GRACE_MS;

  const uploads = await storage.listMultipartUploads(OBJECT_KEY_ROOT_PREFIX);

  // FILTER, never break, and never `?? new Date(0)`: an upload whose `initiated`
  // the engine did not report has an age this sweep cannot establish, and an
  // unknown age is not an old age.
  const stale = uploads.filter(
    (upload) => upload.initiated !== undefined && upload.initiated.getTime() < abandonedBefore,
  );
  // A key this codebase did not write names no document, so nothing can prove the
  // upload is unclaimed and it is left where it is.
  const candidates = stale.flatMap((upload) => {
    const parsed = parseObjectKey(upload.key);
    return parsed === null ? [] : [{ ...upload, documentId: parsed.documentId }];
  });
  if (candidates.length === 0) return;

  const claiming = await DocumentUpload.find({
    _id: { $in: candidates.map((candidate) => candidate.documentId) },
  })
    .select('_id')
    .lean();
  const claimed = new Set(claiming.map((row) => String(row._id)));

  for (const candidate of candidates) {
    if (claimed.has(candidate.documentId)) continue;
    if (engineIsRefusing(totals)) return;
    try {
      await storage.abortMultipartUpload(candidate.key, candidate.uploadId);
      totals.uploadsAborted += 1;
      totals.consecutiveFailures = 0;
    } catch (error: unknown) {
      if (isStorageNotFound(error)) {
        // The engine has already forgotten this upload, which is the outcome this
        // sweep wanted. Routine rather than exotic: a lock that expires mid-run
        // lets the next tick reach the same candidates.
        totals.uploadsAborted += 1;
        totals.consecutiveFailures = 0;
        continue;
      }
      recordFailure(totals);
      logger.error(
        `Document cleanup could not abort abandoned upload ${candidate.uploadId} ` +
          `for ${candidate.key}: ${describe(error)}`,
      );
    }
  }
}

/**
 * Sweep 2 — finish the purges that were interrupted after their marker landed.
 *
 * Deliberately NOT a compare-and-set, unlike the three user-facing purge paths.
 * They mark the row as part of claiming it against a concurrent restore; here the
 * marker is already committed and nothing in the system ever clears it back
 * (`restoreDocument` requires `purgePending: null`, so a marked row can no longer
 * be recovered). Re-claiming a row this job already owns would be a compare against
 * an invariant that holds, which is dead code wearing the costume of caution.
 *
 * It pages on `_id > lastId` with the cursor advanced BEFORE the work, for the
 * reason the trash cron states at the same loop: a row whose object delete fails is
 * deliberately left behind for the next run, so it still matches the predicate, and
 * a loop that re-read the predicate would return the same failing row for ever.
 *
 * The audit row closes a real gap rather than decorating the log. The user-facing
 * purge paths write their audit entry AFTER deleting the row, so a process that
 * died between the two destroyed a document and recorded nothing. This is the run
 * that actually destroys it, so this is where that record belongs.
 */
async function finishPendingPurges(storage: StorageProvider, totals: CleanupTotals): Promise<void> {
  let lastId: mongoose.Types.ObjectId | undefined;
  let examined = 0;

  while (examined < PURGE_PENDING_MAX_PER_RUN && !engineIsRefusing(totals)) {
    // Scoped to the PAGE, not to the run. See the insert at the end of this loop.
    const finishedByUser = new Map<string, number>();
    const pending = { purgePending: true };
    const page = await Document.find(
      lastId === undefined ? pending : { ...pending, _id: { $gt: lastId } },
    )
      .select('_id userId objectKey')
      .sort({ _id: 1 })
      .limit(Math.min(PURGE_PENDING_PAGE_SIZE, PURGE_PENDING_MAX_PER_RUN - examined))
      .lean();

    if (page.length === 0) break;

    for (const row of page) {
      lastId = row._id;
      examined += 1;
      if (engineIsRefusing(totals)) break;
      try {
        await storage.deleteObject(row.objectKey);
        totals.consecutiveFailures = 0;
        // `userId` beside `_id`, the same defense-in-depth every other delete on
        // this collection applies. The engine's own count, never a bare `+= 1`: a
        // row removed by a concurrent request is not this run's purge to claim.
        const { deletedCount } = await Document.deleteOne({ _id: row._id, userId: row.userId });
        if (deletedCount > 0) {
          const userId = String(row.userId);
          finishedByUser.set(userId, (finishedByUser.get(userId) ?? 0) + deletedCount);
          totals.purgesFinished += deletedCount;
        }
      } catch (error: unknown) {
        recordFailure(totals);
        logger.error(
          `Document cleanup could not finish the interrupted purge of document ` +
            `${String(row._id)}; it keeps purgePending for the next run: ${describe(error)}`,
        );
      }
    }

    // Written per PAGE, never once at the end, for the reason the sibling cron
    // states at its own loop: a purge that HAPPENED must stay audited even if a
    // later page does not finish. Accumulating across the whole run would mean a
    // throw from the next page's read — or from `insertMany` itself — erasing the
    // record of up to a full page of documents this job had already destroyed,
    // which is precisely the gap this audit row exists to close.
    if (finishedByUser.size > 0) {
      await AuditLog.insertMany(
        Array.from(finishedByUser.entries()).map(([userId, documentCount]) => ({
          userId,
          action: 'document_purge' as const,
          metadata: { action: 'gc_finish_interrupted', documentCount },
          ipAddress: 'system',
          userAgent: 'system/document-cleanup-job',
          timestamp: new Date(),
        })),
      );
    }
  }
}

/**
 * Sweep 3 — delete objects that no row can name, and nothing else.
 *
 * An object is deleted only when ALL of these hold, and every one of them is a
 * reason to LEAVE it when it does not:
 *
 *   1. its key parses as `u/<userId>/d/<documentId>` — a key this code did not
 *      write names no document, so nothing can prove it is an orphan;
 *   2. the engine reported a `LastModified` and it is older than
 *      {@link ORPHAN_MIN_AGE_MS} — an object whose age is unknown is one this sweep
 *      must not touch, and a young one may belong to a completion in flight;
 *   3. NO `documents` row carries that `_id`, **in any state**. The lookup is by id
 *      alone, with no `deletedAt` or `purgePending` filter, and that absence is the
 *      single most important line in this file: a document sitting in the trash is
 *      recoverable for `TRASH_AUTO_PURGE_DAYS` and is older than a day within
 *      hours, so a lookup that excluded trashed rows would delete the bytes of
 *      every trashed document the morning after it was trashed;
 *   4. NO `document_uploads` row carries that `_id` either, so a transfer in flight
 *      keeps the parts it has already stored;
 *   5. the document id's OWN timestamp — it is an `ObjectId` minted when the
 *      transfer was initiated — is older than `DOCUMENT_UPLOAD_TTL_HOURS` plus the
 *      same hour sweep 1 uses.
 *
 * ## Condition (5) is not belt and braces; without it this job destroys files
 *
 * `completeUpload` deletes the staging row BEFORE it inserts the `documents` row,
 * so for the length of one request an object exists that neither collection names —
 * conditions (3) and (4) are both satisfied inside that window. Condition (2) is
 * what is supposed to make the window unreachable, and for a MULTIPART transfer it
 * does, because the object only comes into existence at completion. But a
 * SINGLE-SEGMENT transfer is stored with `PutObject` straight to the final key at
 * PART time, so its `LastModified` is when the byte arrived, not when the transfer
 * completed. With `DOCUMENT_UPLOAD_TTL_HOURS` raised above 24 (it is configurable
 * to 168), a client that uploads its one part and completes thirty hours later
 * presents a day-old object during that window, and a sweep landing in it deletes
 * the bytes of a document the user is about to see listed. The row survives holding
 * the only wrapped key, pointing at nothing: silent, permanent, and shaped exactly
 * like corruption.
 *
 * Condition (5) closes it deterministically rather than probabilistically, using
 * data already in hand. The id IS an `ObjectId` minted at init, so it carries the
 * transfer's start time; and a completion is refused once the staging row's
 * `expiresAt` — set at init to start plus the TTL — has passed. So past
 * `start + TTL + 1h` no completion for that key can ever succeed again, and the
 * two reads above are racing nothing at all.
 *
 * ## Where it resumes, and why it is a key rather than a token
 *
 * A run examines at most {@link ORPHAN_SWEEP_MAX_KEYS_PER_RUN} keys, so on a bucket
 * holding more than that a run cannot see the whole thing. Restarting from the
 * beginning every hour would mean the same first thousand keys for ever, and an
 * orphan sitting at position twenty thousand would never be reclaimed at all —
 * a bound that never advances is not a bound, it is a blind spot.
 *
 * So the caller carries the last key examined into the next run and passes it as
 * `startAfter`, wrapping back to the beginning of the bucket only once a listing
 * reaches its end. `startAfter` takes an ordinary key rather than the engine's
 * opaque continuation token, which is what makes resuming an hour later legitimate:
 * a token is documented as obfuscated, with nothing said about how long one remains
 * meaningful, whereas the key is a string this codebase produced itself and the
 * conformance suite pins both implementations against it.
 *
 * Within one run the fallback is the other way round: if a page comes back empty
 * while reporting that more follows, there is no key to resume after, so that ONE
 * step uses the engine's continuation token, which is precisely what a token is for
 * inside a single listing. {@link ORPHAN_SWEEP_MAX_PAGES_PER_RUN} bounds the run
 * regardless, so termination never depends on the engine behaving.
 *
 * The cursor lives in the closure `startDocumentCleanupJob` creates, so it survives
 * every tick of one process and starts over after a restart. That is the accepted
 * limitation: the sweep is a backstop whose work is measured in objects per day,
 * and a deployment that restarts faster than it can walk its own bucket has the
 * primary reclamation paths still doing the work.
 */
async function sweepOrphanedObjects(
  storage: StorageProvider,
  now: Date,
  resumeAfter: string | undefined,
  totals: CleanupTotals,
): Promise<string | undefined> {
  const orphanedBefore = now.getTime() - ORPHAN_MIN_AGE_MS;
  // The instant past which NO completion for a transfer started then can still
  // succeed. See condition (4) in this function's note.
  const completableBefore =
    now.getTime() - config.DOCUMENT_UPLOAD_TTL_HOURS * 60 * 60 * 1000 - ABANDONED_UPLOAD_GRACE_MS;
  let cursor = resumeAfter;
  /**
   * Set only after a page came back empty while reporting that more follows. There
   * is no key to resume after in that case, so this run falls back to the engine's
   * own token, which is exactly what a continuation token is for INSIDE one
   * listing. It is never carried across runs — that is the durable `cursor`'s job,
   * and a token is not durable.
   */
  let withinRunToken: string | undefined;
  let pagesRead = 0;

  while (
    totals.keysExamined < ORPHAN_SWEEP_MAX_KEYS_PER_RUN &&
    pagesRead < ORPHAN_SWEEP_MAX_PAGES_PER_RUN &&
    !engineIsRefusing(totals)
  ) {
    pagesRead += 1;
    const remaining = ORPHAN_SWEEP_MAX_KEYS_PER_RUN - totals.keysExamined;
    const page = await storage.listObjects(OBJECT_KEY_ROOT_PREFIX, {
      maxKeys: Math.min(ORPHAN_SWEEP_PAGE_SIZE, remaining),
      ...(withinRunToken !== undefined
        ? { continuationToken: withinRunToken }
        : cursor === undefined
          ? {}
          : { startAfter: cursor }),
    });
    withinRunToken = undefined;

    const candidates: { key: string; documentId: string }[] = [];
    for (const object of page.objects) {
      totals.keysExamined += 1;
      cursor = object.key;
      const parsed = parseObjectKey(object.key);
      // A key this codebase did not write names no document, so nothing here can
      // prove it is an orphan.
      if (parsed === null) continue;
      // An object whose age the engine did not report is one this sweep must not
      // touch. The field is optional in the port for exactly this case.
      if (object.lastModified === undefined) continue;
      if (object.lastModified.getTime() >= orphanedBefore) continue;
      if (new Types.ObjectId(parsed.documentId).getTimestamp().getTime() >= completableBefore)
        continue;
      candidates.push({ key: object.key, documentId: parsed.documentId });
    }

    if (candidates.length > 0) {
      const ids = candidates.map((candidate) => candidate.documentId);
      // No `deletedAt` and no `purgePending` filter on either read. See (3) above.
      const [documents, uploads] = await Promise.all([
        Document.find({ _id: { $in: ids } })
          .select('_id')
          .lean(),
        DocumentUpload.find({ _id: { $in: ids } })
          .select('_id')
          .lean(),
      ]);
      const named = new Set([...documents, ...uploads].map((row) => String(row._id)));

      for (const candidate of candidates) {
        if (named.has(candidate.documentId)) continue;
        if (engineIsRefusing(totals)) break;
        try {
          await storage.deleteObject(candidate.key);
          totals.orphansDeleted += 1;
          totals.consecutiveFailures = 0;
        } catch (error: unknown) {
          recordFailure(totals);
          logger.error(
            `Document cleanup could not delete orphaned object ${candidate.key}: ${describe(error)}`,
          );
        }
      }
    }

    // The end of the listing, so the next run starts the bucket over. Deliberately
    // NOT a wrap inside this run: continuing here would spend a second budget on
    // keys this run already walked past.
    if (page.nextContinuationToken === undefined) return undefined;
    if (page.objects.length === 0) {
      // More to come, but nothing here to resume after. See `withinRunToken`.
      withinRunToken = page.nextContinuationToken;
    }
  }

  return cursor;
}

/**
 * One run: take the lock, sweep, release. Separated from the cron registration so
 * the whole body is one testable unit and the callback below is three lines.
 *
 * The lock is acquired INSIDE the try and released only `if (lockId)`, so a run
 * that never got the lock cannot delete the holder's. The release has its own
 * try/catch for the reason the other crons state: a transient failure there would
 * reject the tracked promise, and `trackJob`'s bookkeeping chain would turn that
 * into an unhandled rejection that takes the whole API server down.
 */
async function runDocumentCleanup(carriedCursor: string | undefined): Promise<string | undefined> {
  let lockId: string | null = null;
  let cursor = carriedCursor;

  try {
    lockId = await acquireJobLock('document-cleanup', DOCUMENT_CLEANUP_LOCK_TTL_MS);
    if (!lockId) {
      logger.info('Document cleanup skipped: another instance holds the lock');
      return cursor;
    }

    const storage = getStorage();
    const now = new Date();
    const totals: CleanupTotals = {
      uploadsAborted: 0,
      purgesFinished: 0,
      orphansDeleted: 0,
      keysExamined: 0,
      failures: 0,
      consecutiveFailures: 0,
    };

    await abortAbandonedUploads(storage, now, totals);
    await finishPendingPurges(storage, totals);
    cursor = await sweepOrphanedObjects(storage, now, cursor, totals);

    if (
      totals.uploadsAborted > 0 ||
      totals.purgesFinished > 0 ||
      totals.orphansDeleted > 0 ||
      totals.failures > 0
    ) {
      logger.info(
        `Document cleanup complete: aborted ${String(totals.uploadsAborted)} abandoned upload(s), ` +
          `finished ${String(totals.purgesFinished)} interrupted purge(s), ` +
          `deleted ${String(totals.orphansDeleted)} orphaned object(s) from ` +
          `${String(totals.keysExamined)} key(s) examined, ${String(totals.failures)} failure(s)`,
      );
    }
  } catch (error: unknown) {
    logger.error(`Document cleanup job failed: ${describe(error)}`);
  } finally {
    if (lockId) {
      try {
        await releaseJobLock('document-cleanup', lockId);
      } catch (releaseErr: unknown) {
        logger.error(`Failed to release document-cleanup lock: ${describe(releaseErr)}`);
      }
    }
  }

  return cursor;
}

/**
 * Schedule the collector, or nothing at all when the operator configured no object
 * storage.
 *
 * Returning `null` rather than a task whose body no-ops is the honest shape: the
 * document store is off on that deployment, there is no bucket, and a cron tick
 * that exists only to notice that is a lock acquisition an hour, for ever.
 * `server.ts` puts the result straight into the array `createGracefulShutdown`
 * receives, which already accepts `null` for exactly this reason (a non-primary
 * worker starts none of the crons).
 *
 * The orphan cursor lives here, in the closure, rather than at module scope: one
 * process schedules the job once, so the ticks share it, while a test that calls
 * this function twice gets two independent collectors instead of one whose
 * behaviour depends on which test ran first.
 */
export function startDocumentCleanupJob(): ScheduledTask | null {
  if (!storageConfigured) {
    logger.info('Document cleanup job not scheduled: object storage is not configured');
    return null;
  }

  let orphanCursor: string | undefined;

  // Half past the hour, deliberately not on it: the backup scheduler runs at
  // :00 and holds a 30-minute lock, and stacking two hourly jobs on the same
  // instant on a single-threaded process buys nothing.
  const task = cron.schedule(
    '30 * * * *',
    () => {
      const jobPromise = runDocumentCleanup(orphanCursor).then((cursor) => {
        orphanCursor = cursor;
      });
      trackJob(jobPromise);
      return jobPromise;
    },
    { timezone: 'UTC' },
  );

  logger.info('Document cleanup job scheduled (hourly at :30 UTC)');
  return task;
}
