import mongoose from 'mongoose';
import { maskEmail } from '@hvault/shared';
import { createModuleLogger } from './logger.js';
import { storageConfigured } from '../config/index.js';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { AuditLog } from '../models/AuditLog.js';
import { BackupLog } from '../models/BackupLog.js';
import { Document } from '../models/Document.js';
import { DocumentUpload } from '../models/DocumentUpload.js';
import { DeviceProof } from '../models/DeviceProof.js';
import { Invitation } from '../models/Invitation.js';
import { Challenge } from '../models/Challenge.js';
import { createAuditLog } from '../services/auditService.js';
import { getStorage } from '../services/storage/index.js';
import { userObjectPrefix } from './documentObjects.js';
import { revokeTrustedDevices } from './trustedDevices.js';
import { revokeDeviceProofs } from './deviceProofs.js';
import { supportsTransactions } from './transactionSupport.js';

const logger = createModuleLogger('cascade-delete');

/**
 * Erase every stored object the user owns, AFTER their rows are gone.
 *
 * ## Why it runs last, and why that order is not negotiable
 *
 * A document row holds the only wrapped copy of the key that decrypts its object.
 * Deleting the rows first therefore makes any object that survives this sweep
 * cryptographically unrecoverable — ciphertext under a key that exists nowhere, on
 * the server or in a browser or in a backup (documents are deliberately absent from
 * the backup payload). Sweeping first and then failing to delete the rows would be
 * the inverse and much worse: rows pointing at objects that no longer exist.
 *
 * ## Why it lists by PREFIX instead of walking the rows it just deleted
 *
 * `u/<userId>/` covers every object the account can own, including the object of a
 * partially written upload whose staging row was already removed above, and
 * including one whose row was lost to an earlier interrupted deletion. A per-row
 * walk would reach only the documents that happened to still have a row.
 *
 * ## Why it can never throw
 *
 * It is reached only AFTER the deletion has committed, and the failure handling of
 * both cascade paths is to re-set `deletionPending` so the zombie loop retries. That
 * flag lives on a user row this function has already watched disappear, so letting a
 * storage failure escape would make `cascadeDeleteUser` answer `false` for an
 * erasure that fully succeeded, and the retry would be attempted for ever against a
 * user that is not there. So every failure is logged and swallowed: the account IS
 * erased, and the residue is bounded — the garbage collector's orphan sweep deletes
 * an object with no `documents` row, which is exactly what these are.
 *
 * The same argument is why the sweep stops at the first failing call rather than
 * pressing on key by key. A storage engine that refuses one delete is almost always
 * refusing all of them, the collector reclaims whatever is left either way, and the
 * alternative is thousands of doomed requests inside an account deletion.
 *
 * Storage may be unconfigured — the document store is optional and this helper is
 * reached by `tokenCleanup`'s zombie loop on every deployment — in which case there
 * is nothing to sweep and `getStorage()` would throw 503 at a caller that has no way
 * to answer it.
 */
async function eraseUserObjects(userId: string): Promise<void> {
  if (!storageConfigured) return;

  let deleted = 0;
  let failingKey: string | undefined;
  try {
    const storage = getStorage();
    const prefix = userObjectPrefix(userId);
    let continuationToken: string | undefined;
    do {
      // Cleared per page, so a listing that fails on the SECOND page reports the
      // listing rather than naming a key from the first page that was in fact
      // deleted successfully.
      failingKey = undefined;
      const page = await storage.listObjects(
        prefix,
        continuationToken === undefined ? undefined : { continuationToken },
      );
      for (const object of page.objects) {
        // Held so the failure log can name the key that stopped the sweep, which
        // is the one datum an operator needs to reclaim it by hand.
        failingKey = object.key;
        await storage.deleteObject(object.key);
        deleted += 1;
      }
      // The listing is the caller's to paginate (see `StorageProvider.listObjects`):
      // one user may own up to `MAX_DOCUMENTS_PER_USER` objects against an engine
      // page of a thousand, so reading a single page would silently leave the rest
      // of the account's ciphertext in the bucket.
      continuationToken = page.nextContinuationToken;
    } while (continuationToken !== undefined);

    if (deleted > 0) {
      logger.info(`Cascade delete removed ${String(deleted)} stored object(s) for user ${userId}`);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    logger.error(
      `Cascade delete could not erase every stored object for user ${userId} ` +
        `(${String(deleted)} removed, stopped at ${failingKey ?? 'the prefix listing'}): ${msg}`,
    );
  }
}

interface CascadeDeleteOptions {
  userId: mongoose.Types.ObjectId | string;
  userEmail: string;
  /** IP address for audit log */
  ip: string;
  /** User agent for audit log */
  userAgent: string;
  /**
   * The action of the system row recording the erasure: the owner's own request,
   * the zombie loop finishing an interrupted one, or the reaper erasing an account
   * that was never verified (F-21).
   */
  auditAction: 'account_delete' | 'deletion_cleanup' | 'unverified_account_reaped';
}

/** Rows per batch when erasing the bulky collections. */
const CASCADE_BATCH_SIZE = 1_000;

/**
 * The per-account collections that can grow large, erased in batches BEFORE the
 * final step: the audit log (up to its caps, plus a year of security rows), the
 * vault's items and folders, both document collections, the refresh tokens (a
 * spent token stays behind as a reuse-detection tombstone for seven days, one per
 * refresh), the backup log (a year of it), the device proofs, the invitations
 * the account minted and its second-factor challenges (one per proven password,
 * each gone five minutes later by TTL, but nothing stops many sign-ins inside
 * those five minutes).
 *
 * Nothing here is implicit: a collection that is neither here nor in
 * {@link sweepRemainingRows} is never erased, whatever else the application does
 * with it, so a phase that adds a per-account collection adds it to BOTH.
 */
const BATCHED_TENANT_MODELS = [
  AuditLog,
  VaultItem,
  Folder,
  Document,
  DocumentUpload,
  RefreshToken,
  BackupLog,
  DeviceProof,
  Invitation,
  Challenge,
] as const;

/**
 * Erases every row of {@link BATCHED_TENANT_MODELS} the account owns, a thousand
 * at a time: read a page of ids, delete exactly those (with `userId` in the
 * filter as well), repeat until a short page. Each batch is its own small,
 * repeatable `deleteMany`, so an account of any size costs many short operations
 * rather than one that grows with its history, and a batch that already ran is a
 * no-op when the cascade is run again.
 */
async function eraseInBatches(userId: string): Promise<void> {
  const owner = new mongoose.Types.ObjectId(userId);
  // The account's first write, and idempotent: whoever called, the account is
  // marked as being erased BEFORE any of its data goes, so a failure anywhere
  // below leaves an account that cannot be served and that the zombie loop will
  // finish. Callers set it too; the guarantee must not rest on their discipline.
  await User.updateOne({ _id: owner }, { $set: { deletionPending: true } });
  for (const model of BATCHED_TENANT_MODELS) {
    let erased = 0;
    let stalled = false;
    for (;;) {
      // From the PRIMARY: a lagging secondary (a URI asking for
      // `secondaryPreferred`) would hand this batch the ids the last one already
      // deleted, and two such batches in a row trip the stall guard below.
      const batch = await model.collection
        .find({ userId: owner }, { projection: { _id: 1 }, readPreference: 'primary' })
        .limit(CASCADE_BATCH_SIZE)
        .toArray();
      if (batch.length === 0) break;
      // Hinted to `_id`: a thousand point lookups. Left to the planner, the
      // account's `userId` index wins the trial (its first entries are exactly
      // this batch) and the delete then walks every remaining row of the account
      // to finish, which made each batch cost what was left and the whole erasure
      // quadratic in the account's size (measured: 250,000 audit rows took 77 s).
      const { deletedCount } = await model.collection.deleteMany(
        { userId: owner, _id: { $in: batch.map((row) => row._id) } },
        { hint: { _id: 1 } },
      );
      erased += deletedCount;
      if (batch.length < CASCADE_BATCH_SIZE) break;
      // A full batch of which nothing was deleted: once, it is another run of this
      // erasure (the request and the zombie loop can overlap) that removed the rows
      // between the read and the delete, and the next read moves on. Twice in a row,
      // it is a batch that cannot be removed and would be read again for ever, so the
      // erasure refuses: the account stays pending and the next run tries again.
      if (deletedCount === 0) {
        if (stalled) throw new Error(`no progress erasing ${model.modelName} rows`);
        stalled = true;
      } else {
        stalled = false;
      }
    }
    if (erased > 0) {
      logger.info(
        `Cascade delete erased ${String(erased)} ${model.modelName} row(s) for ${userId}`,
      );
    }
  }
}

/**
 * The final step's erasure: one `deleteMany` per collection, for the rows written
 * while the batches ran (a request authenticated before `deletionPending` was set
 * can still be in flight), plus the trusted devices, which are capped at a handful
 * and so never needed batching. Normally every one of these removes nothing.
 *
 * And every invitation that NAMES the erased address. An invitation belongs to its
 * inviter, so the batches (by `userId`) never reach the one this account registered
 * with, or one still open for it, and each carries the address in clear until it
 * expires: an erasure that left them would not have erased the address.
 */
async function sweepRemainingRows(
  userId: string,
  userEmail: string,
  session?: mongoose.ClientSession,
): Promise<void> {
  const options = session ? { session } : {};
  await AuditLog.deleteMany({ userId }, options);
  await VaultItem.deleteMany({ userId }, options);
  await Folder.deleteMany({ userId }, options);
  await Document.deleteMany({ userId }, options);
  await DocumentUpload.deleteMany({ userId }, options);
  await RefreshToken.deleteMany({ userId }, options);
  await BackupLog.deleteMany({ userId }, options);
  // The invitations this account minted (`userId` is the inviter). One it did not
  // spend dies with it: an erased account vouches for nobody.
  await Invitation.deleteMany({ userId }, options);
  await Invitation.deleteMany({ email: userEmail.trim().toLowerCase() }, options);
  // A challenge minted by a sign-in that proved the password while the batches ran.
  await Challenge.deleteMany({ userId }, options);
  await revokeDeviceProofs(userId, options);
  await revokeTrustedDevices(userId, session);
}

/**
 * The row that outlives the account, recording that it was erased. System-scoped
 * (`userId: null`), so nothing that reads an account's log ever returns it, and it
 * names the account by id with the address MASKED: an erasure that kept the
 * address in clear for a year would not have erased it. The field is called
 * `maskedEmail` because it is not an address; records written before it existed
 * carried `deletedEmail` in clear and are rewritten by migration v2.
 */
function deletionRecord(userId: string, userEmail: string): Record<string, unknown> {
  return { deletedUserId: userId, maskedEmail: maskEmail(userEmail) };
}

/**
 * Erase everything an account owns: its rows, then its stored objects.
 *
 * ## Idempotent forward-only erasure, not an all-or-nothing transaction
 *
 * An account's history can be large — a year of audit rows, thousands of items,
 * a refresh tombstone per refresh — and a single transaction sized by it is one
 * MongoDB aborts at its lifetime limit, which would leave the account impossible
 * to delete. So the bulky collections are erased in small batches FIRST
 * ({@link eraseInBatches}), and the final step (a transaction when the topology
 * supports one) holds only a sweep for stragglers, the trusted devices and the
 * user row itself.
 *
 * That is safe because `deletionPending` is set BEFORE any data goes — by both
 * callers (`userController.deleteAccount`, and the `tokenCleanup` zombie loop,
 * which only ever finds users that carry it) and again as the cascade's own
 * first write, so the guarantee does not rest on them — and a pending account can do
 * nothing: sign-in answers it exactly as a wrong password, and the access-token
 * check and the refresh both refuse it. A failure anywhere therefore leaves a
 * half-erased account that cannot be used, still flagged, and the zombie loop
 * runs the whole cascade again from the top — every batch that already finished
 * is a no-op. The user row is removed only in the final step, so until the
 * erasure completes the address cannot be registered again either.
 *
 * The system row ({@link deletionRecord}) is written only by the run that
 * actually removes the user row, so a re-run over an erased account writes
 * nothing at all.
 *
 * Rows first, then the user's stored objects (see {@link eraseUserObjects}).
 *
 * Returns true if the ROW deletion completed successfully. The object sweep is
 * best-effort by design and never changes that answer.
 */
export async function cascadeDeleteUser(opts: CascadeDeleteOptions): Promise<boolean> {
  const { userId, userEmail, ip, userAgent, auditAction } = opts;
  const userIdStr = typeof userId === 'string' ? userId : userId.toString();

  const erased = supportsTransactions()
    ? await cascadeDeleteTransactional(userIdStr, userEmail, ip, userAgent, auditAction)
    : await cascadeDeleteSequential(userIdStr, userEmail, ip, userAgent, auditAction);

  // The object sweep is hoisted HERE, above both paths, rather than repeated inside
  // each of them, and that placement carries three properties worth stating:
  //
  //   * it cannot flip the answer. Both branch functions own a try/catch whose
  //     failure handling re-sets `deletionPending` on a user row that this point in
  //     the code has already watched disappear; a sweep inside either of them could
  //     turn a committed erasure into `false` and make the zombie loop retry a user
  //     that is not there, for ever. Out here there is no catch to fall into, and
  //     `eraseUserObjects` swallows its own failures as well.
  //   * it runs only when the erasure finished. A cascade that failed part-way may
  //     already have erased some `documents` rows (the batches are forward-only),
  //     but their objects stay until a run completes: an object is never deleted
  //     while a row that names it can still exist, and one whose row is gone is
  //     reclaimed by the re-run's sweep or by the collector's orphan sweep.
  //   * it runs on BOTH paths from one call site, so a third path (or a caller that
  //     stops going through the transactional branch) cannot quietly lose it.
  if (erased) {
    await eraseUserObjects(userIdStr);
  }
  return erased;
}

/**
 * Re-asserts `deletionPending` after a failed run, so the cleanup job retries.
 *
 * Both callers leave the flag SET while the cascade runs — neither clears it
 * before the erasure is durable — so this write is normally a no-op. It is kept
 * as a defensive backstop: it is the one place that can restore the retry signal
 * if any future caller leaves the flag unset. Best-effort — if the re-set itself
 * fails the user requires manual intervention, so it is logged prominently.
 */
async function reassertDeletionPending(userId: string, branch: string): Promise<void> {
  try {
    await User.updateOne({ _id: userId }, { $set: { deletionPending: true } });
  } catch {
    logger.error(`Failed to re-set deletionPending for user ${userId} (${branch} path)`);
  }
}

/**
 * Transactional cascade delete: the batches, then ONE small transaction holding
 * the straggler sweep, the user row and the system row, which therefore commit
 * or abort together.
 *
 * Exported so the transactional code path (in particular, the
 * `deletionPending` re-set on failure) can be unit-tested against a standalone
 * in-memory MongoDB. The standalone fallback is exercised via the public
 * `cascadeDeleteUser` entry point.
 *
 * It deletes ROWS ONLY and deliberately does NOT sweep the user's stored objects:
 * that step belongs to `cascadeDeleteUser`, which owns it for both branches
 * precisely so it cannot sit inside the `catch` below. Production code must
 * therefore always go through `cascadeDeleteUser`; calling this directly erases
 * an account and leaves its ciphertext in the bucket.
 *
 * @internal
 */
export async function cascadeDeleteTransactional(
  userId: string,
  userEmail: string,
  ip: string,
  userAgent: string,
  auditAction: CascadeDeleteOptions['auditAction'],
): Promise<boolean> {
  let session: mongoose.ClientSession | undefined;
  try {
    await eraseInBatches(userId);

    // Opened only now, so the transaction's lifetime covers the small remainder
    // and never the batches.
    const txn = await mongoose.startSession();
    session = txn;
    await txn.withTransaction(async () => {
      await sweepRemainingRows(userId, userEmail, txn);
      const removed = await User.findByIdAndDelete(userId, { session: txn });
      if (removed) {
        // Inside the same session, so the record commits or aborts together with
        // the deletion it records.
        await createAuditLog(null, auditAction, deletionRecord(userId, userEmail), ip, userAgent, {
          session: txn,
        });
      }
    });
    logger.info(`Cascade delete (transactional) completed for user ${userId}`);
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    logger.error(`Cascade delete (transactional) failed for user ${userId}: ${msg}`);
    await reassertDeletionPending(userId, 'transactional');
    return false;
  } finally {
    await session?.endSession();
  }
}

/**
 * Sequential cascade delete — no transaction: the batches, the straggler sweep,
 * then the user row. On failure, re-sets `deletionPending: true` so the next
 * cleanup cycle can retry.
 */
async function cascadeDeleteSequential(
  userId: string,
  userEmail: string,
  ip: string,
  userAgent: string,
  auditAction: CascadeDeleteOptions['auditAction'],
): Promise<boolean> {
  try {
    await eraseInBatches(userId);
    await sweepRemainingRows(userId, userEmail);
    const removed = await User.findByIdAndDelete(userId);
    if (removed) {
      await createAuditLog(null, auditAction, deletionRecord(userId, userEmail), ip, userAgent);
    }

    logger.info(`Cascade delete (sequential) completed for user ${userId}`);
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    logger.error(`Cascade delete (sequential) failed for user ${userId}: ${msg}`);
    await reassertDeletionPending(userId, 'sequential');
    return false;
  }
}
