import mongoose from 'mongoose';
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
import { createAuditLog } from '../services/auditService.js';
import { getStorage } from '../services/storage/index.js';
import { userObjectPrefix } from './documentObjects.js';
import { revokeTrustedDevices } from './trustedDevices.js';
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
  /** Audit action name for the deletion log entry */
  auditAction: 'account_delete' | 'deletion_cleanup';
}

/**
 * Delete all data associated with a user in the correct order.
 * Runs inside a MongoDB transaction when the topology supports it.
 * Falls back to sequential deletes with re-set of `deletionPending` on failure.
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
  //   * it runs only when the rows are actually gone. A cascade that failed leaves
  //     the `documents` rows in place, and deleting their objects then would strand
  //     rows pointing at nothing — the one ordering this feature must never produce.
  //   * it runs on BOTH paths from one call site, so a third path (or a caller that
  //     stops going through the transactional branch) cannot quietly lose it.
  if (erased) {
    await eraseUserObjects(userIdStr);
  }
  return erased;
}

/**
 * Transactional cascade delete — all-or-nothing via MongoDB session.
 *
 * Exported so the transactional code path (in particular, the
 * `deletionPending` re-set on transaction abort) can be unit-tested against a
 * standalone in-memory MongoDB. The standalone fallback is exercised via the
 * public `cascadeDeleteUser` entry point.
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
  auditAction: string,
): Promise<boolean> {
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      await VaultItem.deleteMany({ userId }, { session });
      await Folder.deleteMany({ userId }, { session });
      await RefreshToken.deleteMany({ userId }, { session });
      await revokeTrustedDevices(userId, session);
      await BackupLog.deleteMany({ userId }, { session });
      // Nothing in this helper is implicit: a collection that is not named here is
      // simply never erased, whatever else the application does with it. Both
      // document collections are therefore stated, inside the session, so they
      // commit or abort with the rest.
      await Document.deleteMany({ userId }, { session });
      await DocumentUpload.deleteMany({ userId }, { session });

      // Create the system-scoped audit log (userId: null) inside the same
      // session so it commits or aborts together with the cascade deletes.
      // Without forwarding the session, the audit row would persist even if
      // the transaction later aborted, breaking the "logged events reflect
      // committed state" invariant.
      await createAuditLog(
        null,
        auditAction,
        { deletedUserId: userId, deletedEmail: userEmail },
        ip,
        userAgent,
        { session },
      );

      await AuditLog.deleteMany({ userId }, { session });
      await User.findByIdAndDelete(userId, { session });
    });
    logger.info(`Cascade delete (transactional) completed for user ${userId}`);
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    logger.error(`Cascade delete (transactional) failed for user ${userId}: ${msg}`);

    // Re-assert deletionPending so the cleanup job retries on the next cycle.
    // Both callers (`userController.deleteAccount` and the `tokenCleanup`
    // zombie loop) now leave the flag SET while we run — neither clears it
    // before the erasure is durable — so on an abort this write is normally a
    // no-op. It is kept as a defensive backstop: it is the one place that can
    // restore the retry signal if any future caller (or a partially-applied
    // sequential path) leaves the flag unset. Best-effort — if the re-set
    // itself fails the user requires manual intervention; we log prominently.
    try {
      await User.updateOne({ _id: userId }, { $set: { deletionPending: true } });
    } catch {
      logger.error(`Failed to re-set deletionPending for user ${userId} (transactional path)`);
    }
    return false;
  } finally {
    await session.endSession();
  }
}

/**
 * Sequential cascade delete — no transaction. On failure, re-sets
 * `deletionPending: true` so the next cleanup cycle can retry.
 */
async function cascadeDeleteSequential(
  userId: string,
  userEmail: string,
  ip: string,
  userAgent: string,
  auditAction: string,
): Promise<boolean> {
  try {
    await VaultItem.deleteMany({ userId });
    await Folder.deleteMany({ userId });
    await RefreshToken.deleteMany({ userId });
    await revokeTrustedDevices(userId);
    await BackupLog.deleteMany({ userId });
    // Stated explicitly, for the same reason as on the transactional path above.
    await Document.deleteMany({ userId });
    await DocumentUpload.deleteMany({ userId });

    await createAuditLog(
      null,
      auditAction,
      { deletedUserId: userId, deletedEmail: userEmail },
      ip,
      userAgent,
    );

    await AuditLog.deleteMany({ userId });
    await User.findByIdAndDelete(userId);

    logger.info(`Cascade delete (sequential) completed for user ${userId}`);
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    logger.error(`Cascade delete (sequential) failed for user ${userId}: ${msg}`);

    // Re-set deletionPending so the cleanup job retries on the next cycle
    try {
      await User.updateOne({ _id: userId }, { $set: { deletionPending: true } });
    } catch {
      logger.error(`Failed to re-set deletionPending for user ${userId}`);
    }
    return false;
  }
}
