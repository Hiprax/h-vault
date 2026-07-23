import mongoose from 'mongoose';
import { createLogger } from '@hiprax/logger';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { AuditLog } from '../models/AuditLog.js';
import { BackupLog } from '../models/BackupLog.js';
import { createAuditLog } from '../services/auditService.js';
import { revokeTrustedDevices } from './trustedDevices.js';

const logger = createLogger({ moduleName: 'cascade-delete' });

/**
 * Check if the current MongoDB topology supports multi-document transactions
 * (requires a replica set or sharded cluster).
 *
 * Exported for tests so the transactional path can be exercised against a
 * standalone in-memory MongoDB by stubbing this helper.
 */
export function supportsTransactions(): boolean {
  return (
    mongoose.connection.readyState === mongoose.ConnectionStates.connected &&
    Boolean(mongoose.connection.getClient().options.replicaSet)
  );
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
 * Returns true if the deletion completed successfully.
 */
export async function cascadeDeleteUser(opts: CascadeDeleteOptions): Promise<boolean> {
  const { userId, userEmail, ip, userAgent, auditAction } = opts;
  const userIdStr = typeof userId === 'string' ? userId : userId.toString();

  if (supportsTransactions()) {
    return cascadeDeleteTransactional(userIdStr, userEmail, ip, userAgent, auditAction);
  }
  return cascadeDeleteSequential(userIdStr, userEmail, ip, userAgent, auditAction);
}

/**
 * Transactional cascade delete — all-or-nothing via MongoDB session.
 *
 * Exported so the transactional code path (in particular, the
 * `deletionPending` re-set on transaction abort) can be unit-tested against a
 * standalone in-memory MongoDB. The standalone fallback is exercised via the
 * public `cascadeDeleteUser` entry point.
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
