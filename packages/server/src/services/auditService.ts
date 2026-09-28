import { createModuleLogger, errorMessage } from '../utils/logger.js';
import type { ClientSession } from 'mongoose';
import {
  MAX_STRANGER_AUDIT_ROWS_PER_USER,
  STRANGER_WRITABLE_AUDIT_ACTIONS,
  type AuditAction,
} from '@hvault/shared';
import { AuditLog } from '../models/AuditLog.js';
import { MAX_USER_AGENT_LENGTH } from '../utils/controllerHelpers.js';

const logger = createModuleLogger('audit-service');

/**
 * Optional persistence options for {@link createAuditLog}.
 *
 * When `session` is provided, the audit-log document is written inside the
 * given MongoDB transaction so the entry commits or aborts together with the
 * surrounding writes. Callers that emit an audit event from within
 * `withTransaction` MUST forward the session, otherwise the audit row
 * persists even when the transaction aborts and the audit-log invariant
 * ("logged events reflect committed state") is broken.
 */
export interface CreateAuditLogOptions {
  session?: ClientSession | undefined;
}

/**
 * Persists an audit-log entry to the database.
 *
 * `userAgent` is truncated to {@link MAX_USER_AGENT_LENGTH} as a final
 * persistence-layer safety net. Callers SHOULD already pass a pre-truncated
 * value via {@link getRequestContext} in `controllerHelpers.ts` — that helper
 * normalises the IP/UA at the request boundary so this function is never the
 * sole guard against oversized values.
 *
 * @param userId     The ID of the user who performed the action.
 * @param action     A label describing the audited action (e.g. `"login"`,
 *                   `"item_create"`).
 * @param metadata   Optional key-value data that provides additional context.
 * @param ipAddress  The client's IP address.
 * @param userAgent  The client's User-Agent header value.
 * @param options    Optional persistence options. Pass `{ session }` when
 *                   emitting from inside a MongoDB transaction so the audit
 *                   entry commits or aborts together with the transaction.
 */
export async function createAuditLog(
  userId: string | null,
  action: string,
  metadata: Record<string, unknown> | undefined,
  ipAddress: string,
  userAgent: string,
  options: CreateAuditLogOptions = {},
): Promise<void> {
  try {
    const truncatedUserAgent =
      userAgent.length > MAX_USER_AGENT_LENGTH
        ? userAgent.slice(0, MAX_USER_AGENT_LENGTH)
        : userAgent;

    const doc = {
      userId,
      action: action as AuditAction,
      ipAddress,
      userAgent: truncatedUserAgent,
      ...(metadata !== undefined ? { metadata } : {}),
    };

    if (options.session) {
      await AuditLog.create([doc], { session: options.session });
    } else {
      await AuditLog.create(doc);
    }

    logger.debug('Audit log created', { userId, action });

    if (userId !== null && isStrangerWritable(action)) {
      await noteStrangerWritableInsert(userId);
    }
  } catch (err: unknown) {
    // Audit logging should never break the main request flow, so we catch
    // and log any persistence errors rather than re-throwing.
    logger.error('Failed to persist audit log', {
      userId,
      action,
      error: errorMessage(err),
    });
  }
}

// ── Actions a stranger can write, and their cap ──────────────────────────────

function isStrangerWritable(action: string): boolean {
  return (STRANGER_WRITABLE_AUDIT_ACTIONS as readonly string[]).includes(action);
}

/** How many inserts of the stranger-writable actions trigger one trim. */
export const STRANGER_AUDIT_TRIM_EVERY = 100;

/**
 * How many accounts the process-local counter below tracks at once. Past it, an
 * account that is not already tracked is trimmed AT ONCE instead of being
 * remembered: an attacker spraying many accounts must not be able to keep a
 * victim's counter from ever reaching {@link STRANGER_AUDIT_TRIM_EVERY}.
 */
export const STRANGER_AUDIT_TRACKED_ACCOUNTS = 10_000;

const strangerInsertsSinceTrim = new Map<string, number>();

/**
 * Keeps an account's stranger-writable rows (`STRANGER_WRITABLE_AUDIT_ACTIONS`:
 * failed sign-ins, rejected trusted-device cookies, link unlocks) to the newest
 * {@link MAX_STRANGER_AUDIT_ROWS_PER_USER}, oldest first. Only those actions are
 * ever removed, so a stranger can neither grow the log without bound nor push the
 * owner's own history out of it.
 *
 * Deletes everything strictly older than the cap-th newest row, with `_id` as the
 * tie-break, so exactly the newest rows survive even when many share a timestamp.
 */
export async function trimStrangerAuditRows(userId: string): Promise<void> {
  const filter = { userId, action: { $in: [...STRANGER_WRITABLE_AUDIT_ACTIONS] } };
  const [boundary] = await AuditLog.find(filter)
    .sort({ timestamp: -1, _id: -1 })
    .skip(MAX_STRANGER_AUDIT_ROWS_PER_USER - 1)
    .limit(1)
    .select('timestamp _id')
    .lean();
  if (!boundary) return;
  await AuditLog.deleteMany({
    ...filter,
    $or: [
      { timestamp: { $lt: boundary.timestamp } },
      { timestamp: boundary.timestamp, _id: { $lt: boundary._id } },
    ],
  });
}

/**
 * Counts one stranger-writable insert for `userId` and trims the account's rows
 * on every {@link STRANGER_AUDIT_TRIM_EVERY}th. The counter is per process, so
 * across a cluster (or a restart) an account can sit at most one interval per
 * process above the cap before the next trim brings it back: the bound holds,
 * only its slack is per process. Never throws; a failed trim is logged and the
 * next interval retries it.
 */
export async function noteStrangerWritableInsert(userId: string): Promise<void> {
  const seen = strangerInsertsSinceTrim.get(userId);
  let due: boolean;
  if (seen === undefined && strangerInsertsSinceTrim.size >= STRANGER_AUDIT_TRACKED_ACCOUNTS) {
    due = true;
  } else {
    const next = (seen ?? 0) + 1;
    due = next >= STRANGER_AUDIT_TRIM_EVERY;
    if (due) {
      strangerInsertsSinceTrim.delete(userId);
    } else {
      strangerInsertsSinceTrim.set(userId, next);
    }
  }
  if (!due) return;
  try {
    await trimStrangerAuditRows(userId);
  } catch (err: unknown) {
    logger.error('Failed to trim stranger-writable audit rows', {
      userId,
      error: errorMessage(err),
    });
  }
}

/** Forgets every tracked count. For tests that need a known starting point. */
export function resetStrangerAuditTracking(): void {
  strangerInsertsSinceTrim.clear();
}

// ── Locked sign-in attempts, coalesced per minute ───────────────────────────

const COALESCE_BUCKET_MS = 60 * 1000;
const LOCKED_ATTEMPT_METADATA = { reason: 'locked' } as const;

function isDuplicateKey(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === 11000;
}

/**
 * Records ONE unproven sign-in attempt made while the account's password is
 * locked, as `login_failed{reason:'locked'}`, coalesced into one row per account
 * per minute whatever the address or user agent, with `count` holding the
 * attempts. The row is written identically whether the password presented was
 * right or wrong — nothing in it (and nothing in the audit-log API that returns
 * it) may say which, or the log would hand the password oracle the lockout closes
 * to anyone holding a session. The owner learns of a correct password from an
 * unproven device only out of band, never from this row.
 *
 * One upsert on a unique key, so a flood costs one row a minute. The first
 * attempt of a minute that loses an insert race to a concurrent one is retried
 * as an update of the winner's row. Like {@link createAuditLog}, it never throws.
 */
export async function recordLockedAttempt(
  userId: string,
  ipAddress: string,
  userAgent: string,
  now: Date = new Date(),
): Promise<void> {
  const bucket = Math.floor(now.getTime() / COALESCE_BUCKET_MS) * COALESCE_BUCKET_MS;
  const coalesceKey = `${userId}|login_failed|${LOCKED_ATTEMPT_METADATA.reason}|${String(bucket)}`;
  const insertFields = {
    userId,
    action: 'login_failed' as const,
    metadata: { ...LOCKED_ATTEMPT_METADATA },
    ipAddress,
    userAgent: userAgent.slice(0, MAX_USER_AGENT_LENGTH),
    timestamp: now,
  };
  try {
    let inserted: boolean;
    try {
      const result = await AuditLog.updateOne(
        { coalesceKey },
        { $inc: { count: 1 }, $setOnInsert: insertFields },
        { upsert: true, setDefaultsOnInsert: false },
      );
      inserted = result.upsertedCount === 1;
    } catch (err: unknown) {
      if (!isDuplicateKey(err)) throw err;
      await AuditLog.updateOne({ coalesceKey }, { $inc: { count: 1 } });
      inserted = false;
    }
    if (inserted) {
      await noteStrangerWritableInsert(userId);
    }
  } catch (err: unknown) {
    logger.error('Failed to persist a locked sign-in attempt', {
      userId,
      error: errorMessage(err),
    });
  }
}

/**
 * The same awaited round trip {@link recordLockedAttempt} makes, for a sign-in
 * that named no account: an update that can match nothing and never inserts, so
 * an unregistered address costs what a locked one does and writes nothing.
 */
export async function recordNothing(): Promise<void> {
  try {
    await AuditLog.updateOne({ coalesceKey: '|nobody|' }, { $inc: { count: 1 } });
  } catch (err: unknown) {
    logger.error('Failed the equalising audit round trip', { error: errorMessage(err) });
  }
}
