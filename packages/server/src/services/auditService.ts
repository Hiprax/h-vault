import { createLogger } from '@hiprax/logger';
import type { ClientSession } from 'mongoose';
import type { AuditAction } from '@hvault/shared';
import { AuditLog } from '../models/AuditLog.js';
import { MAX_USER_AGENT_LENGTH } from '../utils/controllerHelpers.js';

const logger = createLogger({ moduleName: 'audit-service' });

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
  } catch (err: unknown) {
    // Audit logging should never break the main request flow, so we catch
    // and log any persistence errors rather than re-throwing.
    logger.error('Failed to persist audit log', {
      userId,
      action,
      error: err,
    });
  }
}
