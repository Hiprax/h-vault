import express from 'express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { httpErrors } from '@hiprax/errors';
import {
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS,
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER,
} from '@hvault/shared';
import { createModuleLogger } from '../utils/logger.js';
import { createKeyedQuota, createSemaphore } from '../utils/partSemaphore.js';
import type { KeyedQuota, Semaphore } from '../utils/partSemaphore.js';
import { admitWithinBudget } from './admission.js';

const logger = createModuleLogger('large-body-admission');

/**
 * Admission to the two routes that accept a 30 MB JSON body, `POST /backup/restore`
 * and `POST /vault/items/bulk-reencrypt`, in the order it must run:
 *
 *   1. the route's rate limiter (`passwordVerifyLimiter`), which keys on the user
 *      the router-level `authenticate` has already set and so needs nothing from
 *      the body;
 *   2. {@link holdLargeBodySlot}, this account's share and one process-wide slot;
 *   3. {@link parseLargeJsonBody}, which buffers and parses the body;
 *   4. validation, then the handler, wrapped by {@link holdingLargeBodySlot} so the
 *      slot outlives the response when the handler does.
 *
 * THE ORDER IS THE CONTROL. A limiter or a slot placed after the parser runs only
 * once 30 MB has been buffered and `JSON.parse` has allocated it, so it bounds how
 * many requests are ANSWERED and never how many are BUFFERED. Both routes shipped
 * that way once: the sixth request in a window cost exactly what the first five did
 * before it was refused. `tests/route-table.test.ts` pins the order by reading the
 * real router stack, because an assertion that a limiter is merely PRESENT on a
 * route cannot see where it sits.
 *
 * What moving the limiter first changes, stated rather than left to be found: a
 * request the parser would refuse (413, malformed JSON) now spends a unit of the
 * limiter's budget, and a rate-limit store outage now answers 500 before the body
 * is read rather than after.
 */

/**
 * The parser ceiling on both routes.
 *
 * NOT `MAX_RESTORE_DATA_LENGTH` (25 MiB) rounded up. A restore posts
 * `{ conflictStrategy, data: JSON.stringify(backupData) }`, so the backup document
 * travels as a JSON STRING value and every `"` inside it is escaped to `\"` on the
 * wire. A quote-dense backup (thousands of small items, each carrying a full
 * password history) is ~6-7% quotes, which inflates a body whose inner `data` is
 * still within the 25 MiB schema cap to well over 26 MB — a 413 from the parser
 * before Zod ever sees it, i.e. a backup the app produced but could not restore.
 * 30 MB keeps ~20% headroom over the inner cap and still sits below nginx's
 * `client_max_body_size 32m`, so a genuinely oversized payload is refused by the app
 * with a structured JSON error rather than by the proxy with an opaque one. A full
 * key rotation re-encrypts every item and folder in one request and is comparable
 * in size to a full backup, so it shares the number.
 */
export const LARGE_JSON_BODY_LIMIT_BYTES = 30 * 1024 * 1024;

/**
 * Buffers and parses a large JSON body. ONE instance, mounted on both routes, so
 * the route table can find it by identity. Both paths are exempted from the global
 * 2 MB parser in `app.ts` (`CUSTOM_BODY_LIMIT_PATHS`).
 */
export const parseLargeJsonBody: RequestHandler = express.json({
  limit: LARGE_JSON_BODY_LIMIT_BYTES,
});

/**
 * The process-wide budget: large-body requests whose body is being read, parsed or
 * handled right now. Sized in `@hvault/shared` beside the measurements it is sized
 * from.
 *
 * A request past it WAITS rather than being refused. Waiting costs a socket and no
 * memory, because its body has not been read, and the condition clears when an
 * operation already in flight finishes. That is not milliseconds here, unlike the
 * part route: a 10,000-row restore measures 17-21 seconds and a full rotation 7-10,
 * so a third concurrent request can wait tens of seconds. The time it waits counts
 * against the server-wide receive deadline (`HTTP_REQUEST_TIMEOUT_MS`, 240 s by
 * default, operator-tunable), which was derived from this very body size and is
 * why no second, route-scoped deadline is armed here: it would be the same number.
 */
export const largeBodySemaphore: Semaphore = createSemaphore(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS);

/**
 * One account's share of {@link largeBodySemaphore}: a request past it is refused
 * at once, holding nothing. Without the share, two requests from one account that
 * declare a `Content-Length` and then send nothing hold every slot in the process
 * for as long as the server will wait for a body.
 */
export const largeBodyUserQuota: KeyedQuota = createKeyedQuota(
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER,
);

/**
 * The refusal past the share. 409, remedy first, under 200 characters (the client
 * shows a 4xx message verbatim and slices at 200), and with NO `data`: a 409
 * carrying `data.vaultKeyVersion` means "your vault key is stale" to every client
 * consumer, and this is not that.
 *
 * 409 because it is the answer the second of two concurrent requests from one
 * account already got: both handlers take the per-account vault-rotation lock and
 * the loser is refused with 409. The share gives the same request the same status,
 * before its body is read instead of after. Never 503, which is redacted to its
 * status text in production, and never 429, which the client reads as "the
 * fifteen-minute budget is spent".
 */
export const LARGE_BODY_BUSY_MESSAGE =
  'Wait for the restore or vault key rotation already in progress on this account to finish, then try again.';

/**
 * What the slot holder and the handler wrapper share for one request: whether the
 * handler is running, and the release a `close` during it had to defer.
 */
interface SlotTicket {
  inHandler: boolean;
  releaseWhenSettled: (() => void) | null;
}

/** Keyed by the response, so a ticket lives exactly as long as its request. */
const tickets = new WeakMap<Response, SlotTicket>();

/**
 * The identity a large-body request is charged to. `authenticate` is mounted at
 * ROUTER level on both routers, so `req.user` is always set here; the shared
 * fallback is the direction that fails CLOSED, exactly as the part holder's is.
 */
function largeBodyIdentity(req: Request): string {
  return req.user?._id ?? 'anonymous';
}

/**
 * Charges this account's share, then holds one {@link largeBodySemaphore} slot from
 * before the body is read until the response has closed AND the handler has
 * settled. The admission mechanics (the destroyed check, charging before queueing,
 * registering `close` before `acquire`) are `admitWithinBudget`'s.
 *
 * WHY `close` ALONE IS NOT THE END. A client that aborts mid-request closes the
 * response while the handler is still running, and Express does not cancel a
 * handler: a restore keeps its parsed body, parses the backup inside it and writes
 * up to 10,000 rows for another twenty seconds. Released on `close`, that slot
 * would let one account send a full body, drop the connection, and send the next,
 * with every one of them resident at once — the budget would bound connections,
 * not memory. So a `close` that arrives while the handler runs DEFERS the release to
 * {@link holdingLargeBodySlot}, and a `close` before the handler was reached (a 400,
 * a 413, a request that waited in the queue) releases at once.
 */
export function holdLargeBodySlot(req: Request, res: Response, next: NextFunction): void {
  const ticket: SlotTicket = { inHandler: false, releaseWhenSettled: null };

  admitWithinBudget(res, next, {
    semaphore: largeBodySemaphore,
    quota: largeBodyUserQuota,
    identity: largeBodyIdentity(req),
    refuse(_refused, refuse) {
      // The identity is deliberately NOT logged, as the rate limiters omit their key.
      logger.warn('Large-body request refused: the account already has one in flight', {
        limit: MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER,
      });
      refuse(httpErrors.conflict(LARGE_BODY_BUSY_MESSAGE));
    },
    granted() {
      tickets.set(res, ticket);
    },
    closed(release) {
      if (ticket.inHandler) ticket.releaseWhenSettled = release;
      else release();
    },
  });
}

/** The shape `catchAsync` hands back, which is what both routes mount. */
type LargeBodyHandler = (req: Request, res: Response, next: NextFunction) => unknown;

/**
 * Wraps the handler of a large-body route so the slot {@link holdLargeBodySlot}
 * took is held until the handler has SETTLED, not merely until the response closed.
 *
 * A handler reached with no ticket means the chain in front of it is wrong — the
 * holder is missing, or sits after this — and it is refused with 500 rather than
 * run, because running it would be running a 30 MB operation that no budget
 * counted. `tests/route-table.test.ts` is what keeps the chain right; this is what
 * makes a wrong one fail closed rather than silently unbounded.
 */
export function holdingLargeBodySlot(handler: LargeBodyHandler): RequestHandler {
  return async function largeBodyHandler(req, res, next): Promise<void> {
    const ticket = tickets.get(res);
    if (ticket === undefined) {
      next(httpErrors.internalServerError('Large-body handler reached without an admission slot'));
      return;
    }
    ticket.inHandler = true;
    try {
      await handler(req, res, next);
    } finally {
      ticket.inHandler = false;
      ticket.releaseWhenSettled?.();
    }
  };
}
