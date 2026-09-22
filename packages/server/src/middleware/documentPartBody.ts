import express from 'express';
import type { Request, RequestHandler, Response, NextFunction } from 'express';
import { ErrorHandler, httpErrors } from '@hiprax/errors';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  MAX_IN_FLIGHT_PART_UPLOADS_PER_USER,
  MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
} from '@hvault/shared';
import { createModuleLogger } from '../utils/logger.js';
import { partUploadSemaphore, partUploadUserQuota } from '../utils/partSemaphore.js';
import { admitWithinBudget } from './admission.js';

const logger = createModuleLogger('document-part-body');

/**
 * The three middlewares that stand in front of `PUT /documents/uploads/:id/parts/:n`,
 * in the order they must run: the length guard, the concurrency slot, then the body
 * parser.
 *
 * THE ORDER IS THE WHOLE POINT, and each step is here because the step after it
 * cannot do its job otherwise:
 *
 *   1. {@link requirePartContentLength} answers 411 before anything reads the
 *      socket. A request with neither `Content-Length` nor `Transfer-Encoding` has
 *      no body as far as `type-is` is concerned, so the parser below would SKIP it
 *      and leave `req.body` undefined; and a chunked request has no declared length
 *      to check the received bytes against, which is a number this handler's ledger
 *      and quota arithmetic depend on. Both are refused here, cheaply, and neither
 *      consumes a concurrency slot.
 *   2. {@link holdPartUploadSlot} charges this identity's share of the budget and
 *      takes one of `MAX_IN_FLIGHT_PART_UPLOADS` slots, holding both until the
 *      response closes — so across the parser AND across the storage call. It must
 *      sit AHEAD of the parser: Express runs a route's parser before its handler,
 *      so a slot taken in the handler is taken after 8 MiB has already been
 *      buffered and bounds nothing.
 *   3. {@link parsePartUploadBody} buffers the part.
 */

// ---------------------------------------------------------------------------
// 1. The length guard
// ---------------------------------------------------------------------------

/** 411. Named because it is written out here rather than read from a factory. */
const HTTP_LENGTH_REQUIRED = 411;

/**
 * Refuses a part upload that does not declare its length, with 411.
 *
 * `@hiprax/errors` has no 411 factory — `httpErrors` stops at 410 and picks up
 * again at 413 — so the status is constructed directly. `ErrorHandler` resolves its
 * own status text from the same table (`Length Required`), and
 * `createErrorMiddleware` treats it exactly as it treats an `httpErrors` value, so
 * this is the same flat error body every other refusal produces.
 *
 * A CHUNKED body is refused here too, and deliberately: `Transfer-Encoding:
 * chunked` carries no declared length, and the length is what the byte count is
 * checked against before a part is forwarded to the storage engine. A client that
 * cannot state the size of a sealed segment it has already computed is a client
 * with a bug, and accepting one would mean storing a part whose size nothing
 * verified.
 */
export function requirePartContentLength(req: Request, _res: Response, next: NextFunction): void {
  if (req.headers['content-length'] === undefined) {
    next(
      new ErrorHandler(
        'Content-Length is required for a document part upload',
        HTTP_LENGTH_REQUIRED,
      ),
    );
    return;
  }
  next();
}

// ---------------------------------------------------------------------------
// 2. The concurrency slot
// ---------------------------------------------------------------------------

/** How soon a refused client may try again. One second: the condition is a peer's part. */
const PART_SLOT_RETRY_AFTER_SECONDS = '1';

/**
 * How long the server will wait for ONE part's body once that part holds a slot.
 *
 * Derived, never chosen: one sealed segment at
 * {@link MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND}, which is 64 seconds at today's
 * numbers. It is far tighter than `HTTP_REQUEST_TIMEOUT_MS`, and it has to be,
 * because the two bound different things. The server-wide deadline is sized to the
 * largest body ANY route accepts (a 30 MB restore), since Node has no per-route
 * form of it; this one is sized to the largest body THIS route accepts — and here
 * waiting costs more than a socket, because the slot was taken before the body was
 * read and every other account's parts queue behind it. (The two 30 MB routes hold
 * a slot from before their body is read too, but their body IS the one the
 * server-wide deadline was derived from, so a tighter copy of it would be a
 * different number for the same body; see `middleware/largeBodyAdmission.ts`.)
 *
 * ARMED WHEN THE SLOT IS GRANTED AND CLEARED WHEN THE BODY ARRIVES, which is what
 * keeps it a deadline on RECEIPT rather than on the request. Time spent queued for
 * a slot is not the client's fault, and the storage call that follows the body is
 * deliberately left unbounded here: `partSemaphore.ts` records why a slow engine is
 * allowed to hold a slot, and turning this into a deadline on the whole request
 * would cap a healthy upload to protect against an unhealthy engine.
 */
export const PART_UPLOAD_BODY_DEADLINE_MS =
  (DOCUMENT_CIPHERTEXT_CHUNK_BYTES / MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND) * 1_000;

/**
 * The identity a part upload is charged to.
 *
 * `authenticate` is mounted at ROUTER level in `routes/documents.ts`, so through
 * the mounted chain `req.user` is always set and the fallback below is
 * unreachable. It is a single shared bucket rather than a per-request free pass
 * because that is the direction that fails CLOSED: if some future chain ever
 * reached this middleware without an authenticated user, those requests would
 * share ONE share instead of each getting an unbounded one.
 */
function partUploadIdentity(req: Request): string {
  return req.user?._id ?? 'anonymous';
}

/**
 * Charges this identity's share of the budget, then holds one
 * {@link partUploadSemaphore} slot for the whole request/response cycle.
 *
 * THE SHARE IS CHARGED FIRST, and before the slot is even requested, so it bounds
 * QUEUED requests as well as granted ones. That ordering is the point: the hazard
 * is a client that declares a `Content-Length` and then sends nothing, which costs
 * it a socket and costs the process a slot, and an identity allowed to queue
 * without limit could convert its own refusal into a growing pile of them. An
 * identity at its share is answered 503 immediately — never 429, which the browser
 * treats as "the fifteen-minute budget is spent, stop retrying", while this
 * condition clears as soon as one of that account's own parts finishes.
 *
 * The `close` listener is registered BEFORE the slot is requested, and that is
 * load-bearing rather than tidy. A queued request whose client disconnects would
 * otherwise have no listener at the moment `close` fires, and the slot it is later
 * granted would never be released — one leaked slot per abandoned upload, until the
 * budget reached zero and every part upload in the process hung forever. Registering
 * first turns that case into "the slot is granted and immediately handed back".
 *
 * `close` rather than `finish`: `finish` fires only when a response was written, so
 * an aborted connection would leak the same way. Node emits `close` on the response
 * in both cases, and the release is idempotent, so wiring the one event that always
 * fires is enough.
 *
 * REGISTERING FIRST IS NOT ENOUGH ON ITS OWN, because `close` may ALREADY have
 * fired. TWO middlewares ahead of this one await a MongoDB round trip: the router's
 * `authenticate`, which reads the user on EVERY request in every environment, and
 * `documentPartLimiter`, which writes its counter in production. A client that
 * disconnects during either arrives here with a response that is already destroyed,
 * and a listener added afterwards never runs (measured: `res.destroyed` and
 * `res.closed` are both true at that point, and a late `close` handler is never
 * called). Nothing is charged or taken in that case, and the chain deliberately
 * stops here — there is nobody to answer. The check is BEFORE the charge and before
 * `acquire`, not a take-then-hand-back: a slot handed to a dead request is a slot
 * taken from the live one waiting behind it.
 *
 * Those mechanics live ONCE, in `middleware/admission.ts` (`admitWithinBudget`),
 * shared with the large-body slot holder; what is part-specific here is the 503
 * refusal, the body deadline, and releasing on `close` without waiting for anything.
 *
 * Built by a FACTORY over `bodyDeadlineMs` rather than reading
 * {@link PART_UPLOAD_BODY_DEADLINE_MS} directly, so the deadline can be exercised
 * at a tenth of a second by a test that drives a real socket through the real
 * chain. The mounted handler below is the same code at the shipped number; a test
 * that had to wait 64 seconds for it would be a test that gets deleted.
 */
export function createPartSlotHolder(bodyDeadlineMs: number): RequestHandler {
  return function holdPartUploadSlot(req: Request, res: Response, next: NextFunction): void {
    let deadline: NodeJS.Timeout | undefined;

    admitWithinBudget(res, next, {
      semaphore: partUploadSemaphore,
      quota: partUploadUserQuota,
      identity: partUploadIdentity(req),
      refuse(refused, refuse) {
        // Logged, because on the wire this refusal is indistinguishable from the 503
        // an unreachable storage engine produces (both are redacted to their status
        // text in production), and those two call for opposite operator responses.
        // The identity is deliberately NOT logged, exactly as the rate limiters'
        // handlers omit their key.
        logger.warn('Document part refused: the account is at its in-flight share', {
          limit: MAX_IN_FLIGHT_PART_UPLOADS_PER_USER,
        });
        refused.setHeader('Retry-After', PART_SLOT_RETRY_AFTER_SECONDS);
        refuse(
          httpErrors.serviceUnavailable(
            'Too many document part uploads are already in flight for this account',
          ),
        );
      },
      granted() {
        // The body deadline, armed at the moment this request starts costing the
        // process memory. The socket is DESTROYED rather than answered: the parser
        // below is mid-stream by then, so writing a response would race a body that
        // is still arriving — and the client treats a reset on a part exactly as it
        // treats the 408 the server-wide deadline produces, as a transfer to retry.
        deadline = setTimeout(() => {
          logger.warn('Document part destroyed: its body did not arrive inside the deadline', {
            deadlineMs: bodyDeadlineMs,
          });
          res.destroy();
        }, bodyDeadlineMs);
        // Never a reason to keep the process alive: a shutdown that is draining
        // connections does not need to wait for this to fire.
        deadline.unref();
        // `end` fires when the parser has consumed the whole body, which is the
        // moment this stops being a deadline the client can miss. Without it the
        // timer would still be armed across the storage call and would destroy a
        // healthy upload whose engine was merely slow.
        req.once('end', () => {
          if (deadline !== undefined) clearTimeout(deadline);
        });
      },
      closed(release) {
        // A part holds its slot across the storage call and no further: once the
        // response has closed there is nothing left of it in memory to account for.
        if (deadline !== undefined) clearTimeout(deadline);
        release();
      },
    });
  };
}

/** The mounted holder, at this deployment's {@link PART_UPLOAD_BODY_DEADLINE_MS}. */
export const holdPartUploadSlot: RequestHandler = createPartSlotHolder(
  PART_UPLOAD_BODY_DEADLINE_MS,
);

// ---------------------------------------------------------------------------
// 3. The body parser
// ---------------------------------------------------------------------------

/**
 * Headroom above one sealed segment, so that the parser's 413 means "far too
 * large" and the handler's own size rule owns the near misses.
 *
 * A part one byte over the segment size is a FRAMING error, and the handler can say
 * so precisely ("part 3 must be exactly N bytes"); a parser limit set to the exact
 * segment size would answer it with a generic "request entity too large" instead.
 * Anything past this margin cannot be a framing mistake, and `raw-body` refuses it
 * from the `Content-Length` header alone, without buffering a byte.
 */
const PART_BODY_SLACK_BYTES = 1024;

/** The parser's ceiling: one sealed segment plus {@link PART_BODY_SLACK_BYTES}. */
export const PART_BODY_LIMIT_BYTES = DOCUMENT_CIPHERTEXT_CHUNK_BYTES + PART_BODY_SLACK_BYTES;

/**
 * Buffers the part as a `Buffer`.
 *
 * MOUNTED AT ROUTE LEVEL, NEVER APP LEVEL, and the reason is not body size — it is
 * the MongoDB injection sanitizer in `app.ts`. That sanitizer rebuilds any object
 * body key by key to strip `$`-prefixed operators, and a `Buffer` is an object that
 * is not an Array, so it would be rewritten into a plain object of numeric keys:
 * `{0: 137, 1: 80, …}`. The part would then fail its own digest check, or worse be
 * forwarded as something that is not the bytes the client sealed. Mounted here, the
 * parser runs after the sanitizer, after `hppx` and after the request logger, none
 * of which ever see a Buffer.
 *
 * There is deliberately NO entry added to `CUSTOM_BODY_LIMIT_PATHS` for this route.
 * That Set is matched by exact `req.path` equality, so a parameterised path can
 * never match it and the entry would do nothing; and adding a dead entry would read
 * as though the global JSON parser were the hazard here, when the hazard is the
 * sanitizer. The global parser is inert on this route anyway: it only parses
 * `application/json`, and `body-parser` leaves `req.body` undefined when it skips.
 *
 * `inflate: false`, so a `Content-Encoding` other than `identity` is refused with
 * 415 rather than decompressed. A sealed segment is ciphertext and does not
 * compress, so the option buys a client nothing; what it costs the server is the
 * correspondence between `Content-Length` and the number of bytes the handler ends
 * up holding, because an inflating parser can no longer compare the two. That
 * correspondence is what the ledger and the quota are computed from.
 */
export const parsePartUploadBody: RequestHandler = express.raw({
  type: 'application/octet-stream',
  limit: PART_BODY_LIMIT_BYTES,
  inflate: false,
});
