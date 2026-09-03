import express from 'express';
import type { Request, RequestHandler, Response, NextFunction } from 'express';
import { ErrorHandler } from '@hiprax/errors';
import { DOCUMENT_CIPHERTEXT_CHUNK_BYTES } from '@hvault/shared';
import { partUploadSemaphore } from '../utils/partSemaphore.js';

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
 *   2. {@link holdPartUploadSlot} takes one of `MAX_IN_FLIGHT_PART_UPLOADS` slots
 *      and holds it until the response closes — so across the parser AND across the
 *      storage call. It must sit AHEAD of the parser: Express runs a route's parser
 *      before its handler, so a slot taken in the handler is taken after 8 MiB has
 *      already been buffered and bounds nothing.
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

/**
 * Holds one {@link partUploadSemaphore} slot for the whole request/response cycle.
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
 */
export function holdPartUploadSlot(req: Request, res: Response, next: NextFunction): void {
  let release: (() => void) | undefined;
  let closed = false;

  res.once('close', () => {
    closed = true;
    release?.();
  });

  partUploadSemaphore.acquire((grantedRelease) => {
    release = grantedRelease;
    if (closed) {
      // The response ended while this request was queued. Hand the slot straight
      // back and do NOT continue down the chain: there is nobody to answer.
      grantedRelease();
      return;
    }
    next();
  });
}

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
