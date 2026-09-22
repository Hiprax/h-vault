import http from 'node:http';
import type { RequestListener, Server } from 'node:http';
import { config } from '../config/index.js';

/**
 * The three numbers that decide how long this server will wait for a request it
 * is being handed one byte at a time, and the one function that builds a server
 * carrying them.
 *
 * WHY THIS EXISTS AT ALL. Node's defaults are `requestTimeout` 300_000 and
 * `headersTimeout` 60_000, and nothing here used to set either. Node's own
 * documentation says both "must be set to a non-zero value (e.g. 120 seconds) to
 * protect against potential Denial-of-Service attacks in case the server is
 * deployed without a reverse proxy in front", and this application has a route
 * where the default is worse than slow: `PUT /documents/uploads/:id/parts/:n`
 * takes one of `MAX_IN_FLIGHT_PART_UPLOADS` concurrency slots BEFORE its body
 * parser runs (deliberately — see `utils/partSemaphore.ts`), so a request that
 * declares a `Content-Length` and then dribbles holds a slot for as long as the
 * server will wait. At the default that is five minutes per request.
 *
 * NOR DOES THE DEPLOYMENT'S NGINX ABSORB IT. `docker/nginx/internal.conf` sets
 * `proxy_request_buffering off` on `/api/`, so a body streams through rather than
 * being collected first, and its `client_body_timeout` is a BETWEEN-READS timeout
 * that one byte every hundred seconds never trips. The deadline has to be here.
 *
 * WHAT IT DOES NOT COVER, measured rather than assumed: it bounds RECEIPT. A
 * request whose body has fully arrived is not interrupted while its controller
 * runs — a handler sleeping four seconds under a one-second `requestTimeout` still
 * answered 200 — so a long vault rotation, a backup collection or a trash purge is
 * unaffected by any value here. The value is therefore sized to the largest BODY
 * any route accepts rather than to the part route, which carries its own much
 * tighter body deadline in `middleware/documentPartBody.ts`.
 *
 * THE TWO TRAPS, both measured on the pinned Node 24 runtime, both invisible when
 * got wrong, and both answered by building the server through its OPTIONS object
 * rather than by assigning the properties afterwards:
 *
 *   1. **Enforcement is a SWEEP, not a timer.** Node checks open connections every
 *      `connectionsCheckingInterval` milliseconds, which defaults to 30_000 — so a
 *      deadline with the default sweep actually fires up to thirty seconds late.
 *      The interval is pinned to {@link CONNECTIONS_CHECKING_INTERVAL_MS} below,
 *      and it is READ WHEN THE SERVER STARTS LISTENING, so it has to be in place
 *      before then. Handing it to the constructor removes that ordering question
 *      rather than answering it.
 *   2. **Node SWAPS the two timeouts when `headersTimeout` is the larger**, in C++
 *      and without a word anywhere (`ConnectionsList::Expired` calls `std::swap`):
 *      measured, a 1-second request timeout beside the default 60-second headers
 *      timeout let a dribbling body survive ninety seconds. Assigned as PROPERTIES
 *      that pair is validated by nothing at all; handed to the constructor it is
 *      refused with `ERR_OUT_OF_RANGE`, so a mis-ordered configuration cannot
 *      start rather than enforcing the opposite of what it says. `envSchema`
 *      refuses the same pair earlier, naming both variables.
 */

/**
 * How often Node sweeps open connections looking for one that has outstayed its
 * deadline, in milliseconds.
 *
 * Five seconds rather than Node's 30, because the sweep period is added to every
 * deadline it enforces. It is NOT an operator-facing setting: it changes the
 * precision of the two deadlines, not the policy, and the cost of a sweep is a
 * walk of this process's own incomplete requests with no I/O. Node `unref`s the
 * interval, so it never holds a draining process open.
 */
export const CONNECTIONS_CHECKING_INTERVAL_MS = 5_000;

/** The deadlines one HTTP server is built with. */
export interface HttpTimeouts {
  /** Milliseconds the server will spend receiving one whole request. */
  requestTimeoutMs: number;
  /** Milliseconds it will spend on that request's headers. Never greater than the above. */
  headersTimeoutMs: number;
  /** Milliseconds between the sweeps that enforce the two. */
  connectionsCheckingIntervalMs: number;
}

/** This deployment's configured deadlines, resolved once. */
export const HTTP_TIMEOUTS: HttpTimeouts = {
  requestTimeoutMs: config.HTTP_REQUEST_TIMEOUT_MS,
  headersTimeoutMs: config.HTTP_HEADERS_TIMEOUT_MS,
  connectionsCheckingIntervalMs: CONNECTIONS_CHECKING_INTERVAL_MS,
};

/**
 * An HTTP server for `requestListener`, carrying `timeouts` from the moment it
 * exists.
 *
 * Used in place of `app.listen`, which is `http.createServer(app).listen(...)`
 * with no seam between the two — and the seam is exactly where these numbers have
 * to go.
 */
export function createTimedServer(
  requestListener: RequestListener,
  timeouts: HttpTimeouts = HTTP_TIMEOUTS,
): Server {
  return http.createServer(
    {
      requestTimeout: timeouts.requestTimeoutMs,
      headersTimeout: timeouts.headersTimeoutMs,
      connectionsCheckingInterval: timeouts.connectionsCheckingIntervalMs,
    },
    requestListener,
  );
}
