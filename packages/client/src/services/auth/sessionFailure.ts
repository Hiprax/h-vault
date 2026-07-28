/**
 * Classifying a failed session operation: is the session GONE, or was that a
 * hiccup?
 *
 * This is one of the load-bearing distinctions in the client, and getting it
 * wrong is destructive rather than merely annoying. Every caller that refreshes
 * the access token reads a rejection as "log the user out". Because
 * `authStore.lock()` deliberately keeps `accessToken` set, that logout is not a
 * local teardown — it reaches `POST /auth/logout`, which DELETES the refresh-token
 * row server-side. So treating a 429, a 502 or a dropped Wi-Fi connection as an
 * expired session does not just bounce the user to the login screen: it destroys
 * a perfectly valid session that had days or weeks left on it, irreversibly, and
 * strands them on a login form.
 *
 * That is exactly what shipped. `UnlockScreen`, `ProtectedRoute` and the Axios
 * 401 interceptor each wrapped their refresh in a bare `catch` and logged out on
 * anything. Only `sessionResume` got it right, and this module is that predicate
 * promoted to the single definition all four now share.
 *
 * The rule, stated once:
 *
 *   - **401 / 403 — authoritative.** The server looked at the credential and
 *     rejected it: the refresh token is unknown, expired, replayed (reuse
 *     detection has already revoked the family), or the account is locked. The
 *     session really is over; log out.
 *   - **Everything else — transient.** 429 (a rate limit we will be under again
 *     shortly), any 5xx, a network error with no `response` at all (offline, DNS,
 *     a restarting container), a timeout, or a non-Axios throw from our own code.
 *     KEEP the session and surface a retryable error.
 *
 * Note the asymmetry is deliberate and safe in both directions: mistaking a dead
 * session for a transient one costs the user one extra failed request before the
 * next 401 settles it, while mistaking a transient failure for a dead session
 * costs them the session itself.
 */

import { isAxiosError } from 'axios';

/**
 * Whether a 403 came from the CSRF middleware rather than from a handler that
 * refused the request on its merits.
 *
 * The server's error envelope is flat — `{ success, message, statusCode,
 * statusText }` with no code field — so the message is the only signal, and
 * `middleware/csrf.ts` emits exactly one: `'invalid csrf token'`. Matched
 * case-insensitively on the substring `csrf` so a rewording of that sentence
 * does not silently change behaviour. Every other 403 the API can produce
 * (`ACCOUNT_LOCKED`, and the refresh endpoint's locked-account branch) carries an
 * `ERROR_CODES` constant as its message and contains no such token.
 *
 * Two callers depend on this, for opposite reasons: the Axios interceptor replays
 * only a CSRF 403, and {@link isSessionGone} refuses to call one a dead session.
 */
export function isCsrfRejection(error: unknown): boolean {
  if (!isAxiosError(error)) return false;
  if (error.response?.status !== 403) return false;
  const message: unknown = (error.response.data as Record<string, unknown> | undefined)?.message;
  return typeof message === 'string' && message.toLowerCase().includes('csrf');
}

/**
 * Whether `error` proves the session is authoritatively gone and the user must
 * sign in again.
 *
 * Returns `false` for anything it cannot prove — that default is the point.
 *
 * **A CSRF 403 is explicitly excluded**, and that exclusion is load-bearing. A
 * CSRF token is bound to `hashToken(refreshToken)` and every refresh rotates that
 * cookie, so a stale token is an ordinary, expected, entirely recoverable
 * condition — the interceptor's job is to fetch a fresh one and replay. Treating
 * it as authoritative would mean that a CSRF token which failed to refresh (the
 * token endpoint briefly unreachable or rate-limited) logged the user out and
 * revoked a session that was never in question. The generic 403s that DO mean the
 * session is over — a locked account from `/auth/refresh` — are unaffected,
 * because their message is an `ERROR_CODES` constant, not a CSRF complaint.
 */
export function isSessionGone(error: unknown): boolean {
  if (!isAxiosError(error)) return false;
  if (isCsrfRejection(error)) return false;
  const status = error.response?.status;
  return status === 401 || status === 403;
}

/**
 * Whether `error` is a rate-limit rejection (HTTP 429).
 *
 * Split out from {@link isSessionGone} because a 429 needs its own treatment
 * rather than merely "not a logout": it is the one transient failure that carries
 * a usable recovery time, and the one the user must be told about explicitly, or
 * they will keep retrying and keep extending the very window they are waiting on.
 */
export function isRateLimited(error: unknown): boolean {
  return isAxiosError(error) && error.response?.status === 429;
}

/** Upper bound on a `Retry-After` we will quote back to the user, in seconds. */
const MAX_RETRY_AFTER_SECONDS = 3600;

/**
 * Seconds to wait, parsed from a 429's `Retry-After` header, or `null` when the
 * response carries no usable value.
 *
 * Handles both forms RFC 9110 permits — a delay in seconds, and an HTTP-date —
 * mirroring `services/health/breachCheck.ts`, which is the one place in the
 * client that already reads this header correctly. Clamped to a sane range so a
 * malformed or hostile header cannot render "try again in 4 million seconds".
 */
export function retryAfterSeconds(error: unknown): number | null {
  if (!isAxiosError(error)) return null;

  // `headers` is typed non-nullable on a present response, so an optional chain
  // there is flagged as unreachable; `response` itself is what may be absent.
  const header: unknown = error.response?.headers['retry-after'];
  if (typeof header !== 'string' || header.length === 0) return null;

  const asSeconds = Number(header);
  if (Number.isFinite(asSeconds)) {
    if (asSeconds <= 0) return null;
    return Math.min(Math.ceil(asSeconds), MAX_RETRY_AFTER_SECONDS);
  }

  const asDate = Date.parse(header);
  if (Number.isNaN(asDate)) return null;
  const deltaSeconds = Math.ceil((asDate - Date.now()) / 1000);
  if (deltaSeconds <= 0) return null;
  return Math.min(deltaSeconds, MAX_RETRY_AFTER_SECONDS);
}

/**
 * A user-facing sentence for a transient failure, or `null` when `error` is not
 * one of the cases this module speaks for (so the caller falls back to
 * `getApiErrorMessage`).
 *
 * Kept here, next to the classification, so the message and the branch that
 * produces it cannot drift: a 429 that is silently rendered as
 * "Request failed with status code 429" reads to the user as "wrong password".
 */
export function describeTransientFailure(error: unknown): string | null {
  if (isRateLimited(error)) {
    const wait = retryAfterSeconds(error);
    return wait === null
      ? 'Too many attempts. Please wait a moment and try again.'
      : `Too many attempts. Please try again in ${formatWait(wait)}.`;
  }

  if (isAxiosError(error) && error.response === undefined) {
    return 'Could not reach the server. Check your connection and try again.';
  }

  if (isAxiosError(error) && (error.response?.status ?? 0) >= 500) {
    return 'The server is temporarily unavailable. Please try again in a moment.';
  }

  return null;
}

/** `90` -> `"1 minute 30 seconds"`-free, compact wait rendering. */
function formatWait(totalSeconds: number): string {
  if (totalSeconds < 60) {
    return `${totalSeconds} second${totalSeconds === 1 ? '' : 's'}`;
  }
  const minutes = Math.ceil(totalSeconds / 60);
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}
