/**
 * Server-side constants shared across controllers.
 */

export const REFRESH_COOKIE_NAME = 'refreshToken';

/**
 * Cookie carrying the raw trusted-device token that lets a 2FA account skip the
 * 2FA step at its next login. Scoped to `path: '/api/v1/auth'` (narrower than the
 * refresh cookie's `/api/v1`) so the browser only ever sends it to the auth
 * endpoints that consume it — least privilege. The raw token lives ONLY in this
 * cookie; the server stores just its SHA-256.
 */
export const TRUSTED_DEVICE_COOKIE_NAME = 'trustedDevice';

/**
 * Hard ceiling, in bytes, on the body of a single HIBP Pwned Passwords range
 * response (`utils/hibp.ts`). Applied as BOTH `maxContentLength` and
 * `maxBodyLength` on the outbound `axios` call, which is the only outbound HTTP
 * call the server makes.
 *
 * Why a bound is needed at all: `axios` defaults both to `-1`, and its Node
 * adapter only runs the size check when the value is `> -1`, so without this an
 * anomalous or hostile upstream body buffers into the process without limit.
 * The batch endpoint fans out `HIBP_FANOUT_CONCURRENCY` (8) of these at once,
 * against a shipped container `mem_limit` of 1g.
 *
 * Why this number:
 * - A range row is a 35-char SHA-1 suffix, a colon, a decimal count and CRLF —
 *   about 44-48 bytes. `Add-Padding: true` tops a response UP TO 800-1,000 rows
 *   when the real count is below that, so padding sets a floor rather than a
 *   ceiling and the size is driven by the corpus. Prefixes are near-uniformly
 *   distributed over 16^5, so a single prefix's real row count grows with the
 *   corpus: this is deliberately NOT pinned to one published corpus size, and
 *   the margin should be re-derived rather than assumed. On any corpus that
 *   keeps a single prefix in the low thousands of rows the response stays in
 *   the low hundreds of KB, leaving a several-fold margin under 1 MiB. Revisit
 *   the number if a legitimate range is ever refused — the failure is loud (a
 *   reported failed check), never a silent wrong answer.
 * - It equals the MINIMUM value `HIBP_CACHE_MAX_BYTES` will accept
 *   (`config/index.ts`), so a single cached range can never exceed even the
 *   smallest L1 budget an operator can configure — which matters because the L1
 *   eviction loop deliberately keeps one entry that alone exceeds the budget.
 * - Worst case is 8 x 1 MiB = 8 MiB PER REQUEST. It is not a process-wide
 *   ceiling: `breachBatchLimiter` bounds requests per window per user, not
 *   requests in flight, so N concurrent batches cost N times that. The point of
 *   the bound is that the per-fetch cost went from UNBOUNDED to 1 MiB, which is
 *   what makes the total a function of concurrency at all.
 *
 * `axios` enforces `maxContentLength` INCREMENTALLY on the response stream and
 * destroys the socket on the chunk that crosses it, so this is a real memory
 * bound rather than a check performed after the body is already resident.
 */
export const HIBP_MAX_RANGE_RESPONSE_BYTES = 1_048_576;
