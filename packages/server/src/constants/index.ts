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
 * `maxBodyLength` on the outbound `axios` call. It is one of the two outbound
 * HTTP calls the server makes; the other, the release check in
 * `utils/updateCheck.ts`, is bounded the same way.
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

// ── Release notes and the update check ──────────────────────────────

/**
 * The release an account with no stored release-notes watermark is treated as
 * having seen: the last release before the notes existed. Such an account is
 * shown every release after it once, and is caught up from then on.
 *
 * Fixed, never derived from the running version: an account created before the
 * feature must see the release that introduced it however many releases later
 * it first signs in.
 */
export const RELEASE_NOTES_BASELINE_VERSION = '0.14.1';

/**
 * Where the update check asks for the newest release. The repository part is
 * configuration (`UPDATE_CHECK_REPOSITORY`); the host is not, so no setting can
 * point the server's outbound request at another host.
 */
export const UPDATE_CHECK_API_BASE_URL = 'https://api.github.com';
/** The REST API version the request asks for; supported by GitHub until at least 2028. */
export const UPDATE_CHECK_API_VERSION = '2026-03-10';
/** GitHub refuses a request without a User-Agent. Names the software, never its version. */
export const UPDATE_CHECK_USER_AGENT = 'H-Vault-Update-Check';
/** The largest release document accepted. The biggest published so far is under 100 KB. */
export const UPDATE_CHECK_MAX_RESPONSE_BYTES = 1_048_576;
/**
 * Idle limit on the socket, and a hard limit on the whole request. The first is
 * axios's `timeout`, which in Node only fires while NOTHING arrives, so a server
 * trickling one byte at a time would outlive it; the second is an abort signal
 * that ends the request however slowly it is progressing.
 */
export const UPDATE_CHECK_SOCKET_TIMEOUT_MS = 10_000;
export const UPDATE_CHECK_TOTAL_TIMEOUT_MS = 15_000;
/** How often the scheduled check runs. Two requests a day is far under GitHub's 60 an hour. */
export const UPDATE_CHECK_INTERVAL_HOURS = 12;
/**
 * The first check after a boot waits this long, plus a random share of
 * `UPDATE_CHECK_BOOT_JITTER_MS`, so a fleet restarted together does not ask at
 * the same second, and a crash-looping server does not ask on every start.
 */
export const UPDATE_CHECK_BOOT_DELAY_MS = 60_000;
export const UPDATE_CHECK_BOOT_JITTER_MS = 300_000;
/**
 * How long a successful check is trusted. Past this, the state reads `unknown`
 * rather than `current`: "you are up to date" is a claim the server only makes
 * when it recently asked.
 */
export const UPDATE_CHECK_FRESHNESS_MS = 72 * 60 * 60 * 1000;
/**
 * The shortest gap between two requests to GitHub, whoever asks. A "Check now"
 * inside it answers from the stored state, so no number of clicks or users can
 * spend the host's unauthenticated budget.
 */
export const UPDATE_CHECK_MIN_INTERVAL_MS = 5 * 60 * 1000;
/** JobLock lease for one check: generous against a 15 s request. */
export const UPDATE_CHECK_LOCK_TTL_MS = 2 * 60 * 1000;
/** The repository whose releases the update check reads unless configured otherwise. */
export const DEFAULT_UPDATE_CHECK_REPOSITORY = 'Hiprax/h-vault';
/**
 * `owner/name` as GitHub spells them: an owner of up to 39 letters, digits and
 * hyphens starting with a letter or digit, and a name of letters, digits, `.`,
 * `_` and `-`. Nothing that could leave the URL path segment it is placed in.
 */
export const GITHUB_REPOSITORY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
/** The most addresses `UPDATE_NOTIFY_EMAILS` accepts. */
export const MAX_UPDATE_NOTIFY_EMAILS = 10;
