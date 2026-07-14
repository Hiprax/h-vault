/**
 * Process-local, per-email failed-login throttle.
 *
 * This drives ONLY the progressive login delay. It is deliberately NOT the
 * lockout driver: `User.failedLoginAttempts` / `User.lockoutUntil` remain the
 * sole, durable source of truth for locking an account.
 *
 * Why a separate counter at all? The delay must be applied identically on the
 * "this email does not exist" path and the "wrong password" path — otherwise
 * the response time itself reveals whether an account exists, which defeats the
 * dummy-bcrypt equalization in `authController.login`. A non-existent email has
 * no User row to count against, so the counter cannot live in the database.
 *
 * Trade-offs, accepted knowingly:
 *
 *   • Per-process. Under clustering each worker sees only a share of an
 *     attacker's attempts, so the delay ramps more slowly than a global counter
 *     would. Symmetry — the actual security property — is unaffected, because a
 *     worker's count never depends on whether the email exists. Lockout, which
 *     does need cluster-wide durability, stays in the database.
 *   • Bounded. `email` is unbounded attacker-supplied input, so the map is size
 *     capped with oldest-first eviction and entries expire. An attacker can
 *     therefore flood distinct emails to evict a victim's entry and reset the
 *     ramp; that weakens the delay but not the lockout, and eviction is blind to
 *     account existence, so it cannot leak existence either.
 *   • Pruned lazily, never on a timer. A `setInterval` would hold the event loop
 *     open, interfering with graceful shutdown and hanging test runs.
 */

/** How long a recorded attempt counts toward the delay (sliding). */
export const LOGIN_THROTTLE_TTL_MS = 15 * 60 * 1000;

/** Hard cap on tracked emails; the oldest entry is evicted beyond this. */
export const LOGIN_THROTTLE_MAX_ENTRIES = 10_000;

/** Minimum spacing between full sweeps for expired entries. */
const PRUNE_INTERVAL_MS = 60 * 1000;

interface ThrottleEntry {
  count: number;
  expiresAt: number;
}

/**
 * Insertion-ordered, so the first key is always the least recently recorded —
 * which is what makes oldest-first eviction a plain `keys().next()`.
 */
const attempts = new Map<string, ThrottleEntry>();

let lastPrunedAt = 0;

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function pruneExpired(now: number): void {
  if (now - lastPrunedAt < PRUNE_INTERVAL_MS) return;
  lastPrunedAt = now;

  for (const [key, entry] of attempts) {
    if (entry.expiresAt <= now) {
      attempts.delete(key);
    }
  }
}

/**
 * Records one failed login attempt for `email` and returns the running count,
 * which the caller feeds to `getProgressiveDelay`. An expired entry restarts
 * the count at 1.
 */
export function recordFailedLoginAttempt(email: string): number {
  const key = normalizeEmail(email);
  const now = Date.now();
  pruneExpired(now);

  const existing = attempts.get(key);
  const count = existing && existing.expiresAt > now ? existing.count + 1 : 1;

  // Delete before set so the key moves to the end of the insertion order and
  // the eviction below always drops the least recently recorded email.
  attempts.delete(key);
  attempts.set(key, { count, expiresAt: now + LOGIN_THROTTLE_TTL_MS });

  while (attempts.size > LOGIN_THROTTLE_MAX_ENTRIES) {
    const oldest = attempts.keys().next();
    if (oldest.done) break;
    attempts.delete(oldest.value);
  }

  return count;
}

/** Clears the count for `email` (called once credentials verify successfully). */
export function resetLoginAttempts(email: string): void {
  attempts.delete(normalizeEmail(email));
}

/** Current count for `email`; 0 when untracked or expired. */
export function peekLoginAttempts(email: string): number {
  const entry = attempts.get(normalizeEmail(email));
  if (!entry || entry.expiresAt <= Date.now()) return 0;
  return entry.count;
}

/** Number of tracked emails (exposed for the eviction/pruning tests). */
export function loginThrottleSize(): number {
  return attempts.size;
}

/** Drops all tracked state. */
export function clearLoginThrottle(): void {
  attempts.clear();
  lastPrunedAt = 0;
}
