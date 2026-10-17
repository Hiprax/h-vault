/**
 * The account-level conditions that bar a user from being served, in ONE
 * definition.
 *
 * They are evaluated at four entry points — `authController.login`,
 * `authController.login2fa`, the refresh handler, and the Passport JWT strategy
 * in `middleware/auth.ts` — and until this module existed each site spelled them
 * out for itself. That is how `login` came to be the one door with no
 * `deletionPending` check: a zombie left by a failed cascade delete could
 * complete a full sign-in, writing a `RefreshToken` row and an audit row under an
 * account mid-erasure, for the whole six-hour `tokenCleanup` window.
 *
 * ## Why this returns flags instead of throwing
 *
 * The policies genuinely differ, and flattening them would be a regression in
 * each case:
 *
 *  - `login` reads ONLY the password factor. During a password lockout it answers
 *    every UNPROVEN client exactly as it answers a wrong password, whether or not
 *    the password was right, so a lockout can never confirm a guess; a client
 *    holding a valid device proof for the account proceeds.
 *  - `login2fa` reads ONLY the second factor, and answers its lockout with a
 *    distinct `ACCOUNT_LOCKED`: the password is already proven at that step, so
 *    the distinct answer carries no oracle.
 *  - the refresh handler collapses the deletion and verification refusals into
 *    `TOKEN_INVALID` and does NOT consult either lockout: the refresh cookie is
 *    itself proof of a prior authentication, and refusing it would freeze the
 *    owner's live sessions (including the one they would use to change the
 *    password) for as long as a stranger kept guessing.
 *  - the Passport strategy answers every refusal identically (`done(null, false)`)
 *    and consults no lockout either. That site passes only the two fields it
 *    projects, which is why those fields are individually optional here.
 *
 * So the shared thing is the PREDICATE, not the response, and this returns
 * named booleans rather than one verdict: a single ordered answer would have to
 * pick a precedence, and no two of the callers share one. What an absent field
 * means is set out on {@link AccountStatusFields}, and it is not the same for
 * all of them.
 */

/**
 * The subset of a user record these conditions read. Every field is optional so
 * a caller can pass exactly what it projected.
 *
 * What an ABSENT field means differs per condition, and the difference is
 * deliberate rather than an oversight, so it is stated rather than generalised:
 *
 *  - `deletionPending`, `lockoutUntil` and `secondFactorLockout` read as "this
 *    condition does not apply". Each is a marker written only when the condition
 *    starts, so its absence and its falsehood are the same state.
 *  - `emailVerified` reads as UNVERIFIED, because it is a positive assertion and
 *    its absence is the absence of that assertion. A caller that does not project
 *    it is therefore refused rather than waved through, which is the fail-closed
 *    direction — but it means "do not read `emailUnverified` unless you projected
 *    the field" is a real rule, not a stylistic preference. `middleware/auth.ts`
 *    projects it for exactly this reason.
 *
 * The two lockouts are the ones a caller may legitimately leave out entirely, and
 * that caller must simply not read `passwordLocked`/`secondFactorLocked`, which
 * cannot distinguish "not locked" from "not asked for". `secondFactorLockout` is
 * `select: false` on the model, so a caller that reads `secondFactorLocked` must
 * have projected it by name (`login2fa` does; the one verifier re-reads it).
 */
export interface AccountStatusFields {
  deletionPending?: boolean | undefined;
  emailVerified?: boolean | undefined;
  lockoutUntil?: Date | null | undefined;
  secondFactorLockout?: { until?: Date | null | undefined } | null | undefined;
}

export interface AccountStatus {
  /**
   * A cascade delete has been requested for this account and has not finished.
   * The flag is the only durable record that the data still needs erasing, so an
   * account carrying it is mid-erasure and must not be served.
   */
  deletionPending: boolean;
  /** The address has never been confirmed, so the account is not usable yet. */
  emailUnverified: boolean;
  /** The PASSWORD factor's lockout deadline exists and has not yet passed. */
  passwordLocked: boolean;
  /** The SECOND factor's lockout deadline exists and has not yet passed. */
  secondFactorLocked: boolean;
}

/**
 * Whether a lockout deadline is still running at `now`.
 *
 * Strictly greater: a deadline that has arrived has been SERVED, and each factor
 * discharges a served lockout at its own step. `>=` would hold the account one
 * request longer for no reason and would make the boundary untestable.
 */
function isLockoutRunning(until: Date | null | undefined, now: Date): boolean {
  return until != null && until.getTime() > now.getTime();
}

/**
 * Evaluates the conditions against one user record.
 *
 * `now` is injectable so a caller that has already fixed an instant (or a test
 * that needs a deterministic boundary) evaluates the lockout against that
 * instant rather than against a second, slightly later, clock read.
 */
export function evaluateAccountStatus(
  user: AccountStatusFields,
  now: Date = new Date(),
): AccountStatus {
  // `=== true` rather than a truthiness test: the field defaults to `undefined`
  // and is only ever written as a boolean, so anything else is corruption and
  // must not be read as "pending".
  const deletionPending = user.deletionPending === true;
  const emailUnverified = user.emailVerified !== true;
  const passwordLocked = isLockoutRunning(user.lockoutUntil, now);
  const secondFactorLocked = isLockoutRunning(user.secondFactorLockout?.until, now);

  return { deletionPending, emailUnverified, passwordLocked, secondFactorLocked };
}
