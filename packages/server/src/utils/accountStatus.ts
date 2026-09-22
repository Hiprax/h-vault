/**
 * The three account-level conditions that bar a user from being served, in ONE
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
 * The three policies genuinely differ, and flattening them would be a
 * regression in each case:
 *
 *  - `login` must evaluate the lockout BEFORE the verification check and must
 *    answer `ACCOUNT_LOCKED` only to a caller that supplied the correct password
 *    — telling a wrong-password caller that the account is locked is an
 *    enumeration oracle, and the surrounding branches equalize their timing by
 *    hand.
 *  - the refresh handler collapses the deletion and verification refusals into
 *    `TOKEN_INVALID` and answers the lockout with a 403 `ACCOUNT_LOCKED`.
 *  - the Passport strategy answers every refusal identically (`done(null, false)`)
 *    and deliberately does NOT consult the lockout at all: an access token lives
 *    fifteen minutes and the refresh gate is where a lockout ends the session.
 *    That site therefore passes only the two fields it projects, which is why
 *    those fields are individually optional here.
 *
 * So the shared thing is the PREDICATE, not the response, and this returns three
 * named booleans rather than one verdict: a single ordered answer would have to
 * pick a precedence, and no two of the four callers share one. A caller that does
 * not supply `lockoutUntil` must simply not read `lockedOut`, which cannot
 * distinguish "not locked" from "not asked for".
 */

/**
 * The subset of a user record these conditions read. Every field is optional so
 * a caller can pass exactly what it projected; a field that is absent reads as
 * "this condition does not apply".
 */
export interface AccountStatusFields {
  deletionPending?: boolean | undefined;
  emailVerified?: boolean | undefined;
  lockoutUntil?: Date | null | undefined;
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
  /** A lockout deadline exists and has not yet passed. */
  lockedOut: boolean;
}

/**
 * Evaluates the three conditions against one user record.
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
  // Strictly greater: a deadline that has arrived has been SERVED, and `login`
  // discharges it on the next correct password. `>=` would hold the account one
  // request longer for no reason and would make the boundary untestable.
  const lockedOut = user.lockoutUntil != null && user.lockoutUntil.getTime() > now.getTime();

  return { deletionPending, emailUnverified, lockedOut };
}
