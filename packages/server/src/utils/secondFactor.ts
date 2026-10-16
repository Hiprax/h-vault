/**
 * The ONE second-factor verifier.
 *
 * Every site that accepts a TOTP or backup code goes through
 * {@link verifySecondFactor}: `login2fa`, `verify2fa`, `disable2fa`,
 * `regenerateBackupCodes` and `deleteAccount`. Before it existed each site
 * validated codes for itself: none of the three signed-in sites counted a wrong
 * code, so a session holder who knew the master password could guess codes at
 * `disable2fa` without ever touching the brake, and two of them (`disable2fa`,
 * `deleteAccount`) never consumed a right one, so a code spent there could be
 * spent again at `login2fa` inside the same step.
 *
 * What the verifier decides, per site:
 *
 *  - **The secret.** `verify2fa` checks the PENDING secret its setup step minted;
 *    every other site checks the enrolled one.
 *  - **The lock.** Every site but `verify2fa` refuses while the second factor is
 *    locked, WITHOUT reading the code and without counting (a refusal is not a
 *    failure). A lockout whose deadline has passed is discharged first: every
 *    site has proven the master password before it asks for a code, so this is
 *    the same "served lockout" discharge the password step performs, and without
 *    it the first mistyped code after the wait would re-lock at once.
 *  - **The count.** A wrong code counts on the second factor's own state at every
 *    site but `verify2fa`. Enrolment is exempt: its secret is known to whoever
 *    called `setup2fa` with the master password moments ago, so a failure there
 *    guesses nothing, and counting it would lock out users who mistype while
 *    enrolling.
 *  - **Backup codes** are accepted only where the caller says so (`login2fa`).
 *
 * What it does NOT do is write the success. A correct code is consumed by a
 * compare-and-set, and three callers already make a compound atomic write that
 * the consumption must be part of (`verify2fa` enables 2FA in it,
 * `regenerateBackupCodes` stores the new codes, `disable2fa` removes the factor).
 * Splitting that write in two would reopen the race it closes. So the verifier
 * RETURNS the fragment — `casFilter` and `casUpdate` — and each caller merges it
 * into its own single write with {@link withSecondFactorCas}; a write that then
 * matches nothing means another request spent the code first.
 */
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import type { Types } from 'mongoose';
import { twoFactorEncryptionKey } from '../config/index.js';
import { User } from '../models/User.js';
import { cryptoManager } from './cryptoManager.js';
import { evaluateAccountStatus } from './accountStatus.js';
import { dischargeServedSecondFactor, registerFailedAuthAttempt } from './lockout.js';

/** Every site that verifies a second factor. */
type SecondFactorSite =
  'login2fa' | 'verify2fa' | 'disable2fa' | 'regenerateBackupCodes' | 'deleteAccount';

/** The fields of a user the verifier reads. Callers pass the document they loaded. */
export interface SecondFactorSubject {
  _id: Types.ObjectId;
  email: string;
  twoFactorSecret?: string | undefined;
  pendingTwoFactorSecret?: string | undefined;
  backupCodes?: string[] | undefined;
  lastTotpTimestamp?: number | undefined;
}

export interface VerifySecondFactorOptions {
  site: SecondFactorSite;
  /** Whether a backup code may stand in for a TOTP code at this site. */
  acceptBackupCodes: boolean;
}

/** A filter or update fragment, keyed by path or operator. */
type Fragment = Record<string, unknown>;

export type SecondFactorVerdict =
  | { ok: true; kind: 'totp' | 'backup_code'; casFilter: Fragment; casUpdate: Fragment }
  | { ok: false; reason: 'locked' }
  | {
      ok: false;
      reason: 'invalid';
      /** The second factor's counter after this failure (0 where nothing counts). */
      attempts: number;
    };

const TOTP_PERIOD_SECONDS = 30;

/**
 * The shape of a TOTP code: six digits, exactly what the authenticator shows.
 *
 * The verifier checks a code as the ONE kind its shape can be (I-10). A six-digit
 * string is never a backup code (those are sixteen hexadecimal characters, and
 * have been since the first release), so it is checked as a TOTP code only and a
 * wrong one costs no bcrypt compare; anything else can never equal a six-digit
 * TOTP code, so it is checked as a backup code only and the TOTP secret is not
 * even decrypted. No code that could match before is refused now.
 */
const TOTP_CODE_PATTERN = /^\d{6}$/;

/**
 * Finds which stored backup code `code` is, or -1.
 *
 * Always compares against EVERY stored hash, so the response time does not say
 * which position matched.
 */
export async function findMatchingBackupCodeIndex(
  code: string,
  hashedCodes: string[],
): Promise<number> {
  let matchIndex = -1;
  for (let i = 0; i < hashedCodes.length; i++) {
    const hashed = hashedCodes[i];
    if (hashed !== undefined && (await bcrypt.compare(code, hashed))) {
      matchIndex = i;
    }
  }
  return matchIndex;
}

/**
 * Checks `code` for `user` at `site`, counting a failure where the site counts.
 * See the module comment for the per-site rules. Never writes a success.
 */
export async function verifySecondFactor(
  user: SecondFactorSubject,
  code: string,
  { site, acceptBackupCodes }: VerifySecondFactorOptions,
): Promise<SecondFactorVerdict> {
  const enrolment = site === 'verify2fa';
  const now = new Date();

  if (!enrolment) {
    // Read afresh and from the primary rather than off the caller's document:
    // the state is `select: false`, and a caller that forgot to project it would
    // otherwise read "not locked" for ever.
    const state = await User.findById(user._id)
      .read('primary')
      .select('+secondFactorLockout')
      .lean();
    const lockout = state?.secondFactorLockout;
    if (evaluateAccountStatus({ secondFactorLockout: lockout }, now).secondFactorLocked) {
      return { ok: false, reason: 'locked' };
    }
    if (lockout?.until) {
      await dischargeServedSecondFactor(user._id, now);
    }
  }

  const secretCiphertext = enrolment ? user.pendingTwoFactorSecret : user.twoFactorSecret;
  const totpShaped = TOTP_CODE_PATTERN.test(code);
  let verdict: SecondFactorVerdict | null = null;

  if (totpShaped && secretCiphertext) {
    const secret = cryptoManager.decryptTextSync(secretCiphertext, twoFactorEncryptionKey);
    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: TOTP_PERIOD_SECONDS,
      secret: Secret.fromBase32(secret),
    });
    // window: 1 allows ±1 time step (±30s) to tolerate minor clock drift.
    const delta = totp.validate({ token: code, window: 1, timestamp: now.getTime() });
    if (delta !== null) {
      const step = Math.floor(now.getTime() / 1000 / TOTP_PERIOD_SECONDS) + delta;
      // A step at or before the last one accepted is a replay: already spent.
      const spent = user.lastTotpTimestamp != null && step <= user.lastTotpTimestamp;
      if (!spent) {
        verdict = {
          ok: true,
          kind: 'totp',
          casFilter: {
            // Bound to the exact secret the code was checked against, so a
            // disable (which removes it) or a re-enrolment (which replaces it)
            // landing between this check and the caller's write refuses the write.
            ...(enrolment
              ? { twoFactorEnabled: false, pendingTwoFactorSecret: secretCiphertext }
              : { twoFactorEnabled: true, twoFactorSecret: secretCiphertext }),
            // The replay compare-and-set: only a step strictly after the stored one.
            $or: [
              { lastTotpTimestamp: { $exists: false } },
              { lastTotpTimestamp: null },
              { lastTotpTimestamp: { $lt: step } },
            ],
          },
          casUpdate: { $set: { lastTotpTimestamp: step } },
        };
      }
    }
  }

  const storedCodes = user.backupCodes ?? [];
  if (!totpShaped && acceptBackupCodes && storedCodes.length > 0) {
    const index = await findMatchingBackupCodeIndex(code, storedCodes);
    const matched = storedCodes[index];
    if (matched !== undefined) {
      verdict = {
        ok: true,
        kind: 'backup_code',
        // Single use through the write itself: the element must still be there.
        casFilter: { twoFactorEnabled: true, backupCodes: matched },
        casUpdate: { $pull: { backupCodes: matched } },
      };
    }
  }

  if (verdict !== null) return verdict;
  if (enrolment) return { ok: false, reason: 'invalid', attempts: 0 };

  const attempts = await registerFailedAuthAttempt(user._id, user.email, 'second_factor');
  return { ok: false, reason: 'invalid', attempts };
}

/**
 * Merges a successful verdict's compare-and-set into a caller's own write, so the
 * code is consumed by the same single atomic statement that does the site's work.
 *
 * Operators are merged path by path. Where the caller's update `$unset`s a path
 * the fragment would `$set` (`disable2fa` removes `lastTotpTimestamp` together
 * with the secret), the caller's `$unset` wins: the fragment's FILTER has already
 * made the write conditional on the step being unspent, and the write that
 * follows removes the factor the step belonged to. Filters are merged so that
 * both sides' conditions hold: two `$or` clauses are combined under `$and` rather
 * than one silently replacing the other.
 */
export function withSecondFactorCas(
  filter: Fragment,
  update: Record<string, Fragment>,
  verdict: Extract<SecondFactorVerdict, { ok: true }>,
): { filter: Fragment; update: Record<string, Fragment> } {
  const merged: Record<string, Fragment> = { ...update };
  for (const [operator, paths] of Object.entries(verdict.casUpdate)) {
    merged[operator] = { ...(merged[operator] ?? {}), ...(paths as Fragment) };
  }
  const unset = merged.$unset;
  const set = merged.$set;
  if (unset && set) {
    merged.$set = Object.fromEntries(
      Object.entries(set).filter(([path]) => !Object.hasOwn(unset, path)),
    );
  }
  const callerOr = filter.$or;
  const fragmentOr = verdict.casFilter.$or;
  if (callerOr === undefined || fragmentOr === undefined) {
    return { filter: { ...filter, ...verdict.casFilter }, update: merged };
  }
  const { $or: _callerOr, $and: callerAnd, ...callerRest } = filter;
  const { $or: _fragmentOr, ...fragmentRest } = verdict.casFilter;
  // A caller's own `$and` is kept, extended by the two `$or` clauses.
  const and = Array.isArray(callerAnd) ? (callerAnd as unknown[]) : [];
  return {
    filter: {
      ...callerRest,
      ...fragmentRest,
      $and: [...and, { $or: callerOr }, { $or: fragmentOr }],
    },
    update: merged,
  };
}
