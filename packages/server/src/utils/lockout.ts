/**
 * The failed-authentication brake, per FACTOR, in ONE module.
 *
 * Two factors, two states. The PASSWORD factor keeps the four legacy top-level
 * fields (`failedLoginAttempts`, `lockoutUntil`, `lockoutEpisodeId`,
 * `lockoutNotifiedAt`) under their old names; the SECOND factor keeps the same
 * four facts in `User.secondFactorLockout`. A wrong password writes only the
 * first, a wrong TOTP or backup code only the second, and each factor is read
 * only by its own step. One shared counter is what let ten wrong codes refuse
 * the CORRECT password with a distinct `ACCOUNT_LOCKED`, which confirmed the
 * password to whoever presented it.
 *
 * Every write the brake makes lives here, so the two controllers that count
 * failures (`authController` for the password and the 2FA step,
 * `utils/secondFactor.ts` for every code check) cannot drift apart again, and
 * every discharge goes through {@link lockoutClearUpdate} or its document twin.
 */
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import type mongoose from 'mongoose';
import type { HydratedDocument, UpdateQuery } from 'mongoose';
import { LOCKOUT_DURATION_MINUTES, MAX_LOGIN_ATTEMPTS, maskEmail } from '@hvault/shared';
import { config } from '../config/index.js';
import { User } from '../models/User.js';
import type { IUser } from '../models/User.js';
import { sendAccountUnlockEmail } from './email.js';
import { notifySecurityEventLater } from './securityNotifications.js';
import { derivePurposeKey } from './token.js';
import { createModuleLogger } from './logger.js';

const logger = createModuleLogger('lockout');

/** Which factor's state a failure, a lock or a discharge belongs to. */
export type LockoutFactor = 'password' | 'second_factor';

/** Every factor an unlock link may name. The claim is checked against this list. */
export const LOCKOUT_FACTORS: readonly LockoutFactor[] = ['password', 'second_factor'];

const LOCKOUT_DURATION_MS = LOCKOUT_DURATION_MINUTES * 60 * 1000;

/**
 * How often a lockout that is already running may be pushed further out.
 *
 * During a password lockout every unproven attempt extends the deadline, so the
 * brake holds for as long as guessing continues, but at most once per this
 * interval: the extension is a conditional write whose filter only matches a
 * deadline at least this old, so a flood of attempts costs the account ONE
 * modified User write a minute rather than one per request. Unbounded User
 * writes would also abort the owner's own vault-key rotation, whose transaction
 * writes the User document last.
 */
const LOCKOUT_EXTENSION_INTERVAL_MS = 60 * 1000;

/**
 * How long an emailed unlock link stays usable.
 *
 * ONE definition, because three things have to agree on it: the JWT's own
 * `expiresIn`, the re-mail decision in {@link lockFactor} (which asks whether
 * the outstanding token will still verify when the new lockout ends), and the
 * sentence a user reads in `utils/email.ts` — "This link will expire in 1 hour".
 * The last of those is prose and no test can pin it, so the value must not be
 * changed here without changing it there.
 *
 * It must stay STRICTLY GREATER than `LOCKOUT_DURATION_MS`. The link is the
 * shortcut out of a lockout, so a token that expires before the lockout it was
 * minted for would leave the owner waiting out the full window with a dead link
 * in their inbox — the failure this whole mechanism exists to prevent.
 */
const UNLOCK_TOKEN_TTL_MINUTES = 60;
const UNLOCK_TOKEN_TTL_MS = UNLOCK_TOKEN_TTL_MINUTES * 60 * 1000;

/** The payload an unlock link carries. `factor` is absent on links minted before it existed. */
export interface JwtUnlockPayload {
  userId: string;
  purpose: string;
  stateHash: string;
  factor?: LockoutFactor;
}

interface FactorPaths {
  attempts: string;
  until: string;
  episode: string;
  notified: string;
  /** The top-level path a projection must name to read the three below it. */
  projection: string;
}

const FACTOR_PATHS: Record<LockoutFactor, FactorPaths> = {
  password: {
    attempts: 'failedLoginAttempts',
    until: 'lockoutUntil',
    episode: 'lockoutEpisodeId',
    notified: 'lockoutNotifiedAt',
    projection: '+lockoutEpisodeId +lockoutNotifiedAt',
  },
  second_factor: {
    attempts: 'secondFactorLockout.failedAttempts',
    until: 'secondFactorLockout.until',
    episode: 'secondFactorLockout.episodeId',
    notified: 'secondFactorLockout.notifiedAt',
    projection: '+secondFactorLockout',
  },
};

/** One factor's state, read off a loaded user document whatever its storage. */
export interface FactorState {
  failedAttempts: number;
  until?: Date | undefined;
  episodeId?: string | undefined;
}

export function factorStateOf(
  user: Pick<
    IUser,
    'failedLoginAttempts' | 'lockoutUntil' | 'lockoutEpisodeId' | 'secondFactorLockout'
  >,
  factor: LockoutFactor,
): FactorState {
  if (factor === 'password') {
    return {
      failedAttempts: user.failedLoginAttempts,
      until: user.lockoutUntil,
      episodeId: user.lockoutEpisodeId,
    };
  }
  const state = user.secondFactorLockout;
  return {
    failedAttempts: state?.failedAttempts ?? 0,
    until: state?.until,
    episodeId: state?.episodeId,
  };
}

/**
 * The update that ends one factor's lock episode, as ONE definition per factor.
 *
 * A lockout is four facts, not one — the counter, the deadline, the episode
 * identity the emailed link is bound to, and the timestamp of the link mailed for
 * it — and every site that discharges a lockout has to clear all four. Leaving
 * the episode behind would keep a spent unlock link alive; leaving the mail
 * timestamp behind would suppress the next episode's mail. The discharge sites
 * are: `login`'s served-deadline discharge, the completion of a sign-in (only
 * for a factor that is not locked at that moment: a client that proved itself
 * past a running lockout does not clear what strangers built), the one
 * verifier's served second-factor discharge, `unlockAccount`, and — through the
 * document-shaped twin below — `resetPassword`.
 *
 * A fresh object per call: Mongoose may annotate the update it is handed, and a
 * shared literal would carry that annotation into the next caller.
 */
export function lockoutClearUpdate(factor: LockoutFactor): UpdateQuery<IUser> {
  if (factor === 'second_factor') {
    return { $unset: { secondFactorLockout: 1 } };
  }
  return {
    $set: { failedLoginAttempts: 0 },
    $unset: { lockoutUntil: 1, lockoutEpisodeId: 1, lockoutNotifiedAt: 1 },
  };
}

/**
 * The same discharge applied to a loaded document, for a caller already saving
 * other fields in the same write (`resetPassword`) or one that must correct the
 * copy it loaded (`login`'s served discharge). Change it together with
 * {@link lockoutClearUpdate}.
 */
export function clearLockoutStateOnDocument(
  user: HydratedDocument<IUser>,
  factor: LockoutFactor,
): void {
  if (factor === 'second_factor') {
    user.secondFactorLockout = undefined;
    return;
  }
  user.failedLoginAttempts = 0;
  user.lockoutUntil = undefined;
  user.lockoutEpisodeId = undefined;
  user.lockoutNotifiedAt = undefined;
}

function generateStateHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** The episode an unlock link for `factor` must name, read off a loaded document. */
export function unlockEpisodeOf(
  user: Pick<IUser, 'lockoutEpisodeId' | 'secondFactorLockout'>,
  factor: LockoutFactor,
): string | undefined {
  return factor === 'password' ? user.lockoutEpisodeId : user.secondFactorLockout?.episodeId;
}

/** Whether `stateHash` names `episodeId`. A missing episode matches nothing. */
export function unlockTokenNamesEpisode(stateHash: string, episodeId: string | undefined): boolean {
  return episodeId !== undefined && episodeId !== '' && stateHash === generateStateHash(episodeId);
}

function signUnlockToken(userId: string, episodeId: string, factor: LockoutFactor): string {
  return jwt.sign(
    {
      userId,
      purpose: 'account_unlock',
      // Bound to the EPISODE, never to the deadline: the deadline moves on every
      // re-lock and the identity does not.
      stateHash: generateStateHash(episodeId),
      // Signed, so a link can only ever discharge the factor it was mailed for.
      factor,
    } satisfies JwtUnlockPayload,
    derivePurposeKey(config.JWT_REFRESH_SECRET, 'account_unlock'),
    { algorithm: 'HS256', expiresIn: UNLOCK_TOKEN_TTL_MS / 1000 },
  );
}

/**
 * Starts or extends `factor`'s lock episode, then guarantees a usable unlock
 * link is outstanding for it.
 *
 * ## The three writes, and why each is a conditional update rather than a read
 *
 * 1. **Start-or-extend the episode, in ONE statement.** An aggregation-pipeline
 *    update, so the deadline and the episode identity are decided in a single
 *    atomic write and the account is never observable as locked with no episode.
 *    `$ifNull` keeps a running episode's identity and mints one only when the
 *    field is null or missing, so exactly ONE of N concurrent threshold-crossing
 *    requests starts the episode and every other one inherits it. The identity is
 *    never replaced, which is what makes the link already in the owner's inbox
 *    survive a re-lock. `extraFilter` narrows the write: the locked-branch
 *    extension passes a filter that matches only a deadline at least
 *    {@link LOCKOUT_EXTENSION_INTERVAL_MS} old, and when it matches nothing there
 *    is nothing more to do.
 * 2. **Read back which episode won.** Pinned to the PRIMARY: `MONGODB_URI` is the
 *    operator's, and a `readPreference=secondaryPreferred` on it would make this
 *    a read that may predate the write above — the account would be locked with
 *    NO unlock link ever mailed. The episode path is `select: false`, so it is
 *    asked for by name.
 * 3. **Claim the mail.** A link is "outstanding" only while it will still verify
 *    at the moment the new lockout ends, i.e. while
 *    `notifiedAt >= until - UNLOCK_TOKEN_TTL_MS`. The claim is a filter rather
 *    than a read-then-write so exactly one concurrent request wins it, and it is
 *    scoped to the episode it would mail for, so a discharge in the gap declines
 *    it instead of stamping a timestamp that would silence the next episode.
 *
 * Several live tokens can name one episode and that is harmless: they are the
 * same capability, and the first one spent clears the episode and kills the rest.
 */
async function lockFactor(
  userId: mongoose.Types.ObjectId,
  email: string,
  factor: LockoutFactor,
  extraFilter: Record<string, unknown> = {},
): Promise<void> {
  const paths = FACTOR_PATHS[factor];
  const now = new Date();
  const until = new Date(now.getTime() + LOCKOUT_DURATION_MS);

  const locked = await User.updateOne(
    { _id: userId, ...extraFilter },
    [
      {
        $set: {
          [paths.until]: until,
          [paths.episode]: { $ifNull: [`$${paths.episode}`, crypto.randomUUID()] },
        },
      },
    ],
    // Mongoose refuses an update pipeline unless it is asked for by name, because
    // it does not cast one. Nothing here needs casting: `until` is already a
    // `Date` and the minted identity is already a string.
    { updatePipeline: true },
  );
  if (locked.matchedCount === 0) return;

  const current = await User.findById(userId).read('primary').select(paths.projection);
  // Deleted, or discharged since that write: there is no episode to name, and a
  // link bound to the empty string would match every account with no episode.
  const episodeId = current ? unlockEpisodeOf(current, factor) : undefined;
  if (!episodeId) return;

  const claimed = await User.findOneAndUpdate(
    {
      _id: userId,
      [paths.episode]: episodeId,
      $or: [
        { [paths.notified]: null },
        { [paths.notified]: { $lt: new Date(until.getTime() - UNLOCK_TOKEN_TTL_MS) } },
      ],
    },
    { $set: { [paths.notified]: now } },
  );
  if (!claimed) return;

  logger.warn('Account factor locked due to too many failed attempts', {
    userId: userId.toString(),
    email: maskEmail(email),
    factor,
  });

  const unlockToken = signUnlockToken(userId.toString(), episodeId, factor);
  // A second-factor lockout means the master password was entered correctly, which
  // is a security notice of its own (F-26): sent through the ONE notification
  // helper, with no link, from this same claim, so it goes once per link lifetime
  // like the link itself. The link is the functional half and stays a mail of its
  // own. Neither is awaited: this runs inside a sign-in request.
  if (factor === 'second_factor') {
    notifySecurityEventLater(userId, 'second_factor_lockout');
  }
  // Fire-and-forget: the response must not wait on SMTP, and a send failure must
  // not turn a refusal into a 500.
  void sendAccountUnlockEmail(email, unlockToken, factor).then((result) => {
    if (!result.success) {
      logger.error('Failed to send account unlock email', {
        userId: userId.toString(),
        email: maskEmail(email),
        factor,
        error: result.message,
      });
    }
  });
}

/**
 * Records ONE failed attempt on `factor`'s state, locks that factor when the
 * counter reaches {@link MAX_LOGIN_ATTEMPTS}, and returns the counter.
 *
 * The increment is capped: it matches only a counter below the threshold, so a
 * counter never grows past MAX however long guessing continues. For the
 * password, a counter left AT the threshold by a lockout that expired unserved
 * (nobody presented the right credential after the deadline) re-locks on the
 * next failure, which is the brake working. A served lockout is discharged at that factor's own step:
 * the password's only by a correct password, the second factor's by the next
 * code check (the master password is already proven there), before the code
 * is read.
 *
 * Called only for a factor that is NOT locked: a locked password answers
 * unproven clients through {@link extendPasswordLockout}, and a locked second
 * factor refuses before a code is read.
 */
export async function registerFailedAuthAttempt(
  userId: mongoose.Types.ObjectId,
  email: string,
  factor: LockoutFactor,
): Promise<number> {
  const paths = FACTOR_PATHS[factor];
  const incremented = await User.findOneAndUpdate(
    {
      _id: userId,
      $or: [{ [paths.attempts]: { $lt: MAX_LOGIN_ATTEMPTS } }, { [paths.attempts]: null }],
    },
    { $inc: { [paths.attempts]: 1 } },
    { returnDocument: 'after' },
  ).select(paths.projection);

  // No match means the counter is already at the cap (or the account is gone, in
  // which case the lock below matches nothing and returns).
  const attempts = incremented
    ? factorStateOf(incremented, factor).failedAttempts
    : MAX_LOGIN_ATTEMPTS;
  if (attempts < MAX_LOGIN_ATTEMPTS) return attempts;

  await lockFactor(userId, email, factor);
  return attempts;
}

/**
 * The bounded accounting of an unproven login during a running PASSWORD
 * lockout: no increment (the counter is already at the cap), and the deadline
 * pushed out at most once per {@link LOCKOUT_EXTENSION_INTERVAL_MS}, so the
 * lockout lasts as long as the guessing does while costing one modified write a
 * minute. When the extension happens it also re-runs the mail claim, so a usable
 * link stays outstanding however long the lockout is renewed (the claim itself
 * limits that to one mail per `UNLOCK_TOKEN_TTL_MS - LOCKOUT_DURATION_MS`).
 */
export async function extendPasswordLockout(
  userId: mongoose.Types.ObjectId,
  email: string,
): Promise<void> {
  const threshold = new Date(Date.now() + LOCKOUT_DURATION_MS - LOCKOUT_EXTENSION_INTERVAL_MS);
  await lockFactor(userId, email, 'password', { lockoutUntil: { $lt: threshold } });
}

/**
 * The same awaited round trip {@link extendPasswordLockout} makes, for a login
 * that named no account: a conditional write that cannot match anything, so an
 * unregistered address costs what a locked one does and writes nothing.
 */
export async function extendNothing(): Promise<void> {
  await User.updateOne(
    { _id: null, lockoutUntil: { $lt: new Date(0) } },
    [{ $set: { lockoutUntil: new Date(0) } }],
    { updatePipeline: true },
  );
}

/**
 * Discharges a SERVED second-factor lockout: the deadline has passed while the
 * counter still sits at the cap. Conditional on the deadline being past, so a
 * concurrent re-lock is never wiped. Without it the first wrong code after the
 * wait would re-lock at once, and TOTP fails systematically (a drifted clock, a
 * replayed step), so a user would be kept out by their own phone.
 */
export async function dischargeServedSecondFactor(
  userId: mongoose.Types.ObjectId,
  now: Date,
): Promise<void> {
  await User.updateOne(
    { _id: userId, 'secondFactorLockout.until': { $lte: now } },
    lockoutClearUpdate('second_factor'),
  );
}

/**
 * Discharges `factor`'s lockout for the unlock link that named `episodeId`, and
 * reports whether it did. The write is conditioned on that episode still being
 * the stored one, so a link verified against one episode never clears another:
 * a second use of the same link (a double click, a replay) finds the episode
 * already gone and discharges nothing.
 */
export async function dischargeUnlockedEpisode(
  userId: mongoose.Types.ObjectId,
  factor: LockoutFactor,
  episodeId: string,
): Promise<boolean> {
  const result = await User.updateOne(
    // Never on an account being erased: an unlock restores nothing there, and the
    // erasure must find the row as it left it.
    { _id: userId, [FACTOR_PATHS[factor].episode]: episodeId, deletionPending: { $ne: true } },
    lockoutClearUpdate(factor),
  );
  return result.matchedCount === 1;
}

/**
 * Whether a factor's stored deadline is absent or already passed: the filter that
 * makes a completion discharge conditional on the lockout still not running when
 * the write lands, rather than when the request read the account.
 */
function notRunning(untilPath: string, now: Date): Record<string, unknown> {
  return {
    $or: [
      { [untilPath]: { $exists: false } },
      { [untilPath]: null },
      { [untilPath]: { $lte: now } },
    ],
  };
}

/**
 * Discharges what a COMPLETED authentication clears: each factor's counter,
 * EXCEPT a factor whose lockout is running.
 *
 * A client can complete a sign-in past a running lockout only by proving itself
 * (a device proof past the password lockout, the password step before a later
 * password lockout, a trusted device past a second-factor lockout); the failures
 * that built that lockout were not its own, and clearing them would hand whoever
 * made them a fresh budget. So a factor locked when the request read the account
 * is left alone, and each clear is ALSO conditioned on the lockout still not
 * running when the write lands: a lockout that starts while this request is in
 * flight survives it. A lockout that has merely been SERVED is discharged at its
 * own step before a sign-in gets here.
 */
export async function dischargeOnCompletion(
  user: Pick<IUser, '_id' | 'failedLoginAttempts' | 'lockoutUntil' | 'secondFactorLockout'>,
  status: { passwordLocked: boolean; secondFactorLocked: boolean },
  now: Date = new Date(),
): Promise<void> {
  if (!status.passwordLocked && (user.failedLoginAttempts > 0 || user.lockoutUntil != null)) {
    await User.updateOne(
      { _id: user._id, ...notRunning(FACTOR_PATHS.password.until, now) },
      lockoutClearUpdate('password'),
    );
  }
  if (!status.secondFactorLocked && user.secondFactorLockout != null) {
    await User.updateOne(
      { _id: user._id, ...notRunning(FACTOR_PATHS.second_factor.until, now) },
      lockoutClearUpdate('second_factor'),
    );
  }
}
