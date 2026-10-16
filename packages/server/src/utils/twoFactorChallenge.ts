/**
 * The ONE place the single-use second-factor challenge is issued, checked and
 * consumed (see `models/Challenge.ts` for why it exists).
 *
 * `login` calls {@link issueTwoFactorChallenge} and signs the token it returns the
 * claims for; `login2fa` calls {@link isChallengeOpen} before it reads the code
 * and {@link consumeTwoFactorChallenge} once the code is right, BEFORE the code
 * itself is consumed. That order is deliberate: of two exchanges racing on one
 * token, the loser is refused by the challenge and keeps its code (a backup code
 * is a recovery credential, and a refused exchange must not burn one).
 */
import crypto from 'node:crypto';
import type { Types } from 'mongoose';
import { Challenge } from '../models/Challenge.js';

/** How long a challenge token lives: the five minutes `login` has always given it. */
export const TWO_FACTOR_CHALLENGE_SECONDS = 300;

/** The claims `login` signs: `jti` names the row, `iat`/`exp` are the row's own life. */
export interface TwoFactorChallengeClaims {
  jti: string;
  iat: number;
  exp: number;
}

/**
 * Writes the row a new challenge token will name, and returns the claims to sign.
 *
 * `iat` and `exp` are fixed HERE and signed as given, so the token expires at the
 * very second the row's `expiresAt` names: a token can never outlive its row (the
 * TTL index removes a row only after `expiresAt`), and a row never outlives its
 * token by more than the TTL monitor's minute.
 */
export async function issueTwoFactorChallenge(
  userId: Types.ObjectId,
  now: Date = new Date(),
): Promise<TwoFactorChallengeClaims> {
  const jti = crypto.randomUUID();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + TWO_FACTOR_CHALLENGE_SECONDS;
  await Challenge.create({ jti, userId, expiresAt: new Date(exp * 1000), consumedAt: null });
  return { jti, iat, exp };
}

/** The filter of a challenge that may still complete a sign-in. */
function openChallengeFilter(jti: string, userId: string, now: Date) {
  return { jti, userId, consumedAt: null, expiresAt: { $gt: now } };
}

/**
 * Whether the token's challenge can still complete a sign-in: it exists, belongs
 * to the account the token names, is unexpired and unconsumed.
 *
 * Asked before the code is read, so a spent token costs nothing: no code check,
 * no count on the second factor, no bcrypt. It is a READ and decides nothing on
 * its own; {@link consumeTwoFactorChallenge} is the decision.
 */
export async function isChallengeOpen(
  jti: string,
  userId: string,
  now: Date = new Date(),
): Promise<boolean> {
  const row = await Challenge.exists(openChallengeFilter(jti, userId, now)).read('primary');
  return row !== null;
}

/**
 * Consumes the challenge with ONE compare-and-set. `true` for exactly one caller
 * per challenge, ever; every other caller, concurrent or later, gets `false`.
 */
export async function consumeTwoFactorChallenge(
  jti: string,
  userId: string,
  now: Date = new Date(),
): Promise<boolean> {
  const consumed = await Challenge.findOneAndUpdate(openChallengeFilter(jti, userId, now), {
    $set: { consumedAt: now },
  }).lean();
  return consumed !== null;
}
