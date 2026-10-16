/**
 * The second-factor challenge is single-use (I-01), and the code's shape picks
 * the one branch that can match it (I-10).
 *
 * I-01. `login` answers a 2FA account's proven password with a `tempToken`, a
 * signed JWT valid for five minutes. A signature alone let that token be
 * exchanged for a session as many times as its life allowed: each exchange still
 * needed a correct code, so it was never a bypass, but one proof of the master
 * password bought any number of sessions. The token now names a row in the
 * `challenges` collection (its `jti`), and the first exchange that presents a
 * correct code consumes that row with ONE compare-and-set, so every later
 * presentation of the same token, an OLDER token after a newer one was used, and
 * the loser of two concurrent exchanges are all refused. One row per token rather
 * than a "last consumed id" on the user, which would only stop the newest token.
 *
 * I-10. A wrong six-digit code used to fall through to the backup-code branch and
 * cost a bcrypt compare per stored code (eight bcrypt-12 compares, measured about
 * three seconds per wrong code). The verifier now chooses by shape: six digits
 * is a TOTP code and is checked as nothing else; anything else is a backup code
 * and never runs the TOTP check. A six-digit string can never equal a backup code
 * (sixteen hexadecimal characters since the first release), so no code that
 * matched before is refused now.
 */
import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { Challenge } from '../src/models/Challenge.js';
import { cryptoManager } from '../src/utils/cryptoManager.js';
import { TWO_FACTOR_CHALLENGE_SECONDS } from '../src/utils/twoFactorChallenge.js';
import { cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { createTestUser, deriveTestPurposeKey, getCsrf, type TestUser } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';

const API = '/api/v1';
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';
const BACKUP_CODES = [
  'a1b2c3d4e5f60718',
  'b2c3d4e5f6071829',
  'c3d4e5f60718293a',
  'd4e5f60718293a4b',
] as const;

interface TwoFactorAccount {
  user: TestUser;
  secret: Secret;
}

/** A verified account with an enrolled authenticator and four backup codes. */
async function createTwoFactorAccount(): Promise<TwoFactorAccount> {
  const secret = new Secret();
  const user = await createTestUser({ emailVerified: true });
  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      backupCodes: await Promise.all(BACKUP_CODES.map((code) => bcrypt.hash(code, 4))),
    },
  });
  return { user, secret };
}

function totpAt(secret: Secret, timestamp: number): string {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret }).generate({ timestamp });
}

function totpNow(secret: Secret): string {
  return totpAt(secret, Date.now());
}

/** A six-digit code that no step inside the verifier's ±1 window accepts. */
function wrongTotp(secret: Secret): string {
  const now = Date.now();
  const accepted = new Set(
    [-60_000, -30_000, 0, 30_000, 60_000].map((d) => totpAt(secret, now + d)),
  );
  return ['000000', '111111', '222222', '333333', '444444', '555555'].find(
    (c) => !accepted.has(c),
  )!;
}

/** Signs in with the master password and returns the challenge token `login` issued. */
async function passwordStep(user: TestUser): Promise<string> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  const res = await agent
    .post(`${API}/auth/login`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ email: user.email, authHash: user.authHash });
  expect(res.status).toBe(200);
  expect(res.body.data.twoFactorRequired).toBe(true);
  return res.body.data.tempToken as string;
}

async function secondFactorStep(tempToken: string, code: string): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login/2fa`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ tempToken, code });
}

async function remainingBackupCodes(userId: string): Promise<number> {
  const row = await User.findById(userId).select('+backupCodes').lean();
  return row?.backupCodes?.length ?? -1;
}

async function sessionsOf(userId: string): Promise<number> {
  return RefreshToken.countDocuments({ userId });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('I-01: login issues a challenge row that backs the token', () => {
  it('stores exactly one unconsumed row for the token, bound to the account, expiring with it', async () => {
    const { user } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);

    const claims = jwt.decode(tempToken) as { jti?: string; iat?: number; exp?: number };
    expect(typeof claims.jti).toBe('string');
    // Five minutes, the life the 2FA step has always given the token, issued now
    // (never stamped in the future, which would lengthen it).
    expect(TWO_FACTOR_CHALLENGE_SECONDS).toBe(300);
    expect(claims.exp! - claims.iat!).toBe(TWO_FACTOR_CHALLENGE_SECONDS);
    expect(claims.iat! * 1000).toBeLessThanOrEqual(Date.now());
    const rows = await Challenge.find({ userId: user.id }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.jti).toBe(claims.jti);
    expect(rows[0]!.consumedAt).toBeNull();
    // The row lives exactly as long as the token, to the second.
    expect(rows[0]!.expiresAt.getTime()).toBe(claims.exp! * 1000);
    // Negative: a token is never minted without its row, and two sign-ins never share one.
    const second = await passwordStep(user);
    expect((jwt.decode(second) as { jti: string }).jti).not.toBe(claims.jti);
    expect(await Challenge.countDocuments({ userId: user.id })).toBe(2);
  });
});

describe('I-01: a challenge buys one session', () => {
  it('refuses a spent challenge presented again with a fresh TOTP code, and spends nothing', async () => {
    const { user, secret } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);

    const first = await secondFactorStep(tempToken, BACKUP_CODES[0]);
    expect(first.status).toBe(200);
    expect(await sessionsOf(user.id)).toBe(2);

    const replay = await secondFactorStep(tempToken, totpNow(secret));
    expect(replay.status).toBe(401);
    expect(replay.body.message).toBe('TOKEN_INVALID');
    expect(replay.headers['set-cookie'] ?? []).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/^refreshToken=[^;]+/)]),
    );
    // Nothing was issued and nothing was spent or counted: the TOTP step is still
    // unused, and the second factor's counter never moved.
    expect(await sessionsOf(user.id)).toBe(2);
    const row = await User.findById(user.id).select('+secondFactorLockout').lean();
    expect(row?.lastTotpTimestamp).toBeUndefined();
    expect(row?.secondFactorLockout).toBeUndefined();
    expect((await Challenge.findOne({ userId: user.id }).lean())?.consumedAt).toBeInstanceOf(Date);
  });

  it('refuses a WRONG code on a spent challenge as a dead token: nothing counted, no bcrypt', async () => {
    const { user, secret } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);
    expect((await secondFactorStep(tempToken, totpNow(secret))).status).toBe(200);
    const compare = vi.spyOn(bcrypt, 'compare');

    // A guesser holding a spent token learns nothing about codes and moves no counter.
    const sixDigits = await secondFactorStep(tempToken, wrongTotp(secret));
    const backupShaped = await secondFactorStep(tempToken, 'ffffffffffffffff');

    for (const res of [sixDigits, backupShaped]) {
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('TOKEN_INVALID');
    }
    expect(compare).not.toHaveBeenCalled();
    const row = await User.findById(user.id).select('+secondFactorLockout').lean();
    expect(row?.secondFactorLockout).toBeUndefined();
  });

  it('refuses an OLDER unexpired challenge after a newer one was consumed', async () => {
    const { user } = await createTwoFactorAccount();
    const older = await passwordStep(user);
    const newer = await passwordStep(user);

    expect((await secondFactorStep(older, BACKUP_CODES[0])).status).toBe(200);
    expect((await secondFactorStep(newer, BACKUP_CODES[1])).status).toBe(200);

    // Both are spent now; neither the older nor the newer one buys another session.
    const olderAgain = await secondFactorStep(older, BACKUP_CODES[2]);
    const newerAgain = await secondFactorStep(newer, BACKUP_CODES[3]);
    expect(olderAgain.status).toBe(401);
    expect(newerAgain.status).toBe(401);
    expect(olderAgain.body.message).toBe('TOKEN_INVALID');
    // The two refused presentations consumed no backup code.
    expect(await remainingBackupCodes(user.id)).toBe(2);
    expect(await sessionsOf(user.id)).toBe(3);
  });

  it('lets exactly one of two concurrent exchanges win, and the loser spends no code', async () => {
    const { user } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);

    const results = await Promise.all([
      secondFactorStep(tempToken, BACKUP_CODES[0]),
      secondFactorStep(tempToken, BACKUP_CODES[1]),
    ]);

    expect(results.map((res) => res.status).sort()).toEqual([200, 401]);
    expect(await sessionsOf(user.id)).toBe(2);
    // The challenge is consumed BEFORE the code, so the loser's code survives.
    expect(await remainingBackupCodes(user.id)).toBe(3);
  });

  it('lets exactly one of two exchanges win even when both have passed the open check', async () => {
    // Deterministic twin of the race above: both requests are held at the consuming
    // compare-and-set until both have arrived there, so each has already passed the
    // read-only open check and verified its code. Only the CAS can separate them.
    const { user } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);
    const real = Challenge.findOneAndUpdate.bind(Challenge);
    let arrived = 0;
    let release!: () => void;
    const bothThere = new Promise<void>((resolve) => (release = resolve));
    vi.spyOn(Challenge, 'findOneAndUpdate').mockImplementation(((
      ...args: Parameters<typeof real>
    ) => {
      arrived += 1;
      if (arrived === 2) release();
      const query = real(...args);
      const exec = query.exec.bind(query);
      query.exec = (async () => {
        await bothThere;
        return exec();
      }) as typeof query.exec;
      return query;
    }) as typeof Challenge.findOneAndUpdate);

    const results = await Promise.all([
      secondFactorStep(tempToken, BACKUP_CODES[0]),
      secondFactorStep(tempToken, BACKUP_CODES[1]),
    ]);

    expect(arrived).toBe(2);
    expect(results.map((res) => res.status).sort()).toEqual([200, 401]);
    expect(results.find((res) => res.status === 401)!.body.message).toBe('TOKEN_INVALID');
    expect(await sessionsOf(user.id)).toBe(2);
    expect(await remainingBackupCodes(user.id)).toBe(3);
  });

  it("refuses a token whose challenge row has expired, even while the token's own signature is still in date", async () => {
    const { user } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);
    await Challenge.updateOne(
      { userId: user.id },
      { $set: { expiresAt: new Date(Date.now() - 1_000) } },
    );

    const res = await secondFactorStep(tempToken, BACKUP_CODES[0]);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await remainingBackupCodes(user.id)).toBe(4);
    expect(await sessionsOf(user.id)).toBe(1);
  });

  it('does not consume the challenge on a wrong code, so the owner can retype', async () => {
    const { user, secret } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);

    const wrong = await secondFactorStep(tempToken, wrongTotp(secret));
    expect(wrong.status).toBe(401);
    expect(wrong.body.message).toBe('TWO_FA_INVALID');
    expect((await Challenge.findOne({ userId: user.id }).lean())?.consumedAt).toBeNull();

    const right = await secondFactorStep(tempToken, totpNow(secret));
    expect(right.status).toBe(200);
  });

  it('refuses a correctly signed token that names no challenge, and spends nothing', async () => {
    const { user } = await createTwoFactorAccount();
    // An open challenge exists for the account, so a token naming none must not be
    // matched to it by accident.
    await passwordStep(user);
    // What a token minted before this release looks like: signed, unexpired, no row.
    const bare = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      {
        algorithm: 'HS256',
        expiresIn: '5m',
      },
    );

    const res = await secondFactorStep(bare, BACKUP_CODES[0]);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await remainingBackupCodes(user.id)).toBe(4);
    expect(await sessionsOf(user.id)).toBe(1);
  });

  it("refuses a token naming ANOTHER account's challenge", async () => {
    const { user } = await createTwoFactorAccount();
    const other = await createTwoFactorAccount();
    await passwordStep(other.user);
    const foreign = await Challenge.findOne({ userId: other.user.id }).lean();

    const crossed = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { algorithm: 'HS256', expiresIn: '5m', jwtid: foreign!.jti },
    );

    const res = await secondFactorStep(crossed, BACKUP_CODES[0]);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await remainingBackupCodes(user.id)).toBe(4);
    expect((await Challenge.findById(foreign!._id).lean())?.consumedAt).toBeNull();
  });
});

describe('I-01: the challenges collection', () => {
  it('declares a unique jti, a userId index for the erasure, and a TTL on expiresAt', async () => {
    await Challenge.createIndexes();
    const indexes = await Challenge.collection.indexes();
    const byKey = (key: Record<string, number>) =>
      indexes.find((index) => JSON.stringify(index.key) === JSON.stringify(key));

    expect(byKey({ jti: 1 })?.unique).toBe(true);
    expect(byKey({ userId: 1 })).toBeDefined();
    expect(byKey({ expiresAt: 1 })?.expireAfterSeconds).toBe(0);
    // Negative: the token id is the only unique key; many challenges per account.
    expect(byKey({ userId: 1 })?.unique).not.toBe(true);
  });
});

describe('I-10: the code shape selects the branch', () => {
  it('checks a wrong six-digit code as a TOTP code only: no bcrypt compare, still counted', async () => {
    const { user, secret } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);
    const compare = vi.spyOn(bcrypt, 'compare');

    const res = await secondFactorStep(tempToken, wrongTotp(secret));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');
    expect(compare).not.toHaveBeenCalled();
    // Still a counted failure on the second factor, and no code was consumed.
    const row = await User.findById(user.id).select('+secondFactorLockout').lean();
    expect(row?.secondFactorLockout?.failedAttempts).toBe(1);
    expect(await remainingBackupCodes(user.id)).toBe(4);
  });

  it('checks a backup-shaped code as a backup code only: the TOTP secret is never opened', async () => {
    const { user } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);
    const decrypt = vi.spyOn(cryptoManager, 'decryptTextSync');
    const compare = vi.spyOn(bcrypt, 'compare');

    const res = await secondFactorStep(tempToken, BACKUP_CODES[2]);

    expect(res.status).toBe(200);
    expect(decrypt).not.toHaveBeenCalled();
    expect(compare).toHaveBeenCalled();
    expect(await remainingBackupCodes(user.id)).toBe(3);
  });

  it('accepts backup codes that begin or end with six digits: the TOTP shape is the WHOLE code', async () => {
    // About one real code in sixteen starts with six decimal digits. The shape rule
    // must match the entire code, or such a code would be read as a TOTP code and
    // the owner's recovery credential refused.
    const { user } = await createTwoFactorAccount();
    const digitLed = ['123456789abcdef0', '1234567890123456', 'abcdef0123456789'];
    await User.findByIdAndUpdate(user.id, {
      $set: { backupCodes: await Promise.all(digitLed.map((code) => bcrypt.hash(code, 4))) },
    });

    for (const [index, code] of digitLed.entries()) {
      const res = await secondFactorStep(await passwordStep(user), code);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await remainingBackupCodes(user.id)).toBe(digitLed.length - index - 1);
    }
  });

  it('still accepts a valid TOTP code', async () => {
    const { user, secret } = await createTwoFactorAccount();
    const tempToken = await passwordStep(user);

    const res = await secondFactorStep(tempToken, totpNow(secret));

    expect(res.status).toBe(200);
    expect(await remainingBackupCodes(user.id)).toBe(4);
  });
});

async function eraseAndCheckChallenges(): Promise<void> {
  const { user } = await createTwoFactorAccount();
  const bystander = await createTwoFactorAccount();
  await passwordStep(user);
  await passwordStep(user);
  await passwordStep(bystander.user);

  expect(
    await cascadeDeleteUser({
      userId: user.id,
      userEmail: user.email,
      ip: '198.51.100.7',
      userAgent: 'the-owner',
      auditAction: 'account_delete',
    }),
  ).toBe(true);

  expect(await Challenge.countDocuments({ userId: user.id })).toBe(0);
  // Negative: another account's challenge is untouched.
  expect(await Challenge.countDocuments({ userId: bystander.user.id })).toBe(1);
}

describe('I-01: account erasure removes the challenges (sequential branch)', () => {
  beforeEach(() => {
    expect(supportsTransactions()).toBe(false);
  });

  it('erases every challenge row the account owns, and no other', async () => {
    await eraseAndCheckChallenges();
  });

  it('erases the challenges in the batch pass, read from the primary', async () => {
    const { user } = await createTwoFactorAccount();
    await passwordStep(user);
    const reads: unknown[] = [];
    const real = mongoose.mongo.Collection.prototype.find;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'challenges') {
        reads.push((args[1] as { readPreference?: unknown } | undefined)?.readPreference);
      }
      return real.apply(this, args);
    } as never);

    expect(
      await cascadeDeleteUser({
        userId: user.id,
        userEmail: user.email,
        ip: '198.51.100.7',
        userAgent: 'the-owner',
        auditAction: 'account_delete',
      }),
    ).toBe(true);

    expect(reads.length).toBeGreaterThanOrEqual(1);
    expect(reads.every((preference) => preference === 'primary')).toBe(true);
    expect(await Challenge.countDocuments({ userId: user.id })).toBe(0);
  });

  it('names the collection in the final sweep as well as in the batches', async () => {
    const { user } = await createTwoFactorAccount();
    await passwordStep(user);
    const sweep = vi.spyOn(Challenge, 'deleteMany');

    expect(
      await cascadeDeleteUser({
        userId: user.id,
        userEmail: user.email,
        ip: '198.51.100.7',
        userAgent: 'the-owner',
        auditAction: 'account_delete',
      }),
    ).toBe(true);

    // A row written while the batches ran (a sign-in already past authentication)
    // is caught by the final step, which names this collection itself.
    expect(sweep).toHaveBeenCalledWith({ userId: user.id }, expect.anything());
    expect(await Challenge.countDocuments({ userId: user.id })).toBe(0);
  });
});

describe('I-01: account erasure removes the challenges (transactional branch)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    expect(supportsTransactions()).toBe(true);
  });

  it('erases every challenge row the account owns inside the final step, and no other', async () => {
    await eraseAndCheckChallenges();
  });
});
