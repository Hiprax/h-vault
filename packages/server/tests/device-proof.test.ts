/**
 * F-03 — the `__hv_device` proof cookie: what a lockout must never touch.
 *
 * A lockout exists to brake GUESSING. A client that has already completed an
 * authentication for the account is not guessing, so it must not be braked: the
 * owner's own browsers keep working while a stranger holds the account locked.
 * Neither existing cookie can say "this browser authenticated before": a
 * trusted-device cookie exists only for 2FA accounts that ticked remember-me
 * (and `disable2fa` revokes it), and a browser with a live refresh cookie never
 * posts to `/login` at all. Hence a dedicated proof:
 *
 *   - minted at EVERY completed authentication, rotated on use, 30 days;
 *   - stored hashed and scoped to one account (`device_proofs`, TTL);
 *   - with its OWN failure budget: five wrong passwords in fifteen minutes
 *     revoke it (one typo must not burn the device, five must), and until then
 *     a wrong password counts on the proof, not on the account;
 *   - revoked by a password reset, a password change, log-out-everywhere and
 *     refresh-token reuse;
 *   - set single-use for ten minutes by the unlock link, so the browser that
 *     follows the link is proven even when a stranger re-locks the account
 *     seconds later.
 *
 * Rows are seeded and read through the raw collection so this file needs
 * nothing but the collection name from the code under test.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { DeviceProof } from '../src/models/DeviceProof.js';
import { hashToken } from '../src/utils/token.js';
import { cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { clearDeviceProofCookie, issueUnlockProof } from '../src/utils/deviceProofs.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import {
  authHeader,
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';

const API = '/api/v1';
const COOKIE = '__hv_device';
const DAY_MS = 24 * 60 * 60 * 1000;
const LOCKOUT_MS = 30 * 60 * 1000;

interface ProofRow {
  _id: mongoose.Types.ObjectId;
  tokenHash: string;
  userId: mongoose.Types.ObjectId;
  expiresAt: Date;
  failures?: number;
  failuresSince?: Date;
  singleUse?: boolean;
  createdAt?: Date;
}

const proofs = () => mongoose.connection.collection<ProofRow>('device_proofs');

async function seedProof(
  userId: string,
  overrides: Partial<ProofRow> = {},
): Promise<{ raw: string; id: mongoose.Types.ObjectId }> {
  const raw = crypto.randomBytes(32).toString('hex');
  const id = new mongoose.Types.ObjectId();
  const now = new Date();
  await proofs().insertOne({
    _id: id,
    tokenHash: hashToken(raw),
    userId: new mongoose.Types.ObjectId(userId),
    expiresAt: new Date(now.getTime() + 30 * DAY_MS),
    failures: 0,
    singleUse: false,
    createdAt: now,
    ...overrides,
  });
  return { raw, id };
}

async function proofsOf(userId: string): Promise<ProofRow[]> {
  return proofs()
    .find({ userId: new mongoose.Types.ObjectId(userId) })
    .toArray();
}

function setCookies(res: request.Response): string[] {
  const header = res.headers['set-cookie'] as unknown as string[] | string | undefined;
  if (header === undefined) return [];
  return Array.isArray(header) ? header : [header];
}

/** The `__hv_device` Set-Cookie line, or undefined. */
function proofCookie(res: request.Response): string | undefined {
  return setCookies(res).find((c) => c.startsWith(`${COOKIE}=`));
}

/** The raw value a response set for the proof, or undefined (a clear sets ''). */
function proofValue(res: request.Response): string | undefined {
  const line = proofCookie(res);
  if (line === undefined) return undefined;
  return decodeURIComponent(line.slice(COOKIE.length + 1).split(';')[0]!);
}

async function postLogin(
  email: string,
  authHash: string,
  proof?: string,
): Promise<request.Response> {
  const agent = request(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login`)
    .set('x-csrf-token', token)
    .set('Cookie', proof === undefined ? cookie : `${cookie}; ${COOKIE}=${proof}`)
    .send({ email, authHash });
}

async function lockPassword(userId: string, until = new Date(Date.now() + LOCKOUT_MS)) {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
        lockoutUntil: until,
        lockoutEpisodeId: 'pw-episode',
      },
    },
  );
}

/**
 * The ONE answer an unproven sign-in gets during a password lockout, whether the
 * password was right or wrong: anything else (a 403, a 500, a body that differs)
 * is itself the oracle the lockout closes (F-03).
 */
function expectUniformRefusal(res: request.Response): void {
  expect(res.status).toBe(401);
  expect(res.body.message).toBe('Invalid email or password');
  expect(res.body.data).toBeUndefined();
  expect(String(res.headers['set-cookie'] ?? '')).not.toMatch(/refreshToken=/);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('F-03 — a proof is minted at every completed authentication', () => {
  it('a password-only sign-in sets a hashed, account-scoped, 30-day, httpOnly proof', async () => {
    const user = await createTestUser({ emailVerified: true });

    const res = await postLogin(user.email, user.rawPassword);
    expect(res.status).toBe(200);

    const line = proofCookie(res);
    expect(line).toBeDefined();
    expect(line).toMatch(/HttpOnly/i);
    expect(line).toMatch(/Path=\/api\/v1\/auth(;|$)/);
    expect(line).toMatch(/Max-Age=2592000/);
    const raw = proofValue(res)!;
    expect(raw).toMatch(/^[0-9a-f]{64}$/);

    const rows = await proofsOf(user.id);
    expect(rows).toHaveLength(1);
    // Only the hash is stored, and the raw value never appears in the body.
    expect(rows[0]!.tokenHash).toBe(hashToken(raw));
    expect(rows[0]!.singleUse ?? false).toBe(false);
    expect(Math.abs(rows[0]!.expiresAt.getTime() - (Date.now() + 30 * DAY_MS))).toBeLessThan(
      60_000,
    );
    expect(JSON.stringify(res.body)).not.toContain(raw);
  });

  it('a sign-in completed at the 2FA step, and one completed by a trusted device, each mint a proof', async () => {
    const secret = new Secret();
    const user = await createTestUser({ emailVerified: true });
    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: new CryptoManager().encryptTextSync(
          secret.base32,
          process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
        ),
        lastTotpTimestamp: 1,
      },
    });
    const UA = 'DeviceProof2fa/1.0';
    const agent = request(app);
    const c1 = await getCsrf(agent);
    const step1 = await agent
      .post(`${API}/auth/login`)
      .set('User-Agent', UA)
      .set('x-csrf-token', c1.token)
      .set('Cookie', c1.cookie)
      .send({ email: user.email, authHash: user.rawPassword });
    expect(step1.body.data.twoFactorRequired).toBe(true);
    const c2 = await getCsrf(agent);
    const step2 = await agent
      .post(`${API}/auth/login/2fa`)
      .set('User-Agent', UA)
      .set('x-csrf-token', c2.token)
      .set('Cookie', c2.cookie)
      .send({
        tempToken: step1.body.data.tempToken as string,
        code: new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret }).generate(),
      });
    expect(step2.status).toBe(200);
    const minted = proofValue(step2);
    expect(minted).toMatch(/^[0-9a-f]{64}$/);
    expect((await proofsOf(user.id)).map((r) => r.tokenHash)).toEqual([hashToken(minted!)]);

    // The trusted-device skip completes a sign-in too.
    const trusted = crypto.randomBytes(32).toString('hex');
    await TrustedDevice.create({
      userId: new mongoose.Types.ObjectId(user.id),
      tokenHash: hashToken(trusted),
      deviceInfo: { userAgent: '', ip: '', fingerprint: '' },
      expiresAt: new Date(Date.now() + 30 * DAY_MS),
    });
    const skip = await postLogin(
      user.email,
      user.rawPassword,
      `${minted!}; trustedDevice=${trusted}`,
    );
    expect(skip.status).toBe(200);
    expect(skip.body.data.accessToken).toEqual(expect.any(String));
    const rotated = proofValue(skip);
    expect(rotated).toMatch(/^[0-9a-f]{64}$/);
    expect(rotated).not.toBe(minted);
    expect((await proofsOf(user.id)).map((r) => r.tokenHash)).toEqual([hashToken(rotated!)]);
  });

  it('a password step that only issues a 2FA challenge mints nothing', async () => {
    const user = await createTestUser({ emailVerified: true, twoFactorEnabled: true });
    await User.updateOne({ _id: user.id }, { $set: { twoFactorSecret: 'x' } });

    const res = await postLogin(user.email, user.rawPassword);
    expect(res.status).toBe(200);
    expect(res.body.data.twoFactorRequired).toBe(true);
    expect(proofCookie(res)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('a failed sign-in mints nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    const res = await postLogin(user.email, 'wrong-auth-hash');
    expect(res.status).toBe(401);
    expect(proofCookie(res)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('rotates on use: the presented proof is consumed and a new one replaces it', async () => {
    const user = await createTestUser({ emailVerified: true });
    const first = await seedProof(user.id, { failures: 3, failuresSince: new Date() });

    const res = await postLogin(user.email, user.rawPassword, first.raw);
    expect(res.status).toBe(200);

    const next = proofValue(res);
    expect(next).toBeDefined();
    expect(next).not.toBe(first.raw);
    const rows = await proofsOf(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).toBe(hashToken(next!));
    // The old value is dead, and the new proof starts with a clean budget.
    expect(await proofs().findOne({ _id: first.id })).toBeNull();
    expect(rows[0]!.failures ?? 0).toBe(0);
  });
});

describe('F-03 — a proven client is not braked by a password lockout', () => {
  it('a proven login during a password lockout proceeds, and leaves the lockout in place', async () => {
    const user = await createTestUser({ emailVerified: true });
    const proof = await seedProof(user.id);
    await lockPassword(user.id);

    const res = await postLogin(user.email, user.rawPassword, proof.raw);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));

    // The lockout strangers built is not the owner's to clear by signing in.
    const after = await User.findById(user.id).select('+lockoutEpisodeId');
    expect(after!.failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS);
    expect(after!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
    expect(after!.lockoutEpisodeId).toBe('pw-episode');
  });

  it('a proof for another account is unproven, and is neither spent nor charged', async () => {
    const owner = await createTestUser({ emailVerified: true });
    const victim = await createTestUser({ emailVerified: true });
    const ownersProof = await seedProof(owner.id);
    await lockPassword(victim.id);

    const res = await postLogin(victim.email, victim.rawPassword, ownersProof.raw);
    expectUniformRefusal(res);
    expect(res.body.data?.accessToken).toBeUndefined();

    const wrong = await postLogin(victim.email, 'wrong-auth-hash', ownersProof.raw);
    expect(wrong.status).toBe(401);

    const row = await proofs().findOne({ _id: ownersProof.id });
    expect(row).not.toBeNull();
    expect(row!.failures ?? 0).toBe(0);
  });
});

describe('F-03 — a proof has its own failure budget', () => {
  it(
    'five wrong passwords on a proven client revoke the proof with an audit row, and the ' +
      'sixth is unproven',
    async () => {
      const user = await createTestUser({ emailVerified: true });
      const proof = await seedProof(user.id);

      for (let i = 1; i <= 4; i++) {
        const res = await postLogin(user.email, 'wrong-auth-hash', proof.raw);
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('Invalid email or password');
        const row = await proofs().findOne({ _id: proof.id });
        expect(row!.failures).toBe(i);
        // Counted on the PROOF, not on the account: the owner's typos do not
        // lock out the owner's other new devices.
        expect((await User.findById(user.id))!.failedLoginAttempts).toBe(0);
      }

      const fifth = await postLogin(user.email, 'wrong-auth-hash', proof.raw);
      expect(fifth.status).toBe(401);
      expect(fifth.body.message).toBe('Invalid email or password');
      expect(await proofs().findOne({ _id: proof.id })).toBeNull();
      // The browser is told to drop it.
      expect(proofValue(fifth)).toBe('');
      const revoked = await AuditLog.find({ userId: user.id, action: 'device_proof_revoked' })
        .lean()
        .exec();
      expect(revoked).toHaveLength(1);
      expect(revoked[0]!.metadata).toEqual({ reason: 'failure_budget' });

      // The sixth, still carrying the dead value, is an ordinary unproven failure.
      const sixth = await postLogin(user.email, 'wrong-auth-hash', proof.raw);
      expect(sixth.status).toBe(401);
      expect((await User.findById(user.id))!.failedLoginAttempts).toBe(1);
    },
    60_000,
  );

  it('one typo does not burn the device: a correct password after four failures still proves it', async () => {
    const user = await createTestUser({ emailVerified: true });
    const proof = await seedProof(user.id, { failures: 4, failuresSince: new Date() });
    await lockPassword(user.id);

    const res = await postLogin(user.email, user.rawPassword, proof.raw);
    expect(res.status).toBe(200);
  });

  it('failures older than the window do not count toward the budget', async () => {
    const user = await createTestUser({ emailVerified: true });
    const proof = await seedProof(user.id, {
      failures: 4,
      failuresSince: new Date(Date.now() - 16 * 60 * 1000),
    });

    const res = await postLogin(user.email, 'wrong-auth-hash', proof.raw);
    expect(res.status).toBe(401);
    const row = await proofs().findOne({ _id: proof.id });
    expect(row).not.toBeNull();
    expect(row!.failures).toBe(1);
  });
});

describe('F-03 — a forged or expired proof is unproven and cleared', () => {
  it('a forged value proves nothing and the cookie is cleared', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const res = await postLogin(user.email, user.rawPassword, 'f'.repeat(64));
    expectUniformRefusal(res);
    expect(proofValue(res)).toBe('');
  });

  it('an expired proof the TTL monitor has not yet reaped proves nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    const stale = await seedProof(user.id, { expiresAt: new Date(Date.now() - 1000) });
    await lockPassword(user.id);

    const res = await postLogin(user.email, user.rawPassword, stale.raw);
    expectUniformRefusal(res);
    expect(proofValue(res)).toBe('');
  });
});

describe('F-03 — a presented proof reveals nothing about the address', () => {
  /** The response's status, body and every `__hv_device` directive, for comparison. */
  function answer(res: request.Response): unknown {
    // `stack` is the error middleware's debug field outside production (it names
    // the throwing line); production never sends it, so it is not compared.
    const { stack: _stack, ...body } = res.body as Record<string, unknown>;
    return {
      status: res.status,
      body,
      proofDirectives: setCookies(res)
        .filter((c) => c.startsWith(`${COOKIE}=`))
        .map((c) => c.replace(/Expires=[^;]+/i, 'Expires=*')),
    };
  }

  it.each([
    ['a forged value', () => Promise.resolve('f'.repeat(64))],
    [
      'an expired proof',
      async () => {
        const other = await createTestUser({ emailVerified: true });
        return (await seedProof(other.id, { expiresAt: new Date(Date.now() - 1000) })).raw;
      },
    ],
  ])(
    'an unknown address and a registered one answer %s identically, cookie directives included',
    async (_label, makeValue) => {
      const registered = await createTestUser({ emailVerified: true });
      const value = await makeValue();

      const known = await postLogin(registered.email, 'wrong-auth-hash', value);
      const unknown = await postLogin(
        `nobody-${registered.id}@example.com`,
        'wrong-auth-hash',
        value,
      );

      expect(known.status).toBe(401);
      expect(answer(unknown)).toEqual(answer(known));
      // And the dead value is cleared in both cases, so the browser stops sending it.
      expect(proofValue(unknown)).toBe('');
    },
  );
});

describe('F-03 — the unlock link proves the browser that follows it', () => {
  function unlockToken(userId: string, episodeId: string): string {
    return jwt.sign(
      { userId, purpose: 'account_unlock', stateHash: generateStateHash(episodeId) },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: 3600 },
    );
  }

  it(
    'sets a single-use ten-minute proof; after a stranger re-locks, that browser still signs ' +
      'in while an unproven one is refused',
    async () => {
      const user = await createTestUser({ emailVerified: true });
      await lockPassword(user.id);

      const agent = request(app);
      const csrf = await getCsrf(agent);
      const unlocked = await agent
        .post(`${API}/auth/unlock-account`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ token: unlockToken(user.id, 'pw-episode') });
      expect(unlocked.status).toBe(200);

      const line = proofCookie(unlocked);
      expect(line).toMatch(/Max-Age=600(;|$)/);
      const raw = proofValue(unlocked)!;
      const [row] = await proofsOf(user.id);
      expect(row!.tokenHash).toBe(hashToken(raw));
      expect(row!.singleUse).toBe(true);
      expect(Math.abs(row!.expiresAt.getTime() - (Date.now() + 10 * 60 * 1000))).toBeLessThan(
        60_000,
      );

      // A stranger re-locks the account at once.
      for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
        expect((await postLogin(user.email, 'stranger-guess')).status).toBe(401);
      }
      expect((await User.findById(user.id))!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

      // An unproven browser, even with the right password, is refused...
      const unproven = await postLogin(user.email, user.rawPassword);
      expectUniformRefusal(unproven);

      // ...and the browser that followed the link is not.
      const proven = await postLogin(user.email, user.rawPassword, raw);
      expect(proven.status).toBe(200);
      expect(proven.body.data.accessToken).toEqual(expect.any(String));

      // Single use: the unlock proof is spent, replaced by an ordinary one.
      const rows = await proofsOf(user.id);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.singleUse ?? false).toBe(false);
      expect(rows[0]!.tokenHash).not.toBe(hashToken(raw));
      const replay = await postLogin(user.email, user.rawPassword, raw);
      expectUniformRefusal(replay);
    },
    60_000,
  );
});

describe('F-03 — revocation', () => {
  it('a password reset revokes every proof', async () => {
    const user = await createTestUser({ emailVerified: true });
    await seedProof(user.id);
    await seedProof(user.id);
    const stored = await User.findById(user.id).select('+authHash');
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash(stored!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const agent = request(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/reset-password`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        token,
        email: user.email,
        newAuthHash: 'new-auth-hash',
        newEncryptedVaultKey: 'k',
        newVaultKeyIv: 'i',
        newVaultKeyTag: 't',
      });
    expect(res.status).toBe(200);
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('a password change revokes every proof', async () => {
    const user = await createTestUser({ emailVerified: true });
    await seedProof(user.id);
    await seedProof(user.id);

    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .put(`${API}/user/change-password`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'new-auth-hash',
        newEncryptedVaultKey: 'k',
        newVaultKeyIv: 'i',
        newVaultKeyTag: 't',
      });
    expect(res.status).toBe(200);
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it("log-out-everywhere revokes every proof, the caller's copies included, and re-proves the caller", async () => {
    const user = await createTestUser({ emailVerified: true });
    const mine = await seedProof(user.id);
    await seedProof(user.id);
    await seedProof(user.id);
    const bystander = await createTestUser({ emailVerified: true });
    await seedProof(bystander.id);

    const logoutAll = async (proof?: string): Promise<request.Response> => {
      const agent = request(app);
      const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
      const jar = [csrf.cookie, `refreshToken=${user.refreshToken}`];
      if (proof !== undefined) jar.push(`${COOKIE}=${proof}`);
      return agent
        .post(`${API}/auth/logout-all`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', jar.join('; '));
    };

    const res = await logoutAll(mine.raw);
    expect(res.status).toBe(200);

    // The caller's old value is dead (a stolen copy of it included)...
    expect(await proofs().findOne({ _id: mine.id })).toBeNull();
    await lockPassword(user.id);
    const copy = await postLogin(user.email, user.rawPassword, mine.raw);
    expectUniformRefusal(copy);
    // ...and the caller holds a fresh one, which is the only proof left.
    const fresh = proofValue(res);
    expect(fresh).toMatch(/^[0-9a-f]{64}$/);
    expect(fresh).not.toBe(mine.raw);
    expect((await proofsOf(user.id)).map((r) => r.tokenHash)).toEqual([hashToken(fresh!)]);
    expect(await proofsOf(bystander.id)).toHaveLength(1);

    // A caller that presented no proof is not given one: a session alone does not earn it.
    const bare = await logoutAll();
    expect(bare.status).toBe(200);
    expect(proofCookie(bare)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it("log-out-everywhere replaces a caller's single-use proof like for like: single-use, 10 minutes", async () => {
    const user = await createTestUser({ emailVerified: true });
    const single = await seedProof(user.id, {
      singleUse: true,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });
    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/auth/logout-all`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set(
        'Cookie',
        [csrf.cookie, `refreshToken=${user.refreshToken}`, `${COOKIE}=${single.raw}`].join('; '),
      );
    expect(res.status).toBe(200);

    const fresh = proofValue(res);
    expect(fresh).toMatch(/^[0-9a-f]{64}$/);
    expect(fresh).not.toBe(single.raw);
    expect(proofCookie(res)).toMatch(/Max-Age=600/);
    const rows = await proofsOf(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).toBe(hashToken(fresh!));
    // Negative: never upgraded to a 30-day reusable proof by a session alone.
    expect(rows[0]!.singleUse).toBe(true);
    expect(rows[0]!.expiresAt.getTime()).toBeLessThan(Date.now() + 11 * 60 * 1000);
    expect(await proofs().findOne({ _id: single.id })).toBeNull();
  });

  it('refresh-token reuse revokes every proof (the device is presumed stolen)', async () => {
    const user = await createTestUser({ emailVerified: true });
    await seedProof(user.id);
    await RefreshToken.updateOne(
      { tokenHash: hashToken(user.refreshToken) },
      { $set: { usedAt: new Date() } },
    );

    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_REUSE_DETECTED');
    expect(await proofsOf(user.id)).toHaveLength(0);
  });
});

describe('F-03 — bounded growth', () => {
  it('keeps at most MAX_DEVICE_PROOFS_PER_USER (50) proofs, evicting the oldest', async () => {
    const user = await createTestUser({ emailVerified: true });
    const oldest = await seedProof(user.id, { createdAt: new Date(Date.now() - 10 * DAY_MS) });
    for (let i = 0; i < 49; i++) {
      await seedProof(user.id, { createdAt: new Date(Date.now() - DAY_MS + i) });
    }

    const res = await postLogin(user.email, user.rawPassword);
    expect(res.status).toBe(200);

    const rows = await proofsOf(user.id);
    expect(rows).toHaveLength(50);
    expect(rows.some((r) => r._id.equals(oldest.id))).toBe(false);
    expect(rows.some((r) => r.tokenHash === hashToken(proofValue(res)!))).toBe(true);
  });
});

describe('F-03 — proof handling edge cases', () => {
  it('a failure to mint a proof never fails a completed sign-in', async () => {
    const user = await createTestUser({ emailVerified: true });
    vi.spyOn(DeviceProof, 'create').mockImplementationOnce((() =>
      Promise.reject(new Error('datastore unavailable'))) as never);

    const res = await postLogin(user.email, user.rawPassword);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));
    expect(proofCookie(res)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('a forged value followed by a completed sign-in sends ONE directive: the new proof', async () => {
    const user = await createTestUser({ emailVerified: true });
    const res = await postLogin(user.email, user.rawPassword, 'f'.repeat(64));
    expect(res.status).toBe(200);
    const directives = setCookies(res).filter((c) => c.startsWith(`${COOKIE}=`));
    expect(directives).toHaveLength(1);
    expect(proofValue(res)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('a single-use proof is spent by the password step even when a second factor is owed', async () => {
    const user = await createTestUser({ emailVerified: true, twoFactorEnabled: true });
    await User.updateOne({ _id: user.id }, { $set: { twoFactorSecret: 'x' } });
    const single = await seedProof(user.id, {
      singleUse: true,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    await lockPassword(user.id);

    const first = await postLogin(user.email, user.rawPassword, single.raw);
    expect(first.status).toBe(200);
    expect(first.body.data.twoFactorRequired).toBe(true);
    expect(await proofs().findOne({ _id: single.id })).toBeNull();

    const again = await postLogin(user.email, user.rawPassword, single.raw);
    expectUniformRefusal(again);
  });

  it('the unlock link leaves a browser that already holds a live proof with that proof', async () => {
    const user = await createTestUser({ emailVerified: true });
    const held = await seedProof(user.id);
    await lockPassword(user.id);
    const link = jwt.sign(
      { userId: user.id, purpose: 'account_unlock', stateHash: generateStateHash('pw-episode') },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: 3600 },
    );
    const agent = request(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/unlock-account`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; ${COOKIE}=${held.raw}`)
      .send({ token: link });
    expect(res.status).toBe(200);
    expect(proofCookie(res)).toBeUndefined();
    const rows = await proofsOf(user.id);
    expect(rows.map((r) => r._id.toString())).toEqual([held.id.toString()]);
  });

  it('a malformed (JSON-prefixed) cookie is treated as absent: no lookup, no directive', async () => {
    const user = await createTestUser({ emailVerified: true });
    const spy = vi.spyOn(DeviceProof, 'findOne');
    const res = await postLogin(user.email, 'wrong-auth-hash', 'j:%7B%22a%22%3A1%7D');
    expect(res.status).toBe(401);
    expect(spy).not.toHaveBeenCalled();
    expect(proofCookie(res)).toBeUndefined();
  });

  it('the model declares the lookup, per-account and TTL indexes', () => {
    const indexes = DeviceProof.schema.indexes();
    expect(indexes).toContainEqual([{ tokenHash: 1 }, expect.objectContaining({ unique: true })]);
    expect(indexes).toContainEqual([{ userId: 1, createdAt: -1 }, expect.anything()]);
    expect(indexes).toContainEqual([
      { expiresAt: 1 },
      expect.objectContaining({ expireAfterSeconds: 0 }),
    ]);
  });
});

describe('F-03 — a proof in use stays alive; a single-use proof is spent exactly once', () => {
  async function refreshWithProof(user: TestUser, proof?: string): Promise<request.Response> {
    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const jar = [csrf.cookie, `refreshToken=${user.refreshToken}`];
    if (proof !== undefined) jar.push(`${COOKIE}=${proof}`);
    return agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', jar.join('; '));
  }

  it('a session refresh slides the expiry of the proof the browser holds, and mints nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    const held = await seedProof(user.id, { expiresAt: new Date(Date.now() + DAY_MS) });

    const res = await refreshWithProof(user, held.raw);
    expect(res.status).toBe(200);
    const row = await proofs().findOne({ _id: held.id });
    expect(Math.abs(row!.expiresAt.getTime() - (Date.now() + 30 * DAY_MS))).toBeLessThan(60_000);
    expect(proofValue(res)).toBe(held.raw);
    expect(proofCookie(res)).toMatch(/Max-Age=2592000/);
    expect(await proofsOf(user.id)).toHaveLength(1);
  });

  it("a refresh without a proof, with another account's proof, or with a single-use one extends nothing", async () => {
    const user = await createTestUser({ emailVerified: true });
    const none = await refreshWithProof(user);
    expect(none.status).toBe(200);
    expect(proofCookie(none)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);

    const other = await createTestUser({ emailVerified: true });
    const foreign = await seedProof(other.id, { expiresAt: new Date(Date.now() + DAY_MS) });
    const user2 = await createTestUser({ emailVerified: true });
    const res2 = await refreshWithProof(user2, foreign.raw);
    expect(res2.status).toBe(200);
    expect(proofCookie(res2)).toBeUndefined();
    const foreignRow = await proofs().findOne({ _id: foreign.id });
    expect(foreignRow!.expiresAt.getTime()).toBeLessThan(Date.now() + 2 * DAY_MS);

    const user3 = await createTestUser({ emailVerified: true });
    const single = await seedProof(user3.id, {
      singleUse: true,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    const res3 = await refreshWithProof(user3, single.raw);
    expect(res3.status).toBe(200);
    const singleRow = await proofs().findOne({ _id: single.id });
    expect(singleRow!.expiresAt.getTime()).toBeLessThan(Date.now() + 11 * 60 * 1000);
  });

  it('a failure to extend the held proof never fails the refresh, and re-sends nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    const held = await seedProof(user.id, { expiresAt: new Date(Date.now() + DAY_MS) });
    const extend = vi
      .spyOn(DeviceProof, 'updateOne')
      .mockImplementationOnce((() => Promise.reject(new Error('datastore unavailable'))) as never);

    const res = await refreshWithProof(user, held.raw);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));
    expect(extend).toHaveBeenCalledTimes(1);
    expect(proofCookie(res)).toBeUndefined();
    const row = await proofs().findOne({ _id: held.id });
    expect(row!.expiresAt.getTime()).toBeLessThan(Date.now() + 2 * DAY_MS);
  });

  it('two concurrent sign-ins racing with one single-use proof: exactly one is proven', async () => {
    const user = await createTestUser({ emailVerified: true });
    const single = await seedProof(user.id, {
      singleUse: true,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    await lockPassword(user.id);

    const results = await Promise.all([
      postLogin(user.email, user.rawPassword, single.raw),
      postLogin(user.email, user.rawPassword, single.raw),
    ]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expectUniformRefusal(results.find((r) => r.status !== 200)!);
  });

  it('one directive per response even when the clear was the only cookie queued before the mint', async () => {
    const user = await createTestUser({ emailVerified: true });
    const mini = express();
    mini.get('/t', (_req, res, next) => {
      clearDeviceProofCookie(res);
      issueUnlockProof(res, new mongoose.Types.ObjectId(user.id)).then(() => {
        res.status(204).end();
      }, next);
    });
    const res = await request(mini).get('/t');
    const directives = setCookies(res).filter((c) => c.startsWith(`${COOKIE}=`));
    expect(directives).toHaveLength(1);
    expect(proofValue(res)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('F-03 — account deletion erases the proofs (sequential branch)', () => {
  beforeEach(() => {
    expect(supportsTransactions()).toBe(false);
  });

  it('cascadeDeleteUser removes the target account proofs and no one else', async () => {
    const target = await createTestUser({ emailVerified: true });
    const bystander = await createTestUser({ emailVerified: true });
    await seedProof(target.id);
    await seedProof(bystander.id);

    const ok = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test',
      auditAction: 'account_delete',
    });
    expect(ok).toBe(true);
    expect(await proofsOf(target.id)).toHaveLength(0);
    expect(await proofsOf(bystander.id)).toHaveLength(1);
  });
});

describe('F-03 — account deletion erases the proofs (transactional branch)', () => {
  useReplicaSetConnection({ timeoutMs: 90_000 });

  it('a password change whose write is superseded aborts, and the proofs survive with it', async () => {
    expect(supportsTransactions()).toBe(true);
    const user = await createTestUser({ emailVerified: true });
    await seedProof(user.id);
    await seedProof(user.id);
    // The vault-key write inside the transaction matches nothing (a rotation
    // landed in between), which aborts the transaction the revocation ran in.
    const original = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const filter = args[0] as Record<string, unknown>;
      const options = args[2] as { session?: unknown } | undefined;
      if (options?.session !== undefined && 'vaultKeyVersion' in filter) {
        return Promise.resolve({ matchedCount: 0, modifiedCount: 0, acknowledged: true });
      }
      return original(...args);
    }) as never);

    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .put(`${API}/user/change-password`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'new-auth-hash',
        newEncryptedVaultKey: 'k',
        newVaultKeyIv: 'i',
        newVaultKeyTag: 't',
      });
    expect(res.status).toBe(409);
    expect(await proofsOf(user.id)).toHaveLength(2);
  });

  it('a password change revokes every proof inside its transaction', async () => {
    expect(supportsTransactions()).toBe(true);
    const user = await createTestUser({ emailVerified: true });
    await seedProof(user.id);
    await seedProof(user.id);
    const startSession = vi.spyOn(mongoose, 'startSession');

    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .put(`${API}/user/change-password`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'new-auth-hash',
        newEncryptedVaultKey: 'k',
        newVaultKeyIv: 'i',
        newVaultKeyTag: 't',
      });
    expect(res.status).toBe(200);
    expect(startSession).toHaveBeenCalled();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('cascadeDeleteUser removes the target account proofs on the transactional branch', async () => {
    expect(supportsTransactions()).toBe(true);
    const target: TestUser = await createTestUser({ emailVerified: true });
    const bystander = await createTestUser({ emailVerified: true });
    await seedProof(target.id);
    await seedProof(bystander.id);

    const startSession = vi.spyOn(mongoose, 'startSession');
    const ok = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test',
      auditAction: 'account_delete',
    });
    expect(ok).toBe(true);
    expect(startSession).toHaveBeenCalled();
    expect(await proofsOf(target.id)).toHaveLength(0);
    expect(await proofsOf(bystander.id)).toHaveLength(1);
  });
});

describe('DeviceProof serialisation', () => {
  it('never serialises the token hash (what a stolen cookie must hash to), nor __v', async () => {
    const proof = await DeviceProof.create({
      userId: new mongoose.Types.ObjectId(),
      tokenHash: hashToken('a-proof-cookie-value'),
      expiresAt: new Date(Date.now() + 60_000),
    });

    const json = proof.toJSON();
    expect(Object.hasOwn(json, 'tokenHash')).toBe(false);
    expect(Object.hasOwn(json, '__v')).toBe(false);
    expect(JSON.stringify(json)).not.toContain(hashToken('a-proof-cookie-value'));
    // And the strip is not achieved by emitting nothing: the fields a reader may see survive.
    expect(String(json.userId)).toBe(proof.userId.toString());
    expect(json.expiresAt).toEqual(proof.expiresAt);
  });
});

describe('F-03 — handing out an unlock proof is best effort, never a failure of what it rides on', () => {
  function unlockToken(userId: string, episodeId: string): string {
    return jwt.sign(
      { userId, purpose: 'account_unlock', stateHash: generateStateHash(episodeId) },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: 3600 },
    );
  }

  it('an unlock whose proof cannot be stored still unlocks, audits, and answers 200', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    const create = vi
      .spyOn(DeviceProof, 'create')
      .mockImplementationOnce((() => Promise.reject(new Error('datastore unavailable'))) as never);

    const agent = request(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/unlock-account`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ token: unlockToken(user.id, 'pw-episode') });

    expect(create).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
    // The link did its job: the lockout is gone and the unlock is on the record.
    const stored = await User.findById(user.id).lean();
    expect(stored!.lockoutUntil ?? null).toBeNull();
    expect(stored!.failedLoginAttempts).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'account_unlock' })).toBe(1);
    // Negative: no proof was handed out, and none is stored.
    expect(proofCookie(res)).toBeUndefined();
    expect(await proofsOf(user.id)).toHaveLength(0);
  });

  it('log-out-everywhere whose replacement proof cannot be stored still revokes, suspends and audits', async () => {
    const user = await createTestUser({ emailVerified: true });
    const single = await seedProof(user.id, {
      singleUse: true,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: {
          'settings.backup.backupRecipients': [
            {
              email: 'third@example.org',
              state: 'confirmed',
              confirmedAt: new Date(),
              approvedAt: new Date(),
              confirmationDue: false,
              confirmationSentAt: null,
              confirmationAttempts: 0,
              nonce: 'a'.repeat(64),
            },
          ],
          'settings.backup.recipientsRevision': 1,
        },
      },
    );
    const create = vi
      .spyOn(DeviceProof, 'create')
      .mockImplementationOnce((() => Promise.reject(new Error('datastore unavailable'))) as never);

    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/auth/logout-all`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set(
        'Cookie',
        [csrf.cookie, `refreshToken=${user.refreshToken}`, `${COOKIE}=${single.raw}`].join('; '),
      );

    expect(create).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
    // Everything log-out-everywhere exists for still happened.
    expect(await proofs().findOne({ _id: single.id })).toBeNull();
    const stored = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    const recipients = (
      stored as unknown as { settings: { backup: { backupRecipients: { state: string }[] } } }
    ).settings.backup.backupRecipients;
    expect(recipients.map((r) => r.state)).toEqual(['suspended']);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'session_revoke' })).toBe(1);
    // Negative: no replacement proof exists, and none was sent.
    expect(await proofsOf(user.id)).toHaveLength(0);
    expect(proofValue(res) ?? '').toBe('');
  });
});
