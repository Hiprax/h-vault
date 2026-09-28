/**
 * F-03 / F-28 — two factors, two states, and ONE second-factor verifier.
 *
 * The password and the second factor used to share one durable counter
 * (`failedLoginAttempts`/`lockoutUntil`). That coupling was both an oracle and a
 * lever: ten wrong TOTP codes refused the CORRECT password with a distinct
 * `ACCOUNT_LOCKED`, and the three session-level code checks (`disable2fa`,
 * `regenerateBackupCodes`, `deleteAccount`) counted nothing at all, so a session
 * holder who knew the password could guess codes there without ever touching
 * the brake, and `disable2fa` never consumed the step it accepted.
 *
 * What is pinned here:
 *
 *   - a wrong code at ANY verifying site counts on the second factor's own
 *     state (`secondFactorLockout`) and never on the password's;
 *   - the password step reads only the password state, the 2FA step reads only
 *     the second-factor state, and each has its own served discharge;
 *   - a code is consumed atomically wherever it is accepted, so the same code
 *     cannot succeed at two sites (two deterministic interleavings, each order);
 *   - enrolment (`verify2fa`) neither counts nor refuses;
 *   - the unlock link names the factor it unlocks, and discharges that one only.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
    sendSecondFactorLockoutEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import * as email from '../src/utils/email.js';
import {
  authHeader,
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const UA = 'SecondFactorLockout/1.0';
const LOCKOUT_MS = 30 * 60 * 1000;

const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

const mockedPasswordMail = vi.mocked(email.sendAccountUnlockEmail);
// Looked up through the namespace, not destructured: the function does not exist
// before the fix, and this file must still load against that code so its RED is
// an assertion failure rather than an import error.
const secondFactorMail = (): ReturnType<typeof vi.fn> | undefined =>
  (email as unknown as Record<string, ReturnType<typeof vi.fn> | undefined>)[
    'sendSecondFactorLockoutEmail'
  ];

interface RawLockout {
  failedAttempts?: number;
  until?: Date;
  episodeId?: string;
  notifiedAt?: Date;
}

interface RawUser {
  failedLoginAttempts?: number;
  lockoutUntil?: Date;
  lockoutEpisodeId?: string;
  secondFactorLockout?: RawLockout;
  twoFactorEnabled?: boolean;
  lastTotpTimestamp?: number;
}

/** The stored document, read past the schema so an absent path reads as absent. */
async function raw(userId: string): Promise<RawUser> {
  const doc = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(userId) });
  expect(doc).not.toBeNull();
  return doc as unknown as RawUser;
}

async function create2faUser(): Promise<{ user: TestUser; secret: Secret }> {
  const secret = new Secret();
  const user = await createTestUser({ emailVerified: true });
  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      lastTotpTimestamp: 1,
    },
  });
  return { user, secret };
}

function totpFor(secret: Secret): TOTP {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
}

/** A code that misses all three accepted steps, deterministically. */
function wrongCode(secret: Secret): string {
  const totp = totpFor(secret);
  const now = Date.now();
  const accepted = new Set([
    totp.generate({ timestamp: now - 30_000 }),
    totp.generate({ timestamp: now }),
    totp.generate({ timestamp: now + 30_000 }),
  ]);
  let candidate = (Number(totp.generate({ timestamp: now })) + 500_000) % 1_000_000;
  let code = String(candidate).padStart(6, '0');
  while (accepted.has(code)) {
    candidate = (candidate + 1) % 1_000_000;
    code = String(candidate).padStart(6, '0');
  }
  return code;
}

async function postLogin(email: string, authHash: string): Promise<request.Response> {
  const agent = request(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ email, authHash });
}

async function post2fa(tempToken: string, code: string): Promise<request.Response> {
  const agent = request(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login/2fa`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ tempToken, code });
}

async function challenge(user: TestUser): Promise<string> {
  const res = await postLogin(user.email, user.rawPassword);
  expect(res.status).toBe(200);
  expect(res.body.data.twoFactorRequired).toBe(true);
  expect(res.body.data.accessToken).toBeUndefined();
  return res.body.data.tempToken as string;
}

type SessionSite = 'disable2fa' | 'regenerateBackupCodes' | 'deleteAccount';

/** Drives one of the three session-level code checks with the correct password. */
async function atSite(site: SessionSite, user: TestUser, code: string): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
  const base =
    site === 'disable2fa'
      ? agent.delete(`${API}/user/2fa`)
      : site === 'regenerateBackupCodes'
        ? agent.post(`${API}/user/2fa/regenerate-backup-codes`)
        : agent.delete(`${API}/user`);
  return base
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
    .send({ password: user.rawPassword, code });
}

/** A lock the second factor earned: ten failures, deadline running, episode minted. */
async function lockSecondFactor(userId: string, until = new Date(Date.now() + LOCKOUT_MS)) {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        secondFactorLockout: {
          failedAttempts: MAX_LOGIN_ATTEMPTS,
          until,
          episodeId: 'sf-episode-seeded',
        },
      },
    },
  );
}

async function lockPassword(userId: string, until = new Date(Date.now() + LOCKOUT_MS)) {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
        lockoutUntil: until,
        lockoutEpisodeId: 'pw-episode-seeded',
      },
    },
  );
}

beforeEach(() => {
  mockedPasswordMail.mockReset();
  mockedPasswordMail.mockResolvedValue({ success: true, message: 'sent' });
  const sf = secondFactorMail();
  sf?.mockReset();
  sf?.mockResolvedValue({ success: true, message: 'sent' });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('F-28 — every session-level code check counts on the second factor', () => {
  it.each<SessionSite>(['disable2fa', 'regenerateBackupCodes', 'deleteAccount'])(
    'a wrong code at %s increments secondFactorLockout.failedAttempts and nothing else',
    async (site) => {
      const { user, secret } = await create2faUser();

      const res = await atSite(site, user, wrongCode(secret));
      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Invalid verification code');

      const after = await raw(user.id);
      expect(after.secondFactorLockout?.failedAttempts).toBe(1);
      expect(after.secondFactorLockout?.until).toBeUndefined();
      // The password factor is a different state and is never written by a code.
      expect(after.failedLoginAttempts ?? 0).toBe(0);
      expect(after.lockoutUntil).toBeUndefined();
      // Nothing the site exists to do happened.
      expect(after.twoFactorEnabled).toBe(true);
      expect(await User.exists({ _id: user.id })).not.toBeNull();
    },
  );

  it(
    'ten wrong codes at disable2fa lock the second factor, so a correct code at login2fa is ' +
      'then refused while the password step still answers',
    async () => {
      const { user, secret } = await create2faUser();

      for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
        const res = await atSite('disable2fa', user, wrongCode(secret));
        expect(res.status).toBe(400);
      }

      const locked = await raw(user.id);
      expect(locked.secondFactorLockout?.failedAttempts).toBe(MAX_LOGIN_ATTEMPTS);
      expect(locked.secondFactorLockout?.until?.getTime()).toBeGreaterThan(Date.now());
      expect(locked.secondFactorLockout?.episodeId).toEqual(expect.any(String));
      expect(locked.failedLoginAttempts ?? 0).toBe(0);

      // The password is proven at the first step, so a challenge is still issued...
      const tempToken = await challenge(user);
      // ...and the second step, with the CORRECT code, refuses: the password is
      // already known there, so the distinct answer is no oracle.
      const res = await post2fa(tempToken, totpFor(secret).generate());
      expect(res.status).toBe(403);
      expect(res.body.message).toBe('ACCOUNT_LOCKED');
      expect(res.body.data?.accessToken).toBeUndefined();

      // Negatives: no session minted, no login recorded, and the refused request
      // consumed nothing (the step is still unused).
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
      expect((await raw(user.id)).lastTotpTimestamp).toBe(1);
    },
    60_000,
  );

  it('a correct code at a session site is refused with 403 while the second factor is locked', async () => {
    const { user, secret } = await create2faUser();
    await lockSecondFactor(user.id);

    const res = await atSite('disable2fa', user, totpFor(secret).generate());
    expect(res.status).toBe(403);
    expect(res.body.message).toBe('ACCOUNT_LOCKED');

    const after = await raw(user.id);
    expect(after.twoFactorEnabled).toBe(true);
    // A refusal is not a failure: the locked state is not advanced.
    expect(after.secondFactorLockout?.failedAttempts).toBe(MAX_LOGIN_ATTEMPTS);
    expect(after.lastTotpTimestamp).toBe(1);
  });
});

describe('F-03 — the two factors keep coherent, separate states', () => {
  it(
    'ten wrong TOTPs, then the correct password: the password step still issues a challenge, ' +
      'and the 2FA step refuses',
    async () => {
      const { user, secret } = await create2faUser();

      const first = await challenge(user);
      for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
        const res = await post2fa(first, wrongCode(secret));
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('TWO_FA_INVALID');
      }

      const after = await raw(user.id);
      expect(after.secondFactorLockout?.failedAttempts).toBe(MAX_LOGIN_ATTEMPTS);
      expect(after.secondFactorLockout?.until?.getTime()).toBeGreaterThan(Date.now());
      // The password was right every time; its state is untouched.
      expect(after.failedLoginAttempts ?? 0).toBe(0);
      expect(after.lockoutUntil).toBeUndefined();

      const again = await postLogin(user.email, user.rawPassword);
      expect(again.status).toBe(200);
      expect(again.body.data.twoFactorRequired).toBe(true);
      expect(typeof again.body.data.tempToken).toBe('string');

      const refused = await post2fa(
        again.body.data.tempToken as string,
        totpFor(secret).generate(),
      );
      expect(refused.status).toBe(403);
      expect(refused.body.message).toBe('ACCOUNT_LOCKED');

      // The second-factor mail, never the password one, and exactly once.
      expect(mockedPasswordMail).not.toHaveBeenCalled();
      const sf = secondFactorMail();
      expect(sf).toBeDefined();
      expect(sf).toHaveBeenCalledTimes(1);
      expect(sf!.mock.calls[0]![0]).toBe(user.email);
    },
    60_000,
  );

  it('nine wrong TOTPs and one wrong password leave both factors unlocked', async () => {
    const { user, secret } = await create2faUser();

    const tempToken = await challenge(user);
    for (let i = 0; i < MAX_LOGIN_ATTEMPTS - 1; i++) {
      expect((await post2fa(tempToken, wrongCode(secret))).status).toBe(401);
    }
    const wrongPassword = await postLogin(user.email, 'wrong-auth-hash');
    expect(wrongPassword.status).toBe(401);

    const after = await raw(user.id);
    expect(after.secondFactorLockout?.failedAttempts).toBe(MAX_LOGIN_ATTEMPTS - 1);
    expect(after.secondFactorLockout?.until).toBeUndefined();
    expect(after.failedLoginAttempts).toBe(1);
    expect(after.lockoutUntil).toBeUndefined();
    expect(mockedPasswordMail).not.toHaveBeenCalled();
    expect(secondFactorMail()).not.toHaveBeenCalled();

    // Both doors still open: the owner completes a sign-in, which clears both.
    const token2 = await challenge(user);
    const ok = await post2fa(token2, totpFor(secret).generate());
    expect(ok.status).toBe(200);
    expect(ok.body.data.accessToken).toEqual(expect.any(String));
    const cleared = await raw(user.id);
    expect(cleared.secondFactorLockout?.failedAttempts ?? 0).toBe(0);
    expect(cleared.failedLoginAttempts).toBe(0);
  }, 60_000);

  it('login2fa reads only the second-factor state: a password lockout does not refuse it', async () => {
    const { user, secret } = await create2faUser();
    const tempToken = await challenge(user);
    // The password locks AFTER this client proved it (another client guessing).
    await lockPassword(user.id);

    const res = await post2fa(tempToken, totpFor(secret).generate());
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));

    // Completing a sign-in does not clear the lockout strangers built.
    const after = await raw(user.id);
    expect(after.failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS);
    expect(after.lockoutUntil?.getTime()).toBeGreaterThan(Date.now());
    expect(after.lockoutEpisodeId).toBe('pw-episode-seeded');
  });

  it('a SERVED second-factor lockout is discharged before the code is checked', async () => {
    const { user, secret } = await create2faUser();
    await lockSecondFactor(user.id, new Date(Date.now() - 60_000));

    const tempToken = await challenge(user);
    const res = await post2fa(tempToken, wrongCode(secret));
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');

    // A fresh budget of ten, not one: the counter restarted at this failure and
    // no new lock (and no mail) was produced by it.
    const after = await raw(user.id);
    expect(after.secondFactorLockout?.failedAttempts).toBe(1);
    expect(after.secondFactorLockout?.until).toBeUndefined();
    expect(after.secondFactorLockout?.episodeId).toBeUndefined();
    expect(secondFactorMail()).not.toHaveBeenCalled();
  });

  it('negative: a fresh correct code on an unlocked account completes the sign-in', async () => {
    const { user, secret } = await create2faUser();
    const tempToken = await challenge(user);
    const res = await post2fa(tempToken, totpFor(secret).generate());
    expect(res.status).toBe(200);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(1);
  });
});

describe('F-28 — enrolment is not a brake', () => {
  async function beginSetup(user: TestUser): Promise<Secret> {
    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/user/2fa/setup`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({ password: user.rawPassword });
    expect(res.status).toBe(200);
    return Secret.fromBase32(res.body.data.secret as string);
  }

  async function verify(user: TestUser, code: string): Promise<request.Response> {
    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    return agent
      .post(`${API}/user/2fa/verify`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({ code });
  }

  it('verify2fa neither counts wrong enrolment codes nor refuses while a lock is recorded', async () => {
    const user = await createTestUser({ emailVerified: true });
    const secret = await beginSetup(user);
    await lockSecondFactor(user.id);

    for (let i = 0; i < MAX_LOGIN_ATTEMPTS + 2; i++) {
      const res = await verify(user, wrongCode(secret));
      expect(res.status).toBe(400);
    }
    expect((await raw(user.id)).secondFactorLockout?.failedAttempts).toBe(MAX_LOGIN_ATTEMPTS);

    const ok = await verify(user, totpFor(secret).generate());
    expect(ok.status).toBe(200);
    expect(ok.body.data.backupCodes).toHaveLength(8);
    expect((await raw(user.id)).twoFactorEnabled).toBe(true);
  }, 60_000);
});

describe('F-28 — a compound write is never split: the code is consumed by the write that does the work', () => {
  interface Write {
    method: string;
    filter: Record<string, unknown>;
    update: Record<string, Record<string, unknown> | undefined>;
  }

  /** Records every single-document User write the request makes, and lets it run. */
  function recordUserWrites(): Write[] {
    const writes: Write[] = [];
    for (const method of ['updateOne', 'findOneAndUpdate', 'updateMany'] as const) {
      const original = User[method].bind(User) as (...args: unknown[]) => unknown;
      vi.spyOn(User, method).mockImplementation(((...args: unknown[]) => {
        writes.push({
          method,
          filter: (args[0] ?? {}) as Record<string, unknown>,
          update: (args[1] ?? {}) as Write['update'],
        });
        return original(...args);
      }) as never);
    }
    return writes;
  }

  const touchesStep = (write: Write): boolean =>
    write.update['$set']?.['lastTotpTimestamp'] !== undefined;

  it('verify2fa enables 2FA and records the step in ONE findOneAndUpdate', async () => {
    const user = await createTestUser({ emailVerified: true });
    const agent = request(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const setup = await agent
      .post(`${API}/user/2fa/setup`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({ password: user.rawPassword });
    const secret = Secret.fromBase32(setup.body.data.secret as string);

    const writes = recordUserWrites();
    const csrf2 = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/user/2fa/verify`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2.token)
      .set('Cookie', `${csrf2.cookie}; refreshToken=${user.refreshToken}`)
      .send({ code: totpFor(secret).generate() });
    expect(res.status).toBe(200);

    const stepWrites = writes.filter(touchesStep);
    expect(stepWrites).toHaveLength(1);
    const [write] = stepWrites;
    expect(write!.method).toBe('findOneAndUpdate');
    expect(write!.update['$set']?.['twoFactorEnabled']).toBe(true);
    expect(write!.filter['twoFactorEnabled']).toBe(false);
    expect(write!.filter['$or']).toEqual(expect.any(Array));
    // Nothing else enabled the factor on the side.
    expect(writes.filter((w) => w.update['$set']?.['twoFactorEnabled'] === true)).toHaveLength(1);
  });

  it('regenerateBackupCodes stores the new codes and records the step in ONE findOneAndUpdate', async () => {
    const { user, secret } = await create2faUser();

    const writes = recordUserWrites();
    const res = await atSite('regenerateBackupCodes', user, totpFor(secret).generate());
    expect(res.status).toBe(200);

    const stepWrites = writes.filter(touchesStep);
    expect(stepWrites).toHaveLength(1);
    const [write] = stepWrites;
    expect(write!.method).toBe('findOneAndUpdate');
    expect(write!.update['$set']?.['backupCodes']).toEqual(expect.any(Array));
    expect(write!.filter['twoFactorEnabled']).toBe(true);
    expect(write!.filter['$or']).toEqual(expect.any(Array));
    expect(writes.filter((w) => w.update['$set']?.['backupCodes'] !== undefined)).toHaveLength(1);
  });
});

describe('F-28 — a code is consumed atomically wherever it is accepted', () => {
  /**
   * Holds the first matching write until `release()` is called, then lets it run
   * for real. The seam is the model's two single-document write methods, hooked
   * together behind ONE gate, so the interleaving is the same whichever of the
   * two a handler uses to make its compare-and-set.
   */
  function pauseFirstWrite(
    matches: (update: Record<string, Record<string, unknown> | undefined>) => boolean,
  ): { reached: Promise<void>; release: () => void } {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let signal!: () => void;
    const reached = new Promise<void>((resolve) => {
      signal = resolve;
    });
    let paused = false;
    for (const method of ['updateOne', 'findOneAndUpdate'] as const) {
      const original = User[method].bind(User) as (...args: unknown[]) => unknown;
      vi.spyOn(User, method).mockImplementation(((...args: unknown[]) => {
        const update = (args[1] ?? {}) as Record<string, Record<string, unknown> | undefined>;
        const query = original(...args) as { exec: () => Promise<unknown> };
        if (!paused && !Array.isArray(update) && matches(update)) {
          paused = true;
          signal();
          // The query itself is returned, so the handler can still chain on it;
          // only its execution waits for the gate.
          const exec = query.exec.bind(query);
          query.exec = () => gate.then(exec);
        }
        return query;
      }) as never);
    }
    return { reached, release };
  }

  it('login2fa verifies code C and pauses; disable2fa spends C; login2fa is then refused', async () => {
    const { user, secret } = await create2faUser();
    const code = totpFor(secret).generate();
    const tempToken = await challenge(user);

    const hold = pauseFirstWrite((u) => u['$set']?.['lastTotpTimestamp'] !== undefined);
    const pending = post2fa(tempToken, code);
    await hold.reached;

    const disabled = await atSite('disable2fa', user, code);
    expect(disabled.status).toBe(200);

    hold.release();
    const res = await pending;
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');
    expect(res.body.data?.accessToken).toBeUndefined();
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
  }, 60_000);

  it('disable2fa verifies code C and pauses; login2fa spends C; disable2fa is then refused', async () => {
    const { user, secret } = await create2faUser();
    const code = totpFor(secret).generate();
    const tempToken = await challenge(user);

    const hold = pauseFirstWrite((u) => u['$set']?.['twoFactorEnabled'] === false);
    const pending = atSite('disable2fa', user, code);
    await hold.reached;

    const signedIn = await post2fa(tempToken, code);
    expect(signedIn.status).toBe(200);

    hold.release();
    const res = await pending;
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Invalid verification code');

    // The replayed code changed nothing: 2FA is still on.
    const after = await User.findById(user.id).select('+twoFactorSecret');
    expect(after!.twoFactorEnabled).toBe(true);
    expect(after!.twoFactorSecret).toEqual(expect.any(String));
    expect(await AuditLog.countDocuments({ userId: user.id, action: '2fa_disable' })).toBe(0);
  }, 60_000);

  it('deleteAccount verifies code C and pauses; login2fa spends C; deleteAccount is then refused', async () => {
    const { user, secret } = await create2faUser();
    const code = totpFor(secret).generate();
    const tempToken = await challenge(user);

    const hold = pauseFirstWrite((u) => u['$set']?.['deletionPending'] === true);
    const pending = atSite('deleteAccount', user, code);
    await hold.reached;

    const signedIn = await post2fa(tempToken, code);
    expect(signedIn.status).toBe(200);

    hold.release();
    const res = await pending;
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Invalid verification code');

    // Nothing was deleted, and the account is not even marked for deletion.
    const after = await raw(user.id);
    expect(after).toBeDefined();
    expect((after as Record<string, unknown>)['deletionPending']).toBeUndefined();
  }, 60_000);

  it('two uses of one unlock link race: the second to write discharges nothing and is refused', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    const link = jwt.sign(
      {
        userId: user.id,
        purpose: 'account_unlock',
        stateHash: generateStateHash('pw-episode-seeded'),
      },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: 3600 },
    );
    const unlock = async (): Promise<request.Response> => {
      const agent = request(app);
      const { token, cookie } = await getCsrf(agent);
      return agent
        .post(`${API}/auth/unlock-account`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ token: link });
    };

    const hold = pauseFirstWrite((u) => u['$unset']?.['lockoutEpisodeId'] !== undefined);
    const first = unlock();
    await hold.reached;
    const second = await unlock();
    expect(second.status).toBe(200);

    hold.release();
    const late = await first;
    expect(late.status).toBe(400);
    expect(late.body.message).toBe('TOKEN_INVALID');
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'account_unlock' })).toBe(1);
  });
});

describe('F-03 — the unlock link names its factor', () => {
  function unlockToken(userId: string, episodeId: string, factor?: string): string {
    return jwt.sign(
      {
        userId,
        purpose: 'account_unlock',
        stateHash: generateStateHash(episodeId),
        ...(factor === undefined ? {} : { factor }),
      },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: 3600 },
    );
  }

  async function unlock(token: string): Promise<request.Response> {
    const agent = request(app);
    const { token: csrf, cookie } = await getCsrf(agent);
    return agent
      .post(`${API}/auth/unlock-account`)
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token });
  }

  it('the second-factor lock mails a second-factor link that discharges only that factor', async () => {
    const { user, secret } = await create2faUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { failedLoginAttempts: 3 } },
    );

    const tempToken = await challenge(user);
    for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
      expect((await post2fa(tempToken, wrongCode(secret))).status).toBe(401);
    }
    const sf = secondFactorMail();
    expect(sf).toHaveBeenCalledTimes(1);
    const link = sf!.mock.calls[0]![1] as string;
    const claims = jwt.decode(link) as Record<string, unknown>;
    expect(claims['factor']).toBe('second_factor');

    const res = await unlock(link);
    expect(res.status).toBe(200);

    const after = await raw(user.id);
    expect(after.secondFactorLockout?.until).toBeUndefined();
    expect(after.secondFactorLockout?.episodeId).toBeUndefined();
    expect(after.secondFactorLockout?.failedAttempts ?? 0).toBe(0);
    // The password factor's own state is not the link's to clear.
    expect(after.failedLoginAttempts).toBe(3);

    const audit = await AuditLog.findOne({ userId: user.id, action: 'account_unlock' }).lean();
    expect(audit?.metadata).toEqual({ method: 'email_link', factor: 'second_factor' });
  }, 60_000);

  it('a second-factor link cannot discharge a password lockout with the same episode name', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const res = await unlock(unlockToken(user.id, 'pw-episode-seeded', 'second_factor'));
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect((await raw(user.id)).lockoutUntil?.getTime()).toBeGreaterThan(Date.now());
  });

  it('a link minted before the claim existed is read as a password link', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    await lockSecondFactor(user.id);

    const res = await unlock(unlockToken(user.id, 'pw-episode-seeded'));
    expect(res.status).toBe(200);

    const after = await raw(user.id);
    expect(after.lockoutUntil).toBeUndefined();
    expect(after.failedLoginAttempts).toBe(0);
    // The other factor's lock is untouched.
    expect(after.secondFactorLockout?.until?.getTime()).toBeGreaterThan(Date.now());
  });

  it('an unknown factor claim is refused and discharges nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const res = await unlock(unlockToken(user.id, 'pw-episode-seeded', 'hardware_key'));
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect((await raw(user.id)).failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS);
  });
});
