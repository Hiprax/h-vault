/**
 * A1 — the shared lockout counter must survive a replayed password step.
 *
 * `User.failedLoginAttempts` is ONE counter serving BOTH authentication steps:
 * `POST /auth/login` increments it on a wrong password, and `POST /auth/login/2fa`
 * increments it on a wrong code. It is also the ONLY per-account brake on the 2FA
 * step — `routes/auth.ts` gives `/login/2fa` `authLimiter` + `tokenVerifyLimiter`,
 * both of which are keyed by IP, never by account.
 *
 * `login` used to clear that counter (and `lockoutUntil`) the moment bcrypt
 * agreed, BEFORE the `if (user.twoFactorEnabled)` branch — that is, on a login
 * that had NOT completed, because a second factor was still owed. An attacker
 * holding the master password could therefore replay the password step between
 * batches of wrong codes and reset the only brake on the second factor: nine
 * guesses, one `/auth/login`, nine more, for ever. The residual bound was
 * `accountLimiter` at 20 requests per email per 15 minutes on `/login` — roughly
 * 180 TOTP guesses per quarter hour instead of ten per half hour.
 *
 * The reset now happens only where an authentication actually COMPLETES:
 *
 *   • `finishLogin` — the ordinary non-2FA completion, and the trusted-device
 *     2FA-skip that shares it (a skip still presents two factors: the password,
 *     and a device-bound trust token that only a prior successful 2FA can mint,
 *     and which `findOneAndDelete` burns as it is used);
 *   • `login2fa`, once the code verifies.
 *
 * A 2FA challenge that is issued and abandoned resets nothing.
 *
 * The process-local per-email throttle (`utils/loginThrottle.ts`) deliberately
 * keeps its old behaviour and is still cleared as soon as the password verifies:
 * it drives ONLY the progressive sleep on the password step, it is not consulted
 * anywhere in `login2fa`, and a verified password is proof that the password
 * guessing this counter exists to slow has ended. That is asserted below so the
 * two counters cannot be conflated by a later change.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// The unlock mail is stubbed so "did the threshold crossing mail exactly once?"
// is directly observable; the real sender is an inert no-op in the test
// environment (no SMTP configured), which makes the question unanswerable.
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import mongoose from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { sendAccountUnlockEmail } from '../src/utils/email.js';
import { hashToken } from '../src/utils/token.js';
import { peekLoginAttempts } from '../src/utils/loginThrottle.js';
import { createTestUser, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Pinned so every request in a file carries the same device identity: the temp
 * token is bound to `sha256(req.ip | User-Agent)`, so an unpinned UA would make
 * the interleaved login's token unusable at the 2FA step for the wrong reason.
 */
const UA = 'A1LockoutCounter/1.0';

const mockedUnlockEmail = vi.mocked(sendAccountUnlockEmail);
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/** Creates an email-verified user with 2FA enabled, and returns its TOTP secret. */
async function create2faUser(): Promise<{ user: TestUser; secret: Secret }> {
  const secret = new Secret();
  const user = await createTestUser({ emailVerified: true });
  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      // An old time step, so a genuinely valid code is not rejected as a replay.
      lastTotpTimestamp: 1,
    },
  });
  return { user, secret };
}

function totpFor(secret: Secret): TOTP {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
}

/**
 * A six-digit code that cannot verify RIGHT NOW.
 *
 * `totp.validate({ window: 1 })` accepts three time steps, so excluding only the
 * current code would leave a one-in-333,000 chance of accidentally submitting a
 * neighbour and turning a failure assertion green. The candidate is walked until
 * it misses all three, which makes the result deterministic rather than merely
 * improbable. Recomputed per attempt, because the accepted set moves with the
 * clock while a cached string does not.
 */
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

/** Drives the real password step. Returns the whole response, never just a token. */
async function postLogin(
  agent: request.Agent,
  email: string,
  authHash: string,
  extraCookies?: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', extraCookies ? `${cookie}; ${extraCookies}` : cookie)
    .send({ email, authHash });
}

/** Drives the real second step with a server-minted temp token. */
async function post2fa(
  agent: request.Agent,
  tempToken: string,
  code: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login/2fa`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ tempToken, code });
}

/** Password step that must return a 2FA challenge; yields the server's temp token. */
async function challenge(agent: request.Agent, user: TestUser): Promise<string> {
  const res = await postLogin(agent, user.email, user.rawPassword);
  expect(res.status).toBe(200);
  expect(res.body.data.twoFactorRequired).toBe(true);
  // A challenge is not a session: nothing that completes a login may be present.
  expect(res.body.data.accessToken).toBeUndefined();
  return res.body.data.tempToken as string;
}

async function counterOf(userId: string): Promise<{ attempts: number; lockoutUntil?: Date }> {
  const row = await User.findById(userId);
  expect(row).not.toBeNull();
  return {
    attempts: row!.failedLoginAttempts,
    ...(row!.lockoutUntil ? { lockoutUntil: row!.lockoutUntil } : {}),
  };
}

describe('A1 — the shared lockout counter across the two authentication steps', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
    // Re-armed rather than merely cleared: the sender is fire-and-forget
    // (`void send(...).then(...)`), so it must keep returning a promise.
    mockedUnlockEmail.mockReset();
    mockedUnlockEmail.mockResolvedValue({ success: true, message: 'sent' });
  });

  it(
    'still locks the account after MAX_LOGIN_ATTEMPTS total 2FA failures even when a successful ' +
      'password step is replayed between them',
    async () => {
      const { user, secret } = await create2faUser();
      const half = MAX_LOGIN_ATTEMPTS / 2;

      // ── First batch of wrong codes, under the first challenge ──────────────
      const firstToken = await challenge(agent, user);
      for (let i = 0; i < half; i++) {
        const res = await post2fa(agent, firstToken, wrongCode(secret));
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('TWO_FA_INVALID');
      }
      expect((await counterOf(user.id)).attempts).toBe(half);

      // ── The replay: a SUCCESSFUL password step, mid-attack ─────────────────
      // This is the whole finding. The password is correct, so the request
      // returns 200 — but it completes no authentication, because the account
      // still owes a second factor. It must therefore reset nothing.
      const secondToken = await challenge(agent, user);

      const afterReplay = await counterOf(user.id);
      expect(afterReplay.attempts).toBe(half);
      expect(afterReplay.lockoutUntil).toBeUndefined();

      // ── Second batch, under the replayed challenge ─────────────────────────
      for (let i = 0; i < half; i++) {
        const res = await post2fa(agent, secondToken, wrongCode(secret));
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('TWO_FA_INVALID');
      }

      // MAX_LOGIN_ATTEMPTS wrong codes in total — the account is locked.
      const locked = await counterOf(user.id);
      expect(locked.attempts).toBe(MAX_LOGIN_ATTEMPTS);
      expect(locked.lockoutUntil).toBeDefined();
      expect(locked.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

      // The threshold was crossed exactly once, so exactly one unlock mail.
      expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
      expect(mockedUnlockEmail.mock.calls[0]![0]).toBe(user.email);

      // Both doors are now shut. The second step refuses before the code is read...
      const blocked2fa = await post2fa(agent, secondToken, wrongCode(secret));
      expect(blocked2fa.status).toBe(403);
      expect(blocked2fa.body.message).toBe('ACCOUNT_LOCKED');

      // ...and the password step, with the CORRECT password, reports the lockout
      // to the owner rather than handing out another challenge to replay.
      const blockedLogin = await postLogin(agent, user.email, user.rawPassword);
      expect(blockedLogin.status).toBe(403);
      expect(blockedLogin.body.message).toBe('ACCOUNT_LOCKED');
      expect(blockedLogin.body.data?.tempToken).toBeUndefined();

      // Negatives: no authentication ever completed, so no session and no
      // `login` audit row exists — only the seeded refresh token remains.
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'login_failed' })).toBe(
        MAX_LOGIN_ATTEMPTS,
      );
    },
    60_000,
  );

  it('clears the process-local throttle at the challenge, but not the durable counter', async () => {
    // The two counters are easy to conflate and only one of them may be cleared
    // by a password alone, so this pins BOTH halves of that split in one place.
    // Both assertions can go red: moving `resetLoginAttempts` onto the
    // completed-authentication paths leaves the throttle at 1, and restoring the
    // old unconditional durable reset leaves the counter at 0.
    const { user } = await create2faUser();

    const failed = await postLogin(agent, user.email, 'wrong-auth-hash');
    expect(failed.status).toBe(401);
    expect(peekLoginAttempts(user.email)).toBe(1);
    expect((await counterOf(user.id)).attempts).toBe(1);

    await challenge(agent, user);

    // The throttle drives only the progressive sleep on the password step, and
    // a correct password is proof that guessing has ended, so it clears here...
    expect(peekLoginAttempts(user.email)).toBe(0);
    // ...while the durable counter, which is also the 2FA step's only
    // per-account brake, survives an authentication that has not completed.
    const after = await counterOf(user.id);
    expect(after.attempts).toBe(1);
    expect(after.lockoutUntil).toBeUndefined();
  }, 30_000);

  it('clears the counter once the second factor actually verifies', async () => {
    const { user, secret } = await create2faUser();

    const tempToken = await challenge(agent, user);
    for (let i = 0; i < 4; i++) {
      expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
    }
    expect((await counterOf(user.id)).attempts).toBe(4);

    const res = await post2fa(agent, tempToken, totpFor(secret).generate());
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();

    const after = await counterOf(user.id);
    expect(after.attempts).toBe(0);
    expect(after.lockoutUntil).toBeUndefined();
  }, 30_000);

  it('clears the counter on an ordinary login for an account with no second factor', async () => {
    const user = await createTestUser({ emailVerified: true });

    for (let i = 0; i < 4; i++) {
      expect((await postLogin(agent, user.email, 'wrong-auth-hash')).status).toBe(401);
    }
    expect((await counterOf(user.id)).attempts).toBe(4);

    const res = await postLogin(agent, user.email, user.rawPassword);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();
    expect(res.body.data.twoFactorRequired).toBeUndefined();

    const after = await counterOf(user.id);
    expect(after.attempts).toBe(0);
    expect(after.lockoutUntil).toBeUndefined();
  }, 30_000);

  describe('a lockout that was served', () => {
    /** Puts the account in the state a finished lockout leaves behind. */
    async function expireLockout(userId: string): Promise<void> {
      await User.findByIdAndUpdate(userId, {
        $set: {
          failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
          lockoutUntil: new Date(Date.now() - 60_000),
        },
      });
    }

    it(
      'is discharged by the password step, so a 2FA account gets the same fresh budget a ' +
        'passwordless-second-factor account has always had',
      async () => {
        const { user, secret } = await create2faUser();
        await expireLockout(user.id);

        // The thirty minutes were actually served — the only way to arrive here,
        // since a LIVE lockout 403s this very request (asserted below).
        const tempToken = await challenge(agent, user);

        const discharged = await counterOf(user.id);
        expect(discharged.attempts).toBe(0);
        expect(discharged.lockoutUntil).toBeUndefined();

        // The budget restored is the designed one: ten guesses, then a lock —
        // not one guess, which is what an undischarged counter of ten would give.
        for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
          expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
        }

        const relocked = await counterOf(user.id);
        expect(relocked.attempts).toBe(MAX_LOGIN_ATTEMPTS);
        expect(relocked.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

        // The threshold was crossed cleanly, so a FRESH unlock link was mailed.
        // Under an undischarged counter this crossing reads 11, never 10, and
        // the user is left with no live recovery link at all.
        expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
        expect(mockedUnlockEmail.mock.calls[0]![0]).toBe(user.email);
      },
      60_000,
    );

    it('is NOT discharged while it is still running, and the deadline is not rewritten', async () => {
      const { user } = await create2faUser();
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: MAX_LOGIN_ATTEMPTS, lockoutUntil },
      });

      const res = await postLogin(agent, user.email, user.rawPassword);
      expect(res.status).toBe(403);
      expect(res.body.message).toBe('ACCOUNT_LOCKED');
      expect(res.body.data?.tempToken).toBeUndefined();

      // Nothing moved: not the count, and not the deadline — the outstanding
      // unlock link's `stateHash` is bound to that exact timestamp.
      const after = await counterOf(user.id);
      expect(after.attempts).toBe(MAX_LOGIN_ATTEMPTS);
      expect(after.lockoutUntil!.getTime()).toBe(lockoutUntil.getTime());
      expect(mockedUnlockEmail).not.toHaveBeenCalled();
    }, 30_000);
  });

  describe('the trusted-device 2FA skip', () => {
    async function seedTrustedDevice(userId: string, raw: string): Promise<void> {
      await TrustedDevice.create({
        userId: new mongoose.Types.ObjectId(userId),
        tokenHash: hashToken(raw),
        deviceInfo: { userAgent: '', ip: '', fingerprint: '' },
        expiresAt: new Date(Date.now() + 30 * DAY_MS),
      });
    }

    it('clears the counter, because a recognised device completes the login', async () => {
      const { user, secret } = await create2faUser();
      const raw = 'a1-trusted-skip-token';
      await seedTrustedDevice(user.id, raw);

      const tempToken = await challenge(agent, user);
      for (let i = 0; i < 4; i++) {
        expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
      }
      expect((await counterOf(user.id)).attempts).toBe(4);

      // The cookie is a possession factor a prior successful 2FA minted, and it
      // is burned as it is spent — so this IS a completed authentication, and it
      // issues a real session rather than another challenge.
      const res = await postLogin(agent, user.email, user.rawPassword, `trustedDevice=${raw}`);
      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBeUndefined();
      expect(res.body.data.accessToken).toBeDefined();

      const after = await counterOf(user.id);
      expect(after.attempts).toBe(0);
      expect(after.lockoutUntil).toBeUndefined();
    }, 30_000);

    it('leaves the counter alone when the cookie is rejected and the challenge returns', async () => {
      const { user, secret } = await create2faUser();

      const tempToken = await challenge(agent, user);
      for (let i = 0; i < 4; i++) {
        expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
      }
      expect((await counterOf(user.id)).attempts).toBe(4);

      // No matching grant exists, so the branch fails closed to the 2FA prompt.
      // An unrecognised cookie must not become the reset oracle the replayed
      // password step used to be.
      const res = await postLogin(
        agent,
        user.email,
        user.rawPassword,
        'trustedDevice=a1-not-a-real-grant',
      );
      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBe(true);
      expect(res.body.data.accessToken).toBeUndefined();

      const after = await counterOf(user.id);
      expect(after.attempts).toBe(4);
      expect(after.lockoutUntil).toBeUndefined();

      // The rejection is recorded, and no session was minted for it.
      expect(
        await AuditLog.countDocuments({ userId: user.id, action: 'trusted_device_rejected' }),
      ).toBe(1);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
    }, 30_000);
  });
});
