/**
 * A1 — the second factor's lockout counter must survive a replayed password step.
 *
 * Rewritten for F-03/F-28 (two factors, two states). This file used to pin ONE
 * shared `failedLoginAttempts` counter serving both authentication steps; that
 * sharing is exactly what let ten wrong TOTP codes refuse the CORRECT password
 * with a distinct `ACCOUNT_LOCKED` (a password oracle), so the counter is now
 * split: the password factor keeps the legacy fields, and the second factor
 * counts on its own `secondFactorLockout` state through the one verifier
 * (`utils/secondFactor.ts`). What this file still pins is the property A1 was
 * written for, restated per factor: a successful PASSWORD step is not a
 * completed authentication, so it must reset nothing on the second factor —
 * otherwise a password holder could replay it between batches of wrong codes
 * and reset the second factor's only per-account brake for ever.
 *
 * The resets happen only where an authentication actually COMPLETES:
 *
 *   • `finishLogin` — the ordinary non-2FA completion, and the trusted-device
 *     2FA-skip that shares it;
 *   • `login2fa`, once the code verifies.
 *
 * and only for a factor whose lockout is not running at that moment.
 *
 * The process-local per-email throttle (`utils/loginThrottle.ts`) deliberately
 * keeps its old behaviour and is still cleared as soon as the password verifies:
 * it drives ONLY the progressive sleep on the password step.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// The unlock mail is stubbed so "did the threshold crossing mail exactly once?"
// is directly observable; the real sender is an inert no-op in the test
// environment (no SMTP configured), which makes the question unanswerable.
// One unlock-link sender serves both factors since F-26 (`sendAccountUnlockEmail(email,
// token, factor)`); the second factor's alert left the email module for the security
// notice helper. Each factor's link is still observed on a spy of its own, so every
// assertion below keeps its meaning: `password` for the password factor's link,
// `secondFactor` for the two-factor step's.
const unlockMails = vi.hoisted(() => ({
  password: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  secondFactor: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
}));

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: (email: string, token: string, factor = 'password') =>
      (factor === 'second_factor' ? unlockMails.secondFactor : unlockMails.password)(email, token),
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

const mockedUnlockEmail = unlockMails.password;
const mockedSecondFactorEmail = unlockMails.secondFactor;
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

/** The PASSWORD factor's state (the legacy top-level fields). */
async function counterOf(userId: string): Promise<{ attempts: number; lockoutUntil?: Date }> {
  const row = await User.findById(userId);
  expect(row).not.toBeNull();
  return {
    attempts: row!.failedLoginAttempts,
    ...(row!.lockoutUntil ? { lockoutUntil: row!.lockoutUntil } : {}),
  };
}

/** The SECOND factor's state (`secondFactorLockout`, `select: false`). */
async function secondFactorOf(userId: string): Promise<{ attempts: number; lockoutUntil?: Date }> {
  const row = await User.findById(userId).select('+secondFactorLockout');
  expect(row).not.toBeNull();
  const state = row!.secondFactorLockout;
  return {
    attempts: state?.failedAttempts ?? 0,
    ...(state?.until ? { lockoutUntil: state.until } : {}),
  };
}

describe('A1 — each factor keeps its own lockout counter across the two steps', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
    // Re-armed rather than merely cleared: the sender is fire-and-forget
    // (`void send(...).then(...)`), so it must keep returning a promise.
    mockedUnlockEmail.mockReset();
    mockedUnlockEmail.mockResolvedValue({ success: true, message: 'sent' });
    mockedSecondFactorEmail.mockReset();
    mockedSecondFactorEmail.mockResolvedValue({ success: true, message: 'sent' });
  });

  it(
    'still locks the second factor after MAX_LOGIN_ATTEMPTS total 2FA failures even when a ' +
      'successful password step is replayed between them',
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
      expect((await secondFactorOf(user.id)).attempts).toBe(half);

      // ── The replay: a SUCCESSFUL password step, mid-attack ─────────────────
      // The password is correct, so the request returns 200 — but it completes
      // no authentication, because the account still owes a second factor. It
      // must therefore reset nothing.
      const secondToken = await challenge(agent, user);

      const afterReplay = await secondFactorOf(user.id);
      expect(afterReplay.attempts).toBe(half);
      expect(afterReplay.lockoutUntil).toBeUndefined();

      // ── Second batch, under the replayed challenge ─────────────────────────
      for (let i = 0; i < half; i++) {
        const res = await post2fa(agent, secondToken, wrongCode(secret));
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('TWO_FA_INVALID');
      }

      // MAX_LOGIN_ATTEMPTS wrong codes in total — the SECOND factor is locked,
      // and the password factor (proven every time) is not.
      const locked = await secondFactorOf(user.id);
      expect(locked.attempts).toBe(MAX_LOGIN_ATTEMPTS);
      expect(locked.lockoutUntil).toBeDefined();
      expect(locked.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
      expect(await counterOf(user.id)).toEqual({ attempts: 0 });

      // The threshold was crossed exactly once, so exactly one mail, and it is
      // the second-factor one (it tells the owner the password was entered).
      expect(mockedSecondFactorEmail).toHaveBeenCalledTimes(1);
      expect(mockedSecondFactorEmail.mock.calls[0]![0]).toBe(user.email);
      expect(mockedUnlockEmail).not.toHaveBeenCalled();

      // The second step refuses before the code is read (the password is proven
      // there, so the distinct answer is no oracle)...
      const blocked2fa = await post2fa(agent, secondToken, wrongCode(secret));
      expect(blocked2fa.status).toBe(403);
      expect(blocked2fa.body.message).toBe('ACCOUNT_LOCKED');

      // ...while the password step, which reads only the password factor, keeps
      // answering the correct password with a challenge. It used to answer 403
      // ACCOUNT_LOCKED here, which confirmed the password to whoever sent it.
      const passwordStep = await postLogin(agent, user.email, user.rawPassword);
      expect(passwordStep.status).toBe(200);
      expect(passwordStep.body.data.twoFactorRequired).toBe(true);
      expect(passwordStep.body.data.accessToken).toBeUndefined();

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
    // ...while the PASSWORD factor's durable counter survives an authentication
    // that has not completed (only a completed sign-in clears it).
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
    expect((await secondFactorOf(user.id)).attempts).toBe(4);

    const res = await post2fa(agent, tempToken, totpFor(secret).generate());
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();

    const after = await secondFactorOf(user.id);
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
      'is discharged by the password step, and the second factor then keeps its own budget ' +
        'and its own mail',
      async () => {
        const { user, secret } = await create2faUser();
        await expireLockout(user.id);

        // The thirty minutes were actually served, so the correct password
        // discharges the PASSWORD factor's state at this step.
        const tempToken = await challenge(agent, user);

        const discharged = await counterOf(user.id);
        expect(discharged.attempts).toBe(0);
        expect(discharged.lockoutUntil).toBeUndefined();

        // Ten wrong codes now spend the SECOND factor's own budget of ten, and
        // lock that factor alone.
        for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
          expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
        }

        const relocked = await secondFactorOf(user.id);
        expect(relocked.attempts).toBe(MAX_LOGIN_ATTEMPTS);
        expect(relocked.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
        expect(await counterOf(user.id)).toEqual({ attempts: 0 });

        // The crossing was clean, so a fresh second-factor link was mailed.
        expect(mockedSecondFactorEmail).toHaveBeenCalledTimes(1);
        expect(mockedSecondFactorEmail.mock.calls[0]![0]).toBe(user.email);
        expect(mockedUnlockEmail).not.toHaveBeenCalled();
      },
      60_000,
    );

    it('is NOT discharged while it is still running, and the deadline is not rewritten', async () => {
      const { user } = await create2faUser();
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: MAX_LOGIN_ATTEMPTS, lockoutUntil },
      });

      // F-03: an unproven browser gets the wrong-password answer during a
      // running lockout, right password or not (this pinned 403 ACCOUNT_LOCKED).
      const res = await postLogin(agent, user.email, user.rawPassword);
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Invalid email or password');
      expect(res.body.data?.tempToken).toBeUndefined();

      // Nothing moved: not the count, and not the deadline (the lockout is fresh,
      // and the outstanding unlock link names the lock episode, which a password
      // alone never discharges while the lockout runs).
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
      expect((await secondFactorOf(user.id)).attempts).toBe(4);

      // The cookie is a possession factor a prior successful 2FA minted, and it
      // is burned as it is spent — so this IS a completed authentication, and it
      // issues a real session rather than another challenge.
      const res = await postLogin(agent, user.email, user.rawPassword, `trustedDevice=${raw}`);
      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBeUndefined();
      expect(res.body.data.accessToken).toBeDefined();

      const after = await secondFactorOf(user.id);
      expect(after.attempts).toBe(0);
      expect(after.lockoutUntil).toBeUndefined();
    }, 30_000);

    it('leaves the counter alone when the cookie is rejected and the challenge returns', async () => {
      const { user, secret } = await create2faUser();

      const tempToken = await challenge(agent, user);
      for (let i = 0; i < 4; i++) {
        expect((await post2fa(agent, tempToken, wrongCode(secret))).status).toBe(401);
      }
      expect((await secondFactorOf(user.id)).attempts).toBe(4);

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

      const after = await secondFactorOf(user.id);
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
