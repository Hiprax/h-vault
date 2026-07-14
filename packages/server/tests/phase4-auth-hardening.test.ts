/**
 * Phase 4 — Auth anti-enumeration & 2FA hardening
 *
 *   • T7 — forgotPassword / resendVerification send their email fire-and-forget
 *     so the existing-user path no longer awaits the SMTP round-trip, closing
 *     the email-enumeration timing side-channel.
 *   • T8 — account lockout is no longer an existence oracle on login: a locked
 *     account is indistinguishable from invalid credentials unless the correct
 *     password is supplied.
 *   • T9 — the 2FA step has account-scoped brute-force throttling parity with
 *     the password step (failed codes increment the shared lockout counter),
 *     and a successful 2FA verification resets that counter.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// ── Mock the email module BEFORE importing app ───────────────────────────────
// Only the two senders used by the fire-and-forget paths under test are
// overridden; every other sender keeps its real (test-env no-op) behaviour.
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...original,
    sendPasswordResetEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
    sendVerificationEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
  type EmailResult,
} from '../src/utils/email.js';
import { createTestUser, deriveTestPurposeKey, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const BCRYPT_ROUNDS = 4;
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

const mockedResetEmail = vi.mocked(sendPasswordResetEmail);
const mockedVerifEmail = vi.mocked(sendVerificationEmail);

/** A deferred email send we resolve manually, to assert response/send ordering. */
function deferredSend(): {
  promise: Promise<EmailResult>;
  resolve: () => void;
  isResolved: () => boolean;
} {
  let resolveFn!: () => void;
  let resolved = false;
  const promise = new Promise<EmailResult>((resolve) => {
    resolveFn = () => {
      resolved = true;
      resolve({ success: true, message: 'sent' });
    };
  });
  return { promise, resolve: resolveFn, isResolved: () => resolved };
}

/** Creates a 2FA-enabled user and returns the user + its TOTP secret. */
async function create2faUser(
  rawCodes: string[] = [],
): Promise<{ user: TestUser; secretObj: Secret }> {
  const secretObj = new Secret();
  const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);
  const user = await createTestUser({ emailVerified: true });

  const hashedCodes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, BCRYPT_ROUNDS)));

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: encryptedSecret,
      backupCodes: hashedCodes,
      lastTotpTimestamp: 1, // old timestamp so fresh codes are accepted
    },
  });

  return { user, secretObj };
}

function makeTempToken(userId: string): string {
  return jwt.sign({ userId, purpose: '2fa_temp' }, deriveTestPurposeKey('2fa_temp'), {
    expiresIn: '5m',
  });
}

describe('Phase 4 — Auth anti-enumeration & 2FA hardening', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    mockedResetEmail.mockReset();
    mockedResetEmail.mockResolvedValue({ success: true, message: 'sent' });
    mockedVerifEmail.mockReset();
    mockedVerifEmail.mockResolvedValue({ success: true, message: 'sent' });
  });

  // ── T7 — fire-and-forget email send ────────────────────────────────────────

  describe('T7 — SMTP send is fire-and-forget (no enumeration timing channel)', () => {
    it('returns the forgot-password response BEFORE the SMTP send resolves', async () => {
      const user = await createTestUser({ email: `t7-fp-${crypto.randomUUID()}@example.com` });

      // If the controller awaited the send, the request would hang until we
      // resolve this deferred (which we do not before awaiting the response),
      // so the test would time out. With fire-and-forget the response returns
      // while the send is still pending.
      const send = deferredSend();
      mockedResetEmail.mockReturnValueOnce(send.promise);

      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/forgot-password`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: user.email });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockedResetEmail).toHaveBeenCalledTimes(1);
      // The HTTP response came back while the slow send was still pending.
      expect(send.isResolved()).toBe(false);

      send.resolve();
      await send.promise;
    });

    it('returns the resend-verification response BEFORE the SMTP send resolves', async () => {
      const user = await createTestUser({
        email: `t7-rv-${crypto.randomUUID()}@example.com`,
        emailVerified: false,
      });

      const send = deferredSend();
      mockedVerifEmail.mockReturnValueOnce(send.promise);

      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/resend-verification`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: user.email });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockedVerifEmail).toHaveBeenCalledTimes(1);
      expect(send.isResolved()).toBe(false);

      send.resolve();
      await send.promise;
    });

    it('does not send (or await) any email for a non-existent forgot-password email', async () => {
      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/forgot-password`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: `ghost-${crypto.randomUUID()}@example.com` });

      // Generic success response, identical to the existing-user path...
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      // ...but no reset email is initiated for a non-existent account.
      expect(mockedResetEmail).not.toHaveBeenCalled();
    });
  });

  // ── T8 — lockout is not an enumeration oracle ──────────────────────────────

  describe('T8 — account lockout is not an existence oracle', () => {
    async function lock(userId: string, lockoutUntil: Date): Promise<void> {
      await User.updateOne({ _id: userId }, { $set: { failedLoginAttempts: 10, lockoutUntil } });
    }

    it('a locked account + wrong password is indistinguishable from a non-existent email', async () => {
      const user = await createTestUser({ email: `t8-locked-${crypto.randomUUID()}@example.com` });
      await lock(user.id, new Date(Date.now() + 30 * 60 * 1000));

      const c1 = await getCsrf(agent);
      const lockedRes = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', c1.token)
        .set('Cookie', c1.cookie)
        .send({ email: user.email, authHash: 'wrong-password' });

      const c2 = await getCsrf(agent);
      const ghostRes = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', c2.token)
        .set('Cookie', c2.cookie)
        .send({ email: `never-${crypto.randomUUID()}@example.com`, authHash: 'wrong-password' });

      // Same status AND same message — no distinguishable signal.
      expect(lockedRes.status).toBe(401);
      expect(ghostRes.status).toBe(401);
      expect(lockedRes.body.success).toBe(false);
      expect(lockedRes.body.message).toBe(ghostRes.body.message);
    });

    it('reveals ACCOUNT_LOCKED only when the correct password is supplied', async () => {
      const user = await createTestUser({ email: `t8-owner-${crypto.randomUUID()}@example.com` });
      await lock(user.id, new Date(Date.now() + 30 * 60 * 1000));

      // Wrong password on the same locked account must NOT reveal the lockout —
      // it returns the generic 401 (this half fails against the old code, which
      // surfaced 403 ACCOUNT_LOCKED before the password was ever checked).
      const wrong = await getCsrf(agent);
      const wrongRes = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', wrong.token)
        .set('Cookie', wrong.cookie)
        .send({ email: user.email, authHash: 'definitely-wrong' });
      expect(wrongRes.status).toBe(401);
      expect(wrongRes.body.message).not.toBe('ACCOUNT_LOCKED');

      // The correct password reveals the lockout to the legitimate owner.
      const right = await getCsrf(agent);
      const rightRes = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', right.token)
        .set('Cookie', right.cookie)
        .send({ email: user.email, authHash: user.rawPassword });
      expect(rightRes.status).toBe(403);
      expect(rightRes.body.message).toBe('ACCOUNT_LOCKED');
    });

    it('does not mutate lockout state on a wrong-password attempt against a locked account', async () => {
      const user = await createTestUser({ email: `t8-immut-${crypto.randomUUID()}@example.com` });
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await lock(user.id, lockoutUntil);

      const { token, cookie } = await getCsrf(agent);
      await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: user.email, authHash: 'still-wrong' });

      const after = await User.findById(user.id);
      expect(after!.failedLoginAttempts).toBe(10); // not incremented while locked
      expect(after!.lockoutUntil!.getTime()).toBe(lockoutUntil.getTime()); // unchanged
    });
  });

  // ── T9 — 2FA brute-force throttling parity ─────────────────────────────────

  describe('T9 — 2FA step has account-scoped brute-force throttling', () => {
    it('locks the account after MAX failed 2FA attempts and then blocks with ACCOUNT_LOCKED', async () => {
      const { user } = await create2faUser(['realbackupcode01']);

      // 10 invalid codes (16-char alphanumeric — passes schema, fails verify).
      for (let i = 0; i < 10; i++) {
        const tempToken = makeTempToken(user.id);
        const { token, cookie } = await getCsrf(agent);
        const res = await agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', token)
          .set('Cookie', cookie)
          .send({ tempToken, code: `wrong0000000000${i}` });
        expect(res.status).toBe(401);
      }

      const locked = await User.findById(user.id);
      expect(locked!.failedLoginAttempts).toBe(10);
      expect(locked!.lockoutUntil).toBeDefined();
      expect(locked!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

      // A further attempt (even with a fresh, valid temp token) is now blocked
      // by the lockout check before the code is ever evaluated.
      const tempToken = makeTempToken(user.id);
      const { token, cookie } = await getCsrf(agent);
      const blocked = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ tempToken, code: 'wrong00000000099' });

      expect(blocked.status).toBe(403);
      expect(blocked.body.message).toBe('ACCOUNT_LOCKED');
    }, 30_000);

    it('increments the shared failed-attempt counter on a single wrong 2FA code', async () => {
      const { user } = await create2faUser(['realbackupcode02']);

      const tempToken = makeTempToken(user.id);
      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ tempToken, code: 'totallywrong0001' });

      expect(res.status).toBe(401);

      const after = await User.findById(user.id);
      expect(after!.failedLoginAttempts).toBe(1);
      expect(after!.lockoutUntil).toBeUndefined();
    });

    it('resets the failed-attempt counter on a successful 2FA verification', async () => {
      const { user, secretObj } = await create2faUser([]);
      // Simulate earlier wrong-code attempts in this 2FA session (below threshold).
      await User.findByIdAndUpdate(user.id, { $set: { failedLoginAttempts: 4 } });

      const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
      const validCode = totp.generate();

      const tempToken = makeTempToken(user.id);
      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ tempToken, code: validCode });

      expect(res.status).toBe(200);

      const after = await User.findById(user.id);
      expect(after!.failedLoginAttempts).toBe(0);
      expect(after!.lockoutUntil).toBeUndefined();
    });
  });
});
