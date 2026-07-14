/**
 * Phase 2 — login progressive-delay enumeration oracle (#1)
 *
 * `POST /auth/login` used to source its progressive delay from the durable
 * `User.failedLoginAttempts` counter, which only exists for a REAL account. A
 * non-existent email was therefore never delayed while an existing one slept
 * 1s/3s/5s — a multi-second timing oracle that told an attacker which emails
 * were registered, defeating the dummy-bcrypt equalization sitting right next
 * to it.
 *
 * The delay is now driven by the process-local per-email throttle
 * (`utils/loginThrottle.ts`), which counts attempts against ANY email. Every
 * branch of `login` that returns the generic "Invalid email or password" 401
 * must record exactly once, so all of them sleep for exactly the same time:
 *
 *   (a) the email does not exist;
 *   (b) wrong password against a LOCKED account (returns the same generic 401,
 *       so omitting it would make a locked account answer fast while an unknown
 *       email slept — an inverse oracle);
 *   (c) wrong password against an unlocked account.
 *
 * The real sleeps are skipped under `isTest`, so these tests assert the delay's
 * INPUT: the throttle count each branch produces, and the delay
 * `getProgressiveDelay` derives from it. `User.failedLoginAttempts` remains the
 * sole lockout driver and is asserted to stay independent.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Spy on the throttle while keeping its real behaviour, so we can assert each
// failing branch records EXACTLY once (a branch that recorded twice would sleep
// twice and reopen the asymmetry).
vi.mock('../src/utils/loginThrottle.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/loginThrottle.js')>();
  return {
    ...actual,
    recordFailedLoginAttempt: vi.fn(actual.recordFailedLoginAttempt),
    resetLoginAttempts: vi.fn(actual.resetLoginAttempts),
  };
});

import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { getProgressiveDelay } from '../src/controllers/authController.js';
import {
  recordFailedLoginAttempt,
  peekLoginAttempts,
  clearLoginThrottle,
} from '../src/utils/loginThrottle.js';
import { createTestUser, getCsrf, type CsrfPair } from './helpers.js';

const API = '/api/v1';
const LOCKOUT_MS = 30 * 60 * 1000;

const mockedRecord = vi.mocked(recordFailedLoginAttempt);

function withCsrf(req: request.Test, csrf: CsrfPair): request.Test {
  return req.set('x-csrf-token', csrf.token).set('Cookie', csrf.cookie);
}

describe('login progressive-delay symmetry (#1)', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    clearLoginThrottle();
    mockedRecord.mockClear();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  /** One failed login attempt. Returns the HTTP status. */
  async function failedLogin(email: string, authHash = 'wrong-password'): Promise<number> {
    const res = await withCsrf(agent.post(`${API}/auth/login`).send({ email, authHash }), csrf);
    return res.status;
  }

  /** The delay `login` would have slept for, given the throttle's current count. */
  function currentDelayFor(email: string): number {
    return getProgressiveDelay(peekLoginAttempts(email));
  }

  describe('the delay a failed login incurs is identical for a real and an unknown email', () => {
    it('ramps identically across the full 0 → 1s → 3s → 5s curve', async () => {
      const existing = await createTestUser({ emailVerified: true });
      const unknown = 'never-registered@example.com';

      const existingDelays: number[] = [];
      const unknownDelays: number[] = [];

      for (let attempt = 1; attempt <= 7; attempt++) {
        expect(await failedLogin(existing.email)).toBe(401);
        existingDelays.push(currentDelayFor(existing.email));

        expect(await failedLogin(unknown)).toBe(401);
        unknownDelays.push(currentDelayFor(unknown));
      }

      expect(unknownDelays).toEqual(existingDelays);
      // And the curve is the real one — a fix that simply delayed nothing at all
      // would also be "symmetric", so pin the actual values.
      expect(existingDelays).toEqual([0, 0, 1000, 1000, 3000, 3000, 5000]);
    });

    it('delays an unknown email on its very first attempt exactly as a real one', async () => {
      const existing = await createTestUser({ emailVerified: true });

      await failedLogin(existing.email);
      await failedLogin('unknown-first@example.com');

      expect(peekLoginAttempts('unknown-first@example.com')).toBe(
        peekLoginAttempts(existing.email),
      );
    });
  });

  describe('every generic-401 branch records exactly once', () => {
    it('records once for a non-existent email', async () => {
      expect(await failedLogin('no-such-user@example.com')).toBe(401);

      expect(mockedRecord).toHaveBeenCalledTimes(1);
      expect(mockedRecord).toHaveBeenCalledWith('no-such-user@example.com');
    });

    it('records once for a wrong password on an unlocked account', async () => {
      const user = await createTestUser({ emailVerified: true });

      expect(await failedLogin(user.email)).toBe(401);

      // Exactly once: the old DB-counter sleep was REPLACED, not added to. Two
      // records here would mean this branch sleeps twice as long as branch (a).
      expect(mockedRecord).toHaveBeenCalledTimes(1);
      expect(mockedRecord).toHaveBeenCalledWith(user.email);
    });

    it('records once for a wrong password on a LOCKED account', async () => {
      const user = await createTestUser({ emailVerified: true });
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil: new Date(Date.now() + LOCKOUT_MS) },
      });

      // Same generic 401 as an unknown email — so it must carry the same delay.
      expect(await failedLogin(user.email)).toBe(401);
      expect(mockedRecord).toHaveBeenCalledTimes(1);
    });
  });

  describe('a locked account is not a fast-path oracle', () => {
    it('delays a locked account exactly as an unknown email at the same attempt count', async () => {
      const locked = await createTestUser({ emailVerified: true });
      await User.findByIdAndUpdate(locked.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil: new Date(Date.now() + LOCKOUT_MS) },
      });
      const unknown = 'unknown-vs-locked@example.com';

      for (let attempt = 1; attempt <= 5; attempt++) {
        expect(await failedLogin(locked.email)).toBe(401);
        expect(await failedLogin(unknown)).toBe(401);

        expect(currentDelayFor(locked.email)).toBe(currentDelayFor(unknown));
      }

      // Both reached the 3s band — the locked account is not answering instantly.
      expect(currentDelayFor(locked.email)).toBe(3000);
    });

    it('still leaves lockout state untouched on the locked branch', async () => {
      const locked = await createTestUser({ emailVerified: true });
      const lockoutUntil = new Date(Date.now() + LOCKOUT_MS);
      await User.findByIdAndUpdate(locked.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil },
      });

      await failedLogin(locked.email);

      // The throttle only sleeps. It must not extend the lockout or bump the
      // counter, or the unlock email already issued (its token bound to
      // lockoutUntil) would be invalidated.
      const after = await User.findById(locked.id);
      expect(after!.failedLoginAttempts).toBe(10);
      expect(after!.lockoutUntil?.getTime()).toBe(lockoutUntil.getTime());
    });
  });

  describe('the delay is decoupled from the database lockout counter', () => {
    it('derives the delay from the throttle, not from failedLoginAttempts', async () => {
      const user = await createTestUser({ emailVerified: true });
      // Simulate failures already banked in the database (an earlier session, or
      // another worker in the cluster) with nothing yet in this process.
      await User.findByIdAndUpdate(user.id, { $set: { failedLoginAttempts: 6 } });

      await failedLogin(user.email);

      // Throttle-driven: first attempt seen here, so no delay — exactly what an
      // unknown email's first attempt gets. Under the old DB-driven delay this
      // request slept 5s while an unknown email slept 0s.
      expect(peekLoginAttempts(user.email)).toBe(1);
      expect(currentDelayFor(user.email)).toBe(0);

      // Lockout still advances on the durable counter, untouched by this change.
      const after = await User.findById(user.id);
      expect(after!.failedLoginAttempts).toBe(7);
    });

    it('locks the account at the threshold regardless of the in-memory throttle', async () => {
      const user = await createTestUser({ emailVerified: true });
      await User.findByIdAndUpdate(user.id, { $set: { failedLoginAttempts: 9 } });

      await failedLogin(user.email);

      const after = await User.findById(user.id);
      expect(after!.failedLoginAttempts).toBe(10);
      expect(after!.lockoutUntil).toBeTruthy();
    });
  });

  describe('a successful login clears the throttle', () => {
    it('resets the count after correct credentials', async () => {
      const user = await createTestUser({ emailVerified: true });

      await failedLogin(user.email);
      await failedLogin(user.email);
      expect(peekLoginAttempts(user.email)).toBe(2);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({ email: user.email, authHash: user.rawPassword }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(peekLoginAttempts(user.email)).toBe(0);
    });

    it('resets a count accrued while the account was locked, once it unlocks', async () => {
      const user = await createTestUser({ emailVerified: true });
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil: new Date(Date.now() + LOCKOUT_MS) },
      });

      // Attempts on the locked branch never touch `failedLoginAttempts`...
      await failedLogin(user.email);
      await failedLogin(user.email);
      expect(peekLoginAttempts(user.email)).toBe(2);

      // ...so once the lockout is lifted, a successful login lands with the DB
      // counter already at 0. The throttle reset must NOT be gated on that
      // counter, or this stale count of 2 would survive and delay the next typo.
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: 0 },
        $unset: { lockoutUntil: 1 },
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({ email: user.email, authHash: user.rawPassword }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(peekLoginAttempts(user.email)).toBe(0);
    });

    it('resets before the 2FA step returns its temp token', async () => {
      const user = await createTestUser({ emailVerified: true, twoFactorEnabled: true });

      await failedLogin(user.email);
      expect(peekLoginAttempts(user.email)).toBe(1);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({ email: user.email, authHash: user.rawPassword }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBe(true);
      // The password check succeeded, so the throttle is cleared even though
      // `login` returns early for the 2FA step.
      expect(peekLoginAttempts(user.email)).toBe(0);
    });
  });

  describe('the unknown-email path is otherwise unchanged', () => {
    it('returns the same generic message as a wrong password', async () => {
      const user = await createTestUser({ emailVerified: true });

      const unknownRes = await withCsrf(
        agent
          .post(`${API}/auth/login`)
          .send({ email: 'still-generic@example.com', authHash: 'wrong-password' }),
        csrf,
      );
      const wrongPwRes = await withCsrf(
        agent.post(`${API}/auth/login`).send({ email: user.email, authHash: 'wrong-password' }),
        csrf,
      );

      expect(unknownRes.status).toBe(401);
      expect(wrongPwRes.status).toBe(401);
      expect(unknownRes.body.error?.message).toBe(wrongPwRes.body.error?.message);
    });

    it('does not create a User row for an unknown email', async () => {
      await failedLogin('phantom@example.com');

      expect(await User.countDocuments({ email: 'phantom@example.com' })).toBe(0);
      expect(peekLoginAttempts('phantom@example.com')).toBe(1);
    });
  });
});
