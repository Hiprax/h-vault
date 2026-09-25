/**
 * A locked account must always hold a recovery link that still works.
 *
 * ## The permanent-lockout path this file closes
 *
 * Account lockout is the one control in H-Vault that anybody can trigger against
 * anybody: it needs the victim's email address and nothing else. That is
 * acceptable only because it expires — "30 minutes after 10 failed attempts",
 * as `README.md` puts it — and because the owner is mailed a link that ends it
 * sooner.
 *
 * Neither held. `failedLoginAttempts` is cleared only where an authentication
 * COMPLETES, so an account that was locked and then abandoned sits at 10 for
 * ever. Every later wrong password is therefore also "at or past the threshold",
 * which re-wrote `lockoutUntil` for another 30 minutes AND, because the unlock
 * token's `stateHash` was bound to that exact timestamp, invalidated the only
 * link the owner had ever been sent. No replacement was issued, because the mail
 * was guarded by `newAttempts === MAX_FAILED_ATTEMPTS` and 11 is not 10. One
 * wrong password every half hour — well inside `authLimiter`'s 20 per IP per 15
 * minutes and `accountLimiter`'s 20 per email per 15 minutes — locked a stranger
 * out of their vault indefinitely.
 *
 * The only remaining exit was `POST /auth/reset-password`, and in this product
 * that is not a recovery path: the client mints a FRESH vault key during a reset
 * (`ResetPasswordPage.tsx`: "old data encrypted with the previous key is
 * unrecoverable"). So the shipped answer to a permanent lockout was total data
 * loss.
 *
 * ## What is pinned here
 *
 * The fix binds the unlock token to a lock EPISODE — `User.lockoutEpisodeId`, a
 * value minted when a lockout begins, carried unchanged through every re-lock,
 * and cleared only when the lockout is genuinely discharged — and replaces the
 * equality mail guard with "is a link that outlives this lockout already
 * outstanding?".
 *
 * These tests drive the real endpoints against a real `mongod` and assert the
 * observable end state, because the claim is about what a victim can do, not
 * about the shape of a token:
 *
 *  1. the 11th wrong password re-locks, and the link mailed at the 10th STILL
 *     unlocks the account, which then genuinely signs in;
 *  2. the account is never left with a live lockout and no live link — once the
 *     outstanding token can no longer cover the lockout, the next failure mails
 *     a replacement that works;
 *  3. neither of those turns the mailer into a flood: a re-lock while a covering
 *     link is outstanding sends nothing;
 *  4. the same holds for the 2FA step, which carries the same lock logic;
 *  5. an account already locked when this code was deployed (a lockout with no
 *     episode) recovers on its next failed attempt rather than needing a
 *     migration.
 *
 * Every case carries the negative that matters: exactly how many mails were
 * sent, and that a spent link cannot be replayed.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// The unlock mailer is stubbed so "was a link sent, and which one?" is directly
// observable. The real sender is an inert no-op in the test environment (no SMTP
// configured), which would make the token unreadable rather than absent.
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import type { HydratedDocument } from 'mongoose';
import { CryptoManager } from '@hiprax/crypto';
import { LOCKOUT_DURATION_MINUTES, MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import type { IUser } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { sendAccountUnlockEmail } from '../src/utils/email.js';
import {
  authHeader,
  createTestUser,
  generateStateHash,
  getCsrf,
  deriveTestPurposeKey,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const BCRYPT_ROUNDS = 4;
const LOCKOUT_DURATION_MS = LOCKOUT_DURATION_MINUTES * 60 * 1000;

const mockedUnlockEmail = vi.mocked(sendAccountUnlockEmail);
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/**
 * Reads a user back INCLUDING the episode fields. Both are `select: false` on the
 * model — they are internal bookkeeping and `getProfile` answers with a lean
 * spread of everything that is not hidden — so a plain `findById` returns them as
 * `undefined` and every assertion below would pass vacuously.
 */
async function readUser(id: string): Promise<HydratedDocument<IUser>> {
  const doc = await User.findById(id).select('+lockoutEpisodeId +lockoutNotifiedAt');
  expect(doc, 'user should exist').not.toBeNull();
  return doc!;
}

/** The token argument of the Nth unlock mail (0-based), as the mailer saw it. */
function mailedToken(call: number): string {
  const args = mockedUnlockEmail.mock.calls[call];
  expect(args, `expected an unlock email at index ${call}`).toBeDefined();
  return args![1];
}

async function postLogin(
  agent: request.Agent,
  email: string,
  authHash: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login`)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ email, authHash });
}

async function postUnlock(agent: request.Agent, token: string): Promise<request.Response> {
  const { token: csrf, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/unlock-account`)
    .set('x-csrf-token', csrf)
    .set('Cookie', cookie)
    .send({ token });
}

/** Drives wrong passwords until the account crosses the lockout threshold. */
async function lockOut(agent: request.Agent, user: TestUser): Promise<void> {
  for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i += 1) {
    const res = await postLogin(agent, user.email, 'wrong-auth-hash');
    expect(res.status).toBe(401);
  }
}

/**
 * Rewinds the stored lockout deadline into the past, which is what the passage
 * of `LOCKOUT_DURATION_MINUTES` looks like to every reader of the field. Fake
 * timers are not usable here: the handlers, the driver and `mongod` would have
 * to agree on the clock, and supertest's sockets would stall on the first one
 * that did not.
 */
async function expireLockout(userId: string): Promise<void> {
  await User.findByIdAndUpdate(userId, {
    $set: { lockoutUntil: new Date(Date.now() - 60_000) },
  });
}

describe('lockout recovery — the emailed unlock link survives a re-lock', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    // Re-arm rather than merely clear: the sender is fire-and-forget
    // (`void send(...).then(...)`), so it must keep returning a promise.
    mockedUnlockEmail.mockReset();
    mockedUnlockEmail.mockResolvedValue({ success: true, message: 'sent' });
    user = await createTestUser({ emailVerified: true });
  });

  it('lets the link mailed at the threshold unlock an account the 11th attempt re-locked', async () => {
    await lockOut(agent, user);

    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    const link = mailedToken(0);

    const locked = await readUser(user.id);
    expect(locked!.failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS);
    expect(locked!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
    const firstDeadline = locked!.lockoutUntil!.getTime();
    const episode = locked!.lockoutEpisodeId;
    expect(episode).toBeTruthy();
    // The link that was actually mailed names that episode…
    const claims = jwt.decode(link) as { stateHash?: string; exp?: number } | null;
    expect(claims?.stateHash).toBe(generateStateHash(episode!));

    // …and outlives the lockout it was minted for. This is the load-bearing
    // relation between the token's hour and the lockout's half hour, and it is
    // pinned HERE because nothing else enforces it: `LOCKOUT_DURATION_MINUTES` is
    // a shared constant editable from another package, and raising it past the
    // token's lifetime would silently turn every mailed link into one that dies
    // before the lockout does — with the entire suite still green.
    expect(claims?.exp).toBeDefined();
    expect(claims!.exp! * 1000).toBeGreaterThan(locked!.lockoutUntil!.getTime());

    // The lockout is waited out, and one more wrong password arrives — the
    // ordinary shape of a grinding attack, and the exact input that used to
    // strand the victim.
    await expireLockout(user.id);
    const eleventh = await postLogin(agent, user.email, 'wrong-auth-hash');
    expect(eleventh.status).toBe(401);
    expect(eleventh.body.message).toBe('Invalid email or password');

    const relocked = await readUser(user.id);
    expect(relocked!.failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS + 1);
    // Genuinely re-locked (the brake still works) and on a NEW deadline.
    expect(relocked!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
    expect(relocked!.lockoutUntil!.getTime()).not.toBe(firstDeadline);
    // …on the SAME episode. This is the identity the outstanding link is bound
    // to, and a re-lock that minted a new one would orphan that link exactly as
    // rewriting the deadline used to.
    expect(relocked!.lockoutEpisodeId).toBe(episode);

    // No second mail: a link that still covers this lockout is outstanding, so
    // re-mailing would be a flood vector and nothing else.
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);

    // The point of the whole phase — the only link the victim ever received
    // still works.
    const unlocked = await postUnlock(agent, link);
    expect(unlocked.status).toBe(200);
    expect(unlocked.body.success).toBe(true);

    const after = await readUser(user.id);
    expect(after!.failedLoginAttempts).toBe(0);
    expect(after!.lockoutUntil).toBeUndefined();
    // The episode is discharged WHOLE. A surviving `lockoutEpisodeId` would keep
    // the spent link alive; a surviving `lockoutNotifiedAt` would suppress the
    // mail for the next lockout.
    expect(after!.lockoutEpisodeId).toBeUndefined();
    expect(after!.lockoutNotifiedAt).toBeUndefined();

    // And the recovery is real, end to end: the owner can sign in again.
    const signedIn = await postLogin(agent, user.email, user.rawPassword);
    expect(signedIn.status).toBe(200);
    expect(signedIn.body.data.accessToken).toBeDefined();

    // The spent link is single-use: a replay must not re-run the unlock.
    const replay = await postUnlock(agent, link);
    expect(replay.status).toBe(400);
    expect(replay.body.message).toBe('TOKEN_INVALID');
  });

  it('mails a working replacement once the outstanding link can no longer cover the lockout', async () => {
    await lockOut(agent, user);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);

    // The outstanding link was minted long enough ago that it will expire before
    // the lockout a further failure is about to write. That is precisely the
    // state in which the account would otherwise be left locked with no usable
    // link, so the next failure has to mail a replacement.
    await expireLockout(user.id);
    await User.findByIdAndUpdate(user.id, {
      $set: { lockoutNotifiedAt: new Date(Date.now() - 2 * 60 * 60 * 1000) },
    });

    const again = await postLogin(agent, user.email, 'wrong-auth-hash');
    expect(again.status).toBe(401);

    expect(mockedUnlockEmail).toHaveBeenCalledTimes(2);
    const replacement = mailedToken(1);

    // The replacement names the episode that is STILL RUNNING — not a new one
    // (which would have orphaned the link the owner may already have opened) and
    // not the empty string (which would match every account with no lockout).
    // The two tokens may even be byte-identical when both are minted in the same
    // second, and that is correct: one episode, one capability.
    const stillLocked = await readUser(user.id);
    expect(stillLocked!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
    expect(stillLocked!.lockoutEpisodeId).toBeTruthy();
    const decoded = jwt.decode(replacement) as { stateHash?: string } | null;
    expect(decoded?.stateHash).toBe(generateStateHash(stillLocked!.lockoutEpisodeId!));

    const unlocked = await postUnlock(agent, replacement);
    expect(unlocked.status).toBe(200);

    const after = await readUser(user.id);
    expect(after!.lockoutUntil).toBeUndefined();
    expect(after!.failedLoginAttempts).toBe(0);
  });

  it('keeps an account locked before this code existed recoverable without a migration', async () => {
    // A lockout written by the previous release: a deadline, a counter past the
    // threshold, and no episode of any kind. Its outstanding link is bound to
    // the old value and is gone; what must NOT be gone is the ability to get a
    // new one.
    await User.findByIdAndUpdate(user.id, {
      $set: {
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
        lockoutUntil: new Date(Date.now() - 60_000),
      },
    });

    const next = await postLogin(agent, user.email, 'wrong-auth-hash');
    expect(next.status).toBe(401);

    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    const link = mailedToken(0);

    const unlocked = await postUnlock(agent, link);
    expect(unlocked.status).toBe(200);

    const after = await readUser(user.id);
    expect(after!.lockoutUntil).toBeUndefined();
    expect(after!.failedLoginAttempts).toBe(0);
  });

  it('keeps the 2FA step on the same episode, so its link survives a re-lock too', async () => {
    const secretObj = new Secret();
    const twoFa = await createTestUser({ emailVerified: true });
    await User.findByIdAndUpdate(twoFa.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: cm.encryptTextSync(secretObj.base32, encKey),
        backupCodes: [await bcrypt.hash('abcdef0123456789', BCRYPT_ROUNDS)],
        lastTotpTimestamp: 1,
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS - 1,
      },
    });

    const tempToken = jwt.sign(
      { userId: twoFa.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { expiresIn: '5m' },
    );
    const real = Number(
      new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj }).generate(),
    );
    const wrongCode = String((real + 500_000) % 1_000_000).padStart(6, '0');

    const post2fa = async (): Promise<request.Response> => {
      const { token, cookie } = await getCsrf(agent);
      return agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ tempToken, code: wrongCode });
    };

    // Crossing the threshold on the 2FA step mails the link.
    const crossing = await post2fa();
    expect(crossing.status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    const link = mailedToken(0);

    // A second wrong code after the wait re-locks without re-mailing…
    await expireLockout(twoFa.id);
    const relock = await post2fa();
    expect(relock.status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);

    const stillLocked = await readUser(twoFa.id);
    expect(stillLocked!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

    // …and the original link still ends it.
    const unlocked = await postUnlock(agent, link);
    expect(unlocked.status).toBe(200);
    const after = await readUser(twoFa.id);
    expect(after!.lockoutUntil).toBeUndefined();
    expect(after!.failedLoginAttempts).toBe(0);
  });

  it('writes no session and no login row while the victim is locked out', async () => {
    // The whole episode above must leave the account with nothing but the
    // failure trail: a lockout that mints a session would be a far worse bug
    // than the one being fixed.
    await lockOut(agent, user);
    await expireLockout(user.id);
    await postLogin(agent, user.email, 'wrong-auth-hash');

    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1); // the seeded one
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login_failed' })).toBe(
      MAX_LOGIN_ATTEMPTS + 1,
    );
  });

  it('mints no link when the episode read-back finds nothing', async () => {
    // The one defensive arm in the lock helper. If the account is deleted (or its
    // lockout discharged) between the atomic increment and the write that starts
    // the episode, there is no episode to name — and a link minted anyway would
    // be bound to the empty string, which is a fixed value that matches EVERY
    // account with no episode running. It must bail instead, before the write
    // that claims the mail.
    await User.findByIdAndUpdate(user.id, {
      $set: { failedLoginAttempts: MAX_LOGIN_ATTEMPTS - 1 },
    });

    // The read-back after the atomic lock write finds nothing, which is what a
    // vanished (or discharged) document looks like from there. Everything before
    // it — the increment and the lock write — runs for real.
    const readPreferences: string[] = [];
    const spy = vi
      .spyOn(User, 'findById')
      // The production read chains `.read('primary').select('+lockoutEpisodeId')`,
      // so the stand-in has to be query-shaped rather than a bare promise — and
      // shaped like the WHOLE chain. `read('primary')` is load-bearing there: a
      // deployment whose `MONGODB_URI` names a secondary read preference would
      // otherwise let this read predate the lock write two lines above it and mail
      // no link at all.
      .mockReturnValueOnce({
        read: (preference: string) => {
          readPreferences.push(preference);
          return { select: () => Promise.resolve(null) };
        },
      } as never);

    try {
      const res = await postLogin(agent, user.email, 'wrong-auth-hash');
      expect(res.status).toBe(401);

      expect(mockedUnlockEmail).not.toHaveBeenCalled();
      expect(spy).toHaveBeenCalledTimes(1);
      // The read preference is asserted, not merely accommodated. A deployment
      // whose `MONGODB_URI` carries `readPreference=secondaryPreferred` would
      // otherwise let this read predate the lock write two lines above it in
      // production: it would answer `undefined`, take the bail this case covers
      // for the WRONG reason, and the account would sit locked for thirty minutes
      // with no unlock link ever sent.
      expect(readPreferences).toEqual(['primary']);
    } finally {
      spy.mockRestore();
    }

    // …and it stopped BEFORE claiming the mail, so the next genuine failure can
    // still send one. A consumed claim here would be the silence this whole file
    // exists to end.
    const after = await readUser(user.id);
    expect(after!.lockoutNotifiedAt).toBeUndefined();
    // The lock itself DID land — the bail is after the atomic write, not instead
    // of it — so the account is genuinely locked and genuinely has an episode to
    // be mailed about on the next attempt. Without this the case would also pass
    // on a handler that gave up before locking at all, which is a different and
    // much worse behaviour wearing the same assertions.
    expect(after!.lockoutUntil).toBeInstanceOf(Date);
    expect(after!.lockoutEpisodeId).toEqual(expect.any(String));
  });

  it('claims no mail for an episode that was discharged while the lock was being written', async () => {
    // The interleaving both reviews independently asked about, forced at the one
    // seam where it can happen: the handler settles the lock atomically, reads the
    // episode back, and THEN claims the mail. If the owner discharges the lockout
    // in between — spends the link, completes a sign-in, resets the password — the
    // claim must not land, because it would stamp `lockoutNotifiedAt` on an account
    // with no episode and that stamp suppresses the mail for the NEXT lockout for
    // up to half an hour. That is the silence this file exists to end, in miniature.
    //
    // The discharge is injected through the read-back rather than mocked away: the
    // handler still performs every real write, and what the stand-in adds is a
    // concurrent `updateOne` at a moment a `Promise.all` cannot reliably hit.
    await User.findByIdAndUpdate(user.id, {
      $set: { failedLoginAttempts: MAX_LOGIN_ATTEMPTS - 1 },
    });

    const original = User.findById.bind(User);
    const spy = vi.spyOn(User, 'findById').mockImplementationOnce(((id: string) => ({
      // Mirrors the production chain, `.read('primary').select(...)`.
      read: (preference: string) => ({
        select: async (projection: string) => {
          const snapshot = await original(id).read(preference).select(projection);
          // The owner's discharge commits here, after the handler's lock write
          // and before its claim.
          await User.updateOne(
            { _id: id },
            {
              $set: { failedLoginAttempts: 0 },
              $unset: { lockoutUntil: 1, lockoutEpisodeId: 1, lockoutNotifiedAt: 1 },
            },
          );
          return snapshot;
        },
      }),
    })) as never);

    try {
      const res = await postLogin(agent, user.email, 'wrong-auth-hash');
      expect(res.status).toBe(401);
    } finally {
      spy.mockRestore();
    }

    // No link for an episode nobody can be unlocked with…
    expect(mockedUnlockEmail).not.toHaveBeenCalled();
    // …and, the part that lasts: no claim consumed, so the next genuine lockout
    // still gets its mail.
    const after = await readUser(user.id);
    expect(after.lockoutNotifiedAt).toBeUndefined();
    expect(after.lockoutEpisodeId).toBeUndefined();

    // Proof that the next lockout really does mail: ten more failures.
    await lockOut(agent, user);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
  });

  it('never puts the episode identity or the notification time on the wire', async () => {
    // `GET /user/profile` answers with a `.lean()` spread of the whole user
    // document minus two named fields, so anything not hidden AT THE SCHEMA is
    // returned to the caller. Neither of these is a credential — the unlock link
    // is a signed JWT and knowing the episode forges nothing — but they are
    // internal bookkeeping no client wants, and an opt-out projection is the wrong
    // place to be deciding that. Dropping `select: false` from the model turns
    // this red.
    await lockOut(agent, user);

    const res = await agent
      .get(`${API}/user/profile`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data).not.toHaveProperty('lockoutEpisodeId');
    expect(res.body.data).not.toHaveProperty('lockoutNotifiedAt');
    // …and the assertion is not vacuous: the sibling field that IS disclosed is
    // present, so the response really does carry the account's lockout state.
    expect(res.body.data.lockoutUntil).toBeDefined();
    // The episode itself exists; it is simply not sent.
    expect((await readUser(user.id)).lockoutEpisodeId).toBeTruthy();
  });

  it('bounds a lockout to LOCKOUT_DURATION_MINUTES from the attempt that wrote it', async () => {
    // Pins the deadline arithmetic the re-mail rule is derived from: if a
    // re-lock silently lengthened the window, "the outstanding link outlives the
    // lockout" would stop being true without any test noticing.
    const before = Date.now();
    await lockOut(agent, user);
    const after = Date.now();

    const locked = await readUser(user.id);
    expect(locked!.lockoutUntil!.getTime()).toBeGreaterThanOrEqual(before + LOCKOUT_DURATION_MS);
    expect(locked!.lockoutUntil!.getTime()).toBeLessThanOrEqual(after + LOCKOUT_DURATION_MS);
  });
});
