/**
 * F-28 — the ONE second-factor verifier (`utils/secondFactor.ts`) and the
 * per-factor lockout helpers it counts through (`utils/lockout.ts`), as units.
 *
 * The HTTP behaviour of every site is pinned in `second-factor-lockout.test.ts`;
 * this file pins the rules the verifier applies whatever site calls it: a spent
 * step is refused, a backup code is single-use through the fragment the caller
 * writes, a failure counts everywhere but at enrolment, a lock refuses
 * everywhere but at enrolment, and the verifier itself never writes a success.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

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

import bcrypt from 'bcryptjs';
import mongoose, { type HydratedDocument } from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import { User, type IUser } from '../src/models/User.js';
import {
  findMatchingBackupCodeIndex,
  verifySecondFactor,
  withSecondFactorCas,
  type SecondFactorSubject,
} from '../src/utils/secondFactor.js';
import {
  clearLockoutStateOnDocument,
  dischargeOnCompletion,
  dischargeUnlockedEpisode,
  factorStateOf,
  lockoutClearUpdate,
  registerFailedAuthAttempt,
  unlockEpisodeOf,
  unlockTokenNamesEpisode,
} from '../src/utils/lockout.js';
import { createTestUser, generateStateHash } from './helpers.js';

const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';
const LOCKOUT_MS = 30 * 60 * 1000;

const passwordMail = unlockMails.password;
const secondFactorMail = unlockMails.secondFactor;

function totpFor(secret: Secret): TOTP {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
}

function currentStep(): number {
  return Math.floor(Date.now() / 1000 / 30);
}

function wrongCode(secret: Secret): string {
  const totp = totpFor(secret);
  const now = Date.now();
  const accepted = new Set([-30_000, 0, 30_000].map((d) => totp.generate({ timestamp: now + d })));
  let candidate = (Number(totp.generate({ timestamp: now })) + 500_000) % 1_000_000;
  let code = String(candidate).padStart(6, '0');
  while (accepted.has(code)) {
    candidate = (candidate + 1) % 1_000_000;
    code = String(candidate).padStart(6, '0');
  }
  return code;
}

interface Enrolled {
  subject: SecondFactorSubject;
  secret: Secret;
  ciphertext: string;
}

/** An account with 2FA enabled; `backupCodes` are stored hashed. */
async function enrolled(backupCodes: string[] = []): Promise<Enrolled> {
  const secret = new Secret();
  const ciphertext = cm.encryptTextSync(secret.base32, encKey);
  const user = await createTestUser({ emailVerified: true });
  const hashed = await Promise.all(backupCodes.map((c) => bcrypt.hash(c, 4)));
  await User.findByIdAndUpdate(user.id, {
    $set: { twoFactorEnabled: true, twoFactorSecret: ciphertext, backupCodes: hashed },
  });
  const doc = await User.findById(user.id).select('+twoFactorSecret +backupCodes');
  return { subject: doc!, secret, ciphertext };
}

async function lockoutOf(userId: mongoose.Types.ObjectId) {
  const doc = await User.collection.findOne({ _id: userId });
  return (doc as unknown as { secondFactorLockout?: Record<string, unknown> }).secondFactorLockout;
}

async function seedSecondFactor(
  userId: mongoose.Types.ObjectId,
  state: { failedAttempts: number; until?: Date; episodeId?: string },
): Promise<void> {
  await User.collection.updateOne({ _id: userId }, { $set: { secondFactorLockout: state } });
}

beforeEach(() => {
  passwordMail.mockReset();
  passwordMail.mockResolvedValue({ success: true, message: 'sent' });
  secondFactorMail.mockReset();
  secondFactorMail.mockResolvedValue({ success: true, message: 'sent' });
});

describe('verifySecondFactor — a correct TOTP', () => {
  it('returns the replay compare-and-set bound to the secret, and writes nothing itself', async () => {
    const { subject, secret, ciphertext } = await enrolled();

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'disable2fa',
      acceptBackupCodes: false,
    });

    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.kind).toBe('totp');
    const step = (verdict.casUpdate['$set'] as { lastTotpTimestamp: number }).lastTotpTimestamp;
    expect(Math.abs(step - currentStep())).toBeLessThanOrEqual(1);
    expect(verdict.casFilter).toEqual({
      twoFactorEnabled: true,
      twoFactorSecret: ciphertext,
      $or: [
        { lastTotpTimestamp: { $exists: false } },
        { lastTotpTimestamp: null },
        { lastTotpTimestamp: { $lt: step } },
      ],
    });
    // The success is the caller's to write: nothing was consumed yet.
    const stored = await User.findById(subject._id);
    expect(stored!.lastTotpTimestamp).toBeUndefined();
    expect(await lockoutOf(subject._id)).toBeUndefined();
  });

  it('refuses a step already spent, and counts it as a failure', async () => {
    const { subject, secret } = await enrolled();
    // Set on the loaded document itself: spreading a hydrated document would drop
    // `_id`, which is a getter on its prototype.
    subject.lastTotpTimestamp = currentStep() + 1;

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'login2fa',
      acceptBackupCodes: true,
    });

    expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: 1 });
    expect((await lockoutOf(subject._id))?.['failedAttempts']).toBe(1);
  });

  it('checks the PENDING secret at verify2fa, bound to that pending ciphertext', async () => {
    const user = await createTestUser({ emailVerified: true });
    const secret = new Secret();
    const pending = cm.encryptTextSync(secret.base32, encKey);
    const subject = {
      ...(await User.findById(user.id))!.toObject(),
      pendingTwoFactorSecret: pending,
    } as SecondFactorSubject;

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'verify2fa',
      acceptBackupCodes: false,
    });

    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.casFilter).toMatchObject({
      twoFactorEnabled: false,
      pendingTwoFactorSecret: pending,
    });
    expect(verdict.casFilter).not.toHaveProperty('twoFactorSecret');
  });
});

describe('verifySecondFactor — backup codes', () => {
  it('returns a $pull fragment that makes the code single-use through the write', async () => {
    const { subject } = await enrolled(['backupcode000001', 'backupcode000002']);

    const verdict = await verifySecondFactor(subject, 'backupcode000002', {
      site: 'login2fa',
      acceptBackupCodes: true,
    });
    expect(verdict.ok).toBe(true);
    if (!verdict.ok) return;
    expect(verdict.kind).toBe('backup_code');

    const first = await User.findOneAndUpdate(
      { _id: subject._id, ...verdict.casFilter },
      verdict.casUpdate,
      { returnDocument: 'after' },
    ).select('+backupCodes');
    expect(first!.backupCodes).toHaveLength(1);

    // The same fragment a second time matches nothing: the element is gone.
    const second = await User.findOneAndUpdate(
      { _id: subject._id, ...verdict.casFilter },
      verdict.casUpdate,
    );
    expect(second).toBeNull();
  });

  it('is refused, and counted, at a site that does not accept backup codes', async () => {
    const { subject } = await enrolled(['backupcode000003']);

    const verdict = await verifySecondFactor(subject, 'backupcode000003', {
      site: 'regenerateBackupCodes',
      acceptBackupCodes: false,
    });

    expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: 1 });
    const stored = await User.findById(subject._id).select('+backupCodes');
    expect(stored!.backupCodes).toHaveLength(1);
  });

  it('findMatchingBackupCodeIndex reports the matching position, or -1', async () => {
    const hashes = await Promise.all(['aaaa1111', 'bbbb2222'].map((c) => bcrypt.hash(c, 4)));
    expect(await findMatchingBackupCodeIndex('bbbb2222', hashes)).toBe(1);
    expect(await findMatchingBackupCodeIndex('cccc3333', hashes)).toBe(-1);
    expect(await findMatchingBackupCodeIndex('aaaa1111', [])).toBe(-1);
  });
});

describe('verifySecondFactor — counting and locking', () => {
  it.each(['login2fa', 'disable2fa', 'regenerateBackupCodes', 'deleteAccount'] as const)(
    'counts a wrong code at %s on the second factor only',
    async (site) => {
      const { subject, secret } = await enrolled();

      const verdict = await verifySecondFactor(subject, wrongCode(secret), {
        site,
        acceptBackupCodes: site === 'login2fa',
      });

      expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: 1 });
      expect((await lockoutOf(subject._id))?.['failedAttempts']).toBe(1);
      const stored = await User.findById(subject._id);
      expect(stored!.failedLoginAttempts).toBe(0);
      expect(stored!.lockoutUntil).toBeUndefined();
    },
  );

  it('never counts at verify2fa', async () => {
    const user = await createTestUser({ emailVerified: true });
    const secret = new Secret();
    const subject = {
      ...(await User.findById(user.id))!.toObject(),
      pendingTwoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
    } as SecondFactorSubject;

    const verdict = await verifySecondFactor(subject, wrongCode(secret), {
      site: 'verify2fa',
      acceptBackupCodes: false,
    });

    expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: 0 });
    expect(await lockoutOf(subject._id)).toBeUndefined();
  });

  it('refuses without reading the code while locked, and does not advance the count', async () => {
    const { subject, secret } = await enrolled();
    await seedSecondFactor(subject._id, {
      failedAttempts: MAX_LOGIN_ATTEMPTS,
      until: new Date(Date.now() + LOCKOUT_MS),
      episodeId: 'e1',
    });

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'login2fa',
      acceptBackupCodes: true,
    });

    expect(verdict).toEqual({ ok: false, reason: 'locked' });
    expect((await lockoutOf(subject._id))?.['failedAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
  });

  it('is not refused by a recorded lock at verify2fa', async () => {
    const user = await createTestUser({ emailVerified: true });
    const secret = new Secret();
    const userId = new mongoose.Types.ObjectId(user.id);
    await seedSecondFactor(userId, {
      failedAttempts: MAX_LOGIN_ATTEMPTS,
      until: new Date(Date.now() + LOCKOUT_MS),
    });
    const subject = {
      ...(await User.findById(user.id))!.toObject(),
      pendingTwoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
    } as SecondFactorSubject;

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'verify2fa',
      acceptBackupCodes: false,
    });
    expect(verdict.ok).toBe(true);
  });

  it('locks at the threshold, mints an episode and mails the second-factor link once', async () => {
    const { subject, secret } = await enrolled();

    for (let i = 1; i <= MAX_LOGIN_ATTEMPTS; i++) {
      const verdict = await verifySecondFactor(subject, wrongCode(secret), {
        site: 'disable2fa',
        acceptBackupCodes: false,
      });
      expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: i });
    }

    const state = await lockoutOf(subject._id);
    expect(state?.['failedAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
    expect((state?.['until'] as Date).getTime()).toBeGreaterThan(Date.now());
    expect(state?.['episodeId']).toEqual(expect.any(String));
    expect(state?.['notifiedAt']).toBeInstanceOf(Date);
    expect(secondFactorMail).toHaveBeenCalledTimes(1);
    expect(passwordMail).not.toHaveBeenCalled();

    // The next attempt is a refusal, not an eleventh count.
    const refused = await verifySecondFactor(subject, wrongCode(secret), {
      site: 'disable2fa',
      acceptBackupCodes: false,
    });
    expect(refused).toEqual({ ok: false, reason: 'locked' });
    expect((await lockoutOf(subject._id))?.['failedAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
  });

  it('discharges a served lockout before verifying, so a correct code then passes', async () => {
    const { subject, secret } = await enrolled();
    await seedSecondFactor(subject._id, {
      failedAttempts: MAX_LOGIN_ATTEMPTS,
      until: new Date(Date.now() - 1000),
      episodeId: 'served',
    });

    const verdict = await verifySecondFactor(subject, totpFor(secret).generate(), {
      site: 'login2fa',
      acceptBackupCodes: true,
    });

    expect(verdict.ok).toBe(true);
    expect(await lockoutOf(subject._id)).toBeUndefined();
  });

  it('verifies nothing and counts nothing at enrolment for a subject with no pending secret', async () => {
    const user = await createTestUser({ emailVerified: true });
    const subject = (await User.findById(user.id))!;

    const verdict = await verifySecondFactor(subject, '123456', {
      site: 'verify2fa',
      acceptBackupCodes: false,
    });

    expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: 0 });
    expect(await lockoutOf(subject._id)).toBeUndefined();
  });

  it('treats an account deleted mid-request as unlocked, and its failure lands nowhere', async () => {
    const { subject, secret } = await enrolled();
    await User.deleteOne({ _id: subject._id });

    const verdict = await verifySecondFactor(subject, wrongCode(secret), {
      site: 'disable2fa',
      acceptBackupCodes: false,
    });

    expect(verdict).toEqual({ ok: false, reason: 'invalid', attempts: MAX_LOGIN_ATTEMPTS });
    expect(await User.exists({ _id: subject._id })).toBeNull();
    expect(secondFactorMail).not.toHaveBeenCalled();
  });
});

describe('withSecondFactorCas', () => {
  const totpVerdict = {
    ok: true as const,
    kind: 'totp' as const,
    casFilter: { twoFactorEnabled: true, $or: [{ lastTotpTimestamp: null }] },
    casUpdate: { $set: { lastTotpTimestamp: 42 } },
  };

  it('merges the fragment into the caller write, operator by operator', () => {
    const merged = withSecondFactorCas({ _id: 'u' }, { $set: { backupCodes: ['x'] } }, totpVerdict);
    expect(merged).toEqual({
      filter: { _id: 'u', twoFactorEnabled: true, $or: [{ lastTotpTimestamp: null }] },
      update: { $set: { backupCodes: ['x'], lastTotpTimestamp: 42 } },
    });
  });

  it("lets the caller's $unset win over the fragment's $set of the same path", () => {
    const merged = withSecondFactorCas(
      { _id: 'u' },
      { $set: { twoFactorEnabled: false }, $unset: { lastTotpTimestamp: 1 } },
      totpVerdict,
    );
    expect(merged.update).toEqual({
      $set: { twoFactorEnabled: false },
      $unset: { lastTotpTimestamp: 1 },
    });
    // The filter still carries the step condition: consumption is enforced there.
    expect(merged.filter['$or']).toEqual([{ lastTotpTimestamp: null }]);
  });

  it('keeps BOTH sides of a filter when both carry an $or', () => {
    const merged = withSecondFactorCas(
      { _id: 'u', $or: [{ a: 1 }, { b: 2 }] },
      { $set: { x: 1 } },
      totpVerdict,
    );
    expect(merged.filter).toEqual({
      _id: 'u',
      twoFactorEnabled: true,
      $and: [{ $or: [{ a: 1 }, { b: 2 }] }, { $or: [{ lastTotpTimestamp: null }] }],
    });
  });

  it("keeps a caller's own $and when it combines two $or clauses", () => {
    const merged = withSecondFactorCas(
      { _id: 'u', $and: [{ c: 3 }], $or: [{ a: 1 }] },
      {},
      totpVerdict,
    );
    expect(merged.filter['$and']).toEqual([
      { c: 3 },
      { $or: [{ a: 1 }] },
      { $or: [{ lastTotpTimestamp: null }] },
    ]);
  });

  it('adds an operator the caller did not use', () => {
    const merged = withSecondFactorCas(
      { _id: 'u' },
      {},
      {
        ok: true,
        kind: 'backup_code',
        casFilter: { backupCodes: 'h' },
        casUpdate: { $pull: { backupCodes: 'h' } },
      },
    );
    expect(merged.update).toEqual({ $pull: { backupCodes: 'h' } });
  });
});

describe('lockout helpers — per factor', () => {
  it('lockoutClearUpdate clears exactly one factor', () => {
    expect(lockoutClearUpdate('password')).toEqual({
      $set: { failedLoginAttempts: 0 },
      $unset: { lockoutUntil: 1, lockoutEpisodeId: 1, lockoutNotifiedAt: 1 },
    });
    expect(lockoutClearUpdate('second_factor')).toEqual({ $unset: { secondFactorLockout: 1 } });
    // A fresh object per call, so an annotation on one cannot leak into the next.
    expect(lockoutClearUpdate('password')).not.toBe(lockoutClearUpdate('password'));
  });

  it('clearLockoutStateOnDocument clears exactly one factor on a loaded document', async () => {
    const user = await createTestUser();
    const doc = (await User.findById(user.id))!;
    doc.failedLoginAttempts = 4;
    doc.lockoutUntil = new Date();
    doc.lockoutEpisodeId = 'p';
    doc.lockoutNotifiedAt = new Date();
    doc.secondFactorLockout = { failedAttempts: 2, episodeId: 's' };

    clearLockoutStateOnDocument(doc, 'second_factor');
    expect(doc.secondFactorLockout).toBeUndefined();
    expect(doc.failedLoginAttempts).toBe(4);

    clearLockoutStateOnDocument(doc, 'password');
    expect(doc.failedLoginAttempts).toBe(0);
    expect(doc.lockoutUntil).toBeUndefined();
    expect(doc.lockoutEpisodeId).toBeUndefined();
    expect(doc.lockoutNotifiedAt).toBeUndefined();
  });

  it('factorStateOf and unlockEpisodeOf read each factor from its own storage', () => {
    const until = new Date();
    const user = {
      failedLoginAttempts: 3,
      lockoutUntil: until,
      lockoutEpisodeId: 'pw',
      secondFactorLockout: { failedAttempts: 7, until, episodeId: 'sf' },
    };
    expect(factorStateOf(user, 'password')).toEqual({
      failedAttempts: 3,
      until,
      episodeId: 'pw',
    });
    expect(factorStateOf(user, 'second_factor')).toEqual({
      failedAttempts: 7,
      until,
      episodeId: 'sf',
    });
    expect(factorStateOf({ failedLoginAttempts: 0 }, 'second_factor')).toEqual({
      failedAttempts: 0,
      until: undefined,
      episodeId: undefined,
    });
    expect(unlockEpisodeOf(user, 'password')).toBe('pw');
    expect(unlockEpisodeOf(user, 'second_factor')).toBe('sf');
    expect(unlockEpisodeOf({}, 'second_factor')).toBeUndefined();
  });

  it('unlockTokenNamesEpisode refuses a missing or empty episode', () => {
    expect(unlockTokenNamesEpisode(generateStateHash('e'), 'e')).toBe(true);
    expect(unlockTokenNamesEpisode(generateStateHash('e'), 'f')).toBe(false);
    expect(unlockTokenNamesEpisode(generateStateHash(''), '')).toBe(false);
    expect(unlockTokenNamesEpisode(generateStateHash(''), undefined)).toBe(false);
  });

  it('registerFailedAuthAttempt never grows a counter past the threshold', async () => {
    const user = await createTestUser();
    const userId = new mongoose.Types.ObjectId(user.id);
    await User.updateOne({ _id: userId }, { $set: { failedLoginAttempts: MAX_LOGIN_ATTEMPTS } });

    expect(await registerFailedAuthAttempt(userId, user.email, 'password')).toBe(
      MAX_LOGIN_ATTEMPTS,
    );
    const stored = await User.findById(userId).select('+lockoutEpisodeId');
    expect(stored!.failedLoginAttempts).toBe(MAX_LOGIN_ATTEMPTS);
    // Still at the threshold, so the failure re-locks (an unserved lockout).
    expect(stored!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
    expect(stored!.lockoutEpisodeId).toEqual(expect.any(String));
    expect(passwordMail).toHaveBeenCalledTimes(1);
    expect(secondFactorMail).not.toHaveBeenCalled();
  });

  it('dischargeOnCompletion clears only factors whose lockout is not running', async () => {
    const idle = { passwordLocked: false, secondFactorLocked: false };
    const seed = async (
      fields: Record<string, unknown>,
    ): Promise<{ id: mongoose.Types.ObjectId; doc: HydratedDocument<IUser> }> => {
      const user = await createTestUser();
      const id = new mongoose.Types.ObjectId(user.id);
      await User.collection.updateOne({ _id: id }, { $set: fields });
      const doc = (await User.findById(id).select('+secondFactorLockout'))!;
      return { id, doc };
    };
    const stored = async (id: mongoose.Types.ObjectId) =>
      (await User.collection.findOne({ _id: id })) as unknown as Record<string, unknown>;

    // Both factors have failures and neither is locked: both are cleared.
    const both = await seed({ failedLoginAttempts: 2, secondFactorLockout: { failedAttempts: 1 } });
    await dischargeOnCompletion(both.doc, idle);
    expect(await stored(both.id)).toMatchObject({ failedLoginAttempts: 0 });
    expect((await stored(both.id))['secondFactorLockout']).toBeUndefined();

    // A factor locked when the request read the account is left alone.
    const running = new Date(Date.now() + 30 * 60 * 1000);
    const pw = await seed({
      failedLoginAttempts: 10,
      lockoutUntil: running,
      secondFactorLockout: { failedAttempts: 3 },
    });
    await dischargeOnCompletion(pw.doc, { passwordLocked: true, secondFactorLocked: false });
    expect((await stored(pw.id))['failedLoginAttempts']).toBe(10);
    expect((await stored(pw.id))['secondFactorLockout']).toBeUndefined();

    // A lockout that STARTED after the request read the account survives the
    // write too: the clear is conditioned on the deadline not running when it lands.
    const late = await seed({ failedLoginAttempts: 4 });
    await User.collection.updateOne(
      { _id: late.id },
      { $set: { failedLoginAttempts: 10, lockoutUntil: running } },
    );
    await dischargeOnCompletion(late.doc, idle);
    expect((await stored(late.id))['failedLoginAttempts']).toBe(10);
    const lateSf = await seed({ secondFactorLockout: { failedAttempts: 4 } });
    await User.collection.updateOne(
      { _id: lateSf.id },
      { $set: { secondFactorLockout: { failedAttempts: 10, until: running } } },
    );
    await dischargeOnCompletion(lateSf.doc, idle);
    expect((await stored(lateSf.id))['secondFactorLockout']).toMatchObject({ failedAttempts: 10 });

    // A deadline alone, with the counter already at zero, is still state to clear;
    // and an account with nothing to clear is not written at all.
    const deadline = await seed({ failedLoginAttempts: 0, lockoutUntil: new Date(0) });
    await dischargeOnCompletion(deadline.doc, idle);
    expect((await stored(deadline.id))['lockoutUntil']).toBeUndefined();
    const clean = await seed({ failedLoginAttempts: 0 });
    const spy = vi.spyOn(User, 'updateOne');
    await dischargeOnCompletion(clean.doc, idle);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('dischargeUnlockedEpisode clears one factor only while the verified episode is stored', async () => {
    const user = await createTestUser();
    const id = new mongoose.Types.ObjectId(user.id);
    await User.collection.updateOne(
      { _id: id },
      {
        $set: {
          failedLoginAttempts: 10,
          lockoutEpisodeId: 'ep-1',
          secondFactorLockout: { failedAttempts: 10, episodeId: 'sf-1' },
        },
      },
    );

    expect(await dischargeUnlockedEpisode(id, 'password', 'ep-other')).toBe(false);
    expect(await dischargeUnlockedEpisode(id, 'password', 'ep-1')).toBe(true);
    const after = (await User.collection.findOne({ _id: id })) as unknown as Record<
      string,
      unknown
    >;
    expect(after['failedLoginAttempts']).toBe(0);
    expect(after['lockoutEpisodeId']).toBeUndefined();
    expect(after['secondFactorLockout']).toMatchObject({ episodeId: 'sf-1' });
    // Spent: a second use finds nothing to discharge.
    expect(await dischargeUnlockedEpisode(id, 'password', 'ep-1')).toBe(false);
    expect(await dischargeUnlockedEpisode(id, 'second_factor', 'sf-1')).toBe(true);
  });
});
