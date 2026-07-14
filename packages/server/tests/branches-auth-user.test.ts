/**
 * Error / edge branches of `authController` and `userController` that the rest
 * of the suite never reaches.
 *
 * Each block drives a real failure path end-to-end through the HTTP layer and
 * asserts the contract that path exists to uphold — the status, the error code,
 * the resulting database state, and (where the handler writes one) the audit row:
 *
 *   • login2fa integrity guards — a `twoFactorEnabled` record whose secret is
 *     gone, and a wrong code against an account with no backup codes left.
 *   • login2fa backup-code single-use under a genuine concurrent race (the
 *     `$pull` loser must NOT be issued tokens).
 *   • the unlock email is sent exactly ONCE per lockout-threshold crossing —
 *     a further failure on an already-over-threshold account re-locks silently.
 *   • refresh: the new-token write failing AFTER the old token was claimed must
 *     clear the cookie, 500, and leave reuse detection guarding the old token.
 *   • verify2fa: a pending 2FA setup is only usable with BOTH halves present.
 *   • deleteAccount: a failed cascade must leave the account marked
 *     `deletionPending` (retryable) rather than reporting success.
 *   • registration is body-identical whether the SMTP send succeeds or fails
 *     (the anti-enumeration invariant the fire-and-forget send exists to keep).
 *   • logout-all / disable-2fa session revocation with and without a refresh
 *     cookie — the caller's own session is spared only when it is identified.
 *   • the TRANSACTIONAL refresh + change-password branches, which only run on a
 *     replica set (the production topology, `rs0`) and which the standalone
 *     harness never reaches.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';

// The email senders under assertion are stubbed so "was this mail sent, and did
// the send succeed?" is directly observable; the real senders are inert no-ops
// in the test environment (no SMTP configured), which makes the success arm of
// every `if (!result.success)` handler unreachable.
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
    sendVerificationEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
    sendRegistrationAttemptEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

// Delegates to the real cascade by default; a single test forces the failure
// return value to exercise the "deletion partially failed" branch.
vi.mock('../src/utils/cascadeDelete.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/cascadeDelete.js')>();
  return { ...actual, cascadeDeleteUser: vi.fn(actual.cascadeDeleteUser) };
});

import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { BACKUP_CODES_COUNT } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  sendAccountUnlockEmail,
  sendRegistrationAttemptEmail,
  sendVerificationEmail,
} from '../src/utils/email.js';
import { cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { hashToken } from '../src/utils/token.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  deriveTestPurposeKey,
  seedItem,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const BCRYPT_ROUNDS = 4;
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

const mockedUnlockEmail = vi.mocked(sendAccountUnlockEmail);
const mockedVerificationEmail = vi.mocked(sendVerificationEmail);
const mockedRegistrationEmail = vi.mocked(sendRegistrationAttemptEmail);
const mockedCascade = vi.mocked(cascadeDeleteUser);

/** A well-formed registration body for a fresh (or given) email. */
function registrationBody(email: string): Record<string, unknown> {
  return {
    email,
    authHash: 'client-derived-auth-hash',
    encryptedVaultKey: 'encrypted-vault-key',
    vaultKeyIv: 'vault-key-iv',
    vaultKeyTag: 'vault-key-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
  };
}

/** Seeds an extra refresh-token row (a second/third device) for a user. */
async function seedSession(userId: string): Promise<string> {
  const raw = crypto.randomBytes(64).toString('hex');
  await RefreshToken.create({
    userId,
    tokenHash: hashToken(raw),
    familyId: crypto.randomUUID(),
    deviceInfo: { userAgent: 'other-device', ip: '10.0.0.1', fingerprint: 'other' },
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  return raw;
}

/** Creates a 2FA-enabled user with a known secret and (optionally) backup codes. */
async function create2faUser(rawBackupCodes: string[] = []): Promise<{
  user: TestUser;
  secretObj: Secret;
}> {
  const secretObj = new Secret();
  const user = await createTestUser({ emailVerified: true });
  const hashed = await Promise.all(rawBackupCodes.map((c) => bcrypt.hash(c, BCRYPT_ROUNDS)));

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secretObj.base32, encKey),
      backupCodes: hashed,
      lastTotpTimestamp: 1, // an old step, so fresh codes are accepted
    },
  });

  return { user, secretObj };
}

/** A device-unbound 2FA temp token (as issued when the login carried no device). */
function makeTempToken(userId: string): string {
  return jwt.sign({ userId, purpose: '2fa_temp' }, deriveTestPurposeKey('2fa_temp'), {
    expiresIn: '5m',
  });
}

function totpFor(secretObj: Secret): TOTP {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
}

/** A 6-digit code guaranteed NOT to be the live TOTP (or either drift window). */
function definitelyWrongCode(secretObj: Secret): string {
  const real = Number(totpFor(secretObj).generate());
  return String((real + 500_000) % 1_000_000).padStart(6, '0');
}

async function post2fa(
  agent: request.Agent,
  tempToken: string,
  code: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login/2fa`)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ tempToken, code });
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

describe('authController — login2fa record-integrity guards', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request.agent(app);
    mockedUnlockEmail.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('refuses to complete 2FA for an account flagged twoFactorEnabled whose secret is gone', async () => {
    const { user } = await create2faUser(['abcdef0123456789']);
    // A corrupted / half-migrated record: the flag survives, the secret does not.
    await User.findByIdAndUpdate(user.id, { $unset: { twoFactorSecret: 1 } });

    const res = await post2fa(agent, makeTempToken(user.id), '123456');

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TWO_FA_NOT_ENABLED');
    // No session may be minted off a record whose second factor cannot be checked.
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1); // the seeded one only
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
  });

  it('rejects a wrong TOTP for an account that has no backup codes left', async () => {
    // Every backup code already consumed — the backup-code fallback must be
    // skipped entirely rather than throwing on an empty array.
    const { user, secretObj } = await create2faUser([]);

    const res = await post2fa(agent, makeTempToken(user.id), definitelyWrongCode(secretObj));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);

    // The wrong code still counts toward the shared lockout counter.
    const after = await User.findById(user.id);
    expect(after).not.toBeNull();
    expect(after!.failedLoginAttempts).toBe(1);
    expect(
      await AuditLog.countDocuments({ userId: user.id, action: 'login_failed' }),
    ).toBeGreaterThan(0);
  });
});

describe('authController — a backup code is consumed exactly once under a concurrent race', () => {
  it('issues tokens to exactly one of two simultaneous logins using the same backup code', async () => {
    const rawCode = 'abcdef0123456789';
    const { user } = await create2faUser([rawCode]);

    const [a, b] = await Promise.all([
      post2fa(request.agent(app), makeTempToken(user.id), rawCode),
      post2fa(request.agent(app), makeTempToken(user.id), rawCode),
    ]);

    const statuses = [a.status, b.status].sort((x, y) => x - y);
    expect(statuses).toEqual([200, 401]);

    const loser = a.status === 401 ? a : b;
    expect(loser.body.message).toBe('TWO_FA_INVALID');

    // The code is gone, and exactly ONE new session exists (the seeded token + one).
    const after = await User.findById(user.id).select('+backupCodes');
    expect(after).not.toBeNull();
    expect(after!.backupCodes).toHaveLength(0);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(2);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(1);
  });
});

describe('authController — the unlock email fires once per lockout-threshold crossing', () => {
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

  it('sends the unlock email on the attempt that crosses the threshold (control)', async () => {
    await User.findByIdAndUpdate(user.id, { $set: { failedLoginAttempts: 9 } });

    const res = await postLogin(agent, user.email, 'wrong-auth-hash');

    expect(res.status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    expect(mockedUnlockEmail.mock.calls[0]![0]).toBe(user.email);

    const after = await User.findById(user.id);
    expect(after!.failedLoginAttempts).toBe(10);
    expect(after!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
  });

  it('re-locks without a second email when the counter is already past the threshold', async () => {
    // An expired lockout whose counter was never reset (the user never logged in
    // again). A further failure must re-lock — but must NOT re-mail: a duplicate
    // unlock link is both a mail-flood vector and a second live unlock token.
    await User.findByIdAndUpdate(user.id, {
      $set: { failedLoginAttempts: 10, lockoutUntil: new Date(Date.now() - 60_000) },
    });

    const res = await postLogin(agent, user.email, 'wrong-auth-hash');

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid email or password');
    expect(mockedUnlockEmail).not.toHaveBeenCalled();

    const after = await User.findById(user.id);
    expect(after!.failedLoginAttempts).toBe(11);
    expect(after!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
  });

  it('sends the unlock email when a wrong 2FA code is the attempt that crosses the threshold', async () => {
    const { user: twoFaUser, secretObj } = await create2faUser(['abcdef0123456789']);
    await User.findByIdAndUpdate(twoFaUser.id, { $set: { failedLoginAttempts: 9 } });

    const res = await post2fa(agent, makeTempToken(twoFaUser.id), definitelyWrongCode(secretObj));

    expect(res.status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    expect(mockedUnlockEmail.mock.calls[0]![0]).toBe(twoFaUser.email);

    const after = await User.findById(twoFaUser.id);
    expect(after!.failedLoginAttempts).toBe(10);
    expect(after!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
  });

  it('re-locks the 2FA step without a second email when already past the threshold', async () => {
    const { user: twoFaUser, secretObj } = await create2faUser(['abcdef0123456789']);
    await User.findByIdAndUpdate(twoFaUser.id, { $set: { failedLoginAttempts: 10 } });

    const res = await post2fa(agent, makeTempToken(twoFaUser.id), definitelyWrongCode(secretObj));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');
    expect(mockedUnlockEmail).not.toHaveBeenCalled();

    const after = await User.findById(twoFaUser.id);
    expect(after!.failedLoginAttempts).toBe(11);
    expect(after!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());
  });
});

describe('authController — refresh fails safely when the new token cannot be written', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser({ emailVerified: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('clears the cookie, 500s, and leaves reuse detection guarding the claimed token', async () => {
    const createSpy = vi
      .spyOn(RefreshToken, 'create')
      .mockRejectedValueOnce(new Error('transient mongo failure') as never);

    // The CSRF token is bound to the active refresh session, so it must be
    // minted with the refresh cookie already attached.
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`);

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);

    // The cookie must be cleared — the old token is spent and no new one exists,
    // so the client has to re-authenticate rather than retry with dead state.
    const setCookie = res.headers['set-cookie'] as unknown as string[];
    expect(setCookie.some((c) => /^refreshToken=;/.test(c))).toBe(true);

    // Exactly the original row survives, claimed. No replacement was issued.
    const rows = await RefreshToken.find({ userId: user.id });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).toBe(hashToken(user.refreshToken));
    expect(rows[0]!.usedAt).toBeInstanceOf(Date);

    // And the spent token is still guarded: presenting it again is reuse, which
    // revokes the family rather than silently minting a session.
    createSpy.mockRestore();
    const csrf2 = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const replay = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf2.token)
      .set('Cookie', `${csrf2.cookie}; refreshToken=${user.refreshToken}`);

    expect(replay.status).toBe(401);
    expect(replay.body.message).toBe('TOKEN_REUSE_DETECTED');
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
  });
});

describe('userController — verify2fa requires a complete pending setup', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser({ emailVerified: true });
  });

  it('rejects a pending secret that carries no expiry and does not enable 2FA', async () => {
    const secretObj = new Secret();
    // A half-written setup row: secret present, TTL missing. Accepting it would
    // resurrect a pending secret that can never expire.
    await User.findByIdAndUpdate(user.id, {
      $set: { pendingTwoFactorSecret: cm.encryptTextSync(secretObj.base32, encKey) },
      $unset: { pendingTwoFactorExpiry: 1 },
    });

    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/verify`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ code: totpFor(secretObj).generate() });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/no pending 2fa setup/i);

    const after = await User.findById(user.id).select('+twoFactorSecret +backupCodes');
    expect(after).not.toBeNull();
    expect(after!.twoFactorEnabled).toBe(false);
    expect(after!.twoFactorSecret).toBeUndefined();
    expect(await AuditLog.countDocuments({ userId: user.id, action: '2fa_enable' })).toBe(0);
  });
});

describe('userController — deleteAccount reports a failed cascade instead of a false success', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser({ emailVerified: true });
    mockedCascade.mockClear();
  });

  it('500s and leaves the account marked deletionPending so cleanup can retry', async () => {
    await seedItem(user.id);
    mockedCascade.mockResolvedValueOnce(false);

    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .delete(`${API}/user`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword });

    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/cleanup will complete shortly/i);

    // The GDPR erasure is NOT reported done: the durable retry marker stays set
    // and the still-unerased data is left for the zombie-cleanup job to finish.
    const after = await User.findById(user.id);
    expect(after).not.toBeNull();
    expect(after!.deletionPending).toBe(true);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('authController — registration is body-identical whether the email send works or not', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request.agent(app);
    mockedVerificationEmail.mockReset();
  });

  async function register(body: Record<string, unknown>): Promise<request.Response> {
    const { token, cookie } = await getCsrf(agent);
    return agent
      .post(`${API}/auth/register`)
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send(body);
  }

  it('returns the same 201 body for a delivered and an undelivered verification email', async () => {
    // The response must not become an oracle for SMTP state: with mail broken,
    // `emailSent` must still read true (otherwise a broken relay would let an
    // attacker distinguish a new account from an existing one, whose
    // notification path returns the constant true).
    mockedVerificationEmail.mockResolvedValueOnce({ success: true, message: 'sent' });
    const delivered = await register(registrationBody(`ok-${crypto.randomUUID()}@example.com`));

    mockedVerificationEmail.mockResolvedValueOnce({
      success: false,
      message: 'smtp_send_failed: relay down',
    });
    const failed = await register(registrationBody(`bad-${crypto.randomUUID()}@example.com`));

    expect(delivered.status).toBe(201);
    expect(failed.status).toBe(201);
    expect(failed.body).toEqual(delivered.body);
    expect(failed.body.data).toEqual({ emailSent: true });

    // Both accounts really were created (the failed send must not roll one back).
    expect(mockedVerificationEmail).toHaveBeenCalledTimes(2);
    expect(await User.countDocuments({})).toBe(2);
  });

  it('answers a duplicate registration identically and creates no second account', async () => {
    const email = `dupe-${crypto.randomUUID()}@example.com`;
    mockedVerificationEmail.mockResolvedValue({ success: true, message: 'sent' });
    mockedRegistrationEmail.mockReset();
    mockedRegistrationEmail.mockResolvedValue({ success: true, message: 'sent' });

    const first = await register(registrationBody(email));
    const second = await register(registrationBody(email));

    // Byte-identical status and body: the endpoint must not reveal that the
    // address is already taken.
    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);

    // The second attempt notified the real owner instead of creating an account.
    expect(mockedRegistrationEmail).toHaveBeenCalledTimes(1);
    expect(mockedRegistrationEmail.mock.calls[0]![0]).toBe(email);
    expect(await User.countDocuments({ email })).toBe(1);
  });
});

describe('authController — logout-all with no refresh cookie revokes every session', () => {
  it('spares nothing when the caller cannot be identified, and audits the count', async () => {
    const user = await createTestUser({ emailVerified: true });
    await seedSession(user.id);
    await seedSession(user.id);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(3);

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/logout-all`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({});

    expect(res.status).toBe(200);

    // Without a refresh cookie there is no "current" session to exclude, so the
    // whole family goes — a global sign-out, not a partial one.
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);

    const audit = await AuditLog.findOne({ userId: user.id, action: 'session_revoke' });
    expect(audit).not.toBeNull();
    expect(audit!.metadata).toMatchObject({ sessionsRevoked: 3 });
  });
});

describe('userController — disable2fa keeps the calling session and revokes the rest', () => {
  it('deletes every other refresh token while the caller stays signed in', async () => {
    const { user, secretObj } = await create2faUser(['abcdef0123456789']);
    await seedSession(user.id);
    await seedSession(user.id);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(3);

    const agent = request.agent(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .delete(`${API}/user/2fa`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`)
      .send({ password: user.rawPassword, code: totpFor(secretObj).generate() });

    expect(res.status).toBe(200);

    // The security downgrade revokes the sessions minted under 2FA — except the
    // caller's own, which is identified by the refresh cookie it presented.
    const survivors = await RefreshToken.find({ userId: user.id });
    expect(survivors).toHaveLength(1);
    expect(survivors[0]!.tokenHash).toBe(hashToken(user.refreshToken));

    const after = await User.findById(user.id).select('+twoFactorSecret +backupCodes');
    expect(after!.twoFactorEnabled).toBe(false);
    expect(after!.twoFactorSecret).toBeUndefined();
  });
});

describe('userController — regenerateBackupCodes guards', () => {
  it('rejects a wrong TOTP and leaves the existing backup codes untouched', async () => {
    const { user, secretObj } = await create2faUser(['abcdef0123456789']);
    const before = await User.findById(user.id).select('+backupCodes');
    const originalCodes = [...before!.backupCodes];

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/regenerate-backup-codes`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword, code: definitelyWrongCode(secretObj) });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    // A rejected regeneration must not have invalidated the user's real codes.
    const after = await User.findById(user.id).select('+backupCodes');
    expect(after!.backupCodes).toEqual(originalCodes);
    expect(await bcrypt.compare('abcdef0123456789', after!.backupCodes[0]!)).toBe(true);
    expect(
      await AuditLog.countDocuments({ userId: user.id, action: '2fa_backup_codes_regenerated' }),
    ).toBe(0);
  });

  it('regenerates without a TOTP for a 2FA record that has no stored secret', async () => {
    // The defensive branch: `twoFactorEnabled` with no `twoFactorSecret` (a
    // half-written record). There is no code to verify — and no replay to
    // guard — but the account must still be able to publish fresh codes.
    const user = await createTestUser({ emailVerified: true });
    await User.findByIdAndUpdate(user.id, {
      $set: { twoFactorEnabled: true, backupCodes: [await bcrypt.hash('old-code-000000', 4)] },
      $unset: { twoFactorSecret: 1 },
    });

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/regenerate-backup-codes`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword });

    expect(res.status).toBe(200);
    const issued = res.body.data.backupCodes as string[];
    expect(issued).toHaveLength(BACKUP_CODES_COUNT);

    // The codes handed to the user are exactly the ones persisted (hashed), and
    // the old code is gone.
    const after = await User.findById(user.id).select('+backupCodes');
    expect(after!.backupCodes).toHaveLength(BACKUP_CODES_COUNT);
    expect(await bcrypt.compare(issued[0]!, after!.backupCodes[0]!)).toBe(true);
    expect(await bcrypt.compare('old-code-000000', after!.backupCodes[0]!)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Replica-set (transactional) branches.
//
// Production runs MongoDB as a single-node replica set (`rs0`), so
// `supportsTransactions(...)` is TRUE there and `refresh` / `changePassword`
// both take their transactional branch. The default harness connects to a
// STANDALONE server, where that branch is unreachable — every other test in the
// suite therefore exercises only the sequential fallback. Stand up a real
// replica set so the production path actually runs.
//
// This block is LAST in the file: its beforeAll swaps the global mongoose
// connection.
// ─────────────────────────────────────────────────────────────────────────────

describe('transactional (replica-set) auth branches', () => {
  let replSet: MongoMemoryReplSet;

  beforeAll(async () => {
    await mongoose.disconnect();
    replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replSet.getUri());

    // Guard: without a genuine replica set the handlers would silently take the
    // sequential path and these tests would assert the wrong branch.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  }, 120_000);

  afterAll(async () => {
    await mongoose.disconnect();
    await replSet.stop();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rotates the refresh token inside a transaction: old claimed, new issued in the same family', async () => {
    const user = await createTestUser({ emailVerified: true });
    const original = await RefreshToken.findOne({ tokenHash: hashToken(user.refreshToken) });
    expect(original).not.toBeNull();

    const sessionSpy = vi.spyOn(mongoose, 'startSession');

    const agent = request.agent(app);
    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeTruthy();
    // The sequential fallback never opens a session — this proves the branch.
    expect(sessionSpy).toHaveBeenCalled();

    // Claim and create BOTH committed: the old row is spent, the replacement
    // exists, and it inherits the family so reuse detection still spans them.
    const claimed = await RefreshToken.findById(original!._id);
    expect(claimed!.usedAt).toBeInstanceOf(Date);

    const rows = await RefreshToken.find({ userId: user.id });
    expect(rows).toHaveLength(2);
    const fresh = rows.find((r) => r.tokenHash !== hashToken(user.refreshToken));
    expect(fresh).toBeDefined();
    expect(fresh!.familyId).toBe(original!.familyId);
    expect(fresh!.usedAt == null).toBe(true);
  });

  it('rejects an unknown refresh token in the transactional path without minting anything', async () => {
    const user = await createTestUser({ emailVerified: true });
    const bogus = crypto.randomBytes(64).toString('hex');

    const agent = request.agent(app);
    const csrf = await getCsrf(agent, `refreshToken=${bogus}`);
    const res = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${bogus}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');

    const setCookie = res.headers['set-cookie'] as unknown as string[];
    expect(setCookie.some((c) => /^refreshToken=;/.test(c))).toBe(true);

    // The transaction found no row to claim, so it must have created no token
    // either — only the user's original session remains.
    const rows = await RefreshToken.find({ userId: user.id });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).toBe(hashToken(user.refreshToken));
  });

  it('commits the password change and the session revocation together', async () => {
    const user = await createTestUser({ emailVerified: true });
    await seedSession(user.id);
    const before = await User.findById(user.id).select('+authHash');

    const sessionSpy = vi.spyOn(mongoose, 'startSession');

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .put(`${API}/user/change-password`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'brand-new-auth-hash',
        newEncryptedVaultKey: 'txn-new-vault-key',
        newVaultKeyIv: 'txn-new-iv',
        newVaultKeyTag: 'txn-new-tag',
      });

    expect(res.status).toBe(200);
    expect(sessionSpy).toHaveBeenCalled();

    const after = await User.findById(user.id).select('+authHash');
    expect(after!.authHash).not.toBe(before!.authHash);
    expect(await bcrypt.compare('brand-new-auth-hash', after!.authHash)).toBe(true);
    expect(after!.encryptedVaultKey).toBe('txn-new-vault-key');
    expect(after!.passwordChangedAt.getTime()).toBeGreaterThan(Date.now() - 60_000);

    // The other half of the transaction: every refresh token is gone, so no
    // session survives a password change.
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
  });
});
