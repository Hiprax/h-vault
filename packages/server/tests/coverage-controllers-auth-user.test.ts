import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { TOTP, Secret } from 'otpauth';

import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { acquireJobLock } from '../src/utils/jobLock.js';
import { cryptoManager } from '../src/utils/cryptoManager.js';
import { twoFactorEncryptionKey } from '../src/config/index.js';
import { getProgressiveDelay } from '../src/controllers/authController.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  deriveTestPurposeKey,
  generateStateHash,
  type CsrfPair,
  type TestUser,
} from './helpers.js';

// nodemailer is mocked so the email-utility section can drive a real transporter
// (the app itself has no SMTP configured under test, so its own sends still
// short-circuit before `createTransport` is ever reached).
const mailerMocks = vi.hoisted(() => ({
  createTransport: vi.fn(),
  sendMail: vi.fn(),
  verify: vi.fn(),
}));

vi.mock('nodemailer', () => ({
  default: { createTransport: mailerMocks.createTransport },
}));

const API = '/api/v1';

function withCsrf(req: request.Test, csrf: CsrfPair): request.Test {
  return req.set('x-csrf-token', csrf.token).set('Cookie', csrf.cookie);
}

function registrationBody(email = `new-${crypto.randomUUID()}@example.com`) {
  return {
    email,
    authHash: 'client-derived-auth-hash',
    encryptedVaultKey: 'encrypted-vault-key',
    vaultKeyIv: 'vault-key-iv',
    vaultKeyTag: 'vault-key-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256' as const,
    encryptionVersion: 1,
  };
}

/** Enables 2FA on a user with a known TOTP secret, returning that secret. */
async function enableTwoFactor(userId: string): Promise<string> {
  const secretObj = new Secret();
  const secret = secretObj.base32;
  await User.findByIdAndUpdate(userId, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey),
      backupCodes: [await bcrypt.hash('deadbeefdeadbeef', 4)],
    },
  });
  return secret;
}

function totpFor(secret: string): TOTP {
  return new TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  });
}

/** The TOTP time step the server will derive for a code generated right now. */
function currentTimeStep(): number {
  return Math.floor(Date.now() / 1000 / 30);
}

describe('authController — register does not disturb an existing account', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  it('returns the same 201 body but leaves the existing account byte-for-byte intact', async () => {
    const body = registrationBody();

    const first = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);
    expect(first.status).toBe(201);

    const before = await User.findOne({ email: body.email }).select('+authHash');
    expect(before).not.toBeNull();

    // A second registration with the SAME email but ATTACKER-CHOSEN credentials.
    // It must be indistinguishable in the response, and — critically — must not
    // overwrite the victim's auth hash or vault key.
    const attack = {
      ...body,
      authHash: 'attacker-chosen-auth-hash',
      encryptedVaultKey: 'attacker-vault-key',
      vaultKeyIv: 'attacker-iv',
      vaultKeyTag: 'attacker-tag',
    };
    const second = await withCsrf(agent.post(`${API}/auth/register`).send(attack), csrf);

    expect(second.status).toBe(first.status);
    expect(second.body).toEqual(first.body);
    expect(second.body.data).toEqual({ emailSent: true });

    // Exactly one account, with the ORIGINAL credentials untouched.
    expect(await User.countDocuments({ email: body.email })).toBe(1);
    const after = await User.findOne({ email: body.email }).select('+authHash');
    expect(after!._id.toString()).toBe(before!._id.toString());
    expect(after!.authHash).toBe(before!.authHash);
    expect(after!.encryptedVaultKey).toBe('encrypted-vault-key');
    expect(after!.vaultKeyIv).toBe('vault-key-iv');
    expect(after!.vaultKeyTag).toBe('vault-key-tag');
    expect(await bcrypt.compare('attacker-chosen-auth-hash', after!.authHash)).toBe(false);

    // The duplicate attempt writes no audit trail entry against the victim
    // (only the original registration did).
    const registrations = await AuditLog.countDocuments({
      userId: before!._id.toString(),
      action: 'registration',
    });
    expect(registrations).toBe(1);
  });
});

describe('authController — JWT purpose claim is validated independently of the signing key', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser({ emailVerified: false });
  });

  // Each token below is signed with the CORRECT purpose-derived key for the
  // endpoint it is sent to (so `jwt.verify` succeeds) but carries a foreign
  // `purpose` claim. Only the explicit purpose check can reject these.

  it('rejects a verify-email token whose purpose claim says password_reset', async () => {
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash(String(false)),
      },
      deriveTestPurposeKey('email_verification'),
      { algorithm: 'HS256', expiresIn: '24h' },
    );

    const res = await withCsrf(agent.post(`${API}/auth/verify-email`).send({ token }), csrf);

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('TOKEN_INVALID');

    // The account must still be unverified.
    const dbUser = await User.findById(user.id);
    expect(dbUser!.emailVerified).toBe(false);
  });

  it('rejects a reset-password token whose purpose claim says email_verification', async () => {
    const dbUser = await User.findById(user.id).select('+authHash');
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'email_verification',
        stateHash: generateStateHash(dbUser!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await withCsrf(
      agent.post(`${API}/auth/reset-password`).send({
        token,
        email: user.email,
        newAuthHash: 'attacker-new-hash',
        newEncryptedVaultKey: 'attacker-key',
        newVaultKeyIv: 'attacker-iv',
        newVaultKeyTag: 'attacker-tag',
      }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');

    // The password must NOT have been reset.
    const after = await User.findById(user.id).select('+authHash');
    expect(after!.authHash).toBe(dbUser!.authHash);
    expect(after!.encryptedVaultKey).not.toBe('attacker-key');
  });

  it('rejects an unlock-account token whose purpose claim says account_delete', async () => {
    const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
    await User.findByIdAndUpdate(user.id, {
      $set: { failedLoginAttempts: 10, lockoutUntil },
    });

    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'account_delete',
        stateHash: generateStateHash(lockoutUntil.toISOString()),
      },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await withCsrf(agent.post(`${API}/auth/unlock-account`).send({ token }), csrf);

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');

    // Still locked.
    const after = await User.findById(user.id);
    expect(after!.failedLoginAttempts).toBe(10);
    expect(after!.lockoutUntil?.getTime()).toBe(lockoutUntil.getTime());
  });

  it('rejects a 2FA temp token whose purpose claim says account_unlock', async () => {
    const twoFaUser = await createTestUser({ emailVerified: true });
    const secret = await enableTwoFactor(twoFaUser.id);

    const token = jwt.sign(
      { userId: twoFaUser.id, purpose: 'account_unlock' },
      deriveTestPurposeKey('2fa_temp'),
      { algorithm: 'HS256', expiresIn: '5m' },
    );

    const res = await withCsrf(
      agent
        .post(`${API}/auth/login/2fa`)
        .send({ tempToken: token, code: totpFor(secret).generate() }),
      csrf,
    );

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(res.body.data?.accessToken).toBeUndefined();
  });
});

describe('authController — token subject must still exist', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  // A well-formed ObjectId that owns no User document.
  const ghostId = '507f1f77bcf86cd799439011';

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  it('rejects a 2FA temp token for a deleted user with TOKEN_INVALID', async () => {
    const tempToken = jwt.sign(
      { userId: ghostId, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { algorithm: 'HS256', expiresIn: '5m' },
    );

    const res = await withCsrf(
      agent.post(`${API}/auth/login/2fa`).send({ tempToken, code: '123456' }),
      csrf,
    );

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
  });

  it('rejects a verify-email token for a deleted user', async () => {
    const token = jwt.sign(
      { userId: ghostId, purpose: 'email_verification', stateHash: generateStateHash('false') },
      deriveTestPurposeKey('email_verification'),
      { algorithm: 'HS256', expiresIn: '24h' },
    );

    const res = await withCsrf(agent.post(`${API}/auth/verify-email`).send({ token }), csrf);
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
  });

  it('rejects a reset-password token for a deleted user', async () => {
    const token = jwt.sign(
      { userId: ghostId, purpose: 'password_reset', stateHash: generateStateHash('whatever') },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await withCsrf(
      agent.post(`${API}/auth/reset-password`).send({
        token,
        email: 'ghost@example.com',
        newAuthHash: 'h',
        newEncryptedVaultKey: 'k',
        newVaultKeyIv: 'i',
        newVaultKeyTag: 't',
      }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
  });

  it('rejects an unlock-account token for a deleted user', async () => {
    const token = jwt.sign(
      { userId: ghostId, purpose: 'account_unlock', stateHash: generateStateHash('') },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await withCsrf(agent.post(`${API}/auth/unlock-account`).send({ token }), csrf);
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
  });
});

describe('authController — verify-email stateHash binding', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  it('rejects a token whose stateHash does not match the current verification state', async () => {
    const user = await createTestUser({ emailVerified: false });

    // stateHash of 'true' — i.e. minted for an ALREADY-verified state — must not
    // verify an unverified account.
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'email_verification',
        stateHash: generateStateHash(String(true)),
      },
      deriveTestPurposeKey('email_verification'),
      { algorithm: 'HS256', expiresIn: '24h' },
    );

    const res = await withCsrf(agent.post(`${API}/auth/verify-email`).send({ token }), csrf);

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    const after = await User.findById(user.id);
    expect(after!.emailVerified).toBe(false);
  });
});

describe('authController — POST /auth/resend-verification', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  it('returns an identical generic body for unverified, already-verified and unknown emails', async () => {
    const unverified = await createTestUser({ emailVerified: false });
    const verified = await createTestUser({ emailVerified: true });

    const resUnverified = await withCsrf(
      agent.post(`${API}/auth/resend-verification`).send({ email: unverified.email }),
      csrf,
    );
    const resVerified = await withCsrf(
      agent.post(`${API}/auth/resend-verification`).send({ email: verified.email }),
      csrf,
    );
    const resUnknown = await withCsrf(
      agent
        .post(`${API}/auth/resend-verification`)
        .send({ email: `nobody-${crypto.randomUUID()}@example.com` }),
      csrf,
    );

    for (const res of [resUnverified, resVerified, resUnknown]) {
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual({ emailSent: true });
    }
    // Byte-identical bodies: no enumeration oracle between the three paths.
    expect(resVerified.body).toEqual(resUnverified.body);
    expect(resUnknown.body).toEqual(resUnverified.body);

    // Resending must never flip verification state either way.
    expect((await User.findById(unverified.id))!.emailVerified).toBe(false);
    expect((await User.findById(verified.id))!.emailVerified).toBe(true);
  });

  it('rejects a malformed email with 400 before touching the database', async () => {
    const res = await withCsrf(
      agent.post(`${API}/auth/resend-verification`).send({ email: 'not-an-email' }),
      csrf,
    );
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});

describe('authController — getProgressiveDelay ladder', () => {
  // The delay ladder is the brute-force cost function referenced by both the
  // password step and the 2FA step; the thresholds are the contract.
  it('escalates at 3, 5 and 7 failed attempts and never before', () => {
    expect(getProgressiveDelay(0)).toBe(0);
    expect(getProgressiveDelay(2)).toBe(0);
    expect(getProgressiveDelay(3)).toBe(1000);
    expect(getProgressiveDelay(4)).toBe(1000);
    expect(getProgressiveDelay(5)).toBe(3000);
    expect(getProgressiveDelay(6)).toBe(3000);
    expect(getProgressiveDelay(7)).toBe(5000);
    expect(getProgressiveDelay(50)).toBe(5000);
  });
});

describe('userController — PUT /user/settings validation', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  it('rejects an empty settings payload with 400 and changes nothing', async () => {
    const before = await User.findById(user.id).lean();

    const res = await withCsrf(
      agent.put(`${API}/user/settings`).set('Authorization', authHeader(user.accessToken)).send({}),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/no settings provided/i);

    const after = await User.findById(user.id).lean();
    expect(after!.settings).toEqual(before!.settings);
    // A rejected update must not write an audit row.
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'settings_update' })).toBe(0);
  });

  it('rejects defaultPasswordOptions whose length is below minNumbers + minSymbols', async () => {
    const before = await User.findById(user.id).lean();

    const res = await withCsrf(
      agent
        .put(`${API}/user/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .send({
          defaultPasswordOptions: {
            length: 8,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            excludeAmbiguous: false,
            minNumbers: 5,
            minSymbols: 5,
          },
        }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);

    const after = await User.findById(user.id).lean();
    expect(after!.settings.defaultPasswordOptions).toEqual(before!.settings.defaultPasswordOptions);
  });

  it('accepts defaultPasswordOptions where length equals minNumbers + minSymbols', async () => {
    const res = await withCsrf(
      agent
        .put(`${API}/user/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .send({
          defaultPasswordOptions: {
            length: 10,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            excludeAmbiguous: false,
            minNumbers: 5,
            minSymbols: 5,
          },
        }),
      csrf,
    );

    expect(res.status).toBe(200);
    const after = await User.findById(user.id).lean();
    expect(after!.settings.defaultPasswordOptions.length).toBe(10);
    expect(after!.settings.defaultPasswordOptions.minNumbers).toBe(5);
  });
});

describe('User model — defaultPasswordOptions cross-field validator (defense-in-depth)', () => {
  it('fires on save() and rejects an invalid subdocument', async () => {
    const user = new User({
      email: `model-${crypto.randomUUID()}@example.com`,
      authHash: 'hash',
      encryptedVaultKey: 'k',
      vaultKeyIv: 'i',
      vaultKeyTag: 't',
      settings: {
        defaultPasswordOptions: { length: 6, minNumbers: 4, minSymbols: 4 },
      },
    });

    await expect(user.save()).rejects.toThrow(
      /Password length must be at least the sum of minNumbers and minSymbols/,
    );
    expect(await User.countDocuments({ email: user.email })).toBe(0);
  });

  it('fires on findOneAndUpdate({ runValidators: true }) and leaves the stored settings intact', async () => {
    const seeded = await createTestUser();
    const before = await User.findById(seeded.id).lean();

    await expect(
      User.findByIdAndUpdate(
        seeded.id,
        {
          $set: {
            'settings.defaultPasswordOptions': {
              length: 8,
              uppercase: true,
              lowercase: true,
              numbers: true,
              symbols: true,
              excludeAmbiguous: false,
              minNumbers: 6,
              minSymbols: 6,
            },
          },
        },
        { runValidators: true, returnDocument: 'after' },
      ),
    ).rejects.toThrow(/Password length must be at least the sum of minNumbers and minSymbols/);

    const after = await User.findById(seeded.id).lean();
    expect(after!.settings.defaultPasswordOptions).toEqual(before!.settings.defaultPasswordOptions);
  });

  it('accepts a valid subdocument through findOneAndUpdate({ runValidators: true })', async () => {
    const seeded = await createTestUser();

    await User.findByIdAndUpdate(
      seeded.id,
      {
        $set: {
          'settings.defaultPasswordOptions': {
            length: 24,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
            excludeAmbiguous: false,
            minNumbers: 3,
            minSymbols: 3,
          },
        },
      },
      { runValidators: true },
    );

    const after = await User.findById(seeded.id).lean();
    expect(after!.settings.defaultPasswordOptions.length).toBe(24);
    expect(after!.settings.defaultPasswordOptions.minSymbols).toBe(3);
  });
});

describe('userController — 2FA verify preconditions', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  it('returns 400 when no 2FA setup is pending and does not enable 2FA', async () => {
    const res = await withCsrf(
      agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ code: '123456' }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/no pending 2fa setup/i);

    const after = await User.findById(user.id).select('+twoFactorSecret');
    expect(after!.twoFactorEnabled).toBe(false);
    expect(after!.twoFactorSecret).toBeUndefined();
  });

  it('returns 400 for an expired pending setup and clears the pending secret', async () => {
    const secret = new Secret().base32;
    await User.findByIdAndUpdate(user.id, {
      $set: {
        pendingTwoFactorSecret: cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey),
        pendingTwoFactorExpiry: new Date(Date.now() - 60_000),
      },
    });

    const res = await withCsrf(
      agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ code: totpFor(secret).generate() }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/expired/i);

    // The stale pending secret must be purged, and 2FA must remain off.
    const after = await User.findById(user.id).select(
      '+pendingTwoFactorSecret +pendingTwoFactorExpiry +twoFactorSecret',
    );
    expect(after!.pendingTwoFactorSecret).toBeUndefined();
    expect(after!.pendingTwoFactorExpiry).toBeUndefined();
    expect(after!.twoFactorEnabled).toBe(false);
  });

  it('rejects a replayed TOTP time step and does not enable 2FA', async () => {
    const secret = new Secret().base32;
    await User.findByIdAndUpdate(user.id, {
      $set: {
        pendingTwoFactorSecret: cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey),
        pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
        // The current time step has already been consumed.
        lastTotpTimestamp: currentTimeStep() + 1,
      },
    });

    const res = await withCsrf(
      agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ code: totpFor(secret).generate() }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    const after = await User.findById(user.id).select('+twoFactorSecret +backupCodes');
    expect(after!.twoFactorEnabled).toBe(false);
    expect(after!.backupCodes ?? []).toHaveLength(0);
  });
});

describe('userController — 2FA disable and backup-code regeneration replay guards', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  it('rejects a replayed TOTP on 2FA disable and keeps 2FA enabled', async () => {
    const secret = await enableTwoFactor(user.id);
    await User.findByIdAndUpdate(user.id, {
      $set: { lastTotpTimestamp: currentTimeStep() + 1 },
    });

    const res = await withCsrf(
      agent
        .delete(`${API}/user/2fa`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ code: totpFor(secret).generate(), password: user.rawPassword }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    const after = await User.findById(user.id).select('+twoFactorSecret');
    expect(after!.twoFactorEnabled).toBe(true);
    expect(after!.twoFactorSecret).toBeTruthy();
  });

  it('rejects backup-code regeneration when 2FA is not enabled', async () => {
    const res = await withCsrf(
      agent
        .post(`${API}/user/2fa/regenerate-backup-codes`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ password: user.rawPassword, code: '123456' }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/not enabled/i);

    const after = await User.findById(user.id).select('+backupCodes');
    expect(after!.backupCodes ?? []).toHaveLength(0);
  });

  it('rejects a replayed TOTP on backup-code regeneration and leaves the old codes in place', async () => {
    await enableTwoFactor(user.id);
    const secret = new Secret().base32;
    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorSecret: cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey),
        lastTotpTimestamp: currentTimeStep() + 1,
      },
    });
    const before = await User.findById(user.id).select('+backupCodes');

    const res = await withCsrf(
      agent
        .post(`${API}/user/2fa/regenerate-backup-codes`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ password: user.rawPassword, code: totpFor(secret).generate() }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    const after = await User.findById(user.id).select('+backupCodes');
    expect(after!.backupCodes).toEqual(before!.backupCodes);
  });
});

describe('userController — account deletion 2FA replay guard', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  it('does not delete the account when the supplied TOTP replays a consumed time step', async () => {
    const secret = await enableTwoFactor(user.id);
    await User.findByIdAndUpdate(user.id, {
      $set: { lastTotpTimestamp: currentTimeStep() + 1 },
    });

    const res = await withCsrf(
      agent
        .delete(`${API}/user`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ password: user.rawPassword, code: totpFor(secret).generate() }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/invalid verification code/i);

    // The account must survive, un-flagged for deletion.
    const after = await User.findById(user.id);
    expect(after).not.toBeNull();
    expect(after!.deletionPending).toBeUndefined();
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThan(0);
  });

  it('requires a 2FA code when 2FA is enabled and leaves the account intact without one', async () => {
    await enableTwoFactor(user.id);

    const res = await withCsrf(
      agent
        .delete(`${API}/user`)
        .set('Authorization', authHeader(user.accessToken))
        .send({ password: user.rawPassword }),
      csrf,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/two-factor authentication code is required/i);
    expect(await User.findById(user.id)).not.toBeNull();
  });
});

describe('userController — sessions and audit log', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
  });

  it('flags exactly the caller’s own refresh token as the current session', async () => {
    // A second, unrelated session for the same user.
    await RefreshToken.create({
      userId: user.id,
      tokenHash: crypto.createHash('sha256').update('other-session').digest('hex'),
      familyId: crypto.randomUUID(),
      deviceInfo: { userAgent: 'other-agent', ip: '10.0.0.1', fingerprint: 'other' },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const res = await agent
      .get(`${API}/user/sessions`)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', `refreshToken=${user.refreshToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(2);
    const current = res.body.data.filter((s: { current: boolean }) => s.current);
    expect(current).toHaveLength(1);
    expect(current[0].deviceInfo.userAgent).toBe('test-agent');

    // The raw token hash must never be serialized to the client.
    for (const session of res.body.data as Record<string, unknown>[]) {
      expect(session.tokenHash).toBeUndefined();
    }
  });

  it('reports no current session when the request carries no refresh cookie', async () => {
    const res = await agent
      .get(`${API}/user/sessions`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.every((s: { current: boolean }) => s.current === false)).toBe(true);
  });

  it('rejects an audit-log limit above the hard cap and honours the cap itself', async () => {
    const tooBig = await agent
      .get(`${API}/user/audit-log?limit=101`)
      .set('Authorization', authHeader(user.accessToken));
    expect(tooBig.status).toBe(400);
    expect(tooBig.body.success).toBe(false);

    const atCap = await agent
      .get(`${API}/user/audit-log?limit=100`)
      .set('Authorization', authHeader(user.accessToken));
    expect(atCap.status).toBe(200);
    expect(atCap.body.pagination.limit).toBe(100);
  });

  it('paginates audit entries and never returns another user’s rows', async () => {
    const other = await createTestUser();

    const auditRow = (userId: string, offsetMs: number) => ({
      userId,
      action: 'login' as const,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      timestamp: new Date(Date.now() - offsetMs),
    });

    for (let i = 0; i < 5; i++) {
      await AuditLog.create(auditRow(user.id, i * 1000));
    }
    await AuditLog.create(auditRow(other.id, 0));

    const page1 = await agent
      .get(`${API}/user/audit-log?page=1&limit=2`)
      .set('Authorization', authHeader(user.accessToken));
    expect(page1.status).toBe(200);
    expect(page1.body.data).toHaveLength(2);
    expect(page1.body.pagination).toMatchObject({ page: 1, limit: 2, total: 5, totalPages: 3 });

    const page3 = await agent
      .get(`${API}/user/audit-log?page=3&limit=2`)
      .set('Authorization', authHeader(user.accessToken));
    expect(page3.body.data).toHaveLength(1);

    // userId is projected out, and the other user's row is never counted.
    expect(page1.body.data[0].userId).toBeUndefined();
    const otherLogs = await agent
      .get(`${API}/user/audit-log?limit=100`)
      .set('Authorization', authHeader(other.accessToken));
    expect(otherLogs.body.pagination.total).toBe(1);
  });
});

describe('jobLock — a non-duplicate-key failure must propagate', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rethrows a transient database error instead of silently reporting "not acquired"', async () => {
    const spy = vi
      .spyOn(JobLock, 'findOneAndUpdate')
      .mockRejectedValue(new Error('connection reset') as never);

    await expect(acquireJobLock('propagating-job', 60_000)).rejects.toThrow('connection reset');
    expect(spy).toHaveBeenCalled();
  });

  it('returns null (rather than throwing) when a live lock is already held', async () => {
    await JobLock.create({
      jobName: 'live-job',
      lockedBy: 'someone-else',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 60_000),
    });

    await expect(acquireJobLock('live-job', 60_000)).resolves.toBeNull();

    // The incumbent holder's lock document must be untouched.
    const lock = await JobLock.findOne({ jobName: 'live-job' });
    expect(lock!.lockedBy).toBe('someone-else');
  });
});

describe('email utility — transporter verification and send-result handling', () => {
  const envKeys = ['EMAIL_PROVIDER', 'SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM'] as const;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    saved = {};
    for (const key of envKeys) saved[key] = process.env[key];

    mailerMocks.sendMail.mockReset();
    mailerMocks.verify.mockReset();
    mailerMocks.createTransport.mockReset();
    mailerMocks.createTransport.mockReturnValue({
      sendMail: mailerMocks.sendMail,
      verify: mailerMocks.verify,
    });
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (saved[key] === undefined) {
        Reflect.deleteProperty(process.env, key);
      } else {
        process.env[key] = saved[key];
      }
    }
    vi.resetModules();
  });

  /** Re-imports the email module with a live SMTP transporter configured. */
  async function importEmailWithSmtp() {
    process.env['EMAIL_PROVIDER'] = 'smtp';
    process.env['SMTP_HOST'] = 'smtp.example.com';
    process.env['SMTP_USER'] = 'user@example.com';
    process.env['SMTP_PASS'] = 'password123';
    process.env['SMTP_FROM'] = 'H-Vault <noreply@example.com>';
    vi.resetModules();
    return import('../src/utils/email.js');
  }

  it('verifies the transporter exactly once across multiple sends', async () => {
    mailerMocks.verify.mockResolvedValue(true);
    mailerMocks.sendMail.mockResolvedValue({ accepted: ['a@example.com'] });

    const { sendEmail } = await importEmailWithSmtp();

    await sendEmail('a@example.com', 'One', '<p>1</p>');
    await sendEmail('a@example.com', 'Two', '<p>2</p>');

    expect(mailerMocks.verify).toHaveBeenCalledTimes(1);
    expect(mailerMocks.sendMail).toHaveBeenCalledTimes(2);
  });

  it('still sends when the one-time SMTP verification fails (verify is advisory)', async () => {
    mailerMocks.verify.mockRejectedValue(new Error('VERIFY not supported'));
    mailerMocks.sendMail.mockResolvedValue({ accepted: ['a@example.com'] });

    const { sendEmail } = await importEmailWithSmtp();

    const result = await sendEmail('a@example.com', 'Subject', '<p>body</p>');

    expect(result).toEqual({ success: true, message: 'Email sent successfully.' });
    expect(mailerMocks.sendMail).toHaveBeenCalledTimes(1);
  });

  it('reports a non-acceptance when the server returns no accepted recipients', async () => {
    mailerMocks.verify.mockResolvedValue(true);
    // No `accepted` key at all — the Array.isArray guard must treat it as empty.
    mailerMocks.sendMail.mockResolvedValue({ messageId: 'x' });

    const { sendEmail } = await importEmailWithSmtp();
    const result = await sendEmail('a@example.com', 'Subject', '<p>body</p>');

    expect(result.success).toBe(false);
    expect(result.message).toBe('Email was not accepted by the mail server.');
  });

  it('differentiates a send failure from an unconfigured transporter', async () => {
    mailerMocks.verify.mockResolvedValue(true);
    mailerMocks.sendMail.mockRejectedValue(new Error('550 mailbox unavailable'));

    const { sendEmail } = await importEmailWithSmtp();
    const failed = await sendEmail('a@example.com', 'Subject', '<p>body</p>');

    expect(failed.success).toBe(false);
    expect(failed.message).toBe('smtp_send_failed: 550 mailbox unavailable');
    // The unconfigured case is a DIFFERENT, distinguishable message — callers
    // (register / forgot-password) log on it.
    expect(failed.message).not.toBe('transporter_not_configured');
  });

  it('falls back to "Unknown error" when the transport rejects with a non-Error', async () => {
    mailerMocks.verify.mockResolvedValue(true);
    mailerMocks.sendMail.mockRejectedValue('socket hang up');

    const { sendEmail } = await importEmailWithSmtp();
    const result = await sendEmail('a@example.com', 'Subject', '<p>body</p>');

    expect(result).toEqual({ success: false, message: 'smtp_send_failed: Unknown error' });
  });

  it('returns transporter_not_configured (and creates no transport) when SMTP is absent', async () => {
    process.env['EMAIL_PROVIDER'] = 'smtp';
    process.env['SMTP_HOST'] = '';
    process.env['SMTP_USER'] = '';
    process.env['SMTP_PASS'] = '';
    process.env['SMTP_FROM'] = '';
    vi.resetModules();
    const { sendEmail } = await import('../src/utils/email.js');

    const result = await sendEmail('a@example.com', 'Subject', '<p>body</p>');

    expect(result).toEqual({ success: false, message: 'transporter_not_configured' });
    expect(mailerMocks.createTransport).not.toHaveBeenCalled();
    expect(mailerMocks.sendMail).not.toHaveBeenCalled();
  });
});
