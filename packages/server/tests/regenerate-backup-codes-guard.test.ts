/**
 * regenerateBackupCodes — `twoFactorEnabled` conditional-write guard.
 *
 * `POST /user/2fa/regenerate-backup-codes` reads the user, verifies the password
 * and the TOTP, hashes ten fresh backup codes, and only then writes them. The
 * enabled-check at the top is a READ, so a `disable2fa` landing in that window
 * used to be followed by a write that re-populated `backupCodes` (and
 * `lastTotpTimestamp`) on an account whose 2FA was already off.
 *
 * Both persistence branches now condition on `twoFactorEnabled: true`, mirroring
 * verify2fa's conditional-write pattern, so a disabled-underneath-us request
 * writes nothing.
 *
 * The race is made deterministic by intercepting `bcrypt.hash` — the controller
 * hashes the new codes AFTER both reads and BEFORE the write, so disabling 2FA
 * from inside the first hash reproduces the interleaving exactly.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/** Narrow, single-signature view of the overloaded bcryptjs binding, so `vi.spyOn` types cleanly. */
const bcryptHashable = bcrypt as unknown as {
  hash: (data: string, salt: number) => Promise<string>;
};

/** Mirrors exactly what `disable2fa` persists. */
async function disable2faInDb(userId: string): Promise<void> {
  await User.findByIdAndUpdate(userId, {
    $set: { twoFactorEnabled: false },
    $unset: { twoFactorSecret: 1, backupCodes: 1, lastTotpTimestamp: 1 },
  });
}

async function create2faUser(options: { withSecret?: boolean } = {}): Promise<{
  user: TestUser;
  secretObj: Secret;
}> {
  const secretObj = new Secret();
  const user = await createTestUser({ emailVerified: true });

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      ...(options.withSecret === false
        ? {}
        : { twoFactorSecret: cm.encryptTextSync(secretObj.base32, encKey) }),
      lastTotpTimestamp: 1,
    },
  });

  return { user, secretObj };
}

/**
 * Disables 2FA in the DB from inside the first `bcrypt.hash` call — i.e. after the
 * controller has read the user and validated the TOTP, but before it persists the
 * new backup codes.
 */
function disableDuringCodeHashing(userId: string): void {
  const realHash = bcryptHashable.hash.bind(bcrypt);
  let disabled = false;
  vi.spyOn(bcryptHashable, 'hash').mockImplementation(async (data: string, salt: number) => {
    if (!disabled) {
      disabled = true;
      await disable2faInDb(userId);
    }
    return realHash(data, salt);
  });
}

describe('regenerateBackupCodes — twoFactorEnabled conditional write', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects and writes nothing when 2FA is disabled mid-request (TOTP branch)', async () => {
    const { user, secretObj } = await create2faUser();
    const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
    const code = totp.generate();

    disableDuringCodeHashing(user.id);

    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/regenerate-backup-codes`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword, code });

    expect(res.status).toBe(400);

    // The disabled account must carry no backup codes and no revived TOTP timestamp.
    const persisted = await User.findById(user.id).select('+backupCodes');
    expect(persisted?.twoFactorEnabled).toBe(false);
    expect(persisted?.backupCodes ?? []).toHaveLength(0);
    expect(persisted?.lastTotpTimestamp ?? null).toBeNull();
  });

  it('rejects and writes nothing when 2FA is disabled mid-request (no-secret branch)', async () => {
    // Defensive branch: twoFactorEnabled with no stored secret → no TOTP required.
    const { user } = await create2faUser({ withSecret: false });

    disableDuringCodeHashing(user.id);

    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/regenerate-backup-codes`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword });

    expect(res.status).toBe(400);
    // The error envelope exposes the message on `error.message`; tolerate the
    // flat shape too so the assertion pins the CAUSE, not the envelope.
    const message: string = res.body.error?.message ?? res.body.message ?? '';
    expect(message).toMatch(/not enabled/i);

    const persisted = await User.findById(user.id).select('+backupCodes');
    expect(persisted?.twoFactorEnabled).toBe(false);
    expect(persisted?.backupCodes ?? []).toHaveLength(0);
  });

  it('still regenerates normally when 2FA stays enabled', async () => {
    const { user, secretObj } = await create2faUser();
    const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });

    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post(`${API}/user/2fa/regenerate-backup-codes`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({ password: user.rawPassword, code: totp.generate() });

    expect(res.status).toBe(200);
    const returned: string[] = res.body.data.backupCodes;
    expect(returned.length).toBeGreaterThan(0);

    const persisted = await User.findById(user.id).select('+backupCodes');
    expect(persisted?.twoFactorEnabled).toBe(true);
    expect(persisted?.backupCodes).toHaveLength(returned.length);
  });
});
