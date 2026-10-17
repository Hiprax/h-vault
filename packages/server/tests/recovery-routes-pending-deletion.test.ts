/**
 * The emailed recovery routes refuse an account whose erasure has begun.
 *
 * An account marked `deletionPending` (its owner deleted it and the erasure is
 * still running or must be finished by the clean-up job, or the reaper of
 * never-verified accounts claimed it) can no longer be signed in to, refreshed or
 * used with a session. A password reset or an unlock link therefore restores
 * nothing for it, and completing one only did harm: it answered "reset
 * successfully" for an account about to vanish, failed with a 500 when the row had
 * just gone, and could write an audit row under the erased account after the
 * erasure had swept its rows. Both routes now answer such an account the way they
 * answer a dead link, before anything is written, and the reset also when the
 * erasure's claim lands between its read and its write.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';

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
import mongoose from 'mongoose';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { sendPasswordResetEmail, sendVerificationEmail } from '../src/utils/email.js';
import {
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const EPISODE = 'pending-deletion-episode';

afterEach(() => {
  vi.restoreAllMocks();
});

async function resetLink(user: TestUser): Promise<string> {
  const stored = await User.findById(user.id).select('+authHash').lean();
  return jwt.sign(
    { userId: user.id, purpose: 'password_reset', stateHash: generateStateHash(stored!.authHash) },
    deriveTestPurposeKey('password_reset'),
    { algorithm: 'HS256', expiresIn: '1h' },
  );
}

function unlockLink(user: TestUser): string {
  return jwt.sign(
    { userId: user.id, purpose: 'account_unlock', stateHash: generateStateHash(EPISODE) },
    deriveTestPurposeKey('account_unlock'),
    { algorithm: 'HS256', expiresIn: 3600 },
  );
}

async function post(path: string, body: Record<string, unknown>): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}${path}`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(body);
}

const resetBody = (user: TestUser, token: string): Record<string, unknown> => ({
  token,
  email: user.email,
  newAuthHash: 'reset-auth-hash-value',
  newEncryptedVaultKey: 'fresh-encrypted-vault-key',
  newVaultKeyIv: 'fresh-vault-iv',
  newVaultKeyTag: 'fresh-vault-tag',
});

async function markPending(userId: string): Promise<void> {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    { $set: { deletionPending: true } },
  );
}

async function lockPassword(userId: string): Promise<void> {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        failedLoginAttempts: 10,
        lockoutUntil: new Date(Date.now() + 30 * 60 * 1000),
        lockoutEpisodeId: EPISODE,
      },
    },
  );
}

async function storedCredential(userId: string): Promise<string | undefined> {
  const row = await User.findById(userId).select('+authHash').lean();
  return row?.authHash;
}

/**
 * Makes the NEXT `User.findById(...).select(...)` read the account as it is, and
 * then marks it pending: the erasure's claim landing between the handler's read
 * and its write.
 */
function claimAfterTheRead(userId: string): void {
  const realFindById = User.findById.bind(User) as (id: unknown) => {
    select: (fields: string) => Promise<unknown>;
  };
  vi.spyOn(User, 'findById').mockImplementationOnce(((id: unknown) => ({
    select: async (fields: string) => {
      const doc = await realFindById(id).select(fields);
      await markPending(userId);
      return doc;
    },
  })) as never);
}

describe('a password reset for an account being erased', () => {
  it('is refused like a dead link, before anything is written', async () => {
    const user = await createTestUser({ emailVerified: true });
    const token = await resetLink(user);
    await markPending(user.id);
    const before = await storedCredential(user.id);

    const res = await post('/auth/reset-password', resetBody(user, token));

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await storedCredential(user.id)).toBe(before);
    // Nothing revoked, nothing recorded: the erasure finds the account as it left it.
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
  });

  it('is refused, and records nothing, when the claim lands between its read and its write', async () => {
    const user = await createTestUser({ emailVerified: true });
    const token = await resetLink(user);
    claimAfterTheRead(user.id);

    const res = await post('/auth/reset-password', resetBody(user, token));

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
  });

  it('is refused, not a 500, when the account row is already gone at the write', async () => {
    const user = await createTestUser({ emailVerified: true });
    const token = await resetLink(user);
    const realFindById = User.findById.bind(User) as (id: unknown) => {
      select: (fields: string) => Promise<unknown>;
    };
    vi.spyOn(User, 'findById').mockImplementationOnce(((id: unknown) => ({
      select: async (fields: string) => {
        const doc = await realFindById(id).select(fields);
        await User.collection.deleteOne({ _id: new mongoose.Types.ObjectId(user.id) });
        return doc;
      },
    })) as never);

    const res = await post('/auth/reset-password', resetBody(user, token));

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
  });

  it('a failure of the write other than a vanished row is still a server error', async () => {
    const user = await createTestUser({ emailVerified: true });
    const token = await resetLink(user);
    vi.spyOn(User.prototype, 'save').mockRejectedValueOnce(new Error('write concern timeout'));

    const res = await post('/auth/reset-password', resetBody(user, token));

    expect(res.status).toBe(500);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'password_change' })).toBe(0);
  });

  it('still resets a live account', async () => {
    const user = await createTestUser({ emailVerified: true });

    const res = await post('/auth/reset-password', resetBody(user, await resetLink(user)));

    expect(res.status).toBe(200);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'password_change' })).toBe(1);
  });
});

describe('an unlock link for an account being erased', () => {
  it('is refused like a dead link, before anything is written', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    await markPending(user.id);
    const writes = vi.spyOn(User, 'updateOne');

    const res = await post('/auth/unlock-account', { token: unlockLink(user) });

    // Refused at the read: the discharge is not even attempted.
    expect(writes).not.toHaveBeenCalled();
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    const row = await User.findById(user.id).select('+lockoutEpisodeId').lean();
    expect(row!.lockoutEpisodeId).toBe(EPISODE);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
    // No device proof is handed to the browser that followed it.
    const cookies = ([] as string[]).concat(res.headers['set-cookie'] ?? []);
    expect(cookies.some((cookie) => cookie.startsWith('__hv_device=') && !/=;/.test(cookie))).toBe(
      false,
    );
  });

  it('discharges nothing when the claim lands between its read and its write', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    claimAfterTheRead(user.id);

    const res = await post('/auth/unlock-account', { token: unlockLink(user) });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('TOKEN_INVALID');
    const row = await User.findById(user.id).select('+lockoutEpisodeId').lean();
    expect(row!.lockoutEpisodeId).toBe(EPISODE);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
  });

  it('still unlocks a live account', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const res = await post('/auth/unlock-account', { token: unlockLink(user) });

    expect(res.status).toBe(200);
    const row = await User.findById(user.id).select('+lockoutEpisodeId').lean();
    expect(row!.lockoutEpisodeId).toBeUndefined();
  });
});

describe('a reset link requested for an account being erased', () => {
  it('is not mailed, and the answer is the one every address gets', async () => {
    const user = await createTestUser({ emailVerified: true });
    const unknown = await post('/auth/forgot-password', { email: 'nobody-here@example.com' });
    await markPending(user.id);
    vi.mocked(sendPasswordResetEmail).mockClear();

    const res = await post('/auth/forgot-password', { email: user.email });

    expect(res.status).toBe(200);
    expect(res.body).toEqual(unknown.body);
    expect(sendPasswordResetEmail).not.toHaveBeenCalled();
  });

  it('is mailed for a live account', async () => {
    const user = await createTestUser({ emailVerified: true });
    vi.mocked(sendPasswordResetEmail).mockClear();

    const res = await post('/auth/forgot-password', { email: user.email });

    expect(res.status).toBe(200);
    expect(sendPasswordResetEmail).toHaveBeenCalledTimes(1);
    expect(vi.mocked(sendPasswordResetEmail).mock.calls[0]![0]).toBe(user.email);
  });
});

describe('a new verification link requested for an account being erased', () => {
  it('is not mailed, and the answer is the one every address gets', async () => {
    const user = await createTestUser({ emailVerified: false });
    const unknown = await post('/auth/resend-verification', { email: 'nobody-here@example.com' });
    await markPending(user.id);
    vi.mocked(sendVerificationEmail).mockClear();

    const res = await post('/auth/resend-verification', { email: user.email });

    expect(res.status).toBe(200);
    expect(res.body).toEqual(unknown.body);
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('is mailed for an unverified account nobody is erasing', async () => {
    const user = await createTestUser({ emailVerified: false });
    vi.mocked(sendVerificationEmail).mockClear();

    const res = await post('/auth/resend-verification', { email: user.email });

    expect(res.status).toBe(200);
    expect(sendVerificationEmail).toHaveBeenCalledTimes(1);
    expect(vi.mocked(sendVerificationEmail).mock.calls[0]![0]).toBe(user.email);
  });
});
