/**
 * Tests targeting specific coverage gaps across the server package.
 * Each section addresses uncovered lines identified by v8 coverage analysis.
 */
import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { JobLock } from '../src/models/JobLock.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { acquireJobLock } from '../src/utils/jobLock.js';
import { getProgressiveDelay } from '../src/controllers/authController.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  deriveTestPurposeKey,
  getCsrf as getCsrfWithAgent,
  JWT_SECRET,
  JWT_PURPOSE_SECRET,
} from './helpers.js';

// coverage-gaps uses a bare request(app) instead of an agent; wrap the shared helper.
async function getCsrf(extraCookies?: string): Promise<{ token: string; cookie: string }> {
  return getCsrfWithAgent(request(app) as unknown as import('supertest').Agent, extraCookies);
}

// ═══════════════════════════════════════════════════════════════════════
// Model toJSON transforms
// ═══════════════════════════════════════════════════════════════════════

describe('Model toJSON transforms', () => {
  describe('AuditLog.toJSON', () => {
    it('strips __v from serialized output', async () => {
      const user = await createTestUser();
      const doc = await AuditLog.create({
        userId: user.id,
        action: 'login',
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      });

      const json = doc.toJSON();
      expect(json).not.toHaveProperty('__v');
      // userId is intentionally stripped from serialized output — see the
      // toJSON transform on each model for rationale.
      expect(json).not.toHaveProperty('userId');
      expect(json).toHaveProperty('_id');
      expect(json).toHaveProperty('action', 'login');
    });
  });

  describe('BackupLog.toJSON', () => {
    it('strips __v from serialized output', async () => {
      const user = await createTestUser();
      const doc = await BackupLog.create({
        userId: user.id,
        status: 'success',
        sentTo: ['test@example.com'],
        fileSizeBytes: 1024,
        itemCount: 5,
      });

      const json = doc.toJSON();
      expect(json).not.toHaveProperty('__v');
      expect(json).toHaveProperty('_id');
      expect(json).toHaveProperty('status', 'success');
      expect(json).toHaveProperty('sentTo');
      expect(json.sentTo).toEqual(['test@example.com']);
    });
  });

  describe('RefreshToken.toJSON', () => {
    it('strips __v and tokenHash from serialized output', async () => {
      const user = await createTestUser();
      const doc = await RefreshToken.create({
        userId: user.id,
        tokenHash: 'sensitive-hash-value',
        familyId: 'family-1',
        deviceInfo: {
          userAgent: 'test-agent',
          ip: '127.0.0.1',
          fingerprint: 'fp-1',
        },
        expiresAt: new Date(Date.now() + 86400000),
      });

      const json = doc.toJSON();
      expect(json).not.toHaveProperty('__v');
      expect(json).not.toHaveProperty('tokenHash');
      expect(json).toHaveProperty('_id');
      expect(json).toHaveProperty('familyId', 'family-1');
      expect(json).toHaveProperty('deviceInfo');
    });
  });

  describe('User.toJSON', () => {
    it('strips authHash, twoFactorSecret, backupCodes, and __v', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id);
      expect(dbUser).not.toBeNull();

      const json = dbUser!.toJSON();
      expect(json).not.toHaveProperty('__v');
      expect(json).not.toHaveProperty('authHash');
      expect(json).not.toHaveProperty('twoFactorSecret');
      expect(json).not.toHaveProperty('backupCodes');
      expect(json).toHaveProperty('_id');
      expect(json).toHaveProperty('email');
      expect(json).toHaveProperty('emailVerified');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// JobLock edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('acquireJobLock edge cases', () => {
  it('returns null when another instance holds the lock', async () => {
    // Create a lock held by a different instance
    await JobLock.create({
      jobName: 'test-job-taken',
      lockedBy: 'another-instance-id',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 600_000), // far future
    });

    const result = await acquireJobLock('test-job-taken', 60_000);
    expect(result).toBeNull();
  });

  it('returns null on duplicate key error (race condition)', async () => {
    // Simulate duplicate key error by creating a lock and then trying via upsert
    // We mock findOneAndUpdate to throw a duplicate key error
    const _origFn = JobLock.findOneAndUpdate.bind(JobLock);
    const mockError = new Error('E11000 duplicate key error') as Error & { code: number };
    mockError.code = 11000;

    vi.spyOn(JobLock, 'findOneAndUpdate').mockRejectedValueOnce(mockError);

    const result = await acquireJobLock('test-dup-key', 60_000);
    expect(result).toBeNull();

    vi.restoreAllMocks();
  });

  it('re-throws non-duplicate-key errors', async () => {
    const otherError = new Error('Something else went wrong');
    vi.spyOn(JobLock, 'findOneAndUpdate').mockRejectedValueOnce(otherError);

    await expect(acquireJobLock('test-other-err', 60_000)).rejects.toThrow(
      'Something else went wrong',
    );

    vi.restoreAllMocks();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Auth middleware — JWT edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Auth middleware edge cases', () => {
  it('rejects JWT with non-string userId in payload', async () => {
    // Create a token with numeric userId
    const badToken = jwt.sign({ userId: 12345 }, JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '1m',
    });
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', `Bearer ${badToken}`)
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(401);
  });

  it('rejects JWT with missing userId in payload', async () => {
    // Create a token without userId
    const badToken = jwt.sign({ foo: 'bar' }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '1m' });
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', `Bearer ${badToken}`)
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(401);
  });

  it('rejects JWT for deleted user (user not found in DB)', async () => {
    // Create a token for a non-existent user ID
    const fakeUserId = new mongoose.Types.ObjectId().toString();
    const orphanToken = jwt.sign({ userId: fakeUserId }, JWT_SECRET, {
      algorithm: 'HS256',
      subject: fakeUserId,
      expiresIn: '15m',
    });
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', `Bearer ${orphanToken}`)
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CSV import with mapping (toolsController)
// ═══════════════════════════════════════════════════════════════════════

describe('CSV import with mapping', () => {
  it('imports CSV data with column mapping', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const csvData =
      'Name,EncData,DIv,DTag,EName,NIv,NTag\n' +
      'item1,enc-data-1,iv1,tag1,enc-name-1,niv1,ntag1\n' +
      'item2,enc-data-2,iv2,tag2,enc-name-2,niv2,ntag2';

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        format: 'csv',
        data: csvData,
        csvMapping: {
          Name: 'name',
          EncData: 'encryptedData',
          DIv: 'dataIv',
          DTag: 'dataTag',
          EName: 'encryptedName',
          NIv: 'nameIv',
          NTag: 'nameTag',
        },
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.importedCount).toBe(2);
  });

  it('handles CSV with quoted fields containing commas', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const csvData =
      'EncData,DIv,DTag,EName,NIv,NTag\n' + '"data,with,commas",iv1,tag1,"name,comma",niv1,ntag1';

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        format: 'csv',
        data: csvData,
        csvMapping: {
          EncData: 'encryptedData',
          DIv: 'dataIv',
          DTag: 'dataTag',
          EName: 'encryptedName',
          NIv: 'nameIv',
          NTag: 'nameTag',
        },
      });

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(1);
  });

  it('handles CSV with escaped double quotes', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const csvData =
      'EncData,DIv,DTag,EName,NIv,NTag\n' + '"data""escaped",iv1,tag1,"name""esc",niv1,ntag1';

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        format: 'csv',
        data: csvData,
        csvMapping: {
          EncData: 'encryptedData',
          DIv: 'dataIv',
          DTag: 'dataTag',
          EName: 'encryptedName',
          NIv: 'nameIv',
          NTag: 'nameTag',
        },
      });

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(1);
  });

  it('rejects CSV with header only (no data rows)', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        format: 'csv',
        data: 'EncData,DIv,DTag,EName,NIv,NTag',
        csvMapping: {
          EncData: 'encryptedData',
          DIv: 'dataIv',
          DTag: 'dataTag',
          EName: 'encryptedName',
          NIv: 'nameIv',
          NTag: 'nameTag',
        },
      });

    expect(res.status).toBe(400);
  });

  it('imports with bitwarden format (JSON-based)', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const importData = JSON.stringify({
      items: [
        {
          itemType: 'login',
          encryptedData: 'enc-bw-1',
          dataIv: 'iv-bw-1',
          dataTag: 'tag-bw-1',
          encryptedName: 'name-bw-1',
          nameIv: 'niv-bw-1',
          nameTag: 'ntag-bw-1',
        },
      ],
    });

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ format: 'bitwarden', data: importData });

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(1);
  });

  it('rejects bitwarden format with invalid JSON', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ format: 'bitwarden', data: 'not-json' });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('rejects bitwarden format without items array', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ format: 'lastpass', data: JSON.stringify({ data: 'no items' }) });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });
});

// NOTE: a former `optionalAuth middleware` describe here only hit
// `GET /api/v1/health` — an endpoint that does not use `optionalAuth` at all —
// so it would have stayed green if `optionalAuth` were deleted entirely. The
// real middleware is now exercised directly (attach / no-attach / invalid-token
// / unverified / db-error branches) in `coverage-middleware-auth.test.ts`, so
// the no-op describe was removed.

// ═══════════════════════════════════════════════════════════════════════
// Auth middleware — emailVerified enforcement
// ═══════════════════════════════════════════════════════════════════════

describe('authenticate middleware emailVerified enforcement', () => {
  it('rejects unverified user with 401 even with a valid JWT', async () => {
    const user = await createTestUser({ emailVerified: false });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(401);
  });

  it('allows verified user with a valid JWT', async () => {
    const user = await createTestUser({ emailVerified: true });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
  });

  it('rejects user whose emailVerified was revoked after token issuance', async () => {
    const user = await createTestUser({ emailVerified: true });

    // Revoke emailVerified after token was issued
    await User.findByIdAndUpdate(user.id, { emailVerified: false });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ObjectId validation middleware
// ═══════════════════════════════════════════════════════════════════════

describe('validateObjectId middleware', () => {
  it('returns 400 for invalid ObjectId on vault item get', async () => {
    const user = await createTestUser();
    const res = await request(app)
      .get('/api/v1/vault/items/not-a-valid-id')
      .set('Authorization', authHeader(user.accessToken));
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('Invalid');
  });

  it('returns 400 for invalid ObjectId on vault item delete', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();
    const res = await request(app)
      .delete('/api/v1/vault/items/invalid-id')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid ObjectId on folder update', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();
    const res = await request(app)
      .put('/api/v1/folders/bad-id')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ encryptedName: 'x', nameIv: 'y', nameTag: 'z' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid ObjectId on session revoke', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();
    const res = await request(app)
      .delete('/api/v1/user/sessions/xyz')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);
    expect(res.status).toBe(400);
  });

  it('allows valid ObjectId through', async () => {
    const user = await createTestUser();
    const validId = new mongoose.Types.ObjectId().toString();
    const res = await request(app)
      .get(`/api/v1/vault/items/${validId}`)
      .set('Authorization', authHeader(user.accessToken));
    // Should pass ObjectId validation (404 because item doesn't exist, not 400)
    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Progressive login delay — getProgressiveDelay unit tests
// ═══════════════════════════════════════════════════════════════════════

describe('getProgressiveDelay', () => {
  it('returns 0 for 1-2 failed attempts', () => {
    expect(getProgressiveDelay(0)).toBe(0);
    expect(getProgressiveDelay(1)).toBe(0);
    expect(getProgressiveDelay(2)).toBe(0);
  });

  it('returns 1000ms for 3-4 failed attempts', () => {
    expect(getProgressiveDelay(3)).toBe(1000);
    expect(getProgressiveDelay(4)).toBe(1000);
  });

  it('returns 3000ms for 5-6 failed attempts', () => {
    expect(getProgressiveDelay(5)).toBe(3000);
    expect(getProgressiveDelay(6)).toBe(3000);
  });

  it('returns 5000ms for 7+ failed attempts', () => {
    expect(getProgressiveDelay(7)).toBe(5000);
    expect(getProgressiveDelay(10)).toBe(5000);
    expect(getProgressiveDelay(100)).toBe(5000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// M6: TOTP window consistency — all verification points use window: 1 (±30s)
// ═══════════════════════════════════════════════════════════════════════

describe('TOTP window consistency', () => {
  // These exercise the ACTUAL ±30s tolerance both controllers apply, rather
  // than grepping the source for the literal `window: 1` (which a refactor to a
  // named constant, or Prettier reflow, would silently defeat). A code from the
  // immediately adjacent 30s step must be accepted (window >= 1); a code two
  // steps away must be rejected (window < 2) — pinning the tolerance to exactly
  // one step on both the login-2FA (authController) and 2FA-verify
  // (userController) paths.
  const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';
  const cm = new CryptoManager();

  /** Creates a 2FA-enabled user whose TOTP secret is known to the test. */
  async function enable2faUser(): Promise<{
    user: Awaited<ReturnType<typeof createTestUser>>;
    secret: Secret;
  }> {
    const secret = new Secret();
    const user = await createTestUser({ emailVerified: true });
    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
        // Old timestamp so a fresh code (a much later time step) is never
        // rejected by the replay guard — this test isolates the window check.
        lastTotpTimestamp: 1,
      },
    });
    return { user, secret };
  }

  /** A TOTP for `secret` computed `offsetMs` away from the current time. */
  function codeAt(secret: Secret, offsetMs: number): string {
    const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
    return totp.generate({ timestamp: Date.now() + offsetMs });
  }

  function tempTokenFor(userId: string): string {
    return jwt.sign({ userId, purpose: '2fa_temp' }, deriveTestPurposeKey('2fa_temp'), {
      expiresIn: '5m',
    });
  }

  it('login/2fa accepts a code from the adjacent 30s step (window 1)', async () => {
    const { user, secret } = await enable2faUser();
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ tempToken: tempTokenFor(user.id), code: codeAt(secret, -30_000) });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('login/2fa rejects a code two 30s steps away (outside window 1)', async () => {
    const { user, secret } = await enable2faUser();
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ tempToken: tempTokenFor(user.id), code: codeAt(secret, -60_000) });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it('2fa/verify accepts a code from the adjacent step and enables 2FA', async () => {
    const user = await createTestUser({ emailVerified: true });

    const { token: csrf1, cookie: cookie1 } = await getCsrf();
    const setupRes = await request(app)
      .post('/api/v1/user/2fa/setup')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1)
      .send({ password: user.rawPassword });
    expect(setupRes.status).toBe(200);
    const secret = Secret.fromBase32(setupRes.body.data.secret as string);

    const { token: csrf2, cookie: cookie2 } = await getCsrf();
    const res = await request(app)
      .post('/api/v1/user/2fa/verify')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ code: codeAt(secret, -30_000) });

    expect(res.status).toBe(200);
    const refreshed = await User.findById(user.id);
    expect(refreshed).not.toBeNull();
    expect(refreshed!.twoFactorEnabled).toBe(true);
  });

  it('2fa/verify rejects a code two steps away and leaves 2FA disabled', async () => {
    const user = await createTestUser({ emailVerified: true });

    const { token: csrf1, cookie: cookie1 } = await getCsrf();
    const setupRes = await request(app)
      .post('/api/v1/user/2fa/setup')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1)
      .send({ password: user.rawPassword });
    expect(setupRes.status).toBe(200);
    const secret = Secret.fromBase32(setupRes.body.data.secret as string);

    const { token: csrf2, cookie: cookie2 } = await getCsrf();
    const res = await request(app)
      .post('/api/v1/user/2fa/verify')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ code: codeAt(secret, -60_000) });

    expect(res.status).toBe(400);
    const refreshed = await User.findById(user.id);
    expect(refreshed).not.toBeNull();
    expect(refreshed!.twoFactorEnabled).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Backup controller edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Backup controller edge cases', () => {
  it('setupBackup returns 404 when the user vanishes between auth and the update write', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Keep the user alive so the JWT strategy AND the authHash re-check pass,
    // then force the FINAL `findByIdAndUpdate(...).select('-__v').lean()` to
    // resolve null — the exact race the controller's `if (!user) throw
    // notFound(...)` guards. Deleting the user instead (as this test used to)
    // makes the JWT strategy reject with 401 before the controller runs, so the
    // named branch was never exercised and removing the guard would not fail it.
    vi.spyOn(User, 'findByIdAndUpdate').mockReturnValue({
      select: () => ({ lean: () => Promise.resolve(null) }),
    } as never);

    try {
      const res = await request(app)
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf)
        .set('Cookie', cookie)
        .send({
          authHash: user.authHash,
          encryptedBWK: 'test-bwk',
          bwkIv: 'test-iv',
          bwkTag: 'test-tag',
          bwkSalt: 'test-salt',
        });

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('User not found');
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('updateBackupSettings requires at least one setting', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Setup backup first
    await User.findByIdAndUpdate(user.id, {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'bwk',
        'settings.backup.bwkIv': 'iv',
        'settings.backup.bwkTag': 'tag',
        'settings.backup.bwkSalt': 'salt',
      },
    });

    const res = await request(app)
      .put('/api/v1/backup/settings')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({});

    expect(res.status).toBe(400);
  });

  it('triggerBackup succeeds for user with no items', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Setup backup encryption first (isConfigured required for triggering)
    await User.findByIdAndUpdate(user.id, {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'bwk',
        'settings.backup.bwkIv': 'iv',
        'settings.backup.bwkTag': 'tag',
        'settings.backup.bwkSalt': 'salt',
      },
    });

    const res = await request(app)
      .post('/api/v1/backup/trigger')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('downloadBackup succeeds and returns backup data', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Setup backup encryption (required for download)
    await User.findByIdAndUpdate(user.id, {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'test-bwk',
        'settings.backup.bwkIv': 'test-iv',
        'settings.backup.bwkTag': 'test-tag',
        'settings.backup.bwkSalt': 'test-salt',
      },
    });

    const res = await request(app)
      .get('/api/v1/backup/download')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
  });

  it('changeBackupPassword returns 404 when the update write finds no user', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // As with setupBackup: leave the user alive so auth + the current-password
    // bcrypt check pass, then force the final `findByIdAndUpdate` to resolve
    // null so the controller's `if (!user) throw notFound(...)` branch actually
    // runs (deleting the user would 401 at the JWT strategy first).
    vi.spyOn(User, 'findByIdAndUpdate').mockReturnValue({
      select: () => ({ lean: () => Promise.resolve(null) }),
    } as never);

    try {
      const res = await request(app)
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf)
        .set('Cookie', cookie)
        .send({
          password: user.rawPassword,
          newEncryptedBWK: 'new-bwk',
          newBwkIv: 'new-iv',
          newBwkTag: 'new-tag',
          newBwkSalt: 'new-salt',
        });

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('User not found');
    } finally {
      vi.restoreAllMocks();
    }
  });

  // NOTE: a former "downloadBackup returns error if user not found" test
  // deleted the user and accepted `[401, 404]`. `downloadBackup` reaches its
  // `if (!user)` branch via `User.findById` — the SAME call the JWT strategy
  // uses to authenticate — so a deleted user is always rejected at 401 before
  // the controller runs, and the branch cannot be isolated over HTTP without
  // breaking auth. Deleted-user rejection on an authenticated route is already
  // covered by "rejects JWT for deleted user" above, so the redundant,
  // mis-titled test was removed.
});

// ═══════════════════════════════════════════════════════════════════════
// Auth controller — resend verification edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Resend verification edge cases', () => {
  it('returns generic success for non-existent email', async () => {
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ email: 'nonexistent@example.com' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns generic success for already verified email', async () => {
    const user = await createTestUser({ emailVerified: true });
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ email: user.email });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('sends verification email for unverified user', async () => {
    const user = await createTestUser({ emailVerified: false });
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ email: user.email });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns identical message and emailSent for unverified and nonexistent emails (anti-enumeration)', async () => {
    const user = await createTestUser({ emailVerified: false });
    const { token: csrf1, cookie: cookie1 } = await getCsrf();

    const res1 = await request(app)
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1)
      .send({ email: user.email });

    const { token: csrf2, cookie: cookie2 } = await getCsrf();

    const res2 = await request(app)
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ email: 'nonexistent@example.com' });

    // Both must return the same generic message and emailSent: true
    expect(res1.body.message).toBe(res2.body.message);
    expect(res1.body.data.emailSent).toBe(true);
    expect(res2.body.data.emailSent).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Vault controller — additional edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Vault controller edge cases', () => {
  it('getUserId throws unauthorized when req.user is missing', async () => {
    // Send request without auth header
    const { token: csrf, cookie } = await getCsrf();

    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Import edge cases — folder ownership validation
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// Auth controller — token edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Auth controller token edge cases', () => {
  it('refresh rejects expired refresh token', async () => {
    const user = await createTestUser();

    // Create an expired refresh token
    const crypto = await import('node:crypto');
    const { hashToken } = await import('../src/utils/token.js');

    const expiredRefreshRaw = crypto.default.randomBytes(64).toString('hex');
    const expiredRefreshHash = hashToken(expiredRefreshRaw);
    const familyId = crypto.default.randomUUID();

    await RefreshToken.create({
      userId: user.id,
      tokenHash: expiredRefreshHash,
      familyId,
      deviceInfo: {
        userAgent: 'test-agent',
        ip: '127.0.0.1',
        fingerprint: 'test-fp',
      },
      expiresAt: new Date(Date.now() - 1000), // Already expired
    });

    // Bind the CSRF token to the same refresh-token family the request uses.
    const { token: csrf, cookie: csrfCookie } = await getCsrf(`refreshToken=${expiredRefreshRaw}`);

    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .set('x-csrf-token', csrf)
      .set('Cookie', `${csrfCookie}; refreshToken=${expiredRefreshRaw}`)
      .send();

    expect(res.status).toBe(401);
  });

  it('verify-email rejects token with wrong purpose', async () => {
    const user = await createTestUser({ emailVerified: false });
    const { token: csrf, cookie } = await getCsrf();

    // Create a token with wrong purpose
    const wrongPurposeToken = jwt.sign(
      { userId: user.id, purpose: 'password_reset', stateHash: 'fake' },
      JWT_PURPOSE_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/verify-email')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token: wrongPurposeToken });

    expect(res.status).toBe(400);
  });

  it('verify-email rejects token for non-existent user', async () => {
    const fakeUserId = new mongoose.Types.ObjectId().toString();
    const { token: csrf, cookie } = await getCsrf();

    const badToken = jwt.sign(
      { userId: fakeUserId, purpose: 'email_verification', stateHash: 'fake' },
      deriveTestPurposeKey('email_verification'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/verify-email')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token: badToken });

    expect(res.status).toBe(400);
  });

  it('verify-email rejects token with stale state hash', async () => {
    const user = await createTestUser({ emailVerified: false });
    const { token: csrf, cookie } = await getCsrf();

    // Create a token with stale state hash (emailVerified was false, but hash doesn't match)
    const staleToken = jwt.sign(
      { userId: user.id, purpose: 'email_verification', stateHash: 'stale-hash' },
      deriveTestPurposeKey('email_verification'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/verify-email')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token: staleToken });

    expect(res.status).toBe(400);
  });

  it('unlock-account rejects token for non-existent user', async () => {
    const fakeUserId = new mongoose.Types.ObjectId().toString();
    const { token: csrf, cookie } = await getCsrf();

    const badToken = jwt.sign(
      { userId: fakeUserId, purpose: 'account_unlock', stateHash: 'fake' },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/unlock-account')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token: badToken });

    expect(res.status).toBe(400);
  });

  it('unlock-account rejects token with stale state hash', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Lock the account
    await User.findByIdAndUpdate(user.id, {
      failedLoginAttempts: 10,
      lockoutUntil: new Date(Date.now() + 30 * 60 * 1000),
    });

    const staleToken = jwt.sign(
      { userId: user.id, purpose: 'account_unlock', stateHash: 'stale-hash' },
      deriveTestPurposeKey('account_unlock'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/unlock-account')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ token: staleToken });

    expect(res.status).toBe(400);
  });

  it('reset-password rejects token for non-existent user', async () => {
    const fakeUserId = new mongoose.Types.ObjectId().toString();
    const { token: csrf, cookie } = await getCsrf();

    const badToken = jwt.sign(
      { userId: fakeUserId, purpose: 'password_reset', stateHash: 'fake' },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        token: badToken,
        email: 'nonexistent@example.com',
        newAuthHash: 'new-hash',
        newEncryptedVaultKey: 'new-key',
        newVaultKeyIv: 'new-iv',
        newVaultKeyTag: 'new-tag',
      });

    expect(res.status).toBe(400);
  });

  it('reset-password rejects token with stale state hash', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const staleToken = jwt.sign(
      { userId: user.id, purpose: 'password_reset', stateHash: 'wrong-hash' },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        token: staleToken,
        email: user.email,
        newAuthHash: 'new-hash',
        newEncryptedVaultKey: 'new-key',
        newVaultKeyIv: 'new-iv',
        newVaultKeyTag: 'new-tag',
      });

    expect(res.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Vault controller — restore from trash, sorting, filtering edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Vault controller additional paths', () => {
  // NOTE: a former "lists items filtered by tag" test lived here. It only
  // asserted `status === 200`, and there is NO tag filter in `listItems` nor a
  // `tag` param in `listVaultItemsSchema` (the query key is stripped by Zod),
  // so it could never fail regardless of what the endpoint returned. It was
  // removed rather than left as false coverage for a feature that does not
  // exist.

  it('lists items sorted by createdAt ascending and descending', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Create three items with distinguishable, strictly increasing createdAt so
    // the sort order is observable (not a zero-item vault where any sort passes).
    const createdIds: string[] = [];
    for (let i = 0; i < 3; i++) {
      const createRes = await request(app)
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf)
        .set('Cookie', cookie)
        .send(sampleVaultItem({ encryptedName: `item-${String(i)}` }));
      expect(createRes.status).toBe(201);
      createdIds.push(createRes.body.data._id as string);
      // Space out createdAt so ordering is deterministic. `timestamps: false`
      // stops Mongoose from re-stamping updatedAt/createdAt on this write.
      await VaultItem.updateOne(
        { _id: createdIds[i]! },
        { $set: { createdAt: new Date(Date.now() + i * 1000) } },
        { timestamps: false },
      );
    }

    const ascRes = await request(app)
      .get('/api/v1/vault/items?sortBy=createdAt&sortOrder=asc')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(ascRes.status).toBe(200);
    const ascIds = (ascRes.body.data as { _id: string }[]).map((r) => r._id);
    expect(ascIds).toEqual(createdIds);

    const descRes = await request(app)
      .get('/api/v1/vault/items?sortBy=createdAt&sortOrder=desc')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(descRes.status).toBe(200);
    const descIds = (descRes.body.data as { _id: string }[]).map((r) => r._id);
    expect(descIds).toEqual([...createdIds].reverse());
  });

  it('lists trash items', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Create and soft-delete an item
    const createRes = await request(app)
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send(sampleVaultItem());

    const itemId = createRes.body.data._id as string;

    await request(app)
      .delete(`/api/v1/vault/items/${itemId}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    const res = await request(app)
      .get('/api/v1/vault/items/trash')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Folder controller — edge cases
// ═══════════════════════════════════════════════════════════════════════

describe('Folder controller edge cases', () => {
  it('returns 404 when updating non-existent folder', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();
    const fakeId = new mongoose.Types.ObjectId().toString();

    const res = await request(app)
      .put(`/api/v1/folders/${fakeId}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({
        encryptedName: 'updated-name',
        nameIv: 'new-iv',
        nameTag: 'new-tag',
      });

    expect(res.status).toBe(404);
  });

  it('returns 404 when deleting non-existent folder', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();
    const fakeId = new mongoose.Types.ObjectId().toString();

    const res = await request(app)
      .delete(`/api/v1/folders/${fakeId}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Backup restore — conflict strategies
// ═══════════════════════════════════════════════════════════════════════

describe('Backup restore conflict strategies', () => {
  it('restores with keep_both strategy creating new folders and items', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    // Set up backup
    await User.findByIdAndUpdate(user.id, {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'bwk',
        'settings.backup.bwkIv': 'iv',
        'settings.backup.bwkTag': 'tag',
        'settings.backup.bwkSalt': 'salt',
      },
    });

    // Create existing folder and item
    const { Folder } = await import('../src/models/Folder.js');
    const folder = await Folder.create({
      userId: user.id,
      encryptedName: 'folder-1',
      nameIv: 'fiv',
      nameTag: 'ftag',
    });

    const item = await VaultItem.create({
      userId: user.id,
      itemType: 'login',
      encryptedData: 'existing-data',
      dataIv: 'div',
      dataTag: 'dtag',
      encryptedName: 'existing-name',
      nameIv: 'niv',
      nameTag: 'ntag',
    });

    // Create backup data that conflicts with existing
    const backupData = JSON.stringify({
      items: [
        {
          _id: item._id.toString(),
          itemType: 'login',
          encryptedData: 'backup-data',
          dataIv: 'bdiv',
          dataTag: 'bdtag',
          encryptedName: 'backup-name',
          nameIv: 'bniv',
          nameTag: 'bntag',
          folderId: folder._id.toString(),
        },
      ],
      folders: [
        {
          _id: folder._id.toString(),
          encryptedName: 'backup-folder',
          nameIv: 'bfiv',
          nameTag: 'bftag',
        },
      ],
    });

    const res = await request(app)
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ data: backupData, conflictStrategy: 'keep_both' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.itemsRestored).toBe(1);

    // Both original and new items/folders should exist
    const allFolders = await Folder.find({ userId: user.id }).lean();
    expect(allFolders.length).toBe(2); // original + new

    const allItems = await VaultItem.find({ userId: user.id }).lean();
    expect(allItems.length).toBe(2); // original + new
  });

  it('restores with overwrite strategy', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    await User.findByIdAndUpdate(user.id, {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'bwk',
        'settings.backup.bwkIv': 'iv',
        'settings.backup.bwkTag': 'tag',
        'settings.backup.bwkSalt': 'salt',
      },
    });

    const item = await VaultItem.create({
      userId: user.id,
      itemType: 'login',
      encryptedData: 'old-data',
      dataIv: 'div',
      dataTag: 'dtag',
      encryptedName: 'old-name',
      nameIv: 'niv',
      nameTag: 'ntag',
    });

    const backupData = JSON.stringify({
      items: [
        {
          _id: item._id.toString(),
          itemType: 'login',
          encryptedData: 'overwritten-data',
          dataIv: 'new-div',
          dataTag: 'new-dtag',
          encryptedName: 'overwritten-name',
          nameIv: 'new-niv',
          nameTag: 'new-ntag',
        },
      ],
    });

    const res = await request(app)
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ data: backupData, conflictStrategy: 'overwrite' });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(0);

    // Verify data was overwritten
    const updated = await VaultItem.findById(item._id).lean();
    expect(updated!.encryptedData).toBe('overwritten-data');
  });
});

describe('Import folder ownership validation', () => {
  it('strips folderId that does not belong to the user', async () => {
    const user = await createTestUser();
    const { token: csrf, cookie } = await getCsrf();

    const importData = JSON.stringify({
      items: [
        {
          itemType: 'login',
          encryptedData: 'enc-data',
          dataIv: 'div',
          dataTag: 'dtag',
          encryptedName: 'enc-name',
          nameIv: 'niv',
          nameTag: 'ntag',
          folderId: new mongoose.Types.ObjectId().toString(), // non-existent folder
        },
      ],
    });

    const res = await request(app)
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf)
      .set('Cookie', cookie)
      .send({ format: 'json', data: importData });

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(1);

    // Verify the item was created without folderId
    const items = await VaultItem.find({ userId: user.id }).lean();
    expect(items).toHaveLength(1);
    expect(items[0]!.folderId).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Audit service: userAgent truncation
// ---------------------------------------------------------------------------
describe('AuditLog userAgent truncation', () => {
  it('should truncate userAgent longer than 512 characters', async () => {
    const { createAuditLog } = await import('../src/services/auditService.js');
    const longUserAgent = 'A'.repeat(1024);
    await createAuditLog(
      '000000000000000000000000',
      'login',
      undefined,
      '127.0.0.1',
      longUserAgent,
    );

    const logs = await AuditLog.find({ ipAddress: '127.0.0.1' }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userAgent).toHaveLength(512);
    expect(logs[0]!.userAgent).toBe('A'.repeat(512));
  });

  it('should keep userAgent as-is when within 512 chars', async () => {
    const { createAuditLog } = await import('../src/services/auditService.js');
    const normalAgent = 'Mozilla/5.0 (Test)';
    await createAuditLog('000000000000000000000000', 'login', undefined, '10.0.0.1', normalAgent);

    const logs = await AuditLog.find({ ipAddress: '10.0.0.1' }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userAgent).toBe(normalAgent);
  });
});

// ---------------------------------------------------------------------------
// AuditLog model: maxlength on userAgent field
// ---------------------------------------------------------------------------
describe('AuditLog model userAgent maxlength', () => {
  it('should have maxlength 512 on userAgent field', () => {
    const schema = AuditLog.schema;
    const userAgentPath = schema.path('userAgent') as mongoose.SchemaType & {
      options?: { maxlength?: number };
    };
    expect(userAgentPath.options?.maxlength).toBe(512);
  });
});
