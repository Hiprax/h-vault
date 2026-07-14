/**
 * Tests for medium-priority fixes (Batch 6):
 *
 * - MEDIUM-1: trustedDevices field removed from User model
 * - MEDIUM-2: All audit log creation routes through createAuditLog() with truncation
 * - MEDIUM-3: Lockout email sent only once (on exact threshold crossing)
 * - MEDIUM-9: Sequential rotation fallback cleans up rotationInProgress on error
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { Types } from 'mongoose';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { createAuditLog } from '../src/services/auditService.js';
import { createTestUser, getCsrf } from './helpers.js';
import type { TestUser, CsrfPair } from './helpers.js';

const API = '/api/v1';

function withCsrf(req: request.Test, csrf: CsrfPair, accessToken?: string): request.Test {
  let r = req.set('x-csrf-token', csrf.token).set('Cookie', csrf.cookie);
  if (accessToken) {
    r = r.set('Authorization', `Bearer ${accessToken}`);
  }
  return r;
}

// ---------------------------------------------------------------------------
// MEDIUM-1: trustedDevices removed from User model
// ---------------------------------------------------------------------------
describe('MEDIUM-1: trustedDevices field removed', () => {
  it('should create a user without trustedDevices in settings', async () => {
    const user = await createTestUser();
    const dbUser = await User.findById(user.id).lean();
    expect(dbUser).toBeDefined();
    // trustedDevices should not be present in settings
    expect((dbUser!.settings as Record<string, unknown>)['trustedDevices']).toBeUndefined();
  });

  it('should return profile without trustedDevices in settings', async () => {
    const agent = request.agent(app);
    const user = await createTestUser();
    const csrf = await getCsrf(agent);

    const res = await withCsrf(agent.get(`${API}/user/profile`), csrf, user.accessToken);

    expect(res.status).toBe(200);
    expect(res.body.data.settings.trustedDevices).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// MEDIUM-2: createAuditLog truncates userAgent and accepts null userId
// ---------------------------------------------------------------------------
describe('MEDIUM-2: audit log creation via createAuditLog()', () => {
  it('should truncate userAgent to 512 characters', async () => {
    const fakeObjectId = new Types.ObjectId().toString();
    const longUserAgent = 'A'.repeat(600);
    await createAuditLog(fakeObjectId, 'login', undefined, '127.0.0.1', longUserAgent);

    const logs = await AuditLog.find({ action: 'login' });
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userAgent).toHaveLength(512);
  });

  it('should accept null userId for system-level audit logs', async () => {
    await createAuditLog(null, 'deletion_cleanup', { reason: 'test' }, 'system', 'test-agent');

    const logs = await AuditLog.find({ action: 'deletion_cleanup' });
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userId).toBeNull();
    expect(logs[0]!.metadata).toEqual({ reason: 'test' });
  });

  it('should preserve userAgent that is exactly 512 characters', async () => {
    const fakeObjectId = new Types.ObjectId().toString();
    const exactAgent = 'B'.repeat(512);
    await createAuditLog(fakeObjectId, 'login', undefined, '127.0.0.1', exactAgent);

    const logs = await AuditLog.find({ action: 'login' });
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userAgent).toHaveLength(512);
  });

  it('account deletion should create audit log via createAuditLog with truncation', async () => {
    const agent = request.agent(app);
    const user = await createTestUser();
    const csrf = await getCsrf(agent);

    const longUA = 'X'.repeat(600);
    const res = await withCsrf(
      agent.delete(`${API}/user`).send({ password: user.rawPassword }).set('User-Agent', longUA),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(200);

    // The system-scoped account_delete audit log should have truncated userAgent
    const logs = await AuditLog.find({ action: 'account_delete' });
    expect(logs).toHaveLength(1);
    expect(logs[0]!.userAgent.length).toBeLessThanOrEqual(512);
  });
});

// ---------------------------------------------------------------------------
// MEDIUM-3: Lockout email sent only on exact threshold
// ---------------------------------------------------------------------------
describe('MEDIUM-3: atomic lockout email deduplication', () => {
  let agent: request.Agent;
  let testUser: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    testUser = await createTestUser();
  });

  it('should set lockoutUntil when failedLoginAttempts reaches MAX_FAILED_ATTEMPTS', async () => {
    // Send 10 failed attempts
    for (let i = 0; i < 10; i++) {
      const csrfN = await getCsrf(agent);
      await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: 'wrong-password',
        }),
        csrfN,
      );
    }

    const user = await User.findOne({ email: testUser.email });
    expect(user!.failedLoginAttempts).toBe(10);
    expect(user!.lockoutUntil).toBeDefined();
  }, 60_000);

  it('should not mutate lockout state when a wrong password is tried on a locked account', async () => {
    // Pre-set failedLoginAttempts to exactly MAX (10) with existing lockout
    // This simulates that lockout was already triggered at the threshold
    const existingLockout = new Date(Date.now() + 30 * 60 * 1000);
    await User.updateOne(
      { email: testUser.email },
      { $set: { failedLoginAttempts: 10, lockoutUntil: existingLockout } },
    );

    // A wrong password on a locked account returns the SAME generic 401 as a
    // non-existent email (the lockout is no longer surfaced as ACCOUNT_LOCKED
    // unless the correct password is supplied — closing the enumeration oracle).
    const csrfN = await getCsrf(agent);
    const res = await withCsrf(
      agent.post(`${API}/auth/login`).send({
        email: testUser.email,
        authHash: 'wrong-password',
      }),
      csrfN,
    );

    expect(res.status).toBe(401);

    // Lockout state must remain untouched: failedLoginAttempts is NOT
    // incremented and lockoutUntil is unchanged, so an unlock email already
    // issued (its token bound to lockoutUntil) stays valid.
    const user = await User.findOne({ email: testUser.email });
    expect(user!.failedLoginAttempts).toBe(10);
    expect(user!.lockoutUntil).toBeDefined();
    expect(user!.lockoutUntil!.getTime()).toBe(existingLockout.getTime());
  });
});

// ---------------------------------------------------------------------------
// MEDIUM-9: Sequential rotation fallback cleanup on error
// ---------------------------------------------------------------------------
describe('MEDIUM-9: rotation fallback cleanup', () => {
  it('should have rotationInProgress:false after user creation', async () => {
    const user = await createTestUser();
    const dbUser = await User.findById(user.id);
    expect(dbUser!.rotationInProgress).toBe(false);
    expect(dbUser!.pendingEncryptedVaultKey).toBeUndefined();
  });

  it('should clear rotationInProgress during login recovery', async () => {
    const testUser = await createTestUser();

    // Simulate an interrupted rotation
    await User.updateOne(
      { _id: testUser.id },
      {
        $set: {
          rotationInProgress: true,
          pendingEncryptedVaultKey: 'pending-key',
          pendingVaultKeyIv: 'pending-iv',
          pendingVaultKeyTag: 'pending-tag',
        },
      },
    );

    // Login should detect and recover
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await withCsrf(
      agent.post(`${API}/auth/login`).send({
        email: testUser.email,
        authHash: testUser.rawPassword,
        deviceInfo: {
          userAgent: 'test',
          ip: '127.0.0.1',
          fingerprint: 'test-fp',
        },
      }),
      csrf,
    );

    expect(res.status).toBe(200);

    // Verify rotation state was cleaned up
    const dbUser = await User.findById(testUser.id);
    expect(dbUser!.rotationInProgress).toBe(false);
    expect(dbUser!.pendingEncryptedVaultKey).toBeUndefined();

    // Verify audit log for rotation recovery
    const recoveryLogs = await AuditLog.find({ action: 'rotation_recovery' });
    expect(recoveryLogs.length).toBeGreaterThanOrEqual(1);
  });
});
