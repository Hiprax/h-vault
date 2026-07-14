/**
 * Tests for security fixes:
 * - Task 2.11: Import deduplication with encryptedName fallback after vault key rotation
 * - Task 2.12: Folder parentId remapping during keep_both restore
 * - Task 3.1: Purpose-specific JWT signing keys (derivePurposeKey)
 * - Task 3.2: Reduced TOTP validation window (1 instead of 3)
 * - Task 3.3: TOTP replay protection (lastTotpTimestamp)
 * - Task 8: Backup code constant-time comparison
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { Types } from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { Folder } from '../src/models/Folder.js';
import { derivePurposeKey } from '../src/utils/token.js';
import { findMatchingBackupCodeIndex } from '../src/controllers/authController.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf as getCsrfBase,
  JWT_PURPOSE_SECRET,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(
  agent: request.SuperTest<request.Test>,
  extraCookies?: string,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent, extraCookies);
  return { csrfToken: token, csrfCookie: cookie };
}

// =====================================================================
// Task 2.11: Import deduplication with encryptedName fallback
// =====================================================================

describe('Task 2.11: Import deduplication after vault key rotation', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should detect duplicates by encryptedName when searchHash differs (post-rotation)', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Create an existing item with searchHash-A (valid 64-char hex)
    const items = [
      sampleVaultItem({ encryptedName: 'same-encrypted-name', searchHash: 'a'.repeat(64) }),
    ];
    await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ format: 'json', data: JSON.stringify({ items }) });

    // Import same item with different searchHash (simulating post-rotation) but same encryptedName
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const rotatedItems = [
      sampleVaultItem({ encryptedName: 'same-encrypted-name', searchHash: 'b'.repeat(64) }),
    ];
    const res = await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({
        format: 'json',
        data: JSON.stringify({ items: rotatedItems }),
        conflictStrategy: 'skip',
      });

    expect(res.status).toBe(201);
    expect(res.body.data.duplicateCount).toBe(1);
    expect(res.body.data.importedCount).toBe(0);
  });

  it('should overwrite by encryptedName when searchHash differs', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const items = [
      sampleVaultItem({ encryptedName: 'overwrite-target', searchHash: 'c'.repeat(64) }),
    ];
    await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ format: 'json', data: JSON.stringify({ items }) });

    // Overwrite with different searchHash but same encryptedName
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const updatedItems = [
      sampleVaultItem({
        encryptedName: 'overwrite-target',
        searchHash: 'd'.repeat(64),
        encryptedData: 'updated-data',
      }),
    ];
    const res = await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({
        format: 'json',
        data: JSON.stringify({ items: updatedItems }),
        conflictStrategy: 'overwrite',
      });

    expect(res.status).toBe(201);
    expect(res.body.data.overwrittenCount).toBe(1);
  });

  it('should still match by searchHash when both hash and name match', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const hash = 'e'.repeat(64);
    const items = [sampleVaultItem({ encryptedName: 'hash-match', searchHash: hash })];
    await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ format: 'json', data: JSON.stringify({ items }) });

    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ format: 'json', data: JSON.stringify({ items }), conflictStrategy: 'skip' });

    expect(res.status).toBe(201);
    expect(res.body.data.duplicateCount).toBe(1);
  });

  it('should import unique items when neither hash nor name matches', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const items = [sampleVaultItem({ encryptedName: 'existing-item', searchHash: 'f'.repeat(64) })];
    await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ format: 'json', data: JSON.stringify({ items }) });

    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const newItems = [
      sampleVaultItem({ encryptedName: 'completely-new-item', searchHash: '0'.repeat(64) }),
    ];
    const res = await agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({
        format: 'json',
        data: JSON.stringify({ items: newItems }),
        conflictStrategy: 'skip',
      });

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(1);
    expect(res.body.data.duplicateCount).toBe(0);
  });
});

// =====================================================================
// Task 2.12: Folder parentId remapping during keep_both restore
// =====================================================================

describe('Task 2.12: Folder parentId remapping during keep_both restore', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should remap parentId for newly created folders during keep_both', async () => {
    const parentFolderId = new Types.ObjectId().toString();
    const childFolderId = new Types.ObjectId().toString();

    // First, create existing folders with those IDs
    const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
    const initialData = JSON.stringify({
      items: [],
      folders: [
        { _id: parentFolderId, ...sampleFolder({ encryptedName: 'parent-folder' }) },
        {
          _id: childFolderId,
          ...sampleFolder({ encryptedName: 'child-folder', parentId: parentFolderId }),
        },
      ],
    });

    await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1)
      .send({ conflictStrategy: 'skip', data: initialData });

    // Now restore with keep_both using the same folder IDs
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const keepBothData = JSON.stringify({
      items: [],
      folders: [
        { _id: parentFolderId, ...sampleFolder({ encryptedName: 'parent-folder-dup' }) },
        {
          _id: childFolderId,
          ...sampleFolder({ encryptedName: 'child-folder-dup', parentId: parentFolderId }),
        },
      ],
    });

    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ conflictStrategy: 'keep_both', data: keepBothData });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);

    // Verify the new child folder's parentId points to the new parent (not the old one)
    const allFolders = await Folder.find({ userId: user.id }).lean();
    expect(allFolders.length).toBe(4); // 2 originals + 2 new

    // Find the new child folder (not the original)
    const newFolders = allFolders.filter(
      (f) => String(f._id) !== parentFolderId && String(f._id) !== childFolderId,
    );
    const newParent = newFolders.find((f) => f.encryptedName === 'parent-folder-dup');
    const newChild = newFolders.find((f) => f.encryptedName === 'child-folder-dup');

    expect(newParent).toBeDefined();
    expect(newChild).toBeDefined();
    // The new child's parentId should point to the new parent, not the original
    expect(String(newChild!.parentId)).toBe(String(newParent!._id));
  });

  it('should handle keep_both when only child folder has conflict', async () => {
    const parentFolderId = new Types.ObjectId().toString();
    const childFolderId = new Types.ObjectId().toString();

    // Create only the child folder initially
    const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
    const initialData = JSON.stringify({
      items: [],
      folders: [
        {
          _id: childFolderId,
          ...sampleFolder({ encryptedName: 'child-only', parentId: parentFolderId }),
        },
      ],
    });

    await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1)
      .send({ conflictStrategy: 'skip', data: initialData });

    // Now restore with keep_both with a child that conflicts and references a new parent
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const keepBothData = JSON.stringify({
      items: [],
      folders: [
        { _id: parentFolderId, ...sampleFolder({ encryptedName: 'new-parent' }) },
        {
          _id: childFolderId,
          ...sampleFolder({ encryptedName: 'child-dup', parentId: parentFolderId }),
        },
      ],
    });

    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ conflictStrategy: 'keep_both', data: keepBothData });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);
  });
});

// =====================================================================
// Task 3.1: Purpose-specific JWT signing keys
// =====================================================================

describe('Task 3.1: Purpose-specific JWT signing keys (derivePurposeKey)', () => {
  it('should derive different keys for different purposes', () => {
    const secret = 'test-secret-12345678901234567890';
    const key1 = derivePurposeKey(secret, 'email_verification');
    const key2 = derivePurposeKey(secret, 'password_reset');
    const key3 = derivePurposeKey(secret, '2fa_temp');
    const key4 = derivePurposeKey(secret, 'account_unlock');

    // All keys should be different
    expect(key1).not.toBe(key2);
    expect(key1).not.toBe(key3);
    expect(key1).not.toBe(key4);
    expect(key2).not.toBe(key3);
    expect(key2).not.toBe(key4);
    expect(key3).not.toBe(key4);
  });

  it('should derive deterministic keys for the same purpose', () => {
    const secret = 'test-secret-12345678901234567890';
    const key1 = derivePurposeKey(secret, 'email_verification');
    const key2 = derivePurposeKey(secret, 'email_verification');
    expect(key1).toBe(key2);
  });

  it('should derive a 64-character hex string', () => {
    const key = derivePurposeKey('secret', 'purpose');
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should reject tokens signed with a different purpose key', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser({ emailVerified: false });
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Sign an email_verification token with the password_reset derived key
    const crossPurposeToken = jwt.sign(
      {
        userId: user.id,
        purpose: 'email_verification',
        stateHash: generateStateHash(String(false)),
      },
      deriveTestPurposeKey('password_reset'), // Wrong purpose key
      { algorithm: 'HS256', expiresIn: '24h' },
    );

    const res = await agent
      .post('/api/v1/auth/verify-email')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ token: crossPurposeToken });

    expect(res.status).toBe(400);
  });

  it('should reject tokens signed with the base secret instead of derived key', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser({ emailVerified: false });
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Sign with the base secret (not derived)
    const baseSecretToken = jwt.sign(
      {
        userId: user.id,
        purpose: 'email_verification',
        stateHash: generateStateHash(String(false)),
      },
      JWT_PURPOSE_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' },
    );

    const res = await agent
      .post('/api/v1/auth/verify-email')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ token: baseSecretToken });

    expect(res.status).toBe(400);
  });
});

// =====================================================================
// Task 3.2: Reduced TOTP validation window
// =====================================================================

describe('Task 3.2: Reduced TOTP validation window', () => {
  const cm = new CryptoManager();
  // Override password validation for test encryption key
  (cm as unknown as { validatePassword: (_p: string) => boolean }).validatePassword = () => true;

  const PERIOD_MS = 30_000;
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

  /**
   * Wait until the wall clock is comfortably mid-step (≥3s from either 30s
   * boundary) so that a code generated for `currentStep - k` stays exactly `k`
   * steps out when the server validates a moment later — making the window
   * boundary deterministic rather than boundary-flaky.
   */
  const alignToMidStep = async (): Promise<void> => {
    const into = Date.now() % PERIOD_MS;
    if (into < 3_000) await sleep(3_000 - into);
    else if (into > 27_000) await sleep(PERIOD_MS - into + 3_000);
  };

  /** Provision a 2FA-enabled user and return its TOTP handle + a temp token. */
  const setup2faUser = async (
    agent: request.SuperTest<request.Test>,
  ): Promise<{ totp: TOTP; tempToken: string; csrfToken: string; csrfCookie: string }> => {
    const secretObj = new Secret();
    const encryptedSecret = cm.encryptTextSync(
      secretObj.base32,
      process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
    );
    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: { twoFactorEnabled: true, twoFactorSecret: encryptedSecret },
    });
    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const tempToken = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { expiresIn: '5m' },
    );
    const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
    return { totp, tempToken, csrfToken, csrfCookie };
  };

  it('should accept a current TOTP code (window=1 allows current time step)', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const { totp, tempToken, csrfToken, csrfCookie } = await setup2faUser(agent);
    const validCode = totp.generate();

    const res = await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code: validCode });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.accessToken).toBeDefined();
  });

  it('should accept a code from one time step in the past (±1 tolerance)', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const { totp, tempToken, csrfToken, csrfCookie } = await setup2faUser(agent);

    await alignToMidStep();
    const step = Math.floor(Date.now() / PERIOD_MS);
    const oneStepAgo = totp.generate({ timestamp: (step - 1) * PERIOD_MS });

    const res = await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code: oneStepAgo });

    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();
  });

  it('should REJECT a code two time steps out (window is 1, not wider)', async () => {
    // This is the assertion that actually pins the window: widening the server's
    // `totp.validate({ window })` back to 2 (or 3, its pre-hardening value) would
    // make a ±2 code valid, turning this 401 into a 200.
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const { totp, tempToken, csrfToken, csrfCookie } = await setup2faUser(agent);

    await alignToMidStep();
    const step = Math.floor(Date.now() / PERIOD_MS);
    const twoStepsAgo = totp.generate({ timestamp: (step - 2) * PERIOD_MS });

    const res = await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code: twoStepsAgo });

    expect(res.status).toBe(401);
  });
});

// =====================================================================
// Task 3.3: TOTP replay protection
// =====================================================================

describe('Task 3.3: TOTP replay protection', () => {
  const cm = new CryptoManager();
  (cm as unknown as { validatePassword: (_p: string) => boolean }).validatePassword = () => true;

  it('should store lastTotpTimestamp after successful TOTP login', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const secretObj = new Secret();
    const secret = secretObj.base32;
    const encryptedSecret = cm.encryptTextSync(
      secret,
      process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
    );

    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: { twoFactorEnabled: true, twoFactorSecret: encryptedSecret },
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const tempToken = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { expiresIn: '5m' },
    );

    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secretObj,
    });
    const validCode = totp.generate();

    await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code: validCode });

    // Verify lastTotpTimestamp was stored
    const updatedUser = await User.findById(user.id).lean();
    expect(updatedUser!.lastTotpTimestamp).toBeDefined();
    expect(typeof updatedUser!.lastTotpTimestamp).toBe('number');
  });

  it('should reject replayed TOTP code (same time step)', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const secretObj = new Secret();
    const secret = secretObj.base32;
    const encryptedSecret = cm.encryptTextSync(
      secret,
      process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
    );

    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: { twoFactorEnabled: true, twoFactorSecret: encryptedSecret },
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const tempToken = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { expiresIn: '5m' },
    );

    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secretObj,
    });
    const code = totp.generate();

    // Simulate a TOTP that was already used by marking its OWN time step as
    // consumed. This is read AFTER generation (never before) so a 30s boundary
    // crossing between setup and the request can't leave lastTotpTimestamp one
    // step behind the generated code — which would make a genuine replay look
    // fresh and flake this assertion. Setting it to the current step guarantees
    // the code's matched step is <= lastTotpTimestamp, so the replay guard fires.
    const codeTimeStep = Math.floor(Date.now() / 1000 / 30);
    await User.findByIdAndUpdate(user.id, {
      $set: { lastTotpTimestamp: codeTimeStep },
    });

    const res = await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code });

    // Should be rejected because the code's time step <= lastTotpTimestamp
    expect(res.status).toBe(401);
  });

  it('should not update lastTotpTimestamp when backup code is used', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const secretObj = new Secret();
    const secret = secretObj.base32;
    const encryptedSecret = cm.encryptTextSync(
      secret,
      process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
    );
    const bcrypt = await import('bcryptjs');

    const user = await createTestUser();
    const backupCode = crypto.randomBytes(8).toString('hex');
    const hashedBackupCode = await bcrypt.hash(backupCode, 4);

    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        backupCodes: [hashedBackupCode],
      },
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const tempToken = jwt.sign(
      { userId: user.id, purpose: '2fa_temp' },
      deriveTestPurposeKey('2fa_temp'),
      { expiresIn: '5m' },
    );

    const res = await agent
      .post('/api/v1/auth/login/2fa')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ tempToken, code: backupCode });

    expect(res.status).toBe(200);

    // lastTotpTimestamp should NOT be set when backup code was used
    const updatedUser = await User.findById(user.id).lean();
    expect(updatedUser!.lastTotpTimestamp).toBeUndefined();
  });

  // Removed: 'should have lastTotpTimestamp field on User model' wrote 12345 with
  // findByIdAndUpdate and read it straight back — a pure Mongoose round-trip with
  // no production code between write and read. The field's existence AND its
  // production-driven write are already proven by 'should store lastTotpTimestamp
  // after successful TOTP login' (a real 2FA login sets it) and the replay tests
  // above, so the deleted test added runtime with no regression signal.
});

// =====================================================================
// Task 3.3b: TOTP replay protection for disable2fa, verify2fa, regenerateBackupCodes
// =====================================================================

describe('Task 3.3b: TOTP replay protection in userController', () => {
  const cm = new CryptoManager();
  (cm as unknown as { validatePassword: (_p: string) => boolean }).validatePassword = () => true;
  const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

  // ── disable2fa ──────────────────────────────────────────────────────

  describe('disable2fa replay protection', () => {
    it('should reject replayed TOTP code when disabling 2FA', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1'],
        },
      });

      // Simulate a TOTP that was already used by setting lastTotpTimestamp to current time step
      const currentTimeStep = Math.floor(Date.now() / 1000 / 30);
      await User.findByIdAndUpdate(user.id, {
        $set: { lastTotpTimestamp: currentTimeStep },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code, password: user.rawPassword });

      // Should be rejected because the code's time step <= lastTotpTimestamp
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should clear lastTotpTimestamp when 2FA is disabled', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1'],
          lastTotpTimestamp: 1000, // Old timestamp that won't conflict
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code, password: user.rawPassword });

      expect(res.status).toBe(200);

      // lastTotpTimestamp should be cleared when 2FA is disabled
      const updatedUser = await User.findById(user.id).lean();
      expect(updatedUser!.twoFactorEnabled).toBe(false);
      expect(updatedUser!.lastTotpTimestamp).toBeUndefined();
    });
  });

  // ── verify2fa ──────────────────────────────────────────────────────

  describe('verify2fa replay protection', () => {
    it('should reject replayed TOTP code when verifying 2FA setup', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedPendingSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          pendingTwoFactorSecret: encryptedPendingSecret,
          pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
        },
      });

      // Simulate a TOTP that was already used by setting lastTotpTimestamp to current time step
      const currentTimeStep = Math.floor(Date.now() / 1000 / 30);
      await User.findByIdAndUpdate(user.id, {
        $set: { lastTotpTimestamp: currentTimeStep },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code });

      // Should be rejected because the code's time step <= lastTotpTimestamp
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should store lastTotpTimestamp after successful 2FA verification', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedPendingSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          pendingTwoFactorSecret: encryptedPendingSecret,
          pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code });

      expect(res.status).toBe(200);

      // lastTotpTimestamp should be stored after successful verification
      const updatedUser = await User.findById(user.id).lean();
      expect(updatedUser!.lastTotpTimestamp).toBeDefined();
      expect(typeof updatedUser!.lastTotpTimestamp).toBe('number');
    });
  });

  // ── regenerateBackupCodes ──────────────────────────────────────────

  describe('regenerateBackupCodes replay protection', () => {
    it('should reject replayed TOTP code when regenerating backup codes', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1'],
        },
      });

      // Simulate a TOTP that was already used by setting lastTotpTimestamp to current time step
      const currentTimeStep = Math.floor(Date.now() / 1000 / 30);
      await User.findByIdAndUpdate(user.id, {
        $set: { lastTotpTimestamp: currentTimeStep },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/user/2fa/regenerate-backup-codes')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code, password: user.rawPassword });

      // Should be rejected because the code's time step <= lastTotpTimestamp
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should update lastTotpTimestamp after successful backup code regeneration', async () => {
      const agent = request(app) as unknown as request.SuperTest<request.Test>;
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(secret, encKey);

      const user = await createTestUser();
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1'],
          lastTotpTimestamp: 1000, // Old timestamp that won't conflict
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/user/2fa/regenerate-backup-codes')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code, password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.data.backupCodes).toBeDefined();

      // lastTotpTimestamp should be updated after successful regeneration
      const updatedUser = await User.findById(user.id).lean();
      expect(updatedUser!.lastTotpTimestamp).toBeDefined();
      expect(typeof updatedUser!.lastTotpTimestamp).toBe('number');
      // Should be a recent time step (not the old value of 1000)
      const currentTimeStep = Math.floor(Date.now() / 1000 / 30);
      expect(updatedUser!.lastTotpTimestamp).toBeGreaterThan(1000);
      expect(updatedUser!.lastTotpTimestamp).toBeLessThanOrEqual(currentTimeStep + 1);
    });
  });
});

// =====================================================================
// Task 8: Backup code constant-time comparison
// =====================================================================

describe('Task 8: findMatchingBackupCodeIndex constant-time comparison', () => {
  const LOW_ROUNDS = 4; // Use low bcrypt rounds for fast tests

  it('returns the correct index for a matching backup code', async () => {
    const rawCode = 'abcdef1234567890';
    const hashed = await bcrypt.hash(rawCode, LOW_ROUNDS);
    const hashedCodes = [
      await bcrypt.hash('othercode0000001', LOW_ROUNDS),
      hashed,
      await bcrypt.hash('othercode0000002', LOW_ROUNDS),
    ];
    const result = await findMatchingBackupCodeIndex(rawCode, hashedCodes);
    expect(result).toBe(1);
  });

  it('returns -1 for an invalid backup code', async () => {
    const hashedCodes = [
      await bcrypt.hash('code0000000000aa', LOW_ROUNDS),
      await bcrypt.hash('code0000000000bb', LOW_ROUNDS),
    ];
    const result = await findMatchingBackupCodeIndex('wrongcode0000000', hashedCodes);
    expect(result).toBe(-1);
  });

  it('returns -1 for an empty codes array', async () => {
    const result = await findMatchingBackupCodeIndex('anycode000000000', []);
    expect(result).toBe(-1);
  });

  it('returns the last matching index when duplicates exist', async () => {
    // Constant-time iteration means it always processes all entries;
    // if the same code appears more than once the last match wins.
    const rawCode = 'duplicatecode001';
    const hashed1 = await bcrypt.hash(rawCode, LOW_ROUNDS);
    const hashed2 = await bcrypt.hash(rawCode, LOW_ROUNDS);
    const hashedCodes = [hashed1, await bcrypt.hash('other00000000000', LOW_ROUNDS), hashed2];
    const result = await findMatchingBackupCodeIndex(rawCode, hashedCodes);
    // Because the function iterates all codes without short-circuiting,
    // the last match at index 2 overwrites the earlier one at index 0.
    expect(result).toBe(2);
  });

  it('handles a single code array correctly', async () => {
    const rawCode = 'singlecode000001';
    const hashed = await bcrypt.hash(rawCode, LOW_ROUNDS);
    const result = await findMatchingBackupCodeIndex(rawCode, [hashed]);
    expect(result).toBe(0);
  });
});

// =====================================================================
// Task: TOTP replay protection for deleteAccount
// =====================================================================

describe('TOTP replay protection for deleteAccount', () => {
  const cm = new CryptoManager();
  (cm as unknown as { validatePassword: (_p: string) => boolean }).validatePassword = () => true;
  const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

  it('should reject replayed TOTP code on deleteAccount', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const secretObj = new Secret();
    const secret = secretObj.base32;
    const encryptedSecret = cm.encryptTextSync(secret, encKey);

    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        backupCodes: ['hashed-code-1'],
      },
    });

    // Simulate a TOTP that was already used by setting lastTotpTimestamp to current time step
    const currentTimeStep = Math.floor(Date.now() / 1000 / 30);
    await User.findByIdAndUpdate(user.id, {
      $set: { lastTotpTimestamp: currentTimeStep },
    });

    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(secret),
    });
    const code = totp.generate();

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const res = await agent
      .delete('/api/v1/user')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ password: user.rawPassword, code });

    // Should be rejected because the code's time step <= lastTotpTimestamp
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);

    // User should still exist (account not deleted)
    const dbUser = await User.findById(user.id);
    expect(dbUser).not.toBeNull();
  });

  it('should allow deleteAccount with a fresh TOTP code', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const secretObj = new Secret();
    const secret = secretObj.base32;
    const encryptedSecret = cm.encryptTextSync(secret, encKey);

    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: {
        twoFactorEnabled: true,
        twoFactorSecret: encryptedSecret,
        backupCodes: ['hashed-code-1'],
        lastTotpTimestamp: 1000, // Old timestamp that won't conflict
      },
    });

    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(secret),
    });
    const code = totp.generate();

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const res = await agent
      .delete('/api/v1/user')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ password: user.rawPassword, code });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // User should be deleted
    const dbUser = await User.findById(user.id);
    expect(dbUser).toBeNull();
  });
});

// =====================================================================
// Task: Timing equalization for forgotPassword and resendVerification
// =====================================================================

describe('Timing equalization for forgotPassword and resendVerification', () => {
  it('forgotPassword should return same structure for existing and non-existing emails', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();
    const { csrfToken: csrfToken1, csrfCookie: csrfCookie1 } = await getCsrf(agent);

    const existingRes = await agent
      .post('/api/v1/auth/forgot-password')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email: user.email });

    const { csrfToken: csrfToken2, csrfCookie: csrfCookie2 } = await getCsrf(agent);

    const nonExistentRes = await agent
      .post('/api/v1/auth/forgot-password')
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', csrfCookie2)
      .send({ email: 'nonexistent-timing@example.com' });

    // Both should return success with the same generic message
    expect(existingRes.status).toBe(200);
    expect(nonExistentRes.status).toBe(200);
    expect(existingRes.body.success).toBe(true);
    expect(nonExistentRes.body.success).toBe(true);
    expect(existingRes.body.message).toBe(nonExistentRes.body.message);
  });

  it('resendVerification should return same structure for non-existing and verified emails', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    // Create a verified user (the early-return path for already-verified users)
    const user = await createTestUser({ emailVerified: true });
    const { csrfToken: csrfToken1, csrfCookie: csrfCookie1 } = await getCsrf(agent);

    const verifiedRes = await agent
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1)
      .send({ email: user.email });

    const { csrfToken: csrfToken2, csrfCookie: csrfCookie2 } = await getCsrf(agent);

    const nonExistentRes = await agent
      .post('/api/v1/auth/resend-verification')
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', csrfCookie2)
      .send({ email: 'nonexistent-timing-resend@example.com' });

    // Both should return success with the same generic message
    expect(verifiedRes.status).toBe(200);
    expect(nonExistentRes.status).toBe(200);
    expect(verifiedRes.body.success).toBe(true);
    expect(nonExistentRes.body.success).toBe(true);
    expect(verifiedRes.body.message).toBe(nonExistentRes.body.message);
  });
});

// =====================================================================
// Task: Folder field allowlist defense-in-depth
// =====================================================================

describe('Folder field allowlist defense-in-depth', () => {
  // NOTE: the earlier tests here sent ONLY schema-valid fields (`sampleFolder()`
  // / encryptedName+icon) and asserted a normal create/update worked — so the
  // injection property they were named for was never exercised. These send
  // SERVER-ONLY fields in the body (userId → an IDOR attempt, sourceRefId, _id,
  // favorite, createdAt) and assert none of them reach the persisted document.
  // This guards the whole request stack end to end (the createFolderSchema's
  // strip mode + the controller's `pickAllowedFields`). The allowlist filter
  // itself is unit-tested in controller-helpers.test.ts.
  it('should not persist client-supplied server-only fields on folder create', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const foreignUserId = new Types.ObjectId().toString();
    const foreignId = new Types.ObjectId().toString();

    const res = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        ...sampleFolder(),
        userId: foreignUserId, // IDOR attempt — ownership must come from the JWT
        sourceRefId: 'injected-provenance',
        _id: foreignId,
        favorite: true,
        createdAt: '2000-01-01T00:00:00.000Z',
      });

    expect(res.status).toBe(201);
    const folderId = res.body.data._id as string;

    const folder = await Folder.findById(folderId).lean();
    expect(folder).not.toBeNull();
    expect(folder!.encryptedName).toBe('test-encrypted-folder-name');
    // Ownership derives from the JWT, never the request body.
    expect(folder!.userId.toString()).toBe(user.id);
    expect(folder!.userId.toString()).not.toBe(foreignUserId);
    // Server-only provenance is never client-settable.
    expect(folder!.sourceRefId).toBeUndefined();
    // The _id is server-minted, not adopted from the body.
    expect(folderId).not.toBe(foreignId);
  });

  it('should not persist client-supplied server-only fields on folder update', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();
    const { csrfToken: csrfToken1, csrfCookie: csrfCookie1 } = await getCsrf(agent);

    // Create folder first
    const createRes = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken1)
      .set('Cookie', csrfCookie1)
      .send(sampleFolder());

    expect(createRes.status).toBe(201);
    const folderId = createRes.body.data._id as string;

    const foreignUserId = new Types.ObjectId().toString();
    const { csrfToken: csrfToken2, csrfCookie: csrfCookie2 } = await getCsrf(agent);

    const updateRes = await agent
      .put(`/api/v1/folders/${folderId}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken2)
      .set('Cookie', csrfCookie2)
      .send({
        encryptedName: 'updated-name',
        nameIv: 'updated-iv',
        nameTag: 'updated-tag',
        icon: 'star',
        userId: foreignUserId, // IDOR attempt on update
        sourceRefId: 'injected-provenance',
      });

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.success).toBe(true);
    expect(updateRes.body.data.encryptedName).toBe('updated-name');
    expect(updateRes.body.data.icon).toBe('star');
    // userId is intentionally absent from API responses (server-only field).
    expect(updateRes.body.data.userId).toBeUndefined();

    // The persisted document keeps its real owner and gained no provenance field.
    const folder = await Folder.findById(folderId).lean();
    expect(folder).not.toBeNull();
    expect(folder!.userId.toString()).toBe(user.id);
    expect(folder!.userId.toString()).not.toBe(foreignUserId);
    expect(folder!.sourceRefId).toBeUndefined();
  });
});

// =====================================================================
// HIGH-8 / MISSING-1: passwordChangedAt JWT iat invalidation
// =====================================================================

describe('HIGH-8 / MISSING-1: passwordChangedAt invalidates existing JWTs', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should reject access tokens issued before password change', async () => {
    // Original accessToken from createTestUser is issued at now, passwordChangedAt
    // is set to epoch (default) for users created directly via Mongoose — so the
    // token is initially valid.
    const before = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(before.status).toBe(200);

    // Change password
    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const changeRes = await agent
      .put('/api/v1/user/change-password')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'brand-new-password-hash',
        newEncryptedVaultKey: 'new-vk',
        newVaultKeyIv: 'new-iv',
        newVaultKeyTag: 'new-tag',
      });
    expect(changeRes.status).toBe(200);

    // The original access token, issued before passwordChangedAt was updated,
    // should now be rejected by the JWT strategy.
    const after = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(after.status).toBe(401);
  });

  it('should accept access tokens issued after password change', async () => {
    // Change password
    const { csrfToken, csrfCookie } = await getCsrf(agent);
    await agent
      .put('/api/v1/user/change-password')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'new-password-hash-value',
        newEncryptedVaultKey: 'vk2',
        newVaultKeyIv: 'iv2',
        newVaultKeyTag: 'tag2',
      });

    // Wait >1s to guarantee the new JWT iat is strictly greater than passwordChangedAt
    // (JWT iat is second-precision while passwordChangedAt is millisecond-precision).
    await new Promise((r) => setTimeout(r, 1100));

    // Issue a fresh access token AFTER the password change
    const { generateAccessToken } = await import('./helpers.js');
    const freshToken = generateAccessToken(user.id);

    const res = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(freshToken));
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('should revoke refresh tokens on password change', async () => {
    const { RefreshToken } = await import('../src/models/RefreshToken.js');

    const beforeCount = await RefreshToken.countDocuments({ userId: user.id });
    expect(beforeCount).toBeGreaterThanOrEqual(1);

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    await agent
      .put('/api/v1/user/change-password')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'another-new-hash',
        newEncryptedVaultKey: 'x',
        newVaultKeyIv: 'y',
        newVaultKeyTag: 'z',
      });

    const afterCount = await RefreshToken.countDocuments({ userId: user.id });
    expect(afterCount).toBe(0);
  });

  it('should set passwordChangedAt on resetPassword', async () => {
    const { csrfToken: csrfInit, csrfCookie: cookieInit } = await getCsrf(agent);

    // Build a valid reset token (mirrors forgotPassword).
    const resetToken = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash((await User.findById(user.id).select('+authHash'))!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const beforeUser = await User.findById(user.id);
    const beforePwdAt = beforeUser!.passwordChangedAt.getTime();

    const res = await agent
      .post('/api/v1/auth/reset-password')
      .set('Cookie', cookieInit)
      .set('x-csrf-token', csrfInit)
      .send({
        token: resetToken,
        email: user.email,
        newAuthHash: 'reset-new-hash',
        newEncryptedVaultKey: 'r-vk',
        newVaultKeyIv: 'r-iv',
        newVaultKeyTag: 'r-tag',
      });

    expect(res.status).toBe(200);

    const afterUser = await User.findById(user.id);
    expect(afterUser!.passwordChangedAt.getTime()).toBeGreaterThan(beforePwdAt);
  });

  it('should set passwordChangedAt to epoch on register (no prior password change)', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const email = `pwchanged-${crypto.randomUUID()}@example.com`;

    const res = await agent
      .post('/api/v1/auth/register')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
        email,
        authHash: 'register-hash-value',
        encryptedVaultKey: 'evk',
        vaultKeyIv: 'eiv',
        vaultKeyTag: 'etag',
        kdfIterations: 600000,
        kdfAlgorithm: 'PBKDF2-SHA256',
        encryptionVersion: 1,
      });
    expect(res.status).toBe(201);

    const created = await User.findOne({ email });
    expect(created).not.toBeNull();
    // New users have no password "change" — defaults to epoch so that
    // JWTs issued immediately after registration are always valid.
    expect(created!.passwordChangedAt.getTime()).toBe(0);
  });

  it('should never expose passwordChangedAt in /user/profile response', async () => {
    const res = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(res.status).toBe(200);
    expect(res.body.data.passwordChangedAt).toBeUndefined();
  });

  it('should reject old access tokens after password reset', async () => {
    // Verify the token works before reset
    const before = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(before.status).toBe(200);

    // Build a valid reset token (mirrors forgotPassword)
    const resetToken = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash((await User.findById(user.id).select('+authHash'))!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const resetRes = await agent
      .post('/api/v1/auth/reset-password')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
        token: resetToken,
        email: user.email,
        newAuthHash: 'reset-new-auth-hash',
        newEncryptedVaultKey: 'reset-vk',
        newVaultKeyIv: 'reset-iv',
        newVaultKeyTag: 'reset-tag',
      });
    expect(resetRes.status).toBe(200);

    // The old access token should now be rejected because passwordChangedAt
    // was updated and the token's iat is earlier
    const after = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(after.status).toBe(401);
  });
});

// =====================================================================
// HIGH-9: forgotPassword / resendVerification timing equalization
// =====================================================================

describe('HIGH-9: forgotPassword/resendVerification timing equalization', () => {
  let agent: request.SuperTest<request.Test>;

  // A wall-clock threshold is worthless here: BCRYPT_ROUNDS=4 in the test env,
  // so the dummy bcrypt.compare the equalization relies on costs a few ms and
  // deleting it leaves the median diff far below any lenient (200ms) budget —
  // the test would stay green with the enumeration channel reopened. The
  // security property is STRUCTURAL: the same dummy bcrypt.compare must run on
  // the existing-account path AND the non-existent-account path so the two take
  // the same shape. Spy on it and assert exactly one dummy comparison per path.
  const DUMMY_PLAINTEXT = 'dummy-timing-equalization-value';

  const countDummyCompareCalls = (spy: ReturnType<typeof vi.spyOn>): number =>
    spy.mock.calls.filter((call) => call[0] === DUMMY_PLAINTEXT).length;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('runs the dummy bcrypt.compare once on BOTH forgotPassword paths (existing + non-existent)', async () => {
    await createTestUser({ email: 'timing-existing@example.com' });
    // spyOn preserves the real implementation (calls through), so the endpoint
    // still behaves normally; we only observe the call.
    const compareSpy = vi.spyOn(bcrypt, 'compare');

    const c1 = await getCsrf(agent);
    compareSpy.mockClear();
    const existingRes = await agent
      .post('/api/v1/auth/forgot-password')
      .set('Cookie', c1.csrfCookie)
      .set('x-csrf-token', c1.csrfToken)
      .send({ email: 'timing-existing@example.com' });
    expect(existingRes.status).toBe(200);
    expect(countDummyCompareCalls(compareSpy)).toBe(1);

    const c2 = await getCsrf(agent);
    compareSpy.mockClear();
    const missingRes = await agent
      .post('/api/v1/auth/forgot-password')
      .set('Cookie', c2.csrfCookie)
      .set('x-csrf-token', c2.csrfToken)
      .send({ email: 'timing-nonexistent-never-registered@example.com' });
    expect(missingRes.status).toBe(200);
    expect(countDummyCompareCalls(compareSpy)).toBe(1);
  });

  it('runs the dummy bcrypt.compare once on BOTH resendVerification paths (existing + non-existent)', async () => {
    await createTestUser({ email: 'rv-existing@example.com', emailVerified: false });
    const compareSpy = vi.spyOn(bcrypt, 'compare');

    const c1 = await getCsrf(agent);
    compareSpy.mockClear();
    const existingRes = await agent
      .post('/api/v1/auth/resend-verification')
      .set('Cookie', c1.csrfCookie)
      .set('x-csrf-token', c1.csrfToken)
      .send({ email: 'rv-existing@example.com' });
    expect(existingRes.status).toBe(200);
    expect(countDummyCompareCalls(compareSpy)).toBe(1);

    const c2 = await getCsrf(agent);
    compareSpy.mockClear();
    const missingRes = await agent
      .post('/api/v1/auth/resend-verification')
      .set('Cookie', c2.csrfCookie)
      .set('x-csrf-token', c2.csrfToken)
      .send({ email: 'rv-nobody-here@example.com' });
    expect(missingRes.status).toBe(200);
    expect(countDummyCompareCalls(compareSpy)).toBe(1);
  });
});

// =====================================================================
// HIGH-5: Refresh token rotation race handled under transaction
// =====================================================================

describe('HIGH-5: Refresh token rotation race handled correctly', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should issue new refresh token atomically with the mark-used operation', async () => {
    const { RefreshToken } = await import('../src/models/RefreshToken.js');
    const { hashToken } = await import('../src/utils/token.js');
    const originalHash = hashToken(user.refreshToken);

    const originalToken = await RefreshToken.findOne({ tokenHash: originalHash });
    expect(originalToken).not.toBeNull();
    const familyId = originalToken!.familyId;

    // Ensure only 1 token exists before refresh
    expect(await RefreshToken.countDocuments({ familyId })).toBe(1);

    const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const res = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrf.csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', csrf.csrfToken);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.accessToken).toBeDefined();

    // After successful refresh: original marked used AND a new token exists.
    // These must both be true for the invariant to hold.
    const afterOriginal = await RefreshToken.findOne({ tokenHash: originalHash });
    expect(afterOriginal!.usedAt).not.toBeNull();

    const familyCount = await RefreshToken.countDocuments({ familyId });
    expect(familyCount).toBe(2); // original (used) + new
  });

  it('should still detect reuse when the original token is reused after claim', async () => {
    const { RefreshToken } = await import('../src/models/RefreshToken.js');
    const { hashToken } = await import('../src/utils/token.js');
    const originalHash = hashToken(user.refreshToken);
    const familyId = (await RefreshToken.findOne({ tokenHash: originalHash }))!.familyId;

    // First use — legitimate
    const c1 = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const r1 = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${c1.csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', c1.csrfToken);
    expect(r1.status).toBe(200);

    // Second use — reuse attack
    const c2 = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
    const r2 = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${c2.csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', c2.csrfToken);
    expect(r2.status).toBe(401);
    expect(r2.body.message).toBe('TOKEN_REUSE_DETECTED');

    // Entire family revoked
    expect(await RefreshToken.countDocuments({ familyId })).toBe(0);
  });
});
