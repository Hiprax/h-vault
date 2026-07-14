import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  deriveTestPurposeKey,
  generateStateHash,
  type CsrfPair,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function registrationBody(overrides: Record<string, unknown> = {}) {
  return {
    email: `audit-test-${Date.now()}@example.com`,
    authHash: 'my-auth-hash-value',
    encryptedVaultKey: 'enc-vault-key',
    vaultKeyIv: 'vault-iv',
    vaultKeyTag: 'vault-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    ...overrides,
  };
}

// ===========================================================================
// Tests
// ===========================================================================

describe('Audit Logging', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  // ── Task 3.1: settings_update audit log ─────────────────────────────

  describe('settings_update', () => {
    let user: TestUser;

    beforeEach(async () => {
      user = await createTestUser();
    });

    it('should create a settings_update audit log when settings are changed', async () => {
      const res = await agent
        .put(`${API}/user/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ theme: 'dark', autoLockTimeout: 10 });

      expect(res.status).toBe(200);

      const log = await AuditLog.findOne({ userId: user.id, action: 'settings_update' }).lean();
      expect(log).not.toBeNull();
      expect(log!.action).toBe('settings_update');
      expect(log!.metadata).toBeDefined();
      expect((log!.metadata as { changedKeys: string[] }).changedKeys).toEqual(
        expect.arrayContaining(['theme', 'autoLockTimeout']),
      );
    });

    it('should include only changed setting keys in metadata', async () => {
      const res = await agent
        .put(`${API}/user/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ clipboardClearTimeout: 15 });

      expect(res.status).toBe(200);

      const log = await AuditLog.findOne({ userId: user.id, action: 'settings_update' }).lean();
      expect(log).not.toBeNull();
      const keys = (log!.metadata as { changedKeys: string[] }).changedKeys;
      expect(keys).toEqual(['clipboardClearTimeout']);
    });
  });

  // ── Task 3.2: email_verified audit log ──────────────────────────────

  describe('email_verified', () => {
    it('should create an email_verified audit log on successful verification', async () => {
      // Create an unverified user
      const user = await createTestUser({ emailVerified: false });

      // Generate a valid verification token
      const verificationToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'email_verification',
          stateHash: generateStateHash(String(false)),
        },
        deriveTestPurposeKey('email_verification'),
        { algorithm: 'HS256', expiresIn: '24h' },
      );

      const res = await agent
        .post(`${API}/auth/verify-email`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ token: verificationToken });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/verified/i);

      const log = await AuditLog.findOne({ userId: user.id, action: 'email_verified' }).lean();
      expect(log).not.toBeNull();
      expect(log!.action).toBe('email_verified');
    });

    it('should NOT create an email_verified audit log when already verified', async () => {
      // Create an already-verified user
      const user = await createTestUser({ emailVerified: true });

      // Token with stateHash for emailVerified=true would fail validation,
      // so we just verify no log is created for the "already verified" path
      const verificationToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'email_verification',
          stateHash: generateStateHash(String(true)),
        },
        deriveTestPurposeKey('email_verification'),
        { algorithm: 'HS256', expiresIn: '24h' },
      );

      await agent
        .post(`${API}/auth/verify-email`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ token: verificationToken });

      const log = await AuditLog.findOne({ userId: user.id, action: 'email_verified' }).lean();
      expect(log).toBeNull();
    });
  });

  // ── Task 3.3: registration audit log ────────────────────────────────

  describe('registration', () => {
    it('should create a registration audit log for a new user', async () => {
      const body = registrationBody();

      const res = await agent
        .post(`${API}/auth/register`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send(body);

      expect(res.status).toBe(201);

      const log = await AuditLog.findOne({ action: 'registration' }).lean();
      expect(log).not.toBeNull();
      expect(log!.action).toBe('registration');
      expect(log!.userId).not.toBeNull();
      // Email should be masked in metadata
      expect(log!.metadata).toBeDefined();
      const maskedEmail = (log!.metadata as { email: string }).email;
      expect(maskedEmail).toContain('***');
      expect(maskedEmail).toContain('@');
    });

    it('should NOT create a registration audit log for duplicate email', async () => {
      const existingUser = await createTestUser();
      const body = registrationBody({ email: existingUser.email });

      await agent
        .post(`${API}/auth/register`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send(body);

      const log = await AuditLog.findOne({ action: 'registration' }).lean();
      expect(log).toBeNull();
    });
  });

  // ── Task 4.10/4.11: user-agent truncation invariant ─────────────────

  describe('userAgent truncation', () => {
    it('truncates oversized User-Agent headers to 512 characters before persistence', async () => {
      // 1500-char User-Agent — well above the 512 cap shared by AuditLog and
      // RefreshToken. The getRequestContext helper must clip at the boundary
      // so audit-log writes never carry oversized values, even if a future
      // controller bypasses Mongoose validators.
      const oversizedUa = 'X'.repeat(1500);
      const user = await createTestUser();

      const res = await agent
        .put(`${API}/user/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .set('User-Agent', oversizedUa)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ theme: 'dark' });

      expect(res.status).toBe(200);

      const log = await AuditLog.findOne({
        userId: user.id,
        action: 'settings_update',
      }).lean();
      expect(log).not.toBeNull();
      expect(log!.userAgent.length).toBe(512);
      expect(log!.userAgent).toBe('X'.repeat(512));
    });
  });

  // ── F1: ipAddress truncation invariant ──────────────────────────────

  describe('ipAddress truncation', () => {
    // NOTE: a former test here drove `PUT /user/settings` with a 500-char
    // `X-Forwarded-For` and asserted `log.ipAddress.length <= 45`. It was
    // vacuous: the shared app has `trust proxy` OFF, so the spoofed header
    // never reached `req.ip` (which stayed the ~15-char loopback address), and
    // the assertion held whether or not the clamp existed. The probe-app test
    // below drives the real truncation invariant deterministically (trust proxy
    // ON, `req.ip` forced to 500 chars) and is what actually pins the fix.
    it('truncates an oversized req.ip to 45 chars before audit-log persistence', async () => {
      // Direct integration test of the truncation invariant: stand up a
      // minimal app with `trust proxy` enabled, override req.ip with a
      // 500-char string, and verify the row persists with a 45-char ipAddress.
      const { default: express } = await import('express');
      const { getRequestContext } = await import('../src/utils/controllerHelpers.js');
      const { createAuditLog } = await import('../src/services/auditService.js');

      const probe = express();
      probe.set('trust proxy', true);
      probe.use((req, _res, next) => {
        Object.defineProperty(req, 'ip', { value: 'B'.repeat(500), configurable: true });
        next();
      });
      probe.get('/probe', (req, res) => {
        const ctx = getRequestContext(req);
        // Fire-and-forget audit write inside the request to mirror real flow.
        void createAuditLog(null, 'login_failed', { reason: 'probe' }, ctx.ip, ctx.userAgent).then(
          () => res.json({ ip: ctx.ip }),
        );
      });

      const probeRes = await request(probe).get('/probe');
      expect(probeRes.status).toBe(200);
      // getRequestContext must have already clipped to 45 chars.
      expect((probeRes.body as { ip: string }).ip.length).toBe(45);
      expect((probeRes.body as { ip: string }).ip).toBe('B'.repeat(45));

      // The audit row must exist with the truncated value — i.e. the
      // Mongoose ValidationError was avoided and `createAuditLog` did NOT
      // silently swallow the write.
      const log = await AuditLog.findOne({ action: 'login_failed' }).sort({ createdAt: -1 }).lean();
      expect(log).not.toBeNull();
      expect(log!.ipAddress.length).toBe(45);
      expect(log!.ipAddress).toBe('B'.repeat(45));
    });
  });
});
