import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import authRouter from '../src/routes/auth.js';
import { createTestUser, authHeader, getCsrf, type CsrfPair, type TestUser } from './helpers.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { unlockLimiter, authLimiter } from '../src/middleware/rateLimiter.js';

/** Minimal view of an Express router layer for stack introspection. */
interface RouteStackLayer {
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: unknown }[];
  };
}

describe('POST /api/v1/auth/verify-unlock', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  it('should return 200 for valid auth hash', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: user.rawPassword });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe('Unlock verified');
  });

  it('should return 401 for invalid auth hash', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: 'wrong-auth-hash' });

    expect(res.status).toBe(401);
  });

  it('should return 401 without authentication', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: 'some-hash' });

    expect(res.status).toBe(401);
  });

  it('should return 400 for missing authHash', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({});

    expect(res.status).toBe(400);
  });

  it('should return 400 for empty authHash', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: '' });

    expect(res.status).toBe(400);
  });

  it('should create audit log on failed verification', async () => {
    await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: 'wrong-hash' });

    const logs = await AuditLog.find({
      userId: user.id,
      action: 'password_verification_failed',
    }).lean();

    const verifyLogs = logs.filter(
      (l) => (l.metadata as Record<string, unknown> | undefined)?.endpoint === 'verify_unlock',
    );
    expect(verifyLogs.length).toBeGreaterThanOrEqual(1);
  });

  it('should create a vault_unlock audit log on successful verification (Task 3.9)', async () => {
    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: user.rawPassword });

    expect(res.status).toBe(200);

    const logs = await AuditLog.find({ userId: user.id, action: 'vault_unlock' }).lean();
    expect(logs.length).toBeGreaterThanOrEqual(1);
  });

  it('should NOT create a vault_unlock audit log on failed verification', async () => {
    await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: 'definitely-wrong' });

    const logs = await AuditLog.find({ userId: user.id, action: 'vault_unlock' }).lean();
    expect(logs.length).toBe(0);
  });
});

describe('POST /api/v1/auth/verify-unlock — rate limiting', () => {
  // The production `unlockLimiter` is a pass-through no-op in test mode, so its
  // 429 behaviour, its 5/user/5min threshold, its `unlock:` key prefix and its
  // userId keying are exercised end to end against the REAL exported symbol
  // (with isProduction forced true, on a real Mongo store) in
  // coverage-rate-limiter.test.ts. The previous test here built its OWN
  // express-rate-limit instance on a throwaway app, so it only proved
  // express-rate-limit can count — deleting `unlockLimiter` from the route, or
  // raising its limit to 5000, left it green. What is verified HERE, and cannot
  // be verified there, is the WIRING: the exact production `unlockLimiter`
  // binding is mounted on the real `/verify-unlock` route.
  it('mounts the production unlockLimiter (and authLimiter) on the /verify-unlock route', () => {
    const stack = (authRouter as unknown as { stack: RouteStackLayer[] }).stack;
    const layer = stack.find(
      (l) => l.route?.path === '/verify-unlock' && l.route.methods.post === true,
    );
    expect(layer).toBeDefined();

    const handles = layer!.route!.stack.map((s) => s.handle);
    // Reference equality against the imported bindings: removing unlockLimiter
    // from routes/auth.ts drops it from this list and fails the assertion.
    expect(handles).toContain(unlockLimiter);
    expect(handles).toContain(authLimiter);
  });

  it('keeps the /verify-unlock route reachable through the mounted app', async () => {
    // The mounted limiter must not break the happy path (it is a no-op in test):
    // a valid unlock still returns 200 through the real app + real limiter chain.
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const user = await createTestUser();

    const res = await agent
      .post('/api/v1/auth/verify-unlock')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: user.rawPassword });

    expect(res.status).toBe(200);
  });
});
