import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import authRouter from '../src/routes/auth.js';
import { createTestUser, authHeader, getCsrf, type CsrfPair, type TestUser } from './helpers.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { User } from '../src/models/User.js';
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
  it('mounts the production unlockLimiter — and NOT authLimiter — on /verify-unlock', () => {
    const stack = (authRouter as unknown as { stack: RouteStackLayer[] }).stack;
    const layer = stack.find(
      (l) => l.route?.path === '/verify-unlock' && l.route.methods.post === true,
    );
    expect(layer).toBeDefined();

    const handles = layer!.route!.stack.map((s) => s.handle);
    // Reference equality against the imported bindings: removing unlockLimiter
    // from routes/auth.ts drops it from this list and fails the assertion.
    expect(handles).toContain(unlockLimiter);

    // `authLimiter` must NOT be here, and this assertion is the whole point.
    //
    // It used to be, and that was a shipped defect. `authLimiter` is one flat
    // `auth:<ip>` bucket of 10 per 15 minutes shared with `/login`, `/register`
    // and `/login/2fa`. Unlocking the vault is not a credential attempt against
    // that budget — it is something the app does every time an idle timer fires —
    // and each unlock spent TWO slots (this route plus the `/auth/refresh` the
    // unlock screen issued first). A few lock/unlock cycles therefore drained the
    // login budget, and the user's next `POST /auth/login` was rejected with 429
    // on its FIRST attempt, locking them out of their own vault until the window
    // rolled over.
    //
    // `unlockLimiter` alone is the correct control here and is strictly tighter
    // for this traffic: 5 per 5 minutes, keyed by userId (so it cannot be diluted
    // by IP rotation, and one user cannot exhaust another's budget).
    expect(handles).not.toContain(authLimiter);
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

describe('POST /api/v1/auth/verify-unlock — the live wrapped vault key', () => {
  // The unlock screen derives the vault key from what this answer carries, not
  // from the copy its browser cached at sign-in. A rotation made in another
  // session re-wraps a NEW vault key under the same master key and signs nothing
  // out, so that cached copy still opens — onto the superseded key, under which no
  // row the rotation rewrote can be read. Every item then "could not be
  // decrypted", on every unlock and every reload, until the user signs out.
  let agent: request.Agent;
  let csrf: CsrfPair;
  let user: TestUser;

  const send = (path: string, body: Record<string, unknown>) =>
    agent
      .post(path)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send(body);

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('answers with the wrapper and generation the account holds after a rotation elsewhere', async () => {
    const rotation = await send('/api/v1/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      items: [],
      folders: [],
      documents: [],
      newEncryptedVaultKey: 'rotated-elsewhere-vault-key',
      newVaultKeyIv: 'rotated-elsewhere-iv',
      newVaultKeyTag: 'rotated-elsewhere-tag',
      vaultKeyVersion: 0,
    });
    expect(rotation.status).toBe(200);

    const res = await send('/api/v1/auth/verify-unlock', { authHash: user.rawPassword });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe('Unlock verified');
    // EXACTLY these four: the reply is built field by field, so no credential
    // (`authHash`) and no interrupted rotation's wrapper rides along with it.
    expect(res.body.data).toStrictEqual({
      encryptedVaultKey: 'rotated-elsewhere-vault-key',
      vaultKeyIv: 'rotated-elsewhere-iv',
      vaultKeyTag: 'rotated-elsewhere-tag',
      vaultKeyVersion: 1,
    });
  });

  it('reports generation 0 for an account whose row has no generation stored', async () => {
    // Accounts created before the field existed carry no column at all; the
    // server reads that as 0 everywhere (`vaultKeyVersionOf`), and so must this.
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $unset: { vaultKeyVersion: 1 } },
    );

    const res = await send('/api/v1/auth/verify-unlock', { authHash: user.rawPassword });

    expect(res.status).toBe(200);
    expect(res.body.data).toStrictEqual({
      encryptedVaultKey: 'test-encrypted-vault-key',
      vaultKeyIv: 'test-vault-key-iv',
      vaultKeyTag: 'test-vault-key-tag',
      vaultKeyVersion: 0,
    });
  });

  it('carries no wrapper at all when the password is wrong', async () => {
    const res = await send('/api/v1/auth/verify-unlock', { authHash: 'wrong-auth-hash' });

    expect(res.status).toBe(401);
    expect(res.body).not.toHaveProperty('data');
    expect(JSON.stringify(res.body)).not.toContain('test-encrypted-vault-key');
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'vault_unlock' })).toBe(0);
  });

  it('reads the account from the primary, so a lagging secondary cannot hand back a retired wrapper', async () => {
    const pinned: string[] = [];
    const original = mongoose.Query.prototype.read;
    vi.spyOn(mongoose.Query.prototype, 'read').mockImplementation(function (
      this: mongoose.Query<unknown, unknown>,
      ...args: Parameters<typeof original>
    ) {
      if (this.model.modelName === 'User' && args[0] === 'primary')
        pinned.push((this as unknown as { op?: string }).op ?? '');
      return original.apply(this, args);
    });

    const res = await send('/api/v1/auth/verify-unlock', { authHash: user.rawPassword });

    expect(res.status).toBe(200);
    expect(pinned).toContain('findOne');
  });

  it('reads the profile from the primary too, since an unlock falls back to its wrapper', async () => {
    // An instance answering verify-unlock without `data` (a rolling restart) sends
    // the unlock screen to `GET /user/profile` for the same three fields, and a
    // session checking whether its key was replaced compares against them too.
    const pinned: string[] = [];
    const original = mongoose.Query.prototype.read;
    vi.spyOn(mongoose.Query.prototype, 'read').mockImplementation(function (
      this: mongoose.Query<unknown, unknown>,
      ...args: Parameters<typeof original>
    ) {
      if (this.model.modelName === 'User' && args[0] === 'primary')
        pinned.push((this as unknown as { op?: string }).op ?? '');
      return original.apply(this, args);
    });

    const res = await agent
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.encryptedVaultKey).toBe('test-encrypted-vault-key');
    expect(pinned).toContain('findOne');
  });
});
