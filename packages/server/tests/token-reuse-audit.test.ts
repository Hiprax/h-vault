/**
 * F-16: the strongest compromise signal the server has leaves a trace the owner
 * can read.
 *
 * A refresh token presented a second time after it was rotated is REUSE: the
 * cookie was copied, so the server revokes the token's whole family, every
 * trusted device and every device proof. That revocation used to happen in
 * silence: the owner's sessions ended, devices had to complete two-factor again,
 * and the audit log said nothing about why. These cases pin:
 *
 * - one `token_reuse_detected` row for the victim, written by the reuse branch,
 *   whose ip/user agent are the REPLAYER's (that request's) and whose metadata
 *   carries what was revoked and the revoked family's own device (the browser the
 *   stolen cookie was issued to), never the token, its hash or the family id;
 * - that a replay of the same token after detection writes no second row (the
 *   family is gone, so it is an unknown token);
 * - that an unknown token writes no row at all (it names no account);
 * - that the two other revocations of a whole account's devices that already
 *   write an audit row, "log out everywhere" and a password reset, now say how
 *   many trusted devices went with it.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import type { AuditAction } from '@hvault/shared';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { User } from '../src/models/User.js';
import { hashToken } from '../src/utils/token.js';
import {
  authHeader,
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

afterEach(() => {
  vi.restoreAllMocks();
});

const REPLAYER_UA = 'replayer-agent/1.0';

/** Presents `refreshToken` to `POST /auth/refresh` from a fresh browser. */
async function refreshWith(
  refreshToken: string,
  userAgent = 'owner-agent/1.0',
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent, `refreshToken=${refreshToken}`);
  return agent
    .post(`${API}/auth/refresh`)
    .set('User-Agent', userAgent)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', `${csrf.cookie}; refreshToken=${refreshToken}`);
}

/** Stores `count` trusted devices for `userId`. */
async function seedTrustedDevices(userId: string, count: number): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    await TrustedDevice.create({
      userId,
      tokenHash: hashToken(crypto.randomBytes(32).toString('hex')),
      deviceInfo: { userAgent: `device-${String(i)}`, ip: '10.0.0.9', fingerprint: 'fp' },
      expiresAt: new Date(Date.now() + 86_400_000),
    });
  }
}

/** Every audit row of `action` for `userId`, oldest first. */
async function auditRows(userId: string, action: AuditAction): Promise<Record<string, unknown>[]> {
  return (await AuditLog.find({ userId, action })
    .sort({ timestamp: 1 })
    .lean()) as unknown as Record<string, unknown>[];
}

describe('F-16: refresh-token reuse is audited', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('writes one token_reuse_detected row naming what was revoked and the revoked family device, never the token', async () => {
    const stored = await RefreshToken.findOne({ tokenHash: hashToken(user.refreshToken) }).lean();
    const familyId = stored!.familyId;
    // A second, live session in another family: reuse revokes only the family.
    const otherFamily = await RefreshToken.create({
      userId: user.id,
      tokenHash: hashToken('other-family-token'),
      familyId: crypto.randomUUID(),
      deviceInfo: { userAgent: 'other', ip: '127.0.0.2', fingerprint: 'other' },
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    await seedTrustedDevices(user.id, 2);
    // The legitimate rotation: the presented token is now spent, its successor live.
    expect((await refreshWith(user.refreshToken)).status).toBe(200);

    const replay = await refreshWith(user.refreshToken, REPLAYER_UA);

    expect(replay.status).toBe(401);
    expect(replay.body.message).toBe('TOKEN_REUSE_DETECTED');
    const rows = await auditRows(user.id, 'token_reuse_detected');
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    // The row's own request context is the replayer's.
    expect(row.userAgent).toBe(REPLAYER_UA);
    expect(row.metadata).toEqual({
      familyIdHash: hashToken(familyId).slice(0, 16),
      sessionsRevoked: 1,
      trustedDevicesRevoked: 2,
      revokedDeviceInfo: { userAgent: 'test-agent', ip: '127.0.0.1' },
    });
    // Nothing that could be presented again, or that names the family, is stored.
    const serialized = JSON.stringify(row);
    expect(serialized).not.toContain(user.refreshToken);
    expect(serialized).not.toContain(hashToken(user.refreshToken));
    expect(serialized).not.toContain(familyId);
    // The revocations themselves still happen: the family and the devices are gone,
    // the other family is untouched.
    expect(await RefreshToken.countDocuments({ userId: user.id, familyId })).toBe(0);
    expect(await RefreshToken.exists({ _id: otherFamily._id })).not.toBeNull();
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });

  it('writes no second row when the same token is replayed again (the family is gone)', async () => {
    expect((await refreshWith(user.refreshToken)).status).toBe(200);
    expect((await refreshWith(user.refreshToken, REPLAYER_UA)).body.message).toBe(
      'TOKEN_REUSE_DETECTED',
    );

    const again = await refreshWith(user.refreshToken, REPLAYER_UA);

    expect(again.status).toBe(401);
    expect(again.body.message).toBe('TOKEN_INVALID');
    expect(await auditRows(user.id, 'token_reuse_detected')).toHaveLength(1);
  });

  it('writes one row when two replays of one token race', async () => {
    expect((await refreshWith(user.refreshToken)).status).toBe(200);
    // Both replays are held at the claim, the reuse branch's LAST write, until
    // both have reached it. A replay only gets there after its lookup found the
    // spent token and it ran the revocations, so each arrives believing it is
    // the detection: the interleaving in which recording on every detection
    // writes two rows.
    const spent = await RefreshToken.findOne({ tokenHash: hashToken(user.refreshToken) }).lean();
    const real = RefreshToken.deleteOne.bind(RefreshToken) as (filter: unknown) => unknown;
    let arrived = 0;
    let release!: () => void;
    const bothArrived = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.spyOn(RefreshToken, 'deleteOne').mockImplementation(((filter: { _id?: unknown }) => {
      const query = real(filter);
      if (String(filter._id) !== String(spent!._id)) return query;
      arrived += 1;
      if (arrived === 2) release();
      return bothArrived.then(() => query);
    }) as never);

    const replays = await Promise.all([
      refreshWith(user.refreshToken, REPLAYER_UA),
      refreshWith(user.refreshToken, REPLAYER_UA),
    ]);

    expect(arrived).toBe(2);
    for (const res of replays) {
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('TOKEN_REUSE_DETECTED');
    }
    expect(await auditRows(user.id, 'token_reuse_detected')).toHaveLength(1);
  });

  it('leaves the replayed token in place when the revocation fails part-way, so the next replay finishes it', async () => {
    expect((await refreshWith(user.refreshToken)).status).toBe(200);
    await seedTrustedDevices(user.id, 1);
    vi.spyOn(TrustedDevice, 'deleteMany').mockRejectedValueOnce(new Error('connection reset'));

    const failed = await refreshWith(user.refreshToken, REPLAYER_UA);

    expect(failed.status).toBe(500);
    // The family's sessions went, the replayed row did not, and nothing was recorded yet.
    expect(await RefreshToken.exists({ tokenHash: hashToken(user.refreshToken) })).not.toBeNull();
    expect(await auditRows(user.id, 'token_reuse_detected')).toHaveLength(0);
    vi.restoreAllMocks();

    const again = await refreshWith(user.refreshToken, REPLAYER_UA);

    expect(again.status).toBe(401);
    expect(again.body.message).toBe('TOKEN_REUSE_DETECTED');
    const rows = await auditRows(user.id, 'token_reuse_detected');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.metadata).toMatchObject({ trustedDevicesRevoked: 1 });
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });

  it('writes no row for an unknown token', async () => {
    const before = await AuditLog.countDocuments({ userId: user.id });

    const res = await refreshWith(crypto.randomBytes(64).toString('hex'));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_INVALID');
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(before);
    expect(await AuditLog.countDocuments({ action: 'token_reuse_detected' })).toBe(0);
  });

  it('writes no row for a legitimate rotation', async () => {
    expect((await refreshWith(user.refreshToken)).status).toBe(200);
    expect(await AuditLog.countDocuments({ action: 'token_reuse_detected' })).toBe(0);
  });
});

describe('F-16: the other whole-account device revocations say how many devices went', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
    await seedTrustedDevices(user.id, 3);
  });

  it('"log out everywhere" records trustedDevicesRevoked on its session_revoke row', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const res = await agent
      .post(`${API}/auth/logout-all`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie);

    expect(res.status).toBe(200);
    const rows = await auditRows(user.id, 'session_revoke');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.metadata).toEqual({ sessionsRevoked: 1, trustedDevicesRevoked: 3 });
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
    expect(await AuditLog.countDocuments({ action: 'token_reuse_detected' })).toBe(0);
  });

  it('a password reset records trustedDevicesRevoked on its password_change row', async () => {
    const stored = await User.findById(user.id).select('+authHash').lean();
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash(stored!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const res = await agent
      .post(`${API}/auth/reset-password`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        token,
        email: user.email,
        newAuthHash: 'reset-auth-hash-value',
        newEncryptedVaultKey: 'fresh-encrypted-vault-key',
        newVaultKeyIv: 'fresh-vault-iv',
        newVaultKeyTag: 'fresh-vault-tag',
      });

    expect(res.status).toBe(200);
    const rows = await auditRows(user.id, 'password_change');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.metadata).toEqual({ method: 'reset', trustedDevicesRevoked: 3 });
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });
});
