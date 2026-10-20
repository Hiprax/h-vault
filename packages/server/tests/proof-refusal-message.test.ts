/**
 * Every route that re-checks the master password refuses a WRONG proof with one
 * and the same sentence, `MASTER_PASSWORD_PROOF_REFUSED_MESSAGE`.
 *
 * The sentence is load-bearing, not cosmetic. Such a 401 is only ever produced
 * after `authenticate` has accepted the session, so the client recognises it by
 * that exact sentence (`isMasterPasswordRefusal`) and reports it without the
 * refresh-and-replay it applies to every other 401. A route that answered with a
 * different wording would silently go back to charging a typo twice against the
 * shared re-authentication budget (`passwordVerifyLimiter`), which is the defect
 * this pins. Two routes said "Password verification failed" until 0.19.0.
 *
 * Each case also asserts the `password_verification_failed` audit row naming the
 * route, and that the 401 is not the stale-session sentence the interceptor DOES
 * refresh on.
 *
 * `POST /auth/invitations` is pinned beside its own setup in
 * `registration-mode.test.ts`, because it only exists while registration is by
 * invitation.
 */
import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';
import request from 'supertest';
import { MASTER_PASSWORD_PROOF_REFUSED_MESSAGE } from '@hvault/shared';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { SESSION_INVALID_MESSAGE } from '../src/constants/index.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';
import { ROUTE_TABLE } from './support/routeTable.js';

const API = '/api/v1';
const WRONG = 'not-the-master-password-proof';

interface ProofCase {
  method: 'post' | 'put' | 'delete';
  path: string;
  /** The `endpoint` the failure's audit row names. */
  endpoint: string;
  twoFactorEnabled?: boolean;
  body: () => Record<string, unknown>;
}

const CASES: ProofCase[] = [
  {
    method: 'put',
    path: '/user/notifications',
    endpoint: 'notifications',
    body: () => ({ authHash: WRONG, notifications: { trusted_device_granted: false } }),
  },
  {
    method: 'put',
    path: '/user/change-password',
    endpoint: 'change_password',
    body: () => ({
      currentAuthHash: WRONG,
      newAuthHash: 'new-auth-hash-value',
      newEncryptedVaultKey: 'rewrapped-vault-key',
      newVaultKeyIv: 'rewrapped-iv',
      newVaultKeyTag: 'rewrapped-tag',
    }),
  },
  {
    method: 'post',
    path: '/user/2fa/setup',
    endpoint: '2fa_setup',
    body: () => ({ password: WRONG }),
  },
  {
    method: 'delete',
    path: '/user/2fa',
    endpoint: '2fa_disable',
    twoFactorEnabled: true,
    body: () => ({ code: '123456', password: WRONG }),
  },
  {
    method: 'post',
    path: '/user/2fa/regenerate-backup-codes',
    endpoint: 'regenerate_backup_codes',
    twoFactorEnabled: true,
    body: () => ({ password: WRONG }),
  },
  {
    method: 'delete',
    path: '/user',
    endpoint: 'delete_account',
    body: () => ({ password: WRONG }),
  },
  {
    method: 'post',
    path: '/tools/export',
    endpoint: 'export',
    body: () => ({ authHash: WRONG }),
  },
  {
    method: 'post',
    path: '/backup/setup',
    endpoint: 'backup_setup',
    body: () => ({
      authHash: WRONG,
      encryptedBWK: 'wrapped-bwk',
      bwkIv: 'bwk-iv',
      bwkTag: 'bwk-tag',
      bwkSalt: 'bwk-salt',
    }),
  },
  {
    method: 'put',
    path: '/backup/recipients',
    endpoint: 'backup_recipients',
    body: () => ({ authHash: WRONG, backupEmails: [] }),
  },
  {
    method: 'put',
    path: '/backup/change-password',
    endpoint: 'change_backup_password',
    body: () => ({
      password: WRONG,
      newEncryptedBWK: 'wrapped-bwk',
      newBwkIv: 'bwk-iv',
      newBwkTag: 'bwk-tag',
      newBwkSalt: 'bwk-salt',
    }),
  },
  {
    method: 'post',
    path: '/vault/items/purge-unreadable',
    endpoint: 'purge_unreadable',
    body: () => ({
      authHash: WRONG,
      encryptedVaultKey: 'test-encrypted-vault-key',
      vaultKeyIv: 'test-vault-key-iv',
      vaultKeyTag: 'test-vault-key-tag',
      items: [
        { id: new mongoose.Types.ObjectId().toHexString(), nameIv: 'name-iv', dataIv: 'data-iv' },
      ],
      folders: [],
    }),
  },
  {
    method: 'post',
    path: '/vault/items/bulk-reencrypt',
    endpoint: 'bulk_reencrypt',
    body: () => ({
      authHash: WRONG,
      items: [],
      newEncryptedVaultKey: 'new-evk',
      newVaultKeyIv: 'new-iv',
      newVaultKeyTag: 'new-tag',
    }),
  },
];

async function sendWrongProof(proofCase: ProofCase, user: TestUser): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  return agent[proofCase.method](`${API}${proofCase.path}`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .set('Authorization', authHeader(user.accessToken))
    .send(proofCase.body());
}

describe('a wrong master-password proof is refused with the one shared sentence', () => {
  it('covers every route that mounts the re-authentication budget, except the two noted', () => {
    // Read from the route table, which `route-table.test.ts` holds to the real
    // routers, so a proof route added later fails here until it is listed above.
    // The two left out: invitations (pinned in registration-mode.test.ts, as it
    // exists only in invitation mode) and the backup restore, which carries no
    // proof.
    const key = (method: string, path: string): string => `${method} ${path.replace(/\/$/, '')}`;
    const mounted = ROUTE_TABLE.filter((row) => row.limiters.includes('passwordVerifyLimiter'))
      .map((row) => key(row.method, row.path))
      .filter((route) => route !== 'post /api/v1/auth/invitations')
      .filter((route) => route !== 'post /api/v1/backup/restore')
      .sort();
    expect(mounted).toEqual(CASES.map((c) => key(c.method, `${API}${c.path}`)).sort());
  });

  for (const proofCase of CASES) {
    it(`${proofCase.method.toUpperCase()} ${proofCase.path}`, async () => {
      const user = await createTestUser(
        proofCase.twoFactorEnabled === true ? { twoFactorEnabled: true } : {},
      );

      const res = await sendWrongProof(proofCase, user);

      expect(res.status).toBe(401);
      expect((res.body as { message: string }).message).toBe(MASTER_PASSWORD_PROOF_REFUSED_MESSAGE);
      expect((res.body as { message: string }).message).not.toBe(SESSION_INVALID_MESSAGE);
      const failed = await AuditLog.find({
        userId: user.id,
        action: 'password_verification_failed',
      }).lean();
      expect(failed).toHaveLength(1);
      expect(failed[0]?.metadata).toMatchObject({ endpoint: proofCase.endpoint });
    });
  }
});
