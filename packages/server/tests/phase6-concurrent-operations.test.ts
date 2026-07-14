import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { JobLock } from '../src/models/JobLock.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from './helpers.js';

// ---------------------------------------------------------------------------
// Phase 6 — Task 6.1: Concurrent Operation Safety Tests
// Scenarios not covered by the pre-existing phase7-concurrent-safety and
// concurrent-operations suites:
//   • Two real concurrent triggerBackup calls deduplicated by JobLock.
//   • Concurrent verify2fa calls should not enable 2FA twice or issue
//     multiple backup code sets.
// ---------------------------------------------------------------------------

const BWK_SETUP = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

async function configureBackup(token: string, rawPassword: string): Promise<void> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const res = await agent
    .post('/api/v1/backup/setup')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ ...BWK_SETUP, authHash: rawPassword });
  expect(res.status).toBe(200);
}

describe('Phase 6 — Concurrent Operation Safety (extra coverage)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── Concurrent trigger backup via real API ─────────────────────────

  describe('Concurrent POST /backup/trigger (real concurrent requests)', () => {
    it('rejects a trigger while another backup for the same user is in progress', async () => {
      await configureBackup(user.accessToken, user.rawPassword);

      // The former version fired two "simultaneous" requests and asserted
      // `successCount >= 1 && successCount + conflictCount === 2`. Because a
      // no-item backup completes fast and Node serialises the two requests,
      // BOTH legitimately return 200 — so those assertions held even with the
      // JobLock guard entirely removed (0 conflicts). Under genuine overlap the
      // dedup is unobservable in this harness, so we force the overlap
      // deterministically: hold the per-user lock live (as another cluster
      // worker would mid-backup) and prove the request is REJECTED and produces
      // no backup.
      const lockJobName = `backup:trigger:${user.id}`;
      await JobLock.create({
        jobName: lockJobName,
        lockedBy: 'concurrent-worker',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie);

      // With the lock held the handler must 409 and must NOT proceed to
      // generate a backup. Removing the `if (!lockId) throw conflict(...)`
      // guard would make this a 200 that writes a BackupLog row instead.
      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);

      // No backup was produced: no BackupLog row and lastBackupAt never stamped.
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
      const persisted = await User.findById(user.id).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.settings.backup.lastBackupAt).toBeUndefined();

      // The rejected request must NOT release the other worker's lock.
      const heldLock = await JobLock.findOne({ jobName: lockJobName });
      expect(heldLock).not.toBeNull();
      expect(heldLock!.lockedBy).toBe('concurrent-worker');
    });

    it('should allow a fresh trigger after a previous trigger completes', async () => {
      await configureBackup(user.accessToken, user.rawPassword);

      const fire = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post('/api/v1/backup/trigger')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie);
      };

      const first = await fire();
      expect(first.status).toBe(200);

      // Lock is released — second trigger after the first completes must succeed
      const second = await fire();
      expect(second.status).toBe(200);
    });
  });

  // ── Concurrent verify2fa — must not double-enable or duplicate codes ─

  describe('Concurrent POST /user/2fa/verify', () => {
    it('should enable 2FA once and emit only a single set of backup codes', async () => {
      const { TOTP, Secret } = await import('otpauth');

      // Setup 2FA to stash pending secret
      const setupAgent = request.agent(app);
      const setupCsrf = await getCsrf(setupAgent);
      const setupRes = await setupAgent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', setupCsrf.token)
        .set('Cookie', setupCsrf.cookie)
        .send({ password: user.rawPassword });
      expect(setupRes.status).toBe(200);

      const secret: string = setupRes.body.data.secret;
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const code = totp.generate();

      const fireVerify = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post('/api/v1/user/2fa/verify')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ code });
      };

      const [first, second] = await Promise.all([fireVerify(), fireVerify()]);

      // No server crashes
      expect(first.status).toBeLessThan(500);
      expect(second.status).toBeLessThan(500);

      // Exactly one must succeed. The loser can receive:
      //   • 409 (already enabled — second request sees twoFactorEnabled=true)
      //   • 400 (pending secret cleared by winner or code replay guard fires)
      const results = [first, second];
      const successes = results.filter((r) => r.status === 200);
      const failures = results.filter((r) => r.status !== 200);
      expect(successes.length).toBe(1);
      expect(failures.length).toBe(1);
      expect([400, 409]).toContain(failures[0]!.status);

      // 2FA must be enabled in the DB
      const persisted = await User.findById(user.id).select(
        '+twoFactorSecret +backupCodes +pendingTwoFactorSecret +pendingTwoFactorExpiry',
      );
      expect(persisted!.twoFactorEnabled).toBe(true);
      expect(persisted!.twoFactorSecret).toBeTruthy();
      // Pending secret must be cleared after successful verify
      expect(persisted!.pendingTwoFactorSecret).toBeUndefined();
      expect(persisted!.pendingTwoFactorExpiry).toBeUndefined();

      // Backup codes must be generated exactly once (single set of hashes)
      const backupCodes = (persisted!.backupCodes ?? []) as string[];
      expect(backupCodes.length).toBeGreaterThan(0);
      // All hashes are unique (no accidental duplication from two runs)
      expect(new Set(backupCodes).size).toBe(backupCodes.length);

      // Only the winner returned backup codes in the response
      const winner = successes[0]!;
      const returnedCodes = winner.body.data.backupCodes as string[];
      expect(Array.isArray(returnedCodes)).toBe(true);
      expect(returnedCodes.length).toBe(backupCodes.length);
    });

    it('should reject verify with stale pending secret after a fresh setup', async () => {
      const { TOTP, Secret } = await import('otpauth');

      // Initial setup
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      const first = await agent1
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1.token)
        .set('Cookie', csrf1.cookie)
        .send({ password: user.rawPassword });
      expect(first.status).toBe(200);
      const oldSecret: string = first.body.data.secret;

      // Second setup overwrites the pending secret
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      const second = await agent2
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2.token)
        .set('Cookie', csrf2.cookie)
        .send({ password: user.rawPassword });
      expect(second.status).toBe(200);
      const newSecret: string = second.body.data.secret;
      expect(newSecret).not.toBe(oldSecret);

      // Verifying with the OLD secret should fail — the pending stash now
      // holds the new secret, so TOTP validation against it fails.
      const oldTotp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(oldSecret),
      });
      const oldCode = oldTotp.generate();

      const verifyAgent = request.agent(app);
      const verifyCsrf = await getCsrf(verifyAgent);
      const verifyRes = await verifyAgent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', verifyCsrf.token)
        .set('Cookie', verifyCsrf.cookie)
        .send({ code: oldCode });
      expect(verifyRes.status).toBe(400);

      // 2FA must not have been enabled
      const persisted = await User.findById(user.id);
      expect(persisted!.twoFactorEnabled).toBe(false);
    });
  });
});
