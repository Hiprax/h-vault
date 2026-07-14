import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Folder } from '../src/models/Folder.js';
import { JobLock } from '../src/models/JobLock.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  seedFolder,
  seedItem,
  type TestUser,
} from './helpers.js';

/**
 * Behavioural coverage for the error/edge branches of `backupController.ts`
 * that no other suite reaches:
 *
 *  • `updateBackupSettings` — the "nothing to update" 400.
 *  • `triggerBackup` — the un-configured-encryption 400.
 *  • the FINAL whole-payload size check in `triggerBackup` / `downloadBackup`
 *    (distinct from the in-cursor streaming guard the other suites drive).
 *  • `changeBackupPassword` — the branch that PERSISTS a new BWK-wrapped vault
 *    key (every existing test exercises only the clearing branch).
 *  • `restoreBackup` — the folder loop's per-branch error handling: a
 *    ValidationError / CastError raised on the `overwrite` and `keep_both`
 *    paths must fall THROUGH the bespoke E11000 retries and be skipped by the
 *    outer guard as `invalid_folder_data`, leaving the existing row intact;
 *    and a genuine infrastructure error must PROPAGATE (never be swallowed as
 *    a per-row skip) on both the folder and the item loop.
 */

type Agent = request.SuperTest<request.Test>;

const BWK_SETUP = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

async function post(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .post(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie)
    .send(body as object);
}

async function put(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .put(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie)
    .send(body as object);
}

async function configureBackup(agent: Agent, user: TestUser): Promise<void> {
  const res = await post(agent, '/api/v1/backup/setup', user.accessToken, {
    ...BWK_SETUP,
    authHash: user.rawPassword,
  });
  expect(res.status).toBe(200);
}

/** Runs `fn` with a temporarily overridden BACKUP_MAX_SIZE_MB. */
async function withBackupMaxSizeMb(mb: number, fn: () => Promise<void>): Promise<void> {
  const original = config.BACKUP_MAX_SIZE_MB;
  (config as unknown as Record<string, unknown>).BACKUP_MAX_SIZE_MB = mb;
  try {
    await fn();
  } finally {
    (config as unknown as Record<string, unknown>).BACKUP_MAX_SIZE_MB = original;
  }
}

async function restore(
  agent: Agent,
  user: TestUser,
  conflictStrategy: 'skip' | 'overwrite' | 'keep_both',
  payload: { items?: unknown[]; folders?: unknown[] },
): Promise<request.Response> {
  return post(agent, '/api/v1/backup/restore', user.accessToken, {
    conflictStrategy,
    data: JSON.stringify(payload),
  });
}

describe('backupController — uncovered error/edge branches', () => {
  let agent: Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request(app) as unknown as Agent;
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── updateBackupSettings: nothing to update ─────────────────────────────

  describe('PUT /api/v1/backup/settings', () => {
    it('400s on an empty body and leaves the stored backup settings untouched', async () => {
      // Every field of backupSettingsSchema is optional, so `{}` passes Zod and
      // reaches the controller. Without the emptiness guard it would issue an
      // `$set: {}` update and answer 200 for a request that changed nothing.
      await put(agent, '/api/v1/backup/settings', user.accessToken, { scheduleHour: 9 });

      const res = await put(agent, '/api/v1/backup/settings', user.accessToken, {});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(String(res.body.message)).toMatch(/no backup settings provided/i);

      const dbUser = await User.findById(user.id).lean();
      expect(dbUser!.settings.backup.scheduleHour).toBe(9);
      // A rejected update must not be audited as a settings change.
      expect(
        await AuditLog.countDocuments({ userId: user.id, action: 'backup_settings_update' }),
      ).toBe(1);
    });
  });

  // ── triggerBackup: encryption not configured ────────────────────────────

  describe('POST /api/v1/backup/trigger', () => {
    it('400s when backup encryption was never configured, and does no work', async () => {
      const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(String(res.body.message)).toMatch(/must be configured/i);

      // The guard sits ahead of the dedup lock and of every write.
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await JobLock.countDocuments({ jobName: `backup:trigger:${user.id}` })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_triggered' })).toBe(
        0,
      );
    });
  });

  // ── The FINAL whole-payload size check ──────────────────────────────────
  //
  // The in-cursor streaming guard only ever sums the *rows*. The backup envelope
  // — version, exportDate, the wrapped vault key and the whole backupEncryption
  // block — is never counted there, so on an EMPTY vault the cursors add nothing
  // and the streaming guard cannot fire at all. The final `Buffer.byteLength`
  // check on the serialized payload is the only thing standing between an
  // operator's size budget and an over-budget response. Drive it by setting a
  // budget below the envelope's own size.

  describe('final serialized-payload size check', () => {
    it('413s a trigger whose envelope alone exceeds the budget, writes no BackupLog and releases the lock', async () => {
      await configureBackup(agent, user);

      await withBackupMaxSizeMb(0, async () => {
        const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);
        // NOT the in-cursor guard: with an empty vault neither cursor iterates,
        // so "during collection" must NOT appear. Pinning this proves the final
        // check is what fired.
        expect(String(res.body.message)).not.toMatch(/during collection/i);
        expect(String(res.body.message)).toMatch(/exceeds the maximum allowed size/i);
      });

      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_triggered' })).toBe(
        0,
      );
      const dbUser = await User.findById(user.id).lean();
      expect(dbUser!.settings.backup.lastBackupAt).toBeUndefined();
      // The `finally` must release the per-user dedup lock even on the 413, or
      // the account would be wedged for the lock's full 5-minute TTL.
      expect(await JobLock.countDocuments({ jobName: `backup:trigger:${user.id}` })).toBe(0);
    });

    it('413s a download whose envelope alone exceeds the budget and writes no BackupLog', async () => {
      await configureBackup(agent, user);

      await withBackupMaxSizeMb(0, async () => {
        const res = await agent
          .get('/api/v1/backup/download')
          .set('Authorization', authHeader(user.accessToken));

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);
        expect(String(res.body.message)).not.toMatch(/during collection/i);
        expect(String(res.body.message)).toMatch(/exceeds the maximum allowed size/i);
      });

      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_download' })).toBe(0);
    });
  });

  // ── changeBackupPassword: persist a new BWK-wrapped vault key ───────────

  describe('PUT /api/v1/backup/change-password', () => {
    it('persists the new BWK-wrapped vault key when all three fields are supplied', async () => {
      await configureBackup(agent, user);

      const res = await put(agent, '/api/v1/backup/change-password', user.accessToken, {
        password: user.rawPassword,
        newEncryptedBWK: 'rotated-encrypted-bwk',
        newBwkIv: 'rotated-bwk-iv',
        newBwkTag: 'rotated-bwk-tag',
        newBwkSalt: 'rotated-bwk-salt',
        newBwkEncryptedVaultKey: 'rotated-bwk-vault-key',
        newBwkVaultKeyIv: 'rotated-vk-iv',
        newBwkVaultKeyTag: 'rotated-vk-tag',
      });

      expect(res.status).toBe(200);

      // The BWK-wrapped vault key is what makes a backup restorable on another
      // account. Dropping it here (i.e. taking the $unset branch) would silently
      // strand every future backup taken under the new password.
      const dbUser = await User.findById(user.id).lean();
      const backup = dbUser!.settings.backup;
      expect(backup.encryptedBWK).toBe('rotated-encrypted-bwk');
      expect(backup.bwkIv).toBe('rotated-bwk-iv');
      expect(backup.bwkTag).toBe('rotated-bwk-tag');
      expect(backup.bwkSalt).toBe('rotated-bwk-salt');
      expect(backup.bwkEncryptedVaultKey).toBe('rotated-bwk-vault-key');
      expect(backup.bwkVaultKeyIv).toBe('rotated-vk-iv');
      expect(backup.bwkVaultKeyTag).toBe('rotated-vk-tag');
      // Configuration itself is untouched by a password change.
      expect(backup.isConfigured).toBe(true);
    });

    it('a later change WITHOUT those fields clears the now-stale wrapped vault key', async () => {
      await configureBackup(agent, user);
      await put(agent, '/api/v1/backup/change-password', user.accessToken, {
        password: user.rawPassword,
        newEncryptedBWK: 'bwk-1',
        newBwkIv: 'iv-1',
        newBwkTag: 'tag-1',
        newBwkSalt: 'salt-1',
        newBwkEncryptedVaultKey: 'vk-1',
        newBwkVaultKeyIv: 'vk-iv-1',
        newBwkVaultKeyTag: 'vk-tag-1',
      });

      const res = await put(agent, '/api/v1/backup/change-password', user.accessToken, {
        password: user.rawPassword,
        newEncryptedBWK: 'bwk-2',
        newBwkIv: 'iv-2',
        newBwkTag: 'tag-2',
        newBwkSalt: 'salt-2',
      });

      expect(res.status).toBe(200);

      // A vault key wrapped under the OLD BWK is undecryptable under the new
      // one — keeping it would hand the restore flow a key it cannot unwrap.
      const dbUser = await User.findById(user.id).lean();
      const backup = dbUser!.settings.backup;
      expect(backup.encryptedBWK).toBe('bwk-2');
      expect(backup.bwkEncryptedVaultKey).toBeUndefined();
      expect(backup.bwkVaultKeyIv).toBeUndefined();
      expect(backup.bwkVaultKeyTag).toBeUndefined();
    });
  });

  // ── restoreBackup: folder-loop data errors on the CONFLICT branches ──────
  //
  // Both branches wrap their write in a bespoke E11000-only retry. A
  // ValidationError / CastError must fall through that retry's `else` and be
  // caught by the outer per-folder guard as `invalid_folder_data`, so one bad
  // row never aborts the whole restore.

  describe('POST /api/v1/backup/restore — malformed folder on a conflict branch', () => {
    it('skips (not aborts) an OVERWRITE whose encryptedName exceeds the model maxlength, leaving the folder intact', async () => {
      const existing = await seedFolder(user.id, { encryptedName: 'original-name' });
      const goodItem = { ...sampleVaultItem({ encryptedName: 'still-restored' }) };

      const res = await restore(agent, user, 'overwrite', {
        folders: [
          {
            _id: String(existing._id),
            ...sampleFolder({ encryptedName: 'x'.repeat(1001) }),
          },
        ],
        items: [goodItem],
      });

      expect(res.status).toBe(200);
      expect(res.body.data.foldersRestored).toBe(0);
      expect(res.body.data.foldersSkipped).toBe(1);
      expect(res.body.data.folderSkipReasons).toEqual([
        { folderId: String(existing._id), reason: 'invalid_folder_data' },
      ]);
      // The rest of the restore still runs — the guard is per-row, not per-request.
      expect(res.body.data.itemsRestored).toBe(1);

      const raw = await Folder.findById(String(existing._id)).lean();
      expect(raw).not.toBeNull();
      expect(raw!.encryptedName).toBe('original-name');
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    });

    it('skips an OVERWRITE carrying an un-castable sortOrder (CastError) and keeps the folder as it was', async () => {
      const existing = await seedFolder(user.id, { encryptedName: 'keep-me', sortOrder: 3 });

      const res = await restore(agent, user, 'overwrite', {
        folders: [
          {
            _id: String(existing._id),
            ...sampleFolder({ encryptedName: 'tampered', sortOrder: 'not-a-number' }),
          },
        ],
      });

      expect(res.status).toBe(200);
      expect(res.body.data.foldersRestored).toBe(0);
      expect(res.body.data.folderSkipReasons).toEqual([
        { folderId: String(existing._id), reason: 'invalid_folder_data' },
      ]);

      const raw = await Folder.findById(String(existing._id)).lean();
      expect(raw!.encryptedName).toBe('keep-me');
      expect(raw!.sortOrder).toBe(3);
    });

    it('skips a KEEP_BOTH duplicate whose encryptedName is over-length, without duplicating or losing the original', async () => {
      const existing = await seedFolder(user.id, { encryptedName: 'original-name' });

      const res = await restore(agent, user, 'keep_both', {
        folders: [
          {
            _id: String(existing._id),
            ...sampleFolder({ encryptedName: 'y'.repeat(1001) }),
          },
        ],
      });

      expect(res.status).toBe(200);
      expect(res.body.data.foldersRestored).toBe(0);
      expect(res.body.data.foldersSkipped).toBe(1);
      expect(res.body.data.folderSkipReasons).toEqual([
        { folderId: String(existing._id), reason: 'invalid_folder_data' },
      ]);

      // keep_both's duplicate never materialised, and the original is untouched.
      const folders = await Folder.find({ userId: user.id }).lean();
      expect(folders).toHaveLength(1);
      expect(folders[0]!.encryptedName).toBe('original-name');
    });

    it('records invalid_folder_data in the backup_restored audit metadata', async () => {
      const existing = await seedFolder(user.id, { encryptedName: 'audited' });

      await restore(agent, user, 'overwrite', {
        folders: [
          { _id: String(existing._id), ...sampleFolder({ encryptedName: 'z'.repeat(1001) }) },
        ],
      });

      const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_restored' }).lean();
      expect(audit).not.toBeNull();
      const meta = audit!.metadata as Record<string, unknown>;
      expect(meta.foldersSkipped).toBe(1);
      expect(meta.folderSkipReasons).toEqual([
        { folderId: String(existing._id), reason: 'invalid_folder_data' },
      ]);
    });
  });

  // ── restoreBackup: infra errors must PROPAGATE, never be swallowed ───────
  //
  // The per-row guards deliberately narrow to persistence-layer DATA errors
  // (ValidationError / CastError / E11000). A transient DB failure must fail the
  // request loudly: swallowing it as a per-row "skip" would report a successful
  // restore to a user whose data silently never landed. `Model.create` is the DB
  // boundary here, so it is the only thing stubbed; every assertion is made
  // against the HTTP response and the real database.

  describe('POST /api/v1/backup/restore — non-data errors propagate', () => {
    it('fails the request (does not skip the row) when the folder insert hits a transient DB error', async () => {
      const spy = vi
        .spyOn(Folder, 'create')
        .mockRejectedValueOnce(new Error('transient mongo failure') as never);

      const res = await restore(agent, user, 'skip', {
        folders: [{ _id: new Types.ObjectId().toString(), ...sampleFolder() }],
        items: [{ ...sampleVaultItem() }],
      });

      expect(spy).toHaveBeenCalledTimes(1);
      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);

      // Nothing was persisted and, crucially, no "successful restore" was audited.
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_restored' })).toBe(0);
    });

    it('fails the request (does not skip the row) when the item insert hits a transient DB error', async () => {
      const spy = vi
        .spyOn(VaultItem, 'create')
        .mockRejectedValueOnce(new Error('transient mongo failure') as never);

      const res = await restore(agent, user, 'skip', {
        items: [{ _id: new Types.ObjectId().toString(), ...sampleVaultItem() }],
      });

      expect(spy).toHaveBeenCalledTimes(1);
      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);

      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_restored' })).toBe(0);
    });
  });

  // ── restoreBackup: skip-reason id for a row with no usable _id ───────────

  describe('POST /api/v1/backup/restore — skip reasons for id-less rows', () => {
    it("reports itemId 'unknown' for a row missing both its _id and its encryption fields", async () => {
      const existingItem = await seedItem(user.id, { encryptedName: 'untouched' });

      const res = await restore(agent, user, 'skip', {
        items: [
          { itemType: 'login', encryptedName: 'partial-row' }, // no _id, no ciphertext
          { ...sampleVaultItem({ encryptedName: 'valid-row' }) },
        ],
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(1);
      // The client renders this list; a row with no id must still be reportable.
      expect(res.body.data.itemSkipReasons).toEqual([
        { itemId: 'unknown', reason: 'missing_encryption_fields' },
      ]);

      // The half-formed row was never written, and the pre-existing item stands.
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
      const untouched = await VaultItem.findById(String(existingItem._id)).lean();
      expect(untouched!.encryptedName).toBe('untouched');
    });
  });
});
