import cron, { type ScheduledTask } from 'node-cron';
import { createLogger } from '@hiprax/logger';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { BackupLog } from '../models/BackupLog.js';
import { sendEmail, escapeHtml } from '../utils/email.js';
import { config } from '../config/index.js';
import { APP_VERSION, maskEmail } from '@hvault/shared';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';

const logger = createLogger({ moduleName: 'jobs/backup' });

interface BackupPayload {
  version: string;
  formatVersion: number;
  timestamp: string;
  encryptionVersion: number;
  items: unknown[];
  folders: unknown[];
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  backupEncryption: {
    encryptedBWK: string | undefined;
    bwkIv: string | undefined;
    bwkTag: string | undefined;
    bwkSalt: string | undefined;
    bwkEncryptedVaultKey: string | undefined;
    bwkVaultKeyIv: string | undefined;
    bwkVaultKeyTag: string | undefined;
  };
  itemCount: number;
}

async function processUserBackup(user: {
  _id: unknown;
  email: string;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  settings: {
    backup: {
      enabled: boolean;
      backupEmails?: string[];
      encryptedBWK?: string;
      bwkIv?: string;
      bwkTag?: string;
      bwkSalt?: string;
      bwkEncryptedVaultKey?: string;
      bwkVaultKeyIv?: string;
      bwkVaultKeyTag?: string;
    };
  };
}): Promise<void> {
  const userId = String(user._id);
  const emails = user.settings.backup.backupEmails?.length
    ? user.settings.backup.backupEmails
    : [user.email];

  try {
    const maxSizeBytes = config.BACKUP_MAX_SIZE_MB * 1024 * 1024;
    const items: unknown[] = [];
    const folders: unknown[] = [];
    let estimatedSize = 0;

    // Stream folders and vault items via cursors against a shared size budget,
    // mirroring the strategy used by the manual backup trigger and the export
    // endpoint. The conservative field-length estimator (see
    // `utils/sizeEstimator.ts`) avoids per-iteration JSON.stringify in the hot
    // loop; the final payload is serialized once below.
    const folderCursor = Folder.find({ userId }).select('-sourceRefId').lean().cursor();
    for await (const folder of folderCursor) {
      estimatedSize += estimateFolderJsonSize(folder as unknown as Record<string, unknown>);
      if (estimatedSize > maxSizeBytes) {
        logger.warn(`Backup for user ${userId} exceeds max size during folder streaming`);
        await BackupLog.create({
          userId,
          status: 'failed',
          errorMessage: 'Backup file exceeds maximum size limit',
          sentTo: emails,
          timestamp: new Date(),
        });
        return;
      }
      folders.push(folder);
    }

    const itemCursor = VaultItem.find({
      userId,
      deletedAt: { $exists: false },
    })
      .select('-sourceRefId')
      .lean()
      .cursor();

    for await (const item of itemCursor) {
      estimatedSize += estimateItemJsonSize(item as unknown as Record<string, unknown>);
      if (estimatedSize > maxSizeBytes) {
        logger.warn(`Backup for user ${userId} exceeds max size during item streaming`);
        await BackupLog.create({
          userId,
          status: 'failed',
          errorMessage: 'Backup file exceeds maximum size limit',
          sentTo: emails,
          timestamp: new Date(),
        });
        return;
      }
      items.push(item);
    }

    const backupData: BackupPayload = {
      version: APP_VERSION,
      formatVersion: 1,
      timestamp: new Date().toISOString(),
      encryptionVersion: 1,
      items,
      folders,
      // Include encrypted vault key for cross-account restore re-encryption
      encryptedVaultKey: user.encryptedVaultKey,
      vaultKeyIv: user.vaultKeyIv,
      vaultKeyTag: user.vaultKeyTag,
      // Include backup encryption metadata for self-contained cross-account restore
      backupEncryption: {
        encryptedBWK: user.settings.backup.encryptedBWK,
        bwkIv: user.settings.backup.bwkIv,
        bwkTag: user.settings.backup.bwkTag,
        bwkSalt: user.settings.backup.bwkSalt,
        bwkEncryptedVaultKey: user.settings.backup.bwkEncryptedVaultKey,
        bwkVaultKeyIv: user.settings.backup.bwkVaultKeyIv,
        bwkVaultKeyTag: user.settings.backup.bwkVaultKeyTag,
      },
      itemCount: items.length,
    };

    const backupJson = JSON.stringify(backupData);
    const backupBuffer = Buffer.from(backupJson, 'utf-8');

    if (backupBuffer.length > maxSizeBytes) {
      logger.warn(
        `Backup for user ${userId} exceeds max size (${String(backupBuffer.length)} bytes)`,
      );
      await BackupLog.create({
        userId,
        status: 'failed',
        errorMessage: 'Backup file exceeds maximum size limit',
        sentTo: emails,
        timestamp: new Date(),
      });
      return;
    }

    const safeAppName = escapeHtml(config.APP_NAME);
    const subject = `${config.APP_NAME} - Encrypted Vault Backup`;
    const html = `<h2>${safeAppName} Encrypted Backup</h2>
       <p>Your encrypted vault backup is attached.</p>
       <p>This backup was generated on ${new Date().toLocaleString()}.</p>
       <p>Items backed up: ${String(items.length)}</p>
       <p><strong>This file can only be restored through the ${safeAppName} application using your backup encryption password.</strong></p>`;
    const attachment = {
      filename: `hvault-backup-${new Date().toISOString().split('T')[0]}.enc`,
      content: backupBuffer,
      contentType: 'application/octet-stream',
    };

    let emailsSentCount = 0;
    const failedEmails: string[] = [];

    for (const email of emails) {
      const emailResult = await sendEmail(email, subject, html, [attachment]);
      if (emailResult.success) {
        emailsSentCount++;
      } else {
        failedEmails.push(email);
        logger.warn(
          `Backup email failed for user ${userId} to ${maskEmail(email)}: ${emailResult.message}`,
        );
      }
    }

    if (emailsSentCount === 0) {
      await BackupLog.create({
        userId,
        status: 'failed',
        errorMessage: `Email delivery failed for: ${failedEmails.join(', ')}`,
        sentTo: emails,
        timestamp: new Date(),
      }).catch((_e: unknown) => {
        /* best effort */
      });

      await User.findByIdAndUpdate(userId, {
        'settings.backup.lastBackupAt': new Date(),
        'settings.backup.lastBackupStatus': 'failed',
      }).catch((_e: unknown) => {
        /* best effort */
      });

      return;
    }

    try {
      await BackupLog.create({
        userId,
        status: 'success',
        fileSizeBytes: backupBuffer.length,
        itemCount: items.length,
        sentTo: emails,
        ...(failedEmails.length > 0
          ? { errorMessage: `Email delivery failed for: ${failedEmails.join(', ')}` }
          : {}),
        timestamp: new Date(),
      });
      await User.findByIdAndUpdate(userId, {
        'settings.backup.lastBackupAt': new Date(),
        'settings.backup.lastBackupStatus': 'success',
      });
    } catch (statusError) {
      await User.findByIdAndUpdate(userId, {
        'settings.backup.lastBackupAt': new Date(),
        'settings.backup.lastBackupStatus': 'failed',
      }).catch((_e: unknown) => {
        /* best effort */
      });
      throw statusError;
    }

    logger.info(
      `Backup sent for user ${userId} (${String(items.length)} items, ${String(emailsSentCount)}/${String(emails.length)} emails)`,
    );
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.error(`Backup failed for user ${userId}: ${message}`);

    await BackupLog.create({
      userId,
      status: 'failed',
      errorMessage: 'Backup processing failed',
      sentTo: emails,
      timestamp: new Date(),
    }).catch((_e: unknown) => {
      /* best effort */
    });

    await User.findByIdAndUpdate(userId, {
      'settings.backup.lastBackupAt': new Date(),
      'settings.backup.lastBackupStatus': 'failed',
    }).catch((_e: unknown) => {
      /* best effort */
    });
  }
}

const BACKUP_LOCK_TTL_MS = 30 * 60 * 1000; // 30 minutes

export function startBackupScheduler(): ScheduledTask {
  // Run every hour, check which users need backups at this hour
  const task = cron.schedule(
    '0 * * * *',
    () => {
      const jobPromise = (async () => {
        let lockId: string | null = null;
        try {
          lockId = await acquireJobLock('backup-scheduler', BACKUP_LOCK_TTL_MS);
          if (!lockId) {
            logger.info('Backup scheduler skipped: another instance holds the lock');
            return;
          }

          const currentHour = new Date().getUTCHours();

          const userCursor = User.find({
            'settings.backup.enabled': true,
            'settings.backup.scheduleHour': currentHour,
            'settings.backup.encryptedBWK': { $exists: true, $ne: '' },
          })
            .lean()
            .cursor();

          let userCount = 0;
          let batch: Parameters<typeof processUserBackup>[0][] = [];
          const batchSize = 5;

          for await (const user of userCursor) {
            batch.push(user as Parameters<typeof processUserBackup>[0]);
            userCount++;

            if (batch.length >= batchSize) {
              await Promise.allSettled(batch.map((u) => processUserBackup(u)));
              batch = [];
            }
          }

          // Process any remaining users in the final partial batch
          if (batch.length > 0) {
            await Promise.allSettled(batch.map((u) => processUserBackup(u)));
          }

          if (userCount > 0) {
            logger.info(
              `Processed backups for ${String(userCount)} users at hour ${String(currentHour)} UTC`,
            );
          }
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          logger.error(`Backup scheduler failed: ${message}`);
        } finally {
          // Only release a lock we actually acquired, and never let a transient
          // release failure escape the job promise (it would surface as an
          // unhandled rejection via the tracker bookkeeping chain).
          if (lockId) {
            try {
              await releaseJobLock('backup-scheduler', lockId);
            } catch (releaseErr: unknown) {
              const msg = releaseErr instanceof Error ? releaseErr.message : 'Unknown error';
              logger.error(`Failed to release backup-scheduler lock: ${msg}`);
            }
          }
        }
      })();
      trackJob(jobPromise);
      return jobPromise;
    },
    { timezone: 'UTC' },
  );

  logger.info('Backup scheduler started (checks every hour)');
  return task;
}
