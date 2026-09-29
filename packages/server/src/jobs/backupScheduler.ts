import cron, { type ScheduledTask } from 'node-cron';
import { createModuleLogger } from '../utils/logger.js';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { BackupLog } from '../models/BackupLog.js';
import { sendEmail, escapeHtml, isEmailConfigured } from '../utils/email.js';
import { config } from '../config/index.js';
import { APP_VERSION, maskEmail } from '@hvault/shared';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';
import { collectDocumentSummary, type DocumentSummary } from '../utils/documentSummary.js';
import { acquireWithin, heavyResponseSemaphore } from '../utils/heavyResponseBudget.js';
import { claimOutboundMail } from '../utils/outboundMailBudget.js';
import {
  confirmedRecipientsFor,
  currentRecipientsFor,
  noteBackupDelivered,
  recordUndeliverableBackup,
  type UndeliverableReason,
} from '../utils/backupRecipients.js';
import { recordJobAuditEntries } from '../services/auditService.js';
import type { IBackupRecipientDoc } from '../models/User.js';

const logger = createModuleLogger('jobs/backup');

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
  /**
   * The documents this backup does NOT contain — see `utils/documentSummary.ts`.
   * Carried by the SCHEDULED payload as well as the manual one, because a
   * breadcrumb only the download had would leave the backup most users actually
   * receive silently incomplete.
   */
  documentSummary: DocumentSummary;
}

/**
 * How long one account's scheduled backup waits for a heavy-response slot before it
 * is recorded as failed and the run moves on (5 minutes). Bounded so a burst of
 * downloads cannot stall the whole run past its 30-minute lock. A plain object so a
 * test can shorten it; nothing in production writes to it.
 */
export const SCHEDULED_BACKUP_SLOT_POLICY = { waitMs: 5 * 60 * 1000 };

type ScheduledUser = Parameters<typeof buildAndMailBackup>[0];

/**
 * One account's scheduled backup, inside one of the process's heavy-response slots:
 * the same budget the download, the export and the manual trigger are admitted
 * through, because this builds the same whole-vault document. It waits for a slot
 * (a job has no request to refuse) for at most {@link SCHEDULED_BACKUP_SLOT_POLICY}.
 */
async function processUserBackup(user: ScheduledUser): Promise<void> {
  // Who may receive it is decided BEFORE a slot is taken: a run that can mail
  // nobody is recorded without reading the vault or holding a slot another
  // account's backup is waiting for.
  if (confirmedRecipientsFor(user).length === 0) {
    const userId = String(user._id);
    logger.info(`Backup for user ${userId} not sent: no recipient has confirmed`);
    await recordUndeliverable(userId, 'no_confirmed_recipient').catch((err: unknown) => {
      logger.error(`Could not record the undeliverable backup of user ${userId}: ${String(err)}`);
    });
    return;
  }
  const release = await acquireWithin(heavyResponseSemaphore, SCHEDULED_BACKUP_SLOT_POLICY.waitMs);
  if (release === null) {
    const userId = String(user._id);
    logger.warn(`Backup for user ${userId} skipped: no heavy-response slot became free in time`);
    await BackupLog.create({
      userId,
      status: 'failed',
      errorMessage: 'The server was busy with other backups; it will retry at the next schedule',
      sentTo: [],
      timestamp: new Date(),
    }).catch((_e: unknown) => {
      /* best effort */
    });
    return;
  }
  try {
    await buildAndMailBackup(user);
  } finally {
    release();
  }
}

/**
 * Records a scheduled run that mails nothing (see `recordUndeliverableBackup`),
 * with the audit row written the way jobs write theirs.
 */
function recordUndeliverable(userId: string, reason: UndeliverableReason): Promise<void> {
  return recordUndeliverableBackup(userId, reason, (metadata) =>
    recordJobAuditEntries([
      {
        userId,
        action: 'backup_failed',
        metadata,
        ipAddress: 'system',
        userAgent: 'system/backup-scheduler',
      },
    ]),
  );
}

async function buildAndMailBackup(user: {
  _id: unknown;
  email: string;
  emailVerified?: boolean;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  settings: {
    backup: {
      enabled: boolean;
      backupRecipients?: IBackupRecipientDoc[];
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
  // The ONE recipient rule the manual trigger uses too: confirmed entries only, the
  // account's own verified address when there is no list, and NEVER the account
  // address as a stand-in for a list nobody on has confirmed.
  let emails = confirmedRecipientsFor(user);

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
      documentSummary: await collectDocumentSummary(userId),
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

    // Re-checked at the last moment: an erasure that began while this backup
    // was being assembled wins, and nothing is mailed or logged for it.
    if ((await User.exists({ _id: userId, deletionPending: { $ne: true } })) === null) {
      logger.info(`Backup for user ${userId} skipped: the account is being erased`);
      return;
    }

    // Who may receive it NOW, read fresh from the primary: the account was read at
    // the start of the run and the slot may have been waited for, and a recovery
    // that suspended a recipient in between must stop the mail to it.
    emails = await currentRecipientsFor(userId);
    if (emails.length === 0) {
      logger.info(`Backup for user ${userId} not sent: no recipient is confirmed any more`);
      await recordUndeliverable(userId, 'no_confirmed_recipient');
      return;
    }

    // The day's outbound budget, for every recipient at once, before the first send
    // (not claimed with email off: nothing would be sent).
    if (isEmailConfigured() && !(await claimOutboundMail(userId, emails.length))) {
      logger.info(`Backup for user ${userId} not sent: the daily email limit is reached`);
      await recordUndeliverable(userId, 'daily_mail_budget');
      return;
    }

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
      await noteBackupDelivered(userId);
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
            // An account being erased is never backed up: mailing its vault would
            // send data the owner asked to have destroyed, and the backup log row
            // (which names the recipients) would outlive the erasure.
            deletionPending: { $ne: true },
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
