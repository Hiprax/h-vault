import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { BackupLog } from '../models/BackupLog.js';
import { createAuditLog } from '../services/auditService.js';
import { sendEmail, escapeHtml } from '../utils/email.js';
import { config, emailConfigured } from '../config/index.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import {
  assertVaultNotRotating,
  getRequestContext,
  getUserId,
  pickAllowedFields,
} from '../utils/controllerHelpers.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';
import { hasCycle } from '../utils/folderGraph.js';
import {
  APP_VERSION,
  ITEM_TYPES,
  MAX_IMPORT_ITEMS,
  MAX_ITEMS_PER_USER,
  MAX_FOLDERS_PER_USER,
  maskEmail,
} from '@hvault/shared';
import type {
  BackupSetupInput,
  BackupSettingsInput,
  BackupChangePasswordInput,
  BackupHistoryInput,
  RestoreBackupInput,
  IItemSkipReason,
  IFolderSkipReason,
} from '@hvault/shared';

const logger = createLogger({ moduleName: 'backup-controller' });

/** TTL for the per-user backup trigger lock (5 minutes). */
const BACKUP_TRIGGER_LOCK_TTL_MS = 5 * 60 * 1000;

// ── Helpers ──────────────────────────────────────────────────────────

const ALLOWED_FOLDER_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'searchHash',
  'parentId',
  'icon',
  'color',
  'sortOrder',
]);

const ALLOWED_ITEM_FIELDS = new Set([
  'encryptedData',
  'dataIv',
  'dataTag',
  'encryptedName',
  'nameIv',
  'nameTag',
  'itemType',
  'tags',
  'favorite',
  'folderId',
  'searchHash',
  'passwordHistory',
]);

// A searchHash is an HMAC-SHA256 digest rendered as 64 lowercase hex chars. The
// Folder/VaultItem models enforce this via a `match` validator, so a backup row
// (legacy or tampered) carrying any other shape would otherwise throw a Mongoose
// ValidationError mid-restore. Mirrors `sanitizeImportFields` in toolsController.
const SEARCH_HASH_RE = /^[a-f0-9]{64}$/;

/**
 * Counts how many backup rows a restore will actually INSERT as net-new documents,
 * so the per-user caps reflect real collection growth rather than raw backup size.
 *
 * - `keep_both` always mints a fresh row per backup entry → every row is net-new
 *   (this is exactly the unbounded growth the caps exist to bound).
 * - `skip` / `overwrite` insert ONLY rows with no existing match; a row whose
 *   backup `_id` is already owned, or matches an existing `(userId, sourceRefId)`
 *   provenance row, is skipped / updated in place and adds nothing. Counting those
 *   as insertions would falsely 400 an idempotent repeat restore once
 *   existing + backup crosses the cap, breaking the documented "fully idempotent
 *   across repeated restores" guarantee.
 * - A backup row with a missing / invalid `_id` gets a freshly-minted id, so it can
 *   never match and always counts as net-new.
 *
 * `matchExisting` returns the subset of the candidate ids that already exist for
 * the user (by owned `_id` or by `sourceRefId`); it is injected so the caller
 * supplies the concrete model (VaultItem or Folder). The `(userId, sourceRefId)`
 * partial index backs its provenance lookup.
 */
async function countNetNewRestoreRows(
  backupRows: Record<string, unknown>[],
  conflictStrategy: RestoreBackupInput['conflictStrategy'],
  matchExisting: (candidateIds: string[]) => Promise<Set<string>>,
): Promise<number> {
  if (backupRows.length === 0) return 0;
  // keep_both duplicates unconditionally, so every backup row is a fresh insert.
  if (conflictStrategy === 'keep_both') return backupRows.length;

  const candidateIds: string[] = [];
  let netNew = 0;
  for (const row of backupRows) {
    if (mongoose.isValidObjectId(row._id)) {
      candidateIds.push(String(row._id));
    } else {
      netNew++; // no valid _id → a fresh id is minted → always net-new
    }
  }
  if (candidateIds.length === 0) return netNew;

  const matched = await matchExisting(candidateIds);
  for (const id of candidateIds) {
    if (!matched.has(id)) netNew++;
  }
  return netNew;
}

async function collectBackupData(
  userId: string,
  maxSizeBytes: number,
): Promise<{
  json: string;
  itemCount: number;
}> {
  const user = await User.findById(userId).lean();

  // Stream both folders and vault items via cursors and accumulate against a
  // shared size budget. Folders run first because items frequently reference
  // them in the final payload structure. Both share the same field-length
  // estimator (see `utils/sizeEstimator.ts`) used by the export endpoint, so
  // we never serialize per-row in the hot loop.
  const items: unknown[] = [];
  const folders: unknown[] = [];
  let estimatedSize = 0;

  const folderCursor = Folder.find({ userId }).select('-sourceRefId').lean().cursor();
  for await (const folder of folderCursor) {
    estimatedSize += estimateFolderJsonSize(folder as unknown as Record<string, unknown>);
    if (estimatedSize > maxSizeBytes) {
      throw httpErrors.payloadTooLarge(
        `Backup size exceeds the maximum allowed size during collection`,
      );
    }
    folders.push(folder);
  }

  const itemCursor = VaultItem.find({ userId, deletedAt: { $exists: false } })
    .select('-sourceRefId')
    .lean()
    .cursor();
  for await (const item of itemCursor) {
    estimatedSize += estimateItemJsonSize(item as unknown as Record<string, unknown>);
    if (estimatedSize > maxSizeBytes) {
      throw httpErrors.payloadTooLarge(
        `Backup size exceeds the maximum allowed size during collection`,
      );
    }
    items.push(item);
  }

  const backupPayload = {
    version: APP_VERSION,
    exportDate: new Date().toISOString(),
    items,
    folders,
    encryptedVaultKey: user?.encryptedVaultKey,
    vaultKeyIv: user?.vaultKeyIv,
    vaultKeyTag: user?.vaultKeyTag,
    backupEncryption: {
      encryptedBWK: user?.settings.backup.encryptedBWK,
      bwkIv: user?.settings.backup.bwkIv,
      bwkTag: user?.settings.backup.bwkTag,
      bwkSalt: user?.settings.backup.bwkSalt,
      bwkEncryptedVaultKey: user?.settings.backup.bwkEncryptedVaultKey,
      bwkVaultKeyIv: user?.settings.backup.bwkVaultKeyIv,
      bwkVaultKeyTag: user?.settings.backup.bwkVaultKeyTag,
    },
    metadata: {
      itemCount: items.length,
      folderCount: folders.length,
    },
  };

  return {
    json: JSON.stringify(backupPayload),
    itemCount: items.length,
  };
}

// ── Handlers ─────────────────────────────────────────────────────────

export const setupBackup = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as BackupSetupInput;

  // Verify current password before allowing backup setup — prevents an attacker
  // with a stolen JWT from overwriting the backup encryption configuration.
  const existingUser = await User.findById(userId).select('+authHash');
  if (!existingUser) {
    throw httpErrors.notFound('User not found');
  }

  const isMatch = await bcrypt.compare(body.authHash, existingUser.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'backup_setup' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  const setFields: Record<string, unknown> = {
    'settings.backup.encryptedBWK': body.encryptedBWK,
    'settings.backup.bwkIv': body.bwkIv,
    'settings.backup.bwkTag': body.bwkTag,
    'settings.backup.bwkSalt': body.bwkSalt,
    'settings.backup.isConfigured': true,
  };

  const unsetFields: Record<string, 1> = {};

  if (body.bwkEncryptedVaultKey && body.bwkVaultKeyIv && body.bwkVaultKeyTag) {
    setFields['settings.backup.bwkEncryptedVaultKey'] = body.bwkEncryptedVaultKey;
    setFields['settings.backup.bwkVaultKeyIv'] = body.bwkVaultKeyIv;
    setFields['settings.backup.bwkVaultKeyTag'] = body.bwkVaultKeyTag;
  } else {
    // Explicitly remove stale BWK-encrypted vault key (e.g. after vault key rotation)
    unsetFields['settings.backup.bwkEncryptedVaultKey'] = 1;
    unsetFields['settings.backup.bwkVaultKeyIv'] = 1;
    unsetFields['settings.backup.bwkVaultKeyTag'] = 1;
  }

  const updateOp: Record<string, unknown> = { $set: setFields };
  if (Object.keys(unsetFields).length > 0) {
    updateOp.$unset = unsetFields;
  }

  const user = await User.findByIdAndUpdate(userId, updateOp, { returnDocument: 'after' })
    .select('-__v')
    .lean();

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  const setupCtx = getRequestContext(req);
  await createAuditLog(userId, 'backup_setup', undefined, setupCtx.ip, setupCtx.userAgent);

  logger.info('Backup configured', { userId });

  res.status(200).json({
    success: true,
    message: 'Backup password configured',
  });
});

export const updateBackupSettings = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);
    const body = req.body as BackupSettingsInput;

    const setFields: Record<string, unknown> = {};
    const unsetFields: Record<string, unknown> = {};

    if (body.enabled !== undefined) {
      setFields['settings.backup.enabled'] = body.enabled;
    }
    if (body.scheduleHour !== undefined) {
      setFields['settings.backup.scheduleHour'] = body.scheduleHour;
    }
    if (body.backupEmails !== undefined) {
      setFields['settings.backup.backupEmails'] = body.backupEmails;
      // Clean up deprecated backupEmail field
      unsetFields['settings.backup.backupEmail'] = 1;
    }

    if (Object.keys(setFields).length === 0) {
      throw httpErrors.badRequest('No backup settings provided to update');
    }

    // If enabling backup, require encryption to be configured
    if (body.enabled === true) {
      const existingUser = await User.findById(userId).lean();
      if (!existingUser) {
        throw httpErrors.notFound('User not found');
      }
      if (!existingUser.settings.backup.isConfigured) {
        throw httpErrors.badRequest('Backup encryption must be configured before enabling backups');
      }
    }

    const updateOp: Record<string, unknown> = { $set: setFields };
    if (Object.keys(unsetFields).length > 0) {
      updateOp.$unset = unsetFields;
    }

    const user = await User.findByIdAndUpdate(userId, updateOp, { returnDocument: 'after' })
      .select('-__v')
      .lean();

    if (!user) {
      throw httpErrors.notFound('User not found');
    }

    const settingsCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'backup_settings_update',
      { updatedFields: Object.keys(setFields) },
      settingsCtx.ip,
      settingsCtx.userAgent,
    );

    logger.info('Backup settings updated', { userId });

    res.status(200).json({
      success: true,
      message: 'Backup settings updated',
      data: user.settings.backup,
    });
  },
);

export const triggerBackup = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const user = await User.findById(userId).lean();

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  if (!user.settings.backup.isConfigured) {
    throw httpErrors.badRequest('Backup encryption must be configured before triggering backups');
  }

  // Per-user deduplication via distributed MongoDB lock — works across PM2 cluster workers.
  const backupJobName = `backup:trigger:${userId}`;
  const lockId = await acquireJobLock(backupJobName, BACKUP_TRIGGER_LOCK_TTL_MS);
  if (!lockId) {
    throw httpErrors.conflict('A backup is already in progress for this account');
  }

  // Collect response data inside try, release lock in finally, then send response.
  // This ensures the lock is released before the HTTP response reaches the client.
  let responseData: {
    itemCount: number;
    fileSizeBytes: number;
    emailSent: boolean;
    emailsSent: number;
    emailsFailed: number;
    failedEmails: string[];
    emails: string[];
  };

  try {
    const maxSizeBytes = config.BACKUP_MAX_SIZE_MB * 1024 * 1024;
    const { json, itemCount } = await collectBackupData(userId, maxSizeBytes);
    const fileSizeBytes = Buffer.byteLength(json, 'utf8');

    // Final size check on the complete serialized payload (includes metadata overhead)
    if (fileSizeBytes > maxSizeBytes) {
      throw httpErrors.payloadTooLarge(
        `Backup size (${String(Math.ceil(fileSizeBytes / (1024 * 1024)))} MB) exceeds the maximum allowed size (${String(config.BACKUP_MAX_SIZE_MB)} MB)`,
      );
    }

    // Determine recipient emails
    const emails = user.settings.backup.backupEmails?.length
      ? user.settings.backup.backupEmails
      : [user.email];

    let emailsSentCount = 0;
    let emailsFailedCount = 0;
    const failedEmails: string[] = [];

    if (emailConfigured) {
      const backupBuffer = Buffer.from(json, 'utf-8');
      const safeAppName = escapeHtml(config.APP_NAME);
      const subject = `${config.APP_NAME} - Encrypted Vault Backup`;
      const html = `<h2>${safeAppName} Encrypted Backup</h2>
       <p>Your encrypted vault backup is attached.</p>
       <p>This backup was generated on ${new Date().toLocaleString()}.</p>
       <p>Items backed up: ${String(itemCount)}</p>
       <p><strong>This file can only be restored through the ${safeAppName} application using your backup encryption password.</strong></p>`;
      const attachment = {
        filename: `hvault-backup-${new Date().toISOString().split('T')[0]}.enc`,
        content: backupBuffer,
        contentType: 'application/octet-stream',
      };

      for (const email of emails) {
        const emailResult = await sendEmail(email, subject, html, [attachment]);
        if (emailResult.success) {
          emailsSentCount++;
        } else {
          emailsFailedCount++;
          failedEmails.push(email);
          logger.warn('Backup email failed during manual trigger', {
            userId,
            email: maskEmail(email),
            error: emailResult.message,
          });
        }
      }
    }

    const emailSent = emailsSentCount > 0;
    const status = emailSent ? 'success' : emailConfigured ? 'failed' : 'success';

    await BackupLog.create({
      userId,
      status,
      fileSizeBytes,
      itemCount,
      sentTo: emails,
      ...(failedEmails.length > 0
        ? { errorMessage: `Email delivery failed for: ${failedEmails.join(', ')}` }
        : {}),
    });

    await User.findByIdAndUpdate(userId, {
      $set: {
        'settings.backup.lastBackupAt': new Date(),
        'settings.backup.lastBackupStatus': status,
      },
    });

    const triggerCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'backup_triggered',
      {
        itemCount,
        fileSizeBytes,
        emailSent,
        emailsSent: emailsSentCount,
        emailsFailed: emailsFailedCount,
      },
      triggerCtx.ip,
      triggerCtx.userAgent,
    );

    logger.info('Backup triggered', {
      userId,
      itemCount,
      fileSizeBytes,
      emailsSentCount,
      emailsFailedCount,
    });

    responseData = {
      itemCount,
      fileSizeBytes,
      emailSent,
      emailsSent: emailsSentCount,
      emailsFailed: emailsFailedCount,
      failedEmails,
      emails,
    };
  } finally {
    await releaseJobLock(backupJobName, lockId);
  }

  res.status(200).json({
    success: true,
    message:
      responseData.emailsSent === responseData.emails.length
        ? 'Backup created and sent successfully'
        : responseData.emailsSent > 0
          ? `Backup created. Sent to ${String(responseData.emailsSent)}/${String(responseData.emails.length)} recipients`
          : emailConfigured
            ? 'Backup created but all email deliveries failed'
            : 'Backup created successfully (email not configured)',
    data: {
      itemCount: responseData.itemCount,
      fileSizeBytes: responseData.fileSizeBytes,
      emailSent: responseData.emailSent,
      emailsSent: responseData.emailsSent,
      emailsFailed: responseData.emailsFailed,
      failedEmails: responseData.failedEmails,
    },
  });
});

export const downloadBackup = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const user = await User.findById(userId).lean();

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  if (!user.settings.backup.isConfigured) {
    throw httpErrors.badRequest('Backup encryption must be configured before downloading backups');
  }

  const maxSizeBytes = config.BACKUP_MAX_SIZE_MB * 1024 * 1024;
  const { json, itemCount } = await collectBackupData(userId, maxSizeBytes);
  const fileSizeBytes = Buffer.byteLength(json, 'utf8');

  // Final size check on the complete serialized payload (includes metadata overhead)
  if (fileSizeBytes > maxSizeBytes) {
    throw httpErrors.payloadTooLarge(
      `Backup size exceeds the maximum allowed size (${String(config.BACKUP_MAX_SIZE_MB)} MB)`,
    );
  }

  await BackupLog.create({
    userId,
    status: 'success',
    fileSizeBytes,
    itemCount,
    sentTo: ['download'],
  });

  const downloadCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'backup_download',
    { fileSizeBytes, itemCount },
    downloadCtx.ip,
    downloadCtx.userAgent,
  );

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `hvault-backup-${timestamp}.enc`;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', String(fileSizeBytes));

  res.status(200).send(json);
});

export const getBackupHistory = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const { page, limit } = req.query as unknown as BackupHistoryInput;
  const skip = (page - 1) * limit;

  const [logs, total] = await Promise.all([
    BackupLog.find({ userId })
      .select('-userId')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    BackupLog.countDocuments({ userId }),
  ]);

  const totalPages = Math.ceil(total / limit);

  res.status(200).json({
    success: true,
    data: logs,
    pagination: {
      page,
      limit,
      total,
      totalPages,
    },
  });
});

export const changeBackupPassword = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);
    const body = req.body as BackupChangePasswordInput;

    // Verify current password before allowing backup password change
    const existingUser = await User.findById(userId).select('+authHash');
    if (!existingUser) {
      throw httpErrors.notFound('User not found');
    }

    const isMatch = await bcrypt.compare(body.password, existingUser.authHash);
    if (!isMatch) {
      const failCtx = getRequestContext(req);
      await createAuditLog(
        userId,
        'password_verification_failed',
        { endpoint: 'change_backup_password' },
        failCtx.ip,
        failCtx.userAgent,
      );
      throw httpErrors.unauthorized('Current password is incorrect');
    }

    const pwSetFields: Record<string, unknown> = {
      'settings.backup.encryptedBWK': body.newEncryptedBWK,
      'settings.backup.bwkIv': body.newBwkIv,
      'settings.backup.bwkTag': body.newBwkTag,
      'settings.backup.bwkSalt': body.newBwkSalt,
    };

    const pwUnsetFields: Record<string, 1> = {};

    if (body.newBwkEncryptedVaultKey && body.newBwkVaultKeyIv && body.newBwkVaultKeyTag) {
      pwSetFields['settings.backup.bwkEncryptedVaultKey'] = body.newBwkEncryptedVaultKey;
      pwSetFields['settings.backup.bwkVaultKeyIv'] = body.newBwkVaultKeyIv;
      pwSetFields['settings.backup.bwkVaultKeyTag'] = body.newBwkVaultKeyTag;
    } else {
      pwUnsetFields['settings.backup.bwkEncryptedVaultKey'] = 1;
      pwUnsetFields['settings.backup.bwkVaultKeyIv'] = 1;
      pwUnsetFields['settings.backup.bwkVaultKeyTag'] = 1;
    }

    const pwUpdateOp: Record<string, unknown> = { $set: pwSetFields };
    if (Object.keys(pwUnsetFields).length > 0) {
      pwUpdateOp.$unset = pwUnsetFields;
    }

    const user = await User.findByIdAndUpdate(userId, pwUpdateOp, { returnDocument: 'after' })
      .select('-__v')
      .lean();

    if (!user) {
      throw httpErrors.notFound('User not found');
    }

    const changeCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'backup_password_changed',
      undefined,
      changeCtx.ip,
      changeCtx.userAgent,
    );

    logger.info('Backup password changed', { userId });

    res.status(200).json({
      success: true,
      message: 'Backup password changed successfully',
    });
  },
);

export const restoreBackup = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as RestoreBackupInput;
  const { conflictStrategy, data } = body;

  // A restore NEVER replaces the caller's vault key. The client re-encrypts every
  // backup row to this account's current vault key before sending, so restore only
  // ever adds/updates rows that are already decryptable under the account's key.
  // That is exactly why it must be fenced during a rotation: the key the client
  // re-encrypted against is the one the rotation is replacing.
  await assertVaultNotRotating(userId);

  // Parse the backup data (client sends already-decrypted JSON)
  let backupPayload: {
    items?: Record<string, unknown>[];
    folders?: Record<string, unknown>[];
  };

  try {
    backupPayload = JSON.parse(data) as typeof backupPayload;
  } catch {
    throw httpErrors.badRequest('Invalid backup data: malformed JSON');
  }

  const backupItems = backupPayload.items ?? [];
  const backupFolders = backupPayload.folders ?? [];

  const totalEntries = backupItems.length + backupFolders.length;
  if (totalEntries > MAX_IMPORT_ITEMS) {
    throw httpErrors.badRequest(
      `Restore exceeds the maximum allowed item count (${String(MAX_IMPORT_ITEMS)}). Received ${String(totalEntries)} entries.`,
    );
  }

  // Enforce the per-user item + folder caps against the number of rows this
  // restore will actually INSERT, not the raw backup size. Under skip / overwrite
  // a repeat restore matches prior rows by owned `_id` or `(userId, sourceRefId)`
  // and inserts nothing, so a blunt `existing + backup.length` sum would falsely
  // reject an idempotent repeat restore once it crosses the cap — breaking the
  // "fully idempotent across repeated restores" guarantee. keep_both always mints
  // fresh rows, so there every backup row counts (the growth the cap bounds).
  const existingItemCount = await VaultItem.countDocuments({ userId });
  const netNewItems = await countNetNewRestoreRows(backupItems, conflictStrategy, async (ids) => {
    const objectIds = ids.map((id) => new mongoose.Types.ObjectId(id));
    const [owned, bySourceRef] = await Promise.all([
      VaultItem.find({ userId, _id: { $in: objectIds } })
        .select('_id')
        .lean(),
      VaultItem.find({ userId, sourceRefId: { $in: ids } })
        .select('sourceRefId')
        .lean(),
    ]);
    const matched = new Set<string>();
    for (const r of owned) matched.add(String(r._id));
    for (const r of bySourceRef) {
      if (typeof r.sourceRefId === 'string') matched.add(r.sourceRefId);
    }
    return matched;
  });
  if (existingItemCount + netNewItems > MAX_ITEMS_PER_USER) {
    throw httpErrors.badRequest(
      `Restore would exceed the per-user item limit (${String(MAX_ITEMS_PER_USER)}). You currently have ${String(existingItemCount)} items and this restore would add ${String(netNewItems)}.`,
    );
  }

  const existingFolderCount = await Folder.countDocuments({ userId });
  const netNewFolders = await countNetNewRestoreRows(
    backupFolders,
    conflictStrategy,
    async (ids) => {
      const objectIds = ids.map((id) => new mongoose.Types.ObjectId(id));
      const [owned, bySourceRef] = await Promise.all([
        Folder.find({ userId, _id: { $in: objectIds } })
          .select('_id')
          .lean(),
        Folder.find({ userId, sourceRefId: { $in: ids } })
          .select('sourceRefId')
          .lean(),
      ]);
      const matched = new Set<string>();
      for (const r of owned) matched.add(String(r._id));
      for (const r of bySourceRef) {
        if (typeof r.sourceRefId === 'string') matched.add(r.sourceRefId);
      }
      return matched;
    },
  );
  if (existingFolderCount + netNewFolders > MAX_FOLDERS_PER_USER) {
    throw httpErrors.badRequest(
      `Restore would exceed the per-user folder limit (${String(MAX_FOLDERS_PER_USER)}). You currently have ${String(existingFolderCount)} folders and this restore would add ${String(netNewFolders)}.`,
    );
  }

  let itemsRestored = 0;
  let itemsSkipped = 0;
  let foldersRestored = 0;
  let foldersSkipped = 0;
  const itemSkipReasons: IItemSkipReason[] = [];
  const folderSkipReasons: IFolderSkipReason[] = [];

  // Map old folder IDs to new folder IDs (used by keep_both to remap item folderIds)
  const folderIdMap = new Map<string, string>();

  // Restore folders first (items may reference them)
  if (backupFolders.length > 0) {
    // Only `_id` (owned-row identity) and `sourceRefId` (restore provenance) are
    // read from these rows — the conflict strategy is applied with a targeted
    // write, never from the fetched document — so project away everything else.
    // A full fetch would pull each folder's encrypted name/IV/tag into memory for
    // no reason, on a request that already holds a multi-MB backup payload.
    const existingFolders = await Folder.find({ userId }).select('_id sourceRefId').lean();
    const existingFolderIds = new Set(existingFolders.map((f) => String(f._id)));

    // Provenance index for idempotent REPEAT restores. A prior restore stamps
    // every FRESH row with `sourceRefId = the backup row's original _id`. On a
    // second restore of the same backup (cross-account, or same-account after a
    // permanent delete) that backup ref id is no longer owned by `_id`, but it
    // still matches a row's `sourceRefId` — so we can apply the conflict strategy
    // against THAT row instead of inserting a duplicate. `_id`-owned matching
    // (below) always takes precedence; this is the fallback. Non-unique index →
    // a keep_both duplicate may share a sourceRefId; the last write wins here,
    // which is deterministic per fetch and acceptable (keep_both is intentional
    // duplication, so which row skip/overwrite lands on does not matter).
    const existingFolderBySourceRef = new Map<string, (typeof existingFolders)[number]>();
    for (const f of existingFolders) {
      if (typeof f.sourceRefId === 'string') {
        existingFolderBySourceRef.set(f.sourceRefId, f);
      }
    }

    for (const folder of backupFolders) {
      const rawId = folder._id;
      const folderId = mongoose.isValidObjectId(rawId)
        ? String(rawId)
        : new mongoose.Types.ObjectId().toString();
      // Resolve the row this backup folder maps onto, in precedence order:
      //   1. owned by `_id` (the strongest identity — the user's own live row);
      //   2. else a prior-restored row matched by `(userId, sourceRefId)`.
      // `targetFolderId` is the REAL `_id` to apply the conflict strategy against
      // (for an owned match it equals `folderId`; for a sourceRefId match it is
      // the prior row's own `_id`, which differs from the backup ref). `undefined`
      // means no existing row → fresh-insert with a new `_id`.
      const ownedByBackupId = existingFolderIds.has(folderId);
      const srcMatchedFolder = ownedByBackupId
        ? undefined
        : existingFolderBySourceRef.get(folderId);
      const targetFolderId = ownedByBackupId
        ? folderId
        : srcMatchedFolder
          ? String(srcMatchedFolder._id)
          : undefined;

      const sanitizedFolder = pickAllowedFields(folder, ALLOWED_FOLDER_FIELDS);

      // Drop a malformed searchHash up front so it can never trip the model's
      // `match` validator (a ValidationError here would otherwise abort the whole
      // restore). A valid-format hash is kept; collisions are handled per-branch
      // below via the unique partial index's E11000.
      if (
        sanitizedFolder.searchHash !== undefined &&
        (typeof sanitizedFolder.searchHash !== 'string' ||
          !SEARCH_HASH_RE.test(sanitizedFolder.searchHash))
      ) {
        sanitizedFolder.searchHash = undefined;
      }

      // Drop a malformed parentId up front so an un-castable value can't throw a
      // CastError and abort the restore — the primary goal of this sanitization,
      // mirroring the item loop's folderId handling. On the create paths (fresh
      // insert / keep_both duplicate) the folder is stored without a parent; on
      // the overwrite path the stripped value is simply ignored (a bare
      // `$set: undefined` is dropped by Mongoose), so an existing folder keeps
      // its current parent rather than being yanked to the root by corrupt
      // backup data — exactly how the item loop treats a stripped folderId on
      // overwrite. A valid-but-dangling parentId is separately cleared by the
      // post-loop cleanup below.
      if (
        sanitizedFolder.parentId !== undefined &&
        !mongoose.isValidObjectId(sanitizedFolder.parentId)
      ) {
        sanitizedFolder.parentId = undefined;
      }

      // Each folder write is guarded so one bad row never aborts the whole
      // restore. The bespoke per-branch E11000 searchHash-strip retries below
      // still run FIRST (this is a compose, not a replace); this outer guard
      // catches a residual persistence-layer data error — a ValidationError
      // (missing/over-length required field), a CastError, or an E11000 that
      // even the retry couldn't resolve — and skips just that folder as
      // `invalid_folder_data`, mirroring the item loop. Anything else (a
      // transient DB failure) still propagates and fails the request.
      try {
        if (targetFolderId !== undefined) {
          // `targetFolderId` (narrowed to string) is the real `_id` of the matched
          // row — owned by backup id, or a prior-restored row keyed by sourceRefId.
          const matchedFolderId = targetFolderId;
          if (conflictStrategy === 'skip') {
            foldersSkipped++;
            folderSkipReasons.push({ folderId, reason: 'conflict_skipped' });
            // Record backupRefId -> the existing row's real id so any restored
            // child that references this backup id remaps onto the kept row.
            folderIdMap.set(folderId, matchedFolderId);
            continue;
          }
          if (conflictStrategy === 'overwrite') {
            // The folder's searchHash is in ALLOWED_FOLDER_FIELDS, so the $set can
            // write a hash that collides with a *different* sibling folder (e.g. a
            // tampered backup, or two folders renamed to the same name after the
            // backup was taken). That violates the unique partial (userId,
            // searchHash) index → E11000. Mirror the keep_both / fresh-insert
            // siblings: retry the overwrite with searchHash stripped so the rest of
            // the folder data is still applied rather than 500-ing the restore.
            try {
              await Folder.findOneAndUpdate(
                { _id: matchedFolderId, userId },
                { $set: { ...sanitizedFolder, userId } },
                { runValidators: true },
              );
              foldersRestored++;
            } catch (err: unknown) {
              if (
                err instanceof Error &&
                'code' in err &&
                (err as { code?: number }).code === 11000
              ) {
                const { searchHash: _ovwHash, ...folderWithoutHash } = sanitizedFolder;
                await Folder.findOneAndUpdate(
                  { _id: matchedFolderId, userId },
                  { $set: { ...folderWithoutHash, userId }, $unset: { searchHash: 1 } },
                  { runValidators: true },
                );
                foldersRestored++;
              } else {
                throw err;
              }
            }
            // The overwrite writes `parentId` from the raw backup row (a backup
            // ref id), so this row now needs the post-loop remap too — record it.
            folderIdMap.set(folderId, matchedFolderId);
            continue;
          }
          // keep_both: create a new folder with a new _id and record the mapping.
          // Duplication is keep_both's contract, so this fires even for a
          // sourceRefId match. The Folder model has a unique partial index on
          // (userId, searchHash); since the backup folder shares its searchHash
          // with the existing one, re-using it would throw E11000 and crash the
          // entire restore. Strip searchHash from the duplicate so the insert
          // succeeds — the user can rename the folder later, rebuilding the hash.
          // Stamp `sourceRefId = folderId` so a later restore recognizes this row.
          const { searchHash: _dupSearchHash, ...folderWithoutHash } = sanitizedFolder;
          try {
            const newFolder = await Folder.create({
              ...folderWithoutHash,
              userId,
              sourceRefId: folderId,
            });
            folderIdMap.set(folderId, String(newFolder._id));
            foldersRestored++;
          } catch (err: unknown) {
            if (
              err instanceof Error &&
              'code' in err &&
              (err as { code?: number }).code === 11000
            ) {
              foldersSkipped++;
              folderSkipReasons.push({ folderId, reason: 'conflict_skipped' });
              continue;
            }
            throw err;
          }
        } else {
          // NEW to this user: either a folder deleted since the backup was made,
          // or a foreign _id from a cross-account backup. NEVER reuse the backup's
          // _id here — MongoDB `_id` is globally unique across the whole
          // collection, so a backup id that belongs to ANOTHER account (or was
          // already restored once) would throw E11000 and — via the outer guard —
          // silently drop this folder. Mint a fresh _id (omit `_id` so Mongoose
          // generates one) and stamp `sourceRefId = folderId` (the backup ref id)
          // so a REPEAT restore of the same backup recognizes this row by
          // `(userId, sourceRefId)` instead of duplicating it. Record backupRefId
          // -> newId so child folders and items that referenced the backup id are
          // rewired by the remap below.
          //
          // The searchHash may still collide with a sibling folder (e.g. one the
          // user created post-backup with the same name) — the only remaining
          // unique index on this path is the partial (userId, searchHash). Catch
          // that E11000 and retry without searchHash rather than failing.
          try {
            const newFolder = await Folder.create({
              ...sanitizedFolder,
              userId,
              sourceRefId: folderId,
            });
            folderIdMap.set(folderId, String(newFolder._id));
            foldersRestored++;
          } catch (err: unknown) {
            if (
              err instanceof Error &&
              'code' in err &&
              (err as { code?: number }).code === 11000
            ) {
              const { searchHash: _siblingHash, ...folderWithoutHash } = sanitizedFolder;
              const retryFolder = await Folder.create({
                ...folderWithoutHash,
                userId,
                sourceRefId: folderId,
              });
              folderIdMap.set(folderId, String(retryFolder._id));
              foldersRestored++;
            } else {
              throw err;
            }
          }
        }
      } catch (err: unknown) {
        const isDataError =
          err instanceof Error && (err.name === 'ValidationError' || err.name === 'CastError');
        const isDuplicateKey =
          err instanceof Error && 'code' in err && (err as { code?: number }).code === 11000;
        if (!isDataError && !isDuplicateKey) {
          throw err;
        }
        foldersSkipped++;
        folderSkipReasons.push({ folderId, reason: 'invalid_folder_data' });
        logger.warn('Skipped malformed backup folder during restore', {
          userId,
          folderId,
          error: err instanceof Error ? err.message : 'unknown',
        });
      }
    }

    // Remap parentIds for every RESTORE-MANAGED folder. `folderIdMap` maps each
    // backup ref id -> the resulting real `_id` for EVERY branch this restore
    // touched: fresh inserts and keep_both duplicates (backupRefId -> a fresh id),
    // AND — since Phase 4 — owned `_id` and sourceRefId matches (backupRefId -> an
    // EXISTING row's id, sometimes an identity mapping where the two are equal).
    // A restored/overwritten folder is stored with its raw backup parentId (a
    // backup ref id); once the parent's resulting id is known, point the child at
    // it.
    //
    // SCOPED, not global: the remap only touches folders whose `_id` is in
    // `folderIdMap.values()` — i.e. rows this restore created OR matched. A folder
    // the user created by hand outside any restore is never a map value (its id
    // corresponds to no backup ref), so it can never be re-parented here; an
    // unscoped updateMany would instead silently relocate such live children under
    // a restored folder. Identity mappings (owned same-account skip/overwrite,
    // where backupRefId === real id) are SKIPPED below: rewriting a parentId to
    // the value it already holds is a pure no-op, and skipping avoids a redundant
    // write per owned folder. A non-identity match only ever maps a backup ref id
    // (foreign / previously-restored) to a real id; an owned folder's live
    // parentId is always a real owned id, so it can never equal such a key and is
    // never wrongly relocated. The remap runs after all folder writes, so it
    // resolves child-before-parent orderings; map values never appear as map keys,
    // so it cannot cascade.
    if (folderIdMap.size > 0) {
      const newFolderObjectIds = [...folderIdMap.values()].map(
        (id) => new mongoose.Types.ObjectId(id),
      );
      for (const [oldId, newId] of folderIdMap) {
        if (oldId === newId) continue; // identity mapping — nothing to rewrite
        await Folder.updateMany(
          {
            userId,
            _id: { $in: newFolderObjectIds },
            parentId: new mongoose.Types.ObjectId(oldId),
          },
          { $set: { parentId: new mongoose.Types.ObjectId(newId) } },
        );
      }
    }

    // Validate parentIds — clear any that reference non-existent folders
    const restoredFolderIds = new Set(
      (await Folder.find({ userId }).select('_id').lean()).map((f) => String(f._id)),
    );
    await Folder.updateMany(
      {
        userId,
        parentId: {
          $exists: true,
          $nin: [...restoredFolderIds].map((id) => new mongoose.Types.ObjectId(id)),
        },
      },
      { $unset: { parentId: 1 } },
    );

    // Defense-in-depth against a tampered backup planting a self-referential
    // parentId (folder.parentId === folder._id). The dangling cleanup above
    // cannot catch it — the id IS a valid folder — yet it would loop any tree
    // walker (sidebar render, depth checks). Clear any self-parent for this user.
    // Global like the dangling cleanup: it only ever touches already-broken data.
    await Folder.updateMany(
      { userId, $expr: { $eq: ['$parentId', '$_id'] } },
      { $unset: { parentId: 1 } },
    );

    // Defense-in-depth against a tampered backup planting a MULTI-folder cycle
    // (A.parentId=B, B.parentId=A, or a longer A→B→C→A loop). The self-parent
    // guard above only catches a 1-cycle; in a 2+-folder cycle every folder
    // points at a real, existing folder, so neither the dangling cleanup nor the
    // self-parent guard touches it — yet it loops any tree walker (sidebar
    // render, depth checks). Break it with a GLOBAL sweep over ALL of the user's
    // folders, matching the deliberately-global dangling/self-parent sweeps
    // above. Every restore-managed folder (skip / overwrite / keep_both / fresh)
    // is recorded in folderIdMap, so a folderIdMap-scoped candidate set would in
    // practice catch the same cycles — any cycle this restore can create includes
    // at least one folder whose parentId it wrote, and that folder is always a
    // folderIdMap value. The sweep is global anyway for consistency with the
    // adjacent sweeps and as defense-in-depth (it also breaks any cycle among
    // folders NOT in folderIdMap), which is cheap and safe because it only ever
    // touches already-broken data.
    //
    // The predicate is self-membership ONLY (`hasCycle` → the folder appears in
    // its own ancestor chain), NEVER `depth >= MAX_FOLDER_NESTING_DEPTH`: a
    // legitimate acyclic chain can reach the maximum nesting depth without being
    // cyclic, and a depth check would wrongly detach a valid maximum-depth leaf.
    //
    // Break cycles ITERATIVELY — clear ONE offending parentId, then re-evaluate.
    // A single pass that cleared every currently-flagged folder would detach
    // BOTH edges of a 2-cycle (flattening the pair); clearing one edge at a time
    // leaves the pair as an acyclic child→parent chain. Clearing a parentId can
    // never create a new cycle, so every pass makes progress and the loop is
    // bounded by the parented-folder count (each cleared edge strictly shrinks
    // that set); it exits the moment a full pass finds no cycle. Only folders
    // that HAVE a parentId can be in a cycle, so the scan is confined to those.
    let brokeEdge = true;
    while (brokeEdge) {
      brokeEdge = false;
      const parentedFolders = await Folder.find({ userId, parentId: { $exists: true } })
        .select('_id')
        .lean();
      for (const candidate of parentedFolders) {
        if (await hasCycle(String(candidate._id), userId)) {
          await Folder.updateOne({ _id: candidate._id, userId }, { $unset: { parentId: 1 } });
          brokeEdge = true;
          break;
        }
      }
    }
  }

  // Restore vault items
  if (backupItems.length > 0) {
    // Include trashed items to avoid E11000 duplicate key errors when items exist
    // in trash. The loop below reads exactly three fields off these rows — `_id`
    // (owned-row identity), `sourceRefId` (restore provenance) and `deletedAt`
    // (the trashed auto-restore branch) — so project away the rest. Without this,
    // a vault at the 10,000-item cap pulls every `encryptedData` blob (up to
    // MAX_ENCRYPTED_DATA_LENGTH each) into memory purely to read an id, on the one
    // request that is already holding a multi-MB backup payload and its parse.
    const existingItems = await VaultItem.find({ userId })
      .select('_id sourceRefId deletedAt')
      .lean();
    const existingItemMap = new Map(existingItems.map((i) => [String(i._id), i]));

    // Provenance index for idempotent REPEAT restores (mirrors the folder index
    // above): a prior restore stamps each fresh item with `sourceRefId = the
    // backup row's original _id`, so a second restore matches it by
    // `(userId, sourceRefId)` instead of duplicating. `_id`-owned matching takes
    // precedence; this is the fallback.
    const existingItemBySourceRef = new Map<string, (typeof existingItems)[number]>();
    for (const i of existingItems) {
      if (typeof i.sourceRefId === 'string') {
        existingItemBySourceRef.set(i.sourceRefId, i);
      }
    }

    // Build set of currently valid user folder IDs (post-restore). Includes
    // any folders newly created during the keep_both branch (their target
    // remap IDs are already inside the user's collection by this point, but
    // we union folderIdMap.values() defensively to keep the contract explicit).
    const validFolderIds = new Set(
      (await Folder.find({ userId }).select('_id').lean()).map((f) => String(f._id)),
    );
    for (const newId of folderIdMap.values()) {
      validFolderIds.add(newId);
    }

    for (const item of backupItems) {
      // Validate itemType is a recognized enum value
      const itemType = typeof item.itemType === 'string' ? item.itemType : '';
      if (!(ITEM_TYPES as readonly string[]).includes(itemType)) {
        const skipId = typeof item._id === 'string' ? item._id : 'unknown';
        itemsSkipped++;
        itemSkipReasons.push({ itemId: skipId, reason: 'invalid_item_type' });
        continue;
      }

      // Validate required encryption fields are present and non-empty
      const encryptedData = typeof item.encryptedData === 'string' ? item.encryptedData : '';
      const dataIv = typeof item.dataIv === 'string' ? item.dataIv : '';
      const dataTag = typeof item.dataTag === 'string' ? item.dataTag : '';
      const encryptedName = typeof item.encryptedName === 'string' ? item.encryptedName : '';
      const nameIv = typeof item.nameIv === 'string' ? item.nameIv : '';
      const nameTag = typeof item.nameTag === 'string' ? item.nameTag : '';
      if (!encryptedData || !dataIv || !dataTag || !encryptedName || !nameIv || !nameTag) {
        const skipId = typeof item._id === 'string' ? item._id : 'unknown';
        itemsSkipped++;
        itemSkipReasons.push({ itemId: skipId, reason: 'missing_encryption_fields' });
        continue;
      }

      const rawId = item._id;
      const itemId = mongoose.isValidObjectId(rawId)
        ? String(rawId)
        : new mongoose.Types.ObjectId().toString();
      // Resolve the row this backup item maps onto, owned-by-`_id` first, then a
      // prior-restored row by `(userId, sourceRefId)`. When matched, the conflict
      // strategy is applied against the matched row's real `_id` (equal to `itemId`
      // for an owned match; the prior row's own id for a sourceRefId match — see
      // `matchedItemId` below). No match → fresh-insert with a new `_id`.
      const ownedItem = existingItemMap.get(itemId);
      const srcMatchedItem = ownedItem ? undefined : existingItemBySourceRef.get(itemId);
      const existingItem = ownedItem ?? srcMatchedItem;
      const isTrashed = existingItem?.deletedAt != null;

      const sanitizedItem = pickAllowedFields(item, ALLOWED_ITEM_FIELDS);

      // Remap folderId if a new folder was created during keep_both
      if (typeof sanitizedItem.folderId === 'string' && folderIdMap.has(sanitizedItem.folderId)) {
        sanitizedItem.folderId = folderIdMap.get(sanitizedItem.folderId);
      }

      // Strip folderId values that don't belong to the user's existing folders.
      // A tampered backup file could otherwise plant arbitrary ObjectIds in
      // folderId, leaving items pointing at non-existent or other-user folders.
      // Listing queries scope by userId so it isn't an IDOR escalation, but
      // the dangling reference would surface in the UI as "unknown folder".
      if (
        typeof sanitizedItem.folderId === 'string' &&
        !validFolderIds.has(sanitizedItem.folderId)
      ) {
        sanitizedItem.folderId = undefined;
      }

      // Drop a malformed searchHash (legacy/tampered backups) so it can't trip
      // the model's `match` validator. The import path applies the same guard;
      // restore must match it. A valid item with a bad searchHash is still
      // restored — just without the hash, which the user rebuilds on next edit.
      if (
        sanitizedItem.searchHash !== undefined &&
        (typeof sanitizedItem.searchHash !== 'string' ||
          !SEARCH_HASH_RE.test(sanitizedItem.searchHash))
      ) {
        sanitizedItem.searchHash = undefined;
      }

      // Each per-item write is guarded so one bad row never aborts the whole
      // restore. Only persistence-layer rejections (Mongoose ValidationError —
      // e.g. an over-length encrypted field — or an E11000 duplicate key from a
      // tampered/legacy backup) are swallowed as a skip; any other error
      // (e.g. a transient DB failure) still propagates and fails the request.
      try {
        if (existingItem) {
          // The real `_id` of the matched row — owned by backup id, or a
          // prior-restored row keyed by sourceRefId.
          const matchedItemId = String(existingItem._id);
          if (isTrashed) {
            // Item exists in trash — auto-restore by updating its data and
            // clearing deletedAt, REGARDLESS of conflictStrategy. Surface this
            // override as a skip reason so the client can warn the user that
            // their `skip`/`keep_both` selection did not apply to trashed
            // entries.
            await VaultItem.findOneAndUpdate(
              { _id: matchedItemId, userId },
              { $set: { ...sanitizedItem, userId }, $unset: { deletedAt: 1 } },
              { runValidators: true },
            );
            itemsRestored++;
            itemSkipReasons.push({ itemId, reason: 'trashed_auto_restored' });
            continue;
          }
          if (conflictStrategy === 'skip') {
            itemsSkipped++;
            itemSkipReasons.push({ itemId, reason: 'conflict_skipped' });
            continue;
          }
          if (conflictStrategy === 'overwrite') {
            await VaultItem.findOneAndUpdate(
              { _id: matchedItemId, userId },
              { $set: { ...sanitizedItem, userId } },
              { runValidators: true },
            );
            itemsRestored++;
            continue;
          }
          // keep_both: create a new item with a new _id. Duplication is its
          // contract, so this fires even for a sourceRefId match. Stamp
          // `sourceRefId = itemId` so a later restore recognizes this row.
          await VaultItem.create({ ...sanitizedItem, userId, sourceRefId: itemId });
          itemsRestored++;
        } else {
          // NEW to this user: an item deleted since the backup, or a foreign _id
          // from a cross-account backup. Mint a fresh _id (omit `_id`) — never
          // reuse the backup's globally-unique _id, which may belong to another
          // account and would throw E11000, silently dropping this item. VaultItem
          // has no unique index besides _id, so a Mongo-minted _id cannot collide.
          // Stamp `sourceRefId = itemId` (the backup ref id) so a REPEAT restore of
          // the same backup recognizes this row by `(userId, sourceRefId)` instead
          // of duplicating it.
          await VaultItem.create({ ...sanitizedItem, userId, sourceRefId: itemId });
          itemsRestored++;
        }
      } catch (err: unknown) {
        // Persistence-layer data-quality rejections are skipped per-item:
        //   • ValidationError — a failed model validator (over-length field, etc.)
        //   • CastError — an un-castable field (e.g. a malformed passwordHistory
        //     `changedAt` date in a tampered/legacy backup; the update path
        //     surfaces this as a bare CastError rather than a ValidationError)
        //   • E11000 — a duplicate key. With fresh _id minting on the insert path
        //     this is now unreachable for items: VaultItem has no unique index
        //     besides the Mongo-minted _id, and two backup rows sharing an _id each
        //     get a distinct fresh one. Kept defensively (races / future indexes).
        // Anything else (a transient DB failure, etc.) still propagates and
        // fails the request — we never want to silently swallow infra errors.
        const isDataError =
          err instanceof Error && (err.name === 'ValidationError' || err.name === 'CastError');
        const isDuplicateKey =
          err instanceof Error && 'code' in err && (err as { code?: number }).code === 11000;
        if (!isDataError && !isDuplicateKey) {
          throw err;
        }
        itemsSkipped++;
        itemSkipReasons.push({ itemId, reason: 'invalid_item_data' });
        logger.warn('Skipped malformed backup item during restore', {
          userId,
          itemId,
          error: err instanceof Error ? err.message : 'unknown',
        });
      }
    }
  }

  const restoreCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'backup_restored',
    {
      itemsRestored,
      itemsSkipped,
      foldersRestored,
      foldersSkipped,
      conflictStrategy,
      ...(itemSkipReasons.length > 0 ? { itemSkipReasons } : {}),
      ...(folderSkipReasons.length > 0 ? { folderSkipReasons } : {}),
    },
    restoreCtx.ip,
    restoreCtx.userAgent,
  );

  logger.info('Backup restored', {
    userId,
    itemsRestored,
    itemsSkipped,
    foldersRestored,
    foldersSkipped,
  });

  res.status(200).json({
    success: true,
    message: 'Backup restored successfully',
    data: {
      itemsRestored,
      itemsSkipped,
      foldersRestored,
      foldersSkipped,
      itemSkipReasons,
      folderSkipReasons,
    },
  });
});
