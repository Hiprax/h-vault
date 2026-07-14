import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
import { createAuditLog } from '../services/auditService.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import {
  assertVaultNotRotating,
  getRequestContext,
  getUserId,
  pickAllowedFields,
  vaultRotationLockName,
} from '../utils/controllerHelpers.js';
import { supportsTransactions } from '../utils/transactionSupport.js';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import type {
  ListVaultItemsInput,
  ListTrashInput,
  CreateVaultItemInput,
  UpdateVaultItemInput,
  BulkDeleteInput,
  BulkMoveInput,
  BulkReEncryptInput,
} from '@hvault/shared';

const logger = createLogger({ moduleName: 'vault-controller' });

// ── Helpers ──────────────────────────────────────────────────────────

const ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'itemType', 'favorite'];

// Defense-in-depth field allowlists — even though Zod validates the request body,
// these ensure only expected fields are passed to Mongoose create/update operations.
const ALLOWED_CREATE_FIELDS = new Set([
  'itemType',
  'folderId',
  'tags',
  'favorite',
  'encryptedData',
  'dataIv',
  'dataTag',
  'encryptedName',
  'nameIv',
  'nameTag',
  'searchHash',
]);

const ALLOWED_UPDATE_FIELDS = new Set([
  'folderId',
  'tags',
  'favorite',
  'encryptedData',
  'dataIv',
  'dataTag',
  'encryptedName',
  'nameIv',
  'nameTag',
  'searchHash',
  'passwordHistory',
]);

/**
 * Lifts the rotation fence and drops the crash-recovery markers.
 *
 * Every exit from a rotation that has already raised the fence must call this
 * (or fold the same `$set`/`$unset` into its own final write, as the sequential
 * success path does when it commits the new vault key atomically). A rotation
 * that dies before clearing leaves the flag set; `authController.login`'s
 * crash-recovery clears it on the user's next sign-in, so the account can never
 * be permanently wedged.
 */
async function clearRotationState(userId: string): Promise<void> {
  await User.updateOne(
    { _id: userId },
    {
      $set: { rotationInProgress: false },
      $unset: {
        pendingEncryptedVaultKey: '',
        pendingVaultKeyIv: '',
        pendingVaultKeyTag: '',
      },
    },
  );
}

// ── Handlers ─────────────────────────────────────────────────────────

export const listItems = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const query = req.query as unknown as ListVaultItemsInput;

  const { page, limit, itemType, folderId, favorite, trash, sortBy, sortOrder } = query;

  const filter: Record<string, unknown> = { userId };

  if (itemType) {
    filter.itemType = itemType;
  }

  if (folderId) {
    filter.folderId = folderId;
  }

  if (favorite !== undefined) {
    filter.favorite = favorite;
  }

  if (trash) {
    filter.deletedAt = { $exists: true, $ne: null };
  } else {
    filter.deletedAt = null;
  }

  const skip = (page - 1) * limit;
  const sortDirection = sortOrder === 'asc' ? 1 : -1;
  const safeSortBy = ALLOWED_SORT_FIELDS.includes(sortBy) ? sortBy : 'updatedAt';

  const [items, total] = await Promise.all([
    VaultItem.find(filter)
      .select('-userId -sourceRefId')
      .sort({ [safeSortBy]: sortDirection })
      .skip(skip)
      .limit(limit)
      .lean(),
    VaultItem.countDocuments(filter),
  ]);

  const totalPages = Math.ceil(total / limit);

  res.status(200).json({
    success: true,
    data: items,
    pagination: {
      page,
      limit,
      total,
      totalPages,
    },
  });
});

export const getItem = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const item = await VaultItem.findOne({ _id: id, userId }).select('-userId -sourceRefId').lean();

  if (!item) {
    throw httpErrors.notFound('Vault item not found');
  }

  res.status(200).json({
    success: true,
    data: item,
  });
});

export const createItem = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as CreateVaultItemInput;

  // Ciphertext-creating write: reject it while a vault key rotation is running,
  // otherwise this row's ciphertext (under the OLD key) is stranded when the
  // rotation commits the new key.
  await assertVaultNotRotating(userId);

  // Enforce per-user vault item count limit
  const itemCount = await VaultItem.countDocuments({ userId });
  if (itemCount >= MAX_ITEMS_PER_USER) {
    throw httpErrors.badRequest(
      `Item limit reached. You can have a maximum of ${String(MAX_ITEMS_PER_USER)} items.`,
    );
  }

  if (body.folderId) {
    const folderExists = await Folder.exists({ _id: body.folderId, userId });
    if (!folderExists) {
      throw httpErrors.notFound('Target folder not found');
    }
  }

  const sanitizedBody = pickAllowedFields(body, ALLOWED_CREATE_FIELDS);

  const item = await VaultItem.create({
    ...sanitizedBody,
    userId,
  });

  const createCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_create',
    { itemId: String(item._id), itemType: item.itemType },
    createCtx.ip,
    createCtx.userAgent,
  );

  logger.info('Vault item created', { userId, itemId: String(item._id) });

  res.status(201).json({
    success: true,
    data: item.toJSON(),
  });
});

export const updateItem = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const body = req.body as UpdateVaultItemInput;

  // Ciphertext-creating write (see assertVaultNotRotating): an update issued
  // during a rotation would overwrite a just-rotated row with old-key ciphertext.
  await assertVaultNotRotating(userId);

  if (body.folderId !== undefined && body.folderId !== null) {
    const folderExists = await Folder.exists({ _id: body.folderId, userId });
    if (!folderExists) {
      throw httpErrors.notFound('Target folder not found');
    }
  }

  const sanitizedUpdate = pickAllowedFields(body, ALLOWED_UPDATE_FIELDS);

  // When folderId is explicitly null, use $unset so the field is removed from the
  // document entirely — matching the behaviour of bulkMove (and folder deletion
  // orphan cleanup). Mixing `folderId: null` with `$unset` elsewhere would leave
  // the collection in an inconsistent state for filters and queries.
  const updateOp: Record<string, unknown> = {};
  if ('folderId' in sanitizedUpdate && sanitizedUpdate.folderId === null) {
    delete sanitizedUpdate.folderId;
    updateOp.$unset = { folderId: 1 };
  }
  if (Object.keys(sanitizedUpdate).length > 0) {
    updateOp.$set = sanitizedUpdate;
  }

  const item = await VaultItem.findOneAndUpdate({ _id: id, userId }, updateOp, {
    returnDocument: 'after',
    runValidators: true,
  })
    .select('-userId -sourceRefId')
    .lean();

  if (!item) {
    throw httpErrors.notFound('Vault item not found');
  }

  const updateCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_update',
    { itemId: id, itemType: item.itemType },
    updateCtx.ip,
    updateCtx.userAgent,
  );

  logger.info('Vault item updated', { userId, itemId: id });

  res.status(200).json({
    success: true,
    data: item,
  });
});

export const deleteItem = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const item = await VaultItem.findOneAndUpdate(
    { _id: id, userId },
    { $set: { deletedAt: new Date() } },
    { returnDocument: 'after' },
  ).lean();

  if (!item) {
    throw httpErrors.notFound('Vault item not found');
  }

  const deleteCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_delete',
    { itemId: id, itemType: item.itemType },
    deleteCtx.ip,
    deleteCtx.userAgent,
  );

  logger.info('Vault item soft-deleted', { userId, itemId: id });

  res.status(200).json({
    success: true,
    message: 'Item moved to trash',
  });
});

export const permanentDelete = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const item = await VaultItem.findOneAndDelete({
    _id: id,
    userId,
    deletedAt: { $ne: null },
  }).lean();

  if (!item) {
    throw httpErrors.notFound('Vault item not found in trash');
  }

  const permanentDeleteCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_delete',
    { itemId: id, itemType: item.itemType, permanent: true },
    permanentDeleteCtx.ip,
    permanentDeleteCtx.userAgent,
  );

  logger.info('Vault item permanently deleted', { userId, itemId: id });

  res.status(200).json({
    success: true,
    message: 'Item permanently deleted',
  });
});

export const restoreItem = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const item = await VaultItem.findOneAndUpdate(
    { _id: id, userId, deletedAt: { $exists: true, $ne: null } },
    { $unset: { deletedAt: 1 } },
    { returnDocument: 'after' },
  )
    .select('-userId -sourceRefId')
    .lean();

  if (!item) {
    throw httpErrors.notFound('Vault item not found or not in trash');
  }

  const restoreCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_restore',
    { itemId: id, itemType: item.itemType },
    restoreCtx.ip,
    restoreCtx.userAgent,
  );

  logger.info('Vault item restored', { userId, itemId: id });

  res.status(200).json({
    success: true,
    data: item,
    message: 'Item restored from trash',
  });
});

export const bulkDelete = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { ids } = req.body as BulkDeleteInput;

  const result = await VaultItem.updateMany(
    { _id: { $in: ids }, userId },
    { $set: { deletedAt: new Date() } },
  );

  const bulkDeleteCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_delete',
    { action: 'bulk_delete', count: result.modifiedCount, requestedCount: ids.length },
    bulkDeleteCtx.ip,
    bulkDeleteCtx.userAgent,
  );

  logger.info('Vault items bulk soft-deleted', {
    userId,
    requestedCount: ids.length,
    modifiedCount: result.modifiedCount,
  });

  res.status(200).json({
    success: true,
    data: {
      modifiedCount: result.modifiedCount,
    },
    message: `${String(result.modifiedCount)} items moved to trash`,
  });
});

export const bulkMove = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { ids, folderId } = req.body as BulkMoveInput;

  // Validate target folder belongs to the authenticated user (IDOR prevention)
  if (folderId !== null) {
    const folderExists = await Folder.exists({ _id: folderId, userId });
    if (!folderExists) {
      throw httpErrors.notFound('Target folder not found');
    }
  }

  const update = folderId !== null ? { $set: { folderId } } : { $unset: { folderId: 1 } };

  const result = await VaultItem.updateMany({ _id: { $in: ids }, userId }, update);

  const bulkMoveCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_update',
    { action: 'bulk_move', count: result.modifiedCount, requestedCount: ids.length, folderId },
    bulkMoveCtx.ip,
    bulkMoveCtx.userAgent,
  );

  logger.info('Vault items bulk moved', {
    userId,
    folderId,
    requestedCount: ids.length,
    modifiedCount: result.modifiedCount,
  });

  res.status(200).json({
    success: true,
    data: {
      modifiedCount: result.modifiedCount,
    },
    message: `${String(result.modifiedCount)} items moved`,
  });
});

export const listTrash = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const query = req.query as unknown as ListTrashInput;

  const { page, limit, sortBy, sortOrder } = query;

  const filter = {
    userId,
    deletedAt: { $exists: true, $ne: null },
  };

  const skip = (page - 1) * limit;
  const sortDirection = sortOrder === 'asc' ? 1 : -1;
  const safeSortBy = ['deletedAt', 'createdAt', 'updatedAt', 'itemType'].includes(sortBy)
    ? sortBy
    : 'deletedAt';

  const [items, total] = await Promise.all([
    VaultItem.find(filter)
      .select('-userId -sourceRefId')
      .sort({ [safeSortBy]: sortDirection })
      .skip(skip)
      .limit(limit)
      .lean(),
    VaultItem.countDocuments(filter),
  ]);

  const totalPages = Math.ceil(total / limit);

  res.status(200).json({
    success: true,
    data: items,
    pagination: {
      page,
      limit,
      total,
      totalPages,
    },
  });
});

export const emptyTrash = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  // Bound deletion to items trashed before the operation started so that
  // concurrent soft-deletes arriving mid-request are not swept up.
  const startTime = new Date();
  const result = await VaultItem.deleteMany({
    userId,
    deletedAt: { $exists: true, $ne: null, $lte: startTime },
  });
  const totalDeleted = result.deletedCount;

  const emptyTrashCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'item_delete',
    { action: 'empty_trash', count: totalDeleted },
    emptyTrashCtx.ip,
    emptyTrashCtx.userAgent,
  );

  logger.info('Trash emptied', { userId, deletedCount: totalDeleted });

  res.status(200).json({
    success: true,
    data: {
      deletedCount: totalDeleted,
    },
    message: `${String(totalDeleted)} items permanently deleted`,
  });
});

export const bulkReEncrypt = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const {
    authHash,
    idempotencyKey,
    items,
    folders,
    newEncryptedVaultKey,
    newVaultKeyIv,
    newVaultKeyTag,
  } = req.body as BulkReEncryptInput;

  // Verify the user's password before allowing vault key rotation
  const user = await User.findById(userId).select('+authHash');
  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  const isMatch = await bcrypt.compare(authHash, user.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'bulk_reencrypt' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Password verification failed');
  }

  // If idempotencyKey is provided, check for duplicate request
  if (idempotencyKey && user.lastRotationKey === idempotencyKey) {
    logger.info('Duplicate vault key rotation request detected, returning success', {
      userId,
      idempotencyKey,
    });
    res.status(200).json({
      success: true,
      message: 'Vault key rotated successfully',
      data: { updatedCount: items.length + folders.length },
    });
    return;
  }

  // Acquire a per-user distributed lock to prevent concurrent vault key rotations.
  // The same lock name is what login crash-recovery probes (via
  // `isVaultRotationLockHeld`) to tell a live rotation from a crashed one, so it
  // is built from the shared helper to keep the two sites in lockstep.
  const rotationJobName = vaultRotationLockName(userId);
  const ROTATION_LOCK_TTL_MS = 5 * 60 * 1000; // 5 minutes
  const lockId = await acquireJobLock(rotationJobName, ROTATION_LOCK_TTL_MS);
  if (!lockId) {
    throw httpErrors.conflict('Vault key rotation is already in progress');
  }

  // Track errors from the non-transactional fallback path so that
  // partial failures can be reported in the response.
  const rotationItemErrors: { id: string; error: string }[] = [];
  const rotationFolderErrors: { id: string; error: string }[] = [];

  try {
    // Helper: build the $set for a vault item during rotation
    const buildItemSet = (item: (typeof items)[number]): Record<string, unknown> => ({
      encryptedName: item.encryptedName,
      nameIv: item.nameIv,
      nameTag: item.nameTag,
      encryptedData: item.encryptedData,
      dataIv: item.dataIv,
      dataTag: item.dataTag,
      ...(item.searchHash !== undefined ? { searchHash: item.searchHash } : {}),
      ...(item.passwordHistory !== undefined ? { passwordHistory: item.passwordHistory } : {}),
    });

    // Check if the topology supports transactions (replica set or sharded cluster)
    // before attempting one, rather than relying on error string matching. Routed
    // through the shared, injectable helper so the transaction branch below can be
    // exercised against a real replica set in tests.
    if (supportsTransactions(mongoose.connection)) {
      // Raise the rotation fence for the whole server-side processing window so
      // a second session still holding the OLD vault key cannot land ciphertext
      // that this rotation's (client-enumerated) set does not cover — see
      // `assertVaultNotRotating`. This MUST be a committed write made OUTSIDE
      // the transaction: a write performed inside it is invisible to other
      // sessions until commit, which is precisely the window being fenced.
      await User.updateOne({ _id: userId }, { $set: { rotationInProgress: true } });

      // `startSession` sits INSIDE the try that owns the clear: the fence is
      // already up by this point, so a throw from the session acquisition itself
      // would otherwise leave it raised without a crash to blame.
      let session: mongoose.ClientSession | undefined;
      try {
        const txnSession = await mongoose.startSession();
        session = txnSession;
        await txnSession.withTransaction(async () => {
          // Update all vault items with new encrypted data
          for (const item of items) {
            const result = await VaultItem.updateOne(
              { _id: item.id, userId },
              { $set: buildItemSet(item) },
              { session: txnSession },
            );

            if (result.matchedCount === 0) {
              throw httpErrors.notFound(`Vault item ${item.id} not found`);
            }
          }

          // Update all folders with new encrypted names
          for (const folder of folders) {
            const folderResult = await Folder.updateOne(
              { _id: folder.id, userId },
              {
                $set: {
                  encryptedName: folder.encryptedName,
                  nameIv: folder.nameIv,
                  nameTag: folder.nameTag,
                },
              },
              { session: txnSession },
            );

            if (folderResult.matchedCount === 0) {
              throw httpErrors.notFound(`Folder ${folder.id} not found`);
            }
          }

          // Update the encrypted vault key and idempotency key on the user
          const userUpdate: Record<string, unknown> = {
            encryptedVaultKey: newEncryptedVaultKey,
            vaultKeyIv: newVaultKeyIv,
            vaultKeyTag: newVaultKeyTag,
          };
          if (idempotencyKey) {
            userUpdate.lastRotationKey = idempotencyKey;
            userUpdate.lastRotationAt = new Date();
          }
          await User.updateOne({ _id: userId }, { $set: userUpdate }, { session: txnSession });
        });
      } finally {
        // Lower the fence on BOTH outcomes — a committed rotation and an aborted
        // one (e.g. a missing item id). `withTransaction` has already committed
        // or rolled back by the time we get here, so this write is safe outside
        // the session. Clearing before `endSession` guarantees it runs even if
        // ending the session throws; a failure to clear is logged rather than
        // masking the original error, and login crash-recovery is the backstop.
        try {
          await clearRotationState(userId);
        } catch (clearErr) {
          logger.error('Failed to clear rotation state after transactional rotation', {
            userId,
            error: clearErr instanceof Error ? clearErr.message : String(clearErr),
          });
        }
        if (session) {
          await session.endSession();
        }
      }
    } else {
      logger.warn('Transactions not available, falling back to sequential vault key rotation', {
        userId,
      });

      // Snapshot every targeted item and folder BEFORE applying any updates so
      // that a partial failure can be rolled back to the original ciphertext.
      // Without this, a successful first update + a failed second update would
      // leave the database in a state where some items carry NEW ciphertext (only
      // decryptable with the new vault key) while the user's vault key is rolled
      // back to the OLD value — i.e. the user can no longer decrypt those items.
      const itemIds = items.map((i) => i.id);
      const folderIds = folders.map((f) => f.id);
      const itemSnapshots = await VaultItem.find({ _id: { $in: itemIds }, userId })
        .select(
          '_id encryptedName nameIv nameTag encryptedData dataIv dataTag searchHash passwordHistory',
        )
        .lean();
      const folderSnapshots = await Folder.find({ _id: { $in: folderIds }, userId })
        .select('_id encryptedName nameIv nameTag')
        .lean();

      // If any requested id is missing from the snapshot, abort BEFORE writing.
      // This catches `Vault item not found` errors up-front so we never partially
      // write before discovering the mismatch.
      const itemSnapshotIds = new Set(itemSnapshots.map((s) => String(s._id)));
      const folderSnapshotIds = new Set(folderSnapshots.map((s) => String(s._id)));
      const missingItems = itemIds.filter((id) => !itemSnapshotIds.has(id));
      const missingFolders = folderIds.filter((id) => !folderSnapshotIds.has(id));
      if (missingItems.length > 0 || missingFolders.length > 0) {
        for (const id of missingItems)
          rotationItemErrors.push({ id, error: 'Vault item not found' });
        for (const id of missingFolders)
          rotationFolderErrors.push({ id, error: 'Folder not found' });
        logger.warn('Vault key rotation aborted: requested ids missing before write', {
          userId,
          missingItems: missingItems.length,
          missingFolders: missingFolders.length,
        });
        throw httpErrors.conflict(
          `Vault key rotation failed: ${String(rotationItemErrors.length)} item(s) and ${String(rotationFolderErrors.length)} folder(s) could not be updated. The vault key was not changed. Please retry.`,
        );
      }

      // Track items and folders successfully written with NEW ciphertext so we
      // can roll them back to the snapshot if a later write fails.
      const writtenItemIds: string[] = [];
      const writtenFolderIds: string[] = [];

      // Set rotation state marker before starting sequential updates so that a
      // crash mid-way can be detected on the next login. Store the pending new
      // vault key data so the rotation can be identified as incomplete.
      await User.updateOne(
        { _id: userId },
        {
          $set: {
            rotationInProgress: true,
            pendingEncryptedVaultKey: newEncryptedVaultKey,
            pendingVaultKeyIv: newVaultKeyIv,
            pendingVaultKeyTag: newVaultKeyTag,
          },
        },
      );

      // Helper to roll back successfully-written items and folders to their
      // pre-rotation ciphertext. Best-effort: rollback failures are logged but
      // do not throw, because the higher-level abort path needs to clear
      // rotation state regardless.
      //
      // Snapshot lookup uses Maps keyed by stringified _id so the rollback is
      // O(N) over the written-id list. The previous implementation used
      // `snapshots.find(...)` inside a loop, which degraded to O(N²) over the
      // (item, folder) cap of ~10k × 1k respectively — fine on success (rollback
      // never runs) but several seconds wall-time when an unlucky late failure
      // forced a large rollback.
      const itemSnapshotById = new Map(itemSnapshots.map((s) => [String(s._id), s]));
      const folderSnapshotById = new Map(folderSnapshots.map((s) => [String(s._id), s]));

      const rollbackPartialWrites = async (): Promise<void> => {
        let rolledBackItems = 0;
        let rolledBackFolders = 0;
        let rollbackFailures = 0;

        for (const id of writtenItemIds) {
          const snap = itemSnapshotById.get(id);
          if (!snap) continue;
          try {
            // Build a deterministic $set/$unset pair: fields that existed in the
            // snapshot are restored; fields that didn't exist (searchHash,
            // passwordHistory) are removed so the rollback is faithful.
            const restoreSet: Record<string, unknown> = {
              encryptedName: snap.encryptedName,
              nameIv: snap.nameIv,
              nameTag: snap.nameTag,
              encryptedData: snap.encryptedData,
              dataIv: snap.dataIv,
              dataTag: snap.dataTag,
            };
            const restoreUnset: Record<string, ''> = {};
            if (snap.searchHash !== undefined) {
              restoreSet.searchHash = snap.searchHash;
            } else {
              restoreUnset.searchHash = '';
            }
            if (snap.passwordHistory !== undefined) {
              restoreSet.passwordHistory = snap.passwordHistory;
            } else {
              restoreUnset.passwordHistory = '';
            }
            const restoreOp: Record<string, unknown> = { $set: restoreSet };
            if (Object.keys(restoreUnset).length > 0) {
              restoreOp.$unset = restoreUnset;
            }
            await VaultItem.updateOne({ _id: id, userId }, restoreOp);
            rolledBackItems++;
          } catch (rollbackErr) {
            rollbackFailures++;
            logger.error('Failed to roll back vault item during rotation rollback', {
              userId,
              itemId: id,
              error: rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr),
            });
          }
        }

        for (const id of writtenFolderIds) {
          const snap = folderSnapshotById.get(id);
          if (!snap) continue;
          try {
            await Folder.updateOne(
              { _id: id, userId },
              {
                $set: {
                  encryptedName: snap.encryptedName,
                  nameIv: snap.nameIv,
                  nameTag: snap.nameTag,
                },
              },
            );
            rolledBackFolders++;
          } catch (rollbackErr) {
            rollbackFailures++;
            logger.error('Failed to roll back folder during rotation rollback', {
              userId,
              folderId: id,
              error: rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr),
            });
          }
        }

        logger.warn('Vault key rotation rolled back partially-written ciphertext', {
          userId,
          rolledBackItems,
          rolledBackFolders,
          rollbackFailures,
        });
      };

      try {
        // Strict abort-on-first-failure: every successful write is tracked so it
        // can be rolled back if a later write fails. This guarantees that on
        // failure, no item carries NEW ciphertext while the vault key is OLD.
        for (const item of items) {
          try {
            const result = await VaultItem.updateOne(
              { _id: item.id, userId },
              { $set: buildItemSet(item) },
            );

            if (result.matchedCount === 0) {
              rotationItemErrors.push({ id: item.id, error: 'Vault item not found' });
              break;
            }
            writtenItemIds.push(item.id);
          } catch (err) {
            const message = err instanceof Error ? err.message : 'Unknown error';
            rotationItemErrors.push({ id: item.id, error: message });
            logger.error('Failed to update vault item during rotation', {
              userId,
              itemId: item.id,
              error: message,
            });
            break;
          }
        }

        // Only proceed to folders if no item errors so we never compound failures.
        if (rotationItemErrors.length === 0) {
          for (const folder of folders) {
            try {
              const folderResult = await Folder.updateOne(
                { _id: folder.id, userId },
                {
                  $set: {
                    encryptedName: folder.encryptedName,
                    nameIv: folder.nameIv,
                    nameTag: folder.nameTag,
                  },
                },
              );

              if (folderResult.matchedCount === 0) {
                rotationFolderErrors.push({ id: folder.id, error: 'Folder not found' });
                break;
              }
              writtenFolderIds.push(folder.id);
            } catch (err) {
              const message = err instanceof Error ? err.message : 'Unknown error';
              rotationFolderErrors.push({ id: folder.id, error: message });
              logger.error('Failed to update folder during rotation', {
                userId,
                folderId: folder.id,
                error: message,
              });
              break;
            }
          }
        }

        if (rotationItemErrors.length > 0 || rotationFolderErrors.length > 0) {
          logger.warn(
            'Vault key rotation aborted due to partial failures — rolling back partial writes',
            {
              userId,
              itemErrors: rotationItemErrors.length,
              folderErrors: rotationFolderErrors.length,
              itemsUpdated: writtenItemIds.length,
              foldersUpdated: writtenFolderIds.length,
            },
          );

          // Roll back successfully-written ciphertext to its pre-rotation state
          // so the user's existing (unchanged) vault key can still decrypt
          // everything on next login.
          await rollbackPartialWrites();

          // Clear rotation state so the user can retry. The vault key remains
          // as whatever was last successfully committed (i.e. unchanged).
          await clearRotationState(userId);

          throw httpErrors.conflict(
            `Vault key rotation failed: ${String(rotationItemErrors.length)} item(s) and ${String(rotationFolderErrors.length)} folder(s) could not be updated. The vault key was not changed. Please retry.`,
          );
        }

        await User.updateOne(
          { _id: userId },
          {
            $set: {
              encryptedVaultKey: newEncryptedVaultKey,
              vaultKeyIv: newVaultKeyIv,
              vaultKeyTag: newVaultKeyTag,
              rotationInProgress: false,
              ...(idempotencyKey
                ? { lastRotationKey: idempotencyKey, lastRotationAt: new Date() }
                : {}),
            },
            $unset: {
              pendingEncryptedVaultKey: '',
              pendingVaultKeyIv: '',
              pendingVaultKeyTag: '',
            },
          },
        );
      } catch (rotationErr) {
        // Unexpected exception path (not the orderly conflict abort above). Roll
        // back any partially-written ciphertext and clean up rotation state so
        // the user isn't stuck with rotationInProgress=true. The vault key
        // remains as whatever was last successfully committed.
        logger.error('Sequential vault key rotation failed, cleaning up rotation state', {
          userId,
          error: rotationErr,
        });
        try {
          await rollbackPartialWrites();
        } catch (rollbackErr) {
          logger.error('Rollback after rotation failure also failed', {
            userId,
            error: rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr),
          });
        }
        await clearRotationState(userId);
        throw rotationErr;
      }
    }
  } finally {
    await releaseJobLock(rotationJobName, lockId);
  }

  const totalErrors = rotationItemErrors.length + rotationFolderErrors.length;

  const rotateCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'password_change',
    {
      action: 'vault_key_rotation',
      itemCount: items.length,
      folderCount: folders.length,
      ...(totalErrors > 0
        ? { itemErrors: rotationItemErrors.length, folderErrors: rotationFolderErrors.length }
        : {}),
    },
    rotateCtx.ip,
    rotateCtx.userAgent,
  );

  logger.info('Vault key rotated', {
    userId,
    itemCount: items.length,
    folderCount: folders.length,
    errors: totalErrors,
  });

  res.status(200).json({
    success: true,
    message:
      totalErrors > 0
        ? `Vault key rotated with ${String(totalErrors)} error(s)`
        : 'Vault key rotated successfully',
    data: {
      updatedCount: items.length + folders.length - totalErrors,
      ...(rotationItemErrors.length > 0 ? { itemErrors: rotationItemErrors } : {}),
      ...(rotationFolderErrors.length > 0 ? { folderErrors: rotationFolderErrors } : {}),
    },
  });
});
