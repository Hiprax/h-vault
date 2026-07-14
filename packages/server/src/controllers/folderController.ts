import type { Request, Response } from 'express';
import mongoose from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import { Folder } from '../models/Folder.js';
import { VaultItem } from '../models/VaultItem.js';
import { createAuditLog } from '../services/auditService.js';
import {
  assertVaultNotRotating,
  getRequestContext,
  getUserId,
  pickAllowedFields,
} from '../utils/controllerHelpers.js';
import { getAncestorChain, hasCycle } from '../utils/folderGraph.js';
import {
  deleteFolderQuerySchema,
  MAX_FOLDERS_PER_USER,
  MAX_FOLDER_NESTING_DEPTH,
} from '@hvault/shared';
import type { CreateFolderInput, UpdateFolderInput, ReorderFolderInput } from '@hvault/shared';

const logger = createLogger({ moduleName: 'folder-controller' });

// ── Helpers ──────────────────────────────────────────────────────────

// Defense-in-depth field allowlists — even though Zod validates the request body,
// these ensure only expected fields are passed to Mongoose create/update operations.
const ALLOWED_CREATE_FOLDER_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'searchHash',
  'parentId',
  'icon',
  'color',
  'sortOrder',
]);

const ALLOWED_UPDATE_FOLDER_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'searchHash',
  'parentId',
  'icon',
  'color',
  'sortOrder',
]);

/**
 * Validates that adding a folder under `parentId` would not exceed
 * `MAX_FOLDER_NESTING_DEPTH`.  Uses `$graphLookup` (single DB query) instead
 * of N+1 individual queries.
 */
async function validateFolderDepth(parentId: string, userId: string): Promise<void> {
  const { depth } = await getAncestorChain(parentId, userId);
  if (depth >= MAX_FOLDER_NESTING_DEPTH) {
    throw httpErrors.badRequest('Maximum folder nesting depth exceeded');
  }
}

/**
 * Computes the height of the subtree rooted at `folderId` — the number of
 * folder levels from the folder itself down to its deepest descendant,
 * inclusive. A leaf folder has height 1. Uses a single descending
 * `$graphLookup` (startWith `$_id`, connectFromField `_id`, connectToField
 * `parentId`) with a `depthField`, so the deepest descendant level is read in
 * one query instead of N+1. Used by `updateFolder` to ensure a re-parent does
 * not push the moved subtree's leaves past `MAX_FOLDER_NESTING_DEPTH`.
 */
async function getSubtreeHeight(folderId: string, userId: string): Promise<number> {
  const result = await Folder.aggregate<{
    descendants: { depth: number }[];
  }>([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(folderId),
        userId: new mongoose.Types.ObjectId(userId),
      },
    },
    {
      $graphLookup: {
        from: 'folders',
        startWith: '$_id',
        connectFromField: '_id',
        connectToField: 'parentId',
        as: 'descendants',
        depthField: 'depth',
        maxDepth: MAX_FOLDER_NESTING_DEPTH,
        restrictSearchWithMatch: { userId: new mongoose.Types.ObjectId(userId) },
      },
    },
    { $project: { 'descendants.depth': 1 } },
  ]);

  if (!result[0] || result[0].descendants.length === 0) {
    return 1;
  }

  // `depth` is 0 for direct children, 1 for grandchildren, …, so the deepest
  // descendant sits (maxDescendantDepth + 1) levels below the folder.
  // Including the folder itself, the subtree height is (maxDescendantDepth + 2).
  const maxDescendantDepth = result[0].descendants.reduce(
    (max, d) => (d.depth > max ? d.depth : max),
    0,
  );
  return maxDescendantDepth + 2;
}

// ── Handlers ─────────────────────────────────────────────────────────

export const listFolders = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const folders = await Folder.find({ userId })
    .select('-userId -sourceRefId')
    .sort({ sortOrder: 1 })
    .lean();

  res.status(200).json({
    success: true,
    data: folders,
  });
});

export const createFolder = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as CreateFolderInput;

  // A folder's `encryptedName` is vault-key ciphertext, so a folder created
  // during a rotation would be stranded by the new key — fence it.
  await assertVaultNotRotating(userId);

  // Enforce per-user folder count limit
  const folderCount = await Folder.countDocuments({ userId });
  if (folderCount >= MAX_FOLDERS_PER_USER) {
    throw httpErrors.badRequest(
      `Folder limit reached. You can have a maximum of ${String(MAX_FOLDERS_PER_USER)} folders.`,
    );
  }

  // Validate parentId belongs to the authenticated user (IDOR prevention)
  if (body.parentId) {
    const parentExists = await Folder.exists({ _id: body.parentId, userId });
    if (!parentExists) {
      throw httpErrors.notFound('Parent folder not found');
    }
    await validateFolderDepth(body.parentId, userId);
  }

  const filteredBody = pickAllowedFields(body, ALLOWED_CREATE_FOLDER_FIELDS);

  let folder;
  try {
    folder = await Folder.create({
      ...filteredBody,
      userId,
    });
  } catch (err: unknown) {
    if (err instanceof Error && 'code' in err && (err as { code?: number }).code === 11000) {
      throw httpErrors.conflict('A folder with this name already exists');
    }
    throw err;
  }

  const createCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'folder_create',
    { folderId: String(folder._id), parentId: body.parentId ?? null },
    createCtx.ip,
    createCtx.userAgent,
  );

  logger.info('Folder created', { userId, folderId: String(folder._id) });

  res.status(201).json({
    success: true,
    data: folder.toJSON(),
  });
});

export const updateFolder = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  // Normalize the route id to lowercase hex. `validateObjectId` only checks
  // `isValid` and leaves the case untouched, but `body.parentId` is lowercased
  // by `objectIdSchema.transform(...)` and the `ancestorIds` returned by
  // `getAncestorChain` come from `_id.toString()` (always lowercase). Without
  // this, an UPPER-CASE `:id` makes the `body.parentId === id` self-parent check
  // and the `ancestorIds.includes(id)` cycle check both miss, so a self-parent or
  // a cycle could be persisted (the case-insensitive `findOneAndUpdate` still
  // matches the doc). Lowercasing here keeps all string comparisons consistent.
  const id = (req.params as { id: string }).id.toLowerCase();
  const body = req.body as UpdateFolderInput;

  // A rename rewrites `encryptedName` under the caller's (possibly about-to-be-
  // superseded) vault key — fence it for the rotation window.
  await assertVaultNotRotating(userId);

  if (body.parentId) {
    if (body.parentId === id) {
      throw httpErrors.badRequest('A folder cannot be its own parent');
    }

    // Validate parentId belongs to the authenticated user (IDOR prevention)
    const parentExists = await Folder.exists({ _id: body.parentId, userId });
    if (!parentExists) {
      throw httpErrors.notFound('Parent folder not found');
    }

    // ONE ancestor traversal answers BOTH guards below — the depth bound needs
    // `depth`, the circular-reference bound needs `ancestorIds`. They used to
    // run two identical `$graphLookup` aggregations per re-parent.
    const { ancestorIds, depth: parentDepth } = await getAncestorChain(body.parentId, userId);

    // Depth validation must account for the ENTIRE subtree being moved, not
    // just the new parent. Re-parenting relocates every descendant of `id`, so
    // the deepest descendant lands at (parentDepth + subtreeHeight). Creation
    // is naturally bounded (a new folder has no descendants); a move is not.
    // Since subtreeHeight >= 1, this combined check also subsumes the
    // parent-only depth guard (parentDepth >= MAX) that createFolder uses.
    const subtreeHeight = await getSubtreeHeight(id, userId);
    if (parentDepth + subtreeHeight > MAX_FOLDER_NESTING_DEPTH) {
      throw httpErrors.badRequest('Maximum folder nesting depth exceeded');
    }

    // Prevent circular folder references: the folder being moved must not
    // already be an ancestor of its new parent.
    if (ancestorIds.includes(id)) {
      throw httpErrors.badRequest('Circular folder reference detected');
    }
  }

  const filteredBody = pickAllowedFields(body, ALLOWED_UPDATE_FOLDER_FIELDS);

  // When parentId is explicitly null, use $unset so the field is removed from the
  // document entirely — matching the behaviour of deleteFolder's child-folder
  // reassignment. Mixing `parentId: null` with `$unset` elsewhere would leave
  // the collection in an inconsistent state for filters and queries.
  const updateOp: Record<string, unknown> = {};
  if ('parentId' in filteredBody && filteredBody.parentId === null) {
    delete filteredBody.parentId;
    updateOp.$unset = { parentId: 1 };
  }
  if (Object.keys(filteredBody).length > 0) {
    updateOp.$set = filteredBody;
  }

  let folder;
  try {
    folder = await Folder.findOneAndUpdate({ _id: id, userId }, updateOp, {
      returnDocument: 'after',
      runValidators: true,
    })
      .select('-userId -sourceRefId')
      .lean();
  } catch (err: unknown) {
    if (err instanceof Error && 'code' in err && (err as { code?: number }).code === 11000) {
      throw httpErrors.conflict('A folder with this name already exists');
    }
    throw err;
  }

  if (!folder) {
    throw httpErrors.notFound('Folder not found');
  }

  // The pre-write circular check above and this write are not atomic. Two
  // concurrent re-parents (A → B and B → A) can each pass their own check
  // before either write lands, and together persist a 2-cycle — which makes
  // both folders disappear from the client's tree builder. Re-check the
  // COMMITTED state: because each request's check runs after its own write and
  // a cycle needs both writes, at least one racing request is guaranteed to
  // observe it.
  //
  // Break the cycle by REMOVING the edge this request just added, rather than
  // restoring the folder's previous parent: dropping an edge can never create a
  // cycle, whereas re-adding the old edge could close a different one under a
  // three-way race. Same "break at least one edge" philosophy as the restore
  // path's cycle sweep.
  //
  // Scope: only `parentId` is reverted. Any other field carried by the same PUT
  // (a rename, icon, colour, sortOrder) stays applied even though this returns
  // 409, because reverting them would need a before-image the `returnDocument:
  // 'after'` write does not give us. Reaching that state needs a lost re-parent
  // race on a request that ALSO renames — which no client issues (the app sends
  // `parentId` only on create).
  if (body.parentId && (await hasCycle(id, userId))) {
    await Folder.updateOne({ _id: id, userId }, { $unset: { parentId: 1 } });
    logger.warn('Concurrent re-parent formed a folder cycle; reverted parentId', {
      userId,
      folderId: id,
      parentId: body.parentId,
    });
    throw httpErrors.conflict('Circular folder reference detected');
  }

  const updateCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'folder_update',
    { folderId: id },
    updateCtx.ip,
    updateCtx.userAgent,
  );

  logger.info('Folder updated', { userId, folderId: id });

  res.status(200).json({
    success: true,
    data: folder,
  });
});

export const deleteFolder = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const { action } = deleteFolderQuerySchema.parse(req.query);

  const folder = await Folder.findOne({ _id: id, userId }).lean();

  if (!folder) {
    throw httpErrors.notFound('Folder not found');
  }

  // Use a transaction for atomicity when replica set is available.
  // Falls back to non-transactional operations for standalone deployments.
  //
  // WARNING: On standalone MongoDB (no replica set), folder deletion is non-atomic.
  // A crash mid-operation could leave orphaned items pointing to a deleted folder.
  // A post-delete cleanup step below clears any stale folderId references to mitigate this.
  const useTransaction =
    mongoose.connection.readyState === mongoose.ConnectionStates.connected &&
    // Check if the topology supports sessions (replica set or sharded cluster)
    Boolean(mongoose.connection.getClient().options.replicaSet);

  const session = useTransaction ? await mongoose.startSession() : null;
  const sessionOpt = session ? { session } : {};

  try {
    const execute = async (): Promise<void> => {
      if (action === 'delete') {
        // Soft-delete all items in this folder (move to trash)
        await VaultItem.updateMany(
          { folderId: id, userId, deletedAt: { $eq: null } },
          { $set: { deletedAt: new Date() } },
          sessionOpt,
        );
      } else {
        // Move items to parent folder (or root if no parent)
        const parentId = folder.parentId;
        if (parentId) {
          await VaultItem.updateMany(
            { folderId: id, userId },
            { $set: { folderId: parentId } },
            sessionOpt,
          );
        } else {
          await VaultItem.updateMany(
            { folderId: id, userId },
            { $unset: { folderId: 1 } },
            sessionOpt,
          );
        }
      }

      // Move child folders to the parent as well
      const parentUpdate = folder.parentId
        ? { $set: { parentId: folder.parentId } }
        : { $unset: { parentId: 1 } };
      await Folder.updateMany({ parentId: id, userId }, parentUpdate, sessionOpt);

      // Delete the folder itself
      await Folder.deleteOne({ _id: id, userId }, sessionOpt);
    };

    if (session) {
      await session.withTransaction(execute);
    } else {
      await execute();
    }
  } finally {
    if (session) {
      await session.endSession();
    }
  }

  // Clean up any orphaned folderId references that may remain after non-atomic
  // deletion on standalone MongoDB (no replica set). This is targeted to the
  // just-deleted folder rather than scanning all folders on every list request.
  // Only targets non-trashed items — trashed items may legitimately retain
  // the deleted folder's ID from the action=delete soft-delete path.
  void VaultItem.updateMany({ userId, folderId: id, deletedAt: null }, { $unset: { folderId: 1 } })
    .then((result) => {
      if (result.modifiedCount > 0) {
        logger.info(`Cleaned up ${String(result.modifiedCount)} orphaned folderId references`, {
          userId,
          folderId: id,
        });
      }
    })
    .catch((err: unknown) => {
      logger.warn('Failed to clean orphaned folderId references', { error: err });
    });

  const deleteCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'folder_delete',
    { folderId: id, action },
    deleteCtx.ip,
    deleteCtx.userAgent,
  );

  logger.info('Folder deleted', { userId, folderId: id, action });

  res.status(200).json({
    success: true,
    message: 'Folder deleted',
  });
});

export const reorderFolder = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const { sortOrder } = req.body as ReorderFolderInput;

  const folder = await Folder.findOneAndUpdate(
    { _id: id, userId },
    { $set: { sortOrder } },
    { returnDocument: 'after', runValidators: true },
  )
    .select('-userId -sourceRefId')
    .lean();

  if (!folder) {
    throw httpErrors.notFound('Folder not found');
  }

  const reorderCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'folder_reorder',
    { folderId: id, sortOrder },
    reorderCtx.ip,
    reorderCtx.userAgent,
  );

  logger.info('Folder reordered', { userId, folderId: id, sortOrder });

  res.status(200).json({
    success: true,
    data: folder,
  });
});
