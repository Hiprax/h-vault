import type { Request, Response } from 'express';
import mongoose, { type ClientSession } from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createModuleLogger, errorMessage } from '../utils/logger.js';
import { Folder } from '../models/Folder.js';
import { VaultItem } from '../models/VaultItem.js';
import { Document } from '../models/Document.js';
import { createAuditLog } from '../services/auditService.js';
import {
  assertVaultNotRotating,
  assertVaultWritable,
  confirmCreatedRow,
  getRequestContext,
  getUserId,
  orStaleVaultKey,
  pickAllowedFields,
  resolveVaultKeyVersion,
} from '../utils/controllerHelpers.js';
import { createdRowId, isDuplicateIdError, ROW_ID_TAKEN_MESSAGE } from '../utils/rowIds.js';
import {
  createCountedRow,
  deleteCountedRow,
  reserveVaultWrite,
  settleVaultWrite,
  updateCountedRow,
} from '../utils/vaultQuota.js';
import { getAncestorChain, hasCycle } from '../utils/folderGraph.js';
import { supportsTransactions } from '../utils/transactionSupport.js';
import { deleteFolderQuerySchema, MAX_FOLDER_NESTING_DEPTH } from '@hvault/shared';
import type { CreateFolderInput, UpdateFolderInput, ReorderFolderInput } from '@hvault/shared';

const logger = createModuleLogger('folder-controller');

// ── Helpers ──────────────────────────────────────────────────────────

// Defense-in-depth field allowlists — even though Zod validates the request body,
// these ensure only expected fields are passed to Mongoose create/update operations.
const ALLOWED_CREATE_FOLDER_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'parentId',
  'icon',
  'color',
  'sortOrder',
]);

const ALLOWED_UPDATE_FOLDER_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'parentId',
  'icon',
  'color',
  'sortOrder',
]);

/**
 * The folder update fields that carry ciphertext: a rename. An update without them changed only where the folder sits or how it
 * looks, and its audit row says so (`contentChanged: false`) — see
 * `vaultController`'s `ITEM_CONTENT_FIELDS` for why.
 */
const FOLDER_CONTENT_FIELDS = ['encryptedName', 'nameIv', 'nameTag'] as const;

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
    .select('-userId -sourceRefId -searchHash')
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

  // And refuse a name sealed under a generation the account has already left
  // behind: the fence is blind once the rotation commits, and the folder would
  // land with a name nothing can decrypt. `null` means the recoverable 409
  // carrying the current generation has already been answered. The reasoning in
  // full is in `vaultController.createItem`.
  if ((await resolveVaultKeyVersion(res, userId, body.vaultKeyVersion)) === null) return;

  // Validate parentId belongs to the authenticated user (IDOR prevention)
  if (body.parentId) {
    const parentExists = await Folder.exists({ _id: body.parentId, userId });
    if (!parentExists) {
      throw httpErrors.notFound('Parent folder not found');
    }
    await validateFolderDepth(body.parentId, userId);
  }

  const filteredBody = pickAllowedFields(body, ALLOWED_CREATE_FOLDER_FIELDS);

  // Spread in by name, past the allowlist, for the reason `createdRowId` gives.
  const rowId = await createdRowId(userId, body.idNonce);

  // Counted against the account's byte quota (F-24) and the per-user folder cap
  // (F-15) in one conditional reservation before the insert, like an item: the
  // cap is never a count read here and trusted by the insert after it.
  const folderData = { ...filteredBody, ...rowId, userId };
  let folder;
  try {
    folder = await createCountedRow('folder', userId, folderData, () => Folder.create(folderData));
  } catch (err: unknown) {
    // The derived `_id` is the one unique index a folder insert can violate (a
    // retried create). Two folders may share a name: no keyed hash of it is
    // stored (F-12), so there is nothing to compare names by.
    if (isDuplicateIdError(err)) throw httpErrors.conflict(ROW_ID_TAKEN_MESSAGE);
    throw err;
  }

  // Checked again now that the row exists, and withdrawn on a refusal, for the
  // reason `vaultController.createItem` gives.
  if (!(await confirmCreatedRow(res, 'folder', userId, folder, body.vaultKeyVersion))) return;

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

  // And for the window the fence cannot see, after that rotation has committed.
  // Endpoint-wide rather than body-dependent, exactly as in
  // `vaultController.updateItem`: a re-parent that carries no name is refused
  // too, because a control decided from the fields the caller chose to send is a
  // control the caller can step around.
  if ((await resolveVaultKeyVersion(res, userId, body.vaultKeyVersion)) === null) return;

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
  const contentChanged = FOLDER_CONTENT_FIELDS.some((field) => Object.hasOwn(filteredBody, field));

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

  // Through the quota (F-24): a rename that grows the row is reserved first, the
  // write is pinned on the row it measured, and the change is settled. No unique
  // index covers a field an update can write, so a rename never conflicts.
  // The vault key re-checked after every measure, as in `vaultController.updateItem`.
  const written = await orStaleVaultKey(res, () =>
    updateCountedRow({
      kind: 'folder',
      userId,
      id,
      update: updateOp,
      beforeWrite: () => assertVaultWritable(userId, body.vaultKeyVersion),
    }),
  );
  if (written === null) return;
  const updated = written.value;

  if (!updated) {
    throw httpErrors.notFound('Folder not found');
  }
  // Without its owner, its restore provenance and a residual name hash (F-12).
  const { userId: _owner, sourceRefId: _sourceRefId, searchHash: _searchHash, ...folder } = updated;

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
    { folderId: id, contentChanged },
    updateCtx.ip,
    updateCtx.userAgent,
  );

  logger.info('Folder updated', { userId, folderId: id });

  res.status(200).json({
    success: true,
    data: folder,
  });
});

/** Where a removed folder's members go: to the trash with it, or up to its parent. */
type FolderRemovalAction = 'delete' | 'move';

/**
 * Re-homes what a folder being removed holds, inside `session` when one is given.
 *
 * The folder's MEMBERS are vault items and documents, and both are treated
 * identically: `action=delete` trashes them, `action=move` re-parents them to the
 * folder's parent or to the root. Writing the filter and the update ONCE and
 * applying them to both collections is what makes that identity structural rather
 * than a coincidence of two copied blocks: a branch added to one copy and not the
 * other would leave documents stranded in a folder that no longer exists. Child
 * folders always move up to the same parent.
 *
 * `deletedAt: { $eq: null }` matches an ABSENT field as well as a null one, which is
 * what both models rely on: an already-trashed row keeps the timestamp it was
 * trashed with rather than being re-stamped now.
 */
async function rehomeFolderContents(
  userId: string,
  folderId: string,
  parentId: unknown,
  action: FolderRemovalAction,
  session: ClientSession | undefined,
): Promise<void> {
  const sessionOpt = session ? { session } : {};
  const memberFilter =
    action === 'delete' ? { folderId, userId, deletedAt: { $eq: null } } : { folderId, userId };
  const memberUpdate =
    action === 'delete'
      ? { $set: { deletedAt: new Date() } }
      : parentId
        ? { $set: { folderId: parentId } }
        : { $unset: { folderId: 1 } };

  await VaultItem.updateMany(memberFilter, memberUpdate, sessionOpt);
  await Document.updateMany(memberFilter, memberUpdate, sessionOpt);

  // Move child folders to the parent as well
  const parentUpdate = parentId ? { $set: { parentId } } : { $unset: { parentId: 1 } };
  await Folder.updateMany({ parentId: folderId, userId }, parentUpdate, sessionOpt);
}

/**
 * Runs `execute` in a transaction when the topology supports one, else directly.
 *
 * On standalone MongoDB (no replica set) a folder removal is non-atomic: a crash
 * mid-operation could leave orphaned items pointing to a deleted folder, which
 * {@link sweepOrphanedFolderReferences} mitigates. The topology check is
 * `utils/transactionSupport.ts` and nothing else: it used to be inlined here, and an
 * inlined copy is a second answer to a question every multi-collection writer has to
 * answer the same way (see `tests/topology-predicate.test.ts`). `withTransaction`
 * may run `execute` again after a transient error, so it must reset what it records.
 */
async function inFolderTransaction(
  execute: (session: ClientSession | undefined) => Promise<void>,
): Promise<void> {
  const session = supportsTransactions(mongoose.connection) ? await mongoose.startSession() : null;
  try {
    if (session) {
      await session.withTransaction(() => execute(session));
    } else {
      await execute(undefined);
    }
  } finally {
    if (session) {
      await session.endSession();
    }
  }
}

/**
 * Clears any orphaned `folderId` references a non-atomic (standalone) removal may
 * leave on the folder's ACTIVE members (trashed rows may legitimately keep the
 * removed folder's id from the `action=delete` path).
 *
 * AWAITED, deliberately. This used to be a floating `void ....then()`, which gave the
 * mitigation the very failure mode it exists to mitigate: a process that dies just
 * after answering loses the sweep exactly as it lost the write the sweep was
 * compensating for, and the orphan survives. Two indexed `updateMany`s issued together
 * cost a single round trip and make the reference provably gone by the time the caller
 * is told the folder is. It also removed a race the suite could see but not control:
 * whether the floating promise resolved before the worker moved on decided whether
 * this branch ran at all, so `packages/server` line and branch coverage differed run
 * to run and the ratchet gate flickered. Documents are swept alongside items, for the
 * same reason.
 *
 * Never fails the removal: the folder IS gone, and a stale `folderId` on an item is a
 * cosmetic inconsistency that the client's tree builder and the next delete both
 * tolerate. Turning it into a 500 would report the whole operation as failed when the
 * part the caller asked for succeeded.
 */
async function sweepOrphanedFolderReferences(userId: string, folderId: string): Promise<void> {
  try {
    const orphaned = { userId, folderId, deletedAt: null };
    const [itemCleanup, documentCleanup] = await Promise.all([
      VaultItem.updateMany(orphaned, { $unset: { folderId: 1 } }),
      Document.updateMany(orphaned, { $unset: { folderId: 1 } }),
    ]);
    const cleared = itemCleanup.modifiedCount + documentCleanup.modifiedCount;
    if (cleared > 0) {
      logger.info(`Cleaned up ${String(cleared)} orphaned folderId references`, {
        userId,
        folderId,
      });
    }
  } catch (err: unknown) {
    logger.warn('Failed to clean orphaned folderId references', { error: errorMessage(err) });
  }
}

/** The folder row of `folderId` owned by `userId`, as a counted-delete filter. */
function ownedFolderFilter(userId: string, folderId: string): Record<string, unknown> {
  return {
    _id: new mongoose.Types.ObjectId(folderId),
    userId: new mongoose.Types.ObjectId(userId),
  };
}

/**
 * Removes ONE folder only while its sealed name is still the ciphertext `readPin`
 * names (`{ nameIv: { $eq } }`), and moves what it holds up to its parent. Resolves
 * to whether the folder went, and calls `onRemoved` once the removal is final (also when
 * a later step throws after it). Used by the unreadable-entry purge, whose client
 * judged that exact ciphertext unreadable.
 *
 * CLAIM FIRST: the pinned, counted delete is the first write, so a folder renamed or
 * re-sealed since the check (fresh IVs) misses it and nothing at all is moved, on
 * either topology. Only after a hit are its members and child folders re-parented, to
 * the `parentId` read off the row that delete removed. On a replica set the claim and
 * the moves commit together; on a standalone deployment a crash between them leaves
 * members pointing at a folder that is gone, which the sweep and the client's tree
 * builder both tolerate.
 */
export async function removeFolderIfUnchanged(
  userId: string,
  folderId: string,
  readPin: Record<string, unknown>,
  onRemoved: () => void,
): Promise<boolean> {
  const reservation = await reserveVaultWrite(userId, { bytes: 0 });
  const claim = { bytes: 0, removed: false, inTransaction: false, committed: false };
  try {
    await inFolderTransaction(async (session) => {
      claim.bytes = 0;
      claim.removed = false;
      claim.inTransaction = session !== undefined;
      const gone = await deleteCountedRow(
        'folder',
        { ...ownedFolderFilter(userId, folderId), ...readPin },
        session,
      );
      if (!gone) return;
      claim.bytes = gone.counted;
      claim.removed = true;
      await rehomeFolderContents(userId, folderId, gone.row.parentId, 'move', session);
    });
    claim.committed = true;
  } finally {
    // A transaction that threw committed nothing, so it subtracts nothing (as in
    // `deleteFolder`). Without one, a claim that ran is final although a later step
    // failed, and is subtracted exactly.
    const removed = claim.removed && (claim.committed || !claim.inTransaction);
    // Told here, not by the return value, so a removal that is final is reported
    // even when a later step throws.
    if (removed) onRemoved();
    await settleVaultWrite(reservation, removed ? -claim.bytes : 0, {
      folders: removed ? -1 : 0,
    });
  }
  if (claim.removed) await sweepOrphanedFolderReferences(userId, folderId);
  return claim.removed;
}

export const deleteFolder = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const { action } = deleteFolderQuerySchema.parse(req.query);

  const folder = await Folder.findOne({ _id: id, userId }).lean();

  if (!folder) {
    throw httpErrors.notFound('Folder not found');
  }

  // Touch first (F-24): the folder row is counted, so its removal is subtracted
  // once it is gone, by the bytes the database measured on the row it removed,
  // and from the folder cap's count (F-15): without that, the count only grew and
  // `MAX_FOLDERS_PER_USER` folders would become a lifetime limit.
  const reservation = await reserveVaultWrite(userId, { bytes: 0 });
  let folderBytes = 0;
  let foldersRemoved = 0;

  await inFolderTransaction(async (session) => {
    // Reset per attempt: `withTransaction` may run this again after a transient
    // error, and the aborted attempt removed nothing.
    folderBytes = 0;
    foldersRemoved = 0;
    await rehomeFolderContents(userId, id, folder.parentId, action, session);

    // Delete the folder itself, measured by the database as it goes.
    const gone = await deleteCountedRow('folder', ownedFolderFilter(userId, id), session);
    folderBytes = gone?.counted ?? 0;
    foldersRemoved = gone ? 1 : 0;
  });
  // Only now is the removal certain: the transaction committed (or, standalone, the
  // folder's delete, the last step, ran). A transaction that threw removed nothing,
  // or nothing anyone can be sure of, so it subtracts nothing; an overcount is what
  // the hourly recount corrects.
  await settleVaultWrite(reservation, -folderBytes, { folders: -foldersRemoved });

  await sweepOrphanedFolderReferences(userId, id);

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

  // A position is a counted field (F-24): through the quota like any other change.
  const updated = await updateCountedRow({
    kind: 'folder',
    userId,
    id,
    update: { $set: { sortOrder } },
  });

  if (!updated) {
    throw httpErrors.notFound('Folder not found');
  }
  // Without its owner, its restore provenance and a residual name hash (F-12).
  const { userId: _owner, sourceRefId: _sourceRefId, searchHash: _searchHash, ...folder } = updated;

  const reorderCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'folder_reorder',
    // The stored id, not the route's spelling: `validateObjectId` accepts either
    // case, and the audit service coalesces a run of reorders by this value.
    { folderId: String(folder._id), sortOrder },
    reorderCtx.ip,
    reorderCtx.userAgent,
  );

  logger.info('Folder reordered', { userId, folderId: id, sortOrder });

  res.status(200).json({
    success: true,
    data: folder,
  });
});
