import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createModuleLogger } from '../utils/logger.js';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { Document } from '../models/Document.js';
import { User } from '../models/User.js';
import { createAuditLog } from '../services/auditService.js';
import {
  acquireVaultRotationLock,
  assertFolderOwned,
  assertVaultNotRotating,
  buildFolderAwareUpdate,
  getRequestContext,
  getUserId,
  pickAllowedFields,
  releaseVaultRotationLock,
  resolveVaultKeyVersion,
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

const logger = createModuleLogger('vault-controller');

// ── Helpers ──────────────────────────────────────────────────────────

const ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'itemType', 'favorite'] as const;

/** The fields `GET /vault/items/trash` may be ordered by. */
const ALLOWED_TRASH_SORT_FIELDS = ['deletedAt', 'createdAt', 'updatedAt', 'itemType'] as const;

/**
 * The sort field a request asked for, taken FROM THE ALLOWLIST rather than from
 * the request.
 *
 * `allowed.includes(sortBy) ? sortBy : fallback` admits exactly the same four
 * strings, so this is not a stronger check — but the value it returns flows from
 * the constant array instead of from `req.query`, and that difference is worth
 * having twice over. It is what a reader can verify locally, without holding the
 * `includes` guard in their head while looking at the computed key three lines
 * down; and it is what static analysis can verify too, because a computed key
 * whose string came from a request is a NoSQL-injection finding however it was
 * guarded, while one that came from a literal array is not.
 */
function resolveSortField<const T extends readonly string[]>(
  allowed: T,
  requested: string,
  fallback: T[number],
): T[number] {
  return allowed.find((field) => field === requested) ?? fallback;
}

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
 * Lifts the rotation fence, and NOTHING ELSE.
 *
 * Every exit from a rotation that has already raised the fence must call this. A
 * rotation that dies before doing so leaves the flag set; `authController.login`'s
 * crash-recovery lowers it on the user's next sign-in, so the account can never be
 * permanently wedged.
 *
 * It deliberately does NOT drop the crash-recovery markers, and that is the whole
 * reason this function is one line long. `pendingEncryptedVaultKey` and its IV/tag
 * are the new vault key wrapped under the account's MEK, written by the sequential
 * path before its first row write so that a crash mid-rotation is recoverable:
 * rows the loop reached are sealed under that key and NOTHING ELSE ANYWHERE stores
 * it. This function runs on every ABORT — the coverage 409, the missing-id abort,
 * the unexpected-exception path — and an abort is precisely the case where a crash
 * may have happened first and left those rows behind. Clearing the wrapper here
 * destroyed them, silently, behind an error message that told the user to retry.
 *
 * The wrapper is dropped in exactly two places, both of them a COMMIT: the
 * transactional path's final `User.updateOne` and the sequential path's. A commit
 * is the only event that makes it redundant, because `bulkReEncrypt` refuses any
 * rotation that neither adopts the pending wrapper nor explicitly discards it.
 */
async function lowerRotationFence(userId: string): Promise<void> {
  await User.updateOne({ _id: userId }, { $set: { rotationInProgress: false } });
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
  const safeSortBy = resolveSortField(ALLOWED_SORT_FIELDS, sortBy, 'updatedAt');

  // `_id` as a TIEBREAK, so the sort is a TOTAL order rather than a partial one.
  // Without it, `updatedAt` ties — which an import's `insertMany` and a hundred-row
  // bulk move both produce by stamping one instant across every row they touch —
  // leave the order within the tie unspecified, and a `skip`/`limit` walk can then
  // return one row on two pages while never returning another. That is exactly the
  // `[A, A, B]` rotation payload `bulkReEncryptSchema`'s duplicate-id refusal and
  // `assertRotationCoversEveryRow` exist to catch, arriving from an ordinary client
  // rather than a hostile one. `documentController`'s own list has carried this
  // tiebreak from the start.
  //
  // Two things it is NOT. It does not make a `skip`-based walk safe under
  // concurrent INSERTS or DELETES — only keyset pagination (`_id > lastId`, which
  // this codebase uses where that matters) would — so the two refusals above stay
  // the backstop rather than becoming decoration.
  //
  // And it is NOT free, stated at its real size rather than as a shrug. None of
  // `VaultItem`'s COMPOUND indexes carries `_id` (every collection has the
  // automatic `_id_` index, which is no help to a compound sort), so
  // `{updatedAt: -1, _id: -1}` can no longer be served by
  // `{userId: 1, updatedAt: -1}` and the planner adds a blocking SORT. That SORT
  // sits ABOVE the FETCH, so a page no longer reads roughly `skip + limit` rows —
  // the old plan fetched at least that many, and more on an account with trash,
  // since `deletedAt` was a residual filter on the index rather than a bound in it
  // — it reads EVERY row the filter matches, bounded by `MAX_ITEMS_PER_USER`, and
  // sorts them, holding at most `skip + limit` of them in the sort buffer because
  // the `limit` bounds it. On the MongoDB this project pins (8.0; the behaviour
  // dates from 6.0) a sort past the 100 MB limit SPILLS TO TEMPORARY FILES rather
  // than failing, so the price is latency and IO and never an error the user sees.
  //
  // It is accepted rather than bought off with indexes because the cheaper fix is
  // not cheap here: `_id` would have to be appended to every sort-serving compound
  // index, and `scripts/create-indexes.ts` only ever calls `createIndexes()` — it
  // never drops — so each superseded prefix would linger until a drop migration
  // retired it. It is also the same cost the document list already pays
  // (`documentController`'s `sendDocumentPage`).
  const [items, total] = await Promise.all([
    VaultItem.find(filter)
      .select('-userId -sourceRefId')
      .sort({ [safeSortBy]: sortDirection, _id: sortDirection })
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

  // And reject it when the rotation has ALREADY committed. The fence above is
  // blind to that case — its flag is lowered by then — yet a session still
  // holding the superseded key can decrypt, can encrypt, and has no way to
  // notice: every row it creates from that moment is sealed under a key the
  // account has replaced, so it lands stranded and reads back as an undecodable
  // placeholder for ever. `null` means the recoverable 409 carrying the current
  // generation has already been answered.
  if ((await resolveVaultKeyVersion(res, userId, body.vaultKeyVersion)) === null) return;

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

  // The same write is just as destructive AFTER the rotation commits, and the
  // fence cannot see that — see `createItem`. The guard belongs to the ENDPOINT
  // and not to the shape of the body: a metadata-only update (the client's
  // `updateItemMeta`) is refused too, because deciding it from which fields the
  // caller happened to send would put the control behind a predicate the caller
  // chooses. That costs a rotated account nothing, since every caller already
  // holds the generation it was issued.
  if ((await resolveVaultKeyVersion(res, userId, body.vaultKeyVersion)) === null) return;

  await assertFolderOwned(body.folderId, userId);

  const sanitizedUpdate = pickAllowedFields(body, ALLOWED_UPDATE_FIELDS);

  // `folderId: null` becomes an `$unset` rather than a stored null — see
  // `buildFolderAwareUpdate`, which `documentController.updateDocument` shares so
  // the two cannot come to disagree about what an unfiled row looks like.
  const updateOp = buildFolderAwareUpdate(sanitizedUpdate);

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
  const safeSortBy = resolveSortField(ALLOWED_TRASH_SORT_FIELDS, sortBy, 'deletedAt');

  // The same `_id` tiebreak `listItems` carries, and the tie is the NORMAL case
  // here rather than an unlucky one: a bulk delete stamps one `deletedAt` across
  // every row it touches. See the note above for what this does and does not buy.
  const [items, total] = await Promise.all([
    VaultItem.find(filter)
      .select('-userId -sourceRefId')
      .sort({ [safeSortBy]: sortDirection, _id: sortDirection })
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
    documents,
    newEncryptedVaultKey,
    newVaultKeyIv,
    newVaultKeyTag,
    discardPendingVaultKey,
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

  /**
   * The answer a retry of an already-completed rotation gets.
   *
   * Written once because it is sent from two places — the cheap pre-lock check
   * and the authoritative one under the lock — and a client that retried cannot
   * be allowed to tell which of them answered it.
   */
  const sendAlreadyRotated = (): void => {
    logger.info('Duplicate vault key rotation request detected, returning success', {
      userId,
      idempotencyKey,
    });
    res.status(200).json({
      success: true,
      message: 'Vault key rotated successfully',
      data: { updatedCount: items.length + folders.length + documents.length },
    });
  };

  // The cheap pre-lock check: a retry that arrives after the original finished is
  // answered without taking a lock at all. It is a FAST PATH and not the
  // guarantee — `user` was read above, before the lock existed, so a retry that
  // read it while the original was still running gets a stale answer here. The
  // authoritative check is the re-read below, under the lock.
  if (idempotencyKey && user.lastRotationKey === idempotencyKey) {
    sendAlreadyRotated();
    return;
  }

  // Acquire the per-user vault-key exclusion lock. It prevents concurrent
  // rotations, it is what login crash-recovery probes (via
  // `isVaultRotationLockHeld`) to tell a live rotation from a crashed one, and it
  // is what every other write whose vault-key check cannot be folded into its own
  // filter holds across its check-to-commit span.
  //
  // Through the shared helper rather than an `acquireJobLock` spelled here, so
  // the TTL and the refusal cannot differ between this holder and the five
  // others. A per-site TTL is how one holder ends up holding the lock for longer
  // than another believes it can be held, which lets a rotation in mid-span and
  // breaks the exclusion silently; a per-site message is how a loser gets told
  // which holder won, which it cannot know.
  const lockId = await acquireVaultRotationLock(userId);

  // The idempotency check, again and authoritatively, now that the lock is held.
  //
  // `acquireJobLock` is an atomic conditional upsert, so two live holders are
  // impossible and a genuine double rotation is not what this closes. What it
  // closes is the SEQUENTIAL one: a retry whose `User.findById` above landed
  // while the original was still inside the lock reads a `lastRotationKey` the
  // original has not written yet, spends a bcrypt compare — hundreds of
  // milliseconds at the shipped cost — and reaches this lock AFTER the original
  // released it. The pre-lock check saw a stale value; this one cannot, because
  // `lastRotationKey` is only ever written under this lock, so a read taken under
  // it is authoritative and needs no compare-and-set.
  //
  // What a second rotation costs, in order: `vaultKeyVersion` is `$inc`'d again,
  // and that number is what a document upload's completion checks the client's
  // wrapped key against, so a spurious bump refuses an upload holding a key that
  // is genuinely current; and a second `vault_key_rotation` audit row is written
  // for a rotation the user asked for once.
  let alreadyRotated = false;
  try {
    if (idempotencyKey !== undefined) {
      const committed = await User.findById(userId).select('lastRotationKey').lean();
      alreadyRotated = committed?.lastRotationKey === idempotencyKey;
    }
  } catch (readError) {
    // The lock is ours and nothing else will free it before its TTL, so a failure
    // to answer this question must not leave it held for five minutes.
    await releaseVaultRotationLock(userId, lockId);
    throw readError;
  }
  if (alreadyRotated) {
    // Released BEFORE the response, exactly as the `finally` below does it: a
    // client that fires its next request the moment this one lands must not race
    // the release round trip and be told a finished rotation is still running.
    await releaseVaultRotationLock(userId, lockId);
    sendAlreadyRotated();
    return;
  }

  /**
   * The filter BOTH branches put on the write that replaces the vault key, so a
   * master-password change committed since this request read the account cannot
   * be clobbered by it.
   *
   * `changePassword` re-wraps the vault key under a MEK derived from the NEW
   * password and stores that as the account's only copy. This handler stores the
   * NEW vault key wrapped under the MEK the rotating session holds — which is the
   * OLD one if the password changed since. Unconditional, the later of the two
   * writes wins and the account is left with a password that works and a wrapper
   * nothing can open: total, unrecoverable loss.
   *
   * The lock does not close it on its own, which is why this filter exists as
   * well. `user` was read BEFORE the lock was taken — it had to be, the bcrypt
   * compare above depends on it — so a password change that commits and releases
   * inside that gap is invisible here, and Passport does not catch it either: it
   * re-checks `iat` against `passwordChangedAt` per REQUEST, and this request is
   * already past it.
   *
   * `authHash` and not `passwordChangedAt`, and the difference matters: `authHash`
   * is `required` on the model, so every row has one and no legacy widening of the
   * kind `vaultKeyVersionFilter` needs applies here, while bcrypt salts every hash
   * afresh so a change always moves it — even a change back to the same password.
   */
  const unchangedCredentialFilter = { _id: userId, authHash: user.authHash };

  /** What a rotation that lost that race is told. */
  const credentialMovedMessage =
    'Vault key rotation failed: the master password for this account was changed while the ' +
    'rotation was running, so the new vault key would have been sealed under a password that ' +
    'no longer exists. The vault key was not changed. Sign in again and retry.';

  // Track errors from the non-transactional fallback path so that
  // partial failures can be reported in the response.
  const rotationItemErrors: { id: string; error: string }[] = [];
  const rotationFolderErrors: { id: string; error: string }[] = [];
  const rotationDocumentErrors: { id: string; error: string }[] = [];

  /**
   * The sequential path's abort message, written once because it is raised from
   * two places — the pre-write missing-id check and the post-loop failure check —
   * and a per-leg count that drifted between them would misreport which leg
   * failed.
   */
  const rotationFailureMessage = (): string =>
    `Vault key rotation failed: ${String(rotationItemErrors.length)} item(s), ` +
    `${String(rotationFolderErrors.length)} folder(s) and ` +
    `${String(rotationDocumentErrors.length)} document(s) could not be updated. ` +
    `The vault key was not changed. Please retry.`;

  try {
    // ── The outstanding-rotation guard ───────────────────────────────
    //
    // While `pendingEncryptedVaultKey` is set, a crash has left rows sealed under
    // the key it wraps and nothing else anywhere stores that key. A rotation to
    // ANY OTHER key would therefore replace the vault key while leaving those rows
    // behind for ever — and behind a 200, because the server cannot tell which
    // rows the client could not read and the client reports them as "already
    // unreadable". So the only rotation accepted here is one that ADOPTS that
    // wrapper (finishing what the crash interrupted), unless the request says in
    // so many words that it is abandoning it.
    //
    // Read under the rotation lock, not from the `user` document loaded before it:
    // that read predates the lock and a rotation committing in between would make
    // this refuse a request that is now correct.
    //
    // Placed after the authoritative idempotency check so a retransmission of a
    // rotation that already committed is still answered as a success rather than
    // refused for a wrapper its own commit removed.
    const outstanding = await User.findById(userId).select('pendingEncryptedVaultKey').lean();
    const pendingWrapper = outstanding?.pendingEncryptedVaultKey;
    if (
      pendingWrapper !== undefined &&
      pendingWrapper !== newEncryptedVaultKey &&
      discardPendingVaultKey !== true
    ) {
      logger.warn('Vault key rotation refused: an interrupted rotation is still outstanding', {
        userId,
      });
      throw httpErrors.conflict(
        'An interrupted vault key rotation is still outstanding on this account. Entries ' +
          'already re-encrypted are sealed under the key it was moving to, and that key is ' +
          'stored only as the wrapper this account holds, so rotating to a different one ' +
          'would leave them unreadable for ever. Finish the interrupted rotation instead, or ' +
          'resend this request with `discardPendingVaultKey` to abandon it deliberately.',
      );
    }

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

    // Helper: build the $set for a document during rotation.
    //
    // Three fields, and deliberately only three. A rotation rewraps the DEK; it
    // never reads, rewrites or even names the stored object, which is the whole
    // reason the store uses envelope encryption. Framing (`streamSalt`,
    // `noncePrefix`, `chunkPlaintextBytes`), sizes and `objectKey` are unreachable
    // from here, so a rotation cannot mis-frame a document it cannot open.
    const buildDocumentSet = (doc: (typeof documents)[number]): Record<string, unknown> => ({
      encryptedDek: doc.encryptedDek,
      dekIv: doc.dekIv,
      dekTag: doc.dekTag,
    });

    /**
     * Refuses a rotation whose payload does not name every row the account holds.
     *
     * The set of rows a rotation rewrites is chosen by the CLIENT, from an
     * enumeration it performed before the request was sent. The write fence
     * (`rotationInProgress`) only goes up when the request ARRIVES, so it cannot
     * see a row created in between — and that row is then left sealed under a
     * vault key that no longer exists, silently, behind a 200. This is the check
     * that closes that window, and it must run AFTER the fence is raised or the
     * same race simply moves to the gap between the count and the fence.
     *
     * DISTINCT ids, not array length. `bulkReEncryptSchema` also rejects repeats
     * outright, but the guarantee here must not lean on it: a payload of
     * `[A, A, B]` against an account holding `{A, B, C}` satisfies the missing-id
     * abort (every id it names exists and is owned) and a length comparison alike,
     * and would replace the vault key while leaving C unreadable forever.
     *
     * Combined with the missing-id abort — which already guarantees every supplied
     * id exists and belongs to this user — equal cardinality is equal SETS, so
     * counting is enough and a `$nin` over ten thousand ids is not needed.
     *
     * The counts are UNFILTERED: no `deletedAt` predicate. A trashed row is sealed
     * under the same vault key as an active one and the client enumerates both, so
     * a count that excluded the trash would refuse every rotation on any account
     * that has ever deleted anything.
     */
    const assertRotationCoversEveryRow = async (
      session?: mongoose.ClientSession,
    ): Promise<void> => {
      // Awaited one at a time rather than through `Promise.all`: a ClientSession
      // may not have two operations in flight at once, and these are three
      // counted index scans.
      const options = session === undefined ? {} : { session };
      const itemCount = await VaultItem.countDocuments({ userId }, options);
      const folderCount = await Folder.countDocuments({ userId }, options);
      const documentCount = await Document.countDocuments({ userId }, options);

      const suppliedItems = new Set(items.map((i) => i.id)).size;
      const suppliedFolders = new Set(folders.map((f) => f.id)).size;
      const suppliedDocuments = new Set(documents.map((d) => d.id)).size;

      const shortfalls: string[] = [];
      if (suppliedItems !== itemCount) {
        shortfalls.push(`items: ${String(suppliedItems)} supplied, ${String(itemCount)} stored`);
      }
      if (suppliedFolders !== folderCount) {
        shortfalls.push(
          `folders: ${String(suppliedFolders)} supplied, ${String(folderCount)} stored`,
        );
      }
      const documentsShort = suppliedDocuments !== documentCount;
      if (documentsShort) {
        shortfalls.push(
          `documents: ${String(suppliedDocuments)} supplied, ${String(documentCount)} stored`,
        );
      }
      if (shortfalls.length === 0) {
        return;
      }

      logger.warn('Vault key rotation aborted: payload does not cover every row', {
        userId,
        shortfalls,
      });
      throw httpErrors.conflict(
        `Vault key rotation failed: the request does not cover every row this account holds ` +
          `(${shortfalls.join('; ')}). A row was created, imported or restored after the vault ` +
          `was enumerated` +
          (documentsShort
            ? ', or a document is awaiting permanent deletion and stays counted until the hourly ' +
              'cleanup finishes it, or this server has no object storage configured, in which ' +
              'case its documents cannot be enumerated or re-keyed until it has'
            : '') +
          `. The vault key was not changed. Please re-read the vault and retry.`,
      );
    };

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

          // Rewrap every document's DEK under the new vault key. A full peer of
          // the two loops above: same ownership predicate, same treatment of a
          // miss. No object in the bucket is read or written.
          for (const doc of documents) {
            const documentResult = await Document.updateOne(
              { _id: doc.id, userId },
              { $set: buildDocumentSet(doc) },
              { session: txnSession },
            );

            if (documentResult.matchedCount === 0) {
              throw httpErrors.notFound(`Document ${doc.id} not found`);
            }
          }

          // Every supplied id now exists and is owned; this is what proves the
          // payload covered EVERY row. Inside the transaction and after the
          // loops, so a shortfall aborts the whole rotation rather than leaving
          // rewritten ciphertext behind, and so a bogus id still surfaces as the
          // 404 the loops above raise rather than as a coverage complaint.
          await assertRotationCoversEveryRow(txnSession);

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
          // `$inc` in the SAME update document that stores the key, never a value
          // computed from the `user` read above: that read happens before the
          // rotation lock is taken, so a computed `$set` would be racy. The
          // counter is what an in-flight document upload's completion checks
          // itself against, so it must move exactly when the key it names does.
          //
          // The crash-recovery markers are dropped HERE, in the commit, rather
          // than in the `finally` below — a commit is the only event that makes
          // them redundant, and the `finally` also runs on every abort. The
          // guard above has already established that a rotation reaching this
          // point either adopts the pending wrapper or was told to discard it.
          //
          // Conditioned on the credential this request authenticated against —
          // see `unchangedCredentialFilter`. A miss throws, which aborts the
          // whole transaction, so nothing this rotation wrote survives it.
          const keyWrite = await User.updateOne(
            unchangedCredentialFilter,
            {
              $set: userUpdate,
              $inc: { vaultKeyVersion: 1 },
              $unset: {
                pendingEncryptedVaultKey: '',
                pendingVaultKeyIv: '',
                pendingVaultKeyTag: '',
              },
            },
            { session: txnSession },
          );
          if (keyWrite.matchedCount === 0) {
            logger.warn('Vault key rotation aborted: the master password changed mid-rotation', {
              userId,
            });
            throw httpErrors.conflict(credentialMovedMessage);
          }
        });
      } finally {
        // Lower the fence on BOTH outcomes — a committed rotation and an aborted
        // one (e.g. a missing item id). `withTransaction` has already committed
        // or rolled back by the time we get here, so this write is safe outside
        // the session. Clearing before `endSession` guarantees it runs even if
        // ending the session throws; a failure to clear is logged rather than
        // masking the original error, and login crash-recovery is the backstop.
        try {
          await lowerRotationFence(userId);
        } catch (clearErr) {
          logger.error('Failed to lower the rotation fence after a transactional rotation', {
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
      const documentIds = documents.map((d) => d.id);
      const itemSnapshots = await VaultItem.find({ _id: { $in: itemIds }, userId })
        .select(
          '_id encryptedName nameIv nameTag encryptedData dataIv dataTag searchHash passwordHistory',
        )
        .lean();
      const folderSnapshots = await Folder.find({ _id: { $in: folderIds }, userId })
        .select('_id encryptedName nameIv nameTag')
        .lean();
      // Documents are snapshotted for the same reason, and the reason is sharper
      // here: a document whose DEK is rewrapped under a vault key that is then
      // rolled back is a FILE nobody can open again, and unlike an item there is
      // no second copy of its plaintext anywhere. Only the three wrap fields are
      // read, because only those three are ever written.
      const documentSnapshots = await Document.find({ _id: { $in: documentIds }, userId })
        .select('_id encryptedDek dekIv dekTag')
        .lean();

      // If any requested id is missing from the snapshot, abort BEFORE writing.
      // This catches `Vault item not found` errors up-front so we never partially
      // write before discovering the mismatch.
      const itemSnapshotIds = new Set(itemSnapshots.map((s) => String(s._id)));
      const folderSnapshotIds = new Set(folderSnapshots.map((s) => String(s._id)));
      const documentSnapshotIds = new Set(documentSnapshots.map((s) => String(s._id)));
      const missingItems = itemIds.filter((id) => !itemSnapshotIds.has(id));
      const missingFolders = folderIds.filter((id) => !folderSnapshotIds.has(id));
      const missingDocuments = documentIds.filter((id) => !documentSnapshotIds.has(id));
      if (missingItems.length > 0 || missingFolders.length > 0 || missingDocuments.length > 0) {
        for (const id of missingItems)
          rotationItemErrors.push({ id, error: 'Vault item not found' });
        for (const id of missingFolders)
          rotationFolderErrors.push({ id, error: 'Folder not found' });
        for (const id of missingDocuments)
          rotationDocumentErrors.push({ id, error: 'Document not found' });
        logger.warn('Vault key rotation aborted: requested ids missing before write', {
          userId,
          missingItems: missingItems.length,
          missingFolders: missingFolders.length,
          missingDocuments: missingDocuments.length,
        });
        throw httpErrors.conflict(rotationFailureMessage());
      }

      // Track items and folders successfully written with NEW ciphertext so we
      // can roll them back to the snapshot if a later write fails.
      const writtenItemIds: string[] = [];
      const writtenFolderIds: string[] = [];
      const writtenDocumentIds: string[] = [];

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
      const documentSnapshotById = new Map(documentSnapshots.map((s) => [String(s._id), s]));

      /**
       * True when undoing the rewritten ciphertext would DESTROY the account
       * rather than save it.
       *
       * The final `User.updateOne` below is the one write in this branch whose
       * failure is ambiguous. A connection that drops after the server applied it
       * is indistinguishable, from this process, from one that dropped before —
       * and the two demand opposite responses. If it applied, every row already
       * carries ciphertext sealed under the new key, that key IS now the
       * account's key, and restoring the snapshots would leave every one of those
       * rows readable only with a key nothing anywhere holds. The rollback that
       * exists to prevent exactly that loss would be the thing that caused it, on
       * an account whose data was, at that instant, completely intact.
       *
       * `encryptedVaultKey` answers it definitively: nothing but that final write
       * puts the new wrapper there, and the wrapper is a fresh random key the
       * client minted for this attempt, so equality is proof rather than
       * coincidence.
       *
       * An unreadable answer is treated as "may have applied", which is the one
       * asymmetry worth stating. The two unknown outcomes are not equally bad:
       * skipping a rollback that was needed leaves rows under the pending wrapper
       * — which this same branch stored precisely so an interrupted rotation can
       * be finished, and which the client can still open — while performing one
       * that was not needed is irreversible and total. When the datastore will not
       * say, the non-destructive branch is the only defensible one.
       */
      const rollbackWouldDestroyACommittedRotation = async (): Promise<boolean> => {
        try {
          const committed = await User.findById(userId).select('encryptedVaultKey').lean();
          return committed?.encryptedVaultKey === newEncryptedVaultKey;
        } catch (readErr) {
          logger.error(
            'Could not determine whether the rotation committed; skipping the rollback rather ' +
              'than risk restoring ciphertext under a key that has already been replaced',
            {
              userId,
              error: readErr instanceof Error ? readErr.message : String(readErr),
            },
          );
          return true;
        }
      };

      const rollbackPartialWrites = async (): Promise<void> => {
        // Asked HERE rather than at either call site, so the rule covers both the
        // orderly abort above and the exception path below with one statement. On
        // the orderly abort the answer is always false — that path is reached
        // before the final write runs at all — so this costs it one indexed read
        // and changes nothing about it.
        if (await rollbackWouldDestroyACommittedRotation()) {
          logger.error(
            'Vault key rotation failed AFTER its final write landed — the rotation is committed, ' +
              'so the re-encrypted rows are left in place and NOT rolled back',
            {
              userId,
              itemsUpdated: writtenItemIds.length,
              foldersUpdated: writtenFolderIds.length,
              documentsUpdated: writtenDocumentIds.length,
            },
          );
          return;
        }

        let rolledBackItems = 0;
        let rolledBackFolders = 0;
        let rolledBackDocuments = 0;
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

        for (const id of writtenDocumentIds) {
          const snap = documentSnapshotById.get(id);
          if (!snap) continue;
          try {
            // All three columns are required on the model, so unlike an item's
            // `searchHash` there is no absent-field case to `$unset`: the
            // snapshot always carries a full wrap to restore.
            await Document.updateOne(
              { _id: id, userId },
              {
                $set: {
                  encryptedDek: snap.encryptedDek,
                  dekIv: snap.dekIv,
                  dekTag: snap.dekTag,
                },
              },
            );
            rolledBackDocuments++;
          } catch (rollbackErr) {
            rollbackFailures++;
            logger.error('Failed to roll back document during rotation rollback', {
              userId,
              documentId: id,
              error: rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr),
            });
          }
        }

        logger.warn('Vault key rotation rolled back partially-written ciphertext', {
          userId,
          rolledBackItems,
          rolledBackFolders,
          rolledBackDocuments,
          rollbackFailures,
        });
      };

      try {
        // Coverage, checked BEFORE the first write and AFTER the fence went up.
        // Before, because on this topology a shortfall discovered later would
        // have to be undone row by row; after, because a count taken before the
        // fence leaves the very window this closes. The missing-id abort above
        // has already established that every supplied id exists and is owned, so
        // matching cardinality here means the payload names every row.
        await assertRotationCoversEveryRow();

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

        // Documents last, and only if nothing failed before them, for the same
        // reason folders follow items: a failure here rolls back every leg, and
        // compounding failures across legs makes the rollback set ambiguous.
        if (rotationItemErrors.length === 0 && rotationFolderErrors.length === 0) {
          for (const doc of documents) {
            try {
              const documentResult = await Document.updateOne(
                { _id: doc.id, userId },
                { $set: buildDocumentSet(doc) },
              );

              if (documentResult.matchedCount === 0) {
                rotationDocumentErrors.push({ id: doc.id, error: 'Document not found' });
                break;
              }
              writtenDocumentIds.push(doc.id);
            } catch (err) {
              const message = err instanceof Error ? err.message : 'Unknown error';
              rotationDocumentErrors.push({ id: doc.id, error: message });
              logger.error('Failed to update document during rotation', {
                userId,
                documentId: doc.id,
                error: message,
              });
              break;
            }
          }
        }

        if (
          rotationItemErrors.length > 0 ||
          rotationFolderErrors.length > 0 ||
          rotationDocumentErrors.length > 0
        ) {
          logger.warn(
            'Vault key rotation aborted due to partial failures — rolling back partial writes',
            {
              userId,
              itemErrors: rotationItemErrors.length,
              folderErrors: rotationFolderErrors.length,
              documentErrors: rotationDocumentErrors.length,
              itemsUpdated: writtenItemIds.length,
              foldersUpdated: writtenFolderIds.length,
              documentsUpdated: writtenDocumentIds.length,
            },
          );

          // Roll back successfully-written ciphertext to its pre-rotation state
          // so the user's existing (unchanged) vault key can still decrypt
          // everything on next login.
          await rollbackPartialWrites();

          // Clear rotation state so the user can retry. The vault key remains
          // as whatever was last successfully committed (i.e. unchanged).
          await lowerRotationFence(userId);

          throw httpErrors.conflict(rotationFailureMessage());
        }

        // Conditioned on the credential this request authenticated against — see
        // `unchangedCredentialFilter`. A miss means a master-password change
        // committed while this rotation ran, so the wrapper below is sealed under
        // a MEK the account no longer has. Throwing here reaches the catch under
        // it, which rolls every rewritten row back and lowers the fence; the
        // rollback is correct precisely because this write did NOT apply, and
        // `rollbackWouldDestroyACommittedRotation` confirms that rather than
        // assuming it.
        const keyWrite = await User.updateOne(unchangedCredentialFilter, {
          $set: {
            encryptedVaultKey: newEncryptedVaultKey,
            vaultKeyIv: newVaultKeyIv,
            vaultKeyTag: newVaultKeyTag,
            rotationInProgress: false,
            ...(idempotencyKey
              ? { lastRotationKey: idempotencyKey, lastRotationAt: new Date() }
              : {}),
          },
          // Same update document as the key it names, and `$inc` rather than a
          // value computed from the `user` read above, which happened before the
          // rotation lock was taken.
          $inc: { vaultKeyVersion: 1 },
          $unset: {
            pendingEncryptedVaultKey: '',
            pendingVaultKeyIv: '',
            pendingVaultKeyTag: '',
          },
        });
        if (keyWrite.matchedCount === 0) {
          logger.warn('Vault key rotation aborted: the master password changed mid-rotation', {
            userId,
          });
          throw httpErrors.conflict(credentialMovedMessage);
        }
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
        await lowerRotationFence(userId);
        throw rotationErr;
      }
    }
  } finally {
    await releaseVaultRotationLock(userId, lockId);
  }

  const totalErrors =
    rotationItemErrors.length + rotationFolderErrors.length + rotationDocumentErrors.length;

  const rotateCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'password_change',
    {
      action: 'vault_key_rotation',
      itemCount: items.length,
      folderCount: folders.length,
      documentCount: documents.length,
      ...(totalErrors > 0
        ? {
            itemErrors: rotationItemErrors.length,
            folderErrors: rotationFolderErrors.length,
            documentErrors: rotationDocumentErrors.length,
          }
        : {}),
    },
    rotateCtx.ip,
    rotateCtx.userAgent,
  );

  logger.info('Vault key rotated', {
    userId,
    itemCount: items.length,
    folderCount: folders.length,
    documentCount: documents.length,
    errors: totalErrors,
  });

  res.status(200).json({
    success: true,
    message:
      totalErrors > 0
        ? `Vault key rotated with ${String(totalErrors)} error(s)`
        : 'Vault key rotated successfully',
    data: {
      updatedCount: items.length + folders.length + documents.length - totalErrors,
      ...(rotationItemErrors.length > 0 ? { itemErrors: rotationItemErrors } : {}),
      ...(rotationFolderErrors.length > 0 ? { folderErrors: rotationFolderErrors } : {}),
      ...(rotationDocumentErrors.length > 0 ? { documentErrors: rotationDocumentErrors } : {}),
    },
  });
});
