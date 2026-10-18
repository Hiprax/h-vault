import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import {
  heavyOpLimiter,
  passwordVerifyLimiter,
  vaultItemWriteLimiter,
  vaultListLimiter,
} from '../middleware/rateLimiter.js';
import {
  LARGE_JSON_BODY_LIMIT_BYTES,
  holdLargeBodySlot,
  holdingLargeBodySlot,
  parseLargeJsonBody,
} from '../middleware/largeBodyAdmission.js';
import { sanitizeRequestBody } from '../middleware/sanitizeBody.js';
import {
  listVaultItemsSchema,
  listTrashSchema,
  createVaultItemSchema,
  updateVaultItemSchema,
  bulkDeleteSchema,
  bulkMoveSchema,
  bulkReEncryptSchema,
  purgeUnreadableSchema,
} from '@hvault/shared';
import {
  listItems,
  getItem,
  createItem,
  updateItem,
  deleteItem,
  permanentDelete,
  restoreItem,
  bulkDelete,
  bulkMove,
  listTrash,
  emptyTrash,
  bulkReEncrypt,
  purgeUnreadable,
} from '../controllers/vaultController.js';

const router = Router();

// A full rotation re-encrypts every vault item, folder and document key and ships
// them in one request, so the payload is comparable in size to a full backup and
// shares restore's 30 MB parser (`middleware/largeBodyAdmission.ts`).
//
// Exported as a number of BYTES because `tests/rotation-payload-budget.test.ts`
// derives the worst-case rotation body from the shared constants and asserts it
// fits inside this value. A limit written only as a string here would leave that
// test restating the number, and a restated bound is the copy that drifts.
export const BULK_REENCRYPT_BODY_LIMIT_BYTES = LARGE_JSON_BODY_LIMIT_BYTES;

// All vault routes require authentication
router.use(authenticate);

// ── Item CRUD ────────────────────────────────────────────────────────

router.get('/items', vaultListLimiter, validate(listVaultItemsSchema, 'query'), listItems);
router.get('/items/trash', vaultListLimiter, validate(listTrashSchema, 'query'), listTrash);
router.get('/items/:id', validateObjectId(), getItem);
// Every item mutation writes an audit row that is kept for 365 days, so each one
// carries `vaultItemWriteLimiter` (per user; see its docblock for why it is not
// `generalAuthLimiter`: the client's bulk actions send one of these per row).
router.post('/items', vaultItemWriteLimiter, validate(createVaultItemSchema, 'body'), createItem);
router.put(
  '/items/:id',
  vaultItemWriteLimiter,
  validateObjectId(),
  validate(updateVaultItemSchema, 'body'),
  updateItem,
);
router.delete('/items/:id', vaultItemWriteLimiter, validateObjectId(), deleteItem);
router.delete('/items/:id/permanent', vaultItemWriteLimiter, validateObjectId(), permanentDelete);

// ── Restore ──────────────────────────────────────────────────────────

router.post('/items/restore/:id', vaultItemWriteLimiter, validateObjectId(), restoreItem);

// ── Bulk operations ──────────────────────────────────────────────────

router.post('/items/bulk-delete', heavyOpLimiter, validate(bulkDeleteSchema, 'body'), bulkDelete);
router.post('/items/bulk-move', heavyOpLimiter, validate(bulkMoveSchema, 'body'), bulkMove);
// The limiter and the admission slot run BEFORE the 30 MB body is read, or they
// bound nothing (see `middleware/largeBodyAdmission.ts`). The sanitizer runs
// straight AFTER the parser, because the app-level one ran before this body existed
// (it filtered only the query).
router.post(
  '/items/bulk-reencrypt',
  passwordVerifyLimiter,
  holdLargeBodySlot,
  parseLargeJsonBody,
  sanitizeRequestBody,
  validate(bulkReEncryptSchema, 'body'),
  holdingLargeBodySlot(bulkReEncrypt),
);

// Permanently delete the entries no key the account stores can open. A
// re-authentication endpoint (the master password is in the body), so it carries
// `passwordVerifyLimiter` and never a looser budget. Its body is at most ~1.1 MB at
// the row caps, inside the global 2 MB parser.
router.post(
  '/items/purge-unreadable',
  passwordVerifyLimiter,
  validate(purgeUnreadableSchema, 'body'),
  purgeUnreadable,
);

// ── Trash ────────────────────────────────────────────────────────────

router.delete('/items/trash/empty', heavyOpLimiter, emptyTrash);

export default router;
