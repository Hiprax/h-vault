import { Router } from 'express';
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import { heavyOpLimiter, passwordVerifyLimiter } from '../middleware/rateLimiter.js';
import {
  listVaultItemsSchema,
  listTrashSchema,
  createVaultItemSchema,
  updateVaultItemSchema,
  bulkDeleteSchema,
  bulkMoveSchema,
  bulkReEncryptSchema,
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
} from '../controllers/vaultController.js';

const router = Router();

// Route-specific body parser for vault key rotation (bulk re-encrypt). A full
// rotation re-encrypts every vault item + folder and ships them in one request,
// so the payload is comparable in size to a full backup. This 30 MB limit
// mirrors POST /backup/restore (see routes/backup.ts for why 30 and not 26) and
// overrides the global 2 MB parser so a large-vault rotation is not rejected
// with HTTP 413 before validation runs. The matching path is exempted from the
// global parser in app.ts (CUSTOM_BODY_LIMIT_PATHS).
const bulkReEncryptBodyParser = express.json({ limit: '30mb' });

// All vault routes require authentication
router.use(authenticate);

// ── Item CRUD ────────────────────────────────────────────────────────

router.get('/items', validate(listVaultItemsSchema, 'query'), listItems);
router.get('/items/trash', validate(listTrashSchema, 'query'), listTrash);
router.get('/items/:id', validateObjectId(), getItem);
router.post('/items', validate(createVaultItemSchema, 'body'), createItem);
router.put('/items/:id', validateObjectId(), validate(updateVaultItemSchema, 'body'), updateItem);
router.delete('/items/:id', validateObjectId(), deleteItem);
router.delete('/items/:id/permanent', validateObjectId(), permanentDelete);

// ── Restore ──────────────────────────────────────────────────────────

router.post('/items/restore/:id', validateObjectId(), restoreItem);

// ── Bulk operations ──────────────────────────────────────────────────

router.post('/items/bulk-delete', heavyOpLimiter, validate(bulkDeleteSchema, 'body'), bulkDelete);
router.post('/items/bulk-move', heavyOpLimiter, validate(bulkMoveSchema, 'body'), bulkMove);
router.post(
  '/items/bulk-reencrypt',
  bulkReEncryptBodyParser,
  passwordVerifyLimiter,
  validate(bulkReEncryptSchema, 'body'),
  bulkReEncrypt,
);

// ── Trash ────────────────────────────────────────────────────────────

router.delete('/items/trash/empty', heavyOpLimiter, emptyTrash);

export default router;
