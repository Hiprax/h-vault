import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { folderWriteLimiter, generalAuthLimiter } from '../middleware/rateLimiter.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import {
  createFolderSchema,
  updateFolderSchema,
  deleteFolderQuerySchema,
  reorderFolderSchema,
} from '@hvault/shared';
import {
  listFolders,
  createFolder,
  updateFolder,
  deleteFolder,
  reorderFolder,
} from '../controllers/folderController.js';
const router = Router();

// All folder routes require authentication
router.use(authenticate);

router.get('/', generalAuthLimiter, listFolders);
// Every folder mutation writes an audit row that is kept for 365 days, so each one
// carries `folderWriteLimiter` (per user, and sized for a drag that re-sorts every
// sibling, which the client sends as one `/sort` request per moved folder).
router.post('/', folderWriteLimiter, validate(createFolderSchema, 'body'), createFolder);
router.put(
  '/:id',
  folderWriteLimiter,
  validateObjectId(),
  validate(updateFolderSchema, 'body'),
  updateFolder,
);
router.delete(
  '/:id',
  folderWriteLimiter,
  validateObjectId(),
  validate(deleteFolderQuerySchema, 'query'),
  deleteFolder,
);
router.put(
  '/:id/sort',
  folderWriteLimiter,
  validateObjectId(),
  validate(reorderFolderSchema, 'body'),
  reorderFolder,
);

export default router;
