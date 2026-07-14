import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { generalAuthLimiter } from '../middleware/rateLimiter.js';
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
router.post('/', validate(createFolderSchema, 'body'), createFolder);
router.put('/:id', validateObjectId(), validate(updateFolderSchema, 'body'), updateFolder);
router.delete('/:id', validateObjectId(), validate(deleteFolderQuerySchema, 'query'), deleteFolder);
router.put('/:id/sort', validateObjectId(), validate(reorderFolderSchema, 'body'), reorderFolder);

export default router;
