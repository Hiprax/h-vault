import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { requireStorage } from '../middleware/requireStorage.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import { documentUploadLimiter, generalAuthLimiter } from '../middleware/rateLimiter.js';
import { initDocumentUploadSchema } from '@hvault/shared';
import {
  abortUpload,
  getUpload,
  initUpload,
  listUploads,
} from '../controllers/documentController.js';

const router = Router();

// Every document route is authenticated, and every one of them then requires
// object storage to be configured. Both are ROUTER-level: `authenticate` first, so
// an unauthenticated caller learns nothing about this operator's configuration,
// and `requireStorage` ahead of every route-level limiter, so a deployment with no
// bucket spends no rate-limit budget answering requests it will always refuse.
router.use(authenticate);
router.use(requireStorage);

// ── Uploads ──────────────────────────────────────────────────────────
//
// The literal `/uploads` prefix is declared here, and every later route that
// takes a bare `/:id` must be declared BELOW it — exactly as `routes/vault.ts`
// declares `/items/trash` before `/items/:id`. Express matches in declaration
// order, so a `/:id` above these would swallow the word `uploads` as an id.

router.get('/uploads', generalAuthLimiter, listUploads);
router.post(
  '/uploads',
  documentUploadLimiter,
  validate(initDocumentUploadSchema, 'body'),
  initUpload,
);
router.get('/uploads/:id', generalAuthLimiter, validateObjectId(), getUpload);
router.delete('/uploads/:id', documentUploadLimiter, validateObjectId(), abortUpload);

export default router;
