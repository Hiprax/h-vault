import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import {
  heavyOpLimiter,
  breachCheckLimiter,
  breachBatchLimiter,
  passwordVerifyLimiter,
  importLimiter,
} from '../middleware/rateLimiter.js';
import {
  holdHeavyResponseSlot,
  holdingHeavyResponseSlot,
} from '../middleware/heavyResponseAdmission.js';
import {
  checkBreachSchema,
  checkBreachBatchSchema,
  exportSchema,
  importSchema,
} from '@hvault/shared';
import {
  checkPasswordBreach,
  checkPasswordBreachBatch,
  exportVault,
  importVault,
} from '../controllers/toolsController.js';

const router = Router();

// All tools routes require authentication
router.use(authenticate);

router.post(
  '/check-password-breach',
  breachCheckLimiter,
  validate(checkBreachSchema, 'body'),
  checkPasswordBreach,
);
router.post(
  '/check-password-breach/batch',
  breachBatchLimiter,
  validate(checkBreachBatchSchema, 'body'),
  checkPasswordBreachBatch,
);
// A heavy response like the backup download: one slot after the limiters and the
// validation, kept until the response has closed and the handler has settled.
router.post(
  '/export',
  heavyOpLimiter,
  passwordVerifyLimiter,
  holdHeavyResponseSlot,
  validate(exportSchema, 'body'),
  holdingHeavyResponseSlot(exportVault),
);
router.post('/import', importLimiter, validate(importSchema, 'body'), importVault);

export default router;
