import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import {
  heavyOpLimiter,
  passwordVerifyLimiter,
  generalAuthLimiter,
} from '../middleware/rateLimiter.js';
import {
  holdLargeBodySlot,
  holdingLargeBodySlot,
  parseLargeJsonBody,
} from '../middleware/largeBodyAdmission.js';
import {
  backupSetupSchema,
  backupSettingsSchema,
  backupChangePasswordSchema,
  backupHistorySchema,
  restoreBackupSchema,
} from '@hvault/shared';
import {
  setupBackup,
  updateBackupSettings,
  triggerBackup,
  downloadBackup,
  getBackupHistory,
  changeBackupPassword,
  restoreBackup,
} from '../controllers/backupController.js';

const router = Router();

// All backup routes require authentication
router.use(authenticate);

router.post('/setup', passwordVerifyLimiter, validate(backupSetupSchema, 'body'), setupBackup);
// `generalAuthLimiter` (60/user/min) on the two endpoints that previously carried
// none. Both are cheap and infrequent, but a valid session could otherwise spam
// them without bound — the settings write emits audit rows, and the history read
// is an unbounded paged query against `backupLogs`.
router.put(
  '/settings',
  generalAuthLimiter,
  validate(backupSettingsSchema, 'body'),
  updateBackupSettings,
);
router.post('/trigger', heavyOpLimiter, triggerBackup);
router.get('/download', heavyOpLimiter, downloadBackup);
router.get(
  '/history',
  generalAuthLimiter,
  validate(backupHistorySchema, 'query'),
  getBackupHistory,
);
router.put(
  '/change-password',
  passwordVerifyLimiter,
  validate(backupChangePasswordSchema, 'body'),
  changeBackupPassword,
);
// Restore accepts a 30 MB body, so the ORDER in front of its parser is the control
// (see `middleware/largeBodyAdmission.ts`): the limiter and the admission slot run
// BEFORE the body is read, or they bound nothing.
router.post(
  '/restore',
  passwordVerifyLimiter,
  holdLargeBodySlot,
  parseLargeJsonBody,
  validate(restoreBackupSchema, 'body'),
  holdingLargeBodySlot(restoreBackup),
);

export default router;
