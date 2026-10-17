import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import {
  heavyOpLimiter,
  passwordVerifyLimiter,
  generalAuthLimiter,
  tokenVerifyLimiter,
} from '../middleware/rateLimiter.js';
import {
  holdLargeBodySlot,
  holdingLargeBodySlot,
  parseLargeJsonBody,
} from '../middleware/largeBodyAdmission.js';
import {
  holdHeavyResponseSlot,
  holdingHeavyResponseSlot,
} from '../middleware/heavyResponseAdmission.js';
import { sanitizeRequestBody } from '../middleware/sanitizeBody.js';
import {
  backupSetupSchema,
  backupSettingsSchema,
  backupRecipientsSchema,
  confirmBackupRecipientSchema,
  backupChangePasswordSchema,
  backupHistorySchema,
  restoreBackupSchema,
} from '@hvault/shared';
import {
  setupBackup,
  updateBackupSettings,
  updateBackupRecipients,
  confirmBackupRecipient,
  triggerBackup,
  downloadBackup,
  getBackupHistory,
  changeBackupPassword,
  restoreBackup,
} from '../controllers/backupController.js';

const router = Router();

// A recipient following its confirmation link (F-05). PUBLIC, and therefore
// mounted ABOVE `authenticate`: the person at that address usually has no account
// here, and the single-use token is the whole credential. Token-verification
// budget per address, like the other emailed-link endpoints.
router.post(
  '/recipients/confirm',
  tokenVerifyLimiter,
  validate(confirmBackupRecipientSchema, 'body'),
  confirmBackupRecipient,
);

// Every other backup route requires authentication
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
// Where mailed backups go (F-05): the master-password proof on every change, on
// the budget every such proof shares.
router.put(
  '/recipients',
  passwordVerifyLimiter,
  validate(backupRecipientsSchema, 'body'),
  updateBackupRecipients,
);
// The two routes that build a whole backup: each takes one heavy-response slot
// after its limiter (two per process, one per account) and keeps it until the
// response has closed and the handler has settled.
router.post(
  '/trigger',
  heavyOpLimiter,
  holdHeavyResponseSlot,
  holdingHeavyResponseSlot(triggerBackup),
);
router.get(
  '/download',
  heavyOpLimiter,
  holdHeavyResponseSlot,
  holdingHeavyResponseSlot(downloadBackup),
);
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
// BEFORE the body is read, or they bound nothing. The sanitizer runs straight AFTER
// the parser: the global parser in `app.ts` skips this path, so the app-level
// sanitizer ran before this body existed and filtered only the query.
router.post(
  '/restore',
  passwordVerifyLimiter,
  holdLargeBodySlot,
  parseLargeJsonBody,
  sanitizeRequestBody,
  validate(restoreBackupSchema, 'body'),
  holdingLargeBodySlot(restoreBackup),
);

export default router;
