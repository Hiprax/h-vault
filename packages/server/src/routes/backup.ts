import { Router } from 'express';
import express from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { heavyOpLimiter, passwordVerifyLimiter } from '../middleware/rateLimiter.js';
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

// Route-specific body parser for backup restore. This overrides the global 2 MB
// limit so that large backup files can be restored.
//
// The 30 MB figure is NOT `MAX_RESTORE_DATA_LENGTH` (25 MiB) rounded up. The
// client posts `{ conflictStrategy, data: JSON.stringify(backupData) }`, so the
// backup document travels as a JSON *string* value and every `"` inside it is
// escaped to `\"` on the wire. A quote-dense backup (thousands of small items,
// each carrying a full password history) is ~6-7% quotes, which inflates a body
// whose inner `data` is still within the 25 MiB schema cap to well over 26 MB —
// a 413 from the parser before Zod ever sees it, i.e. a backup the app produced
// but could not restore. 30 MB keeps ~20% headroom over the 25 MiB inner cap and
// still sits below nginx's `client_max_body_size 32m`, so a genuinely oversized
// payload is rejected by the app with a structured JSON error rather than by the
// proxy with an opaque one.
const restoreBodyParser = express.json({ limit: '30mb' });

router.post('/setup', passwordVerifyLimiter, validate(backupSetupSchema, 'body'), setupBackup);
router.put('/settings', validate(backupSettingsSchema, 'body'), updateBackupSettings);
router.post('/trigger', heavyOpLimiter, triggerBackup);
router.get('/download', heavyOpLimiter, downloadBackup);
router.get('/history', validate(backupHistorySchema, 'query'), getBackupHistory);
router.put(
  '/change-password',
  passwordVerifyLimiter,
  validate(backupChangePasswordSchema, 'body'),
  changeBackupPassword,
);
router.post(
  '/restore',
  restoreBodyParser,
  passwordVerifyLimiter,
  validate(restoreBackupSchema, 'body'),
  restoreBackup,
);

export default router;
