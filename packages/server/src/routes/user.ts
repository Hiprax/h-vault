import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { validateObjectId } from '../middleware/validateObjectId.js';
import {
  passwordVerifyLimiter,
  tokenVerifyLimiter,
  generalAuthLimiter,
} from '../middleware/rateLimiter.js';
import {
  updateSettingsSchema,
  changePasswordSchema,
  setup2faSchema,
  verify2faSchema,
  disable2faSchema,
  regenerateBackupCodesSchema,
  auditLogQuerySchema,
  deleteAccountSchema,
} from '@hvault/shared';
import {
  getProfile,
  updateSettings,
  changePassword,
  setup2fa,
  verify2fa,
  disable2fa,
  regenerateBackupCodes,
  listSessions,
  revokeSession,
  getAuditLog,
  deleteAccount,
} from '../controllers/userController.js';

const router = Router();

// All user routes require authentication
router.use(authenticate);

// ── Profile & Settings ───────────────────────────────────────────────

router.get('/profile', generalAuthLimiter, getProfile);
router.put('/settings', validate(updateSettingsSchema, 'body'), updateSettings);
router.put(
  '/change-password',
  passwordVerifyLimiter,
  validate(changePasswordSchema, 'body'),
  changePassword,
);

// ── Two-Factor Authentication ────────────────────────────────────────

router.post('/2fa/setup', passwordVerifyLimiter, validate(setup2faSchema, 'body'), setup2fa);
router.post('/2fa/verify', tokenVerifyLimiter, validate(verify2faSchema, 'body'), verify2fa);
router.delete('/2fa', passwordVerifyLimiter, validate(disable2faSchema, 'body'), disable2fa);
router.post(
  '/2fa/regenerate-backup-codes',
  passwordVerifyLimiter,
  validate(regenerateBackupCodesSchema, 'body'),
  regenerateBackupCodes,
);

// ── Sessions ─────────────────────────────────────────────────────────

router.get('/sessions', generalAuthLimiter, listSessions);
router.delete('/sessions/:id', validateObjectId(), revokeSession);

// ── Audit Log ────────────────────────────────────────────────────────

router.get('/audit-log', generalAuthLimiter, validate(auditLogQuerySchema, 'query'), getAuditLog);

// ── Account Deletion ────────────────────────────────────────────────

router.delete('/', passwordVerifyLimiter, validate(deleteAccountSchema, 'body'), deleteAccount);

export default router;
