import express from 'express';
import {
  registerSchema,
  loginSchema,
  login2faSchema,
  verifyEmailSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  unlockAccountSchema,
  verifyUnlockSchema,
  resendVerificationSchema,
} from '@hvault/shared';
import { validate } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';
import {
  authLimiter,
  tokenVerifyLimiter,
  accountLimiter,
  unlockLimiter,
  refreshLimiter,
  generalAuthLimiter,
} from '../middleware/rateLimiter.js';
import {
  register,
  login,
  login2fa,
  refresh,
  lock,
  logout,
  logoutAll,
  verifyEmail,
  forgotPassword,
  resetPassword,
  unlockAccount,
  verifyUnlock,
  resendVerification,
} from '../controllers/authController.js';

const router = express.Router();

// Public routes with auth rate limiter
router.post('/register', authLimiter, validate(registerSchema, 'body'), register);
router.post('/login', authLimiter, accountLimiter, validate(loginSchema, 'body'), login);
router.post(
  '/login/2fa',
  authLimiter,
  tokenVerifyLimiter,
  validate(login2faSchema, 'body'),
  login2fa,
);

// Token refresh (rate-limited to prevent abuse via unlock/refresh loops)
router.post('/refresh', authLimiter, refreshLimiter, refresh);

// Authenticated routes. These are state-changing (audit writes, refresh-token
// revocation) but were previously unlimited — a valid session could spam /lock
// to flood the audit log or churn token revocation. generalAuthLimiter (per
// user, 60/min; a no-op in dev/test) is generous for these infrequent
// operations while closing the abuse window. It is keyed by userId, so it runs
// AFTER authenticate.
router.post('/lock', authenticate, generalAuthLimiter, lock);
router.post('/logout', authenticate, generalAuthLimiter, logout);
router.post('/logout-all', authenticate, generalAuthLimiter, logoutAll);
router.post(
  '/verify-unlock',
  authenticate,
  authLimiter,
  unlockLimiter,
  validate(verifyUnlockSchema, 'body'),
  verifyUnlock,
);

// Email verification (no auth required, token-based)
router.post('/verify-email', tokenVerifyLimiter, validate(verifyEmailSchema, 'body'), verifyEmail);
router.post(
  '/resend-verification',
  authLimiter,
  validate(resendVerificationSchema, 'body'),
  resendVerification,
);

// Password recovery with auth rate limiter + token verification limiter
router.post(
  '/forgot-password',
  authLimiter,
  validate(forgotPasswordSchema, 'body'),
  forgotPassword,
);
router.post(
  '/reset-password',
  tokenVerifyLimiter,
  validate(resetPasswordSchema, 'body'),
  resetPassword,
);

// Account unlock (email-based, token verification limiter)
router.post(
  '/unlock-account',
  tokenVerifyLimiter,
  validate(unlockAccountSchema, 'body'),
  unlockAccount,
);

export default router;
