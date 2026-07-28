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

// ---------------------------------------------------------------------------
// Rate-limiter placement invariant — read before adding a limiter to a route.
//
// `authLimiter` counts CREDENTIAL ATTEMPTS: a human deliberately presenting a
// password, or asking for an email link. It is IP-keyed on a single flat
// `auth:<ip>` bucket shared by every route it is mounted on.
//
// Endpoints the APPLICATION drives on its own — `/refresh` (fired whenever the
// 5-minute access token lapses) and `/verify-unlock` (fired on every vault
// unlock) — must therefore NEVER be mounted behind it. Both were, and the result
// was that ordinary use of the app drained the login budget: an open tab spent
// ~3 slots per window refreshing, each unlock spent 2 more, and the user's next
// `POST /auth/login` was rejected with 429 on its FIRST attempt. They now carry
// their own correctly-keyed limiters (`refreshLimiter` by IP, `unlockLimiter` by
// userId), which are stricter for their own traffic and invisible to the
// credential budget.
//
// `tests/auth-limiter-isolation.test.ts` enforces this in both directions.
// ---------------------------------------------------------------------------

// Public routes with the credential-attempt rate limiter
router.post('/register', authLimiter, validate(registerSchema, 'body'), register);
router.post('/login', authLimiter, accountLimiter, validate(loginSchema, 'body'), login);
router.post(
  '/login/2fa',
  authLimiter,
  tokenVerifyLimiter,
  validate(login2faSchema, 'body'),
  login2fa,
);

// Token refresh. Session maintenance, not a credential attempt: bounded by
// `refreshLimiter` ALONE, keyed on the client IP — the one identity an
// unauthenticated caller cannot forge. See the invariant above.
router.post('/refresh', refreshLimiter, refresh);

// Authenticated routes. These are state-changing (audit writes, refresh-token
// revocation) but were previously unlimited — a valid session could spam /lock
// to flood the audit log or churn token revocation. generalAuthLimiter (per
// user, 60/min; a no-op in dev/test) is generous for these infrequent
// operations while closing the abuse window. It is keyed by userId, so it runs
// AFTER authenticate.
router.post('/lock', authenticate, generalAuthLimiter, lock);
router.post('/logout', authenticate, generalAuthLimiter, logout);
router.post('/logout-all', authenticate, generalAuthLimiter, logoutAll);
// Vault unlock verification. Also session maintenance: `authenticate` runs first,
// so `unlockLimiter` keys by userId — a stricter and more precise bound than the
// IP-keyed credential bucket, and one an attacker cannot dilute by rotating IPs.
// `authLimiter` is deliberately absent; mounting it here is what coupled a vault
// unlock to the user's ability to log in.
router.post(
  '/verify-unlock',
  authenticate,
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
