import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { TOTP, Secret } from 'otpauth';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import { config, isProduction, isTest, twoFactorEncryptionKey } from '../config/index.js';
import { REFRESH_COOKIE_NAME } from '../constants/index.js';
import { User } from '../models/User.js';
import { RefreshToken } from '../models/RefreshToken.js';
import {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  derivePurposeKey,
} from '../utils/token.js';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendAccountUnlockEmail,
  sendRegistrationAttemptEmail,
} from '../utils/email.js';
import { createAuditLog } from '../services/auditService.js';
import { cryptoManager } from '../utils/cryptoManager.js';
import { recordFailedLoginAttempt, resetLoginAttempts } from '../utils/loginThrottle.js';
import {
  getRequestContext,
  isVaultRotationLockHeld,
  MAX_USER_AGENT_LENGTH,
  pickAllowedFields,
} from '../utils/controllerHelpers.js';
import { clearCsrfCookie } from '../middleware/csrf.js';
import {
  ERROR_CODES,
  LOCKOUT_DURATION_MINUTES,
  MAX_LOGIN_ATTEMPTS,
  maskEmail,
} from '@hvault/shared';
import type {
  RegisterInput,
  LoginInput,
  Login2faInput,
  ResetPasswordInput,
  VerifyUnlockInput,
} from '@hvault/shared';

const logger = createLogger({ moduleName: 'auth' });

const DAY_MS = 24 * 60 * 60 * 1000;
const LOCKOUT_DURATION_MS = LOCKOUT_DURATION_MINUTES * 60 * 1000;
const MAX_FAILED_ATTEMPTS = MAX_LOGIN_ATTEMPTS;

// Pre-computed bcrypt hash used for timing-safe dummy comparisons when a user
// is not found. This ensures the login endpoint takes approximately the same
// time regardless of whether the email exists, preventing email enumeration
// via timing side-channel attacks.
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(
  'dummy-password-for-timing-equalization',
  config.BCRYPT_ROUNDS,
);

/**
 * Returns the progressive delay in milliseconds based on the number of failed login attempts.
 * 0ms for 1-2 attempts, 1s at 3+, 3s at 5+, 5s at 7+.
 */
export function getProgressiveDelay(failedAttempts: number): number {
  if (failedAttempts >= 7) return 5000;
  if (failedAttempts >= 5) return 3000;
  if (failedAttempts >= 3) return 1000;
  return 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Applies the progressive brute-force delay for a failed login attempt.
 *
 * The attempt count comes from the process-local per-email throttle rather than
 * the durable `User.failedLoginAttempts` counter, because a non-existent email
 * has no User row to count against. Sourcing the delay from the database
 * counter delayed only real accounts, so the response time itself revealed
 * whether an email was registered — an enumeration oracle that defeated the
 * dummy-bcrypt equalization. `User.failedLoginAttempts` remains the sole driver
 * of account lockout; this counter drives nothing but the sleep.
 *
 * EVERY branch of `login` that returns the generic "Invalid email or password"
 * 401 must call this exactly once, immediately before throwing. Routing all of
 * them through one helper makes their latency identical by construction instead
 * of by three hand-audited call sites. Calling it twice on one branch, or
 * skipping it on one, reopens the oracle.
 *
 * The remaining asymmetry — the wrong-password branch also writes the counter,
 * an audit log, and sometimes a lockout — is a few milliseconds of database
 * work against the seconds this equalizes, and equalizing it would mean issuing
 * dummy writes for arbitrary attacker-supplied emails. Deliberately not chased.
 */
async function applyFailedLoginDelay(email: string): Promise<void> {
  const attempts = recordFailedLoginAttempt(email);
  if (isTest) return;

  const delay = getProgressiveDelay(attempts);
  if (delay > 0) {
    await sleep(delay);
  }
}

interface JwtEmailPayload {
  userId: string;
  purpose: string;
  stateHash: string;
}

interface JwtResetPayload {
  userId: string;
  purpose: string;
  stateHash: string;
}

interface JwtTempPayload {
  userId: string;
  purpose: string;
  deviceHash?: string;
}

interface JwtUnlockPayload {
  userId: string;
  purpose: string;
  stateHash: string;
}

/**
 * Generates a SHA-256 hash of the given value to embed in JWT tokens.
 * When the underlying value changes (e.g., authHash after password reset),
 * tokens containing the old hash become invalid.
 */
function generateStateHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Generates a SHA-256 hash of the requesting device's IP and User-Agent.
 * Used to bind 2FA temp tokens to the originating device so that a stolen
 * temp token cannot be used from a different device.
 */
function generateDeviceHash(req: Request): string {
  const ip = req.ip ?? 'unknown';
  const userAgent = req.headers['user-agent'] ?? '';
  return crypto.createHash('sha256').update(`${ip}|${userAgent}`).digest('hex');
}

interface AuthenticatedRequest extends Request {
  user: {
    _id: string;
  };
}

function setRefreshCookie(res: Response, token: string, maxAgeMs: number): void {
  res.cookie(REFRESH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1',
    maxAge: maxAgeMs,
  });
}

interface RefreshLifetime {
  expiresAt: Date;
  absoluteExpiresAt?: Date;
  maxAgeMs: number;
}

/**
 * Single source of truth for a refresh token's lifetime, so the cookie's
 * `maxAge`, the persisted row's `expiresAt`, and the family's absolute deadline
 * are always computed from ONE `Date.now()` and can never drift apart.
 *
 * Three cases, in priority order:
 *  - **Rotation of a remembered family** (`absoluteExpiresAt` present): carry the
 *    deadline forward UNCHANGED. `expiresAt` is pinned to it and `maxAge` is the
 *    remaining time, so an active user's "30 days" is truly absolute — rotation
 *    never extends it (§1.2 principle 5 / §1.7).
 *  - **Fresh remembered login** (`remember: true`, no deadline yet): mint a new
 *    30-day (`REFRESH_TOKEN_REMEMBER_DAYS`) absolute deadline.
 *  - **Everything else** (standard login, or rotation of a row with no deadline):
 *    slide to `now + REFRESH_TOKEN_DAYS`, no `absoluteExpiresAt` — byte-for-byte
 *    today's behaviour (§1.2 principle 6).
 */
export function resolveRefreshLifetime(opts: {
  remember?: boolean;
  absoluteExpiresAt?: Date | undefined;
}): RefreshLifetime {
  const now = Date.now();
  const existing = opts.absoluteExpiresAt;
  if (existing) {
    return {
      expiresAt: new Date(existing),
      absoluteExpiresAt: existing,
      maxAgeMs: Math.max(0, existing.getTime() - now),
    };
  }
  if (opts.remember) {
    const rememberMs = config.REFRESH_TOKEN_REMEMBER_DAYS * DAY_MS;
    return {
      expiresAt: new Date(now + rememberMs),
      absoluteExpiresAt: new Date(now + rememberMs),
      maxAgeMs: rememberMs,
    };
  }
  const standardMs = config.REFRESH_TOKEN_DAYS * DAY_MS;
  return {
    expiresAt: new Date(now + standardMs),
    maxAgeMs: standardMs,
  };
}

function clearRefreshCookie(res: Response): void {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1',
  });
}

// ─── Register ────────────────────────────────────────────────────────────────

// Defense-in-depth field allowlist — even though Zod validates the request body
// (and strips unknown keys), this guards against future schema drift that could
// inadvertently let user-controllable fields like `emailVerified` reach the
// User model and bypass account verification.
const ALLOWED_REGISTER_FIELDS = new Set([
  'email',
  'authHash',
  'encryptedVaultKey',
  'vaultKeyIv',
  'vaultKeyTag',
  'kdfIterations',
  'kdfAlgorithm',
  'encryptionVersion',
]);

export const register = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const body = req.body as RegisterInput;
  const sanitized = pickAllowedFields(body, ALLOWED_REGISTER_FIELDS);
  const email = sanitized.email as string;
  const authHash = sanitized.authHash as string;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    // Perform a dummy bcrypt hash to equalize response time with the new-user
    // path, preventing email enumeration via timing side-channel.
    await bcrypt.hash(authHash, config.BCRYPT_ROUNDS);

    // Send notification email asynchronously (don't block the response)
    void sendRegistrationAttemptEmail(email).then((result) => {
      if (!result.success) {
        logger.error('Failed to send registration attempt notification', {
          email: maskEmail(email),
          error: result.message,
        });
      }
    });

    // Return the same response as a successful registration to prevent email enumeration
    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email to verify your account.',
      data: { emailSent: true },
    });
    return;
  }

  const hashedAuth = await bcrypt.hash(authHash, config.BCRYPT_ROUNDS);

  const user = await User.create({
    ...sanitized,
    authHash: hashedAuth,
  });

  const registerCtx = getRequestContext(req);
  await createAuditLog(
    user._id.toString(),
    'registration',
    { email: maskEmail(email) },
    registerCtx.ip,
    registerCtx.userAgent,
  );

  const verificationToken = jwt.sign(
    {
      userId: user._id.toString(),
      purpose: 'email_verification',
      stateHash: generateStateHash(String(false)),
    } satisfies JwtEmailPayload,
    derivePurposeKey(config.JWT_REFRESH_SECRET, 'email_verification'),
    { algorithm: 'HS256', expiresIn: '24h' },
  );

  logger.info('New user registered', {
    userId: user._id.toString(),
    email: maskEmail(email),
  });

  // Fire-and-forget the SMTP send (mirroring forgotPassword / resendVerification
  // and the existing-account path above). Awaiting the send here — and gating
  // the response on its result — reopened the email-enumeration channel two
  // ways: (1) a body oracle, since with SMTP unconfigured (permitted in
  // production, only warned) every NEW registration returned emailSent:false
  // while every EXISTING one returned emailSent:true; (2) a timing oracle, since
  // the new-account path awaited the SMTP round-trip that the existing path
  // skips. A constant emailSent:true keeps both paths body- and status-identical.
  void sendVerificationEmail(email, verificationToken).then((result) => {
    if (!result.success) {
      logger.error('Failed to send verification email', {
        userId: user._id.toString(),
        email: maskEmail(email),
        error: result.message,
      });
    }
  });

  // Keep the same message and emailSent value regardless of email delivery
  // outcome to prevent email enumeration. The frontend uses data.emailSent for
  // feedback; it is constant here to match the existing-account path exactly.
  res.status(201).json({
    success: true,
    message: 'Registration successful. Please check your email to verify your account.',
    data: { emailSent: true },
  });
});

// ─── Login ───────────────────────────────────────────────────────────────────

export const login = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const body = req.body as LoginInput;
  const { email, authHash, deviceInfo } = body;
  const { ip, userAgent } = getRequestContext(req);

  const user = await User.findOne({ email }).select('+authHash +twoFactorSecret +backupCodes');
  if (!user) {
    // Perform a dummy bcrypt compare to equalize response time with the
    // existing-user path, preventing email enumeration via timing side-channel.
    await bcrypt.compare(authHash, DUMMY_BCRYPT_HASH);
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  const isMatch = await bcrypt.compare(authHash, user.authHash);

  // Handle account lockout AFTER the bcrypt compare so a locked account is
  // indistinguishable from invalid credentials to anyone who does not already
  // know the password. Returning 403 ACCOUNT_LOCKED *before* the compare (the
  // previous behaviour) let an attacker force a lockout on a target email and
  // read the 403 as confirmation the account exists — an enumeration oracle,
  // and a timing oracle since the locked path skipped bcrypt entirely. We now
  // surface ACCOUNT_LOCKED only to a caller that supplies the correct password
  // (the legitimate owner); a wrong/guessed password on a locked account
  // returns the same generic 401 as a non-existent email. Lockout state is not
  // mutated on this path, so any unlock email already issued (its token bound
  // to the current lockoutUntil) stays valid.
  if (user.lockoutUntil && user.lockoutUntil > new Date()) {
    if (isMatch) {
      throw httpErrors.forbidden(ERROR_CODES.ACCOUNT_LOCKED);
    }
    // Wrong password against a locked account returns the same generic 401 as
    // an unknown email, so it must carry the same delay. Without this, a locked
    // account would answer in bcrypt time while an unknown email slept for
    // seconds — "fast" would then mean "this account exists and is locked",
    // an inverse oracle worse than the one being closed. The throttle only
    // sleeps; lockout state is still left untouched here, so an unlock email
    // already issued (its token bound to lockoutUntil) stays valid.
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  // Check email verification after bcrypt compare to avoid disclosing whether
  // an email is registered and unverified. Return the same 401 status and
  // message as invalid credentials, with a hint in the data field so the
  // client can show a helpful message without exposing this in the error code.
  if (isMatch && !user.emailVerified) {
    // The password was correct, so this is not a brute-force attempt.
    resetLoginAttempts(email);
    res.status(401).json({
      success: false,
      message: 'Invalid email or password',
      data: { reason: 'email_not_verified' },
    });
    return;
  }

  if (!isMatch) {
    // Atomically increment failedLoginAttempts first, then check the result
    // to prevent race conditions where concurrent requests read stale counts
    const updatedUser = await User.findOneAndUpdate(
      { _id: user._id },
      { $inc: { failedLoginAttempts: 1 } },
      { returnDocument: 'after' },
    );

    const newAttempts = updatedUser?.failedLoginAttempts ?? 1;
    const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;

    if (shouldLock) {
      // Set lockout in a separate atomic update based on the actual count
      // (idempotent — safe to re-set if multiple concurrent requests exceed the threshold)
      const lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
      await User.updateOne({ _id: user._id }, { $set: { lockoutUntil } });

      // Only send the unlock email when we are the request that crossed the
      // threshold (exactly equal), preventing duplicate emails from concurrent
      // failed logins that both exceed MAX_FAILED_ATTEMPTS.
      if (newAttempts === MAX_FAILED_ATTEMPTS) {
        logger.warn('Account locked due to too many failed attempts', { email: maskEmail(email) });

        // Send unlock email - use lockoutUntil (stable) instead of failedLoginAttempts (can change)
        const unlockToken = jwt.sign(
          {
            userId: user._id.toString(),
            purpose: 'account_unlock',
            stateHash: generateStateHash(lockoutUntil.toISOString()),
          } satisfies JwtUnlockPayload,
          derivePurposeKey(config.JWT_REFRESH_SECRET, 'account_unlock'),
          { algorithm: 'HS256', expiresIn: '1h' },
        );

        // Send email asynchronously (don't block the response)
        void sendAccountUnlockEmail(email, unlockToken).then((result) => {
          if (!result.success) {
            logger.error('Failed to send account unlock email', {
              email: maskEmail(email),
              error: result.message,
            });
          }
        });
      }
    }

    await createAuditLog(
      user._id.toString(),
      'login_failed',
      { reason: 'invalid_password' },
      ip,
      userAgent,
    );

    // Progressive delay: slow down brute-force attempts. Driven by the shared
    // per-email throttle, NOT by `newAttempts`, so an unknown email is delayed
    // identically (see applyFailedLoginDelay). Exactly one delay per branch.
    await applyFailedLoginDelay(email);

    throw httpErrors.unauthorized('Invalid email or password');
  }

  // Reset failed attempts on successful credential check. The throttle reset is
  // UNCONDITIONAL: attempts recorded while the account was locked never touched
  // `failedLoginAttempts`, so gating it on the database counter would let a
  // stale in-memory count survive a successful login and delay the next typo.
  resetLoginAttempts(email);

  if (user.failedLoginAttempts > 0 || user.lockoutUntil) {
    user.failedLoginAttempts = 0;
    user.lockoutUntil = undefined;
    await user.save();
  }

  // Detect and recover from interrupted vault key rotation. If rotationInProgress
  // is true, the server crashed mid-rotation. Clear the flag and pending fields so
  // the user can log in normally. Items partially re-encrypted with the new key
  // will be undecryptable, but the user can trigger a fresh rotation to fix it.
  //
  // `rotationInProgress` doubles as the LIVE write-fence read by
  // `assertVaultNotRotating`, raised at the start of `bulkReEncrypt` and cleared
  // at its end. So this recovery must fire ONLY for a genuinely crashed rotation,
  // never for one still in flight: a rotation that is actively processing holds
  // the `vault-rotation:<userId>` JobLock for its whole flag-true window
  // (acquired before the flag is set, released after it is cleared), whereas a
  // crashed one leaves no live lock. Clearing the flag while a rotation is live
  // would lower the fence mid-run and readmit a second session's stale-key write
  // that the rotation's client-enumerated set does not cover — stranding that row
  // under the superseded key, the exact data loss the fence prevents. A crashed
  // rotation's lock TTL-expires (ROTATION_LOCK_TTL_MS), after which the next
  // login clears the stuck flag; a live rotation clears it itself on
  // commit/abort, so nothing is left wedged either way.
  if (user.rotationInProgress && !(await isVaultRotationLockHeld(user._id.toString()))) {
    logger.warn('Interrupted vault key rotation detected during login — clearing rotation state', {
      userId: user._id.toString(),
      email: maskEmail(email),
    });

    await User.updateOne(
      { _id: user._id },
      {
        $set: { rotationInProgress: false },
        $unset: {
          pendingEncryptedVaultKey: 1,
          pendingVaultKeyIv: 1,
          pendingVaultKeyTag: 1,
        },
      },
    );

    await createAuditLog(
      user._id.toString(),
      'rotation_recovery',
      { detail: 'Interrupted vault key rotation detected and cleared during login' },
      ip,
      userAgent,
    );
  }

  // 2FA flow
  if (user.twoFactorEnabled) {
    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        purpose: '2fa_temp',
        deviceHash: generateDeviceHash(req),
      } satisfies JwtTempPayload,
      derivePurposeKey(config.JWT_REFRESH_SECRET, '2fa_temp'),
      { algorithm: 'HS256', expiresIn: '5m' },
    );

    res.status(200).json({
      success: true,
      data: {
        twoFactorRequired: true,
        tempToken,
      },
    });
    return;
  }

  // Issue tokens
  const accessToken = generateAccessToken(user._id.toString());
  const refreshTokenRaw = generateRefreshToken();
  const refreshTokenHash = hashToken(refreshTokenRaw);
  const familyId = crypto.randomUUID();

  const lifetime = resolveRefreshLifetime({});
  await RefreshToken.create({
    userId: user._id,
    tokenHash: refreshTokenHash,
    familyId,
    deviceInfo: sanitizeDeviceInfo(deviceInfo, req),
    expiresAt: lifetime.expiresAt,
    ...(lifetime.absoluteExpiresAt ? { absoluteExpiresAt: lifetime.absoluteExpiresAt } : {}),
  });

  setRefreshCookie(res, refreshTokenRaw, lifetime.maxAgeMs);
  clearCsrfCookie(res);

  await createAuditLog(user._id.toString(), 'login', undefined, ip, userAgent);

  logger.info('User logged in', { userId: user._id.toString(), email: maskEmail(email) });

  res.status(200).json({
    success: true,
    data: {
      accessToken,
      encryptedVaultKey: user.encryptedVaultKey,
      vaultKeyIv: user.vaultKeyIv,
      vaultKeyTag: user.vaultKeyTag,
      kdfIterations: user.kdfIterations,
      kdfAlgorithm: user.kdfAlgorithm,
    },
  });
});

// ─── Login 2FA ───────────────────────────────────────────────────────────────

export const login2fa = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Login2faInput;
  const { tempToken, code, deviceInfo } = body;
  const { ip, userAgent } = getRequestContext(req);

  let payload: JwtTempPayload;
  try {
    payload = jwt.verify(tempToken, derivePurposeKey(config.JWT_REFRESH_SECRET, '2fa_temp'), {
      algorithms: ['HS256'],
    }) as JwtTempPayload;
  } catch {
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  // Validate the JWT purpose to prevent token misuse across different flows
  if (typeof payload.purpose !== 'string' || payload.purpose !== '2fa_temp') {
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  // Verify the requesting device matches the one that initiated the 2FA flow.
  // This prevents a stolen temp token from being used on a different device.
  // Uses constant-time comparison to prevent timing side-channel attacks.
  if (payload.deviceHash) {
    const currentDeviceHash = generateDeviceHash(req);
    const expected = Buffer.from(payload.deviceHash, 'utf8');
    const actual = Buffer.from(currentDeviceHash, 'utf8');
    // timingSafeEqual requires equal-length buffers. Since both are SHA-256
    // hex digests they should always be 64 chars, but guard against edge cases.
    const isMatch = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
    if (!isMatch) {
      logger.warn('2FA device mismatch detected', { userId: payload.userId });
      throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
    }
  }

  const user = await User.findById(payload.userId).select(
    '+twoFactorSecret +backupCodes +encryptedVaultKey +vaultKeyIv +vaultKeyTag',
  );
  if (!user) {
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  // Defense-in-depth: reject 2FA completion if the account became locked
  // between the password step and the 2FA step (e.g. a concurrent brute-force
  // attempt on another session triggered the lockout). The temp token alone
  // must not bypass an active lockout.
  if (user.lockoutUntil && user.lockoutUntil > new Date()) {
    throw httpErrors.forbidden(ERROR_CODES.ACCOUNT_LOCKED);
  }

  if (!user.twoFactorEnabled || !user.twoFactorSecret) {
    throw httpErrors.badRequest(ERROR_CODES.TWO_FA_NOT_ENABLED);
  }

  // Decrypt the stored secret before TOTP verification
  const decryptedSecret = cryptoManager.decryptTextSync(
    user.twoFactorSecret,
    twoFactorEncryptionKey,
  );

  // Try TOTP verification first
  const totp = new TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(decryptedSecret),
  });
  // window: 1 allows ±1 time step (±30s) to tolerate minor clock drift
  const totpDelta = totp.validate({ token: code, window: 1 });
  let isValid = totpDelta !== null;
  let usedBackupCode = false;

  // TOTP replay protection: reject codes that have already been used.
  // The delta from validate() tells us which time step the code belongs to.
  // We store the time step and reject codes at or before the stored timestamp.
  if (isValid && totpDelta !== null) {
    const currentTimeStep = Math.floor(Date.now() / 1000 / 30) + totpDelta;
    if (user.lastTotpTimestamp != null && currentTimeStep <= user.lastTotpTimestamp) {
      isValid = false; // Replay detected — code already used
    }
  }

  // If TOTP fails, try backup codes
  if (!isValid && user.backupCodes && user.backupCodes.length > 0) {
    const matchIndex = await findMatchingBackupCodeIndex(code, user.backupCodes);
    if (matchIndex >= 0) {
      // Atomically remove the matched backup code to prevent race conditions
      // where the same code could be used twice concurrently.
      const matchedCode = user.backupCodes[matchIndex];
      // `as any` is required here because Mongoose's TypeScript definitions
      // (FilterQuery<T>) do not support MongoDB's array element matching syntax
      // where `{ backupCodes: matchedCode }` means "match documents where the
      // backupCodes array contains matchedCode". The Mongoose types expect
      // `backupCodes` to be the full array type, not a single element value.
      // This is a known Mongoose typing limitation (not a runtime concern).
      const result = await User.findOneAndUpdate(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
        { _id: user._id, backupCodes: matchedCode } as any,
        { $pull: { backupCodes: matchedCode } },
        { returnDocument: 'after' },
      );
      if (result) {
        isValid = true;
        usedBackupCode = true;
        logger.info('Backup code used for 2FA', { userId: user._id.toString() });
      }
      // If result is null, the code was already consumed by a concurrent request
    }
  }

  if (!isValid) {
    // Brute-force protection parity with the password step: a wrong 2FA code
    // counts as a failed authentication attempt. Without this the 2FA step —
    // the last line of defense once the password is known or phished — could be
    // brute-forced for the full 5-minute life of the (reusable, IP-keyed-only)
    // temp token. Atomically increment, then lock at the threshold, mirroring
    // the password-step logic so the shared lockout applies across both steps.
    const updatedUser = await User.findOneAndUpdate(
      { _id: user._id },
      { $inc: { failedLoginAttempts: 1 } },
      { returnDocument: 'after' },
    );

    const newAttempts = updatedUser?.failedLoginAttempts ?? 1;
    if (newAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
      await User.updateOne({ _id: user._id }, { $set: { lockoutUntil } });

      // Only the request that crosses the threshold (exactly equal) sends the
      // unlock email, preventing duplicate mail from concurrent failures.
      if (newAttempts === MAX_FAILED_ATTEMPTS) {
        logger.warn('Account locked due to too many failed 2FA attempts', {
          userId: user._id.toString(),
        });

        const unlockToken = jwt.sign(
          {
            userId: user._id.toString(),
            purpose: 'account_unlock',
            stateHash: generateStateHash(lockoutUntil.toISOString()),
          } satisfies JwtUnlockPayload,
          derivePurposeKey(config.JWT_REFRESH_SECRET, 'account_unlock'),
          { algorithm: 'HS256', expiresIn: '1h' },
        );

        // Send email asynchronously (don't block the response)
        void sendAccountUnlockEmail(user.email, unlockToken).then((result) => {
          if (!result.success) {
            logger.error('Failed to send account unlock email', {
              userId: user._id.toString(),
              error: result.message,
            });
          }
        });
      }
    }

    await createAuditLog(
      user._id.toString(),
      'login_failed',
      { reason: '2fa_invalid' },
      ip,
      userAgent,
    );

    // Progressive delay: slow down brute-force attempts (skipped in test
    // environment). This step keeps using the durable `failedLoginAttempts`
    // counter — unlike `login`, which must source its delay from the per-email
    // throttle. There is no enumeration vector to equalize here: reaching this
    // code requires a valid, device-bound temp token, which is only ever issued
    // for an account that exists and whose password already verified.
    if (!isTest) {
      const delay = getProgressiveDelay(newAttempts);
      if (delay > 0) {
        await sleep(delay);
      }
    }

    throw httpErrors.unauthorized(ERROR_CODES.TWO_FA_INVALID);
  }

  // Reset any failed-attempt count accrued from earlier wrong 2FA codes in
  // this session (parity with the password step, which resets on a successful
  // credential check). Uses an atomic update rather than saving the loaded doc
  // so a concurrent increment is not clobbered.
  if (user.failedLoginAttempts > 0 || user.lockoutUntil) {
    await User.updateOne(
      { _id: user._id },
      { $set: { failedLoginAttempts: 0 }, $unset: { lockoutUntil: 1 } },
    );
  }

  // Atomically persist the TOTP time step to prevent replay — including the
  // same-time-step concurrent race that the earlier read-check (a non-atomic
  // read-then-write) cannot catch, since two requests can both pass that check
  // before either writes. This compare-and-set writes only when the time step
  // strictly advances the stored value; a no-op update (matchedCount === 0)
  // means another concurrent request already consumed this (or a later) code,
  // so it is rejected as a replay. It runs BEFORE token issuance below, so a
  // replay loser never receives tokens. Skipped for backup codes (already
  // consumed single-use atomically via the $pull above).
  if (!usedBackupCode && totpDelta !== null) {
    const usedTimeStep = Math.floor(Date.now() / 1000 / 30) + totpDelta;
    const cas = await User.updateOne(
      {
        _id: user._id,
        $or: [
          { lastTotpTimestamp: { $exists: false } },
          { lastTotpTimestamp: null },
          { lastTotpTimestamp: { $lt: usedTimeStep } },
        ],
      },
      { $set: { lastTotpTimestamp: usedTimeStep } },
    );
    if (cas.matchedCount === 0) {
      await createAuditLog(
        user._id.toString(),
        'login_failed',
        { reason: '2fa_replay' },
        ip,
        userAgent,
      );
      throw httpErrors.unauthorized(ERROR_CODES.TWO_FA_INVALID);
    }
  }

  // Issue tokens
  const accessToken = generateAccessToken(user._id.toString());
  const refreshTokenRaw = generateRefreshToken();
  const refreshTokenHash = hashToken(refreshTokenRaw);
  const familyId = crypto.randomUUID();

  const lifetime = resolveRefreshLifetime({});
  await RefreshToken.create({
    userId: user._id,
    tokenHash: refreshTokenHash,
    familyId,
    deviceInfo: sanitizeDeviceInfo(deviceInfo, req),
    expiresAt: lifetime.expiresAt,
    ...(lifetime.absoluteExpiresAt ? { absoluteExpiresAt: lifetime.absoluteExpiresAt } : {}),
  });

  setRefreshCookie(res, refreshTokenRaw, lifetime.maxAgeMs);
  clearCsrfCookie(res);

  await createAuditLog(user._id.toString(), 'login', { twoFactor: true }, ip, userAgent);

  logger.info('User logged in via 2FA', { userId: user._id.toString() });

  res.status(200).json({
    success: true,
    data: {
      accessToken,
      encryptedVaultKey: user.encryptedVaultKey,
      vaultKeyIv: user.vaultKeyIv,
      vaultKeyTag: user.vaultKeyTag,
      kdfIterations: user.kdfIterations,
      kdfAlgorithm: user.kdfAlgorithm,
    },
  });
});

// ─── Refresh ─────────────────────────────────────────────────────────────────

export const refresh = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const token: string | undefined = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;

  if (!token) {
    throw httpErrors.unauthorized('Refresh token not provided');
  }

  const tokenHash = hashToken(token);

  // Check if the topology supports transactions (replica set or sharded cluster)
  // before attempting one, rather than relying on error string matching.
  const supportsTransactions =
    mongoose.connection.readyState === mongoose.ConnectionStates.connected &&
    Boolean(mongoose.connection.getClient().options.replicaSet);

  const newRefreshTokenRaw = generateRefreshToken();
  const newRefreshTokenHash = hashToken(newRefreshTokenRaw);

  // Holds the matched token's metadata after successful atomic claim.
  interface ClaimedTokenMeta {
    userId: mongoose.Types.ObjectId;
    familyId: string;
    deviceInfo: { userAgent: string; ip: string; fingerprint: string };
    // The cookie is set once, after both branches. Carry the rotated lifetime's
    // max-age here so it is derived from the SAME computation that pinned the
    // new row's expiresAt — the cookie and the row can never disagree.
    maxAgeMs: number;
  }
  let claimed: ClaimedTokenMeta | null = null;

  if (supportsTransactions) {
    // Transactional path: perform the claim (mark-used) AND create the new
    // token inside a single transaction so both commit or neither does. This
    // eliminates the race where the original token could be marked used but
    // the new token creation fails, leaving the user without a valid refresh
    // token. If the transaction commits, we are guaranteed a new token exists.
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const storedToken = await RefreshToken.findOneAndUpdate(
          { tokenHash, usedAt: null, expiresAt: { $gt: new Date() } },
          { $set: { usedAt: new Date() } },
          { returnDocument: 'before', session },
        );

        if (!storedToken) {
          // Leave claimed=null; handled after the transaction completes.
          return;
        }

        // Rotation carries any absolute family deadline forward unchanged; a row
        // without one slides to now + REFRESH_TOKEN_DAYS (today's behaviour).
        const lifetime = resolveRefreshLifetime({
          absoluteExpiresAt: storedToken.absoluteExpiresAt,
        });

        await RefreshToken.create(
          [
            {
              userId: storedToken.userId,
              tokenHash: newRefreshTokenHash,
              familyId: storedToken.familyId,
              deviceInfo: storedToken.deviceInfo,
              expiresAt: lifetime.expiresAt,
              ...(lifetime.absoluteExpiresAt
                ? { absoluteExpiresAt: lifetime.absoluteExpiresAt }
                : {}),
            },
          ],
          { session },
        );

        claimed = {
          userId: storedToken.userId,
          familyId: storedToken.familyId,
          deviceInfo: storedToken.deviceInfo,
          maxAgeMs: lifetime.maxAgeMs,
        };
      });
    } finally {
      await session.endSession();
    }
  } else {
    // Non-transactional fallback (standalone MongoDB). We accept the edge
    // case that the claim may succeed but the subsequent create could fail —
    // a crash between the two leaves the user having to log in again. This
    // is a mild inconvenience, not a security issue: the old token is
    // already invalidated and cannot be reused.
    const storedToken = await RefreshToken.findOneAndUpdate(
      { tokenHash, usedAt: null, expiresAt: { $gt: new Date() } },
      { $set: { usedAt: new Date() } },
      { returnDocument: 'before' },
    );

    if (storedToken) {
      // Rotation carries any absolute family deadline forward unchanged; a row
      // without one slides to now + REFRESH_TOKEN_DAYS (today's behaviour).
      const lifetime = resolveRefreshLifetime({
        absoluteExpiresAt: storedToken.absoluteExpiresAt,
      });
      try {
        await RefreshToken.create({
          userId: storedToken.userId,
          tokenHash: newRefreshTokenHash,
          familyId: storedToken.familyId,
          deviceInfo: storedToken.deviceInfo,
          expiresAt: lifetime.expiresAt,
          ...(lifetime.absoluteExpiresAt ? { absoluteExpiresAt: lifetime.absoluteExpiresAt } : {}),
        });
        claimed = {
          userId: storedToken.userId,
          familyId: storedToken.familyId,
          deviceInfo: storedToken.deviceInfo,
          maxAgeMs: lifetime.maxAgeMs,
        };
      } catch (createErr: unknown) {
        // New token creation failed after claim; log loudly. The user must
        // log in again, but reuse detection still guards the old token.
        logger.error(
          'Non-transactional refresh: failed to create new token after claiming old one',
          { userId: storedToken.userId.toString(), error: createErr },
        );
        clearRefreshCookie(res);
        throw httpErrors.internalServerError('Failed to issue new refresh token');
      }
    }
  }

  if (!claimed) {
    // The atomic claim did not match a row. Either the token doesn't exist,
    // it was already used (reuse attack), or it expired. Look it up to
    // differentiate between these cases.
    const existingToken = await RefreshToken.findOne({ tokenHash });
    if (existingToken) {
      // Token exists — check if it's expired (unused) vs reused
      if (!existingToken.usedAt && existingToken.expiresAt < new Date()) {
        await RefreshToken.deleteOne({ _id: existingToken._id });
        clearRefreshCookie(res);
        throw httpErrors.unauthorized(ERROR_CODES.TOKEN_EXPIRED);
      }
      // usedAt is set → token reuse (potential stolen token attack). Revoke
      // the entire family so no descendant tokens can be used either.
      logger.warn('Refresh token reuse detected — revoking entire token family', {
        userId: existingToken.userId.toString(),
        familyId: existingToken.familyId,
      });
      await RefreshToken.deleteMany({
        userId: existingToken.userId,
        familyId: existingToken.familyId,
      });
      clearRefreshCookie(res);
      throw httpErrors.unauthorized(ERROR_CODES.TOKEN_REUSE_DETECTED);
    }

    clearRefreshCookie(res);
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  const claimedMeta: ClaimedTokenMeta = claimed;

  // Look up user for new access token and verify account status
  const user = await User.findById(claimedMeta.userId);
  if (!user || user.deletionPending || !user.emailVerified) {
    clearRefreshCookie(res);
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }
  if (user.lockoutUntil && user.lockoutUntil > new Date()) {
    clearRefreshCookie(res);
    throw httpErrors.forbidden(ERROR_CODES.ACCOUNT_LOCKED);
  }

  const accessToken = generateAccessToken(user._id.toString());

  setRefreshCookie(res, newRefreshTokenRaw, claimedMeta.maxAgeMs);
  clearCsrfCookie(res);

  res.status(200).json({
    success: true,
    data: { accessToken },
  });
});

// ─── Logout ──────────────────────────────────────────────────────────────────

export const logout = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = (req as AuthenticatedRequest).user._id;
  const token: string | undefined = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;

  if (token) {
    const tokenHash = hashToken(token);
    await RefreshToken.deleteOne({ tokenHash });
  }

  clearRefreshCookie(res);
  clearCsrfCookie(res);

  const logoutCtx = getRequestContext(req);
  await createAuditLog(userId, 'logout', undefined, logoutCtx.ip, logoutCtx.userAgent);

  logger.info('User logged out', { userId });

  res.status(200).json({
    success: true,
    message: 'Logged out successfully',
  });
});

// ─── Lock ────────────────────────────────────────────────────────────────────

/**
 * POST /auth/lock
 *
 * Records a `vault_lock` audit event when the client manually locks the vault.
 * Lock is semantically distinct from logout: the refresh token cookie remains
 * valid so the user can unlock without re-authenticating, but we want the
 * action visible in the audit trail for paranoid users reviewing access.
 */
export const lock = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = (req as AuthenticatedRequest).user._id;

  const lockCtx = getRequestContext(req);
  await createAuditLog(userId, 'vault_lock', undefined, lockCtx.ip, lockCtx.userAgent);

  res.status(200).json({
    success: true,
    message: 'Vault locked',
  });
});

// ─── Logout All ──────────────────────────────────────────────────────────────

export const logoutAll = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = (req as AuthenticatedRequest).user._id;

  // Exclude the current session's refresh token so the caller stays logged in
  const currentToken: string | undefined = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;
  const filter: Record<string, unknown> = { userId };

  if (currentToken) {
    const currentTokenHash = hashToken(currentToken);
    filter.tokenHash = { $ne: currentTokenHash };
  }

  const result = await RefreshToken.deleteMany(filter);

  clearCsrfCookie(res);

  const logoutAllCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'session_revoke',
    { sessionsRevoked: result.deletedCount },
    logoutAllCtx.ip,
    logoutAllCtx.userAgent,
  );

  logger.info('All other sessions revoked', { userId, count: result.deletedCount });

  res.status(200).json({
    success: true,
    message: 'All other sessions have been revoked',
  });
});

// ─── Verify Email ────────────────────────────────────────────────────────────

export const verifyEmail = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const { token } = req.body as { token: string };

  let payload: JwtEmailPayload;
  try {
    payload = jwt.verify(token, derivePurposeKey(config.JWT_REFRESH_SECRET, 'email_verification'), {
      algorithms: ['HS256'],
    }) as JwtEmailPayload;
  } catch {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Validate the JWT purpose to prevent token misuse across different flows
  if (typeof payload.purpose !== 'string' || payload.purpose !== 'email_verification') {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  const user = await User.findById(payload.userId);
  if (!user) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Verify the token was generated for the current email verification state
  // (invalidates the token once the email has been verified)
  if (payload.stateHash !== generateStateHash(String(user.emailVerified))) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  if (user.emailVerified) {
    res.status(200).json({
      success: true,
      message: 'Email already verified',
    });
    return;
  }

  user.emailVerified = true;
  await user.save();

  const verifyEmailCtx = getRequestContext(req);
  await createAuditLog(
    user._id.toString(),
    'email_verified',
    undefined,
    verifyEmailCtx.ip,
    verifyEmailCtx.userAgent,
  );

  logger.info('Email verified', { userId: user._id.toString() });

  res.status(200).json({
    success: true,
    message: 'Email verified successfully',
  });
});

// ─── Forgot Password ────────────────────────────────────────────────────────

export const forgotPassword = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body as { email: string };

  const user = await User.findOne({ email }).select('+authHash');

  // Always perform a dummy bcrypt compare with the same cost factor as real
  // password comparisons, regardless of whether the user exists. This keeps
  // the endpoint response time roughly constant so that email enumeration
  // via timing side-channel is prevented. Using bcrypt.hash(..., 1) would
  // take ~1ms vs the real ~200ms, leaking the presence of the account.
  // We run this on BOTH paths because the existing-user path does no real
  // bcrypt work (it only sends an email and signs a JWT).
  await bcrypt.compare('dummy-timing-equalization-value', DUMMY_BCRYPT_HASH);

  if (!user) {
    // Return generic success to avoid email enumeration
    res.status(200).json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.',
      data: { emailSent: true },
    });
    return;
  }

  const resetToken = jwt.sign(
    {
      userId: user._id.toString(),
      purpose: 'password_reset',
      stateHash: generateStateHash(user.authHash),
    } satisfies JwtResetPayload,
    derivePurposeKey(config.JWT_REFRESH_SECRET, 'password_reset'),
    { algorithm: 'HS256', expiresIn: '1h' },
  );

  // Fire-and-forget the SMTP send so the response returns before the mail
  // round-trip. Awaiting it here would make the existing-user path measurably
  // slower than the non-existent-user path (which performs no SMTP work),
  // reopening the email-enumeration timing channel that the dummy bcrypt above
  // is meant to close. Mirrors the register-attempt notification pattern.
  void sendPasswordResetEmail(email, resetToken).then((result) => {
    if (result.success) {
      logger.info('Password reset email sent', { userId: user._id.toString() });
    } else {
      logger.error('Failed to send password reset email', {
        userId: user._id.toString(),
        email: maskEmail(email),
        error: result.message,
      });
    }
  });

  // Always return the same generic message regardless of email delivery outcome
  // to prevent anti-enumeration leaks (SMTP failure would otherwise change the
  // response for existing users, revealing their existence).
  res.status(200).json({
    success: true,
    message: 'If an account with that email exists, a password reset link has been sent.',
    data: { emailSent: true },
  });
});

// ─── Reset Password ─────────────────────────────────────────────────────────

export const resetPassword = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const body = req.body as ResetPasswordInput;
  const { token, email, newAuthHash, newEncryptedVaultKey, newVaultKeyIv, newVaultKeyTag } = body;

  let payload: JwtResetPayload;
  try {
    payload = jwt.verify(token, derivePurposeKey(config.JWT_REFRESH_SECRET, 'password_reset'), {
      algorithms: ['HS256'],
    }) as JwtResetPayload;
  } catch {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Validate the JWT purpose to prevent token misuse across different flows
  if (typeof payload.purpose !== 'string' || payload.purpose !== 'password_reset') {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  const user = await User.findById(payload.userId).select('+authHash');
  if (!user) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Validate that the submitted email matches the token's user's email.
  // The email is used as the PBKDF2 salt for key derivation on the client.
  // If the user enters a different email, the derived keys will be wrong,
  // permanently locking them out of their vault.
  if (email.toLowerCase() !== user.email.toLowerCase()) {
    throw httpErrors.badRequest(ERROR_CODES.EMAIL_MISMATCH);
  }

  // Verify the token was generated for the current authHash
  // (invalidates the token once the password has been changed)
  if (payload.stateHash !== generateStateHash(user.authHash)) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  const hashedAuth = await bcrypt.hash(newAuthHash, config.BCRYPT_ROUNDS);

  // Revoke all existing sessions BEFORE saving the new password. If the save
  // fails after revocation, the user just has to log in again with their new
  // credentials once the reset finishes. The reverse ordering would leave
  // stale refresh tokens valid after a password change, which is a security
  // issue. For strong guarantees on replica sets, a transaction would be
  // preferable, but sequential-delete-first is safe under any failure mode.
  await RefreshToken.deleteMany({ userId: user._id });

  user.authHash = hashedAuth;
  user.encryptedVaultKey = newEncryptedVaultKey;
  user.vaultKeyIv = newVaultKeyIv;
  user.vaultKeyTag = newVaultKeyTag;
  user.failedLoginAttempts = 0;
  user.lockoutUntil = undefined;
  user.passwordChangedAt = new Date();
  await user.save();

  const resetCtx = getRequestContext(req);
  await createAuditLog(
    user._id.toString(),
    'password_change',
    { method: 'reset' },
    resetCtx.ip,
    resetCtx.userAgent,
  );

  logger.info('Password reset completed', { userId: user._id.toString() });

  res.status(200).json({
    success: true,
    message: 'Password has been reset successfully. Please log in with your new credentials.',
  });
});

// ─── Unlock Account ──────────────────────────────────────────────────────────

export const unlockAccount = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const { token } = req.body as { token: string };

  let payload: JwtUnlockPayload;
  try {
    payload = jwt.verify(token, derivePurposeKey(config.JWT_REFRESH_SECRET, 'account_unlock'), {
      algorithms: ['HS256'],
    }) as JwtUnlockPayload;
  } catch {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Validate the JWT purpose to prevent token misuse across different flows
  if (typeof payload.purpose !== 'string' || payload.purpose !== 'account_unlock') {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  const user = await User.findById(payload.userId);
  if (!user) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Verify the token was generated for the current lockout state using lockoutUntil
  // (invalidates the token once the account has been unlocked, since lockoutUntil is cleared)
  if (payload.stateHash !== generateStateHash(user.lockoutUntil?.toISOString() ?? '')) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  user.failedLoginAttempts = 0;
  user.lockoutUntil = undefined;
  await user.save();

  const unlockCtx = getRequestContext(req);
  await createAuditLog(
    user._id.toString(),
    'account_unlock',
    { method: 'email_link' },
    unlockCtx.ip,
    unlockCtx.userAgent,
  );

  logger.info('Account unlocked via email', { userId: user._id.toString() });

  res.status(200).json({
    success: true,
    message: 'Account has been unlocked successfully. You can now log in.',
  });
});

// ─── Resend Verification Email ────────────────────────────────────────────────

export const resendVerification = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body as { email: string };

  const user = await User.findOne({ email });

  // Always perform a dummy bcrypt compare (cost 12) regardless of whether
  // the user exists, to equalize response time across paths and prevent
  // email enumeration via timing side-channel. The existing-user path does
  // no real bcrypt work (JWT sign + email template build + SMTP send), so
  // without this equalization the non-existent path alone would add a
  // ~200ms asymmetry and leak account existence.
  await bcrypt.compare('dummy-timing-equalization-value', DUMMY_BCRYPT_HASH);

  if (!user || user.emailVerified) {
    // Return generic success to prevent email enumeration
    res.status(200).json({
      success: true,
      message:
        'If an account with that email exists and is unverified, a verification email has been sent.',
      data: { emailSent: true },
    });
    return;
  }

  const verificationToken = jwt.sign(
    {
      userId: user._id.toString(),
      purpose: 'email_verification',
      stateHash: generateStateHash(String(false)),
    } satisfies JwtEmailPayload,
    derivePurposeKey(config.JWT_REFRESH_SECRET, 'email_verification'),
    { algorithm: 'HS256', expiresIn: '24h' },
  );

  // Fire-and-forget the SMTP send (see forgotPassword) so the existing-user
  // path returns in the same time as the non-existent/already-verified path,
  // closing the email-enumeration timing channel.
  void sendVerificationEmail(email, verificationToken).then((result) => {
    if (result.success) {
      logger.info('Verification email resent', {
        userId: user._id.toString(),
        email: maskEmail(email),
      });
    } else {
      logger.error('Failed to resend verification email', {
        userId: user._id.toString(),
        email: maskEmail(email),
        error: result.message,
      });
    }
  });

  // Always return the same generic message regardless of email delivery outcome
  // to prevent anti-enumeration leaks (SMTP failure would otherwise change the
  // response for existing users, revealing their existence).
  res.status(200).json({
    success: true,
    message:
      'If an account with that email exists and is unverified, a verification email has been sent.',
    data: { emailSent: true },
  });
});

// ─── Verify Unlock ──────────────────────────────────────────────────────────

/**
 * POST /auth/verify-unlock
 *
 * Lightweight endpoint for the unlock screen to verify the auth hash
 * server-side. This provides server-side rate limiting for unlock attempts,
 * preventing an attacker with XSS from clearing client-side lockout state.
 *
 * The client still performs the actual crypto derivation locally — this
 * endpoint only validates the derived auth hash against bcrypt.
 */
export const verifyUnlock = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const user = req.user;
  if (!user?._id) {
    throw httpErrors.unauthorized('Authentication required');
  }

  const { authHash } = req.body as VerifyUnlockInput;

  const fullUser = await User.findById(user._id).select('+authHash');
  if (!fullUser) {
    throw httpErrors.notFound('User not found');
  }

  const verifyUnlockCtx = getRequestContext(req);
  const isMatch = await bcrypt.compare(authHash, fullUser.authHash);
  if (!isMatch) {
    await createAuditLog(
      user._id,
      'password_verification_failed',
      { endpoint: 'verify_unlock' },
      verifyUnlockCtx.ip,
      verifyUnlockCtx.userAgent,
    );

    throw httpErrors.unauthorized('Invalid credentials');
  }

  await createAuditLog(
    user._id,
    'vault_unlock',
    undefined,
    verifyUnlockCtx.ip,
    verifyUnlockCtx.userAgent,
  );

  clearCsrfCookie(res);

  res.status(200).json({
    success: true,
    message: 'Unlock verified',
  });
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

// IP and fingerprint caps are local to refresh-token deviceInfo storage; the
// userAgent cap is shared with audit-log persistence via
// {@link MAX_USER_AGENT_LENGTH} so the truncation invariant is enforced
// uniformly across both persistence paths.
const DEVICE_INFO_LIMITS = { ip: 45, fingerprint: 128 } as const;

function sanitizeDeviceInfo(
  deviceInfo: { userAgent?: string; fingerprint?: string } | undefined,
  req: Request,
): { userAgent: string; ip: string; fingerprint: string } {
  const ip = req.ip ?? 'unknown';
  const rawUserAgent =
    typeof deviceInfo?.userAgent === 'string'
      ? deviceInfo.userAgent
      : (req.headers['user-agent'] ?? '');
  const rawFingerprint = typeof deviceInfo?.fingerprint === 'string' ? deviceInfo.fingerprint : '';
  return {
    userAgent: rawUserAgent.slice(0, MAX_USER_AGENT_LENGTH),
    ip: ip.slice(0, DEVICE_INFO_LIMITS.ip),
    fingerprint: rawFingerprint.slice(0, DEVICE_INFO_LIMITS.fingerprint),
  };
}

export async function findMatchingBackupCodeIndex(
  code: string,
  hashedCodes: string[],
): Promise<number> {
  // Always iterate ALL backup codes to prevent timing-based leakage of the
  // backup code position. Short-circuiting on first match would reveal which
  // index matched via response-time differences.
  let matchIndex = -1;
  for (let i = 0; i < hashedCodes.length; i++) {
    const hashed = hashedCodes[i];
    if (hashed !== undefined && (await bcrypt.compare(code, hashed))) {
      matchIndex = i;
    }
  }
  return matchIndex;
}
