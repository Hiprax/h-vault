import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createModuleLogger, errorMessage } from '../utils/logger.js';
import { config, isProduction, isTest } from '../config/index.js';
import { REFRESH_COOKIE_NAME, TRUSTED_DEVICE_COOKIE_NAME } from '../constants/index.js';
import { User } from '../models/User.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { TrustedDevice } from '../models/TrustedDevice.js';
import { revokeTrustedDevices } from '../utils/trustedDevices.js';
import {
  clearDeviceProofCookie,
  consumeDeviceProof,
  extendPresentedDeviceProof,
  findPresentedDeviceProof,
  issueDeviceProof,
  issueUnlockProof,
  provesAccount,
  recordProofFailure,
  revokeDeviceProofs,
} from '../utils/deviceProofs.js';
import { supportsTransactions } from '../utils/transactionSupport.js';
import {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  derivePurposeKey,
} from '../utils/token.js';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendRegistrationAttemptEmail,
} from '../utils/email.js';
import { createAuditLog, recordLockedAttempt, recordNothing } from '../services/auditService.js';
import { recordFailedLoginAttempt, resetLoginAttempts } from '../utils/loginThrottle.js';
import {
  getRequestContext,
  isVaultRotationLockHeld,
  MAX_USER_AGENT_LENGTH,
  pickAllowedFields,
  vaultKeyVersionOf,
} from '../utils/controllerHelpers.js';
import { readStringCookie } from '../utils/cookies.js';
import { evaluateAccountStatus } from '../utils/accountStatus.js';
import {
  LOCKOUT_FACTORS,
  clearLockoutStateOnDocument,
  dischargeOnCompletion,
  dischargeUnlockedEpisode,
  extendNothing,
  extendPasswordLockout,
  lockoutClearUpdate,
  registerFailedAuthAttempt,
  unlockEpisodeOf,
  unlockTokenNamesEpisode,
  type JwtUnlockPayload,
  type LockoutFactor,
} from '../utils/lockout.js';
import { verifySecondFactor } from '../utils/secondFactor.js';
import { clearCsrfCookie } from '../middleware/csrf.js';
import {
  APP_VERSION,
  ERROR_CODES,
  MAX_SESSIONS,
  MAX_TRUSTED_DEVICES,
  maskEmail,
} from '@hvault/shared';
import type {
  RegisterInput,
  LoginInput,
  Login2faInput,
  ResetPasswordInput,
  VerifyUnlockInput,
} from '@hvault/shared';

const logger = createModuleLogger('auth');

const DAY_MS = 24 * 60 * 60 * 1000;

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
 * The awaited DATABASE work is equalised separately, and only where it is
 * unbounded: a locked account answers every unproven attempt with one
 * conditional User update and one coalesced audit upsert, and an unknown address
 * (or an account mid-erasure) makes the same two round trips with filters that
 * match nothing, so no row is ever created for an address nobody registered.
 * The unlocked wrong-password branch still does its own counting (a few
 * milliseconds), which at most ten attempts per lock episode can sample.
 */
async function applyFailedLoginDelay(email: string): Promise<void> {
  await applyProgressiveDelay(recordFailedLoginAttempt(email));
}

/**
 * Sleeps for the progressive delay `attempts` failures earn (skipped in the test
 * environment). The ONE place the delay is applied, for both steps: the password
 * step passes the per-email throttle's count (see `applyFailedLoginDelay`), the
 * 2FA step the second factor's durable counter.
 */
async function applyProgressiveDelay(attempts: number): Promise<void> {
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
  // Carried from the login step so the 2FA step honours "remember me" without
  // trusting a client-supplied field. Optional so a temp token minted before
  // this field existed (or by a non-remembered login) is read as false.
  rememberMe?: boolean;
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

/**
 * Sets the trusted-device cookie. Scoped to `path: '/api/v1/auth'` — narrower
 * than the refresh cookie's `/api/v1` — so the browser only sends this token to
 * the auth endpoints that consume it (least privilege). The raw token is written
 * ONLY here; it is never returned in a response body, logged, or stored (only its
 * SHA-256 is persisted). `maxAge` mirrors the record's absolute expiry.
 */
function setTrustedDeviceCookie(res: Response, token: string, maxAgeMs: number): void {
  res.cookie(TRUSTED_DEVICE_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1/auth',
    maxAge: maxAgeMs,
  });
}

/**
 * Clears the trusted-device cookie. The attributes (minus `maxAge`) MUST match
 * `setTrustedDeviceCookie` exactly — same `path` and `sameSite`/`secure` — or the
 * browser treats it as a different cookie and never removes it. Called when a
 * presented trusted-device cookie is unrecognised/expired/foreign, so a stale
 * token is not sent again on the next login.
 */
function clearTrustedDeviceCookie(res: Response): void {
  res.clearCookie(TRUSTED_DEVICE_COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1/auth',
  });
}

/**
 * Enforces `MAX_SESSIONS` as a real per-user cap over LIVE refresh rows only,
 * evicting the oldest unused ones so a new login never exceeds the limit.
 *
 * **Only `usedAt: null` rows are counted or deleted.** A `RefreshToken` row is
 * not a session (§1.4): once rotated, the old row is left in place with `usedAt`
 * set as a reuse-detection tombstone, and reuse detection depends on finding it.
 * With `JWT_ACCESS_EXPIRY = '5m'` an active session mints ~288 rows/day, so a
 * user crosses 50 rows in hours — counting all rows would delete tombstones
 * (silently downgrading a future stolen-cookie replay from `TOKEN_REUSE_DETECTED`
 * to `TOKEN_INVALID`, so the family is never revoked) and delete other devices'
 * live-but-rotated rows (logging them out). Both are avoided by the filter.
 *
 * Called AFTER the new row is created at login and 2FA-login, so the freshly
 * minted session is the newest by `createdAt` and can never be the one evicted;
 * the oldest `excess` live rows are removed instead. Not called from `refresh`:
 * rotation replaces a row rather than adding a session, so the live count there
 * is unchanged. The `usedAt: null` re-filter on the delete also skips any row a
 * concurrent rotation consumed between the read and the delete.
 */
async function enforceSessionCap(userId: mongoose.Types.ObjectId): Promise<void> {
  const liveCount = await RefreshToken.countDocuments({ userId, usedAt: null });
  if (liveCount <= MAX_SESSIONS) return;

  const excess = liveCount - MAX_SESSIONS;
  // `excess >= 1` and there are `liveCount` matching rows, so `find` returns
  // exactly `excess` ids — the oldest live sessions. The `usedAt: null` re-filter
  // on the delete also skips any row a concurrent rotation consumed in between.
  const oldest = await RefreshToken.find({ userId, usedAt: null })
    .sort({ createdAt: 1 })
    .limit(excess)
    .select('_id')
    .lean();

  await RefreshToken.deleteMany({
    userId,
    usedAt: null,
    _id: { $in: oldest.map((row) => row._id) },
  });
}

/**
 * Enforces `MAX_TRUSTED_DEVICES` as a per-user cap, evicting the oldest records
 * beyond the limit. Called AFTER the fresh record is created, so the just-minted
 * device is the newest by `createdAt` and can never be the one evicted; only a
 * user's oldest trust grants are dropped. Silently bounds per-user growth so a
 * user who checks "remember me" on many devices cannot accumulate them without
 * limit (each is also TTL-reaped at its own `expiresAt`).
 */
async function enforceTrustedDeviceCap(userId: mongoose.Types.ObjectId): Promise<void> {
  const count = await TrustedDevice.countDocuments({ userId });
  if (count <= MAX_TRUSTED_DEVICES) return;

  const excess = count - MAX_TRUSTED_DEVICES;
  const oldest = await TrustedDevice.find({ userId })
    .sort({ createdAt: 1 })
    .limit(excess)
    .select('_id')
    .lean();

  await TrustedDevice.deleteMany({
    userId,
    _id: { $in: oldest.map((row) => row._id) },
  });
}

/**
 * Mints a trusted-device record for a 2FA account that logged in with
 * "remember me", so the device may skip the 2FA step until the grant expires.
 *
 * A fresh 32-byte random token is generated; only its SHA-256 (`hashToken`) is
 * persisted, and the RAW token is written solely into the `Set-Cookie` header by
 * `setTrustedDeviceCookie` — never returned in a response body, logged, or
 * stored. The absolute expiry is `now + TRUSTED_DEVICE_DAYS`; the TTL index on
 * the model evicts the record the instant it passes. Returns nothing — the
 * caller audits `trusted_device_grant` separately with request context.
 */
async function grantTrustedDevice(
  res: Response,
  userId: mongoose.Types.ObjectId,
  deviceInfo: { userAgent: string; ip: string; fingerprint: string },
): Promise<void> {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const maxAgeMs = config.TRUSTED_DEVICE_DAYS * DAY_MS;
  const expiresAt = new Date(Date.now() + maxAgeMs);

  await TrustedDevice.create({
    userId,
    tokenHash,
    deviceInfo,
    expiresAt,
  });
  await enforceTrustedDeviceCap(userId);

  setTrustedDeviceCookie(res, rawToken, maxAgeMs);
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
    // A new account starts caught up: the release notes are for what changed
    // since someone last used the app, and this account has not used it yet.
    // Written by the server, never taken from the body (the allowlist above
    // would drop it anyway).
    releaseNotesSeenVersion: APP_VERSION,
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
  const { email, authHash, deviceInfo, rememberMe } = body;
  const { ip, userAgent } = getRequestContext(req);

  // The device proof the browser presented, looked up by its hash alone BEFORE
  // the account is known, so the lookup costs the same whether or not the address
  // is registered (a lookup made only for real accounts would itself be an oracle).
  const presented = await findPresentedDeviceProof(req);
  // A value that names no live proof (forged, spent, revoked, expired) is
  // cleared HERE, before the address is looked up, so every such request gets the
  // same directive whether or not the address is registered: clearing it only for
  // a real account turned one request per address into a certain existence answer.
  if (presented !== null && presented.proof === null) {
    clearDeviceProofCookie(res);
  }

  const user = await User.findOne({ email }).select(
    '+authHash +twoFactorSecret +backupCodes +secondFactorLockout',
  );
  if (!user) {
    // Perform a dummy bcrypt compare to equalize response time with the
    // existing-user path, preventing email enumeration via timing side-channel,
    // and the same two awaited round trips a locked account makes, with filters
    // that match nothing: an unregistered address costs what a locked one does,
    // however long a stranger keeps asking, and writes nothing.
    await bcrypt.compare(authHash, DUMMY_BCRYPT_HASH);
    await extendNothing();
    await recordNothing();
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  const isMatch = await bcrypt.compare(authHash, user.authHash);

  // The three account-level refusals, evaluated once against one instant. The
  // ORDER they are applied in below is this handler's own and differs from the
  // refresh handler's deliberately; only the predicates are shared
  // (`utils/accountStatus.ts`).
  const status = evaluateAccountStatus(user);

  // PROVEN: this browser completed an authentication for THIS account before, so
  // it is not guessing and a password lockout does not brake it. A proof for
  // another account proves nothing here and is not charged or deleted (its row
  // lapses at its own expiry; the browser's cookie is replaced if this sign-in
  // completes).
  const proof = provesAccount(presented, user._id) ? presented.proof : null;

  // An account whose cascade delete is still outstanding is served nothing, and
  // is served it identically whether or not the password was right. `deletionPending`
  // survives only a FAILED cascade, so such a record is a zombie mid-erasure: the
  // Passport strategy and the refresh handler already refuse it, and this door did
  // not, which let one complete a full sign-in — writing a `RefreshToken` row and
  // an audit row under an account being deleted — for the whole six-hour
  // `tokenCleanup` window. The refusal is the generic 401 with the shared delay
  // rather than anything specific, because a distinguishable answer here would tell
  // an attacker that the address is registered AND being closed, and it costs the
  // same round trips as an unknown address. Nothing is written, deliberately: the
  // point is that no row is created under an account mid-erasure.
  if (status.deletionPending) {
    await extendNothing();
    await recordNothing();
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  // A single-use proof (the unlock link's) is SPENT by the first correct password
  // it accompanies, even when a second factor is still owed, and spending it is an
  // atomic claim: of two requests racing with it, only the one whose delete landed
  // is proven, so it cannot carry a browser past the password lockout twice. It is
  // decided here, after the mid-erasure refusal, so an account being deleted does
  // not spend it (the unverified-address refusal below still can: no proof exists
  // for an account that never signed in, except an unlock link's).
  const proven =
    proof !== null && (!proof.singleUse || !isMatch || (await consumeDeviceProof(proof)));

  // A running PASSWORD lockout, for a browser that has not proven itself.
  //
  // The answer is EXACTLY the wrong-password answer, whether or not the password
  // was right: same 401, same message, same delay, and the same awaited writes
  // (one conditional User update, one coalesced audit upsert) on both branches. The
  // bcrypt compare above still runs, so the time is the same too. A distinct answer
  // for the correct password — the `403 ACCOUNT_LOCKED` this used to send — turned
  // every lockout into an oracle that confirmed a guessed password to whoever made
  // it, and a correct-password-only write would have been the same oracle in time.
  //
  // The accounting is bounded, because a stranger can send these forever: the
  // counter is not incremented (it already sits at the threshold), the deadline is
  // pushed out at most once a minute while attempts continue (so the lockout lasts
  // as long as the guessing, at one modified User write a minute, which is also
  // what keeps an owner's vault-key rotation, whose transaction writes the User
  // document last, from being aborted by the flood), and the audit row is one per
  // account per minute with a count. The row says `reason: 'locked'` and nothing
  // else: `GET /user/audit-log` returns whole rows to any session holder, so a
  // field that differed by correctness would hand the oracle to anyone who could
  // lock the account and read the log.
  //
  // A PROVEN browser never reaches this branch (see `proven` above), and nothing
  // here clears the lockout: only the deadline passing, the unlock link, or a
  // completed sign-in outside a running lockout does.
  if (status.passwordLocked && !proven) {
    await extendPasswordLockout(user._id, email);
    await recordLockedAttempt(user._id.toString(), ip, userAgent);
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  // Check email verification after bcrypt compare to avoid disclosing whether
  // an email is registered and unverified. Return the same 401 status and
  // message as invalid credentials, with a hint in the data field so the
  // client can show a helpful message without exposing this in the error code.
  if (isMatch && status.emailUnverified) {
    // The password was correct, so this is not a brute-force attempt.
    resetLoginAttempts(email);
    res.status(401).json({
      success: false,
      message: 'Invalid email or password',
      data: { reason: 'email_not_verified' },
    });
    return;
  }

  if (!isMatch && proof !== null) {
    // A wrong password from a PROVEN browser counts against the proof, not the
    // account (the OWASP device-cookie protocol: lock the device cookie, not the
    // account), so the owner's typo never locks out the owner's other new
    // devices. Five in the window revoke the proof, and the browser is then an
    // ordinary unrecognised one. Same row, same delay and same 401 as any other
    // wrong password.
    await recordProofFailure(res, proof, { ip, userAgent });
    await createAuditLog(
      user._id.toString(),
      'login_failed',
      { reason: 'invalid_password' },
      ip,
      userAgent,
    );
    await applyFailedLoginDelay(email);
    throw httpErrors.unauthorized('Invalid email or password');
  }

  if (!isMatch) {
    // Counts the attempt on the PASSWORD factor's own state, locks that factor at
    // the threshold, and keeps a usable unlock link outstanding for its episode.
    // The second factor has a state of its own and is never written here. The
    // returned count is unused: this step's progressive delay comes from the
    // per-email throttle, not the durable counter, so that a non-existent email
    // is delayed identically.
    await registerFailedAuthAttempt(user._id, email, 'password');

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

  // The process-local throttle drives ONLY the progressive sleep on THIS step —
  // `login2fa` never reads it, taking its own delay from the durable counter
  // instead — so a verified password clears it here even when a second factor is
  // still owed: a correct password is proof that the password guessing this
  // counter exists to slow has ended, and clearing it hands a password-holding
  // attacker nothing at the second step. It is emphatically NOT the durable
  // lockout counter, which is handled separately below and in `finishLogin`.
  // The reset is also UNCONDITIONAL: attempts recorded while the account was
  // locked never touched `failedLoginAttempts`, so gating it on the database
  // counter would let a stale in-memory count survive a successful login and
  // delay the next typo.
  resetLoginAttempts(email);

  // A PASSWORD lockout that was actually SERVED is discharged here, before the
  // `twoFactorEnabled` branch — the one case in which a password alone clears the
  // password factor's counter.
  //
  // It is reachable only after the deadline passed: `lockoutUntil` is written
  // solely by `utils/lockout.ts`, and while it is in the FUTURE this handler
  // refuses above. So the budget it restores is ten guesses per half hour, which
  // is the designed lockout rate, not a bypass of it. Without it the counter
  // would sit at the threshold for ever (a failure only ever caps it), and the
  // first typo after any lockout would re-lock the account for another half hour.
  // The second factor has its own served discharge, inside the one verifier in
  // `utils/secondFactor.ts`, and this one never touches it.
  //
  // Atomic update rather than `user.save()` on the document loaded before the
  // bcrypt compare: a concurrent `$inc` must not be clobbered by a stale
  // in-memory zero. The in-memory copy is corrected through the SAME helper pair,
  // so `finishLogin`'s own guarded reset below does not repeat the write.
  //
  // Only a lockout that is NOT running: a proven browser reaches this line during
  // a running lockout, and signing in must not clear what strangers built. No
  // second clock read: `status` was evaluated against one instant, and asking
  // `new Date()` again could only disagree with the branch that let this through.
  if (user.lockoutUntil && !status.passwordLocked) {
    // Conditioned on the stored deadline still being the served one, so a
    // lockout written by a concurrent failure in the meantime is not wiped.
    await User.updateOne(
      { _id: user._id, lockoutUntil: { $lte: user.lockoutUntil } },
      lockoutClearUpdate('password'),
    );
    clearLockoutStateOnDocument(user, 'password');
  }

  // Detect and recover from interrupted vault key rotation. If rotationInProgress
  // is true, the server crashed mid-rotation; lowering the flag lets the account
  // write again.
  //
  // The FLAG is all that is cleared, and that is the whole point. The sequential
  // rotation path commits `rotationInProgress: true` in the same update as the new
  // vault key wrapped under the account's MEK (`pendingEncryptedVaultKey` and its
  // IV/tag), expressly so a crash is recoverable: rows written before the crash are
  // sealed under THAT key and no other copy of it exists anywhere — not on the
  // client, which minted it in memory and has long since navigated away, and not in
  // a backup, which stores ciphertext rather than the key. Destroying the wrapper
  // here, as this handler used to, is therefore the one irreversible act available
  // at this point: a flag can be recomputed, a key cannot. It is kept, reported by
  // `GET /user/profile` as `interruptedRotation`, and cleared by the next rotation
  // that COMMITS (both commit paths `$unset` it; `lowerRotationFence`, which runs on
  // every ABORT, deliberately does not),
  // which is the only event that makes it redundant.
  //
  // The transactional path never writes the wrapper at all: it rolls back atomically,
  // so a crash there leaves nothing half-done to finish and nothing outstanding to
  // report. Whether the wrapper is present is exactly the discriminator, which is
  // why it is derived rather than stored as a second flag.
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
  // rotation's lock TTL-expires (VAULT_ROTATION_LOCK_TTL_MS), after which the
  // next login clears the stuck flag; a live rotation clears it itself on
  // commit/abort, so nothing is left wedged either way.
  //
  // That lock now has four holders besides the rotation — the import, the
  // restore, the document completion and the master-password change all take it
  // across their own check-to-commit spans — so a `true` answer no longer means
  // "a rotation is live". It means "somebody is mid-span", and the effect here is
  // that the cleanup of a stuck flag is DEFERRED to the next login rather than
  // performed during someone else's span. Deferring costs nothing: every one of
  // those holders is itself refused by the stuck flag it would be racing, so none
  // can hold the lock for more than the round trip it takes to be told so, and
  // lowering a fence has never been urgent. The error in the other direction —
  // clearing the flag out from under a live rotation — is the one that strands a
  // row, and this predicate still cannot make it.
  if (user.rotationInProgress && !(await isVaultRotationLockHeld(user._id.toString()))) {
    // Read from the document this handler already loaded rather than re-reading:
    // the fence is down only for a rotation with no live lock, so nothing can be
    // writing this field concurrently.
    const rotationOutstanding = Boolean(user.pendingEncryptedVaultKey);

    logger.warn('Interrupted vault key rotation detected during login — lowering the write fence', {
      userId: user._id.toString(),
      email: maskEmail(email),
      // The wrapper itself is never logged; only whether one is outstanding.
      interruptedRotation: rotationOutstanding,
    });

    await User.updateOne({ _id: user._id }, { $set: { rotationInProgress: false } });

    await createAuditLog(
      user._id.toString(),
      'rotation_recovery',
      {
        detail: rotationOutstanding
          ? 'Interrupted vault key rotation detected during login: the write fence was lowered and the pending vault key was retained so the rotation can be finished'
          : 'Interrupted vault key rotation detected during login: the write fence was lowered; no pending vault key was stored, so nothing is outstanding',
        // The same fact `GET /user/profile` reports, under the same name, so the
        // audit trail and the profile can never be read as saying different things.
        interruptedRotation: rotationOutstanding,
      },
      ip,
      userAgent,
    );
  }

  // Completes an authenticated (non-2FA-challenge) login: issues the access +
  // refresh tokens, persists the refresh row honouring the request's `rememberMe`
  // via `resolveRefreshLifetime`, enforces the session cap, sets the refresh
  // cookie, clears CSRF, audits `login`, and writes the success body. Shared by
  // the ordinary non-2FA path AND the trusted-device 2FA-skip path so the two can
  // never drift (§1.2 principle 10); only the audit metadata differs. Both call
  // it with the SAME `rememberMe` from the request, so an unchecked box never
  // silently produces a 30-day session on either path.
  const finishLogin = async (auditMetadata?: Record<string, unknown>): Promise<void> => {
    // Discharge the counters, FIRST — before any token is minted, so a failure
    // here cannot 500 a request that has already written a session row and
    // shipped a refresh cookie.
    //
    // The reset belongs to a COMPLETED authentication and not merely to a
    // verified password: clearing the second factor's counter at the password
    // step would let a password holder replay that step between batches of wrong
    // codes and reset the second factor's only per-account brake for ever.
    // `finishLogin` is the right home because BOTH paths that complete a login
    // without a submitted code run through it: the ordinary non-2FA completion,
    // and the trusted-device 2FA skip (two factors presented: the password, and a
    // device-bound token minted only after a verified TOTP and burned as it is
    // spent). The counterpart for a submitted code is the end of `login2fa`.
    //
    // A factor whose lockout is RUNNING is not cleared here: a client completes a
    // sign-in past a running lockout only by proving itself, and the failures
    // that built that lockout were somebody else's (`dischargeOnCompletion`).
    //
    // Atomic update rather than `user.save()` on the document loaded before the
    // bcrypt compare: a concurrent `$inc` must not be clobbered by a stale zero.
    await dischargeOnCompletion(user, status);

    const accessToken = generateAccessToken(user._id.toString());
    const refreshTokenRaw = generateRefreshToken();
    const refreshTokenHash = hashToken(refreshTokenRaw);
    const familyId = crypto.randomUUID();

    const lifetime = resolveRefreshLifetime({ remember: rememberMe });
    await RefreshToken.create({
      userId: user._id,
      tokenHash: refreshTokenHash,
      familyId,
      deviceInfo: sanitizeDeviceInfo(deviceInfo, req),
      expiresAt: lifetime.expiresAt,
      ...(lifetime.absoluteExpiresAt ? { absoluteExpiresAt: lifetime.absoluteExpiresAt } : {}),
    });
    await enforceSessionCap(user._id);

    setRefreshCookie(res, refreshTokenRaw, lifetime.maxAgeMs);
    clearCsrfCookie(res);
    // A completed authentication earns this browser a device proof, rotating the
    // one it presented.
    await issueDeviceProof(res, user._id, presented);

    await createAuditLog(user._id.toString(), 'login', auditMetadata, ip, userAgent);

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
        // Which vault key the wrapped key above IS. A rotation revokes nothing
        // and refreshes no key already resident in a running session, so this is
        // the only moment the client can learn which generation the key it is
        // about to decrypt belongs to — and without that it cannot tell a server
        // asking "is this the current key?" from one asking "is this YOUR key?".
        vaultKeyVersion: vaultKeyVersionOf(user),
      },
    });
  };

  // 2FA flow
  if (user.twoFactorEnabled) {
    // Trusted-device 2FA skip. Runs ONLY when the browser actually presents a
    // `trustedDevice` cookie: a normal 2FA login (no cookie) performs NO lookup,
    // NO cookie clear, and writes NO audit, so it can never flood the audit log
    // (365-day TTL) with a spurious `trusted_device_rejected` row — nor emit a
    // pointless `Set-Cookie` — on every ordinary 2FA login. The check sits here,
    // strictly AFTER the bcrypt compare and lockout evaluation above, so a cookie
    // can never become an authentication bypass or an account-enumeration oracle.
    const trustedCookie = readStringCookie(req, TRUSTED_DEVICE_COOKIE_NAME);
    if (trustedCookie) {
      // Consume the record atomically: `findOneAndDelete` recognises and burns
      // the token in one step, so a replayed (already-consumed) cookie simply
      // finds nothing. The filter is scoped to THIS user AND to an unexpired
      // grant, so another user's cookie or a lapsed one never matches — and,
      // because of the `userId` scope, another user's record is never deleted.
      const record = await TrustedDevice.findOneAndDelete({
        tokenHash: hashToken(trustedCookie),
        userId: user._id,
        expiresAt: { $gt: new Date() },
      });

      if (record) {
        // Recognised device: rotate the trust token — a stolen cookie stops
        // working the moment the legitimate user returns — while carrying the
        // ORIGINAL `expiresAt` forward UNCHANGED, so rotation never extends the
        // trust window (§1.7). The replacement neither grows nor shrinks the
        // per-user count, so no `MAX_TRUSTED_DEVICES` enforcement is needed here.
        const rawToken = crypto.randomBytes(32).toString('hex');
        await TrustedDevice.create({
          userId: user._id,
          tokenHash: hashToken(rawToken),
          deviceInfo: sanitizeDeviceInfo(deviceInfo, req),
          expiresAt: record.expiresAt,
          lastUsedAt: new Date(),
        });
        setTrustedDeviceCookie(res, rawToken, Math.max(0, record.expiresAt.getTime() - Date.now()));

        // Complete the login as the non-2FA path, honouring the REQUEST's own
        // `rememberMe` (NOT a hardcoded true): a user who unchecked the box on a
        // trusted device must get a standard-length session, not a silent 30-day
        // one. Audited as a password-only login that skipped the second factor.
        await finishLogin({ twoFactor: false, trustedDevice: true });
        return;
      }

      // Cookie present but unrecognised / expired / another user's: fail closed
      // to the normal 2FA prompt. Clear the stale cookie and audit the rejection.
      // Deliberately does NOT revoke the user's OTHER trusted devices (§1.7): a
      // lost-rotation race costs exactly one extra 2FA prompt and nothing more,
      // so global revocation on a benign race would be user-hostile for no gain.
      clearTrustedDeviceCookie(res);
      await createAuditLog(
        user._id.toString(),
        'trusted_device_rejected',
        undefined,
        ip,
        userAgent,
      );
    }

    const tempToken = jwt.sign(
      {
        userId: user._id.toString(),
        purpose: '2fa_temp',
        deviceHash: generateDeviceHash(req),
        // Carry "remember me" into the SIGNED token so the 2FA step honours it
        // from the verified payload, never from a forgeable request body.
        rememberMe,
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

  // A non-2FA account with "remember me" extends the refresh horizon only —
  // there is no second factor to skip, so no trusted-device record is minted
  // (§1.7). An unchecked box slides to today's standard REFRESH_TOKEN_DAYS.
  await finishLogin();
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

  // "Remember me" is read ONLY from the verified token, never from the request
  // body (login2faSchema carries no such field), so a tampered body cannot
  // upgrade a standard login to a remembered/trusted one.
  const remember = payload.rememberMe === true;

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
    '+twoFactorSecret +backupCodes +encryptedVaultKey +vaultKeyIv +vaultKeyTag +secondFactorLockout',
  );
  if (!user) {
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  const status = evaluateAccountStatus(user);

  // The same zombie refusal the password step applies. A temp token is minted
  // only by `login`, which now refuses a `deletionPending` account outright — but
  // one issued in the five minutes BEFORE the deletion request is still valid, and
  // spending it here would complete exactly the sign-in that refusal exists to
  // prevent: a session row and an audit row written under an account mid-erasure.
  // Answered as `TOKEN_INVALID`, matching the refresh handler and this handler's
  // own treatment of a user that no longer exists.
  if (status.deletionPending) {
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  if (!user.twoFactorEnabled || !user.twoFactorSecret) {
    throw httpErrors.badRequest(ERROR_CODES.TWO_FA_NOT_ENABLED);
  }

  // The browser's device proof, read now, before the code is checked, so a read
  // failure is a 500 that has spent nothing rather than one after a TOTP step or a
  // backup code was consumed. It is only used to rotate the proof on completion.
  const presented = await findPresentedDeviceProof(req);

  // The ONE verifier reads only the SECOND factor's state: it refuses while that
  // factor is locked (the password is already proven at this step, so the
  // distinct `ACCOUNT_LOCKED` below is no oracle), discharges a served lockout,
  // counts a wrong code on that factor alone, and hands back the compare-and-set
  // that consumes a right one. A PASSWORD lockout is deliberately not consulted:
  // this client proved the password before it was locked (or with a device
  // proof), and refusing it here would lock the owner out of the very sign-in a
  // proven client is allowed to complete.
  const verdict = await verifySecondFactor(user, code, {
    site: 'login2fa',
    acceptBackupCodes: true,
  });

  if (!verdict.ok) {
    if (verdict.reason === 'locked') {
      throw httpErrors.forbidden(ERROR_CODES.ACCOUNT_LOCKED);
    }

    await createAuditLog(
      user._id.toString(),
      'login_failed',
      { reason: '2fa_invalid' },
      ip,
      userAgent,
    );

    // Progressive delay: slow down brute-force attempts (skipped in test
    // environment). This step uses the second factor's durable counter — unlike
    // `login`, which must source its delay from the per-email throttle. There is
    // no enumeration vector to equalize here: reaching this code requires a
    // valid, device-bound temp token, which is only ever issued for an account
    // that exists and whose password already verified.
    await applyProgressiveDelay(verdict.attempts);

    throw httpErrors.unauthorized(ERROR_CODES.TWO_FA_INVALID);
  }

  // Consume the code, atomically, BEFORE any token is issued: a TOTP step is
  // spent by the compare-and-set on `lastTotpTimestamp`, a backup code by pulling
  // it out of the array. A write that matches nothing means another request spent
  // the same code first (or the factor was disabled or replaced since it was
  // checked), so this one is refused as a replay and receives nothing.
  const usedBackupCode = verdict.kind === 'backup_code';
  const consumed = await User.findOneAndUpdate(
    { _id: user._id, ...verdict.casFilter },
    verdict.casUpdate,
    { returnDocument: 'after' },
  ).select('+backupCodes');
  if (!consumed) {
    await createAuditLog(
      user._id.toString(),
      'login_failed',
      { reason: '2fa_replay' },
      ip,
      userAgent,
    );
    throw httpErrors.unauthorized(ERROR_CODES.TWO_FA_INVALID);
  }

  if (usedBackupCode) {
    logger.info('Backup code used for 2FA', { userId: user._id.toString() });
    // Audited HERE, at the point of consumption, rather than beside the `login`
    // row below: the code is spent whatever happens next, and a failure between
    // here and the response would otherwise burn a recovery credential leaving no
    // record the owner can see. `remaining` comes from the document the atomic
    // pull actually produced, never from the pre-read array, which a concurrent
    // redemption would make lie.
    await createAuditLog(
      user._id.toString(),
      '2fa_backup_code_used',
      { remaining: countBackupCodes(consumed) },
      ip,
      userAgent,
    );
  }

  // A completed authentication: clear each factor's counter, except a factor
  // whose lockout is running now (a password lockout that strangers built while
  // this client, which had already proven the password, was at this step).
  await dischargeOnCompletion(user, status);

  // Issue tokens
  const accessToken = generateAccessToken(user._id.toString());
  const refreshTokenRaw = generateRefreshToken();
  const refreshTokenHash = hashToken(refreshTokenRaw);
  const familyId = crypto.randomUUID();

  // Honour "remember me" from the verified temp token: a remembered 2FA login
  // gets the same 30-day (REFRESH_TOKEN_REMEMBER_DAYS) absolute-deadline session
  // as a remembered non-2FA login. An unchecked box slides to REFRESH_TOKEN_DAYS.
  const sanitizedDeviceInfo = sanitizeDeviceInfo(deviceInfo, req);
  const lifetime = resolveRefreshLifetime({ remember });
  await RefreshToken.create({
    userId: user._id,
    tokenHash: refreshTokenHash,
    familyId,
    deviceInfo: sanitizedDeviceInfo,
    expiresAt: lifetime.expiresAt,
    ...(lifetime.absoluteExpiresAt ? { absoluteExpiresAt: lifetime.absoluteExpiresAt } : {}),
  });

  await enforceSessionCap(user._id);

  setRefreshCookie(res, refreshTokenRaw, lifetime.maxAgeMs);
  clearCsrfCookie(res);
  // A completed authentication earns this browser a device proof, rotating the
  // one it presented (the 2FA step is where a 2FA account's sign-in completes).
  await issueDeviceProof(res, user._id, presented);

  // Grant a trusted device so this device may skip the 2FA step until the grant
  // expires. Minted only on a remembered login completed with a REAL second
  // factor; the raw token lives solely in the Set-Cookie header. Done before the
  // response is written so the cookie ships.
  //
  // `!usedBackupCode` is the load-bearing half. A TOTP code proves the second
  // factor is present on this device right now, which is the thing trust is
  // being extended to. A backup code proves the opposite: it is the recovery
  // credential, issued eight at a time and kept precisely where the
  // authenticator is not — on paper, in another password manager, in an email to
  // oneself. Minting a grant from it turned one line off that sheet into a
  // `TRUSTED_DEVICE_DAYS` (30) standing skip of the second factor, and because a
  // trusted-device login mints a fresh remembered session while the record keeps
  // its own expiry, up to `REFRESH_TOKEN_REMEMBER_DAYS + TRUSTED_DEVICE_DAYS`
  // (60) days without a TOTP code ever being presented again. Whoever loses the
  // sheet also needs the master password, which is why this is a hardening fix
  // and not an open door — but a recovery credential must buy exactly one
  // recovery, not a month of them, and the account owner had no way to see it
  // had bought more.
  //
  // The remembered SESSION is deliberately still honoured above: `remember`
  // drives `resolveRefreshLifetime`, and this condition does not. "Remember me"
  // and "skip the second factor on this device" are two promises, and only the
  // second one depends on which credential was presented.
  if (remember && !usedBackupCode) {
    await grantTrustedDevice(res, user._id, sanitizedDeviceInfo);
    await createAuditLog(user._id.toString(), 'trusted_device_grant', undefined, ip, userAgent);
  }

  // `backupCode` discriminates the two credentials on the row itself. The
  // audit-log UI renders the action and not the metadata, so the user-visible
  // record of a spent code is the `2fa_backup_code_used` row written at the
  // point of consumption; this field is for anything reading the API, where
  // `{ twoFactor: true }` alone could not tell the two logins apart.
  await createAuditLog(
    user._id.toString(),
    'login',
    { twoFactor: true, backupCode: usedBackupCode },
    ip,
    userAgent,
  );

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
      // The 2FA leg completes a sign-in exactly as the direct one does, so it
      // publishes the same pairing. See the note on the other response.
      vaultKeyVersion: vaultKeyVersionOf(user),
    },
  });
});

// ─── Refresh ─────────────────────────────────────────────────────────────────

/**
 * The one account-level refusal a refresh can hit: the account is gone,
 * mid-erasure, or never verified. Nothing will ever make that cookie work again,
 * so the refusal clears it.
 *
 * A LOCKOUT is deliberately not a refusal, for either factor. The refresh cookie
 * is itself proof of a prior authentication, so the client presenting it is not
 * guessing anything; refusing it froze every existing session for as long as a
 * stranger kept the account locked, and under a second-factor lockout it would
 * also stop the owner changing the master password, the one remedy that evicts
 * someone who knows it.
 */
type RefreshRefusal = 'invalid';

/**
 * The account-level policy for a refresh, as a value: the refusal it earns, or
 * `null` when the account may be served.
 *
 * ## Why the caller runs this BEFORE the claim
 *
 * The refresh handler's claim is destructive by design: it marks the presented row
 * `usedAt` and commits a successor whose raw value exists only in the response
 * about to be written. Evaluating the account AFTER that meant the refusal threw
 * between the commit and `setRefreshCookie`, so the presented cookie was spent,
 * its successor was unreachable, and the next presentation of the cookie the user
 * still held was a *reuse* event that revoked the whole family.
 *
 * @param session binds the read to an open transaction, so a caller inside one
 *   reads what that transaction sees.
 */
async function accountRefreshRefusal(
  userId: mongoose.Types.ObjectId,
  session?: mongoose.ClientSession,
): Promise<RefreshRefusal | null> {
  const user = await User.findById(userId, null, session ? { session } : {});
  const status = user && evaluateAccountStatus(user);

  // Collapsed into one refusal on purpose: a refresh cookie is not a credential
  // the caller chose, so distinguishing "no such account" from "mid-erasure" from
  // "never verified" tells a holder of a stolen cookie something it should not.
  if (!status || status.deletionPending || status.emailUnverified) return 'invalid';
  return null;
}

/**
 * {@link accountRefreshRefusal} carried by an exception, which exists for exactly
 * one caller: the transactional branch, where a throw is the only thing that
 * ABORTS the claim it has already made. The standalone branch reads the value
 * directly instead, because a gate that runs before the claim has nothing to undo.
 *
 * Nothing writes to `res` from inside the transaction callback — `withTransaction`
 * is free to re-run that callback, and a `Set-Cookie` header appended twice is a
 * header sent twice.
 */
class RefreshRefusedError extends Error {
  constructor() {
    super('refresh refused: invalid');
    this.name = 'RefreshRefusedError';
  }
}

/**
 * Renders the refusal from ONE place, so the two topology branches cannot drift
 * on it: the cookie is cleared, because nothing will make it work again. Never
 * returns.
 */
function throwRefreshRefusal(res: Response): never {
  clearRefreshCookie(res);
  throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
}

export const refresh = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const token = readStringCookie(req, REFRESH_COOKIE_NAME);

  if (!token) {
    throw httpErrors.unauthorized('Refresh token not provided');
  }

  const tokenHash = hashToken(token);

  // Check if the topology supports transactions (replica set or sharded cluster)
  // before attempting one, rather than relying on error string matching.
  //
  // The check itself is `utils/transactionSupport.ts` and nothing else: it used to
  // be inlined here, and an inlined copy is a second answer to a question every
  // multi-collection writer has to answer the same way (see
  // `tests/topology-predicate.test.ts`).
  const useTransaction = supportsTransactions(mongoose.connection);

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

  if (useTransaction) {
    // Transactional path: perform the claim (mark-used) AND create the new
    // token inside a single transaction so both commit or neither does. This
    // eliminates the race where the original token could be marked used but
    // the new token creation fails, leaving the user without a valid refresh
    // token. If the transaction commits, we are guaranteed a new token exists.
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        // Reset FIRST, every attempt. `withTransaction` re-runs this callback on a
        // transient error, and an aborted attempt's writes are gone while this
        // variable's assignment is not: an attempt that claimed, then lost its
        // commit, then found nothing to claim on the retry (a sibling tab got
        // there first) would leave `claimed` pointing at a successor row that was
        // never committed — and the handler would answer 200 and set a cookie for
        // a token that does not exist, costing the session on the next refresh.
        claimed = null;

        const storedToken = await RefreshToken.findOneAndUpdate(
          { tokenHash, usedAt: null, expiresAt: { $gt: new Date() } },
          { $set: { usedAt: new Date() } },
          { returnDocument: 'before', session },
        );

        if (!storedToken) {
          // Leave claimed=null; handled after the transaction completes.
          return;
        }

        // The account gate, inside the transaction and on its session. A refusal
        // THROWS here rather than returning, because that is what makes
        // `withTransaction` abort: the claim above is undone together with the
        // successor below, so a refused refresh spends nothing at all.
        const refusal = await accountRefreshRefusal(storedToken.userId, session);
        if (refusal) throw new RefreshRefusedError();

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
    } catch (err) {
      // Converted OUT here, after the abort and before anything touches `res`.
      if (err instanceof RefreshRefusedError) throwRefreshRefusal(res);
      throw err;
    } finally {
      await session.endSession();
    }
  } else {
    // Non-transactional fallback (standalone MongoDB). We accept the edge
    // case that the claim may succeed but the subsequent create could fail —
    // a crash between the two leaves the user having to log in again. This
    // is a mild inconvenience, not a security issue: the old token is
    // already invalidated and cannot be reused.
    // There is no transaction to join, so the gate takes the only other position
    // that cannot burn the token: ahead of the claim, with nothing yet to undo.
    // The read carries the claim's OWN filter, and that is load-bearing — a row
    // that is already spent or expired must fall straight through to the reuse and
    // expiry branches below, or a refused account would be the one state in which a
    // replayed cookie escaped family revocation.
    const claimable = await RefreshToken.findOne({
      tokenHash,
      usedAt: null,
      expiresAt: { $gt: new Date() },
    })
      .select('userId')
      .lean();
    if (claimable) {
      const refusal = await accountRefreshRefusal(claimable.userId);
      if (refusal) throwRefreshRefusal(res);
    }

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
          { userId: storedToken.userId.toString(), error: errorMessage(createErr) },
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
      // Reuse detection is the strongest compromise signal in the system: the
      // cookie has been replayed after rotation, so the device is presumed
      // stolen. Revoke the user's trusted devices too — otherwise a stolen-cookie
      // attacker's next login on that device would skip 2FA (§1.5 site 7).
      await revokeTrustedDevices(existingToken.userId);
      // The device proofs go too: they share the cookie jar a stolen refresh token
      // came out of, and each one exempts a browser from the password lockout.
      await revokeDeviceProofs(existingToken.userId);
      clearRefreshCookie(res);
      throw httpErrors.unauthorized(ERROR_CODES.TOKEN_REUSE_DETECTED);
    }

    clearRefreshCookie(res);
    throw httpErrors.unauthorized(ERROR_CODES.TOKEN_INVALID);
  }

  const claimedMeta: ClaimedTokenMeta = claimed;

  // No account check here, and no second `User` read to make it with: the gate ran
  // BEFORE the claim (and, on the transactional path, inside the very transaction
  // that committed it), so reaching this line already means the account may be
  // served. Re-checking here is precisely what was removed — a refusal at this
  // point arrives after the presented token has been spent and its successor
  // committed, which is how a refusal destroyed a session it never meant to end.
  const accessToken = generateAccessToken(claimedMeta.userId.toString());

  setRefreshCookie(res, newRefreshTokenRaw, claimedMeta.maxAgeMs);
  clearCsrfCookie(res);
  // A browser using its session keeps its device proof alive (best effort).
  await extendPresentedDeviceProof(req, res, claimedMeta.userId);

  res.status(200).json({
    success: true,
    data: { accessToken },
  });
});

// ─── Logout ──────────────────────────────────────────────────────────────────

export const logout = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = (req as AuthenticatedRequest).user._id;
  const token = readStringCookie(req, REFRESH_COOKIE_NAME);

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
  const currentToken = readStringCookie(req, REFRESH_COOKIE_NAME);
  const filter: Record<string, unknown> = { userId };

  if (currentToken) {
    const currentTokenHash = hashToken(currentToken);
    filter.tokenHash = { $ne: currentTokenHash };
  }

  const result = await RefreshToken.deleteMany(filter);

  // "Log out everywhere" is an explicit user request to drop every other
  // session, so the second-factor trust granted to those devices must drop with
  // them (§1.5 site 6). Unlike per-session logout, this revokes ALL trusted
  // devices — a returning device then has to complete 2FA again.
  await revokeTrustedDevices(userId);

  // EVERY device proof goes, including the one this browser holds: a stolen copy
  // of it is exactly what "log out everywhere" has to cut off, and keeping the
  // value would keep the copy working. A browser that presented a live proof for
  // this account is handed a fresh one (a replacement, never a first proof: a
  // session alone does not earn one), so it stays recognised and the copy dies.
  const presented = await findPresentedDeviceProof(req);
  const callerProven = provesAccount(presented, new mongoose.Types.ObjectId(userId));
  await revokeDeviceProofs(userId);
  if (callerProven) {
    // Like for like: a single-use proof is replaced by a single-use one.
    const id = new mongoose.Types.ObjectId(userId);
    if (presented.proof.singleUse) {
      await issueUnlockProof(res, id);
    } else {
      await issueDeviceProof(res, id, null);
    }
  }

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

  // A password reset invalidates every existing session; the second-factor trust
  // that let devices skip 2FA must drop with them (§1.5 site 1), or a device
  // trusted under the old password would still bypass 2FA after the reset.
  await revokeTrustedDevices(user._id);
  // And every device proof: a reset changes the footing every one was granted on.
  await revokeDeviceProofs(user._id);

  user.authHash = hashedAuth;
  user.encryptedVaultKey = newEncryptedVaultKey;
  user.vaultKeyIv = newVaultKeyIv;
  user.vaultKeyTag = newVaultKeyTag;
  // An interrupted rotation's wrapper is dropped HERE, and this is the one place
  // dropping it is correct rather than destructive.
  //
  // `changePassword` re-wraps that key under the new MEK because the key is still
  // the only way to read the rows the crashed rotation had already re-sealed. A
  // RESET cannot: it is reached without the old master password, so the old MEK
  // does not exist anywhere and the client mints a brand-new vault key. Every row
  // in the account is already unreadable at this point — `ResetPasswordPage` says
  // so before the user confirms — so the pending wrapper is not a key any more,
  // just ciphertext nothing can open.
  //
  // Keeping it is not neutral. `getProfile` derives `interruptedRotation` from
  // its presence, so the Settings page would offer to finish a rotation that can
  // never be finished, for ever; and `bulkReEncrypt`'s outstanding-rotation guard
  // reads the same field, so every future rotation on the account would be
  // refused until the user discarded a wrapper nothing had told them about.
  user.pendingEncryptedVaultKey = undefined;
  user.pendingVaultKeyIv = undefined;
  user.pendingVaultKeyTag = undefined;
  // Same reasoning for the write fence: a reset that lands while a rotation was
  // still flagged would otherwise leave the account refusing its own writes until
  // the next login lowered it, over a rotation whose subject no longer exists.
  user.rotationInProgress = false;
  clearLockoutStateOnDocument(user, 'password');
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

  // Which factor this link unlocks. A link minted before the claim existed was
  // always a password link, so an absent claim reads as `password`; anything
  // else must be one of the known factors, or the link is refused. The claim is
  // inside the signature, so a link can only ever discharge the factor it was
  // mailed for.
  const factor: LockoutFactor | undefined =
    payload.factor === undefined
      ? 'password'
      : LOCKOUT_FACTORS.find((known) => known === payload.factor);
  if (factor === undefined) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Both episode fields are `select: false`; without the `+` every link would be
  // compared against `undefined` and rejected.
  const user = await User.findById(payload.userId).select('+lockoutEpisodeId +secondFactorLockout');
  if (!user) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // Verify the token names the lock episode that is still running for ITS factor.
  //
  // Binding to the EPISODE rather than to the deadline is what keeps one link
  // alive for a whole episode however long an attacker grinds: the deadline is
  // rewritten by every re-lock and the identity is not. Clearing the episode on
  // discharge is what keeps the link SINGLE-USE. A missing episode matches
  // nothing: the hash of the empty string is a fixed value every account with no
  // episode would otherwise match.
  const episodeId = unlockEpisodeOf(user, factor);
  if (episodeId === undefined || !unlockTokenNamesEpisode(payload.stateHash, episodeId)) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // An atomic update rather than `user.save()`: this clears one factor's state
  // and nothing else, it must not run whole-document validators against a record
  // an unauthenticated caller reached, and it is conditioned on the episode just
  // verified still being the stored one, so a second use of the same link that
  // raced the first discharges nothing and is refused like any spent link.
  if (!(await dischargeUnlockedEpisode(user._id, factor, episodeId))) {
    throw httpErrors.badRequest(ERROR_CODES.TOKEN_INVALID);
  }

  // The browser that followed the link gets a single-use, ten-minute device
  // proof: a stranger can re-lock the account seconds after the link is used,
  // and without this the owner would be locked out again before they could sign in.
  // A browser that already holds a live proof for this account keeps it rather
  // than trading a 30-day proof for a 10-minute one.
  if (!provesAccount(await findPresentedDeviceProof(req), user._id)) {
    await issueUnlockProof(res, user._id);
  }

  const unlockCtx = getRequestContext(req);
  await createAuditLog(
    user._id.toString(),
    'account_unlock',
    { method: 'email_link', factor },
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

/**
 * How many 2FA backup codes a loaded user document still holds.
 *
 * `backupCodes` is `select: false` on the model, so it is absent unless a query
 * explicitly asks for it — which makes its type `string[] | undefined` at every
 * call site, and makes "the field was not projected" a case this has to answer
 * for. Zero is the safe answer: it is what an account with no codes left would
 * report, so a caller that forgets the projection under-reports rather than
 * throwing inside a login.
 *
 * It is a named, exported function rather than an inline `?.length ?? 0` for one
 * reason: inline, the not-projected arm is unreachable from any route and would
 * sit forever as an uncovered branch that nobody could honestly exercise. Here
 * it is an ordinary boundary case of a pure function, and is tested as one.
 */
export function countBackupCodes(user: { backupCodes?: string[] | undefined }): number {
  return user.backupCodes?.length ?? 0;
}
