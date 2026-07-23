import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import mongoose from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import { User } from '../models/User.js';
import { RefreshToken } from '../models/RefreshToken.js';
import { TrustedDevice } from '../models/TrustedDevice.js';
import { AuditLog } from '../models/AuditLog.js';
import { hashToken } from '../utils/token.js';
import { createAuditLog } from '../services/auditService.js';
import { cascadeDeleteUser } from '../utils/cascadeDelete.js';
import { revokeTrustedDevices } from '../utils/trustedDevices.js';
import { getRequestContext, getUserId } from '../utils/controllerHelpers.js';
import { cryptoManager } from '../utils/cryptoManager.js';
import { config, isProduction, twoFactorEncryptionKey } from '../config/index.js';
import { REFRESH_COOKIE_NAME } from '../constants/index.js';
import { APP_NAME, BACKUP_CODES_COUNT, MAX_SESSIONS, MAX_TRUSTED_DEVICES } from '@hvault/shared';
import type {
  UpdateSettingsInput,
  ChangePasswordInput,
  AuditLogQueryInput,
  Setup2faInput,
  Disable2faInput,
  DeleteAccountInput,
  RegenerateBackupCodesInput,
} from '@hvault/shared';

const logger = createLogger({ moduleName: 'user-controller' });

// ── Handlers ─────────────────────────────────────────────────────────

export const getProfile = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const user = await User.findById(userId).select('-__v -passwordChangedAt').lean();

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  const backupSettings = user.settings.backup;
  const isConfigured = Boolean(backupSettings.encryptedBWK);

  const profile = {
    ...user,
    settings: {
      ...user.settings,
      backup: {
        enabled: backupSettings.enabled,
        scheduleHour: backupSettings.scheduleHour,
        backupEmails: backupSettings.backupEmails,
        lastBackupAt: backupSettings.lastBackupAt,
        lastBackupStatus: backupSettings.lastBackupStatus,
        isConfigured,
        // Include encrypted BWK components so the client can verify the backup
        // password locally (zero-knowledge). These are opaque ciphertext, not secrets.
        encryptedBWK: backupSettings.encryptedBWK,
        bwkIv: backupSettings.bwkIv,
        bwkTag: backupSettings.bwkTag,
        bwkSalt: backupSettings.bwkSalt,
      },
    },
  };

  res.status(200).json({
    success: true,
    data: profile,
  });
});

export const updateSettings = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as UpdateSettingsInput;

  // Build a flat $set object for settings sub-fields
  const setFields: Record<string, unknown> = {};

  if (body.autoLockTimeout !== undefined) {
    setFields['settings.autoLockTimeout'] = body.autoLockTimeout;
  }
  if (body.clipboardClearTimeout !== undefined) {
    setFields['settings.clipboardClearTimeout'] = body.clipboardClearTimeout;
  }
  if (body.defaultPasswordLength !== undefined) {
    setFields['settings.defaultPasswordLength'] = body.defaultPasswordLength;
  }
  if (body.defaultPasswordOptions !== undefined) {
    setFields['settings.defaultPasswordOptions'] = body.defaultPasswordOptions;
  }
  if (body.theme !== undefined) {
    setFields['settings.theme'] = body.theme;
  }
  if (body.language !== undefined) {
    setFields['settings.language'] = body.language;
  }

  if (Object.keys(setFields).length === 0) {
    throw httpErrors.badRequest('No settings provided to update');
  }

  const user = await User.findByIdAndUpdate(
    userId,
    { $set: setFields },
    { returnDocument: 'after', runValidators: true },
  )
    .select('-__v')
    .lean();

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  const changedKeys = Object.keys(setFields).map((k) => k.replace('settings.', ''));

  const settingsCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'settings_update',
    { changedKeys },
    settingsCtx.ip,
    settingsCtx.userAgent,
  );

  logger.info('User settings updated', { userId });

  res.status(200).json({
    success: true,
    data: user.settings,
  });
});

export const changePassword = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as ChangePasswordInput;

  const user = await User.findById(userId).select('+authHash');

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  const isMatch = await bcrypt.compare(body.currentAuthHash, user.authHash);

  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'change_password' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  const newHash = await bcrypt.hash(body.newAuthHash, config.BCRYPT_ROUNDS);
  const passwordChangedAt = new Date();

  // Use a transaction (if supported by the MongoDB topology) so that both the
  // refresh-token revocation and the user password update are committed atomically.
  // Standalone MongoDB (no replica set) does not support transactions — in that
  // fallback path, we delete refresh tokens BEFORE saving the user. This is the
  // safer ordering: if the process crashes between the two steps, the user's
  // refresh tokens are already gone and they'll be forced to log in again
  // (mild inconvenience). The reverse ordering could leave stale refresh tokens
  // valid for a user whose password has been changed, which is a security issue.
  const supportsTransactions =
    mongoose.connection.readyState === mongoose.ConnectionStates.connected &&
    Boolean(mongoose.connection.getClient().options.replicaSet);

  if (supportsTransactions) {
    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await RefreshToken.deleteMany({ userId }, { session });
        // Changing the master password invalidates every session; the trusted
        // devices granted under the old password must lose their 2FA-skip too
        // (§1.5 site 2). Runs in the same transaction so it commits atomically
        // with the password update.
        await revokeTrustedDevices(userId, session);
        await User.updateOne(
          { _id: userId },
          {
            $set: {
              authHash: newHash,
              encryptedVaultKey: body.newEncryptedVaultKey,
              vaultKeyIv: body.newVaultKeyIv,
              vaultKeyTag: body.newVaultKeyTag,
              passwordChangedAt,
            },
          },
          { session },
        );
      });
    } finally {
      await session.endSession();
    }
  } else {
    // Standalone MongoDB — revoke refresh tokens BEFORE updating the password.
    // If the subsequent save fails, the user simply has to log in again with
    // their existing password. The reverse order would leave stale tokens valid
    // for a user whose password has changed.
    await RefreshToken.deleteMany({ userId });
    // Same revocation as the transactional branch (§1.5 site 2): drop trusted
    // devices so none skips 2FA under the new password.
    await revokeTrustedDevices(userId);
    user.authHash = newHash;
    user.encryptedVaultKey = body.newEncryptedVaultKey;
    user.vaultKeyIv = body.newVaultKeyIv;
    user.vaultKeyTag = body.newVaultKeyTag;
    user.passwordChangedAt = passwordChangedAt;
    await user.save();
  }

  const pwCtx = getRequestContext(req);
  await createAuditLog(userId, 'password_change', undefined, pwCtx.ip, pwCtx.userAgent);

  logger.info('Password changed', { userId });

  res.status(200).json({
    success: true,
    message: 'Password changed successfully. Please log in again.',
  });
});

export const setup2fa = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { password } = req.body as Setup2faInput;

  const user = await User.findById(userId).select('+authHash');

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  // Verify current password before allowing 2FA setup
  const isMatch = await bcrypt.compare(password, user.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: '2fa_setup' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  if (user.twoFactorEnabled) {
    throw httpErrors.conflict('Two-factor authentication is already enabled');
  }

  const secretObj = new Secret();
  const secret = secretObj.base32;
  const totp = new TOTP({
    issuer: APP_NAME,
    label: user.email,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: secretObj,
  });
  const otpauthUri = totp.toString();

  // Store the pending secret server-side (encrypted) with a 10-minute TTL.
  // Use findByIdAndUpdate to ensure the fields are persisted reliably, since the
  // user document was fetched with .select('+authHash') which excludes these fields.
  const encryptedPendingSecret = cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey);
  await User.findByIdAndUpdate(userId, {
    $set: {
      pendingTwoFactorSecret: encryptedPendingSecret,
      pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
    },
  });

  // Backup codes are only generated in verify2fa after the user confirms 2FA setup
  res.status(200).json({
    success: true,
    data: {
      secret,
      otpauthUri,
      qrCodeDataUrl: otpauthUri,
    },
  });
});

export const verify2fa = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { code } = req.body as { code: string };

  const user = await User.findById(userId).select(
    '+pendingTwoFactorSecret +pendingTwoFactorExpiry',
  );

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  if (user.twoFactorEnabled) {
    throw httpErrors.conflict('Two-factor authentication is already enabled');
  }

  if (!user.pendingTwoFactorSecret || !user.pendingTwoFactorExpiry) {
    throw httpErrors.badRequest(
      'No pending 2FA setup found. Please start the setup process first.',
    );
  }

  if (user.pendingTwoFactorExpiry < new Date()) {
    // Clear expired pending secret
    await User.findByIdAndUpdate(userId, {
      $unset: { pendingTwoFactorSecret: 1, pendingTwoFactorExpiry: 1 },
    });
    throw httpErrors.badRequest('2FA setup has expired. Please start the setup process again.');
  }

  // Decrypt the pending secret stored server-side
  const secret = cryptoManager.decryptTextSync(user.pendingTwoFactorSecret, twoFactorEncryptionKey);

  const totp = new TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  });
  // window: 1 allows ±1 time step (±30s) to tolerate minor clock drift
  const delta = totp.validate({ token: code, window: 1 });

  if (delta === null) {
    throw httpErrors.badRequest('Invalid verification code');
  }

  // TOTP replay protection: reject codes that have already been used.
  // The delta from validate() tells us which time step the code belongs to.
  // We store the time step and reject codes at or before the stored timestamp.
  const totpTimeStep = Math.floor(Date.now() / 1000 / 30) + delta;
  if (user.lastTotpTimestamp != null && totpTimeStep <= user.lastTotpTimestamp) {
    throw httpErrors.badRequest('Invalid verification code');
  }

  // The secret is already encrypted from the setup step — re-encrypt for permanent storage
  const encryptedSecret = cryptoManager.encryptTextSync(secret, twoFactorEncryptionKey);

  // Generate and hash backup codes
  const backupCodes: string[] = [];
  const hashedBackupCodes: string[] = [];

  for (let i = 0; i < BACKUP_CODES_COUNT; i++) {
    const backupCode = crypto.randomBytes(8).toString('hex');
    backupCodes.push(backupCode);
    const hashed = await bcrypt.hash(backupCode, config.BCRYPT_ROUNDS);
    hashedBackupCodes.push(hashed);
  }

  // Atomic conditional update — ensures only one concurrent verify can enable
  // 2FA. If two requests race here (e.g. same user, two tabs), exactly one wins
  // the compare-and-set and commits a single set of backup codes. The loser
  // gets null back and returns 409, so the returned backup codes in the
  // successful response are the ones actually persisted. The filter conditions
  // on both `twoFactorEnabled: false` AND that this TOTP time step strictly
  // advances `lastTotpTimestamp`, folding the replay guard into the same atomic
  // compare-and-set (the earlier read-check is a non-atomic read-then-write that
  // a same-time-step race could slip past) — a replayed/raced code matches 0
  // docs and is rejected below.
  const updated = await User.findOneAndUpdate(
    {
      _id: userId,
      twoFactorEnabled: false,
      $or: [
        { lastTotpTimestamp: { $exists: false } },
        { lastTotpTimestamp: null },
        { lastTotpTimestamp: { $lt: totpTimeStep } },
      ],
    },
    {
      $set: {
        twoFactorSecret: encryptedSecret,
        backupCodes: hashedBackupCodes,
        twoFactorEnabled: true,
        lastTotpTimestamp: totpTimeStep,
      },
      $unset: {
        pendingTwoFactorSecret: 1,
        pendingTwoFactorExpiry: 1,
      },
    },
    { returnDocument: 'after' },
  );

  if (!updated) {
    throw httpErrors.conflict('Two-factor authentication is already enabled');
  }

  // Enabling 2FA changes the second-factor regime, so any pre-existing trust must
  // be re-established under the new factor rather than carried over (§1.5 site 4).
  // In practice a just-enabled account holds no trusted devices (they are minted
  // only at a 2FA login), so this is defence-in-depth against a future path that
  // could leave a stale record behind.
  await revokeTrustedDevices(userId);

  const enable2faCtx = getRequestContext(req);
  await createAuditLog(userId, '2fa_enable', undefined, enable2faCtx.ip, enable2faCtx.userAgent);

  logger.info('2FA enabled', { userId });

  res.status(200).json({
    success: true,
    message: 'Two-factor authentication enabled',
    data: {
      backupCodes,
    },
  });
});

export const disable2fa = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { code, password } = req.body as Disable2faInput;

  const user = await User.findById(userId).select('+authHash +twoFactorSecret +backupCodes');

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  // Verify current password before allowing 2FA disable
  const isMatch = await bcrypt.compare(password, user.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: '2fa_disable' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  if (!user.twoFactorEnabled || !user.twoFactorSecret) {
    throw httpErrors.badRequest('Two-factor authentication is not enabled');
  }

  // Decrypt the stored secret
  const decryptedSecret = cryptoManager.decryptTextSync(
    user.twoFactorSecret,
    twoFactorEncryptionKey,
  );
  const totp = new TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(decryptedSecret),
  });
  // window: 1 allows ±1 time step (±30s) to tolerate minor clock drift
  const delta = totp.validate({ token: code, window: 1 });

  if (delta === null) {
    throw httpErrors.badRequest('Invalid verification code');
  }

  // TOTP replay protection: reject codes that have already been used.
  // The delta from validate() tells us which time step the code belongs to.
  // We store the time step and reject codes at or before the stored timestamp.
  const currentTimeStep = Math.floor(Date.now() / 1000 / 30) + delta;
  if (user.lastTotpTimestamp != null && currentTimeStep <= user.lastTotpTimestamp) {
    throw httpErrors.badRequest('Invalid verification code');
  }

  // Use findByIdAndUpdate to reliably unset fields. The user document was
  // fetched with .select('+authHash +twoFactorSecret +backupCodes') which
  // may not persist $unset correctly via user.save() on partially-selected docs.
  await User.findByIdAndUpdate(userId, {
    $set: { twoFactorEnabled: false },
    $unset: { twoFactorSecret: 1, backupCodes: 1, lastTotpTimestamp: 1 },
  });

  // Disabling 2FA is a downgrade in account security. Revoke all refresh
  // tokens (except the caller's current one) so previously-issued sessions
  // from the 2FA-enabled regime cannot continue under reduced authentication.
  // Mirrors the logoutAll pattern.
  const currentToken: string | undefined = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;
  const filter: Record<string, unknown> = { userId };
  if (currentToken) {
    filter.tokenHash = { $ne: hashToken(currentToken) };
  }
  await RefreshToken.deleteMany(filter);

  // Disabling 2FA removes the second factor entirely, so every trusted-device
  // record — which exists solely to skip that factor — is now meaningless and
  // must be revoked (§1.5 site 3). Revoke ALL of them (not "all but current"):
  // a trusted device is a login-time construct, not the current session.
  await revokeTrustedDevices(userId);

  const disable2faCtx = getRequestContext(req);
  await createAuditLog(userId, '2fa_disable', undefined, disable2faCtx.ip, disable2faCtx.userAgent);

  logger.info('2FA disabled', { userId });

  res.status(200).json({
    success: true,
    message: 'Two-factor authentication disabled',
  });
});

export const regenerateBackupCodes = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);
    const { password, code } = req.body as RegenerateBackupCodesInput;

    const user = await User.findById(userId).select('+authHash +twoFactorSecret');

    if (!user) {
      throw httpErrors.notFound('User not found');
    }

    if (!user.twoFactorEnabled) {
      throw httpErrors.badRequest('Two-factor authentication is not enabled');
    }

    // Verify current password
    const isMatch = await bcrypt.compare(password, user.authHash);
    if (!isMatch) {
      const failCtx = getRequestContext(req);
      await createAuditLog(
        userId,
        'password_verification_failed',
        { endpoint: 'regenerate_backup_codes' },
        failCtx.ip,
        failCtx.userAgent,
      );
      throw httpErrors.unauthorized('Current password is incorrect');
    }

    // Require 2FA code when 2FA is enabled
    let totpTimeStep: number | undefined;
    if (user.twoFactorSecret) {
      if (!code) {
        throw httpErrors.badRequest('Two-factor authentication code is required');
      }
      const decryptedSecret = cryptoManager.decryptTextSync(
        user.twoFactorSecret,
        twoFactorEncryptionKey,
      );
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(decryptedSecret),
      });
      const delta = totp.validate({ token: code, window: 1 });
      if (delta === null) {
        throw httpErrors.badRequest('Invalid verification code');
      }

      // TOTP replay protection: reject codes that have already been used.
      // The delta from validate() tells us which time step the code belongs to.
      // We store the time step and reject codes at or before the stored timestamp.
      totpTimeStep = Math.floor(Date.now() / 1000 / 30) + delta;
      if (user.lastTotpTimestamp != null && totpTimeStep <= user.lastTotpTimestamp) {
        throw httpErrors.badRequest('Invalid verification code');
      }
    }

    // Generate new backup codes (old ones are completely replaced)
    const backupCodes: string[] = [];
    const hashedBackupCodes: string[] = [];

    for (let i = 0; i < BACKUP_CODES_COUNT; i++) {
      const backupCode = crypto.randomBytes(8).toString('hex');
      backupCodes.push(backupCode);
      const hashed = await bcrypt.hash(backupCode, config.BCRYPT_ROUNDS);
      hashedBackupCodes.push(hashed);
    }

    // Persist the new backup codes. Both writes are conditional on
    // `twoFactorEnabled: true` (mirroring verify2fa's conditional write): the
    // enabled-check above is a read, so a `disable2fa` that lands between it and
    // this write would otherwise let the regeneration re-populate `backupCodes` on
    // an account whose 2FA is already off. A no-match means the account was
    // disabled underneath us — the request is rejected, nothing is written.
    //
    // When a TOTP was verified, the replay guard is folded into the same atomic
    // compare-and-set: write only if this time step strictly advances
    // `lastTotpTimestamp`. A no-op (null result) also means a concurrent request
    // already consumed this code, so it is rejected as a replay — two racing
    // regenerations must not each publish a distinct backup-code set (the returned
    // codes must equal the ones persisted). The earlier read-check is non-atomic
    // and a same-time-step race can slip past.
    if (totpTimeStep !== undefined) {
      const updated = await User.findOneAndUpdate(
        {
          _id: userId,
          twoFactorEnabled: true,
          $or: [
            { lastTotpTimestamp: { $exists: false } },
            { lastTotpTimestamp: null },
            { lastTotpTimestamp: { $lt: totpTimeStep } },
          ],
        },
        { $set: { backupCodes: hashedBackupCodes, lastTotpTimestamp: totpTimeStep } },
      );
      if (!updated) {
        throw httpErrors.badRequest('Invalid verification code');
      }
    } else {
      // No TOTP was verified (defensive: 2FA enabled without a stored secret) —
      // there is nothing to replay-guard, but the enabled-guard still applies.
      const updated = await User.findOneAndUpdate(
        { _id: userId, twoFactorEnabled: true },
        { $set: { backupCodes: hashedBackupCodes } },
      );
      if (!updated) {
        throw httpErrors.badRequest('Two-factor authentication is not enabled');
      }
    }

    // Regenerating backup codes replaces second-factor recovery material, so the
    // old trust in that factor must drop (§1.5 site 5) — a device trusted before
    // the rotation should re-prove the second factor.
    await revokeTrustedDevices(userId);

    const regenCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      '2fa_backup_codes_regenerated',
      { detail: 'Backup codes regenerated' },
      regenCtx.ip,
      regenCtx.userAgent,
    );

    logger.info('Backup codes regenerated', { userId });

    res.status(200).json({
      success: true,
      message: 'Backup codes regenerated',
      data: { backupCodes },
    });
  },
);

export const listSessions = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  // Only LIVE sessions (`usedAt: null`) are listed. A rotated row is left in
  // place with `usedAt` set as a reuse-detection tombstone (§1.4), not a
  // session — including them would inflate the count far past MAX_SESSIONS
  // (an active session mints hundreds of rows/day) and disagree with the cap
  // that `enforceSessionCap` enforces over exactly this same filtered set.
  const tokens = await RefreshToken.find({ userId, usedAt: null })
    .sort({ createdAt: -1 })
    .limit(MAX_SESSIONS)
    .lean();

  // Identify the current session by comparing refresh token hashes
  const currentToken: string | undefined = req.cookies[REFRESH_COOKIE_NAME] as string | undefined;
  const currentTokenHash = currentToken ? hashToken(currentToken) : null;

  const sessions = tokens.map((token) => ({
    _id: String(token._id),
    deviceInfo: token.deviceInfo,
    createdAt: token.createdAt,
    expiresAt: token.expiresAt,
    current: currentTokenHash !== null && token.tokenHash === currentTokenHash,
  }));

  res.status(200).json({
    success: true,
    data: sessions,
  });
});

export const revokeSession = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const token = await RefreshToken.findOneAndDelete({ _id: id, userId });

  if (!token) {
    throw httpErrors.notFound('Session not found');
  }

  const sessRevokeCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'session_revoke',
    { sessionId: id },
    sessRevokeCtx.ip,
    sessRevokeCtx.userAgent,
  );

  logger.info('Session revoked', { userId, sessionId: id });

  res.status(200).json({
    success: true,
    message: 'Session revoked',
  });
});

// ── Trusted Devices ──────────────────────────────────────────────────

/**
 * GET /user/trusted-devices
 *
 * Lists the caller's trusted-device records (the devices allowed to skip the
 * 2FA step at login). Each record is explicitly projected so the server-only
 * `tokenHash` — the SHA-256 a stolen cookie would have to match — is NEVER
 * returned. `.lean()` bypasses the schema's `toJSON` strip, so the projection
 * here is the guard.
 */
export const getTrustedDevices = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const records = await TrustedDevice.find({ userId })
    .sort({ createdAt: -1 })
    .limit(MAX_TRUSTED_DEVICES)
    .lean();

  const devices = records.map((d) => ({
    _id: String(d._id),
    deviceInfo: d.deviceInfo,
    createdAt: d.createdAt,
    lastUsedAt: d.lastUsedAt,
    expiresAt: d.expiresAt,
  }));

  res.status(200).json({
    success: true,
    data: devices,
  });
});

/**
 * DELETE /user/trusted-devices/:id
 *
 * Revokes a single trusted device by id, scoped to the caller — another user's
 * id matches nothing and 404s. The device must complete 2FA again on its next
 * login.
 */
export const revokeTrustedDevice = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);
    const { id } = req.params as { id: string };

    const record = await TrustedDevice.findOneAndDelete({ _id: id, userId });

    if (!record) {
      throw httpErrors.notFound('Trusted device not found');
    }

    const ctx = getRequestContext(req);
    await createAuditLog(
      userId,
      'trusted_device_revoke',
      { trustedDeviceId: id },
      ctx.ip,
      ctx.userAgent,
    );

    logger.info('Trusted device revoked', { userId, trustedDeviceId: id });

    res.status(200).json({
      success: true,
      message: 'Trusted device revoked',
    });
  },
);

/**
 * DELETE /user/trusted-devices
 *
 * Revokes ALL of the caller's trusted devices via the shared
 * `revokeTrustedDevices` helper — the ninth §1.5 revocation site. Every
 * previously-trusted device then has to complete 2FA again.
 */
export const revokeAllTrustedDevices = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);

    const count = await revokeTrustedDevices(userId);

    const ctx = getRequestContext(req);
    await createAuditLog(userId, 'trusted_device_revoke', { count }, ctx.ip, ctx.userAgent);

    logger.info('All trusted devices revoked', { userId, count });

    res.status(200).json({
      success: true,
      message: 'All trusted devices revoked',
    });
  },
);

export const getAuditLog = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const query = req.query as unknown as AuditLogQueryInput;

  const { page, limit, action } = query;

  const filter: Record<string, unknown> = { userId };

  if (action) {
    filter.action = action;
  }

  const skip = (page - 1) * limit;

  const [logs, total] = await Promise.all([
    AuditLog.find(filter).select('-userId').sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
    AuditLog.countDocuments(filter),
  ]);

  const totalPages = Math.ceil(total / limit);

  res.status(200).json({
    success: true,
    data: logs,
    pagination: {
      page,
      limit,
      total,
      totalPages,
    },
  });
});

// ── Delete Account (GDPR) ──────────────────────────────────────────

export const deleteAccount = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { password, code } = req.body as DeleteAccountInput;

  const user = await User.findById(userId).select('+authHash +twoFactorSecret');

  if (!user) {
    throw httpErrors.notFound('User not found');
  }

  // Verify the user's password before allowing account deletion
  const isMatch = await bcrypt.compare(password, user.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'delete_account' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  // Require 2FA code when 2FA is enabled
  if (user.twoFactorEnabled && user.twoFactorSecret) {
    if (!code) {
      throw httpErrors.badRequest('Two-factor authentication code is required');
    }
    const decryptedSecret = cryptoManager.decryptTextSync(
      user.twoFactorSecret,
      twoFactorEncryptionKey,
    );
    const totp = new TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(decryptedSecret),
    });
    const delta = totp.validate({ token: code, window: 1 });
    if (delta === null) {
      throw httpErrors.badRequest('Invalid verification code');
    }

    // TOTP replay protection: reject codes that have already been used.
    // The delta from validate() tells us which time step the code belongs to.
    // We store the time step and reject codes at or before the stored timestamp.
    // Since the account is being deleted, we don't need to update lastTotpTimestamp.
    const currentTimeStep = Math.floor(Date.now() / 1000 / 30) + delta;
    if (user.lastTotpTimestamp != null && currentTimeStep <= user.lastTotpTimestamp) {
      throw httpErrors.badRequest('Invalid verification code');
    }
  }

  // Phase 1: Mark user as pending deletion. If any subsequent step fails,
  // a background cleanup job can detect and complete the deletion.
  await User.updateOne({ _id: userId }, { $set: { deletionPending: true } });

  // Phase 2: Cascade delete all associated data. Uses a MongoDB transaction
  // when the topology supports it (replica set), otherwise falls back to
  // sequential deletes with retry via deletionPending flag.
  const deleteCtx = getRequestContext(req);
  const deleted = await cascadeDeleteUser({
    userId,
    userEmail: user.email,
    ip: deleteCtx.ip,
    userAgent: deleteCtx.userAgent,
    auditAction: 'account_delete',
  });

  if (!deleted) {
    // The user is marked deletionPending — cleanup job will retry
    throw httpErrors.internalServerError(
      'Account deletion partially failed. Cleanup will complete shortly.',
    );
  }

  // Clear the refresh token cookie
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1',
  });

  logger.info('Account deleted', { userId });

  res.status(200).json({
    success: true,
    message: 'Account deleted successfully',
  });
});
