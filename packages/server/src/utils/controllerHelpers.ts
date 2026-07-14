import type { Request } from 'express';
import { httpErrors } from '@hiprax/errors';
import { User } from '../models/User.js';
import { JobLock } from '../models/JobLock.js';

/**
 * Maximum length, in characters, for any persisted `userAgent` value across
 * the codebase.
 *
 * INVARIANT: Every store of a `User-Agent` header — audit log rows
 * (`AuditLog.userAgent`, `maxlength: 512`) and refresh-token device info
 * (`RefreshToken.deviceInfo.userAgent`, `maxlength: 512`) — uses this same
 * upper bound. Pre-truncating at the request boundary via
 * {@link getRequestContext} ensures the length cap is enforced even when a
 * controller bypasses Mongoose validators (e.g. `findOneAndUpdate` without
 * `runValidators: true`). The model-level `maxlength` validators remain as
 * defense-in-depth.
 */
export const MAX_USER_AGENT_LENGTH = 512;

/**
 * Maximum length, in characters, for any persisted or rate-limit-bucketed IP
 * address value across the codebase.
 *
 * 45 chars is the upper bound of an RFC-compliant IPv6 address with an
 * embedded IPv4 segment (e.g. `0000:0000:0000:0000:0000:ffff:255.255.255.255`).
 *
 * INVARIANT: Every consumer of a client IP — audit log rows
 * (`AuditLog.ipAddress`, `maxlength: 45`), refresh-token device info
 * (`RefreshToken.deviceInfo.ip`, `maxlength: 45`), and rate-limit bucket keys
 * (`resolveClientKey` in `middleware/rateLimiter.ts`) — uses this same upper
 * bound. Pre-truncating at the request boundary via {@link getRequestContext}
 * ensures the length cap is enforced even when a malicious upstream proxy
 * forwards an oversized `X-Forwarded-For` value. Without this cap:
 *
 *   1. Audit-log writes throw a Mongoose `ValidationError` (silently swallowed
 *      by `auditService.createAuditLog`'s try/catch), so an attacker who can
 *      reach a `TRUST_PROXY=true` deployment can suppress every audit row for
 *      their request — including `login_failed` / `password_verification_failed`
 *      — by sending a single oversized header.
 *   2. Rate-limit buckets fragment per-spoofed-IP, letting an attacker rotate
 *      arbitrary-length `X-Forwarded-For` values to evade `authLimiter`,
 *      `csrfLimiter`, `tokenVerifyLimiter`, `heavyOpLimiter`, and
 *      `healthLimiter`.
 *
 * The model-level `maxlength` validators remain as defense-in-depth.
 */
export const MAX_IP_ADDRESS_LENGTH = 45;

/**
 * Extracts the authenticated user's ID from the request object.
 * Throws 401 if the user is not authenticated.
 */
export function getUserId(req: Request): string {
  const user = req.user;
  if (!user?._id) {
    throw httpErrors.unauthorized('Authentication required');
  }
  return user._id;
}

/**
 * Defense-in-depth field allowlist filter.
 * Returns a new object containing only the keys present in `allowedFields`.
 */
export function pickAllowedFields(
  data: Record<string, unknown>,
  allowedFields: Set<string>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of allowedFields) {
    if (key in data) {
      result[key] = data[key];
    }
  }
  return result;
}

/**
 * Rejects a write that would persist NEW ciphertext under the caller's vault
 * key while a vault-key rotation is being processed for that user.
 *
 * A rotation (`vaultController.bulkReEncrypt`) re-encrypts a set of rows that
 * the client enumerated and decrypted with the OLD key, then overwrites
 * `User.encryptedVaultKey` with the new one. A second active session still
 * holding the old key can decrypt — and therefore happily write — throughout
 * that window, but its row is not in the rotation's set, so once the new key
 * lands that row is permanently undecryptable and the writing session is never
 * told. Fencing the server-side processing window turns that silent data loss
 * into a retryable 409.
 *
 * Called by every ciphertext-creating handler: `createItem` / `updateItem`
 * (vault), `createFolder` / `updateFolder` (folders), `importVault` (tools) and
 * `restoreBackup` (backup). Handlers that persist no vault-key ciphertext —
 * `bulkMove`, `restoreItem`, the deletes, `reorderFolder`, `deleteFolder` —
 * deliberately do NOT call it: they only touch metadata / soft-delete flags,
 * which a rotation neither reads nor rewrites, so blocking them would be a
 * needless availability hit.
 *
 * Not called by `bulkReEncrypt` itself: the flag is its own, and a stuck flag
 * left by a crashed rotation must never lock the user out of retrying (login
 * crash-recovery in `authController.login` also clears such a flag).
 */
export async function assertVaultNotRotating(userId: string): Promise<void> {
  const user = await User.findById(userId).select('rotationInProgress').lean();
  if (user?.rotationInProgress === true) {
    throw httpErrors.conflict('Vault key rotation is in progress. Please wait and retry.');
  }
}

/**
 * The distributed-lock name a vault-key rotation holds for its user. Sole source
 * of the string so the writer (`vaultController.bulkReEncrypt`, which acquires
 * and releases it) and the liveness probe ({@link isVaultRotationLockHeld}, used
 * by login crash-recovery) can never drift apart — a mismatch would silently
 * defeat the guard.
 */
export function vaultRotationLockName(userId: string): string {
  return `vault-rotation:${userId}`;
}

/**
 * True while a vault-key rotation is ACTIVELY processing for `userId`.
 *
 * `bulkReEncrypt` acquires the {@link vaultRotationLockName} JobLock BEFORE it
 * raises the `rotationInProgress` flag and releases it AFTER clearing that flag,
 * so a live rotation holds this lock for the entire flag-true window; a rotation
 * that crashed mid-flight leaves a lock whose `expiresAt` has passed (the TTL
 * reaper may not have removed the row yet, hence the explicit `expiresAt` range
 * predicate rather than mere existence).
 *
 * This is the discriminator login crash-recovery needs. `rotationInProgress`
 * doubles as the live write-fence read by {@link assertVaultNotRotating}, so
 * login must clear it ONLY for a genuinely crashed rotation (no live lock) and
 * never for one still in progress — clearing a live fence would readmit a
 * second session's stale-key write that the rotation's enumerated set does not
 * cover, stranding that row under the superseded key.
 */
export async function isVaultRotationLockHeld(userId: string): Promise<boolean> {
  const lock = await JobLock.exists({
    jobName: vaultRotationLockName(userId),
    expiresAt: { $gt: new Date() },
  });
  return lock !== null;
}

/**
 * Normalised request context used by audit-log writes, refresh-token writes,
 * and any other persistence path that captures client metadata.
 *
 * Centralising this prevents per-controller drift (`req.headers['user-agent']`
 * vs `req.get('user-agent')`, `'unknown'` vs `''` fallbacks) and enforces the
 * {@link MAX_USER_AGENT_LENGTH} truncation invariant at the source so callers
 * cannot accidentally write an oversized user-agent string by bypassing
 * Mongoose validators.
 */
export function getRequestContext(req: Request): { ip: string; userAgent: string } {
  const rawIp = req.ip ?? 'unknown';
  const ip = rawIp.length > MAX_IP_ADDRESS_LENGTH ? rawIp.slice(0, MAX_IP_ADDRESS_LENGTH) : rawIp;
  const rawUserAgent = req.get('user-agent') ?? 'unknown';
  const userAgent =
    rawUserAgent.length > MAX_USER_AGENT_LENGTH
      ? rawUserAgent.slice(0, MAX_USER_AGENT_LENGTH)
      : rawUserAgent;
  return { ip, userAgent };
}
