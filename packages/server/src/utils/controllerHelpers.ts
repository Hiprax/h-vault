import type { Request } from 'express';
import { httpErrors } from '@hiprax/errors';
import { User } from '../models/User.js';
import { Folder } from '../models/Folder.js';
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
 * Refuses a write that would file a row under a folder the caller does not own.
 *
 * The two "no folder named here" values are passed through rather than checked,
 * and they mean different things to the caller: `undefined` is "leave the folder
 * alone" and `null` is "clear it". Neither names a folder, so neither can name
 * somebody else's.
 *
 * A folder that exists but belongs to another account is answered with the SAME
 * 404 as one that never existed, so the status cannot be used to enumerate
 * another account's folders.
 *
 * Shared by `vaultController.updateItem` and `documentController.updateDocument`
 * because the check IS the same check: both file a row under `folderId`, and a
 * second copy would be a second place for the status or the scoping to drift.
 */
export async function assertFolderOwned(
  folderId: string | null | undefined,
  userId: string,
): Promise<void> {
  if (folderId === undefined || folderId === null) return;

  const folderExists = await Folder.exists({ _id: folderId, userId });
  if (!folderExists) {
    throw httpErrors.notFound('Target folder not found');
  }
}

/**
 * Turns an allowlisted update into the Mongo operator document that applies it,
 * with `folderId: null` expressed as an `$unset` rather than a stored null.
 *
 * That distinction is not cosmetic. `vaultItemResponseSchema` and
 * `documentResponseSchema` both declare `folderId` as `.optional()` and NOT
 * `.nullable()`, so a stored null comes back as `folderId: null` and fails the
 * client's pre-decryption shape check on every un-filed row: the row is intact
 * and unreadable. `bulkMove` and the folder-deletion orphan sweep `$unset` for
 * the same reason, so one predicate — `folderId: null`, which matches an ABSENT
 * field — continues to mean one thing across every collection.
 *
 * It MUTATES `update`, deleting the `folderId` key it turned into an `$unset`,
 * and that is deliberate: leaving it would put `folderId: null` back into `$set`
 * and store the null this exists to avoid. A caller that needs the field names a
 * request carried — `updateDocument` audits them — must therefore read them
 * BEFORE calling this.
 *
 * An empty result is a legitimate outcome, not a failure: a body naming only
 * fields the allowlist dropped produces `{}`, and each caller decides what that
 * means for it.
 */
export function buildFolderAwareUpdate(update: Record<string, unknown>): Record<string, unknown> {
  const updateOp: Record<string, unknown> = {};

  if ('folderId' in update && update.folderId === null) {
    delete update.folderId;
    updateOp.$unset = { folderId: 1 };
  }
  if (Object.keys(update).length > 0) {
    updateOp.$set = update;
  }

  return updateOp;
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
 * The distributed-lock name a vault import holds for its user, mirroring
 * {@link vaultRotationLockName}.
 *
 * `toolsController.importVault` checks the per-user item cap and then writes;
 * without serialization two overlapping imports can each read a count that fits
 * and then both insert, breaching `MAX_ITEMS_PER_USER`. A transaction alone does
 * NOT close that race on every topology — a standalone deployment (and the
 * default test harness) rejects multi-document transactions entirely — so the
 * lock is what actually bounds concurrency. `acquireJobLock` is an atomic upsert
 * against the unique `jobName` index, which holds with or without transactions.
 *
 * Scope: `operations` is now the only import wire shape, so this lock covers
 * every import — import-vs-import cannot breach the cap on any topology. What it
 * does NOT cover is a row committed by a DIFFERENT endpoint (`POST /items`,
 * `POST /backup/restore`) between the executor's count and its insert; that
 * narrower window is pre-existing, is shared with `vaultController.createItem`'s
 * own count-then-write check, and is documented where it is taken in
 * `toolsController.executeImportOperations`.
 */
export function vaultImportLockName(userId: string): string {
  return `vault-import:${userId}`;
}

/**
 * The distributed-lock name one document completion holds, mirroring
 * {@link vaultImportLockName} — but keyed by the UPLOAD, not by the user.
 *
 * That difference is the design. Completing a transfer touches exactly one
 * staging row, one stored object and one `documents` row, all named by this id,
 * so two completions of DIFFERENT uploads cannot interfere and must not queue
 * behind each other: a user may legitimately run
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` transfers and finish them at the
 * same moment.
 *
 * What it does exclude is a completion racing ITSELF — a client retry after a
 * timeout, or a double-clicked button. The unique `_id` on `documents` already
 * makes a second ROW impossible, so this lock is not what guarantees that; what
 * it prevents is the second run getting half-way (aborting a multipart upload the
 * first is completing, deleting a staging row out from under it, re-charging the
 * quota) before the primary key stops it. The two completions of one upload are
 * therefore serialized, and the loser reports the winner's row rather than a
 * conflict whenever that row already exists.
 *
 * Note what this lock deliberately does NOT overlap: the per-user
 * {@link vaultRotationLockName}. The two are disjoint, which is exactly why
 * completion needs {@link assertVaultNotRotating} as well as its vault-key
 * version check — holding this lock says nothing at all about whether a rotation
 * is running.
 *
 * The name carries the OWNER as well as the upload, even though an upload id is
 * already globally unique and adding the owner changes nothing for the account that
 * holds it. It closes a small oracle: the lock is taken before ownership is read, so
 * an unscoped name would let a caller who somehow knew another account's upload id
 * observe a "completion in progress" conflict where an unknown id answers "not
 * found" — and this codebase's standing rule is that a foreign id and an id that
 * never existed must be indistinguishable.
 */
export function documentCompleteLockName(userId: string, uploadId: string): string {
  return `document-complete:${userId}:${uploadId}`;
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
