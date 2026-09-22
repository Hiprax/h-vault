import type { Request, Response } from 'express';
import { ErrorHandler, httpErrors } from '@hiprax/errors';
import { User } from '../models/User.js';
import { Folder } from '../models/Folder.js';
import { JobLock } from '../models/JobLock.js';
import { acquireJobLock, releaseJobLock } from './jobLock.js';
import { createModuleLogger } from './logger.js';

const logger = createModuleLogger('controller-helpers');

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
 *      `csrfLimiter`, `tokenVerifyLimiter`, `refreshLimiter`, and `healthLimiter`.
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
 *
 * ## It is a READ, and a read is not a fence on its own
 *
 * Nothing here holds anything. Between this read and the write it is protecting
 * lie whatever validation, lookups and network calls the handler performs, and a
 * rotation that raises its own flag inside that gap is one this read has already
 * decided does not exist. The flag is therefore necessary and not sufficient:
 * a handler whose gap is more than a statement or two takes
 * {@link acquireVaultRotationLock} across it, which makes this answer stay true
 * until the write lands. Most such handlers call this AFTER taking the lock;
 * `importVault` reads it first, before a multi-megabyte body is validated, and
 * that is sound for a reason set out at {@link acquireVaultRotationLock} rather
 * than assumed here.
 */
export async function assertVaultNotRotating(userId: string): Promise<void> {
  const user = await User.findById(userId).select('rotationInProgress').lean();
  if (user?.rotationInProgress === true) {
    throw httpErrors.conflict('Vault key rotation is in progress. Please wait and retry.');
  }
}

/**
 * The distributed-lock name that EXCLUDES a vault-key rotation for one user.
 * Sole source of the string, so no holder and no probe can drift from another —
 * a mismatch would silently defeat every guarantee below.
 *
 * ## Five holders, not one
 *
 * It is named for the rotation because the rotation is what it exists to
 * exclude, but `vaultController.bulkReEncrypt` is only its first holder. Every
 * operation whose vault-key check cannot be folded into its own write as a
 * filter takes it too, for the span between that check and its commit:
 * `toolsController.importVault`, `backupController.restoreBackup`,
 * `documentController.completeUpload` and `userController.changePassword`.
 * {@link assertVaultKeyVersion}'s docblock states the rule that decides which of
 * the two mechanisms an endpoint gets.
 *
 * Holding it means no rotation can START, because `bulkReEncrypt` acquires it
 * before it raises `rotationInProgress` and releases it after clearing that
 * flag. It says nothing about a rotation that has already COMMITTED, which is
 * what the generation check is for, nor about one that CRASHED, which is what
 * the fence read is for.
 *
 * ## What it costs the probe
 *
 * {@link isVaultRotationLockHeld} can no longer read a held lock as "a rotation
 * is live"; it reads it as "some holder is mid-span". That is the fail-closed
 * direction for its one caller and is spelled out there.
 */
export function vaultRotationLockName(userId: string): string {
  return `vault-rotation:${userId}`;
}

/**
 * How long any one holder of {@link vaultRotationLockName} may hold it before it
 * is treated as crashed and re-acquirable.
 *
 * ONE number for every holder, deliberately, and generous rather than tuned per
 * site. The two failure directions are not symmetrical: a TTL that lapses inside
 * a live span lets a rotation acquire the lock alongside the holder and breaks
 * the exclusion **silently**, with a stranded row as the only evidence; a TTL
 * that outlives a crashed span costs availability, loudly, on an operation the
 * user can retry. Five minutes bounds the longest span any holder has — a
 * restore writing up to `MAX_IMPORT_ITEMS` rows one at a time — with room to
 * spare, and it is the number `bulkReEncrypt` has always used.
 *
 * What a crashed holder blocks for those five minutes is a rotation, an import,
 * a restore, a document completion and a master-password change. On the
 * master-password change specifically that is not a new cost: a crashed rotation
 * also leaves `rotationInProgress` raised, and the fence refuses that endpoint
 * until a LOGIN lowers it — which cannot happen until this same TTL lapses,
 * because login crash-recovery declines while the lock is live.
 *
 * Module-private, exactly like {@link VAULT_ROTATION_LOCK_BUSY_MESSAGE} below
 * and for the same reason: {@link acquireVaultRotationLock} is the ONE thing
 * that applies it, so there is nothing outside this file that may legitimately
 * read it — and an export nobody imports is how a second, divergent TTL gets
 * introduced at a call site. Other modules refer to it by NAME in prose, which
 * is the right kind of reference to a number they must not restate.
 */
const VAULT_ROTATION_LOCK_TTL_MS = 5 * 60 * 1000;

/**
 * The refusal every loser of {@link vaultRotationLockName} receives.
 *
 * ONE sentence for all five holders, because the loser cannot tell which of them
 * won and must not be told a story that might be false: naming "a rotation"
 * specifically was accurate while the rotation was the only holder and is a lie
 * now. It keeps the words "already in progress" that the rotation's own refusal
 * has always carried.
 */
const VAULT_ROTATION_LOCK_BUSY_MESSAGE =
  'Another change that re-seals this account under its vault key is already in progress ' +
  '(a vault key rotation, an import, a backup restore, a document completion or a master ' +
  'password change). Please wait and retry.';

/**
 * Takes {@link vaultRotationLockName} for the caller's check-to-commit span.
 *
 * ## Why a lock rather than a filter
 *
 * {@link assertVaultKeyVersion} answers "is the caller holding the current vault
 * key?" with a READ, and a read is only worth the distance to the write that
 * trusts it. A handler whose write can carry the answer in its own filter uses
 * {@link vaultKeyVersionFilter} and needs nothing here. A handler whose write
 * cannot — because it writes a different collection (`insertMany`, `Document`),
 * writes many rows, or spends seconds in a storage engine between the two —
 * holds this instead, and the rotation's own acquisition then genuinely excludes
 * it rather than merely being unlikely to interleave.
 *
 * ## Non-blocking, and that is the design
 *
 * A loser is refused with a 409 it can retry, never queued. Queueing on a lock
 * whose longest holder is a five-minute rotation would turn a rare conflict into
 * a request that holds a connection open for minutes, and the operations that
 * take this lock are all ones a client re-issues cheaply. Because nothing ever
 * waits, no ordering of acquisitions can deadlock — but the order is fixed
 * anyway so it stays reviewable: this lock is the INNERMOST one every handler
 * takes. `importVault` holds `vault-import:<userId>` outside it and
 * `completeUpload` holds `document-complete:<userId>:<uploadId>` outside it;
 * nothing takes this one first and then takes either of those.
 *
 * ## Where the fence read goes, and why either side of this is sound
 *
 * {@link assertVaultNotRotating} stays: this lock and that flag catch different
 * rotations. Holding the lock means none can START; the flag is the only thing
 * that sees one that CRASHED, whose lock has since TTL-expired and whose fence is
 * stuck up.
 *
 * `restoreBackup`, `completeUpload` and `changePassword` acquire first and read
 * the fence second, which is the order that needs no argument. `importVault`
 * reads the fence at the top of the handler, before a multi-megabyte body is
 * validated, and acquires later — and that is sound for a reason worth writing
 * down rather than re-deriving: a rotation that started after that read either
 * still holds this lock, in which case the acquisition below fails, or has
 * finished and lowered its flag, in which case the generation check catches it.
 * The only state the early read can be stale about is one the acquisition or the
 * generation check refuses anyway.
 *
 * @throws 409 when another holder has it. Callers release with
 *   {@link releaseVaultRotationLock} from a `finally`, before the response is
 *   written.
 */
export async function acquireVaultRotationLock(userId: string): Promise<string> {
  const lockId = await acquireJobLock(vaultRotationLockName(userId), VAULT_ROTATION_LOCK_TTL_MS);
  if (lockId === null) {
    throw httpErrors.conflict(VAULT_ROTATION_LOCK_BUSY_MESSAGE);
  }
  return lockId;
}

/**
 * Releases a lock taken with {@link acquireVaultRotationLock}.
 *
 * Scoped to the acquisition id by `releaseJobLock`, so a holder whose TTL lapsed
 * mid-span cannot free the lock a later holder has since taken.
 */
export async function releaseVaultRotationLock(userId: string, lockId: string): Promise<void> {
  await releaseJobLock(vaultRotationLockName(userId), lockId);
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
 * The distributed-lock name one transfer OPEN holds for its user, mirroring
 * {@link vaultImportLockName} — and keyed by the USER, unlike
 * {@link documentCompleteLockName} below.
 *
 * That difference is the design. `documentController.initUpload` decides three
 * per-user budgets — the document count, the concurrent-transfer count and the
 * byte quota — by reading a count and then writing a staging row, which is the
 * same read-then-write an import performs against `MAX_ITEMS_PER_USER`. Two
 * opens that each individually fit can therefore both pass the read and both
 * write, and the budgets they breach are per-user, so the lock has to be too. As
 * there, a transaction alone would not close it on every topology: a standalone
 * deployment (and the default test harness) rejects multi-document transactions
 * outright, while `acquireJobLock` is an atomic upsert against the unique
 * `jobName` index and holds either way.
 *
 * The concurrency cap is the one that makes this load-bearing rather than tidy.
 * The document count is read from `documents`, where only a COMPLETION writes, so
 * a burst of opens cannot move it. What a burst CAN move is the number of live
 * staging rows, and `MAX_DOCUMENTS_PER_ROTATION` is derived on the assumption
 * that this number is bounded: an account can finish at most
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1` documents past the advertised
 * limit. Unserialized, nothing enforced that — N simultaneous opens all read zero
 * live transfers and all commit — and an account carried past
 * `MAX_DOCUMENTS_PER_ROTATION` can never rotate its vault key again, because the
 * payload that must name every row is at once too long for the schema's `.max()`
 * and, if trimmed, too short for the handler's coverage check.
 *
 * The 409 a loser receives is reachable by a real user, but only just: the upload
 * panel sends one file at a time, so producing it means confirming a second file
 * inside the milliseconds the first open takes. It is reported to them verbatim
 * as "retry", and a scripted client can produce it at will.
 */
export function documentInitLockName(userId: string): string {
  return `document-init:${userId}`;
}

/**
 * The distributed-lock name one document completion holds, mirroring
 * {@link vaultImportLockName} — but keyed by the UPLOAD, not by the user.
 *
 * That difference is the design. Completing a transfer touches exactly one
 * staging row, one stored object and one `documents` row, all named by this id,
 * so two completions of DIFFERENT uploads cannot interfere through anything THIS
 * lock protects, and must not queue behind each other for it.
 *
 * They do queue for something else, and it is worth being exact rather than
 * leaving the sentence above to read as more than it says: a completion also
 * holds the per-user {@link vaultRotationLockName} from its quota read to its
 * insert, so a user running `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` transfers
 * and finishing them at the same moment now has all but one of those completions
 * refused with a retryable 409. That is a deliberate trade recorded at
 * `completeUpload`, and it buys two things this lock cannot: a document can never
 * be sealed under a superseded vault key, which would permanently end the
 * account's ability to rotate, and the per-user quota is measured against every
 * document committed before the insert it licenses, which a lock keyed by upload
 * leaves two completions free to overshoot together. Neither is a reason to widen
 * THIS lock to the user: the per-user lock already covers both spans, and this one
 * would additionally serialise the ledger reads and buy nothing.
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
 * {@link documentInitLockName} that the OTHER end of the same transfer takes, nor
 * the per-user {@link vaultRotationLockName}. All three are distinct names, which
 * is exactly why completion needs {@link assertVaultNotRotating} as well as its
 * vault-key version check — holding this lock says nothing at all about whether a
 * rotation is running — and why it takes the exclusion lock as well rather than
 * assuming this one stands in for it. Acquisition order is this lock OUTSIDE the
 * exclusion lock, never the reverse.
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
 * True while SOME holder of {@link vaultRotationLockName} is mid-span for
 * `userId` — which includes, but is no longer limited to, a vault-key rotation
 * that is actively processing.
 *
 * `bulkReEncrypt` acquires the JobLock BEFORE it raises the `rotationInProgress`
 * flag and releases it AFTER clearing that flag, so a live rotation holds this
 * lock for the entire flag-true window; a rotation that crashed mid-flight leaves
 * a lock whose `expiresAt` has passed (the TTL reaper may not have removed the
 * row yet, hence the explicit `expiresAt` range predicate rather than mere
 * existence).
 *
 * This is the discriminator login crash-recovery needs. `rotationInProgress`
 * doubles as the live write-fence read by {@link assertVaultNotRotating}, so
 * login must clear it ONLY for a genuinely crashed rotation (no live lock) and
 * never for one still in progress — clearing a live fence would readmit a
 * second session's stale-key write that the rotation's enumerated set does not
 * cover, stranding that row under the superseded key.
 *
 * ## The implication that runs one way only
 *
 * "A live rotation holds this lock" is still true. "This lock is held, therefore
 * a rotation is live" is NOT, and has not been since the lock acquired its other
 * four holders (see {@link vaultRotationLockName}). What the caller gets from a
 * `true` answer is therefore weaker than it used to be: it means "do not touch
 * the flag right now", not "a rotation is running". That is the direction the
 * one caller needs. An import, a restore, a completion or a password change
 * holding the lock makes login recovery DEFER the cleanup of a stuck flag to the
 * next login, which is free — those holders are all refused by that same stuck
 * flag anyway, so none of them can hold the lock for long while it is raised,
 * and the flag's cleanup has never been urgent. The opposite error, clearing a
 * live rotation's fence, is the one that costs a row, and this predicate still
 * cannot make it.
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

/**
 * The account's vault-key generation, as a definite number.
 *
 * `vaultKeyVersion` is typed optional on `IUser` on purpose (see the field's own
 * docblock): a hydrated read applies the schema default and always yields a
 * number, while a `.lean()` read of an account created before the column existed
 * yields nothing at all — and the hot paths use `.lean()`. Zero is the correct
 * answer for that account, because zero is what "has never rotated" means and
 * what MongoDB's `$inc` will treat a missing value as.
 *
 * A named, exported function rather than four inline `?? 0`s, for the reason
 * `authController`'s `countBackupCodes` exists in the same shape: inline at a hydrated call
 * site the fallback arm is unreachable from any route, so it would sit for ever
 * as an uncovered branch nobody could honestly exercise. Here the missing value
 * and the missing user are ordinary boundary cases of a pure function, and are
 * tested as ones.
 */
export function vaultKeyVersionOf(user: { vaultKeyVersion?: number | undefined } | null): number {
  return user?.vaultKeyVersion ?? 0;
}

/**
 * Why a write derived from the vault key was refused. Three answers, because
 * they are three different faults and only one of them is a rotation.
 */
type StaleVaultKeyReason =
  /** The caller named a generation BEHIND the account's: a rotation has committed. */
  | 'rotated'
  /** The caller named a generation AHEAD of the account's: bookkeeping fault or a forged body. */
  | 'unreached'
  /** The caller named no generation at all, on an account that has rotated at least once. */
  | 'unnamed';

const STALE_VAULT_KEY_MESSAGES: Record<StaleVaultKeyReason, (current: number) => string> = {
  rotated: (current) =>
    'The vault key was rotated elsewhere. Reload to pick up vault key version ' +
    `${String(current)}, then retry this change.`,
  unreached: (current) =>
    'This request reported a vault key version this account has never had. Reload to pick up ' +
    `vault key version ${String(current)}, then retry this change.`,
  unnamed: (current) =>
    'This request did not say which vault key it used, and this account is on vault key version ' +
    `${String(current)}. Reload the application and retry: an out-of-date client may be holding ` +
    'a superseded vault key.',
};

/**
 * The recoverable 409 {@link assertVaultKeyVersion} throws: this account's
 * CURRENT vault-key generation, attached to an error.
 *
 * ## Why this is a class and not `httpErrors.conflict()`
 *
 * The client needs the NUMBER. `@hiprax/errors`'s response envelope is flat —
 * `createErrorMiddleware` builds `{ success, message, statusCode, statusText }`
 * and discards every other property of the error it was handed — so a thrown
 * `httpErrors.conflict('…')` can only ever put the generation in prose, and a
 * client cannot act on prose. That is the same wall
 * `documentController.completeUpload` hit, which is why its 409 is written with
 * a bare `res.status(409).json(...)` rather than thrown; see the comment there.
 *
 * ## It fails SAFE when nobody catches it
 *
 * It extends `ErrorHandler` with `statusCode: 409`, and
 * `handleCommonErrors`'s default branch preserves `err.statusCode`. So a
 * handler that throws this and does NOT catch it still refuses the write with a
 * 409 — it just loses the number, costing the client a profile re-read it could
 * have been given. The failure mode of forgetting to catch is therefore a
 * slower recovery, never an accepted stale-key write.
 *
 * ## Rendering it is the CALLER's job, deliberately
 *
 * A caller that wants the recoverable body catches this and answers
 * `{ success: false, message: error.message, data: { vaultKeyVersion } }`,
 * which is byte-for-byte the shape `completeUpload` already emits and the shape
 * `swagger.ts` documents. It is not rendered here because the remedy sentence
 * differs per endpoint (rewrap and retry one request, versus reload and
 * re-drive a whole import), and because an error-rendering middleware keyed on
 * this class would put a second, silent answer in front of the one the error
 * middleware already gives.
 */
export class StaleVaultKeyError extends ErrorHandler {
  /** The account's CURRENT generation — what the client must rewrap under. */
  readonly vaultKeyVersion: number;

  /** Which of the three faults this is. Do not branch on the message. */
  readonly reason: StaleVaultKeyReason;

  constructor(vaultKeyVersion: number, reason: StaleVaultKeyReason) {
    super(STALE_VAULT_KEY_MESSAGES[reason](vaultKeyVersion), 409);
    this.name = 'StaleVaultKeyError';
    this.vaultKeyVersion = vaultKeyVersion;
    this.reason = reason;
  }
}

/**
 * Refuses a write that seals NEW ciphertext under a vault key the account has
 * already replaced, and returns the account's current generation.
 *
 * ## The defect this exists for
 *
 * {@link assertVaultNotRotating} catches a rotation that is IN PROGRESS: its
 * flag is raised before `bulkReEncrypt` enumerates, so a row written inside
 * that window is one the new key will not cover. It cannot catch a rotation
 * that has already COMMITTED, because the flag is cleared by then — and a
 * second session holding the superseded key is at its most dangerous precisely
 * then, since it can still decrypt, still encrypt, and has no way to notice.
 * `User.vaultKeyVersion` is `$inc`ed exactly once per completed rotation, so
 * comparing the caller's claim against it closes the half of the window the
 * fence cannot see. The two are peers and neither replaces the other; every
 * guarded handler wants both.
 *
 * ## The four branches, and why the third one is the whole point
 *
 * | `supplied`            | account's `vaultKeyVersion` | outcome |
 * | --------------------- | --------------------------- | ------- |
 * | equal to current      | anything                    | allowed; returns current |
 * | below current         | > 0                         | 409 `rotated` |
 * | above current         | anything                    | 409 `unreached`, logged |
 * | `undefined`           | **> 0**                     | 409 `unnamed` — FAIL CLOSED |
 * | `undefined`           | 0                           | allowed; returns 0 |
 *
 * The field is OPTIONAL on the wire because making it required would be a
 * breaking request-schema change that no MAJOR bump accounts for
 * (`audit:openapi` runs `oasdiff breaking --fail-on WARN`). Optional on the
 * wire is NOT optional in effect: a caller that cannot name a generation is a
 * caller that may be holding a superseded key, so the omission is refused for
 * every account that has ever rotated. What the compatibility branch still
 * serves is exactly the set of accounts for which the defect is impossible — an
 * account at generation 0 has never rotated, so there is no superseded key for
 * anyone to be holding. Widening that branch to "allow whenever the field is
 * absent" would reinstate the total-loss path for every rotated account, which
 * is the one thing this helper is for.
 *
 * A generation ABOVE the current one is named separately even though the
 * equality check below would refuse it anyway, for the reason
 * `documentController.completeUpload` states at length: the number in a request
 * body is the client's own record of which key it holds, never an echo of
 * something this server said, and no honest client can hold a generation the
 * account has never reached. It is answered with the same recoverable refusal
 * rather than a 400 because what matters is that nothing was committed, and
 * handing back the real number lets a confused client recover instead of
 * wedging.
 *
 * ## What it deliberately does NOT do
 *
 * It is a guard, not an existence check. A `userId` with no row yields 0 —
 * `vaultKeyVersionOf`'s documented answer for an absent value, and the same
 * answer {@link assertVaultNotRotating} gives (`user?.rotationInProgress`
 * passes for a missing user). Passport has already proved the account exists
 * and is verified on every authenticated request, and the write that follows
 * carries its own `_id` filter, so there is nothing here for a 404 to protect.
 *
 * It also does not make the check atomic with the write. The returned number is
 * what a caller puts in the write's own filter, via
 * {@link vaultKeyVersionFilter} — `User.updateOne({ _id, vaultKeyVersion:`
 * `vaultKeyVersionFilter(resolved) }, …)` — so that a rotation committing
 * between this read and that write matches nothing instead of clobbering. Use
 * that helper and not a bare `vaultKeyVersion: resolved`; the reason is in its
 * own docblock and it is not cosmetic. A caller whose write cannot carry such a
 * filter takes {@link vaultRotationLockName} across the span instead.
 *
 * @param userId The authenticated caller, from {@link getUserId}.
 * @param supplied The generation the caller claims, or `undefined` when the
 *   request did not carry one.
 * @returns The account's current `vaultKeyVersion`.
 * @throws {StaleVaultKeyError} 409, carrying the current generation.
 */
export async function assertVaultKeyVersion(
  userId: string,
  supplied: number | undefined,
): Promise<number> {
  const user = await User.findById(userId).select('vaultKeyVersion').lean();
  const current = vaultKeyVersionOf(user);

  if (supplied === undefined) {
    if (current > 0) {
      // NOT logged, unlike `unreached` below, and the asymmetry is deliberate.
      // This one is reached by an out-of-date but HONEST client on every write it
      // attempts, so logging it would emit a line per keystroke-driven save for
      // as long as that tab stays open; `unreached` cannot be produced by any
      // honest client at all, which is why that one is worth saying out loud.
      // The refusal itself is what tells the user, and it tells them to reload.
      throw new StaleVaultKeyError(current, 'unnamed');
    }
    return current;
  }

  if (supplied > current) {
    logger.warn('A write claimed a vault key version this account has never reached', {
      userId,
      claimed: supplied,
      current,
    });
    throw new StaleVaultKeyError(current, 'unreached');
  }

  if (supplied !== current) {
    throw new StaleVaultKeyError(current, 'rotated');
  }

  return current;
}

/**
 * The `vaultKeyVersion` predicate a guarded write puts in its OWN filter, so the
 * check {@link assertVaultKeyVersion} made cannot be undone by a rotation that
 * commits in between.
 *
 * ## Why this is a function and not the number
 *
 * `User.vaultKeyVersion` is `default: 0` on the schema, so every account created
 * through Mongoose has a 0 written for it — but there is no backfill migration
 * (see the field's own comment in `models/User.ts`), so an account created
 * before the column existed has NO value at all. Reading that is safe:
 * {@link vaultKeyVersionOf} maps it to 0, and `$inc` treats it as 0, which is
 * why the model comment can say a legacy account is indistinguishable from one
 * that has never rotated.
 *
 * As a WRITE FILTER it stops being indistinguishable, because MongoDB equality
 * on `0` does not match a missing field. Measured against a real mongod, on a
 * row whose column was removed with `$unset`:
 *
 * ```
 * { vaultKeyVersion: 0 }               matchedCount 0   <-- the whole account bricked
 * { vaultKeyVersion: { $in: [0, null] } }  matchedCount 1
 * ```
 *
 * A bare `vaultKeyVersion: resolved` therefore matches nothing on a legacy
 * account, and a caller that reads `matchedCount === 0` as the recoverable 409
 * tells that user to reload and retry — forever, because there is no newer
 * generation for them to rewrap under. On `PUT /user/change-password` that is a
 * master password which can never be changed again.
 *
 * `null` inside `$in` matches a null value AND a missing field, which is the
 * same idiom `buildFolderAwareUpdate` relies on for an unfiled row. It is only
 * needed at generation 0 — every later generation was written by an `$inc`, so
 * the field provably exists — and it must NOT be widened to every generation,
 * because `{ $in: [3, null] }` would match a legacy row as though it were at
 * generation 3.
 */
export function vaultKeyVersionFilter(
  vaultKeyVersion: number,
): number | { $in: (number | null)[] } {
  return vaultKeyVersion === 0 ? { $in: [0, null] } : vaultKeyVersion;
}

/**
 * Answers the recoverable 409 a stale vault-key generation earns.
 *
 * Written directly rather than thrown through `httpErrors`, for the reason
 * {@link StaleVaultKeyError}'s own docblock gives: the client needs the NUMBER,
 * and `@hiprax/errors`'s response envelope is flat and has nowhere to put one.
 * Byte-for-byte the shape `documentController.completeUpload` emits and
 * `swagger.ts` documents for every guarded write.
 *
 * ONE definition rather than one per controller: six handlers across four files
 * answer this refusal, and a second copy is a second place for the envelope to
 * drift from the published document.
 */
export function sendStaleVaultKey(res: Response, error: StaleVaultKeyError): void {
  res.status(409).json({
    success: false,
    message: error.message,
    data: { vaultKeyVersion: error.vaultKeyVersion },
  });
}

/**
 * {@link assertVaultKeyVersion} plus {@link sendStaleVaultKey}: the account's
 * current generation, or `null` once the recoverable 409 has been ANSWERED.
 *
 * ```ts
 * const vaultKeyVersion = await resolveVaultKeyVersion(res, userId, body.vaultKeyVersion);
 * if (vaultKeyVersion === null) return;
 * ```
 *
 * The `null` arm means the response is already written, so the caller must
 * return immediately; continuing would try to send a second answer. The pair is
 * written here rather than as a try/catch at each of the six call sites because
 * copying a catch-and-render block is how one of them ends up rendering a
 * different envelope, and because the refusal has exactly one correct shape.
 *
 * ## Not for use inside a transaction callback
 *
 * A refusal has to ABORT a transaction, and answering plus returning normally
 * would let it COMMIT. A guarded write that runs inside `withTransaction` calls
 * {@link assertVaultKeyVersion} directly, lets the `StaleVaultKeyError` unwind
 * the transaction, and renders it with {@link sendStaleVaultKey} outside —
 * which is what `toolsController.executeImportOperations` does.
 *
 * Forgetting the `null` check is not silent: the write that follows still runs
 * and Express reports the second response. Forgetting the guard ENTIRELY is the
 * failure this returns a value to make visible, and every guarded endpoint pins
 * its refusal in `tests/stale-vault-key-writes.test.ts`.
 */
export async function resolveVaultKeyVersion(
  res: Response,
  userId: string,
  supplied: number | undefined,
): Promise<number | null> {
  try {
    return await assertVaultKeyVersion(userId, supplied);
  } catch (error) {
    if (error instanceof StaleVaultKeyError) {
      sendStaleVaultKey(res, error);
      return null;
    }
    throw error;
  }
}
