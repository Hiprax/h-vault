import { createModuleLogger, errorMessage } from '../utils/logger.js';
import type { ClientSession, Types } from 'mongoose';
import {
  AUDIT_COALESCE_WINDOW_MS,
  MAX_ACTIVITY_AUDIT_ROWS_PER_USER,
  MAX_STRANGER_AUDIT_ROWS_PER_USER,
  STRANGER_WRITABLE_AUDIT_ACTIONS,
  type AuditAction,
} from '@hvault/shared';
import { AuditLog } from '../models/AuditLog.js';
import { MAX_USER_AGENT_LENGTH } from '../utils/controllerHelpers.js';

const logger = createModuleLogger('audit-service');

// ── The two classes ─────────────────────────────────────────────────────────

/**
 * What an audit row records, and so what may ever happen to it after it is
 * written.
 *
 * - `security`: what happened to the account's identity and its protections —
 *   sign-ins and sign-outs, passwords, the second factor, sessions and trusted
 *   devices, exports and imports, backups set up, changed, downloaded or
 *   restored, settings, recovery, deletion. Never coalesced and never trimmed:
 *   each row is an event the owner may need to find a year later. The one
 *   exception is the three {@link STRANGER_WRITABLE_AUDIT_ACTIONS}, which anyone
 *   who knows the address can write, so they are coalesced while the password is
 *   locked (`recordLockedAttempt`) and capped at `MAX_STRANGER_AUDIT_ROWS_PER_USER`.
 *   Every other security row takes a credential or a session to write and is
 *   bounded by its route's limiter and the retention TTL.
 * - `activity`: what the account did to its own items, folders, documents and
 *   backups. A session can write these as fast as its write limiters allow, so
 *   they are capped per account at `MAX_ACTIVITY_AUDIT_ROWS_PER_USER`, oldest
 *   first, and a short allowlist of them is coalesced (see {@link COALESCE_TARGET}).
 *   Flooding them can push out only older activity, never a security row.
 */
export type AuditClass = 'security' | 'activity';

/**
 * Every action's class. TOTAL on purpose: an action added to `AUDIT_ACTIONS`
 * without a class here is a type error, so no new action can land in the log
 * without somebody deciding whether it may ever be trimmed.
 */
export const AUDIT_ACTION_CLASS = {
  login: 'security',
  login_failed: 'security',
  logout: 'security',
  password_change: 'security',
  password_verification_failed: 'security',
  '2fa_enable': 'security',
  '2fa_disable': 'security',
  item_create: 'activity',
  item_update: 'activity',
  item_delete: 'activity',
  item_restore: 'activity',
  export: 'security',
  export_plaintext: 'security',
  import: 'security',
  session_revoke: 'security',
  vault_lock: 'activity',
  vault_unlock: 'activity',
  backup_triggered: 'activity',
  backup_sent: 'activity',
  backup_failed: 'activity',
  backup_restored: 'security',
  backup_password_changed: 'security',
  folder_create: 'activity',
  folder_update: 'activity',
  folder_delete: 'activity',
  folder_reorder: 'activity',
  account_unlock: 'security',
  account_delete: 'security',
  backup_setup: 'security',
  backup_settings_update: 'security',
  backup_download: 'security',
  trash_auto_purge: 'activity',
  '2fa_backup_codes_regenerated': 'security',
  '2fa_backup_code_used': 'security',
  rotation_recovery: 'security',
  deletion_cleanup: 'security',
  unverified_account_reaped: 'security',
  // Security, not activity: settings include how soon the vault locks itself and
  // how soon a copied secret leaves the clipboard, so a session that lowered them
  // must not be able to push the record of it out by flooding item edits.
  settings_update: 'security',
  email_verified: 'security',
  registration: 'security',
  trusted_device_grant: 'security',
  trusted_device_revoke: 'security',
  trusted_device_rejected: 'security',
  // Written once per stolen family, and only by a client holding one of its spent
  // tokens: never trimmed, never coalesced.
  token_reuse_detected: 'security',
  device_proof_revoked: 'security',
  document_create: 'activity',
  document_update: 'activity',
  document_delete: 'activity',
  document_restore: 'activity',
  document_purge: 'activity',
  invitation_create: 'security',
  // Where mailed backups go: each changes where the whole vault leaves the server.
  backup_recipients_update: 'security',
  backup_recipient_confirmed: 'security',
  backup_recipients_suspended: 'security',
  // An irreversible bulk deletion behind the master password: never trimmed.
  unreadable_entries_purged: 'security',
} as const satisfies Record<AuditAction, AuditClass>;

/** The actions whose class is `activity`, as a type: what the allowlist may name. */
type ActivityAuditAction = {
  [A in AuditAction]: (typeof AUDIT_ACTION_CLASS)[A] extends 'activity' ? A : never;
}[AuditAction];

/** The activity-class actions, the set the per-account activity cap trims. */
const ACTIVITY_AUDIT_ACTIONS: readonly AuditAction[] = (
  Object.keys(AUDIT_ACTION_CLASS) as AuditAction[]
).filter((action) => AUDIT_ACTION_CLASS[action] === 'activity');

function isStrangerWritable(action: string): boolean {
  return (STRANGER_WRITABLE_AUDIT_ACTIONS as readonly string[]).includes(action);
}

// ── Coalescing ──────────────────────────────────────────────────────────────

type AuditMetadata = Record<string, unknown>;

/**
 * The only actions ever counted into an earlier row, and for each, the TARGET a
 * row is about — or `null` when this row may not be coalesced at all.
 *
 * Only metadata-only activity is here. A change to an item's or a folder's
 * ciphertext (`contentChanged: true`, set by the controller from the fields the
 * update actually carried) is a real change of what the row protects and keeps a
 * row of its own; so does a row written before the marker existed (`undefined`
 * is not `false`). A row whose target this cannot name is never coalesced either.
 * Keyed by {@link ActivityAuditAction}, so naming a security action here is a type
 * error: a security row is never counted into another.
 */
export const COALESCE_TARGET: Readonly<
  Partial<Record<ActivityAuditAction, (metadata: AuditMetadata) => string | null>>
> = {
  item_update: (metadata) =>
    metadata.contentChanged === false && typeof metadata.itemId === 'string'
      ? metadata.itemId
      : null,
  folder_update: (metadata) =>
    metadata.contentChanged === false && typeof metadata.folderId === 'string'
      ? metadata.folderId
      : null,
  folder_reorder: (metadata) => (typeof metadata.folderId === 'string' ? metadata.folderId : null),
};

function coalesceTarget(action: AuditAction, metadata: AuditMetadata | undefined): string | null {
  const target = (
    COALESCE_TARGET as Partial<Record<AuditAction, (m: AuditMetadata) => string | null>>
  )[action];
  return target !== undefined && metadata !== undefined ? target(metadata) : null;
}

/**
 * Counts this event into the account's NEWEST row when that row is the same
 * event by the same actor: the same allowlisted action on the same target, from
 * the same address and user agent, itself coalescible, and no older than
 * {@link AUDIT_COALESCE_WINDOW_MS}. Returns whether it did; `false` means the
 * caller writes a row of its own.
 *
 * Only the newest row, so a coalesced row always stands for one uninterrupted run
 * of identical edits, and two actors interleaving on one item — which is exactly
 * what the owner of a shared or hijacked account needs to see — never share a row,
 * as far as an actor can be told apart: by address and user agent (two browsers
 * behind one address sending an identical user-agent string are one actor here).
 * The row takes the LATEST edit's time and metadata (a locked-attempt row, by
 * contrast, keeps the first attempt's); `$max` keeps a slower concurrent request
 * from moving the time backwards, and `$inc` counts both. The write re-states the
 * actor and the window in its own filter, so a row that aged out or was replaced
 * between the read and the write is never counted into.
 *
 * The newest row is read from the primary, sorted on `timestamp` alone: every
 * generation of the account's index serves that (a worker may serve while
 * another is still building migration v2's indexes), and a tie within one
 * millisecond can only make an edit a row of its own, never merge two actors.
 */
async function coalesceIntoNewest(
  userId: string,
  action: AuditAction,
  metadata: AuditMetadata | undefined,
  ipAddress: string,
  userAgent: string,
  now: Date,
  session: ClientSession | undefined,
): Promise<boolean> {
  if (metadata === undefined) return false;
  const target = coalesceTarget(action, metadata);
  if (target === null) return false;
  const windowStart = new Date(now.getTime() - AUDIT_COALESCE_WINDOW_MS);

  const newest = await AuditLog.findOne({ userId })
    .sort({ timestamp: -1 })
    .select('action metadata ipAddress userAgent timestamp')
    .read('primary')
    .session(session ?? null)
    .lean();
  if (
    newest?.action !== action ||
    newest.ipAddress !== ipAddress ||
    newest.userAgent !== userAgent ||
    newest.timestamp.getTime() < windowStart.getTime() ||
    coalesceTarget(action, newest.metadata) !== target
  ) {
    return false;
  }

  const result = await AuditLog.updateOne(
    { _id: newest._id, userId, action, ipAddress, userAgent, timestamp: { $gte: windowStart } },
    { $inc: { count: 1 }, $max: { timestamp: now }, $set: { metadata } },
  ).session(session ?? null);
  return result.matchedCount === 1;
}

/**
 * {@link coalesceIntoNewest}, where a failure means "write a row of its own":
 * counting into an earlier row is an economy, and failing at it must never cost
 * the event its record.
 */
async function tryCoalesce(
  userId: string,
  action: AuditAction,
  metadata: AuditMetadata | undefined,
  ipAddress: string,
  userAgent: string,
  now: Date,
  options: CreateAuditLogOptions,
): Promise<boolean> {
  try {
    return await coalesceIntoNewest(
      userId,
      action,
      metadata,
      ipAddress,
      userAgent,
      now,
      options.session,
    );
  } catch (err: unknown) {
    logger.warn('Could not coalesce an audit row; writing it as a row of its own', {
      userId,
      action,
      error: errorMessage(err),
    });
    return false;
  }
}

// ── Writing a row ───────────────────────────────────────────────────────────

/**
 * Optional persistence options for {@link createAuditLog}.
 *
 * When `session` is provided, the audit-log document is written inside the
 * given MongoDB transaction so the entry commits or aborts together with the
 * surrounding writes. Callers that emit an audit event from within
 * `withTransaction` MUST forward the session, otherwise the audit row
 * persists even when the transaction aborts and the audit-log invariant
 * ("logged events reflect committed state") is broken.
 */
export interface CreateAuditLogOptions {
  session?: ClientSession | undefined;
}

/**
 * Persists an audit-log entry: THE writer every request path goes through, so
 * the class rules above hold for all of them. An allowlisted metadata-only edit
 * repeated by the same actor is counted into its previous row
 * ({@link coalesceIntoNewest}); every other event is a row of its own, and each
 * inserted row counts toward its account's sampled trim ({@link noteAuditInsert}).
 *
 * `userAgent` is truncated to {@link MAX_USER_AGENT_LENGTH} as a final
 * persistence-layer safety net. Callers SHOULD already pass a pre-truncated
 * value via {@link getRequestContext} in `controllerHelpers.ts` — that helper
 * normalises the IP/UA at the request boundary so this function is never the
 * sole guard against oversized values.
 *
 * Never throws: an audit write must not break the request it records.
 *
 * @param userId     The account the event belongs to; `null` for a system row.
 * @param action     What happened. Its class decides what may later happen to it.
 * @param metadata   Optional key-value data that provides additional context.
 * @param ipAddress  The client's IP address.
 * @param userAgent  The client's User-Agent header value.
 * @param options    Optional persistence options. Pass `{ session }` when
 *                   emitting from inside a MongoDB transaction so the audit
 *                   entry commits or aborts together with the transaction.
 */
export async function createAuditLog(
  userId: string | Types.ObjectId | null,
  action: AuditAction,
  metadata: AuditMetadata | undefined,
  ipAddress: string,
  userAgent: string,
  options: CreateAuditLogOptions = {},
): Promise<void> {
  const account = userId === null ? null : String(userId);
  try {
    const truncatedUserAgent =
      userAgent.length > MAX_USER_AGENT_LENGTH
        ? userAgent.slice(0, MAX_USER_AGENT_LENGTH)
        : userAgent;
    const now = new Date();

    if (
      account !== null &&
      (await tryCoalesce(account, action, metadata, ipAddress, truncatedUserAgent, now, options))
    ) {
      logger.debug('Audit log coalesced', { userId: account, action });
      return;
    }

    const doc = {
      userId: account,
      action,
      ipAddress,
      userAgent: truncatedUserAgent,
      timestamp: now,
      ...(metadata !== undefined ? { metadata } : {}),
    };

    if (options.session) {
      await AuditLog.create([doc], { session: options.session });
    } else {
      await AuditLog.create(doc);
    }

    logger.debug('Audit log created', { userId: account, action });

    if (account !== null) {
      await noteAuditInsert(account, action);
    }
  } catch (err: unknown) {
    // Audit logging should never break the main request flow, so we catch
    // and log any persistence errors rather than re-throwing.
    logger.error('Failed to persist audit log', {
      userId: account,
      action,
      error: errorMessage(err),
    });
  }
}

/** One row a background job writes about an account (or about the system). */
export interface JobAuditEntry {
  userId: string | null;
  action: AuditAction;
  metadata: AuditMetadata;
  ipAddress: string;
  userAgent: string;
}

/**
 * The writer for background jobs, which record one row per account per batch.
 * The rows go in as ONE `insertMany`, as the jobs always wrote them, and each
 * then counts toward its account's sampled trim exactly as a request's row does
 * — a job is not a way around the cap.
 *
 * Unlike {@link createAuditLog} this THROWS when the insert fails. The jobs rely
 * on that: a purge whose record could not be written stops, rather than going on
 * destroying rows nobody will ever see a trace of. The trims that follow never
 * throw.
 */
export async function recordJobAuditEntries(entries: readonly JobAuditEntry[]): Promise<void> {
  if (entries.length === 0) return;
  const timestamp = new Date();
  await AuditLog.insertMany(entries.map((entry) => ({ ...entry, timestamp })));
  for (const entry of entries) {
    if (entry.userId !== null) {
      await noteAuditInsert(entry.userId, entry.action);
    }
  }
}

// ── Keeping each class to its cap ───────────────────────────────────────────

/** Rows per delete when a trim removes a backlog. */
const TRIM_DELETE_BATCH = 5_000;

/**
 * Deletes the account's rows of `actions` older than the `max`-th newest, with
 * `_id` as the tie-break so exactly the newest `max` survive even when many share
 * a timestamp. Rows of any other action are never read or touched. Returns how
 * many it removed.
 *
 * The excess goes in batches of {@link TRIM_DELETE_BATCH}, oldest first, each a
 * delete of named ids: an account far over its cap (the first run on a deployment
 * that has kept everything until now) costs many bounded commands rather than one
 * that could outlast the driver's socket timeout. `maxBatches` bounds how many of
 * them one call may issue: a trim run inside a request removes at most one batch
 * and leaves a larger backlog to the hourly job.
 */
async function keepNewest(
  userId: string,
  actions: readonly AuditAction[],
  max: number,
  maxBatches: number = Number.POSITIVE_INFINITY,
): Promise<number> {
  const filter = { userId, action: { $in: [...actions] } };
  const [boundary] = await AuditLog.find(filter)
    .sort({ timestamp: -1, _id: -1 })
    .skip(max - 1)
    .limit(1)
    .select('timestamp _id')
    .lean();
  if (!boundary) return 0;
  const older = {
    ...filter,
    $or: [
      { timestamp: { $lt: boundary.timestamp } },
      { timestamp: boundary.timestamp, _id: { $lt: boundary._id } },
    ],
  };
  let removed = 0;
  for (let batches = 0; batches < maxBatches; batches += 1) {
    const batch = await AuditLog.find(older)
      .sort({ timestamp: 1, _id: 1 })
      .limit(TRIM_DELETE_BATCH)
      .select('_id')
      .lean();
    if (batch.length === 0) break;
    const { deletedCount } = await AuditLog.deleteMany({
      userId,
      _id: { $in: batch.map((row) => row._id) },
    }).hint({ _id: 1 });
    removed += deletedCount;
    // A batch that removed nothing was removed by someone else in between; the
    // next read would return rows past it, but a batch that CANNOT be removed
    // would be read again for ever, so no progress ends the trim.
    if (deletedCount === 0 || batch.length < TRIM_DELETE_BATCH) break;
  }
  return removed;
}

/**
 * Keeps an account's stranger-writable rows (`STRANGER_WRITABLE_AUDIT_ACTIONS`:
 * failed sign-ins, rejected trusted-device cookies, link unlocks) to the newest
 * {@link MAX_STRANGER_AUDIT_ROWS_PER_USER}, oldest first. Only those actions are
 * ever removed, so a stranger can neither grow the log without bound nor push the
 * owner's own history out of it.
 */
export async function trimStrangerAuditRows(userId: string): Promise<number> {
  return keepNewest(userId, STRANGER_WRITABLE_AUDIT_ACTIONS, MAX_STRANGER_AUDIT_ROWS_PER_USER);
}

/**
 * Keeps an account's activity-class rows to the newest
 * {@link MAX_ACTIVITY_AUDIT_ROWS_PER_USER}, oldest first. Security rows are never
 * read or touched.
 */
export async function trimActivityAuditRows(userId: string): Promise<number> {
  return keepNewest(userId, ACTIVITY_AUDIT_ACTIONS, MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
}

/** How many inserts of one capped set, for one account, trigger one trim. */
export const AUDIT_TRIM_EVERY = 100;

/**
 * How many accounts each process-local counter below tracks at once. Past it, an
 * account that is not already tracked is trimmed AT ONCE instead of being
 * remembered: an attacker spraying many accounts must not be able to keep a
 * victim's counter from ever reaching {@link AUDIT_TRIM_EVERY}.
 */
export const AUDIT_TRIM_TRACKED_ACCOUNTS = 10_000;

interface TrimSampler {
  note(userId: string): Promise<void>;
  reset(): void;
}

/**
 * Counts inserts per account and runs `trim` on every {@link AUDIT_TRIM_EVERY}th.
 * The count is per process, so across a cluster (or a restart) an account can sit
 * at most one interval per process above its cap until the next sampled trim or
 * the hourly maintenance job brings it back: the bound holds, only its slack is
 * per process. Never throws; a failed trim is logged and retried by the next
 * interval or the job.
 */
function createTrimSampler(
  label: string,
  trim: (userId: string) => Promise<number>,
  whenFull: 'trim-at-once' | 'forget-oldest',
): TrimSampler {
  const insertsSinceTrim = new Map<string, number>();
  return {
    async note(userId: string): Promise<void> {
      const seen = insertsSinceTrim.get(userId);
      if (
        seen === undefined &&
        insertsSinceTrim.size >= AUDIT_TRIM_TRACKED_ACCOUNTS &&
        whenFull === 'forget-oldest'
      ) {
        // The least recently STARTED count is dropped (a Map iterates in
        // insertion order). That account loses at most one interval's progress
        // toward its next sampled trim, and the hourly job bounds it regardless.
        const oldest = insertsSinceTrim.keys().next();
        if (oldest.done !== true) insertsSinceTrim.delete(oldest.value);
      }
      let due: boolean;
      if (seen === undefined && insertsSinceTrim.size >= AUDIT_TRIM_TRACKED_ACCOUNTS) {
        due = true;
      } else {
        const next = (seen ?? 0) + 1;
        due = next >= AUDIT_TRIM_EVERY;
        if (due) {
          insertsSinceTrim.delete(userId);
        } else {
          insertsSinceTrim.set(userId, next);
        }
      }
      if (!due) return;
      try {
        await trim(userId);
      } catch (err: unknown) {
        logger.error(`Failed to trim ${label} audit rows`, {
          userId,
          error: errorMessage(err),
        });
      }
    },
    reset(): void {
      insertsSinceTrim.clear();
    },
  };
}

/**
 * Full, the two samplers part ways. A stranger can spray accounts to keep a
 * victim's count from ever reaching the interval, so an untracked stranger write
 * past the bound trims at once; its cap is small and that trim is cheap. Activity
 * rows are written by the accounts themselves, and on a large instance ten
 * thousand accounts with a few recent edits each is simply normal, so trimming at
 * once there would put a hundred-thousand-row walk on every edit of every account
 * past the bound. The activity sampler forgets its oldest count instead, and the
 * hourly job (`jobs/maintenance.ts`) is what holds the cap.
 */
// A sampled trim runs inside the request that wrote the row, so it removes at
// most ONE batch; the hourly job removes the rest of a backlog.
const strangerSampler = createTrimSampler(
  'stranger-writable',
  (userId) =>
    keepNewest(userId, STRANGER_WRITABLE_AUDIT_ACTIONS, MAX_STRANGER_AUDIT_ROWS_PER_USER, 1),
  'trim-at-once',
);
const activitySampler = createTrimSampler(
  'activity',
  (userId) => keepNewest(userId, ACTIVITY_AUDIT_ACTIONS, MAX_ACTIVITY_AUDIT_ROWS_PER_USER, 1),
  'forget-oldest',
);

/** Counts one stranger-writable insert for `userId`; trims on every hundredth. */
export async function noteStrangerWritableInsert(userId: string): Promise<void> {
  await strangerSampler.note(userId);
}

/** Counts one activity insert for `userId`; trims on every hundredth. */
export async function noteActivityInsert(userId: string): Promise<void> {
  await activitySampler.note(userId);
}

/**
 * Counts one inserted row toward the sampled trim of the set it belongs to: the
 * stranger-writable actions, or the activity class. Every other security row is
 * never trimmed, so it counts toward nothing.
 */
async function noteAuditInsert(userId: string, action: AuditAction): Promise<void> {
  if (isStrangerWritable(action)) {
    await strangerSampler.note(userId);
  } else if (AUDIT_ACTION_CLASS[action] === 'activity') {
    await activitySampler.note(userId);
  }
}

/** Forgets every tracked stranger-writable count. For tests. */
export function resetStrangerAuditTracking(): void {
  strangerSampler.reset();
}

/** Forgets every tracked activity count. For tests. */
export function resetActivityAuditTracking(): void {
  activitySampler.reset();
}

// ── Locked sign-in attempts, coalesced per minute ───────────────────────────

const COALESCE_BUCKET_MS = 60 * 1000;
const LOCKED_ATTEMPT_METADATA = { reason: 'locked' } as const;

function isDuplicateKey(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === 11000;
}

/**
 * The filter that finds a coalesced row by its key, written so its index serves
 * it. `{coalesceKey: 1}` is a PARTIAL index (`$type: 'string'`), and the planner
 * uses a partial index only for a query that states its filter expression: an
 * equality on a string is not taken to imply `$type`, so `{coalesceKey}` alone is
 * a scan of every account's audit log on every locked, unknown-address or
 * mid-deletion sign-in. The `$eq` still seeds the field of an upserted row.
 */
function byCoalesceKey(coalesceKey: string): Record<string, unknown> {
  return { coalesceKey: { $eq: coalesceKey, $type: 'string' } };
}

/**
 * Records ONE unproven sign-in attempt made while the account's password is
 * locked, as `login_failed{reason:'locked'}`, coalesced into one row per account
 * per minute whatever the address or user agent, with `count` holding the
 * attempts. The row is written identically whether the password presented was
 * right or wrong — nothing in it (and nothing in the audit-log API that returns
 * it) may say which, or the log would hand the password oracle the lockout closes
 * to anyone holding a session. The owner learns of a correct password from an
 * unproven device only out of band, never from this row.
 *
 * One upsert on a unique key, so a flood costs one row a minute. The first
 * attempt of a minute that loses an insert race to a concurrent one is retried
 * as an update of the winner's row. Like {@link createAuditLog}, it never throws.
 */
export async function recordLockedAttempt(
  userId: string,
  ipAddress: string,
  userAgent: string,
  now: Date = new Date(),
): Promise<void> {
  const bucket = Math.floor(now.getTime() / COALESCE_BUCKET_MS) * COALESCE_BUCKET_MS;
  const coalesceKey = `${userId}|login_failed|${LOCKED_ATTEMPT_METADATA.reason}|${String(bucket)}`;
  const insertFields = {
    userId,
    action: 'login_failed' as const,
    metadata: { ...LOCKED_ATTEMPT_METADATA },
    ipAddress,
    userAgent: userAgent.slice(0, MAX_USER_AGENT_LENGTH),
    timestamp: now,
  };
  try {
    let inserted: boolean;
    try {
      const result = await AuditLog.updateOne(
        byCoalesceKey(coalesceKey),
        { $inc: { count: 1 }, $setOnInsert: insertFields },
        { upsert: true, setDefaultsOnInsert: false },
      );
      inserted = result.upsertedCount === 1;
    } catch (err: unknown) {
      if (!isDuplicateKey(err)) throw err;
      await AuditLog.updateOne(byCoalesceKey(coalesceKey), { $inc: { count: 1 } });
      inserted = false;
    }
    if (inserted) {
      await noteStrangerWritableInsert(userId);
    }
  } catch (err: unknown) {
    logger.error('Failed to persist a locked sign-in attempt', {
      userId,
      error: errorMessage(err),
    });
  }
}

/**
 * The same awaited round trip {@link recordLockedAttempt} makes, for a sign-in
 * that named no account: an update that can match nothing and never inserts, so
 * an unregistered address costs what a locked one does and writes nothing.
 */
export async function recordNothing(): Promise<void> {
  try {
    await AuditLog.updateOne(byCoalesceKey('|nobody|'), { $inc: { count: 1 } });
  } catch (err: unknown) {
    logger.error('Failed the equalising audit round trip', { error: errorMessage(err) });
  }
}
