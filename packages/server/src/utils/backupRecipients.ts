import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import mongoose, { type ClientSession } from 'mongoose';
import { httpErrors } from '@hiprax/errors';
import { maskEmail, type IBackupRecipient } from '@hvault/shared';
import { User, type IBackupRecipientDoc } from '../models/User.js';
import { BackupLog } from '../models/BackupLog.js';
import { config } from '../config/index.js';
import { derivePurposeKey } from './token.js';
import { isEmailConfigured, sendBackupRecipientConfirmationEmail, tokenLink } from './email.js';
import { claimOutboundMail } from './outboundMailBudget.js';
import { notifySecurityEvent } from './securityNotifications.js';
import { createModuleLogger, errorMessage } from './logger.js';

/**
 * Backup recipients (F-05): the ONE module that decides where a mailed backup may
 * go and that moves a recipient between its states.
 *
 * A mailed backup is the whole vault leaving the server as an attachment. Three
 * rules make the list something the account owner controls, and nothing else:
 *
 *   1. The OWNER approves the list with the master password (`PUT
 *      /backup/recipients`); a session alone cannot change it.
 *   2. Each address other than the account's own verified one CONFIRMS it wants
 *      the backups, through a single-use link bound to (account, address, nonce),
 *      before it receives any. The click proves the RECIPIENT agrees, never the
 *      owner, which is why an address carried over from before these rules waits
 *      for the owner's approval before it is even asked.
 *   3. A password reset, a password change and "log out everywhere" SUSPEND every
 *      third-party address, rotating its nonce so every link already mailed dies,
 *      until the owner approves the list again. Somebody who confirmed their own
 *      address while holding the account keeps nothing once the owner recovers it.
 *
 * The confirmation job, the manual trigger and the scheduler all go through here.
 */

const logger = createModuleLogger('backup-recipients');

/** The JWT `purpose` of a recipient confirmation link, and its signing-key label. */
const RECIPIENT_TOKEN_PURPOSE = 'backup_recipient';
/** How long a confirmation link stays usable. */
const RECIPIENT_TOKEN_TTL = '24h';
/** The application page the link opens; it reads the token from the fragment. */
const CONFIRM_RECIPIENT_PATH = '/backup/confirm-recipient';
/** How many times a list update recomputes after losing its revision check. */
const LIST_UPDATE_ATTEMPTS = 3;
/** How long a mailed link stays usable, in ms: a save does not re-mail an address inside it. */
const RECIPIENT_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
/**
 * How many FAILED sends of one entry's confirmation are made in all (the first
 * attempt, usually inline in the list update, then retries by the hourly step)
 * before it stops: each one spends a message of the account's daily budget, and a
 * relay that refuses one address would otherwise drain the budget every hour and
 * starve the backups. Saving the list again starts the count over.
 */
const MAX_CONFIRMATION_ATTEMPTS = 3;
const NOTICED_PATH = 'settings.backup.undeliverableNoticedAt';

const RECIPIENTS_PATH = 'settings.backup.backupRecipients';
const REVISION_PATH = 'settings.backup.recipientsRevision';

interface AccountForRecipients {
  email: string;
  emailVerified?: boolean | undefined;
  settings?: { backup?: { backupRecipients?: IBackupRecipientDoc[] | undefined } | undefined };
}

/** An account's stored recipient list; absent (never configured) reads as empty. */
function recipientListOf(account: {
  settings: { backup: { backupRecipients?: IBackupRecipientDoc[] | undefined } };
}): IBackupRecipientDoc[] {
  return account.settings.backup.backupRecipients ?? [];
}

/** A fresh confirmation nonce: 32 random bytes, hex. */
function newNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * The addresses a backup of this account may be mailed to, now.
 *
 * - No list at all, or an empty one: the account's own address, when it is
 *   verified. That has always been where a backup goes when the owner named no
 *   one, and it reroutes nothing.
 * - A list: its CONFIRMED entries, and only those. When none is confirmed the
 *   answer is empty, never the account address: the owner chose to send the
 *   backup elsewhere, and quietly sending it somewhere else instead is not a
 *   decision this code may take. The caller records the run and tells the owner.
 */
export function confirmedRecipientsFor(account: AccountForRecipients): string[] {
  const backup = account.settings?.backup;
  const list = backup?.backupRecipients;
  if (list === undefined) {
    // A document migration v4 has not reached yet (a worker serving while another
    // one runs the migration): an old plain list is a list nobody on has
    // confirmed, never "no list at all".
    const legacy = (backup as { backupEmails?: unknown } | undefined)?.backupEmails;
    if (Array.isArray(legacy) && legacy.length > 0) return [];
  }
  if (list === undefined || list.length === 0) {
    return account.emailVerified === true ? [account.email] : [];
  }
  return list.filter((entry) => entry.state === 'confirmed').map((entry) => entry.email);
}

/**
 * The recipient list as the API reports it: built field by field, so no read
 * that happens to carry an entry's nonce can put it on the wire.
 */
export function publicRecipients(
  list: readonly IBackupRecipientDoc[] | undefined,
): IBackupRecipient[] {
  return (list ?? []).map((entry) => ({
    email: entry.email,
    state: entry.state,
    confirmedAt: entry.confirmedAt ? entry.confirmedAt.toISOString() : null,
    approved: entry.approvedAt !== null && entry.approvedAt !== undefined,
  }));
}

/**
 * A stored backup-settings subdocument as a REPLY carries it (`PUT /backup/settings`
 * and `PUT /user/settings` answer with the stored subdocument): every field it held
 * before the recipients moved, the recipient list built field by field (never a
 * nonce), the revision counter left out, and the retired `backupEmails` always
 * empty so an older client reading it finds a list and no address. The two pieces
 * of bookkeeping (the revision counter, the notice episode) are left out.
 */
export function publicBackupSettings<
  T extends {
    backupRecipients?: IBackupRecipientDoc[] | undefined;
    recipientsRevision?: number | undefined;
    undeliverableNoticedAt?: Date | null | undefined;
  },
>(
  backup: T,
): Omit<T, 'backupRecipients' | 'recipientsRevision' | 'undeliverableNoticedAt'> & {
  backupEmails: string[];
  backupRecipients: IBackupRecipient[];
} {
  const {
    backupRecipients,
    recipientsRevision: _revision,
    undeliverableNoticedAt: _noticed,
    ...rest
  } = backup;
  return { ...rest, backupEmails: [], backupRecipients: publicRecipients(backupRecipients) };
}

/** What an owner's list update changed, for the response and the audit row. */
export interface RecipientListUpdate {
  recipients: IBackupRecipientDoc[];
  added: string[];
  removed: string[];
  /** Addresses suspended after confirming that this approval confirmed again. */
  reinstated: string[];
}

/** The master password changed after the proof was checked (or the account is gone). */
function staleProof(): Error {
  return httpErrors.unauthorized(
    'Your master password changed while the recipients were being saved. Sign in again and retry.',
  );
}

/**
 * Stores the owner's approved list. The caller has ALREADY checked the
 * master-password proof.
 *
 * Every address is (re)approved now. The account's own verified address is
 * confirmed at once. An address that is already confirmed stays confirmed, nonce
 * and all (nothing about it changed); one suspended after confirming is confirmed
 * again, with a fresh nonce; one already approved and waiting on a link that is
 * still owed or still valid is left as it is. Every other one, new, suspended
 * before it ever confirmed, carried over by migration v4, or waiting on a link
 * that has expired, becomes pending with a fresh nonce and a confirmation owed.
 *
 * Read, compute, then write only while `recipientsRevision` is unchanged, so a
 * confirmation, a suspension or the confirmation job that lands in between is
 * never overwritten by a list computed from what came before it; a lost race
 * recomputes, and a third loss is a 409. Both the read and the write are also
 * conditioned on `provenAuthHash`, the stored credential the caller checked the
 * proof against: once a password reset or change has replaced it, this answers 401
 * instead of recomputing, so the recovery's suspension stands.
 */
export async function applyRecipientList(
  userId: string,
  emails: readonly string[],
  provenAuthHash: string,
  now: Date = new Date(),
): Promise<RecipientListUpdate> {
  const wanted = [...new Set(emails.map((email) => email.trim().toLowerCase()))];
  for (let attempt = 0; attempt < LIST_UPDATE_ATTEMPTS; attempt += 1) {
    // The whole document plus the nonces: an inclusive projection naming the list
    // AND `+…nonce` beneath it is a path collision the server refuses. Read, and
    // later written, ONLY while the stored credential is still the one the proof
    // was checked against: a password reset or change that lands in between
    // suspends the list, and a proof of the OLD password must never be what undoes
    // that suspension.
    const account = await User.findOne({ _id: userId, authHash: provenAuthHash })
      .select(`+${RECIPIENTS_PATH}.nonce`)
      .read('primary')
      .lean();
    if (!account) throw staleProof();
    const current = recipientListOf(account);
    const revision = account.settings.backup.recipientsRevision;

    const next: IBackupRecipientDoc[] = wanted.map((email) => {
      const existing = current.find((entry) => entry.email === email);
      if (existing?.state === 'confirmed') return { ...existing, approvedAt: now };
      // SUSPENDED after having confirmed: the owner approving it again with the
      // master password restores exactly what the suspension withdrew. The
      // address's own consent was never in question, and its nonce still rotates,
      // so every link mailed before the suspension stays dead.
      if (existing?.state === 'suspended' && existing.confirmedAt) {
        return {
          ...existing,
          state: 'confirmed',
          approvedAt: now,
          confirmationDue: false,
          confirmationSentAt: null,
          confirmationAttempts: 0,
          nonce: newNonce(),
        };
      }
      // Already approved and waiting: its link is still owed or still valid, so a
      // save leaves it alone rather than killing the link in the recipient's inbox
      // and mailing another (a way to mail one address again and again).
      if (
        existing?.state === 'pending' &&
        existing.approvedAt &&
        (existing.confirmationDue === true ||
          (existing.confirmationSentAt &&
            now.getTime() - existing.confirmationSentAt.getTime() < RECIPIENT_TOKEN_TTL_MS))
      ) {
        return existing;
      }
      if (email === account.email && account.emailVerified) {
        return {
          email,
          state: 'confirmed',
          confirmedAt: now,
          approvedAt: now,
          confirmationDue: false,
          confirmationSentAt: null,
          nonce: newNonce(),
        };
      }
      return {
        email,
        state: 'pending',
        confirmedAt: null,
        approvedAt: now,
        confirmationDue: true,
        confirmationSentAt: null,
        confirmationAttempts: 0,
        nonce: newNonce(),
      };
    });

    const written = await User.updateOne(
      { _id: userId, authHash: provenAuthHash, [REVISION_PATH]: revision ?? null },
      // A saved list starts a new episode for the "backup not sent" notice.
      { $set: { [RECIPIENTS_PATH]: next, [NOTICED_PATH]: null }, $inc: { [REVISION_PATH]: 1 } },
    );
    if (written.matchedCount === 1) {
      return {
        recipients: next,
        added: wanted.filter((email) => !current.some((entry) => entry.email === email)),
        removed: current.map((entry) => entry.email).filter((email) => !wanted.includes(email)),
        reinstated: current
          .filter((entry) => entry.state === 'suspended' && entry.confirmedAt)
          .map((entry) => entry.email)
          .filter((email) => wanted.includes(email)),
      };
    }
  }
  throw httpErrors.conflict(
    'The backup recipients changed while this update was being saved. Reload and try again.',
  );
}

/**
 * Suspends every recipient other than the account's own address: `suspended`,
 * no longer approved, no confirmation owed, and a FRESH nonce each, so every link
 * mailed before this moment is refused from now on. The account's own entry is
 * left as it is.
 *
 * ONE conditional update-pipeline write (it compares each entry with the
 * account's own `email` field, which a plain update cannot), taken only when there
 * is something to suspend, and it bumps `recipientsRevision` so a list update
 * computed before it cannot land after it. Pass `session` from inside a
 * transaction. Returns how many entries were suspended.
 */
export async function suspendThirdPartyRecipients(
  userId: string | mongoose.Types.ObjectId,
  session?: ClientSession,
): Promise<number> {
  const suspendable = {
    $filter: {
      input: { $ifNull: [`$${RECIPIENTS_PATH}`, []] },
      as: 'r',
      cond: { $and: [{ $ne: ['$$r.email', '$email'] }, { $ne: ['$$r.state', 'suspended'] }] },
    },
  };
  // One random base per call, the entry's position appended: every rotated entry
  // gets its own value, none of which any mailed link carries.
  const base = newNonce();
  const before = await User.findOneAndUpdate(
    { _id: userId, $expr: { $gt: [{ $size: suspendable }, 0] } },
    [
      {
        $set: {
          [RECIPIENTS_PATH]: {
            $map: {
              input: { $range: [0, { $size: `$${RECIPIENTS_PATH}` }] },
              as: 'i',
              in: {
                $let: {
                  vars: { r: { $arrayElemAt: [`$${RECIPIENTS_PATH}`, '$$i'] } },
                  in: {
                    $cond: [
                      {
                        $or: [
                          { $eq: ['$$r.email', '$email'] },
                          { $eq: ['$$r.state', 'suspended'] },
                        ],
                      },
                      '$$r',
                      {
                        $mergeObjects: [
                          '$$r',
                          {
                            state: 'suspended',
                            approvedAt: null,
                            confirmationDue: false,
                            confirmationSentAt: null,
                            confirmationAttempts: 0,
                            nonce: { $concat: [base, '.', { $toString: '$$i' }] },
                          },
                        ],
                      },
                    ],
                  },
                },
              },
            },
          },
          [REVISION_PATH]: { $add: [{ $ifNull: [`$${REVISION_PATH}`, 0] }, 1] },
          [NOTICED_PATH]: null,
        },
      },
    ],
    {
      updatePipeline: true,
      returnDocument: 'before',
      projection: { email: 1, [`${RECIPIENTS_PATH}.email`]: 1, [`${RECIPIENTS_PATH}.state`]: 1 },
      ...(session ? { session } : {}),
    },
  ).lean();
  if (!before) return 0;
  return recipientListOf(before).filter(
    (entry) => entry.email !== before.email && entry.state !== 'suspended',
  ).length;
}

interface RecipientTokenPayload {
  userId: string;
  purpose: string;
  email: string;
  nonce: string;
}

function recipientTokenKey(): string {
  return derivePurposeKey(config.JWT_REFRESH_SECRET, RECIPIENT_TOKEN_PURPOSE);
}

/** The signed confirmation token for one entry, bound to its CURRENT nonce. */
function signRecipientToken(userId: string, email: string, nonce: string): string {
  return jwt.sign(
    { userId, purpose: RECIPIENT_TOKEN_PURPOSE, email, nonce } satisfies RecipientTokenPayload,
    recipientTokenKey(),
    { algorithm: 'HS256', expiresIn: RECIPIENT_TOKEN_TTL },
  );
}

/** A confirmation that took: which account's list, and which address. */
export interface ConfirmedRecipient {
  userId: string;
  email: string;
}

/**
 * Consumes a confirmation token. Needs no session: the recipient usually has no
 * account here.
 *
 * ONE conditional write: the entry named by the token's (account, address,
 * nonce) must still be `pending` and owner-approved, on an account that is not
 * being erased; it becomes `confirmed` and its nonce rotates, so the same link is
 * refused the second time. Anything else (a bad signature, another purpose, a
 * spent or superseded link, another address, a suspended or removed entry) is
 * `null`, and the caller answers every one of them the same way.
 */
export async function confirmRecipientToken(
  token: string,
  now: Date = new Date(),
): Promise<ConfirmedRecipient | null> {
  let payload: Partial<RecipientTokenPayload>;
  try {
    payload = jwt.verify(token, recipientTokenKey(), {
      algorithms: ['HS256'],
    }) as Partial<RecipientTokenPayload>;
  } catch {
    return null;
  }
  const { userId, purpose, email, nonce } = payload;
  if (
    purpose !== RECIPIENT_TOKEN_PURPOSE ||
    typeof userId !== 'string' ||
    !mongoose.isValidObjectId(userId) ||
    typeof email !== 'string' ||
    typeof nonce !== 'string' ||
    nonce.length === 0
  ) {
    return null;
  }
  const result = await User.updateOne(
    {
      _id: userId,
      deletionPending: { $ne: true },
      [RECIPIENTS_PATH]: {
        $elemMatch: { email, nonce, state: 'pending', approvedAt: { $ne: null } },
      },
    },
    {
      $set: {
        [`${RECIPIENTS_PATH}.$.state`]: 'confirmed',
        [`${RECIPIENTS_PATH}.$.confirmedAt`]: now,
        [`${RECIPIENTS_PATH}.$.confirmationDue`]: false,
        [`${RECIPIENTS_PATH}.$.nonce`]: newNonce(),
        [NOTICED_PATH]: null,
      },
      $inc: { [REVISION_PATH]: 1 },
    },
  );
  return result.matchedCount === 1 ? { userId, email } : null;
}

/** What {@link sendDueConfirmations} did for one account. */
export interface ConfirmationRun {
  sent: number;
  /** Confirmations still owed afterwards (budget spent, relay failed, email off). */
  pending: number;
}

/**
 * Mails every confirmation the account owes, inside its daily budget. The one
 * sender: the list update calls it straight after storing, and the hourly
 * maintenance step calls it for whatever is still owed.
 *
 * Per entry: CLAIM it first (a conditional write that clears `confirmationDue`
 * only if the entry still carries the nonce read and still owes the mail, so two
 * senders never both mail it); then claim one message of the budget; then sign a
 * token with that nonce and send. A refused budget or a failed send hands the
 * entry back (owed again, until a failed send has happened
 * {@link MAX_CONFIRMATION_ATTEMPTS} times) and stops the account's run: the budget
 * is spent for the day, or the relay is refusing, and trying the next address
 * costs the same. Delivery is AT MOST ONCE: a process that dies between the claim
 * and the send leaves the entry claimed and unsent, and the owner re-sends it by
 * saving the list once its link would have expired.
 */
export async function sendDueConfirmations(
  userId: string,
  now: Date = new Date(),
): Promise<ConfirmationRun> {
  // From the primary: this runs right after the list write it follows, and a
  // lagging secondary would answer with the list as it was before it.
  const account = await User.findById(userId)
    .select(`+${RECIPIENTS_PATH}.nonce`)
    .read('primary')
    .lean();
  if (!account) return { sent: 0, pending: 0 };
  const due = recipientListOf(account).filter(
    (entry): entry is IBackupRecipientDoc & { nonce: string } =>
      entry.state === 'pending' && entry.confirmationDue === true && Boolean(entry.nonce),
  );
  if (account.deletionPending === true || !isEmailConfigured()) {
    return { sent: 0, pending: due.length };
  }

  let sent = 0;
  for (const [index, entry] of due.entries()) {
    const nonce = entry.nonce;
    const claimed = await User.updateOne(
      {
        _id: userId,
        [RECIPIENTS_PATH]: {
          $elemMatch: { email: entry.email, nonce, state: 'pending', confirmationDue: true },
        },
      },
      {
        $set: {
          [`${RECIPIENTS_PATH}.$.confirmationDue`]: false,
          [`${RECIPIENTS_PATH}.$.confirmationSentAt`]: now,
        },
        $inc: { [REVISION_PATH]: 1 },
      },
    );
    if (claimed.matchedCount === 0) continue;

    // Owed again, unless `failed` and this was the entry's last allowed attempt.
    const handBack = (failed: boolean) => {
      const attempts = (entry.confirmationAttempts ?? 0) + (failed ? 1 : 0);
      return User.updateOne(
        {
          _id: userId,
          [RECIPIENTS_PATH]: {
            $elemMatch: {
              email: entry.email,
              nonce,
              confirmationDue: false,
              confirmationSentAt: now,
            },
          },
        },
        {
          $set: {
            [`${RECIPIENTS_PATH}.$.confirmationDue`]: attempts < MAX_CONFIRMATION_ATTEMPTS,
            [`${RECIPIENTS_PATH}.$.confirmationSentAt`]: null,
            [`${RECIPIENTS_PATH}.$.confirmationAttempts`]: attempts,
          },
          $inc: { [REVISION_PATH]: 1 },
        },
      );
    };

    if (!(await claimOutboundMail(userId, 1, now))) {
      await handBack(false);
      logger.info('Recipient confirmations deferred: the daily email budget is spent', { userId });
      return { sent, pending: due.length - index };
    }

    const link = tokenLink(CONFIRM_RECIPIENT_PATH, signRecipientToken(userId, entry.email, nonce));
    const result = await sendBackupRecipientConfirmationEmail(
      entry.email,
      link,
      maskEmail(account.email),
    );
    if (!result.success) {
      await handBack(true);
      logger.warn('A recipient confirmation could not be sent; it stays owed', {
        userId,
        recipient: maskEmail(entry.email),
        error: result.message,
      });
      return { sent, pending: due.length - index };
    }
    sent += 1;
  }
  return { sent, pending: 0 };
}

/**
 * How long one run of the maintenance step may spend sending confirmations. Small:
 * it is the last step of a run whose lock lasts 15 minutes and whose first two
 * steps budget 13 of them.
 */
const CONFIRMATION_STEP_BUDGET_MS = 60 * 1000;
/** How many accounts one page of the step reads. */
const CONFIRMATION_PAGE_SIZE = 100;

/**
 * The maintenance step: every account that still owes a recipient a confirmation
 * mail (the partial index on `confirmationDue` holds exactly those), a page at a
 * time by `_id`, until the time budget runs out (at least one account per run).
 * Does nothing when email is not configured: the mails stay owed until it is.
 *
 * Only an OWNER-APPROVED entry is ever owed a mail, so an address carried over by
 * migration v4 is never mailed until the owner approves the list.
 */
export async function sendOwedRecipientConfirmations(
  budgetMs: number = CONFIRMATION_STEP_BUDGET_MS,
): Promise<void> {
  if (!isEmailConfigured()) return;
  const startedAt = Date.now();
  let lastId: mongoose.Types.ObjectId | undefined;
  let accounts = 0;
  let sent = 0;
  for (;;) {
    const page = await User.find({
      [`${RECIPIENTS_PATH}.confirmationDue`]: true,
      deletionPending: { $ne: true },
      ...(lastId === undefined ? {} : { _id: { $gt: lastId } }),
    })
      .select('_id')
      .sort({ _id: 1 })
      // The partial index holds exactly these accounts; a planner that preferred
      // `_id` for the sort would walk every account instead.
      .hint({ [`${RECIPIENTS_PATH}.confirmationDue`]: 1 })
      .limit(CONFIRMATION_PAGE_SIZE)
      .lean();
    if (page.length === 0) break;
    for (const { _id } of page) {
      lastId = _id;
      accounts += 1;
      try {
        sent += (await sendDueConfirmations(_id.toString())).sent;
      } catch (err: unknown) {
        logger.error('Could not send the confirmations an account owes', {
          userId: _id.toString(),
          error: errorMessage(err),
        });
      }
      if (Date.now() - startedAt >= budgetMs) {
        logger.info('Recipient confirmations paused at the time budget', { accounts, sent });
        return;
      }
    }
  }
  if (accounts > 0) logger.info('Recipient confirmations sent', { accounts, sent });
}

/** Why a backup run mailed nothing, as the `backup_failed` audit row names it. */
export type UndeliverableReason = 'no_confirmed_recipient' | 'daily_mail_budget';

const UNDELIVERABLE_TEXT: Record<UndeliverableReason, string> = {
  no_confirmed_recipient: 'No confirmed backup recipient',
  daily_mail_budget:
    'Sending to every confirmed recipient would have gone over the daily backup email limit',
};

/**
 * Records a backup run that mailed nothing, the same way from the manual trigger
 * and from the scheduler: a failed `BackupLog` row naming no recipient, the
 * account's last-backup status, the `backup_failed` audit row (written by the
 * caller's own writer: a request has an address and a user agent, a job has
 * neither), and, when the reason is that no recipient has confirmed, a notice to
 * the owner's own verified address: at most once per episode, inside the daily
 * budget, no attachment (the episode is claimed first, so a notice the budget or
 * the relay refuses is not tried again in that episode). Nothing at all for an
 * account being erased.
 */
export async function recordUndeliverableBackup(
  userId: string,
  reason: UndeliverableReason,
  writeAudit: (metadata: { reason: UndeliverableReason }) => Promise<void>,
  now: Date = new Date(),
): Promise<void> {
  // Re-checked here, fresh: the scheduler works from the account as it read it at the
  // start of the run, and an erasure that began since wins. Nothing is recorded (a
  // log row would outlive the account) and nothing is mailed to the erased address.
  const owner = await User.findById(userId)
    .select('email emailVerified deletionPending')
    .read('primary')
    .lean();
  if (!owner || owner.deletionPending === true) return;
  await BackupLog.create({
    userId,
    status: 'failed',
    errorMessage: UNDELIVERABLE_TEXT[reason],
    sentTo: [],
    timestamp: now,
  });
  await User.updateOne(
    { _id: userId },
    { $set: { 'settings.backup.lastBackupAt': now, 'settings.backup.lastBackupStatus': 'failed' } },
  );
  await writeAudit({ reason });
  if (reason !== 'no_confirmed_recipient' || !isEmailConfigured()) return;

  if (!owner.emailVerified) return;
  // Once per episode: an account whose recipients never confirm would otherwise be
  // told again every scheduled run, for ever. Saving the list, a confirmation, a
  // suspension or a delivered backup starts a new episode.
  const claimed = await User.updateOne(
    { _id: userId, [NOTICED_PATH]: null },
    { $set: { [NOTICED_PATH]: now } },
  );
  if (claimed.matchedCount === 0) return;
  // Through the ONE security-notice helper (F-26), which decides whether to send
  // (the owner may have turned these off) BEFORE the daily backup budget is
  // claimed, so a unit is spent only on a notice that is about to leave.
  const outcome = await notifySecurityEvent(
    userId,
    'backup_not_sent',
    {},
    {
      beforeSend: async () => {
        if (await claimOutboundMail(userId, 1, now)) return true;
        logger.info('The backup-not-sent notice was skipped: the daily email budget is spent', {
          userId,
        });
        return false;
      },
    },
  );
  if (outcome === 'failed') {
    logger.warn('The backup-not-sent notice could not be sent', { userId });
  }
}

/**
 * A backup was delivered to at least one recipient: the next undeliverable run is
 * a new episode, and the owner is told about it again.
 */
export async function noteBackupDelivered(userId: string): Promise<void> {
  await User.updateOne(
    { _id: userId, [NOTICED_PATH]: { $ne: null } },
    { $set: { [NOTICED_PATH]: null } },
  );
}

/**
 * Who may receive a backup of this account at the moment of sending: the same rule
 * as {@link confirmedRecipientsFor}, read FRESH from the primary. The trigger and
 * the scheduler read the account before the backup is built and, for the
 * scheduler, before a slot is free; a reset, a password change or "log out
 * everywhere" that suspends a recipient in that time must stop the mail to it, so
 * the list the budget is claimed for and the mail is sent to comes from here.
 */
export async function currentRecipientsFor(userId: string): Promise<string[]> {
  const account = await User.findById(userId)
    .select(`email emailVerified settings.backup`)
    .read('primary')
    .lean();
  return account ? confirmedRecipientsFor(account) : [];
}
