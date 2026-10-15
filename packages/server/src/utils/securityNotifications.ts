import crypto from 'node:crypto';
import net from 'node:net';
import type mongoose from 'mongoose';
import {
  MANDATORY_SECURITY_NOTIFICATION_EVENTS,
  SECURITY_NOTIFICATION_INTERVAL_MINUTES,
  maskEmail,
  type SecurityNotificationEvent,
  type SecurityNotificationPreferenceEvent,
} from '@hvault/shared';
import { config } from '../config/index.js';
import { User } from '../models/User.js';
import { escapeHtml, isEmailConfigured, sendEmail } from './email.js';
import { trackJob } from './jobTracker.js';
import { createModuleLogger, errorMessage } from './logger.js';

const logger = createModuleLogger('security-notifications');

const INTERVAL_MS = SECURITY_NOTIFICATION_INTERVAL_MINUTES * 60 * 1000;

/** Why a recipient list lost its third-party entries. */
type SuspensionReason = 'password_reset' | 'password_change' | 'logout_all';

/**
 * What a notice may say beyond its fixed text. Every field is either validated
 * here or reduced to a form that cannot carry anything the request chose: the
 * address only when it IS an IP address, recipient addresses only masked, counts
 * only as integers. Never a token, a link carrying a parameter, a user agent or
 * any other free text from the request.
 */
export interface SecurityEventContext {
  /** The address the event came from; shown only when `net.isIP` accepts it. */
  ip?: string | undefined;
  /** `backup_recipients_changed`: the new list, shown masked. */
  recipients?: readonly string[] | undefined;
  /** `backup_recipients_suspended`: how many were suspended, and by what. */
  count?: number | undefined;
  reason?: SuspensionReason | undefined;
  /** `security_notices_turned_off`: the events the owner stopped being mailed about. */
  events?: readonly SecurityNotificationPreferenceEvent[] | undefined;
  /**
   * `account_deletion_requested` ONLY: the address as the caller read it BEFORE the
   * erasure began. The row is being deleted, so nothing about it can be read (or
   * stamped) by the time this runs.
   */
  snapshot?: { email: string; emailVerified: boolean } | undefined;
}

/**
 * Optional work run after every check has passed and the notice's slot is claimed,
 * and before anything is sent; `false` sends nothing. For a notice that spends a
 * budget of its own (`backup_not_sent` and the daily backup mail budget), so the
 * budget is spent only on a mail that is actually about to leave.
 */
export interface SecurityNoticeOptions {
  beforeSend?: (() => Promise<boolean>) | undefined;
}

export type NotificationOutcome =
  | 'sent'
  | 'not_configured'
  | 'no_account'
  | 'unverified'
  | 'opted_out'
  | 'debounced'
  | 'refused'
  | 'failed';

/** How each event the owner can choose is named in a sentence. */
const PREFERENCE_LABELS: Record<SecurityNotificationPreferenceEvent, string> = {
  locked_sign_in_correct_password: 'your correct master password entered during a lockout',
  password_reset: 'master password resets',
  password_changed: 'master password changes',
  two_factor_enabled: 'two-factor authentication turned on',
  two_factor_disabled: 'two-factor authentication turned off',
  backup_codes_regenerated: 'new two-factor backup codes',
  trusted_device_granted: 'browsers trusted to skip two-factor sign-in',
  device_proof_revoked: 'browsers no longer recognised',
  second_factor_lockout: 'two-factor sign-in locked',
  backup_recipients_changed: 'backup recipient changes',
  backup_recipients_suspended: 'backup recipients suspended',
  token_reuse_detected: 'copied sessions detected',
  backup_not_sent: 'backups not sent',
};

const MANDATORY: readonly SecurityNotificationEvent[] = MANDATORY_SECURITY_NOTIFICATION_EVENTS;

interface Notice {
  subject: string;
  heading: string;
  /** Plain-text paragraphs; escaped when rendered. */
  paragraphs: string[];
}

const SIGNED_IN_REMEDY =
  'change it now from a device where you are already signed in (Settings, Change Password): ' +
  'that signs out every other session.';

const REASON_TEXT: Record<SuspensionReason, string> = {
  password_reset: 'your master password was reset',
  password_change: 'your master password was changed',
  logout_all: 'you signed out everywhere',
};

/**
 * The ONE place a security notice's words live: a closed table, one entry per
 * event, so no call site writes a sentence of its own and nothing the request
 * carried can become one.
 */
function noticeFor(event: SecurityNotificationEvent, context: SecurityEventContext): Notice {
  switch (event) {
    case 'locked_sign_in_correct_password':
      return {
        subject: 'Your H-Vault master password was entered during a lockout',
        heading: 'Your correct master password was entered during a lockout',
        paragraphs: [
          'Sign-in to your account is locked because of repeated failed attempts. During the ' +
            'lockout, a browser that has not signed in to your account before entered your ' +
            'correct master password. The sign-in was refused like every other attempt.',
          'If this was you, nothing is wrong: sign in from a browser you have used before, or ' +
            'use the unlock link emailed when the lockout began.',
          `If it was not you, someone knows your master password: ${SIGNED_IN_REMEDY}`,
        ],
      };
    case 'password_reset':
      return {
        subject: 'Your H-Vault master password was reset',
        heading: 'Your master password was reset',
        paragraphs: [
          'The master password of your account was reset with a link emailed to this address. ' +
            'Everything stored in the vault before the reset can no longer be decrypted.',
          'If this was not you, someone can read this mailbox: secure your email account first, ' +
            'then reset your master password again.',
        ],
      };
    case 'password_changed':
      return {
        subject: 'Your H-Vault master password was changed',
        heading: 'Your master password was changed',
        paragraphs: [
          'The master password of your account was changed from a signed-in session, and every ' +
            'session was signed out.',
          'If this was not you, someone knew your previous master password. Use "Forgot ' +
            'password" on the sign-in page to take the account back; a reset cannot decrypt ' +
            'what is stored in the vault.',
        ],
      };
    case 'two_factor_enabled':
      return {
        subject: 'Two-factor authentication was turned on for your H-Vault account',
        heading: 'Two-factor authentication was turned on',
        paragraphs: [
          'Signing in to your account now also needs a code from your authenticator app.',
          'If this was not you, someone knows your master password: ' + SIGNED_IN_REMEDY,
        ],
      };
    case 'two_factor_disabled':
      return {
        subject: 'Two-factor authentication was turned off for your H-Vault account',
        heading: 'Two-factor authentication was turned off',
        paragraphs: [
          'Signing in to your account no longer needs a code from your authenticator app.',
          'If this was not you, someone knows your master password and had a two-factor code: ' +
            SIGNED_IN_REMEDY +
            ' Then turn two-factor authentication on again.',
        ],
      };
    case 'backup_codes_regenerated':
      return {
        subject: 'New two-factor backup codes were created for your H-Vault account',
        heading: 'New backup codes were created',
        paragraphs: [
          'A new set of two-factor backup codes was created for your account, and the previous ' +
            'codes no longer work.',
          'If this was not you, someone knows your master password: ' + SIGNED_IN_REMEDY,
        ],
      };
    case 'trusted_device_granted':
      return {
        subject: 'A browser was trusted to skip two-factor sign-in on your H-Vault account',
        heading: 'A browser was trusted',
        paragraphs: [
          'After a sign-in with a two-factor code, a browser was trusted to skip the two-factor ' +
            'step for a limited time. You can see and revoke trusted browsers in Settings.',
          'If this was not you, revoke it, then ' + SIGNED_IN_REMEDY,
        ],
      };
    case 'device_proof_revoked':
      return {
        subject: 'A browser is no longer recognised on your H-Vault account',
        heading: 'A browser is no longer recognised',
        paragraphs: [
          'A browser that had signed in to your account before entered a wrong master password ' +
            'several times, so it is no longer recognised: during a lockout it is now refused ' +
            'like any browser that has never signed in.',
          'If this was not you, someone is guessing your master password on a device that has ' +
            'signed in to your account.',
        ],
      };
    case 'second_factor_lockout':
      return {
        subject: 'Two-factor sign-in to your H-Vault account was locked',
        heading: 'Two-factor sign-in was locked',
        paragraphs: [
          'Your master password was entered correctly, and then the two-factor code failed too ' +
            'many times. Two-factor sign-in to your account is locked for 30 minutes.',
          `If this was not you, someone knows your master password: ${SIGNED_IN_REMEDY}`,
          'If it was you, wait for the lock to end, or use the unlock link emailed to you ' +
            'separately.',
        ],
      };
    case 'backup_recipients_changed': {
      const list = (context.recipients ?? []).map((address) => maskEmail(address));
      return {
        subject: 'Where your H-Vault backups are emailed was changed',
        heading: 'Your backup recipients were changed',
        paragraphs: [
          list.length === 0
            ? 'The list of addresses your encrypted backups are emailed to was changed, and it ' +
              'is now empty: backups are emailed to your own verified address.'
            : 'The list of addresses your encrypted backups are emailed to was changed. It now ' +
              `holds: ${list.join(', ')}. An address other than your own receives nothing until ` +
              'it confirms.',
          'If this was not you, someone knows your master password: ' + SIGNED_IN_REMEDY,
        ],
      };
    }
    case 'backup_recipients_suspended': {
      const count = context.count ?? 0;
      const why = context.reason === undefined ? 'a security change' : REASON_TEXT[context.reason];
      return {
        subject: 'Your H-Vault backup recipients were suspended',
        heading: 'Your backup recipients were suspended',
        paragraphs: [
          `Because ${why}, ${String(count)} backup ` +
            `${count === 1 ? 'recipient' : 'recipients'} other than your own address ` +
            `${count === 1 ? 'was' : 'were'} suspended: nothing is emailed to ` +
            `${count === 1 ? 'it' : 'them'} until you approve the list again in Backup settings ` +
            'with your master password.',
        ],
      };
    }
    case 'token_reuse_detected':
      return {
        subject: 'A copied H-Vault session was detected and signed out',
        heading: 'A copied session was detected',
        paragraphs: [
          'A session of your account was used after it had already been replaced, which happens ' +
            'when a session is copied off a device. That session was signed out on every device ' +
            'that held it, and every trusted browser was revoked.',
          'If you did not just restore a browser from a backup, someone may have copied it: ' +
            SIGNED_IN_REMEDY,
        ],
      };
    case 'security_notices_turned_off': {
      const labels = (context.events ?? []).map((event) => PREFERENCE_LABELS[event]);
      return {
        subject: 'Some H-Vault security emails were turned off',
        heading: 'Some security emails were turned off',
        paragraphs: [
          'Your account will no longer email you about: ' +
            (labels.length === 0 ? 'nothing' : labels.join('; ')) +
            '. Turning these off needs your master password.',
          'If this was not you, someone knows your master password: ' +
            SIGNED_IN_REMEDY +
            ' Then turn these emails on again in Settings.',
        ],
      };
    }
    case 'account_deletion_requested':
      return {
        subject: 'Your H-Vault account is being deleted',
        heading: 'Your account is being deleted',
        paragraphs: [
          'Deletion of your account was requested with its master password. The account and ' +
            'everything stored in it are being erased; this cannot be undone.',
        ],
      };
    case 'backup_not_sent':
      return {
        subject: `${config.APP_NAME} - Backup not sent`,
        heading: 'Your backup was not sent',
        paragraphs: [
          `${config.APP_NAME} did not email your encrypted backup because no address on your ` +
            'backup recipient list has confirmed it wants to receive it. A recipient confirms by ' +
            'following the link it was emailed. After a password reset, a password change or ' +
            'signing out everywhere, the recipients are suspended until you approve the list ' +
            'again with your master password.',
          'Review the list in Backup settings. You can also download a backup there at any time.',
        ],
      };
  }
}

/**
 * The HTML of one notice. Every interpolated value is escaped. The only link is
 * the plain Settings address, built from configuration: a notice carries no token
 * and no link parameter, so it is never worth stealing and never a template for a
 * phishing copy that asks the reader to click something.
 */
export function renderSecurityNotice(
  event: SecurityNotificationEvent,
  context: SecurityEventContext,
  now: Date,
): { subject: string; html: string } {
  const notice = noticeFor(event, context);
  const when = `${now.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  const ip = context.ip !== undefined && net.isIP(context.ip) !== 0 ? context.ip : undefined;
  const details = [`Time: ${when}`, ...(ip === undefined ? [] : [`From the address: ${ip}`])];
  const settingsUrl = escapeHtml(`${config.APP_URL}/settings`);
  const paragraph = (text: string) =>
    `<p style="color: #4a4a4a; line-height: 1.6;">${escapeHtml(text)}</p>`;
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">${escapeHtml(notice.heading)}</h2>
      ${notice.paragraphs.map(paragraph).join('\n      ')}
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">${details.map((d) => escapeHtml(d)).join('<br>')}</p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        Choose which of these emails you receive in <a href="${settingsUrl}" style="color: #2563eb;">Settings</a>.
        Some can be turned off only with your master password, and a few are always sent.
      </p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();
  return { subject: notice.subject, html };
}

/**
 * What makes two notices the same notice: the event and every word the body says
 * apart from the time and the address it came from. A digest, so the stored key is
 * short and names no recipient.
 */
function noticeKey(event: SecurityNotificationEvent, context: SecurityEventContext): string {
  const notice = noticeFor(event, context);
  const digest = crypto
    .createHash('sha256')
    .update(JSON.stringify([notice.subject, notice.paragraphs]))
    .digest('hex')
    .slice(0, 32);
  return `${event}:${digest}`;
}

/**
 * Emails the account owner about a security event (F-26): the ONE way the server
 * tells an owner something happened to their account. Never rejects; the outcome
 * says what it did.
 *
 * In order: nothing at all when email is not configured (nothing read, nothing
 * claimed); nothing for an account that is gone or being erased (the deletion notice
 * is written from the snapshot its caller read first) or whose address was never
 * verified (an address nobody proved is not the owner's to mail); nothing when the
 * owner turned the event off (two mandatory events cannot be); then the account's
 * LAST-NOTICE slot is CLAIMED with one conditional update that matches unless the
 * last notice was this same one less than an hour ago, so a repeated event mails
 * once an hour while any different notice, a later change of state included, always
 * goes, and the owner's newest mail is never out of date. Only then is it sent. A
 * send that fails keeps the slot.
 *
 * The claim is written with `timestamps: false`. `updatedAt` is part of the profile
 * reply, and one of these notices exists precisely to stay invisible to every API
 * (a correct password presented during a lockout): a write that moved it would be
 * the oracle the lockout's uniform answer removes.
 */
export async function notifySecurityEvent(
  userId: mongoose.Types.ObjectId | string,
  event: SecurityNotificationEvent,
  context: SecurityEventContext = {},
  options: SecurityNoticeOptions = {},
): Promise<NotificationOutcome> {
  try {
    if (!isEmailConfigured()) return 'not_configured';
    const now = new Date();
    let address: string;
    if (event === 'account_deletion_requested') {
      const snapshot = context.snapshot;
      if (snapshot === undefined) return 'no_account';
      if (!snapshot.emailVerified) return 'unverified';
      address = snapshot.email;
    } else {
      const account = await User.findById(userId)
        .select('email emailVerified deletionPending settings.notifications')
        .read('primary')
        .lean();
      if (!account || account.deletionPending === true) return 'no_account';
      // A missing field reads as unverified, like the sign-in check.
      if (!account.emailVerified) return 'unverified';
      if (
        !MANDATORY.includes(event) &&
        account.settings.notifications?.[event as SecurityNotificationPreferenceEvent] === false
      ) {
        return 'opted_out';
      }
      const key = noticeKey(event, context);
      const claimed = await User.updateOne(
        {
          _id: userId,
          deletionPending: { $ne: true },
          $nor: [
            {
              'securityNotices.key': key,
              'securityNotices.at': { $gt: new Date(now.getTime() - INTERVAL_MS) },
            },
          ],
        },
        { $set: { securityNotices: { key, at: now } } },
        { timestamps: false },
      );
      if (claimed.matchedCount === 0) return 'debounced';
      address = account.email;
    }
    if (options.beforeSend !== undefined && !(await options.beforeSend())) return 'refused';
    const { subject, html } = renderSecurityNotice(event, context, now);
    const result = await sendEmail(address, subject, html);
    if (!result.success) {
      logger.warn('A security notice could not be sent', {
        userId: String(userId),
        event,
        error: result.message,
      });
      return 'failed';
    }
    return 'sent';
  } catch (err: unknown) {
    logger.error('A security notice failed', {
      userId: String(userId),
      event,
      error: errorMessage(err),
    });
    return 'failed';
  }
}

/**
 * {@link notifySecurityEvent} without waiting for it: for a request that must not
 * spend the database round trips or the SMTP time of a notice. Tracked, so a
 * shutdown waits for it and its outcome can never become an unhandled rejection.
 */
export function notifySecurityEventLater(
  userId: mongoose.Types.ObjectId | string,
  event: SecurityNotificationEvent,
  context: SecurityEventContext = {},
): void {
  trackJob(notifySecurityEvent(userId, event, context).then(() => undefined));
}
