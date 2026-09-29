import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { createModuleLogger } from './logger.js';
import { isLoopbackIpLiteral } from './networkAddress.js';
import { maskEmail } from '@hvault/shared';
import { config } from '../config/index.js';

const logger = createModuleLogger('email');

// ── HTML encoding ────────────────────────────────────────────────────

/**
 * Encodes a string for safe embedding in HTML content.
 * Prevents HTML injection when config values (e.g. APP_NAME) are
 * interpolated into email templates.
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Types ─────────────────────────────────────────────────────────────

export interface EmailResult {
  success: boolean;
  message: string;
}

// ── Transporter ────────────────────────────────────────────────────────

let transporter: Transporter | undefined;

/**
 * Lazily initialises and returns the nodemailer transporter.
 * Supports both SMTP and Gmail providers via EMAIL_PROVIDER config.
 * Returns `undefined` when email is not configured so callers can skip sending.
 */
function getTransporter(): Transporter | undefined {
  if (transporter) return transporter;

  if (config.EMAIL_PROVIDER === 'gmail') {
    if (!config.GMAIL_USERNAME || !config.GMAIL_PASSWORD) {
      logger.warn('Gmail credentials are not configured — emails will not be sent');
      return undefined;
    }

    transporter = nodemailer.createTransport({
      service: 'gmail',
      // Implicit TLS on 465 (the well-known service); the floor matches SMTP's.
      tls: { minVersion: 'TLSv1.2' },
      auth: {
        user: config.GMAIL_USERNAME,
        pass: config.GMAIL_PASSWORD,
      },
    });

    return transporter;
  }

  // SMTP provider
  if (!config.SMTP_HOST) {
    logger.warn('SMTP_HOST is not configured — emails will not be sent');
    return undefined;
  }

  transporter = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    secure: smtpImplicitTls(),
    // STARTTLS is MANDATORY unless the policy says otherwise: without it nodemailer
    // upgrades only when the relay advertises STARTTLS, so a relay (or anything on
    // the path that strips the advertisement) that does not gets the credentials in
    // `AUTH PLAIN` and every one-time link in the clear. With it, a relay that cannot
    // upgrade is refused before either is sent. Irrelevant under implicit TLS
    // (`secure`), which is TLS from the first byte.
    requireTLS: smtpTlsPolicy().required,
    // Certificate verification stays on (nodemailer's default); these only raise the
    // protocol floor and, for an operator with a private CA, name what to trust.
    tls: smtpTlsOptions(),
    auth: {
      user: config.SMTP_USER,
      pass: config.SMTP_PASS,
    },
  });

  return transporter;
}

/** Whether the SMTP connection is TLS from its first byte (port 465 unless SMTP_SECURE says otherwise). */
function smtpImplicitTls(): boolean {
  return config.SMTP_SECURE ?? config.SMTP_PORT === 465;
}

/** Why the SMTP connection does or does not have to be encrypted. */
interface SmtpTlsPolicy {
  required: boolean;
  /** The operator's own words for it, for the boot report. */
  reason: 'SMTP_REQUIRE_TLS=true' | 'SMTP_REQUIRE_TLS=false' | 'loopback SMTP_HOST' | 'default';
}

/**
 * `SMTP_REQUIRE_TLS` is TRI-STATE on purpose. `true` requires TLS whatever the host
 * (a loopback relay included, which is what the transport tests use); `false`
 * turns the requirement off, for a plaintext relay the operator controls; unset
 * requires it for every relay except one whose `SMTP_HOST` is a loopback IP
 * LITERAL (`127.0.0.1`, `::1`), where the connection cannot leave the machine (a
 * local Postfix rarely has a certificate). A NAME is never exempt, `localhost`
 * included: nodemailer resolves a name through network DNS first, so the name's
 * answer, not the operator, would decide where the credentials go in the clear
 * (`utils/networkAddress.ts`).
 */
function smtpTlsPolicy(): SmtpTlsPolicy {
  if (config.SMTP_REQUIRE_TLS === true) return { required: true, reason: 'SMTP_REQUIRE_TLS=true' };
  if (config.SMTP_REQUIRE_TLS === false) {
    return { required: false, reason: 'SMTP_REQUIRE_TLS=false' };
  }
  if (config.SMTP_HOST !== undefined && isLoopbackIpLiteral(config.SMTP_HOST)) {
    return { required: false, reason: 'loopback SMTP_HOST' };
  }
  return { required: true, reason: 'default' };
}

/** The TLS options every transport gets: TLS 1.2 or later, and the operator's CA if one is configured. */
function smtpTlsOptions(): { minVersion: 'TLSv1.2'; ca?: string } {
  return config.SMTP_TLS_CA === undefined
    ? { minVersion: 'TLSv1.2' }
    : { minVersion: 'TLSv1.2', ca: config.SMTP_TLS_CA };
}

/**
 * Resolves the "from" address for outgoing emails.
 */
function getFromAddress(): string {
  if (config.SMTP_FROM) return config.SMTP_FROM;

  if (config.EMAIL_PROVIDER === 'gmail' && config.GMAIL_USERNAME) {
    return `${config.APP_NAME} <${config.GMAIL_USERNAME}>`;
  }

  if (config.SMTP_HOST) {
    return `${config.APP_NAME} <noreply@${config.SMTP_HOST}>`;
  }

  return `${config.APP_NAME} <noreply@hvault.local>`;
}

// ── SMTP verification ─────────────────────────────────────────────────

/**
 * Tracks whether transporter.verify() has been attempted: once per process, at
 * boot ({@link verifyEmailTransportAtBoot}) or, failing that, on the first send.
 */
let transporterVerified = false;

/** Whether {@link verifyEmailTransportAtBoot} has run: its report is made once per process. */
let bootCheckDone = false;

/** How much of a transport's failure text is kept; its replies can run long. */
const MAX_SMTP_FAILURE_DETAIL_LENGTH = 500;

/**
 * An email address inside free text: a run of address characters on each side
 * of one `@`. The lookbehind starts a match only at a token boundary, so each
 * character is scanned a bounded number of times and a long reply with no `@`
 * costs linear time, not quadratic.
 */
const EMBEDDED_ADDRESS = /(?<![^\s<>()[\]{},;:"'])[^\s<>()[\]{},;:"'@]+@[^\s<>()[\]{},;:"'@]+/g;

/**
 * What this module says about a transport failure, in its log line AND in the
 * `smtp_send_failed: <details>` it returns (which every caller logs).
 *
 * A relay's refusal quotes the recipient ("550 5.1.1 <someone@example.com>:
 * Recipient address rejected"), and the error object carries it again in
 * `response` and `rejected`. So only the MESSAGE is used, every address in it
 * goes through the shared `maskEmail` (the form this module already logs `to`
 * in), and the result is capped.
 */
function smtpFailureDetail(err: unknown): string {
  // A transport that rejects with anything but an Error has always been
  // reported as 'Unknown error'; that part of the contract is unchanged.
  const text = err instanceof Error ? err.message : 'Unknown error';
  return text
    .replace(EMBEDDED_ADDRESS, (address) => maskEmail(address))
    .slice(0, MAX_SMTP_FAILURE_DETAIL_LENGTH);
}

/**
 * Runs `transporter.verify()` once per process and logs the outcome; never throws.
 *
 * `verify()` connects, upgrades (STARTTLS when required) and authenticates without
 * sending anything, so a failure here is the failure every send would meet. It is
 * logged at ERROR, with the relay, the TLS requirement and the remedy, because
 * {@link sendEmail} never throws: a relay that cannot satisfy the TLS requirement
 * would otherwise fail every verification, reset and unlock email one silent log
 * line at a time, and new users could not finish signing up.
 */
async function verifyTransporterOnce(mailer: Transporter): Promise<void> {
  if (transporterVerified) return;
  transporterVerified = true;

  try {
    await mailer.verify();
    logger.info('SMTP transporter verification succeeded');
  } catch (err: unknown) {
    logger.error(
      config.EMAIL_PROVIDER === 'gmail'
        ? 'Gmail verification FAILED: verification, password-reset and unlock emails will fail to ' +
            'send while this persists. Check GMAIL_USERNAME and the app password in GMAIL_PASSWORD.'
        : 'SMTP relay verification FAILED: verification, password-reset and unlock emails will fail ' +
            'to send while this persists. If the relay offers no STARTTLS (or presents a certificate ' +
            'this server does not trust), give it TLS, set SMTP_TLS_CA to its CA, or, ONLY for a ' +
            'plaintext relay you control, set SMTP_REQUIRE_TLS=false (a relay on this machine: use ' +
            '127.0.0.1, not localhost, which is resolved through DNS).',
      {
        host: config.EMAIL_PROVIDER === 'gmail' ? 'smtp.gmail.com' : config.SMTP_HOST,
        port: config.EMAIL_PROVIDER === 'gmail' ? 465 : config.SMTP_PORT,
        requireTLS: config.EMAIL_PROVIDER === 'gmail' ? true : smtpTlsPolicy().required,
        error: smtpFailureDetail(err),
      },
    );
  }
}

/**
 * The boot-time email check, called once by `server.ts` when the port is open:
 * builds the transport, says ONCE when SMTP is allowed to run unencrypted (and
 * why), and verifies the relay (see {@link verifyTransporterOnce}). Resolves
 * whatever happens and does nothing at all when email is not configured, so the
 * caller can fire it without awaiting.
 */
export async function verifyEmailTransportAtBoot(): Promise<void> {
  if (bootCheckDone || !isEmailConfigured()) return;
  bootCheckDone = true;
  try {
    const mailer = getTransporter();
    if (!mailer) return;

    // Gmail and implicit TLS are encrypted from the first byte; only STARTTLS can be skipped.
    if (config.EMAIL_PROVIDER !== 'gmail' && !smtpImplicitTls()) {
      const policy = smtpTlsPolicy();
      if (!policy.required) {
        logger.warn(
          'SMTP is not required to use TLS: if the relay offers no STARTTLS, the SMTP credentials ' +
            'and every emailed link (verification, password reset, unlock) cross that hop in the clear.',
          { host: config.SMTP_HOST, reason: policy.reason },
        );
      }
    }

    await verifyTransporterOnce(mailer);
  } catch (err: unknown) {
    // Nothing above is expected to throw (the verification catches its own
    // failure), but the caller fires this without awaiting it, and an unhandled
    // rejection ends the process: the guarantee is kept here, not assumed.
    logger.error('SMTP startup check could not run', { error: smtpFailureDetail(err) });
  }
}

/**
 * Whether an email provider is configured at all, WITHOUT building a transport or
 * logging. For a background sender that must stay silent when email is off,
 * rather than warning on every run the way {@link sendEmail} does for a send that
 * a user asked for.
 */
export function isEmailConfigured(): boolean {
  if (config.EMAIL_PROVIDER === 'gmail') {
    return Boolean(config.GMAIL_USERNAME && config.GMAIL_PASSWORD);
  }
  return Boolean(config.SMTP_HOST);
}

// ── Generic send ───────────────────────────────────────────────────────

/**
 * Sends an email via the configured email provider (SMTP or Gmail).
 * Returns a result object indicating success or failure instead of throwing.
 *
 * @param to       Recipient email address.
 * @param subject  Email subject line.
 * @param html     HTML body of the email.
 */
export async function sendEmail(
  to: string,
  subject: string,
  html: string,
  attachments?: { filename: string; content: Buffer; contentType: string }[],
): Promise<EmailResult> {
  let mailer: Transporter | undefined;
  try {
    mailer = getTransporter();
  } catch (err: unknown) {
    // Building the transport can throw for an option nodemailer rejects; this
    // function's contract is that it never throws, so that is a failed send.
    const detail = smtpFailureDetail(err);
    logger.error('Failed to build the email transport', {
      to: maskEmail(to),
      subject,
      error: detail,
    });
    return { success: false, message: `smtp_send_failed: ${detail}` };
  }

  if (!mailer) {
    logger.warn('Skipping email — email provider not configured', { to: maskEmail(to), subject });
    return { success: false, message: 'transporter_not_configured' };
  }

  // One-time SMTP verification, if the boot check has not already run it.
  await verifyTransporterOnce(mailer);

  try {
    const result = await mailer.sendMail({
      from: getFromAddress(),
      to,
      subject,
      html,
      attachments,
    });

    // Check if email was accepted by the SMTP server
    const accepted = Array.isArray(result.accepted) ? result.accepted : [];
    if (accepted.length === 0) {
      const msg = 'Email was not accepted by the mail server.';
      logger.warn('Email not accepted', { to: maskEmail(to), subject });
      return { success: false, message: msg };
    }

    logger.info('Email sent', { to: maskEmail(to), subject });
    return { success: true, message: 'Email sent successfully.' };
  } catch (err: unknown) {
    const detail = smtpFailureDetail(err);
    logger.error('Failed to send email', { to: maskEmail(to), subject, error: detail });
    return { success: false, message: `smtp_send_failed: ${detail}` };
  }
}

// ── Links ─────────────────────────────────────────────────────────────

/**
 * A link into the application that carries a one-time token, with the token in
 * the URL FRAGMENT: `${APP_URL}${path}#token=<token>`. The ONE builder of every
 * emailed one-time link: verification, password-reset, unlock (both factors) and
 * backup-recipient confirmation (`tests/token-link-boundary.test.ts`). An invitation
 * link is not mailed; it is built by `utils/invitations.ts`, also as a fragment.
 *
 * A fragment is never sent to a server, so the token cannot land in an access log,
 * a proxy's log or a `Referer` header on the way to the page; the page reads it
 * from `location.hash`, removes it from the address bar and POSTs it. A query
 * string does all three of those things with it.
 *
 * @param path   The application path, starting with `/`.
 * @param token  The token; percent-encoded here.
 */
export function tokenLink(path: string, token: string): string {
  return `${config.APP_URL}${path}#token=${encodeURIComponent(token)}`;
}

// ── Specialised senders ────────────────────────────────────────────────

/**
 * Sends an email-verification message containing a one-time link.
 *
 * @param email  The recipient address.
 * @param token  The verification token (carried in the link's fragment by {@link tokenLink}).
 */
export async function sendVerificationEmail(email: string, token: string): Promise<EmailResult> {
  const verifyUrl = tokenLink('/verify-email', token);

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Verify your email address</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Thank you for signing up for H-Vault. Please click the button below to verify your email address.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${verifyUrl}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Verify Email
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If you did not create an account, you can safely ignore this email.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If the button above does not work, copy and paste the following link into your browser:
      </p>
      <p style="color: #2563eb; font-size: 14px; word-break: break-all;">${escapeHtml(verifyUrl)}</p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'Verify your H-Vault email', html);
}

/**
 * Sends a password-reset email containing a one-time link.
 *
 * @param email  The recipient address.
 * @param token  The password-reset token (carried in the link's fragment by {@link tokenLink}).
 */
export async function sendPasswordResetEmail(email: string, token: string): Promise<EmailResult> {
  const resetUrl = tokenLink('/reset-password', token);

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Reset your password</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        We received a request to reset the password for your H-Vault account. Click the button below to choose a new password.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${resetUrl}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Reset Password
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        This link will expire in 1 hour. If you did not request a password reset, please ignore this email.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If the button above does not work, copy and paste the following link into your browser:
      </p>
      <p style="color: #2563eb; font-size: 14px; word-break: break-all;">${escapeHtml(resetUrl)}</p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'Reset your H-Vault password', html);
}

/**
 * Sends a notification to an existing user that someone attempted to register with their email.
 *
 * @param email  The recipient address.
 */
export async function sendRegistrationAttemptEmail(email: string): Promise<EmailResult> {
  const loginUrl = `${config.APP_URL}/login`;

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Registration attempt detected</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Someone attempted to create a new H-Vault account using your email address.
        If this was you, you already have an account. You can log in using the button below.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${loginUrl}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Log In
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If you did not attempt to register, you can safely ignore this email. Your account is secure.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If you have forgotten your password, you can reset it from the login page.
      </p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'H-Vault registration attempt', html);
}

/**
 * Sends an account-unlock email containing a one-time link.
 *
 * @param email  The recipient address.
 * @param token  The unlock token (carried in the link's fragment by {@link tokenLink}).
 */
export async function sendAccountUnlockEmail(email: string, token: string): Promise<EmailResult> {
  const unlockUrl = tokenLink('/unlock-account', token);

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Your account has been locked</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Your H-Vault account has been locked due to too many failed login attempts.
        Click the button below to unlock your account.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${unlockUrl}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Unlock Account
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        This link will expire in 1 hour. Following it also lets the browser you open it in sign in
        for the next 10 minutes even if someone keeps guessing. Otherwise sign-ins from new browsers
        stay locked for 30 minutes at a time while the failed attempts continue. Sessions you
        already have are not affected, and neither, usually, is a browser that signed in recently.
      </p>
      <p style="color: #4a4a4a; line-height: 1.6;">
        <strong>Do not reset your master password to get back in.</strong> A reset erases everything
        in your vault; this link is the way back in.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If you did not attempt to log in, someone may be trying to access your account.
        We recommend changing your password after unlocking.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If the button above does not work, copy and paste the following link into your browser:
      </p>
      <p style="color: #2563eb; font-size: 14px; word-break: break-all;">${escapeHtml(unlockUrl)}</p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'Your H-Vault account has been locked', html);
}

/**
 * Tells the owner that their master password was accepted and then the second
 * factor failed often enough to lock the two-factor step.
 *
 * That combination is only reachable by someone who KNOWS the master password,
 * so the mail says so plainly and leads with the remedy that actually evicts
 * such a person: changing the master password (which the owner can still do from
 * any signed-in session: a second-factor lockout never refuses a refresh). The
 * link unlocks the two-factor step only; it never touches the password's own
 * lockout state.
 */
export async function sendSecondFactorLockoutEmail(
  email: string,
  token: string,
): Promise<EmailResult> {
  const unlockUrl = tokenLink('/unlock-account', token);

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Two-factor sign-in has been locked</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Your master password was entered correctly, and then the two-factor code failed too many
        times. Two-factor sign-in to your H-Vault account is locked for 30 minutes.
      </p>
      <p style="color: #4a4a4a; line-height: 1.6;">
        <strong>If this was not you, someone knows your master password.</strong> Change it now from
        a device where you are already signed in (Settings, Change Password): that signs out
        everyone else.
      </p>
      <p style="color: #4a4a4a; line-height: 1.6;">
        If it was you, use the button below to unlock two-factor sign-in.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${unlockUrl}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Unlock two-factor sign-in
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        This link will expire in 1 hour.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If the button above does not work, copy and paste the following link into your browser:
      </p>
      <p style="color: #2563eb; font-size: 14px; word-break: break-all;">${escapeHtml(unlockUrl)}</p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'Two-factor sign-in to your H-Vault account was locked', html);
}

/** What the update-available email says. */
export interface UpdateAvailableEmail {
  /** The version this server runs. */
  current: string;
  /** The newer release the check found. */
  latest: string;
  publishedAt: Date | null;
  /** The release page, built by the server from configuration. */
  releaseUrl: string;
}

/**
 * Tells one of the server's administrators (`UPDATE_NOTIFY_EMAILS`) that a newer
 * release is published. Sent at most once per release, by the release check.
 * Every interpolated value is escaped, although each one is either a validated
 * version or a URL the server built itself.
 */
export async function sendUpdateAvailableEmail(
  email: string,
  update: UpdateAvailableEmail,
): Promise<EmailResult> {
  const latest = escapeHtml(update.latest);
  const current = escapeHtml(update.current);
  const releaseUrl = escapeHtml(update.releaseUrl);
  const aboutUrl = escapeHtml(`${config.APP_URL}/settings/about`);
  const published =
    update.publishedAt === null
      ? ''
      : ` It was published on ${escapeHtml(update.publishedAt.toISOString().slice(0, 10))}.`;

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>H-Vault ${latest} is available</title></head>
    <body style="margin: 0; padding: 24px; background: #f6f7f9; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; color: #1f2937;">
      <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 28px;">
        <h1 style="margin: 0 0 12px; font-size: 20px;">H-Vault ${latest} is available</h1>
        <p style="margin: 0 0 16px; line-height: 1.6;">
          This server runs H-Vault ${current}. A newer release, ${latest}, is out.${published}
        </p>
        <p style="margin: 0 0 24px;">
          <a href="${releaseUrl}" style="display: inline-block; padding: 10px 22px; border-radius: 6px; background: #1d4ed8; color: #ffffff; font-weight: 600; text-decoration: none;">Read the release notes</a>
        </p>
        <p style="margin: 0 0 8px; line-height: 1.6;">To update a Docker installation, run these in its directory:</p>
        <pre style="margin: 0 0 16px; padding: 12px 14px; border-radius: 6px; background: #111827; color: #f9fafb; font-size: 13px; line-height: 1.6; white-space: pre-wrap;">git pull
# set HVAULT_VERSION=${latest} in .env, then:
docker compose up -d --build --wait</pre>
        <p style="margin: 0 0 16px; line-height: 1.6;">
          H-Vault also shows this under <a href="${aboutUrl}" style="color: #1d4ed8;">Settings, About H-Vault</a>.
        </p>
        <p style="margin: 0; font-size: 12px; line-height: 1.6; color: #6b7280;">
          You receive this because your address is listed in UPDATE_NOTIFY_EMAILS on this server.
          Remove it there to stop these emails. The server sends one per release.
        </p>
      </div>
    </body>
    </html>
  `.trim();

  return sendEmail(email, `H-Vault ${update.latest} is available`, html);
}

/**
 * Asks an address to confirm that it agrees to receive an account's encrypted
 * backups. Sent to the RECIPIENT, who may have no account here: it names the
 * account only masked, and ignoring it is the way to decline (nothing is ever
 * mailed to an address that has not followed its link).
 *
 * @param email         The recipient address.
 * @param link          The confirmation link, built by {@link tokenLink}.
 * @param maskedOwner   The requesting account's address, masked.
 */
export async function sendBackupRecipientConfirmationEmail(
  email: string,
  link: string,
  maskedOwner: string,
): Promise<EmailResult> {
  const safeLink = escapeHtml(link);
  const owner = escapeHtml(maskedOwner);
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Confirm this address for encrypted backups</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        The H-Vault account ${owner} asked to send its encrypted vault backups to this address.
        Nothing will be sent here unless you confirm.
      </p>
      <div style="text-align: center; margin: 32px 0;">
        <a href="${safeLink}"
           style="background-color: #2563eb; color: #ffffff; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
          Confirm this address
        </a>
      </div>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If you do not recognise this request, ignore this email: no backup will be sent to you.
        This link expires in 24 hours and works once.
      </p>
      <p style="color: #6b6b6b; font-size: 14px; line-height: 1.6;">
        If the button above does not work, copy and paste the following link into your browser:
      </p>
      <p style="color: #2563eb; font-size: 14px; word-break: break-all;">${safeLink}</p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, 'Confirm this address for H-Vault backups', html);
}

/**
 * Tells the account owner that a backup was NOT mailed because no address on the
 * recipient list has confirmed. Sent to the account's own address, with no
 * attachment: the backup is never rerouted there, because the owner chose to send
 * it somewhere else. A fixed text, so nothing in it comes from the request.
 */
export async function sendBackupNotSentNotice(email: string): Promise<EmailResult> {
  const safeAppName = escapeHtml(config.APP_NAME);
  const settingsUrl = escapeHtml(`${config.APP_URL}/settings/backup`);
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1a1a1a;">Your backup was not sent</h2>
      <p style="color: #4a4a4a; line-height: 1.6;">
        ${safeAppName} did not email your encrypted backup because no address on your backup
        recipient list has confirmed it wants to receive it. A recipient confirms by following the
        link it was emailed. After a password reset, a password change or signing out everywhere,
        the recipients are suspended until you approve the list again with your master password.
      </p>
      <p style="color: #4a4a4a; line-height: 1.6;">
        Review the list in <a href="${settingsUrl}" style="color: #2563eb;">Backup settings</a>.
        You can also download a backup there at any time.
      </p>
      <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 24px 0;">
      <p style="color: #9a9a9a; font-size: 12px;">H-Vault &mdash; Your passwords, secured.</p>
    </body>
    </html>
  `.trim();

  return sendEmail(email, `${config.APP_NAME} - Backup not sent`, html);
}
