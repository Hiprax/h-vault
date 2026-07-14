import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { createLogger } from '@hiprax/logger';
import { maskEmail } from '@hvault/shared';
import { config } from '../config/index.js';

const logger = createLogger({ moduleName: 'email' });

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

  const secure = config.SMTP_SECURE ?? config.SMTP_PORT === 465;

  transporter = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: config.SMTP_PORT,
    secure,
    auth: {
      user: config.SMTP_USER,
      pass: config.SMTP_PASS,
    },
  });

  return transporter;
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
 * Tracks whether transporter.verify() has been attempted.
 * We only run it once (on the first sendEmail call) to surface config
 * issues early without blocking sends — some SMTP servers reject VERIFY
 * but accept MAIL FROM.
 */
let transporterVerified = false;

/**
 * Runs transporter.verify() once on first sendEmail call.
 * Logs the result but never blocks the send attempt.
 */
async function verifyTransporterOnce(mailer: Transporter): Promise<void> {
  if (transporterVerified) return;
  transporterVerified = true;

  try {
    await mailer.verify();
    logger.info('SMTP transporter verification succeeded');
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    logger.error('SMTP transporter verification failed — sends may still work', { error: errMsg });
  }
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
  const mailer = getTransporter();

  if (!mailer) {
    logger.warn('Skipping email — email provider not configured', { to: maskEmail(to), subject });
    return { success: false, message: 'transporter_not_configured' };
  }

  // Run one-time SMTP verification (non-blocking)
  await verifyTransporterOnce(mailer);

  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const result: { accepted?: readonly unknown[] } = await mailer.sendMail({
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
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    logger.error('Failed to send email', { to: maskEmail(to), subject, error: err });
    return { success: false, message: `smtp_send_failed: ${errMsg}` };
  }
}

// ── Specialised senders ────────────────────────────────────────────────

/**
 * Sends an email-verification message containing a one-time link.
 *
 * @param email  The recipient address.
 * @param token  The verification token (will be URL-encoded).
 */
export async function sendVerificationEmail(email: string, token: string): Promise<EmailResult> {
  const verifyUrl = `${config.APP_URL}/verify-email?token=${encodeURIComponent(token)}`;

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
 * @param token  The password-reset token (will be URL-encoded).
 */
export async function sendPasswordResetEmail(email: string, token: string): Promise<EmailResult> {
  const resetUrl = `${config.APP_URL}/reset-password?token=${encodeURIComponent(token)}`;

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
 * @param token  The unlock token (will be URL-encoded).
 */
export async function sendAccountUnlockEmail(email: string, token: string): Promise<EmailResult> {
  const unlockUrl = `${config.APP_URL}/unlock-account?token=${encodeURIComponent(token)}`;

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
        This link will expire in 1 hour. Your account will also automatically unlock after 30 minutes.
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
