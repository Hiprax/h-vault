import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { createTestPki } from './smtpTestPki.js';

// ── Mock nodemailer ──────────────────────────────────────────────────────────
// The email module creates a transporter lazily via nodemailer.createTransport.
// We mock nodemailer globally so every dynamic re-import picks up the mock.

const mockVerify = vi.fn().mockResolvedValue(true);
const mockSendMail = vi
  .fn()
  .mockResolvedValue({ messageId: 'test-msg-id', accepted: ['test@example.com'] });
const mockCreateTransport = vi.fn().mockReturnValue({ sendMail: mockSendMail, verify: mockVerify });

vi.mock('nodemailer', () => ({
  default: {
    createTransport: mockCreateTransport,
  },
}));

// Prevent dotenv from throwing on re-import after vi.resetModules()
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

// Silence logger output during tests. One shared set of spies, so a test can
// read what the email module logged; `beforeEach` clears them.
const mockLog = vi.hoisted(() => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}));
vi.mock('@hiprax/logger', () => ({
  createLogger: () => mockLog,
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Snapshot of email-related env vars to restore after each test. */
const emailEnvKeys = [
  'SMTP_HOST',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_FROM',
  'SMTP_PORT',
  'SMTP_SECURE',
  'EMAIL_PROVIDER',
  'GMAIL_USERNAME',
  'GMAIL_PASSWORD',
  'SMTP_REQUIRE_TLS',
  'SMTP_TLS_CA',
] as const;
let savedEnv: Record<string, string | undefined>;

function saveEmailEnv() {
  savedEnv = {};
  for (const key of emailEnvKeys) {
    savedEnv[key] = process.env[key];
  }
}

function restoreEmailEnv() {
  for (const key of emailEnvKeys) {
    if (savedEnv[key] === undefined) {
      Reflect.deleteProperty(process.env, key);
    } else {
      process.env[key] = savedEnv[key];
    }
  }
}

/**
 * Dynamically imports the email module after resetting modules.
 * This ensures a fresh `transporter` cache for each test.
 * Hoisted `vi.mock` calls persist across resets.
 */
async function freshImport() {
  vi.resetModules();
  const mod = await import('../src/utils/email.js');
  return mod;
}

/**
 * Sets SMTP-related env vars before importing the config + email module.
 * Returns the freshly imported email module.
 */
async function importWithSmtp(overrides: Record<string, string | undefined> = {}) {
  process.env['EMAIL_PROVIDER'] = 'smtp';
  process.env['SMTP_HOST'] = overrides['SMTP_HOST'] ?? 'smtp.example.com';
  process.env['SMTP_USER'] = overrides['SMTP_USER'] ?? 'user@example.com';
  process.env['SMTP_PASS'] = overrides['SMTP_PASS'] ?? 'password123';
  for (const key of ['SMTP_FROM', 'SMTP_REQUIRE_TLS', 'SMTP_TLS_CA'] as const) {
    const value = overrides[key];
    if (value !== undefined) process.env[key] = value;
    else Reflect.deleteProperty(process.env, key);
  }

  return freshImport();
}

/**
 * Sets Gmail-related env vars before importing the config + email module.
 * Returns the freshly imported email module.
 */
async function importWithGmail(overrides: Record<string, string | undefined> = {}) {
  process.env['EMAIL_PROVIDER'] = 'gmail';
  process.env['GMAIL_USERNAME'] = overrides['GMAIL_USERNAME'] ?? 'user@gmail.com';
  process.env['GMAIL_PASSWORD'] = overrides['GMAIL_PASSWORD'] ?? 'app-password-123';
  // Clear SMTP vars to avoid config conflicts
  delete process.env['SMTP_HOST'];
  delete process.env['SMTP_USER'];
  delete process.env['SMTP_PASS'];
  delete process.env['SMTP_FROM'];

  return freshImport();
}

/**
 * Clears email env vars so no provider is configured.
 * Returns the freshly imported email module.
 */
async function importWithoutEmail() {
  delete process.env['EMAIL_PROVIDER'];
  delete process.env['SMTP_HOST'];
  delete process.env['SMTP_USER'];
  delete process.env['SMTP_PASS'];
  delete process.env['SMTP_FROM'];
  delete process.env['GMAIL_USERNAME'];
  delete process.env['GMAIL_PASSWORD'];

  return freshImport();
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Email utility', () => {
  beforeEach(() => {
    saveEmailEnv();
    mockSendMail.mockClear();
    mockCreateTransport.mockClear();
    mockVerify.mockClear();
    for (const spy of Object.values(mockLog)) spy.mockClear();
    mockSendMail.mockResolvedValue({ messageId: 'test-msg-id', accepted: ['test@example.com'] });
    mockVerify.mockResolvedValue(true);
  });

  afterEach(() => {
    restoreEmailEnv();
  });

  // ── sendEmail ────────────────────────────────────────────────────────────

  describe('sendEmail', () => {
    it('should return failure with transporter_not_configured when SMTP is not configured', async () => {
      const { sendEmail } = await importWithoutEmail();

      const result = await sendEmail('test@example.com', 'Test Subject', '<p>Hello</p>');

      expect(result.success).toBe(false);
      expect(result.message).toBe('transporter_not_configured');
      expect(mockCreateTransport).not.toHaveBeenCalled();
      expect(mockSendMail).not.toHaveBeenCalled();
    });

    it('resolves smtp_send_failed, never throws, when building the transport throws', async () => {
      mockCreateTransport.mockImplementationOnce(() => {
        throw new Error('unsupported transport option');
      });
      const { sendEmail } = await importWithSmtp();

      await expect(sendEmail('recipient@example.com', 'Subject', '<p>Body</p>')).resolves.toEqual({
        success: false,
        message: 'smtp_send_failed: unsupported transport option',
      });
      expect(mockSendMail).not.toHaveBeenCalled();
    });

    it('should send email when SMTP is configured and return success', async () => {
      const { sendEmail } = await importWithSmtp();

      const result = await sendEmail('recipient@example.com', 'Test Subject', '<p>Hello</p>');

      expect(result.success).toBe(true);
      expect(result.message).toMatch(/sent successfully/i);

      expect(mockCreateTransport).toHaveBeenCalledOnce();
      expect(mockCreateTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          host: 'smtp.example.com',
          port: 587,
          secure: false,
          auth: {
            user: 'user@example.com',
            pass: 'password123',
          },
        }),
      );

      expect(mockSendMail).toHaveBeenCalledOnce();
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'recipient@example.com',
          subject: 'Test Subject',
          html: '<p>Hello</p>',
        }),
      );
    });

    it('should use secure: true when SMTP port is 465', async () => {
      process.env['SMTP_PORT'] = '465';
      const { sendEmail } = await importWithSmtp();

      await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(mockCreateTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          port: 465,
          secure: true,
        }),
      );
    });

    it('should return failure with smtp_send_failed prefix when sendMail fails', async () => {
      const sendMailError = new Error('SMTP connection refused');
      mockSendMail.mockRejectedValueOnce(sendMailError);

      const { sendEmail } = await importWithSmtp();

      const result = await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(result.success).toBe(false);
      expect(result.message).toContain('smtp_send_failed');
      expect(result.message).toContain('SMTP connection refused');
    });

    it('masks every address inside the failure it returns and logs, and logs no error object', async () => {
      // What a real relay answers for an unknown mailbox: the address is in the
      // message, in `response`, and in `rejected`. Only the (masked) message may
      // reach a caller, who logs it, or this module's own log line.
      const refusal = Object.assign(
        new Error(
          "Can't send mail - all recipients were rejected: 550 5.1.1 <victim@example.com>: Recipient address rejected",
        ),
        {
          code: 'EENVELOPE',
          response: '550 5.1.1 <victim@example.com>: Recipient address rejected',
          rejected: ['victim@example.com'],
        },
      );
      mockSendMail.mockRejectedValueOnce(refusal);
      const { sendEmail } = await importWithSmtp();

      const result = await sendEmail('victim@example.com', 'Subject', '<p>Body</p>');

      const detail =
        "Can't send mail - all recipients were rejected: 550 5.1.1 <v***m@example.com>: Recipient address rejected";
      expect(result).toEqual({ success: false, message: `smtp_send_failed: ${detail}` });
      expect(mockLog.error).toHaveBeenCalledWith('Failed to send email', {
        to: 'v***m@example.com',
        subject: 'Subject',
        error: detail,
      });
      expect(JSON.stringify(mockLog.error.mock.calls)).not.toContain('victim@example.com');
    });

    it('masks an address in a transporter verification failure too', async () => {
      mockVerify.mockRejectedValueOnce(
        new Error('Invalid login: 535 5.7.8 user@example.com: credentials rejected'),
      );
      const { sendEmail } = await importWithSmtp();

      await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(mockLog.error).toHaveBeenCalledWith(
        expect.stringContaining('SMTP relay verification FAILED'),
        expect.objectContaining({
          error: 'Invalid login: 535 5.7.8 u***r@example.com: credentials rejected',
        }),
      );
      expect(JSON.stringify(mockLog.error.mock.calls)).not.toContain('user@example.com');
    });

    it('caps the failure detail, however long the transport says it is', async () => {
      mockSendMail.mockRejectedValueOnce(new Error('x'.repeat(10_000)));
      const { sendEmail } = await importWithSmtp();

      const result = await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(result.message).toBe(`smtp_send_failed: ${'x'.repeat(500)}`);
    });

    it('should return failure when email is not accepted', async () => {
      mockSendMail.mockResolvedValueOnce({ messageId: 'test-msg-id', accepted: [] });

      const { sendEmail } = await importWithSmtp();

      const result = await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(result.success).toBe(false);
      expect(result.message).toMatch(/not accepted/i);
    });

    it('should use SMTP_FROM when set', async () => {
      const { sendEmail } = await importWithSmtp({
        SMTP_HOST: 'smtp.example.com',
        SMTP_USER: 'user@example.com',
        SMTP_PASS: 'password123',
        SMTP_FROM: 'custom-sender@example.com',
      });

      await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'custom-sender@example.com',
        }),
      );
    });

    it('should fall back to generated from address when SMTP_FROM is not set', async () => {
      const { sendEmail } = await importWithSmtp({
        SMTP_HOST: 'mail.myhost.com',
        SMTP_USER: 'user@example.com',
        SMTP_PASS: 'password123',
        SMTP_FROM: undefined,
      });

      await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'H-Vault <noreply@mail.myhost.com>',
        }),
      );
    });

    it('should pass attachments to sendMail', async () => {
      const { sendEmail } = await importWithSmtp();

      const attachments = [
        {
          filename: 'backup.json',
          content: Buffer.from('{"data": "test"}'),
          contentType: 'application/json',
        },
      ];

      await sendEmail('test@example.com', 'Backup', '<p>Attached</p>', attachments);

      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          attachments,
        }),
      );
    });

    it('should cache the transporter after first creation', async () => {
      const { sendEmail } = await importWithSmtp();

      await sendEmail('a@example.com', 'First', '<p>1</p>');
      await sendEmail('b@example.com', 'Second', '<p>2</p>');

      // createTransport should only be called once due to caching
      expect(mockCreateTransport).toHaveBeenCalledOnce();
      expect(mockSendMail).toHaveBeenCalledTimes(2);
    });
  });

  // ── Gmail transporter ──────────────────────────────────────────────────

  // ── Transport security (F-08) ──────────────────────────────────────────

  describe('SMTP transport security', () => {
    /** The options the email module handed nodemailer for its one SMTP transport. */
    function transportOptions(): Record<string, unknown> {
      expect(mockCreateTransport).toHaveBeenCalledOnce();
      return mockCreateTransport.mock.calls[0]?.[0] as Record<string, unknown>;
    }

    it.each([
      ['a relay on the network, policy unset', true, 'smtp.example.com', undefined],
      ['127.0.0.1, policy unset (the loopback exemption)', false, '127.0.0.1', undefined],
      ['localhost, a NAME that DNS answers for, policy unset', true, 'localhost', undefined],
      ['a name under .localhost, policy unset', true, 'mail.localhost', undefined],
      ['::1, policy unset', false, '::1', undefined],
      [
        'a name that only CONTAINS localhost, policy unset',
        true,
        'localhost.example.com',
        undefined,
      ],
      ['loopback with SMTP_REQUIRE_TLS=true', true, '127.0.0.1', 'true'],
      ['a relay on the network with SMTP_REQUIRE_TLS=false', false, 'smtp.example.com', 'false'],
    ] as const)('for %s, requireTLS is %s', async (_label, required, host, policy) => {
      const { sendEmail } = await importWithSmtp({ SMTP_HOST: host, SMTP_REQUIRE_TLS: policy });

      await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

      const options = transportOptions();
      expect(options['requireTLS']).toBe(required);
      // The protocol floor applies whatever the policy, and certificate
      // verification is never turned off.
      expect(options['tls']).toEqual({ minVersion: 'TLSv1.2' });
      expect(JSON.stringify(options)).not.toContain('rejectUnauthorized');
    });

    it('hands nodemailer the operator CA when one is configured, and nothing else about trust', async () => {
      const { caPem: ca } = await createTestPki('H-Vault email unit test CA');
      const { sendEmail } = await importWithSmtp({ SMTP_TLS_CA: ca });

      await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

      expect(transportOptions()['tls']).toEqual({ minVersion: 'TLSv1.2', ca });
    });

    describe('verifyEmailTransportAtBoot', () => {
      it('verifies the relay once at boot and logs success, so the first send does not verify again', async () => {
        const { verifyEmailTransportAtBoot, sendEmail } = await importWithSmtp();

        await verifyEmailTransportAtBoot();
        await verifyEmailTransportAtBoot();
        // Verified at boot, before any mail was sent, and only once.
        expect(mockVerify).toHaveBeenCalledOnce();
        expect(mockSendMail).not.toHaveBeenCalled();
        await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

        expect(mockVerify).toHaveBeenCalledOnce();
        expect(mockLog.info).toHaveBeenCalledWith('SMTP transporter verification succeeded');
        expect(mockLog.error).not.toHaveBeenCalled();
        // TLS is required for smtp.example.com, so there is nothing to warn about.
        expect(mockLog.warn).not.toHaveBeenCalled();
      });

      it('reports a relay that cannot be used LOUDLY, naming the remedy, and never rejects', async () => {
        mockVerify.mockRejectedValueOnce(new Error('Error upgrading connection with STARTTLS'));
        const { verifyEmailTransportAtBoot } = await importWithSmtp();

        await expect(verifyEmailTransportAtBoot()).resolves.toBeUndefined();

        expect(mockLog.error).toHaveBeenCalledOnce();
        const [message, meta] = mockLog.error.mock.calls[0] as [string, Record<string, unknown>];
        expect(message).toMatch(/verification, password-reset and unlock emails/i);
        expect(message).toContain('SMTP_REQUIRE_TLS');
        expect(meta).toEqual({
          host: 'smtp.example.com',
          port: 587,
          requireTLS: true,
          error: 'Error upgrading connection with STARTTLS',
        });
        expect(mockLog.info).not.toHaveBeenCalledWith('SMTP transporter verification succeeded');
      });

      it.each([
        ['SMTP_REQUIRE_TLS=false', 'smtp.example.com', 'false'],
        ['loopback SMTP_HOST', '127.0.0.1', undefined],
      ] as const)(
        'warns once at boot that mail is not required to be encrypted (%s)',
        async (reason, host, policy) => {
          const { verifyEmailTransportAtBoot, sendEmail } = await importWithSmtp({
            SMTP_HOST: host,
            SMTP_REQUIRE_TLS: policy,
          });

          await verifyEmailTransportAtBoot();
          await verifyEmailTransportAtBoot();
          await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

          const warnings = mockLog.warn.mock.calls.filter(([m]) =>
            String(m).includes('not required to use TLS'),
          );
          expect(warnings).toHaveLength(1);
          expect(warnings[0]?.[1]).toEqual({ host, reason });
        },
      );

      it('never rejects, even when building the transport throws, and says so', async () => {
        mockCreateTransport.mockImplementationOnce(() => {
          throw new Error('unsupported transport option');
        });
        const { verifyEmailTransportAtBoot } = await importWithSmtp();

        await expect(verifyEmailTransportAtBoot()).resolves.toBeUndefined();

        expect(mockVerify).not.toHaveBeenCalled();
        expect(mockLog.error).toHaveBeenCalledWith('SMTP startup check could not run', {
          error: 'unsupported transport option',
        });
      });

      it('names the Gmail remedy, not the SMTP one, when Gmail verification fails', async () => {
        mockVerify.mockRejectedValueOnce(
          new Error('Invalid login: 535-5.7.8 Username and Password not accepted'),
        );
        const { verifyEmailTransportAtBoot } = await importWithGmail();

        await verifyEmailTransportAtBoot();

        const [message, meta] = mockLog.error.mock.calls[0] as [string, Record<string, unknown>];
        expect(message).toMatch(/^Gmail verification FAILED/);
        expect(message).toContain('GMAIL_PASSWORD');
        expect(message).not.toContain('SMTP_REQUIRE_TLS');
        expect(meta).toMatchObject({ host: 'smtp.gmail.com', port: 465, requireTLS: true });
      });

      it('does nothing when email is not configured: no transport, no verification, no error', async () => {
        const { verifyEmailTransportAtBoot } = await importWithoutEmail();

        await verifyEmailTransportAtBoot();

        expect(mockCreateTransport).not.toHaveBeenCalled();
        expect(mockVerify).not.toHaveBeenCalled();
        expect(mockLog.error).not.toHaveBeenCalled();
      });
    });
  });

  describe('Gmail provider', () => {
    it('should create Gmail transporter when EMAIL_PROVIDER is gmail', async () => {
      const { sendEmail } = await importWithGmail();

      const result = await sendEmail('recipient@example.com', 'Test', '<p>Hello</p>');

      expect(result.success).toBe(true);
      expect(mockCreateTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'gmail',
          tls: { minVersion: 'TLSv1.2' },
          auth: {
            user: 'user@gmail.com',
            pass: 'app-password-123',
          },
        }),
      );
    });

    it('should return failure when Gmail credentials are not configured', async () => {
      process.env['EMAIL_PROVIDER'] = 'gmail';
      delete process.env['GMAIL_USERNAME'];
      delete process.env['GMAIL_PASSWORD'];
      delete process.env['SMTP_HOST'];
      delete process.env['SMTP_USER'];
      delete process.env['SMTP_PASS'];

      const { sendEmail } = await freshImport();

      const result = await sendEmail('test@example.com', 'Subject', '<p>Body</p>');

      expect(result.success).toBe(false);
      expect(result.message).toBe('transporter_not_configured');
    });

    it('should use Gmail username as from address when SMTP_FROM not set', async () => {
      const { sendEmail } = await importWithGmail();

      await sendEmail('recipient@example.com', 'Subject', '<p>Body</p>');

      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: 'H-Vault <user@gmail.com>',
        }),
      );
    });
  });

  // ── sendVerificationEmail ────────────────────────────────────────────────

  describe('sendVerificationEmail', () => {
    it('should call sendEmail with the correct subject and return result', async () => {
      const { sendVerificationEmail } = await importWithSmtp();

      const result = await sendVerificationEmail('user@example.com', 'abc123');

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Verify your H-Vault email',
        }),
      );
    });

    it('should include the verification URL with encoded token in HTML', async () => {
      const { sendVerificationEmail } = await importWithSmtp();

      const token = 'token/with special&chars=true';
      await sendVerificationEmail('user@example.com', token);

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      const expectedUrl = `http://localhost:5000/verify-email#token=${encodeURIComponent(token)}`;

      expect(html).toContain(expectedUrl);
    });

    it('should include APP_URL in HTML', async () => {
      const { sendVerificationEmail } = await importWithSmtp();

      await sendVerificationEmail('user@example.com', 'token123');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('http://localhost:5000');
    });

    it('should return failure when email is not configured', async () => {
      const { sendVerificationEmail } = await importWithoutEmail();

      const result = await sendVerificationEmail('user@example.com', 'token123');

      expect(result.success).toBe(false);
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });

  // ── sendPasswordResetEmail ───────────────────────────────────────────────

  describe('sendPasswordResetEmail', () => {
    it('should call sendEmail with the correct subject and return result', async () => {
      const { sendPasswordResetEmail } = await importWithSmtp();

      const result = await sendPasswordResetEmail('user@example.com', 'reset-token');

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Reset your H-Vault password',
        }),
      );
    });

    it('should include the reset URL with encoded token in HTML', async () => {
      const { sendPasswordResetEmail } = await importWithSmtp();

      const token = 'reset/token&special=true';
      await sendPasswordResetEmail('user@example.com', token);

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      const expectedUrl = `http://localhost:5000/reset-password#token=${encodeURIComponent(token)}`;

      expect(html).toContain(expectedUrl);
    });

    it('should include APP_URL in HTML', async () => {
      const { sendPasswordResetEmail } = await importWithSmtp();

      await sendPasswordResetEmail('user@example.com', 'token123');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('http://localhost:5000');
    });

    it('should return failure when email is not configured', async () => {
      const { sendPasswordResetEmail } = await importWithoutEmail();

      const result = await sendPasswordResetEmail('user@example.com', 'token123');

      expect(result.success).toBe(false);
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });

  // ── sendAccountUnlockEmail ───────────────────────────────────────────────

  describe('sendAccountUnlockEmail', () => {
    it('should call sendEmail with the correct subject and return result', async () => {
      const { sendAccountUnlockEmail } = await importWithSmtp();

      const result = await sendAccountUnlockEmail('user@example.com', 'unlock-token');

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Your H-Vault account has been locked',
        }),
      );
    });

    it('should include the unlock URL with encoded token in HTML', async () => {
      const { sendAccountUnlockEmail } = await importWithSmtp();

      const token = 'unlock/token&special=true';
      await sendAccountUnlockEmail('user@example.com', token);

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      const expectedUrl = `http://localhost:5000/unlock-account#token=${encodeURIComponent(token)}`;

      expect(html).toContain(expectedUrl);
    });

    it('names the link as the remedy and warns that a reset erases the vault', async () => {
      const { sendAccountUnlockEmail } = await importWithSmtp();

      await sendAccountUnlockEmail('user@example.com', 'token123');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('Do not reset your master password to get back in.');
      expect(html).toContain('A reset erases everything');
      expect(html).toContain('this link is the way back in');
      // What a lockout leaves alone, stated whole: the owner's sessions and a
      // recently signed-in browser keep working while strangers keep guessing.
      expect(html).toContain(
        'Sessions you already have are not affected, and neither, usually, is a browser that ' +
          'signed in recently.',
      );
      // The old promise ("will also automatically unlock after 30 minutes") is
      // no longer true while guessing continues, so it must not be made.
      expect(html).not.toContain('automatically unlock after 30 minutes');
    });

    it('should include APP_URL in HTML', async () => {
      const { sendAccountUnlockEmail } = await importWithSmtp();

      await sendAccountUnlockEmail('user@example.com', 'token123');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('http://localhost:5000');
    });

    it('should return failure when email is not configured', async () => {
      const { sendAccountUnlockEmail } = await importWithoutEmail();

      const result = await sendAccountUnlockEmail('user@example.com', 'token123');

      expect(result.success).toBe(false);
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });

  // ── sendAccountUnlockEmail, second factor ───────────────────────────────
  //
  // Rewritten for F-26 (PLAN.md 14.2, judged design option A): the second-factor
  // lockout mail was ONE mail carrying both the alert ("your master password was
  // entered correctly") and the unlock link. A security notice may carry no token or
  // link, so the alert moved to `utils/securityNotifications.ts` (pinned in
  // `security-notifications.test.ts`) and the link is now the same factor-worded
  // sender as the password factor's. What is pinned here is the link mail itself.

  describe('sendAccountUnlockEmail for the second factor', () => {
    it('sends the two-factor unlock link, worded for that step, with the remedy if it was not the owner', async () => {
      const { sendAccountUnlockEmail } = await importWithSmtp();

      const token = 'sf/token&special=true';
      const result = await sendAccountUnlockEmail('user@example.com', token, 'second_factor');

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledTimes(1);
      const sent = (mockSendMail as Mock).mock.calls[0]?.[0] as {
        to: string;
        subject: string;
        html: string;
      };
      expect(sent.to).toBe('user@example.com');
      expect(sent.subject).toBe('Unlock two-factor sign-in to your H-Vault account');
      expect(sent.html).toContain('It unlocks the two-factor step only.');
      // The remedy that evicts a password holder is named, not only the link.
      expect(sent.html).toContain('Change Password');
      expect(sent.html).toContain(
        `http://localhost:5000/unlock-account#token=${encodeURIComponent(token)}`,
      );
      // It is not the password-lockout mail, nor does it advise a reset.
      expect(sent.subject).not.toBe('Your H-Vault account has been locked');
      expect(sent.html).not.toContain('Do not reset your master password');
    });

    it('returns failure and sends nothing when email is not configured', async () => {
      const { sendAccountUnlockEmail } = await importWithoutEmail();

      const result = await sendAccountUnlockEmail('user@example.com', 'token123', 'second_factor');

      expect(result.success).toBe(false);
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });

  // ── sendRegistrationAttemptEmail ─────────────────────────────────────────

  describe('sendRegistrationAttemptEmail', () => {
    it('should call sendEmail with the correct subject and return result', async () => {
      const { sendRegistrationAttemptEmail } = await importWithSmtp();

      const result = await sendRegistrationAttemptEmail('user@example.com');

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'H-Vault registration attempt',
        }),
      );
    });

    it('should include the login URL in HTML', async () => {
      const { sendRegistrationAttemptEmail } = await importWithSmtp();

      await sendRegistrationAttemptEmail('user@example.com');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('http://localhost:5000/login');
    });

    it('should include APP_URL in HTML', async () => {
      const { sendRegistrationAttemptEmail } = await importWithSmtp();

      await sendRegistrationAttemptEmail('user@example.com');

      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('http://localhost:5000');
    });

    it('should return failure when email is not configured', async () => {
      const { sendRegistrationAttemptEmail } = await importWithoutEmail();

      const result = await sendRegistrationAttemptEmail('user@example.com');

      expect(result.success).toBe(false);
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });

  // ── isEmailConfigured ────────────────────────────────────────────────────

  describe('isEmailConfigured', () => {
    it('is true for SMTP with a host, and for Gmail with both credentials', async () => {
      expect((await importWithSmtp()).isEmailConfigured()).toBe(true);
      expect((await importWithGmail()).isEmailConfigured()).toBe(true);
    });

    it('is false with no provider configured, and builds no transport and logs nothing', async () => {
      const { isEmailConfigured } = await importWithoutEmail();
      expect(isEmailConfigured()).toBe(false);
      expect(mockCreateTransport).not.toHaveBeenCalled();
      expect(mockLog.warn).not.toHaveBeenCalled();
    });

    it('is false for Gmail without its credentials', async () => {
      process.env['EMAIL_PROVIDER'] = 'gmail';
      delete process.env['GMAIL_USERNAME'];
      delete process.env['GMAIL_PASSWORD'];
      delete process.env['SMTP_HOST'];
      delete process.env['SMTP_USER'];
      delete process.env['SMTP_PASS'];
      const { isEmailConfigured } = await freshImport();
      expect(isEmailConfigured()).toBe(false);
    });
  });

  // ── sendUpdateAvailableEmail ─────────────────────────────────────────────

  describe('sendUpdateAvailableEmail', () => {
    const update = {
      current: '0.15.0',
      latest: '0.16.0',
      publishedAt: new Date('2026-10-02T08:30:00Z'),
      releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.16.0',
    };

    it('sends one message naming both versions, the date, the release and the update steps', async () => {
      const { sendUpdateAvailableEmail } = await importWithSmtp();

      const result = await sendUpdateAvailableEmail('admin@example.com', update);

      expect(result.success).toBe(true);
      expect(mockSendMail).toHaveBeenCalledTimes(1);
      const message = (mockSendMail as Mock).mock.calls[0]?.[0] as {
        to: string;
        subject: string;
        html: string;
      };
      expect(message.to).toBe('admin@example.com');
      expect(message.subject).toBe('H-Vault 0.16.0 is available');
      expect(message.html).toContain(
        '<h1 style="margin: 0 0 12px; font-size: 20px;">H-Vault 0.16.0 is available</h1>',
      );
      expect(message.html).toContain(
        'This server runs H-Vault 0.15.0. A newer release, 0.16.0, is out.',
      );
      expect(message.html).toContain('It was published on 2026-10-02.');
      expect(message.html).toContain(`href="${update.releaseUrl}"`);
      expect(message.html).toContain('# set HVAULT_VERSION=0.16.0 in .env, then:');
      expect(message.html).toContain('docker compose up -d --build --wait');
      expect(message.html).toContain('href="http://localhost:5000/settings/about"');
      expect(message.html).toContain('listed in UPDATE_NOTIFY_EMAILS');
    });

    it('leaves the date sentence out when the release has no publication time', async () => {
      const { sendUpdateAvailableEmail } = await importWithSmtp();
      await sendUpdateAvailableEmail('admin@example.com', { ...update, publishedAt: null });
      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).toContain('A newer release, 0.16.0, is out.\n');
      expect(html).not.toContain('published on');
    });

    it('escapes every interpolated value', async () => {
      const { sendUpdateAvailableEmail } = await importWithSmtp();
      await sendUpdateAvailableEmail('admin@example.com', {
        current: '<i>1</i>',
        latest: '<b>2</b>',
        publishedAt: null,
        releaseUrl: 'https://github.com/x/y/releases/tag/v2" onmouseover="alert(1)',
      });
      const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
      expect(html).not.toContain('<b>2</b>');
      expect(html).not.toContain('<i>1</i>');
      expect(html).toContain('&lt;b&gt;2&lt;/b&gt;');
      expect(html).toContain('&lt;i&gt;1&lt;/i&gt;');
      expect(html).not.toContain('" onmouseover="');
    });

    it('reports a failure when email is not configured', async () => {
      const { sendUpdateAvailableEmail } = await importWithoutEmail();
      const result = await sendUpdateAvailableEmail('admin@example.com', update);
      expect(result).toEqual({ success: false, message: 'transporter_not_configured' });
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });
});

// ── escapeHtml utility ──────────────────────────────────────────────────

describe('escapeHtml', () => {
  it('encodes HTML special characters', async () => {
    const { escapeHtml } = await import('../src/utils/email.js');
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
    );
  });

  it('encodes ampersands and single quotes', async () => {
    const { escapeHtml } = await import('../src/utils/email.js');
    expect(escapeHtml("Tom & Jerry's")).toBe('Tom &amp; Jerry&#39;s');
  });

  it('returns plain strings unchanged', async () => {
    const { escapeHtml } = await import('../src/utils/email.js');
    expect(escapeHtml('H-Vault')).toBe('H-Vault');
  });
});

// ── Token links (F-27) ──────────────────────────────────────────────────

describe('every one-time token link carries its token in the URL fragment, never the query', () => {
  // A query string is part of the request line both Nginx tiers log, and it is
  // sent on as a Referer; a fragment never leaves the browser. So the token must
  // appear after `#` and nowhere after `?`, in the button AND in the copy-paste
  // text, for all four links: verification, reset, unlock (password and second
  // factor share the page) and the backup recipient's confirmation.
  const TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJwIjoieCJ9.sig-_nature';

  beforeEach(() => {
    saveEmailEnv();
    mockSendMail.mockClear();
    mockCreateTransport.mockClear();
    mockSendMail.mockResolvedValue({ messageId: 'test-msg-id', accepted: ['user@example.com'] });
    mockVerify.mockResolvedValue(true);
  });

  afterEach(() => {
    restoreEmailEnv();
  });

  /** Every absolute link in a sent message, parsed. */
  function linksIn(html: string): URL[] {
    return [...html.matchAll(/href="([^"]+)"/g)].map(
      (m) => new URL(m[1]!.replaceAll('&amp;', '&')),
    );
  }

  it.each([
    ['verification', '/verify-email', 'sendVerificationEmail'],
    ['password reset', '/reset-password', 'sendPasswordResetEmail'],
    ['account unlock', '/unlock-account', 'sendAccountUnlockEmail'],
  ] as const)('the %s email links to %s#token=…', async (_label, path, sender) => {
    const email = await importWithSmtp();

    await email[sender]('user@example.com', TOKEN);

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    const [link, ...others] = linksIn(html);
    expect(others).toEqual([]);
    expect(link?.origin).toBe('http://localhost:5000');
    expect(link?.pathname).toBe(path);
    expect(link?.hash).toBe(`#token=${TOKEN}`);
    expect(link?.search).toBe('');
    // The copy-paste paragraph is the same link, and nothing carries it in a query.
    expect(html).toContain(`>http://localhost:5000${path}#token=${TOKEN}</p>`);
    expect(html).not.toContain('?token=');
    expect(html).not.toContain('&token=');
  });

  it('the second-factor unlock email links to /unlock-account#token=…', async () => {
    const { sendAccountUnlockEmail } = await importWithSmtp();

    await sendAccountUnlockEmail('user@example.com', TOKEN, 'second_factor');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    const [link, ...others] = linksIn(html);
    expect(others).toEqual([]);
    expect(link?.pathname).toBe('/unlock-account');
    expect(link?.hash).toBe(`#token=${TOKEN}`);
    expect(link?.search).toBe('');
    expect(html).not.toContain('?token=');
  });

  it('tokenLink builds the recipient confirmation link the same way, percent-encoding the token', async () => {
    const { tokenLink } = await importWithSmtp();

    const link = new URL(tokenLink('/backup/confirm-recipient', 'a b&c=d#e'));

    expect(link.pathname).toBe('/backup/confirm-recipient');
    expect(link.search).toBe('');
    expect(link.hash).toBe('#token=a%20b%26c%3Dd%23e');
    expect(decodeURIComponent(link.hash.slice('#token='.length))).toBe('a b&c=d#e');
  });
});

// ── URL escaping in email display text ──────────────────────────────────

describe('email template URL display-text escaping', () => {
  // The token is encodeURIComponent'd before it reaches the URL, so a special
  // character can never enter via the token. To make escaping OBSERVABLE we
  // craft an APP_URL containing an HTML-special `&`: the href attribute must
  // carry it RAW while the display-text paragraph must carry it ESCAPED
  // (`&amp;`). With a plain http://localhost:5000 APP_URL the two are identical
  // and escapeHtml's removal is undetectable — the defect these tests fix.
  const CRAFTED_APP_URL = 'http://localhost:5000/app?x=1&y=2';
  let savedAppUrl: string | undefined;

  beforeEach(() => {
    saveEmailEnv();
    savedAppUrl = process.env['APP_URL'];
    process.env['APP_URL'] = CRAFTED_APP_URL;
    mockSendMail.mockClear();
    mockCreateTransport.mockClear();
    mockVerify.mockClear();
    mockSendMail.mockResolvedValue({ messageId: 'test-msg-id', accepted: ['test@example.com'] });
    mockVerify.mockResolvedValue(true);
  });

  afterEach(() => {
    restoreEmailEnv();
    if (savedAppUrl === undefined) {
      delete process.env['APP_URL'];
    } else {
      process.env['APP_URL'] = savedAppUrl;
    }
  });

  it('should escape display-text URLs in verification email', async () => {
    const { sendVerificationEmail } = await importWithSmtp();

    await sendVerificationEmail('user@example.com', 'tok');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    // href attribute carries the RAW ampersand.
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/verify-email#token=tok"');
    // Display-text paragraph carries the ESCAPED ampersand (proves escapeHtml ran).
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/verify-email#token=tok</p>');
    // And the display paragraph must NOT contain the raw `x=1&y=2` sequence.
    expect(html).not.toContain('x=1&y=2/verify-email#token=tok</p>');
  });

  it('should escape display-text URLs in password reset email', async () => {
    const { sendPasswordResetEmail } = await importWithSmtp();

    await sendPasswordResetEmail('user@example.com', 'tok');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/reset-password#token=tok"');
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/reset-password#token=tok</p>');
    expect(html).not.toContain('x=1&y=2/reset-password#token=tok</p>');
  });

  it('should escape display-text URLs in the second-factor unlock email', async () => {
    const { sendAccountUnlockEmail } = await importWithSmtp();

    await sendAccountUnlockEmail('user@example.com', 'tok', 'second_factor');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/unlock-account#token=tok"');
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/unlock-account#token=tok</p>');
    expect(html).not.toContain('x=1&y=2/unlock-account#token=tok</p>');
  });

  it('should escape display-text URLs in account unlock email', async () => {
    const { sendAccountUnlockEmail } = await importWithSmtp();

    await sendAccountUnlockEmail('user@example.com', 'tok');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/unlock-account#token=tok"');
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/unlock-account#token=tok</p>');
    expect(html).not.toContain('x=1&y=2/unlock-account#token=tok</p>');
  });
});
