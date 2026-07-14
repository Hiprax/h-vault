import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';

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

// Silence logger output during tests
vi.mock('@hiprax/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
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
  if (overrides['SMTP_FROM'] !== undefined) {
    process.env['SMTP_FROM'] = overrides['SMTP_FROM'];
  } else {
    delete process.env['SMTP_FROM'];
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

  describe('Gmail provider', () => {
    it('should create Gmail transporter when EMAIL_PROVIDER is gmail', async () => {
      const { sendEmail } = await importWithGmail();

      const result = await sendEmail('recipient@example.com', 'Test', '<p>Hello</p>');

      expect(result.success).toBe(true);
      expect(mockCreateTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'gmail',
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
      const expectedUrl = `http://localhost:5000/verify-email?token=${encodeURIComponent(token)}`;

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
      const expectedUrl = `http://localhost:5000/reset-password?token=${encodeURIComponent(token)}`;

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
      const expectedUrl = `http://localhost:5000/unlock-account?token=${encodeURIComponent(token)}`;

      expect(html).toContain(expectedUrl);
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
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/verify-email?token=tok"');
    // Display-text paragraph carries the ESCAPED ampersand (proves escapeHtml ran).
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/verify-email?token=tok</p>');
    // And the display paragraph must NOT contain the raw `x=1&y=2` sequence.
    expect(html).not.toContain('x=1&y=2/verify-email?token=tok</p>');
  });

  it('should escape display-text URLs in password reset email', async () => {
    const { sendPasswordResetEmail } = await importWithSmtp();

    await sendPasswordResetEmail('user@example.com', 'tok');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/reset-password?token=tok"');
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/reset-password?token=tok</p>');
    expect(html).not.toContain('x=1&y=2/reset-password?token=tok</p>');
  });

  it('should escape display-text URLs in account unlock email', async () => {
    const { sendAccountUnlockEmail } = await importWithSmtp();

    await sendAccountUnlockEmail('user@example.com', 'tok');

    const html = (mockSendMail as Mock).mock.calls[0]?.[0]?.html as string;
    expect(html).toContain('href="http://localhost:5000/app?x=1&y=2/unlock-account?token=tok"');
    expect(html).toContain('http://localhost:5000/app?x=1&amp;y=2/unlock-account?token=tok</p>');
    expect(html).not.toContain('x=1&y=2/unlock-account?token=tok</p>');
  });
});
