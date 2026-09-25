import net from 'node:net';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import nodemailer from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';

/** `text` as a literal inside a regular expression: every metacharacter escaped. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── Why this file exists ─────────────────────────────────────────────────────
// `email.test.ts` replaces nodemailer with a mock, so it pins what `sendEmail`
// does with whatever the mock hands back, and nothing about what the REAL library
// hands back. The contract `sendEmail` depends on lives in the library: that
// `sendMail` resolves with an `accepted` array, that every failure it reports is
// an `Error` (the `smtp_send_failed: <details>` message is built from
// `err.message`, and a non-Error would degrade to "Unknown error"), that a binary
// attachment (the backup emails) arrives byte for byte, and that the well-known
// `'gmail'` service still resolves to Gmail's submission endpoint. Those are
// exactly the surfaces a major upgrade of the library can move, so this file
// drives the real transport end to end against a loopback SMTP responder.
//
// Nothing here leaves the machine: the responder listens on 127.0.0.1, which the
// harness egress guard allows, and the Gmail case only reads the resolved options.

// Prevent dotenv from loading a developer's root `.env` on each fresh import.
vi.mock('dotenv', () => ({ default: { config: vi.fn() } }));

// Silence logger output; no assertion here reads a log line.
vi.mock('@hiprax/logger', () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

// ── Loopback SMTP responder ──────────────────────────────────────────────────

const SMTP_USER = 'mailer@example.test';
const SMTP_PASS = 'transport-contract-pass';

interface Session {
  commands: string[];
  data: string[];
}

interface Responder {
  port: number;
  sessions: Session[];
  close: () => Promise<void>;
}

/**
 * A minimal ESMTP responder: advertises AUTH PLAIN (and no STARTTLS, so the
 * session stays plaintext on loopback), records every command line per
 * connection, and either accepts or refuses each recipient. `dropConnections`
 * makes it a server that accepts the TCP connection and hangs up before the
 * greeting, which is a dead relay without a port that some other process could
 * claim between "free" and "connect".
 */
async function startResponder(
  options: { rejectRecipients?: boolean; dropConnections?: boolean } = {},
): Promise<Responder> {
  const sessions: Session[] = [];
  const sockets = new Set<net.Socket>();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    const session: Session = { commands: [], data: [] };
    sessions.push(session);
    if (options.dropConnections) {
      socket.destroy();
      return;
    }
    let buffered = '';
    let inData = false;

    socket.write('220 responder.test ESMTP\r\n');
    socket.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('utf8');
      let end = buffered.indexOf('\r\n');
      while (end !== -1) {
        const line = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        end = buffered.indexOf('\r\n');

        if (inData) {
          if (line === '.') {
            inData = false;
            socket.write('250 2.0.0 queued\r\n');
          } else {
            // RFC 5321 section 4.5.2: a leading dot was doubled by the sender.
            session.data.push(line.startsWith('..') ? line.slice(1) : line);
          }
          continue;
        }

        session.commands.push(line);
        switch ((line.split(' ')[0] ?? '').toUpperCase()) {
          case 'EHLO':
            socket.write('250-responder.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n');
            break;
          case 'AUTH':
            socket.write('235 2.7.0 accepted\r\n');
            break;
          case 'MAIL':
          case 'RSET':
            socket.write('250 2.1.0 ok\r\n');
            break;
          case 'RCPT':
            socket.write(
              options.rejectRecipients ? '550 5.1.1 mailbox unavailable\r\n' : '250 2.1.5 ok\r\n',
            );
            break;
          case 'DATA':
            inData = true;
            socket.write('354 end with <CRLF>.<CRLF>\r\n');
            break;
          case 'QUIT':
            socket.end('221 2.0.0 bye\r\n');
            break;
          default:
            socket.write('502 5.5.2 unrecognised\r\n');
        }
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no TCP address');

  return {
    port: address.port,
    sessions,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

// ── Environment ──────────────────────────────────────────────────────────────

const EMAIL_ENV_KEYS = [
  'EMAIL_PROVIDER',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_SECURE',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_FROM',
  'GMAIL_USERNAME',
  'GMAIL_PASSWORD',
] as const;
let savedEnv: Record<string, string | undefined> = {};

/** Points the email module at `port` on loopback and imports it fresh. */
async function importPointedAt(port: number) {
  process.env['EMAIL_PROVIDER'] = 'smtp';
  process.env['SMTP_HOST'] = '127.0.0.1';
  process.env['SMTP_PORT'] = String(port);
  process.env['SMTP_USER'] = SMTP_USER;
  process.env['SMTP_PASS'] = SMTP_PASS;
  process.env['SMTP_FROM'] = 'H-Vault <noreply@example.test>';
  delete process.env['SMTP_SECURE'];
  vi.resetModules();
  return import('../src/utils/email.js');
}

describe('sendEmail over the real nodemailer transport', () => {
  let responder: Responder | undefined;

  beforeEach(() => {
    savedEnv = {};
    for (const key of EMAIL_ENV_KEYS) savedEnv[key] = process.env[key];
  });

  afterEach(async () => {
    await responder?.close();
    responder = undefined;
    for (const key of EMAIL_ENV_KEYS) {
      const value = savedEnv[key];
      if (value === undefined) Reflect.deleteProperty(process.env, key);
      else process.env[key] = value;
    }
  });

  it('delivers through the real transport and reports the recipient the server accepted', async () => {
    responder = await startResponder();
    const { sendEmail } = await importPointedAt(responder.port);

    const result = await sendEmail('alice@example.test', 'Contract subject', '<p>Hello</p>');

    expect(result).toEqual({ success: true, message: 'Email sent successfully.' });
    // Connection 1 is the one-time verify, connection 2 the delivery.
    expect(responder.sessions).toHaveLength(2);
    const [verify, delivery] = responder.sessions;
    expect(verify?.commands.some((c) => c.startsWith('MAIL FROM'))).toBe(false);
    const expectedAuth = Buffer.from(`\0${SMTP_USER}\0${SMTP_PASS}`).toString('base64');
    expect(delivery?.commands).toContain(`AUTH PLAIN ${expectedAuth}`);
    expect(delivery?.commands.find((c) => c.startsWith('MAIL FROM'))).toMatch(
      /^MAIL FROM:<noreply@example\.test>/,
    );
    expect(delivery?.commands.find((c) => c.startsWith('RCPT TO'))).toBe(
      'RCPT TO:<alice@example.test>',
    );
    expect(delivery?.data).toContain('Subject: Contract subject');
  });

  it('verifies the transport once per process, not once per message', async () => {
    responder = await startResponder();
    const { sendEmail } = await importPointedAt(responder.port);

    await sendEmail('alice@example.test', 'First', '<p>1</p>');
    const second = await sendEmail('bob@example.test', 'Second', '<p>2</p>');

    expect(second.success).toBe(true);
    // verify + first delivery + second delivery; a second verify would make four.
    expect(responder.sessions).toHaveLength(3);
    expect(responder.sessions[2]?.commands).toContain('RCPT TO:<bob@example.test>');
  });

  it('resolves smtp_send_failed with the library error text when every recipient is refused', async () => {
    responder = await startResponder({ rejectRecipients: true });
    const { sendEmail } = await importPointedAt(responder.port);

    const result = await sendEmail('nobody@example.test', 'Refused', '<p>x</p>');

    expect(result.success).toBe(false);
    expect(result.message.startsWith('smtp_send_failed: ')).toBe(true);
    // The details are the library's own message, which only survives if the
    // rejection is an Error; a non-Error would have produced "Unknown error".
    expect(result.message).not.toBe('smtp_send_failed: Unknown error');
    expect(result.message).toMatch(/mailbox unavailable|recipients/i);
    // The message body was never sent.
    const delivery = responder.sessions.at(-1);
    expect(delivery?.commands).not.toContain('DATA');
    expect(delivery?.data).toEqual([]);
  });

  it('resolves smtp_send_failed, never throws, when the relay hangs up before its greeting', async () => {
    responder = await startResponder({ dropConnections: true });
    const { sendEmail } = await importPointedAt(responder.port);

    const outcome = sendEmail('alice@example.test', 'Unreachable', '<p>x</p>');

    await expect(outcome).resolves.toEqual({
      success: false,
      message: expect.stringMatching(/^smtp_send_failed: .*socket close/i) as unknown,
    });
  });

  it('delivers a binary attachment byte for byte, the way the backup emails send one', async () => {
    responder = await startResponder();
    const { sendEmail } = await importPointedAt(responder.port);
    // Every byte value, then a deterministic pseudo-random tail: an encrypted
    // backup is exactly this kind of payload, and nothing in it may be altered.
    const backup = Buffer.alloc(4096);
    let state = 0x2545f491;
    for (let i = 0; i < backup.length; i++) {
      state = (Math.imul(state, 1103515245) + 12345) >>> 0;
      backup[i] = i < 256 ? i : state >>> 24;
    }
    const filename = 'hvault-backup-2026-01-01.enc';

    const result = await sendEmail('alice@example.test', 'Encrypted Vault Backup', '<p>x</p>', [
      { filename, content: backup, contentType: 'application/octet-stream' },
    ]);

    expect(result).toEqual({ success: true, message: 'Email sent successfully.' });
    const message = (responder.sessions.at(-1)?.data ?? []).join('\r\n');
    const boundary = /Content-Type: multipart\/mixed;\s+boundary="([^"]+)"/.exec(message)?.[1];
    expect(boundary, message.slice(0, 600)).toBeDefined();
    const parts = message.split(`--${boundary ?? ''}`).slice(1, -1);
    const attachments = parts.filter((part) => /Content-Disposition: attachment/.test(part));
    // Exactly one attachment, next to the HTML body rather than instead of it.
    expect(attachments).toHaveLength(1);
    expect(parts.some((part) => /Content-Type: text\/html/.test(part))).toBe(true);
    const [headers = '', body = ''] = (attachments[0] ?? '').split('\r\n\r\n');
    expect(headers).toMatch(/Content-Type: application\/octet-stream/);
    expect(headers).toMatch(/Content-Transfer-Encoding: base64/);
    expect(headers).toMatch(new RegExp(`filename="?${escapeRegExp(filename)}"?`));
    const decoded = Buffer.from(body.replace(/\s+/g, ''), 'base64');
    expect(decoded.equals(backup)).toBe(true);
  });

  it('keeps transporter_not_configured distinct from a send failure when SMTP is unset', async () => {
    delete process.env['SMTP_HOST'];
    delete process.env['SMTP_USER'];
    delete process.env['SMTP_PASS'];
    process.env['EMAIL_PROVIDER'] = 'smtp';
    vi.resetModules();
    const { sendEmail } = await import('../src/utils/email.js');

    const result = await sendEmail('alice@example.test', 'Unset', '<p>x</p>');

    expect(result).toEqual({ success: false, message: 'transporter_not_configured' });
    expect(result.message.startsWith('smtp_send_failed')).toBe(false);
  });
});

describe("nodemailer's well-known 'gmail' service", () => {
  it('resolves to the implicit-TLS submission endpoint email.ts relies on', () => {
    // The exact option shape `getTransporter` builds for EMAIL_PROVIDER=gmail.
    const transport = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: 'someone@gmail.com', pass: 'app-password' },
    });
    expect(transport.transporter).toBeInstanceOf(SMTPTransport);
    const resolved = (transport.transporter as SMTPTransport).options;

    expect(resolved.host).toBe('smtp.gmail.com');
    expect(resolved.port).toBe(465);
    expect(resolved.secure).toBe(true);
    // The credentials survive the service lookup rather than being replaced by it.
    expect(resolved.auth).toEqual({ user: 'someone@gmail.com', pass: 'app-password' });
    transport.close();
  });
});
