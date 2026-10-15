/**
 * F-05: backup recipients are PROVEN, and a change of footing re-authenticates.
 *
 * A mailed backup is the whole vault leaving the server as an attachment, to
 * whichever addresses the account lists. Before this suite, the list was part of
 * `PUT /backup/settings`: a stolen session (no master password) could point the
 * next scheduled backup at any address, nobody at that address had to agree, and
 * a password reset or "log out everywhere" left the attacker's address in place.
 *
 * What is pinned here, end to end through the real mail code (only the SMTP
 * transport is a double, so every assertion reads the `to` of a message the
 * application actually handed to the transport):
 *
 *   * the list moves ONLY through `PUT /backup/recipients`, behind the master-
 *     password proof, and the old field on `PUT /backup/settings` is REFUSED
 *     rather than silently stripped;
 *   * an address receives a backup only once it has CONFIRMED, through a single-
 *     use link bound to one (account, address, nonce), which needs no session;
 *   * no run falls back to the account address when the list has entries but none
 *     is confirmed; the owner is told instead;
 *   * a password reset, a password change and "log out everywhere" SUSPEND every
 *     third-party recipient, and the links they were sent die with the rotation;
 *   * the daily outbound budget counts backups AND confirmations.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Document } from '../src/models/Document.js';
import { runMaintenance } from '../src/jobs/maintenance.js';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { suspendThirdPartyRecipients } from '../src/utils/backupRecipients.js';
import { claimOutboundMail } from '../src/utils/outboundMailBudget.js';
import { installTestClock, uninstallTestClock } from './clock.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  deriveTestPurposeKey,
  generateStateHash,
  JWT_SECRET,
  type TestUser,
} from './helpers.js';

// ── The SMTP transport double ────────────────────────────────────────────────

interface SentMail {
  to: string;
  subject: string;
  html: string;
  attachments?: { filename: string }[] | undefined;
}

const transport = vi.hoisted(() => ({
  sent: [] as SentMail[],
  fail: false,
  /** Every message handed to the transport, refused ones included. */
  attempts: [] as string[],
}));

vi.mock('nodemailer', () => ({
  default: {
    createTransport: () => ({
      verify: () => Promise.resolve(true),
      sendMail: (message: SentMail) => {
        transport.attempts.push(message.to);
        if (transport.fail) return Promise.reject(new Error('relay refused the message'));
        transport.sent.push(message);
        return Promise.resolve({
          messageId: `m-${String(transport.sent.length)}`,
          accepted: [message.to],
        });
      },
    }),
  },
}));

// Email is configured for this file: an SMTP host is set, so `sendEmail` builds a
// transport (the double above) instead of reporting "not configured".
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return {
    ...actual,
    emailConfigured: true,
    config: {
      ...actual.config,
      SMTP_HOST: 'smtp.recipients.test',
      SMTP_USER: 'relay-user',
      SMTP_PASS: 'relay-pass',
    },
  };
});

// The scheduler's cron is captured, never scheduled.
const cronCallbacks = vi.hoisted(() => ({ list: [] as (() => Promise<void>)[] }));
vi.mock('node-cron', () => ({
  default: {
    schedule: (_expr: string, cb: () => Promise<void>) => {
      cronCallbacks.list.push(cb);
      return { stop: () => undefined };
    },
  },
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

const CONFIRM_LINK = /\/backup\/confirm-recipient#token=([A-Za-z0-9._%-]+)/;

const backupMailsTo = (): string[] =>
  transport.sent.filter((m) => (m.attachments ?? []).length > 0).map((m) => m.to);

const confirmationMailsTo = (): string[] =>
  transport.sent.filter((m) => CONFIRM_LINK.test(m.html)).map((m) => m.to);

/** The confirmation token most recently mailed to `address`. */
function lastConfirmationToken(address: string): string {
  const mails = transport.sent.filter((m) => m.to === address && CONFIRM_LINK.test(m.html));
  const last = mails.at(-1);
  if (!last) throw new Error(`no confirmation mail was sent to ${address}`);
  const match = CONFIRM_LINK.exec(last.html);
  return decodeURIComponent(match![1]!);
}

function freshAccessToken(userId: string): string {
  // `iat` one second ahead, so a token minted right after a password change is
  // not refused by the `iat < passwordChangedAt` rule (second-level precision).
  return jwt.sign({ userId, iat: Math.ceil(Date.now() / 1000) + 1 }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: userId,
    expiresIn: '15m',
  });
}

async function send(
  method: 'put' | 'post',
  path: string,
  body: Record<string, unknown>,
  accessToken?: string,
  cookies: string[] = [],
): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  const req = agent[method](path)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', [csrf.cookie, ...cookies].join('; '));
  if (accessToken !== undefined) req.set('Authorization', authHeader(accessToken));
  return req.send(body);
}

async function setUpBackup(user: TestUser): Promise<void> {
  const res = await send(
    'post',
    '/api/v1/backup/setup',
    {
      encryptedBWK: 'test-encrypted-bwk-data',
      bwkIv: 'test-bwk-iv-value',
      bwkTag: 'test-bwk-tag-value',
      bwkSalt: 'test-bwk-salt-value',
      authHash: user.authHash,
    },
    user.accessToken,
  );
  expect(res.status).toBe(200);
}

const putRecipients = (user: TestUser, backupEmails: string[], authHash = user.authHash) =>
  send('put', '/api/v1/backup/recipients', { authHash, backupEmails }, user.accessToken);

const confirm = (token: string) => send('post', '/api/v1/backup/recipients/confirm', { token });

const trigger = (user: TestUser, accessToken = user.accessToken) =>
  send('post', '/api/v1/backup/trigger', {}, accessToken);

interface StoredRecipient {
  email: string;
  state: string;
  nonce?: string;
  approvedAt?: Date | null;
}

async function storedRecipients(userId: string): Promise<StoredRecipient[]> {
  const raw = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(userId) });
  const backup = (raw?.['settings'] as { backup?: { backupRecipients?: StoredRecipient[] } })
    ?.backup;
  return backup?.backupRecipients ?? [];
}

async function stateOf(userId: string, email: string): Promise<string | undefined> {
  return (await storedRecipients(userId)).find((r) => r.email === email)?.state;
}

/** Mails a confirmation to each address and follows every link: the list ends confirmed. */
async function confirmedList(user: TestUser, emails: string[]): Promise<void> {
  const res = await putRecipients(user, emails);
  expect(res.status).toBe(200);
  for (const email of emails) {
    if (email === user.email) continue;
    expect((await confirm(lastConfirmationToken(email))).status).toBe(200);
  }
  for (const email of emails) expect(await stateOf(user.id, email)).toBe('confirmed');
}

const utcDay = (d = new Date()): string => d.toISOString().slice(0, 10);

beforeAll(() => {
  // The scheduler registers exactly one cron callback per start.
  cronCallbacks.list.length = 0;
});

beforeEach(() => {
  transport.sent.length = 0;
  transport.attempts.length = 0;
  transport.fail = false;
});

// ── 6.1: the list moves only with the master-password proof ─────────────────

describe('PUT /backup/settings no longer carries recipients (F-05)', () => {
  it('refuses the old combined body with a 400 naming the new route, and stores NOTHING from it', async () => {
    const user = await createTestUser();
    await setUpBackup(user);

    const res = await send(
      'put',
      '/api/v1/backup/settings',
      { enabled: true, scheduleHour: 5, backupEmails: ['attacker@evil.test'] },
      user.accessToken,
    );

    expect(res.status).toBe(400);
    expect(res.body.message).toContain('PUT /api/v1/backup/recipients');
    const stored = await User.findById(user.id).lean();
    // Not the schedule, not the switch, not the address: a refused body writes nothing.
    expect(stored!.settings.backup.enabled).toBe(false);
    expect(stored!.settings.backup.scheduleHour).toBe(3);
    expect(await storedRecipients(user.id)).toEqual([]);
    const raw = await User.collection.findOne({ email: user.email });
    expect(JSON.stringify(raw)).not.toContain('attacker@evil.test');
    expect(transport.sent).toEqual([]);
  });

  it('a session WITHOUT the master password cannot route the next backup to its own address', async () => {
    const user = await createTestUser();
    await setUpBackup(user);

    // What a stolen access token could do before: one settings write, then a backup.
    await send(
      'put',
      '/api/v1/backup/settings',
      { backupEmails: ['attacker@evil.test'] },
      user.accessToken,
    );
    const res = await trigger(user);

    expect(res.status).toBe(200);
    expect(backupMailsTo()).toEqual([user.email]);
    expect(transport.sent.map((m) => m.to)).not.toContain('attacker@evil.test');
  });

  it('still saves the schedule and the switch when the body carries no recipients', async () => {
    const user = await createTestUser();
    await setUpBackup(user);

    const res = await send(
      'put',
      '/api/v1/backup/settings',
      { enabled: true, scheduleHour: 5 },
      user.accessToken,
    );

    expect(res.status).toBe(200);
    const stored = await User.findById(user.id).lean();
    expect(stored!.settings.backup.enabled).toBe(true);
    expect(stored!.settings.backup.scheduleHour).toBe(5);
  });
});

describe('PUT /backup/recipients requires the master-password proof (F-05)', () => {
  it('answers 400 without a proof and 401 with a wrong one, leaving the stored list unchanged', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await confirmedList(user, [user.email]);
    const before = await storedRecipients(user.id);

    const missing = await send(
      'put',
      '/api/v1/backup/recipients',
      { backupEmails: ['stranger@evil.test'] },
      user.accessToken,
    );
    expect(missing.status).toBe(400);

    const wrong = await putRecipients(user, ['stranger@evil.test'], 'not-the-master-password');
    expect(wrong.status).toBe(401);
    expect(wrong.body.message).toBe('Current password is incorrect');

    expect(await storedRecipients(user.id)).toEqual(before);
    expect(transport.sent.map((m) => m.to)).not.toContain('stranger@evil.test');
    const failed = await AuditLog.find({
      userId: user.id,
      action: 'password_verification_failed',
    }).lean();
    expect(failed.map((row) => (row.metadata as { endpoint?: string }).endpoint)).toEqual([
      'backup_recipients',
    ]);
  });

  it('with the proof, stores the list unconfirmed and audits it with MASKED addresses', async () => {
    const user = await createTestUser();
    await setUpBackup(user);

    const res = await putRecipients(user, ['Friend@Example.org', user.email]);

    expect(res.status).toBe(200);
    const recipients = res.body.data.recipients as { email: string; state: string }[];
    expect(recipients).toEqual([
      expect.objectContaining({ email: 'friend@example.org', state: 'pending' }),
      expect.objectContaining({ email: user.email, state: 'confirmed' }),
    ]);
    const rows = await AuditLog.find({
      userId: user.id,
      action: 'backup_recipients_update',
    }).lean();
    expect(rows).toHaveLength(1);
    const logged = JSON.stringify(rows[0]!.metadata);
    expect(logged).not.toContain('friend@example.org');
    expect(logged).not.toContain(user.email);
    expect(logged).toContain('f***d@example.org');
  });
});

// ── 6.2: only confirmed recipients receive a backup ──────────────────────────

describe('recipient confirmation (F-05)', () => {
  it('never mails a backup to an unconfirmed address; emailsSent counts only confirmed ones', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['kept@example.org', 'waiting@example.org']);
    expect((await confirm(lastConfirmationToken('kept@example.org'))).status).toBe(200);
    transport.sent.length = 0;

    const res = await trigger(user);

    expect(res.status).toBe(200);
    expect(backupMailsTo()).toEqual(['kept@example.org']);
    expect(res.body.data.emailsSent).toBe(1);
    expect(res.body.data.failedEmails).toEqual([]);
    const log = await BackupLog.findOne({ userId: user.id }).lean();
    expect(log!.sentTo).toEqual(['kept@example.org']);
  });

  it('when entries exist but none is confirmed, sends NO backup (not even to the account) and tells the owner', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['waiting@example.org']);
    transport.sent.length = 0;

    const res = await trigger(user);

    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/confirmed/i);
    expect(backupMailsTo()).toEqual([]);
    const notices = transport.sent.filter((m) => m.to === user.email);
    expect(notices).toHaveLength(1);
    expect(notices[0]!.attachments ?? []).toEqual([]);
    const audit = await AuditLog.find({ userId: user.id, action: 'backup_failed' }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ reason: 'no_confirmed_recipient' }]);
  });

  it('confirms exactly its (account, address) pair, without a session, and only once', async () => {
    const owner = await createTestUser();
    const other = await createTestUser();
    await setUpBackup(owner);
    await setUpBackup(other);
    await putRecipients(owner, ['shared@example.org', 'second@example.org']);
    const ownerToken = lastConfirmationToken('shared@example.org');
    await putRecipients(other, ['shared@example.org']);

    // No Authorization header, no refresh cookie: the recipient has no account here.
    const first = await confirm(ownerToken);
    expect(first.status).toBe(200);
    expect(JSON.stringify(first.body)).not.toContain(owner.email);

    expect(await stateOf(owner.id, 'shared@example.org')).toBe('confirmed');
    expect(await stateOf(owner.id, 'second@example.org')).toBe('pending');
    expect(await stateOf(other.id, 'shared@example.org')).toBe('pending');

    const second = await confirm(ownerToken);
    expect(second.status).toBe(400);

    // The same account and nonce, but another address: refused.
    const decoded = jwt.decode(ownerToken) as Record<string, unknown>;
    const forged = jwt.sign(
      { ...decoded, email: 'second@example.org' },
      deriveTestPurposeKey('backup_recipient'),
      { algorithm: 'HS256' },
    );
    expect((await confirm(forged)).status).toBe(400);
    // A token of another purpose, well signed and carrying the LIVE nonce of a
    // pending entry, is refused on its purpose alone...
    const secondToken = lastConfirmationToken('second@example.org');
    const otherPurpose = jwt.sign(
      { ...(jwt.decode(secondToken) as Record<string, unknown>), purpose: 'email_verification' },
      deriveTestPurposeKey('backup_recipient'),
      { algorithm: 'HS256' },
    );
    expect((await confirm(otherPurpose)).status).toBe(400);
    expect(await stateOf(owner.id, 'second@example.org')).toBe('pending');
    // ...while the genuine link for that entry still works.
    expect((await confirm(secondToken)).status).toBe(200);

    const audit = await AuditLog.find({
      userId: owner.id,
      action: 'backup_recipient_confirmed',
    }).lean();
    expect(audit).toHaveLength(2);
    const logged = JSON.stringify(audit.map((row) => row.metadata));
    expect(logged).not.toContain('shared@example.org');
    expect(logged).not.toContain('second@example.org');
  });

  it('saving the list again does not re-mail an address whose link is still valid, and the link keeps working', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['once@example.org']);
    const link = lastConfirmationToken('once@example.org');

    await putRecipients(user, ['once@example.org', 'another@example.org']);
    await putRecipients(user, ['once@example.org', 'another@example.org']);

    expect(confirmationMailsTo().filter((to) => to === 'once@example.org')).toHaveLength(1);
    expect(confirmationMailsTo().filter((to) => to === 'another@example.org')).toHaveLength(1);
    expect((await confirm(link)).status).toBe(200);
  });

  it('stops retrying a confirmation the relay keeps refusing after three failed sends', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    transport.fail = true;

    await putRecipients(user, ['refused@example.org']);
    for (let run = 0; run < 4; run += 1) await runMaintenance();

    // One attempt inline, two from the job, then nothing: the budget is not drained.
    expect(transport.attempts.filter((to) => to === 'refused@example.org')).toHaveLength(3);
    const owed = await User.countDocuments({
      _id: user.id,
      'settings.backup.backupRecipients.confirmationDue': true,
    });
    expect(owed).toBe(0);

    // Saving the list again starts over.
    transport.fail = false;
    await putRecipients(user, ['refused@example.org']);
    expect(confirmationMailsTo()).toEqual(['refused@example.org']);
  });

  it('mails the link with the token in the URL FRAGMENT, never in a query string', async () => {
    const user = await createTestUser();
    await setUpBackup(user);

    await putRecipients(user, ['fragment@example.org']);

    const mail = transport.sent.find((m) => m.to === 'fragment@example.org');
    expect(mail).toBeDefined();
    expect(mail!.html).toMatch(CONFIRM_LINK);
    expect(mail!.html).not.toMatch(/confirm-recipient\?token=/);
    expect(mail!.attachments ?? []).toEqual([]);
  });

  it('never puts a recipient nonce on the wire', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    const put = await putRecipients(user, ['nonce@example.org']);
    const nonces = (await storedRecipients(user.id)).map((r) => r.nonce).filter(Boolean);
    expect(nonces.length).toBeGreaterThan(0);

    const profile = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    const settings = await send(
      'put',
      '/api/v1/backup/settings',
      { scheduleHour: 4 },
      user.accessToken,
    );
    const userSettings = await send(
      'put',
      '/api/v1/user/settings',
      { theme: 'dark' },
      user.accessToken,
    );

    for (const res of [put, profile, settings, userSettings]) {
      const body = JSON.stringify(res.body);
      expect(body).not.toContain('"nonce"');
      for (const nonce of nonces) expect(body).not.toContain(String(nonce));
    }
    expect(profile.body.data.settings.backup.backupEmails).toEqual([]);
    expect(profile.body.data.settings.backup.backupRecipients).toEqual([
      expect.objectContaining({ email: 'nonce@example.org', state: 'pending' }),
    ]);
  });
});

describe('the scheduler sends only to confirmed recipients (F-05)', () => {
  // The scheduler picks the accounts whose `scheduleHour` is the CURRENT UTC hour,
  // read when its tick runs; these tests set that hour when they seed the account.
  // A run straddling an hour boundary would seed one hour and tick in the next, so
  // the wall clock is frozen for the block (the date only: timers stay real).
  beforeEach(() => {
    installTestClock();
  });
  afterEach(() => {
    uninstallTestClock();
  });

  async function runScheduledBackup(): Promise<void> {
    startBackupScheduler();
    const callback = cronCallbacks.list.at(-1)!;
    await callback();
  }

  async function scheduledUser(): Promise<TestUser> {
    const user = await createTestUser();
    await setUpBackup(user);
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          'settings.backup.enabled': true,
          'settings.backup.scheduleHour': new Date().getUTCHours(),
        },
      },
    );
    return user;
  }

  it('skips unconfirmed entries', async () => {
    const user = await scheduledUser();
    await putRecipients(user, ['on@example.org', 'off@example.org']);
    await confirm(lastConfirmationToken('on@example.org'));
    transport.sent.length = 0;

    await runScheduledBackup();

    expect(backupMailsTo()).toEqual(['on@example.org']);
  });

  it('records no_confirmed_recipient when none is confirmed, and never falls back to the account address', async () => {
    const user = await scheduledUser();
    await putRecipients(user, ['off@example.org']);
    transport.sent.length = 0;

    await runScheduledBackup();

    expect(backupMailsTo()).toEqual([]);
    expect(transport.sent.filter((m) => m.to === user.email)).toHaveLength(1);
    const log = await BackupLog.findOne({ userId: user.id }).lean();
    expect(log!.status).toBe('failed');
    expect(log!.sentTo).toEqual([]);
    const audit = await AuditLog.find({ userId: user.id, action: 'backup_failed' }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ reason: 'no_confirmed_recipient' }]);
  });

  it('a suspension that lands while the run waits stops the mail: recipients are re-read before sending', async () => {
    const user = await scheduledUser();
    await putRecipients(user, ['third@example.org']);
    await confirm(lastConfirmationToken('third@example.org'));
    transport.sent.length = 0;

    // The run's last check before mailing; the account was read at the start.
    const original = User.exists.bind(User);
    const spy = vi
      .spyOn(User, 'exists')
      .mockImplementationOnce(((...args: unknown[]) =>
        suspendThirdPartyRecipients(user.id).then(() =>
          (original as (...a: unknown[]) => unknown)(...args),
        )) as unknown as typeof User.exists);
    try {
      await runScheduledBackup();
    } finally {
      spy.mockRestore();
    }

    expect(backupMailsTo()).toEqual([]);
    const audit = await AuditLog.find({ userId: user.id, action: 'backup_failed' }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ reason: 'no_confirmed_recipient' }]);
  });

  it('tells the owner once per episode, not on every run; saving the list starts a new one', async () => {
    const user = await scheduledUser();
    await putRecipients(user, ['off@example.org']);
    transport.sent.length = 0;

    await runScheduledBackup();
    await runScheduledBackup();
    expect(transport.sent.filter((m) => m.to === user.email)).toHaveLength(1);
    expect(await BackupLog.countDocuments({ userId: user.id, status: 'failed' })).toBe(2);

    transport.sent.length = 0;
    await putRecipients(user, ['off@example.org']);
    await runScheduledBackup();
    expect(transport.sent.filter((m) => m.to === user.email)).toHaveLength(1);
  });
});

// ── 6.2 (e): a change of footing suspends every third-party recipient ────────

describe('recovery suspends third-party recipients (F-05)', () => {
  async function resetPassword(user: TestUser): Promise<void> {
    const stored = await User.findById(user.id).select('+authHash').lean();
    const token = jwt.sign(
      {
        userId: user.id,
        purpose: 'password_reset',
        stateHash: generateStateHash(stored!.authHash),
      },
      deriveTestPurposeKey('password_reset'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );
    const res = await send('post', '/api/v1/auth/reset-password', {
      token,
      email: user.email,
      newAuthHash: 'reset-auth-hash-value',
      newEncryptedVaultKey: 'fresh-encrypted-vault-key',
      newVaultKeyIv: 'fresh-vault-iv',
      newVaultKeyTag: 'fresh-vault-tag',
    });
    expect(res.status).toBe(200);
  }

  async function changePassword(user: TestUser): Promise<void> {
    const res = await send(
      'put',
      '/api/v1/user/change-password',
      {
        currentAuthHash: user.authHash,
        newAuthHash: 'changed-auth-hash-value',
        newEncryptedVaultKey: 'rewrapped-vault-key',
        newVaultKeyIv: 'rewrapped-iv',
        newVaultKeyTag: 'rewrapped-tag',
      },
      user.accessToken,
    );
    expect(res.status).toBe(200);
  }

  async function logoutAll(user: TestUser): Promise<void> {
    const res = await send('post', '/api/v1/auth/logout-all', {}, user.accessToken);
    expect(res.status).toBe(200);
  }

  it.each([
    ['a password reset', resetPassword, 'password_reset'],
    ['a password change', changePassword, 'password_change'],
    ['log out everywhere', logoutAll, 'logout_all'],
  ] as const)(
    'after %s, a confirmed third party receives nothing and its old link is refused; the owner still receives',
    async (_label, recover, reason) => {
      const user = await createTestUser();
      await setUpBackup(user);
      await putRecipients(user, [user.email, 'third@example.org']);
      const oldLink = lastConfirmationToken('third@example.org');
      expect((await confirm(oldLink)).status).toBe(200);
      transport.sent.length = 0;
      expect(backupMailsTo()).toEqual([]);

      await recover(user);

      expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');
      expect(await stateOf(user.id, user.email)).toBe('confirmed');
      const res = await trigger(user, freshAccessToken(user.id));
      expect(res.status).toBe(200);
      expect(backupMailsTo()).toEqual([user.email]);
      expect((await confirm(oldLink)).status).toBe(400);
      expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');
      const audit = await AuditLog.find({
        userId: user.id,
        action: 'backup_recipients_suspended',
      }).lean();
      expect(audit.map((row) => row.metadata)).toEqual([{ count: 1, reason }]);
    },
  );

  it('a suspended recipient comes back only through a re-approval with the proof; its old link stays dead', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['third@example.org']);
    const oldLink = lastConfirmationToken('third@example.org');
    expect((await confirm(oldLink)).status).toBe(200);
    await logoutAll(user);
    transport.sent.length = 0;

    // No proof, no way back.
    expect((await putRecipients(user, ['third@example.org'], 'wrong-proof')).status).toBe(401);
    expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');

    const res = await putRecipients(user, ['third@example.org']);

    // The owner's approval restores what the suspension withdrew: the address had
    // confirmed, so it is confirmed again, without a new mail to click.
    expect(res.status).toBe(200);
    expect(await stateOf(user.id, 'third@example.org')).toBe('confirmed');
    expect(confirmationMailsTo()).toEqual([]);
    // Its nonce rotated at the suspension and again now: the old link is refused.
    expect((await confirm(oldLink)).status).toBe(400);
  });

  it('a recipient suspended before it ever confirmed must confirm after the re-approval', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['late@example.org']);
    const firstLink = lastConfirmationToken('late@example.org');
    await logoutAll(user);
    expect((await confirm(firstLink)).status).toBe(400);
    transport.sent.length = 0;

    await putRecipients(user, ['late@example.org']);

    expect(await stateOf(user.id, 'late@example.org')).toBe('pending');
    expect(confirmationMailsTo()).toEqual(['late@example.org']);
    expect((await confirm(lastConfirmationToken('late@example.org'))).status).toBe(200);
  });

  it.each([
    ['a password reset', resetPassword],
    ['a password change', changePassword],
    ['log out everywhere', logoutAll],
  ] as const)(
    '%s on an account with NO recipient list writes no list and no audit row, and the account address still receives',
    async (_label, recover) => {
      const user = await createTestUser();
      await setUpBackup(user);

      await recover(user);

      const raw = await User.collection.findOne({ email: user.email });
      const backup = (raw!['settings'] as { backup: Record<string, unknown> }).backup;
      expect('backupRecipients' in backup).toBe(false);
      expect('recipientsRevision' in backup).toBe(false);
      expect(
        await AuditLog.countDocuments({ userId: user.id, action: 'backup_recipients_suspended' }),
      ).toBe(0);
      expect((await trigger(user, freshAccessToken(user.id))).status).toBe(200);
      expect(backupMailsTo()).toEqual([user.email]);
    },
  );

  it('a suspension that lands while a manual backup is being built stops the mail to that address', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, [user.email, 'third@example.org']);
    expect((await confirm(lastConfirmationToken('third@example.org'))).status).toBe(200);
    transport.sent.length = 0;

    // The build reads the document summary after the recipients were first read.
    const original = Document.aggregate.bind(Document);
    const spy = vi
      .spyOn(Document, 'aggregate')
      .mockImplementationOnce(((...args: unknown[]) =>
        suspendThirdPartyRecipients(user.id).then(() =>
          (original as (...a: unknown[]) => unknown)(...args),
        )) as unknown as typeof Document.aggregate);
    let res: request.Response;
    try {
      res = await trigger(user);
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(200);
    expect(backupMailsTo()).toEqual([user.email]);
    expect(res.body.data.emailsSent).toBe(1);
  });

  it('a list update whose proof predates a password change is refused, and the suspension stands', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['third@example.org']);
    expect((await confirm(lastConfirmationToken('third@example.org'))).status).toBe(200);

    // The password changes between the list update's proof check and its write.
    const original = User.updateOne.bind(User);
    let changed = false;
    const spy = vi.spyOn(User, 'updateOne').mockImplementation(((
      filter: Record<string, unknown>,
      ...rest: unknown[]
    ) => {
      if (!changed && 'settings.backup.recipientsRevision' in filter) {
        changed = true;
        spy.mockRestore();
        return changePassword(user).then(() =>
          (original as (...args: unknown[]) => unknown)(filter, ...rest),
        );
      }
      return (original as (...args: unknown[]) => unknown)(filter, ...rest);
    }) as unknown as typeof User.updateOne);
    let res: request.Response;
    try {
      res = await putRecipients(user, ['third@example.org', 'new@example.org']);
    } finally {
      spy.mockRestore();
    }

    expect(changed).toBe(true);
    expect(res.status).toBe(401);
    expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');
    expect(await stateOf(user.id, 'new@example.org')).toBeUndefined();
  });

  /**
   * The window the SECOND suspension closes: a list update proving the OLD password
   * lands after the first suspension and before the new credential is stored. Its
   * proof still matches, so it reinstates the confirmed address and mails a link to
   * a new one; only the suspension after the credential write undoes both.
   */
  const saveListInsideTheWindow = (user: TestUser) =>
    putRecipients(user, ['third@example.org', 'fresh@example.org']);

  it('a password reset suspends again after the new credential: a list saved inside the window is cut off', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['third@example.org']);
    expect((await confirm(lastConfirmationToken('third@example.org'))).status).toBe(200);
    transport.sent.length = 0;

    const originalSave = User.prototype.save;
    let inWindow: number | undefined;
    const spy = vi.spyOn(User.prototype, 'save').mockImplementationOnce(async function (
      this: InstanceType<typeof User>,
      ...args: unknown[]
    ) {
      inWindow = (await saveListInsideTheWindow(user)).status;
      return (originalSave as (...a: unknown[]) => Promise<unknown>).apply(this, args);
    } as unknown as typeof User.prototype.save);
    try {
      await resetPassword(user);
    } finally {
      spy.mockRestore();
    }

    // The save landed (its proof was still the stored credential)...
    expect(inWindow).toBe(200);
    // ...and was undone: neither address receives, and the link it mailed is dead.
    expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');
    expect(await stateOf(user.id, 'fresh@example.org')).toBe('suspended');
    expect((await confirm(lastConfirmationToken('fresh@example.org'))).status).toBe(400);
  });

  it('a sequential password change suspends again after the new credential: a list saved inside the window is cut off', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['third@example.org']);
    expect((await confirm(lastConfirmationToken('third@example.org'))).status).toBe(200);
    transport.sent.length = 0;

    const original = User.updateOne.bind(User);
    let inWindow: number | undefined;
    const spy = vi.spyOn(User, 'updateOne').mockImplementation(((
      filter: Record<string, unknown>,
      update: { $set?: Record<string, unknown> },
      ...rest: unknown[]
    ) => {
      if (
        inWindow === undefined &&
        'vaultKeyVersion' in filter &&
        update.$set?.['authHash'] !== undefined
      ) {
        return saveListInsideTheWindow(user).then((res) => {
          inWindow = res.status;
          return (original as (...a: unknown[]) => unknown)(filter, update, ...rest);
        });
      }
      return (original as (...a: unknown[]) => unknown)(filter, update, ...rest);
    }) as unknown as typeof User.updateOne);
    try {
      await changePassword(user);
    } finally {
      spy.mockRestore();
    }

    expect(inWindow).toBe(200);
    expect(await stateOf(user.id, 'third@example.org')).toBe('suspended');
    expect(await stateOf(user.id, 'fresh@example.org')).toBe('suspended');
    expect((await confirm(lastConfirmationToken('fresh@example.org'))).status).toBe(400);
  });

  it('a list update that races a suspension recomputes from the suspended state and cannot revive old links', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await putRecipients(user, ['racer@example.org', 'waiting@example.org']);
    const racerLink = lastConfirmationToken('racer@example.org');
    expect((await confirm(racerLink)).status).toBe(200);
    const waitingLink = lastConfirmationToken('waiting@example.org');
    transport.sent.length = 0;

    // The suspension lands between the list update's read and its write.
    const original = User.updateOne.bind(User);
    let raced = false;
    const spy = vi.spyOn(User, 'updateOne').mockImplementation(((
      filter: Record<string, unknown>,
      ...rest: unknown[]
    ) => {
      if (!raced && 'settings.backup.recipientsRevision' in filter) {
        raced = true;
        return suspendThirdPartyRecipients(user.id).then(() =>
          (original as (...args: unknown[]) => unknown)(filter, ...rest),
        );
      }
      return (original as (...args: unknown[]) => unknown)(filter, ...rest);
    }) as unknown as typeof User.updateOne);
    let res: request.Response;
    try {
      res = await putRecipients(user, ['racer@example.org', 'waiting@example.org']);
    } finally {
      spy.mockRestore();
    }

    expect(raced).toBe(true);
    expect(res.status).toBe(200);
    // Recomputed from the suspended entries: the confirmed one is reinstated, the
    // never-confirmed one gets a NEW link; neither old link opens anything.
    expect(await stateOf(user.id, 'racer@example.org')).toBe('confirmed');
    expect(await stateOf(user.id, 'waiting@example.org')).toBe('pending');
    expect((await confirm(racerLink)).status).toBe(400);
    expect((await confirm(waitingLink)).status).toBe(400);
    expect(confirmationMailsTo()).toEqual(['waiting@example.org']);
  });
});

// ── 6.2 (d, f): migration v4 mails nobody; re-approval does ──────────────────

describe('existing recipients after the upgrade (F-05)', () => {
  it('become pending with NO mail from the migration or the job, until the owner re-approves; then one confirmation each', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    const user = await createTestUser();
    await setUpBackup(user);
    await User.collection.updateOne(
      { email: user.email },
      {
        $set: {
          'settings.backup.backupEmails': [
            user.email,
            'legacy-a@example.org',
            'Legacy-B@example.org',
          ],
        },
      },
    );

    await runMigrations();

    expect(transport.sent).toEqual([]);
    const migrated = await storedRecipients(user.id);
    expect(migrated.map((r) => [r.email, r.state])).toEqual([
      [user.email, 'confirmed'],
      ['legacy-a@example.org', 'pending'],
      ['legacy-b@example.org', 'pending'],
    ]);
    const raw = await User.collection.findOne({ email: user.email });
    expect(
      (raw!['settings'] as { backup: Record<string, unknown> }).backup['backupEmails'],
    ).toBeUndefined();

    // The hourly job owes them nothing: the owner has not re-approved.
    await runMaintenance();
    expect(transport.sent).toEqual([]);

    // The account's own confirmed address keeps receiving meanwhile.
    expect((await trigger(user)).status).toBe(200);
    expect(backupMailsTo()).toEqual([user.email]);
    transport.sent.length = 0;

    // Re-approval while the relay is down: nothing leaves, the mails stay owed.
    transport.fail = true;
    const approved = await putRecipients(user, [
      user.email,
      'legacy-a@example.org',
      'legacy-b@example.org',
    ]);
    expect(approved.status).toBe(200);
    expect(transport.sent).toEqual([]);
    transport.fail = false;

    await runMaintenance();
    expect(confirmationMailsTo().sort()).toEqual(['legacy-a@example.org', 'legacy-b@example.org']);

    // Exactly one each: a second run owes nothing.
    await runMaintenance();
    expect(confirmationMailsTo()).toHaveLength(2);
    expect((await confirm(lastConfirmationToken('legacy-a@example.org'))).status).toBe(200);
  });
});

describe('migration v4 edge cases (F-05)', () => {
  it('never copies the legacy single backupEmail (no release mailed it): the account keeps receiving at its own address', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    const user = await createTestUser();
    await setUpBackup(user);
    await User.collection.updateOne(
      { email: user.email },
      {
        $set: {
          'settings.backup.backupEmails': [],
          'settings.backup.backupEmail': 'stale@example.org',
        },
      },
    );

    await runMigrations();

    const raw = await User.collection.findOne({ email: user.email });
    const backup = (raw!['settings'] as { backup: Record<string, unknown> }).backup;
    expect(backup['backupEmail']).toBeUndefined();
    expect(backup['backupEmails']).toBeUndefined();
    expect(backup['backupRecipients']).toBeUndefined();
    expect((await trigger(user)).status).toBe(200);
    expect(backupMailsTo()).toEqual([user.email]);
  });

  it('drops invalid entries, merges duplicates and keeps at most ten', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    const user = await createTestUser();
    const legacy = [
      'not-an-address',
      'A@example.org',
      'a@example.org',
      `${'x'.repeat(250)}@example.org`,
      ...Array.from({ length: 11 }, (_, i) => `r${String(i)}@example.org`),
    ];
    await User.collection.updateOne(
      { email: user.email },
      { $set: { 'settings.backup.backupEmails': legacy } },
    );

    await runMigrations();

    const recipients = await storedRecipients(user.id);
    expect(recipients.map((r) => r.email)).toEqual([
      'a@example.org',
      ...Array.from({ length: 9 }, (_, i) => `r${String(i)}@example.org`),
    ]);
    expect(recipients.every((r) => r.state === 'pending' && r.approvedAt === null)).toBe(true);
    // A hydrated save of the account still validates.
    const doc = await User.findById(user.id);
    doc!.passwordChangedAt = new Date();
    await expect(doc!.save()).resolves.toBeDefined();
    expect(transport.sent).toEqual([]);
  });

  it('a list saved before the migration ran on another worker reads as "none confirmed", never as "no list"', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await User.collection.updateOne(
      { email: user.email },
      { $set: { 'settings.backup.backupEmails': ['unmigrated@example.org'] } },
    );

    const res = await trigger(user);

    expect(res.status).toBe(409);
    expect(backupMailsTo()).toEqual([]);
  });
});

// ── 6.3: one daily budget covers backups and confirmations ───────────────────

describe('daily outbound mail budget (F-05)', () => {
  // The budget is a UTC calendar day: the worker's clock is frozen where it stands, so
  // a run near midnight cannot put the seeded day and the claimed day on either side
  // of it (frozen in place, not moved: mongod keeps real time).
  beforeEach(() => {
    installTestClock();
  });
  afterEach(() => {
    uninstallTestClock();
  });

  async function seedCount(userId: string, count: number, day = utcDay()): Promise<void> {
    await User.updateOne({ _id: userId }, { $set: { outboundMail: { day, count } } });
  }

  async function outbound(userId: string): Promise<{ day: string; count: number } | undefined> {
    const doc = await User.findById(userId).select('+outboundMail').lean();
    return (doc as unknown as { outboundMail?: { day: string; count: number } }).outboundMail;
  }

  async function twoConfirmed(): Promise<TestUser> {
    const user = await createTestUser();
    await setUpBackup(user);
    await confirmedList(user, ['one@example.org', 'two@example.org']);
    transport.sent.length = 0;
    return user;
  }

  it('sends the 30th mail of the day', async () => {
    const user = await twoConfirmed();
    await seedCount(user.id, 28);

    const res = await trigger(user);

    expect(res.status).toBe(200);
    expect(backupMailsTo().sort()).toEqual(['one@example.org', 'two@example.org']);
    expect(await outbound(user.id)).toEqual({ day: utcDay(), count: 30 });
  });

  it('refuses the 31st with a 409 naming the budget, and sends nothing', async () => {
    const user = await twoConfirmed();
    await seedCount(user.id, 29);

    const res = await trigger(user);

    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/limit/i);
    expect(transport.sent).toEqual([]);
    expect(await outbound(user.id)).toEqual({ day: utcDay(), count: 29 });
  });

  it("starts a new day's count from zero", async () => {
    const user = await twoConfirmed();
    await seedCount(user.id, 30, '2000-01-01');

    expect((await trigger(user)).status).toBe(200);

    expect(await outbound(user.id)).toEqual({ day: utcDay(), count: 2 });
  });

  it('a claim stamped with an EARLIER day than the stored one is refused, never a reset backwards', async () => {
    // A confirmation run that started just before midnight still carries the old
    // day when it claims; meanwhile a fresh claim has started the new day's count.
    const user = await createTestUser();
    const newDay = new Date(Date.UTC(2026, 9, 15, 0, 0, 1));
    const oldDay = new Date(Date.UTC(2026, 9, 14, 23, 59, 50));
    await seedCount(user.id, 10, '2026-10-15');

    expect(await claimOutboundMail(user.id, 1, oldDay)).toBe(false);

    // Nothing moved: the new day keeps its spend.
    expect(await outbound(user.id)).toEqual({ day: '2026-10-15', count: 10 });
    // Negative: a claim on the stored day still adds to it, and a LATER day resets.
    expect(await claimOutboundMail(user.id, 2, newDay)).toBe(true);
    expect(await outbound(user.id)).toEqual({ day: '2026-10-15', count: 12 });
    expect(await claimOutboundMail(user.id, 1, new Date(Date.UTC(2026, 9, 16, 0, 0, 0)))).toBe(
      true,
    );
    expect(await outbound(user.id)).toEqual({ day: '2026-10-16', count: 1 });
  });

  it('forty concurrent claims of one message each: exactly thirty succeed', async () => {
    const user = await createTestUser();

    const outcomes = await Promise.all(
      Array.from({ length: 40 }, () => claimOutboundMail(user.id, 1)),
    );

    expect(outcomes.filter(Boolean)).toHaveLength(30);
    expect(await outbound(user.id)).toEqual({ day: utcDay(), count: 30 });
  });

  it('counts confirmations toward the budget, and leaves an unsent one owed', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    await seedCount(user.id, 29);

    await putRecipients(user, ['first@example.org', 'second@example.org']);

    expect(confirmationMailsTo()).toEqual(['first@example.org']);
    expect(await outbound(user.id)).toEqual({ day: utcDay(), count: 30 });
    const owed = await User.countDocuments({
      _id: user.id,
      'settings.backup.backupRecipients': {
        $elemMatch: { email: 'second@example.org', confirmationDue: true },
      },
    });
    expect(owed).toBe(1);
  });
});

describe('the reads that follow a recipient-list write come from the primary (F-05)', () => {
  // On a URI asking for `secondaryPreferred`, a lagging secondary would hand the
  // inline confirmation sender the OLD list (so the new addresses wait for the
  // hourly job) and the reply the OLD list too, which the settings page then
  // writes over the user's edit. Both reads must see the write they follow.
  it('the inline sender and the reply read the list they just wrote from the primary', async () => {
    const user = await createTestUser();
    await setUpBackup(user);
    const reads: { projection: string; mode: unknown }[] = [];
    const real = mongoose.mongo.Collection.prototype.findOne;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOne').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'users') {
        const options = args[1] as
          { projection?: unknown; readPreference?: string | { mode?: string } } | undefined;
        const preference = options?.readPreference;
        reads.push({
          projection: JSON.stringify(options?.projection ?? {}),
          mode: typeof preference === 'string' ? preference : preference?.mode,
        });
      }
      return real.apply(this, args);
    } as never);

    const res = await putRecipients(user, ['first@example.org']);

    expect(res.status).toBe(200);
    expect(confirmationMailsTo()).toEqual(['first@example.org']);
    // The inline sender reads the whole account WITH the entries' nonces (every
    // other default read of the account excludes them), and the reply reads the
    // list alone.
    const senderReads = reads.filter(
      (read) =>
        read.projection.includes('":0') && !read.projection.includes('backupRecipients.nonce'),
    );
    const replyReads = reads.filter(
      (read) => read.projection === JSON.stringify({ 'settings.backup.backupRecipients': 1 }),
    );
    expect(senderReads.length).toBeGreaterThanOrEqual(1);
    expect(replyReads).toHaveLength(1);
    for (const read of [...senderReads, ...replyReads]) expect(read.mode).toBe('primary');
  });
});
