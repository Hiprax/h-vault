/**
 * F-26: the account owner is emailed when something security-relevant happens to
 * the account, through ONE helper (`utils/securityNotifications.ts`), at most once
 * per account per event per hour, and never when email is not configured or the
 * owner turned the event off.
 *
 * Each event is driven through its REAL route (or, for the two background ones,
 * its real helper), against a mocked SMTP relay: what is asserted is the mail that
 * left, its recipient, that there is exactly one, and that its body carries no
 * token, no link parameter and no secret. The correct-password-during-a-lockout
 * signal is asserted to be a mail and NOTHING an API returns.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo, Socket } from 'node:net';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import {
  MAX_BACKUP_MAILS_PER_USER_PER_DAY,
  MAX_LOGIN_ATTEMPTS,
  maskEmail,
  type SecurityNotificationEvent,
} from '@hvault/shared';

interface SentMail {
  to: string;
  subject: string;
  html: string;
}

const transport = vi.hoisted(() => ({ sent: [] as SentMail[], fail: false }));

vi.mock('nodemailer', () => ({
  default: {
    createTransport: () => ({
      verify: () => Promise.resolve(true),
      sendMail: (message: SentMail) => {
        if (transport.fail) return Promise.reject(new Error('relay refused the message'));
        transport.sent.push(message);
        return Promise.resolve({ messageId: 'm', accepted: [message.to] });
      },
    }),
  },
}));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return {
    ...actual,
    emailConfigured: true,
    config: {
      ...actual.config,
      SMTP_HOST: 'smtp.notices.test',
      SMTP_USER: 'u',
      SMTP_PASS: 'p',
    },
  };
});

// Pass-through spies on the helper, so a test can tell WHICH path sent a mail.
vi.mock('../src/utils/securityNotifications.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/securityNotifications.js')>();
  return {
    ...actual,
    notifySecurityEvent: vi.fn(actual.notifySecurityEvent),
    notifySecurityEventLater: vi.fn(actual.notifySecurityEventLater),
  };
});

import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { settleTrackedJobs } from './support/trackedJobs.js';
import { recordUndeliverableBackup } from '../src/utils/backupRecipients.js';
import * as emailModule from '../src/utils/email.js';
import * as notifications from '../src/utils/securityNotifications.js';
import {
  authHeader,
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';
import { seedConfirmedRecipients } from './support/backupRecipients.js';

const API = '/api/v1';
const LOCKOUT_MS = 30 * 60 * 1000;
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

const SUBJECTS: Record<SecurityNotificationEvent, string> = {
  locked_sign_in_correct_password: 'Your H-Vault master password was entered during a lockout',
  password_reset: 'Your H-Vault master password was reset',
  password_changed: 'Your H-Vault master password was changed',
  two_factor_enabled: 'Two-factor authentication was turned on for your H-Vault account',
  two_factor_disabled: 'Two-factor authentication was turned off for your H-Vault account',
  backup_codes_regenerated: 'New two-factor backup codes were created for your H-Vault account',
  trusted_device_granted:
    'A browser was trusted to skip two-factor sign-in on your H-Vault account',
  device_proof_revoked: 'A browser is no longer recognised on your H-Vault account',
  second_factor_lockout: 'Two-factor sign-in to your H-Vault account was locked',
  backup_recipients_changed: 'Where your H-Vault backups are emailed was changed',
  backup_recipients_suspended: 'Your H-Vault backup recipients were suspended',
  token_reuse_detected: 'A copied H-Vault session was detected and signed out',
  account_deletion_requested: 'Your H-Vault account is being deleted',
  backup_not_sent: `${config.APP_NAME} - Backup not sent`,
  security_notices_turned_off: 'Some H-Vault security emails were turned off',
};

/** Waits until every tracked background job (the notices among them) has settled. */
const settle = settleTrackedJobs;

function noticesTo(address: string, event: SecurityNotificationEvent): SentMail[] {
  return transport.sent.filter((m) => m.to === address && m.subject === SUBJECTS[event]);
}

/**
 * Exactly one notice of `event` went to `address`, and it carries nothing worth
 * stealing: its only link is the plain Settings address, nothing in it looks like
 * a URL parameter or a signed token, and none of `secrets` appears in it.
 */
async function expectOneCleanNotice(
  address: string,
  event: SecurityNotificationEvent,
  secrets: readonly string[] = [],
): Promise<SentMail> {
  await settle();
  const notices = noticesTo(address, event);
  expect(notices).toHaveLength(1);
  const html = notices[0]!.html;
  const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
  expect(hrefs).toEqual([`${config.APP_URL}/settings`]);
  expect(html).not.toMatch(/[?#&][A-Za-z_]+=/);
  expect(html).not.toContain('eyJ');
  for (const secret of secrets) expect(html).not.toContain(secret);
  return notices[0]!;
}

async function send(
  method: 'get' | 'put' | 'post' | 'delete',
  path: string,
  body: Record<string, unknown> | undefined,
  options: { accessToken?: string; cookies?: string; userAgent?: string } = {},
): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent, options.cookies);
  const req = agent[method](`${API}${path}`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', options.cookies ? `${csrf.cookie}; ${options.cookies}` : csrf.cookie)
    .set('User-Agent', options.userAgent ?? 'NoticeTest/1.0');
  if (options.accessToken !== undefined) req.set('Authorization', authHeader(options.accessToken));
  return body === undefined ? req : req.send(body);
}

async function twoFactorUser(): Promise<{ user: TestUser; secret: Secret }> {
  const secret = new Secret();
  const user = await createTestUser();
  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      lastTotpTimestamp: 1,
    },
  });
  return { user, secret };
}

const codeFor = (secret: Secret): string =>
  new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret }).generate();

/** A code that misses every accepted step. */
function wrongCode(secret: Secret): string {
  const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
  const now = Date.now();
  const accepted = new Set([-30_000, 0, 30_000].map((d) => totp.generate({ timestamp: now + d })));
  let candidate = (Number(totp.generate({ timestamp: now })) + 500_000) % 1_000_000;
  while (accepted.has(String(candidate).padStart(6, '0'))) candidate = (candidate + 1) % 1_000_000;
  return String(candidate).padStart(6, '0');
}

async function lockPassword(userId: string): Promise<void> {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
        lockoutUntil: new Date(Date.now() + LOCKOUT_MS),
        lockoutEpisodeId: 'pw-episode-seeded',
        // The unlock link of this episode is already out, so no unlock mail joins in.
        lockoutNotifiedAt: new Date(),
      },
    },
  );
}

beforeEach(() => {
  transport.sent.length = 0;
  transport.fail = false;
  vi.mocked(notifications.notifySecurityEvent).mockClear();
  vi.mocked(notifications.notifySecurityEventLater).mockClear();
});

afterEach(async () => {
  await settle();
  vi.restoreAllMocks();
});

describe('F-26: each security event mails the account owner exactly once', () => {
  it('password changed', async () => {
    const user = await createTestUser();
    const res = await send(
      'put',
      '/user/change-password',
      {
        currentAuthHash: user.authHash,
        newAuthHash: 'changed-auth-hash-value',
        newEncryptedVaultKey: 'rewrapped-vault-key',
        newVaultKeyIv: 'rewrapped-iv',
        newVaultKeyTag: 'rewrapped-tag',
      },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'password_changed', [
      user.authHash,
      'changed-auth-hash-value',
      'rewrapped-vault-key',
    ]);
  });

  it('password reset completed', async () => {
    const user = await createTestUser();
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
    const res = await send('post', '/auth/reset-password', {
      token,
      email: user.email,
      newAuthHash: 'brand-new-auth-hash',
      newEncryptedVaultKey: 'new-enc-vault-key',
      newVaultKeyIv: 'new-vault-iv',
      newVaultKeyTag: 'new-vault-tag',
    });
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'password_reset', [token, 'brand-new-auth-hash']);
  });

  it('two-factor authentication turned on', async () => {
    const secret = new Secret();
    const user = await createTestUser();
    await User.findByIdAndUpdate(user.id, {
      $set: {
        pendingTwoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
        pendingTwoFactorExpiry: new Date(Date.now() + 10 * 60 * 1000),
      },
    });
    const res = await send(
      'post',
      '/user/2fa/verify',
      { code: codeFor(secret) },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'two_factor_enabled', [secret.base32]);
  });

  it('two-factor authentication turned off', async () => {
    const { user, secret } = await twoFactorUser();
    const res = await send(
      'delete',
      '/user/2fa',
      { password: user.rawPassword, code: codeFor(secret) },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'two_factor_disabled', [secret.base32]);
  });

  it('backup codes regenerated (and the new codes are not in the mail)', async () => {
    const { user, secret } = await twoFactorUser();
    const res = await send(
      'post',
      '/user/2fa/regenerate-backup-codes',
      { password: user.rawPassword, code: codeFor(secret) },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    const codes = res.body.data.backupCodes as string[];
    expect(codes.length).toBeGreaterThan(0);
    await expectOneCleanNotice(user.email, 'backup_codes_regenerated', codes);
  });

  it('trusted device granted at a remembered two-factor sign-in', async () => {
    const { user, secret } = await twoFactorUser();
    const login = await send('post', '/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
      rememberMe: true,
    });
    expect(login.body.data.twoFactorRequired).toBe(true);
    const tempToken = login.body.data.tempToken as string;
    const res = await send('post', '/auth/login/2fa', { tempToken, code: codeFor(secret) });
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'trusted_device_granted', [tempToken]);
  });

  it('a device proof revoked after its failure budget', async () => {
    const user = await createTestUser();
    const signedIn = await send('post', '/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
    });
    expect(signedIn.status).toBe(200);
    const proofCookie = ([] as string[])
      .concat(signedIn.headers['set-cookie'] ?? [])
      .find((c) => c.startsWith('__hv_device='))!
      .split(';')[0]!;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const res = await send(
        'post',
        '/auth/login',
        { email: user.email, authHash: 'wrong-hash' },
        { cookies: proofCookie },
      );
      expect(res.status).toBe(401);
    }
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'device_proof_revoked' })).toBe(
      1,
    );
    await expectOneCleanNotice(user.email, 'device_proof_revoked', [proofCookie.split('=')[1]!]);
  });

  it('second-factor lockout: one alert through the helper, and the unlock link in its own mail', async () => {
    const { user, secret } = await twoFactorUser();
    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
      const login = await send('post', '/auth/login', {
        email: user.email,
        authHash: user.rawPassword,
      });
      const res = await send('post', '/auth/login/2fa', {
        tempToken: login.body.data.tempToken as string,
        code: wrongCode(secret),
      });
      expect(res.status).toBe(401);
    }
    const alert = await expectOneCleanNotice(user.email, 'second_factor_lockout', [secret.base32]);
    expect(alert.html).toContain('entered correctly');
    // The functional unlock link is a mail of its own, like the password factor's.
    const links = transport.sent.filter((m) => m.to === user.email && /#token=/.test(m.html));
    expect(links).toHaveLength(1);
    expect(transport.sent.filter((m) => m.to === user.email)).toHaveLength(2);
    // Sent through the ONE helper.
    expect(
      [
        ...vi.mocked(notifications.notifySecurityEvent).mock.calls,
        ...vi.mocked(notifications.notifySecurityEventLater).mock.calls,
      ].map((call) => call[1]),
    ).toContain('second_factor_lockout');
  });

  it('backup recipients changed, listing them masked', async () => {
    const user = await createTestUser();
    const res = await send(
      'put',
      '/backup/recipients',
      { authHash: user.authHash, backupEmails: ['someone.else@example.org'] },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    const notice = await expectOneCleanNotice(user.email, 'backup_recipients_changed', [
      'someone.else@example.org',
    ]);
    expect(notice.html).toContain(maskEmail('someone.else@example.org'));
  });

  it('backup recipients suspended by "log out everywhere"', async () => {
    const user = await createTestUser();
    await seedConfirmedRecipients(user.id, ['third@example.org']);
    const res = await send('post', '/auth/logout-all', undefined, {
      accessToken: user.accessToken,
      cookies: `refreshToken=${user.refreshToken}`,
    });
    expect(res.status).toBe(200);
    const notice = await expectOneCleanNotice(user.email, 'backup_recipients_suspended', [
      'third@example.org',
    ]);
    expect(notice.html).toContain('1 backup recipient other than your own address was suspended');
  });

  it('refresh-token reuse detected', async () => {
    const user = await createTestUser();
    const first = await send('post', '/auth/refresh', undefined, {
      cookies: `refreshToken=${user.refreshToken}`,
    });
    expect(first.status).toBe(200);
    const replay = await send('post', '/auth/refresh', undefined, {
      cookies: `refreshToken=${user.refreshToken}`,
    });
    expect(replay.status).toBe(401);
    expect(replay.body.message).toBe('TOKEN_REUSE_DETECTED');
    await expectOneCleanNotice(user.email, 'token_reuse_detected', [user.refreshToken]);
  });

  it('account deletion requested, to the address read before the erasure', async () => {
    const user = await createTestUser();
    const res = await send(
      'delete',
      '/user',
      { password: user.rawPassword },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    expect(await User.findById(user.id).lean()).toBeNull();
    await expectOneCleanNotice(user.email, 'account_deletion_requested', [user.rawPassword]);
  });

  it('backup not sent: through the helper, and the email module no longer has fixed notices', async () => {
    const user = await createTestUser();
    await recordUndeliverableBackup(user.id, 'no_confirmed_recipient', () => Promise.resolve());
    await expectOneCleanNotice(user.email, 'backup_not_sent');
    expect(
      [
        ...vi.mocked(notifications.notifySecurityEvent).mock.calls,
        ...vi.mocked(notifications.notifySecurityEventLater).mock.calls,
      ].map((call) => call[1]),
    ).toContain('backup_not_sent');
    // The interim senders of Phases 2 and 6 are gone: nothing can mail a fixed
    // security notice around the helper any more.
    expect(Object.keys(emailModule)).not.toContain('sendBackupNotSentNotice');
    expect(Object.keys(emailModule)).not.toContain('sendSecondFactorLockoutEmail');
  });
});

describe('F-26: a correct password during a lockout is a mail, never an API field', () => {
  it('still mails when the guesser disconnected before the answer was ready', async () => {
    const user = await createTestUser();
    await lockPassword(user.id);
    const csrf = await getCsrf(request(app));
    const server = http.createServer(app);
    const sockets: Socket[] = [];
    server.on('connection', (socket: Socket) => sockets.push(socket));
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;
    const body = JSON.stringify({ email: user.email, authHash: user.rawPassword });
    const client = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/api/v1/auth/login',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-csrf-token': csrf.token,
        cookie: csrf.cookie,
      },
    });
    client.on('error', () => undefined);
    const realCompare = bcrypt.compare.bind(bcrypt);
    // The client leaves while the server is comparing the password, so the
    // response is already closed when the locked branch is reached.
    const compare = vi.spyOn(bcrypt, 'compare').mockImplementationOnce((async (
      a: string,
      b: string,
    ) => {
      client.destroy();
      const serverSocket = sockets[0]!;
      if (!serverSocket.destroyed) await once(serverSocket, 'close');
      return realCompare(a, b);
    }) as unknown as typeof bcrypt.compare);
    try {
      client.end(body);
      await vi.waitFor(() => expect(compare).toHaveBeenCalled());
      await vi.waitFor(() =>
        expect(noticesTo(user.email, 'locked_sign_in_correct_password')).toHaveLength(1),
      );
    } finally {
      server.close();
    }
  });

  it('mails the owner once, while the answer, the audit row and every read match a wrong password', async () => {
    const user = await createTestUser();
    await lockPassword(user.id);

    const wrong = await send('post', '/auth/login', {
      email: user.email,
      authHash: 'a-wrong-hash',
    });
    await settle();
    expect(noticesTo(user.email, 'locked_sign_in_correct_password')).toHaveLength(0);

    const right = await send('post', '/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
    });
    // The same answer, word for word.
    expect(right.status).toBe(401);
    expect(right.body).toEqual(wrong.body);
    await vi.waitFor(() =>
      expect(noticesTo(user.email, 'locked_sign_in_correct_password')).toHaveLength(1),
    );
    await expectOneCleanNotice(user.email, 'locked_sign_in_correct_password', [user.rawPassword]);

    // The audit log the owner (or anyone holding a session) can read says nothing
    // that differs between the two attempts.
    const log = await send('get', '/user/audit-log', undefined, { accessToken: user.accessToken });
    expect(log.status).toBe(200);
    const locked = (log.body.data as Record<string, unknown>[]).filter(
      (row) => row['action'] === 'login_failed',
    );
    expect(locked).toHaveLength(1);
    expect(locked[0]!['metadata']).toEqual({ reason: 'locked' });
    expect(JSON.stringify(log.body)).not.toMatch(/correct|securityNotices/i);

    // Nor does the profile or the settings reply, where the hourly slot lives.
    const profile = await send('get', '/user/profile', undefined, {
      accessToken: user.accessToken,
    });
    expect(profile.status).toBe(200);
    expect(JSON.stringify(profile.body)).not.toContain('securityNotices');
    expect(JSON.stringify(profile.body)).not.toContain('locked_sign_in_correct_password":"');
    const settings = await send(
      'put',
      '/user/settings',
      { theme: 'dark' },
      { accessToken: user.accessToken },
    );
    expect(JSON.stringify(settings.body)).not.toContain('securityNotices');
  });

  it('leaves every API read byte-identical: the profile, and the audit log against a wrong-only twin', async () => {
    const owner = await createTestUser();
    const twin = await createTestUser();
    await lockPassword(owner.id);
    await lockPassword(twin.id);
    const read = async (user: TestUser) => ({
      profile: (await send('get', '/user/profile', undefined, { accessToken: user.accessToken }))
        .body as Record<string, unknown>,
      log: (await send('get', '/user/audit-log', undefined, { accessToken: user.accessToken }))
        .body as { data: Record<string, unknown>[] },
    });
    const attempt = (user: TestUser, authHash: string) =>
      send('post', '/auth/login', { email: user.email, authHash });

    await attempt(owner, 'a-wrong-hash');
    await attempt(twin, 'a-wrong-hash');
    await settle();
    const before = await read(owner);

    // The owner's guess is right; the twin's is wrong again.
    await attempt(owner, owner.rawPassword);
    await attempt(twin, 'another-wrong-hash');
    await settle();
    expect(noticesTo(owner.email, 'locked_sign_in_correct_password')).toHaveLength(1);
    const after = await read(owner);
    const twinAfter = await read(twin);

    // The profile, `updatedAt` included, did not move at all.
    expect(after.profile).toEqual(before.profile);
    // The owner's log reads exactly like the twin's, apart from whose it is.
    const shape = (rows: Record<string, unknown>[]) =>
      rows.map(({ action, metadata, count, ipAddress, userAgent }) => ({
        action,
        metadata,
        count,
        ipAddress,
        userAgent,
      }));
    expect(shape(after.log.data)).toEqual(shape(twinAfter.log.data));
    // And the notice spent nothing a session can see, such as the backup mail budget.
    const stored = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(owner.id) });
    expect(stored!['outboundMail']).toBeUndefined();
  });

  it('sends nothing for a wrong password during the lockout', async () => {
    const user = await createTestUser();
    await lockPassword(user.id);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(
        (await send('post', '/auth/login', { email: user.email, authHash: 'nope' })).status,
      ).toBe(401);
    }
    await settle();
    expect(transport.sent.filter((m) => m.to === user.email)).toEqual([]);
  });
});

describe('F-26: when a notice is NOT sent', () => {
  async function regenerate(user: TestUser, secret: Secret): Promise<void> {
    const res = await send(
      'post',
      '/user/2fa/regenerate-backup-codes',
      { password: user.rawPassword, code: codeFor(secret) },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    // Each regeneration spends its code's step; the next one needs a later step.
    await User.updateOne({ _id: user.id }, { $set: { lastTotpTimestamp: 1 } });
  }

  it('two identical events within an hour send one mail; the next hour sends again', async () => {
    const { user, secret } = await twoFactorUser();
    await regenerate(user, secret);
    await regenerate(user, secret);
    await settle();
    expect(noticesTo(user.email, 'backup_codes_regenerated')).toHaveLength(1);

    // An hour later (the slot moved back rather than the clock forward).
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { 'securityNotices.at': new Date(Date.now() - 61 * 60 * 1000) } },
    );
    await regenerate(user, secret);
    await settle();
    expect(noticesTo(user.email, 'backup_codes_regenerated')).toHaveLength(2);
  });

  it('nothing is sent, read or claimed when email is not configured', async () => {
    const { user, secret } = await twoFactorUser();
    const host = config.SMTP_HOST;
    (config as { SMTP_HOST: string | undefined }).SMTP_HOST = '';
    try {
      await regenerate(user, secret);
      await settle();
    } finally {
      (config as { SMTP_HOST: string | undefined }).SMTP_HOST = host;
    }
    expect(transport.sent).toEqual([]);
    const stored = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    expect(stored!['securityNotices']).toBeUndefined();
  });

  it('an event the owner turned off sends nothing and claims nothing', async () => {
    const { user, secret } = await twoFactorUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { 'settings.notifications.backup_codes_regenerated': false } },
    );
    await regenerate(user, secret);
    await settle();
    expect(transport.sent).toEqual([]);
    const stored = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    expect(stored!['securityNotices']).toBeUndefined();
  });

  it('nothing is mailed to an address that was never verified', async () => {
    const user = await createTestUser({ emailVerified: false });
    expect(await notifications.notifySecurityEvent(user.id, 'password_changed')).toBe('unverified');
    expect(transport.sent).toEqual([]);
    const stored = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    expect(stored!['securityNotices']).toBeUndefined();
  });

  it('only an IDENTICAL notice in a row is held back: a later change of state always mails', async () => {
    const user = await createTestUser();
    // On, off, on again inside the hour: the owner's latest mail must say "on".
    for (const event of [
      'two_factor_enabled',
      'two_factor_disabled',
      'two_factor_enabled',
    ] as const) {
      expect(await notifications.notifySecurityEvent(user.id, event)).toBe('sent');
    }
    expect(transport.sent.map((m) => m.subject)).toEqual([
      SUBJECTS.two_factor_enabled,
      SUBJECTS.two_factor_disabled,
      SUBJECTS.two_factor_enabled,
    ]);
    // Two different recipient lists are two notices; the same list twice is one.
    transport.sent.length = 0;
    const changed = (recipients: string[]) =>
      notifications.notifySecurityEvent(user.id, 'backup_recipients_changed', { recipients });
    expect(await changed(['a@example.org'])).toBe('sent');
    expect(await changed(['b@example.org'])).toBe('sent');
    expect(await changed(['b@example.org'])).toBe('debounced');
    expect(transport.sent).toHaveLength(2);
    expect(transport.sent[1]!.html).toContain(maskEmail('b@example.org'));
  });

  it('nothing is mailed for an account being erased', async () => {
    const user = await createTestUser();
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });
    expect(await notifications.notifySecurityEvent(user.id, 'password_changed')).toBe('no_account');
    expect(transport.sent).toEqual([]);
  });
});

describe('F-26: the notice body', () => {
  const now = new Date('2026-10-15T12:34:56Z');

  it('shows the request address only when it is an IP address, and never free text', () => {
    const shown = notifications.renderSecurityNotice(
      'password_changed',
      { ip: '203.0.113.7' },
      now,
    );
    expect(shown.html).toContain('203.0.113.7');
    expect(shown.html).toContain('2026-10-15 12:34 UTC');
    const forged = notifications.renderSecurityNotice(
      'password_changed',
      { ip: 'Visit https://evil.example/reset?token=abc' },
      now,
    );
    expect(forged.html).not.toContain('evil.example');
    expect(forged.html).not.toContain('From the address');
  });

  it('masks every recipient address and escapes what it shows', () => {
    const { html } = notifications.renderSecurityNotice(
      'backup_recipients_changed',
      { recipients: ['<b>x</b>@example.org', 'plain@example.org'] },
      now,
    );
    expect(html).not.toContain('plain@example.org');
    expect(html).toContain(maskEmail('plain@example.org'));
    expect(html).not.toContain('<b>x</b>');
  });

  it('reads sensibly with no context at all', () => {
    const changed = notifications.renderSecurityNotice('backup_recipients_changed', {}, now);
    expect(changed.html).toContain('it is now empty');
    const suspended = notifications.renderSecurityNotice('backup_recipients_suspended', {}, now);
    expect(suspended.html).toContain('Because a security change, 0 backup recipients');
  });

  it('has a fixed text for every event, with the Settings link and nothing else', () => {
    const events = Object.keys(SUBJECTS) as SecurityNotificationEvent[];
    for (const event of events) {
      const { subject, html } = notifications.renderSecurityNotice(
        event,
        { count: 2, reason: 'logout_all', recipients: [] },
        now,
      );
      expect(subject).toBe(SUBJECTS[event]);
      expect([...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1])).toEqual([
        `${config.APP_URL}/settings`,
      ]);
    }
  });
});

// The deletion notice needs the account's address, which the erasure removes.
describe('F-26: the deletion notice', () => {
  it('is mandatory: sent even when the owner turned every other notice off', async () => {
    const user = await createTestUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: Object.fromEntries(
          Object.keys(SUBJECTS).map((event) => [`settings.notifications.${event}`, false]),
        ),
      },
    );
    const res = await send(
      'delete',
      '/user',
      { password: user.rawPassword },
      { accessToken: user.accessToken },
    );
    expect(res.status).toBe(200);
    await expectOneCleanNotice(user.email, 'account_deletion_requested');
    expect(transport.sent).toHaveLength(1);
  });
});

describe('F-26: the helper reports what it did, and never throws', () => {
  it('a relay that refuses the mail is "failed", and the slot stays claimed', async () => {
    const user = await createTestUser();
    transport.fail = true;
    expect(await notifications.notifySecurityEvent(user.id, 'password_changed')).toBe('failed');
    transport.fail = false;
    // Claimed before the send: the same notice is not retried within the hour.
    expect(await notifications.notifySecurityEvent(user.id, 'password_changed')).toBe('debounced');
    expect(transport.sent).toEqual([]);
  });

  it('a database failure is "failed", not a rejection', async () => {
    const user = await createTestUser();
    vi.spyOn(User, 'findById').mockImplementationOnce((() => {
      throw new Error('database unavailable');
    }) as unknown as typeof User.findById);
    await expect(notifications.notifySecurityEvent(user.id, 'password_changed')).resolves.toBe(
      'failed',
    );
    expect(transport.sent).toEqual([]);
  });

  it('the deletion notice needs its snapshot, and a verified one', async () => {
    const user = await createTestUser();
    expect(await notifications.notifySecurityEvent(user.id, 'account_deletion_requested')).toBe(
      'no_account',
    );
    expect(
      await notifications.notifySecurityEvent(user.id, 'account_deletion_requested', {
        snapshot: { email: user.email, emailVerified: false },
      }),
    ).toBe('unverified');
    expect(transport.sent).toEqual([]);
  });

  it('a backup-not-sent notice whose daily budget is spent is "refused" and sends nothing', async () => {
    const user = await createTestUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: {
          outboundMail: {
            day: new Date().toISOString().slice(0, 10),
            count: MAX_BACKUP_MAILS_PER_USER_PER_DAY,
          },
        },
      },
    );
    await recordUndeliverableBackup(user.id, 'no_confirmed_recipient', () => Promise.resolve());
    await settle();
    expect(transport.sent).toEqual([]);
    const outcomes = await Promise.all(
      vi.mocked(notifications.notifySecurityEvent).mock.results.map((r) => r.value as unknown),
    );
    expect(outcomes).toEqual(['refused']);
  });

  it('an empty "turned off" list still reads as a sentence', () => {
    const { html } = notifications.renderSecurityNotice(
      'security_notices_turned_off',
      {},
      new Date('2026-10-15T00:00:00Z'),
    );
    expect(html).toContain('no longer email you about: nothing.');
  });
});
