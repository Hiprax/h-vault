/**
 * F-26: which security emails the owner receives. `PUT /user/settings` takes no
 * password, so it may turn any notice ON and the optional ones off, but never a
 * CRITICAL one off; that takes `PUT /user/notifications` with the master-password
 * proof, conditioned on the credential it proved, and it tells the owner. The two
 * mandatory notices are not a preference at all.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import mongoose from 'mongoose';
import request from 'supertest';
import {
  CRITICAL_SECURITY_NOTIFICATION_EVENTS,
  SECURITY_NOTIFICATION_PREFERENCE_EVENTS,
} from '@hvault/shared';

interface SentMail {
  to: string;
  subject: string;
  html: string;
}

const transport = vi.hoisted(() => ({ sent: [] as SentMail[] }));

vi.mock('nodemailer', () => ({
  default: {
    createTransport: () => ({
      verify: () => Promise.resolve(true),
      sendMail: (message: SentMail) => {
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
    config: { ...actual.config, SMTP_HOST: 'smtp.prefs.test', SMTP_USER: 'u', SMTP_PASS: 'p' },
  };
});

import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { settleTrackedJobs } from './support/trackedJobs.js';
import jwt from 'jsonwebtoken';
import {
  authHeader,
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const PASSWORD_CHANGED = 'Your H-Vault master password was changed';
const TURNED_OFF = 'Some H-Vault security emails were turned off';

const settle = settleTrackedJobs;

async function send(
  method: 'get' | 'put',
  path: string,
  user: TestUser,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  const req = agent[method](`${API}${path}`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .set('Authorization', authHeader(user.accessToken));
  return body === undefined ? req : req.send(body);
}

/** The raw stored preference map (absent when nothing was ever turned off). */
async function storedPreferences(userId: string): Promise<Record<string, unknown> | undefined> {
  const doc = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(userId) });
  const settings = doc!['settings'] as Record<string, unknown> | undefined;
  return settings?.['notifications'] as Record<string, unknown> | undefined;
}

/** Changes the password through the real route: a critical event. */
async function changePassword(user: TestUser): Promise<void> {
  const res = await send('put', '/user/change-password', user, {
    currentAuthHash: user.authHash,
    newAuthHash: 'changed-auth-hash-value',
    newEncryptedVaultKey: 'rewrapped-vault-key',
    newVaultKeyIv: 'rewrapped-iv',
    newVaultKeyTag: 'rewrapped-tag',
  });
  expect(res.status).toBe(200);
  await settle();
}

const subjectsTo = (address: string) =>
  transport.sent.filter((m) => m.to === address).map((m) => m.subject);

beforeEach(() => {
  transport.sent.length = 0;
});

afterEach(async () => {
  await settle();
  vi.restoreAllMocks();
});

describe('F-26: reading the preferences', () => {
  it('the profile lists every optional notice, on unless turned off, and never a mandatory one', async () => {
    const user = await createTestUser();
    const res = await send('get', '/user/profile', user);
    expect(res.status).toBe(200);
    expect(res.body.data.settings.notifications).toEqual(
      Object.fromEntries(SECURITY_NOTIFICATION_PREFERENCE_EVENTS.map((event) => [event, true])),
    );
    expect(res.body.data.settings.notifications).not.toHaveProperty('account_deletion_requested');
    expect(res.body.data.settings.notifications).not.toHaveProperty('security_notices_turned_off');
  });
});

describe('F-26: PUT /user/settings (no password)', () => {
  it.each(CRITICAL_SECURITY_NOTIFICATION_EVENTS)(
    'refuses turning off the critical notice %s, stores nothing, and the event still mails',
    async (event) => {
      const user = await createTestUser();
      const res = await send('put', '/user/settings', user, {
        theme: 'dark',
        notifications: { [event]: false },
      });
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('PUT /api/v1/user/notifications');
      expect(await storedPreferences(user.id)).toBeUndefined();
      const doc = await User.findById(user.id).lean();
      expect(doc!.settings.theme).toBe('system');
      if (event === 'password_changed') {
        await changePassword(user);
        expect(subjectsTo(user.email)).toEqual([PASSWORD_CHANGED]);
      }
    },
  );

  it('turns an optional notice off, after which the event sends nothing', async () => {
    const user = await createTestUser();
    const res = await send('put', '/user/settings', user, {
      notifications: { trusted_device_granted: false },
    });
    expect(res.status).toBe(200);
    expect(res.body.data.notifications.trusted_device_granted).toBe(false);
    expect(res.body.data.notifications.password_changed).toBe(true);
    expect(await storedPreferences(user.id)).toEqual({ trusted_device_granted: false });
    const audit = await AuditLog.findOne({ userId: user.id, action: 'settings_update' }).lean();
    expect(audit!.metadata).toEqual({ changedKeys: ['notifications.trusted_device_granted'] });
  });

  it('turns a critical notice back ON without a password', async () => {
    const user = await createTestUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { 'settings.notifications.password_changed': false } },
    );
    const res = await send('put', '/user/settings', user, {
      notifications: { password_changed: true },
    });
    expect(res.status).toBe(200);
    expect(res.body.data.notifications.password_changed).toBe(true);
    await changePassword(user);
    expect(subjectsTo(user.email)).toEqual([PASSWORD_CHANGED]);
  });

  it('refuses a mandatory notice or an unknown name as a preference', async () => {
    const user = await createTestUser();
    for (const name of ['account_deletion_requested', 'security_notices_turned_off', 'nope']) {
      const res = await send('put', '/user/settings', user, { notifications: { [name]: false } });
      expect(res.status).toBe(400);
    }
    expect(await storedPreferences(user.id)).toBeUndefined();
  });
});

describe('F-26: PUT /user/notifications (master password)', () => {
  it('requires the proof: missing → 400, wrong → 401 and audited; nothing stored, the event still mails', async () => {
    const user = await createTestUser();
    const missing = await send('put', '/user/notifications', user, {
      notifications: { password_changed: false },
    });
    expect(missing.status).toBe(400);
    const wrong = await send('put', '/user/notifications', user, {
      authHash: 'not-the-password',
      notifications: { password_changed: false },
    });
    expect(wrong.status).toBe(401);
    const failures = await AuditLog.find({
      userId: user.id,
      action: 'password_verification_failed',
    }).lean();
    expect(failures.map((row) => row.metadata)).toEqual([{ endpoint: 'notifications' }]);
    expect(await storedPreferences(user.id)).toBeUndefined();

    await changePassword(user);
    expect(subjectsTo(user.email)).toEqual([PASSWORD_CHANGED]);
  });

  it('with the proof turns a critical notice off, tells the owner once, and the event then sends nothing', async () => {
    const user = await createTestUser();
    const res = await send('put', '/user/notifications', user, {
      authHash: user.authHash,
      notifications: { password_changed: false, trusted_device_granted: false },
    });
    expect(res.status).toBe(200);
    expect(res.body.data.notifications.password_changed).toBe(false);
    expect(res.body.data.notifications.trusted_device_granted).toBe(false);
    expect(res.body.data.notifications.token_reuse_detected).toBe(true);
    expect(await storedPreferences(user.id)).toEqual({
      password_changed: false,
      trusted_device_granted: false,
    });
    await settle();
    // One mandatory notice, naming the critical one only.
    expect(subjectsTo(user.email)).toEqual([TURNED_OFF]);
    const notice = transport.sent[0]!.html;
    expect(notice).toContain('master password changes');
    expect(notice).not.toContain('browsers trusted');
    expect(notice).not.toContain(user.authHash);

    transport.sent.length = 0;
    await changePassword(user);
    expect(subjectsTo(user.email)).toEqual([]);
  });

  it('off, back on, and off again within the hour mails the "turned off" notice both times', async () => {
    // The owner's own "turned off" an hour ago says nothing about the second one,
    // which may be somebody else holding the password: it is never held back.
    const user = await createTestUser();
    const off = () =>
      send('put', '/user/notifications', user, {
        authHash: user.authHash,
        notifications: { password_changed: false },
      });

    expect((await off()).status).toBe(200);
    await settle();
    const on = await send('put', '/user/settings', user, {
      notifications: { password_changed: true },
    });
    expect(on.status).toBe(200);
    await settle();
    // Turning a notice back on mails nothing.
    expect(subjectsTo(user.email)).toEqual([TURNED_OFF]);
    expect((await off()).status).toBe(200);
    await settle();

    expect(subjectsTo(user.email)).toEqual([TURNED_OFF, TURNED_OFF]);
  });

  it('turning optional notices off with the proof sends no notice about it', async () => {
    const user = await createTestUser();
    const res = await send('put', '/user/notifications', user, {
      authHash: user.authHash,
      notifications: { trusted_device_granted: false },
    });
    expect(res.status).toBe(200);
    await settle();
    expect(transport.sent).toEqual([]);
  });

  it('refuses a proof of a password that changed before the write (401, nothing stored)', async () => {
    const user = await createTestUser();
    const original = User.findOneAndUpdate.bind(User);
    vi.spyOn(User, 'findOneAndUpdate').mockImplementationOnce(((
      ...args: Parameters<typeof original>
    ) => {
      const query = original(...args);
      const exec = query.exec.bind(query);
      // A reset lands between the proof and the write, i.e. when the write runs.
      query.exec = (async () => {
        await User.collection.updateOne(
          { _id: new mongoose.Types.ObjectId(user.id) },
          { $set: { authHash: '$2a$04$replacedreplacedreplacedreplacedreplacedreplacedrepl' } },
        );
        return exec();
      }) as typeof query.exec;
      return query;
    }) as unknown as typeof User.findOneAndUpdate);
    const res = await send('put', '/user/notifications', user, {
      authHash: user.authHash,
      notifications: { password_changed: false },
    });
    expect(res.status).toBe(401);
    expect(await storedPreferences(user.id)).toBeUndefined();
    await settle();
    expect(transport.sent).toEqual([]);
  });

  it('refuses an empty change, a mandatory notice and an unknown name', async () => {
    const user = await createTestUser();
    for (const notifications of [
      {},
      { account_deletion_requested: false },
      { security_notices_turned_off: false },
      { nope: true },
    ]) {
      const res = await send('put', '/user/notifications', user, {
        authHash: user.authHash,
        notifications,
      });
      expect(res.status).toBe(400);
    }
    expect(await storedPreferences(user.id)).toBeUndefined();
  });
});

describe('F-26: PUT /user/notifications for an account gone mid-request', () => {
  it('answers 404 and stores nothing when the account cannot be read', async () => {
    const user = await createTestUser();
    const original = User.findById.bind(User);
    let calls = 0;
    vi.spyOn(User, 'findById').mockImplementation(((...args: unknown[]) => {
      calls += 1;
      // The first read is authentication's; the second is the handler's.
      if (calls === 2) return original(new mongoose.Types.ObjectId());
      return (original as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof User.findById);
    const res = await send('put', '/user/notifications', user, {
      authHash: user.authHash,
      notifications: { password_changed: false },
    });
    expect(res.status).toBe(404);
    expect(await storedPreferences(user.id)).toBeUndefined();
  });
});

describe('F-26: a password reset takes the account back', () => {
  async function resetPassword(user: TestUser): Promise<request.Response> {
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
    const agent = request(app);
    const csrf = await getCsrf(agent);
    return agent
      .post(`${API}/auth/reset-password`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        token,
        email: user.email,
        newAuthHash: 'brand-new-auth-hash',
        newEncryptedVaultKey: 'new-enc-vault-key',
        newVaultKeyIv: 'new-vault-iv',
        newVaultKeyTag: 'new-vault-tag',
      });
  }

  it('turns every critical notice back on, and leaves the optional ones as chosen', async () => {
    const user = await createTestUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: {
          'settings.notifications.password_changed': false,
          'settings.notifications.token_reuse_detected': false,
          'settings.notifications.trusted_device_granted': false,
        },
      },
    );
    const res = await resetPassword(user);
    expect(res.status).toBe(200);
    expect(await storedPreferences(user.id)).toEqual({ trusted_device_granted: false });
  });

  it('also clears an opt-out written between its read and its save (a proof of the old password)', async () => {
    const user = await createTestUser();
    const original = User.findById.bind(User);
    let reads = 0;
    vi.spyOn(User, 'findById').mockImplementation(((...args: Parameters<typeof original>) => {
      const query = original(...args);
      reads += 1;
      // The first read is the test's own (the token's state hash); the second is
      // the reset's: the opt-out lands just after it, before the save.
      if (reads === 2) {
        const exec = query.exec.bind(query);
        query.exec = (async () => {
          const doc = await exec();
          await User.collection.updateOne(
            { _id: new mongoose.Types.ObjectId(user.id) },
            { $set: { 'settings.notifications.password_changed': false } },
          );
          return doc;
        }) as typeof query.exec;
      }
      return query;
    }) as unknown as typeof User.findById);
    const res = await resetPassword(user);
    expect(res.status).toBe(200);
    expect(reads).toBeGreaterThanOrEqual(2);
    expect(await storedPreferences(user.id)).toEqual({});
  });
});
