/**
 * F-05, the edges of the backup-recipient rules: what happens when the database,
 * the relay, the budget or the timing does not cooperate. The main behaviour is
 * pinned in `backup-recipients.test.ts`; every case here drives a path that suite
 * does not, and each names what must NOT happen as well as what must.
 */
import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Document } from '../src/models/Document.js';
import { config } from '../src/config/index.js';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import {
  confirmedRecipientsFor,
  currentRecipientsFor,
  recordUndeliverableBackup,
  sendDueConfirmations,
  sendOwedRecipientConfirmations,
  suspendThirdPartyRecipients,
} from '../src/utils/backupRecipients.js';
import { claimOutboundMail } from '../src/utils/outboundMailBudget.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  deriveTestPurposeKey,
  type TestUser,
} from './helpers.js';
import { seedConfirmedRecipients } from './support/backupRecipients.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';

interface SentMail {
  to: string;
  subject: string;
  html: string;
  attachments?: { filename: string }[] | undefined;
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
    config: { ...actual.config, SMTP_HOST: 'smtp.edges.test', SMTP_USER: 'u', SMTP_PASS: 'p' },
  };
});

const cronCallbacks = vi.hoisted(() => ({ list: [] as (() => Promise<void>)[] }));
vi.mock('node-cron', () => ({
  default: {
    schedule: (_expr: string, cb: () => Promise<void>) => {
      cronCallbacks.list.push(cb);
      return { stop: () => undefined };
    },
  },
}));

const CONFIRM_LINK = /\/backup\/confirm-recipient#token=([A-Za-z0-9._%-]+)/;
const backupMailsTo = () =>
  transport.sent.filter((m) => (m.attachments ?? []).length > 0).map((m) => m.to);
const confirmationMailsTo = () =>
  transport.sent.filter((m) => CONFIRM_LINK.test(m.html)).map((m) => m.to);
const utcDay = () => new Date().toISOString().slice(0, 10);

async function send(
  method: 'put' | 'post',
  path: string,
  body: Record<string, unknown>,
  accessToken?: string,
): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent);
  const req = agent[method](path).set('x-csrf-token', csrf.token).set('Cookie', csrf.cookie);
  if (accessToken !== undefined) req.set('Authorization', authHeader(accessToken));
  return req.send(body);
}

async function backupUser(overrides: { emailVerified?: boolean } = {}): Promise<TestUser> {
  const user = await createTestUser(overrides);
  await User.updateOne(
    { _id: user.id },
    {
      $set: {
        'settings.backup.encryptedBWK': 'bwk',
        'settings.backup.bwkIv': 'iv',
        'settings.backup.bwkTag': 'tag',
        'settings.backup.bwkSalt': 'salt',
        'settings.backup.isConfigured': true,
        'settings.backup.enabled': true,
        'settings.backup.scheduleHour': new Date().getUTCHours(),
      },
    },
  );
  return user;
}

/** An owner-approved address still owed its confirmation mail, stored raw. */
async function seedOwed(userId: string, email: string, extra: Record<string, unknown> = {}) {
  await User.collection.updateOne({ _id: new mongoose.Types.ObjectId(userId) }, {
    $push: {
      'settings.backup.backupRecipients': {
        email,
        state: 'pending',
        confirmedAt: null,
        approvedAt: new Date(),
        confirmationDue: true,
        confirmationSentAt: null,
        confirmationAttempts: 0,
        nonce: crypto.randomBytes(32).toString('hex'),
        ...extra,
      },
    },
  } as never);
}

async function owedCount(userId: string): Promise<number> {
  const doc = await User.findById(userId).lean();
  return (doc?.settings.backup.backupRecipients ?? []).filter((r) => r.confirmationDue).length;
}

async function runScheduledBackup(): Promise<void> {
  startBackupScheduler();
  await cronCallbacks.list.at(-1)!();
}

beforeEach(() => {
  transport.sent.length = 0;
  transport.fail = false;
});

describe('the list update when the world moves underneath it', () => {
  it('answers 404 when the account vanished after authentication, and stores nothing', async () => {
    const user = await backupUser();
    const original = User.findById.bind(User);
    let calls = 0;
    const spy = vi.spyOn(User, 'findById').mockImplementation(((...args: unknown[]) => {
      calls += 1;
      // The first read is authentication's; the second is the handler's.
      if (calls === 2) return original(new mongoose.Types.ObjectId());
      return (original as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof User.findById);
    let res: request.Response;
    try {
      res = await send(
        'put',
        '/api/v1/backup/recipients',
        { authHash: user.authHash, backupEmails: ['x@example.org'] },
        user.accessToken,
      );
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(404);
    expect((await User.findById(user.id).lean())!.settings.backup.backupRecipients).toBeUndefined();
    expect(transport.sent).toEqual([]);
  });

  it('still answers 200 with the stored list when sending the confirmations fails on the database; the mails stay owed', async () => {
    const user = await backupUser();
    const original = User.updateOne.bind(User);
    const spy = vi.spyOn(User, 'updateOne').mockImplementation(((
      filter: Record<string, unknown>,
      ...rest: unknown[]
    ) => {
      const elem = (filter['settings.backup.backupRecipients'] ?? {}) as {
        $elemMatch?: { confirmationDue?: boolean };
      };
      if (elem.$elemMatch?.confirmationDue === true) {
        return Promise.reject(new Error('database unavailable'));
      }
      return (original as (...a: unknown[]) => unknown)(filter, ...rest);
    }) as unknown as typeof User.updateOne);
    let res: request.Response;
    try {
      res = await send(
        'put',
        '/api/v1/backup/recipients',
        { authHash: user.authHash, backupEmails: ['owed@example.org'] },
        user.accessToken,
      );
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(200);
    expect(res.body.data.confirmationsSent).toBe(0);
    expect(res.body.data.confirmationsPending).toBe(1);
    expect(transport.sent).toEqual([]);
    expect(await owedCount(user.id)).toBe(1);
  });
});

describe('a manual backup whose only recipient is suspended while it is built', () => {
  it('sends nothing, answers 409 and records no_confirmed_recipient', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['only@example.org']);
    const original = Document.aggregate.bind(Document);
    const spy = vi
      .spyOn(Document, 'aggregate')
      .mockImplementationOnce(((...args: unknown[]) =>
        suspendThirdPartyRecipients(user.id).then(() =>
          (original as (...a: unknown[]) => unknown)(...args),
        )) as unknown as typeof Document.aggregate);
    let res: request.Response;
    try {
      res = await send('post', '/api/v1/backup/trigger', {}, user.accessToken);
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(409);
    expect(backupMailsTo()).toEqual([]);
    const audit = await AuditLog.find({ userId: user.id, action: 'backup_failed' }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ reason: 'no_confirmed_recipient' }]);
  });
});

describe('the scheduler at the edges', () => {
  it('records daily_mail_budget and mails nothing when the budget is spent', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['one@example.org']);
    await User.updateOne(
      { _id: user.id },
      { $set: { outboundMail: { day: utcDay(), count: 30 } } },
    );

    await runScheduledBackup();

    expect(transport.sent).toEqual([]);
    const log = await BackupLog.findOne({ userId: user.id }).lean();
    expect(log!.status).toBe('failed');
    expect(log!.errorMessage).toMatch(/daily backup email limit/i);
    const audit = await AuditLog.find({ userId: user.id, action: 'backup_failed' }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ reason: 'daily_mail_budget' }]);
  });

  it('mails nothing at all for an unverified account with no list: no backup, no notice', async () => {
    const user = await backupUser({ emailVerified: false });

    await runScheduledBackup();

    expect(transport.sent).toEqual([]);
    expect((await BackupLog.findOne({ userId: user.id }).lean())!.status).toBe('failed');
  });

  it('keeps going when recording an undeliverable run fails', async () => {
    const failing = await backupUser();
    await seedOwed(failing.id, 'never@example.org');
    const healthy = await backupUser();
    await seedConfirmedRecipients(healthy.id, ['fine@example.org']);
    const original = BackupLog.create.bind(BackupLog);
    const spy = vi
      .spyOn(BackupLog, 'create')
      .mockImplementation(((doc: { userId?: unknown }) =>
        String(doc.userId) === failing.id
          ? Promise.reject(new Error('backup log unavailable'))
          : (original as (d: unknown) => unknown)(doc)) as unknown as typeof BackupLog.create);
    try {
      await runScheduledBackup();
    } finally {
      spy.mockRestore();
    }

    expect(backupMailsTo()).toEqual(['fine@example.org']);
  });

  it('skips the not-sent notice when the day budget is spent, and logs a notice the relay refuses', async () => {
    const spent = await backupUser();
    await seedOwed(spent.id, 'x@example.org');
    await User.updateOne(
      { _id: spent.id },
      { $set: { outboundMail: { day: utcDay(), count: 30 } } },
    );
    await runScheduledBackup();
    expect(transport.sent).toEqual([]);

    const refused = await backupUser();
    await seedOwed(refused.id, 'y@example.org');
    await User.updateOne({ _id: spent.id }, { $set: { 'settings.backup.enabled': false } });
    transport.fail = true;
    await runScheduledBackup();
    transport.fail = false;

    expect(transport.sent).toEqual([]);
    // The notice was attempted (the episode is claimed) and the budget spent on it.
    const doc = await User.findById(refused.id).select('+outboundMail').lean();
    expect((doc as unknown as { outboundMail: { count: number } }).outboundMail.count).toBe(1);
    expect(doc!.settings.backup.undeliverableNoticedAt).toBeInstanceOf(Date);
  });
});

const CHANGED_PASSWORD = {
  newAuthHash: 'changed-auth-hash-value',
  newEncryptedVaultKey: 'rewrapped-vault-key',
  newVaultKeyIv: 'rewrapped-iv',
  newVaultKeyTag: 'rewrapped-tag',
};

/** Makes the password change's own conditional vault-key write match nothing, once. */
function supersedeTheVaultKeyWrite() {
  const original = User.updateOne.bind(User);
  return vi.spyOn(User, 'updateOne').mockImplementation(((
    filter: Record<string, unknown>,
    update: { $set?: Record<string, unknown> },
    ...rest: unknown[]
  ) => {
    if ('vaultKeyVersion' in filter && update.$set?.['authHash'] !== undefined) {
      return Promise.resolve({ acknowledged: true, matchedCount: 0, modifiedCount: 0 });
    }
    return (original as (...a: unknown[]) => unknown)(filter, update, ...rest);
  }) as unknown as typeof User.updateOne);
}

async function recipientState(userId: string): Promise<string | undefined> {
  return (await User.findById(userId).lean())?.settings.backup.backupRecipients?.[0]?.state;
}

describe('a password change whose vault-key write is superseded (sequential branch)', () => {
  it('answers 409; the suspension made before the write has committed and stands', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['third@example.org']);
    const spy = supersedeTheVaultKeyWrite();
    let res: request.Response;
    try {
      res = await send(
        'put',
        '/api/v1/user/change-password',
        { currentAuthHash: user.authHash, ...CHANGED_PASSWORD },
        user.accessToken,
      );
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(409);
    expect(await recipientState(user.id)).toBe('suspended');
  });
});

describe('a password change on a replica set (transactional branch)', () => {
  useReplicaSetConnection({ timeoutMs: 120_000 });

  beforeAll(() => {
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  });

  it('suspends third-party recipients in the same transaction as the new password', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['third@example.org']);

    const res = await send(
      'put',
      '/api/v1/user/change-password',
      { currentAuthHash: user.authHash, ...CHANGED_PASSWORD },
      user.accessToken,
    );

    expect(res.status).toBe(200);
    expect(await recipientState(user.id)).toBe('suspended');
    const audit = await AuditLog.find({
      userId: user.id,
      action: 'backup_recipients_suspended',
    }).lean();
    expect(audit.map((row) => row.metadata)).toEqual([{ count: 1, reason: 'password_change' }]);
  });

  it('rolls the suspension back with an aborted transaction, and audits none', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['third@example.org']);
    const spy = supersedeTheVaultKeyWrite();
    let res: request.Response;
    try {
      res = await send(
        'put',
        '/api/v1/user/change-password',
        { currentAuthHash: user.authHash, ...CHANGED_PASSWORD },
        user.accessToken,
      );
    } finally {
      spy.mockRestore();
    }

    expect(res.status).toBe(409);
    expect(await recipientState(user.id)).toBe('confirmed');
    expect(
      await AuditLog.countDocuments({ userId: user.id, action: 'backup_recipients_suspended' }),
    ).toBe(0);
  });
});

describe('confirmation tokens with malformed claims', () => {
  it('refuses a token that does not verify at all', async () => {
    const res = await send('post', '/api/v1/backup/recipients/confirm', { token: 'not.a.token' });

    expect(res.status).toBe(400);
  });

  it.each([
    [
      'a user id that is not an ObjectId',
      { userId: 'not-an-id', email: 'a@example.org', nonce: 'n' },
    ],
    ['a non-string address', { email: 42, nonce: 'n' }],
    ['an empty nonce', { email: 'a@example.org', nonce: '' }],
    ['a missing nonce', { email: 'a@example.org' }],
  ])('refuses %s', async (_label, claims) => {
    const user = await backupUser();
    await seedOwed(user.id, 'a@example.org');
    const token = jwt.sign(
      { userId: user.id, purpose: 'backup_recipient', ...claims },
      deriveTestPurposeKey('backup_recipient'),
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    const res = await send('post', '/api/v1/backup/recipients/confirm', { token });

    expect(res.status).toBe(400);
    const doc = await User.findById(user.id).lean();
    expect(doc!.settings.backup.backupRecipients![0]!.state).toBe('pending');
  });
});

describe('sending confirmations', () => {
  it('two senders at once mail each address once', async () => {
    const user = await backupUser();
    await seedOwed(user.id, 'a@example.org');
    await seedOwed(user.id, 'b@example.org');

    const [first, second] = await Promise.all([
      sendDueConfirmations(user.id),
      sendDueConfirmations(user.id),
    ]);

    expect(first.sent + second.sent).toBe(2);
    expect(confirmationMailsTo().sort()).toEqual(['a@example.org', 'b@example.org']);
    expect(await owedCount(user.id)).toBe(0);
  });

  it('reports everything owed and sends nothing for an account being erased, or one that is gone', async () => {
    const user = await backupUser();
    await seedOwed(user.id, 'a@example.org');
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    expect(await sendDueConfirmations(user.id)).toEqual({ sent: 0, pending: 1 });
    expect(await sendDueConfirmations(new mongoose.Types.ObjectId().toString())).toEqual({
      sent: 0,
      pending: 0,
    });
    expect(transport.sent).toEqual([]);
  });

  it('counts a failed send against an entry stored without an attempt count', async () => {
    const user = await backupUser();
    await seedOwed(user.id, 'old@example.org', { confirmationAttempts: undefined });
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $unset: { 'settings.backup.backupRecipients.0.confirmationAttempts': '' } },
    );
    transport.fail = true;

    expect(await sendDueConfirmations(user.id)).toEqual({ sent: 0, pending: 1 });

    const entry = (await User.findById(user.id).lean())!.settings.backup.backupRecipients![0]!;
    expect(entry.confirmationAttempts).toBe(1);
    expect(entry.confirmationDue).toBe(true);
  });

  it('the hourly step does nothing while email is not configured, and leaves the mails owed', async () => {
    const user = await backupUser();
    await seedOwed(user.id, 'a@example.org');
    const host = config.SMTP_HOST;
    (config as { SMTP_HOST: string | undefined }).SMTP_HOST = '';
    try {
      await sendOwedRecipientConfirmations();
    } finally {
      (config as { SMTP_HOST: string | undefined }).SMTP_HOST = host;
    }

    expect(transport.sent).toEqual([]);
    expect(await owedCount(user.id)).toBe(1);
  });

  it('the hourly step stops at its time budget after one account, and one failing account does not stop it', async () => {
    const broken = await backupUser();
    await seedOwed(broken.id, 'broken@example.org');
    const first = await backupUser();
    await seedOwed(first.id, 'first@example.org');
    const second = await backupUser();
    await seedOwed(second.id, 'second@example.org');

    const original = User.findById.bind(User);
    const spy = vi.spyOn(User, 'findById').mockImplementation(((
      id: unknown,
      ...rest: unknown[]
    ) => {
      if (String(id) === broken.id) throw new Error('database unavailable');
      return (original as (...a: unknown[]) => unknown)(id, ...rest);
    }) as unknown as typeof User.findById);
    try {
      // A zero budget still finishes one account; the failing one is logged and passed.
      await sendOwedRecipientConfirmations(0);
      const afterFirstRun = confirmationMailsTo().length;
      expect(afterFirstRun).toBeLessThanOrEqual(1);
      await sendOwedRecipientConfirmations(60_000);
    } finally {
      spy.mockRestore();
    }

    expect(confirmationMailsTo().sort()).toEqual(['first@example.org', 'second@example.org']);
    expect(await owedCount(broken.id)).toBe(1);
  });
});

describe('an account being erased', () => {
  it('records nothing and mails nothing for an undeliverable run', async () => {
    const user = await backupUser();
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });
    const audit = vi.fn(() => Promise.resolve());

    await recordUndeliverableBackup(user.id, 'no_confirmed_recipient', audit);

    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    expect(audit).not.toHaveBeenCalled();
    expect(transport.sent).toEqual([]);
  });

  it('refuses a confirmation link', async () => {
    const user = await backupUser();
    await send(
      'put',
      '/api/v1/backup/recipients',
      { authHash: user.authHash, backupEmails: ['r@example.org'] },
      user.accessToken,
    );
    const match = CONFIRM_LINK.exec(transport.sent.find((m) => m.to === 'r@example.org')!.html);
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    const res = await send('post', '/api/v1/backup/recipients/confirm', {
      token: decodeURIComponent(match![1]!),
    });

    expect(res.status).toBe(400);
    const entry = (await User.findById(user.id).lean())!.settings.backup.backupRecipients![0]!;
    expect(entry.state).toBe('pending');
  });
});

describe('small rules', () => {
  it('an unverified account with no list has nobody to mail', () => {
    expect(
      confirmedRecipientsFor({
        email: 'a@example.org',
        emailVerified: false,
        settings: { backup: {} },
      }),
    ).toEqual([]);
  });

  it('a fresh read of an account that no longer exists names nobody', async () => {
    expect(await currentRecipientsFor(new mongoose.Types.ObjectId().toString())).toEqual([]);
  });

  it('suspends inside a caller session', async () => {
    const user = await backupUser();
    await seedConfirmedRecipients(user.id, ['s@example.org']);
    const session = await mongoose.startSession();
    try {
      expect(await suspendThirdPartyRecipients(user.id, session)).toBe(1);
    } finally {
      await session.endSession();
    }
    expect((await User.findById(user.id).lean())!.settings.backup.backupRecipients![0]!.state).toBe(
      'suspended',
    );
  });

  it.each([0, -1, 1.5, 31, Number.NaN])('never claims %s messages', async (count) => {
    const user = await createTestUser();

    expect(await claimOutboundMail(user.id, count)).toBe(false);
    const doc = await User.findById(user.id).select('+outboundMail').lean();
    expect((doc as unknown as { outboundMail?: unknown }).outboundMail).toBeUndefined();
  });
});

describe('migration v4 at the edges', () => {
  async function freshMigrations(): Promise<void> {
    await mongoose.connection.collection('migrations').deleteMany({ version: 4 });
  }

  it('tolerates an existing index built differently, and fails on any other index error', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    const users = mongoose.connection.collection('users');

    await freshMigrations();
    const conflict = vi
      .spyOn(users, 'createIndex')
      .mockRejectedValueOnce(Object.assign(new Error('options conflict'), { code: 85 }));
    try {
      await expect(runMigrations()).resolves.toBeUndefined();
    } finally {
      conflict.mockRestore();
    }

    await freshMigrations();
    const other = vi
      .spyOn(users, 'createIndex')
      .mockRejectedValueOnce(Object.assign(new Error('not authorised'), { code: 13 }));
    try {
      await expect(runMigrations()).rejects.toThrow('not authorised');
    } finally {
      other.mockRestore();
    }
    // A failed migration is not recorded, so the next start retries it.
    expect(await mongoose.connection.collection('migrations').countDocuments({ version: 4 })).toBe(
      0,
    );
  });

  it('a second run changes nothing (idempotent)', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    await freshMigrations();
    const user = await createTestUser();
    await User.collection.updateOne(
      { email: user.email },
      { $set: { 'settings.backup.backupEmails': ['legacy@example.org'] } },
    );
    await runMigrations();
    const first = await User.collection.findOne({ email: user.email });

    await freshMigrations();
    await runMigrations();

    const second = await User.collection.findOne({ email: user.email });
    expect(second!['settings']).toEqual(first!['settings']);
    expect(transport.sent).toEqual([]);
  });

  it('converts more accounts than one write batch, and a non-array legacy value lists nobody', async () => {
    const { runMigrations } = await import('../src/utils/migrations.js');
    await freshMigrations();
    const docs = Array.from({ length: 501 }, (_, i) => ({
      email: `bulk${String(i)}@example.org`,
      emailVerified: true,
      settings: { backup: { backupEmails: [`r${String(i)}@example.org`] } },
    }));
    docs.push({
      email: 'odd@example.org',
      emailVerified: true,
      settings: { backup: { backupEmails: { 0: 'not-a-list@example.org' } as never } },
    });
    await User.collection.insertMany(docs);

    await runMigrations();

    const converted = await User.collection.countDocuments({
      'settings.backup.backupRecipients.0.state': 'pending',
      email: /^bulk/,
    });
    expect(converted).toBe(501);
    const odd = await User.collection.findOne({ email: 'odd@example.org' });
    expect(
      (odd!['settings'] as { backup: Record<string, unknown> }).backup['backupRecipients'],
    ).toEqual([]);
    expect(transport.sent).toEqual([]);
  });
});
