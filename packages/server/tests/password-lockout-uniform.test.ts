/**
 * F-03 — a PASSWORD lockout answers unproven clients uniformly, at uniform cost,
 * with bounded accounting, and never touches existing sessions.
 *
 * Before: during a lockout the CORRECT password earned a distinct
 * `403 ACCOUNT_LOCKED` while a wrong one earned the generic 401 — so a lockout
 * confirmed a guessed password to whoever made it — and neither answer counted
 * or audited the attempt, and every existing session was refused at refresh for
 * as long as a stranger kept the account locked.
 *
 * After, for a login that presents no valid device proof for the account:
 *
 *   (a) a right and a wrong password get the SAME generic 401 and write the SAME
 *       audit row (`login_failed{reason:'locked'}`): nothing the audit-log API
 *       returns says which one was right;
 *   (b) a proven client proceeds (device-proof.test.ts pins the proof itself);
 *   (c) refresh is never refused for either factor's lockout;
 *   (d) the accounting is bounded: the counter never passes MAX, the deadline
 *       moves at most once a minute, the rows coalesce per minute with a count;
 *   (d2) the stranger-writable audit actions are capped per account;
 *   (e) both branches perform the same awaited writes, and an unregistered
 *       address performs the same round trips while writing nothing.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendAccountUnlockEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import mongoose from 'mongoose';
import {
  MAX_LOGIN_ATTEMPTS,
  MAX_STRANGER_AUDIT_ROWS_PER_USER,
  STRANGER_WRITABLE_AUDIT_ACTIONS,
} from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { sendAccountUnlockEmail } from '../src/utils/email.js';
import * as auditService from '../src/services/auditService.js';
import { hashToken } from '../src/utils/token.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';
import { advanceClockBy, installTestClock, uninstallTestClock } from './clock.js';

const API = '/api/v1';
const LOCKOUT_MS = 30 * 60 * 1000;
const mockedUnlockEmail = vi.mocked(sendAccountUnlockEmail);

async function postLogin(email: string, authHash: string): Promise<request.Response> {
  const agent = request(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login`)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ email, authHash });
}

async function refreshWith(user: TestUser): Promise<request.Response> {
  const agent = request(app);
  const csrf = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
  return agent
    .post(`${API}/auth/refresh`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', `${csrf.cookie}; refreshToken=${user.refreshToken}`);
}

async function lockPassword(userId: string, until = new Date(Date.now() + LOCKOUT_MS)) {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    {
      $set: {
        failedLoginAttempts: MAX_LOGIN_ATTEMPTS,
        lockoutUntil: until,
        lockoutEpisodeId: 'pw-episode',
        lockoutNotifiedAt: new Date(),
      },
    },
  );
}

async function rawUser(userId: string): Promise<Record<string, unknown>> {
  const doc = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(userId) });
  expect(doc).not.toBeNull();
  return doc as unknown as Record<string, unknown>;
}

async function lockedRows(userId: string) {
  return AuditLog.find({ userId, action: 'login_failed', 'metadata.reason': 'locked' })
    .sort({ timestamp: 1 })
    .lean();
}

/** The generic 401 body, minus nothing: status, message, statusCode, statusText. */
function answerOf(res: request.Response): unknown {
  return { status: res.status, body: res.body as unknown };
}

beforeEach(() => {
  mockedUnlockEmail.mockReset();
  mockedUnlockEmail.mockResolvedValue({ success: true, message: 'sent' });
});

afterEach(() => {
  uninstallTestClock();
  vi.restoreAllMocks();
});

describe('F-03 (a) — during a password lockout a right and a wrong password are indistinguishable', () => {
  it(
    "after ten wrong passwords, the owner's correct password from a new client gets the " +
      "generic 401 and an audit row identical to a wrong guess's",
    async () => {
      const user = await createTestUser({ emailVerified: true });
      for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
        expect((await postLogin(user.email, 'stranger-guess')).status).toBe(401);
      }
      expect((await rawUser(user.id))['lockoutUntil']).toBeInstanceOf(Date);

      installTestClock();
      const wrong = await postLogin(user.email, 'another-guess');
      // Separate minutes, so the two attempts land on two rows that can be compared.
      advanceClockBy(61_000);
      const right = await postLogin(user.email, user.rawPassword);

      expect(right.status).toBe(401);
      expect(right.body.message).toBe('Invalid email or password');
      expect(answerOf(right)).toEqual(answerOf(wrong));
      // The headers differ in nothing either: the same set of names, the same cookies
      // (none minting a session or a device proof).
      expect(Object.keys(right.headers).sort()).toEqual(Object.keys(wrong.headers).sort());
      expect(right.headers['set-cookie']).toEqual(wrong.headers['set-cookie']);
      expect(String(right.headers['set-cookie'] ?? '')).not.toMatch(/refreshToken=|__hv_device=/);
      expect(right.body.data).toBeUndefined();
      expect(JSON.stringify(right.body)).not.toContain('ACCOUNT_LOCKED');
      uninstallTestClock();

      // What the audit-log API returns for the two attempts differs in nothing
      // but its identity and its time.
      const agent = request(app);
      const log = await agent
        .get(`${API}/user/audit-log?page=1&limit=100&action=login_failed`)
        .set('Authorization', authHeader(user.accessToken));
      expect(log.status).toBe(200);
      const locked = (log.body.data as Record<string, unknown>[]).filter(
        (row) => (row['metadata'] as { reason?: string } | undefined)?.reason === 'locked',
      );
      expect(locked).toHaveLength(2);
      const strip = (row: Record<string, unknown>) => {
        const { _id: _i, timestamp: _t, ...rest } = row;
        return rest;
      };
      expect(strip(locked[0]!)).toEqual(strip(locked[1]!));
      expect(locked[0]!['metadata']).toEqual({ reason: 'locked' });
      // No session was minted for the right password.
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(0);
    },
    60_000,
  );
});

describe('F-03 (c) — refresh is never refused for a lockout', () => {
  it('an existing session refreshes under a PASSWORD lockout', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const res = await refreshWith(user);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));
    expect(JSON.stringify(res.body)).not.toContain('ACCOUNT_LOCKED');
  });

  it('an existing session refreshes under a SECOND-FACTOR lockout', async () => {
    const user = await createTestUser({ emailVerified: true });
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: {
          secondFactorLockout: {
            failedAttempts: MAX_LOGIN_ATTEMPTS,
            until: new Date(Date.now() + LOCKOUT_MS),
            episodeId: 'e',
          },
        },
      },
    );

    const res = await refreshWith(user);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toEqual(expect.any(String));
  });

  it('negative: a refresh token that was replayed is still refused (reuse detection intact)', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    await RefreshToken.updateOne(
      { tokenHash: hashToken(user.refreshToken) },
      { $set: { usedAt: new Date() } },
    );
    const res = await refreshWith(user);
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TOKEN_REUSE_DETECTED');
  });
});

describe('F-03 (d) — the accounting of a running lockout is bounded', () => {
  it(
    'counter capped, deadline moved at most once a minute, rows coalesced per minute with a ' +
      'count, and User writes bounded',
    async () => {
      // Audit rows coalesce per wall-clock MINUTE, so the start is pinned one second
      // into a minute: the first five attempts (0-4 s) and the four after the jump
      // (65-68 s) each fall inside one minute whatever second the suite starts in.
      installTestClock({ at: Math.floor(Date.now() / 60_000) * 60_000 + 60_000 + 1_000 });
      const user = await createTestUser({ emailVerified: true });
      const until = new Date(Date.now() + LOCKOUT_MS);
      await lockPassword(user.id, until);
      const initial = JSON.stringify(await rawUser(user.id));

      // Five unproven attempts inside one minute of a fresh lockout.
      let modified = 0;
      let previous = initial;
      // One second apart, so an extension on every attempt would move the deadline
      // every time (with a frozen clock it would rewrite the same value unnoticed).
      for (let i = 0; i < 5; i++) {
        if (i > 0) advanceClockBy(1_000);
        const res = await postLogin(user.email, i % 2 === 0 ? 'guess' : user.rawPassword);
        expect(res.status).toBe(401);
        const now = JSON.stringify(await rawUser(user.id));
        if (now !== previous) modified += 1;
        previous = now;
      }
      expect(modified).toBe(0);
      let stored = await rawUser(user.id);
      expect(stored['failedLoginAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
      expect((stored['lockoutUntil'] as Date).getTime()).toBe(until.getTime());
      let rows = await lockedRows(user.id);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.count).toBe(5);

      // A minute later the guessing continues: the deadline moves exactly once.
      advanceClockBy(61_000);
      const extendedAt = Date.now();
      modified = 0;
      for (let i = 0; i < 4; i++) {
        if (i > 0) advanceClockBy(1_000);
        const res = await postLogin(user.email, 'guess');
        expect(res.status).toBe(401);
        const now = JSON.stringify(await rawUser(user.id));
        if (now !== previous) modified += 1;
        previous = now;
      }
      expect(modified).toBe(1);
      stored = await rawUser(user.id);
      expect(stored['failedLoginAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
      expect((stored['lockoutUntil'] as Date).getTime()).toBe(extendedAt + LOCKOUT_MS);
      // The episode (and so the link already mailed) survives the extension.
      expect(stored['lockoutEpisodeId']).toBe('pw-episode');
      rows = await lockedRows(user.id);
      expect(rows.map((row) => row.count)).toEqual([5, 4]);
    },
    60_000,
  );

  it('an extended lockout mails a fresh link once the outstanding one would lapse', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id, new Date(Date.now() + 10 * 60 * 1000));
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { lockoutNotifiedAt: new Date(Date.now() - 2 * 60 * 60 * 1000) } },
    );

    const res = await postLogin(user.email, 'guess');
    expect(res.status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
    expect(mockedUnlockEmail.mock.calls[0]![0]).toBe(user.email);

    // Once mailed, the next extension a minute later does not mail again.
    installTestClock();
    advanceClockBy(61_000);
    expect((await postLogin(user.email, 'guess')).status).toBe(401);
    expect(mockedUnlockEmail).toHaveBeenCalledTimes(1);
  });

  it('an unproven correct password neither clears nor restarts the lockout', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);
    const before = await rawUser(user.id);

    const res = await postLogin(user.email, user.rawPassword);
    expect(res.status).toBe(401);

    const after = await rawUser(user.id);
    expect(after['failedLoginAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
    expect(after['lockoutEpisodeId']).toBe(before['lockoutEpisodeId']);
  });
});

describe('F-03 (d2) — the stranger-writable audit actions have their own cap', () => {
  it(
    'MAX_STRANGER_AUDIT_ROWS_PER_USER + 200 stranger rows leave exactly the cap, newest kept, ' +
      "and the owner's own rows untouched",
    async () => {
      const user = await createTestUser({ emailVerified: true });
      const userId = new mongoose.Types.ObjectId(user.id);
      const base = Date.now() - 24 * 60 * 60 * 1000;

      // The owner's own history, older than every stranger row.
      await AuditLog.insertMany([
        {
          userId,
          action: 'login',
          ipAddress: 'o',
          userAgent: 'o',
          timestamp: new Date(base - 5000),
        },
        {
          userId,
          action: 'item_create',
          ipAddress: 'o',
          userAgent: 'o',
          timestamp: new Date(base - 4000),
        },
      ]);
      const seeded = MAX_STRANGER_AUDIT_ROWS_PER_USER + 100;
      await AuditLog.insertMany(
        Array.from({ length: seeded }, (_, i) => ({
          userId,
          action: STRANGER_WRITABLE_AUDIT_ACTIONS[i % STRANGER_WRITABLE_AUDIT_ACTIONS.length],
          ipAddress: 's',
          userAgent: 's',
          timestamp: new Date(base + i * 1000),
        })),
      );

      // One hundred more through the service, as requests would write them.
      for (let i = 0; i < 100; i++) {
        await auditService.createAuditLog(
          user.id,
          'login_failed',
          { reason: 'invalid_password' },
          '203.0.113.9',
          'stranger',
        );
      }

      const strangerRows = await AuditLog.find({
        userId,
        action: { $in: [...STRANGER_WRITABLE_AUDIT_ACTIONS] },
      })
        .sort({ timestamp: 1 })
        .lean();
      expect(strangerRows).toHaveLength(MAX_STRANGER_AUDIT_ROWS_PER_USER);
      // Newest kept: the oldest survivor is seeded row #200, and every row the
      // service wrote survived.
      expect(strangerRows[0]!.timestamp.getTime()).toBe(base + 200 * 1000);
      expect(strangerRows.filter((row) => row.ipAddress === '203.0.113.9')).toHaveLength(100);
      // The owner's rows are not the stranger's to evict.
      expect(await AuditLog.countDocuments({ userId, action: 'login' })).toBe(1);
      expect(await AuditLog.countDocuments({ userId, action: 'item_create' })).toBe(1);
    },
    120_000,
  );

  it('a full tracking map trims an untracked account at once instead of forgetting it', async () => {
    const victim = await createTestUser({ emailVerified: true });
    const victimId = new mongoose.Types.ObjectId(victim.id);
    await AuditLog.insertMany(
      Array.from({ length: MAX_STRANGER_AUDIT_ROWS_PER_USER + 3 }, (_, i) => ({
        userId: victimId,
        action: 'login_failed',
        ipAddress: 's',
        userAgent: 's',
        timestamp: new Date(Date.now() - 1_000_000 + i),
      })),
    );

    // Spray enough other accounts to fill the process-local tracker.
    auditService.resetStrangerAuditTracking();
    for (let i = 0; i < auditService.STRANGER_AUDIT_TRACKED_ACCOUNTS; i++) {
      await auditService.noteStrangerWritableInsert(new mongoose.Types.ObjectId().toString());
    }
    await auditService.noteStrangerWritableInsert(victim.id);

    expect(await AuditLog.countDocuments({ userId: victimId })).toBe(
      MAX_STRANGER_AUDIT_ROWS_PER_USER,
    );
    auditService.resetStrangerAuditTracking();
  });
});

describe('F-03 (e) — uniform cost', () => {
  type Call = string;

  /** Records every write the two models are asked to make, in order. */
  function recordWrites(): Call[] {
    const calls: Call[] = [];
    const methods = [
      'updateOne',
      'updateMany',
      'findOneAndUpdate',
      'create',
      'insertMany',
    ] as const;
    for (const model of [User, AuditLog] as const) {
      for (const method of methods) {
        const target = model as unknown as Record<string, (...args: unknown[]) => unknown>;
        const original = target[method]!.bind(model);
        vi.spyOn(target, method).mockImplementation(((...args: unknown[]) => {
          calls.push(`${model.modelName}.${method}`);
          return original(...args);
        }) as never);
      }
    }
    return calls;
  }

  it('the right-hash and wrong-hash branches of a locked login perform the same awaited writes', async () => {
    const user = await createTestUser({ emailVerified: true });
    await lockPassword(user.id);

    const wrongCalls = recordWrites();
    expect((await postLogin(user.email, 'guess')).status).toBe(401);
    vi.restoreAllMocks();
    const rightCalls = recordWrites();
    expect((await postLogin(user.email, user.rawPassword)).status).toBe(401);
    vi.restoreAllMocks();

    expect(rightCalls).toEqual(wrongCalls);
    // Not merely equal: each is the bounded accounting, one write per model.
    expect(wrongCalls).toEqual(['User.updateOne', 'AuditLog.updateOne']);
  });

  it('an account mid-deletion makes the same round trips for a right password, and writes nothing', async () => {
    const user = await createTestUser({ emailVerified: true });
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $set: { deletionPending: true } },
    );
    const before = JSON.stringify(await rawUser(user.id));
    const rowsBefore = await AuditLog.countDocuments({ userId: user.id });
    const tokensBefore = await RefreshToken.countDocuments({ userId: user.id });

    const calls = recordWrites();
    const res = await postLogin(user.email, user.rawPassword);
    vi.restoreAllMocks();

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid email or password');
    expect(calls).toEqual(['User.updateOne', 'AuditLog.updateOne']);
    expect(JSON.stringify(await rawUser(user.id))).toBe(before);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(rowsBefore);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(tokensBefore);
  });

  it('an unregistered address makes the same round trips, and writes nothing', async () => {
    const rowsBefore = await AuditLog.countDocuments({});
    const usersBefore = await User.countDocuments({});

    const calls = recordWrites();
    const res = await postLogin('nobody-at-all@example.com', 'guess');
    vi.restoreAllMocks();

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid email or password');
    expect(calls).toEqual(['User.updateOne', 'AuditLog.updateOne']);
    expect(await AuditLog.countDocuments({})).toBe(rowsBefore);
    expect(await User.countDocuments({})).toBe(usersBefore);
  });
});
