import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { maskEmail } from '@hvault/shared';

/**
 * F-21: an account whose address was never verified is provisional. It cannot
 * sign in, but it holds its address for ever, so whoever registered first (a
 * typo, or a squatter) kept the rightful owner out of it. `tokenCleanup` now
 * reaps every account still unverified `UNVERIFIED_ACCOUNT_TTL_DAYS` after it was
 * created, and only such an account:
 *
 *   - `emailVerified` must be EXACTLY `false` (a legacy row with no field is not
 *     provisional, whatever the sign-in check makes of it);
 *   - an account that owns any vault, folder or document row is never reaped;
 *   - each account is CLAIMED with a conditional `deletionPending` write before
 *     the cascade, and `verifyEmail` writes only while the account is not being
 *     erased, so a verification racing the reaper either wins (and the account
 *     stays) or is refused (and the erasure finishes): never a verified account
 *     with half its data gone.
 *
 * The cascade is REAL here: what is asserted is the erasure, not a call.
 */

vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

import cron from 'node-cron';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import {
  createTestUser,
  deriveTestPurposeKey,
  generateStateHash,
  getCsrf,
  type CsrfPair,
} from './helpers.js';

const API = '/api/v1';
const DAY_MS = 24 * 60 * 60 * 1000;
const REAPED = 'unverified_account_reaped';

const mockedSchedule = vi.mocked(cron.schedule);

async function runTokenCleanup(): Promise<void> {
  startTokenCleanupJob();
  const calls = mockedSchedule.mock.calls;
  const callback = calls[calls.length - 1]![1] as () => Promise<void>;
  await callback();
}

/** An account created `ageMs` ago, with the given verification state. */
async function accountAged(
  ageMs: number,
  verified: boolean | 'absent',
): Promise<{ id: string; email: string }> {
  const user = await createTestUser({ emailVerified: verified === true });
  const update: Record<string, unknown> = {
    $set: { createdAt: new Date(Date.now() - ageMs) },
  };
  if (verified === 'absent') update['$unset'] = { emailVerified: 1 };
  // Raw, so neither timestamps nor the schema default rewrite what is planted.
  await User.collection.updateOne({ _id: new mongoose.Types.ObjectId(user.id) }, update);
  return { id: user.id, email: user.email };
}

function verificationToken(userId: string): string {
  return jwt.sign(
    { userId, purpose: 'email_verification', stateHash: generateStateHash(String(false)) },
    deriveTestPurposeKey('email_verification'),
    { algorithm: 'HS256', expiresIn: '24h' },
  );
}

const ttlMs = (): number => config.UNVERIFIED_ACCOUNT_TTL_DAYS * DAY_MS;

describe('F-21: never-verified accounts are reaped by tokenCleanup', () => {
  it('UNVERIFIED_ACCOUNT_TTL_DAYS defaults to seven days', () => {
    expect(config.UNVERIFIED_ACCOUNT_TTL_DAYS).toBe(7);
  });

  it('erases an unverified account older than the TTL, records it masked, and frees the address', async () => {
    const victim = await accountAged(ttlMs() + 60_000, false);
    const owner = new mongoose.Types.ObjectId(victim.id);
    expect(await RefreshToken.countDocuments({ userId: owner })).toBe(1);

    await runTokenCleanup();

    expect(await User.findById(victim.id).lean()).toBeNull();
    expect(await RefreshToken.countDocuments({ userId: owner })).toBe(0);

    // ONE system row, outside every account's log, naming the account by id with
    // the address masked; the address in clear appears nowhere in it.
    const rows = await AuditLog.find({ action: REAPED }).lean();
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.userId).toBeNull();
    expect(row.metadata).toEqual({
      deletedUserId: victim.id,
      maskedEmail: maskEmail(victim.email),
    });
    expect(JSON.stringify(row)).not.toContain(victim.email);
    expect(row.ipAddress).toBe('system');

    // The address can be registered again by its rightful owner.
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/register`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        email: victim.email,
        authHash: 'a-fresh-auth-hash',
        encryptedVaultKey: 'enc-vault-key',
        vaultKeyIv: 'vault-iv',
        vaultKeyTag: 'vault-tag',
        kdfIterations: 600_000,
        kdfAlgorithm: 'PBKDF2-SHA256',
        encryptionVersion: 1,
      });
    expect(res.status).toBe(201);
    const fresh = await User.findOne({ email: victim.email }).lean();
    expect(fresh).not.toBeNull();
    expect(fresh!._id.toString()).not.toBe(victim.id);
    expect(fresh!.emailVerified).toBe(false);
  });

  it('keeps a young unverified account, an old verified one and an old one with no verification field', async () => {
    const young = await accountAged(ttlMs() - 60 * 60 * 1000, false);
    const verified = await accountAged(ttlMs() * 10, true);
    const legacy = await accountAged(ttlMs() * 10, 'absent');

    await runTokenCleanup();

    for (const kept of [young, verified, legacy]) {
      const row = await User.findById(kept.id).lean();
      expect(row).not.toBeNull();
      expect(row!.deletionPending).toBeUndefined();
    }
    expect(await AuditLog.countDocuments({ action: REAPED })).toBe(0);
  });

  it.each([
    ['a vault item', VaultItem],
    ['a folder', Folder],
    ['a document', Document],
    ['an upload in progress', DocumentUpload],
  ] as const)('never reaps an old unverified account that owns %s', async (_label, model) => {
    const holder = await accountAged(ttlMs() * 2, false);
    // Raw, so the row needs none of the model's other required fields: what is
    // under test is that the reaper sees an OWNED row, whatever its shape.
    await model.collection.insertOne({ userId: new mongoose.Types.ObjectId(holder.id) });

    await runTokenCleanup();

    const row = await User.findById(holder.id).lean();
    expect(row).not.toBeNull();
    expect(row!.deletionPending).toBeUndefined();
    expect(await model.collection.countDocuments({ userId: row!._id })).toBe(1);
    expect(await AuditLog.countDocuments({ action: REAPED })).toBe(0);
  });

  it('does not reap an account verified after it was selected (the claim is conditional)', async () => {
    const racer = await accountAged(ttlMs() * 2, false);
    // The ownership check runs between the selection and the claim: verify the
    // account there, exactly as a verification landing in that gap would.
    // (`tokenCleanup` reads no vault item before the reaper, so this is the first.)
    const original = VaultItem.collection.findOne.bind(VaultItem.collection);
    const exists = vi.spyOn(VaultItem.collection, 'findOne').mockImplementationOnce((async (
      ...args: Parameters<typeof original>
    ) => {
      await User.updateOne({ _id: racer.id }, { $set: { emailVerified: true } });
      return original(...args);
    }) as unknown as typeof original);
    let checks: number;
    try {
      await runTokenCleanup();
    } finally {
      // Read before the restore, which clears the record.
      checks = exists.mock.calls.length;
      exists.mockRestore();
    }
    // The race was really injected: the check ran, between selection and claim.
    expect(checks).toBeGreaterThan(0);

    const row = await User.findById(racer.id).lean();
    expect(row).not.toBeNull();
    expect(row!.emailVerified).toBe(true);
    expect(row!.deletionPending).toBeUndefined();
    expect(await AuditLog.countDocuments({ action: REAPED })).toBe(0);
  });
});

describe('F-21: verifyEmail never resurrects an account being erased', () => {
  let agent: ReturnType<typeof request.agent>;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function verify(token: string): request.Test {
    return agent
      .post(`${API}/auth/verify-email`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ token });
  }

  it('refuses a verification link for an account the reaper has already claimed', async () => {
    const claimed = await accountAged(ttlMs() * 2, false);
    await User.updateOne({ _id: claimed.id }, { $set: { deletionPending: true } });

    const res = await verify(verificationToken(claimed.id));

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('TOKEN_INVALID');
    const row = await User.findById(claimed.id).lean();
    expect(row!.emailVerified).toBe(false);
    expect(row!.deletionPending).toBe(true);
    expect(await AuditLog.countDocuments({ userId: row!._id, action: 'email_verified' })).toBe(0);
  });

  it('refuses when the claim lands between its read and its write', async () => {
    const racer = await accountAged(ttlMs() * 2, false);
    const original = User.findById.bind(User);
    // The read returns the account as it was (not pending); the reaper's claim
    // lands before the handler writes.
    vi.spyOn(User, 'findById').mockImplementationOnce(((id: unknown, ...rest: unknown[]) => {
      const query = original(id as string, ...(rest as []));
      return {
        then(resolve: (v: unknown) => unknown, reject: (e: unknown) => unknown) {
          return query
            .then(async (doc: unknown) => {
              await User.collection.updateOne(
                { _id: new mongoose.Types.ObjectId(racer.id) },
                { $set: { deletionPending: true } },
              );
              return doc;
            })
            .then(resolve, reject);
        },
      };
    }) as unknown as typeof User.findById);

    const res = await verify(verificationToken(racer.id));

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('TOKEN_INVALID');
    const row = await User.findById(racer.id).lean();
    expect(row!.emailVerified).toBe(false);
    expect(row!.deletionPending).toBe(true);
  });

  it('still verifies an account nobody is erasing', async () => {
    const user = await accountAged(60_000, false);

    const res = await verify(verificationToken(user.id));

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Email verified successfully');
    const row = await User.findById(user.id).lean();
    expect(row!.emailVerified).toBe(true);
    expect(row!.deletionPending).toBeUndefined();
    expect(await AuditLog.countDocuments({ userId: row!._id, action: 'email_verified' })).toBe(1);
  });

  it('verifies an account stored before the field existed (no emailVerified at all)', async () => {
    const legacy = await accountAged(60_000, 'absent');

    const res = await verify(verificationToken(legacy.id));

    expect(res.status).toBe(200);
    const row = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(legacy.id) });
    expect(row!['emailVerified']).toBe(true);
  });

  it('a verified account is kept by the next reaper run', async () => {
    const user = await accountAged(ttlMs() * 2, false);
    expect((await verify(verificationToken(user.id))).status).toBe(200);

    await runTokenCleanup();

    expect(await User.findById(user.id).lean()).not.toBeNull();
    expect(await AuditLog.countDocuments({ action: REAPED })).toBe(0);
  });
});
