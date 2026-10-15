/**
 * Account erasure leaves no plaintext address behind (F-02, Phase 3), including in
 * the invitations collection (F-24, Phase 5), and reads what it erases from the
 * primary.
 *
 * An invitation belongs to its INVITER (`userId`), and the cascade erases an
 * account's rows by `userId`, so an invitation that names the erased account as
 * its INVITEE (`email`) used to survive the erasure with the address in clear,
 * spent or not, until its seven-day expiry. The erasure now removes every
 * invitation naming the erased address as well, in the same final step that
 * removes the user row, on both branches.
 *
 * The batches are read from the PRIMARY: on a deployment whose URI asks for
 * `secondaryPreferred`, a lagging secondary would hand the next batch the ids the
 * previous one already deleted, and two such batches in a row trip the stall
 * guard on a perfectly healthy erasure.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { Invitation } from '../src/models/Invitation.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { cascadeDeleteTransactional, cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { createTestUser, type TestUser } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';

afterEach(() => {
  vi.restoreAllMocks();
});

async function seedInvitation(email: string, inviter: string | null, consumed: boolean) {
  return Invitation.create({
    tokenHash: crypto.randomBytes(32).toString('hex'),
    email,
    userId: inviter === null ? null : new mongoose.Types.ObjectId(inviter),
    expiresAt: new Date(Date.now() + 7 * 86_400_000),
    ...(consumed ? { consumedAt: new Date() } : {}),
  });
}

async function erase(victim: TestUser): Promise<boolean> {
  return cascadeDeleteUser({
    userId: victim.id,
    userEmail: victim.email,
    ip: '198.51.100.44',
    userAgent: 'the-owner',
    auditAction: 'account_delete',
  });
}

async function invitationsNaming(email: string): Promise<number> {
  return Invitation.countDocuments({ email: email.toLowerCase() });
}

async function eraseAndCheckInvitations(): Promise<void> {
  const inviter = await createTestUser({ emailVerified: true });
  const victim = await createTestUser({ emailVerified: true });
  // The invitation the victim registered with (spent), one still open for the same
  // address (operator-minted), and one the victim minted for somebody else.
  await seedInvitation(victim.email, inviter.id, true);
  await seedInvitation(victim.email, null, false);
  await seedInvitation('someone-else@example.org', victim.id, false);
  // Negative: an invitation for an unrelated address by an unrelated inviter.
  const bystander = await seedInvitation('bystander@example.org', inviter.id, false);

  expect(await erase(victim)).toBe(true);

  expect(await invitationsNaming(victim.email)).toBe(0);
  expect(await Invitation.countDocuments({ userId: victim.id })).toBe(0);
  expect(await Invitation.findById(bystander._id).lean()).not.toBeNull();
  // Nothing anywhere in the collection still carries the erased address.
  const local = victim.email.split('@')[0]!;
  const leftovers = await Invitation.find({}).lean();
  expect(JSON.stringify(leftovers)).not.toContain(local);
  // And the erasure was recorded as before.
  expect(await AuditLog.countDocuments({ userId: null, action: 'account_delete' })).toBeGreaterThan(
    0,
  );
}

describe('sequential branch (standalone)', () => {
  it('erases every invitation naming the erased address, spent or open, and no other', async () => {
    expect(supportsTransactions()).toBe(false);
    await eraseAndCheckInvitations();
  });

  it('reads every batch it erases from the primary', async () => {
    const victim = await createTestUser({ emailVerified: true });
    const finds: { collection: string; readPreference: unknown }[] = [];
    const real = mongoose.mongo.Collection.prototype.find;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const options = args[1] as { readPreference?: unknown } | undefined;
      finds.push({ collection: this.collectionName, readPreference: options?.readPreference });
      return real.apply(this, args);
    } as never);

    expect(await erase(victim)).toBe(true);

    const batchReads = finds.filter((read) =>
      ['audit_logs', 'vault_items', 'folders', 'invitations', 'device_proofs'].includes(
        read.collection,
      ),
    );
    expect(batchReads.length).toBeGreaterThanOrEqual(5);
    for (const read of batchReads) {
      expect(read.readPreference).toBe('primary');
    }
  });
});

describe('transactional branch (replica set)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    expect(supportsTransactions()).toBe(true);
  });

  it('erases every invitation naming the erased address inside the final transaction', async () => {
    await eraseAndCheckInvitations();
  });
});

describe('the transactional erasure when no session can be opened', () => {
  it('reports failure and leaves the account marked for the next attempt, never a crash of its own', async () => {
    const user = await createTestUser();
    vi.spyOn(mongoose, 'startSession').mockRejectedValueOnce(new Error('no session available'));

    // Its contract is a boolean: the caller re-runs a failed erasure later.
    await expect(
      cascadeDeleteTransactional(user.id, user.email, 'system', 'test', 'deletion_cleanup'),
    ).resolves.toBe(false);

    const row = await mongoose.connection
      .collection('users')
      .findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    expect(row).not.toBeNull();
    expect(row?.['deletionPending']).toBe(true);
  });
});
