import { describe, it, expect, beforeEach, vi } from 'vitest';
import mongoose from 'mongoose';

// Capture logger output so the "logs prominently" test can assert the operator
// signal, and so the cascade modules resolve a logger. Hoisted so the (also
// hoisted) mock factory can reference it. Mirrors phase5-job-resilience.
const { loggerError, loggerInfo, loggerWarn, loggerDebug } = vi.hoisted(() => ({
  loggerError: vi.fn(),
  loggerInfo: vi.fn(),
  loggerWarn: vi.fn(),
  loggerDebug: vi.fn(),
}));

vi.mock('@hiprax/logger', async (importOriginal) => {
  const original = await importOriginal<typeof import('@hiprax/logger')>();
  return {
    ...original,
    createLogger: () => ({
      error: loggerError,
      info: loggerInfo,
      warn: loggerWarn,
      debug: loggerDebug,
    }),
  };
});

import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { cascadeDeleteUser, cascadeDeleteTransactional } from '../src/utils/cascadeDelete.js';
import { createAuditLog } from '../src/services/auditService.js';
import { createTestUser, sampleVaultItem, sampleFolder } from './helpers.js';

describe('cascadeDeleteUser', () => {
  let userId: string;
  let userEmail: string;

  beforeEach(async () => {
    const testUser = await createTestUser();
    userId = testUser.id;
    userEmail = testUser.email;

    // Create associated data for the user
    await VaultItem.create({ ...sampleVaultItem(), userId });
    await VaultItem.create({ ...sampleVaultItem(), userId });
    await Folder.create({ ...sampleFolder(), userId });
    await AuditLog.create({
      userId,
      action: 'login',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });
    await BackupLog.create({
      userId,
      status: 'success',
      sentTo: ['test@example.com'],
    });
  });

  it('deletes all associated data for a user', async () => {
    const result = await cascadeDeleteUser({
      userId,
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    expect(result).toBe(true);
    expect(await User.findById(userId)).toBeNull();
    expect(await VaultItem.countDocuments({ userId })).toBe(0);
    expect(await Folder.countDocuments({ userId })).toBe(0);
    expect(await RefreshToken.countDocuments({ userId })).toBe(0);
    expect(await AuditLog.countDocuments({ userId })).toBe(0);
    expect(await BackupLog.countDocuments({ userId })).toBe(0);
  });

  it('creates a system-scoped audit log entry that survives deletion', async () => {
    await cascadeDeleteUser({
      userId,
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    // System audit log has userId: null (stored in metadata)
    const systemLogs = await AuditLog.find({ userId: null, action: 'account_delete' });
    expect(systemLogs.length).toBeGreaterThanOrEqual(1);
    const logMeta = systemLogs[0]!.metadata as Record<string, unknown>;
    expect(logMeta.deletedUserId).toBe(userId);
    expect(logMeta.deletedEmail).toBe(userEmail);
  });

  it('does not affect other users data (cross-user isolation)', async () => {
    const otherUser = await createTestUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: otherUser.id });
    await Folder.create({ ...sampleFolder(), userId: otherUser.id });

    await cascadeDeleteUser({
      userId,
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    // Original user is deleted
    expect(await User.findById(userId)).toBeNull();

    // Other user's data is intact
    expect(await User.findById(otherUser.id)).not.toBeNull();
    expect(await VaultItem.countDocuments({ userId: otherUser.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: otherUser.id })).toBe(1);
  });

  it('allows re-registration after deletion', async () => {
    await cascadeDeleteUser({
      userId,
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    // Re-register with the same email
    const newUser = await User.create({
      email: userEmail,
      authHash: 'new-auth-hash',
      emailVerified: true,
      encryptedVaultKey: 'new-key',
      vaultKeyIv: 'new-iv',
      vaultKeyTag: 'new-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
    });

    expect(newUser.email).toBe(userEmail);
    expect(newUser._id.toString()).not.toBe(userId);
  });

  it('works with deletion_cleanup audit action', async () => {
    await cascadeDeleteUser({
      userId,
      userEmail,
      ip: 'system',
      userAgent: 'system/token-cleanup-job',
      auditAction: 'deletion_cleanup',
    });

    expect(await User.findById(userId)).toBeNull();
    const systemLogs = await AuditLog.find({ userId: null, action: 'deletion_cleanup' });
    expect(systemLogs.length).toBeGreaterThanOrEqual(1);
  });

  it('re-sets deletionPending on sequential failure', async () => {
    // MongoMemoryServer is standalone, so cascadeDeleteUser routes to the
    // SEQUENTIAL path. Enter it with the flag CLEARED — the one state where the
    // catch-block re-set is load-bearing rather than a no-op.
    await User.updateOne({ _id: userId }, { $set: { deletionPending: false } });

    // Force the first sequential delete to throw so the catch block runs.
    const deleteSpy = vi
      .spyOn(VaultItem, 'deleteMany')
      .mockRejectedValueOnce(new Error('forced sequential failure'));

    let result: boolean;
    try {
      result = await cascadeDeleteUser({
        userId,
        userEmail,
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        auditAction: 'account_delete',
      });
    } finally {
      deleteSpy.mockRestore();
    }

    // The cascade did not complete...
    expect(result).toBe(false);
    // ...the user still exists (nothing was deleted)...
    const userAfter = await User.findById(userId).lean();
    expect(userAfter).not.toBeNull();
    // ...and deletionPending was restored so the next cleanup cycle retries.
    expect(userAfter!.deletionPending).toBe(true);
  });

  it('handles user with no associated data', async () => {
    // Create a fresh user with no items, folders, etc.
    const bareUser = await createTestUser();

    // Delete the refresh token created by createTestUser
    await RefreshToken.deleteMany({ userId: bareUser.id });

    const result = await cascadeDeleteUser({
      userId: bareUser.id,
      userEmail: bareUser.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    expect(result).toBe(true);
    expect(await User.findById(bareUser.id)).toBeNull();
  });

  it('handles userId as ObjectId type', async () => {
    const result = await cascadeDeleteUser({
      userId: new mongoose.Types.ObjectId(userId),
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    expect(result).toBe(true);
    expect(await User.findById(userId)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// createAuditLog: session forwarding (Task 2.1)
// ---------------------------------------------------------------------------
//
// The transactional cascade-delete path runs every write inside a MongoDB
// session so the entire operation aborts atomically on failure. Until this
// fix, the audit-log insert was the one write that ran outside the session,
// which meant a mid-flight transaction abort would leave the audit row behind
// while the user, items, folders, and refresh tokens still existed — a clear
// violation of the "logged events reflect committed state" invariant.
//
// MongoMemoryServer in this test suite is a standalone instance and cannot
// run multi-document transactions, so we exercise the contract at the layer
// it lives in: `createAuditLog` must forward `{ session }` to
// `AuditLog.create` when the option is provided. Together with the call-site
// change in `cascadeDeleteTransactional`, this guarantees the audit row
// commits or aborts together with the surrounding writes on a real
// replica-set deployment.
describe('createAuditLog session forwarding', () => {
  it('forwards the session option to AuditLog.create when provided', async () => {
    const createSpy = vi.spyOn(AuditLog, 'create').mockResolvedValueOnce([] as unknown as never);

    const fakeSession = { id: 'fake-session' } as unknown as mongoose.ClientSession;

    await createAuditLog(
      null,
      'account_delete',
      { deletedUserId: 'u', deletedEmail: 'a@b.co' },
      '127.0.0.1',
      'test-agent',
      { session: fakeSession },
    );

    expect(createSpy).toHaveBeenCalledTimes(1);
    const call = createSpy.mock.calls[0]!;
    // Mongoose accepts `Model.create([doc], { session })` for session-bound writes.
    expect(Array.isArray(call[0])).toBe(true);
    expect(call[1]).toMatchObject({ session: fakeSession });

    createSpy.mockRestore();
  });

  it('does not pass any options to AuditLog.create when no session is given', async () => {
    const createSpy = vi.spyOn(AuditLog, 'create').mockResolvedValueOnce({} as unknown as never);

    await createAuditLog(null, 'account_delete', undefined, '127.0.0.1', 'test-agent');

    expect(createSpy).toHaveBeenCalledTimes(1);
    const call = createSpy.mock.calls[0]!;
    // Standalone-mode call retains the single-doc form (no array, no options).
    expect(Array.isArray(call[0])).toBe(false);
    expect(call[1]).toBeUndefined();

    createSpy.mockRestore();
  });

  it('sequential cascade completes and leaves no orphan audit row when the audit insert fails', async () => {
    // A swallowed audit-insert failure must NOT abort the cascade: `createAuditLog`
    // wraps `AuditLog.create` in try/catch (auditService), so the sequential path
    // still erases the account. If that swallow were ever removed, the rejection
    // would propagate into `cascadeDeleteSequential`'s catch, `result` would be
    // `false`, and the user would survive — all caught here.
    const target = await createTestUser();
    await RefreshToken.deleteMany({ userId: target.id });
    await VaultItem.create({ ...sampleVaultItem(), userId: target.id });
    await Folder.create({ ...sampleFolder(), userId: target.id });

    // Force the (single) audit insert to throw.
    const createSpy = vi
      .spyOn(AuditLog, 'create')
      .mockRejectedValueOnce(new Error('forced audit failure'));

    let result: boolean;
    try {
      result = await cascadeDeleteUser({
        userId: target.id,
        userEmail: target.email,
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        auditAction: 'account_delete',
      });
    } finally {
      createSpy.mockRestore();
    }

    // The swallowed audit failure did NOT abort the cascade.
    expect(result).toBe(true);
    expect(await User.findById(target.id)).toBeNull();
    expect(await VaultItem.countDocuments({ userId: target.id })).toBe(0);
    expect(await Folder.countDocuments({ userId: target.id })).toBe(0);

    // And no audit row leaked (the only insert was rejected).
    const orphanLogs = await AuditLog.find({
      action: 'account_delete',
      'metadata.deletedUserId': target.id,
    });
    expect(orphanLogs.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Transactional path: deletionPending re-set on transaction abort
// ---------------------------------------------------------------------------
//
// `deletionPending` is the sole durable signal that a user's data still needs
// erasing, so no caller clears it before the erasure is durable: both
// `userController.deleteAccount` and the `tokenCleanup` zombie loop leave it
// SET across the cascade. `cascadeDeleteTransactional`'s re-set on abort is
// therefore a defensive backstop — it is the one place that can restore the
// retry signal if the flag is ever found unset when the transaction aborts.
// This suite exercises that backstop directly, by clearing the flag itself and
// asserting the abort path restores it.
//
// MongoMemoryServer is standalone and cannot run multi-document transactions,
// so we exercise the contract by calling the exported transactional helper
// directly and forcing one of its writes to throw. The catch block must
// restore `deletionPending: true` regardless of whether the transaction
// itself was real or simulated.
describe('cascadeDeleteTransactional — deletionPending re-set on failure', () => {
  it('re-sets deletionPending: true after transaction abort', async () => {
    const target = await createTestUser();
    await RefreshToken.deleteMany({ userId: target.id });

    // Drive the backstop: enter the cascade with the flag unset, the one state
    // in which the abort-time re-set is load-bearing rather than a no-op.
    await User.updateOne({ _id: target.id }, { $set: { deletionPending: false } });

    // Force the very first write inside the transaction to throw. This
    // exercises the catch block without depending on real replica-set
    // transaction support.
    const deleteSpy = vi
      .spyOn(VaultItem, 'deleteMany')
      .mockRejectedValueOnce(new Error('forced transactional failure'));

    let result: boolean;
    try {
      result = await cascadeDeleteTransactional(
        target.id,
        target.email,
        '127.0.0.1',
        'test-agent',
        'deletion_cleanup',
      );
    } finally {
      deleteSpy.mockRestore();
    }

    expect(result).toBe(false);

    // The user must still exist (the transaction aborted before the User
    // delete) AND must be flagged as deletionPending: true so the next
    // cleanup cycle retries.
    const userAfter = await User.findById(target.id).lean();
    expect(userAfter).not.toBeNull();
    expect(userAfter!.deletionPending).toBe(true);
  });

  it('logs prominently when the deletionPending re-set itself fails', async () => {
    const target = await createTestUser();
    await RefreshToken.deleteMany({ userId: target.id });

    loggerError.mockClear();

    const deleteSpy = vi
      .spyOn(VaultItem, 'deleteMany')
      .mockRejectedValueOnce(new Error('forced transactional failure'));
    const updateSpy = vi
      .spyOn(User, 'updateOne')
      .mockRejectedValueOnce(new Error('re-set failure'));

    let result: boolean;
    try {
      result = await cascadeDeleteTransactional(
        target.id,
        target.email,
        '127.0.0.1',
        'test-agent',
        'deletion_cleanup',
      );
    } finally {
      deleteSpy.mockRestore();
      updateSpy.mockRestore();
    }

    // The catch must still return false (cascade did not complete) without
    // letting the inner re-set failure escape the function.
    expect(result).toBe(false);

    // The operator MUST get a prominent signal that this user now needs manual
    // intervention — the whole point of the inner catch. Asserting the log call
    // is what makes a silent `catch {}` regression turn this test red.
    expect(
      loggerError.mock.calls.some((call) =>
        String(call[0]).includes('Failed to re-set deletionPending'),
      ),
    ).toBe(true);
  });
});
