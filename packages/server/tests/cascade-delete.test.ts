import { describe, it, expect, beforeEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES, maskEmail } from '@hvault/shared';

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

/**
 * Storage is ON for this whole file, because the cascade's object sweep is what
 * most of the new cases are about. The unconfigured case is deliberately NOT
 * expressed here by flipping this flag mid-file: `storageConfigured` is a const
 * evaluated once at module load, and a per-test override would be a second,
 * subtler source of truth for it. It lives in `account-deletion-cascade.test.ts`,
 * which mocks no configuration at all and therefore runs with the document store
 * genuinely off — the state every 0.9.x deployment is in.
 */
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      if (storageRef.current === undefined) {
        throw new Error('the in-memory storage double was not installed for this test');
      }
      return storageRef.current;
    },
  };
});

import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { cascadeDeleteUser, cascadeDeleteTransactional } from '../src/utils/cascadeDelete.js';
import { createAuditLog } from '../src/services/auditService.js';
import { buildObjectKey, userObjectPrefix } from '../src/utils/documentObjects.js';
import { createInMemoryStorage, DEFAULT_MAX_KEYS } from './helpers/inMemoryStorage.js';
import { createTestUser, sampleVaultItem, sampleFolder } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';

/** A fresh in-memory bucket per test, so no case can see another's objects. */
beforeEach(() => {
  storageRef.current = createInMemoryStorage();
});

/**
 * A committed document row beside its object, as a completion leaves the pair.
 *
 * The bytes are a single sealed segment of 32 plaintext bytes; nothing here
 * decrypts anything, so the only property that matters is that row and object
 * agree on `ciphertextBytes` and that the key is the one `buildObjectKey` mints.
 */
async function seedDocument(userId: string): Promise<{ id: string; objectKey: string }> {
  const documentId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(userId, documentId.toHexString());
  const ciphertextBytes = 32 + DOCUMENT_TAG_BYTES;

  await Document.create({
    _id: documentId,
    userId,
    objectKey,
    encryptedDek: 'dek-ciphertext',
    dekIv: 'dek-iv',
    dekTag: 'dek-tag',
    streamSalt: Buffer.alloc(32, 7).toString('base64'),
    noncePrefix: Buffer.alloc(7, 3).toString('base64'),
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes,
    plaintextBytes: 32,
  });

  await storageRef.current!.putObject(objectKey, Buffer.alloc(ciphertextBytes, 0x5a));
  return { id: String(documentId), objectKey };
}

/**
 * A staging row for a transfer that never completed, beside the bytes of its
 * first (and here only) part.
 *
 * Seeded as a `PutObject`-shaped single-segment transfer: `s3UploadId` absent, so
 * the object already exists in the bucket under the key the committed row would
 * have carried. That is the state the sweep has to reach and a row-by-row walk of
 * `documents` never would.
 */
async function seedUpload(userId: string): Promise<{ id: string; objectKey: string }> {
  const uploadId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(userId, uploadId.toHexString());

  await DocumentUpload.create({
    _id: uploadId,
    userId,
    objectKey,
    encryptedDek: 'dek-ciphertext',
    dekIv: 'dek-iv',
    dekTag: 'dek-tag',
    streamSalt: Buffer.alloc(32, 7).toString('base64'),
    noncePrefix: Buffer.alloc(7, 3).toString('base64'),
    declaredPlaintextBytes: 32,
    declaredChunkCount: 1,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    receivedBytes: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  await storageRef.current!.putObject(objectKey, Buffer.alloc(DOCUMENT_TAG_BYTES + 32, 0x11));
  return { id: String(uploadId), objectKey };
}

/** Every key the bucket holds under one user's prefix. */
function keysFor(userId: string): string[] {
  const prefix = userObjectPrefix(userId);
  return storageRef.current!.storedKeys().filter((key) => key.startsWith(prefix));
}

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
    // Masked, under its own name (F-02): an erasure record that kept the address
    // in clear for a year would not have erased it.
    expect(logMeta.maskedEmail).toBe(maskEmail(userEmail));
    expect(logMeta).not.toHaveProperty('deletedEmail');
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
    // SEQUENTIAL path. Enter it with the flag CLEARED, and make the cascade's own
    // first write (the `deletionPending` mark, F-02) the one that fails: that is the
    // one state where the catch-block re-set is load-bearing rather than a no-op.
    await User.updateOne({ _id: userId }, { $set: { deletionPending: false } });

    const markSpy = vi
      .spyOn(User, 'updateOne')
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
      markSpy.mockRestore();
    }

    // The cascade did not complete...
    expect(result).toBe(false);
    // ...the user still exists (the mark failed before any data went)...
    const userAfter = await User.findById(userId).lean();
    expect(await VaultItem.countDocuments({ userId })).toBeGreaterThan(0);
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

    // Enter the cascade with the flag unset. The cascade's own first write sets
    // it again, so what this pins is that a FAILING re-set in the catch is
    // attempted (`updates === 2`), logged, and never escapes.
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
    // The cascade's FIRST write is its own `deletionPending` mark (F-02), so the
    // failure is aimed at the second `updateOne`: the re-set in the catch.
    const originalUpdateOne = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    let updates = 0;
    const updateSpy = vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      updates += 1;
      if (updates === 2) return Promise.reject(new Error('re-set failure'));
      return originalUpdateOne(...args);
    }) as never);

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
    expect(updates).toBe(2);

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

// ---------------------------------------------------------------------------
// The document store: rows, and the objects the rows are the only key to
// ---------------------------------------------------------------------------
//
// Two different obligations meet in this helper, and they fail in opposite ways.
//
// The ROW deletions are ordinary and easy to forget: nothing in `cascadeDeleteUser`
// is implicit, so a collection that is not named is simply never erased, and the
// account's documents would outlive the account — a GDPR erasure failure with no
// symptom anyone would notice.
//
// The OBJECT sweep is the opposite: it is best-effort, it runs after the rows are
// already gone, and the one thing it must never do is report failure. The caller's
// failure handling re-sets `deletionPending` on a user row that no longer exists,
// so a sweep that threw would make the zombie loop retry a deleted account for ever
// while every retry answered `false`. The cases below therefore assert the return
// value and the surviving rows on the failing path just as hard as they assert the
// deleted bytes on the happy one.
//
// Storage is a DOUBLE here (`helpers/inMemoryStorage.ts`) and Mongo is real, which
// is the seam the whole server suite uses: object storage is an external service in
// the same class as SMTP, while every "the row is gone" assertion below is a
// statement about a real database.
describe('cascadeDeleteUser — the document store', () => {
  let userId: string;
  let userEmail: string;

  beforeEach(async () => {
    const testUser = await createTestUser();
    userId = testUser.id;
    userEmail = testUser.email;
  });

  async function erase(): Promise<boolean> {
    return cascadeDeleteUser({
      userId,
      userEmail,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });
  }

  it('erases the account document rows, its staging rows and its stored objects, and touches no other account', async () => {
    const kept = await createTestUser();
    const keptDocument = await seedDocument(kept.id);

    await seedDocument(userId);
    await seedDocument(userId);
    await seedUpload(userId);

    expect(keysFor(userId)).toHaveLength(3);

    const result = await erase();

    expect(result).toBe(true);
    expect(await User.findById(userId)).toBeNull();
    expect(await Document.countDocuments({ userId })).toBe(0);
    expect(await DocumentUpload.countDocuments({ userId })).toBe(0);
    expect(keysFor(userId)).toEqual([]);

    // The negative that matters: `u/<userId>/` is a prefix, and a sweep that
    // dropped its trailing slash or listed the whole bucket would reach here.
    expect(await Document.countDocuments({ userId: kept.id })).toBe(1);
    expect(keysFor(kept.id)).toEqual([keptDocument.objectKey]);
    expect(storageRef.current!.readObject(keptDocument.objectKey)).toBeDefined();
  });

  it('erases an object whose row is already gone, which a per-row walk never would', async () => {
    // The state an interrupted earlier deletion leaves: the row was removed, the
    // object was not. Nothing in `documents` names this key any more, so the only
    // thing that can find it is the prefix listing.
    const orphanKey = buildObjectKey(userId, new mongoose.Types.ObjectId().toHexString());
    await storageRef.current!.putObject(orphanKey, Buffer.alloc(DOCUMENT_TAG_BYTES, 0x7f));

    expect(await erase()).toBe(true);
    expect(keysFor(userId)).toEqual([]);
  });

  it('follows the listing past the engine page boundary instead of erasing only the first page', async () => {
    // The provider's contract makes pagination the CALLER's, and one account may
    // own thousands of objects against an engine page of a thousand. A sweep that
    // read a single page would leave the remainder of the account's ciphertext in
    // the bucket, so the count here is deliberately one past that boundary.
    for (let i = 0; i <= DEFAULT_MAX_KEYS; i += 1) {
      const key = buildObjectKey(userId, new mongoose.Types.ObjectId().toHexString());
      await storageRef.current!.putObject(key, Buffer.alloc(DOCUMENT_TAG_BYTES, 0x22));
    }
    expect(keysFor(userId)).toHaveLength(DEFAULT_MAX_KEYS + 1);

    expect(await erase()).toBe(true);
    expect(keysFor(userId)).toEqual([]);
  });

  it('still reports success, erases every row and logs the failing key when the object sweep fails', async () => {
    const seeded = await seedDocument(userId);
    loggerError.mockClear();

    const failure = new Error('storage engine unreachable');
    const deleteSpy = vi
      .spyOn(storageRef.current!, 'deleteObject')
      .mockRejectedValue(failure as never);

    let result: boolean;
    try {
      result = await erase();
    } finally {
      deleteSpy.mockRestore();
    }

    // The erasure DID happen, so the answer must be true. A `false` here re-sets
    // `deletionPending` on a user row that is gone, and the zombie loop then
    // retries a deleted account on every cycle for ever.
    expect(result).toBe(true);
    expect(await User.findById(userId)).toBeNull();
    expect(await Document.countDocuments({ userId })).toBe(0);
    expect(await DocumentUpload.countDocuments({ userId })).toBe(0);

    // The operator gets the signal, naming the account, so the residue is
    // attributable rather than silent.
    expect(
      loggerError.mock.calls.some(
        (call) =>
          String(call[0]).includes('could not erase every stored object') &&
          String(call[0]).includes(userId) &&
          String(call[0]).includes(seeded.objectKey),
      ),
    ).toBe(true);

    // And the bytes really are still there — the assertion that keeps this case
    // honest, since a sweep that silently succeeded would pass everything above.
    expect(keysFor(userId)).toHaveLength(1);
  });

  it('names the prefix listing, not a key, when the sweep cannot even list the account', async () => {
    // The other half of the failure log. When `listObjects` is what fails, no key
    // has been reached yet, so the message must say so rather than naming a key
    // it never saw — an operator reading "stopped at u/…/d/…" would go looking for
    // one object when the whole listing is what did not happen.
    await seedDocument(userId);
    loggerError.mockClear();

    const listSpy = vi
      .spyOn(storageRef.current!, 'listObjects')
      .mockRejectedValue(new Error('listing refused') as never);

    let result: boolean;
    try {
      result = await erase();
    } finally {
      listSpy.mockRestore();
    }

    expect(result).toBe(true);
    expect(await Document.countDocuments({ userId })).toBe(0);
    expect(
      loggerError.mock.calls.some((call) =>
        String(call[0]).includes('stopped at the prefix listing'),
      ),
    ).toBe(true);
    // No key was reached, so nothing was deleted.
    expect(keysFor(userId)).toHaveLength(1);
  });

  // Restated for F-02 (PLAN.md 3.2): erasure is forward-only, so a failure after
  // the batches leaves the document ROWS already gone. What must still hold is the
  // ordering this feature exists for: no stored object is touched until the erasure
  // completes, and the re-run's prefix sweep reclaims it.
  it('does not touch a single stored object when the row deletion itself fails, and the re-run sweeps it', async () => {
    const seeded = await seedDocument(userId);
    await User.updateOne({ _id: userId }, { $set: { deletionPending: false } });

    const deleteSpy = vi
      .spyOn(VaultItem, 'deleteMany')
      .mockRejectedValueOnce(new Error('forced sequential failure'));

    let result: boolean;
    try {
      result = await erase();
    } finally {
      deleteSpy.mockRestore();
    }

    expect(result).toBe(false);
    // The object survives the failed run: it is swept only once the erasure has
    // finished, never while a run that failed may have left a row naming it.
    expect(keysFor(userId)).toEqual([seeded.objectKey]);
    // The account is still there and flagged, so the zombie loop retries it.
    const userAfter = await User.findById(userId).lean();
    expect(userAfter?.deletionPending).toBe(true);

    expect(await erase()).toBe(true);
    expect(await Document.countDocuments({ userId })).toBe(0);
    expect(keysFor(userId)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The transactional path, against a real replica set
// ---------------------------------------------------------------------------
//
// `MongoMemoryServer` is standalone, so every block above takes the SEQUENTIAL
// branch: the transaction's own body — including whether the two document
// collections are erased inside the session, and whether an abort puts them back —
// is unreachable from there. `useReplicaSetConnection()` points the process-wide
// mongoose singleton at a single-node replica set for this block and restores it
// afterwards.
describe('cascadeDeleteUser — transactional path with the document store', () => {
  useReplicaSetConnection({ timeoutMs: 120_000 });

  it('erases both document collections inside the transaction and then sweeps the objects', async () => {
    const user = await createTestUser();
    await seedDocument(user.id);
    await seedUpload(user.id);

    const result = await cascadeDeleteUser({
      userId: user.id,
      userEmail: user.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    expect(result).toBe(true);
    expect(await User.findById(user.id)).toBeNull();
    expect(await Document.countDocuments({ userId: user.id })).toBe(0);
    expect(await DocumentUpload.countDocuments({ userId: user.id })).toBe(0);
    expect(keysFor(user.id)).toEqual([]);
  });

  // Restated for F-02 (PLAN.md 3.2): the document collections are erased in
  // batches BEFORE the final transaction, so an abort no longer rolls them back.
  // The invariant kept: an aborted erasure sweeps no object, leaves the account
  // pending, and the re-run finishes the rows and then the objects.
  it('an abort sweeps no object and leaves the account pending; the re-run finishes rows and objects', async () => {
    const user = await createTestUser();
    const seeded = await seedDocument(user.id);
    const staged = await seedUpload(user.id);
    const untouched = [seeded.objectKey, staged.objectKey].sort();
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: false } });

    // Fail the straggler sweep INSIDE the transaction.
    const auditSpy = vi
      .spyOn(AuditLog, 'deleteMany')
      .mockRejectedValueOnce(new Error('forced transactional failure'));

    let result: boolean;
    try {
      result = await cascadeDeleteUser({
        userId: user.id,
        userEmail: user.email,
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        auditAction: 'account_delete',
      });
    } finally {
      auditSpy.mockRestore();
    }

    expect(result).toBe(false);
    expect(keysFor(user.id)).toEqual(untouched);
    const userAfter = await User.findById(user.id).lean();
    expect(userAfter?.deletionPending).toBe(true);
    expect(await AuditLog.countDocuments({ userId: null, action: 'account_delete' })).toBe(0);

    expect(
      await cascadeDeleteUser({
        userId: user.id,
        userEmail: user.email,
        ip: '127.0.0.1',
        userAgent: 'test-agent',
        auditAction: 'account_delete',
      }),
    ).toBe(true);
    expect(await Document.countDocuments({ userId: user.id })).toBe(0);
    expect(await DocumentUpload.countDocuments({ userId: user.id })).toBe(0);
    expect(keysFor(user.id)).toEqual([]);
    expect(await AuditLog.countDocuments({ userId: null, action: 'account_delete' })).toBe(1);
  });
});
