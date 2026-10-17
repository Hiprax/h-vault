/**
 * F-02 — deleting an account stays small however large the account grew, and
 * leaves no plaintext address behind.
 *
 * The bulky per-account collections are erased in batches BEFORE the final
 * transaction, which is left with a sweep for rows written while the batches ran,
 * the trusted devices and the user row: a transaction sized by the account's
 * whole history is one MongoDB aborts at its lifetime limit, which would leave the
 * account undeletable. The erasure is idempotent and forward-only: a failure
 * leaves `deletionPending` set and the next run starts again from the top, every
 * finished batch being a no-op.
 *
 * The system row that survives the account records it with a MASKED address:
 * after erasure the address must not appear anywhere in the database.
 */
import { describe, it, expect, vi, afterEach, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { maskEmail } from '@hvault/shared';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { DeviceProof } from '../src/models/DeviceProof.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { useReplicaSetConnection } from './mongoHarness.js';

/** Every collection that holds rows keyed by `userId`, which erasure must empty. */
const TENANT_MODELS = {
  AuditLog,
  VaultItem,
  Folder,
  RefreshToken,
  BackupLog,
  Document,
  DocumentUpload,
  DeviceProof,
  TrustedDevice,
} as const;

/** The bulky ones: none of these may be erased inside the final transaction. */
const BULKY = [
  'AuditLog',
  'VaultItem',
  'Folder',
  'RefreshToken',
  'BackupLog',
  'Document',
  'DocumentUpload',
  'DeviceProof',
] as const;

const SIZES = {
  auditRows: 250_000,
  items: 5_000,
  tombstones: 2_000,
  folders: 300,
  backupLogs: 400,
  documents: 60,
  uploads: 5,
  deviceProofs: 50,
  trustedDevices: 10,
};

afterEach(() => {
  vi.restoreAllMocks();
});

function hex(): string {
  return crypto.randomBytes(16).toString('hex');
}

async function insertChunked(
  collection: mongoose.mongo.Collection,
  docs: Record<string, unknown>[],
): Promise<void> {
  for (let i = 0; i < docs.length; i += 20_000) {
    await collection.insertMany(docs.slice(i, i + 20_000), { ordered: false });
  }
}

/**
 * An account of the size F-02 is about, seeded straight into the collections
 * (the cascade is the unit under test, so nothing here goes through the app).
 */
async function seedAccount(
  n: Partial<typeof SIZES> = SIZES,
): Promise<{ id: mongoose.Types.ObjectId; email: string }> {
  const sizes = { ...SIZES, ...n };
  const email = `erase.me.${hex()}@example.org`;
  const user = await User.create({
    email,
    authHash: '$2a$04$fakehashfakehashfakehashfakehashfakehashfakehashfake',
    emailVerified: true,
    encryptedVaultKey: 'vk',
    vaultKeyIv: 'iv',
    vaultKeyTag: 'tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    deletionPending: true,
  });
  const id = user._id;
  const now = Date.now();
  const future = new Date(now + 24 * 60 * 60 * 1000);

  await insertChunked(
    AuditLog.collection,
    Array.from({ length: sizes.auditRows }, (_, i) => ({
      userId: id,
      action: i % 2 === 0 ? 'item_update' : 'login',
      metadata: { itemId: `x${String(i)}` },
      ipAddress: '203.0.113.5',
      userAgent: 'seed',
      timestamp: new Date(now - (sizes.auditRows - i) * 1000),
      count: 1,
    })),
  );
  await insertChunked(
    VaultItem.collection,
    Array.from({ length: sizes.items }, () => ({
      userId: id,
      itemType: 'login',
      encryptedData: 'd',
      dataIv: 'i',
      dataTag: 't',
      encryptedName: 'n',
      nameIv: 'i',
      nameTag: 't',
      createdAt: new Date(now),
      updatedAt: new Date(now),
    })),
  );
  await insertChunked(
    RefreshToken.collection,
    Array.from({ length: sizes.tombstones }, () => ({
      userId: id,
      tokenHash: hex(),
      familyId: hex(),
      usedAt: new Date(now),
      expiresAt: future,
      deviceInfo: { userAgent: 'seed', ip: '203.0.113.5', fingerprint: 'fp' },
    })),
  );
  await insertChunked(
    Folder.collection,
    Array.from({ length: sizes.folders }, () => ({
      userId: id,
      encryptedName: 'n',
      nameIv: 'i',
      nameTag: 't',
    })),
  );
  await insertChunked(
    BackupLog.collection,
    Array.from({ length: sizes.backupLogs }, () => ({
      userId: id,
      status: 'success',
      sentTo: [email],
      timestamp: new Date(now),
    })),
  );
  await insertChunked(
    Document.collection,
    Array.from({ length: sizes.documents }, () => ({
      userId: id,
      objectKey: `u/${id.toHexString()}/d/${hex()}`,
    })),
  );
  await insertChunked(
    DocumentUpload.collection,
    Array.from({ length: sizes.uploads }, () => ({ userId: id, objectKey: hex() })),
  );
  await insertChunked(
    DeviceProof.collection,
    Array.from({ length: sizes.deviceProofs }, () => ({
      userId: id,
      tokenHash: hex(),
      expiresAt: future,
    })),
  );
  await insertChunked(
    TrustedDevice.collection,
    Array.from({ length: sizes.trustedDevices }, () => ({
      userId: id,
      tokenHash: hex(),
      expiresAt: future,
    })),
  );
  return { id, email };
}

async function tenantCounts(userId: mongoose.Types.ObjectId): Promise<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const [name, model] of Object.entries(TENANT_MODELS)) {
    counts[name] = await model.collection.countDocuments({ userId });
  }
  counts['User'] = await User.collection.countDocuments({ _id: userId });
  return counts;
}

const ZERO = Object.fromEntries(
  [...Object.keys(TENANT_MODELS), 'User'].map((name) => [name, 0]),
) as Record<string, number>;

/** True when `needle` occurs in any document of any collection of the database. */
async function appearsAnywhere(needle: string): Promise<string[]> {
  const db = mongoose.connection.db!;
  const hits: string[] = [];
  for (const { name } of await db.listCollections({}, { nameOnly: true }).toArray()) {
    if (name.startsWith('system.')) continue;
    const cursor = db.collection(name).find({});
    for await (const doc of cursor) {
      if (JSON.stringify(doc).includes(needle)) {
        hits.push(name);
        break;
      }
    }
  }
  return hits;
}

/**
 * Records every Mongoose `deleteMany` on a tenant model that runs INSIDE a
 * session, with how many rows it removed. This is the transaction's size.
 */
function recordInSessionDeletes(): Map<string, number> {
  const removed = new Map<string, number>();
  for (const [name, model] of Object.entries(TENANT_MODELS)) {
    const original = model.deleteMany.bind(model) as (...args: unknown[]) => PromiseLike<{
      deletedCount: number;
    }>;
    vi.spyOn(model, 'deleteMany').mockImplementation(((...args: unknown[]) => {
      const options = args[1] as { session?: unknown } | undefined;
      const query = original(...args);
      if (options?.session === undefined) return query;
      return Promise.resolve(query).then((result) => {
        removed.set(name, (removed.get(name) ?? 0) + result.deletedCount);
        return result;
      });
    }) as never);
  }
  return removed;
}

async function eraseAndCheck(inTransaction: boolean): Promise<void> {
  const victim = await seedAccount();
  const bystander = await seedAccount({
    auditRows: 40,
    items: 20,
    tombstones: 5,
    folders: 3,
    backupLogs: 2,
    documents: 2,
    uploads: 1,
    deviceProofs: 2,
    trustedDevices: 2,
  });
  const bystanderBefore = await tenantCounts(bystander.id);
  const inSession = recordInSessionDeletes();

  const erased = await cascadeDeleteUser({
    userId: victim.id,
    userEmail: victim.email,
    ip: '198.51.100.44',
    userAgent: 'the-owner',
    auditAction: 'account_delete',
  });

  expect(erased).toBe(true);
  expect(await tenantCounts(victim.id)).toEqual(ZERO);

  if (inTransaction) {
    // The transaction was left the stragglers and the handful of trusted devices:
    // none of the bulky collections was erased inside it.
    for (const name of BULKY) {
      expect({ name, removed: inSession.get(name) ?? 0 }).toEqual({ name, removed: 0 });
    }
  }

  // The system row that outlives the account names it by id, and masks the address.
  const systemRows = await AuditLog.find({ userId: null, action: 'account_delete' }).lean();
  expect(systemRows).toHaveLength(1);
  expect(systemRows[0]!.metadata).toEqual({
    deletedUserId: victim.id.toString(),
    maskedEmail: maskEmail(victim.email),
  });
  // Nothing anywhere still carries the address or its local part.
  const localPart = victim.email.slice(0, victim.email.indexOf('@'));
  expect(await appearsAnywhere(victim.email)).toEqual([]);
  expect(await appearsAnywhere(localPart)).toEqual([]);

  // Negative: the other account is untouched, down to the last row.
  expect(await tenantCounts(bystander.id)).toEqual(bystanderBefore);

  // A second run over an erased account is a no-op: it succeeds, writes nothing.
  const auditBefore = await AuditLog.countDocuments({});
  expect(
    await cascadeDeleteUser({
      userId: victim.id,
      userEmail: victim.email,
      ip: '198.51.100.44',
      userAgent: 'the-owner',
      auditAction: 'account_delete',
    }),
  ).toBe(true);
  expect(await AuditLog.countDocuments({})).toBe(auditBefore);
  expect(await tenantCounts(victim.id)).toEqual(ZERO);
  expect(await tenantCounts(bystander.id)).toEqual(bystanderBefore);
}

describe('sequential branch (standalone)', () => {
  it('erases 250,000 audit rows and 5,000 items completely, with no plaintext address left', async () => {
    expect(supportsTransactions()).toBe(false);
    await eraseAndCheck(false);
  }, 300_000);

  it('a failed batch leaves the account pending and a re-run finishes it (forward-only)', async () => {
    const victim = await seedAccount({
      auditRows: 3_000,
      items: 2_500,
      tombstones: 10,
      folders: 2,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    // The items' second batch is refused: the audit rows and the first thousand
    // items are already gone, and must stay gone.
    const original = VaultItem.collection.deleteMany.bind(VaultItem.collection);
    let calls = 0;
    vi.spyOn(VaultItem.collection, 'deleteMany').mockImplementation(((
      ...args: Parameters<typeof original>
    ) => {
      calls += 1;
      if (calls === 2) return Promise.reject(new Error('refused mid-erasure'));
      return original(...args);
    }) as never);

    const first = await cascadeDeleteUser({
      userId: victim.id,
      userEmail: victim.email,
      ip: 'ip',
      userAgent: 'ua',
      auditAction: 'deletion_cleanup',
    });
    expect(first).toBe(false);
    const user = await User.findById(victim.id).lean();
    expect(user).not.toBeNull();
    expect(user!.deletionPending).toBe(true);
    // No system row for an erasure that has not finished.
    expect(await AuditLog.countDocuments({ userId: null })).toBe(0);

    vi.restoreAllMocks();
    expect(
      await cascadeDeleteUser({
        userId: victim.id,
        userEmail: victim.email,
        ip: 'ip',
        userAgent: 'ua',
        auditAction: 'deletion_cleanup',
      }),
    ).toBe(true);
    expect(await tenantCounts(victim.id)).toEqual(ZERO);
    expect(await AuditLog.countDocuments({ userId: null, action: 'deletion_cleanup' })).toBe(1);
  }, 120_000);
});

describe('the erasure marks the account itself, and never spins', () => {
  it('sets deletionPending as its own first write, so a caller that forgot cannot leave a usable half-erased account', async () => {
    const victim = await seedAccount({
      auditRows: 2_500,
      items: 5,
      tombstones: 1,
      folders: 1,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    await User.updateOne({ _id: victim.id }, { $set: { deletionPending: false } });
    // The flag write itself must land before any data goes: observe it at the
    // moment the first batch delete runs.
    const original = AuditLog.collection.deleteMany.bind(AuditLog.collection);
    let flagAtFirstDelete: boolean | undefined;
    vi.spyOn(AuditLog.collection, 'deleteMany').mockImplementation((async (
      ...args: Parameters<typeof original>
    ) => {
      if (flagAtFirstDelete === undefined) {
        const user = await User.collection.findOne({ _id: victim.id });
        flagAtFirstDelete = user?.['deletionPending'] === true;
        // ...and this erasure fails right after its first batch.
        throw new Error('refused after the first batch');
      }
      return original(...args);
    }) as never);

    const erased = await cascadeDeleteUser({
      userId: victim.id,
      userEmail: victim.email,
      ip: 'ip',
      userAgent: 'ua',
      auditAction: 'account_delete',
    });
    expect(erased).toBe(false);
    expect(flagAtFirstDelete).toBe(true);
    const user = await User.findById(victim.id).lean();
    expect(user!.deletionPending).toBe(true);
  });

  it('refuses, rather than looping, when full batches keep deleting nothing', async () => {
    const victim = await seedAccount({
      auditRows: 1_000,
      items: 1,
      tombstones: 1,
      folders: 1,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    let deletes = 0;
    vi.spyOn(AuditLog.collection, 'deleteMany').mockImplementation((() => {
      deletes += 1;
      return Promise.resolve({ acknowledged: true, deletedCount: 0 });
    }) as never);

    const erased = await cascadeDeleteUser({
      userId: victim.id,
      userEmail: victim.email,
      ip: 'ip',
      userAgent: 'ua',
      auditAction: 'account_delete',
    });
    expect(erased).toBe(false);
    // One empty batch is allowed (an overlapping run took those rows); the second
    // in a row refuses.
    expect(deletes).toBe(2);
    expect(await User.countDocuments({ _id: victim.id, deletionPending: true })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: null })).toBe(0);
  });
  it('a batch another run erased first is not a failure: the erasure goes on', async () => {
    const victim = await seedAccount({
      auditRows: 2_500,
      items: 1,
      tombstones: 1,
      folders: 1,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    // An overlapping run deletes the rows this run just read, before its delete.
    const original = AuditLog.collection.deleteMany.bind(AuditLog.collection);
    let raced = false;
    vi.spyOn(AuditLog.collection, 'deleteMany').mockImplementation((async (
      ...args: Parameters<typeof original>
    ) => {
      if (!raced) {
        raced = true;
        await original(...args);
      }
      return original(...args);
    }) as never);

    expect(
      await cascadeDeleteUser({
        userId: victim.id,
        userEmail: victim.email,
        ip: 'ip',
        userAgent: 'ua',
        auditAction: 'account_delete',
      }),
    ).toBe(true);
    expect(raced).toBe(true);
    expect(await tenantCounts(victim.id)).toEqual(ZERO);
  });
});

describe('transactional branch (replica set)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    expect(supportsTransactions()).toBe(true);
  });

  it('erases 250,000 audit rows and 5,000 items with a transaction that holds only stragglers', async () => {
    await eraseAndCheck(true);
  }, 300_000);

  it('the erasure record is written INSIDE the transaction that removes the user row', async () => {
    const victim = await seedAccount({
      auditRows: 20,
      items: 2,
      tombstones: 1,
      folders: 1,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    // The session the user row is deleted in, and the one the record is written
    // in: the same transaction, or a failed commit would leave a record for an
    // erasure that did not happen.
    let deleteSession: mongoose.ClientSession | undefined;
    let recordSession: mongoose.ClientSession | undefined;
    let recordInTransaction = false;
    const originalDelete = User.findByIdAndDelete.bind(User) as (...args: unknown[]) => unknown;
    vi.spyOn(User, 'findByIdAndDelete').mockImplementation(((...args: unknown[]) => {
      deleteSession = (args[1] as { session?: mongoose.ClientSession } | undefined)?.session;
      return originalDelete(...args);
    }) as never);
    const originalCreate = AuditLog.create.bind(AuditLog) as (...args: unknown[]) => unknown;
    vi.spyOn(AuditLog, 'create').mockImplementation(((...args: unknown[]) => {
      recordSession = (args[1] as { session?: mongoose.ClientSession } | undefined)?.session;
      recordInTransaction = recordSession?.inTransaction() ?? false;
      return originalCreate(...args);
    }) as never);

    expect(
      await cascadeDeleteUser({
        userId: victim.id,
        userEmail: victim.email,
        ip: 'ip',
        userAgent: 'ua',
        auditAction: 'account_delete',
      }),
    ).toBe(true);

    expect(deleteSession).toBeDefined();
    expect(recordSession).toBe(deleteSession);
    expect(recordInTransaction).toBe(true);
    expect(await AuditLog.countDocuments({ userId: null, action: 'account_delete' })).toBe(1);
  }, 120_000);

  it('a row written while the batches ran is swept inside the transaction', async () => {
    const victim = await seedAccount({
      auditRows: 1_500,
      items: 10,
      tombstones: 2,
      folders: 1,
      backupLogs: 1,
      documents: 1,
      uploads: 1,
      deviceProofs: 1,
      trustedDevices: 1,
    });
    // The moment the final transaction opens, a request that was already in
    // flight lands one more row of each kind.
    const original = mongoose.startSession.bind(mongoose);
    vi.spyOn(mongoose, 'startSession').mockImplementation((async (...args: unknown[]) => {
      await AuditLog.collection.insertOne({
        userId: victim.id,
        action: 'item_update',
        ipAddress: 'late',
        userAgent: 'late',
        timestamp: new Date(),
        count: 1,
      });
      await VaultItem.collection.insertOne({
        userId: victim.id,
        itemType: 'login',
        encryptedData: 'late',
      });
      return (original as (...a: unknown[]) => Promise<mongoose.ClientSession>)(...args);
    }) as never);
    const inSession = recordInSessionDeletes();

    expect(
      await cascadeDeleteUser({
        userId: victim.id,
        userEmail: victim.email,
        ip: 'ip',
        userAgent: 'ua',
        auditAction: 'account_delete',
      }),
    ).toBe(true);
    expect(await tenantCounts(victim.id)).toEqual(ZERO);
    expect(inSession.get('AuditLog')).toBe(1);
    expect(inSession.get('VaultItem')).toBe(1);
  }, 120_000);
});
