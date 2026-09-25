/**
 * The two BULK writers must hold the per-user vault-key exclusion lock across
 * their whole check-to-commit span, not merely read the fence on the way in.
 *
 * ## The defect this file closes
 *
 * `assertVaultNotRotating` is a READ. `assertVaultKeyVersion` is a READ. For
 * `POST /tools/import` and `POST /backup/restore` the distance between those
 * reads and the first row written is not a statement or two: it is a
 * multi-megabyte `JSON.parse`, the entry-count cap, the field-length checks, the
 * folder lookups, the update-target lookups, a job-lock acquisition and up to
 * four counted collection scans. A rotation that raises its fence anywhere
 * inside that span is one both reads have already decided does not exist, and
 * every row the bulk writer then commits is sealed under a key the rotation is
 * in the middle of replacing — enumerated before those rows existed, so no key
 * the account holds will ever open them and no later rotation can repair them.
 *
 * Nothing about that is exotic. A restore is the one operation a user reaches
 * for precisely when they are also thinking about their keys.
 *
 * ## What "atomic" means here, and how it is proved
 *
 * The fix is not a third read. Both writers now take
 * `vaultRotationLockName(userId)` — the same lock `bulkReEncrypt` acquires
 * BEFORE it raises the fence and releases AFTER it lowers it — so a rotation
 * either loses the acquisition and is refused, or wins it and the bulk writer is
 * refused. A test that only held the lock and watched a request 409 would pass
 * just as well against a guard placed at the top of the handler and released
 * immediately, so the case that matters here is the opposite one: a probe that
 * runs INSIDE the write itself and tries to take the lock. It can only succeed
 * if the span the lock covers stops short of the write, which is the whole
 * defect. Both writers are pinned that way, at the row-writing call itself.
 *
 * ## The negatives
 *
 * A refusal must write nothing and must leave no lock behind — a leaked lock is
 * not a lost request but a five-minute outage on rotation, import, restore,
 * document completion and the master-password change at once. Both are asserted
 * on every path here, including the paths that fail for an unrelated reason.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import {
  vaultImportLockName,
  vaultKeyVersionOf,
  vaultRotationLockName,
} from '../src/utils/controllerHelpers.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  sampleVaultItem,
  sampleFolder,
  type TestUser,
} from './helpers.js';

let user: TestUser;

beforeEach(async () => {
  user = await createTestUser();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** One authenticated, CSRF-bearing POST. */
async function post(path: string, body: Record<string, unknown>): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(path)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .send(body);
}

const IMPORT_BODY = {
  format: 'json',
  operations: {
    inserts: [{ ...sampleVaultItem({ encryptedName: 'imported' }), searchHash: 'a'.repeat(64) }],
  },
};

const RESTORE_BODY = {
  conflictStrategy: 'skip' as const,
  data: JSON.stringify({
    items: [sampleVaultItem({ encryptedName: 'restored' })],
    folders: [sampleFolder({ encryptedName: 'restored-folder' })],
  }),
};

async function importVault(extra: Record<string, unknown> = {}): Promise<request.Response> {
  return post('/api/v1/tools/import', { ...IMPORT_BODY, ...extra });
}

async function restoreBackup(extra: Record<string, unknown> = {}): Promise<request.Response> {
  return post('/api/v1/backup/restore', { ...RESTORE_BODY, ...extra });
}

/** Rows and audit rows, so "nothing was written" can be asserted as one value. */
async function snapshot(): Promise<Record<string, number>> {
  return {
    items: await VaultItem.countDocuments({ userId: user.id }),
    folders: await Folder.countDocuments({ userId: user.id }),
    audits: await AuditLog.countDocuments({
      userId: user.id,
      action: { $in: ['import', 'backup_restored'] },
    }),
  };
}

/** Every lock this account could be holding, so a leak cannot hide. */
async function heldLocks(): Promise<Record<string, number>> {
  return {
    rotation: await JobLock.countDocuments({ jobName: vaultRotationLockName(user.id) }),
    import: await JobLock.countDocuments({ jobName: vaultImportLockName(user.id) }),
  };
}

/** Takes the exclusion lock as a rotation would, and returns its release. */
async function holdRotationLock(): Promise<() => Promise<void>> {
  const lockId = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
  expect(lockId, 'the fixture could not take the lock it is testing').not.toBeNull();
  return async () => {
    await releaseJobLock(vaultRotationLockName(user.id), lockId as string);
  };
}

/**
 * The ONE sentence every loser of the exclusion lock receives, whichever of the
 * five holders it is and whichever of them won. Restated here rather than
 * imported, because it is module-private on purpose (a second copy at a call
 * site is how a holder-specific story creeps back in) and because what matters
 * is the text on the wire.
 */
const EXCLUSION_MESSAGE =
  'Another change that re-seals this account under its vault key is already in progress ' +
  '(a key rotation, import, backup restore, document completion or master password ' +
  'change). Please wait and retry.';

/**
 * The refusal a loser of the exclusion lock receives: a 409 that names no
 * particular holder, because the loser cannot know which one won — so it lists
 * every holder there is, rather than guessing one.
 */
function expectExclusionConflict(res: request.Response): void {
  expect(res.status, JSON.stringify(res.body)).toBe(409);
  expect(res.body.success).toBe(false);
  expect(res.body.message).toBe(EXCLUSION_MESSAGE);
  // Whole, as the client shows it: `getApiErrorMessage` cuts every message at
  // 200 characters (`MAX_ERROR_MESSAGE_LENGTH`), and a sentence longer than that
  // loses its remedy — the part that tells the user what to do.
  expect(String(res.body.message).length).toBeLessThanOrEqual(200);
  // NOT the recoverable stale-generation refusal: there is no number to hand
  // back, the caller's generation is fine, and a client that saw one would
  // rewrap under a key that was never the problem.
  expect(res.body.data).toBeUndefined();
}

describe('POST /tools/import holds the vault-key exclusion lock across its span', () => {
  it('is refused, writes nothing and leaves no lock behind while a rotation holds it', async () => {
    const release = await holdRotationLock();
    const before = await snapshot();

    const res = await importVault();

    expectExclusionConflict(res);
    expect(await snapshot()).toEqual(before);
    // The import's OWN lock is taken first and must still be released on the way
    // out; only the rotation lock the fixture holds may survive this request.
    expect(await heldLocks()).toEqual({ rotation: 1, import: 0 });

    await release();
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });

  it('imports normally once the lock is free, and holds nothing afterwards', async () => {
    const release = await holdRotationLock();
    expect((await importVault()).status).toBe(409);
    await release();

    const res = await importVault();

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.data).toEqual({
      insertedCount: 1,
      updatedCount: 0,
      insertedIds: expect.any(Array),
    });
    // One echoed id per insert, in order (pinned exactly in vault-field-format.test.ts).
    expect(res.body.data.insertedIds).toHaveLength(1);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });

  it('still holds the lock at the moment `insertMany` runs', async () => {
    // The case a top-of-handler acquisition cannot pass. The probe runs inside
    // the write itself and tries to take the lock a rotation would take; it must
    // fail, because the import is holding it.
    const realInsertMany = VaultItem.insertMany.bind(VaultItem);
    let lockWasFreeAtWriteTime: boolean | null = null;
    vi.spyOn(VaultItem, 'insertMany').mockImplementation((async (docs: never, opts: never) => {
      const stolen = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
      lockWasFreeAtWriteTime = stolen !== null;
      if (stolen !== null) await releaseJobLock(vaultRotationLockName(user.id), stolen);
      return realInsertMany(docs, opts);
    }) as never);

    const res = await importVault();

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(
      lockWasFreeAtWriteTime,
      'the probe never ran, so this case proves nothing about the span',
    ).not.toBeNull();
    expect(
      lockWasFreeAtWriteTime,
      'a rotation could take the exclusion lock while the import was writing',
    ).toBe(false);
  });

  it('does not take the exclusion lock at all when its own import lock is contended', async () => {
    // Acquisition order is import lock first, exclusion lock second. A loser of
    // the first must leave the second untouched — taking it and then failing
    // would block a rotation for nothing.
    const importLockId = await acquireJobLock(vaultImportLockName(user.id), 60_000);
    const before = await snapshot();

    const res = await importVault();

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.message).toMatch(/import is already in progress/i);
    expect(await snapshot()).toEqual(before);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 1 });

    await releaseJobLock(vaultImportLockName(user.id), importLockId as string);
  });
});

describe('POST /backup/restore holds the vault-key exclusion lock across its span', () => {
  it('is refused, writes nothing and leaves no lock behind while a rotation holds it', async () => {
    const release = await holdRotationLock();
    const before = await snapshot();

    const res = await restoreBackup();

    expectExclusionConflict(res);
    expect(await snapshot()).toEqual(before);
    expect(await heldLocks()).toEqual({ rotation: 1, import: 0 });

    await release();
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });

  it('restores normally once the lock is free, and holds nothing afterwards', async () => {
    const release = await holdRotationLock();
    expect((await restoreBackup()).status).toBe(409);
    await release();

    const res = await restoreBackup();

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });

  it('still holds the lock at the moment a row is created', async () => {
    const realCreate = VaultItem.create.bind(VaultItem);
    let lockWasFreeAtWriteTime: boolean | null = null;
    vi.spyOn(VaultItem, 'create').mockImplementation((async (doc: never) => {
      const stolen = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
      lockWasFreeAtWriteTime = stolen !== null;
      if (stolen !== null) await releaseJobLock(vaultRotationLockName(user.id), stolen);
      return realCreate(doc);
    }) as never);

    const res = await restoreBackup();

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(
      lockWasFreeAtWriteTime,
      'the probe never ran, so this case proves nothing about the span',
    ).not.toBeNull();
    expect(
      lockWasFreeAtWriteTime,
      'a rotation could take the exclusion lock while the restore was writing',
    ).toBe(false);
  });

  it('releases the lock when the restore fails for an unrelated reason', async () => {
    // A malformed body is refused inside the span, after the lock is taken. The
    // refusal must still be a 400 about the body — not a conflict — and it must
    // not strand the lock.
    const release = await holdRotationLock();
    await release();

    const res = await post('/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: 'this is not JSON',
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/malformed JSON/i);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });
});

describe('no refusal is written while the exclusion lock is still held', () => {
  /**
   * The ordering `importVault` and `completeUpload` both document and that the
   * restore and the master-password change now share: the outcome is decided
   * under the lock and RENDERED after it.
   *
   * A 409 that reaches the socket first invites the client to do exactly what its
   * message asks — rewrap under the generation it carries and retry — inside the
   * milliseconds the release round trip takes, and be told a finished request is
   * "already in progress". That is a conflict the client can do nothing about and
   * cannot distinguish from a real one.
   *
   * The seam is `JobLock.deleteOne`, which is what a release IS, so the order can
   * be observed without reaching into the handler.
   */
  async function orderOf(
    path: string,
    body: Record<string, unknown>,
  ): Promise<{ status: number; order: string[] }> {
    const order: string[] = [];
    const realDeleteOne = JobLock.deleteOne.bind(JobLock);
    vi.spyOn(JobLock, 'deleteOne').mockImplementation(((filter: Record<string, unknown>) => {
      // Delayed so a render-then-release ordering is caught rather than racing us
      // to completion.
      return (async () => {
        await new Promise((resolve) => setTimeout(resolve, 25));
        const result = await realDeleteOne(filter);
        if (String(filter.jobName) === vaultRotationLockName(user.id)) {
          order.push('exclusion-lock-released');
        }
        return result;
      })();
    }) as never);

    const res = await post(path, body);
    order.push('response-received');
    vi.restoreAllMocks();
    return { status: res.status, order };
  }

  /** Puts the account on generation 1 so a body naming 0 is refused. */
  async function rotateOnce(): Promise<void> {
    await User.updateOne({ _id: user.id }, { $inc: { vaultKeyVersion: 1 } });
  }

  it('releases before it answers a restore refused for a superseded generation', async () => {
    await rotateOnce();

    const { status, order } = await orderOf('/api/v1/backup/restore', {
      ...RESTORE_BODY,
      vaultKeyVersion: 0,
    });

    expect(status).toBe(409);
    expect(order).toEqual(['exclusion-lock-released', 'response-received']);
  });

  it('releases before it answers an import refused for a superseded generation', async () => {
    await rotateOnce();

    const { status, order } = await orderOf('/api/v1/tools/import', {
      ...IMPORT_BODY,
      vaultKeyVersion: 0,
    });

    expect(status).toBe(409);
    expect(order).toEqual(['exclusion-lock-released', 'response-received']);
  });
});

describe('the exclusion lock and the rotation fence are peers, not substitutes', () => {
  it('refuses a bulk write on a CRASHED rotation, whose lock has lapsed but whose fence is up', async () => {
    // The one case the lock alone cannot see: a rotation that died mid-flight
    // left `rotationInProgress` raised and its lock has since TTL-expired, so the
    // acquisition below SUCCEEDS. What refuses the request is the fence read that
    // follows the acquisition — which is why the acquisition comes first and the
    // read second, and why the read was not deleted when the lock arrived.
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
    const before = await snapshot();

    const res = await importVault();

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.message).toMatch(/rotation is in progress/i);
    expect(await snapshot()).toEqual(before);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });

    const restored = await restoreBackup();
    expect(restored.status).toBe(409);
    expect(restored.body.message).toMatch(/rotation is in progress/i);
    expect(await snapshot()).toEqual(before);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });

  it('leaves a never-rotated account writing normally, holding nothing', async () => {
    expect(vaultKeyVersionOf(await User.findById(user.id).lean())).toBe(0);

    expect((await importVault()).status).toBe(201);
    expect((await restoreBackup()).status).toBe(200);
    expect(await heldLocks()).toEqual({ rotation: 0, import: 0 });
  });
});
