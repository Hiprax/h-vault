import { describe, it, expect, vi, beforeEach } from 'vitest';
import mongoose from 'mongoose';

/**
 * `jobs/documentCleanup.ts` — the object-storage garbage collector.
 *
 * ## What this file is actually defending
 *
 * Every other cleanup path in this system deletes a ROW, and a row deleted in error
 * is recoverable from a backup. This job deletes OBJECTS, and an object deleted in
 * error is gone for ever: the `documents` row holds the only wrapped copy of the key
 * that opens it, documents are deliberately absent from the backup payload, and the
 * browser threw its copy away when the tab closed. So the assertions that matter
 * most here are the negatives — the cases where the sweep must decide it cannot
 * prove an object is garbage and must therefore leave it alone. Each one is written
 * so that removing the guard it covers turns it red.
 *
 * ## Why the job's resilience cases live here rather than in the shared suite
 *
 * `phase5-job-resilience.test.ts` parameterises the three unconditional crons over
 * transient lock failures. This job is not unconditional: on a deployment with no
 * `S3_*` configured it is never scheduled at all, which is what that file's
 * environment looks like. Its lock cases are therefore reproduced here, against a
 * storage double that actually exists.
 */

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

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

/**
 * `storageConfigured` republished as a GETTER over a hoisted flag, so one file can
 * exercise both the configured deployment (almost every test) and the unconfigured
 * one (where the job must not be scheduled at all). Vite compiles the import into a
 * property read at each use site, so the getter is consulted every time.
 *
 * The rest of `config` passes through untouched: re-mocking it with
 * `vi.resetModules()` + `vi.doMock` re-evaluates `models/User.ts` and throws
 * `OverwriteModelError`.
 */
const { deployment } = vi.hoisted(() => ({ deployment: { storageConfigured: true } }));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  const mocked: Record<string, unknown> = { ...actual };
  Object.defineProperty(mocked, 'storageConfigured', {
    get: () => deployment.storageConfigured,
    enumerable: true,
    configurable: true,
  });
  return mocked;
});

/**
 * `releaseJobLock` passed through unless a test asks it to fail. A transient
 * failure there must not reject the tracked promise: `trackJob`'s bookkeeping
 * chain would surface it as an unhandled rejection, which the logger's crash
 * coordinator escalates to `process.exit(1)` — the whole API server, killed by a
 * cleanup job that could not put a lock down.
 */
const { lockFaults } = vi.hoisted(() => ({ lockFaults: { releaseFails: false } }));

vi.mock('../src/utils/jobLock.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/jobLock.js')>();
  return {
    ...actual,
    releaseJobLock: async (jobName: string, lockId: string): Promise<void> => {
      if (lockFaults.releaseFails) {
        throw new Error('lock release failed: connection closing');
      }
      return actual.releaseJobLock(jobName, lockId);
    },
  };
});

const { storageRef, storageAccess } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
  storageAccess: { count: 0 },
}));

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      storageAccess.count += 1;
      if (storageRef.current === undefined) {
        throw new Error('the in-memory storage double was not installed for this test');
      }
      return storageRef.current;
    },
  };
});

import cron from 'node-cron';
import { config } from '../src/config/index.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { JobLock } from '../src/models/JobLock.js';
import { startDocumentCleanupJob } from '../src/jobs/documentCleanup.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';

/**
 * The orphan sweep's per-run budget, restated here because the job keeps it
 * private (nothing outside that module has any business reading it, and exporting
 * a constant for a test is how a module's surface grows for no caller). Stated as
 * a literal rather than derived, so if the job's own number changes this test goes
 * red and somebody has to look at it — which is the point.
 */
const ORPHAN_SWEEP_MAX_KEYS_PER_RUN = 1_000;

/** The job's hard ceiling on listing requests per run, restated for the same reason. */
const ORPHAN_SWEEP_MAX_PAGES_PER_RUN = 32;

const mockedSchedule = vi.mocked(cron.schedule);

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** The double's clock, so an object can be seeded "thirty hours ago" in a millisecond. */
const clock = { now: new Date() };

function at(msAgo: number): Date {
  return new Date(Date.now() - msAgo);
}

/**
 * An ObjectId whose embedded TIMESTAMP is `msAgo` in the past, with a random tail
 * so two calls at the same instant do not collide.
 *
 * The timestamp is not decoration: the orphan sweep's fifth condition reads it to
 * decide whether a completion for that key could still succeed, so a fixture built
 * with a fresh id would be protected by that condition and would never reach the
 * behaviour under test.
 */
function agedId(msAgo: number): mongoose.Types.ObjectId {
  const seconds = Math.floor((Date.now() - msAgo) / 1000)
    .toString(16)
    .padStart(8, '0');
  return new mongoose.Types.ObjectId(
    seconds + new mongoose.Types.ObjectId().toHexString().slice(8),
  );
}

/** Every column a `documents` row needs, with nothing decryptable in it. */
function documentRow(
  userId: mongoose.Types.ObjectId,
  documentId: mongoose.Types.ObjectId,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    _id: documentId,
    userId,
    objectKey: buildObjectKey(userId.toHexString(), documentId.toHexString()),
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
    ciphertextBytes: 48,
    plaintextBytes: 32,
    ...overrides,
  };
}

/** Seeds a `documents` row and its object, the object written `objectAgeMs` ago. */
async function seedDocument(
  userId: mongoose.Types.ObjectId,
  options: { idAgeMs: number; objectAgeMs: number; overrides?: Record<string, unknown> } = {
    idAgeMs: 30 * HOUR,
    objectAgeMs: 30 * HOUR,
  },
): Promise<{ id: mongoose.Types.ObjectId; objectKey: string }> {
  const documentId = agedId(options.idAgeMs);
  await Document.create(documentRow(userId, documentId, options.overrides ?? {}));
  const objectKey = buildObjectKey(userId.toHexString(), documentId.toHexString());
  clock.now = at(options.objectAgeMs);
  await storageRef.current!.putObject(objectKey, Buffer.alloc(48, 0x5a));
  clock.now = new Date();
  return { id: documentId, objectKey };
}

/** Seeds a bare object with no row of any kind behind it. */
async function seedOrphan(
  userId: mongoose.Types.ObjectId,
  options: { idAgeMs?: number; objectAgeMs?: number } = {},
): Promise<{ id: mongoose.Types.ObjectId; objectKey: string }> {
  const documentId = agedId(options.idAgeMs ?? 30 * HOUR);
  const objectKey = buildObjectKey(userId.toHexString(), documentId.toHexString());
  clock.now = at(options.objectAgeMs ?? 30 * HOUR);
  await storageRef.current!.putObject(objectKey, Buffer.alloc(16, 0x41));
  clock.now = new Date();
  return { id: documentId, objectKey };
}

/** A staging row for a transfer that is still live. */
async function seedStagingRow(
  userId: mongoose.Types.ObjectId,
  documentId: mongoose.Types.ObjectId,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  await DocumentUpload.create({
    _id: documentId,
    userId,
    objectKey: buildObjectKey(userId.toHexString(), documentId.toHexString()),
    encryptedDek: 'dek-ciphertext',
    dekIv: 'dek-iv',
    dekTag: 'dek-tag',
    streamSalt: Buffer.alloc(32, 7).toString('base64'),
    noncePrefix: Buffer.alloc(7, 3).toString('base64'),
    declaredPlaintextBytes: 32,
    declaredChunkCount: 2,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    expiresAt: new Date(Date.now() + DAY),
    ...overrides,
  });
}

/** Opens an engine-side multipart upload for a key, initiated `msAgo` in the past. */
async function seedEngineUpload(objectKey: string, msAgo: number): Promise<string> {
  clock.now = at(msAgo);
  const uploadId = await storageRef.current!.createMultipartUpload(objectKey);
  clock.now = new Date();
  return uploadId;
}

/** Registers the collector and hands back the callback the cron would have fired. */
function startAndCapture(): () => Promise<void> {
  startDocumentCleanupJob();
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
  deployment.storageConfigured = true;
  lockFaults.releaseFails = false;
  storageAccess.count = 0;
  clock.now = new Date();
  storageRef.current = createInMemoryStorage({ clock: () => clock.now });
  mockedSchedule.mockReturnValue({ stop: vi.fn() } as unknown as ReturnType<typeof cron.schedule>);
});

describe('documentCleanup registration', () => {
  it('schedules an hourly UTC run and hands back a stoppable task for the shutdown drain', () => {
    const task = startDocumentCleanupJob();

    expect(mockedSchedule).toHaveBeenCalledTimes(1);
    expect(mockedSchedule).toHaveBeenCalledWith('30 * * * *', expect.any(Function), {
      timezone: 'UTC',
    });
    // `server.ts` puts this straight into the array `createGracefulShutdown`
    // receives; without a stoppable task the cron outlives the drain and fires
    // after the database connection has been closed underneath it.
    expect(task).not.toBeNull();
    expect(typeof task?.stop).toBe('function');
  });

  it('schedules nothing at all when the deployment configured no object storage', () => {
    deployment.storageConfigured = false;

    const task = startDocumentCleanupJob();

    expect(task).toBeNull();
    // The three negatives: no cron, no storage client, no lock. A job that merely
    // no-ops inside its body would still take a lock every hour for ever on a
    // deployment that has no bucket to sweep.
    expect(mockedSchedule).not.toHaveBeenCalled();
    expect(storageAccess.count).toBe(0);
  });
});

describe('documentCleanup sweep 1: abandoned engine-side uploads', () => {
  it('aborts an engine upload past the TTL plus an hour that no staging row claims', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const orphanKey = buildObjectKey(userId.toHexString(), agedId(30 * HOUR).toHexString());
    const uploadId = await seedEngineUpload(orphanKey, 30 * HOUR);

    await callback();

    await expect(storageRef.current!.listParts(orphanKey, uploadId)).rejects.toMatchObject({
      statusCode: 404,
    });
    expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
  });

  it('leaves an engine upload alone while a staging row still claims it', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const documentId = agedId(30 * HOUR);
    const objectKey = buildObjectKey(userId.toHexString(), documentId.toHexString());
    const uploadId = await seedEngineUpload(objectKey, 30 * HOUR);
    // The row is what makes this transfer live. Its own `expiresAt` is in the
    // future, so a client may still be sending parts against it.
    await seedStagingRow(userId, documentId, { s3UploadId: uploadId });

    await callback();

    // THE NEGATIVE THAT MATTERS for this sweep: aborting here throws away every
    // part a client has already sent, mid-transfer, on the strength of a clock.
    const surviving = await storageRef.current!.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([uploadId]);
  });

  it("claims an engine upload by the staging row's _id, never by its s3UploadId", async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const documentId = agedId(30 * HOUR);
    const objectKey = buildObjectKey(userId.toHexString(), documentId.toHexString());
    const uploadId = await seedEngineUpload(objectKey, 30 * HOUR);
    // The SAME live transfer as the case above, with one difference: the row's
    // `s3UploadId` does not match the handle the engine is holding. That is the
    // shape an interrupted re-initiation leaves behind, and it is the only shape
    // that tells the two implementations apart — every other fixture in this file
    // seeds both identifiers in agreement, so a sweep rewritten to
    // `find({ s3UploadId: { $in: ... } })` passes all of them.
    //
    // Keying on `_id` is not a stylistic preference: `_id` IS the documentId inside
    // the object key and it is the collection's primary index, while `s3UploadId`
    // carries no index at all, so the alternative turns an hourly job into a full
    // scan of the busiest collection in the schema AND, here, aborts a transfer a
    // client is still sending parts to.
    await seedStagingRow(userId, documentId, { s3UploadId: 'a-stale-handle' });

    await callback();

    const surviving = await storageRef.current!.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([uploadId]);
  });

  it('leaves an upload younger than the threshold, and does not stop scanning at it', async () => {
    const callback = startAndCapture();
    // Nothing may be assumed about the order the ENGINE reports uploads in — the
    // shipped one sorts by upload id, which is neither key order nor age order, and
    // the port promises only a complete page. What this case needs is simply an
    // order in which the YOUNG upload comes FIRST, because a sweep that stopped at
    // the first entry younger than its threshold would then leave the older one
    // behind it unreclaimed for ever.
    //
    // It is arranged to come first TWICE OVER, and that redundancy is deliberate:
    // its key sorts first, which is the order the double reports (a determinism
    // choice for the fake, pinned by its own case in `storage-contract.test.ts`),
    // AND it is seeded first, so the trap stays reachable under plain insertion
    // order too. Depending on the double's sort alone would leave this case passing
    // vacuously the day that sort changed.
    const youngKey = buildObjectKey('000000000000000000000001', agedId(1 * HOUR).toHexString());
    const oldKey = buildObjectKey('ffffffffffffffffffffffff', agedId(30 * HOUR).toHexString());
    const youngUpload = await seedEngineUpload(youngKey, 1 * HOUR);
    const oldUpload = await seedEngineUpload(oldKey, 30 * HOUR);

    await callback();

    const surviving = await storageRef.current!.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([youngUpload]);
    expect(surviving.map((upload) => upload.uploadId)).not.toContain(oldUpload);
  });

  it('leaves an engine upload whose key it did not write', async () => {
    const callback = startAndCapture();
    // The key does not parse, so nothing here can tie it to a document, and an
    // upload that cannot be shown to be abandoned must not be abandoned.
    const uploadId = await seedEngineUpload('u/not-an-object-id/d/whatever', 30 * HOUR);

    await callback();

    const surviving = await storageRef.current!.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([uploadId]);
    expect(loggerError).not.toHaveBeenCalled();
  });

  it('abandons the run when the engine refuses abort after abort', async () => {
    const callback = startAndCapture();
    for (let index = 0; index < 9; index += 1) {
      const key = buildObjectKey(
        new mongoose.Types.ObjectId().toHexString(),
        agedId(30 * HOUR).toHexString(),
      );
      await seedEngineUpload(key, 30 * HOUR);
    }
    const abort = vi
      .spyOn(storageRef.current!, 'abortMultipartUpload')
      .mockRejectedValue(new Error('storage is down'));

    await callback();

    // Five consecutive refusals end the run. Pressing on would spend the
    // fifteen-minute lock TTL on an engine that is plainly not answering, and let
    // the next hourly tick start a second sweep alongside this one.
    expect(abort).toHaveBeenCalledTimes(5);
    expect(await storageRef.current!.listMultipartUploads()).toHaveLength(9);
  });

  it('leaves an upload whose initiation time the engine did not report', async () => {
    // An engine is not obliged to report `Initiated`, and the port makes it
    // optional so that "I cannot establish this upload's age" is representable.
    // An unknown age is not an old age.
    storageRef.current = createInMemoryStorage({ clock: () => clock.now, omitTimestamps: true });
    const callback = startAndCapture();
    const key = buildObjectKey('000000000000000000000002', agedId(30 * HOUR).toHexString());
    const uploadId = await seedEngineUpload(key, 30 * HOUR);

    await callback();

    const surviving = await storageRef.current.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([uploadId]);
  });

  it('logs an abort the engine refused and carries on to the next candidate', async () => {
    const callback = startAndCapture();
    const stubbornKey = buildObjectKey('000000000000000000000004', agedId(30 * HOUR).toHexString());
    const removableKey = buildObjectKey(
      '000000000000000000000005',
      agedId(30 * HOUR).toHexString(),
    );
    const stubborn = await seedEngineUpload(stubbornKey, 30 * HOUR);
    await seedEngineUpload(removableKey, 30 * HOUR);
    const realAbort = storageRef.current!.abortMultipartUpload.bind(storageRef.current!);
    vi.spyOn(storageRef.current!, 'abortMultipartUpload').mockImplementation(
      async (key: string, uploadId: string) => {
        if (key === stubbornKey) throw new Error('storage refused this abort');
        return realAbort(key, uploadId);
      },
    );

    await callback();

    // One refusal is not the engine being down, so the rest of the page is still
    // reclaimed rather than the whole sweep being abandoned on the first error.
    const surviving = await storageRef.current!.listMultipartUploads();
    expect(surviving.map((upload) => upload.uploadId)).toEqual([stubborn]);
    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining('could not abort abandoned upload'),
    );
  });

  it('does not accept a foreign object carrying a 404 as proof the upload is gone', async () => {
    const callback = startAndCapture();
    const key = buildObjectKey('000000000000000000000006', agedId(30 * HOUR).toHexString());
    const uploadId = await seedEngineUpload(key, 30 * HOUR);
    // A plain object with the right-looking shape, which is NOT an error this
    // codebase threw. Duck-typing on the number alone would read it as "the engine
    // has already forgotten this upload", count an abort that never happened, and
    // reset the circuit breaker — while the multipart, and its parts, survive.
    vi.spyOn(storageRef.current!, 'abortMultipartUpload').mockRejectedValue({
      statusCode: 404,
      message: 'not from @hiprax/errors',
    });

    await callback();

    expect(await storageRef.current!.listMultipartUploads()).toHaveLength(1);
    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining(`could not abort abandoned upload ${uploadId}`),
    );
  });

  it('counts an already-forgotten upload as done rather than as a failure', async () => {
    const callback = startAndCapture();
    const key = buildObjectKey('000000000000000000000003', agedId(30 * HOUR).toHexString());
    await seedEngineUpload(key, 30 * HOUR);
    const { httpErrors } = await import('@hiprax/errors');
    vi.spyOn(storageRef.current!, 'abortMultipartUpload').mockRejectedValue(
      httpErrors.notFound('Multipart upload not found'),
    );

    await callback();

    // A lock that expires mid-run lets the next tick reach the same candidates, so
    // a 404 here is routine. Logging it as a failure would train an operator to
    // ignore this job's error lines.
    expect(loggerError).not.toHaveBeenCalled();
  });
});

describe('documentCleanup sweep 2: interrupted purges', () => {
  it('finishes a purgePending row by deleting the object and then the row', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const pending = await seedDocument(userId, {
      idAgeMs: 2 * HOUR,
      objectAgeMs: 2 * HOUR,
      overrides: { deletedAt: at(DAY), purgePending: true },
    });

    await callback();

    expect(await Document.findById(pending.id)).toBeNull();
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('records the destruction it completed, which the interrupted request never did', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    await seedDocument(userId, {
      idAgeMs: 2 * HOUR,
      objectAgeMs: 2 * HOUR,
      overrides: { deletedAt: at(DAY), purgePending: true },
    });

    await callback();

    // The user-facing purge writes its audit row AFTER deleting the document row,
    // so a process that died between the two destroyed a file and recorded
    // nothing. This run is the one that actually destroyed it.
    const audits = await AuditLog.find({ userId, action: 'document_purge' }).lean();
    expect(audits).toHaveLength(1);
    expect(audits[0]?.metadata).toMatchObject({
      action: 'gc_finish_interrupted',
      documentCount: 1,
    });
    expect(audits[0]?.userAgent).toBe('system/document-cleanup-job');
  });

  it('claims no purge that another request completed first, and audits none', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const raced = await seedDocument(userId, {
      idAgeMs: 2 * HOUR,
      objectAgeMs: 2 * HOUR,
      overrides: { deletedAt: at(DAY), purgePending: true },
    });
    const realDelete = storageRef.current!.deleteObject.bind(storageRef.current!);
    // A concurrent request finishing the same interrupted purge, in the exact gap
    // between this run's object delete and its row delete.
    vi.spyOn(storageRef.current!, 'deleteObject').mockImplementation(async (key: string) => {
      await Document.deleteOne({ _id: raced.id });
      return realDelete(key);
    });

    await callback();

    // The destruction happened, so the state is right — but it was not this run's
    // to report. Counting it would put a number in the log and in the audit trail
    // that the other request has already accounted for.
    expect(await Document.findById(raced.id)).toBeNull();
    expect(storageRef.current!.storedKeys()).toEqual([]);
    expect(await AuditLog.countDocuments({ userId })).toBe(0);
    expect(loggerError).not.toHaveBeenCalled();
  });

  it('keeps the audit record of a page it finished when a later page throws', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    for (let index = 0; index < 3; index += 1) {
      await seedDocument(userId, {
        idAgeMs: 2 * HOUR,
        objectAgeMs: 2 * HOUR,
        overrides: { deletedAt: at(DAY), purgePending: true },
      });
    }
    // The sweep reads a first page, finishes it, then reads again to see whether
    // more remain. That second read is where the database is made to go away.
    const realFind = Document.find.bind(Document);
    let reads = 0;
    vi.spyOn(Document, 'find').mockImplementation(((...args: unknown[]) => {
      reads += 1;
      if (reads === 2) throw new Error('the database went away between pages');
      return (realFind as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof Document.find);

    await callback();

    // Three documents were destroyed before the failure, and the record of that
    // destruction survives it. Accumulating the audit across the whole run and
    // inserting once at the end would lose it entirely — and this job exists
    // partly BECAUSE the user-facing purge writes its audit after the row delete,
    // so nothing else would ever record these three.
    expect(await Document.countDocuments({ userId })).toBe(0);
    const audits = await AuditLog.find({ userId, action: 'document_purge' }).lean();
    expect(audits).toHaveLength(1);
    expect(audits[0]?.metadata).toMatchObject({
      action: 'gc_finish_interrupted',
      documentCount: 3,
    });
    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining('Document cleanup job failed'),
    );
  });

  it('leaves a row whose object delete failed marked for the next run, and moves past it', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const stuck = await seedDocument(userId, {
      idAgeMs: 2 * HOUR,
      objectAgeMs: 2 * HOUR,
      overrides: { deletedAt: at(DAY), purgePending: true },
    });
    const healthy = await seedDocument(userId, {
      idAgeMs: 2 * HOUR,
      objectAgeMs: 2 * HOUR,
      overrides: { deletedAt: at(DAY), purgePending: true },
    });
    const realDelete = storageRef.current!.deleteObject.bind(storageRef.current!);
    vi.spyOn(storageRef.current!, 'deleteObject').mockImplementation(async (key: string) => {
      if (key === stuck.objectKey) throw new Error('storage refused this key');
      return realDelete(key);
    });

    await callback();

    // The failing row survives WITH its marker (deleting it would destroy the only
    // wrapped key while the ciphertext is still in the bucket) and the page cursor
    // advanced past it, so the second row was still reached.
    const survivor = await Document.findById(stuck.id).lean();
    expect(survivor?.purgePending).toBe(true);
    expect(await Document.findById(healthy.id)).toBeNull();
    expect(storageRef.current!.storedKeys()).toEqual([stuck.objectKey]);
    expect(loggerError).toHaveBeenCalledTimes(1);
  });

  it('keeps going through scattered failures, because the breaker counts consecutive ones', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const seeded: { id: mongoose.Types.ObjectId; objectKey: string }[] = [];
    for (let index = 0; index < 12; index += 1) {
      seeded.push(
        await seedDocument(userId, {
          idAgeMs: 2 * HOUR,
          objectAgeMs: 2 * HOUR,
          overrides: { deletedAt: at(DAY), purgePending: true },
        }),
      );
    }
    // Rows are visited in `_id` order, so the alternation has to be decided in
    // that order rather than in creation order.
    seeded.sort((left, right) => (left.id.toHexString() < right.id.toHexString() ? -1 : 1));
    const doomed = new Set(seeded.filter((_row, index) => index % 2 === 0).map((r) => r.objectKey));
    const realDelete = storageRef.current!.deleteObject.bind(storageRef.current!);
    vi.spyOn(storageRef.current!, 'deleteObject').mockImplementation(async (key: string) => {
      if (doomed.has(key)) throw new Error('storage refused this key');
      return realDelete(key);
    });

    await callback();

    // Six failures in one run, but never two in a row, so the breaker never trips
    // and every healthy row is still finished. A counter that only ever climbed
    // would have abandoned the run after the ninth row and left the last three
    // interrupted purges — and their quota — in place for another hour.
    expect(await Document.countDocuments({ purgePending: true })).toBe(6);
    expect(storageRef.current!.storedKeys().sort()).toEqual([...doomed].sort());
  });

  it('gives up on the run once the engine has refused several deletes in a row', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    for (let index = 0; index < 9; index += 1) {
      await seedDocument(userId, {
        idAgeMs: 2 * HOUR,
        objectAgeMs: 2 * HOUR,
        overrides: { deletedAt: at(DAY), purgePending: true },
      });
    }
    const deleteObject = vi
      .spyOn(storageRef.current!, 'deleteObject')
      .mockRejectedValue(new Error('storage is down'));

    await callback();

    // Five consecutive refusals end the run. At the client's pinned five-second
    // connect timeout and three attempts, pressing on through a thousand rows is
    // over four hours — long past the fifteen-minute lock TTL, which would let the
    // next tick start a second concurrent sweep.
    expect(deleteObject).toHaveBeenCalledTimes(5);
    expect(await Document.countDocuments({ purgePending: true })).toBe(9);
  });
});

describe('documentCleanup sweep 3: orphaned objects', () => {
  it('deletes an object older than a day that no row of any kind names', async () => {
    const callback = startAndCapture();
    await seedOrphan(new mongoose.Types.ObjectId());

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('never deletes a live document object, however old the object is', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const active = await seedDocument(userId, { idAgeMs: 90 * DAY, objectAgeMs: 90 * DAY });
    // The one most likely to be broken by an over-eager filter: a trashed document
    // is recoverable for TRASH_AUTO_PURGE_DAYS and is older than a day within
    // hours, so a lookup that excluded trashed rows would destroy the bytes of
    // every trashed document the morning after it was trashed.
    const trashed = await seedDocument(userId, {
      idAgeMs: 90 * DAY,
      objectAgeMs: 90 * DAY,
      overrides: { deletedAt: at(2 * DAY) },
    });

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual([active.objectKey, trashed.objectKey].sort());
    expect(await Document.countDocuments({ userId })).toBe(2);
  });

  it('never deletes the parts of a transfer that is still staged', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const inFlight = await seedOrphan(userId, { idAgeMs: 30 * HOUR, objectAgeMs: 30 * HOUR });
    await seedStagingRow(userId, inFlight.id);

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual([inFlight.objectKey]);
  });

  it('never deletes an object whose transfer could still be completed', async () => {
    // The window this guards is real: `completeUpload` deletes the staging row
    // BEFORE it inserts the documents row, and a single-segment upload is written
    // straight to its final key at PART time — so with the upload TTL raised above
    // a day, an object older than a day can belong to a transfer that is still
    // completable, and a sweep landing inside that window destroys the file while
    // the row that names it survives.
    const originalTtl = config.DOCUMENT_UPLOAD_TTL_HOURS;
    (config as Record<string, unknown>).DOCUMENT_UPLOAD_TTL_HOURS = 48;
    try {
      const callback = startAndCapture();
      const userId = new mongoose.Types.ObjectId();
      // Thirty hours old: past the day-old floor, but inside a 48-hour TTL, and
      // with neither row present — exactly the state the window produces.
      const racing = await seedOrphan(userId, { idAgeMs: 30 * HOUR, objectAgeMs: 30 * HOUR });

      await callback();

      expect(storageRef.current!.storedKeys()).toEqual([racing.objectKey]);
    } finally {
      (config as Record<string, unknown>).DOCUMENT_UPLOAD_TTL_HOURS = originalTtl;
    }
  });

  it('logs an orphan it could not delete and carries on to the next one', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const stubborn = await seedOrphan(userId);
    await seedOrphan(userId);
    const realDelete = storageRef.current!.deleteObject.bind(storageRef.current!);
    vi.spyOn(storageRef.current!, 'deleteObject').mockImplementation(async (key: string) => {
      if (key === stubborn.objectKey) throw new Error('storage refused this key');
      return realDelete(key);
    });

    await callback();

    // One refusal is not the engine being down, so the sweep finishes its budget.
    expect(storageRef.current!.storedKeys()).toEqual([stubborn.objectKey]);
    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining(`could not delete orphaned object ${stubborn.objectKey}`),
    );
  });

  it('abandons the run when the engine refuses delete after delete', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    for (let index = 0; index < 9; index += 1) {
      await seedOrphan(userId);
    }
    const deleteObject = vi
      .spyOn(storageRef.current!, 'deleteObject')
      .mockRejectedValue(new Error('storage is down'));

    await callback();

    expect(deleteObject).toHaveBeenCalledTimes(5);
    expect(storageRef.current!.storedKeys()).toHaveLength(9);
  });

  it('falls back to the engine token for one step when a page arrives empty but truncated', async () => {
    const callback = startAndCapture();
    await seedOrphan(new mongoose.Types.ObjectId());
    const realList = storageRef.current!.listObjects.bind(storageRef.current!);
    let served = 0;
    const listObjects = vi
      .spyOn(storageRef.current!, 'listObjects')
      .mockImplementation(async (prefix, options) => {
        served += 1;
        // A listing is allowed to hand back no keys and still say more follow.
        // There is no key to resume after in that state, so the durable cursor
        // cannot advance and the run would otherwise re-issue this same request
        // until its lock expired.
        if (served === 1) return { objects: [], nextContinuationToken: 'engine-token-1' };
        return realList(prefix, options);
      });

    await callback();

    expect(listObjects.mock.calls[1]?.[1]?.continuationToken).toBe('engine-token-1');
    // And it still made progress: the orphan behind that empty page was reclaimed.
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('stops at its page ceiling when the engine only ever says there is more', async () => {
    const callback = startAndCapture();
    const listObjects = vi
      .spyOn(storageRef.current!, 'listObjects')
      .mockResolvedValue({ objects: [], nextContinuationToken: 'always-more' });

    await expect(callback()).resolves.toBeUndefined();

    // Termination is a property of this code, not of the engine's good behaviour:
    // the key budget cannot bound a loop whose pages carry no keys, so the page
    // ceiling is what stops the run spinning inside its own lock.
    expect(listObjects).toHaveBeenCalledTimes(ORPHAN_SWEEP_MAX_PAGES_PER_RUN);
  });

  it('leaves an object younger than a day even when nothing names it', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const fresh = await seedOrphan(userId, { idAgeMs: 30 * HOUR, objectAgeMs: 2 * HOUR });

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual([fresh.objectKey]);
  });

  it('leaves an object whose age the engine did not report', async () => {
    storageRef.current = createInMemoryStorage({ clock: () => clock.now, omitTimestamps: true });
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const unknownAge = await seedOrphan(userId);

    await callback();

    expect(storageRef.current.storedKeys()).toEqual([unknownAge.objectKey]);
  });

  it('leaves a key it did not write, because such a key names no document', async () => {
    const callback = startAndCapture();
    clock.now = at(90 * DAY);
    await storageRef.current!.putObject('u/not-an-object-id/d/whatever', Buffer.alloc(4));
    clock.now = new Date();

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual(['u/not-an-object-id/d/whatever']);
  });

  it('examines at most its per-run budget and resumes after the last key on the next run', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    // One more object than the sweep will look at in a single run. The budget is a
    // module constant on purpose — a test seam that let this file shrink it would
    // prove the cap only for a number production never uses — so the fixture is
    // sized against the real one. Bare objects in a Map, so this costs
    // milliseconds.
    const keys: string[] = [];
    for (let index = 0; index <= ORPHAN_SWEEP_MAX_KEYS_PER_RUN; index += 1) {
      keys.push((await seedOrphan(userId)).objectKey);
    }
    keys.sort();
    const lastKey = keys[keys.length - 1] as string;
    const budgetBoundaryKey = keys[ORPHAN_SWEEP_MAX_KEYS_PER_RUN - 1] as string;
    const listObjects = vi.spyOn(storageRef.current!, 'listObjects');

    await callback();

    // The cap held: one key was left unexamined, so an hourly sweep can never
    // become an unbounded walk of somebody's whole bucket.
    expect(storageRef.current!.storedKeys()).toEqual([lastKey]);

    await callback();

    // And the next run picked up where the last one stopped rather than re-walking
    // the bucket from the beginning. Without the carried cursor, a bucket larger
    // than the budget would hide every orphan past the first page for ever — which
    // would also make `cascadeDelete`'s promise that this job reclaims whatever its
    // own object sweep could not delete simply false.
    expect(storageRef.current!.storedKeys()).toEqual([]);
    const resumedWith = listObjects.mock.calls.map((call) => call[1]?.startAfter);
    expect(resumedWith).toContain(budgetBoundaryKey);
    // The resumption is a plain KEY, never the engine's opaque continuation token:
    // a token is documented as obfuscated with nothing said about how long one
    // stays valid, and an hourly job hands its cursor back an hour later.
    expect(listObjects.mock.calls.every((call) => call[1]?.continuationToken === undefined)).toBe(
      true,
    );
  });
});

describe('documentCleanup run mechanics', () => {
  it('releases its lock even when a sweep throws', async () => {
    const callback = startAndCapture();
    vi.spyOn(storageRef.current!, 'listMultipartUploads').mockRejectedValue(
      new Error('the engine is unreachable'),
    );

    await expect(callback()).resolves.toBeUndefined();

    // A lock left behind would silence the job until its fifteen-minute TTL
    // expired, which on an hourly schedule is a skipped run.
    expect(await JobLock.findOne({ jobName: 'document-cleanup' })).toBeNull();
    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining('Document cleanup job failed'),
    );
  });

  it('contains a failure to put the lock down instead of rejecting the tracked promise', async () => {
    const callback = startAndCapture();
    lockFaults.releaseFails = true;

    // Resolves, never rejects. `trackJob`'s bookkeeping chain re-raises a rejected
    // job promise, and the process-wide crash handler turns that into exit(1).
    await expect(callback()).resolves.toBeUndefined();

    expect(loggerError).toHaveBeenCalledWith(
      expect.stringContaining('Failed to release document-cleanup lock'),
    );
  });

  it('reports a non-Error failure without letting it read as a missing message', async () => {
    const callback = startAndCapture();
    // Nothing obliges a rejected promise to carry an `Error`, and a job whose log
    // line said `undefined` would be worse than one that said nothing.
    vi.spyOn(storageRef.current!, 'listMultipartUploads').mockRejectedValue('not an Error at all');

    await expect(callback()).resolves.toBeUndefined();

    expect(loggerError).toHaveBeenCalledWith('Document cleanup job failed: Unknown error');
  });

  it('does no work at all while another instance holds the lock', async () => {
    const callback = startAndCapture();
    const userId = new mongoose.Types.ObjectId();
    const orphan = await seedOrphan(userId);
    await JobLock.create({
      jobName: 'document-cleanup',
      lockedBy: 'another-instance',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    await callback();

    expect(storageRef.current!.storedKeys()).toEqual([orphan.objectKey]);
    expect(loggerInfo).toHaveBeenCalledWith(expect.stringContaining('another instance holds'));
  });
});
