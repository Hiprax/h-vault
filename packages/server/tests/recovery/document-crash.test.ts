/**
 * Crash consistency for the document store: what MongoDB and the bucket hold
 * after the process died mid-transfer, mid-completion and mid-purge — and what the
 * garbage collector then does about it.
 *
 * `crash-consistency.test.ts` asks this question of the vault, at the rotation
 * fence and the import's transaction boundary. This file asks it of the one
 * subsystem where the answer is not recoverable from a backup: documents are
 * deliberately absent from the backup payload, the `documents` row holds the ONLY
 * wrapped copy of the key that opens its object, and an object deleted in error is
 * gone for ever. Every compensating path the store has — the completion handler's
 * `deleteObject` in its `catch`, the abort in `initUpload`'s `catch`, the release
 * of a per-upload lock in a `finally` — runs in a `catch` or a `finally`, and
 * SIGKILL runs neither. So the three sweeps of `jobs/documentCleanup.ts` are the
 * only thing standing between a crash and a bucket that leaks, and this file is
 * where the premise those sweeps rest on is actually produced by a crash rather
 * than written by hand.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS ADDS OVER `document-cleanup.test.ts`, WHICH ALREADY PASSES
 * ---------------------------------------------------------------------------
 *
 * That suite is thorough about the collector's DECISIONS, and it is right to seed
 * its fixtures by hand: it needs an object thirty hours old, a key that parses to
 * nothing, a page that is truncated but empty. What it cannot do — and says
 * nothing about — is whether a real crash produces the states it decides on. If
 * `uploadPart` started writing its ledger before forwarding the bytes, if
 * `completeUpload` began creating the row before deleting the staging one, or if
 * `purgeDocument` stopped marking `purgePending` first, every one of those tests
 * would still pass while the collector was answering questions nobody was asking.
 *
 * ---------------------------------------------------------------------------
 * THE TWO SEAMS, AND WHY EACH IS WHAT IT IS
 * ---------------------------------------------------------------------------
 *
 * MONGO IS REAL, and it is the datastore under test: the staging ledger, the
 * `purgePending` marker, the per-upload JobLock and the audit row are all decided
 * by a query against a real mongod, in a real child process, killed by a real
 * signal.
 *
 * OBJECT STORAGE IS THE PARENT'S DOUBLE, reached from the child over an IPC
 * bridge (`storageBridge.ts`). It is an external service in the same class as SMTP
 * and the breach API — the plan classifies it that way, the double's own header
 * says so, and the identical port contract runs against the REAL engine in
 * `test:storage`. The bridge exists because the parent has to see the bucket the
 * dead child wrote to, and a double built inside the child would die with it. The
 * header of `storageBridge.ts` records why a container is the wrong answer HERE
 * specifically: `tests/recovery/**` is not excluded from `vitest.config.ts`, so
 * every file in this directory also runs inside `test:integration` on every push,
 * and that task declares no Docker.
 *
 * ---------------------------------------------------------------------------
 * HOW THE WORLD IS AGED, AND THE FIXTURE THAT WOULD HAVE BEEN A LIE
 * ---------------------------------------------------------------------------
 *
 * Two of the three sweeps only act on things that are old: an engine-side upload
 * past `DOCUMENT_UPLOAD_TTL_HOURS + 1h`, an object past twenty-four hours whose
 * document id is itself past that same completion horizon. A crash produces
 * something that is seconds old, so the world has to be moved forward.
 *
 * It is moved with the repository's own clock seam (`tests/clock.ts`,
 * `toFake: ['Date']`), never by forging an aged `_id`. That distinction is the
 * whole reason this paragraph exists. A staging row whose `_id` is timestamped
 * thirty hours ago while its `expiresAt` is still in the future is a state the
 * production code PROVES cannot occur — `expiresAt` is set at init to the start
 * plus the TTL, which is exactly why the orphan sweep is allowed to read the id's
 * timestamp as a completion horizon at all. Building that fixture would mean the
 * sweep was deleting the object of a still-completable transfer while this file
 * called it correct, and the test would go on passing with that guard deleted.
 * Advancing the clock ages everything consistently, the way a day actually passing
 * does.
 *
 * One consequence to keep in mind when editing: every HTTP request belongs BEFORE
 * the advance. An access token lives fifteen minutes, so a request made thirty
 * hours into the faked future is a 401 with nothing to do with the drill.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import request from 'supertest';
import { Types } from 'mongoose';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';

vi.mock('../../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

vi.mock('../../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/storage/index.js')>();
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

// The collector is driven by hand, so the cron that would schedule it is replaced
// and its callback captured — the same technique `document-cleanup.test.ts` uses,
// and the reason `runDocumentCleanup` needs no export of its own.
vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

import cron from 'node-cron';
import app from '../../src/app.js';
import { AuditLog } from '../../src/models/AuditLog.js';
import { Document } from '../../src/models/Document.js';
import { DocumentUpload } from '../../src/models/DocumentUpload.js';
import { JobLock } from '../../src/models/JobLock.js';
import { startDocumentCleanupJob } from '../../src/jobs/documentCleanup.js';
import { documentCompleteLockName } from '../../src/utils/controllerHelpers.js';
import { buildObjectKey } from '../../src/utils/documentObjects.js';
import { createInMemoryStorage } from '../helpers/inMemoryStorage.js';
import { advanceClockBy, installTestClock, uninstallTestClock } from '../clock.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from '../helpers.js';
import { getActiveMongoUri } from '../mongoHarness.js';
import { expectKilled, runCrashProbe } from './crashProbe.js';

const HOUR = 60 * 60 * 1000;

/**
 * Far enough past every threshold the collector reads, in one jump.
 *
 * `DOCUMENT_UPLOAD_TTL_HOURS` defaults to 24 and both age rules add an hour of
 * grace on top, so thirty hours clears the lot with room that does not depend on
 * the exact default.
 */
const AGE_JUMP_MS = 30 * HOUR;

/** Opaque strings: nothing in this file decrypts anything. */
const FRAMING = {
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};
const WRAPPED_DEK = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
};
const SEALED_META = {
  encryptedMeta: 'ZG9jdW1lbnQtbWV0YWRhdGEtY2lwaGVydGV4dA==',
  metaIv: 'bWV0YS1pdg==',
  metaTag: 'bWV0YS10YWc=',
};

/**
 * A body whose bytes vary along its length, so a truncation or a reorder cannot
 * survive the digest the part route computes for itself.
 */
function pattern(bytes: number, seed: number): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 131 + seed) & 0xff;
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

const mockedSchedule = vi.mocked(cron.schedule);

/** Registers the collector and hands back the callback the cron would have fired. */
function startAndCapture(): () => Promise<void> {
  startDocumentCleanupJob();
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

/**
 * Ages the world by thirty hours, runs one collector tick, and hands the clock
 * back.
 *
 * The advance is scoped to this helper so it can never leak into a later case, and
 * it wraps the tick rather than the assertions: the tick is the only thing that
 * has to believe a day has passed, and an assertion made under a faked clock is
 * one more thing to reason about for no gain.
 */
async function runCleanupAfter(ms: number): Promise<void> {
  const tick = startAndCapture();
  installTestClock();
  try {
    advanceClockBy(ms);
    await tick();
  } finally {
    uninstallTestClock();
  }
}

/** One collector tick at the present instant, for the sweep that has no age rule. */
async function runCleanupNow(): Promise<void> {
  await startAndCapture()();
}

let user: TestUser;

async function post(path: string, body: Record<string, unknown>): Promise<request.Response> {
  const agent = request.agent(app);
  const pending = agent.post(path).set('Authorization', authHeader(user.accessToken));
  const csrf = await getCsrf(agent);
  return pending.set('Cookie', csrf.cookie).set('x-csrf-token', csrf.token).send(body);
}

async function del(path: string): Promise<request.Response> {
  const agent = request.agent(app);
  const pending = agent.delete(path).set('Authorization', authHeader(user.accessToken));
  const csrf = await getCsrf(agent);
  return pending.set('Cookie', csrf.cookie).set('x-csrf-token', csrf.token);
}

/** Opens a transfer through the real init route and returns its upload id. */
async function initTransfer(declaredChunkCount: number): Promise<string> {
  const declaredPlaintextBytes =
    declaredChunkCount === 1
      ? 1_024
      : (declaredChunkCount - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1;
  const response = await post('/api/v1/documents/uploads', {
    ...WRAPPED_DEK,
    ...FRAMING,
    declaredPlaintextBytes,
    declaredChunkCount,
  });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return (response.body as { data: { uploadId: string } }).data.uploadId;
}

/** Sends one part through the real part route, from the PARENT. */
async function putPart(uploadId: string, partNumber: number, body: Buffer): Promise<void> {
  const agent = request.agent(app);
  const pending = agent
    .put(`/api/v1/documents/uploads/${uploadId}/parts/${String(partNumber)}`)
    .set('Authorization', authHeader(user.accessToken));
  const csrf = await getCsrf(agent);
  const response = await pending
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .set('x-hv-part-sha256', digestOf(body))
    .type('application/octet-stream')
    .send(body);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
}

/** A committed single-segment document, through init, part and complete. */
async function commitDocument(): Promise<{ id: string; objectKey: string }> {
  const uploadId = await initTransfer(1);
  await putPart(uploadId, 1, pattern(1_024 + DOCUMENT_TAG_BYTES, 5));
  const completed = await post(`/api/v1/documents/uploads/${uploadId}/complete`, {
    ...SEALED_META,
    ...WRAPPED_DEK,
    vaultKeyVersion: 0,
  });
  expect(completed.status, JSON.stringify(completed.body)).toBe(201);
  const row = await Document.findById(uploadId).select('objectKey').lean();
  expect(row).not.toBeNull();
  return { id: uploadId, objectKey: row!.objectKey };
}

beforeEach(async () => {
  vi.clearAllMocks();
  mockedSchedule.mockReturnValue({ stop: vi.fn() } as unknown as ReturnType<typeof cron.schedule>);
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'document-crash@example.com' });
});

afterEach(() => {
  // The clock is restored inside `runCleanupAfter`'s `finally`, so this is the net
  // for an assertion that threw before reaching it: a worker left frozen runs every
  // LATER file against a clock that stopped in the middle of a test it never heard of.
  uninstallTestClock();
});

describe('a crash during a part upload', () => {
  it('leaves no document row, an unrecorded part in the engine, and an upload the collector reclaims only once the staging row is gone', async () => {
    const uploadId = await initTransfer(2);
    const storage = storageRef.current!;

    // A POSITIVE CONTROL for the negative below, and the reason it is here: the
    // collector logs and swallows its own failures (`runDocumentCleanup`'s catch),
    // so "the engine-side upload survived the first tick" would read exactly the
    // same if that tick had done nothing at all. This is an object no row will ever
    // name, seeded now so the clock advance ages it too. The same tick that must
    // LEAVE the claimed upload alone must DELETE this — which is what proves the
    // sweep ran and discriminated, rather than simply not running.
    const control = buildObjectKey(user.id, new Types.ObjectId().toHexString());
    await storage.putObject(control, Buffer.alloc(16, 0x41));
    // The FINAL part of the transfer, which is the only one the framing rules let
    // be short — so the drill costs sixty-four bytes instead of eight mebibytes,
    // and the request still travels as a real `application/octet-stream` body.
    const part = pattern(64, 9);

    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'document-part-before-ledger-write',
      method: 'PUT',
      path: `/api/v1/documents/uploads/${uploadId}/parts/2`,
      token: user.accessToken,
      bodyBase64: part.toString('base64'),
      headers: { 'x-hv-part-sha256': digestOf(part) },
      storage,
    });
    expectKilled(outcome, 'document-part-before-ledger-write');

    // NOTHING WAS COMMITTED. A part is not a document, and a crash during one may
    // not produce a row the account is charged for and the browser cannot open.
    expect(await Document.countDocuments({})).toBe(0);

    // The engine holds the part; the ledger does not know about it. This is the
    // ordering `uploadPart` claims — bytes first, ledger second — asserted from the
    // one instant in which the two disagree.
    const engineParts = await storage.listParts(
      (await DocumentUpload.findById(uploadId).select('objectKey').lean())!.objectKey,
      (await DocumentUpload.findById(uploadId).select('s3UploadId').lean())!.s3UploadId!,
    );
    expect(engineParts).toEqual([{ partNumber: 2, etag: expect.any(String), bytes: 64 }]);
    const staging = await DocumentUpload.findById(uploadId).lean();
    expect(staging).not.toBeNull();
    expect(staging!.parts).toEqual([]);
    expect(staging!.receivedBytes).toBe(0);

    // THE NEGATIVE, and it is the one that costs a user their file if it inverts:
    // a staging row still names this upload, so however old the upload is, the
    // collector must leave it alone. A sweep that aborted here would destroy the
    // parts of a transfer whose client is still sending.
    await runCleanupAfter(AGE_JUMP_MS);
    expect(await storage.listMultipartUploads('u/')).toHaveLength(1);
    // ...and the control is gone, so that tick really did sweep.
    expect(storage.storedKeys()).not.toContain(control);

    // The staging row reaches its TTL. Deleted explicitly rather than waited for,
    // in the same spirit as `crash-consistency.test.ts`'s `expireLock`: MongoDB's
    // TTL monitor runs on its own schedule, and this IS the state it produces —
    // the index deletes the ROW and nothing else, which is precisely why this
    // sweep has to reason from the engine's own initiation dates instead.
    const removed = await DocumentUpload.deleteOne({ _id: uploadId });
    expect(removed.deletedCount).toBe(1);

    await runCleanupAfter(AGE_JUMP_MS);

    // Now nothing names it, and the engine-side upload is reclaimed.
    expect(await storage.listMultipartUploads('u/')).toEqual([]);
    // And still no row appeared from anywhere, and no object was assembled: an
    // aborted multipart upload leaves no object behind.
    expect(await Document.countDocuments({})).toBe(0);
    expect(storage.storedKeys()).toEqual([]);
  }, 120_000);
});

describe('a crash between the completion write and the document row', () => {
  it('leaves an object neither collection names, which the orphan sweep reclaims while never touching a live document', async () => {
    const storage = storageRef.current!;

    // The LIVE document is seeded FIRST, before the advance, and that ordering is
    // the whole strength of the negative below. Aged thirty hours along with
    // everything else, it satisfies every orphan condition except one: it still has
    // a `documents` row. Seeded after the advance it would be protected by its own
    // fresh id instead, and the assertion would stay green with the row check
    // deleted.
    const live = await commitDocument();

    const uploadId = await initTransfer(1);
    await putPart(uploadId, 1, pattern(1_024 + DOCUMENT_TAG_BYTES, 3));
    const orphanKey = (await DocumentUpload.findById(uploadId).select('objectKey').lean())!
      .objectKey;

    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'document-complete-before-row-insert',
      path: `/api/v1/documents/uploads/${uploadId}/complete`,
      token: user.accessToken,
      body: { ...SEALED_META, ...WRAPPED_DEK, vaultKeyVersion: 0 },
      storage,
    });
    expectKilled(outcome, 'document-complete-before-row-insert');

    // THE STATE THE WHOLE `ORPHAN_MIN_AGE_MS` CONSTANT EXISTS FOR: the staging row
    // is already gone, the row that replaces it was never written, and the object
    // sits at its final key named by nothing at all.
    expect(await DocumentUpload.findById(uploadId).lean()).toBeNull();
    expect(await Document.findById(uploadId).lean()).toBeNull();
    expect(storage.storedKeys()).toContain(orphanKey);

    // The per-upload lock is still HELD by the dead process, because the release
    // lives in a `finally` SIGKILL never runs. Recorded rather than glossed over:
    // it is why a retried completion for this id is refused for the lock's two
    // minutes, and it is harmless precisely because there is nothing left to retry.
    const heldLock = await JobLock.findOne({
      jobName: documentCompleteLockName(user.id, uploadId),
    }).lean();
    expect(heldLock).not.toBeNull();
    expect(heldLock!.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // A day passes. The orphan is reclaimed.
    await runCleanupAfter(AGE_JUMP_MS);

    expect(storage.storedKeys()).not.toContain(orphanKey);

    // THE NEGATIVE, and the reason this file exists at all. The live document is
    // the same age, its key parses the same way, its id passes the same completion
    // horizon — the ONLY thing protecting it is that a `documents` row names it.
    // Its object is still there and its row is untouched.
    expect(storage.storedKeys()).toEqual([live.objectKey]);
    expect(await Document.findById(live.id).lean()).not.toBeNull();
    expect(await Document.countDocuments({})).toBe(1);
  }, 120_000);
});

describe('a crash between the object delete and the row delete', () => {
  it('leaves purgePending behind, and the collector finishes the purge and audits it without touching the other document', async () => {
    const storage = storageRef.current!;
    const doomed = await commitDocument();
    const survivor = await commitDocument();

    // A permanent delete is the second half of a two-step destruction, so the row
    // has to be in the trash before it can be purged.
    expect((await del(`/api/v1/documents/${doomed.id}`)).status).toBe(200);

    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'document-purge-after-object-delete',
      method: 'DELETE',
      path: `/api/v1/documents/${doomed.id}/permanent`,
      token: user.accessToken,
      storage,
    });
    expectKilled(outcome, 'document-purge-after-object-delete');

    // THE MARKER IS THE WHOLE POINT. It was committed BEFORE the object delete, so
    // it survives a crash that the object did not, and it is what turns an
    // irreversible half-finished deletion into work the collector can finish. A
    // handler that deleted the object first would leave a row with no marker and no
    // object: a document that lists, counts against the quota, and can never open.
    const stranded = await Document.findById(doomed.id).lean();
    expect(stranded).not.toBeNull();
    expect(stranded!.purgePending).toBe(true);
    expect(stranded!.deletedAt).toBeInstanceOf(Date);
    expect(storage.storedKeys()).toEqual([survivor.objectKey]);

    // The user's own request never answered, so no audit row was written for a
    // destruction that had already happened. That gap is exactly what the sweep's
    // audit entry closes, and it is asserted in both directions.
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'document_purge' })).toBe(0);

    // No advance: this sweep has no age rule, deliberately — an interrupted purge
    // is already committed work, and making it wait a day would leave the user's
    // bytes charged to them for that day.
    await runCleanupNow();

    expect(await Document.findById(doomed.id).lean()).toBeNull();
    const audits = await AuditLog.find({ userId: user.id, action: 'document_purge' }).lean();
    expect(audits).toHaveLength(1);
    expect(audits[0]!.metadata).toMatchObject({
      action: 'gc_finish_interrupted',
      documentCount: 1,
    });

    // THE NEGATIVE. One row was finished, not the trash and not the account: the
    // other document keeps its row and its object.
    expect(await Document.findById(survivor.id).lean()).not.toBeNull();
    expect(storage.storedKeys()).toEqual([survivor.objectKey]);
  }, 120_000);
});
