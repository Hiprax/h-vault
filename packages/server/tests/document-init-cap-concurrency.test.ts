/**
 * Phase 11 — the per-user document caps cannot be breached by OVERLAPPING
 * transfer opens, on the STANDALONE topology.
 *
 * `POST /documents/uploads` decides three per-user budgets — the document count,
 * the concurrent-transfer count and the byte quota — by reading a count and then
 * writing a staging row. Two opens that each individually fit can therefore both
 * pass the read and then both write, unless something serializes them. The
 * default harness (`tests/setup.ts`) connects to a standalone `MongoMemoryServer`,
 * which rejects multi-document transactions, so the guarantee rests ENTIRELY on
 * the per-user `document-init:<userId>` JobLock, exactly as the import path's
 * cap rests on `vault-import:<userId>` (`import-cap-concurrency.test.ts`).
 *
 * ## Why the concurrency cap is the one that matters
 *
 * The document count is read from `documents`, and only a COMPLETION writes
 * there, so a burst of opens cannot move it: whatever a racing open observes, the
 * number is the same one. What a burst CAN move is the staging-row count, and
 * that is the cap the whole arithmetic hangs off. `MAX_DOCUMENTS_PER_ROTATION`
 * (`packages/shared/src/constants/index.ts`) is derived as the advertised limit
 * plus the concurrency cap, on the stated reasoning that an account can finish at
 * most `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1` documents past the limit.
 * Unserialized, that bound is not enforced by anything: N simultaneous opens all
 * read zero live transfers and all commit, so N documents land past the limit for
 * any N. An account past `MAX_DOCUMENTS_PER_ROTATION` can then never rotate its
 * vault key again — too many rows for the schema's `.max()` and too few named for
 * the handler's coverage check, at the same time — with permanently deleting
 * documents the only way out. That is what these cases pin.
 *
 * ## Seams
 *
 * MONGO IS REAL: every cap here is decided by a query, and the JobLock is an
 * atomic upsert against a unique index, so a faked datastore would test the fake.
 * OBJECT STORAGE IS A DOUBLE (`helpers/inMemoryStorage.ts`), the same seam
 * `document-uploads.test.ts` takes and for the same reason.
 *
 * Covers:
 *   • an open parked inside the locked region 409s a second, overlapping one, and
 *     that loser leaves neither a staging row nor an engine-side multipart upload
 *   • a refused open releases the lock rather than stranding it for its TTL
 *   • a burst of overlapping opens never exceeds the concurrency cap, and what
 *     landed reconciles exactly with what was reported
 *   • the cap is REACHABLE as well as enforced: filling it is a 201 each time and
 *     the next open is the documented 400
 *   • transfers that COMPLETE between the two cap reads cannot carry the account
 *     past the bound — which is what fixes the order the two counts are read in
 *   • a payload naming every row rotates an account at the overshoot the caps permit
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_DOCUMENTS_PER_ROTATION,
  MAX_DOCUMENTS_PER_USER,
} from '@hvault/shared';

const { storageState } = vi.hoisted(() => ({ storageState: { configured: true } }));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return {
    ...actual,
    get storageConfigured() {
      return storageState.configured;
    },
  };
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

import app from '../src/app.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { JobLock } from '../src/models/JobLock.js';
import { documentInitLockName } from '../src/utils/controllerHelpers.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

const UPLOADS_PATH = '/api/v1/documents/uploads';
const ROTATE_PATH = '/api/v1/vault/items/bulk-reencrypt';

/**
 * The wrapped-DEK and framing fields a valid init body carries, byte-exact.
 *
 * `streamSalt` and `noncePrefix` are padded base64 of EXACTLY 32 and 7 bytes:
 * `initDocumentUploadSchema` pins both byte counts, so an approximation would be
 * rejected by the validator and every case here would fail for the wrong reason.
 */
const FRAMING = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/**
 * A valid init body for a transfer of `chunks` segments.
 *
 * TWO segments throughout, deliberately. A single-segment transfer is a
 * `PutObject` and opens no engine-side multipart upload, so it could not show
 * that a REFUSED open leaves nothing behind at the engine either — which is the
 * second half of every refusal in this handler.
 */
function initBody(chunks = 2): Record<string, unknown> {
  return {
    ...FRAMING,
    declaredPlaintextBytes: (chunks - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
    declaredChunkCount: chunks,
  };
}

/**
 * Builds a ready-to-fire init request whose CSRF handshake has already happened,
 * so several of them can be launched at genuinely the same moment rather than
 * staggered by their own preamble.
 */
async function prepareInit(user: TestUser): Promise<() => Promise<request.Response>> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);

  // `Promise.resolve` is load-bearing, not decoration: a supertest `Test` is a
  // lazy thenable that only dispatches when something subscribes to it. Handing
  // the raw object back would let `const pending = send()` sit there having sent
  // nothing, and a test that then waits for the request to arrive would hang.
  return () =>
    Promise.resolve(
      agent
        .post(UPLOADS_PATH)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send(initBody()),
    );
}

/**
 * Shrinks the account's effective document headroom to `headroom` rows without
 * seeding thousands of them.
 *
 * The stub calls THROUGH to the real count and adds a fixed offset, so the value
 * the handler sees still tracks what has actually been written. A flat
 * `mockResolvedValue` would pin the count to a constant and could never notice a
 * row a racing request had committed, which is precisely the interaction under
 * test. Same technique, and the same reason, as `pinHeadroom` in
 * `import-cap-concurrency.test.ts`.
 */
function pinDocumentHeadroom(headroom: number): void {
  const realCountDocuments = Document.countDocuments.bind(Document) as unknown as (
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ) => Promise<number>;
  const offset = MAX_DOCUMENTS_PER_USER - headroom;

  vi.spyOn(Document, 'countDocuments').mockImplementation(((
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ) => realCountDocuments(filter, options).then((count) => count + offset)) as never);
}

/** A live staging row for `user`, bypassing the handler. */
async function seedUpload(user: TestUser): Promise<void> {
  const uploadId = new mongoose.Types.ObjectId();
  await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, uploadId.toHexString()),
    ...FRAMING,
    declaredPlaintextBytes: 1024,
    declaredChunkCount: 1,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
}

/**
 * A committed document row for `user`, bypassing the handler.
 *
 * Only the columns the counts and the rotation read matter here, so this is the
 * state a completion LEAVES rather than the path that leaves it.
 */
async function seedDocument(user: TestUser): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    encryptedDek: 'dek-ciphertext-old',
    dekIv: 'dek-iv-old',
    dekTag: 'dek-tag-old',
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    streamSalt: Buffer.alloc(32, 11).toString('base64'),
    noncePrefix: Buffer.alloc(7, 5).toString('base64'),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
    plaintextBytes: 1024,
  });
  return documentId.toHexString();
}

/** Live staging rows the account holds. */
function liveUploads(user: TestUser): Promise<number> {
  return DocumentUpload.countDocuments({ userId: user.id, expiresAt: { $gt: new Date() } });
}

/** Multipart uploads the engine still holds open. */
async function openMultipartUploads(): Promise<number> {
  return (await storageRef.current!.listMultipartUploads()).length;
}

let user: TestUser;

beforeEach(async () => {
  storageState.configured = true;
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'document-init-concurrency@example.com' });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Phase 11 — the document caps hold under overlapping transfer opens (standalone)', () => {
  it('409s an open that overlaps one already inside the locked region, and starts nothing', async () => {
    // One row of headroom, so the document cap is live rather than incidental:
    // this account is at `MAX_DOCUMENTS_PER_USER - 1`, which is exactly the state
    // in which an unbounded overshoot is unrecoverable.
    pinDocumentHeadroom(1);

    // Park the FIRST open at its staging write — inside the lock and past every
    // cap check — so the second is guaranteed to arrive while the lock is
    // genuinely held. Without this the overlap would depend on scheduling luck
    // and the test would prove the lock only intermittently.
    let announceArrival!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceArrival = resolve;
    });
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });

    const realCreate = DocumentUpload.create.bind(DocumentUpload) as unknown as (
      doc: Record<string, unknown>,
    ) => Promise<unknown>;
    let firstWrite = true;
    vi.spyOn(DocumentUpload, 'create').mockImplementation((async (doc: Record<string, unknown>) => {
      if (firstWrite) {
        firstWrite = false;
        announceArrival();
        await gate;
      }
      return realCreate(doc);
    }) as never);

    const sendFirst = await prepareInit(user);
    const sendSecond = await prepareInit(user);

    const first = sendFirst();
    await parked;

    // Resolves fully while the first request is still holding the lock.
    const second = await sendSecond();
    expect(second.status, JSON.stringify(second.body)).toBe(409);
    expect(String(second.body.message)).toMatch(/already being opened/i);

    openGate();
    expect((await first).status).toBe(201);

    // The loser was refused before its own cap checks, so it read no count, wrote
    // no staging row and — the negative this handler owes on every refusal — left
    // no engine-side multipart upload for the collector to find an hour later.
    expect(await DocumentUpload.countDocuments({}), 'the loser left a staging row').toBe(1);
    expect(await openMultipartUploads(), 'the loser left a multipart upload open').toBe(1);
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('never opens more transfers than the concurrency cap when a burst arrives at once', async () => {
    // Eight simultaneous opens against an account one row below the advertised
    // document limit. Every one of them fits in isolation; together they are more
    // than twice the concurrency budget.
    const BURST = 8;
    pinDocumentHeadroom(1);

    const senders = await Promise.all(Array.from({ length: BURST }, () => prepareInit(user)));
    const responses = await Promise.all(senders.map((send) => send()));

    // 201 (it ran), 409 (the lock refused it) and 400 (a cap refused it) are the
    // only legal outcomes; anything else — a 500 from a duplicate-key crash, say
    // — is a real defect rather than a benign loss of the race.
    for (const res of responses) {
      expect([201, 400, 409], JSON.stringify(res.body)).toContain(res.status);
    }

    const opened = responses.filter((res) => res.status === 201);
    // Progress is guaranteed: whoever takes the lock first cannot be refused,
    // because the account holds no transfers when it looks.
    expect(opened.length).toBeGreaterThanOrEqual(1);

    const rows = await liveUploads(user);

    // THE INVARIANT. Delete the JobLock and this fails: all eight read zero live
    // transfers before any of them writes, all eight pass, and eight staging rows
    // land in a three-transfer budget.
    expect(rows, 'a burst opened more transfers than the concurrency cap').toBeLessThanOrEqual(
      MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
    );
    // And nothing was opened that was not also reported, or the other way round.
    expect(rows).toBe(opened.length);
    expect(await openMultipartUploads()).toBe(opened.length);
    expect(storageRef.current!.storedKeys()).toEqual([]);

    // The consequence that makes this a data-loss bug rather than an accounting
    // one: every transfer this account can hold open will commit a document, and
    // the total has to stay inside the rotation payload's cap or the vault key can
    // never be rotated again.
    expect(
      MAX_DOCUMENTS_PER_USER - 1 + rows,
      'the reachable document total exceeds what a rotation payload may name',
    ).toBeLessThanOrEqual(MAX_DOCUMENTS_PER_ROTATION);

    // The cap is REACHABLE as well as enforced. A lock that simply refused
    // everything would satisfy every assertion above; this is the other direction,
    // and it is what pins the budget at three rather than at one.
    while ((await liveUploads(user)) < MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER) {
      const res = await (await prepareInit(user))();
      expect(res.status, JSON.stringify(res.body)).toBe(201);
    }
    const past = await (await prepareInit(user))();
    expect(past.status, JSON.stringify(past.body)).toBe(400);
    expect(String(past.body.message)).toMatch(/uploads in progress/i);
    expect(await liveUploads(user)).toBe(MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER);
  });

  it('refuses the open when transfers complete BETWEEN the two cap reads', async () => {
    // The bound the lock claims is `D + L`, where `D` is committed documents and
    // `L` is live staging rows — and the lock alone does not establish it, because
    // a COMPLETION holds a different lock (`documentCompleteLockName`, keyed by
    // upload, deliberately disjoint) and can land between the two reads. Reading
    // the live-transfer count FIRST is what closes that: `L` can only fall while
    // this request holds the lock, so the value it used bounds the rows still
    // outstanding when the document count is read.
    //
    // Read the other way round, `D = MAX_DOCUMENTS_PER_USER - 1` taken before
    // three completions land pairs with `L = 0` taken after them, both pass, and
    // the account finishes on `MAX_DOCUMENTS_PER_USER +
    // MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` — `MAX_DOCUMENTS_PER_ROTATION`
    // exactly, with the slack that constant documents reduced to nothing.
    //
    // The completions are SIMULATED, and that is the seam: a completion's whole
    // effect on these two counts is to delete a staging row and insert a document
    // row (`documentController.completeUpload`), which is what happens below. The
    // real path has its own suite in `document-complete.test.ts`; driving it here
    // would mean uploading parts to prove an arithmetic property that does not
    // depend on them.
    const OUTSTANDING = MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER;
    pinDocumentHeadroom(1);
    for (let i = 0; i < OUTSTANDING; i += 1) {
      await seedUpload(user);
    }

    // Park the open at its live-transfer read, which is where a completion is free
    // to interleave, and let the completions land while it is held there.
    let announceArrival!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceArrival = resolve;
    });
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });

    const realCount = DocumentUpload.countDocuments.bind(DocumentUpload) as unknown as (
      ...args: unknown[]
    ) => Promise<number>;
    let firstRead = true;
    vi.spyOn(DocumentUpload, 'countDocuments').mockImplementation(((...args: unknown[]) => {
      if (firstRead) {
        firstRead = false;
        announceArrival();
        return gate.then(() => realCount(...args));
      }
      return realCount(...args);
    }) as never);

    const send = await prepareInit(user);
    const pending = send();
    await parked;

    const staged = await DocumentUpload.find({ userId: user.id }).lean();
    expect(staged).toHaveLength(OUTSTANDING);
    for (const row of staged) {
      await seedDocument(user);
      await DocumentUpload.deleteOne({ _id: row._id });
    }

    openGate();
    const res = await pending;

    // Refused, and by the DOCUMENT cap: the live-transfer count it read is stale
    // low, so it is the count of committed rows — now at the ceiling — that stops
    // it. Which of the two refuses is not the point; that one of them does, is.
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(await DocumentUpload.countDocuments({ userId: user.id })).toBe(0);
    expect(await openMultipartUploads()).toBe(0);

    // The invariant, stated as the number it bounds. `pinDocumentHeadroom(1)` put
    // the account one row below the advertised limit before those transfers
    // completed, so its committed total is now exactly the documented maximum and
    // a rotation can still name every row of it.
    const committed = MAX_DOCUMENTS_PER_USER - 1 + OUTSTANDING;
    expect(committed).toBe(MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1);
    expect(
      committed + (await DocumentUpload.countDocuments({ userId: user.id })),
      'a completion landing between the two cap reads carried the account past the rotation payload cap',
    ).toBeLessThanOrEqual(MAX_DOCUMENTS_PER_ROTATION);
  });

  it('names the transfer-open lock per user, not globally', () => {
    // Every concurrency case above builds the contended key by calling the same
    // function the handler does, so none of them can tell a per-user lock from a
    // global one. Pinned literally here, and behaviourally in the case below.
    expect(documentInitLockName('507f1f77bcf86cd799439011')).toBe(
      'document-init:507f1f77bcf86cd799439011',
    );
    expect(documentInitLockName('a')).not.toBe(documentInitLockName('b'));
  });

  it('lets a second account open a transfer while the first account holds the lock', async () => {
    const other = await createTestUser({ email: 'document-init-other@example.com' });

    // Hold the FIRST account's lock for the duration. A global lock name would
    // refuse the second account with a 409; a per-user one must not notice — the
    // budgets this lock protects are per-user, so serializing strangers against
    // each other would be an availability bug with no cap behind it.
    const held = await acquireJobLock(documentInitLockName(user.id), 60_000);
    expect(held).not.toBeNull();

    try {
      const theirs = await (await prepareInit(other))();
      expect(theirs.status, JSON.stringify(theirs.body)).toBe(201);

      // And the first account really is still locked out, so this is not passing
      // simply because the lock was never held.
      const ours = await (await prepareInit(user))();
      expect(ours.status, JSON.stringify(ours.body)).toBe(409);
    } finally {
      await releaseJobLock(documentInitLockName(user.id), held!);
    }
  });

  it('releases the lock when the open is REFUSED', async () => {
    // A lock left behind by a refusal would block every retry for its whole TTL,
    // turning one 400 into a two-minute outage for that account's uploads.
    //
    // The name claims only what this pins. The handler ALSO releases before the
    // response is written, and that ordering is deliberately not asserted here:
    // the server's own `deleteOne` wins the race against any query a client could
    // issue afterwards, so moving the release below `res.json` would leave both
    // assertions green. The mirrored precedent is written the same honest way —
    // `document-complete.test.ts`'s "releases its lock even when the completion is
    // refused".
    for (let i = 0; i < MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER; i += 1) {
      await seedUpload(user);
    }

    const refused = await (await prepareInit(user))();
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(String(refused.body.message)).toMatch(/uploads in progress/i);
    expect(await JobLock.countDocuments({ jobName: documentInitLockName(user.id) })).toBe(0);

    // A slot frees up, and the very next request — sent with no delay after the
    // refusal above — succeeds rather than colliding with a lingering lock.
    await DocumentUpload.deleteOne({ userId: user.id });
    const accepted = await (await prepareInit(user))();
    expect(accepted.status, JSON.stringify(accepted.body)).toBe(201);
    expect(await JobLock.countDocuments({ jobName: documentInitLockName(user.id) })).toBe(0);
  });

  it('rotates an account whose payload names every row, at the overshoot the caps now permit', async () => {
    // The consequence of the cases above, and the half of "an account at the cap
    // can still rotate" that belongs on the SERVER. Split deliberately, because
    // the two halves fail for different reasons and only one of them needs volume:
    //
    //   • the ARITHMETIC — that the wire cap admits an array naming every row an
    //     account can hold — is a full-size question, and it is pinned by PARSING
    //     at that size in `packages/shared/tests/schemas.test.ts` ('accepts a
    //     documents leg naming every row an account can actually hold' / 'rejects
    //     a documents leg over MAX_DOCUMENTS_PER_ROTATION'), with the relation
    //     itself in `packages/shared/tests/constants.test.ts`. Not repeated here.
    //   • the HANDLER — that a payload naming every row passes
    //     `assertRotationCoversEveryRow` and rewraps all of them — does not depend
    //     on how many rows there are, so it is exercised at a scaled size below
    //     rather than by seeding five thousand rows into the fast tier.
    //
    // The precondition is derived from the two constants the handler ENFORCES,
    // never from `MAX_DOCUMENTS_PER_ROTATION`, which is the number it is checking.
    const reachableMaximum = MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1;
    expect(
      reachableMaximum,
      'a rotation payload cannot name every row an account can hold',
    ).toBeLessThanOrEqual(MAX_DOCUMENTS_PER_ROTATION);

    const SEEDED = 12;
    const ids: string[] = [];
    for (let i = 0; i < SEEDED; i += 1) {
      ids.push(await seedDocument(user));
    }

    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(ROTATE_PATH)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({
        authHash: user.rawPassword,
        items: [],
        newEncryptedVaultKey: 'rotated-vault-key',
        newVaultKeyIv: 'rotated-vault-key-iv',
        newVaultKeyTag: 'rotated-vault-key-tag',
        documents: ids.map((id) => ({
          id,
          encryptedDek: `dek-ciphertext-new-${id}`,
          dekIv: 'dek-iv-new',
          dekTag: 'dek-tag-new',
        })),
      });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    // Every row moved to the new wrap: a rotation that reported success while
    // leaving one row under the superseded key is the failure this whole leg
    // exists to prevent.
    const stale = await Document.countDocuments({
      userId: user.id,
      encryptedDek: 'dek-ciphertext-old',
    });
    expect(stale, 'a document was left wrapped under the superseded vault key').toBe(0);
  });
});
