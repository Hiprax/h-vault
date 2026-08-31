/**
 * `POST /documents/uploads`, `GET /documents/uploads`, `GET /documents/uploads/:id`
 * and `DELETE /documents/uploads/:id` — the three requests that open, describe and
 * abandon a transfer.
 *
 * ## What each refusal here has to prove
 *
 * Every refusal in this handler is a refusal to START something, so "it answered
 * 400" is half an assertion. The other half is that it left NOTHING behind: no
 * staging row (which would burn one of the caller's
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` slots and reserve quota that is never
 * released until a TTL fires) and no engine-side multipart upload (which would sit
 * in the bucket costing the operator money until the hourly collector found it,
 * with nothing in the database naming it). Both negatives are asserted in every
 * refusal case below.
 *
 * ## The two seams, and why they are the ones they are
 *
 * MONGO IS REAL. Ownership, the count cap, the concurrency cap and the quota are
 * all decided by a query, so a faked datastore would test the fake.
 *
 * OBJECT STORAGE IS A DOUBLE (`helpers/inMemoryStorage.ts`), because it is an
 * external service in the same class as SMTP and the breach API, and the same
 * contract suite runs that double and a real engine in the conformance gate — so
 * a divergence is a test failure elsewhere rather than a surprise in production.
 *
 * `storageConfigured` sits behind a mutable getter for the same reason
 * `config-endpoint.test.ts` does: the suite's real answer is "unconfigured" (the
 * four `S3_*` variables are pinned empty in `vitest.config.ts`), and the 503 that
 * answer produces is itself a case worth keeping in the same file as the happy
 * path.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_DOCUMENTS_PER_USER,
  documentUploadResponseSchema,
  initDocumentUploadResponseSchema,
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
import { config } from '../src/config/index.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, sampleFolder, type TestUser } from './helpers.js';

const BYTES_PER_MB = 1024 * 1024;
const UPLOADS_PATH = '/api/v1/documents/uploads';
/** The operator's per-user byte quota, as the handler computes it. */
const QUOTA_BYTES = config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER * BYTES_PER_MB;

/**
 * The wrapped-DEK and framing fields a valid init body carries.
 *
 * `streamSalt` and `noncePrefix` are padded base64 of EXACTLY 32 and 7 bytes:
 * `initDocumentUploadSchema` pins both byte counts (and the padding, because
 * 31, 32 and 33 bytes all encode to 44 characters), so an approximation here
 * would be rejected by the validator and every case in this file would fail for
 * the wrong reason.
 */
const FRAMING = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/** A valid init body for a transfer of `chunks` segments. */
function initBody(
  chunks: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...FRAMING,
    // One byte into the last segment, so `declaredChunkCount` is exactly `chunks`
    // under `ceil(bytes / DOCUMENT_PLAINTEXT_CHUNK_BYTES)`.
    declaredPlaintextBytes: (chunks - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
    declaredChunkCount: chunks,
    ...overrides,
  };
}

/** A live staging row for `user`, bypassing the handler. */
async function seedUpload(
  user: TestUser,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const uploadId = new mongoose.Types.ObjectId();
  const upload = await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, uploadId.toHexString()),
    ...FRAMING,
    declaredPlaintextBytes: 1024,
    declaredChunkCount: 1,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    ...overrides,
  });
  return String(upload._id);
}

/** A committed document row for `user`, of `plaintextBytes` in one segment. */
async function seedDocument(user: TestUser, plaintextBytes: number): Promise<void> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    ...FRAMING,
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: plaintextBytes + DOCUMENT_TAG_BYTES,
    plaintextBytes,
  });
}

type Method = 'get' | 'post' | 'delete';

/** One authenticated request through the real app, with a real CSRF pair. */
async function call(
  method: Method,
  path: string,
  user: TestUser,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const pending = agent[method](path).set('Authorization', authHeader(user.accessToken));
  const pair = await getCsrf(agent);
  pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token);
  if (body !== undefined) pending.send(body);
  return pending;
}

/** Every key the double holds, plus every multipart upload still open. */
async function engineState(): Promise<{ keys: string[]; uploads: number }> {
  const storage = storageRef.current!;
  return { keys: storage.storedKeys(), uploads: (await storage.listMultipartUploads()).length };
}

let user: TestUser;

beforeEach(async () => {
  storageState.configured = true;
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'documents-owner@example.com' });
});

describe('POST /documents/uploads opens a transfer', () => {
  it('mints the future document id and frames the transfer from the SERVER constant', async () => {
    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(initDocumentUploadResponseSchema.safeParse(res.body.data).success).toBe(true);
    const { uploadId, vaultKeyVersion, chunkPlaintextBytes } = res.body.data as {
      uploadId: string;
      vaultKeyVersion: number;
      chunkPlaintextBytes: number;
    };
    // The framing is the server's own constant, never anything the client sent —
    // the browser binds its key derivation to the id and frames its segments to
    // this number before it seals the first byte.
    expect(chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    expect(vaultKeyVersion).toBe(0);

    const row = await DocumentUpload.findById(uploadId).lean();
    expect(row).not.toBeNull();
    expect(row!.objectKey).toBe(buildObjectKey(user.id, uploadId));
    expect(row!.chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    expect(row!.receivedBytes).toBe(0);
    expect(row!.parts).toEqual([]);
    expect(row!.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // One segment is a `PutObject`, so there is no multipart handle to keep and
    // none was opened — three round trips saved on the common case of a small
    // file, and the reason `s3UploadId` is absent rather than empty.
    expect(row!.s3UploadId).toBeUndefined();
    expect(await engineState()).toEqual({ keys: [], uploads: 0 });
  });

  it('opens exactly one engine-side multipart upload for a multi-segment transfer', async () => {
    const res = await call('post', UPLOADS_PATH, user, initBody(3));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const uploadId = (res.body.data as { uploadId: string }).uploadId;
    const row = await DocumentUpload.findById(uploadId).lean();
    expect(row!.s3UploadId).toBeDefined();

    const open = await storageRef.current!.listMultipartUploads();
    expect(open).toHaveLength(1);
    expect(open[0]!.key).toBe(buildObjectKey(user.id, uploadId));
    expect(open[0]!.uploadId).toBe(row!.s3UploadId);
    // Nothing is STORED yet: opening a multipart upload writes no object.
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('echoes the caller’s current vault-key version, so completion can be checked against it', async () => {
    await User.updateOne({ _id: user.id }, { $set: { vaultKeyVersion: 4 } });

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect((res.body.data as { vaultKeyVersion: number }).vaultKeyVersion).toBe(4);
    const row = await DocumentUpload.findById(
      (res.body.data as { uploadId: string }).uploadId,
    ).lean();
    expect(row!.vaultKeyVersion).toBe(4);
  });

  it('ignores every server-assigned field a client tries to supply', async () => {
    // The allowlist, over the wire. A client that could choose `objectKey` could
    // address another account's object; one that could choose `chunkPlaintextBytes`
    // could frame its own segments; one that could choose `vaultKeyVersion` could
    // defeat the rotation check at completion.
    const foreignId = new mongoose.Types.ObjectId().toHexString();
    const res = await call('post', UPLOADS_PATH, user, {
      ...initBody(1),
      _id: foreignId,
      objectKey: 'u/attacker/d/anything',
      chunkPlaintextBytes: 99,
      vaultKeyVersion: 999,
      receivedBytes: 5_000_000,
      parts: [{ partNumber: 1, etag: 'forged', bytes: 8 }],
      expiresAt: new Date('2099-01-01').toISOString(),
    });

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const uploadId = (res.body.data as { uploadId: string }).uploadId;
    expect(uploadId).not.toBe(foreignId);

    const row = await DocumentUpload.findById(uploadId).lean();
    expect(row!.objectKey).toBe(buildObjectKey(user.id, uploadId));
    expect(row!.chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    expect(row!.vaultKeyVersion).toBe(0);
    expect(row!.receivedBytes).toBe(0);
    expect(row!.parts).toEqual([]);
    // The TTL the operator configured, not the year 2099.
    const ttlMs = config.DOCUMENT_UPLOAD_TTL_HOURS * 60 * 60 * 1000;
    expect(row!.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + ttlMs + 5_000);
  });

  it('accepts a folder the caller owns and records it on the staging row', async () => {
    const folder = await Folder.create({ userId: user.id, ...sampleFolder() });

    const res = await call(
      'post',
      UPLOADS_PATH,
      user,
      initBody(1, { folderId: String(folder._id) }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const row = await DocumentUpload.findById(
      (res.body.data as { uploadId: string }).uploadId,
    ).lean();
    expect(String(row!.folderId)).toBe(String(folder._id));
  });
});

describe('POST /documents/uploads refuses without leaving anything behind', () => {
  /** Asserts the two negatives every refusal here owes: no row, no engine upload. */
  async function expectNothingStarted(): Promise<void> {
    expect(await DocumentUpload.countDocuments({}), 'a refused init created a staging row').toBe(0);
    expect(await engineState()).toEqual({ keys: [], uploads: 0 });
  }

  it('answers 409 while a vault-key rotation is running', async () => {
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

    const res = await call('post', UPLOADS_PATH, user, initBody(3));

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(String(res.body.message)).toMatch(/rotation/i);
    // A wrapped DEK is ciphertext under the vault key being replaced, so a row
    // written here would be unreadable the moment the rotation committed.
    await expectNothingStarted();
  });

  it('answers 400 when the declared size exceeds the operator size cap', async () => {
    const overCap = config.MAX_DOCUMENT_SIZE_MB * BYTES_PER_MB + 1;
    const chunks = Math.ceil(overCap / DOCUMENT_PLAINTEXT_CHUNK_BYTES);

    const res = await call('post', UPLOADS_PATH, user, {
      ...FRAMING,
      declaredPlaintextBytes: overCap,
      declaredChunkCount: chunks,
    });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/too large/i);
    await expectNothingStarted();
  });

  it('answers 400 at the document count cap', async () => {
    // The cap is enforced from a COUNT, so the cheapest honest way to reach it is
    // to make the count say so. Seeding 5,000 real rows would test mongo's insert
    // throughput, not this branch.
    vi.spyOn(Document, 'countDocuments').mockResolvedValueOnce(MAX_DOCUMENTS_PER_USER as never);

    const res = await call('post', UPLOADS_PATH, user, initBody(2));

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/document limit/i);
    await expectNothingStarted();
  });

  it('answers 400 at the concurrent-transfer cap, counting only LIVE rows', async () => {
    for (let i = 0; i < MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER; i++) {
      await seedUpload(user);
    }

    const res = await call('post', UPLOADS_PATH, user, initBody(2));

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/uploads in progress/i);
    expect(await DocumentUpload.countDocuments({})).toBe(MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER);
    expect(await engineState()).toEqual({ keys: [], uploads: 0 });
  });

  it('does NOT count an expired staging row against the concurrency cap', async () => {
    // The control for the case above, and a real hazard: the TTL index reaps a
    // row when it gets round to it, so counting a dead transfer would lock a user
    // out of their own budget for as long as that lag lasts.
    for (let i = 0; i < MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER; i++) {
      await seedUpload(user, { expiresAt: new Date(Date.now() - 60_000) });
    }

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it('admits the transfer that exactly FILLS the quota', async () => {
    // The n side of the boundary, and the control for the case below: a check
    // written with the wrong comparison refuses this one, and a suite that only
    // tested the overflow would never notice.
    await seedDocument(user, QUOTA_BYTES - 1);

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(await DocumentUpload.countDocuments({})).toBe(1);
  });

  it('answers 400 for the byte PAST the quota', async () => {
    await seedDocument(user, QUOTA_BYTES);

    // `initBody(1)` declares a single byte, so this refusal is the n+1 side of
    // the boundary above and nothing else.
    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/quota/i);
    await expectNothingStarted();
  });

  it('counts bytes already RESERVED by a live transfer against the quota', async () => {
    // Committed bytes alone are not the budget: three concurrent transfers that
    // each fit on their own can exceed it together, and the whole point of
    // charging the DECLARED size at init is that the server has not received
    // those bytes yet.
    await seedUpload(user, { declaredPlaintextBytes: QUOTA_BYTES });

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/quota/i);
    // The seeded row survives and no second one joined it.
    expect(await DocumentUpload.countDocuments({})).toBe(1);
    expect(await engineState()).toEqual({ keys: [], uploads: 0 });
  });

  it('does NOT reserve quota for an EXPIRED transfer, which can never complete', async () => {
    // The other half of the rule above. A dead row's bytes are the garbage
    // collector's problem, not a reservation — charging for one would lock a user
    // out of their whole budget for as long as the TTL reaper lagged.
    await seedUpload(user, {
      declaredPlaintextBytes: QUOTA_BYTES,
      expiresAt: new Date(Date.now() - 60_000),
    });

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it('charges a TRASHED document against the quota, because its object still exists', async () => {
    const documentId = new mongoose.Types.ObjectId();
    await Document.create({
      _id: documentId,
      userId: user.id,
      objectKey: buildObjectKey(user.id, documentId.toHexString()),
      ...FRAMING,
      encryptedMeta: 'meta-ciphertext',
      metaIv: 'meta-iv',
      metaTag: 'meta-tag',
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: 1,
      ciphertextBytes: QUOTA_BYTES + DOCUMENT_TAG_BYTES,
      plaintextBytes: QUOTA_BYTES,
      deletedAt: new Date(),
    });

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/quota/i);
  });

  it("does not charge ANOTHER account's documents against this caller's quota", async () => {
    // Trivial to get wrong with an aggregate that forgets its `$match`, and the
    // symptom would be one large account making the service unusable for
    // everybody else.
    const stranger = await createTestUser({ email: 'documents-whale@example.com' });
    await seedDocument(stranger, QUOTA_BYTES);

    const res = await call('post', UPLOADS_PATH, user, initBody(1));

    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });

  it('answers 404 for a folder belonging to somebody else, and opens nothing', async () => {
    const stranger = await createTestUser({ email: 'documents-stranger@example.com' });
    const foreignFolder = await Folder.create({ userId: stranger.id, ...sampleFolder() });

    const res = await call(
      'post',
      UPLOADS_PATH,
      user,
      initBody(3, { folderId: String(foreignFolder._id) }),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(String(res.body.message)).toMatch(/folder/i);
    await expectNothingStarted();
    // …and the folder itself is untouched.
    expect(await Folder.countDocuments({ userId: stranger.id })).toBe(1);
  });

  it('answers 400 when the declared chunk count disagrees with the declared size', async () => {
    // The wire schema's own refine, checked here because the framing it pins is
    // what every later segment boundary is computed from.
    const res = await call('post', UPLOADS_PATH, user, {
      ...FRAMING,
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES * 3,
      declaredChunkCount: 1,
    });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/declaredChunkCount/);
    await expectNothingStarted();
  });

  it('answers 400 for a truncated stream salt, which is still valid base64', async () => {
    // 31 bytes encodes to the same 44 characters as 32; only the padding differs.
    // A salt one byte short would otherwise reach the row and surface, three
    // requests later, as a file that will not decrypt.
    const res = await call('post', UPLOADS_PATH, user, {
      ...FRAMING,
      streamSalt: Buffer.alloc(31, 7).toString('base64'),
      declaredPlaintextBytes: 10,
      declaredChunkCount: 1,
    });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/streamSalt/);
    await expectNothingStarted();
  });
});

describe('the document store refuses everything when no object storage is configured', () => {
  beforeEach(() => {
    storageState.configured = false;
  });

  it('answers 503 on every route, before any handler runs', async () => {
    const uploadId = new mongoose.Types.ObjectId().toHexString();
    const responses = await Promise.all([
      call('get', UPLOADS_PATH, user),
      call('post', UPLOADS_PATH, user, initBody(1)),
      call('get', `${UPLOADS_PATH}/${uploadId}`, user),
      call('delete', `${UPLOADS_PATH}/${uploadId}`, user),
    ]);

    for (const res of responses) {
      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(res.body.success).toBe(false);
    }
    // Nothing was written, and in particular the valid init body did not create a
    // row on a deployment that could never store its bytes.
    expect(await DocumentUpload.countDocuments({})).toBe(0);
  });

  it('still answers 401 to an unauthenticated caller, so the guard leaks no configuration', async () => {
    // `authenticate` runs FIRST. If the storage guard came first, an anonymous
    // probe could tell a deployment with a bucket from one without.
    const res = await request(app).get(UPLOADS_PATH);

    expect(res.status).toBe(401);
    expect(String(res.body.message)).toMatch(/no auth token/i);
  });
});

describe('GET /documents/uploads/:id', () => {
  it('returns the transfer without the wrapped key, the storage key or the engine handle', async () => {
    const uploadId = await seedUpload(user, {
      s3UploadId: 'engine-handle-1',
      parts: [{ partNumber: 1, etag: '"abc"', bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES }],
      receivedBytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
    });

    const res = await call('get', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(documentUploadResponseSchema.safeParse(res.body.data).success).toBe(true);
    const data = res.body.data as Record<string, unknown>;
    expect(data._id).toBe(uploadId);
    expect(data.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(data.parts).toEqual([{ partNumber: 1, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES }]);

    // The negatives. The client holds the DEK in memory for the life of the
    // transfer, so echoing the server's copy back would widen the exposure for
    // nothing; the object key is the one server-assigned address in the row; the
    // engine handle is not a client's to present.
    const serialized = JSON.stringify(res.body);
    for (const absent of ['encryptedDek', 'dekIv', 'dekTag', 'objectKey', 's3UploadId', 'userId']) {
      expect(data, `${absent} must not be echoed`).not.toHaveProperty(absent);
    }
    expect(serialized).not.toContain('engine-handle-1');
    expect(serialized).not.toContain(FRAMING.encryptedDek);
    // The engine's own receipt for the part is not a client's business either.
    expect(serialized).not.toContain('"abc"');
  });

  it('returns an EXPIRED transfer, which is how a user finds one to cancel', async () => {
    // Deliberately not filtered by expiry, unlike the caps: a dead row can accept
    // no part, but hiding it would leave a transfer nothing can point at. The
    // response carries `expiresAt` so the UI can say which it is.
    const uploadId = await seedUpload(user, { expiresAt: new Date(Date.now() - 60_000) });

    const res = await call('get', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(res.status).toBe(200);
    expect(new Date((res.body.data as { expiresAt: string }).expiresAt).getTime()).toBeLessThan(
      Date.now(),
    );
  });
});

describe('GET /documents/uploads', () => {
  it("returns only the caller's transfers, newest first", async () => {
    const stranger = await createTestUser({ email: 'documents-other@example.com' });
    const strangerUpload = await seedUpload(stranger);
    const older = await seedUpload(user, { createdAt: new Date(Date.now() - 60_000) });
    const newer = await seedUpload(user);

    const res = await call('get', UPLOADS_PATH, user);

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const ids = (res.body.data as { _id: string }[]).map((row) => row._id);
    expect(ids).toEqual([newer, older]);
    expect(ids, "another account's transfer was listed").not.toContain(strangerUpload);
    for (const row of res.body.data as Record<string, unknown>[]) {
      expect(documentUploadResponseSchema.safeParse(row).success).toBe(true);
      expect(row).not.toHaveProperty('encryptedDek');
      expect(row).not.toHaveProperty('objectKey');
    }
  });

  it('is an empty list, not a 404, for an account with no transfers', async () => {
    const res = await call('get', UPLOADS_PATH, user);

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([]);
  });
});

describe('DELETE /documents/uploads/:id abandons a transfer', () => {
  it('aborts the engine-side upload and deletes the staging row', async () => {
    const init = await call('post', UPLOADS_PATH, user, initBody(3));
    const uploadId = (init.body.data as { uploadId: string }).uploadId;
    expect(await storageRef.current!.listMultipartUploads()).toHaveLength(1);

    const res = await call('delete', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.success).toBe(true);
    expect(await DocumentUpload.findById(uploadId).lean()).toBeNull();
    // The parts the engine was holding are released, not merely forgotten.
    expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });

  it('deletes a single-segment transfer without calling the engine at all', async () => {
    // No `s3UploadId` means no multipart upload to abort. Calling the engine here
    // anyway would be a request per cancellation for nothing, and on a
    // single-segment transfer there is no handle to pass it.
    const uploadId = await seedUpload(user);
    const abortSpy = vi.spyOn(storageRef.current!, 'abortMultipartUpload');

    const res = await call('delete', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(res.status).toBe(200);
    expect(abortSpy).not.toHaveBeenCalled();
    expect(await DocumentUpload.findById(uploadId).lean()).toBeNull();
  });

  it('answers 404 the second time, having already deleted the row', async () => {
    const uploadId = await seedUpload(user);
    await call('delete', `${UPLOADS_PATH}/${uploadId}`, user);

    const repeat = await call('delete', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(repeat.status).toBe(404);
    expect(repeat.body.success).toBe(false);
  });

  it('keeps the row and reports the failure when the engine refuses the abort', async () => {
    // The order is abort-then-delete precisely so this case leaves a row that
    // still NAMES the engine-side upload: deleting first would orphan it, and the
    // collector would have to find it by age instead.
    const uploadId = await seedUpload(user, { s3UploadId: 'engine-handle-2' });
    vi.spyOn(storageRef.current!, 'abortMultipartUpload').mockRejectedValueOnce(
      new Error('engine unreachable'),
    );

    const res = await call('delete', `${UPLOADS_PATH}/${uploadId}`, user);

    expect(res.status).toBe(500);
    expect(await DocumentUpload.findById(uploadId).lean()).not.toBeNull();
  });
});
