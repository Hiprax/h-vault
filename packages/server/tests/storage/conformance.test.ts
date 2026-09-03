/**
 * `test:storage` — the storage port against the engine this stack actually ships.
 *
 * Everywhere else in the push tier, object storage is a double
 * (`helpers/inMemoryStorage.ts`), because it is an external service in the same
 * class as SMTP and the datastore under test is Mongo. That is the right seam,
 * and it has one blind spot: a double agrees with whatever we believed when we
 * wrote it. This file is where that belief is checked against a real engine.
 *
 * ## What is here that is not in `storage-contract.test.ts`
 *
 * The shared contract (`helpers/storageContract.ts`) runs UNCHANGED against the
 * real provider, and that is the point of it — the double stands in for this, so
 * both must pass the identical cases. What this file adds is everything the
 * contract deliberately refuses to state, because it is a property of THIS engine
 * rather than of the port:
 *
 *   * **a short middle part is stored without complaint** — the measurement the
 *     whole gate exists for. Nothing below the server refuses one, and the server
 *     is asserted here to refuse it, through the real route, with the real engine
 *     behind it. A defect that relaxed that check is invisible to every other kind
 *     of test: the request succeeds, the object is written, and the document
 *     becomes permanently unreadable at a point in the file nobody can predict.
 *   * **8 MiB parts, at the real framing size**, against the engine configured
 *     with `block_size = "8M"` — so one crypto segment is one part is one block is
 *     one ranged read, end to end, rather than by construction in a Map.
 *   * **which name the engine gives each kind of absence**, which is what decides
 *     whether `mapStorageError` answers 404 or 503. A test with the SDK mocked can
 *     only assert that our mapping handles the names we imagined.
 *
 * ## Seams
 *
 * The ENGINE is real and in a container (`tests/harness/s3Server.ts`, shared with
 * the end-to-end harness). MONGO is real, as everywhere in this package. Nothing
 * is mocked except `services/storage/index.js`, and that is mocked in order to
 * install the REAL provider pointed at the container rather than to replace it.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
} from '@hvault/shared';
import { startStorageEngine, type StorageEngine } from '../../../../tests/harness/s3Server.js';
import { createS3Provider } from '../../src/services/storage/s3Provider.js';
import type { StorageProvider, StorageRangeRead } from '../../src/services/storage/types.js';
import { runStorageContract } from '../helpers/storageContract.js';

vi.mock('../../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { providerRef } = vi.hoisted(() => ({
  providerRef: { current: undefined as StorageProvider | undefined },
}));

vi.mock('../../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      if (providerRef.current === undefined) {
        throw new Error('the real storage provider was not installed for this test');
      }
      return providerRef.current;
    },
  };
});

import app from '../../src/app.js';
import { DocumentUpload } from '../../src/models/DocumentUpload.js';
import { PART_DIGEST_HEADER } from '../../src/controllers/documentController.js';
import { buildObjectKey } from '../../src/utils/documentObjects.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from '../helpers.js';

let engine: StorageEngine;
let provider: StorageProvider;

beforeAll(async () => {
  engine = await startStorageEngine({
    // The readiness probe IS the port's own `headBucket`, built from the same
    // provider every case below uses — so "ready" means ready for this client's
    // credentials, signing and addressing, not merely that a socket answers.
    probe: (connection) => createS3Provider(connection).headBucket(),
  });
  provider = createS3Provider(engine);
  providerRef.current = provider;
}, 120_000);

afterAll(async () => {
  await engine.stop();
});

/**
 * A key nothing else in this run uses.
 *
 * The bucket is shared across the whole file — one container per file, not one
 * per case — so uniqueness cannot be assumed from an empty bucket the way it can
 * with the double. Built through `buildObjectKey` so the engine is exercised with
 * the key SHAPE production uses, including its `u/<user>/d/<document>` prefix.
 */
function uniqueKey(): string {
  return buildObjectKey(randomBytes(12).toString('hex'), randomBytes(12).toString('hex'));
}

/**
 * Bytes with a recognisable pattern.
 *
 * Never `Buffer.alloc(n)`: a run of identical bytes survives being reordered,
 * truncated in the middle and re-expanded, so a body of zeros would let exactly
 * the class of corruption this file exists to detect pass every comparison in it.
 */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let index = 0; index < bytes; index += 1) {
    buffer[index] = (index * 31 + (index >> 8) + seed) & 0xff;
  }
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

/** Reads a ranged read to the end, as a digest, so an 8 MiB compare stays cheap. */
async function digestOfRange(read: StorageRangeRead): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of read.body) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

// ---------------------------------------------------------------------------
// The shared contract, unchanged, against the real engine
// ---------------------------------------------------------------------------

runStorageContract('real engine in a container', () => ({ provider, uniqueKey }));

// ---------------------------------------------------------------------------
// What only a real engine can answer
// ---------------------------------------------------------------------------

describe('the engine, at the real framing size', () => {
  it('returns every 8 MiB segment at exactly the offset the framing predicts', async () => {
    // One crypto segment is one uploaded part is one downloaded range, and the
    // engine is configured with `block_size = "8M"` so that one part is also
    // exactly one engine block. Everything else in this repository takes that
    // correspondence on trust — the double concatenates Buffers, and the upload
    // suites assert against the double. This is the only place it is measured
    // against the thing production talks to, at the size production uses.
    const key = uniqueKey();
    const first = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 1);
    const second = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 2);
    const final = pattern(1234, 3);
    const uploadId = await provider.createMultipartUpload(key);

    const uploaded = [
      await provider.uploadPart(key, uploadId, 1, first),
      await provider.uploadPart(key, uploadId, 2, second),
      await provider.uploadPart(key, uploadId, 3, final),
    ];

    // The ledger the completion step verifies, reported by the engine itself.
    const ledger = await provider.listParts(key, uploadId);
    expect(ledger.map((part) => part.partNumber)).toEqual([1, 2, 3]);
    expect(ledger.map((part) => part.bytes)).toEqual([
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      1234,
    ]);

    await provider.completeMultipartUpload(
      key,
      uploadId,
      uploaded.map((part) => ({ partNumber: part.partNumber, etag: part.etag })),
    );

    const stat = await provider.headObject(key);
    expect(stat.bytes).toBe(2 * DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 1234);

    // Segment `i` starts at `i * DOCUMENT_CIPHERTEXT_CHUNK_BYTES`, computed
    // rather than looked up, which is the property the read path rests on.
    const segment = async (index: number, bytes: number): Promise<string> => {
      const start = index * DOCUMENT_CIPHERTEXT_CHUNK_BYTES;
      const read = await provider.getObjectRange(key, start, start + bytes - 1);
      expect(read.bytes).toBe(bytes);
      return digestOfRange(read);
    };
    expect(await segment(0, DOCUMENT_CIPHERTEXT_CHUNK_BYTES)).toBe(digestOf(first));
    expect(await segment(1, DOCUMENT_CIPHERTEXT_CHUNK_BYTES)).toBe(digestOf(second));
    expect(await segment(2, 1234)).toBe(digestOf(final));
    // The negative: two segments of the same length must not read back the same
    // bytes, which is what a range that ignored its offset would produce.
    expect(digestOf(first)).not.toBe(digestOf(second));

    await provider.deleteObject(key);
  });

  it('STORES A SHORT MIDDLE PART, which is why the server is the only thing refusing one', async () => {
    // The measurement this whole gate exists for, and it is a permission rather
    // than a refusal: S3's contract only ever exempts the LAST part from the
    // minimum, and this engine does not enforce even that. A short middle part is
    // accepted, completed, and the finished object is SHORTER than the framing
    // predicts — so segment 1 no longer begins at one chunk, every later ranged
    // read authenticates as nothing, and the document can never be opened again.
    // Nothing announces it. If this case ever goes red, the engine has grown a
    // check of its own and the server's is no longer the only line of defence —
    // which is worth knowing, but is not a reason to remove the server's.
    const key = uniqueKey();
    const short = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 1, 4);
    const second = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 5);
    const uploadId = await provider.createMultipartUpload(key);

    const first = await provider.uploadPart(key, uploadId, 1, short);
    const middle = await provider.uploadPart(key, uploadId, 2, second);
    const final = await provider.uploadPart(key, uploadId, 3, pattern(10, 6));

    expect((await provider.listParts(key, uploadId)).map((part) => part.bytes)).toEqual([
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 1,
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      10,
    ]);

    await provider.completeMultipartUpload(key, uploadId, [
      { partNumber: 1, etag: first.etag },
      { partNumber: 2, etag: middle.etag },
      { partNumber: 3, etag: final.etag },
    ]);

    const stat = await provider.headObject(key);
    expect(stat.bytes).toBe(2 * DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 9);

    // And the damage, stated as bytes rather than as a description: the range the
    // framing says holds segment 1 holds something else entirely.
    const read = await provider.getObjectRange(
      key,
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      2 * DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 1,
    );
    expect(await digestOfRange(read)).not.toBe(digestOf(second));

    await provider.deleteObject(key);
  });

  it('reports every open upload under a prefix, in a STABLE order that is the engine’s own', async () => {
    // The engine's LISTING ORDER, recorded rather than required, and this is the
    // case that found it. The shared contract used to assert key order for every
    // implementation, on the strength of AWS's ListMultipartUploads reference — and
    // that reference documents key-then-initiation-time sorting for a general
    // purpose bucket while documenting a directory bucket, in the same block, as one
    // where the uploads "aren't sorted lexicographically based on the object keys".
    // So it was never a property of "S3", and it is not one of this engine: measured
    // here, five uploads opened for keys zz, aa, mm, bb, yy came back as
    // yy, bb, mm, zz, aa — exactly the set sorted by UPLOAD ID, stable across
    // repeated calls, and uncorrelated with both key and age.
    //
    // What is ASSERTED below is only the part that decides a design question:
    // completeness and stability. Ordering by upload id is a third-party
    // implementation detail nothing here depends on, so pinning it would be a gate
    // that goes red when nobody is harmed. Stability is worth pinning, because it is
    // the difference between two sentences a maintainer may write in
    // `documentCleanup.ts`: under a VARYING order a backlog would drain by
    // resampling the head, and under this stable one it drains only by the counting
    // argument that docblock actually makes. That argument is the safe one either
    // way, and this is what says the unsafe one may not be written.
    const base = uniqueKey();
    const keys = ['zz', 'aa', 'mm', 'bb', 'yy'].map((suffix) => `${base}-${suffix}`);
    const opened = new Map<string, string>();
    for (const key of keys) opened.set(key, await provider.createMultipartUpload(key));

    const first = await provider.listMultipartUploads(`${base}-`);
    const second = await provider.listMultipartUploads(`${base}-`);

    expect(first.map((upload) => upload.key).sort()).toEqual([...keys].sort());
    // Stable: two calls with nothing changed in between report the same sequence.
    expect(second.map((upload) => `${upload.key}#${upload.uploadId}`)).toEqual(
      first.map((upload) => `${upload.key}#${upload.uploadId}`),
    );
    // And every entry is addressable, which is what an abort needs: the id that
    // came back with a key must be the id that key's upload was opened with.
    for (const upload of first) {
      expect(upload.uploadId).toBe(opened.get(upload.key));
    }

    for (const [key, uploadId] of opened) await provider.abortMultipartUpload(key, uploadId);
  });

  it('dates an open upload from when it was opened, which is what the collector filters on', async () => {
    // The contract asserts `initiated` is a Date. What it cannot assert is that
    // the engine populates it with a real instant: the garbage collector aborts an
    // upload only once it can prove the upload is older than
    // `DOCUMENT_UPLOAD_TTL_HOURS`, so an engine that reported the epoch would make
    // the sweep abort live transfers, and one that reported `undefined` would make
    // it abort none of them ever.
    const key = uniqueKey();
    const before = Date.now();
    const uploadId = await provider.createMultipartUpload(key);

    const listed = await provider.listMultipartUploads(key);

    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({ key, uploadId });
    const initiated = listed[0]?.initiated;
    expect(initiated).toBeInstanceOf(Date);
    // A five-minute window either side: wide enough that a loaded machine or a
    // second of clock skew inside the container cannot flake it, narrow enough
    // that the epoch, a null date and "now plus a day" all fail.
    expect(initiated!.getTime()).toBeGreaterThan(before - 300_000);
    expect(initiated!.getTime()).toBeLessThan(before + 300_000);

    await provider.abortMultipartUpload(key, uploadId);
  });
});

describe('the names this engine gives an absence, which decide 404 or 503', () => {
  /** A provider pointed at a bucket that was never created. */
  const wrongBucket = (): StorageProvider =>
    createS3Provider({
      endpoint: engine.endpoint,
      region: engine.region,
      bucket: 'hvault-harness-no-such-bucket',
      accessKeyId: engine.accessKeyId,
      secretAccessKey: engine.secretAccessKey,
      forcePathStyle: engine.forcePathStyle,
    });

  it('names the missing BUCKET on every operation that can carry an error body, so it reads as 503', async () => {
    // `mapStorageError` deliberately keeps `NoSuchBucket` OUT of its not-found set
    // and in its unavailable set, because the two mean opposite things to a user:
    // a missing object is "this file is gone", while a missing bucket is a
    // misconfigured deployment in which EVERY document reads as gone. That
    // decision is only worth anything if the engine actually says `NoSuchBucket`,
    // and no test with the SDK mocked can establish that — it can only replay the
    // name we already assumed.
    const storage = wrongBucket();
    const key = uniqueKey();

    await expect(storage.getObjectRange(key, 0, 7)).rejects.toMatchObject({ statusCode: 503 });
    await expect(storage.listObjects('u/')).rejects.toMatchObject({ statusCode: 503 });
    await expect(storage.putObject(key, Buffer.from('x'))).rejects.toMatchObject({
      statusCode: 503,
    });
    await expect(storage.createMultipartUpload(key)).rejects.toMatchObject({ statusCode: 503 });
    // The negative that carries the whole decision: none of these may be the 404
    // the read path renders as "this file is gone".
    await expect(storage.getObjectRange(key, 0, 7)).rejects.not.toMatchObject({ statusCode: 404 });
  });

  it('cannot name it on a HEAD, which is the protocol rather than a mapping to fix', async () => {
    // Measured, and recorded so nobody "fixes" it: a HEAD response carries no
    // body, so there is no error document for the engine to put `NoSuchBucket`
    // in and the SDK can only synthesise `NotFound` from the status. Both
    // `headBucket` and `headObject` therefore report a missing bucket as 404.
    //
    // It costs nothing where it happens. `headBucket` is the boot preflight,
    // which never rejects and only records a probe result, and `headObject` is
    // never the sole basis for telling a user their file is gone — the read path
    // reaches `getObjectRange`, which is in the case above and does carry the
    // name. Widening the classifier to treat a bare 404 from a HEAD as
    // unavailable would misreport every genuinely missing object instead.
    const storage = wrongBucket();

    await expect(storage.headBucket()).rejects.toMatchObject({ statusCode: 404 });
    await expect(storage.headObject(uniqueKey())).rejects.toMatchObject({ statusCode: 404 });
  });

  it('separates a missing key, a missing upload and an already-deleted object', async () => {
    // Three different absences that `mapStorageError` folds into one 404, and one
    // that is not an error at all. The last is what makes the purge path safe to
    // run twice after a crash, and it is a property of the SERVICE rather than of
    // our code: S3 delete is specified as idempotent, and this asserts the engine
    // agrees rather than assuming it.
    const key = uniqueKey();

    await expect(provider.getObjectRange(key, 0, 7)).rejects.toMatchObject({ statusCode: 404 });
    await expect(provider.headObject(key)).rejects.toMatchObject({ statusCode: 404 });
    await expect(provider.listParts(key, 'no-such-upload-id')).rejects.toMatchObject({
      statusCode: 404,
    });
    await expect(provider.abortMultipartUpload(key, 'no-such-upload-id')).rejects.toMatchObject({
      statusCode: 404,
    });
    await expect(provider.deleteObject(key)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The server, in front of the real engine
// ---------------------------------------------------------------------------

describe('the server in front of that engine', () => {
  /** The wrapped-DEK and framing columns a staging row carries. Opaque here. */
  const FRAMING = {
    encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
    dekIv: 'ZGVrLWl2LWJhc2U2NA==',
    dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
    streamSalt: Buffer.alloc(32, 7).toString('base64'),
    noncePrefix: Buffer.alloc(7, 3).toString('base64'),
  };

  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser({ email: 'storage-conformance@example.com' });
  });

  /**
   * A live staging row with a REAL engine-side multipart upload behind it.
   *
   * Seeded rather than driven through `POST /uploads`, exactly as
   * `document-parts.test.ts` does it: this case is about the part handler, and
   * going through init would make it fail for init's reasons too.
   */
  async function seedUpload(
    chunks: number,
  ): Promise<{ id: string; objectKey: string; s3UploadId: string }> {
    const uploadId = new mongoose.Types.ObjectId();
    const objectKey = buildObjectKey(user.id, uploadId.toHexString());
    const s3UploadId = await provider.createMultipartUpload(objectKey);

    await DocumentUpload.create({
      _id: uploadId,
      userId: user.id,
      objectKey,
      s3UploadId,
      ...FRAMING,
      declaredPlaintextBytes: (chunks - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      declaredChunkCount: chunks,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      vaultKeyVersion: 0,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });

    return { id: String(uploadId), objectKey, s3UploadId };
  }

  /** One authenticated part upload through the real app, with a real CSRF pair. */
  async function putPart(
    uploadId: string,
    partNumber: number,
    body: Buffer,
  ): Promise<request.Response> {
    const agent = request.agent(app);
    const pending = agent
      .put(`/api/v1/documents/uploads/${uploadId}/parts/${String(partNumber)}`)
      .set('Authorization', authHeader(user.accessToken));
    const pair = await getCsrf(agent);
    return pending
      .set('Cookie', pair.cookie)
      .set('x-csrf-token', pair.token)
      .set(PART_DIGEST_HEADER, digestOf(body))
      .type('application/octet-stream')
      .send(body);
  }

  it('REFUSES the short middle part the engine above would have taken, and stores nothing', async () => {
    // The pair to the engine case above, and the assertion that justifies this
    // gate's existence: the engine accepts a short middle part, the server does
    // not, and the server is the only thing in the chain that does. Asserted
    // through the real route against the real engine, so a relaxed check cannot
    // be hidden by a double that refuses on the server's behalf.
    const seeded = await seedUpload(3);
    const short = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 1, 7);

    const res = await putPart(seeded.id, 1, short);

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/must be exactly/i);

    // The three negatives, and the middle one is the whole point: a handler that
    // answered 400 AFTER forwarding the bytes would pass a status-only test while
    // leaving a part in the engine that the completion step would happily
    // assemble.
    expect(await provider.listParts(seeded.objectKey, seeded.s3UploadId)).toEqual([]);
    await expect(provider.headObject(seeded.objectKey)).rejects.toMatchObject({ statusCode: 404 });
    const row = await DocumentUpload.findById(seeded.id).lean();
    expect(row?.parts ?? []).toEqual([]);
    expect(row?.receivedBytes ?? -1).toBe(0);

    await provider.abortMultipartUpload(seeded.objectKey, seeded.s3UploadId);
  });

  it('stores a full-size non-final part in the engine and records the engine’s own etag', async () => {
    // The happy path, which is what makes the refusal above mean something: the
    // same route, the same engine, one byte different in the size, and the part
    // arrives. Without it, a handler that refused every part would pass the case
    // above.
    const seeded = await seedUpload(3);
    const body = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 8);

    const res = await putPart(seeded.id, 1, body);

    expect(res.status, JSON.stringify(res.body)).toBe(200);

    const ledger = await provider.listParts(seeded.objectKey, seeded.s3UploadId);
    expect(ledger).toHaveLength(1);
    expect(ledger[0]).toMatchObject({ partNumber: 1, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES });

    const row = await DocumentUpload.findById(seeded.id).lean();
    expect(row?.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    // Verbatim, quotes included: S3 returns the ETag quoted and compares the same
    // string at completion, so a server that normalised it would hand the engine
    // a value it does not recognise — and a double free to invent its own etag
    // format could never surface that.
    expect(row?.parts?.[0]?.etag).toBe(ledger[0]?.etag);
    expect(String(row?.parts?.[0]?.etag)).toMatch(/^".+"$/);

    await provider.abortMultipartUpload(seeded.objectKey, seeded.s3UploadId);
  });

  it('lets the LAST part be short, down to a bare authentication tag', async () => {
    // The other side of the rule, against the real engine: the final part is the
    // only one allowed to be short, and the engine takes it. A server that
    // refused short parts outright would make every document whose plaintext is
    // not an exact multiple of the chunk size unstorable.
    const seeded = await seedUpload(2);
    const body = pattern(DOCUMENT_TAG_BYTES, 9);

    const res = await putPart(seeded.id, 2, body);

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const ledger = await provider.listParts(seeded.objectKey, seeded.s3UploadId);
    expect(ledger.map((part) => part.bytes)).toEqual([DOCUMENT_TAG_BYTES]);

    await provider.abortMultipartUpload(seeded.objectKey, seeded.s3UploadId);
  });
});
