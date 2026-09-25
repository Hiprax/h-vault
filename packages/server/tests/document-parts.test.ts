/**
 * `PUT /documents/uploads/:id/parts/:partNumber` — the one request that carries a
 * document's bytes.
 *
 * ## What a refusal here has to prove
 *
 * Every case below asserts three things, not one: the status, that the STORAGE
 * ENGINE holds nothing new, and that the STAGING LEDGER did not grow. A handler
 * that answered 400 after forwarding the bytes would pass a status-only test while
 * leaving an object in the bucket the user is charged for and the collector has to
 * find; one that answered 400 after appending to the ledger would make completion
 * derive a `chunkCount` from a part that does not exist.
 *
 * ## The rule the engine itself does not enforce
 *
 * A NON-FINAL part must be exactly `DOCUMENT_CIPHERTEXT_CHUNK_BYTES`. Garage was
 * measured ACCEPTING a short middle part, and S3's own contract only requires that
 * the last part be allowed to be short. Nothing below the server refuses one, and a
 * short middle part moves every later segment boundary by the shortfall, so every
 * subsequent ranged read decrypts to nothing. The case named "a short middle part"
 * is therefore the most important test in this file.
 *
 * ## The two seams
 *
 * MONGO IS REAL: ownership, expiry and the ledger are all decided by a query.
 * OBJECT STORAGE IS A DOUBLE (`helpers/inMemoryStorage.ts`), because it is an
 * external service in the same class as SMTP, and the same contract suite runs that
 * double and a real engine in the conformance gate.
 */
import { createHash } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_IN_FLIGHT_PART_UPLOADS,
} from '@hvault/shared';

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

import app from '../src/app.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { Document } from '../src/models/Document.js';
import { JobLock } from '../src/models/JobLock.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { documentCompleteLockName } from '../src/utils/controllerHelpers.js';
import { PART_DIGEST_HEADER, uploadPart } from '../src/controllers/documentController.js';
import { PART_BODY_LIMIT_BYTES } from '../src/middleware/documentPartBody.js';
import { partUploadSemaphore } from '../src/utils/partSemaphore.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

/** The wrapped-DEK and framing columns a staging row carries. Opaque here. */
const FRAMING = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/**
 * A body whose bytes vary along its length.
 *
 * Never `Buffer.alloc(n)`. A run of identical bytes survives being reordered,
 * truncated in the middle and re-expanded, so a body of zeros would let a whole
 * class of corruption through every digest and length check in this file.
 */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

/** One sealed segment's worth of bytes: the size every non-final part must be. */
const fullPart = (): Buffer => pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);

interface SeedOptions {
  chunks?: number;
  multipart?: boolean;
  expiresAt?: Date;
}

interface Seeded {
  id: string;
  objectKey: string;
  s3UploadId: string | undefined;
}

/**
 * A live staging row, with the engine-side multipart upload a real init would have
 * opened for a multi-segment transfer.
 *
 * Seeded rather than driven through `POST /uploads` on purpose: this file is about
 * the part handler, and going through init would make every case here fail for
 * init's reasons too.
 */
async function seedUpload(user: TestUser, options: SeedOptions = {}): Promise<Seeded> {
  const chunks = options.chunks ?? 1;
  const multipart = options.multipart ?? chunks > 1;
  const uploadId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(user.id, uploadId.toHexString());
  const s3UploadId = multipart
    ? await storageRef.current!.createMultipartUpload(objectKey)
    : undefined;

  await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey,
    ...(s3UploadId === undefined ? {} : { s3UploadId }),
    ...FRAMING,
    declaredPlaintextBytes: (chunks - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
    declaredChunkCount: chunks,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    expiresAt: options.expiresAt ?? new Date(Date.now() + 60 * 60 * 1000),
  });

  return { id: String(uploadId), objectKey, s3UploadId };
}

const partPath = (uploadId: string, partNumber: number | string): string =>
  `/api/v1/documents/uploads/${uploadId}/parts/${String(partNumber)}`;

interface PutOptions {
  body?: Buffer;
  /** Omit to send no digest header at all. */
  digest?: string | null;
  contentType?: string | null;
  headers?: Record<string, string>;
}

/** One authenticated part upload through the real app, with a real CSRF pair. */
async function putPart(
  user: TestUser,
  uploadId: string,
  partNumber: number | string,
  options: PutOptions = {},
): Promise<request.Response> {
  const body = options.body ?? Buffer.alloc(DOCUMENT_TAG_BYTES, 1);
  const agent = request.agent(app);
  const pair = await getCsrf(agent);
  const pending = agent
    .put(partPath(uploadId, partNumber))
    .set('Authorization', authHeader(user.accessToken));
  pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token);

  const digest = options.digest === undefined ? digestOf(body) : options.digest;
  if (digest !== null) pending.set(PART_DIGEST_HEADER, digest);
  for (const [name, value] of Object.entries(options.headers ?? {})) pending.set(name, value);

  if (options.contentType !== null) {
    pending.type(options.contentType ?? 'application/octet-stream');
  }
  return pending.send(body);
}

/**
 * One PUT with a chunked body and NO `Content-Length`, over a real socket.
 *
 * supertest cannot express this: superagent computes `Content-Length` from the
 * body it is handed, and setting `Transfer-Encoding` alongside it produces a
 * request Node refuses on its own as a smuggling shape. `http.request` chunks
 * automatically when no length is set, which is exactly the client this guard
 * exists for.
 */
async function chunkedPut(
  path: string,
  body: Buffer,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const server = app.listen(0);
  try {
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const { port } = server.address() as AddressInfo;
    return await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'PUT', path, headers }, (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => (text += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** The ledger and the engine, as one object, for the "nothing happened" assertions. */
async function stateOf(seeded: Seeded): Promise<{
  parts: { partNumber: number; bytes: number; etag?: string }[];
  receivedBytes: number;
  storedKeys: string[];
  engineParts: number;
}> {
  const row = await DocumentUpload.findById(seeded.id).lean();
  const storage = storageRef.current!;
  return {
    parts: (row?.parts ?? []).map((part) => ({
      partNumber: part.partNumber,
      bytes: part.bytes,
      ...(part.etag === undefined ? {} : { etag: part.etag }),
    })),
    receivedBytes: row?.receivedBytes ?? -1,
    storedKeys: storage.storedKeys(),
    engineParts:
      seeded.s3UploadId === undefined
        ? 0
        : (await storage.listParts(seeded.objectKey, seeded.s3UploadId)).length,
  };
}

/** The state a transfer is in before its first part: nothing anywhere. */
const UNTOUCHED = { parts: [], receivedBytes: 0, storedKeys: [], engineParts: 0 };

let user: TestUser;

beforeEach(async () => {
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'document-parts@example.com' });
});

// ---------------------------------------------------------------------------
// The happy paths, which are what make every refusal below mean something
// ---------------------------------------------------------------------------

describe('storing a part', () => {
  it('stores a single-segment transfer as ONE whole object, with no engine receipt', async () => {
    const seeded = await seedUpload(user, { chunks: 1 });
    const body = pattern(4096 + DOCUMENT_TAG_BYTES);

    const res = await putPart(user, seeded.id, 1, { body });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toEqual({
      partNumber: 1,
      bytes: body.length,
      receivedBytes: body.length,
    });

    // The bytes are the object, verbatim — one segment is one `PutObject`, not a
    // one-part multipart upload, which would cost three round trips for the common
    // case of a small file.
    const storage = storageRef.current!;
    expect(storage.storedKeys()).toEqual([seeded.objectKey]);
    expect(digestOf(storage.readObject(seeded.objectKey)!)).toBe(digestOf(body));
    expect(await storage.listMultipartUploads()).toEqual([]);

    // …and the ledger entry carries NO etag, because `PutObject` returns none. The
    // key must be absent rather than empty: completion tells the two paths apart.
    const row = await DocumentUpload.findById(seeded.id).lean();
    expect(row!.parts).toHaveLength(1);
    expect(row!.parts[0]!.etag).toBeUndefined();
    expect(row!.receivedBytes).toBe(body.length);
  });

  it('stores a multi-segment part through the engine and keeps its etag verbatim', async () => {
    const seeded = await seedUpload(user, { chunks: 3 });
    const body = fullPart();

    const res = await putPart(user, seeded.id, 2, { body });

    expect(res.status, JSON.stringify(res.body)).toBe(200);

    // The etag on the row is the engine's own, character for character. Anything
    // else — a locally computed digest, a normalised copy with the quotes stripped
    // — would be refused by a real engine as `InvalidPart` at completion time,
    // which is one request too late to recover from.
    const storage = storageRef.current!;
    const engineParts = await storage.listParts(seeded.objectKey, seeded.s3UploadId!);
    expect(engineParts).toHaveLength(1);
    const row = await DocumentUpload.findById(seeded.id).lean();
    expect(row!.parts[0]!.etag).toBe(engineParts[0]!.etag);
    expect(row!.parts[0]).toMatchObject({ partNumber: 2, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES });

    // A multipart upload writes no object until it is completed.
    expect(storage.storedKeys()).toEqual([]);
  });

  it('lets the LAST part be short, down to a bare authentication tag', async () => {
    // A zero-byte final segment seals to exactly one tag. It is legal, and it is
    // the boundary the non-final rule must not be allowed to swallow.
    const seeded = await seedUpload(user, { chunks: 2 });
    const body = Buffer.alloc(DOCUMENT_TAG_BYTES, 9);

    const res = await putPart(user, seeded.id, 2, { body });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect((await stateOf(seeded)).receivedBytes).toBe(DOCUMENT_TAG_BYTES);
  });

  it('replaces a re-sent part instead of counting it twice', async () => {
    // The property that makes a retry safe. A client that retries part 2 after a
    // timeout must not leave the transfer believing it received two of them: the
    // quota is charged from `receivedBytes`, and completion derives `chunkCount`
    // from the ledger's length.
    const seeded = await seedUpload(user, { chunks: 2 });
    const first = fullPart();
    // A DIFFERENT sealed segment of the same length, so the engine's etag — which
    // is a digest of the bytes — genuinely moves. Re-sending byte-identical bytes
    // would leave the etag unchanged and the assertion below could not fail.
    const second = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 7);

    expect((await putPart(user, seeded.id, 1, { body: first })).status).toBe(200);
    const afterFirst = await stateOf(seeded);

    const res = await putPart(user, seeded.id, 1, { body: second });
    expect(res.status, JSON.stringify(res.body)).toBe(200);

    const after = await stateOf(seeded);
    expect(after.parts).toHaveLength(1);
    expect(after.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(res.body.data.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    // The engine holds one part too, not two, and the ledger's etag moved with it.
    expect(after.engineParts).toBe(1);
    expect(after.parts[0]!.etag).not.toBe(afterFirst.parts[0]!.etag);
  });

  it('accumulates receivedBytes across distinct parts', async () => {
    const seeded = await seedUpload(user, { chunks: 3 });

    await putPart(user, seeded.id, 1, { body: fullPart() });
    const res = await putPart(user, seeded.id, 2, { body: fullPart() });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const after = await stateOf(seeded);
    expect(after.parts.map((part) => part.partNumber).sort()).toEqual([1, 2]);
    expect(after.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES * 2);
  });
});

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

describe('refusing a part', () => {
  it('refuses a SHORT MIDDLE PART, which the storage engine itself accepts', async () => {
    // Measured: Garage stores a non-final part below the chunk size without
    // complaint, and S3's contract only ever exempts the LAST part. Nothing under
    // this handler will refuse it, and the damage is silent and total — segment `i`
    // stops starting at `i * DOCUMENT_CIPHERTEXT_CHUNK_BYTES`, so every ranged read
    // after the short part returns bytes that authenticate as nothing at all and
    // the document can never be opened again. This handler is the only thing
    // standing between that and a permanently unreadable file.
    const seeded = await seedUpload(user, { chunks: 3 });
    const short = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 1);

    const res = await putPart(user, seeded.id, 1, { body: short });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/must be exactly/i);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a non-final part that is one byte OVER the chunk size', async () => {
    // The other side of the same rule, and inside the parser's slack so that it is
    // this handler answering rather than `raw-body`. Uniform parts are what let
    // segment `i`'s offset be computed instead of looked up.
    const seeded = await seedUpload(user, { chunks: 3 });
    const long = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 1);

    const res = await putPart(user, seeded.id, 1, { body: long });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/must be exactly/i);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses an empty final part, which cannot even hold its own tag', async () => {
    const seeded = await seedUpload(user, { chunks: 2 });

    const res = await putPart(user, seeded.id, 2, {
      body: Buffer.alloc(DOCUMENT_TAG_BYTES - 1, 3),
    });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/last part/i);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a request that declares no Content-Length, with 411', async () => {
    // Driven through `node:http` rather than supertest, because superagent always
    // sets `Content-Length` from the buffer it is given and adding
    // `Transfer-Encoding` beside it makes Node reject the request itself as a
    // smuggling shape. Omitting the length entirely is the only way a real client
    // gets here, and Node then chunks the body automatically.
    //
    // It matters because a chunked part has NO declared length, and the length is
    // what the received byte count is checked against before anything is stored.
    const seeded = await seedUpload(user, { chunks: 1 });
    const body = Buffer.alloc(DOCUMENT_TAG_BYTES, 4);
    const pair = await getCsrf(request.agent(app));

    const res = await chunkedPut(partPath(seeded.id, 1), body, {
      Authorization: authHeader(user.accessToken),
      Cookie: pair.cookie,
      'x-csrf-token': pair.token,
      [PART_DIGEST_HEADER]: digestOf(body),
      'Content-Type': 'application/octet-stream',
    });

    expect(res.status, res.body).toBe(411);
    expect(JSON.parse(res.body).statusText).toBe('Length Required');
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a body past the parser ceiling with 413', async () => {
    const seeded = await seedUpload(user, { chunks: 1 });

    const res = await putPart(user, seeded.id, 1, { body: pattern(PART_BODY_LIMIT_BYTES + 1) });

    expect(res.status, JSON.stringify(res.body)).toBe(413);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a body that is not octet-stream with 415', async () => {
    const seeded = await seedUpload(user, { chunks: 1 });

    const res = await putPart(user, seeded.id, 1, { contentType: 'application/json' });

    expect(res.status, JSON.stringify(res.body)).toBe(415);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a COMPRESSED body with 415 rather than inflating it', async () => {
    // `inflate: false`. A sealed segment is ciphertext and does not compress, so a
    // client gains nothing; what the server would lose is the correspondence
    // between `Content-Length` and the number of bytes it ends up holding, which is
    // what the ledger and the quota are computed from.
    const seeded = await seedUpload(user, { chunks: 1 });

    const res = await putPart(user, seeded.id, 1, {
      headers: { 'Content-Encoding': 'gzip' },
    });

    expect(res.status, JSON.stringify(res.body)).toBe(415);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it.each([
    ['no digest header at all', null],
    ['a digest that is not hexadecimal', 'z'.repeat(64)],
    ['a digest of the wrong length', 'a'.repeat(63)],
    ['an UPPERCASE digest', 'A'.repeat(64)],
  ])('refuses %s', async (_label, digest) => {
    const seeded = await seedUpload(user, { chunks: 1 });

    const res = await putPart(user, seeded.id, 1, { digest });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toContain(PART_DIGEST_HEADER);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a part whose bytes do not match the digest the client declared', async () => {
    const seeded = await seedUpload(user, { chunks: 1 });
    const body = pattern(2048 + DOCUMENT_TAG_BYTES);

    const res = await putPart(user, seeded.id, 1, {
      body,
      digest: digestOf(Buffer.concat([body, Buffer.of(0)])),
    });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/does not match its declared digest/i);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it.each([
    // `0` matches the decimal pattern and is refused by the RANGE instead: part
    // numbers are one-based because S3's are, while segment indices are zero-based,
    // and confusing the two is the likeliest way to address the wrong part.
    ['0, which confuses a segment index with a part number', '0', /to be >=1/],
    ['a decimal with a leading zero', '01', /decimal integer/i],
    ['hexadecimal', '0x2', /decimal integer/i],
    ['exponential notation', '1e1', /decimal integer/i],
    ['not a number at all', 'two', /decimal integer/i],
  ])('refuses a part number given as %s', async (_label, partNumber, refusal) => {
    // `documentPartParamsSchema` uses a strict decimal pattern rather than
    // `z.coerce.number()`, which would read `0x10` as 16, `1e3` as 1000 and an
    // empty string as 0 — four ways to address a part other than the one the URL
    // appears to name.
    //
    // The REFUSAL is asserted, not just the status, and that is what makes each of
    // these able to fail. Under a coercing schema most of these values become a
    // part number the handler then rejects for a different reason — the wrong size
    // for a non-final part, or a number past the declared count — so a bare
    // `toBe(400)` would stay green while the URL was being read as a number nobody
    // wrote. It also lets the body stay small: the refusal is decided from the URL
    // before the 411 guard, the semaphore and the parser run (deliberately, so a
    // bad part number costs no memory), so the server answers while the client is
    // still writing, and a full chunk in flight is destroyed with the socket and
    // surfaces as EPIPE in the client rather than as a fact about the handler.
    const seeded = await seedUpload(user, { chunks: 2 });

    const res = await putPart(user, seeded.id, partNumber);

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(refusal);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a part number past the declared chunk count', async () => {
    const seeded = await seedUpload(user, { chunks: 2 });

    const res = await putPart(user, seeded.id, 3, { body: fullPart() });

    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(String(res.body.message)).toMatch(/outside it/i);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it("refuses another account's upload id and leaves that transfer untouched", async () => {
    const intruder = await createTestUser({ email: 'document-parts-intruder@example.com' });
    const seeded = await seedUpload(user, { chunks: 1 });

    const res = await putPart(intruder, seeded.id, 1, { body: pattern(1024) });

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a part against an EXPIRED staging row, indistinguishably from a missing one', async () => {
    // The TTL index removes the row within the minute rather than at the instant it
    // expires, so a part can genuinely arrive against one. A transfer past its
    // deadline can never be completed, so accepting bytes for it would write an
    // object nobody can ever name — and the two answers have to be identical, or
    // the difference is a clock oracle.
    const seeded = await seedUpload(user, {
      chunks: 1,
      expiresAt: new Date(Date.now() - 1000),
    });
    const absent = new mongoose.Types.ObjectId().toHexString();

    const expired = await putPart(user, seeded.id, 1, { body: pattern(1024) });
    const missing = await putPart(user, absent, 1, { body: pattern(1024) });

    expect(expired.status).toBe(404);
    expect(expired.status).toBe(missing.status);
    expect(expired.body.message).toEqual(missing.body.message);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  it('refuses a multi-segment row that names no engine-side upload, instead of overwriting the object', async () => {
    // Unreachable through `initUpload`, which opens the multipart upload before it
    // writes the row and aborts it if the write fails — so this is a corrupt or
    // hand-written row. It is worth refusing loudly because the alternative is
    // worse than an error: falling through to `putObject` would store this one part
    // as the WHOLE object and silently destroy every other part of the transfer.
    const seeded = await seedUpload(user, { chunks: 3, multipart: false });

    const res = await putPart(user, seeded.id, 1, { body: fullPart() });

    expect(res.status, JSON.stringify(res.body)).toBe(500);
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });

  /**
   * A single-segment part whose staging row disappears while `putObject` runs:
   * `before` runs inside the storage call, AFTER the row lookup and BEFORE the
   * object is written, which is exactly where a cancel's claim-then-delete lands.
   */
  async function partWhoseRowVanishes(
    before: (seeded: Seeded) => Promise<void>,
  ): Promise<{ seeded: Seeded; res: request.Response }> {
    const seeded = await seedUpload(user, { chunks: 1 });
    const base = storageRef.current!;
    storageRef.current = {
      ...base,
      putObject: async (key: string, body: Uint8Array) => {
        await DocumentUpload.deleteOne({ _id: seeded.id });
        await before(seeded);
        await base.putObject(key, body);
      },
    };
    const res = await putPart(user, seeded.id, 1, { body: pattern(1024) });
    storageRef.current = base;
    return { seeded, res };
  }

  it('does not resurrect a staging row that disappeared while the part was being stored', async () => {
    // A real race: the row's TTL fires, or the caller cancels from another tab,
    // between the lookup and the ledger write. The update must not upsert — a
    // recreated row would hold quota nothing can release and would be listed as a
    // transfer that can never complete.
    const { seeded, res } = await partWhoseRowVanishes(async () => undefined);

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(res.body.message).toBe('Upload not found');
    expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
    expect(await DocumentUpload.countDocuments({ userId: user.id })).toBe(0);
  });

  it('deletes the object a single-segment part stored after its row was gone, when no document owns it', async () => {
    // A cancel claims the row and deletes the object while this part is still
    // inside `putObject`; the part then writes the object again. Left alone, those
    // bytes sat in the bucket for the orphan sweep's 25 hours, charged to nobody.
    const { seeded, res } = await partWhoseRowVanishes(async () => undefined);

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(storageRef.current!.storedKeys()).not.toContain(seeded.objectKey);
    expect(storageRef.current!.storedKeys()).toEqual([]);
    // The completion lock it took to decide is handed back.
    expect(
      await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
    ).toBe(0);
  });

  it('still answers 404, and releases the lock, when deleting that object fails', async () => {
    // Best-effort, like every delete that follows a vanished row: nothing is left
    // to retry against, so the failure is logged, the object is left for the
    // collector's orphan sweep, and the lock the decision was made under is
    // handed back rather than held until its TTL.
    const deletes: string[] = [];
    const { seeded, res } = await partWhoseRowVanishes(async () => {
      storageRef.current!.deleteObject = async (key: string) => {
        deletes.push(key);
        throw new Error('storage engine unavailable');
      };
    });

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(res.body.message).toBe('Upload not found');
    expect(deletes).toEqual([seeded.objectKey]);
    expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    expect(
      await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
    ).toBe(0);
  });

  it('keeps that object when a document already names it, in any state', async () => {
    // A completion claims the row the same way and commits a `documents` row naming
    // this very key. A TRASHED, purge-pending document still owns its object: the
    // purge deletes it, and deleting it here would leave a row that never opens.
    const { seeded, res } = await partWhoseRowVanishes(async (s) => {
      await Document.collection.insertOne({
        _id: new mongoose.Types.ObjectId(s.id),
        userId: new mongoose.Types.ObjectId(user.id),
        objectKey: s.objectKey,
        deletedAt: new Date(),
        purgePending: true,
      });
    });

    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    expect(await Document.countDocuments({ objectKey: seeded.objectKey })).toBe(1);
  });

  it('keeps that object while a completion of the upload holds its lock', async () => {
    // A completion between its claim and its insert holds this lock, and no
    // document exists yet. Deleting then would destroy the bytes it is committing,
    // so the part leaves them; if that completion fails, it deletes them itself.
    let lockId: string | null = null;
    const { seeded, res } = await partWhoseRowVanishes(async (s) => {
      lockId = await acquireJobLock(documentCompleteLockName(user.id, s.id), 60_000);
    });

    expect(lockId).not.toBeNull();
    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    // The part did not take over, or release, a lock it never held.
    expect(
      await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
    ).toBe(1);
    await releaseJobLock(documentCompleteLockName(user.id, seeded.id), lockId!);
  });

  it('refuses a body whose length disagrees with its declared Content-Length', async () => {
    // Node's own HTTP parser makes this unreachable over the wire — measured, both
    // ways: a body shorter than `Content-Length` and a body longer than it are each
    // answered with a bare 400 before Express is reached — so the handler is
    // invoked directly, which is the only level at which its own third check can
    // fire. It is worth having: the ledger entry, `receivedBytes` and the quota are
    // all computed from a length, so a parser, a proxy or a transfer coding that
    // ever broke that correspondence would corrupt every one of them silently.
    const seeded = await seedUpload(user, { chunks: 1 });
    const body = pattern(1024);
    const req = {
      user: { _id: user.id },
      params: { id: seeded.id, partNumber: 1 },
      // One byte more than the body actually holds.
      headers: {
        'content-length': String(body.length + 1),
        [PART_DIGEST_HEADER]: digestOf(body),
      },
      body,
    } as unknown as Parameters<typeof uploadPart>[0];
    const res = { json: vi.fn() } as unknown as Parameters<typeof uploadPart>[1];
    const next = vi.fn();

    await uploadPart(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]![0]).toMatchObject({ statusCode: 400 });
    expect(String((next.mock.calls[0]![0] as Error).message)).toMatch(/delivered/i);
    expect(res.json).not.toHaveBeenCalled();
    expect(await stateOf(seeded)).toEqual(UNTOUCHED);
  });
});

// ---------------------------------------------------------------------------
// The concurrency budget, and where it is mounted
// ---------------------------------------------------------------------------

describe('the in-flight budget', () => {
  it('holds a slot ACROSS the storage call, and takes it BEFORE the body is parsed', async () => {
    // The discriminating assertion in this file, and the one that goes red if the
    // semaphore is moved into the handler or mounted after `express.raw`.
    //
    // Every slot is occupied by a part whose storage call is deliberately blocked.
    // Another part then arrives with a body past the parser's ceiling. If the
    // parser ran first it would answer 413 from the `Content-Length` header alone
    // and the request would never reach the semaphore, so `waiting` would stay at
    // 0 and the wait below would time out. Reaching 1 is the proof that the slot is
    // taken first — and the 413 arriving only AFTER a slot frees is the proof that
    // it is held across the storage call rather than released at `next()`.
    //
    // ONE IDENTITY PER REQUEST, which is not decoration either: the process budget
    // is shared out per account (`MAX_IN_FLIGHT_PART_UPLOADS_PER_USER`), so one
    // account filling every slot is a state the server now refuses to enter. The
    // property under test here is the PROCESS-wide one — a slot taken before the
    // parser and held across storage — and filling the budget from distinct
    // accounts is what reaches that state without tripping the per-account share.
    // `part-upload-fairness.test.ts` owns the share itself.
    const base = storageRef.current!;
    const blocked: (() => void)[] = [];
    storageRef.current = {
      ...base,
      putObject: async (key: string, body: Uint8Array) => {
        await new Promise<void>((resolve) => blocked.push(resolve));
        await base.putObject(key, body);
      },
    };

    const occupying: Promise<request.Response>[] = [];
    let queued: Promise<request.Response> | undefined;
    // Everything that could throw runs inside the `try`, and the `finally` always
    // unblocks the stores and drains the requests. Without it a FAILING assertion
    // leaves four supertest servers waiting on a promise nothing will ever resolve,
    // and the whole suite hangs instead of reporting which assertion failed — a
    // regression that presents as a timeout is a regression nobody can read.
    try {
      for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS; i += 1) {
        const holder = await createTestUser({
          email: `document-parts-slot-${String(i)}@example.com`,
        });
        const seeded = await seedUpload(holder, { chunks: 1 });
        occupying.push(putPart(holder, seeded.id, 1, { body: pattern(512 + i) }));
      }
      await vi.waitFor(
        () => {
          expect(blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS);
        },
        { timeout: 10_000, interval: 10 },
      );
      expect(partUploadSemaphore.available).toBe(0);

      const oversize = await seedUpload(user, { chunks: 1 });
      queued = putPart(user, oversize.id, 1, { body: pattern(PART_BODY_LIMIT_BYTES + 1) });
      await vi.waitFor(
        () => {
          expect(partUploadSemaphore.waiting).toBe(1);
        },
        { timeout: 10_000, interval: 10 },
      );

      // The queued request has NOT been answered while every slot is held: its body
      // has not been looked at yet, so the 413 it is destined for cannot have been
      // decided.
      let settledEarly = false;
      void queued.then(
        () => (settledEarly = true),
        () => (settledEarly = true),
      );
      await new Promise((resolve) => setImmediate(resolve));
      expect(settledEarly, 'the oversize part was answered before it held a slot').toBe(false);
    } finally {
      for (const resolve of blocked) resolve();
      const settled = await Promise.allSettled(occupying);
      for (const result of settled) {
        expect(result.status).toBe('fulfilled');
        expect((result as PromiseFulfilledResult<request.Response>).value.status).toBe(200);
      }
      if (queued !== undefined) {
        // Only now, with a slot free, is the body parsed — and refused.
        expect((await queued).status).toBe(413);
      }
    }

    // Nothing leaked: the whole budget is back.
    await vi.waitFor(
      () => {
        expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
      },
      { timeout: 10_000, interval: 10 },
    );
  });
});
