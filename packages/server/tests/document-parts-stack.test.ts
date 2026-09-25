/**
 * An 8 MiB sealed segment arrives intact, through the WHOLE application.
 *
 * ## Why this is its own file, and why it drives `app` rather than the router
 *
 * The part parser is the only body parser in this codebase that produces a
 * `Buffer`, and `app.ts` mounts four things ahead of every router that have opinions
 * about `req.body`:
 *
 *   1. `express.json({ limit: '2mb' })`, whose limit would refuse this body if it
 *      ever claimed the request;
 *   2. `express.urlencoded`;
 *   3. the **MongoDB injection sanitizer**, which rebuilds any object body key by
 *      key to strip `$`-prefixed operators — and a `Buffer` is an object that is not
 *      an Array, so a raw parser mounted app-level would hand it a Buffer and get
 *      back `{0: 137, 1: 80, …}`;
 *   4. `hppx` with `mergeStrategy: 'keepLast'`, and the request logger, which
 *      reads and masks body keys.
 *
 * Exercising the router in isolation would prove nothing about any of them. Every
 * assertion here therefore goes through `app`, which is what makes this file a
 * regression test for the route-level mounting decision rather than a duplicate of
 * `document-parts.test.ts`.
 *
 * ## What "intact" is asserted to mean
 *
 * Not `res.status === 200`. The bytes are captured at the storage boundary — the
 * first place downstream of the handler — and compared by TYPE, by LENGTH and by
 * DIGEST against what was sent. Each of the three catches something the others do
 * not: a rewritten Buffer is still 8 MiB of *something* and would pass a length
 * check, and a truncated one would pass a type check.
 */
import { createHash } from 'node:crypto';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { DOCUMENT_CIPHERTEXT_CHUNK_BYTES, DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';

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
import { PART_DIGEST_HEADER } from '../src/controllers/documentController.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

/**
 * A full sealed segment whose every byte differs from its neighbours.
 *
 * The pattern is the assertion's teeth. A body of zeros is invariant under
 * reordering, under truncation followed by re-padding, and under a rewrite that
 * happens to preserve length — so it would sail through the digest comparison this
 * file exists to make.
 */
function sealedSegment(): Buffer {
  const buffer = Buffer.allocUnsafe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
  for (let i = 0; i < buffer.length; i += 1) buffer[i] = (i * 131 + (i >>> 11)) & 0xff;
  return buffer;
}

const digestOf = (body: Uint8Array): string => createHash('sha256').update(body).digest('hex');

let user: TestUser;

beforeEach(async () => {
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'document-parts-stack@example.com' });
});

describe('an 8 MiB octet-stream body through the whole app', () => {
  it('reaches the storage boundary as an intact Buffer of exactly one ciphertext chunk', async () => {
    const uploadId = new mongoose.Types.ObjectId();
    const objectKey = buildObjectKey(user.id, uploadId.toHexString());
    const base = storageRef.current!;
    const s3UploadId = await base.createMultipartUpload(objectKey);

    // Capture what the handler actually forwards. This is the boundary immediately
    // downstream of the handler, so it is the closest observable point to "what the
    // handler received" that does not involve reaching into the handler.
    const seen: { body: unknown }[] = [];
    storageRef.current = {
      ...base,
      uploadPart: async (key: string, id: string, partNumber: number, body: Uint8Array) => {
        seen.push({ body });
        return base.uploadPart(key, id, partNumber, body);
      },
    };

    await DocumentUpload.create({
      _id: uploadId,
      userId: user.id,
      objectKey,
      s3UploadId,
      encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
      dekIv: 'ZGVrLWl2LWJhc2U2NA==',
      dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
      streamSalt: Buffer.alloc(32, 7).toString('base64'),
      noncePrefix: Buffer.alloc(7, 3).toString('base64'),
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      declaredChunkCount: 2,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      vaultKeyVersion: 0,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });

    const body = sealedSegment();
    const expectedDigest = digestOf(body);

    const agent = request.agent(app);
    const pair = await getCsrf(agent);
    const pending = agent
      .put(`/api/v1/documents/uploads/${uploadId.toHexString()}/parts/1`)
      .set('Authorization', authHeader(user.accessToken));
    const res = await pending
      .set('Cookie', pair.cookie)
      .set('x-csrf-token', pair.token)
      .set(PART_DIGEST_HEADER, expectedDigest)
      .type('application/octet-stream')
      .send(body);

    // The 200 is itself evidence: the handler recomputes SHA-256 over whatever it
    // was handed and compares it with the header, so a body the sanitizer had
    // rewritten could not have got this far.
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toEqual({
      partNumber: 1,
      bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      receivedBytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
    });

    // …and the bytes at the boundary are a Buffer, of exactly one ciphertext
    // chunk, with the digest they were sent with. All three, because each one
    // survives a failure the others miss.
    expect(seen).toHaveLength(1);
    const forwarded = seen[0]!.body;
    expect(Buffer.isBuffer(forwarded)).toBe(true);
    expect((forwarded as Buffer).length).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(digestOf(forwarded as Buffer)).toBe(expectedDigest);

    // The specific corruption this file guards against, named so a failure reads
    // as itself: the sanitizer would have produced a plain object of numeric keys,
    // which is neither a Buffer nor a Uint8Array.
    expect(Object.getPrototypeOf(forwarded)).not.toBe(Object.prototype);

    const engineParts = await base.listParts(objectKey, s3UploadId);
    expect(engineParts).toEqual([
      expect.objectContaining({ partNumber: 1, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES }),
    ]);
  });

  it('still applies the global 2 MB JSON limit to the same route when the body is JSON', async () => {
    // The other half of the mounting decision. The route-level raw parser claims
    // only `application/octet-stream`; everything else on this path is still the
    // application's own JSON parser at its 2 MB limit, so raising this one route's
    // ceiling to 8 MiB did not open a hole for an 8 MiB JSON body anywhere.
    //
    // Aimed at a REAL staging row rather than an id that names nothing, so the
    // negative is worth stating: the transfer must be untouched afterwards. A
    // refusal that had already reached the handler would show up here as a ledger
    // entry.
    const uploadId = new mongoose.Types.ObjectId();
    await DocumentUpload.create({
      _id: uploadId,
      userId: user.id,
      objectKey: buildObjectKey(user.id, uploadId.toHexString()),
      encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
      dekIv: 'ZGVrLWl2LWJhc2U2NA==',
      dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
      streamSalt: Buffer.alloc(32, 7).toString('base64'),
      noncePrefix: Buffer.alloc(7, 3).toString('base64'),
      declaredPlaintextBytes: 1024,
      declaredChunkCount: 1,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      vaultKeyVersion: 0,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });

    const agent = request.agent(app);
    const pair = await getCsrf(agent);
    const pending = agent
      .put(`/api/v1/documents/uploads/${uploadId.toHexString()}/parts/1`)
      .set('Authorization', authHeader(user.accessToken));
    const res = await pending
      .set('Cookie', pair.cookie)
      .set('x-csrf-token', pair.token)
      .type('application/json')
      .send(JSON.stringify({ padding: 'x'.repeat(3 * 1024 * 1024) }));

    expect(res.status, JSON.stringify(res.body)).toBe(413);

    const row = await DocumentUpload.findById(uploadId).lean();
    expect(row!.parts).toEqual([]);
    expect(row!.receivedBytes).toBe(0);
    expect(storageRef.current!.storedKeys()).toEqual([]);
  });
});
