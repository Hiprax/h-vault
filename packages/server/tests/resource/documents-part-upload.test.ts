/**
 * A document at exactly the configured maximum size, delivered part by part
 * through the real route, inside a time and memory budget.
 *
 * `PUT /documents/uploads/:id/parts/:n` is the only route in this application that
 * a client is expected to call dozens of times for one user action, and the only
 * one whose body is a multi-megabyte `Buffer`. Everything in front of it exists to
 * bound what that costs: a 411 before the socket is read, one of
 * `MAX_IN_FLIGHT_PART_UPLOADS` concurrency slots taken AHEAD of the parser, a
 * parser ceiling of one sealed segment plus a kilobyte, and a handler that hashes
 * the buffer once and forwards it. None of that was ever measured AT VOLUME: every
 * other suite sends one part, or a handful of tiny ones, so a change that made the
 * handler retain each part — an accumulating ledger read into memory, a second copy
 * taken for a digest, a stream never drained — would leave all of them green.
 *
 * ## Why the part count is derived and not chosen
 *
 * The transfer is the LARGEST one this deployment's configuration permits:
 * `MAX_DOCUMENT_SIZE_MB` plaintext bytes, which the framing rule turns into
 * `ceil(bytes / DOCUMENT_PLAINTEXT_CHUNK_BYTES)` parts, every one of them but the
 * last exactly `DOCUMENT_CIPHERTEXT_CHUNK_BYTES`. At the default cap that is
 * thirteen parts, twelve of them at the maximum part size. A hard-coded "send ten
 * parts" would stop describing the worst case the moment an operator raised the
 * cap; this number moves with the configuration, which is what makes the budget
 * below a statement about the deployment rather than about a literal.
 *
 * ## The storage double is a SINK here, deliberately
 *
 * `uploadPart` is decorated to hash the bytes and drop them. The subject of this
 * measurement is the SERVER's transient memory — what one 8 MiB part costs between
 * the socket and the storage call — and a double that retained every part would add
 * a hundred megabytes of fake bucket to `rssGrowthMb` and make the budget a
 * statement about the fixture. What is kept is a receipt per part (its number, its
 * length and its digest), which is what the assertions are made against, so nothing
 * about the transfer goes unchecked; only the bytes are dropped, and only after
 * they have been measured.
 *
 * ## One measured scenario per file
 *
 * The rule from `measure.ts`: V8 does not hand freed pages back promptly, so a
 * second heavy case in this worker would measure its growth from a floor this one
 * raised and could not fail. The suite's global `afterEach` truncates every
 * collection as well, so the staging row seeded here survives exactly one test.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { createHash } from 'node:crypto';
import request from 'supertest';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
} from '@hvault/shared';

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

import app from '../../src/app.js';
import { config } from '../../src/config/index.js';
import { Document } from '../../src/models/Document.js';
import { DocumentUpload } from '../../src/models/DocumentUpload.js';
import { createInMemoryStorage } from '../helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from '../helpers.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

const BYTES_PER_MB = 1024 * 1024;

/** The largest document this configuration accepts, in plaintext bytes. */
const MAX_PLAINTEXT_BYTES = config.MAX_DOCUMENT_SIZE_MB * BYTES_PER_MB;

/** The framing that size implies. `ceil`, exactly as the shared refine computes it. */
const CHUNK_COUNT = Math.max(1, Math.ceil(MAX_PLAINTEXT_BYTES / DOCUMENT_PLAINTEXT_CHUNK_BYTES));

/** The last part is the only one allowed to be short, and it carries the remainder. */
const FINAL_PART_BYTES =
  MAX_PLAINTEXT_BYTES - (CHUNK_COUNT - 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES + DOCUMENT_TAG_BYTES;

/** Every byte that crosses the route, which is what the duration budget is per. */
const TOTAL_CIPHERTEXT_BYTES =
  (CHUNK_COUNT - 1) * DOCUMENT_CIPHERTEXT_CHUNK_BYTES + FINAL_PART_BYTES;

const budget = RESOURCE_BUDGETS.documentsPartUpload;

/**
 * A part body whose bytes vary along its length.
 *
 * Never a run of one value: a uniform buffer is invariant under truncation
 * followed by re-padding and under reordering, so the per-part digest receipts
 * below would agree on bytes the route had mangled.
 */
function pattern(bytes: number, seed: number): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 131 + (i >>> 11) + seed) & 0xff;
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

/** One receipt per part, recorded by the sink instead of the bytes. */
interface PartReceipt {
  partNumber: number;
  bytes: number;
  sha256: string;
}

describe('a document at the configured maximum size, part by part', () => {
  let user: TestUser;
  let uploadId: string;
  const receipts: PartReceipt[] = [];

  /**
   * The two bodies, built ONCE and re-sent.
   *
   * Twelve freshly allocated 8 MiB buffers would put ninety-six megabytes of
   * FIXTURE inside the window `measure()` samples, and the budget would then be
   * mostly a statement about this file. Re-sending one buffer is also what a
   * client retrying a part does, and the route is required to be indifferent to
   * it: the digest is recomputed server-side per request either way.
   */
  const fullPart = pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 1);
  const finalPart = pattern(FINAL_PART_BYTES, 2);
  const fullDigest = digestOf(fullPart);
  const finalDigest = digestOf(finalPart);

  beforeAll(async () => {
    const base = createInMemoryStorage();
    // The sink. Everything else on the double behaves normally, so the multipart
    // handle `initUpload` opens is real and the route's own error paths are not
    // altered — only the retention of the part bodies is.
    storageRef.current = {
      ...base,
      uploadPart: async (_key: string, _id: string, partNumber: number, body: Uint8Array) => {
        const buffer = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
        receipts.push({ partNumber, bytes: body.byteLength, sha256: digestOf(buffer) });
        return { partNumber, etag: `"part-${String(partNumber)}"`, bytes: body.byteLength };
      },
    };

    user = await createTestUser({ email: 'documents-part-upload@example.com' });

    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const pending = agent
      .post('/api/v1/documents/uploads')
      .set('Authorization', authHeader(user.accessToken));
    const init = await pending
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({
        encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
        dekIv: 'ZGVrLWl2LWJhc2U2NA==',
        dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
        streamSalt: Buffer.alloc(32, 7).toString('base64'),
        noncePrefix: Buffer.alloc(7, 3).toString('base64'),
        declaredPlaintextBytes: MAX_PLAINTEXT_BYTES,
        declaredChunkCount: CHUNK_COUNT,
      });
    // Asserted here rather than left to fail obscurely inside the measurement:
    // an init refused by the size cap or the framing refine would otherwise show
    // up as thirteen 404s and a duration of nothing at all.
    expect(init.status, JSON.stringify(init.body)).toBe(201);
    uploadId = (init.body as { data: { uploadId: string } }).data.uploadId;
  }, 300_000);

  it('delivers every part of the largest permitted document inside the time and memory budget', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const run = await measure(async () => {
      const statuses: number[] = [];
      // One at a time, which is what the client does: `MAX_IN_FLIGHT_PART_UPLOADS`
      // is the server's ceiling, not a target, and a parallel fixture would
      // measure the semaphore rather than the per-part cost.
      for (let partNumber = 1; partNumber <= CHUNK_COUNT; partNumber += 1) {
        const isFinal = partNumber === CHUNK_COUNT;
        const body = isFinal ? finalPart : fullPart;
        const response = await agent
          .put(`/api/v1/documents/uploads/${uploadId}/parts/${String(partNumber)}`)
          .set('Authorization', authHeader(user.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token)
          .set('x-hv-part-sha256', isFinal ? finalDigest : fullDigest)
          // `.type()`, not a hand-set `Content-Length`: superagent computes the
          // length from the buffer it is handed, and a second copy of that number
          // is a second thing that can disagree with the body.
          .type('application/octet-stream')
          .send(body);
        statuses.push(response.status);
      }
      return statuses;
    });

    const row = await DocumentUpload.findById(uploadId).lean();
    const ledger = (row?.parts ?? [])
      .map((part) => ({ partNumber: part.partNumber, bytes: part.bytes }))
      .sort((left, right) => left.partNumber - right.partNumber);
    const documents = await Document.countDocuments({});

    recordScenarioCase('documents-part-upload', 'delivers-every-part', {
      invariant:
        'a document at the configured maximum size is delivered part by part inside the time and memory budget, with every part recorded exactly once and no document row created',
      maxDocumentSizeMb: config.MAX_DOCUMENT_SIZE_MB,
      chunkCount: CHUNK_COUNT,
      fullPartBytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      finalPartBytes: FINAL_PART_BYTES,
      totalCiphertextBytes: TOTAL_CIPHERTEXT_BYTES,
      partsAccepted: run.result.filter((status) => status === 200).length,
      receivedBytes: row?.receivedBytes ?? null,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    // Every part was accepted, and the ledger is the transfer the client sent:
    // one entry per part, in order, at the sizes the framing requires.
    expect(run.result).toEqual(Array.from({ length: CHUNK_COUNT }, () => 200));
    expect(ledger).toEqual(
      Array.from({ length: CHUNK_COUNT }, (_unused, index) => ({
        partNumber: index + 1,
        bytes: index + 1 === CHUNK_COUNT ? FINAL_PART_BYTES : DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
      })),
    );
    // `receivedBytes` is DERIVED from that ledger by the handler's pipeline update,
    // so a drift between the two is the arithmetic the quota is charged from going
    // wrong at volume.
    expect(row?.receivedBytes).toBe(TOTAL_CIPHERTEXT_BYTES);

    // The bytes that reached the storage boundary are the bytes the client sealed,
    // for every one of the thirteen — not just the first, which is the only one any
    // other suite sends.
    expect(receipts).toHaveLength(CHUNK_COUNT);
    // The part NUMBERS the handler forwarded, as a set. Load-bearing rather than
    // pedantic, because twelve of these requests carry the IDENTICAL buffer: a
    // handler that passed the wrong number to `uploadPart` for two full parts
    // mis-assembles the object in the bucket, and every other assertion here would
    // stay green — the lengths and digests match by construction, and the ledger
    // below is written from the route parameter rather than from the storage call.
    expect(
      receipts.map((receipt) => receipt.partNumber).sort((left, right) => left - right),
    ).toEqual(Array.from({ length: CHUNK_COUNT }, (_unused, index) => index + 1));
    for (const receipt of receipts) {
      const isFinal = receipt.partNumber === CHUNK_COUNT;
      expect(receipt.bytes).toBe(isFinal ? FINAL_PART_BYTES : DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
      expect(receipt.sha256).toBe(isFinal ? finalDigest : fullDigest);
    }

    // THE NEGATIVE. Delivering every part commits nothing: a document exists only
    // after a completion, and a part route that created a row would charge the
    // account for a transfer that was never finished and hand the browser a
    // document whose metadata blob does not exist.
    expect(documents).toBe(0);

    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
