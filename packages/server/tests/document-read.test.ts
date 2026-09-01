/**
 * The document store's five read endpoints.
 *
 * ## What is actually at stake here
 *
 * Four of them hand back a row and one hands back ciphertext, and the interesting
 * assertions are all about the second kind. `GET /documents/:id/segments/:index`
 * is the only route in this application that answers with raw bytes, and the byte
 * window it answers with is computed on the SERVER from the row's own framing
 * columns. There is no `Range` header on it and there must never be one: the
 * stored object is a pure concatenation of sealed segments, so segment `i` is at a
 * fixed offset, and a client that could name its own window could ask for one that
 * straddles two segments. The cases below therefore read every position that can
 * be wrong — the first segment, a middle one, and the short final one — and
 * compare them with the exact slices of the object that was stored.
 *
 * The other half of that is `chunkPlaintextBytes`, which lives on the ROW rather
 * than being read from `DOCUMENT_PLAINTEXT_CHUNK_BYTES`. That column exists so
 * that changing the constant later cannot re-frame a document that already exists,
 * and the only way to prove the handler honours it is to read a document framed on
 * a DIFFERENT chunk size, which is what the three-segment fixture below is. A
 * handler that reached for the constant would compute every offset past the first
 * from a chunk 8 MiB wide and return nothing at all.
 *
 * ## The two seams
 *
 * MONGO IS REAL: ownership, the trash predicate, pagination and the usage sums are
 * all decided by a query. OBJECT STORAGE IS A DOUBLE
 * (`helpers/inMemoryStorage.ts`), because it is an external service in the same
 * class as SMTP, and the same contract suite runs that double and a real engine in
 * the conformance gate. Where a case needs to assert that storage was NOT touched,
 * it spies on the double rather than asking the double to remember, so the
 * negative is visible in the test that makes it.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Readable } from 'node:stream';
import request from 'supertest';
import mongoose from 'mongoose';
import { httpErrors } from '@hiprax/errors';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
  PAGINATION_DEFAULTS,
  documentResponseSchema,
  documentUsageResponseSchema,
} from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

/**
 * The module logger, mocked because ONE branch on this route file has no other
 * observable effect.
 *
 * When `pipeline` fails part-way through a segment it has already destroyed both
 * streams, so whether the handler logs or re-throws makes no difference a client
 * can see — the connection is reset either way. The log line IS the branch's
 * deliverable, and asserting it is the only way to pin "log it, do not re-throw"
 * against a change that would ask the error middleware to serialise JSON onto a
 * socket that is gone. Same shape `s3-provider.test.ts` uses.
 */
const logs = vi.hoisted(() => ({
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
  verbose: vi.fn(),
  http: vi.fn(),
  silly: vi.fn(),
}));

vi.mock('../src/utils/logger.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/logger.js')>();
  return { ...actual, createModuleLogger: () => logs };
});

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
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, seedFolder, type TestUser } from './helpers.js';

const BYTES_PER_MB = 1024 * 1024;

/**
 * The two plaintext framing fields, at their exact byte counts.
 *
 * Real base64 of real lengths rather than placeholder strings, because every case
 * below parses the response with `documentResponseSchema`, and that schema pins
 * both to `DOCUMENT_STREAM_SALT_BYTES` and `DOCUMENT_NONCE_PREFIX_BYTES` — a salt
 * one byte short is still valid base64 and would be refused.
 */
const FRAMING = {
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/** Opaque ciphertext columns. Nothing in this file decrypts anything. */
const SEALED = {
  encryptedDek: 'dek-ciphertext',
  dekIv: 'dek-iv',
  dekTag: 'dek-tag',
  encryptedMeta: 'meta-ciphertext',
  metaIv: 'meta-iv',
  metaTag: 'meta-tag',
};

/**
 * A stored object whose bytes vary along its length.
 *
 * Never `Buffer.alloc(n, k)`: a run of identical bytes is equal to itself at every
 * offset, so a handler that read segment 2 from segment 1's position would return
 * bytes that compare equal and the range arithmetic would go untested.
 */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

// ---------------------------------------------------------------------------
// The two fixtures, and why there are two
// ---------------------------------------------------------------------------

/**
 * A document framed on the SERVER's real chunk size, holding one segment.
 *
 * One segment on purpose: a two-segment document at the production framing would
 * need an 8 MiB buffer per segment for no extra assurance, because the offsets
 * that matter are exercised by {@link SMALL} below. What this fixture is for is
 * proving the default framing is handled at all — `segmentRange` computes a final
 * segment's end from `ciphertextBytes` rather than from the chunk size, and a
 * document whose only segment is far shorter than a chunk is exactly where an
 * implementation that used the chunk size would over-read.
 */
const DEFAULT_FRAMED = {
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  chunkCount: 1,
  ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
};

/**
 * A document framed on a 64-byte chunk, holding three segments: two full and one
 * short.
 *
 * `chunkPlaintextBytes` is a COLUMN, not the constant, and this fixture is the
 * proof of it. Its ciphertext is 80 + 80 + 26 = 186 bytes, so the three segment
 * ranges are `[0,79]`, `[80,159]` and `[160,185]` — every one of which a handler
 * reading `DOCUMENT_PLAINTEXT_CHUNK_BYTES` instead would get wrong. It also keeps
 * the fixture at 186 bytes rather than 16 MiB, which is why the test runs in
 * milliseconds.
 */
const SMALL = {
  chunkPlaintextBytes: 64,
  chunkCount: 3,
  // 2 full segments of (64 + 16), plus a final segment of 10 plaintext bytes + tag.
  ciphertextBytes: 2 * (64 + DOCUMENT_TAG_BYTES) + (10 + DOCUMENT_TAG_BYTES),
};

/** The inclusive ranges `SMALL`'s three segments occupy, written out independently. */
const SMALL_RANGES = [
  { start: 0, end: 79 },
  { start: 80, end: 159 },
  { start: 160, end: 185 },
] as const;

interface SeedOptions {
  chunkPlaintextBytes?: number;
  chunkCount?: number;
  ciphertextBytes?: number;
  favorite?: boolean;
  folderId?: string;
  deletedAt?: Date;
  /** Stamped after creation with Mongoose's timestamps suppressed. */
  updatedAt?: Date;
  /** Stored at the row's object key. Omit and the bucket stays empty for this row. */
  body?: Buffer;
}

interface Seeded {
  id: string;
  objectKey: string;
}

/**
 * A committed document row, and optionally its object.
 *
 * Seeded directly rather than driven through the upload endpoints: those have
 * their own suites, and routing every case here through init, thirteen parts and a
 * completion would make each failure ambiguous between four handlers. What is
 * reproduced faithfully is the STATE a completion leaves — a row whose three sizes
 * satisfy the identities `documentResponseSchema` re-checks, beside an object of
 * exactly `ciphertextBytes`.
 */
async function seedDocument(user: TestUser, options: SeedOptions = {}): Promise<Seeded> {
  const chunkPlaintextBytes = options.chunkPlaintextBytes ?? DEFAULT_FRAMED.chunkPlaintextBytes;
  const chunkCount = options.chunkCount ?? DEFAULT_FRAMED.chunkCount;
  const ciphertextBytes = options.ciphertextBytes ?? DEFAULT_FRAMED.ciphertextBytes;

  const documentId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(user.id, documentId.toHexString());

  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey,
    ...SEALED,
    ...FRAMING,
    chunkPlaintextBytes,
    chunkCount,
    ciphertextBytes,
    // The container identity, in the one direction the row records it: the object
    // is the file plus exactly one authentication tag per segment.
    plaintextBytes: ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount,
    ...(options.favorite === undefined ? {} : { favorite: options.favorite }),
    ...(options.folderId === undefined ? {} : { folderId: options.folderId }),
    ...(options.deletedAt === undefined ? {} : { deletedAt: options.deletedAt }),
  });

  if (options.updatedAt !== undefined) {
    // `timestamps: false`, or Mongoose stamps `updatedAt` with the wall clock and
    // the ordering cases below would be asserting against the time the fixture was
    // written rather than against the value they asked for.
    await Document.updateOne(
      { _id: documentId },
      { $set: { updatedAt: options.updatedAt } },
      { timestamps: false },
    );
  }

  if (options.body !== undefined) {
    await storageRef.current!.putObject(objectKey, options.body);
  }

  return { id: String(documentId), objectKey };
}

/** One authenticated GET. No CSRF pair: every route in this file is a safe method. */
const get = (user: TestUser, path: string): request.Test =>
  request(app).get(path).set('Authorization', authHeader(user.accessToken));

/** The ids a list response carries, in the order it carried them. */
const idsOf = (body: { data: { _id: string }[] }): string[] => body.data.map((row) => row._id);

describe('the document read endpoints', () => {
  let owner: TestUser;
  let intruder: TestUser;

  beforeEach(async () => {
    storageRef.current = createInMemoryStorage();
    owner = await createTestUser({ email: 'document-reader@example.com' });
    intruder = await createTestUser({ email: 'document-intruder@example.com' });
  });

  // -------------------------------------------------------------------------
  describe('GET /documents', () => {
    it('lists only the caller’s active documents and hides trashed and foreign rows', async () => {
      const first = await seedDocument(owner, { updatedAt: new Date('2026-01-01T00:00:00.000Z') });
      const second = await seedDocument(owner, { updatedAt: new Date('2026-02-01T00:00:00.000Z') });
      const trashed = await seedDocument(owner, { deletedAt: new Date() });
      const foreign = await seedDocument(intruder);

      const res = await get(owner, '/api/v1/documents');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.success).toBe(true);
      // Newest change first, which is the default sort.
      expect(idsOf(res.body)).toEqual([second.id, first.id]);
      // The negatives that matter: neither the trashed row nor the other
      // account's row may appear, in the list or in the count.
      expect(idsOf(res.body)).not.toContain(trashed.id);
      expect(idsOf(res.body)).not.toContain(foreign.id);
      expect(res.body.pagination).toEqual({ page: 1, limit: 50, total: 2, totalPages: 1 });
    });

    it('strips the owner, the storage key and the version from every row it returns', async () => {
      await seedDocument(owner);

      const res = await get(owner, '/api/v1/documents');

      expect(res.status).toBe(200);
      const [row] = res.body.data as Record<string, unknown>[];
      // `objectKey` is the one server-assigned address on the row; a client that
      // never learns it cannot form an expectation about it. `userId` is implied
      // by the session. `__v` must be absent so that this shape and the hydrated
      // one `POST .../complete` answers with are the SAME shape.
      expect(row).not.toHaveProperty('objectKey');
      expect(row).not.toHaveProperty('userId');
      expect(row).not.toHaveProperty('__v');
      // …and what is left is a row a client can parse before it decrypts.
      expect(documentResponseSchema.safeParse(row).success, JSON.stringify(row)).toBe(true);
    });

    it('paginates without repeating or dropping a row across page boundaries', async () => {
      const seeded: string[] = [];
      for (let index = 0; index < 5; index += 1) {
        const { id } = await seedDocument(owner, {
          updatedAt: new Date(Date.UTC(2026, 0, index + 1)),
        });
        seeded.push(id);
      }

      const pages = await Promise.all([
        get(owner, '/api/v1/documents?page=1&limit=2'),
        get(owner, '/api/v1/documents?page=2&limit=2'),
        get(owner, '/api/v1/documents?page=3&limit=2'),
      ]);

      expect(pages.map((page) => page.status)).toEqual([200, 200, 200]);
      expect(pages.map((page) => idsOf(page.body).length)).toEqual([2, 2, 1]);
      for (const page of pages) {
        expect(page.body.pagination).toMatchObject({ total: 5, totalPages: 3 });
      }
      // Newest first, so the concatenation is the seeding order reversed — and,
      // more importantly, it is every id exactly once.
      const walked = pages.flatMap((page) => idsOf(page.body));
      expect(walked).toEqual([...seeded].reverse());
      expect(new Set(walked).size).toBe(5);
    });

    it('breaks a tie on the sort key with the document id, in the direction asked for', async () => {
      // Every row shares an `updatedAt`, which is the state that makes `skip` /
      // `limit` pagination unsafe: without a total order the engine may answer two
      // requests in two orders, and a row that moves across a page boundary is one
      // the client sees twice or never. The observable consequence of the tiebreak
      // is that the ids themselves are ordered.
      const stamp = new Date('2026-03-04T05:06:07.000Z');
      for (let index = 0; index < 4; index += 1) {
        await seedDocument(owner, { updatedAt: stamp });
      }

      const descending = await get(owner, '/api/v1/documents');
      const ascending = await get(owner, '/api/v1/documents?sortOrder=asc');

      expect(descending.status).toBe(200);
      const descendingIds = idsOf(descending.body);
      expect(descendingIds).toHaveLength(4);
      expect(descendingIds).toEqual([...descendingIds].sort().reverse());

      expect(ascending.status).toBe(200);
      const ascendingIds = idsOf(ascending.body);
      expect(ascendingIds).toEqual([...ascendingIds].sort());
      // The two orders are genuinely opposite, so neither assertion above is
      // passing because the engine happened to return one fixed order.
      expect(ascendingIds).toEqual([...descendingIds].reverse());
    });

    it('filters by folder, and leaves a document filed elsewhere out', async () => {
      const folder = await seedFolder(owner.id);
      const other = await seedFolder(owner.id, { encryptedName: 'other-folder' });
      const filed = await seedDocument(owner, { folderId: String(folder._id) });
      const elsewhere = await seedDocument(owner, { folderId: String(other._id) });
      const unfiled = await seedDocument(owner);

      const res = await get(owner, `/api/v1/documents?folderId=${String(folder._id)}`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(idsOf(res.body)).toEqual([filed.id]);
      expect(idsOf(res.body)).not.toContain(elsewhere.id);
      expect(idsOf(res.body)).not.toContain(unfiled.id);
      expect(res.body.pagination.total).toBe(1);
    });

    it('reads favorite=false as false rather than as a truthy string', async () => {
      // `z.stringbool()`, never `z.coerce.boolean()`: the latter is `Boolean(input)`
      // and would make `?favorite=false` mean true, which is the defect this
      // assertion exists for.
      const starred = await seedDocument(owner, { favorite: true });
      const plain = await seedDocument(owner, { favorite: false });

      const yes = await get(owner, '/api/v1/documents?favorite=true');
      const no = await get(owner, '/api/v1/documents?favorite=false');

      expect(idsOf(yes.body)).toEqual([starred.id]);
      expect(idsOf(no.body)).toEqual([plain.id]);
      expect(idsOf(no.body)).not.toContain(starred.id);
    });

    it('refuses a page below one, a limit past the maximum and an unknown sort key', async () => {
      await seedDocument(owner);

      const cases = [
        '/api/v1/documents?page=0',
        `/api/v1/documents?limit=${String(PAGINATION_DEFAULTS.MAX_LIMIT + 1)}`,
        '/api/v1/documents?sortBy=name',
        '/api/v1/documents?folderId=not-an-object-id',
      ];

      for (const path of cases) {
        const res = await get(owner, path);
        expect(res.status, `${path} answered ${String(res.status)}`).toBe(400);
        expect(res.body.success).toBe(false);
        // A Zod refusal, never a 422 and never a silently-defaulted list.
        expect(res.body).not.toHaveProperty('data');
      }
    });
  });

  // -------------------------------------------------------------------------
  describe('GET /documents/trash', () => {
    it('returns trashed documents only, and the active list returns the others only', async () => {
      const active = await seedDocument(owner);
      const older = await seedDocument(owner, { deletedAt: new Date('2026-01-01T00:00:00.000Z') });
      const newer = await seedDocument(owner, { deletedAt: new Date('2026-02-01T00:00:00.000Z') });
      const foreign = await seedDocument(intruder, { deletedAt: new Date() });

      const trash = await get(owner, '/api/v1/documents/trash');
      const list = await get(owner, '/api/v1/documents');

      expect(trash.status, JSON.stringify(trash.body)).toBe(200);
      // Most recently trashed first, which is the default sort.
      expect(idsOf(trash.body)).toEqual([newer.id, older.id]);
      expect(idsOf(trash.body)).not.toContain(active.id);
      expect(idsOf(trash.body)).not.toContain(foreign.id);
      expect(trash.body.pagination.total).toBe(2);

      // The complement, asserted in the same case because the two predicates only
      // mean anything together: a partition that overlaps or that loses a row
      // would satisfy either half alone.
      expect(idsOf(list.body)).toEqual([active.id]);
    });

    it('carries deletedAt on every row it returns', async () => {
      const deletedAt = new Date('2026-04-05T06:07:08.000Z');
      await seedDocument(owner, { deletedAt });

      const res = await get(owner, '/api/v1/documents/trash');

      expect(res.status).toBe(200);
      const [row] = res.body.data as { deletedAt?: string }[];
      expect(row!.deletedAt).toBe(deletedAt.toISOString());
      expect(documentResponseSchema.safeParse(row).success, JSON.stringify(row)).toBe(true);
    });

    it('refuses a sort key the active list has but the trash does not', async () => {
      const res = await get(owner, '/api/v1/documents/trash?sortBy=favorite');

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  describe('GET /documents/usage', () => {
    it('counts trashed documents and their bytes, and reports the operator limits', async () => {
      await seedDocument(owner, { ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES });
      await seedDocument(owner, {
        ciphertextBytes: 512 + DOCUMENT_TAG_BYTES,
        deletedAt: new Date(),
      });
      // Another account's document, which must move neither number.
      await seedDocument(intruder, { ciphertextBytes: 4096 + DOCUMENT_TAG_BYTES });

      const res = await get(owner, '/api/v1/documents/usage');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(documentUsageResponseSchema.safeParse(res.body.data).success).toBe(true);
      // A trashed document still occupies its object, so it still costs quota —
      // both numbers include it, exactly as `initUpload` measures them.
      expect(res.body.data).toEqual({
        documentCount: 2,
        usedBytes: 1024 + 512,
        quotaBytes: config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER * BYTES_PER_MB,
        maxDocumentSizeBytes: config.MAX_DOCUMENT_SIZE_MB * BYTES_PER_MB,
      });
    });

    it('reports zeroes for an account holding nothing, rather than failing', async () => {
      const res = await get(owner, '/api/v1/documents/usage');

      expect(res.status).toBe(200);
      expect(res.body.data.documentCount).toBe(0);
      expect(res.body.data.usedBytes).toBe(0);
      expect(res.body.data.quotaBytes).toBeGreaterThan(0);
    });
  });

  // -------------------------------------------------------------------------
  describe('GET /documents/:id', () => {
    it('returns the row it was asked for, without the storage key', async () => {
      const { id } = await seedDocument(owner);

      const res = await get(owner, `/api/v1/documents/${id}`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data._id).toBe(id);
      expect(res.body.data.chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
      expect(res.body.data).not.toHaveProperty('objectKey');
      expect(res.body.data).not.toHaveProperty('userId');
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
    });

    it('returns a trashed document, so the trash view can open one before purging it', async () => {
      const deletedAt = new Date('2026-05-06T07:08:09.000Z');
      const { id } = await seedDocument(owner, { deletedAt });

      const res = await get(owner, `/api/v1/documents/${id}`);

      expect(res.status).toBe(200);
      expect(res.body.data._id).toBe(id);
      expect(res.body.data.deletedAt).toBe(deletedAt.toISOString());
    });

    it('answers a foreign id exactly as it answers one that never existed', async () => {
      const { id } = await seedDocument(owner);
      const absent = new mongoose.Types.ObjectId().toHexString();

      const foreign = await get(intruder, `/api/v1/documents/${id}`);
      const missing = await get(intruder, `/api/v1/documents/${absent}`);

      expect(foreign.status).toBe(404);
      expect(missing.status).toBe(404);
      // Indistinguishable, or the response enumerates other accounts' ids one
      // request at a time.
      expect(foreign.body.message).toBe(missing.body.message);
      expect(foreign.body.success).toBe(false);
      // …and the refusal handed back nothing about the row.
      expect(foreign.body).not.toHaveProperty('data');
    });

    it('rejects a malformed id with the one id-format message', async () => {
      const res = await get(owner, '/api/v1/documents/not-an-object-id');

      expect(res.status).toBe(400);
      expect(String(res.body.message)).toMatch(/invalid id format/i);
    });
  });

  // -------------------------------------------------------------------------
  describe('GET /documents/:id/segments/:index', () => {
    it('returns each segment byte-for-byte from a range computed on the row', async () => {
      const body = pattern(SMALL.ciphertextBytes, 11);
      const { id } = await seedDocument(owner, { ...SMALL, body });

      for (const [index, range] of SMALL_RANGES.entries()) {
        const res = await get(owner, `/api/v1/documents/${id}/segments/${String(index)}`);

        expect(res.status, `segment ${String(index)}: ${JSON.stringify(res.body)}`).toBe(200);
        // The exact slice of the stored object, which is the assertion the whole
        // route exists to satisfy: the first segment, a middle one, and the SHORT
        // final one, each read from the offset its framing puts it at.
        expect(res.body).toEqual(body.subarray(range.start, range.end + 1));
      }

      // The three segments concatenated are the whole object and nothing more —
      // no byte read twice, none skipped.
      const parts = await Promise.all(
        SMALL_RANGES.map(
          async (_range, index) =>
            (await get(owner, `/api/v1/documents/${id}/segments/${String(index)}`)).body,
        ),
      );
      expect(Buffer.concat(parts as Buffer[])).toEqual(body);
    });

    it('frames from the row’s chunkPlaintextBytes rather than from the server constant', async () => {
      // `SMALL` is framed on a 64-byte chunk. A handler reading
      // `DOCUMENT_PLAINTEXT_CHUNK_BYTES` would place segment 1 at 8 MiB, which is
      // past the end of a 186-byte object; this is the case that would go red.
      const body = pattern(SMALL.ciphertextBytes, 3);
      const { id } = await seedDocument(owner, { ...SMALL, body });

      const res = await get(owner, `/api/v1/documents/${id}/segments/1`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toEqual(body.subarray(80, 160));
      expect(res.headers['content-length']).toBe('80');
      // And the constant really is a different number, so the case is not passing
      // because the two agree.
      expect(SMALL.chunkPlaintextBytes).not.toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    });

    it('sends octet-stream, no-store and the exact segment length', async () => {
      const body = pattern(DEFAULT_FRAMED.ciphertextBytes, 5);
      const { id } = await seedDocument(owner, { body });

      const res = await get(owner, `/api/v1/documents/${id}/segments/0`);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/octet-stream');
      // A segment is user ciphertext: it must not survive in a disk cache, a
      // shared-computer profile or an intermediary.
      expect(res.headers['cache-control']).toBe('no-store');
      // The length the FRAMING implies, so a short read is a truncated response
      // the client cannot mistake for a whole segment.
      expect(res.headers['content-length']).toBe(String(DEFAULT_FRAMED.ciphertextBytes));
      expect((res.body as Buffer).byteLength).toBe(DEFAULT_FRAMED.ciphertextBytes);
    });

    it('refuses an index outside this document, and reads no object for it', async () => {
      const { id } = await seedDocument(owner, { ...SMALL, body: pattern(SMALL.ciphertextBytes) });
      const readSpy = vi.spyOn(storageRef.current!, 'getObjectRange');

      const res = await get(owner, `/api/v1/documents/${id}/segments/3`);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/3 segment\(s\); segment 3 is outside it/);
      // The bound belongs to THIS document, so it has to be checked after the row
      // is read and before storage is touched at all.
      expect(readSpy).not.toHaveBeenCalled();
      readSpy.mockRestore();
    });

    it('refuses an index that is not a canonical decimal, and reads no object', async () => {
      const { id } = await seedDocument(owner, { body: pattern(DEFAULT_FRAMED.ciphertextBytes) });
      const readSpy = vi.spyOn(storageRef.current!, 'getObjectRange');

      // `-1` and `abc` are rejected by the shape; `00`, `0x0`, ` 0` and `1e0` are
      // the four `Number()` would have accepted as other indices, which is why the
      // param schema is a regex over decimal digits rather than `z.coerce.number()`.
      // `MAX_DOCUMENT_CHUNK_COUNT` is one past the last addressable index.
      const indices = [
        '-1',
        'abc',
        '00',
        '0x0',
        '%201',
        '1e0',
        '1.0',
        String(MAX_DOCUMENT_CHUNK_COUNT),
      ];
      for (const index of indices) {
        const res = await get(owner, `/api/v1/documents/${id}/segments/${index}`);
        expect(res.status, `index ${index} answered ${String(res.status)}`).toBe(400);
        expect(res.body.success).toBe(false);
      }

      expect(readSpy).not.toHaveBeenCalled();
      readSpy.mockRestore();
    });

    it('answers 404 when the stored object is gone, and says what is missing', async () => {
      // No `body`: the row exists and the bucket does not hold its object, which is
      // the state a purge interrupted half-way leaves. There is deliberately no
      // `objectMissing` column — the condition is discovered here.
      const { id } = await seedDocument(owner);

      const res = await get(owner, `/api/v1/documents/${id}/segments/0`);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.success).toBe(false);
      // A message about the DOCUMENT, not about a storage key, because this one
      // reaches the UI: only 5xx is redacted, and only in production.
      expect(String(res.body.message)).toMatch(/stored contents of this document are missing/i);
      expect(String(res.body.message)).not.toMatch(/object|bucket|s3/i);
    });

    it("refuses another account's document and never touches its object", async () => {
      const body = pattern(DEFAULT_FRAMED.ciphertextBytes, 9);
      const { id, objectKey } = await seedDocument(owner, { body });
      const readSpy = vi.spyOn(storageRef.current!, 'getObjectRange');

      const res = await get(intruder, `/api/v1/documents/${id}/segments/0`);

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      // The scoping is on the QUERY, so the refusal happens before an object key is
      // ever in hand — an implementation that looked the row up by `_id` alone and
      // checked the owner afterwards would have read these bytes first.
      expect(readSpy).not.toHaveBeenCalled();
      // …and the owner's object is untouched.
      expect(storageRef.current!.readObject(objectKey)).toEqual(body);
      readSpy.mockRestore();
    });

    it('streams a trashed document, which is what makes a download before purging possible', async () => {
      const body = pattern(DEFAULT_FRAMED.ciphertextBytes, 13);
      const { id } = await seedDocument(owner, { body, deletedAt: new Date() });

      const res = await get(owner, `/api/v1/documents/${id}/segments/0`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual(body);
    });

    it('refuses a segment whose stored range is the wrong length, before writing a byte', async () => {
      // The row says 186 bytes; the bucket holds a truncated object. The engine
      // clamps a range that runs past the end rather than failing, so without this
      // check the client would receive a short body under a `Content-Length` that
      // promised a whole segment — and the failure would surface much later as a
      // tag mismatch that reads like corruption.
      const { id, objectKey } = await seedDocument(owner, { ...SMALL });
      await storageRef.current!.putObject(objectKey, pattern(SMALL.ciphertextBytes - 20, 17));

      const res = await get(owner, `/api/v1/documents/${id}/segments/2`);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(res.body.success).toBe(false);
      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    it('passes on an unreachable engine as 503 rather than as a missing document', async () => {
      // Only the provider's 404 is re-worded into "the stored contents of this
      // document are missing". Everything else is passed through untouched, and the
      // difference is what a user is told: a 503 is "come back in a minute", while
      // "this file is gone" is a sentence a password manager must not say about a
      // document that is still there.
      const { id } = await seedDocument(owner, { body: pattern(DEFAULT_FRAMED.ciphertextBytes) });
      vi.spyOn(storageRef.current!, 'getObjectRange').mockRejectedValueOnce(
        httpErrors.serviceUnavailable('Object storage is unavailable'),
      );

      const res = await get(owner, `/api/v1/documents/${id}/segments/0`);

      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(String(res.body.message)).not.toMatch(/stored contents of this document are missing/i);
    });

    it('resets the connection when the segment stream dies part-way through', async () => {
      // `pipeline` destroys both streams on failure, so by the time the handler's
      // catch runs the client's connection is already gone and there is no response
      // left to write: re-throwing would ask the error middleware to serialise JSON
      // onto a dead socket. A reset is also the RIGHT outcome — the declared
      // `Content-Length` means a truncated body cannot be mistaken for a whole
      // segment, and the segment's authentication tag would refuse it even if it
      // could.
      const { id } = await seedDocument(owner, { body: pattern(DEFAULT_FRAMED.ciphertextBytes) });
      const segmentBytes = DEFAULT_FRAMED.ciphertextBytes;
      vi.spyOn(storageRef.current!, 'getObjectRange').mockResolvedValueOnce({
        bytes: segmentBytes,
        // The length the row promises, delivered as a stream that fails after its
        // first chunk — the shape a dropped connection to the engine really has.
        body: new Readable({
          read(this: Readable) {
            this.push(Buffer.alloc(16, 1));
            this.destroy(new Error('the engine dropped the connection'));
          },
        }),
      });

      logs.error.mockClear();

      const outcome = await get(owner, `/api/v1/documents/${id}/segments/0`).then(
        (res) => ({ ok: true as const, res }),
        (error: unknown) => ({ ok: false as const, error }),
      );

      // An HTTP client may surface a reset either way — as a thrown transport error
      // or as a truncated 200 — and which one is a property of the client, not of
      // this handler. What the handler guarantees is the same in both: the caller
      // never receives a WHOLE segment, and never a JSON error body written on top
      // of octet-stream bytes it had already started sending.
      if (outcome.ok) {
        expect(outcome.res.headers['content-type']).toMatch(/application\/octet-stream/);
        expect(outcome.res.headers['content-type']).not.toMatch(/application\/json/);
        expect(Buffer.isBuffer(outcome.res.body) ? outcome.res.body.length : 0).toBeLessThan(
          segmentBytes,
        );
      } else {
        expect(outcome.error).toBeInstanceOf(Error);
      }

      // The branch's own deliverable. `pipeline` has already destroyed both streams
      // by the time the catch runs, so this is what distinguishes "log it" from
      // "re-throw it onto a socket that is gone".
      expect(logs.error).toHaveBeenCalledWith(
        'A document segment stream failed part-way through',
        expect.objectContaining({ documentId: id, index: 0 }),
      );

      // And the failure was contained: the very next read of the very same segment
      // returns the whole thing, byte for byte.
      const retry = await get(owner, `/api/v1/documents/${id}/segments/0`);
      expect(retry.status).toBe(200);
      expect(retry.body).toEqual(pattern(DEFAULT_FRAMED.ciphertextBytes));
      expect(retry.headers['content-length']).toBe(String(segmentBytes));
    });

    it('answers an unauthenticated caller with 401 and reads nothing', async () => {
      const { id } = await seedDocument(owner, { body: pattern(DEFAULT_FRAMED.ciphertextBytes) });
      const readSpy = vi.spyOn(storageRef.current!, 'getObjectRange');

      const res = await request(app).get(`/api/v1/documents/${id}/segments/0`);

      expect(res.status).toBe(401);
      expect(readSpy).not.toHaveBeenCalled();
      readSpy.mockRestore();
    });
  });
});
