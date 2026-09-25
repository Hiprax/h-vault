/**
 * `POST /documents/uploads/:id/complete` — the request that turns a finished
 * transfer into a document.
 *
 * ## What this handler must never be talked into
 *
 * It is the ONLY place a `documents` row is created, and every number on that row
 * describes bytes the client no longer controls. So the cases below are mostly
 * about what the server refuses to be told: the sizes are derived from the parts
 * the storage engine reports and never from the request, the part ledger and the
 * engine must agree before either is believed, and the derived triple has to be
 * self-consistent — because three numbers each correct on its own can still
 * describe a document that lists, counts against a quota and never opens. The
 * `documentResponseSchema` refines a client runs on every read are the standard
 * every committed row here is measured against.
 *
 * ## The two refusals that are NOT the same
 *
 * A stale `vaultKeyVersion` leaves the transfer alive on purpose: the whole reason
 * the wrapped key crosses the wire a second time is so that a rotation costs one
 * retried request instead of re-uploading the file, and a case here proves the
 * retry works. A quota breach releases the transfer, because those bytes are
 * exactly the ones the account cannot hold. Both halves are asserted, in both
 * directions.
 *
 * ## The two seams
 *
 * MONGO IS REAL: ownership, the ledger, the audit row and the unique `_id` that
 * makes a repeat completion idempotent are all decided by a query. OBJECT STORAGE
 * IS A DOUBLE (`helpers/inMemoryStorage.ts`), because it is an external service in
 * the same class as SMTP, and the same contract suite runs that double and a real
 * engine in the conformance gate.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  documentResponseSchema,
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
import { config } from '../src/config/index.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { Folder } from '../src/models/Folder.js';
import { JobLock } from '../src/models/JobLock.js';
import { User } from '../src/models/User.js';
import { documentCompleteLockName, vaultRotationLockName } from '../src/utils/controllerHelpers.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

const BYTES_PER_MB = 1024 * 1024;
const QUOTA_BYTES = config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER * BYTES_PER_MB;

/** The framing columns a staging row carries. Opaque strings; nothing here decrypts. */
const FRAMING = {
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/** The wrapped key as it was recorded at INIT — the copy this handler must NOT use. */
const STAGED_DEK = {
  encryptedDek: 'staged-dek-ciphertext',
  dekIv: 'staged-dek-iv',
  dekTag: 'staged-dek-tag',
};

/** The wrapped key as the COMPLETION body carries it — the copy that must be stored. */
const BODY_DEK = {
  encryptedDek: 'completion-dek-ciphertext',
  dekIv: 'completion-dek-iv',
  dekTag: 'completion-dek-tag',
};

const SEALED_META = {
  encryptedMeta: 'document-metadata-ciphertext',
  metaIv: 'meta-iv',
  metaTag: 'meta-tag',
};

/**
 * A body whose bytes vary along its length.
 *
 * Never `Buffer.alloc(n)`: a run of identical bytes survives being reordered or
 * truncated in the middle and re-expanded, so the concatenation assertion in the
 * multipart case would pass on a document the engine had scrambled.
 */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

interface SeedOptions {
  /** The sizes of the parts this transfer delivered, in ascending part order. */
  partSizes?: number[];
  /** Defaults to `partSizes.length`, so a mismatch has to be asked for. */
  declaredChunkCount?: number;
  declaredPlaintextBytes?: number;
  /** Defaults to `declaredChunkCount > 1`. */
  multipart?: boolean;
  expiresAt?: Date;
  folderId?: string;
  vaultKeyVersion?: number;
  /** Write the delivered parts into the staging ledger. Default true. */
  recordLedger?: boolean;
  /** Store the delivered parts in the engine. Default true. */
  storeInEngine?: boolean;
  /** Overrides the `receivedBytes` the ledger would imply. */
  receivedBytes?: number;
  /** Sizes the ENGINE holds, when they must differ from the ledger's. */
  engineSizes?: number[];
}

interface Seeded {
  id: string;
  objectKey: string;
  s3UploadId: string | undefined;
  partSizes: number[];
}

/**
 * A staging row with its parts already delivered, standing in for a finished
 * transfer.
 *
 * Seeded rather than driven through init and the part route on purpose: those two
 * have their own suites, and routing every case here through them would make each
 * failure ambiguous between three handlers. What is faithfully reproduced is the
 * STATE they leave — the engine holding the bytes, and the ledger recording them —
 * because that state is exactly what this handler reads.
 */
async function seedTransfer(user: TestUser, options: SeedOptions = {}): Promise<Seeded> {
  const partSizes = options.partSizes ?? [1024 + DOCUMENT_TAG_BYTES];
  const engineSizes = options.engineSizes ?? partSizes;
  const declaredChunkCount = options.declaredChunkCount ?? Math.max(1, partSizes.length);
  const multipart = options.multipart ?? declaredChunkCount > 1;
  const storage = storageRef.current!;

  const uploadId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(user.id, uploadId.toHexString());
  const s3UploadId = multipart ? await storage.createMultipartUpload(objectKey) : undefined;

  if (options.storeInEngine !== false) {
    for (const [index, bytes] of engineSizes.entries()) {
      const body = pattern(bytes, index + 1);
      if (s3UploadId === undefined) {
        await storage.putObject(objectKey, body);
      } else {
        await storage.uploadPart(objectKey, s3UploadId, index + 1, body);
      }
    }
  }

  const ledger =
    options.recordLedger === false
      ? []
      : partSizes.map((bytes, index) => ({ partNumber: index + 1, bytes }));

  await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey,
    ...(s3UploadId === undefined ? {} : { s3UploadId }),
    ...STAGED_DEK,
    ...FRAMING,
    declaredPlaintextBytes:
      options.declaredPlaintextBytes ??
      partSizes.reduce((total, bytes) => total + bytes, 0) - DOCUMENT_TAG_BYTES * partSizes.length,
    declaredChunkCount,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: options.vaultKeyVersion ?? 0,
    parts: ledger,
    receivedBytes: options.receivedBytes ?? ledger.reduce((total, part) => total + part.bytes, 0),
    ...(options.folderId === undefined ? {} : { folderId: options.folderId }),
    expiresAt: options.expiresAt ?? new Date(Date.now() + 60 * 60 * 1000),
  });

  return { id: String(uploadId), objectKey, s3UploadId, partSizes };
}

const completePath = (uploadId: string): string => `/api/v1/documents/uploads/${uploadId}/complete`;

/** The completion body a well-behaved client sends. */
const completionBody = (vaultKeyVersion = 0): Record<string, unknown> => ({
  ...SEALED_META,
  ...BODY_DEK,
  vaultKeyVersion,
});

/** One authenticated completion through the real app, with a real CSRF pair. */
async function complete(
  user: TestUser,
  uploadId: string,
  body: Record<string, unknown> = completionBody(),
): Promise<request.Response> {
  const agent = request.agent(app);
  const pair = await getCsrf(agent);
  const pending = agent
    .post(completePath(uploadId))
    .set('Authorization', authHeader(user.accessToken));
  return pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token).send(body);
}

/** One sign-in through the real route, with a real CSRF pair. */
async function signIn(user: TestUser): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/auth/login')
    .set('Cookie', cookie)
    .set('x-csrf-token', token)
    .send({ email: user.email, authHash: user.rawPassword });
}

/**
 * A REAL vault-key rotation, not a `$set` on the counter.
 *
 * The counter and the new wrapped vault key move in one update, and it is that
 * pairing the cases below depend on: a `$set` would advance the number while
 * leaving the account's stored key the one the session still holds, which is the
 * opposite of the situation being modelled. The account holds no items, folders
 * or documents here, so three empty legs satisfy the completeness check — a
 * staging row is not a `documents` row and is invisible to a rotation, which is
 * the whole reason an in-flight transfer needs a version check at all.
 */
async function rotateVaultKey(user: TestUser): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/vault/items/bulk-reencrypt')
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', cookie)
    .set('x-csrf-token', token)
    .send({
      authHash: user.rawPassword,
      items: [],
      folders: [],
      documents: [],
      newEncryptedVaultKey: 'rotated-vault-key',
      newVaultKeyIv: 'rotated-vault-key-iv',
      newVaultKeyTag: 'rotated-vault-key-tag',
    });
}

/** Everything a refusal must have left untouched, in one object. */
async function stateOf(seeded: Seeded): Promise<{
  documents: number;
  ledger: { partNumber: number; bytes: number }[];
  receivedBytes: number | null;
  storedKeys: string[];
  openUploads: number;
}> {
  const row = await DocumentUpload.findById(seeded.id).lean();
  const storage = storageRef.current!;
  return {
    documents: await Document.countDocuments({}),
    ledger: (row?.parts ?? []).map((part) => ({ partNumber: part.partNumber, bytes: part.bytes })),
    receivedBytes: row?.receivedBytes ?? null,
    storedKeys: storage.storedKeys(),
    openUploads: (await storage.listMultipartUploads()).length,
  };
}

describe('POST /documents/uploads/:id/complete', () => {
  let user: TestUser;

  beforeEach(async () => {
    storageRef.current = createInMemoryStorage();
    user = await createTestUser({ email: 'documents-complete@example.com' });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // The committed row
  // -------------------------------------------------------------------------

  describe('what it commits', () => {
    it('derives the framing from the part ledger and stores the DEK from the COMPLETION body', async () => {
      const seeded = await seedTransfer(user, { partSizes: [1024 + DOCUMENT_TAG_BYTES] });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      // The row a client reads must satisfy both of the identities it re-checks.
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
      const row = await Document.findById(seeded.id).lean();
      expect(row).not.toBeNull();
      expect(row!.chunkCount).toBe(1);
      expect(row!.ciphertextBytes).toBe(1024 + DOCUMENT_TAG_BYTES);
      expect(row!.plaintextBytes).toBe(1024);
      expect(row!.chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
      // The whole point of sending the wrapped key twice: the STAGING copy is not
      // what is committed, or a rotation mid-transfer could never be recovered from.
      expect(row!.encryptedDek).toBe(BODY_DEK.encryptedDek);
      expect(row!.dekIv).toBe(BODY_DEK.dekIv);
      expect(row!.dekTag).toBe(BODY_DEK.dekTag);
      expect(row!.encryptedDek).not.toBe(STAGED_DEK.encryptedDek);
      // Each of the three sealed-metadata columns individually, not as a group: the
      // IV and the tag are both opaque base64 of similar shape, so a transposition
      // between them produces a row that satisfies every schema on the wire and a
      // blob that can never be opened again.
      expect(row!.encryptedMeta).toBe(SEALED_META.encryptedMeta);
      expect(row!.metaIv).toBe(SEALED_META.metaIv);
      expect(row!.metaTag).toBe(SEALED_META.metaTag);
      // The framing parameters DO come from the staging row: they were chosen at
      // init and are already baked into the stored segment.
      expect(row!.streamSalt).toBe(FRAMING.streamSalt);
      expect(row!.noncePrefix).toBe(FRAMING.noncePrefix);
      expect(row!.objectKey).toBe(seeded.objectKey);
      // …and the transfer is gone, with its bytes still in the bucket.
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });

    it('commits what ARRIVED, not what the transfer declared it would send', async () => {
      // The case the whole derivation exists for, and it is reachable through the
      // ordinary API rather than contrived: a client may declare one plaintext byte,
      // which frames the transfer as a single segment, and then legally deliver a
      // final part of any size up to a full chunk — the part handler only pins the
      // size of NON-final parts. Believing the declaration would commit a row saying
      // one byte for an object holding four thousand, so the document would read
      // short, the digest inside its metadata would never match, and the account
      // would be charged for a byte of the four kilobytes it is using.
      const seeded = await seedTransfer(user, {
        partSizes: [4096 + DOCUMENT_TAG_BYTES],
        declaredPlaintextBytes: 1,
        declaredChunkCount: 1,
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const row = await Document.findById(seeded.id).lean();
      expect(row!.plaintextBytes).toBe(4096);
      expect(row!.ciphertextBytes).toBe(4096 + DOCUMENT_TAG_BYTES);
      expect(row!.plaintextBytes).not.toBe(1);
    });

    it('never echoes the owner or the storage key back to the client', async () => {
      const seeded = await seedTransfer(user);

      const res = await complete(user, seeded.id);

      expect(res.status).toBe(201);
      const data = res.body.data as Record<string, unknown>;
      expect(data).not.toHaveProperty('userId');
      expect(data).not.toHaveProperty('objectKey');
      expect(data).not.toHaveProperty('__v');
      expect(data._id).toBe(seeded.id);
    });

    it('completes a multipart transfer into one object that is the parts concatenated', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const row = await Document.findById(seeded.id).lean();
      expect(row!.chunkCount).toBe(2);
      expect(row!.ciphertextBytes).toBe(
        DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 4096 + DOCUMENT_TAG_BYTES,
      );
      expect(row!.plaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES + 4096);
      // The engine now holds ONE object of exactly that length, and holds no open
      // multipart upload — the parts were named back to it and it assembled them.
      const stored = storageRef.current!.readObject(seeded.objectKey);
      expect(stored?.byteLength).toBe(row!.ciphertextBytes);
      expect(
        Buffer.compare(
          stored!,
          Buffer.concat([
            pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 1),
            pattern(4096 + DOCUMENT_TAG_BYTES, 2),
          ]),
        ),
      ).toBe(0);
      expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
    });

    it('writes one document_create audit row naming the DERIVED sizes, and no other document action', async () => {
      const seeded = await seedTransfer(user, { partSizes: [2048 + DOCUMENT_TAG_BYTES] });

      await complete(user, seeded.id);

      const entries = await AuditLog.find({ userId: user.id }).lean();
      const created = entries.filter((entry) => entry.action === 'document_create');
      expect(created).toHaveLength(1);
      expect(created[0]!.metadata).toMatchObject({
        documentId: seeded.id,
        chunkCount: 1,
        plaintextBytes: 2048,
      });
      // No read is audited anywhere in this codebase, and completion must not
      // invent a second row for the same act.
      expect(entries.filter((entry) => entry.action.startsWith('document_'))).toHaveLength(1);
    });

    it('keeps a folder that still exists and STRIPS one deleted since init', async () => {
      const folder = await Folder.create({
        userId: user.id,
        encryptedName: 'folder-ciphertext',
        nameIv: 'iv',
        nameTag: 'tag',
        searchHash: 'a'.repeat(64),
        sortOrder: 0,
      });
      const kept = await seedTransfer(user, { folderId: String(folder._id) });
      const orphaned = await seedTransfer(user, { folderId: String(folder._id) });

      expect((await complete(user, kept.id)).status).toBe(201);
      await Folder.deleteOne({ _id: folder._id });
      expect((await complete(user, orphaned.id)).status).toBe(201);

      // Filed where the user asked, when the folder is still there…
      expect(String((await Document.findById(kept.id).lean())!.folderId)).toBe(String(folder._id));
      // …and unfiled rather than filed under an id that appears in no listing.
      expect((await Document.findById(orphaned.id).lean())!.folderId).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Verification against the engine
  // -------------------------------------------------------------------------

  describe('what it refuses, having verified the parts against the engine', () => {
    it('refuses a transfer whose last part never arrived', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredChunkCount: 2,
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/declared 2 part\(s\) and 1 arrived/i);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('refuses a GAP in the part numbers, because a gap moves every later segment', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredChunkCount: 3,
      });
      // Renumber the delivered pair as parts 1 and 3, on both sides, so the only
      // thing wrong is the hole.
      await DocumentUpload.updateOne(
        { _id: seeded.id },
        {
          $set: {
            parts: [
              { partNumber: 1, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
              { partNumber: 3, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
            ],
          },
        },
      );
      await storageRef.current!.uploadPart(
        seeded.objectKey,
        seeded.s3UploadId!,
        3,
        pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 3),
      );
      // The engine now holds 1, 2 and 3; drop 2 so both sides show the same hole.
      const engine = createInMemoryStorage();
      storageRef.current = engine;
      const reopened = await engine.createMultipartUpload(seeded.objectKey);
      await engine.uploadPart(
        seeded.objectKey,
        reopened,
        1,
        pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 1),
      );
      await engine.uploadPart(
        seeded.objectKey,
        reopened,
        3,
        pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 3),
      );
      await DocumentUpload.updateOne({ _id: seeded.id }, { $set: { s3UploadId: reopened } });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/missing part 2/i);
      expect(await Document.countDocuments({})).toBe(0);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });

    it('refuses when the engine holds a part the server never accepted', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 512 + DOCUMENT_TAG_BYTES],
      });
      // The engine holds a third part; the ledger records two. Believing the
      // engine alone would frame a document around a part nothing validated.
      await storageRef.current!.uploadPart(
        seeded.objectKey,
        seeded.s3UploadId!,
        3,
        pattern(512 + DOCUMENT_TAG_BYTES, 9),
      );
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/holds 3 part\(s\).*accepted 2/i);
      expect(await stateOf(seeded)).toEqual(before);
    });

    it('refuses when the engine and the ledger disagree about a part SIZE', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [1024 + DOCUMENT_TAG_BYTES],
        engineSizes: [2048 + DOCUMENT_TAG_BYTES],
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(
        /byte\(s\) in storage and .* in this transfer's ledger/i,
      );
      expect(await stateOf(seeded)).toEqual(before);
    });

    it('refuses a SHORT MIDDLE PART that reached the engine, which the engine itself accepts', async () => {
      // The rule nothing below the server enforces. S3 only requires the LAST part
      // to be allowed to be short, and the engine this stack ships was measured
      // accepting a short middle one; it shifts every later segment boundary by the
      // shortfall, so every ranged read after it decrypts to nothing.
      const shortMiddle = DOCUMENT_CIPHERTEXT_CHUNK_BYTES - 8;
      const seeded = await seedTransfer(user, {
        partSizes: [shortMiddle, 4096 + DOCUMENT_TAG_BYTES],
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/segment boundary/i);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('refuses a PHANTOM EMPTY FINAL SEGMENT, where all three derived numbers are individually fine', async () => {
      // Two parts whose last is exactly one authentication tag. Every earlier check
      // passes: the part handler permits it (only a NON-final part must be a full
      // chunk), the engine permits it (the last part may be short), the ledger and
      // the engine agree, and the count matches what was declared. What breaks is
      // the relationship BETWEEN the three derived numbers — the plaintext is one
      // whole chunk, so the document is one segment, while the ledger says two.
      // Committed, that row fails `documentResponseSchema` on every read: it would
      // list, count against the quota, and never open.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES],
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/cannot frame a document/i);
      expect(String(res.body.message)).toMatch(/chunkCount must equal ceil/i);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('admits the same transfer with ONE more plaintext byte in the final segment', async () => {
      // The n+1 side of the boundary above, and the control for it: a refusal
      // written one comparison too wide would take this legitimate document with it.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES + 1],
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const row = await Document.findById(seeded.id).lean();
      expect(row!.chunkCount).toBe(2);
      expect(row!.plaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1);
    });

    it('admits an EMPTY file, which is one segment holding nothing but its tag', async () => {
      // The other legitimate neighbour of the phantom refusal above, and the reason
      // `documentChunkCountFor` carries its `max(1, ...)`: a zero-byte file is still
      // one sealed segment, so the smallest object that can exist is exactly one
      // authentication tag. A refusal narrowed to `plaintextBytes <= 0` would break
      // every empty upload, and every other case in this file would stay green.
      const seeded = await seedTransfer(user, { partSizes: [DOCUMENT_TAG_BYTES] });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
      const row = await Document.findById(seeded.id).lean();
      expect(row!.plaintextBytes).toBe(0);
      expect(row!.chunkCount).toBe(1);
      expect(row!.ciphertextBytes).toBe(DOCUMENT_TAG_BYTES);
    });

    it('refuses a transfer that received no parts at all, naming the transfer rather than the object', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [1024 + DOCUMENT_TAG_BYTES],
        recordLedger: false,
        storeInEngine: false,
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/no parts have been received/i);
      // Not the storage engine's "Stored object not found", which reads as though
      // the upload itself had vanished.
      expect(String(res.body.message)).not.toMatch(/stored object/i);
      expect(await Document.countDocuments({})).toBe(0);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });

    it('refuses a multi-segment row that names no engine-side upload rather than storing one part as the whole document', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 32],
        multipart: false,
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('refuses an expired transfer with the same 404 its TTL will shortly make literal', async () => {
      const seeded = await seedTransfer(user, { expiresAt: new Date(Date.now() - 60_000) });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(String(res.body.message)).toMatch(/upload not found/i);
      expect(await Document.countDocuments({})).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // The vault key
  // -------------------------------------------------------------------------

  describe('the vault-key fence and version check', () => {
    it('answers 409 with the CURRENT version, keeps the transfer, and creates no row', async () => {
      const seeded = await seedTransfer(user);
      // Raised directly: the rotation that increments it commits the new vault key
      // in the same update, and this handler's contract with it is the number alone.
      await User.updateOne({ _id: user.id }, { $set: { vaultKeyVersion: 3 } });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id, completionBody(0));

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.success).toBe(false);
      // Machine-readable, because the client rewraps against this number.
      expect(res.body.data).toEqual({ vaultKeyVersion: 3 });
      expect(String(res.body.message)).toMatch(/version 3/);
      // Diagnosed as the rotation it is, and not as the bookkeeping fault the
      // belt below answers — the two refusals share a remedy, not a cause.
      expect(String(res.body.message)).toMatch(/rotated/i);
      expect(String(res.body.message)).not.toMatch(/never had/i);
      // NOTHING released: the transfer is exactly as it was, which is what makes
      // the retry below cost one request instead of the whole file.
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('accepts the retry that rewraps the key, without a byte being re-sent', async () => {
      const seeded = await seedTransfer(user);
      await User.updateOne({ _id: user.id }, { $set: { vaultKeyVersion: 3 } });
      expect((await complete(user, seeded.id, completionBody(0))).status).toBe(409);

      const rewrapped = {
        ...SEALED_META,
        encryptedDek: 'rewrapped-dek-ciphertext',
        dekIv: 'rewrapped-dek-iv',
        dekTag: 'rewrapped-dek-tag',
        vaultKeyVersion: 3,
      };
      const res = await complete(user, seeded.id, rewrapped);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const row = await Document.findById(seeded.id).lean();
      expect(row!.encryptedDek).toBe('rewrapped-dek-ciphertext');
      expect(row!.dekTag).toBe('rewrapped-dek-tag');
      // The bytes were never touched: one object, the one the transfer uploaded.
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });

    it('refuses a rotation that STARTS after the cheap check, which only the late fence sees', async () => {
      // The window the second fence exists for, and the reason one check is not
      // enough. The completion reads the ledger from the storage engine, computes
      // its arithmetic and re-checks the quota before it commits anything; a
      // rotation that begins anywhere in there has already enumerated the account's
      // documents WITHOUT this one, so a row inserted afterwards is wrapped under a
      // key the rotation will supersede and nothing will ever unwrap it again. The
      // version cannot catch it either: the rotation raises its flag before it
      // touches the number.
      //
      // The engine read is the seam the delay is injected at, because it is exactly
      // where the real elapsed time is.
      const seeded = await seedTransfer(user);
      const engine = storageRef.current!;
      const realHeadObject = engine.headObject.bind(engine);
      vi.spyOn(engine, 'headObject').mockImplementation(async (key: string) => {
        await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
        return realHeadObject(key);
      });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/rotation is in progress/i);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    it('refuses while a rotation is IN PROGRESS, which the version alone cannot see', async () => {
      // The flag is raised before the rotation enumerates, so a row inserted now is
      // a row the enumeration will not have seen and the new key will not cover —
      // and the version has not moved yet, so only the fence catches it.
      const seeded = await seedTransfer(user);
      await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/rotation is in progress/i);
      expect(await stateOf(seeded)).toEqual(before);
      expect(before.documents).toBe(0);
    });

    // -----------------------------------------------------------------------
    // The version has to describe the CLIENT's key, not the server's clock
    // -----------------------------------------------------------------------

    it('publishes, at sign-in, the vault key version the wrapped key it hands back belongs to', async () => {
      // Every case above moves the SERVER's number after the transfer opened, so
      // the number the client echoes back is the stale one and the comparison at
      // completion catches it. None of them models the other order: a session that
      // signed in, kept its key in memory, and only then had the account rotated
      // from somewhere else. A rotation revokes no session and refreshes no key
      // (`vaultController.ts` touches neither `RefreshToken` nor
      // `passwordChangedAt`), so that session is still live and still holding the
      // superseded key — and if it opens a transfer now, init reads the CURRENT
      // number and echoes it, the numbers agree at completion, and the row commits
      // wrapped under a key the account no longer stores.
      //
      // The only thing that can break that agreement is the client sending the
      // version its OWN key belongs to, and the only place it can learn that is the
      // response that handed it the key. Sign-in is that response: it is where the
      // wrapped vault key is delivered, and it fetches no profile. Unlock re-derives
      // from the very blob delivered here, so the two travel together for the life
      // of the session.
      const before = await signIn(user);
      expect(before.status, JSON.stringify(before.body)).toBe(200);
      expect(before.body.data.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect(before.body.data.vaultKeyVersion).toBe(0);

      const rotation = await rotateVaultKey(user);
      expect(rotation.status, JSON.stringify(rotation.body)).toBe(200);

      // It tracks the key, both parts of it: a session signing in AFTER the
      // rotation is handed the new wrapped key and the number that names it, so it
      // never takes the 409 below.
      const after = await signIn(user);
      expect(after.status, JSON.stringify(after.body)).toBe(200);
      expect(after.body.data.encryptedVaultKey).toBe('rotated-vault-key');
      expect(after.body.data.vaultKeyVersion).toBe(1);
    });

    it('refuses a session whose key predates a rotation the init echo already reflects, and commits nothing', async () => {
      // The S1 arrangement, end to end: sign in, THEN rotate, THEN open the
      // transfer. The staging row therefore carries the CURRENT version — this is
      // what `initUpload` would have echoed — so the number that would once have
      // come back in the completion body agrees with the server and nothing stops
      // the row committing.
      const session = await signIn(user);
      expect(session.status, JSON.stringify(session.body)).toBe(200);
      // Read from the response rather than written as a literal on purpose: a
      // literal would pass whether or not the server ever told this session which
      // key version it holds, which is precisely the thing being fixed.
      const sessionVaultKeyVersion: unknown = session.body.data.vaultKeyVersion;
      expect(sessionVaultKeyVersion).toBe(0);

      expect((await rotateVaultKey(user)).status).toBe(200);
      expect((await User.findById(user.id).lean())!.vaultKeyVersion).toBe(1);

      const seeded = await seedTransfer(user, { vaultKeyVersion: 1 });
      const state = await stateOf(seeded);

      const res = await complete(user, seeded.id, completionBody(sessionVaultKeyVersion as number));

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      // THE NEGATIVE, and the reason this finding is data loss rather than an
      // error code: a row committed here would list, charge the quota, never open,
      // and — because the browser aborts a whole rotation on the first row it
      // cannot unwrap — block every future rotation of this account until it was
      // permanently deleted.
      expect(await Document.countDocuments({})).toBe(0);
      // And the transfer is untouched, so the recovery costs one rewrapped
      // completion rather than the file.
      expect(await stateOf(seeded)).toEqual(state);
    });

    it('refuses a version ABOVE the current one as unreachable, not as a rotation', async () => {
      // The belt. The number now arrives from the client's own bookkeeping rather
      // than from a server echo, and a version the account has never reached cannot
      // name a key it ever stored. Answered with the recoverable refusal rather
      // than a hard 400 — it still commits nothing, which is the property that
      // matters, and it hands back the number a confused client needs instead of
      // destroying a finished transfer.
      //
      // The DIAGNOSIS is what makes this its own case and not a restatement of the
      // mismatch below it. A plain `!==` refuses this too, so the status, the
      // payload and the negatives alone would say nothing about whether the
      // separate branch exists at all; the message is what only that branch
      // produces, and it is the difference between sending a reader to look for a
      // rotation and telling them the client's own bookkeeping is wrong.
      const seeded = await seedTransfer(user);
      const state = await stateOf(seeded);

      const res = await complete(user, seeded.id, completionBody(7));

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/never had/i);
      expect(String(res.body.message)).not.toMatch(/rotated/i);
      // Still the number to rewrap under, because the remedy is the same.
      expect(String(res.body.message)).toMatch(/version 0/);
      expect(res.body.data).toEqual({ vaultKeyVersion: 0 });
      expect(await Document.countDocuments({})).toBe(0);
      expect(await stateOf(seeded)).toEqual(state);
    });
  });

  // -------------------------------------------------------------------------
  // The exclusion lock: what makes the pair above hold all the way to the insert
  // -------------------------------------------------------------------------

  /**
   * The fence and the version check are READS, and the distance from them to
   * `Document.create` is not a statement or two: for a multipart transfer it
   * contains the engine's own completion call, which is seconds for a large
   * object. A rotation that begins and commits entirely inside that span
   * enumerates an account this document is not yet part of, so its completeness
   * check has nothing to catch and the row lands wrapped under a superseded key.
   * That row then makes EVERY future rotation abort: the client cannot unwrap its
   * DEK, so it can never re-key it, and the coverage check refuses a payload that
   * does not name it. One completion in the wrong millisecond permanently ends
   * the account's ability to rotate.
   *
   * The version check cannot simply move after the engine call instead — the
   * engine invalidates the upload id on success, so a client told to rewrap would
   * find nothing left to complete. So the span is made atomic rather than short:
   * the completion holds `vault-rotation:<userId>`, the same lock `bulkReEncrypt`
   * takes before it raises the fence, from before the late pair until after the
   * insert.
   *
   * The cost is named rather than hidden: two completions of DIFFERENT uploads
   * for the same account no longer overlap. The loser is refused with a 409 that
   * preserves its staging row, which is the retryable shape every other refusal
   * here already uses, and the client treats a 409 carrying no number as an
   * ordinary failure it re-drives.
   */
  describe('the vault-key exclusion lock, held from the late pair to the insert', () => {
    /** Takes the exclusion lock as a rotation would, and returns its release. */
    async function holdExclusionLock(): Promise<() => Promise<void>> {
      const lockId = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
      expect(lockId, 'the fixture could not take the lock it is testing').not.toBeNull();
      return async () => {
        await releaseJobLock(vaultRotationLockName(user.id), lockId as string);
      };
    }

    const exclusionLocks = async (): Promise<number> =>
      JobLock.countDocuments({ jobName: vaultRotationLockName(user.id) });

    it('refuses while a rotation holds the lock, and leaves the transfer retryable', async () => {
      const seeded = await seedTransfer(user);
      const release = await holdExclusionLock();
      const before = await stateOf(seeded);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/already in progress/i);
      // No number: the caller's generation is fine and rewrapping would be the
      // wrong remedy, so the refusal must not look like the stale-key one.
      expect(res.body.data).toBeUndefined();
      // THE NEGATIVE: the staging row, its ledger and the stored bytes are all
      // exactly as they were, so the retry costs one request and not the file.
      expect(await stateOf(seeded)).toEqual(before);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
      // The per-upload lock is taken first and must still be released.
      expect(
        await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
      ).toBe(0);

      await release();
      const retried = await complete(user, seeded.id);
      expect(retried.status, JSON.stringify(retried.body)).toBe(201);
      expect(await exclusionLocks()).toBe(0);
    });

    it('still holds the lock at the moment the row is inserted', async () => {
      // The case a check-and-release cannot pass: the probe runs inside the write
      // itself and tries to take the lock a rotation would take.
      const seeded = await seedTransfer(user);
      const realCreate = Document.create.bind(Document);
      let lockWasFreeAtInsertTime: boolean | null = null;
      vi.spyOn(Document, 'create').mockImplementation((async (doc: never) => {
        const stolen = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
        lockWasFreeAtInsertTime = stolen !== null;
        if (stolen !== null) await releaseJobLock(vaultRotationLockName(user.id), stolen);
        return realCreate(doc);
      }) as never);

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(
        lockWasFreeAtInsertTime,
        'the probe never ran, so this case proves nothing about the span',
      ).not.toBeNull();
      expect(
        lockWasFreeAtInsertTime,
        'a rotation could take the exclusion lock while the completion was inserting',
      ).toBe(false);
    });

    it('still holds the lock while the engine assembles a multipart object', async () => {
      // The seconds-long half of the span, and the half the version check cannot
      // be moved past. A rotation must not be able to slip in here either.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 1024 + DOCUMENT_TAG_BYTES],
      });
      const engine = storageRef.current!;
      const realComplete = engine.completeMultipartUpload.bind(engine);
      let lockWasFreeMidAssembly: boolean | null = null;
      vi.spyOn(engine, 'completeMultipartUpload').mockImplementation(
        async (key: string, uploadId: string, parts: { partNumber: number; etag: string }[]) => {
          const stolen = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
          lockWasFreeMidAssembly = stolen !== null;
          if (stolen !== null) await releaseJobLock(vaultRotationLockName(user.id), stolen);
          return realComplete(key, uploadId, parts);
        },
      );

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(lockWasFreeMidAssembly, 'the probe never ran').not.toBeNull();
      expect(
        lockWasFreeMidAssembly,
        'a rotation could take the exclusion lock while the engine was assembling the object',
      ).toBe(false);
    });

    it('releases the lock when the completion is refused for an unrelated reason', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredChunkCount: 2,
      });

      expect((await complete(user, seeded.id)).status).toBe(400);

      // A leaked exclusion lock is not one stalled upload: it blocks rotation,
      // import, restore, every other completion and the master-password change
      // for the whole five-minute TTL.
      expect(await exclusionLocks()).toBe(0);
    });

    it('does not take the exclusion lock when the per-upload lock is contended', async () => {
      // Acquisition order is per-upload lock first, exclusion lock second. A loser
      // of the first must leave the second untouched, or one duplicated retry
      // would block a rotation for nothing.
      const seeded = await seedTransfer(user);
      await JobLock.create({
        jobName: documentCompleteLockName(user.id, seeded.id),
        lockedBy: 'another-completion',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/already being completed/i);
      expect(await exclusionLocks()).toBe(0);
    });

    it('holds nothing once an ordinary completion has succeeded', async () => {
      const seeded = await seedTransfer(user);

      expect((await complete(user, seeded.id)).status).toBe(201);

      expect(await exclusionLocks()).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Quota, measured on what arrived
  // -------------------------------------------------------------------------

  describe('the quota, re-measured against the bytes actually received', () => {
    it('releases the transfer when the received bytes do not fit, and commits nothing', async () => {
      const documentId = new mongoose.Types.ObjectId();
      await Document.create({
        _id: documentId,
        userId: user.id,
        objectKey: buildObjectKey(user.id, documentId.toHexString()),
        ...STAGED_DEK,
        ...FRAMING,
        encryptedMeta: 'meta',
        metaIv: 'iv',
        metaTag: 'tag',
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        chunkCount: 1,
        ciphertextBytes: QUOTA_BYTES - 1024 + DOCUMENT_TAG_BYTES,
        plaintextBytes: QUOTA_BYTES - 1024,
      });
      // Declares one byte — which FITS the remaining budget — and delivers four
      // kilobytes, which does not. A quota re-checked against the declaration would
      // admit this and let an account store as much as it liked by understating
      // every transfer.
      const seeded = await seedTransfer(user, {
        partSizes: [4096 + DOCUMENT_TAG_BYTES],
        declaredPlaintextBytes: 1,
        declaredChunkCount: 1,
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toMatch(/quota/i);
      // The one refusal here that leaves nothing behind: the parts ARE the bytes
      // this account cannot hold, so holding them for a day would bill the operator
      // for storage the accounting does not cover.
      expect(await Document.countDocuments({})).toBe(1);
      expect(await Document.findById(seeded.id).lean()).toBeNull();
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([]);
      // The refusal is decided under the exclusion lock now, and a throw from inside
      // that span must not leave it held for the rest of its five-minute TTL.
      expect(await JobLock.countDocuments({ jobName: vaultRotationLockName(user.id) })).toBe(0);
    });

    it('aborts the engine-side upload too when a MULTIPART transfer breaches the quota', async () => {
      // The other arm of the release: a multipart transfer holds parts rather than a
      // finished object, so leaving it would cost the operator the same bytes in a
      // form nothing in the database names once the staging TTL fires.
      const documentId = new mongoose.Types.ObjectId();
      await Document.create({
        _id: documentId,
        userId: user.id,
        objectKey: buildObjectKey(user.id, documentId.toHexString()),
        ...STAGED_DEK,
        ...FRAMING,
        encryptedMeta: 'meta',
        metaIv: 'iv',
        metaTag: 'tag',
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        chunkCount: 1,
        ciphertextBytes: QUOTA_BYTES + DOCUMENT_TAG_BYTES,
        plaintextBytes: QUOTA_BYTES,
      });
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(await Document.countDocuments({})).toBe(1);
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
      expect(storageRef.current!.storedKeys()).toEqual([]);
    });

    it('admits the transfer that exactly FILLS the quota', async () => {
      // The n side of the boundary, without which the refusal above could be a
      // comparison written one byte too tight and nothing would say so.
      const documentId = new mongoose.Types.ObjectId();
      await Document.create({
        _id: documentId,
        userId: user.id,
        objectKey: buildObjectKey(user.id, documentId.toHexString()),
        ...STAGED_DEK,
        ...FRAMING,
        encryptedMeta: 'meta',
        metaIv: 'iv',
        metaTag: 'tag',
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        chunkCount: 1,
        ciphertextBytes: QUOTA_BYTES - 1024 + DOCUMENT_TAG_BYTES,
        plaintextBytes: QUOTA_BYTES - 1024,
      });
      const seeded = await seedTransfer(user, { partSizes: [1024 + DOCUMENT_TAG_BYTES] });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(await Document.countDocuments({})).toBe(2);
    });

    describe('when several completions of DIFFERENT uploads race for the same room', () => {
      /** One committed document of `plaintextBytes`, standing in for everything already stored. */
      async function seedCommitted(plaintextBytes: number): Promise<void> {
        const documentId = new mongoose.Types.ObjectId();
        await Document.create({
          _id: documentId,
          userId: user.id,
          objectKey: buildObjectKey(user.id, documentId.toHexString()),
          ...STAGED_DEK,
          ...FRAMING,
          encryptedMeta: 'meta',
          metaIv: 'iv',
          metaTag: 'tag',
          chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          chunkCount: 1,
          ciphertextBytes: plaintextBytes + DOCUMENT_TAG_BYTES,
          plaintextBytes,
        });
      }

      /**
       * Runs `around` in place of every aggregation executed against `documents`,
       * handing it the real execution to call.
       *
       * At `Aggregate#exec` rather than `Model.aggregate`, because the handler chains
       * `.read(...)` onto the `Aggregate` the model returns, so a replacement for the
       * model method would have to be a whole `Aggregate`. `committedBytesFor` is the
       * only aggregation over `documents` a completion runs.
       */
      function interceptDocumentAggregates(
        around: (
          run: () => Promise<unknown>,
          aggregate: mongoose.Aggregate<unknown>,
        ) => Promise<unknown>,
      ): void {
        const realExec = mongoose.Aggregate.prototype.exec;
        vi.spyOn(mongoose.Aggregate.prototype, 'exec').mockImplementation(function (
          this: mongoose.Aggregate<unknown>,
        ) {
          const run = (): Promise<unknown> => realExec.call(this);
          return (this.model() === Document ? around(run, this) : run()) as never;
        });
      }

      /** A promise and the function that settles it. */
      function gate(): { opened: Promise<void>; open: () => void } {
        let open!: () => void;
        const opened = new Promise<void>((resolve) => {
          open = resolve;
        });
        return { opened, open };
      }

      it('reads the committed total while holding the exclusion lock, not before it', async () => {
        // The structural half: the quota's read and the insert it licenses are one
        // decision only if nothing that could insert can run between them, and every
        // completion takes this lock. A probe inside the read tries to take it.
        const seeded = await seedTransfer(user);
        let lockWasFreeAtQuotaRead: boolean | null = null;
        const readPreferences: unknown[] = [];
        interceptDocumentAggregates(async (run, aggregate) => {
          readPreferences.push(aggregate.options.readPreference);
          const stolen = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
          lockWasFreeAtQuotaRead = stolen !== null;
          if (stolen !== null) await releaseJobLock(vaultRotationLockName(user.id), stolen);
          return run();
        });

        const res = await complete(user, seeded.id);

        expect(res.status, JSON.stringify(res.body)).toBe(201);
        expect(lockWasFreeAtQuotaRead, 'the probe never ran').not.toBeNull();
        expect(
          lockWasFreeAtQuotaRead,
          'another completion could commit between the quota read and this insert',
        ).toBe(false);
        // …and from the primary, because the lock only serializes the read against the
        // previous winner's insert if the read can SEE that insert: a secondary a
        // `readPreference=secondaryPreferred` connection string hands out may not yet.
        expect(readPreferences).toEqual([{ mode: 'primary' }]);
      });

      it('commits exactly one of three the quota has room for, and keeps the other two retryable', async () => {
        // Room for ONE more 1 KiB document, and three finished 1 KiB transfers
        // completing at once. The first is parked INSIDE its insert until each of
        // the other two has either read the committed total or been answered;
        // any read taken while it is parked is held back until it has committed.
        // That is the interleaving that overshoots when the read happens outside
        // the lock: both late reads see a total that still fits, and both then
        // commit after the first. Serialised, neither gets as far as the read.
        await seedCommitted(QUOTA_BYTES - 1024);
        const [first, second, third] = [
          await seedTransfer(user),
          await seedTransfer(user),
          await seedTransfer(user),
        ] as [Seeded, Seeded, Seeded];

        const insertReached = gate();
        const firstSettled = gate();
        const othersProgressed = gate();
        let progressed = 0;
        const progress = (): void => {
          progressed += 1;
          if (progressed >= 2) othersProgressed.open();
        };
        let firstParked = false;

        const realCreate = Document.create.bind(Document);
        vi.spyOn(Document, 'create').mockImplementation((async (doc: never) => {
          if (!firstParked) {
            firstParked = true;
            insertReached.open();
            await othersProgressed.opened;
          }
          return realCreate(doc);
        }) as never);
        interceptDocumentAggregates(async (run) => {
          const result = await run();
          if (firstParked) {
            progress();
            await firstSettled.opened;
          }
          return result;
        });

        const firstResponse = complete(user, first.id).then((res) => {
          firstSettled.open();
          return res;
        });
        // Fails fast rather than timing out if the first completion is answered
        // without ever reaching its insert, which would leave nothing parked.
        await Promise.race([
          insertReached.opened,
          firstResponse.then((res) => {
            throw new Error(
              `the first completion was answered before its insert: ${String(res.status)} ${JSON.stringify(res.body)}`,
            );
          }),
        ]);
        const later = [second, third].map((seeded) =>
          complete(user, seeded.id).then((res) => {
            progress();
            return res;
          }),
        );
        const [won, ...lost] = await Promise.all([firstResponse, ...later]);

        expect(won!.status, JSON.stringify(won!.body)).toBe(201);
        for (const res of lost) {
          expect(res.status, JSON.stringify(res.body)).toBe(409);
          expect(String(res.body.message)).toMatch(/already in progress/i);
        }
        // Exactly one of the three became a document, and the account is exactly full.
        expect(
          await Document.countDocuments({ _id: { $in: [first.id, second.id, third.id] } }),
        ).toBe(1);
        expect(await Document.findById(first.id).lean()).not.toBeNull();
        // THE NEGATIVE: the two that lost kept every byte and every ledger entry, so
        // they were refused for contention and not quietly released.
        for (const seeded of [second, third]) {
          const row = await DocumentUpload.findById(seeded.id).lean();
          expect(row, 'a losing transfer lost its staging row').not.toBeNull();
          expect(row!.receivedBytes).toBe(seeded.partSizes[0]);
          expect(storageRef.current!.storedKeys()).toContain(seeded.objectKey);
        }
        expect(await JobLock.countDocuments({ jobName: vaultRotationLockName(user.id) })).toBe(0);

        // Retried once the winner has committed, a loser meets the quota honestly,
        // and that refusal, unlike contention, releases what it holds.
        vi.restoreAllMocks();
        const retried = await complete(user, second.id);
        expect(retried.status, JSON.stringify(retried.body)).toBe(400);
        expect(String(retried.body.message)).toMatch(/quota/i);
        expect(await DocumentUpload.findById(second.id).lean()).toBeNull();
        expect(storageRef.current!.storedKeys()).not.toContain(second.objectKey);
        expect(await Document.countDocuments({ userId: user.id })).toBe(2);
      });
    });

    it("does not charge another account's documents against this caller's quota", async () => {
      const stranger = await createTestUser({ email: 'documents-complete-whale@example.com' });
      const strangerDocId = new mongoose.Types.ObjectId();
      await Document.create({
        _id: strangerDocId,
        userId: stranger.id,
        objectKey: buildObjectKey(stranger.id, strangerDocId.toHexString()),
        ...STAGED_DEK,
        ...FRAMING,
        encryptedMeta: 'meta',
        metaIv: 'iv',
        metaTag: 'tag',
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        chunkCount: 1,
        ciphertextBytes: QUOTA_BYTES + DOCUMENT_TAG_BYTES,
        plaintextBytes: QUOTA_BYTES,
      });
      const seeded = await seedTransfer(user);

      expect((await complete(user, seeded.id)).status).toBe(201);
    });
  });

  // -------------------------------------------------------------------------
  // Repeats, races and a failed write
  // -------------------------------------------------------------------------

  describe('a completion that happens twice', () => {
    it('reports the first attempt’s document again, and creates no second row or audit entry', async () => {
      const seeded = await seedTransfer(user);
      const first = await complete(user, seeded.id);

      const second = await complete(user, seeded.id);

      // Indistinguishable on purpose: a client that retried after a timeout must
      // not be able to tell whether its first attempt landed.
      expect(second.status, JSON.stringify(second.body)).toBe(201);
      expect(second.body.data).toEqual(first.body.data);
      expect(await Document.countDocuments({})).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'document_create' })).toBe(1);
    });

    it('reports the committed row when the document appears AFTER its own existence check', async () => {
      // The unique `_id` is the last barrier, and it is the one that holds when the
      // lock does not — a lock whose TTL expired mid-completion, or a row the reaper
      // took. The engine read is the seam: the document is committed from inside it,
      // which is precisely the interleaving the lock is supposed to prevent and must
      // not be relied on to.
      const seeded = await seedTransfer(user);
      const engine = storageRef.current!;
      const realHeadObject = engine.headObject.bind(engine);
      vi.spyOn(engine, 'headObject').mockImplementation(async (key: string) => {
        await Document.create({
          _id: seeded.id,
          userId: user.id,
          objectKey: seeded.objectKey,
          ...STAGED_DEK,
          ...FRAMING,
          encryptedMeta: 'raced-meta',
          metaIv: 'raced-iv',
          metaTag: 'raced-tag',
          chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          chunkCount: 1,
          ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
          plaintextBytes: 1024,
        });
        return realHeadObject(key);
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      // The row that was already there, not this request's would-be one.
      expect((res.body.data as { encryptedMeta: string }).encryptedMeta).toBe('raced-meta');
      expect(await Document.countDocuments({})).toBe(1);
      // …and the object it names is still in the bucket. The failed insert must not
      // take the winner's bytes with it.
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'document_create' })).toBe(0);
    });

    it('serializes a concurrent pair: one row, one audit entry, and no 5xx', async () => {
      const seeded = await seedTransfer(user);

      const [left, right] = await Promise.all([
        complete(user, seeded.id),
        complete(user, seeded.id),
      ]);

      const statuses = [left.status, right.status];
      // At least one committed, and whatever the other did it was a conflict the
      // client can retry — never a 5xx, and never a silent second document.
      expect(statuses).toContain(201);
      for (const status of statuses) expect([201, 409]).toContain(status);
      expect(await Document.countDocuments({})).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'document_create' })).toBe(1);
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
      expect(await DocumentUpload.countDocuments({})).toBe(0);
    });

    it('answers 409 rather than 404 while another completion holds the lock and has not committed yet', async () => {
      const seeded = await seedTransfer(user);
      // The lock taken by somebody else, with no document row behind it yet — the
      // state a genuinely concurrent pair passes through.
      await JobLock.create({
        jobName: documentCompleteLockName(user.id, seeded.id),
        lockedBy: 'another-completion',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/already being completed/i);
      expect(await Document.countDocuments({})).toBe(0);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });

    it('reports the committed document when the lock is held but the row already exists', async () => {
      const seeded = await seedTransfer(user);
      expect((await complete(user, seeded.id)).status).toBe(201);
      // The winner released its lock; a stale holder appears afterwards. The honest
      // answer is the document, not a conflict — this is the interleaving that would
      // otherwise 404 a successfully completed upload.
      await JobLock.create({
        jobName: documentCompleteLockName(user.id, seeded.id),
        lockedBy: 'a-stale-completion',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(String((res.body.data as { _id: string })._id)).toBe(seeded.id);
      expect(await Document.countDocuments({})).toBe(1);
    });

    it('releases its lock even when the completion is refused', async () => {
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredChunkCount: 2,
      });

      expect((await complete(user, seeded.id)).status).toBe(400);

      // A lock left behind would block every retry of this transfer for its whole
      // TTL, turning one bad request into a two-minute outage for that upload.
      expect(
        await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
      ).toBe(0);
    });

    it('refuses when the ledger moved while the completion was doing its arithmetic', async () => {
      // `receivedBytes` is recomputed by the part handler as the sum of the ledger,
      // so a value that disagrees with the parts is exactly what a part landing
      // mid-completion looks like from here. The transfer SURVIVES: this refusal is
      // retryable, unlike the quota.
      const seeded = await seedTransfer(user, {
        partSizes: [1024 + DOCUMENT_TAG_BYTES],
        receivedBytes: 99,
      });

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(String(res.body.message)).toMatch(/changed while it was being completed/i);
      expect(await Document.countDocuments({})).toBe(0);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });

    it('leaves a MULTIPART transfer retryable when the engine fails to assemble it', async () => {
      // The failure this ordering exists for. Every part is present and verified;
      // one metadata call to the storage engine does not answer. Re-uploading the
      // file because of that is not a recovery, so the staging row, its ledger and
      // the engine-side parts must all survive and the identical request must
      // succeed on the second attempt.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });
      const engine = storageRef.current!;
      const realComplete = engine.completeMultipartUpload.bind(engine);
      const completeSpy = vi
        .spyOn(engine, 'completeMultipartUpload')
        .mockRejectedValueOnce(new Error('the storage engine timed out'));

      const failed = await complete(user, seeded.id);

      expect(failed.status, JSON.stringify(failed.body)).toBe(500);
      expect(await Document.countDocuments({})).toBe(0);
      // Nothing was thrown away: the row, the exact ledger it held, and the engine's
      // parts are all still there.
      const row = await DocumentUpload.findById(seeded.id).lean();
      expect(row).not.toBeNull();
      expect(row!.receivedBytes).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 4096 + DOCUMENT_TAG_BYTES);
      expect(row!.parts).toHaveLength(2);
      expect(await engine.listMultipartUploads()).toHaveLength(1);
      expect(
        await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
      ).toBe(0);

      completeSpy.mockImplementation(realComplete);
      const retried = await complete(user, seeded.id);

      expect(retried.status, JSON.stringify(retried.body)).toBe(201);
      expect((await Document.findById(seeded.id).lean())!.chunkCount).toBe(2);
      expect(await engine.listMultipartUploads()).toEqual([]);
    });

    it('refuses a foreign upload id the same way as an unknown one while its owner is completing it', async () => {
      // The completion lock is taken before ownership is read, so its NAME carries
      // the owner. Without that, a caller who knew somebody else's upload id would
      // see "already being completed" where an id belonging to nobody answers "not
      // found", and this codebase's standing rule is that those two must be
      // indistinguishable.
      const seeded = await seedTransfer(user);
      const intruder = await createTestUser({ email: 'documents-complete-intruder@example.com' });
      await JobLock.create({
        jobName: documentCompleteLockName(user.id, seeded.id),
        lockedBy: 'the-owner-completion',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const foreign = await complete(intruder, seeded.id);
      const unknown = await complete(intruder, '0123456789abcdef01234567');

      expect(foreign.status, JSON.stringify(foreign.body)).toBe(404);
      expect(foreign.status).toBe(unknown.status);
      expect(foreign.body.message).toEqual(unknown.body.message);
      // …and the owner's transfer is untouched by either attempt.
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
      expect(await Document.countDocuments({})).toBe(0);
    });

    it('deletes the stored object when the document row cannot be written', async () => {
      const seeded = await seedTransfer(user);
      vi.spyOn(Document, 'create').mockRejectedValueOnce(new Error('write concern failed'));

      const res = await complete(user, seeded.id);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(await Document.countDocuments({})).toBe(0);
      // Not left for the hourly collector: until it ran, the user would be charged
      // bucket space for a document they cannot see, let alone remove.
      expect(storageRef.current!.storedKeys()).toEqual([]);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'document_create' })).toBe(0);
      expect(
        await JobLock.countDocuments({ jobName: documentCompleteLockName(user.id, seeded.id) }),
      ).toBe(0);
    });
  });
});
