/**
 * The document store's five mutating endpoints: the metadata update and the four
 * transitions of the trash lifecycle.
 *
 * ## What is actually at stake here
 *
 * Two different things, and they need different kinds of assertion.
 *
 * `PUT /documents/:id` is guarded by an ALLOWLIST, and an allowlist is only ever
 * proved by what it refuses. Content is immutable after upload — a segment is
 * never rewritten, which is what guarantees a nonce is never reused under the
 * stream key — so the framing columns, the wrapped document key and the object
 * key must be unreachable from this route. Every case below that exercises the
 * update therefore snapshots the WHOLE row first and asserts, field by field,
 * that nothing outside the allowlist moved. A test that only checked the new
 * name landed would pass just as happily against a handler that spread the
 * request body into `$set`.
 *
 * The lifecycle routes are about ORDER. A document is a row beside an object,
 * and the row holds the only wrapped copy of the key that decrypts the object, so
 * "delete it" is two deletions that can be interrupted between. The design is:
 * mark the row `purgePending`, delete the object, delete the row — and the cases
 * here observe that order from INSIDE the object delete, which is the only place
 * the intermediate state exists. Reversing the last two steps would leave an
 * object charged to nobody with nothing left to name it, and no assertion about
 * the final state alone could tell the two implementations apart.
 *
 * ## The two seams
 *
 * MONGO IS REAL: ownership, the trash predicates, the `$unset` of `folderId` and
 * the bounded empty-trash set are all decided by a query, and a faked datastore
 * would test none of them. OBJECT STORAGE IS A DOUBLE
 * (`helpers/inMemoryStorage.ts`), because it is an external service in the same
 * class as SMTP, and the same contract runs that double and a real engine in the
 * conformance gate. Where a case needs a storage failure it makes the DOUBLE
 * fail; nothing here stubs a Mongoose method, so every "the row was not touched"
 * assertion is a statement about a real database.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { httpErrors } from '@hiprax/errors';
import {
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
import { AuditLog } from '../src/models/AuditLog.js';
import { Document } from '../src/models/Document.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, seedFolder, type TestUser } from './helpers.js';

/**
 * The two plaintext framing fields, at their exact byte counts.
 *
 * Real base64 of real lengths rather than placeholders, because the update cases
 * parse the response with `documentResponseSchema`, which pins both to
 * `DOCUMENT_STREAM_SALT_BYTES` and `DOCUMENT_NONCE_PREFIX_BYTES`.
 */
const FRAMING = {
  streamSalt: Buffer.alloc(32, 11).toString('base64'),
  noncePrefix: Buffer.alloc(7, 5).toString('base64'),
};

/** Opaque ciphertext columns. Nothing in this file decrypts anything. */
const SEALED = {
  encryptedDek: 'dek-ciphertext',
  dekIv: 'dek-iv',
  dekTag: 'dek-tag',
  encryptedMeta: 'meta-ciphertext',
  metaIv: 'meta-iv-original',
  metaTag: 'meta-tag-original',
};

/** A re-seal of the metadata blob, as the browser would send one after a rename. */
const RESEALED = {
  encryptedMeta: 'meta-ciphertext-renamed',
  metaIv: 'meta-iv-fresh',
  metaTag: 'meta-tag-fresh',
};

/** One segment of 1,024 plaintext bytes, which is what `seedDocument` records. */
const OBJECT_BODY = Buffer.alloc(1024 + DOCUMENT_TAG_BYTES, 0x3c);

/**
 * The columns that describe HOW the stored object is cut into sealed segments,
 * plus the wrapped key and the storage address.
 *
 * Named once, as a list, because "the update cannot reach any of these" is the
 * single most important property in this file and it is asserted from several
 * cases. A column added to the model and not added here would silently leave that
 * property half-checked, which is why the whole-row comparison below runs
 * ALONGSIDE this list rather than instead of it.
 */
const UNREACHABLE_COLUMNS = [
  'objectKey',
  'encryptedDek',
  'dekIv',
  'dekTag',
  'streamSalt',
  'noncePrefix',
  'chunkPlaintextBytes',
  'chunkCount',
  'ciphertextBytes',
  'plaintextBytes',
] as const;

interface SeedOptions {
  favorite?: boolean;
  folderId?: string;
  deletedAt?: Date;
  purgePending?: boolean;
  /** Omit and the bucket stays empty for this row. */
  body?: Buffer;
}

interface Seeded {
  id: string;
  objectKey: string;
}

/**
 * A committed document row, and optionally its object.
 *
 * Seeded directly rather than driven through the upload endpoints, which have
 * their own suites: routing every case here through init, a part and a completion
 * would make each failure ambiguous between four handlers. What is reproduced
 * faithfully is the STATE a completion leaves — a row whose three sizes satisfy
 * the identities `documentResponseSchema` re-checks, beside an object of exactly
 * `ciphertextBytes`.
 */
async function seedDocument(user: TestUser, options: SeedOptions = {}): Promise<Seeded> {
  const documentId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(user.id, documentId.toHexString());

  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey,
    ...SEALED,
    ...FRAMING,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: OBJECT_BODY.byteLength,
    plaintextBytes: OBJECT_BODY.byteLength - DOCUMENT_TAG_BYTES,
    ...(options.favorite === undefined ? {} : { favorite: options.favorite }),
    ...(options.folderId === undefined ? {} : { folderId: options.folderId }),
    ...(options.deletedAt === undefined ? {} : { deletedAt: options.deletedAt }),
    ...(options.purgePending === undefined ? {} : { purgePending: options.purgePending }),
  });

  if (options.body !== undefined) {
    await storageRef.current!.putObject(objectKey, options.body);
  }

  return { id: String(documentId), objectKey };
}

/**
 * The row exactly as it sits in the database, untyped.
 *
 * Untyped on purpose: the "nothing else moved" comparisons take the WHOLE
 * document, so they must see every field the model has — including one added
 * later, which a typed projection would quietly drop out of the comparison.
 */
async function rawRow(id: string): Promise<Record<string, unknown> | null> {
  return (await Document.findById(id).lean()) as Record<string, unknown> | null;
}

/** The same row with the named keys removed, for a diff that ignores what changed. */
function without(row: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const excluded = new Set(keys);
  return Object.fromEntries(Object.entries(row).filter(([key]) => !excluded.has(key)));
}

type StateChanging = 'put' | 'post' | 'delete';

/**
 * One authenticated state-changing request through the real app, with a real CSRF
 * pair.
 *
 * A real pair rather than a bypass: `doubleCsrfProtection` is mounted ahead of
 * every route in the application, so a helper that skipped it would be exercising
 * a middleware stack this server does not run.
 */
async function send(
  method: StateChanging,
  user: TestUser,
  path: string,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const pending = agent[method](path).set('Authorization', authHeader(user.accessToken));
  const pair = await getCsrf(agent);
  const authorized = pending.set('Cookie', pair.cookie).set('x-csrf-token', pair.token);
  return body === undefined ? authorized.send() : authorized.send(body);
}

/** One authenticated GET. No CSRF pair: a safe method needs none. */
const get = (user: TestUser, path: string): request.Test =>
  request(app).get(path).set('Authorization', authHeader(user.accessToken));

/** Every audit action this account has accumulated, sorted, with duplicates kept. */
async function auditActions(user: TestUser): Promise<string[]> {
  const rows = await AuditLog.find({ userId: user.id }).lean();
  return rows.map((row) => row.action).sort();
}

describe('the document mutation endpoints', () => {
  let owner: TestUser;
  let intruder: TestUser;

  beforeEach(async () => {
    storageRef.current = createInMemoryStorage();
    owner = await createTestUser({ email: 'document-mutator@example.com' });
    intruder = await createTestUser({ email: 'document-mutate-intruder@example.com' });
  });

  // -------------------------------------------------------------------------
  describe('PUT /documents/:id', () => {
    it('re-seals the metadata and leaves the wrapped key and every framing column byte-identical', async () => {
      const seeded = await seedDocument(owner, { body: OBJECT_BODY });
      const before = (await rawRow(seeded.id))!;

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, RESEALED);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.success).toBe(true);
      // The response is what the client parses before it derives any key from it.
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
      expect(res.body.data).toMatchObject(RESEALED);
      // Every read on this route file is `.lean()`, which does NOT run the
      // model's `toJSON` transform, so the projection is the control rather than
      // a second line of defense. `documentResponseSchema` runs in STRIP mode and
      // would accept all three of these, so they are named here explicitly.
      expect('objectKey' in res.body.data, 'the storage address was echoed back').toBe(false);
      expect('userId' in res.body.data).toBe(false);
      expect('__v' in res.body.data).toBe(false);

      const after = (await rawRow(seeded.id))!;
      expect(after.encryptedMeta).toBe(RESEALED.encryptedMeta);
      expect(after.metaTag).toBe(RESEALED.metaTag);

      // THE NEGATIVE THAT MATTERS. Named column by column first, so a failure
      // reads as "the handler moved `chunkCount`" rather than as an object diff.
      for (const column of UNREACHABLE_COLUMNS) {
        expect(after[column], `PUT changed ${column}`).toStrictEqual(before[column]);
      }
      // …and then the whole row, so a column added to the model later is covered
      // by this case without anyone remembering to add it above.
      expect(without(after, ['encryptedMeta', 'metaIv', 'metaTag', 'updatedAt'])).toStrictEqual(
        without(before, ['encryptedMeta', 'metaIv', 'metaTag', 'updatedAt']),
      );

      // The stored object is untouched: this endpoint never addresses storage.
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
      expect(storageRef.current!.readObject(seeded.objectKey)).toEqual(OBJECT_BODY);
    });

    it('stores a metaIv different from the one the row already held', async () => {
      // This is the endpoint at which a nonce could repeat: the metadata key is
      // deterministic in (DEK, streamSalt, documentId) and so fixed for the
      // document's life, while the blob is deliberately mutable. The browser's
      // `encryptMeta` generates its own IV and accepts none; what is pinned HERE
      // is that the write path carries a fresh one through to the row instead of
      // keeping the old value, which would republish a blob under a stale nonce.
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;
      expect(before.metaIv).toBe(SEALED.metaIv);

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, RESEALED);

      expect(res.status).toBe(200);
      const after = (await rawRow(seeded.id))!;
      expect(after.metaIv).toBe(RESEALED.metaIv);
      expect(after.metaIv).not.toBe(before.metaIv);
      expect(res.body.data.metaIv).toBe(RESEALED.metaIv);
    });

    it('ignores chunkCount, objectKey and encryptedDek smuggled in beside a legitimate field', async () => {
      // This exercises the PIPELINE, and two independent filters stand in it: the
      // wire schema strips an unknown key (`z.object()` does so by default, and
      // `packages/shared/tests/document-schema.test.ts` pins it directly), and the
      // handler's own allowlist drops it again. Measured: removing either one on
      // its own leaves this case green, and removing both turns it red — which is
      // what "defense in depth" is supposed to mean and is worth having observed
      // rather than assumed.
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;
      const foreignKey = buildObjectKey(intruder.id, new mongoose.Types.ObjectId().toHexString());

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, {
        // The one field that IS allowed, so the request is not refused outright
        // and the handler really runs its update. A body of forbidden fields
        // alone would be answered by the empty-update branch and would prove
        // nothing about the allowlist.
        favorite: true,
        chunkCount: 99,
        chunkPlaintextBytes: 17,
        ciphertextBytes: 1,
        plaintextBytes: 1,
        objectKey: foreignKey,
        encryptedDek: 'attacker-wrapped-key',
        dekIv: 'attacker-iv',
        dekTag: 'attacker-tag',
        streamSalt: Buffer.alloc(32, 0xff).toString('base64'),
        noncePrefix: Buffer.alloc(7, 0xff).toString('base64'),
        userId: intruder.id,
        deletedAt: new Date().toISOString(),
        purgePending: true,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data.favorite).toBe(true);

      const after = (await rawRow(seeded.id))!;
      expect(after.favorite).toBe(true);
      for (const column of UNREACHABLE_COLUMNS) {
        expect(after[column], `PUT accepted a smuggled ${column}`).toStrictEqual(before[column]);
      }
      // The three lifecycle and ownership columns the body also tried to set.
      expect(after.userId).toStrictEqual(before.userId);
      expect(after.deletedAt).toBeUndefined();
      expect(after.purgePending).toBeUndefined();
      expect(without(after, ['favorite', 'updatedAt'])).toStrictEqual(
        without(before, ['favorite', 'updatedAt']),
      );
    });

    it('moves a document into an owned folder', async () => {
      const folder = await seedFolder(owner.id, { encryptedName: 'target-folder' });
      const seeded = await seedDocument(owner);

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, {
        folderId: String(folder._id),
      });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data.folderId).toBe(String(folder._id));
      expect(String((await rawRow(seeded.id))!.folderId)).toBe(String(folder._id));
    });

    it('clears folderId by removing the key entirely, never by storing a null', async () => {
      // `documentResponseSchema` declares `folderId` as `.optional()` and NOT
      // `.nullable()`, exactly as `vaultItemResponseSchema` does. A handler that
      // wrote `$set: { folderId: null }` would make every un-filed document fail
      // the client's pre-decryption shape check — the row intact and unreadable.
      const folder = await seedFolder(owner.id, { encryptedName: 'source-folder' });
      const seeded = await seedDocument(owner, { folderId: String(folder._id) });

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, { folderId: null });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect('folderId' in res.body.data, 'folderId came back as a key').toBe(false);
      expect(res.body.data.folderId).toBeUndefined();
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);

      const after = (await rawRow(seeded.id))!;
      expect('folderId' in after, 'the column was set to null instead of unset').toBe(false);
    });

    it('refuses a folderId belonging to another account with 404 and changes nothing', async () => {
      const foreignFolder = await seedFolder(intruder.id, { encryptedName: 'intruder-folder' });
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, {
        folderId: String(foreignFolder._id),
        ...RESEALED,
      });

      // 404 rather than 403, so a caller cannot enumerate another account's
      // folders by watching which id earns which status.
      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.message).toBe('Target folder not found');
      // The refusal happens BEFORE the write, so the re-seal in the same body
      // did not land either.
      expect(await rawRow(seeded.id)).toStrictEqual(before);
      expect(await auditActions(owner)).not.toContain('document_update');
    });

    it('answers a body that names nothing writable with the row as it stands, and audits nothing', async () => {
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, {});

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data._id).toBe(seeded.id);
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
      // No write at all, `updatedAt` included: a no-op that bumped the timestamp
      // would reorder the caller's list for a request that changed nothing.
      expect(await rawRow(seeded.id)).toStrictEqual(before);
      expect(await auditActions(owner)).not.toContain('document_update');
    });

    it('refuses a partial metadata seal with 400 and changes nothing', async () => {
      // The three fields are ONE seal. Writing a new blob beside the old IV and
      // tag would store a row that can never be decrypted.
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, {
        encryptedMeta: 'half-a-seal',
      });

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(await rawRow(seeded.id)).toStrictEqual(before);
    });

    it('is NOT refused while a vault-key rotation is in progress', async () => {
      // The deliberate asymmetry with every other ciphertext-creating write in
      // this codebase. `assertVaultNotRotating` guards writes producing
      // ciphertext under the VAULT key; the metadata blob is sealed under an
      // HKDF subkey of the document's own DEK, which a rotation never touches —
      // it rewraps the DEK and leaves the blob alone. Refusing here would cost a
      // user an unexplained 409 on a rename and protect nothing.
      const seeded = await seedDocument(owner);
      await mongoose.connection
        .collection('users')
        .updateOne(
          { _id: new mongoose.Types.ObjectId(owner.id) },
          { $set: { rotationInProgress: true } },
        );

      const res = await send('put', owner, `/api/v1/documents/${seeded.id}`, RESEALED);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect((await rawRow(seeded.id))!.encryptedMeta).toBe(RESEALED.encryptedMeta);
    });

    it('writes one document_update audit row naming the fields and no ciphertext', async () => {
      const seeded = await seedDocument(owner);

      await send('put', owner, `/api/v1/documents/${seeded.id}`, { ...RESEALED, favorite: true });

      const rows = await AuditLog.find({ userId: owner.id, action: 'document_update' }).lean();
      expect(rows).toHaveLength(1);
      expect(rows[0]!.metadata).toMatchObject({
        documentId: seeded.id,
        fields: ['encryptedMeta', 'favorite', 'metaIv', 'metaTag'],
      });
      // An audit row carrying the sealed blob would put a copy of it in a second
      // collection under a different retention.
      expect(JSON.stringify(rows[0]!.metadata)).not.toContain(RESEALED.encryptedMeta);
    });

    it('refuses another account’s document with 404 and leaves it untouched', async () => {
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;

      const res = await send('put', intruder, `/api/v1/documents/${seeded.id}`, RESEALED);

      expect(res.status).toBe(404);
      expect(await rawRow(seeded.id)).toStrictEqual(before);
    });

    it('answers 404 for a body that names nothing writable on a document that is gone', async () => {
      // The no-op branch is a READ, so it has to reach the same 404 the write
      // branch does. Without its own existence check, a `{}` body would answer 200
      // with an empty envelope for a document that never existed — the one shape a
      // client cannot tell from success.
      const absent = new mongoose.Types.ObjectId().toHexString();

      const res = await send('put', owner, `/api/v1/documents/${absent}`, {});

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.success).toBe(false);
      expect(res.body.data).toBeUndefined();
      expect(await auditActions(owner)).not.toContain('document_update');
    });

    it('answers a foreign id exactly as it answers an absent one, for a no-op body too', async () => {
      // The scoping is on the query, so the no-op read cannot become a way to ask
      // whether another account holds a given id.
      const seeded = await seedDocument(owner);
      const absent = new mongoose.Types.ObjectId().toHexString();

      const foreign = await send('put', intruder, `/api/v1/documents/${seeded.id}`, {});
      const unknown = await send('put', intruder, `/api/v1/documents/${absent}`, {});

      expect(foreign.status).toBe(404);
      expect(foreign.status).toBe(unknown.status);
      expect(foreign.body.message).toEqual(unknown.body.message);
    });
  });

  // -------------------------------------------------------------------------
  describe('DELETE /documents/:id', () => {
    it('stamps deletedAt, leaves the object in place and leaves the quota unchanged', async () => {
      const seeded = await seedDocument(owner, { body: OBJECT_BODY });
      const usageBefore = await get(owner, '/api/v1/documents/usage');

      const res = await send('delete', owner, `/api/v1/documents/${seeded.id}`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.message).toBe('Document moved to trash');

      const after = (await rawRow(seeded.id))!;
      expect(after.deletedAt).toBeInstanceOf(Date);
      // A soft delete frees nothing: the object is still in the bucket, so it
      // still costs the operator storage and still counts against the quota. The
      // UI says so, and a user who saw space returned here would be misled.
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
      expect(storageRef.current!.readObject(seeded.objectKey)).toEqual(OBJECT_BODY);

      const usageAfter = await get(owner, '/api/v1/documents/usage');
      expect(usageAfter.body.data).toStrictEqual(usageBefore.body.data);
      expect(usageAfter.body.data.usedBytes).toBe(OBJECT_BODY.byteLength - DOCUMENT_TAG_BYTES);
      expect(usageAfter.body.data.documentCount).toBe(1);
    });

    it('moves the document out of the active list and into the trash list', async () => {
      const seeded = await seedDocument(owner);

      await send('delete', owner, `/api/v1/documents/${seeded.id}`);

      const active = await get(owner, '/api/v1/documents');
      const trash = await get(owner, '/api/v1/documents/trash');
      expect(active.body.data.map((row: { _id: string }) => row._id)).toEqual([]);
      expect(trash.body.data.map((row: { _id: string }) => row._id)).toEqual([seeded.id]);
    });

    it('is idempotent for a caller retrying, and re-stamps deletedAt', async () => {
      // Documented behaviour rather than an accident: the query is scoped by
      // `{_id, userId}` with no `deletedAt` predicate, exactly as the vault
      // item's soft delete is, so a client whose first request timed out gets a
      // 200 instead of a confusing 404. The cost is that the auto-purge clock
      // restarts, which delays an automatic purge and can lose nothing.
      const first = new Date('2026-01-01T00:00:00.000Z');
      const seeded = await seedDocument(owner, { deletedAt: first });

      const res = await send('delete', owner, `/api/v1/documents/${seeded.id}`);

      expect(res.status).toBe(200);
      const after = (await rawRow(seeded.id))!;
      expect((after.deletedAt as Date).getTime()).toBeGreaterThan(first.getTime());
    });

    it('writes one document_delete audit row and no purge action', async () => {
      const seeded = await seedDocument(owner, { body: OBJECT_BODY });

      await send('delete', owner, `/api/v1/documents/${seeded.id}`);

      expect(await auditActions(owner)).toEqual(['document_delete']);
    });

    it('answers 404 for an id that belongs to nobody', async () => {
      const res = await send(
        'delete',
        owner,
        `/api/v1/documents/${new mongoose.Types.ObjectId().toHexString()}`,
      );

      expect(res.status).toBe(404);
      expect(res.body.message).toBe('Document not found');
    });
  });

  // -------------------------------------------------------------------------
  describe('POST /documents/:id/restore', () => {
    it('clears deletedAt by removing the key and returns the restored row', async () => {
      const seeded = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });

      const res = await send('post', owner, `/api/v1/documents/${seeded.id}/restore`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.message).toBe('Document restored from trash');
      expect('deletedAt' in res.body.data).toBe(false);
      expect(documentResponseSchema.safeParse(res.body.data).success).toBe(true);
      expect('objectKey' in res.body.data, 'the storage address was echoed back').toBe(false);
      expect('userId' in res.body.data).toBe(false);

      const after = (await rawRow(seeded.id))!;
      // `$unset`, not `$set: null`. The sparse index over `deletedAt` is only
      // small while the field is genuinely ABSENT on the active majority; a
      // restore that wrote a null would index every row ever trashed.
      expect('deletedAt' in after, 'deletedAt was nulled rather than removed').toBe(false);

      const active = await get(owner, '/api/v1/documents');
      expect(active.body.data.map((row: { _id: string }) => row._id)).toEqual([seeded.id]);
      expect(await auditActions(owner)).toEqual(['document_restore']);
    });

    it('refuses a document that is not in the trash', async () => {
      const seeded = await seedDocument(owner);
      const before = (await rawRow(seeded.id))!;

      const res = await send('post', owner, `/api/v1/documents/${seeded.id}/restore`);

      expect(res.status).toBe(404);
      expect(await rawRow(seeded.id)).toStrictEqual(before);
      expect(await auditActions(owner)).toEqual([]);
    });

    it('refuses a row whose permanent deletion has already begun', async () => {
      // A `purgePending` row has had its marker raised immediately before the
      // object delete and the marker comes down only when the row itself is
      // deleted, so its object is gone or going and the hourly collector will
      // remove the row. Restoring it would put a document back in the ACTIVE
      // list that 404s on every segment and then disappears with no explanation.
      const seeded = await seedDocument(owner, { deletedAt: new Date(), purgePending: true });
      const before = (await rawRow(seeded.id))!;

      const res = await send('post', owner, `/api/v1/documents/${seeded.id}/restore`);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.message).toBe('Document not found, not in trash, or already being deleted');
      expect(await rawRow(seeded.id)).toStrictEqual(before);
      expect(await auditActions(owner)).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  describe('DELETE /documents/:id/permanent', () => {
    it('marks the row, deletes the object, then deletes the row — in that order', async () => {
      const seeded = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const storage = storageRef.current!;

      // The intermediate state exists only for the duration of the object
      // delete, so it is observed from INSIDE it. Asserting the final state
      // alone could not tell this implementation from one that deleted the row
      // first and left the object orphaned.
      const seen: { rowPresent?: boolean; purgePending?: unknown; objectPresent?: boolean } = {};
      const realDelete = storage.deleteObject.bind(storage);
      const deleteSpy = vi
        .spyOn(storage, 'deleteObject')
        .mockImplementation(async (key: string) => {
          const row = await rawRow(seeded.id);
          seen.rowPresent = row !== null;
          seen.purgePending = row?.purgePending;
          seen.objectPresent = storage.readObject(key) !== undefined;
          await realDelete(key);
        });

      const res = await send('delete', owner, `/api/v1/documents/${seeded.id}/permanent`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.message).toBe('Document permanently deleted');

      // The marker was already committed when the object delete ran, and the row
      // was still there — which is what the collector needs in order to finish a
      // purge interrupted at exactly this point.
      expect(deleteSpy).toHaveBeenCalledTimes(1);
      expect(deleteSpy).toHaveBeenCalledWith(seeded.objectKey);
      expect(seen.rowPresent).toBe(true);
      expect(seen.purgePending).toBe(true);
      expect(seen.objectPresent).toBe(true);

      // …and afterwards both are gone.
      expect(await rawRow(seeded.id)).toBeNull();
      expect(storage.storedKeys()).toEqual([]);
      expect(await auditActions(owner)).toEqual(['document_purge']);
    });

    it('returns the storage the document was holding, so the quota falls', async () => {
      const kept = await seedDocument(owner, { body: OBJECT_BODY });
      const purged = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const before = await get(owner, '/api/v1/documents/usage');
      expect(before.body.data.documentCount).toBe(2);

      await send('delete', owner, `/api/v1/documents/${purged.id}/permanent`);

      const after = await get(owner, '/api/v1/documents/usage');
      expect(after.body.data.documentCount).toBe(1);
      expect(after.body.data.usedBytes).toBe(OBJECT_BODY.byteLength - DOCUMENT_TAG_BYTES);
      expect(storageRef.current!.storedKeys()).toEqual([kept.objectKey]);
    });

    it('refuses a document that is not in the trash, and touches neither the row nor the object', async () => {
      // A permanent delete is the second, deliberate half of a two-step
      // destruction: it must not be reachable in one request from the active
      // list, or a mis-clicked button destroys a file with no undo.
      const seeded = await seedDocument(owner, { body: OBJECT_BODY });
      const before = (await rawRow(seeded.id))!;

      const res = await send('delete', owner, `/api/v1/documents/${seeded.id}/permanent`);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.message).toBe('Document not found in trash');
      expect(await rawRow(seeded.id)).toStrictEqual(before);
      expect(storageRef.current!.readObject(seeded.objectKey)).toEqual(OBJECT_BODY);
      expect(await auditActions(owner)).toEqual([]);
    });

    it('leaves purgePending set for the collector when the object cannot be deleted', async () => {
      // The failure the marker exists for. The row is marked BEFORE the delete
      // is attempted, so a storage outage leaves a row the hourly collector
      // finds and finishes rather than a document the user believes is gone. The
      // caller is told, because reporting success for work that has not happened
      // is the one outcome that would be wrong here.
      const seeded = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const storage = storageRef.current!;
      vi.spyOn(storage, 'deleteObject').mockRejectedValue(
        httpErrors.serviceUnavailable('Object storage is unavailable'),
      );

      const res = await send('delete', owner, `/api/v1/documents/${seeded.id}/permanent`);

      expect(res.status).toBe(503);
      const after = (await rawRow(seeded.id))!;
      expect(after.purgePending).toBe(true);
      expect(after.deletedAt).toBeInstanceOf(Date);
      expect(storage.readObject(seeded.objectKey)).toEqual(OBJECT_BODY);
      // No success audit row for a purge that did not happen.
      expect(await auditActions(owner)).toEqual([]);
    });

    it('answers 404 for another account’s trashed document and deletes nothing', async () => {
      const seeded = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });

      const res = await send('delete', intruder, `/api/v1/documents/${seeded.id}/permanent`);

      expect(res.status).toBe(404);
      expect(await rawRow(seeded.id)).not.toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });
  });

  // -------------------------------------------------------------------------
  describe('DELETE /documents/trash/empty', () => {
    it('destroys every trashed document and its object, and touches nothing else', async () => {
      const active = await seedDocument(owner, { body: OBJECT_BODY });
      const trashedA = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const trashedB = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const foreignTrashed = await seedDocument(intruder, {
        deletedAt: new Date(),
        body: OBJECT_BODY,
      });

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data).toStrictEqual({ deletedCount: 2, failedCount: 0 });
      expect(res.body.message).toBe('2 document(s) permanently deleted');

      expect(await rawRow(trashedA.id)).toBeNull();
      expect(await rawRow(trashedB.id)).toBeNull();
      // The active document and the other account's trash are outside the set.
      expect(await rawRow(active.id)).not.toBeNull();
      expect(await rawRow(foreignTrashed.id)).not.toBeNull();
      // Every object follows its row, and only its row. A `deleteMany` over the
      // rows — which is what the vault item version is, correctly, because an
      // item is only a row — would leave four objects here instead of two.
      expect(storageRef.current!.storedKeys()).toEqual(
        [active.objectKey, foreignTrashed.objectKey].sort(),
      );
      expect(await auditActions(owner)).toEqual(['document_purge']);
    });

    it('is bounded to the documents that were in the trash when it started', async () => {
      // The same bound the vault item version carries: a document trashed by
      // another tab WHILE the request runs is outside the set and survives, so
      // "empty the trash" means the trash the user was looking at.
      const old = await seedDocument(owner, {
        deletedAt: new Date(Date.now() - 60_000),
        body: OBJECT_BODY,
      });
      const future = await seedDocument(owner, {
        deletedAt: new Date(Date.now() + 60_000),
        body: OBJECT_BODY,
      });

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status).toBe(200);
      expect(res.body.data.deletedCount).toBe(1);
      expect(await rawRow(old.id)).toBeNull();
      expect(
        await rawRow(future.id),
        'a row trashed after the request started was swept',
      ).not.toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([future.objectKey]);
    });

    it('counts a row whose object cannot be deleted, finishes the rest, and leaves its marker', async () => {
      // One unreachable object must not abandon the rows after it. The failing
      // row keeps its `purgePending` marker, so the collector finishes exactly
      // that row, which is why this answers 200 rather than an error: nothing is
      // lost, the work is deferred, and the marker is what defers it.
      //
      // This case also proves the walk TERMINATES. A failing row stays in the
      // trashed set, so an implementation that re-read the same page instead of
      // paging forward on `_id` would loop here until the test timed out.
      const failing = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const succeeding = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const storage = storageRef.current!;
      const realDelete = storage.deleteObject.bind(storage);
      vi.spyOn(storage, 'deleteObject').mockImplementation(async (key: string) => {
        if (key === failing.objectKey) {
          throw httpErrors.serviceUnavailable('Object storage is unavailable');
        }
        await realDelete(key);
      });

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data).toStrictEqual({ deletedCount: 1, failedCount: 1 });

      const survivor = (await rawRow(failing.id))!;
      expect(survivor.purgePending).toBe(true);
      expect(await rawRow(succeeding.id)).toBeNull();
      expect(storage.storedKeys()).toEqual([failing.objectKey]);

      const audited = await AuditLog.findOne({ userId: owner.id, action: 'document_purge' }).lean();
      expect(audited!.metadata).toMatchObject({
        action: 'empty_trash',
        deletedCount: 1,
        failedCount: 1,
      });
    });

    it('terminates when the LAST row of a page fails, which is the case that can loop', async () => {
      // The narrow case the `_id` cursor exists for, and the one the case above
      // does NOT cover: there, a later row succeeded and carried the cursor past
      // the failure, so the walk finished even with the cursor advanced only on
      // success. Here the failing row is the ONLY row, so nothing else can move
      // the cursor — and a failing row STAYS in the trashed set by design,
      // because leaving it to the collector is the whole point. An
      // implementation that advanced the cursor only after a successful purge
      // would re-read this row for ever and this case would hang.
      const onlyRow = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const storage = storageRef.current!;
      const deleteSpy = vi
        .spyOn(storage, 'deleteObject')
        .mockRejectedValue(httpErrors.serviceUnavailable('Object storage is unavailable'));

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data).toStrictEqual({ deletedCount: 0, failedCount: 1 });
      // Attempted exactly ONCE. A count above one is the loop re-reading a row it
      // was supposed to leave behind, which is the failure this case is named for
      // and which a status assertion alone would miss on a page that eventually
      // gave up.
      expect(deleteSpy).toHaveBeenCalledTimes(1);
      expect((await rawRow(onlyRow.id))!.purgePending).toBe(true);
      expect(storage.storedKeys()).toEqual([onlyRow.objectKey]);
    });

    it('leaves a document alone when another tab restores it mid-walk', async () => {
      // The page is read before the walk begins, so a document can be restored
      // between the read and its turn — `POST /documents/:id/restore` succeeds
      // while nothing has marked it. The marker write is therefore a CLAIM that
      // re-states the trash predicate: it refuses a row that is live again, and
      // once it lands a restore can no longer win, because the restore requires
      // `purgePending: null`.
      //
      // Without that, this request would delete the object of a document the user
      // had just recovered and then the row holding its only wrapped key. There is
      // no recovery from that and no error anywhere to notice it by: the response
      // would report a successful purge.
      const restored = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });
      const alsoTrashed = await seedDocument(owner, { deletedAt: new Date(), body: OBJECT_BODY });

      // The concurrent restore lands inside the very call that would otherwise
      // mark the row, so the REAL claim filter is what has to refuse it.
      const realUpdateOne = Document.updateOne.bind(Document);
      vi.spyOn(Document, 'updateOne').mockImplementationOnce(((...args: unknown[]) =>
        realUpdateOne({ _id: restored.id }, { $unset: { deletedAt: 1 } }).then(() =>
          (realUpdateOne as (...inner: unknown[]) => unknown)(...args),
        )) as never);

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      // Skipped, not purged and not failed — there was nothing left to destroy.
      expect(res.body.data).toStrictEqual({ deletedCount: 1, failedCount: 0 });

      const survivor = (await rawRow(restored.id))!;
      expect(
        survivor,
        'the restored document must survive the empty-trash walk',
      ).not.toBeUndefined();
      expect(survivor.deletedAt, 'and it must still be out of the trash').toBeUndefined();
      expect(survivor.purgePending, 'the claim was refused, so no marker').toBeUndefined();
      // The negative that matters most: its bytes are untouched, while the row
      // that really was trashed went as asked.
      expect(storageRef.current!.storedKeys()).toEqual([restored.objectKey]);
      expect(await rawRow(alsoTrashed.id)).toBeNull();
    });

    it('succeeds on an empty trash without touching storage', async () => {
      const active = await seedDocument(owner, { body: OBJECT_BODY });
      const deleteSpy = vi.spyOn(storageRef.current!, 'deleteObject');

      const res = await send('delete', owner, '/api/v1/documents/trash/empty');

      expect(res.status).toBe(200);
      expect(res.body.data).toStrictEqual({ deletedCount: 0, failedCount: 0 });
      expect(deleteSpy).not.toHaveBeenCalled();
      expect(await rawRow(active.id)).not.toBeNull();
    });
  });
});
