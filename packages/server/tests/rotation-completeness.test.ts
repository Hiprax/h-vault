/**
 * The rotation ENUMERATION WINDOW, and the check that closes it.
 *
 * `POST /vault/items/bulk-reencrypt` replaces the vault key and every row's
 * ciphertext in one request, and the set of rows it rewrites is chosen by the
 * CLIENT: the browser lists the account, re-encrypts what it listed, and posts
 * the result. The write fence (`rotationInProgress`) goes up when the request
 * ARRIVES, so it cannot see anything created between the client's enumeration
 * and that moment. A row created in that window is left sealed under the
 * superseded vault key while the key itself is replaced, which makes it
 * permanently unreadable — silently, with a 200 response.
 *
 * The fix is a completeness check inside the write: the number of DISTINCT ids
 * supplied must equal the account's current row count, for items, for folders
 * and for documents alike. It is deliberately a comparison of DISTINCT ids
 * rather than of array lengths, because `bulkReEncryptSchema` places no
 * uniqueness constraint on any of the three arrays: a payload of `[A, A, B]`
 * against an account holding `{A, B, C}` satisfies both the pre-existing
 * missing-id abort (every supplied id exists and is owned) and a naive length
 * comparison, replaces the vault key, and leaves C unreadable. A paginated
 * enumeration that double-reads a page under a concurrent write produces
 * exactly that payload, so this is a buggy-client path before it is a hostile
 * one.
 *
 * Both branches of the handler are exercised. The default harness is a
 * STANDALONE mongod, so the top block runs the sequential fallback; the bottom
 * block borrows a real replica set so `supportsTransactions()` is true and the
 * transactional branch runs. A check present in only one of the two is the
 * defect wearing a different hat.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import type { Request, Response } from 'express';
import { bulkReEncrypt } from '../src/controllers/vaultController.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { Document } from '../src/models/Document.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createTestUser, authHeader, getCsrf, seedItem, seedFolder } from './helpers.js';
import type { TestUser } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';

const NEW_KEY = {
  newEncryptedVaultKey: 'rotated-vault-key',
  newVaultKeyIv: 'rotated-vault-key-iv',
  newVaultKeyTag: 'rotated-vault-key-tag',
};

/** The vault key `createTestUser` seeds, i.e. the value a refused rotation must leave in place. */
const ORIGINAL_KEY = 'test-encrypted-vault-key';

/** The ciphertext `sampleVaultItem` seeds, i.e. what an unrotated item still carries. */
const ORIGINAL_ITEM_NAME = 'test-encrypted-name';
const ORIGINAL_FOLDER_NAME = 'test-encrypted-folder-name';

interface RotationItem {
  id: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
}

interface RotationDocument {
  id: string;
  encryptedDek: string;
  dekIv: string;
  dekTag: string;
}

interface RotationFolder {
  id: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
}

/** What the browser would post for one item it enumerated and re-encrypted. */
function rotatedItem(id: string): RotationItem {
  return {
    id,
    encryptedName: `rotated-name-${id}`,
    nameIv: 'rotated-name-iv',
    nameTag: 'rotated-name-tag',
    encryptedData: `rotated-data-${id}`,
    dataIv: 'rotated-data-iv',
    dataTag: 'rotated-data-tag',
  };
}

/** What the browser would post for one folder it enumerated and re-encrypted. */
function rotatedFolder(id: string): RotationFolder {
  return {
    id,
    encryptedName: `rotated-folder-${id}`,
    nameIv: 'rotated-folder-iv',
    nameTag: 'rotated-folder-tag',
  };
}

/** The DEK wrap a seeded document starts with, i.e. what a refused rotation leaves. */
const ORIGINAL_DEK = 'dek-ciphertext-original';

/** A committed `documents` row. Only the wrap and the lifecycle flag matter here. */
async function seedDocument(user: TestUser, deletedAt?: Date): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    encryptedDek: ORIGINAL_DEK,
    dekIv: 'dek-iv-original',
    dekTag: 'dek-tag-original',
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    streamSalt: Buffer.alloc(32, 11).toString('base64'),
    noncePrefix: Buffer.alloc(7, 5).toString('base64'),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
    plaintextBytes: 1024,
    ...(deletedAt === undefined ? {} : { deletedAt }),
  });
  return String(documentId);
}

/** What the browser would post for one document whose DEK it rewrapped. */
function rewrappedDocument(id: string): RotationDocument {
  return {
    id,
    encryptedDek: `dek-ciphertext-new-${id}`,
    dekIv: 'dek-iv-new',
    dekTag: 'dek-tag-new',
  };
}

async function rotate(user: TestUser, body: Record<string, unknown>): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/vault/items/bulk-reencrypt')
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', cookie)
    .set('x-csrf-token', token)
    .send({ authHash: user.rawPassword, ...NEW_KEY, ...body });
}

/** Reads the columns a refused rotation must have left untouched. */
async function vaultKeyOf(userId: string): Promise<string | undefined> {
  const user = await User.findById(userId).lean();
  return user?.encryptedVaultKey;
}

/**
 * The paginated ENUMERATION the rotation payload is built from.
 *
 * The completeness check above refuses a payload that does not name every row, and
 * `bulkReEncryptSchema` refuses one that names a row twice. Both are backstops for
 * the same client-side fault: a `skip`/`limit` walk over a sort with no total order
 * re-reads a row on one page and drops another, so the payload reaches the right
 * length while missing a row. This block pins the ORDER those backstops exist to
 * make unnecessary — and it is not a claim that the walk is now safe under
 * concurrent writes, which only keyset pagination would give.
 */
describe('Listing a vault page by page', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  /** Every `_id` the paginated list yields, walked to the end at `limit` per page. */
  async function walk(path: string, limit: number): Promise<string[]> {
    const seen: string[] = [];
    let page = 1;
    let totalPages = 1;
    do {
      const res = await request(app)
        .get(`${path}?page=${String(page)}&limit=${String(limit)}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);
      seen.push(...(res.body.data as { _id: string }[]).map((row) => row._id));
      totalPages = res.body.pagination.totalPages as number;
      page += 1;
    } while (page <= totalPages);
    return seen;
  }

  it('yields every item exactly once when the whole vault shares one updatedAt', async () => {
    // A single `updateMany` stamps one timestamp across every row, which is what
    // an import's `insertMany` and a 100-row bulk move both do. With the default
    // sort (`updatedAt`) and no tiebreak the order within that tie is unspecified,
    // so a `skip`-based walk can return one row on two pages and never return
    // another — the exact `[A, A, B]` payload the rotation's duplicate-id refusal
    // and its coverage check exist to catch, arriving from an ordinary client
    // rather than a hostile one.
    const ids: string[] = [];
    for (let index = 0; index < 12; index += 1) {
      const item = await seedItem(user.id, { encryptedName: `tied-${String(index)}` });
      ids.push(String(item._id));
    }
    await VaultItem.updateMany({ userId: user.id }, { $set: { updatedAt: new Date() } });

    const seen = await walk('/api/v1/vault/items', 3);

    expect(seen).toHaveLength(ids.length);
    expect(new Set(seen).size).toBe(ids.length);
    // The ORDER, which is what makes this case able to fail. The default sort is
    // `updatedAt` DESCENDING, so a total order puts the newest `_id` first;
    // without a tiebreak the tied rows come back in the index's own natural order,
    // which is `_id` ASCENDING — measured, and the exact opposite. So this
    // assertion is red the moment the tiebreak is removed, rather than merely
    // describing what a walk happened to do.
    expect(seen).toEqual([...ids].reverse());
  });

  it('yields every trashed item exactly once when the whole trash shares one deletedAt', async () => {
    // The trash list sorts by `deletedAt`, and "empty the trash" or a bulk delete
    // stamps one instant across every row it touches, so the tie is the NORMAL
    // case here rather than an unlucky one.
    const ids: string[] = [];
    for (let index = 0; index < 12; index += 1) {
      const item = await seedItem(user.id, { encryptedName: `trashed-${String(index)}` });
      ids.push(String(item._id));
    }
    await VaultItem.updateMany({ userId: user.id }, { $set: { deletedAt: new Date() } });

    const seen = await walk('/api/v1/vault/items/trash', 3);

    expect(seen).toHaveLength(ids.length);
    expect(new Set(seen).size).toBe(ids.length);
    expect(seen).toEqual([...ids].reverse());
  });
});

describe('Rotation completeness — sequential (standalone) branch', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('runs against a topology where transactions are NOT available', () => {
    // The sequential branch is reached ONLY when `supportsTransactions` is false,
    // so without this the block would silently assert the TRANSACTIONAL branch the
    // day the harness handed this file a replica set — and every case below would
    // still pass, against code it was never written for. A standalone `it` rather
    // than a hook: a failing hook is reported as harness breakage and can rename or
    // suppress the tests around it, while this fails as one line that says what
    // broke. Its replica-set counterpart asserts the mirror image.
    expect(supportsTransactions(mongoose.connection)).toBe(false);
  });

  it('refuses a rotation whose payload omits an ITEM created after the client enumerated, and leaves the old vault key in place', async () => {
    // The client enumerates the account: one item exists, and it is re-encrypted.
    const enumerated = await seedItem(user.id);
    const payload = [rotatedItem(String(enumerated._id))];

    // A second session creates another item while the request is in flight. The
    // write fence cannot see it: the fence only goes up when the request lands.
    const missed = await seedItem(user.id, { encryptedName: 'created-after-enumeration' });

    const res = await rotate(user, { items: payload, folders: [] });

    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);
    expect(String(res.body.message)).toMatch(/retry/i);

    // The negative that matters: the vault key was NOT replaced, so the row the
    // payload missed is still readable with the key the user already holds.
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    // And nothing was half-written: the enumerated item still carries its
    // original ciphertext, sealed under the same (unchanged) key.
    const enumeratedRow = await VaultItem.findById(enumerated._id).lean();
    expect(enumeratedRow).not.toBeNull();
    expect(enumeratedRow!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
    const missedRow = await VaultItem.findById(missed._id).lean();
    expect(missedRow).not.toBeNull();
    expect(missedRow!.encryptedName).toBe('created-after-enumeration');

    // The fence came back down, so the account is usable and the rotation retryable.
    const after = await User.findById(user.id).lean();
    expect(after!.rotationInProgress).toBe(false);
  });

  it('refuses a rotation whose payload omits a FOLDER created after the client enumerated', async () => {
    const item = await seedItem(user.id);
    const enumerated = await seedFolder(user.id);
    const missed = await seedFolder(user.id, { encryptedName: 'folder-after-enumeration' });

    const res = await rotate(user, {
      items: [rotatedItem(String(item._id))],
      folders: [rotatedFolder(String(enumerated._id))],
    });

    expect(res.status).toBe(409);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    const enumeratedRow = await Folder.findById(enumerated._id).lean();
    expect(enumeratedRow!.encryptedName).toBe(ORIGINAL_FOLDER_NAME);
    const missedRow = await Folder.findById(missed._id).lean();
    expect(missedRow!.encryptedName).toBe('folder-after-enumeration');
    // The item leg must not have been written either — a rotation that rewrites
    // items and then refuses leaves ciphertext the old key cannot open.
    const itemRow = await VaultItem.findById(item._id).lean();
    expect(itemRow!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
  });

  it('rejects a payload that repeats one id to reach the right length, and changes nothing', async () => {
    // Three items; the payload names only two of them but repeats one, so its
    // LENGTH matches the account's row count while its COVERAGE does not.
    const a = await seedItem(user.id, { encryptedName: 'item-a' });
    const b = await seedItem(user.id, { encryptedName: 'item-b' });
    const c = await seedItem(user.id, { encryptedName: 'item-c' });

    const res = await rotate(user, {
      items: [rotatedItem(String(a._id)), rotatedItem(String(a._id)), rotatedItem(String(b._id))],
      folders: [],
    });

    // 400, and exactly 400: `validate(bulkReEncryptSchema, 'body')` runs before the
    // handler, so the duplicate-id `.superRefine` is what refuses this payload.
    // `not.toBe(200)` would have accepted a 500 as a pass. The handler's OWN
    // distinct-id check — the one that would matter if this schema rule were ever
    // relaxed — is exercised directly further down, because nothing that goes
    // through the route can reach it.
    expect(res.status).toBe(400);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    for (const row of [a, b, c]) {
      const stored = await VaultItem.findById(row._id).lean();
      expect(stored!.encryptedName).toBe(row.encryptedName);
    }
  });

  it('reports a FOLDER the write no longer matches, and rolls the rest back', async () => {
    // A folder deleted BETWEEN the pre-write snapshot and the write itself. The
    // missing-id abort cannot close that window — it reads the snapshot, and the
    // row can go afterwards — so the loop has to answer for it, and the answer is
    // the same as any other failed leg: report it, roll back what was already
    // written, and leave the vault key alone. The documents leg has carried this
    // case since it was written; the folders leg it was modelled on did not, so
    // the arm that reports a vanished folder had never run.
    const first = await seedFolder(user.id, { encryptedName: 'folder-a' });
    const second = await seedFolder(user.id, { encryptedName: 'folder-b' });

    const realUpdateOne = Folder.updateOne.bind(Folder);
    let writes = 0;
    vi.spyOn(Folder, 'updateOne').mockImplementation(
      (...args: Parameters<typeof Folder.updateOne>) => {
        writes += 1;
        // The SECOND write, so the first has already been applied and there is
        // something for the rollback to undo.
        if (writes === 2) {
          return Promise.resolve({
            acknowledged: true,
            matchedCount: 0,
            modifiedCount: 0,
            upsertedCount: 0,
            upsertedId: null,
          }) as ReturnType<typeof Folder.updateOne>;
        }
        return realUpdateOne(...args);
      },
    );

    try {
      const res = await rotate(user, {
        items: [],
        folders: [rotatedFolder(String(first._id)), rotatedFolder(String(second._id))],
      });

      expect(res.status).toBe(409);
      expect(String(res.body.message)).toMatch(/0 item\(s\), 1 folder\(s\) and 0 document\(s\)/);

      // Rolled back to the name the untouched vault key can still open.
      const rolledBack = await Folder.findById(first._id).lean();
      expect(rolledBack!.encryptedName).toBe('folder-a');
      // And the folder the write MISSED still holds its own original name. Under
      // the mutants this file can reach, the rollback assertion above is what goes
      // red first, so this is a NEGATIVE rather than a unique mutant-killer: it
      // says the row nobody managed to write carries no rotated ciphertext. It is
      // the assertion that would catch a future rewrite of this loop into
      // write-everything-then-check, where the missed row IS reached by the write.
      const missed = await Folder.findById(second._id).lean();
      expect(missed!.encryptedName).toBe('folder-b');

      expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);
      const after = await User.findById(user.id).lean();
      expect(after!.rotationInProgress).toBe(false);
      // `vaultKeyVersion` is what an in-flight upload compares itself against, so a
      // rotation that did not happen must not have moved it — the commit `$inc`s
      // it — and `clearRotationState`'s `$unset` must have left no half-written
      // pending wrap for login's crash-recovery to find. Both are negatives on the
      // same footing as the one above, mirroring what the documents leg's twin
      // asserts (`rotation-documents.test.ts`).
      expect(after!.vaultKeyVersion).toBe(0);
      expect(after!.pendingEncryptedVaultKey).toBeUndefined();
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('reports an ITEM the write no longer matches, and rolls the rest back', async () => {
    // The items leg's own `matchedCount === 0` arm — the twin of the folder case
    // above and of the documents one in `rotation-documents.test.ts`. All three
    // legs answer a row that vanished between the pre-write snapshot and the write
    // the same way, and all three need their own case, because each pushes onto
    // its OWN error array and the 409 counts them separately.
    const first = await seedItem(user.id, { encryptedName: ORIGINAL_ITEM_NAME });
    const second = await seedItem(user.id, { encryptedName: 'item-b' });

    const realUpdateOne = VaultItem.updateOne.bind(VaultItem);
    let writes = 0;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(
      (...args: Parameters<typeof VaultItem.updateOne>) => {
        writes += 1;
        // The SECOND write, so the first has already landed and the rollback has
        // something real to undo. `=== 2` and not `>= 2` for exactly that reason:
        // the rollback goes through this same spy.
        if (writes === 2) {
          return Promise.resolve({
            acknowledged: true,
            matchedCount: 0,
            modifiedCount: 0,
            upsertedCount: 0,
            upsertedId: null,
          }) as ReturnType<typeof VaultItem.updateOne>;
        }
        return realUpdateOne(...args);
      },
    );

    try {
      const res = await rotate(user, {
        items: [rotatedItem(String(first._id)), rotatedItem(String(second._id))],
        folders: [],
      });

      expect(res.status).toBe(409);
      // The count lands on the ITEMS leg and nowhere else, which is what the three
      // separate error arrays buy.
      expect(String(res.body.message)).toMatch(/1 item\(s\), 0 folder\(s\) and 0 document\(s\)/);

      // Rolled back to the ciphertext the untouched vault key still opens.
      const rolledBack = await VaultItem.findById(first._id).lean();
      expect(rolledBack!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
      // And the row the write missed was never reached. Like its twin in the
      // folder case, this is a NEGATIVE rather than a mutant-killer — the spy
      // replaces that write outright, so no production path can touch this row —
      // and it earns its place by catching a future rewrite of the loop into
      // write-everything-then-check, where the missed row IS reached.
      const missed = await VaultItem.findById(second._id).lean();
      expect(missed!.encryptedName).toBe('item-b');

      expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);
      const after = await User.findById(user.id).lean();
      expect(after!.rotationInProgress).toBe(false);
      // Reinforcing, not unique: `clearRotationState` is one shared function, so
      // the documents leg's twin (`rotation-documents.test.ts`) already kills a
      // mutant that neuters its `$unset`. Asserted here anyway, because a guard
      // that cleared the fence for some legs and not others would show up only in
      // the leg it skipped.
      expect(after!.vaultKeyVersion).toBe(0);
      expect(after!.pendingEncryptedVaultKey).toBeUndefined();
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('refuses a rotation whose payload omits a DOCUMENT created after the client enumerated', async () => {
    const item = await seedItem(user.id);
    const enumerated = await seedDocument(user);
    const missed = await seedDocument(user);

    const res = await rotate(user, {
      items: [rotatedItem(String(item._id))],
      folders: [],
      documents: [rewrappedDocument(enumerated)],
    });

    expect(res.status).toBe(409);
    // The message names the leg AND says why a document count can lag, because a
    // purge that has not finished is the one legitimate cause of this shortfall.
    expect(String(res.body.message)).toMatch(/documents: 1 supplied, 2 stored/);
    expect(String(res.body.message)).toMatch(/awaiting permanent deletion/);
    // And it names the OTHER cause of a documents shortfall, which is the one a
    // client cannot recover from by retrying: this count is unconditional while
    // every document route sits behind `requireStorage`, so an operator who
    // removed the storage configuration from a server that still holds document
    // rows leaves an account that can never rotate. Refusing is correct — nobody
    // can rewrap a key they cannot read — but "re-read the vault and retry" is
    // advice that can never work, and the action that does work is naming here.
    expect(String(res.body.message)).toMatch(/no object storage configured/);

    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);
    // Neither wrap moved: the DEK the missed document still holds is the one the
    // unchanged vault key can unwrap, so the file is still openable.
    for (const id of [enumerated, missed]) {
      const row = await Document.findById(id).lean();
      expect(row!.encryptedDek).toBe(ORIGINAL_DEK);
    }
    // And the item leg, which ran first in the loop order, wrote nothing either.
    const itemRow = await VaultItem.findById(item._id).lean();
    expect(itemRow!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
  });

  it('counts a document awaiting permanent deletion, so a stuck purge delays rather than corrupts a rotation', async () => {
    // `purgePending` marks a row whose object delete has started; the row still
    // exists, its DEK is still the only way to read anything left in the bucket,
    // and the hourly cleanup is what finishes it. Counting it is therefore
    // correct — and the 409's wording is what tells the operator why.
    const stuck = await seedDocument(user);
    await Document.updateOne({ _id: stuck }, { $set: { purgePending: true } });

    const refused = await rotate(user, { items: [], folders: [], documents: [] });
    expect(refused.status).toBe(409);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    // Naming it rotates the account: the row is a peer, not an exception.
    const accepted = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrappedDocument(stuck)],
    });
    expect(accepted.status, JSON.stringify(accepted.body)).toBe(200);
    expect(await vaultKeyOf(user.id)).toBe('rotated-vault-key');
  });

  it('still rotates an account whose payload covers every row, including trashed ones', async () => {
    const active = await seedItem(user.id);
    const trashed = await seedItem(user.id, {
      encryptedName: 'trashed-item',
      deletedAt: new Date(),
    });
    const folder = await seedFolder(user.id);
    const activeDocument = await seedDocument(user);
    const trashedDocument = await seedDocument(user, new Date());

    const res = await rotate(user, {
      items: [rotatedItem(String(active._id)), rotatedItem(String(trashed._id))],
      folders: [rotatedFolder(String(folder._id))],
      documents: [rewrappedDocument(activeDocument), rewrappedDocument(trashedDocument)],
    });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.success).toBe(true);
    expect(await vaultKeyOf(user.id)).toBe('rotated-vault-key');

    // A trashed DOCUMENT is counted for the same reason a trashed item is: it is
    // sealed under the same key, so an account that has ever deleted a file would
    // otherwise be unable to rotate at all.
    for (const id of [activeDocument, trashedDocument]) {
      const row = await Document.findById(id).lean();
      expect(row!.encryptedDek).toBe(`dek-ciphertext-new-${id}`);
    }

    // A trashed row is sealed under the same key as an active one, so it must be
    // rotated too — and counted, or an account that has ever deleted anything
    // could never rotate again.
    const trashedRow = await VaultItem.findById(trashed._id).lean();
    expect(trashedRow!.encryptedName).toBe(`rotated-name-${String(trashed._id)}`);
    const activeRow = await VaultItem.findById(active._id).lean();
    expect(activeRow!.encryptedName).toBe(`rotated-name-${String(active._id)}`);
    const folderRow = await Folder.findById(folder._id).lean();
    expect(folderRow!.encryptedName).toBe(`rotated-folder-${String(folder._id)}`);
  });
});

/**
 * The handler's OWN distinct-id check, reached directly.
 *
 * `bulkReEncryptSchema`'s `.superRefine` refuses a repeated id with a 400 before
 * the handler ever runs, so nothing that goes through the route can exercise the
 * `new Set(...).size` inside `assertRotationCoversEveryRow`. That is the right
 * order for production and the wrong one for a test: the two checks answer
 * different questions — the schema asks "is this payload well formed", the handler
 * asks "does this payload cover every row" — and a handler that compared
 * `items.length` instead would rotate the vault key while leaving a row sealed
 * under the old one, with nothing to catch it if the schema rule were ever relaxed.
 *
 * So the handler is called directly, which `catchAsync` from `@hiprax/errors`
 * supports: it is typed with all three parameters regardless of the wrapped
 * handler's arity, and the error arrives at `next` rather than as a status.
 */
describe('The rotation handler, called without its validator', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('counts DISTINCT ids, so a repeated one cannot stand in for a row it never named', async () => {
    const a = await seedItem(user.id, { encryptedName: 'item-a' });
    const b = await seedItem(user.id, { encryptedName: 'item-b' });
    const c = await seedItem(user.id, { encryptedName: 'item-c' });

    // `[A, A, B]` against `{A, B, C}`: every id it names exists and is owned, so
    // the missing-id abort passes it, and its LENGTH matches the row count. Only
    // the distinct count refuses it.
    const req = {
      user: { _id: user.id },
      ip: '192.0.2.1',
      get: () => 'vitest',
      body: {
        authHash: user.rawPassword,
        // Both legs are named explicitly: with the validator bypassed, Zod's
        // `.default([])` never ran, and the handler dereferences `.length` on each.
        folders: [],
        documents: [],
        items: [rotatedItem(String(a._id)), rotatedItem(String(a._id)), rotatedItem(String(b._id))],
        ...NEW_KEY,
      },
    } as unknown as Request;
    const res = { status: () => res, json: () => res } as unknown as Response;
    const next = vi.fn();

    await bulkReEncrypt(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const error = next.mock.calls[0]?.[0] as { statusCode?: number; message?: string };
    expect(error.statusCode).toBe(409);
    expect(error.message).toMatch(/items: 2 supplied, 3 stored/);

    // The negatives: nothing was rotated, and the fence was lowered again.
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);
    for (const row of [a, b, c]) {
      const stored = await VaultItem.findById(row._id).lean();
      expect(stored!.encryptedName).toBe(row.encryptedName);
    }
    const after = await User.findById(user.id).lean();
    // `toBe(false)`, as every other fence assertion in this file is: `toBeFalsy`
    // would also pass on an `$unset` flag, which is a different outcome.
    expect(after?.rotationInProgress).toBe(false);
  });
});

describe('Rotation completeness — transactional (replica-set) branch', () => {
  useReplicaSetConnection({ timeoutMs: 60_000 });

  let user: TestUser;

  beforeEach(async () => {
    // A guard rather than an assumption: without a genuine replica set the
    // handler silently takes the sequential path and this block would assert the
    // wrong branch while still passing.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
    user = await createTestUser();
  });

  it('refuses a rotation whose payload omits an ITEM created after the client enumerated, and commits nothing', async () => {
    const enumerated = await seedItem(user.id);
    const missed = await seedItem(user.id, { encryptedName: 'created-after-enumeration' });

    const res = await rotate(user, {
      items: [rotatedItem(String(enumerated._id))],
      folders: [],
    });

    expect(res.status).toBe(409);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    // The transaction aborted, so the item the payload DID name was rolled back.
    const enumeratedRow = await VaultItem.findById(enumerated._id).lean();
    expect(enumeratedRow!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
    const missedRow = await VaultItem.findById(missed._id).lean();
    expect(missedRow!.encryptedName).toBe('created-after-enumeration');

    const after = await User.findById(user.id).lean();
    expect(after!.rotationInProgress).toBe(false);
  });

  it('refuses a rotation whose payload omits a FOLDER created after the client enumerated', async () => {
    const item = await seedItem(user.id);
    const enumerated = await seedFolder(user.id);
    await seedFolder(user.id, { encryptedName: 'folder-after-enumeration' });

    const res = await rotate(user, {
      items: [rotatedItem(String(item._id))],
      folders: [rotatedFolder(String(enumerated._id))],
    });

    expect(res.status).toBe(409);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);
    const itemRow = await VaultItem.findById(item._id).lean();
    expect(itemRow!.encryptedName).toBe(ORIGINAL_ITEM_NAME);
  });

  it('keeps a COMMITTED rotation even when lowering the fence afterwards fails', async () => {
    // The `finally` that lowers `rotationInProgress` runs AFTER `withTransaction`
    // has already committed. A failure there must not be allowed to mask a
    // rotation that really happened: the new vault key is the only key that opens
    // the rewritten ciphertext, so reporting failure would send the client back to
    // re-encrypt rows it can no longer read. The handler logs and carries on, and
    // the fence it could not lower is left for login's crash-recovery.
    //
    // Only `clearRotationState`'s write is made to fail. It is told apart from the
    // in-transaction key write by its `$unset` — that one uses `$set` + `$inc` and
    // carries a session — so the rotation itself still commits for real.
    const item = await seedItem(user.id);
    const realUpdateOne = User.updateOne.bind(User);
    vi.spyOn(User, 'updateOne').mockImplementation((...args: Parameters<typeof User.updateOne>) => {
      const update = args[1] as Record<string, unknown> | undefined;
      if (update && '$unset' in update) {
        return Promise.reject(new Error('fence-clear failed')) as ReturnType<typeof User.updateOne>;
      }
      return realUpdateOne(...args);
    });

    try {
      const res = await rotate(user, {
        items: [rotatedItem(String(item._id))],
        folders: [],
      });

      // Committed, and reported as committed.
      expect(res.status).toBe(200);
      expect(await vaultKeyOf(user.id)).toBe('rotated-vault-key');
      const row = await VaultItem.findById(item._id).lean();
      expect(row!.encryptedName).toBe(`rotated-name-${String(item._id)}`);

      // The observable cost of the failed clear, and the reason login's
      // crash-recovery exists: the fence is still up.
      const after = await User.findById(user.id).lean();
      expect(after!.rotationInProgress).toBe(true);
      expect(after!.vaultKeyVersion).toBe(1);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('still rotates an account whose payload covers every row, including trashed ones', async () => {
    const active = await seedItem(user.id);
    const trashed = await seedItem(user.id, {
      encryptedName: 'trashed-item',
      deletedAt: new Date(),
    });

    const res = await rotate(user, {
      items: [rotatedItem(String(active._id)), rotatedItem(String(trashed._id))],
      folders: [],
    });

    expect(res.status).toBe(200);
    expect(await vaultKeyOf(user.id)).toBe('rotated-vault-key');
    const trashedRow = await VaultItem.findById(trashed._id).lean();
    expect(trashedRow!.encryptedName).toBe(`rotated-name-${String(trashed._id)}`);
  });
});
