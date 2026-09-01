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
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
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

describe('Rotation completeness — sequential (standalone) branch', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
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

    expect(res.status).not.toBe(200);
    expect(await vaultKeyOf(user.id)).toBe(ORIGINAL_KEY);

    for (const row of [a, b, c]) {
      const stored = await VaultItem.findById(row._id).lean();
      expect(stored!.encryptedName).toBe(row.encryptedName);
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
