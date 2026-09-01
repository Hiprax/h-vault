/**
 * The documents leg of `POST /vault/items/bulk-reencrypt`, and the vault-key
 * version counter it moves.
 *
 * A rotation rewraps 32 bytes per document — the DEK, sealed under a key derived
 * from the vault key and bound to the document id — and touches no stored object
 * at all. That is the entire reason the document store uses envelope encryption:
 * a scheme that re-encrypted the FILE would make rotation impossible on any
 * account holding gigabytes.
 *
 * The leg is a FULL PEER of items and folders, which is what this file pins. On
 * both branches: the same ownership predicate, the same abort on a miss, and — on
 * the sequential branch, which is what a standalone mongod and therefore any
 * single-node self-host runs — the same snapshot, written-id tracking and
 * rollback. Without the rollback arm, a partial failure leaves documents wrapped
 * under the NEW key while the stored vault key is still the OLD one, which is
 * every file in the account permanently unreadable, with no second copy of the
 * plaintext anywhere.
 *
 * `vaultKeyVersion` is incremented with `$inc` in the SAME update document that
 * stores the new key. It is the number an in-flight upload's completion checks
 * itself against, so a completion that read the old version before the rotation
 * and lands after it is refused with a 409 rather than committing a DEK nothing
 * can unwrap. `changePassword` must NOT move it: that flow re-wraps the SAME
 * vault key under a new MEK, so an upload spanning a password change is still
 * valid.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Document } from '../src/models/Document.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createTestUser, authHeader, getCsrf, seedItem } from './helpers.js';
import type { TestUser } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';

const NEW_KEY = {
  newEncryptedVaultKey: 'rotated-vault-key',
  newVaultKeyIv: 'rotated-vault-key-iv',
  newVaultKeyTag: 'rotated-vault-key-tag',
};

const ORIGINAL_KEY = 'test-encrypted-vault-key';

/** The wrap a seeded document starts with, i.e. what a refused rotation must leave. */
const ORIGINAL_WRAP = {
  encryptedDek: 'dek-ciphertext-old',
  dekIv: 'dek-iv-old',
  dekTag: 'dek-tag-old',
};

/**
 * The columns a rotation must never reach.
 *
 * Named as a list because "the rewrap cannot mis-frame a document" is the single
 * most important property here: the framing fields and the sizes decide how the
 * stored object is cut into sealed segments, and a rotation that moved one would
 * produce a file that opens to nothing while every status code stayed green.
 */
const UNREACHABLE_COLUMNS = [
  'objectKey',
  'streamSalt',
  'noncePrefix',
  'encryptedMeta',
  'metaIv',
  'metaTag',
  'chunkPlaintextBytes',
  'chunkCount',
  'ciphertextBytes',
  'plaintextBytes',
] as const;

interface SeedDocumentOptions {
  deletedAt?: Date;
}

/**
 * A committed `documents` row, seeded directly.
 *
 * Driving it through init, a part and a completion would make every failure here
 * ambiguous between four handlers that have their own suites; what matters to a
 * rotation is only the STATE a completion leaves behind.
 */
async function seedDocument(user: TestUser, options: SeedDocumentOptions = {}): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    ...ORIGINAL_WRAP,
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    streamSalt: Buffer.alloc(32, 11).toString('base64'),
    noncePrefix: Buffer.alloc(7, 5).toString('base64'),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
    plaintextBytes: 1024,
    ...(options.deletedAt === undefined ? {} : { deletedAt: options.deletedAt }),
  });
  return String(documentId);
}

/** What the browser posts for one document whose DEK it rewrapped. */
function rewrapped(id: string): Record<string, string> {
  return {
    id,
    encryptedDek: `dek-ciphertext-new-${id}`,
    dekIv: 'dek-iv-new',
    dekTag: 'dek-tag-new',
  };
}

function rotatedItem(id: string): Record<string, string> {
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

async function rawDocument(id: string): Promise<Record<string, unknown>> {
  const row = (await Document.findById(id).lean()) as Record<string, unknown> | null;
  expect(row).not.toBeNull();
  return row!;
}

function pick(row: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(keys.map((key) => [key, row[key]]));
}

describe('Vault key rotation — documents leg (sequential branch)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rewraps every document DEK, moves vaultKeyVersion by exactly one, and touches no framing column', async () => {
    const active = await seedDocument(user);
    const trashed = await seedDocument(user, { deletedAt: new Date() });
    const before = await rawDocument(active);

    const res = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrapped(active), rewrapped(trashed)],
    });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.updatedCount).toBe(2);

    // Both wraps moved — a trashed document is sealed under the same vault key as
    // an active one, so leaving it behind would strand it on restore.
    for (const id of [active, trashed]) {
      const row = await rawDocument(id);
      expect(row.encryptedDek).toBe(`dek-ciphertext-new-${id}`);
      expect(row.dekIv).toBe('dek-iv-new');
      expect(row.dekTag).toBe('dek-tag-new');
    }

    // …and nothing else did. The stored object was never read or written, so any
    // movement in these columns would be a rotation that had mis-framed a file.
    const after = await rawDocument(active);
    expect(pick(after, UNREACHABLE_COLUMNS)).toEqual(pick(before, UNREACHABLE_COLUMNS));

    const rotated = await User.findById(user.id).lean();
    expect(rotated!.encryptedVaultKey).toBe('rotated-vault-key');
    expect(rotated!.vaultKeyVersion).toBe(1);
    expect(rotated!.rotationInProgress).toBe(false);
  });

  it('leaves vaultKeyVersion at 0 and every wrap untouched when the rotation is refused', async () => {
    const id = await seedDocument(user);

    // A second document the payload does not name: the rotation is refused, and
    // the refusal must not have moved the counter a completion checks against.
    await seedDocument(user);

    const res = await rotate(user, { items: [], folders: [], documents: [rewrapped(id)] });

    expect(res.status).toBe(409);
    const untouched = await rawDocument(id);
    expect(untouched.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).toBe(ORIGINAL_KEY);
    expect(after!.vaultKeyVersion).toBe(0);
  });

  it('aborts before any write when a document id is missing, naming all three legs', async () => {
    const real = await seedDocument(user);
    const ghost = new mongoose.Types.ObjectId().toHexString();

    const res = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrapped(real), rewrapped(ghost)],
    });

    expect(res.status).toBe(409);
    expect(String(res.body.message)).toMatch(
      /0 item\(s\), 0 folder\(s\) and 1 document\(s\) could not be updated/,
    );

    // The pre-write abort is what makes this safe: the real document's wrap was
    // never replaced, so the vault key the user still holds still opens it.
    const untouched = await rawDocument(real);
    expect(untouched.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).toBe(ORIGINAL_KEY);
    expect(after!.vaultKeyVersion).toBe(0);
  });

  it('rolls a rewrapped document back to its old wrap when a later document write fails', async () => {
    const first = await seedDocument(user);
    const second = await seedDocument(user);

    // Fail the SECOND document write only, after the first has committed. This is
    // the arm that matters on a standalone deployment: without it the first
    // document stays wrapped under a vault key that is about to be discarded.
    const realUpdateOne = Document.updateOne.bind(Document);
    let writes = 0;
    vi.spyOn(Document, 'updateOne').mockImplementation(
      (...args: Parameters<typeof Document.updateOne>) => {
        writes += 1;
        if (writes === 2) {
          throw new Error('simulated storage failure on the second document');
        }
        return realUpdateOne(...args);
      },
    );

    const res = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrapped(first), rewrapped(second)],
    });

    expect(res.status).toBe(409);
    expect(String(res.body.message)).toMatch(/1 document\(s\) could not be updated/);

    // The rollback ran: the first document carries its ORIGINAL wrap again, which
    // is the only wrap the (unchanged) vault key can produce.
    const rolledBack = await rawDocument(first);
    expect(rolledBack.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    expect(rolledBack.dekIv).toBe(ORIGINAL_WRAP.dekIv);
    expect(rolledBack.dekTag).toBe(ORIGINAL_WRAP.dekTag);

    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).toBe(ORIGINAL_KEY);
    expect(after!.vaultKeyVersion).toBe(0);
    expect(after!.rotationInProgress).toBe(false);
    expect(after!.pendingEncryptedVaultKey).toBeUndefined();
  });

  it('rolls documents back when an ITEM write fails after they were rewrapped', async () => {
    // Documents are written last, so this is the reverse direction: proving the
    // item leg's failure path reaches the document rollback would be vacuous
    // here. What this pins instead is that a failing item leg never lets the
    // document leg run at all, so no document is left under the new key.
    const item = await seedItem(user.id);
    const doc = await seedDocument(user);

    vi.spyOn(VaultItem, 'updateOne').mockImplementation(() => {
      throw new Error('simulated failure on the item leg');
    });

    const res = await rotate(user, {
      items: [rotatedItem(String(item._id))],
      folders: [],
      documents: [rewrapped(doc)],
    });

    expect(res.status).toBe(409);
    const untouched = await rawDocument(doc);
    expect(untouched.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).toBe(ORIGINAL_KEY);
    expect(after!.vaultKeyVersion).toBe(0);
  });

  it('counts documents in the idempotency short-circuit and does not increment the version twice', async () => {
    const doc = await seedDocument(user);
    const item = await seedItem(user.id);
    const idempotencyKey = '11111111-2222-4333-8444-555555555555';
    const body = {
      idempotencyKey,
      items: [rotatedItem(String(item._id))],
      folders: [],
      documents: [rewrapped(doc)],
    };

    const first = await rotate(user, body);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.data.updatedCount).toBe(2);
    expect((await User.findById(user.id).lean())!.vaultKeyVersion).toBe(1);

    // The replay is a no-op that still reports the same count — and above all
    // does not move the version, which would strand every in-flight upload twice.
    const replay = await rotate(user, body);
    expect(replay.status).toBe(200);
    expect(replay.body.data.updatedCount).toBe(2);
    expect((await User.findById(user.id).lean())!.vaultKeyVersion).toBe(1);
  });

  it('rejects a documents leg that names one id twice, before the handler runs', async () => {
    const doc = await seedDocument(user);

    const res = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrapped(doc), rewrapped(doc)],
    });

    // 400, not 409: a repeated id is a malformed payload, and rejecting it in the
    // schema keeps the handler's own check a pure coverage question.
    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/documents.*duplicate ids/i);
    const untouched = await rawDocument(doc);
    expect(untouched.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    expect((await User.findById(user.id).lean())!.encryptedVaultKey).toBe(ORIGINAL_KEY);
  });

  it('rotates an account with no documents exactly as before, leaving the leg absent', async () => {
    const item = await seedItem(user.id);

    // No `documents` key at all: an older client, or a server with no storage
    // configured. The schema defaults it to `[]` and nothing else changes.
    const res = await rotate(user, { items: [rotatedItem(String(item._id))], folders: [] });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data.updatedCount).toBe(1);
    expect((await User.findById(user.id).lean())!.vaultKeyVersion).toBe(1);
  });
});

describe('Vault key rotation — documents leg (transactional branch)', () => {
  useReplicaSetConnection({ timeoutMs: 60_000 });

  let user: TestUser;

  beforeEach(async () => {
    expect(supportsTransactions(mongoose.connection)).toBe(true);
    user = await createTestUser();
  });

  it('commits every rewrapped DEK and the version bump in one transaction', async () => {
    const first = await seedDocument(user);
    const second = await seedDocument(user, { deletedAt: new Date() });

    const res = await rotate(user, {
      items: [],
      folders: [],
      documents: [rewrapped(first), rewrapped(second)],
    });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    for (const id of [first, second]) {
      expect((await rawDocument(id)).encryptedDek).toBe(`dek-ciphertext-new-${id}`);
    }
    const rotated = await User.findById(user.id).lean();
    expect(rotated!.encryptedVaultKey).toBe('rotated-vault-key');
    expect(rotated!.vaultKeyVersion).toBe(1);
  });

  it('aborts the whole transaction with 404 on a missing document id, committing nothing', async () => {
    const real = await seedDocument(user);
    const ghost = new mongoose.Types.ObjectId().toHexString();

    const res = await rotate(user, {
      items: [],
      folders: [],
      // The real document is processed FIRST, so its write is already applied
      // inside the transaction when the ghost aborts it.
      documents: [rewrapped(real), rewrapped(ghost)],
    });

    // 404 is unique to the transactional branch; the sequential fallback answers
    // the same scenario with a 409, which is what tells the two apart.
    expect(res.status).toBe(404);
    expect(String(res.body.message)).toContain(ghost);

    const rolledBack = await rawDocument(real);
    expect(rolledBack.encryptedDek).toBe(ORIGINAL_WRAP.encryptedDek);
    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).toBe(ORIGINAL_KEY);
    expect(after!.vaultKeyVersion).toBe(0);
    expect(after!.rotationInProgress).toBe(false);
  });
});

describe('changePassword must not move vaultKeyVersion', () => {
  it('re-wraps the same vault key under a new MEK and leaves the counter alone', async () => {
    const user = await createTestUser();
    // A rotation first, so the counter is at a value a stray `$inc` or a computed
    // `$set` would visibly disturb — starting from 0 would hide a reset to 0.
    const item = await seedItem(user.id);
    const rotation = await rotate(user, { items: [rotatedItem(String(item._id))], folders: [] });
    expect(rotation.status, JSON.stringify(rotation.body)).toBe(200);
    expect((await User.findById(user.id).lean())!.vaultKeyVersion).toBe(1);

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .put('/api/v1/user/change-password')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: 'a-brand-new-auth-hash',
        newEncryptedVaultKey: 'rewrapped-under-the-new-mek',
        newVaultKeyIv: 'rewrapped-iv',
        newVaultKeyTag: 'rewrapped-tag',
      });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const after = await User.findById(user.id).lean();
    // The wrapper moved…
    expect(after!.encryptedVaultKey).toBe('rewrapped-under-the-new-mek');
    // …but the KEY inside it did not, so an upload that read version 1 before the
    // password change is still valid and must not be refused.
    expect(after!.vaultKeyVersion).toBe(1);
  });
});
