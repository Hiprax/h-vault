import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { createTestUser, authHeader, sampleVaultItem, sampleFolder, getCsrf } from './helpers.js';
import type { TestUser } from './helpers.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';

// ---------------------------------------------------------------------------
// Pure-logic unit tests for the extracted topology helper.
//
// These pass fabricated connection objects, so they assert the branch logic
// deterministically without depending on the real (replica-set) connection.
// ---------------------------------------------------------------------------

describe('supportsTransactions helper', () => {
  const fakeConn = (readyState: number, replicaSet: unknown): mongoose.Connection =>
    ({
      readyState,
      getClient: () => ({ options: { replicaSet } }),
    }) as unknown as mongoose.Connection;

  it('returns true when connected AND a replica set is configured', () => {
    expect(supportsTransactions(fakeConn(mongoose.ConnectionStates.connected, 'rs0'))).toBe(true);
  });

  it('returns false when connected but no replica set is configured (standalone)', () => {
    expect(supportsTransactions(fakeConn(mongoose.ConnectionStates.connected, undefined))).toBe(
      false,
    );
  });

  it('returns false when a replica set is configured but the connection is not ready', () => {
    expect(supportsTransactions(fakeConn(mongoose.ConnectionStates.disconnected, 'rs0'))).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// Integration: the transaction (replica-set) branch of bulkReEncrypt.
//
// The default test harness (tests/setup.ts) connects to a STANDALONE
// mongodb-memory-server, which rejects multi-document transactions — so every
// other rotation test exercises only the sequential fallback. Here we stand up
// a single-node replica set so `supportsTransactions(mongoose.connection)` is
// genuinely true and `session.withTransaction(...)` actually runs, letting us
// assert the commit and atomic-abort semantics of the transaction branch.
//
// The 404-vs-409 status for a missing item id is the key discriminator: the
// transaction branch throws httpErrors.notFound (404), whereas the sequential
// fallback aggregates errors and throws httpErrors.conflict (409). A 404 here
// proves the transaction path ran.
// ---------------------------------------------------------------------------

describe('Vault key rotation — transaction (replica-set) branch', () => {
  let replSet: MongoMemoryReplSet;
  let user: TestUser;

  beforeAll(async () => {
    // The global setup.ts beforeAll already connected mongoose to a standalone
    // server. Drop that connection and reconnect to a replica set so the
    // transaction branch is reachable. setup.ts's afterAll still stops its own
    // (now idle) standalone server.
    await mongoose.disconnect();
    replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replSet.getUri());

    // Sanity guard: if the replica set did not register (e.g. the URI lacked
    // the replicaSet option), the controller would silently take the sequential
    // path and these tests would assert the wrong branch. Fail loudly instead.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  }, 60_000);

  afterAll(async () => {
    await mongoose.disconnect();
    await replSet.stop();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // A fresh user per test (collections are cleared by setup.ts afterEach).
  const seedUser = async (): Promise<void> => {
    user = await createTestUser();
  };

  async function createItemViaApi(overrides: Record<string, unknown> = {}): Promise<string> {
    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send(sampleVaultItem(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  async function createFolderViaApi(overrides: Record<string, unknown> = {}): Promise<string> {
    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send(sampleFolder(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  it('commits the new vault key + re-encrypted ciphertext inside a transaction', async () => {
    await seedUser();
    const itemId1 = await createItemViaApi();
    const itemId2 = await createItemViaApi();
    const folderId = await createFolderViaApi();

    // Prove the transaction branch is taken by spying on startSession — the
    // sequential fallback never opens a session.
    const startSessionSpy = vi.spyOn(mongoose, 'startSession');

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send({
        authHash: user.rawPassword,
        items: [
          {
            id: itemId1,
            encryptedName: 'txn-name-1',
            nameIv: 'txn-niv-1',
            nameTag: 'txn-ntag-1',
            encryptedData: 'txn-data-1',
            dataIv: 'txn-div-1',
            dataTag: 'txn-dtag-1',
          },
          {
            id: itemId2,
            encryptedName: 'txn-name-2',
            nameIv: 'txn-niv-2',
            nameTag: 'txn-ntag-2',
            encryptedData: 'txn-data-2',
            dataIv: 'txn-div-2',
            dataTag: 'txn-dtag-2',
          },
        ],
        folders: [
          {
            id: folderId,
            encryptedName: 'txn-folder-name',
            nameIv: 'txn-folder-iv',
            nameTag: 'txn-folder-tag',
          },
        ],
        newEncryptedVaultKey: 'txn-new-vault-key',
        newVaultKeyIv: 'txn-new-vault-key-iv',
        newVaultKeyTag: 'txn-new-vault-key-tag',
      })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(startSessionSpy).toHaveBeenCalled();

    // Items committed
    const item1 = await VaultItem.findById(itemId1);
    expect(item1!.encryptedName).toBe('txn-name-1');
    expect(item1!.encryptedData).toBe('txn-data-1');
    const item2 = await VaultItem.findById(itemId2);
    expect(item2!.encryptedData).toBe('txn-data-2');

    // Folder committed
    const folder = await Folder.findById(folderId);
    expect(folder!.encryptedName).toBe('txn-folder-name');

    // Vault key committed
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('txn-new-vault-key');
    expect(updatedUser!.vaultKeyIv).toBe('txn-new-vault-key-iv');
    expect(updatedUser!.vaultKeyTag).toBe('txn-new-vault-key-tag');

    // Fence lowered again on the way out.
    expect(updatedUser!.rotationInProgress).toBe(false);
  });

  it('raises the write fence OUTSIDE the transaction and clears it on commit', async () => {
    await seedUser();
    const itemId = await createItemViaApi();

    // The fence has to be a committed write made before `startSession`: a write
    // performed inside the transaction stays invisible to other sessions until
    // commit, which is exactly the window it is supposed to fence. Spy on
    // `User.updateOne` (vi.spyOn calls through) to prove the raise carried no
    // session and the clear ran afterwards — the flag is set and cleared within
    // the one request, so it cannot be observed from the database alone.
    const updateSpy = vi.spyOn(User, 'updateOne');

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send({
        authHash: user.rawPassword,
        items: [
          {
            id: itemId,
            encryptedName: 'fenced-name',
            nameIv: 'fenced-niv',
            nameTag: 'fenced-ntag',
            encryptedData: 'fenced-data',
            dataIv: 'fenced-div',
            dataTag: 'fenced-dtag',
          },
        ],
        folders: [],
        newEncryptedVaultKey: 'fenced-vault-key',
        newVaultKeyIv: 'fenced-vault-key-iv',
        newVaultKeyTag: 'fenced-vault-key-tag',
      })
      .expect(200);

    const raiseCall = updateSpy.mock.calls.find((call) =>
      JSON.stringify(call[1]).includes('"rotationInProgress":true'),
    );
    expect(raiseCall).toBeDefined();
    // No session option => a committed, immediately-visible write.
    expect(raiseCall![2]).toBeUndefined();

    const clearCall = updateSpy.mock.calls.find((call) =>
      JSON.stringify(call[1]).includes('"rotationInProgress":false'),
    );
    expect(clearCall).toBeDefined();

    const rotated = await User.findById(user.id);
    expect(rotated!.rotationInProgress).toBe(false);
    expect(rotated!.pendingEncryptedVaultKey).toBeUndefined();
    expect(rotated!.encryptedVaultKey).toBe('fenced-vault-key');
  });

  it('aborts atomically with 404 when an item id is missing — no partial commit', async () => {
    await seedUser();
    // A valid item processed FIRST, then a missing id. The transaction must roll
    // back the already-applied first write so no ciphertext/key mismatch remains.
    const validId = await createItemViaApi();
    const missingId = new mongoose.Types.ObjectId().toString();

    const agent = request.agent(app);
    const { token, cookie } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', cookie)
      .set('x-csrf-token', token)
      .send({
        authHash: user.rawPassword,
        items: [
          {
            id: validId,
            encryptedName: 'should-roll-back',
            nameIv: 'rb-niv',
            nameTag: 'rb-ntag',
            encryptedData: 'should-roll-back-data',
            dataIv: 'rb-div',
            dataTag: 'rb-dtag',
          },
          {
            id: missingId,
            encryptedName: 'ghost',
            nameIv: 'g-niv',
            nameTag: 'g-ntag',
            encryptedData: 'ghost-data',
            dataIv: 'g-div',
            dataTag: 'g-dtag',
          },
        ],
        newEncryptedVaultKey: 'aborted-vault-key',
        newVaultKeyIv: 'aborted-iv',
        newVaultKeyTag: 'aborted-tag',
      })
      // 404 (httpErrors.notFound) is unique to the transaction branch; the
      // sequential fallback would return 409 for the same scenario.
      .expect(404);

    expect(res.body.success).toBe(false);

    // The first item's write was rolled back — original ciphertext preserved.
    const validItem = await VaultItem.findById(validId);
    expect(validItem!.encryptedName).toBe('test-encrypted-name');
    expect(validItem!.encryptedData).toBe('test-encrypted-data-base64');

    // Vault key unchanged — the abort never committed the new key.
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');

    // The fence is raised outside the transaction, so the abort's rollback does
    // NOT lower it — the `finally` must, or every later write would 409 until
    // the user next logs in.
    expect(updatedUser!.rotationInProgress).toBe(false);

    const agent2 = request.agent(app);
    const csrf2 = await getCsrf(agent2);
    await agent2
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf2.cookie)
      .set('x-csrf-token', csrf2.token)
      .send(sampleVaultItem({ encryptedName: 'after-aborted-txn-rotation' }))
      .expect(201);
  });
});
