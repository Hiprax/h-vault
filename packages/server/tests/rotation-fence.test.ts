import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { JobLock } from '../src/models/JobLock.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf,
  seedItem,
  seedFolder,
  type TestUser,
} from './helpers.js';

// ---------------------------------------------------------------------------
// Rotation fence — a vault key rotation must not silently strand ciphertext
// written by a second session that still holds the OLD key.
//
// `bulkReEncrypt` re-encrypts the set of rows the CLIENT enumerated, then swaps
// `User.encryptedVaultKey`. A concurrent write from another device lands
// ciphertext under the old key that is NOT in that set — permanently
// undecryptable once the new key commits, with no error shown to the writer.
// The fence (`assertVaultNotRotating`) turns that silent loss into a retryable
// 409 for the six ciphertext-creating handlers, and leaves the metadata-only
// handlers (move / delete / restore / reorder) untouched.
//
// The fence covers only the window in which the rotation is RUNNING. Its peer,
// `assertVaultKeyVersion`, covers the window after it has COMMITTED, when the
// flag is down and a second session can still hold the superseded key
// indefinitely; that guard is pinned in `stale-vault-key-writes.test.ts`. Every
// request in THIS file therefore names no generation and runs against an
// account that has never rotated, which is the compatibility branch — except
// where a case below rotates for real and says so.
//
// The default harness (tests/setup.ts) is a STANDALONE mongodb-memory-server,
// so the rotation exercises the sequential fallback here; the transaction
// branch's flag lifecycle is asserted in vault-rotation-transaction.test.ts.
// ---------------------------------------------------------------------------

describe('Vault key rotation fence', () => {
  let user: TestUser;
  let itemId: string;
  let folderId: string;

  beforeEach(async () => {
    user = await createTestUser();
    const item = await seedItem(user.id, { encryptedName: 'pre-existing-item' });
    const folder = await seedFolder(user.id, { encryptedName: 'pre-existing-folder' });
    itemId = String(item._id);
    folderId = String(folder._id);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Helpers ─────────────────────────────────────────────────────────

  async function mutate(
    method: 'post' | 'put' | 'delete',
    path: string,
    body?: Record<string, unknown>,
  ): Promise<request.Response> {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const req =
      method === 'post'
        ? agent.post(path)
        : method === 'put'
          ? agent.put(path)
          : agent.delete(path);
    return req
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(body ?? {});
  }

  /** Flips the server-side rotation marker the fence reads. */
  async function setRotating(inProgress: boolean): Promise<void> {
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: inProgress } });
  }

  /**
   * Issues every ciphertext-creating write exactly once and returns each
   * endpoint's status, so a single assertion covers all six fenced handlers and
   * a failure names the endpoint that regressed.
   */
  async function attemptEveryCiphertextWrite(): Promise<Record<string, number>> {
    const createItemRes = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'written-during-rotation' }),
    );
    const updateItemRes = await mutate('put', `/api/v1/vault/items/${itemId}`, {
      encryptedName: 'renamed-during-rotation',
      nameIv: 'new-name-iv',
      nameTag: 'new-name-tag',
    });
    const createFolderRes = await mutate(
      'post',
      '/api/v1/folders',
      sampleFolder({ encryptedName: 'folder-during-rotation' }),
    );
    const updateFolderRes = await mutate('put', `/api/v1/folders/${folderId}`, {
      encryptedName: 'folder-renamed-during-rotation',
      nameIv: 'folder-name-iv',
      nameTag: 'folder-name-tag',
    });
    const importRes = await mutate('post', '/api/v1/tools/import', {
      format: 'json',
      operations: {
        inserts: [sampleVaultItem({ encryptedName: 'imported', searchHash: 'a'.repeat(64) })],
      },
    });
    const restoreRes = await mutate('post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'restored' })],
        folders: [],
      }),
    });

    return {
      'POST /vault/items': createItemRes.status,
      'PUT /vault/items/:id': updateItemRes.status,
      'POST /folders': createFolderRes.status,
      'PUT /folders/:id': updateFolderRes.status,
      'POST /tools/import': importRes.status,
      'POST /backup/restore': restoreRes.status,
    };
  }

  // ── Fenced: every ciphertext-creating write ─────────────────────────

  describe('while a rotation is in progress', () => {
    beforeEach(async () => {
      await setRotating(true);
    });

    it('returns 409 from every ciphertext-creating write', async () => {
      const statuses = await attemptEveryCiphertextWrite();

      expect(statuses).toEqual({
        'POST /vault/items': 409,
        'PUT /vault/items/:id': 409,
        'POST /folders': 409,
        'PUT /folders/:id': 409,
        'POST /tools/import': 409,
        'POST /backup/restore': 409,
      });
    });

    it('persists no ciphertext from a fenced write', async () => {
      await attemptEveryCiphertextWrite();

      // Only the two rows seeded in beforeEach survive, with their original
      // ciphertext — nothing was created, nothing was overwritten.
      const items = await VaultItem.find({ userId: user.id }).lean();
      const folders = await Folder.find({ userId: user.id }).lean();
      expect(items).toHaveLength(1);
      expect(folders).toHaveLength(1);
      expect(items[0]!.encryptedName).toBe('pre-existing-item');
      expect(folders[0]!.encryptedName).toBe('pre-existing-folder');
    });

    it('explains the 409 so the client can retry', async () => {
      const res = await mutate(
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ encryptedName: 'blocked' }),
      );

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toMatch(/rotation is in progress/i);
    });

    // ── NOT fenced: metadata-only writes ─────────────────────────────
    //
    // These persist no vault-key ciphertext (a rotation neither reads nor
    // rewrites `folderId` / `deletedAt` / `sortOrder`), so fencing them would be
    // a needless availability hit during a multi-second rotation.

    it('does not block a bulk move (folderId only)', async () => {
      const res = await mutate('post', '/api/v1/vault/items/bulk-move', {
        ids: [itemId],
        folderId,
      });

      expect(res.status).toBe(200);
      const moved = await VaultItem.findById(itemId).lean();
      expect(String(moved!.folderId)).toBe(folderId);
    });

    it('does not block soft-delete, restore, or permanent delete', async () => {
      const deleteRes = await mutate('delete', `/api/v1/vault/items/${itemId}`);
      expect(deleteRes.status).toBe(200);
      expect((await VaultItem.findById(itemId).lean())!.deletedAt).toBeTruthy();

      const restoreRes = await mutate('post', `/api/v1/vault/items/restore/${itemId}`);
      expect(restoreRes.status).toBe(200);
      expect((await VaultItem.findById(itemId).lean())!.deletedAt).toBeFalsy();

      await mutate('delete', `/api/v1/vault/items/${itemId}`);
      const permanentRes = await mutate('delete', `/api/v1/vault/items/${itemId}/permanent`);
      expect(permanentRes.status).toBe(200);
      expect(await VaultItem.findById(itemId).lean()).toBeNull();
    });

    it('does not block a folder reorder (sortOrder only)', async () => {
      const res = await mutate('put', `/api/v1/folders/${folderId}/sort`, { sortOrder: 7 });

      expect(res.status).toBe(200);
      expect((await Folder.findById(folderId).lean())!.sortOrder).toBe(7);
    });
  });

  // ── Unfenced once the rotation has finished ─────────────────────────

  it('allows every ciphertext-creating write once the flag clears', async () => {
    await setRotating(true);
    await setRotating(false);

    const statuses = await attemptEveryCiphertextWrite();

    expect(statuses).toEqual({
      'POST /vault/items': 201,
      'PUT /vault/items/:id': 200,
      'POST /folders': 201,
      'PUT /folders/:id': 200,
      'POST /tools/import': 201,
      'POST /backup/restore': 200,
    });
  });

  // ── The rotation itself raises and lowers the fence ─────────────────

  describe('bulkReEncrypt flag lifecycle (sequential path)', () => {
    const rotationBody = (items: { id: string }[], folders: { id: string }[]) => ({
      authHash: user.rawPassword,
      items: items.map((i) => ({
        id: i.id,
        encryptedName: 'rotated-name',
        nameIv: 'rotated-name-iv',
        nameTag: 'rotated-name-tag',
        encryptedData: 'rotated-data',
        dataIv: 'rotated-data-iv',
        dataTag: 'rotated-data-tag',
      })),
      folders: folders.map((f) => ({
        id: f.id,
        encryptedName: 'rotated-folder-name',
        nameIv: 'rotated-folder-iv',
        nameTag: 'rotated-folder-tag',
      })),
      newEncryptedVaultKey: 'rotated-vault-key',
      newVaultKeyIv: 'rotated-vault-key-iv',
      newVaultKeyTag: 'rotated-vault-key-tag',
    });

    it('raises the fence, then clears it and the pending fields on success', async () => {
      // `vi.spyOn` calls through by default, so the rotation runs for real and we
      // can still read back the update operations it issued — the only way to
      // observe a flag that is deliberately set and cleared within one request.
      const updateSpy = vi.spyOn(User, 'updateOne');

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );
      expect(res.status).toBe(200);

      const ops = updateSpy.mock.calls.map((call) => JSON.stringify(call[1]));
      expect(ops.some((op) => op.includes('"rotationInProgress":true'))).toBe(true);
      expect(ops.some((op) => op.includes('"rotationInProgress":false'))).toBe(true);

      const rotated = await User.findById(user.id).lean();
      expect(rotated!.rotationInProgress).toBe(false);
      expect(rotated!.pendingEncryptedVaultKey).toBeUndefined();
      expect(rotated!.pendingVaultKeyIv).toBeUndefined();
      expect(rotated!.pendingVaultKeyTag).toBeUndefined();
      expect(rotated!.encryptedVaultKey).toBe('rotated-vault-key');

      // With the fence lowered again, a write flows immediately — PROVIDED it
      // names the generation the rotation just minted. The fence and the
      // generation guard are peers covering the two halves of the same window,
      // and this is where they are told apart: the fence is down, so whatever
      // refuses the second request below is not the fence.
      expect(rotated!.vaultKeyVersion).toBe(1);
      const afterRotation = await mutate(
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ encryptedName: 'after-rotation', vaultKeyVersion: 1 }),
      );
      expect(afterRotation.status).toBe(201);

      // And a write still naming the superseded generation is refused, with the
      // recoverable body the fence's own 409 does not carry. Before the
      // generation guard existed this request succeeded and left a row sealed
      // under a key the account had just replaced.
      const stillStale = await mutate(
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ encryptedName: 'sealed-under-the-old-key', vaultKeyVersion: 0 }),
      );
      expect(stillStale.status).toBe(409);
      expect(stillStale.body.data).toEqual({ vaultKeyVersion: 1 });
    });

    it('lowers the fence when the rotation aborts mid-write', async () => {
      // Force a failure AFTER the fence is raised and the item loop has already
      // written new ciphertext: the folder write throws, so the orderly
      // conflict-abort must roll the item back AND lower the fence. (The
      // missing-id abort below is a different branch — it rejects before the
      // fence goes up at all.)
      vi.spyOn(Folder, 'updateOne').mockImplementationOnce(() => {
        throw new Error('simulated folder write failure');
      });

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );
      expect(res.status).toBe(409);

      const afterAbort = await User.findById(user.id).lean();
      expect(afterAbort!.rotationInProgress).toBe(false);
      // The pending wrapper SURVIVES the abort, deliberately: it is the only
      // stored copy of the key this rotation was moving to, and an abort is
      // precisely where a crash may already have sealed rows under it. Only a
      // COMMIT drops it. The next rotation must adopt it or discard it in so
      // many words — see the outstanding-rotation guard in `bulkReEncrypt`.
      expect(afterAbort!.pendingEncryptedVaultKey).toBe('rotated-vault-key');
      // Vault key untouched, and the item's new ciphertext rolled back to the
      // ciphertext the untouched key can still decrypt.
      expect(afterAbort!.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect((await VaultItem.findById(itemId).lean())!.encryptedName).toBe('pre-existing-item');

      // Fence down ⇒ the user can write again immediately.
      const write = await mutate(
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ encryptedName: 'after-mid-write-abort' }),
      );
      expect(write.status).toBe(201);
    });

    it('leaves the fence down after a rotation rejected before it starts', async () => {
      const missingId = new mongoose.Types.ObjectId().toString();

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }, { id: missingId }], []),
      );
      expect(res.status).toBe(409);

      const afterAbort = await User.findById(user.id).lean();
      expect(afterAbort!.rotationInProgress).toBe(false);
      expect(afterAbort!.pendingEncryptedVaultKey).toBeUndefined();
      // The vault key was never swapped, so the old ciphertext is still valid.
      expect(afterAbort!.encryptedVaultKey).toBe('test-encrypted-vault-key');

      // A failed rotation must not wedge the account's writes.
      const write = await mutate(
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ encryptedName: 'after-failed-rotation' }),
      );
      expect(write.status).toBe(201);
    });

    /**
     * The sequential path's final `User.updateOne` is the one write whose failure
     * is AMBIGUOUS. A socket that drops after the server applied it looks exactly
     * like one that dropped before, and the two demand opposite responses: the
     * rows are already re-encrypted under the new key, which is now the account's
     * key, so restoring them to their pre-rotation ciphertext would leave every
     * one of them sealed under a key nothing holds. The rollback that exists to
     * PREVENT that loss would be the thing that causes it, and it would do so on
     * an account whose data was, at that moment, entirely intact.
     *
     * So the rollback asks the datastore what actually landed before it undoes
     * anything. It is a question with a definite answer — `encryptedVaultKey` is
     * either the new wrapper or it is not, and only the final write can have put
     * it there — and it is asked in `rollbackPartialWrites` itself rather than at
     * the catch, so BOTH call sites are covered by one rule.
     */
    it('does not roll back over a final write that may already have applied', async () => {
      // An ambiguous failure, reproduced faithfully: the write is performed for
      // real and THEN the call rejects, which is what a connection dropping after
      // the server applied it looks like to this process.
      const realUpdateOne = User.updateOne.bind(User);
      vi.spyOn(User, 'updateOne').mockImplementation((async (
        filter: never,
        update: never,
        options?: never,
      ) => {
        const applied = await realUpdateOne(filter, update, options);
        if (JSON.stringify(update).includes('encryptedVaultKey')) {
          throw new Error('connection reset after the write was applied');
        }
        return applied;
      }) as never);

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );
      // The request still fails: the server genuinely does not know it succeeded,
      // and reporting a success it cannot see would be a different lie.
      expect(res.status).toBe(500);

      vi.restoreAllMocks();
      const after = await User.findById(user.id).lean();
      // The rotation DID land. Everything below is what makes that survivable.
      expect(after!.encryptedVaultKey).toBe('rotated-vault-key');
      expect(after!.vaultKeyVersion).toBe(1);
      // THE NEGATIVE, and the whole point: the rows were NOT restored to the
      // ciphertext only the superseded key can open.
      expect((await VaultItem.findById(itemId).lean())!.encryptedName).toBe('rotated-name');
      expect((await Folder.findById(folderId).lean())!.encryptedName).toBe('rotated-folder-name');
      // And the account is not left wedged: the fence is down and the lock freed.
      expect(after!.rotationInProgress).toBe(false);
      expect(await JobLock.countDocuments({ jobName: `vault-rotation:${user.id}` })).toBe(0);
    });

    it('still rolls back in full when the final write genuinely did not apply', async () => {
      // The other side of the same decision, and the case that proves the skip is
      // a CHECK and not a blanket "never roll back". Here the final write is
      // rejected without being performed, so the vault key is untouched and the
      // rows carry ciphertext only the NEW key could open — which nothing holds.
      // Restoring them is the only correct answer.
      const realUpdateOne = User.updateOne.bind(User);
      vi.spyOn(User, 'updateOne').mockImplementation((async (
        filter: never,
        update: never,
        options?: never,
      ) => {
        if (JSON.stringify(update).includes('encryptedVaultKey')) {
          throw new Error('connection reset before the write was applied');
        }
        return realUpdateOne(filter, update, options);
      }) as never);

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );
      expect(res.status).toBe(500);

      vi.restoreAllMocks();
      const after = await User.findById(user.id).lean();
      expect(after!.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect(after!.vaultKeyVersion ?? 0).toBe(0);
      // Rolled back to the ciphertext the untouched key still opens.
      expect((await VaultItem.findById(itemId).lean())!.encryptedName).toBe('pre-existing-item');
      expect((await Folder.findById(folderId).lean())!.encryptedName).toBe('pre-existing-folder');
      // The pending wrapper survives, because a crash may already have sealed
      // rows under it — the outstanding-rotation guard's contract.
      expect(after!.pendingEncryptedVaultKey).toBe('rotated-vault-key');
      expect(await JobLock.countDocuments({ jobName: `vault-rotation:${user.id}` })).toBe(0);
    });

    it('skips the rollback when it CANNOT tell whether the rotation committed', async () => {
      // The third outcome, and the one whose default matters most. When the
      // datastore will not answer, the two mistakes are not equally bad: rolling
      // back a rotation that committed is irreversible and total, while skipping
      // one that did not leaves the rows under the pending wrapper this branch
      // stored expressly so an interrupted rotation can be finished. So an
      // unreadable answer takes the non-destructive branch.
      //
      // Only the rollback's own read is broken; the writes and every other read in
      // the request stay real, so the request reaches the rollback for a genuine
      // reason rather than a manufactured one.
      const realUpdateOne = User.updateOne.bind(User);
      vi.spyOn(User, 'updateOne').mockImplementation((async (
        filter: never,
        update: never,
        options?: never,
      ) => {
        if (JSON.stringify(update).includes('encryptedVaultKey')) {
          throw new Error('connection reset before the write was applied');
        }
        return realUpdateOne(filter, update, options);
      }) as never);
      const realFindById = User.findById.bind(User);
      vi.spyOn(User, 'findById').mockImplementation(((id: string) => {
        const query = realFindById(id);
        const realSelect = query.select.bind(query);
        query.select = ((fields: string) =>
          fields === 'encryptedVaultKey'
            ? { lean: () => Promise.reject(new Error('datastore unavailable')) }
            : realSelect(fields)) as never;
        return query;
      }) as never);

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );
      expect(res.status).toBe(500);

      vi.restoreAllMocks();
      // The vault key was never replaced, so this account is NOT lost — and the
      // rows were left as the rotation wrote them rather than restored blindly.
      const after = await User.findById(user.id).lean();
      expect(after!.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect((await VaultItem.findById(itemId).lean())!.encryptedName).toBe('rotated-name');
      // The route back: the pending wrapper is the key those rows are under, and
      // it survives.
      expect(after!.pendingEncryptedVaultKey).toBe('rotated-vault-key');
      expect(after!.rotationInProgress).toBe(false);
      expect(await JobLock.countDocuments({ jobName: `vault-rotation:${user.id}` })).toBe(0);
    });

    it('never fences the rotation endpoint itself, so a stuck flag can be retried', async () => {
      await setRotating(true);

      const res = await mutate(
        'post',
        '/api/v1/vault/items/bulk-reencrypt',
        rotationBody([{ id: itemId }], [{ id: folderId }]),
      );

      expect(res.status).toBe(200);
      expect((await User.findById(user.id).lean())!.rotationInProgress).toBe(false);
    });
  });

  // ── Login crash-recovery still clears a stuck flag ──────────────────

  it('clears a stuck rotation flag on login, unblocking fenced writes', async () => {
    // Simulate a server crash mid-rotation: the flag and the pending vault key
    // are committed, but nothing ever cleared them.
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          rotationInProgress: true,
          pendingEncryptedVaultKey: 'half-rotated-key',
          pendingVaultKeyIv: 'half-rotated-iv',
          pendingVaultKeyTag: 'half-rotated-tag',
        },
      },
    );

    const blocked = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'blocked-by-stuck-flag' }),
    );
    expect(blocked.status).toBe(409);

    const loginRes = await mutate('post', '/api/v1/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
    });
    expect(loginRes.status).toBe(200);

    const recovered = await User.findById(user.id).lean();
    expect(recovered!.rotationInProgress).toBe(false);
    // The FLAG is lowered and nothing else: the pending wrapper is the only stored
    // copy of the key the crashed rotation had already sealed rows under, so it
    // survives until a rotation commits. See `rotation-interrupted-recovery.test.ts`.
    expect(recovered!.pendingEncryptedVaultKey).toBe('half-rotated-key');
    expect(recovered!.pendingVaultKeyIv).toBe('half-rotated-iv');
    expect(recovered!.pendingVaultKeyTag).toBe('half-rotated-tag');

    const unblocked = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'unblocked-after-recovery' }),
    );
    expect(unblocked.status).toBe(201);
  });

  // ── Login must NOT lower a LIVE fence ───────────────────────────────
  //
  // `rotationInProgress` doubles as the live write-fence. A rotation that is
  // still processing holds the `vault-rotation:<userId>` JobLock for its whole
  // window, so a concurrent login must tell "crashed" (no live lock → clear the
  // stuck flag) from "in flight" (lock held → leave the fence up). Clearing a
  // live fence would readmit a second session's stale-key write that the
  // rotation's enumerated set does not cover — the exact data loss the fence
  // closes.
  //
  // That lock now has four other holders — the import, the restore, the document
  // completion and the master-password change all take it across their own
  // check-to-commit spans — so "lock held" means "somebody is mid-span", not
  // "a rotation is live". The implication the login branch needs still runs the
  // right way: a live rotation always holds it, so a `false` answer is still
  // proof that no rotation is running, and a `true` answer merely DEFERS the
  // cleanup of a stuck flag to the next login. What the cases below pin is that
  // branch, so they take the lock by hand and say nothing about who holds it.

  it('leaves the fence up on login while a rotation is actively in progress (lock held)', async () => {
    // A LIVE rotation: the flag is committed AND the rotation lock is held with a
    // future expiry (bulkReEncrypt holds it for the entire flag-true window).
    await JobLock.create({
      jobName: `vault-rotation:${user.id}`,
      lockedBy: 'rotation-in-flight',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });
    await setRotating(true);

    // The fence is up before the login lands.
    const blockedBefore = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'blocked-before-concurrent-login' }),
    );
    expect(blockedBefore.status).toBe(409);

    const loginRes = await mutate('post', '/api/v1/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
    });
    expect(loginRes.status).toBe(200);

    // Login must NOT have cleared the live fence, and must NOT have logged a
    // spurious recovery. (Against the pre-fix code the flag would be false, the
    // recovery count 1, and the write below would 201 — stranding that row.)
    const after = await User.findById(user.id).lean();
    expect(after!.rotationInProgress).toBe(true);
    expect(await AuditLog.countDocuments({ action: 'rotation_recovery' })).toBe(0);

    const blockedAfter = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'still-blocked-after-concurrent-login' }),
    );
    expect(blockedAfter.status).toBe(409);
  });

  it('clears the flag on login once the rotation lock has expired (crashed rotation)', async () => {
    // A crashed rotation: the flag is stuck and the lock row lingers but its
    // expiry is in the past (the TTL reaper may not have removed it yet). Login
    // must treat an expired lock as a crash and recover, exactly as it does when
    // no lock row remains at all.
    await JobLock.create({
      jobName: `vault-rotation:${user.id}`,
      lockedBy: 'crashed-rotation',
      lockedAt: new Date(Date.now() - 10 * 60 * 1000),
      expiresAt: new Date(Date.now() - 1000),
    });
    await setRotating(true);

    const loginRes = await mutate('post', '/api/v1/auth/login', {
      email: user.email,
      authHash: user.rawPassword,
    });
    expect(loginRes.status).toBe(200);

    const recovered = await User.findById(user.id).lean();
    expect(recovered!.rotationInProgress).toBe(false);

    const unblocked = await mutate(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedName: 'unblocked-after-expired-lock' }),
    );
    expect(unblocked.status).toBe(201);
  });
});
