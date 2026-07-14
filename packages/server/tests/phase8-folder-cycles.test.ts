/**
 * Phase 8 — folders: single ancestor query + concurrent-cycle guard.
 *
 * Covers two defects in `folderController.updateFolder`:
 *
 *  - #6 (efficiency): a re-parent ran TWO identical `$graphLookup` ancestor
 *    aggregations — one for the depth guard, one inside the circular-reference
 *    helper. It now runs exactly one, whose `ancestorIds` serve the circular
 *    check inline.
 *  - #5 (race): the circular pre-check and the `findOneAndUpdate` are not
 *    atomic, so simultaneous A → B and B → A re-parents could each pass their
 *    own check and together persist a 2-cycle (which makes both folders vanish
 *    from the client's tree builder). A post-write `hasCycle` re-check now
 *    reverts the just-written `parentId` and returns 409.
 *
 * The race is reproduced DETERMINISTICALLY by wrapping `getAncestorChain` and
 * landing the opposite edge right after it resolves — i.e. exactly in the
 * window between this request's check and its write.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MAX_FOLDER_NESTING_DEPTH } from '@hvault/shared';
import app from '../src/app.js';
import { Folder } from '../src/models/Folder.js';
import { getAncestorChain, hasCycle } from '../src/utils/folderGraph.js';
import { createTestUser, authHeader, sampleFolder, getCsrf, type TestUser } from './helpers.js';

// A hook fired immediately AFTER `getAncestorChain` resolves — i.e. after
// `updateFolder` has read the ancestor chain its circular check relies on, but
// before it writes. Simulates a concurrent request's write landing in that gap.
const race = vi.hoisted(() => ({ afterAncestorChain: null as (() => Promise<void>) | null }));

vi.mock('../src/utils/folderGraph.js', async () => {
  const actual = await vi.importActual<typeof import('../src/utils/folderGraph.js')>(
    '../src/utils/folderGraph.js',
  );
  return {
    ...actual,
    // `hasCycle` stays REAL: it is the guard under test, and it calls the real
    // module-internal `getAncestorChain`, so it is unaffected by this wrapper.
    getAncestorChain: vi.fn(async (folderId: string, userId: string, maxDepth?: number) => {
      const result = await actual.getAncestorChain(folderId, userId, maxDepth);
      if (race.afterAncestorChain) {
        const hook = race.afterAncestorChain;
        race.afterAncestorChain = null;
        await hook();
      }
      return result;
    }),
  };
});

const FOLDER_BASE = '/api/v1/folders';

const oid = (id: string): mongoose.Types.ObjectId => new mongoose.Types.ObjectId(id);

describe('Phase 8 — folder re-parent: single ancestor query + concurrent-cycle guard', () => {
  let user: TestUser;
  let agent: request.Agent;
  let csrf: { cookie: string; token: string };

  beforeEach(async () => {
    vi.clearAllMocks();
    race.afterAncestorChain = null;
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  // ── Helpers ────────────────────────────────────────────────────────

  async function apiCreateFolder(overrides: Record<string, unknown> = {}) {
    const res = await agent
      .post(FOLDER_BASE)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleFolder(overrides));
    expect(res.status).toBe(201);
    return res.body.data as { _id: string };
  }

  /** PUTs a re-parent of `id` under `parentId`. */
  function putParent(id: string, parentId: string): request.Test {
    return agent
      .put(`${FOLDER_BASE}/${id}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({ parentId });
  }

  /** Creates a parent→child chain of `length` folders directly in the DB. */
  async function buildChain(length: number, prefix: string): Promise<string[]> {
    const ids: string[] = [];
    for (let i = 0; i < length; i++) {
      const folder = await Folder.create({
        userId: user.id,
        ...sampleFolder({
          encryptedName: `${prefix}-${String(i)}`,
          ...(i > 0 ? { parentId: ids[i - 1] } : {}),
        }),
      });
      ids.push(String(folder._id));
    }
    return ids;
  }

  /** Reads a folder's raw `parentId` (undefined when unset). */
  async function rawParentId(id: string): Promise<string | undefined> {
    const doc = await mongoose.connection.db!.collection('folders').findOne({ _id: oid(id) });
    const parentId = doc?.parentId as mongoose.Types.ObjectId | undefined;
    return parentId ? String(parentId) : undefined;
  }

  // ── #6 — one ancestor traversal per re-parent ──────────────────────

  describe('single ancestor query (#6)', () => {
    it('runs exactly ONE getAncestorChain per re-parent (was two)', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'one-p' });
      const child = await apiCreateFolder({ encryptedName: 'one-c' });

      vi.mocked(getAncestorChain).mockClear();

      const res = await putParent(child._id, parent._id);

      expect(res.status).toBe(200);
      // The depth guard and the circular check now share a single traversal.
      // (`hasCycle`'s post-write check calls the real, module-internal
      // `getAncestorChain`, so it is not counted here.)
      expect(vi.mocked(getAncestorChain)).toHaveBeenCalledTimes(1);
    });

    it('still rejects a direct circular re-parent (A → B → A) with 400', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'circ-a' });
      const folderB = await apiCreateFolder({
        encryptedName: 'circ-b',
        parentId: folderA._id,
      });

      const res = await putParent(folderA._id, folderB._id);

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Circular folder reference detected');
      expect(await rawParentId(folderA._id)).toBeUndefined();
    });

    it('still enforces the exact depth cap on a re-parent (50 allowed, 51 rejected)', async () => {
      expect(MAX_FOLDER_NESTING_DEPTH).toBe(50);

      // Parent chain p[0..48]: p[47] sits at depth 48, p[48] at depth 49.
      const p = await buildChain(49, 'cap');
      // Two-level subtree (height 2) rooted at s[0].
      const s = await buildChain(2, 'leaf');

      // 48 + 2 = 50 → the deepest leaf lands exactly at the cap → allowed.
      const allowRes = await putParent(s[0]!, p[47]!);
      expect(allowRes.status).toBe(200);

      // 49 + 2 = 51 → one past the cap → rejected.
      const rejectRes = await putParent(s[0]!, p[48]!);
      expect(rejectRes.status).toBe(400);
      expect(rejectRes.body.message).toContain('Maximum folder nesting depth exceeded');

      // The rejected move must not have been applied.
      expect(await rawParentId(s[0]!)).toBe(p[47]!);
    });

    it('allows a legitimate re-parent (the new guard does not false-positive)', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'ok-p' });
      const child = await apiCreateFolder({ encryptedName: 'ok-c' });

      const res = await putParent(child._id, parent._id);

      expect(res.status).toBe(200);
      expect(res.body.data.parentId).toBe(parent._id);
      expect(await rawParentId(child._id)).toBe(parent._id);
      await expect(hasCycle(child._id, user.id)).resolves.toBe(false);
    });
  });

  // ── #5 — post-write cycle guard ────────────────────────────────────

  describe('concurrent re-parent cycle guard (#5)', () => {
    it('reverts and 409s when the opposite edge lands between the check and the write', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'toctou-a' });
      const folderB = await apiCreateFolder({ encryptedName: 'toctou-b' });

      // Request under test: move A under B. Its circular pre-check reads B's
      // ancestor chain (empty → passes). The racing request's write (B under A)
      // lands in the gap right after, so the committed state is a 2-cycle.
      race.afterAncestorChain = async () => {
        await mongoose.connection
          .db!.collection('folders')
          .updateOne({ _id: oid(folderB._id) }, { $set: { parentId: oid(folderA._id) } });
      };

      const res = await putParent(folderA._id, folderB._id);

      // The pre-check could not see it; the post-write check must.
      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Circular folder reference detected');

      // The edge this request wrote is reverted; the racing request's edge stays.
      expect(await rawParentId(folderA._id)).toBeUndefined();
      expect(await rawParentId(folderB._id)).toBe(folderA._id);

      // No cycle survives, so neither folder can vanish from the tree.
      await expect(hasCycle(folderA._id, user.id)).resolves.toBe(false);
      await expect(hasCycle(folderB._id, user.id)).resolves.toBe(false);
    });

    it('leaves no persistent cycle when A → B and B → A are re-parented concurrently', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'conc-a' });
      const folderB = await apiCreateFolder({ encryptedName: 'conc-b' });

      const [resAB, resBA] = await Promise.all([
        putParent(folderA._id, folderB._id),
        putParent(folderB._id, folderA._id),
      ]);

      // Whatever the interleaving, each request is either applied (200),
      // rejected up front (400), or reverted after the fact (409).
      for (const res of [resAB, resBA]) {
        expect([200, 400, 409]).toContain(res.status);
      }

      // Both cannot win — that is exactly the state that would persist a cycle.
      expect([resAB.status, resBA.status].filter((s) => s === 200).length).toBeLessThanOrEqual(1);

      // The invariant that actually matters, regardless of who won.
      await expect(hasCycle(folderA._id, user.id)).resolves.toBe(false);
      await expect(hasCycle(folderB._id, user.id)).resolves.toBe(false);

      const parentOfA = await rawParentId(folderA._id);
      const parentOfB = await rawParentId(folderB._id);
      expect(parentOfA === folderB._id && parentOfB === folderA._id).toBe(false);
    });
  });
});
