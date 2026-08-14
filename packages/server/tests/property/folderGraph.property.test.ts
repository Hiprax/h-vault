/**
 * The folder forest, as a MODEL-BASED property test against a real mongod.
 *
 * Folders are the one user-facing structure in this vault with a shape that can
 * be corrupted rather than merely wrong. Two invariants hold it together:
 *
 *   1. **No cycle.** A cycle makes every folder in it vanish from the client's
 *      tree builder — the items are still there, but nothing renders them — and
 *      `getAncestorChain` can only report it after the fact.
 *   2. **No chain deeper than `MAX_FOLDER_NESTING_DEPTH`.** The guard exists
 *      because the traversal, the UI indentation and the restore path all assume
 *      a bounded depth.
 *
 * Three handlers can move an edge: create (with a parent), re-parent, and delete
 * (which PROMOTES the deleted folder's children to its own parent). Each guards
 * itself, and each guard is correct on its own — so the interesting failures live
 * in the SEQUENCES, which is exactly what a model-based test explores and what no
 * example test enumerates.
 *
 * The model is an in-memory parent map plus three walks over it (depth, height,
 * ancestry). That is the "simple reference implementation" the second half of this
 * file compares `hasCycle` against, and it is deliberately NOT a copy of the
 * production traversal: the production one is a `$graphLookup` aggregation with a
 * `maxDepth` and a `restrictSearchWithMatch`, the model is a `while` loop over a
 * `Map`. Two independent computations of the same predicate is the point.
 *
 * The seam is the real Express app over a real mongod, through the real routes —
 * no stubbed guard, no faked aggregation.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import mongoose from 'mongoose';
import request from 'supertest';
import { MAX_FOLDERS_PER_USER, MAX_FOLDER_NESTING_DEPTH } from '@hvault/shared';
import app from '../../src/app.js';
import { Folder } from '../../src/models/Folder.js';
import { getAncestorChain, hasCycle } from '../../src/utils/folderGraph.js';
import { authHeader, createTestUser, getCsrf, sampleFolder, type TestUser } from '../helpers.js';
import { HEAVY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

const BASE = '/api/v1/folders';

let user: TestUser;
let agent: request.Agent;
let csrf: { cookie: string; token: string };

beforeEach(async () => {
  user = await createTestUser();
  agent = request.agent(app);
  csrf = await getCsrf(agent);
});

// ---------------------------------------------------------------------------
// The reference implementation: a parent map and three walks over it
// ---------------------------------------------------------------------------

/**
 * The forest as the test understands it: folder id -> parent id (or `null` for a
 * root). Every predicate below is computed from this map alone.
 */
class ForestModel {
  readonly parents = new Map<string, string | null>();

  add(id: string, parentId: string | null): void {
    this.parents.set(id, parentId);
  }

  /** Every folder id, in insertion order. */
  ids(): string[] {
    return [...this.parents.keys()];
  }

  /**
   * The ancestor chain of `id`, nearest first, stopping at a root, at a missing
   * parent, or as soon as a node repeats (which is how a walk through a cycle
   * terminates). Bounded by the number of folders, like the production traversal.
   */
  ancestors(id: string): string[] {
    const chain: string[] = [];
    const seen = new Set<string>([id]);
    let current = this.parents.get(id) ?? null;

    while (current !== null && chain.length <= MAX_FOLDERS_PER_USER) {
      chain.push(current);
      if (seen.has(current)) break;
      seen.add(current);
      current = this.parents.get(current) ?? null;
    }
    return chain;
  }

  /**
   * The reference `hasCycle`: is `id` its OWN ancestor?
   *
   * Deliberately self-membership, matching the predicate under test rather than a
   * depth heuristic — a node whose chain LEADS INTO a cycle it is not part of is
   * not itself in a cycle, and `getAncestorChain` reports it as such.
   */
  isInCycle(id: string): boolean {
    return this.ancestors(id).includes(id);
  }

  /** 1 for a root, 1 + ancestors for anything else. Meaningless inside a cycle. */
  depth(id: string): number {
    return this.ancestors(id).length + 1;
  }

  /** Levels from `id` down to its deepest descendant, inclusive (a leaf is 1). */
  height(id: string): number {
    const children = [...this.parents.entries()]
      .filter(([, parent]) => parent === id)
      .map(([child]) => child);
    if (children.length === 0) return 1;
    return 1 + Math.max(...children.map((child) => this.height(child)));
  }

  /** Does `candidate` sit anywhere below `ancestorId`? */
  isDescendantOf(candidate: string, ancestorId: string): boolean {
    return this.ancestors(candidate).includes(ancestorId);
  }

  /** The deepest chain anywhere in the forest. */
  maxDepth(): number {
    return this.ids().reduce((deepest, id) => Math.max(deepest, this.depth(id)), 0);
  }

  /** What `deleteFolder` does: promote the children, then drop the folder. */
  remove(id: string): void {
    const parentOfDeleted = this.parents.get(id) ?? null;
    for (const [child, parent] of this.parents) {
      if (parent === id) this.parents.set(child, parentOfDeleted);
    }
    this.parents.delete(id);
  }

  reParent(id: string, parentId: string | null): void {
    this.parents.set(id, parentId);
  }
}

/** The parent map as the DATABASE holds it, for the same user. */
async function readForest(userId: string): Promise<Map<string, string | null>> {
  const rows = await Folder.find({ userId }).select('_id parentId').lean();
  return new Map(rows.map((row) => [String(row._id), row.parentId ? String(row.parentId) : null]));
}

/** The two structural invariants, checked against the DATABASE after every step. */
async function assertForestIsSound(context: string): Promise<void> {
  const forest = await readForest(user.id);
  const mirror = new ForestModel();
  for (const [id, parentId] of forest) mirror.add(id, parentId);

  for (const id of mirror.ids()) {
    expect(mirror.isInCycle(id), `${context} — ${id} is its own ancestor in the database`).toBe(
      false,
    );
    // The production predicate must agree with the model on every node, not only
    // where the model expects trouble.
    expect(await hasCycle(id, user.id), `${context} — hasCycle disagreed on ${id}`).toBe(false);
  }
  expect(mirror.maxDepth(), `${context} — the forest is deeper than the cap`).toBeLessThanOrEqual(
    MAX_FOLDER_NESTING_DEPTH,
  );
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function apiCreate(parentId: string | null): Promise<request.Response> {
  return agent
    .post(BASE)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .send(sampleFolder(parentId === null ? {} : { parentId }));
}

async function apiReParent(id: string, parentId: string | null): Promise<request.Response> {
  return agent
    .put(`${BASE}/${id}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .send({ parentId });
}

async function apiDelete(id: string): Promise<request.Response> {
  return agent
    .delete(`${BASE}/${id}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

/**
 * The "real system" side of the model run.
 *
 * It carries the model rather than a client, because the real system here is the
 * live Express app over the live mongod, reached through the module-scope
 * supertest agent and account that `beforeEach` creates — there is nothing to
 * thread through. Declared anyway so `fc.asyncModelRun`'s two type parameters
 * stay explicit rather than inferred as `unknown`.
 */
interface Real {
  model: ForestModel;
}

/**
 * Which decision branches the generated sequences actually REACHED.
 *
 * Asserted after the property, and that assertion is load-bearing rather than
 * decorative: a model-based test whose sequences never attempt a cycle proves
 * nothing about the cycle guard, and it fails SILENTLY — measured, on the first
 * version of this file, by deleting `ancestorIds.includes(id)` from
 * `updateFolder` and watching the property stay green. Counting the branches
 * turns "the sample happened to be boring" into a red run.
 *
 * The two branches a 12-command sequence CANNOT reach — a create under a parent
 * already at the 50-deep cap, and a re-parent that would push a subtree past it —
 * are covered by their own deterministic tests below, against a directly seeded
 * chain. Claiming them here would be claiming coverage that does not exist.
 */
const reached = {
  createUnderParent: 0,
  reParentAccepted: 0,
  reParentSelf: 0,
  reParentCycle: 0,
  deleteWithChildren: 0,
};

type FolderCommand = fc.AsyncCommand<ForestModel, Real>;

/**
 * `pick` is an unbounded index taken MODULO the live folder count, not a 0-1
 * fraction and not an index into a fixed list.
 *
 * Two reasons, and the second was measured. A command is generated BEFORE it is
 * known how many folders exist when it runs, so the index has to be resolved
 * against the live list — that is what keeps a generated sequence meaningful
 * after an earlier delete. And a `fc.double({ min: 0, max: 1 })` fraction is the
 * wrong shape for this: fast-check biases a double hard towards its boundary
 * values, so `childPick` and `parentPick` were BOTH 0 or BOTH 1 almost every
 * time, and 17 of 17 generated re-parents were self-parents. `fc.nat` spreads
 * across the range instead.
 */
function resolve(ids: string[], pick: number): string | null {
  if (ids.length === 0) return null;
  return ids[pick % ids.length] ?? null;
}

class CreateFolder implements FolderCommand {
  constructor(
    private readonly pick: number,
    private readonly underParent: boolean,
    private readonly deepen: boolean,
  ) {}

  check(): boolean {
    return true;
  }

  async run(model: ForestModel): Promise<void> {
    const ids = model.ids();
    const parentId = this.underParent
      ? this.deepen
        ? (ids[ids.length - 1] ?? null)
        : resolve(ids, this.pick)
      : null;
    // What the guard must decide: a new folder under a parent already at the cap
    // is refused, and nothing else is.
    const expectRefusal = parentId !== null && model.depth(parentId) >= MAX_FOLDER_NESTING_DEPTH;

    const response = await apiCreate(parentId);

    if (expectRefusal) {
      expect(
        response.status,
        `create under depth-${String(model.depth(parentId ?? ''))} parent`,
      ).toBe(400);
      expect(String(response.body.message)).toMatch(/nesting depth/i);
    } else {
      expect(response.status, 'create').toBe(201);
      model.add(String(response.body.data._id), parentId);
      if (parentId !== null) reached.createUnderParent++;
    }
    await assertForestIsSound('after create');
  }

  toString(): string {
    if (!this.underParent) return 'create(at root)';
    return `create(under ${this.deepen ? 'newest' : `#${String(this.pick)}`})`;
  }
}

class ReParentFolder implements FolderCommand {
  constructor(
    private readonly childPick: number,
    private readonly parentPick: number,
    private readonly toRoot: boolean,
  ) {}

  check(model: ForestModel): boolean {
    return model.ids().length > 0;
  }

  async run(model: ForestModel): Promise<void> {
    const ids = model.ids();
    const child = resolve(ids, this.childPick);
    if (child === null) return;
    const parent = this.toRoot ? null : resolve(ids, this.parentPick);

    if (parent === null) {
      // Detaching to the root can never create a cycle and can only reduce depth,
      // so it must always be accepted.
      const response = await apiReParent(child, null);
      expect(response.status, 'detach to root').toBe(200);
      model.reParent(child, null);
      await assertForestIsSound('after detach');
      return;
    }

    // The prediction, computed entirely from the model: the server must refuse a
    // self-parent, a move under one's own descendant (a cycle), and a move that
    // would push the moved SUBTREE past the cap.
    const selfParent = parent === child;
    const wouldCycle = model.isDescendantOf(parent, child);
    const wouldOverflow = model.depth(parent) + model.height(child) > MAX_FOLDER_NESTING_DEPTH;
    const expectRefusal = selfParent || wouldCycle || wouldOverflow;

    const before = model.parents.get(child) ?? null;
    const response = await apiReParent(child, parent);

    if (selfParent) reached.reParentSelf++;
    if (wouldCycle) reached.reParentCycle++;

    if (expectRefusal) {
      expect(
        response.status,
        `re-parent ${child} under ${parent} (self=${String(selfParent)} cycle=${String(wouldCycle)} overflow=${String(wouldOverflow)})`,
      ).toBe(400);
      // A refused move must leave the edge exactly as it was: a guard that
      // rejected AFTER writing would satisfy a status-only assertion.
      const row = await Folder.findOne({ _id: child, userId: user.id }).select('parentId').lean();
      expect(row, 'the refused folder still exists').not.toBeNull();
      expect(row?.parentId ? String(row.parentId) : null, 'a refused move wrote anyway').toBe(
        before,
      );
    } else {
      expect(
        response.status,
        `re-parent ${child} under ${parent} at depth ${String(model.depth(parent))} + height ${String(model.height(child))}`,
      ).toBe(200);
      model.reParent(child, parent);
      reached.reParentAccepted++;
    }
    await assertForestIsSound('after re-parent');
  }

  toString(): string {
    return `reParent(#${String(this.childPick)} -> ${this.toRoot ? 'root' : `#${String(this.parentPick)}`})`;
  }
}

class DeleteFolder implements FolderCommand {
  constructor(private readonly pick: number) {}

  check(model: ForestModel): boolean {
    return model.ids().length > 0;
  }

  async run(model: ForestModel): Promise<void> {
    const id = resolve(model.ids(), this.pick);
    if (id === null) return;

    const hadChildren = [...model.parents.values()].includes(id);
    const response = await apiDelete(id);
    expect(response.status, 'delete').toBe(200);
    model.remove(id);
    if (hadChildren) reached.deleteWithChildren++;

    // The promotion is the part worth predicting: every child of the deleted
    // folder must now sit under the folder's own parent, not be orphaned and not
    // be deleted with it.
    const forest = await readForest(user.id);
    expect(forest.has(id), 'the deleted folder is gone').toBe(false);
    for (const modelId of model.ids()) {
      expect(forest.get(modelId) ?? null, `parent of ${modelId} after deleting ${id}`).toBe(
        model.parents.get(modelId) ?? null,
      );
    }
    await assertForestIsSound('after delete');
  }

  toString(): string {
    return `delete(#${String(this.pick)})`;
  }
}

// ---------------------------------------------------------------------------
// The model-based property
// ---------------------------------------------------------------------------

describe('folder forest — any sequence of create, re-parent and delete', () => {
  it('never produces a cycle, never exceeds the depth cap, and refuses exactly the operations that would', async () => {
    const commands = fc.commands(
      [
        fc
          .tuple(
            fc.nat({ max: 31 }),
            // Weighted towards creating UNDER something, and towards the newest
            // folder when it does: a flat forest has no ancestors, and a guard
            // about ancestry is then never exercised at all.
            fc.oneof(
              { weight: 3, arbitrary: fc.constant(true) },
              { weight: 1, arbitrary: fc.constant(false) },
            ),
            fc.oneof(
              { weight: 2, arbitrary: fc.constant(true) },
              { weight: 1, arbitrary: fc.constant(false) },
            ),
          )
          .map(([pick, underParent, deepen]) => new CreateFolder(pick, underParent, deepen)),
        fc
          .tuple(
            fc.nat({ max: 31 }),
            fc.nat({ max: 31 }),
            // Weighted towards a real parent: detaching to the root is the easy
            // case and should not dominate the sample.
            fc.oneof(
              { weight: 4, arbitrary: fc.constant(false) },
              { weight: 1, arbitrary: fc.constant(true) },
            ),
          )
          .map(
            ([childPick, parentPick, toRoot]) => new ReParentFolder(childPick, parentPick, toRoot),
          ),
        fc.nat({ max: 31 }).map((pick) => new DeleteFolder(pick)),
      ],
      // `size: 'large'` on purpose: fast-check biases command counts SMALL by
      // default, and a two-folder forest has no ancestry — so the guards under
      // test are never asked anything. Measured: with the default size, every
      // single re-parent the sample attempted was a self-parent.
      { maxCommands: 12, size: 'large' },
    );

    await fc.assert(
      fc.asyncProperty(commands, async (sequence) => {
        // Each run starts from an empty forest for this account. The suite's
        // `afterEach` truncation is per TEST, and a property runs many times
        // inside one, so the reset belongs here.
        await Folder.deleteMany({ userId: user.id });
        const model = new ForestModel();
        // Every run starts from a THREE-DEEP CHAIN rather than from nothing.
        // Ancestry is the precondition for every interesting decision — a cycle
        // needs a descendant to move under, a promotion needs a grandchild — and a
        // sequence that has to build one first spends most of its commands on
        // scaffolding. Seeded through the real API, so the starting state is one
        // the product itself can produce.
        let parentId: string | null = null;
        for (let level = 0; level < 3; level++) {
          const seeded = await apiCreate(parentId);
          expect(seeded.status, 'seeding the starting chain').toBe(201);
          parentId = String(seeded.body.data._id);
          model.add(parentId, level === 0 ? null : (model.ids()[level - 1] ?? null));
        }
        await fc.asyncModelRun(() => ({ model, real: { model } }), sequence);
      }),
      // 15 sequences of up to 12 commands: measured at ~1.2s against a real
      // mongod, which is what the budget buys here. Each command already makes
      // several HTTP round trips and two invariant queries per folder, so the
      // exploration per run is far larger than the run count suggests.
      propertyRun({ numRuns: 3 * HEAVY_RUNS }),
    );

    // The sample must have ASKED the guards something. Each of these is a
    // decision branch the property claims to cover, and a generator change that
    // stopped reaching one would otherwise leave this test green while testing
    // less — the exact failure this file was measured to have before the
    // creation bias above was added.
    expect(reached.createUnderParent, 'no folder was ever created under a parent').toBeGreaterThan(
      0,
    );
    expect(reached.reParentAccepted, 'no re-parent was ever accepted').toBeGreaterThan(0);
    expect(reached.reParentSelf, 'no self-parent was ever attempted').toBeGreaterThan(0);
    expect(reached.reParentCycle, 'no cycle-forming re-parent was ever attempted').toBeGreaterThan(
      0,
    );
    expect(reached.deleteWithChildren, 'no folder with children was ever deleted').toBeGreaterThan(
      0,
    );
  });
});

describe('folder forest — the depth cap, at the exact bound', () => {
  // The two refusal branches a 12-command sequence cannot reach, because reaching
  // them needs a 50-deep chain. Driven against a directly seeded chain instead of
  // being claimed as property coverage that does not exist.

  it('refuses a create under a parent already at the maximum depth, and allows one below it', async () => {
    await Folder.deleteMany({ userId: user.id });
    const chain = await seedForest(
      Array.from({ length: MAX_FOLDER_NESTING_DEPTH }, (_, index) =>
        index === 0 ? null : index - 1,
      ),
    );

    const atCap = await apiCreate(chain[chain.length - 1] ?? null);
    expect(atCap.status, 'create under the deepest folder').toBe(400);
    expect(String(atCap.body.message)).toMatch(/nesting depth/i);

    // One level up is depth 49, so a child there lands exactly AT the cap and must
    // be accepted: the bound is `>=`, and an off-by-one here would refuse a legal
    // folder rather than an illegal one.
    const oneAbove = await apiCreate(chain[chain.length - 2] ?? null);
    expect(oneAbove.status, 'create under the second-deepest folder').toBe(201);
    await assertForestIsSound('after a create at the cap');
  });

  it('refuses a re-parent that would push the moved SUBTREE past the cap', async () => {
    await Folder.deleteMany({ userId: user.id });
    // A chain two short of the cap, plus a separate three-deep subtree.
    const trunk = await seedForest(
      Array.from({ length: MAX_FOLDER_NESTING_DEPTH - 2 }, (_, index) =>
        index === 0 ? null : index - 1,
      ),
    );
    const deepest = trunk[trunk.length - 1] ?? '';

    const top = await apiCreate(null);
    const middle = await apiCreate(String(top.body.data._id));
    await apiCreate(String(middle.body.data._id));
    const movedRoot = String(top.body.data._id);

    // depth(deepest) = 48, height(movedRoot) = 3 -> 51 > 50.
    const refused = await apiReParent(movedRoot, deepest);
    expect(refused.status, 'move a height-3 subtree under a depth-48 folder').toBe(400);
    expect(String(refused.body.message)).toMatch(/nesting depth/i);

    // The subtree is untouched: a guard that rejected after writing would leave the
    // forest over-deep while reporting a refusal.
    const row = await Folder.findOne({ _id: movedRoot, userId: user.id }).select('parentId').lean();
    expect(row?.parentId ?? null, 'a refused move wrote anyway').toBeNull();

    // One level higher fits exactly: 47 + 3 = 50.
    const accepted = await apiReParent(movedRoot, trunk[trunk.length - 2] ?? '');
    expect(accepted.status, 'the same move one level higher').toBe(200);
    await assertForestIsSound('after a re-parent that exactly fills the cap');
  });
});

// ---------------------------------------------------------------------------
// hasCycle against the reference, over graphs the API cannot produce
// ---------------------------------------------------------------------------

/**
 * Writes a parent map DIRECTLY, bypassing every controller guard.
 *
 * That is not a shortcut: `restoreBackup` writes folder rows straight from a
 * backup file, so a tampered backup really can plant a cycle — which is the whole
 * reason `hasCycle` exists and why its traversal is bounded by
 * `MAX_FOLDERS_PER_USER` rather than by the nesting cap.
 */
async function seedForest(edges: (number | null)[]): Promise<string[]> {
  const ids = edges.map(() => new mongoose.Types.ObjectId());
  await Folder.insertMany(
    ids.map((id, index) => {
      const parentIndex = edges[index];
      return {
        _id: id,
        userId: new mongoose.Types.ObjectId(user.id),
        ...sampleFolder(),
        ...(parentIndex === null || parentIndex === undefined
          ? {}
          : { parentId: ids[parentIndex % ids.length] }),
      };
    }),
  );
  return ids.map(String);
}

describe('hasCycle agrees with a simple reference implementation', () => {
  it('matches the reference on an arbitrary directly-written parent graph', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Each node points at another node BY INDEX, or at nothing. An arbitrary
        // functional graph: forests, chains, self-loops and multi-node cycles all
        // occur, and none of them can be created through the API.
        fc.array(fc.option(fc.nat({ max: 11 }), { nil: null }), { minLength: 1, maxLength: 12 }),
        async (edges) => {
          await Folder.deleteMany({ userId: user.id });
          const ids = await seedForest(edges);

          const model = new ForestModel();
          edges.forEach((parentIndex, index) => {
            const id = ids[index];
            if (id === undefined) return;
            model.add(id, parentIndex === null ? null : (ids[parentIndex % ids.length] ?? null));
          });

          for (const id of ids) {
            expect(
              await hasCycle(id, user.id),
              `${propertyBanner()} — hasCycle disagreed on ${id} for edges ${JSON.stringify(edges)}`,
            ).toBe(model.isInCycle(id));
          }
        },
      ),
      // 20 graphs of up to 12 nodes, each node queried through the real
      // aggregation: ~240 `$graphLookup` round trips per run of this property.
      propertyRun({ numRuns: 4 * HEAVY_RUNS }),
    );
  });

  it('leaves a legitimate acyclic chain at the maximum nesting depth alone', async () => {
    // The case the predicate is deliberately NOT a depth test for: a chain of
    // exactly `MAX_FOLDER_NESTING_DEPTH` folders is legal, and flagging it would
    // detach a valid leaf. Generated at exactly the cap, not near it.
    await Folder.deleteMany({ userId: user.id });
    const edges = Array.from({ length: MAX_FOLDER_NESTING_DEPTH }, (_, index) =>
      index === 0 ? null : index - 1,
    );
    const ids = await seedForest(edges);

    for (const id of ids) {
      expect(await hasCycle(id, user.id), `hasCycle flagged an acyclic chain at ${id}`).toBe(false);
    }
    // And the chain really is that deep, so the assertion above is about what it
    // claims to be: the leaf's ancestor chain is one short of the cap.
    const leaf = ids[ids.length - 1] ?? '';
    const { depth } = await getAncestorChain(leaf, user.id, MAX_FOLDERS_PER_USER);
    expect(depth).toBe(MAX_FOLDER_NESTING_DEPTH);
  });

  it('detects a cycle LONGER than the nesting cap, which a depth-bounded walk would miss', async () => {
    // `hasCycle` bounds its traversal by `MAX_FOLDERS_PER_USER`, not by the
    // nesting cap, precisely so a restore-planted cycle of 52 folders is still
    // found: the start node only re-enters its own ancestor set at recursion depth
    // `cycleLength - 1`.
    await Folder.deleteMany({ userId: user.id });
    const length = MAX_FOLDER_NESTING_DEPTH + 2;
    const edges = Array.from({ length }, (_, index) => (index === 0 ? length - 1 : index - 1));
    const ids = await seedForest(edges);

    for (const id of ids) {
      expect(await hasCycle(id, user.id), `hasCycle missed a ${String(length)}-folder cycle`).toBe(
        true,
      );
    }
  });

  it('reports a node whose chain LEADS INTO a cycle it is not part of as cycle-free', async () => {
    // The distinction the predicate is built on: self-membership, not "the walk
    // never terminates". X -> A -> B -> A leaves X outside the cycle, and
    // detaching X would be wrong.
    await Folder.deleteMany({ userId: user.id });
    const ids = await seedForest([1, 2, 1]);
    const [outside, inFirst, inSecond] = ids as [string, string, string];

    expect(await hasCycle(outside, user.id)).toBe(false);
    expect(await hasCycle(inFirst, user.id)).toBe(true);
    expect(await hasCycle(inSecond, user.id)).toBe(true);
  });
});
