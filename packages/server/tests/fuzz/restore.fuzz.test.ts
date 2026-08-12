/**
 * Fuzzing `POST /backup/restore` — the folder-graph remapping in particular.
 *
 * A backup document is an untrusted file. It arrives from the user's own disk,
 * it may have been written by another account, it may have been hand-edited,
 * and its `_id` values are GLOBALLY unique across the whole collection rather
 * than scoped to the caller. So the restore path has to survive every shape a
 * graph can take and still leave the account in a state the app can walk.
 *
 * The contract this suite pins:
 *
 *   1. **A forest, or a refusal.** After any restore that returns 2xx, no
 *      folder is its own ancestor, none is its own parent, and no `parentId`
 *      points at a folder that does not exist. A cycle is not a cosmetic
 *      problem: every tree walker in the app — the sidebar, the depth check,
 *      `getAncestorChain` — loops on one.
 *   2. **No row is lost to a swallowed duplicate key.** The per-row `try` in
 *      the controller swallows `ValidationError`, `CastError` and **E11000**
 *      as a per-row skip. That is right for genuinely malformed data and was
 *      catastrophic for a duplicate key: reusing a backup's `_id` on a
 *      cross-account restore threw E11000 for every row, each was swallowed as
 *      a skip, and the restore reported success having written nothing. This
 *      suite refuses `invalid_item_data` / `invalid_folder_data` for any row
 *      that is well-formed, and separately requires every such row to be
 *      findable in the database afterwards.
 *   3. **Everything is accounted for.** `restored + skipped` equals the number
 *      of rows sent, in both collections. A row that is neither is a row nobody
 *      will ever look for.
 *   4. **A repeat restore is a no-op.** Sending the same document twice under
 *      `skip` or `overwrite` must not grow the collection.
 *
 * ---------------------------------------------------------------------------
 * THE SEAM, AND THE ORACLE
 * ---------------------------------------------------------------------------
 *
 * The real Express app over a real mongod, through the real route, the real
 * middleware and the real Mongoose models — including the unique partial
 * `(userId, searchHash)` index on folders, which is what makes E11000 reachable
 * at all. Nothing is mocked.
 *
 * The acyclicity oracle is an INDEPENDENT walker over the parent map read back
 * from the database, not the production `hasCycle`. Using the predicate the
 * controller itself calls would only prove the controller agrees with itself;
 * `hasCycle` is checked against its own reference implementation in
 * `tests/property/folderGraph.property.test.ts`, which is a different question.
 *
 * Nesting DEPTH is deliberately not asserted. `restoreBackup` breaks cycles and
 * clears dangling parents but never enforces `MAX_FOLDER_NESTING_DEPTH` — by
 * design, because the guard is a self-membership predicate precisely so a
 * legitimate acyclic chain at the cap survives. A depth assertion here would be
 * inventing a rule the endpoint does not have.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import fc from 'fast-check';
import app from '../../src/app.js';
import { Folder } from '../../src/models/Folder.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { createTestUser, authHeader, getCsrf, seedFolder, seedItem } from '../helpers.js';
import type { TestUser } from '../helpers.js';
import { HEAVY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/**
 * The distinctive strings a failure prints.
 *
 * Matched by `verify:selftest`'s evidence predicate, and deliberately not test
 * NAMES: a JUnit report carries a `<testcase name=…>` for every test that ran,
 * so a name-matching predicate is satisfied by a fully green report.
 */
const CYCLE = 'restore fuzz: the restored folder graph contains a cycle';
const LOST_ROW = 'restore fuzz: a well-formed backup row was swallowed as a skip';

interface SkipReason {
  reason: string;
}

interface RestoreResult {
  status: number;
  itemsRestored: number;
  itemsSkipped: number;
  foldersRestored: number;
  foldersSkipped: number;
  itemSkipReasons: SkipReason[];
  folderSkipReasons: SkipReason[];
}

type ConflictStrategy = 'skip' | 'overwrite' | 'keep_both';

interface BackupDocument {
  folders: Record<string, unknown>[];
  items: Record<string, unknown>[];
}

async function restore(
  user: TestUser,
  document: BackupDocument,
  conflictStrategy: ConflictStrategy,
): Promise<RestoreResult> {
  const agent = request(app);
  const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
  const res = await agent
    .post('/api/v1/backup/restore')
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send({ conflictStrategy, data: JSON.stringify(document) });

  const data = (res.body as { data?: Partial<RestoreResult> }).data ?? {};
  return {
    status: res.status,
    itemsRestored: data.itemsRestored ?? 0,
    itemsSkipped: data.itemsSkipped ?? 0,
    foldersRestored: data.foldersRestored ?? 0,
    foldersSkipped: data.foldersSkipped ?? 0,
    itemSkipReasons: data.itemSkipReasons ?? [],
    folderSkipReasons: data.folderSkipReasons ?? [],
  };
}

/**
 * The independent oracle: every folder that is reachable from itself by
 * following `parentId`, walking the map read back from the database.
 *
 * Bounded by the number of folders rather than by a depth constant, so a cycle
 * longer than the nesting cap is still detected and a legitimate deep chain is
 * not mistaken for one.
 */
async function cyclicFolders(userId: string): Promise<string[]> {
  const rows = await Folder.find({ userId }).select('_id parentId').lean();
  const parentOf = new Map<string, string | undefined>(
    rows.map((row) => [
      String(row._id),
      row.parentId === undefined || row.parentId === null ? undefined : String(row.parentId),
    ]),
  );

  const cyclic: string[] = [];
  for (const start of parentOf.keys()) {
    const seen = new Set<string>([start]);
    let current = parentOf.get(start);
    for (let step = 0; step < parentOf.size + 1 && current !== undefined; step++) {
      if (seen.has(current)) {
        cyclic.push(start);
        break;
      }
      seen.add(current);
      current = parentOf.get(current);
    }
  }
  return cyclic;
}

/** Every `parentId` that names a folder the user does not have. */
async function danglingParents(userId: string): Promise<string[]> {
  const rows = await Folder.find({ userId }).select('_id parentId').lean();
  const ids = new Set(rows.map((row) => String(row._id)));
  return rows
    .filter((row) => row.parentId !== undefined && row.parentId !== null)
    .map((row) => String(row.parentId))
    .filter((parentId) => !ids.has(parentId));
}

/** The invariants that must hold after ANY 2xx restore, whatever was sent. */
async function assertForest(userId: string, label: string): Promise<void> {
  const cyclic = await cyclicFolders(userId);
  expect(
    cyclic,
    `${CYCLE} — after ${label}, ${String(cyclic.length)} folder(s) are their own ancestor. ` +
      `Every tree walker in the app loops on that. ${propertyBanner()}`,
  ).toEqual([]);

  const dangling = await danglingParents(userId);
  expect(
    dangling,
    `after ${label}, a parentId points at no folder: ${dangling.join(', ')}`,
  ).toEqual([]);

  const selfParented = await Folder.countDocuments({
    userId,
    $expr: { $eq: ['$parentId', '$_id'] },
  });
  expect(selfParented, `after ${label}, a folder is its own parent`).toBe(0);
}

/** Accounting: nothing sent may go unreported. */
function assertAccounting(result: RestoreResult, document: BackupDocument, label: string): void {
  expect(
    result.foldersRestored + result.foldersSkipped,
    `after ${label}, folder accounting does not add up`,
  ).toBe(document.folders.length);
  expect(
    result.itemsRestored + result.itemsSkipped,
    `after ${label}, item accounting does not add up`,
  ).toBe(document.items.length);
}

/** No row may be lost to a persistence error the controller swallowed. */
function assertNothingSwallowed(result: RestoreResult, label: string): void {
  const swallowed = [
    ...result.folderSkipReasons.filter((r) => r.reason === 'invalid_folder_data'),
    ...result.itemSkipReasons.filter((r) => r.reason === 'invalid_item_data'),
  ];
  expect(
    swallowed,
    `${LOST_ROW} — ${label} reported ${String(swallowed.length)} row(s) as invalid data. ` +
      `Every row sent here is well-formed, so the only way to get that reason is a ` +
      `duplicate key the per-row catch turned into a skip. ${propertyBanner()}`,
  ).toEqual([]);
}

const objectId = (): string => new mongoose.Types.ObjectId().toString();
const hash = (seed: string): string =>
  seed
    .padEnd(64, '0')
    .slice(0, 64)
    .replace(/[^a-f0-9]/g, 'a');

/** A well-formed backup folder row carrying whatever identity the caller chose. */
function backupFolder(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _id: objectId(),
    encryptedName: 'enc-folder',
    nameIv: 'iv',
    nameTag: 'tag',
    sortOrder: 0,
    ...overrides,
  };
}

/** A well-formed backup item row. */
function backupItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _id: objectId(),
    itemType: 'login',
    encryptedData: 'enc-data',
    dataIv: 'iv',
    dataTag: 'tag',
    encryptedName: 'enc-name',
    nameIv: 'iv',
    nameTag: 'tag',
    tags: [],
    favorite: false,
    ...overrides,
  };
}

describe('restore fuzz — an adversarial folder graph', () => {
  let owner: TestUser;
  let stranger: TestUser;

  beforeEach(async () => {
    owner = await createTestUser();
    stranger = await createTestUser();
  });

  // ── The named adversarial shapes ─────────────────────────────────────────
  //
  // Each is a specific graph somebody could put in a file, written out rather
  // than generated, because the reason each one is dangerous is different and a
  // generator cannot say so.

  it('flattens a self-parent rather than storing a folder inside itself', async () => {
    const id = objectId();
    const document: BackupDocument = {
      folders: [backupFolder({ _id: id, parentId: id })],
      items: [],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    expect(result.foldersRestored).toBe(1);
    await assertForest(owner.id, 'a self-parented folder');
    assertAccounting(result, document, 'a self-parented folder');
    assertNothingSwallowed(result, 'a self-parented folder');
  });

  it('breaks a mutual two-folder cycle by clearing ONE edge, keeping both folders', async () => {
    // One edge, not both: clearing both would flatten a pair the user meant to
    // nest. The chain that survives is a legitimate parent/child relationship.
    const a = objectId();
    const b = objectId();
    const document: BackupDocument = {
      folders: [
        backupFolder({ _id: a, parentId: b, encryptedName: 'A' }),
        backupFolder({ _id: b, parentId: a, encryptedName: 'B' }),
      ],
      items: [],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    await assertForest(owner.id, 'a mutual two-folder cycle');
    assertNothingSwallowed(result, 'a mutual two-folder cycle');

    const folders = await Folder.find({ userId: owner.id }).lean();
    expect(folders).toHaveLength(2);
    const parented = folders.filter((f) => f.parentId !== undefined && f.parentId !== null);
    expect(parented, 'exactly one edge of the pair should survive').toHaveLength(1);
  });

  it('breaks a three-folder cycle', async () => {
    const [a, b, c] = [objectId(), objectId(), objectId()];
    const document: BackupDocument = {
      folders: [
        backupFolder({ _id: a, parentId: b }),
        backupFolder({ _id: b, parentId: c }),
        backupFolder({ _id: c, parentId: a }),
      ],
      items: [],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    await assertForest(owner.id, 'a three-folder cycle');
    assertNothingSwallowed(result, 'a three-folder cycle');

    // All three folders survive, and exactly ONE edge is cleared — the sweep
    // clears one parent per pass and re-evaluates, so a 3-cycle becomes a
    // three-deep chain rather than three orphans. Asserting only "no cycle"
    // would be satisfied by detaching all three, which loses the nesting the
    // user had.
    const folders = await Folder.find({ userId: owner.id }).lean();
    expect(folders).toHaveLength(3);
    expect(
      folders.filter((f) => f.parentId !== undefined && f.parentId !== null),
      'exactly one edge of the triangle should be cleared',
    ).toHaveLength(2);
  });

  it('clears a parentId that names no folder at all', async () => {
    const document: BackupDocument = {
      folders: [backupFolder({ parentId: objectId() })],
      items: [],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    await assertForest(owner.id, 'a dangling parentId');
    assertNothingSwallowed(result, 'a dangling parentId');
  });

  it("clears a parentId that names ANOTHER ACCOUNT's live folder", async () => {
    // The dangerous variant of the previous case: the id resolves to a real
    // document, just not one this user may see. It must be cleared rather than
    // stored, or the sidebar would render a parent the owner cannot read.
    const foreign = await seedFolder(stranger.id, { encryptedName: 'stranger-folder' });
    const document: BackupDocument = {
      folders: [backupFolder({ parentId: String(foreign._id) })],
      items: [],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    await assertForest(owner.id, "another account's folder as a parent");

    const restored = await Folder.find({ userId: owner.id }).lean();
    expect(restored).toHaveLength(1);
    expect(restored[0]!.parentId).toBeUndefined();
  });

  it('restores rows whose _id belongs to another account, minting fresh ids', async () => {
    // The E11000 case, and the reason clause 2 exists. `_id` is unique across
    // the whole collection, so reusing the backup's id threw a duplicate key for
    // EVERY row; the per-row catch turned each into a skip, and the restore
    // reported success having written nothing.
    const foreignFolder = await seedFolder(stranger.id, { encryptedName: 'f-foreign' });
    const foreignItem = await seedItem(stranger.id, { encryptedName: 'i-foreign' });
    const document: BackupDocument = {
      folders: [backupFolder({ _id: String(foreignFolder._id), encryptedName: 'f-foreign' })],
      items: [backupItem({ _id: String(foreignItem._id), encryptedName: 'i-foreign' })],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    assertNothingSwallowed(result, "a backup carrying another account's _ids");
    assertAccounting(result, document, "a backup carrying another account's _ids");
    expect(result.foldersRestored).toBe(1);
    expect(result.itemsRestored).toBe(1);

    // The rows exist, under FRESH ids, stamped with the backup's id as
    // provenance — and the stranger's originals are untouched.
    const folders = await Folder.find({ userId: owner.id }).lean();
    const items = await VaultItem.find({ userId: owner.id }).lean();
    expect(folders).toHaveLength(1);
    expect(items).toHaveLength(1);
    expect(String(folders[0]!._id)).not.toBe(String(foreignFolder._id));
    expect(folders[0]!.sourceRefId).toBe(String(foreignFolder._id));
    expect(items[0]!.sourceRefId).toBe(String(foreignItem._id));
    expect(await Folder.countDocuments({ userId: stranger.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: stranger.id })).toBe(1);
  });

  it('restores every row of a backup whose rows share one sourceRefId and one searchHash', async () => {
    // Two collisions at once: a duplicate `searchHash` violates the unique
    // partial `(userId, searchHash)` folder index — the one index that makes
    // E11000 reachable on a same-account restore — and duplicate `_id`s inside
    // one document make the provenance index ambiguous.
    const shared = hash('deadbeef');
    const duplicated = objectId();
    const document: BackupDocument = {
      folders: [
        backupFolder({ _id: duplicated, searchHash: shared, encryptedName: 'one' }),
        backupFolder({ _id: duplicated, searchHash: shared, encryptedName: 'two' }),
      ],
      items: [
        backupItem({ _id: duplicated, encryptedName: 'i-one' }),
        backupItem({ _id: duplicated, encryptedName: 'i-two' }),
      ],
    };

    const result = await restore(owner, document, 'skip');
    expect(result.status).toBe(200);
    assertAccounting(result, document, 'duplicated ids and search hashes');
    await assertForest(owner.id, 'duplicated ids and search hashes');

    // Both items survive: `VaultItem` has no unique index but `_id`, and each
    // insert mints its own. The SECOND folder is legitimately refused by the
    // unique partial index — that is the index doing its job, not a swallowed
    // error — so the folder path is asserted on the reason, not on the count.
    expect(await VaultItem.countDocuments({ userId: owner.id })).toBe(2);
    for (const reason of result.folderSkipReasons) {
      expect(reason.reason).toBe('conflict_skipped');
    }
  });

  it('rejects a document that is not JSON at all, without touching the vault', async () => {
    await seedFolder(owner.id, { encryptedName: 'pre-existing' });
    const agent = request(app);
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(owner.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ conflictStrategy: 'skip', data: '{"folders":[' });

    expect(res.status).toBe(400);
    expect(await Folder.countDocuments({ userId: owner.id })).toBe(1);
  });

  // ── The generated graphs ─────────────────────────────────────────────────

  /**
   * One generated backup document.
   *
   * `parentRef` is an INDEX-or-marker rather than an id, because the ids are not
   * known until the document is assembled: `self` names the folder's own id (the
   * one-cycle), a number names another row in the same document (which is how a
   * multi-folder cycle arises), `dangling` is a fresh id nobody owns, and
   * `malformed` is a string that cannot be cast to an ObjectId at all — the
   * value that used to abort a whole restore with a CastError.
   */
  const parentRef = fc.oneof(
    fc.constant<'none'>('none'),
    fc.constant<'self'>('self'),
    fc.constant<'dangling'>('dangling'),
    fc.constant<'malformed'>('malformed'),
    fc.nat({ max: 5 }),
  );

  type ParentRef = 'none' | 'self' | 'dangling' | 'malformed' | number;

  interface FolderSpec {
    parent: ParentRef;
    /** A searchHash shared between rows is what reaches the unique partial index. */
    hashSeed: string;
    /** Reuses the first row's `_id`, so one document carries a duplicate identity. */
    reuseFirstId: boolean;
    /**
     * Uses a live folder id belonging to ANOTHER account as this row's `_id`.
     *
     * This is the shape that produced the silent data loss: `_id` is unique
     * across the whole collection, so a foreign id thrown at `create` raises
     * E11000, which the per-row catch turns into a skip.
     */
    foreignId: boolean;
  }

  /**
   * A cycle deliberately written into the document, on top of whatever the free
   * index references happen to produce.
   *
   * Measured, and the reason this exists: with cross-references drawn
   * independently per folder, twenty generated documents contained NO multi-folder
   * cycle at all — the property stayed green with the controller's cycle sweep
   * disabled, which is the same "the sequences never attempted a cycle" hole the
   * folder-graph model hit in Phase 9. An explicit injector makes the shape the
   * property is ABOUT reachable by construction, and the reach counters below
   * prove it was reached.
   */
  type CycleInjection = 'none' | 'pair' | 'triangle';

  interface ItemSpec {
    folderRef: 'none' | number;
    /** As `FolderSpec.foreignId`, for the item collection. */
    foreignId: boolean;
  }

  interface DocumentSpec {
    folders: FolderSpec[];
    items: ItemSpec[];
    strategy: ConflictStrategy;
    injectCycle: CycleInjection;
  }

  /** Live ids belonging to an account the caller has nothing to do with. */
  interface ForeignIds {
    folderId: string;
    itemId: string;
  }

  const folderSpec: fc.Arbitrary<FolderSpec> = fc.record({
    parent: parentRef,
    hashSeed: fc.constantFrom('a', 'b', 'c', ''),
    reuseFirstId: fc.boolean(),
    foreignId: fc.boolean(),
  });

  const documentSpec: fc.Arbitrary<DocumentSpec> = fc.record({
    folders: fc.array(folderSpec, { minLength: 1, maxLength: 6 }),
    items: fc.array(
      fc.record({
        folderRef: fc.oneof(fc.constant<'none'>('none'), fc.nat({ max: 5 })),
        foreignId: fc.boolean(),
      }),
      { maxLength: 4 },
    ),
    strategy: fc.constantFrom<ConflictStrategy>('skip', 'overwrite', 'keep_both'),
    injectCycle: fc.constantFrom<CycleInjection>('none', 'pair', 'triangle'),
  });

  /** True when the folder rows, read as a parent map over their own ids, contain a cycle. */
  function documentHasMultiFolderCycle(folders: Record<string, unknown>[]): boolean {
    const parentOf = new Map<string, string | undefined>();
    for (const folder of folders) {
      parentOf.set(String(folder._id), folder.parentId ? String(folder.parentId) : undefined);
    }
    for (const start of parentOf.keys()) {
      const seen = new Set<string>([start]);
      let current = parentOf.get(start);
      let steps = 0;
      while (current !== undefined && steps <= parentOf.size) {
        if (current === start && seen.size > 1) return true;
        if (seen.has(current)) break;
        seen.add(current);
        current = parentOf.get(current);
        steps++;
      }
    }
    return false;
  }

  /**
   * A folder and an item that belong to a THIRD account, so a generated document
   * can carry ids that are live elsewhere in the collection.
   *
   * A fresh stranger per case rather than one for the file: the rows must still
   * exist when the restore runs, and `tests/setup.ts` truncates every collection
   * between tests but not between fast-check cases.
   */
  async function seedForeignIds(): Promise<ForeignIds> {
    const other = await createTestUser();
    const folder = await seedFolder(other.id, { encryptedName: 'foreign-folder' });
    const item = await seedItem(other.id, { encryptedName: 'foreign-item' });
    return { folderId: String(folder._id), itemId: String(item._id) };
  }

  function buildDocument(spec: DocumentSpec, foreign: ForeignIds): BackupDocument {
    const ids = spec.folders.map((folder) => (folder.foreignId ? foreign.folderId : objectId()));
    const firstId = ids[0]!;

    const folders = spec.folders.map((folder, index) => {
      const id = folder.reuseFirstId ? firstId : ids[index]!;
      const row: Record<string, unknown> = backupFolder({
        _id: id,
        encryptedName: `f${String(index)}`,
      });
      if (folder.hashSeed !== '') row.searchHash = hash(folder.hashSeed);
      if (folder.parent === 'self') row.parentId = id;
      else if (folder.parent === 'dangling') row.parentId = objectId();
      else if (folder.parent === 'malformed') row.parentId = 'not-an-object-id';
      else if (typeof folder.parent === 'number') row.parentId = ids[folder.parent % ids.length];
      return row;
    });

    // The injected cycle is written LAST so it survives whatever the free
    // references chose, and it is built over rows with DISTINCT ids.
    //
    // That second part was measured rather than assumed: `reuseFirstId` makes
    // two rows share one `_id`, and a cycle written across such a pair collapses
    // into a self-parent — which the controller's separate self-parent sweep
    // clears, so the property was never exercising the multi-folder sweep at
    // all. The reach counter below is what caught it.
    // The LAST row carrying each id, because a document may repeat one: a later
    // row with the same `_id` overwrites the earlier one's parent in every map
    // built from this document, the controller's included. Writing the cycle
    // onto an earlier row would therefore have it silently clobbered.
    const lastRowById = new Map<string, Record<string, unknown>>();
    for (const folder of folders) lastRowById.set(String(folder._id), folder);
    const distinct = [...lastRowById.values()];
    // Silently a no-op when the document is too small to hold the shape: a
    // two-row document cannot carry a triangle.
    if (spec.injectCycle === 'pair' && distinct.length >= 2) {
      distinct[0]!.parentId = distinct[1]!._id;
      distinct[1]!.parentId = distinct[0]!._id;
    } else if (spec.injectCycle === 'triangle' && distinct.length >= 3) {
      distinct[0]!.parentId = distinct[1]!._id;
      distinct[1]!.parentId = distinct[2]!._id;
      distinct[2]!.parentId = distinct[0]!._id;
    }

    const items = spec.items.map((item, index) => {
      const row: Record<string, unknown> = backupItem({ encryptedName: `i${String(index)}` });
      if (item.foreignId) row._id = foreign.itemId;
      if (typeof item.folderRef === 'number') row.folderId = ids[item.folderRef % ids.length];
      return row;
    });

    return { folders, items };
  }

  /**
   * Cases for the generated properties.
   *
   * Higher than the harness's `HEAVY_RUNS` (5), and the reason is measured
   * rather than aspirational: the reach counters below require every hostile
   * SHAPE to have been generated at least once, and five documents do not
   * reliably contain a self-parent, a cross-reference cycle, a malformed parent
   * AND a duplicated search hash. At twenty, each case being a fresh account and
   * one HTTP round trip against a real mongod, the property costs about four
   * seconds and reaches all of them. `HEAVY_RUNS` still bounds the idempotency
   * property, which restores twice per case.
   */
  const GRAPH_RUNS = 20;

  it('leaves an acyclic forest for any generated graph, under any strategy', async () => {
    // A property that never generated a cycle would pass against a controller
    // with no cycle guard at all — the exact failure Phase 9 measured on the
    // folder-graph model. So the shapes REACHED are counted and asserted, and a
    // generator change that stops producing them fails loudly instead of
    // quietly testing less.
    const reached = {
      selfParent: 0,
      crossReference: 0,
      /** A document whose folder rows really do form a multi-folder cycle. */
      multiFolderCycle: 0,
      dangling: 0,
      malformed: 0,
      duplicateHash: 0,
      duplicateId: 0,
      foreignId: 0,
      strategies: new Set<ConflictStrategy>(),
    };

    await fc.assert(
      fc.asyncProperty(documentSpec, async (spec) => {
        const user = await createTestUser();
        const foreign = await seedForeignIds();
        const document = buildDocument(spec, foreign);
        const label = `a generated graph of ${String(document.folders.length)} folders under ${spec.strategy}`;

        // Counted from the DOCUMENT, never from the spec that asked for it.
        // `buildDocument` overwrites 2-3 rows' `parentId` to inject a cycle and
        // `reuseFirstId` can throw a row's foreign `_id` away, so a spec that
        // said "malformed" may have produced nothing of the sort by the time the
        // controller saw it. A counter that trusted the spec would report a shape
        // as reached that was never sent — which is precisely the vacuity these
        // counters exist to detect, moved one level up.
        reached.strategies.add(spec.strategy);
        const ids = document.folders.map((folder) => String(folder._id));
        const seenIds = new Set<string>();
        for (const folder of document.folders) {
          const id = String(folder._id);
          const parent = folder.parentId === undefined ? undefined : String(folder.parentId);
          if (parent === id) reached.selfParent++;
          else if (parent === 'not-an-object-id') reached.malformed++;
          else if (parent !== undefined && ids.includes(parent)) reached.crossReference++;
          else if (parent !== undefined) reached.dangling++;
          if (seenIds.has(id)) reached.duplicateId++;
          seenIds.add(id);
          if (id === foreign.folderId) reached.foreignId++;
        }
        for (const item of document.items) {
          if (String(item._id) === foreign.itemId) reached.foreignId++;
        }
        const hashes = document.folders
          .map((folder) => folder.searchHash)
          .filter((hash): hash is string => typeof hash === 'string');
        if (new Set(hashes).size < hashes.length) reached.duplicateHash++;
        if (documentHasMultiFolderCycle(document.folders)) reached.multiFolderCycle++;

        const result = await restore(user, document, spec.strategy);
        expect(result.status, `${label} was refused with ${String(result.status)}`).toBe(200);

        await assertForest(user.id, label);
        assertAccounting(result, document, label);
        assertNothingSwallowed(result, label);

        // Every row REPORTED as restored is really there. The account is fresh,
        // so nothing can match an existing row: every restored row is an insert,
        // whatever the strategy, and the two counts must agree exactly. Without
        // this a controller that incremented its counter and never wrote would
        // satisfy the accounting check and the skip-reason check alike.
        expect(await Folder.countDocuments({ userId: user.id }), `${label}: folders written`).toBe(
          result.foldersRestored,
        );
        expect(await VaultItem.countDocuments({ userId: user.id }), `${label}: items written`).toBe(
          result.itemsRestored,
        );

        // Every surviving item points at a folder this account owns, or at none.
        // A restore that left a foreign or dangling folderId behind shows up in
        // the UI as an item filed under a folder nobody can open.
        const folderIds = new Set(
          (await Folder.find({ userId: user.id }).select('_id').lean()).map((f) => String(f._id)),
        );
        const items = await VaultItem.find({ userId: user.id }).select('folderId').lean();
        for (const item of items) {
          if (item.folderId === undefined || item.folderId === null) continue;
          expect(
            folderIds.has(String(item.folderId)),
            `${label}: an item points at folder ${String(item.folderId)}, which this account does not own`,
          ).toBe(true);
        }
      }),
      propertyRun({ numRuns: GRAPH_RUNS }),
    );

    for (const [shape, count] of Object.entries(reached)) {
      if (shape === 'strategies') continue;
      expect(count as number, `the generator never produced a ${shape} folder`).toBeGreaterThan(0);
    }
    expect([...reached.strategies].sort()).toEqual(['keep_both', 'overwrite', 'skip']);
  });

  it('is idempotent: restoring the same generated document twice adds nothing', async () => {
    await fc.assert(
      fc.asyncProperty(
        documentSpec.filter((spec) => spec.strategy !== 'keep_both'),
        async (spec) => {
          // `keep_both` is excluded because duplication is its contract, not a
          // defect — it is the one strategy that is SUPPOSED to grow the vault
          // on a repeat restore.
          const user = await createTestUser();
          const document = buildDocument(spec, await seedForeignIds());
          const label = `a repeated generated restore under ${spec.strategy}`;

          await restore(user, document, spec.strategy);
          const afterFirst = {
            folders: await Folder.countDocuments({ userId: user.id }),
            items: await VaultItem.countDocuments({ userId: user.id }),
          };

          const second = await restore(user, document, spec.strategy);
          expect(second.status).toBe(200);
          assertNothingSwallowed(second, label);
          await assertForest(user.id, label);

          expect(await Folder.countDocuments({ userId: user.id }), label).toBe(afterFirst.folders);
          expect(await VaultItem.countDocuments({ userId: user.id }), label).toBe(afterFirst.items);
        },
      ),
      propertyRun({ numRuns: HEAVY_RUNS }),
    );
  });
});
