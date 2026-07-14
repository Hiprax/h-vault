import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  seedFolder,
  dbBackupPayload,
  rawFolders,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// ─────────────────────────────────────────────────────────────────────────────
// A tampered/corrupt backup can plant a MULTI-folder cycle among the restored
// folders (A.parentId=B, B.parentId=A, or a longer A→B→C→A loop). The self-parent
// guard only catches a 1-cycle; a 2+-folder cycle leaves every folder pointing at
// a real, existing folder, so neither the dangling cleanup nor the self-parent
// guard touches it. `restoreBackup` therefore runs a GLOBAL, ITERATIVE cycle-break
// pass (self-membership predicate only, never depth>=max): it clears exactly ONE
// edge per cycle, leaving the folders as an acyclic child→parent chain, and leaves
// non-cyclic trees — including a legitimate maximum-depth chain — untouched.
// ─────────────────────────────────────────────────────────────────────────────

async function restore(
  agent: request.SuperTest<request.Test>,
  token: string,
  body: Record<string, unknown>,
) {
  const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/backup/restore')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send(body);
}

function byName(docs: Record<string, unknown>[], name: string): Record<string, unknown> {
  const found = docs.find((d) => d.encryptedName === name);
  if (!found) throw new Error(`no doc with encryptedName ${name}`);
  return found;
}

/** Number of folders that still carry a parentId (i.e. surviving parent edges). */
function parentedCount(folders: Record<string, unknown>[]): number {
  return folders.filter((f) => f.parentId != null).length;
}

/**
 * Walks the parentId pointers of every folder and returns true if ANY of them
 * loops (a node revisited while ascending). Detects self-loops and multi-folder
 * cycles alike, independent of the server-side `$graphLookup` implementation.
 */
function hasAnyCycle(folders: Record<string, unknown>[]): boolean {
  const parentOf = new Map<string, string | undefined>();
  for (const f of folders) {
    parentOf.set(String(f._id), f.parentId != null ? String(f.parentId) : undefined);
  }
  for (const start of parentOf.keys()) {
    const seen = new Set<string>();
    let cur: string | undefined = start;
    while (cur !== undefined) {
      if (seen.has(cur)) return true;
      seen.add(cur);
      cur = parentOf.get(cur);
    }
  }
  return false;
}

describe('Backup restore — multi-folder cycle break (tampered backups)', () => {
  let userA: TestUser;
  let userB: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    userA = await createTestUser();
    userB = await createTestUser();
  });

  it('(a) fresh-insert 2-folder cycle → exactly one edge broken, both folders persist, no loop', async () => {
    const fA = await seedFolder(userA.id, { encryptedName: 'A' });
    const fB = await seedFolder(userA.id, { encryptedName: 'B' });
    const payload = await dbBackupPayload(userA.id);
    // Tamper: A.parentId=B, B.parentId=A (a 2-cycle among the backup rows).
    byName(payload.folders, 'A').parentId = String(fB._id);
    byName(payload.folders, 'B').parentId = String(fA._id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(2);
    // Exactly ONE edge survives — the pair became an acyclic child→parent chain,
    // not two detached roots.
    expect(parentedCount(bFolders)).toBe(1);
    expect(hasAnyCycle(bFolders)).toBe(false);

    // A's own tree was never cyclic and is untouched.
    const aFolders = await rawFolders(userA.id);
    expect(hasAnyCycle(aFolders)).toBe(false);
    expect(byName(aFolders, 'A').parentId).toBeUndefined();
    expect(byName(aFolders, 'B').parentId).toBeUndefined();
  });

  it('(b) fresh-insert 3-folder cycle A→B→C→A → broken (one edge cleared), no loop', async () => {
    const fA = await seedFolder(userA.id, { encryptedName: 'A' });
    const fB = await seedFolder(userA.id, { encryptedName: 'B' });
    const fC = await seedFolder(userA.id, { encryptedName: 'C' });
    const payload = await dbBackupPayload(userA.id);
    byName(payload.folders, 'A').parentId = String(fB._id);
    byName(payload.folders, 'B').parentId = String(fC._id);
    byName(payload.folders, 'C').parentId = String(fA._id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(3);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(3);
    // A 3-cycle loses exactly one edge → two edges remain (an acyclic chain).
    expect(parentedCount(bFolders)).toBe(2);
    expect(hasAnyCycle(bFolders)).toBe(false);
  });

  it('(c) PRE-EXISTING overwrite 2-cycle broken by the GLOBAL sweep', async () => {
    // Both folders already belong to the restorer and are restored via overwrite
    // (matched by owned _id, keeping their original _ids). This exercises the
    // GLOBAL cycle-break sweep breaking a cycle among PRE-EXISTING owned folders —
    // the case the self-parent guard and dangling cleanup cannot touch. (Note: the
    // overwrite branch DOES record these rows in folderIdMap as identity mappings,
    // so a folderIdMap-scoped candidate set would catch them too; the sweep is
    // global for consistency with the adjacent dangling/self-parent sweeps and as
    // defense-in-depth — see the controller comment.)
    const fA = await seedFolder(userB.id, { encryptedName: 'A' });
    const fB = await seedFolder(userB.id, { encryptedName: 'B' });
    const payload = await dbBackupPayload(userB.id);
    byName(payload.folders, 'A').parentId = String(fB._id);
    byName(payload.folders, 'B').parentId = String(fA._id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(2);
    // Owned rows keep their original _ids (overwrite in place, no re-mint).
    expect(bFolders.map((f) => String(f._id)).sort()).toEqual(
      [String(fA._id), String(fB._id)].sort(),
    );
    expect(parentedCount(bFolders)).toBe(1);
    expect(hasAnyCycle(bFolders)).toBe(false);
  });

  it('(d) non-cyclic 3-level tree is untouched by the cycle-break sweep', async () => {
    const root = await seedFolder(userA.id, { encryptedName: 'root' });
    const mid = await seedFolder(userA.id, { encryptedName: 'mid', parentId: root._id });
    await seedFolder(userA.id, { encryptedName: 'leaf', parentId: mid._id });
    const payload = await dbBackupPayload(userA.id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(3);

    const bFolders = await rawFolders(userB.id);
    const newRoot = byName(bFolders, 'root');
    const newMid = byName(bFolders, 'mid');
    const newLeaf = byName(bFolders, 'leaf');
    // Every edge preserved — the sweep must not clear any valid parentId.
    expect(newRoot.parentId).toBeUndefined();
    expect(String(newMid.parentId)).toBe(String(newRoot._id));
    expect(String(newLeaf.parentId)).toBe(String(newMid._id));
    expect(parentedCount(bFolders)).toBe(2);
    expect(hasAnyCycle(bFolders)).toBe(false);
  });

  it('(d-depth) a legitimate maximum-depth (50) acyclic chain is left fully intact', async () => {
    // MAX_FOLDER_NESTING_DEPTH is 50. A chain of 50 folders puts the deepest
    // leaf at computed depth 50 — i.e. `depth >= MAX_FOLDER_NESTING_DEPTH` is
    // TRUE for it. A depth-based cycle predicate would wrongly detach that leaf;
    // the self-membership predicate correctly leaves the whole acyclic chain
    // untouched. This is the regression guard for that distinction.
    const CHAIN = 50;
    let prevId: unknown = null;
    for (let i = 0; i < CHAIN; i++) {
      const overrides: Record<string, unknown> = { encryptedName: `d${String(i)}` };
      if (prevId !== null) overrides.parentId = prevId;
      const f = await seedFolder(userA.id, overrides);
      prevId = f._id;
    }
    const payload = await dbBackupPayload(userA.id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(CHAIN);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(CHAIN);
    // Every folder but the root retains its parent — nothing detached.
    expect(parentedCount(bFolders)).toBe(CHAIN - 1);
    expect(hasAnyCycle(bFolders)).toBe(false);
    // The deepest leaf specifically still has a parent (would be null if a
    // depth>=max predicate had fired on it).
    expect(byName(bFolders, `d${String(CHAIN - 1)}`).parentId).not.toBeUndefined();
  });

  it('(long-cycle) a cycle LONGER than the folder-nesting cap (55 folders) is still broken', async () => {
    // Regression guard: the cycle detector must traverse deep enough to catch a
    // cycle whose length exceeds MAX_FOLDER_NESTING_DEPTH (50). A start node
    // re-enters its own ancestor set only at recursion depth `cycleLength - 1`,
    // so a detector capped at 50 would MISS any 52+-folder cycle and leave it
    // persisted. The restore path bypasses depth validation, so a tampered
    // backup can plant such a cycle (folder count is capped only at 500).
    const N = 55;
    const seeded: Record<string, unknown>[] = [];
    for (let i = 0; i < N; i++) {
      seeded.push(await seedFolder(userA.id, { encryptedName: `c${String(i)}` }));
    }
    const payload = await dbBackupPayload(userA.id);
    // Tamper: c_i.parentId = c_{(i+1) % N} — one big cycle over all N folders.
    for (let i = 0; i < N; i++) {
      byName(payload.folders, `c${String(i)}`).parentId = String(seeded[(i + 1) % N]!._id);
    }

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(N);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(N);
    // Exactly one edge broken → N-1 edges remain, and no loop survives.
    expect(parentedCount(bFolders)).toBe(N - 1);
    expect(hasAnyCycle(bFolders)).toBe(false);
  });

  it('two independent 2-cycles each lose exactly one edge', async () => {
    const fA = await seedFolder(userA.id, { encryptedName: 'A' });
    const fB = await seedFolder(userA.id, { encryptedName: 'B' });
    const fC = await seedFolder(userA.id, { encryptedName: 'C' });
    const fD = await seedFolder(userA.id, { encryptedName: 'D' });
    const payload = await dbBackupPayload(userA.id);
    // Cycle 1: A↔B. Cycle 2: C↔D.
    byName(payload.folders, 'A').parentId = String(fB._id);
    byName(payload.folders, 'B').parentId = String(fA._id);
    byName(payload.folders, 'C').parentId = String(fD._id);
    byName(payload.folders, 'D').parentId = String(fC._id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(4);

    const bFolders = await rawFolders(userB.id);
    expect(bFolders).toHaveLength(4);
    // Each 2-cycle keeps exactly one edge → two edges total across both pairs.
    expect(parentedCount(bFolders)).toBe(2);
    expect(hasAnyCycle(bFolders)).toBe(false);
  });
});
