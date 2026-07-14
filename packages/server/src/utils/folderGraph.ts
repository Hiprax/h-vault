import mongoose from 'mongoose';
import { MAX_FOLDER_NESTING_DEPTH, MAX_FOLDERS_PER_USER } from '@hvault/shared';
import { Folder } from '../models/Folder.js';

/**
 * Shared folder-graph helpers.
 *
 * Ancestor traversal was previously module-private to `folderController`, but
 * the backup restore flow is a SECOND consumer (it must break folder cycles
 * planted by a tampered backup). Both call sites use the identical, tested
 * traversal here so the logic never diverges into two copies.
 */

/**
 * Retrieves the full ancestor chain of a folder in a single DB query using
 * `$graphLookup`.  This replaces the previous N+1-query approach that issued
 * one `findOne` per ancestor level (up to 50 sequential queries in the worst
 * case).
 *
 * `$graphLookup` is cycle-safe: it terminates at `maxDepth` and never revisits a
 * node, so a genuine cycle among the user's folders surfaces as the folder
 * appearing in its OWN ancestor chain (see `hasCycle`).
 *
 * `maxDepth` bounds the recursion. It defaults to `MAX_FOLDER_NESTING_DEPTH`,
 * which is what the depth/circular-reference guards in `folderController` need
 * (a chain that reaches the nesting cap is treated as over-deep). The cycle
 * detector overrides it (see `hasCycle`) because a cycle's start node only
 * reappears in its own ancestor set at recursion depth `cycleLength - 1`, so a
 * cap of 50 would miss any cycle of 52+ folders.
 */
export async function getAncestorChain(
  folderId: string,
  userId: string,
  maxDepth: number = MAX_FOLDER_NESTING_DEPTH,
): Promise<{ ancestorIds: string[]; depth: number }> {
  const result = await Folder.aggregate<{
    ancestors: { _id: mongoose.Types.ObjectId }[];
  }>([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(folderId),
        userId: new mongoose.Types.ObjectId(userId),
      },
    },
    {
      $graphLookup: {
        from: 'folders',
        startWith: '$parentId',
        connectFromField: 'parentId',
        connectToField: '_id',
        as: 'ancestors',
        maxDepth,
        restrictSearchWithMatch: { userId: new mongoose.Types.ObjectId(userId) },
      },
    },
    { $project: { 'ancestors._id': 1 } },
  ]);

  if (!result[0]) {
    return { ancestorIds: [], depth: 0 };
  }

  const ancestorIds = result[0].ancestors.map((a) => a._id.toString());
  // depth = ancestor count + 1 (the folder itself)
  return { ancestorIds, depth: ancestorIds.length + 1 };
}

/**
 * Self-membership cycle predicate: returns `true` iff `folderId` appears in its
 * OWN ancestor chain — the only reliable signal of a real cycle among the
 * user's folders. Because `$graphLookup` is cycle-safe, a genuine `A → B → A`
 * (or longer) loop surfaces as the folder being one of its own ancestors.
 *
 * DELIBERATELY NOT a `depth >= MAX_FOLDER_NESTING_DEPTH` check: a legitimate
 * ACYCLIC chain can reach the maximum nesting depth without being cyclic, and
 * flagging it would wrongly detach a valid maximum-depth leaf. Callers that
 * need to reject an over-deep-but-acyclic re-parent (e.g. `updateFolder`) apply
 * their own depth guard on top of this predicate.
 *
 * The ancestor traversal is bounded by `MAX_FOLDERS_PER_USER`, NOT by
 * `MAX_FOLDER_NESTING_DEPTH`: a cycle's start node only re-enters its own
 * ancestor set at recursion depth `cycleLength - 1`, and the restore path
 * (`restoreBackup`) writes folders directly, bypassing the nesting-depth guard —
 * so a tampered backup can plant a cycle far longer than 50. A cycle can involve
 * at most every folder the user owns, so a cap of `MAX_FOLDERS_PER_USER`
 * guarantees the start node is reached for ANY real cycle. For acyclic data the
 * traversal still stops at the real root well before the cap, so the higher
 * ceiling costs nothing in the common case.
 */
export async function hasCycle(folderId: string, userId: string): Promise<boolean> {
  const { ancestorIds } = await getAncestorChain(folderId, userId, MAX_FOLDERS_PER_USER);
  return ancestorIds.includes(folderId);
}
