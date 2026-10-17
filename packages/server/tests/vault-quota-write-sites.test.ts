/**
 * F-24: every write to a counted collection is accounted for, by construction.
 *
 * The vault byte counter is only as exact as the set of writers that move it. A
 * new `VaultItem.updateOne` somewhere that changes a ciphertext field without
 * going through the quota module would drift the counter on every call, and no
 * behavioural test of the existing paths would notice. So this file reads the
 * server's source with the TypeScript compiler and finds EVERY write call on the
 * two counted models (`VaultItem`, `Folder`, their `.collection`) and every write
 * on a raw collection handle, outside `utils/vaultQuota.ts` and the models. Each
 * must be one of:
 *
 * - inside a callback handed to `createCountedRow`/`updateCountedRow` (the module
 *   reserves, measures and settles around it); or
 * - a site listed in {@link ACCOUNTED_SITES}, by file, enclosing function, callee
 *   and COUNT, with the reason it keeps the counter exact.
 *
 * The comparison runs both ways: a site the list does not name fails, and so
 * does an entry no site matches any more. A raw handle to a counted collection
 * ACQUIRED anywhere (`connection.collection('vault_items')`, or by a name this scan
 * cannot read) is a site too, whatever is later done with it, so a handle kept in
 * a variable cannot carry writes past the scan. What this cannot see is a write
 * through a hydrated document's `save()`; nothing in the server saves an item or
 * a folder that way, and the behavioural suites hold every path that writes a
 * row to the database's own total.
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');

/** Methods that write. */
const WRITE_METHODS = new Set([
  'create',
  'insertMany',
  'insertOne',
  'updateOne',
  'updateMany',
  'findOneAndUpdate',
  'findByIdAndUpdate',
  'deleteOne',
  'deleteMany',
  'findOneAndDelete',
  'findByIdAndDelete',
  'bulkWrite',
  'replaceOne',
  'findOneAndReplace',
]);

/** The quota module's own wrappers: a write inside a callback handed to one is accounted. */
const WRAPPERS = new Set(['createCountedRow', 'updateCountedRow']);

/**
 * Every accounted write that does not go through a wrapper, and why the counter
 * stays exact. Key: `<file relative to src>#<enclosing declaration>#<callee>`.
 */
const ACCOUNTED_SITES: Record<string, { count: number; reason: string }> = {
  'controllers/vaultController.ts#deleteItem#VaultItem.findOneAndUpdate': {
    count: 1,
    reason: 'trash: sets `deletedAt`, a placement field the quota does not count',
  },
  'controllers/vaultController.ts#restoreItem#VaultItem.findOneAndUpdate': {
    count: 1,
    reason: 'restore from trash: unsets `deletedAt` (placement)',
  },
  'controllers/vaultController.ts#bulkDelete#VaultItem.updateMany': {
    count: 1,
    reason: 'bulk trash: `deletedAt` only (placement)',
  },
  'controllers/vaultController.ts#bulkMove#VaultItem.updateMany': {
    count: 1,
    reason: 'bulk move: `folderId` only (placement)',
  },
  'controllers/vaultController.ts#bulkReEncrypt#VaultItem.updateOne': {
    count: 1,
    reason:
      'transactional rotation: the counter moves by the snapshot difference, inside the same transaction',
  },
  'controllers/vaultController.ts#bulkReEncrypt#Folder.updateOne': {
    count: 1,
    reason: 'transactional rotation (as above)',
  },
  'controllers/vaultController.ts#pinnedRotationWrite#VaultItem.updateOne': {
    count: 1,
    reason:
      'sequential rotation and its rollback: pinned on the measured row (the rollback also on its IVs); its delta, or on an unknown outcome what it could add, is settled in a `finally`',
  },
  'controllers/vaultController.ts#pinnedRotationWrite#Folder.updateOne': {
    count: 1,
    reason: 'sequential rotation and its rollback (as above)',
  },
  'controllers/folderController.ts#updateFolder#Folder.updateOne': {
    count: 1,
    reason: 'cycle repair: unsets `parentId` (placement)',
  },
  'controllers/folderController.ts#execute#VaultItem.updateMany': {
    count: 1,
    reason: "a deleted folder's items, trashed or moved: `deletedAt` / `folderId` only (placement)",
  },
  'controllers/folderController.ts#execute#Folder.updateMany': {
    count: 1,
    reason: "a deleted folder's children, moved up: `parentId` only (placement)",
  },
  'controllers/folderController.ts#deleteFolder#VaultItem.updateMany': {
    count: 1,
    reason: 'items left pointing at a folder that no longer exists: unsets `folderId` (placement)',
  },
  'controllers/backupController.ts#restoreUnderRotationLock#Folder.updateMany': {
    count: 3,
    reason: 'restore: remaps and clears `parentId` (placement)',
  },
  'controllers/backupController.ts#restoreUnderRotationLock#Folder.updateOne': {
    count: 1,
    reason: 'restore: breaks a cycle by unsetting one `parentId` (placement)',
  },
  "utils/migrations.ts#removeSearchHash#acquire mongoose.connection.collection('vault_items')": {
    count: 1,
    reason:
      'migration v5 (F-12): drops the name-hash index and unsets `searchHash` in batches; the counter is NOT moved, so it overcounts by the removed bytes (the safe direction) until the hourly recount',
  },
  "utils/migrations.ts#removeSearchHash#acquire mongoose.connection.collection('folders')": {
    count: 1,
    reason: 'migration v5 (F-12), as for vault_items',
  },
  "utils/migrations.ts#backfillVaultRowCounters#acquire mongoose.connection.collection('vault_items')":
    {
      count: 1,
      reason:
        'migration v6 (F-15): READS only, one grouped count of item rows per owner; its writes go to the `users` row counters, each only while that counter is absent',
    },
  "utils/migrations.ts#backfillVaultRowCounters#acquire mongoose.connection.collection('folders')":
    {
      count: 1,
      reason: 'migration v6 (F-15), as for vault_items: a grouped count of folder rows, no write',
    },
  'controllers/toolsController.ts#execute#VaultItem.insertMany': {
    count: 1,
    reason: 'import: one reservation for the whole request; what landed is settled',
  },
  'controllers/toolsController.ts#execute#VaultItem.updateOne': {
    count: 1,
    reason: 'import overwrite: pinned on the measured row; counted into what landed',
  },
  'middleware/rateLimitStore.ts#collection#acquire db.collection<RateLimitRecord>(RATE_LIMIT_COLLECTION)':
    {
      count: 1,
      reason:
        "the rate-limit store's own counter collection, named by a constant (RATE_LIMIT_COLLECTION), never a vault collection",
    },
  'utils/cascadeDelete.ts#sweepRemainingRows#VaultItem.deleteMany': {
    count: 1,
    reason: 'account erasure: the counter goes with the user row',
  },
  'utils/cascadeDelete.ts#sweepRemainingRows#Folder.deleteMany': {
    count: 1,
    reason: 'account erasure (as above)',
  },
  'utils/cascadeDelete.ts#eraseInBatches#model.collection.deleteMany': {
    count: 1,
    reason: "account erasure: the batched walk over every tenant collection, the vault's included",
  },
};

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return name.endsWith('.ts') ? [full] : [];
  });
}

/**
 * The name of the function that encloses `node`: a named function or method, or
 * the variable a function (or a call wrapping one, such as `catchAsync(...)`) is
 * assigned to. A variable met BEFORE any function boundary (`const result = await
 * X.updateOne(...)`) holds the call's result, not its code, and is passed over.
 */
function enclosingName(node: ts.Node): string {
  let crossedFunction = false;
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionDeclaration(current) || ts.isMethodDeclaration(current)) {
      if (current.name) return current.name.getText();
      crossedFunction = true;
    } else if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) {
      crossedFunction = true;
    } else if (
      crossedFunction &&
      ts.isVariableDeclaration(current) &&
      ts.isIdentifier(current.name)
    ) {
      return current.name.text;
    }
  }
  return '<module>';
}

/** True when `node` sits inside a function passed as an argument to a wrapper. */
function insideWrapper(node: ts.Node): boolean {
  for (let current = node.parent; current; current = current.parent) {
    if (
      (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) &&
      ts.isCallExpression(current.parent) &&
      current.parent.arguments.includes(current as ts.Expression) &&
      WRAPPERS.has(current.parent.expression.getText())
    ) {
      return true;
    }
  }
  return false;
}

/** Collections the quota counts, by their stored names. */
const COUNTED_COLLECTIONS = new Set(['vault_items', 'folders']);

/**
 * The receiver a write is aimed at when it can reach a counted collection, else
 * `null`:
 * - the two models and their `.collection`;
 * - `<variable>.collection` for a lower-case variable, which may hold any model
 *   (the cascade's walk over every tenant collection does); another model named
 *   outright (`User.collection`) cannot be a counted one;
 * - `<x>.collection(<name>)` naming a counted collection, or naming one by an
 *   expression this scan cannot read. A handle that takes no name is its owner's
 *   own fixed collection (the rate-limit store's).
 */
function countedReceiver(receiver: ts.Expression): string | null {
  const text = receiver.getText();
  if (text === 'VaultItem' || text === 'Folder') return text;
  if (ts.isPropertyAccessExpression(receiver) && receiver.name.text === 'collection') {
    const owner = receiver.expression.getText();
    if (owner === 'VaultItem' || owner === 'Folder') return text;
    return /^[a-z]/.test(owner) ? text : null;
  }
  if (
    ts.isCallExpression(receiver) &&
    ts.isPropertyAccessExpression(receiver.expression) &&
    receiver.expression.name.text === 'collection'
  ) {
    const [name] = receiver.arguments;
    if (name === undefined) return null;
    if (ts.isStringLiteralLike(name)) return COUNTED_COLLECTIONS.has(name.text) ? text : null;
    return text;
  }
  return null;
}

interface Scan {
  accounted: Map<string, number>;
  wrapped: string[];
}

function scan(): Scan {
  const accounted = new Map<string, number>();
  const wrapped: string[] = [];
  for (const file of sourceFiles(SRC)) {
    const relative = path.relative(SRC, file).split(path.sep).join('/');
    if (relative === 'utils/vaultQuota.ts' || relative.startsWith('models/')) continue;
    const source = ts.createSourceFile(
      file,
      readFileSync(file, 'utf8'),
      ts.ScriptTarget.Latest,
      true,
    );
    const visit = (node: ts.Node): void => {
      // Acquiring a raw handle to a counted collection is a site in itself.
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'collection' &&
        countedReceiver(node) !== null
      ) {
        const key = `${relative}#${enclosingName(node)}#acquire ${node.getText()}`;
        accounted.set(key, (accounted.get(key) ?? 0) + 1);
      }
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        WRITE_METHODS.has(node.expression.name.text)
      ) {
        const receiver = countedReceiver(node.expression.expression);
        if (receiver !== null) {
          const callee = `${receiver}.${node.expression.name.text}`;
          if (insideWrapper(node)) {
            wrapped.push(`${relative}#${callee}`);
          } else {
            const key = `${relative}#${enclosingName(node)}#${callee}`;
            accounted.set(key, (accounted.get(key) ?? 0) + 1);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { accounted, wrapped };
}

describe('every write to a counted collection is accounted for', () => {
  const { accounted, wrapped } = scan();

  it('the writes outside the quota wrappers are exactly the listed ones, at the listed counts', () => {
    const found = Object.fromEntries([...accounted.entries()].sort());
    const expected = Object.fromEntries(
      Object.entries(ACCOUNTED_SITES)
        .map(([key, entry]) => [key, entry.count] as const)
        .sort(),
    );
    expect(found).toEqual(expected);
  });

  it('every listed site says why it keeps the counter exact', () => {
    for (const [key, entry] of Object.entries(ACCOUNTED_SITES)) {
      expect(entry.reason.length, key).toBeGreaterThan(20);
    }
  });

  it('the scan sees the writes that DO go through the wrappers (it is not blind)', () => {
    // One per creating path at least: an item create, a folder create, and the
    // restore's creates of both.
    expect(wrapped).toEqual(
      expect.arrayContaining([
        'controllers/vaultController.ts#VaultItem.create',
        'controllers/folderController.ts#Folder.create',
        'controllers/backupController.ts#VaultItem.create',
        'controllers/backupController.ts#Folder.create',
      ]),
    );
  });
});
