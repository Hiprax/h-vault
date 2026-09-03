import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';

// The ONLY static application import in this file, and that is the whole
// mechanism. `config/database.ts` registers models purely as an import side
// effect, so the set of names on the shared mongoose instance immediately after
// it loads IS the set it registers — and nothing else in this module graph can
// inflate it. Adding an import of any model above this line would make the
// assertion below pass vacuously.
import '../src/config/database.js';

const registeredByDatabaseConfig = new Set(mongoose.modelNames());

// Loaded AFTER the snapshot, so the models it pulls in cannot be mistaken for
// ones `database.ts` registered. Re-importing a module that `database.ts`
// already evaluated is a cache hit rather than a second `mongoose.model()` call,
// so this cannot throw `OverwriteModelError`.
const { indexedModels } = await import('../scripts/indexedModels.js');

/**
 * The two model lists this project keeps, and the drift between them that
 * nothing used to catch.
 *
 * `scripts/indexedModels.ts` is what the production `create-indexes` pass BUILDS.
 * `src/config/database.ts` is what `verifyIndexes()` can SEE, because it iterates
 * `mongoose.modelNames()` and a model nobody imported is not in it. A model
 * present in the first list and missing from the second is a model whose absent
 * indexes production never warns about — the exact silence that
 * `migrations.test.ts` was written to prevent for the OTHER list.
 *
 * `migrations.test.ts` cannot make this assertion: it imports `indexedModels`
 * statically, which registers every model in it, so by the time any of its cases
 * run the two sets are identical no matter what `database.ts` says.
 */
describe('model registration drift', () => {
  it('registers every create-indexes model, so verifyIndexes can see all of them', () => {
    const missing = indexedModels
      .map((entry) => entry.name)
      .filter((name) => !registeredByDatabaseConfig.has(name));

    expect(
      missing,
      `src/config/database.ts must import every model listed in scripts/indexedModels.ts, ` +
        `or connectDatabase()'s index verification silently skips it: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('names the document-store models specifically, since they are the newest pair', () => {
    // Called out by name for the same reason `migrations.test.ts` names Migration
    // and TrustedDevice: the loop above is only as good as the list it walks, and
    // a model dropped from BOTH lists at once would pass it in silence.
    expect(registeredByDatabaseConfig.has('Document')).toBe(true);
    expect(registeredByDatabaseConfig.has('DocumentUpload')).toBe(true);
  });

  it('snapshots a real set, so the comparison is not passing on an empty one', () => {
    // The denominator. If `database.ts` ever stopped registering models as an
    // import side effect, every assertion above would pass against two empty sets
    // and report nothing at all.
    expect(registeredByDatabaseConfig.size).toBe(indexedModels.length);
    expect(indexedModels.length).toBeGreaterThan(5);
  });
});
