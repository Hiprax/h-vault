/**
 * `healthResultsStore` — the error half.
 *
 * This module's contract is that it degrades and never propagates: a load
 * answers `null`, a save no-ops, and a clear resolves, whatever IndexedDB does.
 * That contract is only worth anything if the failing paths are actually
 * exercised, so each one here is driven by a REAL engine failure (a version
 * conflict, a genuine `ConstraintError` on a real request) rather than by a
 * double, and each is asserted on what an observer can see: the value returned,
 * the record that survived, and the work that still got done afterwards.
 *
 * Two branches here are deliberately left uncovered rather than covered with a
 * substituted request: the `?? new Error(<fallback>)` arms in `openDb` and
 * `getStoredRecord`. A real failing request always populates `error`, so only a
 * double reaches them — and a double proves nothing, because the rejection value
 * is swallowed either way. Measured: replacing both with a bare
 * `reject(request.error)` leaves this whole file green, which is the definition
 * of a test that cannot fail for a reason anyone cares about. The `??` stays
 * because rejecting with `null` is wrong on its own terms; the branch stays
 * uncovered because nothing can assert it.
 *
 * The sharpest of these is `clearHealthResults`. `authStore.logout` AWAITS it
 * (`authStore.ts:699`) and three teardown steps run after that await, so a clear
 * that rejected — or hung — would leave the session half torn down. "A failed
 * clear never blocks logout" is the property, and it is asserted from both ends:
 * here, that the clear resolves rather than rejecting; and in
 * `authStore-functional.test.ts`, that logout's remaining teardown still runs
 * even when it does reject.
 */

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { deriveUserHash } from '../src/services/offlineCache';
import {
  loadHealthResults,
  saveBreachResults,
  saveStrengthScores,
  clearHealthResults,
} from '../src/services/health/healthResultsStore';
import { createDoomedRequestFactory, openRawDatabase } from './indexeddbFailures.js';

const HEALTH_DB_PREFIX = 'hvault-health';
const SCRATCH_DB = 'health-results-error-scratch';

let doomedRequest: () => IDBRequest;
let userSeq = 0;

beforeAll(async () => {
  doomedRequest = await createDoomedRequestFactory(SCRATCH_DB);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function nextUser(): string {
  userSeq += 1;
  return `health-err-user-${String(userSeq)}`;
}

async function makeKey(): Promise<CryptoKey> {
  return cryptoService.importVaultKey(cryptoService.generateVaultKey());
}

async function healthDbName(userId: string): Promise<string> {
  return `${HEALTH_DB_PREFIX}-${await deriveUserHash(userId)}`;
}

/**
 * Put this user's health database at a version the module cannot open, so its
 * `indexedDB.open(name, 1)` fails through `request.onerror` with a real
 * `VersionError`. No part of the module is substituted.
 */
async function blockDatabaseWithNewerVersion(userId: string): Promise<void> {
  (await openRawDatabase(await healthDbName(userId), 2)).close();
}

describe('healthResultsStore — a database that will not open', () => {
  it('loads as a clean cache miss', async () => {
    const userId = nextUser();
    await blockDatabaseWithNewerVersion(userId);

    await expect(loadHealthResults(userId, await makeKey())).resolves.toBeNull();
  });

  it('makes a breach save a silent no-op rather than a rejection', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await blockDatabaseWithNewerVersion(userId);

    await expect(
      saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 3 }], 0, 1),
    ).resolves.toBeUndefined();
    // Nothing was written, so a later read still misses — the save degraded, it
    // did not half-succeed.
    await expect(loadHealthResults(userId, key)).resolves.toBeNull();
  });

  it('makes a strength save a silent no-op rather than a rejection', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await blockDatabaseWithNewerVersion(userId);

    await expect(
      saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 2 }]),
    ).resolves.toBeUndefined();
    await expect(loadHealthResults(userId, key)).resolves.toBeNull();
  });

  it('lets a clear resolve, so logout is never blocked by it', async () => {
    const userId = nextUser();
    await blockDatabaseWithNewerVersion(userId);

    await expect(clearHealthResults(userId)).resolves.toBeUndefined();
  });
});

describe('healthResultsStore — a read request that fails', () => {
  it('treats a failed record read as a cache miss', async () => {
    const userId = nextUser();
    const key = await makeKey();
    // Seed a real record first, so a `null` answer can only come from the failed
    // read and not from an empty store.
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 7 }], 0, 42);
    expect(await loadHealthResults(userId, key)).not.toBeNull();

    vi.spyOn(IDBObjectStore.prototype, 'get').mockImplementation(
      () => doomedRequest() as IDBRequest<unknown>,
    );
    await expect(loadHealthResults(userId, key)).resolves.toBeNull();

    // And the failure was transient, not destructive: the record is still there.
    vi.restoreAllMocks();
    const recovered = await loadHealthResults(userId, key);
    expect(recovered?.perItem.a).toEqual({ v: 'v1', breach: 7 });
    expect(recovered?.scanCompletedAt).toBe(42);
  });
});

describe('healthResultsStore — a write transaction that fails', () => {
  /**
   * Redirect `put` to `add`, so writing the single `v1` record over an existing
   * one becomes a real `ConstraintError` that bubbles to the write
   * transaction's `onerror`. One substitution at the storage boundary; the
   * failure, the event and the `DOMException` are the engine's own.
   */
  function putBehavesAsAdd(): void {
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (
      this: IDBObjectStore,
      value: unknown,
    ) {
      return this.add(value);
    });
  }

  it('swallows the failure and leaves the previous snapshot untouched', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 100);

    putBehavesAsAdd();
    await expect(
      saveBreachResults(userId, key, [{ id: 'a', v: 'v2', breach: 9 }], 5, 200),
    ).resolves.toBeUndefined();

    vi.restoreAllMocks();
    const payload = await loadHealthResults(userId, key);
    // Not merged, not cleared, not half-written: the older snapshot survives
    // whole. Persistence degrading to session-only is the documented behaviour.
    expect(payload?.perItem.a).toEqual({ v: 'v1', breach: 1 });
    expect(payload?.scanCompletedAt).toBe(100);
    expect(payload?.breachFailedCount).toBe(0);
  });

  it('keeps the write queue alive, so the next save still lands', async () => {
    // `enqueueWrite` chains through both outcomes; a rejected op that broke the
    // chain would silently stop every later persist for the tab's lifetime.
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 100);

    putBehavesAsAdd();
    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 3 }]);
    vi.restoreAllMocks();

    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 4 }]);

    const payload = await loadHealthResults(userId, key);
    expect(payload?.perItem.a).toEqual({ v: 'v1', strength: 4, breach: 1 });
  });

  it('swallows a WRITE transaction that ABORTS with no request error to bubble', async () => {
    // The `putStoredRecord` abort leg. `put`'s return value is discarded, so
    // replacing it with an abort issues no request and nothing fires `error`.
    // Without the leg this promise never settles, and because `enqueueWrite`
    // chains every mutation through ONE promise, that stalls every later save
    // AND the logout clear queued behind it — so this test fails by timing out
    // and takes the assertions after it with it, which is the shape of the bug.
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 11);

    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (this: IDBObjectStore) {
      this.transaction.abort();
      return undefined as unknown as IDBRequest<IDBValidKey>;
    });

    await expect(
      saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 4 }]),
    ).resolves.toBeUndefined();

    vi.restoreAllMocks();
    // Rolled back whole, and the queue still works afterwards.
    expect((await loadHealthResults(userId, key))?.perItem.a).toEqual({ v: 'v1', breach: 1 });
    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 2 }]);
    expect((await loadHealthResults(userId, key))?.perItem.a).toEqual({
      v: 'v1',
      strength: 2,
      breach: 1,
    });
  });
});

describe('healthResultsStore — a clear that fails', () => {
  it('resolves anyway, and leaves the snapshot rather than half-deleting it', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 4 }], 0, 7);

    // `clear()` issues no `put`, so the substitution is on `clear` itself: it
    // becomes a duplicate `add` against the record just written.
    vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
      return this.add({ key: 'v1' }) as unknown as IDBRequest<undefined>;
    });

    await expect(clearHealthResults(userId)).resolves.toBeUndefined();

    vi.restoreAllMocks();
    expect((await loadHealthResults(userId, key))?.perItem.a).toEqual({ v: 'v1', breach: 4 });
  });

  it('resolves when the clear transaction ABORTS with no request error to bubble', async () => {
    // The module discards `clear()`'s return value, so replacing it with an abort
    // issues no request at all: the transaction ends with an `abort` event and
    // there is no `error` event to bubble to `tx.onerror`. A handler that listens
    // only for `complete` and `error` therefore never settles — and because
    // `authStore.logout` AWAITS this promise, logout would hang for the rest of
    // the session with the vault half torn down. That is the exact property this
    // module exists to hold, defeated by a branch nothing was listening on.
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 3);

    vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
      this.transaction.abort();
      return undefined as unknown as IDBRequest<undefined>;
    });

    await expect(clearHealthResults(userId)).resolves.toBeUndefined();

    vi.restoreAllMocks();
    // The abort rolled nothing back because nothing was written; the snapshot is
    // still there, which is the right outcome for a clear that did not happen.
    expect((await loadHealthResults(userId, key))?.perItem.a).toEqual({ v: 'v1', breach: 1 });
  });

  it('still resolves when the clear runs behind an in-flight save', async () => {
    // The clear is queued behind any pending save so a persist cannot land after
    // it and resurrect a cleared snapshot. A failure inside the queue must not
    // strand the caller — logout awaits this promise.
    const userId = nextUser();
    const key = await makeKey();

    const save = saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 2 }], 0, 9);
    const clear = clearHealthResults(userId);
    await expect(Promise.all([save, clear])).resolves.toEqual([undefined, undefined]);

    expect(await loadHealthResults(userId, key)).toBeNull();
  });
});
