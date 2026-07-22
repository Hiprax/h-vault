import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { deriveUserHash } from '../src/services/offlineCache';
import {
  loadHealthResults,
  saveBreachResults,
  saveStrengthScores,
  clearHealthResults,
  type BreachSaveEntry,
} from '../src/services/health/healthResultsStore';

let seq = 0;
function nextUser(): string {
  return `user-${String(seq++)}`;
}

async function makeKey(): Promise<CryptoKey> {
  return cryptoService.importVaultKey(cryptoService.generateVaultKey());
}

/** Write a raw record directly into the health DB (to seed corrupt/invalid data). */
async function putRawRecord(userId: string, blob: unknown): Promise<void> {
  const hash = await deriveUserHash(userId);
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(`hvault-health-${hash}`, 1);
    req.onupgradeneeded = () => {
      const d = req.result;
      if (!d.objectStoreNames.contains('results'))
        d.createObjectStore('results', { keyPath: 'key' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('open failed'));
  });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction('results', 'readwrite');
    tx.objectStore('results').put({ key: 'v1', blob });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('put failed'));
  });
  db.close();
}

describe('healthResultsStore', () => {
  it('round-trips breach results (breached count + checked-clean absence)', async () => {
    const userId = nextUser();
    const key = await makeKey();
    const entries: BreachSaveEntry[] = [
      { id: 'a', v: 'v1', breach: 42 },
      { id: 'b', v: 'v1' },
    ];
    await saveBreachResults(userId, key, entries, 1, 1_700_000_000_000);

    const payload = await loadHealthResults(userId, key);
    expect(payload).not.toBeNull();
    expect(payload!.scanCompletedAt).toBe(1_700_000_000_000);
    expect(payload!.breachFailedCount).toBe(1);
    expect(payload!.perItem.a).toEqual({ v: 'v1', breach: 42 });
    expect(payload!.perItem.b).toEqual({ v: 'v1' });
  });

  it('carries a version-matched strength across a later breach save', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 1 }]);
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 9 }], 0, 123);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.perItem.a).toEqual({ v: 'v1', breach: 9, strength: 1 });
  });

  it('drops carried strength when the version changed', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 1 }]);
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v2', breach: 9 }], 0, 123);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.perItem.a).toEqual({ v: 'v2', breach: 9 });
  });

  it('strength save preserves a version-matched breach and drops a mismatched one', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(
      userId,
      key,
      [
        { id: 'a', v: 'v1', breach: 5 },
        { id: 'b', v: 'v1', breach: 7 },
      ],
      0,
      1,
    );
    await saveStrengthScores(userId, key, [
      { id: 'a', v: 'v1', strength: 2 },
      { id: 'b', v: 'v2', strength: 3 },
    ]);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.perItem.a).toEqual({ v: 'v1', strength: 2, breach: 5 });
    expect(payload!.perItem.b).toEqual({ v: 'v2', strength: 3 });
  });

  it('preserves strength-only items not part of a breach scan', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveStrengthScores(userId, key, [{ id: 'x', v: 'v1', strength: 0 }]);
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 3 }], 0, 1);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.perItem.x).toEqual({ v: 'v1', strength: 0 });
    expect(payload!.perItem.a).toEqual({ v: 'v1', breach: 3 });
  });

  it('leaves scanCompletedAt null after a strength-only save', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 1 }]);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.scanCompletedAt).toBeNull();
    expect(payload!.breachFailedCount).toBe(0);
  });

  it('returns null when no record exists', async () => {
    expect(await loadHealthResults(nextUser(), await makeKey())).toBeNull();
  });

  it('returns null when decrypting with a different key (vault-key rotation)', async () => {
    const userId = nextUser();
    const keyA = await makeKey();
    const keyB = await makeKey();
    await saveBreachResults(userId, keyA, [{ id: 'a', v: 'v1', breach: 1 }], 0, 1);
    expect(await loadHealthResults(userId, keyB)).toBeNull();
  });

  it('returns null on undecryptable-to-JSON content', async () => {
    const userId = nextUser();
    const key = await makeKey();
    const blob = await cryptoService.encryptData('not-json-at-all', key);
    await putRawRecord(userId, blob);
    expect(await loadHealthResults(userId, key)).toBeNull();
  });

  it('returns null on a shape-invalid payload', async () => {
    const userId = nextUser();
    const key = await makeKey();
    const blob = await cryptoService.encryptData(JSON.stringify({ nope: true }), key);
    await putRawRecord(userId, blob);
    expect(await loadHealthResults(userId, key)).toBeNull();
  });

  it('serializes concurrent breach + strength writes without clobbering (no RMW race)', async () => {
    const userId = nextUser();
    const key = await makeKey();
    // Fire both writers concurrently (no await between them). Without the write
    // queue, both would load the empty snapshot and the last committer would drop
    // the other's field. Serialized, both fields survive regardless of order.
    const p1 = saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 5 }], 0, 123);
    const p2 = saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 2 }]);
    await Promise.all([p1, p2]);

    const payload = await loadHealthResults(userId, key);
    expect(payload!.perItem.a).toEqual({ v: 'v1', breach: 5, strength: 2 });
    expect(payload!.scanCompletedAt).toBe(123);
  });

  it('clearHealthResults removes the snapshot', async () => {
    const userId = nextUser();
    const key = await makeKey();
    await saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 1);
    expect(await loadHealthResults(userId, key)).not.toBeNull();
    await clearHealthResults(userId);
    expect(await loadHealthResults(userId, key)).toBeNull();
  });

  it('swallows an encryption/write error during save', async () => {
    const userId = nextUser();
    const key = await makeKey();
    const spy = vi
      .spyOn(cryptoService, 'encryptData')
      .mockRejectedValueOnce(new Error('crypto boom'));
    await expect(
      saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 1),
    ).resolves.toBeUndefined();
    spy.mockRestore();
    expect(await loadHealthResults(userId, key)).toBeNull();
  });

  it('degrades gracefully when IndexedDB is unavailable', async () => {
    const userId = nextUser();
    const key = await makeKey();
    const original = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
    Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
    try {
      await expect(
        saveBreachResults(userId, key, [{ id: 'a', v: 'v1', breach: 1 }], 0, 1),
      ).resolves.toBeUndefined();
      await expect(
        saveStrengthScores(userId, key, [{ id: 'a', v: 'v1', strength: 1 }]),
      ).resolves.toBeUndefined();
      await expect(loadHealthResults(userId, key)).resolves.toBeNull();
      await expect(clearHealthResults(userId)).resolves.toBeUndefined();
    } finally {
      if (original) Object.defineProperty(globalThis, 'indexedDB', original);
    }
  });
});
