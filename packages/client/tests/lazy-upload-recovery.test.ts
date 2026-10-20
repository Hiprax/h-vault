/**
 * `lazyUploadRecovery`'s loading contract.
 *
 * The loader exists for the reason `lazySha256` does: the documents store is
 * reachable STATICALLY from `authStore`, so the upload recovery engine has to be
 * fetched the first time someone uploads, not by every user on every visit.
 *
 * What each case would catch:
 *   • a wrong path in the `import()` — the real module would not load at all.
 *   • dropping the IN-FLIGHT memo — a second caller arriving mid-load starts the
 *     load path over rather than joining it.
 *   • dropping `inFlight = null` on rejection — one failed chunk load would leave
 *     every later upload attached to the same rejected promise for the tab's
 *     whole life.
 *   • dropping the translation — the upload panel would show a bundler's
 *     "Failed to fetch dynamically imported module" to a person.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

const ENGINE = '../src/services/documents/uploadRecovery.js';

/**
 * A fresh module registry per case, because the thing under test IS a
 * module-level cache: importing once at the top would make the second case
 * observe the first one's state.
 */
async function freshLoader(): Promise<typeof import('../src/lib/lazyUploadRecovery')> {
  vi.resetModules();
  return import('../src/lib/lazyUploadRecovery');
}

afterEach(() => {
  vi.doUnmock(ENGINE);
  vi.resetModules();
});

describe('lazyUploadRecovery', () => {
  it('loads the real recovery engine', async () => {
    const { loadUploadRecovery } = await freshLoader();

    const engine = await loadUploadRecovery();

    expect(engine.retryStep).toBeTypeOf('function');
    expect(engine.prepareResume).toBeTypeOf('function');
    expect(engine.UploadStoppedError).toBeTypeOf('function');
  });

  it('performs ONE load for two cold callers, and hands every later caller the same module', async () => {
    const { loadUploadRecovery } = await freshLoader();

    const first = loadUploadRecovery();
    const second = loadUploadRecovery();

    // Promise IDENTITY is what "one load" means, for the reason the
    // `lazySha256` suite records: the ES module map already deduplicates the
    // fetch, so only the handed-back promise shows whether the second caller
    // re-entered the load path. It is also why the loader is not `async`.
    expect(second).toBe(first);
    const engine = await first;
    expect(await second).toBe(engine);
    expect(await loadUploadRecovery()).toBe(engine);
  });

  it('says what happened in words a person can act on, keeping the failure as the cause', async () => {
    vi.resetModules();
    vi.doMock(ENGINE, () => {
      throw new Error('Failed to fetch dynamically imported module');
    });
    const { loadUploadRecovery, UPLOAD_ENGINE_UNAVAILABLE_MESSAGE } =
      await import('../src/lib/lazyUploadRecovery');

    const failure: unknown = await loadUploadRecovery().catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe(UPLOAD_ENGINE_UNAVAILABLE_MESSAGE);
    expect(UPLOAD_ENGINE_UNAVAILABLE_MESSAGE).toBe(
      'Part of H-Vault needed for uploads did not load. Try again; if it keeps failing, reload the page.',
    );
    // The bundler's own wording is kept for the log, never shown.
    expect((failure as Error).message).not.toMatch(/dynamically imported/);
    expect((failure as Error).cause).toBeInstanceOf(Error);
  });

  it('lets a failed load be retried instead of caching the rejection for ever', async () => {
    vi.resetModules();
    let failNextLoad = true;
    vi.doMock(ENGINE, () => {
      if (failNextLoad) {
        failNextLoad = false;
        throw new Error('chunk load failed');
      }
      return { marker: 'the engine' };
    });
    const { loadUploadRecovery } = await import('../src/lib/lazyUploadRecovery');

    const failed = loadUploadRecovery();
    await expect(failed).rejects.toThrow(Error);
    // The discriminating assertion: with the rejected promise kept, this second
    // call would hand back the SAME rejection, and a person whose network blipped
    // during one upload could not upload again without reloading the tab.
    const retried = loadUploadRecovery();
    expect(retried).not.toBe(failed);
    await expect(retried).resolves.toMatchObject({ marker: 'the engine' });
    expect(failNextLoad).toBe(false);
  });
});
