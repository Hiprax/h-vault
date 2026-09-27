/**
 * The browser never asks the JavaScript engine to compile a string, so the
 * application's Content-Security-Policy (`script-src` without `'unsafe-eval'`)
 * has nothing to refuse.
 *
 * Zod 4 decides whether it may use its compiled object parser by PROBING:
 * `new Function('')` inside a try/catch, run the first time an object schema is
 * constructed unless `z.config({ jitless: true })` is already in force. Under
 * this application's policy the probe can only fail, and a failed probe is not
 * silent: the browser raises a `securitypolicyviolation` and prints it on the
 * console of every page. `@hvault/shared/zod` sets `jitless` in every browser
 * realm before any schema exists, and this file pins that from the outside, by
 * watching the engine's string-compilation entry point itself while the real
 * schemas are built and used.
 *
 * WHY THE PRECONDITION. Zod keeps its configuration on `globalThis` and is
 * loaded natively rather than through Vitest's module graph, so a Zod that some
 * earlier import had already loaded would have made its decision before the
 * trap below existed, and this test would pass without observing anything. Each
 * test file runs in a fresh worker, and the assertion turns "fresh" from an
 * assumption into a checked fact: if isolation ever changes, this fails loudly
 * instead of passing vacuously.
 */
import { describe, expect, it } from 'vitest';

interface Recorded {
  kind: 'construct' | 'call';
  args: unknown[];
}

describe('building and using the shared schemas in a browser realm', () => {
  it('never compiles a string, so a CSP without unsafe-eval has nothing to report', async () => {
    const zodGlobal = globalThis as { __zod_globalConfig?: unknown };
    expect(zodGlobal.__zod_globalConfig, 'Zod was already loaded in this worker').toBeUndefined();

    const RealFunction = globalThis.Function;
    const recorded: Recorded[] = [];
    globalThis.Function = new Proxy(RealFunction, {
      construct(target, args: unknown[], newTarget: (...a: unknown[]) => unknown) {
        recorded.push({ kind: 'construct', args });
        return Reflect.construct(target, args, newTarget) as object;
      },
      apply(target, thisArg: unknown, args: unknown[]) {
        recorded.push({ kind: 'call', args });
        return Reflect.apply(target, thisArg, args) as unknown;
      },
    });

    try {
      const shared = await import('@hvault/shared');
      const { z } = await import('zod');

      // Real schemas, parsed for real: the object parser is exercised, not only
      // constructed, and it still produces the right values.
      expect(shared.paginationSchema.parse({ page: '2' })).toEqual({ page: 2, limit: 50 });
      expect(shared.listVaultItemsSchema.parse({ sortOrder: 'asc', trash: 'false' })).toEqual({
        page: 1,
        limit: 50,
        sortOrder: 'asc',
        sortBy: 'updatedAt',
        trash: false,
      });
      const refused = shared.listVaultItemsSchema.safeParse({ sortOrder: 'sideways' });
      expect(refused.success).toBe(false);

      expect(recorded).toEqual([]);
      expect(z.config().jitless).toBe(true);

      // The client's own schemas import `@hvault/shared/zod`, and it must be the
      // same Zod the shared schemas were built with, not a second copy that
      // could make its own decision before `jitless` was set on it.
      const configured = await import('@hvault/shared/zod');
      expect(configured.z).toBe(z);
      const clientSchema = configured.z.object({ note: configured.z.string() });
      expect(clientSchema.parse({ note: 'a  b', extra: 1 })).toEqual({ note: 'a  b' });
      expect(recorded).toEqual([]);
    } finally {
      globalThis.Function = RealFunction;
    }
  });
});
