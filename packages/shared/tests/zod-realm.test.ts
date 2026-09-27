/**
 * Which realms build their schemas without Zod's compiled object parser.
 *
 * Every browser realm (a window, the sandboxed preview frame, a worker, and
 * jsdom, which stands in for them in the client suite) is governed by a
 * Content-Security-Policy that refuses string compilation, so Zod's
 * `new Function('')` probe there can only fail, and failing it raises a
 * `securitypolicyviolation`. Node has no such policy, and keeps the compiled
 * parser, which is about three times faster on a rotation-sized body.
 *
 * `packages/client/tests/zod-csp.test.ts` pins the browser side end to end; this
 * file pins the decision itself and that the server's realm is left alone.
 */
import { describe, expect, it, vi } from 'vitest';
import { z, zodRealmConfig } from '../src/zod.js';

describe('zodRealmConfig', () => {
  it.each([
    ['a window (or jsdom)', { document: {} }],
    // Only the property's presence matters: that is how a worker realm shows.
    ['a worker', { WorkerGlobalScope: {} }],
    ['a realm that has both', { document: {}, WorkerGlobalScope: {} }],
  ])('turns the compiled parser off in %s', (_label, scope) => {
    expect(zodRealmConfig(scope)).toEqual({ jitless: true });
  });

  it('leaves the configuration untouched in a realm with neither', () => {
    expect(zodRealmConfig({})).toEqual({});
    // A property merely NAMED like a browser global is still a property: the
    // decision is about what the realm exposes, never about its value.
    expect(zodRealmConfig({ window: {}, self: {} })).toEqual({});
  });

  it("treats the server's own realm as Node, not as a browser", () => {
    expect(zodRealmConfig(globalThis)).toEqual({});
  });
});

describe('the configured Zod, loaded in a browser realm', () => {
  it('applies the decision the moment the module loads, before any schema exists', async () => {
    // Node plays a window for one import: the module is re-evaluated with a
    // `document` present, which is what every page, frame and jsdom test has.
    const scope = globalThis as { document?: unknown };
    scope.document = {};
    try {
      vi.resetModules();
      const fresh = await import('../src/zod.js');
      expect(fresh.z.config().jitless).toBe(true);
    } finally {
      delete scope.document;
      // Zod keeps one configuration per process; hand the rest of this file
      // the Node realm's.
      delete (z.config() as { jitless?: boolean }).jitless;
    }
    expect(z.config().jitless).toBeUndefined();
  });
});

describe('the configured Zod, loaded in Node', () => {
  it('keeps the compiled object parser, and still validates', () => {
    expect(z.config().jitless).not.toBe(true);

    const schema = z.object({ name: z.string().min(1), count: z.number().int() });
    expect(schema.parse({ name: 'a', count: 2, extra: true })).toEqual({ name: 'a', count: 2 });
    expect(schema.safeParse({ name: '', count: 2 }).success).toBe(false);
  });
});
