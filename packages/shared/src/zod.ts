/**
 * The one Zod every schema the browser builds comes from.
 *
 * WHY THIS MODULE EXISTS. The first time Zod 4 constructs an object schema it
 * decides whether it may use its compiled object parser, and it decides by
 * PROBING: `new Function('')` inside a try/catch (`allowsEval` in
 * `zod/v4/core/util.js`), skipped only when `z.config({ jitless: true })` is
 * already in force at that moment. This application's Content-Security-Policy
 * allows no string compilation (`script-src` has no `'unsafe-eval'`), so in a
 * browser the probe can only fail, and a failed probe is not silent: the browser
 * raises a `securitypolicyviolation`, which printed a CSP error on the console
 * of every page. Setting `jitless` changes no parse path there, because the
 * refused probe already made Zod fall back to the same interpreter; it only
 * stops the engine being asked.
 *
 * WHY HERE AND NOT IN THE APP'S ENTRY POINT. The setting has to be in force
 * before the FIRST object schema is constructed, and the shared schemas are
 * built at module scope in a chunk that executes before the entry chunk's own
 * code, so a call at the top of `main.tsx` ran too late. A dependency edge is the
 * only ordering a bundler has to keep whatever it does with chunks: every schema
 * module imports `z` from here, so this module's body has run before any of them.
 * The client's own schemas import `@hvault/shared/zod` for the same reason, and
 * a lint rule (`eslint.config.mjs`) refuses a direct `zod` import in the client
 * and in this package. A dynamic `import('zod')` is the one form it cannot see.
 *
 * WHY `package.json` NAMES THIS FILE IN `sideEffects`. The package is otherwise
 * side-effect free, and under `"sideEffects": false` Rolldown treated this
 * module as a pure re-export of `z` and dropped the `z.config` call from the
 * production bundle (measured: the violation stayed, in Chromium and Firefox).
 * Declared as the one module with a side effect, it is kept, and a bundle that
 * imports only constants from this package still pulls in no Zod.
 *
 * WHY NODE IS LEFT ALONE. The server has no such policy, and there the compiled
 * parser is roughly three times faster: 9.7 ms against 31 ms for a
 * 10,000-item rotation body, measured. So the decision is made per realm: any
 * realm a Content-Security-Policy can govern (a window or frame, a worker, and
 * jsdom, which stands in for them in the client's tests) runs without it.
 */
import { z } from 'zod';

/** The Zod configuration a realm needs: `jitless` wherever a CSP can apply. */
export function zodRealmConfig(scope: object): Parameters<typeof z.config>[0] {
  return 'document' in scope || 'WorkerGlobalScope' in scope ? { jitless: true } : {};
}

z.config(zodRealmConfig(globalThis));

export { z };
