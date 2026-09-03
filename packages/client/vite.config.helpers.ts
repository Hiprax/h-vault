/**
 * Pure, dependency-free helpers for the client Vite build configuration.
 *
 * These are kept in a standalone module (importing no Vite plugins) so the
 * dev-host and chunking logic can be unit-tested in isolation, without having
 * to evaluate the full Vite config and its plugin chain.
 */

/**
 * Resolves the Vite dev-server bind address.
 *
 * Defaults to the loopback interface (`127.0.0.1`) for safe local development,
 * E2E runs, and CI. Containerized development (`docker-compose.dev.yml`) sets
 * `VITE_HOST=0.0.0.0` so Vite binds the container's external interface and the
 * published port becomes reachable from the host — Docker DNATs published ports
 * to the container's `eth0`, not its loopback, so a loopback-only bind is
 * unreachable from outside the container.
 *
 * An empty `VITE_HOST` is treated as unset.
 */
export function resolveDevHost(env: Record<string, string | undefined> = process.env): string {
  return env.VITE_HOST || '127.0.0.1';
}

/**
 * Default Vite dev-server port.
 *
 * 5173 is Vite's own canonical default. It is deliberately NOT 3000: on Windows,
 * Hyper-V / WSL2 / Docker reserve dynamic TCP ranges that routinely swallow 3000
 * (observed: 2932-3031). A reserved port fails the bind with **EACCES**, not
 * EADDRINUSE, and because the dev server runs with `strictPort: true` that aborts
 * Vite outright — which also takes the Playwright E2E suite down, since its
 * webServer probe waits on this port. 5173 sits outside those reserved ranges.
 *
 * Override with `VITE_PORT` if 5173 is ever taken. `playwright.config.ts` imports
 * this same helper, so the dev server and the E2E probe URL can never drift apart.
 */
export const DEFAULT_DEV_PORT = 5173;

/**
 * Resolves the Vite dev-server port from `VITE_PORT`, falling back to
 * {@link DEFAULT_DEV_PORT}.
 *
 * An empty, non-numeric, or out-of-range value is treated as unset rather than
 * passed through: `Number('') === 0` would otherwise bind a RANDOM free port,
 * silently desyncing Playwright's fixed probe URL and every documented dev URL.
 */
export function resolveDevPort(env: Record<string, string | undefined> = process.env): number {
  const raw = env.VITE_PORT;
  if (!raw) return DEFAULT_DEV_PORT;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) return DEFAULT_DEV_PORT;
  return parsed;
}

/**
 * Rollup `manualChunks` strategy for the production build.
 *
 * Goals:
 * 1. Split large, eagerly-loaded vendor code into stable, long-term-cacheable
 *    chunks so the initial entry stays small and no eager chunk trips the
 *    chunk-size advisory.
 * 2. Keep heavy on-demand dependencies (zxcvbn, qrcode, react-markdown,
 *    otpauth, …) in their own dynamic chunks: the function returns `undefined`
 *    for them so they are NEVER hoisted into an eager vendor chunk. (A blanket
 *    `node_modules` catch-all must never be added — it would pull these lazy
 *    deps, especially the ~820 kB zxcvbn dictionary, into the initial download.)
 *
 * Only an explicit allow-list of always-eager packages is grouped; every other
 * module returns `undefined` and uses Vite's default on-demand chunking.
 *
 * `id` is an absolute on-disk module path using OS-native separators, so it is
 * normalized to forward slashes for cross-platform matching (Windows paths use
 * backslashes).
 */
export function manualChunks(id: string): string | undefined {
  const path = id.replace(/\\/g, '/');

  if (!path.includes('/node_modules/')) {
    // First-party source uses Vite's default (route-based) chunking.
    return undefined;
  }

  // React runtime + router: always eager, grouped together.
  //
  // `react-router` is the only router package to match: v8 removed
  // `react-router-dom` entirely and folded its exports back into `react-router`,
  // so listing the old name here would be a dead alternative. Note the
  // alternation order is load-bearing in the other direction — `react`,
  // `react-dom` and `react-router` are all prefixes of longer package names, and
  // each alternative is anchored by the trailing `\/`, so `react-router-x` can
  // never match `react-router`.
  if (/\/node_modules\/(react|react-dom|react-router|scheduler)\//.test(path)) {
    return 'vendor-react';
  }

  // Other always-loaded vendors: validation, HTTP, state, and forms.
  if (/\/node_modules\/(zod|axios|zustand|react-hook-form|@hookform)\//.test(path)) {
    return 'vendor-core';
  }

  // Everything else — including lazy-only deps (zxcvbn, qrcode, react-markdown,
  // otpauth) — falls through to Vite's default on-demand chunking.
  return undefined;
}

/**
 * Rollup `manualChunks` strategy for the DOCUMENT SANDBOX's build.
 *
 * A SECOND function rather than a branch inside {@link manualChunks}, and the
 * separation is the point: the application build must never carry naming rules
 * for a package it must never contain. If it did, the day somebody statically
 * imported the format engine from an application module, Rollup would emit the
 * app's own copy of Prettier under the same chunk names as the sandbox's — and
 * `scripts/ci/bundle-gate.mjs` reports a base name that carries an explicit
 * budget and is emitted into BOTH asset directories, so the two copies would
 * share one ceiling that could be raised for either.
 *
 * As it stands, that mistake fails the gate on SIZE instead: the app's copies
 * take Rollup's default names (`standalone`, `babel`, `estree`, …) and each is
 * measured against `DEFAULT_CHUNK_BUDGET_KB`, which three of them breach on
 * their own. Either way it is caught; this way the two builds' budgets stay
 * independent. The assertion that actually fires FIRST, and reads as what it is,
 * is `packages/client/tests/sandbox-boundary.test.ts`: no module outside
 * `src/sandbox/` may reach into it at runtime.
 *
 * FOUR Prettier chunks, not one, because the per-type dynamic imports in
 * `src/sandbox/transform/formatEngine.ts` are what makes formatting a README
 * cost 288 KB instead of a megabyte:
 *
 *   - `vendor-prettier-core`   `standalone` + `estree`, needed by every syntax
 *   - `vendor-prettier-json`   the `babel` parser, for the JSON family
 *   - `vendor-prettier-markdown`
 *   - `vendor-prettier-yaml`
 *
 * Everything else — the renderers, `lowlight`, `jsonrepair` — returns
 * `undefined` and keeps Vite's per-dynamic-import chunking, which is what put
 * each renderer in its own chunk in the first place. A blanket `node_modules`
 * catch-all must never be added here for the same reason it must never be added
 * to the application's: it would collapse every on-demand chunk into one eager
 * download, and in this build that download happens inside a frame that opens
 * for a `.png`.
 *
 * `id` is an absolute on-disk path in OS-native separators, so it is normalised
 * to forward slashes before matching, exactly as the application's is.
 */
export function sandboxManualChunks(id: string): string | undefined {
  const path = id.replace(/\\/g, '/');

  if (!path.includes('/node_modules/prettier/')) {
    // First-party source and every other dependency use Vite's default
    // per-dynamic-import chunking.
    return undefined;
  }

  // Anchored on the FILE each plugin is, not on a directory: Prettier ships its
  // plugins as `plugins/<name>.mjs`, so the trailing dot is what stops
  // `markdown.` from also matching a hypothetical `markdown-extra.mjs`.
  if (path.includes('/prettier/plugins/babel.')) return 'vendor-prettier-json';
  if (path.includes('/prettier/plugins/markdown.')) return 'vendor-prettier-markdown';
  if (path.includes('/prettier/plugins/yaml.')) return 'vendor-prettier-yaml';
  // `standalone` and `estree` and anything else Prettier pulls in. `estree` is
  // the PRINTER for what the `babel` parser produces and is equally needed by
  // Markdown and YAML runs that never load `babel`, so it belongs with the core
  // rather than with the JSON parser.
  return 'vendor-prettier-core';
}

// ---------------------------------------------------------------------------
// The document sandbox's output layout, and the service worker's view of it
// ---------------------------------------------------------------------------
//
// These are plain data, in this dependency-free module, for one reason: the
// application's Vite config pulls React, Tailwind and the PWA plugin, so it
// cannot be imported cheaply in a unit test — and asserting a config's SOURCE
// TEXT proves nothing about what Vite was actually handed. Exported constants
// can be asserted directly, and both configs import them, so the pattern that
// excludes a directory and the setting that creates it cannot drift apart.

/**
 * The document sandbox's HTML entry, relative to the client package root.
 *
 * Named in three places that must agree: `vite.config.sandbox.ts` builds it, the
 * service worker's navigation denylist has to exempt it, and the Express route
 * that serves it attaches the sandbox's own Content-Security-Policy. The first
 * two import this constant; the third is a different package and pins the same
 * string in its own test.
 */
export const SANDBOX_HTML = 'sandbox.html';

/**
 * Where the sandbox build's chunks and assets are emitted.
 *
 * A DIRECTORY, and its own, because that directory alone is served with
 * `Access-Control-Allow-Origin: *` and `Cross-Origin-Resource-Policy:
 * cross-origin` — which a module script fetched by an opaque origin needs and
 * which `assets/` deliberately does not carry. Setting `build.assetsDir` to this
 * is the ONE setting from which Vite derives the entry, chunk and asset
 * filenames alike.
 */
export const SANDBOX_ASSETS_DIR = 'sandbox-assets';

/**
 * What the service worker precaches: everything the application build emits.
 *
 * Unchanged in substance from the literal it replaces; it lives here so the
 * pattern and the ignore below can be asserted together.
 */
export const WORKBOX_GLOB_PATTERNS = ['**/*.{js,css,html,ico,png,svg,woff2}'];

/**
 * The sandbox output, excluded from the precache.
 *
 * DEFENCE IN DEPTH THAT CANNOT CURRENTLY FIRE, and saying so is the point of
 * this comment. The PWA plugin runs only in the APPLICATION build, and workbox
 * globs the output directory at the END of that build — before the sandbox build
 * has written anything — so `sandbox.html` and `sandbox-assets/` are not there to
 * be matched. The exclusion that actually holds is the BUILD LAYOUT, not this
 * list.
 *
 * It is kept anyway because the hazard it guards is real and silent. With
 * `registerType: 'prompt'` an installed client keeps its old service worker until
 * the user accepts an update, so a precached `sandbox.html` naming hashed asset
 * URLs that were NOT precached would, after a deploy, hand every returning user a
 * 404, a handshake timeout and "download to view". Under two separate builds that
 * cannot happen; if the two are ever merged, it can, and this is what would
 * already be in place.
 *
 * `scripts/ci/bundle-gate.mjs` asserts the generated manifest contains no sandbox
 * entry. Label that for what it is: a CANARY against the builds being merged, not
 * evidence that this list does anything today.
 */
export const WORKBOX_GLOB_IGNORES = [SANDBOX_HTML, `${SANDBOX_ASSETS_DIR}/**`];

/**
 * Navigations the service worker must NOT answer with the application shell.
 *
 * MANDATORY rather than conditional. `vite-plugin-pwa` ships
 * `defaultWorkbox = { …, navigateFallback: 'index.html' }` and this project sets
 * none of its own, so a NavigationRoute covers every navigation — and AN IFRAME
 * LOAD IS A NAVIGATION. Without this the service worker answers `/sandbox.html`
 * with the app shell: the frame boots the application instead of the sandbox,
 * never completes a handshake, and the viewer degrades to "download to view"
 * with no failing request anywhere to explain it.
 *
 * Anchored with `(?:\?|$)` rather than a bare `$`, because workbox tests a
 * denylist entry against `pathname + search`. A bare `$` stops matching the
 * moment the frame's `src` gains a query string — a theme hint, a cache-buster —
 * and the failure is invisible: only an INSTALLED client, only after a deploy,
 * and only as a viewer that quietly degrades.
 */
export const NAVIGATE_FALLBACK_DENYLIST = [/^\/sandbox\.html(?:\?|$)/];
