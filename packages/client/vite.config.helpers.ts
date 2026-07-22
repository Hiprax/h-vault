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
  if (/\/node_modules\/(react|react-dom|react-router|react-router-dom|scheduler)\//.test(path)) {
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
