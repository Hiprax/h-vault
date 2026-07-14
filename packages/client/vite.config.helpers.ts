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
