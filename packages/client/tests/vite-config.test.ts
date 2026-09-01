// @vitest-environment node
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DEV_PORT,
  NAVIGATE_FALLBACK_DENYLIST,
  SANDBOX_ASSETS_DIR,
  SANDBOX_HTML,
  WORKBOX_GLOB_IGNORES,
  WORKBOX_GLOB_PATTERNS,
  manualChunks,
  resolveDevHost,
  resolveDevPort,
} from '../vite.config.helpers';

// T31 — the Vite dev-server host must be overridable via VITE_HOST so the dev
// Docker container can bind 0.0.0.0 (and thus be reachable through Docker's
// published port), while every other context keeps the safe loopback default.
describe('resolveDevHost (T31 — dev Docker reachability)', () => {
  it('defaults to loopback when VITE_HOST is unset', () => {
    expect(resolveDevHost({})).toBe('127.0.0.1');
  });

  it('treats an empty VITE_HOST as unset', () => {
    expect(resolveDevHost({ VITE_HOST: '' })).toBe('127.0.0.1');
  });

  it('binds the configured VITE_HOST when set (e.g. 0.0.0.0 in Docker)', () => {
    expect(resolveDevHost({ VITE_HOST: '0.0.0.0' })).toBe('0.0.0.0');
  });

  it('reads from process.env by default', () => {
    const original = process.env.VITE_HOST;
    try {
      process.env.VITE_HOST = '0.0.0.0';
      expect(resolveDevHost()).toBe('0.0.0.0');
      delete process.env.VITE_HOST;
      expect(resolveDevHost()).toBe('127.0.0.1');
    } finally {
      if (original === undefined) {
        delete process.env.VITE_HOST;
      } else {
        process.env.VITE_HOST = original;
      }
    }
  });
});

// The dev-server port must be overridable via VITE_PORT (Docker dev, or a host
// where the default is taken) and must NEVER silently resolve to 0 — Vite would
// then bind a RANDOM free port and Playwright's fixed probe URL would hang until
// its 180s webServer timeout. The default is deliberately not 3000: Windows
// reserves dynamic TCP ranges that routinely include it, and a reserved port
// fails to bind with EACCES, which aborts a `strictPort: true` dev server.
describe('resolveDevPort (dev-server port resolution)', () => {
  it('defaults to Vite’s 5173 when VITE_PORT is unset', () => {
    expect(resolveDevPort({})).toBe(5173);
    expect(DEFAULT_DEV_PORT).toBe(5173);
  });

  it('never defaults to a Windows-reserved 3000', () => {
    expect(resolveDevPort({})).not.toBe(3000);
  });

  it('uses a valid VITE_PORT override', () => {
    expect(resolveDevPort({ VITE_PORT: '5180' })).toBe(5180);
  });

  it('treats an empty VITE_PORT as unset', () => {
    expect(resolveDevPort({ VITE_PORT: '' })).toBe(DEFAULT_DEV_PORT);
  });

  it('falls back rather than binding a random port on a non-numeric value', () => {
    expect(resolveDevPort({ VITE_PORT: 'not-a-port' })).toBe(DEFAULT_DEV_PORT);
  });

  it('rejects out-of-range and non-integer values', () => {
    expect(resolveDevPort({ VITE_PORT: '0' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '70000' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '-1' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '5173.5' })).toBe(DEFAULT_DEV_PORT);
  });

  it('reads from process.env by default', () => {
    const original = process.env.VITE_PORT;
    try {
      process.env.VITE_PORT = '5181';
      expect(resolveDevPort()).toBe(5181);
      delete process.env.VITE_PORT;
      expect(resolveDevPort()).toBe(DEFAULT_DEV_PORT);
    } finally {
      if (original === undefined) {
        delete process.env.VITE_PORT;
      } else {
        process.env.VITE_PORT = original;
      }
    }
  });
});

// T30 — manualChunks must split eager vendors into cacheable chunks while
// leaving heavy on-demand deps (zxcvbn, qrcode, react-markdown, otpauth) in
// their own dynamic chunks, so no eager chunk trips the size advisory.
describe('manualChunks (T30 — vendor splitting)', () => {
  it('groups the React runtime + router into vendor-react', () => {
    expect(manualChunks('/repo/node_modules/react/index.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/react-dom/client.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/react-router/dist/index.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/scheduler/index.js')).toBe('vendor-react');
  });

  it('matches Windows (backslash) module paths too', () => {
    expect(manualChunks('C:\\repo\\node_modules\\react-dom\\client.js')).toBe('vendor-react');
    expect(manualChunks('C:\\repo\\node_modules\\react-router\\dist\\production\\index.js')).toBe(
      'vendor-react',
    );
    expect(manualChunks('C:\\repo\\node_modules\\zod\\index.js')).toBe('vendor-core');
  });

  // Every alternative in the vendor-react group is a PREFIX of some other real
  // package name (`react` of `react-router`, `react-router` of the now-removed
  // `react-router-dom`), so the trailing path separator is what keeps the match
  // anchored to a whole package directory. Without it, dropping the
  // `react-router-dom` alternative during the v8 migration would have been
  // indistinguishable from silently widening `react-router` to match any
  // `react-router-*` package.
  it('anchors each vendor-react alternative to a whole package directory', () => {
    // Not the router, despite sharing its prefix.
    expect(manualChunks('/repo/node_modules/react-router-dom/dist/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/react-routerx/index.js')).toBeUndefined();
    // A lazy-only React ecosystem package must keep its own dynamic chunk.
    // (`react-markdown` makes the same point and is already asserted above.)
    expect(manualChunks('/repo/node_modules/react-window/dist/index.js')).toBeUndefined();
    // The router's own transitive dependency is not hoisted into an eager chunk.
    // This is not idle: CLAUDE.md records "a blanket node_modules catch-all must
    // never be added", and this is the assertion that would catch one.
    expect(manualChunks('/repo/node_modules/cookie-es/dist/index.mjs')).toBeUndefined();
  });

  it('groups always-eager data/form vendors into vendor-core', () => {
    expect(manualChunks('/repo/node_modules/zod/lib/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/axios/lib/axios.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/zustand/esm/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/react-hook-form/dist/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/@hookform/resolvers/zod/dist/index.js')).toBe(
      'vendor-core',
    );
  });

  it('keeps heavy lazy-only deps out of any eager vendor chunk', () => {
    expect(manualChunks('/repo/node_modules/zxcvbn/lib/main.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/qrcode/lib/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/react-markdown/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/micromark/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/otpauth/dist/otpauth.esm.js')).toBeUndefined();
  });

  it('leaves application source to default chunking', () => {
    expect(manualChunks('/repo/packages/client/src/stores/authStore.ts')).toBeUndefined();
    expect(manualChunks('/repo/packages/client/src/components/ui/Button.tsx')).toBeUndefined();
  });
});

// Confirm the real Vite config wires the tested helpers (faithfulness) and the
// chunk-size advisory limit that accommodates the lazy zxcvbn dictionary chunk.
describe('vite.config wiring', () => {
  it('wires the dev host, manualChunks, and chunk-size limit', async () => {
    const mod = await import('../vite.config');
    const config = mod.default as {
      server?: { host?: unknown; strictPort?: unknown; port?: unknown; cors?: unknown };
      build?: {
        chunkSizeWarningLimit?: unknown;
        rollupOptions?: { output?: { manualChunks?: unknown } };
      };
    };

    expect(config.server?.host).toBe(resolveDevHost());
    expect(config.server?.strictPort).toBe(true);
    // Resolved through the shared helper (the same one playwright.config.ts uses),
    // never a second hardcoded literal that could drift from the probe URL. Compared
    // against the helper rather than the 5173 literal so a developer running with
    // VITE_PORT set does not see a spurious failure; the default itself is pinned
    // environment-independently in the resolveDevPort suite above.
    expect(config.server?.port).toBe(resolveDevPort());
    expect(config.build?.rollupOptions?.output?.manualChunks).toBe(manualChunks);
    expect(config.build?.chunkSizeWarningLimit).toBe(850);
  });
});

// The document sandbox is a SECOND Vite build, and every setting below is one
// that fails SILENTLY when it is missing: a blank frame, an unstyled viewer, or
// an application deleted by the build that was meant to sit beside it. None of
// them is observable in jsdom (which never loads an iframe's `src`) and none is
// observable in the app's own build output, so they are pinned here, against the
// real configs, before anything downstream depends on them.
describe('the document sandbox build', () => {
  it('routes chunks AND assets into sandbox-assets/ through the one setting that does both', async () => {
    const mod = await import('../vite.config.sandbox');
    const config = mod.default as {
      build?: {
        assetsDir?: unknown;
        emptyOutDir?: unknown;
        copyPublicDir?: unknown;
        outDir?: unknown;
        rollupOptions?: { input?: unknown; output?: unknown };
      };
      plugins?: unknown;
    };

    // ONE setting, from which Vite derives `entryFileNames`, `chunkFileNames`
    // AND `assetFileNames`. Setting only `assetFileNames` is the plausible
    // mistake — it routes the stylesheet and leaves every JS chunk in
    // `dist/assets/`, which is served with no `Access-Control-Allow-Origin`, so
    // the opaque origin's module fetch fails and the frame is silently blank
    // while every header assertion elsewhere still passes.
    // Compared against the SHARED constant rather than the literal, because the
    // service worker's ignore list is built from the same one. A literal here
    // would let the build move its output while the exclusion kept naming the
    // old directory, and a glob that matches nothing is a check that cannot fail.
    expect(config.build?.assetsDir).toBe(SANDBOX_ASSETS_DIR);
    // MANDATORY. `resolveEmptyOutDir` returns true whenever `outDir` is inside
    // the project root, so the default would make this build delete the
    // application it was just told to sit beside — surfacing as a missing app,
    // not as anything about the sandbox.
    expect(config.build?.emptyOutDir).toBe(false);
    // The app build already copied `public/`; Vite re-copies it on every build.
    expect(config.build?.copyPublicDir).toBe(false);
    expect(config.build?.outDir).toBe('dist');
    expect(String(config.build?.rollupOptions?.input).endsWith(SANDBOX_HTML)).toBe(true);
    // The assertion that actually closes the failure the comment above
    // describes. `assetsDir` only decides the filenames Vite DERIVES; an
    // explicit `rollupOptions.output.chunkFileNames` (added, plausibly, to
    // "match the app") overrides that derivation and puts every JS chunk back in
    // `dist/assets/`, where it is served with no ACAO — a frame that is blank in
    // production only, with every header assertion elsewhere still green.
    expect(config.build?.rollupOptions?.output).toBeUndefined();
  });

  it('sets its size advisory to the ceiling the gate actually enforces', async () => {
    // The advisory and the gate must name ONE number. `bundle.budgetKb.lowlight`
    // is ratcheted `lower`, so tightening it without this would leave the
    // sandbox build printing no warning until well past the point the gate
    // fails — an advisory that has silently stopped advising.
    //
    // Read from the gate's own module rather than restated, which is the same
    // thing `gate-surface.test.ts` does with `chunkBaseName`.
    // Imported without a cast on purpose: `packages/client/tsconfig.test.json`
    // sets `allowJs`, so the key is resolved against the real table and renaming
    // `lowlight` there fails THIS file at type-check. A `Record<string, number>`
    // cast would instead hand back `undefined` and compare it to the advisory.
    const { CHUNK_BUDGETS_KB } = await import('../../../scripts/ci/lib/bundle-budgets.mjs');
    const mod = await import('../vite.config.sandbox');
    const config = mod.default as { build?: { chunkSizeWarningLimit?: unknown } };
    expect(config.build?.chunkSizeWarningLimit).toBe(CHUNK_BUDGETS_KB.lowlight);
  });

  it('emits no modulepreload polyfill, so "this document fetches nothing" is structural', async () => {
    // Vite injects that polyfill into every entry by default, and it carries a
    // `fetch()` and a document-wide `MutationObserver`. It is inert here — no
    // preload links, and it early-returns on any modern engine — but the
    // sandbox's own source claims in two places that it makes no request of any
    // kind, and a reader checking that against the built chunk would find a
    // `fetch(` and be right to doubt it. `scripts/ci/bundle-gate.mjs` asserts the
    // built output; this asserts the setting that produces it.
    const mod = await import('../vite.config.sandbox');
    const config = mod.default as { build?: { modulePreload?: unknown } };
    expect(config.build?.modulePreload).toEqual({ polyfill: false });
  });

  it('carries no plugin from the application build', async () => {
    const mod = await import('../vite.config.sandbox');
    const config = mod.default as { plugins?: unknown[] };
    // A second `VitePWA` would emit its own `sw.js` OVER the application's,
    // replacing the app's service worker with one that precaches a preview
    // document. React and Tailwind are absent for their own reasons (a smaller
    // parser surface, and the plain-CSS constraint the sandbox stylesheet
    // inherits). Asserted as "no plugins at all" rather than "not VitePWA",
    // because the next plugin added here would be added without thought.
    expect(config.plugins ?? []).toEqual([]);
  });

  it('builds the application FIRST and the sandbox SECOND', async () => {
    // Order and `emptyOutDir` are one invariant, not two settings. Vite empties
    // an `outDir` inside the project root, so with the default the sandbox
    // build deletes the app; reverse the order and the app build would delete
    // the sandbox instead. Read out of the runner rather than asserted about
    // the config, because the runner is what decides it.
    const runner = await readFile(
      fileURLToPath(new URL('../scripts/build.mjs', import.meta.url)),
      'utf8',
    );
    const appBuild = runner.indexOf("viteBuild('vite build')");
    const sandboxBuild = runner.indexOf("viteBuild('vite build (sandbox)'");
    expect(appBuild).toBeGreaterThan(-1);
    expect(sandboxBuild).toBeGreaterThan(appBuild);
    expect(runner).toContain('vite.config.sandbox.ts');
    // Through the SAME retry wrapper, never a bare `spawnSync`: that wrapper
    // exists for Rolldown's intermittent native teardown segfault on Windows,
    // and a second build without it fails a Windows contributor's push for a
    // reason the first build is already known to survive.
    expect(runner.match(/spawnSync\(/g) ?? []).toHaveLength(1);
  });
});

// The dev server is what the e2e and a11y gates actually drive, and it serves
// the sandbox's modules from `/src/sandbox/` rather than from `sandbox-assets/`,
// so the production path-scoped header rule cannot reach them.
describe('the dev server answers the sandbox frame', () => {
  it("allows an Origin: null request without widening past Vite's own default", async () => {
    const { defaultAllowedOrigins } = await import('vite');
    const mod = await import('../vite.config');
    const config = mod.default as { server?: { cors?: { origin?: unknown } } };
    const origins = config.server?.cors?.origin;

    expect(Array.isArray(origins)).toBe(true);
    const list = origins as unknown[];
    // This is the assertion that proves the addition is LOAD-BEARING rather
    // than decorative: an opaque origin sends the literal string `null`, and
    // Vite's default regex does not match it. Without the entry below, the
    // module fetch gets no ACAO, fails as a network error, and the frame is
    // blank in dev — which nothing earlier catches, because jsdom never loads
    // an iframe's src.
    expect(defaultAllowedOrigins.test('null')).toBe(false);
    expect(list).toContain('null');
    // And the default is KEPT rather than replaced. `origin: true` or `'*'`
    // would also make the frame work, and would drop the restriction for every
    // request rather than for the one the frame makes.
    expect(list).toContain(defaultAllowedOrigins);
    // Nothing wider than those two. `'null'` already re-admits every opaque
    // origin (any page can mint one with a sandboxed `srcdoc` iframe), which is
    // a cost the config records rather than hides — but `true`, `'*'` or a
    // catch-all regex on top of it would take the dev server from "readable by
    // an opaque origin" to "readable by name", and would do so without anyone
    // having to write down why.
    expect(list).toHaveLength(2);
    expect(list).not.toContain(true);
    expect(list).not.toContain('*');
  });

  it('keeps the service worker from answering the sandbox frame with the app shell', () => {
    // `vite-plugin-pwa` defaults `navigateFallback` to `index.html` and this
    // config sets none of its own, so a NavigationRoute covers every
    // navigation — and an iframe load IS a navigation. Without the denylist the
    // frame boots the application instead of the sandbox, never handshakes, and
    // the viewer degrades to "download to view" with no failing request
    // anywhere to explain it.
    //
    // The patterns are EXERCISED rather than compared to a literal: a pattern
    // that is present but does not match (a missing escape, a stray anchor) is
    // the whole failure mode, and it would survive any equality assertion.
    const matches = (url: string): boolean =>
      NAVIGATE_FALLBACK_DENYLIST.some((pattern) => pattern.test(url));

    expect(matches('/sandbox.html')).toBe(true);
    // Workbox tests a denylist entry against `pathname + search`, so a bare `$`
    // anchor stops matching the moment the frame's src gains a query string —
    // and the regression is invisible: installed clients only, after a deploy
    // only, as a viewer that silently degrades to "download to view".
    expect(matches('/sandbox.html?theme=dark')).toBe(true);
    // Not so loose that it swallows the application's own routes, which would
    // take the whole offline experience out with it.
    expect(matches('/vault')).toBe(false);
    expect(matches('/documents/abc')).toBe(false);
    expect(matches('/sandbox.html.bak')).toBe(false);
  });

  it('excludes the sandbox from the precache with patterns that would match it', () => {
    // This exclusion CANNOT FIRE today and the constant says so: the PWA plugin
    // runs only in the application build, and workbox globs `dist` at the end of
    // that build — before the sandbox build has written anything — so there is
    // nothing there for these patterns to match. What actually keeps the sandbox
    // out of the precache is the two-build layout, and `scripts/ci/bundle-gate.mjs`
    // asserts the generated manifest as a canary against the two being merged.
    //
    // What IS asserted here is that the list is not decorative: if the builds are
    // ever merged, these patterns have to match the paths they name. A typo'd
    // ignore would otherwise sit in the config looking like protection.
    const ignores = WORKBOX_GLOB_IGNORES;
    expect(ignores).toContain(SANDBOX_HTML);
    expect(ignores).toContain(`${SANDBOX_ASSETS_DIR}/**`);
    // And the precache patterns still cover the application's own output, which
    // is what an over-eager ignore would take with it.
    expect(WORKBOX_GLOB_PATTERNS).toEqual(['**/*.{js,css,html,ico,png,svg,woff2}']);
  });

  it('wires the shared constants into the real config rather than restating them', async () => {
    // Identity, not equality: the whole reason these constants were extracted is
    // that `vite.config.ts` pulls React, Tailwind and the PWA plugin, so its
    // options cannot be read back out of the plugin — and asserting its SOURCE
    // TEXT proves nothing about what Vite was handed. The sandbox config CAN be
    // read back, so the wiring is pinned where it is observable, and the
    // behaviour of the constants is pinned above where it is pure.
    const mod = await import('../vite.config.sandbox');
    const config = mod.default as { build?: { assetsDir?: unknown } };
    expect(config.build?.assetsDir).toBe(SANDBOX_ASSETS_DIR);
    // A second literal `'sandbox-assets'` in `vite.config.ts` is exactly the
    // drift this replaces; the app config imports the same binding.
    const source = await readFile(
      fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
      'utf8',
    );
    expect(source).toContain('WORKBOX_GLOB_IGNORES');
    expect(source).toContain('NAVIGATE_FALLBACK_DENYLIST');
    expect(source).not.toContain("'sandbox-assets'");
  });
});
