import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { SANDBOX_ASSETS_DIR, SANDBOX_HTML, sandboxManualChunks } from './vite.config.helpers';

/**
 * The document sandbox's build — a SECOND build, not a second input.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS SEPARATE AT ALL
 * ---------------------------------------------------------------------------
 *
 * `sandbox.html` could have been added to the app build's
 * `rollupOptions.input`, and that would have been wrong in a way nothing in the
 * pipeline would report. The application renders note bodies with
 * `react-markdown`, and this document needs the same `unified` / `remark` /
 * `micromark` / `mdast` / `hast` substrate. `manualChunks` returns `undefined`
 * for every one of those modules, so in ONE build Rollup hoists them into a
 * chunk reachable from both entries — and `chunkFileNames` then cannot classify
 * it, because both answers are wrong. Emit it to `assets/` and the sandbox's
 * import is CORS-blocked, so markdown preview is dead in production. Emit it to
 * `sandbox-assets/` and the app's own notes chunk silently leaves the PWA
 * precache and the `bundle` gate's measured set.
 *
 * Two graphs, two outputs, and no shared chunk is POSSIBLE. The separation is
 * structural instead of something maintained by care. The cost — the markdown
 * substrate present in both bundles — is accepted deliberately: the sandbox's
 * copy never enters the app's initial payload and never enters its precache, so
 * neither the offline behaviour nor the start-up budget changes.
 *
 * Zod stays host-side for the same reason rather than merely for tidiness:
 * `manualChunks` puts `zod` in `vendor-core` alongside AXIOS, so a shared
 * runtime schema would drag an HTTP client into a document whose entire premise
 * is that it can issue no request. The message TYPES are shared as type-only
 * imports, which are erased at build time; the sandbox hand-rolls its own
 * validator for the handful of shapes it accepts.
 *
 * ---------------------------------------------------------------------------
 * THE PLUGINS THAT ARE ABSENT, AND WHY
 * ---------------------------------------------------------------------------
 *
 *   * NO `VitePWA`. A second instance would emit its own `sw.js` over the app's,
 *     replacing the application's service worker with one that precaches a
 *     preview document. (The app's plugin cannot reach this output either:
 *     workbox globs `dist` at the END of the app build, before this build has
 *     written anything, which is why `sandbox.html` and `sandbox-assets/` cannot
 *     enter the precache manifest at all.)
 *   * NO `@vitejs/plugin-react`. The sandbox is plain DOM: no framework in the
 *     document that parses untrusted input is a smaller attack surface and a
 *     smaller download.
 *   * NO `@tailwindcss/vite`. This is a constraint on later work as much as a
 *     decision here: `sandbox.css` must be authored as PLAIN CSS, because with
 *     no Tailwind plugin in this config a file of utility classes ships
 *     unstyled and reports no error at all.
 */
export default defineConfig({
  build: {
    // The same directory the app builds into: one `public/` tree ships, and the
    // Express static root, the Nginx document root and the smoke gate's staged
    // artifact all keep exactly one layout to know about.
    outDir: 'dist',
    // MANDATORY. Vite's `resolveEmptyOutDir` returns true whenever `outDir` is
    // inside the project root, so the default would make this build DELETE the
    // application it was just told to sit beside. The symptom is a missing app,
    // not anything that reads as being about the sandbox.
    emptyOutDir: false,
    // `public/` is copied by the app build. Vite re-copies it on every build, so
    // leaving this on would rewrite that copy for nothing.
    copyPublicDir: false,
    // NO MODULEPRELOAD POLYFILL, and this is a security invariant rather than a
    // size one — though it is both.
    //
    // Vite injects that polyfill into every entry by default, and it contains a
    // `fetch()` call and a `MutationObserver` over the whole document. It early-
    // returns on any browser that supports `modulepreload`, and `sandbox.html`
    // declares no preload links, so it is dead in practice — but this document's
    // own code says in two places that it fetches NOTHING, and a reader checking
    // that claim against the built chunk would find a `fetch(` and be right to
    // doubt it. Turning it off makes the claim structural instead of
    // conditional, and reclaims ~700 bytes of a deliberately tight budget.
    //
    // Nothing is lost: the application build keeps its polyfill, and this
    // document has one entry and no preload list for a polyfill to act on.
    modulePreload: { polyfill: false },
    // ONE setting, and it is the whole of the routing. Vite derives
    // `entryFileNames`, `chunkFileNames` AND `assetFileNames` from `assetsDir`.
    // Setting only `assetFileNames` — the plausible mistake, because the
    // stylesheet is the file one thinks about — routes the stylesheet correctly
    // and leaves every JS chunk in `dist/assets/`, which is served with no
    // `Access-Control-Allow-Origin`; the module fetch from an opaque origin then
    // fails and the frame is SILENTLY blank. The CSS matters for the mirror
    // reason: it is an ASSET rather than a chunk, so it travels by a different
    // option than the entry, and `/assets/` carries neither the ACAO a CORS-mode
    // module needs nor the CORP a no-cors stylesheet link needs. A viewer that
    // ships unstyled in production only is that symptom, and every header
    // assertion still passes, because they all look at the entry script.
    assetsDir: SANDBOX_ASSETS_DIR,
    sourcemap: process.env.NODE_ENV !== 'production',
    // The highlight.js common language set, reached through `lowlight`, is
    // measured at ~887 KiB and is the largest thing this document can load. It
    // is deliberately lazy twice over — `renderers/text.ts` imports it only for
    // an extension that maps to a real grammar, and the markdown pipeline only
    // for a document that actually contains a fenced block with a declared
    // language — so it never enters the entry chunk.
    //
    // The advisory is raised to the number the GATE already enforces
    // (`bundle.budgetKb.lowlight` in `scripts/ci/lib/bundle-budgets.mjs`, which
    // is ratcheted downward and can never be quietly loosened) rather than to
    // whatever silences it. Vite's default 500 kB would print a warning on every
    // build for a chunk whose size is a measured, bounded decision, and a
    // warning nobody can act on is how a real one gets ignored. The application
    // config does the same thing, for zxcvbn, for the same reason.
    chunkSizeWarningLimit: 960,
    rollupOptions: {
      // Absolute, resolved from this file: the build is invoked from the
      // package directory by `scripts/build.mjs`, but a relative input would
      // silently resolve against `process.cwd()` if it ever were not.
      input: fileURLToPath(new URL(SANDBOX_HTML, import.meta.url)),
      output: {
        // `manualChunks` AND NOTHING ELSE. `entryFileNames`, `chunkFileNames`
        // and `assetFileNames` are all DERIVED from `assetsDir` above, and
        // setting any of them here — plausibly, to "match the app" — overrides
        // that derivation and puts every JS chunk back in `dist/assets/`, which
        // is served with no `Access-Control-Allow-Origin`. The frame's module
        // fetch then fails and the document is silently blank in production
        // only. `packages/client/tests/vite-config.test.ts` pins this key set.
        manualChunks: sandboxManualChunks,
      },
    },
  },
});
