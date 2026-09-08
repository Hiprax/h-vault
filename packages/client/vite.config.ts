import { defaultAllowedOrigins, defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';
import {
  NAVIGATE_FALLBACK_DENYLIST,
  WORKBOX_GLOB_IGNORES,
  WORKBOX_GLOB_PATTERNS,
  manualChunks,
  resolveDevHost,
  resolveDevPort,
} from './vite.config.helpers.ts';

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: 'prompt',
      includeAssets: ['favicon.ico', 'favicon.svg'],
      manifest: {
        name: 'H-Vault',
        short_name: 'H-Vault',
        description: 'Zero-knowledge password manager',
        theme_color: '#3b82f6',
        background_color: '#0a0f1e',
        display: 'standalone',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: '/pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png',
          },
          {
            src: '/pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
          },
        ],
      },
      workbox: {
        globPatterns: WORKBOX_GLOB_PATTERNS,
        cleanupOutdatedCaches: true,
        // Defence in depth that cannot currently fire, and the constant says so
        // in full: the PWA plugin runs only in the APP build and workbox globs
        // `dist` before the sandbox build has written anything, so there is
        // nothing here for these patterns to match. What actually keeps the
        // sandbox out of the precache is the two-build layout.
        globIgnores: WORKBOX_GLOB_IGNORES,
        // MANDATORY, not conditional: an iframe load IS a navigation, and
        // without this the service worker answers `/sandbox.html` with the
        // application shell. See the constant for the whole reason, including
        // why the anchor is `(?:\?|$)` and not a bare `$`.
        navigateFallbackDenylist: NAVIGATE_FALLBACK_DENYLIST,
        runtimeCaching: [
          {
            urlPattern: /^https?:\/\/.*\/api\//,
            handler: 'NetworkOnly',
          },
        ],
      },
    }),
  ],
  server: {
    // 5173 by default (Vite's own), overridable via VITE_PORT. NOT 3000: Windows
    // reserves dynamic ranges that swallow it, and the bind then fails EACCES.
    // See resolveDevPort in vite.config.helpers.ts.
    port: resolveDevPort(),
    // Loopback by default (local dev / E2E / CI). Docker dev sets VITE_HOST=0.0.0.0
    // so the container's published port is reachable from the host.
    host: resolveDevHost(),
    // Fail loudly rather than silently sliding to another port, which would
    // desync Playwright's fixed probe URL and the documented dev URL.
    strictPort: true,
    // DEV ONLY, and required for the document sandbox to load at all here.
    //
    // In dev, `npm run dev` serves `/sandbox.html` with unbundled modules from
    // `/src/sandbox/` and `/node_modules/.vite/deps/` — NOT from
    // `sandbox-assets/` — so the path-scoped rule that production uses cannot
    // apply. A module script is fetched in CORS mode unconditionally, and the
    // frame holds an opaque origin, so its request carries `Origin: null`. Vite
    // 8 defaults `server.cors` to `{ origin: defaultAllowedOrigins }`, a regex
    // matching only localhost / 127.0.0.1 / [::1]; `null` fails it, no
    // `Access-Control-Allow-Origin` comes back, the fetch is a network error,
    // and the frame is blank in dev exactly as it would be in production
    // without the header.
    //
    // This is what the e2e and a11y gates actually drive (`playwright.config.ts`
    // runs `e2e/start-server.ts`, which spawns `npm run dev`), and nothing
    // earlier catches it: jsdom never loads an iframe's `src`.
    //
    // The default regex is KEPT and `'null'` is ADDED to it, rather than the
    // whole thing being replaced with `true` or `'*'`. Vite introduced that
    // default deliberately, to stop any website reading a developer's source
    // out of their dev server, and replacing it outright would undo that for
    // every path at once.
    //
    // BE HONEST ABOUT WHAT THIS STILL COSTS, because "narrowest possible
    // addition" would be a comfortable half-truth and is how the next person
    // justifies widening it further. `null` is not OUR frame's origin; it is
    // the serialization of EVERY opaque origin. Any page a developer visits can
    // mint one — `<iframe sandbox="allow-scripts" srcdoc="...">` — fetch from
    // this loopback dev server, and post the response up to itself. So this
    // re-admits the class of read Vite's default closed, for the dev server
    // only. It is accepted on four counts and none of them is "it is narrow":
    // the setting exists only in development and reaches no built artifact
    // (production scopes the same permission to `sandbox-assets/` alone, by
    // path); the server binds loopback by default; no credential is granted, so
    // nothing authenticated can be read (the API is a separate process and the
    // access token lives in memory); and what is readable is this project's own
    // client source, which ships to every visitor in production regardless. A
    // path-scoped rule is NOT the missing refinement — in dev the frame's
    // modules come from `/src/...` and `/node_modules/.vite/deps/...`, so
    // scoping would mean enumerating the transitive graph and would fail
    // silently the first time it grew.
    cors: { origin: [defaultAllowedOrigins, 'null'] },
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: process.env.NODE_ENV !== 'production',
    // zxcvbn ships an irreducible ~820 kB dictionary that is loaded lazily
    // (only for password-strength checks), so the advisory is raised just above
    // it. Eager chunks stay far below this via manualChunks below.
    chunkSizeWarningLimit: 850,
    rollupOptions: {
      output: {
        // Split eager vendors into cacheable chunks and keep lazy deps in their
        // own on-demand chunks (see vite.config.helpers.ts).
        manualChunks,
      },
    },
  },
});
