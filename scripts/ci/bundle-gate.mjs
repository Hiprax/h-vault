#!/usr/bin/env node
/**
 * `audit:bundle` — the client bundle's size budgets.
 *
 * What this gate exists for is one specific regression, and it is a regression
 * no other check in this repository can see: a library that is DELIBERATELY
 * loaded on demand becoming a static import. zxcvbn (~400 kB), Argon2id via
 * hash-wasm, and the whole file-encryption tool are all dynamic chunks by
 * design, and turning any of them into an eager one is a one-line change that
 * type-checks, lints, passes every test, builds cleanly and makes the
 * application slower to start for every visitor forever.
 *
 * `vite.config.ts` already declares a 850 kB `chunkSizeWarningLimit`. A warning
 * printed during a build is not a gate; this makes that number binding and adds
 * the one it does not cover: the INITIAL PAYLOAD, which is what a first-time
 * visitor downloads before anything renders.
 *
 *   node scripts/ci/bundle-gate.mjs      the gate (this is what the pipeline runs)
 *   npm run audit:bundle                 the same thing
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. IT MEASURES THE BUILT ARTIFACT, not the config that produced it. A
 *     `manualChunks` table asserted against itself proves nothing about what the
 *     bundler emitted; the emitted bytes are the only honest subject. That is why
 *     the task declares `build:client` as a prerequisite: with no `dist` the gate
 *     reports "could not run" (exit 2) rather than passing over nothing.
 *
 *  b. THE INITIAL PAYLOAD IS READ FROM `index.html`, not assumed. The entry
 *     module, its `modulepreload` list and its stylesheets are exactly what the
 *     browser fetches before first paint, and the bundler is the one that decides
 *     that list. Reading it back is what makes a chunk PROMOTED into the eager
 *     graph visible here.
 *
 *  c. BUDGETS ARE KEYED BY CHUNK BASE NAME. Filenames carry a content hash that
 *     changes on every meaningful edit, so a budget keyed by filename would need
 *     rewriting on every commit and would therefore be deleted. `main-4aSwR9SA.js`
 *     is measured as `main`.
 *
 *  d. EVERY CHUNK HAS A CEILING, listed or not. `DEFAULT_CHUNK_BUDGET_KB` covers
 *     the ones with no entry of their own, so a new route cannot arrive
 *     unbounded — which is the hole a hand-maintained list always has.
 *
 *  e. TWO ASSET DIRECTORIES ARE ENUMERATED, NOT ONE. The client is built twice:
 *     the application into `dist/assets/`, and the document sandbox — its own
 *     Vite config, its own module graph — into `dist/sandbox-assets/`. A gate
 *     that walked only `assets/` would leave every sandbox chunk both unmeasured
 *     and unbounded, AND would make any budget key added for one of them match
 *     nothing at all: `bundle.budgetKb.*` ratchets `lower`, so an entry that
 *     matches no file is a ceiling that can never be exceeded and a test that
 *     can never fail. The same applies to the HTML shell: there are two
 *     documents now, each is a shell rather than an asset store, and each is
 *     held to the same per-document budget.
 *
 *  f. THE TWO GRAPHS ARE CHECKED FOR CROSS-REFERENCES, IN BOTH DIRECTIONS.
 *     `index.html` must name nothing from `sandbox-assets/`, and `sandbox.html`
 *     nothing from `assets/`. Each direction catches a different way the
 *     separation rots: the first is the application picking up a chunk that is
 *     served with permissive CORS headers, the second is the sandbox depending
 *     on one served with none — and the second is silent, because the frame goes
 *     blank in production while every header assertion elsewhere still passes.
 *     The check is phrased against the DIRECTORIES rather than against "the
 *     sandbox graph", because a module shared between the two would land in
 *     neither and an assertion about graphs would quietly mean nothing.
 *
 *  h. THE SANDBOX'S CHUNKS MUST CONTAIN NO NETWORK PRIMITIVE. The isolated
 *     render document is served under `connect-src 'none'`, which blocks every
 *     way of READING a response — `fetch`, `XMLHttpRequest`, WebSockets,
 *     `EventSource`, `sendBeacon` — so any one of those in its bundle is dead
 *     code that a later policy change would silently bring to life. (It is only
 *     those that the policy stops: `script-src`, `style-src`, `img-src` and
 *     `font-src` allow `'self'`, so an `<img>` src is still a GET this server
 *     sees. `packages/server/src/config/sandboxCsp.ts` states the bound.) The
 *     rule exists because the absence was briefly FALSE of the built artifact
 *     while true of the source: Vite injects a
 *     modulepreload polyfill into every entry by default, and it carries a
 *     `fetch()` and a document-wide `MutationObserver`. It was inert (no preload
 *     links, and it early-returns on any modern engine), which is exactly why
 *     nothing noticed. `build.modulePreload: { polyfill: false }` removed it;
 *     this check is what stops it, or anything like it, coming back. A string
 *     scan of minified output is a blunt instrument, and it is the right one
 *     here: the claim is about the BYTES that reach an opaque origin, and the
 *     honest subject of a claim about bytes is the bytes.
 *
 *  g. THE SERVICE WORKER'S PRECACHE MANIFEST IS A CANARY, NOT A PROOF. It must
 *     name no `sandbox.html` and nothing under `sandbox-assets/`. Under the
 *     current layout it CANNOT: the PWA plugin runs only in the application
 *     build and workbox globs `dist` before the sandbox build has written
 *     anything, so the `globIgnores` in `vite.config.helpers.ts` match nothing
 *     and this assertion is one that cannot fail today. It is here for the day
 *     the two builds are merged, which is the change that would make it fire —
 *     and the failure it guards is invisible otherwise, because `registerType:
 *     'prompt'` keeps installed clients on the old service worker, so a
 *     precached `sandbox.html` naming un-precached hashed URLs would hand every
 *     returning user a 404 and a dead viewer after a deploy.
 *
 *  i. `/api/` MUST BE `NetworkOnly`, AND THAT ONE CAN FAIL TODAY. It is the
 *     difference between "the server stores ciphertext" and "the browser also
 *     keeps a durable unencrypted copy": any caching strategy on `/api/` would
 *     write every downloaded document segment into the Cache API, where it
 *     survives a lock, a logout and the browser being closed. It is one word in
 *     `vite.config.ts` and changing it reads as a performance improvement, which
 *     is exactly why it is asserted against the GENERATED worker rather than
 *     against the config that asks for it.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, writeJsonReport } from './lib/reports.mjs';
import {
  CHUNK_BUDGETS_KB,
  DEFAULT_CHUNK_BUDGET_KB,
  HTML_SHELL_BUDGET_KB,
  INITIAL_PAYLOAD_BUDGET_KB,
  chunkBaseName,
} from './lib/bundle-budgets.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const distDir = path.join(repoRoot, 'packages', 'client', 'dist');
const indexHtml = path.join(distDir, 'index.html');
/**
 * The isolated render document is emitted OUTSIDE `dist/`, and that is a
 * security control rather than a layout preference: `dist/` becomes both the
 * `express.static` root and the Nginx document root, and the sandbox document's
 * whole containment is the per-response CSP Express attaches to it, so a copy
 * either server could answer off disk carries the application's policy instead.
 * `packages/client/vite.config.helpers.ts` (`SANDBOX_DOCUMENT_OUT_DIR`) holds
 * the argument and the four URL spellings that proved ordering was not enough.
 *
 * It matters here because this gate must keep reading the document from where it
 * now is, while resolving the assets it NAMES against `dist/` — they did not
 * move and must not.
 */
const sandboxDocumentDir = path.join(repoRoot, 'packages', 'client', 'dist-sandbox');

/**
 * (e) The two documents the client build emits, and the asset directory each
 * one's chunks are routed to. Both must exist for the gate to have run at all:
 * a missing `sandbox.html` means the second build did not happen, which is a
 * "could not run" rather than a pass over half the output.
 *
 * Carried with their absolute paths because the two now live in different
 * directories; every reference they hold is still resolved against `distDir`.
 */
const HTML_SHELLS = [
  { file: 'index.html', absolute: indexHtml },
  { file: 'sandbox.html', absolute: path.join(sandboxDocumentDir, 'sandbox.html') },
];
const SANDBOX_ASSETS_DIR = 'sandbox-assets';
const ASSET_DIRS = ['assets', SANDBOX_ASSETS_DIR];

const kb = (bytes) => Number((bytes / 1024).toFixed(2));

for (const { absolute } of HTML_SHELLS) {
  if (existsSync(absolute)) continue;
  console.error(
    color.red(`  ✖ ${path.relative(repoRoot, absolute)} is missing — build the client first`),
  );
  process.exit(2);
}

ensureReportDir();

const html = readFileSync(indexHtml, 'utf8');

/** Every asset an HTML document tells the browser to fetch before it paints. */
const referencedAssets = (document) => [
  ...[...document.matchAll(/<script[^>]+type="module"[^>]+src="([^"]+)"/g)].map((m) => m[1]),
  ...[...document.matchAll(/<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"/g)].map((m) => m[1]),
  ...[...document.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"/g)].map((m) => m[1]),
];

// (b) Exactly what the browser fetches before first paint.
const eager = referencedAssets(html);

const problems = [];

// (e) Each document is a shell, not an asset store, and each is held to the
// same per-document ceiling. That per-document check is the GATE.
//
// The reported `measured.htmlShellKb` is their sum, and it is a RECORD rather
// than a gate: `ratchet-check.mjs` declares `bundle.measured.*` as `info` and
// skips it before any comparison, and it never reads this report at all — only
// the committed CEILINGS (`bundle.budgetKb.*`, `defaultChunkBudgetKb`,
// `initialPayloadBudgetKb`, `htmlShellBudgetKb`) are ratcheted, direction
// `lower`, straight from `lib/bundle-budgets.mjs`. That is deliberate on the
// ratchet's part and is worth stating plainly here, because the opposite belief
// is what would prompt someone to "repair" it by flipping the direction — which
// would price every legitimate new page as a regression. The per-file
// breakdown is emitted beside the sum so the record stays readable when the sum
// moves.
const htmlShells = [];
let htmlShellBytes = 0;
for (const { file: shell, absolute } of HTML_SHELLS) {
  const bytes = statSync(absolute).size;
  htmlShellBytes += bytes;
  htmlShells.push({ file: shell, kb: kb(bytes) });
  if (kb(bytes) > HTML_SHELL_BUDGET_KB) {
    problems.push(
      `${shell} is ${String(kb(bytes))} KiB, over its ${String(HTML_SHELL_BUDGET_KB)} KiB budget`,
    );
  }
  // Every asset EACH document names must actually be in the output. This was
  // asymmetric before the sandbox arrived — `index.html`'s references were
  // checked and nothing checked the other document's — and the asymmetry mattered
  // precisely for the new one: a build that emitted `sandbox.html` naming chunks
  // it had not written produces a frame that never boots, never handshakes, and
  // degrades to "download to view" with no failing gate anywhere.
  for (const href of referencedAssets(readFileSync(absolute, 'utf8'))) {
    if (existsSync(path.join(distDir, href.replace(/^\//, '')))) continue;
    problems.push(`${shell} references ${href}, which is not in the build output`);
  }
}

let initialPayloadBytes = statSync(indexHtml).size;
const eagerAssets = [];
for (const href of eager) {
  const file = path.join(distDir, href.replace(/^\//, ''));
  // Missing files are already reported by the per-shell loop above; here the
  // only job is to skip one so the payload total is not a lie.
  if (!existsSync(file)) continue;
  const bytes = statSync(file).size;
  initialPayloadBytes += bytes;
  eagerAssets.push({ href, kb: kb(bytes) });
}

// (c) + (d) + (e) Every emitted chunk, in BOTH asset directories, measured and
// bounded. A directory that does not exist is reported rather than skipped: the
// only way `sandbox-assets/` is absent is that the second build did not run, and
// silently measuring half the output is exactly the failure this widening
// exists to prevent.
const chunks = [];
let totalJsBytes = 0;
for (const dir of ASSET_DIRS) {
  const absolute = path.join(distDir, dir);
  if (!existsSync(absolute)) {
    problems.push(`the build output has no ${dir}/ directory`);
    continue;
  }
  for (const entry of readdirSync(absolute).sort()) {
    if (!entry.endsWith('.js') && !entry.endsWith('.css')) continue;
    const bytes = statSync(path.join(absolute, entry)).size;
    if (entry.endsWith('.js')) totalJsBytes += bytes;
    const base = chunkBaseName(entry);
    const budgetKb = CHUNK_BUDGETS_KB[base] ?? DEFAULT_CHUNK_BUDGET_KB;
    const overBudget = kb(bytes) > budgetKb;
    if (overBudget) {
      problems.push(
        `chunk ${base} is ${String(kb(bytes))} KiB, over its ${String(budgetKb)} KiB budget (${dir}/${entry})`,
      );
    }
    chunks.push({
      dir,
      file: entry,
      base,
      kb: kb(bytes),
      budgetKb,
      explicitBudget: base in CHUNK_BUDGETS_KB,
      overBudget,
    });
  }
}

if (chunks.length === 0) {
  problems.push('the build output contains no chunks at all');
}

// AN EXPLICIT BUDGET KEY MUST COVER EXACTLY ONE CHUNK.
//
// Budgets are keyed by chunk BASE NAME and there are two directories, so a name
// occurring in both shares one ceiling between two unrelated chunks. That is the
// hazard: raising the key to fit the sandbox's copy would silently raise the
// application's by the same amount, and `bundle.budgetKb.*`'s `lower` ratchet
// cannot see it, because it is one key. A sandbox chunk that arrived named
// `main` would inherit the application's 850 KiB ceiling instead of the 128 KiB
// default, and nothing would say so.
//
// The rule is scoped to names with an EXPLICIT entry, and that scoping is a
// correction rather than a relaxation. Rolldown emits its own runtime shim as a
// chunk in EVERY graph that code-splits, so `rolldown-runtime` appears in both
// directories the moment the sandbox gains its per-mode dynamic imports — which
// is the design, not a naming mistake, and no rename is available for a chunk
// the bundler names itself. Two unlisted chunks share nothing that can be
// quietly raised: they both fall under `DEFAULT_CHUNK_BUDGET_KB`, which every
// unlisted chunk in both directories already shares. The dangerous case — a
// collision on a name that carries its own ceiling — is still refused outright.
const dirsByBase = new Map();
for (const chunk of chunks) {
  const seen = dirsByBase.get(chunk.base) ?? new Set();
  seen.add(chunk.dir);
  dirsByBase.set(chunk.base, seen);
}
for (const [base, dirs] of dirsByBase) {
  if (dirs.size < 2) continue;
  if (!(base in CHUNK_BUDGETS_KB)) continue;
  problems.push(
    `chunk name ${base} carries an explicit budget and is emitted into ${[...dirs].sort().join(' and ')}, so one ceiling would cover two unrelated chunks`,
  );
}

// (f) Neither document may reach into the other's asset directory.
for (const { file: shell, absolute } of HTML_SHELLS) {
  const forbidden = shell === 'sandbox.html' ? 'assets' : 'sandbox-assets';
  for (const href of referencedAssets(readFileSync(absolute, 'utf8'))) {
    // `/assets/` is a prefix of nothing else, but `/sandbox-assets/` starts with
    // neither, so each is matched on its own leading segment rather than by
    // `includes`, which would report `/assets/x.js` for the sandbox's own
    // directory and never fire for the application's.
    if (!href.replace(/^\//, '').startsWith(`${forbidden}/`)) continue;
    problems.push(`${shell} references ${href}, which belongs to the other build's ${forbidden}/`);
  }
}

// (h) The isolated document carries no primitive that could READ a response,
// checked against what was actually emitted rather than against what its source
// says.
const NETWORK_PRIMITIVES = ['fetch(', 'XMLHttpRequest', 'navigator.sendBeacon', 'EventSource'];
const sandboxDir = path.join(distDir, SANDBOX_ASSETS_DIR);
if (existsSync(sandboxDir)) {
  for (const entry of readdirSync(sandboxDir).sort()) {
    if (!entry.endsWith('.js')) continue;
    const source = readFileSync(path.join(sandboxDir, entry), 'utf8');
    for (const primitive of NETWORK_PRIMITIVES) {
      if (!source.includes(primitive)) continue;
      problems.push(
        `${SANDBOX_ASSETS_DIR}/${entry} contains ${primitive}, but the sandbox is served under connect-src 'none', which blocks every way of reading a response`,
      );
    }
  }
}

// (g) The precache canary, and (i) the one thing about the service worker that
// is NOT a canary.
const serviceWorker = path.join(distDir, 'sw.js');
if (!existsSync(serviceWorker)) {
  problems.push('the build output has no sw.js, so the precache manifest cannot be checked');
} else {
  const manifest = readFileSync(serviceWorker, 'utf8');
  // `vendor-prettier-` joins the canary rather than forming a second check.
  // Those four chunks are emitted by the SANDBOX build, so they are excluded by
  // the same thing that excludes everything else it emits — the build layout,
  // not a glob — and this fires only if the two builds are merged. Naming them
  // explicitly is worth a line anyway, because they are the largest thing that
  // would arrive in the precache if they ever were: about a megabyte pushed into
  // the install-time download of every user, including everyone who never ticks
  // a checkbox.
  for (const forbidden of ['sandbox.html', 'sandbox-assets/', 'vendor-prettier-']) {
    if (!manifest.includes(forbidden)) continue;
    problems.push(
      `the service worker precaches ${forbidden}, which means the two builds have been merged`,
    );
  }
  // (i) `/api/` IS `NetworkOnly`, and this one CAN fail today.
  //
  // It is what keeps a document's segment ciphertext out of the Cache API: a
  // caching strategy on `/api/` would write every downloaded segment into a
  // durable, unencrypted store that survives a lock, a logout and the browser
  // being closed. The strategy is one word in `vite.config.ts`'s
  // `runtimeCaching`, and changing it is the kind of edit that reads as a
  // performance improvement.
  //
  // Asserted against the GENERATED worker rather than the config, because the
  // config is an instruction and this is the artifact that ships. Both halves
  // are required: the route must exist, and it must be bound to `NetworkOnly`.
  const apiRoute = /registerRoute\(\s*\/\^https\?:[^,]*api[^,]*,\s*new\s+\w+\.NetworkOnly/.test(
    manifest,
  );
  if (!apiRoute) {
    problems.push(
      'the service worker does not register /api/ as NetworkOnly, so API responses — including document segment ciphertext — could enter the Cache API',
    );
  }
}
if (kb(initialPayloadBytes) > INITIAL_PAYLOAD_BUDGET_KB) {
  problems.push(
    `the initial payload is ${String(kb(initialPayloadBytes))} KiB, over its ${String(INITIAL_PAYLOAD_BUDGET_KB)} KiB budget`,
  );
}

writeJsonReport('bundle.json', {
  version: 1,
  task: 'audit:bundle',
  checkedAt: new Date().toISOString(),
  budgets: {
    chunkKb: CHUNK_BUDGETS_KB,
    defaultChunkKb: DEFAULT_CHUNK_BUDGET_KB,
    initialPayloadKb: INITIAL_PAYLOAD_BUDGET_KB,
    htmlShellKb: HTML_SHELL_BUDGET_KB,
  },
  measured: {
    htmlShellKb: kb(htmlShellBytes),
    htmlShells,
    initialPayloadKb: kb(initialPayloadBytes),
    totalJsKb: kb(totalJsBytes),
    chunkCount: chunks.length,
    eagerAssets,
  },
  problems,
  chunks,
});

if (problems.length > 0) {
  for (const problem of problems) console.error(color.red(`      ${problem}`));
  warn(`${String(problems.length)} bundle budget violation(s)`);
  process.exit(1);
}

note(
  `bundle.json — initial payload ${String(kb(initialPayloadBytes))} KiB of ${String(INITIAL_PAYLOAD_BUDGET_KB)}, ` +
    `${String(chunks.length)} chunks across ${String(ASSET_DIRS.length)} asset directories, ` +
    `${String(kb(totalJsBytes))} KiB of JavaScript, every budget met`,
);
