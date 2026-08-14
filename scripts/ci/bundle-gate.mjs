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

const kb = (bytes) => Number((bytes / 1024).toFixed(2));

if (!existsSync(indexHtml)) {
  console.error(
    color.red(`  ✖ ${path.relative(repoRoot, indexHtml)} is missing — build the client first`),
  );
  process.exit(2);
}

ensureReportDir();

const html = readFileSync(indexHtml, 'utf8');
const htmlBytes = Buffer.byteLength(html, 'utf8');

// (b) Exactly what the browser fetches before first paint.
const eager = [
  ...[...html.matchAll(/<script[^>]+type="module"[^>]+src="([^"]+)"/g)].map((m) => m[1]),
  ...[...html.matchAll(/<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"/g)].map((m) => m[1]),
  ...[...html.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"/g)].map((m) => m[1]),
];

const problems = [];
let initialPayloadBytes = htmlBytes;
const eagerAssets = [];
for (const href of eager) {
  const file = path.join(distDir, href.replace(/^\//, ''));
  if (!existsSync(file)) {
    problems.push(`index.html references ${href}, which is not in the build output`);
    continue;
  }
  const bytes = statSync(file).size;
  initialPayloadBytes += bytes;
  eagerAssets.push({ href, kb: kb(bytes) });
}

// (c) + (d) Every emitted chunk, measured and bounded.
const assetsDir = path.join(distDir, 'assets');
const chunks = [];
let totalJsBytes = 0;
for (const entry of existsSync(assetsDir) ? readdirSync(assetsDir).sort() : []) {
  if (!entry.endsWith('.js') && !entry.endsWith('.css')) continue;
  const bytes = statSync(path.join(assetsDir, entry)).size;
  if (entry.endsWith('.js')) totalJsBytes += bytes;
  const base = chunkBaseName(entry);
  const budgetKb = CHUNK_BUDGETS_KB[base] ?? DEFAULT_CHUNK_BUDGET_KB;
  const overBudget = kb(bytes) > budgetKb;
  if (overBudget) {
    problems.push(
      `chunk ${base} is ${String(kb(bytes))} KiB, over its ${String(budgetKb)} KiB budget (${entry})`,
    );
  }
  chunks.push({
    file: entry,
    base,
    kb: kb(bytes),
    budgetKb,
    explicitBudget: base in CHUNK_BUDGETS_KB,
    overBudget,
  });
}

if (chunks.length === 0) {
  problems.push('the build output contains no chunks at all');
}
if (kb(htmlBytes) > HTML_SHELL_BUDGET_KB) {
  problems.push(
    `index.html is ${String(kb(htmlBytes))} KiB, over its ${String(HTML_SHELL_BUDGET_KB)} KiB budget`,
  );
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
    htmlShellKb: kb(htmlBytes),
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
    `${String(chunks.length)} chunks, ${String(kb(totalJsBytes))} KiB of JavaScript, every budget met`,
);
