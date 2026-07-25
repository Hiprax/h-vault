/**
 * Guards the router package contract.
 *
 * React Router v8 REMOVED the `react-router-dom` package and folded its exports
 * back into `react-router`; there is no 8.x of `react-router-dom` and no patched
 * 7.x, so `react-router-dom` can only ever pull a `react-router` inside the
 * GHSA-qwww-vcr4-c8h2 vulnerable range (`>=7.12.0 <8.3.0`). Reintroducing it —
 * by hand, or by a tool "helpfully" adding it back alongside a v7 pin — silently
 * reopens that advisory and fails the `audit` and `docker` pipeline gates.
 *
 * Two halves, because either alone is insufficient:
 *
 * 1. A DECLARATION check: no manifest may depend on `react-router-dom`, and no
 *    module specifier anywhere in the package may name it. A stale
 *    `vi.mock('react-router-dom', …)` is the nastiest version of this — it points
 *    at a module nothing imports, so it silently stops mocking and the test
 *    quietly exercises the real router instead of the stub it thinks it installed.
 *
 * 2. A RUNTIME check: the exports this app actually uses must resolve from the
 *    bare `react-router` entry point. That is precisely what the v7 -> v8 rename
 *    changed, and precisely what a future major could change again by pushing
 *    them behind a subpath.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve as pathResolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const clientRoot = pathResolve(__dirname, '..');
const repoRoot = pathResolve(clientRoot, '../..');

/** Directories that are generated or vendored, never authored here. */
const SKIP_DIRS = new Set(['node_modules', 'dist', 'coverage', '.vite', 'dev-dist']);

/** Extensions that can carry a module specifier or a dependency declaration. */
const SCANNED = /\.(?:tsx?|jsx?|mjs|cjs|json)$/;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(join(dir, entry.name), out);
    } else if (entry.isFile() && SCANNED.test(entry.name)) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

/** Every key at every depth of a (possibly nested) dependency/override map. */
function collectKeysDeep(value: unknown, out: string[] = []): string[] {
  if (typeof value !== 'object' || value === null) return out;
  for (const [key, child] of Object.entries(value)) {
    out.push(key);
    collectKeysDeep(child, out);
  }
  return out;
}

/**
 * Matches `react-router-dom` only as a QUOTED module specifier or manifest key —
 * `from 'react-router-dom'`, `vi.mock('react-router-dom')`,
 * `await import('react-router-dom')`, `"react-router-dom": "^7"` — so that prose
 * in a comment explaining why the package is gone does not trip the guard.
 *
 * Backticks are deliberately NOT in the character class. A template-literal
 * specifier is legal JS, but adding backticks here was tried and immediately
 * produced false positives on ordinary markdown code spans in comments (this
 * repo writes package names as `like-this` throughout, including in the very
 * comments that explain the v8 removal). A guard that fires on documentation
 * prose gets weakened or deleted by the next maintainer, which is strictly worse
 * than leaving one unreachable form uncovered: Prettier enforces `singleQuote`,
 * so a backtick specifier would not survive `format:check` anyway, and if the
 * package were ever declared as a real dependency the manifest test above
 * catches it regardless of how any source file spells the import.
 */
const SPECIFIER = /['"]react-router-dom(?:\/[^'"]*)?['"]/;

describe('router package (GHSA-qwww-vcr4-c8h2 — react-router-dom must stay gone)', () => {
  it('declares react-router and no react-router-dom in any workspace manifest', () => {
    const manifests = [
      'package.json',
      'packages/client/package.json',
      'packages/server/package.json',
      'packages/shared/package.json',
    ];

    let declaresRouter = false;

    for (const rel of manifests) {
      const pkg = JSON.parse(readFileSync(pathResolve(repoRoot, rel), 'utf8')) as Record<
        string,
        unknown
      >;
      for (const field of [
        'dependencies',
        'devDependencies',
        'peerDependencies',
        'optionalDependencies',
        'overrides',
        'resolutions',
      ]) {
        const deps = pkg[field];
        if (deps === undefined || deps === null) continue;
        // `overrides` nests — `{ "foo": { "react-router-dom": "7" } }` is a legal
        // npm override that a top-level key check would walk straight past — so
        // every key at every depth is collected, not just the first level.
        expect(
          collectKeysDeep(deps),
          `${rel} ${field} must not name react-router-dom at any depth`,
        ).not.toContain('react-router-dom');
        if (collectKeysDeep(deps).includes('react-router')) declaresRouter = true;
      }
    }

    // Sanity: the guard above would also pass if the router were removed entirely.
    expect(declaresRouter, 'some workspace must declare react-router').toBe(true);
  });

  it('never names react-router-dom as a module specifier in any authored source tree', () => {
    // Deliberately wider than `packages/client`: the router is a client-only
    // dependency today, but a stale specifier in `e2e/` (which drives real
    // navigation) or in a future workspace would be just as broken and would
    // otherwise go unnoticed here.
    const roots = ['packages', 'e2e', 'scripts'].map((d) => pathResolve(repoRoot, d));

    const offenders = roots
      .flatMap((root) => walk(root))
      // This spec necessarily quotes the forbidden name (in its own assertions
      // and in the worked examples in its header comment), so it exempts itself.
      // Derived from `import.meta.url` rather than hardcoded, so renaming the
      // file cannot turn the exemption into a silent hole somewhere else.
      .filter((file) => file !== __filename)
      .filter((file) => SPECIFIER.test(readFileSync(file, 'utf8')))
      .map((file) => relative(repoRoot, file));

    expect(
      offenders,
      `these files still reference the removed package: ${offenders.join(', ')}`,
    ).toEqual([]);
  });

  it('resolves every router export this app uses from the bare react-router entry', async () => {
    const router = await import('react-router');

    // Exactly the surface `packages/client` imports, across src and tests.
    const used = [
      'BrowserRouter',
      'Link',
      'MemoryRouter',
      'Navigate',
      'Outlet',
      'Route',
      'Routes',
      'useLocation',
      'useNavigate',
      'useParams',
      'useSearchParams',
    ] as const;

    for (const name of used) {
      expect(router, `react-router must export ${name}`).toHaveProperty(name);
      // Components are objects (forwardRef/memo wrappers); hooks are functions.
      expect(['function', 'object'], `${name} must be renderable/callable`).toContain(
        typeof (router as Record<string, unknown>)[name],
      );
    }
  });

  it('serves the DOM router bindings from the react-router/dom subpath', async () => {
    // Recorded so the split is not rediscovered the hard way: the v8 upgrade
    // guide directs `RouterProvider` and `HydratedRouter` to `react-router/dom`.
    // This app is declarative (`BrowserRouter`) and needs neither, but anything
    // that later adopts a data router must import them from there.
    //
    // Asserted only as a POSITIVE: `RouterProvider` happens to be re-exported
    // from the main entry too in 8.3.0, and asserting its absence there would
    // pin a third-party packaging detail that upstream is free to change without
    // any defect in H-Vault.
    const dom = await import('react-router/dom');

    expect(dom).toHaveProperty('HydratedRouter');
    expect(dom).toHaveProperty('RouterProvider');
  });
});
