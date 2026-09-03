// @vitest-environment node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The line between the application and its isolated document, asserted against
 * the SOURCE GRAPH rather than against a build.
 *
 * ## What this pins, and why nothing else can
 *
 * `src/sandbox/` is a separate Vite build with a separate Rollup graph, and the
 * whole isolation rests on that separation: the frame's modules are served from
 * `sandbox-assets/` with permissive CORS headers a module fetched by an opaque
 * origin needs, and the application's are not. The moment an application module
 * statically imports one of the sandbox's, that module joins the APPLICATION's
 * graph too — and the consequences are all silent:
 *
 *   - Prettier and the JSON repairer, which the format engine reaches only
 *     through `import()`, become chunks of the application build. Rollup names
 *     them by their own file names (`standalone`, `babel`, `estree`), they land
 *     in `dist/assets/`, and three of them breach `DEFAULT_CHUNK_BUDGET_KB` —
 *     so `audit:bundle` does fail, but it fails as "a chunk is too big", which
 *     is a symptom rather than the defect.
 *   - The markdown pipeline, `lowlight` and the HTML parser would do the same.
 *   - And a module that Rollup could reach from BOTH entries is exactly the
 *     hoisting hazard `vite.config.sandbox.ts` exists to make impossible.
 *
 * `scripts/ci/bundle-gate.mjs` checks the built HTML documents for
 * cross-references, which is the downstream symptom. This is the assertion that
 * fires FIRST, on the edit itself, and reads as what it is.
 *
 * ## What is deliberately allowed
 *
 * TYPE-only imports, in both directions. `import type` is erased at build, so it
 * creates no edge in either graph — and the sandbox depends on that already: it
 * shares its message shapes with the application as types from `@hvault/shared`
 * precisely because a shared runtime schema would drag `zod`, and therefore
 * `axios`, into a document that is forbidden to make a request.
 */

const clientRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = path.join(clientRoot, 'src');
const sandboxDir = path.join(srcDir, 'sandbox');

/** Every `.ts`/`.tsx` file under a directory. */
function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const absolute = path.join(dir, entry);
    if (statSync(absolute).isDirectory()) {
      found.push(...sourceFiles(absolute));
      continue;
    }
    if (entry.endsWith('.ts') || entry.endsWith('.tsx')) found.push(absolute);
  }
  return found;
}

/**
 * The specifiers a module imports at RUNTIME.
 *
 * `import type` and `export type` are dropped, because they are erased at build
 * and create no edge. A `import { type X }` inline specifier is NOT dropped:
 * the statement itself still emits an import unless every binding in it is a
 * type, and this deliberately errs towards reporting an edge that turns out to
 * be erasable rather than missing one that is not.
 */
function runtimeSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  const pattern = /(?:^|\n)\s*(?:import|export)\s+(type\s+)?([^;]*?)from\s*['"]([^'"]+)['"]/g;
  for (const match of source.matchAll(pattern)) {
    if (match[1] !== undefined) continue;
    specifiers.push(match[3] ?? '');
  }
  // A SIDE-EFFECT import (`import './sandbox.css';`) has no `from`, so the
  // pattern above never sees it — and it is a full runtime edge, the kind that
  // would pull a whole module graph in for its top-level effects alone. The
  // sandbox's own entry uses this form for its stylesheet, so it is not a
  // hypothetical shape.
  for (const match of source.matchAll(/(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g)) {
    specifiers.push(match[1] ?? '');
  }
  // Dynamic imports create an edge too — a lazier one, but the same graph.
  for (const match of source.matchAll(/\bimport\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    specifiers.push(match[1] ?? '');
  }
  return specifiers;
}

describe('the sandbox boundary', () => {
  const files = sourceFiles(srcDir);

  it('has application modules to check, and sandbox modules to check them against', () => {
    // A directory walk that found nothing would make every assertion below pass
    // over an empty list.
    expect(files.length).toBeGreaterThan(50);
    expect(sourceFiles(sandboxDir).length).toBeGreaterThan(5);
  });

  it('lets no application module import a sandbox module at runtime', () => {
    const offenders: string[] = [];
    for (const file of files) {
      if (file.startsWith(`${sandboxDir}${path.sep}`)) continue;
      for (const specifier of runtimeSpecifiers(readFileSync(file, 'utf8'))) {
        if (!specifier.startsWith('.')) continue;
        const resolved = path.resolve(path.dirname(file), specifier);
        if (!resolved.startsWith(sandboxDir)) continue;
        offenders.push(`${path.relative(clientRoot, file)} -> ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('lets no sandbox module import an application store, service or component', () => {
    // The other direction, and it matters for a different reason: the frame must
    // not be able to reach a key, a token or an HTTP client even by accident,
    // and every one of those lives behind one of these three directories.
    const offenders: string[] = [];
    for (const file of sourceFiles(sandboxDir)) {
      for (const specifier of runtimeSpecifiers(readFileSync(file, 'utf8'))) {
        if (!specifier.startsWith('.')) continue;
        const resolved = path.resolve(path.dirname(file), specifier);
        if (resolved.startsWith(sandboxDir)) continue;
        offenders.push(`${path.relative(clientRoot, file)} -> ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('lets no application module import Prettier or the JSON repairer', () => {
    // The consequence rather than the shape, so a future module that reached
    // them WITHOUT going through `src/sandbox/` is caught too. Both are declared
    // dependencies of this package precisely so the sandbox can load them, and
    // nothing else may.
    const offenders: string[] = [];
    for (const file of files) {
      if (file.startsWith(`${sandboxDir}${path.sep}`)) continue;
      for (const specifier of runtimeSpecifiers(readFileSync(file, 'utf8'))) {
        if (
          specifier === 'prettier' ||
          specifier.startsWith('prettier/') ||
          specifier === 'jsonrepair'
        ) {
          offenders.push(`${path.relative(clientRoot, file)} -> ${specifier}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('detects the edge it is meant to detect', () => {
    // The check above passes over a clean tree, so this is what proves it can
    // fail: the same extractor, run over a module that DOES import a sandbox
    // module at runtime, must report it — and must NOT report the type-only
    // import beside it.
    const hostile = [
      "import type { SandboxTheme } from '@hvault/shared';",
      "import { runTransform } from '../sandbox/transform/formatEngine';",
      "import type { Foo } from '../sandbox/renderers/text';",
      "import '../sandbox/sandbox.css';",
      "const { renderText } = await import('../sandbox/renderers/text');",
    ].join('\n');
    // Order follows the extractor's three passes: `from` imports, then
    // side-effect imports, then dynamic ones. All three edges are reported and
    // the two type-only lines are not.
    expect(runtimeSpecifiers(hostile)).toEqual([
      '../sandbox/transform/formatEngine',
      '../sandbox/sandbox.css',
      '../sandbox/renderers/text',
    ]);
  });
});
