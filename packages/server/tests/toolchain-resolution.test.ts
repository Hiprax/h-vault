/**
 * Two TypeScripts are installed on purpose, and each name must resolve to the
 * right one.
 *
 * TypeScript 7 is a native compiler that ships no JavaScript API: its package's
 * main entry exports a version string and nothing else. Every build and
 * type-check script runs `tsc`, and that must be 7. Two consumers still need the
 * 6.x API: typescript-eslint (whose peer range stops below 6.1) and the suites
 * that parse tsconfigs through `import ts from 'typescript'`. So the root
 * manifest installs TypeScript 7 as `@typescript/native` and the TypeScript 6
 * compatibility package as `typescript`, the arrangement the TypeScript team
 * documents for exactly this situation.
 *
 * (The second describe below pins the same kind of property for Vitest.)
 *
 * What makes it worth a test is that it fails SILENTLY in both directions. The
 * compatibility package depends on the real 6.x package under a second alias,
 * `@typescript/old`, which npm hoists to the top level, and whose manifest ALSO
 * declares a `tsc` binary. If an install ever links that one into
 * `node_modules/.bin`, every gate type-checks and builds with TypeScript 6 while
 * the manifest says 7 — green, and not the compiler anyone chose. And if the
 * `typescript` name ever resolves to 7, typescript-eslint loads a package with no
 * API and the lint gate fails with an opaque `Cannot read properties of
 * undefined` from inside its parser rather than naming the cause.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createTestTempDir } from './tempDir.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const requireFromRoot = createRequire(path.join(repoRoot, 'package.json'));
const vitestCli = path.join(
  path.dirname(requireFromRoot.resolve('vitest/package.json')),
  'vitest.mjs',
);

interface Manifest {
  name?: string;
  version?: string;
  bin?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

function manifestOf(packageName: string): { dir: string; manifest: Manifest } {
  const file = requireFromRoot.resolve(`${packageName}/package.json`);
  return { dir: path.dirname(file), manifest: JSON.parse(readFileSync(file, 'utf8')) as Manifest };
}

function majorOf(version: string | undefined): number {
  expect(version, 'a manifest without a version').toMatch(/^\d+\.\d+\.\d+/);
  return Number((version as string).split('.')[0]);
}

/** `a.b.c` compared numerically; negative when `a < b`. */
function compareVersions(a: string, b: string): number {
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

describe('the TypeScript toolchain', () => {
  it('links node_modules/.bin/tsc to the TypeScript 7 compiler, never to the 6.x package behind the compatibility alias', () => {
    const binDir = path.join(repoRoot, 'node_modules', '.bin');
    const native = manifestOf('@typescript/native');
    const old = manifestOf('@typescript/old');
    const nativeBin = realpathSync(path.join(native.dir, 'bin', 'tsc'));

    expect(native.manifest.name).toBe('typescript');
    expect(majorOf(native.manifest.version)).toBe(7);
    // The negative this whole test exists for: the hoisted 6.x package declares
    // a `tsc` binary too.
    expect(old.manifest.bin?.['tsc']).toBeDefined();

    if (process.platform === 'win32') {
      // npm writes shim FILES on Windows rather than links, so the question
      // "which script does `tsc` run" is answered by the shim's own text.
      const shim = readFileSync(path.join(binDir, 'tsc.cmd'), 'utf8');
      expect(shim, 'node_modules/.bin/tsc is not the TypeScript 7 compiler').toContain(
        path.join('@typescript', 'native', 'bin', 'tsc'),
      );
      expect(shim).not.toContain(path.join('@typescript', 'old'));
    } else {
      const target = realpathSync(path.join(binDir, 'tsc'));
      expect(target, 'node_modules/.bin/tsc is not the TypeScript 7 compiler').toBe(nativeBin);
      expect(target.startsWith(realpathSync(old.dir) + path.sep)).toBe(false);
    }

    // And the binary really is the compiler the manifest names.
    const launcher = process.platform === 'win32' ? nativeBin : path.join(binDir, 'tsc');
    const printed = execFileSync(process.execPath, [launcher, '--version'], { encoding: 'utf8' });
    expect(printed.trim()).toBe(`Version ${String(native.manifest.version)}`);
  });

  it('resolves `typescript` to a 6.x compiler API inside the range typescript-eslint accepts', async () => {
    const ts = (await import('typescript')).default;
    expect(majorOf(ts.version)).toBe(6);
    // The API is really there, not a version stub like TypeScript 7's main entry.
    expect(typeof ts.createSourceFile).toBe('function');
    expect(typeof ts.getParsedCommandLineOfConfigFile).toBe('function');

    const range = manifestOf('@typescript-eslint/typescript-estree').manifest.peerDependencies?.[
      'typescript'
    ];
    // Read, not assumed: the day typescript-eslint widens its range to accept 7,
    // this shape changes, this test goes red, and the alias can be retired.
    const bounds = /^>=(\d+\.\d+\.\d+) <(\d+\.\d+\.\d+)$/.exec(range ?? '');
    expect(bounds, `unexpected typescript-eslint peer range "${String(range)}"`).not.toBeNull();
    const [, floor, ceiling] = bounds as RegExpExecArray;
    expect(compareVersions(ts.version, floor as string)).toBeGreaterThanOrEqual(0);
    expect(compareVersions(ts.version, ceiling as string)).toBeLessThan(0);
    expect(majorOf(ceiling)).toBeLessThan(7);
  });
});

/**
 * Vitest loads its environment and its coverage provider BY NAME, from its own
 * location, and the mutation runner drives the root copy of Vitest. So the tree
 * must hold ONE Vitest that every package resolves, with those peers reachable
 * from it. A fragmented install is not hypothetical: moving Vitest to the root
 * while jsdom stayed inside `packages/client` made the whole client suite run no
 * tests at all ("Cannot find package 'jsdom'"), and the mutation runner's workers
 * fail to start the same way.
 */
describe('the test toolchain', () => {
  it('resolves one Vitest from every package, and its environment and provider from Vitest itself', () => {
    const rootVitest = realpathSync(requireFromRoot.resolve('vitest/package.json'));
    for (const workspace of ['shared', 'server', 'client']) {
      const fromPackage = createRequire(path.join(repoRoot, 'packages', workspace, 'package.json'));
      expect(realpathSync(fromPackage.resolve('vitest/package.json')), workspace).toBe(rootVitest);
    }
    const fromVitest = createRequire(rootVitest);
    for (const peer of ['jsdom', '@vitest/coverage-v8', 'vite']) {
      expect(() => fromVitest.resolve(`${peer}/package.json`), peer).not.toThrow();
    }
    // The runner the mutation gate uses sees that same copy.
    const fromRunner = createRequire(
      requireFromRoot.resolve('@stryker-mutator/vitest-runner/package.json'),
    );
    expect(realpathSync(fromRunner.resolve('vitest/package.json'))).toBe(rootVitest);
  });
});

/**
 * The mutation runner selects tests by NAME, and the name it builds must be one
 * the installed Vitest accepts. This is the property that failed silently.
 *
 * For every mutant, `@stryker-mutator/vitest-runner` narrows the run to the
 * tests that cover it by setting `testNamePattern` to the names its setup file
 * recorded, joining each test's describe chain with a single space. Vitest 5
 * matches `testNamePattern` against the chain joined with ` > `, so under it no
 * nested test ever matched, no test ran for any mutant, and every mutant was
 * reported as SURVIVED. Measured on `packages/shared/src/utils/index.ts`: 90.06 %
 * killed with Vitest 4, 0 % with Vitest 5, same Stryker 10. Upstream:
 * stryker-js issue #6210, unfixed in any release when Vitest was held at 4.
 *
 * So this runs the real contract rather than comparing version numbers: a real
 * Vitest over a nested fixture, first to obtain the name exactly as the runner's
 * own `collectTestName` builds it, then filtered by that name exactly as the
 * runner filters (escaped, as a RegExp). Exactly that test must run. It goes red
 * if EITHER side moves: a Vitest that stops matching the runner's names, or a
 * runner that changes how it builds them.
 */
describe('the mutation runner and Vitest agree on test names', () => {
  it('selects a nested test by the name the Stryker runner builds for it, and nothing else', () => {
    const runnerDir = path.dirname(
      requireFromRoot.resolve('@stryker-mutator/vitest-runner/package.json'),
    );
    // Reached by file path on purpose: the runner does not export these, and the
    // file moving is itself a reason to re-examine the arrangement.
    const collectTestNameUrl = pathToFileURL(
      path.join(runnerDir, 'dist', 'src', 'test-helpers.js'),
    );
    const fromRunner = createRequire(path.join(runnerDir, 'package.json'));
    // The names used for filtering are RECORDED by an inline copy of this
    // function in the runner's setup file (it is copied into the sandbox and may
    // not import anything local). Imported here is the exported twin, so the
    // two must be the same code, or a fix to one alone would turn this green
    // while the runner stayed broken.
    const functionSource = (file: string): string => {
      const text = readFileSync(path.join(runnerDir, 'dist', 'src', file), 'utf8');
      const match = /function collectTestName\([\s\S]*?\n}/.exec(text);
      expect(match, `collectTestName not found in ${file}`).not.toBeNull();
      return (match as RegExpExecArray)[0].replace(/\s+/g, ' ');
    };
    expect(functionSource('stryker-setup.js')).toBe(functionSource('test-helpers.js'));

    const root = createTestTempDir('hv-runner-names-');
    mkdirSync(path.join(root, 't'));
    writeFileSync(path.join(root, 'package.json'), '{ "type": "module", "private": true }\n');
    const log = path.join(root, 'ran.jsonl');
    // The fixture is CONSTANT text: the two values it needs arrive through its
    // environment, so no code is ever assembled from a path.
    writeFileSync(
      path.join(root, 't', 'nested.test.js'),
      [
        `import { appendFileSync } from 'node:fs';`,
        `const { collectTestName } = await import(process.env.HV_RUNNER_TEST_HELPERS);`,
        `const record = (task) => appendFileSync(process.env.HV_NAME_LOG, JSON.stringify({ test: task.name, runnerName: collectTestName(task) }) + '\\n');`,
        `describe('outer suite', () => {`,
        `  describe('inner suite', () => {`,
        `    test('selected case', ({ task }) => { record(task); });`,
        `    test('other case', ({ task }) => { record(task); });`,
        `  });`,
        `});`,
        `test('top level case', ({ task }) => { record(task); });`,
        '',
      ].join('\n'),
    );

    const env = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => !name.startsWith('VITEST') && name !== 'NODE_V8_COVERAGE',
        ),
      ),
      HV_RUNNER_TEST_HELPERS: collectTestNameUrl.href,
      HV_NAME_LOG: log,
    };
    const runVitest = (extra: string[]) => {
      writeFileSync(log, '');
      const result = spawnSync(
        process.execPath,
        [vitestCli, 'run', '--root', root, '--globals', '--pool', 'forks', ...extra],
        { cwd: root, env, encoding: 'utf8', timeout: 90_000 },
      );
      const ran = readFileSync(log, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as { test: string; runnerName: string });
      return { status: result.status, output: `${result.stdout}\n${result.stderr}`, ran };
    };

    const all = runVitest([]);
    expect(all.status, all.output).toBe(0);
    expect(all.ran.map((entry) => entry.test).sort()).toEqual([
      'other case',
      'selected case',
      'top level case',
    ]);
    const runnerName = all.ran.find((entry) => entry.test === 'selected case')?.runnerName;
    expect(runnerName).toBe('outer suite inner suite selected case');

    const { escapeRegExp } = fromRunner('@stryker-mutator/util') as {
      escapeRegExp: (input: string) => string;
    };
    const filtered = runVitest(['--testNamePattern', escapeRegExp(runnerName as string)]);
    expect(
      filtered.ran.map((entry) => entry.test),
      'The Stryker vitest-runner builds test names this Vitest does not match, so every ' +
        'mutant would "survive" (stryker-js #6210). Do not lift the Vitest hold until a ' +
        'released runner makes this pass: see the Vitest note in CONTRIBUTING.md.\n' +
        filtered.output,
    ).toEqual(['selected case']);
  }, 120_000);
});
