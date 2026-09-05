/**
 * Every tsc invocation `type-check` runs keeps its own incremental build info — and
 * no config that EMITS is allowed to carry any.
 *
 * `npm run type-check` fans out into seven separate tsc invocations, and without
 * build info each one re-reads and re-checks every file from scratch: measured at
 * 1m 12s for the gate, against a 90-second budget for the whole tier-0 surface.
 * With `incremental` plus a per-invocation `tsBuildInfoFile` a run over an unchanged
 * tree reuses the previous program and re-reports its stored diagnostics instead of
 * recomputing them, measured at 25s.
 *
 * Three properties are worth a test rather than a comment, because each of them
 * fails SILENTLY — the gate stays green and only the speed, or the output, is wrong:
 *
 *   * a NEW tsc invocation inherits nothing, so it is cold on every commit unless
 *     its config or its command line names a build-info file;
 *   * two invocations pointed at ONE file overwrite each other's state on every
 *     alternate run, which costs the whole speedup and looks, from outside, exactly
 *     like the feature working;
 *   * `incremental` on a config that EMITS is worse than useless. A non-build `tsc`
 *     never checks whether its outputs still exist (typescript 6.0.3 guards that
 *     loop with `if (!isIncremental)`, and only in build mode), so `dist/` removed
 *     while the build info survived makes `npm run build` exit 0 having emitted
 *     nothing — and the same flag silences `tsc -b`'s own output check for the
 *     client. Both measured. That is why the three build configs carry neither key
 *     and the three `tsc --noEmit` passes take theirs from a `--tsBuildInfoFile`
 *     flag in the `type-check` script instead.
 *
 * The invocation list is DERIVED from the `type-check` scripts rather than
 * hard-coded, so an invocation added to the gate is checked here the moment it is
 * added; `EXPECTED_INVOCATIONS` pins the other direction, so one silently dropped
 * from the gate is red too.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

/** Where every build-info file must live: gitignored, and outside every package. */
const BUILD_INFO_DIR = path.join(repoRoot, '.cache', 'tsbuildinfo');

/**
 * The tsc invocations the gate is known to run, and where each one's build info is
 * declared. Pinned BY LITERAL NAME on purpose: the derivation below catches an
 * invocation added without build info, and this list catches one removed entirely.
 */
const EXPECTED_INVOCATIONS = [
  { config: 'packages/client/tsconfig.json', declaredBy: 'command' },
  { config: 'packages/client/tsconfig.test.json', declaredBy: 'config' },
  { config: 'packages/server/tsconfig.json', declaredBy: 'command' },
  { config: 'packages/server/tsconfig.test.json', declaredBy: 'config' },
  { config: 'packages/shared/tsconfig.json', declaredBy: 'command' },
  { config: 'packages/shared/tsconfig.test.json', declaredBy: 'config' },
  { config: 'tsconfig.e2e.json', declaredBy: 'config' },
] as const;

/**
 * The configs `npm run build` compiles, which must therefore carry NO incremental
 * state. Kept as a literal so the intent stays readable, and checked against the
 * workspace list below so a fourth package cannot join the repository unnoticed. The
 * derivation is by workspace rather than by command because the client's build reaches
 * tsc through `packages/client/scripts/build.mjs`, which this file does not parse.
 */
const EMITTING_CONFIGS = [
  'packages/shared/tsconfig.json',
  'packages/server/tsconfig.json',
  'packages/client/tsconfig.json',
];

interface PackageManifest {
  scripts?: Record<string, string>;
}

interface Invocation {
  /** Repo-relative, POSIX-separated path of the tsconfig this command compiles. */
  config: string;
  /** Absolute build-info path the COMMAND names, if it names one. */
  commandBuildInfo?: string;
  /** Whether the command passes `--incremental` itself. */
  commandIncremental: boolean;
}

function readManifest(dir: string): PackageManifest {
  return JSON.parse(
    readFileSync(path.join(repoRoot, dir, 'package.json'), 'utf-8'),
  ) as PackageManifest;
}

/** Reads what a single `tsc …` command compiles, and what it declares on the way. */
function parseTscCommand(command: string, cwd: string): Invocation {
  const tokens = command.trim().split(/\s+/);
  const valueOf = (...flags: string[]): string | undefined => {
    const index = tokens.findIndex((token) => flags.includes(token));
    return index >= 0 ? tokens[index + 1] : undefined;
  };
  const named = valueOf('-p', '--project');
  const buildInfo = valueOf('--tsBuildInfoFile');
  return {
    config: path.posix.normalize(path.posix.join(cwd, named ?? 'tsconfig.json')),
    // A path on the command line resolves against the CWD npm gives the script,
    // which is the package directory — NOT against the config it names.
    ...(buildInfo === undefined
      ? {}
      : { commandBuildInfo: path.resolve(repoRoot, cwd, buildInfo) }),
    commandIncremental: tokens.includes('--incremental'),
  };
}

/**
 * Every tsc invocation `npm run type-check` reaches, derived from the scripts
 * themselves: the root script chains `npm run type-check -w <package>` for each
 * workspace and `npm run type-check:e2e` at the root, and each of those chains one
 * or more `tsc` commands.
 */
function invocationsUnderTypeCheck(): Invocation[] {
  const rootScripts = readManifest('.').scripts ?? {};
  const invocations: Invocation[] = [];

  const expand = (script: string, cwd: string): void => {
    for (const command of script.split('&&').map((part) => part.trim())) {
      if (command.startsWith('tsc')) {
        invocations.push(parseTscCommand(command, cwd));
        continue;
      }
      const npmRun = /^npm run ([\w:-]+)(?: -w (\S+))?$/.exec(command);
      expect(npmRun, `unrecognised command in a type-check script: "${command}"`).not.toBeNull();
      const [, scriptName, workspace] = npmRun as RegExpExecArray;
      const nextCwd = workspace ?? cwd;
      const nested = (workspace ? readManifest(workspace) : { scripts: rootScripts }).scripts?.[
        scriptName as string
      ];
      expect(nested, `${nextCwd} declares no "${String(scriptName)}" script`).toBeDefined();
      expand(nested as string, nextCwd);
    }
  };

  const typeCheck = rootScripts['type-check'];
  expect(typeCheck, 'the root package declares no "type-check" script').toBeDefined();
  expand(typeCheck as string, '.');
  return invocations;
}

/**
 * The raw `compilerOptions` a config file declares ITSELF (comments and all).
 *
 * Used where INHERITING would be the bug: `tsBuildInfoFile` is a path, so a check-only
 * config that took one through `extends` would name a file it shares with every other
 * config extending the same base.
 */
function ownCompilerOptions(project: string): Record<string, unknown> {
  const absolute = path.join(repoRoot, project);
  const parsed = ts.readConfigFile(absolute, (file) => ts.sys.readFile(file));
  expect(parsed.error, `${project} does not parse as a tsconfig`).toBeUndefined();
  const config = parsed.config as { compilerOptions?: Record<string, unknown> };
  return config.compilerOptions ?? {};
}

/** The build-info file an invocation actually uses, from its command or its config. */
function effectiveBuildInfo(invocation: Invocation): string | undefined {
  if (invocation.commandBuildInfo !== undefined) return invocation.commandBuildInfo;
  const declared = ownCompilerOptions(invocation.config)['tsBuildInfoFile'];
  if (typeof declared !== 'string') return undefined;
  // A relative path in a tsconfig resolves against the file that declares it.
  return path.resolve(path.dirname(path.join(repoRoot, invocation.config)), declared);
}

/**
 * The compilerOptions a config EFFECTIVELY runs with, `extends` resolved.
 *
 * Used where inheriting is exactly the danger: `incremental` in `tsconfig.base.json`
 * is the obvious shortcut for someone trying to make the gate faster, all three
 * emitting configs extend that file, and reading only what each one DECLARES reports
 * green while `npm run build` quietly stops emitting. Measured, not imagined: with
 * `incremental` in the base, `rm -rf packages/server/dist && npm run build -w
 * packages/server` produced 0 files and this suite stayed green until this function
 * existed.
 */
function effectiveCompilerOptions(project: string): ts.CompilerOptions {
  const host: ts.ParseConfigFileHost = {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
      throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
    },
  };
  const parsed = ts.getParsedCommandLineOfConfigFile(path.join(repoRoot, project), {}, host);
  expect(parsed, `${project} does not parse as a tsconfig`).toBeDefined();
  return (parsed as ts.ParsedCommandLine).options;
}

describe('tsc build info', () => {
  const invocations = invocationsUnderTypeCheck();

  it('runs exactly the invocations the gate is known to run, in both directions', () => {
    const derived = invocations
      .map((invocation) => ({
        config: invocation.config,
        declaredBy: invocation.commandBuildInfo === undefined ? 'config' : 'command',
      }))
      .sort((a, b) => a.config.localeCompare(b.config));
    expect(derived).toEqual([...EXPECTED_INVOCATIONS].map((entry) => ({ ...entry })));
  });

  it.each(invocations.map((invocation) => [invocation.config, invocation] as const))(
    '%s runs incrementally, against a file of its own',
    (_config, invocation) => {
      const options = ownCompilerOptions(invocation.config);
      // `composite` implies `incremental`, which is why it counts here.
      expect(
        invocation.commandIncremental ||
          options['incremental'] === true ||
          options['composite'] === true,
      ).toBe(true);
      expect(effectiveBuildInfo(invocation)).toBeTypeOf('string');
    },
  );

  it('gives every invocation a DISTINCT file, inside the gitignored cache directory', () => {
    const resolved = invocations.map((invocation) => effectiveBuildInfo(invocation) as string);

    expect(new Set(resolved).size).toBe(invocations.length);
    for (const file of resolved) {
      expect(path.dirname(file)).toBe(BUILD_INFO_DIR);
      expect(file.endsWith('.tsbuildinfo')).toBe(true);
    }
  });

  it('names every workspace whose build compiles a config, in both directions', () => {
    // A fourth package added to the monorepo would otherwise be checked by nothing:
    // its build config would be free to carry incremental state and no case here
    // would ever look at it.
    const { workspaces } = JSON.parse(
      readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'),
    ) as { workspaces?: string[] };
    expect(workspaces, 'the root package declares no workspaces').toBeDefined();
    const building = (workspaces ?? [])
      .filter((workspace) => readManifest(workspace).scripts?.['build'] !== undefined)
      .map((workspace) => path.posix.join(workspace, 'tsconfig.json'));
    expect(building.sort()).toEqual([...EMITTING_CONFIGS].sort());
  });

  it('keeps the shared base config free of incremental state', () => {
    // Every emitting config extends it, so `incremental` set here reaches all three at
    // once — the cheapest possible way to re-open the silent no-op build, and the one
    // a check that reads only each config's own options cannot see.
    const base = ownCompilerOptions('tsconfig.base.json');
    expect(base['incremental']).toBeUndefined();
    expect(base['tsBuildInfoFile']).toBeUndefined();
  });

  it.each(EMITTING_CONFIGS)(
    '%s, which EMITS, keeps no build info that outlives its outputs',
    (project) => {
      // Two failure modes, one root cause: an incremental tsc does not check whether
      // the outputs it already recorded still exist (in build mode the loop is
      // guarded by `if (!isIncremental)`; outside build mode there is no such loop at
      // all). A build-info file that survives `rm -rf dist` therefore turns
      // `npm run build` into a silent no-op — measured: 162 emitted files, then 0.
      //
      // So an emitting config may not declare `incremental`. `composite` is a
      // different matter: `packages/shared` needs it because the other two packages
      // reference it, and it implies `incremental`. That project is made safe the
      // only other way there is — its build info is pinned INSIDE `outDir`, so the
      // state dies with the outputs it describes.
      // EFFECTIVE options, not declared ones: `extends` is how this comes back.
      const options = effectiveCompilerOptions(project);
      expect(options.incremental).toBeUndefined();

      const buildInfo = options.tsBuildInfoFile;
      if (options.composite === true) {
        expect(typeof buildInfo).toBe('string');
        const configDir = path.dirname(path.join(repoRoot, project));
        const outDir = path.resolve(configDir, options.outDir ?? '.');
        expect(path.resolve(configDir, buildInfo as string).startsWith(outDir + path.sep)).toBe(
          true,
        );
      } else {
        expect(buildInfo).toBeUndefined();
      }
    },
  );

  it('has `clean` remove the build info it does not otherwise notice', () => {
    // Deleting `dist/` and leaving the build info is exactly the silent-no-op case
    // above, and `npm run clean` deletes `dist/`. It must therefore take the build
    // info with it. This is a spelling check over the script text rather than a
    // behavioural one — there is no honest way to assert `rimraf`'s effect from a
    // unit test — so it is deliberately narrow about which paths it names:
    // `packages/client/tsconfig.tsbuildinfo` is what `tsc -b` writes on every client
    // build, and `packages/shared/tsconfig.tsbuildinfo` is where the shared package's
    // `composite` build wrote BEFORE that path was pinned inside `dist/`, kept so a
    // checkout predating the change is cleaned too.
    const clean = readManifest('.').scripts?.['clean'] ?? '';
    expect(clean).toContain('.cache/tsbuildinfo');
    expect(clean).toContain('packages/shared/tsconfig.tsbuildinfo');
    expect(clean).toContain('packages/client/tsconfig.tsbuildinfo');
  });

  it('keeps the build info out of the repository and out of every image layer', () => {
    // It describes one machine's tree state, and an incremental tsc trusts it
    // without checking the outputs it names. Committing one would make a
    // checkout's first build depend on whose machine wrote it; copying one into a
    // build context could leave a stage's build a silent no-op.
    const gitignore = readFileSync(path.join(repoRoot, '.gitignore'), 'utf-8');
    expect(gitignore).toMatch(/^\.cache\/$/m);
    expect(gitignore).toMatch(/^\*\.tsbuildinfo$/m);

    const dockerignore = readFileSync(path.join(repoRoot, '.dockerignore'), 'utf-8');
    expect(dockerignore).toMatch(/^\*\*\/\*\.tsbuildinfo$/m);
    // Depth-agnostic, for the same reason as this file's `**/logs` and `**/.env`
    // rules: a bare `.cache` would exclude only the root one.
    expect(dockerignore).toMatch(/^\*\*\/\.cache$/m);
    expect(dockerignore).not.toMatch(/^\.cache$/m);
  });
});
