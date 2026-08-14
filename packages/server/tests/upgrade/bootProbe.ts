/**
 * A hermetic boot probe: load the CURRENT server's environment configuration in
 * a fresh process, against nothing but a `.env` file this test wrote.
 *
 * ---------------------------------------------------------------------------
 * WHY A CHILD PROCESS, AND WHY A TEMPORARY REPOSITORY ROOT
 * ---------------------------------------------------------------------------
 *
 * `config/index.ts` reads `process.env` exactly once, at module load, after
 * dotenv has populated it from the `.env` at the monorepo root — a path it
 * resolves from its OWN module URL, not from `process.cwd()`. Two consequences
 * decide the shape of this helper:
 *
 *   1. An in-process `vi.resetModules()` + re-import cannot represent a boot.
 *      The worker's environment already carries everything `vitest.config.ts`
 *      pins, and `process.env` cannot express "this variable does not exist"
 *      when a real `.env` on the developer's machine is about to supply it.
 *      dotenv never overwrites a key that is already set, so the only way to
 *      make a variable genuinely ABSENT is to control the file dotenv reads.
 *
 *   2. Controlling that file means controlling where the config module thinks
 *      the repository root is. So the probe copies `packages/server/src` into a
 *      temporary directory laid out like the repository, symlinks `node_modules`
 *      beside it, and writes its `.env` at that temporary root. The config module
 *      then resolves four levels up to the temp directory, loads the fixture
 *      `.env`, and the operator's own `.env` is invisible — on a machine that has
 *      one and on one that does not, identically.
 *
 * The whole `src` tree is copied rather than the two files the probe actually
 * imports (`config/index.ts` and the logger it builds). A hand-picked subset is a
 * second list that drifts: the day config gains an import, a subset copy fails
 * with a resolution error that looks nothing like the thing under test. The copy
 * costs single-digit milliseconds.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DOES AND DOES NOT PROVE
 * ---------------------------------------------------------------------------
 *
 * It loads `config/index.ts`, which is the boot-time consumer of every
 * environment variable and the first application module `server.ts` imports:
 * every variable that was removed, renamed or left unset decides this process's
 * fate here, before a port is bound or a database is reached.
 *
 * It deliberately does NOT import `app.ts`. Under `NODE_ENV=production` that
 * module reads `packages/server/public/index.html` at import time and throws
 * without it — a property of the BUILD, not of the configuration, so a config
 * probe that required one would report a missing client bundle as a bad `.env`.
 * The full artefact boot is `test:smoke`, and the full stack boot is
 * `test:deploy`; both already run.
 */
import { cpSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { REPO_ROOT, createTestTempDir } from '../tempDir.js';

const execFileAsync = promisify(execFile);

/**
 * The KILL deadline: past this the child is a hang, not a slow boot, and it is
 * reported as exit 124 rather than as an ordinary failure. Measured at ~0.45 s
 * on the reference machine, so ten seconds is far too coarse to fire on a loaded
 * machine and far too tight for a boot that has started waiting on something.
 */
const BOOT_DEADLINE_MS = 10_000;

/**
 * The exit code a killed child is reported as. The same value the pipeline's own
 * process helper uses for a gate that outlived its deadline, so a hang reads the
 * same way wherever it is seen.
 */
export const TIMEOUT_EXIT = 124;

/**
 * The FAST bound, and it must stay strictly below {@link BOOT_DEADLINE_MS} or it
 * asserts nothing.
 *
 * That is not hypothetical: this constant was originally the deadline itself,
 * which made the assertion unfalsifiable — anything reaching 10 s is killed and
 * surfaces as exit 124, which the sweep already checks two lines earlier, so the
 * only window left was a self-exit in the sub-millisecond band around the kill.
 * A boot that degraded twenty-fold to 9 s would have passed while being exactly
 * the restart-loop experience the assertion exists to prevent. Three seconds is
 * ~6x the measured cost: coarse enough not to flake on a loaded machine, tight
 * enough to see a real regression.
 */
export const BOOT_FAST_MS = 3_000;

export interface BootResult {
  /** 0 when the configuration loaded, non-zero when the server refused to boot. */
  exitCode: number;
  /** Everything the process said, both streams, so a message can be asserted. */
  output: string;
  /** The parsed configuration, present only on a successful boot. */
  config?: Record<string, unknown>;
  /** How long the child took, wall clock. */
  durationMs: number;
}

/**
 * Boots the current server's configuration against `envFile`, verbatim.
 *
 * `envFile` is the literal text of a `.env`: the probe writes it unchanged, so a
 * fixture can carry comments, blank keys and stale variables exactly as an
 * operator's file does.
 */
export async function bootWithEnvFile(envFile: string): Promise<BootResult> {
  const root = createTestTempDir('hv-upgrade-boot-');

  mkdirSync(path.join(root, 'packages', 'server'), { recursive: true });
  cpSync(
    path.join(REPO_ROOT, 'packages', 'server', 'src'),
    path.join(root, 'packages', 'server', 'src'),
    {
      recursive: true,
    },
  );
  // A JUNCTION rather than a copy, because the tree is hundreds of megabytes —
  // but Windows refuses `symlink` without Developer Mode or an elevated shell,
  // and the failure would surface as `EPERM` out of THIS call, in the parent,
  // with a message about symlinks rather than about configuration. The catch
  // around the child spawn below anticipates that error and cannot see it from
  // here, so it is handled where it happens: a JUNCTION needs no elevation on
  // Windows and the type argument is ignored on POSIX, and a refusal even of that
  // is reported as the harness fault it is rather than as a configuration one.
  try {
    symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(root, 'node_modules'), 'junction');
  } catch (error) {
    throw new Error(
      `the boot probe could not link ${REPO_ROOT}/node_modules into its temporary root: ` +
        `${String(error)}. This is a harness failure, not a configuration one — the probe ` +
        'never ran. (A copy is not an acceptable fallback here: the tree is hundreds of ' +
        'megabytes and every case in this suite creates its own root.)',
    );
  }
  // The manifest that governs how the copied sources are resolved. Without it
  // the server's modules would be interpreted under a different module regime
  // than the one they actually run in — which is a divergence in the very thing
  // a boot probe is supposed to reproduce faithfully.
  writeFileSync(
    path.join(root, 'packages', 'server', 'package.json'),
    `${JSON.stringify({ name: '@hvault/server-boot-probe', private: true, type: 'module' }, null, 2)}\n`,
    'utf-8',
  );
  writeFileSync(path.join(root, '.env'), envFile, 'utf-8');

  // Prints the loaded configuration as one JSON line on stdout. Anything the
  // config module logs goes to the same streams and is captured with it, which
  // is what lets a test assert the MESSAGE an operator would read.
  writeFileSync(
    path.join(root, 'boot.mts'),
    [
      "const mod = await import('./packages/server/src/config/index.js');",
      'process.stdout.write(`__CONFIG__${JSON.stringify(mod.config)}\\n`);',
      '',
    ].join('\n'),
    'utf-8',
  );

  const started = Date.now();
  let exitCode = 0;
  let output = '';
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ['--import', 'tsx', './boot.mts'],
      {
        cwd: root,
        timeout: BOOT_DEADLINE_MS,
        // A boot must not inherit this worker's environment: `vitest.config.ts`
        // pins two dozen variables into it, every one of which would silently
        // stand in for a variable the fixture `.env` is meant to supply — or,
        // worse, for one a test is deliberately withholding. Only what a shell
        // genuinely needs is passed through.
        env: {
          PATH: process.env['PATH'] ?? '',
          HOME: process.env['HOME'] ?? root,
          // The determinism pins travel with the child. Nothing in
          // `config/index.ts` is timezone- or locale-sensitive today
          // (`.toLowerCase()` is locale-invariant), so this is latent rather
          // than live — but the day a cron default, a date parse or a
          // `toLocaleLowerCase` enters the schema, this one probe would become
          // machine-dependent while every other test around it is pinned.
          TZ: 'UTC',
          LANG: 'C.UTF-8',
          LC_ALL: 'C.UTF-8',
          // Keeps the rotating log files this boot creates inside the temp
          // directory. Outside `NODE_ENV=test` the logger attaches its file
          // transports, and their default location is relative to the working
          // directory — which is this temp root, but pinning it is cheaper than
          // depending on that.
          LOG_DIRECTORY: path.join(root, 'logs'),
        },
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    output = `${stdout}${stderr}`;
  } catch (error) {
    // `code` is typed as `unknown` on purpose. Node sets it to a NUMBER for an
    // ordinary non-zero exit but to a STRING for a spawn failure ('ENOENT' when
    // tsx or node cannot be found, 'EACCES', 'EPERM' when Windows refuses the
    // symlink) — so declaring it `number` would be a type lie that reports a
    // broken harness as "the server refused to boot". A non-numeric code is
    // surfaced as its own value and as a prefix on the output, so the transcript
    // says which of the two happened.
    const failure = error as {
      code?: unknown;
      killed?: boolean;
      stdout?: string;
      stderr?: string;
    };
    output = `${failure.stdout ?? ''}${failure.stderr ?? ''}`;
    if (failure.killed === true) {
      // A timeout leaves `code` unset and `killed` true. Reported as a distinct,
      // impossible-to-mistake exit code rather than folded into "it failed": a
      // boot that HANGS is a different defect from a boot that refuses, and an
      // operator watching a restart loop has to be able to tell them apart.
      exitCode = TIMEOUT_EXIT;
    } else if (typeof failure.code === 'number') {
      exitCode = failure.code;
    } else {
      exitCode = 1;
      output = `the boot probe could not spawn a child process (${String(failure.code)})\n${output}`;
    }
  }

  // Anchored on the object's own braces and parsed defensively. A probe that
  // threw a SyntaxError on a half-written line would report a defect in the
  // application as a defect in itself, which is the one thing an instrument may
  // not do: an unparseable marker means "no configuration was loaded", which is
  // exactly what a refused boot means.
  const marker = /^__CONFIG__(\{.*\})$/m.exec(output);
  let config: Record<string, unknown> | undefined;
  if (marker) {
    try {
      config = JSON.parse(marker[1]!) as Record<string, unknown>;
    } catch {
      config = undefined;
    }
  }

  return {
    exitCode,
    output,
    durationMs: Date.now() - started,
    ...(config ? { config } : {}),
  };
}
