/**
 * Process helpers for the local pipeline.
 *
 * Two Windows facts shape every function here:
 *
 *   1. `npm`/`npx` are `.cmd` shims. Since the fix for CVE-2024-27980, Node
 *      refuses to spawn a `.cmd` without `shell: true` (it throws EINVAL), so
 *      npm has to go through a shell on win32 — and only on win32, because a
 *      POSIX shell would brace-expand glob arguments (`*.{ts,tsx}`) before the
 *      tool ever sees them.
 *   2. Real executables (`docker`, `git`, `node`) spawn fine without a shell on
 *      every platform, and skipping the shell keeps their arguments verbatim.
 *
 * Hence the split: `runNpm` vs `runExe`/`captureExe`. Nothing here interpolates
 * user input into a command line, so there is no injection surface. On the
 * `shell: true` (win32 npm) path the args are pre-joined into the command string
 * by `resolveSpawn` (to sidestep Node 24's DEP0190), which is safe only while
 * every argument stays a trusted, space-free literal — `assertShellSafeArgs`
 * enforces exactly that.
 */
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const isWindows = process.platform === 'win32';

/** Repository root, resolved from this file rather than from `process.cwd()`. */
export const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
);

/**
 * Characters that a `cmd.exe` command line would re-interpret (metacharacters)
 * or that would silently re-tokenise a pre-joined argument (whitespace).
 */
const SHELL_UNSAFE = /[\s"&|<>^%()]/;

/**
 * Throws if any argument cannot be safely folded into a single shell command
 * string. See `resolveSpawn` for why this invariant is load-bearing.
 */
export function assertShellSafeArgs(args) {
  for (const arg of args) {
    if (SHELL_UNSAFE.test(arg)) {
      throw new Error(
        `proc: refusing to shell-join unsafe argument ${JSON.stringify(arg)} — ` +
          'pipeline arguments must be trusted, space-free, metacharacter-free literals',
      );
    }
  }
}

/**
 * Resolves the exact `(command, args)` pair handed to `spawn`.
 *
 * DEP0190: Node 24 warns — and internally concatenates the args WITHOUT escaping
 * (space-separated only) — when an args array is combined with `shell: true`.
 * The shell path therefore pre-joins the arguments into the command string here
 * and hands `spawn` an EMPTY args array. That is byte-for-byte the command line
 * Node would have built internally, minus the deprecation warning (the warning's
 * trigger is `shell && args.length > 0`, which an empty array no longer meets).
 *
 * The non-shell path (POSIX npm and every `runExe`) keeps its args verbatim,
 * preserving both the no-brace-expansion behaviour documented at the top of this
 * file and `runExe`'s verbatim-argument contract.
 *
 * The join is lossless ONLY because every argument the pipeline passes is a
 * trusted, space-free, metacharacter-free literal (see the GATES array in
 * `local-ci.mjs`). `assertShellSafeArgs` enforces that invariant so a future
 * argument with a space or a `cmd.exe` metacharacter fails loudly here instead
 * of being silently re-tokenised — or silently reopening the very injection
 * surface DEP0190 exists to flag, now with no warning to catch it.
 */
export function resolveSpawn(command, args, shell) {
  if (shell && args.length > 0) {
    assertShellSafeArgs(args);
    return { command: [command, ...args].join(' '), args: [] };
  }
  return { command, args };
}

/**
 * Runs a command, streaming stdout/stderr straight to the terminal.
 *
 * @returns {Promise<number>} the exit code (127 when the binary is missing)
 */
function stream(command, args, { shell = false, env = {} } = {}) {
  return new Promise((resolve) => {
    const spawnTarget = resolveSpawn(command, args, shell);
    const child = spawn(spawnTarget.command, spawnTarget.args, {
      cwd: repoRoot,
      stdio: 'inherit',
      shell,
      env: { ...process.env, ...env },
    });
    child.on('error', () => {
      resolve(127);
    });
    child.on('close', (code, signal) => {
      // A signal-terminated child (Ctrl-C) reports code === null.
      resolve(code ?? (signal ? 130 : 1));
    });
  });
}

/** Runs an npm script. Goes through cmd.exe on Windows; never on POSIX. */
export function runNpm(args, options = {}) {
  return stream('npm', args, { ...options, shell: isWindows });
}

/** Runs a real executable (docker, git, node) with its arguments passed verbatim. */
export function runExe(command, args, options = {}) {
  return stream(command, args, { ...options, shell: false });
}

/**
 * Runs an executable and captures its output instead of streaming it.
 *
 * @returns {{ status: number, stdout: string, stderr: string, ok: boolean }}
 */
export function captureExe(command, args, { env = {}, input } = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...env },
    ...(input === undefined ? {} : { input }),
  });
  const status = result.error ? 127 : (result.status ?? 1);
  return {
    status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? (result.error ? result.error.message : ''),
    ok: status === 0,
  };
}

/** True when `command --version` (or the given probe args) succeeds. */
export function hasExe(command, probeArgs = ['--version']) {
  return captureExe(command, probeArgs).ok;
}
