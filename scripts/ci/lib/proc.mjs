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
 * user input into a command line, so there is no injection surface.
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
 * Runs a command, streaming stdout/stderr straight to the terminal.
 *
 * @returns {Promise<number>} the exit code (127 when the binary is missing)
 */
function stream(command, args, { shell = false, env = {} } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
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
