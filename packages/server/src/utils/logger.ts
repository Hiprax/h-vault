import path from 'node:path';
import { createLogger, type RotationStrategy } from '@hiprax/logger';
import type { Logger } from 'winston';

/**
 * This application's one way to build a logger.
 *
 * `createLogger` from @hiprax/logger defaults `logDirectory` to
 * `path.resolve(process.cwd(), 'logs')` with BOTH file transports on, and every
 * call site here used to take that default. Two consequences followed, and both
 * are why this module exists:
 *
 *   • THE LOG DIRECTORY WAS WHEREVER THE PROCESS HAPPENED TO START. `cwd()` is
 *     the repository root under `npm start`, the package directory under
 *     `npm run … -w packages/server`, and `/app` inside the container. An
 *     operator who wanted logs on a mounted volume had no way to say so.
 *   • THE TEST SUITE WROTE ROTATING LOG FILES INTO THE CHECKOUT. Every server
 *     run appended ~1.6 MB to `packages/server/logs`, measured at 406 files and
 *     448 MB accumulated over this project's history — invisible to every gate,
 *     because the directory is gitignored. Nothing reads those files: a test run
 *     is watched through its reporter.
 *
 * So the directory is configurable via `LOG_DIRECTORY`, and the file transports
 * are off under `NODE_ENV=test`. The console transport is untouched in every
 * environment, so a failing run still says why.
 *
 * And the files are BOUNDED (F-17). In the Docker stack the log directory is a
 * size-capped tmpfs (64 MB for the app, 16 MB for the bootstrap one-shot), which
 * is memory the container is charged for, and @hiprax/logger's default retention
 * (`20m` per file kept `14d`, a count of DAYS) bounds nothing: every one of ~40
 * module loggers also opened a file of its own. So:
 *
 *   • module files are OFF in production unless `LOG_MODULE_FILES=true` (the
 *     global file already carries every line, and the console carries the full
 *     stream, which the container runtime captures and rotates);
 *   • every file, module or global, keeps at most {@link LOG_FILE_ROTATION}:
 *     `maxFiles` is a bare COUNT, so the global file is bounded at 4 MB x 3 =
 *     12 MB whatever is logged. `tests/log-storage-bound.test.ts` sums every file
 *     the server's loggers open under each container's compose environment and
 *     holds it below that container's tmpfs, parsed from `docker-compose.yml`;
 *   • a failure a file transport REPORTS is written ONCE on the console
 *     ({@link reportLogFileFailure}). Not every failure is reported: a failed
 *     write to the file itself (ENOSPC measured, EACCES by the same path) surfaces in
 *     winston-daily-rotate-file 5.0.0 as an `error` event on its internal
 *     stream that nothing listens to, so it is an uncaught exception and the
 *     process exits (measured against `/dev/full`). The bound above is what
 *     keeps the tmpfs from filling; the defect is written up for the logger's
 *     owner, and `node_modules` is never patched around it.
 *
 * WHY THIS READS `process.env` AND NOT `config`. `config/index.ts` builds a
 * logger of its own, to report on its own validation, before the parsed config
 * exists — so a logger module that imported `config` would be a cycle through
 * the one module that cannot wait for it. The three values here are read straight
 * from the environment for that reason, and they are the only three: everything
 * else a logger needs is a constant.
 */

/** The default, matching @hiprax/logger's own: `<cwd>/logs`. */
export const DEFAULT_LOG_DIRECTORY_NAME = 'logs';

/**
 * Where rotating log files go.
 *
 * A blank or whitespace-only `LOG_DIRECTORY` is treated as unset, matching how
 * `config/index.ts` maps an empty environment variable to `undefined`: an
 * operator who comments the value out in `.env` gets the default rather than a
 * logger trying to create a directory named `''`.
 */
export function resolveLogDirectory(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.LOG_DIRECTORY?.trim();
  if (configured) return path.resolve(configured);
  return path.resolve(process.cwd(), DEFAULT_LOG_DIRECTORY_NAME);
}

/**
 * Whether the rotating file transports are attached.
 *
 * False only under `NODE_ENV=test`. @hiprax/logger creates the log directory
 * when — and only when — at least one file transport is enabled, so this also
 * decides whether the directory is created at all.
 */
export function shouldWriteLogFiles(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NODE_ENV !== 'test';
}

/**
 * Whether each module also writes a rotating file of its own, beside the shared
 * global file that carries every module's lines.
 *
 * `LOG_MODULE_FILES=true` or `false` decides it (case and surrounding space
 * ignored); unset, blank or anything else means the default: off in production
 * (the Docker stack's log directory is a small tmpfs, and a file per module
 * multiplies what it must hold by the number of modules), on elsewhere, where a
 * file per module is what a developer reads. Under `NODE_ENV=test` no file is
 * written at all ({@link shouldWriteLogFiles}).
 */
function shouldWriteModuleFiles(env: NodeJS.ProcessEnv = process.env): boolean {
  const configured = env.LOG_MODULE_FILES?.trim().toLowerCase();
  if (configured === 'true') return true;
  if (configured === 'false') return false;
  return env.NODE_ENV !== 'production';
}

/**
 * The retention of every rotating log file this application opens: a new file
 * every 4 MB (and every day), at most 3 kept. `maxFiles` is a bare number, which
 * @hiprax/logger reads as a COUNT of files; a `d` suffix would be a number of
 * DAYS, which bounds nothing when a day can produce any number of files. So the
 * global file is at most 12 MB, inside the 16 MB the bootstrap container's log
 * tmpfs holds and far inside the app's 64 MB.
 *
 * Every field is spelled out rather than spread from the library's
 * `defaultRotation`: the two others are the library's own defaults, which
 * `tests/log-storage-bound.test.ts` holds equal, and a module that read a value
 * from the logger package at import time would break every suite that replaces
 * that package with a partial mock.
 */
export const LOG_FILE_ROTATION: Readonly<RotationStrategy> = Object.freeze({
  maxSize: '4m',
  maxFiles: '3',
  datePattern: 'YYYY-MM-DD',
  zippedArchive: false,
});

let logFileFailureReported = false;

/**
 * What a transport-reported log failure does: ONE line on the console (the
 * stream the container runtime keeps), for the first failure of the process,
 * and nothing for the rest; the library's own fallback would print each
 * distinct message, and a log stream that fills with "cannot write the log"
 * lines is its own flood. Never throws. It sees only the failures a transport
 * EMITS (the library's `onTransportError` contract); a failed write to the file
 * itself is not one of them today (see the module comment).
 */
function reportLogFileFailure(error: Error): void {
  if (logFileFailureReported) return;
  logFileFailureReported = true;
  console.error(
    `[logger] A log file could not be written (${error.message}). File logging may be ` +
      'incomplete until the cause is fixed; the console stream is unaffected. Further ' +
      'failures are not reported.',
  );
}

/**
 * Builds this application's logger for one module.
 *
 * Every `createLogger` call under `packages/server/src` goes through here, so
 * the directory, the transport set and the retention are decided once.
 * @hiprax/logger caches on `moduleName` + `logDirectory`, so repeated calls for
 * the same module return the same instance, exactly as the direct calls did.
 * The ONE global file takes the rotation of the first logger that opens it,
 * which is why every logger passes the same one.
 */
export function createModuleLogger(moduleName: string): Logger {
  const writeFiles = shouldWriteLogFiles();
  return createLogger({
    moduleName,
    logDirectory: resolveLogDirectory(),
    includeFile: writeFiles && shouldWriteModuleFiles(),
    includeGlobalFile: writeFiles,
    rotation: LOG_FILE_ROTATION,
    globalRotation: LOG_FILE_ROTATION,
    onTransportError: reportLogFileFailure,
  });
}

/**
 * What a log line records about a caught error: its message, and nothing else.
 *
 * Pass `error: errorMessage(err)` in log metadata, never `error: err`. Since
 * `@hiprax/logger` 1.2, an `Error` in metadata renders its name, message, stack,
 * own fields and `cause` chain, where it used to render `{}`. A driver error's
 * own fields can carry request data (nodemailer's `rejected` recipients, a
 * MongoDB duplicate key's `keyValue`), which has no place in a log kept for a
 * year. One helper also keeps the call sites branch-free.
 *
 * Anything that is neither an `Error` nor a string becomes `'Unknown error'`. It
 * is never passed through `String()`, which runs arbitrary `toString` code and
 * can throw inside a catch block.
 */
export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return 'Unknown error';
}
