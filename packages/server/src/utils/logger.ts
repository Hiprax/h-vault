import path from 'node:path';
import { createLogger } from '@hiprax/logger';
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
 * WHY THIS READS `process.env` AND NOT `config`. `config/index.ts` builds a
 * logger of its own, to report on its own validation, before the parsed config
 * exists — so a logger module that imported `config` would be a cycle through
 * the one module that cannot wait for it. The two values here are read straight
 * from the environment for that reason, and they are the only two: everything
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
 * Builds this application's logger for one module.
 *
 * Every `createLogger` call under `packages/server/src` goes through here, so
 * the directory and the transport set are decided once. @hiprax/logger caches on
 * `moduleName` + `logDirectory`, so repeated calls for the same module return
 * the same instance, exactly as the direct calls did.
 */
export function createModuleLogger(moduleName: string): Logger {
  const writeFiles = shouldWriteLogFiles();
  return createLogger({
    moduleName,
    logDirectory: resolveLogDirectory(),
    includeFile: writeFiles,
    includeGlobalFile: writeFiles,
  });
}
