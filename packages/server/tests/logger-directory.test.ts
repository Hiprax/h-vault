/**
 * `utils/logger.ts` — where log files go, and when there are none.
 *
 * This module exists because of a measured defect rather than a design idea.
 * Every `createLogger({ moduleName })` in `packages/server/src` used to take
 * @hiprax/logger's defaults: a `logDirectory` of `path.resolve(cwd(), 'logs')`
 * with `includeFile` and `includeGlobalFile` both true. Two things followed —
 * an operator had no way to put logs anywhere else, and every
 * `npm test -w packages/server` appended ~1.6 MB of rotating log files into the
 * checkout (measured at 406 files and 448 MB accumulated), invisible to every
 * gate because the directory is gitignored.
 *
 * The suite-wide proof of the fix is in `tempDir.test.ts`: the log directories
 * are no longer on the repo-write guard's allowlist, so a single bare
 * `createLogger` anywhere in the server fails the run at the first import that
 * builds a logger. This file covers the decisions that guard cannot see — what
 * the directory resolves to, and that the production branch still attaches file
 * transports rather than having been quietly turned off for everyone.
 */
import { describe, expect, it } from 'vitest';
import path from 'node:path';
import type transport from 'winston-transport';
import {
  createModuleLogger,
  DEFAULT_LOG_DIRECTORY_NAME,
  resolveLogDirectory,
  shouldWriteLogFiles,
} from '../src/utils/logger.js';

/** A rotating file transport carries a `filename`; the console transport does not. */
const isFileTransport = (t: transport): boolean =>
  typeof (t as unknown as { filename?: unknown }).filename === 'string';

describe('log directory resolution', () => {
  it('honours LOG_DIRECTORY, resolved to an absolute path', () => {
    expect(resolveLogDirectory({ LOG_DIRECTORY: '/var/log/hvault' })).toBe('/var/log/hvault');
    // Relative values resolve against the process, so an operator writing
    // `LOG_DIRECTORY=./data/logs` gets a path rather than a path fragment that
    // means something different to every transport that reads it.
    expect(path.isAbsolute(resolveLogDirectory({ LOG_DIRECTORY: 'data/logs' }))).toBe(true);
  });

  it('treats a blank value as unset rather than as a directory named ""', () => {
    // `.env` files routinely carry `LOG_DIRECTORY=` for a commented-out setting,
    // and `config/index.ts` maps an empty variable to `undefined` for exactly
    // this reason. Without the trim-and-check the logger would try to create a
    // directory named `''` and take the whole boot down with it.
    const fallback = path.resolve(process.cwd(), DEFAULT_LOG_DIRECTORY_NAME);
    expect(resolveLogDirectory({ LOG_DIRECTORY: '' })).toBe(fallback);
    expect(resolveLogDirectory({ LOG_DIRECTORY: '   ' })).toBe(fallback);
    expect(resolveLogDirectory({})).toBe(fallback);
  });
});

describe('file transports', () => {
  it('is off under NODE_ENV=test and on everywhere else', () => {
    // Both directions, because the failure that matters is the SECOND one: a
    // change that disabled file logging for everybody would make this suite
    // quieter and every self-hosted deployment blind, and the first assertion
    // alone would applaud it.
    expect(shouldWriteLogFiles({ NODE_ENV: 'test' })).toBe(false);
    expect(shouldWriteLogFiles({ NODE_ENV: 'production' })).toBe(true);
    expect(shouldWriteLogFiles({ NODE_ENV: 'development' })).toBe(true);
    expect(shouldWriteLogFiles({})).toBe(true);
  });

  it('builds a logger with no file transport in this process, and keeps the console', () => {
    // The suite runs with NODE_ENV pinned to `test` by `tests/setup.ts`, so this
    // asserts the state the whole run is in: nothing here writes a log file. The
    // console transport survives, because a run whose failures print nothing is
    // a worse trade than the files this removes.
    const logger = createModuleLogger('logger-directory-spec');

    expect(logger.transports.length).toBeGreaterThan(0);
    expect(logger.transports.filter(isFileTransport)).toHaveLength(0);
  });
});
