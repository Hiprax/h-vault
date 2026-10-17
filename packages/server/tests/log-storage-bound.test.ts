/**
 * F-17: the log files the server writes inside a container fit the tmpfs they
 * are written to.
 *
 * Both Node containers keep their root filesystem read-only and give the logger
 * a size-capped tmpfs (`docker-compose.yml`). Every `createModuleLogger` call
 * used to open a rotating file of its own beside the shared global file, each at
 * @hiprax/logger's default retention (`20m` per file, kept `14d`: a count of
 * DAYS, so the number of files is unbounded within them), so one module that
 * logged hard could fill the tmpfs and a log flood had no ceiling at all. What
 * fills a tmpfs is memory the container is charged for, and a full one turns
 * every later file write into an error.
 *
 * The bound is computed, not asserted from the code's own constants: the real
 * loggers are built for every module name the server source uses, under the
 * environment the compose file gives each container, and every rotating file
 * they open is summed at its own `maxSize` x `maxFiles` (a day-count retention
 * is unbounded). The total must be below the size of the tmpfs that holds that
 * container's log directory, parsed from the compose file.
 *
 * Which files are opened is read from the options each logger hands to
 * @hiprax/logger's `createLogger` (a pass-through spy), because the library
 * keeps the ONE shared global file inside a closure that no logger exposes: by
 * its documented contract, one module file per logger with `includeFile`, and
 * one global file at the rotation of the FIRST logger that opened it
 * (`globalRotation`, else `rotation`). The module files are then checked against
 * the real transports, so the reading is the library's, not ours.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';

vi.mock('@hiprax/logger', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@hiprax/logger')>();
  return { ...actual, createLogger: vi.fn(actual.createLogger) };
});

import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import {
  createLogger,
  defaultRotation,
  shutdownAllLoggers,
  type LoggerOptions,
  type RotationStrategy,
} from '@hiprax/logger';
import type transport from 'winston-transport';
import { createModuleLogger, LOG_FILE_ROTATION } from '../src/utils/logger.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '../src');
const COMPOSE = path.resolve(HERE, '../../../docker-compose.yml');

/** The two Node containers that load the server's modules. */
const LOGGING_SERVICES = ['hvault-app', 'hvault-bootstrap'] as const;

const ENV_KEYS = ['NODE_ENV', 'LOG_DIRECTORY', 'LOG_MODULE_FILES'] as const;
const savedEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
const scratch: string[] = [];

afterEach(async () => {
  for (const key of ENV_KEYS) {
    const value = savedEnv[key];
    if (value === undefined) Reflect.deleteProperty(process.env, key);
    else process.env[key] = value;
  }
  await shutdownAllLoggers();
  for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return name.endsWith('.ts') ? [full] : [];
  });
}

/** Every module name the server source builds a logger for. */
function moduleNames(): string[] {
  const names = new Set<string>();
  for (const file of sourceFiles(SRC)) {
    for (const match of readFileSync(file, 'utf8').matchAll(/createModuleLogger\('([^']+)'\)/g)) {
      names.add(match[1]!);
    }
  }
  return [...names].sort();
}

/** Bytes in a compose / rotate-file size such as `64m`, `500k`, `1g`. */
function sizeBytes(value: string): number {
  const match = /^(\d+(?:\.\d+)?)([kmg])$/i.exec(value.trim());
  if (!match) throw new Error(`Not a size: ${value}`);
  const unit = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[match[2]!.toLowerCase() as 'k' | 'm' | 'g'];
  return Number(match[1]) * unit;
}

/** The most files a rotate-file transport keeps: a bare count, or unbounded for a day count. */
function fileCount(maxFiles: unknown): number {
  if (typeof maxFiles === 'number') return maxFiles;
  if (typeof maxFiles === 'string' && /^\d+$/.test(maxFiles)) return Number(maxFiles);
  return Number.POSITIVE_INFINITY;
}

interface ContainerLogging {
  env: Record<string, string>;
  tmpfsBytes: number;
}

/** What the compose file gives one container: its environment and its log tmpfs size. */
function containerLogging(service: string): ContainerLogging {
  const compose = parse(readFileSync(COMPOSE, 'utf8'), { merge: true }) as {
    services: Record<string, { environment?: Record<string, unknown>; tmpfs?: string[] }>;
  };
  const definition = compose.services[service];
  expect(definition, service).toBeDefined();
  const env = Object.fromEntries(
    Object.entries(definition!.environment ?? {}).map(([key, value]) => [key, String(value)]),
  );
  // The log directory is the one tmpfs mounted at a path ending in `/logs`.
  const logMounts = (definition!.tmpfs ?? []).filter((entry) => /\/logs:/.test(entry));
  expect(logMounts, `${service} log tmpfs`).toHaveLength(1);
  const size = /(?:^|,)size=([^,]+)/.exec(logMounts[0]!.split(':')[1] ?? '')?.[1];
  expect(size, `${service} log tmpfs size`).toBeDefined();
  return { env, tmpfsBytes: sizeBytes(size!) };
}

interface Built {
  /** Every rotating file opened, keyed `module:<name>` or `global`, with the rotation it keeps. */
  files: Map<string, RotationStrategy>;
  /** The module loggers' own rotating-file transports, as the library built them. */
  moduleTransports: transport[];
  /** The log directory they write to. */
  dir: string;
}

/** Builds every module's logger under `env` (log directory in a scratch dir). */
function buildUnder(env: Record<string, string>): Built {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-log-bound-'));
  scratch.push(dir);
  for (const key of ENV_KEYS) {
    if (key === 'LOG_DIRECTORY') process.env[key] = dir;
    else if (env[key] === undefined) Reflect.deleteProperty(process.env, key);
    else process.env[key] = env[key];
  }
  vi.mocked(createLogger).mockClear();
  const moduleTransports: transport[] = [];
  for (const name of moduleNames()) {
    for (const t of createModuleLogger(name).transports) {
      if (typeof (t as unknown as { filename?: unknown }).filename === 'string') {
        moduleTransports.push(t);
      }
    }
  }
  const files = new Map<string, RotationStrategy>();
  for (const [options] of vi.mocked(createLogger).mock.calls as [LoggerOptions][]) {
    if (options.includeFile !== false) {
      files.set(`module:${String(options.moduleName)}`, {
        ...defaultRotation,
        ...options.rotation,
      });
    }
    if (options.includeGlobalFile !== false && !files.has('global')) {
      files.set('global', { ...defaultRotation, ...(options.globalRotation ?? options.rotation) });
    }
  }
  return { files, moduleTransports, dir };
}

/** The most bytes the opened files can keep, summed. */
function totalBound(files: Map<string, RotationStrategy>): number {
  let sum = 0;
  for (const rotation of files.values()) {
    if (typeof rotation.maxSize !== 'string') return Number.POSITIVE_INFINITY;
    sum += sizeBytes(rotation.maxSize) * fileCount(rotation.maxFiles);
  }
  return sum;
}

/** Each module file the options describe is a real transport keeping exactly that rotation. */
function expectModuleFilesAsBuilt(built: Built): void {
  const described = [...built.files.keys()].filter((key) => key.startsWith('module:'));
  expect(built.moduleTransports).toHaveLength(described.length);
  for (const t of built.moduleTransports) {
    const options = (t as unknown as { options: { maxSize?: unknown; maxFiles?: unknown } })
      .options;
    const { dirname, filename } = t as unknown as { dirname: string; filename: string };
    // A module named `jobs/backup` writes `jobs/backup-%DATE%.log` under the directory.
    const name = path.relative(built.dir, path.join(dirname, filename)).replace('-%DATE%.log', '');
    const rotation = built.files.get(`module:${name}`);
    expect(rotation, name).toBeDefined();
    expect(options.maxSize).toBe(rotation!.maxSize);
    expect(options.maxFiles).toBe(rotation!.maxFiles);
  }
}

describe('F-17: log files inside the container fit their tmpfs', () => {
  it('reads module names from the source (the scan is not blind)', () => {
    const names = moduleNames();
    expect(names.length).toBeGreaterThan(20);
    expect(names).toEqual(expect.arrayContaining(['auth', 'vault-quota', 'migrations', 'http']));
  });

  for (const service of LOGGING_SERVICES) {
    it(`${service}: the total file-transport bound is below its log tmpfs`, () => {
      const { env, tmpfsBytes } = containerLogging(service);
      expect(env.NODE_ENV).toBe('production');

      const built = buildUnder(env);

      expectModuleFilesAsBuilt(built);
      // A file is still written (the stream is not merely switched off)...
      expect(built.files.has('global')).toBe(true);
      // ...and every byte the files can keep fits, with the console as the full stream.
      expect(totalBound(built.files)).toBeLessThan(tmpfsBytes);
    });
  }

  it('writes a failure the file transport reports to console.error once, however many follow', () => {
    // Development, where module files are on, so a real file transport is in reach.
    const { moduleTransports } = buildUnder({ NODE_ENV: 'development' });
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    // Two different failures the transport itself reports (as it does for a
    // failed removal of a rotated archive). A failed write to the file is NOT
    // one: winston-daily-rotate-file 5.0.0 does not forward its stream's errors,
    // so that ends the process instead (see utils/logger.ts); the count bound is
    // the control for it, not this handler.
    moduleTransports[0]!.emit('error', new Error('EACCES: permission denied, unlink'));
    moduleTransports[0]!.emit('error', new Error('ENOENT: no such file or directory, unlink'));

    expect(consoleError).toHaveBeenCalledTimes(1);
    expect(String(consoleError.mock.calls[0]![0])).toMatch(/log file/i);
    expect(String(consoleError.mock.calls[0]![0])).toContain('EACCES');
  });

  it('keeps the library defaults for everything but the two bounds', () => {
    expect(LOG_FILE_ROTATION).toEqual({ ...defaultRotation, maxSize: '4m', maxFiles: '3' });
    expect(Object.isFrozen(LOG_FILE_ROTATION)).toBe(true);
  });

  it('still attaches no file transport at all under NODE_ENV=test', () => {
    const built = buildUnder({ NODE_ENV: 'test' });
    expect(built.files.size).toBe(0);
    expect(built.moduleTransports).toEqual([]);
  });

  it('keeps the module files in development, each bounded by count', () => {
    const built = buildUnder({ NODE_ENV: 'development' });

    expectModuleFilesAsBuilt(built);
    // One per module plus the shared global file, all with a finite bound.
    expect(built.files.size).toBe(moduleNames().length + 1);
    expect(totalBound(built.files)).toBeLessThan(Number.POSITIVE_INFINITY);
  });

  it('honours an explicit LOG_MODULE_FILES either way', () => {
    expect(buildUnder({ NODE_ENV: 'production', LOG_MODULE_FILES: 'true' }).files.size).toBe(
      moduleNames().length + 1,
    );
    expect(buildUnder({ NODE_ENV: 'development', LOG_MODULE_FILES: 'false' }).files.size).toBe(1);
  });
});
