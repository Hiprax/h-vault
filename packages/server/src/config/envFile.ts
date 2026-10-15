/**
 * Loads the deployment's `.env` into `process.env`, once, before any
 * configuration is parsed.
 *
 * Its own module because two configurations read the environment: the
 * application's (`config/index.ts`) and the index bootstrap's secret-free subset
 * (`config/indexConfig.ts`, which `scripts/create-indexes.ts` and the models with
 * TTL indexes read). Both import this module first, and an ES module is
 * evaluated once per process, so the file is read exactly once whichever of the
 * two a process loads.
 *
 * In the Docker stack's index bootstrap there is no `.env` to read: that
 * container is given exactly the index keys through its `environment:` block and
 * no `env_file`, so the load below finds no file and changes nothing.
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import dotenv from 'dotenv';

// Resolve .env from the monorepo root (4 levels up from packages/server/src/config/).
// When using npm workspaces, process.cwd() points to the package directory, not the
// monorepo root. This caused dotenv to load packages/server/.env (test config with
// empty SMTP values) instead of the root .env (actual user config).
const configDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(configDir, '..', '..', '..', '..');
const rootEnvPath = path.join(rootDir, '.env');

// Every option that decides WHAT is loaded, pinned. dotenv also reads its options
// from `DOTENV_*` (and `DOTENV_CONFIG_*`) environment variables on every
// `config()` call, with the options passed here taking precedence, so anything
// left unpinned is something an ambient variable can change. `override: false` is
// the load-bearing one: a variable the environment already holds must win over
// the file (the server suite's pinned `test.env` beats a developer's root .env
// only because of it, the E2E harness points storage at its own engine that way,
// and a process-manager or shell export is expected to beat the file). The encoding and
// the parser are pinned so the file is read the one way it has always been read.
const DOTENV_LOAD_OPTIONS = { override: false, encoding: 'utf8', fast: false } as const;

// The root .env when there is one, else the one in CWD (a standalone deployment
// without .env at the monorepo root, e.g. inside a Docker container). The
// fallback is named explicitly rather than left to dotenv's default, which
// `DOTENV_PATH` would otherwise redirect.
const envPath = fs.existsSync(rootEnvPath) ? rootEnvPath : path.resolve(process.cwd(), '.env');
dotenv.config({ ...DOTENV_LOAD_OPTIONS, path: envPath });
