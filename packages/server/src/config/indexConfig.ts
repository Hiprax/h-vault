/**
 * The configuration the index bootstrap needs, and nothing secret.
 *
 * `scripts/create-indexes.ts` builds every collection's indexes, and three models
 * take their TTL retention from configuration when they load (`AuditLog`,
 * `BackupLog`, `PwnedRangeCache`). They used to read the application
 * configuration (`config/index.ts`), whose schema refuses to load without every
 * application secret, so the Docker stack's `hvault-bootstrap` one-shot, which
 * only connects to the database and builds indexes, had to be handed the whole
 * root `.env`: JWT, session and 2FA keys, SMTP and storage credentials included
 * (F-20). This module and `indexConfigSchema.ts` (the seven keys that step reads,
 * their rules and defaults) are all of the configuration that step loads; the
 * one-shot receives exactly these keys by interpolation and no `env_file`
 * (`docker-compose.yml`).
 *
 * `config/index.ts` composes the same shape into its own, importing it from
 * `indexConfigSchema.ts` (which validates nothing on load), so the application
 * reads these keys with the same rules and the same defaults, its configuration
 * is unchanged, and a misconfigured server still lists every issue at once. A
 * retention setting changed in `.env` therefore reaches the index the bootstrap
 * builds and the value the application reads alike.
 *
 * Nothing here may be a secret. `MONGODB_URI` carries the scoped database user's
 * password inside it, which is the one credential this step genuinely uses.
 */
import './envFile.js';
import { parseIndexConfig } from './indexConfigSchema.js';

/** The index configuration, parsed from the environment (after the `.env` load) when this module loads. */
export const indexConfig = parseIndexConfig(process.env);
