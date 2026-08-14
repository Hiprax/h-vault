#!/usr/bin/env node
/**
 * Prints the OpenAPI 3.0.3 document `packages/server/src/config/swagger.ts`
 * builds, as JSON, on stdout.
 *
 * Run through `node --import tsx`, never through `npx`: `npx` is a `.cmd` shim
 * on Windows and Node refuses to spawn one without a shell (see the header of
 * `lib/proc.mjs`), so the `audit:config` gate would report "could not build the
 * OpenAPI document" on the one platform this project is also developed on.
 *
 * The document is generated rather than read from a checked-in file because
 * `swaggerSpec` IS what the server serves at /api/v1/docs.json; linting a copy
 * would be linting something that can drift. `swagger.ts` imports only
 * `@hvault/shared` (for APP_VERSION), so this has no side effects and needs no
 * environment.
 */
const module_ = await import('../../packages/server/src/config/swagger.ts');
process.stdout.write(JSON.stringify(module_.swaggerSpec, null, 2));
