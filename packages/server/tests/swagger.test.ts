import { describe, it, expect, beforeAll, vi } from 'vitest';
import type { Mock } from 'vitest';
import type winston from 'winston';
import request from 'supertest';
import { APP_VERSION } from '@hvault/shared';
import app from '../src/app.js';
import { swaggerSpec } from '../src/config/swagger.js';
import { warnIfSwaggerEnabledInProduction } from '../src/utils/swaggerWarning.js';
import { ROUTE_TABLE } from './support/routeTable.js';

describe('API Documentation', () => {
  describe('GET /api/docs', () => {
    it('should serve the Swagger UI page', async () => {
      const res = await request(app).get('/api/docs/').redirects(1);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
    });
  });

  describe('GET /api/v1/docs.json', () => {
    it('should return the OpenAPI spec as JSON', async () => {
      const res = await request(app).get('/api/v1/docs.json');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.body.openapi).toBe('3.0.3');
      expect(res.body.info.title).toBe('H-Vault API');
      // Assert against the canonical app version (injected from package.json into
      // the shared APP_VERSION constant), NOT a copied literal. swagger.ts still
      // hardcodes its version string, so this turns RED if that literal ever
      // drifts from the released package version — the doc-sync bug the earlier
      // `toBe('1.1.0')` literal could not catch (and which broke on every bump).
      expect(res.body.info.version).toBe(APP_VERSION);
    });

    it('should include all API tags', async () => {
      const res = await request(app).get('/api/v1/docs.json');

      const tagNames = res.body.tags.map((t: { name: string }) => t.name);
      expect(tagNames).toContain('Health');
      expect(tagNames).toContain('Auth');
      expect(tagNames).toContain('Vault');
      expect(tagNames).toContain('Folders');
      expect(tagNames).toContain('User');
      expect(tagNames).toContain('Tools');
      expect(tagNames).toContain('Backup');
      expect(tagNames).toContain('Documents');
    });

    it('should include security schemes', async () => {
      const res = await request(app).get('/api/v1/docs.json');

      const schemes = res.body.components.securitySchemes;
      expect(schemes.bearerAuth).toBeDefined();
      expect(schemes.bearerAuth.type).toBe('http');
      expect(schemes.bearerAuth.scheme).toBe('bearer');
      expect(schemes.csrfToken).toBeDefined();
      expect(schemes.csrfToken.type).toBe('apiKey');
    });

    it('should document all major endpoint paths', async () => {
      const res = await request(app).get('/api/v1/docs.json');

      const paths = Object.keys(res.body.paths);
      expect(paths).toContain('/health');
      expect(paths).toContain('/auth/login');
      expect(paths).toContain('/auth/register');
      expect(paths).toContain('/vault/items');
      expect(paths).toContain('/folders');
      expect(paths).toContain('/user/profile');
      expect(paths).toContain('/tools/check-password-breach');
      expect(paths).toContain('/backup/setup');
      expect(paths).toContain('/documents');
      expect(paths).toContain('/documents/trash');
      expect(paths).toContain('/documents/usage');
      expect(paths).toContain('/documents/uploads');
      expect(paths).toContain('/documents/uploads/{id}');
      expect(paths).toContain('/documents/uploads/{id}/parts/{partNumber}');
      expect(paths).toContain('/documents/uploads/{id}/complete');
      expect(paths).toContain('/documents/{id}');
      expect(paths).toContain('/documents/{id}/restore');
      expect(paths).toContain('/documents/{id}/permanent');
      expect(paths).toContain('/documents/trash/empty');
      expect(paths).toContain('/documents/{id}/segments/{index}');
    });
  });

  describe('swaggerSpec object', () => {
    it('should have valid OpenAPI version', () => {
      expect(swaggerSpec.openapi).toBe('3.0.3');
    });

    it('should define reusable schemas for all domain models', () => {
      const schemas = swaggerSpec.components.schemas as Record<string, unknown>;
      expect(schemas.VaultItemResponse).toBeDefined();
      expect(schemas.FolderResponse).toBeDefined();
      expect(schemas.UserProfile).toBeDefined();
      expect(schemas.AuditLogEntry).toBeDefined();
      expect(schemas.BackupLogEntry).toBeDefined();
      expect(schemas.HealthResponse).toBeDefined();
      expect(schemas.ErrorResponse).toBeDefined();
    });

    it('should define reusable error responses', () => {
      const responses = swaggerSpec.components.responses as Record<string, unknown>;
      expect(responses.Unauthorized).toBeDefined();
      expect(responses.Forbidden).toBeDefined();
      expect(responses.NotFound).toBeDefined();
      expect(responses.RateLimited).toBeDefined();
      expect(responses.ValidationError).toBeDefined();
      expect(responses.StorageUnavailable).toBeDefined();
    });

    it('should have the API server defined', () => {
      expect(swaggerSpec.servers).toHaveLength(1);
      expect(swaggerSpec.servers[0].url).toBe('/api/v1');
    });

    it('should have authHash maxLength matching Zod schema (100)', () => {
      const schemas = swaggerSpec.components.schemas as Record<
        string,
        { properties?: Record<string, { maxLength?: number }> }
      >;
      const registerProps = schemas.RegisterRequest?.properties;
      const loginProps = schemas.LoginRequest?.properties;
      const bulkReEncryptProps = schemas.BulkReEncryptRequest?.properties;
      const changePasswordProps = schemas.ChangePasswordRequest?.properties;
      expect(registerProps?.authHash?.maxLength).toBe(100);
      expect(loginProps?.authHash?.maxLength).toBe(100);
      expect(bulkReEncryptProps?.authHash?.maxLength).toBe(100);
      expect(changePasswordProps?.currentAuthHash?.maxLength).toBe(100);
      expect(changePasswordProps?.newAuthHash?.maxLength).toBe(100);
    });

    it('documents the optional rememberMe login flag (boolean, default false)', () => {
      const schemas = swaggerSpec.components.schemas as Record<
        string,
        { properties?: Record<string, { type?: string; default?: unknown }> }
      >;
      const rememberMe = schemas.LoginRequest?.properties?.rememberMe;
      expect(rememberMe).toBeDefined();
      expect(rememberMe?.type).toBe('boolean');
      expect(rememberMe?.default).toBe(false);
    });

    it('should have encryptedVaultKey maxLength matching Zod schema (200)', () => {
      const schemas = swaggerSpec.components.schemas as Record<
        string,
        { properties?: Record<string, { maxLength?: number }> }
      >;
      const registerProps = schemas.RegisterRequest?.properties;
      const resetProps = schemas.ResetPasswordRequest?.properties;
      const bulkReEncryptProps = schemas.BulkReEncryptRequest?.properties;
      const changePasswordProps = schemas.ChangePasswordRequest?.properties;
      expect(registerProps?.encryptedVaultKey?.maxLength).toBe(200);
      expect(resetProps?.newEncryptedVaultKey?.maxLength).toBe(200);
      expect(bulkReEncryptProps?.newEncryptedVaultKey?.maxLength).toBe(200);
      expect(changePasswordProps?.newEncryptedVaultKey?.maxLength).toBe(200);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Spec accuracy — documentation synchronization
  // ──────────────────────────────────────────────────────────────────────────

  describe('spec accuracy (doc sync)', () => {
    it('bearerAuth description reflects the real access-token lifetime (5 min, not 15 min)', () => {
      const schemes = swaggerSpec.components.securitySchemes as Record<
        string,
        { description?: string }
      >;
      const desc = schemes['bearerAuth']?.description ?? '';
      // The JWT access token default lifetime is 5m (config JWT_ACCESS_EXPIRY),
      // so the spec must not advertise the stale "15 min" value.
      expect(desc).not.toContain('15 min');
      expect(desc).toContain('5 min');
    });

    it('no operation description references a nonexistent "apiLimiter"', () => {
      const paths = swaggerSpec.paths as Record<string, Record<string, unknown>>;
      const offenders: string[] = [];
      for (const [route, methods] of Object.entries(paths)) {
        for (const [method, op] of Object.entries(methods)) {
          const description =
            op && typeof op === 'object' && 'description' in op
              ? (op as { description?: unknown }).description
              : undefined;
          if (typeof description === 'string' && description.includes('apiLimiter')) {
            offenders.push(`${method.toUpperCase()} ${route}`);
          }
        }
      }
      expect(offenders).toEqual([]);
    });

    it('the export operation advertises JSON only (CSV is import-only)', () => {
      const paths = swaggerSpec.paths as Record<string, Record<string, unknown>>;
      const exportPost = paths['/tools/export']?.['post'];
      const description =
        exportPost && typeof exportPost === 'object' && 'description' in exportPost
          ? (exportPost as { description?: unknown }).description
          : undefined;
      expect(typeof description).toBe('string');
      expect(description as string).not.toMatch(/csv/i);
      expect(description as string).toContain('JSON');
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // The document store, as a documentation CONTRACT
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * `audit:config` lints this document with Spectral, and Spectral's OpenAPI
   * ruleset asks whether it is WELL-FORMED. It cannot ask whether an operation
   * is USEFUL: one with no description, a bare path parameter and no documented
   * failure passes it cleanly. These assertions are the other half.
   *
   * They are scoped to the document store on purpose. Its operations were all
   * written at once, to one standard, which is exactly the shape that decays one
   * addition at a time — and the surface is compared against `ROUTE_TABLE`
   * rather than against a number, so a seventeenth route mounted in
   * `routes/documents.ts` fails HERE until it is documented, and an operation
   * documented for a route nobody mounts fails too. A count would have been
   * satisfied by swapping one for another.
   */
  describe('the document store operations', () => {
    interface DocumentedParameter {
      name?: string;
      in?: string;
      description?: unknown;
      schema?: { example?: unknown; enum?: unknown };
    }
    interface DocumentedOperation {
      operationId?: unknown;
      tags?: unknown;
      summary?: unknown;
      description?: unknown;
      security?: unknown;
      parameters?: DocumentedParameter[];
      requestBody?: unknown;
      responses?: Record<string, unknown>;
    }

    const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'] as const;

    /** Every documented `/documents…` operation, keyed `METHOD /path`. */
    const documented = new Map<string, DocumentedOperation>();
    for (const [route, methods] of Object.entries(
      swaggerSpec.paths as Record<string, Record<string, unknown>>,
    )) {
      if (!route.startsWith('/documents')) continue;
      for (const method of HTTP_METHODS) {
        const operation = methods[method] as DocumentedOperation | undefined;
        if (operation) documented.set(`${method.toUpperCase()} ${route}`, operation);
      }
    }

    /**
     * The same key, built from the route table: strip the `/api/v1` mount,
     * rewrite Express's `:param` as OpenAPI's `{param}`, and drop the router
     * root's trailing slash (`collectAppRoutes` composes it as mount + `'/'`).
     */
    const mounted = ROUTE_TABLE.filter((row) => row.path.startsWith('/api/v1/documents')).map(
      (row) => {
        const path = row.path
          .slice('/api/v1'.length)
          .replace(/:([A-Za-z0-9_]+)/g, '{$1}')
          .replace(/^(\/documents)\/$/, '$1');
        return `${row.method.toUpperCase()} ${path}`;
      },
    );

    // Every case below iterates `documented` and asserts an empty offender
    // list, which is a shape that passes over nothing if the map is ever empty
    // — a changed route prefix, a restructured `paths`. Only the surface case
    // would catch that, so the guard runs first and makes each case honest on
    // its own.
    beforeAll(() => {
      expect(documented.size).toBeGreaterThan(0);
    });

    it('documents every mounted document route, and no route it does not mount', () => {
      expect([...documented.keys()].sort()).toEqual([...mounted].sort());
    });

    it('gives every one of them an id, a tag, a summary and a description', () => {
      const thin = [...documented.entries()]
        .filter(
          ([, op]) =>
            typeof op.operationId !== 'string' ||
            !Array.isArray(op.tags) ||
            !op.tags.includes('Documents') ||
            typeof op.summary !== 'string' ||
            op.summary === '' ||
            typeof op.description !== 'string' ||
            // A one-line restatement of the summary is what this is guarding
            // against, so the bar is a real sentence rather than a non-empty
            // string. Every description here is a paragraph today.
            (op.description as string).length < 80,
        )
        .map(([key]) => key);
      expect(thin).toEqual([]);
    });

    it('declares an authenticated security requirement on every one of them', () => {
      // The NEGATIVE half matters more than the positive one: `security: []`
      // is the OpenAPI spelling of "this endpoint is public", and it is one
      // edit away. Every document route sits behind `authenticate`.
      const unauthenticated = [...documented.entries()]
        .filter(([, op]) => {
          const security = op.security;
          if (!Array.isArray(security) || security.length === 0) return true;
          return !security.every(
            (requirement) =>
              typeof requirement === 'object' &&
              requirement !== null &&
              'bearerAuth' in (requirement as Record<string, unknown>),
          );
        })
        .map(([key]) => key);
      expect(unauthenticated).toEqual([]);
    });

    it('documents a 401, a 429 and the 503 the storage guard answers, on every one of them', () => {
      // `requireStorage` is router-level, so 503 is an outcome of ALL sixteen
      // rather than of the ones that touch storage — a caller against a
      // deployment with no object storage sees it from the list endpoints too.
      const missing: string[] = [];
      for (const [key, op] of documented) {
        for (const status of ['401', '429', '503']) {
          if (!(status in (op.responses ?? {}))) missing.push(`${key} has no ${status}`);
        }
      }
      expect(missing).toEqual([]);
    });

    // "at least one 4xx" is what this pair REPLACED, and the reason is worth
    // keeping: every operation inherits 401 from DOCUMENT_BASE_ERRORS, so a
    // filter over the whole 4xx range was satisfied before any operation-specific
    // failure existed and pinned "these routes are authenticated" — which the
    // case above already pins better. Two of the sixteen genuinely have no other
    // 4xx (GET /documents/usage and GET /documents/uploads take no id and no
    // body), so the honest form is conditional on the operation's own shape.

    it('documents a 404 on every operation that names one row', () => {
      const missing = [...documented.entries()]
        .filter(([, op]) => (op.parameters ?? []).some((parameter) => parameter.in === 'path'))
        .filter(([, op]) => !('404' in (op.responses ?? {})))
        .map(([key]) => key);
      // A foreign id earns the same 404 as one that never existed, which is what
      // stops documents being enumerated — so an id-taking route that does not
      // document it is documenting a different security posture than it has.
      expect(missing).toEqual([]);
    });

    it('documents a 400 on every operation that accepts a request body', () => {
      const missing = [...documented.entries()]
        .filter(([, op]) => op.requestBody !== undefined)
        .filter(([, op]) => !('400' in (op.responses ?? {})))
        .map(([key]) => key);
      // Zod rejections come from one middleware and are ALWAYS 400 in this
      // codebase, never 422, so a body-taking operation without one is wrong
      // about the shape of its own failures.
      expect(missing).toEqual([]);
    });

    it('gives every parameter a description, and an example unless it is an enum', () => {
      // The regression this pins actually shipped: the transfer-id parameter
      // was declared as a bare `{ type: 'string' }` while the document-id one
      // beside it carried an example, so "try it out" in the docs UI offered
      // nothing to try on half the routes.
      //
      // Path, query AND header — scoping it to path parameters is what let
      // `page`, `limit` and `x-hv-part-sha256` stay bare through the pass that
      // was supposed to catch exactly that. An ENUM is exempt from the example
      // and only from the example: its schema already shows a reader every
      // value it accepts, and a `default` names the one it will get.
      const bare: string[] = [];
      for (const [key, op] of documented) {
        for (const parameter of op.parameters ?? []) {
          const label = `${key} ${parameter.in ?? '?'}:${parameter.name ?? '?'}`;
          if (typeof parameter.description !== 'string' || parameter.description === '') {
            bare.push(`${label} has no description`);
          }
          if (parameter.schema?.enum === undefined && parameter.schema?.example === undefined) {
            bare.push(`${label} has no example`);
          }
        }
      }
      expect(bare).toEqual([]);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Production warning log (Task 7.2)
  // ──────────────────────────────────────────────────────────────────────────

  describe('warnIfSwaggerEnabledInProduction', () => {
    /** Spy that the production call site can accept AND the tests can assert on. */
    type MockLogger = Pick<winston.Logger, 'warn'> & { warn: Mock };

    // winston's `warn` is a five-overload `LeveledLogMethod` returning a Logger, so
    // no plain spy can satisfy every arm; state the shape once here instead of at
    // each of the five call sites.
    function makeLogger(): MockLogger {
      return { warn: vi.fn() } as unknown as MockLogger;
    }

    it('should emit a warning when NODE_ENV=production and ENABLE_SWAGGER=true', () => {
      const logger = makeLogger();
      const result = warnIfSwaggerEnabledInProduction(
        { NODE_ENV: 'production', ENABLE_SWAGGER: true },
        logger,
      );

      expect(result).toBe(true);
      expect(logger.warn).toHaveBeenCalledTimes(1);
      const [message] = logger.warn.mock.calls[0] as [string];
      expect(message).toContain('Swagger UI is ENABLED in production');
      expect(message).toContain('ENABLE_SWAGGER=true');
      expect(message).toContain('/api/docs');
      expect(message).toContain('/api/v1/docs.json');
      // Should mention that it exposes unauthenticated access so operators
      // understand the actual risk.
      expect(message.toLowerCase()).toContain('unauthenticated');
    });

    it('should NOT emit a warning when NODE_ENV=development (Swagger is expected)', () => {
      const logger = makeLogger();
      const result = warnIfSwaggerEnabledInProduction(
        { NODE_ENV: 'development', ENABLE_SWAGGER: false },
        logger,
      );

      expect(result).toBe(false);
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('should NOT emit a warning when NODE_ENV=development even if ENABLE_SWAGGER=true', () => {
      const logger = makeLogger();
      const result = warnIfSwaggerEnabledInProduction(
        { NODE_ENV: 'development', ENABLE_SWAGGER: true },
        logger,
      );

      expect(result).toBe(false);
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('should NOT emit a warning when NODE_ENV=test', () => {
      const logger = makeLogger();
      const result = warnIfSwaggerEnabledInProduction(
        { NODE_ENV: 'test', ENABLE_SWAGGER: true },
        logger,
      );

      expect(result).toBe(false);
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('should NOT emit a warning when NODE_ENV=production but ENABLE_SWAGGER=false', () => {
      const logger = makeLogger();
      const result = warnIfSwaggerEnabledInProduction(
        { NODE_ENV: 'production', ENABLE_SWAGGER: false },
        logger,
      );

      expect(result).toBe(false);
      expect(logger.warn).not.toHaveBeenCalled();
    });
  });
});
