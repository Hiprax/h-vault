import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import { APP_VERSION } from '@hvault/shared';
import app from '../src/app.js';
import { swaggerSpec } from '../src/config/swagger.js';
import { warnIfSwaggerEnabledInProduction } from '../src/utils/swaggerWarning.js';

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
  // Production warning log (Task 7.2)
  // ──────────────────────────────────────────────────────────────────────────

  describe('warnIfSwaggerEnabledInProduction', () => {
    function makeLogger(): { warn: ReturnType<typeof vi.fn> } {
      return { warn: vi.fn() };
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
