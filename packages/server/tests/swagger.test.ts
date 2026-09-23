import { describe, it, expect, beforeAll, vi } from 'vitest';
import type { Mock } from 'vitest';
import type winston from 'winston';
import request from 'supertest';
import { z } from 'zod';
import * as sharedSchemas from '@hvault/shared';
import {
  bulkReEncryptSchema,
  APP_VERSION,
  backupChangePasswordSchema,
  backupSetupSchema,
  changePasswordSchema,
  createFolderSchema,
  createVaultItemSchema,
  importSchema,
  restoreBackupSchema,
  updateFolderSchema,
  updateVaultItemSchema,
} from '@hvault/shared';
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
  // Identity and tagging, across the WHOLE document
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Every operation carries a unique `operationId` and a declared tag.
   *
   * `operationId` is the name a generated client gives the method, so an
   * operation without one is a method a generator has to invent a name for — and
   * two operations that share one is a client whose second method silently
   * overwrites its first. Spectral's `operation-operationId`,
   * `operation-operationId-unique` and `operation-tag-defined` all police this,
   * and `audit:config` ratchets their findings downward, but a ratchet is a
   * number: it says fifty-three became zero, not WHICH fifty-three, and it only
   * speaks when that gate is run. Pinning it here means a fifty-fourth operation
   * added without an id fails the ordinary server suite instead.
   *
   * Deliberately document-wide, unlike the document-store block below: this is
   * the property that was missing from every operation OUTSIDE it.
   */
  describe('operation identity and tagging', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'] as const;

    /** Every operation in the document, keyed `METHOD /path`. */
    const operations = new Map<string, { operationId?: unknown; tags?: unknown }>();
    for (const [route, methods] of Object.entries(
      swaggerSpec.paths as Record<string, Record<string, unknown>>,
    )) {
      for (const method of HTTP_METHODS) {
        const operation = methods[method] as { operationId?: unknown; tags?: unknown } | undefined;
        if (operation) operations.set(`${method.toUpperCase()} ${route}`, operation);
      }
    }

    /** The tag names the document declares up front, which is the allowed set. */
    const declaredTags = new Set(
      (swaggerSpec.tags as { name?: unknown }[]).map((tag) => String(tag.name)),
    );

    // Each case below asserts an EMPTY offender list, a shape that passes over
    // nothing if the map is ever empty — a restructured `paths`, a renamed key.
    beforeAll(() => {
      expect(operations.size).toBeGreaterThan(0);
      expect(declaredTags.size).toBeGreaterThan(0);
    });

    it('gives every operation an operationId', () => {
      const anonymous = [...operations.entries()]
        .filter(([, op]) => typeof op.operationId !== 'string' || op.operationId === '')
        .map(([key]) => key);
      expect(anonymous).toEqual([]);
    });

    it('never repeats an operationId', () => {
      const seen = new Map<string, string[]>();
      for (const [key, op] of operations) {
        if (typeof op.operationId !== 'string') continue;
        seen.set(op.operationId, [...(seen.get(op.operationId) ?? []), key]);
      }
      const collisions = [...seen.entries()].filter(([, keys]) => keys.length > 1);
      expect(collisions).toEqual([]);
    });

    it('keeps every operationId usable as a generated method name', () => {
      // Spectral's `operation-operationId-valid-in-url` asks only that the id
      // survives a URL; a generated CLIENT additionally has to turn it into an
      // identifier, and `list-vault-items` or `2faSetup` does not become one
      // without a rename nobody controls. camelCase, starting with a letter.
      const malformed = [...operations.values()]
        .map((op) => op.operationId)
        .filter((id) => typeof id !== 'string' || !/^[a-z][A-Za-z0-9]*$/.test(id));
      expect(malformed).toEqual([]);
    });

    it('tags every operation, and only with a tag the document declares', () => {
      const untagged = [...operations.entries()]
        .filter(
          ([, op]) =>
            !Array.isArray(op.tags) ||
            op.tags.length === 0 ||
            !op.tags.every((tag) => typeof tag === 'string' && declaredTags.has(tag)),
        )
        .map(([key]) => key);
      expect(untagged).toEqual([]);
    });

    it('declares no tag it never uses', () => {
      // The other direction, and the one a count would miss: a tag left behind
      // by a removed endpoint shows up in every rendered client as an empty
      // section, and nothing else in this suite would notice.
      const used = new Set(
        [...operations.values()].flatMap((op) => (Array.isArray(op.tags) ? op.tags : [])),
      );
      expect([...declaredTags].filter((tag) => !used.has(tag))).toEqual([]);
    });

    it('publishes contact information a consumer of this API can act on', () => {
      // Spectral's `info-contact`. The URL matters more than the object: a
      // consumer who finds a defect needs somewhere to take it, and SECURITY.md
      // routes a VULNERABILITY somewhere else entirely (a private advisory), so
      // this must be the ordinary-issues destination rather than an address.
      const info = swaggerSpec.info as { contact?: { name?: unknown; url?: unknown } };
      expect(typeof info.contact?.name).toBe('string');
      expect(info.contact?.url).toMatch(/^https:\/\//);
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
  // The vault-key-version contract
  // ──────────────────────────────────────────────────────────────────────────

  describe('the writes guarded by a vault key version', () => {
    /**
     * Every write whose request body may name the vault-key generation it sealed
     * its ciphertext under, mapped to the two places this document has to say so:
     * the request component, and the operation's `409`.
     *
     * The table is checked in BOTH directions, never against a count. Direction
     * one: each row's component declares the property and each row's operation
     * declares the recoverable `409`. Direction two: any shared schema that grows
     * an optional `vaultKeyVersion`, and any request component that documents
     * one, must appear here — which is what turns "somebody guarded an eighth
     * endpoint and forgot the document" from a silent omission into a red test.
     *
     * A count would pass on a row swapped for another, and a one-directional
     * check would pass on the case that actually happens: the guard landing in a
     * controller while the published contract still says the endpoint cannot
     * answer 409.
     */
    const GUARDED_WRITES: {
      schemaName: string;
      schema: { shape: Record<string, z.ZodType> };
      component: string;
      route: string;
      method: 'post' | 'put';
    }[] = [
      {
        schemaName: 'changePasswordSchema',
        schema: changePasswordSchema,
        component: 'ChangePasswordRequest',
        route: '/user/change-password',
        method: 'put',
      },
      {
        schemaName: 'createVaultItemSchema',
        schema: createVaultItemSchema,
        component: 'CreateVaultItemRequest',
        route: '/vault/items',
        method: 'post',
      },
      {
        schemaName: 'updateVaultItemSchema',
        schema: updateVaultItemSchema,
        component: 'UpdateVaultItemRequest',
        route: '/vault/items/{id}',
        method: 'put',
      },
      {
        schemaName: 'createFolderSchema',
        schema: createFolderSchema,
        component: 'CreateFolderRequest',
        route: '/folders',
        method: 'post',
      },
      {
        schemaName: 'updateFolderSchema',
        schema: updateFolderSchema,
        component: 'UpdateFolderRequest',
        route: '/folders/{id}',
        method: 'put',
      },
      {
        schemaName: 'importSchema',
        schema: importSchema,
        component: 'ImportRequest',
        route: '/tools/import',
        method: 'post',
      },
      // A rotation reads the generation only in re-seal mode, where it is the one
      // thing standing between a same-key re-seal and a key rotated away underneath
      // it; an ordinary rotation conditions its commit on the credential instead.
      {
        schemaName: 'bulkReEncryptSchema',
        schema: bulkReEncryptSchema,
        component: 'BulkReEncryptRequest',
        route: '/vault/items/bulk-reencrypt',
        method: 'post',
      },
      {
        schemaName: 'restoreBackupSchema',
        schema: restoreBackupSchema,
        component: 'RestoreBackupRequest',
        route: '/backup/restore',
        method: 'post',
      },
      // The two that store the account's vault key sealed under the BACKUP key —
      // the copy a cross-account restore unwraps. Both wrap their object in a
      // refinement, which is the shape in which a field added to the wrong side
      // of the `.superRefine(...)` / `.refine(...)` call is silently stripped, so
      // `schema.shape` is read here for the same reason the bound tests read it.
      {
        schemaName: 'backupSetupSchema',
        schema: backupSetupSchema,
        component: 'BackupSetupRequest',
        route: '/backup/setup',
        method: 'post',
      },
      {
        schemaName: 'backupChangePasswordSchema',
        schema: backupChangePasswordSchema,
        component: 'BackupChangePasswordRequest',
        route: '/backup/change-password',
        method: 'put',
      },
    ];

    const components = swaggerSpec.components as {
      schemas: Record<string, { properties?: Record<string, unknown>; required?: string[] }>;
    };
    const paths = swaggerSpec.paths as Record<
      string,
      Record<string, { responses?: Record<string, unknown> }>
    >;

    /** True when a shape entry accepts an absent value, i.e. it is `.optional()`. */
    const isOptional = (schema: z.ZodType): boolean => schema.safeParse(undefined).success;

    it.each(GUARDED_WRITES)(
      '$schemaName accepts the generation, and $component documents it as OPTIONAL',
      ({ schema, component }) => {
        expect(isOptional(schema.shape.vaultKeyVersion!)).toBe(true);

        const documented = components.schemas[component]?.properties?.vaultKeyVersion as
          { type?: unknown; minimum?: unknown } | undefined;
        expect(documented).toBeDefined();
        expect(documented?.type).toBe('integer');
        expect(documented?.minimum).toBe(0);

        // The half that carries the compatibility argument. Listing it as
        // required would be a breaking request-schema change, which is the whole
        // reason the field is optional and the server fails closed instead.
        expect(components.schemas[component]?.required ?? []).not.toContain('vaultKeyVersion');
      },
    );

    it.each(GUARDED_WRITES)(
      '$method $route documents the recoverable 409 with the number in `data`',
      ({ route, method }) => {
        const conflict = paths[route]?.[method]?.responses?.['409'] as
          | {
              description?: unknown;
              content?: {
                'application/json'?: {
                  schema?: { properties?: { data?: { properties?: Record<string, unknown> } } };
                };
              };
            }
          | undefined;

        expect(conflict).toBeDefined();
        // A bare `409: { description }` is the shape that leaves the client with
        // prose it cannot act on; the number is what makes the refusal cost one
        // retried request instead of a profile round trip first.
        expect(
          conflict?.content?.['application/json']?.schema?.properties?.data?.properties,
        ).toHaveProperty('vaultKeyVersion');
        expect(String(conflict?.description)).toContain('data.vaultKeyVersion');
      },
    );

    it('documents the generation on every request component that can carry one, and no other', () => {
      // Direction two, swagger side: a component that advertises the field for an
      // endpoint whose schema does not accept it tells a client to send something
      // the server strips, and the client then believes it is protected.
      //
      // Scoped to the OPTIONAL carriers, mirroring the schema-side rule below.
      // `CompleteDocumentUploadRequest` demands the generation outright — it is a
      // newer contract with no compatibility debt — and is documented with the
      // document-store operations, so its presence here would be a false match
      // rather than a finding.
      const expected = GUARDED_WRITES.map((write) => write.component).sort();
      const documented = Object.entries(components.schemas)
        .filter(
          ([name, schema]) =>
            name.endsWith('Request') &&
            schema.properties?.vaultKeyVersion !== undefined &&
            !(schema.required ?? []).includes('vaultKeyVersion'),
        )
        .map(([name]) => name)
        .sort();

      expect(documented).toEqual(expected);
    });

    it('still demands the generation outright on a document completion', () => {
      // The companion half of the carve-out above: if that contract ever relaxed
      // to optional, the exclusion would start hiding a real omission instead of
      // a deliberate difference, and this is what says so.
      const complete = components.schemas.CompleteDocumentUploadRequest;

      expect(complete?.properties?.vaultKeyVersion).toBeDefined();
      expect(complete?.required ?? []).toContain('vaultKeyVersion');
    });

    it('lists every shared write schema that carries an optional generation', () => {
      // Direction two, schema side. This is the one that catches the omission
      // that matters: a later change adds the field to an eighth write envelope,
      // wires the guard, and the published contract still says that endpoint
      // cannot answer 409. Enumerating the shared package rather than restating
      // the list is what makes it unmissable.
      //
      // A REQUIRED `vaultKeyVersion` is deliberately not in scope here:
      // `completeDocumentUploadSchema` demands one outright (a newer contract
      // with no compatibility debt) and the document response schemas report one,
      // and all three are documented with the document-store operations.
      const carriers = Object.entries(sharedSchemas)
        .filter(([, value]) => {
          if (!(value instanceof z.ZodType) || !('shape' in value)) return false;
          const { vaultKeyVersion } = (value as { shape: Record<string, z.ZodType | undefined> })
            .shape;
          return vaultKeyVersion !== undefined && isOptional(vaultKeyVersion);
        })
        .map(([name]) => name)
        .sort();

      expect(carriers).toEqual(GUARDED_WRITES.map((write) => write.schemaName).sort());
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

describe('the documented rate limits', () => {
  const paths = swaggerSpec.paths as Record<
    string,
    Record<string, { responses?: Record<string, unknown> } | undefined>
  >;

  /** `ROUTE_TABLE`'s Express path as the spec spells it, relative to its `/api/v1` server. */
  const specPathOf = (path: string): string =>
    path
      .slice('/api/v1'.length)
      .replace(/:([A-Za-z0-9_]+)/g, '{$1}')
      .replace(/(.)\/$/, '$1');

  const limited = ROUTE_TABLE.filter(
    (row) => row.path.startsWith('/api/v1/') && row.limiters.length > 0,
  );

  it('documents every rate-limited route, and declares its 429', () => {
    // A client reading the spec has no other way to learn that an endpoint can
    // answer 429. Derived from the route table, so a limited route that is left
    // out of the spec, or documented without its 429, fails here.
    const undocumented = limited
      .filter((row) => paths[specPathOf(row.path)]?.[row.method] === undefined)
      .map((row) => `${row.method.toUpperCase()} ${specPathOf(row.path)}`);
    const missing429 = limited
      .filter((row) => {
        const operation = paths[specPathOf(row.path)]?.[row.method];
        return operation !== undefined && !('429' in (operation.responses ?? {}));
      })
      .map((row) => `${row.method.toUpperCase()} ${specPathOf(row.path)}`);
    expect(undocumented).toEqual([]);
    expect(missing429).toEqual([]);
    // Vacuity guard: the route table really does carry limited routes.
    expect(limited.length).toBeGreaterThan(40);
  });
});
