import type { JsonObject } from 'swagger-ui-express';
import {
  APP_VERSION,
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  HIBP_BATCH_MAX_PREFIXES,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
} from '@hvault/shared';

// ---------------------------------------------------------------------------
// Document-route building blocks
// ---------------------------------------------------------------------------
//
// The sixteen document operations repeated four things verbatim: the id path
// parameter, the pagination query parameters, the `{ success, data }` envelope
// and the tail of `$ref`ed error responses. Naming each once and spreading it
// leaves the SERVED document byte-for-byte identical — a spread emits the same
// keys, and JavaScript enumerates integer-like keys in ascending numeric order
// however they were inserted, which is why an error tail may be spread before
// the 2xx it follows — while giving a response added to every document route one
// place to be added rather than sixteen.
//
// Plain constants rather than `components.parameters` / `components.responses`
// entries with `$ref`s: a `$ref` would change what /api/v1/docs.json serves, and
// this file's output IS the published contract. The existing
// `components.responses` entries are referenced from here for the same reason
// they always were — they were already `$ref`s in the served document.

/** The document id, as every `/documents/{id}` route declares it. */
const DOCUMENT_ID_PARAM = {
  name: 'id',
  in: 'path',
  required: true,
  schema: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c0' },
};

/** The staging-transfer id, as every `/documents/uploads/{id}` route declares it. */
const UPLOAD_ID_PARAM = { name: 'id', in: 'path', required: true, schema: { type: 'string' } };

/**
 * The `page` and `limit` query parameters, at whichever ceiling the endpoint sets.
 *
 * `page` is identical everywhere and `limit` never is, which is why this takes the
 * two numbers rather than being two constants: written out twice, the pair became
 * a clone of itself the moment the second one existed.
 */
const pageParams = (maxLimit: number, defaultLimit: number): Record<string, unknown>[] => [
  { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
  {
    name: 'limit',
    in: 'query',
    schema: { type: 'integer', minimum: 1, maximum: maxLimit, default: defaultLimit },
  },
];

/**
 * `page` and `limit` as the four ITEM lists declare them — documents, trashed
 * documents, vault items, trashed vault items.
 *
 * Separate from `LOG_PAGE_PARAMS` below because the two ceilings are different
 * decisions rather than one number written twice: an item list is what a client
 * pages through to render a vault, while a log is read a screenful at a time.
 * `paginationSchema` in `@hvault/shared` is what actually enforces either.
 */
const LIST_PAGE_PARAMS = pageParams(200, 50);

/** `page` and `limit` as the two LOG lists declare them: a smaller page, capped lower. */
const LOG_PAGE_PARAMS = pageParams(100, 20);

/** `sortOrder`; the two list endpoints differ in their sort KEYS, never in the direction. */
const DOCUMENT_SORT_ORDER_PARAM = {
  name: 'sortOrder',
  in: 'query',
  schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
};

/** The one schema reference three document responses return. */
const DOCUMENT_RESPONSE_REF = { $ref: '#/components/schemas/DocumentResponse' };

/**
 * The three answers EVERY document route can give: it is authenticated, it is
 * budgeted, and it needs object storage the operator may not have configured.
 *
 * Three operations declare a status of their own between the 404 and the 429 — a
 * 409 on the two that commit, 411/413/415 on the part route — and they simply
 * declare it after the spread. Integer-like keys serialise in ascending numeric
 * order whatever order they were written in, so the emitted document is the same
 * either way and no second, partial constant is needed for them.
 */
const DOCUMENT_BASE_ERRORS = {
  401: { $ref: '#/components/responses/Unauthorized' },
  429: { $ref: '#/components/responses/RateLimited' },
  503: { $ref: '#/components/responses/StorageUnavailable' },
};

/** ...and a 400 wherever `validate()` stands in front of the handler. */
const DOCUMENT_INPUT_ERRORS = {
  ...DOCUMENT_BASE_ERRORS,
  400: { $ref: '#/components/responses/ValidationError' },
};

/** ...and a 404 wherever the route names one row, which a foreign id also earns. */
const DOCUMENT_ITEM_ERRORS = {
  ...DOCUMENT_INPUT_ERRORS,
  404: { $ref: '#/components/responses/NotFound' },
};

/** ...and a 403 wherever the route changes state and therefore carries the CSRF check. */
const DOCUMENT_ITEM_WRITE_ERRORS = {
  ...DOCUMENT_ITEM_ERRORS,
  403: { $ref: '#/components/responses/Forbidden' },
};

/** The CSRF-checked write that names no row: emptying the trash. */
const DOCUMENT_BULK_WRITE_ERRORS = {
  ...DOCUMENT_BASE_ERRORS,
  403: { $ref: '#/components/responses/Forbidden' },
};

/**
 * The standard `{ success, data }` envelope, as a response object.
 *
 * `extraProperties` is spread AFTER `data`, which is where the two responses
 * that carry a `message` already put it.
 */
const jsonEnvelope = (
  description: string,
  data: Record<string, unknown>,
  extraProperties: Record<string, unknown> = {},
): Record<string, unknown> => ({
  description,
  content: {
    'application/json': {
      schema: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          data,
          ...extraProperties,
        },
      },
    },
  },
});

/** The paginated form of the same envelope, for every list endpoint in this document. */
const pageEnvelope = (description: string, itemsRef: string): Record<string, unknown> =>
  jsonEnvelope(
    description,
    { type: 'array', items: { $ref: itemsRef } },
    { pagination: { $ref: '#/components/schemas/Pagination' } },
  );

/**
 * OpenAPI 3.0.3 specification for the H-Vault REST API.
 *
 * This spec documents all public and authenticated endpoints, request/response
 * schemas, authentication mechanisms, and rate limiting tiers.
 *
 * The version is read from the shared APP_VERSION constant (injected from the
 * root package.json at build time), never copied here as a literal: a hardcoded
 * string silently drifts from the released version on the first bump nobody
 * remembers to mirror, and a published API document that lies about its own
 * version is worse than one that has none.
 */
export const swaggerSpec: JsonObject = {
  openapi: '3.0.3',
  info: {
    title: 'H-Vault API',
    version: APP_VERSION,
    description:
      'Zero-knowledge password manager, secret store, and encrypted note-taking API. All vault data is encrypted client-side with AES-256-GCM before reaching the server — the server never sees plaintext user data.',
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
  },
  servers: [
    {
      url: '/api/v1',
      description: 'API v1',
    },
  ],
  tags: [
    { name: 'Health', description: 'Health check endpoint' },
    { name: 'Auth', description: 'Authentication and account management' },
    { name: 'Vault', description: 'Encrypted vault item CRUD operations' },
    { name: 'Folders', description: 'Folder management for organizing vault items' },
    { name: 'User', description: 'User profile, settings, 2FA, and session management' },
    { name: 'Tools', description: 'Password generation, breach checking, import/export' },
    { name: 'Backup', description: 'Encrypted backup management' },
    {
      name: 'Documents',
      description:
        'Encrypted document store. Present on every server; usable only where the operator has configured object storage, which GET /config advertises.',
    },
  ],

  // ---------------------------------------------------------------------------
  // Security schemes
  // ---------------------------------------------------------------------------
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          'Short-lived JWT access token (default 5 min lifetime, configurable via JWT_ACCESS_EXPIRY). Obtain via POST /auth/login.',
      },
      csrfToken: {
        type: 'apiKey',
        in: 'header',
        name: 'x-csrf-token',
        description:
          'HMAC-SHA256 double-submit CSRF token. Fetch from GET /csrf-token before state-changing requests.',
      },
    },

    // -----------------------------------------------------------------------
    // Reusable schemas
    // -----------------------------------------------------------------------
    schemas: {
      // -- Generic response wrappers --
      SuccessResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string' },
        },
        required: ['success'],
      },
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          error: {
            type: 'object',
            properties: {
              code: { type: 'string', example: 'VALIDATION_ERROR' },
              message: { type: 'string', example: 'Invalid request body' },
            },
            required: ['code', 'message'],
          },
        },
        required: ['success', 'error'],
      },
      Pagination: {
        type: 'object',
        properties: {
          page: { type: 'integer', example: 1 },
          limit: { type: 'integer', example: 50 },
          total: { type: 'integer', example: 120 },
          totalPages: { type: 'integer', example: 3 },
        },
        required: ['page', 'limit', 'total', 'totalPages'],
      },

      // -- Device info (shared) --
      DeviceInfo: {
        type: 'object',
        properties: {
          userAgent: { type: 'string', maxLength: 512 },
          fingerprint: { type: 'string', maxLength: 128 },
        },
      },

      // -- Auth schemas --
      RegisterRequest: {
        type: 'object',
        required: [
          'email',
          'authHash',
          'encryptedVaultKey',
          'vaultKeyIv',
          'vaultKeyTag',
          'kdfIterations',
          'kdfAlgorithm',
        ],
        properties: {
          email: { type: 'string', format: 'email', maxLength: 254 },
          authHash: { type: 'string', minLength: 1, maxLength: 100 },
          encryptedVaultKey: { type: 'string', minLength: 1, maxLength: 200 },
          vaultKeyIv: { type: 'string', minLength: 1, maxLength: 24 },
          vaultKeyTag: { type: 'string', minLength: 1, maxLength: 32 },
          kdfIterations: { type: 'integer', minimum: 100000 },
          kdfAlgorithm: { type: 'string', enum: ['PBKDF2-SHA256'] },
          encryptionVersion: { type: 'integer', default: 1 },
        },
      },
      LoginRequest: {
        type: 'object',
        required: ['email', 'authHash'],
        properties: {
          email: { type: 'string', format: 'email', maxLength: 254 },
          authHash: { type: 'string', minLength: 1, maxLength: 100 },
          rememberMe: {
            type: 'boolean',
            default: false,
            description:
              'Opt-in "remember me on this device". Extends the refresh-token horizon to the remember lifetime and, for a 2FA account, lets this device skip the 2FA step on later logins until the trust grant expires. Carried into the signed 2FA temp token, so it cannot be tampered with at the 2FA step. The master password is still always required to decrypt the vault.',
          },
          deviceInfo: { $ref: '#/components/schemas/DeviceInfo' },
        },
      },
      LoginSuccessResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          data: {
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              encryptedVaultKey: { type: 'string' },
              vaultKeyIv: { type: 'string' },
              vaultKeyTag: { type: 'string' },
              kdfIterations: { type: 'integer' },
              kdfAlgorithm: { type: 'string' },
            },
          },
        },
      },
      Login2faRequiredResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          data: {
            type: 'object',
            properties: {
              twoFactorRequired: { type: 'boolean', example: true },
              tempToken: { type: 'string' },
            },
          },
        },
      },
      Login2faRequest: {
        type: 'object',
        required: ['tempToken', 'code'],
        properties: {
          tempToken: { type: 'string', minLength: 1 },
          code: { type: 'string', minLength: 6, maxLength: 16 },
          deviceInfo: { $ref: '#/components/schemas/DeviceInfo' },
        },
      },
      VerifyEmailRequest: {
        type: 'object',
        required: ['token'],
        properties: {
          token: { type: 'string', minLength: 1 },
        },
      },
      ResendVerificationRequest: {
        type: 'object',
        required: ['email'],
        properties: {
          email: { type: 'string', format: 'email', maxLength: 254 },
        },
      },
      ForgotPasswordRequest: {
        type: 'object',
        required: ['email'],
        properties: {
          email: { type: 'string', format: 'email', maxLength: 254 },
        },
      },
      ResetPasswordRequest: {
        type: 'object',
        required: [
          'token',
          'newAuthHash',
          'newEncryptedVaultKey',
          'newVaultKeyIv',
          'newVaultKeyTag',
        ],
        properties: {
          token: { type: 'string', minLength: 1 },
          newAuthHash: { type: 'string', minLength: 1, maxLength: 100 },
          newEncryptedVaultKey: { type: 'string', minLength: 1, maxLength: 200 },
          newVaultKeyIv: { type: 'string', minLength: 1, maxLength: 24 },
          newVaultKeyTag: { type: 'string', minLength: 1, maxLength: 32 },
        },
      },
      UnlockAccountRequest: {
        type: 'object',
        required: ['token'],
        properties: {
          token: { type: 'string', minLength: 1 },
        },
      },

      // -- Vault item schemas --
      VaultItemResponse: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          userId: { type: 'string' },
          itemType: { type: 'string', enum: ['login', 'secret', 'note', 'card', 'identity'] },
          folderId: { type: 'string', nullable: true },
          tags: { type: 'array', items: { type: 'string' } },
          favorite: { type: 'boolean' },
          encryptedData: { type: 'string' },
          dataIv: { type: 'string' },
          dataTag: { type: 'string' },
          encryptedName: { type: 'string' },
          nameIv: { type: 'string' },
          nameTag: { type: 'string' },
          searchHash: { type: 'string', nullable: true },
          passwordHistory: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                encryptedPassword: { type: 'string' },
                iv: { type: 'string' },
                tag: { type: 'string' },
                changedAt: { type: 'string', format: 'date-time' },
              },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
          deletedAt: { type: 'string', format: 'date-time', nullable: true },
        },
      },
      CreateVaultItemRequest: {
        type: 'object',
        required: [
          'itemType',
          'encryptedData',
          'dataIv',
          'dataTag',
          'encryptedName',
          'nameIv',
          'nameTag',
        ],
        properties: {
          itemType: { type: 'string', enum: ['login', 'secret', 'note', 'card', 'identity'] },
          folderId: { type: 'string', description: 'MongoDB ObjectId of the target folder' },
          tags: { type: 'array', items: { type: 'string', maxLength: 50 }, maxItems: 20 },
          favorite: { type: 'boolean', default: false },
          encryptedData: { type: 'string', minLength: 1, maxLength: 500000 },
          dataIv: { type: 'string', minLength: 1, maxLength: 24 },
          dataTag: { type: 'string', minLength: 1, maxLength: 32 },
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          searchHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
        },
      },
      UpdateVaultItemRequest: {
        type: 'object',
        properties: {
          folderId: { type: 'string', nullable: true },
          tags: { type: 'array', items: { type: 'string', maxLength: 50 }, maxItems: 20 },
          favorite: { type: 'boolean' },
          encryptedData: { type: 'string', minLength: 1, maxLength: 500000 },
          dataIv: { type: 'string', minLength: 1, maxLength: 24 },
          dataTag: { type: 'string', minLength: 1, maxLength: 32 },
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          searchHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
          passwordHistory: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                encryptedPassword: { type: 'string' },
                iv: { type: 'string' },
                tag: { type: 'string' },
                changedAt: { type: 'string', format: 'date-time' },
              },
            },
            maxItems: 10,
          },
        },
      },
      BulkDeleteRequest: {
        type: 'object',
        required: ['ids'],
        properties: {
          ids: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 100 },
        },
      },
      BulkMoveRequest: {
        type: 'object',
        required: ['ids', 'folderId'],
        properties: {
          ids: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 100 },
          folderId: { type: 'string', nullable: true },
        },
      },

      BulkReEncryptRequest: {
        type: 'object',
        required: ['authHash', 'items', 'newEncryptedVaultKey', 'newVaultKeyIv', 'newVaultKeyTag'],
        properties: {
          authHash: {
            type: 'string',
            minLength: 1,
            maxLength: 100,
            description: 'Current auth hash for verification',
          },
          items: {
            type: 'array',
            items: {
              type: 'object',
              required: [
                'id',
                'encryptedName',
                'nameIv',
                'nameTag',
                'encryptedData',
                'dataIv',
                'dataTag',
              ],
              properties: {
                id: { type: 'string' },
                encryptedName: { type: 'string' },
                nameIv: { type: 'string' },
                nameTag: { type: 'string' },
                encryptedData: { type: 'string' },
                dataIv: { type: 'string' },
                dataTag: { type: 'string' },
                searchHash: { type: 'string' },
              },
            },
            maxItems: 10000,
          },
          folders: {
            type: 'array',
            description:
              'Every folder in the account, with its name re-encrypted under the new vault key.',
            items: {
              type: 'object',
              required: ['id', 'encryptedName', 'nameIv', 'nameTag'],
              properties: {
                id: { type: 'string' },
                encryptedName: { type: 'string' },
                nameIv: { type: 'string' },
                nameTag: { type: 'string' },
              },
            },
            maxItems: 1000,
          },
          documents: {
            type: 'array',
            description:
              'Every document in the account, active and trashed alike, with its document key (DEK) rewrapped under the new vault key. Only the wrapped key travels: no stored object is read or written by a rotation, which is why rotating an account holding gigabytes is possible at all. Omit the field entirely on a server with no storage configured.',
            items: {
              type: 'object',
              required: ['id', 'encryptedDek', 'dekIv', 'dekTag'],
              properties: {
                id: { type: 'string' },
                encryptedDek: { type: 'string', minLength: 1, maxLength: 200 },
                dekIv: { type: 'string', minLength: 1, maxLength: 24 },
                dekTag: { type: 'string', minLength: 1, maxLength: 32 },
              },
            },
            maxItems: 5000,
          },
          newEncryptedVaultKey: { type: 'string', minLength: 1, maxLength: 200 },
          newVaultKeyIv: { type: 'string', minLength: 1, maxLength: 24 },
          newVaultKeyTag: { type: 'string', minLength: 1, maxLength: 32 },
        },
      },

      // -- Folder schemas --
      FolderResponse: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          userId: { type: 'string' },
          encryptedName: { type: 'string' },
          nameIv: { type: 'string' },
          nameTag: { type: 'string' },
          parentId: { type: 'string', nullable: true },
          icon: { type: 'string', nullable: true },
          color: { type: 'string', nullable: true },
          sortOrder: { type: 'integer' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      CreateFolderRequest: {
        type: 'object',
        required: ['encryptedName', 'nameIv', 'nameTag'],
        properties: {
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          parentId: { type: 'string' },
          icon: { type: 'string', maxLength: 50 },
          color: { type: 'string', maxLength: 20 },
          sortOrder: { type: 'integer', default: 0 },
        },
      },
      UpdateFolderRequest: {
        type: 'object',
        properties: {
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          parentId: { type: 'string', nullable: true },
          icon: { type: 'string', maxLength: 50 },
          color: { type: 'string', maxLength: 20 },
          sortOrder: { type: 'integer' },
        },
      },
      ReorderFolderRequest: {
        type: 'object',
        required: ['sortOrder'],
        properties: {
          sortOrder: { type: 'integer', minimum: 0 },
        },
      },

      // -- User schemas --
      UserProfile: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          email: { type: 'string', format: 'email' },
          emailVerified: { type: 'boolean' },
          twoFactorEnabled: { type: 'boolean' },
          kdfIterations: { type: 'integer' },
          kdfAlgorithm: { type: 'string' },
          encryptionVersion: { type: 'integer' },
          settings: { $ref: '#/components/schemas/UserSettings' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      UserSettings: {
        type: 'object',
        properties: {
          autoLockTimeout: { type: 'integer', description: 'Idle minutes before lock (1-1440)' },
          lockOnHidden: {
            type: 'boolean',
            description: 'Also lock once the tab has been hidden for lockOnHiddenDelay minutes',
          },
          lockOnHiddenDelay: {
            type: 'integer',
            description: 'Minutes hidden before locking, when lockOnHidden is true (1-1440)',
          },
          clipboardClearTimeout: { type: 'integer', description: 'Seconds (5-300)' },
          defaultPasswordLength: { type: 'integer', description: '8-128' },
          defaultPasswordOptions: {
            type: 'object',
            properties: {
              length: { type: 'integer' },
              uppercase: { type: 'boolean' },
              lowercase: { type: 'boolean' },
              numbers: { type: 'boolean' },
              symbols: { type: 'boolean' },
              excludeAmbiguous: { type: 'boolean' },
              minNumbers: { type: 'integer' },
              minSymbols: { type: 'integer' },
            },
          },
          theme: { type: 'string', enum: ['light', 'dark', 'system'] },
          language: { type: 'string' },
        },
      },
      ChangePasswordRequest: {
        type: 'object',
        required: [
          'currentAuthHash',
          'newAuthHash',
          'newEncryptedVaultKey',
          'newVaultKeyIv',
          'newVaultKeyTag',
        ],
        properties: {
          currentAuthHash: { type: 'string', minLength: 1, maxLength: 100 },
          newAuthHash: { type: 'string', minLength: 1, maxLength: 100 },
          newEncryptedVaultKey: { type: 'string', minLength: 1, maxLength: 200 },
          newVaultKeyIv: { type: 'string', minLength: 1, maxLength: 24 },
          newVaultKeyTag: { type: 'string', minLength: 1, maxLength: 32 },
        },
      },
      Setup2faRequest: {
        type: 'object',
        required: ['password'],
        properties: {
          password: { type: 'string', minLength: 1, maxLength: 500 },
        },
      },
      Verify2faRequest: {
        type: 'object',
        required: ['code'],
        properties: {
          code: { type: 'string', minLength: 6, maxLength: 6 },
        },
      },
      Disable2faRequest: {
        type: 'object',
        required: ['code'],
        properties: {
          code: { type: 'string', minLength: 6, maxLength: 16 },
        },
      },
      SessionInfo: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          deviceInfo: {
            type: 'object',
            properties: {
              userAgent: { type: 'string' },
              ip: { type: 'string' },
              fingerprint: { type: 'string' },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          expiresAt: { type: 'string', format: 'date-time' },
          current: { type: 'boolean' },
        },
      },
      TrustedDeviceInfo: {
        type: 'object',
        description:
          'A device allowed to skip the 2FA step at login. The server-only SHA-256 token hash is never included.',
        properties: {
          _id: { type: 'string' },
          deviceInfo: {
            type: 'object',
            properties: {
              userAgent: { type: 'string' },
              ip: { type: 'string' },
              fingerprint: { type: 'string' },
            },
          },
          createdAt: { type: 'string', format: 'date-time' },
          lastUsedAt: { type: 'string', format: 'date-time' },
          expiresAt: { type: 'string', format: 'date-time' },
        },
      },
      AuditLogEntry: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          action: { type: 'string' },
          metadata: { type: 'object', additionalProperties: true },
          ipAddress: { type: 'string' },
          userAgent: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },

      // -- Tools schemas --
      CheckBreachRequest: {
        type: 'object',
        required: ['hashPrefix'],
        properties: {
          hashPrefix: {
            type: 'string',
            minLength: 5,
            maxLength: 5,
            description: 'First 5 hex chars of SHA-1 hash (k-anonymity)',
          },
        },
      },
      CheckBreachBatchRequest: {
        type: 'object',
        required: ['hashPrefixes'],
        properties: {
          hashPrefixes: {
            type: 'array',
            minItems: 1,
            maxItems: HIBP_BATCH_MAX_PREFIXES,
            items: {
              type: 'string',
              minLength: 5,
              maxLength: 5,
            },
            description:
              'Deduplicated 5-char SHA-1 prefixes of the caller’s unique passwords (k-anonymity). Only prefixes are sent; the full hash never leaves the client.',
          },
        },
      },
      ImportPasswordHistoryEntry: {
        type: 'object',
        required: ['encryptedPassword', 'iv', 'tag', 'changedAt'],
        properties: {
          encryptedPassword: { type: 'string', minLength: 1, maxLength: 5000 },
          iv: { type: 'string', minLength: 1, maxLength: 24 },
          tag: { type: 'string', minLength: 1, maxLength: 32 },
          changedAt: { type: 'string', format: 'date-time' },
        },
      },
      ImportInsertItem: {
        type: 'object',
        required: [
          'itemType',
          'encryptedName',
          'nameIv',
          'nameTag',
          'encryptedData',
          'dataIv',
          'dataTag',
          'searchHash',
        ],
        properties: {
          itemType: {
            type: 'string',
            enum: ['login', 'card', 'identity', 'note', 'secret'],
          },
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          encryptedData: { type: 'string', minLength: 1, maxLength: 500000 },
          dataIv: { type: 'string', minLength: 1, maxLength: 24 },
          dataTag: { type: 'string', minLength: 1, maxLength: 32 },
          searchHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
          tags: {
            type: 'array',
            items: { type: 'string', minLength: 1, maxLength: 50 },
            maxItems: 20,
            default: [],
            description:
              'Each tag is trimmed before its length is checked, so a whitespace-only tag is rejected.',
          },
          favorite: { type: 'boolean', default: false },
          folderId: {
            type: 'string',
            pattern: '^[0-9a-fA-F]{24}$',
            description: 'ObjectId; stripped when not owned by you.',
          },
          passwordHistory: {
            type: 'array',
            maxItems: 10,
            items: { $ref: '#/components/schemas/ImportPasswordHistoryEntry' },
            description:
              "Preserves an item's previous passwords when it is recreated from a native H-Vault export.",
          },
        },
      },
      ImportUpdateItem: {
        type: 'object',
        required: [
          'id',
          'encryptedName',
          'nameIv',
          'nameTag',
          'encryptedData',
          'dataIv',
          'dataTag',
          'searchHash',
        ],
        properties: {
          id: {
            type: 'string',
            pattern: '^[0-9a-fA-F]{24}$',
            description: 'ObjectId of the LIVE item of yours this operation replaces.',
          },
          encryptedName: { type: 'string', minLength: 1, maxLength: 1000 },
          nameIv: { type: 'string', minLength: 1, maxLength: 24 },
          nameTag: { type: 'string', minLength: 1, maxLength: 32 },
          encryptedData: { type: 'string', minLength: 1, maxLength: 500000 },
          dataIv: { type: 'string', minLength: 1, maxLength: 24 },
          dataTag: { type: 'string', minLength: 1, maxLength: 32 },
          searchHash: {
            type: 'string',
            pattern: '^[a-f0-9]{64}$',
            description:
              'Recomputed by the client: an update replaces the encrypted name, so the stored hash must be refreshed alongside it.',
          },
          passwordHistory: {
            type: 'array',
            maxItems: 10,
            items: { $ref: '#/components/schemas/ImportPasswordHistoryEntry' },
            description: "The replaced password, prepended to the item's history.",
          },
        },
        description:
          'Content only: an update deliberately cannot carry tags, favorite, folderId or itemType, so an import can never reorganize or retype an existing vault.',
      },
      ImportRequest: {
        type: 'object',
        required: ['format', 'operations'],
        properties: {
          format: {
            type: 'string',
            enum: [
              'bitwarden',
              'lastpass',
              'keepass',
              'chrome',
              'firefox',
              'onepassword',
              'csv',
              'json',
            ],
            description:
              'Source the items originated from (audit metadata only). All parsing and encryption happen client-side; the server receives already-encrypted native items regardless of format.',
          },
          operations: {
            type: 'object',
            description:
              'The explicit work to perform. `inserts.length + updates.length` must be between 1 and 10,000; a large import is split into several sequential requests by the client, which cannot change the outcome.',
            properties: {
              inserts: {
                type: 'array',
                default: [],
                items: { $ref: '#/components/schemas/ImportInsertItem' },
              },
              updates: {
                type: 'array',
                default: [],
                items: { $ref: '#/components/schemas/ImportUpdateItem' },
              },
            },
          },
          conflictStrategy: {
            type: 'string',
            enum: ['skip', 'overwrite', 'keep_both'],
            default: 'skip',
            description:
              'Audit metadata only. The server performs NO matching: the match key for a login is its site and username, both of which live inside the encrypted blob, so conflict resolution happens client-side and arrives here already decided.',
          },
        },
      },

      // -- Backup schemas --
      BackupSetupRequest: {
        type: 'object',
        required: ['encryptedBWK', 'bwkIv', 'bwkTag', 'bwkSalt'],
        properties: {
          encryptedBWK: { type: 'string', minLength: 1, maxLength: 500 },
          bwkIv: { type: 'string', minLength: 1, maxLength: 24 },
          bwkTag: { type: 'string', minLength: 1, maxLength: 32 },
          bwkSalt: { type: 'string', minLength: 1, maxLength: 64 },
        },
      },
      BackupSettingsRequest: {
        type: 'object',
        properties: {
          enabled: { type: 'boolean' },
          scheduleHour: { type: 'integer', minimum: 0, maximum: 23 },
          backupEmails: {
            type: 'array',
            items: { type: 'string', format: 'email', maxLength: 254 },
            maxItems: 10,
          },
        },
      },
      BackupChangePasswordRequest: {
        type: 'object',
        required: ['newEncryptedBWK', 'newBwkIv', 'newBwkTag', 'newBwkSalt'],
        properties: {
          newEncryptedBWK: { type: 'string', minLength: 1, maxLength: 500 },
          newBwkIv: { type: 'string', minLength: 1, maxLength: 24 },
          newBwkTag: { type: 'string', minLength: 1, maxLength: 32 },
          newBwkSalt: { type: 'string', minLength: 1, maxLength: 64 },
        },
      },
      RestoreBackupRequest: {
        type: 'object',
        required: ['data'],
        properties: {
          conflictStrategy: {
            type: 'string',
            enum: ['skip', 'overwrite', 'keep_both'],
            default: 'skip',
          },
          data: {
            type: 'string',
            minLength: 1,
            maxLength: 26214400,
            description: 'Backup file contents (max 25 MB)',
          },
        },
      },
      BackupLogEntry: {
        type: 'object',
        properties: {
          _id: { type: 'string' },
          status: { type: 'string', enum: ['success', 'failed'] },
          fileSizeBytes: { type: 'integer' },
          itemCount: { type: 'integer' },
          errorMessage: { type: 'string' },
          sentTo: { type: 'array', items: { type: 'string' } },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },

      // -- Document store --
      //
      // The upload shapes, plus the committed document row — which first crosses
      // the wire from the completion endpoint, so it is documented here rather
      // than waiting for the read endpoints that also return it.
      InitDocumentUploadRequest: {
        type: 'object',
        description:
          'Opens a transfer. The document key (DEK) is already wrapped under a key derived from the vault key and bound to the upload id; the salt and nonce prefix are the plaintext framing parameters of the stored container. chunkPlaintextBytes, vaultKeyVersion and the storage key are assigned by the server and are rejected here.',
        required: [
          'encryptedDek',
          'dekIv',
          'dekTag',
          'streamSalt',
          'noncePrefix',
          'declaredPlaintextBytes',
          'declaredChunkCount',
        ],
        properties: {
          encryptedDek: {
            type: 'string',
            maxLength: 200,
            description: 'The 256-bit document key, AES-256-GCM wrapped, base64.',
            example: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
          },
          dekIv: { type: 'string', maxLength: 24, example: 'ZGVrLWl2LWJhc2U2NA==' },
          dekTag: { type: 'string', maxLength: 32, example: 'ZGVrLXRhZy1iYXNlNjQ=' },
          streamSalt: {
            type: 'string',
            description:
              'HKDF salt for the stream and metadata keys: 32 random bytes, padded base64.',
            example: 'c3RyZWFtLXNhbHQtZXhhY3RseS0zMi1ieXRlcy0hIQ==',
          },
          noncePrefix: {
            type: 'string',
            description:
              'First 7 bytes of every segment nonce, padded base64. The remaining 5 bytes are the segment index and the last-segment flag.',
            example: 'AQIDBAUGBw==',
          },
          declaredPlaintextBytes: {
            type: 'integer',
            minimum: 0,
            description:
              'Plaintext size the client intends to send. Refused above the operator size cap.',
            example: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
          },
          declaredChunkCount: {
            type: 'integer',
            minimum: 1,
            description:
              'Must equal ceil(declaredPlaintextBytes / the server chunk size), and at least 1 — a zero-byte document is still one segment.',
            example: 2,
          },
          folderId: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c0' },
        },
      },
      InitDocumentUploadResponse: {
        type: 'object',
        required: ['uploadId', 'vaultKeyVersion', 'chunkPlaintextBytes'],
        properties: {
          uploadId: {
            type: 'string',
            description:
              'The FUTURE document id, minted here because it is bound into the key derivation before the first byte is sealed.',
            example: '66c0f1a2b3c4d5e6f7a8b9c0',
          },
          vaultKeyVersion: {
            type: 'integer',
            minimum: 0,
            description:
              "The caller's vault-key version at init. Completion is refused with 409 when it no longer matches, which is what stops a rotation mid-transfer from committing a key nothing can unwrap.",
            example: 0,
          },
          chunkPlaintextBytes: {
            type: 'integer',
            description:
              'Plaintext one segment holds. Server-chosen; the client frames its segments to it.',
            example: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          },
        },
      },
      DocumentUploadResponse: {
        type: 'object',
        description:
          'A transfer in progress. It deliberately carries no wrapped key, no storage key and no engine handle: the client holds the document key in memory for the life of the upload.',
        required: [
          '_id',
          'streamSalt',
          'noncePrefix',
          'declaredPlaintextBytes',
          'declaredChunkCount',
          'chunkPlaintextBytes',
          'vaultKeyVersion',
          'parts',
          'receivedBytes',
          'createdAt',
          'expiresAt',
        ],
        properties: {
          _id: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c0' },
          folderId: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c1' },
          streamSalt: { type: 'string', example: 'c3RyZWFtLXNhbHQtZXhhY3RseS0zMi1ieXRlcy0hIQ==' },
          noncePrefix: { type: 'string', example: 'AQIDBAUGBw==' },
          declaredPlaintextBytes: { type: 'integer', example: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1 },
          declaredChunkCount: { type: 'integer', example: 2 },
          chunkPlaintextBytes: { type: 'integer', example: DOCUMENT_PLAINTEXT_CHUNK_BYTES },
          vaultKeyVersion: { type: 'integer', example: 0 },
          parts: {
            type: 'array',
            description:
              'The parts the server already holds, so a resumed transfer sends only what is missing.',
            items: {
              type: 'object',
              required: ['partNumber', 'bytes'],
              properties: {
                partNumber: { type: 'integer', minimum: 1, example: 1 },
                bytes: { type: 'integer', example: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
              },
            },
          },
          receivedBytes: { type: 'integer', example: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
          createdAt: { type: 'string', format: 'date-time' },
          expiresAt: {
            type: 'string',
            format: 'date-time',
            description:
              'Set once at init and never slid forward. Past it the transfer can no longer accept a part, and the staging row is removed by a TTL index — which deletes the row ONLY, not the stored parts.',
          },
        },
      },

      CompleteDocumentUploadRequest: {
        type: 'object',
        description:
          'Turns a finished transfer into a document. The wrapped document key is sent a SECOND time here, and that is what makes a mid-transfer vault-key rotation cost one request instead of the whole file: on a 409 the browser rewraps the key it still holds and retries this request alone. The sizes of the document are NOT in this body — the server derives them from the parts the storage engine reports and refuses anything the client claims about them.',
        required: [
          'encryptedMeta',
          'metaIv',
          'metaTag',
          'encryptedDek',
          'dekIv',
          'dekTag',
          'vaultKeyVersion',
        ],
        properties: {
          encryptedMeta: {
            type: 'string',
            maxLength: MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
            description:
              'The sealed metadata blob: filename, MIME type, extension, size, content digest, tags and note, encrypted under a key derived from the document key. The server never sees any of it.',
            example: 'ZG9jdW1lbnQtbWV0YWRhdGEtY2lwaGVydGV4dA==',
          },
          metaIv: { type: 'string', maxLength: 24, example: 'bWV0YS1pdi1iYXNlNjQ=' },
          metaTag: { type: 'string', maxLength: 32, example: 'bWV0YS10YWctYmFzZTY0' },
          encryptedDek: {
            type: 'string',
            maxLength: 200,
            description:
              'The wrapped document key, under the vault key named by vaultKeyVersion. Taken from HERE rather than from the copy recorded at init.',
            example: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
          },
          dekIv: { type: 'string', maxLength: 24, example: 'ZGVrLWl2LWJhc2U2NA==' },
          dekTag: { type: 'string', maxLength: 32, example: 'ZGVrLXRhZy1iYXNlNjQ=' },
          vaultKeyVersion: {
            type: 'integer',
            minimum: 0,
            description:
              "The vault-key version the wrapped key above was produced under. Refused with 409 when it is no longer the account's current version.",
            example: 0,
          },
        },
      },
      UpdateDocumentRequest: {
        type: 'object',
        description:
          "Everything a stored document may be changed to. CONTENT IS IMMUTABLE AFTER UPLOAD: a segment is never rewritten, which is what guarantees a nonce is never reused under the stream key, so this body cannot reach a framing field, the wrapped document key or the storage key — replacing a document's bytes means uploading a new document. The three metadata fields move together or not at all, because they are one seal. Every field is optional and a body naming none of them is answered with the row as it stands.",
        properties: {
          encryptedMeta: {
            type: 'string',
            maxLength: MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
            description:
              'The re-sealed metadata blob — a rename, a retag or an edited note. Sealed under a key derived from the document key, which a vault-key rotation does not change, which is why this endpoint is not refused during one.',
            example: 'cmVuYW1lZC1tZXRhZGF0YS1jaXBoZXJ0ZXh0',
          },
          metaIv: {
            type: 'string',
            maxLength: 24,
            description:
              'A FRESHLY RANDOM IV for every re-seal. The metadata key is fixed for a document’s whole life while the blob is mutable, so this is the one value in the design that must never repeat; the browser generates it and never accepts one from a caller.',
            example: 'bmV3LW1ldGEtaXYtYmFzZTY0',
          },
          metaTag: { type: 'string', maxLength: 32, example: 'bmV3LW1ldGEtdGFnLWJhc2U2NA==' },
          favorite: { type: 'boolean', example: true },
          folderId: {
            type: 'string',
            nullable: true,
            description:
              'An owned folder id, or null to remove the document from its folder. A folder belonging to another account is answered with 404, not 403, so folders cannot be enumerated.',
            example: '66c0f1a2b3c4d5e6f7a8b9c1',
          },
        },
      },
      DocumentResponse: {
        type: 'object',
        description:
          'A committed document. Everything the server can read about it is here; the filename, type, tags, note and content digest are inside encryptedMeta. The storage key and the owner are stripped from every response. The three sizes are derived server-side from the parts the storage engine reported and satisfy two identities the client re-checks: chunkCount is ceil(plaintextBytes / chunkPlaintextBytes) and at least 1, and ciphertextBytes is plaintextBytes plus one authentication tag per segment.',
        required: [
          '_id',
          'favorite',
          'encryptedDek',
          'dekIv',
          'dekTag',
          'streamSalt',
          'noncePrefix',
          'encryptedMeta',
          'metaIv',
          'metaTag',
          'chunkPlaintextBytes',
          'chunkCount',
          'ciphertextBytes',
          'plaintextBytes',
          'createdAt',
          'updatedAt',
        ],
        properties: {
          _id: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c0' },
          folderId: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c1' },
          favorite: { type: 'boolean', example: false },
          encryptedDek: { type: 'string', example: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0' },
          dekIv: { type: 'string', example: 'ZGVrLWl2LWJhc2U2NA==' },
          dekTag: { type: 'string', example: 'ZGVrLXRhZy1iYXNlNjQ=' },
          streamSalt: { type: 'string', example: 'c3RyZWFtLXNhbHQtZXhhY3RseS0zMi1ieXRlcy0hIQ==' },
          noncePrefix: { type: 'string', example: 'AQIDBAUGBw==' },
          encryptedMeta: { type: 'string', example: 'ZG9jdW1lbnQtbWV0YWRhdGEtY2lwaGVydGV4dA==' },
          metaIv: { type: 'string', example: 'bWV0YS1pdi1iYXNlNjQ=' },
          metaTag: { type: 'string', example: 'bWV0YS10YWctYmFzZTY0' },
          chunkPlaintextBytes: {
            type: 'integer',
            description:
              'Read from the ROW and never from the server constant, so changing that constant cannot re-frame a document that already exists.',
            example: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          },
          chunkCount: { type: 'integer', minimum: 1, example: 2 },
          ciphertextBytes: { type: 'integer', example: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 33 },
          plaintextBytes: { type: 'integer', example: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1 },
          purgePending: {
            type: 'boolean',
            description:
              'Present only between the object delete and the row delete of a permanent purge, so a crash between the two leaves a marker the collector finishes.',
          },
          deletedAt: { type: 'string', format: 'date-time' },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      DocumentUsageResponse: {
        type: 'object',
        description:
          'What this account has stored and what it may store. Trashed documents are counted in both measurements, because they still occupy their objects in the bucket and both caps are enforced that way; the UI says so rather than letting a user assume a deletion failed. The two limits are reported alongside the measurements because an operator can change either at a restart.',
        required: ['documentCount', 'usedBytes', 'quotaBytes', 'maxDocumentSizeBytes'],
        properties: {
          documentCount: { type: 'integer', minimum: 0, example: 42 },
          usedBytes: {
            type: 'integer',
            minimum: 0,
            description: 'Plaintext bytes, summed over every document including trashed ones.',
            example: 734003200,
          },
          quotaBytes: {
            type: 'integer',
            minimum: 1,
            description: 'DOCUMENT_STORAGE_QUOTA_MB_PER_USER, in bytes.',
            example: 2147483648,
          },
          maxDocumentSizeBytes: {
            type: 'integer',
            minimum: 1,
            description: 'MAX_DOCUMENT_SIZE_MB, in bytes.',
            example: 104857600,
          },
        },
      },

      // -- Health --
      HealthResponse: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['ok', 'error'] },
          uptime: { type: 'number', description: 'Seconds' },
          version: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
          database: { type: 'string', enum: ['connected', 'disconnected'] },
        },
      },
    },

    // -----------------------------------------------------------------------
    // Reusable response references
    // -----------------------------------------------------------------------
    responses: {
      Unauthorized: {
        description: 'Missing or invalid authentication token',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      Forbidden: {
        description: 'CSRF token invalid or insufficient permissions',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      NotFound: {
        description: 'Requested resource not found',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      RateLimited: {
        description: 'Rate limit exceeded',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      ValidationError: {
        description: 'Request body failed schema validation',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
      Acknowledged: {
        description: 'The operation succeeded and returns no payload beyond the acknowledgement',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/SuccessResponse' },
          },
        },
      },
      StorageUnavailable: {
        description:
          'The document store is not available on this deployment because no object storage is configured. In production the body is redacted to its status text, so a client determines availability from GET /config rather than from this response.',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/ErrorResponse' },
          },
        },
      },
    },
  },

  // ---------------------------------------------------------------------------
  // Paths
  // ---------------------------------------------------------------------------
  paths: {
    // -- Documents --
    //
    // Every route here sits behind `authenticate` AND a storage guard that answers
    // 503 where the operator has configured no object storage, so 503 is a
    // documented outcome of every one of them rather than an error condition.
    '/documents': {
      get: {
        operationId: 'listDocuments',
        tags: ['Documents'],
        summary: 'List documents',
        description:
          "The caller's own documents that are not in the trash, paginated. The server cannot sort by name — the name lives inside encryptedMeta and it never sees it — so the sort keys are the three columns it does hold, and the document id breaks ties so that skip/limit pagination has a total order and a row cannot slip across a page boundary between two requests.",
        security: [{ bearerAuth: [] }],
        parameters: [
          ...LIST_PAGE_PARAMS,
          {
            name: 'folderId',
            in: 'query',
            schema: { type: 'string', example: '66c0f1a2b3c4d5e6f7a8b9c1' },
          },
          { name: 'favorite', in: 'query', schema: { type: 'boolean', example: true } },
          {
            name: 'sortBy',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['createdAt', 'updatedAt', 'favorite'],
              default: 'updatedAt',
            },
          },
          DOCUMENT_SORT_ORDER_PARAM,
        ],
        responses: {
          200: pageEnvelope('Paginated documents', '#/components/schemas/DocumentResponse'),
          ...DOCUMENT_INPUT_ERRORS,
        },
      },
    },
    '/documents/trash': {
      get: {
        operationId: 'listDocumentTrash',
        tags: ['Documents'],
        summary: 'List trashed documents',
        description:
          'Documents this account has moved to the trash, paginated and sorted by deletion time by default. A trashed document still occupies its object in the bucket and still counts against the storage quota reported by GET /documents/usage, so recovering that space needs a permanent delete rather than a trash.',
        security: [{ bearerAuth: [] }],
        parameters: [
          ...LIST_PAGE_PARAMS,
          {
            name: 'sortBy',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['deletedAt', 'createdAt', 'updatedAt'],
              default: 'deletedAt',
            },
          },
          DOCUMENT_SORT_ORDER_PARAM,
        ],
        responses: {
          200: pageEnvelope('Paginated trashed documents', '#/components/schemas/DocumentResponse'),
          ...DOCUMENT_INPUT_ERRORS,
        },
      },
    },
    '/documents/usage': {
      get: {
        operationId: 'getDocumentUsage',
        tags: ['Documents'],
        summary: 'Storage usage and limits',
        description:
          'The document count and plaintext bytes this account holds, alongside the per-user quota and the per-document size cap the operator configured. Both measurements include trashed documents, because both caps are enforced that way and a usage figure smaller than the one an upload is refused against would be an explanation the user cannot see.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: jsonEnvelope('Usage and limits', {
            $ref: '#/components/schemas/DocumentUsageResponse',
          }),
          ...DOCUMENT_BASE_ERRORS,
        },
      },
    },
    '/documents/uploads': {
      get: {
        operationId: 'listDocumentUploads',
        tags: ['Documents'],
        summary: 'List transfers in progress',
        description:
          "The caller's own staging uploads, newest first, each with the parts the server already holds. Expired rows are included on purpose: they can no longer accept a part, and listing them is how a user finds one to cancel.",
        security: [{ bearerAuth: [] }],
        responses: {
          200: jsonEnvelope('Transfers in progress', {
            type: 'array',
            items: { $ref: '#/components/schemas/DocumentUploadResponse' },
          }),
          ...DOCUMENT_BASE_ERRORS,
        },
      },
      post: {
        operationId: 'initDocumentUpload',
        tags: ['Documents'],
        summary: 'Open a transfer',
        description:
          'Reserves an upload id, records the wrapped document key and the framing, and opens an engine-side multipart upload when more than one segment is declared. The id it returns is the future document id: the browser binds its key derivation to it before sealing the first byte, so it can never be reassigned without re-encrypting the file. Refused with 400 when the declared size exceeds the operator cap, the document count or concurrent-transfer cap is reached, or the storage quota would be exceeded, and with 409 while a vault-key rotation is running.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/InitDocumentUploadRequest' },
            },
          },
        },
        responses: {
          201: jsonEnvelope('Transfer opened', {
            $ref: '#/components/schemas/InitDocumentUploadResponse',
          }),
          ...DOCUMENT_ITEM_WRITE_ERRORS,
          409: {
            description: 'A vault-key rotation is in progress; retry when it finishes',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
        },
      },
    },
    '/documents/uploads/{id}': {
      get: {
        operationId: 'getDocumentUpload',
        tags: ['Documents'],
        summary: 'Get one transfer',
        description:
          'One staging upload with its part ledger, which is what makes a resume possible: the client compares the ledger with the segments it has sealed and sends only the missing ones. An id belonging to another account is indistinguishable from one that never existed.',
        security: [{ bearerAuth: [] }],
        parameters: [UPLOAD_ID_PARAM],
        responses: {
          200: jsonEnvelope('The transfer', {
            $ref: '#/components/schemas/DocumentUploadResponse',
          }),
          ...DOCUMENT_ITEM_ERRORS,
        },
      },
      delete: {
        operationId: 'abortDocumentUpload',
        tags: ['Documents'],
        summary: 'Cancel a transfer',
        description:
          'Aborts the engine-side multipart upload, then deletes the staging row — in that order, so a crash between the two leaves a row that still names the upload rather than an upload nothing names. No document is created and no committed document is affected.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [UPLOAD_ID_PARAM],
        responses: {
          200: { $ref: '#/components/responses/Acknowledged' },
          ...DOCUMENT_ITEM_WRITE_ERRORS,
        },
      },
    },

    '/documents/uploads/{id}/parts/{partNumber}': {
      put: {
        operationId: 'uploadDocumentPart',
        tags: ['Documents'],
        summary: 'Store one sealed segment',
        description:
          'Stores one part of a transfer. The body is the raw sealed segment as application/octet-stream, `Content-Length` is required (411 without it), and `x-hv-part-sha256` carries the SHA-256 the server recomputes over the bytes it received. Every part except the LAST must be exactly the ciphertext chunk size: the storage engine accepts a short middle part, and one would shift every later segment boundary and leave the document permanently undecryptable, so the server is what refuses it. Re-sending a part number replaces its ledger entry rather than adding a second one, which is what makes a retried part safe.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [
          UPLOAD_ID_PARAM,
          {
            name: 'partNumber',
            in: 'path',
            required: true,
            description: 'One-based, as S3 numbers parts; segment indices are zero-based.',
            schema: { type: 'integer', minimum: 1, example: 1 },
          },
          {
            name: 'x-hv-part-sha256',
            in: 'header',
            required: true,
            description: 'SHA-256 of the sealed segment, 64 lowercase hexadecimal characters.',
            schema: { type: 'string', pattern: '^[a-f0-9]{64}$' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/octet-stream': {
              schema: { type: 'string', format: 'binary' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('Part stored', {
            type: 'object',
            properties: {
              partNumber: { type: 'integer', example: 1 },
              bytes: { type: 'integer', example: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
              receivedBytes: {
                type: 'integer',
                description: 'The sum of every part stored so far.',
                example: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
              },
            },
          }),
          ...DOCUMENT_ITEM_WRITE_ERRORS,
          411: {
            description: 'The request declared no Content-Length',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          413: {
            description: 'The body is larger than one sealed segment',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          415: {
            description: 'The body was not sent as unencoded application/octet-stream',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
        },
      },
    },

    '/documents/uploads/{id}/complete': {
      post: {
        operationId: 'completeDocumentUpload',
        tags: ['Documents'],
        summary: 'Turn a finished transfer into a document',
        description:
          "Verifies every part against the storage engine's own ledger, DERIVES the document's chunk count and its ciphertext and plaintext sizes from that ledger rather than from this request, re-checks the storage quota against the bytes actually received, and commits the document row. Nothing the client says about the size of its own file is believed. Refused with 400 when a part is missing, when the engine and the server disagree about a part, or when the parts cannot frame a document (a final segment holding only its authentication tag is the case that looks valid and is not); with 409 while a vault-key rotation is running, when the wrapped key was produced under a superseded vault key, or when another completion of the same transfer is already in flight. A repeat completion returns the document the first one committed, so a client that retried after a timeout cannot tell whether its first attempt landed.",
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [UPLOAD_ID_PARAM],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CompleteDocumentUploadRequest' },
            },
          },
        },
        responses: {
          201: jsonEnvelope('The document, committed', DOCUMENT_RESPONSE_REF),
          ...DOCUMENT_ITEM_WRITE_ERRORS,
          409: {
            description:
              'The completion cannot proceed yet. A stale vaultKeyVersion carries the current one in `data`, so the client rewraps the document key it still holds and retries this request alone rather than re-sending the file; a rotation in progress or a completion already in flight carry no data and are retried unchanged.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: false },
                    message: { type: 'string' },
                    data: {
                      type: 'object',
                      description: 'Present only for a superseded vault key.',
                      properties: {
                        vaultKeyVersion: { type: 'integer', minimum: 0, example: 1 },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },

    '/documents/{id}': {
      get: {
        operationId: 'getDocument',
        tags: ['Documents'],
        summary: 'Get one document',
        description:
          'One document row: the wrapped document key, the plaintext framing parameters, the sealed metadata blob and the sizes. Trashed documents are returned too, and carry deletedAt, so the trash view can open one before restoring or purging it. An id belonging to another account is indistinguishable from one that never existed. Before decrypting anything a client should check this row against itself (the two size identities), and then check every framing field against the AUTHENTICATED copy inside the metadata blob — that second comparison is mandatory and is what a substituted salt or nonce prefix is caught by.',
        security: [{ bearerAuth: [] }],
        parameters: [DOCUMENT_ID_PARAM],
        responses: {
          200: jsonEnvelope('The document', DOCUMENT_RESPONSE_REF),
          ...DOCUMENT_ITEM_ERRORS,
        },
      },
      put: {
        operationId: 'updateDocument',
        tags: ['Documents'],
        summary: 'Update a document’s metadata and attributes',
        description:
          'Re-seals the metadata blob (a rename, a retag, an edited note) and sets the favorite flag and the folder. It cannot change a single byte of the stored content or of the framing that describes it, and it cannot touch the wrapped document key or the storage key: content is immutable after upload, so replacing bytes means uploading a new document. Sending folderId as null removes the document from its folder; the field is then ABSENT from the response rather than present and null. Unlike every other write that produces ciphertext, this endpoint is NOT refused while a vault-key rotation is running, because the metadata blob is sealed under a key derived from the document key and a rotation only rewraps that key.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [DOCUMENT_ID_PARAM],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UpdateDocumentRequest' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('The updated document', DOCUMENT_RESPONSE_REF),
          ...DOCUMENT_ITEM_WRITE_ERRORS,
        },
      },
      delete: {
        operationId: 'deleteDocument',
        tags: ['Documents'],
        summary: 'Move a document to the trash',
        description:
          'A soft delete: the deletion time is stamped on the row and nothing else happens. The stored object stays in the bucket, the row keeps its wrapped key, and the document still counts against both the document limit and the storage quota reported by GET /documents/usage — so the space comes back at DELETE /documents/{id}/permanent, or when the trash auto-purge reaches it, and the UI says so rather than letting a user assume the deletion failed.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [DOCUMENT_ID_PARAM],
        responses: {
          200: { $ref: '#/components/responses/Acknowledged' },
          ...DOCUMENT_ITEM_WRITE_ERRORS,
        },
      },
    },

    '/documents/{id}/restore': {
      post: {
        operationId: 'restoreDocument',
        tags: ['Documents'],
        summary: 'Restore a document from the trash',
        description:
          'Clears the deletion time and returns the restored row. Refused with 404 for a document that is not in the trash, and also for one whose permanent deletion has already begun — such a row carries purgePending, its stored object is gone or going, and the garbage collector will remove the row, so restoring it would return a document that cannot be downloaded and then disappears.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [DOCUMENT_ID_PARAM],
        responses: {
          200: jsonEnvelope('The restored document', DOCUMENT_RESPONSE_REF, {
            message: { type: 'string', example: 'Document restored from trash' },
          }),
          ...DOCUMENT_ITEM_WRITE_ERRORS,
        },
      },
    },

    '/documents/{id}/permanent': {
      delete: {
        operationId: 'purgeDocument',
        tags: ['Documents'],
        summary: 'Permanently delete a trashed document',
        description:
          'Destroys a trashed document for good, in three ordered steps: the row is marked purgePending, the stored object is deleted, and only then is the row deleted. A crash after any of them leaves a marker the hourly collector finishes, and the order is what stops an object outliving the row that names it. Deleting the row destroys the only wrapped copy of the document key, so any object that somehow survived is ciphertext under a key that exists nowhere — documents are deliberately absent from the backup payload. Only a document already in the trash may be purged.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [DOCUMENT_ID_PARAM],
        responses: {
          200: { $ref: '#/components/responses/Acknowledged' },
          ...DOCUMENT_ITEM_WRITE_ERRORS,
        },
      },
    },

    '/documents/trash/empty': {
      delete: {
        operationId: 'emptyDocumentTrash',
        tags: ['Documents'],
        summary: 'Permanently delete every trashed document',
        description:
          'Runs the same three ordered steps as a per-document purge over every document that was in the trash when the request arrived — a document trashed by another tab while it runs is outside that set and survives. It is not a bulk row delete: every document owns an object, so deleting the rows alone would leave the objects behind with nothing naming them. A document whose object cannot be deleted is counted rather than thrown, because it is already marked purgePending and the hourly collector will finish it, so the response reports both counts and the request succeeds either way.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: jsonEnvelope(
            'What was destroyed, and what was deferred to the collector',
            {
              type: 'object',
              required: ['deletedCount', 'failedCount'],
              properties: {
                deletedCount: { type: 'integer', minimum: 0, example: 4 },
                failedCount: {
                  type: 'integer',
                  minimum: 0,
                  description:
                    'Documents left marked purgePending for the collector to finish. Zero on a healthy deployment.',
                  example: 0,
                },
              },
            },
            { message: { type: 'string', example: '4 document(s) permanently deleted' } },
          ),
          ...DOCUMENT_BULK_WRITE_ERRORS,
        },
      },
    },

    '/documents/{id}/segments/{index}': {
      get: {
        operationId: 'getDocumentSegment',
        tags: ['Documents'],
        summary: 'Read one sealed segment',
        description:
          "One segment of the stored ciphertext, streamed as application/octet-stream with Cache-Control: no-store and an exact Content-Length. There is no Range header on this endpoint and there must never be one: the byte window is computed on the server from the document's own framing columns, so a segment can only ever be read from the offset it was written to. Segment indices are zero-based and the last one is chunkCount - 1; an index outside that is 400, and a document whose stored object has gone missing is 404. The client requests segments one at a time, verifies each one's authentication tag, and compares a running SHA-256 with the digest inside the metadata blob at the end.",
        security: [{ bearerAuth: [] }],
        parameters: [
          DOCUMENT_ID_PARAM,
          {
            name: 'index',
            in: 'path',
            required: true,
            description: 'Zero-based segment index, below the document chunkCount.',
            schema: { type: 'integer', minimum: 0, example: 0 },
          },
        ],
        responses: {
          200: {
            description:
              'The sealed segment. The body is raw ciphertext, not a JSON envelope, and Content-Length is the exact segment length so a truncated response cannot be mistaken for a whole one.',
            headers: {
              'Cache-Control': {
                description: 'Always no-store: a segment is user ciphertext and is never cached.',
                schema: { type: 'string', example: 'no-store' },
              },
            },
            content: {
              'application/octet-stream': {
                schema: { type: 'string', format: 'binary' },
              },
            },
          },
          ...DOCUMENT_ITEM_ERRORS,
        },
      },
    },

    // -- Health --
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Health check',
        description:
          'Returns server health status including database connectivity, uptime, and version.',
        responses: {
          200: jsonEnvelope('Server is healthy', { $ref: '#/components/schemas/HealthResponse' }),
        },
      },
    },

    // -- CSRF --
    '/csrf-token': {
      get: {
        tags: ['Auth'],
        summary: 'Get CSRF token',
        description:
          'Returns a double-submit CSRF token. Include this token in the `x-csrf-token` header for all state-changing requests (POST, PUT, DELETE). Rate limited by csrfLimiter (30 req/IP per 15 min) in production.',
        responses: {
          200: {
            description: 'CSRF token',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        token: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },

    // -- Auth --
    '/auth/register': {
      post: {
        tags: ['Auth'],
        summary: 'Register a new account',
        description:
          'Creates a new user account. Returns a generic success response for all attempts (prevents email enumeration). Existing accounts receive a notification email instead of an error. Rate limited: 5 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RegisterRequest' },
            },
          },
        },
        responses: {
          201: {
            description: 'Registration initiated (check email for verification link)',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Login with credentials',
        description:
          'Authenticates with email and auth hash. If 2FA is enabled, returns a temporary token for the 2FA step — UNLESS the request carries a valid `trustedDevice` cookie for this account, in which case the 2FA step is skipped and the login completes directly (the cookie is checked strictly after the password comparison, so a wrong password never consumes it). A recognized trusted-device cookie is consumed and rotated, carrying its original expiry forward; an unknown/expired/foreign cookie is cleared and the login falls back to the normal 2FA prompt. Rate limited: 10 req/IP + 20 req/email per 15 min. Progressive delay: 1s at 3+ failures, 3s at 5+, 5s at 7+.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/LoginRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Login successful or 2FA required',
            content: {
              'application/json': {
                schema: {
                  oneOf: [
                    { $ref: '#/components/schemas/LoginSuccessResponse' },
                    { $ref: '#/components/schemas/Login2faRequiredResponse' },
                  ],
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          403: {
            description: 'Email not verified or account locked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/login/2fa': {
      post: {
        tags: ['Auth'],
        summary: 'Complete 2FA verification',
        description:
          'Verifies a TOTP code (or backup code) to complete two-factor authentication. Rate limited: 5 req/IP + 3 req/IP per 15 min. When the originating login opted into "remember me" (carried in the signed temp token, not the request body), a successful response additionally sets a httpOnly `trustedDevice` cookie scoped to `/api/v1/auth`, allowing this device to skip the 2FA step on later logins until the trust grant expires.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Login2faRequest' },
            },
          },
        },
        responses: {
          200: {
            description:
              '2FA verification successful. Sets a httpOnly refresh-token cookie, and — only when the login opted into "remember me" — a httpOnly `trustedDevice` cookie (scoped to `/api/v1/auth`) whose raw value is never returned in the response body.',
            headers: {
              'Set-Cookie': {
                description:
                  'Sets `refreshToken` (httpOnly, path `/api/v1`) and, for a remembered login, `trustedDevice` (httpOnly, path `/api/v1/auth`). Only the SHA-256 of the trusted-device token is stored server-side.',
                schema: { type: 'string' },
              },
            },
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginSuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/refresh': {
      post: {
        tags: ['Auth'],
        summary: 'Refresh access token',
        description:
          'Exchanges a valid refresh token (httpOnly cookie) for a new access token. Implements token rotation with reuse detection.',
        responses: {
          200: {
            description: 'Token refreshed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginSuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'Logout current session',
        description: 'Revokes the current refresh token and clears the cookie.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: {
            description: 'Logged out',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/auth/logout-all': {
      post: {
        tags: ['Auth'],
        summary: 'Logout all other sessions',
        description: 'Revokes all refresh tokens except the current session.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: {
            description: 'All other sessions revoked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/auth/verify-email': {
      post: {
        tags: ['Auth'],
        summary: 'Verify email address',
        description:
          'Verifies the email address using a token from the verification email. Rate limited: 3 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/VerifyEmailRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Email verified',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/resend-verification': {
      post: {
        tags: ['Auth'],
        summary: 'Resend email verification',
        description: 'Resends the email verification link. Rate limited: 5 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ResendVerificationRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Verification email sent (generic response for all inputs)',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/forgot-password': {
      post: {
        tags: ['Auth'],
        summary: 'Request password reset',
        description: 'Sends a password reset email. Rate limited: 5 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ForgotPasswordRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Reset email sent (generic response for all inputs)',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/reset-password': {
      post: {
        tags: ['Auth'],
        summary: 'Reset password with token',
        description:
          'Resets the master password using a valid reset token. Rate limited: 3 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ResetPasswordRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Password reset successful',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/auth/unlock-account': {
      post: {
        tags: ['Auth'],
        summary: 'Unlock locked account',
        description:
          'Unlocks an account that was locked after too many failed login attempts. Rate limited: 3 req/IP per 15 min.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UnlockAccountRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Account unlocked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },

    // -- Vault items --
    '/vault/items': {
      get: {
        tags: ['Vault'],
        summary: 'List vault items',
        description:
          'Returns paginated, filterable, sortable list of vault items. All item data is encrypted.',
        security: [{ bearerAuth: [] }],
        parameters: [
          ...LIST_PAGE_PARAMS,
          {
            name: 'itemType',
            in: 'query',
            schema: { type: 'string', enum: ['login', 'secret', 'note', 'card', 'identity'] },
          },
          { name: 'folderId', in: 'query', schema: { type: 'string' } },
          { name: 'favorite', in: 'query', schema: { type: 'boolean' } },
          {
            name: 'sortBy',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['createdAt', 'updatedAt', 'itemType', 'favorite'],
              default: 'updatedAt',
            },
          },
          {
            name: 'sortOrder',
            in: 'query',
            schema: { type: 'string', enum: ['asc', 'desc'], default: 'desc' },
          },
        ],
        responses: {
          200: pageEnvelope('Paginated vault items', '#/components/schemas/VaultItemResponse'),
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
      post: {
        tags: ['Vault'],
        summary: 'Create vault item',
        description: 'Creates a new encrypted vault item.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateVaultItemRequest' },
            },
          },
        },
        responses: {
          201: jsonEnvelope('Item created', { $ref: '#/components/schemas/VaultItemResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/vault/items/trash': {
      get: {
        tags: ['Vault'],
        summary: 'List trashed items',
        description: 'Returns paginated list of soft-deleted vault items.',
        security: [{ bearerAuth: [] }],
        parameters: [...LIST_PAGE_PARAMS],
        responses: {
          200: pageEnvelope('Paginated trashed items', '#/components/schemas/VaultItemResponse'),
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/vault/items/trash/empty': {
      delete: {
        tags: ['Vault'],
        summary: 'Empty trash',
        description: 'Permanently deletes all items in the trash.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: {
            description: 'Trash emptied',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: { deleted: { type: 'integer' } },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/vault/items/bulk-delete': {
      post: {
        tags: ['Vault'],
        summary: 'Bulk soft-delete items',
        description: 'Soft-deletes up to 100 vault items at once.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BulkDeleteRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Items soft-deleted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: { deleted: { type: 'integer' } },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/vault/items/bulk-move': {
      post: {
        tags: ['Vault'],
        summary: 'Bulk move items to folder',
        description: 'Moves up to 100 vault items to a folder (or root if folderId is null).',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BulkMoveRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Items moved',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: { updated: { type: 'integer' } },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/vault/items/bulk-reencrypt': {
      post: {
        tags: ['Vault'],
        summary: 'Bulk re-encrypt vault items',
        description:
          'Re-encrypts an account onto a new vault key after a master password change: every item, every folder and every document key, in one request. Verifies the current auth hash before proceeding. The payload must name EVERY row the account holds, including trashed ones — the request is refused with 409 when it does not, because a row created between the enumeration and the request would otherwise be left under the superseded key. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BulkReEncryptRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Items re-encrypted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: { updated: { type: 'integer' } },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
          404: { $ref: '#/components/responses/NotFound' },
          409: {
            description:
              'The rotation was refused and the vault key was NOT changed: another rotation is already running, a named row could not be updated, or the payload did not cover every row the account holds. Re-read the vault and retry.',
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/vault/items/{id}': {
      get: {
        tags: ['Vault'],
        summary: 'Get vault item',
        description: 'Returns a single vault item by ID.',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: jsonEnvelope('Vault item', { $ref: '#/components/schemas/VaultItemResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
      put: {
        tags: ['Vault'],
        summary: 'Update vault item',
        description: 'Updates an existing vault item.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UpdateVaultItemRequest' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('Item updated', { $ref: '#/components/schemas/VaultItemResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
      delete: {
        tags: ['Vault'],
        summary: 'Soft-delete vault item',
        description: 'Moves a vault item to the trash (soft delete).',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Item soft-deleted',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/vault/items/{id}/permanent': {
      delete: {
        tags: ['Vault'],
        summary: 'Permanently delete vault item',
        description: 'Permanently deletes a trashed vault item. Cannot be undone.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Item permanently deleted',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/vault/items/restore/{id}': {
      post: {
        tags: ['Vault'],
        summary: 'Restore trashed item',
        description: 'Restores a soft-deleted vault item from the trash.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: jsonEnvelope('Item restored', { $ref: '#/components/schemas/VaultItemResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },

    // -- Folders --
    '/folders': {
      get: {
        tags: ['Folders'],
        summary: 'List folders',
        description: 'Returns all folders for the authenticated user.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Folder list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/FolderResponse' },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
      post: {
        tags: ['Folders'],
        summary: 'Create folder',
        description: 'Creates a new folder for organizing vault items.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateFolderRequest' },
            },
          },
        },
        responses: {
          201: jsonEnvelope('Folder created', { $ref: '#/components/schemas/FolderResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/folders/{id}': {
      put: {
        tags: ['Folders'],
        summary: 'Update folder',
        description: 'Updates folder properties. Validates against circular parent references.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UpdateFolderRequest' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('Folder updated', { $ref: '#/components/schemas/FolderResponse' }),
          400: {
            description: 'Circular parent reference detected',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
      delete: {
        tags: ['Folders'],
        summary: 'Delete folder',
        description:
          "Deletes a folder. Its members are the vault items AND the documents inside it, and both are treated the same way: `action=move` (default) re-parents them to the folder's parent, or to the root when it has none, while `action=delete` moves them to the trash alongside the folder. Trashing a document does not delete its stored bytes; the scheduled trash purge does that once it is `TRASH_AUTO_PURGE_DAYS` old.",
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          {
            name: 'action',
            in: 'query',
            schema: { type: 'string', enum: ['move', 'delete'], default: 'move' },
          },
        ],
        responses: {
          200: {
            description: 'Folder deleted',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/folders/{id}/sort': {
      put: {
        tags: ['Folders'],
        summary: 'Reorder folder',
        description: 'Updates the sort order of a folder.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ReorderFolderRequest' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('Folder reordered', { $ref: '#/components/schemas/FolderResponse' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },

    // -- User --
    '/user/profile': {
      get: {
        tags: ['User'],
        summary: 'Get user profile',
        description: 'Returns the authenticated user profile and settings.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: jsonEnvelope('User profile', { $ref: '#/components/schemas/UserProfile' }),
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/user/settings': {
      put: {
        tags: ['User'],
        summary: 'Update user settings',
        description:
          'Updates user preferences such as theme, auto-lock timeout, and password generation defaults.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/UserSettings' },
            },
          },
        },
        responses: {
          200: jsonEnvelope('Settings updated', { $ref: '#/components/schemas/UserProfile' }),
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/user/change-password': {
      put: {
        tags: ['User'],
        summary: 'Change master password',
        description:
          'Changes the master password. Requires current auth hash for verification. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ChangePasswordRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Password changed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/user/2fa/setup': {
      post: {
        tags: ['User'],
        summary: 'Start 2FA setup',
        description:
          'Initiates two-factor authentication setup. Returns a TOTP secret and QR code. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Setup2faRequest' },
            },
          },
        },
        responses: {
          200: {
            description: '2FA setup data',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        secret: { type: 'string' },
                        otpauthUri: { type: 'string' },
                        qrCodeDataUrl: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/user/2fa/verify': {
      post: {
        tags: ['User'],
        summary: 'Complete 2FA setup',
        description:
          'Verifies a TOTP code to finalize 2FA setup. Returns backup codes. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Verify2faRequest' },
            },
          },
        },
        responses: {
          200: {
            description: '2FA enabled with backup codes',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        backupCodes: {
                          type: 'array',
                          items: { type: 'string' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/user/2fa': {
      delete: {
        tags: ['User'],
        summary: 'Disable 2FA',
        description:
          'Disables two-factor authentication. Requires a valid TOTP or backup code. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Disable2faRequest' },
            },
          },
        },
        responses: {
          200: {
            description: '2FA disabled',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/user/sessions': {
      get: {
        tags: ['User'],
        summary: 'List active sessions',
        description: 'Returns all active sessions for the authenticated user.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Active sessions',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/SessionInfo' },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/user/sessions/{id}': {
      delete: {
        tags: ['User'],
        summary: 'Revoke session',
        description: 'Revokes a specific active session by its refresh token ID.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Session revoked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/user/trusted-devices': {
      get: {
        tags: ['User'],
        summary: 'List trusted devices',
        description:
          'Returns the devices allowed to skip the 2FA step at login for the authenticated user. The server-only token hash is never returned.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Trusted devices',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/TrustedDeviceInfo' },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
      delete: {
        tags: ['User'],
        summary: 'Revoke all trusted devices',
        description:
          'Revokes every trusted device for the authenticated user. Each device must complete 2FA again on its next login.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: {
            description: 'All trusted devices revoked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/user/trusted-devices/{id}': {
      delete: {
        tags: ['User'],
        summary: 'Revoke trusted device',
        description:
          'Revokes a specific trusted device by its id. The device must complete 2FA again on its next login.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Trusted device revoked',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          404: { $ref: '#/components/responses/NotFound' },
        },
      },
    },
    '/user/audit-log': {
      get: {
        tags: ['User'],
        summary: 'Get audit log',
        description: 'Returns paginated audit log entries for the authenticated user.',
        security: [{ bearerAuth: [] }],
        parameters: [
          ...LOG_PAGE_PARAMS,
          {
            name: 'action',
            in: 'query',
            schema: { type: 'string', description: 'Filter by audit action type' },
          },
        ],
        responses: {
          200: pageEnvelope('Audit log entries', '#/components/schemas/AuditLogEntry'),
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },

    // -- Tools --
    '/tools/check-password-breach': {
      post: {
        tags: ['Tools'],
        summary: 'Check password breach (HIBP)',
        description:
          'Checks if a password hash prefix has been found in data breaches using the Have I Been Pwned k-anonymity API.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CheckBreachRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Breach check result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'string',
                      description:
                        'The Have I Been Pwned range for the submitted prefix: newline-separated `SUFFIX:COUNT` rows, with the count-0 padding rows removed. The client matches the remaining 35 characters of its own SHA-1 hash against these rows locally, so the server never learns which suffix — if any — matched.',
                      example:
                        '0018A45C4D1DEF81644B54AB7F969B88D65:1\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2',
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/tools/check-password-breach/batch': {
      post: {
        tags: ['Tools'],
        summary: 'Check password breaches in bulk (HIBP)',
        description:
          'Checks several password hash prefixes against Have I Been Pwned in one request, preserving k-anonymity (only the first 5 hex chars of each SHA-1 hash are sent; the client deduplicates its passwords first). The server serves warm results from its per-process cache and fans the rest out to HIBP with bounded concurrency. The response maps each resolved prefix to its HIBP range text and reports any prefixes whose lookup failed under `errors`, so the client can mark those passwords as not-checked rather than not-breached.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CheckBreachBatchRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Batched breach check result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      additionalProperties: { type: 'string' },
                      description: 'Map of hash prefix to its HIBP range text.',
                    },
                    errors: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Prefixes whose lookup failed (reported, not silently dropped).',
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/tools/export': {
      post: {
        tags: ['Tools'],
        summary: 'Export vault',
        description: 'Exports all vault items as JSON. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['authHash'],
                properties: {
                  format: { type: 'string', enum: ['json'], default: 'json' },
                  authHash: { type: 'string', minLength: 1, maxLength: 100 },
                  portableFormat: {
                    type: 'string',
                    enum: ['bitwarden-json', 'bitwarden-csv', 'chrome-csv'],
                    description:
                      'Audit metadata only. Records which portable plaintext format the browser produced from this response. The server does not branch on it; the response body is identical whether or not it is sent.',
                  },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Export data (JSON)',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        items: {
                          type: 'array',
                          items: { $ref: '#/components/schemas/VaultItemResponse' },
                        },
                        exportedAt: { type: 'string', format: 'date-time' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/tools/import': {
      post: {
        tags: ['Tools'],
        summary: 'Import vault items',
        description:
          'Executes already-decided import operations. The client parses the source export (Bitwarden, LastPass, KeePass, Chrome, Firefox, 1Password, generic CSV, or a native H-Vault export), resolves conflicts against its own decrypted vault, and encrypts every item locally before calling this endpoint; the server never sees plaintext, never parses the source format, and performs no matching of its own. Identity is computed in the browser from decrypted content — a login matches on its site and username, every other type on its exact content — and is neither transmitted nor stored, so `conflictStrategy` arrives already applied. The server validates ownership, field lengths and the per-account item cap, then applies exactly the `inserts` and `updates` it was given, under a per-user lock and (where the topology supports it) one transaction. Max 10,000 operations per request (large imports are split into several sequential requests by the client, which cannot change the outcome). Rate limited by `importLimiter`: 60 req/user per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ImportRequest' },
            },
          },
        },
        responses: {
          201: {
            description: 'Import result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        insertedCount: { type: 'integer' },
                        updatedCount: { type: 'integer' },
                      },
                    },
                    message: { type: 'string' },
                  },
                },
              },
            },
          },
          400: {
            description:
              'The body failed schema validation (a missing or malformed ciphertext field, `searchHash`, tag or `passwordHistory` entry rejects the whole request); an update names an item that does not exist, is in the trash, or is not yours; the same id appears twice; a field is over-length; or the import would exceed the per-account item cap. Nothing is written.',
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          409: {
            description:
              'A vault-key rotation is in flight, another import for this account is already running, or an item an update targeted was modified or removed mid-request. Under `skip` and `overwrite`, re-running the import is safe: the client re-resolves against the current vault and sends only what is left. Under `keep_both` nothing is ever matched, so a re-run inserts the rows that already landed a second time.',
          },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },

    // -- Backup --
    '/backup/setup': {
      post: {
        tags: ['Backup'],
        summary: 'Setup backup encryption',
        description:
          'Configures the backup encryption key (BWK). The client generates and encrypts the BWK before sending. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BackupSetupRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Backup configured',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/backup/settings': {
      put: {
        tags: ['Backup'],
        summary: 'Update backup settings',
        description: 'Updates backup schedule and email settings.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BackupSettingsRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Backup settings updated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { type: 'object' },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
        },
      },
    },
    '/backup/trigger': {
      post: {
        tags: ['Backup'],
        summary: 'Trigger backup now',
        description:
          'Creates and emails an encrypted backup immediately. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        responses: {
          200: {
            description: 'Backup triggered',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/backup/download': {
      get: {
        tags: ['Backup'],
        summary: 'Download backup',
        description:
          'Downloads the latest encrypted backup as a file stream. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [] }],
        responses: {
          200: {
            description: 'Encrypted backup file',
            content: {
              'application/octet-stream': {
                schema: { type: 'string', format: 'binary' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/backup/history': {
      get: {
        tags: ['Backup'],
        summary: 'Backup history',
        description: 'Returns paginated backup history log.',
        security: [{ bearerAuth: [] }],
        parameters: [...LOG_PAGE_PARAMS],
        responses: {
          200: pageEnvelope('Backup log entries', '#/components/schemas/BackupLogEntry'),
          401: { $ref: '#/components/responses/Unauthorized' },
        },
      },
    },
    '/backup/change-password': {
      put: {
        tags: ['Backup'],
        summary: 'Change backup password',
        description:
          'Re-encrypts the BWK with a new backup password. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BackupChangePasswordRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Backup password changed',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessResponse' },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
    '/backup/restore': {
      post: {
        tags: ['Backup'],
        summary: 'Restore from backup',
        description:
          'Restores vault items and folders from an encrypted backup file. Supports skip, overwrite, and keep_both conflict strategies. Rate limited: 3 req/IP per 15 min.',
        security: [{ bearerAuth: [], csrfToken: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RestoreBackupRequest' },
            },
          },
        },
        responses: {
          200: {
            description: 'Backup restored',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'object',
                      properties: {
                        itemsRestored: { type: 'integer' },
                      },
                    },
                  },
                },
              },
            },
          },
          401: { $ref: '#/components/responses/Unauthorized' },
          400: { $ref: '#/components/responses/ValidationError' },
          429: { $ref: '#/components/responses/RateLimited' },
        },
      },
    },
  },
};
