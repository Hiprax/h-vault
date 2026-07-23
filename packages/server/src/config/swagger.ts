import type { JsonObject } from 'swagger-ui-express';
import { APP_VERSION, HIBP_BATCH_MAX_PREFIXES } from '@hvault/shared';

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
          autoLockTimeout: { type: 'integer', description: 'Minutes (1-1440)' },
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
    },
  },

  // ---------------------------------------------------------------------------
  // Paths
  // ---------------------------------------------------------------------------
  paths: {
    // -- Health --
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Health check',
        description:
          'Returns server health status including database connectivity, uptime, and version.',
        responses: {
          200: {
            description: 'Server is healthy',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/HealthResponse' },
                  },
                },
              },
            },
          },
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
          { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
          },
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
          200: {
            description: 'Paginated vault items',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/VaultItemResponse' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
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
          201: {
            description: 'Item created',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/VaultItemResponse' },
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
    '/vault/items/trash': {
      get: {
        tags: ['Vault'],
        summary: 'List trashed items',
        description: 'Returns paginated list of soft-deleted vault items.',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
          },
        ],
        responses: {
          200: {
            description: 'Paginated trashed items',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/VaultItemResponse' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
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
          'Re-encrypts all vault items with a new vault key after a master password change. Verifies the current auth hash before proceeding. Rate limited: 3 req/IP per 15 min.',
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
          200: {
            description: 'Vault item',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/VaultItemResponse' },
                  },
                },
              },
            },
          },
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
          200: {
            description: 'Item updated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/VaultItemResponse' },
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
          200: {
            description: 'Item restored',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/VaultItemResponse' },
                  },
                },
              },
            },
          },
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
          201: {
            description: 'Folder created',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/FolderResponse' },
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
          200: {
            description: 'Folder updated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/FolderResponse' },
                  },
                },
              },
            },
          },
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
          'Deletes a folder. Use `action=move` (default) to move items to root, or `action=delete` to delete items with the folder.',
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
          200: {
            description: 'Folder reordered',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/FolderResponse' },
                  },
                },
              },
            },
          },
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
          200: {
            description: 'User profile',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/UserProfile' },
                  },
                },
              },
            },
          },
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
          200: {
            description: 'Settings updated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: { $ref: '#/components/schemas/UserProfile' },
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
          { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
          },
          {
            name: 'action',
            in: 'query',
            schema: { type: 'string', description: 'Filter by audit action type' },
          },
        ],
        responses: {
          200: {
            description: 'Audit log entries',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/AuditLogEntry' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
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
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, default: 1 } },
          {
            name: 'limit',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
          },
        ],
        responses: {
          200: {
            description: 'Backup log entries',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', example: true },
                    data: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/BackupLogEntry' },
                    },
                    pagination: { $ref: '#/components/schemas/Pagination' },
                  },
                },
              },
            },
          },
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
