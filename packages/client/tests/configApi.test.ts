/**
 * Tests for the public-config API service (`services/api/configApi.ts`).
 *
 * Covers `getPublicConfigApi` (thin `GET /config` wrapper) and the two cached
 * resolvers over it, `getFileEncryptionMaxBytes` and `getDocumentsConfig`.
 *
 * The pair matters as a pair. One envelope carries two features that have nothing
 * to do with each other, and each resolver validates only the block it acts on
 * through its own narrowing of the single full shape — so a bad value under
 * `documents` cannot change the File Encryption cap, and a bad `fileEncryption`
 * cannot hide the document store. Both directions are asserted below, because
 * either one is silent when it breaks.
 *
 * For `getFileEncryptionMaxBytes`:
 *   - server-value path (returns the configured limit in bytes)
 *   - fallback path (network error → shared-constant fallback)
 *   - fallback path (malformed/invalid payload → shared-constant fallback)
 *   - single-call caching (one network call across repeated resolves)
 *
 * The shared axios client is mocked so no real network/CSRF setup runs, and
 * `vi.resetModules()` is used before each test to reset the module-level cache
 * (rather than exposing a test-only reset from production code).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, MAX_FILE_ENCRYPTION_SIZE_MB } from '@hvault/shared';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));

vi.mock('../src/services/api/client', () => ({
  api: {
    get: (...args: unknown[]) => mockGet(...args),
  },
  clearCsrfToken: vi.fn(),
}));

const BYTES_PER_MB = 1024 * 1024;
const FALLBACK_BYTES = MAX_FILE_ENCRYPTION_SIZE_MB * BYTES_PER_MB;

/** Build a well-formed `{ success, data }` config envelope wire response. */
function makeWire(maxSizeMB: number): { data: unknown } {
  return { data: { success: true, data: { fileEncryption: { maxSizeMB } } } };
}

// Import fresh after `vi.resetModules()` so each test gets an empty cache.
async function importConfigApi() {
  return import('../src/services/api/configApi');
}

describe('configApi', () => {
  beforeEach(() => {
    mockGet.mockReset();
    vi.resetModules();
  });

  describe('getPublicConfigApi', () => {
    it('GETs /config and returns the typed PublicConfig envelope', async () => {
      mockGet.mockResolvedValue(makeWire(250));
      const { getPublicConfigApi } = await importConfigApi();

      const res = await getPublicConfigApi();

      expect(mockGet).toHaveBeenCalledWith('/config');
      if (!res.data.success) throw new Error('expected a successful config envelope');
      expect(res.data.data.fileEncryption.maxSizeMB).toBe(250);
    });
  });

  describe('getFileEncryptionMaxBytes', () => {
    it('returns the server-provided limit converted to bytes', async () => {
      mockGet.mockResolvedValue(makeWire(250));
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const bytes = await getFileEncryptionMaxBytes();

      expect(bytes).toBe(250 * BYTES_PER_MB);
      expect(mockGet).toHaveBeenCalledTimes(1);
    });

    it('falls back to the shared constant on network failure', async () => {
      mockGet.mockRejectedValue(new Error('network down'));
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const bytes = await getFileEncryptionMaxBytes();

      expect(bytes).toBe(FALLBACK_BYTES);
    });

    it('falls back to the shared constant when the payload is malformed', async () => {
      // Negative maxSizeMB fails the shared publicConfigResponseSchema.
      mockGet.mockResolvedValue({
        data: { success: true, data: { fileEncryption: { maxSizeMB: -5 } } },
      });
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const bytes = await getFileEncryptionMaxBytes();

      expect(bytes).toBe(FALLBACK_BYTES);
    });

    it('falls back when the envelope shape is entirely wrong', async () => {
      mockGet.mockResolvedValue({ data: { unexpected: true } });
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const bytes = await getFileEncryptionMaxBytes();

      expect(bytes).toBe(FALLBACK_BYTES);
    });

    it('caches the result — one network call across repeated concurrent resolves', async () => {
      mockGet.mockResolvedValue(makeWire(300));
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const [a, b, c] = await Promise.all([
        getFileEncryptionMaxBytes(),
        getFileEncryptionMaxBytes(),
        getFileEncryptionMaxBytes(),
      ]);

      expect(a).toBe(300 * BYTES_PER_MB);
      expect(b).toBe(300 * BYTES_PER_MB);
      expect(c).toBe(300 * BYTES_PER_MB);
      expect(mockGet).toHaveBeenCalledTimes(1);
    });

    it('caches the result across sequential resolves', async () => {
      mockGet.mockResolvedValue(makeWire(64));
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const first = await getFileEncryptionMaxBytes();
      const second = await getFileEncryptionMaxBytes();
      const third = await getFileEncryptionMaxBytes();

      expect(first).toBe(64 * BYTES_PER_MB);
      expect(second).toBe(64 * BYTES_PER_MB);
      expect(third).toBe(64 * BYTES_PER_MB);
      expect(mockGet).toHaveBeenCalledTimes(1);
    });

    it('reads the cap out of an envelope whose documents block is malformed', async () => {
      // The coupling this guards against: ONE envelope carries two features that
      // have nothing to do with each other, and this function reads only one of
      // them. Validating the other would mean a mistyped operator extension, or a
      // field a newer server adds, silently reverting the File Encryption cap to
      // its default — a feature breaking for a reason nobody can see, caused by a
      // block it never looks at.
      mockGet.mockResolvedValue({
        data: {
          success: true,
          data: {
            fileEncryption: { maxSizeMB: 42 },
            documents: { maxSizeMB: -1, allowedExtensions: ['x'.repeat(64)] },
          },
        },
      });
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const bytes = await getFileEncryptionMaxBytes();

      expect(bytes).toBe(42 * BYTES_PER_MB);
      // The negative that makes the assertion mean something: this is NOT the
      // fallback, so the parse really did succeed.
      expect(bytes).not.toBe(FALLBACK_BYTES);
    });

    it('caches the fallback too — a failed first fetch is not retried', async () => {
      mockGet.mockRejectedValue(new Error('network down'));
      const { getFileEncryptionMaxBytes } = await importConfigApi();

      const first = await getFileEncryptionMaxBytes();
      const second = await getFileEncryptionMaxBytes();

      expect(first).toBe(FALLBACK_BYTES);
      expect(second).toBe(FALLBACK_BYTES);
      expect(mockGet).toHaveBeenCalledTimes(1);
    });
  });

  describe('getDocumentsConfig', () => {
    /** A well-formed envelope carrying both blocks. */
    function makeFullWire(documents: unknown): { data: unknown } {
      return {
        data: { success: true, data: { fileEncryption: { maxSizeMB: 100 }, documents } },
      };
    }

    it('returns the advertised block, numbers and all, when the feature is on', async () => {
      const block = {
        enabled: true,
        maxSizeMB: 100,
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        maxDocuments: 5000,
        quotaMB: 2048,
        allowedExtensions: ['md', 'pdf'],
      };
      mockGet.mockResolvedValue(makeFullWire(block));
      const { getDocumentsConfig } = await importConfigApi();

      await expect(getDocumentsConfig()).resolves.toEqual(block);
    });

    it('reports the feature off when the server advertises it off', async () => {
      mockGet.mockResolvedValue(makeFullWire({ enabled: false }));
      const { getDocumentsConfig } = await importConfigApi();

      await expect(getDocumentsConfig()).resolves.toEqual({ enabled: false });
    });

    it('reports the feature off when the block is ABSENT — a server older than it', async () => {
      // The third of the three wire states. It collapses onto the same answer as
      // `enabled: false` because the client behaves identically; the two stay
      // distinguishable on the wire so an operator can tell "my server is old" from
      // "my storage is unconfigured".
      mockGet.mockResolvedValue(makeWire(100));
      const { getDocumentsConfig } = await importConfigApi();

      await expect(getDocumentsConfig()).resolves.toEqual({ enabled: false });
    });

    it('refuses a malformed block rather than acting on it', async () => {
      // Narrow does not mean lenient: this is the reader that would compare a byte
      // count against `maxSizeMB`, so a negative one has to be refused HERE.
      mockGet.mockResolvedValue(makeFullWire({ enabled: true, maxSizeMB: -1 }));
      const { getDocumentsConfig } = await importConfigApi();

      const config = await getDocumentsConfig();

      expect(config).toEqual({ enabled: false });
      // The negative that gives the assertion meaning: the numbers were dropped
      // wholesale, not passed through with the bad one intact.
      expect(config.maxSizeMB).toBeUndefined();
    });

    it('reads its own block out of an envelope whose fileEncryption block is malformed', async () => {
      // The mirror image of the coupling the File Encryption reader guards against,
      // and the reason this function does NOT use the full schema: `fileEncryption`
      // is a REQUIRED field of the envelope, so validating the whole document here
      // would hide the document store because of a block it never reads.
      mockGet.mockResolvedValue({
        data: {
          success: true,
          data: { fileEncryption: { maxSizeMB: -5 }, documents: { enabled: true, maxSizeMB: 50 } },
        },
      });
      const { getDocumentsConfig } = await importConfigApi();

      const config = await getDocumentsConfig();

      expect(config).toEqual({ enabled: true, maxSizeMB: 50 });
      // Not the fallback, so the parse really did succeed.
      expect(config.enabled).toBe(true);
    });

    it('never rejects — a network failure resolves to the feature being off', async () => {
      mockGet.mockRejectedValue(new Error('network down'));
      const { getDocumentsConfig } = await importConfigApi();

      await expect(getDocumentsConfig()).resolves.toEqual({ enabled: false });
    });

    it('caches the result — one network call across repeated concurrent resolves', async () => {
      mockGet.mockResolvedValue(makeFullWire({ enabled: true, maxSizeMB: 100 }));
      const { getDocumentsConfig } = await importConfigApi();

      const [a, b, c] = await Promise.all([
        getDocumentsConfig(),
        getDocumentsConfig(),
        getDocumentsConfig(),
      ]);

      expect(a).toBe(b);
      expect(b).toBe(c);
      expect(mockGet).toHaveBeenCalledTimes(1);
    });

    it('caches the fallback too — a failed first fetch is not retried', async () => {
      mockGet.mockRejectedValue(new Error('network down'));
      const { getDocumentsConfig } = await importConfigApi();

      await getDocumentsConfig();
      await getDocumentsConfig();

      // Without this, every navigation, every nav-bar render and every size check
      // would re-hit the endpoint for the whole duration of an outage.
      expect(mockGet).toHaveBeenCalledTimes(1);
    });

    it('keeps its memo separate from the File Encryption one', async () => {
      mockGet.mockResolvedValue(makeFullWire({ enabled: true, maxSizeMB: 50 }));
      const { getDocumentsConfig, getFileEncryptionMaxBytes } = await importConfigApi();

      const documents = await getDocumentsConfig();
      const bytes = await getFileEncryptionMaxBytes();

      // Each reads the block it owns out of the same envelope. The document store's
      // own 50 MB cap must not become the File Encryption tool's, which is 100 here.
      expect(documents.maxSizeMB).toBe(50);
      expect(bytes).toBe(100 * BYTES_PER_MB);
    });
  });
});
