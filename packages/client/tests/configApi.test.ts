/**
 * Tests for the public-config API service (`services/api/configApi.ts`).
 *
 * Covers `getPublicConfigApi` (thin `GET /config` wrapper) and the cached
 * `getFileEncryptionMaxBytes` resolver:
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
import { MAX_FILE_ENCRYPTION_SIZE_MB } from '@hvault/shared';

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
});
