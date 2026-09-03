import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_DOCUMENTS_PER_USER,
  publicConfigResponseSchema,
} from '@hvault/shared';

/**
 * `storageConfigured` behind a mutable getter, so ONE file can observe both
 * states of the document block.
 *
 * `vitest.config.ts` pins the four `S3_*` connection variables EMPTY, so the
 * suite's real answer is always "unconfigured" — which is the state most of this
 * file wants and the state a fresh 0.9.x deployment is in. The enabled branch is
 * the one that has to be reached deliberately.
 *
 * A GETTER rather than a fixed `true`: named imports compile to property reads on
 * the mocked namespace, so the controller sees whatever the flag says at the
 * moment it runs, and the two states are two tests rather than two files. It is a
 * HOISTED `vi.mock` (never `vi.resetModules()` + `vi.doMock`, which re-evaluates
 * `models/User.ts` and throws `OverwriteModelError`), and everything else in the
 * config module is the genuine value.
 */
const { storageState } = vi.hoisted(() => ({ storageState: { configured: false } }));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return {
    ...actual,
    get storageConfigured() {
      return storageState.configured;
    },
  };
});

import app from '../src/app.js';
import configRouter from '../src/routes/config.js';
import { config } from '../src/config/index.js';
import { healthLimiter } from '../src/middleware/rateLimiter.js';

// Minimal shape of the Express router internals we introspect to assert the
// route is wired with the healthLimiter (rate limiters are pass-through no-ops
// in test mode, so a 429 is not behaviorally observable here).
interface RouteHandlerLayer {
  handle?: unknown;
}
interface RouterLayer {
  route?: { path?: string; stack?: RouteHandlerLayer[] };
}

afterEach(() => {
  storageState.configured = false;
});

describe('GET /api/v1/config', () => {
  it('returns the configured file-encryption size limit', async () => {
    const res = await request(app).get('/api/v1/config');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.fileEncryption.maxSizeMB).toBe(config.FILE_ENCRYPTION_MAX_SIZE_MB);
    expect(Number.isInteger(res.body.data.fileEncryption.maxSizeMB)).toBe(true);
    expect(res.body.data.fileEncryption.maxSizeMB).toBeGreaterThan(0);
  });

  it('returns a payload that matches the shared publicConfigResponseSchema', async () => {
    const res = await request(app).get('/api/v1/config');

    const parsed = publicConfigResponseSchema.safeParse(res.body);
    expect(parsed.success).toBe(true);
  });

  it('requires no authentication (no Authorization header, no cookies)', async () => {
    const res = await request(app).get('/api/v1/config');

    // No 401/403 — the endpoint is public.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('exposes nothing beyond the file-encryption cap and the document advertisement', async () => {
    const res = await request(app).get('/api/v1/config');

    expect(Object.keys(res.body.data)).toEqual(['fileEncryption', 'documents']);
    expect(Object.keys(res.body.data.fileEncryption)).toEqual(['maxSizeMB']);
  });

  it('is wired behind the healthLimiter middleware', () => {
    const stack = (configRouter as unknown as { stack: RouterLayer[] }).stack;
    const layer = stack.find((l) => l.route?.path === '/config');
    expect(layer).toBeDefined();

    const handles = layer?.route?.stack?.map((s) => s.handle) ?? [];
    expect(handles).toContain(healthLimiter);
  });

  // NOTE: a "ten rapid requests all 200" test was removed here. Every rate
  // limiter is a pass-through no-op outside production (see rateLimiter.ts), so
  // that assertion held regardless of how the endpoint or its limiter was wired
  // — it could not be turned red by any production change and only added HTTP
  // round-trips. The healthLimiter WIRING is pinned by the test above; the store
  // is exercised for real in tests/rate-limit-store.test.ts.
});

/**
 * The document block, in the two states a server can be in.
 *
 * The third state — the block ABSENT — is what an older server sends and is not
 * reachable from this code at all; `publicConfigDataSchema` marks the block
 * optional so a current CLIENT can still read that payload, and the `upgrade`
 * gate is what exercises it.
 */
describe('GET /api/v1/config — the document store advertisement', () => {
  it('reports the feature off, and nothing else, when no object storage is configured', async () => {
    const res = await request(app).get('/api/v1/config');

    // `enabled: false` rather than an omitted block, because the two mean
    // different things to an operator: "my server is old" versus "my storage is
    // unconfigured" have identical client behaviour and completely different
    // fixes.
    expect(res.body.data.documents).toEqual({ enabled: false });
    // Not one number leaks in this state. A cap advertised by a server that
    // cannot accept an upload would have the client offering the feature.
    expect(Object.keys(res.body.data.documents)).toEqual(['enabled']);
  });

  it('publishes the limits the browser needs when storage IS configured', async () => {
    storageState.configured = true;

    const res = await request(app).get('/api/v1/config');

    expect(res.status).toBe(200);
    expect(res.body.data.documents).toEqual({
      enabled: true,
      maxSizeMB: config.MAX_DOCUMENT_SIZE_MB,
      // The SERVER's framing constant, never a client-chosen value: the browser
      // computes `declaredChunkCount` from it before sealing the first segment.
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      maxDocuments: MAX_DOCUMENTS_PER_USER,
      quotaMB: config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER,
      allowedExtensions: config.DOCUMENT_ALLOWED_EXTENSIONS,
    });
    expect(publicConfigResponseSchema.safeParse(res.body).success).toBe(true);
  });

  it('never publishes an endpoint, a bucket or a credential', async () => {
    storageState.configured = true;

    const res = await request(app).get('/api/v1/config');

    // The negative that matters on a public, unauthenticated endpoint. Asserted
    // over the SERIALIZED body rather than key by key, so a field added to the
    // block later is covered by this test without anyone remembering to extend
    // it.
    const serialized = JSON.stringify(res.body);
    for (const forbidden of ['S3_', 'endpoint', 'bucket', 'accessKey', 'secret', 'region']) {
      expect(serialized.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });

  it('still parses under the shared schema with the block absent, which is an older server', () => {
    // The N-1 direction, checked against the schema rather than over the wire,
    // because this server can no longer produce that payload. A required
    // `documents` block here would make a current client reject an older
    // server's config outright — and the File Encryption cap would silently fall
    // back to its default along with it.
    const legacy = { success: true as const, data: { fileEncryption: { maxSizeMB: 100 } } };
    expect(publicConfigResponseSchema.safeParse(legacy).success).toBe(true);
  });
});
