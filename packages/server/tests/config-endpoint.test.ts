import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { publicConfigResponseSchema } from '@hvault/shared';
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

  it('does not expose any field other than the file-encryption size cap', async () => {
    const res = await request(app).get('/api/v1/config');

    expect(Object.keys(res.body.data)).toEqual(['fileEncryption']);
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
