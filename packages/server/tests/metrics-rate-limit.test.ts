import { describe, it, expect } from 'vitest';
import express from 'express';
import type { Request, Response } from 'express';
import request from 'supertest';
import { metricsLimiter } from '../src/middleware/rateLimiter.js';
import { getMetrics } from '../src/controllers/metricsController.js';

// The PRODUCTION behaviour of metricsLimiter — the 60-req/min threshold, the
// `metrics:` key prefix (isolation from the `health:` bucket), the /64 IPv6
// masking and the 429 message — is exercised end to end against the REAL
// exported limiter, with `isProduction` forced true and a real Mongo store, in
// coverage-rate-limiter.test.ts (the "metricsLimiter" row of the IP-keyed
// threshold table). Two mirrored-config clone limiters used to live here; they
// tested express-rate-limit's own counting rather than the production limiter
// (regressing the real limit/prefix/keyGenerator left them green), so they were
// removed in favour of the real-symbol coverage above. What remains here
// asserts the test-mode behaviour of the real exported symbol.

describe('metricsLimiter', () => {
  it('is exported as a middleware function', () => {
    expect(typeof metricsLimiter).toBe('function');
  });

  it('is a no-op pass-through in test mode (no 429 within window)', async () => {
    const app = express();
    app.use(metricsLimiter as express.RequestHandler);
    app.get('/metrics', (_req: Request, res: Response) => {
      res.json({ success: true });
    });

    // Send well above the 60-req/min production limit; pass-through lets them all succeed.
    for (let i = 0; i < 70; i++) {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
    }
  });

  it('does not break the metrics endpoint when mounted before the handler', async () => {
    // Mirror app.ts's mount shape: app.get('/api/v1/metrics', metricsLimiter, getMetrics).
    // In test mode the limiter is a no-op, so a request (METRICS_TOKEN unset in
    // test config) flows through the real limiter into the real getMetrics
    // controller and returns the metrics payload.
    const app = express();
    app.get('/metrics', metricsLimiter as express.RequestHandler, getMetrics);
    const { errorMiddleware } = await import('@hiprax/errors');
    app.use(errorMiddleware);

    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(typeof res.body.data.uptime).toBe('number');
  });
});
