import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import app from '../src/app.js';
import { getMetrics } from '../src/controllers/metricsController.js';
import { createTestUser } from './helpers.js';

describe('Health routes', () => {
  describe('GET /api/v1/health', () => {
    it('should return status ok when database is connected', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ok');
      expect(res.body.data.version).toBeDefined();
      expect(typeof res.body.data.uptime).toBe('number');
      expect(res.body.data.database).toBe('connected');
      expect(res.body.data.timestamp).toBeDefined();
    });

    it('should not expose detailed job/backup info even with ?detailed=true', async () => {
      const res = await request(app).get('/api/v1/health?detailed=true');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe('ok');
      // Detailed mode was removed to prevent leaking JobLock internals
      expect(res.body.data.jobs).toBeUndefined();
      expect(res.body.data.lastBackup).toBeUndefined();
    });
  });
});

describe('Metrics controller', () => {
  const VALID_METRICS_TOKEN = 'test-metrics-token-at-least-16-chars';

  it('should return uptime, memory usage, and database state with valid token', async () => {
    // Create a standalone app with the metrics handler and METRICS_TOKEN check
    const { errorMiddleware } = await import('@hiprax/errors');
    const metricsApp = express();
    metricsApp.get('/metrics', getMetrics);
    metricsApp.use(errorMiddleware);

    // When METRICS_TOKEN is not set in config, the handler allows access
    // (the route itself is gated in app.ts by config.METRICS_TOKEN).
    // Here we test the handler directly without config gating.
    const res = await request(metricsApp).get('/metrics');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(typeof res.body.data.uptime).toBe('number');
    expect(res.body.data.memory).toBeDefined();
    expect(typeof res.body.data.memory.rss).toBe('number');
    expect(typeof res.body.data.memory.heapTotal).toBe('number');
    expect(typeof res.body.data.memory.heapUsed).toBe('number');
    expect(typeof res.body.data.memory.external).toBe('number');
    expect(res.body.data.database).toBeDefined();
    expect(res.body.data.database.state).toBe('connected');
    expect(res.body.data.database.readyState).toBe(1);
  });

  it('should reject requests with missing x-metrics-token when METRICS_TOKEN is configured', async () => {
    const { config } = await import('../src/config/index.js');
    const { errorMiddleware } = await import('@hiprax/errors');

    const originalToken = config.METRICS_TOKEN;
    // Temporarily set METRICS_TOKEN
    (config as Record<string, unknown>).METRICS_TOKEN = VALID_METRICS_TOKEN;

    try {
      const metricsApp = express();
      metricsApp.get('/metrics', getMetrics);
      metricsApp.use(errorMiddleware);

      const res = await request(metricsApp).get('/metrics');
      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    } finally {
      (config as Record<string, unknown>).METRICS_TOKEN = originalToken;
    }
  });

  it('should reject requests with an invalid x-metrics-token', async () => {
    const { config } = await import('../src/config/index.js');
    const { errorMiddleware } = await import('@hiprax/errors');

    const originalToken = config.METRICS_TOKEN;
    (config as Record<string, unknown>).METRICS_TOKEN = VALID_METRICS_TOKEN;

    try {
      const metricsApp = express();
      metricsApp.get('/metrics', getMetrics);
      metricsApp.use(errorMiddleware);

      const res = await request(metricsApp)
        .get('/metrics')
        .set('x-metrics-token', 'wrong-token-value-abcdef');
      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    } finally {
      (config as Record<string, unknown>).METRICS_TOKEN = originalToken;
    }
  });

  it('should allow requests with a valid x-metrics-token', async () => {
    const { config } = await import('../src/config/index.js');
    const { errorMiddleware } = await import('@hiprax/errors');

    const originalToken = config.METRICS_TOKEN;
    (config as Record<string, unknown>).METRICS_TOKEN = VALID_METRICS_TOKEN;

    try {
      const metricsApp = express();
      metricsApp.get('/metrics', getMetrics);
      metricsApp.use(errorMiddleware);

      const res = await request(metricsApp)
        .get('/metrics')
        .set('x-metrics-token', VALID_METRICS_TOKEN);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(typeof res.body.data.uptime).toBe('number');
    } finally {
      (config as Record<string, unknown>).METRICS_TOKEN = originalToken;
    }
  });

  it('should reject requests with a wrong-length x-metrics-token (constant-time)', async () => {
    const { config } = await import('../src/config/index.js');
    const { errorMiddleware } = await import('@hiprax/errors');

    const originalToken = config.METRICS_TOKEN;
    (config as Record<string, unknown>).METRICS_TOKEN = VALID_METRICS_TOKEN;

    try {
      const metricsApp = express();
      metricsApp.get('/metrics', getMetrics);
      metricsApp.use(errorMiddleware);

      // Token shorter than expected
      const shortRes = await request(metricsApp).get('/metrics').set('x-metrics-token', 'short');
      expect(shortRes.status).toBe(403);

      // Token longer than expected
      const longRes = await request(metricsApp)
        .get('/metrics')
        .set('x-metrics-token', VALID_METRICS_TOKEN + '-extra-long-padding-added');
      expect(longRes.status).toBe(403);
    } finally {
      (config as Record<string, unknown>).METRICS_TOKEN = originalToken;
    }
  });

  it('should reject a non-string (array) x-metrics-token header via the typeof guard', async () => {
    // A DUPLICATED header surfaces as `string[]` in Node. The HTTP path can't
    // deliver that here (Node coalesces most repeated request headers into a
    // single comma-joined string, which would hit the length/content mismatch
    // branch, not the typeof branch — making this identical to the
    // header-absent test). So exercise the controller's
    // `typeof provided !== 'string'` guard directly with an array-valued header.
    const { config } = await import('../src/config/index.js');
    const originalToken = config.METRICS_TOKEN;
    (config as Record<string, unknown>).METRICS_TOKEN = VALID_METRICS_TOKEN;

    try {
      // Spy on the constant-time comparison: the typeof guard MUST short-circuit
      // BEFORE any buffer comparison. (An array header would otherwise flow into
      // Buffer.from + timingSafeEqual and still 403 via the length-mismatch
      // branch, so asserting the 403 status alone would NOT catch the guard's
      // removal — asserting the comparison never ran does.)
      const timingSpy = vi.spyOn(crypto, 'timingSafeEqual');
      const req = { headers: { 'x-metrics-token': ['a', 'b'] } } as unknown as Request;
      let sentStatus: number | null = null;
      const res = {
        status(code: number) {
          sentStatus = code;
          return this;
        },
        json() {
          return this;
        },
      } as unknown as Response;
      let capturedErr: unknown;
      const next: NextFunction = (err?: unknown) => {
        capturedErr = err;
      };

      try {
        await getMetrics(req, res, next);
        await Promise.resolve(); // flush any microtask before asserting

        // Rejected before any success response is produced...
        expect(capturedErr).toBeDefined();
        expect((capturedErr as { statusCode?: number }).statusCode).toBe(403);
        expect(sentStatus).toBeNull();
        // ...and rejected by the typeof guard, NOT by the buffer comparison.
        expect(timingSpy).not.toHaveBeenCalled();
      } finally {
        timingSpy.mockRestore();
      }
    } finally {
      (config as Record<string, unknown>).METRICS_TOKEN = originalToken;
    }
  });

  it('should not register the /metrics route when METRICS_TOKEN is not set', async () => {
    // The main app does not set METRICS_TOKEN in test, so the route should 404
    await createTestUser();
    const res = await request(app).get('/api/v1/metrics');
    expect(res.status).toBe(404);
  });
});
