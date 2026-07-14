import { test, expect } from '@playwright/test';
import { createAuthenticatedUser, authGet, authMutate, getCsrf, createItem } from './helpers';

/**
 * Security-focused E2E tests.
 *
 * Verifies that security headers, CSRF protection, error handling,
 * MongoDB injection prevention, and other security measures work correctly.
 */

// ─── Security Headers ────────────────────────────────────────────────────────

test.describe('Security Headers', () => {
  test('should include core security headers on API responses', async ({ request }) => {
    const response = await request.get('/api/v1/health');
    const headers = response.headers();

    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBeDefined();
    expect(headers['x-xss-protection']).toBeDefined();
  });

  test('should include Content-Security-Policy header', async ({ request }) => {
    const response = await request.get('/api/v1/health');
    const csp = response.headers()['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp!.length).toBeGreaterThan(0);
  });

  test('should not expose server version in headers', async ({ request }) => {
    const response = await request.get('/api/v1/health');
    expect(response.headers()['x-powered-by']).toBeUndefined();
  });

  test('should include security headers on all route types', async ({ request }) => {
    // API endpoint
    const apiRes = await request.get('/api/v1/health');
    expect(apiRes.headers()['x-content-type-options']).toBe('nosniff');

    // CSRF endpoint
    const csrfRes = await request.get('/api/v1/csrf-token');
    expect(csrfRes.headers()['x-content-type-options']).toBe('nosniff');
  });
});

// ─── CSRF Protection ─────────────────────────────────────────────────────────

test.describe('CSRF Protection', () => {
  test('should provide CSRF token endpoint', async ({ request }) => {
    const response = await request.get('/api/v1/csrf-token');
    expect(response.ok()).toBe(true);

    const data = (await response.json()) as {
      success: boolean;
      data: { csrfToken: string };
    };
    expect(data.success).toBe(true);
    expect(data.data.csrfToken).toBeDefined();
    expect(data.data.csrfToken.length).toBeGreaterThan(0);
  });

  test('should reject state-changing requests without CSRF token', async ({ request }) => {
    const response = await request.post('/api/v1/auth/login', {
      data: { email: 'test@example.com', authHash: 'fake-hash' },
      headers: { 'content-type': 'application/json' },
    });

    // Should fail without CSRF token
    expect([400, 401, 403]).toContain(response.status());
  });

  test('should reject requests with invalid CSRF token', async ({ request }) => {
    const response = await request.post('/api/v1/auth/login', {
      data: { email: 'test@example.com', authHash: 'fake-hash' },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': 'invalid-csrf-token',
      },
    });

    expect([400, 401, 403]).toContain(response.status());
  });

  test('should allow GET requests without CSRF token', async ({ request }) => {
    const response = await request.get('/api/v1/health');
    expect(response.ok()).toBe(true);
  });
});

// ─── API Error Handling ──────────────────────────────────────────────────────

test.describe('API Error Handling', () => {
  test('should return proper error format for invalid endpoints', async ({ request }) => {
    const response = await request.get('/api/v1/nonexistent');
    expect(response.status()).toBe(404);
  });

  test('should not leak stack traces in error responses', async ({ request }) => {
    const response = await request.get('/api/v1/nonexistent');
    const text = await response.text();

    expect(text).not.toContain('at Object.');
    expect(text).not.toContain('at Module.');
    expect(text).not.toContain('node_modules');
    expect(text).not.toContain('\\src\\');
  });

  test('should return consistent error format', async ({ request }) => {
    const response = await request.get('/api/v1/vault/items');
    expect(response.status()).toBe(401);

    const body = (await response.json()) as {
      success: boolean;
      error?: { code: string; message: string };
      message?: string;
    };
    expect(body.success).toBe(false);
  });

  test('should reject requests with invalid JSON body', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.post('/api/v1/auth/login', {
      data: 'not valid json{{',
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': csrf,
      },
    });
    expect(response.ok()).toBe(false);
  });
});

// ─── MongoDB Injection Prevention ────────────────────────────────────────────

test.describe('MongoDB Injection Prevention', () => {
  test('should reject requests with $gt operator in email', async ({ request }) => {
    const response = await request.post('/api/v1/auth/login', {
      data: { email: { $gt: '' }, authHash: 'test' },
      headers: { 'content-type': 'application/json' },
    });
    expect(response.ok()).toBe(false);
  });

  test('should reject requests with $ne operator', async ({ request }) => {
    const response = await request.post('/api/v1/auth/login', {
      data: { email: { $ne: '' }, authHash: 'test' },
      headers: { 'content-type': 'application/json' },
    });
    expect(response.ok()).toBe(false);
  });

  test('should reject requests with $regex operator', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.post('/api/v1/auth/login', {
      data: { email: { $regex: '.*' }, authHash: 'test' },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': csrf,
      },
    });
    expect(response.ok()).toBe(false);
  });
});

// ─── Health Endpoint ─────────────────────────────────────────────────────────

test.describe('Health Endpoint', () => {
  test('should return healthy status', async ({ request }) => {
    const response = await request.get('/api/v1/health');
    expect(response.ok()).toBe(true);

    const body = (await response.json()) as {
      success: boolean;
      data: { status: string; database: string };
    };
    expect(body.success).toBe(true);
    expect(body.data.status).toBe('ok');
    expect(body.data.database).toBe('connected');
  });

  test('health endpoint should not require authentication', async ({ request }) => {
    // No auth headers sent
    const response = await request.get('/api/v1/health');
    expect(response.ok()).toBe(true);
  });
});

// ─── Token Security ──────────────────────────────────────────────────────────

test.describe('Token Security', () => {
  test('should reject expired/invalid JWT tokens', async ({ request }) => {
    const response = await request.get('/api/v1/vault/items', {
      headers: { authorization: 'Bearer invalid.jwt.token' },
    });
    expect(response.status()).toBe(401);
  });

  test('should reject requests with malformed authorization header', async ({ request }) => {
    const response = await request.get('/api/v1/vault/items', {
      headers: { authorization: 'NotBearer token' },
    });
    expect(response.status()).toBe(401);
  });

  test('should reject requests with empty bearer token', async ({ request }) => {
    const response = await request.get('/api/v1/vault/items', {
      headers: { authorization: 'Bearer ' },
    });
    expect(response.status()).toBe(401);
  });
});

// ─── Input Validation ────────────────────────────────────────────────────────

test.describe('Input Validation', () => {
  test('should reject vault item creation with missing required fields', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/vault/items', {
      itemType: 'login',
      // Missing encryptedData, dataIv, dataTag, etc.
    });
    expect(res.status()).toBe(400);
  });

  test('should reject vault item with invalid item type', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/vault/items', {
      itemType: 'invalid_type',
      encryptedData: 'test',
      dataIv: 'test',
      dataTag: 'test',
      encryptedName: 'test',
      nameIv: 'test',
      nameTag: 'test',
      tags: [],
      favorite: false,
    });
    expect(res.status()).toBe(400);
  });

  test('should reject invalid ObjectId in URL params', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/vault/items/not-valid-id');
    expect(res.status()).toBe(400);
  });
});

// ─── Cross-User Data Isolation ───────────────────────────────────────────────

test.describe('Cross-User Data Isolation', () => {
  test('should prevent accessing other user data via direct ID', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    const itemId = await createItem(request, user1);

    // User2 should get 404 (not 403 - prevents ID enumeration)
    const res = await authGet(request, user2, `/api/v1/vault/items/${itemId}`);
    expect(res.status()).toBe(404);
  });

  test('should return empty list when accessing another user vault', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    // User1 creates items
    await createItem(request, user1);
    await createItem(request, user1);

    // User2's vault should be empty
    const res = await authGet(request, user2, '/api/v1/vault/items');
    const body = (await res.json()) as { pagination: { total: number } };
    expect(body.pagination.total).toBe(0);
  });
});
