import { test, expect } from '@playwright/test';
import * as OTPAuth from 'otpauth';
import { createAuthenticatedUser, authMutate, getCsrf, type AuthenticatedUser } from './helpers';

/**
 * Two-Factor Authentication E2E tests.
 *
 * Covers the full 2FA lifecycle: setup, verify, login with TOTP, backup codes,
 * regenerate backup codes, and disable. Also tests auth guard rejections.
 *
 * Uses the otpauth library to generate valid TOTP codes at test time.
 */

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Extracts the TOTP secret from the 2FA setup response and creates a TOTP instance. */
function createTOTP(secret: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: 'H-Vault',
    label: 'test',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

/** Sets up 2FA for a user: calls setup, generates TOTP, verifies. Returns secret + backup codes. */
async function setup2FA(
  request: Parameters<typeof authMutate>[0],
  user: AuthenticatedUser,
): Promise<{ secret: string; backupCodes: string[]; totp: OTPAuth.TOTP }> {
  // 1. Setup — get secret
  const setupRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/setup', {
    password: user.authHash,
  });
  expect(setupRes.ok()).toBe(true);
  const setupBody = (await setupRes.json()) as {
    data: { secret: string; qrCode: string };
  };
  const secret = setupBody.data.secret;
  expect(secret).toBeDefined();
  expect(secret.length).toBeGreaterThan(0);

  const totp = createTOTP(secret);

  // 2. Verify — activate 2FA with a valid TOTP code
  const code = totp.generate();
  const verifyRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/verify', {
    code,
  });
  expect(verifyRes.ok()).toBe(true);
  const verifyBody = (await verifyRes.json()) as {
    data: { backupCodes: string[] };
  };
  expect(verifyBody.data.backupCodes.length).toBeGreaterThan(0);

  return { secret, backupCodes: verifyBody.data.backupCodes, totp };
}

// ─── Auth Guard Tests ───────────────────────────────────────────────────────

test.describe('2FA Auth Guards', () => {
  test('should reject 2FA setup without authentication', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.post('/api/v1/user/2fa/setup', {
      data: { password: 'test-auth-hash' },
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    });
    expect(response.status()).toBe(401);
  });

  test('should reject 2FA verify without authentication', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.post('/api/v1/user/2fa/verify', {
      data: { code: '123456' },
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    });
    expect(response.status()).toBe(401);
  });

  test('should reject 2FA disable without authentication', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.delete('/api/v1/user/2fa', {
      data: { code: '123456', password: 'test-auth-hash' },
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    });
    expect(response.status()).toBe(401);
  });

  test('should reject 2FA login with invalid temp token', async ({ request }) => {
    const csrf = await getCsrf(request);
    const response = await request.post('/api/v1/auth/login/2fa', {
      data: { tempToken: 'invalid-token', code: '123456' },
      headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    });
    expect(response.status()).toBe(401);
  });
});

// ─── Full 2FA Lifecycle ─────────────────────────────────────────────────────

test.describe('2FA Setup and Verification', () => {
  test('should setup 2FA and return secret and QR code', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const setupRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/setup', {
      password: user.authHash,
    });
    expect(setupRes.ok()).toBe(true);

    const body = (await setupRes.json()) as {
      success: boolean;
      data: { secret: string; otpauthUri: string; qrCodeDataUrl: string };
    };
    expect(body.success).toBe(true);
    expect(body.data.secret).toBeDefined();
    expect(body.data.secret.length).toBeGreaterThan(0);
    expect(body.data.otpauthUri).toBeDefined();
  });

  test('should reject 2FA setup with wrong password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/user/2fa/setup', {
      password: 'wrong-password-hash',
    });
    expect(res.status()).toBe(401);
  });

  test('should verify 2FA with valid TOTP code and return backup codes', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { backupCodes } = await setup2FA(request, user);

    // Backup codes should be returned
    expect(backupCodes.length).toBeGreaterThan(0);
    // Each backup code should be a non-empty string
    for (const code of backupCodes) {
      expect(code.length).toBeGreaterThan(0);
    }
  });

  test('should reject verification with invalid TOTP code', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Setup first (get secret)
    await authMutate(request, user, 'post', '/api/v1/user/2fa/setup', {
      password: user.authHash,
    });

    // Verify with wrong code
    const verifyRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/verify', {
      code: '000000',
    });
    expect(verifyRes.ok()).toBe(false);
  });
});

// ─── 2FA Login Flow ─────────────────────────────────────────────────────────

test.describe('2FA Login Flow', () => {
  test('should require 2FA code when logging in with 2FA enabled', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setup2FA(request, user);

    // Logout first
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Attempt login — should return tempToken (2FA required)
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });

    // Login with 2FA enabled should return 200 with twoFactorRequired flag
    expect(loginRes.ok()).toBe(true);
    const loginBody = (await loginRes.json()) as {
      data: { twoFactorRequired: boolean; tempToken: string };
    };
    expect(loginBody.data.twoFactorRequired).toBe(true);
    expect(loginBody.data.tempToken).toBeDefined();
  });

  test('should complete login with valid TOTP code', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { totp } = await setup2FA(request, user);

    // Logout
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Login — get temp token
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    const loginBody = (await loginRes.json()) as {
      data: { tempToken: string };
    };

    // Complete 2FA login
    // Generate code for the next time period to avoid TOTP replay protection
    // (setup2FA already consumed the current time step's code during verification)
    const code = totp.generate({ timestamp: Date.now() + 30_000 });
    const tfaCsrf = await getCsrf(request);
    const tfaRes = await request.post('/api/v1/auth/login/2fa', {
      data: { tempToken: loginBody.data.tempToken, code },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf,
      },
    });
    expect(tfaRes.ok()).toBe(true);

    const tfaBody = (await tfaRes.json()) as {
      data: { accessToken: string };
    };
    expect(tfaBody.data.accessToken).toBeDefined();
  });

  test('should login with backup code when 2FA is enabled', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { backupCodes } = await setup2FA(request, user);

    // Logout
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Login — get temp token
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    const loginBody = (await loginRes.json()) as {
      data: { tempToken: string };
    };

    // Use backup code (the `code` field accepts both TOTP and backup codes)
    const tfaCsrf = await getCsrf(request);
    const tfaRes = await request.post('/api/v1/auth/login/2fa', {
      data: {
        tempToken: loginBody.data.tempToken,
        code: backupCodes[0],
      },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf,
      },
    });
    expect(tfaRes.ok()).toBe(true);

    const tfaBody = (await tfaRes.json()) as {
      data: { accessToken: string };
    };
    expect(tfaBody.data.accessToken).toBeDefined();
  });

  test('should reject 2FA login with wrong TOTP code', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setup2FA(request, user);

    // Logout
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Login — get temp token
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    const loginBody = (await loginRes.json()) as {
      data: { tempToken: string };
    };

    // Wrong code
    const tfaCsrf = await getCsrf(request);
    const tfaRes = await request.post('/api/v1/auth/login/2fa', {
      data: { tempToken: loginBody.data.tempToken, code: '000000' },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf,
      },
    });
    expect(tfaRes.ok()).toBe(false);
  });
});

// ─── Backup Codes ───────────────────────────────────────────────────────────

test.describe('2FA Backup Codes', () => {
  test('should regenerate backup codes', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { backupCodes: originalCodes, totp } = await setup2FA(request, user);

    // Regenerate backup codes (requires TOTP code when 2FA is enabled)
    const code = totp.generate({ timestamp: Date.now() + 30_000 });
    const regenRes = await authMutate(
      request,
      user,
      'post',
      '/api/v1/user/2fa/regenerate-backup-codes',
      { password: user.authHash, code },
    );
    expect(regenRes.ok()).toBe(true);

    const regenBody = (await regenRes.json()) as {
      data: { backupCodes: string[] };
    };
    expect(regenBody.data.backupCodes.length).toBeGreaterThan(0);

    // New codes should be different from original
    const newCodes = regenBody.data.backupCodes;
    expect(newCodes).not.toEqual(originalCodes);
  });

  test('should invalidate old backup codes after regeneration', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { backupCodes: originalCodes, totp } = await setup2FA(request, user);

    // Regenerate (requires TOTP code for next time period)
    const code = totp.generate({ timestamp: Date.now() + 30_000 });
    await authMutate(request, user, 'post', '/api/v1/user/2fa/regenerate-backup-codes', {
      password: user.authHash,
      code,
    });

    // Logout
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Login — get temp token
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    const loginBody = (await loginRes.json()) as {
      data: { tempToken: string };
    };

    // Try old backup code — should fail
    const tfaCsrf = await getCsrf(request);
    const tfaRes = await request.post('/api/v1/auth/login/2fa', {
      data: {
        tempToken: loginBody.data.tempToken,
        backupCode: originalCodes[0],
      },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf,
      },
    });
    expect(tfaRes.ok()).toBe(false);
  });

  test('should reject regeneration with wrong password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setup2FA(request, user);

    const res = await authMutate(
      request,
      user,
      'post',
      '/api/v1/user/2fa/regenerate-backup-codes',
      { password: 'wrong-password' },
    );
    expect(res.status()).toBe(401);
  });
});

// ─── Disable 2FA ────────────────────────────────────────────────────────────

test.describe('2FA Disable', () => {
  test('should disable 2FA with valid TOTP code and password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { totp } = await setup2FA(request, user);

    // Generate code for next time period to avoid replay protection
    const code = totp.generate({ timestamp: Date.now() + 30_000 });
    const disableRes = await authMutate(request, user, 'delete', '/api/v1/user/2fa', {
      code,
      password: user.authHash,
    });
    expect(disableRes.ok()).toBe(true);

    // Logout and login — should NOT require 2FA anymore
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    expect(loginRes.ok()).toBe(true);

    const loginBody = (await loginRes.json()) as {
      data: { accessToken?: string; twoFactorRequired?: boolean };
    };
    // Should return access token directly, no 2FA required
    expect(loginBody.data.accessToken).toBeDefined();
    expect(loginBody.data.twoFactorRequired).toBeFalsy();
  });

  test('should reject disabling 2FA with wrong password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const { totp } = await setup2FA(request, user);

    const code = totp.generate({ timestamp: Date.now() + 30_000 });
    const res = await authMutate(request, user, 'delete', '/api/v1/user/2fa', {
      code,
      password: 'wrong-password',
    });
    expect(res.status()).toBe(401);
  });

  test('should reject disabling 2FA with wrong TOTP code', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setup2FA(request, user);

    const res = await authMutate(request, user, 'delete', '/api/v1/user/2fa', {
      code: '000000',
      password: user.authHash,
    });
    expect(res.ok()).toBe(false);
  });
});

// ─── TOTP Replay Protection ────────────────────────────────────────────────

test.describe('TOTP Replay Protection', () => {
  test('should reject a reused TOTP code within the same time window', async ({
    request,
  }, testInfo) => {
    testInfo.setTimeout(60_000);

    const user = await createAuthenticatedUser(request);
    const { totp } = await setup2FA(request, user);

    // Logout so we can test the login flow
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Generate a TOTP code for the next time step (30s ahead of NOW, not setup time).
    // setup2FA consumed a time step during verify. By generating at Date.now() + 30_000
    // right before login, we ensure the code is for a time step after what setup2FA used.
    // The TOTP window is +-1 step (30s), so +30_000 is within the server's acceptance window.
    const timestamp = Date.now() + 30_000;
    const code = totp.generate({ timestamp });

    // First login attempt — get temp token and complete 2FA
    const loginCsrf1 = await getCsrf(request);
    const loginRes1 = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf1,
      },
    });
    expect(loginRes1.ok()).toBe(true);
    const loginBody1 = (await loginRes1.json()) as {
      data: { tempToken: string };
    };

    // Complete 2FA with the code — should succeed
    const tfaCsrf1 = await getCsrf(request);
    const tfaRes1 = await request.post('/api/v1/auth/login/2fa', {
      data: { tempToken: loginBody1.data.tempToken, code },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf1,
      },
    });
    expect(tfaRes1.ok()).toBe(true);
    const tfaBody1 = (await tfaRes1.json()) as {
      data: { accessToken: string };
    };
    expect(tfaBody1.data.accessToken).toBeDefined();

    // Logout to start a fresh session
    const logoutUser = { ...user, accessToken: tfaBody1.data.accessToken };
    await authMutate(request, logoutUser, 'post', '/api/v1/auth/logout');

    // Second login attempt with the SAME code (same timestamp = same time step)
    const loginCsrf2 = await getCsrf(request);
    const loginRes2 = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf2,
      },
    });
    expect(loginRes2.ok()).toBe(true);
    const loginBody2 = (await loginRes2.json()) as {
      data: { tempToken: string };
    };

    // Attempt 2FA with the SAME code — should be rejected (replay protection)
    const tfaCsrf2 = await getCsrf(request);
    const tfaRes2 = await request.post('/api/v1/auth/login/2fa', {
      data: { tempToken: loginBody2.data.tempToken, code },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf2,
      },
    });
    expect(tfaRes2.ok()).toBe(false);
    expect(tfaRes2.status()).toBeGreaterThanOrEqual(400);
  });
});

// ─── Backup Code Invalidation After Regeneration ────────────────────────────

test.describe('Backup Code Invalidation After Regeneration', () => {
  test('should reject old backup code and accept new one after regeneration', async ({
    request,
  }, testInfo) => {
    testInfo.setTimeout(60_000);
    const user = await createAuthenticatedUser(request);
    const { backupCodes: originalCodes, totp } = await setup2FA(request, user);

    // Regenerate backup codes (requires password and TOTP code)
    const regenCode = totp.generate({ timestamp: Date.now() + 30_000 });
    const regenRes = await authMutate(
      request,
      user,
      'post',
      '/api/v1/user/2fa/regenerate-backup-codes',
      { password: user.authHash, code: regenCode },
    );
    expect(regenRes.ok()).toBe(true);
    const regenBody = (await regenRes.json()) as {
      data: { backupCodes: string[] };
    };
    const newCodes = regenBody.data.backupCodes;
    expect(newCodes.length).toBeGreaterThan(0);

    // Logout
    await authMutate(request, user, 'post', '/api/v1/auth/logout');

    // Attempt login with an OLD backup code — should fail
    const loginCsrf1 = await getCsrf(request);
    const loginRes1 = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf1,
      },
    });
    expect(loginRes1.ok()).toBe(true);
    const loginBody1 = (await loginRes1.json()) as {
      data: { tempToken: string };
    };

    const tfaCsrf1 = await getCsrf(request);
    const oldCodeRes = await request.post('/api/v1/auth/login/2fa', {
      data: {
        tempToken: loginBody1.data.tempToken,
        code: originalCodes[0],
      },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf1,
      },
    });
    expect(oldCodeRes.ok()).toBe(false);

    // Attempt login with a NEW backup code — should succeed
    // Need a fresh temp token (the old one may still be valid but let's get a clean one)
    const loginCsrf2 = await getCsrf(request);
    const loginRes2 = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf2,
      },
    });
    expect(loginRes2.ok()).toBe(true);
    const loginBody2 = (await loginRes2.json()) as {
      data: { tempToken: string };
    };

    const tfaCsrf2 = await getCsrf(request);
    const newCodeRes = await request.post('/api/v1/auth/login/2fa', {
      data: {
        tempToken: loginBody2.data.tempToken,
        code: newCodes[0],
      },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': tfaCsrf2,
      },
    });
    expect(newCodeRes.ok()).toBe(true);
    const newCodeBody = (await newCodeRes.json()) as {
      data: { accessToken: string };
    };
    expect(newCodeBody.data.accessToken).toBeDefined();
  });
});
