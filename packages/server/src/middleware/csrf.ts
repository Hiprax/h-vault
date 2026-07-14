/**
 * Custom CSRF protection middleware.
 *
 * Uses HMAC-based token validation on the `x-csrf-token` header. This avoids
 * the double-submit cookie pattern which breaks when a development proxy
 * (e.g. Vite) sits between the browser and the API server.
 *
 * Security model:
 * - The CSRF token is an HMAC (keyed with the server secret) over a random
 *   nonce plus a session identifier so the token is bound to the requesting
 *   session and cannot ride into a different session after logout/login.
 * - For authenticated requests the session identifier is the SHA-256 hash of
 *   the active refresh-token cookie. For unauthenticated requests it is a
 *   random per-token value with an `anon:` prefix so anonymous tokens are
 *   single-session by construction.
 * - Only same-origin code can read the token from the `/csrf-token` response
 *   (enforced by the browser's same-origin policy), so a cross-origin
 *   attacker cannot obtain a valid token.
 * - A cookie is still set for backward compatibility with tests that rely on
 *   the double-submit pattern, but it is NOT required for validation.
 */

import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { httpErrors } from '@hiprax/errors';
import { config, isProduction } from '../config/index.js';
import { REFRESH_COOKIE_NAME } from '../constants/index.js';
import { hashToken } from '../utils/token.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_COOKIE = '__csrf';
const CSRF_TOKEN_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
const ANON_SESSION_PREFIX = 'anon:';

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

/**
 * Derives a stable session identifier from the active refresh-token cookie.
 * Falls back to a random anonymous identifier when no refresh cookie is
 * present so that the resulting token is bound to a single anonymous flow.
 */
function resolveSessionId(req: Request): string {
  const refreshToken: unknown = req.cookies[REFRESH_COOKIE_NAME];
  if (typeof refreshToken === 'string' && refreshToken.length > 0) {
    return hashToken(refreshToken);
  }
  return `${ANON_SESSION_PREFIX}${crypto.randomBytes(16).toString('hex')}`;
}

function createToken(sessionId: string): string {
  const timestamp = Date.now().toString(36);
  const randomValue = crypto.randomBytes(32).toString('hex');
  const payload = `${timestamp}:${sessionId}:${randomValue}`;
  const hmac = crypto.createHmac('sha256', config.SESSION_SECRET).update(payload).digest('hex');
  return `${hmac}.${payload}`;
}

/**
 * Constant-time CSRF token verification.
 *
 * Token format: `HMAC(timestamp:sessionId:randomValue).timestamp:sessionId:randomValue`
 *
 * Always computes the HMAC and performs the timing-safe comparison regardless
 * of whether the token format is valid. This prevents timing side-channels
 * that could leak information about valid token structure.
 */
function verifyToken(token: string, currentSessionId: string): boolean {
  const dotIndex = token.indexOf('.');
  // Extract parts but always continue to the HMAC comparison
  const receivedHmac = dotIndex > 0 ? token.slice(0, dotIndex) : '';
  const payload = dotIndex > 0 ? token.slice(dotIndex + 1) : '';

  // Always compute HMAC even for malformed input to prevent timing leaks
  const expectedHmac = crypto
    .createHmac('sha256', config.SESSION_SECRET)
    .update(payload)
    .digest('hex');

  // Pad to equal length for timingSafeEqual (which requires equal-length buffers)
  const HMAC_HEX_LENGTH = 64; // SHA-256 hex digest is always 64 chars
  const a = Buffer.alloc(HMAC_HEX_LENGTH);
  const b = Buffer.alloc(HMAC_HEX_LENGTH);
  Buffer.from(expectedHmac, 'utf8').copy(a);
  Buffer.from(receivedHmac.slice(0, HMAC_HEX_LENGTH), 'utf8').copy(b);

  const hmacMatch = crypto.timingSafeEqual(a, b);

  // Validate structure
  const formatValid = dotIndex > 0 && receivedHmac.length > 0 && payload.length > 0;

  // Parse payload — format: timestamp:sessionId:randomValue
  const firstColon = payload.indexOf(':');
  const lastColon = payload.lastIndexOf(':');
  const hasSessionField = firstColon > 0 && lastColon > firstColon;
  const timestampStr = hasSessionField ? payload.slice(0, firstColon) : '';
  const sessionId = hasSessionField ? payload.slice(firstColon + 1, lastColon) : '';
  const timestamp = timestampStr ? parseInt(timestampStr, 36) : 0;
  const now = Date.now();
  const tokenAge = now - timestamp;
  const timestampValid = timestamp > 0 && tokenAge >= 0 && tokenAge <= CSRF_TOKEN_MAX_AGE_MS;

  // Bind the token to the active session. Anonymous tokens carry a unique
  // random session identifier so they can only be used while still anonymous;
  // authenticated tokens carry hashToken(refreshToken) so they expire when
  // the refresh token rotates or the session ends.
  const sessionMatch = constantTimeStringEqual(sessionId, currentSessionId);

  return hmacMatch && formatValid && timestampValid && sessionMatch;
}

/**
 * Constant-time string equality check that pads to the longer length so that
 * comparison time does not depend on the input length.
 */
function constantTimeStringEqual(a: string, b: string): boolean {
  const max = Math.max(a.length, b.length, 1);
  const ba = Buffer.alloc(max);
  const bb = Buffer.alloc(max);
  Buffer.from(a, 'utf8').copy(ba);
  Buffer.from(b, 'utf8').copy(bb);
  return crypto.timingSafeEqual(ba, bb) && a.length === b.length;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * CSRF protection middleware.
 *
 * - Safe methods (GET, HEAD, OPTIONS) are allowed through.
 * - State-changing methods must include a valid `x-csrf-token` header.
 */
export function doubleCsrfProtection(req: Request, _res: Response, next: NextFunction): void {
  if (SAFE_METHODS.has(req.method)) {
    next();
    return;
  }

  const headerToken = req.headers['x-csrf-token'] as string | undefined;
  if (!headerToken) {
    next(httpErrors.forbidden('invalid csrf token'));
    return;
  }

  // Authenticated requests bind the token to the active refresh-token cookie.
  // For unauthenticated requests the token must carry the `anon:` session
  // prefix it was issued with, so we extract that prefix from the token
  // payload and require the token to verify against itself. This prevents an
  // anonymous token from continuing to validate after the refresh cookie
  // appears (e.g. after login/refresh in the same agent).
  const refreshToken: unknown = req.cookies[REFRESH_COOKIE_NAME];
  const expectedSessionId =
    typeof refreshToken === 'string' && refreshToken.length > 0
      ? hashToken(refreshToken)
      : extractAnonSessionId(headerToken);

  if (!verifyToken(headerToken, expectedSessionId)) {
    next(httpErrors.forbidden('invalid csrf token'));
    return;
  }

  next();
}

function extractAnonSessionId(token: string): string {
  const dotIndex = token.indexOf('.');
  if (dotIndex <= 0) return '';
  const payload = token.slice(dotIndex + 1);
  const firstColon = payload.indexOf(':');
  const lastColon = payload.lastIndexOf(':');
  if (firstColon <= 0 || lastColon <= firstColon) return '';
  const sessionField = payload.slice(firstColon + 1, lastColon);
  return sessionField.startsWith(ANON_SESSION_PREFIX) ? sessionField : '';
}

/**
 * Handler that returns a CSRF token for the client to use in subsequent
 * requests via the `x-csrf-token` header.
 */
export function csrfTokenHandler(req: Request, res: Response): void {
  const sessionId = resolveSessionId(req);
  const token = createToken(sessionId);

  // Set a cookie as well for tests that rely on the double-submit pattern.
  // maxAge matches the server-side token TTL (24h) so the cookie expires in
  // lockstep with the token and stale cookies do not accumulate.
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: true,
    sameSite: isProduction ? 'strict' : 'lax',
    secure: isProduction,
    path: '/',
    maxAge: CSRF_TOKEN_MAX_AGE_MS,
  });

  res.status(200).json({ success: true, data: { csrfToken: token } });
}

/**
 * Clears the CSRF cookie. Should be invoked at every transition that changes
 * the session identity (login, refresh rotation, logout, unlock verify) so
 * that a token bound to the previous session cannot ride into the new one.
 */
export function clearCsrfCookie(res: Response): void {
  res.clearCookie(CSRF_COOKIE, {
    httpOnly: true,
    sameSite: isProduction ? 'strict' : 'lax',
    secure: isProduction,
    path: '/',
  });
}
