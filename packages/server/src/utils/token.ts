import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import { config } from '../config/index.js';

/**
 * Derives a purpose-specific signing key from the base secret using HMAC-SHA256.
 * Each token purpose (email_verification, password_reset, 2fa_temp, account_unlock)
 * gets its own derived key so that a compromised token of one type cannot be used
 * to forge tokens of another type.
 *
 * @param secret  The base secret (e.g. JWT_REFRESH_SECRET).
 * @param purpose The token purpose string used as the HMAC message.
 * @returns A hex-encoded derived key suitable for use as a JWT signing secret.
 */
export function derivePurposeKey(secret: string, purpose: string): string {
  return crypto.createHmac('sha256', secret).update(purpose).digest('hex');
}

/**
 * Signs a short-lived JWT access token containing the user ID as the
 * standard `sub` (subject) claim.
 *
 * @param userId  The unique identifier of the authenticated user.
 * @returns A signed JWT string.
 */
export function generateAccessToken(userId: string): string {
  const expiresIn = config.JWT_ACCESS_EXPIRY as SignOptions['expiresIn'];
  return jwt.sign({ userId }, config.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    subject: userId,
    expiresIn,
  } as SignOptions);
}

/**
 * Generates a cryptographically secure random token suitable for use as a
 * refresh token. The returned value is a 64-byte hex string (128 characters).
 */
export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString('hex');
}

/**
 * Produces a SHA-256 hex digest of the given token.
 * Use this to hash refresh tokens before storing them in the database so
 * that raw token values are never persisted.
 *
 * @param token  The raw token string to hash.
 * @returns The hex-encoded SHA-256 hash.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}
