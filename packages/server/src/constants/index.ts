/**
 * Server-side constants shared across controllers.
 */

export const REFRESH_COOKIE_NAME = 'refreshToken';

/**
 * Cookie carrying the raw trusted-device token that lets a 2FA account skip the
 * 2FA step at its next login. Scoped to `path: '/api/v1/auth'` (narrower than the
 * refresh cookie's `/api/v1`) so the browser only ever sends it to the auth
 * endpoints that consume it — least privilege. The raw token lives ONLY in this
 * cookie; the server stores just its SHA-256.
 */
export const TRUSTED_DEVICE_COOKIE_NAME = 'trustedDevice';
