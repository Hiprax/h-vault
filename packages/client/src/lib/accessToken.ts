/**
 * Reading the client's own access token.
 *
 * The access token is a JWT the server has already signed and will verify again
 * on every request. Nothing here is a security check — it cannot be, since the
 * payload is only base64 and the client holds no key. It exists so the client can
 * answer one cheap question without a round-trip: *is the token I am holding still
 * worth sending?*
 */

/**
 * Decode a JWT's payload without verifying it. Returns `null` for anything that
 * is not a well-formed three-part token with a JSON object payload.
 *
 * Handles base64url (`-`/`_`) and missing `=` padding, both of which `atob`
 * rejects but which are normal in a JWT.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  const payload = parts[1];
  if (parts.length !== 3 || !payload) return null;

  try {
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    // `atob` requires the length to be a multiple of 4; JWTs strip the padding.
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    const parsed: unknown = JSON.parse(atob(padded));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    // Malformed base64, malformed JSON — either way there is nothing to read.
    return null;
  }
}

/**
 * Margin, in milliseconds, by which a token must outlive "now" to count as
 * usable. Covers the request's own flight time plus any clock skew between the
 * browser and the server, so we never send a token that expires mid-flight and
 * take a 401 we could have avoided.
 */
export const ACCESS_TOKEN_FRESHNESS_MARGIN_MS = 60_000;

/**
 * Whether `token` can be used right now, i.e. it parses and has more than
 * {@link ACCESS_TOKEN_FRESHNESS_MARGIN_MS} of life left.
 *
 * **Fails closed.** A token that is absent, unparseable, or carries no numeric
 * `exp` returns `false`, so the caller refreshes. The only way to get `true` is a
 * token that demonstrably has time left — which is what makes it safe to skip a
 * refresh on the strength of this.
 *
 * The motivating case is the unlock screen. `authStore.lock()` deliberately keeps
 * `accessToken` set (the session stays alive across a lock; only key material is
 * zeroed), so after a short auto-lock the token is typically still valid for
 * minutes. Refreshing anyway — which is what the unlock screen used to do
 * unconditionally, on every attempt — spent a rate-limit slot, rotated the
 * refresh-token cookie, invalidated the CSRF token, and thereby forced an extra
 * 403-and-replay round-trip, all to obtain a token no better than the one already
 * in hand.
 */
export function isAccessTokenUsable(
  token: string | null | undefined,
  nowMs: number = Date.now(),
): boolean {
  if (!token) return false;

  const payload = decodeJwtPayload(token);
  if (!payload) return false;

  const exp = payload.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return false;

  return exp * 1000 - nowMs > ACCESS_TOKEN_FRESHNESS_MARGIN_MS;
}
