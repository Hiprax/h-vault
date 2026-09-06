import type { Request } from 'express';

/**
 * Reads a request cookie, yielding it ONLY when it is a non-empty string.
 *
 * `req.cookies[name]` is genuinely `unknown`, not `string | undefined`, and the
 * types Express ships do not say so. `app.ts` mounts `cookieParser()`, whose
 * `JSONCookies` step walks every parsed cookie and REPLACES the raw string with
 * `JSON.parse(value.slice(2))` for any `j:`-prefixed value whose parse result is
 * truthy (`node_modules/cookie-parser/index.js:102-118`). A client that sends
 * `refreshToken=j:{"a":1}` therefore hands the handler a plain object;
 * `j:1` hands it a number; `j:[1,2]` an array; `j:true` a boolean. Only a falsy
 * parse (`j:0`, `j:false`, `j:null`) is left as the raw string it arrived as.
 *
 * That matters because every consumer here immediately feeds the value to
 * `hashToken`, i.e. `createHash('sha256').update(value)`, which throws
 * `ERR_INVALID_ARG_TYPE` on anything that is not a string / Buffer / TypedArray /
 * DataView. Casting instead of narrowing turned six handlers — `login`'s
 * trusted-device read, `refresh`, `logout`, `logoutAll`, `disable2fa` and
 * `listSessions` — into unhandled 500s on a value any client can set, and left
 * `disable2fa` half-applied: the throw landed between the `twoFactorEnabled: false`
 * write and the session/trusted-device revocations that must accompany it.
 *
 * The contract is deliberately total: **a malformed cookie is indistinguishable
 * from an absent one.** Not a 400, which would tell an attacker their probe was
 * understood; not a 500, which is the bug. Every call site already treats the
 * empty string as absent (`if (token)`, `currentToken ? … : null`), so the
 * `length > 0` clause preserves that exactly rather than introducing a new case.
 *
 * SOLE definition of this narrowing. `middleware/csrf.ts` reads the refresh
 * cookie as well — when it mints a token, and again when it validates one on a
 * state-changing request — and it got the guard right by hand before the
 * controllers did; it now reads through here so the two cannot drift, since a
 * second copy is a second place for someone to "simplify" it back into a cast.
 *
 * One consequence of "malformed == absent" is worth stating rather than
 * discovering: on `logoutAll`, and on `disable2fa`'s `revokeFilter`, absent means
 * no session is spared, so a caller who sends a malformed cookie revokes their
 * own current session along with the rest. That is the right trade here — a
 * wider-than-intended revocation of the caller's OWN sessions, against a crash —
 * and it cannot reach another account, because both filters are scoped to the
 * `userId` the bearer token authenticated.
 */
export function readStringCookie(req: Request, name: string): string | undefined {
  const value: unknown = req.cookies[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
