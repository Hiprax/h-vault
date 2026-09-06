/**
 * A2 — a cookie value is only a value when it is a string.
 *
 * `app.ts` mounts `cookieParser()` with no secret, so only the JSON branch runs
 * (`node_modules/cookie-parser/index.js:69`). `JSONCookies` (`:103-118`) walks
 * every parsed cookie and REPLACES the raw string with `JSON.parse(value.slice(2))`
 * for any `j:`-prefixed value whose parse result is truthy:
 *
 *   `j:{"a":1}` -> `{ a: 1 }` (object)      `j:1`     -> `1` (number)
 *   `j:[1,2]`   -> `[1, 2]`   (array)       `j:true`  -> `true` (boolean)
 *
 * `req.cookies[name]` is therefore genuinely `unknown`, and a consumer that casts
 * it to `string | undefined` asserts something the runtime does not guarantee.
 * `hashToken` is `createHash('sha256').update(token)`, which throws
 * `ERR_INVALID_ARG_TYPE` on a non-string, so six handlers used to answer an
 * unhandled 500 to a value any client can set:
 *
 *   `login` (trusted-device read), `refresh`, `logout`, `logoutAll`,
 *   `disable2fa`, `listSessions`.
 *
 * The contract these tests pin is narrow and total: **a malformed cookie must be
 * indistinguishable from an absent one.** Not a 400, not a 500 — absent. That is
 * what `middleware/csrf.ts` already does at its own two read sites, and it is the
 * only reading that keeps a purely client-controlled value from selecting a code
 * path no unauthenticated caller should be able to select.
 *
 * `disable2fa` is the sharp one, and it gets its own describe block: the cookie
 * read sat AFTER the `twoFactorEnabled: false` write, so the throw left the
 * account with 2FA off, every refresh token from the 2FA-enabled regime still
 * live, every trusted device still honoured, and no `2fa_disable` audit row.
 *
 * Both halves are fixed — `utils/cookies.ts` narrows the read at all eight sites
 * that make one, and `disable2fa` now reads the request before it writes — so
 * everything below is a regression test, and the tense above is deliberate.
 *
 * NOTE on the `login` case: `authController.login` has no `refreshToken` read at
 * all — its cast is over the **`trustedDevice`** cookie, so that is the one the
 * test malforms. A malformed `refreshToken` is sent alongside it anyway, because
 * `middleware/csrf.ts` reads that cookie on every request and the test should
 * prove the whole request survives one, not just the handler.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

/**
 * Probe for the ORDERING half of this phase (5.3), which the type guard alone
 * cannot pin: once a malformed cookie can no longer throw, "read the cookie,
 * then write the flag" and "write the flag, then read the cookie" become
 * indistinguishable from the outside. So the failure is injected back in at the
 * one step that moved.
 *
 * `hashToken` is called TWICE per state-changing request that carries a refresh
 * cookie: once by `middleware/csrf.ts:155` while validating the token's session
 * binding, and once by the handler. Arming `throwOnCall = 2` therefore fails the
 * HANDLER's hash — exactly the throw `disable2fa` used to take mid-downgrade —
 * and leaves the middleware alone. `calls` is asserted alongside the outcome so
 * that if the middleware ever stops hashing, this test fails loudly rather than
 * quietly targeting the wrong call.
 *
 * Declared through `vi.hoisted` because the `vi.mock` factory below is hoisted
 * above the module-scope bindings it closes over.
 */
const probe = vi.hoisted(() => ({ calls: [] as string[], throwOnCall: 0 }));

vi.mock('../src/utils/token.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/token.js')>();
  return {
    ...actual,
    hashToken: (token: string): string => {
      probe.calls.push(token);
      if (probe.throwOnCall !== 0 && probe.calls.length === probe.throwOnCall) {
        throw new TypeError('simulated failure reading the request cookie');
      }
      return actual.hashToken(token);
    },
  };
});
import request from 'supertest';
import crypto from 'node:crypto';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { hashToken } from '../src/utils/token.js';
import { createTestUser, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const UA = 'A2CookieTypeGuards/1.0';

/**
 * Both shapes are exercised everywhere rather than one, because they fail at
 * different points: an object is truthy and reaches `hashToken`, while a number
 * is truthy AND would survive a `typeof value === 'object'` style narrowing. A
 * guard that admitted either would still be broken.
 */
const MALFORMED = [
  { label: 'j:{"a":1} (an object)', raw: 'j:{"a":1}' },
  { label: 'j:1 (a number)', raw: 'j:1' },
] as const;

/** Cookie header value for a malformed `refreshToken`, percent-encoded as a browser would. */
function refreshCookie(raw: string): string {
  return `refreshToken=${encodeURIComponent(raw)}`;
}

/** Cookie header value for a malformed `trustedDevice`. */
function trustedCookie(raw: string): string {
  return `trustedDevice=${encodeURIComponent(raw)}`;
}

const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/** Creates an email-verified user with 2FA enabled, and returns its TOTP secret. */
async function create2faUser(): Promise<{ user: TestUser; secret: Secret }> {
  const secret = new Secret();
  const user = await createTestUser({ emailVerified: true });
  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      // An old time step, so a genuinely valid code is not rejected as a replay.
      lastTotpTimestamp: 1,
    },
  });
  return { user, secret };
}

function currentCode(secret: Secret): string {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret }).generate();
}

/** Seeds a second live refresh row so "revoked everything" is observable, not vacuous. */
async function seedExtraSession(userId: string): Promise<string> {
  const raw = crypto.randomBytes(64).toString('hex');
  await RefreshToken.create({
    userId,
    tokenHash: hashToken(raw),
    familyId: crypto.randomUUID(),
    deviceInfo: { userAgent: 'other-device', ip: '127.0.0.1', fingerprint: 'other' },
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  return raw;
}

async function seedTrustedDevice(userId: string): Promise<void> {
  await TrustedDevice.create({
    userId,
    tokenHash: hashToken(crypto.randomBytes(32).toString('hex')),
    deviceInfo: { userAgent: 'other-device', ip: '127.0.0.1', fingerprint: 'other' },
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  });
}

/** Every `Set-Cookie` value on a response, as a flat array. */
function setCookies(res: request.Response): string[] {
  const header = res.headers['set-cookie'] as string | string[] | undefined;
  if (!header) return [];
  return Array.isArray(header) ? header : [header];
}

describe('A2 — a malformed cookie must behave exactly as an absent one', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
    probe.calls.length = 0;
    probe.throwOnCall = 0;
  });

  describe.each(MALFORMED)('with a $label refresh cookie', ({ raw }) => {
    it('POST /auth/refresh answers 401 "not provided", never a 500, and mints no session', async () => {
      const { token, cookie } = await getCsrf(agent, refreshCookie(raw));

      const res = await agent
        .post(`${API}/auth/refresh`)
        .set('User-Agent', UA)
        .set('x-csrf-token', token)
        .set('Cookie', `${cookie}; ${refreshCookie(raw)}`)
        .send({});

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Refresh token not provided');
      // The negative, and it is a real discriminator rather than decoration:
      // a cookie merely COERCED to a string (`String({a:1})`) would fall through
      // to the `TOKEN_INVALID` branch, which DOES clear the cookie. "Absent"
      // throws before that, so nothing is cleared and no session is minted.
      expect(setCookies(res).some((c) => c.startsWith('refreshToken='))).toBe(false);
    });

    it('POST /auth/logout succeeds and leaves the caller’s real refresh row intact', async () => {
      const user = await createTestUser();
      await seedTrustedDevice(user.id);
      const before = await RefreshToken.countDocuments({ userId: user.id });
      expect(before).toBe(1);

      const { token, cookie } = await getCsrf(agent, refreshCookie(raw));
      const res = await agent
        .post(`${API}/auth/logout`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('x-csrf-token', token)
        .set('Cookie', `${cookie}; ${refreshCookie(raw)}`)
        .send({});

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // An ABSENT cookie names no row, so `logout` deletes nothing — the negative
      // that separates "treated as absent" from "treated as some other token".
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
      expect(await RefreshToken.exists({ tokenHash: hashToken(user.refreshToken) })).not.toBeNull();

      // The single-session logout still audits, and still does NOT touch trust —
      // `revokeTrustedDevices` is deliberately absent from this handler, unlike
      // `logoutAll`, whose sibling test asserts the mirror (0).
      const logoutRows = await AuditLog.find({ userId: user.id, action: 'logout' }).lean();
      expect(logoutRows).toHaveLength(1);
      expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(1);
    });

    it('POST /auth/logout-all revokes every session and every trusted device', async () => {
      const user = await createTestUser();
      await seedExtraSession(user.id);
      await seedTrustedDevice(user.id);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(2);

      const { token, cookie } = await getCsrf(agent, refreshCookie(raw));
      const res = await agent
        .post(`${API}/auth/logout-all`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('x-csrf-token', token)
        .set('Cookie', `${cookie}; ${refreshCookie(raw)}`)
        .send({});

      expect(res.status).toBe(200);
      // No cookie names a session to spare, so EVERY row goes — including the
      // caller's own. That is what an absent cookie has always meant here.
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
      expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);

      // The handler records how many it revoked, which is the sharpest available
      // statement that the malformed cookie named NO row: had it somehow matched
      // one, the `$ne` exclusion would have spared it and this would read 1.
      const revokeRows = await AuditLog.find({ userId: user.id, action: 'session_revoke' }).lean();
      expect(revokeRows).toHaveLength(1);
      expect(revokeRows[0]?.metadata).toMatchObject({ sessionsRevoked: 2 });
    });

    it('GET /user/sessions lists the sessions and marks none of them current', async () => {
      const user = await createTestUser();
      await seedExtraSession(user.id);

      const res = await agent
        .get(`${API}/user/sessions`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('Cookie', refreshCookie(raw));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(2);
      // The negative: an unreadable cookie must never be able to point at a row.
      // Compared as a list rather than with `.every`, so a failure names which.
      expect(res.body.data.map((s: { current: boolean }) => s.current)).toEqual([false, false]);
    });
  });

  /**
   * Pins the `value.length > 0` half of `readStringCookie`, which nothing else
   * reaches: no test in the suite transmits an empty cookie, and a cleared cookie
   * is DROPPED from the jar rather than sent as an empty value, so deleting that
   * clause leaves the whole suite green.
   *
   * What it would break is not this handler — `if (token)` rejects `''` either
   * way — but `middleware/csrf.ts`. `resolveSessionId` (`:46`) binds a token
   * minted with no cookie to a random `anon:` id; `validateCsrf` (`:155`) would
   * then see `''` as a STRING and derive `hashToken('')` instead, which is a
   * CONSTANT shared by every caller presenting an empty cookie. The token stops
   * validating (403 here), and the "anonymous tokens are single-session by
   * construction" property at `csrf.ts:13-15` is gone. So the request succeeding
   * is the assertion.
   */
  it('treats an EMPTY refresh cookie as absent, at the CSRF binding and at the handler', async () => {
    const user = await createTestUser();

    // Minted with NO cookie at all, so the token carries an `anon:` session id.
    const { token, cookie } = await getCsrf(agent);

    const res = await agent
      .post(`${API}/auth/logout`)
      .set('User-Agent', UA)
      .set('Authorization', `Bearer ${user.accessToken}`)
      .set('x-csrf-token', token)
      .set('Cookie', `${cookie}; refreshToken=`)
      .send({});

    // Not 403: the empty cookie did not re-bind the CSRF token to a hash.
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // And the handler read it as absent too, so it named no row to delete.
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
    expect(await RefreshToken.exists({ tokenHash: hashToken(user.refreshToken) })).not.toBeNull();
  });

  /**
   * The TRUE direction, and no other test in the suite pins it: `user.test.ts`
   * asserts the shape, the cap and the live-row filter of `GET /user/sessions`
   * but never the `current` flag, and the only other `.current` matches under
   * `packages/server/tests` are an unrelated `storageRef.current`. Without this,
   * `listSessions` could stop reading the cookie altogether —
   * `readStringCookie` replaced by a bare `undefined` — and every "malformed
   * behaves as absent" test above would stay green, because absent is what they
   * assert. This is what makes those tests mean something.
   */
  it('marks exactly the caller’s own session current when the cookie IS readable', async () => {
    const user = await createTestUser();
    await seedExtraSession(user.id);

    const res = await agent
      .get(`${API}/user/sessions`)
      .set('User-Agent', UA)
      .set('Authorization', `Bearer ${user.accessToken}`)
      .set('Cookie', `refreshToken=${user.refreshToken}`);

    expect(res.status).toBe(200);
    const rows = res.body.data as { _id: string; current: boolean }[];
    expect(rows).toHaveLength(2);

    const current = rows.filter((r) => r.current);
    expect(current).toHaveLength(1);

    const own = await RefreshToken.findOne({ tokenHash: hashToken(user.refreshToken) }).lean();
    expect(own).not.toBeNull();
    expect(current[0]?._id).toBe(String(own?._id));
  });

  describe.each(MALFORMED)('with a $label trusted-device cookie', ({ raw }) => {
    it('POST /auth/login still issues the 2FA challenge and audits no rejection', async () => {
      const { user } = await create2faUser();
      const cookies = `${trustedCookie(raw)}; ${refreshCookie(raw)}`;
      const { token, cookie } = await getCsrf(agent, cookies);

      const res = await agent
        .post(`${API}/auth/login`)
        .set('User-Agent', UA)
        .set('x-csrf-token', token)
        .set('Cookie', `${cookie}; ${cookies}`)
        .send({ email: user.email, authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBe(true);
      expect(typeof res.body.data.tempToken).toBe('string');
      // A challenge is not a session.
      expect(res.body.data.accessToken).toBeUndefined();

      // The negatives that separate "absent" from "rejected": an absent cookie
      // performs NO lookup, so it writes no `trusted_device_rejected` row and
      // emits no `trustedDevice` Set-Cookie clearing header.
      expect(
        await AuditLog.countDocuments({ userId: user.id, action: 'trusted_device_rejected' }),
      ).toBe(0);
      expect(setCookies(res).some((c) => c.startsWith('trustedDevice='))).toBe(false);
    });
  });
});

describe('A2 — DELETE /user/2fa must apply completely or not at all', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
    probe.calls.length = 0;
    probe.throwOnCall = 0;
  });

  describe.each(MALFORMED)('with a $label refresh cookie', ({ raw }) => {
    it('disables 2FA, revokes every session and trusted device, and audits it', async () => {
      const { user, secret } = await create2faUser();
      await seedExtraSession(user.id);
      await seedTrustedDevice(user.id);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(2);

      const { token, cookie } = await getCsrf(agent, refreshCookie(raw));
      const res = await agent
        .delete(`${API}/user/2fa`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('x-csrf-token', token)
        .set('Cookie', `${cookie}; ${refreshCookie(raw)}`)
        .send({ password: user.rawPassword, code: currentCode(secret) });

      expect(res.status).toBe(200);

      // The FULL observable outcome, not just the flag: the half-applied state
      // this test exists to forbid is "flag off, everything else untouched".
      const row = await User.findById(user.id).select('+twoFactorSecret +backupCodes').lean();
      expect(row?.twoFactorEnabled).toBe(false);
      expect(row?.twoFactorSecret).toBeUndefined();
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
      expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: '2fa_disable' })).toBe(1);
    });
  });

  /**
   * Atomicity on a failed WRITE. Note what this does NOT pin: a rejected
   * `findByIdAndUpdate` persists nothing under either ordering, so this test is
   * green whether the cookie is read before the write or after it. It guards the
   * other direction — someone moving the revocations or the audit row ABOVE the
   * write. The ordering itself is pinned by the test after this one.
   */
  it('leaves 2FA fully ENABLED when the disabling write itself fails', async () => {
    const { user, secret } = await create2faUser();
    await seedExtraSession(user.id);
    await seedTrustedDevice(user.id);

    // The write is made to fail at the database, which is the only failure mode
    // that can genuinely interleave with the revocations. Everything downstream
    // of it must therefore be unreachable.
    const spy = vi
      .spyOn(User, 'findByIdAndUpdate')
      .mockRejectedValueOnce(new Error('simulated write failure'));

    try {
      const { token, cookie } = await getCsrf(agent);
      const res = await agent
        .delete(`${API}/user/2fa`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ password: user.rawPassword, code: currentCode(secret) });

      expect(res.status).toBe(500);
      // The 500 must be the INJECTED one. Without this the test would pass on
      // any incidental server error and prove nothing about the ordering.
      expect(res.body.message).toBe('simulated write failure');
    } finally {
      spy.mockRestore();
    }

    // 2FA is still on, and NONE of the consequences of a disable happened —
    // the account is exactly as it was, not half-downgraded.
    const row = await User.findById(user.id).select('+twoFactorSecret').lean();
    expect(row?.twoFactorEnabled).toBe(true);
    expect(row?.twoFactorSecret).toBeTruthy();
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(2);
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: user.id, action: '2fa_disable' })).toBe(0);
  });

  it('leaves 2FA fully ENABLED when reading the request cookie fails', async () => {
    const { user, secret } = await create2faUser();
    await seedExtraSession(user.id);
    await seedTrustedDevice(user.id);

    const cookie = `refreshToken=${user.refreshToken}`;
    // Minted WITH the refresh cookie, so the token binds to that session and the
    // middleware takes its hashing branch — the branch this probe counts on.
    const { token, cookie: csrfCookie } = await getCsrf(agent, cookie);

    probe.calls.length = 0;
    probe.throwOnCall = 2;
    let res: request.Response;
    try {
      res = await agent
        .delete(`${API}/user/2fa`)
        .set('User-Agent', UA)
        .set('Authorization', `Bearer ${user.accessToken}`)
        .set('x-csrf-token', token)
        .set('Cookie', `${csrfCookie}; ${cookie}`)
        .send({ password: user.rawPassword, code: currentCode(secret) });
    } finally {
      probe.throwOnCall = 0;
    }

    expect(res.status).toBe(500);
    expect(res.body.message).toBe('simulated failure reading the request cookie');

    // The probe hit the intended call: the middleware's hash, then the handler's.
    // Without this the test could silently be failing the wrong one.
    expect(probe.calls).toEqual([user.refreshToken, user.refreshToken]);

    // The point of the ordering: a failure at the cookie read happens BEFORE the
    // downgrade, so the account is untouched rather than half-downgraded. Move
    // the read back below `User.findByIdAndUpdate` and `twoFactorEnabled` is
    // `false` here while everything a disable is supposed to revoke lives on.
    const row = await User.findById(user.id).select('+twoFactorSecret').lean();
    expect(row?.twoFactorEnabled).toBe(true);
    expect(row?.twoFactorSecret).toBeTruthy();
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(2);
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: user.id, action: '2fa_disable' })).toBe(0);
  });
});
