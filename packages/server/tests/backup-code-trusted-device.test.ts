/**
 * A3 — a single-use backup code must not mint a standing 2FA bypass.
 *
 * A backup code is a RECOVERY credential. It is handed out in a batch of eight,
 * printed or saved somewhere the authenticator app is not, and it exists for the
 * day the phone is lost. That is the opposite footing from a TOTP code, which
 * proves the second factor is present on this device RIGHT NOW.
 *
 * `login2fa` used to mint a trusted device on any remembered success, without
 * looking at which of the two credentials had been presented. So one code off a
 * printed sheet bought a `TRUSTED_DEVICE_DAYS` (30 by default) standing skip of
 * the 2FA step on that browser — and, because a trusted-device login mints a
 * fresh remembered session while the trust record keeps its own expiry, up to
 * `REFRESH_TOKEN_REMEMBER_DAYS + TRUSTED_DEVICE_DAYS` (60) days without the
 * second factor ever being presented again. The user could not see it had
 * happened: consumption produced a `logger.info` on the server and nothing in
 * the audit log, and the `login` row recorded `{ twoFactor: true }`, which is
 * exactly what a TOTP login records.
 *
 * The rule this file pins, in both directions:
 *
 *   • a remembered login completed with a BACKUP CODE creates no
 *     `TrustedDevice` row, sets no `trustedDevice` cookie, writes no
 *     `trusted_device_grant` row, and leaves the next login demanding 2FA;
 *   • a remembered login completed with a TOTP code still grants one, exactly
 *     as before — the fix must not cost the feature;
 *   • either way the remembered SESSION is untouched (30-day absolute
 *     deadline), because "remember me" and "trust this device to skip the
 *     second factor" are two different promises and only the second one is
 *     withdrawn here;
 *   • backup-code consumption is audited as `2fa_backup_code_used`, with the
 *     number of codes left, and the `login` row says which credential was used.
 *
 * Everything below drives the REAL two-step flow — `POST /auth/login` for the
 * server-minted temp token, then `POST /auth/login/2fa` — rather than signing a
 * temp token locally, because `rememberMe` reaches the second step only inside
 * that signed token and a locally minted one would prove nothing about how it
 * got there.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import { BACKUP_CODES_COUNT } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { hashToken } from '../src/utils/token.js';
import { countBackupCodes } from '../src/controllers/authController.js';
import { createTestUser, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const DAY_MS = 24 * 60 * 60 * 1000;
const BCRYPT_ROUNDS = 4;

/**
 * Pinned for every request in the file: the temp token is bound to
 * `sha256(req.ip | User-Agent)`, so an unpinned User-Agent would make the
 * server-minted token unusable at the second step for the wrong reason.
 */
const UA = 'A3BackupCodeTrust/1.0';

const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

interface TwoFactorUser {
  user: TestUser;
  secret: Secret;
  /** The raw codes, in the order they were hashed into the account. */
  codes: string[];
}

/** Creates a verified 2FA account holding `BACKUP_CODES_COUNT` real backup codes. */
async function create2faUser(): Promise<TwoFactorUser> {
  const secret = new Secret();
  const user = await createTestUser({ emailVerified: true });
  // 16 hex characters, exactly as `verify2fa` mints them (`randomBytes(8)`),
  // which is also the `login2faSchema` maximum — a longer stand-in would be
  // rejected by validation before reaching any of the logic under test.
  const codes = Array.from({ length: BACKUP_CODES_COUNT }, () =>
    crypto.randomBytes(8).toString('hex'),
  );
  const hashed = await Promise.all(codes.map((code) => bcrypt.hash(code, BCRYPT_ROUNDS)));

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: cm.encryptTextSync(secret.base32, encKey),
      backupCodes: hashed,
      // An old time step, so a genuinely current TOTP code is not rejected as a
      // replay by the stored-timestamp check.
      lastTotpTimestamp: 1,
    },
  });

  return { user, secret, codes };
}

function totpFor(secret: Secret): string {
  return new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret }).generate();
}

/**
 * The real password step. `extraCookies` is replayed verbatim alongside CSRF —
 * and is handed to `getCsrf` as well, because a CSRF token binds to the refresh
 * cookie present when it was minted (`middleware/csrf.ts:resolveSessionId`), so
 * minting it without the replay and then sending the replay would fail the
 * request as a CSRF violation rather than exercising anything here.
 */
async function postLogin(
  agent: request.Agent,
  user: TestUser,
  rememberMe: boolean,
  extraCookies?: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent, extraCookies);
  return agent
    .post(`${API}/auth/login`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', extraCookies ? `${cookie}; ${extraCookies}` : cookie)
    .send({ email: user.email, authHash: user.rawPassword, rememberMe });
}

/** The real second step, with a server-minted temp token. */
async function post2fa(
  agent: request.Agent,
  tempToken: string,
  code: string,
): Promise<request.Response> {
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/auth/login/2fa`)
    .set('User-Agent', UA)
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ tempToken, code });
}

/** Password step that must hand back a challenge, never a session. */
async function challenge(
  agent: request.Agent,
  user: TestUser,
  rememberMe: boolean,
): Promise<string> {
  const res = await postLogin(agent, user, rememberMe);
  expect(res.status).toBe(200);
  expect(res.body.data.twoFactorRequired).toBe(true);
  expect(res.body.data.accessToken).toBeUndefined();
  return res.body.data.tempToken as string;
}

function setCookiesOf(res: request.Response): string[] {
  return (res.headers['set-cookie'] as string[] | undefined) ?? [];
}

/** The `Set-Cookie` line for `name`, or `undefined` when the response sets none. */
function findCookie(res: request.Response, name: string): string | undefined {
  return setCookiesOf(res).find((c) => c.startsWith(`${name}=`));
}

function cookieValue(setCookieLine: string): string {
  return setCookieLine.split(';')[0]!.split('=')[1]!;
}

async function auditCount(userId: string, action: string): Promise<number> {
  // `action` is widened to `string` on purpose: these queries must be able to
  // ask about a value that is NOT in `AUDIT_ACTIONS`, which is how the "no such
  // row was written" negatives stay meaningful.
  return AuditLog.countDocuments({ userId, action } as Record<string, unknown>);
}

async function remainingCodes(userId: string): Promise<number> {
  const row = await User.findById(userId).select('+backupCodes');
  expect(row).not.toBeNull();
  return row!.backupCodes?.length ?? 0;
}

describe('A3 — a backup code completes a login without minting a trusted device', () => {
  let agent: request.Agent;

  beforeEach(() => {
    agent = request(app);
  });

  it(
    'grants NO trusted device when a remembered login is completed with a backup code, ' +
      'while still opening the remembered session',
    async () => {
      const { user, codes } = await create2faUser();

      const tempToken = await challenge(agent, user, true);
      const res = await post2fa(agent, tempToken, codes[0]!);

      // The login itself succeeds — a backup code is a valid second factor.
      expect(res.status).toBe(200);
      expect(res.body.data.accessToken).toBeDefined();
      expect(res.body.data.encryptedVaultKey).toBe('test-encrypted-vault-key');

      // ── The finding: no standing 2FA bypass was created ──────────────────
      expect(findCookie(res, 'trustedDevice')).toBeUndefined();
      expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
      expect(await auditCount(user.id, 'trusted_device_grant')).toBe(0);

      // ── The other half: the SESSION promise is still kept ────────────────
      // "Remember me" and "trust this device to skip 2FA" are two different
      // things, and only the second is withdrawn. Without this the fix would
      // silently downgrade every backup-code login to a 7-day session.
      const refreshCookie = findCookie(res, 'refreshToken');
      expect(refreshCookie).toBeDefined();
      const row = await RefreshToken.findOne({
        tokenHash: hashToken(cookieValue(refreshCookie!)),
      });
      expect(row).not.toBeNull();
      expect(row!.absoluteExpiresAt).toBeDefined();
      expect(row!.absoluteExpiresAt!.getTime() - Date.now()).toBeGreaterThan(25 * DAY_MS);

      // ── The code was genuinely spent ─────────────────────────────────────
      expect(await remainingCodes(user.id)).toBe(BACKUP_CODES_COUNT - 1);

      // ── And the user can SEE it happened ─────────────────────────────────
      const used = await AuditLog.findOne({ userId: user.id, action: '2fa_backup_code_used' });
      expect(used).not.toBeNull();
      expect(used!.metadata).toEqual({ remaining: BACKUP_CODES_COUNT - 1 });
      expect(used!.ipAddress.length).toBeGreaterThan(0);
      expect(used!.userAgent).toBe(UA);

      // …and the login row is no longer indistinguishable from a TOTP login.
      const login = await AuditLog.findOne({ userId: user.id, action: 'login' });
      expect(login).not.toBeNull();
      expect(login!.metadata).toEqual({ twoFactor: true, backupCode: true });
    },
  );

  it('still grants a trusted device when the same remembered login uses a TOTP code', async () => {
    const { user, secret } = await create2faUser();

    const tempToken = await challenge(agent, user, true);
    const res = await post2fa(agent, tempToken, totpFor(secret));

    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();

    // The cookie ships, scoped to the auth path, and carries the raw token…
    const tdCookie = findCookie(res, 'trustedDevice');
    expect(tdCookie).toBeDefined();
    expect(tdCookie).toMatch(/Path=\/api\/v1\/auth/i);
    const raw = cookieValue(tdCookie!);
    expect(raw.length).toBeGreaterThan(0);

    // …while the database holds only its hash, against exactly one record.
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(1);
    const record = await TrustedDevice.findOne({ userId: user.id });
    expect(record!.tokenHash).toBe(hashToken(raw));
    expect(JSON.stringify(res.body)).not.toContain(raw);

    expect(await auditCount(user.id, 'trusted_device_grant')).toBe(1);

    // No backup code was touched, so nothing claims one was.
    expect(await remainingCodes(user.id)).toBe(BACKUP_CODES_COUNT);
    expect(await auditCount(user.id, '2fa_backup_code_used')).toBe(0);

    const login = await AuditLog.findOne({ userId: user.id, action: 'login' });
    expect(login!.metadata).toEqual({ twoFactor: true, backupCode: false });
  });

  it('leaves the NEXT login on that browser demanding a second factor', async () => {
    // The consequence, stated the way an attacker would use it: sign in once
    // with a code off the printed sheet, then come back and skip 2FA for a
    // month. Everything the first response set is replayed on the second login,
    // so this fails if ANY credential shipped that the password step honours.
    const { user, codes } = await create2faUser();

    const first = await post2fa(agent, await challenge(agent, user, true), codes[0]!);
    expect(first.status).toBe(200);

    const replay = setCookiesOf(first)
      .map((line) => line.split(';')[0]!)
      // The CSRF cookie is minted per request by `getCsrf`; replaying a stale
      // one would fail the request for a reason that is not the subject here.
      .filter((pair) => !pair.startsWith('__csrf=') && pair.split('=')[1] !== '')
      .join('; ');

    const second = await postLogin(agent, user, true, replay);
    expect(second.status).toBe(200);
    expect(second.body.data.twoFactorRequired).toBe(true);
    expect(second.body.data.tempToken).toBeDefined();
    expect(second.body.data.accessToken).toBeUndefined();

    // The absence is because nothing was ever granted, not because something
    // was granted and then refused: a refusal writes its own row and clears the
    // cookie, and neither happened.
    expect(await auditCount(user.id, 'trusted_device_rejected')).toBe(0);
    expect(findCookie(second, 'trustedDevice')).toBeUndefined();
    expect(await auditCount(user.id, 'login')).toBe(1);
  });

  it('grants no trusted device for a backup code when "remember me" was not checked either', async () => {
    // The boundary on the other side of the new condition: with `remember`
    // false the grant was already unreachable, so this pins that the fix did
    // not accidentally invert anything, and that the session stays standard.
    const { user, codes } = await create2faUser();

    const res = await post2fa(agent, await challenge(agent, user, false), codes[0]!);
    expect(res.status).toBe(200);

    expect(findCookie(res, 'trustedDevice')).toBeUndefined();
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
    expect(await auditCount(user.id, 'trusted_device_grant')).toBe(0);

    const row = await RefreshToken.findOne({
      tokenHash: hashToken(cookieValue(findCookie(res, 'refreshToken')!)),
    });
    expect(row!.absoluteExpiresAt).toBeUndefined();

    // The code is still spent and still audited: visibility does not depend on
    // the remember-me box.
    expect(await remainingCodes(user.id)).toBe(BACKUP_CODES_COUNT - 1);
    expect(await auditCount(user.id, '2fa_backup_code_used')).toBe(1);
  });

  it('writes no backup-code audit row when the submitted code matches nothing', async () => {
    // The negative that keeps the new row honest: it must record a code that
    // was CONSUMED, not a code that was merely offered.
    const { user } = await create2faUser();
    const tempToken = await challenge(agent, user, true);

    const res = await post2fa(agent, tempToken, 'ffffffffffffffff');
    expect(res.status).toBe(401);
    expect(res.body.message).toBe('TWO_FA_INVALID');

    expect(await auditCount(user.id, '2fa_backup_code_used')).toBe(0);
    expect(await auditCount(user.id, 'login')).toBe(0);
    expect(await auditCount(user.id, 'login_failed')).toBe(1);
    expect(await remainingCodes(user.id)).toBe(BACKUP_CODES_COUNT);
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });

  it('records `remaining: 0` when the code spent was the last one', async () => {
    // The row the whole `remaining` field exists for. A user who reads
    // "Backup Code Used - 0 left" still has a working authenticator and can
    // regenerate; one who never sees it discovers the problem when the phone
    // is already gone.
    const { user, codes } = await create2faUser();
    // Strip the account down to a single code, so the one spent below is it.
    await User.findByIdAndUpdate(user.id, { $set: { backupCodes: [] } });
    const lastCode = codes[0]!;
    await User.findByIdAndUpdate(user.id, {
      $set: { backupCodes: [await bcrypt.hash(lastCode, BCRYPT_ROUNDS)] },
    });

    const res = await post2fa(agent, await challenge(agent, user, true), lastCode);
    expect(res.status).toBe(200);

    const row = await AuditLog.findOne({ userId: user.id, action: '2fa_backup_code_used' });
    expect(row).not.toBeNull();
    expect(row!.metadata).toEqual({ remaining: 0 });
    expect(await remainingCodes(user.id)).toBe(0);
  });

  it('counts down correctly when two DIFFERENT codes are redeemed at once', async () => {
    // This is the scenario that decides how `remaining` is computed. The count
    // comes from the post-image of the atomic `$pull` (`returnDocument: 'after'`
    // plus `.select('+backupCodes')`), never from the array read at the top of
    // the handler minus one — that array is read before a bcrypt walk over
    // every stored code, which is a wide window for a second redemption to land
    // in, and subtracting one from a stale read would report the same number
    // twice.
    //
    // What this pins deterministically is the pair of invariants that must hold
    // however the two requests interleave: exactly six codes survive, and the
    // two audit rows carry two DIFFERENT counts summing to the two states the
    // account actually passed through. It is honest about its limits: if the
    // two requests happened to serialise completely, a stale-read
    // implementation would also produce 7 and 6, so this test is a guard
    // rather than a proof.
    const { user, codes } = await create2faUser();

    const [firstToken, secondToken] = await Promise.all([
      challenge(agent, user, true),
      challenge(agent, user, true),
    ]);

    const [first, second] = await Promise.all([
      post2fa(agent, firstToken, codes[0]!),
      post2fa(agent, secondToken, codes[1]!),
    ]);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    expect(await remainingCodes(user.id)).toBe(BACKUP_CODES_COUNT - 2);

    const rows = await AuditLog.find({ userId: user.id, action: '2fa_backup_code_used' });
    expect(rows).toHaveLength(2);
    const counts = rows
      .map((r) => (r.metadata as { remaining: number }).remaining)
      .sort((a, b) => b - a);
    expect(counts).toEqual([BACKUP_CODES_COUNT - 1, BACKUP_CODES_COUNT - 2]);

    // Two codes spent, two devices NOT trusted.
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });

  it('discharges the shared lockout counter when a backup code verifies', async () => {
    // Parity with the TOTP path, and with the rule Phase 4 established: the
    // durable `failedLoginAttempts` counter — the ONLY per-account brake on the
    // 2FA step — is cleared by a COMPLETED authentication, and completing with a
    // backup code is one. Without this a user who mistyped a few codes before
    // reaching for the printed sheet would carry those failures forward and lock
    // themselves out on their next slip. `twofa-lockout-counter.test.ts` pins
    // this for TOTP; nothing pinned it for the credential people reach for
    // precisely when they are already having a bad day.
    const { user, codes } = await create2faUser();

    const tempToken = await challenge(agent, user, true);
    for (let i = 0; i < 4; i++) {
      expect((await post2fa(agent, tempToken, 'ffffffffffffffff')).status).toBe(401);
    }
    expect((await User.findById(user.id))!.failedLoginAttempts).toBe(4);

    const res = await post2fa(agent, tempToken, codes[0]!);
    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();

    const after = await User.findById(user.id);
    expect(after!.failedLoginAttempts).toBe(0);
    expect(after!.lockoutUntil).toBeUndefined();

    // …and it did so without buying any trust on the way.
    expect(await TrustedDevice.countDocuments({ userId: user.id })).toBe(0);
  });
});

describe('countBackupCodes', () => {
  // The helper exists so the "field was not projected" arm is an ordinary
  // boundary case of a pure function instead of an unreachable branch inside a
  // login handler. Both arms are exercised here; deleting either half of
  // `user.backupCodes?.length ?? 0` turns one of these red.
  it('counts the codes a projected document holds', () => {
    expect(countBackupCodes({ backupCodes: ['a', 'b', 'c'] })).toBe(3);
  });

  it('reports 0 for an account whose codes are all spent', () => {
    expect(countBackupCodes({ backupCodes: [] })).toBe(0);
  });

  it('reports 0 rather than throwing when the field was never projected', () => {
    // `backupCodes` is `select: false`, so this is what every query that forgets
    // `+backupCodes` hands back. Under-reporting is the safe direction; throwing
    // here would take down a login.
    expect(countBackupCodes({})).toBe(0);
  });
});
