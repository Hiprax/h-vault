/**
 * `PUT /user/change-password` must refuse a wrapper built from a superseded
 * vault key.
 *
 * ## The total-loss path this file closes
 *
 * A master-password change is the one write that REPLACES `User.encryptedVaultKey`
 * rather than adding a row beside it. It re-wraps the vault key the session holds
 * under a MEK derived from the new password, and stores that as the account's only
 * copy.
 *
 * A vault-key ROTATION performed anywhere else revokes no session and refreshes no
 * key (see `authStore.vaultKeyVersion`'s docblock on the client), so a second
 * session can hold the superseded vault key indefinitely and has no way to notice:
 * it can still decrypt everything it already loaded, and it can still encrypt. If
 * that session then changes the master password, the wrapper it uploads names the
 * OLD key. Nothing on the server can tell the difference — the wrapper is opaque
 * ciphertext — so the write lands, the live key's only stored copy is gone, and
 * every row in the account is permanently undecryptable. There is no recovery:
 * nothing anywhere can decrypt a vault whose key is gone.
 *
 * No race is required. The rotation may have finished days earlier; all it takes
 * is a tab left open.
 *
 * ## What is pinned here, and why the datastore is real
 *
 * The guard is a WRITE FILTER — `{ _id, vaultKeyVersion: vaultKeyVersionFilter(n) }`
 * — so the claim is about what MongoDB does with that predicate, not about the
 * shape of an object. Two states only a real mongod produces decide it:
 *
 *  1. An account whose `vaultKeyVersion` column was never written. `User.vaultKeyVersion`
 *     is `default: 0` with no backfill migration, and equality on `0` does not match
 *     a missing field, so a bare `vaultKeyVersion: 0` filter matches NOTHING on such
 *     a row. A caller reading `matchedCount === 0` as the recoverable conflict would
 *     tell that user to reload and retry for ever, because no newer generation exists
 *     to rewrap under — their master password could never be changed again. That case
 *     is written with a real `$unset` rather than described.
 *  2. The `$inc` a real rotation performs, which is what moves the account off
 *     generation 0 in the first place. The rotations here therefore go through
 *     `POST /vault/items/bulk-reencrypt` over HTTP rather than a hand-written
 *     `$set`, so the number the guard compares against is one the product actually
 *     produced.
 *
 * ## Both write branches, because the plan's defect is in both
 *
 * `changePassword` commits through a transaction on a replica set and through a
 * sequential fallback on a standalone deployment, and the two write the user
 * document by different means. The default harness (`tests/setup.ts`) is a
 * standalone server, so the first block covers the fallback; the second borrows a
 * single-node replica set so `supportsTransactions` is genuinely true and asserts
 * the same contract through `session.withTransaction`.
 *
 * ## The negatives every refusing case carries
 *
 * A refusal that mutated anything would be worse than no guard, because the caller
 * was told nothing happened. Every refusal therefore asserts the stored wrapper is
 * untouched, the OLD password still authenticates, `passwordChangedAt` has not
 * moved, the session's refresh token and trusted device still exist, and no
 * `password_change` audit row was written.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { hashToken } from '../src/utils/token.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { vaultKeyVersionOf } from '../src/utils/controllerHelpers.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from './helpers.js';
import { useReplicaSetConnection } from './mongoHarness.js';

/** The wrapper a stale session would upload: built from the key it still holds. */
const STALE_WRAPPER = {
  newEncryptedVaultKey: 'wrapper-built-from-the-SUPERSEDED-vault-key',
  newVaultKeyIv: 'stale-iv',
  newVaultKeyTag: 'stale-tag',
} as const;

/** The wrapper a session holding the live key would upload. */
const LIVE_WRAPPER = {
  newEncryptedVaultKey: 'wrapper-built-from-the-LIVE-vault-key',
  newVaultKeyIv: 'live-iv',
  newVaultKeyTag: 'live-tag',
} as const;

/** What the rotation below leaves stored as the account's wrapped vault key. */
const ROTATED_VAULT_KEY = 'rotated-vault-key';

const NEW_AUTH_HASH = 'brand-new-auth-hash';

/** The account fields a refusal must leave exactly as they were. */
interface AccountSnapshot {
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  vaultKeyVersion: number;
  passwordChangedAt: number;
  refreshTokens: number;
  trustedDevices: number;
}

/**
 * Every case in this file, defined once and run against both write branches.
 *
 * A factory rather than two copies: the contract is identical and the branch is
 * chosen by the topology the enclosing block connected to, so a divergence between
 * the two would be a defect rather than a difference worth expressing twice.
 * `expectTransactions` is asserted, not assumed — a replica set that failed to
 * register would otherwise silently take the fallback and every assertion in that
 * block would be about the branch already covered.
 */
function defineChangePasswordGuardCases(expectTransactions: boolean): void {
  let user: TestUser;

  beforeEach(async () => {
    expect(supportsTransactions(mongoose.connection)).toBe(expectTransactions);
    user = await createTestUser();
    await TrustedDevice.create({
      userId: new mongoose.Types.ObjectId(user.id),
      tokenHash: hashToken('trusted-device-raw-token'),
      deviceInfo: { userAgent: 'seed-agent', ip: '127.0.0.1', fingerprint: 'seed-fp' },
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** One authenticated, CSRF-bearing request. */
  async function send(
    method: 'put' | 'post',
    path: string,
    body: Record<string, unknown>,
  ): Promise<request.Response> {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const req = method === 'put' ? agent.put(path) : agent.post(path);
    return req
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(body);
  }

  /**
   * Rotates the account's vault key through the real endpoint, so
   * `vaultKeyVersion` is moved by the product's own `$inc`.
   *
   * The payload is empty because the account holds no rows: a rotation must name
   * every row the account has, and zero named ids cover zero rows.
   */
  async function rotateVaultKey(): Promise<void> {
    const res = await send('post', '/api/v1/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      items: [],
      folders: [],
      documents: [],
      newEncryptedVaultKey: ROTATED_VAULT_KEY,
      newVaultKeyIv: 'rotated-vault-key-iv',
      newVaultKeyTag: 'rotated-vault-key-tag',
    });
    expect(res.status).toBe(200);
    // The rotation is the fixture, so its effect is asserted rather than assumed:
    // a rotation that stopped incrementing would make every case below vacuous.
    const rotated = await User.findById(user.id).lean();
    expect(rotated?.vaultKeyVersion).toBe(1);
    expect(rotated?.encryptedVaultKey).toBe(ROTATED_VAULT_KEY);
    expect(rotated?.rotationInProgress).toBe(false);
  }

  async function changePassword(extra: Record<string, unknown> = {}): Promise<request.Response> {
    return send('put', '/api/v1/user/change-password', {
      currentAuthHash: user.rawPassword,
      newAuthHash: NEW_AUTH_HASH,
      ...STALE_WRAPPER,
      ...extra,
    });
  }

  async function snapshot(): Promise<AccountSnapshot> {
    const row = await User.findById(user.id).lean();
    if (row === null) throw new Error('the test account disappeared');
    return {
      encryptedVaultKey: row.encryptedVaultKey,
      vaultKeyIv: row.vaultKeyIv,
      vaultKeyTag: row.vaultKeyTag,
      vaultKeyVersion: vaultKeyVersionOf(row),
      passwordChangedAt: row.passwordChangedAt.getTime(),
      refreshTokens: await RefreshToken.countDocuments({ userId: user.id }),
      trustedDevices: await TrustedDevice.countDocuments({ userId: user.id }),
    };
  }

  /** True when the stored auth hash still verifies the password given. */
  async function passwordStillWorks(raw: string): Promise<boolean> {
    const row = await User.findById(user.id).select('+authHash').lean();
    if (row === null) throw new Error('the test account disappeared');
    return bcrypt.compare(raw, row.authHash);
  }

  /**
   * How many MASTER-PASSWORD-CHANGE rows this account has.
   *
   * The filter is narrower than the action alone, and it has to be: a vault-key
   * ROTATION audits under the very same `password_change` action, distinguishing
   * itself only by `metadata.action: 'vault_key_rotation'`. Counting the action
   * alone would score the fixture's own rotation as a password change and make
   * "no password change was recorded" true of a request that recorded one.
   */
  async function passwordChangeAudits(): Promise<number> {
    return AuditLog.countDocuments({
      userId: user.id,
      action: 'password_change',
      'metadata.action': { $exists: false },
    });
  }

  /**
   * THE NEGATIVE, in one place: nothing about the account moved, and the OLD
   * password still opens it.
   *
   * It takes the snapshot the caller captured BEFORE the request rather than
   * comparing against literals, so a fixture change cannot quietly turn this into
   * a weaker assertion.
   */
  async function expectNothingChanged(before: AccountSnapshot): Promise<void> {
    expect(await snapshot()).toEqual(before);
    expect(await passwordStillWorks(user.rawPassword)).toBe(true);
    expect(await passwordStillWorks(NEW_AUTH_HASH)).toBe(false);
    expect(await passwordChangeAudits()).toBe(0);
  }

  // ── The defect ────────────────────────────────────────────────────────

  describe('a session holding a superseded vault key', () => {
    it('is refused with a recoverable 409 and overwrites nothing', async () => {
      await rotateVaultKey();
      const before = await snapshot();

      // Exactly what a second session sends: the generation it recorded when it
      // received its wrapped key, and a wrapper built from that key.
      const res = await changePassword({ vaultKeyVersion: 0 });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      // The NUMBER is what makes the refusal recoverable: with it the client
      // re-wraps under the live key and retries in one request.
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      expect(res.body.message).toMatch(/rotated elsewhere/i);

      // The whole point. Without the guard this field now holds a wrapper for a
      // key that no longer exists, and the account is unrecoverable.
      await expectNothingChanged(before);
      expect((await snapshot()).encryptedVaultKey).toBe(ROTATED_VAULT_KEY);
    });

    it('is refused when it cannot name a generation at all', async () => {
      // `vaultKeyVersion` is OPTIONAL on the wire (making it required would be a
      // breaking request-schema change), and this is the case that stops optional
      // meaning ignorable. An out-of-date client sends no version at all, and on a
      // rotated account that client may be holding the superseded key.
      await rotateVaultKey();
      const before = await snapshot();

      const res = await changePassword();

      expect(res.status).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      expect(res.body.message).toMatch(/did not say which vault key it used/i);
      await expectNothingChanged(before);
    });

    it('is refused when it claims a generation the account has never reached', async () => {
      // No honest client can hold a generation above the account's, so this is a
      // bookkeeping fault or a forged body. It is answered with the same
      // recoverable refusal rather than a 400, because what matters is that
      // nothing was committed and that the client is handed the real number.
      const before = await snapshot();

      const res = await changePassword({ vaultKeyVersion: 7 });

      expect(res.status).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 0 });
      expect(res.body.message).toMatch(/never had/i);
      await expectNothingChanged(before);
    });
  });

  // ── The write that must still go through ──────────────────────────────

  describe('a session holding the live vault key', () => {
    it('changes the password on a rotated account when it names the current generation', async () => {
      await rotateVaultKey();

      const res = await changePassword({ vaultKeyVersion: 1, ...LIVE_WRAPPER });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const after = await snapshot();
      expect(after.encryptedVaultKey).toBe(LIVE_WRAPPER.newEncryptedVaultKey);
      expect(after.vaultKeyIv).toBe(LIVE_WRAPPER.newVaultKeyIv);
      expect(after.vaultKeyTag).toBe(LIVE_WRAPPER.newVaultKeyTag);
      expect(await passwordStillWorks(NEW_AUTH_HASH)).toBe(true);
      expect(await passwordStillWorks(user.rawPassword)).toBe(false);
      // The generation names WHICH vault key is stored, and a password change
      // re-wraps the SAME one, so it must not move.
      expect(after.vaultKeyVersion).toBe(1);
      // Every session and every 2FA skip granted under the old password is gone.
      expect(after.refreshTokens).toBe(0);
      expect(after.trustedDevices).toBe(0);
      expect(await passwordChangeAudits()).toBe(1);
    });

    it('changes the password on an account that has never rotated and names no generation', async () => {
      // The compatibility branch, and the only thing it serves: an account at
      // generation 0 has never rotated, so no session can be holding a superseded
      // key. An existing client that has not been updated keeps working.
      const res = await changePassword(LIVE_WRAPPER);

      expect(res.status).toBe(200);
      const after = await snapshot();
      expect(after.encryptedVaultKey).toBe(LIVE_WRAPPER.newEncryptedVaultKey);
      expect(after.vaultKeyVersion).toBe(0);
      expect(await passwordStillWorks(NEW_AUTH_HASH)).toBe(true);
    });

    it('changes the password on an account that has never rotated and names generation 0', async () => {
      // Zero is a real generation, not an absence. A guard written with a
      // truthiness check treats this identically to an absent field, which is the
      // mutation this case exists to kill.
      const res = await changePassword({ vaultKeyVersion: 0, ...LIVE_WRAPPER });

      expect(res.status).toBe(200);
      expect((await snapshot()).encryptedVaultKey).toBe(LIVE_WRAPPER.newEncryptedVaultKey);
    });

    it('changes the password on a row that predates the `vaultKeyVersion` column', async () => {
      // The trap that turns this guard from a fix into a brick. `vaultKeyVersion`
      // has no backfill migration, so an account created before the column existed
      // has no value at all — and MongoDB equality on `0` does not match a missing
      // field. Filtered with a bare `vaultKeyVersion: 0` this write matches
      // nothing, the refusal tells the user to reload and retry, and the retry can
      // never succeed because there is no newer generation to rewrap under: that
      // account's master password could never be changed again.
      //
      // A real `$unset`, because Mongoose applies the schema default on a hydrated
      // read and an absent column is the one state a hydrated fixture cannot
      // reproduce.
      await User.updateOne({ _id: user.id }, { $unset: { vaultKeyVersion: '' } });
      expect((await User.findById(user.id).lean())?.vaultKeyVersion).toBeUndefined();

      const res = await changePassword(LIVE_WRAPPER);

      expect(res.status).toBe(200);
      const after = await User.findById(user.id).lean();
      expect(after?.encryptedVaultKey).toBe(LIVE_WRAPPER.newEncryptedVaultKey);
      // Still absent: a password change must not invent a generation for an
      // account that has never rotated.
      expect(after?.vaultKeyVersion).toBeUndefined();
      expect(await passwordStillWorks(NEW_AUTH_HASH)).toBe(true);
    });
  });

  // ── The fence: a rotation that has not finished yet ───────────────────

  describe('while a rotation is being processed', () => {
    beforeEach(async () => {
      await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
    });

    it('refuses the change and writes nothing', async () => {
      // The version check catches a rotation that has COMMITTED; the fence catches
      // one still running, whose flag was raised before it enumerated. Neither
      // replaces the other: mid-rotation the account is still on the old
      // generation, so the version alone would wave this through and the new key
      // would land on top of the one the rotation is about to store.
      const before = await snapshot();

      const res = await changePassword({ vaultKeyVersion: 0 });

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/rotation is in progress/i);
      // This refusal carries no number: there is nothing to rewrap under yet, and
      // the remedy is to wait rather than to re-read.
      expect(res.body.data).toBeUndefined();
      await expectNothingChanged(before);
    });

    it('reports the rotation, not the stale generation, when BOTH hold', async () => {
      // The case that pins the ORDER of the two guards, and it is reachable: an
      // account already on generation 1 with a second rotation in flight, and a
      // client still claiming generation 0. Version-first would answer with a
      // number that is about to change again and invite the client to rewrap
      // against it — and the client retries exactly ONCE, so that flap spends the
      // whole retry budget and surfaces a failure for a condition whose real
      // remedy is to wait. Fence-first answers "wait", and the ABSENCE of the
      // number is how the client tells the two apart.
      await User.updateOne(
        { _id: user.id },
        { $set: { vaultKeyVersion: 1, rotationInProgress: true } },
      );
      const before = await snapshot();

      const res = await changePassword({ vaultKeyVersion: 0 });

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/rotation is in progress/i);
      expect(res.body.message).not.toMatch(/rotated elsewhere/i);
      expect(res.body.data).toBeUndefined();
      await expectNothingChanged(before);
    });

    it('still answers a wrong current password with 401, and still audits it', async () => {
      // The guards sit AFTER the password proof, deliberately. Fencing first would
      // answer 409 to a request that never proved the password, so the 401 and its
      // `password_verification_failed` audit row — the row that records a wrong
      // password against this account — would both vanish for the duration of
      // every rotation.
      const res = await changePassword({
        currentAuthHash: 'wrong-password-value',
        vaultKeyVersion: 0,
      });

      expect(res.status).toBe(401);
      expect(
        await AuditLog.countDocuments({
          userId: user.id,
          action: 'password_verification_failed',
        }),
      ).toBe(1);
    });
  });

  // ── The interleaving the prior read cannot see ────────────────────────

  /**
   * Lands a rotation's `$inc` in the window between the guard's read and the
   * vault-key write, and returns the response to a change-password sent into it.
   *
   * What makes the guard safe against this interleaving is the FILTER on the
   * write, never the read that precedes it. Producing it needs a seam inside the
   * handler's own span, and the vault-key write itself is the only one there: the
   * spy recognises it by the field it sets, performs the concurrent increment
   * through the ORIGINAL method — captured before the spy, so the increment
   * cannot re-enter it — and then calls through unchanged. Every other
   * `User.updateOne` in the request passes straight through.
   */
  async function changePasswordRacingARotation(): Promise<request.Response> {
    const originalUpdateOne = User.updateOne.bind(User);
    let raced = false;
    vi.spyOn(User, 'updateOne').mockImplementation((async (
      filter: never,
      update: never,
      options?: never,
    ) => {
      if (!raced && JSON.stringify(update).includes('encryptedVaultKey')) {
        raced = true;
        await originalUpdateOne({ _id: user.id }, { $inc: { vaultKeyVersion: 1 } });
      }
      return originalUpdateOne(filter, update, options);
    }) as never);

    const res = await changePassword({ vaultKeyVersion: 0, ...LIVE_WRAPPER });
    expect(raced).toBe(true);
    return res;
  }

  it('refuses when a rotation commits between the guard read and the write', async () => {
    const res = await changePasswordRacingARotation();

    expect(res.status).toBe(409);
    expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
    const after = await User.findById(user.id).lean();
    // The wrapper the request carried was legitimate when it was built and is
    // stale by the time it arrives, so it must not be stored.
    expect(after?.encryptedVaultKey).toBe('test-encrypted-vault-key');
    expect(await passwordStillWorks(user.rawPassword)).toBe(true);
    expect(await passwordStillWorks(NEW_AUTH_HASH)).toBe(false);
    expect(await passwordChangeAudits()).toBe(0);
  });

  it('does not report an unrelated datastore failure as a stale vault key', async () => {
    // The refusal is caught narrowly, by type. A blanket catch around the guard
    // would turn any failure of that read — a dropped connection, a timeout —
    // into a 409 telling the user their key was rotated, which is both false and
    // unactionable. Only the guard's own read is broken here; the two before it
    // are left real, so the request gets as far as the guard.
    const realFindById = User.findById.bind(User);
    vi.spyOn(User, 'findById').mockImplementation(((id: string) => {
      const query = realFindById(id);
      const realSelect = query.select.bind(query);
      query.select = ((fields: string) =>
        fields === 'vaultKeyVersion'
          ? { lean: () => Promise.reject(new Error('datastore unavailable')) }
          : realSelect(fields)) as never;
      return query;
    }) as never);
    const before = await snapshot();

    const res = await changePassword({ vaultKeyVersion: 0, ...LIVE_WRAPPER });

    expect(res.status).toBe(500);
    expect(res.body.data).toBeUndefined();
    vi.restoreAllMocks();
    await expectNothingChanged(before);
  });

  it('accounts for the session revocation according to what its branch can undo', async () => {
    // The ONE observable difference between the two branches, asserted rather
    // than left to be discovered.
    //
    // Both branches revoke every refresh token and every trusted device before
    // the vault-key write, and that ordering is deliberate: the reverse would
    // leave sessions valid for an account whose password had just changed. On a
    // replica set the revocation is inside the same transaction as the
    // conditional write, so a write matching nothing aborts it and the session
    // survives the refusal intact. The sequential fallback has no transaction to
    // abort, so the revocation has already committed — the user is signed out of
    // every device over a change that did not happen, which is the same cost the
    // fallback's own comment already accepts for a crash between its two steps,
    // and it is bounded by this interleaving alone (the ordinary refusals above
    // are decided before anything is revoked, and they revoke nothing).
    const res = await changePasswordRacingARotation();
    expect(res.status).toBe(409);

    const sessions = await RefreshToken.countDocuments({ userId: user.id });
    const devices = await TrustedDevice.countDocuments({ userId: user.id });
    if (expectTransactions) {
      expect({ sessions, devices }).toEqual({ sessions: 1, devices: 1 });
    } else {
      expect({ sessions, devices }).toEqual({ sessions: 0, devices: 0 });
    }
  });
}

describe('PUT /user/change-password — vault-key guard (sequential fallback)', () => {
  defineChangePasswordGuardCases(false);
});

describe('PUT /user/change-password — vault-key guard (transaction branch)', () => {
  // Borrows the process-wide mongoose connection for a single-node replica set
  // and hands it back afterwards, so this block carries no dependence on being
  // declared last under `sequence.shuffle`.
  useReplicaSetConnection({ timeoutMs: 60_000 });

  defineChangePasswordGuardCases(true);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lets an unrelated transaction failure surface instead of calling it a stale key', async () => {
    // The sentinel that aborts the transaction on a no-match write is caught by
    // TYPE, so anything else that fails inside the transaction still propagates.
    // Catching broadly there would answer 409 "your vault key was rotated" to a
    // request that failed for a reason the caller can do nothing about, and would
    // report the account's own generation as the remedy.
    const user = await createTestUser();
    vi.spyOn(RefreshToken, 'deleteMany').mockRejectedValueOnce(
      new Error('transaction participant unavailable') as never,
    );
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const res = await agent
      .put('/api/v1/user/change-password')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({
        currentAuthHash: user.rawPassword,
        newAuthHash: NEW_AUTH_HASH,
        vaultKeyVersion: 0,
        ...LIVE_WRAPPER,
      });

    expect(res.status).toBe(500);
    expect(res.body.data).toBeUndefined();
    // And nothing was written: the whole point of the transaction.
    const after = await User.findById(user.id).lean();
    expect(after?.encryptedVaultKey).toBe('test-encrypted-vault-key');
  });
});
