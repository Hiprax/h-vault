/**
 * `assertVaultKeyVersion` — the optimistic-concurrency guard for every write
 * that seals new ciphertext under the account's vault key.
 *
 * ## What is being pinned, and why a unit test would not do it
 *
 * The guard's whole job is to read ONE number out of Mongo and decide a refusal
 * from it, so the seam is the query: `User.findById(userId)
 * .select('vaultKeyVersion').lean()`. A `.lean()` read is exactly where the
 * difference between "the field is 0" and "the field is absent" survives —
 * Mongoose's schema default fires on a HYDRATED read and not on a lean one — and
 * that difference is the compatibility branch this guard hangs on. Faking the
 * model would assert the fake. So mongod is real here (the suite's own
 * `tests/setup.ts` harness), and the row for an account created before the
 * column existed is produced with a real `$unset` rather than described.
 *
 * ## The case that matters most
 *
 * `vaultKeyVersion` is OPTIONAL on the wire, and the temptation with an optional
 * guard field is to let an absent value through. That is the total-vault-loss
 * path the guard exists to close, so the fail-closed case — no version supplied,
 * account already rotated — is asserted on its own, and asserted to carry the
 * number a client needs in order to recover.
 *
 * ## The negative every case carries
 *
 * A guard that refuses and writes anyway is worse than no guard, because the
 * refusal tells the caller nothing happened. Every refusing case therefore
 * re-reads the account afterwards and asserts the stored vault-key wrapper, the
 * generation and `updatedAt` are all untouched.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { handleCommonErrors } from '@hiprax/errors';
import {
  assertVaultKeyVersion,
  StaleVaultKeyError,
  vaultKeyVersionFilter,
  vaultKeyVersionOf,
} from '../src/utils/controllerHelpers.js';
import { User } from '../src/models/User.js';
import { createModuleLogger } from '../src/utils/logger.js';
import { createTestUser, type TestUser } from './helpers.js';

/**
 * The very logger instance the helper holds. `@hiprax/logger` caches on
 * `moduleName` + `logDirectory` (see `createModuleLogger`'s docblock), so asking
 * for the same module name here returns the same object rather than a second
 * one — which is what makes a spy on it observe the helper's own call instead of
 * a look-alike.
 */
const helperLogger = createModuleLogger('controller-helpers');

/** The fields a refusal must leave exactly as they were. */
interface AccountSnapshot {
  vaultKeyVersion: number;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  updatedAt: number;
}

describe('assertVaultKeyVersion', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** Moves the account onto a later vault-key generation, as a rotation does. */
  async function setGeneration(version: number): Promise<void> {
    await User.updateOne({ _id: user.id }, { $set: { vaultKeyVersion: version } });
  }

  async function snapshot(): Promise<AccountSnapshot> {
    const row = await User.findById(user.id).lean();
    if (row === null) throw new Error('the test account disappeared');
    return {
      vaultKeyVersion: vaultKeyVersionOf(row),
      encryptedVaultKey: row.encryptedVaultKey,
      vaultKeyIv: row.vaultKeyIv,
      vaultKeyTag: row.vaultKeyTag,
      updatedAt: row.updatedAt.getTime(),
    };
  }

  /**
   * Runs the guard and returns the refusal, failing loudly when it did not
   * refuse — `rejects.toThrow` alone would pass on a guard that threw a
   * `TypeError`, which is the shape a broken test has rather than a caught
   * defect.
   */
  async function refusal(supplied: number | undefined): Promise<StaleVaultKeyError> {
    const before = await snapshot();
    let caught: unknown;
    let allowed: number | undefined;
    try {
      allowed = await assertVaultKeyVersion(user.id, supplied);
    } catch (error) {
      caught = error;
    }
    // Thrown OUTSIDE the try, so it cannot be swallowed by the catch that is
    // there to collect the guard's own refusal. Thrown from inside, this message
    // surfaced as the *received value* of the assertion below rather than as the
    // failure, which is quieter than a case like this should be.
    if (caught === undefined) {
      throw new Error(
        `expected a refusal, but the guard allowed the write and returned ${String(allowed)}`,
      );
    }
    expect(caught).toBeInstanceOf(StaleVaultKeyError);
    const staleKeyError = caught as StaleVaultKeyError;

    // THE NEGATIVE. A refusal that mutated the account would be a worse defect
    // than the one the guard is closing, because the caller was told nothing
    // happened.
    expect(await snapshot()).toEqual(before);

    return staleKeyError;
  }

  describe('an account that has never rotated', () => {
    it('allows a write that names no generation at all, and reports generation 0', async () => {
      // The compatibility branch, and the ONLY thing it serves: an account at
      // generation 0 has never rotated, so no session can be holding a
      // superseded key and there is nothing for the guard to protect.
      await expect(assertVaultKeyVersion(user.id, undefined)).resolves.toBe(0);
    });

    it('allows a write that names generation 0 explicitly', async () => {
      // Zero is a real generation, not an absence. A guard written with a
      // truthiness check (`if (!supplied)`) treats this identically to
      // `undefined`, which is the mutation this case exists to kill.
      await expect(assertVaultKeyVersion(user.id, 0)).resolves.toBe(0);
    });

    it('refuses a write that names a generation the account has never reached', async () => {
      const error = await refusal(1);

      expect(error.reason).toBe('unreached');
      expect(error.statusCode).toBe(409);
      expect(error.vaultKeyVersion).toBe(0);
    });
  });

  describe('an account that has rotated', () => {
    beforeEach(async () => {
      await setGeneration(2);
    });

    it('allows a write that names the current generation, and reports it', async () => {
      await expect(assertVaultKeyVersion(user.id, 2)).resolves.toBe(2);
    });

    it('FAILS CLOSED on a write that names no generation, handing back the current one', async () => {
      // The case the optional wire field is a trap for. A client that cannot say
      // which vault key it used is a client that may be holding the superseded
      // one, and this account HAS a superseded one.
      const error = await refusal(undefined);

      expect(error.reason).toBe('unnamed');
      expect(error.statusCode).toBe(409);
      // The number is the whole point of the refusal being recoverable: without
      // it the client has to re-read its profile to learn what to rewrap under.
      expect(error.vaultKeyVersion).toBe(2);
      expect(error.message).toContain('vault key version 2');
    });

    it('refuses a write that names the superseded generation', async () => {
      const error = await refusal(1);

      expect(error.reason).toBe('rotated');
      expect(error.statusCode).toBe(409);
      expect(error.vaultKeyVersion).toBe(2);
      expect(error.message).toContain('rotated elsewhere');
    });

    it('refuses generation 0 once the account has moved past it', async () => {
      // The boundary below the current generation: `0` must not be waved through
      // as though it were the absent case.
      const error = await refusal(0);

      expect(error.reason).toBe('rotated');
      expect(error.vaultKeyVersion).toBe(2);
    });

    it('refuses, and LOGS, a write that claims a generation above the current one', async () => {
      // No honest client can hold a generation the account has never reached, so
      // this is a bookkeeping fault or a forged body. It stays refused, and it is
      // said out loud, because "rotated" would send whoever reads the log looking
      // for a rotation that never happened.
      const warn = vi.spyOn(helperLogger, 'warn');

      const error = await refusal(3);

      expect(error.reason).toBe('unreached');
      expect(error.vaultKeyVersion).toBe(2);
      expect(error.message).toContain('never had');
      expect(warn).toHaveBeenCalledWith(
        'A write claimed a vault key version this account has never reached',
        expect.objectContaining({ userId: user.id, claimed: 3, current: 2 }),
      );
    });

    it('distinguishes the three refusals by `reason`, not by prose', async () => {
      // A caller rendering the recoverable 409 branches on `reason`. Three
      // refusals collapsing onto one value would make that branch a coin toss,
      // and every message-only assertion above would still pass.
      const reasons = [await refusal(1), await refusal(3), await refusal(undefined)].map(
        (error) => error.reason,
      );

      expect(reasons).toEqual(['rotated', 'unreached', 'unnamed']);
      expect(new Set(reasons).size).toBe(3);
    });
  });

  describe('a row that predates the `vaultKeyVersion` column', () => {
    beforeEach(async () => {
      // A real `$unset`, not a described one: Mongoose applies the schema default
      // on a hydrated read and NOT on the `.lean()` read the guard performs, so
      // an absent column is the one state a hydrated fixture cannot reproduce.
      await User.updateOne({ _id: user.id }, { $unset: { vaultKeyVersion: '' } });
      const raw = await User.findById(user.id).lean();
      expect(raw?.vaultKeyVersion).toBeUndefined();
    });

    it('treats the absent column as generation 0 and allows the write', async () => {
      await expect(assertVaultKeyVersion(user.id, undefined)).resolves.toBe(0);
      await expect(assertVaultKeyVersion(user.id, 0)).resolves.toBe(0);
    });

    it('still refuses a generation above 0 on such a row', async () => {
      const error = await refusal(1);

      expect(error.reason).toBe('unreached');
      expect(error.vaultKeyVersion).toBe(0);
    });
  });

  describe('an id with no account behind it', () => {
    // The guard is a guard, not an existence check: Passport has already proved
    // the account exists on every authenticated request, and the write that
    // follows carries its own `_id` filter. So a missing row answers with
    // `vaultKeyVersionOf`'s documented value for an absent generation — the same
    // answer `assertVaultNotRotating` gives a missing user — rather than
    // inventing a 404 that no route can reach.
    const ABSENT_ID = '507f1f77bcf86cd799439011';

    it('resolves to generation 0 rather than throwing', async () => {
      await expect(assertVaultKeyVersion(ABSENT_ID, undefined)).resolves.toBe(0);
      await expect(assertVaultKeyVersion(ABSENT_ID, 0)).resolves.toBe(0);
    });

    it('refuses a claimed generation above 0, and writes nothing', async () => {
      const before = await User.countDocuments({});

      await expect(assertVaultKeyVersion(ABSENT_ID, 1)).rejects.toBeInstanceOf(StaleVaultKeyError);

      // No upsert, no row invented by the read.
      expect(await User.countDocuments({})).toBe(before);
      expect(await User.exists({ _id: ABSENT_ID })).toBeNull();
    });
  });

  describe('vaultKeyVersionFilter — the predicate a guarded write puts in its own filter', () => {
    /**
     * The trap this exists for, measured rather than argued. `User.vaultKeyVersion`
     * is `default: 0`, but there is no backfill migration, so an account created
     * before the column existed has no value at all. Reading that is harmless —
     * `vaultKeyVersionOf` and `$inc` both treat it as 0 — but a WRITE FILTER of
     * `{ vaultKeyVersion: 0 }` does not match a missing field, so the write silently
     * matches nothing and a caller that reads `matchedCount === 0` as the
     * recoverable 409 tells that user to reload and retry forever.
     *
     * These cases are written against `updateOne`'s real `matchedCount` rather than
     * against the predicate's shape, because the shape is not the claim — what
     * MongoDB does with it is.
     */
    async function stripColumn(id: string): Promise<void> {
      await User.updateOne({ _id: id }, { $unset: { vaultKeyVersion: '' } });
      const raw = await User.findById(id).lean();
      expect(raw?.vaultKeyVersion).toBeUndefined();
    }

    async function writeUnderFilter(id: string, resolved: number): Promise<number> {
      const result = await User.updateOne(
        { _id: id, vaultKeyVersion: vaultKeyVersionFilter(resolved) },
        { $set: { vaultKeyIv: 'rewrapped' } },
      );
      return result.matchedCount;
    }

    it('matches a legacy row whose column was never written', async () => {
      await stripColumn(user.id);

      expect(await writeUnderFilter(user.id, 0)).toBe(1);
      // The negative that makes it a real assertion: the naive predicate the
      // helper exists to replace matches NOTHING on the same row.
      const naive = await User.updateOne(
        { _id: user.id, vaultKeyVersion: 0 },
        { $set: { vaultKeyIv: 'must-not-apply' } },
      );
      expect(naive.matchedCount).toBe(0);
    });

    it('matches an ordinary never-rotated row, which stores an explicit 0', async () => {
      expect(await writeUnderFilter(user.id, 0)).toBe(1);
    });

    it('matches a rotated row at its own generation', async () => {
      await setGeneration(3);

      expect(await writeUnderFilter(user.id, 3)).toBe(1);
    });

    it('refuses a rotated row when the resolved generation is stale, and writes nothing', async () => {
      await setGeneration(3);
      const before = await snapshot();

      expect(await writeUnderFilter(user.id, 0)).toBe(0);
      expect(await writeUnderFilter(user.id, 2)).toBe(0);

      // The widening that would look like a fix and is not: `{ $in: [3, null] }`
      // would match a legacy row as though it were at generation 3, so the
      // `null` arm is correct ONLY at generation 0.
      expect(await snapshot()).toEqual(before);
    });

    it('never admits a legacy row at a generation above 0', async () => {
      await stripColumn(user.id);

      expect(await writeUnderFilter(user.id, 1)).toBe(0);
      expect(await writeUnderFilter(user.id, 3)).toBe(0);
    });

    it('widens ONLY at generation 0', () => {
      // The shape, asserted once, because the `null` arm appearing at any other
      // generation is the mutation the behavioural cases above cannot see: there
      // is no stored row that would reveal `{ $in: [3, null] }` as wrong unless a
      // legacy row happens to exist at the same moment.
      expect(vaultKeyVersionFilter(0)).toEqual({ $in: [0, null] });
      expect(vaultKeyVersionFilter(1)).toBe(1);
      expect(vaultKeyVersionFilter(2)).toBe(2);
      expect(vaultKeyVersionFilter(4_294_967_296)).toBe(4_294_967_296);
    });
  });

  describe('the refusal renders as a 409 even when nobody catches it', () => {
    it('is an `ErrorHandler` with status 409, so the error middleware answers correctly', async () => {
      // The fail-SAFE property. A handler that throws this and forgets to catch
      // it loses the number, and therefore costs the client a profile re-read —
      // but it must never lose the REFUSAL. `handleCommonErrors` reaches its
      // default branch for this name and preserves `statusCode`.
      const error = await refusal(1);

      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('StaleVaultKeyError');
      expect(error.statusCode).toBe(409);
      expect(error.statusText).toBe('Conflict');
      expect(error.message.length).toBeGreaterThan(0);

      // Asserted through the CONSUMER, not only on the object. The docblock's
      // central promise is about what `@hiprax/errors` does with an error whose
      // `name` matches none of its cases, and that is a property of the library:
      // an upgrade that adds a case, or changes the default branch to stop
      // preserving `statusCode`, would turn every uncaught refusal into a 500
      // with nothing in this suite going red.
      const normalised = handleCommonErrors(error);
      expect(normalised.statusCode).toBe(409);
      expect(normalised.message).toBe(error.message);
    });

    it('never puts the vault key, the auth hash or the user id in its message', async () => {
      // The message is shown to the end user verbatim (a 4xx is not redacted),
      // so it carries a generation and a remedy and nothing else.
      const error = await refusal(1);

      expect(error.message).not.toContain(user.id);
      expect(error.message).not.toContain('test-encrypted-vault-key');
      expect(error.message).not.toContain('test-vault-key-tag');
    });
  });
});
