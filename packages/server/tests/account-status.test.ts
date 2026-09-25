/**
 * `utils/accountStatus.ts` — the three account-level refusal predicates that
 * `login`, `login2fa`, the refresh handler and the Passport JWT strategy all read.
 *
 * The four HTTP paths are covered by their own suites; what is pinned here is the
 * shape of the predicates themselves, where the interesting cases are ones an
 * end-to-end test cannot express deterministically:
 *
 *  - the lockout boundary at EXACTLY the deadline, which decides whether a
 *    lockout that has just arrived is still enforced or has been served;
 *  - `deletionPending: false`, which is the value the cleanup job writes when a
 *    deletion is ABORTED (`background-jobs.test.ts` does exactly this) and which
 *    must therefore read as "not pending" rather than as a truthy-ish refusal;
 *  - a caller that projects only some of the fields, which is how the Passport
 *    strategy calls it.
 */
import { describe, it, expect } from 'vitest';
import { evaluateAccountStatus } from '../src/utils/accountStatus.js';

const NOW = new Date('2026-09-22T10:00:00.000Z');

describe('evaluateAccountStatus', () => {
  it('clears a fully healthy account', () => {
    expect(evaluateAccountStatus({ emailVerified: true, deletionPending: undefined }, NOW)).toEqual(
      {
        deletionPending: false,
        emailUnverified: false,
        lockedOut: false,
      },
    );
  });

  it('reports a deletion only for the literal true, never for an aborted one', () => {
    const base = { emailVerified: true } as const;
    expect(evaluateAccountStatus({ ...base, deletionPending: true }, NOW).deletionPending).toBe(
      true,
    );
    // The abort case: the cleanup scan selects on `{ deletionPending: true }`, so
    // an explicit `false` means "no longer being deleted" and the account must be
    // served normally.
    expect(evaluateAccountStatus({ ...base, deletionPending: false }, NOW).deletionPending).toBe(
      false,
    );
    expect(evaluateAccountStatus(base, NOW).deletionPending).toBe(false);
  });

  it('treats an unset verification flag as unverified', () => {
    expect(evaluateAccountStatus({ emailVerified: false }, NOW).emailUnverified).toBe(true);
    expect(evaluateAccountStatus({}, NOW).emailUnverified).toBe(true);
    expect(evaluateAccountStatus({ emailVerified: true }, NOW).emailUnverified).toBe(false);
  });

  it.each([
    { at: 'one millisecond before the deadline', offsetMs: -1, expected: true },
    { at: 'exactly at the deadline', offsetMs: 0, expected: false },
    { at: 'one millisecond after the deadline', offsetMs: 1, expected: false },
  ])('evaluates a lockout $at as lockedOut=$expected', ({ offsetMs, expected }) => {
    // A deadline that has ARRIVED has been served: `login` discharges it on the
    // next correct password, and holding the account for one more request would
    // contradict that. This is the boundary the whole 30-minute promise rests on.
    const lockoutUntil = new Date(NOW.getTime() - offsetMs);
    expect(evaluateAccountStatus({ emailVerified: true, lockoutUntil }, NOW).lockedOut).toBe(
      expected,
    );
  });

  it('reports no lockout when the field is absent or null', () => {
    // Both spellings occur: a user document that never had one, and a caller that
    // did not project the field (the Passport strategy). Neither may read as a
    // lockout, and neither may throw on `.getTime()`.
    expect(evaluateAccountStatus({ emailVerified: true }, NOW).lockedOut).toBe(false);
    expect(evaluateAccountStatus({ emailVerified: true, lockoutUntil: null }, NOW).lockedOut).toBe(
      false,
    );
  });

  it('defaults `now` to the current instant', () => {
    // The default parameter is what every production caller uses; a broken
    // default would make every one of them evaluate against the epoch.
    const future = new Date(Date.now() + 60_000);
    const past = new Date(Date.now() - 60_000);
    expect(evaluateAccountStatus({ emailVerified: true, lockoutUntil: future }).lockedOut).toBe(
      true,
    );
    expect(evaluateAccountStatus({ emailVerified: true, lockoutUntil: past }).lockedOut).toBe(
      false,
    );
  });
});
