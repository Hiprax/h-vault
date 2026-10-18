/**
 * The two ways an unlock can fail AFTER `verify-unlock` has accepted the master
 * password.
 *
 * Neither is a wrong password, so the unlock screen reports each in its own words
 * and charges no attempt against the local lockout: the proof succeeded, and a
 * counter fed by failures the user did not cause locks them out of their own vault
 * for nothing.
 *
 * A module of their own rather than exports of `authStore`, because the screen
 * tests replace that module wholesale, and a class the mock does not provide would
 * turn every `instanceof` below into a TypeError.
 */

/**
 * The account's CURRENT wrapped vault key, as `verify-unlock` (or the profile)
 * answered with it, will not open under the master key derived from a password the
 * server has just accepted.
 *
 * Never answered by retrying the copy the browser cached at sign-in: that is
 * exactly the superseded key the live wrapper exists to replace.
 */
export class StoredVaultKeyUnreadableError extends Error {
  constructor() {
    super('The vault key this account stores could not be opened. Sign out and sign in again.');
    this.name = 'StoredVaultKeyUnreadableError';
  }
}

/**
 * The session an unlock began for was gone by the time the key had been opened
 * (another tab signed out, which clears the store). Nothing was written, and the
 * keys the unlock derived were cleared.
 */
export class UnlockSessionChangedError extends Error {
  constructor() {
    super('This session ended while the vault was being unlocked. Sign in again.');
    this.name = 'UnlockSessionChangedError';
  }
}
