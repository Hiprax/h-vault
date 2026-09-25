/**
 * `staleVaultKeyVersion` (`services/api/staleVaultKey.ts`) reads the one refusal
 * in this API that carries a number: the recoverable 409 a write earns when it
 * names a vault-key generation the account has left behind.
 *
 * Getting it wrong is not a cosmetic failure. A `null` where a version exists
 * turns a recoverable conflict into a failed upload and, on the vault write
 * paths, into a save that is refused with nothing on screen saying why. A number
 * invented from a malformed body is worse: `0` means "this account has never
 * rotated", so reading one out of a missing field would tell a session it is
 * healthy at the exact moment it is not.
 *
 * Three other refusals share the 409 status and carry no `data` at all — a
 * rotation in progress, a duplicate folder name, a concurrent import — and each
 * has a different remedy, so the discriminant under test is the PRESENCE of a
 * non-negative integer `data.vaultKeyVersion` and never the message.
 *
 * These cases moved here with the function, which lived in `documentsApi.ts`
 * while the document completion was its only source.
 */

import { describe, it, expect } from 'vitest';
import { AxiosError } from 'axios';
import { staleVaultKeyVersion } from '../src/services/api/staleVaultKey.js';

describe('staleVaultKeyVersion', () => {
  const conflict = (data: unknown): AxiosError =>
    new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, {
      status: 409,
      statusText: 'Conflict',
      headers: {},
      config: { headers: {} } as never,
      data,
    });

  it('reads the version out of a stale-key 409', () => {
    expect(staleVaultKeyVersion(conflict({ success: false, data: { vaultKeyVersion: 4 } }))).toBe(
      4,
    );
  });

  it('reads a version of ZERO rather than treating it as absent', () => {
    // The boundary that a truthiness check gets wrong: an account that has never
    // rotated is at version 0, and answering `null` there would report the
    // recoverable refusal as an unrecoverable one.
    expect(staleVaultKeyVersion(conflict({ success: false, data: { vaultKeyVersion: 0 } }))).toBe(
      0,
    );
  });

  it('answers null for a 409 that carries no version', () => {
    // The per-upload lock's "already being completed" conflict looks like this.
    expect(
      staleVaultKeyVersion(conflict({ success: false, message: 'already completing' })),
    ).toBeNull();
  });

  it('answers null for a 409 whose payload is present but names no version', () => {
    // The envelope carries a `data` key, so the first guard passes; the payload
    // itself is what has nothing to read.
    expect(staleVaultKeyVersion(conflict({ success: false, data: { other: 1 } }))).toBeNull();
    expect(staleVaultKeyVersion(conflict({ success: false, data: 'not an object' }))).toBeNull();
    expect(staleVaultKeyVersion(conflict({ success: false, data: null }))).toBeNull();
  });

  it('answers null for a 409 whose version is not a non-negative integer', () => {
    expect(staleVaultKeyVersion(conflict({ data: { vaultKeyVersion: '4' } }))).toBeNull();
    expect(staleVaultKeyVersion(conflict({ data: { vaultKeyVersion: -1 } }))).toBeNull();
    expect(staleVaultKeyVersion(conflict({ data: { vaultKeyVersion: 1.5 } }))).toBeNull();
    expect(staleVaultKeyVersion(conflict({ data: { vaultKeyVersion: null } }))).toBeNull();
  });

  it('answers null for a 409 whose body is not an object', () => {
    expect(staleVaultKeyVersion(conflict('Conflict'))).toBeNull();
    expect(staleVaultKeyVersion(conflict(undefined))).toBeNull();
  });

  it('answers null for any status other than 409, even one carrying a version', () => {
    const badRequest = new AxiosError('nope', 'ERR_BAD_REQUEST', undefined, undefined, {
      status: 400,
      statusText: 'Bad Request',
      headers: {},
      config: { headers: {} } as never,
      data: { data: { vaultKeyVersion: 9 } },
    });

    expect(staleVaultKeyVersion(badRequest)).toBeNull();
  });

  it('answers null for a rejection that is not an axios error at all', () => {
    expect(staleVaultKeyVersion(new Error('offline'))).toBeNull();
    expect(staleVaultKeyVersion(null)).toBeNull();
    expect(
      staleVaultKeyVersion({ response: { status: 409, data: { data: { vaultKeyVersion: 3 } } } }),
    ).toBeNull();
  });
});
