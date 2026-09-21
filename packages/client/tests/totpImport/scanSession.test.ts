import { describe, it, expect, beforeEach } from 'vitest';
import { MAX_LOGIN_TOTP_LENGTH } from '@hvault/shared';
import {
  endScanSession,
  heldSecretCount,
  holdEntries,
  otpauthUriFor,
  secretFor,
} from '../../src/services/totpImport/scanSession';
import { parseTotpValue } from '../../src/lib/totp';
import type { MigrationEntry } from '../../src/services/totpImport/migrationReader';

function entry(overrides: Partial<MigrationEntry> = {}): MigrationEntry {
  return {
    type: 'totp',
    secret: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    name: 'alice@example.com',
    issuer: 'Acme',
    algorithm: 'SHA1',
    digits: 6,
    counter: null,
    ...overrides,
  };
}

beforeEach(() => {
  endScanSession();
});

describe('holding decoded keys', () => {
  it('returns only display metadata, never the key itself', () => {
    const [held] = holdEntries([entry()]);
    // The shape IS the protection: a component cannot leak a prop that does not
    // exist, so nothing reaches React DevTools or a store.
    expect(held).toBeDefined();
    expect(Object.keys(held ?? {})).not.toContain('secret');
    expect(JSON.stringify(held)).not.toContain('AEBAGBA');
  });

  it('hands back the key only when asked, by id', () => {
    const [held] = holdEntries([entry()]);
    expect(secretFor(held?.id ?? '')).toMatch(/^[A-Z2-7]+$/);
    expect(secretFor('nothing-like-this')).toBeNull();
  });

  it('builds a storable otpauth URI that reads back with every parameter intact', () => {
    const [held] = holdEntries([entry({ algorithm: 'SHA256', digits: 8 })]);
    const uri = otpauthUriFor(held!) ?? '';
    const parsed = parseTotpValue(uri);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.algorithm).toBe('SHA256');
      expect(parsed.value.digits).toBe(8);
      expect(parsed.value.issuer).toBe('Acme');
      // The migration payload carries no period, so 30 is emitted as a constant
      // rather than guessed at.
      expect(parsed.value.period).toBe(30);
    }
  });

  it('marks an entry it cannot generate codes for, rather than dropping it', () => {
    // The user's other authenticator may well support MD5; the key is still
    // worth copying even though this app cannot display a code for it.
    const [held] = holdEntries([entry({ algorithm: 'MD5' })]);
    expect(held?.generatable).toBe(false);
    expect(otpauthUriFor(held!)).toBeNull();
    expect(secretFor(held?.id ?? '')).not.toBeNull();
  });

  it('shortens an over-long label and says it did, rather than storing something unreadable', () => {
    // An over-length `data.totp` fails validation on every DECRYPT, which would
    // strand the whole item in a read-only state the user cannot edit out of.
    const [held] = holdEntries([entry({ issuer: 'I'.repeat(400), name: 'a'.repeat(400) })]);
    expect(held?.labelTruncated).toBe(true);
    expect((otpauthUriFor(held!) ?? '').length).toBeLessThanOrEqual(MAX_LOGIN_TOTP_LENGTH);
  });

  it('keeps a counter-based entry usable, counter intact', () => {
    const [held] = holdEntries([entry({ type: 'hotp', counter: '18446744073709551615' })]);
    expect(otpauthUriFor(held!)).toContain('counter=18446744073709551615');
  });

  it('gives every entry a distinct id, including identical accounts', () => {
    const entries = holdEntries([entry(), entry()]);
    expect(entries).toHaveLength(2);
    expect(entries[0]?.id).not.toBe(entries[1]?.id);
  });
});

describe('endScanSession', () => {
  it('zeroes the key bytes in place, not merely the reference to them', () => {
    const secret = Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
    holdEntries([entry({ secret })]);
    expect(heldSecretCount()).toBe(1);

    endScanSession();

    // The array the caller still holds is the one that was stored, so this is
    // the actual guarantee: the canonical copy is gone from memory.
    expect([...secret]).toEqual(Array<number>(10).fill(0));
    expect(heldSecretCount()).toBe(0);
  });

  it('leaves nothing retrievable afterwards', () => {
    const [held] = holdEntries([entry()]);
    endScanSession();
    expect(secretFor(held?.id ?? '')).toBeNull();
    expect(otpauthUriFor(held!)).toBeNull();
  });

  it('is safe to call when nothing is held', () => {
    expect(() => {
      endScanSession();
      endScanSession();
    }).not.toThrow();
  });
});
