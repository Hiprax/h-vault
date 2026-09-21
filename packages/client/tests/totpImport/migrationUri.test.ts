import { describe, it, expect } from 'vitest';
import { isMigrationUri, parseMigrationUri } from '../../src/services/totpImport/migrationUri';
import { MigrationParseError } from '../../src/services/totpImport/migrationReader';
import {
  encodeMigrationUri,
  encodeMigrationUriWithLiteralPlus,
  encodePayload,
  sampleSecret,
  toBase64,
} from '../support/migrationEncoder';

function codeFor(uri: string): string {
  try {
    parseMigrationUri(uri);
  } catch (error) {
    if (error instanceof MigrationParseError) return error.code;
    return `unexpected:${String(error)}`;
  }
  return 'no-error';
}

const ONE_ACCOUNT = {
  entries: [{ secret: sampleSecret(), name: 'Acme:alice', issuer: 'Acme' }],
  version: 1,
  batchSize: 1,
  batchIndex: 0,
  batchId: 7,
};

describe('isMigrationUri', () => {
  it('recognises the export scheme in any case, and nothing else', () => {
    expect(isMigrationUri('otpauth-migration://offline?data=AA')).toBe(true);
    expect(isMigrationUri('OTPAUTH-MIGRATION://offline?data=AA')).toBe(true);
    expect(isMigrationUri('  otpauth-migration://offline?data=AA  ')).toBe(true);
    expect(isMigrationUri('otpauth://totp/a?secret=JBSWY3DPEHPK3PXP')).toBe(false);
    expect(isMigrationUri('https://example.com')).toBe(false);
  });
});

describe('parseMigrationUri', () => {
  it('reads a link exactly as Google Authenticator encodes one', () => {
    const payload = parseMigrationUri(encodeMigrationUri(ONE_ACCOUNT));
    expect(payload.entries).toHaveLength(1);
    expect(payload.entries[0]?.issuer).toBe('Acme');
    expect(payload.batchId).toBe(7);
  });

  it('reads a link whose base64 carries an UNENCODED plus sign', () => {
    // The trap this whole module is shaped around. `URLSearchParams` implements
    // form decoding, where `+` means SPACE, so the obvious
    // `new URL(uri).searchParams.get('data')` silently corrupts any payload
    // containing one and the failure looks exactly like a bad camera read.
    const uri = encodeMigrationUriWithLiteralPlus(ONE_ACCOUNT);
    expect(uri).toContain('+');

    // Proof the fixture really is the dangerous shape: the naive read mangles it.
    const naive = new URL(uri).searchParams.get('data') ?? '';
    expect(naive).toContain(' ');
    expect(naive).not.toBe(toBase64(encodePayload(ONE_ACCOUNT)));

    expect(parseMigrationUri(uri).entries).toHaveLength(1);
  });

  it('accepts the URL-safe alphabet and rebuilds missing padding', () => {
    // Derived from a payload that really does contain a `+`, so the substitution
    // below is exercised rather than being a no-op on a fixture that happens to
    // contain neither character.
    const withPlus = encodeMigrationUriWithLiteralPlus(ONE_ACCOUNT);
    const base64 = withPlus.slice(withPlus.indexOf('data=') + 5);
    expect(base64).toContain('+');

    const urlSafe = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(urlSafe).toContain('-');
    expect(parseMigrationUri(`otpauth-migration://offline?data=${urlSafe}`).entries).toHaveLength(
      1,
    );
  });

  it.each([
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP', 'malformed'],
    ['otpauth-migration://offline', 'malformed'],
    ['otpauth-migration://offline?data=', 'malformed'],
    ['otpauth-migration://offline?data=!!!!', 'malformed'],
    ['otpauth-migration://offline?data=%E0%A4%A', 'malformed'],
  ])('refuses %s', (uri, code) => {
    expect(codeFor(uri)).toBe(code);
  });

  it('refuses a link longer than it will read, before decoding anything', () => {
    const huge = `otpauth-migration://offline?data=${'A'.repeat(20_000)}`;
    expect(codeFor(huge)).toBe('too-large');
  });

  it('refuses a payload that decodes to more bytes than it will read', () => {
    const big = toBase64(new Uint8Array(5000));
    expect(codeFor(`otpauth-migration://offline?data=${encodeURIComponent(big)}`)).toBe(
      'too-large',
    );
  });

  it('refuses base64 that passes the alphabet but cannot be decoded', () => {
    // A single character pads to "A===", which is a valid-looking but
    // undecodable group. The alphabet check alone would let it through.
    expect(codeFor('otpauth-migration://offline?data=A')).toBe('malformed');
  });

  it('refuses a link the URL parser itself rejects', () => {
    expect(codeFor('otpauth-migration://[')).toBe('malformed');
  });

  it('never throws anything that is not a MigrationParseError', () => {
    for (const uri of ['', 'otpauth-migration://', 'otpauth-migration://offline?data=A', 'x']) {
      expect(codeFor(uri).startsWith('unexpected:')).toBe(false);
    }
  });
});
