import { describe, it, expect } from 'vitest';
import { Secret } from 'otpauth';
import {
  TOTP_DEFAULTS,
  describeTotpFailure,
  isDecodableBase32,
  normaliseBase32,
  parseTotpValue,
  buildOtpauthUri,
  decodeBase32,
  encodeBase32,
  type TotpParseFailure,
} from '../src/lib/totp';

/**
 * `lib/totp.ts` is the one place that decides what a stored `data.totp` value
 * MEANS, in either of the two shapes the application writes into it. Every
 * assertion here names a shape that really occurs: the item form writes a bare
 * secret, the third-party import parsers write an `otpauth://` URI verbatim,
 * and `toOtpauthUri` emits one on every export.
 */

function expectOk(raw: string) {
  const result = parseTotpValue(raw);
  if (!result.ok) throw new Error(`expected a parse, got ${result.reason} for ${raw}`);
  return result.value;
}

function expectFail(raw: string): TotpParseFailure {
  const result = parseTotpValue(raw);
  if (result.ok) throw new Error(`expected a failure for ${raw}`);
  return result.reason;
}

describe('normaliseBase32', () => {
  it('strips the separators people paste, drops padding, and uppercases', () => {
    expect(normaliseBase32('jbsw y3dp-ehpk 3pxp')).toBe('JBSWY3DPEHPK3PXP');
    expect(normaliseBase32('JBSWY3DPEHPK3PXP====')).toBe('JBSWY3DPEHPK3PXP');
    expect(normaliseBase32('  ')).toBe('');
  });

  it('drops padding only at the end, so an interior "=" still fails the alphabet', () => {
    expect(isDecodableBase32(normaliseBase32('JBSW=Y3DPEHPK3PXP'))).toBe(false);
  });
});

describe('isDecodableBase32', () => {
  // A group of 8 characters is 5 bytes; the legal partial groups are 2, 4, 5
  // and 7 characters. Residues 1, 3 and 6 encode no whole number of bytes.
  it.each([
    ['JBSWY3DP', 8, true],
    ['JBSWY3DPEHPK3PXP', 16, true],
    ['JBSWY3DPEHPK3PXPJBSWY3DPEB', 26, true],
    ['JB', 2, true],
    ['JBSW', 4, true],
    ['JBSWY', 5, true],
    ['JBSWY3D', 7, true],
  ])('accepts %s (%i characters), which decodes to whole bytes', (value, length, expected) => {
    expect(value).toHaveLength(length);
    expect(isDecodableBase32(value)).toBe(expected);
  });

  it.each([
    ['J', 1],
    ['JBS', 3],
    ['JBSWY3', 6],
    ['JBSWY3DP2', 9],
  ])('rejects %s (%i characters), which decodes to a partial byte', (value, length) => {
    expect(value).toHaveLength(length);
    expect(isDecodableBase32(value)).toBe(false);
  });

  it('rejects the empty string and anything outside the base32 alphabet', () => {
    expect(isDecodableBase32('')).toBe(false);
    expect(isDecodableBase32('JBSWY3D1')).toBe(false); // 1 and 0 are not base32
    expect(isDecodableBase32('jbswy3dp')).toBe(false); // caller must normalise first
  });
});

describe('parseTotpValue, bare secret', () => {
  it('reads a bare secret as a TOTP on the specification defaults', () => {
    expect(expectOk('JBSWY3DPEHPK3PXP')).toEqual({
      type: 'totp',
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: '',
      account: '',
      algorithm: TOTP_DEFAULTS.algorithm,
      digits: TOTP_DEFAULTS.digits,
      period: TOTP_DEFAULTS.period,
      counter: null,
    });
  });

  it('normalises before judging, so a pasted secret works', () => {
    expect(expectOk('jbsw y3dp-ehpk 3pxp').secret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('reports an empty value as absent, not as malformed encoding', () => {
    expect(expectFail('')).toBe('empty');
    expect(expectFail('   ')).toBe('empty');
  });

  it('reports a malformed secret as malformed', () => {
    expect(expectFail('JBSWY3DP2')).toBe('invalid-base32');
    expect(expectFail('JBSWY3D1')).toBe('invalid-base32');
  });
});

describe('parseTotpValue, otpauth:// URI', () => {
  it('honours every parameter rather than assuming the defaults', () => {
    const value = expectOk(
      'otpauth://totp/GitHub:alice%40example.com' +
        '?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60',
    );
    expect(value).toEqual({
      type: 'totp',
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'GitHub',
      account: 'alice@example.com',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
      counter: null,
    });
  });

  it('falls back to the defaults only when a parameter is absent', () => {
    const value = expectOk('otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP');
    expect(value.algorithm).toBe('SHA1');
    expect(value.digits).toBe(6);
    expect(value.period).toBe(30);
    expect(value.issuer).toBe('');
    expect(value.account).toBe('alice');
  });

  it('takes the issuer from the label prefix when no issuer parameter is given', () => {
    expect(expectOk('otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP').issuer).toBe('Acme');
  });

  it('lets the issuer parameter win when the two disagree', () => {
    // The specification says they "should be equal" and names no winner; newer
    // implementations use the parameter, so it wins here.
    const value = expectOk('otpauth://totp/Stale:alice?secret=JBSWY3DPEHPK3PXP&issuer=Fresh');
    expect(value.issuer).toBe('Fresh');
  });

  it('accepts a percent-encoded colon and the optional spaces after it', () => {
    const value = expectOk(
      'otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=JBSWY3DPEHPK3PXP',
    );
    expect(value.issuer).toBe('Big Corporation');
    expect(value.account).toBe('alice@bigco.com');
  });

  it('folds the scheme and type case, which a non-special URL does not fold for it', () => {
    expect(expectOk('OTPAUTH://TOTP/alice?secret=JBSWY3DPEHPK3PXP').type).toBe('totp');
  });

  it('reads a counter-based URI as hotp, keeping the counter as a string', () => {
    const value = expectOk(
      'otpauth://hotp/Acme:alice?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615',
    );
    expect(value.type).toBe('hotp');
    // A decimal string, so a 64-bit counter survives a round trip that `number`
    // would silently round.
    expect(value.counter).toBe('18446744073709551615');
  });

  it('leaves the counter null for a counter-based URI that omits or malforms it', () => {
    expect(expectOk('otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP').counter).toBeNull();
    expect(expectOk('otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=x').counter).toBeNull();
  });

  it.each([
    ['otpauth://steam/a?secret=JBSWY3DPEHPK3PXP', 'invalid-uri'],
    ['otpauth://totp/a', 'missing-secret'],
    ['otpauth://totp/a?secret=', 'missing-secret'],
    ['otpauth://totp/a?secret=JBSWY3DP2', 'invalid-base32'],
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=MD5', 'unsupported-algorithm'],
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=9', 'unsupported-digits'],
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=six', 'unsupported-digits'],
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0', 'unsupported-period'],
    ['otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=-30', 'unsupported-period'],
  ])('refuses %s with %s', (uri, reason) => {
    expect(expectFail(uri)).toBe(reason);
  });

  it('refuses a malformed URI rather than throwing', () => {
    expect(expectFail('otpauth://')).toBe('invalid-uri');
    // One the URL parser itself rejects, rather than one it parses into a
    // shape this cannot use.
    expect(expectFail('otpauth://[')).toBe('invalid-uri');
  });

  it('refuses a label with a malformed percent escape, rather than throwing', () => {
    // `decodeURIComponent` throws a `URIError` on a truncated escape, and an
    // `otpauth://` link is a stored value that can be anything.
    expect(expectFail('otpauth://totp/%E0?secret=JBSWY3DPEHPK3PXP')).toBe('invalid-uri');
  });

  it('accepts the digit counts that occur in the wild', () => {
    for (const digits of [6, 7, 8]) {
      const value = expectOk(`otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=${String(digits)}`);
      expect(value.digits).toBe(digits);
    }
  });

  it('accepts every algorithm it claims to support, in any case', () => {
    expect(expectOk('otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=sha512').algorithm).toBe(
      'SHA512',
    );
  });
});

describe('describeTotpFailure', () => {
  const reasons: TotpParseFailure[] = [
    'empty',
    'invalid-base32',
    'invalid-uri',
    'missing-secret',
    'unsupported-algorithm',
    'unsupported-digits',
    'unsupported-period',
  ];

  it('has a distinct, non-empty sentence for every reason', () => {
    const sentences = reasons.map((reason) => describeTotpFailure(reason));
    for (const sentence of sentences) expect(sentence.length).toBeGreaterThan(0);
    expect(new Set(sentences).size).toBe(reasons.length);
  });

  it('keeps the wording the vault has always shown for a malformed secret', () => {
    expect(describeTotpFailure('invalid-base32')).toBe('Invalid TOTP secret (not valid base32)');
  });
});

describe('encodeBase32', () => {
  it('produces what an independent base32 decoder reads back as the same bytes', () => {
    // A genuine cross-implementation check: `otpauth` decodes; this encodes.
    // Nothing here shares code with it, so a bit-order or padding mistake shows
    // up as different bytes rather than as two copies of the same bug agreeing.
    for (let length = 1; length <= 40; length += 1) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length) & 0xff);
      const encoded = encodeBase32(bytes);
      expect([...Secret.fromBase32(encoded).bytes]).toEqual([...bytes]);
    }
  });

  it('emits no padding and only alphabet characters', () => {
    const encoded = encodeBase32(Uint8Array.from([1, 2, 3]));
    expect(encoded).toMatch(/^[A-Z2-7]+$/);
  });

  it('produces lengths this app will accept back', () => {
    // The residue rule and the encoder have to agree, or a secret this app
    // produced would be refused by this app.
    for (let length = 1; length <= 40; length += 1) {
      const encoded = encodeBase32(new Uint8Array(length));
      expect(parseTotpValue(encoded).ok).toBe(true);
    }
  });
});

describe('decodeBase32', () => {
  it('round-trips with the encoder for every length', () => {
    for (let length = 1; length <= 40; length += 1) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 53 + length) & 0xff);
      expect([...decodeBase32(encodeBase32(bytes))]).toEqual([...bytes]);
    }
  });

  it('agrees with an independent decoder', () => {
    const encoded = 'JBSWY3DPEHPK3PXP';
    expect([...decodeBase32(encoded)]).toEqual([...Secret.fromBase32(encoded).bytes]);
  });

  it('tolerates the separators and padding people paste', () => {
    expect([...decodeBase32('jbsw y3dp-ehpk 3pxp')]).toEqual([...decodeBase32('JBSWY3DPEHPK3PXP')]);
  });

  it('throws on a character outside the alphabet rather than skipping it', () => {
    // Skipping would silently shorten the key, and a shortened key generates
    // confidently wrong codes for ever.
    expect(() => decodeBase32('JBSW1234')).toThrow(RangeError);
  });
});

describe('buildOtpauthUri', () => {
  const BASE = {
    type: 'totp' as const,
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'GitHub',
    account: 'alice@example.com',
    algorithm: 'SHA256' as const,
    digits: 8,
    period: 60,
    counter: null,
  };

  it('round-trips through the parser without losing a parameter', () => {
    const built = buildOtpauthUri(BASE, 500);
    const parsed = parseTotpValue(built?.uri ?? '');
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value).toEqual({
        type: 'totp',
        secret: BASE.secret,
        issuer: 'GitHub',
        account: 'alice@example.com',
        algorithm: 'SHA256',
        digits: 8,
        period: 60,
        counter: null,
      });
    }
    expect(built?.truncated).toBe(false);
  });

  it('round-trips a counter-based entry, keeping the counter exact', () => {
    const built = buildOtpauthUri(
      { ...BASE, type: 'hotp', counter: '18446744073709551615', digits: 6 },
      500,
    );
    expect(built?.uri).toContain('counter=18446744073709551615');
    const parsed = parseTotpValue(built?.uri ?? '');
    expect(parsed.ok && parsed.value.type).toBe('hotp');
  });

  it('shortens the label to fit, and never the secret', () => {
    // An over-long value would fail validation on every DECRYPT, not just on
    // save, which would strand the whole item in a read-only state.
    const built = buildOtpauthUri(
      { ...BASE, issuer: 'I'.repeat(300), account: 'a'.repeat(300) },
      500,
    );
    expect(built).not.toBeNull();
    expect(built?.uri.length).toBeLessThanOrEqual(500);
    expect(built?.truncated).toBe(true);
    // The key survived intact, which is the whole point of trimming the label.
    const parsed = parseTotpValue(built?.uri ?? '');
    expect(parsed.ok && parsed.value.secret).toBe(BASE.secret);
  });

  it('refuses rather than storing something shorter when even the bare key will not fit', () => {
    expect(buildOtpauthUri(BASE, 40)).toBeNull();
  });

  it('omits the issuer entirely when there is none, rather than emitting an empty label', () => {
    const built = buildOtpauthUri({ ...BASE, issuer: '' }, 500);
    expect(built?.uri).not.toContain('issuer=');
    expect(built?.uri).toContain('/alice%40example.com?');
  });
});
