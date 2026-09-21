import { describe, it, expect, vi, afterEach } from 'vitest';
import { pickUniform, randomBelow, randomBigIntBelow } from '../src/lib/secureRandom';

/**
 * The rejection loop is driven by spying on `globalThis.crypto.getRandomValues`
 * rather than through an injectable parameter, which is this repository's
 * existing pattern and is why `secureRandom` has no test-only API surface.
 */

function feed(...responses: number[][]) {
  let call = 0;
  return vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((array: Uint8Array) => {
    const bytes = responses[Math.min(call, responses.length - 1)] ?? [];
    call += 1;
    array.set(bytes.slice(0, array.length));
    return array;
  }) as typeof globalThis.crypto.getRandomValues);
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('randomBigIntBelow', () => {
  it('refuses a non-positive bound rather than inventing an answer', () => {
    expect(() => randomBigIntBelow(0n)).toThrow(RangeError);
    expect(() => randomBigIntBelow(-1n)).toThrow(RangeError);
  });

  it('spends no entropy when there is only one possible value', () => {
    const spy = feed([0xff]);
    expect(randomBigIntBelow(1n)).toBe(0n);
    expect(spy).not.toHaveBeenCalled();
  });

  it('rejects an out-of-range draw and redraws, rather than folding it with a modulo', () => {
    // Bound 3: the mask keeps 2 bits, so a draw of 3 is out of range. Folding it
    // (`% 3`) would return 0 and make 0 twice as likely as 2. Rejecting is the
    // difference between a uniform generator and a biased one.
    const spy = feed([0xff], [0x00]);
    expect(randomBigIntBelow(3n)).toBe(0n);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('draws exactly the masked number of bytes, not a whole machine word', () => {
    // Whole-byte rejection over a 130-bit bound accepts under 1 per cent of
    // draws; masking to the bound's own bit length is what keeps it above a half.
    const spy = feed([0x00]);
    randomBigIntBelow(2n ** 130n);
    const buffer = spy.mock.calls[0]?.[0] as Uint8Array | undefined;
    expect(buffer?.length).toBe(17); // ceil(130 / 8)
  });

  it('never rejects for a power-of-two bound', () => {
    // All-ones is the worst case: it must still land inside the range.
    const spy = feed([0xff, 0xff, 0xff]);
    expect(randomBigIntBelow(2048n)).toBe(2047n);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('returns every value it is asked for, and only values in range', () => {
    for (let i = 0; i < 200; i += 1) {
      const value = randomBigIntBelow(88n);
      expect(value).toBeGreaterThanOrEqual(0n);
      expect(value).toBeLessThan(88n);
    }
  });

  it('throws when the platform has no CSPRNG, rather than falling back', () => {
    vi.stubGlobal('crypto', undefined);
    expect(() => randomBigIntBelow(10n)).toThrow(/Cryptographic random API is unavailable/);
  });
});

describe('randomBelow', () => {
  it.each([0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1])(
    'refuses the bound %p',
    (bound) => {
      expect(() => randomBelow(bound)).toThrow(RangeError);
    },
  );

  it('agrees with the bigint form', () => {
    feed([0x00]);
    expect(randomBelow(88)).toBe(0);
  });

  it('stays inside its range over many draws', () => {
    for (let i = 0; i < 200; i += 1) {
      const value = randomBelow(10);
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(10);
    }
  });
});

describe('pickUniform', () => {
  it('refuses an empty list instead of returning undefined', () => {
    expect(() => pickUniform([])).toThrow(RangeError);
  });

  it('throws when the drawn index holds nothing, instead of substituting a value', () => {
    // A sparse array is the only way to reach the guard, and the guard is the
    // whole point: the code this replaces answered `?? 'word'` here, which put a
    // literal constant into a passphrase and left the entropy claim unchanged.
    const holey = new Array<string>(2);
    holey[0] = 'a';
    feed([0xff]); // forces the index to 1, which holds nothing
    expect(() => pickUniform(holey)).toThrow(/no item at the drawn index/);
  });

  it('returns a member of the list', () => {
    const items = ['a', 'b', 'c'] as const;
    for (let i = 0; i < 50; i += 1) {
      expect(items).toContain(pickUniform(items));
    }
  });
});
