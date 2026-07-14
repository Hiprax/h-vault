import { describe, it, expect } from 'vitest';
import { PASSPHRASE_WORDS } from '../../src/constants/passphraseWords';

describe('PASSPHRASE_WORDS', () => {
  it('contains exactly 2048 words (a power of two → exactly 11 bits per word)', () => {
    expect(PASSPHRASE_WORDS.length).toBe(2048);
  });

  it('yields exactly 11 bits of entropy per word', () => {
    // log2(2048) === 11 exactly. The generator relies on this for its honest entropy
    // readout, so pin it: any change to the list size must be a deliberate power of two.
    expect(Math.log2(PASSPHRASE_WORDS.length)).toBe(11);
  });

  it('all entries are lowercase strings between 3 and 8 characters', () => {
    for (const word of PASSPHRASE_WORDS) {
      expect(word).toMatch(/^[a-z]+$/);
      expect(word.length).toBeGreaterThanOrEqual(3);
      expect(word.length).toBeLessThanOrEqual(8);
    }
  });

  it('contains no duplicate words', () => {
    const unique = new Set(PASSPHRASE_WORDS);
    expect(unique.size).toBe(PASSPHRASE_WORDS.length);
  });

  it('provides at least 50 bits of entropy for a 5-word passphrase', () => {
    const entropyPerWord = Math.log2(PASSPHRASE_WORDS.length);
    const fiveWordEntropy = entropyPerWord * 5;
    expect(fiveWordEntropy).toBeGreaterThanOrEqual(50);
  });
});
