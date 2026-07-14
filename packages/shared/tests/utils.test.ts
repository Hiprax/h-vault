import { describe, it, expect } from 'vitest';
import { maskEmail, formatBytes, generateId, normalizeUri } from '../src/utils/index.js';

// ---------------------------------------------------------------------------
// maskEmail
// ---------------------------------------------------------------------------
describe('maskEmail', () => {
  it('masks a normal email', () => {
    expect(maskEmail('john@example.com')).toBe('j***n@example.com');
  });

  it('masks a two-character local part with first and last', () => {
    expect(maskEmail('ab@example.com')).toBe('a***b@example.com');
  });

  it('masks a single-character local part', () => {
    expect(maskEmail('a@example.com')).toBe('a***@example.com');
  });

  it('returns *** for missing @ symbol', () => {
    expect(maskEmail('noemail')).toBe('***');
  });

  it('returns *** for empty string', () => {
    expect(maskEmail('')).toBe('***');
  });

  it('returns *** when @ is first character', () => {
    expect(maskEmail('@example.com')).toBe('***');
  });

  it('handles long local parts', () => {
    expect(maskEmail('longusername@example.com')).toBe('l***e@example.com');
  });

  it('uses last @ when multiple @ signs exist', () => {
    // lastIndexOf('@') keeps the full local part ('user@name') and masks it as
    // 'u***e'; an indexOf('@') implementation would return 'u***r@name@example.com'.
    expect(maskEmail('user@name@example.com')).toBe('u***e@example.com');
  });
});

// ---------------------------------------------------------------------------
// formatBytes
// ---------------------------------------------------------------------------
describe('formatBytes', () => {
  it('returns "0 B" for zero bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('formats bytes', () => {
    expect(formatBytes(500)).toBe('500 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(1024)).toBe('1 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(1024 * 1024)).toBe('1 MB');
  });

  it('formats gigabytes', () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB');
  });

  it('formats terabytes', () => {
    expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
  });

  it('formats fractional values', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
  });

  it('handles negative bytes', () => {
    expect(formatBytes(-1024)).toBe('0 B');
  });

  it('handles NaN', () => {
    expect(formatBytes(NaN)).toBe('0 B');
  });

  it('handles Infinity', () => {
    expect(formatBytes(Infinity)).toBe('0 B');
  });

  it('handles -Infinity', () => {
    expect(formatBytes(-Infinity)).toBe('0 B');
  });

  it('formats large byte values', () => {
    const result = formatBytes(5 * 1024 * 1024 * 1024 * 1024 * 1024);
    expect(result).toContain('TB');
  });

  // Sub-byte inputs are the one range the guards above do not exclude: they are
  // finite, positive and non-zero, so they reach the logarithm. log(bytes) is
  // negative there, and Math.floor rounds toward -Infinity, so the unit index
  // went negative — which made Math.pow(1024, i) a fraction and turned the
  // division into a multiplication. formatBytes(0.5) reported "512 B", the very
  // same string as formatBytes(512), a 1024x overstatement of a value that is
  // not even one byte.
  it('does not overstate a sub-byte value as a whole number of bytes', () => {
    expect(formatBytes(0.5)).toBe('0.5 B');
    expect(formatBytes(0.5)).not.toBe(formatBytes(512));
  });

  it('rounds a very small sub-byte value down to "0 B" rather than inflating it', () => {
    expect(formatBytes(0.001)).toBe('0 B');
  });

  // The smallest representable double: the pre-clamp exponent was -108, and
  // Math.pow(1024, -108) underflows to exactly 0, so dividing by it yielded
  // Infinity and the function returned the string "Infinity B".
  it('never reports Infinity for the smallest representable positive value', () => {
    const result = formatBytes(Number.MIN_VALUE);
    expect(result).toBe('0 B');
    expect(result).not.toContain('Infinity');
  });

  it('formats every value below 1 KB exactly, including sub-byte ones', () => {
    const cases: [number, string][] = [
      [Number.MIN_VALUE, '0 B'],
      [0.001, '0 B'],
      [0.5, '0.5 B'],
      [1, '1 B'],
      [512, '512 B'],
      [1023, '1023 B'],
    ];
    for (const [value, expected] of cases) {
      expect(formatBytes(value)).toBe(expected);
    }
  });
});

// ---------------------------------------------------------------------------
// generateId
// ---------------------------------------------------------------------------
describe('generateId', () => {
  it('returns a 32-character hex string', () => {
    const id = generateId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateId()));
    expect(ids.size).toBe(100);
  });

  it('does not contain hyphens', () => {
    const id = generateId();
    expect(id).not.toContain('-');
  });

  it('falls back to getRandomValues when randomUUID is unavailable', () => {
    const origRandomUUID = crypto.randomUUID;
    // Temporarily remove randomUUID to exercise fallback
    Object.defineProperty(crypto, 'randomUUID', { value: undefined, configurable: true });
    try {
      const id = generateId();
      expect(id).toMatch(/^[0-9a-f]{32}$/);
      expect(id).toHaveLength(32);
    } finally {
      Object.defineProperty(crypto, 'randomUUID', { value: origRandomUUID, configurable: true });
    }
  });

  it('fallback generates unique IDs', () => {
    const origRandomUUID = crypto.randomUUID;
    Object.defineProperty(crypto, 'randomUUID', { value: undefined, configurable: true });
    try {
      const ids = new Set(Array.from({ length: 50 }, () => generateId()));
      expect(ids.size).toBe(50);
    } finally {
      Object.defineProperty(crypto, 'randomUUID', { value: origRandomUUID, configurable: true });
    }
  });

  it('throws when both randomUUID and getRandomValues are unavailable', () => {
    const origRandomUUID = crypto.randomUUID;
    const origGetRandomValues = crypto.getRandomValues;
    Object.defineProperty(crypto, 'randomUUID', { value: undefined, configurable: true });
    Object.defineProperty(crypto, 'getRandomValues', { value: undefined, configurable: true });
    try {
      expect(() => generateId()).toThrow('Cryptographic random API is unavailable');
    } finally {
      Object.defineProperty(crypto, 'randomUUID', { value: origRandomUUID, configurable: true });
      Object.defineProperty(crypto, 'getRandomValues', {
        value: origGetRandomValues,
        configurable: true,
      });
    }
  });

  it('throws when the crypto global itself is undefined', () => {
    const globalRef = globalThis as { crypto?: Crypto };
    const origCrypto = globalRef.crypto;
    Object.defineProperty(globalRef, 'crypto', { value: undefined, configurable: true });
    try {
      expect(() => generateId()).toThrow('Cryptographic random API is unavailable');
    } finally {
      Object.defineProperty(globalRef, 'crypto', { value: origCrypto, configurable: true });
    }
  });
});

// ---------------------------------------------------------------------------
// normalizeUri
// ---------------------------------------------------------------------------
describe('normalizeUri', () => {
  it('prepends https:// to bare domains', () => {
    expect(normalizeUri('example.com')).toBe('https://example.com');
  });

  it('prepends https:// to domains with paths', () => {
    expect(normalizeUri('example.com/login')).toBe('https://example.com/login');
  });

  it('preserves http:// URIs', () => {
    expect(normalizeUri('http://example.com')).toBe('http://example.com');
  });

  it('preserves https:// URIs', () => {
    expect(normalizeUri('https://example.com')).toBe('https://example.com');
  });

  it('preserves mailto: URIs', () => {
    expect(normalizeUri('mailto:user@example.com')).toBe('mailto:user@example.com');
  });

  it('returns empty string as-is', () => {
    expect(normalizeUri('')).toBe('');
  });

  it('does not prefix URIs with other schemes', () => {
    expect(normalizeUri('ftp://example.com')).toBe('ftp://example.com');
  });

  it('does not prefix javascript: URIs (XSS prevention handled by isSafeUrl)', () => {
    expect(normalizeUri('javascript:alert(1)')).toBe('javascript:alert(1)');
  });

  it('is case-insensitive for protocol detection', () => {
    expect(normalizeUri('HTTPS://Example.com')).toBe('HTTPS://Example.com');
    expect(normalizeUri('HTTP://Example.com')).toBe('HTTP://Example.com');
  });

  it('handles protocol-relative URIs (//example.com)', () => {
    expect(normalizeUri('//example.com')).toBe('https://example.com');
  });

  it('handles protocol-relative URIs with paths', () => {
    expect(normalizeUri('//example.com/path')).toBe('https://example.com/path');
  });
});
