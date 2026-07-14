import { describe, it, expect } from 'vitest';
import { publicConfigDataSchema, publicConfigResponseSchema } from '../src/schemas/config.js';

describe('publicConfigResponseSchema', () => {
  it('accepts a valid response envelope', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 100 } },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.data.fileEncryption.maxSizeMB).toBe(100);
    }
  });

  it('accepts an optional message field', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 25 } },
      message: 'ok',
    });
    expect(result.success).toBe(true);
  });

  it('rejects a missing maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: {} },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a missing fileEncryption object', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: {},
    });
    expect(result.success).toBe(false);
  });

  it('rejects a negative maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: -1 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a zero maxSizeMB (must be positive)', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 0 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a non-integer maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 12.5 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a success:false envelope', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: false,
      data: { fileEncryption: { maxSizeMB: 100 } },
    });
    expect(result.success).toBe(false);
  });
});

describe('publicConfigDataSchema', () => {
  it('validates the inner PublicConfig shape independently', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('rejects a negative maxSizeMB', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: -5 },
    });
    expect(result.success).toBe(false);
  });
});
