/**
 * Tests for MEDIUM-12: Device fingerprint utility.
 *
 * Verifies that getDeviceFingerprint generates a stable 16-char hex string,
 * caches it in localStorage, and returns the cached value on subsequent calls.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { getDeviceFingerprint } from '../src/utils/deviceFingerprint.js';

describe('getDeviceFingerprint', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return a 16-character hex string', async () => {
    const fp = await getDeviceFingerprint();
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
  });

  it('should cache the fingerprint in localStorage', async () => {
    const fp = await getDeviceFingerprint();
    expect(localStorage.getItem('__hv_device_fingerprint')).toBe(fp);
  });

  it('should return the same fingerprint on subsequent calls', async () => {
    const fp1 = await getDeviceFingerprint();
    const fp2 = await getDeviceFingerprint();
    expect(fp1).toBe(fp2);
  });

  it('should return the stored fingerprint from localStorage without rehashing', async () => {
    localStorage.setItem('__hv_device_fingerprint', 'abcdef0123456789');
    const digestSpy = vi.spyOn(crypto.subtle, 'digest');

    const fp = await getDeviceFingerprint();

    expect(fp).toBe('abcdef0123456789');
    expect(digestSpy).not.toHaveBeenCalled();
  });

  it('should regenerate fingerprint if stored value has wrong length', async () => {
    localStorage.setItem('__hv_device_fingerprint', 'tooshort');

    const fp = await getDeviceFingerprint();

    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    expect(fp).not.toBe('tooshort');
  });

  it('should work when localStorage is unavailable for reading', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('localStorage unavailable');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('localStorage unavailable');
    });

    const fp = await getDeviceFingerprint();
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
  });
});
