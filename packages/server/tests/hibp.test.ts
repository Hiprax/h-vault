import { describe, it, expect, vi, afterEach } from 'vitest';
import axios from 'axios';
import { stripPaddingRows, fetchRangeFromHibp } from '../src/utils/hibp.js';

describe('utils/hibp', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('stripPaddingRows', () => {
    it('drops count-0 padding rows and keeps real rows', () => {
      const body = 'AAAAA:2\r\nBBBBB:0\r\nCCCCC:7';
      expect(stripPaddingRows(body)).toBe('AAAAA:2\r\nCCCCC:7');
    });

    it('does not mistake a high count ending in 0 for padding', () => {
      const body = 'AAAAA:10\r\nBBBBB:100\r\nCCCCC:0';
      expect(stripPaddingRows(body)).toBe('AAAAA:10\r\nBBBBB:100');
    });

    it('drops blank and malformed (colon-less) lines', () => {
      const body = 'AAAAA:3\r\n\r\nnotarow\r\nBBBBB:1';
      expect(stripPaddingRows(body)).toBe('AAAAA:3\r\nBBBBB:1');
    });

    it('normalizes lone-LF input to CRLF output', () => {
      expect(stripPaddingRows('AAAAA:1\nBBBBB:2')).toBe('AAAAA:1\r\nBBBBB:2');
    });

    it('returns an empty string when every row is padding', () => {
      expect(stripPaddingRows('AAAAA:0\r\nBBBBB:0')).toBe('');
    });

    it('returns an empty string for an empty body', () => {
      expect(stripPaddingRows('')).toBe('');
    });
  });

  describe('fetchRangeFromHibp', () => {
    it('requests the k-anonymity URL with Add-Padding + SSRF hardening and returns stripped rows', async () => {
      const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: 'REAL:5\r\nPADDING:0' });

      const result = await fetchRangeFromHibp('5BAA6');

      expect(result).toBe('REAL:5');
      expect(getSpy).toHaveBeenCalledWith(
        'https://api.pwnedpasswords.com/range/5BAA6',
        expect.objectContaining({
          maxRedirects: 0,
          timeout: 10_000,
          responseType: 'text',
          headers: expect.objectContaining({
            'User-Agent': 'H-Vault-Password-Manager',
            'Add-Padding': 'true',
          }),
        }),
      );
    });

    it('propagates a network error', async () => {
      vi.spyOn(axios, 'get').mockRejectedValue(new Error('ETIMEDOUT'));
      await expect(fetchRangeFromHibp('ABCDE')).rejects.toThrow('ETIMEDOUT');
    });
  });
});
