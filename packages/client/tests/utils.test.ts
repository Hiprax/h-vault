import { describe, it, expect } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';

import { cn, getApiErrorMessage, isSafeUrl } from '../src/lib/utils';

// ---------------------------------------------------------------------------
// cn() — class name merging via clsx + tailwind-merge
// ---------------------------------------------------------------------------

describe('cn', () => {
  it('returns empty string when called with no arguments', () => {
    expect(cn()).toBe('');
  });

  it('merges multiple class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar');
  });

  it('handles conditional classes (false values are omitted)', () => {
    expect(cn('base', false && 'hidden', 'extra')).toBe('base extra');
  });

  it('handles undefined and null values', () => {
    expect(cn('a', undefined, null, 'b')).toBe('a b');
  });

  it('deduplicates conflicting Tailwind spacing classes (last wins)', () => {
    // tailwind-merge resolves conflicting utilities — p-2 overrides p-4
    expect(cn('p-4', 'p-2')).toBe('p-2');
  });

  it('merges conflicting Tailwind color utility classes (last wins)', () => {
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500');
  });

  it('handles array inputs', () => {
    expect(cn(['foo', 'bar'])).toBe('foo bar');
  });

  it('handles object inputs (truthy values included, falsy omitted)', () => {
    expect(cn({ hidden: true, visible: false })).toBe('hidden');
  });

  it('handles mixed input types together', () => {
    expect(cn('base', ['arr1', 'arr2'], { conditional: true }, undefined)).toBe(
      'base arr1 arr2 conditional',
    );
  });

  it('returns empty string for all-falsy inputs', () => {
    expect(cn(false, null, undefined, 0, '')).toBe('');
  });
});

// ---------------------------------------------------------------------------
// getApiErrorMessage() — extracting user-friendly error messages
// ---------------------------------------------------------------------------

/**
 * Helper to build a realistic AxiosError with the given response data.
 */
function makeAxiosError(data?: Record<string, unknown>, status = 400): AxiosError {
  const headers = new AxiosHeaders();
  const config = { headers: new AxiosHeaders() };

  const response = data
    ? {
        data,
        status,
        statusText: 'Bad Request',
        headers,
        config,
      }
    : undefined;

  const error = new AxiosError(
    `Request failed with status code ${String(status)}`,
    AxiosError.ERR_BAD_REQUEST,
    config as never,
    undefined,
    response as never,
  );

  return error;
}

describe('getApiErrorMessage', () => {
  it('returns the server message from an Axios error response', () => {
    const err = makeAxiosError({ message: 'Email already in use' });
    expect(getApiErrorMessage(err)).toBe('Email already in use');
  });

  it('returns Axios Error.message when the Axios error has no response (network error)', () => {
    // Network error — no response object at all. AxiosError is still an Error,
    // so the function falls through to the `error instanceof Error` branch.
    const err = new AxiosError('Network Error', AxiosError.ERR_NETWORK, {
      headers: new AxiosHeaders(),
    } as never);
    expect(getApiErrorMessage(err)).toBe('Network Error');
  });

  it('returns Axios Error.message when the Axios error has no response data', () => {
    // response is undefined in makeAxiosError when data is not provided.
    // Falls through to `error instanceof Error` → err.message.
    const err = makeAxiosError(undefined, 500);
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 500');
  });

  it('returns Axios Error.message when the server message is empty string', () => {
    // An empty string is not a valid server message (length check fails),
    // so the function falls through to `error instanceof Error`.
    const err = makeAxiosError({ message: '' });
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 400');
  });

  it('returns Error.message for a non-Axios Error instance', () => {
    const err = new Error('Something broke');
    expect(getApiErrorMessage(err)).toBe('Something broke');
  });

  it('returns the default fallback for a plain string value', () => {
    expect(getApiErrorMessage('oops')).toBe('Something went wrong. Please try again.');
  });

  it('returns the default fallback for a number value', () => {
    expect(getApiErrorMessage(42)).toBe('Something went wrong. Please try again.');
  });

  it('returns the default fallback for null', () => {
    expect(getApiErrorMessage(null)).toBe('Something went wrong. Please try again.');
  });

  it('returns the default fallback for undefined', () => {
    expect(getApiErrorMessage(undefined)).toBe('Something went wrong. Please try again.');
  });

  it('returns a custom fallback when provided for non-Error values', () => {
    expect(getApiErrorMessage('whatever', 'Custom fallback')).toBe('Custom fallback');
  });

  it('prefers server message over the generic Axios Error.message', () => {
    // An AxiosError is also an Error. The server message should take priority
    // over the generic "Request failed with status code …" message.
    const err = makeAxiosError({ message: 'Invalid credentials' });
    expect(err.message).toContain('Request failed with status code');
    expect(getApiErrorMessage(err)).toBe('Invalid credentials');
  });

  it('falls back to Axios Error.message when response.data.message is a number', () => {
    // Not a string, so the server-message check fails; falls to instanceof Error.
    const err = makeAxiosError({ message: 12345 });
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 400');
  });

  it('falls back to Axios Error.message when response.data.message is an object', () => {
    const err = makeAxiosError({ message: { nested: 'value' } });
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 400');
  });

  it('falls back to Axios Error.message when response.data.message is a boolean', () => {
    const err = makeAxiosError({ message: true });
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 400');
  });

  it('falls back to Axios Error.message when response.data has no message field', () => {
    const err = makeAxiosError({ error: 'something' });
    expect(getApiErrorMessage(err)).toBe('Request failed with status code 400');
  });

  it('returns custom fallback for non-Error values instead of default', () => {
    expect(getApiErrorMessage(null, 'Try again later')).toBe('Try again later');
    expect(getApiErrorMessage(undefined, 'Oops')).toBe('Oops');
    expect(getApiErrorMessage(42, 'Unexpected')).toBe('Unexpected');
  });

  it('returns Error.message regardless of custom fallback for Error instances', () => {
    // The fallback is only used when the value is not an Error instance.
    const err = new TypeError('type mismatch');
    expect(getApiErrorMessage(err, 'Ignored fallback')).toBe('type mismatch');
  });

  it('truncates extremely long server error messages to 200 characters', () => {
    const longMessage = 'x'.repeat(500);
    const err = makeAxiosError({ message: longMessage });
    const result = getApiErrorMessage(err);
    expect(result).toHaveLength(200);
    expect(result).toBe('x'.repeat(200));
  });

  it('truncates extremely long Error.message to 200 characters', () => {
    const longMessage = 'y'.repeat(300);
    const err = new Error(longMessage);
    const result = getApiErrorMessage(err);
    expect(result).toHaveLength(200);
    expect(result).toBe('y'.repeat(200));
  });

  it('does not truncate messages at or under 200 characters', () => {
    const exactMessage = 'z'.repeat(200);
    const err = makeAxiosError({ message: exactMessage });
    expect(getApiErrorMessage(err)).toHaveLength(200);

    const shortMessage = 'Short error';
    const err2 = makeAxiosError({ message: shortMessage });
    expect(getApiErrorMessage(err2)).toBe('Short error');
  });
});

// ---------------------------------------------------------------------------
// isSafeUrl() — URL protocol safety check
// ---------------------------------------------------------------------------

describe('isSafeUrl', () => {
  it('allows http URLs', () => {
    expect(isSafeUrl('http://example.com')).toBe(true);
  });

  it('allows https URLs', () => {
    expect(isSafeUrl('https://example.com')).toBe(true);
  });

  it('allows mailto URLs', () => {
    expect(isSafeUrl('mailto:user@example.com')).toBe(true);
  });

  it('is case-insensitive for protocols', () => {
    expect(isSafeUrl('HTTPS://example.com')).toBe(true);
    expect(isSafeUrl('HTTP://example.com')).toBe(true);
    expect(isSafeUrl('MAILTO:user@example.com')).toBe(true);
  });

  it('rejects javascript: URLs', () => {
    expect(isSafeUrl('javascript:alert(1)')).toBe(false);
  });

  it('rejects data: URLs', () => {
    expect(isSafeUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
  });

  it('rejects vbscript: URLs', () => {
    expect(isSafeUrl('vbscript:MsgBox("XSS")')).toBe(false);
  });

  it('rejects ftp: URLs', () => {
    expect(isSafeUrl('ftp://example.com')).toBe(false);
  });

  it('rejects empty strings', () => {
    expect(isSafeUrl('')).toBe(false);
  });

  it('rejects relative paths', () => {
    expect(isSafeUrl('/path/to/page')).toBe(false);
  });

  it('rejects protocol-relative URLs', () => {
    expect(isSafeUrl('//example.com')).toBe(false);
  });
});
