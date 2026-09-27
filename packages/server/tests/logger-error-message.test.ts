/**
 * `errorMessage`: what a log line records about a caught error.
 *
 * Since `@hiprax/logger` 1.2, an `Error` placed in log metadata renders its
 * name, message, stack, own fields and `cause` chain; before that it rendered as
 * `{}`. A driver error's own fields can carry request data (nodemailer's
 * `rejected` recipients, a MongoDB duplicate key's `keyValue`), so the call
 * sites record the MESSAGE, through this one helper, and never the object.
 * One helper also means the call sites carry no branch of their own.
 */
import { describe, expect, it } from 'vitest';
import { errorMessage } from '../src/utils/logger.js';

describe('errorMessage', () => {
  it("returns an Error's message, and none of its other fields", () => {
    const err = Object.assign(new Error('connection refused'), {
      code: 'ECONNREFUSED',
      rejected: ['someone@example.com'],
    });
    expect(errorMessage(err)).toBe('connection refused');
    expect(errorMessage(new TypeError('bad input'))).toBe('bad input');
  });

  it('returns a thrown string as it is', () => {
    expect(errorMessage('plain failure')).toBe('plain failure');
    expect(errorMessage('')).toBe('');
  });

  it('never turns anything else into text, so it cannot leak or throw doing so', () => {
    const hostile = {
      toString(): string {
        throw new Error('toString must not be called');
      },
    };
    for (const value of [null, undefined, 42, { message: 'looks like an error' }, hostile]) {
      expect(errorMessage(value)).toBe('Unknown error');
    }
  });
});
