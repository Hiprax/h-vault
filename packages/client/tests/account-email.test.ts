/**
 * The email field every account form validates — sign-in, registration, the
 * forgotten-password request and the reset — held to ONE definition.
 *
 * The email is not only a login name here: it is the salt of the master-password
 * key derivation, so an address the server would accept but the user did not mean
 * is a vault nobody can open again. The four forms therefore have to agree on
 * exactly what they refuse, and each refusal names what is wrong in words the
 * form shows beside the field.
 */
import { describe, expect, it } from 'vitest';
import { accountEmailSchema } from '../src/lib/accountEmail';

const messageFor = (value: unknown): string | undefined => {
  const result = accountEmailSchema.safeParse(value);
  return result.success ? undefined : result.error.issues[0]?.message;
};

describe('accountEmailSchema', () => {
  it('accepts an ordinary address and returns it unchanged', () => {
    expect(accountEmailSchema.parse('user@example.com')).toBe('user@example.com');
    expect(accountEmailSchema.parse('first.last@mail.co.uk')).toBe('first.last@mail.co.uk');
  });

  it('says the field is required when it is empty, and only then', () => {
    expect(messageFor('')).toBe('Email is required');
    // One character is not "empty": it is refused as malformed instead.
    expect(messageFor('a')).toBe('Enter a valid email address');
  });

  it('refuses a string that is not an address', () => {
    expect(messageFor('not an address')).toBe('Enter a valid email address');
    expect(messageFor('user@')).toBe('Enter a valid email address');
  });

  it('refuses a domain with no dot — the typo that locks a zero-knowledge account', () => {
    expect(messageFor('user@gmailcom')).toBe('Enter a valid email address');
    expect(messageFor('user@example.')).toBe('Enter a valid email address');
  });

  it('refuses a value that is not a string at all', () => {
    expect(accountEmailSchema.safeParse(undefined).success).toBe(false);
    expect(accountEmailSchema.safeParse(42).success).toBe(false);
  });
});
