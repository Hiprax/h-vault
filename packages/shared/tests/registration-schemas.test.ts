/**
 * The registration-control wire shapes (F-24): the invitation token, the mint
 * request, and the `registration` block of `GET /config`.
 *
 * Bounds are pinned by PARSING at the bound and one past it, never by comparing
 * constants; every refusal is checked to be a refusal of THIS field.
 */
import { describe, it, expect } from 'vitest';
import {
  createInvitationSchema,
  invitationTokenSchema,
  registerSchema,
} from '../src/schemas/auth.js';
import { publicConfigDataSchema, registrationConfigResponseSchema } from '../src/schemas/config.js';
import { MAX_INVITATION_TOKEN_LENGTH, REGISTRATION_MODES } from '../src/constants/index.js';

/** The distinct issue paths of a failed parse, or `null` when it succeeded. */
function failedPaths(result: {
  success: boolean;
  error?: { issues: { path: PropertyKey[]; message: string }[] };
}): string[] | null {
  if (result.success) return null;
  // Distinct paths: the e-mail schema reports a bad address under two checks.
  return [...new Set((result.error?.issues ?? []).map((issue) => issue.path.join('.')))];
}

describe('invitationTokenSchema', () => {
  it('accepts every base64url character, from one character up to the bound', () => {
    for (const token of [
      'a',
      'Z',
      '0',
      '-',
      '_',
      'AZaz09-_',
      'x'.repeat(MAX_INVITATION_TOKEN_LENGTH),
    ]) {
      expect(invitationTokenSchema.safeParse(token).success, token).toBe(true);
    }
  });

  it('refuses the empty token and one past the bound', () => {
    expect(invitationTokenSchema.safeParse('').success).toBe(false);
    expect(
      invitationTokenSchema.safeParse('x'.repeat(MAX_INVITATION_TOKEN_LENGTH + 1)).success,
    ).toBe(false);
  });

  it('refuses any character outside base64url, wherever it sits, with its own message', () => {
    // Standard base64's `+`, `/` and `=`, whitespace, and a character at the start
    // or the end of an otherwise valid token: the pattern is anchored both ways.
    for (const token of ['ab+c', 'ab/c', 'abc=', 'a c', '+abc', 'abc+', 'abc\n', '\nabc', 'ä']) {
      const result = invitationTokenSchema.safeParse(token);
      expect(result.success, JSON.stringify(token)).toBe(false);
      expect(result.error?.issues.map((issue) => issue.message)).toEqual(['Invalid invitation']);
    }
  });

  it('is optional on registration, and refused there when malformed', () => {
    const base = {
      email: 'test@example.com',
      authHash: 'somehash',
      encryptedVaultKey: 'encryptedkey',
      vaultKeyIv: 'iv-value',
      vaultKeyTag: 'tag-value',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256' as const,
    };
    expect(registerSchema.safeParse(base).success).toBe(true);
    const withToken = registerSchema.safeParse({ ...base, invitationToken: 'AZaz09-_' });
    expect(withToken.success && withToken.data.invitationToken).toBe('AZaz09-_');
    expect(failedPaths(registerSchema.safeParse({ ...base, invitationToken: 'a/b' }))).toEqual([
      'invitationToken',
    ]);
  });
});

describe('createInvitationSchema', () => {
  const valid = { authHash: 'h', email: 'friend@example.com' };

  it('accepts a proof and an address, and drops anything else', () => {
    const result = createInvitationSchema.safeParse({ ...valid, mode: 'open' });
    expect(result.success && result.data).toEqual(valid);
  });

  it('bounds the master-password proof at 1 to 100 characters', () => {
    expect(createInvitationSchema.safeParse({ ...valid, authHash: 'h'.repeat(100) }).success).toBe(
      true,
    );
    expect(failedPaths(createInvitationSchema.safeParse({ ...valid, authHash: '' }))).toEqual([
      'authHash',
    ]);
    expect(
      failedPaths(createInvitationSchema.safeParse({ ...valid, authHash: 'h'.repeat(101) })),
    ).toEqual(['authHash']);
  });

  it('requires both fields, and a real address', () => {
    expect(failedPaths(createInvitationSchema.safeParse({ email: valid.email }))).toEqual([
      'authHash',
    ]);
    expect(failedPaths(createInvitationSchema.safeParse({ authHash: 'h' }))).toEqual(['email']);
    expect(
      failedPaths(createInvitationSchema.safeParse({ ...valid, email: 'not-an-address' })),
    ).toEqual(['email']);
  });
});

describe('the registration block of GET /config', () => {
  const fileEncryption = { maxSizeMB: 100 };

  it('accepts every registration mode, and an older server that sends no block', () => {
    for (const mode of REGISTRATION_MODES) {
      const result = publicConfigDataSchema.safeParse({ fileEncryption, registration: { mode } });
      expect(result.success && result.data.registration).toEqual({ mode });
    }
    const older = publicConfigDataSchema.safeParse({ fileEncryption });
    expect(older.success && older.data.registration).toBeUndefined();
  });

  it('refuses a mode it does not know, and a block without one', () => {
    expect(
      failedPaths(
        publicConfigDataSchema.safeParse({ fileEncryption, registration: { mode: 'sometimes' } }),
      ),
    ).toEqual(['registration.mode']);
    expect(
      failedPaths(publicConfigDataSchema.safeParse({ fileEncryption, registration: {} })),
    ).toEqual(['registration.mode']);
  });

  it('reads the registration block alone, so another block cannot cost the page its mode', () => {
    // The register page's parse: a missing or malformed `fileEncryption` or
    // `documents` block must not fail it, and is not carried into the result.
    const result = registrationConfigResponseSchema.safeParse({
      success: true,
      data: { registration: { mode: 'invite' }, documents: { enabled: 'garbage' } },
    });
    expect(result.success && result.data.data).toEqual({ registration: { mode: 'invite' } });

    const unknown = registrationConfigResponseSchema.safeParse({
      success: true,
      data: { registration: { mode: 'sometimes' } },
    });
    expect(failedPaths(unknown)).toEqual(['data.registration.mode']);
  });
});
