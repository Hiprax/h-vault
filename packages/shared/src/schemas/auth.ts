import { z } from 'zod';
import { ENCRYPTION_VERSION } from '../constants/index.js';

export const emailSchema = z
  .email()
  .max(254)
  .toLowerCase()
  .trim()
  .refine(
    // Require a TLD-like dot in the domain. Zod's z.email() accepts `user@host`
    // (no dot) which is technically valid per RFC 5322 but is overwhelmingly the
    // result of a typo. For a zero-knowledge product where the email is the
    // PBKDF2 salt, a typo permanently locks the user out — so we add a "must
    // have a TLD" guard. Implementation: split on `@` (at most once), then
    // verify the host has at least one interior dot with non-empty labels on
    // either side. No regex backtracking risk.
    (v) => {
      const at = v.lastIndexOf('@');
      if (at === -1) return false;
      const host = v.slice(at + 1);
      if (host.length === 0 || host.startsWith('.') || host.endsWith('.')) return false;
      const labels = host.split('.');
      if (labels.length < 2) return false;
      return labels.every((label) => label.length > 0 && !/[\s@]/.test(label));
    },
    'Must be a valid email address',
  );

export const registerSchema = z.object({
  email: emailSchema,
  authHash: z.string().min(1).max(100),
  encryptedVaultKey: z.string().min(1).max(200),
  vaultKeyIv: z.string().min(1).max(24),
  vaultKeyTag: z.string().min(1).max(32),
  kdfIterations: z.number().int().min(500_000).max(10_000_000),
  kdfAlgorithm: z.literal('PBKDF2-SHA256'),
  encryptionVersion: z.number().int().min(1).max(ENCRYPTION_VERSION).default(ENCRYPTION_VERSION),
});

export const loginSchema = z.object({
  email: emailSchema,
  authHash: z.string().min(1).max(100),
  deviceInfo: z
    .object({
      userAgent: z.string().max(512).default(''),
      fingerprint: z.string().max(128).default(''),
    })
    .optional(),
});

export const login2faSchema = z.object({
  tempToken: z.string().min(1).max(2000),
  code: z
    .string()
    .min(6)
    .max(16)
    .refine((val) => /^[a-zA-Z0-9]+$/.test(val), {
      message: 'Code must contain only alphanumeric characters',
    }),
  deviceInfo: z
    .object({
      userAgent: z.string().max(512).default(''),
      fingerprint: z.string().max(128).default(''),
    })
    .optional(),
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1).max(2000),
  email: emailSchema,
  newAuthHash: z.string().min(1).max(100),
  newEncryptedVaultKey: z.string().min(1).max(200),
  newVaultKeyIv: z.string().min(1).max(24),
  newVaultKeyTag: z.string().min(1).max(32),
});

export const verifyEmailSchema = z.object({
  token: z.string().min(1).max(2000),
});

export const changePasswordSchema = z.object({
  currentAuthHash: z.string().min(1).max(100),
  newAuthHash: z.string().min(1).max(100),
  newEncryptedVaultKey: z.string().min(1).max(200),
  newVaultKeyIv: z.string().min(1).max(24),
  newVaultKeyTag: z.string().min(1).max(32),
});

export const unlockAccountSchema = z.object({
  token: z.string().min(1).max(2000),
});

export const verifyUnlockSchema = z.object({
  authHash: z.string().min(1).max(100),
});

export const resendVerificationSchema = z.object({
  email: emailSchema,
});
