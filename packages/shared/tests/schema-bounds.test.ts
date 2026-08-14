/**
 * The wire schemas' BOUNDS, FORMATS, PAIRED FIELDS and MESSAGES.
 *
 * Every case in this file was chosen by the mutation oracle rather than by
 * reading the code and imagining what might break: `test:mutation` reported 400
 * surviving mutants in `packages/shared/src`, and each `describe` below answers
 * one class of them. That provenance matters, because it is what distinguishes
 * these assertions from the ones the suite already had — `schemas.test.ts`
 * proves the schemas ACCEPT what they should, and almost every survivor here is
 * a schema quietly accepting something it should refuse.
 *
 * The four classes, and the defect each one would let ship:
 *
 *  1. AN UNANCHORED FORMAT. `/^[a-f0-9]{64}$/` with either anchor removed still
 *     matches every valid hash, so no existing test noticed — while
 *     `"<64 hex>; drop"` becomes an acceptable `searchHash`. Anchors, length and
 *     character class are asserted per format, from BOTH ends.
 *  2. A BOUND THAT MOVED. `.max(100)` reads identically to `.min(100)` from any
 *     test that only ever sends a 40-character value. Each bound is probed AT
 *     the limit (must pass) and ONE PAST it (must fail) — the pair is what pins
 *     the number, since either half alone is satisfied by a mutant.
 *  3. A PAIRED-FIELD REFINE THAT ALWAYS RETURNS TRUE. The ciphertext trios exist
 *     so an update can never store a name with someone else's IV; nothing
 *     asserted the refine, so replacing its body with `true` changed no test.
 *  4. A CUSTOM MESSAGE REPLACED BY ZOD'S DEFAULT. These are what an operator and
 *     an end user actually read when a request is refused, and the fields that
 *     carry one (icon, colour, TOTP code, expiry) carry it because the default
 *     says nothing useful.
 *
 * Two survivor classes are deliberately NOT here, because they are not missing
 * assertions: see the `EQUIV-MUTANT` entries in `.testfortress/suppressions.json`
 * for `emailSchema`'s `.trim()` and its TLD refine, both of which sit downstream
 * of a `z.email()` that already rejects every input they would.
 */
import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  changePasswordSchema,
  emailSchema,
  loginSchema,
  login2faSchema,
  registerSchema,
  resetPasswordSchema,
} from '../src/schemas/auth.js';
import {
  createFolderSchema,
  updateFolderSchema,
  reorderFolderSchema,
  deleteFolderQuerySchema,
} from '../src/schemas/folder.js';
import {
  checkBreachSchema,
  checkBreachBatchSchema,
  disable2faSchema,
  importSchema,
  verify2faSchema,
} from '../src/schemas/user.js';
import {
  bulkDeleteSchema,
  createVaultItemSchema,
  updateVaultItemSchema,
} from '../src/schemas/vault.js';
import {
  ENCRYPTION_VERSION,
  HIBP_BATCH_MAX_PREFIXES,
  MAX_BULK_OPERATIONS,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_IMPORT_ITEMS,
  MAX_TAGS_PER_ITEM,
  MAX_TAG_LENGTH,
} from '../src/constants/index.js';

const hex = (n: number, char = 'a') => char.repeat(n);
const HASH = hex(64);
const OID = hex(24, '1');
const chars = (n: number) => 'x'.repeat(n);

/** A minimal payload each schema accepts, so a case changes exactly one thing. */
const validRegister = {
  email: 'user@example.com',
  authHash: chars(40),
  encryptedVaultKey: chars(80),
  vaultKeyIv: chars(16),
  vaultKeyTag: chars(24),
  kdfIterations: 600_000,
  kdfAlgorithm: 'PBKDF2-SHA256',
};
const validFolder = { encryptedName: chars(20), nameIv: chars(16), nameTag: chars(24) };
const validItem = {
  itemType: 'login',
  encryptedData: chars(50),
  dataIv: chars(16),
  dataTag: chars(24),
  ...validFolder,
};

/** `safeParse`, reported as the issue list a caller would actually see. */
const issues = (schema: z.ZodType, value: unknown) => {
  const result = schema.safeParse(value);
  return result.success
    ? []
    : result.error.issues.map((i) => ({ path: i.path.join('.'), m: i.message }));
};
const accepts = (schema: z.ZodType, value: unknown) => schema.safeParse(value).success;

describe('formats are anchored at both ends, and to their character class', () => {
  /**
   * Every case is a string that a HALF-anchored or class-widened pattern would
   * accept. The `valid` value proves the case is about the pattern rather than
   * about some other field, which is the half a mutant satisfies for free.
   */
  const FORMATS: {
    name: string;
    parse: (value: string) => boolean;
    valid: string;
    rejected: [string, string][];
  }[] = [
    {
      name: 'createFolderSchema.searchHash',
      parse: (searchHash) => accepts(createFolderSchema, { ...validFolder, searchHash }),
      valid: HASH,
      rejected: [
        [`${HASH}beef`, 'a suffix (the `$` anchor)'],
        [`beef${HASH}`, 'a prefix (the `^` anchor)'],
        [hex(63), 'one character short'],
        [HASH.toUpperCase(), 'upper-case hex, which the server never writes'],
        [`${hex(63)}Z`, 'a character outside the class'],
      ],
    },
    {
      name: 'updateFolderSchema.searchHash',
      parse: (searchHash) => accepts(updateFolderSchema, { searchHash }),
      valid: HASH,
      rejected: [
        [`${HASH}beef`, 'a suffix'],
        [`beef${HASH}`, 'a prefix'],
        [hex(65), 'one character too many'],
        [HASH.toUpperCase(), 'upper-case hex'],
      ],
    },
    {
      name: 'createVaultItemSchema.searchHash',
      parse: (searchHash) => accepts(createVaultItemSchema, { ...validItem, searchHash }),
      valid: HASH,
      rejected: [
        [`${HASH}0`, 'a suffix'],
        [`0${HASH}`, 'a prefix'],
        [HASH.toUpperCase(), 'upper-case hex'],
      ],
    },
    {
      name: 'createFolderSchema.icon',
      parse: (icon) => accepts(createFolderSchema, { ...validFolder, icon }),
      valid: 'folder-icon_2',
      rejected: [
        ['folder icon', 'an interior space'],
        ['../etc/passwd', 'path separators'],
        ['icon\n', 'a trailing newline (the `$` anchor)'],
        ['<script>', 'markup'],
      ],
    },
    {
      name: 'updateFolderSchema.icon',
      parse: (icon) => accepts(updateFolderSchema, { icon }),
      valid: 'folder-icon_2',
      rejected: [
        ['folder icon', 'an interior space'],
        ['icon\n', 'a trailing newline'],
        ['<script>', 'markup'],
      ],
    },
    {
      name: 'createFolderSchema.color',
      parse: (color) => accepts(createFolderSchema, { ...validFolder, color }),
      valid: '#ff00AA',
      rejected: [
        ['#ff00AA extra', 'a suffix'],
        ['x#ff00AA', 'a prefix'],
        ['#ff0', 'the three-digit form this schema does not accept'],
        ['#ff00AAA', 'seven digits'],
        ['ff00AA', 'no leading #'],
        ['#gg00AA', 'a non-hex digit'],
      ],
    },
    {
      name: 'updateFolderSchema.color',
      parse: (color) => accepts(updateFolderSchema, { color }),
      valid: '#ff00AA',
      rejected: [
        ['#ff00AA extra', 'a suffix'],
        ['#ff0', 'the three-digit form'],
        ['#gg00AA', 'a non-hex digit'],
      ],
    },
    {
      name: 'verify2faSchema.code',
      parse: (code) => accepts(verify2faSchema, { code }),
      valid: '123456',
      rejected: [
        ['12345a', 'a letter where the authenticator only ever sends digits'],
        ['12 456', 'an interior space'],
        ['１２３４５６', 'full-width digits, which `\\d` must not match'],
      ],
    },
    {
      name: 'disable2faSchema.code',
      parse: (code) => accepts(disable2faSchema, { code, password: 'pw' }),
      valid: 'abc123XYZ',
      rejected: [
        ['abc-123', 'a hyphen'],
        ['abc 123', 'an interior space'],
        ['abc123!', 'punctuation (the `$` anchor)'],
        ['!abc123', 'a leading symbol (the `^` anchor)'],
      ],
    },
    {
      name: 'checkBreachSchema.hashPrefix',
      parse: (hashPrefix) => accepts(checkBreachSchema, { hashPrefix }),
      valid: 'A1B2C',
      rejected: [
        ['A1B2', 'four characters — HIBP takes exactly five'],
        ['A1B2C3', 'six characters'],
        ['A1B2C ', 'a trailing space'],
        [' A1B2C', 'a leading space'],
        ['A1B2Z', 'a non-hex character'],
      ],
    },
  ];

  it.each(FORMATS)('$name', ({ parse, valid, rejected }) => {
    expect(parse(valid), `the valid value must still be accepted`).toBe(true);
    for (const [value, why] of rejected) {
      expect(parse(value), `must reject ${JSON.stringify(value)}: ${why}`).toBe(false);
    }
  });

  it('rejects a batch prefix that is out of format, wherever it sits in the array', () => {
    // The array's own element schema, which a per-element mutant would silently
    // widen: the FIRST element is the one a naive test checks.
    expect(accepts(checkBreachBatchSchema, { hashPrefixes: ['A1B2C', 'D3E4F'] })).toBe(true);
    expect(accepts(checkBreachBatchSchema, { hashPrefixes: ['A1B2C', 'D3E4'] })).toBe(false);
    expect(accepts(checkBreachBatchSchema, { hashPrefixes: ['A1B2C', 'D3E4FA'] })).toBe(false);
    expect(accepts(checkBreachBatchSchema, { hashPrefixes: ['A1B2C', 'D3E4Z'] })).toBe(false);
  });
});

describe('bounds hold at the limit and refuse one past it', () => {
  /**
   * Both halves are required. "101 characters is rejected" alone is satisfied by
   * a mutant that rejects everything; "100 characters is accepted" alone is
   * satisfied by one that accepts everything. The pair pins the number.
   */
  const BOUNDS: { name: string; at: () => boolean; past: () => boolean }[] = [
    {
      name: 'registerSchema.authHash max 100',
      at: () => accepts(registerSchema, { ...validRegister, authHash: chars(100) }),
      past: () => accepts(registerSchema, { ...validRegister, authHash: chars(101) }),
    },
    {
      name: 'registerSchema.encryptedVaultKey max 200',
      at: () => accepts(registerSchema, { ...validRegister, encryptedVaultKey: chars(200) }),
      past: () => accepts(registerSchema, { ...validRegister, encryptedVaultKey: chars(201) }),
    },
    {
      name: 'registerSchema.vaultKeyIv max 24',
      at: () => accepts(registerSchema, { ...validRegister, vaultKeyIv: chars(24) }),
      past: () => accepts(registerSchema, { ...validRegister, vaultKeyIv: chars(25) }),
    },
    {
      name: 'registerSchema.vaultKeyTag max 32',
      at: () => accepts(registerSchema, { ...validRegister, vaultKeyTag: chars(32) }),
      past: () => accepts(registerSchema, { ...validRegister, vaultKeyTag: chars(33) }),
    },
    {
      name: 'registerSchema.kdfIterations min 500k',
      at: () => accepts(registerSchema, { ...validRegister, kdfIterations: 500_000 }),
      past: () => accepts(registerSchema, { ...validRegister, kdfIterations: 499_999 }),
    },
    {
      name: 'registerSchema.kdfIterations max 10M',
      at: () => accepts(registerSchema, { ...validRegister, kdfIterations: 10_000_000 }),
      past: () => accepts(registerSchema, { ...validRegister, kdfIterations: 10_000_001 }),
    },
    {
      name: 'registerSchema.encryptionVersion max ENCRYPTION_VERSION',
      at: () =>
        accepts(registerSchema, { ...validRegister, encryptionVersion: ENCRYPTION_VERSION }),
      past: () =>
        accepts(registerSchema, { ...validRegister, encryptionVersion: ENCRYPTION_VERSION + 1 }),
    },
    {
      name: 'loginSchema.deviceInfo.userAgent max 512',
      at: () =>
        accepts(loginSchema, {
          email: 'u@e.com',
          authHash: 'a',
          deviceInfo: { userAgent: chars(512) },
        }),
      past: () =>
        accepts(loginSchema, {
          email: 'u@e.com',
          authHash: 'a',
          deviceInfo: { userAgent: chars(513) },
        }),
    },
    {
      name: 'loginSchema.deviceInfo.fingerprint max 128',
      at: () =>
        accepts(loginSchema, {
          email: 'u@e.com',
          authHash: 'a',
          deviceInfo: { fingerprint: chars(128) },
        }),
      past: () =>
        accepts(loginSchema, {
          email: 'u@e.com',
          authHash: 'a',
          deviceInfo: { fingerprint: chars(129) },
        }),
    },
    {
      name: 'login2faSchema.tempToken max 2000',
      at: () => accepts(login2faSchema, { tempToken: chars(2000), code: '123456' }),
      past: () => accepts(login2faSchema, { tempToken: chars(2001), code: '123456' }),
    },
    {
      name: 'login2faSchema.code max 16',
      at: () => accepts(login2faSchema, { tempToken: 't', code: chars(16) }),
      past: () => accepts(login2faSchema, { tempToken: 't', code: chars(17) }),
    },
    {
      name: 'login2faSchema.code min 6',
      at: () => accepts(login2faSchema, { tempToken: 't', code: chars(6) }),
      past: () => accepts(login2faSchema, { tempToken: 't', code: chars(5) }),
    },
    {
      name: 'resetPasswordSchema.newAuthHash max 100',
      at: () =>
        accepts(resetPasswordSchema, {
          token: 't',
          email: 'u@e.com',
          newAuthHash: chars(100),
          newEncryptedVaultKey: 'k',
          newVaultKeyIv: 'i',
          newVaultKeyTag: 'g',
        }),
      past: () =>
        accepts(resetPasswordSchema, {
          token: 't',
          email: 'u@e.com',
          newAuthHash: chars(101),
          newEncryptedVaultKey: 'k',
          newVaultKeyIv: 'i',
          newVaultKeyTag: 'g',
        }),
    },
    {
      name: 'changePasswordSchema.newEncryptedVaultKey max 200',
      at: () =>
        accepts(changePasswordSchema, {
          currentAuthHash: 'c',
          newAuthHash: 'n',
          newEncryptedVaultKey: chars(200),
          newVaultKeyIv: 'i',
          newVaultKeyTag: 'g',
        }),
      past: () =>
        accepts(changePasswordSchema, {
          currentAuthHash: 'c',
          newAuthHash: 'n',
          newEncryptedVaultKey: chars(201),
          newVaultKeyIv: 'i',
          newVaultKeyTag: 'g',
        }),
    },
    {
      name: 'updateFolderSchema.icon max 50',
      at: () => accepts(updateFolderSchema, { icon: chars(50) }),
      past: () => accepts(updateFolderSchema, { icon: chars(51) }),
    },
    {
      name: 'createFolderSchema.icon max 50',
      at: () => accepts(createFolderSchema, { ...validFolder, icon: chars(50) }),
      past: () => accepts(createFolderSchema, { ...validFolder, icon: chars(51) }),
    },
    {
      name: 'createVaultItemSchema.encryptedName max MAX_ENCRYPTED_NAME_LENGTH',
      at: () =>
        accepts(createVaultItemSchema, {
          ...validItem,
          encryptedName: chars(MAX_ENCRYPTED_NAME_LENGTH),
        }),
      past: () =>
        accepts(createVaultItemSchema, {
          ...validItem,
          encryptedName: chars(MAX_ENCRYPTED_NAME_LENGTH + 1),
        }),
    },
    {
      name: 'createVaultItemSchema.dataIv max 24',
      at: () => accepts(createVaultItemSchema, { ...validItem, dataIv: chars(24) }),
      past: () => accepts(createVaultItemSchema, { ...validItem, dataIv: chars(25) }),
    },
    {
      name: 'createVaultItemSchema.dataTag max 32',
      at: () => accepts(createVaultItemSchema, { ...validItem, dataTag: chars(32) }),
      past: () => accepts(createVaultItemSchema, { ...validItem, dataTag: chars(33) }),
    },
    {
      name: 'createVaultItemSchema.tags — element length',
      at: () => accepts(createVaultItemSchema, { ...validItem, tags: [chars(MAX_TAG_LENGTH)] }),
      past: () =>
        accepts(createVaultItemSchema, { ...validItem, tags: [chars(MAX_TAG_LENGTH + 1)] }),
    },
    {
      name: 'createVaultItemSchema.tags — array length',
      at: () =>
        accepts(createVaultItemSchema, {
          ...validItem,
          tags: Array.from({ length: MAX_TAGS_PER_ITEM }, (_, i) => `t${String(i)}`),
        }),
      past: () =>
        accepts(createVaultItemSchema, {
          ...validItem,
          tags: Array.from({ length: MAX_TAGS_PER_ITEM + 1 }, (_, i) => `t${String(i)}`),
        }),
    },
    {
      name: 'bulkDeleteSchema.ids max MAX_BULK_OPERATIONS',
      at: () => accepts(bulkDeleteSchema, { ids: Array<string>(MAX_BULK_OPERATIONS).fill(OID) }),
      past: () =>
        accepts(bulkDeleteSchema, { ids: Array<string>(MAX_BULK_OPERATIONS + 1).fill(OID) }),
    },
    {
      name: 'bulkDeleteSchema.ids min 1',
      at: () => accepts(bulkDeleteSchema, { ids: [OID] }),
      past: () => accepts(bulkDeleteSchema, { ids: [] }),
    },
    {
      name: 'checkBreachBatchSchema.hashPrefixes max HIBP_BATCH_MAX_PREFIXES',
      at: () =>
        accepts(checkBreachBatchSchema, {
          hashPrefixes: Array<string>(HIBP_BATCH_MAX_PREFIXES).fill('A1B2C'),
        }),
      past: () =>
        accepts(checkBreachBatchSchema, {
          hashPrefixes: Array<string>(HIBP_BATCH_MAX_PREFIXES + 1).fill('A1B2C'),
        }),
    },
    {
      name: 'checkBreachBatchSchema.hashPrefixes min 1',
      at: () => accepts(checkBreachBatchSchema, { hashPrefixes: ['A1B2C'] }),
      past: () => accepts(checkBreachBatchSchema, { hashPrefixes: [] }),
    },
  ];

  it.each(BOUNDS)('$name', ({ at, past }) => {
    expect(at(), 'the value AT the bound must be accepted').toBe(true);
    expect(past(), 'the value one PAST the bound must be refused').toBe(false);
  });
});

describe('the ciphertext trios are all-or-nothing', () => {
  /**
   * The refine that survived as `true`. A partial update — a new `encryptedName`
   * with the OLD `nameIv` — is how a vault item becomes permanently
   * undecryptable, and the trio rule is the only thing standing in front of it.
   */
  const NAME_TRIO = { encryptedName: chars(20), nameIv: chars(16), nameTag: chars(24) };
  const DATA_TRIO = { encryptedData: chars(50), dataIv: chars(16), dataTag: chars(24) };

  it('accepts a complete trio and an absent one, on both schemas', () => {
    expect(accepts(updateFolderSchema, NAME_TRIO)).toBe(true);
    expect(accepts(updateFolderSchema, { sortOrder: 3 })).toBe(true);
    expect(accepts(updateVaultItemSchema, { ...NAME_TRIO, ...DATA_TRIO })).toBe(true);
    expect(accepts(updateVaultItemSchema, { favorite: true })).toBe(true);
  });

  it.each([
    ['encryptedName alone', { encryptedName: chars(20) }],
    ['nameIv alone', { nameIv: chars(16) }],
    ['nameTag alone', { nameTag: chars(24) }],
    ['name without its tag', { encryptedName: chars(20), nameIv: chars(16) }],
    ['iv and tag without the name', { nameIv: chars(16), nameTag: chars(24) }],
  ])('refuses a folder update carrying %s', (_name, patch) => {
    const reported = issues(updateFolderSchema, patch);
    expect(reported).toHaveLength(1);
    expect(reported[0]?.m).toBe(
      'encryptedName, nameIv, and nameTag must all be provided together or all omitted',
    );
  });

  it.each([
    ['encryptedData alone', { encryptedData: chars(50) }],
    ['data without its tag', { encryptedData: chars(50), dataIv: chars(16) }],
    ['dataTag alone', { dataTag: chars(24) }],
  ])('refuses an item update carrying %s', (_name, patch) => {
    const reported = issues(updateVaultItemSchema, patch);
    expect(reported.map((i) => i.m)).toContain(
      'encryptedData, dataIv, and dataTag must all be provided together or all omitted',
    );
  });

  it.each([
    ['encryptedName alone', { encryptedName: chars(20) }],
    ['name without its iv', { encryptedName: chars(20), nameTag: chars(24) }],
  ])('refuses an item update carrying %s', (_name, patch) => {
    const reported = issues(updateVaultItemSchema, patch);
    expect(reported.map((i) => i.m)).toContain(
      'encryptedName, nameIv, and nameTag must all be provided together or all omitted',
    );
  });

  it('counts the import operations across BOTH lists, at the cap and one past it', () => {
    // The refine reads `inserts.length + updates.length`, and the survivor was
    // `<=` becoming `<`: an off-by-one nobody would ever notice from a payload
    // of three items.
    const insert = {
      itemType: 'login' as const,
      encryptedData: chars(10),
      dataIv: chars(12),
      dataTag: chars(16),
      encryptedName: chars(10),
      nameIv: chars(12),
      nameTag: chars(16),
      searchHash: HASH,
    };
    const build = (n: number) => ({
      format: 'json' as const,
      conflictStrategy: 'skip' as const,
      operations: { inserts: Array.from({ length: n }, () => insert), updates: [] },
    });
    expect(accepts(importSchema, build(MAX_IMPORT_ITEMS))).toBe(true);
    expect(accepts(importSchema, build(MAX_IMPORT_ITEMS + 1))).toBe(false);
    expect(accepts(importSchema, build(0))).toBe(false);
    const reported = issues(importSchema, build(MAX_IMPORT_ITEMS + 1));
    expect(reported.map((i) => i.path)).toContain('operations');
  });
});

describe('a refused request says which rule refused it', () => {
  /**
   * Zod substitutes its own generic text when a custom message is removed, so
   * every case here is a survivor whose only effect was to replace a sentence a
   * person reads with "Invalid string". The message is the contract for anything
   * the API cannot fix on the user's behalf.
   */
  it.each([
    [
      'folder icon',
      () => issues(createFolderSchema, { ...validFolder, icon: 'not an icon' }),
      'Icon must contain only alphanumeric characters, hyphens, and underscores',
    ],
    [
      'folder icon, on update',
      () => issues(updateFolderSchema, { icon: 'not an icon' }),
      'Icon must contain only alphanumeric characters, hyphens, and underscores',
    ],
    [
      'folder colour',
      () => issues(createFolderSchema, { ...validFolder, color: 'red' }),
      'Color must be a valid hex color code (e.g. #ff0000)',
    ],
    [
      'folder colour, on update',
      () => issues(updateFolderSchema, { color: 'red' }),
      'Color must be a valid hex color code (e.g. #ff0000)',
    ],
    [
      'TOTP code',
      () => issues(verify2faSchema, { code: 'abcdef' }),
      'TOTP code must be exactly 6 digits',
    ],
    [
      '2FA disable code',
      () => issues(disable2faSchema, { code: 'abc-def', password: 'pw' }),
      'Code must contain only alphanumeric characters',
    ],
    [
      '2FA login code',
      () => issues(login2faSchema, { tempToken: 't', code: 'abc-def' }),
      'Code must contain only alphanumeric characters',
    ],
  ])('names the rule for %s', (_case, run, message) => {
    const reported = run();
    expect(reported.map((i) => i.m)).toContain(message);
  });
});

describe('defaults are applied, because an absent field is not an empty one', () => {
  it('defaults a folder sortOrder to 0 and a delete action to move', () => {
    const folder = createFolderSchema.parse(validFolder);
    expect(folder.sortOrder).toBe(0);
    expect(deleteFolderQuerySchema.parse({}).action).toBe('move');
    // …and still refuses a value outside the enum, which a `.default()` moved
    // onto the wrong branch would silently accept.
    expect(accepts(deleteFolderQuerySchema, { action: 'shred' })).toBe(false);
    expect(accepts(reorderFolderSchema, {})).toBe(false);
  });

  it('defaults an item to no tags, not favourite, and rejects a non-boolean favourite', () => {
    const item = createVaultItemSchema.parse(validItem);
    expect(item.tags).toEqual([]);
    expect(item.favorite).toBe(false);
    expect(accepts(createVaultItemSchema, { ...validItem, favorite: 'true' })).toBe(false);
  });

  it('defaults deviceInfo strings to empty and rememberMe to false', () => {
    const login = loginSchema.parse({ email: 'u@e.com', authHash: 'a', deviceInfo: {} });
    expect(login.rememberMe).toBe(false);
    expect(login.deviceInfo).toEqual({ userAgent: '', fingerprint: '' });
    // An absent `deviceInfo` stays absent rather than becoming an empty object:
    // the server distinguishes "no device information" from "blank device
    // information" when it records a session.
    expect(loginSchema.parse({ email: 'u@e.com', authHash: 'a' }).deviceInfo).toBeUndefined();
  });

  it('lower-cases an email but keeps the address itself', () => {
    // `.toLowerCase()` is the one transform in `emailSchema` that changes a value
    // that reaches it — the PBKDF2 salt is the email, so a case difference is a
    // permanently different vault key.
    expect(emailSchema.parse('User@Example.COM')).toBe('user@example.com');
  });
});
