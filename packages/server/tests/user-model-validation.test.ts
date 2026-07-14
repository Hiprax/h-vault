import { describe, it, expect } from 'vitest';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import mongoose from 'mongoose';

/**
 * Mongoose 9 deprecated `Document.prototype.validateSync()` (removed in v10) in
 * favor of the async `Document.prototype.validate()`, which rejects with a
 * `ValidationError` on failure and resolves `undefined` on success. This helper
 * adapts `validate()` back to the `ValidationError | undefined` shape these
 * tests assert against, so every existing assertion is preserved verbatim while
 * the suite no longer emits `validateSync` deprecation warnings. There are no
 * `pre('validate')` hooks on these models, so `validate()` fires exactly the
 * same synchronous (maxlength / cross-field) validators these tests exercise.
 */
async function getValidationError(doc: {
  validate: () => Promise<void>;
}): Promise<mongoose.Error.ValidationError | undefined> {
  try {
    await doc.validate();
    return undefined;
  } catch (e) {
    return e as mongoose.Error.ValidationError;
  }
}

const validUserData = {
  email: 'test@example.com',
  authHash: 'valid-auth-hash',
  encryptedVaultKey: 'valid-encrypted-vault-key',
  vaultKeyIv: 'valid-iv',
  vaultKeyTag: 'valid-tag',
  kdfIterations: 600_000,
  kdfAlgorithm: 'PBKDF2-SHA256',
  encryptionVersion: 1,
};

describe('User model maxlength validators', () => {
  it('should reject authHash exceeding 100 characters', async () => {
    const user = new User({ ...validUserData, authHash: 'a'.repeat(101) });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['authHash']).toBeDefined();
  });

  it('should accept authHash at exactly 100 characters', async () => {
    const user = new User({ ...validUserData, authHash: 'a'.repeat(100) });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should reject encryptedVaultKey exceeding 200 characters', async () => {
    const user = new User({ ...validUserData, encryptedVaultKey: 'a'.repeat(201) });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['encryptedVaultKey']).toBeDefined();
  });

  it('should accept encryptedVaultKey at exactly 200 characters', async () => {
    const user = new User({ ...validUserData, encryptedVaultKey: 'a'.repeat(200) });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should reject vaultKeyIv exceeding 24 characters', async () => {
    const user = new User({ ...validUserData, vaultKeyIv: 'a'.repeat(25) });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['vaultKeyIv']).toBeDefined();
  });

  it('should reject vaultKeyTag exceeding 32 characters', async () => {
    const user = new User({ ...validUserData, vaultKeyTag: 'a'.repeat(33) });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['vaultKeyTag']).toBeDefined();
  });

  it('should reject twoFactorSecret exceeding 500 characters', async () => {
    const user = new User({ ...validUserData, twoFactorSecret: 'a'.repeat(501) });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['twoFactorSecret']).toBeDefined();
  });
});

describe('Backup settings maxlength validators', () => {
  it('should reject encryptedBWK exceeding 500 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { encryptedBWK: 'a'.repeat(501) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.encryptedBWK']).toBeDefined();
  });

  it('should reject bwkIv exceeding 24 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkIv: 'a'.repeat(25) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkIv']).toBeDefined();
  });

  it('should reject bwkTag exceeding 32 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkTag: 'a'.repeat(33) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkTag']).toBeDefined();
  });

  it('should reject bwkSalt exceeding 64 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkSalt: 'a'.repeat(65) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkSalt']).toBeDefined();
  });

  it('should reject bwkEncryptedVaultKey exceeding 500 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkEncryptedVaultKey: 'a'.repeat(501) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkEncryptedVaultKey']).toBeDefined();
  });

  it('should reject bwkVaultKeyIv exceeding 24 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkVaultKeyIv: 'a'.repeat(25) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkVaultKeyIv']).toBeDefined();
  });

  it('should reject bwkVaultKeyTag exceeding 32 characters', async () => {
    const user = new User({
      ...validUserData,
      settings: { backup: { bwkVaultKeyTag: 'a'.repeat(33) } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.bwkVaultKeyTag']).toBeDefined();
  });

  it('should reject backupEmails array exceeding 10 entries', async () => {
    const emails = Array.from({ length: 11 }, (_, i) => `user${String(i)}@example.com`);
    const user = new User({
      ...validUserData,
      settings: { backup: { backupEmails: emails } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    expect(err!.errors['settings.backup.backupEmails']).toBeDefined();
  });

  it('should accept backupEmails array with exactly 10 entries', async () => {
    const emails = Array.from({ length: 10 }, (_, i) => `user${String(i)}@example.com`);
    const user = new User({
      ...validUserData,
      settings: { backup: { backupEmails: emails } },
    });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should reject individual backupEmail exceeding 254 characters', async () => {
    const longEmail = 'a'.repeat(255);
    const user = new User({
      ...validUserData,
      settings: { backup: { backupEmails: [longEmail] } },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
  });

  it('should accept valid backup settings within limits', async () => {
    const user = new User({
      ...validUserData,
      settings: {
        backup: {
          encryptedBWK: 'a'.repeat(500),
          bwkIv: 'a'.repeat(24),
          bwkTag: 'a'.repeat(32),
          bwkSalt: 'a'.repeat(64),
          bwkEncryptedVaultKey: 'a'.repeat(500),
          bwkVaultKeyIv: 'a'.repeat(24),
          bwkVaultKeyTag: 'a'.repeat(32),
        },
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// VaultItem encrypted field maxlength validators
// ---------------------------------------------------------------------------

const validVaultItemData = {
  userId: new mongoose.Types.ObjectId(),
  itemType: 'login' as const,
  encryptedData: 'valid-data',
  dataIv: 'valid-iv',
  dataTag: 'valid-tag',
  encryptedName: 'valid-name',
  nameIv: 'valid-iv',
  nameTag: 'valid-tag',
};

describe('VaultItem model maxlength validators', () => {
  it('should reject encryptedData exceeding 500000 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, encryptedData: 'a'.repeat(500_001) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['encryptedData']).toBeDefined();
  });

  it('should reject dataIv exceeding 24 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, dataIv: 'a'.repeat(25) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['dataIv']).toBeDefined();
  });

  it('should reject dataTag exceeding 32 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, dataTag: 'a'.repeat(33) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['dataTag']).toBeDefined();
  });

  it('should reject encryptedName exceeding 1000 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, encryptedName: 'a'.repeat(1001) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['encryptedName']).toBeDefined();
  });

  it('should reject nameIv exceeding 24 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, nameIv: 'a'.repeat(25) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['nameIv']).toBeDefined();
  });

  it('should reject nameTag exceeding 32 characters', async () => {
    const item = new VaultItem({ ...validVaultItemData, nameTag: 'a'.repeat(33) });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['nameTag']).toBeDefined();
  });

  it('should accept fields within limits', async () => {
    const item = new VaultItem(validVaultItemData);
    const err = await getValidationError(item);
    expect(err).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Folder encrypted field maxlength validators
// ---------------------------------------------------------------------------

const validFolderData = {
  userId: new mongoose.Types.ObjectId(),
  encryptedName: 'valid-name',
  nameIv: 'valid-iv',
  nameTag: 'valid-tag',
};

describe('Folder model maxlength validators', () => {
  it('should reject encryptedName exceeding 1000 characters', async () => {
    const folder = new Folder({ ...validFolderData, encryptedName: 'a'.repeat(1001) });
    const err = await getValidationError(folder);
    expect(err).toBeDefined();
    expect(err!.errors['encryptedName']).toBeDefined();
  });

  it('should reject nameIv exceeding 24 characters', async () => {
    const folder = new Folder({ ...validFolderData, nameIv: 'a'.repeat(25) });
    const err = await getValidationError(folder);
    expect(err).toBeDefined();
    expect(err!.errors['nameIv']).toBeDefined();
  });

  it('should reject nameTag exceeding 32 characters', async () => {
    const folder = new Folder({ ...validFolderData, nameTag: 'a'.repeat(33) });
    const err = await getValidationError(folder);
    expect(err).toBeDefined();
    expect(err!.errors['nameTag']).toBeDefined();
  });

  it('should accept fields within limits', async () => {
    const folder = new Folder(validFolderData);
    const err = await getValidationError(folder);
    expect(err).toBeUndefined();
  });
});

describe('User passwordGenOptions cross-field validator', () => {
  it('should reject defaultPasswordOptions with length < minNumbers + minSymbols on save', async () => {
    const user = new User({
      ...validUserData,
      settings: {
        defaultPasswordOptions: {
          length: 5,
          minNumbers: 3,
          minSymbols: 3,
        },
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
    // Either the inner field validator or the parent path validator will fire.
    const errorPaths = Object.keys(err!.errors);
    expect(
      errorPaths.some(
        (p) =>
          p === 'settings.defaultPasswordOptions' || p === 'settings.defaultPasswordOptions.length',
      ),
    ).toBe(true);
  });

  it('should reject defaultPasswordOptions where bumping minNumbers alone breaks the invariant', async () => {
    // Default length is 20, default minNumbers/minSymbols are 1 each.
    // Push minNumbers beyond length while leaving length alone.
    const user = new User({
      ...validUserData,
      settings: {
        defaultPasswordOptions: {
          length: 10,
          minNumbers: 8,
          minSymbols: 5, // 8 + 5 = 13 > 10
        },
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeDefined();
  });

  it('should accept defaultPasswordOptions where length == minNumbers + minSymbols', async () => {
    const user = new User({
      ...validUserData,
      settings: {
        defaultPasswordOptions: {
          length: 10,
          minNumbers: 5,
          minSymbols: 5,
        },
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should accept defaultPasswordOptions where length > minNumbers + minSymbols', async () => {
    const user = new User({
      ...validUserData,
      settings: {
        defaultPasswordOptions: {
          length: 20,
          minNumbers: 2,
          minSymbols: 2,
        },
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should accept defaultPasswordOptions with default values (length 20, minNumbers/Symbols 1)', async () => {
    const user = new User({
      ...validUserData,
      settings: {
        defaultPasswordOptions: {},
      },
    });
    const err = await getValidationError(user);
    expect(err).toBeUndefined();
  });

  it('should reject a findOneAndUpdate({ runValidators: true }) that replaces the subdocument with an invalid length, leaving the DB unchanged', async () => {
    // The documented contract is that the cross-field validator fires on the
    // UPDATE path (findOneAndUpdate with runValidators) when the whole
    // defaultPasswordOptions subdocument is replaced — the path userController's
    // updateSettings takes. The previous version called User.validate() on a POJO
    // (plain document validation), which is the SAME path the save() tests above
    // already cover and never issues an update query, so a regression that dropped
    // `runValidators` (or moved the validator to a save-only hook) would not be
    // caught. Exercise the real update path against the in-memory DB.
    const user = await User.create({
      ...validUserData,
      email: `pgo-update-${Date.now()}@example.com`,
    });

    await expect(
      User.findByIdAndUpdate(
        user._id,
        {
          $set: {
            'settings.defaultPasswordOptions': { length: 4, minNumbers: 3, minSymbols: 3 },
          },
        },
        { runValidators: true },
      ),
    ).rejects.toThrow(mongoose.Error.ValidationError);

    // The rejected update must not have mutated the stored document.
    const persisted = await User.findById(user._id).lean();
    expect(persisted).not.toBeNull();
    expect(persisted!.settings.defaultPasswordOptions.length).not.toBe(4);
  });
});

describe('VaultItem tags maxlength validators', () => {
  const validItemData = {
    userId: new mongoose.Types.ObjectId(),
    itemType: 'login' as const,
    encryptedData: 'valid-data',
    dataIv: 'valid-iv',
    dataTag: 'valid-tag',
    encryptedName: 'valid-name',
    nameIv: 'valid-iv',
    nameTag: 'valid-tag',
  };

  it('should reject a tag string exceeding 50 characters', async () => {
    const item = new VaultItem({
      ...validItemData,
      tags: ['a'.repeat(51)],
    });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    // Mongoose surfaces per-element string maxlength errors at the indexed path.
    expect(Object.keys(err!.errors).some((p) => p.startsWith('tags'))).toBe(true);
  });

  it('should accept a tag string at exactly 50 characters', async () => {
    const item = new VaultItem({
      ...validItemData,
      tags: ['a'.repeat(50)],
    });
    const err = await getValidationError(item);
    expect(err).toBeUndefined();
  });

  it('should still enforce max-tags-per-item alongside per-element length', async () => {
    const item = new VaultItem({
      ...validItemData,
      tags: Array.from({ length: 21 }, (_, i) => `t${String(i)}`),
    });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
    expect(err!.errors['tags']).toBeDefined();
  });
});

describe('AuditLog ipAddress maxlength validator', () => {
  it('should reject ipAddress exceeding 45 characters (IPv6 textual cap)', async () => {
    const log = new AuditLog({
      action: 'login',
      ipAddress: 'a'.repeat(46),
      userAgent: 'test-ua',
    });
    const err = await getValidationError(log);
    expect(err).toBeDefined();
    expect(err!.errors['ipAddress']).toBeDefined();
  });

  it('should accept ipAddress at exactly 45 characters', async () => {
    const log = new AuditLog({
      action: 'login',
      ipAddress: 'a'.repeat(45),
      userAgent: 'test-ua',
    });
    const err = await getValidationError(log);
    expect(err).toBeUndefined();
  });
});

describe('VaultItem passwordHistory maxlength validation', () => {
  const validItemData = {
    userId: new mongoose.Types.ObjectId(),
    itemType: 'login',
    encryptedData: 'test-data',
    dataIv: 'test-iv',
    dataTag: 'test-tag',
    encryptedName: 'test-name',
    nameIv: 'test-iv',
    nameTag: 'test-tag',
  };

  it('should reject passwordHistory entry with encryptedPassword exceeding 5,000 characters', async () => {
    const item = new VaultItem({
      ...validItemData,
      passwordHistory: [
        {
          encryptedPassword: 'a'.repeat(5_001),
          iv: 'test-iv',
          tag: 'test-tag',
          changedAt: new Date(),
        },
      ],
    });
    const err = await getValidationError(item);
    expect(err).toBeDefined();
  });

  it('should accept passwordHistory entry with encryptedPassword at 5,000 characters', async () => {
    const item = new VaultItem({
      ...validItemData,
      passwordHistory: [
        {
          encryptedPassword: 'a'.repeat(5_000),
          iv: 'test-iv',
          tag: 'test-tag',
          changedAt: new Date(),
        },
      ],
    });
    const err = await getValidationError(item);
    expect(err).toBeUndefined();
  });
});
