/**
 * `test:upgrade`, first half — data written by the PREVIOUS release, read by this one.
 *
 * Eight minor releases of encrypted user data have shipped and nothing has ever
 * checked that an upgrade can still read what the release before it wrote. That
 * is the one class of defect in this application with no recovery path: the
 * server holds only ciphertext, so a field that becomes required, a default that
 * starts being injected, or a model that stops accepting an absent optional does
 * not degrade a feature — it turns a user's vault into an item that renders as
 * "could not be fully decoded", with the password inside it.
 *
 * The fixture is `tests/fixtures/v0.7.0-vault.json`, generated inside a detached
 * worktree at the v0.7.0 tag by that release's own crypto and validated by that
 * release's own schemas; see `nMinusOneFixture.ts` for why the reader here is a
 * deliberately independent implementation of the format, and see the fixture's
 * `provenance` block for who generated it, when, and what was NOT verified.
 *
 * ---------------------------------------------------------------------------
 * WHAT EACH GROUP BELOW WOULD CATCH
 * ---------------------------------------------------------------------------
 *
 *   the schemas   A field added to `vaultItemDataSchemas` without `.optional()`,
 *                 or with a `.default()` that injects a key into every stored
 *                 document. The first refuses an older item outright; the second
 *                 changes what an unedited item hashes to, which silently
 *                 duplicates it on the next import.
 *
 *   the models    An optional field that became required — `sourceRefId` on a
 *                 folder, `absoluteExpiresAt` on a refresh token — or a settings
 *                 subtree a lean read no longer fills in.
 *
 *   the routes    A read path that mutates, truncates or re-serializes ciphertext
 *                 on its way out, and the sliding-session behaviour that a
 *                 refresh row with no absolute deadline must keep with no
 *                 migration.
 *
 * The fixture is never regenerated from the current tree. A golden recorded from
 * unverified output promotes today's bug into tomorrow's specification, and a
 * golden re-recorded from today's code turns this whole file into a tautology.
 */
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import request from 'supertest';
import type { webcrypto } from 'node:crypto';
import { ITEM_TYPES, registerSchema, vaultItemDataSchemas, type ItemType } from '@hvault/shared';
import app from '../../src/app.js';
import { config } from '../../src/config/index.js';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { Folder } from '../../src/models/Folder.js';
import { RefreshToken } from '../../src/models/RefreshToken.js';
import { hashToken } from '../../src/utils/token.js';
import { generateAccessToken, getCsrf } from '../helpers.js';
import {
  deriveMasterKeys,
  nMinusOneVault,
  openText,
  searchHashOf,
  unwrapVaultKey,
} from './nMinusOneFixture.js';

const API = '/api/v1';
const DAY_MS = 24 * 60 * 60 * 1000;

const { account, items, folders, refreshTokens, provenance } = nMinusOneVault;

/**
 * Derived ONCE for the file. 600,000 PBKDF2 iterations is the point of the work
 * factor; paying it per test would add most of a second to each one for a value
 * that cannot change between them.
 */
let vaultKey: webcrypto.CryptoKey;
let searchHashKey: webcrypto.CryptoKey;
let derivedAuthHash: string;

beforeAll(async () => {
  const derived = await deriveMasterKeys(account.masterPassword, account.email);
  derivedAuthHash = derived.authHash;
  ({ vaultKey, searchHashKey } = await unwrapVaultKey(account, derived.masterEncryptionKey));
});

/**
 * Settings keys the CURRENT model carries that the previous release's user
 * document does not — derived from the fixture rather than listed here, so it
 * cannot go stale, and asserted non-empty where it is used so it cannot go
 * vacuous.
 */
function settingsKeysAddedSinceV070(currentSettings: Record<string, unknown>): string[] {
  const before = new Set(Object.keys(account.settings));
  return Object.keys(currentSettings).filter((key) => !before.has(key));
}

/**
 * Seeds the whole fixture vault into the database through the CURRENT models.
 *
 * The user is created through the model and then has the settings keys the
 * previous release did not have REMOVED, which is the only faithful way to
 * produce that document here: Mongoose applies a subdocument's schema defaults
 * on `create()`, so a straight create writes today's shape rather than 0.7.0's,
 * and a raw `insertOne` would have to restate every other default by hand and
 * would drift from the model the day one of them changes.
 */
async function seedNMinusOneVault(): Promise<{
  userId: string;
  accessToken: string;
  itemIds: Map<string, string>;
  folderIds: Map<string, string>;
  settingsRemoved: string[];
}> {
  const user = await User.create({
    email: account.email,
    authHash: '$2a$04$notarealbcrypthashnotarealbcrypthashnotarealbcrypthashno',
    emailVerified: true,
    encryptedVaultKey: account.encryptedVaultKey,
    vaultKeyIv: account.vaultKeyIv,
    vaultKeyTag: account.vaultKeyTag,
    kdfIterations: account.kdfIterations,
    kdfAlgorithm: account.kdfAlgorithm,
    encryptionVersion: account.encryptionVersion,
    settings: account.settings,
  });
  const userId = user._id.toString();

  // Through `toObject()`, because a Mongoose subdocument's own keys are its
  // internals (`$__`, `_doc`, …) rather than the schema's. The settings
  // subschemas carry `_id: false`, so the plain object is exactly the persisted
  // shape.
  const settingsRemoved = settingsKeysAddedSinceV070(
    (user.toObject() as unknown as { settings: Record<string, unknown> }).settings,
  );
  if (settingsRemoved.length > 0) {
    await User.collection.updateOne(
      { _id: user._id },
      { $unset: Object.fromEntries(settingsRemoved.map((key) => [`settings.${key}`, ''])) },
    );
  }

  const folderIds = new Map<string, string>();
  for (const folder of folders) {
    const created = await Folder.create({
      userId,
      encryptedName: folder.encryptedName,
      nameIv: folder.nameIv,
      nameTag: folder.nameTag,
      searchHash: folder.searchHash,
      sortOrder: folder.sortOrder,
      ...(folder.parent ? { parentId: folderIds.get(folder.parent) } : {}),
      ...(folder.sourceRefId ? { sourceRefId: folder.sourceRefId } : {}),
    });
    folderIds.set(folder.id, created._id.toString());
  }

  const itemIds = new Map<string, string>();
  for (const item of items) {
    const created = await VaultItem.create({
      userId,
      itemType: item.itemType,
      encryptedName: item.encryptedName,
      nameIv: item.nameIv,
      nameTag: item.nameTag,
      searchHash: item.searchHash,
      encryptedData: item.encryptedData,
      dataIv: item.dataIv,
      dataTag: item.dataTag,
    });
    itemIds.set(item.id, created._id.toString());
  }

  return { userId, accessToken: generateAccessToken(userId), itemIds, folderIds, settingsRemoved };
}

// ─────────────────────────────────────────────────────────────────────────────
// The fixture is what it says it is
// ─────────────────────────────────────────────────────────────────────────────

describe('the N-1 fixture is a real artefact of the previous release', () => {
  it('carries a provenance note naming its tag, its author and its date', () => {
    // A golden with no provenance is an assertion nobody can check. These four
    // fields are what let a reader decide whether to believe the rest of this
    // file, so their ABSENCE has to fail rather than pass quietly.
    expect(provenance.generatedFromTag).toBe('v0.7.0');
    // The EXACT commit, not merely a 40-hex shape. `v0.7.0` is an annotated tag,
    // so `git rev-parse v0.7.0` yields the tag OBJECT; this is what
    // `git rev-parse v0.7.0^{}` yields, which is the release commit itself.
    // Pinned as a literal because the one edit that turns this whole file into a
    // tautology — regenerating the fixture from the current tree — would change
    // it, and a shape check would wave that through.
    expect(provenance.generatedFromCommit).toBe('8ab3c7609a505e65c02276e78e673eff4195d262');
    expect(provenance.generatedBy).toMatch(/\S+@\S+/);
    expect(provenance.generatedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    // And it states its own limits, so nobody reads more into it than it proves.
    expect(provenance.notVerified.length).toBeGreaterThan(0);
    expect(provenance.neverRegenerate).toContain('v0.7.0');
  });

  it('holds ciphertext that only the fixture master password opens', () => {
    // The whole suite rests on the decrypts below being authenticated rather
    // than incidental. AES-GCM verifies its tag, so a wrong key must REJECT — if
    // it did not, every "it decrypts" assertion here would be worthless.
    expect(items.length).toBeGreaterThan(0);
    return expect(
      deriveMasterKeys(`${account.masterPassword}-wrong`, account.email).then((wrong) =>
        unwrapVaultKey(account, wrong.masterEncryptionKey),
      ),
    ).rejects.toThrow();
  });

  it('covers every item type release 0.7.0 could store', () => {
    // A type absent from the fixture is a type this gate says nothing about, and
    // the omission would be invisible: the file would stay green while a required
    // field was added to exactly that schema.
    //
    // Pinned as the five types that EXISTED at 0.7.0, deliberately not compared
    // against today's `ITEM_TYPES`. A sixth type added later cannot appear in a
    // 0.7.0 vault, so an equality check against the current list would leave two
    // ways out on the day it lands: falsify the golden by inventing a row that
    // release could never have written, or edit this assertion. Both are the
    // pressure Law 2 exists to remove. A new type is exempt and belongs on the
    // list below only if a release that HAD it is ever made the N-1 baseline.
    const V070_ITEM_TYPES = ['login', 'secret', 'note', 'card', 'identity'] as const;
    expect([...new Set(items.map((item) => item.itemType))].sort()).toEqual(
      [...V070_ITEM_TYPES].sort(),
    );
    // And every one of them is still a type this application recognises — the
    // half that WOULD have to fail if a type were ever removed.
    for (const itemType of V070_ITEM_TYPES) {
      expect(ITEM_TYPES, `${itemType} was dropped from ITEM_TYPES`).toContain(itemType);
    }
  });

  it('really does omit the fields it claims to omit', () => {
    // `omits` is the fixture's own claim about which keys a document of that era
    // does NOT carry, and it is what makes the parse assertions below meaningful.
    // Checked against the stored bytes, so a fixture that quietly gained a field
    // stops describing an older document and says so.
    const declared = items.flatMap((item) => item.omits.map((key) => `${item.id}:${key}`));
    expect(declared).toEqual([
      'login-without-backup-codes:backupCodes',
      'identity-without-street2-or-delivery-notes:address.street2',
      'identity-without-street2-or-delivery-notes:address.deliveryNotes',
      'card-without-street2:billingAddress.street2',
      'note-without-format:format',
    ]);

    for (const item of items) {
      const stored = JSON.parse(item.plaintext) as Record<string, unknown>;
      for (const key of item.omits) {
        const [head, leaf] = key.split('.');
        const container = leaf === undefined ? stored : (stored[head!] as Record<string, unknown>);
        expect(container, `${item.id}: ${key}`).toBeTruthy();
        expect(Object.keys(container), `${item.id}: ${key}`).not.toContain(leaf ?? head);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// The schemas
// ─────────────────────────────────────────────────────────────────────────────

/**
 * These decrypts are the INTEGRITY ANCHOR for everything below, and it is worth
 * being exact about what they do and do not prove.
 *
 * Both sides are owned by this directory: the bytes come from the fixture and
 * the reader is `nMinusOneFixture.ts`. So no change to `cryptoService.ts` can
 * turn this group red — that claim belongs to the client leg of this same gate
 * (`packages/client/tests/upgrade/n-minus-1-crypto.test.ts`), which drives the
 * same frozen fixture through the application's OWN crypto.
 *
 * What this group does establish, and what nothing else can, is that
 * `item.plaintext` is genuinely the plaintext of `item.encryptedData` under a
 * key derived from the fixture's own master password. Because AES-GCM
 * authenticates, that is a real check rather than a restatement — and it is what
 * makes the parse assertions below assertions about a 0.7.0 document rather than
 * about a string somebody typed into a JSON file.
 */
describe('a vault written by the previous release still decrypts and parses', () => {
  it.each(items.map((item) => [item.id, item] as const))(
    'decrypts %s to the exact bytes 0.7.0 sealed',
    async (_id, item) => {
      const plaintext = await openText(
        { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag },
        vaultKey,
      );
      // Byte-identical, not merely "parses to the same object": the stored blob
      // is what a re-encrypt would have to reproduce, and a whitespace or
      // key-order change in it is what moves an item's import content hash.
      expect(plaintext).toBe(item.plaintext);

      // The name is a separate triple, so it has to open independently of the
      // data — the shape every read path assumes.
      expect(
        await openText(
          { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
          vaultKey,
        ),
      ).toBe(item.name);

      // The search hash the server matches duplicates on is an HMAC of the name
      // under the vault key, and the fixture recorded the one 0.7.0 produced.
      expect(await searchHashOf(item.name, searchHashKey)).toBe(item.searchHash);
    },
  );

  it.each(items.map((item) => [item.id, item] as const))(
    'parses %s to exactly what 0.7.0 parsed it to',
    (_id, item) => {
      const schema = vaultItemDataSchemas[item.itemType];
      const parsed = schema.safeParse(JSON.parse(item.plaintext));

      // A rejection here is the worst outcome this gate has: on the client that
      // stamps `_validationError`, and the whole item collapses to the read-only
      // "could not be fully decoded" notice with its password inside.
      expect(parsed.success, parsed.success ? '' : JSON.stringify(parsed.error?.issues)).toBe(true);

      // Equality against the PREVIOUS release's own parse output, which is the
      // whole point of the fixture. This fails three separate ways: a value that
      // changed, a key that stopped being emitted, and — the quiet one — a new
      // `.default()` injecting a key into every document written before it
      // existed, which changes what an untouched item hashes to on import.
      expect(parsed.data).toEqual(item.parsedByV070);

      // Key ORDER too, at the top level and one level down — which is where the
      // postal address lives, and where a reordered `.extend()` would land.
      // `toEqual` is order-insensitive, but the import identity of a non-login
      // item is a hash of its serialized content, so a reordering that changes
      // nothing semantically still duplicates every affected item on the next
      // import of the same file.
      const parsedData = parsed.data as Record<string, unknown>;
      expect(Object.keys(parsedData)).toEqual(Object.keys(item.parsedByV070));
      for (const [key, value] of Object.entries(parsedData)) {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
        expect(Object.keys(value as object), `${item.id}.${key}`).toEqual(
          Object.keys(item.parsedByV070[key] as object),
        );
      }
    },
  );

  it('injects only the defaults the previous release already injected', () => {
    // Stated separately from the equality above so the intent is legible rather
    // than implied: parsing an older document may ADD keys (that is what a
    // `.default()` is for), and this pins exactly which, per item. The note
    // gains `format`; the two five-field addresses gain `street2`; the identity
    // gains `deliveryNotes`; and the login that predates `backupCodes` gains
    // NOTHING, because that field is `.optional()` with no default — which is
    // the difference this list exists to keep visible.
    const added: Record<string, string[]> = {};
    for (const item of items) {
      const stored = JSON.parse(item.plaintext) as Record<string, unknown>;
      const parsed = vaultItemDataSchemas[item.itemType].parse(stored) as Record<string, unknown>;
      const keys = Object.keys(parsed).filter((key) => !(key in stored));
      for (const [key, value] of Object.entries(parsed)) {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          const nested = stored[key] as Record<string, unknown> | undefined;
          if (!nested) continue;
          keys.push(
            ...Object.keys(value as object)
              .filter((inner) => !(inner in nested))
              .map((inner) => `${key}.${inner}`),
          );
        }
      }
      added[item.id] = keys;
    }

    expect(added).toEqual({
      'login-without-backup-codes': [],
      'login-with-backup-codes': [],
      'identity-without-street2-or-delivery-notes': ['address.street2', 'address.deliveryNotes'],
      'identity-with-street2-and-delivery-notes': [],
      'card-without-street2': ['billingAddress.street2'],
      'note-without-format': ['format'],
      'secret-with-expiry': [],
    });
  });

  it('declares no required field on any item schema, so ANY older document parses', () => {
    // The general form of the invariant, and the one that does not depend on the
    // fixture at all: an empty object is the oldest possible document, so every
    // schema must accept it. The day a field is added without `.optional()` or a
    // `.default()`, this is the assertion that names it — including for a shape
    // no row in the fixture happens to have.
    for (const itemType of ITEM_TYPES) {
      const parsed = vaultItemDataSchemas[itemType as ItemType].safeParse({});
      expect(
        parsed.success,
        `${itemType}: ${parsed.success ? '' : JSON.stringify(parsed.error?.issues)}`,
      ).toBe(true);
    }
  });

  it('still accepts the credential envelope the previous release minted', () => {
    // Not "could this account register again" for its own sake: `registerSchema`
    // is where the vault-key envelope's bounds are stated, and narrowing one of
    // them — a lower `kdfIterations` ceiling, a shorter `encryptedVaultKey` —
    // would put every account created by an older release outside the contract
    // the current code believes it is holding.
    const parsed = registerSchema.safeParse({
      email: account.email,
      authHash: account.authHash,
      encryptedVaultKey: account.encryptedVaultKey,
      vaultKeyIv: account.vaultKeyIv,
      vaultKeyTag: account.vaultKeyTag,
      kdfIterations: account.kdfIterations,
      kdfAlgorithm: account.kdfAlgorithm,
      encryptionVersion: account.encryptionVersion,
    });
    expect(parsed.success, parsed.success ? '' : JSON.stringify(parsed.error?.issues)).toBe(true);

    // And the auth hash 0.7.0 derived is reproducible from the same master
    // password and email under the same PARAMETERS — 600,000 iterations of
    // PBKDF2-SHA256 over the lowercased email, then one more pass. This pins the
    // format, not the implementation: the client's own derivation is exercised
    // by the client leg of this gate.
    expect(derivedAuthHash).toBe(account.authHash);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// The models and the read paths
// ─────────────────────────────────────────────────────────────────────────────

describe('the current models accept the documents the previous release persisted', () => {
  let seeded: Awaited<ReturnType<typeof seedNMinusOneVault>>;

  beforeEach(async () => {
    seeded = await seedNMinusOneVault();
  });

  it('stores and returns every item with its ciphertext untouched', async () => {
    const res = await request(app)
      .get(`${API}/vault/items`)
      .set('Authorization', `Bearer ${seeded.accessToken}`)
      .expect(200);

    const returned = new Map(
      (
        res.body.data as { _id: string; encryptedData: string; dataIv: string; dataTag: string }[]
      ).map((row) => [row._id, row] as const),
    );
    expect(returned.size).toBe(items.length);

    for (const item of items) {
      const row = returned.get(seeded.itemIds.get(item.id)!);
      expect(row, item.id).toBeDefined();
      // Byte-for-byte on the way out. A read path that trimmed, re-encoded or
      // re-serialized a ciphertext field would leave the row undecryptable and
      // nothing else in the suite would notice.
      expect(row!.encryptedData, item.id).toBe(item.encryptedData);
      expect(row!.dataIv, item.id).toBe(item.dataIv);
      expect(row!.dataTag, item.id).toBe(item.dataTag);
      // And it still opens after the round trip through mongod and the route.
      expect(
        await openText(
          { encrypted: row!.encryptedData, iv: row!.dataIv, tag: row!.dataTag },
          vaultKey,
        ),
      ).toBe(item.plaintext);
    }
  });

  it('accepts a folder with no sourceRefId, and never serializes the one that has it', async () => {
    // `sourceRefId` is stamped only on a fresh restore insert, so most folders
    // have never carried it — and it holds ANOTHER account's ObjectId, which is
    // why the read paths strip it. Both halves are checked here, because "an
    // absent optional is accepted" and "a present one is hidden" fail
    // independently.
    const stored = await Folder.find({ userId: seeded.userId }).lean();
    expect(stored).toHaveLength(folders.length);
    expect(stored.filter((row) => row.sourceRefId === undefined)).toHaveLength(2);
    expect(stored.filter((row) => typeof row.sourceRefId === 'string')).toHaveLength(1);

    const res = await request(app)
      .get(`${API}/folders`)
      .set('Authorization', `Bearer ${seeded.accessToken}`)
      .expect(200);

    const rows = res.body.data as Record<string, unknown>[];
    expect(rows).toHaveLength(folders.length);
    for (const row of rows) {
      expect(Object.keys(row)).not.toContain('sourceRefId');
    }

    // The nesting edge survives too: the child still points at the root.
    const child = rows.find((row) => row._id === seeded.folderIds.get('folder-child'));
    expect(String(child?.parentId)).toBe(seeded.folderIds.get('folder-root'));
  });

  it('fills in the two settings the current release added, without a migration', async () => {
    // The v0.7.0 user document carries no `lockOnHidden` and no
    // `lockOnHiddenDelay`; both were added afterwards. Nothing backfills them,
    // and the profile route reads with `.lean()` — which returns raw BSON, so
    // Mongoose's schema defaults are NOT applied. `withSettingsDefaults` is the
    // one boundary that makes the declared type true, and this is what fails if
    // a future setting skips it: a client would arm an auto-lock timer from
    // `undefined`, compare `NaN` against every deadline, and never lock at all.
    // Derived from the fixture, and asserted rather than assumed: if the current
    // model ever stopped having settings the previous release lacked, this test
    // would still pass while proving nothing, so the list itself is pinned.
    expect(seeded.settingsRemoved.sort()).toEqual(['lockOnHidden', 'lockOnHiddenDelay']);

    const persisted = await User.findById(seeded.userId).lean();
    expect(persisted).not.toBeNull();
    const persistedSettings = persisted!.settings as unknown as Record<string, unknown>;
    expect(Object.keys(persistedSettings)).not.toContain('lockOnHidden');
    expect(Object.keys(persistedSettings)).not.toContain('lockOnHiddenDelay');

    const res = await request(app)
      .get(`${API}/user/profile`)
      .set('Authorization', `Bearer ${seeded.accessToken}`)
      .expect(200);

    const settings = res.body.data.settings as Record<string, unknown>;
    expect(typeof settings.lockOnHidden).toBe('boolean');
    expect(typeof settings.lockOnHiddenDelay).toBe('number');
    expect(Number.isNaN(settings.lockOnHiddenDelay)).toBe(false);
    // The values the older document DID carry are its own, not re-defaulted.
    expect(settings.autoLockTimeout).toBe(15);
    expect(settings.clipboardClearTimeout).toBe(30);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// The refresh row with no absolute deadline
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The two refresh rows, selected by what they DECLARE rather than by position.
 * Reordering the fixture would otherwise silently swap which row each test
 * drives, and one of the two would still pass — for the opposite reason.
 */
const slidingRow = refreshTokens.find((token) => token.omits.includes('absoluteExpiresAt'))!;
const rememberedRow = refreshTokens.find((token) => token.absoluteExpiresInDays !== null)!;

describe('a refresh row with no absoluteExpiresAt keeps sliding, with no migration', () => {
  let userId: string;

  beforeEach(async () => {
    ({ userId } = await seedNMinusOneVault());
    const now = Date.now();
    for (const token of refreshTokens) {
      await RefreshToken.create({
        userId,
        tokenHash: hashToken(token.rawToken),
        familyId: token.familyId,
        deviceInfo: { userAgent: 'n-minus-one', ip: '127.0.0.1', fingerprint: 'n-minus-one' },
        expiresAt: new Date(now + token.expiresInDays * DAY_MS),
        ...(token.absoluteExpiresInDays === null
          ? {}
          : { absoluteExpiresAt: new Date(now + token.absoluteExpiresInDays * DAY_MS) }),
      });
    }
  });

  /** Rotates a raw refresh token and returns the row the rotation minted. */
  async function rotate(rawToken: string) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent, `refreshToken=${rawToken}`);
    const res = await agent
      .post(`${API}/auth/refresh`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', `${csrf.cookie}; refreshToken=${rawToken}`);
    expect(res.status).toBe(200);

    const setCookie = res.headers['set-cookie'] as string | string[] | undefined;
    const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
    const raw = cookies
      .find((cookie) => cookie.startsWith('refreshToken='))
      ?.split(';')[0]!
      .replace('refreshToken=', '');
    expect(raw).toBeTruthy();
    const row = await RefreshToken.findOne({ tokenHash: hashToken(raw!) }).lean();
    expect(row).not.toBeNull();
    return row!;
  }

  it('rotates a pre-0.5.0 row to a fresh seven-day expiry and still no deadline', async () => {
    const stored = await RefreshToken.findOne({
      tokenHash: hashToken(slidingRow.rawToken),
    }).lean();
    expect(stored).not.toBeNull();
    expect(stored!.absoluteExpiresAt).toBeUndefined();

    const before = Date.now();
    const rotated = await rotate(slidingRow.rawToken);

    // The designed behaviour, stated as a range because the row's expiry is
    // computed from the server's own clock: a standard session slides to
    // REFRESH_TOKEN_DAYS from now, every time.
    const expected = before + config.REFRESH_TOKEN_DAYS * DAY_MS;
    expect(rotated.expiresAt.getTime()).toBeGreaterThanOrEqual(expected - 5_000);
    expect(rotated.expiresAt.getTime()).toBeLessThanOrEqual(expected + 60_000);

    // It MOVED. The range above is necessary but not sufficient on its own, and
    // this is why the fixture seeds the row partially elapsed: a rotation that
    // carried the old expiry forward instead of sliding it — which is what
    // "every long-lived session now hard-expires on a fixed date" looks like in
    // one line of the controller — lands inside any sane tolerance when the row
    // started at the full horizon. Against a row with two days left it cannot.
    expect(rotated.expiresAt.getTime()).toBeGreaterThan(stored!.expiresAt.getTime());

    // The negative, and the actual subject of this test: rotation must NOT
    // invent a deadline for a row that never had one. Minting one here would
    // silently convert every pre-0.5.0 session into a hard-expiring one and log
    // those users out on a schedule nobody chose.
    expect(rotated.absoluteExpiresAt).toBeUndefined();
    expect(rotated.familyId).toBe(slidingRow.familyId);
  });

  it('carries a remembered row’s deadline forward unchanged instead of sliding it', async () => {
    // The counterpart, so the test above cannot pass by "rotation ignores
    // absoluteExpiresAt entirely". A remembered family's 30 days is ABSOLUTE:
    // rotation pins `expiresAt` to the deadline rather than extending it.
    const stored = await RefreshToken.findOne({
      tokenHash: hashToken(rememberedRow.rawToken),
    }).lean();
    expect(stored?.absoluteExpiresAt).toBeInstanceOf(Date);
    const deadline = stored!.absoluteExpiresAt!.getTime();

    const rotated = await rotate(rememberedRow.rawToken);
    expect(rotated.absoluteExpiresAt?.getTime()).toBe(deadline);
    expect(rotated.expiresAt.getTime()).toBe(deadline);
  });
});
