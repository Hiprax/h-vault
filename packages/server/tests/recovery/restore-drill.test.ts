/**
 * The disaster-recovery drill: a backup file, restored onto a DIFFERENT
 * database, on a DIFFERENT mongod.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS WHEN `backup-restore-cross-account.test.ts` ALREADY PASSES
 * ---------------------------------------------------------------------------
 *
 * That suite is thorough about the restore ALGORITHM — id minting, folder
 * remapping, repeat-restore idempotency — and every one of its cases runs
 * against the single database the rest of the harness uses, with rows the
 * database already holds. Two things follow, and both of them are exactly what a
 * user needs when their server is gone:
 *
 *   1. Nothing proves the restore does not depend on state the target instance
 *      already has. A backup restored into the database it came from cannot
 *      distinguish "restored the row" from "the row was already there".
 *
 *   2. Nothing proves the CIPHERTEXT survives the trip. Those rows carry
 *      `test-encrypted-data-base64`, so a restore that mangled a byte of real
 *      AES-GCM output — or that lost the IV/tag pairing — would look identical.
 *      The failure a user sees is not a missing row; it is a row that is there
 *      and will not open, with their password inside it.
 *
 * So this drill uses two real mongod processes. The vault is built on the first
 * through the real API with real AES-256-GCM ciphertext; the backup is taken
 * through the real download endpoint; then the connection moves to a second,
 * EMPTY instance where a fresh account restores that file and every item is
 * decrypted and compared byte for byte with what was sealed. The source is read
 * back afterwards, once the connection returns to it, to prove the restore never
 * wrote there.
 *
 * The crypto is an INDEPENDENT implementation of the format (`vaultFormat.ts`),
 * which also explains why it cannot simply import the client's `cryptoService`.
 *
 * ---------------------------------------------------------------------------
 * THE JOURNEY, AND WHOSE CODE RUNS AT EACH STEP
 * ---------------------------------------------------------------------------
 *
 *   sign        what the browser does, implemented HERE rather than by the
 *               client's own code, which a server test cannot import (see
 *               `vaultFormat.ts`): HMAC over the document with `integrity`
 *               removed and re-serialized, under an HKDF subkey of the backup
 *               wrapping key
 *   verify      the same, and the reason the round-trip test below is about the
 *               SERVER: the signature can only verify while the document this
 *               server emits survives `JSON.stringify(JSON.parse(x))` unchanged
 *   recover     the client's step: the backup password opens the wrapping key,
 *               which opens the copy of the vault key the source account used
 *   re-encrypt  the client's step, and the load-bearing one: a restore NEVER
 *               adopts the backup's vault key, so every row is re-sealed under
 *               the NEW account's key before it is sent
 *   restore     the server's `POST /backup/restore`, and the only step below
 *               that runs production code: fresh ids, `sourceRefId` provenance,
 *               folder remapping
 *   read back   the server's `GET /vault/items`, then the client's decrypt
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import type { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../../src/app.js';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { Folder } from '../../src/models/Folder.js';
import { withEgressAllowed } from '../egressGuard.js';
import {
  createStandaloneMongo,
  getStandaloneUri,
  restoreStandaloneConnection,
  switchMongoConnection,
} from '../mongoHarness.js';
import { authHeader, generateAccessToken, getCsrf } from '../helpers.js';
import {
  deriveBackupEncryptionKey,
  deriveMasterKeys,
  generateKey,
  open,
  openText,
  randomBytes,
  seal,
  sealText,
  searchHashOf,
  signBackup,
  splitSignedBackup,
  verifyBackup,
  type Sealed,
} from './vaultFormat.js';

/** One derivation each, in `beforeAll`: 600,000 iterations is not per-test work. */
const MASTER_PASSWORD = 'correct horse battery staple';
const BACKUP_PASSWORD = 'a different backup password entirely';
const WRONG_BACKUP_PASSWORD = 'not the backup password';
const ACCOUNT_EMAIL = 'drill@example.com';

/**
 * The plaintexts, chosen to be hostile to a byte-for-byte claim rather than
 * convenient for one: a non-BMP emoji (surrogate pair), a CRLF, an embedded
 * quote, right-to-left text, and a value long enough to span AES blocks. A
 * round trip that normalised line endings, re-encoded to Latin-1 or truncated
 * would still look plausible against `test-data`.
 */
const ITEM_PLAINTEXTS = [
  JSON.stringify({ username: 'ada@example.com', password: 'p@ss"w0rd', notes: 'line1\r\nline2' }),
  JSON.stringify({ username: 'grace', password: '🔐🔑 نص عربي', notes: 'emoji + RTL' }),
  JSON.stringify({ username: 'long', password: 'x'.repeat(4096), notes: 'spans many blocks' }),
] as const;

const ITEM_NAMES = ['Bank login', 'Mail — 🔐', 'A very long name '.repeat(8).trim()] as const;
const FOLDER_NAME = 'Personal';

/**
 * The six ciphertext fields, read off whatever carries them.
 *
 * Typed structurally rather than as `Record<string, unknown>` so a lean Mongoose
 * document (which has no index signature) and a parsed backup row are both
 * accepted without a cast at every call site.
 */
interface CipherRow {
  encryptedData?: unknown;
  dataIv?: unknown;
  dataTag?: unknown;
  encryptedName?: unknown;
  nameIv?: unknown;
  nameTag?: unknown;
}

const sealedOf = (row: CipherRow, prefix: 'data' | 'name'): Sealed =>
  prefix === 'data'
    ? {
        encrypted: String(row.encryptedData),
        iv: String(row.dataIv),
        tag: String(row.dataTag),
      }
    : {
        encrypted: String(row.encryptedName),
        iv: String(row.nameIv),
        tag: String(row.nameTag),
      };

interface SourceAccount {
  userId: string;
  token: string;
  /** The raw vault key bytes the SOURCE account sealed everything with. */
  rawVaultKey: Uint8Array;
  vaultKey: Awaited<ReturnType<typeof generateKey>>['key'];
  /** The raw backup wrapping key, i.e. what the backup password recovers. */
  rawBwk: Uint8Array;
  itemIds: string[];
  folderId: string;
}

describe('Backup restore drill (two mongod instances, two databases)', () => {
  let targetServer: MongoMemoryServer;
  let targetUri: string;
  let master: Awaited<ReturnType<typeof deriveMasterKeys>>;
  let bek: Awaited<ReturnType<typeof deriveBackupEncryptionKey>>;
  let wrongBek: Awaited<ReturnType<typeof deriveBackupEncryptionKey>>;
  let bwkSalt: string;
  let source: SourceAccount;

  const agent = (): request.Agent => request.agent(app);

  async function post(
    path: string,
    token: string,
    body: Record<string, unknown>,
  ): Promise<request.Response> {
    const client = agent();
    const csrf = await getCsrf(client);
    return client
      .post(path)
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(body);
  }

  beforeAll(async () => {
    // The SECOND mongod. `createStandaloneMongo` draws its port from this
    // worker's own band, so a second instance in a parallel run cannot collide
    // with a sibling's — see tests/mongoHarness.ts.
    targetServer = await withEgressAllowed(createStandaloneMongo);
    targetUri = targetServer.getUri();

    master = await deriveMasterKeys(MASTER_PASSWORD, ACCOUNT_EMAIL);
    bwkSalt = Buffer.from(randomBytes(16)).toString('base64');
    bek = await deriveBackupEncryptionKey(BACKUP_PASSWORD, bwkSalt);
    wrongBek = await deriveBackupEncryptionKey(WRONG_BACKUP_PASSWORD, bwkSalt);
  }, 180_000);

  afterAll(async () => {
    await targetServer.stop();
  });

  /**
   * Builds the account that is about to lose its server: a real wrapped vault
   * key, a configured backup password, three items with real ciphertext and one
   * folder — all through the endpoints a user's browser would call.
   */
  async function seedSourceAccount(): Promise<SourceAccount> {
    const { raw: rawVaultKey, key: vaultKey } = await generateKey();
    const wrappedVaultKey = await seal(rawVaultKey, master.masterEncryptionKey);

    const user = await User.create({
      email: ACCOUNT_EMAIL,
      authHash: await bcrypt.hash(master.authHash, 4),
      emailVerified: true,
      encryptedVaultKey: wrappedVaultKey.encrypted,
      vaultKeyIv: wrappedVaultKey.iv,
      vaultKeyTag: wrappedVaultKey.tag,
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
    });
    const userId = user._id.toString();
    const token = generateAccessToken(userId);

    // The backup password's own key hierarchy, configured through the real
    // endpoint: the wrapping key sealed by the backup encryption key, and a copy
    // of the vault key sealed by the wrapping key. That second copy is the only
    // reason a backup can be opened by an account that never had this vault key.
    const rawBwk = randomBytes(32);
    const encryptedBwk = await seal(rawBwk, bek);
    const bwkKey = await crypto.subtle.importKey('raw', rawBwk, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
    const bwkWrappedVaultKey = await seal(rawVaultKey, bwkKey);

    const setup = await post('/api/v1/backup/setup', token, {
      authHash: master.authHash,
      encryptedBWK: encryptedBwk.encrypted,
      bwkIv: encryptedBwk.iv,
      bwkTag: encryptedBwk.tag,
      bwkSalt,
      bwkEncryptedVaultKey: bwkWrappedVaultKey.encrypted,
      bwkVaultKeyIv: bwkWrappedVaultKey.iv,
      bwkVaultKeyTag: bwkWrappedVaultKey.tag,
    });
    expect(setup.status, JSON.stringify(setup.body)).toBe(200);

    const sealedFolderName = await sealText(FOLDER_NAME, vaultKey);
    const folderRes = await post('/api/v1/folders', token, {
      encryptedName: sealedFolderName.encrypted,
      nameIv: sealedFolderName.iv,
      nameTag: sealedFolderName.tag,
      searchHash: await searchHashOf(FOLDER_NAME, rawVaultKey),
    });
    expect(folderRes.status, JSON.stringify(folderRes.body)).toBe(201);
    const folderId = String(folderRes.body.data._id);

    const itemIds: string[] = [];
    for (const [index, plaintext] of ITEM_PLAINTEXTS.entries()) {
      const name = ITEM_NAMES[index]!;
      const sealedData = await sealText(plaintext, vaultKey);
      const sealedName = await sealText(name, vaultKey);
      const res = await post('/api/v1/vault/items', token, {
        itemType: 'login',
        encryptedData: sealedData.encrypted,
        dataIv: sealedData.iv,
        dataTag: sealedData.tag,
        encryptedName: sealedName.encrypted,
        nameIv: sealedName.iv,
        nameTag: sealedName.tag,
        searchHash: await searchHashOf(name, rawVaultKey),
        tags: ['drill'],
        favorite: index === 0,
        // Only the first item is filed, so the drill covers both the remapped
        // and the unfiled case in one pass.
        ...(index === 0 ? { folderId } : {}),
      });
      expect(res.status, JSON.stringify(res.body)).toBe(201);
      itemIds.push(String(res.body.data._id));
    }

    return { userId, token, rawVaultKey, vaultKey, rawBwk, itemIds, folderId };
  }

  /** Downloads the backup the way the browser does, and signs it. */
  async function downloadAndSign(account: SourceAccount): Promise<string> {
    const res = await request(app)
      .get('/api/v1/backup/download')
      .set('Authorization', authHeader(account.token));
    expect(res.status, res.text.slice(0, 200)).toBe(200);

    const body = res.text;
    const integrity = await signBackup(body, account.rawBwk);
    const parsed = JSON.parse(body) as Record<string, unknown>;
    parsed.integrity = integrity;
    return JSON.stringify(parsed);
  }

  /**
   * Runs `work` against the SECOND instance, then puts the connection back.
   *
   * The borrow is a lifecycle with a matching return, for the reason
   * `useReplicaSetConnection` records: `tests/setup.ts` owns the standalone
   * connection and its `afterEach` truncation, so a block that walked away with
   * the connection would leave every later test talking to the wrong database.
   * The target's collections are truncated on the way out for the same reason:
   * nothing else does it, and the next drill has to find an EMPTY instance or
   * its central claim is unfalsifiable.
   */
  async function onTargetInstance<T>(work: () => Promise<T>): Promise<T> {
    expect(targetUri).not.toBe(getStandaloneUri());
    await switchMongoConnection(targetUri);
    try {
      return await work();
    } finally {
      // The RESTORE is the outer `finally`, and the ordering is load-bearing: a
      // truncation that throws (a target connection that has gone away) would
      // otherwise replace the real failure AND skip the restore, leaving the
      // process pointed at the target for every later test in this file — where
      // the next `beforeEach` would seed the source account into the wrong
      // database.
      try {
        const collections = await mongoose.connection.db!.collections();
        for (const collection of collections) await collection.deleteMany({});
      } finally {
        await restoreStandaloneConnection();
      }
    }
  }

  /**
   * The account the user creates on the new server: same person, same master
   * password, and therefore the same master encryption key — but a BRAND NEW,
   * randomly generated vault key, which is what forces the re-encryption step.
   */
  async function registerRecoveryAccount(): Promise<{
    userId: string;
    token: string;
    rawVaultKey: Uint8Array;
    vaultKey: Awaited<ReturnType<typeof generateKey>>['key'];
  }> {
    const { raw: rawVaultKey, key: vaultKey } = await generateKey();
    const wrapped = await seal(rawVaultKey, master.masterEncryptionKey);
    const user = await User.create({
      email: ACCOUNT_EMAIL,
      authHash: await bcrypt.hash(master.authHash, 4),
      emailVerified: true,
      encryptedVaultKey: wrapped.encrypted,
      vaultKeyIv: wrapped.iv,
      vaultKeyTag: wrapped.tag,
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
    });
    return {
      userId: user._id.toString(),
      token: generateAccessToken(user._id.toString()),
      rawVaultKey,
      vaultKey,
    };
  }

  /** The `backupEncryption` block the download embeds, as the client reads it. */
  interface BackupFile {
    items: Record<string, unknown>[];
    folders: Record<string, unknown>[];
    backupEncryption: {
      encryptedBWK: string;
      bwkIv: string;
      bwkTag: string;
      bwkSalt: string;
      bwkEncryptedVaultKey: string;
      bwkVaultKeyIv: string;
      bwkVaultKeyTag: string;
    };
    metadata: { itemCount: number; folderCount: number };
  }

  /**
   * Recovers the source account's vault key from the file using only the backup
   * password, exactly as the restore screen does.
   */
  async function recoverBackupKeys(
    file: BackupFile,
    encryptionKey: Awaited<ReturnType<typeof deriveBackupEncryptionKey>>,
  ): Promise<{
    rawBwk: Uint8Array;
    sourceVaultKey: Awaited<ReturnType<typeof generateKey>>['key'];
  }> {
    // The file has to CARRY what a recovery needs, and each field is named in
    // the failure. Without this the first thing to go wrong is a `TypeError`
    // from a base64 decode of `undefined`, which describes the test rather than
    // the defect: a download that stopped embedding the BWK-wrapped vault key
    // still restores fine on the account that made it and is worthless on a new
    // one — the exact case this drill exists for.
    for (const field of [
      'encryptedBWK',
      'bwkIv',
      'bwkTag',
      'bwkSalt',
      'bwkEncryptedVaultKey',
      'bwkVaultKeyIv',
      'bwkVaultKeyTag',
    ] as const) {
      expect(file.backupEncryption[field], `the downloaded backup carries no ${field}`).toEqual(
        expect.any(String),
      );
    }

    const rawBwk = await open(
      {
        encrypted: file.backupEncryption.encryptedBWK,
        iv: file.backupEncryption.bwkIv,
        tag: file.backupEncryption.bwkTag,
      },
      encryptionKey,
    );
    const bwkKey = await crypto.subtle.importKey('raw', rawBwk, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
    const rawSourceVaultKey = await open(
      {
        encrypted: file.backupEncryption.bwkEncryptedVaultKey,
        iv: file.backupEncryption.bwkVaultKeyIv,
        tag: file.backupEncryption.bwkVaultKeyTag,
      },
      bwkKey,
    );
    return {
      rawBwk,
      sourceVaultKey: await crypto.subtle.importKey(
        'raw',
        rawSourceVaultKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt'],
      ),
    };
  }

  beforeEach(async () => {
    source = await seedSourceAccount();
  });

  it('restores a downloaded backup into an empty account on a second mongod, byte for byte', async () => {
    const signedFile = await downloadAndSign(source);
    const { body, integrity } = splitSignedBackup(signedFile);

    // The file the user keeps is signed, and the signature verifies before
    // anything else happens.
    expect(integrity).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifyBackup(body, integrity!, source.rawBwk)).toBe(true);

    const file = JSON.parse(body) as BackupFile;
    expect(file.metadata).toEqual({ itemCount: 3, folderCount: 1 });

    const sourceItemsBefore = await VaultItem.find({ userId: source.userId }).lean();
    expect(sourceItemsBefore).toHaveLength(3);

    const restored = await onTargetInstance(async () => {
      // The instance really is empty: no account, no row, nothing this restore
      // could be reading back instead of writing.
      expect(await User.countDocuments({})).toBe(0);
      expect(await VaultItem.countDocuments({})).toBe(0);
      expect(await Folder.countDocuments({})).toBe(0);

      const recovery = await registerRecoveryAccount();
      const { sourceVaultKey } = await recoverBackupKeys(file, bek);

      // A restore never adopts the backup's vault key: the keys differ, so every
      // row is re-sealed under the new account's key before it is sent.
      expect(Buffer.from(recovery.rawVaultKey).equals(Buffer.from(source.rawVaultKey))).toBe(false);

      const items = [];
      for (const row of file.items) {
        const plaintext = await open(sealedOf(row, 'data'), sourceVaultKey);
        const name = await openText(sealedOf(row, 'name'), sourceVaultKey);
        const resealedData = await seal(plaintext, recovery.vaultKey);
        const resealedName = await sealText(name, recovery.vaultKey);
        items.push({
          ...row,
          encryptedData: resealedData.encrypted,
          dataIv: resealedData.iv,
          dataTag: resealedData.tag,
          encryptedName: resealedName.encrypted,
          nameIv: resealedName.iv,
          nameTag: resealedName.tag,
          searchHash: await searchHashOf(name, recovery.rawVaultKey),
        });
      }
      const folders = [];
      for (const row of file.folders) {
        const name = await openText(sealedOf(row, 'name'), sourceVaultKey);
        const resealed = await sealText(name, recovery.vaultKey);
        folders.push({
          ...row,
          encryptedName: resealed.encrypted,
          nameIv: resealed.iv,
          nameTag: resealed.tag,
          searchHash: await searchHashOf(name, recovery.rawVaultKey),
        });
      }

      const res = await post('/api/v1/backup/restore', recovery.token, {
        conflictStrategy: 'skip',
        data: JSON.stringify({ items, folders }),
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data).toMatchObject({
        itemsRestored: 3,
        itemsSkipped: 0,
        foldersRestored: 1,
        foldersSkipped: 0,
      });

      // Read back through the API, then decrypt with the NEW account's key.
      const list = await request(app)
        .get('/api/v1/vault/items?limit=50')
        .set('Authorization', authHeader(recovery.token));
      expect(list.status).toBe(200);
      const rows = list.body.data as Record<string, unknown>[];
      expect(rows).toHaveLength(3);

      const opened: { name: string; plaintext: string }[] = [];
      for (const row of rows) {
        opened.push({
          name: await openText(sealedOf(row, 'name'), recovery.vaultKey),
          plaintext: await openText(sealedOf(row, 'data'), recovery.vaultKey),
        });
      }
      // PAIRED, not two sorted lists: a restore that kept every name and every
      // payload but attached them to each other's rows would satisfy two
      // independent comparisons and hand the user someone else's password under
      // this item's name.
      const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
      expect([...opened].sort(byName)).toEqual(
        ITEM_NAMES.map((name, index) => ({ name, plaintext: ITEM_PLAINTEXTS[index]! })).sort(
          byName,
        ),
      );

      // The rows are NEW documents on this instance — fresh ids, stamped with
      // the provenance of the backup row they came from, and that stamp is never
      // serialized to a client.
      const stored = await VaultItem.find({ userId: recovery.userId }).lean();
      for (const row of stored) {
        expect(source.itemIds).not.toContain(String(row._id));
        expect(source.itemIds).toContain(row.sourceRefId);
      }
      for (const row of rows) expect(row).not.toHaveProperty('sourceRefId');

      // The filed item is still filed, under the folder's NEW id.
      const restoredFolders = await Folder.find({ userId: recovery.userId }).lean();
      expect(restoredFolders).toHaveLength(1);
      const restoredFolderId = String(restoredFolders[0]!._id);
      expect(restoredFolderId).not.toBe(source.folderId);
      const filed = stored.filter((row) => row.folderId !== undefined);
      expect(filed).toHaveLength(1);
      expect(String(filed[0]!.folderId)).toBe(restoredFolderId);
      // WHICH item is filed, not merely that one is — and its metadata came
      // back too. Only the first item was filed, favourited and given a tag.
      expect(await openText(sealedOf(filed[0]!, 'data'), recovery.vaultKey)).toBe(
        ITEM_PLAINTEXTS[0],
      );
      expect(filed[0]!.favorite).toBe(true);
      expect(filed[0]!.tags).toEqual(['drill']);
      expect(await openText(sealedOf(restoredFolders[0]!, 'name'), recovery.vaultKey)).toBe(
        FOLDER_NAME,
      );

      // The account's own vault key is untouched: a restore adds rows, it never
      // replaces the key the account authenticates and decrypts with.
      const account = await User.findById(recovery.userId).lean();
      const accountVaultKey = await open(
        {
          encrypted: account!.encryptedVaultKey,
          iv: account!.vaultKeyIv,
          tag: account!.vaultKeyTag,
        },
        master.masterEncryptionKey,
      );
      expect(Buffer.from(accountVaultKey).equals(Buffer.from(recovery.rawVaultKey))).toBe(true);

      return stored.length;
    });

    expect(restored).toBe(3);

    // Back on the SOURCE instance: still there, still the original ciphertext.
    // A restore that had somehow written here would show up as a fourth row or a
    // changed blob.
    const sourceItemsAfter = await VaultItem.find({ userId: source.userId }).lean();
    expect(sourceItemsAfter).toHaveLength(3);
    expect(sourceItemsAfter.map((row) => row.encryptedData).sort()).toEqual(
      sourceItemsBefore.map((row) => row.encryptedData).sort(),
    );
    for (const row of sourceItemsAfter) {
      expect(ITEM_PLAINTEXTS).toContain(await openText(sealedOf(row, 'data'), source.vaultKey));
    }
  }, 120_000);

  it('emits a document that survives the signing round trip, so a signed backup still verifies', async () => {
    // THE PRODUCTION PROPERTY THIS TEST EXISTS FOR, and the reason it is not a
    // test of the signature algorithm.
    //
    // The browser signs a backup by parsing the downloaded document, deleting
    // `integrity`, re-serializing what is left, and MACing THAT string
    // (BackupSettingsPage.handleDownload). Restore verifies the same way. So the
    // signature only ever verifies while `JSON.stringify(JSON.parse(x))` returns
    // `x` for everything this server emits — and that is a property of
    // `collectBackupData`, not of the MAC. Emit the document with an indent, in
    // a different key order, or with a value that does not survive a JSON round
    // trip, and EVERY signed backup a user holds stops verifying, on restore, on
    // the day they need it. No other test in this repository looks at those
    // bytes.
    const res = await request(app)
      .get('/api/v1/backup/download')
      .set('Authorization', authHeader(source.token));
    expect(res.status).toBe(200);

    const roundTripped = JSON.stringify(JSON.parse(res.text) as unknown);
    expect(roundTripped).toBe(res.text);

    // And end to end over the real bytes: signed as the browser signs it, split
    // as the browser splits it, verified — and refused once a single character
    // of one item's ciphertext is changed, which is the shape a corrupted
    // download or an edited file takes. The document still parses and the row
    // still looks well-formed; only the signature notices.
    //
    // HONEST SCOPE: the verifier exercised here is this suite's own
    // (`vaultFormat.verifyBackup`), because the shipped one lives in the client
    // package and cannot be imported by a server test — see the header of
    // `vaultFormat.ts`. `cryptoService.verifyBackupHmac` has its own coverage in
    // `packages/client/tests/crypto.test.ts`, and its wiring into the restore
    // screen in `packages/client/tests/coverage-backup-settings.test.tsx`. What
    // this adds is the only thing neither of those can: that the bytes THIS
    // SERVER emits are signable and verify unchanged.
    const integrity = await signBackup(res.text, source.rawBwk);
    const signed = JSON.stringify({ ...(JSON.parse(res.text) as object), integrity });
    const pristine = splitSignedBackup(signed);
    expect(pristine.body).toBe(res.text);
    expect(await verifyBackup(pristine.body, pristine.integrity!, source.rawBwk)).toBe(true);

    const parsed = JSON.parse(signed) as Record<string, unknown> & {
      items: Record<string, unknown>[];
    };
    const original = String(parsed.items[0]!.encryptedData);
    parsed.items[0]!.encryptedData = `${original.slice(0, -1)}${original.endsWith('A') ? 'B' : 'A'}`;
    const tampered = splitSignedBackup(JSON.stringify(parsed));
    expect(await verifyBackup(tampered.body, tampered.integrity!, source.rawBwk)).toBe(false);
  }, 120_000);

  it('is useless without the backup password: the wrong one opens nothing', async () => {
    const signedFile = await downloadAndSign(source);
    const { body } = splitSignedBackup(signedFile);
    const file = JSON.parse(body) as BackupFile;

    // The file carries the salt, so the derivation is reproducible — and still
    // authenticated, so the wrong password fails at the tag rather than yielding
    // wrong bytes.
    expect(file.backupEncryption.bwkSalt).toBe(bwkSalt);
    await expect(recoverBackupKeys(file, wrongBek)).rejects.toThrow();

    // The right one recovers exactly the key the source account used.
    const { rawBwk } = await recoverBackupKeys(file, bek);
    expect(Buffer.from(rawBwk).equals(Buffer.from(source.rawBwk))).toBe(true);
  }, 120_000);

  it('restores the same file twice onto the second instance without duplicating a row', async () => {
    const signedFile = await downloadAndSign(source);
    const { body } = splitSignedBackup(signedFile);
    const file = JSON.parse(body) as BackupFile;

    await onTargetInstance(async () => {
      const recovery = await registerRecoveryAccount();
      const { sourceVaultKey } = await recoverBackupKeys(file, bek);

      const items = [];
      for (const row of file.items) {
        const plaintext = await open(sealedOf(row, 'data'), sourceVaultKey);
        const resealed = await seal(plaintext, recovery.vaultKey);
        items.push({
          ...row,
          encryptedData: resealed.encrypted,
          dataIv: resealed.iv,
          dataTag: resealed.tag,
        });
      }
      const payload = { conflictStrategy: 'skip', data: JSON.stringify({ items, folders: [] }) };

      const first = await post('/api/v1/backup/restore', recovery.token, payload);
      expect(first.status).toBe(200);
      expect(first.body.data.itemsRestored).toBe(3);

      // A user who is not sure the first restore worked runs it again — which is
      // exactly when a duplicate-every-row bug is most expensive. The second run
      // matches the rows by their `sourceRefId` provenance and writes nothing.
      const second = await post('/api/v1/backup/restore', recovery.token, payload);
      expect(second.status).toBe(200);
      expect(second.body.data.itemsRestored).toBe(0);
      expect(second.body.data.itemsSkipped).toBe(3);
      expect(await VaultItem.countDocuments({ userId: recovery.userId })).toBe(3);

      // Still readable after the repeat, under the account's own key.
      const stored = await VaultItem.find({ userId: recovery.userId }).lean();
      const opened = [];
      for (const row of stored)
        opened.push(await openText(sealedOf(row, 'data'), recovery.vaultKey));
      expect(opened.sort()).toEqual([...ITEM_PLAINTEXTS].sort());
    });
  }, 120_000);
});
