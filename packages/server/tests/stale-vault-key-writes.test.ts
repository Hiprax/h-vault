/**
 * The four single-row ciphertext writes must refuse a body sealed under a
 * superseded vault key, and the metadata-only handlers beside them must not.
 *
 * ## The defect this file closes
 *
 * `assertVaultNotRotating` fences a rotation that is IN PROGRESS. It cannot see
 * one that has already COMMITTED, because the flag is lowered by then — and a
 * second session holding the superseded key is at its most dangerous precisely
 * then: it can still decrypt everything it loaded, it can still encrypt, and
 * nothing tells it the key moved. Every row it writes after that point is sealed
 * under a key the rotation has already replaced, so the row is stranded the
 * moment it lands: the rotation enumerated the account BEFORE it existed, and no
 * later rotation can decrypt it either. The row reads back as an undecodable
 * placeholder for ever.
 *
 * No race is required. The rotation may have finished days earlier; all it takes
 * is a second tab left open.
 *
 * `User.vaultKeyVersion` is `$inc`ed exactly once per completed rotation, so the
 * generation the client names in its request body is what closes the half of the
 * window the fence cannot see.
 *
 * ## Why the datastore is real, and why the rotation goes over HTTP
 *
 * The number the guard compares against is produced by the product's own `$inc`
 * inside `bulkReEncrypt`, not by a hand-written `$set`, so every rotation here is
 * driven through `POST /vault/items/bulk-reencrypt` against a real `mongod`. A
 * rotation must also NAME every row the account holds
 * (`assertRotationCoversEveryRow`), so the helper enumerates the account first;
 * a rotation that quietly stopped covering rows would otherwise make the whole
 * file vacuous, which is why its effect is asserted rather than assumed.
 *
 * ## The carve-out is pinned as a NEGATIVE, deliberately
 *
 * `controllerHelpers.ts` records which handlers are fenced and which are not:
 * `bulkMove`, `restoreItem`, the deletes, `reorderFolder` and `deleteFolder`
 * persist no vault-key ciphertext, so blocking them would be a pure availability
 * loss. Those are exercised here on a ROTATED account with no version at all and
 * must still succeed — otherwise a later "consistency" pass could fence them and
 * nothing would object.
 *
 * The converse is pinned too, and it is the case most likely to be "fixed" by
 * mistake: a metadata-only body sent to `PUT /vault/items/:id` IS refused,
 * because the guard belongs to the ENDPOINT and not to the shape of the body.
 * `updateItemMeta` on the client routes through that endpoint, so it carries the
 * generation like every other caller. Deciding it from the body instead would
 * put a security control behind a predicate the caller chooses.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { vaultKeyVersionOf, vaultImportLockName } from '../src/utils/controllerHelpers.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  sampleVaultItem,
  sampleFolder,
  seedItem,
  seedFolder,
  type TestUser,
} from './helpers.js';

/** What a rotation leaves stored as the account's wrapped vault key. */
const ROTATED_VAULT_KEY = 'wrapper-minted-by-the-rotation';

/** Ciphertext a rotation rewrites every row with, so a stray write is visible. */
const ROTATED_CIPHERTEXT = 'ciphertext-under-the-ROTATED-key';

/** Ciphertext a stale session would send: sealed under the key it still holds. */
const STALE_CIPHERTEXT = 'ciphertext-under-the-SUPERSEDED-key';

let user: TestUser;

beforeEach(async () => {
  user = await createTestUser();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** One authenticated, CSRF-bearing request. */
async function send(
  method: 'post' | 'put' | 'delete',
  path: string,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const req =
    method === 'post' ? agent.post(path) : method === 'put' ? agent.put(path) : agent.delete(path);
  const withHeaders = req
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
  return body === undefined ? withHeaders : withHeaders.send(body);
}

/**
 * Rotates the account's vault key through the real endpoint, covering every row
 * it currently holds, and returns the generation it landed on.
 */
async function rotateVaultKey(): Promise<number> {
  const items = await VaultItem.find({ userId: user.id }).lean();
  const folders = await Folder.find({ userId: user.id }).lean();

  const res = await send('post', '/api/v1/vault/items/bulk-reencrypt', {
    authHash: user.rawPassword,
    items: items.map((item) => ({
      id: String(item._id),
      encryptedName: ROTATED_CIPHERTEXT,
      nameIv: 'rotated-name-iv',
      nameTag: 'rotated-name-tag',
      encryptedData: ROTATED_CIPHERTEXT,
      dataIv: 'rotated-data-iv',
      dataTag: 'rotated-data-tag',
    })),
    folders: folders.map((folder) => ({
      id: String(folder._id),
      encryptedName: ROTATED_CIPHERTEXT,
      nameIv: 'rotated-name-iv',
      nameTag: 'rotated-name-tag',
    })),
    documents: [],
    newEncryptedVaultKey: ROTATED_VAULT_KEY,
    newVaultKeyIv: 'rotated-vault-key-iv',
    newVaultKeyTag: 'rotated-vault-key-tag',
  });
  expect(res.status).toBe(200);

  // The rotation is the fixture, so its effect is asserted rather than assumed.
  const rotated = await User.findById(user.id).lean();
  expect(rotated?.encryptedVaultKey).toBe(ROTATED_VAULT_KEY);
  expect(rotated?.rotationInProgress).toBe(false);
  return vaultKeyVersionOf(rotated);
}

/** The whole account, as a refusal must leave it. */
interface VaultSnapshot {
  items: Record<string, unknown>[];
  folders: Record<string, unknown>[];
  vaultKeyVersion: number;
  audits: number;
}

async function snapshot(): Promise<VaultSnapshot> {
  return {
    items: (await VaultItem.find({ userId: user.id }).sort({ _id: 1 }).lean()) as unknown as Record<
      string,
      unknown
    >[],
    folders: (await Folder.find({ userId: user.id }).sort({ _id: 1 }).lean()) as unknown as Record<
      string,
      unknown
    >[],
    vaultKeyVersion: vaultKeyVersionOf(await User.findById(user.id).lean()),
    audits: await AuditLog.countDocuments({
      userId: user.id,
      action: { $in: ['item_create', 'item_update', 'folder_create', 'folder_update'] },
    }),
  };
}

/**
 * THE NEGATIVE, in one place: the refusal wrote nothing at all.
 *
 * Compared against a snapshot the caller took BEFORE the request rather than
 * against literals, so every stored field — including the ciphertext the stale
 * session tried to plant — is covered without restating the fixture.
 */
async function expectNothingWritten(before: VaultSnapshot): Promise<void> {
  expect(await snapshot()).toEqual(before);
}

/** The recoverable 409 every refusal must answer with. */
function expectRecoverableConflict(
  res: request.Response,
  currentVersion: number,
  message: RegExp,
): void {
  expect(res.status).toBe(409);
  expect(res.body.success).toBe(false);
  // The NUMBER is what makes the refusal recoverable: with it the client can
  // re-read its key, re-seal and retry instead of guessing.
  expect(res.body.data).toEqual({ vaultKeyVersion: currentVersion });
  expect(res.body.message).toMatch(message);
}

// ── The four guarded writes ──────────────────────────────────────────────

describe('POST /vault/items refuses ciphertext sealed under a superseded vault key', () => {
  it('refuses a generation BEHIND the account and creates nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedData: STALE_CIPHERTEXT, vaultKeyVersion: current - 1 }),
    );

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedData: STALE_CIPHERTEXT }),
    );

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
  });

  it('refuses a generation the account has never reached', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedData: STALE_CIPHERTEXT, vaultKeyVersion: current + 5 }),
    );

    expectRecoverableConflict(res, current, /never had/i);
    await expectNothingWritten(before);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await send(
      'post',
      '/api/v1/vault/items',
      sampleVaultItem({ encryptedData: 'fresh-ciphertext', vaultKeyVersion: current }),
    );

    expect(res.status).toBe(201);
    const stored = await VaultItem.findById(res.body.data._id).lean();
    expect(stored?.encryptedData).toBe('fresh-ciphertext');
    // The generation is a guard, never a stored field.
    expect(stored).not.toHaveProperty('vaultKeyVersion');
  });

  it('accepts a never-rotated account that names no generation', async () => {
    expect(vaultKeyVersionOf(await User.findById(user.id).lean())).toBe(0);

    const res = await send('post', '/api/v1/vault/items', sampleVaultItem());

    expect(res.status).toBe(201);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('PUT /vault/items/:id refuses ciphertext sealed under a superseded vault key', () => {
  let itemId: string;

  beforeEach(async () => {
    itemId = String((await seedItem(user.id))._id);
  });

  it('refuses a generation BEHIND the account and changes nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('put', `/api/v1/vault/items/${itemId}`, {
      encryptedData: STALE_CIPHERTEXT,
      dataIv: 'stale-iv',
      dataTag: 'stale-tag',
      vaultKeyVersion: current - 1,
    });

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
    // Named explicitly as well: this is the byte the rotation just wrote, and
    // overwriting it is the whole defect.
    expect((await VaultItem.findById(itemId).lean())?.encryptedData).toBe(ROTATED_CIPHERTEXT);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('put', `/api/v1/vault/items/${itemId}`, {
      encryptedData: STALE_CIPHERTEXT,
      dataIv: 'stale-iv',
      dataTag: 'stale-tag',
    });

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
  });

  it('refuses a METADATA-ONLY body too: the guard belongs to the endpoint', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('put', `/api/v1/vault/items/${itemId}`, { favorite: true });

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
  });

  it('accepts a metadata-only body that names the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await send('put', `/api/v1/vault/items/${itemId}`, {
      favorite: true,
      vaultKeyVersion: current,
    });

    expect(res.status).toBe(200);
    const stored = await VaultItem.findById(itemId).lean();
    expect(stored?.favorite).toBe(true);
    // Metadata only: the rotation's ciphertext is still there byte for byte.
    expect(stored?.encryptedData).toBe(ROTATED_CIPHERTEXT);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await send('put', `/api/v1/vault/items/${itemId}`, {
      encryptedData: 'fresh-ciphertext',
      dataIv: 'fresh-iv',
      dataTag: 'fresh-tag',
      vaultKeyVersion: current,
    });

    expect(res.status).toBe(200);
    expect((await VaultItem.findById(itemId).lean())?.encryptedData).toBe('fresh-ciphertext');
  });

  it('accepts a never-rotated account that names no generation', async () => {
    const res = await send('put', `/api/v1/vault/items/${itemId}`, { favorite: true });

    expect(res.status).toBe(200);
    expect((await VaultItem.findById(itemId).lean())?.favorite).toBe(true);
  });
});

describe('POST /folders refuses a name sealed under a superseded vault key', () => {
  it('refuses a generation BEHIND the account and creates nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send(
      'post',
      '/api/v1/folders',
      sampleFolder({ encryptedName: STALE_CIPHERTEXT, vaultKeyVersion: current - 1 }),
    );

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send(
      'post',
      '/api/v1/folders',
      sampleFolder({ encryptedName: STALE_CIPHERTEXT }),
    );

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await send(
      'post',
      '/api/v1/folders',
      sampleFolder({ encryptedName: 'fresh-ciphertext', vaultKeyVersion: current }),
    );

    expect(res.status).toBe(201);
    expect((await Folder.findById(res.body.data._id).lean())?.encryptedName).toBe(
      'fresh-ciphertext',
    );
  });

  it('accepts a never-rotated account that names no generation', async () => {
    const res = await send('post', '/api/v1/folders', sampleFolder());

    expect(res.status).toBe(201);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('PUT /folders/:id refuses a name sealed under a superseded vault key', () => {
  let folderId: string;

  beforeEach(async () => {
    folderId = String((await seedFolder(user.id))._id);
  });

  it('refuses a generation BEHIND the account and changes nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('put', `/api/v1/folders/${folderId}`, {
      encryptedName: STALE_CIPHERTEXT,
      nameIv: 'stale-iv',
      nameTag: 'stale-tag',
      vaultKeyVersion: current - 1,
    });

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
    expect((await Folder.findById(folderId).lean())?.encryptedName).toBe(ROTATED_CIPHERTEXT);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('put', `/api/v1/folders/${folderId}`, {
      encryptedName: STALE_CIPHERTEXT,
      nameIv: 'stale-iv',
      nameTag: 'stale-tag',
    });

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await send('put', `/api/v1/folders/${folderId}`, {
      encryptedName: 'fresh-ciphertext',
      nameIv: 'fresh-iv',
      nameTag: 'fresh-tag',
      vaultKeyVersion: current,
    });

    expect(res.status).toBe(200);
    expect((await Folder.findById(folderId).lean())?.encryptedName).toBe('fresh-ciphertext');
  });

  it('accepts a never-rotated account that names no generation', async () => {
    const res = await send('put', `/api/v1/folders/${folderId}`, { color: '#abcdef' });

    expect(res.status).toBe(200);
    expect((await Folder.findById(folderId).lean())?.color).toBe('#abcdef');
  });
});

// ── The two bulk writers ─────────────────────────────────────────────────

/**
 * `POST /tools/import` and `POST /backup/restore` take the same guard, but it
 * sits INSIDE the per-user span that ends at the first write rather than at the
 * top of the handler. The span is the point: between a top-of-handler check and
 * `insertMany` lie the field-length checks, the folder lookups, the
 * update-target lookups, `acquireJobLock` and the cap count, which is hundreds
 * of milliseconds in which a rotation can commit.
 *
 * The placement itself is pinned where the import's other ordering facts live,
 * in `import-operations.test.ts`; what this block pins is the contract every
 * guarded write shares.
 */
describe('POST /tools/import refuses operations sealed under a superseded vault key', () => {
  const INSERT_ROW = {
    ...sampleVaultItem({ encryptedName: STALE_CIPHERTEXT, encryptedData: STALE_CIPHERTEXT }),
    searchHash: 'a'.repeat(64),
  };

  async function importOperations(extra: Record<string, unknown> = {}): Promise<request.Response> {
    return send('post', '/api/v1/tools/import', {
      format: 'json',
      operations: { inserts: [INSERT_ROW] },
      ...extra,
    });
  }

  /** How many import audit rows this account has. */
  async function importAudits(): Promise<number> {
    return AuditLog.countDocuments({ userId: user.id, action: 'import' });
  }

  it('refuses a generation BEHIND the account and inserts nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await importOperations({ vaultKeyVersion: current - 1 });

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
    expect(await importAudits()).toBe(0);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await importOperations();

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
    expect(await importAudits()).toBe(0);
  });

  it('releases the per-user import lock when it refuses', async () => {
    const current = await rotateVaultKey();

    expectRecoverableConflict(
      await importOperations({ vaultKeyVersion: current - 1 }),
      current,
      /rotated elsewhere/i,
    );

    // The guard throws from inside the span the lock protects, so the release in
    // `finally` is what stops one stale batch wedging every later import for the
    // lock's whole TTL.
    expect(await JobLock.countDocuments({ jobName: vaultImportLockName(user.id) })).toBe(0);

    // Proved by running one: the next import succeeds immediately.
    const retried = await importOperations({ vaultKeyVersion: current });
    expect(retried.status).toBe(201);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await importOperations({ vaultKeyVersion: current });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });
    expect(await importAudits()).toBe(1);
  });

  it('accepts a never-rotated account that names no generation', async () => {
    const res = await importOperations();

    expect(res.status).toBe(201);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('POST /backup/restore refuses rows sealed under a superseded vault key', () => {
  async function restore(extra: Record<string, unknown> = {}): Promise<request.Response> {
    return send('post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify({
        items: [sampleVaultItem({ encryptedName: STALE_CIPHERTEXT })],
        folders: [sampleFolder({ encryptedName: STALE_CIPHERTEXT })],
      }),
      ...extra,
    });
  }

  /** How many restore audit rows this account has. */
  async function restoreAudits(): Promise<number> {
    return AuditLog.countDocuments({ userId: user.id, action: 'backup_restored' });
  }

  it('refuses a generation BEHIND the account and restores nothing', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await restore({ vaultKeyVersion: current - 1 });

    expectRecoverableConflict(res, current, /rotated elsewhere/i);
    await expectNothingWritten(before);
    expect(await restoreAudits()).toBe(0);
  });

  it('refuses a request naming NO generation once the account has rotated', async () => {
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await restore();

    expectRecoverableConflict(res, current, /did not say which vault key/i);
    await expectNothingWritten(before);
    expect(await restoreAudits()).toBe(0);
  });

  it('lets the pre-guard body checks answer first, with 400 and not 409', async () => {
    // The placement, not the contract. `restoreBackup` has no job lock, so what
    // makes the guard's span short is where the line sits: after the multi-
    // megabyte `JSON.parse`, the entry-count cap and the four net-new collection
    // scans, and immediately before the first write. Hoisted up beside
    // `assertVaultNotRotating` at the top of the handler it would answer 409
    // here, and the contract cases above would not notice.
    const current = await rotateVaultKey();
    const before = await snapshot();

    const res = await send('post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: 'this is not JSON',
      vaultKeyVersion: current - 1,
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/malformed JSON/i);
    expect(res.body.data).toBeUndefined();
    await expectNothingWritten(before);
  });

  it('accepts the current generation', async () => {
    const current = await rotateVaultKey();

    const res = await restore({ vaultKeyVersion: current });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(await restoreAudits()).toBe(1);
  });

  it('accepts a never-rotated account that names no generation', async () => {
    const res = await restore();

    expect(res.status).toBe(200);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
  });
});

/**
 * `POST /backup/setup` and `PUT /backup/change-password` both store the account's
 * VAULT KEY wrapped under the backup key, from a client-supplied body.
 *
 * ## Why they belong here and not with the backup suite
 *
 * `settings.backup.bwkEncryptedVaultKey` is the same secret `encryptedVaultKey`
 * is, sealed differently: it is what a CROSS-ACCOUNT restore unwraps to read the
 * backup's rows. A session holding a superseded vault key that configures or
 * re-keys backup encryption writes the OLD key there, silently replacing the
 * re-wrap the rotation itself performed. Nothing breaks at the time — the live
 * vault is untouched and a same-account restore goes through the MEK path
 * instead — and the failure surfaces only when somebody restores a later backup
 * into another account and every single row fails to decrypt. That is as far from
 * the mistake as a failure can get, which is why the refusal is worth having.
 *
 * ## The `$unset` branch is the case to be careful about
 *
 * A body that carries no wrapper triple CLEARS the stored one, and that is how a
 * client legitimately drops a wrapper a rotation made stale. It is a guarded
 * write like any other on these endpoints — the guard belongs to the address, not
 * to which fields the body happens to carry — so it too must name the current
 * generation, and it must still clear the wrapper when it does.
 */
describe('the two backup writes that also seal the vault key', () => {
  const BWK_WRAPPER = {
    bwkEncryptedVaultKey: 'vault-key-wrapped-under-the-BACKUP-key',
    bwkVaultKeyIv: 'bwk-vault-key-iv',
    bwkVaultKeyTag: 'bwk-vault-key-tag',
  };

  const SETUP_BODY = {
    authHash: 'placeholder-replaced-per-request',
    encryptedBWK: 'encrypted-bwk',
    bwkIv: 'bwk-iv',
    bwkTag: 'bwk-tag',
    bwkSalt: 'bwk-salt',
  };

  const CHANGE_BODY = {
    password: 'placeholder-replaced-per-request',
    newEncryptedBWK: 'new-encrypted-bwk',
    newBwkIv: 'new-bwk-iv',
    newBwkTag: 'new-bwk-tag',
    newBwkSalt: 'new-bwk-salt',
  };

  /** The wrapper the account currently stores, or `undefined` when it stores none. */
  async function storedWrapper(): Promise<string | undefined> {
    const row = await User.findById(user.id).lean();
    return row?.settings.backup.bwkEncryptedVaultKey;
  }

  /** Puts a wrapper on the account without going through a guarded endpoint. */
  async function seedWrapper(value: string): Promise<void> {
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          'settings.backup.isConfigured': true,
          'settings.backup.encryptedBWK': 'seeded-bwk',
          'settings.backup.bwkIv': 'seeded-iv',
          'settings.backup.bwkTag': 'seeded-tag',
          'settings.backup.bwkSalt': 'seeded-salt',
          'settings.backup.bwkEncryptedVaultKey': value,
          'settings.backup.bwkVaultKeyIv': 'seeded-vk-iv',
          'settings.backup.bwkVaultKeyTag': 'seeded-vk-tag',
        },
      },
    );
  }

  async function setupBackup(extra: Record<string, unknown> = {}): Promise<request.Response> {
    return send('post', '/api/v1/backup/setup', {
      ...SETUP_BODY,
      authHash: user.rawPassword,
      ...BWK_WRAPPER,
      ...extra,
    });
  }

  async function changeBackupPassword(
    extra: Record<string, unknown> = {},
  ): Promise<request.Response> {
    return send('put', '/api/v1/backup/change-password', {
      ...CHANGE_BODY,
      password: user.rawPassword,
      newBwkEncryptedVaultKey: BWK_WRAPPER.bwkEncryptedVaultKey,
      newBwkVaultKeyIv: BWK_WRAPPER.bwkVaultKeyIv,
      newBwkVaultKeyTag: BWK_WRAPPER.bwkVaultKeyTag,
      ...extra,
    });
  }

  describe('POST /backup/setup', () => {
    it('refuses a generation BEHIND the account and leaves the stored wrapper alone', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      const current = await rotateVaultKey();

      const res = await setupBackup({ vaultKeyVersion: current - 1 });

      expectRecoverableConflict(res, current, /rotated elsewhere/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('refuses a request naming NO generation once the account has rotated', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      const current = await rotateVaultKey();

      const res = await setupBackup();

      expectRecoverableConflict(res, current, /did not say which vault key/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('refuses while a rotation is IN PROGRESS, which the generation alone cannot see', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

      const res = await setupBackup({ vaultKeyVersion: 0 });

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.message).toMatch(/rotation is in progress/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('stores the wrapper when the request names the current generation', async () => {
      const current = await rotateVaultKey();

      const res = await setupBackup({ vaultKeyVersion: current });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await storedWrapper()).toBe(BWK_WRAPPER.bwkEncryptedVaultKey);
    });

    it('still CLEARS a stale wrapper when the body carries none and names the generation', async () => {
      await seedWrapper('wrapper-made-stale-by-the-rotation');
      const current = await rotateVaultKey();

      const res = await send('post', '/api/v1/backup/setup', {
        ...SETUP_BODY,
        authHash: user.rawPassword,
        vaultKeyVersion: current,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      // The `$unset` branch is how a client legitimately drops a wrapper a
      // rotation superseded; guarding the endpoint must not break it.
      expect(await storedWrapper()).toBeUndefined();
    });

    it('accepts a never-rotated account that names no generation', async () => {
      const res = await setupBackup();

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await storedWrapper()).toBe(BWK_WRAPPER.bwkEncryptedVaultKey);
    });

    it('still answers a wrong master password with 401, not a conflict', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      await rotateVaultKey();

      const res = await setupBackup({ authHash: 'not-the-password', vaultKeyVersion: 0 });

      // The password proof comes FIRST, exactly as on the master-password
      // change: a wrong credential must keep earning its 401 and its audit row
      // rather than being answered 409 for the duration of every rotation.
      expect(res.status, JSON.stringify(res.body)).toBe(401);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });
  });

  /**
   * The interleaving the guard's READ cannot see, on both endpoints: a rotation
   * that commits between it and the write.
   *
   * What makes these two safe against it is the FILTER on the write, not the read
   * before it, and producing the case needs a seam inside the handler's own span.
   * The wrapper write is the only one there: the spy performs the concurrent
   * increment through the ORIGINAL method — captured before the spy, so it cannot
   * re-enter — and then calls through unchanged.
   */
  function racingARotation(): void {
    // Landed on the GUARD'S OWN READ rather than beside the write, and AWAITED
    // there, because the ordering has to be a fact and not a likelihood. The
    // first draft fired the increment un-awaited from inside the write's mock and
    // relied on it winning the round trip; nothing orders two commands issued
    // that way, so a run in which the increment landed after the filtered write
    // evaluated its predicate would answer 200 and fail for a reason nobody
    // cares about. Hooking the read instead makes the sequence explicit: the
    // guard resolves generation 0, THEN the increment commits, THEN the write
    // filters on 0 and must miss.
    //
    // Fired ONCE. The refusal's own diagnosis re-reads the same projection to
    // report the current number, and a second increment there would make it say
    // 2 for a rotation that happened once.
    let raced = false;
    const realFindById = User.findById.bind(User);
    vi.spyOn(User, 'findById').mockImplementation(((id: string) => {
      const query = realFindById(id);
      const realSelect = query.select.bind(query);
      query.select = ((fields: string) => {
        const selected = realSelect(fields) as unknown as { lean: () => Promise<unknown> };
        if (fields !== 'vaultKeyVersion' || raced) return selected;
        raced = true;
        const realLean = selected.lean.bind(selected);
        return {
          lean: async () => {
            const value = await realLean();
            await User.updateOne({ _id: user.id }, { $inc: { vaultKeyVersion: 1 } });
            return value;
          },
        };
      }) as never;
      return query;
    }) as never);
  }

  it('refuses a setup whose generation moved between the guard and the write', async () => {
    await seedWrapper('wrapper-the-rotation-wrote');
    racingARotation();

    const res = await setupBackup({ vaultKeyVersion: 0 });

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
    expect(res.body.message).toMatch(/rotated elsewhere/i);
    vi.restoreAllMocks();
    expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
  });

  it('refuses a backup-password change whose generation moved between the guard and the write', async () => {
    await seedWrapper('wrapper-the-rotation-wrote');
    racingARotation();

    const res = await changeBackupPassword({ vaultKeyVersion: 0 });

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
    expect(res.body.message).toMatch(/rotated elsewhere/i);
    vi.restoreAllMocks();
    expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
  });

  describe('PUT /backup/change-password', () => {
    it('refuses a generation BEHIND the account and leaves the stored wrapper alone', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      const current = await rotateVaultKey();

      const res = await changeBackupPassword({ vaultKeyVersion: current - 1 });

      expectRecoverableConflict(res, current, /rotated elsewhere/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('refuses a request naming NO generation once the account has rotated', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      const current = await rotateVaultKey();

      const res = await changeBackupPassword();

      expectRecoverableConflict(res, current, /did not say which vault key/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('refuses while a rotation is IN PROGRESS, which the generation alone cannot see', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

      const res = await changeBackupPassword({ vaultKeyVersion: 0 });

      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body.message).toMatch(/rotation is in progress/i);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });

    it('stores the wrapper when the request names the current generation', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      const current = await rotateVaultKey();

      const res = await changeBackupPassword({ vaultKeyVersion: current });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await storedWrapper()).toBe(BWK_WRAPPER.bwkEncryptedVaultKey);
    });

    it('still CLEARS a stale wrapper when the body carries none and names the generation', async () => {
      await seedWrapper('wrapper-made-stale-by-the-rotation');
      const current = await rotateVaultKey();

      const res = await send('put', '/api/v1/backup/change-password', {
        ...CHANGE_BODY,
        password: user.rawPassword,
        vaultKeyVersion: current,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await storedWrapper()).toBeUndefined();
    });

    it('accepts a never-rotated account that names no generation', async () => {
      await seedWrapper('wrapper-from-before');

      const res = await changeBackupPassword();

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await storedWrapper()).toBe(BWK_WRAPPER.bwkEncryptedVaultKey);
    });

    it('still answers a wrong master password with 401, not a conflict', async () => {
      await seedWrapper('wrapper-the-rotation-wrote');
      await rotateVaultKey();

      const res = await changeBackupPassword({ password: 'not-the-password', vaultKeyVersion: 0 });

      expect(res.status, JSON.stringify(res.body)).toBe(401);
      expect(await storedWrapper()).toBe('wrapper-the-rotation-wrote');
    });
  });
});

// ── The carve-out: handlers that persist no vault-key ciphertext ─────────

describe('the deliberately unfenced handlers still work on a rotated account', () => {
  it('lets a rotated account move, trash, restore, reorder and delete with no generation', async () => {
    const itemId = String((await seedItem(user.id))._id);
    const folderId = String((await seedFolder(user.id))._id);
    const targetFolderId = String((await seedFolder(user.id, { sortOrder: 1 }))._id);
    await rotateVaultKey();

    // bulkMove: folder membership only.
    const moved = await send('post', '/api/v1/vault/items/bulk-move', {
      ids: [itemId],
      folderId: targetFolderId,
    });
    expect(moved.status).toBe(200);
    expect(String((await VaultItem.findById(itemId).lean())?.folderId)).toBe(targetFolderId);

    // reorderFolder: sortOrder only.
    const reordered = await send('put', `/api/v1/folders/${folderId}/sort`, { sortOrder: 7 });
    expect(reordered.status).toBe(200);
    expect((await Folder.findById(folderId).lean())?.sortOrder).toBe(7);

    // Soft delete, then restore.
    expect((await send('delete', `/api/v1/vault/items/${itemId}`)).status).toBe(200);
    expect(await VaultItem.findById(itemId).lean()).toHaveProperty('deletedAt');
    expect((await send('post', `/api/v1/vault/items/restore/${itemId}`)).status).toBe(200);
    expect((await VaultItem.findById(itemId).lean())?.deletedAt).toBeUndefined();

    // deleteFolder: removes a row, writes no ciphertext.
    expect((await send('delete', `/api/v1/folders/${folderId}`)).status).toBe(200);
    expect(await Folder.findById(folderId).lean()).toBeNull();

    // The ciphertext the rotation wrote is untouched by every one of them.
    expect((await VaultItem.findById(itemId).lean())?.encryptedData).toBe(ROTATED_CIPHERTEXT);
  });
});
