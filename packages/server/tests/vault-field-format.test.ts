/**
 * The server's half of vault-field format v2.
 *
 * The server cannot open a field, so its whole part in the format is two things,
 * and this file pins both.
 *
 *  1. A CREATED row is stored under the id its fields were sealed to. The browser
 *     binds a new row's fields to `deriveRowId(userId, idNonce)` before the row
 *     exists, so the server must store it under exactly that id: every field
 *     allowlist drops the nonce, and a row that falls back to a server-minted id is
 *     one that never opens again. Pinned at all three create sites (item, folder,
 *     import insert), with the collision handling each needs.
 *  2. A payload from a client that does NOT understand v2 is refused where a v2
 *     field in it would be lost: a rotation that passes one through under the key
 *     it retires, and a restore that lands one under an id it was not bound to.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { deriveRowId } from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { isDuplicateIdError } from '../src/utils/rowIds.js';
import { carriesBoundField } from '../src/utils/vaultFieldFormat.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  sampleVaultItem,
  sampleFolder,
  seedItem,
  seedFolder,
  rawItems,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const NONCE_A = '66f1c2a000112233445566778899aabbccddeeff';
const NONCE_B = '66f1c2a0ffeeddccbbaa99887766554433221100';
const BOUND_IV = 'v2:AAAAAAAAAAAAAAAA';

async function send(
  user: TestUser,
  method: 'post' | 'put',
  path: string,
  body: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent[method](`${API}${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', cookie)
    .set('x-csrf-token', token)
    .send(body);
}

describe('A created row is stored under the id its nonce derives', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('stores an ITEM under the derived id, and a retry of the same create is a 409 that adds nothing', async () => {
    const expected = await deriveRowId(user.id, NONCE_A);

    const res = await send(user, 'post', '/vault/items', sampleVaultItem({ idNonce: NONCE_A }));

    expect(res.status).toBe(201);
    expect(res.body.data._id).toBe(expected);
    const stored = await VaultItem.findById(expected).lean();
    expect(String(stored!.userId)).toBe(user.id);
    // The nonce itself is never stored: it is an input to the id, not a field.
    expect(Object.keys(stored!)).not.toContain('idNonce');

    const retry = await send(user, 'post', '/vault/items', sampleVaultItem({ idNonce: NONCE_A }));
    expect(retry.status).toBe(409);
    expect(retry.body.message).toMatch(/already exists/);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
  });

  it('lets any OTHER create failure through as the error it is, never as a 409', async () => {
    // Only a duplicate _id means "this row already exists". Mapping every create
    // failure to that 409 would tell a client to stop retrying a write that never
    // happened; the rethrow is what keeps a real fault a 500.
    const create = vi.spyOn(VaultItem, 'create').mockRejectedValueOnce(new Error('write refused'));
    let res: request.Response;
    try {
      res = await send(user, 'post', '/vault/items', sampleVaultItem({ idNonce: NONCE_A }));
    } finally {
      create.mockRestore();
    }
    expect(res.status).toBe(500);
    expect(res.body.message ?? '').not.toMatch(/already exists/);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  });

  it('still mints the id itself for an item create that sends no nonce', async () => {
    const res = await send(user, 'post', '/vault/items', sampleVaultItem());
    expect(res.status).toBe(201);
    expect(res.body.data._id).toMatch(/^[0-9a-f]{24}$/);
    expect(res.body.data._id).not.toBe(await deriveRowId(user.id, NONCE_A));
  });

  it('refuses a malformed nonce at 400 and stores nothing', async () => {
    const res = await send(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ idNonce: NONCE_A.toUpperCase() }),
    );
    expect(res.status).toBe(400);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  });

  it('derives from the CALLER: the same nonce from two accounts is two ids, never a collision', async () => {
    const other = await createTestUser();
    const mine = await send(user, 'post', '/vault/items', sampleVaultItem({ idNonce: NONCE_A }));
    const theirs = await send(other, 'post', '/vault/items', sampleVaultItem({ idNonce: NONCE_A }));
    expect(mine.status).toBe(201);
    expect(theirs.status).toBe(201);
    expect(theirs.body.data._id).toBe(await deriveRowId(other.id, NONCE_A));
    expect(theirs.body.data._id).not.toBe(mine.body.data._id);
  });

  it('stores a FOLDER under the derived id, and tells an id collision apart from a name collision', async () => {
    const expected = await deriveRowId(user.id, NONCE_A);
    const created = await send(
      user,
      'post',
      '/folders',
      sampleFolder({ idNonce: NONCE_A, searchHash: 'a'.repeat(64) }),
    );
    expect(created.status).toBe(201);
    expect(created.body.data._id).toBe(expected);

    // Same nonce, different name: the collision is the id's, and must say so.
    const sameId = await send(
      user,
      'post',
      '/folders',
      sampleFolder({ idNonce: NONCE_A, searchHash: 'b'.repeat(64) }),
    );
    expect(sameId.status).toBe(409);
    expect(sameId.body.message).toMatch(/row with this id already exists/);

    // Fresh nonce, same name hash: the name's unique index, and its own sentence.
    const sameName = await send(
      user,
      'post',
      '/folders',
      sampleFolder({ idNonce: NONCE_B, searchHash: 'a'.repeat(64) }),
    );
    expect(sameName.status).toBe(409);
    expect(sameName.body.message).toBe('A folder with this name already exists');
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('An import inserts each row under the id its nonce derives', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  function insertRow(nonce: string | undefined, index: number): Record<string, unknown> {
    return sampleVaultItem({
      encryptedName: `imported-${String(index)}`,
      searchHash: index.toString(16).padStart(64, '0'),
      ...(nonce === undefined ? {} : { idNonce: nonce }),
    });
  }

  function importBody(inserts: Record<string, unknown>[]): Record<string, unknown> {
    return { format: 'json', operations: { inserts, updates: [] } };
  }

  it('stores every insert under its derived id and echoes the ids in insertion order', async () => {
    const res = await send(
      user,
      'post',
      '/tools/import',
      importBody([insertRow(NONCE_A, 0), insertRow(undefined, 1), insertRow(NONCE_B, 2)]),
    );

    expect(res.status).toBe(201);
    const ids = res.body.data.insertedIds as string[];
    expect(res.body.data.insertedCount).toBe(3);
    expect(ids).toHaveLength(3);
    expect(ids[0]).toBe(await deriveRowId(user.id, NONCE_A));
    expect(ids[2]).toBe(await deriveRowId(user.id, NONCE_B));
    // The one without a nonce got a server-minted id, still echoed in its place.
    expect(ids[1]).toMatch(/^[0-9a-f]{24}$/);
    for (const [index, id] of ids.entries()) {
      const stored = await VaultItem.findById(id).lean();
      expect(stored!.encryptedName).toBe(`imported-${String(index)}`);
    }
  });

  it('refuses a batch whose derived id is already stored BEFORE inserting any of it', async () => {
    // The standalone topology has no transaction, and an ordered insertMany keeps
    // every row ahead of a duplicate, so without the pre-check the first row here
    // would be stored and the batch reported as failed.
    await seedItem(user.id, { _id: await deriveRowId(user.id, NONCE_B) });

    const res = await send(
      user,
      'post',
      '/tools/import',
      importBody([insertRow(NONCE_A, 0), insertRow(NONCE_B, 1)]),
    );

    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/row with this id already exists/);
    expect(await VaultItem.exists({ _id: await deriveRowId(user.id, NONCE_A) })).toBeNull();
    expect(await rawItems(user.id)).toHaveLength(1);
  });

  it('answers 409, never 500, when an id is taken between the pre-check and the insert', async () => {
    // The pre-check runs under the import lock, but a create from another endpoint
    // can still store the same id before the insert (a hairline the handler names).
    // That lands as a duplicate-key error from the bulk insert, which must be the
    // same 409 rather than the unmapped 500 it would otherwise become. The window
    // is reproduced by letting the pre-check see nothing.
    const taken = await deriveRowId(user.id, NONCE_A);
    await seedItem(user.id, { _id: taken, encryptedName: 'already-here' });
    const exists = vi.spyOn(VaultItem, 'exists').mockResolvedValue(null);

    let res: request.Response;
    try {
      res = await send(user, 'post', '/tools/import', importBody([insertRow(NONCE_A, 0)]));
    } finally {
      exists.mockRestore();
    }

    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/row with this id already exists/);
    const rows = await rawItems(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.encryptedName).toBe('already-here');
  });

  it('lets any OTHER bulk-insert failure through as a 500, never as the row-exists 409', async () => {
    const insert = vi
      .spyOn(VaultItem, 'insertMany')
      .mockRejectedValueOnce(new Error('bulk write refused'));
    let res: request.Response;
    try {
      res = await send(user, 'post', '/tools/import', importBody([insertRow(NONCE_A, 0)]));
    } finally {
      insert.mockRestore();
    }
    expect(res.status).toBe(500);
    expect(res.body.message ?? '').not.toMatch(/row with this id already exists/);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('refuses one batch naming a nonce twice at 400', async () => {
    const res = await send(
      user,
      'post',
      '/tools/import',
      importBody([insertRow(NONCE_A, 0), insertRow(NONCE_A, 1)]),
    );
    expect(res.status).toBe(400);
    expect(await rawItems(user.id)).toHaveLength(0);
  });
});

describe('A duplicate id is told apart from any other unique-index violation', () => {
  it('reads the violated index off a single write and off a bulk write alike', () => {
    expect(isDuplicateIdError({ code: 11000, keyPattern: { _id: 1 } })).toBe(true);
    expect(
      isDuplicateIdError({ code: 11000, writeErrors: [{ err: { keyPattern: { _id: 1 } } }] }),
    ).toBe(true);
    expect(isDuplicateIdError({ code: 11000, writeErrors: [{ keyPattern: { _id: 1 } }] })).toBe(
      true,
    );
    // Another unique index, another code, a compound pattern, garbage.
    expect(isDuplicateIdError({ code: 11000, keyPattern: { userId: 1, searchHash: 1 } })).toBe(
      false,
    );
    expect(isDuplicateIdError({ code: 11000, keyPattern: { _id: 1, userId: 1 } })).toBe(false);
    expect(isDuplicateIdError({ code: 121, keyPattern: { _id: 1 } })).toBe(false);
    // A bulk write names the index only in each error's server message.
    expect(
      isDuplicateIdError({
        code: 11000,
        writeErrors: [
          {
            err: {
              errmsg: 'E11000 duplicate key error collection: t.v index: _id_ dup key: { _id: 1 }',
            },
          },
        ],
      }),
    ).toBe(true);
    expect(
      isDuplicateIdError({
        code: 11000,
        writeErrors: [
          {
            err: {
              errmsg:
                'E11000 duplicate key error collection: t.f index: userId_1_searchHash_1 dup key: {}',
            },
          },
        ],
      }),
    ).toBe(false);
    expect(isDuplicateIdError({ code: 11000, writeErrors: [null, 'x', { err: {} }] })).toBe(false);
    expect(isDuplicateIdError({ code: 11000 })).toBe(false);
    expect(isDuplicateIdError(null)).toBe(false);
    expect(isDuplicateIdError('E11000')).toBe(false);
  });

  it('matches what the real driver raises for a duplicate _id', async () => {
    const user = await createTestUser();
    const item = await seedItem(user.id);
    const takenId = String(item._id);
    const caught = await VaultItem.create({ ...sampleVaultItem(), _id: takenId, userId: user.id })
      .then(() => null)
      .catch((error: unknown) => error);
    expect(isDuplicateIdError(caught)).toBe(true);
    const bulk = await VaultItem.insertMany([
      { ...sampleVaultItem(), _id: takenId, userId: user.id },
    ])
      .then(() => null)
      .catch((error: unknown) => error);
    expect(isDuplicateIdError(bulk)).toBe(true);
  });
});

describe('A payload a v2-unaware client could only have passed through is refused', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  const NEW_KEY = {
    newEncryptedVaultKey: 'rotated-vault-key',
    newVaultKeyIv: 'rotated-vault-key-iv',
    newVaultKeyTag: 'rotated-vault-key-tag',
  };

  function rotatedItem(
    id: string,
    overrides: Record<string, unknown> = {},
  ): Record<string, unknown> {
    return {
      id,
      encryptedName: `rotated-${id}`,
      nameIv: 'rotated-iv',
      nameTag: 'rotated-tag',
      encryptedData: 'rotated-data',
      dataIv: 'rotated-iv',
      dataTag: 'rotated-tag',
      ...overrides,
    };
  }

  it.each([
    ['an item name', { nameIv: BOUND_IV }, undefined],
    ['an item’s data', { dataIv: BOUND_IV }, undefined],
    [
      'a password-history entry',
      {
        passwordHistory: [
          { encryptedPassword: 'p', iv: BOUND_IV, tag: 't', changedAt: '2026-01-01T00:00:00.000Z' },
        ],
      },
      undefined,
    ],
    ['a folder name', {}, BOUND_IV],
  ])(
    'refuses a rotation carrying a bound %s from a client that does not state format 2, and changes nothing',
    async (_label, itemOverrides, folderIv) => {
      const item = await seedItem(user.id);
      const folder = await seedFolder(user.id);

      const res = await send(user, 'post', '/vault/items/bulk-reencrypt', {
        authHash: user.rawPassword,
        ...NEW_KEY,
        items: [rotatedItem(String(item._id), itemOverrides)],
        folders: [
          {
            id: String(folder._id),
            encryptedName: 'rotated-folder',
            nameIv: folderIv ?? 'rotated-iv',
            nameTag: 't',
          },
        ],
      });

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/^Reload the app, then try again/);
      // And WHY, in full: the client shows a 4xx verbatim, so the reason is part
      // of the refusal rather than decoration around it.
      expect(res.body.message).toMatch(
        /newer format than this page understands, and rotating from it would lose them\.$/,
      );
      expect(String(res.body.message).length).toBeLessThanOrEqual(200);
      const after = await User.findById(user.id).lean();
      expect(after!.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect(after!.vaultKeyVersion).toBe(0);
      expect(after!.rotationInProgress).toBe(false);
      expect(after!.pendingEncryptedVaultKey).toBeUndefined();
      expect((await VaultItem.findById(item._id).lean())!.encryptedName).toBe(item.encryptedName);
    },
  );

  it('accepts the same bound payload from a client that states format 2', async () => {
    const item = await seedItem(user.id);
    const res = await send(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      ...NEW_KEY,
      vaultFieldFormat: 2,
      items: [rotatedItem(String(item._id), { nameIv: BOUND_IV, dataIv: BOUND_IV })],
    });
    expect(res.status).toBe(200);
    expect((await VaultItem.findById(item._id).lean())!.nameIv).toBe(BOUND_IV);
  });

  it('still accepts an unbound rotation from a client that states nothing (an older client loses nothing)', async () => {
    const item = await seedItem(user.id);
    const res = await send(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      ...NEW_KEY,
      items: [rotatedItem(String(item._id))],
    });
    expect(res.status).toBe(200);
    expect((await User.findById(user.id).lean())!.encryptedVaultKey).toBe('rotated-vault-key');
  });

  it('refuses a restore carrying a bound field, and restores nothing', async () => {
    const data = JSON.stringify({
      items: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa', ...sampleVaultItem({ dataIv: BOUND_IV }) }],
      folders: [],
    });
    const res = await send(user, 'post', '/backup/restore', { conflictStrategy: 'skip', data });
    expect(res.status).toBe(409);
    expect(res.body.message).toMatch(/^Reload the app, then restore again/);
    expect(res.body.message).toMatch(
      /newer format than this page understands, and restoring them from it would lose them\.$/,
    );
    expect(String(res.body.message).length).toBeLessThanOrEqual(200);
    expect(await rawItems(user.id)).toHaveLength(0);

    // The same backup without the marker restores as it always did.
    const plain = JSON.stringify({
      items: [{ _id: 'aaaaaaaaaaaaaaaaaaaaaaaa', ...sampleVaultItem() }],
      folders: [],
    });
    const ok = await send(user, 'post', '/backup/restore', {
      conflictStrategy: 'skip',
      data: plain,
    });
    expect(ok.status).toBe(200);
    expect(await rawItems(user.id)).toHaveLength(1);
  });

  it('reads nothing but the row fields a v2 marker can sit on, and never throws on a malformed file', () => {
    expect(carriesBoundField(undefined, 'x')).toBe(false);
    expect(
      carriesBoundField([undefined, null, 7, 'v2:', { nameIv: 'plain' }], [undefined, null]),
    ).toBe(false);
    expect(carriesBoundField([{ passwordHistory: 'v2:' }], [])).toBe(false);
    expect(carriesBoundField([{ passwordHistory: [undefined, null, { iv: 3 }] }], [])).toBe(false);
    // The marker must LEAD the IV: base64 cannot contain it anywhere, but only a
    // leading one is the format's.
    expect(carriesBoundField([{ nameIv: 'AAAAv2:' }], [])).toBe(false);
    // A field that is not an IV is not read, whatever it holds.
    expect(carriesBoundField([{ encryptedName: BOUND_IV, nameTag: BOUND_IV }], [])).toBe(false);
    expect(carriesBoundField([{ passwordHistory: [{ iv: BOUND_IV }] }], [])).toBe(true);
    expect(carriesBoundField([], [{ nameIv: BOUND_IV }])).toBe(true);
  });
});
