/**
 * Crash consistency: what the database holds after the process died mid-write.
 *
 * Graceful shutdown is the case that works, and it is already tested
 * (`utils/gracefulShutdown.ts` plus its suite). This file tests the cases that
 * do not: a real child process, running the real Express application against
 * the real mongod this worker is using, terminated by SIGKILL at a chosen
 * persistence-layer call. See `crashChild.ts` for why the kill is real rather
 * than simulated, and `crashProbe.ts` for the verdict every case checks before
 * it looks at the database.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS ADDS OVER THE SUITES THAT ALREADY PASS
 * ---------------------------------------------------------------------------
 *
 * `rotation-fence.test.ts` already asserts the recovery contract — a login
 * clears a stuck fence only when no live rotation lock exists — but it asserts
 * it against a state it WRITES BY HAND: `rotationInProgress: true` plus a
 * `JobLock` row it creates itself. That is the right way to test the login
 * branch, and it is silent about the premise the whole mechanism rests on: that
 * a crashed rotation actually leaves that state. If the fence write moved after
 * the item loop, or the pending key stopped being recorded, every one of those
 * tests would still pass while a real crash produced something else entirely.
 *
 * Likewise `import-operations.test.ts` asserts that a REJECTED import writes
 * nothing — through the orderly abort path, which runs `catch`, `finally` and
 * the lock release. A crash runs none of those. Its own comment says the quiet
 * part out loud: "this harness is standalone, so a mixed request would leave its
 * inserts committed", which is exactly the case it therefore never covers.
 *
 * So this file asserts the PREMISE, at the two boundaries where "all or nothing"
 * is claimed:
 *
 *   ROTATION  killed between the write-fence commit and the vault-key update,
 *             on both topologies and at both ends of that window. The fence must
 *             be up and the stored vault key must still be the OLD one in every
 *             case — that is what keeps the account recoverable — and on the
 *             transactional path, and at the near end of the sequential one,
 *             every item must still open under that key. At the FAR end of the
 *             sequential window the rows have already been rewritten, and the
 *             test says so rather than pretending otherwise: that path cannot be
 *             made atomic, which is why the pending key is recorded and why the
 *             retry has to work. Then the recovery discrimination, driven by a
 *             lock a dead process really did leave behind: while it is live the
 *             login must NOT lower the fence, and once it has expired the login
 *             must clear it and audit `rotation_recovery`.
 *
 *   IMPORT    killed before the write, inside the transaction, and after the
 *             write has committed, plus while holding the per-user job lock. No
 *             crash may leave a partial insert. Only the middle case has a
 *             transaction to be inside: the other two run on the standalone
 *             path, where the boundary is the write itself, because that
 *             topology has no transactions at all.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TWO TOPOLOGIES ARE BOTH HERE
 * ---------------------------------------------------------------------------
 *
 * `bulkReEncrypt` and `importVault` each have two implementations, chosen at
 * run time by `supportsTransactions()`: a transactional path on a replica set
 * (what the Compose stack deploys) and a sequential fallback on a standalone
 * server. They fail differently under a crash, and only one of them is
 * genuinely atomic — so testing one and claiming the other would be a guess
 * about the deployment that matters most.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import app from '../../src/app.js';
import { AuditLog } from '../../src/models/AuditLog.js';
import { JobLock } from '../../src/models/JobLock.js';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { supportsTransactions } from '../../src/utils/transactionSupport.js';
import { getActiveMongoUri, useReplicaSetConnection } from '../mongoHarness.js';
import { authHeader, generateAccessToken, getCsrf, sampleVaultItem } from '../helpers.js';
import { expectKilled, reapOrphanedTransactions, runCrashProbe } from './crashProbe.js';
import {
  generateKey,
  open,
  openText,
  seal,
  sealText,
  searchHashOf,
  type Sealed,
} from './vaultFormat.js';

/** The plaintexts sealed under the OLD vault key, and read back after a crash. */
const PLAINTEXTS = [
  JSON.stringify({ username: 'ada', password: 'first-secret' }),
  JSON.stringify({ username: 'grace', password: 'second-secret 🔐' }),
] as const;

const NAMES = ['First item', 'Second item'] as const;

/** The password the rotation endpoint re-authenticates with. */
const RAW_AUTH_HASH = 'crash-drill-auth-hash';

interface CrashAccount {
  userId: string;
  token: string;
  /** The account's live vault key, before the rotation that never finished. */
  oldKey: Awaited<ReturnType<typeof generateKey>>['key'];
  oldRawKey: Uint8Array;
  /** How the old vault key is wrapped on the user document. */
  oldWrapped: Sealed;
  /** The key the interrupted rotation was moving to. */
  newKey: Awaited<ReturnType<typeof generateKey>>['key'];
  newWrapped: Sealed;
  /** The key the account's wrapped vault key is sealed under. */
  wrappingKey: Awaited<ReturnType<typeof generateKey>>['key'];
  itemIds: string[];
}

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

let accountSequence = 0;

/**
 * An account with REAL ciphertext, and a second vault key standing by.
 *
 * No key derivation here on purpose: the rotation endpoint bcrypt-compares the
 * `authHash` it is sent against the stored one and never derives anything, so a
 * 600,000-iteration PBKDF2 per test would buy nothing but seconds. What the
 * ciphertext has to be real for is the claim that matters — that after the
 * crash the vault still OPENS under the old key.
 */
async function seedCrashAccount(): Promise<CrashAccount> {
  const { raw: oldRawKey, key: oldKey } = await generateKey();
  const { raw: newRawKey, key: newKey } = await generateKey();
  const { key: wrappingKey } = await generateKey();
  const oldWrapped = await seal(oldRawKey, wrappingKey);
  const newWrapped = await seal(newRawKey, wrappingKey);

  const user = await User.create({
    // A counter, not `Math.random()`: nothing here asserts on the address and
    // the per-test truncation makes collisions impossible anyway, but unpinned
    // randomness in a suite that pins its seed is a habit worth not forming.
    email: `crash-${String((accountSequence += 1))}@example.com`,
    authHash: await bcrypt.hash(RAW_AUTH_HASH, 4),
    emailVerified: true,
    encryptedVaultKey: oldWrapped.encrypted,
    vaultKeyIv: oldWrapped.iv,
    vaultKeyTag: oldWrapped.tag,
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
  });
  const userId = user._id.toString();

  const itemIds: string[] = [];
  for (const [index, plaintext] of PLAINTEXTS.entries()) {
    const name = NAMES[index]!;
    const data = await sealText(plaintext, oldKey);
    const sealedName = await sealText(name, oldKey);
    const item = await VaultItem.create({
      userId,
      itemType: 'login',
      encryptedData: data.encrypted,
      dataIv: data.iv,
      dataTag: data.tag,
      encryptedName: sealedName.encrypted,
      nameIv: sealedName.iv,
      nameTag: sealedName.tag,
      searchHash: await searchHashOf(name, oldRawKey),
    });
    itemIds.push(String(item._id));
  }

  return {
    userId,
    token: generateAccessToken(userId),
    oldKey,
    oldRawKey,
    oldWrapped,
    newKey,
    newWrapped,
    wrappingKey,
    itemIds,
  };
}

/** The rotation payload: every item re-sealed under the NEW key. */
async function rotationBody(account: CrashAccount): Promise<Record<string, unknown>> {
  const items = [];
  for (const [index, id] of account.itemIds.entries()) {
    const data = await sealText(PLAINTEXTS[index]!, account.newKey);
    const name = await sealText(NAMES[index]!, account.newKey);
    items.push({
      id,
      encryptedData: data.encrypted,
      dataIv: data.iv,
      dataTag: data.tag,
      encryptedName: name.encrypted,
      nameIv: name.iv,
      nameTag: name.tag,
    });
  }
  return {
    authHash: RAW_AUTH_HASH,
    items,
    folders: [],
    newEncryptedVaultKey: account.newWrapped.encrypted,
    newVaultKeyIv: account.newWrapped.iv,
    newVaultKeyTag: account.newWrapped.tag,
  };
}

/** An import payload of `count` fresh rows, sealed under the account's key. */
async function importBody(account: CrashAccount, count: number): Promise<Record<string, unknown>> {
  const inserts = [];
  for (let index = 0; index < count; index += 1) {
    const name = `Imported ${String(index)}`;
    const plaintext = JSON.stringify({ username: `user-${String(index)}`, password: 'imported' });
    const data = await sealText(plaintext, account.oldKey);
    const sealedName = await sealText(name, account.oldKey);
    inserts.push({
      itemType: 'login',
      encryptedData: data.encrypted,
      dataIv: data.iv,
      dataTag: data.tag,
      encryptedName: sealedName.encrypted,
      nameIv: sealedName.iv,
      nameTag: sealedName.tag,
      searchHash: await searchHashOf(name, account.oldRawKey),
    });
  }
  return { format: 'json', conflictStrategy: 'skip', operations: { inserts, updates: [] } };
}

/**
 * The account's ORIGINAL items, opened under `key` and sorted.
 *
 * Scoped to the seeded ids rather than to the user, because several cases go on
 * to write further rows whose ciphertext is a placeholder string — a
 * user-scoped read would then fail to decrypt for a reason that has nothing to
 * do with the crash.
 */
async function openSeeded(
  account: CrashAccount,
  key: Awaited<ReturnType<typeof generateKey>>['key'],
): Promise<string[]> {
  const rows = await VaultItem.find({ _id: { $in: account.itemIds } }).lean();
  expect(rows).toHaveLength(account.itemIds.length);
  const opened: string[] = [];
  for (const row of rows) {
    opened.push(await openText(sealedOf(row, 'data'), key));
  }
  return opened.sort();
}

async function post(
  path: string,
  token: string,
  body: Record<string, unknown>,
): Promise<request.Response> {
  const client = request.agent(app);
  const csrf = await getCsrf(client);
  return client
    .post(path)
    .set('Authorization', authHeader(token))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .send(body);
}

/**
 * Expires a lock the way its TTL does, without waiting minutes for it.
 *
 * `isVaultRotationLockHeld` reads `expiresAt > now` explicitly rather than
 * relying on the row being gone, precisely because MongoDB's TTL reaper runs on
 * its own schedule — so a backdated row IS the state a crashed rotation reaches
 * after five minutes, not an approximation of it. Asserted to have matched a
 * row, or the test would be proving the recovery fires for a lock that was
 * never there.
 */
async function expireLock(jobName: string): Promise<void> {
  const result = await JobLock.updateOne(
    { jobName },
    { $set: { expiresAt: new Date(Date.now() - 1000) } },
  );
  expect(result.matchedCount, `no ${jobName} lock to expire`).toBe(1);
}

describe('Crash consistency — sequential path (standalone mongod)', () => {
  let account: CrashAccount;

  beforeEach(async () => {
    // The topology is asserted, not assumed. Every claim in this block is about
    // the SEQUENTIAL fallback, and the only thing that selects it is
    // `supportsTransactions()` returning false — so a harness that quietly
    // acquired a replica set would leave this block testing the other
    // implementation under the wrong name.
    expect(supportsTransactions(mongoose.connection)).toBe(false);
    account = await seedCrashAccount();
  });

  it('leaves the fence up, the vault key old, and every item still readable under the old key', async () => {
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'rotation-before-first-item-write',
      path: '/api/v1/vault/items/bulk-reencrypt',
      token: account.token,
      body: await rotationBody(account),
    });
    expectKilled(outcome, 'rotation-before-first-item-write');

    const user = await User.findById(account.userId).lean();

    // The fence was COMMITTED BEFORE the first row was touched. This is the
    // ordering nothing else asserts: a fence raised after the loop would leave
    // this false, and every existing rotation test would still pass.
    expect(user!.rotationInProgress).toBe(true);

    // The vault key is still the old one — and provably so: the stored wrapper
    // still OPENS, to exactly the key bytes the items were sealed with. A string
    // comparison alone would miss an IV or a tag replaced by another valid
    // triple, which is the shape a half-applied rotation actually has.
    expect(user!.encryptedVaultKey).toBe(account.oldWrapped.encrypted);
    const unwrapped = await open(
      { encrypted: user!.encryptedVaultKey, iv: user!.vaultKeyIv, tag: user!.vaultKeyTag },
      account.wrappingKey,
    );
    expect(Buffer.from(unwrapped).equals(Buffer.from(account.oldRawKey))).toBe(true);

    // The key the rotation was moving to is recorded, so an operator reading the
    // document can tell what was in flight.
    expect(user!.pendingEncryptedVaultKey).toBe(account.newWrapped.encrypted);

    // The whole point: nothing was stranded. Every item still opens with the key
    // the user still has.
    expect(await openSeeded(account, account.oldKey)).toEqual([...PLAINTEXTS].sort());

    // Nothing released the lock, because nothing ran after the kill.
    const lock = await JobLock.findOne({ jobName: `vault-rotation:${account.userId}` }).lean();
    expect(lock).not.toBeNull();
    expect(lock!.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // And the fence does what it is for: a second session holding the old key
    // cannot land ciphertext this interrupted rotation would not have covered.
    const fenced = await post(
      '/api/v1/vault/items',
      account.token,
      sampleVaultItem({ encryptedName: 'written-after-the-crash' }),
    );
    expect(fenced.status).toBe(409);
    expect(await VaultItem.countDocuments({ userId: account.userId })).toBe(PLAINTEXTS.length);
  }, 90_000);

  it('keeps the vault key OLD when the crash lands after the rows were rewritten, so a retry is possible', async () => {
    // THE WINDOW THIS TOPOLOGY CANNOT MAKE ATOMIC, and the reason the case above
    // is not the whole story. Here the kill lands at the very end of the
    // sequential path: every row has already been committed with NEW-key
    // ciphertext, one at a time, and the process dies at the statement that
    // would have stored the new key.
    //
    // What must hold is what makes the account RECOVERABLE rather than lost:
    // the stored vault key is still the old one, the fence is still up, and the
    // key the rotation was moving to is recorded — so the user can sign in,
    // have the fence cleared, and re-run the rotation with the same new key
    // rather than being locked out of their own vault.
    //
    // What is NOT claimed, deliberately, is that the rows still open: on this
    // path they do not, and pretending otherwise would be the comfortable lie.
    // The assertion below states it plainly, and it is the honest cost of a
    // fallback that MongoDB gives no way to make atomic. The deployed stack runs
    // a replica set (docker-compose.yml, `rs0`), where the case in the
    // transactional block shows the same crash losing nothing at all.
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'rotation-before-vault-key-update',
      path: '/api/v1/vault/items/bulk-reencrypt',
      token: account.token,
      body: await rotationBody(account),
    });
    expectKilled(outcome, 'rotation-before-vault-key-update');

    const user = await User.findById(account.userId).lean();
    expect(user!.rotationInProgress).toBe(true);

    // The vault key was NOT swapped. This is the load-bearing one: had the new
    // key landed while an item was still under the old one — or the reverse —
    // the account would hold ciphertext under a key nobody has, with nothing
    // recording which.
    expect(user!.encryptedVaultKey).toBe(account.oldWrapped.encrypted);
    const unwrapped = await open(
      { encrypted: user!.encryptedVaultKey, iv: user!.vaultKeyIv, tag: user!.vaultKeyTag },
      account.wrappingKey,
    );
    expect(Buffer.from(unwrapped).equals(Buffer.from(account.oldRawKey))).toBe(true);
    expect(user!.pendingEncryptedVaultKey).toBe(account.newWrapped.encrypted);
    expect(user!.pendingVaultKeyIv).toBe(account.newWrapped.iv);
    expect(user!.pendingVaultKeyTag).toBe(account.newWrapped.tag);

    // The rows the loop reached carry the NEW key's ciphertext: they open under
    // the key the rotation was moving to, and no longer under the old one.
    // Asserted in BOTH directions, because "cannot be read" and "was not
    // written" look identical from one side.
    expect(await openSeeded(account, account.newKey)).toEqual([...PLAINTEXTS].sort());
    await expect(openSeeded(account, account.oldKey)).rejects.toThrow();

    // And the account is recoverable rather than wedged: the lock expires, the
    // next login lowers the fence, and the SAME rotation payload — the client
    // still holds the new key — completes and makes the vault whole again.
    await expireLock(`vault-rotation:${account.userId}`);
    const login = await post('/api/v1/auth/login', account.token, {
      email: user!.email,
      authHash: RAW_AUTH_HASH,
    });
    expect(login.status).toBe(200);
    expect((await User.findById(account.userId).lean())!.rotationInProgress).toBe(false);

    const retry = await post(
      '/api/v1/vault/items/bulk-reencrypt',
      account.token,
      await rotationBody(account),
    );
    expect(retry.status, JSON.stringify(retry.body)).toBe(200);
    const repaired = await User.findById(account.userId).lean();
    expect(repaired!.encryptedVaultKey).toBe(account.newWrapped.encrypted);
    expect(repaired!.rotationInProgress).toBe(false);
    expect(await openSeeded(account, account.newKey)).toEqual([...PLAINTEXTS].sort());
  }, 90_000);

  it('recovers on login only once the dead rotation’s lock has expired', async () => {
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'rotation-before-first-item-write',
      path: '/api/v1/vault/items/bulk-reencrypt',
      token: account.token,
      body: await rotationBody(account),
    });
    expectKilled(outcome, 'rotation-before-first-item-write');

    const email = (await User.findById(account.userId).lean())!.email;
    const login = async (): Promise<request.Response> =>
      post('/api/v1/auth/login', account.token, { email, authHash: RAW_AUTH_HASH });

    // FIRST LOGIN, while the crashed rotation's lock is still live. From the
    // login's point of view this is indistinguishable from a rotation that is
    // still running in another worker — and it must therefore leave the fence
    // alone. Clearing it here would readmit exactly the stale-key write the
    // fence exists to refuse.
    const early = await login();
    expect(early.status).toBe(200);
    expect((await User.findById(account.userId).lean())!.rotationInProgress).toBe(true);
    expect(
      await AuditLog.countDocuments({ userId: account.userId, action: 'rotation_recovery' }),
    ).toBe(0);
    const stillFenced = await post(
      '/api/v1/vault/items',
      account.token,
      sampleVaultItem({ encryptedName: 'still-fenced' }),
    );
    expect(stillFenced.status).toBe(409);

    // The lock reaches its TTL. NOW the flag is a crash rather than a rotation
    // in flight, and the next login says so.
    await expireLock(`vault-rotation:${account.userId}`);

    const recovered = await login();
    expect(recovered.status).toBe(200);
    const user = await User.findById(account.userId).lean();
    expect(user!.rotationInProgress).toBe(false);
    expect(user!.pendingEncryptedVaultKey).toBeUndefined();
    expect(user!.pendingVaultKeyIv).toBeUndefined();
    expect(user!.pendingVaultKeyTag).toBeUndefined();

    const audits = await AuditLog.find({
      userId: account.userId,
      action: 'rotation_recovery',
    }).lean();
    expect(audits).toHaveLength(1);
    expect(JSON.stringify(audits[0]!.metadata)).toMatch(/interrupted vault key rotation/i);

    // The vault is usable again, still under the key it always had.
    const write = await post(
      '/api/v1/vault/items',
      account.token,
      sampleVaultItem({ encryptedName: 'written-after-recovery' }),
    );
    expect(write.status).toBe(201);
    expect(await openSeeded(account, account.oldKey)).toEqual([...PLAINTEXTS].sort());
  }, 90_000);

  it('writes no row at all when the crash lands before the import’s first insert', async () => {
    const body = await importBody(account, 5);
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'import-before-insert',
      path: '/api/v1/tools/import',
      token: account.token,
      body,
    });
    expectKilled(outcome, 'import-before-insert');

    // Nothing written, nothing audited.
    expect(await VaultItem.countDocuments({ userId: account.userId })).toBe(PLAINTEXTS.length);
    expect(await AuditLog.countDocuments({ userId: account.userId, action: 'import' })).toBe(0);

    // The dead process still owns the per-user import lock, so the next attempt
    // is refused rather than allowed to interleave with a request that might
    // still be running somewhere. That refusal is the correct answer to "I
    // cannot tell whether the other one is alive".
    const lockName = `vault-import:${account.userId}`;
    const held = await JobLock.findOne({ jobName: lockName }).lean();
    expect(held).not.toBeNull();
    expect(held!.expiresAt.getTime()).toBeGreaterThan(Date.now());

    const blocked = await post('/api/v1/tools/import', account.token, body);
    expect(blocked.status).toBe(409);
    expect(JSON.stringify(blocked.body)).toMatch(/already in progress/i);
    expect(await VaultItem.countDocuments({ userId: account.userId })).toBe(PLAINTEXTS.length);

    // And it is a delay, not a wedge: once the lock's TTL passes, the retry
    // lands the whole import exactly once.
    await expireLock(lockName);
    const retry = await post('/api/v1/tools/import', account.token, body);
    expect(retry.status).toBe(201);
    expect(retry.body.data).toEqual({ insertedCount: 5, updatedCount: 0 });
    expect(await VaultItem.countDocuments({ userId: account.userId })).toBe(PLAINTEXTS.length + 5);
  }, 90_000);

  it('leaves a COMPLETE import behind when the crash lands after the write, and nothing locked', async () => {
    const body = await importBody(account, 5);
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'import-after-commit',
      path: '/api/v1/tools/import',
      token: account.token,
      body,
    });
    expectKilled(outcome, 'import-after-commit');

    // Every row arrived — the crash was after the write, so "no partial insert"
    // here means all five, not none.
    const rows = await VaultItem.find({ userId: account.userId }).lean();
    expect(rows).toHaveLength(PLAINTEXTS.length + 5);
    const imported = rows.filter((row) => !account.itemIds.includes(String(row._id)));
    expect(imported).toHaveLength(5);
    for (const row of imported) {
      // Complete rows, not half-written ones: each opens and carries its hash.
      const plaintext = await openText(sealedOf(row, 'data'), account.oldKey);
      expect(plaintext).toMatch(/"password":"imported"/);
      expect(row.searchHash).toMatch(/^[a-f0-9]{64}$/);
    }

    // The lock is released in a `finally` that runs BEFORE the audit row is
    // written, so a crash in this window leaves the user free to import again.
    expect(await JobLock.countDocuments({ jobName: `vault-import:${account.userId}` })).toBe(0);

    // The audit row is what was lost. Recorded rather than glossed over: a write
    // this account will never see an entry for is the honest cost of a crash in
    // this window, and the alternative (auditing before the write) would claim
    // an import that had not happened.
    expect(await AuditLog.countDocuments({ userId: account.userId, action: 'import' })).toBe(0);
  }, 90_000);
});

describe('Crash consistency — transactional path (replica set)', () => {
  useReplicaSetConnection({ timeoutMs: 120_000 });

  let account: CrashAccount;

  /**
   * The safety net for the case the in-test reaps do not cover: an assertion
   * that fails BEFORE them leaves the killed process's transaction open, and
   * `tests/setup.ts`'s per-test truncation then blocks on its locks until mongod
   * ends it a minute later — which turns one red assertion into a 30-second hook
   * timeout and takes every later test in the file with it. Idempotent: it
   * returns 0 when there is nothing to reap.
   */
  afterEach(async () => {
    await reapOrphanedTransactions();
  });

  beforeEach(async () => {
    // The whole point of this block: without transactions these two cases would
    // silently exercise the sequential fallback and claim atomicity it does not
    // have.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
    account = await seedCrashAccount();
  });

  it('discards every re-encrypted row when the crash lands before the vault-key update', async () => {
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'rotation-before-vault-key-update',
      path: '/api/v1/vault/items/bulk-reencrypt',
      token: account.token,
      body: await rotationBody(account),
    });
    expectKilled(outcome, 'rotation-before-vault-key-update');

    const user = await User.findById(account.userId).lean();

    // The fence was committed OUTSIDE the transaction, deliberately — a write
    // made inside it would be invisible to the other sessions it exists to
    // fence — so it survives the abort while the rotation's own writes do not.
    expect(user!.rotationInProgress).toBe(true);
    expect(user!.encryptedVaultKey).toBe(account.oldWrapped.encrypted);

    // Every row is still the OLD ciphertext: the transaction never committed, so
    // the vault is whole, not half-rotated. The reap between the two reads is
    // the assertion that matters — it proves a transaction really was left open,
    // rather than the writes never having happened — while the second read is a
    // cheap restatement, since an abandoned transaction can only ever abort.
    expect(await openSeeded(account, account.oldKey)).toEqual([...PLAINTEXTS].sort());
    expect(await reapOrphanedTransactions()).toBeGreaterThanOrEqual(1);
    expect(await openSeeded(account, account.oldKey)).toEqual([...PLAINTEXTS].sort());

    // Nothing lowered the fence and nothing released the lock.
    const lock = await JobLock.findOne({ jobName: `vault-rotation:${account.userId}` }).lean();
    expect(lock).not.toBeNull();
    expect(lock!.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // Recovery still discriminates on the replica set: live lock, fence stays.
    const email = user!.email;
    const early = await post('/api/v1/auth/login', account.token, {
      email,
      authHash: RAW_AUTH_HASH,
    });
    expect(early.status).toBe(200);
    expect((await User.findById(account.userId).lean())!.rotationInProgress).toBe(true);

    await expireLock(`vault-rotation:${account.userId}`);
    const recovered = await post('/api/v1/auth/login', account.token, {
      email,
      authHash: RAW_AUTH_HASH,
    });
    expect(recovered.status).toBe(200);
    expect((await User.findById(account.userId).lean())!.rotationInProgress).toBe(false);
    expect(
      await AuditLog.countDocuments({ userId: account.userId, action: 'rotation_recovery' }),
    ).toBe(1);
    expect(await openSeeded(account, account.oldKey)).toEqual([...PLAINTEXTS].sort());
  }, 120_000);

  it('leaves no partial insert when the crash lands inside the import transaction', async () => {
    const body = await importBody(account, 5);
    const outcome = await runCrashProbe({
      uri: getActiveMongoUri(),
      scenario: 'import-after-insert-before-commit',
      path: '/api/v1/tools/import',
      token: account.token,
      body,
    });
    expectKilled(outcome, 'import-after-insert-before-commit');

    // The rows were really inserted — inside the transaction — and the process
    // died before the commit. Not one of them may be visible. (Drop the session
    // from that `insertMany` and this is the only assertion in the repository
    // that notices.)
    const after = await VaultItem.countDocuments({ userId: account.userId });
    expect(
      after,
      `a crash inside the import transaction left ${String(after - PLAINTEXTS.length)} item(s) behind`,
    ).toBe(PLAINTEXTS.length);
    expect(await AuditLog.countDocuments({ userId: account.userId, action: 'import' })).toBe(0);

    // The abandoned transaction was really there — one of it — and once mongod
    // ends it (here, rather than sixty seconds from now) the rows are not merely
    // invisible but gone, which is the only outcome an abandoned transaction has.
    // At least one, rather than exactly one: the count is mongod's idle-session
    // table, and pinning it to 1 would make an internal session carrying a
    // transaction subdocument — on a server version nobody has chosen yet — fail
    // this test for a reason unrelated to the code. What is being asserted is
    // that an abandoned transaction was really there.
    expect(await reapOrphanedTransactions()).toBeGreaterThanOrEqual(1);
    const settled = await VaultItem.countDocuments({ userId: account.userId });
    expect(
      settled,
      `the aborted import transaction left ${String(settled - PLAINTEXTS.length)} item(s) behind`,
    ).toBe(PLAINTEXTS.length);

    // And the retry, once the dead process's lock has expired, imports exactly
    // once — five rows, not ten.
    await expireLock(`vault-import:${account.userId}`);
    const retry = await post('/api/v1/tools/import', account.token, body);
    expect(retry.status).toBe(201);
    expect(retry.body.data).toEqual({ insertedCount: 5, updatedCount: 0 });
    expect(await VaultItem.countDocuments({ userId: account.userId })).toBe(PLAINTEXTS.length + 5);
  }, 120_000);
});
