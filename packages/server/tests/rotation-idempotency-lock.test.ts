/**
 * Phase 11 — a vault-key rotation's idempotency check must be answered under the
 * lock it protects, not before it.
 *
 * `bulkReEncrypt` reads the user at the top of the handler, spends a `bcrypt`
 * compare on the supplied `authHash`, tests `user.lastRotationKey ===
 * idempotencyKey` against the value that read captured, and only then acquires
 * the per-user `vault-rotation:<userId>` JobLock. `acquireJobLock` is an atomic
 * conditional upsert, so two live holders are impossible and the failure is not a
 * concurrent double rotation — it is a SEQUENTIAL one. A second request that read
 * the user before the first committed `lastRotationKey`, and reached the lock
 * after the first released it, sees a stale answer to "have I already done this?"
 * and rotates a second time.
 *
 * What that costs, in order of how much it matters. `vaultKeyVersion` is `$inc`'d
 * by both runs, so it moves by two — and that number is what a document upload's
 * completion checks the client's wrapped key against, so a spurious increment
 * makes an in-flight upload refuse a key that is genuinely current. A second
 * `vault_key_rotation` audit row is written for a rotation the user asked for
 * once. Nothing is corrupted while both requests carry the same body — the
 * ciphertext is rewritten identically and `assertRotationCoversEveryRow` still
 * refuses a payload that no longer names every row — which is why this is a
 * correctness bug in the idempotency contract rather than a data-loss one.
 *
 * ## Why this is CONSTRUCTED rather than raced
 *
 * The interleaving above was observed once in 3,811 tests on a contended machine.
 * A test that fires two requests and hopes is not a test, and — worse — the
 * obvious constructions produce a FALSE GREEN in both directions: if the second
 * request's read lands after the first commits, it short-circuits correctly
 * before the lock and one audit row is written; if it reaches the lock while the
 * first still holds it, it takes the documented 409 and one audit row is written.
 * Only the middle ordering exercises the defect. So BOTH halves are built, and
 * NEITHER is raced — there is no margin here to lose on a slow machine:
 *
 *   • The first request is PARKED inside the lock, at its LAST item write, which
 *     is after the lock is taken and before `lastRotationKey` is written. Any read
 *     the second request takes while that park holds is therefore stale by
 *     construction, and the test asserts that directly rather than assuming it.
 *   • The second request is GATED at its own `bcrypt.compare`, which sits between
 *     the stale read it has already taken and the `acquireJobLock` it has not
 *     reached. The gate opens only once the first request's response has landed —
 *     and that request releases its lock BEFORE writing its response, so at that
 *     moment the lock is provably free. The second therefore reaches it as the
 *     next holder rather than bouncing off it with a 409.
 *
 * An earlier draft made the second request's pre-lock phase merely SLOW instead
 * (a cost-13 `authHash` against the suite's pinned `BCRYPT_ROUNDS: '4'`, ~820 ms)
 * and relied on the first finishing inside it. That is a race with far less margin
 * than it looks: `bcryptjs` is pure JS and yields via `setImmediate` only every
 * ~100 ms, so each of the first request's remaining round trips waits behind a
 * slice and the lock came free around half way through the compare. Synchronising
 * on the observed event costs nothing and cannot slip. Do not reintroduce a timing
 * margin here, and do not reach for a sleep.
 *
 * A vacuous pass is made LOUD rather than silent: a 409 from the second request
 * means the ordering never happened, and that is its own assertion with its own
 * message, not a comment.
 *
 * Covers:
 *   • the stale-read interleaving above: one rotation, one audit row, one bump
 *     (across two WORKERS: in one process the account's large-body share refuses the
 *     retry at admission, and that is pinned as its own case)
 *   • the same retry in one process: 409 before the handler, still one rotation
 *   • a failure of that under-lock read releases the lock instead of stranding it
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { vaultKeyVersionOf, vaultRotationLockName } from '../src/utils/controllerHelpers.js';
import {
  LARGE_BODY_BUSY_MESSAGE,
  largeBodyUserQuota,
} from '../src/middleware/largeBodyAdmission.js';
import { authHeader, createTestUser, getCsrf, seedItem, type TestUser } from './helpers.js';

const ROTATE_PATH = '/api/v1/vault/items/bulk-reencrypt';

/**
 * Items the first request rotates, so its payload is a real multi-row one rather
 * than a single write.
 *
 * Not a window knob — there is no window left to tune. The park sits on the LAST
 * of these writes purely so the first request is close to done when it is
 * released; correctness comes from the gate, not from how much work remains.
 */
const ITEM_COUNT = 3;

const IDEMPOTENCY_KEY = '550e8400-e29b-41d4-a716-446655440000';

const NEW_KEY = {
  newEncryptedVaultKey: 'rotated-vault-key',
  newVaultKeyIv: 'rotated-vault-key-iv',
  newVaultKeyTag: 'rotated-vault-key-tag',
};

/**
 * Makes the idempotency re-read — and only that read — fail.
 *
 * Targeted by the FIELD it selects rather than by a call index: `User.findById`
 * is also called by the JWT strategy and by the handler's own `+authHash` read,
 * so a counter would move silently the day either of those changed and the
 * injection would land on the wrong query while the test still went green.
 */
function failLastRotationKeyRead(message: string): void {
  const realFindById = User.findById.bind(User) as unknown as (
    ...args: unknown[]
  ) => Record<string, unknown>;

  vi.spyOn(User, 'findById').mockImplementation(((...args: unknown[]) => {
    const query = realFindById(...args);
    const realSelect = (query.select as (fields: string) => unknown).bind(query);
    query.select = (fields: string): unknown =>
      fields.includes('lastRotationKey')
        ? { lean: (): Promise<never> => Promise.reject(new Error(message)) }
        : realSelect(fields);
    return query;
  }) as never);
}

/** A ready-to-fire rotation whose CSRF handshake has already happened. */
async function prepareRotation(
  user: TestUser,
  body: Record<string, unknown>,
): Promise<() => Promise<request.Response>> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);

  // `Promise.resolve` is load-bearing: a supertest `Test` is a lazy thenable that
  // dispatches only when something subscribes to it, so handing the raw object
  // back would let the request sit there having sent nothing.
  return () =>
    Promise.resolve(
      agent
        .post(ROTATE_PATH)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(body),
    );
}

/** Rotation audit rows, which are written only by a run that actually rotated. */
async function rotationAuditRows(userId: string): Promise<unknown[]> {
  const rows = await AuditLog.find({ userId, action: 'password_change' }).lean();
  return rows.filter((row) => row.metadata?.['action'] === 'vault_key_rotation');
}

let user: TestUser;
let itemIds: string[];

beforeEach(async () => {
  user = await createTestUser({ email: 'rotation-idempotency-lock@example.com' });

  itemIds = [];
  for (let i = 0; i < ITEM_COUNT; i += 1) {
    const item = await seedItem(user.id, {
      encryptedName: `name-${String(i)}`,
      encryptedData: `data-${String(i)}`,
      searchHash: i.toString(16).padStart(64, '0'),
    });
    itemIds.push(String(item._id));
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Phase 11 — the rotation idempotency check is answered under the lock', () => {
  it('rotates ONCE when a retry read `lastRotationKey` before the first request wrote it', async () => {
    const body = {
      authHash: user.rawPassword,
      idempotencyKey: IDEMPOTENCY_KEY,
      items: itemIds.map((id) => ({
        id,
        encryptedName: `rotated-name-${id}`,
        nameIv: 'rotated-name-iv',
        nameTag: 'rotated-name-tag',
        encryptedData: `rotated-data-${id}`,
        dataIv: 'rotated-data-iv',
        dataTag: 'rotated-data-tag',
      })),
      folders: [],
      ...NEW_KEY,
    };

    // ── Park the FIRST request inside the lock, at its LAST item write ──
    // The item loop belongs to the SEQUENTIAL branch, which is the one this
    // harness takes: `tests/setup.ts` connects to a standalone `MongoMemoryServer`
    // and `supportsTransactions` is false there. After this point the only
    // remaining write is the `User.updateOne` that records the new key,
    // `lastRotationKey` and the `vaultKeyVersion` bump — so any read the second
    // request takes while the park holds is stale, and it is the park, not the
    // amount of work left, that guarantees it.
    let announceParked!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceParked = resolve;
    });
    let releasePark!: () => void;
    const park = new Promise<void>((resolve) => {
      releasePark = resolve;
    });

    const realUpdateOne = VaultItem.updateOne.bind(VaultItem) as unknown as (
      ...args: unknown[]
    ) => Promise<unknown>;
    let itemWrites = 0;
    let hasParked = false;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
      itemWrites += 1;
      // Counted across BOTH requests deliberately, and guarded so only the first
      // one parks: a second request that reaches these writes at all is the
      // unfixed behaviour this case exists to catch, and it must not park too.
      if (!hasParked && itemWrites === ITEM_COUNT) {
        hasParked = true;
        announceParked();
        return park.then(() => realUpdateOne(...args));
      }
      return realUpdateOne(...args);
    }) as never);

    // ── GATE the SECOND request at its bcrypt compare ──
    // That compare sits between the stale `User.findById` at the top of the
    // handler and the `acquireJobLock` further down, so holding it here pins the
    // second request in exactly the state this case is about: its read taken, its
    // lock attempt not yet made. The first compare is the first request's own.
    let announceSecondRead!: () => void;
    const secondRead = new Promise<void>((resolve) => {
      announceSecondRead = resolve;
    });
    let releaseSecondCompare!: () => void;
    const secondCompareGate = new Promise<void>((resolve) => {
      releaseSecondCompare = resolve;
    });
    const realCompare = bcrypt.compare.bind(bcrypt) as unknown as (
      ...args: unknown[]
    ) => Promise<boolean>;
    let compares = 0;
    vi.spyOn(bcrypt, 'compare').mockImplementation(((...args: unknown[]) => {
      compares += 1;
      if (compares === 2) {
        announceSecondRead();
        return secondCompareGate.then(() => realCompare(...args));
      }
      return realCompare(...args);
    }) as never);

    const sendFirst = await prepareRotation(user, body);
    const sendSecond = await prepareRotation(user, body);

    const first = sendFirst();
    let firstSettled = false;
    void first.then(
      () => (firstSettled = true),
      () => (firstSettled = true),
    );
    await parked;

    // ── Stand in for a SECOND WORKER ──
    // In one process the second request no longer gets this far: both requests
    // share this account's large-body share of one (`largeBodyAdmission.ts`), so
    // it is refused with 409 before its body is even read — the case below pins
    // that. The interleaving this case constructs is therefore reachable only
    // ACROSS processes, which is exactly how production runs it: pm2 starts two
    // workers, and each counts shares in its own memory. So the second request is
    // given the share a second worker would give it, and nothing else is changed:
    // it still takes a real slot here, reaches the real handler, and meets the real
    // lock. `mockImplementationOnce`, so it applies to this one request only.
    vi.spyOn(largeBodyUserQuota, 'charge').mockImplementationOnce(() => () => undefined);
    const second = sendSecond();
    await secondRead;

    // The staleness, ASSERTED rather than assumed. The first request is parked
    // before the write that records `lastRotationKey`, so the value the second
    // request just read cannot be the one it is about to be compared against.
    const midFlight = await User.findById(user.id).select('lastRotationKey vaultKeyVersion').lean();
    expect(
      midFlight?.lastRotationKey,
      'the first request had already recorded its idempotency key, so the second one’s read was NOT stale and this test proved nothing',
    ).not.toBe(IDEMPOTENCY_KEY);
    expect(
      firstSettled,
      'the first request had already finished when the second was fired, so the two never overlapped',
    ).toBe(false);

    releasePark();
    const firstRes = await first;
    expect(firstRes.status, JSON.stringify(firstRes.body)).toBe(200);

    // The lock is provably free now: `bulkReEncrypt` releases it in the `finally`
    // that wraps its processing, BEFORE the response above was written. So the
    // second request, released here, reaches `acquireJobLock` as the next holder
    // rather than as a loser — the ordering under test, constructed rather than
    // waited for.
    releaseSecondCompare();
    const secondRes = await second;
    // A 409 means the second request reached the lock while the first still held
    // it — the ordering this file does NOT test. Loud, because a test that passes
    // because its scenario never occurred is worse than no test at all.
    expect(
      secondRes.status,
      `the second request was refused with ${String(secondRes.status)}, so it never reached the lock after the first released it and the interleaving under test did not happen: ${JSON.stringify(secondRes.body)}`,
    ).toBe(200);

    // ── The invariants an idempotency key promises ──
    expect(await rotationAuditRows(user.id), 'the rotation ran twice').toHaveLength(1);

    const rotated = await User.findById(user.id).lean();
    // `$inc: { vaultKeyVersion: 1 }` runs on both the transactional and the
    // sequential path, so a double rotation moves this by two — and that number is
    // what a document upload's completion compares the client's wrapped key
    // against, which is what makes a spurious bump more than bookkeeping.
    expect(vaultKeyVersionOf(rotated), 'the vault key generation moved twice').toBe(1);
    expect(rotated?.encryptedVaultKey).toBe(NEW_KEY.newEncryptedVaultKey);
    expect(rotated?.rotationInProgress).toBe(false);
    expect(rotated?.lastRotationKey).toBe(IDEMPOTENCY_KEY);

    // And the second run wrote nothing of its own: every item carries the rotated
    // ciphertext exactly once, and no item was left behind.
    expect(
      await VaultItem.countDocuments({ userId: user.id, encryptedData: /^rotated-data-/ }),
    ).toBe(ITEM_COUNT);
  });

  it('refuses the same retry in ONE process before it reads anything, and still rotates once', async () => {
    // The single-process half of the case above. With the account's large-body
    // share held by the first request, the retry is refused with 409 at admission:
    // it never reaches the handler, so it never takes the read that went stale, and
    // there is nothing for the lock to arbitrate.
    const body = {
      authHash: user.rawPassword,
      idempotencyKey: IDEMPOTENCY_KEY,
      items: itemIds.map((id) => ({
        id,
        encryptedName: `rotated-name-${id}`,
        nameIv: 'rotated-name-iv',
        nameTag: 'rotated-name-tag',
        encryptedData: `rotated-data-${id}`,
        dataIv: 'rotated-data-iv',
        dataTag: 'rotated-data-tag',
      })),
      folders: [],
      ...NEW_KEY,
    };

    // Park the first request at its password check, inside the handler.
    let announceParked!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceParked = resolve;
    });
    let releasePark!: () => void;
    const park = new Promise<void>((resolve) => {
      releasePark = resolve;
    });
    const realCompare = bcrypt.compare.bind(bcrypt) as unknown as (
      ...args: unknown[]
    ) => Promise<boolean>;
    let compares = 0;
    vi.spyOn(bcrypt, 'compare').mockImplementation(((...args: unknown[]) => {
      compares += 1;
      announceParked();
      return park.then(() => realCompare(...args));
    }) as never);

    const sendFirst = await prepareRotation(user, body);
    const sendSecond = await prepareRotation(user, body);

    const first = sendFirst();
    await parked;

    const secondRes = await sendSecond();
    expect(secondRes.status, JSON.stringify(secondRes.body)).toBe(409);
    expect(secondRes.body.message).toBe(LARGE_BODY_BUSY_MESSAGE);
    // Refused before the handler: the only compare so far is the first request's.
    expect(compares).toBe(1);

    releasePark();
    const firstRes = await first;
    expect(firstRes.status, JSON.stringify(firstRes.body)).toBe(200);

    expect(await rotationAuditRows(user.id), 'the rotation ran twice').toHaveLength(1);
    const rotated = await User.findById(user.id).lean();
    expect(vaultKeyVersionOf(rotated), 'the vault key generation moved twice').toBe(1);
    expect(rotated?.lastRotationKey).toBe(IDEMPOTENCY_KEY);
  });

  it('releases the rotation lock when the check under it cannot be answered', async () => {
    // The re-read above is the one query taken between acquiring the lock and
    // entering the block whose `finally` releases it, so it is the one place a
    // failure could strand the lock. Stranding it is not a lost request: the lock
    // is what login crash-recovery probes to tell a live rotation from a crashed
    // one (`isVaultRotationLockHeld`), and a held one blocks every retry for its
    // full five-minute TTL — a transient database blip would become a five-minute
    // lockout on the operation a user reaches for when they think their key is
    // compromised.
    failLastRotationKeyRead('lastRotationKey read failed');

    const res = await (
      await prepareRotation(user, {
        authHash: user.rawPassword,
        idempotencyKey: IDEMPOTENCY_KEY,
        items: itemIds.map((id) => ({
          id,
          encryptedName: `rotated-name-${id}`,
          nameIv: 'rotated-name-iv',
          nameTag: 'rotated-name-tag',
          encryptedData: `rotated-data-${id}`,
          dataIv: 'rotated-data-iv',
          dataTag: 'rotated-data-tag',
        })),
        folders: [],
        ...NEW_KEY,
      })
    )();

    expect(res.status, JSON.stringify(res.body)).toBe(500);
    expect(
      await JobLock.countDocuments({ jobName: vaultRotationLockName(user.id) }),
      'the rotation lock was left held, blocking every retry for its full TTL',
    ).toBe(0);

    // And it failed BEFORE it rotated anything: the refusal must leave the account
    // exactly as it was, not half-way through a key it cannot finish.
    const untouched = await User.findById(user.id).lean();
    expect(vaultKeyVersionOf(untouched)).toBe(0);
    expect(untouched?.encryptedVaultKey).not.toBe(NEW_KEY.newEncryptedVaultKey);
    expect(untouched?.rotationInProgress).not.toBe(true);
    expect(untouched?.lastRotationKey).toBeUndefined();
    expect(await rotationAuditRows(user.id)).toHaveLength(0);
    expect(
      await VaultItem.countDocuments({ userId: user.id, encryptedData: /^rotated-data-/ }),
    ).toBe(0);
  });
});
