/**
 * Phase 10 — resilience-verify: the per-user item cap cannot be breached by
 * OVERLAPPING imports, on the STANDALONE topology.
 *
 * The cap check is a read followed by a write (`countDocuments` → `insertMany`).
 * Two imports that each individually fit can therefore both pass the read and
 * then both write, landing the user over `MAX_ITEMS_PER_USER` — unless something
 * serializes them. The default harness (`tests/setup.ts`) connects to a
 * standalone `MongoMemoryServer`, which rejects multi-document transactions, so
 * on THIS topology the executor's transaction branch never runs and the
 * guarantee rests ENTIRELY on the per-user `vault-import:<userId>` JobLock. That
 * is what these tests pin: the loser of the race gets a 409 and writes nothing,
 * and the cap holds however the requests interleave.
 *
 * The replica-set half of the same guarantee — where `session.withTransaction`
 * genuinely runs and the cap is re-checked inside it — lives in
 * `import-operations-transaction.test.ts`, which already stands up a
 * `MongoMemoryReplSet`.
 *
 * Covers:
 *   • an import parked inside the locked region 409s a second, overlapping one
 *   • sequential imports that collectively exceed the cap: the second is refused
 *   • a burst of overlapping imports never leaves the vault above the cap, and
 *     the rows that landed reconcile exactly with the counts that were reported
 *   • `importLimiter`'s budget against the worst-case batch count of one import
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import {
  MAX_IMPORT_DATA_LENGTH,
  MAX_IMPORT_FILE_SIZE_BYTES,
  MAX_IMPORT_ITEMS,
  MAX_ITEMS_PER_USER,
  PASSWORD_HISTORY_MAX,
} from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { IMPORT_RATE_LIMIT_MAX } from '../src/middleware/rateLimiter.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf, rawItems } from './helpers.js';
import type { TestUser } from './helpers.js';

const API = '/api/v1';

/** A distinct, well-formed (lowercase hex, 64-char) searchHash per index. */
function searchHashFor(index: number): string {
  return index.toString(16).padStart(64, '0');
}

/** One `inserts[]` row that satisfies `importInsertItemSchema`. */
function insertRow(index: number): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `inserted-name-${String(index)}`,
    encryptedData: `inserted-data-${String(index)}`,
    searchHash: searchHashFor(index),
  });
}

/**
 * Builds a ready-to-fire import request whose CSRF handshake has already
 * happened, so several of them can be launched at genuinely the same moment
 * rather than staggered by their own preamble.
 */
async function prepareImport(
  token: string,
  operations: Record<string, unknown>,
): Promise<() => Promise<request.Response>> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);

  // `Promise.resolve` is load-bearing, not decoration: a supertest `Test` is a
  // lazy thenable that only dispatches when something subscribes to it. Handing
  // the raw object back would let `const pending = send()` sit there having sent
  // nothing, and a test that then waits for the request to arrive would hang.
  return () =>
    Promise.resolve(
      agent
        .post(`${API}/tools/import`)
        .set('Authorization', authHeader(token))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ format: 'json', operations }),
    );
}

/**
 * Shrinks the user's effective item headroom to `headroom` NET-NEW rows without
 * seeding 10,000 real ones.
 *
 * The stub calls THROUGH to the real count and adds a fixed offset, so the value
 * the executor sees still tracks what has actually been written. That is what
 * makes a concurrency test meaningful: a flat `mockResolvedValue` would pin the
 * count to a constant and the cap could then never notice rows a racing request
 * had just inserted, which is precisely the interaction under test.
 */
function pinHeadroom(headroom: number): void {
  const realCountDocuments = VaultItem.countDocuments.bind(VaultItem) as unknown as (
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ) => Promise<number>;
  const offset = MAX_ITEMS_PER_USER - headroom;

  vi.spyOn(VaultItem, 'countDocuments').mockImplementation(((
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ) => realCountDocuments(filter, options).then((count) => count + offset)) as never);
}

describe('Phase 10 — the import cap holds under overlapping requests (standalone)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('409s an import that overlaps one already inside the locked region, and writes nothing', async () => {
    // Four rows of headroom, three per request: either request fits on its own,
    // both together do not.
    pinHeadroom(4);

    // Park the FIRST import mid-write, inside the lock and after its cap check,
    // so the second one is guaranteed to arrive while the lock is genuinely
    // held. Without this the overlap would depend on scheduling luck and the
    // test would prove the lock only intermittently.
    let announceArrival!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceArrival = resolve;
    });
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });

    const realInsertMany = VaultItem.insertMany.bind(VaultItem) as unknown as (
      docs: unknown[],
      options?: Record<string, unknown>,
    ) => Promise<unknown[]>;
    let firstWrite = true;
    vi.spyOn(VaultItem, 'insertMany').mockImplementation((async (
      docs: unknown[],
      options?: Record<string, unknown>,
    ) => {
      if (firstWrite) {
        firstWrite = false;
        announceArrival();
        await gate;
      }
      return realInsertMany(docs, options);
    }) as never);

    const sendFirst = await prepareImport(user.accessToken, {
      inserts: [insertRow(1), insertRow(2), insertRow(3)],
    });
    const sendSecond = await prepareImport(user.accessToken, {
      inserts: [insertRow(4), insertRow(5), insertRow(6)],
    });

    const first = sendFirst();
    await parked;

    // Resolves fully while the first request is still holding the lock.
    const second = await sendSecond();
    expect(second.status).toBe(409);
    expect(JSON.stringify(second.body)).toMatch(/import is already in progress/i);

    openGate();
    expect((await first).status).toBe(201);

    // Only the winner's rows exist: the loser was refused before its own cap
    // check, so it never even read a count, let alone wrote.
    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(3);
    expect(stored.map((item) => item.encryptedName).sort()).toEqual([
      'inserted-name-1',
      'inserted-name-2',
      'inserted-name-3',
    ]);
  });

  it('refuses the second of two sequential imports that collectively exceed the cap', async () => {
    // The serialized case: each request fits when it runs, but the second one's
    // cap check must observe the rows the first one committed. This is the
    // outcome the JobLock forces the racing case to degrade into.
    pinHeadroom(4);

    const first = await (
      await prepareImport(user.accessToken, {
        inserts: [insertRow(1), insertRow(2), insertRow(3)],
      })
    )();
    expect(first.status).toBe(201);
    expect(first.body.data.insertedCount).toBe(3);

    const second = await (
      await prepareImport(user.accessToken, {
        inserts: [insertRow(4), insertRow(5), insertRow(6)],
      })
    )();
    expect(second.status).toBe(400);
    expect(JSON.stringify(second.body)).toMatch(/per-user item limit/i);

    expect(await rawItems(user.id)).toHaveLength(3);
  });

  it('never leaves the vault above the cap when several imports are fired at once', async () => {
    // Four concurrent imports of three rows each against four rows of headroom:
    // every one of them fits in isolation, all four together are three times the
    // allowance. Whatever order they interleave in, the vault must end at or
    // below the cap and the rows on disk must reconcile with what was reported.
    const HEADROOM = 4;
    const ROWS_PER_REQUEST = 3;
    const REQUESTS = 4;
    pinHeadroom(HEADROOM);

    const senders = await Promise.all(
      Array.from({ length: REQUESTS }, (_, requestIndex) =>
        prepareImport(user.accessToken, {
          inserts: Array.from({ length: ROWS_PER_REQUEST }, (_, rowIndex) =>
            insertRow(requestIndex * ROWS_PER_REQUEST + rowIndex),
          ),
        }),
      ),
    );
    const responses = await Promise.all(senders.map((send) => send()));

    // 201 (it ran), 409 (the lock refused it) and 400 (the cap refused it) are
    // the only legal outcomes; anything else — a 500 from a duplicate-key crash,
    // say — is a real defect rather than a benign loss of the race.
    for (const res of responses) {
      expect([201, 400, 409]).toContain(res.status);
    }

    const accepted = responses.filter((res) => res.status === 201);
    // Progress is guaranteed: whoever takes the lock first cannot be refused,
    // because the vault is empty when it checks.
    expect(accepted.length).toBeGreaterThanOrEqual(1);

    const reported = accepted.reduce(
      (total, res) => total + (res.body.data.insertedCount as number),
      0,
    );
    const stored = await rawItems(user.id);

    // The invariant. Delete the JobLock and this fails: every request reads the
    // count before any of them writes, all four pass, and 12 rows land in a
    // 4-row allowance.
    expect(stored.length).toBeLessThanOrEqual(HEADROOM);
    // And nothing was written that was not also reported (or vice versa).
    expect(stored).toHaveLength(reported);
  });

  // ── importLimiter sizing ─────────────────────────────────────────────

  it('budgets importLimiter above the worst-case batch count of a single migration', () => {
    // The client splits one resolved import into size-bounded requests, so the
    // question this endpoint's limiter has to answer is: how many requests can a
    // single legitimate migration cost? Derived from the real constants rather
    // than asserted from memory, so a change to any of them fails here.
    //
    // ── Inputs ───────────────────────────────────────────────────────────
    //   MAX_IMPORT_FILE_SIZE_BYTES  8,388,608  the client refuses a larger source file
    //   MAX_ITEMS_PER_USER             10,000  and refuses a file with more rows than this
    //   MAX_IMPORT_ITEMS               10,000  per-request operation cap
    //   client batch budget           943,718  = floor(MAX_IMPORT_DATA_LENGTH * 0.9)
    //
    // The 0.9 factor is the one figure MIRRORED rather than imported: it defines
    // `IMPORT_BATCH_MAX_BYTES` in packages/client/src/services/import/batch.ts,
    // which a server test cannot reach across the workspace boundary. Lowering it
    // there means MORE batches and would not fail here — re-derive this by hand
    // if it ever moves.
    //
    // ── Size model ───────────────────────────────────────────────────────
    //   content   AES-256-GCM is length-preserving and the ciphertext is base64'd,
    //             so encrypted content is ~4/3 of the plaintext it came from, and
    //             that plaintext is bounded by the source file:
    //               8,388,608 * 4/3            = 11,184,811 B
    //   envelope  every operation also carries fixed JSON — six field names, two
    //             16-char IVs, two 24-char tags, a 64-char searchHash, itemType,
    //             tags and favorite — call it 400 B, at most once per row:
    //               10,000 * 400               =  4,000,000 B
    //   history   an UPDATE may additionally carry up to PASSWORD_HISTORY_MAX
    //             prior passwords, ~170 B each with their IV, tag and timestamp.
    //             Pessimistic for realistic data — it assumes EVERY row is an
    //             update onto an item whose history is already saturated:
    //               10,000 * 10 * 170          = 17,000,000 B
    //                                    total = 32,184,811 B  ->  35 batches
    //
    // ── Verdict ──────────────────────────────────────────────────────────
    // 35 requests for a pessimistic migration, against a 60-per-user-per-15-min
    // budget. A mid-way failure does NOT double that under `skip` or `overwrite`:
    // re-running re-resolves against the now-updated vault, so rows that already
    // landed fall into `duplicateSkipped` / `unchanged` and emit no operation at
    // all (PLAN §1.8 step 11) — an import plus its recovery run costs ~36
    // requests, not ~70. The realistic figure is far lower: an all-inserts 8 MiB
    // migration is 17 batches. 60 stands; unchanged.
    //
    // Two limits of that verdict, stated rather than papered over:
    //   • `keep_both` never matches (resolve.ts), so re-running one re-sends
    //     everything and DOES roughly double — but that is the strategy
    //     deliberately duplicating, not a recovery path anyone retries into.
    //   • 170 B/entry is a typical password, not the schema ceiling: the wire
    //     bound on `encryptedPassword` is 5,000 chars, and a vault of 10,000
    //     items each holding ten 500-char history passwords would need ~100
    //     batches and would 429 part-way. That vault is not a realistic artifact,
    //     and the outcome is a rate-limit message plus an idempotent retry rather
    //     than data loss, so it does not justify widening the limiter.
    const CLIENT_BATCH_BUDGET_BYTES = Math.floor(MAX_IMPORT_DATA_LENGTH * 0.9);
    const CIPHERTEXT_EXPANSION = 4 / 3;
    const ENVELOPE_BYTES_PER_OPERATION = 400;
    const HISTORY_BYTES_PER_ENTRY = 170;

    const worstCaseBytes =
      MAX_IMPORT_FILE_SIZE_BYTES * CIPHERTEXT_EXPANSION +
      MAX_ITEMS_PER_USER * ENVELOPE_BYTES_PER_OPERATION +
      MAX_ITEMS_PER_USER * PASSWORD_HISTORY_MAX * HISTORY_BYTES_PER_ENTRY;

    const byteDrivenBatches = Math.ceil(worstCaseBytes / CLIENT_BATCH_BUDGET_BYTES);
    const countDrivenBatches = Math.ceil(MAX_ITEMS_PER_USER / MAX_IMPORT_ITEMS);
    const worstCaseBatches = Math.max(byteDrivenBatches, countDrivenBatches);

    // Bytes are what bind; the per-request operation cap never does.
    expect(countDrivenBatches).toBeLessThanOrEqual(byteDrivenBatches);

    // One worst-case migration, plus the one extra request its recovery run
    // costs, must fit inside a single window with room to spare.
    expect(worstCaseBatches + 1).toBeLessThanOrEqual(IMPORT_RATE_LIMIT_MAX);
  });
});
