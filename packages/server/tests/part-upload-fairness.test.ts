/**
 * The per-identity share of the process-wide part-upload budget.
 *
 * ## The defect this file pins
 *
 * `MAX_IN_FLIGHT_PART_UPLOADS` is a MEMORY budget (see `utils/partSemaphore.ts`):
 * four parts of one sealed segment each, buffered at a time, per worker process.
 * A slot is taken BEFORE the body parser runs, which is what makes the budget
 * bound anything at all — and, until this share existed, it was also what let ONE
 * account take every slot without sending a byte. Four requests that declare a
 * `Content-Length` and then dribble hold all four slots for as long as the server
 * will wait for a body, and every other account's part uploads queue behind them.
 * No valid upload id, no quota and no `init` is needed: the slot is taken two
 * middlewares before the handler that would check any of those.
 *
 * So the property here is not "a user is rate limited". It is: **one identity
 * cannot hold the whole process budget**, and the request that would have taken
 * the fourth slot is refused IMMEDIATELY rather than queued behind a body nobody
 * is sending.
 *
 * ## Why the assertions are about the SEMAPHORE and the STORAGE CALL
 *
 * A status code alone cannot tell "refused before the slot" from "refused after
 * it": both are 503. Every case below therefore also reads
 * `partUploadSemaphore.available` / `.waiting` — the numbers that say whether the
 * budget was spent — and counts the requests that reached the storage boundary,
 * which is the first observable point downstream of the parser. A refusal that had
 * consumed a slot, or queued for one, would show up in those and in nothing else.
 *
 * ## The two seams
 *
 * MONGO IS REAL (the staging rows are queried, as they are in production). OBJECT
 * STORAGE IS A DOUBLE, and its `putObject` is deliberately BLOCKED: that is what
 * keeps a request parked while holding its slot, which is the state this whole
 * file is about. Nothing here mocks the semaphore, the middleware or the route.
 */
import { createHash } from 'node:crypto';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createErrorMiddleware } from '@hiprax/errors';
import mongoose from 'mongoose';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_IN_FLIGHT_PART_UPLOADS,
  MAX_IN_FLIGHT_PART_UPLOADS_PER_USER,
} from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

/**
 * Every record the application's module loggers write, with the module that
 * wrote it. The share refusal is LOGGED on purpose — on the wire it is the same
 * 503 an unreachable storage engine produces, and the two call for opposite
 * operator responses — so the log line is part of what the refusal delivers.
 * `log` is here because `createRequestLogger` ends every response with it.
 */
const logged = vi.hoisted(() => {
  const records: { module: string; level: string; message: unknown; meta: unknown }[] = [];
  const loggerFor = (
    module: string,
  ): Record<string, (message: unknown, meta?: unknown) => void> => {
    const at =
      (level: string) =>
      (message: unknown, meta?: unknown): void => {
        records.push({ module, level, message, meta });
      };
    return {
      error: at('error'),
      warn: at('warn'),
      info: at('info'),
      debug: at('debug'),
      verbose: at('verbose'),
      http: at('http'),
      silly: at('silly'),
      log: at('log'),
    };
  };
  return { records, loggerFor };
});

vi.mock('../src/utils/logger.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/logger.js')>();
  return { ...actual, createModuleLogger: (name: string) => logged.loggerFor(name) };
});

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      if (storageRef.current === undefined) {
        throw new Error('the in-memory storage double was not installed for this test');
      }
      return storageRef.current;
    },
  };
});

import app from '../src/app.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { PART_DIGEST_HEADER } from '../src/controllers/documentController.js';
import { holdingPartUploadSlot } from '../src/middleware/documentPartBody.js';
import { partUploadSemaphore, partUploadUserQuota } from '../src/utils/partSemaphore.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

/** The wrapped-DEK and framing columns a staging row carries. Opaque here. */
const FRAMING = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

/** A body whose bytes vary along its length, so a digest means something. */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

/** A live single-segment staging row for `user`, seeded rather than driven through init. */
async function seedUpload(user: TestUser): Promise<string> {
  const uploadId = new mongoose.Types.ObjectId();
  await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, uploadId.toHexString()),
    ...FRAMING,
    declaredPlaintextBytes: 1,
    declaredChunkCount: 1,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  return String(uploadId);
}

/** One authenticated part upload through the real app, with a real CSRF pair. */
async function putPart(user: TestUser, uploadId: string, seed = 0): Promise<request.Response> {
  const body = pattern(DOCUMENT_TAG_BYTES + 32, seed);
  const agent = request.agent(app);
  const pair = await getCsrf(agent);
  const pending = agent
    .put(`/api/v1/documents/uploads/${uploadId}/parts/1`)
    .set('Authorization', authHeader(user.accessToken));
  return pending
    .set('Cookie', pair.cookie)
    .set('x-csrf-token', pair.token)
    .set(PART_DIGEST_HEADER, digestOf(body))
    .type('application/octet-stream')
    .send(body);
}

/**
 * Installs a storage double whose `putObject` parks until it is released, and
 * returns the list of resolvers — one per request that reached the boundary.
 *
 * The LENGTH of that list is the assertion that matters in this file: it counts
 * the requests whose body was parsed and handed on, so a refusal that is visible
 * there is a refusal that happened too late to have saved anything.
 */
function blockStorage(): { blocked: (() => void)[]; release: () => void } {
  const base = storageRef.current!;
  const blocked: (() => void)[] = [];
  // `release()` reopens the double as well as resolving what is parked in it. A
  // release that only resolved the current waiters would park the NEXT request
  // for ever — holding a slot for the rest of the file and making every later
  // case in it fail for a reason that has nothing to do with what it pins.
  let open = false;
  storageRef.current = {
    ...base,
    putObject: async (key: string, body: Uint8Array) => {
      if (!open) await new Promise<void>((resolve) => blocked.push(resolve));
      await base.putObject(key, body);
    },
  };
  return {
    blocked,
    release: () => {
      open = true;
      for (const resolve of blocked) resolve();
    },
  };
}

/** Waits for the semaphore's own counters to settle on the expected pair. */
async function waitForBudget(available: number, waiting: number): Promise<void> {
  await vi.waitFor(
    () => {
      expect({
        available: partUploadSemaphore.available,
        waiting: partUploadSemaphore.waiting,
      }).toEqual({ available, waiting });
    },
    { timeout: 10_000, interval: 10 },
  );
}

let alice: TestUser;
let bob: TestUser;

beforeEach(async () => {
  storageRef.current = createInMemoryStorage();
  alice = await createTestUser({ email: 'part-fairness-alice@example.com' });
  bob = await createTestUser({ email: 'part-fairness-bob@example.com' });
});

describe('the per-identity share of the in-flight part budget', () => {
  it('refuses one identity a part past its share, without spending a slot or a queue place', async () => {
    logged.records.length = 0;
    const storage = blockStorage();
    const overflow = await seedUpload(alice);
    let refused: request.Response | undefined;

    const held: Promise<request.Response>[] = [];
    // Not `await`ed inside the try: a request the server ADMITS parks inside the
    // blocked storage call and never answers, so awaiting it directly would turn a
    // regression into a thirty-second hang instead of a readable failure. It is
    // started, and the wait below is what carries the deadline.
    let overSharePart: Promise<request.Response> | undefined;
    try {
      for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS_PER_USER; i += 1) {
        held.push(putPart(alice, await seedUpload(alice), i));
      }
      // Every one of them is parked inside the storage call, so each is holding a
      // slot: this is the state one identity is allowed to reach.
      await vi.waitFor(
        () => {
          expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);
        },
        { timeout: 10_000, interval: 10 },
      );
      await waitForBudget(MAX_IN_FLIGHT_PART_UPLOADS - MAX_IN_FLIGHT_PART_UPLOADS_PER_USER, 0);

      overSharePart = putPart(alice, overflow, 99);
      void overSharePart.then((response) => (refused = response));
      await vi.waitFor(
        () => {
          expect(
            refused,
            'the part past the share was never answered: it was admitted and is waiting on a body nobody is sending',
          ).toBeDefined();
        },
        { timeout: 5_000, interval: 10 },
      );
    } finally {
      storage.release();
      for (const settled of await Promise.allSettled([...held, overSharePart])) {
        expect(settled.status).toBe('fulfilled');
      }
      for (const response of await Promise.all(held)) expect(response.status).toBe(200);
    }

    // Refused, and refused by the SHARE rather than by the budget: the process
    // still had a free slot when this request arrived.
    expect(refused!.status, JSON.stringify(refused!.body)).toBe(503);
    expect(refused!.headers['retry-after']).toBe('1');

    // Logged exactly once, by the part-body module, naming the share it hit —
    // and NOT the identity, exactly as the rate limiters leave their key out.
    const refusals = logged.records.filter(
      (record) => record.module === 'document-part-body' && record.level === 'warn',
    );
    expect(refusals).toEqual([
      {
        module: 'document-part-body',
        level: 'warn',
        message: 'Document part refused: the account is at its in-flight share',
        meta: { limit: MAX_IN_FLIGHT_PART_UPLOADS_PER_USER },
      },
    ]);
    expect(JSON.stringify(refusals)).not.toContain(alice.id);
    expect(JSON.stringify(refusals)).not.toContain(alice.email);

    // THE NEGATIVES, and they are the point of the case. The refusal never
    // reached the parser or the handler, so no fourth body was buffered, nothing
    // was stored, and the staging row is exactly as it was seeded. A refusal
    // taken after the slot would leave all three of these different.
    expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);
    const row = await DocumentUpload.findById(overflow).lean();
    expect(row!.parts).toEqual([]);
    expect(row!.receivedBytes).toBe(0);

    // …and the whole budget is back once the parked requests finish: the share is
    // released on the same event the slot is.
    await waitForBudget(MAX_IN_FLIGHT_PART_UPLOADS, 0);
  });

  it('still serves a second identity while the first is at its share', async () => {
    // The reason the share exists. With one account holding its cap, another
    // account's part must still be parsed and handed to storage — which is what
    // "one identity cannot wedge the process" means operationally.
    const storage = blockStorage();
    const held: Promise<request.Response>[] = [];
    let bobsPart: Promise<request.Response> | undefined;

    try {
      for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS_PER_USER; i += 1) {
        held.push(putPart(alice, await seedUpload(alice), i));
      }
      await vi.waitFor(
        () => {
          expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);
        },
        { timeout: 10_000, interval: 10 },
      );

      bobsPart = putPart(bob, await seedUpload(bob), 7);
      // Bob's body was parsed and forwarded while Alice sits at her cap.
      await vi.waitFor(
        () => {
          expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER + 1);
        },
        { timeout: 10_000, interval: 10 },
      );
    } finally {
      storage.release();
      for (const settled of await Promise.allSettled([...held, bobsPart!])) {
        expect(settled.status).toBe('fulfilled');
        expect((settled as PromiseFulfilledResult<request.Response>).value.status).toBe(200);
      }
    }

    await waitForBudget(MAX_IN_FLIGHT_PART_UPLOADS, 0);
  });

  it('re-admits the identity as soon as ONE of its own parts completes', async () => {
    // A share that is charged and never handed back is a share that degrades into
    // a permanent refusal after the first burst — the leak this asserts against is
    // the same shape as the slot leak the semaphore's own docblock records. And it
    // is handed back PART BY PART: the account is re-admitted while its other two
    // parts are still in flight, not only once all of them have finished.
    const storage = blockStorage();
    const held: Promise<request.Response>[] = [];
    for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS_PER_USER; i += 1) {
      held.push(putPart(alice, await seedUpload(alice), i));
    }
    await vi.waitFor(
      () => {
        expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);
      },
      { timeout: 10_000, interval: 10 },
    );

    // At the share: one more is refused.
    const refused = await putPart(alice, await seedUpload(alice), 41);
    expect(refused.status).toBe(503);

    // ONE of the three finishes; the other two stay parked in storage. Which one
    // reached storage first is the server's business, so the race says which.
    storage.blocked[0]!();
    const first = await Promise.race(held);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    await waitForBudget(MAX_IN_FLIGHT_PART_UPLOADS - (MAX_IN_FLIGHT_PART_UPLOADS_PER_USER - 1), 0);
    expect(partUploadUserQuota.heldBy(alice.id)).toBe(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER - 1);

    // The same account is admitted again at once: its next part gets as far as
    // storage (it parks there beside the two still held) rather than a 503.
    const again = putPart(alice, await seedUpload(alice), 42);
    await vi.waitFor(
      () => {
        expect(storage.blocked).toHaveLength(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER + 1);
      },
      { timeout: 10_000, interval: 10 },
    );

    storage.release();
    for (const settled of await Promise.all([...held, again])) {
      expect(settled.status, JSON.stringify(settled.body)).toBe(200);
    }
    await waitForBudget(MAX_IN_FLIGHT_PART_UPLOADS, 0);
    expect(partUploadUserQuota.keys).toBe(0);
  });
});

describe('the part handler wrapper', () => {
  it('refuses to run a wrapped part handler that no slot holder admitted', async () => {
    // The wrapper mounted without the holder in front of it: a misassembled chain.
    // It must fail closed rather than buffer and forward a part no budget counted,
    // and a refusal must not touch the budget either way.
    const handler = vi.fn((_req: express.Request, res: express.Response) => {
      res.json({ ran: true });
    });
    const bare = express();
    bare.put('/bare', holdingPartUploadSlot(handler));
    bare.use(createErrorMiddleware({ exposeServerErrors: true }));

    const res = await request(bare).put('/bare').send(Buffer.alloc(0));
    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Part upload handler reached without an admission slot');
    expect(handler).not.toHaveBeenCalled();
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    expect(partUploadUserQuota.keys).toBe(0);
  });
});
