/**
 * Admission to the two routes that accept a 30 MB body.
 *
 * `POST /backup/restore` and `POST /vault/items/bulk-reencrypt` are the only JSON
 * routes whose body may be fifteen times the global 2 MB limit, so they are the
 * only two where the ORDER of the middlewares in front of the parser decides how
 * much memory a request can make the process spend before anything has judged it.
 *
 * ## The defect this file pins
 *
 * Both chains used to run the 30 MB `express.json` FIRST and `passwordVerifyLimiter`
 * (5 per user per 15 minutes) second. A limiter placed after the parser cannot run
 * until `raw-body` has buffered the whole body and `JSON.parse` has allocated it, so
 * the sixth request in a window was refused only after it had cost exactly what
 * the first five did. The limiter bounded how many requests were ANSWERED, never
 * how many were BUFFERED.
 *
 * ## Why the refusal is observed over a raw socket
 *
 * The request that must be refused declares a large `Content-Length` and then sends
 * almost nothing. A limiter that runs first answers it at once; a parser that runs
 * first waits for bytes that never come, and the request is never answered at all.
 * So "a 429 arrived while the body was still unsent" is the observation that tells
 * the two orders apart, and it can only be made by a client that does not finish
 * what it starts, which supertest and `http.request` both do.
 *
 * ## The seams
 *
 * MONGO IS REAL: the limiter is the production one, constructed over the real
 * `MongoRateLimitStore` on the harness's `mongod`, and the user it keys on is a
 * real row that `authenticate` reads. `isProduction` is forced true for this file's
 * module graph only, because outside production every limiter is a pass-through
 * and the order would be unobservable. The routers are mounted on a bare app
 * rather than through `app.ts`, because the production app refuses to boot without
 * a client build; what that removes is CSRF and the global parsers, none of which
 * sit between `authenticate` and these two chains.
 */
import net from 'node:net';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import passport from 'passport';
import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { createErrorMiddleware } from '@hiprax/errors';
import {
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS,
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER,
} from '@hvault/shared';

/**
 * `vi.mock` (hoisted, evaluated once) rather than `vi.resetModules()` +
 * `vi.doMock`: resetting the registry re-evaluates the Mongoose models against the
 * shared mongoose singleton, which throws `OverwriteModelError`. The same reason
 * `coverage-rate-limiter.test.ts` records.
 */
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import backupRoutes from '../src/routes/backup.js';
import vaultRoutes from '../src/routes/vault.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import {
  LARGE_BODY_BUSY_MESSAGE,
  holdingLargeBodySlot,
  largeBodySemaphore,
  largeBodyUserQuota,
} from '../src/middleware/largeBodyAdmission.js';
import { authHeader, createTestUser, type TestUser } from './helpers.js';

/** `passwordVerifyLimiter`'s budget per window. Read back from the counter it writes, below. */
const PASSWORD_VERIFY_LIMIT = 5;

/**
 * What the refused request declares it will send: comfortably inside the 30 MB
 * parser limit, so a parser that ran first would WAIT for it rather than refuse it
 * from the header with 413 (which would answer the request and hide the defect).
 */
const DECLARED_BODY_BYTES = 20 * 1024 * 1024;

/**
 * How long a refusal may take to arrive. Generous: in the fixed order it arrives in
 * milliseconds, and the bound only matters when the order is wrong, where the
 * request is never answered at all and this is how long the case waits to say so.
 */
const ANSWER_DEADLINE_MS = 5_000;

/** The two large-body routes, as mounted in `app.ts`. */
const LARGE_BODY_ROUTES = [
  { label: 'POST /api/v1/backup/restore', path: '/api/v1/backup/restore' },
  { label: 'POST /api/v1/vault/items/bulk-reencrypt', path: '/api/v1/vault/items/bulk-reencrypt' },
] as const;

/**
 * The two routers under their real prefixes, behind the same `passport.initialize()`
 * and error middleware `app.ts` uses.
 */
function largeBodyApp(): express.Express {
  const local = express();
  local.use(passport.initialize());
  local.use('/api/v1/backup', backupRoutes);
  local.use('/api/v1/vault', vaultRoutes);
  local.use(createErrorMiddleware({ exposeServerErrors: false }));
  return local;
}

interface HeldRequest {
  /** The status line, or `null` when nothing was answered before the deadline. */
  readonly answered: Promise<string | null>;
  /** Everything the server sent, once it has sent it. */
  readonly received: () => string;
  /** Tears the socket down from the client's side. */
  readonly abandon: () => void;
}

/**
 * Writes a complete request head that declares `declaredBytes` of JSON, sends
 * `firstBytes` of it, and then sends nothing ever again.
 */
function heldRequest(
  port: number,
  path: string,
  headers: Record<string, string>,
  declaredBytes: number,
  firstBytes: string,
): HeldRequest {
  const socket = net.connect(port, '127.0.0.1');
  let received = '';

  const answered = new Promise<string | null>((resolve) => {
    const timer = setTimeout(() => resolve(null), ANSWER_DEADLINE_MS);
    socket.on('connect', () => {
      const head = Object.entries({
        Host: `127.0.0.1:${String(port)}`,
        'Content-Type': 'application/json',
        'Content-Length': String(declaredBytes),
        ...headers,
      })
        .map(([name, value]) => `${name}: ${value}\r\n`)
        .join('');
      socket.write(`POST ${path} HTTP/1.1\r\n${head}\r\n`);
      socket.write(firstBytes);
    });
    socket.on('data', (chunk: Buffer) => {
      received += chunk.toString('latin1');
      if (received.includes('\r\n\r\n')) {
        clearTimeout(timer);
        resolve(received.split('\r\n')[0] ?? null);
      }
    });
    // A reset is not an answer; the deadline above decides what it was.
    socket.on('error', () => undefined);
  });

  return { answered, received: () => received, abandon: () => socket.destroy() };
}

/** The `passwordVerifyLimiter` counter document for `user`, as the store wrote it. */
async function passwordVerifyCounter(user: TestUser): Promise<number | null> {
  const row = await mongoose.connection
    .collection(RATE_LIMIT_COLLECTION)
    .findOne({ _id: `pwverify:${user.id}` } as never);
  return row === null ? null : Number((row as { counter?: unknown }).counter);
}

let server: http.Server;
let port: number;
const held: HeldRequest[] = [];

beforeEach(async () => {
  server = http.createServer(largeBodyApp());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  for (const pending of held.splice(0)) pending.abandon();
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  vi.restoreAllMocks();
  // THE LEAK CHECK, after every case in this file: once every connection is gone,
  // every slot and every share is back. A case that leaked one would otherwise be
  // noticed only by the case after it, as a hang.
  await vi.waitFor(() => {
    expect(largeBodySemaphore.available, 'a large-body slot leaked').toBe(
      MAX_IN_FLIGHT_LARGE_BODY_REQUESTS,
    );
    expect(largeBodySemaphore.waiting, 'a large-body request is still queued').toBe(0);
    expect(largeBodyUserQuota.keys, 'an account still holds a share').toBe(0);
  });
});

/** How many connections the server still has open, which is when `close` has fired. */
function openConnections(): Promise<number> {
  return new Promise((resolve, reject) => {
    server.getConnections((error, count) => (error ? reject(error) : resolve(count)));
  });
}

describe.each(LARGE_BODY_ROUTES)('$label admits a request in the right order', ({ path }) => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('refuses the request past the limiter budget before reading its body', async () => {
    // Spend the budget with five small, complete, invalid bodies. Each one passes
    // the limiter and is then refused by validation, which is what proves the
    // limiter counted it: the fifth is still a 400, not a 429.
    for (let attempt = 1; attempt <= PASSWORD_VERIFY_LIMIT; attempt += 1) {
      const res = await request(server)
        .post(path)
        .set('Authorization', authHeader(user.accessToken))
        .send({});
      expect(res.status, `request ${String(attempt)} of the budget`).toBe(400);
    }
    expect(await passwordVerifyCounter(user)).toBe(PASSWORD_VERIFY_LIMIT);

    // The sixth declares 20 MB and sends one byte of it.
    const sixth = heldRequest(
      port,
      path,
      { Authorization: authHeader(user.accessToken) },
      DECLARED_BODY_BYTES,
      '{',
    );
    held.push(sixth);

    const statusLine = await sixth.answered;
    expect(
      statusLine,
      'the request past the budget was never answered: the parser ran first and is waiting for a body nobody is sending',
    ).toBe('HTTP/1.1 429 Too Many Requests');
    expect(sixth.received()).toContain('Too many password verification attempts');
    // The refusal itself was counted, and nothing else was: one request, one unit.
    expect(await passwordVerifyCounter(user)).toBe(PASSWORD_VERIFY_LIMIT + 1);
  });

  it('refuses an unauthenticated request before reading its body', async () => {
    // The router-level `authenticate` is the first thing in both chains. This is
    // the order the limiter move must not disturb: no bearer token, 401, and no
    // counter written, because the limiter never ran.
    const anonymous = heldRequest(port, path, {}, DECLARED_BODY_BYTES, '{');
    held.push(anonymous);

    expect(await anonymous.answered).toBe('HTTP/1.1 401 Unauthorized');
    // No counter of this limiter AT ALL: an anonymous request that reached it would
    // be keyed on something other than this user, so looking only for this user's
    // key could never fail.
    expect(
      await mongoose.connection
        .collection(RATE_LIMIT_COLLECTION)
        .countDocuments({ _id: { $regex: '^pwverify:' } } as never),
    ).toBe(0);
  });
});

describe('the process-wide large-body budget', () => {
  const RESTORE = LARGE_BODY_ROUTES[0].path;
  const ROTATE = LARGE_BODY_ROUTES[1].path;

  it('admits at most the budget at once, queues the next with its body unread, and serves it when a slot frees', async () => {
    const holders = await Promise.all(
      Array.from({ length: MAX_IN_FLIGHT_LARGE_BODY_REQUESTS }, () => createTestUser()),
    );
    const waiter = await createTestUser();
    const quitter = await createTestUser();

    // Two accounts, one stalled 20 MB body each: every slot in the process.
    const stalled = holders.map((holder) =>
      heldRequest(
        port,
        RESTORE,
        { Authorization: authHeader(holder.accessToken) },
        DECLARED_BODY_BYTES,
        '{',
      ),
    );
    held.push(...stalled);
    await vi.waitFor(() => expect(largeBodySemaphore.available).toBe(0));

    // A third account's COMPLETE, small, invalid body. Were it parsed it would be
    // answered 400 at once; queued, it is not answered at all.
    const complete = '{}';
    const queued = heldRequest(
      port,
      ROTATE,
      { Authorization: authHeader(waiter.accessToken) },
      complete.length,
      complete,
    );
    held.push(queued);
    // A fourth that gives up while it waits: the slot it is later granted must come
    // straight back rather than be spent on nobody.
    const gaveUp = heldRequest(
      port,
      ROTATE,
      { Authorization: authHeader(quitter.accessToken) },
      complete.length,
      complete,
    );
    held.push(gaveUp);
    await vi.waitFor(() => expect(largeBodySemaphore.waiting).toBe(2));
    expect(queued.received(), 'the queued request was answered, so its body was parsed').toBe('');
    gaveUp.abandon();
    // Its share is handed back while it is still queued; the slot it has not been
    // given yet is not.
    await vi.waitFor(() => expect(largeBodyUserQuota.heldBy(quitter.id)).toBe(0));
    expect(largeBodySemaphore.waiting).toBe(2);

    // One holder gives up: its slot goes to the FIFO head, which is the waiter.
    stalled[0]!.abandon();
    expect(await queued.answered).toBe('HTTP/1.1 400 Bad Request');
    // The quitter's grant was handed straight back, so exactly one holder remains.
    await vi.waitFor(() => {
      expect(largeBodySemaphore.waiting).toBe(0);
      expect(largeBodySemaphore.available).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS - 1);
    });
  });

  it('refuses a second concurrent request from the same account with 409, before reading its body', async () => {
    const user = await createTestUser();
    const first = heldRequest(
      port,
      RESTORE,
      { Authorization: authHeader(user.accessToken) },
      DECLARED_BODY_BYTES,
      '{',
    );
    held.push(first);
    await vi.waitFor(() =>
      expect(largeBodyUserQuota.heldBy(user.id)).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER),
    );

    // The OTHER route: the share is per account across both, because both are the
    // same memory.
    const second = heldRequest(
      port,
      ROTATE,
      { Authorization: authHeader(user.accessToken) },
      DECLARED_BODY_BYTES,
      '{',
    );
    held.push(second);

    expect(
      await second.answered,
      'the second request was never answered: it was admitted and is waiting on a body nobody is sending',
    ).toBe('HTTP/1.1 409 Conflict');
    expect(second.received()).toContain(LARGE_BODY_BUSY_MESSAGE);
    // It carries no `data`: a 409 with `data.vaultKeyVersion` means "stale key" to the client.
    expect(second.received()).not.toContain('"data"');
    // It took no slot and did not queue for one: only the first holds anything.
    expect(largeBodySemaphore.available).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS - 1);
    expect(largeBodySemaphore.waiting).toBe(0);
    expect(largeBodyUserQuota.heldBy(user.id)).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER);
    // A different account is still admitted beside it.
    const other = await createTestUser();
    const res = await request(server)
      .post(ROTATE)
      .set('Authorization', authHeader(other.accessToken))
      .send({});
    expect(res.status).toBe(400);
  });

  it('hands the slot back when the client aborts before the handler, and after a normal answer', async () => {
    const user = await createTestUser();
    const aborted = heldRequest(
      port,
      RESTORE,
      { Authorization: authHeader(user.accessToken) },
      DECLARED_BODY_BYTES,
      '{',
    );
    held.push(aborted);
    await vi.waitFor(() =>
      expect(largeBodySemaphore.available).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS - 1),
    );
    aborted.abandon();
    await vi.waitFor(() => {
      expect(largeBodySemaphore.available).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS);
      expect(largeBodyUserQuota.keys).toBe(0);
    });

    // A request answered normally (validation, 400) gives both back as well, and the
    // same account is admitted again straight after, which a leaked share would refuse.
    for (let round = 0; round < 2; round += 1) {
      const res = await request(server)
        .post(RESTORE)
        .set('Authorization', authHeader(user.accessToken))
        .send({});
      expect(res.status).toBe(400);
    }
  });

  it('keeps the slot until the handler of an aborted request has settled', async () => {
    const user = await createTestUser();
    // Park the rotation handler at its password check, which is after the body was
    // parsed and before any write. `authenticate` does not use bcrypt, so the first
    // compare is the handler's own.
    let announceParked!: () => void;
    const parked = new Promise<void>((resolve) => (announceParked = resolve));
    let releasePark!: () => void;
    const park = new Promise<void>((resolve) => (releasePark = resolve));
    let settled = false;
    const realCompare = bcrypt.compare.bind(bcrypt) as unknown as (
      ...args: unknown[]
    ) => Promise<boolean>;
    vi.spyOn(bcrypt, 'compare').mockImplementation(((...args: unknown[]) => {
      announceParked();
      return park.then(() => realCompare(...args)).finally(() => (settled = true));
    }) as never);

    const body = JSON.stringify({
      authHash: user.rawPassword,
      items: [],
      folders: [],
      documents: [],
      newEncryptedVaultKey: 'rotated-vault-key',
      newVaultKeyIv: 'rotated-vault-key-iv',
      newVaultKeyTag: 'rotated-vault-key-tag',
    });
    const rotation = heldRequest(
      port,
      ROTATE,
      { Authorization: authHeader(user.accessToken) },
      Buffer.byteLength(body),
      body,
    );
    held.push(rotation);
    await parked;

    // The client goes away while the handler is still running. Wait until the server
    // has seen that, which is when the response's `close` has fired.
    rotation.abandon();
    await vi.waitFor(async () => expect(await openConnections()).toBe(0));
    expect(settled).toBe(false);
    expect(
      largeBodySemaphore.available,
      'the slot came back while the handler still held the parsed body',
    ).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS - 1);
    expect(largeBodyUserQuota.heldBy(user.id)).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER);

    // The handler finishes; only now do the slot and the share come back.
    releasePark();
    await vi.waitFor(() => {
      expect(largeBodySemaphore.available).toBe(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS);
      expect(largeBodyUserQuota.keys).toBe(0);
    });
    expect(settled).toBe(true);
  });

  it('refuses to run a wrapped handler that no slot holder admitted', async () => {
    // The wrapper mounted without the holder in front of it: a misassembled chain.
    // It must fail closed rather than run a 30 MB operation no budget counted.
    const handler = vi.fn((_req: express.Request, res: express.Response) => {
      res.json({ ran: true });
    });
    const bare = express();
    bare.post('/bare', holdingLargeBodySlot(handler));
    bare.use(createErrorMiddleware({ exposeServerErrors: true }));

    const res = await request(bare).post('/bare').send({});
    expect(res.status).toBe(500);
    expect(res.body.message).toBe('Large-body handler reached without an admission slot');
    expect(handler).not.toHaveBeenCalled();
  });
});
