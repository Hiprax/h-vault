/**
 * The deadlines the HTTP server receives a request under, and the one failure they
 * exist for: a client that takes a resource and then stops sending.
 *
 * ## Why this is a test and not a configuration line
 *
 * `PUT /documents/uploads/:id/parts/:n` takes one of `MAX_IN_FLIGHT_PART_UPLOADS`
 * slots BEFORE its body parser runs — deliberately, because a slot taken after
 * 8 MiB has been buffered bounds no memory at all (`utils/partSemaphore.ts`). The
 * consequence is that a request holds a slot for exactly as long as the server is
 * willing to wait for its body, and nothing in this application used to say what
 * that was: Node's default is five minutes, and the stack's internal Nginx cannot
 * help, because it streams `/api/` bodies through (`proxy_request_buffering off`)
 * and its `client_body_timeout` is a BETWEEN-READS timeout that a steady dribble
 * never trips.
 *
 * So the property here is not "a timeout is configured". It is: **a request that
 * stops sending its body is terminated, and the slot it was holding is handed back
 * and used by somebody else.** The second half is what actually matters, and it is
 * asserted by sending a real part upload through the same server afterwards.
 *
 * ## The seams
 *
 * NOTHING IS MOCKED except object storage (the same double every document suite
 * uses) and `storageConfigured`. The server is a real `http.Server` over the real
 * `app`, the stalled request is a real socket writing a real `Content-Length` and
 * then one byte, and the deadline that kills it is the real `createTimedServer`
 * with the numbers turned down — the production values are asserted separately,
 * against the configuration, in the first case below.
 */
import net from 'node:net';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_IN_FLIGHT_PART_UPLOADS,
  MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
} from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

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
import { config } from '../src/config/index.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { PART_DIGEST_HEADER } from '../src/controllers/documentController.js';
import {
  CONNECTIONS_CHECKING_INTERVAL_MS,
  HTTP_TIMEOUTS,
  createTimedServer,
} from '../src/utils/httpTimeouts.js';
import {
  PART_UPLOAD_BODY_DEADLINE_MS,
  createPartSlotHolder,
  parsePartUploadBody,
  requirePartContentLength,
} from '../src/middleware/documentPartBody.js';
import { partUploadSemaphore, partUploadUserQuota } from '../src/utils/partSemaphore.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

/**
 * The deadlines the stalled-request case runs under.
 *
 * Turned down from the shipped values, and that is the only honest way to test
 * this: the property is "the deadline is enforced and the slot comes back", not
 * "the number is 120000", and waiting two minutes for it would be a test nobody
 * runs. The sweep interval is turned down with them, because it is what enforces
 * the deadline and the worst case is the sum of the two.
 */
const FAST_TIMEOUTS = {
  requestTimeoutMs: 1_500,
  headersTimeoutMs: 1_000,
  connectionsCheckingIntervalMs: 100,
};

/** Generous upper bound for the kill: the deadline, the sweep, and room for a slow machine. */
const KILL_DEADLINE_MS = 6_000;

/** The wrapped-DEK and framing columns a staging row carries. Opaque here. */
const FRAMING = {
  encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
  dekIv: 'ZGVrLWl2LWJhc2U2NA==',
  dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

const digestOf = (body: Buffer): string => createHash('sha256').update(body).digest('hex');

/** A live single-segment staging row for `user`. */
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

/**
 * Writes a complete part-upload request head that declares a whole sealed segment,
 * sends ONE byte of it, and then sends nothing ever again.
 *
 * Hand-written over a socket because that is the client under test: supertest and
 * `http.request` both finish what they start, and "finishes what it starts" is
 * precisely the property the attacker does not have.
 */
function dribblingPart(
  port: number,
  path: string,
  headers: Record<string, string>,
): { closed: Promise<{ elapsedMs: number; statusLine: string }>; abandon: () => void } {
  const startedAt = Date.now();
  const socket = net.connect(port, '127.0.0.1');
  let received = '';

  const closed = new Promise<{ elapsedMs: number; statusLine: string }>((resolve) => {
    socket.on('connect', () => {
      const head = Object.entries({
        Host: `127.0.0.1:${String(port)}`,
        // The declared length is a whole segment; one byte of it is sent below.
        'Content-Length': String(DOCUMENT_CIPHERTEXT_CHUNK_BYTES),
        'Content-Type': 'application/octet-stream',
        ...headers,
      })
        .map(([name, value]) => `${name}: ${value}\r\n`)
        .join('');
      socket.write(`PUT ${path} HTTP/1.1\r\n${head}\r\n`);
      socket.write('a');
    });
    socket.on('data', (chunk: Buffer) => (received += chunk.toString('latin1')));
    // Both terminal outcomes resolve: a server that ANSWERS 408 and one that simply
    // destroys the socket have both terminated the request, and the assertion that
    // follows is about the slot either way.
    socket.on('error', () =>
      resolve({ elapsedMs: Date.now() - startedAt, statusLine: 'ECONNRESET' }),
    );
    socket.on('close', () =>
      resolve({
        elapsedMs: Date.now() - startedAt,
        statusLine: received.split('\r\n')[0] ?? '(nothing)',
      }),
    );
  });

  return { closed, abandon: () => socket.destroy() };
}

/**
 * The real part-upload chain — length guard, slot holder, body parser — mounted on
 * a bare Express app at a deadline short enough to observe.
 *
 * Nothing here is a double: `createPartSlotHolder` is the factory the shipped
 * `holdPartUploadSlot` is built from, and the other two middlewares are imported
 * as they are. What the bare mount removes is the authentication, CSRF and storage
 * the deadline has nothing to do with; the identity the share is charged to is
 * supplied directly, because that is all the chain reads.
 */
function partChainApp(
  deadlineMs: number,
  handler: (req: express.Request, res: express.Response) => void,
): express.Express {
  const local = express();
  local.put(
    '/parts/:partNumber',
    (req, _res, next) => {
      Object.assign(req, { user: { _id: 'deadline-user' } });
      next();
    },
    requirePartContentLength,
    createPartSlotHolder(deadlineMs),
    parsePartUploadBody,
    handler,
  );
  return local;
}

/**
 * A server's sweep interval. Read through a cast because `@types/node` declares
 * `connectionsCheckingInterval` on the options object but not on the instance,
 * while the runtime carries it on both — and the interval is the number that
 * decides how LATE a deadline may fire, so it is worth asserting rather than
 * trusting.
 */
const sweepIntervalOf = (target: http.Server): number =>
  (target as unknown as { connectionsCheckingInterval: number }).connectionsCheckingInterval;

let user: TestUser;
let server: http.Server;

beforeEach(async () => {
  storageRef.current = createInMemoryStorage();
  user = await createTestUser({ email: 'http-timeouts@example.com' });
  server = createTimedServer(app);
});

afterEach(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('createTimedServer', () => {
  it("builds a server carrying this deployment's deadlines, and a tighter sweep than Node's", () => {
    // Node's own defaults, so the assertions below are a CHANGE rather than a
    // coincidence: an untimed server reports 300000 / 60000 / 30000.
    const untimed = http.createServer();
    expect(untimed.requestTimeout).toBe(300_000);
    expect(sweepIntervalOf(untimed)).toBe(30_000);

    const timed = createTimedServer(app);

    expect(timed.requestTimeout).toBe(config.HTTP_REQUEST_TIMEOUT_MS);
    expect(timed.headersTimeout).toBe(config.HTTP_HEADERS_TIMEOUT_MS);
    // The sweep is what ENFORCES the two above — a deadline is only ever observed
    // on the next sweep — so leaving it at Node's 30 s would add thirty seconds to
    // every one of them.
    expect(sweepIntervalOf(timed)).toBe(CONNECTIONS_CHECKING_INTERVAL_MS);
    expect(HTTP_TIMEOUTS.connectionsCheckingIntervalMs).toBe(CONNECTIONS_CHECKING_INTERVAL_MS);
  });

  it('refuses to build a server whose headers deadline outlives its request deadline', () => {
    // Node ACCEPTS that pair when the two are assigned as properties and then
    // SWAPS them, silently and in C++, so the server enforces the opposite of what
    // it was configured with — measured: request 2 s beside headers 4 s killed a
    // dribbling body at 4 s. Going through the constructor is what turns that into
    // a refusal, and this is the case that pins the choice of path.
    expect(() =>
      createTimedServer(app, {
        requestTimeoutMs: 2_000,
        headersTimeoutMs: 4_000,
        connectionsCheckingIntervalMs: 100,
      }),
    ).toThrow(RangeError);
  });
});

describe('a part upload that stops sending its body', () => {
  it('is terminated by the deadline, and the slot it held is handed back and reused', async () => {
    server = createTimedServer(app, FAST_TIMEOUTS);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    const stalled = await seedUpload(user);
    const csrf = await getCsrf(request.agent(server));
    const dribble = dribblingPart(port, `/api/v1/documents/uploads/${stalled}/parts/1`, {
      Authorization: authHeader(user.accessToken),
      Cookie: csrf.cookie,
      'x-csrf-token': csrf.token,
      [PART_DIGEST_HEADER]: digestOf(pattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES)),
    });

    try {
      // THE WEDGE ITSELF, asserted before it is relieved: one byte of body has
      // bought this request a slot out of the process budget and a charge against
      // the account's share, and it is holding both while sending nothing.
      await vi.waitFor(
        () => {
          expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS - 1);
          expect(partUploadUserQuota.heldBy(user.id)).toBe(1);
        },
        { timeout: 10_000, interval: 10 },
      );

      const outcome = await Promise.race([
        dribble.closed,
        new Promise<never>((_resolve, reject) =>
          setTimeout(
            () => reject(new Error('the stalled part upload was never terminated')),
            KILL_DEADLINE_MS,
          ),
        ),
      ]);

      // Terminated BY THE DEADLINE: not before it (which would mean something else
      // refused the request), and inside it plus one sweep plus slack.
      expect(outcome.elapsedMs).toBeGreaterThanOrEqual(FAST_TIMEOUTS.requestTimeoutMs - 100);
      expect(outcome.elapsedMs).toBeLessThan(KILL_DEADLINE_MS);
      expect(outcome.statusLine).toContain('408');
    } finally {
      dribble.abandon();
    }

    // The whole budget is back, and the account's charge with it.
    await vi.waitFor(
      () => {
        expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
        expect(partUploadUserQuota.keys).toBe(0);
      },
      { timeout: 10_000, interval: 10 },
    );

    // THE PROPERTY THAT ACTUALLY MATTERS: the slot is usable again. A release that
    // only decremented a counter, or a termination that left the request in the
    // chain, would pass every assertion above and fail this one.
    const body = pattern(DOCUMENT_TAG_BYTES + 32, 3);
    const reused = await seedUpload(user);
    const agent = request.agent(server);
    const pending = agent
      .put(`/api/v1/documents/uploads/${reused}/parts/1`)
      .set('Authorization', authHeader(user.accessToken));
    const pair = await getCsrf(agent);
    const response = await pending
      .set('Cookie', pair.cookie)
      .set('x-csrf-token', pair.token)
      .set(PART_DIGEST_HEADER, digestOf(body))
      .type('application/octet-stream')
      .send(body);

    expect(response.status, JSON.stringify(response.body)).toBe(200);

    // THE NEGATIVE: the abandoned transfer stored nothing and recorded nothing. A
    // partial part admitted to the ledger would make completion derive a chunk
    // count from bytes that do not exist.
    const row = await DocumentUpload.findById(stalled).lean();
    expect(row!.parts).toEqual([]);
    expect(row!.receivedBytes).toBe(0);
    expect(storageRef.current!.storedKeys()).toEqual([buildObjectKey(user.id, reused)]);
  }, 30_000);
});

describe("the part route's own body deadline", () => {
  it('is one sealed segment at the slowest uplink this deployment stands behind', () => {
    // DERIVED, so that changing the segment size or the uplink floor moves the
    // deadline with it rather than leaving a stale literal behind. The value is
    // stated here as well, because the operator-facing documentation quotes it.
    expect(PART_UPLOAD_BODY_DEADLINE_MS).toBe(
      (DOCUMENT_CIPHERTEXT_CHUNK_BYTES / MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND) * 1_000,
    );
    expect(PART_UPLOAD_BODY_DEADLINE_MS).toBe(64_000);
    // …and it is far tighter than the server-wide deadline, which is the whole
    // point of it existing: this route is the one where waiting costs a slot.
    expect(PART_UPLOAD_BODY_DEADLINE_MS).toBeLessThan(config.HTTP_REQUEST_TIMEOUT_MS);
  });

  it('destroys a part whose body stalls, and hands back the slot for the next one', async () => {
    const reached: number[] = [];
    // The SERVER-wide deadline is deliberately left at its shipped value here, so
    // the only thing that can end this request is the route's own.
    server = createTimedServer(
      partChainApp(300, (req, res) => {
        reached.push((req.body as Buffer).length);
        res.json({ ok: true });
      }),
    );
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    const dribble = dribblingPart(port, '/parts/1', {});
    try {
      await vi.waitFor(
        () => {
          expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS - 1);
        },
        { timeout: 10_000, interval: 10 },
      );

      const outcome = await Promise.race([
        dribble.closed,
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('the stalled part was never destroyed')), 5_000),
        ),
      ]);
      // Ended by the route's deadline, not by the server-wide one: the shipped
      // `HTTP_REQUEST_TIMEOUT_MS` is minutes away, so a chain that relied on it
      // would still be waiting here.
      expect(outcome.elapsedMs).toBeGreaterThanOrEqual(250);
      expect(outcome.elapsedMs).toBeLessThan(5_000);
    } finally {
      dribble.abandon();
    }

    await vi.waitFor(
      () => {
        expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
        expect(partUploadUserQuota.keys).toBe(0);
      },
      { timeout: 10_000, interval: 10 },
    );

    // The slot is usable again, and the handler never saw the abandoned request.
    const body = pattern(64, 5);
    const response = await request(server)
      .put('/parts/2')
      .type('application/octet-stream')
      .send(body);
    expect(response.status).toBe(200);
    expect(reached).toEqual([body.length]);
  }, 30_000);

  it('does not destroy a part whose body ARRIVED while its storage call is slow', async () => {
    // The deadline covers RECEIPT and stops there. Drop the `end` listener that
    // clears it and this request — body long since delivered, handler merely slow —
    // is destroyed mid-flight, which is the shape of "a healthy upload capped to
    // protect against an unhealthy engine" that `partSemaphore.ts` argues against.
    let finish: (() => void) | undefined;
    server = createTimedServer(
      partChainApp(200, (req, res) => {
        finish = () => res.json({ bytes: (req.body as Buffer).length });
      }),
    );
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    const body = pattern(128, 9);
    // `.then()` is what DISPATCHES a supertest request: `.send()` only stages the
    // body, so a request that is merely held in a variable is never sent and the
    // wait below would time out on a request the server never saw.
    const pending = request(server)
      .put('/parts/1')
      .type('application/octet-stream')
      .send(body)
      .then((response) => response);
    // Keeps a rejection from arriving as an UNHANDLED one while the case is still
    // running: this file's server is torn down in `afterEach`, so an assertion
    // failure below would otherwise surface as the process exiting rather than as
    // the assertion that failed.
    const guarded = pending.catch(() => undefined);

    await vi.waitFor(
      () => {
        expect(finish).toBeDefined();
      },
      { timeout: 10_000, interval: 10 },
    );

    // A SECOND request, started LATER and never finished, is the clock. Its
    // deadline is armed after the healthy request's and therefore expires after
    // it, so its death proves the healthy request has outlived its own deadline —
    // an event to wait for rather than a duration to sleep through, which is what
    // keeps this case deterministic on a loaded machine.
    const dribble = dribblingPart(port, '/parts/2', {});
    try {
      await Promise.race([
        dribble.closed,
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error('the stalled part was never destroyed')), 5_000),
        ),
      ]);
    } finally {
      dribble.abandon();
    }

    // The dribbler's slot comes back; the healthy request's does not, because the
    // healthy request is still there.
    await vi.waitFor(
      () => {
        expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS - 1);
      },
      { timeout: 10_000, interval: 10 },
    );
    finish!();

    // THE ASSERTION THIS CASE EXISTS FOR: the request that had already delivered
    // its body is answered normally. A deadline still armed across the storage
    // call would have destroyed the socket instead, and this would be a rejection.
    await guarded;
    const response = await pending;
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ bytes: body.length });
    await vi.waitFor(
      () => {
        expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
      },
      { timeout: 10_000, interval: 10 },
    );
  }, 30_000);
});
