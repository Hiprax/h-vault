/**
 * The part-upload semaphore, the per-identity quota beside it, and the middleware
 * that holds one of each.
 *
 * WHAT THIS FILE IS FOR. `document-parts.test.ts` proves the semaphore is mounted
 * where it has to be (ahead of the body parser) by observing the HTTP surface, and
 * `part-upload-fairness.test.ts` proves the share is enforced there. This file
 * proves the primitives underneath are correct in the cases HTTP cannot easily
 * reach: the order slots are handed out in, that a release is idempotent, that a
 * task releasing synchronously does not recurse, that a quota FORGETS a key once
 * its last charge is handed back, and — the two that would be a production outage
 * rather than a bug — that a caller whose response has already closed hands its
 * slot straight back instead of holding it for ever, whether that close happened
 * while it was queued or before it ever arrived.
 *
 * The middleware is exercised with minimal `req`/`res` doubles rather than through
 * supertest, deliberately: what it does is wire an `EventEmitter` event to a
 * release, and the failure being pinned is a LEAK, which is a statement about the
 * semaphore's counter rather than about a response body. Nothing here mocks the
 * unit under test; the semaphore and the middleware are both real.
 */
import { EventEmitter } from 'node:events';
import { describe, it, expect, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import { MAX_IN_FLIGHT_PART_UPLOADS, MAX_IN_FLIGHT_PART_UPLOADS_PER_USER } from '@hvault/shared';
import {
  createKeyedQuota,
  createSemaphore,
  partUploadSemaphore,
  partUploadUserQuota,
} from '../src/utils/partSemaphore.js';
import { holdPartUploadSlot } from '../src/middleware/documentPartBody.js';

/** The headers a refusal sets, recorded so the unit cases can read them back. */
type FakeResponse = EventEmitter & Response & { sentHeaders: Record<string, string> };

/**
 * A `res` that is only what the middleware touches: an emitter with `once`, the
 * `destroyed` flag it reads before taking anything, and a `setHeader` that records.
 */
function fakeResponse(destroyed = false): FakeResponse {
  const sentHeaders: Record<string, string> = {};
  const res = new EventEmitter() as FakeResponse;
  Object.assign(res, {
    destroyed,
    sentHeaders,
    setHeader: (name: string, value: string) => {
      sentHeaders[name] = value;
    },
  });
  return res;
}

/**
 * A `req` carrying only what the middleware touches: the identity the share is
 * charged to, and the `end` event the body deadline is cleared on. A real
 * EventEmitter rather than a stub, because the middleware SUBSCRIBES to it.
 */
function requestFrom(userId?: string): Request {
  const req = new EventEmitter() as EventEmitter & Request;
  if (userId !== undefined) Object.assign(req, { user: { _id: userId } });
  return req;
}

/** An authenticated request from nobody in particular: the anonymous bucket. */
const anonymousRequest = (): Request => requestFrom();

describe('createSemaphore', () => {
  it('hands out every permit before anybody waits', () => {
    const semaphore = createSemaphore(2);
    const granted: number[] = [];

    semaphore.acquire(() => granted.push(1));
    semaphore.acquire(() => granted.push(2));

    expect(granted).toEqual([1, 2]);
    expect(semaphore.available).toBe(0);
    // Nobody is queued: both callers ran, and neither is still pending.
    expect(semaphore.waiting).toBe(0);
  });

  it('queues a caller past the budget and runs it in FIFO order when slots free up', () => {
    const semaphore = createSemaphore(1);
    const ran: string[] = [];
    let releaseFirst: (() => void) | undefined;

    semaphore.acquire((release) => {
      ran.push('first');
      releaseFirst = release;
    });
    semaphore.acquire(() => ran.push('second'));
    semaphore.acquire(() => ran.push('third'));

    // The budget is one, so exactly one caller has run and two are queued. The
    // negative matters as much as the positive: an implementation that ran every
    // caller and only counted would bound no memory at all.
    expect(ran).toEqual(['first']);
    expect(semaphore.waiting).toBe(2);
    expect(semaphore.available).toBe(0);

    releaseFirst!();
    // FIFO: the caller that waited longest goes next, so a queue cannot starve one
    // transfer while a busier one keeps jumping it.
    expect(ran).toEqual(['first', 'second']);
    expect(semaphore.waiting).toBe(1);
  });

  it('treats a second release from the same caller as a no-op', () => {
    const semaphore = createSemaphore(1);
    const ran: string[] = [];
    let release: (() => void) | undefined;

    semaphore.acquire((grant) => {
      release = grant;
    });
    semaphore.acquire(() => ran.push('waiter'));

    release!();
    release!();
    release!();

    // The waiter ran ONCE and the budget is back to exactly one, not three. The
    // middleware wires a release to an event that may fire alongside its own
    // cleanup, so a release that added a permit each time would inflate the budget
    // without bound and the memory ceiling would quietly stop existing.
    expect(ran).toEqual(['waiter']);
    expect(semaphore.available).toBe(0);
    expect(semaphore.permits).toBe(1);
  });

  it('drains a long queue of instantly-releasing callers without recursing', () => {
    // Each granted task releases synchronously, which re-enters the drain loop. A
    // hand-off implemented as a direct recursive call would be one stack frame per
    // waiter here and would throw `RangeError: Maximum call stack size exceeded`;
    // the re-entrancy guard turns it into an iteration instead.
    const semaphore = createSemaphore(1);
    let ran = 0;

    for (let i = 0; i < 20_000; i += 1) {
      semaphore.acquire((release) => {
        ran += 1;
        release();
      });
    }

    expect(ran).toBe(20_000);
    expect(semaphore.waiting).toBe(0);
    expect(semaphore.available).toBe(1);
  });

  it('refuses a budget that is not a positive integer', () => {
    // A zero or negative budget is a semaphore nobody can ever pass, which would
    // present as every part upload in the process hanging for ever with no error
    // anywhere. Fail at construction, where the mistake is.
    expect(() => createSemaphore(0)).toThrow(RangeError);
    expect(() => createSemaphore(-1)).toThrow(RangeError);
    expect(() => createSemaphore(1.5)).toThrow(RangeError);
  });

  it('sizes the shipped instance from the shared memory budget', () => {
    // The number is a MEMORY budget: this many parts of one ciphertext chunk each
    // may be buffered at once, and that product has to fit the container's limit.
    // Read from the shared constant rather than restated, so raising the constant
    // is the only way to raise the ceiling.
    expect(partUploadSemaphore.permits).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
  });
});

describe('createKeyedQuota', () => {
  it('charges one key up to its limit and then refuses, leaving other keys alone', () => {
    const quota = createKeyedQuota(2);

    const first = quota.charge('alice');
    const second = quota.charge('alice');
    const third = quota.charge('alice');

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    // A REFUSAL, not a queue. The middleware turns this into a 503 the client
    // retries in a second; a promise here would be a place for one identity to
    // pile up sockets, which is the problem rather than the fix.
    expect(third).toBeNull();
    expect(quota.heldBy('alice')).toBe(2);

    // The negative: a key at its limit says nothing about any other key, which is
    // the whole point of a per-identity share.
    expect(quota.charge('bob')).not.toBeNull();
    expect(quota.heldBy('bob')).toBe(1);
    expect(quota.keys).toBe(2);
  });

  it('treats a second release of the same charge as a no-op', () => {
    const quota = createKeyedQuota(2);
    const release = quota.charge('alice')!;
    quota.charge('alice');

    release();
    release();
    release();

    // One charge came back, not three. The middleware wires a release to an event
    // that may fire alongside its own cleanup, so a release that decremented every
    // time would hand an identity more of the budget than it is entitled to — and
    // the count would go negative, which reads as "unlimited".
    expect(quota.heldBy('alice')).toBe(1);
  });

  it('forgets a key entirely once its last charge is handed back', () => {
    // The leak this pins is silent and unbounded: a map keyed by user id that
    // never deletes grows by one entry per account that has ever uploaded a part,
    // for the life of the process.
    const quota = createKeyedQuota(1);
    const release = quota.charge('alice')!;
    expect(quota.keys).toBe(1);

    release();

    expect(quota.keys).toBe(0);
    expect(quota.heldBy('alice')).toBe(0);
    // …and the key is chargeable again, rather than stuck at its limit for ever.
    expect(quota.charge('alice')).not.toBeNull();
  });

  it('refuses a limit that is not a positive integer', () => {
    // A zero limit refuses every part upload in the process, which would present
    // as the whole document feature answering 503 with nothing logged. Fail at
    // construction, where the mistake is.
    expect(() => createKeyedQuota(0)).toThrow(RangeError);
    expect(() => createKeyedQuota(-1)).toThrow(RangeError);
    expect(() => createKeyedQuota(1.5)).toThrow(RangeError);
  });

  it('sizes the shipped instance from the shared per-identity share', () => {
    // Read from the shared constant rather than restated, so raising the share is
    // the only way to raise what one account may hold.
    expect(partUploadUserQuota.limit).toBe(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);
  });
});

describe('holdPartUploadSlot', () => {
  it('releases the slot when the response closes, not when the handler returns', () => {
    const res = fakeResponse();
    let called = false;

    holdPartUploadSlot(anonymousRequest(), res, (() => {
      called = true;
    }) as NextFunction);

    expect(called).toBe(true);
    // Still held while the chain runs. That is the point of the whole arrangement:
    // the slot has to cover the body parse AND the storage call, so releasing it
    // when the middleware returns — which is what `next()` completing means —
    // would bound nothing.
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS - 1);

    res.emit('close');
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    // The identity's share came back on the same event, and the quota forgot the
    // key: both halves of what the request took are handed over at once.
    expect(partUploadUserQuota.keys).toBe(0);
  });

  it('hands the slot straight back when the response closed while the request was queued', async () => {
    // The leak this pins is total and permanent: register the `close` listener
    // AFTER acquiring instead of before, and a client that disconnects while
    // queued is never told to release, so one slot is gone for the life of the
    // process. Repeat that until the budget reaches zero and every part upload in
    // the process hangs for ever, with nothing logged and no request failing.
    const held: (() => void)[] = [];
    for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS; i += 1) {
      partUploadSemaphore.acquire((release) => held.push(release));
    }
    expect(partUploadSemaphore.available).toBe(0);

    const res = fakeResponse();
    let called = false;
    holdPartUploadSlot(anonymousRequest(), res, (() => {
      called = true;
    }) as NextFunction);
    expect(partUploadSemaphore.waiting).toBe(1);

    // The client goes away before a slot ever becomes free.
    res.emit('close');
    for (const release of held) release();

    // The queued request never entered the chain — there is nobody to answer — and
    // the whole budget is back, the identity's share with it.
    expect(called).toBe(false);
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    expect(partUploadSemaphore.waiting).toBe(0);
    expect(partUploadUserQuota.keys).toBe(0);
  });

  it('refuses an identity past its share with 503 and Retry-After, taking no slot', () => {
    const held: { res: EventEmitter & Response }[] = [];
    for (let i = 0; i < MAX_IN_FLIGHT_PART_UPLOADS_PER_USER; i += 1) {
      const res = fakeResponse();
      held.push({ res });
      holdPartUploadSlot(requestFrom('alice'), res, (() => undefined) as NextFunction);
    }
    const availableAtCap = partUploadSemaphore.available;

    const res = fakeResponse();
    let called = false;
    // Declared with the error parameter, because the assertion below reads it:
    // a spy over `() => void` has an empty argument tuple and `calls[0][0]` is
    // then a type error rather than the refusal this case exists to inspect.
    const next = vi.fn((_error?: unknown) => {
      called = true;
    });
    holdPartUploadSlot(requestFrom('alice'), res, next as unknown as NextFunction);

    // The chain is not continued with no error: the request is answered.
    expect(called).toBe(true);
    expect(next.mock.calls[0]![0]).toMatchObject({ statusCode: 503 });
    expect(res.sentHeaders['Retry-After']).toBe('1');

    // THE NEGATIVE, and the reason the charge is taken before `acquire`: the
    // refused request consumed neither a slot nor a place in the queue, so an
    // identity cannot turn its own refusal into a pile of waiting sockets.
    expect(partUploadSemaphore.available).toBe(availableAtCap);
    expect(partUploadSemaphore.waiting).toBe(0);
    expect(partUploadUserQuota.heldBy('alice')).toBe(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER);

    for (const entry of held) entry.res.emit('close');
    res.emit('close');
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    expect(partUploadUserQuota.keys).toBe(0);
  });

  it('charges each identity its own share', () => {
    // The share is per identity, not per process: one account at its cap must not
    // be able to refuse another account's first part.
    const alice = fakeResponse();
    holdPartUploadSlot(requestFrom('alice'), alice, (() => undefined) as NextFunction);
    const bob = fakeResponse();
    let bobContinued = false;
    holdPartUploadSlot(requestFrom('bob'), bob, (() => {
      bobContinued = true;
    }) as NextFunction);

    expect(bobContinued).toBe(true);
    expect(partUploadUserQuota.heldBy('alice')).toBe(1);
    expect(partUploadUserQuota.heldBy('bob')).toBe(1);

    alice.emit('close');
    bob.emit('close');
    expect(partUploadUserQuota.keys).toBe(0);
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
  });

  it('takes nothing, and continues nothing, when the response is already destroyed', () => {
    // The leak this pins is the one `close`-listener-first does NOT cover.
    // `documentPartLimiter` awaits a MongoDB write ahead of this middleware, so a
    // client that disconnects during that await arrives here with a response that
    // is already destroyed — and a `close` listener registered afterwards is never
    // called (measured on Node 24). Charging and acquiring anyway would leak both
    // halves permanently, one pair per abandoned upload.
    const res = fakeResponse(true);
    let called = false;

    holdPartUploadSlot(requestFrom('alice'), res, (() => {
      called = true;
    }) as NextFunction);

    expect(called).toBe(false);
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    expect(partUploadSemaphore.waiting).toBe(0);
    expect(partUploadUserQuota.keys).toBe(0);
  });
});
