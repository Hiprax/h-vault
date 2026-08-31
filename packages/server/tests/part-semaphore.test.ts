/**
 * The part-upload semaphore and the middleware that holds one of its slots.
 *
 * WHAT THIS FILE IS FOR. `document-parts.test.ts` proves the semaphore is mounted
 * where it has to be (ahead of the body parser) by observing the HTTP surface. This
 * file proves the primitive underneath is correct in the cases HTTP cannot easily
 * reach: the order slots are handed out in, that a release is idempotent, that a
 * task releasing synchronously does not recurse, and — the one that would be a
 * production outage rather than a bug — that a caller whose response has already
 * closed hands its slot straight back instead of holding it for ever.
 *
 * The middleware is exercised with minimal `req`/`res` doubles rather than through
 * supertest, deliberately: what it does is wire an `EventEmitter` event to a
 * release, and the failure being pinned is a LEAK, which is a statement about the
 * semaphore's counter rather than about a response body. Nothing here mocks the
 * unit under test; the semaphore and the middleware are both real.
 */
import { EventEmitter } from 'node:events';
import { describe, it, expect } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import { MAX_IN_FLIGHT_PART_UPLOADS } from '@hvault/shared';
import { createSemaphore, partUploadSemaphore } from '../src/utils/partSemaphore.js';
import { holdPartUploadSlot } from '../src/middleware/documentPartBody.js';

/** A `res` that is only what the middleware touches: an emitter with `once`. */
function fakeResponse(): EventEmitter & Response {
  return new EventEmitter() as EventEmitter & Response;
}

const NO_REQUEST = {} as Request;

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

describe('holdPartUploadSlot', () => {
  it('releases the slot when the response closes, not when the handler returns', () => {
    const res = fakeResponse();
    let called = false;

    holdPartUploadSlot(NO_REQUEST, res, (() => {
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
    holdPartUploadSlot(NO_REQUEST, res, (() => {
      called = true;
    }) as NextFunction);
    expect(partUploadSemaphore.waiting).toBe(1);

    // The client goes away before a slot ever becomes free.
    res.emit('close');
    for (const release of held) release();

    // The queued request never entered the chain — there is nobody to answer — and
    // the whole budget is back.
    expect(called).toBe(false);
    expect(partUploadSemaphore.available).toBe(MAX_IN_FLIGHT_PART_UPLOADS);
    expect(partUploadSemaphore.waiting).toBe(0);
  });
});
