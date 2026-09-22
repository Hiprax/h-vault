import type { NextFunction, Response } from 'express';
import type { KeyedQuota, Semaphore } from '../utils/partSemaphore.js';

/**
 * The mechanics of holding a slot in a process-wide memory budget from BEFORE a
 * body is read, shared by the two middlewares that do it: the part-upload slot
 * holder (`middleware/documentPartBody.ts`) and the large-body slot holder
 * (`middleware/largeBodyAdmission.ts`).
 *
 * They differ in what happens AROUND the slot, which is what the hooks carry: how a
 * request past its share is answered, what arms when a slot is granted, and when a
 * closed response may hand its slot back. Every step below is shared because each
 * one is a leak or a wasted slot when it is got wrong, and two copies of it would be
 * two places to get it wrong:
 *
 *   1. `res.destroyed` FIRST. The middlewares ahead of a holder await MongoDB round
 *      trips (`authenticate` reads the user on every request, a limiter writes its
 *      counter in production), so a client that disconnects during one arrives here
 *      with `close` ALREADY fired, and a listener added now would never run. Nothing
 *      is charged or taken for it, and the chain stops: there is nobody to answer.
 *   2. The identity's SHARE is charged before the slot is even requested, so it
 *      bounds QUEUED requests as well as granted ones. A request past it is refused
 *      at once, holding nothing.
 *   3. The `close` listener is registered BEFORE `acquire`. A queued request whose
 *      client disconnects would otherwise have no listener when `close` fires, and
 *      the slot it is later granted would never come back.
 *   4. A slot granted to a request that closed while it waited is handed straight
 *      back, and the chain does not continue.
 *   5. `next()` runs SYNCHRONOUSLY inside the grant, after the `granted` hook, so
 *      whatever the hook arms is armed before the parser starts reading.
 *
 * The quota and the semaphore are read through `admission` at CALL time rather than
 * captured, so the module-level instances each holder passes stay the live objects
 * a test can observe.
 */
export interface SlotAdmission {
  readonly semaphore: Semaphore;
  readonly quota: KeyedQuota;
  /** Who the share is charged to. */
  readonly identity: string;
  /** Answers a request whose identity already holds its share. Nothing is held by then. */
  readonly refuse: (res: Response, next: NextFunction) => void;
  /** Runs once a LIVE request holds its slot, immediately before `next()`. */
  readonly granted: () => void;
  /**
   * Runs once when the response closes, with the function that hands back both the
   * share and the slot (idempotent). A hook that must keep them past `close` calls
   * it later; one that need not calls it now.
   */
  readonly closed: (release: () => void) => void;
}

export function admitWithinBudget(
  res: Response,
  next: NextFunction,
  admission: SlotAdmission,
): void {
  if (res.destroyed) return;

  const releaseShare = admission.quota.charge(admission.identity);
  if (releaseShare === null) {
    admission.refuse(res, next);
    return;
  }

  let releaseSlot: (() => void) | undefined;
  let closed = false;

  res.once('close', () => {
    closed = true;
    admission.closed(() => {
      releaseShare();
      releaseSlot?.();
    });
  });

  admission.semaphore.acquire((grantedRelease) => {
    releaseSlot = grantedRelease;
    if (closed) {
      // The response ended while this request was queued. The share was already
      // handed back by the `close` listener above; hand the slot back too.
      grantedRelease();
      return;
    }
    admission.granted();
    next();
  });
}
