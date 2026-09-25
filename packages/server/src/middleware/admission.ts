import type { NextFunction, Request, Response } from 'express';
import { httpErrors } from '@hiprax/errors';
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
 *
 * WHEN a slot comes back is the other half, and both holders need the same answer:
 * see {@link createHandlerSettledRelease}.
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

/**
 * What a slot holder and its handler wrapper share for one request: whether the
 * handler is running, and the release a `close` during it had to defer.
 */
interface SlotTicket {
  inHandler: boolean;
  releaseWhenSettled: (() => void) | null;
}

/** The shape `catchAsync` hands back, which is what every wrapped route mounts. */
export type SlotHandler = (req: Request, res: Response, next: NextFunction) => unknown;

/**
 * A slot is handed back once the response has closed AND the handler has SETTLED,
 * never on `close` alone. One of these per holder: its `granted` hook calls
 * `admit`, its `closed` hook calls `closed`, and the route's handler is mounted
 * through `run`, last in the chain.
 *
 * WHY `close` ALONE IS NOT THE END. A client that aborts mid-request closes the
 * response while the handler is still running, and Express does not cancel a
 * handler: it keeps the body it was handed, and whatever it allocates from it, until
 * its own work returns. Released on `close`, the slot would let one account send a
 * whole body, drop the connection, and send the next, with every one of them
 * resident at once; the budget would bound connections, not memory. So a `close`
 * that arrives while the handler runs DEFERS the release to the moment it settles,
 * and a `close` before the handler was reached (a refusal from the parser, a request
 * that waited in the queue) releases at once.
 *
 * Keyed by the response in a `WeakMap`, so a ticket lives exactly as long as its
 * request.
 */
export interface HandlerSettledRelease {
  /** From the holder's `granted` hook: this response now holds a slot its handler may keep. */
  readonly admit: (res: Response) => void;
  /** From the holder's `closed` hook: release now, or when this response's handler settles. */
  readonly closed: (res: Response, release: () => void) => void;
  /**
   * Wraps a route's handler. A handler reached with no ticket means the chain in
   * front of it is wrong (the holder is missing, or sits after this), and it is
   * refused with 500 carrying `unadmittedMessage` rather than run: running it would
   * be running an operation that no budget counted. `tests/route-table.test.ts` is
   * what keeps the chain right; this is what makes a wrong one fail CLOSED rather
   * than silently unbounded.
   */
  readonly run: (
    handler: SlotHandler,
    req: Request,
    res: Response,
    next: NextFunction,
    unadmittedMessage: string,
  ) => Promise<void>;
}

export function createHandlerSettledRelease(): HandlerSettledRelease {
  const tickets = new WeakMap<Response, SlotTicket>();
  return {
    admit(res) {
      tickets.set(res, { inHandler: false, releaseWhenSettled: null });
    },
    closed(res, release) {
      const ticket = tickets.get(res);
      if (ticket?.inHandler === true) ticket.releaseWhenSettled = release;
      else release();
    },
    async run(handler, req, res, next, unadmittedMessage) {
      const ticket = tickets.get(res);
      if (ticket === undefined) {
        next(httpErrors.internalServerError(unadmittedMessage));
        return;
      }
      ticket.inHandler = true;
      try {
        await handler(req, res, next);
      } finally {
        ticket.inHandler = false;
        ticket.releaseWhenSettled?.();
      }
    },
  };
}
