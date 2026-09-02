/**
 * The crash probe's STORAGE channel: the child speaks the storage port, the
 * parent's double answers, and the parent therefore sees the exact bucket state a
 * killed process left behind.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS AT ALL
 * ---------------------------------------------------------------------------
 *
 * Every document route sits behind `requireStorage`, and every document
 * controller calls `getStorage()`. The crash CHILD is a real separate process, so
 * the `vi.mock('../src/services/storage/index.js')` that every in-process document
 * suite uses cannot reach it, and an ESM export cannot be monkeypatched from
 * outside its module. An in-memory double built INSIDE the child is no use either:
 * it dies with the child, and what these drills assert is precisely what the
 * bucket holds AFTERWARDS.
 *
 * So the child gets a proxy and the parent keeps the state. One implementation
 * (`tests/helpers/inMemoryStorage.ts`, the same double the push tier uses and the
 * same one `tests/storage-contract.test.ts` pins), one copy of the bucket, and a
 * transport in between. This module is that transport and nothing else: it holds
 * no storage semantics of its own, so it cannot drift from the double the way a
 * second implementation would.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT A REAL ENGINE IN A CONTAINER
 * ---------------------------------------------------------------------------
 *
 * Because `tests/recovery/**` is NOT in `vitest.config.ts`'s `exclude` list, which
 * carries only `tests/resource/**` and `tests/storage/**`. Every file in this
 * directory therefore ALSO runs inside `test:integration` on every push, and that
 * task declares `requires: ["build:shared"]` — no Docker. Starting the pinned
 * storage engine here would either make the ordinary server suite fail on a
 * machine with no daemon (the exact outcome `vitest.config.ts`'s own comment says
 * that exclusion exists to prevent: "a suite that fails when a daemon is not
 * running is a suite people learn to distrust") or force `tests/recovery/**` out of
 * the push tier, which would quietly remove the disaster drills from every push.
 * The real engine runs the same port through the same shared contract in
 * `test:storage`, which is where the Docker prerequisite is declared and honest.
 *
 * ---------------------------------------------------------------------------
 * TWO THINGS HERE ARE LOAD-BEARING
 * ---------------------------------------------------------------------------
 *
 *  a. AN ERROR IS RECONSTRUCTED FROM A STATUS CODE, NEVER SHIPPED. Node's advanced
 *     serialization carries an `Error`, but it explicitly does NOT carry properties
 *     set on objects of built-in types — and `ErrorHandler extends Error` with its
 *     `statusCode` as an own property. A round-tripped 404 would therefore arrive
 *     as a bare `Error` with no `statusCode` and no class identity, and
 *     `isStorageNotFound()` — which the controller and the collector both use to
 *     decide whether "it is already gone" counts as success — would answer FALSE.
 *     So the wire carries `{ok:false, statusCode, message}` and the child rebuilds
 *     the error with the matching `httpErrors` factory.
 *
 *  b. THE REPLY MUST NEVER OUTLIVE THE CHILD NOISILY. A probe dies by SIGKILL, so
 *     a reply can be in flight when the channel disappears; an unguarded
 *     `child.send()` then raises `ERR_IPC_CHANNEL_CLOSED` on the parent's
 *     `ChildProcess`, which `crashProbe`'s `error` listener would report as a
 *     spawn failure. Every send is guarded by `connected` and every send callback
 *     swallows a closed channel, and `crashProbe` resolves once so `close` wins.
 */
import type { ChildProcess } from 'node:child_process';
import { Readable } from 'node:stream';
import { ErrorHandler, httpErrors } from '@hiprax/errors';
import type { StorageProvider } from '../../src/services/storage/types.js';

/** The method names the bridge proxies: the storage port, exactly. */
const PORT_METHODS = [
  'headBucket',
  'putObject',
  'headObject',
  'getObjectRange',
  'deleteObject',
  'listObjects',
  'createMultipartUpload',
  'uploadPart',
  'completeMultipartUpload',
  'abortMultipartUpload',
  'listParts',
  'listMultipartUploads',
] as const satisfies readonly (keyof StorageProvider)[];

type PortMethod = (typeof PORT_METHODS)[number];

/**
 * The list above IS the port, checked by the compiler in BOTH directions.
 *
 * `satisfies` catches a name that is not on the port. The constant below catches
 * the direction that actually costs something: a port method the bridge does not
 * proxy. Add one to `StorageProvider` without adding it here and the crash child
 * keeps the REAL S3 provider's implementation of it, pointed at the unreachable
 * endpoint `crashProbe.ts` configures — so the drill would fail with a connection
 * error instead of saying the bridge is incomplete. The `as unknown as
 * StorageProvider` cast at the foot of this file is what makes that possible, which
 * is why the exhaustiveness is asserted rather than left to it.
 */
const _portSurfaceIsExhaustive: Exclude<keyof StorageProvider, PortMethod> extends never
  ? true
  : false = true;
void _portSurfaceIsExhaustive;

/** A call travelling child to parent. */
interface BridgeCall {
  kind: 'hv-storage-call';
  id: number;
  method: PortMethod;
  args: unknown[];
}

/** A reply travelling parent to child. */
type BridgeReply =
  | { kind: 'hv-storage-reply'; id: number; ok: true; value: unknown }
  | { kind: 'hv-storage-reply'; id: number; ok: false; statusCode: number; message: string };

const isCall = (message: unknown): message is BridgeCall =>
  typeof message === 'object' &&
  message !== null &&
  (message as { kind?: unknown }).kind === 'hv-storage-call';

const isReply = (message: unknown): message is BridgeReply =>
  typeof message === 'object' &&
  message !== null &&
  (message as { kind?: unknown }).kind === 'hv-storage-reply';

/**
 * `getObjectRange` is the one method whose result is not serialisable.
 *
 * The port returns `{ body: Readable, bytes }`, and a stream cannot cross a
 * process boundary. The parent drains it to a `Buffer` (a range is one segment, so
 * this is bounded by the framing rather than by the object) and the child wraps the
 * buffer back into a `Readable`, which is what the segment route pipes to its
 * response. Nothing else about the call changes.
 */
const RANGE_METHOD: PortMethod = 'getObjectRange';

async function drain(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// The parent half
// ---------------------------------------------------------------------------

/**
 * Answers the child's storage calls from `provider`, for as long as the child
 * lives.
 *
 * Returns a disposer, so a test that finished with a probe stops listening rather
 * than leaving a handler on a dead process.
 */
export function serveStorageOverIpc(child: ChildProcess, provider: StorageProvider): () => void {
  const reply = (payload: BridgeReply): void => {
    // (b) Both halves of the guard are needed: `connected` closes the ordinary
    // race, and the callback closes the one where the channel dies between the
    // check and the write.
    if (!child.connected) return;
    child.send(payload, undefined, undefined, () => {
      /* the child is gone; that is the expected end of a crash probe */
    });
  };

  const onMessage = (message: unknown): void => {
    if (!isCall(message)) return;
    void (async (): Promise<void> => {
      try {
        const fn = provider[message.method] as (...args: unknown[]) => Promise<unknown>;
        const value = await fn.apply(provider, message.args);
        if (message.method === RANGE_METHOD) {
          const range = value as { body: Readable; bytes: number };
          reply({
            kind: 'hv-storage-reply',
            id: message.id,
            ok: true,
            value: { body: await drain(range.body), bytes: range.bytes },
          });
          return;
        }
        reply({ kind: 'hv-storage-reply', id: message.id, ok: true, value });
      } catch (error) {
        // (a) The STATUS, never the error object. `isStorageNotFound` reads
        // `instanceof ErrorHandler && statusCode === 404`, and neither survives
        // structured cloning.
        const statusCode = error instanceof ErrorHandler ? error.statusCode : 500;
        const message_ = error instanceof Error ? error.message : String(error);
        reply({
          kind: 'hv-storage-reply',
          id: message.id,
          ok: false,
          statusCode,
          message: message_,
        });
      }
    })();
  };

  child.on('message', onMessage);
  return () => {
    child.off('message', onMessage);
  };
}

// ---------------------------------------------------------------------------
// The child half
// ---------------------------------------------------------------------------

/**
 * A `StorageProvider` that forwards every call to the parent.
 *
 * Used only by `crashChild.ts`, which installs it over the memoised provider
 * `getStorage()` built — see the note there for why mutating that object is the
 * injection seam rather than a trick.
 */
export function createIpcStorageClient(): StorageProvider {
  const send = process.send?.bind(process);
  if (!send) {
    throw new Error('the storage bridge needs an IPC channel; the probe was spawned without one');
  }

  const pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (e: unknown) => void }
  >();
  let nextId = 0;

  process.on('message', (message: unknown) => {
    if (!isReply(message)) return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.ok) {
      waiter.resolve(message.value);
      return;
    }
    // (a) Rebuilt here, so the caller sees the SAME error this codebase would
    // have thrown: `isStorageNotFound` recognises the 404, and a 503 still reads
    // as an unreachable engine rather than as a defect.
    if (message.statusCode === 404) waiter.reject(httpErrors.notFound(message.message));
    else if (message.statusCode === 503)
      waiter.reject(httpErrors.serviceUnavailable(message.message));
    else waiter.reject(httpErrors.internalServerError(message.message));
  });

  const call = async (method: PortMethod, args: unknown[]): Promise<unknown> => {
    const id = (nextId += 1);
    const payload: BridgeCall = { kind: 'hv-storage-call', id, method, args };
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      send(payload);
    });
  };

  const client: Record<string, unknown> = {};
  for (const method of PORT_METHODS) {
    client[method] =
      method === RANGE_METHOD
        ? async (...args: unknown[]): Promise<unknown> => {
            const range = (await call(method, args)) as { body: Uint8Array; bytes: number };
            return { body: Readable.from([Buffer.from(range.body)]), bytes: range.bytes };
          }
        : async (...args: unknown[]): Promise<unknown> => call(method, args);
  }
  return client as unknown as StorageProvider;
}
