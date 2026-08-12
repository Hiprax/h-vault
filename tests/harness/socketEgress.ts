/**
 * The socket-level half of the harness egress block, shared by every tier.
 *
 * This is the FLOOR, and it is the layer that actually holds. Patching
 * `http.request` / `https.request` / `fetch` / `XMLHttpRequest` names the host in
 * the error, which is worth having, but each of those is one named entry point
 * among several: `import { request } from 'node:http'` binds the original function
 * before any setup file runs (Node snapshots a builtin's named exports when the
 * module namespace is first created), and `http2`, `tls.connect` and a raw
 * `net.Socket` bypass them entirely. Every one of those still has to open a TCP
 * connection, and every TCP connection in Node goes through
 * `net.Socket.prototype.connect` — a PROTOTYPE method, resolved at call time, so a
 * replacement here cannot be side-stepped by an import form.
 *
 * It lives at the repo root because all three packages need identical semantics.
 * The client tier previously had no socket layer at all, which meant its guard
 * could be walked around by any of the routes above; the shared tier had no guard
 * whatsoever.
 *
 * Loopback and unix domain sockets stay allowed: the suites run a real mongod on
 * 127.0.0.1 and a real Express app under supertest, and neither a loopback socket
 * nor a filesystem socket can make a verdict depend on a third party.
 */
import net from 'node:net';

/**
 * Thrown instead of opening the connection. A named class rather than a bare
 * `Error` so a test can assert the block fired, and so a failure log points at the
 * cause instead of reading like a flaky network.
 */
export class EgressBlockedError extends Error {
  override readonly name = 'EgressBlockedError';

  constructor(
    readonly host: string,
    readonly via: string,
  ) {
    super(
      `EgressBlockedError: the test harness blocked an outbound network request to ` +
        `"${host}" (via ${via}). The unit tier must not reach a third party: stub the ` +
        `client (e.g. vi.spyOn(axios, 'get'), or vi.mock of the api module) and assert ` +
        `on the stub instead.`,
    );
  }
}

/** Everything on this machine. Nothing here can introduce a third-party dependency. */
export function isLocalHost(host: string): boolean {
  const bare = host.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
  if (bare === 'localhost' || bare === '::1' || bare === '::ffff:127.0.0.1') return true;
  // The whole 127/8 loopback block, not just 127.0.0.1: mongod and
  // mongodb-memory-server both use it, and `0.0.0.0` resolves to a local interface.
  if (bare === '0.0.0.0' || bare === '') return true;
  return /^127(\.\d{1,3}){3}$/.test(bare);
}

/**
 * Extracts the host from the three shapes `Socket.prototype.connect` receives.
 *
 * `undefined` means "not a TCP connection to a named host" — a unix domain socket,
 * which cannot leave the machine. Exported so the third shape can be pinned by a
 * test: `net.connect()` normalizes its arguments into an ARRAY before calling the
 * prototype method, and that is the shape undici (and therefore `fetch`) always
 * uses. A version that understood only the plain options object read no host at
 * all, defaulted to "localhost", and allowed every outbound socket while still
 * looking installed.
 */
export function hostFromConnectArgs(args: unknown[]): string | undefined {
  const first = Array.isArray(args[0]) ? (args[0] as unknown[])[0] : args[0];
  const second = Array.isArray(args[0]) ? (args[0] as unknown[])[1] : args[1];

  if (typeof first === 'object' && first !== null) {
    const opts = first as { host?: unknown; path?: unknown };
    if (typeof opts.path === 'string') return undefined;
    if (typeof opts.host === 'string') return opts.host;
    return 'localhost';
  }
  if (typeof second === 'string') return second;
  return 'localhost';
}

/**
 * Suspension depth, not a boolean: a counter cannot be left `false` by a nested
 * or re-entrant caller, and the `finally` in {@link withEgressAllowed} restores
 * exactly the depth it added.
 *
 * The suspension is process-global rather than per async context. That is safe
 * only because its one legitimate caller is a serialized `beforeAll`; anything
 * that suspended concurrently with a test would open a hole. Keep it that way.
 */
let suspended = 0;
let socketPatched = false;

/**
 * Runs `fn` with egress allowed.
 *
 * Exactly one thing is legitimate here: provisioning the local test database.
 * `mongodb-memory-server` downloads the mongod binary from `fastdl.mongodb.org`
 * on a machine that has not cached it, and blocking that leaves a fresh clone
 * unable to run the suite at all — a harness that cannot start is not a stricter
 * harness. The download lands in `node_modules/.cache`, is an artifact fetch
 * rather than behaviour under test, and no assertion depends on its content.
 */
export async function withEgressAllowed<T>(fn: () => Promise<T>): Promise<T> {
  suspended += 1;
  try {
    return await fn();
  } finally {
    suspended -= 1;
  }
}

/** Whether the guard is currently letting connections through. */
export function isEgressSuspended(): boolean {
  return suspended > 0;
}

/**
 * Replaces `net.Socket.prototype.connect`. Idempotent, so a second setup file or a
 * re-import cannot double-wrap it and produce a misleading stack.
 */
export function installSocketEgressGuard(): void {
  if (socketPatched) return;
  socketPatched = true;

  const originalConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function connect(
    this: net.Socket,
    ...args: unknown[]
  ): net.Socket {
    if (suspended === 0) {
      const host = hostFromConnectArgs(args);
      if (host !== undefined && !isLocalHost(host)) {
        throw new EgressBlockedError(host, 'net.Socket.connect');
      }
    }
    return (
      originalConnect as unknown as (this: net.Socket, ...inner: unknown[]) => net.Socket
    ).apply(this, args);
  } as typeof net.Socket.prototype.connect;
}
