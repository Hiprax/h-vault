/**
 * Harness-level outbound-network block for the server suite.
 *
 * Today the only outbound call in production is the HIBP range lookup, and the
 * two suites that exercise it intercept `axios.get` per test — correctly, and
 * with negative `not.toHaveBeenCalled()` assertions. But a per-test stub is a
 * promise each test makes individually: the next suite that forgets one reaches
 * `https://api.pwnedpasswords.com` for real, and then the verdict of a "unit"
 * gate depends on a third party's uptime, rate limits and DNS. A test that
 * breaks when the network is unavailable was never a unit test.
 *
 * So the block lives in the harness, where forgetting is not an option:
 *
 *   • `http.request` / `https.request` (and their `get` shorthands) — the
 *     transport axios and every Node HTTP client uses. Patched here because the
 *     request options still name the HOST, so the error can say which host was
 *     attempted instead of leaving a bare ECONNREFUSED.
 *   • `net.Socket.prototype.connect` — the FLOOR, and the layer that actually
 *     holds: it is a prototype method resolved at call time, so no import form,
 *     `http2` or `tls.connect` can side-step it. It lives in
 *     `tests/harness/socketEgress.ts` because all three tiers need identical
 *     semantics, and this module re-exports it so a test can keep importing
 *     `./egressGuard.js`.
 *
 * Loopback is allowed: the suite's whole point is a real mongod on 127.0.0.1 and
 * a real Express app under supertest, both of which are local sockets. A unix
 * domain socket is allowed for the same reason — it cannot leave the machine.
 */
import http from 'node:http';
import https from 'node:https';
import {
  EgressBlockedError,
  installSocketEgressGuard,
  isEgressSuspended,
  isLocalHost,
} from '../../../tests/harness/socketEgress.js';

// Re-exported so every consumer keeps one import path for the guard, whichever
// layer refused the connection.
export { EgressBlockedError, withEgressAllowed } from '../../../tests/harness/socketEgress.js';

function hostFromHttpArgs(args: unknown[]): string {
  for (const arg of args) {
    if (typeof arg === 'string') {
      try {
        return new URL(arg).hostname;
      } catch {
        return arg;
      }
    }
    if (arg instanceof URL) return arg.hostname;
    if (arg !== null && typeof arg === 'object') {
      const opts = arg as { hostname?: unknown; host?: unknown };
      if (typeof opts.hostname === 'string') return opts.hostname;
      if (typeof opts.host === 'string') return opts.host.split(':')[0] ?? opts.host;
    }
  }
  // Node's own default when `options` carries no host, and what the socket layer
  // in this file already assumes. Returning a sentinel here instead blocked
  // `http.request({ port, path })` — a purely local call — with a misleading
  // message about a host nobody named.
  return 'localhost';
}

let installed = false;

/**
 * Installs the block. Idempotent, so a second setup file (or a re-import) cannot
 * double-wrap the transports and produce a misleading stack.
 */
export function installEgressGuard(): void {
  if (installed) return;
  installed = true;

  const patchHttpModule = (module: typeof http | typeof https, label: string): void => {
    const originalRequest = module.request.bind(module);
    const originalGet = module.get.bind(module);

    const guard = (
      original: (...args: never[]) => unknown,
      via: string,
    ): ((...args: unknown[]) => unknown) => {
      return function guarded(...args: unknown[]): unknown {
        if (!isEgressSuspended()) {
          const host = hostFromHttpArgs(args);
          if (!isLocalHost(host)) throw new EgressBlockedError(host, via);
        }
        return (original as (...inner: unknown[]) => unknown)(...args);
      };
    };

    // The cast is confined to these two assignments: Node types `request`/`get`
    // with several overloads that a single variadic wrapper cannot satisfy
    // structurally, and the wrapper genuinely forwards every argument shape.
    (module as { request: unknown }).request = guard(
      originalRequest as unknown as (...args: never[]) => unknown,
      `${label}.request`,
    );
    (module as { get: unknown }).get = guard(
      originalGet as unknown as (...args: never[]) => unknown,
      `${label}.get`,
    );
  };

  patchHttpModule(http, 'http');
  patchHttpModule(https, 'https');

  // The socket floor, shared with the client and shared tiers.
  installSocketEgressGuard();
}
