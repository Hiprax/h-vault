/**
 * Harness-level outbound-network block for the client suite.
 *
 * The client tier never legitimately reaches the network: every API module is
 * stubbed per test, and jsdom loads no external resources by default. That is a
 * promise each test file makes individually, though, and the first one that
 * forgets a stub turns a unit gate into a check on somebody else's uptime. So the
 * block lives in the harness, where forgetting is not an option.
 *
 * jsdom needs different patch points than Node:
 *
 *   • `fetch` — what the app itself would use, and what undici backs.
 *   • `XMLHttpRequest.prototype.open` — axios picks its XHR adapter whenever
 *     `XMLHttpRequest` exists, which it does under jsdom, so this is the path a
 *     forgotten axios stub actually takes. Patched at `open` rather than `send`
 *     because that is where the URL is still available to name.
 *   • `http.request` / `https.request` — jsdom's XHR performs the real transfer
 *     through Node's http module, so this catches anything that reaches for Node
 *     directly and names the host while doing so.
 *   • `net.Socket.prototype.connect` — the FLOOR, from
 *     `tests/harness/socketEgress.ts`, shared with the other two tiers. The four
 *     patches above are all named entry points, and each can be side-stepped:
 *     `import { request } from 'node:http'` binds the original before any setup
 *     file runs, and `http2` / `tls.connect` / a raw socket never touch them. Every
 *     one of them still has to open a TCP connection.
 *
 * Loopback stays allowed: a component test may drive a URL at `localhost`, and
 * nothing local can make the suite depend on a third party.
 */
import http from 'node:http';
import https from 'node:https';
import {
  EgressBlockedError,
  installSocketEgressGuard,
  isLocalHost,
} from '../../../tests/harness/socketEgress.js';

// Re-exported so a test keeps one import path for the guard, whichever layer
// refused the connection.
export { EgressBlockedError } from '../../../tests/harness/socketEgress.js';

/**
 * jsdom resolves a relative URL against `location.href`, which is
 * `http://localhost:3000/` here, so a relative `/api/v1/...` is loopback and
 * allowed — exactly as a component test expects.
 */
function hostOf(target: unknown): string {
  if (target instanceof URL) return target.hostname;
  const asString = typeof target === 'string' ? target : String(target);
  try {
    const base = typeof location === 'undefined' ? undefined : location.href;
    return new URL(asString, base).hostname;
  } catch {
    return asString;
  }
}

function hostFromHttpArgs(args: unknown[]): string {
  for (const arg of args) {
    if (typeof arg === 'string' || arg instanceof URL) return hostOf(arg);
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

/** Installs the block. Idempotent, so a re-imported setup cannot double-wrap. */
export function installEgressGuard(): void {
  if (installed) return;
  installed = true;

  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === 'function') {
    globalThis.fetch = function guardedFetch(
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ): Promise<Response> {
      const target =
        typeof input === 'string' || input instanceof URL ? input : (input as Request).url;
      const host = hostOf(target);
      if (!isLocalHost(host)) {
        // Rejects rather than throws synchronously: `fetch` is specified to
        // return a promise, and a synchronous throw here would surface as a
        // different failure shape than a real network error would.
        return Promise.reject(new EgressBlockedError(host, 'fetch'));
      }
      return originalFetch(input, init);
    } as typeof fetch;
  }

  if (typeof XMLHttpRequest !== 'undefined') {
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function guardedOpen(
      this: XMLHttpRequest,
      ...args: unknown[]
    ): void {
      const host = hostOf(args[1]);
      if (!isLocalHost(host)) throw new EgressBlockedError(host, 'XMLHttpRequest.open');
      (originalOpen as unknown as (this: XMLHttpRequest, ...inner: unknown[]) => void).apply(
        this,
        args,
      );
    } as typeof XMLHttpRequest.prototype.open;
  }

  for (const [module, label] of [
    [http, 'http'],
    [https, 'https'],
  ] as const) {
    for (const method of ['request', 'get'] as const) {
      const original = module[method].bind(module) as unknown as (...args: unknown[]) => unknown;
      // The cast is confined to this assignment: Node types `request`/`get` with
      // several overloads a single variadic wrapper cannot satisfy structurally,
      // and the wrapper forwards every argument shape unchanged.
      (module as unknown as Record<string, unknown>)[method] = function guarded(
        ...args: unknown[]
      ): unknown {
        const host = hostFromHttpArgs(args);
        if (!isLocalHost(host)) throw new EgressBlockedError(host, `${label}.${method}`);
        return original(...args);
      };
    }
  }

  // The socket floor, shared with the server and shared tiers.
  installSocketEgressGuard();
}
