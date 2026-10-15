import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/** Where the HTTP server listens: `PORT` and `HOST` from the configuration. */
export interface ListenAddress {
  port: number;
  host: string;
}

/**
 * Opens the server's listening socket on `HOST` (loopback unless configured).
 *
 * The host is ALWAYS passed: `server.listen(port)` without one binds every
 * interface, which is how the server listened before `HOST` existed, and is
 * exactly what the default now refuses to do. `tests/listen-address.test.ts` reads
 * the bound address back from a real socket.
 */
export function listenOn(server: Server, address: ListenAddress, onListening: () => void): Server {
  return server.listen(address.port, address.host, onListening);
}

/**
 * The address a listening server is ACTUALLY bound to, as the kernel reports it
 * (`server.address()`), in the form the boot log prints: `127.0.0.1:5000`,
 * `[::]:5000`. The boot log names this rather than the configured `HOST`, so a
 * regression that stops passing the host (and binds every interface) shows up in
 * the one line the smoke gate checks, instead of being hidden behind a log line
 * that repeats the configuration.
 */
export function describeBoundAddress(address: string | AddressInfo | null): string {
  if (address === null) return 'no address (not listening)';
  if (typeof address === 'string') return address;
  return address.family === 'IPv6'
    ? `[${address.address}]:${String(address.port)}`
    : `${address.address}:${String(address.port)}`;
}
