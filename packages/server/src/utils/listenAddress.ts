import type { Server } from 'node:http';

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
