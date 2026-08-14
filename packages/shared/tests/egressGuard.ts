/**
 * This package's view of the harness egress block.
 *
 * The shared package is pure schema and constant code, so it has no HTTP client to
 * patch and needs only the socket FLOOR — which is also the strongest single layer:
 * `fetch` in Node reaches undici, which reaches `net.Socket.prototype.connect`, so
 * one prototype replacement covers every route out of the process.
 *
 * It gets a guard for the same reason the other two do. "This package does not use
 * the network" is a property of today's code, not of the harness, and Phase 9 is
 * about to add property-based tests here; a suite that CAN reach a third party
 * eventually does.
 */
export {
  EgressBlockedError,
  installSocketEgressGuard,
  withEgressAllowed,
} from '../../../tests/harness/socketEgress.js';
