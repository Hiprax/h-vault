import mongoose from 'mongoose';

/**
 * Check whether the active MongoDB topology supports multi-document
 * transactions (i.e. a replica set or sharded cluster). A standalone server —
 * including the in-memory server used by the default test suite — rejects
 * transactions, so callers fall back to a non-transactional path when this
 * returns `false`.
 *
 * Exported (and parameterized on the connection) so it can be exercised in
 * isolation with a fabricated connection and so the transaction branch of
 * callers can be driven against a real `MongoMemoryReplSet` in tests. Mirrors
 * the topology check previously inlined in the vault controller; centralizing
 * it keeps the replica-set detection consistent across call sites.
 *
 * @param connection - Connection to inspect. Defaults to the shared
 *   `mongoose.connection` used throughout the app.
 */
export function supportsTransactions(
  connection: mongoose.Connection = mongoose.connection,
): boolean {
  return (
    connection.readyState === mongoose.ConnectionStates.connected &&
    Boolean(connection.getClient().options.replicaSet)
  );
}
