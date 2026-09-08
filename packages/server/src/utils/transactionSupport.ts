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
 * callers can be driven against a real `MongoMemoryReplSet` in tests.
 *
 * **This is the only definition, and that is enforced.** The check had been
 * copied into four other modules — `utils/cascadeDelete.ts` re-exported it under
 * this same name, and the folder, user and auth controllers each inlined the
 * expression — so "centralizing it keeps the replica-set detection consistent
 * across call sites" described an intention rather than the code. Every caller
 * now imports this function, and `tests/topology-predicate.test.ts` fails if a
 * module reads the driver's `replicaSet` option beside a `readyState`, or
 * declares this name, anywhere else. The reason it matters: each caller writes
 * across several collections and this predicate decides whether that write is
 * atomic, so a divergent copy puts an un-fixed caller on the wrong path, and the
 * wrong path here is a partial write to a vault.
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
