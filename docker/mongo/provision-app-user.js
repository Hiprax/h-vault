// =============================================================================
// H-Vault — application database user provisioning (mongosh script)
// =============================================================================
// Creates the least-privilege account the application and the index bootstrap
// authenticate as, so neither of them ever holds cluster root.
//
// The user is created IN the `hvault` database and granted the built-in
// `readWrite` role on `hvault` and nothing else — no `admin` database, no
// cluster privileges, no second database. That is the exact ceiling the server
// needs: every operation it performs is CRUD, index creation, or a cursor over
// a `hvault` collection. Two of those are easy to overlook and are why the role
// can never be narrowed below `readWrite`:
//
//   * `createIndex` is a HARD boot requirement, not a nicety. `runMigrations()`
//     is awaited during startup and its first act is `ensureLockIndexes()`,
//     which runs on every boot with no local try/catch — an unauthorized
//     `createIndexes` there kills the process before it listens.
//   * The rate-limit store creates its own TTL index lazily on the `rateLimits`
//     collection, which the model-driven bootstrap never touches.
//
// The one command the app sends outside `hvault` is `hello` against `admin`,
// which MongoDB exempts from authorization entirely — so it needs no grant here.
//
// Run as a one-shot by the `hvault-db-init` service, which is gated on
// `hvault-db: service_healthy`; that healthcheck ends on `isWritablePrimary`, so
// this script is guaranteed a writable primary (createUser is a write).
//
// IDEMPOTENCE, and what it deliberately does NOT do: on every later `up` this
// reconciles the user's ROLES but never rewrites an existing password, because
// `db.updateUser()` replaces only the fields present in the update document and
// `pwd` is omitted below. An operator who rotated the password inside the
// database keeps it. The corollary is that changing MONGO_APP_PASSWORD in .env
// alone does NOT re-sync it — rotate inside the database first, exactly as the
// root password already behaves.
//
// Both secrets are read from the environment and authenticated in-script rather
// than passed as --username/--password, so neither ever appears in the
// container's argv (where `docker inspect` and the process table would show it).

const rootUser = process.env.MONGO_ROOT_USERNAME;
const rootPass = process.env.MONGO_ROOT_PASSWORD;
const appUser = process.env.MONGO_APP_USERNAME;
const appPass = process.env.MONGO_APP_PASSWORD;

if (!rootUser || !rootPass) {
  print('[hvault-db-init] MONGO_ROOT_USERNAME and MONGO_ROOT_PASSWORD are required');
  quit(1);
}
if (!appUser || !appPass) {
  print('[hvault-db-init] MONGO_APP_USERNAME and MONGO_APP_PASSWORD are required');
  quit(1);
}

// Authenticate as root against `admin`, where MONGO_INITDB_ROOT_* created it.
// A failure throws, mongosh exits non-zero, and `service_completed_successfully`
// never opens — so the stack fails closed rather than starting an app that
// cannot authenticate.
db.getSiblingDB('admin').auth(rootUser, rootPass);

const appDb = db.getSiblingDB('hvault');
const roles = [{ role: 'readWrite', db: 'hvault' }];

if (appDb.getUser(appUser) === null) {
  appDb.createUser({ user: appUser, pwd: appPass, roles: roles });
  print(`[hvault-db-init] created '${appUser}' with readWrite on hvault`);
} else {
  // Roles ONLY. `pwd` is intentionally absent — see the idempotence note above.
  appDb.updateUser(appUser, { roles: roles });
  print(`[hvault-db-init] '${appUser}' already exists; roles reconciled, password untouched`);
}
