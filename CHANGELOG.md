# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `POST /api/v1/tools/import` accepts a structured `operations` payload — explicit `inserts` and `updates`, where each update names the id of the existing item it replaces — and answers with `{ insertedCount, updatedCount }`. Two new rejections come with it: `400` when an update names an item that does not exist, is in the trash, or belongs to someone else (it is never silently skipped), and `409` when another import for the same account is already running.
- Importing with `overwrite` now asks for confirmation before anything is sent. The prompt states how many existing items will be modified and how many passwords will change, and warns that a matched item's name and content are replaced by the imported version — so anything the file does not carry (a TOTP secret, notes, custom fields) is lost, with only the password recoverable from history.
- An import now reports what happened to every row: how many were imported, updated, already up to date, skipped as duplicates of existing items, dropped as duplicates within the file, and skipped as unusable — with the reason for each unusable row. The counts add up to the number of rows the file contained.

### Changed

- **Breaking:** the `POST /api/v1/tools/import` request contract is now `operations` only. The previous `data` envelope (a JSON string of encrypted items that the server de-duplicated by name) has been removed, and a request carrying it is rejected.
- **Import now identifies items by their decrypted content, not by their name.** A login matches on its site and username, and every other item type on its exact content; the match is computed in the browser, where the plaintext lives, and is never sent or stored. Ten accounts on one site therefore stay ten items instead of collapsing into one, re-importing the same file changes nothing, and how a large import is split into requests can no longer affect the result. `skip` (the default) still never modifies anything, and `keep both` still never matches.
- **`overwrite` can now modify an existing item in place** — replacing its content and its name with the imported version — where before, name-matching made that unpredictable. It requires the confirmation described above, and the password it replaces is always kept in that item's password history.
- Re-importing a native H-Vault export now restores an item's password history along with it, instead of recreating the item with an empty history.
- An imported login whose source had no title is now named `<site> (<username>)` instead of just `<site>`, so several accounts on one site no longer arrive as identical-looking rows. Only a name derived from the URL is affected — a title the source supplied is never changed — and matching is unaffected for any login with a usable site and username, because such a login is matched on those rather than on its name.
- The server no longer decides what is a duplicate. It validates ownership, field lengths and the per-account item limit, then applies exactly the operations it was given; `conflictStrategy` is recorded for the audit log but no longer acted on, because matching now happens in the browser where the decrypted content lives. An import update rewrites item content only — it can never change an item's tags, favorite flag, folder or type.
- Concurrent imports for one account are now serialized, so two overlapping imports can no longer both pass the per-account item limit and push the vault over it. Where the database supports transactions, an import's writes also commit or roll back as a unit, and the limit is re-checked against the state those writes actually see.

### Fixed

- Bitwarden import no longer silently drops parts of an item. An identity's `title`, `middleName`, `username` and `licenseNumber` — none of which the vault has a dedicated field for — are now preserved in the item's notes under clear labels instead of being discarded. Bitwarden SSH-key items (previously imported as an empty note that lost the key entirely) are now imported as a login whose private key, public key and fingerprint are kept in clearly-labelled custom fields, with the private key masked. A Firefox export's `httpRealm` column (which identifies an HTTP Basic/Digest auth entry) is now preserved in notes; the remaining Firefox metadata columns (`formActionOrigin`, `guid`, and the `time*` timestamps) are intentionally not imported, as they have no vault field and would clutter every row.
- Importing an entry with an over-long field no longer discards the whole item. A username, password, note, URL, or custom-field value that exceeds the vault's per-field limit is now clamped to that limit instead of failing validation and dropping the entire entry (password included). The truncated overflow — and the full original URL or username — is preserved in the item's notes under a clear label; a password is clamped but, for safety, is never copied into notes. Custom fields beyond the 100-per-item limit are summarized in notes rather than lost. A scheme-less URL is clamped with room for the `https://` the vault adds, so a very long bare domain no longer becomes a permanently unreadable item.

## [0.2.0] - 2026-07-21

### Added

- Real client-side import for external sources: Bitwarden (JSON and CSV), LastPass, KeePass, Chrome/Edge, Firefox, 1Password, and a generic column-mapping CSV. The browser parses the export, converts each entry to a vault item, and encrypts it with the vault key before upload — no credential, note or field value leaves the device in the clear. Source folders/groups are preserved as tags, and tags are stored in plaintext (they are indexed server-side), so an import makes your source folder names visible to the server; see `SECURITY.md`. A source without a title (e.g. Firefox) derives the item name from the URL host.
- `chrome`, `firefox`, and `onepassword` added to the `/tools/import` `format` values; unsafe-scheme URLs (e.g. `android:`) are dropped from a login's URI list and preserved in its notes.
- `MAX_IMPORT_FILE_SIZE_BYTES` (8 MiB) client-side import-file ceiling; large imports are now split into several size-bounded requests automatically, with per-batch progress shown on the Import button.

### Changed

- Import parsing and encryption are now entirely client-side. The `/tools/import` endpoint accepts only already-encrypted native items (`{ items: [...] }`) regardless of `format`, which is retained purely as audit metadata; the request no longer accepts `csvMapping`.
- Duplicate detection during import matches an incoming item against items already stored, never against other items in the same request — unchanged — but a large import is now split into several sequential requests, so items sharing a name across a batch boundary are treated as duplicates of each other. Two entries both named "Amazon" land as two items when they fall in the same batch, and as one (under `skip`) when they straddle two. Imports small enough to fit one request are unaffected. If you need every same-named entry kept, use the `keep both` conflict strategy.
- `/tools/import` now has its own rate limit (60 requests per user per 15 minutes) instead of sharing the 10-per-IP heavy-operation budget with export, backup and bulk operations. A large migration is uploaded as several encrypted batches, which could otherwise exhaust that shared budget part-way through and stall the import.

### Fixed

- Importing an external export (e.g. a Firefox-exported `.csv`) no longer fails with "No valid items found to import (all items had missing encryption fields)". External formats were never parsed or encrypted on the client, so the zero-knowledge server rejected every row; they are now parsed and encrypted in the browser first.
- Re-importing a large native H-Vault export no longer fails on the 1 MB per-request cap: the encrypted payload is sent in batches.
- The CSV mapping preview now uses an RFC-4180 parser that correctly handles quoted fields containing embedded newlines (the previous line-split parser split them into broken rows).
- A Bitwarden identity carrying an unusual email or phone number (for example a number with an extension, or `+1 555 CALL-NOW`) is no longer discarded wholesale. Those two fields are validated against the same rules the vault enforces and moved into the item's notes when they don't fit, so the rest of the identity — name, address, passport, SSN — is preserved.

### Security

- Removed the server-side plaintext-CSV import branch. It mapped raw CSV cells straight into fields named `encrypted*`, so a mis-triggered client could have stored plaintext secrets server-side, defeating the zero-knowledge guarantee. The server now never parses plaintext on the import path.

## [0.1.2] - 2026-07-20

### Added

- `MONGO_APP_USERNAME` and `MONGO_APP_PASSWORD` environment variables for the least-privilege database account. `MONGO_APP_PASSWORD` is required and ships empty, so the stack refuses to start until it is set — existing deployments must add it to `.env` before the next `docker compose up`.

### Changed

- Moved the default Docker network blocks from `172.28.0.0/24` / `172.28.1.0/24` to `172.31.240.0/24` / `172.31.241.0/24`. Docker allocates its own bridges from the bottom of `172.17.0.0/12` and hand-pinned stacks tend to claim the low `172.2x` blocks, so the previous defaults collided with an existing stack and `docker compose up` failed outright with "Pool overlaps with other one on this address space". Both blocks remain overridable via `HVAULT_EDGE_SUBNET` / `HVAULT_DATA_SUBNET`.
- Documented that `docker compose up -d --wait` can report `container hvault-nginx is unhealthy` while the stack is serving normally, which happens only when re-running it to recover from an app outage longer than about 75 seconds. Nginx's probe runs through the proxy, so it is marked unhealthy during the outage and Compose treats that as terminal rather than waiting for the next probe. The deep probe is deliberate and is retained: it is what proves the whole single-port path at deploy time.

### Fixed

- `GET /api/v1/health`, `GET /api/v1/config` and `GET /api/v1/metrics` now answer correctly while MongoDB is unreachable. Their rate limiters were backed by MongoDB, so a database outage made each request stall for the driver's full server-selection timeout and then fail closed — replacing the intended `503` with `database: "disconnected"` with a generic 500 that both container health probes timed out on before it was even written. Those two limiters now count in process memory, so the endpoints no longer depend on the database they exist to report on. The ten limiters guarding database-dependent routes are unchanged and still fail closed.
- Pinned the internal Nginx to two worker processes instead of `worker_processes auto`. `auto` counts the **host's** CPUs and ignores the container's quota, so the web service forked one worker per host core inside its `cpus: '0.5'` / `mem_limit: 256m` / `pids_limit: 100` budget — measured as four workers on a four-core host, and unbounded on larger machines.

### Security

- The application and index-bootstrap containers now authenticate to MongoDB as a user restricted to `readWrite` on the `hvault` database, instead of as the cluster root user. A new one-shot `hvault-db-init` service provisions that account before the rest of the stack starts, and the app/bootstrap `environment:` blocks blank the discrete `MONGO_ROOT_*` / `MONGO_APP_*` keys that `env_file` would otherwise inject, so the root credential reaches only the database itself and that one short-lived container. A compromise of the application no longer confers administrative access to the cluster, other databases, or user management.

## [0.1.1] - 2026-07-20

### Changed

- Upgraded server, client and tooling dependencies to their latest compatible releases, including `@hiprax/logger` 1.1, `helmet` 8.3, `express-rate-limit` 8.6, `mongodb` 7.5, `react-hook-form` 7.82, `lucide-react` 1.25, `vite` 8.1.5, `tailwindcss` / `@tailwindcss/vite` 4.3.3, `postcss` 8.5.20, `autoprefixer` 10.5.4, `eslint` 10.7, `typescript-eslint` 8.64, `prettier` 3.9.5, `tsx` 4.23.1 and `lint-staged` 17.1. TypeScript is deliberately held at the 6.x line and `@types/node` at the 24.x line to stay aligned with the supported type-check toolchain and the Node 24 runtime.
- Fatal-crash handling (uncaught exceptions and unhandled rejections) is now captured through the logger's process-wide coordinator, which records a single crash entry with a full stack trace plus process and OS context and flushes the log transports under a bounded timeout before the process exits with a non-zero code.

## [0.1.0] - 2026-07-14

First public release.

### Added

**Vault**

- Zero-knowledge vault for five item types — logins, secrets, notes, cards and identities — with full CRUD, search, folders, tags and favorites. All data is encrypted client-side with AES-256-GCM before it reaches the server; the master password never leaves the device.
- PBKDF2-SHA256 (600,000 iterations) key derivation splitting into a Master Encryption Key that never leaves the client and an auth hash that does.
- Client-side vault key rotation with a server-side write fence, idempotent retries, and a transactional path on replica sets.
- Nested folders with circular-reference detection, depth limits and drag-to-reorder.
- Soft delete with a 30-day trash auto-purge, plus restore and permanent delete.
- Password history (up to 10 previous passwords per login item, individually encrypted).
- Built-in TOTP authenticator for stored login items.

**Tools**

- Password generator with a character-set mode and a passphrase mode (2048-word EFF-based list, exactly 11 bits of entropy per word). Strength is reported as exact information-theoretic entropy against a NIST-calibrated five-band scale, with an honest average-case offline-GPU crack-time estimate.
- Vault health checks: weak, reused, old and breached passwords, and logins with no TOTP configured.
- Breach detection via HaveIBeenPwned k-anonymity (only a 5-character SHA-1 prefix leaves the server).
- Standalone client-side File Encryption tool: encrypt any file with a password to a self-contained `.enc` container (Argon2id envelope encryption, sealed filename/mime metadata, embedded integrity hash). Account-agnostic — the file never touches account keys and never leaves the browser.
- Import from Bitwarden, LastPass, KeePass, CSV and JSON with skip / overwrite / keep-both conflict strategies; encrypted JSON export gated behind password re-authentication.

**Security**

- Two-factor authentication (TOTP) with bcrypt-hashed backup codes, regeneration, replay protection and brute-force throttling at the 2FA step.
- Refresh token rotation with reuse detection and family revocation; access tokens invalidated immediately on password change.
- Account lockout after 10 failed attempts with progressive delays and an unlock email, applied so that it never becomes an account-enumeration oracle.
- CSRF protection via an HMAC-SHA256 double-submit token with constant-time verification.
- MongoDB-backed rate limiting across twelve tiers, keyed per IP, per email, per user or per session, with IPv6 `/64` subnet aggregation.
- Encrypted email backups with a separate backup password (zero-knowledge), HMAC-SHA256 integrity signatures, and repeat-safe restore that re-encrypts rows to the account's current key rather than adopting the backup's.
- Searchable audit log covering 37 operations, with TTL-based retention.
- GDPR account deletion that atomically cascades across every collection.

**Platform**

- Self-contained Docker Compose stack — internal Nginx, Express API, one-shot index bootstrap, and MongoDB as a single-node replica set — publishing exactly one loopback-bound host port for the host's system Nginx to terminate TLS in front of.
- PM2 clustering as an alternative deployment path, with distributed MongoDB job locks so background jobs never double-run.
- Progressive Web App with offline read access via IndexedDB, dark/light/system themes, keyboard shortcuts, virtualized lists and WAI-ARIA-conformant components.
- Local CI pipeline (`npm run ci`) running eleven gates — including container builds with Trivy scanning and CodeQL — from the `pre-push` hook.

[Unreleased]: https://github.com/Hiprax/h-vault/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Hiprax/h-vault/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/Hiprax/h-vault/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Hiprax/h-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hiprax/h-vault/releases/tag/v0.1.0
