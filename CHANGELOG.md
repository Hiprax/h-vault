# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New environment variable `HIBP_CACHE_MAX_BYTES` (default 67108864 = 64 MiB, minimum 1 MiB) that bounds the in-memory breach-range cache by measured bytes per worker process, in addition to the existing 10,000-entry cap. A real HIBP range is ~36 KB, so the byte budget is now the binding memory bound; the entry count is a secondary guard.
- New `export_plaintext` audit action recorded when a vault export is produced for a portable plaintext format. `POST /api/v1/tools/export` accepts an optional `portableFormat` field (`bitwarden-json`, `bitwarden-csv`, or `chrome-csv`) used solely as audit metadata; the export response body is unchanged.
- New "Leave H-Vault" plaintext-export page at `/settings/export-data`, reached from a distinct entry-point card in Settings. It exports your whole vault to another password manager as an **unencrypted plaintext file** (Bitwarden JSON, Bitwarden CSV, or Chrome/Edge CSV): pick a format, re-enter your master password, confirm an explicit unencrypted-data warning, and download. The file is generated entirely in the browser and never uploaded; the master password is verified by the server before any plaintext is produced; and items that cannot be decoded, or that the chosen format cannot represent, are reported as skipped/omitted rather than silently dropped. It is a deliberately separate surface from the encrypted `.enc` export/backup and shares no control with it.
- New environment variables `REFRESH_TOKEN_DAYS` (default 7), `REFRESH_TOKEN_REMEMBER_DAYS` (default 30) and `TRUSTED_DEVICE_DAYS` (default 30), in whole days, that configure the standard session lifetime, the opt-in "remember me" session lifetime, and how long a device may skip the 2FA step. The defaults reproduce the previous fixed 7-day session behavior exactly. The server refuses to boot unless `REFRESH_TOKEN_REMEMBER_DAYS` ≥ `REFRESH_TOKEN_DAYS` and `TRUSTED_DEVICE_DAYS` ≥ `REFRESH_TOKEN_REMEMBER_DAYS`.
- `POST /api/v1/auth/login` accepts an optional `rememberMe` flag (default `false`). A remembered login extends the session to `REFRESH_TOKEN_REMEMBER_DAYS` (30 days); for a 2FA account it also registers the device as trusted after the 2FA step so it can skip the 2FA prompt on later logins until the trust grant expires (`TRUSTED_DEVICE_DAYS`). The master password is still always required to decrypt the vault. The flag is carried inside the signed 2FA temp token, so it cannot be tampered with at the 2FA step.
- The login screen now has an opt-in "Remember me on this device" checkbox, with a note that it is only for trusted devices and that the master password is still required on every unlock and is never stored. When checked, the choice is honored whether or not the account uses 2FA.
- New `GET /api/v1/user/trusted-devices` endpoint lists the devices allowed to skip the 2FA step (device info and created/last-used/expiry dates; the server-only token hash is never returned), and `DELETE /api/v1/user/trusted-devices/:id` and `DELETE /api/v1/user/trusted-devices` revoke a single trusted device or all of them. A revoked device must complete 2FA again on its next login.
- A remembered session now resumes across a full browser restart: on the next launch the app silently refreshes the session and lands on the Unlock screen (master password only), instead of the login screen. The vault key is still re-derived from the master password on unlock and is never persisted. The remembered session is abandoned only when the server confirms it is gone; a transient offline or server-restart failure keeps it for the next launch.

### Changed

- The `MAX_SESSIONS` limit (50) is now enforced as a real per-device cap: signing in on a new device evicts your oldest active session once you exceed the limit, instead of the limit only bounding the sessions list. Only live sessions are counted and evicted — the short-lived internal rotation records that back stolen-token detection are never touched — so this never logs another device out spuriously and never weakens reuse detection. The Sessions list now shows only live sessions, so its count matches the enforced cap.
- The in-memory breach-range (HIBP) cache is now bounded by a measured byte budget (`HIBP_CACHE_MAX_BYTES`) as well as by entry count, keeping worker memory within its budget even when cached ranges are unusually large. The PM2 `max_memory_restart` ceiling was raised to 768 MiB to fit one worker holding a full cache plus its ordinary heap (the ceiling is per worker, not aggregate across workers).
- The breach-corpus seeder is now part of the compiled server output, so it can run inside the production Docker image (which ships no `npm` and no `tsx`) with `docker compose exec hvault-app node packages/server/dist/cli/seedBreaches.js`. Local usage is unchanged: `npm run seed-breaches -w packages/server` still works and takes the same flags.

### Removed

- Removed the `JWT_REFRESH_EXPIRY` environment variable. It was validated and documented but read by no code path — the refresh-token lifetime was always the hardcoded 7 days regardless of what it was set to — so an operator who set, say, `JWT_REFRESH_EXPIRY=30d` silently still got 7 days. Configure the session lifetime with the new `REFRESH_TOKEN_DAYS` instead.

### Fixed

- The client production build no longer fails intermittently on Windows from an upstream Rolldown native teardown crash (exit code `0xC0000005`) that fires after the bundle and service worker are already written. `npm run build` now retries `vite build` exactly once, and only on that specific native-crash exit code; ordinary build errors still fail immediately, so a green build always means a genuinely complete one.
- The empty-cache boot log and the operations docs no longer tell operators to run `npm run seed-breaches` from inside the production app container, where `npm` does not exist; they now point at the compiled `node packages/server/dist/cli/seedBreaches.js` command that actually runs there.

### Security

- Trusted devices for the "remember me" 2FA-skip are stored as a server-side record, never a client-asserted flag: the browser holds only a random opaque token and the server stores just its SHA-256, so trust cannot be forged and can be revoked centrally. The raw token appears only in the `Set-Cookie` header (scoped to `/api/v1/auth`) — never in a response body, a log, or the database — and the grant is capped per account (`MAX_TRUSTED_DEVICES` = 10, oldest evicted first) with a hard TTL at its absolute expiry. Three audit actions were added — `trusted_device_grant`, `trusted_device_revoke`, and `trusted_device_rejected` — bringing the audit log to 41 distinct operations.
- The trusted-device 2FA skip is consumed only after the password is verified. `POST /api/v1/auth/login` checks the `trustedDevice` cookie strictly after the bcrypt comparison and lockout evaluation, and only when the cookie is actually present, so a wrong password never reaches the check and an ordinary 2FA login (no cookie) does no lookup, clears no cookie, and writes no audit. On a match the token is consumed and rotated (a fresh token replaces it, carrying the original expiry forward so the trust window is never extended), and the session honors the request's own `rememberMe` (an unchecked box yields a standard-length session, never a silent 30-day one). Any anomaly — an unknown, expired, replayed, or another user's cookie — fails closed to the normal 2FA prompt, clearing the stale cookie and auditing `trusted_device_rejected`, and never revokes the account's other trusted devices.
- A trusted device's 2FA-skip is now dropped automatically on every event that changes the account's authentication footing, so trust can never outlive the second factor it was granted against: a password reset or change, enabling or disabling 2FA, regenerating backup codes, "log out everywhere", stolen-refresh-token reuse detection, and account deletion all revoke the account's trusted devices. Detecting a replayed (stolen) refresh token revokes the trusted devices along with the token family, so an attacker who steals a cookie cannot then skip 2FA. Ordinary single-session logout deliberately does not revoke trust — that would defeat the feature — and the revocation is centralized in one shared helper so no path can silently skip it.
- The portable plaintext export is confined to its own page and code path, physically separate from the encrypted `.enc` export/backup, so a user can never confuse "back up my vault" with "hand out every password in the clear"; the separation is itself a safety control. The exported file is unencrypted plaintext — every password, TOTP secret, card number and note — generated only in the browser, gated behind master-password re-verification and an explicit confirmation dialog, and never written to any store, `localStorage`, `sessionStorage`, or the console. CSV values are quoted per RFC 4180 but deliberately never altered (no formula-injection mutation, which would corrupt legitimate passwords and does not reliably stop spreadsheet formula execution anyway); the page instead warns not to open the file in a spreadsheet and to delete it after importing elsewhere.

## [0.4.0] - 2026-07-22

### Added

- New `POST /api/v1/tools/check-password-breach/batch` endpoint that checks many password hash prefixes in one request (k-anonymity preserved: only the first 5 hex chars of each SHA-1 hash ever leave the device). A breach scan of a large vault now costs a handful of requests instead of one per password. A dedicated rate-limit tier (`breachBatchLimiter`, 300 / user / 15 min) sizes it to cover a full-vault scan without ever returning a partial result.
- The Vault Health "Check for Breaches" control now shows a determinate progress indicator ("Checked X of Y") while a scan runs, so a large check no longer looks stuck.
- Vault Health breach findings and weak-password scores now persist on the device, encrypted with your vault key, so they survive a page refresh, an auto-lock, and a browser close — you no longer have to re-run the long breach scan and wait on the page each time you return. A "Last checked" label shows how old the saved results are, "Check for Breaches" runs a fresh scan and replaces the saved results only after it fully succeeds (a failed or interrupted scan keeps the previous results), and the saved snapshot is cleared on logout.
- A persistent, cross-account server-side cache of breach-range lookups (MongoDB): once any account has checked a given hash prefix, subsequent checks by any account are served locally until the entry ages out, so repeat scans no longer re-query the third party and survive server restarts. If the upstream service is unreachable, a cached range is served as a fallback and a prefix is never reported as "not breached" on failure.
- New opt-in command `npm run seed-breaches -w packages/server` imports the full Have I Been Pwned Pwned Passwords corpus into the local cache for fully-offline / zero-third-party-dependency breach checking. It is idempotent and resumable; an optional scheduled refresh is available via `BREACH_SEED_REFRESH_CRON` and `BREACH_SEED_AUTO`.
- New environment variables `BREACH_CACHE_TTL_DAYS` (default 30), `BREACH_SEED_AUTO` (default `false`), and `BREACH_SEED_REFRESH_CRON` (unset) to tune the breach-range cache and the optional seed refresh.

### Changed

- Vault Health scores password strength in a background Web Worker and windows long result lists, so the page stays responsive on large vaults instead of freezing the browser. The breach check also deduplicates passwords first, so identical/reused passwords cost a single lookup.
- Breach-range requests to Have I Been Pwned now send the `Add-Padding` header and discard the count-0 padding rows, so the queried prefix cannot be inferred from the response size by an on-path observer.
- **The local development server now runs on port 5173 (Vite's default) instead of 3000.** On Windows, Hyper-V/WSL2/Docker reserve dynamic TCP ranges that routinely include 3000; a reserved port fails to bind with `EACCES` rather than `EADDRINUSE`, which aborted `npm run dev` outright and made the whole Playwright E2E suite fail with an unexplained "Timed out waiting from config.webServer". The port is resolved by a single helper (`resolveDevPort`) that both the Vite config and the Playwright config read, so they can never drift, and it is overridable through the process environment with `VITE_PORT` (for example `VITE_PORT=5180 npm run dev`). The dev Docker stack now publishes `127.0.0.1:5173` and the default `CORS_ORIGIN` is `http://localhost:5173`. Production is unaffected: the built SPA is served by Nginx behind the single published port, not by Vite.
- The "Vault" sidebar item is highlighted on the vault list and on an individual item page, but no longer lights up at the same time as "Vault Health" when you open the Vault Health page.
- Pin the production Docker image base to `node:24-alpine3.23` instead of the floating `node:24-alpine` tag. The floating tag had rolled onto Alpine 3.24, whose musl userspace crashes `npm` at process launch (SIGSEGV, exit 139) under the WSL2 kernel used for local image builds, so `npm ci` failed and the images could not be built there. The pinned variant carries the identical Node 24.18.0 runtime and builds cleanly; there is no change to the running application.

### Fixed

- The Vault Health page no longer freezes or hangs the browser on vaults with many passwords; password-strength analysis was moved off the main thread.
- The OpenAPI document now describes the `POST /api/v1/tools/check-password-breach` response as the range text the endpoint actually returns, instead of a `{ found, count }` object it has never returned. A client generated from the spec no longer reads fields that are not there.
- The sidebar no longer highlights both "Vault" and "Vault Health" at once when viewing the `/vault/health` route.

### Security

- The breach check now surfaces passwords it could not verify (for example a failed or rate-limited lookup) instead of reporting them as "not breached", so an unchecked password can no longer be mistaken for a safe one. Restored results are held to the same rule: a password the saved snapshot never covered — one added or edited since the last scan, such as every entry of a large import — is counted as unverified and keeps the "could not be checked" warning on screen, rather than being quietly omitted and leaving a green "No breached passwords found" over credentials nothing has looked at.
- If password-strength analysis cannot complete (for example the analyzer fails to load), Vault Health now shows an explicit "could not analyze" warning instead of a misleading "No issues found", so a failed analysis is never mistaken for a clean result.
- Added an explicit `worker-src 'self'` Content-Security-Policy directive for the new password-strength Web Worker (same-origin only; never a `blob:` worker).
- The persistent breach-range cache stores only PUBLIC Have I Been Pwned data keyed by the 5-char SHA-1 prefix, with no per-user linkage and no stored suffix match, so it preserves the zero-knowledge model (the server still only ever receives the prefix, never a password or full hash). The on-device saved Vault Health results are encrypted with the vault key and remain encrypted at rest across a lock, exactly like the wrapped vault key.
- Force `shell-quote` to `>=1.9.0` through a dependency override, resolving CVE-2026-13311 (HIGH: denial of service via inefficient input parsing). It was pulled in transitively at `1.8.4` by the `concurrently` dev dependency and surfaced in the `bootstrap` image once the image build was unblocked.

## [0.3.0] - 2026-07-22

### Added

- `POST /api/v1/tools/import` accepts a structured `operations` payload — explicit `inserts` and `updates`, where each update names the id of the existing item it replaces — and answers with `{ insertedCount, updatedCount }`. Two new rejections come with it: `400` when an update names an item that does not exist, is in the trash, or belongs to someone else (it is never silently skipped), and `409` when another import for the same account is already running, when a vault-key rotation is in flight, or when an item an update targeted was changed or removed while the request was being applied. With `skip` or `overwrite`, re-running the import is safe: it re-resolves against the current vault and performs only what is left. With `keep both` — which by definition never matches anything — a re-run adds the rows that already landed a second time, and the client now says so instead of advising a retry.
- Importing with `overwrite` now asks for confirmation before anything is sent. The prompt states how many existing items will be modified and how many passwords will change, and warns that a matched item's name and content are replaced by the imported version — so anything the file does not carry (a TOTP secret, notes, custom fields) is lost, with only the password recoverable from history.
- Each vault list row now carries a second, distinguishing label beside its type badge: a login's username (or, when it has none, the site it belongs to), a card's last four digits behind a mask, or an identity's name (or email). Notes and secrets have none, and no password, CVV, SSN, TOTP seed or secret value is ever shown — so several accounts on one site are finally told apart at a glance. The full value is available as a hover tooltip, so a subtitle the row is too narrow to show is still readable.
- An import now reports what happened to every row: how many were imported, updated, already up to date, skipped as duplicates of existing items, dropped as duplicates within the file, and skipped as unusable — with the reason for each unusable row. The counts add up to the number of rows the file contained.

### Changed

- **Breaking:** the `POST /api/v1/tools/import` request contract is now `operations` only. The previous `data` envelope (a JSON string of encrypted items that the server de-duplicated by name) has been removed, and a request carrying it is rejected. A request is bounded by 10,000 combined operations rather than by that envelope's 1 MB string limit; the byte ceiling is now the server's ordinary 2 MB request-body limit, and the client keeps splitting a large migration well inside it.
- An import row the server cannot use — one missing an encrypted field, or carrying a malformed search hash, tag or password-history entry — now rejects the whole request with `400` and writes nothing, instead of being silently filtered out while the rest of the file imported. Nothing is dropped without being reported.
- **Import now identifies items by their decrypted content, not by their name.** A login matches on its site and username, and every other item type on its exact content; the match is computed in the browser, where the plaintext lives, and is never sent or stored. Ten accounts on one site therefore stay ten items instead of collapsing into one, re-importing the same file changes nothing, and how a large import is split into requests can no longer affect the result. `skip` (the default) still never modifies anything, and `keep both` still never matches.
- **`overwrite` can now modify an existing item in place** — replacing its content and its name with the imported version — where before, name-matching made that unpredictable. It requires the confirmation described above, and the password it replaces is always kept in that item's password history.
- Re-importing a native H-Vault export now restores an item's password history along with it, instead of recreating the item with an empty history.
- An imported login whose source had no title is now named `<site> (<username>)` instead of just `<site>`, so several accounts on one site no longer arrive as identical-looking rows. Only a name derived from the URL is affected — a title the source supplied is never changed — and matching is unaffected for any login with a usable site and username, because such a login is matched on those rather than on its name.
- Vault list sorting is now a total order: rows that tie on the chosen key are settled by name, then by the new row subtitle, then by an internal identifier. Ten same-named logins used to appear in whatever order they were loaded in — which differed between a fresh fetch and an offline read — so sorting by Name did nothing for exactly the case a bulk import creates. Reversing the sort direction now produces the exact reverse of the ascending order.
- The server no longer decides what is a duplicate. It validates ownership, field lengths and the per-account item limit, then applies exactly the operations it was given; `conflictStrategy` is recorded for the audit log but no longer acted on, because matching now happens in the browser where the decrypted content lives. An import update rewrites item content only — it can never change an item's tags, favorite flag, folder or type.
- Concurrent imports for one account are now serialized, so two overlapping imports can no longer both pass the per-account item limit and push the vault over it. Where the database supports transactions, an import's writes also commit or roll back as a unit, and the limit is re-checked against the state those writes actually see.

### Fixed

- Import no longer treats two unrelated logins as the same item when one of their web addresses is a match **pattern** or contains a stray backslash. A URL that says `accounts\.google\.com` was being read as the site `accounts`, so a Google and an Okta login sharing a username collapsed onto one identity — with `overwrite` replacing one with the other, and `skip` reporting a genuinely new credential as a duplicate and never importing it. A pattern now identifies no site, matching falls back to exact content, and the same rule applies to any address whose host the URL parser silently rewrites. The vault list stops labelling such a row with that misread host, too.
- The OpenAPI document now describes the import request as tightly as the server validates it: a tag has a minimum length, an item id and a folder id carry their expected format, the operation lists have their default, and the success response documents the `message` it has always returned. A client generated from the spec no longer sends bodies the spec called valid and the server rejects.
- Corrected two statements in the documentation that promised more than the code delivers: a rejected import writes nothing on every failure **except** one — if an item an update targeted is changed or removed mid-request, a MongoDB deployment without a replica set (the default) may already have committed earlier operations from that same request. Re-running remains safe. Relatedly, a deployment whose connection string names a replica set that is not actually configured does not "silently fall back" to non-transactional writes as its startup warning claimed; the affected endpoints fail outright, writing nothing.
- The OpenAPI document no longer advertises `422` for a request that fails schema validation. Every endpoint validates through the same middleware, which has always answered `400`, so a client generated from the spec handled a status the API never sends and missed the one it does.
- An import now refuses to run rather than resolving against a vault it could not fully load — a failed or superseded item fetch, a lock part-way through, or a read served from the offline cache. Matching against a partially loaded vault would have made every existing item look new and duplicated the entire file.
- Vault list rows are no longer packed too tightly once the list passes 50 items. The virtualized list was told each row was 72px tall when it actually renders at 78px, leaving a 2px gap between rows instead of the 8px the shorter list uses.
- Bitwarden import no longer silently drops parts of an item. An identity's `title`, `middleName`, `username` and `licenseNumber` — none of which the vault has a dedicated field for — are now preserved in the item's notes under clear labels instead of being discarded. Bitwarden SSH-key items (previously imported as an empty note that lost the key entirely) are now imported as a login whose private key, public key and fingerprint are kept in clearly-labelled custom fields, with the private key masked. A Firefox export's `httpRealm` column (which identifies an HTTP Basic/Digest auth entry) is now preserved in notes; the remaining Firefox metadata columns (`formActionOrigin`, `guid`, and the `time*` timestamps) are intentionally not imported, as they have no vault field and would clutter every row.
- Importing an entry with an over-long field no longer discards the whole item. A username, password, note, URL, or custom-field value that exceeds the vault's per-field limit is now clamped to that limit instead of failing validation and dropping the entire entry (password included). The truncated overflow — and the full original URL or username — is preserved in the item's notes under a clear label; a password is clamped but, for safety, is never copied into notes. Custom fields beyond the 100-per-item limit are summarized in notes rather than lost. A scheme-less URL is clamped with room for the `https://` the vault adds, so a very long bare domain no longer becomes a permanently unreadable item.
- `package-lock.json` now records the current project version. It was left at `0.1.2` when 0.2.0 was cut, so the first `npm install` on a fresh clone rewrote the lockfile unprompted. No dependency, resolution or integrity hash changed.

### Security

- Import duplicate detection moved off the server entirely: the match key is computed in the browser from decrypted content and is never transmitted or stored, so the server no longer receives the name-equality signal it used to act on. One consequence is stated plainly rather than glossed over — under `overwrite`, the server does see which of your own items an import updates, an equivalence between imported entries and stored items it could not previously compute. It never leaves your own vault and exposes no plaintext; `skip` (the default) and `keep both` send no updates at all. `SECURITY.md` documents this.

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

[Unreleased]: https://github.com/Hiprax/h-vault/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Hiprax/h-vault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Hiprax/h-vault/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Hiprax/h-vault/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/Hiprax/h-vault/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Hiprax/h-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hiprax/h-vault/releases/tag/v0.1.0
