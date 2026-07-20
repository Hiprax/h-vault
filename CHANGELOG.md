# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Hiprax/h-vault/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Hiprax/h-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Hiprax/h-vault/releases/tag/v0.1.0
