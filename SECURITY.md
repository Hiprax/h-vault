# Security Policy

H-Vault stores passwords, secrets and private notes. Security reports are the most
valuable contribution this project can receive, and they are treated accordingly.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub Security Advisories:

**[→ Report a vulnerability](https://github.com/Hiprax/h-vault/security/advisories/new)**

(Repository → **Security** → **Advisories** → **Report a vulnerability**.)

The report stays private between you and the maintainers until a fix is published.

Please include, as far as you can:

- The version, commit or tag you tested.
- How the instance was deployed (Docker stack, PM2, local dev) and anything unusual
  about the configuration.
- A description of the impact — what an attacker gains, and what they need in order
  to get it.
- Reproduction steps, a proof of concept, or the specific code path you believe is
  wrong. A pointer to the exact file and line is worth more than a scanner export.

### What to expect

| Stage              | Target                                                       |
| ------------------ | ------------------------------------------------------------ |
| Acknowledgement    | Within 72 hours                                              |
| Initial assessment | Within 7 days — severity, whether it is accepted, next steps |
| Fix and disclosure | Coordinated with you; critical issues are prioritised        |

You will be credited in the advisory and the release notes unless you ask not to be.
There is no bug bounty — this is an unfunded open-source project — but genuine reports
are always welcomed, investigated, and answered.

## Supported versions

H-Vault is pre-1.0. Only the latest release receives security fixes; there are no
long-term support branches.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Threat model

Being explicit about what the design does and does not defend against is part of the
security posture, not a disclaimer.

### What H-Vault protects against

- **A compromised or hostile server, and a stolen database.** Vault items, item names,
  folder names and password history are encrypted client-side with AES-256-GCM under a
  key the server never sees. The master password never leaves the browser: the server
  stores only a bcrypt hash of a derived auth value, and the vault key only as ciphertext
  it cannot unwrap. A full database dump yields ciphertext.
- **A passive network attacker.** All traffic is expected to run over TLS terminated by
  your reverse proxy, and the vault payloads are already ciphertext underneath it.
- **Credential stuffing and online guessing.** Rate limiting, account lockout with
  progressive delays, and 2FA — with the lockout and 2FA paths deliberately built so they
  do not leak whether an account exists.
- **Backup theft.** Emailed and downloaded backups are encrypted under a _separate_
  backup password and carry an HMAC-SHA256 integrity signature that is verified on restore.
- **Tampered backup files.** Restore validates the signature, rejects dangling and
  self-referential folder links, and breaks any folder cycle a malicious file plants.

### What it cannot protect against

- **A compromised client, or a malicious build served to the browser.** Zero-knowledge
  means the server never _needs_ the plaintext — it does not mean the server _cannot_
  serve JavaScript that steals it. Anyone who can modify the code the browser runs (a
  compromised host, a hostile CDN, a malicious dependency, a stored XSS) can exfiltrate
  the master password or the vault key at the moment they are in memory. This is inherent
  to every browser-based zero-knowledge application, H-Vault included. Self-host it, pin
  the version you deploy, and treat the served bundle as security-critical.
- **A weak master password.** It is the root of the entire key hierarchy. PBKDF2 at
  600,000 iterations raises the cost of an offline attack against a stolen auth hash; it
  does not rescue a guessable password.
- **A lost master password.** There is no recovery path and no reset that preserves data,
  by design — the server cannot decrypt the vault for you. The same applies to the file
  encryption tool's password and the backup password.
- **Malware on the device.** A keylogger, a hostile browser extension, or an attacker with
  the unlocked machine defeats any password manager.
- **Metadata.** The server necessarily learns what it must in order to function: your
  email, when you logged in and from where, how many items and folders you have, when they
  were changed, and their type. Item _contents_ and _names_ are encrypted; their _existence_
  is not. **Tags are stored in plaintext** — they are indexed so the server can filter by
  them — so a tag is a label the server can read. Importing from another password manager
  converts that export's folder/group names into tags, which means the server learns your
  source folder taxonomy (for example `Banking`, `Work SSO`). Do not put anything sensitive
  in a tag; use the item's name or a field instead, both of which are encrypted.
  Import decides what is a duplicate **in your browser**, from decrypted content — a login is
  identified by its site and username — and that identity is never transmitted and never stored,
  so the server never learns it. One nuance is worth stating plainly rather than claiming the
  server simply learns less: under the `overwrite` strategy it does see _which of your own items_
  an import updates — an equivalence between imported entries and stored items it could not
  previously compute. That never leaves your own vault and exposes no plaintext, and `skip` (the
  default) and `keep both` send no updates at all.
- **Your deployment.** An exposed MongoDB port, a `TRUST_PROXY` set higher than the number
  of proxies actually in front of the app, secrets committed to a repository, or a missing
  TLS certificate will undo the guarantees above. The deployment checklist in the README
  exists for this reason.

### Remember me and trusted devices

"Remember me on this device" is **opt-in per login** and changes authentication only — never
cryptography. The master password is still typed on every unlock and is never stored; the vault
key is re-derived from it each time and is never persisted. Choosing it does two things:

- **Extends the session.** A remembered session lasts `REFRESH_TOKEN_REMEMBER_DAYS` (default 30)
  instead of the standard `REFRESH_TOKEN_DAYS` (default 7), and survives a full browser restart:
  on the next launch the app silently refreshes and lands on the **Unlock** screen (master
  password only), not the login screen. The 30-day deadline is **absolute** — token rotation
  carries it forward and never slides it — so a remembered session expires 30 days after it began,
  full stop. A non-remembered session keeps the previous sliding 7-day behaviour exactly.
- **Lets a 2FA device skip the second factor.** On an account with 2FA, a remembered login also
  registers the device as trusted so it can skip the _2FA step_ on later logins. It never skips the
  password step.

The trusted-device model is built to fail safely:

- **Trust is a server-side record, never a client claim.** The browser holds only a random 32-byte
  opaque token; the server stores just its **SHA-256** and can revoke it centrally. The raw token
  appears only in the `Set-Cookie` header — scoped to `/api/v1/auth`, `httpOnly`, `secure` and
  `sameSite=strict` in production — and never in a response body, a log, or the database. A
  client-asserted "I am trusted" flag would be forgeable; a stored hash is not.
- **Checked only after the password.** The trusted-device cookie is read **strictly after** the
  bcrypt comparison and lockout evaluation succeed, and only when the cookie is actually present.
  Checking it earlier would turn the cookie into an authentication bypass and an
  account-enumeration oracle; a wrong password never reaches the check.
- **Rotated on use, expiry never extended.** A recognised token is consumed and replaced, carrying
  the **original** absolute expiry forward, so a stolen cookie stops working the moment the
  legitimate user next logs in, and the trust window is never lengthened by use. The record has a
  hard TTL at that expiry, and grants are capped per account (`MAX_TRUSTED_DEVICES` = 10, oldest
  evicted first).
- **Fail closed to 2FA.** Any anomaly — an unknown, expired, replayed, or another user's cookie —
  falls through to the normal 2FA prompt, clears the stale cookie, and audits
  `trusted_device_rejected`. It does **not** revoke the account's other trusted devices, because the
  attacker still needs the password and global revocation on a benign race would be user-hostile.
- **Revoked on every change of authentication footing.** A trusted device's 2FA-skip is dropped
  automatically — through one shared helper that every path calls — on a password change or reset,
  enabling or disabling 2FA, regenerating backup codes, "log out everywhere", **stolen-refresh-token
  reuse detection**, and account deletion. So trust can never outlive the second factor it was
  granted against, and an attacker who steals a refresh cookie cannot then skip 2FA. Ordinary
  single-session logout deliberately does **not** revoke trust — that would defeat the feature — and
  you can revoke any or all trusted devices yourself from the Sessions page.

**The real time bound.** Because a trusted-device login mints a fresh 30-day session while the trust
record keeps its own 30-day expiry, a user who keeps returning can go up to
`REFRESH_TOKEN_REMEMBER_DAYS + TRUSTED_DEVICE_DAYS` days (60 by default) without re-entering a TOTP.
This is intended: the master password is still required on every unlock, and either window lapsing
lands the user back at a full login.

### Password breach checking (Have I Been Pwned)

Vault Health checks passwords against the Have I Been Pwned Pwned Passwords corpus using
**k-anonymity**: the browser SHA-1-hashes each password and sends only the first **5 hex
characters** of the hash to the server, which proxies the query to HIBP and returns the
list of matching hash suffixes; the full-suffix comparison happens **in the browser**. A
password, or a hash that could identify one, never reaches the server. Outbound requests
to HIBP set `Add-Padding` (so the queried prefix cannot be inferred from the response
size on the wire) and follow no redirects.

- **Server-side breach cache (`pwned_range_cache`).** To avoid re-querying the third
  party, the server persists the range responses it fetches, keyed by that 5-char prefix,
  and shares them across all accounts. Everything stored here is **public HIBP data** —
  identical for everyone and fetchable by anyone — so it is stored in plaintext;
  encrypting public data adds no confidentiality. Crucially there is **no per-user linkage
  and no stored record of which suffix matched**, so the cache cannot reveal whose
  password, or which password, produced a lookup, and the zero-knowledge model is
  preserved. An operator may optionally pre-seed the full corpus for offline /
  zero-third-party-dependency operation — locally with `npm run seed-breaches -w
packages/server`, or inside the production image (which has no `npm`) with
  `docker compose exec hvault-app node packages/server/dist/cli/seedBreaches.js`. The cache is **fail-safe**: a miss
  falls through to HIBP, and an upstream failure with no cached fallback surfaces as an
  error, never as a "not breached" result.
- **On-device saved results.** The breach findings and weak-password scores shown on the
  Vault Health page are cached in the browser (IndexedDB) **encrypted with your vault key**,
  so they survive a page refresh or browser close without forcing a re-scan. They stay
  encrypted at rest across a lock — exactly as safe as the wrapped vault key already
  persisted for unlock — and are erased on logout.

### Portable plaintext export ("Leave H-Vault")

The `/settings/export-data` page exports your whole vault to another password manager
(Bitwarden JSON/CSV, Chrome/Edge CSV). Unlike every other export in the app, the file it
produces is **unencrypted plaintext** — it deliberately contains every password, TOTP
secret, card number and note in the clear, because that is what a competing manager needs
to import. That makes it the single most dangerous artifact H-Vault can create, and the
threat model reflects that:

- **It is a physically separate surface from the encrypted `.enc` export and the backup
  system.** It has its own route, its own entry-point card, and its own confirmation
  dialog, and shares no control or code path with them. The separation is itself a safety
  control: it prevents a user from reaching for "back up my vault" and instead handing out
  every password in cleartext.
- **The plaintext never leaves the browser.** The server is still asked only for the
  encrypted vault (the same `POST /tools/export` ciphertext response); the client decrypts,
  serializes and downloads locally. No plaintext is transmitted, and none is written to any
  store, `localStorage`, `sessionStorage`, or the console.
- **Master-password re-verification gates the export.** The server bcrypt-verifies your
  master password (via the export endpoint's auth hash) before any plaintext is produced,
  and the download only happens after you accept an explicit unencrypted-data warning.
  Cancelling produces no file.
- **Completeness is reported, not assumed.** The client decrypts the server's authoritative
  complete item set; any item it cannot decrypt, or that the chosen format cannot represent,
  is reported as skipped/omitted rather than silently dropped — a silently short export is
  indistinguishable from a complete one, and a user doing this is often about to delete
  their account.
- **CSV values are quoted per RFC 4180 but never altered.** H-Vault does **not** apply the
  common "formula-injection" mitigation of prefixing cells that begin with `=`, `+`, `-` or
  `@`: that would corrupt passwords which legitimately start with those characters, and RFC
  4180 quoting does not stop a spreadsheet from evaluating formulas anyway. For a password
  manager, fidelity wins. The mitigation is instead operational: the page warns you **not to
  open the file in a spreadsheet**, and to **securely delete it** as soon as you have
  imported it elsewhere. Treat the file exactly as you would a sheet of every password you
  own.

## Security practices in this repository

- Every push runs `npm run ci` locally through the `pre-push` hook: dependency audit,
  ESLint with `eslint-plugin-security`, CodeQL, container builds scanned with Trivy
  (zero fixable CRITICAL/HIGH), and a secret scan over every tracked file.
- Production images run non-root on read-only root filesystems, drop all Linux
  capabilities, and set `no-new-privileges`. The Compose stack publishes exactly one
  loopback-bound port; the database has no published port and no route to the internet.
- Secrets are validated at boot: the app refuses to start in production with a
  placeholder secret, a non-HTTPS origin, or a partial mail configuration.

## Hardening your own deployment

Work through the **Deployment security checklist** in the [README](README.md) before you
put an instance in front of real data — in particular: set a dedicated
`TWO_FACTOR_ENCRYPTION_KEY`, generate every secret randomly, terminate TLS, set
`TRUST_PROXY_HOPS` to the true number of proxies, and keep the single published port bound
to `127.0.0.1`.
