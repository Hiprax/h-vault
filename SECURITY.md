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
| 0.13.x  | Yes       |
| < 0.13  | No        |

## Threat model

Being explicit about what the design does and does not defend against is part of the
security posture, not a disclaimer.

### What H-Vault protects against

- **A compromised or hostile server, and a stolen database.** Vault items, item names,
  folder names and password history are encrypted client-side with AES-256-GCM under a
  key the server never sees. The master password never leaves the browser: the server
  stores only a bcrypt hash of a derived auth value, and the vault key only as ciphertext
  it cannot unwrap. A full database dump yields ciphertext. Stored documents are the same
  bargain in a different shape: the bytes are sealed in the browser under a per-document
  key the vault key only ever wraps, and the filename, type, tags and note are sealed with
  them, so a dump of the database and the storage service together yields ciphertext, a
  wrapped key and a set of sizes. **A hostile server cannot reorder, truncate, or splice one
  document into another either** — a segment's position and an end-of-file marker are inside
  its nonce, and the document's id is inside every key derivation, so each of those
  tamperings makes the decryption fail rather than producing plausible bytes.
- **A passive network attacker.** All traffic is expected to run over TLS terminated by
  your reverse proxy, and the vault payloads are already ciphertext underneath it.
- **Credential stuffing and online guessing.** Rate limiting, account lockout with progressive
  delays, and 2FA — with the lockout and 2FA paths deliberately built so they do not leak
  whether an account exists. The failed-attempt count behind that lockout is **one counter
  shared by both sign-in steps**, and it is the only per-account limit on the second factor, so
  it is discharged only by a sign-in that actually **completes** — never merely by a correct
  password, which would let anyone already holding one reset the second factor's only brake
  between batches of guesses. A lockout that has genuinely been waited out is the single
  exception, and reaching it costs the full lockout duration. The credential budget is kept
  separate from the budgets for token refresh and vault unlock, so that ordinary use of the app
  can never spend the allowance you need in order to sign in. A caller-supplied value (a
  header, a cookie, a rotating token) appears in a rate-limit key only where an IP-keyed tier
  bounds the same route regardless — the per-account tier keys on the submitted email for that
  reason, and the refresh tier, which has no such companion, keys on the address alone. Getting
  either wrong turns a limiter into a lockout of the legitimate user, an open door for the
  attacker, or both. Every IP-keyed tier buckets IPv6 by its **`/64` prefix** rather than by
  the individual address, because a single routed IPv6 allocation hands one attacker 18
  quintillion addresses: keyed on the full `/128`, an IP-keyed limiter is not a limiter at all,
  it is a counter that never reaches two. That aggregation happens inside the library that
  parses the address, so it is a dependency this project deliberately keeps current — the
  advisory that stood in exactly that code path (`ip-address`, reachable from every rate-limit
  key) is cleared, and the `/64` bucketing is pinned by a test rather than left to a default.
- **One account reading or changing another's data.** Every route that takes an id scopes its query
  to the authenticated user, and that is asserted **exhaustively rather than by sampling**: the
  route table is built from the real Express router — so a route added tomorrow appears in it
  automatically and cannot be forgotten — and every id-taking route is driven with a second
  account's credentials against the first account's resource. Both halves are checked, because only
  the second one is the security property: the request is refused, **and** the target is unchanged
  afterwards. A 404 that deleted the row on the way out would pass the first check on its own.
- **A value you control selecting a code path on the server.** Cookies are decoded before they
  reach the application, and a specially shaped value arrives as a number or an object rather than
  the text that was sent — so a cookie is treated as a value only where it is genuinely text, and
  that narrowing has exactly one definition that every reader goes through. A cookie the server
  cannot read behaves **exactly as an absent one**, everywhere: not as a server error, and not as a
  distinguishable rejection that would confirm the probe was understood.
- **Backup theft.** Emailed and downloaded backups are encrypted under a _separate_
  backup password and carry an HMAC-SHA256 integrity signature that is verified on restore.
- **Tampered backup files.** Restore validates the signature, rejects dangling and
  self-referential folder links, and breaks any folder cycle a malicious file plants.
- **Irreversible loss of your own data through the app itself.** This is an availability
  property, and zero knowledge is precisely what makes it a security concern: because the
  server holds no plaintext, a decrypted blob the client overwrites incorrectly is gone —
  there is nothing to restore it from and nothing to diff it against. Three controls stand
  in the way, all three on the **editing and import paths** specifically. An item's
  contents are validated against their format before being encrypted, so a value the
  vault would not be able to read back is refused at the save rather than stored and
  discovered on the next read — and the same limits are now applied in the editor as
  well, so the common cases are caught against the field being typed into rather than
  at the moment of saving. Saving an item preserves every stored field the editor does
  not itself render, instead of rewriting the item from just the fields on screen; that
  preservation stays in place even though the fields that motivated it now have editors
  of their own, because it is what makes the next field added to an item type safe by
  default. And an item whose contents cannot be decoded is read-only in the sense that
  matters: nothing offered for it rewrites the contents. Move, favourite, delete and
  restore rewrite no ciphertext at all; rename rewrites only the separately-encrypted
  name and does not put the contents in the request; and the editor — which would
  rewrite all of it from a placeholder — is unavailable.
  Two limits, stated rather than implied. This is not a vault-wide integrity check:
  backup restore and vault-key rotation re-encrypt your data as an opaque blob and
  deliberately do not inspect its format, because they must carry through content this
  version may not understand. And none of it substitutes for the encrypted backups
  described above — keep them.

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
  For **documents** the same rule applies with one addition that is accepted rather than
  mitigated: the server learns how many you have, when each was uploaded and last changed,
  which folder it is in, whether it is a favourite, whether it is in the trash — and **its
  size**, because the byte count is what range arithmetic and the storage quota are computed
  from. It does not learn the filename, the extension, the MIME type, the tags, the note or a
  byte of content: all six are sealed in one blob alongside the file's own SHA-256. Length is a
  real leak and it is worth naming: a size can identify a well-known file, and a set of sizes can
  characterise an account. Padding the ciphertext would hide it and is deliberately not done in
  this version, because it would cost every user storage and bandwidth on every document.
  `DOCUMENT_ALLOWED_EXTENSIONS` does **not** mitigate any of this, and is not a security control
  at all: the server receives ciphertext and cannot see a filename, so the allowlist is applied
  by the browser and any file type reaches the API.
  Finally, some of the document store's own configuration is deliberately **public**.
  `GET /api/v1/config` is unauthenticated — it always was, so a browser can size the File
  Encryption tool's guardrail before anyone signs in — and it now also reports whether the
  document store is enabled and, where it is, the per-document size cap, the per-user quota, the
  document ceiling and the extension allowlist. Those are operator limits rather than user data,
  and they are published to anonymous callers exactly as the File Encryption cap already was. If
  the extension list would tell a stranger something about your organisation, leave it empty; it
  buys no enforcement in exchange.
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
- **Granted only against a real second factor.** A remembered login that completes the 2FA step with
  a **backup code** registers no trusted device. A TOTP code proves the second factor is on the
  device right now; a backup code proves the opposite, since the batch of eight is kept precisely
  where the authenticator app is not — printed, in another password manager, mailed to yourself.
  Granting trust from one turned a single line off that sheet into a 30-day skip of the second
  factor on that browser, and, because each trusted-device login mints a fresh remembered session
  while the record keeps its own expiry, into up to 60 days without a TOTP code being presented
  again. The remembered **session** is unaffected: signing in with a backup code and "Remember me"
  still gives you the full 30 days. Only the 2FA skip is withheld. Spending a code is also audited
  as `2fa_backup_code_used`, and the audit log shows how many codes are left beside that entry, so
  you can see it happened and regenerate before the last one is gone.
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
  you can revoke any or all trusted devices yourself from the Sessions page. Because that revocation
  is what makes the sentence above true, turning off the second factor **reads everything the
  request carries before it changes anything**, so nothing you send can interrupt the switch-off
  between the setting and the revocations that must accompany it — which is what used to leave an
  account with the second factor off and every device it had been granted against still skipping
  it. That is a statement about your input, and deliberately not a claim of atomicity: the four
  writes are sequential rather than a single transaction, so a database failure part-way through
  can still leave the setting cleared ahead of the revocations. If that happens, "log out
  everywhere" on the Sessions page drops every other session and every trusted device on its own.

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
size on the wire), follow no redirects, and are **size-bounded**: the reply is capped at
1 MiB — roughly ten times the largest legitimate padded range — enforced incrementally so
the connection is dropped on the chunk that crosses the cap rather than after the body is
already resident. This is the only outbound HTTP call the server makes, its reply is
buffered whole before anything parses it, and the batch endpoint opens eight at once, so
an unbounded reply from an unhealthy or hostile upstream would be a memory-exhaustion
vector against a container with a 1 GB limit. An oversized reply is refused and reported
as a failed check — never as a "not breached" result. The stored copy carries the same
bound.

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
secret, backup code, card number and note in the clear, because that is what a competing
manager needs to import. That makes it the single most dangerous artifact H-Vault can
create, and the threat model reflects that:

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

### Downloading a login's backup codes

A login's 2FA recovery codes can be downloaded from the item as a plain `.txt` file. It is the
one other place H-Vault writes secret material to disk in the clear, and it carries the same
caveat as the plaintext export in miniature: the file is not encrypted, it is generated
entirely in the browser and never uploaded, it is offered only from the saved item (never from
an unsaved form, so a cancelled edit cannot leave codes on disk with nothing in the vault),
and it takes a separate confirmation that states the file is unencrypted before anything is
written. Delete it once you have stored the codes wherever you intended them to go.

### Displaying a stored document

A document store means arbitrary attacker-chosen files meeting third-party parsers — a markdown
pipeline, an HTML sanitizer, a syntax highlighter, a formatter. The precedent that shaped this
design is **CVE-2024-4367 in Mozilla's pdf.js**: opening a malicious PDF ran the document's own
JavaScript _in the context of the hosting page_. In a password manager the hosting page is the one
holding your unlocked vault key.

So the answer here is structural rather than a promise that the parsers are correct: **no byte of
a stored document is ever parsed in the application's own origin** — not when it is displayed, and
not when the optional format-and-repair transforms run before an upload. Both happen inside one
isolated document, embedded as

```html
<iframe src="/sandbox.html" sandbox="allow-scripts" referrerpolicy="no-referrer" allow=""></iframe>
```

- **`allow-scripts` without `allow-same-origin` gives it an opaque origin.** It fails every
  same-origin check: it cannot read the embedding page's DOM, its `sessionStorage`, its IndexedDB,
  `document.cookie`, or anything the application holds in memory. The two flags must never appear
  together — that pair lets the framed document remove its own sandbox and is worth nothing. No
  other flag is granted: no popups, forms, modals, downloads or top-level navigation, and `allow=""`
  denies every delegated permission.
- **It carries its own, far stricter policy.** A document fetched from an `http(s)` URL does not
  inherit its embedder's CSP, so the route that serves it attaches one of its own:
  `default-src 'none'`, `connect-src 'none'`, `worker-src 'none'`, `object-src 'none'`,
  `base-uri 'none'`, `form-action 'none'`, and `sandbox allow-scripts` repeated as a directive so
  the document sandboxes itself even if a future embedder forgets the attribute. **`connect-src
'none'` is the containment, and it is worth being exact about what that buys**: it blocks
  `fetch`, `XMLHttpRequest`, WebSockets, `EventSource` and `sendBeacon`, so a compromised renderer
  can never READ a response; and no directive in the policy names an external host, so nothing it
  emits can reach a third party. What it does not do is stop every packet — `script-src`,
  `style-src`, `img-src` and `font-src` allow `'self'`, and inside a sandboxed document CSP
  resolves `'self'` from the response's URL rather than from the document's opaque origin, so an
  `<img src="/api/v1/…">` is a request this server would see. The honest bound is therefore **no
  host but this one, and no readable answer**, not "no network at all" — the same bound residual
  risk 1 below describes for self-navigation. All of it is affordable only because there is no PDF
  renderer; see below.
- **It is handed bytes and nothing else.** The application decrypts the file, verifies every
  segment's authentication tag and the whole-file digest, and only then posts the plaintext, a
  render mode, an extension hint and the current theme. Never the document key, the vault key, an
  access token, the document's id, or its name. `referrerpolicy="no-referrer"` is there so the
  embedder's URL — which contains the document id — is not handed over in `document.referrer`.
- **The channel is one-shot.** The frame announces itself once on the window; the application
  accepts that handshake **at most once per frame** and removes the listener at that moment,
  then transfers a `MessagePort` and says everything else over it. One frame per document, created
  fresh and destroyed when you navigate away, so one document can never observe the next. A link
  clicked inside the frame is delivered as a message, checked against the same URL allowlist the
  rest of the app uses (http, https and mailto only), and opened only after you confirm a dialog
  showing the destination's origin — an unchecked `javascript:` URL opened by the application would
  run in the application's origin, which is the whole compromise in one message.
- **PDF and Office formats are download-only, deliberately.** Carrying a PDF renderer would have
  meant a large parser with the history above, plus a worker and a WebAssembly module fetched by
  URL — which would have forced `connect-src` and `worker-src` open for every other format too.
  Downloading a PDF and opening it in the viewer the operating system already has is the better
  trade, and the interface says exactly that rather than showing a broken frame.

**Four residual risks, named rather than implied.** Isolation is a boundary, not a proof of
correctness, and these are the things it does not buy:

1. **A compromised renderer can leak the one file it was handed, by navigating itself away.** No
   sandbox flag and no CSP directive stops a document navigating _itself_, so bytes can be put in
   a URL and carried out. The sandbox flags follow the navigation — the new document is still
   sandboxed and still opaque — so it reaches no vault data and no other document. But a navigated
   document carries **no CSP** (a policy is per-response and does not survive a navigation), so it
   does have network access, and it would be an exfiltration endpoint if the application ever spoke
   to it again. What stops that is the one-shot handshake above: the port died with the previous
   document and the listener that could grant a new one is gone. `window.name` survives a
   navigation and is a second channel of the same shape and the same bounded impact — one file.
2. **It can draw a convincing fake interface inside its own rectangle.** Nothing prevents a
   renderer painting something that looks like a prompt. This is why the master password is asked
   for **only on the full-page lock screen** and nowhere else, and why the document's title, its
   toolbar and its download button are drawn by the application _outside_ the frame, where a
   renderer cannot forge them.
3. **Isolation does nothing about a renderer that displays something other than the file.** A bug
   that renders the wrong text is invisible to every boundary described here, and it matters most
   for exactly the documents someone reads in order to act on them — a recovery sheet, a set of
   backup codes, a key. When the contents matter that much, download the file and check it.
4. **The application still decrypts every byte in its own origin** before posting it to the frame.
   The property this design buys is that untrusted input is never _parsed_ there — not that it
   never exists there. A flaw in the application's own code is still a flaw in the application.

### Rotating your vault key while another session is open

Rotating your vault key does not sign out your other sessions, and that is deliberate: it is a
key operation, not a credential change, and forcing every device to re-authenticate would make a
routine hygiene step feel like a breach. The consequence is that a browser tab left open
elsewhere goes on holding the key it was given when it signed in, and nothing tells it the
account has moved past that key.

Everything encrypted under the vault key is re-encrypted by the rotation itself, so an older
session only matters when it writes something new. Uploading a document is that case, because a
document's own key is wrapped in the browser under the vault key the browser holds. Each sign-in
is therefore told which generation of the vault key it received, and an upload says which one it
used; if that is no longer the current one the upload is refused, the browser fetches the current
key, re-wraps the document's key and finishes — without re-sending the file. A document is never
stored under a key the account no longer has. If you would rather not rely on that at all, sign
out of your other devices from the Sessions page before rotating.

### Deleting a document, and why it cannot be undone

A stored document is two things: an entry in the database and a file of ciphertext in object
storage. The entry holds the only wrapped copy of the key that decrypts that file — the key
exists nowhere else, not on the server, not in the browser once the vault is locked, and not
in a backup, because **documents are deliberately not part of a backup** (their bytes cannot
fit a backup file, and metadata without bytes would restore entries pointing at files that do
not exist; a backup therefore carries only a count, so a restored account cannot quietly look
complete). Deleting the entry is therefore the act that destroys the document. Any file that
somehow survives it is ciphertext under a key that no longer exists anywhere.

That shapes the order every deletion path uses, and it is worth stating because the two
orders look interchangeable and are not:

- **Deleting one document permanently** marks the entry, deletes the file, then deletes the
  entry. A crash in the middle leaves a marker the hourly clean-up finishes; the reverse
  order would leave a file that nothing is left to name. Emptying the document trash and the
  nightly purge of documents trashed beyond `TRASH_AUTO_PURGE_DAYS` do exactly the same
  thing, one document at a time, and a file the storage service refuses to delete leaves its
  entry marked for the next run rather than removing an entry whose file is still there.
- **Deleting an account** is the one path that runs the other way round: every entry is
  removed with the rest of the account's data first, and only then are the account's files
  swept from storage by prefix. Because the entries are already gone, a file the sweep cannot
  reach is already unreadable rather than a document still standing. The erasure is reported
  as complete in that case — it is — and the failure is logged for the operator, with the
  remainder reclaimed by the scheduled clean-up. On a deployment with no document store
  configured the sweep does nothing at all.

Neither deletion is recoverable, and neither is undone by restoring a backup. The same fact
has an operational consequence that belongs to whoever runs the server rather than to whoever
uses it: because documents are not in a backup, the **storage volume is the only copy of every
uploaded file**, and it must be captured alongside the database and the deployment's `.env` —
the wrapped keys live in the database, the ciphertext lives in the storage service, and neither
half is usable without the other. The README's backup section gives the volumes and the
procedure, including why a file-level copy of a running storage engine is not a backup.

That answer is only available to the operator, and on a shared deployment the operator and the
account holder are not the same person. **Download all**, on the Documents page, is the half that
belongs to the account holder: it saves every document the list is showing to their own device,
one at a time, through the identical verified read a single download uses — each file checked
against the digest sealed inside it before a byte of it is written, and no file produced at all
for a document that fails that check. Nothing is combined into an archive, deliberately: a ZIP
writer is a format implementation fed entirely by attacker-chosen bytes and names, and it would
run in the one origin holding the unlocked vault key. Three limits are worth being plain about,
because an export that is trusted for more than it is is worse than none:

- **It is a copy, not a backup, and it is plaintext.** What lands on the device is the decrypted
  file, protected by nothing this application controls — the same trade the plaintext vault export
  makes, and it deserves the same handling.
- **It is one account's view at one moment.** It carries what that account can list: not another
  account's documents, not a row whose sealed metadata will not open (there is no key left to open
  it with, so there is nothing to hand back), and not a row already claimed for permanent deletion.
  Each of those is named in the summary rather than quietly omitted, and the panel says how many
  rows the view could not read at all.
- **It cannot confirm where the files went.** Handing a file to the browser is the last thing the
  page can observe; browsers refuse or queue several downloads from one action and report nothing
  back. The summary therefore says documents were _verified and sent to your browser's downloads_
  and never that they were saved, and it points at the browser's own download list, which is the
  only authoritative record.

The export changes nothing on the server: it is the same authenticated read of the same rows,
under the same per-user rate limits, and it is not audited for the same reason no other read is.
When those limits stop it, or the vault auto-locks part way through, it says which of the two
happened, how much of the library is still on the server, and offers to resume from there.

The hourly clean-up referred to above is the only thing in the system that deletes a stored
file without a request having asked for it, so the rule it works to is stated in the negative:
it deletes a file only when it can prove nothing refers to it. A file is left where it is
whenever its name is not one this system wrote, whenever the storage service does not report
how old it is, whenever it is less than a day old, whenever any entry at all names it —
active, in the trash, or part-way through being purged — and whenever the transfer that
created it could still be completed. Every one of those is a reason to do nothing, because an
unreclaimed file costs storage while a file deleted in error costs a document that no backup
and no key can bring back. The clean-up also stops early once the storage service has refused
several operations in a row, so a failing service produces one short run an hour rather than a
run that never ends.

### Importing codes from Google Authenticator

Reading an authenticator export happens entirely in your browser. The QR code is decoded, the
payload inside it is parsed, and the keys are turned into `otpauth://` links without any of it
reaching the server. The server is involved only if you then choose to create a vault item or
save the set into the document store, and by then the value is encrypted like anything else.

Three things about it are worth stating plainly.

**The decoder runs in the isolated document, not in the page that holds your vault key.** A QR
decoder is third-party code being fed pixels from whatever a camera was pointed at, which is the
one kind of input this application takes from outside the machine. It therefore runs in the same
sandboxed frame the document viewer uses: an opaque origin, no vault key beside it, no token, no
storage, and a policy of `connect-src 'none'`. Running it in the application's own origin would
put it next to the unlocked vault with a full network available to it.

**The residual risk that frame does leave.** Its policy allows `img-src 'self'`, and any iframe can
navigate itself, so a compromised release of that decoder could make credential-less same-origin
GET requests. It could not read the responses, and no cookie would be attached, but a request URL
would land in this server's own access log. That channel cannot be closed for any iframe, and it
is much smaller than the alternative, where the same compromise would have the vault key in reach.
The decoder is a small, zero-dependency package and is pinned like everything else.

**What the decoded keys are while they are on screen.** They are unwrapped TOTP secrets, which is
the plainest secret this application ever holds. They live in one module-level map, never in a
component's props or in a store, and they are overwritten with zeros when you leave the page, when
the vault locks, when you sign out, and when you press Start over. Strings derived from them for
display cannot be overwritten, because JavaScript strings are immutable; those are built at the
moment of use and not kept. Auto-lock is deliberately not suspended while the page is open, so a
long import can be interrupted by the lock, and the page says so rather than holding the vault
open for convenience.

### Your password generator settings are stored in the clear

The length, character types and minimum counts the generator uses are saved on your account as
ordinary settings, beside your auto-lock timeout and theme. They are not encrypted, so an operator
with database access, or anyone who obtains a copy of it, can see the policy behind the passwords
you generate.

This does not weaken a password in the way it may first appear. The strength figure this
application reports already assumes an attacker who knows the policy, which is the conservative
assumption and the correct one; a generated password's strength comes from the random choice
within that policy, not from the policy being secret. It is recorded here because it is
nonetheless a thing the server learns about you, and the threat model above should not have to be
read between the lines.

### Auto-lock

The vault locks after `autoLockTimeout` minutes without interaction (1 to 1440, default 15).
Locking zeroes the vault key and the master encryption key and clears decrypted data from
memory and from the offline cache; the session itself stays alive, so unlocking needs only the
master password, not a full sign-in.

Two properties of that timer are worth stating plainly, because the obvious implementation
gets both wrong:

- **The deadline is wall-clock, not elapsed timer time.** A `setTimeout` measures how long the
  page has been _running_, and browsers do not run a hidden tab on schedule: they throttle its
  timers to roughly one wake per minute after a few minutes hidden, may freeze a discarded tab
  entirely, and stop the clock outright while the machine sleeps. A timer can therefore only
  fire LATE — which for a lock means staying unlocked longer than you asked. H-Vault stores the
  deadline as an absolute instant and re-checks it against the clock whenever the page could
  have missed a wake: on becoming visible, on focus, on a bfcache restore, and on a coarse
  interval. Returning from an hour's sleep locks immediately rather than after the remainder of
  a stale timer.
- **Hiding the tab does not, by itself, lock the vault.** It stops resetting the idle deadline —
  nothing generates activity in a hidden tab — so a hidden tab still locks exactly on schedule.
  Locking sooner _because_ the tab is hidden is a separate opt-in setting (`lockOnHidden`, with
  its own delay in minutes), off by default. Earlier versions did this unconditionally after 30
  seconds regardless of the configured timeout, which meant switching tabs to look something up
  locked the vault; if you want that behaviour, turn it on and choose the delay.

The lock is a client-side control over key material in one browser. It is not an
authentication boundary: the server-side session, its refresh token and its absolute deadline
are what actually bound access, and `POST /auth/verify-unlock` — rate-limited per user — is what
checks the master password on unlock, so clearing browser storage cannot bypass it.

### The OS clipboard

Copying a secret puts it on the operating-system clipboard, which is shared with every
application on the machine and, on some systems, with clipboard-history tools and with other
devices via clipboard sync. H-Vault reduces the exposure window but cannot eliminate it.

- Every copy of secret material goes through one guard, which erases the clipboard after
  the `clipboardClearTimeout` setting (5 to 300 seconds, default 30) and on vault lock,
  logout, or the tab being closed for good.
- **Backgrounding the window deliberately does not erase it.** Switching tabs, minimising,
  or being covered by another window is how you get to the application you are pasting
  into, so the deadline, not the visibility change, decides when the secret goes.
- **The browser decides whether a page may erase the clipboard at all, and no engine
  guarantees it.** Chromium rejects a clipboard write from an unfocused document, so if the
  deadline passes while H-Vault is in the background the erase physically cannot happen at
  that moment. Firefox and Safari state a stricter rule: they require a user gesture for
  _every_ clipboard write, which means a purely timer-driven erase can never succeed on
  those engines, foreground or background. **Do not read that contrast as "the timed erase
  is reliable on Chromium".** This project's own browser tests drive the real deadline on
  both engines it runs, with the page in front and — on Chromium — with the clipboard
  permission granted, and the write is refused on **both**. Whatever the underlying rule
  turns out to be on a given build, the design does not depend on knowing it: a timer-driven
  erase is treated as something that may be refused anywhere, and the retry below is what
  actually lands it.
  H-Vault does not abandon a refused erase. It retries on the next moment the engine will
  accept one: returning to the window, and — the trigger that also works on Firefox and
  Safari — your next click or keypress in H-Vault. In practice that means the erase lands
  the next time you interact with the app. Until then the secret is still on the clipboard.
  Locking or logging out _yourself_ (a real click, or `Ctrl`+`L`) erases it immediately on
  every engine, because that write happens inside your own keypress. An **idle auto-lock** is
  timer-driven, so on Firefox and Safari its erase is retried at your next interaction like
  any other.
- **The erase is unconditional and cannot verify what it is erasing.** Confirming that the
  clipboard still holds H-Vault's secret would require clipboard _read_ access, which would
  mean the page could read anything you had copied from any other application. The guard
  writes an empty string blind instead, which needs write access only. The consequence is
  that a pending erase can clear something you copied elsewhere in the meantime.
- Clipboard state is per browser tab. A lock or logout in one tab does not erase a secret a
  different tab copied, because only the focused tab can write to the clipboard and a tab
  that never copied anything cannot know what the clipboard holds.
- The clipboard is outside the encryption boundary entirely. Nothing H-Vault does protects
  a secret you have pasted somewhere and left there.

## Security practices in this repository

- Every push runs `npm run ci` locally through the `pre-push` hook — twenty-nine gates,
  including a dependency audit at moderate and above over the production tree, ESLint with
  `eslint-plugin-security`, static analysis (CodeQL where the CLI is installed, otherwise
  Semgrep CE or OpenGrep, and the gate reports which engine answered), container builds
  scanned with Trivy (zero fixable CRITICAL/HIGH), a secret scan over every tracked file
  **and every blob in git history**, the cross-user authorization matrix over the whole
  route table, a conformance run of the storage port against the real object-storage engine
  in a container, and a redaction suite that asserts no request value, audit row or
  production error body carries a secret. Eight further gates run before a release, among them a fuzz
  run over the seven import parsers, a crash-consistency drill that SIGKILLs a real process
  mid-write, the mutation oracle, and the deployment clean room.
- The gates are themselves guarded, because a security gate that can be edited to pass is
  not a control. Every marker that weakens a check — a skipped test, a silenced analyzer, a
  swallowed error — must be absent or written down in `.testfortress/suppressions.json`
  with an owner, a reason and an expiry; every gated number is ratcheted in one direction
  only against `.testfortress/baseline.json`; and `npm run verify:selftest` plants one
  defect per registered gate and requires each to go red for a reason its own report
  attributes to that defect. A gate whose prerequisite is missing on the machine — an
  absent CodeQL CLI, a stopped Docker daemon — is reported BLOCKED and counted separately,
  never as proven.
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

### The object storage service

The bundled Docker stack runs an S3-compatible storage service for the document store. Three
properties of it are load-bearing. The first two are asserted by the test suite rather than
left to a reviewer's eye; the third is a measured behaviour of the engine, so it is written
down and covered by the deployment drill rather than by a unit test:

- **It publishes no port and sits on the internal network.** Its S3 API authenticates with a
  static key pair and has none of the application's rate limiting, CSRF handling or session
  management in front of it, so the app container is the only thing that can reach it. Do not
  publish it "for tooling"; use `docker compose exec` instead.
- **Its image is pinned by digest.** It is the one image in the stack this repository does not
  build, and a tag is a mutable pointer.
- **Its bucket credentials rotate as a pair.** Measured against the pinned engine: changing
  the secret alone makes the service exit 1 and refuse to start rather than adopt the new
  value, which under a restart policy is a crash loop. Change the access key id and the secret
  together, then delete the superseded key. The README's secret-rotation table carries the
  procedure.

The service holds nothing but ciphertext: documents are sealed in the browser under a key the
server never sees, so it holds no filename, no MIME type, no tag, no note and no content. That
is what makes it safe for it to be a separate service at all — but it is also why its volume,
and only its volume, holds your users' files. See the backup boundary above.
