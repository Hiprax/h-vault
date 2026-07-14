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
  is not.
- **Your deployment.** An exposed MongoDB port, a `TRUST_PROXY` set higher than the number
  of proxies actually in front of the app, secrets committed to a repository, or a missing
  TLS certificate will undo the guarantees above. The deployment checklist in the README
  exists for this reason.

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
