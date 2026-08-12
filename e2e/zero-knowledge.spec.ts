import { test, expect, type Page, type Request } from '@playwright/test';
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { open, readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import * as OTPAuth from 'otpauth';
import { seededRandom } from '../tests/harness/determinism.js';
import { registerAndSignInViaUI, testDb, testEmail, unlockVault } from './helpers';

/**
 * The zero-knowledge boundary, asserted NEGATIVELY across one whole session.
 *
 * This is the product's entire premise — "the server never sees your data" — and
 * until now it was only ever asserted in fragments: `import-export.spec.ts` checks
 * the import body, `plaintext-export.spec.ts` checks the export call and browser
 * storage. Each proves its own feature; none proves the claim. This spec drives a
 * complete session (register, create one item of every type, edit, search, lock,
 * unlock, rotate the vault key, export, import, back up, restore, enable 2FA, log
 * out), records EVERY request the browser makes along the way, and requires that
 * no plaintext field, no master password, no raw MEK and no unwrapped vault key
 * appears in any of them — nor afterwards in the server's audit rows, its log
 * files, or the documents it stored.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS NOT VACUOUS
 * ---------------------------------------------------------------------------
 *
 * A test that searches recorded traffic for strings it never planted passes by
 * doing nothing, and so does one whose recorder was never attached. Four
 * independent guards make the green result mean something:
 *
 *  1. THE KEYS ARE DERIVED INDEPENDENTLY, IN NODE. The master password and the
 *     email are all it takes to recompute the 512 bits the browser derives
 *     (PBKDF2-SHA-256, 600k, email as salt) and therefore the raw MEK; the
 *     registration request carries the wrapped vault key, so the MEK unwraps it
 *     to the vault key itself. If any step of that reconstruction were wrong the
 *     GCM tag check throws — so reaching a 32-byte vault key proves the secrets
 *     being searched for are the real ones, not plausible-looking noise.
 *  2. THE CIPHERTEXT IS DECRYPTED BACK. Every `POST /vault/items` body is
 *     decrypted with that vault key and matched to the item it created: the
 *     sentinel MUST come back out. That is what proves the recorder saw the very
 *     request that carried the value, rather than having missed it entirely.
 *  3. THE REQUIRED CALLS ARE PINNED. The session's fourteen defining API calls
 *     are asserted present in the recording. A flow that silently stopped
 *     happening — or a recorder that stopped recording — fails here rather than
 *     passing quietly.
 *  4. THE SIDE CHANNELS ARE PROVEN LIVE. The audit scan asserts the expected
 *     rows exist before asserting they are clean, and the log scan asserts the
 *     captured slice actually contains this session's request lines.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS RECORDED, AND WHAT IS DELIBERATELY NOT
 * ---------------------------------------------------------------------------
 *
 * Both capture paths named in the invariant are used, and they are independent:
 * `context.route('**\/api\/**')` sees every API request at interception time, and
 * `context.on('request')` sees every request of any kind, including the ones
 * routing does not match. Each record is flattened into method, URL, headers and
 * body, and it is that flat text the scan reads — a leak into a query parameter
 * or a custom header fails exactly like a leak into a body.
 *
 * `request.headers()` is used rather than `allHeaders()` because it is
 * synchronous: an awaited call inside an event handler would leave promises in
 * flight at assertion time, and the one thing `allHeaders()` adds — cookies — is
 * covered directly and more completely by dumping `context.cookies()` at the end,
 * which sees every cookie the session ever held rather than only those attached
 * to some request.
 *
 * `data:` and `blob:` URLs are excluded. They are not outbound traffic in any
 * sense — nothing is transmitted — and the 2FA QR code is exactly such a URL, so
 * including them would report the browser drawing its own image as a leak.
 */

// ─── Sentinels ───────────────────────────────────────────────────────────────

/**
 * Sentinel values are seeded AND run-unique, for the same reason
 * `helpers.testEmail()` is: the seeded stream (`SEED`, default 1337) makes a run
 * reproducible in shape, while the timestamp guarantees that a value planted
 * today can never be confused with one a previous run left in `logs/`, which is
 * an append-only directory this spec reads.
 */
const nextRandom = seededRandom();
const RUN_ID = `${Date.now().toString(36)}-${nextRandom().toString(36).slice(2, 8)}`;
let sentinelCount = 0;

/** A high-entropy value that exists nowhere else in the system. */
function sentinel(label: string): string {
  sentinelCount += 1;
  const noise = `${nextRandom().toString(36).slice(2, 12)}${nextRandom().toString(36).slice(2, 12)}`;
  return `zks-${label}-${RUN_ID}-${String(sentinelCount)}-${noise}`;
}

/**
 * A Luhn-valid 16-digit card number built from the seeded stream.
 *
 * The card form refuses anything that fails the Luhn check, so the one field on
 * a card worth planting a sentinel in cannot simply be a random string. Fifteen
 * seeded digits plus the computed check digit give a number that is both
 * acceptable to the form and unique to this run.
 */
function sentinelCardNumber(): string {
  let digits = '';
  while (digits.length < 15) digits += Math.floor(nextRandom() * 10).toString();
  let sum = 0;
  // The check digit is position 16, so the first digit is in a doubling column.
  for (const [index, char] of [...digits].entries()) {
    const value = Number(char);
    const doubled = index % 2 === 0 ? value * 2 : value;
    sum += doubled > 9 ? doubled - 9 : doubled;
  }
  return `${digits}${String((10 - (sum % 10)) % 10)}`;
}

/**
 * A base32 TOTP seed from the same stream.
 *
 * The seed cannot be an ordinary sentinel: the login detail view renders a live
 * code from whatever is stored, so an unparseable seed would fail the item's own
 * page rather than the boundary this spec is about. 32 base32 characters is 160
 * bits, which is unique enough to search for.
 */
function sentinelTotpSeed(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let seed = '';
  while (seed.length < 32) seed += alphabet[Math.floor(nextRandom() * alphabet.length)] ?? 'A';
  return seed;
}

/**
 * Every planted value. Item NAMES are sentinels in their own right rather than a
 * readable prefix plus one: the name is encrypted as `encryptedName`, so it is a
 * plaintext field like any other and the scan has to be able to find it alone.
 */
const PLANTED = {
  loginName: sentinel('login-name'),
  loginUsername: sentinel('login-username'),
  loginPassword: sentinel('login-password'),
  loginTotp: sentinelTotpSeed(),
  loginBackupCode: `ZKSBKP-${RUN_ID.replace(/-/g, '')}-${nextRandom().toString(36).slice(2, 10)}`,
  customFieldName: sentinel('custom-name'),
  customFieldValue: sentinel('custom-value'),
  loginNotesEdited: sentinel('login-notes-edited'),
  secretName: sentinel('secret-name'),
  secretValue: sentinel('secret-value'),
  noteName: sentinel('note-name'),
  noteContent: sentinel('note-content'),
  cardName: sentinel('card-name'),
  cardholderName: sentinel('cardholder'),
  cardNumber: sentinelCardNumber(),
  identityName: sentinel('identity-name'),
  identityFirstName: sentinel('identity-first'),
  identityLastName: sentinel('identity-last'),
  identityStreet: sentinel('identity-street'),
  identityDeliveryNotes: sentinel('delivery-notes'),
  importUsername: `${sentinel('import-username')}@example.com`,
  importPassword: sentinel('import-password'),
} as const;

/**
 * The master password, itself a sentinel.
 *
 * It has to clear the registration gate (zxcvbn >= 3, >= 12 characters), which a
 * long random string does comfortably, and it must be unique to this run so that
 * finding it anywhere is attributable to this session and to nothing else.
 */
const MASTER_PASSWORD = `Zk!7${sentinel('master').replace(/-/g, '')}#Qx2`;
/** zxcvbn >= 3 as well: the backup-encryption setup gate requires it. */
const BACKUP_PASSWORD = `Bk#4${sentinel('backup-pw').replace(/-/g, '')}!Vt9`;

// ─── The wire recording ──────────────────────────────────────────────────────

interface WireRecord {
  readonly channel: 'route' | 'event';
  readonly method: string;
  readonly url: string;
  /** method + URL + headers + body, flattened — this is what the scan reads. */
  readonly text: string;
}

function flatten(channel: 'route' | 'event', request: Request): WireRecord | null {
  const url = request.url();
  // Not outbound traffic: nothing is transmitted for a data: or blob: URL.
  if (!/^https?:/i.test(url)) return null;
  const method = request.method();
  const body = request.postData() ?? request.postDataBuffer()?.toString('utf8') ?? '';
  return {
    channel,
    method,
    url,
    text: `${method} ${url}\n${JSON.stringify(request.headers())}\n${body}`,
  };
}

/** Attaches both capture paths. Must run before the first navigation. */
async function recordWire(page: Page): Promise<WireRecord[]> {
  const wire: WireRecord[] = [];
  const context = page.context();
  context.on('request', (request) => {
    const record = flatten('event', request);
    if (record) wire.push(record);
  });
  await context.route('**/api/**', async (route) => {
    const record = flatten('route', route.request());
    if (record) wire.push(record);
    // A page that navigated away mid-flight makes `continue` reject; the request
    // is already recorded, and failing the test for it would be noise.
    await route.continue().catch(() => undefined);
  });
  return wire;
}

/**
 * The forms one planted value could appear in, on the wire or in a cookie.
 *
 * A raw `includes` is not enough on its own. Two of the sentinels are the two
 * passwords, and both carry a `#` by construction (they have to clear the
 * zxcvbn gate); `encodeURIComponent` turns that into `%23`, so a leak through a
 * query string, a form-encoded body or a cookie value would not have matched the
 * literal at all — and those are exactly the channels where percent-encoding
 * happens. Every other planted value is URL-safe by construction (that is why
 * the card number is digits and the TOTP seed base32), so this expansion is a
 * no-op for them and costs one deduplicated comparison.
 *
 * JSON escaping needs no equivalent: no planted value contains a quote or a
 * backslash, so `JSON.stringify` reproduces each one verbatim.
 */
function searchForms(value: string): string[] {
  const encoded = encodeURIComponent(value);
  return encoded === value ? [value] : [value, encoded];
}

/** Whether `haystack` carries `secret` in any of the forms it could take. */
function carries(haystack: string, secret: { value: string }): boolean {
  return searchForms(secret.value).some((form) => haystack.includes(form));
}

/** Every recorded request whose method and URL match. */
function callsTo(wire: readonly WireRecord[], method: string, urlPart: string): WireRecord[] {
  return wire.filter((record) => record.method === method && record.url.includes(urlPart));
}

/** The parsed JSON body of one record, or `undefined` when it carried none. */
function jsonBodyOf(record: WireRecord): Record<string, unknown> | undefined {
  const body = record.text.slice(record.text.indexOf('\n', record.text.indexOf('\n') + 1) + 1);
  if (body.trim() === '') return undefined;
  try {
    return JSON.parse(body) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** The parsed JSON body of the first matching request, or `undefined`. */
function firstJsonBody(
  wire: readonly WireRecord[],
  method: string,
  urlPart: string,
): Record<string, unknown> | undefined {
  for (const record of callsTo(wire, method, urlPart)) {
    const body = jsonBodyOf(record);
    if (body) return body;
  }
  return undefined;
}

// ─── Independent key reconstruction (guard 1) ────────────────────────────────

const PBKDF2_ITERATIONS = 600_000;

/** The browser's first 32 derived bytes: the Master Encryption Key material. */
function deriveMek(masterPassword: string, email: string): Buffer {
  const derived = pbkdf2Sync(
    masterPassword,
    email.trim().toLowerCase(),
    PBKDF2_ITERATIONS,
    64,
    'sha256',
  );
  return derived.subarray(0, 32);
}

interface SealedValue {
  readonly encrypted: string;
  readonly iv: string;
  readonly tag: string;
}

/** AES-256-GCM open, in the split ciphertext/tag encoding `cryptoService` emits. */
function open256Gcm(key: Buffer, sealed: SealedValue): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(sealed.encrypted, 'base64')),
    decipher.final(),
  ]);
}

/** Reads a `{encrypted, iv, tag}` triple out of a request body under three names. */
function sealedFrom(
  body: Record<string, unknown>,
  encryptedKey: string,
  ivKey: string,
  tagKey: string,
): SealedValue {
  return {
    encrypted: String(body[encryptedKey] ?? ''),
    iv: String(body[ivKey] ?? ''),
    tag: String(body[tagKey] ?? ''),
  };
}

/**
 * Every encoding a 32-byte key could plausibly leak as.
 *
 * Four rather than one, and the unpadded variant is not redundant: a substring
 * search for the padded form does not match an unpadded emission (`abc=` is not
 * inside `abc`), so a key sent through `btoa`-then-strip would slip past a
 * padded-only scan. `cryptoService` emits padded standard base64 everywhere, so
 * that is the realistic case; the rest are the cheap insurance.
 */
function keyEncodings(label: string, key: Buffer): { label: string; value: string }[] {
  return [
    { label: `${label} (base64)`, value: key.toString('base64') },
    { label: `${label} (base64, unpadded)`, value: key.toString('base64').replace(/=+$/, '') },
    { label: `${label} (base64url)`, value: key.toString('base64url') },
    { label: `${label} (hex)`, value: key.toString('hex') },
    { label: `${label} (HEX)`, value: key.toString('hex').toUpperCase() },
  ];
}

// ─── The server's own log files (side channel) ───────────────────────────────

/**
 * Anchored on this file, never on `process.cwd()`, so the scan reads the same
 * directories whichever way the suite was started.
 *
 * `__dirname` rather than `import.meta.url`, and that is not a style choice:
 * Playwright loads a spec through a CommonJS require path (the root
 * `package.json` is not `type: module`), where `import.meta` is a SYNTAX ERROR
 * that takes the whole file out of the run — "No tests found", with the real
 * cause a warning above it. `playwright.config.ts` carries the same note.
 */
const REPO_ROOT = path.resolve(__dirname, '..');
/**
 * Both directories the server can write to. `@hiprax/logger` resolves its log
 * directory from `process.cwd()`, and npm runs a workspace script from that
 * workspace, so the dev server writes under `packages/server/logs` while
 * anything started from the repository root writes to `logs/`. Reading both
 * costs nothing and removes a silent dependency on how the harness was started.
 */
const LOG_DIRS = [path.join(REPO_ROOT, 'logs'), path.join(REPO_ROOT, 'packages', 'server', 'logs')];

type LogOffsets = Map<string, number>;

/**
 * A log file this scan must read, INCLUDING a rotated one.
 *
 * `@hiprax/logger` drives winston-daily-rotate-file with `maxSize: '20m'`, and
 * file-stream-rotator names each new chunk by appending an INDEX to the current
 * name: once `http-2026-08-12.log` fills, the live file is
 * `http-2026-08-12.log.1`, then `.2`, while the plain `.log` never grows again.
 * Matching only `.log` therefore reads a file the server has stopped writing to
 * — and it does not fail loudly, because the OTHER loggers (`auth`,
 * `backup-controller`) are small, unrotated, and keep the captured slice
 * non-empty. Measured: the request log and the combined log were both rotated,
 * so the slice held this session's sign-in but not one of its HTTP lines, and
 * the anti-vacuity guard at the end of this spec failed — correctly. Without
 * that guard the "no log line carried a secret" scan would have passed over the
 * two files that carry every request.
 *
 * `.gz` is deliberately not matched: an archived chunk is compressed, so
 * reading it as UTF-8 yields noise rather than log lines. `zippedArchive` is
 * off, so no such file exists today; the pattern says so rather than relying on
 * it. The `.<hash>-audit.json` bookkeeping files are excluded for free.
 */
const LOG_FILE_NAME = /\.log(\.\d+)?$/;

async function logFiles(): Promise<string[]> {
  const files: string[] = [];
  for (const dir of LOG_DIRS) {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      continue;
    }
    for (const name of names) if (LOG_FILE_NAME.test(name)) files.push(path.join(dir, name));
  }
  return files;
}

/** Sizes of every log file, so only what THIS session appends is read back. */
async function logOffsets(): Promise<LogOffsets> {
  const offsets: LogOffsets = new Map();
  for (const file of await logFiles()) offsets.set(file, (await stat(file)).size);
  return offsets;
}

/**
 * Everything the server logged after {@link logOffsets} was taken.
 *
 * The file list is re-read here rather than taken from `before`, which is what
 * makes a rotation DURING the session visible: the new index did not exist when
 * the offsets were captured, so `before.get(file)` is undefined, `?? 0` reads it
 * from the beginning, and nothing of this session is missed. Re-reading a chunk
 * in full is harmless — every sentinel is unique to this run, so an over-read
 * cannot produce a false positive.
 */
async function logsWrittenSince(before: LogOffsets): Promise<string> {
  const chunks: string[] = [];
  for (const file of await logFiles()) {
    const size = (await stat(file)).size;
    const from = before.get(file) ?? 0;
    // Nothing appended since the offsets were taken. With rotated names matched
    // this is the ordinary "idle file" case: the rotator renames forward and
    // never truncates in place, so a file that was live at capture time either
    // grew or was frozen by a rotation whose successor is read above.
    if (size <= from) continue;
    const handle = await open(file, 'r');
    try {
      const buffer = Buffer.alloc(size - from);
      await handle.read(buffer, 0, buffer.length, from);
      chunks.push(buffer.toString('utf8'));
    } finally {
      await handle.close();
    }
  }
  return chunks.join('\n');
}

// ─── UI helpers ──────────────────────────────────────────────────────────────

async function openCreateDialog(page: Page) {
  await page
    .getByRole('button', { name: /^create (new )?item$/i })
    .first()
    .click();
  const dialog = page.getByRole('dialog', { name: /create new vault item/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function goToVault(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
}

async function goToSettings(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
}

async function openItem(page: Page, name: string): Promise<void> {
  await goToVault(page);
  await page.getByTestId('vault-item-name').filter({ hasText: name }).click();
  await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);
}

// ─── The spec ────────────────────────────────────────────────────────────────

/**
 * One test, one session, one registration — deliberately.
 *
 * The invariant is about a whole session rather than about any one call, and
 * every step here costs a 600k-iteration PBKDF2 derivation in the browser (nine
 * of them by the end: register, sign in, unlock, rotate, export, 2FA, and three
 * BEK derivations for backup setup, download and restore), so splitting it into
 * separate tests would mean paying for a fresh account each time to assert the
 * same thing.
 *
 * The budget is bound by that derivation cost, not by network latency. Measured
 * end to end on the reference machine: 24 seconds. It is set two orders of
 * magnitude above that because `helpers.ts` budgets 90 s for ONE derivation on a
 * contended machine, and nine of those is 810 s — so this ceiling is already
 * below the theoretical worst case and must not be tightened. It is a ceiling,
 * not a cost: nothing waits for it unless something is already wrong.
 */
const SESSION_TIMEOUT_MS = 600_000;

test.describe('zero-knowledge boundary', () => {
  // Pins the two matchers the side-channel scans depend on, so neither can be
  // narrowed back without a failure. Neither touches the browser, so both cost
  // microseconds beside the session below.
  test('the log scan reads a rotated log file, and the secret scan sees an encoded value', () => {
    // The live file after a size rotation is the INDEXED one; the plain name
    // stops growing. Narrowing this back to `.endsWith('.log')` was a real
    // failure: the request log had rotated, so the captured slice held the
    // session's sign-in but none of its HTTP lines.
    expect(LOG_FILE_NAME.test('http-2026-08-12.log')).toBe(true);
    expect(LOG_FILE_NAME.test('http-2026-08-12.log.1')).toBe(true);
    expect(LOG_FILE_NAME.test('all-logs-2026-08-12.log.23')).toBe(true);
    // A compressed chunk is not readable as UTF-8, and the rotator's own
    // bookkeeping file is not a log at all.
    expect(LOG_FILE_NAME.test('http-2026-08-12.log.gz')).toBe(false);
    expect(LOG_FILE_NAME.test('.0198-audit.json')).toBe(false);

    // A `#` survives JSON but not a query string or a cookie value, and both
    // passwords carry one by construction.
    const withHash = { value: 'Zk!7abc#Qx2' };
    expect(carries('body=Zk!7abc#Qx2', withHash)).toBe(true);
    expect(carries('?p=Zk!7abc%23Qx2', withHash)).toBe(true);
    expect(carries('nothing of the sort', withHash)).toBe(false);
  });

  test('no plaintext, master password, MEK or vault key ever leaves the browser', async ({
    page,
  }, testInfo) => {
    testInfo.setTimeout(SESSION_TIMEOUT_MS);

    const logsBefore = await logOffsets();
    const wire = await recordWire(page);
    const email = testEmail();

    /** Everything that must never appear anywhere, grown as the session runs. */
    const secrets: { label: string; value: string }[] = [
      { label: 'master password', value: MASTER_PASSWORD },
      { label: 'backup password', value: BACKUP_PASSWORD },
      ...Object.entries(PLANTED).map(([label, value]) => ({ label, value })),
    ];

    // ── Register and sign in ────────────────────────────────────────────────
    await test.step('register and sign in', async () => {
      await registerAndSignInViaUI(page, email, MASTER_PASSWORD);
    });

    // ── Reconstruct the keys the browser derived (guard 1) ──────────────────
    const vaultKey = await test.step('reconstruct the MEK and unwrap the vault key', () => {
      const mek = deriveMek(MASTER_PASSWORD, email);
      const registration = firstJsonBody(wire, 'POST', '/api/v1/auth/register');
      expect(registration, 'the registration request must have been recorded').toBeDefined();
      const wrapped = sealedFrom(registration!, 'encryptedVaultKey', 'vaultKeyIv', 'vaultKeyTag');
      // Throws unless every one of PBKDF2 salt, iteration count, output split and
      // GCM framing matches the browser exactly — which is the point.
      const raw = open256Gcm(mek, wrapped);
      expect(raw, 'the unwrapped vault key must be 256 bits').toHaveLength(32);
      secrets.push(...keyEncodings('raw MEK', mek), ...keyEncodings('unwrapped vault key', raw));
      return raw;
    });

    // ── One item of each of the five types ──────────────────────────────────
    await test.step('create a login carrying a custom field and a backup code', async () => {
      const dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Login' }).click();
      await dialog.locator('#field-name').fill(PLANTED.loginName);
      await dialog.locator('#field-username').fill(PLANTED.loginUsername);
      await dialog.locator('#field-password').fill(PLANTED.loginPassword);
      await dialog.locator('#field-totp').fill(PLANTED.loginTotp);

      await dialog.getByRole('button', { name: '+ Add backup codes' }).click();
      await dialog.getByLabel('Paste your backup codes').fill(PLANTED.loginBackupCode);
      await dialog.getByRole('button', { name: 'Add codes' }).click();

      await dialog.getByRole('button', { name: '+ Add Field' }).click();
      await dialog.getByPlaceholder('Field name').fill(PLANTED.customFieldName);
      await dialog.getByPlaceholder('Value').fill(PLANTED.customFieldValue);

      await dialog.getByRole('button', { name: 'Create' }).click();
      await expect(dialog).toBeHidden();
    });

    await test.step('create a secret, a note, a card and an identity', async () => {
      let dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Secret' }).click();
      await dialog.locator('#field-name').fill(PLANTED.secretName);
      await dialog.locator('#field-value').fill(PLANTED.secretValue);
      await dialog.getByRole('button', { name: 'Create' }).click();
      await expect(dialog).toBeHidden();

      dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Note' }).click();
      await dialog.locator('#field-name').fill(PLANTED.noteName);
      await dialog.locator('#field-content').fill(PLANTED.noteContent);
      await dialog.getByRole('button', { name: 'Create' }).click();
      await expect(dialog).toBeHidden();

      dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Card' }).click();
      await dialog.locator('#field-name').fill(PLANTED.cardName);
      await dialog.locator('#field-cardholderName').fill(PLANTED.cardholderName);
      await dialog.locator('#field-number').fill(PLANTED.cardNumber);
      await dialog.getByRole('button', { name: 'Create' }).click();
      await expect(dialog).toBeHidden();

      dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Identity' }).click();
      await dialog.locator('#field-name').fill(PLANTED.identityName);
      await dialog.locator('#field-firstName').fill(PLANTED.identityFirstName);
      // Required by the identity form; the other four are not.
      await dialog.locator('#field-lastName').fill(PLANTED.identityLastName);
      await dialog.locator('#field-street').fill(PLANTED.identityStreet);
      await dialog.locator('#field-deliveryNotes').fill(PLANTED.identityDeliveryNotes);
      await dialog.getByRole('button', { name: 'Create' }).click();
      await expect(dialog).toBeHidden();
    });

    // ── The ciphertext really carried the sentinels (guard 2) ───────────────
    await test.step('every created item decrypts back to its sentinel', () => {
      const created = callsTo(wire, 'POST', '/api/v1/vault/items').filter(
        (record) => !record.url.includes('bulk-'),
      );
      const byName = new Map<string, string>();
      for (const record of created) {
        const body = jsonBodyOf(record);
        if (!body) continue;
        const name = open256Gcm(
          vaultKey,
          sealedFrom(body, 'encryptedName', 'nameIv', 'nameTag'),
        ).toString('utf8');
        const data = open256Gcm(
          vaultKey,
          sealedFrom(body, 'encryptedData', 'dataIv', 'dataTag'),
        ).toString('utf8');
        byName.set(name, data);
      }

      const expected: [string, string[]][] = [
        [
          PLANTED.loginName,
          [
            PLANTED.loginUsername,
            PLANTED.loginPassword,
            PLANTED.loginTotp,
            PLANTED.loginBackupCode,
            PLANTED.customFieldName,
            PLANTED.customFieldValue,
          ],
        ],
        [PLANTED.secretName, [PLANTED.secretValue]],
        [PLANTED.noteName, [PLANTED.noteContent]],
        [PLANTED.cardName, [PLANTED.cardholderName, PLANTED.cardNumber]],
        [
          PLANTED.identityName,
          [
            PLANTED.identityFirstName,
            PLANTED.identityLastName,
            PLANTED.identityStreet,
            PLANTED.identityDeliveryNotes,
          ],
        ],
      ];
      for (const [name, values] of expected) {
        const data = byName.get(name);
        expect(data, `the recorded create request for "${name}" must decrypt`).toBeDefined();
        for (const value of values) {
          expect(data, `"${name}" must have carried its sentinel, encrypted`).toContain(value);
        }
      }
    });

    // ── Edit ────────────────────────────────────────────────────────────────
    await test.step('edit the login', async () => {
      await openItem(page, PLANTED.loginName);
      await page.getByRole('button', { name: /^edit$/i }).click();
      await page.locator('#field-notes').fill(PLANTED.loginNotesEdited);
      await page.getByRole('button', { name: 'Update' }).click();
      await expect(page.getByText(/item updated/i)).toBeVisible({ timeout: 60_000 });
    });

    // ── Search ──────────────────────────────────────────────────────────────
    await test.step('search for a planted value', async () => {
      await goToVault(page);
      // The query is a decrypted value. Searching is client-side over the
      // decrypted store, so typing it must produce a match WITHOUT the term ever
      // reaching the server — the final scan is what proves the second half.
      await page.getByPlaceholder('Search vault... (Ctrl+K)').fill(PLANTED.loginUsername);
      await expect(page.getByTestId('vault-item-name')).toHaveCount(1);
      await expect(page.getByTestId('vault-item-name')).toHaveText(PLANTED.loginName);
      await page.getByPlaceholder('Search vault... (Ctrl+K)').fill('');
    });

    // ── Lock and unlock ─────────────────────────────────────────────────────
    await test.step('lock and unlock', async () => {
      await page.getByRole('button', { name: /lock vault/i }).click();
      await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });
      await unlockVault(page, MASTER_PASSWORD);
      await expect(page).toHaveURL(/\/vault/, { timeout: 120_000 });
      await expect(page).not.toHaveURL(/\/login/);
    });

    // ── Rotate the vault key ────────────────────────────────────────────────
    await test.step('rotate the vault key', async () => {
      await goToSettings(page);
      await page.getByRole('button', { name: 'Rotate Key' }).click();
      const dialog = page.getByRole('dialog', { name: 'Rotate Vault Key' });
      await expect(dialog).toBeVisible();
      await page.locator('#rotation-password').fill(MASTER_PASSWORD);
      await page.getByRole('button', { name: 'Confirm Rotation' }).click();
      await expect(page.getByText('Vault key rotated successfully')).toBeVisible({
        timeout: 180_000,
      });

      // The NEW vault key is wrapped with the same MEK, so it can be unwrapped
      // the same way — and it must be as absent from the wire as the old one.
      const rotation = firstJsonBody(wire, 'POST', '/api/v1/vault/items/bulk-reencrypt');
      expect(rotation, 'the rotation request must have been recorded').toBeDefined();
      const rotated = open256Gcm(
        deriveMek(MASTER_PASSWORD, email),
        sealedFrom(rotation!, 'newEncryptedVaultKey', 'newVaultKeyIv', 'newVaultKeyTag'),
      );
      expect(rotated, 'the rotated vault key must be 256 bits').toHaveLength(32);
      secrets.push(...keyEncodings('rotated vault key', rotated));
    });

    // ── Export (plaintext, client-side) ─────────────────────────────────────
    await test.step('export the vault to a plaintext file', async () => {
      await goToSettings(page);
      await page.getByRole('link', { name: /Export to another manager/ }).click();
      await expect(page).toHaveURL(/\/settings\/export-data$/);
      await page.locator('#export-master-password').fill(MASTER_PASSWORD);
      await page.getByRole('button', { name: 'Prepare plaintext export' }).click();

      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible({ timeout: 120_000 });
      const downloadPromise = page.waitForEvent('download');
      await dialog.getByRole('button', { name: 'Download plaintext file' }).click();
      const download = await downloadPromise;
      const file = await download.path();
      const content = await readFile(file, 'utf8');
      // The file is the one place the plaintext is SUPPOSED to be, which makes it
      // the proof that the vault really holds these values — the server sent only
      // ciphertext, and the browser decrypted it.
      expect(content).toContain(PLANTED.loginPassword);
      expect(content).toContain(PLANTED.noteContent);
    });

    // ── Import ──────────────────────────────────────────────────────────────
    await test.step('import an external file', async () => {
      await goToSettings(page);
      await page.getByRole('button', { name: 'Import Vault' }).click();
      const paste = page.getByPlaceholder('Paste exported data here...');
      await expect(paste).toBeVisible();
      const select = page
        .locator('select')
        .filter({ has: page.locator('option[value="firefox"]') });
      await select.selectOption('firefox');
      await paste.fill(
        [
          'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged',
          `https://zk.example.com/signin,${PLANTED.importUsername},${PLANTED.importPassword},,https://zk.example.com,{zk1},1,2,3`,
        ].join('\n'),
      );
      await page.getByRole('button', { name: 'Import', exact: true }).click();
      await expect(page.getByText(/Imported 1 item/)).toBeVisible({ timeout: 60_000 });
    });

    // ── Back up and restore ─────────────────────────────────────────────────
    await test.step('configure backup encryption, download a backup and restore it', async () => {
      await goToSettings(page);
      await page.getByRole('link', { name: 'Backup Settings' }).click();
      await expect(page).toHaveURL(/\/settings\/backup$/);
      await page.locator('#backup-password').fill(BACKUP_PASSWORD);
      await page.locator('#confirm-backup-password').fill(BACKUP_PASSWORD);
      await page.locator('#setup-master-password').fill(MASTER_PASSWORD);
      await page.getByRole('button', { name: 'Setup Encryption' }).click();
      await expect(page.getByText('Backup encryption configured')).toBeVisible({
        timeout: 180_000,
      });

      await page.getByRole('button', { name: 'Download Latest' }).click();
      await page.getByPlaceholder('Backup password').fill(BACKUP_PASSWORD);
      const downloadPromise = page.waitForEvent('download');
      await page.getByRole('button', { name: 'Download', exact: true }).click();
      const backupPath = testInfo.outputPath('zero-knowledge-backup.enc');
      await (await downloadPromise).saveAs(backupPath);

      await page.getByRole('button', { name: 'Restore from File' }).click();
      await page.locator('input[type="file"]').setInputFiles(backupPath);
      await page.locator('#restore-password').fill(BACKUP_PASSWORD);
      await page.getByRole('radio', { name: /Overwrite/ }).check();
      await page.getByRole('button', { name: 'Restore', exact: true }).click();
      await expect(page.getByText(/^Backup restored/)).toBeVisible({ timeout: 180_000 });
    });

    // ── Enable 2FA (the seed and a backup code are secrets too) ─────────────
    await test.step('enable two-factor authentication', async () => {
      await goToSettings(page);
      await page.getByRole('button', { name: 'Enable' }).click();
      await page.getByPlaceholder('Master password').fill(MASTER_PASSWORD);

      const setupResponse = page.waitForResponse(
        (response) =>
          response.url().includes('/api/v1/user/2fa/setup') &&
          response.request().method() === 'POST',
      );
      await page.getByRole('button', { name: 'Continue' }).click();
      const setup = (await (await setupResponse).json()) as { data: { secret: string } };
      const seed = setup.data.secret;
      expect(seed, 'the server must have issued a TOTP seed').toBeTruthy();
      // The seed the SERVER issued must not come back out of the browser, and
      // must not land in an audit row or a log line either.
      secrets.push({ label: 'account 2FA seed', value: seed });

      const totp = new OTPAuth.TOTP({
        issuer: 'H-Vault',
        label: email,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(seed),
      });
      const verifyResponse = page.waitForResponse(
        (response) =>
          response.url().includes('/api/v1/user/2fa/verify') &&
          response.request().method() === 'POST',
      );
      await page.getByPlaceholder('6-digit code').fill(totp.generate());
      await page.getByRole('button', { name: 'Verify' }).click();
      const verified = (await (await verifyResponse).json()) as {
        data: { backupCodes: string[] };
      };
      const [firstCode] = verified.data.backupCodes;
      expect(firstCode, 'the server must have issued backup codes').toBeTruthy();
      secrets.push({ label: 'account 2FA backup code', value: firstCode! });

      // The codes are shown once, in a modal whose overlay covers the sidebar —
      // dismiss it, or every later click is intercepted by a backdrop that says
      // nothing about what it is waiting for.
      const codesDialog = page.getByRole('dialog', { name: 'Save Your Backup Codes' });
      await expect(codesDialog).toBeVisible();
      await codesDialog.getByRole('button', { name: /saved these codes/i }).click();
      await expect(codesDialog).toBeHidden();
    });

    // ── Log out ─────────────────────────────────────────────────────────────
    await test.step('log out', async () => {
      await page.getByRole('button', { name: 'Logout' }).click();
      await expect(page).toHaveURL(/\/login/, { timeout: 60_000 });
    });

    // ── Guard 3: the session really made the calls being scanned ────────────
    await test.step('the recording covers the whole session', () => {
      const required: [string, string][] = [
        ['POST', '/api/v1/auth/register'],
        ['POST', '/api/v1/auth/login'],
        ['POST', '/api/v1/vault/items'],
        ['PUT', '/api/v1/vault/items/'],
        ['POST', '/api/v1/auth/verify-unlock'],
        ['POST', '/api/v1/vault/items/bulk-reencrypt'],
        ['POST', '/api/v1/tools/export'],
        ['POST', '/api/v1/tools/import'],
        ['POST', '/api/v1/backup/setup'],
        ['GET', '/api/v1/backup/download'],
        ['POST', '/api/v1/backup/restore'],
        ['POST', '/api/v1/user/2fa/setup'],
        ['POST', '/api/v1/user/2fa/verify'],
        ['POST', '/api/v1/auth/logout'],
      ];
      for (const [method, url] of required) {
        expect(
          callsTo(wire, method, url).length,
          `${method} ${url} must appear in the recording`,
        ).toBeGreaterThan(0);
      }
      // Both capture paths were live, not just one of them.
      expect(wire.some((record) => record.channel === 'route')).toBe(true);
      expect(wire.some((record) => record.channel === 'event')).toBe(true);
      expect(callsTo(wire, 'POST', '/api/v1/vault/items').length).toBeGreaterThanOrEqual(5);
    });

    // ── The invariant, over the wire ────────────────────────────────────────
    await test.step('no request carried a secret', () => {
      const offenders: string[] = [];
      for (const record of wire) {
        for (const secret of secrets) {
          if (carries(record.text, secret)) {
            offenders.push(`${secret.label} in ${record.method} ${record.url} (${record.channel})`);
          }
        }
      }
      expect(offenders, 'no outbound request may carry plaintext or key material').toEqual([]);
    });

    await test.step('no cookie carried a secret', async () => {
      const cookies = JSON.stringify(await page.context().cookies());
      const offenders = secrets.filter((secret) => carries(cookies, secret));
      expect(offenders.map((secret) => secret.label)).toEqual([]);
    });

    // ── The invariant, on the server ────────────────────────────────────────
    await test.step('no audit row carried a secret', async () => {
      const db = await testDb();
      const user = await db.collection('users').findOne({ email });
      expect(user, 'the account must exist server-side').not.toBeNull();
      const rows = await db.collection('audit_logs').find({ userId: user!._id }).toArray();

      // Guard 4: assert the rows are THERE before asserting they are clean.
      const actions = [...new Set(rows.map((row) => String(row['action'])))];
      for (const action of [
        'login',
        'item_create',
        'import',
        'export_plaintext',
        'backup_setup',
        'logout',
      ]) {
        expect(actions, `an audit row for "${action}" must exist`).toContain(action);
      }

      const serialized = JSON.stringify(rows);
      const offenders = secrets.filter((secret) => carries(serialized, secret));
      expect(
        offenders.map((secret) => secret.label),
        'no audit row may carry a secret',
      ).toEqual([]);
    });

    await test.step('no stored document carried a secret', async () => {
      const db = await testDb();
      const offenders: string[] = [];
      for (const collection of await db.collections()) {
        const documents = await collection.find({}).toArray();
        const serialized = JSON.stringify(documents);
        for (const secret of secrets) {
          if (carries(serialized, secret)) {
            offenders.push(`${secret.label} in ${collection.collectionName}`);
          }
        }
      }
      expect(offenders, 'the server may store ciphertext only').toEqual([]);
    });

    await test.step('no log line carried a secret', async () => {
      const written = await logsWrittenSince(logsBefore);
      // Guard 4 again: a log scan over an empty slice proves nothing, so require
      // this session's own request lines to be in it first.
      expect(written, 'the server must have logged this session').toContain('/api/v1/vault/items');
      const offenders = secrets.filter((secret) => carries(written, secret));
      expect(
        offenders.map((secret) => secret.label),
        'no log line may carry a secret',
      ).toEqual([]);
    });
  });
});
