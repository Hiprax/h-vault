import {
  test,
  type BrowserContext,
  type Frame,
  type FrameLocator,
  type Page,
  type APIRequestContext,
  expect,
} from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { execFile } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { seededRandom } from '../tests/harness/determinism.js';
import { A11Y_BLOCKING_IMPACTS } from './a11yViews.js';
import { MongoClient, type Db } from 'mongodb';

// ─── Constants ───────────────────────────────────────────────────────────────

const MONGODB_URI = process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/hvault';
const execFileAsync = promisify(execFile);
export const TEST_PASSWORD = 'E2E-Test-P@ssword-2025!';

/**
 * Budget for a single step that waits on a client-side PBKDF2 key derivation.
 *
 * This number is governed by CPU COST, not by network latency: each register or
 * sign-in step runs a real 600,000-iteration PBKDF2-SHA-256 derivation in the
 * browser (plus server-side bcrypt at 12 rounds on sign-in), and the suite runs
 * `workers: 1` alongside a Vite dev server and an in-memory MongoDB. On a
 * contended machine one derivation alone has been observed past 30 s, which is
 * how the old budget produced intermittent failures in `file-encryption.spec.ts`
 * and `import-export.spec.ts` that passed on a re-run in isolation (the pipeline's
 * `--retries=2` hid them).
 *
 * The two specs failed for DIFFERENT reasons, and it is worth keeping them straight:
 * `file-encryption.spec.ts` already sets its own `test.setTimeout(120_000)`, so for
 * it the binding constraint was this per-assertion budget alone. `import-export.spec.ts`
 * (and `clipboard-hygiene.spec.ts`) set no timeout at all, so for those the test-level
 * floor below is what actually rescues them. Both halves were needed.
 *
 * Do NOT tighten this back towards a "reasonable page-load" number. A derivation
 * that is slow is not a bug the assertion should catch; a genuinely broken sign-in
 * fails on the ASSERTION (wrong URL, visible error), not on the clock.
 */
const PBKDF2_STEP_TIMEOUT_MS = 90_000;

/**
 * Budget for an assertion that gates the FIRST mount of a lazily-loaded route.
 *
 * Bound by Vite's on-demand transform of the route's chunk, not by a key
 * derivation — the same thing `gotoFileEncryptionTool` allows 60 s for. It needs
 * saying because Playwright's default `expect` timeout is 10 s: an unbudgeted
 * gate here would turn every spec that signs in through the UI into a flake on a
 * contended machine, which is the class the constants in this file exist to
 * prevent.
 */
const LAZY_ROUTE_TIMEOUT_MS = 60_000;

/**
 * Floor for the enclosing test's own timeout when a helper performs derivations.
 *
 * Raising {@link PBKDF2_STEP_TIMEOUT_MS} alone would be inert: Playwright's
 * per-test `timeout` (30 s in `playwright.config.ts`) kills the test before a
 * longer assertion budget can ever elapse, so the two must move together. Applied
 * as a FLOOR via `test.info().timeout` rather than a plain `test.setTimeout`,
 * because `setTimeout` SETS the value and an unconditional call here would silently
 * SHORTEN `address-fields.spec.ts`, which asks for 300 s.
 *
 * Note what a floor of 240 s means in the other direction: it RAISES the several
 * specs that ask for 120–150 s of their own. That is intended — those numbers were
 * chosen against the old 30 s assertion budget and are now below what two 90 s
 * derivations can legitimately need. The cost is paid only when something is already
 * wrong: with `workers: 1` and ten call sites, a pathological all-timeout run takes
 * about twice as long to report as it used to.
 *
 * DERIVED from the step budget rather than written as a literal, because the two
 * numbers are not independent: `registerAndSignInViaUI` performs TWO derivations,
 * so a floor below `2 ×` the per-step budget would let the test-level timeout fire
 * first in exactly the contended run the step budget exists for — reintroducing the
 * defect one layer up. The `+ 60 s` covers the non-derivation work in between (the
 * page loads, the direct MongoDB write, and the form fills).
 */
const UI_SIGN_IN_TEST_TIMEOUT_MS = PBKDF2_STEP_TIMEOUT_MS * 2 + 60_000;

/** Raise the current test's timeout to `floor` if it is currently lower. */
function ensureTestTimeoutAtLeast(floor: number): void {
  if (test.info().timeout < floor) test.setTimeout(floor);
}

/**
 * A high-entropy master password guaranteed to clear the registration gate
 * (zxcvbn score >= 3 and >= 12 characters), used by the full-UI sign-in helper.
 */
export const E2E_STRONG_PASSWORD = 'Gx7!vMq2$Lp9#Rt4&Kw8';

// ─── Shared MongoDB Client ──────────────────────────────────────────────────

let sharedClient: MongoClient | undefined;

/** Returns a shared MongoDB client to avoid connection churn during tests. */
async function getMongoDb() {
  if (!sharedClient) {
    sharedClient = new MongoClient(MONGODB_URI, { maxPoolSize: 5 });
    await sharedClient.connect();
  }
  return sharedClient.db();
}

/**
 * The database the server under test is actually using, for specs that have to
 * read what was STORED rather than what was returned.
 *
 * Exposed through the shared client above rather than by opening a second one:
 * the connection is pooled and closed with the process, and a spec that opened
 * its own would leak a pool per file.
 *
 * The zero-knowledge spec is the caller that needs this — the server's audit
 * rows are the one place a leak would be both durable and invisible from the
 * browser, so proving they are clean means reading the collection itself.
 */
export async function testDb(): Promise<Db> {
  return getMongoDb();
}

/**
 * Marks a user's email as verified directly in MongoDB.
 *
 * The E2E harness disables SMTP, so no verification email is ever sent; the
 * server would otherwise reject login with `EMAIL_NOT_VERIFIED`. Flipping the
 * flag directly mirrors {@link createAuthenticatedUser}'s API-level path for the
 * full-UI sign-in flow (which registers and logs in through the real pages).
 */
async function markEmailVerified(email: string): Promise<void> {
  const container = process.env['E2E_DB_CONTAINER'];
  if (container) {
    await markEmailVerifiedInContainer(container, email);
    return;
  }
  const db = await getMongoDb();
  await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });
}

/**
 * The same write, made INSIDE a database container that publishes no port.
 *
 * `scripts/ci/deploy-drill.mjs` runs the sandbox specs against the Compose
 * stack's single published port, and that stack's database is deliberately
 * unreachable from the host — the drill asserts as much, so publishing it for a
 * test would be the drill disproving its own claim. The write therefore goes
 * through `docker exec … mongosh`, the way the drill verifies its own account,
 * selected by the drill setting `E2E_DB_CONTAINER` and the root credential beside
 * it. Every other run leaves that unset and takes the direct client above.
 *
 * The credential reaches the container as `-e NAME` with NO value, which docker
 * reads from this process's environment: the secret is never on an argument
 * vector, where every process on the machine could read it. And the result is
 * CHECKED — one document matched and modified — because a verification that
 * silently matched nothing surfaces two steps later as a sign-in refused with
 * `EMAIL_NOT_VERIFIED`, a symptom that points at the login page instead of here.
 */
async function markEmailVerifiedInContainer(container: string, email: string): Promise<void> {
  const script =
    "db.getSiblingDB('admin').auth(process.env.E2E_DB_ROOT_USERNAME, process.env.E2E_DB_ROOT_PASSWORD);" +
    "const r = db.getSiblingDB('hvault').users.updateOne({ email: process.env.E2E_VERIFY_EMAIL }, { $set: { emailVerified: true } });" +
    "print('matched=' + r.matchedCount + ' modified=' + r.modifiedCount);";
  const { stdout } = await execFileAsync(
    'docker',
    [
      'exec',
      '-e',
      'E2E_DB_ROOT_USERNAME',
      '-e',
      'E2E_DB_ROOT_PASSWORD',
      '-e',
      'E2E_VERIFY_EMAIL',
      container,
      'mongosh',
      '--quiet',
      '--host',
      '127.0.0.1',
      '--eval',
      script,
    ],
    { env: { ...process.env, E2E_VERIFY_EMAIL: email }, encoding: 'utf8' },
  );
  expect(stdout, `verifying ${email} inside ${container}`).toContain('matched=1 modified=1');
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuthenticatedUser {
  email: string;
  authHash: string;
  accessToken: string;
}

// ─── CSRF Helper ─────────────────────────────────────────────────────────────

/** Fetches a CSRF token from the server. */
export async function getCsrf(request: APIRequestContext): Promise<string> {
  const res = await request.get('/api/v1/csrf-token');
  const body = (await res.json()) as { data: { csrfToken: string } };
  return body.data.csrfToken;
}

// ─── API-Level Auth Helpers ──────────────────────────────────────────────────

/**
 * Creates and returns an authenticated user via the API.
 * Registers, verifies email directly in MongoDB, and logs in.
 * Each call creates a unique user for test isolation.
 */
export async function createAuthenticatedUser(
  request: APIRequestContext,
  overrides?: {
    email?: string;
    authHash?: string;
    encryptedVaultKey?: string;
    vaultKeyIv?: string;
    vaultKeyTag?: string;
  },
): Promise<AuthenticatedUser> {
  const email = overrides?.email ?? testEmail();
  const authHash = overrides?.authHash ?? 'e2e-test-auth-hash';

  // 1. Register
  const regCsrf = await getCsrf(request);
  const regRes = await request.post('/api/v1/auth/register', {
    data: {
      email,
      authHash,
      encryptedVaultKey: overrides?.encryptedVaultKey ?? 'e2e-encrypted-vault-key-data',
      vaultKeyIv: overrides?.vaultKeyIv ?? 'e2e-vault-key-iv',
      vaultKeyTag: overrides?.vaultKeyTag ?? 'e2e-vault-key-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
    },
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': regCsrf,
    },
  });
  expect(regRes.ok()).toBe(true);

  // 2. Verify email directly in MongoDB (uses shared connection)
  const db = await getMongoDb();
  await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });

  // 3. Login
  const loginCsrf = await getCsrf(request);
  const loginRes = await request.post('/api/v1/auth/login', {
    data: { email, authHash },
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': loginCsrf,
    },
  });
  expect(loginRes.ok()).toBe(true);

  const loginBody = (await loginRes.json()) as {
    success: boolean;
    data: { accessToken: string };
  };

  return { email, authHash, accessToken: loginBody.data.accessToken };
}

// ─── Authenticated Request Helpers ───────────────────────────────────────────

/** Makes an authenticated GET request. */
export async function authGet(request: APIRequestContext, user: AuthenticatedUser, url: string) {
  return request.get(url, {
    headers: { authorization: `Bearer ${user.accessToken}` },
  });
}

/** Makes an authenticated POST/PUT/DELETE request with CSRF. */
export async function authMutate(
  request: APIRequestContext,
  user: AuthenticatedUser,
  method: 'post' | 'put' | 'delete',
  url: string,
  data?: Record<string, unknown>,
) {
  const csrf = await getCsrf(request);
  const headers: Record<string, string> = {
    authorization: `Bearer ${user.accessToken}`,
    'x-csrf-token': csrf,
  };
  if (data) headers['content-type'] = 'application/json';
  return request[method](url, { ...(data ? { data } : {}), headers });
}

// ─── Data Builders ───────────────────────────────────────────────────────────

/** Creates a sample vault item payload for API tests. */
export function sampleVaultItem(overrides: Record<string, unknown> = {}) {
  return {
    itemType: 'login',
    encryptedData: 'e2e-encrypted-data',
    dataIv: 'e2e-data-iv',
    dataTag: 'e2e-data-tag',
    encryptedName: 'e2e-encrypted-name',
    nameIv: 'e2e-name-iv',
    nameTag: 'e2e-name-tag',
    tags: [],
    favorite: false,
    ...overrides,
  };
}

/**
 * Creates one `operations.inserts` entry for `POST /tools/import`.
 *
 * The import contract requires a `searchHash` on every operation — the client
 * recomputes it alongside the encrypted name — so a plain {@link sampleVaultItem}
 * would be rejected by the schema before the endpoint ever runs.
 */
export function sampleImportInsert(overrides: Record<string, unknown> = {}) {
  return { ...sampleVaultItem(), searchHash: 'a'.repeat(64), ...overrides };
}

/** Creates a sample folder payload for API tests. */
export function sampleFolder(overrides: Record<string, unknown> = {}) {
  return {
    encryptedName: 'e2e-folder-name',
    nameIv: 'e2e-folder-iv',
    nameTag: 'e2e-folder-tag',
    ...overrides,
  };
}

// ─── Email Generator ─────────────────────────────────────────────────────────

/**
 * A seeded pseudo-random stream, plus a counter.
 *
 * `Math.random` was fine for uniqueness and useless for reproduction: an E2E
 * failure that depended on the generated address could not be re-run. The seed
 * comes from the harness (`SEED`, default 1337) and the counter guarantees
 * uniqueness WITHIN a run even though the stream is now identical across runs —
 * `Date.now()` alone is not enough, two specs can start in the same millisecond.
 */
const nextRandom = seededRandom();
let emailCounter = 0;

/** Generates a unique test email for E2E test isolation. */
export function testEmail(): string {
  emailCounter += 1;
  const noise = nextRandom().toString(36).slice(2, 8);
  const id = `${String(Date.now())}-${String(emailCounter)}-${noise}`;
  return `e2e-${id}@test.hvault.local`;
}

// ─── UI Helpers ──────────────────────────────────────────────────────────────

/**
 * Give the page permission to write to the clipboard, on the engines that have
 * such a permission to give.
 *
 * This is a difference in the PLATFORM, not a difference in what any caller
 * asserts: a spec that calls this runs every one of its lines on every engine it
 * is scheduled on. Chromium gates `writeText()` on a Permissions API entry named
 * `clipboard-write`, which is auto-granted to the active tab in a normal browser
 * and has to be granted explicitly to an automated context. Gecko has no such
 * permission at all — it gates the same call on TRANSIENT USER ACTIVATION
 * instead — so the name does not exist there and Playwright rejects it outright
 * with `browserContext.grantPermissions: Unknown permission: clipboard-write`
 * (measured, Playwright 1.61.1 / Firefox 151).
 *
 * Hence the condition, which is on the engine's permission model rather than on
 * a test that is expected to fail: a `try`/`catch` around the grant would have
 * hidden a genuine permission error just as effectively, and skipping the spec
 * on Firefox would have thrown away the only run that exercises the activation
 * rule the clipboard guard was written for.
 *
 * IT LIVES HERE, not in the one spec that first needed it, and that is the
 * point: while it was local to `clipboard-hygiene.spec.ts`,
 * `login-backup-codes.spec.ts` went on calling `grantPermissions` outright. That
 * is inert only while `FIREFOX_SUITE` in `playwright.config.ts` happens not to
 * name that spec — the day a third file joins the second engine, an unconditional
 * grant throws before its first assertion.
 */
export async function grantClipboardWrite(
  context: BrowserContext,
  browserName: 'chromium' | 'firefox' | 'webkit',
): Promise<void> {
  if (browserName === 'chromium') {
    await context.grantPermissions(['clipboard-write']);
  }
}

/**
 * The accessible name of the sidebar control that locks the vault.
 *
 * A named constant because the string is HALF of a collision, and the other half
 * is {@link UNLOCK_SUBMIT_LABEL}. See {@link unlockedLayoutMarker}.
 *
 * Exported so `auto-lock.spec.ts` can build the WRONG matcher out of the same
 * label rather than copying a regex literal: an assertion about a collision has
 * to be about these two strings, or a rename moves the code and leaves the
 * assertion testing a string nothing renders.
 */
export const LOCK_VAULT_LABEL = 'Lock Vault';

/** The accessible name of the unlock screen's submit control. */
export const UNLOCK_SUBMIT_LABEL = 'Unlock Vault';

/**
 * THE control that exists only in the UNLOCKED layout, as one locator.
 *
 * ## Why this is a named factory rather than an inline locator
 *
 * It is the only thing that tells the vault apart from the unlock screen, and
 * `ProtectedRoute` swaps one for the other at the SAME url, so a URL check
 * cannot. Three places needed that discrimination — this file's
 * {@link expectVaultVisible}, {@link lockViaUi}, and `zero-knowledge.spec.ts` —
 * and each had written it out for itself.
 *
 * ## Why `exact`, which is the whole point
 *
 * The obvious spelling, `{ name: /lock vault/i }`, IS NOT A DISCRIMINATOR, and
 * that is a fact about Playwright rather than about this application: a RegExp
 * role-name is matched UNANCHORED (`matchesAttributePart`, operator `=`, which
 * ends in `objValue.match(attrValue)`), and `exact` is ignored for a RegExp. The
 * unlock screen's submit button is called `Unlock Vault`, and
 * `/lock vault/i.test('Unlock Vault')` is TRUE — so the substring form matches
 * the LOCKED screen just as happily as the unlocked one.
 *
 * That was not theoretical. `expectVaultVisible` shipped with the substring form
 * and a docblock stating it distinguished the two states; it returned
 * immediately on the unlock screen instead, so a four-cycle lock/unlock run
 * moved on while a 600,000-iteration derivation was still in flight, the next
 * `lockViaUi()` clicked the unlock screen's own submit button rather than
 * locking, and `unlockVault` then pressed Enter on a button that the finished
 * derivation had just unmounted — burning the test's whole 300 s budget with a
 * screenshot of the vault, sidebar and all. It failed only under contention,
 * which is why it survived several green runs.
 *
 * An exact STRING name is compared with `===` after white-space normalisation,
 * so it refuses `Unlock Vault` and still matches `Lock Vault`. Do not soften it
 * back to a RegExp for convenience, and note that the NON-exact string form is
 * the same trap one step over: `'Lock Vault'` is a case-insensitive substring of
 * `'Unlock Vault'`, so only `exact: true` discriminates. `auto-lock.spec.ts` pins
 * both halves of this.
 *
 * ## The class, not just the instance
 *
 * Three more accessible names exist on BOTH screens, and none of them may ever
 * be used to tell the two apart: `Logout` (the sidebar's, and the unlock
 * screen's), `Show password`/`Hide password` (the unlock screen's reveal toggle,
 * and every vault item form's), and the `Master Password` label (the unlock
 * screen's, and the sign-in and registration pages'). Clicking one of them as an
 * ACTION on a screen already established is fine, because only one exists at a
 * time; reading one as EVIDENCE of which screen is up is the defect above.
 */
export function unlockedLayoutMarker(page: Page) {
  return page.getByRole('button', { name: LOCK_VAULT_LABEL, exact: true });
}

/**
 * Lock the vault through the sidebar control, the way a user does.
 *
 * Deliberately NOT the `Ctrl`+`L` keyboard shortcut: `useKeyboardShortcuts`
 * suppresses every shortcut while focus is in an `INPUT`/`TEXTAREA`/`SELECT`,
 * and the vault page holds a focusable search field — so the keypress silently
 * did nothing and the caller failed waiting for a lock screen that was never
 * going to appear. Clicking the real control has no such precondition and
 * exercises the same `authStore.lock()` path.
 *
 * Built on {@link unlockedLayoutMarker}, which is not merely tidiness: the
 * substring spelling this replaced also matches the unlock screen's `Unlock
 * Vault` button, so a "lock" click landing while the vault was still locked
 * submitted the unlock form a second time instead.
 */
export async function lockViaUi(page: Page): Promise<void> {
  await unlockedLayoutMarker(page).click();
}

/**
 * Waits for the vault page to be visible (authenticated state).
 *
 * Derivation-bound: it is normally called straight after a sign-in submit, which
 * runs the full client-side PBKDF2 key derivation in the browser.
 *
 * It raises the test timeout too, for the same reason `registerAndSignInViaUI`
 * does. That is not redundant belt-and-braces: the step budget below is INERT on
 * its own, because Playwright's 30 s per-test timeout fires first, so a caller
 * that reaches this helper by any route other than `registerAndSignInViaUI`
 * would otherwise get an assertion budget that looks generous and is
 * unreachable. One derivation here, so the floor is the single-step budget plus
 * slack.
 */
export async function expectVaultVisible(page: Page): Promise<void> {
  ensureTestTimeoutAtLeast(PBKDF2_STEP_TIMEOUT_MS + 30_000);
  await expect(page).toHaveURL(/\/vault/, { timeout: PBKDF2_STEP_TIMEOUT_MS });
  // The URL alone is NOT enough, and the gap was load-bearing: locking the vault
  // does not navigate — `ProtectedRoute` swaps the layout for the unlock screen at
  // the SAME url — so a URL-only assertion passed for a LOCKED vault. Every caller
  // that used this to mean "the unlock worked" was therefore asserting nothing, and
  // the failure that produced surfaced two steps later and unrecognisably: the next
  // `lockViaUi()` waited for a control the unlock screen does not have until the
  // whole test timed out, five minutes away from the line that was actually wrong.
  //
  // Through {@link unlockedLayoutMarker}, never a locator written out here: the
  // first version of this assertion used the substring form and therefore matched
  // the unlock screen's own `Unlock Vault` button, so it discriminated nothing and
  // the defect described above stayed live. That note is on the factory.
  await expect(unlockedLayoutMarker(page)).toBeVisible({
    timeout: PBKDF2_STEP_TIMEOUT_MS,
  });
}

/**
 * Registers a brand-new account and signs in, entirely through the real UI so
 * the browser runs the genuine client-side PBKDF2 key derivation on both the
 * register and login pages (unlike the API-level {@link createAuthenticatedUser}
 * helper). Between the two steps it flips `emailVerified` directly in MongoDB,
 * since the E2E harness sends no verification email.
 *
 * Leaves the page on `/vault` with a fully unlocked, in-memory session (the
 * vault key lives only in memory), ready to navigate to any protected route.
 *
 * Costs TWO full PBKDF2 derivations, so it raises the enclosing test's timeout to
 * {@link UI_SIGN_IN_TEST_TIMEOUT_MS} and gives each derivation-bound assertion
 * {@link PBKDF2_STEP_TIMEOUT_MS} — see those constants for why the numbers are
 * what they are and must not be tightened.
 */
export async function registerAndSignInViaUI(
  page: Page,
  email: string = testEmail(),
  password: string = E2E_STRONG_PASSWORD,
): Promise<{ email: string; password: string }> {
  ensureTestTimeoutAtLeast(UI_SIGN_IN_TEST_TIMEOUT_MS);

  // Suppress the first-run onboarding modal so its backdrop never intercepts
  // clicks on the vault shell. Runs before every document load in this context.
  await page.addInitScript(() => {
    localStorage.setItem('hvault_onboarding_completed', 'true');
  });

  // 1. Register through the real UI — the client derives authHash via PBKDF2.
  await page.goto('/register');
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByLabel(/confirm master password/i).fill(password);
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: /create account/i }).click();

  // On success the register page navigates to /login — after the client has
  // derived the MEK and the auth hash.
  await expect(page).toHaveURL(/\/login/, { timeout: PBKDF2_STEP_TIMEOUT_MS });
  // The URL is NOT enough: every route is `lazy()`, so the address changes as
  // soon as navigation commits and the login chunk mounts some time later. Until
  // it does, the REGISTER page is still in the DOM — and it carries an "Email"
  // label and a "Master Password" label of its own, so the fills below happily
  // land on the page that is about to be unmounted. The observed failure was
  // exactly that, and intermittently: the email went to the register form and
  // was thrown away on the swap, the password (typed a few milliseconds later)
  // reached the real login form, and Sign In failed with "Email is required".
  // `markEmailVerified` below usually hid it by giving the chunk time to load.
  // "Welcome Back" is LoginPage's own heading — the register page's is "Create
  // Account" — so waiting for it is a precise test that the swap has happened.
  await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });

  // 2. Verify the email server-side (no SMTP in E2E).
  await markEmailVerified(email);

  // 3. Sign in through the real UI — the client re-derives the same authHash.
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();

  // The second derivation, plus server-side bcrypt on the auth hash.
  await expect(page).toHaveURL(/\/vault/, { timeout: PBKDF2_STEP_TIMEOUT_MS });

  return { email, password };
}

/**
 * Navigates to the File Encryption tool via the sidebar link (client-side SPA
 * navigation, preserving the in-memory session) and waits for the lazily-loaded
 * Encrypt panel to mount. Call after {@link registerAndSignInViaUI}.
 */
export async function gotoFileEncryptionTool(page: Page): Promise<void> {
  await page.getByRole('link', { name: /file encryption/i }).click();
  await expect(page).toHaveURL(/\/tools\/file-encryption/);
  // Not derivation-bound, but bound by the DEV SERVER: the panel is a lazy chunk,
  // so this is the first request that makes Vite transform it (and `@hiprax/crypto`
  // + hash-wasm) on demand. Same contention as the sign-in steps, different cause.
  await expect(page.locator('#file-encrypt-input')).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/**
 * A Google Authenticator export link holding two accounts.
 *
 * RECORDED rather than generated at run time, and deliberately so: the point of
 * driving the tool through this value is that the whole pipeline — base64,
 * protobuf, base32, the URI builder — is exercised against bytes this repository
 * did not just produce from the same code that reads them.
 *
 * It was emitted once by `packages/client/tests/support/migrationEncoder.ts`,
 * which builds the wire format independently of the reader, from two accounts
 * whose keys are the ten bytes `Hello!` + `DEADBEEF` rotated. Neither key is
 * real. To regenerate it, call `encodeMigrationUri` with those two entries.
 */
export const SAMPLE_AUTHENTICATOR_EXPORT_URI =
  'otpauth-migration://offline?data=CjAKCkhlbGxvId6tvu8SFkFjbWU6YWxpY2VAZXhhbXBsZS5jb20aBEFjbWUgASgBMAIKMgoKId6tvu9IZWxsbxIWR2xvYmV4OmJvYkBleGFtcGxlLmNvbRoGR2xvYmV4IAIoAjACEAEYASAAKNIJ';

/**
 * Opens the authenticator-import tool and reads the sample export into it.
 *
 * The PASTE path, never the camera: a browser under test has no camera worth
 * pointing at anything, and this exercises every step after the decoder while
 * staying completely deterministic.
 */
export async function gotoTotpImportTool(page: Page): Promise<void> {
  await page.getByRole('link', { name: /import from authenticator/i }).click();
  await expect(page).toHaveURL(/\/tools\/totp-import/);
  // A lazy chunk, like the file-encryption panel: this is the request that makes
  // the dev server transform it on demand.
  await expect(page.getByText(/Transfer accounts/i)).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/**
 * A photograph of that same export, as a QR code.
 *
 * RECORDED, like every other file in `e2e/fixtures`, and never regenerated from
 * the code under test. Provenance, so it can be rebuilt if it ever has to be:
 * it is `SAMPLE_AUTHENTICATOR_EXPORT_URI` encoded by `qrcode` (soldair) at
 * error-correction level M, `scale: 8`, `margin: 4` — a 53-module version-9
 * symbol rendered 488 x 488. The decoder inside the sandbox is `qr`
 * (paulmillr), which shares no code with the encoder, so reading it back is a
 * round trip across two independent implementations rather than one library
 * agreeing with itself.
 *
 * MEASURED against the sandbox's OWN budget (`effort: 2`, `timeLimit: 120`, the
 * settings tuned for a live camera rather than a still): it decodes in 32 ms, so
 * the margin is not marginal.
 *
 * Why a committed file rather than a buffer minted in the test: `knip` runs with
 * no `ignoreDependencies`, so importing an encoder here would have to be paid
 * for with a root dependency that ships nothing. The drift risk a recorded
 * artefact carries is answered by the test itself, which asserts the accounts
 * the paste path produces from the constant above.
 */
export const AUTHENTICATOR_EXPORT_QR = 'authenticator-export.png';

export async function readSampleExport(page: Page): Promise<void> {
  await page.getByText(/Paste an export link instead/i).click();
  await page.locator('#totp-paste').fill(SAMPLE_AUTHENTICATOR_EXPORT_URI);
  await page.getByRole('button', { name: /read link/i }).click();
  await expect(page.getByText(/Nothing here is saved yet/i)).toBeVisible();
}

/**
 * Unlocks the vault via the unlock screen.
 *
 * ## Why this activates the control from the keyboard rather than with `click()`
 *
 * MEASURED, once, on the run that first put `auto-lock.spec.ts` on a second
 * engine: `several lock/unlock cycles in a row all succeed` burned its entire
 * 300 s budget inside one `click()`, on a machine that was also running the rest
 * of a fifteen-minute suite. The call log ends
 *
 *   - waiting for element to be visible, enabled and stable
 *   - element is not stable
 *   - retrying click action
 *   - element was detached from the DOM, retrying
 *
 * and then goes silent, and the page snapshot taken at the timeout shows THE
 * VAULT, sidebar and all. So the unlock had already succeeded: a click landed,
 * the unlock screen unmounted, and `click()` — which cannot tell "the element
 * vanished because my click worked" from "the element vanished before my click
 * landed" — re-resolved a locator that now matches nothing and waited for it
 * until the test died. The app did exactly the right thing and the helper
 * reported a failure; that is a defect in the helper.
 *
 * The shape is general: every submit control whose success unmounts its own
 * screen can do this, and a contended machine is what makes the first
 * actionability pass fail and the second one race the unmount. It is not
 * engine-specific — Firefox is simply where it came up first.
 *
 * So the control is ACTIVATED FROM THE KEYBOARD instead. `press('Enter')` focuses
 * the button and dispatches the key events in a single step, with no stability
 * poll and no hit-target retry to be caught in when the element leaves as a result
 * of what it just did. Nothing is waved through to get there: the two assertions
 * above it state, as assertions rather than as implicit preconditions, the part of
 * actionability that matters here — the control is on screen and it is enabled.
 * And Enter on a focused `type="submit"` button is a real user path this suite did
 * not otherwise cover.
 *
 * A `hover()` + `page.mouse.down()/up()` pair was tried first, on the theory that
 * it keeps every actionability check while making the click positional. MEASURED:
 * it did not activate the button on Chromium at all, and — because
 * {@link expectVaultVisible} then only compared the URL, which a lock does not
 * change — it failed two steps later as another five-minute hang. Both halves of
 * that are fixed; do not reintroduce the first half.
 */
export async function unlockVault(page: Page, password: string): Promise<void> {
  await page.getByLabel(/master password/i).fill(password);

  const unlock = page.getByRole('button', { name: /unlock/i });
  await expect(unlock).toBeVisible();
  await expect(unlock).toBeEnabled();
  await unlock.press('Enter');
}

// ─── Vault Item Helpers ──────────────────────────────────────────────────────

/** Creates a vault item and returns its ID. */
export async function createItem(
  request: APIRequestContext,
  user: AuthenticatedUser,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const res = await authMutate(
    request,
    user,
    'post',
    '/api/v1/vault/items',
    sampleVaultItem(overrides),
  );
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { data: { _id: string } };
  return body.data._id;
}

// ─── Accessibility (axe) ─────────────────────────────────────────────────────

/**
 * Where the a11y specs leave their raw scan results for `a11y-gate.mjs`.
 *
 * Anchored on THIS FILE, never on `process.cwd()`, for the reason
 * `zero-knowledge.spec.ts` records: npm runs a workspace script from that
 * workspace's directory, so a cwd-relative path writes somewhere else entirely
 * depending on how the suite was invoked. `__dirname` rather than
 * `import.meta.url`, because Playwright loads these files through a CommonJS
 * require path (the root package.json is not `type: module`) where `import.meta`
 * is a syntax error that kills the whole gate before a spec runs.
 */
const A11Y_SCAN_REPORT = path.resolve(
  __dirname,
  '..',
  '.testfortress',
  'reports',
  'a11y-scans.json',
);

/**
 * One offending element.
 *
 * The summary is axe's own explanation, and it is recorded PER NODE rather than
 * once per violation: `color-contrast` groups every failing element in the
 * document under one rule id, and each of them has different colours and a
 * different ratio. A single summary would describe the first one and silently
 * misattribute the rest, which is worse than none.
 */
export interface A11yViolationNode {
  target: string;
  summary: string;
}

/** One axe violation, flattened to what a report reader needs. */
export interface A11yViolation {
  id: string;
  impact: string;
  help: string;
  helpUrl: string;
  /** The offending elements, capped so a report stays readable. */
  nodes: A11yViolationNode[];
}

/** One scanned view. */
export interface A11yScan {
  view: string;
  url: string;
  /** Every violation axe reported, whatever its impact. */
  violations: A11yViolation[];
  /** The subset that fails the gate: every impact in `A11Y_BLOCKING_IMPACTS`. */
  blocking: A11yViolation[];
  /**
   * Checks axe COULD NOT DECIDE, recorded and not gated.
   *
   * These used to be thrown away, and that is the one place this gate could go
   * quiet without going green-by-accident: axe answers `incomplete` when a rule
   * ran and could not reach a verdict — most often `color-contrast` over a
   * background it cannot resolve (a semi-transparent stack, an image, a gradient)
   * — and a check that has silently become unmeasurable is then indistinguishable
   * from one that passes, in every number this gate publishes. It is the same
   * lesson as the completeness check itself, one level down: an axe run over
   * nothing looks exactly like a clean one, and so does an axe rule that gave up.
   *
   * NOT blocking, deliberately. "Needs a human" is not a defect, gating on it
   * would make the gate fail for the shape of a background rather than for a
   * finding, and the one knob that would then be needed to get green again is a
   * rule exclusion.
   *
   * It is not RATCHETED either, and that is a decision rather than an omission,
   * so it is worth being plain about what this therefore does and does not buy.
   * `a11y.json` publishes the count and the findings, and a person reading the
   * gate's own output sees them — but nothing compares the number between runs,
   * so 1 becoming 12 is visible only to a reader. Neither available direction is
   * the answer: `lower` gates it, which is the paragraph above; and `info` is
   * skipped by the compare loop AND never written by `--accept`
   * (`ratchet-check.mjs`), so it would plant a figure nothing maintains — which
   * is the exact rot this gate's prose counts were just cleaned of.
   */
  incomplete: A11yViolation[];
}

/**
 * One row of axe output — a rule and the elements it matched.
 *
 * Derived from what `AxeBuilder.analyze()` actually returns rather than imported
 * from `axe-core`, which is only a transitive dependency here: naming it
 * directly is an undeclared import and `audit:deadcode` says so. Going through
 * the builder also ties the type to the call this file makes, so a major bump of
 * either package is a compile error rather than a silent shape change.
 */
type AxeResultRow = Awaited<ReturnType<AxeBuilder['analyze']>>['violations'][number];

/** How many offending elements one violation lists. Beyond this the fix is the same fix. */
const A11Y_MAX_NODES = 5;

/** How long a CSS transition may take to settle before the wait is a failure. */
const A11Y_TRANSITION_SETTLE_MS = 5_000;

/** How long a transient toast may take to leave before the wait is a failure. */
const A11Y_TOAST_SETTLE_MS = 15_000;

/**
 * Waits until the notification region is empty.
 *
 * A toast is transient and TIMER-DRIVEN: it starts its 300ms exit transition
 * some seconds after it appeared, which can be in the middle of an axe run, and
 * a control that is halfway through fading reports BLENDED colours — a settled
 * success toast measures 8.65:1 and the same toast mid-exit measured 3.29:1.
 * That is a race with the machine's speed rather than a fact about the
 * application, so a scan waits the toast out. {@link settleTransitions} cannot
 * cover it: the transition has not started yet when the scan begins.
 *
 * What this deliberately gives up: axe never sees a toast. Its accessibility is
 * asserted where it is stable instead — `p2-accessibility.test.tsx` pins the
 * `aria-live` politeness per toast type and `ui-components.test.tsx` pins the
 * dismiss button's accessible name — and its settled contrast is 8.65:1
 * (success), 9.16:1 (error), 8.38:1 (warning) and 9.53:1 (info).
 */
async function settleToasts(page: Page): Promise<void> {
  await expect(page.locator('[role="region"][aria-label="Notifications"] > *')).toHaveCount(0, {
    timeout: A11Y_TOAST_SETTLE_MS,
  });
}

/**
 * Waits until no CSS TRANSITION is still running.
 *
 * Colour contrast is measured from the computed style, and a colour that is
 * mid-transition is a BLEND of where it came from and where it is going. Scanning
 * a tab immediately after clicking it measured `#366fed` for a background whose
 * settled value is `#2563eb`, and reported 3.91:1 for a pair that is really
 * 4.94:1 — a failure that depended on how fast the machine was, which is the
 * definition of a flaky gate. This is the precise wait rather than a sleep: it
 * asks the browser what is actually still animating.
 *
 * Only transitions are awaited. `document.getAnimations()` also returns infinite
 * CSS ANIMATIONS — every spinner in the application is one — and waiting for
 * those to finish would hang forever on any view that is loading something.
 */
async function settleTransitions(page: Page): Promise<void> {
  await page.waitForFunction(
    () =>
      document
        .getAnimations()
        .every(
          (animation) =>
            !('transitionProperty' in animation) ||
            animation.playState === 'finished' ||
            animation.playState === 'idle',
        ),
    undefined,
    { timeout: A11Y_TRANSITION_SETTLE_MS },
  );
}

/**
 * Runs axe against whatever the page currently shows and returns the result.
 *
 * The whole document is scanned rather than a subtree, deliberately: a modal's
 * accessibility is partly a claim about everything BEHIND it (`aria-hidden`
 * covering focusable content, a duplicated landmark, an id that is now not
 * unique), and scanning only the dialog cannot see any of that.
 *
 * Nothing is disabled and no rule set is narrowed. axe's default rules run, all
 * findings are recorded, and everything from `moderate` up fails — see
 * {@link A11Y_BLOCKING_IMPACTS}. Narrowing the rules would raise the pass rate
 * without changing the application, which is the coverage-scope cheat wearing an
 * accessibility hat.
 */
export async function scanA11y(page: Page, view: string): Promise<A11yScan> {
  await settleToasts(page);
  await settleTransitions(page);
  const results = await new AxeBuilder({ page }).analyze();
  const flatten = (rows: AxeResultRow[]): A11yViolation[] =>
    rows.map((row) => ({
      id: row.id,
      impact: row.impact ?? 'unknown',
      help: row.help,
      helpUrl: row.helpUrl,
      nodes: row.nodes.slice(0, A11Y_MAX_NODES).map((node) => ({
        target: Array.isArray(node.target) ? node.target.join(' ') : String(node.target),
        summary: (node.failureSummary ?? '').replace(/\s+/g, ' ').trim(),
      })),
    }));
  const violations = flatten(results.violations);
  return {
    view,
    url: page.url(),
    violations,
    blocking: violations.filter((violation) => A11Y_BLOCKING_IMPACTS.includes(violation.impact)),
    // See `A11yScan.incomplete` for why these are recorded and why they are not
    // gated. `failureSummary` is usually absent on an incomplete node, so the
    // summary is often empty here — the rule id and the selector are the report.
    incomplete: flatten(results.incomplete),
  };
}

/**
 * A one-line description of a scan's blocking violations, for an assertion
 * message.
 *
 * The message carries the rule ids and the offending selectors because that is
 * what a reader needs to act; an assertion that says only "expected 0, got 3"
 * sends them back to the browser to find out what.
 */
export function describeA11y(scan: A11yScan): string {
  if (scan.blocking.length === 0) return `${scan.view}: no blocking violations`;
  return `${scan.view} (${scan.url}) has ${String(scan.blocking.length)} blocking axe violation(s): ${scan.blocking
    .map(
      (violation) =>
        `${violation.id} [${violation.impact}] at ${violation.nodes.map((node) => node.target).join(', ')}`,
    )
    .join(' | ')}`;
}

/**
 * Writes the raw scans where the gate reads them.
 *
 * Written by the SPEC rather than derived by the gate from a JUnit file, because
 * JUnit records that a test failed, never what axe found. The gate turns this
 * into `a11y.json`; keeping the two separate is what lets the gate say "this
 * view was never scanned", which a report that only exists when the spec chose
 * to write it could never do.
 */
export function writeA11yScans(suite: string, scans: A11yScan[]): void {
  mkdirSync(path.dirname(A11Y_SCAN_REPORT), { recursive: true });
  writeFileSync(
    A11Y_SCAN_REPORT,
    `${JSON.stringify({ version: 1, suite, scannedAt: new Date().toISOString(), scans }, null, 2)}\n`,
    'utf8',
  );
}

/** Creates a folder and returns its ID. */
export async function createFolder(
  request: APIRequestContext,
  user: AuthenticatedUser,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const res = await authMutate(request, user, 'post', '/api/v1/folders', sampleFolder(overrides));
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { data: { _id: string } };
  return body.data._id;
}

// ─── Documents ───────────────────────────────────────────────────────────────

/**
 * Where the document fixtures live.
 *
 * Anchored on `__dirname` for the two reasons the a11y report path above records:
 * npm runs a workspace script from that workspace's directory, so a cwd-relative
 * path resolves somewhere else depending on how the suite was invoked; and
 * `import.meta` is a syntax error under the CommonJS require path Playwright
 * loads these files through.
 */
const DOCUMENT_FIXTURES = path.resolve(__dirname, 'fixtures');

/**
 * The absolute path of one document fixture.
 *
 * These files are committed ARTEFACTS and never regenerated from the code under
 * test: `broken.json` is deliberately unrepairable, `ugly.json` deliberately
 * unformatted, `hostile.md` deliberately hostile, and `checker.png` /
 * `handbook.pdf` are compared byte for byte. `.prettierignore` keeps the
 * formatter off them and `.gitattributes` marks the directory `-text` so git
 * cannot rewrite a line ending on checkout.
 */
export function documentFixture(name: string): string {
  return path.join(DOCUMENT_FIXTURES, name);
}

/** One document fixture's bytes, for a byte-for-byte comparison after a download. */
export function documentFixtureBytes(name: string): Buffer {
  return readFileSync(documentFixture(name));
}

/**
 * Remove the File System Access save dialog before any page script runs.
 *
 * NOT a convenience, and not a simplification of the code under test. Measured:
 * headless Chromium at `http://127.0.0.1` reports `isSecureContext: true` and
 * DOES expose `window.showSaveFilePicker`, so `saveDocument` takes its picker
 * branch and opens a NATIVE save dialog — a window outside the page that no
 * automation can drive, and the download journey would hang on it forever.
 *
 * Deleting the property makes the browser look like Firefox, Safari or any
 * non-secure context, which is a shipped, supported configuration rather than a
 * fiction: `saveDocument` then takes `saveThroughBlob`, which is the path those
 * users get. The picker branch is covered where it CAN be driven honestly, in
 * `packages/client/tests/documents-download.test.ts`, which stubs the API and
 * asserts the streaming writes, the truncate-on-integrity-failure and the
 * abort-on-anything-else.
 *
 * Called before the first navigation, because an init script applies to
 * documents loaded afterwards and the app reads the property at click time.
 */
export async function disableSaveFilePicker(page: Page): Promise<void> {
  await page.addInitScript(() => {
    // `delete` rather than assigning undefined. `getSaveFilePicker` also checks
    // `typeof window.showSaveFilePicker === 'function'`, so either spelling
    // would work today — but the `in` half of that probe is the one that exists
    // because the property is absent from the DOM types, and removing the
    // property is the state this is meant to reproduce: a browser that never
    // had it. Assigning `undefined` reproduces a browser that has it and broke.
    delete (window as unknown as Record<string, unknown>)['showSaveFilePicker'];
  });
}

/**
 * Navigate to the Documents route through the sidebar and wait for it to mount.
 *
 * The upload input is the readiness signal rather than the heading, and the
 * reason is the one `gotoFileEncryptionTool` records: the route is `lazy()`, so
 * the heading can be on screen while the panel below it is still being
 * transformed by Vite. It is also the element every caller goes on to use.
 */
export async function gotoDocuments(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Documents', exact: true }).click();
  await expect(page).toHaveURL(/\/documents$/);
  await expect(page.getByRole('heading', { name: 'Documents', level: 1 })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
  await expect(page.locator('#document-upload-input')).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/**
 * Upload one fixture with no transform and wait until the stored row is listed.
 *
 * The row is the ONLY honest completion signal available from outside. The
 * progress row disappears when the transfer leaves the registry, which happens
 * on a failure as well as on a success, and the toast is transient; a listed row
 * means the server committed the document and this client decrypted its metadata
 * back with the vault key it sealed it under.
 *
 * `LAZY_ROUTE_TIMEOUT_MS` rather than the default assertion budget: an upload is
 * a SHA-256 over the file, an AES-GCM seal per segment, a round trip per part
 * and a re-listing, on a machine that is also running a Vite dev server, an
 * in-memory mongod and a storage container.
 */
export async function uploadDocument(
  page: Page,
  fixture: string,
  directory: string = DOCUMENT_FIXTURES,
): Promise<void> {
  await page.locator('#document-upload-input').setInputFiles(path.join(directory, fixture));
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(page.getByTestId('document-name').filter({ hasText: fixture })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/**
 * The committed corpus of hostile documents the renderer suites are built on.
 *
 * The client's own copy, read in place rather than duplicated into `fixtures/`:
 * `packages/client/tests/sandbox-markup.test.ts` asserts on these two files in
 * jsdom, and a second copy here would be free to drift from the one the unit tier
 * pins, which is exactly the pair of claims the browser gate exists to join.
 * Pass it as {@link uploadDocument}'s `directory`.
 */
export const SANDBOX_HOSTILE_CORPUS = path.resolve(
  __dirname,
  '..',
  'packages',
  'client',
  'tests',
  'sandbox',
  'corpus',
);

/** Open a listed document's detail view and wait for its own heading. */
export async function openDocument(page: Page, fixture: string): Promise<void> {
  await page.getByTestId('document-name').filter({ hasText: fixture }).click();
  await expect(page).toHaveURL(/\/documents\/[0-9a-f]{24}/);
  await expect(page.getByRole('heading', { name: fixture, level: 1 })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/**
 * How long a preview may take to appear.
 *
 * Bound by the DEV SERVER rather than by the renderer: each mode is a dynamic
 * import, so the first document of a given kind is the request that makes Vite
 * transform that renderer and its dependencies on demand — the syntax
 * highlighter alone is some 890 KiB of language grammars. The same contention
 * `LAZY_ROUTE_TIMEOUT_MS` exists for, one layer further in. Against the built
 * artifact the chunks already exist, so the budget is generous there, never
 * tight.
 */
export const PREVIEW_TIMEOUT_MS = 90_000;

/** The preview frame's locator, for reading its DOM. */
export function previewFrame(page: Page): FrameLocator {
  return page.frameLocator('iframe[title^="Preview of "]');
}

/**
 * The preview frame's `Frame` handle, for asking the isolated document about its
 * OWN globals — the one question a DOM locator cannot answer.
 */
export async function sandboxFrame(page: Page): Promise<Frame> {
  await expect(page.locator('iframe[title^="Preview of "]')).toBeVisible({
    timeout: PREVIEW_TIMEOUT_MS,
  });
  const frame = page.frames().find((candidate) => candidate.url().includes('/sandbox.html'));
  expect(frame, 'no frame is loaded from /sandbox.html').toBeTruthy();
  return frame as Frame;
}

/** Wait until a renderer has put its shell on screen inside the frame. */
export async function waitForRendered(page: Page, mode: string): Promise<void> {
  await expect(previewFrame(page).locator(`.hv-doc-${mode}`)).toBeVisible({
    timeout: PREVIEW_TIMEOUT_MS,
  });
}

/** Back to the list, then open the next document. */
export async function openNext(page: Page, fixture: string): Promise<void> {
  await page.getByRole('link', { name: 'Back to documents' }).click();
  await expect(page).toHaveURL(/\/documents$/);
  await openDocument(page, fixture);
}

/**
 * The isolated document, driven DIRECTLY as a top-level page.
 *
 * `startSandbox` posts `{ kind: 'ready' }` to `win.parent`, and at top level that
 * IS the window itself; its window listener accepts only a message CARRYING A
 * TRANSFERRED PORT and does not remove itself for one without. So an init script
 * registered before the module — which is what `addInitScript` guarantees — can
 * answer the frame's own announcement with a port and complete the real
 * handshake. There is no race and no sleep: the listener exists before the
 * message can be posted.
 *
 * WHY THIS IS AVAILABLE AT ALL, stated because it is a dev-server property and
 * not a claim about production. `test:e2e` and `test:a11y` drive `npm run dev`,
 * which serves `/sandbox.html` with no Content-Security-Policy; the Express route
 * that serves it in production attaches a policy carrying the `sandbox
 * allow-scripts` DIRECTIVE, which makes the document opaque even at top level.
 * This is therefore a way to exercise the RENDERERS, never evidence about the
 * isolation — the isolation is proven against the real embedded frame in
 * `document-viewer.spec.ts`, and under the production policy by
 * `sandbox-policy.prod.ts`, which `test:sandbox` runs against the built artifact.
 */
export interface SandboxRenderOptions {
  /** A `PreviewMode` value. Passed as a string, exactly as the host posts it. */
  mode: string;
  /** The lowercased extension, a highlighting hint and nothing more. */
  ext: string;
  /** The document's bytes. */
  bytes: Buffer;
  theme?: 'light' | 'dark';
}

/** One reply the isolated document sent back on the port. */
export interface SandboxReply {
  kind: string;
  reason?: string;
  href?: string;
}

declare global {
  interface Window {
    /**
     * The harness's end of the handshake, installed by
     * {@link renderInSandboxDirectly}. Present only under that helper, and only
     * on a top-level `/sandbox.html`.
     */
    __hvSandboxPort?: MessagePort;
    /** Every reply the document has posted on that port, in order. */
    __hvSandboxReplies?: SandboxReply[];
  }
}

/**
 * Navigate `page` to `/sandbox.html`, hand the document a port, post one render
 * request, and return every reply it made.
 *
 * Resolves once the document has answered. It ALWAYS answers — `renderRequest`
 * posts `rendered` or `failed` on every branch, which is the contract the host's
 * own ten-second deadline depends on — so a caller can assert on the reply
 * rather than on a timeout.
 */
export async function renderInSandboxDirectly(
  page: Page,
  options: SandboxRenderOptions,
): Promise<SandboxReply[]> {
  await page.addInitScript(() => {
    window.addEventListener('message', (event: MessageEvent) => {
      // The reply this very listener posts below carries the port, and the
      // document's announcement does not. Ignoring the former is what stops the
      // handshake answering itself in a loop.
      if (event.ports.length > 0) return;
      const data: unknown = event.data;
      if (typeof data !== 'object' || data === null) return;
      if ((data as { kind?: unknown }).kind !== 'ready') return;
      const channel = new MessageChannel();
      const replies: SandboxReply[] = [];
      window.__hvSandboxPort = channel.port1;
      window.__hvSandboxReplies = replies;
      channel.port1.addEventListener('message', (message: MessageEvent) => {
        replies.push(message.data as SandboxReply);
      });
      channel.port1.start();
      window.postMessage({ kind: 'harness-handshake' }, '*', [channel.port2]);
    });
  });

  await page.goto('/sandbox.html');
  // The port, not the DOM, is the readiness signal: the module has to have run
  // for the announcement to have been posted at all.
  await page.waitForFunction(() => window.__hvSandboxPort !== undefined, undefined, {
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });

  await page.evaluate(
    ({ mode, ext, theme, bytes }) => {
      // A fresh buffer built inside the page. The bytes cross as an array of
      // numbers because that is what survives Playwright's serialization, and
      // the frame's own validator checks for a REAL ArrayBuffer by its internal
      // slot — a typed-array view or a plain object of the same shape is refused.
      const buffer = new Uint8Array(bytes).buffer;
      window.__hvSandboxPort?.postMessage({ kind: 'render', mode, ext, theme, bytes: buffer });
    },
    {
      mode: options.mode,
      ext: options.ext,
      theme: options.theme ?? 'light',
      bytes: [...options.bytes],
    },
  );

  await page.waitForFunction(() => (window.__hvSandboxReplies?.length ?? 0) > 0, undefined, {
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
  return page.evaluate(() => window.__hvSandboxReplies ?? []);
}
