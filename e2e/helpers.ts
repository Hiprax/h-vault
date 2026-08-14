import { test, type Page, type APIRequestContext, expect } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { seededRandom } from '../tests/harness/determinism.js';
import { A11Y_BLOCKING_IMPACTS } from './a11yViews.js';
import { MongoClient, type Db } from 'mongodb';

// ─── Constants ───────────────────────────────────────────────────────────────

const MONGODB_URI = process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/hvault';
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
  const db = await getMongoDb();
  await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });
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

/** Unlocks the vault via the unlock screen. */
export async function unlockVault(page: Page, password: string): Promise<void> {
  await page.getByLabel(/master password/i).fill(password);
  await page.getByRole('button', { name: /unlock/i }).click();
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
  /** The subset that fails the gate: `serious` and `critical`. */
  blocking: A11yViolation[];
}

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
 * findings are recorded, and only `serious`/`critical` fail — see
 * {@link A11Y_BLOCKING_IMPACTS}. Narrowing the rules would raise the pass rate
 * without changing the application, which is the coverage-scope cheat wearing an
 * accessibility hat.
 */
export async function scanA11y(page: Page, view: string): Promise<A11yScan> {
  await settleToasts(page);
  await settleTransitions(page);
  const results = await new AxeBuilder({ page }).analyze();
  const violations: A11yViolation[] = results.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact ?? 'unknown',
    help: violation.help,
    helpUrl: violation.helpUrl,
    nodes: violation.nodes.slice(0, A11Y_MAX_NODES).map((node) => ({
      target: Array.isArray(node.target) ? node.target.join(' ') : String(node.target),
      summary: (node.failureSummary ?? '').replace(/\s+/g, ' ').trim(),
    })),
  }));
  return {
    view,
    url: page.url(),
    violations,
    blocking: violations.filter((violation) => A11Y_BLOCKING_IMPACTS.includes(violation.impact)),
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
  if (scan.blocking.length === 0) return `${scan.view}: no serious or critical violations`;
  return `${scan.view} (${scan.url}) has ${String(scan.blocking.length)} serious/critical axe violation(s): ${scan.blocking
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
