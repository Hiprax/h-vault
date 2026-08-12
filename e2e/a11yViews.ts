/**
 * The views `test:a11y` scans, named once so three places cannot disagree.
 *
 * This list is the gate's MEMBERSHIP, and it is deliberately a committed
 * constant rather than something derived at run time. The lesson is the one
 * `vitest.security.config.ts` records: a named subset whose membership lives
 * only in the code that runs it shrinks in silence. Here that failure mode is
 * worse than usual, because an axe scan of nothing is indistinguishable from an
 * axe scan that found nothing — both report zero violations.
 *
 * Three independent things therefore read this list:
 *
 *   1. `e2e/a11y.spec.ts` scans each entry and, as its last act, asserts that it
 *      produced a result for EVERY id here. Deleting a scan turns that red.
 *   2. `scripts/ci/a11y-gate.mjs` requires the run's report to carry every id,
 *      so a spec that silently stopped running is a failed gate rather than a
 *      clean one.
 *   3. `packages/server/tests/gate-surface.test.ts` pins the list itself, so
 *      REMOVING an id — which would satisfy both checks above — is a visible
 *      edit somebody has to make on purpose.
 *
 * Kept free of imports (no Playwright, no axe) so a vitest suite and a plain
 * Node script can both read it without pulling a browser harness into scope.
 */

/** One scanned view: the id used in every report, and what it is. */
export interface A11yView {
  /** Stable id. Appears in `a11y.json` and in the gate's output. */
  readonly id: string;
  /** What a reader needs to know about the state the page is in when scanned. */
  readonly description: string;
}

/**
 * Every primary view and modal, in the order the spec visits them.
 *
 * The order is not arbitrary: the two unauthenticated pages come first because
 * they need no session, the item form's five type tabs are scanned inside ONE
 * open create dialog, and the unlock screen comes last because reaching it locks
 * the vault, which ends the authenticated walk.
 */
export const A11Y_VIEWS = [
  { id: 'login', description: 'the sign-in page, signed out' },
  { id: 'register', description: 'the registration page, signed out' },
  { id: 'vault-list', description: 'the vault list with an item in it' },
  { id: 'item-detail', description: 'a login item opened from the list' },
  { id: 'item-form-login', description: 'the create dialog, Login tab' },
  { id: 'item-form-secret', description: 'the create dialog, Secret tab' },
  { id: 'item-form-note', description: 'the create dialog, Note tab' },
  { id: 'item-form-card', description: 'the create dialog, Card tab, billing section collapsed' },
  {
    id: 'item-form-card-billing',
    description: 'the create dialog, Card tab, billing address section expanded',
  },
  {
    id: 'item-form-address-picker',
    description: 'the create dialog, Card tab, saved-address picker panel open',
  },
  { id: 'item-form-identity', description: 'the create dialog, Identity tab' },
  { id: 'settings', description: 'the settings page' },
  { id: 'vault-health', description: 'the vault health page after its checks have run' },
  { id: 'file-encryption', description: 'the file-encryption tool' },
  { id: 'unlock-screen', description: 'the unlock screen, vault locked' },
] as const satisfies readonly A11yView[];

/** Every scanned view's id, in visit order. */
export const A11Y_VIEW_IDS: readonly string[] = A11Y_VIEWS.map((view) => view.id);

/**
 * Impacts that fail the gate.
 *
 * axe grades every violation `minor`, `moderate`, `serious` or `critical`. The
 * gate is the top two, and the other two are RECORDED rather than ignored, so
 * the report says what was found without a moderate finding blocking a push.
 * Both halves matter: a gate that failed on `minor` would be turned off within a
 * week, and one that recorded nothing could never show the debt moving.
 */
export const A11Y_BLOCKING_IMPACTS: readonly string[] = ['serious', 'critical'];
