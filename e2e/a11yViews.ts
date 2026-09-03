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
 * open create dialog, the unlock screen comes near the end because reaching it
 * locks the vault and ends the authenticated walk, and the isolated document
 * comes after even that because it needs no session at all.
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
  { id: 'documents-list', description: 'the documents page with two documents stored' },
  {
    // NOT the panel at rest. At rest it is already inside `documents-list` — it
    // is a plain `<section>` mounted unconditionally on that page, not a dialog
    // that opens — so scanning it idle would be a duplicate of DOM this walk has
    // already covered, inflating a count while covering nothing. The state below
    // exists only after a file is picked and a transform is confirmed, and it is
    // where the panel's controls actually are.
    id: 'document-upload-review',
    description:
      'the documents page with a file selected, both transform controls ticked, and the prepare-and-review panel awaiting confirmation',
  },
  {
    // The DECLINED half of the detail view: a PDF is `PREVIEW_MODES.none`, so
    // the page draws its chrome, the reason and the download button, and creates
    // no frame at all. Distinct DOM from the view below rather than a second
    // look at the same page.
    id: 'document-detail',
    description: 'a stored PDF, which is download-only, so the detail view draws no frame',
  },
  {
    id: 'document-viewer',
    description: 'a stored markdown document, rendered inside the isolated frame',
  },
  { id: 'unlock-screen', description: 'the unlock screen, vault locked' },
  {
    // THE FIFTH VIEW, and its reason is a property of axe rather than of this
    // application, so it is written down here where somebody might otherwise
    // delete it as redundant.
    //
    // The frame's CONTENTS are already scanned by `document-viewer`:
    // `@axe-core/playwright` reaches a child frame through Playwright's own
    // frame tree, which is not subject to the same-origin policy, so a serious
    // finding inside the isolated document fails that view. This view is not a
    // second look at the same nodes. It covers two things that one structurally
    // cannot:
    //
    //   1. axe's PAGE-LEVEL rules never run on a framed document. `document-title`,
    //      `html-has-lang`, `aria-hidden-body` and `meta-viewport` all carry
    //      `matches: 'is-initiator-matches'`, so `packages/client/sandbox.html`'s
    //      own skeleton — its `lang`, its `<title>` — is checked by nothing else
    //      in this repository. It is built by its own Vite config and appears in
    //      no other scan.
    //   2. The framed leg is BEST-EFFORT. `runPartialRecursive` wraps its
    //      child-frame injection in a bare `catch`, so a frame that was slow or
    //      blank yields no partial and a parent run that reports zero violations
    //      while appearing to have covered it. A top-level navigation needs no
    //      handshake, no CORS and no port, so it cannot degrade that way.
    //
    // It is reachable only because both Playwright gates drive `npm run dev`,
    // which serves this document with no Content-Security-Policy. In production
    // the Express route attaches one carrying the `sandbox allow-scripts`
    // DIRECTIVE, which makes the document opaque even at top level — so this is
    // a way to exercise the RENDERERS' output, never evidence about the
    // isolation.
    id: 'sandbox-rendered',
    description:
      'the isolated document itself, navigated to directly and handed a rendered markdown document',
  },
] as const satisfies readonly A11yView[];

/** Every scanned view's id, in visit order. */
export const A11Y_VIEW_IDS: readonly string[] = A11Y_VIEWS.map((view) => view.id);

/**
 * Impacts that fail the gate.
 *
 * axe grades every violation `minor`, `moderate`, `serious` or `critical`. The
 * gate is the top two (plus the ungraded case below), and the other two are
 * RECORDED rather than ignored, so
 * the report says what was found without a moderate finding blocking a push.
 * Both halves matter: a gate that failed on `minor` would be turned off within a
 * week, and one that recorded nothing could never show the debt moving.
 *
 * `unknown` is here for the third case: axe types `impact` as nullable, and
 * `scanA11y` maps a null one to `'unknown'`. Left out, an unclassified violation
 * was neither blocking NOR published in the gate's own counts — a finding that
 * appeared nowhere at all. It fails closed instead, because "axe could not grade
 * this" is not evidence that it is minor.
 */
export const A11Y_BLOCKING_IMPACTS: readonly string[] = ['serious', 'critical', 'unknown'];
