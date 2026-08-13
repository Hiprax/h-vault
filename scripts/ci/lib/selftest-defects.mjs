/**
 * The defect-injection registry: one planted defect per registered gate.
 *
 * `verify:selftest` (scripts/ci/selftest.mjs) reads this map, and a task in
 * `.testfortress/verify.json` with no entry here is a HARD ERROR naming that
 * task. That is the whole design: nine later phases each register new gates, and
 * a selftest that silently covered only the gates that existed when it was
 * written would report confidence it had not earned. Adding a gate therefore
 * means adding its defect case, in the same change, right here.
 *
 * Each case declares:
 *
 *   title     what the planted defect is, in one line
 *   requires  prerequisites the case needs from the world ('docker', 'codeql')
 *   create    files to write into the temp copy (path -> contents)
 *   mutate    existing files to edit in the temp copy (path -> text => text)
 *   timeoutMs optional wall-clock bound on the gate's own run. Only one case
 *             needs it (`test:mutation`, whose unplanted run is hours), and it
 *             is per-case rather than global because a gate killed by a clock it
 *             did not expect would be reported as failing for a reason nobody
 *             planted.
 *   evidence  optional (text) => boolean over the gate's own report, proving the
 *             non-zero exit is ATTRIBUTABLE to this defect. Without it, a gate
 *             that is already red for an unrelated reason would "prove" itself,
 *             which is the failure mode this whole file exists to prevent. Where
 *             a gate's report is only a transcript, the transcript is what is
 *             searched.
 *
 * A note on the two assembled strings below. `scripts/ci/**` is a gate-defining
 * file zone for `audit:integrity`, and `secret-scan.mjs` reads every tracked
 * file, so a literal `eslint-disable` directive or a literal AWS-key-shaped
 * string in THIS file would be a finding in the real repository rather than in
 * the copy. They are assembled from fragments at runtime so the planted marker
 * exists only where it is planted. Do not "tidy" them back into literals.
 */

/** Joins fragments so the marker exists only in the planted file. */
const marker = (...parts) => parts.join('');

const PLANTED_LINT_DIRECTIVE = marker('//', ' eslint-', 'disable-next-line no-console');
const PLANTED_FAKE_SECRET = marker('AKIA', 'IOSFODNN7', 'EXAMPLE');

/** @type {Record<string, {title: string, requires?: string[], create?: Record<string,string>, mutate?: Record<string,(text:string)=>string>, evidence?: (text:string)=>boolean}>} */
export const DEFECTS = {
  engines: {
    title: 'raise engines.node above the running Node, so the floor is not met',
    mutate: {
      'package.json': (text) => text.replace(/"node":\s*">=[^"]*"/, '"node": ">=99.0.0"'),
    },
    evidence: (text) => /is below the required/.test(text),
  },

  'audit:secrets': {
    title: 'commit a file carrying an AWS-access-key-shaped literal',
    create: {
      'packages/server/src/__selftest_secret.ts': `export const key = '${PLANTED_FAKE_SECRET}';\n`,
    },
    evidence: (text) => /__selftest_secret/.test(text),
  },

  'audit:secrets:full': {
    // `buryInHistory` is what makes this case prove the HISTORY leg rather than
    // the working-tree leg its T0 sibling already covers: the harness commits the
    // planted file, deletes it, and commits again, so the tree is clean and only
    // `git rev-list --objects --all` can still see the secret. A tree-only plant
    // would be indistinguishable from the `audit:secrets` case and would prove
    // nothing this gate adds.
    title: 'commit an AWS-access-key-shaped literal, then delete it — leaving it only in history',
    create: {
      'packages/server/src/__selftest_secret_full.ts': `export const key = '${PLANTED_FAKE_SECRET}';\n`,
    },
    buryInHistory: true,
    // The finding must be attributed to HISTORY, not to a file left lying about:
    // both halves of this predicate matter.
    evidence: (text) => /__selftest_secret_full/.test(text) && /"where":\s*"history"/.test(text),
  },

  deadcode: {
    // An exported symbol nothing imports, in a file nothing imports: knip
    // reports it, and the gate refuses to let it be ignored.
    title: 'add a source module nothing imports, exporting a symbol nothing uses',
    create: {
      'packages/shared/src/__selftest_probe.ts':
        'export const selftestProbeValue = 1;\nexport type SelftestProbe = typeof selftestProbeValue;\n',
    },
    evidence: (text) => /__selftest_probe/.test(text),
  },

  'audit:config': {
    requires: ['actionlint', 'hadolint'],
    // An undefined context in a workflow expression. actionlint resolves
    // expressions rather than merely parsing YAML, which is exactly why it is
    // here: a typo'd context is valid YAML and fails only at run time, on the one
    // workflow that publishes releases.
    title: 'reference an undefined context in the release workflow expression',
    mutate: {
      '.github/workflows/release.yml': (text) =>
        text.replace(/^(\s*)(runs-on:.*)$/m, '$1$2\n$1if: ${{ selftestprobe.value == 1 }}'),
    },
    evidence: (text) => /selftestprobe/.test(text),
  },

  'audit:openapi': {
    requires: ['oasdiff'],
    // A response field deleted from the contract the server serves, at an
    // unchanged version. This is the exact shape the gate exists to catch: the
    // field is optional, so no type breaks and no test fails — the SPA simply
    // stops receiving `encryptedVaultKey` and cannot open the vault.
    //
    // Planted in `swagger.ts` rather than in the committed snapshot, because
    // the snapshot is the BASE: editing it would prove the gate notices an
    // edited base, which is not the claim. The claim is that a change to the
    // served document is caught.
    title: 'delete a response field from the served OpenAPI contract without a MAJOR bump',
    mutate: {
      'packages/server/src/config/swagger.ts': (text) =>
        text.replace(/\n\s+encryptedVaultKey: \{ type: 'string' \},(?=\n\s+vaultKeyIv)/, ''),
    },
    evidence: (text) =>
      /encryptedVaultKey/.test(text) && /response-optional-property-removed/.test(text),
  },

  'audit:licenses': {
    // A licence in the production tree that the policy does not accept. Planted
    // by removing one from the allowlist rather than by installing a GPL
    // package: the gate cannot tell the two apart — both are "a production
    // dependency whose licence nobody has approved" — and only one of them is
    // reproducible offline in a temp copy.
    title: 'drop a licence the production tree really uses from the allowlist',
    mutate: {
      '.licenses-allowlist.json': (text) => {
        const policy = JSON.parse(text);
        policy.allow = policy.allow.filter((license) => license !== 'ISC');
        return `${JSON.stringify(policy, null, 2)}\n`;
      },
    },
    evidence: (text) => /is not in .licenses-allowlist.json/.test(text) && /ISC/.test(text),
  },

  'audit:integrity': {
    title: 'add an unledgered lint suppression to a source file',
    create: {
      'packages/shared/src/__selftest_probe.ts': `${PLANTED_LINT_DIRECTIVE}\nexport const probe = 1;\n`,
    },
    evidence: (text) =>
      /__selftest_probe.*LINT-SUPPRESS|LINT-SUPPRESS[\s\S]*__selftest_probe/.test(text),
  },

  'audit:ratchet': {
    // The ratchet's job is to notice that a gate stopped existing, which is the
    // cheapest way to make a pipeline green: delete the check.
    title: 'delete a registered task from the manifest, so a gate silently disappears',
    mutate: {
      '.testfortress/verify.json': (text) => {
        const manifest = JSON.parse(text);
        delete manifest.tasks['format:check'];
        return `${JSON.stringify(manifest, null, 2)}\n`;
      },
    },
    evidence: (text) => /"path":\s*"tasks"/.test(text) && /format:check/.test(text),
  },

  'coverage:check': {
    // A NEW production module, deliberately, and not an uncovered line added to
    // an existing one. The distinction is the whole point of the case.
    //
    // This harness copies the coverage reports rather than re-running the
    // suites, so a line added to a measured file has no entry in the report at
    // all — and diff-cover, correctly, only reports on lines it can find
    // coverage data for. The plant would therefore be INVISIBLE to the
    // patch-coverage half, and the case would quietly prove nothing.
    //
    // A whole new file is visible to the half written for exactly it: a file in
    // no coverage report is indistinguishable from a file that does not exist,
    // so unless the gate enumerates the changed production files ITSELF and
    // checks them against the measured set, an entire untested module reads as
    // 100% patch coverage over zero lines. That is the hole, and this is the
    // defect that proves it is closed. The diff-cover half is exercised on the
    // real tree, where the suites have run and the report describes it.
    title: 'add a production module nothing has ever executed, so its changed lines are unmeasured',
    create: {
      'packages/shared/src/__selftest_uncovered.ts':
        'export function selftestUncovered(value: number): number {\n' +
        '  if (value > 0) return value * 2;\n' +
        '  return -1;\n' +
        '}\n',
    },
    evidence: (text) => /__selftest_uncovered/.test(text),
  },

  'audit:ratchet:full': {
    title: 'raise a coverage percentage while the measured file set loses a file',
    mutate: {
      '.testfortress/baseline.json': (text) => {
        const baseline = JSON.parse(text);
        for (const pkg of Object.values(baseline.packages ?? {})) {
          if (!pkg.coverage?.filesMeasured) continue;
          pkg.coverage.filesMeasured = [
            ...pkg.coverage.filesMeasured,
            'packages/__selftest/never-measured.ts',
          ].sort();
          break;
        }
        return `${JSON.stringify(baseline, null, 2)}\n`;
      },
    },
    // Anchored to the planted path alone: `filesMeasured` also appears when a
    // coverage report is simply absent, and matching that would let the case
    // "prove" a gate the defect never touched.
    evidence: (text) => /never-measured/.test(text),
  },

  lint: {
    title: 'add a source file with an explicit `any`, which this config lints as an error',
    create: {
      'packages/shared/src/__selftest_probe.ts': 'export const probe: any = 1;\n',
    },
    evidence: (text) => /__selftest_probe/.test(text),
  },

  'format:check': {
    title: 'add a file Prettier would reformat',
    create: {
      'packages/shared/src/__selftest_probe.ts': "export const probe    =  'unformatted'  ;;\n",
    },
    evidence: (text) => /__selftest_probe/.test(text),
  },

  typecheck: {
    title: 'assign a string to a number, so tsc must reject it',
    create: {
      'packages/shared/src/__selftest_probe.ts': "export const probe: number = 'not a number';\n",
    },
    evidence: (text) => /__selftest_probe/.test(text),
  },

  build: {
    title: 'break the shared package with a syntax error, so the build cannot emit',
    create: {
      'packages/shared/src/__selftest_probe.ts': 'export const probe = (((;\n',
    },
    // Anchored to the planted file alone. `/error/i` would have matched any
    // build failure, so the case would stop being attributable the moment the
    // build could fail for another reason.
    evidence: (text) => /__selftest_probe/.test(text),
  },

  'test:unit': {
    title: 'add a client unit test whose assertion is false',
    create: {
      'packages/client/tests/__selftest_probe.test.ts':
        "import { describe, it, expect } from 'vitest';\n\n" +
        "describe('selftest probe', () => {\n" +
        "  it('fails on purpose so the gate is proven able to fail', () => {\n" +
        '    expect(1 + 1).toBe(3);\n' +
        '  });\n' +
        '});\n',
    },
    evidence: (text) => /__selftest_probe|selftest probe/.test(text),
  },

  'test:integration': {
    title: 'add a server test whose assertion is false',
    create: {
      'packages/server/tests/__selftest_probe.test.ts':
        "import { describe, it, expect } from 'vitest';\n\n" +
        "describe('selftest probe', () => {\n" +
        "  it('fails on purpose so the gate is proven able to fail', () => {\n" +
        '    expect(1 + 1).toBe(3);\n' +
        '  });\n' +
        '});\n',
    },
    evidence: (text) => /__selftest_probe|selftest probe/.test(text),
  },

  'test:security': {
    // The defect this gate exists to catch, planted at its source: an
    // ownership filter removed from a controller query. `getItem` is chosen
    // because it is a READ — the matrix must go red on a leak, not only on a
    // write — and because the mutation is the single edit a careless refactor
    // would make.
    //
    // The pattern is byte-exact against today's source, and a rewrite of that
    // line (a reordered filter, a Prettier wrap, an extraction into a helper)
    // turns `String.replace` into a no-op. That fails in the SAFE direction:
    // an unplanted defect leaves the gate green, which this harness reports as
    // `unproven` and exits non-zero on — provided the evidence predicate below
    // cannot be satisfied by a green report. Both halves depend on each other.
    title: "drop the ownership filter from getItem, so any user can read any user's item by id",
    mutate: {
      'packages/server/src/controllers/vaultController.ts': (text) =>
        text.replace(
          /VaultItem\.findOne\(\{ _id: id, userId \}\)/,
          'VaultItem.findOne({ _id: id })',
        ),
    },
    // `status was 200` is the discriminator, and it has to be: the report this
    // predicate reads is JUnit XML, which carries a `<testcase name=…>` for
    // every test that RAN, passing or failing. Matching the test's NAME —
    // "refuses user B", the route — would therefore be satisfied by a perfectly
    // green report, and the selftest harness copies the previous run's reports
    // into its workspace, so a command that failed before writing anything
    // (a mongod that would not bind, an unrelated red in the same suite) would
    // have "proved" this gate against a stale green artifact. Only the
    // non-owner receiving a 2xx produces this string, and only the planted
    // defect produces that.
    evidence: (text) => /refuses user B/.test(text) && /status was 200/.test(text),
  },

  'test:observability': {
    // The defect this gate exists to catch, planted at its source and as the
    // single edit a careless refactor would make: one word in app.ts, after
    // which every production 5xx answers with the internal error message —
    // database hostnames, credentials in a connection string, the failing query
    // — instead of "Internal Server Error". CWE-209, and invisible in
    // development, where the middleware exposes those messages by design.
    title: 'let production 5xx bodies expose the internal error message',
    mutate: {
      'packages/server/src/app.ts': (text) =>
        text.replace(
          'createErrorMiddleware({ exposeServerErrors: false })',
          'createErrorMiddleware({ exposeServerErrors: true })',
        ),
    },
    // The custom assertion message, which a PASSING report cannot contain: the
    // JUnit artifact carries a `<testcase name=…>` for every test that ran, so
    // matching a test's NAME would be satisfied by a fully green run — the trap
    // recorded on `test:security` above. Only the failed expectation prints
    // this string.
    evidence: (text) => /production 5xx body leaks internals/.test(text),
  },

  'test:property': {
    // The defect this gate exists to catch, planted at its source and as the
    // single edit a careless "simplification" would make: one AES-GCM IV, reused
    // for every encryption. A fixed IV under GCM leaks the XOR of any two
    // plaintexts encrypted with it AND the authentication subkey, so forgery
    // becomes possible — and it is invisible to every other kind of test, because
    // a fixed-IV implementation round-trips correctly, rejects a wrong key, and
    // rejects a flipped tag. Only the freshness property notices.
    //
    // The pattern is byte-exact against today's `encryptData`. A rewrite of that
    // line turns `String.replace` into a no-op, which fails in the SAFE direction:
    // the gate then stays green, the harness reports `unproven`, and the run exits
    // non-zero — provided the evidence predicate below cannot be satisfied by a
    // green report, which is why it matches the ASSERTION MESSAGE rather than a
    // test name.
    title: 'reuse one AES-GCM IV for every encryption, which only a freshness property can see',
    mutate: {
      'packages/client/src/services/crypto/cryptoService.ts': (text) =>
        text.replace(
          `  async encryptData(
    data: string,
    vaultKey: CryptoKey,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));`,
          `  async encryptData(
    data: string,
    vaultKey: CryptoKey,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const iv = new Uint8Array(IV_BYTES);`,
        ),
    },
    // The custom message of the failing expectation, which a PASSING report cannot
    // contain — the trap recorded on `test:security` above: JUnit carries a
    // `<testcase name=…>` for every test that RAN, so matching a test's name would
    // be satisfied by a fully green run.
    evidence: (text) => /AES-GCM nonce reuse: \d+ calls produced \d+ distinct IV/.test(text),
  },

  'test:snapshot': {
    // The defect this gate exists to catch, planted at its source and as the
    // single edit a careless tidy-up would make: two columns swapped in the
    // Chrome/Edge header. The row values are built positionally further down the
    // same file and do NOT move with it, so the exported file now labels the
    // username column `password` and the password column `username` — every
    // consumer, positional or name-keyed, reads one as the other, and the user
    // finds out while migrating away.
    //
    // It is invisible to every other gate. `chromeCsv.test.ts` checks the header
    // against a literal and would catch this one, but nothing anywhere checks the
    // whole DOCUMENT, which is what makes a reordered row, a `null` that became
    // `""`, or a dropped field visible. The golden does.
    title: 'swap two columns in the Chrome/Edge CSV header, so the file mislabels its own values',
    mutate: {
      'packages/client/src/services/export/formats/chromeCsv.ts': (text) =>
        text.replace(
          "['name', 'url', 'username', 'password', 'note'] as const",
          "['name', 'url', 'password', 'username', 'note'] as const",
        ),
    },
    // The assertion MESSAGE, never a test name: JUnit carries a
    // `<testcase name=…>` for every test that RAN, so a name-matching predicate
    // is satisfied by a fully green report — the trap recorded on `test:security`.
    evidence: (text) => /drifted from its golden/.test(text) && /chrome-csv/.test(text),
  },

  'test:fuzz': {
    // The defect this gate exists to catch: a per-item cap removed from a parser.
    // Without the break, a source file listing more than `MAX_URIS_PER_ITEM`
    // URLs for one login produces an item whose own schema rejects it — and
    // `validateImportItems` then discards the WHOLE login, password included,
    // reporting it as one skipped row. That is the exact class this suite exists
    // for: not a crash, not corruption, but an item that never arrives.
    //
    // The pattern is byte-exact against today's `buildLogin`. A rewrite of that
    // line turns `String.replace` into a no-op, which fails in the SAFE
    // direction: the gate stays green, the harness reports `unproven`, and the
    // run exits non-zero.
    title:
      'remove the per-item URI cap from buildLogin, so an over-full login fails its own schema',
    mutate: {
      'packages/client/src/services/import/itemBuilders.ts': (text) =>
        text.replace('    if (uris.length >= MAX_URIS_PER_ITEM) break;\n', ''),
    },
    // The assertion MESSAGE the contract helper prints, which only a FAILING run
    // can contain — the trap recorded on `test:security`: a JUnit report carries
    // a `<testcase name=…>` for every test that ran, so matching a name would be
    // satisfied by a fully green report. `bitwarden-overfull-lists.json` in the
    // committed corpus is what makes the property, not just the regression test,
    // reach this.
    evidence: (text) => /a parser emitted an item that fails its own schema/.test(text),
  },

  'test:a11y': {
    // The defect this gate exists to catch, planted at its source and as the
    // single edit a careless tidy-up would make: the accessible name removed
    // from the note form's format `<select>`. It still works, it still looks
    // identical, every unit test still passes — and a screen-reader user reaches
    // a combo box announced as nothing at all. axe grades it `select-name`,
    // CRITICAL. It is deliberately a control on a view only THIS gate visits (the
    // create dialog's Note tab), so a green E2E run says nothing about it.
    //
    // A REJECTED alternative, recorded because it is the obvious first choice and
    // it is INERT: stripping `aria-label` from the saved-address picker's search
    // INPUT. Measured here — the gate stayed green, because the accessible-name
    // computation falls back to the `placeholder`, so the control still has a
    // name. A `<select>` has no such fallback, which is exactly why it is the
    // honest plant.
    //
    // The pattern is byte-exact against today's source. A rewrite of that line
    // turns `String.replace` into a no-op, which fails in the SAFE direction:
    // the gate stays green, the harness reports `unproven`, and the run exits
    // non-zero — provided the evidence predicate below cannot be satisfied by a
    // green report, which is why it matches the finding rather than a view name.
    title: "strip the accessible name from the note form's format select",
    mutate: {
      'packages/client/src/components/vault/VaultItemForm.tsx': (text) =>
        text.replace('              aria-label="Note format"\n', ''),
    },
    // `a11y.json` records every scan, including the views that were clean, so a
    // predicate matching a VIEW name would be satisfied by a fully green report —
    // the trap recorded on `test:security`. Only a finding carries a rule id, and
    // only the planted defect produces this one on that view.
    evidence: (text) => /"id":\s*"select-name"/.test(text) && /item-form-note/.test(text),
  },

  'audit:bundle': {
    // The defect is planted in the ARTIFACT, for the same reason `test:smoke`
    // plants one there: this gate's subject IS the build output, and a defect in
    // the sources would only reach it through a rebuild the selftest workspace
    // does not perform.
    //
    // What it simulates is the regression the gate exists for, in the one form
    // that has a byte-stable path: `index.html` inflated past the shell budget,
    // which is what an inlined asset (a base64 font, a data-URI image, a
    // bundler's `assetsInlineLimit` raised) produces. The same code path — and
    // the same `problems` list — is what a chunk over its ceiling trips, so
    // proving one proves the mechanism. Every chunk file carries a content hash
    // in its name, so no per-chunk defect has a path that survives a rebuild.
    //
    // A REJECTED alternative, recorded because it is the obvious first choice:
    // creating an extra `assets/main-selftest.js` over the `main` budget. It
    // works today and is a lie tomorrow — it asserts that a file NOTHING imports
    // counts against a chunk budget, which is a property of this gate's file
    // walk rather than of the application, and it would keep passing if the walk
    // were narrowed to what `index.html` actually references.
    title: 'inflate the built index.html past the shell budget, as an inlined asset would',
    mutate: {
      'packages/client/dist/index.html': (text) =>
        text.replace('</body>', `<!--${'p'.repeat(16 * 1024)}--></body>`),
    },
    // The gate's own violation text. A PASSING run's report carries `problems:
    // []` and no such line, so this cannot be satisfied by a green run — the trap
    // recorded on `test:security`.
    evidence: (text) => /index\.html is [\d.]+ KiB, over its \d+ KiB budget/.test(text),
  },

  'test:resource': {
    // The exact refactor this gate was built for, and the reason it is worth its
    // minute: `collectBackupData`'s item cursor replaced by `find().lean()`.
    //
    // Nothing else in the repository notices. The endpoint returns the same 413
    // for the same oversized vault, with the same message; every backup test
    // stays green, the types are identical, the lint is clean — and the process
    // now materialises the entire collection before deciding it is too large. On
    // an account near MAX_ITEMS_PER_USER that is the difference between reading
    // tens of megabytes and reading hundreds, on an authenticated request.
    //
    // Measured on the reference machine: mongod delivers 3,320 of 10,000 items
    // with the cursor and 10,003 with this line, and peak RSS growth goes from
    // ~56 MB to ~120 MB. Either half of the scenario catches it.
    //
    // The pattern is byte-exact against today's source. A rewrite of those lines
    // turns `String.replace` into a no-op, which fails in the SAFE direction: the
    // gate stays green, the harness reports `unproven`, and the run exits
    // non-zero.
    title: 'read the whole vault before the backup size guard, instead of streaming it',
    mutate: {
      'packages/server/src/controllers/backupController.ts': (text) =>
        text.replace(
          `  const itemCursor = VaultItem.find({ userId, deletedAt: { $exists: false } })
    .select('-sourceRefId')
    .lean()
    .cursor();
  for await (const item of itemCursor) {`,
          `  const allItems = await VaultItem.find({ userId, deletedAt: { $exists: false } })
    .select('-sourceRefId')
    .lean();
  for (const item of allItems) {`,
        ),
    },
    // The assertion's own failure text, which a PASSING run cannot contain — the
    // trap recorded on `test:security`: `resource.json` lists every scenario
    // either way, so matching a scenario id would be satisfied by a fully green
    // report. This matches vitest's rendering of the delivered-documents
    // assertion, which only goes red when the vault was drained.
    evidence: (text) => /expected 100\d\d to be less than 10000/.test(text),
  },

  'test:upgrade': {
    // The defect this gate was built for, and it is a DELETION of one line:
    // `withSettingsDefaults` stops filling in a setting the current release
    // added.
    //
    // What the defect breaks: both read paths use `.lean()`, which returns raw
    // BSON with no schema defaults applied, so an account created before the
    // field existed comes back without the key. The client then arms an
    // auto-lock timer from `undefined`, every deadline comparison against `NaN`
    // is false, and the vault the user asked to lock itself never locks.
    //
    // HONESTY NOTE, because the obvious claim to make here is false: this defect
    // is NOT invisible to the rest of the suite. `packages/server/tests/user.test.ts`
    // synthesizes the same shape with `$unset` and asserts the profile fills it
    // in, so the mutation also turns `test:integration` red on every push. That
    // does not disqualify the case — the obligation is to prove THIS gate can
    // fail, attributably, and it does — but nobody should read this entry as
    // evidence that the gate is the only thing covering the behaviour. What the
    // gate adds over `user.test.ts` is the document itself: a real 0.7.0 vault
    // rather than a current one with two keys removed by hand.
    //
    // Planted in `packages/server/src`, deliberately, rather than in the shared
    // schemas: the gate's command runs vitest over the server sources directly
    // and does NOT rebuild `packages/shared/dist`, so a defect planted in the
    // shared package would never reach the code under test and would prove
    // nothing.
    //
    // The pattern is byte-exact against today's source. A rewrite of that line
    // turns `String.replace` into a no-op, which fails in the SAFE direction: the
    // gate stays green, the harness reports `unproven`, and the run exits
    // non-zero.
    title: 'stop filling in a setting the previous release’s user document does not carry',
    mutate: {
      'packages/server/src/controllers/userController.ts': (text) =>
        text.replace('    lockOnHidden: raw.lockOnHidden ?? LOCK_ON_HIDDEN_DEFAULT,\n', ''),
    },
    // The assertion's own rendered failure, which a PASSING run cannot contain —
    // the trap recorded on `test:security`: the JUnit report lists a `<testcase>`
    // for every test that ran, so matching a test NAME would be satisfied by a
    // fully green report. `boolean` rather than `number` pins it to
    // `lockOnHidden` specifically, since its sibling delay is a number.
    evidence: (text) => /expected 'undefined' to be 'boolean'/.test(text),
  },

  'test:recovery': {
    // The defect this gate was built for, and it is the DELETION OF ONE
    // ARGUMENT: the import's `insertMany` stops running in the transaction's
    // session.
    //
    // What it breaks: on a replica set every imported row is then committed the
    // instant it is written, outside the transaction that is supposed to make
    // the request atomic. A process killed between that insert and the commit —
    // an OOM kill, a container eviction, a deploy that restarted the pod — leaves
    // a PARTIAL import behind: rows the client believes were never accepted,
    // which its next attempt will insert again.
    //
    // What makes it the right case is what does NOT notice it. Measured here:
    // the whole import estate stays green (119 tests across
    // `import-operations`, `tools` and `coverage-controllers-vault-tools`),
    // because the rows still arrive, the counts still add up, the types are
    // identical and the lint is clean. `import-operations.test.ts` even says the
    // quiet part out loud — "this harness is standalone, so a mixed request would
    // leave its inserts committed" — which is exactly why it cannot see this.
    // Only a crash inside the transaction can, and only on a replica set.
    //
    // Planted in `packages/server/src`, deliberately: the gate runs vitest over
    // the server sources directly and does NOT rebuild `packages/shared/dist`,
    // so a defect planted in the shared package would never reach the code under
    // test.
    //
    // The pattern is byte-exact against today's source. A rewrite of that line
    // turns `String.replace` into a no-op, which fails in the SAFE direction: the
    // gate stays green, the harness reports `unproven`, and the run exits
    // non-zero — provided the evidence predicate below cannot be satisfied by a
    // green report, which is why it matches the ASSERTION MESSAGE.
    title:
      'take the import’s insert out of its transaction, so a crash can leave half of it behind',
    mutate: {
      'packages/server/src/controllers/toolsController.ts': (text) =>
        text.replace(
          'const created = await VaultItem.insertMany(insertDocs, sessionOpt);',
          'const created = await VaultItem.insertMany(insertDocs);',
        ),
    },
    // The assertion's own message, which a PASSING run cannot contain — the trap
    // recorded on `test:security`: the JUnit report lists a `<testcase>` for
    // every test that ran, so matching a test NAME would be satisfied by a fully
    // green report. Only a surviving row produces this line.
    evidence: (text) =>
      /a crash inside the import transaction left \d+ item\(s\) behind/.test(text),
  },

  'test:smoke': {
    // The defect is planted in the ARTIFACT, not in the sources, and that is the
    // point of this gate: `test:smoke` runs the emitted bundle, so the emitted
    // bundle is what a case for it has to break. (The selftest workspace carries
    // the built `dist` trees for exactly this reason — see prepareWorkspace.)
    //
    // An index.html with no script tag is a real build failure, not a contrived
    // one: it is what a mis-configured bundler emits, it type-checks, it lints,
    // every unit test passes, the container image builds and Trivy is happy —
    // and every user gets a blank page. Only something that fetches a rendered
    // document from the running artifact can see it.
    title: 'ship an index.html with no script tag, so the built SPA never loads',
    create: {
      'packages/client/dist/index.html':
        '<!doctype html>\n<html lang="en">\n  <head><title>H-Vault</title></head>\n  <body><div id="root"></div></body>\n</html>\n',
    },
    // The assertion's own message, which a PASSING run cannot contain — the trap
    // recorded on `test:security`: matching a step's NAME would be satisfied by a
    // fully green report, since every step is listed either way.
    evidence: (text) => /script nonce=false/.test(text),
  },

  'test:deploy': {
    requires: ['docker'],
    // The single most dangerous edit anyone can make to this deployment, and it
    // is a DELETION of ten characters: the host binding in front of the one
    // published port. A port published without `127.0.0.1:` is reachable from
    // the entire network even behind an active `ufw deny`, because Docker's
    // iptables DOCKER chain is evaluated before INPUT — so the stack goes from
    // "loopback only, TLS terminated by the host's Nginx" to "a password
    // manager's API on the open internet, in cleartext", while every container
    // stays healthy and every request keeps working.
    //
    // A REJECTED alternative, recorded because it is the first thing a reader
    // will reach for: adding `ports: ["127.0.0.1:27017:27017"]` to the database
    // service. It looks like the perfect defect and it is inert — measured here,
    // twice. `docker compose config` renders the mapping, but the service is
    // attached only to the `internal: true` data network, and Docker publishes
    // nothing for such a container: the drill's own probe still finds 27017
    // refused, and `docker compose ps` reports no publisher at all. That is a
    // real defence-in-depth property of this stack rather than a gap in the
    // gate, and it is worth knowing before someone "fixes" the drill to catch a
    // defect that cannot happen.
    //
    // The anchor is byte-exact against today's compose file. A rewrite of that
    // line turns `String.replace` into a no-op, which fails in the SAFE
    // direction: the gate stays green, the harness reports `unproven`, and the
    // run exits non-zero.
    title: 'publish the one host port on every interface instead of on loopback',
    mutate: {
      'docker-compose.yml': (text) =>
        text.replace(
          "- '127.0.0.1:${HVAULT_HTTP_PORT:-8080}:8080'",
          "- '${HVAULT_HTTP_PORT:-8080}:8080'",
        ),
    },
    // The assertion's own message, which only a FAILING run can contain: a green
    // drill records "only 127.0.0.1:18080 is published", and every step is named
    // in the report either way — so matching a step's NAME would be satisfied by
    // a fully green run (the trap recorded on `test:security`).
    evidence: (text) => /not bound to loopback/.test(text),
  },

  'test:mutation': {
    // The Forbidden Action this gate is most likely to attract, planted exactly
    // as someone would write it: an extra `!` pattern in the declared scope.
    // Nothing else in the repository notices. The percentage goes UP (the
    // excluded files were the ones with survivors), the run gets faster, the
    // config diff reads like a tidy-up, and the gate reports a better number
    // over less code — which is the whole reason `mutation.filesMutated` is
    // ratcheted as a superset rather than the globs being ratcheted as a list.
    //
    // It fails in the gate's PRE-FLIGHT, before Stryker starts, which is what
    // makes this case runnable at all: a full run is hours, and a selftest that
    // took hours per case is a selftest nobody runs. `timeoutMs` is the backstop
    // for the other direction — if the anchor below ever drifts and the replace
    // becomes a no-op, the case is killed and reported `unproven` rather than
    // mutating the whole codebase while the harness waits.
    title: 'exclude the client import services from the declared mutation scope',
    mutate: {
      'scripts/ci/lib/mutation-scope.mjs': (text) =>
        text.replace(
          '      PRESENTATIONAL_EXCLUDE,\n',
          "      PRESENTATIONAL_EXCLUDE,\n      '!packages/client/src/services/import/**',\n",
        ),
    },
    timeoutMs: 120_000,
    // The pre-flight's own message. A green run says nothing of the kind, and
    // the file list it prints names the excluded directory.
    evidence: (text) => /scope narrowed/.test(text),
  },

  'audit:deps': {
    // Planting a KNOWN-vulnerable production dependency, rather than relying on
    // whatever advisories happen to be open, is what makes the evidence check
    // meaningful: the gate must fail naming THIS package.
    title: 'add a production dependency with a known advisory (lodash 4.17.11)',
    mutate: {
      'packages/server/package.json': (text) => {
        const pkg = JSON.parse(text);
        pkg.dependencies = { ...pkg.dependencies, lodash: '4.17.11' };
        return `${JSON.stringify(pkg, null, 2)}\n`;
      },
      'package-lock.json': (text) => {
        const lock = JSON.parse(text);
        const server = lock.packages?.['packages/server'];
        if (server) server.dependencies = { ...server.dependencies, lodash: '4.17.11' };
        lock.packages['node_modules/lodash'] = {
          version: '4.17.11',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz',
          license: 'MIT',
        };
        return `${JSON.stringify(lock, null, 2)}\n`;
      },
    },
    evidence: (text) => /lodash/.test(text),
  },

  'test:e2e': {
    title: 'add an end-to-end spec that asserts a page title the app never renders',
    create: {
      'e2e/__selftest_probe.spec.ts':
        "import { test, expect } from '@playwright/test';\n\n" +
        "test('selftest probe fails on purpose', async ({ page }) => {\n" +
        "  await page.goto('/');\n" +
        "  await expect(page).toHaveTitle('a title this application never renders');\n" +
        '});\n',
    },
    evidence: (text) => /selftest probe/.test(text),
  },

  'audit:image': {
    requires: ['docker'],
    // The defect has to land in the IMAGE BUILD, which is the first thing this
    // gate does, rather than in the Nginx config it checks afterwards: the gate
    // is red at HEAD on `nginx -t` (a config file copied without `--chmod`,
    // which Phase 3 Task 3.2 fixes), so a defect downstream of that check is
    // never reached and nothing could attribute the failure to it.
    title: 'break the app image build, so the first thing the gate does cannot succeed',
    mutate: {
      'docker/Dockerfile': (text) =>
        text.replace(
          /^FROM base AS app$/m,
          'FROM base AS app\nRUN echo selftest-probe-defect && exit 1',
        ),
    },
    evidence: (text) => /selftest-probe-defect/.test(text),
  },

  'audit:sast': {
    requires: ['codeql'],
    title: 'add a server module that concatenates a request value into a shell command',
    create: {
      'packages/server/src/__selftest_probe.ts':
        "import { execSync } from 'node:child_process';\n\n" +
        'export const probe = (input: string): string =>\n' +
        '  execSync(`echo ${input}`).toString();\n',
    },
    evidence: (text) => /__selftest_probe/.test(text),
  },
};
