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
