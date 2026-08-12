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
