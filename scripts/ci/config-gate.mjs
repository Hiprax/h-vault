#!/usr/bin/env node
/**
 * `audit:config` — the three configuration languages this repository ships that
 * no compiler, linter or test ever reads:
 *
 *   actionlint  .github/workflows/*.yml   the release workflow, expressions included
 *   hadolint    docker/Dockerfile, docker/mongo.Dockerfile
 *   spectral    the OpenAPI 3.0.3 document packages/server/src/config/swagger.ts builds
 *
 *   node scripts/ci/config-gate.mjs           check, write config.sarif
 *   node scripts/ci/config-gate.mjs --json    the summary on stdout as well
 *
 * Exit codes: 0 = no error-level finding · 1 = at least one · 2 = could not run
 * (a linter is not installed, or the OpenAPI document could not be produced).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE OPENAPI DOCUMENT IS GENERATED FROM SOURCE, NOT READ FROM A FILE. There
 *     is no checked-in spec to lint: `swaggerSpec` is a TypeScript object literal,
 *     and it is what the server serves. Linting anything else would be linting a
 *     copy that can drift. It is evaluated with `tsx`, so this gate needs
 *     `@hvault/shared` built (APP_VERSION) and nothing else.
 *
 *  b. A MISSING LINTER IS "COULD NOT RUN", NEVER A SKIP. Exit 78 is this
 *     pipeline's SKIPPED sentinel and it is honoured from ONE gate (`sast`). A
 *     configuration gate that quietly passed because the binary was absent would
 *     be indistinguishable from one that checked and found nothing.
 *
 *  c. THE VERDICT IS ERROR-LEVEL FINDINGS ONLY, AND THE REST ARE COUNTED. Every
 *     warning is written into config.sarif and totalled into
 *     `warnings.audit:config`, which .testfortress/baseline.json pins and the
 *     ratchet only ever lets fall. That is deliberately not the same as ignoring
 *     them: an ignored warning can be added to freely, a ratcheted one cannot.
 *
 *  d. EVERY TOOL MUST PRODUCE PARSEABLE OUTPUT OR THE GATE FAILS. A linter that
 *     exits non-zero with output nothing can parse is a broken gate, not a clean
 *     one, so an unparseable payload is reported as an error-level finding
 *     against the tool itself rather than being swallowed.
 */
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { captureExe, captureNpm, repoRoot } from './lib/proc.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';
import { color, symbol } from './lib/ui.mjs';

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_CANNOT_RUN = 2;

const asJson = process.argv.includes('--json');
/** Reads a package's own manifest, which is how the tool versions are reported. */
const require = createRequire(import.meta.url);

const fatal = (message) => {
  console.error(color.red(`${symbol.fail} config-gate: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

/** @type {{tool: string, ruleId: string, level: 'error'|'warning'|'note', message: string, file: string, line: number, column?: number}[]} */
const findings = [];
const toolVersions = {};
/** How many files each leg actually examined. A leg that examined none is a failure. */
const inputsExamined = {};

const relative = (file) =>
  path.relative(repoRoot, path.resolve(repoRoot, file)).split(path.sep).join('/');

/**
 * Records an error-level finding against a TOOL rather than against the code.
 *
 * The case this exists for (decision d): a linter that exits non-zero having
 * written nothing a parser can use. `JSON.parse(stdout || '[]')` alone turns
 * that into "zero findings" — a crashed spectral, an actionlint rejecting a flag
 * it no longer knows, a hadolint that could not open a file — every one of them
 * reading as a clean tree. Exit status and parseability are therefore judged
 * together, and the doubt is reported as an error.
 */
function toolFailed(tool, file, run, detail) {
  findings.push({
    tool,
    ruleId: `${tool}-output`,
    level: 'error',
    message:
      `${tool} ${detail} (exit ${String(run.status)}): ` +
      `${(run.stderr || run.stdout || '').trim().slice(0, 300)}`,
    file,
    line: 1,
  });
}

// ---------------------------------------------------------------------------
// actionlint — the workflow files
// ---------------------------------------------------------------------------
{
  const version = captureExe('actionlint', ['-version']);
  if (!version.ok) {
    fatal('actionlint is not on PATH — install it (https://github.com/rhysd/actionlint/releases)');
  }
  toolVersions.actionlint = version.stdout.trim().split('\n')[0] ?? 'unknown';

  // The workflow files are passed EXPLICITLY, and counted. Left to discover them
  // itself, actionlint exits 0 over an empty directory — so deleting the one
  // workflow this leg exists to check would read as a clean run.
  const workflowDir = path.join(repoRoot, '.github', 'workflows');
  const workflows = existsSync(workflowDir)
    ? readdirSync(workflowDir)
        .filter((name) => /\.ya?ml$/.test(name))
        .map((name) => `.github/workflows/${name}`)
        .sort()
    : [];
  inputsExamined.actionlint = workflows.length;
  if (workflows.length === 0) {
    fatal(
      'no workflow files found under .github/workflows — this repository has one (release.yml) ' +
        'and a run that lints nothing is not a clean run',
    );
  }

  // `{{json .}}` is actionlint's documented machine-readable template.
  const run = captureExe('actionlint', ['-format', '{{json .}}', '-no-color', ...workflows]);
  let errors;
  try {
    errors = JSON.parse(run.stdout.trim() || '[]');
  } catch {
    toolFailed('actionlint', '.github/workflows', run, 'produced output this gate cannot parse');
    errors = [];
  }
  // Exit 1 means "found problems" and is expected; anything else (2 = bad
  // option, 3 = fatal) with no findings to show for it is a broken run.
  if (run.status !== 0 && run.status !== 1 && errors.length === 0) {
    toolFailed('actionlint', '.github/workflows', run, 'exited abnormally with no findings');
  }
  for (const error of errors) {
    // actionlint reports only real problems; every one of them is an error.
    findings.push({
      tool: 'actionlint',
      ruleId: `actionlint/${String(error.kind ?? 'unknown')}`,
      level: 'error',
      message: String(error.message ?? ''),
      file: relative(String(error.filepath ?? '.github/workflows')),
      line: Number(error.line ?? 1),
      column: Number(error.column ?? 1),
    });
  }
}

// ---------------------------------------------------------------------------
// hadolint — both Dockerfiles
// ---------------------------------------------------------------------------
{
  const version = captureExe('hadolint', ['--version']);
  if (!version.ok) {
    fatal('hadolint is not on PATH — install it (https://github.com/hadolint/hadolint/releases)');
  }
  toolVersions.hadolint = version.stdout.trim();

  const dockerfiles = ['docker/Dockerfile', 'docker/mongo.Dockerfile'];
  for (const file of dockerfiles) {
    if (!existsSync(path.join(repoRoot, file))) fatal(`${file} is missing`);
  }
  inputsExamined.hadolint = dockerfiles.length;

  const run = captureExe('hadolint', ['--no-color', '--format', 'json', ...dockerfiles]);
  let results;
  try {
    results = JSON.parse(run.stdout.trim() || '[]');
  } catch {
    toolFailed('hadolint', dockerfiles[0], run, 'produced output this gate cannot parse');
    results = [];
  }
  // hadolint exits 1 when it has findings; any other non-zero code with nothing
  // to show is a run that did not happen.
  if (run.status !== 0 && run.status !== 1 && results.length === 0) {
    toolFailed('hadolint', dockerfiles[0], run, 'exited abnormally with no findings');
  }
  /** hadolint's four levels; `style`/`info` are advisory, `warning` is a smell, `error` is a defect. */
  const LEVELS = { error: 'error', warning: 'warning', info: 'note', style: 'note' };
  for (const result of results) {
    findings.push({
      tool: 'hadolint',
      ruleId: `hadolint/${String(result.code ?? 'unknown')}`,
      level: LEVELS[String(result.level)] ?? 'error',
      message: String(result.message ?? ''),
      file: relative(String(result.file ?? dockerfiles[0])),
      line: Number(result.line ?? 1),
      column: Number(result.column ?? 1),
    });
  }
}

// ---------------------------------------------------------------------------
// spectral — the OpenAPI document (a) built from source
// ---------------------------------------------------------------------------
{
  let spectralManifest;
  try {
    spectralManifest = require('@stoplight/spectral-cli/package.json');
  } catch {
    fatal('@stoplight/spectral-cli is not installed (npm install)');
  }
  toolVersions.spectral = `spectral ${spectralManifest.version}`;

  // `node --import tsx`, never `npx`: npx is a `.cmd` shim on Windows and Node
  // refuses to spawn one without a shell, which would make this gate report
  // "could not build the OpenAPI document" on a platform where nothing is wrong.
  const emitted = captureExe(process.execPath, ['--import', 'tsx', 'scripts/ci/emit-openapi.mjs']);
  if (!emitted.ok || !emitted.stdout.trim().startsWith('{')) {
    fatal(
      'could not build the OpenAPI document from packages/server/src/config/swagger.ts ' +
        `(is @hvault/shared built?): ${emitted.stderr.trim().slice(0, 300)}`,
    );
  }
  ensureReportDir();
  writeFileSync(reportPath('openapi.json'), `${emitted.stdout.trim()}\n`, 'utf8');
  inputsExamined.spectral = 1;

  // Through the npm script rather than the binary: see `captureNpm`. The script
  // is `audit:config:openapi`, and it lints exactly the file just written.
  const run = captureNpm(['run', '--silent', 'audit:config:openapi']);
  let results;
  try {
    results = JSON.parse(run.stdout.trim() || '[]');
  } catch {
    // `--quiet` on the npm script is what keeps this from firing on a CLEAN
    // document: without it spectral appends "No results with a severity of
    // 'error' found!" to the JSON array, so the gate would turn red the day the
    // OpenAPI debt is finally paid down. Verified against the vendored CLI.
    toolFailed(
      'spectral',
      'packages/server/src/config/swagger.ts',
      run,
      'produced output this gate cannot parse',
    );
    results = [];
  }
  // Spectral exits 1 when it has results at or above --fail-severity; 2 is a
  // crash (bad ruleset, unreadable document) and writes to stderr, so a 2 with
  // no results is a document that was never linted.
  if (run.status !== 0 && run.status !== 1 && results.length === 0) {
    toolFailed(
      'spectral',
      'packages/server/src/config/swagger.ts',
      run,
      'exited abnormally with no findings',
    );
  }
  /** Spectral severities: 0 error, 1 warn, 2 info, 3 hint. */
  const LEVELS = ['error', 'warning', 'note', 'note'];
  for (const result of results) {
    findings.push({
      tool: 'spectral',
      ruleId: `spectral/${String(result.code ?? 'unknown')}`,
      level: LEVELS[Number(result.severity)] ?? 'error',
      // The path inside the document locates the finding far better than a line
      // number in a file that is regenerated on every run.
      message: `${String(result.message ?? '')} (at ${(result.path ?? []).join('.') || 'document root'})`,
      file: 'packages/server/src/config/swagger.ts',
      line: Number(result.range?.start?.line ?? 0) + 1,
      column: Number(result.range?.start?.character ?? 0) + 1,
    });
  }
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------
const counts = {
  error: findings.filter((f) => f.level === 'error').length,
  warning: findings.filter((f) => f.level === 'warning').length,
  note: findings.filter((f) => f.level === 'note').length,
};

/**
 * Below-error findings PER TOOL, which is what the baseline ratchets.
 *
 * One scalar over three tools would let a hadolint regression hide behind a
 * spectral improvement, and every one of these is lower-is-better, so they are
 * recorded separately. `note` is counted alongside `warning`: a severity level
 * that is neither failed nor ratcheted is a level anyone can add to for free.
 */
const belowError = {};
for (const tool of Object.keys(toolVersions)) {
  belowError[tool] = findings.filter((f) => f.tool === tool && f.level !== 'error').length;
}

const rules = [];
const ruleIndex = new Map();
for (const finding of findings) {
  if (ruleIndex.has(finding.ruleId)) continue;
  ruleIndex.set(finding.ruleId, rules.length);
  rules.push({ id: finding.ruleId, properties: { tool: finding.tool } });
}

const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'audit:config',
          informationUri: 'https://github.com/Hiprax/h-vault',
          properties: { tools: toolVersions, counts, belowError, inputsExamined },
          rules,
        },
      },
      results: findings.map((finding) => ({
        ruleId: finding.ruleId,
        ruleIndex: ruleIndex.get(finding.ruleId),
        level: finding.level,
        message: { text: finding.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: finding.file, uriBaseId: '%SRCROOT%' },
              region: {
                startLine: Math.max(1, finding.line),
                ...(finding.column ? { startColumn: Math.max(1, finding.column) } : {}),
              },
            },
          },
        ],
      })),
    },
  ],
};

writeJsonReport('config.sarif', sarif);
if (asJson) {
  process.stdout.write(`${JSON.stringify({ counts, tools: toolVersions, findings }, null, 2)}\n`);
}

for (const finding of findings.filter((f) => f.level === 'error')) {
  console.error(
    `  ${color.cyan(`${finding.file}:${String(finding.line)}`)}  ` +
      `${color.yellow(`[${finding.ruleId}]`)} ${finding.message}`,
  );
}

if (counts.error > 0) {
  console.error(
    color.red(
      `\n${symbol.fail} audit:config: ${String(counts.error)} error-level finding(s) ` +
        `(${String(counts.warning)} warning, ${String(counts.note)} note)\n`,
    ),
  );
  process.exit(EXIT_FINDINGS);
}

console.log(
  color.green(
    `${symbol.pass} audit:config: 0 errors ` +
      `(${String(counts.warning)} warning, ${String(counts.note)} note) across ` +
      `actionlint, hadolint and spectral`,
  ),
);
process.exit(EXIT_OK);
