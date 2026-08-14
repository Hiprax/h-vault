#!/usr/bin/env node
/**
 * Secret scanner — the single source of truth for both git hooks and both gates.
 *
 *   pre-commit:   secret-scan.mjs --staged           the bytes this commit will contain
 *   audit:secrets (T0): secret-scan.mjs --report     every tracked AND untracked-not-ignored file
 *   audit:secrets:full (T1): --all --history --report  the above, plus every blob in git history
 *
 * The three modes share one pattern list, so they can never drift apart, and they
 * answer three different questions.
 *
 * The working-tree pass is the one a staged-only scan cannot replace: a secret
 * that slipped in before the hook existed, or that was committed with the hook
 * bypassed (see "Escape hatches" in CONTRIBUTING.md), is invisible to it forever
 * after — and so is every file that has not been staged yet, which is why the
 * enumeration includes untracked-not-ignored files rather than the index alone.
 *
 * The history pass answers a question with a different remedy. A secret in
 * history is ALREADY COMPROMISED: it is in every clone and every fork, and no
 * later commit takes it back. Rotate the credential; a history rewrite is
 * optional cleanup afterwards, never the fix.
 *
 * Ignored files are never read, so an untracked `.env` holding real credentials
 * is not a finding — it is the intended way to hold them.
 *
 * A line ending in `secret-scan:allow` is skipped, for the rare true negative.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, repoRoot } from './lib/proc.mjs';
import { writeJsonReport } from './lib/reports.mjs';
import { color, symbol } from './lib/ui.mjs';

const MAX_FILE_BYTES = 1024 * 1024;
const ALLOW_MARKER = 'secret-scan:allow';

/**
 * High-signal patterns first: a provider-shaped credential is a finding on its
 * own. The generic assignment rule is last and deliberately the narrowest one —
 * it is the rule that produces false positives, so it demands a quoted value of
 * real length and rejects anything that looks like a placeholder.
 */
const RULES = [
  { id: 'private-key', re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret', re: /\baws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/i },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  // Fine-grained PATs are a separate prefix from the classic gh*_ tokens above.
  { id: 'github-fine-grained-pat', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  // Both Stripe live secret prefixes: `sk_live_` (secret) and `rk_live_` (restricted).
  { id: 'stripe-live-key', re: /\b[sr]k_live_[0-9a-zA-Z]{16,}\b/ },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  {
    id: 'hardcoded-credential',
    // The key list is deliberately NOT just "secret". This is a secret manager:
    // `secret` is one of its five vault item types, so `secret: 'bg-red-100 ...'`
    // in a Tailwind class map is ordinary domain code. A rule that fires on the
    // bare word is a rule that gets switched off within a week — so only
    // unambiguous credential identifiers qualify.
    re: /\b(?:password|passwd|client[_-]?secret|secret[_-]?key|private[_-]?key|api[_-]?key|access[_-]?token|auth[_-]?token|jwt[_-]?secret|session[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/i,
    isSpurious: (value) =>
      // Config templates, fixtures and docs describe credentials; they do not carry them.
      /^(?:\$|<|\{|%|\.\.\.)|(?:change[_-]?me|your[_-]|example|placeholder|dummy|sample|redacted|xxx+|\*{3,}|test|dev-|fake|noop|none|null|undefined)/i.test(
        value,
      ) ||
      // No credential contains a space. A phrase does — CSS class lists, prose,
      // and template copy all land here.
      /\s/.test(value),
  },
];

/**
 * Paths whose whole job is to contain credential-shaped strings. Each entry is
 * a liability, so each one is here because the alternative is a scanner nobody
 * can leave switched on.
 */
const EXCLUDED = [
  /(^|\/)\.env\.example$/,
  /(^|\/)tests?\//,
  /(^|\/)__tests__\//,
  /(^|\/)e2e\//, // Playwright fixtures register accounts with literal passwords.
  /\.test\.(?:ts|tsx|js|mjs|cjs)$/,
  /\.spec\.(?:ts|tsx|js|mjs|cjs)$/,
  /(^|\/)README\.md$/,
  /(^|\/)CONTRIBUTING\.md$/,
  /(^|\/)SECURITY\.md$/,
  /(^|\/)docker\/nginx\/.*\.example\.conf$/,
  /(^|\/)package-lock\.json$/,
  /(^|\/)scripts\/ci\/secret-scan\.mjs$/, // Contains the patterns themselves.
  /(^|\/)\.husky\//,
];

const isExcluded = (file) => EXCLUDED.some((pattern) => pattern.test(file));

/** A file with a NUL byte in its head is binary; regexing it is meaningless. */
function isBinary(buffer) {
  return buffer.subarray(0, 8192).includes(0);
}

const staged = process.argv.includes('--staged');
// `--history` adds every blob in every reachable commit. `--all` is accepted as
// its companion and is what the whole-tree scan is already doing, so it changes
// nothing on its own; both are spelled out in the T1 command because the pair is
// what a reader expects "the full scan" to say.
const withHistory = process.argv.includes('--history');
// `--report` writes the findings to `.testfortress/reports/` as well as printing
// them: `secrets.json` for the working-tree scan, `secrets-full.json` when
// history is included. Two names on purpose — one report shared by two
// registered tasks means the second run silently overwrites the first's
// evidence. The pre-commit hook passes neither, since a hook run is about one
// commit rather than about the tree's recorded state.
const writeReport = process.argv.includes('--report');

function filesToScan() {
  // Untracked-but-not-ignored files are IN, and that is the whole point of the
  // `--others --exclude-standard` pair: a scan of the index alone is blind to
  // every file that has not been staged yet, which on this project is most new
  // work (nothing here is staged until a commit is actually being made). The
  // same enumeration backs the integrity scanner, for the same reason. Ignored
  // files stay out, so an untracked `.env` holding real credentials is still not
  // a finding — that is the intended way to hold them.
  const args = staged
    ? ['diff', '--cached', '--name-only', '--diff-filter=ACM']
    : ['ls-files', '--cached', '--others', '--exclude-standard'];

  const result = captureExe('git', args);
  if (!result.ok) {
    console.error(`${symbol.fail} secret-scan: git ${args.join(' ')} failed`);
    process.exit(1);
  }
  return [
    ...new Set(
      result.stdout
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  ].filter((file) => !isExcluded(file));
}

/**
 * Every blob in every reachable commit, as `{ oid, file, content }`.
 *
 * A secret that reached history is ALREADY COMPROMISED: it is in every clone and
 * every fork, and deleting the file in a later commit removes nothing. The
 * remedy is rotation — revoke the credential — and only then, optionally, a
 * history rewrite. That is why this is a separate, slower task rather than
 * something the fast gate does: its finding asks for a different action.
 *
 * Objects are read in ONE `git cat-file --batch` pass with a Buffer pipe. A
 * per-object `git show` would be thousands of processes, and a utf8 pipe would
 * corrupt binary blobs before `isBinary` ever got to reject them.
 */
function historyBlobs() {
  const listed = spawnSync('git', ['rev-list', '--objects', '--all'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
  });
  // A GIT FAILURE IS A FAILURE, NOT AN EMPTY HISTORY. Returning `[]` here would
  // print "no secrets found" over a scan that never happened — a killed child
  // (maxBuffer), a corrupt pack, a broken git. The genuinely-empty case needs no
  // special handling: `git rev-list --objects --all` exits 0 with empty output
  // in a repository with no commits (verified), and the `wanted.size === 0`
  // return below covers it.
  if (listed.status !== 0) {
    console.error(
      `${symbol.fail} secret-scan: git rev-list failed (status ${String(listed.status)}) — ` +
        `history was NOT scanned: ${String(listed.stderr ?? listed.error?.message ?? '').slice(0, 300)}`,
    );
    process.exit(1);
  }

  /** oid -> the first non-excluded path it was ever stored at. */
  const wanted = new Map();
  for (const line of listed.stdout.split('\n')) {
    const separator = line.indexOf(' ');
    if (separator < 0) continue; // a commit or tag object: no path, no content to scan
    const oid = line.slice(0, separator);
    const file = line.slice(separator + 1).trim();
    if (!file || isExcluded(file) || wanted.has(oid)) continue;
    wanted.set(oid, file);
  }
  if (wanted.size === 0) return [];

  const batch = spawnSync('git', ['cat-file', '--batch'], {
    cwd: repoRoot,
    input: `${[...wanted.keys()].join('\n')}\n`,
    maxBuffer: 1024 * 1024 * 1024,
  });
  // Same rule as above, and this is the likelier of the two to trip: exceeding
  // `maxBuffer` kills the child with `status === null`, which is not 0 and is
  // certainly not "the history is clean".
  if (batch.status !== 0 || !batch.stdout) {
    console.error(
      `${symbol.fail} secret-scan: git cat-file --batch failed (status ${String(batch.status)}) over ` +
        `${String(wanted.size)} object(s) — history was NOT scanned: ` +
        `${String(batch.stderr ?? batch.error?.message ?? '').slice(0, 300)}`,
    );
    process.exit(1);
  }

  const out = [];
  const buffer = batch.stdout;
  let position = 0;
  while (position < buffer.length) {
    const newline = buffer.indexOf(0x0a, position);
    if (newline < 0) break;
    const [oid, type, size] = buffer.subarray(position, newline).toString('utf8').split(' ');
    if (type !== 'blob') {
      // `<oid> missing` has no payload; a tree does, and is not scannable text.
      position = size === undefined ? newline + 1 : newline + 1 + Number(size) + 1;
      continue;
    }
    const start = newline + 1;
    const end = start + Number(size);
    out.push({ oid, file: wanted.get(oid), content: buffer.subarray(start, end) });
    position = end + 1;
  }
  return out;
}

/**
 * Reads what will actually be scanned.
 *
 * In --staged mode this is the STAGED blob (`git show :path`), not the file on
 * disk. With partial staging (`git add -p`) the two differ, and reading the
 * working tree would both miss a secret that was staged then edited out, and
 * falsely flag one that exists only in the unstaged remainder — the hook must
 * judge exactly the bytes the commit will contain.
 */
function readContent(file) {
  if (staged) {
    const result = captureExe('git', ['show', `:${file}`]);
    return result.ok ? Buffer.from(result.stdout, 'utf8') : null;
  }
  try {
    // Read first, measure after — a stat-then-read pair is a time-of-check /
    // time-of-use race, and the file can also simply vanish between the two
    // (a rebase, a rebuild). Neither is a finding; both are just "skip it".
    return readFileSync(path.join(repoRoot, file));
  } catch {
    return null;
  }
}

const findings = [];

/** Scans one blob's text, appending any finding with the origin the caller names. */
function scanBuffer(buffer, origin) {
  if (buffer.length > MAX_FILE_BYTES || isBinary(buffer)) return;

  const lines = buffer.toString('utf8').split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.includes(ALLOW_MARKER)) return;

    for (const rule of RULES) {
      const match = rule.re.exec(line);
      if (!match) continue;
      if (rule.isSpurious?.(match[1] ?? '')) continue;

      findings.push({
        ...origin,
        line: index + 1,
        rule: rule.id,
        // Never echo the secret back: the scanner's own output would become the
        // next place it leaks (a CI log, a scrollback buffer, a pasted issue).
        excerpt: line.trim().slice(0, 60).replace(/\s+/g, ' '),
      });
      return;
    }
  });
}

/**
 * The DENOMINATOR, recorded and floored.
 *
 * A finding count is meaningless without it: one over-broad `EXCLUDED` pattern,
 * or a `git ls-files` that returns nothing, and the gate is green having read no
 * bytes at all. Zero scanned files is therefore a failure, and both counts go
 * into the report so a later run can be compared with this one.
 */
let filesScanned = 0;
let bytesScanned = 0;

for (const file of filesToScan()) {
  const buffer = readContent(file);
  if (!buffer) continue;
  filesScanned++;
  bytesScanned += buffer.length;
  scanBuffer(buffer, { file, where: 'working-tree' });
}

if (filesScanned === 0) {
  console.error(
    `${symbol.fail} secret-scan: 0 files scanned — the enumeration or the exclusion list is broken, ` +
      'and a scan of nothing finds nothing',
  );
  process.exit(1);
}

let blobsScanned = 0;
if (withHistory) {
  for (const blob of historyBlobs()) {
    blobsScanned++;
    scanBuffer(blob.content, { file: blob.file, where: 'history', object: blob.oid });
  }
}

/** The commits a historical blob is reachable from, so rotation has a date to work with. */
function commitsHolding(oid) {
  const result = captureExe('git', [
    'log',
    '--all',
    '--format=%h %ad',
    '--date=short',
    `--find-object=${oid}`,
  ]);
  return result.ok ? result.stdout.trim().split('\n').filter(Boolean).slice(0, 5) : [];
}

for (const finding of findings) {
  if (finding.where === 'history') finding.commits = commitsHolding(finding.object);
}

if (writeReport) {
  writeJsonReport(withHistory ? 'secrets-full.json' : 'secrets.json', {
    scannedAt: new Date().toISOString(),
    mode: staged ? 'staged' : withHistory ? 'tree+history' : 'tree',
    // What was actually read. "0 findings" over 0 files is not a clean tree.
    filesScanned,
    bytesScanned,
    blobsScanned: withHistory ? blobsScanned : undefined,
    rules: RULES.map((rule) => rule.id),
    findings,
  });
}

if (findings.length > 0) {
  console.error(color.red(`\n${symbol.fail} Possible secrets detected:\n`));
  for (const finding of findings) {
    const where =
      finding.where === 'history' ? ` ${color.gray(`(history ${finding.object})`)}` : '';
    console.error(
      `  ${color.cyan(`${finding.file}:${String(finding.line)}`)}  ${color.yellow(`[${finding.rule}]`)}${where}`,
    );
    console.error(`    ${color.gray(finding.excerpt)}`);
    for (const commit of finding.commits ?? []) console.error(`      ${color.gray(commit)}`);
  }
  console.error(
    color.gray(
      `\n  Remove the secret, or append "${ALLOW_MARKER}" to the line if it is genuinely not one.`,
    ),
  );
  if (findings.some((finding) => finding.where === 'history')) {
    console.error(
      color.gray(
        '  A finding in HISTORY is already compromised: it is in every clone and every fork, and\n' +
          '  no later commit takes it back. ROTATE the credential first; rewriting history is\n' +
          '  optional cleanup afterwards, never the fix.\n',
      ),
    );
  }
  process.exit(1);
}

console.log(
  color.green(
    `${symbol.pass} secret-scan: no secrets in ${String(filesScanned)} file(s)` +
      (withHistory ? ` + ${String(blobsScanned)} historical blob(s)` : ''),
  ),
);
