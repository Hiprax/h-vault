#!/usr/bin/env node
/**
 * Secret scanner — the single source of truth for both git hooks.
 *
 *   pre-commit:  node scripts/ci/secret-scan.mjs --staged   (what you are about to commit)
 *   pipeline:    node scripts/ci/secret-scan.mjs            (every tracked file in the repo)
 *
 * The repo-wide pass is the one that matters: a secret that slipped in before
 * the hook existed, or that was committed with --no-verify, is invisible to a
 * staged-only scan forever after. Both modes share one pattern list so they can
 * never drift apart.
 *
 * Only git-tracked files are read. An untracked `.env` holding real credentials
 * is not a finding — it is the intended way to hold them.
 *
 * A line ending in `secret-scan:allow` is skipped, for the rare true negative.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, repoRoot } from './lib/proc.mjs';
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

function filesToScan() {
  const args = staged
    ? ['diff', '--cached', '--name-only', '--diff-filter=ACM']
    : ['ls-files', '--cached'];

  const result = captureExe('git', args);
  if (!result.ok) {
    console.error(`${symbol.fail} secret-scan: git ${args.join(' ')} failed`);
    process.exit(1);
  }
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((file) => !isExcluded(file));
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

for (const file of filesToScan()) {
  const buffer = readContent(file);
  if (!buffer) continue;
  if (buffer.length > MAX_FILE_BYTES || isBinary(buffer)) continue;

  const lines = buffer.toString('utf8').split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.includes(ALLOW_MARKER)) return;

    for (const rule of RULES) {
      const match = rule.re.exec(line);
      if (!match) continue;
      if (rule.isSpurious?.(match[1] ?? '')) continue;

      findings.push({
        file,
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

if (findings.length > 0) {
  console.error(color.red(`\n${symbol.fail} Possible secrets detected:\n`));
  for (const finding of findings) {
    console.error(
      `  ${color.cyan(`${finding.file}:${String(finding.line)}`)}  ${color.yellow(`[${finding.rule}]`)}`,
    );
    console.error(`    ${color.gray(finding.excerpt)}`);
  }
  console.error(
    color.gray(
      `\n  Remove the secret, or append "${ALLOW_MARKER}" to the line if it is genuinely not one.\n`,
    ),
  );
  process.exit(1);
}

console.log(color.green(`${symbol.pass} secret-scan: no secrets found`));
