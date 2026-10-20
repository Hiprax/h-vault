/**
 * The container vulnerability scan, defined once.
 *
 * Two callers judge images with it: the `docker` gate (`scripts/ci/docker-gate.mjs`)
 * scans the images it builds from the working tree, and the release workflow
 * (`scripts/ci/release-images.mjs build`) scans the exact bytes it is about to
 * publish, on each architecture. They must ask the same question and accept the
 * same exceptions, or a finding waved through in one place would block the other.
 *
 * Everything here is pure: running the scanner is the caller's business.
 */

/**
 * The scanner, pinned by digest like every other image this repository runs.
 *
 * Trivy is exactly the kind of tool whose supply chain matters: it was itself
 * compromised in March 2026 (GHSA-69fq-xp46-6x23, malicious v0.69.4 to v0.69.6
 * images), and the docker gate hands it the daemon socket. A floating `latest`
 * would run whatever was last pushed under that name with that access. The
 * digest is the multi-platform index digest of 0.75.0, read from Docker Hub and
 * from Aqua's own GHCR copy on 2026-10-20 (the two agreed). The vulnerability
 * DATABASE is still fetched fresh on every scan; only the scanner is pinned.
 * CONTRIBUTING.md, "Refreshing the release workflow's pins", is how to move it.
 */
export const TRIVY_IMAGE =
  'aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa';

/**
 * The scan both callers run, minus the subject (an image reference, or
 * `--input <tarball>`).
 *
 * `--exit-code 0` is deliberate: Trivy reports, the caller DECIDES. The verdict
 * has to be taken after the baseline is applied, and a non-zero exit would end
 * the run before that could happen. A scan that genuinely could not run is still
 * caught: it surfaces as a non-zero exit from a scanner that produced no
 * parseable report.
 *
 * `--format json` rather than `table` for the same reason: an accepted finding
 * can only be matched on (id, image, package, path) if those fields survive as
 * data.
 */
export const TRIVY_SCAN_ARGS = Object.freeze([
  'image',
  '--severity',
  'CRITICAL,HIGH',
  '--ignore-unfixed',
  '--exit-code',
  '0',
  '--scanners',
  'vuln',
  '--format',
  'json',
  '--timeout',
  '15m',
]);

/**
 * The accepted-findings list from `scripts/ci/trivy-baseline.json`.
 *
 * Throws on anything but an object with a `findings` array, so a malformed file
 * fails the caller loudly rather than silently accepting nothing (which would
 * look identical to "the baseline worked" on a clean scan) or, worse,
 * everything.
 *
 * @param {string} text
 * @returns {Array<{ id: string, image: string, package: string, pathPrefix: string }>}
 */
export function parseBaseline(text) {
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.findings)) {
    throw new Error('`findings` must be an array');
  }
  return parsed.findings;
}

/**
 * The baseline entry that accepts this finding, if one does.
 *
 * Only when EVERY field matches: the CVE, the image it was reviewed in, the
 * package, and the path prefix. Matching on the CVE alone would let an entry
 * reviewed for npm's bundled copy silently excuse the same CVE appearing in the
 * application's own dependencies, which is exactly the finding that must never
 * be waved through.
 *
 * @param {ReturnType<typeof parseBaseline>} baseline
 * @param {{ id: string, pkg: string, path: string }} finding
 * @param {string} imageName the image's repository name, e.g. `hvault-app`
 */
export function acceptedBy(baseline, finding, imageName) {
  return baseline.find(
    (entry) =>
      entry.id === finding.id &&
      entry.image === imageName &&
      entry.package === finding.pkg &&
      finding.path.startsWith(entry.pathPrefix),
  );
}

/**
 * Every vulnerability in a Trivy JSON report, flattened to what a verdict needs.
 *
 * @param {{ Results?: Array<{ Target?: string, Vulnerabilities?: Array<Record<string, string>> }> }} report
 */
export function extractFindings(report) {
  const findings = [];
  for (const result of report.Results ?? []) {
    for (const vulnerability of result.Vulnerabilities ?? []) {
      findings.push({
        id: vulnerability.VulnerabilityID,
        pkg: vulnerability.PkgName,
        installed: vulnerability.InstalledVersion,
        fixed: vulnerability.FixedVersion ?? '',
        severity: vulnerability.Severity,
        // PkgPath is where the package actually lives; Target is the scan unit
        // it was found through. The path is what distinguishes npm's bundled
        // tree from our own, so it must never fall back to nothing.
        path: vulnerability.PkgPath ?? result.Target ?? '',
        title: vulnerability.Title ?? '',
      });
    }
  }
  return findings;
}

/**
 * Splits a report's findings into the ones the baseline accepts and the rest.
 *
 * @param {ReturnType<typeof extractFindings>} findings
 * @param {ReturnType<typeof parseBaseline>} baseline
 * @param {string} imageName
 */
export function judgeFindings(findings, baseline, imageName) {
  const accepted = [];
  const unresolved = [];
  for (const finding of findings) {
    const entry = acceptedBy(baseline, finding, imageName);
    if (entry) accepted.push({ finding, entry });
    else unresolved.push(finding);
  }
  return { accepted, unresolved };
}

/**
 * Why a report cannot be trusted to have scanned anything, or null when it can.
 *
 * A scan of an image identifies its operating system and reports at least that
 * as a result; every image this repository builds or publishes has one (Alpine).
 * A report without either (an empty tarball, a wrong path, a scanner that
 * skipped the input) would otherwise read as "no findings", which is the one
 * wrong answer a vulnerability gate must never give.
 *
 * @param {{ Metadata?: { OS?: { Family?: string } }, Results?: unknown[] } | null} report
 */
export function scanCoverageProblem(report) {
  if (!report?.Metadata?.OS?.Family) {
    return 'the scan identified no operating system, so it did not examine an image';
  }
  return Array.isArray(report?.Results) && report.Results.length > 0
    ? null
    : 'the scan reported no results at all, so it examined nothing';
}
