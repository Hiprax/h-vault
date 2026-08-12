/**
 * ESLint results → SARIF 2.1.0.
 *
 * ESLint ships no SARIF formatter, and the third-party one is an extra
 * dependency in the security-critical `lint` gate for a conversion that is a
 * dozen fields wide. This is that conversion, kept pure so it can be tested
 * without running ESLint: `toSarif(results, meta)` in, one SARIF document out.
 *
 * Only what a consumer actually reads is emitted — rule metadata, level,
 * message, and a URI + region per finding. Two details are deliberate:
 *
 *   * Paths are repo-relative with `uriBaseId: "%SRCROOT%"`. An absolute path
 *     from one developer's machine is not a location any other tool can resolve.
 *   * A fatal parse error has no `ruleId`. SARIF permits a result without one,
 *     but NOT a `ruleIndex` pointing nowhere, so both are omitted together and
 *     the message carries the parse failure.
 */

/**
 * The subset of SARIF 2.1.0 this emits, declared so consumers get real types
 * rather than `any` — the test asserting the shape is one of them.
 *
 * @typedef {{ startLine: number, startColumn?: number, endLine?: number, endColumn?: number }} SarifRegion
 * @typedef {{ physicalLocation: { artifactLocation: { uri: string, uriBaseId: string }, region: SarifRegion } }} SarifLocation
 * @typedef {{ ruleId?: string, ruleIndex?: number, level: string, message: { text: string }, locations: SarifLocation[] }} SarifResult
 * @typedef {{ id: string, shortDescription?: { text: string }, helpUri?: string, properties?: { category: string } }} SarifRule
 * @typedef {{ tool: { driver: { name: string, informationUri: string, version?: string, rules: SarifRule[] } }, results: SarifResult[] }} SarifRun
 * @typedef {{ $schema: string, version: string, runs: SarifRun[] }} SarifLog
 */

/** ESLint severity → SARIF level. 0 (off) never reaches a result. */
const LEVEL = { 1: 'warning', 2: 'error' };

/** Windows separators are not URI separators. */
const toUri = (file) => file.split('\\').join('/');

/**
 * @param {{filePath: string, messages: {ruleId: string|null, severity: number, message: string,
 *          line?: number, column?: number, endLine?: number, endColumn?: number,
 *          fatal?: boolean}[]}[]} results  ESLint's JSON output
 * @param {{version?: string, rulesMeta?: Record<string, {docs?: {description?: string, url?: string},
 *          type?: string}>, rootDir?: string}} [meta]
 * @returns {SarifLog}
 */
export function toSarif(results, meta = {}) {
  const ruleIndex = new Map();
  const rules = [];
  const sarifResults = [];

  for (const result of results) {
    const uri = toUri(relativize(result.filePath, meta.rootDir));

    for (const message of result.messages) {
      const level = LEVEL[message.severity];
      // Severity 0 is "off" and cannot appear in a report; anything else that is
      // not 1 or 2 is not an ESLint severity at all. Dropping it silently would
      // under-report, so it is surfaced at the more serious level.
      const resolvedLevel = level ?? 'error';

      const entry = {
        level: resolvedLevel,
        message: { text: message.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
              region: region(message),
            },
          },
        ],
      };

      if (message.ruleId) {
        if (!ruleIndex.has(message.ruleId)) {
          ruleIndex.set(message.ruleId, rules.length);
          rules.push(describeRule(message.ruleId, meta.rulesMeta?.[message.ruleId]));
        }
        entry.ruleId = message.ruleId;
        entry.ruleIndex = ruleIndex.get(message.ruleId);
      }

      sarifResults.push(entry);
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ESLint',
            informationUri: 'https://eslint.org',
            ...(meta.version ? { version: meta.version } : {}),
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };
}

/**
 * Counts by SARIF level, which is what `warnings.json` is built from.
 *
 * @param {SarifLog} sarif
 * @returns {{ error: number, warning: number, note: number }}
 */
export function countLevels(sarif) {
  const counts = { error: 0, warning: 0, note: 0 };
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const level = result.level ?? 'warning';
      counts[level] = (counts[level] ?? 0) + 1;
    }
  }
  return counts;
}

function describeRule(id, ruleMeta) {
  const rule = { id };
  const description = ruleMeta?.docs?.description;
  if (description) {
    rule.shortDescription = { text: description };
  }
  if (ruleMeta?.docs?.url) {
    rule.helpUri = ruleMeta.docs.url;
  }
  if (ruleMeta?.type) {
    rule.properties = { category: ruleMeta.type };
  }
  return rule;
}

/**
 * SARIF regions are 1-based and `endColumn` is exclusive, which is exactly
 * ESLint's convention, so the values pass through. A message with no line (a
 * whole-file problem such as an unmatched ignore pattern) gets line 1: SARIF
 * requires `startLine` to be a positive integer when a region is present.
 */
function region(message) {
  const startLine = message.line && message.line > 0 ? message.line : 1;
  const out = { startLine };
  if (message.column && message.column > 0) out.startColumn = message.column;
  if (message.endLine && message.endLine > 0) out.endLine = message.endLine;
  if (message.endColumn && message.endColumn > 0) out.endColumn = message.endColumn;
  return out;
}

function relativize(filePath, rootDir) {
  if (!rootDir) return filePath;
  const root = rootDir.endsWith('/') || rootDir.endsWith('\\') ? rootDir : `${rootDir}/`;
  return filePath.startsWith(root) ? filePath.slice(root.length) : filePath;
}
