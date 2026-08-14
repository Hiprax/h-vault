/**
 * The gate surface's report plumbing.
 *
 * Two things live here, and they exist for the same reason: a gate whose only
 * output is a terminal is a gate nothing can ratchet, diff or audit later.
 *
 *   1. `.testfortress/reports/` — where every gate leaves a machine-readable
 *      artifact (JUnit XML, SARIF, JSON, or the gate's own transcript). One glob
 *      collects the state of the world; nothing is uploaded anywhere.
 *   2. `.testfortress/verify.json` — the manifest: canonical task name → command,
 *      tier, gate criterion and report. It is what lets a tool enumerate the
 *      gates without reading package.json and guessing.
 *
 * The manifest is NOT decoration. `validateManifest` is run by the pipeline on
 * every invocation and a drift between it and the runner's own gate table is a
 * hard "could not run" (exit 2), never a warning — a manifest that has quietly
 * stopped describing reality is worse than none, because everything downstream
 * still believes it.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { repoRoot } from './proc.mjs';

/** Repo-relative, because that is how the manifest names them. */
const REPORT_DIR_REL = '.testfortress/reports';
const REPORT_DIR = path.join(repoRoot, '.testfortress', 'reports');
export const MANIFEST_REL = '.testfortress/verify.json';
const MANIFEST_PATH = path.join(repoRoot, '.testfortress', 'verify.json');

export function ensureReportDir() {
  mkdirSync(REPORT_DIR, { recursive: true });
  return REPORT_DIR;
}

/** Absolute path of a report named the way the manifest names it. */
export function reportPath(name) {
  return path.join(REPORT_DIR, name);
}

/** A manifest `report` field is one name or several; callers want a list. */
export function reportList(report) {
  if (!report) return [];
  return Array.isArray(report) ? report : [report];
}

/**
 * Deletes a gate's declared reports before it runs.
 *
 * Without this, a report left by an earlier run makes the "did this gate write
 * its report?" check pass for a gate that wrote nothing — which is precisely the
 * fake-gate shape the report contract exists to prevent.
 */
export function clearReports(names) {
  for (const name of names) {
    rmSync(reportPath(name), { force: true });
  }
}

/** The declared reports that are NOT on disk. */
export function missingReports(names) {
  return names.filter((name) => !existsSync(reportPath(name)));
}

export function writeJsonReport(name, value) {
  ensureReportDir();
  writeFileSync(reportPath(name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return reportPath(name);
}

export function readJsonReport(name) {
  const file = reportPath(name);
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

export function readTextReport(name) {
  const file = reportPath(name);
  return existsSync(file) ? readFileSync(file, 'utf8') : null;
}

/** @returns {{manifest: unknown|null, error: string|null}} */
export function loadManifest() {
  if (!existsSync(MANIFEST_PATH)) {
    return { manifest: null, error: `${MANIFEST_REL} is missing` };
  }
  try {
    return { manifest: JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')), error: null };
  } catch (error) {
    return { manifest: null, error: `${MANIFEST_REL} is not valid JSON: ${error.message}` };
  }
}

/**
 * Cross-checks the manifest against the runner's own gate table.
 *
 * The two describe the same gates from opposite directions — the manifest for
 * anything reading the repository, the gate table for the runner executing it —
 * so any disagreement means one of them is lying. Returns a list of problems;
 * empty means they agree.
 *
 * `composite` tasks (verify, verify:fast, verify:full) are aggregators, not
 * gates: they are excluded from the comparison so a tier can never run one of
 * itself as a member of itself.
 */
export function validateManifest(manifest, gates) {
  const problems = [];

  if (manifest === null || typeof manifest !== 'object') {
    return [`${MANIFEST_REL} did not parse into an object`];
  }
  if (manifest.version !== 1) {
    problems.push(`${MANIFEST_REL}: unsupported version ${JSON.stringify(manifest.version)}`);
  }
  if (manifest.reportDir !== REPORT_DIR_REL) {
    problems.push(
      `${MANIFEST_REL}: reportDir is ${JSON.stringify(manifest.reportDir)}, expected "${REPORT_DIR_REL}"`,
    );
  }
  const tasks = manifest.tasks;
  if (tasks === null || typeof tasks !== 'object') {
    return [...problems, `${MANIFEST_REL}: "tasks" is missing`];
  }

  const declared = new Map(Object.entries(tasks).filter(([, task]) => task?.composite !== true));

  for (const [name, task] of declared) {
    for (const field of ['cmd', 'tier', 'gate', 'report']) {
      if (task[field] === undefined) {
        problems.push(`${MANIFEST_REL}: task "${name}" is missing "${field}"`);
      }
    }
  }

  for (const gate of gates) {
    const task = declared.get(gate.task);
    if (!task) {
      problems.push(
        `gate "${gate.id}" runs task "${gate.task}", which ${MANIFEST_REL} does not declare`,
      );
      continue;
    }
    if (task.tier !== gate.tier) {
      problems.push(
        `task "${gate.task}": tier ${String(task.tier)} in ${MANIFEST_REL}, ${String(gate.tier)} in the gate table`,
      );
    }
  }

  const gateTasks = new Set(gates.map((gate) => gate.task));
  for (const name of declared.keys()) {
    if (!gateTasks.has(name)) {
      problems.push(`${MANIFEST_REL} declares task "${name}", which no gate runs`);
    }
  }

  return problems;
}
