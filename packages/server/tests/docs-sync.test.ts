import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AUDIT_ACTIONS } from '@hvault/shared';

// Documentation-lint: the README API reference, rate-limit table, env table,
// and counts must stay in sync with the code. Resolve the monorepo-root
// README.md (3 levels up from packages/server/tests/) regardless of cwd.
const testDir = path.dirname(fileURLToPath(import.meta.url));
const readmePath = path.resolve(testDir, '..', '..', '..', 'README.md');
const readme = readFileSync(readmePath, 'utf-8');

describe('README documentation sync', () => {
  it('does not reference the removed POST /tools/generate-password route (generation is client-side)', () => {
    expect(readme).not.toContain('/tools/generate-password');
  });

  it('documents the EXPORT_MAX_SIZE_MB, ENABLE_SWAGGER, and TRUST_PROXY env vars', () => {
    expect(readme).toContain('EXPORT_MAX_SIZE_MB');
    expect(readme).toContain('ENABLE_SWAGGER');
    expect(readme).toContain('TRUST_PROXY');
  });

  it('documents the authenticated POST /auth/lock endpoint', () => {
    expect(readme).toContain('/auth/lock');
  });

  it('the audit-operations count matches AUDIT_ACTIONS.length', () => {
    expect(readme).toContain(`${String(AUDIT_ACTIONS.length)} distinct operations`);
  });

  it('the Heavy Ops rate-limit row reflects the real targets, not "password generation"', () => {
    const heavyOpsRow = readme.split('\n').find((line) => line.includes('Heavy Ops'));
    expect(heavyOpsRow).toBeDefined();
    expect(heavyOpsRow).not.toMatch(/password generation/i);
    // Real heavyOpLimiter targets (empty trash, bulk delete/move, export/import,
    // backup trigger/download).
    expect(heavyOpsRow).toMatch(/empty trash/i);
  });

  it('the export docs advertise JSON only (CSV is import-only)', () => {
    expect(readme).not.toContain('JSON or CSV');
  });
});
