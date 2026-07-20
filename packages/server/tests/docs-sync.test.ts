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

  it('the documented HVAULT_VERSION default matches the root package.json version', () => {
    // The Compose-variable table quotes a concrete default. A release that bumps
    // package.json, docker-compose.yml and .env.example but forgets this cell tells
    // operators to pin the PREVIOUS tag: on a host that still holds the old images,
    // following the README produces a stack that silently serves the old release.
    const rootPackageJson = JSON.parse(
      readFileSync(path.resolve(testDir, '..', '..', '..', 'package.json'), 'utf-8'),
    ) as { version: string };

    const documented = /\|\s*`HVAULT_VERSION`\s*\|\s*`([^`]+)`\s*\|/.exec(readme)?.[1];
    expect(documented).toBe(rootPackageJson.version);
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
