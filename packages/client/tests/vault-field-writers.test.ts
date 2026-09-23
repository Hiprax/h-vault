// @vitest-environment node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Which modules may still seal a vault-key field WITHOUT binding it.
 *
 * Every ordinary write seals its fields in format v2, bound to the row they
 * belong to, through `encryptVaultField`. A write that goes back to the unbound
 * primitive (`cryptoService.encryptData`) type-checks, lints clean and round-trips
 * perfectly, and silently reopens the substitution gap v2 closes for every row it
 * writes: nothing but this list notices. So the list is closed, and each entry
 * says why it is exempt:
 *
 *   - `pages/BackupSettingsPage.tsx`: a RESTORE. The server stores restored rows
 *     under ids it mints itself, so no id is known to seal to; the rows are bound
 *     at the next re-seal.
 *   - `services/health/healthResultsStore.ts`: the health-results cache, a local
 *     encrypted blob that is not a vault row and has no row to be moved to.
 *
 * And the bound primitive (`encryptDataWithAad`) has exactly one caller, the
 * sealer, because a field sealed with additional data but not marked on its IV is
 * a field every reader opens as v1 and fails for ever.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(here, '..', 'src');

/** Every source file under `src/`, as a path relative to it. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (/\.(ts|tsx)$/.test(entry))
      out.push(path.relative(SRC, full).split(path.sep).join('/'));
  }
  return out;
}

/** The files whose CODE (comments stripped) contains `pattern`. */
function filesCalling(pattern: RegExp): string[] {
  return sourceFiles(SRC)
    .filter((file) => {
      const code = readFileSync(path.join(SRC, file), 'utf-8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:])\/\/.*$/gm, '$1');
      return pattern.test(code);
    })
    .sort();
}

describe('vault-field writers', () => {
  it('seals unbound (format v1) only in the two modules with no row id to bind to', () => {
    expect(filesCalling(/\bcryptoService\s*\.\s*encryptData\s*\(/)).toEqual([
      'pages/BackupSettingsPage.tsx',
      'services/health/healthResultsStore.ts',
    ]);
  });

  it('calls the bound primitive only from the sealer, which also marks the field', () => {
    expect(filesCalling(/\.\s*encryptDataWithAad\s*\(/)).toEqual(['services/crypto/vaultField.ts']);
  });

  it('can see a call it is meant to catch', () => {
    // The scan itself, pinned: a file list that came back empty because the
    // pattern or the walk broke would otherwise pass the two checks above.
    expect(sourceFiles(SRC).length).toBeGreaterThan(100);
    expect(filesCalling(/\bencryptVaultField\s*\(/)).toEqual(
      expect.arrayContaining([
        'pages/SettingsPage.tsx',
        'services/crypto/passwordHistory.ts',
        'services/import/encrypt.ts',
        'services/import/operations.ts',
        'stores/vaultStore.ts',
      ]),
    );
  });
});
