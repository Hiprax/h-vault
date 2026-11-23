/**
 * The lint gate refuses the Hangul filler characters that make code invisible.
 *
 * `security/detect-invisible-characters` (eslint-plugin-security 4.1+) reports
 * U+3164 and U+FFA0, which render as nothing and have been used to hide an
 * identifier or a whole statement in plain sight. The repo config lists the
 * security rules one by one, so a new rule is off until it is named there; this
 * pins that it is, through the repo's real config. The characters are built with
 * String.fromCodePoint so that no invisible character sits in this file.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const requireFromRoot = createRequire(path.join(repoRoot, 'package.json'));

interface LintMessage {
  ruleId: string | null;
  severity: number;
}

async function lint(code: string): Promise<LintMessage[]> {
  const { ESLint } = (await import(requireFromRoot.resolve('eslint'))) as {
    ESLint: new (options: { cwd: string }) => {
      lintText: (
        code: string,
        options: { filePath: string },
      ) => Promise<{ messages: LintMessage[] }[]>;
    };
  };
  const eslint = new ESLint({ cwd: repoRoot });
  // The security rules cover production sources, so the snippet is linted AS an
  // existing source file (its text on disk is not read or changed): a path the
  // type-aware config can place in its project.
  const [result] = await eslint.lintText(code, {
    filePath: path.join(repoRoot, 'packages', 'shared', 'src', 'zod.ts'),
  });
  return result?.messages ?? [];
}

const RULE = 'security/detect-invisible-characters';

describe('the lint gate and invisible characters', () => {
  it.each([
    ['U+3164 (HANGUL FILLER)', 0x3164],
    ['U+FFA0 (HALFWIDTH HANGUL FILLER)', 0xffa0],
  ])('reports %s hidden in code, as a warning the zero-warning gate blocks', async (_n, cp) => {
    const hidden = String.fromCodePoint(cp);
    const messages = await lint(`export const value${hidden} = 1;\n`);
    expect(messages.filter((m) => m.ruleId === RULE).map((m) => m.severity)).toEqual([1]);
  });

  it('reports nothing for the same code without the character', async () => {
    const messages = await lint('export const value = 1;\n');
    expect(messages.filter((m) => m.ruleId === RULE)).toEqual([]);
  });
}, 60_000);
