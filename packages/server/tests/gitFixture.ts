/**
 * Git for throwaway fixture repositories, with the machine's own git
 * configuration out of reach.
 *
 * A test that builds a repository in a temp directory, and every child process it
 * starts there that runs git itself (a gate, the integrity scanner, the ratchet),
 * would otherwise read the developer's `~/.gitconfig` and the system file. Each
 * of those settings changes what a fixture is: `tag.gpgSign` made `git tag` fail
 * outright, `commit.gpgSign` makes every commit need a signing key,
 * `core.autocrlf` rewrites what `git add` stores, and `core.excludesFile` hides
 * files from `git ls-files`, which is how the integrity scanner enumerates. Opting
 * out one key at a time is how the next key got through, so the configuration is
 * hidden as a whole: `GIT_CONFIG_GLOBAL=/dev/null` covers both `~/.gitconfig` and
 * `$XDG_CONFIG_HOME/git/config`, and `GIT_CONFIG_NOSYSTEM` the system file.
 *
 * Every inherited `GIT_*` variable is dropped as well. The location variables a
 * hook exports (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, ...) would aim these
 * commands at the REAL repository, which `githooks(5)` says a hook running git in
 * a foreign repository must clear; and `GIT_CONFIG_PARAMETERS`/`GIT_CONFIG_COUNT`
 * carry a parent's `git -c` settings past any file-level isolation.
 */
import { execFileSync } from 'node:child_process';
import { expect } from 'vitest';

/** The environment for fixture git, and for any child that runs git in a fixture. */
export function hermeticGitEnv(): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  };
}

/**
 * The isolation, asserted rather than assumed: every setting git sees in `dir`,
 * under the environment the caller runs its fixture git with, is one the fixture
 * itself wrote (`local` scope). On any machine with a global or system git
 * configuration this fails for an environment that is not hermetic; pass the
 * SAME `env` the fixture's own git calls use, or the check proves nothing.
 */
export function expectOnlyLocalGitConfig(dir: string, env: NodeJS.ProcessEnv): void {
  const scopes = execFileSync('git', ['config', '--list', '--show-scope'], {
    cwd: dir,
    env,
    encoding: 'utf-8',
  })
    .trim()
    .split('\n')
    .map((line) => line.split('\t')[0]);
  expect(new Set(scopes), `git in ${dir} sees configuration the fixture did not write`).toEqual(
    new Set(['local']),
  );
}
