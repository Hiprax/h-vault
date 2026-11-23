/**
 * Git for throwaway repositories, with the machine's own git configuration out of
 * reach: the ONE definition, shared by `scripts/ci/selftest.mjs` (its workspace
 * copy) and `packages/server/tests/gitFixture.ts` (every server test that builds a
 * fixture repository).
 *
 * A program that builds a repository in a temp directory, and every child process
 * it starts there that runs git itself (a gate, the integrity scanner, the
 * ratchet), would otherwise read the developer's `~/.gitconfig` and the system
 * file. Each of those settings changes what the repository is: `tag.gpgSign` made
 * `git tag` fail outright, `commit.gpgSign` makes every commit need a signing key,
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
 *
 * Pure by contract, like every `scripts/ci/lib/**` module: nothing runs at module
 * scope, because tests import it.
 */
import { execFileSync } from 'node:child_process';

/**
 * The environment for git in a throwaway repository, and for any child that runs
 * git there. Everything that is not a `GIT_*` variable is kept as it was.
 *
 * @param {NodeJS.ProcessEnv} [base] the environment to start from (a copy is returned)
 * @returns {NodeJS.ProcessEnv}
 */
export function hermeticGitEnv(base = process.env) {
  return {
    ...Object.fromEntries(Object.entries(base).filter(([key]) => !key.startsWith('GIT_'))),
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  };
}

/**
 * The scope of every configuration entry git sees in `dir` under `env`
 * (`local`, `global`, `system`, `command`, ...), one per entry. A throwaway
 * repository run under {@link hermeticGitEnv} sees `local` only.
 *
 * @param {string} dir
 * @param {NodeJS.ProcessEnv} env
 * @returns {string[]}
 */
export function gitConfigScopes(dir, env) {
  return execFileSync('git', ['config', '--list', '--show-scope'], {
    cwd: dir,
    env,
    encoding: 'utf8',
  })
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => line.split('\t')[0] ?? '');
}
