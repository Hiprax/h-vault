/**
 * Git for throwaway fixture repositories, with the machine's own git
 * configuration out of reach.
 *
 * The environment itself is defined ONCE, in `scripts/ci/lib/hermetic-git.mjs`,
 * because `scripts/ci/selftest.mjs` builds a repository the same way and cannot
 * import TypeScript; that module's header says what is hidden and why. A test that
 * builds a repository runs its git, and every child that runs git there (a gate,
 * the integrity scanner, the ratchet), under {@link hermeticGitEnv}, and proves it
 * with {@link expectOnlyLocalGitConfig}.
 */
import { expect } from 'vitest';
import { gitConfigScopes, hermeticGitEnv } from '../../../scripts/ci/lib/hermetic-git.mjs';

export { hermeticGitEnv };

/**
 * The isolation, asserted rather than assumed: every setting git sees in `dir`,
 * under the environment the caller runs its fixture git with, is one the fixture
 * itself wrote (`local` scope). On any machine with a global or system git
 * configuration this fails for an environment that is not hermetic; pass the
 * SAME `env` the fixture's own git calls use, or the check proves nothing.
 */
export function expectOnlyLocalGitConfig(dir: string, env: NodeJS.ProcessEnv): void {
  expect(
    new Set(gitConfigScopes(dir, env)),
    `git in ${dir} sees configuration the fixture did not write`,
  ).toEqual(new Set(['local']));
}
