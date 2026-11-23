/**
 * `scripts/ci/lib/hermetic-git.mjs`: the environment every throwaway repository's
 * git runs under (the server suites' fixtures and `verify:selftest`'s workspace).
 *
 * The suites that USE it assert the isolation against whatever this machine's git
 * configuration happens to be, which proves nothing on a machine that has none.
 * These cases build a hostile configuration of their own, in a temp `HOME` and
 * `XDG_CONFIG_HOME`, plus the two ways a parent process leaks into a child (a
 * `git -c` carried in `GIT_CONFIG_PARAMETERS`, a hook's `GIT_DIR`), so each one
 * fails on any machine the moment the helper stops hiding one of them.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { gitConfigScopes, hermeticGitEnv } from '../../../scripts/ci/lib/hermetic-git.mjs';

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/**
 * A temp world whose global git configuration is hostile, whatever this machine's
 * own is: `~/.gitconfig` turns tag signing on and names a user, the XDG file turns
 * on `core.autocrlf`, and the inherited environment carries a parent's
 * `git -c commit.gpgSign=true`. `GIT_DIR` is added only by the case about it,
 * because with it set no git command reaches `repo` at all.
 */
function hostileWorld(options: { gitDir?: boolean } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'hv-hermetic-git-'));
  dirs.push(root);
  const home = path.join(root, 'home');
  const xdg = path.join(root, 'xdg');
  const repo = path.join(root, 'repo');
  const elsewhere = path.join(root, 'elsewhere.git');
  mkdirSync(path.join(xdg, 'git'), { recursive: true });
  mkdirSync(home);
  mkdirSync(repo);
  writeFileSync(
    path.join(home, '.gitconfig'),
    '[tag]\n\tgpgSign = true\n[user]\n\tname = leaked\n',
  );
  writeFileSync(path.join(xdg, 'git', 'config'), '[core]\n\tautocrlf = true\n');
  const base: NodeJS.ProcessEnv = {
    PATH: process.env['PATH'],
    HOME: home,
    XDG_CONFIG_HOME: xdg,
    KEEP_ME: 'kept',
    GIT_CONFIG_PARAMETERS: "'commit.gpgsign'='true'",
    ...(options.gitDir ? { GIT_DIR: elsewhere } : {}),
  };
  return { repo, elsewhere, base };
}

const git = (cwd: string, env: NodeJS.ProcessEnv, ...args: string[]) =>
  spawnSync('git', args, { cwd, env, encoding: 'utf-8' });

describe('hermeticGitEnv', () => {
  it('hides the global and XDG configuration and a parent git -c, leaving only the repository', () => {
    const { repo, base } = hostileWorld();
    const env = hermeticGitEnv(base);
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: repo, env });

    // The premise, so a green result means something: inherited as-is, git in this
    // world DOES see the hostile global file and the parent's -c setting.
    const leaky = gitConfigScopes(repo, base);
    expect(leaky).toContain('global');
    expect(leaky).toContain('command');
    expect(git(repo, base, 'config', '--get', 'tag.gpgsign').stdout.trim()).toBe('true');

    // Hermetic: nothing but what `git init` wrote.
    expect(new Set(gitConfigScopes(repo, env))).toEqual(new Set(['local']));
    // Negative: none of the three hostile settings is visible (`--get` exits 1 on unset).
    for (const key of ['tag.gpgsign', 'commit.gpgsign', 'core.autocrlf', 'user.name']) {
      const read = git(repo, env, 'config', '--get', key);
      expect({ key, status: read.status, value: read.stdout }).toEqual({
        key,
        status: 1,
        value: '',
      });
    }
  });

  it("drops a hook's location variables, so git cannot reach another repository", () => {
    // Inherited as-is, `git init` honours GIT_DIR and initialises ELSEWHERE, leaving
    // the intended directory untouched: the overwrite githooks(5) warns about.
    const leaky = hostileWorld({ gitDir: true });
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: leaky.repo, env: leaky.base });
    expect(existsSync(leaky.elsewhere)).toBe(true);
    expect(existsSync(path.join(leaky.repo, '.git'))).toBe(false);

    const world = hostileWorld({ gitDir: true });
    execFileSync('git', ['init', '-q', '-b', 'main'], {
      cwd: world.repo,
      env: hermeticGitEnv(world.base),
    });
    expect(existsSync(path.join(world.repo, '.git'))).toBe(true);
    expect(existsSync(world.elsewhere)).toBe(false);
  });

  it('keeps every other variable, adds only its two overrides, and leaves the base untouched', () => {
    const { base } = hostileWorld({ gitDir: true });
    const before = { ...base };
    const env = hermeticGitEnv(base);

    expect(env['KEEP_ME']).toBe('kept');
    expect(env['HOME']).toBe(base['HOME']);
    expect(env['PATH']).toBe(base['PATH']);
    expect(
      Object.keys(env)
        .filter((key) => key.startsWith('GIT_'))
        .sort(),
    ).toEqual(['GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM']);
    expect(env['GIT_CONFIG_GLOBAL']).toBe('/dev/null');
    expect(env['GIT_CONFIG_NOSYSTEM']).toBe('1');
    // Negative: the caller's environment is not mutated (a copy is returned).
    expect(base).toEqual(before);
  });
});

describe('gitConfigScopes', () => {
  it('reports one scope per configuration entry, in the order git lists them', () => {
    const { repo, base } = hostileWorld();
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: repo, env: hermeticGitEnv(base) });
    const entries = git(repo, base, 'config', '--list').stdout.trim().split('\n');
    const scopes = gitConfigScopes(repo, base);

    expect(scopes).toHaveLength(entries.length);
    // The hostile files are read first (global, in file order), the parent's -c last.
    expect(scopes[0]).toBe('global');
    expect(scopes.at(-1)).toBe('command');
    expect(scopes.every((scope) => ['global', 'local', 'command', 'system'].includes(scope))).toBe(
      true,
    );
  });
});
