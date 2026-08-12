/**
 * Per-test temp directories, and the guard that stops the suite writing into the
 * checkout.
 *
 * The failure this prevents is quiet: a test that writes a fixture into the repo
 * leaves state the NEXT test can read (order dependence wearing the costume of a
 * fixture), dirties the working tree, and lands in `audit:integrity`'s scan of
 * untracked files, where it fails a gate that has nothing to do with it.
 */
import fs from 'node:fs';
import { rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it, onTestFinished } from 'vitest';
import { REPO_ROOT, RepoWriteBlockedError, createTestTempDir } from './tempDir.js';

/**
 * Names a path inside the repository that a probe is about to attempt to write,
 * and registers its removal.
 *
 * Each probe asserts the write was blocked AND that no artifact exists. But the
 * day the guard regresses, the write SUCCEEDS: the assertion that follows fails,
 * and the artifact is left behind in the checkout. `audit:integrity` scans
 * untracked files, so a regression here would additionally fail an unrelated
 * gate and hand the next run a dirty tree — the test would document the damage
 * instead of containing it.
 *
 * The cleanup uses the NAMED `rmSync` import deliberately. `tests/tempDir.ts`
 * documents (and measured) that Node snapshots a builtin's named exports when
 * the module namespace is first created, before any setup file runs, so this
 * binding holds the original function and the guard provably cannot intercept
 * it. `fs.rmSync` would be blocked by the very guard under test.
 */
function repoProbePath(...segments: string[]): string {
  const target = path.join(REPO_ROOT, ...segments);
  onTestFinished(() => {
    rmSync(target, { recursive: true, force: true });
  });
  return target;
}

describe('createTestTempDir', () => {
  it('creates a writable directory outside the repository', () => {
    const dir = createTestTempDir('hv-tempdir-spec-');

    expect(dir.startsWith(tmpdir())).toBe(true);
    expect(dir.startsWith(REPO_ROOT + path.sep)).toBe(false);
    expect(fs.existsSync(dir)).toBe(true);

    const file = path.join(dir, 'fixture.json');
    fs.writeFileSync(file, '{"ok":true}', 'utf-8');
    expect(JSON.parse(fs.readFileSync(file, 'utf-8'))).toEqual({ ok: true });
  });

  it('hands out a fresh directory per call, so two tests cannot collide', () => {
    expect(createTestTempDir()).not.toBe(createTestTempDir());
  });
});

describe('repo write guard', () => {
  // Every call here goes through the `fs` namespace on purpose: that is the form
  // the guard can intercept, and `tests/tempDir.ts` documents why an
  // `import { writeFileSync } from 'node:fs'` binding is out of its reach.
  it('blocks a write into the repository and names the offender and the fix', () => {
    const target = repoProbePath('packages', 'server', 'stray-fixture.json');

    expect(() => fs.writeFileSync(target, 'x')).toThrow(RepoWriteBlockedError);
    expect(() => fs.writeFileSync(target, 'x')).toThrow(/stray-fixture\.json/);
    expect(() => fs.writeFileSync(target, 'x')).toThrow(/createTestTempDir/);
    // And nothing was created: a guard that reported the write after performing
    // it would be a warning, not a guard.
    expect(fs.existsSync(target)).toBe(false);
  });

  it('blocks the directory-creating and removing calls too, not only writeFile', () => {
    const dir = repoProbePath('stray-dir');
    expect(() => fs.mkdirSync(dir)).toThrow(RepoWriteBlockedError);
    expect(fs.existsSync(dir)).toBe(false);

    // The removal path is probed against a path that does NOT exist, never against
    // a real tracked file. Pointing it at `README.md` would mean that the day the
    // guard regresses, this test DELETES README.md and only then reports it — the
    // assertion would document the damage instead of preventing it. With a
    // non-existent target a regressed guard raises ENOENT rather than
    // `RepoWriteBlockedError`, so the test still goes red and nothing is lost.
    const absent = path.join(REPO_ROOT, 'packages', 'server', '.repo-write-probe');
    expect(fs.existsSync(absent)).toBe(false);
    expect(() => fs.rmSync(absent)).toThrow(RepoWriteBlockedError);
  });

  it('leaves the promise API and write streams alone, because the runner needs them', async () => {
    // Not an oversight and not a weakening: wrapping `fs.promises.*` and
    // `createWriteStream` broke vitest's own v8 coverage collection (its
    // per-worker `coverage/.tmp/coverage-N.json` payloads went missing, the read
    // failed with ENOENT, and the run died before the JUnit reporter flushed —
    // leaving `audit:ratchet:full` unable to measure `tests.count` or any server
    // coverage field). A guard that silently disables the pipeline's measurements
    // costs more than the accidental writes it catches. This pins the boundary so
    // it is a decision rather than a gap someone "fixes" back into a broken run.
    const target = repoProbePath('stray-async.json');
    await expect(fs.promises.writeFile(target, 'x')).resolves.toBeUndefined();
    expect(fs.existsSync(target)).toBe(true);
    // Clean up through the ORIGINAL binding: `fs.rmSync` is guarded, and this
    // path is deliberately inside the repo.
    await fs.promises.unlink(target);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('allows the runner’s own outputs, or it would fail the suite it is protecting', () => {
    // Coverage `.tmp` payloads, the JUnit report and the mongod binary cache are
    // all written from inside a worker. Blocking any of them would break the run.
    const allowed = path.join(REPO_ROOT, 'packages', 'server', 'coverage', '.probe-allowed');
    fs.mkdirSync(path.dirname(allowed), { recursive: true });
    expect(() => fs.writeFileSync(allowed, 'ok')).not.toThrow();
    fs.rmSync(allowed, { force: true });

    expect(() =>
      fs.mkdirSync(path.join(REPO_ROOT, '.testfortress', 'reports'), { recursive: true }),
    ).not.toThrow();
  });

  it('leaves writes outside the repository alone', () => {
    const dir = createTestTempDir('hv-tempdir-outside-');
    expect(() => fs.writeFileSync(path.join(dir, 'anything.txt'), 'ok')).not.toThrow();
    expect(() => fs.mkdirSync(path.join(dir, 'nested'))).not.toThrow();
  });
});
