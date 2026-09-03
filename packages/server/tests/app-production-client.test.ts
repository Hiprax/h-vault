/**
 * `app.ts`'s production block: the two build artifacts it reads at boot, and the
 * three things it mounts.
 *
 * ## Why this file exists
 *
 * Everything inside `if (config.NODE_ENV === 'production')` is unreachable from
 * every other server test, because they import `app` under `NODE_ENV=test`. So
 * the reads, the two "your build is incomplete" failures, the sandbox route, the
 * static mount and the SPA fallback have been production-only code that no
 * assertion in this tier could reach — and `sandbox-document.test.ts` says so
 * itself, which is why the POLICY was extracted into `config/sandboxCsp.ts` and
 * pinned there.
 *
 * Extraction covers the policy. It does not cover the WIRING, and the wiring is
 * where this feature's isolation is won or lost: the sandbox route has to be
 * registered BEFORE `express.static`, or a copy of `sandbox.html` answered off
 * disk carries helmet's application policy instead of its own and the isolation
 * quietly stops existing while every renderer keeps working.
 *
 * ## How it reaches that block, and why this is the sanctioned shape
 *
 * A HOISTED `vi.mock` of the config module reports production, exactly as
 * `coverage-rate-limiter.test.ts` does. It must be hoisted rather than
 * `vi.resetModules()` + `vi.doMock`: resetting the registry re-evaluates
 * `models/User.ts` against the externalised mongoose singleton, which throws
 * `OverwriteModelError` on the second `mongoose.model('User')`.
 *
 * `node:fs`'s `readFileSync` is mocked alongside it so the two documents can be
 * supplied WITHOUT writing into the repository — `publicPath` resolves to
 * `packages/server/public`, a real path in the checkout, and a test that created
 * files there would be writing into the tree and racing every other suite.
 */
import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';

const artifacts = vi.hoisted(() => ({
  /** What each requested filename answers with, or a throw when absent. */
  files: new Map<string, string>([
    [
      'index.html',
      '<!doctype html><html><head><script src="/assets/main.js"></script></head></html>',
    ],
    ['sandbox.html', '<!doctype html><html><body><div id="root"></div></body></html>'],
  ]),
}));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true, config: { ...actual.config, NODE_ENV: 'production' } };
});

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    readFileSync: (file: Parameters<typeof actual.readFileSync>[0], ...rest: unknown[]) => {
      const name = String(file).split(/[\\/]/).pop() ?? '';
      const canned = artifacts.files.get(name);
      if (canned !== undefined) return canned;
      return (actual.readFileSync as (...args: unknown[]) => unknown)(file, ...rest);
    },
  };
});

// Static, not a top-level dynamic import: a dynamically-imported module inside a
// mocked graph is attributed to a separate V8 coverage entry, and the merge then
// drops the file from the package report entirely.
import app from '../src/app.js';
import { requireBuildArtifact } from '../src/config/sandboxCsp.js';

describe('the production block mounts the client and the isolated document', () => {
  it('serves the sandbox document from Express, not from the static directory', async () => {
    // The ORDER is the assertion. `express.static` is mounted after this route,
    // so a `sandbox.html` sitting in the public directory can never be the thing
    // that answers — which matters because a static answer would carry helmet's
    // application policy, and the sandbox's entire isolation is the per-response
    // policy this route attaches.
    const response = await request(app).get('/sandbox.html');

    expect(response.status).toBe(200);
    expect(response.text).toContain('<div id="root">');
    const policy = response.headers['content-security-policy'];
    expect(policy).toBeDefined();
    expect(policy).toContain("connect-src 'none'");
    // EXACTLY ONE policy header. Two would be INTERSECTED by the browser, which
    // would kill `blob:` media and `data:` images in one stroke.
    expect(Array.isArray(response.headers['content-security-policy'])).toBe(false);
  });

  it('claims the case-insensitive spelling too, so static cannot answer it', async () => {
    // Express matches paths case-insensitively by default, so the route claims
    // `/SANDBOX.HTML` as well — which is what stops a case-insensitive
    // filesystem serving the file off disk under that spelling with the wrong
    // policy.
    const response = await request(app).get('/SANDBOX.HTML');
    expect(response.status).toBe(200);
    expect(response.headers['content-security-policy']).toContain("connect-src 'none'");
  });

  it('serves the application shell with a per-request nonce, and a DIFFERENT policy', async () => {
    const response = await request(app).get('/vault');

    expect(response.status).toBe(200);
    expect(response.text).toMatch(/<script nonce="[^"]+"/);
    // The application's own policy, which is not the sandbox's: this is the
    // negative that would catch the two being merged.
    const policy = response.headers['content-security-policy'];
    expect(policy).toContain("frame-src 'self'");
    expect(policy).not.toContain("connect-src 'none'");
  });

  it('gives each request its own nonce rather than reusing one', async () => {
    const first = await request(app).get('/vault');
    const second = await request(app).get('/vault');
    const nonceOf = (html: string): string => /<script nonce="([^"]+)"/.exec(html)?.[1] ?? '';

    expect(nonceOf(first.text)).not.toBe('');
    expect(nonceOf(first.text)).not.toBe(nonceOf(second.text));
  });

  it('leaves /api/ to the API rather than answering it with the shell', async () => {
    // The catch-all is `/^(?!\/api\/).*/`. Without that negative lookahead every
    // unmatched API path would answer 200 with an HTML document, and a client
    // would parse the shell as a JSON response.
    const response = await request(app).get('/api/v1/does-not-exist');
    expect(response.status).not.toBe(200);
    expect(response.text).not.toContain('<script nonce=');
  });
});

describe('a production build missing an artifact fails loudly at boot', () => {
  // The MAPPING is tested directly, on `requireBuildArtifact`, rather than by
  // re-importing `app.ts` with a file removed. That route is closed: forcing a
  // second module evaluation needs `vi.resetModules()`, which re-evaluates
  // `models/User.ts` against the externalised mongoose singleton and throws
  // `OverwriteModelError` instead of the error under test (measured). Extracting
  // the mapping is what makes it reachable at all — the call sites above are
  // inside the production block, and the happy path through them is covered by
  // the suite's first describe.
  it('replaces a read failure with a message naming the artifact', () => {
    expect(() =>
      requireBuildArtifact(() => {
        throw new Error('ENOENT: no such file or directory');
      }, 'Production build missing client dist. Run: npm run build:client'),
    ).toThrow('Production build missing client dist. Run: npm run build:client');
  });

  it('says which of the two builds is missing, because they are two builds', () => {
    // The negative that matters: the sandbox message must not be the client
    // message. `sandbox.html` comes out of its own Vite config, which runs after
    // the application build, so "run npm run build:client" is only actionable if
    // the operator is told which artifact never appeared.
    const thrown = (): string => {
      throw new Error('ENOENT');
    };
    expect(() =>
      requireBuildArtifact(
        thrown,
        'Production build missing the document sandbox (sandbox.html). Run: npm run build:client',
      ),
    ).toThrow(/document sandbox \(sandbox\.html\)/);
    expect(() => requireBuildArtifact(thrown, 'a')).not.toThrow(/client dist/);
  });

  it('returns the file untouched when the read succeeds', () => {
    // The pass-through, so the helper cannot become an unconditional throw and
    // still satisfy the two cases above.
    expect(requireBuildArtifact(() => '<!doctype html>', 'unused')).toBe('<!doctype html>');
  });
});
