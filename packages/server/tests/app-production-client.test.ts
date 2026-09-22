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
 * where this feature's isolation is won or lost: the isolated document's entire
 * containment is the per-response Content-Security-Policy the route attaches, so
 * a copy answered off disk by `express.static` carries helmet's application
 * policy instead and the isolation quietly stops existing while every renderer
 * keeps working.
 *
 * ## How it reaches that block, and why this is the sanctioned shape
 *
 * A HOISTED `vi.mock` of the config module reports production, exactly as
 * `coverage-rate-limiter.test.ts` does. It must be hoisted rather than
 * `vi.resetModules()` + `vi.doMock`: resetting the registry re-evaluates
 * `models/User.ts` against the externalised mongoose singleton, which throws
 * `OverwriteModelError` on the second `mongoose.model('User')`.
 *
 * ## The filesystem is REAL here, and that is the whole point
 *
 * An earlier version of this file mocked `node:fs`'s `readFileSync` so the two
 * documents could be supplied without writing into the checkout. That covered
 * the two READS and nothing else — `express.static` does not use `readFileSync`,
 * it stats and streams — so the static mount had no files to find and every
 * question about what it can serve answered itself vacuously. It is exactly the
 * question that matters: four URL spellings miss the Express route and reach
 * static, and while the document sat in the static root all four were answered
 * off disk with the wrong policy.
 *
 * So instead of mocking the filesystem, this file RE-ROOTS the real layout into
 * a temporary directory: `config/clientArtifacts.ts` is mocked with the same two
 * paths it really exports, rebased from the server package root onto a
 * `mkdtemp`. Nothing is written into the repository, `readFileSync` and
 * `express.static` are both real, and — the part that makes this a test rather
 * than a fixture — the temporary tree MIRRORS the production relationship
 * instead of restating it. Move the sandbox document back inside `public/` and
 * the fixture puts it back inside the temporary static root, where static finds
 * it again and the four spellings below go red.
 */
import { afterAll, describe, it, expect, vi } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';

/**
 * Filled in by the `clientArtifacts` factory below, read by the tests.
 *
 * A `vi.hoisted` box rather than plain module state because `vi.mock` factories
 * are hoisted above every import; the box holds no module reference of its own,
 * so it is safe up there, and the factory that fills it runs later — after the
 * imports it needs have been evaluated.
 */
const staged = vi.hoisted(() => {
  /** The marker that says a response body IS the isolated render document. */
  const marker = 'data-hvault-sandbox-document';
  return {
    /** The temporary stand-in for the server package root. */
    root: '',
    /** The temporary `express.static` root. */
    publicDir: '',
    /** Where the isolated document was written, wherever production puts it. */
    sandboxPath: '',
    marker,
    sandboxHtml:
      `<!doctype html><html><body ${marker}><div id="root"></div>` +
      '<script type="module" crossorigin src="/sandbox-assets/sandbox-abc123.js">' +
      '</script></body></html>',
    indexHtml:
      '<!doctype html><html><head><script src="/assets/main-abc123.js"></script></head></html>',
    /** A real file under the static root, so "static is mounted" is not an assumption. */
    assetBody: 'export const sandbox = 1;\n',
  };
});

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true, config: { ...actual.config, NODE_ENV: 'production' } };
});

vi.mock('../src/config/clientArtifacts.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/clientArtifacts.js')>();

  // The real layout, rebased. `CLIENT_PUBLIC_DIR` is `<serverPkg>/public`, so its
  // parent IS the package root; every other artifact path is expressed relative
  // to that and re-joined onto the temporary one. Nothing here restates WHERE the
  // sandbox document lives — it follows whatever the module says.
  const serverRoot = path.dirname(actual.CLIENT_PUBLIC_DIR);
  const rebase = (absolute: string): string =>
    path.join(staged.root, path.relative(serverRoot, absolute));

  staged.root = mkdtempSync(path.join(tmpdir(), 'hvault-production-block-'));
  staged.publicDir = rebase(actual.CLIENT_PUBLIC_DIR);
  staged.sandboxPath = rebase(actual.SANDBOX_DOCUMENT_PATH);

  // `app.ts` reads both documents at module scope, so they have to exist before
  // it is imported — which is why the tree is written by the factory rather than
  // by a `beforeAll` that would run far too late.
  mkdirSync(path.join(staged.publicDir, 'sandbox-assets'), { recursive: true });
  mkdirSync(path.dirname(staged.sandboxPath), { recursive: true });
  writeFileSync(path.join(staged.publicDir, 'index.html'), staged.indexHtml);
  writeFileSync(
    path.join(staged.publicDir, 'sandbox-assets', 'sandbox-abc123.js'),
    staged.assetBody,
  );
  writeFileSync(staged.sandboxPath, staged.sandboxHtml);

  // The two readers are re-pointed as well, because `app.ts` calls THEM rather
  // than joining a path itself: `eslint-plugin-security` can only verify a
  // filename it can trace to literals inside one module, so the read lives beside
  // the constant that builds its path. Each stub is one `readFileSync` of one
  // staged file and restates no production logic; that the REAL readers read
  // exactly the paths their constants name is pinned in
  // `tests/client-artifacts.test.ts`, where a mocked `readFileSync` records the
  // argument.
  return {
    ...actual,
    CLIENT_PUBLIC_DIR: staged.publicDir,
    SANDBOX_DOCUMENT_DIR: path.dirname(staged.sandboxPath),
    SANDBOX_DOCUMENT_PATH: staged.sandboxPath,
    APPLICATION_SHELL_PATH: path.join(staged.publicDir, 'index.html'),
    readApplicationShell: () => readFileSync(path.join(staged.publicDir, 'index.html'), 'utf-8'),
    readSandboxDocument: () => readFileSync(staged.sandboxPath, 'utf-8'),
  };
});

// Static, not a top-level dynamic import: a dynamically-imported module inside a
// mocked graph is attributed to a separate V8 coverage entry, and the merge then
// drops the file from the package report entirely.
import app from '../src/app.js';
import { requireBuildArtifact, SANDBOX_CSP_HEADER } from '../src/config/sandboxCsp.js';
// The canonical list of URL spellings that miss the sandbox route, shared with
// `test:smoke` and `test:deploy`. `clean-room.test.ts` already reaches into the
// same module from this tier, so the import path is an established one.
import { SANDBOX_BYPASS_SPELLINGS } from '../../../scripts/ci/lib/sandbox-headers.mjs';

// Readable aliases for the fixtures. They live in the hoisted box because the
// mock factory needs them and runs during `import app` — i.e. before any
// statement in this module body — so a top-level `const` would still be in its
// temporal dead zone when the factory reached for it (measured: `ReferenceError:
// Cannot access 'INDEX_HTML' before initialization`).
const SANDBOX_DOCUMENT_MARKER = staged.marker;
const SANDBOX_ASSET_BODY = staged.assetBody;

afterAll(() => {
  rmSync(staged.root, { recursive: true, force: true });
});

describe('the production block mounts the client and the isolated document', () => {
  it('serves the sandbox document from Express, not from the static directory', async () => {
    const response = await request(app).get('/sandbox.html');

    expect(response.status).toBe(200);
    expect(response.text).toContain(SANDBOX_DOCUMENT_MARKER);
    // The WHOLE policy, not a substring of it: `connect-src 'none'` is one
    // appended word away from being widened, and `toContain` stays green through
    // `connect-src 'none' https:`.
    expect(response.headers['content-security-policy']).toBe(SANDBOX_CSP_HEADER);
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
    expect(response.text).toContain(SANDBOX_DOCUMENT_MARKER);
    expect(response.headers['content-security-policy']).toBe(SANDBOX_CSP_HEADER);
  });

  it('really has express.static mounted over a real directory', async () => {
    // The guard that stops every assertion below being vacuous. `express.static`
    // stats and streams; it never calls `readFileSync`. A harness that supplied
    // the two documents through a mocked `readFileSync` therefore left the static
    // root EMPTY, and "static did not serve the sandbox document" was true for
    // the one reason that proves nothing.
    const response = await request(app).get('/sandbox-assets/sandbox-abc123.js');

    expect(response.status).toBe(200);
    expect(response.text).toBe(SANDBOX_ASSET_BODY);
    // Served off disk by the static mount, so its `setHeaders` hook ran: the two
    // headers a module script fetched from an opaque origin needs.
    expect(response.headers['access-control-allow-origin']).toBe('*');
    expect(response.headers['cross-origin-resource-policy']).toBe('cross-origin');
    // Not the SPA fallback wearing an asset's URL.
    expect(response.headers['content-type']).not.toMatch(/text\/html/);
  });

  describe('no URL spelling delivers the isolated document without its policy', () => {
    // Express 5 matches the RAW, undecoded pathname; `send` (inside
    // `express.static`) decodes and normalises before touching the filesystem.
    // These four therefore MISS the route, and while `sandbox.html` sat in the
    // static root all four were answered off disk carrying helmet's APPLICATION
    // policy — `connect-src 'self'`, a nonce'd script, `frame-src 'self'` — which
    // is the isolation silently ceasing to exist while every renderer keeps
    // working. Measured, not theorised; the transcript is in the plan for this
    // change and reproduced by this block.
    // The list is IMPORTED from the gate library rather than restated, which is
    // the same one-definition discipline the repository applies to
    // `unlockedLayoutMarker` and `connectSandbox`. `test:smoke` and `test:deploy`
    // already ask these spellings from there; a private copy here meant a sixth
    // spelling added to the shared list would never reach the FAST tier — the only
    // one that runs on every push — and the regression would surface at T1 or T2,
    // or not at all if neither gate could run.
    //
    // The traversal probe is the one entry this block handles separately: it is a
    // `send` property rather than a route-matching one, and it has its own case
    // with its own reasoning below.
    const missesTheRoute = SANDBOX_BYPASS_SPELLINGS.filter((s) => !s.includes('..'));

    it('asks every spelling the wire gates ask, and no fewer', () => {
      // Guards the guard: a `filter` that silently matched nothing — or a shared
      // list that shrank — would make the loop below vacuous.
      expect(missesTheRoute).toEqual([
        '/sandbox%2Ehtml', // the dot, percent-encoded
        '//sandbox.html', // an empty leading path segment
        '/sandbox.htm%6C', // the trailing "l", percent-encoded
        '/%73andbox.html', // the leading "s", percent-encoded
      ]);
      // And the traversal probe really is the only thing the filter removed.
      expect(SANDBOX_BYPASS_SPELLINGS).toHaveLength(missesTheRoute.length + 1);
    });

    for (const spelling of missesTheRoute) {
      it(`answers ${spelling} without handing out the sandbox document`, async () => {
        const response = await request(app).get(spelling);

        // The document is not on the wire AT ALL, which is stronger than "not
        // without its policy" and is what the layout now guarantees: static has
        // no copy to stream, so the request cannot be answered with one.
        //
        // The two wire gates judge the SAME spellings by the looser rule — "not
        // the document, OR the document with its whole policy"
        // (`sandboxBypassProblems`) — and that difference is deliberate rather
        // than a relaxation. Supertest hands Express the raw spelling, so nothing
        // can normalise it and the document must never come back; through Nginx,
        // `try_files $uri @app` matches on the DECODED `$uri`, so a spelling may
        // legitimately arrive at Express as `/sandbox.html` and be answered by
        // the route, policy and all. Tightening the gates to this rule would fail
        // on a correct deployment.
        expect(response.text).not.toContain(SANDBOX_DOCUMENT_MARKER);

        // And the positive half, so this cannot be satisfied by the route
        // disappearing or by the server erroring: the spelling is answered the
        // way any other unknown path is — the application shell, under helmet's
        // own policy, with its per-request nonce.
        expect(response.status).toBe(200);
        expect(response.text).toMatch(/<script nonce="[^"]+"/);
        const policy = String(response.headers['content-security-policy']);
        expect(policy).toContain("frame-src 'self'");
        expect(policy).not.toContain("connect-src 'none'");
      });
    }

    it('does not follow an encoded traversal out of the static root', async () => {
      // The FIX introduced this dependency, so the fix has to assert it. The
      // document now sits exactly one `..` outside the static root, so
      // containment also leans on `send`'s traversal guard: it decodes the path
      // first, then refuses any `..` segment with a 403, with or without a
      // `root`. That is a library property this repository does not own.
      //
      // What reaches the client is NOT that 403, and the difference was measured
      // rather than assumed. `serve-static` runs with `fallthrough` on, and its
      // stream error handler calls bare `next()` for any `statusCode < 500`
      // (node_modules/serve-static/index.js) — so the refusal becomes a
      // fall-through and the SPA catch-all answers 200 with the shell, exactly as
      // it does for the four spellings above. That is the right outcome and it is
      // asserted as what it is: the guard is proven by the document NOT arriving,
      // not by a status code the application layer never emits.
      const response = await request(app).get('/..%2fsandbox-document%2fsandbox.html');

      expect(response.text).not.toContain(SANDBOX_DOCUMENT_MARKER);
      expect(response.status).toBe(200);
      expect(response.text).toMatch(/<script nonce="[^"]+"/);
      expect(String(response.headers['content-security-policy'])).not.toContain(
        "connect-src 'none'",
      );
    });

    // The other half of the measurement, and the half that keeps the four above
    // honest. Express normalises DOT SEGMENTS before matching, so these two DO
    // reach the route — which means "the document is unreachable" is not what is
    // being asserted, and a fix that simply broke `/sandbox.html` for everybody
    // would fail here rather than read as an improvement above.
    for (const spelling of ['/./sandbox.html', '/foo/../sandbox.html']) {
      it(`serves ${spelling} from the route, with the whole policy`, async () => {
        const response = await request(app).get(spelling);

        expect(response.status).toBe(200);
        expect(response.text).toContain(SANDBOX_DOCUMENT_MARKER);
        expect(response.headers['content-security-policy']).toBe(SANDBOX_CSP_HEADER);
      });
    }
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

  it('tells the operator to STAGE the sandbox document, not just to build it', () => {
    // The message `app.ts` actually passes, read from the source rather than
    // restated, because what matters is the sentence an operator sees at boot.
    //
    // On the pm2 path the build is almost never what is missing: `build:client`
    // writes the document to `packages/client/dist-sandbox/`, and something has to
    // copy it to `packages/server/sandbox-document/` — the Dockerfile does, a
    // bare-metal deployment does it by hand. "Run npm run build:client" alone
    // sends an operator to re-run a build they have just run while the file sits
    // one directory away.
    const appSource = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'app.ts'),
      'utf8',
    );
    const message = /'Production build missing the document sandbox[\s\S]{0,400}?\);/.exec(
      appSource,
    );
    expect(message).not.toBeNull();
    expect(message?.[0]).toContain('dist-sandbox');
    expect(message?.[0]).toContain('packages/server/sandbox-document');
  });

  it('returns the file untouched when the read succeeds', () => {
    // The pass-through, so the helper cannot become an unconditional throw and
    // still satisfy the two cases above.
    expect(requireBuildArtifact(() => '<!doctype html>', 'unused')).toBe('<!doctype html>');
  });
});
