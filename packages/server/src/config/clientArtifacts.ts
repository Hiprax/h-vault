import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Where the two documents the production block serves live on disk.
 *
 * ---------------------------------------------------------------------------
 * WHY THEY ARE TWO DIRECTORIES AND NOT ONE
 * ---------------------------------------------------------------------------
 *
 * {@link CLIENT_PUBLIC_DIR} is the `express.static` root: the whole client
 * build, every hashed chunk, every icon. {@link SANDBOX_DOCUMENT_PATH} is the
 * isolated render document, and it is deliberately a SIBLING of that root
 * rather than a file inside it.
 *
 * That separation is the sandbox's isolation, and it is structural on purpose.
 * The document's entire containment is the per-RESPONSE Content-Security-Policy
 * that `createSandboxDocumentHandler` attaches to it (`config/sandboxCsp.ts`):
 * `default-src 'none'`, `connect-src 'none'`, `worker-src 'none'` and `sandbox
 * allow-scripts`. A copy answered off disk by the static middleware carries
 * helmet's APPLICATION policy instead — `connect-src 'self'`, a nonce'd script,
 * `frame-src 'self'` — which is the one failure mode where every renderer keeps
 * working while the containment silently stops existing.
 *
 * Registering the route before the static mount is NOT enough, and that is a
 * measurement rather than a worry. Express 5 matches the RAW, undecoded
 * pathname, while `send` (inside `express.static`) decodes and normalises it
 * before touching the filesystem, so four spellings miss the route and are
 * answered by static off disk:
 *
 * ```text
 * /sandbox.html          200 | ROUTE  | sandbox allow-scripts; default-src 'none'
 * /sandbox%2Ehtml        200 | STATIC | (helmet's application policy)
 * //sandbox.html         200 | STATIC | (helmet's application policy)
 * /sandbox.htm%6C        200 | STATIC | (helmet's application policy)
 * /%73andbox.html        200 | STATIC | (helmet's application policy)
 * /./sandbox.html        200 | ROUTE  | sandbox allow-scripts; default-src 'none'
 * /foo/../sandbox.html   200 | ROUTE  | sandbox allow-scripts; default-src 'none'
 * ```
 *
 * Ordering is a control a URL SPELLING can walk around; absence is not. With
 * the document outside the static root, `express.static` cannot serve it under
 * any spelling, because it does not have it — and the four above fall through
 * to the SPA catch-all, which answers them with the application shell under
 * helmet's own policy, exactly as it answers any other unknown path. This is
 * the same argument the Docker `web-root` stage already makes for Nginx, where
 * the file is deleted from the document root instead of being routed around.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A MODULE OF ITS OWN
 * ---------------------------------------------------------------------------
 *
 * Everything inside `if (config.NODE_ENV === 'production')` in `app.ts` is
 * unreachable from every other server test, so a path computed inline there is
 * production code no assertion in this tier can reach — the same reason the
 * policy itself lives in `config/sandboxCsp.ts`. Extracted, two things become
 * possible: the sibling relationship is asserted directly
 * (`tests/client-artifacts.test.ts`), and `tests/app-production-client.test.ts`
 * can RE-ROOT this exact layout into a temporary directory and drive the real
 * app over it with a real filesystem, instead of mocking `node:fs` and proving
 * nothing about what static can reach.
 *
 * ---------------------------------------------------------------------------
 * WHY THE READS LIVE HERE TOO, AND NOT AT THE CALL SITE
 * ---------------------------------------------------------------------------
 *
 * `eslint-plugin-security`'s `detect-non-literal-fs-filename` accepts a filename
 * only when it can trace the WHOLE expression to literals INSIDE ONE MODULE: it
 * resolves an identifier through its local `const` initializer, and understands
 * `path.join`/`path.resolve`, `fileURLToPath` and `import.meta.url`. An IMPORTED
 * binding is not a local `const`, so `readFileSync(path.join(CLIENT_PUBLIC_DIR,
 * 'index.html'))` written in `app.ts` is reported (measured) — and this project
 * runs lint at `--max-warnings=0` and adds no analyzer suppressions.
 *
 * Keeping the read in the same module as the chain that builds its path is
 * therefore not a workaround; it is the arrangement the analyzer can actually
 * verify end to end, from `import.meta.url` to the filename. `app.ts` passes
 * these functions to `requireBuildArtifact`, which is a thunk-taker for exactly
 * this reason.
 */

/**
 * The server package root, resolved from this module rather than from
 * `process.cwd()`.
 *
 * Two levels up in both trees, which is why the same expression serves both:
 * `packages/server/dist/config/` in a production image and
 * `packages/server/src/config/` in a checkout.
 */
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * The `express.static` root: the client build, exactly as `vite build` emitted
 * it, minus the sandbox document.
 *
 * Populated by `docker/Dockerfile` (`COPY --from=build-client …/dist`) and by
 * `scripts/ci/smoke-gate.mjs`, which stages the same layout under a temporary
 * directory.
 */
export const CLIENT_PUBLIC_DIR = path.join(packageRoot, 'public');

/**
 * The directory holding the isolated render document, and NOTHING that is
 * served statically.
 *
 * A directory rather than a bare file so the build that produces it
 * (`packages/client/vite.config.sandbox.ts`, which writes
 * `packages/client/dist-sandbox/`) can be copied wholesale by one `COPY` and
 * one `cpSync`, and so the reason this is not inside `public/` has somewhere to
 * be written down.
 */
export const SANDBOX_DOCUMENT_DIR = path.join(packageRoot, 'sandbox-document');

/**
 * The isolated render document itself.
 *
 * Read once at boot; a build that never produced it fails the server loudly
 * rather than 404ing one route in production (`requireBuildArtifact`).
 */
export const SANDBOX_DOCUMENT_PATH = path.join(SANDBOX_DOCUMENT_DIR, 'sandbox.html');

/** The application shell, served by the SPA fallback with a per-request nonce. */
export const APPLICATION_SHELL_PATH = path.join(CLIENT_PUBLIC_DIR, 'index.html');

/**
 * Read the application shell off disk.
 *
 * Zero arguments and a literal filename, which is what lets the analyzer follow
 * the whole path. Called once, at boot, through `requireBuildArtifact`, which
 * turns a failed read into a message naming the artifact that is missing.
 */
export function readApplicationShell(): string {
  return readFileSync(path.join(CLIENT_PUBLIC_DIR, 'index.html'), 'utf-8');
}

/**
 * Read the isolated render document off disk.
 *
 * Deliberately reaches into {@link SANDBOX_DOCUMENT_DIR} rather than the static
 * root; that difference is the whole control this module exists to hold.
 */
export function readSandboxDocument(): string {
  return readFileSync(path.join(SANDBOX_DOCUMENT_DIR, 'sandbox.html'), 'utf-8');
}
