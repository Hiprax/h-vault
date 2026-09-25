import express from 'express';
import crypto from 'node:crypto';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { ServerResponse } from 'node:http';
import hppx from 'hppx';
import passport from 'passport';
import { createErrorMiddleware } from '@hiprax/errors';
import { createRequestLogger } from '@hiprax/logger';
import { createModuleLogger } from './utils/logger.js';
import { config } from './config/index.js';
import {
  CLIENT_PUBLIC_DIR,
  readApplicationShell,
  readSandboxDocument,
} from './config/clientArtifacts.js';
import {
  applySandboxAssetHeaders,
  createSandboxDocumentHandler,
  requireBuildArtifact,
} from './config/sandboxCsp.js';
import { APPLICATION_PERMISSIONS_POLICY } from './config/permissionsPolicy.js';
import { doubleCsrfProtection, csrfTokenHandler } from './middleware/csrf.js';
import { csrfLimiter, metricsLimiter } from './middleware/rateLimiter.js';
import { sanitizeRequestBody } from './middleware/sanitizeBody.js';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './config/swagger.js';
import { warnIfSwaggerEnabledInProduction } from './utils/swaggerWarning.js';
// Passport strategy is configured as a side effect when auth middleware is imported
import './middleware/auth.js';

// Import routes
import authRoutes from './routes/auth.js';
import vaultRoutes from './routes/vault.js';
import documentRoutes from './routes/documents.js';
import folderRoutes from './routes/folders.js';
import userRoutes from './routes/user.js';
import toolsRoutes from './routes/tools.js';
import backupRoutes from './routes/backup.js';
import healthRoutes from './routes/health.js';
import configRoutes from './routes/config.js';
import { getMetrics } from './controllers/metricsController.js';

const app = express();

// Trust proxy for deployments behind reverse proxy (Nginx, AWS ALB, Docker).
// Ensures req.ip reflects the real client IP for rate limiting and audit logging.
if (config.TRUST_PROXY) {
  app.set('trust proxy', config.TRUST_PROXY);
}

// Generate per-request CSP nonce
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Security middleware — configured once; nonce is injected dynamically per request
app.use(
  helmet({
    // `useDefaults` is deliberately left unset, and helmet reads that as `true`:
    // the directives below are MERGED over
    // `helmet.contentSecurityPolicy.getDefaultDirectives()`. Five directives
    // this object never names therefore reach every response but
    // `/sandbox.html` from helmet alone — that one route replaces the header
    // outright with its own far stricter policy (`config/sandboxCsp.ts`) —
    // namely `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'self'`,
    // `script-src-attr 'none'` and `upgrade-insecure-requests` — and the first
    // three have no `default-src` fallback, so losing them is a real hole
    // rather than a downgrade. Writing `useDefaults: false` here is a one-word
    // change that removes all five while every directive named below still
    // ships unchanged, which is why the policy is pinned from the OUTSIDE
    // instead: `tests/security-headers.test.ts` asserts each of the five on a
    // real app response, and compares the whole parsed policy against a
    // literal so that DELETING a key below is caught too — dropping `fontSrc`,
    // for instance, silently reverts `font-src` to helmet's looser
    // `'self' https: data:`. Naming a directive below overrides the default of
    // that same name; it does not disable the others.
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          (_req, res) =>
            `'nonce-${(res as ServerResponse & { locals: Record<string, string> }).locals.cspNonce}'`,
          // 'wasm-unsafe-eval' permits WebAssembly compilation ONLY (it does NOT
          // enable JS eval/new Function like the broader 'unsafe-eval'). It is
          // required by the File Encryption tool: @hiprax/crypto's browser
          // Argon2id runs via hash-wasm, which compiles an inline-embedded WASM
          // module. Without this directive the compile fails with a CSP
          // CompileError. hash-wasm instantiates from inline base64 bytes, so no
          // connect-src/worker-src entry or network fetch is needed.
          "'wasm-unsafe-eval'",
        ],
        // 'unsafe-inline' is the accepted trade-off for SPAs: first-party CSS is
        // served from 'self' via <link> tags, but runtime style injection by
        // third-party components (e.g. component libraries) requires inline
        // styles.  Nonces only work for server-injected <style> tags and are
        // redundant for static CSS files loaded via <link>.
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        // Web Workers are same-origin bundled files (the Vault Health page runs
        // zxcvbn password-strength scoring off the main thread in a worker). This
        // is set explicitly so worker loading is decoupled from `script-src` (a
        // future tightening of `script-src` must not silently break the worker);
        // it stays 'self' only, and the worker is a plain bundled file — never a
        // `blob:` (which would require loosening this to `blob:`).
        workerSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'none'"],
        // The application frames exactly one document: `/sandbox.html`, the
        // isolated renderer every stored document's bytes are handed to. That
        // document is same-origin BY URL (its opaque origin comes from the
        // iframe's `sandbox` attribute, not from where it was fetched), so
        // 'self' is the whole of what this needs. NEVER `blob:`, `data:` or a
        // wildcard: those would let an injected iframe carry its own contents
        // and inherit this page's CSP, which is the opposite of the isolation
        // the sandbox exists for. The sandbox document's OWN, far stricter
        // policy is `config/sandboxCsp.ts` and is attached by the route that
        // serves it — a document fetched from an http(s) URL does not inherit
        // its embedder's policy.
        frameSrc: ["'self'"],
      },
    },
    // COEP disabled: no SharedArrayBuffer/cross-origin isolation needed;
    // enabling would block third-party fonts/icons
    crossOriginEmbedderPolicy: false,
  }),
);

// The Permissions-Policy helmet cannot send (it has no option for one). Set on
// every response, before any route and before the static mount, because both
// nginx layers in front of a deployment add the golden floor (which denies the
// camera) to any response that arrives without one, and the authenticator
// import's camera scan runs in the documents this server renders. Why this value,
// and why the isolated document gets a stricter one of its own:
// `config/permissionsPolicy.ts`.
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Permissions-Policy', APPLICATION_PERMISSIONS_POLICY);
  next();
});

app.use(
  cors({
    origin: config.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token', 'x-metrics-token'],
  }),
);

// Body parsing — 2 MB default limit. Routes that need larger payloads (e.g., backup
// restore, vault key rotation) apply a route-specific body parser with a higher
// limit. The global parser skips those routes so the route-level parser can handle
// them instead. Keep this set in sync with the route-level parser that owns each path
// (`parseLargeJsonBody` in middleware/largeBodyAdmission.ts, mounted by routes/backup.ts
// and routes/vault.ts behind their limiter and admission slot, and followed there by
// `sanitizeRequestBody`, because the app-level sanitizer below runs before it).
const CUSTOM_BODY_LIMIT_PATHS = new Set<string>([
  '/api/v1/backup/restore',
  '/api/v1/vault/items/bulk-reencrypt',
]);
const globalJsonParser = express.json({ limit: '2mb' });
/**
 * `req.path` the way the router MATCHES it: case-insensitively, with one optional
 * trailing slash, which is how an Express router matches unless told otherwise.
 * Compared raw, `/api/v1/Backup/Restore/` reaches the restore handler while missing
 * the set above, and its body is parsed here, before authentication and the route's
 * own limiter.
 */
function routedPath(path: string): string {
  const lower = path.toLowerCase();
  return lower.length > 1 && lower.endsWith('/') ? lower.slice(0, -1) : lower;
}
app.use((req: Request, res: Response, next: NextFunction) => {
  // Skip global body parsing for routes with custom body size limits
  if (CUSTOM_BODY_LIMIT_PATHS.has(routedPath(req.path))) {
    next();
    return;
  }
  globalJsonParser(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie parsing
app.use(cookieParser());

// MongoDB operator injection and prototype-pollution prevention, over every body the
// global parser above produced. This mount does NOT cover the routes in
// `CUSTOM_BODY_LIMIT_PATHS`: their body is still unparsed here, so each of them
// mounts the same middleware again straight after its own parser, and
// `tests/route-table.test.ts` fails any route-level JSON parser that is not followed
// by it. See `middleware/sanitizeBody.ts` for why only the body is filtered.
app.use(sanitizeRequestBody);

// HTTP Parameter Pollution protection
app.use(
  hppx({
    whitelist: ['tags', 'ids'],
    mergeStrategy: 'keepLast',
    sources: ['query', 'body'],
  }),
);

// Passport
app.use(passport.initialize());

// Request logging
app.use(
  createRequestLogger({
    // The HTTP logger is built HERE rather than left to `createRequestLogger`'s
    // own default. That default is `createLogger({ moduleName: 'http' })` — the
    // bare call, with @hiprax/logger's `<cwd>/logs` directory and both rotating
    // file transports on — so leaving it out would reintroduce, on the single
    // busiest logger in the process, exactly what `utils/logger.ts` exists to
    // route through one place.
    logger: createModuleLogger('http'),
    // Every credential and every piece of wrapped key material a request body can
    // carry. This list is NOT maintained by hand-audit alone:
    // `tests/request-logger-masking.test.ts` reads every schema the routes validate
    // a body with and fails on any field that is neither listed here nor named, with
    // a reason, as not secret. Adding a request field means deciding which it is.
    maskBodyKeys: [
      'password',
      'authHash',
      'masterPassword',
      'encryptedVaultKey',
      'twoFactorSecret',
      'backupCodes',
      'pendingTwoFactorSecret',
      'newAuthHash',
      'currentAuthHash',
      'newEncryptedVaultKey',
      // The rotation wrapper a password change carries across: a vault key sealed
      // under the new MEK, exactly as `newEncryptedVaultKey` is.
      'newPendingEncryptedVaultKey',
      'encryptedBWK',
      'newEncryptedBWK',
      // The vault key sealed under the backup key, which is what a cross-account
      // restore unwraps, in both the setup and the backup-password-change bodies.
      'bwkEncryptedVaultKey',
      'newBwkEncryptedVaultKey',
      // The wrapped document key. It crosses the wire TWICE — at upload init and
      // again at completion, which is what makes a stale-vault-key 409
      // recoverable without re-sending the file — and it is logged nowhere.
      'encryptedDek',
      // The password-reset / email-verification / account-unlock JWT, the signed
      // 2FA challenge, and a TOTP or backup code: each completes an
      // authentication step on its own.
      'token',
      'tempToken',
      'code',
      // A restore's entire backup file, as ONE JSON string. It carries
      // `encryptedVaultKey`, `encryptedBWK` and `bwkEncryptedVaultKey` inside it,
      // near the start, where key-by-key masking cannot reach: the string is masked
      // whole. Today that is a second line of defence, not the first: the logger
      // takes `req.body` when the request ARRIVES, and the restore body is parsed
      // later, by its own route-level parser, so no restore body is captured at all.
      // The mask is what keeps that true if the parser ever moves ahead of it.
      'data',
    ],
    skip: (req) => {
      // Skip request logging for health probes. The logger's LoggableRequest
      // exposes url / originalUrl (not Express's `path`), so strip any query
      // string ourselves to compare the pathname.
      const rawUrl = req.originalUrl ?? req.url ?? '';
      const pathname = rawUrl.split('?')[0] ?? '';
      return pathname === '/api/v1/health';
    },
    // createRequestLogger returns @hiprax/logger's framework-agnostic
    // LoggableMiddleware (express is only an optional peer of the logger), so
    // bridge it to Express's RequestHandler at the mount site. It is runtime-
    // compatible: Express invokes it as (req, res, next).
  }) as unknown as RequestHandler,
);

// CSRF protection for cookie-based state-changing requests
app.use(doubleCsrfProtection);

// CSRF token endpoint
app.get('/api/v1/csrf-token', csrfLimiter, csrfTokenHandler);

// API documentation (Swagger UI) — available in development/test or when explicitly enabled
if (config.NODE_ENV !== 'production' || config.ENABLE_SWAGGER) {
  // Surface a warning in operator logs when API docs are exposed in production.
  warnIfSwaggerEnabledInProduction(config, createModuleLogger('app'));
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.get('/api/v1/docs.json', (_req: Request, res: Response) => {
    res.json(swaggerSpec);
  });
}

// API routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/vault', vaultRoutes);
app.use('/api/v1/documents', documentRoutes);
app.use('/api/v1/folders', folderRoutes);
app.use('/api/v1/user', userRoutes);
app.use('/api/v1/tools', toolsRoutes);
app.use('/api/v1/backup', backupRoutes);
app.use('/api/v1', healthRoutes);
app.use('/api/v1', configRoutes);

// Metrics endpoint — requires METRICS_TOKEN env var to be set (token-based auth).
// When METRICS_TOKEN is not configured, the endpoint is not registered (returns 404).
// Rate-limited like /health so the unauthenticated endpoint cannot be flooded
// or used for unlimited token-guess attempts.
if (config.METRICS_TOKEN) {
  app.get('/api/v1/metrics', metricsLimiter, getMetrics);
}

// Serve static files in production
if (config.NODE_ENV === 'production') {
  // Read both HTML documents once at startup, BEFORE anything is mounted, so a
  // build missing either of them fails loudly at boot rather than 404ing one
  // route in production. `sandbox.html` is emitted by its own Vite build
  // (`packages/client/vite.config.sandbox.ts`), which runs after the app build
  // and writes OUTSIDE the static root — see `config/clientArtifacts.ts`, which
  // owns both locations, both reads, and the reason they are two directories.
  const indexHtml = requireBuildArtifact(
    readApplicationShell,
    'Production build missing client dist. Run: npm run build:client',
  );
  const sandboxHtml = requireBuildArtifact(
    readSandboxDocument,
    // Names the STAGING step and not just the build, because on the pm2 path the
    // build is almost certainly not what is missing: `npm run build:client`
    // writes the document to `packages/client/dist-sandbox/`, and something has to
    // copy it to `packages/server/sandbox-document/` (the Dockerfile does; a
    // bare-metal deployment does it by hand, exactly as it already copies
    // `packages/client/dist` to `packages/server/public`). Telling an operator to
    // re-run a build they have just run, while the file sits on disk one
    // directory away, is a message that sends them the wrong way.
    'Production build missing the document sandbox (sandbox.html). Run: npm run build:client, ' +
      'then copy packages/client/dist-sandbox to packages/server/sandbox-document',
  );

  // The isolated render document.
  //
  // Its whole isolation is a per-RESPONSE policy: a copy of this file answered
  // off disk by the static middleware would carry helmet's application policy
  // instead, which permits `connect-src 'self'` and a nonce'd script — i.e. the
  // isolation would quietly stop existing while every renderer kept working.
  //
  // What makes that impossible is the LAYOUT, not this line's position. The
  // document is read from a directory `express.static` does not serve, so
  // static cannot answer for it under any spelling. That distinction is
  // measured, not defensive: Express 5 matches the RAW pathname while `send`
  // decodes and normalises it, so `/sandbox%2Ehtml`, `//sandbox.html`,
  // `/sandbox.htm%6C` and `/%73andbox.html` all MISS this route — and while the
  // file sat in the static root, all four were answered off disk with helmet's
  // policy instead of the sandbox's. (An earlier comment here claimed the SPA
  // catch-all absorbed them; it does not get the chance while static holds a
  // copy. It does now, and that is what those four spellings reach.) The route
  // still claims `/SANDBOX.HTML` for free, because Express matches
  // case-insensitively. Nginx has always had the same argument made for it, the
  // other way round: the Docker `web-root` stage DELETED the file from its
  // document root. With the build no longer emitting it there, that deletion is
  // defence in depth against a stale copy, and this is the Express side.
  //
  // The handler and the asset-header hook below both live in `config/
  // sandboxCsp.ts`. That is not tidiness: this whole block is unreachable from
  // an ordinary server test — `app.ts` is imported with `NODE_ENV=test` — so
  // anything written inline here is production code that no assertion in that
  // tier can reach. Extracted, the policy, the three response headers, the
  // directory predicate and now both artifact locations are pinned directly.
  app.get('/sandbox.html', createSandboxDocumentHandler(sandboxHtml));

  app.use(express.static(CLIENT_PUBLIC_DIR, { setHeaders: applySandboxAssetHeaders }));

  app.get(/^(?!\/api\/).*/, (_req, res) => {
    const nonce = res.locals.cspNonce as string;
    // Match <script followed by whitespace or > to avoid false positives
    // in attribute values, strings, or comments
    const html = indexHtml.replace(/<script(?=[\s>])/gi, `<script nonce="${nonce}"`);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  });
}

// Error handling (must be last)
// exposeServerErrors:false redacts 5xx messages to the generic status text in
// production only (CWE-209); 4xx and non-production responses are unaffected,
// and the original error stays reachable to loggers via err.cause.
app.use(createErrorMiddleware({ exposeServerErrors: false }));

export default app;
