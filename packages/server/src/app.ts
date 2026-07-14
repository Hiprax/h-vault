import express from 'express';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { ServerResponse } from 'node:http';
import hppx from 'hppx';
import passport from 'passport';
import { createErrorMiddleware } from '@hiprax/errors';
import { createLogger, createRequestLogger } from '@hiprax/logger';
import { config } from './config/index.js';
import { doubleCsrfProtection, csrfTokenHandler } from './middleware/csrf.js';
import { csrfLimiter, metricsLimiter } from './middleware/rateLimiter.js';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './config/swagger.js';
import { warnIfSwaggerEnabledInProduction } from './utils/swaggerWarning.js';
// Passport strategy is configured as a side effect when auth middleware is imported
import './middleware/auth.js';

// Import routes
import authRoutes from './routes/auth.js';
import vaultRoutes from './routes/vault.js';
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
        objectSrc: ["'none'"],
        mediaSrc: ["'none'"],
        frameSrc: ["'none'"],
      },
    },
    // COEP disabled: no SharedArrayBuffer/cross-origin isolation needed;
    // enabling would block third-party fonts/icons
    crossOriginEmbedderPolicy: false,
  }),
);

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
// them instead. Keep this set in sync with the route-level parsers that own each path
// (see routes/backup.ts and routes/vault.ts).
const CUSTOM_BODY_LIMIT_PATHS = new Set<string>([
  '/api/v1/backup/restore',
  '/api/v1/vault/items/bulk-reencrypt',
]);
const globalJsonParser = express.json({ limit: '2mb' });
app.use((req: Request, res: Response, next: NextFunction) => {
  // Skip global body parsing for routes with custom body size limits
  if (CUSTOM_BODY_LIMIT_PATHS.has(req.path)) {
    next();
    return;
  }
  globalJsonParser(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie parsing
app.use(cookieParser());

// MongoDB injection prevention (custom middleware — express-mongo-sanitize is incompatible with Express 5)
function sanitizeValue(val: unknown): unknown {
  if (typeof val === 'string') return val;
  if (val === null || val === undefined) return val;
  if (Array.isArray(val)) return val.map(sanitizeValue);
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    const clean: Record<string, unknown> = {};
    for (const key of Object.keys(obj)) {
      // Strip MongoDB operator injection keys and prototype pollution vectors
      if (
        key.startsWith('$') ||
        key === '__proto__' ||
        key === 'constructor' ||
        key === 'prototype'
      )
        continue;
      clean[key] = sanitizeValue(obj[key]);
    }
    return clean;
  }
  return val;
}
app.use((_req: Request, _res: Response, next: NextFunction) => {
  if (_req.body && typeof _req.body === 'object') {
    _req.body = sanitizeValue(_req.body);
  }
  // Note: We only sanitize req.body because it is the only source of nested
  // user-controlled objects.
  //
  // - Route params are always plain strings (no nested objects possible).
  // - Query params CAN contain nested objects via bracket syntax in Express 4
  //   (e.g. ?tags[$ne]=foo), but Express 5's default query parser ("simple")
  //   does NOT parse bracket notation — it treats them as literal characters,
  //   so operator injection via query strings is not possible.
  // - Zod validation on all endpoints catches any unexpected shapes downstream
  //   as a defense-in-depth measure.
  //
  // Additionally, req.query and req.params are read-only getters in Express 5.
  next();
});

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
      'encryptedBWK',
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
  warnIfSwaggerEnabledInProduction(config, createLogger({ moduleName: 'app' }));
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.get('/api/v1/docs.json', (_req: Request, res: Response) => {
    res.json(swaggerSpec);
  });
}

// API routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/vault', vaultRoutes);
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
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const publicPath = path.resolve(__dirname, '..', 'public');
  app.use(express.static(publicPath));

  // Read HTML once at startup; inject per-request CSP nonce into script tags
  let indexHtml: string;
  try {
    indexHtml = readFileSync(path.join(publicPath, 'index.html'), 'utf-8');
  } catch {
    throw new Error('Production build missing client dist. Run: npm run build:client');
  }
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
