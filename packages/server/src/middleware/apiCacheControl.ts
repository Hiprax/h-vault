import type { NextFunction, Request, Response } from 'express';

/**
 * Marks an API answer as one no cache may keep: `Cache-Control: no-store`, plus
 * `Pragma: no-cache` for HTTP/1.0 caches, which ignore `Cache-Control`.
 *
 * Every `/api/v1` answer is personal (a profile, a vault page, a wrapped key) or
 * describes this deployment, refusals included. `app.ts` mounts this at `/api/v1`
 * ahead of CORS, the body parsers, CSRF and every router, so an answer produced by
 * any of them carries it; a route that sets `no-store` itself (the document segment
 * stream, an invitation) agrees with it. The application says this itself rather
 * than leaving it to the inner Nginx's floor, because the PM2 path has no inner
 * Nginx.
 *
 * A NAMED function on purpose: `tests/support/routeTable.ts` admits a path-scoped
 * middleware at `/api/v1` only under this name, so an anonymous handler mounted
 * there (which would answer requests no route row covers) is still reported.
 */
export function apiNoStore(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
}
