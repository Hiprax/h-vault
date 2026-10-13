import type { NextFunction, Request, Response } from 'express';
import { httpErrors } from '@hiprax/errors';

/** The refusal's message. Constant, and it names no route: the request reached none. */
export const CROSS_SITE_REQUEST_MESSAGE = 'Cross-site requests to the API are not accepted.';

/**
 * Refuses, with 403, every API request a browser marks `Sec-Fetch-Site: cross-site`.
 *
 * WHO SENDS ONE. The isolated document every stored file is rendered in holds an
 * OPAQUE origin, and an opaque origin is same-site with nothing, so every request
 * it causes arrives marked `cross-site`. Its policy (`config/sandboxCsp.ts`) gives
 * images and fonts no same-origin source, but `script-src` and `style-src` keep
 * `'self'` for the frame's own bundle and nothing stops a document navigating
 * itself, so a compromised renderer could still put `import('/api/v1/…')`, a
 * stylesheet link or a self-navigation on the wire. This is the CLASS control for
 * all of them, and for any other page on another site: no API handler runs for a
 * request a browser says came from another site. The policy is the first layer;
 * this is the one that does not depend on which element made the request.
 *
 * WHO NEVER DOES. The application's own calls are `same-origin` (in development
 * too: the Vite server proxies `/api` from the page's own origin); a typed address
 * is `none`; a sibling subdomain is `same-site`. A client that is not a browser —
 * a health probe, a metrics scraper, the smoke gate, a test — sends no header and
 * passes, which is correct: the header is a browser's statement about its own
 * request, and its ABSENCE proves nothing either way. A cross-site deployment of
 * the client was never possible anyway, because every session cookie is
 * `SameSite=Strict` in production.
 *
 * THE SITE, NEVER THE DESTINATION. A `Sec-Fetch-Dest` rule ("refuse images")
 * would miss the requests the frame's policy cannot stop (module scripts,
 * stylesheets, navigations), and every new destination would be a new hole.
 *
 * A browser sends Fetch Metadata only to a potentially trustworthy URL (HTTPS,
 * or loopback), so on a plain-HTTP deployment this floor is inert; every
 * supported deployment terminates TLS in front of the application.
 *
 * Mounted by `app.ts` at `/api/v1`, right after `apiNoStore` and ahead of CORS,
 * the parsers, CSRF and every router: a refusal is never cached, a cross-site
 * preflight is refused before `cors` would answer it, and nothing is parsed for a
 * request that will not be served. Outside the prefix nothing is refused, which
 * the frame's own `/sandbox-assets/` (fetched cross-site, by design) depends on.
 * A NAMED function, because `tests/support/routeTable.ts` admits a path-scoped
 * middleware at `/api/v1` only by its identity.
 */
export function refuseCrossSiteRequests(req: Request, _res: Response, next: NextFunction): void {
  if (req.get('sec-fetch-site')?.trim().toLowerCase() === 'cross-site') {
    next(httpErrors.forbidden(CROSS_SITE_REQUEST_MESSAGE));
    return;
  }
  next();
}
