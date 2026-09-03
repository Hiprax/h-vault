import type { Request, Response, NextFunction } from 'express';
import { httpErrors } from '@hiprax/errors';
import { storageConfigured } from '../config/index.js';

/**
 * Refuses every document-store request on a deployment that has not configured
 * object storage.
 *
 * The feature is all-or-none, exactly like SMTP: with none of the four `S3_*`
 * connection variables set, `storageConfigured` is false, the router still
 * mounts, and every route under it answers 503 before a controller runs. Mounting
 * conditionally was the alternative and is worse — the route table would then
 * describe a different API on two deployments of the same release, and a caller
 * would get a 404 that reads as "you have the URL wrong" for a server that simply
 * has no bucket.
 *
 * **The client never reads this response, and must not be made to.** `app.ts`
 * mounts `createErrorMiddleware({ exposeServerErrors: false })`, so in production
 * every 5xx message is redacted to its status text and the body is
 * `{success:false, message:'Service Unavailable', statusCode:503}` with nothing
 * naming storage. That redaction is asserted by `test:observability` and must not
 * be weakened for this. The browser learns the feature is unavailable from
 * `GET /config`'s `documents` block — which is why that block reports
 * `enabled: false` rather than being omitted — and hides the section entirely;
 * this 503 exists for a direct API caller, and for the case where the two
 * disagree.
 *
 * Mounted at ROUTER level, ahead of every route-level limiter, so an unconfigured
 * deployment spends no rate-limit budget answering requests it will always refuse.
 * `authenticate` still runs first: an unauthenticated caller learns nothing about
 * whether this operator has storage.
 */
export function requireStorage(_req: Request, _res: Response, next: NextFunction): void {
  if (!storageConfigured) {
    next(httpErrors.serviceUnavailable('Object storage is not configured'));
    return;
  }
  next();
}
