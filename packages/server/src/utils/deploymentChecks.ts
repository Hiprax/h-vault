import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { isLoopbackOrPrivateAddress } from './networkAddress.js';

/**
 * Misconfigurations that used to degrade a deployment SILENTLY, each now
 * reported once in the log; the first two also on the token-gated `/metrics`
 * (never on the public `/health`, which would advertise an instance whose limiters
 * are off):
 *
 *   * A start in development mode (`NODE_ENV` unset or `development`): every rate
 *     limiter is a pass-through there (`middleware/rateLimiter.ts`) and the session
 *     cookies lose `Secure` and `SameSite=Strict` (`test` is the suite's own mode).
 *     {@link reportDeploymentMode}.
 *   * A production server behind a proxy it does not trust: with `TRUST_PROXY`
 *     unset or `0`, `req.ip` is the proxy's address, so every client shares one
 *     rate-limit bucket and every audit row names the proxy.
 *     {@link createProxyTrustDetector}.
 *   * `NODE_TLS_REJECT_UNAUTHORIZED=0` in the environment, which turns certificate
 *     checks off for every outbound connection ({@link reportTlsVerificationOverride}).
 */

interface WarnLogger {
  warn: (message: string, meta?: Record<string, unknown>) => void;
}

let modeReported = false;
let tlsOverrideReported = false;
let proxyWarned = false;
let suspected = false;

/**
 * Logs ONE warning when the server starts in `development` mode. `test` is the
 * suite's own mode and `production` is the only one a deployment should run in,
 * so neither says anything. Called by `server.ts` once the database is connected.
 */
export function reportDeploymentMode(nodeEnv: string, logger: WarnLogger): void {
  if (nodeEnv !== 'development' || modeReported) return;
  modeReported = true;
  logger.warn(
    'This server is running with NODE_ENV=development: rate limiting is OFF and session ' +
      'cookies are sent without Secure and SameSite=Strict. Never expose it like this; ' +
      'start it with NODE_ENV=production.',
  );
}

/**
 * Logs ONE warning when `NODE_TLS_REJECT_UNAUTHORIZED=0` is in the environment.
 * Node then accepts ANY certificate on every outbound TLS connection of the
 * process (SMTP, HaveIBeenPwned, GitHub, object storage), which silently undoes the
 * SMTP TLS requirement and every other verified connection. The application never
 * sets it; this says so when something else did. Called by `server.ts` at boot.
 */
export function reportTlsVerificationOverride(
  env: Record<string, string | undefined>,
  logger: WarnLogger,
): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED !== '0' || tlsOverrideReported) return;
  tlsOverrideReported = true;
  logger.warn(
    'NODE_TLS_REJECT_UNAUTHORIZED=0 is set: this process accepts ANY certificate on every ' +
      'outbound TLS connection, so the SMTP relay, the breach check and object storage are no ' +
      'longer verified. Remove it from the environment.',
  );
}

/** Options for {@link createProxyTrustDetector}: the two settings it depends on. */
export interface ProxyTrustDetectorOptions {
  /** `config.NODE_ENV`: the detector is armed in production only. */
  nodeEnv: string;
  /** `config.TRUST_PROXY` after parsing: `false` when unset, `0` for zero hops. */
  trustProxy: string | number | boolean;
  logger: WarnLogger;
}

/**
 * Middleware that notices a production server receiving proxied requests while it
 * trusts no proxy: `X-Forwarded-For` arriving from a loopback or private-network
 * peer (the host Nginx, or the stack's Nginx over the Docker bridge) with
 * `TRUST_PROXY` unset. It logs ONE warning naming the setting and raises the
 * `/metrics` gauge ({@link proxyMisconfigSuspected}); it changes nothing about the
 * request.
 *
 * The header from a PUBLIC peer is ignored: that is a client supplying the header
 * itself, which an untrusting server is right to disregard, not a proxy somebody
 * forgot to configure. When the detector is not armed it is a bare `next()`.
 */
export function createProxyTrustDetector(options: ProxyTrustDetectorOptions): RequestHandler {
  // Unset parses to `false`, and `0` hops trusts no proxy either (`app.ts` does not
  // even set `trust proxy` for it), so both arm the detector.
  const armed = options.nodeEnv === 'production' && !options.trustProxy;
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (
      armed &&
      !proxyWarned &&
      req.headers['x-forwarded-for'] !== undefined &&
      isLoopbackOrPrivateAddress(req.socket.remoteAddress)
    ) {
      proxyWarned = true;
      suspected = true;
      options.logger.warn(
        'Requests are arriving through a proxy this server does not trust (X-Forwarded-For ' +
          'from a local or private address, TRUST_PROXY unset or 0): every client shares the ' +
          "proxy's rate-limit bucket and audit address. Behind a proxy on this machine set " +
          'TRUST_PROXY=loopback; see .env.example.',
        { peer: req.socket.remoteAddress },
      );
    }
    next();
  };
}

/** Whether the detector has seen the misconfiguration since this process started. */
export function proxyMisconfigSuspected(): boolean {
  return suspected;
}
