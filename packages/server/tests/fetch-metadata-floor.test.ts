/**
 * F-10: the API refuses a request the browser marks `Sec-Fetch-Site: cross-site`,
 * whatever that request asks for.
 *
 * The isolated document every stored file is rendered in holds an OPAQUE origin,
 * and an opaque origin is same-site with nothing, so every request it causes
 * reaches this server marked `cross-site`. Its policy keeps `script-src 'self'`
 * and `style-src 'self'` (its own bundle needs them), and nothing stops a
 * document navigating itself, so a compromised renderer can still put
 * `import('/api/v1/…')`, `<link rel=stylesheet href=/api/v1/…>` or a self-
 * navigation on the wire. The application's own calls are `same-origin`, a typed
 * address is `none`, and a client that is not a browser (a health probe, a
 * metrics scraper, this suite) sends no header at all; none of those is touched.
 *
 * The rule reads the SITE, never the destination: a `Sec-Fetch-Dest` rule would
 * miss the script, stylesheet and navigation requests above, which the frame's
 * policy cannot stop.
 */
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { CROSS_SITE_REQUEST_MESSAGE } from '../src/middleware/fetchMetadata.js';
import { createTestUser, getCsrf } from './helpers.js';

/** The three headers a browser sends with every request, as the frame's would carry them. */
interface FetchMetadata {
  site: string;
  mode: string;
  dest: string;
}

function withMetadata(req: request.Test, metadata: FetchMetadata): request.Test {
  return req
    .set('Sec-Fetch-Site', metadata.site)
    .set('Sec-Fetch-Mode', metadata.mode)
    .set('Sec-Fetch-Dest', metadata.dest);
}

/** The whole refusal: the status, the flat error envelope, and still never cached. */
function expectRefused(res: request.Response): void {
  expect(res.status).toBe(403);
  // Outside production the error handler adds the stack (`exposeServerErrors`
  // governs 5xx only); everything else in the envelope is exact.
  const { stack: _stack, ...envelope } = res.body as Record<string, unknown>;
  expect(envelope).toEqual({
    success: false,
    message: CROSS_SITE_REQUEST_MESSAGE,
    statusCode: 403,
    statusText: 'Forbidden',
  });
  expect(res.headers['cache-control']).toBe('no-store');
}

describe('the API refuses a cross-site request, whatever its destination (F-10)', () => {
  it.each<[string, Omit<FetchMetadata, 'site'>]>([
    ['an image request (<img src>)', { mode: 'no-cors', dest: 'image' }],
    ['a module script request (import())', { mode: 'cors', dest: 'script' }],
    ['a navigation of the frame itself', { mode: 'navigate', dest: 'iframe' }],
    ['a top-level navigation', { mode: 'navigate', dest: 'document' }],
    ['a stylesheet request', { mode: 'no-cors', dest: 'style' }],
    ['a font request', { mode: 'cors', dest: 'font' }],
    ['a fetch() with no destination', { mode: 'cors', dest: 'empty' }],
  ])('refuses %s with 403 and an answer no cache keeps', async (_label, metadata) => {
    const res = await withMetadata(request(app).get('/api/v1/config'), {
      site: 'cross-site',
      ...metadata,
    }).set('Origin', 'null');

    expectRefused(res);
    // The config body is public, but the point is that NO handler answered: a
    // refusal carries nothing a route would have put in it.
    expect(res.body).not.toHaveProperty('data');
  });

  it('refuses before the CSRF endpoint runs, so no token cookie is minted', async () => {
    const res = await withMetadata(request(app).get('/api/v1/csrf-token'), {
      site: 'cross-site',
      mode: 'no-cors',
      dest: 'image',
    });

    expectRefused(res);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('refuses a state-changing request before any handler runs, even one that would succeed', async () => {
    // A valid CSRF pair and the right credentials: same-origin, this is a sign-in.
    // Marked cross-site it must change nothing at all, which is the negative that
    // matters: no session row, no refresh cookie, no audit entry.
    const user = await createTestUser();
    const agent = request(app);
    const { token, cookie } = await getCsrf(agent);
    const auditBefore = await AuditLog.countDocuments({ userId: user.id });
    const sessionsBefore = await RefreshToken.countDocuments({ userId: user.id });

    const refused = await withMetadata(
      agent
        .post('/api/v1/auth/login')
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: user.email, authHash: user.rawPassword }),
      { site: 'cross-site', mode: 'cors', dest: 'empty' },
    );

    expectRefused(refused);
    expect(refused.headers['set-cookie']).toBeUndefined();
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(sessionsBefore);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(auditBefore);

    // The same request, same-origin, signs in: the refusal above was the floor.
    const accepted = await withMetadata(
      agent
        .post('/api/v1/auth/login')
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ email: user.email, authHash: user.rawPassword }),
      { site: 'same-origin', mode: 'cors', dest: 'empty' },
    );
    expect(accepted.status).toBe(200);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(sessionsBefore + 1);
  });

  it('refuses a cross-site CORS preflight ahead of the CORS middleware', async () => {
    // Position, not prefix: `cors` answers a preflight itself, so a floor mounted
    // below it would never see one. Refused here, the browser's preflight fails and
    // the request it was asking about is never sent.
    const res = await request(app)
      .options('/api/v1/auth/login')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Sec-Fetch-Mode', 'cors')
      .set('Sec-Fetch-Dest', 'empty')
      .set('Origin', 'null')
      .set('Access-Control-Request-Method', 'POST');

    expectRefused(res);
    expect(res.headers['access-control-allow-methods']).toBeUndefined();
  });

  it('matches the API prefix and the header value whatever their case', async () => {
    // Express mounts case-insensitively, so `/API/V1/config` reaches the same
    // route; the browser sends the token in lower case, and normalising it costs
    // nothing.
    const upperPath = await withMetadata(request(app).get('/API/V1/config'), {
      site: 'cross-site',
      mode: 'no-cors',
      dest: 'image',
    });
    const upperValue = await withMetadata(request(app).get('/api/v1/config'), {
      site: ' Cross-Site ',
      mode: 'no-cors',
      dest: 'image',
    });

    expectRefused(upperPath);
    expectRefused(upperValue);
  });
});

describe('the API answers every request that is not cross-site', () => {
  it.each([
    ['same-origin (the application itself)', 'same-origin'],
    ['same-site (a sibling subdomain)', 'same-site'],
    ['none (an address typed by the user)', 'none'],
  ])('answers %s', async (_label, site) => {
    const res = await withMetadata(request(app).get('/api/v1/config'), {
      site,
      mode: 'cors',
      dest: 'empty',
    });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toHaveProperty('documents');
  });

  it('answers a client that sends no Fetch Metadata at all (probes, scrapers, older browsers)', async () => {
    const health = await request(app).get('/api/v1/health');
    const config = await request(app).get('/api/v1/config');

    expect(health.status).toBe(200);
    expect(config.status).toBe(200);
    expect(config.body.data).toHaveProperty('documents');
  });

  it('leaves responses outside /api/v1 alone, where the frame’s own assets are served', async () => {
    // The isolated document fetches its module script and stylesheet from
    // `/sandbox-assets/` cross-site, by design (the production-only static mount,
    // exercised by the sandbox gate in a real browser). The floor is scoped to the
    // API prefix so nothing outside it is refused; the documentation page is the
    // outside path this tier serves.
    const res = await request(app)
      .get('/api/docs/')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Sec-Fetch-Mode', 'navigate')
      .set('Sec-Fetch-Dest', 'document');

    expect(res.status).toBe(200);
    expect(res.text).toContain('swagger');
  });
});
