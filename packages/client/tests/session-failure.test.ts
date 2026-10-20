/**
 * `services/auth/sessionFailure.ts` — the predicate that decides whether a failed
 * session operation ends the session.
 *
 * This is one of the highest-consequence branches in the client, which is why it
 * is tested directly rather than only through the four call sites that consume it.
 * Every caller reads a rejection as "log the user out", and because
 * `authStore.lock()` deliberately keeps `accessToken` set, that logout is not a
 * local teardown: it reaches `POST /auth/logout` and DELETES the refresh-token row.
 * So misclassifying a 429 or a dropped connection does not merely bounce the user
 * to the login screen — it destroys a session that had days or weeks left, and
 * strands them on a login form. That is exactly what shipped.
 */
import { describe, it, expect } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import {
  isSessionGone,
  isAccountLocked,
  isCsrfRejection,
  is2faSessionDead,
  isRateLimited,
  retryAfterSeconds,
  describeTransientFailure,
  isMasterPasswordRefusal,
  ACCOUNT_LOCKED_MESSAGE,
} from '../src/services/auth/sessionFailure';
import { MASTER_PASSWORD_PROOF_REFUSED_MESSAGE } from '@hvault/shared';
import { getApiErrorMessage } from '../src/lib/utils';

function axiosError(
  status?: number,
  data: unknown = {},
  headers: Record<string, string> = {},
): AxiosError {
  const err = new AxiosError(status === undefined ? 'Network Error' : `HTTP ${String(status)}`);
  if (status !== undefined) {
    err.response = {
      status,
      statusText: '',
      data,
      headers: new AxiosHeaders(headers),
      config: { headers: new AxiosHeaders() },
    };
  }
  return err;
}

describe('isSessionGone', () => {
  it.each([401, 403])('is TRUE for %s — the server judged the credential', (status) => {
    expect(isSessionGone(axiosError(status, { message: 'TOKEN_INVALID' }))).toBe(true);
  });

  it.each([
    ['a rate limit', 429],
    ['a bad request', 400],
    ['a not-found', 404],
    ['a conflict', 409],
    ['a server error', 500],
    ['a bad gateway', 502],
    ['an unavailable service', 503],
    ['a gateway timeout', 504],
  ])('is FALSE for %s — the session was never judged', (_label, status) => {
    expect(isSessionGone(axiosError(status))).toBe(false);
  });

  it('is FALSE for a network error with no response at all', () => {
    expect(isSessionGone(axiosError())).toBe(false);
  });

  it.each([
    ['a plain Error', new Error('boom')],
    ['a string', 'boom'],
    ['null', null],
    ['undefined', undefined],
    ['an object shaped like a response', { response: { status: 401 } }],
  ])('is FALSE for %s — it cannot prove anything', (_label, value) => {
    // The last case matters: a plain object is NOT an AxiosError, so it must not
    // be able to talk the client into a logout.
    expect(isSessionGone(value)).toBe(false);
  });

  it('is FALSE for a CSRF 403, which is recoverable', () => {
    // A CSRF token is bound to `hashToken(refreshToken)` and every refresh rotates
    // that cookie, so a stale one is expected and the interceptor's job is to fetch
    // a fresh one and replay. Calling it authoritative would mean a CSRF token that
    // could not be re-fetched (endpoint briefly unreachable, or rate-limited)
    // revoked a session nobody had questioned.
    expect(isSessionGone(axiosError(403, { message: 'invalid csrf token' }))).toBe(false);
  });

  it('is FALSE for a locked account, whose session the server deliberately kept', () => {
    // `/auth/refresh` evaluates the account BEFORE it claims the presented token,
    // so a lockout leaves the refresh row unspent and sends no cookie directive at
    // all. Calling it a dead session made the client `POST /auth/logout` and delete
    // the row the server had just gone out of its way not to touch — a thirty-day
    // remembered session destroyed to answer a thirty-minute condition.
    expect(isSessionGone(axiosError(403, { message: 'ACCOUNT_LOCKED' }))).toBe(false);
  });

  it.each([
    ['a forbidden resource', 'FORBIDDEN'],
    ['a refused token', 'TOKEN_INVALID'],
    ['an unverified address', 'EMAIL_NOT_VERIFIED'],
    ['a message that merely quotes the code', 'Account ACCOUNT_LOCKED was refused'],
  ])('is TRUE for %s — only the exact lockout code is excluded', (_label, message) => {
    // The control for the case above. The exclusion is one constant matched
    // exactly, not "403s we feel hopeful about": widening it would silently turn
    // every future 403 into a session the client refuses to end.
    expect(isSessionGone(axiosError(403, { message }))).toBe(true);
  });
});

describe('isMasterPasswordRefusal', () => {
  // The server's one wrong-proof answer: a 401 that can only follow an ACCEPTED
  // session, so a refresh could not change it.
  const refusal = (): AxiosError =>
    axiosError(401, { success: false, message: MASTER_PASSWORD_PROOF_REFUSED_MESSAGE });

  it('is true for a 401 carrying exactly the shared sentence', () => {
    expect(isMasterPasswordRefusal(refusal())).toBe(true);
  });

  it('is false for any other sentence on a 401, however close', () => {
    for (const message of [
      `${MASTER_PASSWORD_PROOF_REFUSED_MESSAGE}.`,
      `Error: ${MASTER_PASSWORD_PROOF_REFUSED_MESSAGE}`,
      MASTER_PASSWORD_PROOF_REFUSED_MESSAGE.toLowerCase(),
      'Invalid or expired token',
      '',
    ]) {
      expect(isMasterPasswordRefusal(axiosError(401, { message }))).toBe(false);
    }
    expect(isMasterPasswordRefusal(axiosError(401, {}))).toBe(false);
    expect(isMasterPasswordRefusal(axiosError(401, 'Current password is incorrect'))).toBe(false);
  });

  it('is false for the same sentence on any other status, and for non-HTTP failures', () => {
    for (const status of [400, 403, 409, 429, 500]) {
      expect(
        isMasterPasswordRefusal(
          axiosError(status, { message: MASTER_PASSWORD_PROOF_REFUSED_MESSAGE }),
        ),
      ).toBe(false);
    }
    expect(isMasterPasswordRefusal(axiosError())).toBe(false);
    expect(isMasterPasswordRefusal(new Error(MASTER_PASSWORD_PROOF_REFUSED_MESSAGE))).toBe(false);
    expect(isMasterPasswordRefusal(null)).toBe(false);
  });

  it('is never read as an ended session, so no caller signs a user out over a typo', () => {
    expect(isSessionGone(refusal())).toBe(false);
    // Every other 401 still is.
    expect(isSessionGone(axiosError(401, { message: 'Invalid or expired token' }))).toBe(true);
  });
});

describe('isAccountLocked', () => {
  it('recognises the exact code the server emits', () => {
    expect(isAccountLocked(axiosError(403, { message: 'ACCOUNT_LOCKED' }))).toBe(true);
  });

  it.each([
    ['a 401 carrying the same message', 401],
    ['a 429', 429],
    ['a 500', 500],
  ])('is FALSE for %s — the status is part of the signal', (_label, status) => {
    expect(isAccountLocked(axiosError(status, { message: 'ACCOUNT_LOCKED' }))).toBe(false);
  });

  it.each([
    ['a CSRF complaint', { message: 'invalid csrf token' }],
    ['another error code', { message: 'FORBIDDEN' }],
    ['the code in lower case', { message: 'account_locked' }],
    ['the code as a substring', { message: 'reason: ACCOUNT_LOCKED' }],
    ['no message at all', {}],
    ['a non-string message', { message: { code: 'ACCOUNT_LOCKED' } }],
    ['a null body', null],
  ])('is FALSE for %s', (_label, data) => {
    expect(isAccountLocked(axiosError(403, data))).toBe(false);
  });

  it('is FALSE for a network error and for a non-Axios throw', () => {
    expect(isAccountLocked(axiosError())).toBe(false);
    expect(isAccountLocked(new Error('ACCOUNT_LOCKED'))).toBe(false);
    expect(
      isAccountLocked({ response: { status: 403, data: { message: 'ACCOUNT_LOCKED' } } }),
    ).toBe(false);
  });
});

describe('is2faSessionDead', () => {
  /**
   * The EXACT body `createErrorMiddleware` puts on the wire: flat, four fields,
   * `message` carrying the machine-readable `ERROR_CODES` constant. Built here
   * rather than inline so that every case below is provably a shape the API can
   * actually produce — which is the whole defect this predicate closes.
   */
  function refusal(status: number, code: string, statusText: string): AxiosError {
    return axiosError(status, { success: false, message: code, statusCode: status, statusText });
  }

  it.each([
    ['an expired refresh row', 401, 'TOKEN_EXPIRED', 'Unauthorized'],
    ['a dead or foreign temp token', 401, 'TOKEN_INVALID', 'Unauthorized'],
    ['an account that locked mid-flow', 403, 'ACCOUNT_LOCKED', 'Forbidden'],
  ])('is TRUE for %s', (_label, status, code, statusText) => {
    expect(is2faSessionDead(refusal(status, code, statusText))).toBe(true);
  });

  it('is FALSE for a wrong 2FA code, the one refusal the same token survives', () => {
    // The case the whole split exists to protect: `TWO_FA_INVALID` is a 401 too,
    // so the status alone can never decide this. If it ever reads TRUE, a mistyped
    // digit destroys the MEK and the user has to start the sign-in over.
    expect(is2faSessionDead(refusal(401, 'TWO_FA_INVALID', 'Unauthorized'))).toBe(false);
  });

  it('is FALSE for TWO_FA_NOT_ENABLED — a 400 the abandon timer still reaps', () => {
    expect(is2faSessionDead(refusal(400, 'TWO_FA_NOT_ENABLED', 'Bad Request'))).toBe(false);
  });

  it('is FALSE for the NESTED envelope the server has never emitted', () => {
    // The shape `verify2fa` used to read, and the shape three tests fabricated.
    // It must stay unrecognised: accepting it here would re-legitimise a body no
    // route can produce and let the fabricated tests pass again.
    expect(
      is2faSessionDead(axiosError(401, { success: false, error: { code: 'TOKEN_INVALID' } })),
    ).toBe(false);
  });

  it.each([
    ['a rate limit', 429],
    ['a server error', 500],
    ['a bad gateway', 502],
  ])('is FALSE for %s carrying the same message — the status corroborates', (_label, status) => {
    // A proxy, a captive portal or a WAF can return any JSON body it likes.
    expect(is2faSessionDead(refusal(status, 'TOKEN_INVALID', 'Error'))).toBe(false);
  });

  it.each([
    ['the code in lower case', { message: 'token_invalid' }],
    ['the code as a substring', { message: 'reason: TOKEN_INVALID' }],
    ['no message at all', {}],
    ['a non-string message', { message: { code: 'TOKEN_INVALID' } }],
    ['a null body', null],
  ])('is FALSE for %s — matched exactly, like isAccountLocked', (_label, data) => {
    expect(is2faSessionDead(axiosError(401, data))).toBe(false);
  });

  it('is FALSE for a network error with no response at all', () => {
    // Offline, DNS, a restarting container: the temp token was never judged, so
    // the MEK stays and the user can simply resubmit.
    expect(is2faSessionDead(axiosError())).toBe(false);
  });

  it.each([
    ['a plain Error', new Error('TOKEN_INVALID')],
    ['a string', 'TOKEN_INVALID'],
    ['null', null],
    ['undefined', undefined],
    [
      'an object shaped like a response',
      { response: { status: 401, data: { message: 'TOKEN_INVALID' } } },
    ],
  ])('is FALSE for %s — it cannot prove anything', (_label, value) => {
    expect(is2faSessionDead(value)).toBe(false);
  });
});

describe('isCsrfRejection', () => {
  it('recognises the message the CSRF middleware actually emits', () => {
    expect(isCsrfRejection(axiosError(403, { message: 'invalid csrf token' }))).toBe(true);
  });

  it('is case-insensitive on the marker', () => {
    expect(isCsrfRejection(axiosError(403, { message: 'Invalid CSRF Token' }))).toBe(true);
  });

  it('requires the status to be 403, not merely the message', () => {
    expect(isCsrfRejection(axiosError(401, { message: 'invalid csrf token' }))).toBe(false);
    expect(isCsrfRejection(axiosError(500, { message: 'invalid csrf token' }))).toBe(false);
  });

  it.each([
    ['ACCOUNT_LOCKED', 'ACCOUNT_LOCKED'],
    ['TOKEN_INVALID', 'TOKEN_INVALID'],
    ['a prose refusal', 'Forbidden'],
  ])('is FALSE for a 403 whose message is %s', (_label, message) => {
    // Enumerated deliberately: blindly replaying a 403 doubled every refused
    // request — two bcrypt compares and two rate-limit slots for one visible
    // attempt.
    expect(isCsrfRejection(axiosError(403, { message }))).toBe(false);
  });

  it.each([
    ['a body with no message', {}],
    ['a non-string message', { message: 42 }],
    ['a null body', null],
  ])('is FALSE for %s', (_label, data) => {
    expect(isCsrfRejection(axiosError(403, data))).toBe(false);
  });

  it('is FALSE for a non-Axios value', () => {
    expect(isCsrfRejection(new Error('invalid csrf token'))).toBe(false);
  });
});

describe('isRateLimited', () => {
  it('is TRUE only for 429', () => {
    expect(isRateLimited(axiosError(429))).toBe(true);
    expect(isRateLimited(axiosError(503))).toBe(false);
    expect(isRateLimited(axiosError())).toBe(false);
    expect(isRateLimited(new Error('429'))).toBe(false);
  });
});

describe('retryAfterSeconds', () => {
  it('reads the delay-seconds form', () => {
    expect(retryAfterSeconds(axiosError(429, {}, { 'retry-after': '45' }))).toBe(45);
  });

  it('rounds a fractional delay up, so the quoted wait is never too short', () => {
    expect(retryAfterSeconds(axiosError(429, {}, { 'retry-after': '2.4' }))).toBe(3);
  });

  it('reads the HTTP-date form', () => {
    const future = new Date(Date.now() + 90_000).toUTCString();
    const seconds = retryAfterSeconds(axiosError(429, {}, { 'retry-after': future }));
    // Second-resolution formatting makes the exact value slightly elastic.
    expect(seconds).toBeGreaterThanOrEqual(88);
    expect(seconds).toBeLessThanOrEqual(91);
  });

  it('clamps an absurd value rather than quoting it', () => {
    // A malformed or hostile header must not render "try again in 4 million
    // seconds"; the cap is one hour.
    expect(retryAfterSeconds(axiosError(429, {}, { 'retry-after': '99999999' }))).toBe(3600);
  });

  it.each([
    ['a past date', new Date(Date.now() - 60_000).toUTCString()],
    ['zero', '0'],
    ['a negative delay', '-5'],
    ['gibberish', 'soonish'],
    ['an empty string', ''],
  ])('returns null for %s', (_label, value) => {
    expect(retryAfterSeconds(axiosError(429, {}, { 'retry-after': value }))).toBeNull();
  });

  it('returns null when the header is absent, and for a non-Axios error', () => {
    expect(retryAfterSeconds(axiosError(429))).toBeNull();
    expect(retryAfterSeconds(axiosError())).toBeNull();
    expect(retryAfterSeconds(new Error('boom'))).toBeNull();
  });
});

describe('describeTransientFailure', () => {
  it('leaves a locked second factor to getApiErrorMessage, which translates the code', () => {
    // F-03: this function spoke for `ACCOUNT_LOCKED` while `/auth/refresh` could
    // answer a lockout. It no longer can (a refresh is never refused for a locked
    // factor), and the code now comes only from two-factor code checks, whose
    // callers render errors through `getApiErrorMessage`, so the branch was
    // removed as dead. The user still never sees the raw constant.
    expect(describeTransientFailure(axiosError(403, { message: 'ACCOUNT_LOCKED' }))).toBeNull();
    const shown = getApiErrorMessage(axiosError(403, { message: 'ACCOUNT_LOCKED' }));
    expect(shown).toBe(ACCOUNT_LOCKED_MESSAGE);
    expect(shown).toMatch(/unlock link/i);
    expect(shown).not.toBe('ACCOUNT_LOCKED');
  });

  it('stays silent on a 403 that is not a lockout', () => {
    // The negative: this function returning a string is what makes a caller treat
    // a failure as recoverable, so it must not speak for refusals it does not own.
    expect(describeTransientFailure(axiosError(403, { message: 'FORBIDDEN' }))).toBeNull();
    expect(describeTransientFailure(axiosError(403, { message: 'invalid csrf token' }))).toBeNull();
  });

  it('quotes the wait for a 429 that carries one', () => {
    expect(describeTransientFailure(axiosError(429, {}, { 'retry-after': '45' }))).toMatch(
      /try again in 45 seconds/i,
    );
  });

  it('uses singular seconds for a one-second wait', () => {
    expect(describeTransientFailure(axiosError(429, {}, { 'retry-after': '1' }))).toMatch(
      /in 1 second\./i,
    );
  });

  it('renders a long wait in minutes, rounded up', () => {
    // 90 s is "2 minutes", not "1" — never tell the user to come back too early.
    expect(describeTransientFailure(axiosError(429, {}, { 'retry-after': '90' }))).toMatch(
      /in 2 minutes/i,
    );
  });

  it('uses singular minute for exactly one minute', () => {
    expect(describeTransientFailure(axiosError(429, {}, { 'retry-after': '60' }))).toMatch(
      /in 1 minute\./i,
    );
  });

  it('still explains a 429 with no usable Retry-After', () => {
    const message = describeTransientFailure(axiosError(429));
    expect(message).toMatch(/too many attempts/i);
    expect(message).not.toMatch(/NaN|undefined|null/);
  });

  it('describes an unreachable server', () => {
    expect(describeTransientFailure(axiosError())).toMatch(/could not reach the server/i);
  });

  it.each([500, 502, 503, 504])('describes a %s as temporarily unavailable', (status) => {
    expect(describeTransientFailure(axiosError(status))).toMatch(/temporarily unavailable/i);
  });

  it.each([
    ['a 401', axiosError(401)],
    ['a 403', axiosError(403, { message: 'FORBIDDEN' })],
    ['a 400', axiosError(400)],
    ['a 404', axiosError(404)],
    ['a plain Error', new Error('boom')],
  ])('returns null for %s, so the caller keeps its own wording', (_label, err) => {
    // Returning a sentence here would mask a genuine credential rejection behind
    // "please try again in a moment", which is how a wrong password and a dead
    // session became indistinguishable in the first place.
    //
    // The 403 row is a plain refusal; `ACCOUNT_LOCKED` has its own case at the top
    // of this block (it is also null now, and translated elsewhere).
    expect(describeTransientFailure(err)).toBeNull();
  });
});
