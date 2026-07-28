/**
 * `lib/accessToken.ts` — reading the client's own JWT.
 *
 * Nothing here is a security check and it cannot be: the payload is only base64
 * and the client holds no key. It answers one cheap question without a round-trip
 * — *is the token I am holding still worth sending?* — and the whole safety of
 * that rests on `isAccessTokenUsable` FAILING CLOSED. A false positive means the
 * unlock screen skips its refresh with a token the server will reject, so every
 * branch that could return `true` by accident is enumerated here.
 */
import { describe, it, expect } from 'vitest';
import {
  decodeJwtPayload,
  isAccessTokenUsable,
  ACCESS_TOKEN_FRESHNESS_MARGIN_MS,
} from '../src/lib/accessToken';

/** Build a JWT-shaped token whose payload is `payload`, base64url, unpadded. */
function jwt(payload: unknown): string {
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `header.${body}.signature`;
}

/** Seconds-since-epoch `exp` claim, `deltaMs` from now. */
function expIn(deltaMs: number): number {
  return Math.floor((Date.now() + deltaMs) / 1000);
}

describe('decodeJwtPayload', () => {
  it('decodes a well-formed payload', () => {
    expect(decodeJwtPayload(jwt({ sub: 'user-1', exp: 123 }))).toEqual({ sub: 'user-1', exp: 123 });
  });

  it('handles base64url and missing padding', () => {
    // `atob` rejects both `-`/`_` and an unpadded length, and both are normal in a
    // JWT — the previous inline decoder in `authStore` handled the alphabet but not
    // the padding.
    const payload = { sub: 'aa?bb>cc', n: 1 };
    expect(decodeJwtPayload(jwt(payload))).toEqual(payload);
  });

  it.each([
    ['an empty string', ''],
    ['one segment', 'header'],
    ['two segments', 'header.body'],
    ['four segments', 'a.b.c.d'],
    ['an empty payload segment', 'header..signature'],
    ['a payload that is not base64', 'header.!!!not-base64!!!.sig'],
    ['a payload that is not JSON', `header.${btoa('not json')}.sig`],
    ['a payload that is a JSON array', `header.${btoa('[1,2,3]')}.sig`],
    ['a payload that is a JSON string', `header.${btoa('"hello"')}.sig`],
    ['a payload that is JSON null', `header.${btoa('null')}.sig`],
  ])('returns null for %s', (_label, token) => {
    expect(decodeJwtPayload(token)).toBeNull();
  });
});

describe('isAccessTokenUsable', () => {
  it('is TRUE for a token with plenty of life left', () => {
    expect(isAccessTokenUsable(jwt({ exp: expIn(10 * 60_000) }))).toBe(true);
  });

  it('is FALSE inside the freshness margin, so a token cannot expire mid-flight', () => {
    const halfMargin = ACCESS_TOKEN_FRESHNESS_MARGIN_MS / 2;
    expect(isAccessTokenUsable(jwt({ exp: expIn(halfMargin) }))).toBe(false);
  });

  it('is FALSE for an already-expired token', () => {
    expect(isAccessTokenUsable(jwt({ exp: expIn(-60_000) }))).toBe(false);
  });

  it('honours an injected clock, so the boundary is testable without waiting', () => {
    const token = jwt({ exp: expIn(10 * 60_000) });
    expect(isAccessTokenUsable(token, Date.now())).toBe(true);
    // Nine minutes later there is under a minute left: inside the margin.
    expect(isAccessTokenUsable(token, Date.now() + 9.5 * 60_000)).toBe(false);
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['an empty string', ''],
  ])('is FALSE for %s', (_label, token) => {
    expect(isAccessTokenUsable(token)).toBe(false);
  });

  it.each([
    ['a malformed token', 'not-a-jwt'],
    ['a payload with no exp', jwt({ sub: 'user-1' })],
    ['a string exp', jwt({ exp: '99999999999' })],
    ['a null exp', jwt({ exp: null })],
    ['a NaN exp', jwt({ exp: Number.NaN })],
  ])('FAILS CLOSED for %s', (_label, token) => {
    // Each of these is a token the client cannot reason about. Returning true for
    // any of them would let the unlock screen skip its refresh on nothing, and the
    // resulting 401 from verify-unlock reads as a wrong master password.
    expect(isAccessTokenUsable(token)).toBe(false);
  });

  it('is FALSE for an Infinity exp', () => {
    // `JSON.stringify(Infinity)` is `null`, so this arrives as a null claim — but
    // assert the outcome rather than the encoding, because the point is that no
    // unbounded value can ever be accepted.
    expect(isAccessTokenUsable(jwt({ exp: Number.POSITIVE_INFINITY }))).toBe(false);
  });
});
