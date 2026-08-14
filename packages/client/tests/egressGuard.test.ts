/**
 * The harness-level egress block for the client tier, asserted through the three
 * transports jsdom actually offers.
 *
 * Each case fails if `installEgressGuard()` stops being called from
 * `tests/setup.ts`, or if one of its patch points is dropped. The XHR case is the
 * load-bearing one: axios selects its XHR adapter whenever `XMLHttpRequest`
 * exists, which it does under jsdom, so a forgotten `vi.mock` of an api module
 * leaves through `XMLHttpRequest`, not through `fetch`.
 */
import axios from 'axios';
import { describe, expect, it } from 'vitest';
import { EgressBlockedError } from './egressGuard.js';

const EXTERNAL = 'https://api.pwnedpasswords.com/range/AAAAA';

describe('egress guard (client)', () => {
  it('rejects fetch to a third party, naming the host and the fix', async () => {
    await expect(fetch(EXTERNAL)).rejects.toThrow(EgressBlockedError);
    await expect(fetch(EXTERNAL)).rejects.toThrow(/api\.pwnedpasswords\.com/);
    await expect(fetch(EXTERNAL)).rejects.toThrow(/must not reach a third party/);
  });

  it('rejects rather than throwing synchronously, because fetch returns a promise', async () => {
    // A synchronous throw would surface as a different failure shape than a real
    // network error, so a caller's `.catch()` would not see it. The call must
    // return a promise that REJECTS — asserting only "did not throw" would also
    // pass on a guard that quietly resolved and let the request out.
    const returned = fetch(EXTERNAL);
    expect(returned).toBeInstanceOf(Promise);
    await expect(returned).rejects.toBeInstanceOf(EgressBlockedError);
  });

  it('blocks XMLHttpRequest.open, which is the adapter axios picks under jsdom', () => {
    const xhr = new XMLHttpRequest();
    expect(() => {
      xhr.open('GET', EXTERNAL);
    }).toThrow(EgressBlockedError);
  });

  it('blocks an axios GET to a third party', async () => {
    await expect(axios.get(EXTERNAL)).rejects.toThrow(/api\.pwnedpasswords\.com/);
  });

  it('allows a relative URL, which resolves against the jsdom origin', () => {
    // Every component test that drives an api module uses a relative `/api/v1/...`
    // path. A guard that treated an unparseable relative URL as external would
    // block the entire client suite instead of only its third-party calls.
    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/v1/vault/items');

    // Opened for real, against the jsdom origin: `readyState === OPENED` is
    // what distinguishes "allowed through" from "silently swallowed".
    expect(xhr.readyState).toBe(XMLHttpRequest.OPENED);
  });

  it('carries the host and the patch point on the error object', async () => {
    const failure: unknown = await fetch(EXTERNAL).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(EgressBlockedError);
    expect((failure as EgressBlockedError).host).toBe('api.pwnedpasswords.com');
    expect((failure as EgressBlockedError).via).toBe('fetch');
    expect((failure as EgressBlockedError).name).toBe('EgressBlockedError');
  });
});
