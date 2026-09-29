/**
 * `useLinkToken` (`lib/linkToken.ts`) directly: where it reads an emailed link's
 * one-time token from, and what it leaves in the URL afterwards. The pages that
 * use it are pinned in `token-link-pages.test.tsx` and
 * `confirm-recipient-page.test.tsx`; these cases pin the hook's own contract.
 */
import { describe, it, expect } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter, useLocation, useNavigationType } from 'react-router';
import { useLinkToken } from '../src/lib/linkToken';

/** The hook, mounted at `entry`, beside a reading of the router's location. */
function mountAt(entry: string, acceptQuery: boolean) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[entry]}>{children}</MemoryRouter>
  );
  return renderHook(
    () => {
      const location = useLocation();
      const navigationType = useNavigationType();
      return {
        // Fragment-only is the default, so the refusing case calls it bare.
        token: useLinkToken(acceptQuery ? { acceptQuery } : undefined),
        url: `${location.pathname}${location.search}${location.hash}`,
        navigationType,
      };
    },
    { wrapper },
  );
}

describe('useLinkToken', () => {
  it.each([
    ['a fragment token, leaving nothing behind', '/p#token=a.b.c', true, 'a.b.c', '/p'],
    ['a percent-encoded fragment token', '/p#token=a%2Eb%20c', true, 'a.b c', '/p'],
    [
      'a query token when accepted, keeping other parameters',
      '/p?x=1&token=q.r.s&y=2',
      true,
      'q.r.s',
      '/p?x=1&y=2',
    ],
    ['a query token when accepted, leaving no bare "?"', '/p?token=q.r.s', true, 'q.r.s', '/p'],
    ['the fragment over the query', '/p?token=old#token=new', true, 'new', '/p'],
    ['no query token when not accepted, still stripping it', '/p?token=q.r.s', false, null, '/p'],
    [
      'nothing from an unrelated fragment, which it leaves alone',
      '/p#section-2',
      true,
      null,
      '/p#section-2',
    ],
    ['nothing from an empty fragment token', '/p#token=', true, null, '/p'],
    ['nothing from an undecodable fragment token', '/p#token=%E0%A4%A', true, null, '/p'],
    ['nothing from an over-long token', `/p#token=${'a'.repeat(2001)}`, true, null, '/p'],
  ] as const)('reads %s', async (_label, entry, acceptQuery, token, url) => {
    const { result } = mountAt(entry, acceptQuery);

    expect(result.current.token).toBe(token);
    await waitFor(() => expect(result.current.url).toBe(url));
    // The value survives the stripping.
    expect(result.current.token).toBe(token);
  });

  it('strips the token by REPLACING the history entry, so Back cannot return to it', async () => {
    const { result } = mountAt('/p#token=a.b.c', true);

    await waitFor(() => expect(result.current.url).toBe('/p'));
    expect(result.current.navigationType).toBe('REPLACE');
  });

  it('makes no navigation at all when the location carries no token', async () => {
    const { result } = mountAt('/p?x=1#section-2', true);

    // Nothing to strip: still the entry the router started on.
    await waitFor(() => expect(result.current.url).toBe('/p?x=1#section-2'));
    expect(result.current.navigationType).toBe('POP');
  });

  it('accepts a token of exactly the bound', () => {
    const { result } = mountAt(`/p#token=${'a'.repeat(2000)}`, true);

    expect(result.current.token).toBe('a'.repeat(2000));
  });
});
