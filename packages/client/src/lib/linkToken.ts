import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';

/**
 * The one-time token an emailed link carries (verification, password reset,
 * unlock, backup-recipient confirmation), read the way the server now writes it:
 * in the URL FRAGMENT, `#token=<percent-encoded token>` (`server/src/utils/email.ts`
 * `tokenLink`). A fragment is never sent to a server, so the token reaches no
 * access log and no `Referer`; a query string does both.
 */

/** Where the link carries its token. */
const TOKEN_FRAGMENT_PREFIX = '#token=';
/** The query parameter the links mailed before the fragment form used. */
const TOKEN_QUERY_PARAMETER = 'token';
/** The bound the server's schemas apply to every one of these tokens. */
const LINK_TOKEN_MAX_LENGTH = 2000;

/** A token of an acceptable length, or null. */
function bounded(token: string | null): string | null {
  return token !== null && token.length > 0 && token.length <= LINK_TOKEN_MAX_LENGTH ? token : null;
}

/**
 * The token from a `#token=…` fragment (the caller has checked the prefix), or
 * null: an empty or over-long token, or one that is not valid percent-encoding.
 */
function readFragmentToken(hash: string): string | null {
  try {
    return bounded(decodeURIComponent(hash.slice(TOKEN_FRAGMENT_PREFIX.length)));
  } catch {
    return null;
  }
}

/** The token from a `?token=` query parameter (the pre-fragment links), or null. */
function readQueryToken(search: string): string | null {
  return bounded(new URLSearchParams(search).get(TOKEN_QUERY_PARAMETER));
}

/** The token a location carries: the fragment first, then (when accepted) the query. */
function tokenIn(hash: string, search: string, acceptQuery: boolean): string | null {
  if (hash.startsWith(TOKEN_FRAGMENT_PREFIX)) return readFragmentToken(hash);
  return acceptQuery ? readQueryToken(search) : null;
}

/**
 * `search` with the token parameter removed, every other parameter kept, WITHOUT
 * the leading `?`: the router's `createPath` adds it to a non-empty search and drops
 * an empty one, so spelling it here would be a second copy of that rule.
 */
function searchWithoutToken(search: string): string {
  const params = new URLSearchParams(search);
  params.delete(TOKEN_QUERY_PARAMETER);
  return params.toString();
}

/**
 * The token of the link this page was opened from, read at mount, and then
 * removed from the address bar (a `replace` navigation, which is
 * `history.replaceState` under the browser router) so it is not left in the
 * session-history entry, a bookmark or a screen share.
 *
 * The fragment is read first. With `acceptQuery`, a link mailed before this release
 * (`?token=`) is still honoured, and stripped the same way; that fallback exists for
 * one release only, for links already in flight. The value survives the stripping,
 * and it changes only when a later location carries a token of its own: a second
 * link opened in the same tab is a hash-only navigation, not a reload.
 */
export function useLinkToken(options: { acceptQuery?: boolean } = {}): string | null {
  const location = useLocation();
  const navigate = useNavigate();
  const acceptQuery = options.acceptQuery === true;
  const [token, setToken] = useState<string | null>(() =>
    tokenIn(location.hash, location.search, acceptQuery),
  );

  useEffect(() => {
    const inFragment = location.hash.startsWith(TOKEN_FRAGMENT_PREFIX);
    const inQuery = new URLSearchParams(location.search).has(TOKEN_QUERY_PARAMETER);
    if (!inFragment && !inQuery) return;
    // A link opened while this page is already showing (a second email, pasted into
    // the same tab) changes only the fragment, so the page is not reloaded and the
    // mount-time read above does not run again: it is read here instead.
    setToken(tokenIn(location.hash, location.search, acceptQuery));
    void navigate(
      {
        pathname: location.pathname,
        search: searchWithoutToken(location.search),
        hash: inFragment ? '' : location.hash,
      },
      { replace: true },
    );
  }, [acceptQuery, location.hash, location.pathname, location.search, navigate]);

  return token;
}
