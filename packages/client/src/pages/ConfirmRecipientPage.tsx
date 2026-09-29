import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { isAxiosError } from 'axios';
import { CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { confirmBackupRecipientApi } from '../services/api/backupApi';
import { getApiErrorMessage } from '../lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '../components/ui/Card';
import { StandalonePage } from '../components/layout/StandalonePage';

/** Where the confirmation link carries its token: the URL fragment, never the query. */
const TOKEN_FRAGMENT_PREFIX = '#token=';
/** What a refused link means, in the recipient's terms. */
const INVALID_LINK_MESSAGE =
  'This confirmation link is not valid. It may have expired, been used already, or been replaced by a newer one.';

/** The same bound the server's schema applies to the token. */
const MAX_TOKEN_LENGTH = 2000;

/**
 * The token from a `#token=` fragment, or null. A fragment is never sent to a
 * server, so the token reaches no access log and no `Referer` on its way here.
 */
function readFragmentToken(hash: string): string | null {
  if (!hash.startsWith(TOKEN_FRAGMENT_PREFIX)) return null;
  let token: string;
  try {
    token = decodeURIComponent(hash.slice(TOKEN_FRAGMENT_PREFIX.length));
  } catch {
    return null;
  }
  return token.length > 0 && token.length <= MAX_TOKEN_LENGTH ? token : null;
}

/**
 * `/backup/confirm-recipient#token=…`: the page a backup recipient lands on from
 * its confirmation email. The recipient usually has no account here, so the page
 * needs no session: it takes the token from the fragment, removes the fragment
 * from the address bar at once (so the token is not left in the history entry or
 * in a bookmark), and sends it to the server once.
 */
export default function ConfirmRecipientPage() {
  const location = useLocation();
  const navigate = useNavigate();
  // Read ONCE, at mount: removing the fragment below changes `location.hash`.
  const [token] = useState(() => readFragmentToken(location.hash));
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    token === null ? 'error' : 'loading',
  );
  const [message, setMessage] = useState(
    token === null
      ? 'This confirmation link is incomplete. Open the link from the email again.'
      : '',
  );
  const calledRef = useRef(false);

  useEffect(() => {
    if (calledRef.current) return;
    calledRef.current = true;

    if (location.hash !== '') {
      void navigate(
        { pathname: location.pathname, search: location.search, hash: '' },
        { replace: true },
      );
    }
    if (!token) return;

    void confirmBackupRecipientApi({ token })
      .then((res) => {
        setStatus('success');
        setMessage(
          (res.data.success ? res.data.message : undefined) ??
            'This address will now receive the encrypted backups it was asked to receive.',
        );
      })
      .catch((err: unknown) => {
        setStatus('error');
        // A refused token is a 400 carrying only a code; the page says what that
        // means for the person holding the link. Anything else (the rate limit, the
        // network) is shown as the server or the client described it.
        setMessage(
          isAxiosError(err) && err.response?.status === 400
            ? INVALID_LINK_MESSAGE
            : getApiErrorMessage(err, INVALID_LINK_MESSAGE),
        );
      });
  }, [location.hash, location.pathname, location.search, navigate, token]);

  return (
    <StandalonePage>
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          {status === 'loading' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
                <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--primary))]" />
              </div>
              <CardTitle as="h1">Confirming Address</CardTitle>
              <CardDescription>Please wait while we confirm this address...</CardDescription>
            </>
          )}

          {status === 'success' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
                <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <CardTitle as="h1">Address Confirmed</CardTitle>
              <CardDescription>{message}</CardDescription>
            </>
          )}

          {status === 'error' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-950">
                <XCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <CardTitle as="h1">Confirmation Failed</CardTitle>
              <CardDescription>{message}</CardDescription>
            </>
          )}
        </CardHeader>

        {status !== 'loading' && (
          <CardContent className="pt-0">
            <CardFooter className="justify-center px-0">
              <Link
                to="/login"
                className="text-sm font-medium text-[hsl(var(--primary))] hover:underline"
              >
                Go to H-Vault
              </Link>
            </CardFooter>
          </CardContent>
        )}
      </Card>
    </StandalonePage>
  );
}
