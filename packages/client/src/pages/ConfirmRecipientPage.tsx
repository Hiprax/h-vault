import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { isAxiosError } from 'axios';
import { CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { confirmBackupRecipientApi } from '../services/api/backupApi';
import { getApiErrorMessage } from '../lib/utils';
import { useLinkToken } from '../lib/linkToken';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '../components/ui/Card';
import { StandalonePage } from '../components/layout/StandalonePage';

/** What a link without a usable token means. */
const INCOMPLETE_LINK_MESSAGE =
  'This confirmation link is incomplete. Open the link from the email again.';
/** What a refused link means, in the recipient's terms. */
const INVALID_LINK_MESSAGE =
  'This confirmation link is not valid. It may have expired, been used already, or been replaced by a newer one.';

/**
 * `/backup/confirm-recipient#token=…`: the page a backup recipient lands on from
 * its confirmation email. The recipient usually has no account here, so the page
 * needs no session: it takes the token from the fragment, removes the fragment
 * from the address bar at once (so the token is not left in the history entry or
 * in a bookmark), and sends it to the server once.
 */
export default function ConfirmRecipientPage() {
  // From the fragment ONLY (this link never had a query form), read once and then
  // removed from the address bar. `lib/linkToken.ts`.
  const token = useLinkToken();
  // The first paint shows the right state before the effect below has run (a
  // browser paints before running it); the effect then keeps both current for a
  // later link too.
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    token === null ? 'error' : 'loading',
  );
  // Shown only once there is an outcome; until then it is the no-token sentence.
  const [message, setMessage] = useState(INCOMPLETE_LINK_MESSAGE);
  // Every token already handled: each is sent once (StrictMode runs this effect
  // twice), and a SECOND link opened in the same tab, which changes the token
  // without a reload, is sent too.
  const handledRef = useRef(new Set<string | null>());
  // Which request is current: an answer for a token a later link superseded is
  // dropped, so it cannot overwrite the newer link's result.
  const requestRef = useRef<object | null>(null);

  useEffect(() => {
    if (handledRef.current.has(token)) return;
    handledRef.current.add(token);
    // A fresh object per request: identity, not arithmetic, tells them apart.
    const request = {};
    requestRef.current = request;

    if (!token) {
      // A link that carries no usable token, the first one or a later one.
      setStatus('error');
      setMessage(INCOMPLETE_LINK_MESSAGE);
      return;
    }

    setStatus('loading');
    void confirmBackupRecipientApi({ token })
      .then((res) => {
        if (request !== requestRef.current) return;
        setStatus('success');
        setMessage(
          (res.data.success ? res.data.message : undefined) ??
            'This address will now receive the encrypted backups it was asked to receive.',
        );
      })
      .catch((err: unknown) => {
        if (request !== requestRef.current) return;
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
  }, [token]);

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

        {(status === 'success' || status === 'error') && (
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
