import { useEffect, useState, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { CheckCircle, XCircle, ArrowLeft, Loader2 } from 'lucide-react';
import { unlockAccountApi } from '../services/api/authApi';
import { getApiErrorMessage } from '../lib/utils';
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
  CardDescription,
} from '../components/ui/Card';

export default function UnlockAccountPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');
  const calledRef = useRef(false);

  useEffect(() => {
    if (calledRef.current) return;
    calledRef.current = true;

    if (!token) {
      setStatus('error');
      setMessage('No unlock token found. Please check the link from your email.');
      return;
    }

    void unlockAccountApi({ token })
      .then((res) => {
        setStatus('success');
        const msg = res.data.success ? res.data.message : undefined;
        setMessage(msg ?? 'Account unlocked successfully. You can now log in.');
      })
      .catch((err: unknown) => {
        setStatus('error');
        setMessage(getApiErrorMessage(err, 'Account unlock failed. The link may have expired.'));
      });
  }, [token]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          {status === 'loading' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
                <Loader2 className="h-6 w-6 animate-spin text-[hsl(var(--primary))]" />
              </div>
              <CardTitle>Unlocking Account</CardTitle>
              <CardDescription>Please wait while we unlock your account...</CardDescription>
            </>
          )}

          {status === 'success' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
                <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <CardTitle>Account Unlocked</CardTitle>
              <CardDescription>{message}</CardDescription>
            </>
          )}

          {status === 'error' && (
            <>
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-950">
                <XCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <CardTitle>Unlock Failed</CardTitle>
              <CardDescription>{message}</CardDescription>
            </>
          )}
        </CardHeader>

        {status !== 'loading' && (
          <CardContent className="pt-0">
            <CardFooter className="justify-center px-0">
              <Link
                to="/login"
                className="inline-flex items-center gap-2 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
              >
                <ArrowLeft className="h-4 w-4" />
                Go to sign in
              </Link>
            </CardFooter>
          </CardContent>
        )}
      </Card>
    </div>
  );
}
