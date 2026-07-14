import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowLeft, CheckCircle, AlertCircle, AlertTriangle } from 'lucide-react';
import { BrandLogo } from '../ui/BrandLogo';
import { forgotPasswordApi } from '../../services/api/authApi';
import { getApiErrorMessage, hasValidEmailTld } from '../../lib/utils';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../ui/Card';

/* -------------------------------------------------------------------------- */
/*  Schema                                                                    */
/* -------------------------------------------------------------------------- */

const forgotPasswordSchema = z.object({
  email: z
    .string()
    .min(1, 'Email is required')
    .pipe(z.email('Enter a valid email address'))
    .refine(hasValidEmailTld, 'Enter a valid email address'),
});

type ForgotPasswordFormValues = z.infer<typeof forgotPasswordSchema>;

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export function ForgotPasswordPage() {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [emailSent, setEmailSent] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  const form = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: {
      email: '',
    },
  });

  const handleSubmit = async (values: ForgotPasswordFormValues) => {
    setIsSubmitting(true);
    setApiError(null);
    try {
      const response = await forgotPasswordApi({ email: values.email });
      const data = response.data;
      const sent = data.success && 'data' in data && data.data.emailSent;
      setEmailSent(sent);
      setIsSubmitted(true);
    } catch (err) {
      // If the API call itself fails (network error, server down), show the error
      setApiError(getApiErrorMessage(err, 'Failed to send reset email. Please try again later.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  /* ---- Success view ---- */
  if (isSubmitted) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="items-center text-center">
            {emailSent ? (
              <>
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
                  <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
                </div>
                <CardTitle>Check Your Email</CardTitle>
                <CardDescription>
                  If an account exists with that email address, we&apos;ve sent password reset
                  instructions. Please check your inbox and spam folder.
                </CardDescription>
              </>
            ) : (
              <>
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-yellow-100 dark:bg-yellow-950">
                  <AlertTriangle className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
                </div>
                <CardTitle>Email Could Not Be Sent</CardTitle>
                <CardDescription>
                  We were unable to send the password reset email. This may be due to a server
                  configuration issue. Please try again later or contact support.
                </CardDescription>
              </>
            )}
          </CardHeader>

          <CardFooter className="justify-center">
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to sign in
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  /* ---- Form view ---- */
  return (
    <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
            <BrandLogo className="h-6 w-6 text-[hsl(var(--primary))]" />
          </div>
          <CardTitle>Forgot Password</CardTitle>
          <CardDescription>
            Enter the email address associated with your account and we&apos;ll send you a link to
            reset your password.
          </CardDescription>
        </CardHeader>

        <form onSubmit={(e) => void form.handleSubmit(handleSubmit)(e)}>
          <CardContent className="space-y-4">
            {apiError && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-3 text-sm text-[hsl(var(--destructive))]"
              >
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{apiError}</span>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="forgot-email" error={!!form.formState.errors.email}>
                Email
              </Label>
              <Input
                id="forgot-email"
                type="email"
                placeholder="you@example.com"
                autoComplete="email"
                autoFocus
                error={!!form.formState.errors.email}
                {...form.register('email')}
              />
              {form.formState.errors.email && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.email.message}
                </p>
              )}
            </div>
          </CardContent>

          <CardFooter className="flex-col gap-4">
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Send Reset Link
            </Button>
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to sign in
            </Link>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
