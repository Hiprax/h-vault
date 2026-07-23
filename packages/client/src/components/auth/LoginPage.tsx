import { useState, useCallback } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Eye, EyeOff, AlertCircle, CheckCircle, AlertTriangle } from 'lucide-react';
import { BrandLogo } from '../ui/BrandLogo';
import { useAuthStore } from '../../stores/authStore';
import { getApiErrorMessage, hasValidEmailTld } from '../../lib/utils';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { OtpInput } from '../ui/OtpInput';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../ui/Card';

/* -------------------------------------------------------------------------- */
/*  Schemas                                                                   */
/* -------------------------------------------------------------------------- */

const loginFormSchema = z.object({
  email: z
    .string()
    .min(1, 'Email is required')
    .pipe(z.email('Enter a valid email address'))
    .refine(hasValidEmailTld, 'Enter a valid email address'),
  masterPassword: z.string().min(1, 'Master password is required'),
  rememberMe: z.boolean(),
});

type LoginFormValues = z.infer<typeof loginFormSchema>;

const twoFactorSchema = z.object({
  code: z
    .string()
    .min(6, 'Code must be at least 6 characters')
    .max(16, 'Code must be at most 16 characters'),
});

type TwoFactorFormValues = z.infer<typeof twoFactorSchema>;

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

interface LocationState {
  registered?: boolean;
  emailSent?: boolean;
  sessionExpired?: boolean;
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, verify2fa, twoFactorRequired } = useAuthStore();
  const locationState = location.state as LocationState | null;

  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [otpValue, setOtpValue] = useState('');

  /* ---- Login form ---- */
  const loginForm = useForm<LoginFormValues>({
    resolver: zodResolver(loginFormSchema),
    defaultValues: {
      email: '',
      masterPassword: '',
      rememberMe: false,
    },
  });

  const handleLogin = async (values: LoginFormValues) => {
    setIsSubmitting(true);
    setApiError(null);
    try {
      await login(values.email, values.masterPassword, values.rememberMe);
      // If 2FA is required the store sets twoFactorRequired=true and we stay
      // on this page to collect the code. Otherwise navigate to the vault.
      const currentState = useAuthStore.getState();
      if (currentState.twoFactorRequired) {
        // Clear password from form state so it doesn't linger in memory
        loginForm.setValue('masterPassword', '');
      } else if (currentState.isAuthenticated) {
        void navigate('/vault', { replace: true });
      }
    } catch (err) {
      setApiError(getApiErrorMessage(err, 'Login failed. Please try again.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  /* ---- 2FA form ---- */
  const twoFactorForm = useForm<TwoFactorFormValues>({
    resolver: zodResolver(twoFactorSchema),
    defaultValues: {
      code: '',
    },
  });

  const handleVerify2fa = async (values: TwoFactorFormValues) => {
    setIsSubmitting(true);
    setApiError(null);
    try {
      await verify2fa(values.code);
      void navigate('/vault', { replace: true });
    } catch (err) {
      setApiError(getApiErrorMessage(err, 'Invalid code. Please try again.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOtpSubmit = useCallback(async () => {
    if (otpValue.length < 6) {
      setApiError('Code must be at least 6 digits');
      return;
    }
    setIsSubmitting(true);
    setApiError(null);
    try {
      await verify2fa(otpValue);
      void navigate('/vault', { replace: true });
    } catch (err) {
      setApiError(getApiErrorMessage(err, 'Invalid code. Please try again.'));
    } finally {
      setIsSubmitting(false);
    }
  }, [otpValue, verify2fa, navigate]);

  /* ---- 2FA view ---- */
  if (twoFactorRequired) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="items-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
              <BrandLogo className="h-6 w-6 text-[hsl(var(--primary))]" />
            </div>
            <CardTitle>Two-Factor Authentication</CardTitle>
            <CardDescription>
              {useBackupCode
                ? 'Enter one of your 16-character backup codes'
                : 'Enter the 6-digit code from your authenticator app'}
            </CardDescription>
          </CardHeader>

          {useBackupCode ? (
            <form onSubmit={(e) => void twoFactorForm.handleSubmit(handleVerify2fa)(e)}>
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
                  <Label htmlFor="backup-code">Backup Code</Label>
                  <Input
                    id="backup-code"
                    placeholder="abcdef1234567890"
                    autoComplete="one-time-code"
                    autoFocus
                    maxLength={16}
                    className="font-mono tracking-wider"
                    error={!!twoFactorForm.formState.errors.code}
                    {...twoFactorForm.register('code')}
                  />
                  {twoFactorForm.formState.errors.code && (
                    <p className="text-sm text-[hsl(var(--destructive))]">
                      {twoFactorForm.formState.errors.code.message}
                    </p>
                  )}
                </div>
              </CardContent>

              <CardFooter className="flex-col gap-4">
                <Button type="submit" className="w-full" loading={isSubmitting}>
                  Verify
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    setUseBackupCode(false);
                    setApiError(null);
                    twoFactorForm.reset();
                    setOtpValue('');
                  }}
                  className="text-sm text-[hsl(var(--primary))] hover:underline"
                >
                  Use authenticator code instead
                </button>
              </CardFooter>
            </form>
          ) : (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleOtpSubmit();
              }}
            >
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
                  <Label>Verification Code</Label>
                  <OtpInput
                    value={otpValue}
                    onChange={setOtpValue}
                    disabled={isSubmitting}
                    autoFocus
                    aria-label="6-digit verification code"
                  />
                </div>
              </CardContent>

              <CardFooter className="flex-col gap-4">
                <Button
                  type="submit"
                  className="w-full"
                  loading={isSubmitting}
                  disabled={otpValue.length < 6}
                >
                  Verify
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    setUseBackupCode(true);
                    setApiError(null);
                    twoFactorForm.reset();
                    setOtpValue('');
                  }}
                  className="text-sm text-[hsl(var(--primary))] hover:underline"
                >
                  Use a backup code
                </button>
              </CardFooter>
            </form>
          )}
        </Card>
      </div>
    );
  }

  /* ---- Login view ---- */
  return (
    <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
            <BrandLogo className="h-6 w-6 text-[hsl(var(--primary))]" />
          </div>
          <CardTitle>Welcome Back</CardTitle>
          <CardDescription>Sign in to your H-Vault account</CardDescription>
        </CardHeader>

        <form onSubmit={(e) => void loginForm.handleSubmit(handleLogin)(e)}>
          <CardContent className="space-y-4">
            {locationState?.sessionExpired && (
              <div
                role="status"
                className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-50 p-3 text-sm text-yellow-800 dark:bg-yellow-950/30 dark:text-yellow-200"
              >
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>Your session has expired. Please sign in again.</span>
              </div>
            )}

            {locationState?.registered && locationState.emailSent !== false && (
              <div
                role="status"
                className="flex items-center gap-2 rounded-md border border-green-500/30 bg-green-50 p-3 text-sm text-green-800 dark:bg-green-950/30 dark:text-green-200"
              >
                <CheckCircle className="h-4 w-4 shrink-0" />
                <span>
                  Account created! Please check your email to verify your address before signing in.
                </span>
              </div>
            )}

            {locationState?.registered && locationState.emailSent === false && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-50 p-3 text-sm text-yellow-800 dark:bg-yellow-950/30 dark:text-yellow-200"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>
                  Account created, but we could not send the verification email. Please use
                  &ldquo;Resend verification&rdquo; from the login error or contact support.
                </span>
              </div>
            )}

            {apiError && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-3 text-sm text-[hsl(var(--destructive))]"
              >
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{apiError}</span>
              </div>
            )}

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="login-email" error={!!loginForm.formState.errors.email}>
                Email
              </Label>
              <Input
                id="login-email"
                type="email"
                placeholder="you@example.com"
                autoComplete="email"
                autoFocus
                error={!!loginForm.formState.errors.email}
                {...loginForm.register('email')}
              />
              {loginForm.formState.errors.email && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {loginForm.formState.errors.email.message}
                </p>
              )}
            </div>

            {/* Master Password */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="login-password" error={!!loginForm.formState.errors.masterPassword}>
                  Master Password
                </Label>
                <Link
                  to="/forgot-password"
                  className="text-xs text-[hsl(var(--primary))] hover:underline"
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your master password"
                  autoComplete="current-password"
                  error={!!loginForm.formState.errors.masterPassword}
                  className="pr-10"
                  {...loginForm.register('masterPassword')}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {loginForm.formState.errors.masterPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {loginForm.formState.errors.masterPassword.message}
                </p>
              )}
            </div>

            {/* Remember me on this device (opt-in) */}
            <div className="space-y-1">
              <label htmlFor="login-remember" className="flex items-center gap-2">
                <input
                  id="login-remember"
                  type="checkbox"
                  aria-describedby="login-remember-hint"
                  className="h-4 w-4 rounded border-[hsl(var(--input))] text-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
                  {...loginForm.register('rememberMe')}
                />
                <span className="text-sm text-[hsl(var(--foreground))]">
                  Remember me on this device
                </span>
              </label>
              <p
                id="login-remember-hint"
                className="pl-6 text-xs text-[hsl(var(--muted-foreground))]"
              >
                Only use this on a device you trust. You&apos;ll still enter your master password
                every time &mdash; it is never stored.
              </p>
            </div>
          </CardContent>

          <CardFooter className="flex-col gap-4">
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Sign In
            </Button>
            <p className="text-center text-sm text-[hsl(var(--muted-foreground))]">
              Don&apos;t have an account?{' '}
              <Link
                to="/register"
                className="font-medium text-[hsl(var(--primary))] hover:underline"
              >
                Create account
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
