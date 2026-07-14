import { useState, useMemo, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../lib/lazyZxcvbn';
import { ArrowLeft, CheckCircle, AlertCircle, AlertTriangle, Eye, EyeOff } from 'lucide-react';
import { BrandLogo } from '../components/ui/BrandLogo';
import { resetPasswordApi } from '../services/api/authApi';
import { cn, getApiErrorMessage, hasValidEmailTld } from '../lib/utils';
import { cryptoService } from '../services/crypto/cryptoService';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '../components/ui/Card';

/* -------------------------------------------------------------------------- */
/*  Schema                                                                    */
/* -------------------------------------------------------------------------- */

const resetPasswordSchema = z
  .object({
    email: z
      .string()
      .min(1, 'Email is required')
      .pipe(z.email('Enter a valid email address'))
      .refine(hasValidEmailTld, 'Enter a valid email address'),
    newPassword: z.string().min(12, 'Password must be at least 12 characters'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type ResetPasswordFormValues = z.infer<typeof resetPasswordSchema>;

/* -------------------------------------------------------------------------- */
/*  Password strength helpers                                                 */
/* -------------------------------------------------------------------------- */

const strengthLabels: Record<number, string> = {
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
};

const strengthColors: Record<number, string> = {
  0: 'bg-red-500',
  1: 'bg-orange-500',
  2: 'bg-yellow-500',
  3: 'bg-green-500',
  4: 'bg-emerald-500',
};

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);

  const form = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { email: '', newPassword: '', confirmPassword: '' },
  });

  const newPasswordValue = form.watch('newPassword');
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    void getZxcvbn().then((fn) => setZxcvbnFn(() => fn));
  }, []);

  const passwordResult = useMemo(
    () => (newPasswordValue && zxcvbnFn ? zxcvbnFn(newPasswordValue) : null),
    [newPasswordValue, zxcvbnFn],
  );

  const handleSubmit = async (values: ResetPasswordFormValues) => {
    if (!token) return;
    setIsSubmitting(true);
    setApiError(null);

    let newMek: CryptoKey | null = null;
    let newVaultKeyRaw: ArrayBuffer | null = null;
    let newVaultKeyCK: CryptoKey | null = null;
    let newAuthKey: ArrayBuffer | null = null;

    try {
      // Enforce minimum password strength (zxcvbn score >= 3) — matches the
      // change-password flow in SettingsPage. The strength meter remains
      // visible above so the user can see the score; this gate blocks
      // submission of a weak master password rather than just warning.
      const zxcvbnLoaded = await getZxcvbn();
      const strengthResult = zxcvbnLoaded(values.newPassword);
      if (strengthResult.score < 3) {
        setApiError('New password is too weak. Please choose a stronger password.');
        document.getElementById('reset-new-password')?.focus();
        return;
      }

      // Derive new keys from the new password + email
      const keys = await cryptoService.deriveKeys(values.newPassword, values.email);
      newMek = keys.masterEncryptionKey;
      newAuthKey = keys.authKey;
      const newAuthHash = cryptoService.getAuthHash(keys.authKey);

      // Generate a fresh vault key (old data encrypted with the previous key is unrecoverable)
      newVaultKeyRaw = cryptoService.generateVaultKey();
      newVaultKeyCK = await cryptoService.importVaultKey(newVaultKeyRaw);
      cryptoService.clearKey(newVaultKeyRaw);
      newVaultKeyRaw = null;
      const encryptedVaultKeyData = await cryptoService.encryptVaultKey(newVaultKeyCK, newMek);

      await resetPasswordApi({
        token,
        email: values.email,
        newAuthHash,
        newEncryptedVaultKey: encryptedVaultKeyData.encrypted,
        newVaultKeyIv: encryptedVaultKeyData.iv,
        newVaultKeyTag: encryptedVaultKeyData.tag,
      });

      setIsSuccess(true);
    } catch (err) {
      setApiError(getApiErrorMessage(err, 'Failed to reset password. The link may have expired.'));
    } finally {
      // Clean up sensitive material
      if (newVaultKeyRaw) cryptoService.clearKey(newVaultKeyRaw);
      if (newVaultKeyCK) void cryptoService.clearCryptoKey(newVaultKeyCK);
      if (newAuthKey) cryptoService.clearKey(newAuthKey);
      if (newMek) void cryptoService.clearCryptoKey(newMek);
      setIsSubmitting(false);
    }
  };

  /* ---- Missing token ---- */
  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="items-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-950">
              <AlertCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
            </div>
            <CardTitle>Invalid Link</CardTitle>
            <CardDescription>
              No reset token found. Please check the link from your email or request a new password
              reset.
            </CardDescription>
          </CardHeader>
          <CardFooter className="justify-center">
            <Link
              to="/forgot-password"
              className="inline-flex items-center gap-2 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
            >
              <ArrowLeft className="h-4 w-4" />
              Request new reset link
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  /* ---- Success view ---- */
  if (isSuccess) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[hsl(var(--background))] px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="items-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
              <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <CardTitle>Password Reset Complete</CardTitle>
            <CardDescription>
              Your password has been reset successfully. You can now sign in with your new password.
            </CardDescription>
          </CardHeader>
          <CardFooter className="justify-center">
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
            >
              <ArrowLeft className="h-4 w-4" />
              Go to sign in
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
          <CardTitle>Reset Password</CardTitle>
          <CardDescription>Enter your email and choose a new master password.</CardDescription>
        </CardHeader>

        <form onSubmit={(e) => void form.handleSubmit(handleSubmit)(e)}>
          <CardContent className="space-y-4">
            {/* Data loss warning */}
            <div
              role="alert"
              className="flex items-start gap-2 rounded-md border border-yellow-300 bg-yellow-50 p-3 text-sm text-yellow-800 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-200"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                Resetting your password generates a new encryption key. Any previously stored vault
                items will become unrecoverable.
              </span>
            </div>

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
              <Label htmlFor="reset-email" error={!!form.formState.errors.email}>
                Email
              </Label>
              <Input
                id="reset-email"
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

            {/* New password */}
            <div className="space-y-2">
              <Label htmlFor="reset-new-password" error={!!form.formState.errors.newPassword}>
                New Master Password
              </Label>
              <div className="relative">
                <Input
                  id="reset-new-password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="At least 12 characters"
                  autoComplete="new-password"
                  error={!!form.formState.errors.newPassword}
                  {...form.register('newPassword')}
                />
                <button
                  type="button"
                  tabIndex={-1}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {form.formState.errors.newPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.newPassword.message}
                </p>
              )}

              {/* Strength meter */}
              {passwordResult && (
                <div className="space-y-1.5" data-testid="password-strength-meter">
                  <div className="flex h-1.5 w-full gap-1">
                    {[0, 1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className={cn(
                          'h-full flex-1 rounded-full transition-colors',
                          i <= passwordResult.score
                            ? strengthColors[passwordResult.score]
                            : 'bg-[hsl(var(--muted))]',
                        )}
                      />
                    ))}
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      {strengthLabels[passwordResult.score]}
                    </p>
                    {passwordResult.feedback.warning && (
                      <p className="text-xs text-[hsl(var(--muted-foreground))]">
                        {passwordResult.feedback.warning}
                      </p>
                    )}
                  </div>
                  {passwordResult.feedback.suggestions.length > 0 && (
                    <ul className="space-y-0.5">
                      {passwordResult.feedback.suggestions.map((suggestion) => (
                        <li
                          key={suggestion}
                          className="text-xs text-[hsl(var(--muted-foreground))]"
                        >
                          {suggestion}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div className="space-y-2">
              <Label
                htmlFor="reset-confirm-password"
                error={!!form.formState.errors.confirmPassword}
              >
                Confirm New Password
              </Label>
              <Input
                id="reset-confirm-password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Re-enter your new password"
                autoComplete="new-password"
                error={!!form.formState.errors.confirmPassword}
                {...form.register('confirmPassword')}
              />
              {form.formState.errors.confirmPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.confirmPassword.message}
                </p>
              )}
            </div>
          </CardContent>

          <CardFooter className="flex-col gap-4">
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Reset Password
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
