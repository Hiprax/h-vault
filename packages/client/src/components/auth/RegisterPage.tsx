import { useState, useMemo, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from '@hvault/shared/zod';
import { MAX_INVITATION_TOKEN_LENGTH } from '@hvault/shared';
import type { RegistrationMode } from '@hvault/shared';
import type zxcvbnType from 'zxcvbn';
import { getZxcvbn } from '../../lib/lazyZxcvbn';
import { Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { BrandLogo } from '../ui/BrandLogo';
import { useAuthStore } from '../../stores/authStore';
import { cn, getApiErrorMessage } from '../../lib/utils';
import { accountEmailSchema } from '../../lib/accountEmail';
import { readRegistrationMode } from '../../services/api/configApi';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Label } from '../ui/Label';
import { FormAlert } from '../ui/FormAlert';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../ui/Card';
import { StandalonePage } from '../layout/StandalonePage';

/* -------------------------------------------------------------------------- */
/*  Schema                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * An invitation as the link carries it: the same alphabet and bound the server's
 * schema enforces (`invitationTokenSchema`), checked here after the form trims, so
 * the page can say so in its own sentence.
 */
function isInvitationToken(value: string): boolean {
  return value.length <= MAX_INVITATION_TOKEN_LENGTH && /^[A-Za-z0-9_-]+$/.test(value);
}

/** The fragment an invitation link carries: `#invite=<token>`. */
const INVITATION_FRAGMENT_PREFIX = '#invite=';

const registerFormSchema = z
  .object({
    email: accountEmailSchema,
    masterPassword: z.string().min(12, 'Master password must be at least 12 characters'),
    confirmPassword: z.string().min(1, 'Please confirm your password'),
    acceptTerms: z.literal(true, {
      message: 'You must acknowledge this to continue',
    }),
    // The invitation, pasted or taken from the link's fragment. Whether one is
    // REQUIRED depends on the server's mode, which the submit handler knows; the
    // schema only refuses something that cannot be one.
    invitationToken: z
      .string()
      .trim()
      .refine((value) => value === '' || isInvitationToken(value), {
        message: 'That is not an invitation code.',
      }),
  })
  .refine((data) => data.masterPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

type RegisterFormValues = z.infer<typeof registerFormSchema>;

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

export function RegisterPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { register: registerUser } = useAuthStore();
  // What the server says about who may register, or null until (or unless) it says.
  const [mode, setMode] = useState<RegistrationMode | null>(null);
  // Whether this visit arrived through an invitation link.
  const [invitedByLink, setInvitedByLink] = useState(false);

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const form = useForm<RegisterFormValues>({
    resolver: zodResolver(registerFormSchema),
    defaultValues: {
      email: '',
      masterPassword: '',
      confirmPassword: '',
      acceptTerms: false as unknown as true,
      invitationToken: '',
    },
  });

  useEffect(() => {
    let active = true;
    void readRegistrationMode().then((value) => {
      if (active) setMode(value);
    });
    return () => {
      active = false;
    };
  }, []);

  // An invitation link carries its token in the FRAGMENT, which the browser never
  // sends to a server. It is moved into the form and the fragment is replaced away
  // at once, so the token stays in no history entry and no later copy of the URL.
  useEffect(() => {
    if (!location.hash.startsWith(INVITATION_FRAGMENT_PREFIX)) return;
    form.setValue('invitationToken', location.hash.slice(INVITATION_FRAGMENT_PREFIX.length));
    setInvitedByLink(true);
    void navigate(
      { pathname: location.pathname, search: location.search, hash: '' },
      { replace: true },
    );
  }, [location.hash, location.pathname, location.search, form, navigate]);

  const showInvitationField = mode === 'invite' || invitedByLink;

  const masterPasswordValue = form.watch('masterPassword');
  const [zxcvbnFn, setZxcvbnFn] = useState<typeof zxcvbnType | null>(null);

  useEffect(() => {
    void getZxcvbn().then((fn) => setZxcvbnFn(() => fn));
  }, []);

  const passwordResult = useMemo(
    () => (masterPasswordValue && zxcvbnFn ? zxcvbnFn(masterPasswordValue) : null),
    [masterPasswordValue, zxcvbnFn],
  );

  const handleRegister = async (values: RegisterFormValues) => {
    setIsSubmitting(true);
    setApiError(null);
    try {
      // Enforce minimum password strength (zxcvbn score >= 3) — matches the
      // change-password flow in SettingsPage. The strength meter remains
      // visible above so the user can see the score; this gate blocks
      // submission of a weak master password rather than just warning.
      const zxcvbnLoaded = await getZxcvbn();
      const strengthResult = zxcvbnLoaded(values.masterPassword);
      if (strengthResult.score < 3) {
        setApiError('New password is too weak. Please choose a stronger password.');
        document.getElementById('register-password')?.focus();
        return;
      }

      const invitationToken = showInvitationField ? values.invitationToken : '';
      if (mode === 'invite' && invitationToken === '') {
        form.setError('invitationToken', {
          message: 'An invitation is required to register on this server.',
        });
        document.getElementById('register-invitation')?.focus();
        return;
      }

      const { emailSent } = await registerUser(
        values.email,
        values.masterPassword,
        invitationToken === '' ? undefined : invitationToken,
      );
      void navigate('/login', {
        replace: true,
        state: { registered: true, emailSent },
      });
    } catch (err) {
      setApiError(getApiErrorMessage(err, 'Registration failed. Please try again.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (mode === 'closed') {
    return (
      <StandalonePage className="py-8">
        <Card className="w-full max-w-md">
          <CardHeader className="items-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
              <BrandLogo className="h-6 w-6 text-[hsl(var(--primary))]" />
            </div>
            <CardTitle as="h1">Create Account</CardTitle>
            <CardDescription>
              Registration is closed on this server. Ask the person who runs it for an account.
            </CardDescription>
          </CardHeader>
          <CardFooter className="flex-col gap-4">
            <p className="text-center text-sm text-[hsl(var(--muted-foreground))]">
              Already have an account?{' '}
              <Link to="/login" className="font-medium text-[hsl(var(--primary))] hover:underline">
                Sign in
              </Link>
            </p>
          </CardFooter>
        </Card>
      </StandalonePage>
    );
  }

  return (
    <StandalonePage className="py-8">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[hsl(var(--primary)/0.1)]">
            <BrandLogo className="h-6 w-6 text-[hsl(var(--primary))]" />
          </div>
          <CardTitle as="h1">Create Account</CardTitle>
          <CardDescription>Set up your H-Vault account</CardDescription>
        </CardHeader>

        <form onSubmit={(e) => void form.handleSubmit(handleRegister)(e)}>
          <CardContent className="space-y-4">
            {apiError && <FormAlert message={apiError} />}

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="register-email" error={!!form.formState.errors.email}>
                Email
              </Label>
              <Input
                id="register-email"
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

            {/* Invitation: on a server that registers by invitation, or when this
                visit came through an invitation link. */}
            {showInvitationField && (
              <div className="space-y-2">
                <Label
                  htmlFor="register-invitation"
                  error={!!form.formState.errors.invitationToken}
                >
                  Invitation code
                </Label>
                <Input
                  id="register-invitation"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Paste the code from your invitation link"
                  error={!!form.formState.errors.invitationToken}
                  {...form.register('invitationToken')}
                />
                {form.formState.errors.invitationToken && (
                  <p className="text-sm text-[hsl(var(--destructive))]">
                    {form.formState.errors.invitationToken.message}
                  </p>
                )}
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  An invitation works for the one address it was made for, once.
                </p>
              </div>
            )}

            {/* Master Password */}
            <div className="space-y-2">
              <Label htmlFor="register-password" error={!!form.formState.errors.masterPassword}>
                Master Password
              </Label>
              <div className="relative">
                <Input
                  id="register-password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Minimum 12 characters"
                  autoComplete="new-password"
                  error={!!form.formState.errors.masterPassword}
                  className="pr-10"
                  {...form.register('masterPassword')}
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
              {form.formState.errors.masterPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.masterPassword.message}
                </p>
              )}

              {/* Strength meter */}
              {passwordResult && (
                <div className="space-y-1.5">
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

            {/* Confirm Password */}
            <div className="space-y-2">
              <Label htmlFor="register-confirm" error={!!form.formState.errors.confirmPassword}>
                Confirm Master Password
              </Label>
              <div className="relative">
                <Input
                  id="register-confirm"
                  type={showConfirmPassword ? 'text' : 'password'}
                  placeholder="Re-enter your master password"
                  autoComplete="new-password"
                  error={!!form.formState.errors.confirmPassword}
                  className="pr-10"
                  {...form.register('confirmPassword')}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showConfirmPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {form.formState.errors.confirmPassword && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.confirmPassword.message}
                </p>
              )}
            </div>

            {/* Warning */}
            <div className="flex gap-2 rounded-md border border-yellow-500/30 bg-yellow-50 p-3 dark:bg-yellow-950/30">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-600 dark:text-yellow-400" />
              <p className="text-xs text-yellow-800 dark:text-yellow-200">
                Your master password cannot be recovered if you forget it. Please store it in a safe
                place. There is no password reset for your vault.
              </p>
            </div>

            {/* Terms */}
            <div className="space-y-1">
              <label className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-1 h-4 w-4 rounded border-[hsl(var(--input))] text-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
                  {...form.register('acceptTerms')}
                />
                <span className="text-sm text-[hsl(var(--muted-foreground))]">
                  I understand that H-Vault cannot recover my master password and that I am
                  responsible for remembering it.
                </span>
              </label>
              {form.formState.errors.acceptTerms && (
                <p className="text-sm text-[hsl(var(--destructive))]">
                  {form.formState.errors.acceptTerms.message}
                </p>
              )}
            </div>
          </CardContent>

          <CardFooter className="flex-col gap-4">
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Create Account
            </Button>
            <p className="text-center text-sm text-[hsl(var(--muted-foreground))]">
              Already have an account?{' '}
              <Link to="/login" className="font-medium text-[hsl(var(--primary))] hover:underline">
                Sign in
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>
    </StandalonePage>
  );
}
