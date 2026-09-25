import { AlertCircle } from 'lucide-react';

interface FormAlertProps {
  /** The sentence to show. */
  message: string;
}

/**
 * The error line an account form shows above its fields.
 *
 * `role="alert"` so a failed sign-in is announced the moment it appears. One
 * definition for every account form, which is what keeps their failures looking
 * and sounding the same. WHETHER to show it stays with each form (`{apiError &&
 * <FormAlert message={apiError} />}`), because each form owns the condition —
 * the unlock screen, for one, hides it while a lockout notice is up.
 */
export function FormAlert({ message }: FormAlertProps) {
  return (
    <div
      role="alert"
      className="flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] bg-[hsl(var(--destructive)/0.05)] p-3 text-sm text-[hsl(var(--destructive))]"
    >
      <AlertCircle className="h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}
