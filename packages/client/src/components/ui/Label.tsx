import { forwardRef, type LabelHTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

export interface LabelProps extends LabelHTMLAttributes<HTMLLabelElement> {
  /** When true, applies destructive color to indicate an error */
  error?: boolean;
}

const Label = forwardRef<HTMLLabelElement, LabelProps>(({ className, error, ...props }, ref) => (
  <label
    ref={ref}
    className={cn(
      'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
      error && 'text-[hsl(var(--destructive))]',
      className,
    )}
    {...props}
  />
));
Label.displayName = 'Label';

export { Label };
