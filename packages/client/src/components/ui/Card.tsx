import { forwardRef, type HTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] text-[hsl(var(--card-foreground))] shadow-sm',
        className,
      )}
      {...props}
    />
  ),
);
Card.displayName = 'Card';

const CardHeader = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('flex flex-col space-y-1.5 p-6', className)} {...props} />
  ),
);
CardHeader.displayName = 'CardHeader';

interface CardTitleProps extends HTMLAttributes<HTMLHeadingElement> {
  /**
   * The heading level, which is a statement about the PAGE, not the card.
   *
   * `h2` by default because that is what a card is almost everywhere here: one
   * section of a page whose own `h1` sits above it (Settings, Backup, Export,
   * File Encryption). A default of `h3` made every one of those pages skip a
   * level (`heading-order`). A card that IS the page — the sign-in, registration,
   * reset, verification and unlock screens — passes `h1`, because its title is
   * the only heading that names the screen (`page-has-heading-one`).
   */
  as?: 'h1' | 'h2' | 'h3';
}

const CardTitle = forwardRef<HTMLHeadingElement, CardTitleProps>(
  ({ as: Heading = 'h2', className, ...props }, ref) => (
    <Heading
      ref={ref}
      className={cn('text-2xl font-semibold leading-none tracking-tight', className)}
      {...props}
    />
  ),
);
CardTitle.displayName = 'CardTitle';

const CardDescription = forwardRef<HTMLParagraphElement, HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn('text-sm text-[hsl(var(--muted-foreground))]', className)}
      {...props}
    />
  ),
);
CardDescription.displayName = 'CardDescription';

const CardContent = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('p-6 pt-0', className)} {...props} />
  ),
);
CardContent.displayName = 'CardContent';

const CardFooter = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn('flex items-center p-6 pt-0', className)} {...props} />
  ),
);
CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter };
