import { CalendarClock, CalendarX } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../../lib/utils';
import {
  cardExpiryHint,
  describeCardExpiry,
  formatCardExpiry,
  type CardExpiry,
  type CardExpiryStatus,
} from '../../lib/cardExpiry';

/**
 * How a warned card looks, by status. A table rather than ternaries at each
 * site, so the badge, the item-view notice and the editor hint can never pair
 * the expired icon with the expiring colour.
 *
 * Every class here already exists elsewhere in the app (the secret type pill,
 * the expired-secret callout, the interrupted-rotation banner, the degraded
 * document badge): each NEW utility class adds to the global stylesheet every
 * page downloads first, and that payload has a budget. Each 700/800 text shade
 * carries its `dark:text-` partner in the same literal (`theme-contrast.test.ts`).
 */
const TONE: Record<
  Exclude<CardExpiryStatus, 'valid'>,
  { label: string; Icon: LucideIcon; pill: string; box: string; text: string }
> = {
  expired: {
    label: 'Expired',
    Icon: CalendarX,
    pill: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    box: 'border-red-500/30 bg-red-50 dark:bg-red-950/30',
    text: 'text-red-700 dark:text-red-300',
  },
  expiring: {
    label: 'Expires soon',
    Icon: CalendarClock,
    pill: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
    box: 'border-amber-300 bg-amber-50 dark:border-amber-700 dark:bg-amber-900/20',
    text: 'text-amber-800 dark:text-amber-300',
  },
};

/**
 * The vault-list pill beside a card's type pill: "Expired" or "Expires soon".
 * Nothing for a valid card or one with no readable expiry.
 *
 * It sits in a fixed-height row of a virtualised list, so its box is the type
 * pill's EXACTLY (`text-xs` line plus `py-0.5` = 20px) and it has no border: a
 * 1px border would make the badge line 22px and push the row past the height the
 * list positions it by. The 12px icon fits inside the 16px line box.
 */
export function CardExpiryBadge({ expiry }: { expiry: CardExpiry | null }) {
  if (expiry === null || expiry.status === 'valid') return null;
  const tone = TONE[expiry.status];
  return (
    <span
      data-testid="card-expiry-badge"
      title={`Valid through ${formatCardExpiry(String(expiry.month), String(expiry.year))}`}
      className={cn(
        'inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
        tone.pill,
      )}
    >
      <tone.Icon className="h-3 w-3" aria-hidden="true" />
      {tone.label}
    </span>
  );
}

/**
 * The expiry notice for one card, in one of two places.
 *
 * - `detail`: a callout in the item view, with the headline, the month it rests
 *   on, and for an expired card what to do about it.
 * - `editor`: a single line under the expiry inputs, recomputed as they change.
 *
 * Neither variant is a live region. The editor's hint must be announced as the
 * user types, but a region that mounts together with its first message is not
 * reliably announced, so the form owns an ALWAYS-mounted `role="status"` and
 * renders this inside it; a second region here would announce everything twice.
 * The item view's notice describes what is already on screen and is not news.
 */
export function CardExpiryNotice({
  expiry,
  variant,
}: {
  expiry: CardExpiry | null;
  variant: 'detail' | 'editor';
}) {
  if (expiry === null || expiry.status === 'valid') return null;
  const tone = TONE[expiry.status];

  if (variant === 'editor') {
    return (
      <p data-testid="card-expiry-hint" className={cn('flex items-start gap-1 text-xs', tone.text)}>
        <tone.Icon className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
        <span>{cardExpiryHint(expiry)}</span>
      </p>
    );
  }

  const { headline, detail } = describeCardExpiry(expiry);
  return (
    <div
      data-testid="card-expiry-notice"
      className={cn('flex items-start gap-2 rounded-lg border p-3', tone.box)}
    >
      <tone.Icon className={cn('mt-0.5 h-4 w-4 shrink-0', tone.text)} aria-hidden="true" />
      <div className="space-y-1 text-sm">
        <p className={cn('font-medium', tone.text)}>{headline}</p>
        <p className="text-[hsl(var(--foreground))]">{detail}</p>
        {expiry.status === 'expired' && (
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            If you have a replacement card, edit this entry and update its details.
          </p>
        )}
      </div>
    </div>
  );
}
