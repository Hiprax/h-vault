import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { CalendarClock, X } from 'lucide-react';
import type { DecryptedVaultItem } from '../../stores/vaultStore';
import { cn } from '../../lib/utils';
import {
  CARD_EXPIRY_SOON_DAYS,
  cardExpiryPhrase,
  readItemCardExpiry,
  type CardExpiry,
} from '../../lib/cardExpiry';
import {
  cardExpiryFingerprint,
  dismissCardExpiryReminder,
  isCardExpiryReminderDismissed,
} from '../../lib/cardExpiryDismissal';

/** How many warned cards the reminder names; the rest are counted. */
const LISTED_CARDS = 3;

interface WarnedCard {
  id: string;
  name: string;
  expiry: CardExpiry;
}

/**
 * Every card the reminder is about, most urgent first.
 *
 * Only live cards whose payload decoded: a trashed card is not one the user
 * still carries, and an undecodable one holds a placeholder rather than its real
 * month and year (`isUndecodableData`). Sorting by `lastValidDay` alone already
 * puts every expired card ahead of every expiring one, since an expired card's
 * last day is before today and an expiring card's is today or later; within a
 * day the name, then the id, make the order total, so the same vault always
 * lists the same three.
 */
function collectWarnedCards(items: readonly DecryptedVaultItem[], now: Date): WarnedCard[] {
  const warned: WarnedCard[] = [];
  for (const item of items) {
    const expiry = readItemCardExpiry(item, now);
    if (expiry === null || expiry.status === 'valid') continue;
    warned.push({ id: item.id, name: item.name, expiry });
  }
  return warned.sort(
    (a, b) =>
      a.expiry.lastValidDay.getTime() - b.expiry.lastValidDay.getTime() ||
      a.name.localeCompare(b.name) ||
      a.id.localeCompare(b.id),
  );
}

/** `1 card`, `2 cards`. */
function cardCount(count: number): string {
  return count === 1 ? '1 card' : `${String(count)} cards`;
}

/** The opening sentence, for any mix of expired and expiring cards (never both zero). */
function summarize(expired: number, expiring: number): string {
  const expiredClause = `${cardCount(expired)} ${expired === 1 ? 'has' : 'have'} expired`;
  const window = `within ${String(CARD_EXPIRY_SOON_DAYS)} days`;
  const expiringVerb = expiring === 1 ? 'expires' : 'expire';
  if (expiring === 0) return `${expiredClause}.`;
  if (expired === 0) return `${cardCount(expiring)} ${expiringVerb} ${window}.`;
  return `${expiredClause} and ${String(expiring)} ${expiringVerb} ${window}.`;
}

interface ExpiringCardsReminderProps {
  /** The vault's items as the store holds them; trash and non-cards are ignored here. */
  items: readonly DecryptedVaultItem[];
  /** The signed-in account, so one browser's dismissal never hides another account's reminder. */
  userId: string;
  /** The instant to judge expiry at. Defaults to the clock when the items change. */
  now?: Date;
  /**
   * Called after the reminder is hidden. The close button disappears with it,
   * so the page moves focus somewhere meaningful (its heading) rather than
   * leaving it on the document body.
   */
  onHidden?: () => void;
  /**
   * Extra classes for the reminder's own box (the page's margins). Taken here
   * rather than by a wrapper, so a hidden reminder leaves no empty element.
   */
  className?: string;
}

/**
 * The vault page's reminder about cards that have expired or expire within
 * {@link CARD_EXPIRY_SOON_DAYS} days: a sentence, links to the first few, and a
 * button that hides it until the set of warned cards changes.
 *
 * Renders NOTHING when there is nothing to say or it was hidden for exactly this
 * set: no wrapper, no empty region. It is deliberately a plain block, never an
 * alert, a status region, a landmark or a heading: it is shown on arrival, not
 * news to interrupt with, and the page's landmark and heading outline are fixed.
 */
export function ExpiringCardsReminder({
  items,
  userId,
  now,
  onHidden,
  className,
}: ExpiringCardsReminderProps) {
  // `now` is read INSIDE the memo rather than defaulted in the signature: a
  // default `new Date()` would be a new dependency on every render.
  const cards = useMemo(() => collectWarnedCards(items, now ?? new Date()), [items, now]);
  const fingerprint = useMemo(
    () =>
      cardExpiryFingerprint(
        userId,
        cards.map((card) => ({ id: card.id, status: card.expiry.status })),
      ),
    [userId, cards],
  );
  // Hidden in THIS mount even when storage refuses the write, for this exact
  // set only: a new fingerprint no longer matches, and the reminder comes back.
  const [hiddenFingerprint, setHiddenFingerprint] = useState<string | null>(null);

  if (
    cards.length === 0 ||
    hiddenFingerprint === fingerprint ||
    isCardExpiryReminderDismissed(fingerprint)
  ) {
    return null;
  }

  const expiredCount = cards.filter((card) => card.expiry.status === 'expired').length;
  const listed = cards.slice(0, LISTED_CARDS);
  const unlisted = cards.length - listed.length;

  const hide = () => {
    dismissCardExpiryReminder(fingerprint);
    setHiddenFingerprint(fingerprint);
    onHidden?.();
  };

  return (
    <div
      data-testid="expiring-cards-reminder"
      className={cn(
        'flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-200',
        className,
      )}
    >
      <CalendarClock className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <div className="min-w-0 flex-1 space-y-1">
        <p>{summarize(expiredCount, cards.length - expiredCount)}</p>
        <ul className="space-y-0.5">
          {listed.map((card) => (
            <li key={card.id}>
              <Link to={`/vault/${card.id}`} className="font-medium underline">
                {card.name || 'Unnamed item'}
              </Link>{' '}
              {cardExpiryPhrase(card.expiry)}
            </li>
          ))}
        </ul>
        {unlisted > 0 && <p>and {unlisted} more</p>}
      </div>
      <button
        type="button"
        onClick={hide}
        aria-label="Hide card expiry reminder"
        className="shrink-0 cursor-pointer rounded p-1 hover:bg-amber-100 dark:hover:bg-amber-800/30"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  );
}
