/**
 * `CardExpiryBadge` and `CardExpiryNotice`: what a warned card looks like in the
 * vault list, in the item view and under the editor's expiry inputs.
 *
 * Every expiry is read through the real `readCardExpiry` at a pinned local
 * instant, so these tests render exactly what a stored card would produce.
 */
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CardExpiryBadge, CardExpiryNotice } from '../../src/components/vault/CardExpiry';
import { readCardExpiry, type CardExpiry } from '../../src/lib/cardExpiry';

const NOW = new Date(2026, 9, 18, 10);

function expiryOf(month: string, year: string): CardExpiry {
  const expiry = readCardExpiry(month, year, NOW);
  if (expiry === null) throw new Error(`expected ${month}/${year} to parse`);
  return expiry;
}

const EXPIRED = expiryOf('3', '2024');
const EXPIRING = expiryOf('11', '2026'); // 18 October to 30 November 2026: 43 days.
const VALID = expiryOf('6', '2030');

describe('CardExpiryBadge', () => {
  it('marks an expired card in red, with its icon and the month it was valid through', () => {
    render(<CardExpiryBadge expiry={EXPIRED} />);
    const badge = screen.getByTestId('card-expiry-badge');
    expect(badge.textContent).toBe('Expired');
    expect(badge.getAttribute('title')).toBe('Valid through 03/2024');
    expect(badge.className).toContain('bg-red-100');
    expect(badge.className).not.toContain('amber');
    const icon = badge.querySelector('svg');
    expect(icon?.getAttribute('aria-hidden')).toBe('true');
    expect(icon?.getAttribute('class')).toContain('lucide-calendar-x');
  });

  it('marks an expiring card in amber with a different icon', () => {
    render(<CardExpiryBadge expiry={EXPIRING} />);
    const badge = screen.getByTestId('card-expiry-badge');
    expect(badge.textContent).toBe('Expires soon');
    expect(badge.getAttribute('title')).toBe('Valid through 11/2026');
    expect(badge.className).toContain('bg-amber-100');
    expect(badge.className).not.toContain('red');
    expect(badge.querySelector('svg')?.getAttribute('class')).toContain('lucide-calendar-clock');
  });

  it('keeps the type pill box and no border, so the fixed-height list row does not grow', () => {
    render(<CardExpiryBadge expiry={EXPIRED} />);
    const classes = screen.getByTestId('card-expiry-badge').className.split(/\s+/);
    expect(classes).toEqual(
      expect.arrayContaining([
        'inline-flex',
        'shrink-0',
        'rounded-full',
        'px-2',
        'py-0.5',
        'text-xs',
      ]),
    );
    expect(classes.some((name) => /^border/.test(name))).toBe(false);
  });

  it('renders nothing for a valid card or an unknown expiry', () => {
    const { container, rerender } = render(<CardExpiryBadge expiry={VALID} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CardExpiryBadge expiry={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('CardExpiryNotice, in the item view', () => {
  it('says an expired card has expired, when, and what to do about it', () => {
    render(<CardExpiryNotice expiry={EXPIRED} variant="detail" />);
    const notice = screen.getByTestId('card-expiry-notice');
    expect(screen.getByText('This card has expired').tagName).toBe('P');
    expect(screen.getByText('This card has expired').className).toContain('font-medium');
    expect(screen.getByText('It was valid through March 2024.')).toBeInTheDocument();
    expect(
      screen.getByText('If you have a replacement card, edit this entry and update its details.'),
    ).toBeInTheDocument();
    expect(notice.className).toContain('bg-red-50');
    expect(notice.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('counts down an expiring card without telling the user to replace it yet', () => {
    render(<CardExpiryNotice expiry={EXPIRING} variant="detail" />);
    const notice = screen.getByTestId('card-expiry-notice');
    expect(notice.textContent).toBe(
      'This card expires in 43 daysIt is valid through the end of November 2026.',
    );
    expect(notice.className).toContain('bg-amber-50');
    expect(screen.queryByText(/replacement card/)).not.toBeInTheDocument();
  });

  it('is neither an alert nor a status region, and adds no heading', () => {
    render(<CardExpiryNotice expiry={EXPIRED} variant="detail" />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading')).not.toBeInTheDocument();
  });

  it('renders nothing for a valid card or an unknown expiry', () => {
    const { container, rerender } = render(<CardExpiryNotice expiry={VALID} variant="detail" />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CardExpiryNotice expiry={null} variant="detail" />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('CardExpiryNotice, under the editor inputs', () => {
  it('tells the user an expired card can still be saved, in one line', () => {
    render(<CardExpiryNotice expiry={EXPIRED} variant="editor" />);
    const hint = screen.getByTestId('card-expiry-hint');
    expect(hint.tagName).toBe('P');
    expect(hint.textContent).toBe(
      'This card expired at the end of March 2024. You can still save it.',
    );
    expect(hint.className).toContain('text-red-700');
    expect(hint.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(screen.queryByTestId('card-expiry-notice')).not.toBeInTheDocument();
  });

  it('gives an expiring card its date and the days left', () => {
    render(<CardExpiryNotice expiry={EXPIRING} variant="editor" />);
    const hint = screen.getByTestId('card-expiry-hint');
    expect(hint.textContent).toBe('This card expires in 43 days, at the end of November 2026.');
    expect(hint.className).toContain('text-amber-800');
  });

  it('brings no live region of its own: the form owns the always-mounted one', () => {
    render(<CardExpiryNotice expiry={EXPIRING} variant="editor" />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByTestId('card-expiry-hint').hasAttribute('aria-live')).toBe(false);
  });

  it('renders nothing for a valid card or an unknown expiry', () => {
    const { container, rerender } = render(<CardExpiryNotice expiry={VALID} variant="editor" />);
    expect(container).toBeEmptyDOMElement();
    rerender(<CardExpiryNotice expiry={null} variant="editor" />);
    expect(container).toBeEmptyDOMElement();
  });
});
