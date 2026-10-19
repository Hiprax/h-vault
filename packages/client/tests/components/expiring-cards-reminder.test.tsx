/**
 * `ExpiringCardsReminder`: the vault page's reminder about cards that have
 * expired or expire soon.
 *
 * Built from real `DecryptedVaultItem` objects, in the shape `vaultStore` keeps
 * them, and judged at a pinned local instant passed as `now` (one test leaves it
 * out to cover the clock default, and freezes the clock for that). What it must
 * never do matters as much as what it shows: render an empty wrapper, count a
 * trashed or undecodable card, claim a live region, a landmark or a heading, or
 * stay hidden once the set of warned cards has changed.
 */
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { ExpiringCardsReminder } from '../../src/components/vault/ExpiringCardsReminder';
import type { DecryptedVaultItem } from '../../src/stores/vaultStore';
import {
  cardExpiryFingerprint,
  isCardExpiryReminderDismissed,
} from '../../src/lib/cardExpiryDismissal';
import { installTestClock } from '../clock';

const NOW = new Date(2026, 9, 18, 10);
const USER = '65f000000000000000000001';
const STAMP = '2026-01-01T00:00:00.000Z';
const HIDE = 'Hide card expiry reminder';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

/** A 24-hex id ending in `suffix`, like the server's ObjectIds. */
function oid(suffix: string): string {
  return suffix.padStart(24, '0');
}

function vaultItem(
  id: string,
  name: string,
  itemType: DecryptedVaultItem['itemType'],
  data: Record<string, unknown>,
  deletedAt?: string,
): DecryptedVaultItem {
  return {
    id,
    itemType,
    tags: [],
    favorite: false,
    name,
    data,
    createdAt: STAMP,
    updatedAt: STAMP,
    ...(deletedAt === undefined ? {} : { deletedAt }),
    _raw: {
      _id: id,
      itemType,
      tags: [],
      favorite: false,
      encryptedData: 'ciphertext',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'ciphertext',
      nameIv: 'iv',
      nameTag: 'tag',
      createdAt: STAMP,
      updatedAt: STAMP,
      ...(deletedAt === undefined ? {} : { deletedAt }),
    },
  };
}

/** A card as `cardDataSchema` decodes it. */
function card(id: string, name: string, expMonth: string, expYear: string): DecryptedVaultItem {
  return vaultItem(id, name, 'card', {
    cardholderName: 'A Holder',
    number: '4111111111111111',
    expMonth,
    expYear,
    cvv: '123',
  });
}

function inRouter(node: ReactNode): ReactNode {
  return <MemoryRouter>{node}</MemoryRouter>;
}

function reminder(): HTMLElement {
  return screen.getByTestId('expiring-cards-reminder');
}

/** The listed cards' text, in order. */
function listed(): string[] {
  return within(reminder())
    .getAllByRole('listitem')
    .map((item) => item.textContent);
}

const EXPIRED_MARCH = card(oid('a1'), 'Old Visa', '3', '2024');
const EXPIRED_SEPTEMBER = card(oid('a2'), 'Store card', '09', '26');
const EXPIRING_NOVEMBER = card(oid('b1'), 'Travel Amex', '11', '2026');
const EXPIRING_OCTOBER = card(oid('b2'), 'Debit', '10', '2026');
const VALID = card(oid('c1'), 'New Visa', '6', '2030');

describe('ExpiringCardsReminder: when there is nothing to say', () => {
  it('renders nothing at all for a vault with no warned card', () => {
    const { container, rerender } = render(
      inRouter(<ExpiringCardsReminder items={[]} userId={USER} now={NOW} />),
    );
    expect(container).toBeEmptyDOMElement();

    rerender(
      inRouter(
        <ExpiringCardsReminder
          items={[VALID, card(oid('c2'), 'No date', '', ''), card(oid('c3'), 'Junk', '13', '2026')]}
          userId={USER}
          now={NOW}
        />,
      ),
    );
    expect(container).toBeEmptyDOMElement();
    expect(localStorage).toHaveLength(0);
  });

  it('ignores trashed cards, undecodable cards and items that are not cards', () => {
    const ignored = [
      vaultItem(oid('d1'), 'Trashed', 'card', { expMonth: '3', expYear: '2024' }, STAMP),
      vaultItem(oid('d2'), 'Half decoded', 'card', {
        expMonth: '3',
        expYear: '2024',
        _validationError: true,
      }),
      vaultItem(oid('d3'), 'Unparsed', 'card', { _raw: '{"expMonth":"3","expYear":"2024"}' }),
      vaultItem(oid('d4'), 'A login', 'login', { expMonth: '3', expYear: '2024' }),
      vaultItem(oid('d5'), 'A wrong type', 'card', { expMonth: 3, expYear: 2024 }),
    ];
    const { container, rerender } = render(
      inRouter(<ExpiringCardsReminder items={ignored} userId={USER} now={NOW} />),
    );
    expect(container).toBeEmptyDOMElement();

    rerender(
      inRouter(
        <ExpiringCardsReminder items={[...ignored, EXPIRED_MARCH]} userId={USER} now={NOW} />,
      ),
    );
    expect(within(reminder()).getByText('1 card has expired.')).toBeInTheDocument();
    expect(listed()).toEqual(['Old Visa expired at the end of March 2024']);
  });
});

describe('ExpiringCardsReminder: what it says', () => {
  it.each([
    ['one expired card', [EXPIRED_MARCH], '1 card has expired.'],
    ['two expired cards', [EXPIRED_MARCH, EXPIRED_SEPTEMBER], '2 cards have expired.'],
    ['one expiring card', [EXPIRING_NOVEMBER], '1 card expires within 60 days.'],
    ['two expiring cards', [EXPIRING_NOVEMBER, EXPIRING_OCTOBER], '2 cards expire within 60 days.'],
    [
      'one expired and two expiring',
      [EXPIRING_NOVEMBER, EXPIRED_MARCH, EXPIRING_OCTOBER],
      '1 card has expired and 2 expire within 60 days.',
    ],
    [
      'two expired and one expiring',
      [EXPIRED_SEPTEMBER, EXPIRING_NOVEMBER, EXPIRED_MARCH],
      '2 cards have expired and 1 expires within 60 days.',
    ],
  ])('summarises %s', (_label, items, sentence) => {
    render(inRouter(<ExpiringCardsReminder items={items} userId={USER} now={NOW} />));
    expect(reminder().querySelector('p')?.textContent).toBe(sentence);
    expect(listed()).toHaveLength(items.length);
    expect(screen.queryByText(/more$/)).not.toBeInTheDocument();
  });

  it('links each listed card to its entry and states its status', () => {
    render(
      inRouter(
        <ExpiringCardsReminder
          items={[EXPIRING_NOVEMBER, EXPIRED_MARCH, VALID, EXPIRING_OCTOBER]}
          userId={USER}
          now={NOW}
        />,
      ),
    );
    expect(listed()).toEqual([
      'Old Visa expired at the end of March 2024',
      'Debit expires in 13 days',
      'Travel Amex expires in 43 days',
    ]);
    const links = within(reminder()).getAllByRole('link');
    expect(links.map((link) => [link.textContent, link.getAttribute('href')])).toEqual([
      ['Old Visa', `/vault/${oid('a1')}`],
      ['Debit', `/vault/${oid('b2')}`],
      ['Travel Amex', `/vault/${oid('b1')}`],
    ]);
    // The valid card is not mentioned anywhere.
    expect(screen.queryByText(/New Visa/)).not.toBeInTheDocument();
  });

  it('lists the three most urgent, ordered by last valid day, then name, then id', () => {
    const items = [
      card(oid('f1'), 'Zulu', '11', '2026'),
      card(oid('e2'), 'Visa', '10', '2026'),
      card(oid('ff'), 'Amex', '10', '2026'),
      card(oid('a9'), 'Zeta', '1', '2025'),
      card(oid('e1'), 'Visa', '10', '2026'),
    ];
    render(inRouter(<ExpiringCardsReminder items={items} userId={USER} now={NOW} />));
    // Expired first even though its name sorts last; the two "Visa" cards share
    // a name and a month, so their ids decide, whatever order they arrived in.
    expect(
      within(reminder())
        .getAllByRole('link')
        .map((link) => link.getAttribute('href')),
    ).toEqual([`/vault/${oid('a9')}`, `/vault/${oid('ff')}`, `/vault/${oid('e1')}`]);
    expect(within(reminder()).getByText('and 2 more')).toBeInTheDocument();
    expect(reminder().querySelector('p')?.textContent).toBe(
      '1 card has expired and 4 expire within 60 days.',
    );
  });

  it('names an unnamed card the way the vault list does', () => {
    render(
      inRouter(
        <ExpiringCardsReminder
          items={[card(oid('a3'), '', '3', '2024')]}
          userId={USER}
          now={NOW}
        />,
      ),
    );
    expect(within(reminder()).getByRole('link', { name: 'Unnamed item' })).toHaveAttribute(
      'href',
      `/vault/${oid('a3')}`,
    );
  });

  it('is a plain block: no alert, no status region, no landmark, no heading', () => {
    render(inRouter(<ExpiringCardsReminder items={[EXPIRED_MARCH]} userId={USER} now={NOW} />));
    expect(reminder().tagName).toBe('DIV');
    for (const role of ['alert', 'status', 'complementary', 'region', 'heading'] as const) {
      expect(screen.queryByRole(role)).not.toBeInTheDocument();
    }
    expect(reminder().querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
  });

  it("puts the page's classes on its own box, so hiding it leaves no wrapper behind", () => {
    const { container } = render(
      inRouter(
        <ExpiringCardsReminder
          items={[EXPIRED_MARCH]}
          userId={USER}
          now={NOW}
          className="mx-4 mt-2 lg:mx-6"
        />,
      ),
    );
    expect(container.firstElementChild).toBe(reminder());
    expect(reminder().className.split(/\s+/)).toEqual(
      expect.arrayContaining(['mx-4', 'mt-2', 'lg:mx-6', 'bg-amber-50', 'rounded-md']),
    );
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    expect(container).toBeEmptyDOMElement();
  });

  it('judges expiry against the clock when no instant is given', () => {
    installTestClock({ at: new Date(2026, 9, 31, 9).getTime() });
    render(inRouter(<ExpiringCardsReminder items={[EXPIRING_OCTOBER]} userId={USER} />));
    expect(listed()).toEqual(['Debit expires today']);
  });
});

describe('ExpiringCardsReminder: hiding it', () => {
  it('hides on request, remembers this set of cards, and hands focus back to the page', () => {
    const onHidden = vi.fn();
    const { container } = render(
      inRouter(
        <ExpiringCardsReminder
          items={[EXPIRED_MARCH, EXPIRING_NOVEMBER]}
          userId={USER}
          now={NOW}
          onHidden={onHidden}
        />,
      ),
    );
    const button = screen.getByRole('button', { name: HIDE });
    expect(button).toHaveAttribute('type', 'button');
    expect(button.getAttribute('aria-label')).not.toMatch(/dismiss|remove|create/i);

    fireEvent.click(button);

    expect(container).toBeEmptyDOMElement();
    expect(onHidden).toHaveBeenCalledTimes(1);
    const fingerprint = cardExpiryFingerprint(USER, [
      { id: oid('a1'), status: 'expired' },
      { id: oid('b1'), status: 'expiring' },
    ]);
    expect(isCardExpiryReminderDismissed(fingerprint)).toBe(true);
    expect(localStorage).toHaveLength(1);
  });

  it('hides without a focus handler too', () => {
    const { container } = render(
      inRouter(<ExpiringCardsReminder items={[EXPIRED_MARCH]} userId={USER} now={NOW} />),
    );
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    expect(container).toBeEmptyDOMElement();
  });

  it('stays hidden on the next visit for the same set of cards', () => {
    const items = [EXPIRED_MARCH, EXPIRING_NOVEMBER];
    const first = render(inRouter(<ExpiringCardsReminder items={items} userId={USER} now={NOW} />));
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    first.unmount();

    // A new mount, the cards in a different order, a later hour of the same day.
    const { container } = render(
      inRouter(
        <ExpiringCardsReminder
          items={[...items].reverse()}
          userId={USER}
          now={new Date(2026, 9, 18, 22)}
        />,
      ),
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('comes back when a card changes status, a card is added, or another account signs in', () => {
    const items = [EXPIRED_MARCH, EXPIRING_OCTOBER];
    const { container, rerender } = render(
      inRouter(<ExpiringCardsReminder items={items} userId={USER} now={NOW} />),
    );
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    expect(container).toBeEmptyDOMElement();

    // The October card expires: same cards, new status.
    rerender(
      inRouter(<ExpiringCardsReminder items={items} userId={USER} now={new Date(2026, 10, 1)} />),
    );
    expect(within(reminder()).getByText('2 cards have expired.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    expect(container).toBeEmptyDOMElement();

    // A card starts expiring.
    rerender(
      inRouter(
        <ExpiringCardsReminder
          items={[...items, EXPIRING_NOVEMBER]}
          userId={USER}
          now={new Date(2026, 10, 1)}
        />,
      ),
    );
    expect(
      within(reminder()).getByText('2 cards have expired and 1 expires within 60 days.'),
    ).toBeInTheDocument();

    // Another account on the same browser never inherits a hidden reminder.
    rerender(
      inRouter(
        <ExpiringCardsReminder items={items} userId={oid('2')} now={new Date(2026, 10, 1)} />,
      ),
    );
    expect(within(reminder()).getByText('2 cards have expired.')).toBeInTheDocument();
  });

  it('still hides when storage refuses the write, and comes back on the next visit', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    const onHidden = vi.fn();
    const first = render(
      inRouter(
        <ExpiringCardsReminder
          items={[EXPIRED_MARCH]}
          userId={USER}
          now={NOW}
          onHidden={onHidden}
        />,
      ),
    );
    fireEvent.click(screen.getByRole('button', { name: HIDE }));
    expect(first.container).toBeEmptyDOMElement();
    expect(onHidden).toHaveBeenCalledTimes(1);
    first.unmount();

    render(inRouter(<ExpiringCardsReminder items={[EXPIRED_MARCH]} userId={USER} now={NOW} />));
    expect(reminder()).toBeInTheDocument();
  });
});
