/**
 * The Settings help: the long explanations behind the three help triggers, and
 * the names those triggers go by.
 *
 * What is pinned:
 *
 *   - Each topic's outline (its section headings, in order) and that every
 *     section says something: an intro and at least one complete sentence per
 *     section, none of them blank.
 *   - The facts a reader acts on, by the exact names the page gives its
 *     controls: a help text that sends someone to a button by a name the page
 *     does not use is a help text that fails them.
 *   - The house style the panel relies on: plain text only (the panel's Tab key
 *     leaves it, so nothing inside may need the keyboard), no em dash, and the
 *     title left to the panel.
 *   - Trigger names that never answer a query for one of the page's controls.
 *
 * Every sentence's source in the code or SECURITY.md is listed beside the change
 * that introduced it; these tests pin the wording, not the truth of it.
 */
import { fireEvent, render, screen, within } from '@testing-library/react';
import { lazy } from 'react';
import { describe, expect, it } from 'vitest';
import SettingsHelp from '../../src/components/settings/SettingsHelp';
import {
  SETTINGS_HELP_TOPICS,
  type SettingsHelpTopic,
} from '../../src/components/settings/settingsHelpTopics';
import { InfoTip } from '../../src/components/ui/InfoTip';

const OUTLINES: Record<SettingsHelpTopic, readonly [string, ...string[]]> = {
  'vault-key-rotation': [
    'What happens when you rotate',
    'What you need',
    'Your other devices',
    'If it is interrupted',
    'When to use it',
    'Good to know',
  ],
  'entry-reseal': [
    'What it protects against',
    'Who needs it',
    'What changes, and what does not',
    'If it is interrupted',
    'What it cannot do',
  ],
  'lock-on-hidden': [
    'What counts as hidden',
    'What locking does',
    'How it works with auto-lock',
    'Turning it on',
    'When to use it',
  ],
};

const TOPICS = Object.keys(OUTLINES) as SettingsHelpTopic[];

function renderTopic(topic: SettingsHelpTopic) {
  const { container } = render(<SettingsHelp topic={topic} />);
  return container;
}

/** The text a section's list says, one string per bullet. */
function bulletsUnder(heading: HTMLElement): string[] {
  const list = heading.nextElementSibling;
  expect(list?.tagName).toBe('UL');
  return within(list as HTMLElement)
    .getAllByRole('listitem')
    .map((item) => item.textContent);
}

describe('SettingsHelp: every topic', () => {
  it.each(TOPICS)('%s: renders its sections in order, each heading over its own list', (topic) => {
    renderTopic(topic);
    const headings = screen.getAllByRole('heading', { level: 3 });

    expect(headings.map((heading) => heading.textContent)).toEqual(OUTLINES[topic]);
    for (const heading of headings) {
      expect(bulletsUnder(heading).length).toBeGreaterThan(0);
    }
  });

  it.each(TOPICS)('%s: opens with an intro, and every bullet is a whole sentence', (topic) => {
    const container = renderTopic(topic);
    const intro = container.querySelector('p');

    expect(intro?.textContent).toMatch(/^[A-Z].{40,}\.$/);
    for (const item of screen.getAllByRole('listitem')) {
      expect(item.textContent).toMatch(/^[A-Z0-9].*[.)]$/);
    }
  });

  it.each(TOPICS)(
    '%s: is plain text, without an em dash, under the title the panel gives it',
    (topic) => {
      const container = renderTopic(topic);
      const text = container.textContent;

      // By code point, so this file carries neither dash itself.
      expect(text).not.toContain(String.fromCodePoint(0x2014));
      expect(text).not.toContain(String.fromCodePoint(0x2013));
      expect(screen.queryAllByRole('heading', { level: 1 })).toHaveLength(0);
      expect(screen.queryAllByRole('heading', { level: 2 })).toHaveLength(0);
      expect(
        container.querySelectorAll('a, button, input, select, textarea, [tabindex]'),
      ).toHaveLength(0);
      expect(text).not.toContain(SETTINGS_HELP_TOPICS[topic].title);
    },
  );
});

describe('SettingsHelp: what each topic tells the reader', () => {
  it('vault key rotation: what it touches, what it needs, and where the controls it names are', () => {
    renderTopic('vault-key-rotation');
    const happens = bulletsUnder(
      screen.getByRole('heading', { name: 'What happens when you rotate' }),
    ).join(' ');
    const needs = bulletsUnder(screen.getByRole('heading', { name: 'What you need' })).join(' ');
    const devices = bulletsUnder(screen.getByRole('heading', { name: 'Your other devices' })).join(
      ' ',
    );
    const interrupted = bulletsUnder(
      screen.getByRole('heading', { name: 'If it is interrupted' }),
    ).join(' ');
    const when = bulletsUnder(screen.getByRole('heading', { name: 'When to use it' })).join(' ');
    const limits = bulletsUnder(screen.getByRole('heading', { name: 'Good to know' })).join(' ');

    expect(happens).toContain('including the ones in your trash');
    expect(happens).toContain('Your documents are not downloaded or uploaded again');
    expect(happens).toContain('Your master password stays the same');
    expect(happens).toContain('Keep the page open');
    expect(needs).toContain('Your master password, to confirm it is you.');
    expect(needs).toContain('backup password. It is optional.');
    expect(needs).toContain('Backup Settings');
    expect(needs).toContain('A rotation cannot be undone');
    expect(devices).toContain('Rotating does not sign out your other devices.');
    expect(devices).toContain('Active Sessions');
    expect(interrupted).toContain('Finish Rotation');
    expect(interrupted).toContain('wait about five minutes');
    expect(when).toContain('Revoke on the Active Sessions page');
    expect(limits).toContain('change your master password first');
    expect(limits).toContain('will not be usable');
  });

  it('entry sealing: same key, nothing visible changes, and what it leaves to a rotation', () => {
    renderTopic('entry-reseal');
    const who = bulletsUnder(screen.getByRole('heading', { name: 'Who needs it' })).join(' ');
    const changes = bulletsUnder(
      screen.getByRole('heading', { name: 'What changes, and what does not' }),
    ).join(' ');
    const interrupted = bulletsUnder(
      screen.getByRole('heading', { name: 'If it is interrupted' }),
    ).join(' ');
    const limits = bulletsUnder(screen.getByRole('heading', { name: 'What it cannot do' })).join(
      ' ',
    );

    expect(who).toContain('an older version of H-Vault');
    expect(who).toContain('restoring a backup');
    expect(changes).toContain('Your vault key stays the same');
    expect(changes).toContain('your documents are not touched');
    expect(changes).toContain('Running it again does no harm');
    expect(interrupted).toContain('run it again to finish');
    expect(limits).toContain('Rotating your vault key is what retires them');
    expect(limits).toContain('an older version of the same entry');
  });

  it('locking a hidden tab: what hidden means, what a lock does, and how to keep the setting', () => {
    renderTopic('lock-on-hidden');
    const hidden = bulletsUnder(
      screen.getByRole('heading', { name: 'What counts as hidden' }),
    ).join(' ');
    const locking = bulletsUnder(screen.getByRole('heading', { name: 'What locking does' })).join(
      ' ',
    );
    const autoLock = bulletsUnder(
      screen.getByRole('heading', { name: 'How it works with auto-lock' }),
    ).join(' ');
    const turningOn = bulletsUnder(screen.getByRole('heading', { name: 'Turning it on' })).join(
      ' ',
    );

    expect(hidden).toContain('another tab');
    expect(locking).toContain('unlocking needs only your master password');
    expect(locking).toContain('clipboard');
    expect(autoLock).toContain('Whichever runs out first locks the vault.');
    expect(turningOn).toContain('It is off until you turn it on.');
    expect(turningOn).toContain('from 1 to 1440');
    expect(turningOn).toContain('Press Save Settings');
  });
});

describe('Settings help topics', () => {
  it('titles each panel and names each trigger', () => {
    expect(SETTINGS_HELP_TOPICS).toEqual({
      'vault-key-rotation': {
        title: 'Vault key rotation, explained',
        label: 'Help: what rotating the vault key does',
      },
      'entry-reseal': {
        title: 'Entry sealing, explained',
        label: 'Help: sealing entries to their place',
      },
      'lock-on-hidden': {
        title: 'Locking a hidden tab, explained',
        label: 'Help: locking when the tab is hidden',
      },
    });
  });

  it('never uses a word the page or its tests find a control by', () => {
    const taken = [
      'rotate vault key',
      're-seal vault entries',
      'rotate key',
      're-seal',
      'create',
      'remove',
      'dismiss',
    ];
    for (const { title, label } of Object.values(SETTINGS_HELP_TOPICS)) {
      for (const word of taken) {
        expect(title.toLowerCase()).not.toContain(word);
        expect(label.toLowerCase()).not.toContain(word);
      }
    }
  });

  it.each(TOPICS)(
    '%s: opens from its trigger as a lazy body, named by its title',
    async (topic) => {
      const Help = lazy(() => import('../../src/components/settings/SettingsHelp'));
      const { title, label } = SETTINGS_HELP_TOPICS[topic];
      render(
        <InfoTip label={label} title={title}>
          <Help topic={topic} />
        </InfoTip>,
      );

      fireEvent.click(screen.getByRole('button', { name: label }));
      // The panel and the body are both lazy chunks: wait for each.
      const dialog = await screen.findByRole('dialog', { name: title });
      const firstHeading = await within(dialog).findByRole('heading', {
        level: 3,
        name: OUTLINES[topic][0],
      });

      expect(firstHeading).toBeInTheDocument();
      expect(document.activeElement).toBe(dialog);
    },
  );
});
