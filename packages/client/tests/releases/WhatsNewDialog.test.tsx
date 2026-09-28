/**
 * "What's new" itself: what it shows once the notes arrive, where focus lands,
 * that every way of closing acknowledges exactly the release it showed (and
 * nothing when the notes never loaded), and its heading outline.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { makeNotes, makeRelease } from './fixtures';
import { headingLevels } from '../support/documentOutline';

const notesApi = vi.hoisted(() => ({ get: vi.fn() }));
const closeDialog = vi.hoisted(() => vi.fn());

vi.mock('../../src/services/api/releaseNotesApi', () => ({ getReleaseNotesApi: notesApi.get }));
vi.mock('../../src/stores/releaseStore', () => ({
  useReleaseStore: (select: (state: { closeDialog: typeof closeDialog }) => unknown) =>
    select({ closeDialog }),
}));

import WhatsNewDialog from '../../src/components/releases/WhatsNewDialog';

const twoNew = makeNotes([
  makeRelease('0.16.0', {
    isNew: true,
    date: '2026-10-02',
    highlights: [
      { icon: 'sparkles', title: 'A headline change', body: 'It is explained here.' },
      {
        icon: 'server',
        title: 'A server setting',
        body: 'Only the administrator acts on this.',
        audience: 'administrators',
      },
    ],
  }),
  makeRelease('0.15.0', { isNew: true }),
  makeRelease('0.14.1'),
]);

async function open(notes = twoNew) {
  notesApi.get.mockResolvedValue(notes);
  const view = render(
    <MemoryRouter>
      <WhatsNewDialog userId="user-a" version={notes.version} />
    </MemoryRouter>,
  );
  await screen.findByRole('heading', { level: 3, name: notes.releases[0]?.title ?? '' });
  return view;
}

beforeEach(() => {
  notesApi.get.mockReset();
  closeDialog.mockReset();
});

afterEach(cleanup);

describe('WhatsNewDialog', () => {
  it('is titled with the version and describes the release and how many are new', async () => {
    await open();
    const dialog = screen.getByRole('dialog', { name: "What's new in H-Vault 0.16.0" });
    expect(dialog).toHaveAccessibleDescription(
      'Released October 2, 2026. 2 updates since you last looked.',
    );
  });

  it('does not count a single new release in words', async () => {
    await open(
      makeNotes([
        makeRelease('0.16.0', { isNew: true, date: '2026-10-02' }),
        makeRelease('0.15.0'),
      ]),
    );
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription('Released October 2, 2026.');
  });

  it('shows the newest release in full and the earlier ones as a history', async () => {
    await open();
    expect(screen.getByText('A headline change')).toBeInTheDocument();
    expect(screen.getByText('For administrators')).toBeInTheDocument();
    const history = screen.getByText('Earlier releases').parentElement!;
    const entries = within(history).getAllByRole('article');
    expect(entries.map((entry) => entry.getAttribute('aria-label'))).toEqual([
      'Release 0.15.0',
      'Release 0.14.1',
    ]);
    // "New for you" only on releases newer than the watermark, which open by default.
    expect(within(entries[0]!).getByText('New for you')).toBeInTheDocument();
    expect(within(entries[0]!).getByRole('button', { name: 'Hide details' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    expect(within(entries[1]!).queryByText('New for you')).toBeNull();
    expect(within(entries[1]!).getByRole('button', { name: 'Show details' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
  });

  it('opens and closes an earlier release on request', async () => {
    await open();
    const older = screen.getByRole('article', { name: 'Release 0.14.1' });
    expect(within(older).queryByText('A fix in 0.14.1.')).toBeNull();
    fireEvent.click(within(older).getByRole('button', { name: 'Show details' }));
    expect(within(older).getByText('A fix in 0.14.1.')).toBeInTheDocument();
    expect(within(older).getByText('Fixed')).toBeInTheDocument();
    fireEvent.click(within(older).getByRole('button', { name: 'Hide details' }));
    expect(within(older).queryByText('A fix in 0.14.1.')).toBeNull();
  });

  it('puts the initial focus on the scrollable notes, not on a button', async () => {
    await open();
    expect(document.activeElement).toBe(screen.getByRole('region', { name: 'Release notes' }));
  });

  it('keeps one h2 with every release title beneath it', async () => {
    await open();
    const levels = headingLevels(screen.getByRole('dialog'));
    expect(levels[0]).toBe(2);
    expect(levels.filter((level) => level === 2)).toHaveLength(1);
    expect(levels.slice(1).every((level) => level === 3 || level === 4)).toBe(true);
  });

  it.each([
    ['Done', () => fireEvent.click(screen.getByRole('button', { name: 'Done' }))],
    ['the close button', () => fireEvent.click(screen.getByRole('button', { name: 'Close' }))],
    ['Escape', () => fireEvent.keyDown(document, { key: 'Escape' })],
    [
      'See full history',
      () => fireEvent.click(screen.getByRole('link', { name: 'See full history' })),
    ],
  ])('acknowledges the shown release once when closed with %s', async (_label, close) => {
    await open();
    close();
    expect(closeDialog).toHaveBeenCalledTimes(1);
    expect(closeDialog).toHaveBeenCalledWith('user-a', '0.16.0');
  });

  it('links the full history on the About page', async () => {
    await open();
    expect(screen.getByRole('link', { name: 'See full history' })).toHaveAttribute(
      'href',
      '/settings/about#release-history',
    );
  });

  it('acknowledges nothing when closed before the notes arrived', () => {
    notesApi.get.mockReturnValue(new Promise(() => undefined));
    render(
      <MemoryRouter>
        <WhatsNewDialog userId="user-a" version="0.16.0" />
      </MemoryRouter>,
    );
    expect(screen.getByText('Loading the release notes')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(closeDialog).toHaveBeenCalledWith('user-a', undefined);
  });

  it('says so when the notes cannot be loaded, and loads them again on request', async () => {
    notesApi.get.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(twoNew);
    render(
      <MemoryRouter>
        <WhatsNewDialog userId="user-a" version="0.16.0" />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText(
        'The release notes could not be loaded. Check your connection and try again.',
      ),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(closeDialog).toHaveBeenLastCalledWith('user-a', undefined);
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('A headline change')).toBeInTheDocument();
    expect(notesApi.get).toHaveBeenCalledTimes(2);
  });

  it('says there are no notes yet when the list is empty', async () => {
    notesApi.get.mockResolvedValue(makeNotes([], { version: '0.16.0' }));
    render(
      <MemoryRouter>
        <WhatsNewDialog userId="user-a" version="0.16.0" />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText('There are no release notes for this version yet.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toHaveAccessibleDescription('');
  });
});
