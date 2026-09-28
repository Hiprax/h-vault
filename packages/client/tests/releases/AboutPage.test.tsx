/**
 * About H-Vault: the running version, what administrators are told about newer
 * releases (never "up to date" without a recent check), the "What's new"
 * preference, and the searchable history.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import { makeNotes, makeRelease, makeStatus, makeUpdate } from './fixtures';

const notesApi = vi.hoisted(() => ({ get: vi.fn() }));
const statusApi = vi.hoisted(() => ({ status: vi.fn(), seen: vi.fn(), check: vi.fn() }));
const settingsApi = vi.hoisted(() => ({ update: vi.fn() }));
const cache = vi.hoisted(() => ({ clear: vi.fn() }));

// The auth store persists through encryptedStorage, which encrypts
// asynchronously: a write started by the last setState of this file could land
// after the environment is gone and fail with "localStorage is not defined".
// Persistence is not what these cases pin, so it resolves at once.
vi.mock('../../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
}));
vi.mock('../../src/services/api/releaseNotesApi', () => ({ getReleaseNotesApi: notesApi.get }));
vi.mock('../../src/services/api/releaseStatusApi', () => ({
  getReleaseStatusApi: statusApi.status,
  markReleaseNotesSeenApi: statusApi.seen,
  checkForUpdateNowApi: statusApi.check,
}));
vi.mock('../../src/services/api/userApi', () => ({ updateSettingsApi: settingsApi.update }));
vi.mock('../../src/hooks/useUserSettings', () => ({ clearSettingsCache: cache.clear }));

import AboutPage from '../../src/pages/AboutPage';
import { ToastProvider } from '../../src/components/ui/Toast';
import { _resetReleaseStoreForTests, useReleaseStore } from '../../src/stores/releaseStore';
import { useAuthStore } from '../../src/stores/authStore';

const history = makeNotes([
  makeRelease('0.16.0', {
    date: '2026-10-02',
    isNew: true,
    title: 'Sharper previews',
    changes: [
      { kind: 'improved', text: 'Previews render faster than before.' },
      { kind: 'security', text: 'A stricter policy guards the preview frame.' },
    ],
  }),
  makeRelease('0.15.0', {
    title: 'Release notes arrive',
    changes: [{ kind: 'added', text: 'The app now explains each update.' }],
  }),
]);

async function renderPage(
  status = makeStatus({ version: '0.16.0', update: makeUpdate() }),
  hash = '',
) {
  statusApi.status.mockResolvedValue(status);
  notesApi.get.mockResolvedValue(history);
  const view = render(
    <ToastProvider>
      <MemoryRouter initialEntries={[`/settings/about${hash}`]}>
        <AboutPage />
      </MemoryRouter>
    </ToastProvider>,
  );
  await screen.findByRole('heading', { level: 3, name: 'Sharper previews' });
  await waitFor(() => {
    expect(useReleaseStore.getState().status).not.toBeNull();
  });
  return view;
}

beforeEach(() => {
  _resetReleaseStoreForTests();
  for (const fn of [
    notesApi.get,
    statusApi.status,
    statusApi.check,
    settingsApi.update,
    cache.clear,
  ]) {
    fn.mockReset();
  }
  useAuthStore.setState({ user: { userId: 'user-a', email: 'user-a@example.com' } });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  useAuthStore.setState({ user: null });
});

describe('AboutPage: this installation', () => {
  it('is one page titled About H-Vault, with the version, its date and its release page', async () => {
    await renderPage();
    expect(screen.getByRole('heading', { level: 1, name: 'About H-Vault' })).toBeInTheDocument();
    expect(screen.getAllByText('0.16.0').length).toBeGreaterThan(0);
    expect(screen.getByText('Released October 2, 2026')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Release notes on GitHub/ })).toHaveAttribute(
      'href',
      'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
    );
  });

  it('shows no update information to an account outside the audience', async () => {
    await renderPage(makeStatus({ version: '0.16.0', update: null }));
    expect(screen.queryByRole('heading', { name: 'Updates' })).toBeNull();
  });

  it('says the server runs the latest release only after a check, naming when', async () => {
    const recent = new Date(Date.now() - 2 * 3_600_000).toISOString();
    await renderPage(
      makeStatus({ version: '0.16.0', update: makeUpdate({ lastSuccessAt: recent }) }),
    );
    expect(
      screen.getByText(/This server runs the latest release\. Checked 2 hours ago\./),
    ).toBeInTheDocument();
  });

  it('explains a newer release and how to update to it', async () => {
    await renderPage(
      makeStatus({
        version: '0.16.0',
        update: makeUpdate({
          state: 'available',
          latestVersion: '0.17.0',
          publishedAt: '2026-11-05T08:00:00.000Z',
          releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.17.0',
        }),
      }),
    );
    expect(
      screen.getByText('H-Vault 0.17.0 is available. This server runs 0.16.0.'),
    ).toBeInTheDocument();
    expect(screen.getByText('Published November 5, 2026.')).toBeInTheDocument();
    expect(screen.getByText(/# set HVAULT_VERSION=0\.17\.0 in \.env, then:/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /What changed in 0\.17\.0/ })).toHaveAttribute(
      'href',
      'https://github.com/Hiprax/h-vault/releases/tag/v0.17.0',
    );
    expect(screen.getByRole('link', { name: /Full update guide/ })).toHaveAttribute(
      'href',
      'https://github.com/Hiprax/h-vault#update',
    );
  });

  it('renders no link from a release address that is not GitHub', async () => {
    await renderPage(
      makeStatus({
        version: '0.16.0',
        releaseUrl: 'https://example.com/x',
        update: makeUpdate({
          state: 'available',
          latestVersion: '0.17.0',
          releaseUrl: 'javascript:alert(1)',
        }),
      }),
    );
    expect(screen.queryByRole('link', { name: /What changed/ })).toBeNull();
    expect(screen.queryByRole('link', { name: /Full update guide/ })).toBeNull();
    expect(screen.queryByRole('link', { name: /Release notes on GitHub/ })).toBeNull();
  });

  it.each([
    [
      'never checked',
      makeUpdate({ state: 'unknown', latestVersion: null, lastSuccessAt: null }),
      'The server has not been able to check GitHub for a newer release yet.',
    ],
    [
      'last success long ago',
      makeUpdate({
        state: 'unknown',
        latestVersion: '0.17.0',
        lastSuccessAt: new Date(Date.now() - 4 * 86_400_000).toISOString(),
      }),
      'The server could not reach GitHub recently. Its last successful check was 4 days ago. The newest release it knew of then was 0.17.0.',
    ],
    [
      'a state this build does not know',
      makeUpdate({ state: 'paused', latestVersion: null, lastSuccessAt: null }),
      'The server has not been able to check GitHub for a newer release yet.',
    ],
  ])('never claims to be up to date when %s', async (_label, update, text) => {
    await renderPage(makeStatus({ version: '0.16.0', update }));
    expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.queryByText(/latest release/)).toBeNull();
  });

  it('says checks are turned off, and offers no check', async () => {
    await renderPage(
      makeStatus({
        version: '0.16.0',
        update: makeUpdate({ state: 'disabled', latestVersion: null, canCheckNow: false }),
      }),
    );
    expect(screen.getByText(/Update checks are turned off on this server/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Check now/ })).toBeNull();
  });

  it('checks now and shows the answer, telling a fresh check from a cached one', async () => {
    await renderPage();
    statusApi.check.mockResolvedValueOnce({
      update: makeUpdate({ state: 'available', latestVersion: '0.17.0' }),
      fetched: true,
    });
    fireEvent.click(screen.getByRole('button', { name: /Check now/ }));
    expect(await screen.findByText('Checked GitHub just now')).toBeInTheDocument();
    expect(useReleaseStore.getState().status?.update?.state).toBe('available');
    expect(
      screen.getByText('H-Vault 0.17.0 is available. This server runs 0.16.0.'),
    ).toBeInTheDocument();

    statusApi.check.mockResolvedValueOnce({ update: makeUpdate(), fetched: false });
    fireEvent.click(screen.getByRole('button', { name: /Check now/ }));
    expect(await screen.findByText('Checked a moment ago')).toBeInTheDocument();
    expect(
      screen.getByText(
        'The server asks GitHub at most once every five minutes; this is its latest answer.',
      ),
    ).toBeInTheDocument();
  });

  it('reports a failed check', async () => {
    await renderPage();
    statusApi.check.mockRejectedValueOnce(new Error('offline'));
    fireEvent.click(screen.getByRole('button', { name: /Check now/ }));
    expect(await screen.findByText('Could not check for updates')).toBeInTheDocument();
  });
});

describe('AboutPage: navigation', () => {
  it('goes back to Settings from its back button', async () => {
    statusApi.status.mockResolvedValue(makeStatus());
    notesApi.get.mockResolvedValue(history);
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={['/settings/about']}>
          <Routes>
            <Route path="/settings/about" element={<AboutPage />} />
            <Route path="/settings" element={<h1>Settings page</h1>} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Back to settings' }));
    expect(await screen.findByRole('heading', { name: 'Settings page' })).toBeInTheDocument();
  });
});

describe("AboutPage: the what's new preference", () => {
  it('saves the preference, refreshes the status and confirms it', async () => {
    await renderPage();
    settingsApi.update.mockResolvedValue({ data: { success: true } });
    statusApi.status.mockResolvedValue(
      makeStatus({
        version: '0.16.0',
        releaseNotes: { showOnUpdate: false },
        update: makeUpdate(),
      }),
    );
    const toggle = screen.getByRole('checkbox', { name: "Show what's new after an update" });
    expect(toggle).toBeChecked();
    fireEvent.click(toggle);
    expect(
      await screen.findByText("What's new will stay behind the version in the sidebar"),
    ).toBeInTheDocument();
    expect(settingsApi.update).toHaveBeenCalledWith({ showReleaseNotes: false });
    expect(cache.clear).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(toggle).not.toBeChecked();
    });
  });

  it('turns it back on with its own confirmation', async () => {
    await renderPage(
      makeStatus({
        version: '0.16.0',
        releaseNotes: { showOnUpdate: false },
        update: makeUpdate(),
      }),
    );
    settingsApi.update.mockResolvedValue({ data: { success: true } });
    fireEvent.click(screen.getByRole('checkbox', { name: "Show what's new after an update" }));
    expect(await screen.findByText("What's new will open after each update")).toBeInTheDocument();
    expect(settingsApi.update).toHaveBeenCalledWith({ showReleaseNotes: true });
  });

  it('reports a failed save and keeps the stored value', async () => {
    await renderPage();
    settingsApi.update.mockRejectedValue(new Error('offline'));
    fireEvent.click(screen.getByRole('checkbox', { name: "Show what's new after an update" }));
    expect(await screen.findByText('Could not save the preference')).toBeInTheDocument();
    expect(cache.clear).not.toHaveBeenCalled();
  });

  it("opens what's new on request", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole('button', { name: "Open what's new" }));
    expect(useReleaseStore.getState().dialogOpen).toBe(true);
  });
});

describe('AboutPage: the release history', () => {
  it('lists every release and offers a filter only for kinds that occur', async () => {
    await renderPage();
    const group = screen.getByRole('group', { name: 'Show changes of one kind' });
    expect(
      within(group)
        .getAllByRole('button')
        .map((button) => button.textContent),
    ).toEqual(['All', 'New', 'Improved', 'Security']);
    expect(screen.getByText('2 releases')).toBeInTheDocument();
  });

  it('narrows to the releases with a kind of change, showing only those changes', async () => {
    await renderPage();
    const security = screen.getByRole('button', { name: 'Security' });
    fireEvent.click(security);
    expect(security).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: 'All' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText('1 release matches')).toBeInTheDocument();
    expect(screen.getByText('A stricter policy guards the preview frame.')).toBeInTheDocument();
    expect(screen.queryByText('Previews render faster than before.')).toBeNull();
    expect(screen.queryByRole('heading', { name: 'Release notes arrive' })).toBeNull();
  });

  it('searches every word across the notes, and says when nothing matches', async () => {
    await renderPage();
    const search = screen.getByRole('searchbox', { name: 'Search the release notes' });
    fireEvent.change(search, { target: { value: 'explains UPDATE' } });
    expect(screen.getByText('1 release matches')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Release notes arrive' })).toBeInTheDocument();
    fireEvent.change(search, { target: { value: 'nothing like this' } });
    expect(screen.getByText('0 releases match')).toBeInTheDocument();
    expect(
      screen.getByText('No release notes match. Try fewer words, or show all kinds of change.'),
    ).toBeInTheDocument();
  });

  it('scrolls to the history when the link names it', async () => {
    const scroll = vi
      .spyOn(Element.prototype, 'scrollIntoView')
      .mockImplementation(() => undefined);
    const focus = vi.spyOn(HTMLElement.prototype, 'focus');
    await renderPage(undefined, '#release-history');
    await waitFor(() => {
      expect(scroll).toHaveBeenCalled();
    });
    const section = document.getElementById('release-history');
    expect(scroll.mock.contexts[0]).toBe(section);
    // Keyboard and screen-reader users land there too, not back where the link was,
    // without a second scroll that would undo the one above.
    expect(document.activeElement).toBe(section);
    expect(focus.mock.calls[focus.mock.contexts.indexOf(section)]).toEqual([
      { preventScroll: true },
    ]);
    // A target of links only: Tab never stops on it.
    expect(section).toHaveAttribute('tabindex', '-1');
  });

  it('lands on one release when the link names it', async () => {
    const scroll = vi
      .spyOn(Element.prototype, 'scrollIntoView')
      .mockImplementation(() => undefined);
    await renderPage(undefined, '#v0-15-0');
    const entry = await screen.findByRole('article', { name: 'Release 0.15.0' });
    await waitFor(() => {
      expect(document.activeElement).toBe(entry);
    });
    expect(scroll.mock.contexts).toEqual([entry]);
    expect(entry).toHaveAttribute('tabindex', '-1');
  });

  it('moves nothing when the link names no element on the page', async () => {
    const scroll = vi
      .spyOn(Element.prototype, 'scrollIntoView')
      .mockImplementation(() => undefined);
    await renderPage(undefined, '#no-such-release');
    expect(await screen.findByRole('heading', { level: 2, name: 'Release history' })).toBeVisible();
    await screen.findAllByRole('article');
    expect(scroll).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(document.body);
  });

  it('says so when the notes cannot be loaded', async () => {
    statusApi.status.mockResolvedValue(makeStatus());
    notesApi.get.mockRejectedValue(new Error('offline'));
    render(
      <ToastProvider>
        <MemoryRouter>
          <AboutPage />
        </MemoryRouter>
      </ToastProvider>,
    );
    expect(
      await screen.findByText(
        'The release notes could not be loaded. Check your connection and reload the page.',
      ),
    ).toBeInTheDocument();
    await act(async () => {
      await Promise.resolve();
    });
  });
});
