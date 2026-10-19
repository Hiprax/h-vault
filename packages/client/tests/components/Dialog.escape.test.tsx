/**
 * Escape closes a dialog through the handler of the LATEST render.
 *
 * The listener sits on `document`, added by an effect. Effects run after the commit
 * that shows new content, so a listener that captured the handler of the render
 * that added it called the PREVIOUS render's handler when Escape came in between.
 * "What's new" showed the effect: its handler names the release it shows, and an
 * Escape pressed as the notes arrived acknowledged nothing (so it came back).
 *
 * The update below lands outside `act`, as a fetch's does, and Escape is pressed
 * from a `MutationObserver`: it runs as soon as the commit has changed the page and
 * before React runs that commit's effects, which is the window a real Escape can
 * hit on a busy machine. (Testing Library's own waits give the effects a task to
 * run in, so pressing after `findBy…` would usually miss the window.)
 */
import { useEffect, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Dialog, DialogContent, DialogTitle } from '../../src/components/ui/Dialog';

afterEach(cleanup);

function Harness({ onClose }: { onClose: (shown: string) => void }) {
  const [shown, setShown] = useState('loading');
  useEffect(() => {
    // As a fetch resolves: a macrotask later, outside any `act`.
    const timer = setTimeout(() => setShown('0.18.0'), 0);
    return () => clearTimeout(timer);
  }, []);
  return (
    <Dialog open onOpenChange={() => onClose(shown)}>
      <DialogContent>
        <DialogTitle>Notes</DialogTitle>
        <p>{`Showing ${shown}`}</p>
      </DialogContent>
    </Dialog>
  );
}

/** Press `key` on the document the moment the page first shows `text`. */
function pressWhenShown(text: string, key: string): MutationObserver {
  const observer = new MutationObserver(() => {
    if (!document.body.textContent?.includes(text)) return;
    observer.disconnect();
    document.dispatchEvent(new KeyboardEvent('keydown', { key }));
  });
  observer.observe(document.body, { subtree: true, childList: true, characterData: true });
  return observer;
}

describe('Dialog Escape', () => {
  it('closes through the handler of the latest render, even before its effects run', async () => {
    const onClose = vi.fn();
    const observer = pressWhenShown('Showing 0.18.0', 'Escape');
    render(<Harness onClose={onClose} />);

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    observer.disconnect();
    expect(onClose).toHaveBeenCalledWith('0.18.0');
    expect(onClose).not.toHaveBeenCalledWith('loading');
  });

  it('ignores other keys', async () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);
    await screen.findByText('Showing 0.18.0');

    fireEvent.keyDown(document, { key: 'Enter' });

    expect(onClose).not.toHaveBeenCalled();
  });
});
