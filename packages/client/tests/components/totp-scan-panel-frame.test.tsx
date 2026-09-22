import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { TotpScanPanel } from '../../src/components/tools/TotpScanPanel';
import { completeSandboxHandshake, nextHostMessage } from '../support/sandboxHandshake';

/**
 * The hidden frame an uploaded photo stands up, and the promise that it goes
 * away again.
 *
 * The panel's own suite stubs `qrSandbox` in order to drive the panel without a
 * frame. This file does the opposite, for a question a stub cannot answer:
 * uploading a photo while the camera is OFF creates a scanner, and therefore a
 * real hidden `/sandbox.html` iframe, that belongs to that single call and that
 * nothing else will ever close. So the driver here is the real one, its
 * handshake is really completed, and the frame's replies are really posted on
 * the port the host transferred.
 *
 * Two shipped defects meet on this path, and both were invisible below this
 * level:
 *
 *  - the close sat AFTER the `await`, inside the `try`, so a scan that REJECTED
 *    skipped it and left one more opaque-origin document attached per attempt;
 *  - the scan was made in the same breath as the scanner was created, before the
 *    frame could possibly have completed its handshake, and the driver refused
 *    it outright — so an upload reported "That image could not be read." for
 *    every photograph ever given to it, however good.
 */

afterEach(() => {
  document.body.innerHTML = '';
});

function renderPanel() {
  const onDecoded = vi.fn();
  const onError = vi.fn();
  render(<TotpScanPanel onDecoded={onDecoded} onError={onError} status={null} />);
  return { onDecoded, onError };
}

async function uploadPhoto() {
  const input = document.querySelector('#totp-photo-input');
  if (input === null) throw new Error('the panel rendered no photo input');
  await act(async () => {
    fireEvent.change(input, {
      target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
    });
  });
}

/** Answer the one outstanding scan request as the frame would. */
async function answerAsFrame(reply: (requestId: number) => unknown): Promise<void> {
  const { host } = completeSandboxHandshake();
  const request = await nextHostMessage<{ kind: string; requestId: number }>(host);
  expect(request.kind).toBe('qrScan');
  await act(async () => {
    host.postMessage(reply(request.requestId));
  });
}

describe('the frame an uploaded photo creates', () => {
  it('sends the photo once the handshake lands, and takes the frame down after', async () => {
    const { onDecoded, onError } = renderPanel();

    // The upload happens FIRST, with the frame still loading. Refusing at this
    // moment is what made the feature impossible.
    await uploadPhoto();
    expect(document.querySelectorAll('iframe')).toHaveLength(1);

    await answerAsFrame((requestId) => ({
      kind: 'qrFound',
      requestId,
      text: 'otpauth-migration://offline?data=AA',
    }));

    await waitFor(() => {
      expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    });
    expect(onError).not.toHaveBeenCalled();
    // The frame belonged to that one call and is gone with it.
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
  });

  it('takes the frame down when the photo simply held no code', async () => {
    const { onDecoded, onError } = renderPanel();

    await uploadPhoto();
    await answerAsFrame((requestId) => ({ kind: 'qrMiss', requestId }));

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.stringContaining('closer, sharper photo'));
    });
    expect(onDecoded).not.toHaveBeenCalled();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
  });

  it('leaks nothing across repeated uploads', async () => {
    // One leaked frame is a bug; one PER ATTEMPT is what the original shape
    // produced, and a single-attempt assertion would still pass against a fix
    // that only closed the first one.
    const { onError } = renderPanel();

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await uploadPhoto();
      expect(document.querySelectorAll('iframe')).toHaveLength(1);
      await answerAsFrame((requestId) => ({ kind: 'qrMiss', requestId }));
      await waitFor(() => {
        expect(onError).toHaveBeenCalledTimes(attempt + 1);
      });
      expect(document.querySelectorAll('iframe')).toHaveLength(0);
    }
  });

  it('takes the frame down, and says what to do instead, when it never starts', async () => {
    // The frame is never given a handshake at all, which is what a CSP or CORS
    // mistake looks like from here: nothing happens and nothing explains it.
    vi.useFakeTimers();
    try {
      const { onError } = renderPanel();
      await uploadPhoto();
      expect(document.querySelectorAll('iframe')).toHaveLength(1);

      await act(async () => {
        vi.advanceTimersByTime(11_000);
      });

      // The parked photo is refused with the wording that NAMES THE REMEDY, and
      // that is the only sentence the user gets. Both consumers of this panel
      // funnel every message into one status line, and the generic fallback
      // arrives a microtask later — so asserting merely that both were called
      // would pin something nobody can see, and would pass against a build that
      // shows the vaguer one.
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith(expect.stringContaining('Paste your export link'));
      expect(onError).not.toHaveBeenCalledWith('That image could not be read.');
      expect(document.querySelectorAll('iframe')).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows the frame's OWN reason for an image it refused, and keeps the frame rule", async () => {
    // End to end over a real port: the frame refuses one image with a reason
    // that names the limit, the host rejects that one scan, and the panel shows
    // the frame's sentence rather than its own. The session was never told to
    // die, so the only thing taken down is the frame this call created.
    const { onError, onDecoded } = renderPanel();

    await uploadPhoto();
    await answerAsFrame((requestId) => ({
      kind: 'qrFailed',
      requestId,
      reason: 'That image is too large to read.',
    }));

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith('That image is too large to read.');
    });
    expect(onError).not.toHaveBeenCalledWith('That image could not be read.');
    expect(onDecoded).not.toHaveBeenCalled();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
  });

  it('builds that frame with an opaque origin and no delegated permission', async () => {
    // Asserted on the frame the PANEL causes to exist, because what contains the
    // decoder is the attribute reaching the DOM, not the helper that wrote it.
    renderPanel();
    await uploadPhoto();

    const frame = document.querySelector('iframe');
    expect(frame?.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame?.getAttribute('sandbox')).not.toContain('allow-same-origin');
    // The camera belongs to this origin and must never be handed to the frame.
    expect(frame?.getAttribute('allow')).toBe('');
    expect(frame?.referrerPolicy).toBe('no-referrer');
  });

  it('does not stand a frame up at all for a pasted link', async () => {
    const { onDecoded } = renderPanel();
    fireEvent.click(screen.getByText(/paste an export link instead/i));
    fireEvent.change(screen.getByLabelText('Export link'), {
      target: { value: 'otpauth-migration://offline?data=AA' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /read link/i }));
    });

    expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
  });
});
