/**
 * The document sandbox's isolation, from both sides.
 *
 * ## How this suite is wired, and why
 *
 * The FRAME's renderer is a pure function over bytes and is tested directly, in
 * jsdom, with no iframe at all. The frame's PROGRAM (`src/sandbox/sandbox.ts`)
 * is driven by importing it against a stub window, which is what an entry point
 * does when it boots. The HOST (`DocumentSandbox`) is rendered for real, and the
 * frame it would talk to is stubbed: jsdom never loads an iframe's `src`, so it
 * never runs the sandbox document, and pretending otherwise would produce a
 * suite that passed against nothing. That gap is closed at the other end by
 * Playwright (Phase 23), where a real `/sandbox.html` renders a real document.
 *
 * ## The threat each case names
 *
 * The one that matters most and reads least obviously is the ONE-SHOT rule. An
 * iframe's sandboxing flags are re-applied to EVERY document created in that
 * nested browsing context, so a compromised renderer that navigates itself to an
 * attacker's origin stays sandboxed, keeps an opaque origin, still reports
 * `event.origin === 'null'`, and is reached through the same `contentWindow`
 * WindowProxy. It passes BOTH checks. What it no longer carries is a CSP, so it
 * has full network access and would be an exfiltration endpoint if the host ever
 * spoke to it again.
 *
 * A test that asserts only the origin check therefore cannot fail against that
 * threat. The test that can is "posting a valid handshake TWICE transfers
 * exactly one port", and it is why the host removes its window listener on the
 * first accept rather than guarding a boolean.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, waitFor, cleanup } from '@testing-library/react';
import { DocumentSandbox } from '../src/components/documents/DocumentSandbox';
import { renderText } from '../src/sandbox/renderers/text';
import { frameMessage, parseRenderRequest } from '../src/sandbox/protocol';

// ---------------------------------------------------------------------------
// A stub frame
// ---------------------------------------------------------------------------

/**
 * What a real `contentWindow` gives the host, and nothing more: an identity to
 * compare `event.source` against, and a `postMessage` that records the transfer
 * list. jsdom leaves `iframe.contentWindow` as a real (about:blank) Window that
 * never loads our document, so it is replaced per test — which is also the only
 * way to make `event.source` match, since a `MessageEvent` constructed in a test
 * cannot name a cross-document window.
 */
interface StubWindow {
  postMessage: ReturnType<typeof vi.fn>;
}

function stubFrameWindow(frame: HTMLIFrameElement): StubWindow {
  const stub: StubWindow = { postMessage: vi.fn() };
  Object.defineProperty(frame, 'contentWindow', {
    configurable: true,
    get: () => stub,
  });
  return stub;
}

/** Dispatch a window `message` the way a framed document's post would arrive. */
function postFromFrame(source: unknown, data: unknown, origin = 'null'): void {
  const event = new MessageEvent('message', { data, origin });
  Object.defineProperty(event, 'source', { configurable: true, get: () => source });
  act(() => {
    window.dispatchEvent(event);
  });
}

/** The port the host transferred, if it transferred one. */
function transferredPort(stub: StubWindow): MessagePort | undefined {
  const call = stub.postMessage.mock.calls[0];
  return call?.[2]?.[0] as MessagePort | undefined;
}

/**
 * A buffer allocated in THIS realm.
 *
 * `new TextEncoder().encode(x).buffer` is not usable here: under jsdom the
 * encoder comes from Node's realm while the global `ArrayBuffer` is jsdom's, so
 * the result fails `instanceof ArrayBuffer` (measured). That is a test-harness
 * artefact and not a production condition — a browser has one realm, and a
 * structured clone materialises the copy in the RECEIVING realm, which is
 * exactly what makes the frame's `instanceof` check correct there. Building the
 * buffer explicitly keeps the fixture honest instead of weakening the check the
 * fixture is meant to exercise.
 */
function bytesOf(text: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(text);
  const buffer = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buffer).set(encoded);
  return buffer;
}

interface HostHandles {
  frame: HTMLIFrameElement;
  stub: StubWindow;
  onLink: ReturnType<typeof vi.fn<(href: string) => void>>;
  onUnavailable: ReturnType<typeof vi.fn<(reason: string) => void>>;
  rerender: (ui: React.ReactElement) => void;
}

function mountHost(overrides: Partial<React.ComponentProps<typeof DocumentSandbox>> = {}) {
  const onLink = vi.fn<(href: string) => void>();
  const onUnavailable = vi.fn<(reason: string) => void>();
  const props = {
    bytes: bytesOf('hello'),
    mode: 'text' as const,
    ext: 'txt',
    theme: 'dark' as const,
    onLink,
    onUnavailable,
    ...overrides,
  };
  const view = render(<DocumentSandbox {...props} />);
  const frame = screen.getByTitle('Document preview') as HTMLIFrameElement;
  const stub = stubFrameWindow(frame);
  const handles: HostHandles = { frame, stub, onLink, onUnavailable, rerender: view.rerender };
  return handles;
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  cleanup();
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// The frame element
// ---------------------------------------------------------------------------

describe('the iframe the host creates', () => {
  it('grants allow-scripts and never allow-same-origin', () => {
    const { frame } = mountHost();
    // `allow-scripts` WITHOUT `allow-same-origin` is what gives the document an
    // opaque origin. The two together are worth NOTHING — a document granted
    // both can remove its own sandbox attribute — so the negative here is the
    // whole assertion, and it is written to fail on the exact edit that would
    // undo the isolation while leaving every renderer working.
    expect(frame.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame.getAttribute('sandbox')).not.toContain('allow-same-origin');
  });

  it('grants no other sandbox capability', () => {
    const { frame } = mountHost();
    const flags = (frame.getAttribute('sandbox') ?? '').split(/\s+/).filter(Boolean);
    expect(flags).toEqual(['allow-scripts']);
    for (const denied of [
      'allow-popups',
      'allow-forms',
      'allow-modals',
      'allow-downloads',
      'allow-top-navigation',
      'allow-popups-to-escape-sandbox',
    ]) {
      expect(flags).not.toContain(denied);
    }
  });

  it('sends no referrer and delegates no permission', () => {
    const { frame } = mountHost();
    // The host is rendered at /documents/<id>. Without this the frame reads that
    // id out of `document.referrer` — the one identifying value the protocol
    // deliberately never sends. helmet's default covers it in production, but
    // that is an undocumented dependency and it is absent on the dev server the
    // end-to-end suite drives.
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer');
    // Deny every delegated permission rather than trusting each feature's default.
    expect(frame.getAttribute('allow')).toBe('');
    expect(frame.getAttribute('src')).toBe('/sandbox.html');
  });
});

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

describe('the handshake', () => {
  it('accepts a ready from the frame and transfers exactly one port', () => {
    const { stub } = mountHost();
    postFromFrame(stub, { kind: 'ready' });

    expect(stub.postMessage).toHaveBeenCalledTimes(1);
    const [data, targetOrigin, transfer] = stub.postMessage.mock.calls[0]!;
    expect(data).toEqual({ kind: 'channel' });
    // FORCED, not chosen: an opaque origin cannot be named. It is precisely why
    // the plaintext travels on the port instead and is never posted to a window.
    expect(targetOrigin).toBe('*');
    expect(transfer).toHaveLength(1);
    expect(transfer[0]).toBeInstanceOf(MessagePort);
  });

  it('posts a valid ready TWICE and still transfers exactly one port', () => {
    // THE case that covers a self-navigated frame. Such a document is still
    // sandboxed, still opaque, still reports origin "null" and is still reached
    // through the same contentWindow — so it passes both the source check and
    // the origin check. A test asserting only the origin check cannot fail
    // against it. What stops it is that the window listener is GONE after the
    // first accept, so the second post reaches nobody.
    const { stub } = mountHost();
    postFromFrame(stub, { kind: 'ready' });
    postFromFrame(stub, { kind: 'ready' });

    expect(stub.postMessage).toHaveBeenCalledTimes(1);
  });

  it('refuses a ready whose origin is not "null", even when the source matches', () => {
    const { stub, onUnavailable } = mountHost();
    postFromFrame(stub, { kind: 'ready' }, 'https://evil.example');

    expect(stub.postMessage).not.toHaveBeenCalled();
    // Ignored rather than torn down: a message from an origin that is not ours
    // and not opaque did not come from our frame at all, and tearing the preview
    // down for it would let any page on the internet cancel a user's preview by
    // posting to the window.
    expect(onUnavailable).not.toHaveBeenCalled();
  });

  it('refuses a ready from a different window', () => {
    const { stub, onUnavailable } = mountHost();
    const impostor = { postMessage: vi.fn() };
    postFromFrame(impostor, { kind: 'ready' });

    expect(stub.postMessage).not.toHaveBeenCalled();
    expect(impostor.postMessage).not.toHaveBeenCalled();
    expect(onUnavailable).not.toHaveBeenCalled();
  });

  it('rejects when either side is null, BEFORE comparing them', () => {
    // An INVARIANT of the accept path, not a lifecycle event. `contentWindow` is
    // null for a detached iframe and `event.source` is null for a message from a
    // closed window, so a bare `source === target` evaluates TRUE when both are
    // null and would accept ANYTHING. That single line is how this design gets
    // undone, and in production it is reachable on the pre-handshake teardown
    // paths — the frame that speaks first, and the handshake timeout.
    //
    // Observed through `MessageChannel`, not through `onUnavailable`. With the
    // guard removed the accept path runs, CONSTRUCTS A CHANNEL, and only then
    // throws on `null.postMessage` — so `onUnavailable` is not called either
    // way, and an assertion on it passes against the broken build. Measured:
    // that is what this test did before it was rewritten. The channel is the
    // first observable act of accepting, so it is the honest subject.
    const channels = vi.spyOn(globalThis, 'MessageChannel');
    const { frame, onUnavailable } = mountHost();
    Object.defineProperty(frame, 'contentWindow', { configurable: true, get: () => null });

    postFromFrame(null, { kind: 'ready' });

    expect(channels).not.toHaveBeenCalled();
    expect(onUnavailable).not.toHaveBeenCalled();
    expect(screen.queryByTitle('Document preview')).not.toBeNull();
  });

  it('tears down a frame that speaks before its handshake', () => {
    const { stub, onUnavailable } = mountHost();
    postFromFrame(stub, { kind: 'render', bytes: bytesOf('x') });

    expect(stub.postMessage).not.toHaveBeenCalled();
    expect(onUnavailable).toHaveBeenCalledTimes(1);
    // The frame is removed, not merely hidden: a hidden frame still loads
    // /sandbox.html, still runs its script and still holds whatever it holds.
    expect(screen.queryByTitle('Document preview')).toBeNull();
  });

  it('falls back to download when the handshake never arrives', () => {
    const { onUnavailable } = mountHost();
    expect(onUnavailable).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(10_000);
    });

    // A CSP or CORS mistake makes the frame blank with no error anyone can read,
    // so the timeout is what turns "nothing happened" into a verdict. An empty
    // rectangle that never resolves is the one outcome that is never acceptable.
    expect(onUnavailable).toHaveBeenCalledTimes(1);
    expect(String(onUnavailable.mock.calls[0]?.[0])).toMatch(/download/i);
    expect(screen.queryByTitle('Document preview')).toBeNull();
  });

  it('does not time out after a successful handshake', () => {
    const { stub, onUnavailable } = mountHost();
    postFromFrame(stub, { kind: 'ready' });

    act(() => {
      vi.advanceTimersByTime(60_000);
    });

    expect(onUnavailable).not.toHaveBeenCalled();
    expect(screen.queryByTitle('Document preview')).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// What crosses
// ---------------------------------------------------------------------------

describe('what the host sends', () => {
  it('posts exactly four fields and no key, token, id or name', async () => {
    const { stub } = mountHost({ mode: 'text', ext: 'md', theme: 'light' });
    const received: unknown[] = [];
    postFromFrame(stub, { kind: 'ready' });
    const port = transferredPort(stub)!;
    const far = new MessageChannel();
    // The transferred port's peer is unreachable from here (the host holds
    // port1 and gave us port2), so listen on the port we were given.
    port.onmessage = (event) => received.push(event.data);
    port.start();
    far.port1.close();
    far.port2.close();

    await waitFor(() => {
      expect(received).toHaveLength(1);
    });
    const payload = received[0] as Record<string, unknown>;
    // Asserted as the EXACT key set, not as "does not contain a key": a
    // whitelist fails when a field is added, which is the direction that leaks.
    expect(Object.keys(payload).sort()).toEqual(['bytes', 'ext', 'kind', 'mode', 'theme']);
    expect(payload['kind']).toBe('render');
    expect(payload['mode']).toBe('text');
    expect(payload['ext']).toBe('md');
    expect(payload['theme']).toBe('light');
    // Compared by brand rather than by `instanceof`: a structured clone through
    // jsdom's MessagePort can materialise the copy in a different realm, which
    // is a harness artefact and not something a browser does.
    expect(Object.prototype.toString.call(payload['bytes'])).toBe('[object ArrayBuffer]');
    expect((payload['bytes'] as ArrayBuffer).byteLength).toBe(5);
  });

  it('leaves the caller’s buffer usable, because it copies rather than transfers', async () => {
    // A component must not consume a prop it was lent. Transferring would detach
    // the caller's ArrayBuffer, so the SECOND post of the same document — a
    // remount on a theme change, a StrictMode double-effect — would throw
    // DataCloneError and kill the preview with no message to explain it.
    const bytes = bytesOf('hello');
    const { stub } = mountHost({ bytes });
    postFromFrame(stub, { kind: 'ready' });

    await waitFor(() => {
      expect(stub.postMessage).toHaveBeenCalled();
    });
    expect(bytes.byteLength).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// The port
// ---------------------------------------------------------------------------

describe('what arrives on the port', () => {
  /** Complete a handshake and return the port the FRAME would hold. */
  function handshake(handles: HostHandles): MessagePort {
    postFromFrame(handles.stub, { kind: 'ready' });
    const port = transferredPort(handles.stub);
    expect(port).toBeInstanceOf(MessagePort);
    port!.start();
    return port!;
  }

  it('opens a link only after its scheme passes isSafeUrl', async () => {
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage(frameMessage.link('https://example.com/a'));
    await waitFor(() => {
      expect(handles.onLink).toHaveBeenCalledWith('https://example.com/a');
    });
  });

  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>x</script>',
    'blob:https://x/y',
    'vbscript:x',
  ])('opens nothing and shows nothing for %s', async (href) => {
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage(frameMessage.link(href));
    port.postMessage(frameMessage.link('https://example.com/after'));

    // The second, valid link is the SYNCHRONISATION: once it has arrived, the
    // hostile one has certainly been processed, so `not.toHaveBeenCalled` is a
    // real observation rather than a race that would pass on an empty queue.
    await waitFor(() => {
      expect(handles.onLink).toHaveBeenCalledWith('https://example.com/after');
    });
    expect(handles.onLink).toHaveBeenCalledTimes(1);
    expect(handles.onLink).not.toHaveBeenCalledWith(href);
    // A refused scheme is not a compromised frame — a README full of
    // `mailto:` and `javascript:` links is ordinary — so the preview survives.
    expect(handles.onUnavailable).not.toHaveBeenCalled();
  });

  it('tears the frame down when a ready-shaped message arrives on the port', async () => {
    // Detection lives HERE and not on the window, because by now the window
    // listener is gone. A renderer that has been compromised and is fishing for
    // a second channel is exactly what this shape looks like.
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage({ kind: 'ready' });

    await waitFor(() => {
      expect(handles.onUnavailable).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByTitle('Document preview')).toBeNull();
  });

  it('tears the frame down on any message outside the expected set', async () => {
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage({ kind: 'exfiltrate', payload: 'secret' });

    await waitFor(() => {
      expect(handles.onUnavailable).toHaveBeenCalledTimes(1);
    });
    expect(handles.onLink).not.toHaveBeenCalled();
  });

  it('reports a renderer failure to the caller rather than leaving a blank frame', async () => {
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage(frameMessage.failed('No renderer for this document type.'));

    await waitFor(() => {
      expect(handles.onUnavailable).toHaveBeenCalledWith('No renderer for this document type.');
    });
  });

  it('takes no action on a successful render', async () => {
    const handles = mountHost();
    const port = handshake(handles);

    port.postMessage(frameMessage.rendered());
    port.postMessage(frameMessage.link('https://example.com/'));

    await waitFor(() => {
      expect(handles.onLink).toHaveBeenCalledTimes(1);
    });
    expect(handles.onUnavailable).not.toHaveBeenCalled();
    expect(screen.queryByTitle('Document preview')).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// One frame per document
// ---------------------------------------------------------------------------

describe('one frame per document', () => {
  it('creates a NEW iframe element for a second document', () => {
    const handles = mountHost();
    const first = screen.getByTitle('Document preview');

    act(() => {
      handles.rerender(
        <DocumentSandbox
          bytes={bytesOf('a different document')}
          mode="text"
          ext="txt"
          theme="dark"
          onLink={handles.onLink}
          onUnavailable={handles.onUnavailable}
        />,
      );
    });

    const second = screen.getByTitle('Document preview');
    // ELEMENT IDENTITY, not merely a changed src. A reused element would mean a
    // listener registered for the previous document, a port that outlived it,
    // and one document able to observe the next.
    expect(second).not.toBe(first);
  });

  it('remounts on a theme change rather than talking to a frame that will not answer', () => {
    // A frame that has already handshaked never posts `ready` again, so re-running
    // the protocol against the SAME element would register a listener nothing
    // speaks to and end in the timeout — a preview that vanishes when the user
    // toggles dark mode.
    const handles = mountHost({ theme: 'dark' });
    const first = screen.getByTitle('Document preview');

    act(() => {
      handles.rerender(
        <DocumentSandbox
          bytes={bytesOf('hello')}
          mode="text"
          ext="txt"
          theme="light"
          onLink={handles.onLink}
          onUnavailable={handles.onUnavailable}
        />,
      );
    });

    expect(screen.getByTitle('Document preview')).not.toBe(first);
    expect(handles.onUnavailable).not.toHaveBeenCalled();
  });

  /**
   * A rename, which is the case neither test above can reach.
   *
   * Every case below holds `bytes` at ONE reference on purpose. The two remount
   * tests above call `bytesOf(...)` a second time, which allocates a second
   * buffer and so takes the host's `seenBytes !== bytes` branch — they pass
   * whatever the element key says, and would go on passing against a host that
   * reused the frame for every prop except the payload. Renaming `notes.md` to
   * `notes.markdown`, or `.txt` to `.log`, changes `mode` and/or `ext` with the
   * same plaintext still in hand, and that is the shape the key has to survive.
   *
   * The two dimensions are exercised SEPARATELY as well as together, so that
   * dropping either one from the key fails a case of its own. `mode` and `ext`
   * are both derived from the document's name at the only call site today, so
   * the mode-only case pins the component's own contract rather than a journey
   * a user can take right now — which is the point: the rule is "every input the
   * effect reads", and a key that lists only the props someone happened to think
   * of is a key that will be wrong again.
   */
  describe('a rename, with the same bytes', () => {
    /**
     * Model the browser, because without this the cases below cannot fail for
     * the right reason.
     *
     * An iframe loads `/sandbox.html` and announces itself with exactly one
     * `ready` — per ELEMENT, at its load. An element that has ALREADY handshaked
     * never speaks again, which is the whole fact the remount rule exists to
     * respect. A helper that re-announced the same element would hand a reused
     * frame a second handshake no browser could produce, and the defect these
     * cases pin would present as a green suite.
     */
    let announced: WeakSet<HTMLIFrameElement>;
    beforeEach(() => {
      announced = new WeakSet<HTMLIFrameElement>();
    });

    function currentFrame(): HTMLIFrameElement {
      return screen.getByTitle('Document preview') as HTMLIFrameElement;
    }

    /** Let the CURRENT element announce itself, once and only once, ever. */
    function announceIfNew(): StubWindow | null {
      const frame = currentFrame();
      if (announced.has(frame)) return null;
      announced.add(frame);
      const stub = stubFrameWindow(frame);
      postFromFrame(stub, { kind: 'ready' });
      return stub;
    }

    /** What the frame was told to render, read off its own channel. */
    async function renderRequestOn(stub: StubWindow): Promise<Record<string, unknown>> {
      const port = transferredPort(stub);
      expect(port).toBeInstanceOf(MessagePort);
      const received: unknown[] = [];
      port!.onmessage = (event) => received.push(event.data);
      port!.start();
      await waitFor(() => {
        expect(received).toHaveLength(1);
      });
      return received[0] as Record<string, unknown>;
    }

    interface Naming {
      mode: React.ComponentProps<typeof DocumentSandbox>['mode'];
      ext: string;
    }

    it.each<[string, Naming, Naming]>([
      ['the mode alone', { mode: 'text', ext: 'md' }, { mode: 'markdown', ext: 'md' }],
      ['the extension alone', { mode: 'text', ext: 'txt' }, { mode: 'text', ext: 'log' }],
      [
        'both, which is what a rename does',
        { mode: 'text', ext: 'txt' },
        { mode: 'markdown', ext: 'md' },
      ],
    ])('replaces the frame when %s changes, and never times out', async (_label, before, after) => {
      const bytes = bytesOf('# hello');
      const handles = mountHost({ bytes, ...before });
      const first = currentFrame();
      announced.add(first);
      postFromFrame(handles.stub, { kind: 'ready' });
      expect(handles.onUnavailable).not.toHaveBeenCalled();

      act(() => {
        handles.rerender(
          <DocumentSandbox
            bytes={bytes}
            mode={after.mode}
            ext={after.ext}
            theme="dark"
            onLink={handles.onLink}
            onUnavailable={handles.onUnavailable}
          />,
        );
      });

      // ELEMENT IDENTITY. A reused element means a listener registered for a
      // handshake that has already happened and can never happen again.
      const second = currentFrame();
      expect(second).not.toBe(first);

      // The new element is told what it is now rendering, over its own channel:
      // the payload is the ONLY thing that carries the mode and the extension,
      // and it crosses exactly once, so a frame cannot be corrected later.
      const stub = announceIfNew();
      expect(stub).not.toBeNull();
      const payload = await renderRequestOn(stub!);
      expect(payload['kind']).toBe('render');
      expect(payload['mode']).toBe(after.mode);
      expect(payload['ext']).toBe(after.ext);
      expect((payload['bytes'] as ArrayBuffer).byteLength).toBe(bytes.byteLength);

      // And the SYMPTOM, which is what the reader would have seen: a frame that
      // has already handshaked never speaks again, so re-running the protocol
      // against it can only end in the ten-second timeout, replacing a working
      // preview with "The document preview did not load."
      act(() => {
        vi.advanceTimersByTime(60_000);
      });
      expect(handles.onUnavailable).not.toHaveBeenCalled();
      expect(screen.queryByTitle('Document preview')).not.toBeNull();
    });

    it('KEEPS the element when nothing the protocol reads changed', async () => {
      // The converse, and the half that had nothing holding it. The key must
      // contain everything the effect reads — and NOTHING ELSE, because a key
      // that moves on an ordinary re-render tears down a healthy frame and
      // re-handshakes mid-preview, which is the same ten-second death from the
      // other direction.
      //
      // Two things are deliberately changed here and neither may move the key.
      // `title` is one the caller really does change on a rename
      // (`Preview of <name>` in `DocumentDetail`), and the effect does not read
      // it. The callbacks are the other: they are passed as fresh inline arrows,
      // which is what a caller writes by default, and they are held in refs
      // precisely so they stay out of the dependency list. Delete that refs
      // indirection, or give `giveUp`'s `useCallback` a dependency, and this
      // goes red — which nothing in this suite could do before.
      const bytes = bytesOf('plain text');
      const handles = mountHost({ bytes, mode: 'text', ext: 'txt' });
      const first = currentFrame();
      announced.add(first);
      postFromFrame(handles.stub, { kind: 'ready' });

      act(() => {
        handles.rerender(
          <DocumentSandbox
            bytes={bytes}
            mode="text"
            ext="txt"
            theme="dark"
            title="Preview of notes.md"
            onLink={(href) => handles.onLink(href)}
            onUnavailable={(reason) => handles.onUnavailable(reason)}
          />,
        );
      });

      // SAME element. The frame is mid-preview and must not be disturbed. Found
      // by tag rather than by title, because the title is one of the two things
      // this case changes.
      const after = document.querySelector('iframe');
      expect(after).toBe(first);
      expect(screen.getByTitle('Preview of notes.md')).toBe(first);
      // And no second handshake was even attempted, so nothing is left waiting
      // on a frame that has already spoken. `announced` already holds this
      // element, so the helper posts nothing — which is the whole point.
      if (after !== null) announced.add(after);
      act(() => {
        vi.advanceTimersByTime(60_000);
      });
      expect(handles.onUnavailable).not.toHaveBeenCalled();
      expect(document.querySelector('iframe')).not.toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// The frame side
// ---------------------------------------------------------------------------

describe('the frame’s own validator', () => {
  const valid = { kind: 'render', mode: 'text', ext: 'txt', theme: 'dark', bytes: bytesOf('x') };

  it('accepts a well-formed request', () => {
    const parsed = parseRenderRequest(valid);
    expect(parsed).not.toBeNull();
    expect(parsed?.mode).toBe('text');
    expect(parsed?.bytes.byteLength).toBe(1);
  });

  it.each([
    ['not an object', 'render'],
    ['null', null],
    ['the wrong kind', { ...valid, kind: 'ready' }],
    ['no mode', { ...valid, mode: undefined }],
    ['an empty mode', { ...valid, mode: '' }],
    ['a non-string ext', { ...valid, ext: 7 }],
    ['an unresolved theme', { ...valid, theme: 'system' }],
    ['no bytes', { ...valid, bytes: undefined }],
    ['a typed-array view instead of a buffer', { ...valid, bytes: new Uint8Array(4) }],
    ['an object wearing byteLength', { ...valid, bytes: { byteLength: 4 } }],
    [
      'an object forging the ArrayBuffer brand',
      { ...valid, bytes: { byteLength: 4, [Symbol.toStringTag]: 'ArrayBuffer' } },
    ],
  ])('refuses %s', (_label, data) => {
    expect(parseRenderRequest(data)).toBeNull();
  });

  it('accepts a buffer from ANOTHER realm, which is where this one always comes from', () => {
    // The input is a structured clone posted from another document, so it is
    // cross-realm by definition. `value instanceof ArrayBuffer` compares against
    // THIS realm's constructor and refuses it — measured under jsdom, where the
    // frame rejected a perfectly good buffer and reported "the preview request
    // was not understood". `new TextEncoder().encode(x).buffer` reproduces that
    // condition here because jsdom's encoder comes from Node's realm.
    const foreign = new TextEncoder().encode('cross-realm').buffer;
    expect(foreign instanceof ArrayBuffer).toBe(false);
    const parsed = parseRenderRequest({ ...valid, bytes: foreign });
    expect(parsed).not.toBeNull();
    expect(parsed?.bytes.byteLength).toBe(11);
  });
});

describe('the plain-text renderer', () => {
  // The renderer itself is covered in depth by `sandbox-renderers.test.ts`
  // (encoding, line numbers, truncation, highlighting, the tabular and JSON
  // views). What is kept HERE is the one property this suite exists for: a
  // document's own bytes reach the page as a TEXT NODE and never as markup.
  it('puts the file in a single text node and never in markup', async () => {
    const rendered = await renderText(document, bytesOf('<script>alert(1)</script>\nplain'), 'txt');
    const code = rendered.querySelector('.hv-lines code');

    expect(code?.childNodes).toHaveLength(1);
    expect(code?.childNodes[0]?.nodeType).toBe(Node.TEXT_NODE);
    expect(code?.textContent).toBe('<script>alert(1)</script>\nplain');
    // The negative is the assertion: had this built a markup string, the file
    // would have contributed an element to the tree.
    expect(rendered.querySelector('script')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The frame's program
// ---------------------------------------------------------------------------

/**
 * `src/sandbox/sandbox.ts` is an entry point: it boots on import, against
 * `window`. Under jsdom `window.parent === window`, so the handshake it posts
 * arrives back at its own listener — harmless, because that listener keys on the
 * presence of a transferred PORT and ignores anything without one, which is the
 * same reason a hostile framing document cannot forge the reply.
 *
 * The module is re-imported per test so its one module-level piece of state (the
 * port) starts null, exactly as it does in a fresh document.
 */
/**
 * `URL.createObjectURL`, which jsdom does not implement.
 *
 * Installed as a PROPERTY on the real `URL` rather than through
 * `vi.stubGlobal('URL', ...)`, and that is not a style preference: replacing the
 * global with an object literal takes the CONSTRUCTOR with it, and the sandbox's
 * own link handling calls `new URL(href)` to tell an absolute href from a
 * relative one — which then fails with "URL is not a constructor", from a line
 * nowhere near the stub.
 */
interface BlobUrlMinting {
  createObjectURL?: (blob: Blob) => string;
  revokeObjectURL?: (url: string) => void;
}

/** A buffer of exact bytes, for a fixture that has to satisfy a signature. */
function rawBytesOf(values: readonly number[]): ArrayBuffer {
  const buffer = new ArrayBuffer(values.length);
  new Uint8Array(buffer).set(values);
  return buffer;
}

describe('the frame’s program', () => {
  interface BootedFrame {
    host: MessagePort;
    ready: ReturnType<typeof vi.fn>;
  }

  async function bootFrame(): Promise<BootedFrame> {
    document.body.innerHTML = '<div id="root"></div>';
    const ready = vi.fn();
    vi.spyOn(window, 'postMessage').mockImplementation(ready as never);
    vi.resetModules();
    await import('../src/sandbox/sandbox');

    // It announced readiness on the window, and that is ALL it announced.
    expect(ready).toHaveBeenCalledTimes(1);
    expect(ready.mock.calls[0]?.[0]).toEqual({ kind: 'ready' });
    expect(ready.mock.calls[0]?.[1]).toBe('*');

    const channel = new MessageChannel();
    const event = new MessageEvent('message', { data: { kind: 'channel' } });
    Object.defineProperty(event, 'ports', { configurable: true, get: () => [channel.port2] });
    window.dispatchEvent(event);
    channel.port1.start();
    return { host: channel.port1, ready };
  }

  /** The frame's next reply on the port. */
  function nextReply(port: MessagePort): Promise<unknown> {
    return new Promise((resolve) => {
      port.addEventListener('message', (event: MessageEvent) => resolve(event.data), {
        once: true,
      });
    });
  }

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('runs a transform and answers with the engine’s own reply', async () => {
    const { host } = await bootFrame();
    // Cleared explicitly: `documentElement` outlives a test, so an earlier
    // RENDER in this file would otherwise leave a theme here and the assertion
    // below would be about that test rather than this one.
    document.documentElement.removeAttribute('data-theme');
    const reply = nextReply(host);
    host.postMessage({
      kind: 'transform',
      text: '{"a":1,}',
      ext: 'json',
      format: true,
      repair: false,
    });

    await expect(reply).resolves.toEqual({
      kind: 'transformed',
      text: '{ "a": 1 }\n',
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: '3.9.5',
    });
    // The transform frame is HIDDEN and renders nothing: it must touch neither
    // the render target nor the theme, both of which belong to the other job.
    // Drawing anything here would be harmless today and the first step towards a
    // transform that puts something on screen for a user to act on.
    expect(document.getElementById('root')?.textContent).toBe('');
    expect(document.documentElement.dataset['theme']).toBeUndefined();
  });

  it('dispatches on the message kind BEFORE either validator runs', async () => {
    // Funnelling everything through the render parser would answer a perfectly
    // good transform request with "the preview request was not understood" — a
    // transform that fails for a reason that is not true.
    const { host } = await bootFrame();
    const reply = nextReply(host);
    host.postMessage({ kind: 'transform', text: '{}', ext: 'json', format: true, repair: false });
    await expect(reply).resolves.toMatchObject({ kind: 'transformed' });
  });

  it('refuses a transform request it cannot parse, on the port', async () => {
    const { host } = await bootFrame();
    const reply = nextReply(host);
    // Neither transform asked for. Nothing in the application produces this, so
    // it is a bug or a message from somebody else, and answering "here is your
    // text back" would attach a provenance record to a transform that never ran.
    host.postMessage({ kind: 'transform', text: '{}', ext: 'json', format: false, repair: false });

    await expect(reply).resolves.toEqual({
      kind: 'failed',
      reason: 'The transform request was not understood.',
    });
  });

  it('answers ON THE PORT even when the engine itself throws', async () => {
    // The one branch that cannot be reached with real input: a chunk that fails
    // to load, or an out-of-memory on a pathological document. SILENCE is the
    // failure being defended against — the host has a thirty-second deadline and
    // nothing else, so a swallowed error costs the user half a minute and tells
    // them nothing. The engine is stubbed rather than the frame, which is the
    // unit under test here.
    document.body.innerHTML = '<div id="root"></div>';
    const ready = vi.fn();
    vi.spyOn(window, 'postMessage').mockImplementation(ready as never);
    vi.resetModules();
    vi.doMock('../src/sandbox/transform/formatEngine', () => ({
      runTransform: () => {
        throw new Error('the chunk did not load');
      },
    }));
    try {
      await import('../src/sandbox/sandbox');
      const channel = new MessageChannel();
      const event = new MessageEvent('message', { data: { kind: 'channel' } });
      Object.defineProperty(event, 'ports', { configurable: true, get: () => [channel.port2] });
      window.dispatchEvent(event);
      channel.port1.start();

      const reply = nextReply(channel.port1);
      channel.port1.postMessage({
        kind: 'transform',
        text: '{}',
        ext: 'json',
        format: true,
        repair: false,
      });

      await expect(reply).resolves.toEqual({
        kind: 'transformFailed',
        stage: 'format',
        message: 'The document could not be formatted.',
        line: null,
        column: null,
        excerpt: '',
      });
    } finally {
      vi.doUnmock('../src/sandbox/transform/formatEngine');
      vi.resetModules();
    }
  });

  it('renders a text document and reports it', async () => {
    const { host } = await bootFrame();
    const reply = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'text',
      ext: 'txt',
      theme: 'light',
      bytes: bytesOf('hello world'),
    });

    await expect(reply).resolves.toEqual({ kind: 'rendered' });
    const root = document.getElementById('root')!;
    // Scoped to the source column: 19.1 gave the text renderer a line-number
    // gutter, which is a second `<pre>` and would otherwise be the one an
    // unscoped `querySelector` found.
    expect(root.querySelector('.hv-lines')?.textContent).toBe('hello world');
    // The resolved theme reaches the document element, never the user's
    // 'system' preference, which the frame could not resolve compatibly.
    expect(document.documentElement.dataset['theme']).toBe('light');
  });

  it('reports a mode it has no renderer for, and renders nothing', async () => {
    // `none` is the mode this project has DECIDED not to render — PDF is its
    // member — and it takes the same branch as a mode string the frame simply
    // does not know, which is why the frame never needs the list of valid modes
    // at runtime. (This case used to be spelled with `markdown`; Phase 19 gave
    // markdown a renderer, so that spelling would now assert the opposite of
    // what it says.)
    const { host } = await bootFrame();
    const reply = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'none',
      ext: 'pdf',
      theme: 'dark',
      bytes: bytesOf('%PDF-1.7 not really'),
    });

    await expect(reply).resolves.toEqual({
      kind: 'failed',
      reason: 'No renderer for this document type.',
    });
    // Emptied, not left holding the previous document — and, in particular, the
    // PDF was NOT rendered as text as a "helpful" fallback.
    expect(document.getElementById('root')?.textContent).toBe('');
  });

  it('loads a renderer per mode, and each one gets the whole request', async () => {
    // The mode switch is a DISPATCH TABLE, and it is the one place a renderer
    // can be wired to the wrong mode — an image request answered by the markdown
    // pipeline would produce a page of mojibake rather than an error. Each branch
    // is driven through the real program, with the request its renderer needs,
    // so a swapped `case` fails here rather than in a screenshot.
    //
    // Each is also a DYNAMIC import, which is what makes it its own chunk; a
    // static one would put the markdown pipeline and the highlighter into the
    // chunk a plain `.txt` preview downloads.
    const objectUrls: string[] = [];
    const urlGlobal = URL as unknown as BlobUrlMinting;
    urlGlobal.createObjectURL = () => {
      objectUrls.push('blob:test');
      return 'blob:test';
    };
    urlGlobal.revokeObjectURL = () => undefined;
    try {
      const { host } = await bootFrame();

      const markdown = nextReply(host);
      host.postMessage({
        kind: 'render',
        mode: 'markdown',
        ext: 'md',
        theme: 'dark',
        bytes: bytesOf('# Heading\n'),
      });
      await expect(markdown).resolves.toEqual({ kind: 'rendered' });
      expect(document.querySelector('#root h1')?.textContent).toBe('Heading');

      const html = nextReply(host);
      host.postMessage({
        kind: 'render',
        mode: 'html',
        ext: 'html',
        theme: 'dark',
        bytes: bytesOf('<h2>Stored</h2>'),
      });
      await expect(html).resolves.toEqual({ kind: 'rendered' });
      expect(document.querySelector('#root h2')?.textContent).toBe('Stored');

      const image = nextReply(host);
      host.postMessage({
        kind: 'render',
        mode: 'image',
        ext: 'png',
        theme: 'dark',
        // RAW bytes, not `bytesOf`: a PNG signature written as a string would
        // be UTF-8 encoded on the way in, turning 0x89 into 0xC2 0x89 — and the
        // sniffer would correctly refuse the result as not a PNG.
        bytes: rawBytesOf([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      });
      await expect(image).resolves.toEqual({ kind: 'rendered' });
      expect(document.querySelector('#root img')).not.toBeNull();

      const media = nextReply(host);
      host.postMessage({
        kind: 'render',
        mode: 'media',
        ext: 'webm',
        theme: 'dark',
        bytes: rawBytesOf([0x1a, 0x45, 0xdf, 0xa3, 0x00, 0x00, 0x00, 0x00]),
      });
      await expect(media).resolves.toEqual({ kind: 'rendered' });
      expect(document.querySelector('#root video')).not.toBeNull();
      // Each of the two media renderers minted its own blob URL, on THIS side of
      // the channel: one made by the application would not resolve in an opaque
      // origin.
      expect(objectUrls).toHaveLength(2);
    } finally {
      delete urlGlobal.createObjectURL;
      delete urlGlobal.revokeObjectURL;
    }
  });

  it('refuses a document whose bytes disagree with its extension, before any renderer', async () => {
    // The sniffer runs ahead of the mode switch, so a file that lies about what
    // it is never reaches a parser chosen on the strength of that lie.
    const { host } = await bootFrame();
    const reply = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'markdown',
      ext: 'md',
      theme: 'dark',
      bytes: bytesOf('%PDF-1.7 and then some'),
    });

    const answer = (await reply) as { kind: string; reason: string };
    expect(answer.kind).toBe('failed');
    expect(answer.reason).toContain('PDF');
    expect(document.getElementById('root')?.textContent).toBe('');
  });

  it('scrolls to a same-document fragment instead of posting it to the host', async () => {
    // A heading anchor, a table-of-contents entry and a GFM footnote are all
    // fragments, and the host validates with `isSafeUrl`, which admits http,
    // https and mailto only — so posting one would drop it silently and stop
    // footnote and heading navigation working with nothing to explain it.
    //
    // The id is resolved against what the SANITIZER wrote: its default schema
    // clobbers every id with the prefix `user-content-` and does not rewrite the
    // hrefs pointing at them, so a naive lookup finds nothing.
    const { host } = await bootFrame();
    const rendered = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'text',
      ext: 'txt',
      theme: 'dark',
      bytes: bytesOf('x'),
    });
    await rendered;

    // jsdom implements no scrolling at all, so the method is installed for the
    // duration of this test and its CALL is the observable outcome.
    const scrollIntoView = vi.fn();
    Object.defineProperty(Element.prototype, 'scrollIntoView', {
      configurable: true,
      writable: true,
      value: scrollIntoView,
    });

    const root = document.getElementById('root')!;
    const target = document.createElement('h2');
    target.id = 'user-content-intro';
    const anchor = document.createElement('a');
    anchor.setAttribute('href', '#intro');
    anchor.textContent = 'to the intro';
    root.append(target, anchor);

    let posted = false;
    host.addEventListener('message', () => {
      posted = true;
    });

    const click = new MouseEvent('click', { bubbles: true, cancelable: true });
    anchor.dispatchEvent(click);
    await Promise.resolve();

    expect(click.defaultPrevented).toBe(true);
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
    expect(posted).toBe(false);
    delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
  });

  it('posts nothing for a relative link, which resolves to nothing for a stored file', async () => {
    const { host } = await bootFrame();
    const rendered = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'text',
      ext: 'txt',
      theme: 'dark',
      bytes: bytesOf('x'),
    });
    await rendered;

    const root = document.getElementById('root')!;
    const anchor = document.createElement('a');
    anchor.setAttribute('href', '../sibling.md');
    anchor.textContent = 'relative';
    root.append(anchor);

    let posted = false;
    host.addEventListener('message', () => {
      posted = true;
    });

    const click = new MouseEvent('click', { bubbles: true, cancelable: true });
    anchor.dispatchEvent(click);
    await Promise.resolve();

    // Prevented in every branch, so no branch can leave the frame following a
    // link, and nothing was handed to the host for a URL it could not open.
    expect(click.defaultPrevented).toBe(true);
    expect(posted).toBe(false);
  });

  it('answers a malformed request rather than staying silent', async () => {
    // Silence is the one thing the frame must never do: the host times out on a
    // frame that never speaks, so a swallowed error costs a working preview and
    // tells nobody why.
    const { host } = await bootFrame();
    const reply = nextReply(host);
    host.postMessage({ kind: 'render', mode: 'text' });

    await expect(reply).resolves.toEqual({
      kind: 'failed',
      reason: 'The preview request was not understood.',
    });
  });

  it('reports a link click instead of navigating', async () => {
    const { host } = await bootFrame();
    const rendered = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'text',
      ext: 'txt',
      theme: 'dark',
      bytes: bytesOf('x'),
    });
    await rendered;

    const root = document.getElementById('root')!;
    const anchor = document.createElement('a');
    anchor.href = 'https://example.com/doc';
    anchor.textContent = 'link';
    root.append(anchor);

    const reply = nextReply(host);
    const click = new MouseEvent('click', { bubbles: true, cancelable: true });
    anchor.dispatchEvent(click);

    // The frame opens nothing itself — it could not, with no `allow-popups` and
    // no `allow-top-navigation` — and the default is prevented so a same-frame
    // navigation cannot happen either.
    expect(click.defaultPrevented).toBe(true);
    await expect(reply).resolves.toEqual({ kind: 'link', href: 'https://example.com/doc' });
  });

  it('ignores a click that is not on a link', async () => {
    const { host } = await bootFrame();
    const replies: unknown[] = [];
    host.addEventListener('message', (event: MessageEvent) => replies.push(event.data));

    const root = document.getElementById('root')!;
    const span = document.createElement('span');
    root.append(span);
    span.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(replies).toEqual([]);
  });

  it('ignores a window message that carries no port, so a reply cannot be forged', async () => {
    // The handshake reply is identified by its transferred PORT, which only the
    // embedder can create — never by its payload, which any framing document
    // could imitate.
    document.body.innerHTML = '<div id="root"></div>';
    vi.spyOn(window, 'postMessage').mockImplementation(vi.fn() as never);
    vi.resetModules();
    const mod = await import('../src/sandbox/sandbox');

    window.dispatchEvent(new MessageEvent('message', { data: { kind: 'channel' } }));
    expect(mod.sandboxChannel()).toBeNull();

    // ...and the real reply is still accepted afterwards, so the refusal above
    // did not consume the one-shot.
    const channel = new MessageChannel();
    const event = new MessageEvent('message', { data: null });
    Object.defineProperty(event, 'ports', { configurable: true, get: () => [channel.port2] });
    window.dispatchEvent(event);
    expect(mod.sandboxChannel()).not.toBeNull();
  });

  it('answers on the port even when a renderer throws, rather than going silent', async () => {
    // Silence is the failure mode with no diagnosis: the host waits out its
    // ten-second timeout and degrades to "download to view", telling the user
    // nothing and telling the log nothing. The fault is injected at the DOM
    // boundary, which is where a renderer's output actually lands.
    const { host } = await bootFrame();
    const root = document.getElementById('root')!;
    vi.spyOn(root, 'replaceChildren').mockImplementationOnce(() => {
      throw new Error('renderer exploded');
    });

    const reply = nextReply(host);
    host.postMessage({
      kind: 'render',
      mode: 'text',
      ext: 'txt',
      theme: 'dark',
      bytes: bytesOf('hello'),
    });

    const answer = (await reply) as { kind: string; reason: string };
    expect(answer.kind).toBe('failed');
    // The message carries NO detail from the error: an error built while parsing
    // the document is built FROM the document, and the host renders this text.
    expect(answer.reason).toBe('The document could not be displayed.');
    expect(answer.reason).not.toContain('exploded');
  });

  it('creates its render target when the document was served without one', async () => {
    // A build that emitted the document without its root element is a build
    // mistake rather than a runtime condition, and recreating it costs nothing
    // when the element is there. The alternative is a blank frame with no
    // explanation, which is indistinguishable from every other silent failure.
    document.body.innerHTML = '';
    vi.spyOn(window, 'postMessage').mockImplementation(vi.fn() as never);
    vi.resetModules();
    await import('../src/sandbox/sandbox');

    const root = document.getElementById('root');
    expect(root).not.toBeNull();
    expect(root?.parentElement).toBe(document.body);
  });

  it('accepts exactly one channel, so a second cannot be handed to it', async () => {
    const { host } = await bootFrame();
    const mod = await import('../src/sandbox/sandbox');
    const first = mod.sandboxChannel();

    const second = new MessageChannel();
    const event = new MessageEvent('message', { data: null });
    Object.defineProperty(event, 'ports', { configurable: true, get: () => [second.port2] });
    window.dispatchEvent(event);

    // The mirror of the host's one-shot rule: with the window listener gone, a
    // second attempt to hand this document a channel reaches nobody.
    expect(mod.sandboxChannel()).toBe(first);
    host.close();
    second.port1.close();
    second.port2.close();
  });
});
