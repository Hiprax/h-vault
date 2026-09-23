import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * The driver's own contract, driven through a stubbed handshake.
 *
 * `connectSandbox` is a COLLABORATOR here, not the unit: what it guarantees (a
 * one-shot handshake, a transferred port, a listener removed before anything is
 * created) is pinned against the real thing in its own suite. What belongs here
 * is the property only this driver decides, and the one that replaces
 * "one frame, one payload" for a streaming session: a reply is an answer only
 * when it matches an OUTSTANDING request, and anything else tears the session
 * down rather than being guessed at.
 */

const connectSandbox = vi.fn();
vi.mock('../../src/lib/sandboxHandshake', () => ({
  connectSandbox: (options: unknown) => connectSandbox(options),
}));

const { openQrScanner, QrImageRefusedError } =
  await import('../../src/services/totpImport/qrSandbox');

type PostFn = (message: unknown, transfer?: Transferable[]) => void;
type FailFn = (reason: string) => void;

interface Captured {
  onMessage: (data: unknown, connection: { post: PostFn; fail: FailFn }) => void;
  onUnavailable: (reason: string) => void;
  post: ReturnType<typeof vi.fn<PostFn>>;
  fail: ReturnType<typeof vi.fn<FailFn>>;
  close: ReturnType<typeof vi.fn<() => void>>;
}

/**
 * Stand the driver up against a stubbed handshake.
 *
 * `handshake: 'deferred'` withholds `onOpen`, which is the state a REAL frame is
 * in for its first tens of milliseconds: created, attached, and not yet able to
 * carry anything. Call the returned `openChannel()` to complete it. The default
 * opens immediately, because most of what this file pins is reply handling.
 */
function openWithStub(options: { handshake?: 'immediate' | 'deferred' } = {}): {
  captured: Captured;
  unavailable: string[];
  scanner: ReturnType<typeof openQrScanner>;
  openChannel: () => void;
} {
  const post = vi.fn<PostFn>();
  // `fail` FORWARDS to `onUnavailable`, exactly as the real handshake does
  // (`lib/sandboxHandshake.ts`: `fail` sets `dead`, tears the channel down and
  // calls `onUnavailable`). A stub that merely recorded the call could only ever
  // assert that the driver ASKED for a teardown, never that the teardown left
  // the caller's promise settled — which is how a `qrFound` that killed the
  // session while stranding the scan it was answering went unnoticed.
  let failed = false;
  const fail = vi.fn<FailFn>((reason: string) => {
    if (failed) return;
    failed = true;
    captured?.onUnavailable(reason);
  });
  const close = vi.fn<() => void>();
  let captured: Captured | null = null;
  let openChannel = (): void => {
    throw new Error('the handshake was already completed');
  };

  connectSandbox.mockImplementation((options_: Record<string, never>) => {
    const opts = options_ as unknown as {
      onOpen: (c: unknown) => void;
      onMessage: Captured['onMessage'];
      onUnavailable: (reason: string) => void;
    };
    const connection = { post, fail };
    captured = { onMessage: opts.onMessage, onUnavailable: opts.onUnavailable, post, fail, close };
    if (options.handshake === 'deferred') {
      openChannel = () => opts.onOpen(connection);
    } else {
      opts.onOpen(connection);
    }
    return { close };
  });

  const unavailable: string[] = [];
  const scanner = openQrScanner((reason) => unavailable.push(reason));
  if (captured === null) throw new Error('connectSandbox was not called');
  return { captured, unavailable, scanner, openChannel: () => openChannel() };
}

/**
 * A stand-in for a camera frame.
 *
 * jsdom has no `ImageBitmap`, so this is an object the driver never inspects.
 * What matters is that it is NOT a `Blob`, because that is the discriminator the
 * driver uses to decide whether the image may be named in a transfer list.
 */
const image = {} as ImageBitmap;

/** A stand-in for an uploaded photo. A `File` IS a `Blob`, which is the point. */
function photo(): Blob {
  return new File([new Uint8Array([1, 2, 3, 4])], 'export.png', { type: 'image/png' });
}

beforeEach(() => {
  connectSandbox.mockReset();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  document.body.innerHTML = '';
});

describe('openQrScanner', () => {
  it('transfers a camera frame rather than copying it', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);

    const [message, transfer] = captured.post.mock.calls[0] ?? [];
    expect((message as { kind: string }).kind).toBe('qrScan');
    // Copying would move megabytes per camera frame across what is, in
    // Chromium, a separate process. Asserted by IDENTITY: `image` is an empty
    // stand-in, so a structural compare would accept any other empty object and
    // could not tell "the image was transferred" from "something was".
    expect(transfer).toHaveLength(1);
    expect(transfer?.[0]).toBe(image);

    const requestId = (message as { requestId: number }).requestId;
    captured.onMessage({ kind: 'qrMiss', requestId }, { post: captured.post, fail: captured.fail });
    await expect(pending).resolves.toBeNull();
  });

  it('names NO transfer list for an uploaded photo, because a Blob cannot be transferred', () => {
    // THE DEFECT THIS REPLACES. This assertion used to read
    // `expect(transfer).toEqual([image])` for a single stand-in object, which
    // said nothing about the input TYPE and so passed happily against a driver
    // that named a `Blob` in a transfer list — the shape that throws
    // `DataCloneError` on every real upload. What is pinned now is the decision
    // itself: the list is present for one type and absent for the other, and
    // neither half can be deleted without the other failing.
    const { captured, scanner } = openWithStub();
    void scanner.scan(photo());

    const [message, transfer] = captured.post.mock.calls[0] ?? [];
    // The image still travels; it is the TRANSFER LIST that must be absent, so
    // the structured clone carries the Blob instead.
    expect((message as { image: unknown }).image).toBeInstanceOf(Blob);
    expect(transfer).toBeUndefined();
  });

  it('rejects one scan, and keeps the session, when the post itself throws', async () => {
    // A refused image is one lost frame, not a dead channel: the port was never
    // touched, so the next frame is 120 ms away rather than never.
    const { captured, scanner } = openWithStub();
    captured.post.mockImplementationOnce(() => {
      throw new DOMException('Found invalid value in transferList.', 'DataCloneError');
    });

    await expect(scanner.scan(image)).rejects.toThrow(/could not be handed to the scanner/);
    expect(captured.fail).not.toHaveBeenCalled();

    // The session still answers, which is the whole claim.
    const second = scanner.scan(image);
    const requestId = (captured.post.mock.calls[1]?.[0] as { requestId: number }).requestId;
    captured.onMessage({ kind: 'qrMiss', requestId }, { post: captured.post, fail: captured.fail });
    await expect(second).resolves.toBeNull();
  });

  it('registers NOTHING for a request whose post threw', async () => {
    // The ordering rule, made observable rather than merely asserted: the id of
    // a request that never went out is not outstanding, so a reply carrying it
    // is a reply to a request that was never made. Register before posting and
    // that entry survives with a live 4 s timer that nothing can ever clear, and
    // this same reply is silently accepted instead of refused.
    const { captured, scanner } = openWithStub();
    captured.post.mockImplementationOnce(() => {
      throw new DOMException('Found invalid value in transferList.', 'DataCloneError');
    });

    await expect(scanner.scan(image)).rejects.toThrow(/could not be handed to the scanner/);
    const failedId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrMiss', requestId: failedId },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it('PARKS a scan asked for before the handshake, rather than refusing it', async () => {
    // THE SECOND DEFECT ON THE UPLOAD PATH, and the one that survived the
    // transfer-list fix. A channel is not open the instant it is asked for. The
    // camera survives that because it is a loop and retries 120 ms later; an
    // upload stands a scanner up and scans ONCE, so refusing here reported
    // "That image could not be read." for every photograph ever uploaded.
    const { captured, scanner, openChannel } = openWithStub({ handshake: 'deferred' });
    const pending = scanner.scan(photo());

    // Nothing has gone out, and nothing has been refused either.
    expect(captured.post).not.toHaveBeenCalled();

    openChannel();

    const [message, transfer] = captured.post.mock.calls[0] ?? [];
    expect((message as { kind: string }).kind).toBe('qrScan');
    expect(transfer).toBeUndefined();

    const requestId = (message as { requestId: number }).requestId;
    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'otpauth-migration://offline?data=AA' },
      { post: captured.post, fail: captured.fail },
    );
    await expect(pending).resolves.toBe('otpauth-migration://offline?data=AA');
  });

  it('sends parked scans in the order they were asked for', async () => {
    const { captured, scanner, openChannel } = openWithStub({ handshake: 'deferred' });
    const first = scanner.scan(image);
    const second = scanner.scan(photo());
    openChannel();

    const calls = captured.post.mock.calls;
    expect(calls).toHaveLength(2);
    // The camera frame keeps its transfer list and the photo still has none, so
    // parking does not quietly change how either one travels.
    expect(calls[0]?.[1]?.[0]).toBe(image);
    expect(calls[1]?.[1]).toBeUndefined();

    const ids = calls.map((call) => (call[0] as { requestId: number }).requestId);
    expect(ids[1]).toBeGreaterThan(ids[0] ?? 0);

    captured.onMessage(
      { kind: 'qrFound', requestId: ids[0], text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );
    captured.onMessage(
      { kind: 'qrMiss', requestId: ids[1] },
      {
        post: captured.post,
        fail: captured.fail,
      },
    );
    await expect(first).resolves.toContain('/a?');
    await expect(second).resolves.toBeNull();
  });

  it('refuses a parked scan with the same sentence when the frame never arrives', async () => {
    // A parked request must not outlive the handshake it is waiting for. The
    // caller gets the wording that names the remedy, exactly as it would have
    // for a request that did go out.
    const { captured, scanner } = openWithStub({ handshake: 'deferred' });
    const pending = scanner.scan(photo());

    captured.onUnavailable('The scanner could not start. Paste your export link instead.');

    await expect(pending).rejects.toThrow(/Paste your export link/);
    expect(captured.post).not.toHaveBeenCalled();
  });

  it('answers a parked scan as a miss when the caller closes deliberately', async () => {
    const { captured, scanner } = openWithStub({ handshake: 'deferred' });
    const pending = scanner.scan(photo());

    scanner.close();

    await expect(pending).resolves.toBeNull();
    expect(captured.post).not.toHaveBeenCalled();
  });

  it('resolves a found code with its text', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'otpauth-migration://offline?data=AA' },
      { post: captured.post, fail: captured.fail },
    );
    await expect(pending).resolves.toBe('otpauth-migration://offline?data=AA');
  });

  it('answers each request with its own reply, even out of order', async () => {
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const second = scanner.scan(image);
    const ids = captured.post.mock.calls.map(
      (call) => (call[0] as { requestId: number }).requestId,
    );

    captured.onMessage(
      { kind: 'qrFound', requestId: ids[1], text: 'otpauth://totp/b?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );
    captured.onMessage(
      { kind: 'qrFound', requestId: ids[0], text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );

    await expect(first).resolves.toContain('/a?');
    await expect(second).resolves.toContain('/b?');
  });

  // A uniform tuple type, so the table does not widen into a union that
  // `it.each` cannot line up with the callback.
  const unexpectedReplies: [unknown, string][] = [
    [{ kind: 'rendered' }, 'a render reply'],
    [{ kind: 'transformed', text: 'x' }, 'a transform reply'],
    [{ kind: 'ready' }, 'a second handshake'],
    ['not an object', 'a bare string'],
  ];

  it.each(unexpectedReplies)('tears the session down on %s', (reply) => {
    const { captured } = openWithStub();
    captured.onMessage(reply, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalled();
  });

  it('tears the session down on a reply to a request that was never made', () => {
    const { captured } = openWithStub();
    captured.onMessage(
      { kind: 'qrFound', requestId: 999, text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it('tears the session down on a SECOND reply to the same request', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    const connection = { post: captured.post, fail: captured.fail };

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    await expect(pending).resolves.toBeNull();

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    expect(captured.fail).toHaveBeenCalled();
  });

  it('refuses an oversized decoded string rather than handing it on', async () => {
    const { captured, scanner } = openWithStub();
    // AWAITED, not `void`ed. Since a session-ending refusal settles every
    // outstanding scan, a `void` here leaves the rejection unconsumed — which
    // Node reports as an unhandled rejection and vitest counts as an error
    // beside a green suite, so the run exits 1 with every test passing. It is
    // also the stronger assertion: what this case is really about is that the
    // caller waiting on that image is told, not merely that the session died.
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'o'.repeat(20_000) },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalled();
    await expect(pending).rejects.toThrow(/unreadable result/);
  });

  it.each([
    ['an oversized decoded string', 'o'.repeat(20_000)],
    ['a decoded value that is not a string', 42],
  ])('SETTLES the scan it was answering when %s kills the session', async (_label, text) => {
    // The session-ending refusals reach the caller through `die`, which settles
    // every outstanding scan by sweeping `pending`. A `qrFound` whose payload is
    // unusable used to be removed from `pending` BEFORE that payload was judged,
    // so `die` swept a map the entry had already left and the promise never
    // settled at all — not resolved, not rejected. `TotpScanPanel.scanFile`'s
    // `finally` therefore never ran, `setBusy(false)` never fired, and the photo
    // input stayed `disabled` for the life of the tab; on the camera path the
    // pump parked on a promise that could not complete.
    //
    // The outcome is captured through a variable rather than awaited directly,
    // so a regression fails on a concrete value instead of hanging until the
    // suite's timeout and reporting nothing about why.
    const { captured, scanner } = openWithStub();
    let outcome: string | null = null;
    void scanner.scan(image).then(
      (value) => {
        outcome = `resolved: ${String(value)}`;
      },
      (error: unknown) => {
        outcome = error instanceof Error ? error.message : String(error);
      },
    );
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFound', requestId, text },
      { post: captured.post, fail: captured.fail },
    );
    await vi.advanceTimersByTimeAsync(0);

    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('unreadable result'));
    expect(outcome).toBe('The scanner sent an unreadable result.');
    // The negative that matters: it was REFUSED, never handed the bad payload.
    expect(outcome).not.toMatch(/^resolved/);
  });

  it('treats one slow image as a miss, not as a dead session', async () => {
    // A camera produces another frame in about 120 ms, so the useful answer to a
    // slow decode is "try the next one" rather than "stop scanning".
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    vi.advanceTimersByTime(5000);
    await expect(pending).resolves.toBeNull();
    expect(captured.fail).not.toHaveBeenCalled();
  });

  it('IGNORES a reply that arrives after its deadline, rather than killing the camera', async () => {
    // The session's central rule is that a reply matching no outstanding request
    // tears everything down. A frame that answers at 4.1 s for a request
    // abandoned at 4.0 s used to hit exactly that rule and stop the camera dead,
    // with nothing on screen to explain it. A slow frame is not a hostile one.
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    vi.advanceTimersByTime(5000);
    await expect(pending).resolves.toBeNull();

    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );

    expect(captured.fail).not.toHaveBeenCalled();
    // And the session is genuinely still usable, not merely un-failed.
    const next = scanner.scan(image);
    const nextId = (captured.post.mock.calls[1]?.[0] as { requestId: number }).requestId;
    captured.onMessage(
      { kind: 'qrMiss', requestId: nextId },
      {
        post: captured.post,
        fail: captured.fail,
      },
    );
    await expect(next).resolves.toBeNull();
  });

  it('forgives a timed-out id EXACTLY ONCE, so a second reply still tears down', async () => {
    // Forgiveness that did not consume the id would hand the frame a permanent
    // licence to send whatever it liked under that number.
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    const connection = { post: captured.post, fail: captured.fail };

    vi.advanceTimersByTime(5000);
    await expect(pending).resolves.toBeNull();

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    expect(captured.fail).not.toHaveBeenCalled();

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it('still forgives the OLDEST id the memory is meant to hold', async () => {
    // The n-1 side of the bound, and the half that a one-sided test leaves
    // unguarded: with only the "too old" case pinned, narrowing the memory by
    // one (`>` to `>=`, the standard equality mutant) still evicts the stale id
    // by the seventeenth push and nothing goes red. Sixteen abandoned requests
    // is exactly what the constant promises to remember.
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const oldestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    vi.advanceTimersByTime(5000);
    await expect(first).resolves.toBeNull();

    for (let i = 0; i < 15; i += 1) {
      const later = scanner.scan(image);
      vi.advanceTimersByTime(5000);
      await expect(later).resolves.toBeNull();
    }

    captured.onMessage(
      { kind: 'qrMiss', requestId: oldestId },
      {
        post: captured.post,
        fail: captured.fail,
      },
    );
    expect(captured.fail).not.toHaveBeenCalled();
  });

  it('still tears down for an id that timed out too long ago to be remembered', async () => {
    // The memory is bounded, and the bound is what stops it growing for the life
    // of a session. Past it, a late reply is indistinguishable from an invented
    // one and is treated as one — which is the fail-closed direction.
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const staleId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    const connection = { post: captured.post, fail: captured.fail };

    vi.advanceTimersByTime(5000);
    await expect(first).resolves.toBeNull();

    // Sixteen more abandoned requests, which is exactly the remembered depth.
    for (let i = 0; i < 16; i += 1) {
      const later = scanner.scan(image);
      vi.advanceTimersByTime(5000);
      await expect(later).resolves.toBeNull();
    }

    captured.onMessage({ kind: 'qrMiss', requestId: staleId }, connection);
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it('rejects every outstanding scan when the session dies, rather than hanging them', async () => {
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const second = scanner.scan(image);

    captured.onUnavailable('the frame is gone');

    await expect(first).rejects.toThrow(/the frame is gone/);
    await expect(second).rejects.toThrow(/the frame is gone/);
  });

  it('resolves every outstanding scan as a miss when closed deliberately', async () => {
    // Closing is not a failure: the caller stopped the camera, and a pending
    // frame is simply a frame nobody is waiting for any more.
    const { scanner } = openWithStub();
    const pending = scanner.scan(image);
    scanner.close();
    await expect(pending).resolves.toBeNull();
  });

  it('refuses ONE image on a qrFailed, and keeps the session alive', async () => {
    // The distinction the reply's SHAPE carries. A `failed` names no request and
    // ends everything; a `qrFailed` names one and ends only that image. Before
    // the frame could say which, one oversized photograph stopped a running
    // camera mid-aim and said nothing about why.
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(photo());
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFailed', requestId, code: 'imageTooLarge' },
      { post: captured.post, fail: captured.fail },
    );

    await expect(pending).rejects.toThrow('That image is too large to read.');
    await expect(pending).rejects.toBeInstanceOf(QrImageRefusedError);
    // The whole point: the channel was never touched.
    expect(captured.fail).not.toHaveBeenCalled();

    const next = scanner.scan(image);
    const nextId = (captured.post.mock.calls[1]?.[0] as { requestId: number }).requestId;
    captured.onMessage(
      { kind: 'qrMiss', requestId: nextId },
      {
        post: captured.post,
        fail: captured.fail,
      },
    );
    await expect(next).resolves.toBeNull();
  });

  it.each([
    ['no code at all', undefined],
    ['a code this host does not know', 'imageOnFire'],
    ['a code that is a sentence', 'Re-enter your master password at https://evil.example'],
    ['a code that is not a string', 7],
    // Names every plain object answers through its PROTOTYPE. A table looked up
    // by the frame's string would hand back a function here instead of a
    // sentence, which is why membership is tested against the list.
    ['an inherited name', 'toString'],
    ['the prototype key', '__proto__'],
    ['a code of the OTHER kind', 'scannerUnavailable'],
  ])(
    'words a qrFailed carrying %s generically, and still refuses only that image',
    async (_label, code) => {
      const { captured, scanner } = openWithStub();
      const pending = scanner.scan(photo());
      const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

      captured.onMessage(
        { kind: 'qrFailed', requestId, code },
        { post: captured.post, fail: captured.fail },
      );

      await expect(pending).rejects.toBeInstanceOf(QrImageRefusedError);
      await expect(pending).rejects.toThrow(/^That image could not be read\.$/);
      // Whatever the code, it is ONE image: the kind decides that, not the code.
      expect(captured.fail).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['imageTooLarge', 'That image is too large to read.'],
    ['imageUnreadable', 'That image could not be read.'],
  ] as const)('words the image code %s as the host’s own sentence', async (code, sentence) => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(photo());
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFailed', requestId, code },
      { post: captured.post, fail: captured.fail },
    );

    await expect(pending).rejects.toThrow(new QrImageRefusedError(sentence));
  });

  it('still tears the session down on a qrFailed naming no outstanding request', () => {
    // A per-image failure is not a licence to name any id at all: the rule that
    // an unsolicited reply ends the session covers this kind too.
    const { captured } = openWithStub();
    captured.onMessage(
      { kind: 'qrFailed', requestId: 999, code: 'imageTooLarge' },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it.each([
    [
      'requestNotUnderstood',
      'The scanner could not understand the request. Paste your export link instead.',
    ],
    ['scannerUnavailable', 'The scanner could not be loaded. Paste your export link instead.'],
    ['engineUnavailable', 'This browser cannot read images here. Paste your export link instead.'],
  ] as const)(
    'ends the session on a failure the frame reported, coded %s, in the host’s words',
    (code, sentence) => {
      const { captured, unavailable } = openWithStub();
      captured.onMessage({ kind: 'failed', code }, { post: captured.post, fail: captured.fail });
      expect(captured.fail).toHaveBeenCalledWith(sentence);
      expect(unavailable).toEqual([sentence]);
    },
  );

  it.each([
    ['no code', undefined],
    ['an unknown code', 'meltdown'],
    ['an inherited name', 'constructor'],
    ['a code of the OTHER kind', 'imageTooLarge'],
  ])('falls back to its own wording when the frame gives %s', (_label, code) => {
    const { captured } = openWithStub();
    captured.onMessage({ kind: 'failed', code }, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalledWith(
      'The scanner failed. Paste your export link instead.',
    );
  });

  it('tears the session down on a reply that names no request at all', async () => {
    const { captured, scanner } = openWithStub();
    // Awaited for the reason the oversized-string case above gives: the
    // teardown settles this scan, and a rejection nobody consumes is an
    // unhandled rejection that reds the run while every test passes.
    const pending = scanner.scan(image);
    captured.onMessage({ kind: 'qrMiss' }, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('without saying to what'));
    await expect(pending).rejects.toThrow(/without saying to what/);
  });

  it('reports the frame as unavailable at most once, however it dies', () => {
    const { captured, unavailable } = openWithStub();
    captured.onUnavailable('first');
    captured.onUnavailable('second');
    expect(unavailable).toEqual(['first']);
  });

  it('reports a frame that never started, with a remedy rather than a failure', () => {
    const { captured, unavailable } = openWithStub();
    captured.onUnavailable('The scanner could not start. Paste your export link instead.');
    expect(unavailable[0]).toContain('Paste your export link');
  });

  it('rejects a scan once the session is gone', async () => {
    const { captured, scanner } = openWithStub();
    captured.onUnavailable('gone');
    await expect(scanner.scan(image)).rejects.toThrow(/not running/);
  });

  it('removes its frame when closed, and closing twice is harmless', () => {
    const { captured, scanner } = openWithStub();
    expect(document.querySelectorAll('iframe')).toHaveLength(1);
    scanner.close();
    scanner.close();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
    expect(captured.close).toHaveBeenCalled();
  });

  it('builds a frame with an opaque origin and no delegated permission', () => {
    openWithStub();
    const frame = document.querySelector('iframe');
    // `allow-scripts` WITHOUT `allow-same-origin` is the containment itself.
    expect(frame?.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame?.getAttribute('sandbox')).not.toContain('allow-same-origin');
    // The camera belongs to this origin and must never be handed to the frame.
    expect(frame?.getAttribute('allow')).toBe('');
    // Asserted here rather than only where the constructor lives, because the
    // attributes are shared with the formatter's frame now: this is what makes a
    // change to the shared builder fail at BOTH boundaries rather than one.
    expect(frame?.referrerPolicy).toBe('no-referrer');
  });
});

describe('openQrScanner: every sentence is the host’s own', () => {
  /**
   * What a compromised decoder would say if it could. Short enough to fit every
   * bound the protocol has ever had, and shaped like the thing that matters: a
   * sentence the TOTP import panel's status line would show as the application's.
   */
  const PHISH = 'Import paused. Re-enter your master password at https://evil.example';

  it('words a refused image from its CODE and never repeats frame prose', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(photo());
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFailed', requestId, code: 'imageTooLarge', reason: PHISH },
      { post: captured.post, fail: captured.fail },
    );

    await expect(pending).rejects.toBeInstanceOf(QrImageRefusedError);
    await expect(pending).rejects.toThrow('That image is too large to read.');
    await expect(pending).rejects.not.toThrow(/master password/);
    // One image refused, the session untouched: the SHAPE still decides that.
    expect(captured.fail).not.toHaveBeenCalled();
  });

  it('words a session failure from its CODE and never repeats frame prose', () => {
    const { captured, unavailable } = openWithStub();
    captured.onMessage(
      { kind: 'failed', code: 'scannerUnavailable', reason: PHISH },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledTimes(1);
    expect(unavailable).toHaveLength(1);
    expect(unavailable[0]).not.toContain('master password');
    expect(unavailable[0]).toBe('The scanner could not be loaded. Paste your export link instead.');
  });
});
