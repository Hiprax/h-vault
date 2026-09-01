import type {
  SandboxFrameMessage,
  SandboxRenderRequest,
  SandboxTheme,
  SandboxTransformFailedMessage,
  SandboxTransformRequest,
} from '@hvault/shared';

/**
 * The sandbox's own message validator — hand-rolled, and deliberately so.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT ZOD
 * ---------------------------------------------------------------------------
 *
 * The application validates with Zod everywhere, and this file could have
 * shared a schema with it. It must not. The sandbox is built as its own Rollup
 * graph, and `manualChunks` puts `zod` in `vendor-core` next to AXIOS — so a
 * shared runtime schema would put an HTTP client inside a document whose whole
 * premise is that it can issue no request of any kind. It would do so silently:
 * the preview would still work, and no gate would report it.
 *
 * What is actually needed here is smaller than a schema library, and saying so
 * is not a cost argument. The frame accepts exactly TWO message shapes — render
 * a document, and transform one — and it does not need to know the list of valid
 * render modes at runtime: it `switch`es on the mode and its `default` branch is
 * "no renderer for this", which is the same answer an unknown mode deserves. So
 * the validation reduces to a handful of `typeof` checks over a few fields.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THIS FILE ENFORCES
 * ---------------------------------------------------------------------------
 *
 * NOTHING that arrives on the port is touched before it has been through here,
 * and anything that does not parse is REFUSED rather than coerced. The frame is
 * the least trusted thing in this system and it should behave as though the
 * embedder might be hostile too: a malformed message means a bug or an attack,
 * and either way the right answer is to render nothing rather than to guess.
 */

/** Narrow an unknown to an indexable object without asserting anything about it. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isTheme(value: unknown): value is SandboxTheme {
  return value === 'light' || value === 'dark';
}

/**
 * Is this a real `ArrayBuffer`, in ANY realm, that nothing can imitate?
 *
 * `value instanceof ArrayBuffer` is the obvious spelling and it is WRONG for
 * this input, because the input crosses a realm by definition: it is a
 * structured clone posted from another document. `instanceof` compares against
 * THIS realm's constructor, so a buffer materialised anywhere else fails it —
 * measured under jsdom, where the frame refused a perfectly good buffer and
 * reported "the preview request was not understood".
 *
 * `Object.prototype.toString` would fix the realm problem and introduce a worse
 * one: `Symbol.toStringTag` makes that answer forgeable by any object.
 *
 * `new DataView(x)` throws a `TypeError` unless `x` carries an ArrayBuffer
 * INTERNAL SLOT. The slot is what identifies the object, so the check is
 * realm-independent and cannot be faked by any property; and unlike borrowing
 * `ArrayBuffer.prototype.byteLength`'s getter it detaches no method, which is
 * both a `this`-scoping hazard and a lint error here.
 *
 * A `SharedArrayBuffer` would also pass. That is not reachable — cross-origin
 * isolation is off, so the constructor does not exist and a structured clone
 * cannot carry one — and it would be harmless if it were, since every consumer
 * downstream (`TextDecoder`, `Uint8Array`, `Blob`) accepts one.
 */
function isArrayBuffer(value: unknown): value is ArrayBuffer {
  try {
    new DataView(value as ArrayBuffer);
    return true;
  } catch {
    return false;
  }
}

/**
 * Parse a host-to-frame message, or return `null`.
 *
 * `bytes` must be a real `ArrayBuffer`, checked by its internal slot rather than
 * by duck-typing a `byteLength`: the value is about to be handed to a decoder
 * and to `Blob`/`Uint8Array` constructors that behave differently — or throw —
 * for a typed-array view or a plain object wearing the same shape. See
 * {@link isArrayBuffer} for why `instanceof` is the wrong spelling here.
 *
 * `mode` is checked only for being a string. Validating it against the list of
 * modes would mean importing that list at runtime, and it would buy nothing: an
 * unrecognised mode and an unsupported one take the same branch.
 */
export function parseRenderRequest(data: unknown): SandboxRenderRequest | null {
  if (!isRecord(data)) return null;
  if (data.kind !== 'render') return null;
  const { mode, ext, theme, bytes } = data;
  if (typeof mode !== 'string' || mode === '') return null;
  if (typeof ext !== 'string') return null;
  if (!isTheme(theme)) return null;
  if (!isArrayBuffer(bytes)) return null;
  return { kind: 'render', mode: mode as SandboxRenderRequest['mode'], ext, theme, bytes };
}

/**
 * Parse a host-to-frame TRANSFORM message, or return `null`.
 *
 * The same shape of validation as {@link parseRenderRequest} and one extra rule:
 * a request that asks for NEITHER transform is refused. Nothing in the
 * application produces one — the panel runs a transform only when a checkbox is
 * ticked — so it is a bug in the host or a message from somebody else, and
 * either way answering "here is your text back, unchanged" would attach a
 * provenance record describing a transform that never happened.
 *
 * `ext` may legitimately be empty, exactly as it may in a render request: the
 * engine answers "this file type cannot be formatted" for it, which is the same
 * answer an unknown extension deserves and is why this validator does not carry
 * the list of formattable types.
 */
export function parseTransformRequest(data: unknown): SandboxTransformRequest | null {
  if (!isRecord(data)) return null;
  if (data.kind !== 'transform') return null;
  const { text, ext, format, repair } = data;
  if (typeof text !== 'string') return null;
  if (typeof ext !== 'string') return null;
  if (typeof format !== 'boolean' || typeof repair !== 'boolean') return null;
  if (!format && !repair) return null;
  return { kind: 'transform', text, ext, format, repair };
}

/**
 * The frame's replies, built here so every one of them is well-formed by
 * construction and the call sites cannot invent a shape of their own.
 *
 * The render replies and the transform replies are DISJOINT sets and each host
 * accepts only its own, which is why they are listed separately rather than
 * merged: a frame answering a render request with a transform result is a frame
 * that has gone wrong, and the host that asked tears it down.
 */
export const frameMessage = {
  rendered: (): SandboxFrameMessage => ({ kind: 'rendered' }),
  failed: (reason: string): SandboxFrameMessage => ({ kind: 'failed', reason }),
  link: (href: string): SandboxFrameMessage => ({ kind: 'link', href }),
  // There is deliberately NO `transformed` builder. The engine returns a
  // complete, discriminated reply of its own and the frame forwards it
  // untouched; a builder here would exist only to be a second place that shape
  // is written down, and an unused one at that.
  transformFailed: (
    failure: Omit<SandboxTransformFailedMessage, 'kind'>,
  ): SandboxTransformFailedMessage => ({ kind: 'transformFailed', ...failure }),
};
