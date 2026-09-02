import { extensionTable } from '@hvault/shared';
import { documentShell, el, notice } from '../dom';

/**
 * Audio and video, from a blob URL this document mints itself.
 *
 * The same three rules as `image.ts`, for the same reasons: the URL is created
 * on THIS side of the channel because a blob URL made in the application's
 * origin would not resolve in an opaque one; nothing is ever fetched, because
 * `connect-src 'none'` forbids it even for a `blob:` URL, so the bytes come from
 * the `ArrayBuffer` that arrived on the port; and the URL is not revoked,
 * because the element re-reads it on every seek and the document is destroyed
 * per preview anyway.
 *
 * `controls` is what makes this a preview rather than an autoplaying surprise.
 * Nothing here sets `autoplay`: a document is opened to be looked at, and a
 * recording that starts playing by itself in a password manager is the last
 * thing anyone wants.
 */

/** Extension to the element that plays it and the media type it is labelled with. */
export const MEDIA_TYPES: Readonly<
  Record<string, { readonly kind: 'audio' | 'video'; readonly type: string }>
> = extensionTable({
  mp4: { kind: 'video', type: 'video/mp4' },
  m4v: { kind: 'video', type: 'video/mp4' },
  webm: { kind: 'video', type: 'video/webm' },
  ogv: { kind: 'video', type: 'video/ogg' },
  mp3: { kind: 'audio', type: 'audio/mpeg' },
  m4a: { kind: 'audio', type: 'audio/mp4' },
  aac: { kind: 'audio', type: 'audio/aac' },
  wav: { kind: 'audio', type: 'audio/wav' },
  flac: { kind: 'audio', type: 'audio/flac' },
  opus: { kind: 'audio', type: 'audio/ogg' },
  // `.ogg` is ambiguous by design of the container — it may hold Vorbis audio
  // or Theora video — and audio is what it holds in practice. `.ogv` is the
  // extension a video-carrying Ogg is supposed to use, and it is handled
  // above.
  ogg: { kind: 'audio', type: 'audio/ogg' },
  oga: { kind: 'audio', type: 'audio/ogg' },
});

/** What the reader is told when the browser cannot play the file. */
export const MEDIA_UNPLAYABLE_NOTICE =
  'This browser could not play this file. The recording may be damaged, or it may use a codec this browser does not carry. Download it to open it with something else.';

export function renderMedia(doc: Document, bytes: ArrayBuffer, ext: string): HTMLElement {
  const shell = documentShell(doc, 'media');
  const descriptor = MEDIA_TYPES[ext];
  if (descriptor === undefined) {
    // Reachable only if `PREVIEW_MODES` gains a `media` extension this table was
    // not taught about, which is precisely the drift a silent `<video>` with an
    // `application/octet-stream` blob would hide. `sandbox-renderers.test.ts`
    // asserts the two agree, so this branch is the runtime half of a check the
    // suite makes statically.
    shell.append(notice(doc, MEDIA_UNPLAYABLE_NOTICE));
    return shell;
  }

  const url = URL.createObjectURL(new Blob([bytes], { type: descriptor.type }));
  const player = el(doc, descriptor.kind, 'hv-media');
  player.controls = true;
  player.preload = 'metadata';
  player.addEventListener('error', () => {
    shell.replaceChildren(notice(doc, MEDIA_UNPLAYABLE_NOTICE));
  });
  player.src = url;

  shell.append(player);
  return shell;
}
