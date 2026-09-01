import { documentShell, el, notice } from '../dom';

/**
 * Images, from a blob URL this document mints itself.
 *
 * ---------------------------------------------------------------------------
 * THREE THINGS THAT LOOK LIKE DETAIL AND ARE NOT
 * ---------------------------------------------------------------------------
 *
 * 1. **The blob URL is minted HERE, never by the application.** A blob URL is
 *    scoped to the origin that created it, and this document's origin is
 *    opaque, so a URL made on the app side simply would not resolve. The bytes
 *    cross the channel; the URL is made on this side of it.
 *
 * 2. **Nothing fetches anything.** The policy this document is served under sets
 *    `connect-src 'none'`, which blocks `fetch()` and `XMLHttpRequest` against a
 *    `blob:` URL exactly as it blocks them against the network. The bytes are
 *    read from the `ArrayBuffer` that arrived on the port, and the URL exists
 *    only to be put in a `src` attribute — which `img-src` governs, and which
 *    does not involve `connect-src` at all.
 *
 * 3. **SVG goes through `<img>` and is NEVER inlined.** An `<img>` renders an
 *    SVG's graphics and does not run its scripts; the same bytes inserted into
 *    the document as markup would run everything they contain. That is the whole
 *    difference between a picture and a program, and it is one attribute wide.
 *
 * The URL is deliberately NOT revoked. A revoked URL breaks a re-decode the
 * browser may do at any time — printing, a device-pixel-ratio change, a
 * scroll-driven repaint — and the document that holds it is destroyed the moment
 * the reader looks at anything else, because the application creates one frame
 * per document and throws it away. The blob's memory is reclaimed with it, and
 * `MAX_PREVIEW_BYTES` is sized for exactly that: a small multiple of the file.
 */

/**
 * Extension to the media type its blob is labelled with.
 *
 * This is the ONLY type information the renderer has. The stored metadata's
 * `mime` field is never sent to this document: it is a string the uploading
 * browser guessed, it travels beside bytes that must be judged on their own
 * evidence, and the sniffer has already compared those bytes with what the
 * extension claims. Deriving it here keeps one source of truth for the claim,
 * and it is a claim the browser is free to reject.
 */
export const IMAGE_MEDIA_TYPES: Readonly<Record<string, string>> = Object.freeze({
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  bmp: 'image/bmp',
  ico: 'image/x-icon',
  svg: 'image/svg+xml',
});

/** What the reader is told when the bytes are not an image the browser can decode. */
export const IMAGE_UNDECODABLE_NOTICE =
  'This file could not be displayed as an image. It may be damaged, or it may not be the kind of image its name says it is. Download it to open it with something else.';

export function renderImage(doc: Document, bytes: ArrayBuffer, ext: string): HTMLElement {
  const shell = documentShell(doc, 'image');
  const type = IMAGE_MEDIA_TYPES[ext] ?? 'application/octet-stream';
  const url = URL.createObjectURL(new Blob([bytes], { type }));

  const image = el(doc, 'img', 'hv-image');
  // A generic, non-empty alternative text. The document's NAME is the obvious
  // thing to put here and this document does not have it — the protocol sends
  // the bytes, the mode, the extension and the theme, and nothing else — so the
  // honest answer names the medium rather than inventing a description. An
  // EMPTY alt would be worse than generic: it declares the image decorative,
  // and this image is the entire document.
  image.alt = 'The stored image';
  image.decoding = 'async';
  image.addEventListener('error', () => {
    // A decode failure is the one outcome an `<img>` reports and a sniffer
    // cannot predict: a file with a correct signature and a corrupt body passes
    // every byte check and still will not render. Replacing the element is what
    // stops the reader staring at a broken-image glyph with no explanation.
    shell.replaceChildren(notice(doc, IMAGE_UNDECODABLE_NOTICE));
  });
  image.src = url;

  shell.append(image);
  return shell;
}
