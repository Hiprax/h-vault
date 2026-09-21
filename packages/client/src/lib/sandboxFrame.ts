/**
 * The containment attributes of an off-screen sandbox frame — ONE definition.
 *
 * Two drivers create a frame imperatively rather than rendering one: the
 * document formatter and the QR scanner. They ask for different work and accept
 * different replies, but the attributes below are not theirs to choose. Those
 * attributes ARE the boundary, so they are written once here and the drivers
 * supply nothing but a title.
 *
 * Why each one is present:
 *
 *  - `sandbox="allow-scripts"` WITHOUT `allow-same-origin` is what gives the
 *    document an OPAQUE ORIGIN. The two must never appear together: with both,
 *    the frame would share this origin and could read the vault key's page,
 *    which is the whole reason third-party parsers run in here at all.
 *  - `referrerPolicy="no-referrer"` keeps the surrounding URL out of any request
 *    the document makes.
 *  - `allow=""` delegates NO permission. That matters most to the scanner: the
 *    camera is granted to the application's origin, and this is what stops the
 *    grant being handed on to the code that reads its frames.
 *  - `display: none` rather than leaving the element unattached, because an
 *    unattached iframe never loads a document at all and the handshake would
 *    simply time out.
 *
 * A third frame, the document viewer, is rendered declaratively by React and
 * carries the same attributes in JSX. It cannot share this function, so each of
 * the three drivers asserts its own frame's attributes through its own tests:
 * the point of those assertions is the attribute reaching the DOM, which a
 * shared constructor would not prove on its own.
 *
 * This module deliberately does not tear anything down. Whoever attached the
 * element removes it, exactly as `connectSandbox` documents.
 */
export function createHiddenSandboxFrame(title: string): HTMLIFrameElement {
  const frame = document.createElement('iframe');
  frame.src = '/sandbox.html';
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.referrerPolicy = 'no-referrer';
  frame.setAttribute('allow', '');
  frame.setAttribute('aria-hidden', 'true');
  frame.title = title;
  frame.style.display = 'none';
  return frame;
}
