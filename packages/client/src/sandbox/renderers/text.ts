/**
 * The plain-text renderer — the first one, and the one that proves the pipe.
 *
 * It is the REAL renderer for the `text` mode, not a stub: 19.1 EXTENDS it with
 * encoding detection, line truncation and the code and tabular modes rather than
 * replacing it.
 *
 * ---------------------------------------------------------------------------
 * THE ONE RULE EVERY RENDERER IN THIS DIRECTORY FOLLOWS
 * ---------------------------------------------------------------------------
 *
 * It returns DOM NODES, and the text arrives as a TEXT NODE. Nothing here builds
 * a markup string, and nothing here is ever assigned to `innerHTML`. That is not
 * caution about this particular format — a `.txt` file cannot be "malicious
 * markup" until something parses it as markup, and the point is that nothing
 * ever does. Serialising a tree back to a string and re-parsing it is the
 * mutation-XSS shape, and the way to not have it is to never produce a string in
 * the first place.
 *
 * The isolation around this document is defence in depth for the renderers that
 * genuinely must parse (markdown, HTML, the highlighter). This one earns its
 * safety structurally, and the pattern is set here so the later ones inherit it.
 */

/**
 * Decode the document's bytes as UTF-8 and return them as a single text node
 * inside a `<pre>`.
 *
 * `fatal: false` is deliberate. A text preview of a file that is ALMOST UTF-8 —
 * one truncated multi-byte sequence, one byte of a different encoding — should
 * show the file with a replacement character where the damage is, not refuse
 * outright: the user is looking at it precisely because they want to know what
 * is in it. A file that is not text at all is caught earlier, by the magic-byte
 * check against its extension's claim (19.3), which is where a refusal belongs.
 *
 * `<pre>` rather than a `<div>` with CSS: the whitespace semantics of a text file
 * are part of its content, and putting them in a stylesheet makes them something
 * a missing stylesheet can lose.
 */
export function renderText(doc: Document, bytes: ArrayBuffer): HTMLElement {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const pre = doc.createElement('pre');
  pre.className = 'hv-text';
  // `textContent` on a fresh element creates exactly one text node. Assigning it
  // is the whole of the rendering, and the reason this renderer cannot be made
  // to execute anything.
  pre.textContent = text;
  return pre;
}
