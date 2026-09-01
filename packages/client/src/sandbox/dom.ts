/**
 * The handful of elements every renderer in this document builds, in one place.
 *
 * Two reasons, and the second is the load-bearing one.
 *
 * The tidy reason: six renderers each need a wrapper, a notice and (three of
 * them) a view toggle, and six copies of a `createElement` sequence is exactly
 * the near-identical block `.jscpd.json`'s duplication counters are ratcheted
 * downward to discourage.
 *
 * The reason that matters: these helpers are the ONE shape in which this
 * document turns a document's own bytes into DOM. Every one of them takes TEXT
 * and assigns it with `textContent`, and none of them accepts markup. Nothing
 * here builds a string of HTML, and nothing here touches `innerHTML` — not as a
 * convention a reviewer has to notice, but because there is no function that
 * would. A renderer that wanted to inject markup would have to stop using this
 * module, which is a visible edit rather than a silent one.
 *
 * (The markdown and HTML renderers are the deliberate exception, and they still
 * do not violate the rule: they turn a SANITIZED hast tree into DOM NODES with
 * `hast-util-to-dom`, never into a string that is re-parsed. Serialising and
 * re-parsing is the mutation-XSS shape, and the way not to have it is to never
 * produce the string.)
 */

/** Create an element with an optional class, and nothing else. */
export function el<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className?: string,
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  if (className !== undefined) node.className = className;
  return node;
}

/**
 * The wrapper every renderer returns, carrying the mode as a class so the
 * stylesheet can lay each one out without a renderer knowing any CSS.
 */
export function documentShell(doc: Document, mode: string): HTMLDivElement {
  const shell = el(doc, 'div', `hv-doc hv-doc-${mode}`);
  return shell;
}

/**
 * A sentence shown above the document itself: an encoding warning, a truncation
 * notice, the disabled-remote-content banner.
 *
 * `role="status"` rather than `role="alert"`: these are conditions of the
 * PREVIEW, not errors, and an alert interrupts a screen reader mid-sentence for
 * something the reader did not ask about. The text is always a constant from
 * this codebase — never a fragment of the document — so a notice can never be a
 * channel for the file to say something in the interface's own voice.
 */
export function notice(doc: Document, text: string): HTMLParagraphElement {
  const node = el(doc, 'p', 'hv-notice');
  node.setAttribute('role', 'status');
  node.textContent = text;
  return node;
}

/**
 * A two-state view toggle: the tabular view of a CSV, the pretty-printed view of
 * a JSON document, and the original text behind each.
 *
 * A real `<button>` with `aria-pressed`, because this is a control and the
 * people who most need to know which view they are looking at are the ones a
 * styled `<div>` tells nothing.
 *
 * It lives INSIDE the frame, and that is not a hole in the rule that the app
 * draws the chrome. What the app owns outside the rectangle is everything a
 * renderer could FORGE to mislead someone: the document's name, and the button
 * that downloads it. A switch between two renderings of the same bytes has
 * nothing to forge — it is part of the rendering, and moving it out would mean a
 * protocol message per format for no gain in what the isolation protects.
 */
export function viewToggle(
  doc: Document,
  labels: readonly [string, string],
  onToggle: (showingSecond: boolean) => void,
): HTMLDivElement {
  const bar = el(doc, 'div', 'hv-toolbar');
  const button = el(doc, 'button', 'hv-toggle');
  button.type = 'button';
  let showingSecond = false;
  const paint = (): void => {
    button.textContent = showingSecond ? labels[0] : labels[1];
    button.setAttribute('aria-pressed', showingSecond ? 'true' : 'false');
  };
  button.addEventListener('click', () => {
    showingSecond = !showingSecond;
    paint();
    onToggle(showingSecond);
  });
  paint();
  bar.append(button);
  return bar;
}
