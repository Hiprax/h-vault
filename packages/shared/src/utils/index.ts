import {
  PREVIEW_MODES,
  REPAIRABLE_TRANSFORM_SYNTAXES,
  TRANSFORM_SYNTAXES,
  type PreviewMode,
  type TransformSyntax,
} from '../constants/index.js';

export function maskEmail(email: string): string {
  const atIndex = email.lastIndexOf('@');
  if (atIndex <= 0) return '***';
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex);
  const first = local[0] ?? '';
  const last = local[local.length - 1] ?? '';
  return local.length <= 1 ? first + '***' + domain : first + '***' + last + domain;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  // Clamp the low end to 0. For 0 < bytes < 1 the logarithm is negative and
  // Math.floor rounds toward -Infinity, so the exponent would go negative:
  // Math.pow(1024, -1) then DIVIDES by 1/1024, i.e. multiplies the value by
  // 1024, and formatBytes(0.5) reported "512 B". A sufficiently small value
  // (Number.MIN_VALUE) underflowed the divisor to 0 and reported "Infinity B".
  const i = Math.min(Math.max(Math.floor(Math.log(bytes) / Math.log(k)), 0), sizes.length - 1);
  const size = sizes[i] ?? 'B';
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${size}`;
}

/**
 * If the URI has no recognized protocol, prepend https://.
 * Preserves empty strings and URIs that already have a scheme.
 */
export function normalizeUri(uri: string): string {
  if (!uri) return uri;
  if (/^(https?:|mailto:)/i.test(uri)) return uri;
  // Don't auto-prefix regex patterns or URIs with other schemes
  if (/^[a-z][a-z0-9+.-]*:/i.test(uri)) return uri;
  // Protocol-relative URIs: //example.com → https://example.com
  if (uri.startsWith('//')) return `https:${uri}`;
  return `https://${uri}`;
}

export function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  // Fallback for environments without crypto.randomUUID
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  throw new Error('Cryptographic random API is unavailable. Cannot generate secure IDs.');
}

/**
 * The extension a document's name claims: the lowercased segment after the LAST
 * dot.
 *
 * ONE definition, in the shared package, because three places have to agree on it
 * and two of them cannot see each other: the browser derives `ext` for the sealed
 * metadata blob and checks it against the operator's advisory allowlist, and the
 * isolated render document keys its renderer off the same value. That document is
 * built as its own module graph and shares nothing with the application, so a copy
 * of this rule living on the app side would be a second copy by construction — and
 * the day someone teaches one of them about `.tar.gz`, the other keeps the old
 * answer.
 *
 * A name with NO dot, and a name whose only dot is LEADING, has no extension:
 * `Dockerfile`, `Makefile`, `.bashrc` and `.env` all answer `''`. That is a
 * decision rather than an oversight — recognising those would need a second lookup
 * keyed by whole filename, which is a second source of truth for one question. A
 * name with several dots keys on the last segment alone (`archive.tar.gz` is
 * `gz`), because that is what every file dialog and every content-type table in
 * general use does.
 *
 * A name ending in a dot answers `''` as well, and deliberately WITHOUT a guard of
 * its own: the slice after the final dot is empty, which is already the right
 * answer. A `lastDot === name.length - 1` check would read as caution and be
 * incapable of changing any outcome — a branch no test could ever fail on.
 *
 * Lower-cased, so `.SH` and `.sh` are one type. Nothing else is normalised: the
 * caller decides what an unrecognised extension means, and a value returned here
 * is never trusted as a claim about what a file actually contains.
 */
export function documentExtension(name: string): string {
  const lastDot = name.lastIndexOf('.');
  // `<= 0` covers both "no dot at all" (-1) and "the only dot is leading" (0).
  if (lastDot <= 0) return '';
  return name.slice(lastDot + 1).toLowerCase();
}

/**
 * The render mode a decrypted document name resolves to.
 *
 * ONE definition of the rule, in the package both sides import, because the
 * question "is this previewable" is asked twice by two different programs: the
 * application asks it to decide whether to create a frame at all, and the
 * isolated sandbox document is told the answer so it can pick a renderer. Two
 * copies of the map would diverge the day someone teaches one of them about a
 * new extension, and the symptom would be an empty rectangle rather than an
 * error.
 *
 * Sits beside {@link documentExtension} rather than in `constants/`, because it
 * is the rule that CONSUMES the extension rule; the map itself
 * ({@link PREVIEW_MODES}) is the constant.
 *
 * Anything the map does not name resolves to `none`, which is a real answer the
 * interface renders ("download to view") rather than a missing one. A name with
 * no extension resolves to `none` for the same reason: `Dockerfile`, `Makefile`,
 * `.bashrc` and `.env` are download-only by the same deliberate rule that says
 * an extension is the segment after the LAST dot.
 */
export function previewModeForName(name: string): PreviewMode {
  const extension = documentExtension(name);
  if (extension === '') return 'none';
  return PREVIEW_MODES[extension] ?? 'none';
}

/**
 * The syntax a decrypted document name resolves to for the in-browser
 * transforms, or `null` when neither of them understands it.
 *
 * The counterpart of {@link previewModeForName}, and it answers `null` rather
 * than a `'none'`-style member for a reason the preview map does not share:
 * `none` is a real render mode with a real behaviour ("download to view"),
 * whereas "not formattable" is the ABSENCE of a transform, and modelling it as a
 * member would give every `switch` in the engine a branch that must not exist.
 * The application turns the `null` into the sentence it shows beside the
 * disabled checkbox; the engine never sees one, because the panel does not offer
 * the checkbox that would produce it.
 */
export function transformSyntaxForName(name: string): TransformSyntax | null {
  return transformSyntaxForExtension(documentExtension(name));
}

/**
 * The same question asked with an extension already in hand.
 *
 * Both spellings exist because the two callers hold different things: the
 * application holds the file's NAME, and the isolated document is told only the
 * EXTENSION — it is never sent the name, because a renderer that cannot know
 * what a file is called cannot leak it. One is defined in terms of the other so
 * the map is read in exactly one place.
 *
 * An empty extension answers `null` without consulting the map: a name with no
 * dot, and one whose only dot is leading, has no extension to look up.
 */
export function transformSyntaxForExtension(extension: string): TransformSyntax | null {
  if (extension === '') return null;
  return TRANSFORM_SYNTAXES[extension] ?? null;
}

/**
 * May the REPAIR checkbox be offered for this syntax?
 *
 * A function over the list rather than the list read directly at each call site,
 * because there are two call sites in two different programs — the panel that
 * offers the checkbox and the engine that runs the repair — and `includes` on a
 * shared array is exactly the kind of one-line rule that gets re-implemented
 * with an inverted condition.
 */
export function canRepairSyntax(syntax: TransformSyntax): boolean {
  return REPAIRABLE_TRANSFORM_SYNTAXES.includes(syntax);
}
