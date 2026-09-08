/**
 * `n` spelled the way English spells it, for the range this repository's
 * documentation counts in.
 *
 * ONE definition, because two suites pin prose against it and a second copy is
 * the very failure both of them exist to catch. `docs-sync.test.ts` uses it for
 * the accessibility gate's scanned-view count (21 sentences across 8 files) and
 * `gate-surface.test.ts` for the number of core modules the mutation gate holds
 * to their own scores.
 *
 * Spelled-out words rather than digits because that is how those sentences are
 * written: rewriting eight documents to suit a regular expression is the wrong
 * way round. Indexed by the number itself, so `NUMBER_WORDS[7]` is `'seven'` and
 * an out-of-range count comes back `undefined` — which every caller asserts
 * against before comparing, so a count that has grown past this table fails
 * loudly instead of comparing `undefined` with `undefined`.
 */
export const NUMBER_WORDS = [
  'zero',
  'one',
  'two',
  'three',
  'four',
  'five',
  'six',
  'seven',
  'eight',
  'nine',
  'ten',
  'eleven',
  'twelve',
  'thirteen',
  'fourteen',
  'fifteen',
  'sixteen',
  'seventeen',
  'eighteen',
  'nineteen',
  'twenty',
  'twenty-one',
  'twenty-two',
  'twenty-three',
  'twenty-four',
  'twenty-five',
  'twenty-six',
  'twenty-seven',
  'twenty-eight',
  'twenty-nine',
  'thirty',
  'thirty-one',
  'thirty-two',
  'thirty-three',
  'thirty-four',
  'thirty-five',
  'thirty-six',
  'thirty-seven',
  'thirty-eight',
  'thirty-nine',
  'forty',
] as const;
