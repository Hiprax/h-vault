/**
 * The DOM matchers are registered on Vitest's `expect` AND typed on it.
 *
 * Two halves, and each one fails a different gate. The runtime half fails `npm
 * test` if `tests/setup.ts` stops registering the matchers, which on its own
 * would be loud anyway. The TYPE half is the one worth a file: `expectTypeOf` is
 * a no-op at runtime and checks only under `tsc -p tsconfig.test.json`, so it is
 * the `type-check` gate that goes red when the matchers stop being typed. That
 * is exactly what the next Vitest major does: Vitest 5 stops reading the global
 * `jest.Matchers` interface that `@testing-library/jest-dom` augments, and every
 * matcher in the client suite became a missing property (measured: 2,376
 * errors). Vitest is held at 4 for a different reason (see PLAN §1.9), and this
 * file is what will say, the day that hold is lifted, that the typing needs
 * redoing too.
 *
 * Asymmetric use (`expect.not.toHaveTextContent(...)`) is deliberately NOT
 * asserted: the package's `jest.Matchers` augmentation does not reach Vitest 4's
 * `AsymmetricMatchersContaining`, so that form was never typed here, and
 * nothing in the suite uses it.
 */
import { describe, it, expect, expectTypeOf } from 'vitest';

describe('jest-dom matchers under Vitest', () => {
  it('are callable on expect(el), and report a real failure rather than passing vacuously', () => {
    const attached = document.createElement('div');
    attached.textContent = 'present';
    document.body.append(attached);
    const detached = document.createElement('div');

    try {
      expect(attached).toBeInTheDocument();
      expect(attached).toHaveTextContent('present');
      expect(detached).not.toBeInTheDocument();
      // The negative: a matcher that was merely declared, and never registered,
      // would throw `toBeInTheDocument is not a function` here instead.
      expect(() => {
        expect(detached).toBeInTheDocument();
      }).toThrow(/element could not be found in the document/);
    } finally {
      attached.remove();
    }
  });

  it('are typed on expect(el) and on expect(el).not', () => {
    const el = document.createElement('button');

    expectTypeOf(expect(el)).toHaveProperty('toBeInTheDocument');
    expectTypeOf(expect(el)).toHaveProperty('toHaveAccessibleName');
    expectTypeOf(expect(el).not).toHaveProperty('toBeInTheDocument');

    // The matcher returns the assertion's own `R`, so a synchronous assertion is
    // `void`, not the received element (which is what passing `T` as the return
    // slot, as the package's own Vitest entry does, would produce).
    expectTypeOf(expect(el).toBeInTheDocument).returns.toBeVoid();

    // Nothing is invented: a misspelling is still a type error, so the
    // augmentation did not degrade `expect` into an index signature.
    expectTypeOf(expect(el)).not.toHaveProperty('toBeInTheDokument');
  });

  it('keep the expected-text argument narrow instead of widening it to the received type', () => {
    const el = document.createElement('button');

    expectTypeOf(expect(el).toHaveAccessibleName)
      .parameter(0)
      .toEqualTypeOf<string | RegExp | undefined>();
  });
});
