/**
 * Unbiased random integers from the platform CSPRNG. Dependency-free, with no
 * module-level state and no entropy pool.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 * ---------------------------------------------------------------------------
 *
 * Every random choice this application makes about a SECRET goes through here,
 * so that "is it biased" is a question about one small file rather than about
 * each call site. Before it, the only unbiased-integer helper in the repository
 * was a module-private function inside a React component, which meant the next
 * feature that needed one would have written its own.
 *
 * ---------------------------------------------------------------------------
 * MASKED REJECTION, AND WHY THE OBVIOUS SPELLING IS THE WRONG ONE
 * ---------------------------------------------------------------------------
 *
 * Rejection sampling over WHOLE BYTES is the intuitive design and it is badly
 * inefficient: drawing `ceil(bits/8)` bytes and rejecting anything `>= n`
 * accepts `n / 256^bytes`, which for the 130-bit bound this module's main caller
 * uses is about 0.8 per cent, roughly 124 attempts per password.
 *
 * Masking to EXACTLY the bound's bit length is what makes the loop cheap, and
 * the guarantee is arithmetic rather than empirical. `bits` is chosen as the
 * length of `n - 1` in binary, so `2^bits >= n > 2^(bits-1)`, and therefore
 * acceptance `= n / 2^bits > 1/2`. Expected iterations is under two for every
 * bound, and for a power of two the mask NEVER rejects, which is why picking a
 * word from the 2048-entry passphrase list costs exactly two bytes.
 *
 * ---------------------------------------------------------------------------
 * THREE THINGS THAT ARE DELIBERATELY ABSENT
 * ---------------------------------------------------------------------------
 *
 *  1. NO ENTROPY POOL. A buffer of unconsumed CSPRNG output would save at most a
 *     couple of dozen `getRandomValues` calls per passphrase and zero per
 *     password (the generator draws exactly once), in exchange for keeping
 *     unconsumed randomness on the JS heap across calls, surviving lock and
 *     logout, and being the hardest thing here to test at the refill seam. In a
 *     zero-knowledge password manager that trade is backwards.
 *  2. NO INJECTABLE RANDOM SOURCE. An optional "source" parameter for tests is a
 *     parameter production code can also pass, and the guard against that would
 *     be a lint rule with an exception for this very file. The suite drives the
 *     rejection branch by spying on `globalThis.crypto.getRandomValues`
 *     instead, which is this repository's existing pattern and costs no API.
 *  3. NO FALLBACK when Web Crypto is missing. It throws, exactly as
 *     `generateId` in `@hvault/shared` does. A generator that silently degrades
 *     to a weaker source is the failure this module exists to prevent.
 */

/** Fill `out` from the platform CSPRNG, or throw. */
function fillRandomBytes(out: Uint8Array<ArrayBuffer>): void {
  // Read through a widened view on purpose. `globalThis.crypto` is typed
  // non-nullable, so the compiler believes this check is redundant; the runtime
  // disagrees in an insecure context, which is exactly the case that must throw
  // rather than silently fall back.
  const webcrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (typeof webcrypto?.getRandomValues !== 'function') {
    throw new Error('Cryptographic random API is unavailable. Cannot generate secrets.');
  }
  webcrypto.getRandomValues(out);
}

/**
 * A uniformly random `bigint` in `[0, exclusiveMax)`.
 *
 * The primitive the password generator is built on: it draws ONE of these per
 * password, over a bound of several hundred bits.
 */
export function randomBigIntBelow(exclusiveMax: bigint): bigint {
  if (exclusiveMax <= 0n) {
    throw new RangeError('randomBigIntBelow needs a positive bound');
  }
  // One possible value, so there is nothing to choose and no entropy to spend.
  if (exclusiveMax === 1n) return 0n;

  // `2^bits >= exclusiveMax > 2^(bits-1)`, which is what bounds the rejection
  // rate below one half. See the header.
  const bits = (exclusiveMax - 1n).toString(2).length;
  const byteCount = Math.ceil(bits / 8);
  const discard = BigInt(byteCount * 8 - bits);
  const buffer = new Uint8Array(byteCount);

  // `for (;;)` rather than `while (true)`: it expresses the same unbounded loop
  // with no condition for a linter to call constant, so the rejection loop needs
  // no suppression at all. The loop exits by `return` once a draw lands in range.
  for (;;) {
    fillRandomBytes(buffer);
    let value = 0n;
    for (const byte of buffer) value = (value << 8n) | BigInt(byte);
    value >>= discard;
    if (value < exclusiveMax) return value;
  }
}

/**
 * A uniformly random integer in `[0, exclusiveMax)`.
 *
 * Built on the `bigint` form rather than duplicating the rejection loop: two
 * loops would be two things to get wrong, and the cost is irrelevant at the
 * sizes this is called with.
 */
export function randomBelow(exclusiveMax: number): number {
  if (!Number.isSafeInteger(exclusiveMax) || exclusiveMax < 1) {
    throw new RangeError('randomBelow needs a positive safe integer bound');
  }
  return Number(randomBigIntBelow(BigInt(exclusiveMax)));
}

/**
 * One uniformly chosen element.
 *
 * The `undefined` guard is not decoration. `noUncheckedIndexedAccess` types the
 * read as possibly absent, and the alternative spelling the compiler accepts is
 * a `?? fallback`, which is how a generator quietly emits a constant in place of
 * a random choice with its reported entropy unchanged. That is a real defect
 * this replaces: the passphrase generator fell back to the literal string
 * `'word'`. Throwing is the only honest answer.
 */
export function pickUniform<T>(items: readonly T[]): T {
  const item = items[randomBelow(items.length)];
  if (item === undefined) {
    throw new Error('pickUniform: no item at the drawn index');
  }
  return item;
}
