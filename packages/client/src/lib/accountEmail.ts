import { z } from 'zod';
import { hasValidEmailTld } from './utils';

/**
 * The email field of every account form — sign-in, registration, the
 * forgotten-password request and the reset — as ONE definition.
 *
 * The address is the salt of the master-password key derivation, so a typo the
 * server would happily accept is a vault nobody can open again. The four forms
 * must therefore refuse exactly the same things, with the same words beside the
 * field; four copies of this chain were four places for one of them to drift.
 *
 * Kept out of `utils.ts` on purpose: that module is imported by the initial
 * payload, and this one pulls in `zod`, which only the lazily loaded account
 * pages need.
 */
export const accountEmailSchema = z
  .string()
  .min(1, 'Email is required')
  .pipe(z.email('Enter a valid email address'))
  .refine(hasValidEmailTld, 'Enter a valid email address');
