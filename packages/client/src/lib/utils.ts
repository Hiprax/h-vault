import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { isAxiosError } from 'axios';
import { ACCOUNT_LOCKED_MESSAGE, isAccountLocked } from '../services/auth/sessionFailure';

/**
 * Merges class names using clsx and tailwind-merge.
 * This utility is used by shadcn/ui components to conditionally
 * apply and deduplicate Tailwind CSS classes.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Only allow safe protocols (http, https, mailto) to prevent javascript: URI XSS. */
export function isSafeUrl(url: string): boolean {
  return /^https?:\/\//i.test(url) || /^mailto:/i.test(url);
}

/**
 * Checks that an email's domain has a TLD-like dot with non-empty labels.
 * Defends against typo lockout for zero-knowledge users (master-password salt
 * is derived from the email, so typos are unrecoverable). Implemented without
 * a backtracking regex to avoid ReDoS risk on very long inputs.
 */
export function hasValidEmailTld(email: string): boolean {
  const at = email.lastIndexOf('@');
  if (at === -1) return false;
  const host = email.slice(at + 1);
  if (host.length === 0 || host.startsWith('.') || host.endsWith('.')) return false;
  const labels = host.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => label.length > 0 && !/[\s@]/.test(label));
}

/** Maximum length for user-facing error messages to prevent UI disruption. */
const MAX_ERROR_MESSAGE_LENGTH = 200;

/**
 * Extracts a human-readable error message from an API error.
 *
 * For Axios errors the server-provided `message` field is preferred over the
 * generic Axios "Request failed with status code …" message.
 * Messages are truncated to {@link MAX_ERROR_MESSAGE_LENGTH} characters.
 *
 * **One refusal is translated rather than quoted.** The server's error envelope is
 * flat and its `message` is sometimes an `ERROR_CODES` constant rather than a
 * sentence, and `ACCOUNT_LOCKED` is the one that now reaches ordinary callers: a
 * refresh refused for a lockout no longer ends the session, so the rejection
 * propagates to whatever made the request instead of being swallowed by a logout.
 * Every one of the twenty-five call sites here would otherwise put the bare string
 * `ACCOUNT_LOCKED` in a toast. The other codes are left alone deliberately — they
 * accompany a refusal the caller already handles, and translating them all would
 * be a rewrite of every error surface rather than a fix for this one.
 */
export function getApiErrorMessage(
  error: unknown,
  fallback = 'Something went wrong. Please try again.',
): string {
  if (isAccountLocked(error)) return ACCOUNT_LOCKED_MESSAGE;

  let message = fallback;

  if (isAxiosError(error)) {
    const serverMessage: unknown = (error.response?.data as Record<string, unknown> | undefined)
      ?.message;
    if (typeof serverMessage === 'string' && serverMessage.length > 0) {
      message = serverMessage;
    } else {
      message = error.message;
    }
  } else if (error instanceof Error) {
    message = error.message;
  }

  return message.slice(0, MAX_ERROR_MESSAGE_LENGTH);
}
