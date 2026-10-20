import { useCallback, useMemo, useRef, useState, type RefObject } from 'react';

/**
 * Why the tag field is saying something under its input:
 * - `duplicate`: the typed tag is already there, so Add did nothing;
 * - `limit`: the list is full, so Add did nothing (the typed text stays);
 * - `pending-limit`: a save found text typed but never added while the list was
 *   full, and stopped rather than drop it.
 */
export type TagNotice = 'duplicate' | 'limit' | 'pending-limit';

/** The state and actions of one tag editor, owned by the form that saves the tags. */
export interface TagField {
  readonly tags: readonly string[];
  /** What is typed in the input and not added yet. */
  readonly draft: string;
  readonly notice: TagNotice | null;
  /** How many tags the owner may carry. */
  readonly max: number;
  readonly inputRef: RefObject<HTMLInputElement | null>;
  setDraft: (value: string) => void;
  /** Adds the trimmed draft, or says why it did not. */
  add: () => void;
  remove: (tag: string) => void;
  /** Replaces the tags and clears the draft and the notice (a new file, a reopened editor). */
  reset: (tags: readonly string[]) => void;
  /**
   * The tags to save, with a typed-but-not-added draft included, or `null` when
   * the draft cannot be added because the list is full (the notice then says so
   * and the input has focus). Text a person typed is saved or explained, never
   * silently dropped: the vault editor used to drop it, and the documents' old
   * comma-separated field kept it.
   */
  commitPending: () => string[] | null;
}

/**
 * The one tag editor's state, shared by the vault item editor and the two places
 * a document's details are typed (the upload panel and Edit details).
 *
 * Tags are trimmed and kept as typed: no lowercasing, and two tags differing only
 * in case are two tags. A comma is an ordinary character, not a separator.
 */
export function useTagField(initialTags: readonly string[], max: number): TagField {
  const [tags, setTags] = useState<readonly string[]>(() => [...initialTags]);
  const [draft, setDraftState] = useState('');
  const [notice, setNotice] = useState<TagNotice | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const setDraft = useCallback((value: string) => {
    setDraftState(value);
    setNotice(null);
  }, []);

  const add = useCallback(() => {
    const tag = draft.trim();
    if (!tag) return;
    if (tags.includes(tag)) {
      setNotice('duplicate');
      return;
    }
    if (tags.length >= max) {
      setNotice('limit');
      return;
    }
    setTags([...tags, tag]);
    setDraftState('');
    setNotice(null);
  }, [draft, tags, max]);

  const remove = useCallback((tag: string) => {
    setTags((prev) => prev.filter((t) => t !== tag));
  }, []);

  const reset = useCallback((next: readonly string[]) => {
    setTags([...next]);
    setDraftState('');
    setNotice(null);
  }, []);

  const commitPending = useCallback((): string[] | null => {
    const tag = draft.trim();
    if (tag === '' || tags.includes(tag)) {
      if (draft !== '') setDraftState('');
      return [...tags];
    }
    if (tags.length >= max) {
      setNotice('pending-limit');
      inputRef.current?.focus();
      return null;
    }
    const next = [...tags, tag];
    setTags(next);
    setDraftState('');
    setNotice(null);
    return next;
  }, [draft, tags, max]);

  return useMemo(
    () => ({ tags, draft, notice, max, inputRef, setDraft, add, remove, reset, commitPending }),
    [tags, draft, notice, max, setDraft, add, remove, reset, commitPending],
  );
}
