/**
 * Shared input styling for the vault item form.
 *
 * The vault components deliberately do not use `components/ui/` (which only the
 * auth pages consume) and style raw `input`/`select`/`textarea` elements instead.
 * This one class string is what makes every control in `VaultItemForm` and its
 * child panels look like the same control, so it lives in one place rather than
 * being copied into each panel and drifting.
 */
export const inputClass =
  'w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]';
