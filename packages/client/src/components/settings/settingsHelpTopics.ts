/**
 * The Settings help topics: each panel's title and its trigger's accessible name.
 *
 * Kept apart from the explanations themselves (`SettingsHelp.tsx`), which load as
 * their own chunk the first time a trigger is hovered, focused or pressed: these
 * few strings render with the page, the long text does not.
 *
 * The names deliberately avoid the words the page's own controls are found by
 * ("Rotate Vault Key", "Re-seal Vault Entries", "rotate key", "re-seal",
 * "create", "remove", "dismiss"), so a help trigger is never what a query for
 * one of those controls matches.
 */
export const SETTINGS_HELP_TOPICS = {
  'vault-key-rotation': {
    title: 'Vault key rotation, explained',
    label: 'Help: what rotating the vault key does',
  },
  'entry-reseal': {
    title: 'Entry sealing, explained',
    label: 'Help: sealing entries to their place',
  },
  'lock-on-hidden': {
    title: 'Locking a hidden tab, explained',
    label: 'Help: locking when the tab is hidden',
  },
} as const;

export type SettingsHelpTopic = keyof typeof SETTINGS_HELP_TOPICS;
