import type { SettingsHelpTopic } from './settingsHelpTopics';

/**
 * The long explanations behind the Settings help triggers, for someone who has
 * never had a vault key explained to them.
 *
 * Loaded lazily (the default export is for `React.lazy`), so none of this text
 * weighs on the Settings page until a help trigger is first hovered, focused or
 * pressed. The panel title is the trigger's (`settingsHelpTopics.ts`); this
 * renders only the body, as DATA through one renderer.
 *
 * Every sentence states what the code and SECURITY.md say, and no more: what
 * each action does, what happens afterwards, when to use it and what it cannot
 * do. A change to the behaviour described here changes this text with it.
 * Controls are named exactly as the page labels them.
 */

interface HelpSection {
  heading: string;
  points: readonly string[];
}

interface HelpTopic {
  intro: string;
  sections: readonly HelpSection[];
}

const HELP: Record<SettingsHelpTopic, HelpTopic> = {
  'vault-key-rotation': {
    intro:
      'Your vault key is the one secret key that locks everything in your vault: every entry, every folder name, and the keys that protect your documents. Your master password unlocks it, and the server only ever holds it in locked form. Rotating swaps it for a brand-new key.',
    sections: [
      {
        heading: 'What happens when you rotate',
        points: [
          'This browser makes a new vault key.',
          'Every entry, including the ones in your trash, and every folder name is unlocked with the old key and locked again with the new one, here in this browser. Nothing leaves it unencrypted.',
          'Your documents are not downloaded or uploaded again. Only the small key that protects each document is locked again, so even large files add almost nothing to the work.',
          'Everything is then sent to the server in one request, together with the new key, locked under your master password.',
          'Your master password stays the same, and you stay signed in on this device.',
          'A progress bar shows how far it has got. Keep the page open until it finishes.',
          'When it is done, a message confirms it. An entry that could not be opened even before the rotation is left exactly as it was, and the message says how many there were.',
        ],
      },
      {
        heading: 'What you need',
        points: [
          'Your master password, to confirm it is you.',
          'If you have set up encrypted backups, you can also enter your backup password. It is optional. With it, your backups can still be restored on a different account. Without it, the rotation still works, but you will need to update your backup password afterwards, on the Backup Settings page.',
          'If some entries cannot be opened and your backup holds an older key that might open them, the rotation stops before changing anything and asks for your backup password, or for your confirmation to go ahead without it.',
          'A recent backup. A rotation cannot be undone, so take a fresh backup before you start.',
        ],
      },
      {
        heading: 'Your other devices',
        points: [
          'Rotating does not sign out your other devices.',
          'A device that was unlocked at the time still holds the old key. When it next reads entries it cannot open, it checks with the server and locks itself. Unlocking it with your master password gives it the new key.',
          'If it tries to save a change first, the save is refused, so nothing can end up locked under a key your account no longer uses, and it shows a notice asking you to sign in again. It shows the same notice, instead of locking, if it is in the middle of a document upload.',
          'If you prefer, sign out your other devices on the Active Sessions page before you rotate.',
          'Try not to edit entries on another device while the rotation runs. If an entry changes in the meantime, the rotation is refused rather than overwrite your edit, and you can try again from this page.',
        ],
      },
      {
        heading: 'If it is interrupted',
        points: [
          'If the page closes or the connection drops part way, sign out and sign in again, then come back to Settings.',
          'If the button now says Finish Rotation, press it. It completes the interrupted rotation with the key it had already started using, instead of making yet another key.',
          'Otherwise, simply rotate again.',
          'If you are told a rotation is still in progress, wait about five minutes, then sign out and in again.',
        ],
      },
      {
        heading: 'When to use it',
        points: [
          'A device or browser that had your vault unlocked may be in the wrong hands, for example a lost laptop or a computer you no longer trust.',
          'You have stopped using a device you do not trust. Sign it out first with Revoke on the Active Sessions page, then rotate.',
          'You want older copies of your entries, such as an old database snapshot or an old backup file, to stop opening with your current key.',
          'You do not need to do it often.',
        ],
      },
      {
        heading: 'Good to know',
        points: [
          'A copy of your old vault key cannot open anything saved after the rotation, and older copies of your entries can no longer be swapped back in.',
          'It cannot take back anything someone has already seen. If your passwords may have been read, change them on the websites they belong to.',
          'The new key is locked under your master password, so rotating does not protect you from someone who knows that password. If it may be known, change your master password first, then rotate.',
          'Encrypted exports made before the rotation will not be usable afterwards. For a backup that survives a rotation, use Backup Settings.',
        ],
      },
    ],
  },
  'entry-reseal': {
    intro:
      "Sealing ties each entry's contents to that one entry. Re-sealing rewrites your entries so that every one of them is tied this way, using the vault key you already have.",
    sections: [
      {
        heading: 'What it protects against',
        points: [
          "The server stores your entries encrypted and cannot read them. But without this tie, someone in control of the server could move one entry's encrypted contents onto another entry, and you might see the wrong password under the right name.",
          'Once an entry is sealed, contents moved onto another entry, into another field, or under another kind of entry do not open. H-Vault shows them as unreadable instead of showing you the wrong thing.',
          "It covers each entry's name, its contents and its previous passwords, and each folder's name. Your documents are already protected this way.",
        ],
      },
      {
        heading: 'Who needs it',
        points: [
          'Entries saved by an older version of H-Vault, before sealing existed.',
          'Entries brought back by restoring a backup, which arrive unsealed until the next re-seal.',
          'Everything you add or edit now is sealed automatically. If you are not sure, running it is safe.',
        ],
      },
      {
        heading: 'What changes, and what does not',
        points: [
          'Your vault key stays the same, so you confirm with your master password only.',
          'Nothing you see changes: the same entries, with the same contents.',
          'Your other devices keep working, and none of them has to unlock again.',
          'Your backups stay valid, and your documents are not touched.',
          'Like a rotation, it runs in this browser with a progress bar. Keep the page open until it finishes.',
          'Running it again does no harm. It simply seals every entry once more.',
        ],
      },
      {
        heading: 'If it is interrupted',
        points: [
          'Nothing is lost. Some entries are already sealed and the rest are still in the older form, all under your current key.',
          'Sign out and sign in again, then run it again to finish.',
          'It is not offered while an interrupted vault key rotation is waiting. Finish that first.',
        ],
      },
      {
        heading: 'What it cannot do',
        points: [
          'It does not make older copies stop working. Copies of your entries from before the re-seal, such as an old database snapshot or a downloaded backup, still open with the same key. Rotating your vault key is what retires them.',
          'It cannot stop a server from showing you an older version of the same entry, such as a password you have since replaced.',
          "It cannot stop a server from hiding entries, or from reordering an entry's previous passwords.",
          'Details stored without encryption are not covered: which folder an entry is in, its tags, and whether it is a favorite.',
          'If an entry you did not change suddenly reads differently, or says it cannot be read, check it against a backup.',
        ],
      },
    ],
  },
  'lock-on-hidden': {
    intro:
      'When this is on, H-Vault locks itself once this tab has been out of sight for the number of minutes you choose.',
    sections: [
      {
        heading: 'What counts as hidden',
        points: [
          'You switched to another tab, or minimized the browser window.',
          'The countdown starts the moment the tab is hidden. Come back before it runs out and it starts again from zero next time.',
        ],
      },
      {
        heading: 'What locking does',
        points: [
          'H-Vault lets go of your keys and clears the entries it had opened from its memory.',
          'It also clears the encrypted copy this browser keeps for offline reading, and stops any document upload in progress.',
          'It tries to clear a secret you copied to the clipboard from this tab. A browser may refuse that while the tab is in the background, so it tries again when you come back or next click or type in H-Vault.',
          'You stay signed in, so unlocking needs only your master password.',
        ],
      },
      {
        heading: 'How it works with auto-lock',
        points: [
          'The auto-lock timeout above still applies, whether the tab is visible or hidden. Whichever runs out first locks the vault.',
          'While a full backup or a full restore runs in a visible tab, the auto-lock timeout waits for it. This setting does not: a tab hidden long enough still locks the vault, and that stops the backup or restore.',
          'Browsers slow down timers in background tabs. If that delays the lock, it happens the moment you return to the tab.',
          'Each H-Vault tab you have open keeps its own countdown and locks by itself.',
        ],
      },
      {
        heading: 'Turning it on',
        points: [
          'It is off until you turn it on.',
          'When it is on, choose the minutes in the box below it, anywhere from 1 to 1440 (one day).',
          'Press Save Settings at the bottom of the page to keep the change.',
          'The setting is saved to your account, so your other devices use it too once they next load H-Vault.',
        ],
      },
      {
        heading: 'When to use it',
        points: [
          'On a shared, work or public computer.',
          'If you often step away and leave the browser open.',
          'If H-Vault is only ever open on your own device, the auto-lock timeout on its own may be all you need.',
        ],
      },
    ],
  },
};

export default function SettingsHelp({ topic }: { topic: SettingsHelpTopic }) {
  const { intro, sections } = HELP[topic];
  return (
    <div className="space-y-3 text-sm text-[hsl(var(--muted-foreground))]">
      <p>{intro}</p>
      {sections.map(({ heading, points }) => (
        <div key={heading} className="space-y-1">
          <h3 className="font-semibold text-[hsl(var(--foreground))]">{heading}</h3>
          <ul className="list-disc space-y-1 pl-5">
            {points.map((point) => (
              <li key={point}>{point}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
