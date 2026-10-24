/**
 * What each control on the Backup page does, always on screen, in one list.
 *
 * Each line is ONE text node that merely starts with a control's name, so a query
 * for a button by its exact name ("Download Latest") still finds only the button.
 */
const LINES = [
  'Save Settings stores Auto-backup and its UTC hour.',
  'Backup Now, and Auto-backup once a day, email an encrypted vault backup (logins, notes, cards, identities, secrets and folders) to your confirmed recipients, or to your account email when none are listed. An emailed backup is never signed, so restoring one asks you to confirm it first. Documents are never emailed.',
  'Download Latest saves the same vault backup to this device, signed with your backup password.',
  'Full Backup saves your vault and every document, with its name, note, tags, folder and favorite, to this device as one encrypted, signed file. It is never emailed and can be large. Documents in the trash are left out.',
  'Settings, backup recipients and two-step sign-in are not part of any backup.',
  'Save Recipients changes who receives emailed backups, and asks for your master password.',
  'Change Backup Password sets a new backup password for the backups made from now on; a file saved earlier still opens with the password it was made with.',
  'Restore from File takes either kind of file. A full backup also brings back its documents.',
  'Browsers without a save dialog cap a full backup at 512 MB.',
] as const;

export function BackupOptionsGuide() {
  return (
    <div
      data-testid="backup-options-guide"
      className="rounded-md border border-[hsl(var(--border))] p-3 text-xs text-[hsl(var(--muted-foreground))]"
    >
      <p className="mb-1 font-medium text-[hsl(var(--foreground))]">What each option does</p>
      <ul className="list-disc space-y-1 pl-4">
        {LINES.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
    </div>
  );
}
