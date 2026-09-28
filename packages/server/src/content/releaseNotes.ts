import type { ReleaseNote } from '@hvault/shared';

export const RELEASE_NOTES: readonly ReleaseNote[] = [
  {
    version: '0.15.0',
    date: '2026-09-28',
    title: 'See what changed after every update',
    summary:
      'H-Vault now shows the version it runs, explains each update in plain words the first time you sign in after it, and keeps the whole release history one click away. Whoever runs the server is told when a newer release is out.',
    highlights: [
      {
        icon: 'sparkles',
        title: "What's new, once, after each update",
        body: 'The first time you sign in after an update, this window shows what changed, with every release you missed marked New for you. Once you close it, it does not open again, on any of your devices.',
      },
      {
        icon: 'clock',
        title: 'The version and every release, one click away',
        body: 'The version at the foot of the sidebar opens these notes at any time. Settings, About H-Vault has the full history, which you can search and filter by kind of change.',
      },
      {
        icon: 'bell',
        title: 'Told when a newer release is out',
        body: 'Twice a day the server checks GitHub for a newer H-Vault. When there is one, administrators see a notice with the update steps, and, when email is set up, each address in UPDATE_NOTIFY_EMAILS gets one email per release.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'added',
        text: "A setting, Show what's new after an update, turns the automatic opening off. The notes then stay behind the version in the sidebar, and a dot tells you something is unread.",
      },
      {
        kind: 'added',
        text: 'A new account starts caught up, so it is never shown the history of releases from before it existed.',
      },
      {
        kind: 'improved',
        text: 'When the server is updated while H-Vault is open, the app notices the next time you unlock it or return to it after a few minutes away, and the update prompt says which version is ready.',
      },
      {
        kind: 'fixed',
        text: "A few colours that followed your system's light or dark mode, instead of the theme you chose in H-Vault, now follow your choice.",
      },
      {
        kind: 'changed',
        text: 'The server now contacts api.github.com twice a day to check for a newer release. It sends no user data and not the version it runs. Set UPDATE_CHECK_ENABLED to false to turn it off.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'Settings, About H-Vault shows administrators whether this server runs the latest release, the update steps when it does not, and a Check now button.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'UPDATE_CHECK_REPOSITORY points the check at a fork, and UPDATE_NOTIFY_EMAILS names the accounts that are told about new releases. Without it, every account sees update information and nobody is emailed.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.14.1',
    date: '2026-09-27',
    title: 'Notes keep your spacing, and viewer line numbers line up',
    summary:
      "Notes now keep the spacing you typed, with Markdown styling restored, and the document viewer's line numbers stay level with their lines.",
    highlights: [
      {
        icon: 'note',
        title: 'Markdown notes keep your spacing',
        body: "Text you line up with spaces stays lined up, a single line break stays a line break, and runs of spaces are kept, in the editor's monospace font. Bold, italics, headings, lists, quotes, code and links still apply. Spaces at the very start of a line are still not kept.",
      },
      {
        icon: 'eye',
        title: 'Preview shows the format you chose',
        body: 'A Plain Text note now previews as plain text, exactly as it will be saved. Until now Preview always treated the text as Markdown.',
      },
      {
        icon: 'file',
        title: 'Line numbers stay level in the document viewer',
        body: 'The numbers beside a text or code file no longer fall a line behind about every 19 lines, because the code and its numbers now use the same font.',
      },
      {
        icon: 'mail',
        title: 'Email addresses masked in delivery failure logs',
        body: "When a mail server refuses a message, its reply usually quotes the recipient's address. The failure detail the server logs now masks every address in it and is capped in length.",
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'fixed',
        text: 'Headings, lists, quotes, code blocks and links in Markdown notes are styled again, and a code block wider than the note now scrolls and can be reached with the keyboard.',
      },
      {
        kind: 'fixed',
        text: "Plain Text notes now use the editor's monospace font, so text aligned with spaces stays aligned.",
      },
      {
        kind: 'fixed',
        text: "The browser's developer console no longer shows a security warning on every page. Nothing about how the app works changed, and the warning stops once the app update prompt has been accepted.",
      },
      {
        kind: 'fixed',
        text: 'Ten server error log lines that recorded an empty object now record the error message, and never the error object itself, whose fields can carry request data.',
        audience: 'administrators',
      },
      {
        kind: 'security',
        text: 'A request parameter repeated under a second spelling, such as a and a[], is now detected and reported as parameter pollution, keeping only the last value. Before, the second spelling silently overwrote the first with no warning.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.14.0',
    date: '2026-09-25',
    title: 'Recoverable key rotation and entries sealed to where they belong',
    summary:
      'Vault-key rotation can now be finished after an interruption, items and folders you create, edit or import are now sealed to their own entry and field, Re-seal Entries updates older ones, and several ways a stale tab, a lockout or a crafted file could cost you data or access are now closed.',
    highlights: [
      {
        icon: 'refresh',
        title: 'Finish an interrupted key rotation',
        body: 'If a vault-key rotation is cut short by a crash or a lost connection, the new key is now kept and Settings offers Finish Rotation, which completes it with that same key. Abandoning the rotation is still possible, as a separate action that says plainly what it costs.',
      },
      {
        icon: 'lock',
        title: 'Entries sealed to the entry and field they belong to',
        body: 'Item names, contents, previous passwords and folder names are now sealed to their own entry and field when you create, edit, rename or import them, so contents a server swaps onto another entry refuse to open instead of showing the wrong password. Re-seal Entries in Settings rewrites older entries this way.',
      },
      {
        icon: 'shield',
        title: 'Backups are checked against your own key',
        body: "Restoring a backup now checks its signature against your account's own key first. A backup that cannot be verified, such as one that arrived by email, asks you before anything is restored, and one that no available key agrees with is still refused.",
      },
      {
        icon: 'key',
        title: 'Unlock links that last, and sessions that survive a lockout',
        body: 'An emailed unlock link now keeps working when the account is locked again, with a fresh one sent when needed. A session that tries to renew during a lockout is left intact instead of destroyed, and resumes once the lockout ends.',
      },
    ],
    changes: [
      {
        kind: 'security',
        text: 'A tab still holding a replaced vault key can no longer save entries nothing can read, or wipe out the vault by changing the master password. The server refuses both, and the app either recovers on its own or asks you to sign in again.',
      },
      {
        kind: 'security',
        text: 'Changing your master password and rotating your vault key can no longer run at the same moment and leave a key nothing can open, and a rotation interrupted at its last step no longer undoes a rotation that had already succeeded.',
      },
      {
        kind: 'fixed',
        text: 'One unreadable entry no longer blocks vault-key rotation for ever. It is carried across as it is, everything else is re-encrypted, and you are told how many entries were left behind.',
      },
      {
        kind: 'security',
        text: 'An import, a backup restore or a document upload can no longer land entries under a vault key that is being replaced as they arrive.',
      },
      {
        kind: 'security',
        text: 'The key derived from your master password is now held by the browser as a key it will use but never reveal, and saving an item no longer exports the raw vault key to compute its search hash.',
      },
      {
        kind: 'security',
        text: 'Signing in is refused for an account whose deletion is still being finished, with the same answer a wrong password gets, and a two-factor sign-in that can no longer complete now wipes the key derived from your master password at once.',
      },
      {
        kind: 'security',
        text: "The isolated document viewer can no longer put its own words in the app's interface, or be served without its isolation under another spelling of its address, and the link dialog shows the address as the browser itself would write it.",
      },
      {
        kind: 'fixed',
        text: 'Reading authenticator codes from a photo now works, an unreadable photo or a slow scan no longer stops the camera, exports with a negative batch number are accepted, and a crafted export that different programs would read differently is refused.',
      },
      {
        kind: 'changed',
        text: 'Bulk tagging, permanent deletion and folder reordering now send four requests at a time and wait out a short rate-limit refusal by themselves, so large actions finish. The folder list is read back from the server after every reorder.',
      },
      {
        kind: 'fixed',
        text: 'Changing a very long login password no longer fails because the previous password was too long to keep in its history.',
      },
      {
        kind: 'fixed',
        text: 'Uploads stalled by a slow connection now retry and resume instead of failing, cancelling a small upload frees its storage at once, and an upload starting as another finishes, or several finishing together, can no longer take an account past its storage quota.',
      },
      {
        kind: 'fixed',
        text: 'Saved Vault Health results are no longer wiped by a save that could not read them, and a future offline-storage upgrade in another tab can no longer leave signing in, locking or signing out waiting for ever.',
      },
      {
        kind: 'security',
        text: 'An encrypted file made elsewhere with unusually heavy key-derivation settings is now refused before any work starts, with a clear message, instead of being able to freeze the tab. Files encrypted with H-Vault are not affected.',
      },
      {
        kind: 'fixed',
        text: 'Every page now has one main region and one top-level heading, headings no longer skip a level, and the sidebar is announced as the page banner.',
      },
      {
        kind: 'added',
        text: 'HTTP_REQUEST_TIMEOUT_MS (4 minutes), HTTP_HEADERS_TIMEOUT_MS (1 minute) and DOCUMENT_PART_BODY_TIMEOUT_MS (64 seconds) bound how long the server waits for a request or an upload piece to arrive, never how long it processes one.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'Both nginx layers now follow the shared golden policy, and the host limits each address to 40 requests a second with a burst of 40. Heavy operations are budgeted per account, and item, folder and two-factor confirmation writes gained per-account limits.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.13.0',
    date: '2026-09-21',
    title: 'Import from Google Authenticator and set password requirements',
    summary:
      'You can now move your two-factor codes out of Google Authenticator by scanning its export QR codes, and the password generator can guarantee a minimum number of each character type while keeping its strength figure exact.',
    highlights: [
      {
        icon: 'scan',
        title: 'Import from Google Authenticator',
        body: 'Import from Authenticator reads the export QR codes with your webcam or from a pasted export link, tracks multi-part exports in any order, and lists each account with a live code. You attach each code to a login yourself, and the whole set can be saved into your encrypted documents.',
      },
      {
        icon: 'key',
        title: 'Minimum counts for each character type',
        body: 'Set a minimum of up to five for each character type you enable. The generator picks uniformly from every password that meets your settings, so each allowed password is equally likely and the strength shown is the true one.',
      },
      {
        icon: 'gauge',
        title: 'See what requirements cost',
        body: 'Requiring characters can only lower strength, because it rules passwords out. When a minimum is set, the readout says how many bits it costs, and the figure beside the meter is the exact strength of the passwords your settings allow.',
      },
      {
        icon: 'clock',
        title: 'Codes now show for more authenticator secrets',
        body: "An item's code tile now accepts the common 26-character secret and full authenticator links, and honours a link's own hash, digit count and interval. Counter-based links now say they cannot be generated instead of showing a code that never matches.",
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'Save as my default stores your generator length, character types and minimums on your account, so the generator opens with them on any device you sign in from.',
      },
      {
        kind: 'added',
        text: 'The login form has a Scan QR code button beside its TOTP field, for adding a code from any service.',
      },
      {
        kind: 'added',
        text: 'Adding an imported code to a login that already has one keeps the old code in a hidden field by default, since a key cannot be recovered once it is gone.',
      },
      {
        kind: 'changed',
        text: 'The generator now refuses to generate when every character type is off, or when the minimums need more characters than the password has, instead of quietly producing something weaker.',
      },
      {
        kind: 'fixed',
        text: 'Accounts created before generator settings existed now get the defaults filled in, and a stored value outside the usable range is brought back into range.',
      },
      {
        kind: 'security',
        text: 'The QR decoder runs inside the same isolated frame the document viewer uses, away from your vault key, and decoded keys are overwritten with zeros when you leave the page, lock, sign out or start over.',
      },
      {
        kind: 'security',
        text: 'The export is read by a bounded parser that refuses oversized or deeply nested input and an unknown hash algorithm, rather than quietly assuming the common one.',
      },
      {
        kind: 'security',
        text: "Random choices about secret material all go through one module that uses the platform's cryptographic generator and refuses to fall back to anything weaker.",
      },
    ],
  },
  {
    version: '0.12.0',
    date: '2026-09-09',
    title: 'Download all your documents, and a notice when offline storage fails',
    summary:
      'You can now save every document in one verified action, the app tells you when it cannot keep an offline copy of your vault, and several sign-in and two-factor protections are tighter.',
    highlights: [
      {
        icon: 'download',
        title: 'Download all documents',
        body: 'Download all saves every document the list is showing, one at a time, through the same verified read a single download uses. A file that fails its checksum produces no file, and if a rate limit or an auto-lock interrupts, you can continue from where it stopped.',
      },
      {
        icon: 'bell',
        title: 'A notice when offline storage fails',
        body: 'If the encrypted offline copy of your vault cannot be saved, a notice now says so while you are still online, and tells you whether browser storage is full or blocked for this site, as private browsing does.',
      },
      {
        icon: 'shield',
        title: 'Backup codes no longer trust a device',
        body: 'Signing in with Remember me and a single-use backup code still gives you the full remembered session, but no longer registers the browser to skip two-factor. Devices trusted this way before keep that trust until it expires; you can revoke them from the Sessions page.',
      },
      {
        icon: 'eye',
        title: 'Backup code use in the audit log',
        body: 'The audit log now records each spent backup code with how many are left, and a sign-in completed with a backup code is told apart from one using your authenticator app.',
      },
    ],
    changes: [
      {
        kind: 'security',
        text: 'Entering the master password again no longer resets the two-factor lockout count; it is cleared only when a sign-in actually completes.',
      },
      {
        kind: 'security',
        text: 'A malformed cookie is now treated as absent everywhere, so it can no longer break sign-in and session requests, and turning off two-factor authentication can no longer be interrupted half-way.',
      },
      {
        kind: 'security',
        text: 'A document uploaded from a tab that was open when you rotated your vault key is no longer stored unreadable; the app re-wraps its key and finishes the upload without re-sending the file.',
      },
      {
        kind: 'security',
        text: "Each app request's anti-forgery token is now accepted in exactly one form, and an oversized reply from the breach-check service now counts as a failed check, never as safe.",
      },
      {
        kind: 'fixed',
        text: 'Retrying a vault-key rotation can no longer run it twice, and a momentary failure to reach the server can no longer make later rotations wrongly claim you hold no documents.',
      },
      {
        kind: 'fixed',
        text: 'Clicking Retry twice on a failed upload no longer creates a document nobody can open; the button now shows Retrying and ignores further clicks.',
      },
      {
        kind: 'fixed',
        text: 'Uploads started at the same moment can no longer slip past the document limit together; the small overshoot an account may finish with is now bounded as intended.',
      },
      {
        kind: 'fixed',
        text: 'A formatting result no longer follows you to the next file you choose, and a file that grows past the size limit while being formatted is refused before it is sent.',
      },
      {
        kind: 'fixed',
        text: 'Emptying the document trash, and the nightly purge, now stop after several storage refusals in a row instead of running for hours, and the trash is re-read so it shows what is really still there.',
      },
      {
        kind: 'fixed',
        text: 'Renaming a document while viewing it no longer replaces the preview with an error, and a rename is no longer applied to the wrong document when the server answers about another one.',
      },
      {
        kind: 'fixed',
        text: 'Very wide spreadsheets no longer freeze the tab; the preview is limited by total cells and says which rows or columns were cut.',
      },
      {
        kind: 'fixed',
        text: 'Previews now show an empty document as an empty page, explain remote images in responsive image markup, and keep links working below an anchor with an unusual character.',
      },
      {
        kind: 'fixed',
        text: 'A browser storage write cancelled as it commits no longer leaves saving, or signing out, waiting for ever.',
      },
      {
        kind: 'fixed',
        text: 'Four controls gained screen-reader names, the folder expander is no longer nested inside the folder button, and warnings on the Leave H-Vault page and audit log labels have more contrast.',
      },
      {
        kind: 'security',
        text: 'The mail library moved to the release that closes an advisory against it. H-Vault never used the affected options, so no version was exposed.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: "The Docker images now name their runtime user by number, the API image's health probe no longer starts a shell, and the build context excludes .cache directories at any depth.",
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.11.0',
    date: '2026-09-04',
    title: 'Folders, favorites, trash and search for documents',
    summary:
      'Documents now have the same navigation as the vault, with folders, favorites, a trash you can restore from and a search box, plus a full-screen viewer. Backup History also pages through every entry instead of only the newest thirty.',
    highlights: [
      {
        icon: 'folder',
        title: 'Folders, favorites and trash for documents',
        body: 'The Documents page gains a rail with All Documents, Favorites, Trash and your folder tree with a count per folder. A document you deleted can now be found, restored or destroyed for good from the trash view.',
      },
      {
        icon: 'search',
        title: 'Search your documents',
        body: "Search covers a document's name, type, tags and note. Everything is decrypted in your browser, so the server is never told what you searched for.",
      },
      {
        icon: 'eye',
        title: 'Full-screen document viewer',
        body: "The viewer can expand to fill the window and comes back with a button or Escape. The document's name and its Download button stay outside the frame, so nothing a document renders can forge them.",
      },
      {
        icon: 'clock',
        title: 'Backup History shows every entry',
        body: 'Backup History now pages through the full record ten entries at a time, with the total and Prev and Next controls, instead of showing only the newest thirty.',
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'Empty trash for documents reports how many were destroyed, and says so when the storage engine could not remove every file.',
      },
      {
        kind: 'added',
        text: 'New uploads are filed into the folder you have open, and the upload panel says which one before it starts.',
      },
      {
        kind: 'added',
        text: "A document's folder now shows on its row and in its details, a trashed document shows when it was deleted, and images and video are centred in the viewer.",
      },
      {
        kind: 'changed',
        text: 'The folder-delete dialog now says that documents in the folder are affected too, and that delete moves them to the trash for thirty days rather than destroying them.',
      },
      {
        kind: 'fixed',
        text: 'Backup History no longer shows No backup history when loading fails, and a backup you download appears without a reload.',
      },
      {
        kind: 'fixed',
        text: 'Paging the backup history or the audit log no longer shows an entry twice, or skips one, when several were written in the same instant.',
      },
      {
        kind: 'fixed',
        text: 'A document deleted while its list was loading no longer reappears, and deleting a folder after the vault locked no longer leaves an unhandled error.',
      },
      {
        kind: 'changed',
        text: 'The backup history endpoint now accepts the page size its published API contract advertises, instead of refusing anything above thirty.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.10.1',
    date: '2026-09-03',
    title: 'A fix for the pre-commit secret scan',
    summary:
      'Nothing changes in the app itself. This release fixes the pre-commit secret scan for people who build H-Vault from source and commit to it.',
    highlights: [
      {
        icon: 'wrench',
        title: 'Pre-commit secret scan no longer blocks skipped files',
        body: 'A commit that touches only files the secret scan is told to skip, such as the README, the security policy, the example settings file, the lockfile or tests, is no longer blocked. The scan now names what it skipped and says it read nothing.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'fixed',
        text: 'The scan keeps its teeth everywhere else: a secret staged beside a skipped file is still found, and a file that survives the exclusions but cannot be read still fails the commit.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.10.0',
    date: '2026-09-03',
    title: 'An encrypted document store with an isolated viewer',
    summary:
      'Where your server has documents turned on, you can now upload files that are encrypted in your browser, preview many types in an isolated frame and download them with a checksum check. Vault-key rotation re-keys them without touching the files.',
    highlights: [
      {
        icon: 'upload',
        title: 'Encrypted documents',
        body: 'Drop a file on the new Documents page and it is encrypted in your browser and sent in parts, with progress and a cancel button. An interrupted transfer resumes without re-sending the parts the server already holds. Locking the vault cancels an upload.',
      },
      {
        icon: 'eye',
        title: 'Previews in an isolated frame',
        body: "Markdown, web pages, text and code, CSV, JSON, images, audio and video are shown in an isolated frame that cannot read the app's storage, cookies or keys, and remote images are never loaded. Links ask before opening, and PDFs are download-only by design.",
      },
      {
        icon: 'download',
        title: 'Downloads checked on the way out',
        body: 'Each segment is authenticated as it arrives and the whole file is compared with the SHA-256 sealed at upload. A mismatch discards the file and tells you, instead of handing you something that is not your document.',
      },
      {
        icon: 'server',
        title: 'The Docker stack ships its own object storage',
        body: 'A sixth service provides S3-compatible storage on the internal network, provisioned on first boot from .env. Upgrading requires S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY and S3_RPC_SECRET in .env, or the stack will not start.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'Opening a document shows its name, type, size, tags, note and checksum, and lets you rename it, retag it, edit its note, favorite it, move it, trash it, restore it or delete it for good.',
      },
      {
        kind: 'added',
        text: 'Before uploading a JSON, Markdown or YAML file you can have it formatted, or for JSON repaired, in the browser. You review the changes and a line-by-line diff, then choose the rewrite or your original.',
      },
      {
        kind: 'added',
        text: 'A file whose contents disagree with its name, such as a PDF renamed to Markdown, is not previewed, and the page says what it actually is.',
      },
      {
        kind: 'added',
        text: 'A document that cannot be opened with your vault key is marked as such, and can still be moved, favorited, trashed and deleted.',
      },
      {
        kind: 'added',
        text: 'Rotating your vault key now re-keys every document by re-wrapping its small key; no file is read, re-uploaded or touched.',
      },
      {
        kind: 'changed',
        text: 'Documents are not part of encrypted backups. A backup now records how many documents the account held, and restoring one says so.',
      },
      {
        kind: 'security',
        text: 'Deleting your account now erases your documents and their stored files; a file storage could not remove at the time can no longer be opened and is cleaned up later.',
      },
      {
        kind: 'security',
        text: "Downloaded documents are never written to the browser's offline cache, and filenames are cleaned of path separators, control characters and direction overrides before saving.",
      },
      {
        kind: 'fixed',
        text: 'A vault-key rotation no longer strands an item, folder or document created while it was being prepared; a rotation that does not cover every entry is refused and can be retried.',
      },
      {
        kind: 'fixed',
        text: 'A failed vault-key rotation now shows the reason when the server gives one meant for you, instead of a flat failure message.',
      },
      {
        kind: 'fixed',
        text: 'Deleting a folder now moves its documents to the trash or to the parent folder, like its vault items, and documents trashed more than thirty days ago are purged on schedule.',
      },
      {
        kind: 'fixed',
        text: 'Vault and trash lists keep a stable order when many items share a timestamp, so paging never shows one twice or skips one.',
      },
      {
        kind: 'added',
        text: 'S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY configure the document store, all or none. MAX_DOCUMENT_SIZE_MB, DOCUMENT_STORAGE_QUOTA_MB_PER_USER and DOCUMENT_UPLOAD_TTL_HOURS set limits; DOCUMENT_ALLOWED_EXTENSIONS is enforced only in the browser.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'An hourly job reclaims storage that no document names any more, and the metrics endpoint reports whether the bucket was reachable at start-up. The health check never contacts storage.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'The app waits for storage to start, not to be healthy, so a storage problem affects documents only. Back up the database, both storage volumes and .env together, because documents are not in the application backup.',
        audience: 'administrators',
      },
      {
        kind: 'security',
        text: 'The app and Nginx images are rebuilt against current Alpine packages, and patched releases of transitive dependencies, including the query-string parser the server uses, clear the reported advisories.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.9.0',
    date: '2026-08-14',
    title: 'Screen-reader and contrast fixes, and Bitwarden imports that keep more',
    summary:
      'Most of this release is behind-the-scenes work on how H-Vault is tested and released. For you it brings screen-reader and contrast fixes, fixes for long website addresses and early expiry dates, and Bitwarden imports that keep more of each item.',
    highlights: [
      {
        icon: 'eye',
        title: 'Better screen-reader support',
        body: 'Multi-select in the vault list now works with a screen reader, and controls that announced themselves as nothing, such as the clipboard timeout, the note format and a website address match type, now have names.',
      },
      {
        icon: 'palette',
        title: 'Readable contrast in the light theme',
        body: 'Secondary labels, red destructive text and buttons, and the status colours now meet the minimum contrast ratio in the light theme. The dark theme has not been fully measured yet, and one known red-text issue remains there.',
      },
      {
        icon: 'upload',
        title: 'Bitwarden imports keep more of each item',
        body: "A card or identity with one over-long field is no longer dropped whole. The field is trimmed to the vault's limit and the trimmed text is kept in the item's notes, except for card numbers and security codes, which are trimmed and reported only.",
      },
      {
        icon: 'server',
        title: 'Images build the same on any machine',
        body: 'Built from a checkout with a restrictive umask, the stack could not start. Every copied file now gets an explicit mode, and the one-shot index bootstrap no longer ships npm, which removes its unfixable scan findings.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'fixed',
        text: 'A bare website address near the maximum length can no longer be saved in a form that refuses every later edit, because the limit is now measured on the address as stored, including the scheme added to a bare domain.',
      },
      {
        kind: 'fixed',
        text: 'Secret expiry dates before the year 100 are now accepted, matching the range the editor advertises, while impossible dates are still refused.',
      },
      {
        kind: 'fixed',
        text: 'Deleting a folder now clears leftover item references to it before it answers, so a restart can no longer lose that cleanup.',
      },
      {
        kind: 'fixed',
        text: 'Submitting a password form before the strength checker had loaded no longer starts loading it a second time.',
      },
      {
        kind: 'added',
        text: 'LOG_DIRECTORY chooses where the rotating log files are written. Unset or blank, they land in logs beside the working directory, as before.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'A release is now published only after the full pipeline passes on a clean checkout, its tag follows the version in package.json, and its notes are the curated changelog section.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: "The database container's health probe now says why it could not start the replica set, reporting only the error's short code.",
        audience: 'administrators',
      },
      {
        kind: 'fixed',
        text: "The Nginx image's configuration files now carry an explicit read-only mode, so a restrictive umask on the build machine no longer stops it starting.",
        audience: 'administrators',
      },
      {
        kind: 'security',
        text: 'The address library that decides which rate-limit bucket a request counts against was updated, closing three address-misclassification advisories, and several build-time dependencies were patched.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'The local pipeline gained tiered entry points and new checks, including deployment, upgrade, recovery, accessibility and cross-user access drills, for anyone building from source.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.8.0',
    date: '2026-07-28',
    title: 'Auto-lock you control, and sessions that survive network hiccups',
    summary:
      'Locking when the tab is hidden is now your choice and off by default, the vault locks correctly after a laptop sleeps, and a brief network problem or ordinary use can no longer sign you out or rate-limit you.',
    highlights: [
      {
        icon: 'timer',
        title: 'Lock when hidden is now a setting',
        body: 'Hiding the tab used to start a hidden 30-second countdown to lock. Whether to lock on hiding, and how long to wait, are now two settings beside the auto-lock timeout, off by default. Turn it on if you relied on the old behaviour.',
      },
      {
        icon: 'lock',
        title: 'The vault locks correctly after sleep',
        body: 'The idle deadline is now a point in time, re-checked when the window comes back, so a vault left open while a laptop slept is locked on waking. Scrolling now counts as activity too.',
      },
      {
        icon: 'refresh',
        title: 'Network hiccups no longer sign you out',
        body: 'A session renewal that fails because the server is briefly unreachable, restarting or rate-limiting no longer ends your session. Only a genuine rejection from the server does; anything else keeps you where you are and offers to try again.',
      },
      {
        icon: 'gauge',
        title: 'No more rate limits from normal use',
        body: 'Signing in now has its own allowance that session refreshes and unlocks cannot spend, raised from ten to twenty requests per fifteen minutes per address.',
      },
    ],
    changes: [
      {
        kind: 'fixed',
        text: 'Unlocking no longer sends you to the sign-in page after a rate limit or a dropped connection; it tells you what went wrong and stays put.',
      },
      {
        kind: 'fixed',
        text: 'A rate limit or lost connection during unlock no longer counts as a wrong master password.',
      },
      {
        kind: 'fixed',
        text: 'If your master password was changed on another device, unlocking now asks you to sign in again instead of reporting an incorrect password.',
      },
      {
        kind: 'security',
        text: 'Session refresh is now genuinely rate limited by client address; before, the limit could never be reached.',
      },
      {
        kind: 'security',
        text: 'A request the server refused on its own merits, such as a sign-in to a locked account, is no longer sent a second time automatically.',
      },
      {
        kind: 'security',
        text: 'The settings, backup settings and backup history endpoints now carry the same per-user rate limit as the other signed-in endpoints.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'RATE_LIMIT_WINDOW_MS and RATE_LIMIT_MAX were removed. Nothing ever read them, so leaving them in .env is harmless.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.7.0',
    date: '2026-07-28',
    title: 'Reuse saved addresses, and edit every identity field safely',
    summary:
      'Cards can borrow a billing address from an identity, identities show and edit all their stored fields, and editing an item no longer erases fields the editor did not show. Addresses gain a second street line and delivery notes.',
    highlights: [
      {
        icon: 'sparkles',
        title: 'Use a saved address for a card',
        body: 'The billing address section offers Use a saved address, a searchable list of identities that have an address. Picking one fills the six billing fields, and Undo fill is offered until you edit them. Delivery notes are never copied, and nothing leaves your device.',
      },
      {
        icon: 'shield',
        title: 'Editing no longer erases fields you cannot see',
        body: "Saving used to rewrite an item from only the fields on screen, which silently erased an identity's company, Social Security number, passport number, notes and custom fields, and a card's notes. Saving now keeps every stored field the form does not edit.",
      },
      {
        icon: 'note',
        title: 'Every identity field is visible and editable',
        body: "An identity's company, Social Security number, passport number and custom fields now appear on the item, with the two numbers masked behind a reveal control, and have controls in the editor. Identities and cards gain a Notes box.",
      },
      {
        icon: 'mail',
        title: 'Second street line and delivery notes',
        body: "Card and identity addresses gain an optional second street line, and an identity's address can carry delivery notes for a courier. Both are encrypted with the rest of the item, and search now looks inside addresses.",
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'An item whose contents could not be decoded can now be renamed; only the name changes, and the encrypted contents stay byte-identical.',
      },
      {
        kind: 'fixed',
        text: 'An item that could not be decoded can no longer be destroyed by opening the editor. Edit is unavailable and explains why, including to keyboard and screen-reader users.',
      },
      {
        kind: 'fixed',
        text: 'Editing a secret no longer shifts its expiry by your time zone or across a daylight-saving change, and a year the vault cannot store is refused with a message.',
      },
      {
        kind: 'fixed',
        text: 'The editor now checks lengths, formats, email addresses and phone numbers the way the vault does, and shows the message on the field.',
      },
      {
        kind: 'fixed',
        text: 'A save the vault could not read back is now refused with a message naming the field, instead of being stored and leaving the item undecodable.',
      },
      {
        kind: 'fixed',
        text: 'Multi-line notes, secret values and custom fields now keep their line breaks on screen, and empty address rows are no longer shown.',
      },
      {
        kind: 'fixed',
        text: 'Editing an identity with no address no longer makes the next import of the same file duplicate it.',
      },
      {
        kind: 'fixed',
        text: 'An imported address line that is too long is trimmed with the rest kept in notes, instead of discarding the whole identity or card.',
      },
      {
        kind: 'fixed',
        text: 'Saving an item over the custom field, website address or recovery code limit now shows a notification instead of silently doing nothing.',
      },
      {
        kind: 'fixed',
        text: 'Entrance animations are skipped when your system asks for reduced motion, and removing a billing address keeps keyboard focus inside the dialog.',
      },
      {
        kind: 'changed',
        text: 'Bitwarden imports now map address lines into the first and second street lines. Re-importing a file you imported before this release may duplicate identities that had a second or third address line.',
      },
      {
        kind: 'added',
        text: 'The plaintext Bitwarden JSON export now carries the second street line and delivery notes, so both round-trip.',
      },
      {
        kind: 'security',
        text: "A high-severity denial-of-service advisory in a build-time dependency was cleared from the project's own dependencies, with its version floor pinned; a copy bundled inside npm in the index bootstrap image was reviewed and accepted.",
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.6.0',
    date: '2026-07-26',
    title: "Keep a login's recovery codes with its password",
    summary:
      'Each login can now hold the two-factor recovery codes for the account it unlocks, encrypted with the rest of the item, with tools to paste, reveal, copy and burn codes one at a time.',
    highlights: [
      {
        icon: 'key',
        title: 'Recovery codes on logins',
        body: 'Every login gains an optional list of backup codes, kept inside the same encrypted data as its password. Each code is masked until revealed and has its own copy and delete buttons, deleting offers Undo, and you are warned when three or fewer are left.',
      },
      {
        icon: 'clipboard',
        title: 'Paste codes in any common format',
        body: 'Paste a JSON array, a comma or space separated list, one code per line, or a single code. The format is detected and reported, and a paste that is not accepted says exactly what is wrong and where.',
      },
      {
        icon: 'download',
        title: 'Codes travel with imports and exports',
        body: 'A generic CSV import can map a column of recovery codes, and the plaintext export carries them in Bitwarden JSON and CSV. Chrome and Edge CSV has no place for them, and its note on what the format loses says so.',
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'Codes can be downloaded from an item as a plain text file, behind a confirmation that says the file is not encrypted.',
      },
      {
        kind: 'added',
        text: 'Duplicates and anything over the 50-code limit are reported, never silently dropped, and codes never appear in the vault list.',
      },
      {
        kind: 'fixed',
        text: 'A CSV column such as 2FA recovery codes is now mapped to the new recovery-codes field instead of the TOTP secret.',
      },
      {
        kind: 'changed',
        text: "An overwrite import replaces a matched item's content, so recovery codes the file does not carry are lost; the confirmation now says so before anything is sent.",
      },
    ],
  },
  {
    version: '0.5.1',
    date: '2026-07-25',
    title: 'A copied password stays until its timeout, and a refused erase is retried',
    summary:
      'Copied secrets now stay on the clipboard until the configured timeout instead of vanishing when you switch tabs, and an erase the browser refuses is retried rather than silently abandoned.',
    highlights: [
      {
        icon: 'clipboard',
        title: 'Switching tabs no longer empties your paste',
        body: 'A copied password used to be wiped whenever the page was hidden, which is exactly when you go to paste it. Now only the configured deadline, a lock, a logout or closing the tab for good erases a copied secret.',
      },
      {
        icon: 'timer',
        title: 'Refused erases are retried',
        body: 'Browsers can refuse a clipboard write from a window that is not focused. A refused erase is now retried when the window regains focus or becomes visible, when the app loads again and on your next click or keypress in H-Vault, even after the vault locks.',
      },
      {
        icon: 'bell',
        title: 'One accurate countdown',
        body: 'There is now one clipboard countdown for the whole app. It tracks the real deadline, disappears when the clipboard is actually erased, and says so when the browser has refused the erase.',
      },
      {
        icon: 'key',
        title: 'Two-factor codes from Settings are covered',
        body: 'The two-factor setup secret and the backup codes copied from Settings are now erased on schedule and on lock and logout, like every other secret.',
      },
    ],
    changes: [
      {
        kind: 'security',
        text: 'Lock and logout now check that the clipboard erase actually happened and retry it if the browser refused, and logout erases the clipboard before contacting the server.',
      },
      {
        kind: 'fixed',
        text: 'Copying a new secret while an earlier erase is due can no longer empty the clipboard you just filled, and locking during a copy erases that value once it lands.',
      },
      {
        kind: 'fixed',
        text: "The password generator's Copy button stays disabled until the first password has been generated.",
      },
      {
        kind: 'fixed',
        text: 'The clipboard erase delay is clamped to 5 to 300 seconds, so a malformed setting can no longer erase a secret the moment you copy it.',
      },
      {
        kind: 'security',
        text: 'The frontend router moved to its version 8 package, resolving a high-severity advisory in the old one. H-Vault does not use the affected mode, so it was not exploitable; refresh your lockfile if you pin dependencies.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.5.0',
    date: '2026-07-23',
    title: 'Remember me, trusted devices and a way to leave H-Vault',
    summary:
      'You can now stay signed in longer on a device you trust and let it skip the two-factor step, manage those devices from the Sessions page, and export your vault as plaintext when moving to another password manager.',
    highlights: [
      {
        icon: 'smartphone',
        title: 'Remember me on trusted devices',
        body: 'An opt-in checkbox at sign-in extends your session to 30 days by default and, with two-factor on, lets the device skip the code step until its trust expires. Your master password is still required on every unlock and is never stored.',
      },
      {
        icon: 'refresh',
        title: 'Remembered sessions survive a browser restart',
        body: 'On the next launch a remembered session lands on the Unlock screen instead of the sign-in page. Your vault key is still derived from your master password on unlock and is never saved.',
      },
      {
        icon: 'shield',
        title: 'See and revoke trusted devices',
        body: 'The Sessions page lists every device allowed to skip two-factor, with its browser, address and dates, and lets you revoke one or all. Trust is also dropped automatically when your password, two-factor setup or backup codes change.',
      },
      {
        icon: 'download',
        title: 'Leave H-Vault with a plaintext export',
        body: 'A separate page in Settings exports your whole vault as an unencrypted Bitwarden JSON, Bitwarden CSV or Chrome and Edge CSV file, built in your browser after you re-enter your master password and confirm a warning.',
      },
    ],
    changes: [
      {
        kind: 'changed',
        text: 'The 50-session limit is now enforced: signing in on a new device ends your oldest active session once you are over it, and the Sessions list shows only live sessions.',
      },
      {
        kind: 'added',
        text: 'Items the plaintext export cannot decode or represent are reported as skipped rather than silently dropped, and each export is recorded in the audit log.',
      },
      {
        kind: 'security',
        text: 'Trusted devices are server-side records that hold only a hash of a random token, so trust cannot be forged, is capped at ten per account and can be revoked centrally.',
      },
      {
        kind: 'security',
        text: "A trusted device's two-factor skip is checked only after your password is verified, and an unknown, expired or replayed token falls back to the normal code prompt.",
      },
      {
        kind: 'added',
        text: 'REFRESH_TOKEN_DAYS (7), REFRESH_TOKEN_REMEMBER_DAYS (30) and TRUSTED_DEVICE_DAYS (30) set session and trust lifetimes in days; the server refuses to boot unless each is at least the one before it.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'JWT_REFRESH_EXPIRY was removed. Nothing ever read it, so sessions always lasted 7 days; set REFRESH_TOKEN_DAYS instead.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'HIBP_CACHE_MAX_BYTES (64 MiB by default) bounds the in-memory breach cache by bytes per worker, and the PM2 memory ceiling rises to 768 MiB per worker.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'The breach-corpus seeder is now part of the compiled server, so it can run inside the production image, which ships no npm.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.4.0',
    date: '2026-07-22',
    title: 'Faster breach scans with results that persist',
    summary:
      'Vault Health now checks a large vault for breaches in a handful of requests with visible progress, keeps its results encrypted on your device between visits, and no longer freezes the browser.',
    highlights: [
      {
        icon: 'gauge',
        title: 'Breach scans in a few requests',
        body: "A full-vault breach check now sends many hash prefixes per request, checks identical passwords once and shows how many it has checked as it runs. Only the first five characters of each password's hash ever leave your device.",
      },
      {
        icon: 'clock',
        title: 'Results kept between visits',
        body: 'Breach findings and strength scores are saved on your device, encrypted with your vault key, so they survive a refresh, an auto-lock and a browser restart. A Last checked label shows their age, and they are cleared on logout.',
      },
      {
        icon: 'shield',
        title: 'Unchecked is never shown as safe',
        body: 'A password that could not be checked, or one added since the last scan, is counted as unverified and keeps its warning, and a strength analysis that fails shows a warning instead of No issues found.',
      },
      {
        icon: 'database',
        title: 'A shared breach cache, and fully offline checks',
        body: 'Breach ranges are cached in MongoDB across accounts and restarts and served as a fallback when the service is down. An opt-in seed command imports the full Pwned Passwords corpus for checks with no third-party dependency.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'improved',
        text: 'Vault Health scores password strength in the background and lists long results efficiently, so large vaults no longer freeze the page.',
      },
      {
        kind: 'security',
        text: 'Breach lookups now ask for padded responses, so an observer on the network cannot infer the queried prefix from the response size.',
      },
      {
        kind: 'security',
        text: 'The shared breach cache holds only public breach data keyed by the five-character prefix, with no link to any user, and the server still never receives a password or a full hash.',
      },
      {
        kind: 'fixed',
        text: 'The sidebar no longer highlights both Vault and Vault Health on the Vault Health page.',
      },
      {
        kind: 'added',
        text: 'BREACH_CACHE_TTL_DAYS (30 by default), BREACH_SEED_AUTO and BREACH_SEED_REFRESH_CRON tune the breach cache and an optional scheduled refresh of the seeded corpus.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'The production image is pinned to the node:24-alpine3.23 base, because the newer Alpine crashed npm during image builds under WSL2. The running application is unchanged.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'The local development server now runs on port 5173 instead of 3000, and can be moved with VITE_PORT. Production is unaffected.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.3.0',
    date: '2026-07-22',
    title: 'Smarter imports that match by content, not by name',
    summary:
      'Imports now recognise existing items by their decrypted content, in your browser, so re-importing is safe and ten accounts on one site stay ten items. Every row is accounted for, and vault rows gain a second label to tell similar items apart.',
    highlights: [
      {
        icon: 'upload',
        title: 'Imports match on content',
        body: 'A login matches on its site and username, and other items on their exact content, worked out in your browser and never sent. Re-importing the same file changes nothing, and several accounts on one site no longer collapse into one.',
      },
      {
        icon: 'eye',
        title: 'A second label on every row',
        body: "Vault rows now show a login's username or site, a card's last four digits behind a mask, or an identity's name or email. No password, CVV, Social Security number, TOTP seed or secret value is ever shown.",
      },
      {
        icon: 'bell',
        title: 'Overwrite asks first',
        body: "Importing with overwrite now says how many items and passwords will change, and warns that anything the file does not carry is lost, before anything is sent. The replaced password is kept in the item's history.",
      },
      {
        icon: 'file',
        title: 'A full import report',
        body: 'An import reports how many rows were imported, updated, already up to date, skipped as duplicates, dropped as duplicates within the file, and skipped as unusable, with the reason for each.',
      },
    ],
    changes: [
      {
        kind: 'changed',
        text: "Re-importing a native H-Vault export now restores each item's password history.",
      },
      {
        kind: 'changed',
        text: 'An imported login with no title is named after its site with the username in brackets, so accounts on one site are easy to tell apart.',
      },
      {
        kind: 'improved',
        text: 'Vault list sorting is now a total order, so same-named items sort consistently and reversing the direction gives the exact reverse.',
      },
      {
        kind: 'fixed',
        text: 'Import now refuses to run against a vault it could not fully load, instead of treating every existing item as new.',
      },
      {
        kind: 'fixed',
        text: 'Web addresses written as match patterns no longer make unrelated logins look like the same item.',
      },
      {
        kind: 'fixed',
        text: "Bitwarden imports keep an identity's title, middle name, username and licence number in notes, and SSH key items become logins with the keys in labelled custom fields.",
      },
      {
        kind: 'fixed',
        text: 'Over-long usernames, passwords, notes, URLs and custom-field values are trimmed instead of discarding the whole entry, with the overflow kept in notes; a password is never copied into notes.',
      },
      {
        kind: 'fixed',
        text: 'Vault list rows past the first fifty now have the same spacing as a shorter list.',
      },
      {
        kind: 'security',
        text: 'Duplicate matching no longer happens on the server. With overwrite the server does see which of your own items an import updates; skip, the default, and keep both send no updates.',
      },
      {
        kind: 'changed',
        text: 'Breaking for API clients: the import endpoint now takes only explicit insert and update operations and returns inserted and updated counts. The old data envelope is rejected.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'Concurrent imports for one account are serialized, and where the database supports transactions an import commits or rolls back as a unit.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.2.0',
    date: '2026-07-21',
    title: 'Import from other password managers, encrypted in your browser',
    summary:
      'You can now import from Bitwarden, LastPass, KeePass, Chrome and Edge, Firefox, 1Password and any CSV. Each entry is converted and encrypted in your browser before it is uploaded.',
    highlights: [
      {
        icon: 'upload',
        title: 'Import from other password managers',
        body: 'Bitwarden JSON and CSV, LastPass, KeePass, Chrome and Edge, Firefox, 1Password and a generic column-mapping CSV are parsed and encrypted in your browser, so no credential, note or field value leaves the device in the clear.',
      },
      {
        icon: 'folder',
        title: 'Source folders become tags',
        body: 'Folders and groups from the source are kept as tags. Tags are stored in plaintext so the server can index them, which means an import makes your source folder names visible to the server.',
      },
      {
        icon: 'gauge',
        title: 'Large imports go in batches',
        body: 'An import file of up to 8 MiB is split into size-bounded requests automatically, with progress shown on the Import button, and imports have their own rate limit so a large migration does not stall part-way.',
      },
    ],
    changes: [
      {
        kind: 'fixed',
        text: 'Importing an export from another manager, such as a Firefox CSV, no longer fails with an error about missing encryption fields.',
      },
      {
        kind: 'fixed',
        text: 'Re-importing a large native H-Vault export no longer fails on the per-request size limit.',
      },
      {
        kind: 'fixed',
        text: 'Quoted CSV fields that contain line breaks are now parsed correctly in the column-mapping preview.',
      },
      {
        kind: 'fixed',
        text: 'A Bitwarden identity with an unusual email or phone number keeps the rest of its data, and the odd value is moved into its notes.',
      },
      {
        kind: 'changed',
        text: "Web addresses with unsafe schemes, such as Android app links, are dropped from a login's address list and kept in its notes.",
      },
      {
        kind: 'changed',
        text: 'When a large import is split into batches, same-named entries in different batches count as duplicates under skip; choose keep both to keep every one.',
      },
      {
        kind: 'security',
        text: "The server's plaintext CSV import path was removed, so the server never parses a plaintext export and can no longer store raw CSV values in fields meant for encrypted data.",
      },
    ],
  },
  {
    version: '0.1.2',
    date: '2026-07-20',
    title: 'Least-privilege database access for the Docker stack',
    summary:
      'An operational release for people who run the Docker stack: the app now connects to its database as a restricted user, and the health checks keep answering during a database outage.',
    highlights: [
      {
        icon: 'database',
        title: 'The app no longer connects as the database root user',
        body: 'The app and the index bootstrap now use a MongoDB user limited to readWrite on the hvault database, created by a new one-shot service. Set MONGO_APP_PASSWORD in .env before the next docker compose up, or the stack will not start.',
        audience: 'administrators',
      },
      {
        icon: 'server',
        title: 'Health checks answer during a database outage',
        body: 'The health, config and metrics endpoints no longer depend on the database they report on, so they answer correctly instead of timing out when MongoDB is unreachable.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'changed',
        text: 'The default Docker networks moved to 172.31.240.0/24 and 172.31.241.0/24 to avoid colliding with other stacks; override them with HVAULT_EDGE_SUBNET and HVAULT_DATA_SUBNET.',
        audience: 'administrators',
      },
      {
        kind: 'fixed',
        text: 'The internal Nginx now runs two worker processes instead of one per host CPU core, keeping it inside its container limits.',
        audience: 'administrators',
      },
      {
        kind: 'changed',
        text: 'Documented that docker compose up --wait can report the Nginx container as unhealthy while serving normally, when recovering from an app outage longer than about 75 seconds.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.1.1',
    date: '2026-07-20',
    title: 'Dependency updates and clearer crash logs',
    summary:
      'A maintenance release that brings server, client and tooling dependencies up to date and makes fatal server crashes easier to diagnose.',
    highlights: [
      {
        icon: 'server',
        title: 'Clearer records of fatal crashes',
        body: 'An uncaught exception or unhandled rejection now records a single crash entry with a full stack trace and process and system context, and flushes the logs within a bounded time before the process exits with a non-zero code.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'improved',
        text: 'Server, client and tooling dependencies were upgraded to their latest compatible releases. TypeScript stays on 6.x and the Node type definitions on 24.x, to match the supported toolchain and the Node 24 runtime.',
        audience: 'administrators',
      },
    ],
  },
  {
    version: '0.1.0',
    date: '2026-07-14',
    title: 'First public release of H-Vault',
    summary:
      'H-Vault is a self-hosted, zero-knowledge password manager, secret store and encrypted note app. Your data is encrypted in your browser before it reaches the server, and your master password never leaves your device.',
    highlights: [
      {
        icon: 'lock',
        title: 'A zero-knowledge vault',
        body: 'Store logins, secrets, notes, cards and identities, with search, folders, tags and favorites. Item names and contents are encrypted in your browser with AES-256-GCM before they reach the server, and the master password never leaves the device. Tags, favorites and folder placement are stored unencrypted.',
      },
      {
        icon: 'key',
        title: 'Password tools and health checks',
        body: 'Generate passwords or passphrases with exact strength figures, and check your vault for weak, reused, old and breached passwords and for logins with no TOTP. A breach check sends only a five-character hash prefix to Have I Been Pwned.',
      },
      {
        icon: 'shield',
        title: 'Strong account protection',
        body: 'Two-factor authentication with backup codes, refresh token rotation with reuse detection, lockout after ten failed attempts with an unlock email, protection against cross-site requests, and layered rate limiting.',
      },
      {
        icon: 'server',
        title: 'Self-hosted with Docker Compose',
        body: 'One self-contained stack runs an internal Nginx, the API, an index bootstrap and MongoDB as a single-node replica set, and publishes a single loopback-bound port for your host Nginx to terminate TLS in front of.',
        audience: 'administrators',
      },
    ],
    changes: [
      {
        kind: 'added',
        text: 'Nested folders with loop detection, depth limits and drag-to-reorder.',
      },
      {
        kind: 'added',
        text: 'A 30-day trash with restore and permanent delete.',
      },
      {
        kind: 'added',
        text: 'Password history keeps up to ten previous passwords per login, each encrypted separately.',
      },
      {
        kind: 'added',
        text: 'A built-in authenticator shows TOTP codes for stored logins.',
      },
      {
        kind: 'added',
        text: 'Rotate your vault key from the browser, with other writes blocked while it runs and retries that are safe to repeat.',
      },
      {
        kind: 'added',
        text: 'A standalone file encryption tool seals any file with a password into a self-contained encrypted file, entirely in your browser and apart from your account keys.',
      },
      {
        kind: 'added',
        text: 'Encrypted email backups with a separate backup password, and a restore that re-encrypts entries to your current key.',
      },
      {
        kind: 'added',
        text: 'An encrypted JSON export behind password re-authentication.',
      },
      {
        kind: 'added',
        text: 'A searchable audit log covering 37 operations, with automatic retention.',
      },
      {
        kind: 'added',
        text: 'Account deletion that removes your data from every collection.',
      },
      {
        kind: 'added',
        text: 'An installable web app with offline read access, dark, light and system themes, keyboard shortcuts and accessible components.',
      },
      {
        kind: 'added',
        text: 'Rate limiting across twelve tiers backed by MongoDB, keyed per address, email, user or session, with IPv6 addresses grouped by /64 subnet.',
        audience: 'administrators',
      },
      {
        kind: 'added',
        text: 'PM2 clustering is supported as an alternative deployment, with distributed job locks so background jobs never run twice.',
        audience: 'administrators',
      },
    ],
  },
];
