# Provenance — `bitwarden-json.json`

Verified-By: maintainer (Hiprax)
Verified-On: 2026-08-12
Source: https://bitwarden.com/help/condition-bitwarden-import/

Checked: read back from the page above on the date named here and compared with
this golden — the two top-level keys `folders` and `items` and their order; the
absence of a `collections` key, which is what distinguishes an INDIVIDUAL vault
export from an organization one; the item keys `id`, `organizationId`,
`folderId`, `type`, `reprompt`, `name`, `notes`, `favorite`, `fields`, `login`;
the numeric item types 1 = login, 2 = secure note, 3 = card, 4 = identity; the
login keys `uris`, `username`, `password`, `totp`; the custom-field type code
0 = text; and the `passwordHistory` entry keys `lastUsedDate` and `password`.
Also checked by reading the file: `null` rather than `""` for every absent
optional value; a folder record per distinct path, with the full slash path as
its `name`; `folderId: null` for an item in no folder; a secret carried as a
secure note with its description, value and expiry folded into `notes`; a card's
billing address folded into `notes` because Bitwarden's card object has no
address field; recovery codes emitted as a HIDDEN field (type 1) and delivery
notes as a TEXT field (type 0); and recovery codes ordered before any
user-defined field.

Not-verified: Bitwarden's own importer was not run against this file — no
Bitwarden account, client or CLI was used. The source page did not enumerate the
`card` or `identity` object keys, so the two names this repository has already
been bitten by — the CVV being `code` rather than `cvv`, and the identity using
`address1`/`address2`/`address3`, `postalCode` and `passportNumber` — carry
forward the maintainer's verification of 2026-07-23 recorded in
`packages/client/src/services/export/formats/bitwardenJson.ts`, re-confirmed here
only against H-Vault's own parser reading the file back. The synthetic
`00000000-0000-4000-8000-…` ids are H-Vault's choice: both Bitwarden and this
repository's importer regenerate ids on import, so only their internal
consistency (an item's `folderId` naming a folder in the same file) matters.

Recording: the bytes were produced by `toBitwardenJson` over the fixture in
`packages/client/tests/export/formats.golden.test.ts`, then read key by key
against the list above before being committed. Nothing regenerates this file:
the suite only ever compares against it.
