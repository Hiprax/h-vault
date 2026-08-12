# Provenance — `bitwarden-csv.csv`

Verified-By: maintainer (Hiprax)
Verified-On: 2026-08-12
Source: https://bitwarden.com/help/condition-bitwarden-import/

Checked: the eleven column headers and their exact order —
`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`
— read back from the page above on the date named here and compared character for
character with row 0 of this golden. Also checked by reading the file: that only
logins and secure notes have a row shape (the card, the identity and the secret
in the fixture are absent, and `omittedCount` is 3); that `type` is the literal
`login` / `note`; that `favorite` is `1` or empty; that `reprompt` is `0`; that
multiple URIs share one `login_uri` cell joined with a comma; that the `fields`
cell puts the recovery codes FIRST, comma-joined so the cell's own newline
separator stays unambiguous; and that every row terminates with CRLF per RFC
4180 while a newline INSIDE a quoted cell stays a bare LF.

Not-verified: Bitwarden's own behaviour on import was not exercised — no
Bitwarden account, client or CLI was used, so this golden pins what the
documented format says and what H-Vault's own parser reads back, not what
Bitwarden's importer does with the file. The `fields` cell's internal
`name: value` layout is H-Vault's choice and is not specified by the source; the
importer folds that cell into notes, so its layout is not part of the contract.

Recording: the bytes were produced by `toBitwardenCsv` over the fixture in
`packages/client/tests/export/formats.golden.test.ts`, then read line by line
against the list above before being committed. Nothing regenerates this file:
the suite only ever compares against it.
