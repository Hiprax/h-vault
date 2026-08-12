# Provenance — `chrome-csv.csv`

Verified-By: maintainer (Hiprax)
Verified-On: 2026-08-12
Source: https://support.google.com/chrome/answer/13068232

Checked: read back from the page above on the date named here — Chrome's import
REQUIRES the three headers `url`, `username` and `password`, spelled exactly so,
on the first line of the file. All three are present in this golden, spelled
identically, and the values under them are the login's first URI, its username
and its password. Also checked by reading the file: exactly one row, because
Chrome's format can carry a login and nothing else (`omittedCount` is 4 for the
five-item fixture); RFC 4180 quoting applied only where it is needed, which this
fixture's password exercises in all three ways at once (an embedded comma, an
embedded double quote doubled to `""`, and a TRAILING space, which an unquoted
cell would lose); CRLF after the header row and no trailing newline; and that
neither recovery code, nor the string `Backup Codes`, nor the TOTP secret appears
anywhere in the file — the format's loss note promises they are absent, and
`notes` travels verbatim into the `note` cell.

Not-verified: Chrome's own importer was not run against this file, and the source
page does NOT enumerate the columns Chrome's own export emits — it documents only
the three required headers. The two extra columns in this golden, `name` and
`note`, and the five-column ORDER, therefore carry forward the maintainer's
verification of 2026-07-23 recorded in
`packages/client/src/services/export/formats/chromeCsv.ts` against Chrome's own
`Passwords.csv`, re-confirmed here only against H-Vault's own `parseChrome`,
which reads all five case-insensitively. A future Chrome release could add a
column without this golden noticing; the three required ones are what the
documented contract covers.

Recording: the bytes were produced by `toChromeCsv` over the fixture in
`packages/client/tests/export/formats.golden.test.ts`, then read cell by cell
against the list above before being committed. Nothing regenerates this file:
the suite only ever compares against it.
