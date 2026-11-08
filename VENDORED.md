# Vendored server packages

`database`, `sqliteuri` and `maintenance` descend from the vendored server at
`internal/pocketcontext/` in the applications. That code was copied from
github.com/pocketcontext/pocketcontext at commit
20843b7c888daaba55f0646dd77455b7b309d4cc, under its MIT license (the `LICENSE`
files in those folders). Import paths were rewritten. PocketBase was later
upgraded from v0.40.4 to v0.41.1 to match upstream commit
279b04b821ec7cbc5c7d2f966f12e1fcfb327a0b: PocketBase moved its Go modules to
`ganigeorgiev.com/pocketbase/*` (pocketbase v0.41.1, dbx v1.13.0), so only the
PocketBase and dbx import paths changed. The rest remains at 20843b7.

Local changes kept here:

- `sqliteuri/`: SQLite `file:` URIs built with forward slashes. `url.URL{Path: "C:\\..."}`
  encodes a Windows drive path as a URI authority, which SQLite rejects.
- `database/`: platform files. Windows has no `O_NOFOLLOW`, and its mode bits
  cannot prove that a file is private. The driver name was generalized.
- `maintenance/`: moved out of the server package; the application's read routes
  come from `maintenance.Policy` instead of being fixed in the code.
- Test and benchmark names and fixtures contain no application product names.

Review upstream security fixes to these packages and port them here by hand.
