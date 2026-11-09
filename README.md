# pocketcontext-core

Shared Go library for the PocketContext family of single-owner, one-binary applications built on PocketBase: the project, sync-safe database and lease handling, private local management and sockets, public HTTPS with an allowlist, hosted mode, remote MCP OAuth, profile registry and private tunnel.

Applications require a tagged release in `go.mod` and pass everything that is theirs to `appserver.New`:

- `appidentity.Identity` (every name: app id, command, port, database and configuration file, environment prefix, local-key header, account email, ...). Every field is required; there is no default.
- `appserver.Policy`: `PublicRoute` is the complete public route allowlist, plus maintenance reads and observability allowlists.
- `appserver.Hooks`: product code at the points applications diverge.
- `appserver.Text`: product copy. `Text.OAuthConsent.Page` (`OAuthPage`) is optional trusted presentation of the OAuth pages: `CSS`, `BrandHTML`, `SignInPath` (the consent page's same-tab Log in, which appends `?next=` and the encoded `/oauth/authorize` request; the application must validate `next`) and `ConnectionsPath` (where a browser visit to `/oauth/connections` redirects; the JSON API is unchanged). Empty fields keep the plain page.

## Packages

| Package | Purpose |
| --- | --- |
| `appidentity` | Required identity value and validation. |
| `atomicfile` | `WriteAtomic`, `CopyFile`, `FileSHA256`, `RenameRetry`, `RandomHex`. |
| `sqliteuri`, `database` | SQLite URIs and the guarded driver with maintenance controller. |
| `maintenance` | Read-only maintenance control; `maintenance.Policy` lists an application's reads. |
| `mcpobserve` | Metadata-only MCP/OAuth diagnostics; tool and route allowlists come from `Policy`. |
| `profiles` | Machine-local profile registry; `profiles.New(namespace)`. |
| `tunnel` | Tailcat private tunnel: one project port, loopback only. |
| `appserver` | `New`, `Project`, `Store`, `Serve`, `Health`, local routes, public listeners, OAuth, hosted mode. |
| `appserver/routepolicytest` | Frozen negative route set applications check their policy against. |
| `appserver.TestServer`, `Runtime.HooksConfig` | The real local routes, reader and public handler composed around an application's app, for that application's tests. |

`tools/` holds the repository checks (`name_check.py`, `identity_scan.py`, `build_tags_sync.py`) and `shared_file_diff.py`, which each application release runs against the other application's shared non-Go files.

## Building

`CGO_ENABLED=1 go test -tags "$(cat build-tags.txt)" ./...` with Go 1.27.3 (`GOTOOLCHAIN=go1.27.3` selects it). Applications copy `build-tags.txt` unchanged.

## Versioning

Tags `vX.Y.Z`. Before 1.0 a minor bump may change the API; applications pin an exact version.

## License

This module is under the [MIT license](LICENSE). The vendored server packages `database`, `sqliteuri` and `maintenance` keep their original MIT license files; see [VENDORED.md](VENDORED.md).
