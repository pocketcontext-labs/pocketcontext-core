# pocketcontext-core

Shared Go library for the PocketContext family of one-binary applications built on PocketBase: the project, sync-safe database and lease handling, private local management and sockets, public HTTPS with an allowlist, hosted mode, remote MCP OAuth, profile registry and private tunnel.

Applications require a tagged release in `go.mod` and pass everything that is theirs to `appserver.New`:

- `appidentity.Identity` (every name: app id, command, port, database and configuration file, environment prefix, local-key header, account email, ...). Every field is required; there is no default.
- `appserver.Policy`: `PublicRoute` is the complete public route allowlist, plus maintenance reads and observability allowlists. `Accounts` is required and has no default: `AccountsSingle` keeps exactly one account (the local password account, or the hosted `OWNER_EMAIL` account); `AccountsMulti` lets a hosted instance hold other accounts beside the owner (see [Multiple hosted accounts](#multiple-hosted-accounts)). It also carries the values that are the application's and not core's: `OAuthScope` (the one MCP scope; connected clients store it), `PublicBodyLimit` (bytes per public request), `Legacy` (the migrations and tables of earlier releases whose databases are refused; explicit empty lists when there are none) and `Hosted` (the per-account hosted budget and its label in 429 responses; left zero, hosted serving is refused). Optional `ReaderFramesSelf` adds `frame-src 'self'` to the reader page's policy, for an application that embeds a sandboxed preview it serves itself; left false, the reader embeds no frames. Optional `HostedSession` sets how long a hosted sign-in lasts (the reader renews it while in use); zero keeps the users collection's token duration.
- `appserver.Hooks`: product code at the points applications diverge. `AllowSignIn(app, email) (bool, error)` (`AccountsMulti` only; `New` refuses it with `AccountsSingle`) decides whether a hosted sign-in for an address without an account creates one.
- `appserver.Text`: product copy, including `OTPLoginPath` (the reader route the hosted sign-in email links to) and `OAuthConsent.SignInHTML` (how to sign in outside hosted mode). `Text.OAuthConsent.Page` (`OAuthPage`) is optional trusted presentation of the OAuth pages: `CSS`, `BrandHTML`, `SignInPath` (the consent page's same-tab Log in, which appends `?next=` and the encoded `/oauth/authorize` request; the application must validate `next`) and `ConnectionsPath` (where a browser visit to `/oauth/connections` redirects; the JSON API is unchanged). Empty fields keep the plain page. Optional `Text.OTPCodeEmail` renders the hosted sign-in email (subject, HTML and plain text) from a six-digit code and the browser link, and enables `POST /api/collections/users/auth-with-otp-code` (`{otpId, code}`; the code is bound to the requesting client's login request, single use with the link, 15 minutes, five wrong codes invalidate the request, rate-limited); without it the email stays link-only.

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
| `appserver.TestServer`, `Runtime.HooksConfig` | The real local routes, reader and public handler composed around an application's app, for that application's tests (`TestServerOptions.HostedProxy` applies a hosted proxy). |

`tools/` holds the repository checks (`name_check.py`, `identity_scan.py`, `build_tags_sync.py`) and `shared_file_diff.py`, which each application release runs against the other application's shared non-Go files.

## Multiple hosted accounts

With `Policy.Accounts` set to `AccountsMulti` (which needs `Policy.Hosted`), a hosted instance holds other `users` records beside the `OWNER_EMAIL` account. Local and tunnel modes keep exactly one local account in both modes, and a database that has held hosted accounts is refused for them. The application's own hooks must accept more than one `users` record (and the deletion of accounts that never signed in).

- **Addresses.** Every address is canonical: trimmed and lower-cased, printable ASCII only. Accounts are found ignoring ASCII case, so case variants are one account; a non-ASCII address gets the unknown-address answer and is never asked about or created.
- **Owner.** Hosted startup creates the owner only on `--hosted-init` or in a database with no accounts. A database whose accounts lack the owner (an `OWNER_EMAIL` change) is refused ("owner changes require explicit maintenance"), and so is one holding the local account, which is never adopted. `OWNER_EMAIL` must not be the local account's address. `Runtime.IsOwner(app, record)` tells the owner from the other users; what each user may do is the application's decision, and core authorizes nothing between them.
- **Sign-in.** `Hooks.AllowSignIn` receives the canonical address and runs for every address that passes the limits, existing accounts included (whose answer is ignored), so its cost does not show which accounts exist. True for an address without an account creates it (random password, not verified, named `Text.AccountName`) and sends its email. Nil, false, an error or a failed save create and send nothing. Every request answers `200 {"otpId": ...}` with a random id when nothing is sent and takes at least 250 ms; failures are logged without the address.
- **Limits.** Each client address (the real client behind a `HostedProxy`) has the sign-in budget the whole instance has with `AccountsSingle` (10, one more every 6 s) for requests and, separately, for redemptions, under an instance ceiling of 100 (one more every 100 ms). Each address gets one email a minute and at most 9 per 15-minute OTP lifetime, below PocketBase's reuse of an earlier OTP id; existing accounts are also refused while they hold 9 pending OTPs. The per-address history keeps 4096 addresses and forgets the oldest.
- **Accounts before proof.** At most 100 unverified accounts exist (the owner included) before `AllowSignIn` stops creating more. A successful sign-in verifies the account, failing closed. Accounts that are unverified, older than the OTP lifetime and without a pending OTP are pruned at start, every 5 minutes and before each creation; the owner and verified accounts never are.
- **OAuth.** Each account may hold 10 connections and 200 access tokens, and accounts other than the owner stop 10 connections and 200 tokens short of the instance limits (100 and 2000), so the owner can always connect. Client registration is anonymous and keeps its instance-wide limit of 256 clients.
- **Local management.** `/api/bundle/token` and `/api/bundle/login-code` act as the owner.

With `AccountsSingle`, `OWNER_EMAIL` may still equal the local account's address; such a hosted database would pass the local-serving check. Applications should not configure it.

## What core fixes for every application

These names are part of core's contract and are not configurable: the `users` collection holding the accounts (one, except on an `AccountsMulti` hosted instance), the local management routes under `/api/bundle/`, the sign-in pages under `/bundle/`, the maintenance route `/api/context/maintenance` with the app store key `contextMaintenanceReadOnly`, and the OAuth and MCP paths (`/oauth/*`, `/mcp`, `/.well-known/oauth-*`). Everything else an application decides is in `Config`.

The synced database is written back after 3 quiet seconds, and at the latest `appserver.MaxWriteBackDelay` (one minute) after the oldest unsaved change, so steady writes still reach the synced folder. Recording a change never waits for a write-back.

## Hosted mode behind a reverse proxy

Hosted mode (`ServeOptions.Hosted`) serves plain HTTP for a proxy that terminates TLS for the configured domain. Two serve-time options, valid only with `Hosted` (`ServeContext` refuses them otherwise), let an application expose this as flags:

- `ServeOptions.HostedHTTPAddress` (string): the listen address, a literal IP and port such as `0.0.0.0:8080` or `127.0.0.1:8098` (`ValidateHostedHTTPAddress`; host names are refused). Empty keeps `:80`. It excludes the development-only `DevHTTPAddress`.
- `ServeOptions.HostedProxy` (`*appserver.HostedProxy{Header string; Networks []netip.Prefix}`): the client address for per-address rate limits (core's six-digit code and OAuth limits and PocketBase's rate limiter). `Header` is exactly `HostedProxyXForwardedFor` (`X-Forwarded-For`, rightmost entry: the one the nearest proxy appended) or `HostedProxyCFConnectingIP` (`CF-Connecting-IP`, one value). `Networks` are the proxy's peer networks; at least one is required, and `0.0.0.0/0`, `::/0`, IPv4-mapped and non-canonical prefixes are refused. `ParseHostedProxy(header, networks)` builds one from a header name and a comma-separated CIDR list (both empty is nil). nil trusts no header and every limiter keys on the TCP peer, as before.

With `HostedProxy` set, the public handler, after the exact Host check and before any limiter, reads the header only when the peer address is inside `Networks`. The value must be one IP without a port or zone (IPv4-mapped addresses are unmapped); loopback, unspecified, multicast and invalid values keep the peer address. The request's remote address becomes `IP:0`. Leftmost `X-Forwarded-For` entries are never read. In every public mode, `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` and the local-key header are then removed, so the application never sees a client-supplied value, and hosted start clears PocketBase's trusted-proxy setting in memory (also after a settings reload), so a stored setting cannot make PocketBase trust a header. Native HTTPS serving (`--domain` without `--hosted`) never trusts a forwarded header. A forwarded address never grants local privilege: public requests are refused by every local management route whatever their peer or headers.

Examples: an AWS Application Load Balancer, `HostedHTTPAddress: "0.0.0.0:8080"` and `HostedProxy{Header: HostedProxyXForwardedFor, Networks: <the load balancer subnets or VPC CIDR>}`; Cloudflare Tunnel through a local proxy, `HostedHTTPAddress: "127.0.0.1:<port>"` and `HostedProxy{Header: HostedProxyCFConnectingIP, Networks: 127.0.0.0/8 and ::1/128}` (plus the private network the local proxy connects from, if it is not loopback).

The hosted server's keep-alive idle timeout is 120 seconds. Keep the proxy's upstream idle timeout below it (an Application Load Balancer defaults to 60 seconds), so the proxy closes idle connections first; otherwise occasional requests race the server's close and get a 502. Server-sent events at `/api/realtime` send nothing while there is nothing to report, so a proxy idle timeout shorter than the expected silence ends the stream; clients reconnect and must refetch what they display after reconnecting. PocketBase also closes a realtime connection after five minutes without a message.

## Building

`CGO_ENABLED=1 go test -tags "$(cat build-tags.txt)" ./...` with Go 1.27.3 (`GOTOOLCHAIN=go1.27.3` selects it). Applications copy `build-tags.txt` unchanged.

## Versioning

Tags `vX.Y.Z`. Before 1.0 a minor bump may change the API; applications pin an exact version.

## License

This module is under the [MIT license](LICENSE). The vendored server packages `database`, `sqliteuri` and `maintenance` keep their original MIT license files; see [VENDORED.md](VENDORED.md).
