# Deployment and operations

The reference deployment uses Docker Compose on Linux AMD64. The reader server
and sign-in browser run as unprivileged users. Only the reader's port is
published, on loopback by default; the login service and VNC stay private.
The server and login images share the same release version.

Run the README setup command from your checkout before starting Compose. It
creates `local/config`, `local/tokens`, `local/state`, `local/data`, and `.env`
with private permissions and the current user/group ids. All generated state is
ignored by Git. Run setup again with additional `--user` arguments to add users;
existing matching credentials are preserved. Configure browser identity before
starting either service; missing OIDC configuration prevents web startup.
Restart both services afterwards.

Browser identity, delegated API admission and publisher credentials are separate
configuration boundaries. Read the [permissions model](AUTHENTICATION.md#permission-boundaries)
before granting access. Required browser authentication has no link-only
compatibility setting; optional worker configuration does not relax it.

## Remote access

Set `NEWSCLIP_PUBLIC_URL` in `.env` to the HTTPS origin users will open, then
place a reverse proxy in front of the loopback reader port. Forward WebSocket
upgrades for `/users/USER/connect/…/vnc`, preserve the request path, and preserve
the external Host header. Do not log bearer headers, sign-in link paths or
query strings. The application validates Host and Origin against the configured
public origin. Forward `/connections/` and its login, callback and POST action
routes as well. Do not publish the login service or its display ports.

Register one OIDC client with callback exactly
`NEWSCLIP_CONNECTIONS_PUBLIC_URL/connections/callback` (use the API public URL
when the browser URL is empty), and authorization-code plus PKCE
support. Use HTTPS for the application and issuer. Configure a required group
and either a signed claim whose value is a registered Newsclip user id, or a
private JSON bindings file of the form
`{"https://identity.example.com": {"stable-subject": "alice"}}`.
The issuer must match exactly. Group membership alone never selects an account.
Before changing a user's binding, disconnect their existing subscriptions;
changing aliases is not an account-transfer operation.

## Configuration

| Setting | Purpose |
|---|---|
| `NEWSCLIP_USERS_FILE` | Required JSON registry of user ids and token hashes |
| `NEWSCLIP_PUBLIC_URL` | MCP/native API public origin and request validation |
| `NEWSCLIP_CONNECTIONS_PUBLIC_URL` | Browser-only origin/base path; defaults to the API public URL |
| `NEWSCLIP_MCP_PUBLIC_URL_ALIASES` | Optional comma-separated trusted API URL aliases; empty by default |
| `NEWSCLIP_CONNECTIONS_ISSUER` | Required OIDC issuer URL |
| `NEWSCLIP_CONNECTIONS_CLIENT_ID` | Required browser client id |
| `NEWSCLIP_CONNECTIONS_GROUP` | Required browser-management group |
| `NEWSCLIP_CONNECTIONS_ACCOUNT_CLAIM` | Signed claim mapping to registered user id; choose this or bindings |
| `NEWSCLIP_CONNECTIONS_BINDINGS_FILE` | Issuer-scoped subject-to-user JSON; choose this or a signed claim |
| `NEWSCLIP_CONNECTIONS_CLIENT_SECRET_FILE` | Optional owned, mode-0600 OIDC client secret file |
| `NEWSCLIP_TRUSTED_PROXY_TOKEN` | Dedicated gateway-to-backend credential; not an agent grant or browser credential |
| `NEWSCLIP_TRUSTED_USER_HEADER` | Gateway-injected registered user, after stripping client-supplied copies |
| `NEWSCLIP_OPS_BEARER_TOKEN` | Separate operator-surface credential; never a reader or browser-management token |
| `NEWSCLIP_LOGIN_URL` | Private login-service address |
| `NEWSCLIP_LOGIN_TOKEN_FILE` | Private file containing the shared internal service token |
| `NEWSCLIP_STATE_HOME` | Sessions, profiles, locks and private diagnostic state |
| `NEWSCLIP_DATA_HOME` | SQLite archives and exports |
| `NEWSCLIP_PROVIDER_ALLOWLIST` | Optional comma-separated provider subset |
| `NEWSCLIP_SEARCH_API_KEY_GUARDIAN` | Operator-supplied Guardian Open Platform API key |
| `NEWSCLIP_URL` / `NEWSCLIP_TOKEN_FILE` | CLI client's user URL and private bearer file |

The Guardian API key is deployment-level configuration. Set it only where its
registered access terms cover the intended use. A missing key affects Guardian
operations, not the other providers.

A separate browser origin does not expand MCP or API admission. Only
`/connections/` and `/users/USER/connect/…` use that origin; MCP and native API
paths retain their configured host and origin checks. Keep the API public URL
fixed when introducing a browser host. Account state and archive paths stay
unchanged.
An existing public API port may be listed explicitly in
`NEWSCLIP_MCP_PUBLIC_URL_ALIASES`. Only those fixed API hosts/origins are added;
the separate browser host/origin cannot be an alias. This supports proxies
that preserve legacy Origin while canonicalizing Host, without admitting
unknown internal hosts.

## Backups and upgrades

SQLite is the archive authority. Use `newsclip --user USER archive-backup PATH`
inside the server with a writable backup destination; do not copy a running
database or its WAL independently. Use `archive-integrity` to check the archive
and `archive-restore` to restore a compatible backup. These administration
commands run locally on the server, not through a remote client.

Keep session/profile backups separate from article backups and protect them as
credentials. Never attach them to an issue. A fresh installation can reconnect
subscriptions without recovering profiles.

Before upgrading, back up each archive and read the release notes. Change
`NEWSCLIP_VERSION` in `.env`, run `docker compose pull`, then `docker compose up
-d`. Confirm `docker compose ps` reports both services healthy and exercise
`auth status` and a retrieval. Retain the previous image version for rollback;
restore a backup only when the older version cannot read the current schema.

For the mandatory browser-auth migration, configure the OIDC client first, then upgrade
both the reader and login service together with the same persistent state
mount. Verify their controls before exposing Connections through the proxy.
Preserve `users/USER/connections/` and `connections-browser/` with the private
state. Once disconnect has been used, an older image that ignores its barrier
is not a safe rollback target. Restore service with a compatible image or fix
forward; do not delete controls to make a subscription appear connected.

Validate the gateway's audience/scope/grant/group-ceiling decisions separately:
an admitted API caller must not manage a browser connection, and a signed-in
browser owner must not acquire an agent API grant. Check revocation according
to each layer's token/session/cache lifetime; browser groups are stored claims,
not a live membership lookup. Test cancellation, incomplete disconnect cleanup
and owner recovery from fresh state as well as reuse after restart. Record live
identities, grants, credential custody and rollout receipts privately; the
[project workplan](../ROADMAP.md) lists the source/artifact acceptance still required.

## Troubleshooting

Use `docker compose logs --tail=100` locally and `newsclip doctor` for browser
prerequisites. Keep logs private. Check the configured public URL if sign-in
links point at an unreachable host. A 401 usually means the user URL and token
do not match, or a token was rotated. A publisher challenge requires the person
or a later attempt from a suitable network; repeating credential submissions is
not a repair. `not_entitled` requires different subscription access, not renewal.

## Adopting shared subscriptions

Keep `subscription-access/` and `.subscription-access-adopted` in the persistent
application state root alongside user state. Forward the authenticated browser POST
routes `connections/choose`, `connections/share`, `connections/unshare` and
`connections/leave` under the existing public-origin policy. These routes accept no
API bearer as browser authority. Sharing requires fresh browser authentication;
selection is a single ordinary form submission. See [state recovery](SHARING.md#storage-and-recovery)
before upgrading or selecting a rollback image.
