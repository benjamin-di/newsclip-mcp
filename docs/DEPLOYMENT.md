# Deployment and operations

The reference deployment uses Docker Compose on Linux AMD64. The reader server
and sign-in browser run as unprivileged users. Only the reader's port is
published, on loopback by default; the login service and VNC stay private.
The server and login images share the same release version.

Run the README setup command from your checkout before starting Compose. It
creates `local/config`, `local/tokens`, `local/state`, `local/data`, and `.env`
with private permissions and the current user/group ids. All generated state is
ignored by Git. Run setup again with additional `--user` arguments to add users;
existing matching credentials are preserved. Restart both services afterwards.

## Remote access

Set `NEWSCLIP_PUBLIC_URL` in `.env` to the HTTPS origin users will open, then
place a reverse proxy in front of the loopback reader port. Forward WebSocket
upgrades for `/users/USER/connect/…/vnc`, preserve the request path, and preserve
the external Host header. Do not log bearer headers, sign-in link paths or
query strings. The application validates Host and Origin against the configured
public origin. Do not publish the login service or its display ports.

## Configuration

| Setting | Purpose |
|---|---|
| `NEWSCLIP_USERS_FILE` | Required JSON registry of user ids and token hashes |
| `NEWSCLIP_PUBLIC_URL` | Public origin used for sign-in links and request validation |
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

## Troubleshooting

Use `docker compose logs --tail=100` locally and `newsclip doctor` for browser
prerequisites. Keep logs private. Check the configured public URL if sign-in
links point at an unreachable host. A 401 usually means the user URL and token
do not match, or a token was rotated. A publisher challenge requires the person
or a later attempt from a suitable network; repeating credential submissions is
not a repair. `not_entitled` requires different subscription access, not renewal.
