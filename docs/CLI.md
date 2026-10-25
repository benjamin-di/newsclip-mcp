# CLI reference

Run `newsclip --help` or `newsclip COMMAND --help` for the current options.
Global options precede the command. `--version` reports the installed version.

## Remote use

```sh
newsclip --server http://127.0.0.1:8000/users/alice \
  --token-file local/tokens/alice.token search "energy" --source ap --json
```

`NEWSCLIP_URL` and `NEWSCLIP_TOKEN_FILE` provide the same defaults. HTTPS is
required except on loopback. Redirects are not followed, and tokens are sent
only as authorization headers. `--user` selects local storage and cannot be
combined with a remote server URL.

| Command | Behavior |
|---|---|
| `search QUERY` | Search selected or all providers; `--source` repeats; supports limit, date bounds, balanced/newest order and JSON |
| `search QUERY --select N` | Read/save the chosen result; `--no-save` reads transiently |
| `get URL` | Retrieve one verified article without archiving |
| `save URL --out FILE` | Archive the article and export Markdown on the client's filesystem |
| `archive-search QUERY` | Search the user's saved articles offline |
| `archive-get ARTICLE_ID` | Read a saved article offline |
| `reextract ARTICLE_ID` | Re-extract the saved raw bytes |
| `archive-integrity` | Inspect SQLite and foreign-key integrity |
| `archive-rebuild-fts` | Rebuild the user's full-text index |
| `auth connect PROVIDER` | Create a human sign-in link |
| `auth login PROVIDER` | Alias for human connection when using a remote server |
| `auth status PROVIDER` | Read stored session health; does not sign in |

With a terminal and no command, the CLI opens an interactive search reader.
Interactive results support paging, selection and local sorting of loaded
pages. Each source reports failures and available coverage independently.
JSON mode is suitable for scripts; expected failures use stable categories and
nonzero exit codes without raw exception details.

## Local administration

`newsclip --user alice ...` operates on Alice's local data under the configured
state/data roots. Local access is an administrator capability. Backups, restores,
provider diagnostics, session clearing/import and archive drift run on the
server itself; they are not remote client operations.

`users add USER --config FILE --token-file NEW_FILE` creates a user. Add
`--rotate` to replace an existing token. The token is written to a private file
and never displayed. `serve --users-file FILE` starts the multi-user server;
`signin-service --users-file FILE` starts its private browser service. Use the
reference Compose deployment for the required environment and browser policy.

`users add-proxy USER --config FILE` registers an identity that authenticates
only through a configured trusted proxy. Its registry entry has
`"token_sha256": null`; it has no native bearer token. The proxy credential and
verified identity header are both required, and unknown users are refused.

`mcp` serves local stdio MCP. `mcp-http` uses the multi-user server when
`NEWSCLIP_USERS_FILE` is configured; a legacy single-user HTTP deployment uses
its dedicated bearer configuration.
