# Python, HTTP and MCP APIs

## Python client

`newsclip.client.NewsclipClient(url, token)` is a synchronous context manager.
Give it the user's base URL, including `/users/USER`. Its methods return typed
models: `search_many`, `get`, `save`, `archive_search`, `archive_get`,
`reextract`, `session_status`, `connect` and `archive_integrity`.

`save(url, out=Path(...))` commits remotely, then writes the returned Markdown
locally. Export failure does not undo the server's archive commit. Search uses
`SearchFilters` for limits, date bounds and balanced/newest ordering. Use
`search_pager` and its `next_batch(limit)` method for interactive paging; search
cursors are private to a user and expire after ten minutes.

For in-process applications, `newsclip.composition.build_service()` constructs
the synchronous local core. Close it when finished. The HTTP server uses
`build_mcp_service(user=...)`, which isolates user roots and has no credential
acquisition authority. Direct core calls do not automatically sign in.

## HTTP

POST JSON to `/users/USER/api/OPERATION` with `Authorization: Bearer TOKEN`.
Unknown request fields are rejected, including attempts to supply another user
or storage path. Responses are `{"ok": true, "result": ...}` or the same closed
error envelope exposed by the CLI/MCP adapters. Authentication errors return
401; malformed requests return 400. Request bodies are limited to 64 KiB.

| Operation | JSON fields |
|---|---|
| `search`, `search_start` | `query`, optional `providers`, optional `filters` |
| `search_next` | `cursor`, optional `limit` |
| `get`, `save` | `url` |
| `archive_search` | `query`, optional `provider`, optional `limit` |
| `archive_get`, `reextract` | `article_id` |
| `session_status`, `connect` | `provider` |
| `archive_integrity`, `archive_rebuild_fts`, `providers`, `doctor` | Empty object |

`search_start` returns a cursor and first page. Other search calls return a
`SearchResponse`, including source status and coverage limitations. `/health`
returns readiness without user/account data. Sign-in relay routes use their
own expiring link authority rather than the user's bearer header.

## MCP

Use streamable HTTP at `/users/USER/mcp` with that user's bearer token. Core
operations are `search`, `get`, `save`, `archive_search`, `archive_get`,
`reextract` and `session_status`; the standalone server adds `connect`.
The `save` tool's optional Markdown filename refers to that user's server
export directory. CLI `save --out` instead writes to the client filesystem.

Tool descriptions distinguish transient reads, durable archiving and explicit
re-extraction. Calls never return credentials, cookie exports, raw browser
profiles or diagnostic captures. A session-required failure calls for human
connection; `not_entitled` means renewal will not grant the requested article.
