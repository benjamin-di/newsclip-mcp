# Newsclip

Search, read and privately archive news through a command-line interface,
Python API, or MCP server. Newsclip uses your existing subscriptions and public
publisher endpoints. It returns an article only when its identity and full
content pass the provider's verification checks.

Subscription sign-in uses [signin-window](https://github.com/benjamin-di/signin-window):
open a short-lived link and sign in on the publisher's page yourself. Newsclip
keeps the verified session afterwards. It does not need your password in a
configuration file or an assistant conversation.

- Ten built-in providers: Financial Times, WSJ, Bloomberg, CNBC, Reuters,
  The Economist, The New York Times, The Guardian, AP News and Axios.
- Fair federated search with source status, date filters and coverage limits.
- Separate user tokens, sessions, retained browser profiles and SQLite archives.
- Transient reading with `get`; durable storage and Markdown export with `save`.
- Local CLI/Python access and authenticated HTTP/MCP access to the same core.
- MIT-licensed original code, with synthetic tests and no bundled account data.

## Quick start

The reference server runs on Linux AMD64 with Docker Compose. Python 3.12+ and
[uv](https://docs.astral.sh/uv/) are used for setup and the CLI. The sign-in
viewer works in a browser or phone; the browser service itself runs on Linux.

```sh
git clone https://github.com/benjamin-di/newsclip-mcp.git
cd newsclip-mcp
uv sync --locked --extra mcp --extra signin
uv run python scripts/setup.py --user alice --user bob
docker compose up -d
```

Setup writes private token files and configuration without printing secrets.
Each person uses their own URL and token file:

```sh
export NEWSCLIP_URL=http://127.0.0.1:8000/users/alice
export NEWSCLIP_TOKEN_FILE="$PWD/local/tokens/alice.token"

uv run newsclip search "energy markets" --source ap --json
uv run newsclip auth connect ft
# Open the returned link, complete sign-in, then check the session.
uv run newsclip auth status ft --json
uv run newsclip get 'https://www.ft.com/content/<article-id>'
uv run newsclip save 'https://www.ft.com/content/<article-id>' --out article.md
uv run newsclip archive-search "energy" --json
```

`get` does not archive. `save` commits the verified article and can additionally
write a Markdown file on the CLI client's machine. Failed, partial and
unauthorized pages never become archived articles. Use `archive-get ARTICLE_ID`
to read a saved article without contacting its publisher.

The default deployment is reachable only on the server itself. For phone or
remote-client access, configure an HTTPS public origin and reverse proxy as
explained in [deployment](docs/DEPLOYMENT.md).

## Interfaces

For MCP, connect your client to
`http://127.0.0.1:8000/users/alice/mcp` with Alice's bearer token. The server
exposes `search`, `get`, `save`, `archive_search`, `archive_get`, `reextract`,
`session_status`, and `connect`. `connect` returns a human sign-in link; read
operations never submit credentials.

For Python:

```python
from pathlib import Path
from newsclip.client import NewsclipClient

with NewsclipClient(
    "http://127.0.0.1:8000/users/alice",
    Path("local/tokens/alice.token").read_text(),
) as client:
    response = client.search_many("energy markets", provider_keys=["ap"])
    for result in response.results:
        print(result.headline, result.url)
```

The local CLI and synchronous `NewsclipService` are also available without
running an HTTP server. `newsclip --user alice ...` selects isolated local
storage; it is an administrator/local-process option, not remote authorization.
`newsclip mcp` serves local stdio MCP with the same local user's access.

## Providers and limits

See the [provider matrix](docs/PROVIDERS.md) for authentication, search coverage
and retrieval behavior. A supported adapter cannot guarantee that a publisher
will accept every network, account or browser. Articles outside a subscription
are reported as `not_entitled`. Provider failures remain visible beside healthy
search results.

Newsclip is for content you are authorized to access. You supply the necessary
subscriptions and API permissions. It does not purchase access, redistribute
publisher content, or grant rights to that content through its software license.

## Documentation

- [CLI reference](docs/CLI.md) and [Python/HTTP/MCP API](docs/API.md)
- [Sign-in and user isolation](docs/AUTHENTICATION.md)
- [Deployment, configuration, backups and upgrades](docs/DEPLOYMENT.md)
- [Provider support and extension](docs/PROVIDERS.md)
- [Architecture](ARCHITECTURE.md), [development](docs/DEVELOPMENT.md) and [roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and [third-party notices](NOTICE)

## Development

```sh
uv sync --locked --extra mcp --extra signin
uv run patchright install chromium
make check
make check-mcp
```

Offline tests use synthetic content and require no publisher credentials. Live
provider checks are explicit private operator actions and are never run on a
contributor's pull request. Public images and release archives are built from
the public release source.

## License

[MIT](LICENSE) for original code. Dependencies retain their own licenses; see
[NOTICE](NOTICE). Newsclip is not affiliated with the supported publishers.
