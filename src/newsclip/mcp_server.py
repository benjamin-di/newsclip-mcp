"""Authenticated MCP adapters over the synchronous Newsclip core.

The adapter is a thin surface: it re-presents seven bounded service operations,
never adds business rules, and never widens the trust boundary. It
does **not** expose login, cookie import/export, session clearing, raw fetches,
or profile operations. The stdio entry point opens no listener; the separate
HTTP entry point requires a dedicated bearer token on every MCP request.

Blocking core calls run through an AnyIO capacity limiter so a slow provider
fetch cannot starve the event loop or exceed a fixed worker-thread bound. The
SessionStore lock and provider rate budgets remain the cross-process and network
authorities; the limiter only bounds in-process concurrency.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

from anyio import CapacityLimiter, to_thread
from pydantic import BaseModel, Field

from .errors import PersistenceError, UsageError
from .models import (
    ArchiveSearchHit,
    Article,
    FrozenModel,
    SearchFilters,
    SearchResponse,
    SearchSort,
    SessionHealth,
)
from .provider_keys import PROVIDER_KEY_PATTERN
from .providers.builtins import BUILTIN_PROVIDER_KEYS_PROSE
from .results import PublicErrorEnvelope, public_error, public_value
from .service import NewsclipService
from .timing import timing_invocation

OPS_ENV = "NEWSCLIP_MCP_OPS"
WORKER_CAPACITY = 4
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8000
BEARER_TOKEN_ENV = "NEWSCLIP_MCP_BEARER_TOKEN"
SERVER_INSTRUCTIONS = (
    "Use search for current provider discovery, then get for transient full text "
    "or save when the user wants persistence. Use archive_search and archive_get "
    "only for previously saved content. session_status only reads stored state and "
    "never logs in or verifies access online. Call reextract only when the user "
    "explicitly asks to update an archived extraction. Built-in provider keys are "
    f"{BUILTIN_PROVIDER_KEYS_PROSE}. This server never performs "
    "login; a session_required result requires operator action outside MCP."
)
SearchQuery = Annotated[
    str,
    Field(
        min_length=1,
        max_length=500,
        description="Current-news search terms; whitespace-only input is invalid.",
    ),
]
ArchiveQuery = Annotated[
    str,
    Field(
        min_length=1,
        max_length=500,
        description="Full-text terms to match only against previously saved articles.",
    ),
]
ProviderKey = Annotated[
    str,
    Field(
        min_length=1,
        max_length=32,
        pattern=PROVIDER_KEY_PATTERN,
        description=(
            f"Configured provider key; built-ins are {BUILTIN_PROVIDER_KEYS_PROSE}."
        ),
    ),
]
ProviderSelection = Annotated[
    list[ProviderKey],
    Field(
        min_length=1,
        description="Providers to search; omit to search every configured provider.",
    ),
]
SearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=100,
        description="Maximum current-news results to return; defaults to 20.",
    ),
]
SearchSortOption = Annotated[
    SearchSort,
    Field(
        description=(
            "Result order: balanced preserves the fair provider-rank merge; "
            "newest reorders only this bounded result batch by publication time."
        )
    ),
]
ArchiveSearchLimit = Annotated[
    int,
    Field(
        ge=1,
        le=100,
        description="Maximum archived-article summaries to return; defaults to 20.",
    ),
]
ArticleUrl = Annotated[
    str,
    Field(
        min_length=1,
        max_length=4096,
        pattern=r"^https://",
        description=(
            "Canonical article URL from a configured provider, supplied by the "
            "user or returned by search; never invent a URL."
        ),
    ),
]
PublishedAfter = Annotated[
    datetime,
    Field(
        description=(
            "Inclusive timezone-aware ISO-8601 lower publication bound; results "
            "without a known date are excluded."
        )
    ),
]
PublishedBefore = Annotated[
    datetime,
    Field(
        description=(
            "Inclusive timezone-aware ISO-8601 upper publication bound; results "
            "without a known date are excluded."
        )
    ),
]
MarkdownFilename = Annotated[
    str,
    Field(
        min_length=3,
        max_length=255,
        description=(
            "Optional plain .md basename for a server-side export; no path or "
            "client filesystem location."
        ),
    ),
]
ArchiveArticleId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        description="Stable archive ID returned by save or archive_search.",
    ),
]
MCP_EXPORT_DIRECTORY = "exports"

#: The only operations the local agent surface exposes. Anything mutating the
#: credential/session boundary is deliberately absent.
EXPOSED_TOOLS = (
    "search",
    "get",
    "save",
    "archive_search",
    "archive_get",
    "session_status",
    "reextract",
)

#: Operations that must never appear on the MCP serving surface.
FORBIDDEN_TOOLS = (
    "login",
    "import_cookies",
    "session_clear",
    "session_reset",
    "session_acknowledge",
    "session_checkpoint",
)


class McpSuccess[ResultT](FrozenModel):
    """Typed successful MCP payload; failures use native ``isError`` results."""

    ok: Literal[True] = True
    result: ResultT


def _validated_success[SuccessModelT: BaseModel](
    payload: dict[str, object],
    model: type[SuccessModelT],
) -> SuccessModelT:
    if payload.get("ok") is not True:
        envelope = PublicErrorEnvelope.model_validate(payload)
        # Emit the same trimmed envelope the structured result carries,
        # so the native error text never publishes unnamed refinements.
        # A ToolError is the one exception FastMCP passes to the client with
        # its message while masking every other (mask_error_details=True):
        # carry only the stable, redacted public envelope through it.
        from fastmcp.exceptions import ToolError

        # NewsclipMcp._call already logged this product failure with its
        # closed fields; FastMCP's generic ERROR line would add nothing.
        raise ToolError(
            json.dumps(envelope.public_dict(), separators=(",", ":")),
            log_level=logging.DEBUG,
        )
    return model.model_validate(payload)


def _log_tool_failure(tool: str, envelope: PublicErrorEnvelope) -> None:
    """Log one line per failed call from closed public fields only.

    Never log the request (URLs can carry tokens), the raw exception, or
    content: the envelope is already the redacted public contract. The
    logger nests under FastMCP's so the serving process emits it with the
    same handler and level as the rest of its log.
    """

    logging.getLogger("fastmcp.newsclip.mcp").log(
        logging.INFO if envelope.category.value == "usage" else logging.WARNING,
        "tool failed tool=%s category=%s reason=%s incident_id=%s diagnostic_id=%s",
        tool,
        envelope.category.value,
        envelope.reason.value if envelope.reason is not None else "-",
        envelope.incident_id or "-",
        envelope.diagnostic_id or "-",
    )


def _archive_search_hit(article: Article) -> ArchiveSearchHit:
    return ArchiveSearchHit(
        id=article.id,
        provider=article.provider,
        url=article.canonical_url,
        headline=article.headline,
        published=article.published,
        section=article.section,
        word_count=article.word_count,
        retrieved_at=article.retrieved_at,
    )


class WorkerDispatcher:
    """Run blocking callables under a fixed worker-thread concurrency bound."""

    def __init__(self, capacity: int = WORKER_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("worker capacity must be at least one")
        self._limiter = CapacityLimiter(capacity)

    @property
    def capacity(self) -> int:
        return int(self._limiter.total_tokens)

    @property
    def in_flight(self) -> int:
        """Threads currently borrowed — never exceeds ``capacity``."""

        return int(self._limiter.borrowed_tokens)

    async def run(self, work: Callable[[], object]) -> object:
        return await to_thread.run_sync(work, limiter=self._limiter)


class NewsclipMcp:
    """Assemble the exposed tools over a lazily-built service."""

    def __init__(
        self,
        service_factory: Callable[[], NewsclipService],
        *,
        capacity: int = WORKER_CAPACITY,
        dispatcher: WorkerDispatcher | None = None,
    ) -> None:
        self._service_factory = service_factory
        self._service: NewsclipService | None = None
        self._service_lock = threading.Lock()
        self._dispatcher = dispatcher or WorkerDispatcher(capacity)

    @property
    def dispatcher(self) -> WorkerDispatcher:
        return self._dispatcher

    def _service_ready(self) -> NewsclipService:
        if self._service is None:
            with self._service_lock:
                if self._service is None:
                    self._service = self._service_factory()
        return self._service

    def prepare(self) -> None:
        """Eagerly prove that the remote service can initialize its state."""

        self._service_ready()

    async def _call(
        self, tool: str, work: Callable[[NewsclipService], object]
    ) -> dict[str, object]:
        # Service construction happens inside the guarded region: a broken
        # environment (state dirs, archive) must fail with the same stable
        # {ok, category, exit_code} envelope as any other product error,
        # not leak a raw factory exception through the transport.
        invocation_id = f"mcp-{uuid4().hex}"
        try:

            def invoke() -> object:
                with timing_invocation(invocation_id):
                    return work(self._service_ready())

            value = await self._dispatcher.run(invoke)
        except Exception as error:  # noqa: BLE001 - mapped to a stable category
            envelope = public_error(error)
            if envelope is None:
                raise
            envelope = envelope.model_copy(update={"diagnostic_id": invocation_id})
            _log_tool_failure(tool, envelope)
            return envelope.public_dict()
        return {"ok": True, "result": public_value(value)}

    async def search(
        self,
        query: SearchQuery,
        providers: ProviderSelection | None = None,
        limit: SearchLimit = 20,
        published_after: PublishedAfter | None = None,
        published_before: PublishedBefore | None = None,
        sort: SearchSortOption = SearchSort.BALANCED,
    ) -> dict[str, object]:
        provider_keys = None if providers is None else tuple(providers)
        return await self._call(
            "search",
            lambda service: service.search_many(
                query,
                SearchFilters(
                    limit=limit,
                    published_after=published_after,
                    published_before=published_before,
                    sort=sort,
                ),
                provider_keys=provider_keys,
            ),
        )

    async def get(self, url: ArticleUrl) -> dict[str, object]:
        return await self._call("get", lambda service: service.get(url))

    async def save(
        self,
        url: ArticleUrl,
        markdown_filename: MarkdownFilename | None = None,
    ) -> dict[str, object]:
        def save_article(service: NewsclipService) -> object:
            if markdown_filename is None:
                return service.save(url)
            destination = _markdown_export_path(service, markdown_filename)
            return service.save(url, out=destination)

        return await self._call("save", save_article)

    async def archive_search(
        self,
        query: ArchiveQuery,
        provider: ProviderKey | None = None,
        limit: ArchiveSearchLimit = 20,
    ) -> dict[str, object]:
        def find(service: NewsclipService) -> object:
            articles = service.archive_search(
                query,
                provider=provider,
                limit=limit,
            )
            return [_archive_search_hit(article) for article in articles]

        return await self._call("archive_search", find)

    async def archive_get(self, article_id: ArchiveArticleId) -> dict[str, object]:
        return await self._call(
            "archive_get", lambda service: service.archive_get(article_id)
        )

    async def session_status(self, provider: ProviderKey) -> dict[str, object]:
        return await self._call(
            "session_status", lambda service: service.session_status(provider)
        )

    async def reextract(self, article_id: ArchiveArticleId) -> dict[str, object]:
        return await self._call(
            "reextract", lambda service: service.reextract(article_id)
        )

    def build_server(self, name: str = "newsclip"):
        """Register the exposed tools on a FastMCP server.

        Importing FastMCP is deferred to here so ``import newsclip.mcp_server``
        (and the wider package) does not require the optional ``mcp`` extra until
        a server is actually built. Transport settings live in ``_http_app``.
        """

        from mcp.types import ToolAnnotations

        server = new_fastmcp(name, instructions=SERVER_INSTRUCTIONS)

        @server.tool(
            title="Search current news",
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=True,
            ),
        )
        async def search(
            query: SearchQuery,
            providers: ProviderSelection | None = None,
            limit: SearchLimit = 20,
            published_after: PublishedAfter | None = None,
            published_before: PublishedBefore | None = None,
            sort: SearchSortOption = SearchSort.BALANCED,
        ) -> McpSuccess[SearchResponse]:
            """Find current articles across the configured providers.

            Use for live discovery, not saved archive content. Returns one
            stateless batch of ranked result metadata, URLs, and per-source
            health—not article bodies. Under a date bound, results with an
            unknown date are withheld and counted per source. It may contact
            providers but never logs in.
            """

            return _validated_success(
                await self.search(
                    query,
                    providers,
                    limit,
                    published_after,
                    published_before,
                    sort,
                ),
                McpSuccess[SearchResponse],
            )

        @server.tool(
            title="Read current article",
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=True,
            ),
        )
        async def get(url: ArticleUrl) -> McpSuccess[Article]:
            """Fetch one current verified full article without archiving it.

            Use a URL supplied by the user or returned by search. This contacts
            the provider, requires existing session state where applicable, and
            never logs in. A proven-expired session may be marked as required.
            Reason not_entitled means the session verified but the article is
            outside the subscription; do not retry or request renewal.
            """

            return _validated_success(await self.get(url), McpSuccess[Article])

        @server.tool(
            title="Save current article",
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=True,
                idempotent_hint=False,
                open_world_hint=True,
            ),
        )
        async def save(
            url: ArticleUrl,
            markdown_filename: MarkdownFilename | None = None,
        ) -> McpSuccess[Article]:
            """Fetch and persist one verified full article.

            Use when the user wants durable archive storage, not a transient
            read. An optional Markdown basename is written (atomically, replacing
            a same-named file) to the server's private exports directory, not the
            client's filesystem. Never logs in. Reason not_entitled means the
            article is outside the subscription; do not retry.
            """

            return _validated_success(
                await self.save(url, markdown_filename),
                McpSuccess[Article],
            )

        @server.tool(
            title="Search saved articles",
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        )
        async def archive_search(
            query: ArchiveQuery,
            provider: ProviderKey | None = None,
            limit: ArchiveSearchLimit = 20,
        ) -> McpSuccess[list[ArchiveSearchHit]]:
            """Find previously saved articles without contacting providers.

            Returns bounded summaries without article bodies. Use archive_get
            with a returned article ID to read one complete saved article. Do not
            use this tool for current-news discovery.
            """

            return _validated_success(
                await self.archive_search(query, provider, limit),
                McpSuccess[list[ArchiveSearchHit]],
            )

        @server.tool(
            title="Read saved article",
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        )
        async def archive_get(
            article_id: ArchiveArticleId,
        ) -> McpSuccess[Article]:
            """Read one complete previously saved article offline.

            Use an article ID returned by save or archive_search. This does not
            contact a provider, re-extract content, or modify the archive.
            """

            return _validated_success(
                await self.archive_get(article_id),
                McpSuccess[Article],
            )

        @server.tool(
            title="Inspect session status",
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        )
        async def session_status(provider: ProviderKey) -> McpSuccess[SessionHealth]:
            """Read redacted stored session health for one provider.

            This does not contact the provider, verify access online, refresh a
            session, or perform login.
            """

            return _validated_success(
                await self.session_status(provider),
                McpSuccess[SessionHealth],
            )

        @server.tool(
            title="Update archived extraction",
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=True,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        )
        async def reextract(article_id: ArchiveArticleId) -> McpSuccess[Article]:
            """Recompute and save an archived article's current extraction.

            Maintenance only: use when the user explicitly asks to update an
            extraction. Reads stored raw bytes with the installed extractor; no
            network request; not an article-read tool.
            """

            return _validated_success(
                await self.reextract(article_id),
                McpSuccess[Article],
            )

        return server


def _markdown_export_path(service: NewsclipService, filename: str) -> Path:
    """Resolve one untrusted MCP filename inside the private server data root."""

    if (
        not filename
        or filename != filename.strip()
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or any(ord(character) < 32 or ord(character) == 127 for character in filename)
        or Path(filename).is_absolute()
        or Path(filename).suffix.casefold() != ".md"
    ):
        raise UsageError("markdown filename must be a plain .md filename")

    export_root = service.archive_path.parent / MCP_EXPORT_DIRECTORY
    try:
        export_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if export_root.is_symlink() or not export_root.is_dir():
            raise PersistenceError("MCP export root is not a private directory")
        os.chmod(export_root, 0o700)
    except OSError as error:
        raise PersistenceError("MCP export root is unavailable") from error
    return export_root / filename


def build_mcp() -> NewsclipMcp:
    """Compose the MCP adapter over the default product service."""

    from .composition import build_mcp_service

    return NewsclipMcp(build_mcp_service)


def run_stdio() -> None:  # pragma: no cover - process entry point
    """Serve the local stdio MCP surface. Opens no network listener."""

    build_mcp().build_server().run(transport="stdio")


class BearerAuthMiddleware:
    """Require one header-only bearer token for every non-health HTTP request."""

    def __init__(self, app: Any, bearer_token: str) -> None:
        token = bearer_token.strip()
        if not token:
            raise ValueError(f"{BEARER_TOKEN_ENV} must not be empty")
        self._app = app
        self._expected = token.encode()

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        is_health = (
            scope["method"] == "GET"
            and scope["path"] == "/health"
            and not scope.get("query_string")
        )
        if is_health:
            await self._app(scope, receive, send)
            return

        authorization = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == b"authorization"
        ]
        offered = b""
        if len(authorization) == 1:
            scheme, separator, credential = authorization[0].partition(b" ")
            if separator and scheme.lower() == b"bearer":
                offered = credential.strip()
        if not offered or not hmac.compare_digest(offered, self._expected):
            from starlette.responses import JSONResponse

            response = JSONResponse(
                {"detail": "Unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self._app(scope, receive, send)


def _allowed_hosts() -> list[str]:
    return [
        value.strip()
        for value in os.environ.get(
            "NEWSCLIP_MCP_ALLOWED_HOSTS",
            (
                "127.0.0.1,127.0.0.1:*,localhost,localhost:*,"
                "newsclip-mcp,newsclip-mcp:*,newsclip-ops,newsclip-ops:*,"
                "host.docker.internal,host.docker.internal:*"
            ),
        ).split(",")
        if value.strip()
    ]


def new_fastmcp(name: str, *, instructions: str):
    """A FastMCP 4 server with the settings every Newsclip surface shares."""

    from fastmcp import FastMCP

    return FastMCP(
        name,
        instructions=instructions,
        # Product errors already return the stable {ok, category} envelope;
        # anything else is unexpected and must not leak its raw text.
        mask_error_details=True,
        # Tool lists only change on deploy: 10-minute private cache hint for
        # clients on the 2026-07-28 protocol.
        cache_ttl=600,
    )


def _http_app(
    server: Any,
    *,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
) -> Any:
    """Stateless JSON streamable HTTP with strict Host/Origin validation."""

    origins = os.environ.get("NEWSCLIP_MCP_ALLOWED_ORIGINS")

    return server.http_app(
        stateless_http=True,
        json_response=True,
        host_origin_protection=True,
        allowed_hosts=_allowed_hosts() if allowed_hosts is None else allowed_hosts,
        allowed_origins=allowed_origins
        if allowed_origins is not None
        else ([entry.strip() for entry in origins.split(",")] if origins else []),
    )


def build_http_app(
    *,
    service_factory: Callable[[], NewsclipService] | None = None,
    bearer_token: str | None = None,
):
    """Build the authenticated, stateless streamable-HTTP application.

    Service composition is deliberately eager here: a broken state mount or
    incompatible archive schema must fail process startup instead of producing
    a healthy listener that fails every tool call.
    """

    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    token = (
        os.environ.get(BEARER_TOKEN_ENV, "") if bearer_token is None else bearer_token
    ).strip()

    if os.environ.get(OPS_ENV, "").strip() == "1":
        from .ops_server import build_ops_app

        return build_ops_app(token)

    if not token:
        raise ValueError(f"{BEARER_TOKEN_ENV} must be set")

    if service_factory is None:
        from .composition import build_mcp_service

        service_factory = build_mcp_service
    adapter = NewsclipMcp(service_factory)
    adapter.prepare()
    server = adapter.build_server()

    @server.custom_route(
        "/health",
        methods=["GET"],
        name="health",
        include_in_schema=False,
    )
    async def health(_request: Request) -> Response:
        return JSONResponse({"status": "ok", "service": "newsclip"})

    return BearerAuthMiddleware(_http_app(server), token)


def run_http(
    *,
    host: str | None = None,
    port: int | None = None,
) -> None:  # pragma: no cover - process entry point
    """Serve the authenticated streamable-HTTP MCP surface."""

    import uvicorn

    resolved_host = host or os.environ.get("NEWSCLIP_MCP_HOST", DEFAULT_HTTP_HOST)
    if port is None:
        try:
            resolved_port = int(
                os.environ.get("NEWSCLIP_MCP_PORT", str(DEFAULT_HTTP_PORT))
            )
        except ValueError as error:
            raise ValueError("NEWSCLIP_MCP_PORT must be an integer") from error
    else:
        resolved_port = port
    if not 1 <= resolved_port <= 65535:
        raise ValueError("NEWSCLIP_MCP_PORT must be between 1 and 65535")

    log_level = os.environ.get("NEWSCLIP_LOG_LEVEL", "info").lower()
    uvicorn.run(
        build_http_app(),
        host=resolved_host,
        port=resolved_port,
        log_level=log_level,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )


__all__ = [
    "EXPOSED_TOOLS",
    "FORBIDDEN_TOOLS",
    "SERVER_INSTRUCTIONS",
    "WORKER_CAPACITY",
    "BEARER_TOKEN_ENV",
    "BearerAuthMiddleware",
    "NewsclipMcp",
    "WorkerDispatcher",
    "build_http_app",
    "build_mcp",
    "run_http",
    "run_stdio",
]
