"""Authenticated, isolated user applications over the shared Newsclip core."""

from __future__ import annotations

import hmac
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError

from .errors import UsageError
from .mcp_server import (
    McpSuccess,
    NewsclipMcp,
    WorkerDispatcher,
    _http_app,
    _validated_success,
)
from .models import (
    ConnectionInfo,
    DoctorReport,
    FrozenModel,
    SearchFilters,
    SearchResponse,
)
from .results import public_error
from .service import FederatedSearchPager, NewsclipService
from .tenancy import User, load_users, require_user, user_scope


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchStart(FrozenModel):
    cursor: str
    page: SearchResponse

    def public_dict(self):
        return self.model_dump(mode="json")


class Search(Payload):
    query: str = Field(min_length=1, max_length=4096)
    providers: list[str] | None = Field(default=None, max_length=10)
    filters: SearchFilters = Field(default_factory=SearchFilters)


class NextPage(Payload):
    cursor: str = Field(pattern=r"^[A-Za-z0-9_-]{32}$")
    limit: int = Field(default=20, ge=1, le=100)


class Url(Payload):
    url: str = Field(min_length=1, max_length=4096)


class Provider(Payload):
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")


class ArticleId(Payload):
    article_id: str = Field(min_length=1, max_length=256)


class ArchiveQuery(Payload):
    query: str = Field(min_length=1, max_length=4096)
    provider: str | None = None
    limit: int = Field(default=20, ge=1, le=100)


@dataclass
class Pager:
    pager: FederatedSearchPager
    expires: float
    lock: threading.Lock = field(default_factory=threading.Lock)


class SharedWorkerDispatcher(WorkerDispatcher):
    """Bound each user before borrowing from the server-wide worker budget."""

    def __init__(self, shared) -> None:
        super().__init__(capacity=4)
        self._shared = shared

    async def run(self, work):
        from anyio import to_thread

        async with self._limiter:
            return await to_thread.run_sync(work, limiter=self._shared)


def validate_public_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or not parts.hostname
        or (
            parts.path.rstrip("/")
            and re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+/?", parts.path) is None
        )
        or (
            parts.scheme != "https"
            and not (
                parts.scheme == "http"
                and parts.hostname in {"localhost", "127.0.0.1", "::1"}
            )
        )
    ):
        raise ValueError(
            "public URL must use HTTPS (or loopback HTTP) "
            "with a simple optional path prefix"
        )
    return value.rstrip("/")


class UserAuth:
    """A URL selects an application; only its user's bearer grants access."""

    def __init__(self, app: Any, user: User, registry_path: Path, origin: str) -> None:
        self.app, self.user, self.registry_path = app, user, registry_path
        parts = urlsplit(origin)
        self.origin, self.host = f"{parts.scheme}://{parts.netloc}", parts.netloc

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        host_headers = [
            value for name, value in scope.get("headers", ()) if name.lower() == b"host"
        ]
        origin_headers = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == b"origin"
        ]
        if host_headers != [self.host.encode()] or (
            origin_headers and origin_headers != [self.origin.encode()]
        ):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                from starlette.responses import JSONResponse

                await JSONResponse(
                    {"detail": "Origin or host refused"}, status_code=403
                )(scope, receive, send)
            return
        root = scope.get("root_path", "")
        path = scope["path"]
        relative = path[len(root) :] if root and path.startswith(root) else path
        # A relay link carries its own unguessable, expiring authority.
        try:
            current = next(
                (
                    entry
                    for entry in load_users(self.registry_path)
                    if entry.id == self.user.id
                ),
                None,
            )
        except (OSError, ValueError):
            current = None
        if current is not None and relative.startswith("/connect/"):
            await self.app(scope, receive, send)
            return
        headers = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == b"authorization"
        ]
        credential = ""
        if len(headers) == 1:
            scheme, separator, raw = headers[0].partition(b" ")
            if separator and scheme.lower() == b"bearer":
                try:
                    credential = raw.decode("ascii")
                except UnicodeDecodeError:
                    credential = ""
        proxy_token = os.environ.get("NEWSCLIP_TRUSTED_PROXY_TOKEN", "")
        proxy_header = (
            os.environ.get("NEWSCLIP_TRUSTED_USER_HEADER", "X-Authenticated-User")
            .lower()
            .encode("ascii")
        )
        identities = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == proxy_header
        ]
        proxy_ok = bool(
            len(proxy_token) >= 32
            and hmac.compare_digest(credential, proxy_token)
            and identities == [self.user.id.encode("ascii")]
        )
        native_ok = (
            not identities and current is not None and current.accepts(credential)
        )
        if not credential or current is None or not (native_ok or proxy_ok):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                from starlette.responses import JSONResponse

                await JSONResponse(
                    {"detail": "Unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )(scope, receive, send)
            return
        with user_scope(self.user.id):
            await self.app(scope, receive, send)


class ProxyUsers:
    """Map an edge-authenticated user's unprefixed API route to their app.

    UserAuth still validates the proxy credential and selected identity. Direct
    per-user URLs retain their native bearer checks. Sign-in links select their
    user in the URL and do not accept a caller-controlled identity header.
    """

    def __init__(self, app, header: bytes, users: set[str]) -> None:
        self.app, self.header, self.users = app, header, users

    async def __call__(self, scope, receive, send):
        if scope["type"] in {"http", "websocket"} and (
            scope["path"] in {"/mcp", "/mcp/"} or scope["path"].startswith("/api/")
        ):
            values = [
                v for k, v in scope.get("headers", ()) if k.lower() == self.header
            ]
            try:
                identifier = (
                    require_user(values[0].decode("ascii"))
                    if len(values) == 1
                    else None
                )
            except (UnicodeDecodeError, ValueError):
                identifier = None
            if identifier is None or identifier not in self.users:
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    from starlette.responses import JSONResponse

                    await JSONResponse({"detail": "Unauthorized"}, status_code=401)(
                        scope, receive, send
                    )
                return
            scope = dict(scope)
            scope["path"] = f"/users/{identifier}{scope['path']}"
            scope["raw_path"] = scope["path"].encode("utf-8")
        await self.app(scope, receive, send)


def build_standalone_app(
    *,
    users_path: Path | None = None,
    public_url: str | None = None,
    login_url: str | None = None,
    login_token: str | None = None,
    service_factory: Callable[[str], NewsclipService] | None = None,
    backend_factory: Callable[[], Any] | None = None,
):
    from anyio import CapacityLimiter
    from signin_window.client import LoginClient
    from signin_window.page import PageText
    from signin_window.relay import Relay
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    from .composition import build_mcp_service

    registry_path = users_path or Path(os.environ["NEWSCLIP_USERS_FILE"])
    users = load_users(registry_path)
    origin = validate_public_url(
        public_url or os.environ.get("NEWSCLIP_PUBLIC_URL", "http://127.0.0.1:8000")
    )
    login_address = login_url or os.environ.get(
        "NEWSCLIP_LOGIN_URL", "http://newsclip-login:8080"
    )
    secret = login_token or read_login_token()
    if len(secret) < 32:
        raise ValueError("login service token must contain at least 32 characters")
    factory = service_factory or (lambda user: build_mcp_service(user=user))
    applications: list[tuple[Any, NewsclipMcp]] = []
    routes: list[Any] = []
    workers = CapacityLimiter(16)

    def make_user_app(user: User):
        adapter = NewsclipMcp(
            lambda: factory(user.id), dispatcher=SharedWorkerDispatcher(workers)
        )
        adapter.prepare()
        server = adapter.build_server()
        backend = (
            backend_factory() if backend_factory else LoginClient(login_address, secret)
        )
        relay = Relay(
            backend,
            f"{origin}/users/{user.id}/connect",
            text=PageText(service="Newsclip"),
        )
        pagers: OrderedDict[str, Pager] = OrderedDict()
        pager_lock = threading.Lock()

        def connection(provider: str) -> ConnectionInfo:
            selected = adapter._service_ready()._registry.get(provider)
            if selected.login_recipe is None:
                raise UsageError("this provider does not require sign-in")
            link = relay.create(
                provider,
                params={"user": user.id, "provider": provider},
                label=provider.upper(),
            )
            return ConnectionInfo(
                url=HttpUrl(link.url),
                expires_at=datetime.fromisoformat(link.expires_at),
                provider=provider,
            )

        @server.tool(title="Connect a news subscription")
        async def connect(provider: str) -> McpSuccess[ConnectionInfo]:
            """Return an expiring link for the person to sign in themselves.

            Give the link to the person. Never enter passwords or verification
            codes. Completion establishes a session, not article entitlement.
            Use session_status afterwards, then retry the requested article.
            """
            return _validated_success(
                await adapter._call("connect", lambda _service: connection(provider)),
                McpSuccess[ConnectionInfo],
            )

        async def api(request: Request):
            operation = request.path_params["operation"]
            raw = bytearray()
            async for part in request.stream():
                raw.extend(part)
                if len(raw) > 65536:
                    return JSONResponse(
                        {"detail": "Request too large"}, status_code=413
                    )
            import json

            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("object required")
                if operation in {"search", "search_start"}:
                    args = Search.model_validate(payload)

                    def search(service):
                        if operation == "search":
                            return service.search_many(
                                args.query, args.filters, provider_keys=args.providers
                            )
                        pager = service.search_pager(
                            args.query, args.filters, provider_keys=args.providers
                        )
                        first = pager.next_batch(args.filters.limit)
                        cursor = token_urlsafe(24)
                        with pager_lock:
                            now = time.monotonic()
                            for key in list(pagers):
                                if pagers[key].expires <= now:
                                    del pagers[key]
                            while len(pagers) >= 16:
                                pagers.popitem(last=False)
                            pagers[cursor] = Pager(pager, now + 600)
                        return SearchStart(cursor=cursor, page=first)

                    value = await adapter._call(operation, search)
                elif operation == "search_next":
                    next_args = NextPage.model_validate(payload)

                    def next_page(_service):
                        with pager_lock:
                            saved = pagers.get(next_args.cursor)
                            if saved is None or saved.expires <= time.monotonic():
                                raise UsageError("search expired; start a new search")
                        with saved.lock:
                            return saved.pager.next_batch(next_args.limit)

                    value = await adapter._call(operation, next_page)
                elif operation in {"get", "save"}:
                    url_args = Url.model_validate(payload)
                    value = await getattr(adapter, operation)(url_args.url)
                elif operation in {"connect", "session_status"}:
                    provider_args = Provider.model_validate(payload)
                    value = await (
                        adapter._call(
                            "connect",
                            lambda _service: connection(provider_args.provider),
                        )
                        if operation == "connect"
                        else adapter.session_status(provider_args.provider)
                    )
                elif operation in {"archive_get", "reextract"}:
                    article_args = ArticleId.model_validate(payload)
                    value = await getattr(adapter, operation)(article_args.article_id)
                elif operation == "archive_search":
                    archive_args = ArchiveQuery.model_validate(payload)
                    value = await adapter._call(
                        operation,
                        lambda service: service.archive_search(
                            archive_args.query,
                            provider=archive_args.provider,
                            limit=archive_args.limit,
                        ),
                    )
                elif operation in {"archive_integrity", "archive_rebuild_fts"}:
                    Payload.model_validate(payload)
                    value = await adapter._call(
                        operation, lambda service: getattr(service, operation)()
                    )
                elif operation == "providers":
                    Payload.model_validate(payload)
                    value = {
                        "ok": True,
                        "result": [
                            provider.key
                            for provider in adapter._service_ready()._registry
                        ],
                    }
                elif operation == "doctor":
                    from shutil import which

                    from .provider_readiness import browser_engine_available

                    Payload.model_validate(payload)

                    def report(service):
                        registry = service._registry
                        return DoctorReport(
                            providers=tuple(provider.key for provider in registry),
                            browser_providers=tuple(
                                provider.key
                                for provider in registry
                                if provider.login_recipe is not None
                                or provider.capabilities.retrieval_transport
                                == "browser"
                                or provider.capabilities.search_transport == "browser"
                            ),
                            browser_engine_available=browser_engine_available(),
                            virtual_display_active=bool(os.environ.get("DISPLAY")),
                            host_xvfb_available=which("Xvfb") is not None,
                            docker_fallback_available=False,
                        )

                    value = await adapter._call("doctor", report)

                else:
                    return JSONResponse({"detail": "Not found"}, status_code=404)
            except (ValidationError, ValueError):
                return JSONResponse({"detail": "Invalid request"}, status_code=400)
            except Exception as error:
                envelope = public_error(error)
                if envelope is not None:
                    return JSONResponse(envelope.public_dict())
                return JSONResponse({"detail": "Operation failed"}, status_code=500)
            return JSONResponse(value, headers={"Cache-Control": "no-store"})

        parts = urlsplit(origin)
        host, browser_origin = parts.netloc, f"{parts.scheme}://{parts.netloc}"
        app = _http_app(server, allowed_hosts=[host], allowed_origins=[browser_origin])
        app.routes.extend(relay.routes("/connect"))
        app.routes.append(Route("/api/{operation}", api, methods=["POST"]))
        applications.append((app, adapter))
        return UserAuth(app, user, registry_path, origin)

    for user in users:
        routes.append(Mount(f"/users/{user.id}", app=make_user_app(user)))

    async def health(_request: Request):
        return JSONResponse({"status": "ok", "service": "newsclip"})

    @asynccontextmanager
    async def lifespan(_app):
        try:
            async with AsyncExitStack() as stack:
                for app, _adapter in applications:
                    await stack.enter_async_context(app.router.lifespan_context(app))
                yield
        finally:
            for _app, adapter in applications:
                adapter._service_ready().close()

    routes.append(Route("/health", health))
    application = Starlette(routes=routes, lifespan=lifespan)
    proxy_token = os.environ.get("NEWSCLIP_TRUSTED_PROXY_TOKEN", "")
    if proxy_token:
        if len(proxy_token) < 32:
            raise ValueError("trusted proxy token must contain at least 32 characters")
        header = os.environ.get("NEWSCLIP_TRUSTED_USER_HEADER", "X-Authenticated-User")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", header) is None:
            raise ValueError("trusted user header is invalid")
        return ProxyUsers(
            application, header.lower().encode("ascii"), {user.id for user in users}
        )
    return application


def read_login_token() -> str:
    path = os.environ.get("NEWSCLIP_LOGIN_TOKEN_FILE")
    return (
        Path(path).read_text().strip()
        if path
        else os.environ.get("NEWSCLIP_LOGIN_TOKEN", "").strip()
    )


def run_server(*, host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    from .browser_runtime.surface import ensure_virtual_display

    ensure_virtual_display()

    uvicorn.run(
        build_standalone_app(),
        host=host,
        port=port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
    )
