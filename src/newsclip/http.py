"""Selected live HTTP route with lossless portable-cookie loading."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie
from typing import cast
from urllib.parse import urlsplit
from uuid import uuid4

from curl_cffi import requests
from curl_cffi.const import CurlECode, CurlHttpVersion
from curl_cffi.curl import CurlError
from curl_cffi.requests import BrowserTypeLiteral
from curl_cffi.requests.cookies import CookieTypes
from pydantic import ValidationError

from .browser_runtime.events import (
    HttpAttemptEvent,
    HttpAttemptOutcome,
    HttpOperationRole,
    HttpRetryReason,
    HttpRouteMode,
    RuntimeTrace,
)
from .errors import ProviderTransportError, TransportFailure
from .models import (
    DEFAULT_HTTP_IMPERSONATION,
    PortableCookie,
    RawFetch,
    SessionArtifact,
)


@dataclass(frozen=True, slots=True)
class _HttpAttemptContext:
    provider: str
    role: HttpOperationRole
    policy_attempt: int
    retry_reason: HttpRetryReason


_HTTP_ATTEMPT_CONTEXT: ContextVar[_HttpAttemptContext | None] = ContextVar(
    "newsclip_http_attempt_context",
    default=None,
)


@contextmanager
def http_attempt_context(
    provider: str,
    role: HttpOperationRole,
    policy_attempt: int,
    retry_reason: HttpRetryReason,
) -> Iterator[None]:
    """Attach bounded provider-policy facts to one physical HTTP attempt."""

    selected = _HttpAttemptContext(
        provider=provider,
        role=role,
        policy_attempt=policy_attempt,
        retry_reason=retry_reason,
    )
    token = _HTTP_ATTEMPT_CONTEXT.set(selected)
    try:
        yield
    finally:
        _HTTP_ATTEMPT_CONTEXT.reset(token)


class CurlCffiHttpClient:
    """Browser-impersonating HTTP routes with bounded process-lifetime affinity."""

    def __init__(
        self,
        *,
        impersonate: BrowserTypeLiteral = DEFAULT_HTTP_IMPERSONATION,
        impersonate_by_host: Mapping[str, BrowserTypeLiteral] | None = None,
        runtime_impersonate_by_host: Callable[[str], str | None] | None = None,
        headers_by_host: Mapping[str, Callable[[], Mapping[str, str]]] | None = None,
        http_version: CurlHttpVersion | None = None,
        default_headers: bool = True,
        trace: RuntimeTrace | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._impersonate = impersonate
        self._impersonate_by_host = {
            host.lower(): value for host, value in (impersonate_by_host or {}).items()
        }
        # Resolved per request against the runtime pin, so a profile the
        # keeper promotes in another container governs the next fetch this
        # long-lived process makes rather than the next restart (R8).
        self._runtime_impersonate_by_host = runtime_impersonate_by_host
        # Resolved per request, never recorded: a declared host's resolver can
        # attach credential headers (e.g. an API key) without the value ever
        # reaching a URL, the archive, or trace evidence.
        self._headers_by_host = {
            host.lower(): resolver for host, resolver in (headers_by_host or {}).items()
        }
        self._http_version = http_version
        self._default_headers = default_headers
        if any(
            not host or host != host.strip()
            for host in (*self._impersonate_by_host, *self._headers_by_host)
        ):
            raise ValueError("HTTP impersonation hosts must be nonblank hostnames")
        self._routes: dict[tuple[str, ...], _Route] = {}
        self._retired_session_routes: set[tuple[str, ...]] = set()
        self._routes_lock = threading.Lock()
        self._closed = False
        self._trace = trace
        self._clock = clock

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        # Authenticated routes keep one locked Session for cookie affinity.
        # Anonymous routes prefer the shared keep-alive Session, but concurrent
        # callers (Reuters sitemap fan-out) must not serialize behind that lock
        # or a later article save will stall until leftover discovery finishes.
        if session is None:
            return self._anonymous_get(url, timeout=timeout)
        impersonate = self._impersonate_for(url, session=session)
        route = self._route(url, session, impersonate)
        with route.lock:
            if route.retired:
                raise ProviderTransportError(
                    "provider HTTP session generation is retired"
                )
            return self._perform_get(
                url,
                client=route.client,
                timeout=timeout,
                impersonate=impersonate,
                route_mode=HttpRouteMode.AUTHENTICATED_AFFINITY,
                contention=False,
                session_cookie_present=True,
                headers=self._headers_for(url),
                route=route,
            )

    def _anonymous_get(self, url: str, *, timeout: float) -> RawFetch:
        headers = self._headers_for(url)
        # Resolved before the route is chosen: the profile is part of the
        # route identity, so a promoted runtime pin opens a new keep-alive
        # session instead of reusing one still speaking the rotted
        # fingerprint (R8).
        impersonate = self._impersonate_for(url, session=None)
        route = self._route(url, None, impersonate)
        acquired = route.lock.acquire(blocking=False)
        if acquired:
            try:
                # A concurrent promotion may have retired this route between
                # resolving it and taking its lock; its client is closed, so
                # fall through to the ephemeral path rather than sending on a
                # dead session.
                if not route.retired:
                    return self._perform_get(
                        url,
                        client=route.client,
                        timeout=timeout,
                        impersonate=impersonate,
                        route_mode=HttpRouteMode.SHARED_AFFINITY,
                        contention=False,
                        session_cookie_present=False,
                        headers=headers,
                        route=route,
                    )
            finally:
                route.lock.release()

        client = self._new_session(impersonate=impersonate)
        try:
            return self._perform_get(
                url,
                client=client,
                timeout=timeout,
                impersonate=impersonate,
                route_mode=HttpRouteMode.OVERFLOW_EPHEMERAL,
                contention=True,
                session_cookie_present=False,
                headers=headers,
            )
        finally:
            client.close()

    def _headers_for(self, url: str) -> dict[str, str] | None:
        """Resolve declared per-host request headers before dispatch.

        A resolver failure (e.g. an unresolvable API key) propagates before any
        request is made, so no partial attempt is recorded for it.
        """

        if not self._headers_by_host:
            return None
        host = (urlsplit(url).hostname or "").lower()
        resolver = self._headers_by_host.get(host)
        if resolver is None:
            return None
        return dict(resolver())

    def _perform_get(
        self,
        url: str,
        *,
        client: requests.Session,
        timeout: float,
        impersonate: BrowserTypeLiteral,
        route_mode: HttpRouteMode,
        contention: bool,
        session_cookie_present: bool,
        headers: Mapping[str, str] | None = None,
        route: _Route | None = None,
    ) -> RawFetch:
        started = self._clock()
        if route is not None:
            route.request_count += 1
        cookie_before = _cookie_state(client) if self._trace is not None else None
        initial_cookies = route.initial_cookies if route is not None else cookie_before
        request_index = route.request_count if route is not None else 1
        route_id = route.trace_id if route is not None else _route_trace_id()
        generation = route.generation_fingerprint if route is not None else None
        request_cookies_changed = (
            cookie_before != initial_cookies
            if cookie_before is not None and initial_cookies is not None
            else None
        )
        try:
            response = client.get(
                url,
                timeout=timeout,
                allow_redirects=not bool(headers),
                headers=dict(headers) if headers else None,
            )
        except CurlError as error:
            category = _curl_category(error)
            self._record_attempt(
                impersonate=impersonate,
                route_mode=route_mode,
                contention=contention,
                outcome=HttpAttemptOutcome.TRANSPORT_ERROR,
                transport_failure=category,
                duration_ms=max(0.0, (self._clock() - started) * 1000),
                route_request_index=request_index,
                route_id=route_id,
                session_generation_fingerprint=generation,
                request_cookies_changed=request_cookies_changed,
            )
            raise ProviderTransportError(
                "provider HTTP request failed", category=category
            ) from error
        headers = response.headers
        cookie_after = _cookie_state(client) if self._trace is not None else None
        redirects = getattr(response, "redirect_count", None)
        self._record_attempt(
            impersonate=impersonate,
            route_mode=route_mode,
            contention=contention,
            outcome=HttpAttemptOutcome.RESPONSE,
            status=response.status_code,
            duration_ms=max(0.0, (self._clock() - started) * 1000),
            datadome_header_present=headers.get("x-datadome") is not None,
            datadome_cookie_present=_datadome_cookie_present(headers.get("set-cookie")),
            route_request_index=request_index,
            route_id=route_id,
            session_generation_fingerprint=generation,
            request_cookies_changed=request_cookies_changed,
            response_cookies_changed=(
                cookie_before != cookie_after
                if cookie_before is not None and cookie_after is not None
                else None
            ),
            redirected=redirects > 0 if type(redirects) is int else None,
        )
        return _raw_fetch(
            url,
            response,
            session_cookie_present=session_cookie_present,
            serving_transport=str(impersonate),
        )

    def _record_attempt(
        self,
        *,
        impersonate: BrowserTypeLiteral,
        route_mode: HttpRouteMode,
        contention: bool,
        outcome: HttpAttemptOutcome,
        duration_ms: float,
        status: int | None = None,
        transport_failure: TransportFailure | None = None,
        datadome_header_present: bool = False,
        datadome_cookie_present: bool = False,
        route_request_index: int | None = None,
        route_id: str | None = None,
        session_generation_fingerprint: str | None = None,
        request_cookies_changed: bool | None = None,
        response_cookies_changed: bool | None = None,
        redirected: bool | None = None,
    ) -> None:
        context = _HTTP_ATTEMPT_CONTEXT.get()
        if self._trace is None or context is None:
            return
        try:
            event = HttpAttemptEvent(
                provider=context.provider,
                role=context.role,
                policy_attempt=context.policy_attempt,
                retry_reason=context.retry_reason,
                impersonate=str(impersonate),
                route_mode=route_mode,
                contention=contention,
                outcome=outcome,
                status=status,
                transport_failure=transport_failure,
                duration_ms=duration_ms,
                datadome_header_present=datadome_header_present,
                datadome_cookie_present=datadome_cookie_present,
                route_request_index=route_request_index,
                route_id=route_id,
                session_generation_fingerprint=session_generation_fingerprint,
                request_cookies_changed=request_cookies_changed,
                response_cookies_changed=response_cookies_changed,
                redirected=redirected,
            )
        except Exception:
            self._trace.note_diagnostic_loss(
                "event_write",
                provider=context.provider,
            )
            return
        self._trace.try_write(event, provider=context.provider)

    def close(self) -> None:
        """Close every route and permanently retire this client instance."""

        with self._routes_lock:
            if self._closed:
                return
            self._closed = True
            routes = tuple(self._routes.values())
            self._routes.clear()
            self._retired_session_routes.clear()
        for route in routes:
            with route.lock:
                route.client.close()
        if self._trace is not None:
            self._trace.flush_health()

    def __enter__(self) -> CurlCffiHttpClient:
        with self._routes_lock:
            if self._closed:
                raise RuntimeError("HTTP client is closed")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _route(
        self,
        url: str,
        session: SessionArtifact | None,
        impersonate: BrowserTypeLiteral,
    ) -> _Route:
        key = _route_key(url, session, impersonate)
        retired_routes: list[_Route] = []
        with self._routes_lock:
            if self._closed:
                raise RuntimeError("HTTP client is closed")
            if key in self._retired_session_routes:
                raise ProviderTransportError(
                    "provider HTTP session generation is retired"
                )
            route = self._routes.get(key)
            if route is None:
                if session is not None:
                    identity = key[:3]
                    for old_key in tuple(self._routes):
                        if old_key[:3] != identity:
                            continue
                        retired = self._routes.pop(old_key)
                        retired.retired = True
                        retired_routes.append(retired)
                        self._retired_session_routes.add(old_key)
                else:
                    # A promoted runtime pin supersedes this origin's older
                    # profile (R8). Close the superseded route rather than
                    # leaving an idle keep-alive connection open on a
                    # fingerprint just measured dead. Unlike a session
                    # generation, the old key is not blocklisted: a pin may
                    # legitimately be promoted back.
                    for old_key in tuple(self._routes):
                        if old_key[0] != "anonymous" or old_key[1] != key[1]:
                            continue
                        retired = self._routes.pop(old_key)
                        retired.retired = True
                        retired_routes.append(retired)
                client: requests.Session
                if session is not None:
                    client = self._new_session(
                        impersonate=impersonate,
                        cookies=portable_cookie_jar(session.cookies),
                        headers=(
                            {"User-Agent": session.user_agent}
                            if session.user_agent is not None
                            else None
                        ),
                    )
                else:
                    client = self._new_session(impersonate=impersonate)
                route = _Route(
                    client=client,
                    lock=threading.Lock(),
                    generation_fingerprint=(
                        hashlib.sha256(
                            str(session.generation_id).encode("ascii")
                        ).hexdigest()[:12]
                        if session is not None
                        else None
                    ),
                    initial_cookies=_cookie_state(client)
                    if self._trace is not None
                    else None,
                )
                self._routes[key] = route
        for retired in retired_routes:
            with retired.lock:
                retired.client.close()
        return route

    def _new_session(
        self,
        *,
        impersonate: BrowserTypeLiteral,
        cookies: CookieTypes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> requests.Session:
        return requests.Session(
            impersonate=impersonate,
            cookies=cookies,
            headers=headers,
            http_version=self._http_version,
            default_headers=self._default_headers,
        )

    def _impersonate_for(
        self,
        url: str,
        *,
        session: SessionArtifact | None,
    ) -> BrowserTypeLiteral:
        # A session route keeps the default profile so its TLS fingerprint
        # stays coherent with the user agent stored in the artifact; provider
        # configuration rejects a per-host profile for session providers.
        if session is not None:
            return self._impersonate
        host = (urlsplit(url).hostname or "").lower()
        configured = self._impersonate_by_host.get(host, self._impersonate)
        if self._runtime_impersonate_by_host is None:
            return configured
        try:
            runtime = self._runtime_impersonate_by_host(host)
        except Exception:
            # The declared pin is always a valid answer. A resolver fault
            # must never take a retrieval down with it.
            return configured
        if runtime is None:
            return configured
        return cast(BrowserTypeLiteral, runtime)


@dataclass
class _Route:
    client: requests.Session
    lock: threading.Lock
    retired: bool = False
    request_count: int = 0
    trace_id: str = field(default_factory=lambda: _route_trace_id())
    generation_fingerprint: str | None = None
    initial_cookies: frozenset[tuple[object, ...]] | None = field(
        default=None, repr=False
    )


def _route_trace_id() -> str:
    return "http-route-" + uuid4().hex[:16]


def _cookie_state(client: requests.Session) -> frozenset[tuple[object, ...]] | None:
    """Private in-memory comparison only; never serialize names or values."""
    try:
        return frozenset(
            (
                cookie.domain,
                cookie.path,
                cookie.name,
                cookie.value,
                cookie.expires,
                cookie.secure,
            )
            for cookie in client.cookies.jar
        )
    except Exception:
        # Diagnostics must not change request dispatch on an unusual adapter.
        return None


def _raw_fetch(
    url: str,
    response: object,
    *,
    session_cookie_present: bool,
    serving_transport: str | None = None,
) -> RawFetch:
    headers = response.headers  # type: ignore[attr-defined]
    try:
        return RawFetch.model_validate(
            {
                "requested_url": url,
                "final_url": str(response.url),  # type: ignore[attr-defined]
                "http_status": response.status_code,  # type: ignore[attr-defined]
                "content_type": headers.get("content-type"),
                "retry_after": _retry_after(headers.get("retry-after")),
                "retrieved_at": datetime.now(UTC),
                "session_cookie_present": session_cookie_present,
                "serving_transport": serving_transport,
                "raw_html": response.content,  # type: ignore[attr-defined]
            }
        )
    except ValidationError as error:
        raise ProviderTransportError(
            "provider HTTP response metadata is invalid"
        ) from error


def _route_key(
    url: str,
    session: SessionArtifact | None,
    impersonate: BrowserTypeLiteral,
) -> tuple[str, ...]:
    if session is not None:
        # A session route is keyed by its generation, and its profile is
        # fixed by the artifact's user agent — the impersonation never
        # varies within one generation, so it stays out of the key and the
        # generation-retirement prefix match keeps working.
        return (
            "session",
            session.provider,
            session.account_key,
            str(session.generation_id),
        )
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("anonymous HTTP route requires an absolute HTTP URL")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("anonymous HTTP route has an invalid port") from error
    default_port = 443 if parsed.scheme == "https" else 80
    origin = f"{parsed.scheme}://{host}"
    if port is not None and port != default_port:
        origin = f"{origin}:{port}"
    # The profile is part of the anonymous route's identity: a keep-alive
    # session speaks one TLS fingerprint for its whole life, so a promoted
    # pin must land on a fresh route rather than silently reuse the old one.
    return ("anonymous", origin, str(impersonate))


def portable_cookie_jar(
    cookies: tuple[PortableCookie, ...],
) -> requests.Cookies:
    """Load every portable field into curl_cffi's stdlib-compatible jar."""

    jar = requests.Cookies()
    for portable in cookies:
        rest: dict[str, str] = {}
        if portable.http_only:
            rest["HttpOnly"] = ""
        if portable.same_site is not None:
            rest["SameSite"] = portable.same_site
        cookie = Cookie(
            version=0,
            name=portable.name,
            value=portable.value,
            port=None,
            port_specified=False,
            domain=portable.domain,
            domain_specified=bool(portable.domain),
            domain_initial_dot=portable.domain.startswith("."),
            path=portable.path,
            path_specified=True,
            secure=portable.secure,
            expires=int(portable.expires) if portable.expires is not None else None,
            discard=portable.expires is None,
            comment=None,
            comment_url=None,
            rest=rest,
            rfc2109=False,
        )
        jar.jar.set_cookie(cookie)
    return jar


def _curl_category(error: CurlError) -> TransportFailure:
    code = getattr(error, "code", None)
    if code == CurlECode.OPERATION_TIMEDOUT:
        return TransportFailure.TIMEOUT
    if code == CurlECode.COULDNT_RESOLVE_HOST:
        return TransportFailure.DNS
    return TransportFailure.TRANSPORT


def _datadome_cookie_present(value: str | None) -> bool:
    if value is None:
        return False
    return any(
        part.strip().lower().startswith("datadome=")
        for part in value.replace("\r", "").replace("\n", "").split(",")
    )


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
        return max(0.0, seconds) if math.isfinite(seconds) else None
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            return None
        return max(0.0, (when - datetime.now(UTC)).total_seconds())
