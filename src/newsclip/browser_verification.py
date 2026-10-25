"""Transport-neutral capture of observed browser verification responses."""

from __future__ import annotations

from contextlib import suppress
from datetime import datetime
from urllib.parse import urlsplit

from pydantic import ValidationError

from .browser_runtime import ObservedNavigation
from .errors import ProviderTransportError
from .models import RawFetch

_HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})


class MainDocumentResponse:
    """Track response/commit pairs while the existing navigation clears a challenge."""

    def __init__(self, page):
        self.page = page
        self.pending = None
        self.current = None
        self.unmatched_commit = False
        self._cdp = None
        self._frame_id = None
        self._loader_id = None
        self._committed_url = None

    def __enter__(self):
        if callable(getattr(self.page, "on", None)):
            self.page.on("response", self._response)
            factory = getattr(
                getattr(self.page, "context", None), "new_cdp_session", None
            )
            if callable(factory):
                try:
                    self._cdp = factory(self.page)
                    self._cdp.on("Page.frameNavigated", self._native_committed)
                    self._cdp.send("Page.enable")
                    frame = self._cdp.send("Page.getFrameTree")["frameTree"]["frame"]
                    self._frame_id = frame["id"]
                except BaseException:
                    self.__exit__()
                    raise
            else:
                self.page.on("framenavigated", self._committed)
        return self

    def __exit__(self, *args):
        remove = getattr(self.page, "remove_listener", None)
        if callable(remove):
            for name, handler in (
                ("response", self._response),
                ("framenavigated", self._committed),
            ):
                with suppress(Exception):
                    remove(name, handler)
        if self._cdp is not None:
            with suppress(Exception):
                self._cdp.detach()

    def _response(self, response):
        try:
            if (
                response.frame is self.page.main_frame
                and response.request.is_navigation_request()
            ):
                self.pending = response
                if self.unmatched_commit and self._committed_url is not None:
                    self._commit(self._committed_url)
        except Exception:
            return

    def _committed(self, frame):
        if frame is not self.page.main_frame:
            return
        self._commit(frame.url)

    def _native_committed(self, event):
        frame = event["frame"]
        if frame.get("id") != self._frame_id:
            return
        # Unlike Patchright's framenavigated event, this excludes History API
        # updates. A document replacement changes Chromium's loader identity.
        self._loader_id = frame["loaderId"]
        self._commit(frame["url"])

    def _commit(self, url):
        self._committed_url = url
        if self.pending is not None and _same_document(self.pending.url, url):
            self.current = self.pending
            self.pending = None
            self.unmatched_commit = False
        else:
            self.unmatched_commit = True

    def select(self, initial):
        if self._cdp is not None:
            frame = self._cdp.send("Page.getFrameTree")["frameTree"]["frame"]
            if (
                self.current is None
                or self.unmatched_commit
                or frame["id"] != self._frame_id
                or frame["loaderId"] != self._loader_id
                or not _same_document(frame["url"], self.page.url)
            ):
                raise ProviderTransportError(
                    "browser response document changed", retryable=False
                )
            return self.current
        response = self.current or initial
        response_url = getattr(response, "url", None)
        if self.unmatched_commit or (
            response_url is not None and not _same_document(response_url, self.page.url)
        ):
            raise ProviderTransportError(
                "browser response document changed", retryable=False
            )
        return response

    def assert_current(self, response):
        if self.select(response) is not response:
            raise ProviderTransportError(
                "browser response document changed", retryable=False
            )


def capture_verification_fetch(
    requested_url: str,
    observed: ObservedNavigation,
    page: object,
    *,
    retrieved_at: datetime,
    session_cookie_present: bool,
) -> RawFetch:
    """Capture rendered HTML only when it belongs to the observed document."""

    if (
        not isinstance(observed.status, int)
        or isinstance(observed.status, bool)
        or not 100 <= observed.status <= 599
    ):
        raise ProviderTransportError("browser verification status is invalid")
    page_url = _page_url(page)
    if not _same_document(observed.response_url, page_url):
        raise ProviderTransportError("browser verification document changed")
    if observed.content_type is not None:
        media_type = observed.content_type.partition(";")[0].strip().lower()
        if media_type not in _HTML_MEDIA_TYPES:
            raise ProviderTransportError("browser verification response is not HTML")
    try:
        content = getattr(page, "content", None)
    except Exception as error:
        raise ProviderTransportError(
            "browser verification content is unavailable"
        ) from error
    if not callable(content):
        raise ProviderTransportError("browser verification content is unavailable")
    try:
        html = content()
    except Exception as error:
        raise ProviderTransportError(
            "browser verification content capture failed"
        ) from error
    if not isinstance(html, str):
        raise ProviderTransportError("browser verification content is invalid")
    final_page_url = _page_url(page)
    if not _same_document(observed.response_url, final_page_url):
        raise ProviderTransportError("browser verification document changed")
    return verification_fetch_from_snapshot(
        requested_url,
        observed,
        document_url=final_page_url,
        raw_html=html.encode("utf-8", "replace"),
        retrieved_at=retrieved_at,
        session_cookie_present=session_cookie_present,
    )


def verification_fetch_from_snapshot(
    requested_url: str,
    observed: ObservedNavigation,
    *,
    document_url: str,
    raw_html: bytes,
    retrieved_at: datetime,
    session_cookie_present: bool,
) -> RawFetch:
    """Build verification evidence from a previously bounded page snapshot."""

    if (
        not isinstance(observed.status, int)
        or isinstance(observed.status, bool)
        or not 100 <= observed.status <= 599
    ):
        raise ProviderTransportError("browser verification status is invalid")
    if not _same_document(observed.response_url, document_url):
        raise ProviderTransportError("browser verification document changed")
    if observed.content_type is not None:
        media_type = observed.content_type.partition(";")[0].strip().lower()
        if media_type not in _HTML_MEDIA_TYPES:
            raise ProviderTransportError("browser verification response is not HTML")
    if not isinstance(raw_html, bytes):
        raise ProviderTransportError("browser verification content is invalid")
    try:
        return RawFetch.model_validate(
            {
                "requested_url": requested_url,
                "final_url": observed.response_url,
                "http_status": observed.status,
                "content_type": observed.content_type,
                "retrieved_at": retrieved_at,
                "session_cookie_present": session_cookie_present,
                "raw_html": raw_html,
            }
        )
    except ValidationError as error:
        raise ProviderTransportError(
            "browser verification response metadata is invalid"
        ) from error


def _same_document(response_url: str, page_url: str) -> bool:
    try:
        response = urlsplit(response_url)
        page = urlsplit(page_url)
        response_port = _effective_port(response.scheme, response.port)
        page_port = _effective_port(page.scheme, page.port)
    except (TypeError, ValueError):
        return False
    if response.scheme not in {"http", "https"} or page.scheme not in {
        "http",
        "https",
    }:
        return False
    if not response.hostname or not page.hostname:
        return False
    return (
        response.scheme.lower(),
        response.hostname.lower(),
        response_port,
        response.path or "/",
        response.query,
    ) == (
        page.scheme.lower(),
        page.hostname.lower(),
        page_port,
        page.path or "/",
        page.query,
    )


def _page_url(page: object) -> str:
    try:
        page_url = getattr(page, "url", None)
    except Exception as error:
        raise ProviderTransportError(
            "browser verification document is unavailable"
        ) from error
    if not isinstance(page_url, str):
        raise ProviderTransportError("browser verification document is unavailable")
    return page_url


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    return {"http": 80, "https": 443}.get(scheme.lower())


__all__ = [
    "capture_verification_fetch",
    "verification_fetch_from_snapshot",
]
