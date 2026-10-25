"""Synchronous client used by the CLI and third-party Python callers."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .errors import (
    ContentNotFullError,
    OperatorActionRequiredError,
    PersistenceError,
    ProviderTransportError,
    SessionRequiredError,
    UsageError,
)
from .models import (
    ArchiveIntegrity,
    Article,
    ConnectionInfo,
    DoctorReport,
    SearchFilters,
    SearchResponse,
    SessionHealth,
)


class NewsclipClient:
    """One user's server client. A token never selects another user's storage."""

    def __init__(self, url: str, token: str, *, transport=None) -> None:
        parts = urlsplit(url)
        if (
            parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or not parts.hostname
            or not token.strip()
            or (
                parts.scheme != "https"
                and not (
                    parts.scheme == "http"
                    and parts.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
        ):
            raise UsageError("use an HTTPS server URL (or loopback HTTP) and a token")
        self._client = httpx.Client(
            base_url=url.rstrip("/") + "/",
            timeout=120,
            headers={"Authorization": f"Bearer {token.strip()}"},
            follow_redirects=False,
            transport=transport,
        )

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(self, operation: str, **payload):
        if not operation.replace("_", "").isalpha():
            raise UsageError("invalid operation")
        try:
            response = self._client.post(f"api/{operation}", json=payload)
            if response.status_code == 401:
                raise UsageError("server rejected the token or user URL")
            if response.status_code >= 400:
                raise ProviderTransportError("Newsclip server rejected the request")
            data = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise ProviderTransportError("Newsclip server is unavailable") from error
        if not isinstance(data, dict) or "ok" not in data:
            raise ProviderTransportError("invalid Newsclip server response")
        if not data["ok"]:
            errors = {
                "usage": UsageError,
                "operator_action": OperatorActionRequiredError,
                "session_required": SessionRequiredError,
                "content_not_full": ContentNotFullError,
                "persistence": PersistenceError,
            }
            error_type = errors.get(str(data.get("category")), ProviderTransportError)
            # The server's closed vocabulary is safe; raw remote errors are not.
            raise error_type(
                data.get("reason") or data.get("message", "operation failed")
            )
        return data["result"]

    def connect(self, provider: str) -> ConnectionInfo:
        return ConnectionInfo.model_validate(self.request("connect", provider=provider))

    def session_status(self, provider: str) -> SessionHealth:
        return SessionHealth.model_validate(
            self.request("session_status", provider=provider)
        )

    def search_many(
        self,
        query: str,
        filters: SearchFilters | None = None,
        *,
        provider_keys=None,
        acquire_session=None,
    ) -> SearchResponse:
        del acquire_session
        filters = filters or SearchFilters()
        return SearchResponse.model_validate(
            self.request(
                "search",
                query=query,
                filters=filters.model_dump(mode="json"),
                providers=provider_keys,
            )
        )

    def search_pager(
        self,
        query: str,
        filters: SearchFilters | None = None,
        *,
        provider_keys=None,
        acquire_session=None,
    ):
        del acquire_session
        filters = filters or SearchFilters()
        result = self.request(
            "search_start",
            query=query,
            filters=filters.model_dump(mode="json"),
            providers=provider_keys,
        )
        return RemotePager(
            self, result["cursor"], SearchResponse.model_validate(result["page"])
        )

    def get(self, url: str, *, acquire_session=None) -> Article:
        del acquire_session
        return Article.model_validate(self.request("get", url=url))

    def save(
        self, url: str, *, out: Path | None = None, acquire_session=None
    ) -> Article:
        del acquire_session
        article = Article.model_validate(self.request("save", url=url))
        if out is not None:
            from .private_state import atomic_private_write

            out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_private_write(out, (article.body_markdown + "\n").encode())
        return article

    def archive_get(self, article_id: str) -> Article:
        return Article.model_validate(
            self.request("archive_get", article_id=article_id)
        )

    def archive_search(
        self, query: str, *, provider: str | None = None, limit: int = 20
    ) -> list[Article]:
        return [
            Article.model_validate(item)
            for item in self.request(
                "archive_search", query=query, provider=provider, limit=limit
            )
        ]

    def reextract(self, article_id: str) -> Article:
        return Article.model_validate(self.request("reextract", article_id=article_id))

    def archive_integrity(self) -> ArchiveIntegrity:
        return ArchiveIntegrity.model_validate(self.request("archive_integrity"))

    def archive_rebuild_fts(self):
        return ArchiveIntegrity.model_validate(self.request("archive_rebuild_fts"))

    def doctor(self) -> DoctorReport:
        result = self.request("doctor")
        # Public JSON includes derived readiness. Recompute it from typed facts.
        result.pop("browser_ready", None)
        for provider in result.get("provider_readiness", []):
            provider.pop("ready", None)
        return DoctorReport.model_validate(result)

    @property
    def archive_path(self) -> str:
        return "remote server"

    def requires_browser_for_url(self, _url: str) -> bool:
        return False

    def requires_browser_for_provider(self, _provider: str) -> bool:
        return False

    def requires_browser_runtime(self, _providers=None) -> bool:
        return False

    def __getattr__(self, name: str):
        if name in {
            "archive_backup",
            "archive_restore",
            "archive_drift",
            "login",
            "session_checkpoint",
            "reset_session",
            "clear_session",
            "acknowledge_session",
            "reset_browser_profile",
        }:
            raise UsageError(
                "run this administration command locally on the server; "
                "use auth connect to sign in"
            )
        raise AttributeError(name)


class RemotePager:
    def __init__(
        self, client: NewsclipClient, cursor: str, first: SearchResponse
    ) -> None:
        self.client, self.cursor = client, cursor
        self.first: SearchResponse | None = first

    def next_batch(self, limit: int) -> SearchResponse:
        if self.first is not None:
            result, self.first = self.first, None
            return result
        return SearchResponse.model_validate(
            self.client.request("search_next", cursor=self.cursor, limit=limit)
        )


def configured_client() -> NewsclipClient | None:
    url = os.environ.get("NEWSCLIP_URL")
    if not url:
        return None
    token_path = os.environ.get("NEWSCLIP_TOKEN_FILE")
    token = (
        Path(token_path).expanduser().read_text().strip()
        if token_path
        else os.environ.get("NEWSCLIP_TOKEN", "")
    )
    return NewsclipClient(url, token)
