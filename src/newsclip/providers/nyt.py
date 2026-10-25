"""Configured New York Times provider and compatibility constructors."""

from __future__ import annotations

from ..assessment import document
from ..configured_provider import (
    ConfiguredLoginRecipe,
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..contracts import HttpClient
from ..errors import ProviderTransportError, TransportFailure
from ..models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderSearchPage,
    RawFetch,
    SearchFilters,
    SessionArtifact,
)
from ..provider_config import ProviderSpec, load_provider_spec

# Every other paid provider here is a hard paywall, so a full body is itself
# session evidence. NYT runs a dynamic meter: a logged-out client can receive a
# complete, identity-matching article well over any word floor, and whether it
# does is not deterministic. That state satisfies every FULL condition the
# shared assessment can observe, so the shared assessment alone would certify a
# metered free read as paid access. Requiring an observed session cookie for
# FULL closes that path at the assessment boundary; nyt_auth.py's exact NYT-S
# predicate closes it again at the candidate boundary.
_METERED_WITHOUT_SESSION = "metered_without_session"
_SERVER_ERROR_TITLE = "Server Error - The New York Times"
_SERVER_ERROR_HEADING = "Server Error"


def _is_server_error_page(fetch: RawFetch) -> bool:
    if not 200 <= fetch.http_status < 300 or fetch.content_type is None:
        return False
    media_type = fetch.content_type.partition(";")[0].strip().lower()
    if media_type not in {"text/html", "application/xhtml+xml"}:
        return False
    parsed = document(fetch.raw_html)
    if parsed is None:
        return False
    title = parsed.xpath("normalize-space(string(/html/head/title))")
    heading = parsed.xpath("normalize-space(string((//h1)[1]))")
    return title == _SERVER_ERROR_TITLE and heading == _SERVER_ERROR_HEADING


class _NYTSearchHttpClient:
    """Classify NYT's successful-status outage document after one fetch."""

    def __init__(self, delegate: HttpClient) -> None:
        self._delegate = delegate

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        fetch = self._delegate.get(url, session=session, timeout=timeout)
        if _is_server_error_page(fetch):
            raise ProviderTransportError(
                "NYT search returned its server error page",
                category=TransportFailure.PROVIDER_ERROR,
            )
        return fetch


class NYTProvider(ConfiguredProvider):
    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("nyt")
        super().__init__(selected_spec)
        self.login_recipe = (
            NYTLoginRecipe(verification_url=verification_url, spec=selected_spec)
            if verification_url is not None
            else None
        )

    def search_page(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        # NYT search is public and served real archive results anonymously.
        # Keep discovery anonymous so a paid jar is never spent — or risked —
        # on a boundary that does not need it.
        return super().search_page(
            _NYTSearchHttpClient(http),
            None,
            query,
            filters,
            next_url=next_url,
            metadata_fetch_budget=metadata_fetch_budget,
        )

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        assessment = super().assess(requested_url, fetch, extraction)
        if (
            assessment.access_state is AccessState.FULL
            and not fetch.session_cookie_present
        ):
            return assessment.model_copy(
                update={
                    "access_state": AccessState.UNKNOWN,
                    "reason": _METERED_WITHOUT_SESSION,
                    "negative_markers": (
                        *assessment.negative_markers,
                        _METERED_WITHOUT_SESSION,
                    ),
                }
            )
        return assessment


class NYTLoginRecipe(ConfiguredLoginRecipe):
    def __init__(
        self, *, verification_url: str, spec: ProviderSpec | None = None
    ) -> None:
        selected_spec = spec or load_provider_spec("nyt")
        super().__init__(
            NYTProvider(spec=selected_spec),
            verification_url=verification_url,
            label="NYT",
        )


def build_nyt_provider(spec: ProviderSpec, verification_url: str | None) -> NYTProvider:
    if verification_url is None:
        raise RuntimeError("NYT registration requires a verification URL")
    return NYTProvider(verification_url=verification_url, spec=spec)


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("nyt"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("nyt"), url)


__all__ = [
    "NYTLoginRecipe",
    "NYTProvider",
    "article_id",
    "build_nyt_provider",
    "normalize_article_url",
]
