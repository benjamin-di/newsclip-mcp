"""CNBC provider using the public Queryly search surface."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urlsplit

from pydantic import HttpUrl

from ..articles import parse_aware_datetime
from ..assessment import search_json_object
from ..configured_provider import (
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..contracts import HttpClient
from ..errors import ProviderContractError
from ..models import ProviderSearchPage, SearchFilters, SearchResult, SessionArtifact
from ..provider_config import ProviderSpec, load_provider_spec

_QUERYLY_KEY = "31a35d40a9a64ab3"
_ADDITIONAL_INDEXES = (
    "4cd6f71fbf22424d,937d600b0d0d4e23,3bfbe40caee7443e,626fdfcd96444f28"
)
_PAGE_SIZE = 20
_MAX_RESULTS = 200
_SEARCH_TIMEOUT_SECONDS = 10
_MAX_SEARCH_URL_LENGTH = 4096


class CNBCProvider(ConfiguredProvider):
    def __init__(self, *, spec: ProviderSpec | None = None) -> None:
        selected_spec = spec or load_provider_spec("cnbc")
        if selected_spec.key != "cnbc":
            raise ValueError("CNBC provider requires its own definition")
        super().__init__(selected_spec)
        self._search = selected_spec.require_adapter_search()

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
        endpoint = str(self._search.endpoint)
        search_url = next_url or _build_search_url(endpoint, query, offset=0)
        offset = _validate_search_url(search_url, query, endpoint=endpoint)
        fetch = http.get(
            search_url,
            session=None,
            timeout=_SEARCH_TIMEOUT_SECONDS,
        )
        if (
            _validate_search_url(str(fetch.final_url), query, endpoint=endpoint)
            != offset
        ):
            raise ProviderContractError("provider search response identity mismatch")
        payload = search_json_object(fetch)
        metadata = payload.get("metadata")
        raw_results = payload.get("results")
        if not isinstance(metadata, Mapping) or not isinstance(raw_results, list):
            raise ProviderContractError("provider search JSON schema changed")
        total = metadata.get("totalresults")
        page_size = metadata.get("pagesize")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or page_size != _PAGE_SIZE
        ):
            raise ProviderContractError("provider search metadata schema changed")

        results: list[SearchResult] = []
        observed_dates: list[datetime] = []
        for item in raw_results:
            if not isinstance(item, Mapping):
                raise ProviderContractError("provider search result schema changed")
            raw_url = item.get("cn:liveURL")
            headline = item.get("cn:title")
            published = parse_aware_datetime(item.get("datePublished"))
            if (
                not isinstance(raw_url, str)
                or not isinstance(headline, str)
                or published is None
            ):
                raise ProviderContractError("provider search result schema changed")
            observed_dates.append(published)
            normalized = self.normalize_url(raw_url)
            normalized_headline = " ".join(headline.split())
            if normalized is None or not normalized_headline:
                continue
            if not filters.includes_published(published):
                continue
            summary = item.get("summary") or item.get("description")
            results.append(
                SearchResult(
                    provider=self.key,
                    url=HttpUrl(normalized),
                    headline=normalized_headline,
                    snippet=(
                        " ".join(summary.split())
                        if isinstance(summary, str) and summary.strip()
                        else None
                    ),
                    published=published,
                )
            )

        consumed = offset + len(raw_results)
        available = min(total, _MAX_RESULTS)
        reached_after_bound = bool(
            filters.published_after is not None
            and observed_dates
            and min(observed_dates) < filters.published_after
        )
        continuation = None
        if (
            len(raw_results) == _PAGE_SIZE
            and consumed < available
            and not reached_after_bound
        ):
            continuation = _build_search_url(endpoint, query, offset=consumed)
        return ProviderSearchPage(results=tuple(results), next_url=continuation)


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("cnbc"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("cnbc"), url)


def _build_search_url(endpoint: str, query: str, *, offset: int) -> str:
    parameters = {
        "queryly_key": _QUERYLY_KEY,
        "query": query,
        "endindex": offset,
        "batchsize": _PAGE_SIZE,
        "showfaceted": "false",
        "additionalindexes": _ADDITIONAL_INDEXES,
        "sort": "date",
    }
    url = f"{endpoint}?{urlencode(parameters)}"
    if len(url) > _MAX_SEARCH_URL_LENGTH:
        raise ProviderContractError("provider search URL is too long")
    return url


def _validate_search_url(raw: str, query: str, *, endpoint: str) -> int:
    if len(raw) > _MAX_SEARCH_URL_LENGTH:
        raise ProviderContractError("provider search URL is too long")
    try:
        parsed = urlsplit(raw)
        expected_endpoint = urlsplit(endpoint)
        port = parsed.port or 443
        expected_port = expected_endpoint.port or 443
    except ValueError as error:
        raise ProviderContractError("invalid provider search URL") from error
    if (
        parsed.scheme != "https"
        or parsed.scheme != expected_endpoint.scheme
        or parsed.hostname != expected_endpoint.hostname
        or parsed.path != expected_endpoint.path
        or parsed.fragment
        or parsed.username
        or parsed.password
        or port != expected_port
    ):
        raise ProviderContractError("invalid provider search URL")
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    expected = {
        "queryly_key": _QUERYLY_KEY,
        "query": query,
        "batchsize": str(_PAGE_SIZE),
        "showfaceted": "false",
        "additionalindexes": _ADDITIONAL_INDEXES,
        "sort": "date",
    }
    if set(parameters) != {*expected, "endindex"} or any(
        parameters[key] != [value] for key, value in expected.items()
    ):
        raise ProviderContractError("invalid provider search parameters")
    offsets = parameters["endindex"]
    if len(offsets) != 1:
        raise ProviderContractError("invalid provider search offset")
    try:
        offset = int(offsets[0])
    except ValueError as error:
        raise ProviderContractError("invalid provider search offset") from error
    if offset < 0 or offset % _PAGE_SIZE:
        raise ProviderContractError("invalid provider search offset")
    return offset


def build_cnbc_provider(
    spec: ProviderSpec, verification_url: str | None
) -> CNBCProvider:
    if verification_url is not None:
        raise RuntimeError("CNBC registration cannot receive a verification URL")
    return CNBCProvider(spec=spec)


__all__ = [
    "CNBCProvider",
    "article_id",
    "build_cnbc_provider",
    "normalize_article_url",
]
