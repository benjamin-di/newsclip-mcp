"""AP News provider using the official current-news sitemap."""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

from lxml import etree
from pydantic import HttpUrl

from ..articles import parse_aware_datetime
from ..configured_provider import ConfiguredProvider, normalize_url, provider_article_id
from ..contracts import HttpClient
from ..errors import (
    ProviderContractError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from ..models import (
    ProviderSearchPage,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
)
from ..provider_config import ProviderSpec, load_provider_spec

_SITEMAP_NAMESPACES = {
    "sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9",
    "news": "http://www.google.com/schemas/sitemap-news/0.9",
}
# The sitemap is one unpaginated document (~450 entries live); the ceiling is a
# drift guard against a pathological payload, not a paging contract.
_MAX_ENTRIES = 5_000
_SEARCH_TIMEOUT_SECONDS = 8
_MAX_SITEMAP_BYTES = 2_000_000
# English function words carry no relevance signal, and a match on one turns
# recency into ranking. Reuters' original seven-word list reproduced exactly
# that defect; new sitemap-search code starts from the principled set.
_QUERY_STOP_WORDS = {
    "a", "an", "and", "any", "are", "as", "at", "be", "been", "but", "by",
    "can", "could", "did", "do", "does", "for", "from", "had", "has", "have",
    "he", "her", "his", "how", "if", "in", "into", "is", "it", "its", "may",
    "more", "most", "no", "not", "of", "on", "or", "our", "she", "should",
    "so", "than", "that", "the", "their", "them", "then", "there", "these",
    "they", "this", "those", "to", "was", "were", "what", "when", "where",
    "which", "while", "who", "why", "will", "with", "would",
}  # fmt: skip


class ApProvider(ConfiguredProvider):
    def __init__(self, *, spec: ProviderSpec | None = None) -> None:
        selected_spec = spec or load_provider_spec("ap")
        if selected_spec.key != "ap":
            raise ValueError("AP provider requires its own definition")
        super().__init__(selected_spec)
        self._search = selected_spec.require_adapter_search()

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        del session
        ranked, _ = self._search_ranked(http, query, filters)
        return [result for _, result in ranked[: filters.limit]]

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
        """Adapt sitemap discovery to the federated pager contract."""

        if next_url is not None:
            raise ProviderContractError("AP search does not expose continuation")
        del session
        del metadata_fetch_budget
        ranked, coverage_start = self._search_ranked(http, query, filters)
        return ProviderSearchPage(
            results=tuple(result for _, result in ranked),
            coverage_start=coverage_start,
        )

    def _search_ranked(
        self,
        http: HttpClient,
        query: str,
        filters: SearchFilters,
    ) -> tuple[list[tuple[int, SearchResult]], datetime | None]:
        """Rank the fetched sitemap and report how far back it reached."""

        query_tokens = _tokens(query) - _QUERY_STOP_WORDS
        if not query_tokens:
            raise UnsearchableQueryError("unsearchable_query")
        candidates: list[tuple[int, SearchResult]] = []
        seen: set[str] = set()
        # AP's news sitemap is a moving window, not an archive — a live sample
        # spanned 47 hours across 445 entries. Report its trailing edge so a
        # small honest result count is not read as "AP has nothing on this".
        # Only owned entries count: a non-article URL further back would claim
        # reach the search never had.
        coverage_start: datetime | None = None
        for raw_url, headline, published in self._sitemap_entries(http):
            normalized = self.normalize_url(raw_url)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            if coverage_start is None or published < coverage_start:
                coverage_start = published
            score = len(
                query_tokens & _tokens(f"{headline} {urlsplit(normalized).path}")
            )
            if score == 0 or not filters.includes_published(published):
                continue
            candidates.append(
                (
                    score,
                    SearchResult(
                        provider=self.key,
                        url=HttpUrl(normalized),
                        headline=headline,
                        published=published,
                    ),
                )
            )
        candidates.sort(
            key=lambda item: (
                -item[0],
                -item[1].published.timestamp() if item[1].published else 0,
                str(item[1].url),
            )
        )
        return candidates, coverage_start

    def _sitemap_entries(
        self,
        http: HttpClient,
    ) -> list[tuple[str, str, datetime]]:
        endpoint = str(self._search.endpoint)
        fetch = http.get(endpoint, session=None, timeout=_SEARCH_TIMEOUT_SECONDS)
        _validate_sitemap_response(fetch, endpoint)
        try:
            parser = etree.XMLParser(
                resolve_entities=False,
                no_network=True,
                recover=False,
                load_dtd=False,
            )
            document = etree.fromstring(fetch.raw_html, parser=parser)
        except etree.XMLSyntaxError as error:
            raise ProviderTransportError(
                "provider sitemap returned malformed XML"
            ) from error
        expected_tag = f"{{{_SITEMAP_NAMESPACES['sitemap']}}}urlset"
        if document.tag != expected_tag:
            raise ProviderContractError("provider sitemap root schema changed")
        nodes = document.xpath("./sitemap:url", namespaces=_SITEMAP_NAMESPACES)
        if not isinstance(nodes, list) or len(nodes) > _MAX_ENTRIES:
            raise ProviderContractError("provider sitemap result count changed")
        entries: list[tuple[str, str, datetime]] = []
        for node in nodes:
            if not isinstance(node, etree._Element):
                raise ProviderContractError("provider sitemap entry schema changed")
            locations = node.xpath(
                "./sitemap:loc/text()", namespaces=_SITEMAP_NAMESPACES
            )
            titles = node.xpath(
                "./news:news/news:title/text()", namespaces=_SITEMAP_NAMESPACES
            )
            published_values = node.xpath(
                "./news:news/news:publication_date/text()",
                namespaces=_SITEMAP_NAMESPACES,
            )
            if len(locations) != 1 or len(titles) != 1 or len(published_values) != 1:
                raise ProviderContractError("provider sitemap entry schema changed")
            location = str(locations[0]).strip()
            headline = " ".join(str(titles[0]).split())
            published = parse_aware_datetime(published_values[0])
            if not location or not headline or published is None:
                raise ProviderContractError("provider sitemap entry schema changed")
            entries.append((location, headline, published))
        return entries


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("ap"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("ap"), url)


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.casefold()))


def _validate_sitemap_response(fetch: RawFetch, endpoint: str) -> None:
    if not 200 <= fetch.http_status < 300:
        raise ProviderTransportError(
            f"provider sitemap returned HTTP {fetch.http_status}"
        )
    if len(fetch.raw_html) > _MAX_SITEMAP_BYTES:
        raise ProviderTransportError("provider sitemap exceeded the size limit")
    media_type = (fetch.content_type or "").partition(";")[0].strip().lower()
    if media_type not in {"application/xml", "text/xml"}:
        raise ProviderTransportError("provider sitemap returned non-XML content")
    if str(fetch.requested_url) != endpoint:
        raise ProviderContractError("provider sitemap request identity mismatch")
    try:
        parsed = urlsplit(str(fetch.final_url))
        expected = urlsplit(endpoint)
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        port = parsed.port or 443
        expected_port = expected.port or 443
    except ValueError as error:
        raise ProviderContractError("invalid provider sitemap response URL") from error
    if (
        parsed.scheme != "https"
        or parsed.scheme != expected.scheme
        or parsed.hostname != expected.hostname
        or parsed.path.rstrip("/") != expected.path.rstrip("/")
        or parsed.fragment
        or parsed.username
        or parsed.password
        or port != expected_port
        or parameters != {}
    ):
        raise ProviderContractError("provider sitemap response identity mismatch")


def build_ap_provider(spec: ProviderSpec, verification_url: str | None) -> ApProvider:
    if verification_url is not None:
        raise RuntimeError("AP registration cannot receive a verification URL")
    return ApProvider(spec=spec)


__all__ = [
    "ApProvider",
    "article_id",
    "build_ap_provider",
    "normalize_article_url",
]
