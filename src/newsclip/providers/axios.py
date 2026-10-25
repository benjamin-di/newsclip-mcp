"""Axios public articles and bounded recent-news sitemap discovery."""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit

from lxml import etree
from pydantic import HttpUrl

from ..articles import parse_aware_datetime
from ..configured_provider import ConfiguredProvider
from ..contracts import HttpClient
from ..errors import (
    ProviderContractError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from ..extraction import TrafilaturaExtractor
from ..models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderSearchPage,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
)
from ..provider_config import ProviderSpec, load_provider_spec
from .axios_story import render_story, story_document
from .base import ProviderNativeExtractionResult, ProviderNativeExtractionState

_NS = {
    "s": "http://www.sitemaps.org/schemas/sitemap/0.9",
    "n": "http://www.google.com/schemas/sitemap-news/0.9",
}
_STOP_WORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "any",
        "are",
        "as",
        "at",
        "be",
        "been",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "for",
        "from",
        "had",
        "has",
        "have",
        "he",
        "her",
        "his",
        "how",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "may",
        "more",
        "most",
        "no",
        "not",
        "of",
        "on",
        "or",
        "our",
        "she",
        "should",
        "so",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "these",
        "they",
        "this",
        "those",
        "to",
        "was",
        "were",
        "what",
        "when",
        "where",
        "which",
        "while",
        "who",
        "why",
        "will",
        "with",
        "would",
    ]
)


class AxiosProvider(ConfiguredProvider):
    def __init__(self, *, spec: ProviderSpec | None = None) -> None:
        selected = spec or load_provider_spec("axios")
        if selected.key != "axios":
            raise ValueError("Axios provider requires its own definition")
        super().__init__(selected)
        self._search = selected.require_adapter_search()
        self.assessment_policy_version += "-axios-public-v2"

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        return list(
            self.search_page(http, session, query, filters).results[: filters.limit]
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
        del session, metadata_fetch_budget
        if next_url is not None:
            raise ProviderContractError("Axios search does not expose continuation")
        tokens = _tokens(query) - _STOP_WORDS
        if not tokens:
            raise UnsearchableQueryError("unsearchable_query")
        ranked: list[tuple[int, SearchResult]] = []
        seen: set[str] = set()
        coverage: datetime | None = None
        for url, headline, published in self._sitemap_entries(http):
            normalized = self.normalize_url(url)
            if normalized is None or normalized in seen:
                continue
            seen.add(normalized)
            coverage = min(coverage, published) if coverage else published
            parts = urlsplit(normalized).path.strip("/").split("/")
            # Keep meaningful Local geography, never the route name or date.
            subject = parts[-1] + (" " + parts[1] if parts[0] == "local" else "")
            score = len(tokens & _tokens(headline + " " + subject))
            if score and filters.includes_published(published):
                ranked.append(
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
        ranked.sort(
            key=lambda item: (
                -item[0],
                -item[1].published.timestamp() if item[1].published else 0,
                str(item[1].url),
            )
        )
        return ProviderSearchPage(
            results=tuple(result for _, result in ranked), coverage_start=coverage
        )

    def _sitemap_entries(self, http: HttpClient) -> list[tuple[str, str, datetime]]:
        endpoint = str(self._search.endpoint)
        fetch = http.get(endpoint, session=None, timeout=8)
        if not 200 <= fetch.http_status < 300:
            raise ProviderTransportError(
                f"Axios sitemap returned HTTP {fetch.http_status}"
            )
        if len(fetch.raw_html) > 2_000_000:
            raise ProviderTransportError("Axios sitemap exceeded the size limit")
        if (fetch.content_type or "").partition(";")[0].strip().lower() not in {
            "application/xml",
            "text/xml",
        }:
            raise ProviderTransportError("Axios sitemap returned non-XML content")
        if str(fetch.requested_url) != endpoint or str(fetch.final_url) != endpoint:
            raise ProviderContractError("Axios sitemap response identity mismatch")
        try:
            parser = etree.XMLParser(
                resolve_entities=False, no_network=True, recover=False, load_dtd=False
            )
            doc = etree.fromstring(fetch.raw_html, parser=parser)
        except etree.XMLSyntaxError as error:
            raise ProviderTransportError(
                "Axios sitemap returned malformed XML"
            ) from error
        if doc.tag != f"{{{_NS['s']}}}urlset":
            raise ProviderContractError("Axios sitemap root schema changed")
        nodes = doc.findall("s:url", _NS)
        if len(nodes) > 5_000:
            raise ProviderContractError("Axios sitemap result count changed")
        entries = []
        for node in nodes:
            values = [
                node.xpath(path, namespaces=_NS)
                for path in (
                    "./s:loc/text()",
                    "./n:news/n:title/text()",
                    "./n:news/n:publication_date/text()",
                )
            ]
            if any(len(value) != 1 for value in values):
                raise ProviderContractError("Axios sitemap entry schema changed")
            url, title, date = (str(value[0]).strip() for value in values)
            published = parse_aware_datetime(date)
            if not url or not title or published is None:
                raise ProviderContractError("Axios sitemap entry schema changed")
            entries.append((url, " ".join(title.split()), published))
        return entries

    def assess(
        self, requested_url: str, fetch: RawFetch, extraction: ExtractedArticle
    ) -> ArticleAssessment:
        assessed = super().assess(requested_url, fetch, extraction)
        if not assessed.promotable:
            return assessed
        try:
            _, story = story_document(fetch)
        except ValueError:
            return assessed.model_copy(
                update={
                    "access_state": AccessState.UNKNOWN,
                    "reason": "axios_story_invalid",
                }
            )
        if self.normalize_url(story["permalink"]) != self.normalize_url(requested_url):
            return assessed.model_copy(
                update={
                    "access_state": AccessState.UNKNOWN,
                    "identity_match": False,
                    "reason": "article_identity_mismatch",
                }
            )
        # Axios emits isAccessibleForFree=false even for public articles.
        # The observed story flag and absence of an active DOM gate must agree.
        if story.get("is_paywalled") is not False:
            return assessed.model_copy(
                update={
                    "access_state": AccessState.TEASER,
                    "negative_markers": ("paywall",),
                    "reason": "paywall_teaser",
                }
            )
        return assessed

    def native_extraction(
        self, requested_url: str, fetch: RawFetch
    ) -> ProviderNativeExtractionResult:
        metadata = TrafilaturaExtractor().extract(
            fetch, scope_xpath=self.extraction_scope
        )
        # Never rescue a teaser, challenge, identity mismatch, or missing body.
        assessed = self.assess(requested_url, fetch, metadata)
        if not assessed.promotable:
            return ProviderNativeExtractionResult(
                ProviderNativeExtractionState.ABSENT, assessed.reason
            )
        try:
            parsed, story = story_document(fetch)
            body = render_story(parsed, story)
        except ValueError as error:
            return ProviderNativeExtractionResult(
                ProviderNativeExtractionState.INVALID, str(error)
            )
        extraction = metadata.model_copy(
            update={"body_markdown": body, "word_count": len(body.split())}
        )
        return ProviderNativeExtractionResult(
            ProviderNativeExtractionState.VALID,
            "axios_public_story",
            extraction=extraction,
            assessment=self.assess(requested_url, fetch, extraction),
            extractor_name="axios-dom",
            extractor_version="2+" + TrafilaturaExtractor().version,
        )


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.casefold()))


def build_axios_provider(
    spec: ProviderSpec, verification_url: str | None
) -> AxiosProvider:
    if verification_url is not None:
        raise RuntimeError("Axios registration cannot receive a verification URL")
    return AxiosProvider(spec=spec)
