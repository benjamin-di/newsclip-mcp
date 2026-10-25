"""Reuters provider using the official current-news sitemap."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime, time
from urllib.parse import parse_qs, urlencode, urlsplit

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
_PAGE_SIZE = 50
# Parallel first-window sitemap pages cover distinctive live queries that can
# sit several hundred URLs deep (live baseline observed at page index 6 /
# offset 300+). Reuters does not guarantee chronological partitioning within or
# across offsets, so the bounded window is ranked only after every page closes.
_MAX_PAGES = 8
_SEARCH_TIMEOUT_SECONDS = 8
_MAX_SITEMAP_BYTES = 2_000_000
_SLUG_DATE_PATTERN = re.compile(r"-(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})$")
# Relevance scoring counts query/candidate token overlap, so a query token only
# earns a candidate its place when the token itself carries information. English
# closed-class words carry none: they occur in a large fraction of headlines
# regardless of subject, so scoring them promotes whichever unrelated story is
# newest. The earlier seven-word list was incomplete by construction — a live
# census of the sitemap window found "of" alone matching 23 of 400 entries for
# the query "Strait of Hormuz", including an outfielder abbreviation.
#
# This is therefore the closed class itself — articles, demonstratives,
# prepositions, conjunctions, pronouns, and auxiliaries — enumerated inline and
# versioned with this module rather than imported from a corpus dependency, so
# the informativeness model stays reviewable and offline-deterministic.
#
# "us" is deliberately absent: in a news corpus it is United States, one of the
# most distinctive tokens a query can carry, not the object pronoun.
_FUNCTION_WORDS = frozenset(
    {
        "a",
        "about",
        "after",
        "against",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "before",
        "between",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "during",
        "for",
        "from",
        "had",
        "has",
        "have",
        "he",
        "her",
        "his",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "may",
        "might",
        "must",
        "my",
        "of",
        "on",
        "or",
        "our",
        "over",
        "she",
        "should",
        "since",
        "so",
        "than",
        "that",
        "the",
        "their",
        "them",
        "these",
        "they",
        "this",
        "those",
        "through",
        "to",
        "under",
        "until",
        "was",
        "we",
        "were",
        "what",
        "when",
        "which",
        "while",
        "who",
        "will",
        "with",
        "would",
        "you",
        "your",
    }
)


class ReutersProvider(ConfiguredProvider):
    def __init__(self, *, spec: ProviderSpec | None = None) -> None:
        selected_spec = spec or load_provider_spec("reuters")
        if selected_spec.key != "reuters":
            raise ValueError("Reuters provider requires its own definition")
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

    def _search_ranked(
        self,
        http: HttpClient,
        query: str,
        filters: SearchFilters,
    ) -> tuple[list[tuple[int, SearchResult]], datetime | None]:
        """Rank the fetched window and report how far back it reached."""

        query_tokens = _tokens(query) - _FUNCTION_WORDS
        if not query_tokens:
            raise UnsearchableQueryError("unsearchable_query")
        pages: dict[int, list[tuple[str, str, datetime]]] = {}
        with ThreadPoolExecutor(max_workers=_MAX_PAGES) as executor:
            futures = {
                executor.submit(
                    self._sitemap_page, http, offset=page * _PAGE_SIZE
                ): page
                for page in range(_MAX_PAGES)
            }
            for future in as_completed(futures):
                page_index = futures[future]
                pages[page_index] = future.result()
        return self._rank_pages(pages, query_tokens, filters)

    def _rank_pages(
        self,
        pages: dict[int, list[tuple[str, str, datetime]]],
        query_tokens: set[str],
        filters: SearchFilters,
    ) -> tuple[list[tuple[int, SearchResult]], datetime | None]:
        candidates: list[tuple[int, SearchResult]] = []
        seen: set[str] = set()
        # The trailing edge of the window, reported so a small honest result
        # count is not read as "Reuters has nothing on this". Deliberately the
        # raw *sitemap* stamp, not the slug-reconciled one: a re-stamped 2024
        # story appearing in today's feed does not mean 2024 was reachable. Only
        # owned entries count, because a non-article URL further back would
        # claim reach the search never had.
        coverage_start: datetime | None = None
        for page in range(_MAX_PAGES):
            entries = pages.get(page)
            if entries is None:
                continue
            for raw_url, headline, sitemap_published in entries:
                normalized = self.normalize_url(raw_url)
                if normalized is None or normalized in seen:
                    continue
                seen.add(normalized)
                if coverage_start is None or sitemap_published < coverage_start:
                    coverage_start = sitemap_published
                subject_path, slug_date = _split_slug_date(urlsplit(normalized).path)
                score = len(query_tokens & _tokens(f"{headline} {subject_path}"))
                published = _reconciled_published(sitemap_published, slug_date)
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
            raise ProviderContractError("Reuters search does not expose continuation")
        del session
        del metadata_fetch_budget
        ranked, coverage_start = self._search_ranked(http, query, filters)
        return ProviderSearchPage(
            results=tuple(result for _, result in ranked),
            coverage_start=coverage_start,
        )

    def _sitemap_page(
        self,
        http: HttpClient,
        *,
        offset: int,
    ) -> list[tuple[str, str, datetime]]:
        endpoint = str(self._search.endpoint)
        url = _sitemap_url(endpoint, offset)
        fetch = http.get(url, session=None, timeout=_SEARCH_TIMEOUT_SECONDS)
        _validate_sitemap_response(fetch, url, endpoint, offset)
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
        if not isinstance(nodes, list) or len(nodes) > _PAGE_SIZE:
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
    return normalize_url(load_provider_spec("reuters"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("reuters"), url)


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.casefold()))


def _split_slug_date(path: str) -> tuple[str, str | None]:
    """Split an article path into its subject text and its trailing slug date.

    The identity ``path_pattern`` requires every accepted Reuters article path
    to end in ``-YYYY-MM-DD``, so that date is guaranteed metadata rather than
    subject matter. Separating it keeps the date out of relevance scoring: every
    entry in a one-day sitemap window shares the same day tokens, so scoring
    them makes any query carrying a year or a bare number match the whole window
    at score 1 — the same defect as scoring function words. Headline digits stay
    scoreable, because there a number is content ("Boeing 737").
    """

    match = _SLUG_DATE_PATTERN.search(path)
    if match is None:  # pragma: no cover - identity guarantees the slug date
        return path, None
    return path[: match.start()], match.group("date")


def _reconciled_published(published: datetime, slug_date: str | None) -> datetime:
    """Clamp a mutable sitemap timestamp to the immutable publish day.

    ``news:publication_date`` is a re-stamp time, not a first-publish time:
    Reuters rewrites it when a story is re-published, and a live census of the
    400-URL window found 11 entries stamped more than a day past their slug
    date, the worst by 773 days. Left alone those re-syndicated stories top
    ``sort=newest`` and pass a recent ``--published-after``, which also inflates
    Reuters' recency in the federated merge.

    The slug date is the fix already on hand: the identity ``path_pattern``
    validates it in every accepted URL, and unlike the sitemap field it never
    changes. Within a calendar day of the slug the sitemap value is kept for its
    intraday precision — a legitimate same-story stamp can sit either side of
    midnight UTC, so the tolerance absorbs the timezone offset. Past that the
    slug day at midnight UTC replaces it.

    ``get`` stays metadata-authoritative (JSON-LD ``datePublished``); the
    remaining search/get divergence is inherent to metadata-versus-article
    sourcing and is now bounded at one day.
    """

    if slug_date is None:  # pragma: no cover - identity guarantees the slug date
        return published
    try:
        slug_day = date.fromisoformat(slug_date)
    except ValueError:  # pragma: no cover - the pattern guarantees the shape
        return published
    if abs((published.astimezone(UTC).date() - slug_day).days) <= 1:
        return published
    return datetime.combine(slug_day, time(), tzinfo=UTC)


def _sitemap_url(endpoint: str, offset: int) -> str:
    if offset < 0 or offset % _PAGE_SIZE:
        raise ProviderContractError("invalid Reuters sitemap offset")
    return f"{endpoint}?{urlencode({'outputType': 'xml', 'from': offset})}"


def _validate_sitemap_response(
    fetch: RawFetch,
    requested_url: str,
    endpoint: str,
    offset: int,
) -> None:
    if not 200 <= fetch.http_status < 300:
        raise ProviderTransportError(
            f"provider sitemap returned HTTP {fetch.http_status}"
        )
    if len(fetch.raw_html) > _MAX_SITEMAP_BYTES:
        raise ProviderTransportError("provider sitemap exceeded the size limit")
    media_type = (fetch.content_type or "").partition(";")[0].strip().lower()
    if media_type not in {"application/xml", "text/xml"}:
        raise ProviderTransportError("provider sitemap returned non-XML content")
    if str(fetch.requested_url) != requested_url:
        raise ProviderContractError("provider sitemap request identity mismatch")
    try:
        parsed = urlsplit(str(fetch.final_url))
        expected_endpoint = urlsplit(endpoint)
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        port = parsed.port or 443
        expected_port = expected_endpoint.port or 443
    except ValueError as error:
        raise ProviderContractError("invalid provider sitemap response URL") from error
    if (
        parsed.scheme != "https"
        or parsed.scheme != expected_endpoint.scheme
        or parsed.hostname != expected_endpoint.hostname
        or parsed.path.rstrip("/") != expected_endpoint.path.rstrip("/")
        or parsed.fragment
        or parsed.username
        or parsed.password
        or port != expected_port
        or parameters != {"outputType": ["xml"], "from": [str(offset)]}
    ):
        raise ProviderContractError("provider sitemap response identity mismatch")


def build_reuters_provider(
    spec: ProviderSpec, verification_url: str | None
) -> ReutersProvider:
    if verification_url is not None:
        raise RuntimeError("Reuters registration cannot receive a verification URL")
    return ReutersProvider(spec=spec)


__all__ = [
    "ReutersProvider",
    "article_id",
    "build_reuters_provider",
    "normalize_article_url",
]
