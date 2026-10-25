"""Configured Bloomberg provider and compatibility constructors."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from math import ceil
from urllib.parse import parse_qs, urlencode, urlsplit

from pydantic import HttpUrl

from ..articles import parse_aware_datetime
from ..assessment import search_json_object
from ..configured_provider import (
    ConfiguredLoginRecipe,
    ConfiguredProvider,
    normalize_url,
    provider_article_id,
)
from ..contracts import HttpClient
from ..errors import ProviderContractError
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
from .base import (
    BrowserSnapshotCompletenessResult,
    ProviderNativeExtractionResult,
    ProviderNativeExtractionState,
)
from .bloomberg_story import BloombergStoryState, extract_bloomberg_story

_SEARCH_TIMEOUT_SECONDS = 10
_MAX_RESULTS = 100
_MAX_CONTINUATION_URL_LENGTH = 8192
# Nemo search returns a fixed page size; live default limit=20 is two pages.
_PAGE_SIZE = 10
# Cap parallel fan-out so a single search stays within warm latency budgets.
_MAX_PARALLEL_PAGES = 3
_READINESS_SHINGLE_SIZE = 5
_NATIVE_EXTRACTOR_NAME = "bloomberg-next-story"
_NATIVE_EXTRACTOR_VERSION = "newsclip-r1"
_NATIVE_POLICY_REVISION = "bloomberg-next-r1"


class BloombergProvider(ConfiguredProvider):
    def __init__(
        self,
        *,
        verification_url: str | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("bloomberg")
        if selected_spec.key != "bloomberg":
            raise ValueError("Bloomberg provider requires its own definition")
        super().__init__(selected_spec)
        self.assessment_policy_version = (
            f"{self.assessment_policy_version}+{_NATIVE_POLICY_REVISION}"
        )
        self._search = selected_spec.require_adapter_search()
        self.login_recipe = (
            BloombergLoginRecipe(verification_url=verification_url, spec=selected_spec)
            if verification_url is not None
            else None
        )

    def browser_snapshot_complete(
        self,
        fetch: RawFetch,
        extraction: ExtractedArticle,
        assessment: ArticleAssessment,
    ) -> BrowserSnapshotCompletenessResult:
        """Prefer a validated story payload; retain DOM coverage as evidence."""

        native = self.native_extraction(str(fetch.requested_url), fetch)
        if native.state is ProviderNativeExtractionState.ABSENT:
            return BrowserSnapshotCompletenessResult(
                complete=assessment.promotable,
                coverage=None,
            )
        if native.state is ProviderNativeExtractionState.INVALID:
            return BrowserSnapshotCompletenessResult(complete=False, coverage=None)
        assert native.extraction is not None
        coverage = _story_coverage(
            native.extraction.body_markdown,
            extraction.body_markdown,
        )
        return BrowserSnapshotCompletenessResult(
            complete=True,
            coverage=coverage,
        )

    def native_extraction(
        self,
        requested_url: str,
        fetch: RawFetch,
    ) -> ProviderNativeExtractionResult:
        """Build a fail-closed article candidate from Bloomberg's story payload."""

        story = extract_bloomberg_story(fetch.raw_html)
        if story.state is BloombergStoryState.ABSENT:
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.ABSENT,
                reason=story.reason,
            )
        if story.state is BloombergStoryState.INVALID:
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.INVALID,
                reason=story.reason,
            )
        candidate = story.candidate
        assert candidate is not None
        requested = self.normalize_url(requested_url)
        final = self.normalize_url(str(fetch.final_url))
        canonical = self.normalize_url(candidate.canonical_url)
        requested_id = self.article_id(requested_url)
        if (
            requested is None
            or final != requested
            or canonical != requested
            or requested_id is None
        ):
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.INVALID,
                reason="story_identity_mismatch",
            )
        if (
            not 200 <= fetch.http_status < 300
            or not fetch.session_cookie_present
            or self.is_interactive_challenge(fetch)
        ):
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.INVALID,
                reason="story_transport_not_authorized",
            )

        assessment_spec = self.spec.assessment
        paragraph_floor = assessment_spec.paragraph_floor
        # The payload floor is a stub guard, not a teaser guard: identity, HTTP
        # status, the session cookie, the challenge check, and the strict
        # component parse above already establish delivery, and the rendered
        # floor stays where it is for the DOM path.
        minimum_words = assessment_spec.effective_story_minimum_words
        if paragraph_floor is None or minimum_words is None:
            raise RuntimeError("Bloomberg structured extraction requires body floors")
        # Measure the delivered body per narrative block rather than per
        # paragraph. Bloomberg publishes market wraps as an intro paragraph, a
        # bulleted list carrying most of the prose, a data table, and a closing
        # paragraph; counting only paragraphs saw two blocks and rejected a
        # whole entitled article, which then failed the read path and session
        # minting alike. The word floor still bounds body size, and the rendered
        # paragraph floor in ConfiguredProvider.assess is unchanged.
        substantial = sum(
            length >= paragraph_floor.substantial_minimum_characters
            for length in candidate.narrative_character_counts
        )
        if (
            candidate.extraction.word_count < minimum_words
            or candidate.narrative_block_count < paragraph_floor.minimum_count
            or substantial < paragraph_floor.minimum_substantial_count
        ):
            return ProviderNativeExtractionResult(
                state=ProviderNativeExtractionState.INVALID,
                reason="story_body_below_floor",
            )
        assessment = ArticleAssessment(
            access_state=AccessState.FULL,
            provider_article_id=requested_id,
            canonical_url=HttpUrl(canonical),
            identity_match=True,
            structural_signals=(
                assessment_spec.canonical_signal,
                "embedded_story_body",
                "embedded_story_block_floor",
                "embedded_story_word_floor",
                "extracted_headline",
                "markdown_body",
            ),
            word_count=candidate.extraction.word_count,
            session_cookie_present=fetch.session_cookie_present,
            reason="full_article_verified",
        )
        return ProviderNativeExtractionResult(
            state=ProviderNativeExtractionState.VALID,
            reason=story.reason,
            extraction=candidate.extraction,
            assessment=assessment,
            extractor_name=_NATIVE_EXTRACTOR_NAME,
            extractor_version=_NATIVE_EXTRACTOR_VERSION,
        )

    def browser_paid_proof_complete(
        self,
        fetch: RawFetch,
        extraction: ExtractedArticle,
        assessment: ArticleAssessment,
    ) -> BrowserSnapshotCompletenessResult:
        """Bind session minting to an entitled article, not to render progress.

        Entitlement lives in the rendered assessment: a paywall or authentication
        marker, a body under the word floor, or a canonical mismatch each deny
        promotion, and the caller separately requires a paid auth cookie. This is
        why a validated payload alone is not accepted here as it is on the read
        path — Bloomberg has served an identical complete story payload beside a
        rendered teaser, so the payload proves delivery, not entitlement.

        Rendered coverage of that payload measures how far the client got, not
        whether this session is entitled. Requiring it also made minting
        impossible whenever Bloomberg rendered part of a story it had delivered
        whole, so coverage is retained as evidence instead of gating the proof.
        """

        native = self.native_extraction(str(fetch.requested_url), fetch)
        if native.state is ProviderNativeExtractionState.INVALID:
            return BrowserSnapshotCompletenessResult(complete=False)
        coverage: float | None = None
        if native.state is ProviderNativeExtractionState.VALID:
            assert native.extraction is not None
            coverage = _story_coverage(
                native.extraction.body_markdown,
                extraction.body_markdown,
            )
        return BrowserSnapshotCompletenessResult(
            complete=assessment.promotable,
            coverage=coverage,
        )

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        """Search with parallel first-window page fan-out.

        Bloomberg's JSON API accepts ``page=N`` without an exclude chain. Wall
        clock then tracks the slowest page rather than the sum of sequential
        GETs, which is what previously pushed default ``limit=20`` over 2s.

        The window is bounded, so a limit it cannot satisfy takes the exclude
        chain directly rather than paying for a fan-out whose results the
        under-fill fallback would discard.
        """

        if filters.limit > _MAX_PARALLEL_PAGES * _PAGE_SIZE:
            return super().search(http, session, query, filters)
        pages_needed = min(
            _MAX_PARALLEL_PAGES,
            max(1, ceil(filters.limit / _PAGE_SIZE)),
        )
        with ThreadPoolExecutor(max_workers=pages_needed) as executor:
            futures = {
                executor.submit(
                    self._fetch_page_results,
                    http,
                    session,
                    query,
                    filters,
                    page=page,
                ): page
                for page in range(1, pages_needed + 1)
            }
            by_page: dict[int, tuple[list[SearchResult], list[str], int]] = {}
            for future in as_completed(futures):
                by_page[futures[future]] = future.result()

        results: list[SearchResult] = []
        seen: set[str] = set()
        resource_ids: set[str] = set()
        available = 0
        for page in range(1, pages_needed + 1):
            page_results, page_resource_ids, page_total = by_page.get(
                page,
                ([], [], 0),
            )
            resource_ids.update(page_resource_ids)
            available = max(available, min(page_total, _MAX_RESULTS))
            for result in page_results:
                key = str(result.url)
                if key in seen:
                    continue
                seen.add(key)
                results.append(result)
                if len(results) >= filters.limit:
                    return results
        if pages_needed == _MAX_PARALLEL_PAGES and len(resource_ids) < available:
            return super().search(http, session, query, filters)
        return results

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
        del metadata_fetch_budget
        endpoint = str(self._search.endpoint)
        search_url = next_url or _page_url(endpoint, query, page=1, excluded=())
        requested_page, excluded = _validate_search_url(
            search_url, query, endpoint=endpoint
        )
        results, resource_ids, total, undated_excluded = self._parse_search_payload(
            http.get(
                search_url,
                session=session,
                timeout=_SEARCH_TIMEOUT_SECONDS,
            ),
            query=query,
            filters=filters,
            requested_page=requested_page,
            excluded=excluded,
        )
        all_excluded = tuple(dict.fromkeys((*excluded, *resource_ids)))
        available = min(total, _MAX_RESULTS)
        continuation = None
        if len(all_excluded) > len(excluded) and len(all_excluded) < available:
            continuation = _page_url(
                endpoint,
                query,
                page=requested_page + 1,
                excluded=all_excluded,
            )
        return ProviderSearchPage(
            results=tuple(results),
            next_url=continuation,
            undated_excluded_count=undated_excluded,
        )

    def _fetch_page_results(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        page: int,
    ) -> tuple[list[SearchResult], list[str], int]:
        # Page-number fan-out omits exclusions; the live API accepts this and
        # returns disjoint pages, so workers do not wait on prior pages.
        search_url = _page_url(
            str(self._search.endpoint), query, page=page, excluded=()
        )
        results, resource_ids, total, _undated = self._parse_search_payload(
            http.get(
                search_url,
                session=session,
                timeout=_SEARCH_TIMEOUT_SECONDS,
            ),
            query=query,
            filters=filters,
            requested_page=page,
            excluded=(),
            allow_page_without_exclude=page > 1,
        )
        return results, resource_ids, total

    def _parse_search_payload(
        self,
        fetch: RawFetch,
        *,
        query: str,
        filters: SearchFilters,
        requested_page: int,
        excluded: tuple[str, ...],
        allow_page_without_exclude: bool = False,
    ) -> tuple[list[SearchResult], list[str], int, int]:
        observed_page, observed_excluded = _validate_search_url(
            str(fetch.final_url),
            query,
            endpoint=str(self._search.endpoint),
            allow_page_without_exclude=allow_page_without_exclude,
        )
        if (observed_page, observed_excluded) != (requested_page, excluded):
            raise ProviderContractError("provider search response identity mismatch")
        payload = search_json_object(fetch)
        raw_results = payload.get("results")
        response_page = payload.get("page")
        total = payload.get("total")
        if (
            not isinstance(raw_results, list)
            or not isinstance(response_page, int)
            or isinstance(response_page, bool)
            or response_page != requested_page
            or not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
        ):
            raise ProviderContractError("provider search JSON schema changed")

        results: list[SearchResult] = []
        resource_ids: list[str] = []
        undated_excluded = 0
        for item in raw_results:
            if not isinstance(item, Mapping):
                raise ProviderContractError("provider search result schema changed")
            resource_id = item.get("resourceId")
            raw_url = item.get("url")
            headline = item.get("headline")
            if (
                not isinstance(resource_id, str)
                or not resource_id.strip()
                or len(resource_id) > 256
                or not isinstance(raw_url, str)
                or not isinstance(headline, str)
            ):
                raise ProviderContractError("provider search result schema changed")
            resource_ids.append(resource_id)
            normalized = self.normalize_url(raw_url)
            normalized_headline = " ".join(headline.split())
            if normalized is None or not normalized_headline:
                continue
            published = parse_aware_datetime(
                item.get("publishedAt")
            ) or self._published_from_url(normalized)
            if not filters.includes_published(published):
                undated_excluded += filters.excludes_undated(published)
                continue
            summary = item.get("summary")
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
        return results, resource_ids, total, undated_excluded

    def _published_from_url(self, normalized_url: str) -> datetime | None:
        match = self._identity_pattern.fullmatch(urlsplit(normalized_url).path)
        if match is None:
            return None
        value = match.groupdict().get("published")
        if value is None:
            return None
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return None
        return parsed.replace(tzinfo=UTC)


class BloombergLoginRecipe(ConfiguredLoginRecipe):
    def __init__(
        self, *, verification_url: str, spec: ProviderSpec | None = None
    ) -> None:
        selected_spec = spec or load_provider_spec("bloomberg")
        super().__init__(
            ConfiguredProvider(selected_spec),
            verification_url=verification_url,
            label="Bloomberg",
        )


def build_bloomberg_provider(
    spec: ProviderSpec, verification_url: str | None
) -> BloombergProvider:
    if verification_url is None:
        raise RuntimeError("Bloomberg registration requires a verification URL")
    return BloombergProvider(verification_url=verification_url, spec=spec)


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("bloomberg"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("bloomberg"), url)


def _story_coverage(source: str, rendered: str) -> float | None:
    source_tokens = _normalized_tokens(source)
    source_shingles = _shingles(source_tokens)
    if not source_shingles:
        return None
    rendered_shingles = _shingles(_normalized_tokens(rendered))
    return len(source_shingles & rendered_shingles) / len(source_shingles)


def _normalized_tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return tuple(re.findall(r"[^\W_]+", normalized, flags=re.UNICODE))


def _shingles(tokens: tuple[str, ...]) -> set[tuple[str, ...]]:
    return {
        tokens[index : index + _READINESS_SHINGLE_SIZE]
        for index in range(len(tokens) - _READINESS_SHINGLE_SIZE + 1)
    }


def _page_url(
    endpoint: str,
    query: str,
    *,
    page: int,
    excluded: tuple[str, ...],
) -> str:
    parameters: dict[str, str | int] = {"query": query}
    if page != 1:
        parameters["page"] = page
    if excluded:
        parameters["exclude"] = ",".join(excluded)
    url = f"{endpoint}?{urlencode(parameters)}"
    if len(url) > _MAX_CONTINUATION_URL_LENGTH:
        raise ProviderContractError("provider search continuation is too long")
    return url


def _validate_search_url(
    url: str,
    query: str,
    *,
    endpoint: str,
    allow_page_without_exclude: bool = False,
) -> tuple[int, tuple[str, ...]]:
    if len(url) > _MAX_CONTINUATION_URL_LENGTH:
        raise ProviderContractError("provider search continuation is too long")
    try:
        parsed = urlsplit(url)
        expected = urlsplit(endpoint)
        port = parsed.port or 443
        expected_port = expected.port or 443
    except ValueError as error:
        raise ProviderContractError(
            "provider search continuation is invalid"
        ) from error
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    pages = parameters.get("page", ["1"])
    excludes = parameters.get("exclude", [""])
    if (
        parsed.scheme.lower() != "https"
        or parsed.scheme.lower() != expected.scheme.lower()
        or (parsed.hostname or "").lower() != (expected.hostname or "").lower()
        or port != expected_port
        or parsed.path.rstrip("/") != expected.path.rstrip("/")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or set(parameters) - {"query", "page", "exclude"}
        or parameters.get("query") != [query]
        or len(pages) != 1
        or not pages[0].isdigit()
        or len(excludes) != 1
    ):
        raise ProviderContractError("provider search continuation is invalid")
    page = int(pages[0])
    if page < 1 or page > _MAX_RESULTS:
        raise ProviderContractError("provider search continuation page is invalid")
    excluded = tuple(value for value in excludes[0].split(",") if value)
    if len(excluded) != len(set(excluded)) or any(
        len(value) > 256 for value in excluded
    ):
        raise ProviderContractError("provider search exclusions are invalid")
    if page == 1 and excluded:
        raise ProviderContractError("first provider search page cannot exclude results")
    if page > 1 and not excluded and not allow_page_without_exclude:
        raise ProviderContractError("continued provider search requires exclusions")
    return page, excluded


__all__ = [
    "BloombergLoginRecipe",
    "BloombergProvider",
    "build_bloomberg_provider",
    "article_id",
    "normalize_article_url",
]
