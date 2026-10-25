"""Generic provider behavior backed by a strict built-in definition."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from lxml import html
from pydantic import HttpUrl

from .articles import parse_aware_datetime
from .assessment import (
    assessment as _assessment,
)
from .assessment import (
    canonical_urls as _canonical_urls,
)
from .assessment import (
    document as _document,
)
from .assessment import (
    metadata_has_headline as _metadata_has_headline,
)
from .assessment import news_article_json_ld
from .assessment import search_document as _search_document
from .contracts import HttpClient
from .errors import ProviderContractError, ProviderTransportError
from .extraction import TrafilaturaExtractor
from .models import (
    AccessState,
    ArticleAssessment,
    ExtractedArticle,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
    SessionVerification,
)
from .provider_config import (
    NegativeRuleSpec,
    ParagraphFloorSpec,
    ProviderSpec,
)

_MARKER = {
    "challenge": "interactive_challenge",
    "authentication": "authentication_page",
    "paywall": "paywall",
}
_NEGATIVE_RESULT = {
    "challenge": (AccessState.BLOCKED, "interactive_challenge"),
    "authentication": (AccessState.AUTH_REQUIRED, "authentication_required"),
    "paywall": (AccessState.TEASER, "paywall_teaser"),
}
# Archive extraction identity depends on this revision. Bump it whenever
# ConfiguredProvider assessment semantics or their shared helpers change.
_ASSESSMENT_ENGINE_REVISION = "configured-r2"
_SEARCH_REQUEST_TIMEOUT_SECONDS = 10
_SEARCH_METADATA_TIMEOUT_SECONDS = 10
_MAX_SEARCH_PAGES_PER_CALL = 10
_MAX_SEARCH_CONTINUATION_URL_LENGTH = 4096


@dataclass(frozen=True)
class _PublishedRecovery:
    published: datetime | None
    stop_provider: bool = False


class ConfiguredProvider:
    """Implement the provider contract using one immutable definition."""

    # A provider opting into another observed type must version its own policy.
    _jsonld_article_types: tuple[str, ...] = ("NewsArticle",)

    def __init__(
        self,
        spec: ProviderSpec,
        *,
        verification_url: str | None = None,
        verification_label: str | None = None,
    ) -> None:
        if verification_url is not None and spec.session is None:
            raise ValueError("anonymous providers cannot configure verification")
        self.spec = spec
        self.key = spec.key
        self.capabilities = spec.capabilities
        self.check = spec.check
        self.assessment_policy_version = spec.assessment_policy_version(
            _ASSESSMENT_ENGINE_REVISION
        )
        self.extraction_scope = (
            spec.extraction.scope_xpath if spec.extraction is not None else None
        )
        self._identity_pattern = re.compile(spec.identity.path_pattern)
        self.login_recipe = (
            ConfiguredLoginRecipe(
                self,
                verification_url=verification_url,
                label=verification_label or spec.key.upper(),
            )
            if verification_url is not None
            else None
        )

    def owns_url(self, url: str) -> bool:
        return self.normalize_url(url) is not None

    def is_interactive_challenge(self, fetch: RawFetch) -> bool:
        """Recognize the provider's configured challenge response contract."""

        if not _is_html(fetch.content_type):
            return False
        document = _document(fetch.raw_html)
        markers = _negative_markers(self.spec, document, str(fetch.final_url))
        return _MARKER["challenge"] in markers

    def normalize_url(self, raw: str) -> str | None:
        return normalize_url(self.spec, raw, pattern=self._identity_pattern)

    def article_id(self, raw: str) -> str | None:
        normalized = self.normalize_url(raw)
        if normalized is None:
            return None
        match = self._identity_pattern.fullmatch(urlsplit(normalized).path)
        if match is None:  # pragma: no cover - normalization invariant
            return None
        identifier = match.group("id")
        return (
            identifier.lower()
            if "id" in self.spec.identity.lowercase_groups
            else identifier
        )

    def retry_response(self, fetch: RawFetch) -> bool:
        """Match the provider's one exact, non-interactive retry fingerprint."""

        rule = self.spec.response_retry
        if (
            rule is None
            or fetch.http_status != rule.status_code
            or not _is_html(fetch.content_type)
        ):
            return False
        document = _document(fetch.raw_html)
        if document is None:
            return False
        titles = _xpath_elements(document, "//head/title")
        if len(titles) != 1:
            return False
        title = " ".join(titles[0].text_content().split())
        return title == rule.title_equals and _any_element_xpath(
            document,
            (rule.required_xpath,),
        )

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        results: list[SearchResult] = []
        seen_results: set[str] = set()
        seen_pages: set[str] = set()
        next_url: str | None = None
        metadata_fetch_budget: int | None = None
        for _ in range(_MAX_SEARCH_PAGES_PER_CALL):
            page = self.search_page(
                http,
                session,
                query,
                filters,
                next_url=next_url,
                metadata_fetch_budget=metadata_fetch_budget,
            )
            for result in page.results:
                key = str(result.url)
                if key in seen_results:
                    continue
                seen_results.add(key)
                results.append(result)
                if len(results) >= filters.limit:
                    return results
            if page.next_url is None:
                return results
            if page.next_url in seen_pages:
                raise ProviderContractError(
                    "provider search continuation loop detected"
                )
            seen_pages.add(page.next_url)
            next_url = page.next_url
            metadata_fetch_budget = page.remaining_metadata_fetches
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
        search = self.spec.require_html_search()
        if metadata_fetch_budget is not None and metadata_fetch_budget < 0:
            raise ProviderContractError(
                "search metadata fetch budget cannot be negative"
            )
        search_url = next_url or (
            f"{search.endpoint}?{urlencode({search.query_parameter: query})}"
        )
        if next_url is not None:
            _validate_search_continuation(
                search_url,
                str(search.endpoint),
                query_parameter=search.query_parameter,
                query=query,
                page_parameter=search.page_parameter,
            )
        fetch = http.get(
            search_url,
            session=session,
            timeout=_SEARCH_REQUEST_TIMEOUT_SECONDS,
        )
        document = _search_document(fetch)
        _validate_search_identity(
            fetch,
            search_url,
            query_parameter=search.query_parameter,
            query=query,
        )

        anchors = _xpath_union_elements(document, search.result_xpath)
        embedded_published = _embedded_published(
            document,
            self.spec,
            self.normalize_url,
        )
        candidates: list[SearchResult] = []
        seen: set[str] = set()
        for anchor in anchors:
            if not isinstance(anchor, html.HtmlElement):
                continue
            normalized = self.normalize_url(anchor.get(search.href_attribute) or "")
            headline = _visible_text(anchor)
            if (
                normalized is None
                or not headline
                or any(
                    headline.startswith(prefix)
                    for prefix in search.rejected_headline_prefixes
                )
                or normalized in seen
            ):
                continue
            seen.add(normalized)
            candidates.append(
                SearchResult(
                    provider=self.key,
                    url=HttpUrl(normalized),
                    headline=headline,
                    published=(
                        _published(anchor, self.spec)
                        or embedded_published.get(normalized)
                        or self._published_from_url(normalized)
                    ),
                )
            )
        if not candidates and not _proves_empty_search(document, self.spec):
            raise ProviderContractError(
                "provider search page matched neither results nor empty evidence"
            )
        budget = (
            search.missing_published_fetch_limit
            if metadata_fetch_budget is None
            else min(
                metadata_fetch_budget,
                search.missing_published_fetch_limit,
            )
        )
        metadata_fetches = 0
        if budget:
            candidates, metadata_fetches = self._enrich_missing_published(
                http,
                session,
                candidates,
                candidate_limit=filters.limit,
                fetch_limit=budget,
            )
        filtered = tuple(_filtered_results(candidates, filters, limit=None))
        return ProviderSearchPage(
            results=filtered,
            next_url=_next_search_url(document, fetch, self.spec, query),
            remaining_metadata_fetches=budget - metadata_fetches,
            undated_excluded_count=sum(
                filters.excludes_undated(candidate.published)
                for candidate in candidates
            ),
        )

    def _published_from_url(self, normalized_url: str) -> datetime | None:
        search = self.spec.require_html_search()
        group = search.published_date_identity_group
        if group is None:
            return None
        match = self._identity_pattern.fullmatch(urlsplit(normalized_url).path)
        if match is None:  # pragma: no cover - normalized URL invariant
            return None
        try:
            parsed = datetime.strptime(
                match.group(group),
                search.published_date_format,
            )
        except (TypeError, ValueError):
            return None
        return parsed.replace(tzinfo=UTC)

    def _enrich_missing_published(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        candidates: list[SearchResult],
        *,
        candidate_limit: int,
        fetch_limit: int,
    ) -> tuple[list[SearchResult], int]:
        missing = [
            candidate
            for candidate in candidates[:candidate_limit]
            if candidate.published is None
        ][:fetch_limit]
        if not missing:
            return candidates, 0

        recovered: dict[str, datetime] = {}
        attempted = 0
        for candidate in missing:
            attempted += 1
            outcome = self._article_published(http, session, str(candidate.url))
            if outcome.published is not None:
                recovered[str(candidate.url)] = outcome.published
            if outcome.stop_provider:
                break
        return (
            [
                candidate.model_copy(
                    update={"published": recovered.get(str(candidate.url))}
                )
                if candidate.published is None
                else candidate
                for candidate in candidates
            ],
            attempted,
        )

    def _article_published(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        url: str,
    ) -> _PublishedRecovery:
        try:
            fetch = http.get(
                url,
                session=session,
                timeout=_SEARCH_METADATA_TIMEOUT_SECONDS,
            )
        except ProviderTransportError:
            return _PublishedRecovery(None, stop_provider=True)
        if (
            fetch.http_status == 429
            or 500 <= fetch.http_status < 600
            or self.retry_response(fetch)
        ):
            return _PublishedRecovery(None, stop_provider=True)
        if not 200 <= fetch.http_status < 300 or not _is_html(fetch.content_type):
            return _PublishedRecovery(None)
        document = _document(fetch.raw_html)
        if document is None:
            return _PublishedRecovery(None)

        requested = self.normalize_url(url)
        final = self.normalize_url(str(fetch.final_url))
        canonicals = _canonical_urls(document, self.normalize_url)
        if requested is None or final != requested or canonicals != [requested]:
            return _PublishedRecovery(None)

        json_ld, _ = news_article_json_ld(document)
        values: list[object] = []
        if json_ld is not None:
            values.append(json_ld.get("datePublished"))
        values.extend(
            document.xpath(
                "//meta[translate(@property, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', "
                "'abcdefghijklmnopqrstuvwxyz')='article:published_time']/@content | "
                "//*[@itemprop='datePublished']/@content"
            )
        )
        return _PublishedRecovery(_first_aware_datetime(values))

    def fetch(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch:
        if not self.owns_url(url):
            raise ValueError(f"{self.key} fetch requires an owned article URL")
        return http.get(url, session=session)

    def assess(
        self,
        requested_url: str,
        fetch: RawFetch,
        extraction: ExtractedArticle,
    ) -> ArticleAssessment:
        requested_id = self.article_id(requested_url)
        final_url = str(fetch.final_url)
        final_id = self.article_id(final_url)
        document = _document(fetch.raw_html)
        markers = _negative_markers(self.spec, document, final_url)
        signals: list[str] = []

        challenge_marker = _MARKER["challenge"]
        if challenge_marker in markers:
            state, reason = _NEGATIVE_RESULT["challenge"]
            return _assessment(
                state,
                extraction,
                fetch,
                reason=reason,
                provider_article_id=requested_id,
                negative_markers=markers,
            )
        for kind in ("authentication", "paywall"):
            marker = _MARKER[kind]
            if marker in markers:
                state, reason = _NEGATIVE_RESULT[kind]
                return _assessment(
                    state,
                    extraction,
                    fetch,
                    reason=reason,
                    provider_article_id=requested_id,
                    negative_markers=markers,
                )
        if not 200 <= fetch.http_status < 300:
            return _assessment(
                AccessState.UNKNOWN,
                extraction,
                fetch,
                reason=_verification_reason("http_error", fetch.http_status),
                provider_article_id=requested_id,
                negative_markers=("http_error",),
            )
        if document is None:
            return _assessment(
                AccessState.UNKNOWN,
                extraction,
                fetch,
                reason="invalid_html",
                provider_article_id=requested_id,
            )

        canonical_urls = _canonical_urls(document, self.normalize_url)
        canonical_url = canonical_urls[0] if len(canonical_urls) == 1 else None
        canonical_id = self.article_id(canonical_url or "")
        if len(canonical_urls) > 1:
            signals.append("canonical_conflict")
        if canonical_id is not None:
            signals.append(self.spec.assessment.canonical_signal)

        json_ld, json_ld_state = news_article_json_ld(
            document, article_types=self._jsonld_article_types
        )
        if json_ld is not None:
            signals.append("newsarticle_jsonld")
            headline = json_ld.get("headline")
            if isinstance(headline, str) and headline.strip():
                signals.append("jsonld_headline")
        elif self.spec.assessment.record_jsonld_state:
            signals.append(f"jsonld_{json_ld_state}")
        if _any_element_xpath(document, self.spec.assessment.article_xpath):
            signals.append("article_body_structure")
        if _any_element_xpath(document, self.spec.assessment.page_headline_xpath):
            signals.append("page_headline")
        if extraction.body_markdown.strip():
            signals.append("markdown_body")
        if _metadata_has_headline(extraction):
            signals.append("extracted_headline")

        identity_match = bool(
            requested_id
            and final_id
            and canonical_id
            and requested_id == final_id == canonical_id
            and len(canonical_urls) == 1
        )
        if not identity_match:
            return _assessment(
                AccessState.UNKNOWN,
                extraction,
                fetch,
                reason="article_identity_mismatch",
                provider_article_id=requested_id,
                canonical_url=canonical_url,
                structural_signals=signals,
            )

        observed = set(signals)
        required = set(self.spec.assessment.required_signals)
        alternatives = self.spec.assessment.metadata_alternatives
        metadata_satisfied = not alternatives or any(
            set(alternative).issubset(observed) for alternative in alternatives
        )
        if not required.issubset(observed) or not metadata_satisfied:
            return _assessment(
                AccessState.UNKNOWN,
                extraction,
                fetch,
                reason="insufficient_article_structure",
                provider_article_id=requested_id,
                canonical_url=canonical_url,
                identity_match=True,
                structural_signals=signals,
            )

        minimum_words = self.spec.assessment.minimum_words
        paragraph_floor = self.spec.assessment.paragraph_floor
        if minimum_words is not None and paragraph_floor is not None:
            if extraction.word_count >= minimum_words:
                signals.append("article_word_floor")
            count, substantial = _paragraph_counts(document, paragraph_floor)
            if (
                count >= paragraph_floor.minimum_count
                and substantial >= paragraph_floor.minimum_substantial_count
            ):
                signals.append("article_paragraph_floor")
            if not {
                "article_word_floor",
                "article_paragraph_floor",
            }.issubset(signals):
                return _assessment(
                    AccessState.TEASER,
                    extraction,
                    fetch,
                    reason="paywall_teaser",
                    provider_article_id=requested_id,
                    canonical_url=canonical_url,
                    identity_match=True,
                    structural_signals=signals,
                    negative_markers=("truncated_body",),
                )

        return _assessment(
            AccessState.FULL,
            extraction,
            fetch,
            reason="full_article_verified",
            provider_article_id=requested_id,
            canonical_url=canonical_url,
            identity_match=True,
            structural_signals=signals,
        )

    def rate_budget(self) -> RateBudget:
        return self.spec.rate_budget


class ConfiguredLoginRecipe:
    """Verify one configured provider using its normal assessment path."""

    def __init__(
        self,
        provider: ConfiguredProvider,
        *,
        verification_url: str,
        label: str,
    ) -> None:
        session = provider.spec.session
        if session is None:
            raise ValueError(f"{label} does not use authenticated sessions")
        if provider.normalize_url(verification_url) is None:
            raise ValueError(f"{label} verification URL must be an owned article URL")
        self.provider = provider.key
        self.candidate_verification_mode = session.candidate_verification_mode
        self.allowed_origins = frozenset(session.allowed_origins)
        self.allowed_cookie_domains = frozenset(session.allowed_cookie_domains)
        self.secret_ref = session.secret_ref
        self.verification_url = verification_url
        self._verification_minimum_words = session.verification_minimum_words
        self._provider = provider

    def verify(
        self, http: HttpClient, artifact: SessionArtifact
    ) -> SessionVerification:
        fetch = http.get(self.verification_url, session=artifact)
        return self.verify_fetch(fetch)

    def verify_fetch(self, fetch: RawFetch) -> SessionVerification:
        """Assess one already-observed verification response."""

        extraction = TrafilaturaExtractor().extract(
            fetch, scope_xpath=self._provider.extraction_scope
        )
        assessment = self._provider.assess(self.verification_url, fetch, extraction)
        verified = assessment.promotable
        access_state = assessment.access_state
        reason = _verification_reason(assessment.reason, fetch.http_status)
        if (
            verified
            and self._verification_minimum_words is not None
            and extraction.word_count < self._verification_minimum_words
        ):
            verified = False
            access_state = AccessState.TEASER
            reason = "verification_body_too_short"
        return SessionVerification(
            verified=verified,
            access_state=access_state,
            reason=reason,
            verified_at=fetch.retrieved_at,
        )


def _verification_reason(reason: str, http_status: int) -> str:
    if reason != "http_error":
        return reason
    if http_status == 401:
        return "http_unauthorized"
    if http_status == 403:
        return "http_forbidden"
    if http_status == 429:
        return "http_rate_limited"
    if 400 <= http_status < 500:
        return "http_client_error"
    if 500 <= http_status < 600:
        return "http_server_error"
    if 300 <= http_status < 400:
        return "http_redirect_error"
    return reason


def normalize_url(
    spec: ProviderSpec,
    raw: str,
    *,
    pattern: re.Pattern[str] | None = None,
) -> str | None:
    """Normalize an owned article URL according to one strict identity spec."""

    candidate = raw.strip()
    if candidate.startswith("//"):
        return None
    if candidate.startswith("/"):
        candidate = f"https://{spec.identity.canonical_host}{candidate}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme.lower() != "https"
        or host not in spec.identity.allowed_hosts
        or parsed.username
        or parsed.password
        or port not in {None, 443}
    ):
        return None
    path = parsed.path.rstrip("/") or "/"
    identity_pattern = pattern or re.compile(spec.identity.path_pattern)
    match = identity_pattern.fullmatch(path)
    if match is None:
        return None
    groups = match.groupdict()
    for name in spec.identity.lowercase_groups:
        groups[name] = groups[name].lower()
    canonical_path = (
        spec.identity.canonical_path.format_map(groups)
        if spec.identity.canonical_path is not None
        else path
    )
    return urlunsplit(("https", spec.identity.canonical_host, canonical_path, "", ""))


def provider_article_id(spec: ProviderSpec, raw: str) -> str | None:
    provider = ConfiguredProvider(spec)
    return provider.article_id(raw)


def _published(anchor: html.HtmlElement, spec: ProviderSpec) -> datetime | None:
    search = spec.require_html_search()
    containers = _xpath_elements(anchor, search.published_container_xpath)
    container = containers[0] if containers else anchor
    values = container.xpath(search.published_value_xpath)
    return _first_aware_datetime(values)


def _embedded_published(
    document: html.HtmlElement,
    spec: ProviderSpec,
    normalizer: Callable[[str], str | None],
) -> dict[str, datetime]:
    embedded = spec.require_html_search().embedded_published
    if embedded is None:
        return {}
    scripts = document.xpath(
        "//script[@id=$script_id and "
        "translate(@type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')="
        "'application/json']/text()",
        script_id=embedded.script_id,
    )
    if len(scripts) != 1:
        return {}
    try:
        payload = json.loads(str(scripts[0]))
    except (json.JSONDecodeError, TypeError):
        return {}

    published: dict[str, datetime] = {}
    conflicts: set[str] = set()
    pending: list[object] = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            raw_url = value.get(embedded.url_field)
            raw_published = value.get(embedded.value_field)
            if isinstance(raw_url, str):
                normalized = normalizer(raw_url)
                parsed = _first_aware_datetime([raw_published])
                if normalized is not None and parsed is not None:
                    existing = published.get(normalized)
                    if existing is not None and existing != parsed:
                        conflicts.add(normalized)
                    else:
                        published[normalized] = parsed
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return {url: value for url, value in published.items() if url not in conflicts}


def _first_aware_datetime(values: list[object]) -> datetime | None:
    for value in values:
        parsed = parse_aware_datetime(value)
        if parsed is not None:
            return parsed
    return None


def _filtered_results(
    candidates: list[SearchResult],
    filters: SearchFilters,
    *,
    limit: int | None = None,
) -> list[SearchResult]:
    filtered = [
        candidate
        for candidate in candidates
        if filters.includes_published(candidate.published)
    ]
    return filtered if limit is None else filtered[:limit]


def _is_html(content_type: str | None) -> bool:
    if content_type is None:
        return True
    media_type = content_type.partition(";")[0].strip().lower()
    return media_type in {"text/html", "application/xhtml+xml"}


def _visible_text(element: html.HtmlElement) -> str:
    """Return visible copy without embedded style, script, or template text."""

    values = element.xpath(
        ".//text()[not(ancestor::style) and not(ancestor::script) "
        "and not(ancestor::template) and not(ancestor::noscript)]"
    )
    return " ".join(" ".join(str(value).split()) for value in values).strip()


def _proves_empty_search(document: html.HtmlElement, spec: ProviderSpec) -> bool:
    return _any_element_xpath(document, spec.require_html_search().empty_result_xpath)


def _validate_search_identity(
    fetch: RawFetch,
    search_url: str,
    *,
    query_parameter: str,
    query: str,
) -> None:
    """Require a successful response to remain the requested search page."""

    expected = urlsplit(search_url)
    observed = urlsplit(str(fetch.final_url))
    expected_scheme = expected.scheme.lower()
    observed_scheme = observed.scheme.lower()
    expected_port = expected.port or (443 if expected_scheme == "https" else 80)
    observed_port = observed.port or (443 if observed_scheme == "https" else 80)
    expected_path = expected.path.rstrip("/") or "/"
    observed_path = observed.path.rstrip("/") or "/"
    expected_query = parse_qs(expected.query, keep_blank_values=True)
    observed_query = parse_qs(observed.query, keep_blank_values=True)
    if (
        observed_scheme != expected_scheme
        or (observed.hostname or "").lower() != (expected.hostname or "").lower()
        or observed_port != expected_port
        or observed_path != expected_path
        or observed.username is not None
        or observed.password is not None
        or observed_query.get(query_parameter) != [query]
        or any(
            observed_query.get(key) != values for key, values in expected_query.items()
        )
    ):
        raise ProviderContractError("provider search response identity mismatch")


def _next_search_url(
    document: html.HtmlElement,
    fetch: RawFetch,
    spec: ProviderSpec,
    query: str,
) -> str | None:
    search = spec.require_html_search()
    if not search.next_href_xpath:
        return None
    raw_urls = {
        (element.get(search.href_attribute) or "").strip()
        for element in _xpath_union_elements(document, search.next_href_xpath)
    }
    raw_urls.discard("")
    if not raw_urls:
        return None
    if len(raw_urls) != 1:
        raise ProviderContractError("provider search returned ambiguous continuation")
    resolved = urljoin(str(fetch.final_url), raw_urls.pop())
    return _validate_search_continuation(
        resolved,
        str(search.endpoint),
        query_parameter=search.query_parameter,
        query=query,
        page_parameter=search.page_parameter,
        current_url=str(fetch.final_url),
    )


def _validate_search_continuation(
    candidate: str,
    endpoint: str,
    *,
    query_parameter: str,
    query: str,
    page_parameter: str | None,
    current_url: str | None = None,
) -> str:
    if len(candidate) > _MAX_SEARCH_CONTINUATION_URL_LENGTH:
        raise ProviderContractError("provider search continuation is too long")
    try:
        parsed = urlsplit(candidate)
        expected = urlsplit(endpoint)
        parsed_scheme = parsed.scheme.lower()
        expected_scheme = expected.scheme.lower()
        parsed_port = parsed.port or (443 if parsed_scheme == "https" else 80)
        expected_port = expected.port or (443 if expected_scheme == "https" else 80)
    except ValueError as error:
        raise ProviderContractError(
            "provider search continuation is invalid"
        ) from error
    parsed_path = parsed.path.rstrip("/") or "/"
    expected_path = expected.path.rstrip("/") or "/"
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    pages = parameters.get(page_parameter, []) if page_parameter else []
    if (
        parsed_scheme != "https"
        or parsed_scheme != expected_scheme
        or (parsed.hostname or "").lower() != (expected.hostname or "").lower()
        or parsed_port != expected_port
        or parsed_path != expected_path
        or parsed.username is not None
        or parsed.password is not None
        or parameters.get(query_parameter) != [query]
        or page_parameter is None
        or len(pages) != 1
        or not pages[0].isdigit()
    ):
        raise ProviderContractError("provider search continuation is invalid")
    page = int(pages[0])
    if page < 2 or page > 10_000:
        raise ProviderContractError("provider search continuation page is invalid")
    if current_url is not None:
        current_parameters = parse_qs(
            urlsplit(current_url).query, keep_blank_values=True
        )
        current_pages = current_parameters.get(page_parameter, ["1"])
        if (
            len(current_pages) != 1
            or not current_pages[0].isdigit()
            or page != int(current_pages[0]) + 1
        ):
            raise ProviderContractError(
                "provider search continuation did not advance one page"
            )
    return urlunsplit((parsed_scheme, parsed.netloc, parsed_path, parsed.query, ""))


def _negative_markers(
    spec: ProviderSpec,
    document: html.HtmlElement | None,
    final_url: str,
) -> tuple[str, ...]:
    markers: list[str] = []
    for rule in spec.assessment.negative_rules:
        if _negative_rule_matches(rule, document, final_url):
            marker = _MARKER[rule.kind]
            if marker not in markers:
                markers.append(marker)
    return tuple(markers)


def _negative_rule_matches(
    rule: NegativeRuleSpec,
    document: html.HtmlElement | None,
    final_url: str,
) -> bool:
    try:
        parsed = urlsplit(final_url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower().rstrip("/") or "/"
        normalized_final = urlunsplit((parsed.scheme.lower(), host, path, "", ""))
    except ValueError:
        host = ""
        path = "/"
        normalized_final = ""
    if normalized_final in {url.lower().rstrip("/") for url in rule.final_urls}:
        return True
    if host in rule.final_url_hosts:
        return True
    if path in {value.lower() for value in rule.final_url_paths}:
        return True
    if any(path.startswith(prefix.lower()) for prefix in rule.final_url_path_prefixes):
        return True
    if document is None:
        return False
    title = " ".join(document.xpath("string(//title)").lower().split())
    if title in {value.lower() for value in rule.title_equals}:
        return True
    if _any_element_xpath(document, rule.xpath_any):
        return True
    page_text = " ".join(document.text_content().lower().split())
    return any(marker.lower() in page_text for marker in rule.text_any)


def _xpath_elements(
    document: html.HtmlElement, expression: str
) -> tuple[html.HtmlElement, ...]:
    """Return only element nodes so configured evidence always fails closed."""

    result = document.xpath(expression)
    if not isinstance(result, list):
        return ()
    return tuple(item for item in result if isinstance(item, html.HtmlElement))


def _xpath_union_elements(
    document: html.HtmlElement, expressions: tuple[str, ...]
) -> tuple[html.HtmlElement, ...]:
    """Evaluate fallback selectors as one node set in document order."""

    union = " | ".join(f"({expression})" for expression in expressions)
    return _xpath_elements(document, union)


def _any_element_xpath(
    document: html.HtmlElement, expressions: tuple[str, ...]
) -> bool:
    return any(_xpath_elements(document, expression) for expression in expressions)


def _paragraph_counts(
    document: html.HtmlElement, floor: ParagraphFloorSpec
) -> tuple[int, int]:
    candidates: list[tuple[bool, int, int, int]] = []
    for element in _xpath_elements(document, floor.root_xpath):
        lengths = [
            len(" ".join(paragraph.text_content().split()))
            for paragraph in _xpath_elements(element, floor.paragraph_xpath)
        ]
        non_empty = sum(length > 0 for length in lengths)
        substantial = sum(
            length >= floor.substantial_minimum_characters for length in lengths
        )
        is_preferred = bool(
            floor.preferred_root_xpath
            and _xpath_elements(element, floor.preferred_root_xpath)
        )
        candidates.append((is_preferred, substantial, non_empty, sum(lengths)))
    if not candidates:
        return 0, 0
    preferred_candidates = [candidate for candidate in candidates if candidate[0]]
    selected = max(
        preferred_candidates or candidates,
        key=lambda candidate: (candidate[1], candidate[2], candidate[3]),
    )
    return selected[2], selected[1]
