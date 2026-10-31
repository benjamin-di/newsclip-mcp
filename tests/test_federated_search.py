from __future__ import annotations

from datetime import UTC, datetime
from threading import Barrier, Event
from time import monotonic

import pytest
from pydantic import ValidationError

from newsclip.errors import (
    OperatorActionRequiredError,
    PersistenceError,
    ProviderContractError,
    ProviderTransportError,
    SessionRequiredError,
    TransportFailure,
    UnsearchableQueryError,
)
from newsclip.models import (
    ArticleAssessment,
    ProviderCapabilities,
    ProviderSearchPage,
    RateBudget,
    RawFetch,
    SearchFilters,
    SearchResult,
    SearchSort,
    SourceSearchReason,
    SourceSearchReport,
    SourceSearchState,
)
from newsclip.providers import (
    BloombergProvider,
    FTProvider,
    ProviderRegistry,
    WSJProvider,
)
from newsclip.results import (
    PublicErrorCategory,
    classify_error,
    public_error,
)
from newsclip.service import (
    FederatedSearchPager,
    NewsclipService,
    _ordered_search_batch,
)

NOW = datetime(2026, 7, 20, tzinfo=UTC)


class FakeHttp:
    def get(self, url, *, session=None, timeout: float = 40):
        raise AssertionError("fixture providers do not use HTTP")


class FakeExtractor:
    name = "fixture"
    version = "1"

    def extract(self, fetch, *, scope_xpath=None):  # pragma: no cover - search only
        raise AssertionError("search does not extract articles")


class SearchProvider:
    login_recipe = None
    assessment_policy_version = "fixture-v1"
    extraction_scope: tuple[str, ...] | None = None

    def __init__(
        self,
        key: str,
        results: list[SearchResult] | None = None,
        *,
        error: Exception | None = None,
        requires_session: bool = False,
        barrier: Barrier | None = None,
        coverage_start: datetime | None = None,
    ) -> None:
        self.key = key
        self.results = results or []
        self.error = error
        self.barrier = barrier
        self.coverage_start = coverage_start
        self.queries: list[str] = []
        self.capabilities = ProviderCapabilities(
            requires_session_for_retrieve=False,
            requires_session_for_search=requires_session,
        )

    def owns_url(self, url: str) -> bool:
        return url.startswith(f"https://{self.key}.test/") or url.startswith(
            "https://shared.test/"
        )

    def search(self, http, session, query: str, filters: SearchFilters):
        self.queries.append(query)
        if self.barrier is not None:
            self.barrier.wait(timeout=2)
        if self.error is not None:
            raise self.error
        return self.results[: filters.limit]

    def search_page(
        self,
        http,
        session,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        assert next_url is None
        return ProviderSearchPage(
            results=tuple(self.search(http, session, query, filters)),
            coverage_start=self.coverage_start,
        )

    def fetch(self, http, session, url: str) -> RawFetch:  # pragma: no cover
        raise AssertionError("search does not fetch articles")

    def assess(self, requested_url, fetch, extraction) -> ArticleAssessment:
        raise AssertionError("search does not assess articles")

    def rate_budget(self) -> RateBudget:
        return RateBudget(requests_per_second=1000, burst=1000)


class PagedSearchProvider(SearchProvider):
    def __init__(
        self,
        key: str,
        pages: dict[str | None, ProviderSearchPage],
        *,
        fail_once: set[str | None] | None = None,
    ) -> None:
        super().__init__(key)
        self.pages = pages
        self.fail_once = set(fail_once or ())
        self.page_calls: list[str | None] = []

    def search_page(
        self,
        http,
        session,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        self.page_calls.append(next_url)
        if next_url in self.fail_once:
            self.fail_once.remove(next_url)
            raise ProviderTransportError("fixture continuation failure")
        return self.pages[next_url]


def _result(
    provider: str,
    slug: str,
    *,
    published: datetime | None = None,
    url: str | None = None,
) -> SearchResult:
    return SearchResult(
        provider=provider,
        url=url or f"https://{provider}.test/{slug}",
        headline=f"{provider} {slug}",
        published=published,
    )


def _service(*providers: SearchProvider, sessions=None) -> NewsclipService:
    return NewsclipService(
        ProviderRegistry(providers),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
        network_sleep=lambda _seconds: None,
    )


def test_search_many_is_concurrent_fair_deterministic_and_deduplicated() -> None:
    barrier = Barrier(2)
    shared = "https://shared.test/article"
    alpha = SearchProvider(
        "alpha",
        [
            _result("alpha", "one", published=datetime(2026, 7, 18, tzinfo=UTC)),
            _result(
                "alpha",
                "shared",
                published=datetime(2026, 7, 17, tzinfo=UTC),
                url=shared,
            ),
            _result("alpha", "three"),
        ],
        barrier=barrier,
    )
    beta = SearchProvider(
        "beta",
        [
            _result("beta", "one", published=datetime(2026, 7, 19, tzinfo=UTC)),
            _result(
                "beta",
                "shared",
                published=datetime(2026, 7, 16, tzinfo=UTC),
                url="https://SHARED.test:443/article#section",
            ),
            _result("beta", "three", published=datetime(2026, 7, 15, tzinfo=UTC)),
        ],
        barrier=barrier,
    )

    response = _service(alpha, beta).search_many(
        "  bank capital  ",
        SearchFilters(limit=5),
    )

    assert response.query == "bank capital"
    assert [str(item.url) for item in response.results] == [
        "https://beta.test/one",
        "https://alpha.test/one",
        shared,
        "https://beta.test/three",
        "https://alpha.test/three",
    ]
    assert [source.provider for source in response.sources] == ["alpha", "beta"]
    assert [source.result_count for source in response.sources] == [3, 3]
    assert [source.missing_published_count for source in response.sources] == [1, 0]
    assert alpha.queries == ["bank capital"]
    assert beta.queries == ["bank capital"]


def test_newest_order_is_deterministic_and_places_unknown_dates_last() -> None:
    provider = SearchProvider(
        "alpha",
        [
            _result("alpha", "unknown"),
            _result("alpha", "same-b", published=NOW),
            _result("alpha", "older", published=datetime(2026, 7, 19, tzinfo=UTC)),
            _result("alpha", "same-a", published=NOW),
        ],
    )

    results = _service(provider).search(
        "alpha",
        "rates",
        SearchFilters(sort=SearchSort.NEWEST),
    )

    assert [result.headline for result in results] == [
        "alpha same-a",
        "alpha same-b",
        "alpha older",
        "alpha unknown",
    ]


def test_bounded_batch_ordering_is_non_mutating_and_reversible() -> None:
    balanced = [
        _result("alpha", "undated"),
        _result("beta", "newest", published=NOW),
        _result("alpha", "older", published=datetime(2026, 7, 19, tzinfo=UTC)),
    ]

    newest = _ordered_search_batch(balanced, SearchSort.NEWEST)
    restored = _ordered_search_batch(balanced, SearchSort.BALANCED)

    assert [result.headline for result in newest] == [
        "beta newest",
        "alpha older",
        "alpha undated",
    ]
    assert restored == tuple(balanced)
    assert [result.headline for result in balanced] == [
        "alpha undated",
        "beta newest",
        "alpha older",
    ]


def test_newest_order_is_local_to_each_balanced_pager_batch() -> None:
    alpha = SearchProvider(
        "alpha",
        [
            _result("alpha", "rank-one", published=datetime(2026, 7, 18, tzinfo=UTC)),
            _result("alpha", "rank-two", published=datetime(2026, 7, 20, tzinfo=UTC)),
        ],
    )
    beta = SearchProvider(
        "beta",
        [
            _result("beta", "rank-one", published=datetime(2026, 7, 17, tzinfo=UTC)),
            _result("beta", "rank-two", published=datetime(2026, 7, 19, tzinfo=UTC)),
        ],
    )
    pager = _service(alpha, beta).search_pager(
        "markets",
        SearchFilters(limit=2, sort=SearchSort.NEWEST),
    )

    first = pager.next_batch(2)
    second = pager.next_batch(2)

    assert [result.headline for result in first.results] == [
        "alpha rank-one",
        "beta rank-one",
    ]
    assert [result.headline for result in second.results] == [
        "alpha rank-two",
        "beta rank-two",
    ]
    assert first.has_more is True
    assert second.has_more is False


def test_pager_is_lazy_fair_and_deduplicates_across_batches() -> None:
    shared = "https://shared.test/article"
    alpha = PagedSearchProvider(
        "alpha",
        {
            None: ProviderSearchPage(
                results=(
                    _result("alpha", "shared", url=shared),
                    _result("alpha", "two"),
                ),
                next_url="alpha-page-2",
            ),
            "alpha-page-2": ProviderSearchPage(results=(_result("alpha", "three"),)),
        },
    )
    beta = PagedSearchProvider(
        "beta",
        {
            None: ProviderSearchPage(
                results=(
                    _result("beta", "shared", url=shared),
                    _result("beta", "two"),
                )
            )
        },
    )
    pager = _service(alpha, beta).search_pager("markets", SearchFilters(limit=2))

    first = pager.next_batch(2)

    assert [result.headline for result in first.results] == [
        "alpha shared",
        "alpha two",
    ]
    assert first.has_more is True
    assert alpha.page_calls == [None]
    assert beta.page_calls == [None]

    second = pager.next_batch(2)

    assert [result.headline for result in second.results] == [
        "beta two",
        "alpha three",
    ]
    assert second.has_more is False
    assert alpha.page_calls == [None, "alpha-page-2"]
    assert beta.page_calls == [None]
    assert [source.result_count for source in second.sources] == [3, 2]


def test_pager_retries_a_failed_continuation_without_advancing_it() -> None:
    provider = PagedSearchProvider(
        "alpha",
        {
            None: ProviderSearchPage(
                results=(_result("alpha", "one"),), next_url="page-2"
            ),
            "page-2": ProviderSearchPage(results=(_result("alpha", "two"),)),
        },
        fail_once={"page-2"},
    )
    pager = _service(provider).search_pager("markets", SearchFilters(limit=1))

    assert [result.headline for result in pager.next_batch(1).results] == ["alpha one"]
    failed = pager.next_batch(1)
    retried = pager.next_batch(1)

    assert failed.results == ()
    assert failed.has_more is True
    assert failed.sources[0].state is SourceSearchState.UNAVAILABLE
    assert [result.headline for result in retried.results] == ["alpha two"]
    assert retried.has_more is False
    assert provider.page_calls == [None, "page-2", "page-2"]


class StallingSearchProvider(SearchProvider):
    """Holds its first page until released, then answers normally."""

    def __init__(self, key: str, results: list[SearchResult]) -> None:
        super().__init__(key, results)
        self.release = Event()
        self.finished = Event()
        self.calls = 0

    def search_page(
        self,
        http,
        session,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        self.calls += 1
        if self.calls == 1:
            assert self.release.wait(timeout=10)
        try:
            return super().search_page(
                http,
                session,
                query,
                filters,
                next_url=next_url,
                metadata_fetch_budget=metadata_fetch_budget,
            )
        finally:
            if self.calls == 1:
                self.finished.set()


def test_pager_reports_a_straggler_as_timeout_without_waiting_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FederatedSearchPager, "_BATCH_DEADLINE_SECONDS", 0.2)
    slow = StallingSearchProvider("slow", [_result("slow", "one")])
    fast = SearchProvider("fast", [_result("fast", "one")])
    pager = _service(slow, fast).search_pager("markets", SearchFilters(limit=5))

    started = monotonic()
    try:
        first = pager.next_batch(5)
        elapsed = monotonic() - started
    finally:
        slow.release.set()

    assert elapsed < 5
    assert [result.headline for result in first.results] == ["fast one"]
    assert first.sources[0].state is SourceSearchState.UNAVAILABLE
    assert first.sources[0].reason is SourceSearchReason.TIMEOUT
    assert first.sources[1].state is SourceSearchState.OK
    assert first.has_more is True
    envelope = public_error(
        ProviderTransportError("fixture", category=TransportFailure.TIMEOUT)
    )
    assert envelope is not None and envelope.retryable is True

    # The abandoned worker finishes after the response; its page is never
    # applied, so the next batch requests the same first page afresh.
    assert slow.finished.wait(timeout=5)
    second = pager.next_batch(5)

    assert [result.headline for result in second.results] == ["slow one"]
    assert [source.state for source in second.sources] == [
        SourceSearchState.OK,
        SourceSearchState.OK,
    ]
    assert [source.result_count for source in second.sources] == [1, 1]
    assert second.has_more is False
    assert slow.calls == 2


def test_every_source_straggling_is_an_aggregate_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FederatedSearchPager, "_BATCH_DEADLINE_SECONDS", 0.1)
    slow = StallingSearchProvider("slow", [_result("slow", "one")])
    pager = _service(slow).search_pager("markets")

    try:
        with pytest.raises(ProviderTransportError) as failure:
            pager.next_batch(5)
    finally:
        slow.release.set()

    assert failure.value.category is TransportFailure.TIMEOUT
    assert failure.value.retryable is True


def test_pager_terminates_a_provider_with_a_continuation_loop() -> None:
    provider = PagedSearchProvider(
        "alpha",
        {
            None: ProviderSearchPage(
                results=(_result("alpha", "one"),), next_url="page-2"
            ),
            "page-2": ProviderSearchPage(results=(), next_url="page-2"),
        },
    )
    pager = _service(provider).search_pager("markets", SearchFilters(limit=1))

    first = pager.next_batch(1)
    failed = pager.next_batch(1)
    repeated = pager.next_batch(1)

    assert [result.headline for result in first.results] == ["alpha one"]
    assert failed.results == ()
    assert failed.has_more is False
    assert failed.sources[0].state is SourceSearchState.UNAVAILABLE
    assert failed.sources[0].reason is SourceSearchReason.CONTRACT
    assert repeated == failed
    assert provider.page_calls == [None, "page-2"]


def test_pager_bounds_empty_upstream_page_scans_per_batch() -> None:
    pages = {
        None: ProviderSearchPage(results=(), next_url="page-2"),
        **{
            f"page-{page}": ProviderSearchPage(
                results=(),
                next_url=f"page-{page + 1}",
            )
            for page in range(2, 12)
        },
    }
    provider = PagedSearchProvider("alpha", pages)
    pager = _service(provider).search_pager("markets")

    response = pager.next_batch(20)

    assert response.results == ()
    assert response.has_more is True
    assert len(provider.page_calls) == 10


def test_partial_failure_succeeds_and_preserves_source_statuses() -> None:
    unavailable = SearchProvider(
        "offline",
        error=ProviderTransportError("fixture outage"),
    )
    empty = SearchProvider("empty")

    response = _service(unavailable, empty).search_many("rates")

    assert response.results == ()
    assert [source.state for source in response.sources] == [
        SourceSearchState.UNAVAILABLE,
        SourceSearchState.OK,
    ]
    assert response.sources[0].reason is SourceSearchReason.TRANSPORT
    assert response.sources[1].result_count == 0


@pytest.mark.parametrize("category", list(TransportFailure))
def test_every_transport_category_has_a_publishable_envelope(
    category: TransportFailure,
) -> None:
    """The public categories are a smaller, stable set than the internal ones.

    Resolving one from the other by value silently required the two enums to
    stay identical, so adding an internal category made the envelope that
    exists to keep failures legible raise ValueError instead. Walking every
    member keeps that coupling from being reintroduced.
    """

    envelope = public_error(ProviderTransportError("fixture", category=category))

    assert envelope is not None
    assert envelope.exit_code == 5
    assert envelope.category in set(PublicErrorCategory)


@pytest.mark.parametrize(
    ("category", "reason"),
    [
        (TransportFailure.RATE_LIMITED, SourceSearchReason.RATE_LIMITED),
        (TransportFailure.PROVIDER_ERROR, SourceSearchReason.PROVIDER_ERROR),
    ],
)
def test_a_provider_answered_refusal_is_named_in_its_source_report(
    category: TransportFailure, reason: SourceSearchReason
) -> None:
    """This report is what the outer watchdog pages on.

    Reporting a throttling or erroring provider as ``transport`` there is what
    sent the 2026-08-10 FT page's reader looking for a tunnel fault.
    """

    refused = SearchProvider(
        "refused", error=ProviderTransportError("fixture refusal", category=category)
    )
    healthy = SearchProvider("healthy")

    response = _service(refused, healthy).search_many("rates")

    assert response.sources[0].state is SourceSearchState.UNAVAILABLE
    assert response.sources[0].reason is reason
    assert response.sources[1].state is SourceSearchState.OK


class ThrottledHttp:
    def __init__(self) -> None:
        self.calls = 0

    def get(self, url, *, session=None, timeout: float = 40):
        self.calls += 1
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=429,
            content_type="text/html",
            retry_after=30,
            retrieved_at=NOW,
            raw_html=b"THROTTLED",
        )


class TwoRequestSearchProvider(SearchProvider):
    def search(self, http, session, query: str, filters: SearchFilters):
        self.queries.append(query)
        # The second request meets the deferral the first 429 published.
        http.get(f"https://{self.key}.test/search?page=1")
        http.get(f"https://{self.key}.test/search?page=2")
        raise AssertionError("an active long deferral must refuse the request")


def test_a_long_retry_after_is_a_rate_limited_source_not_a_stalled_search() -> None:
    throttled = TwoRequestSearchProvider("throttled")
    healthy = SearchProvider("healthy", [_result("healthy", "one")])
    http = ThrottledHttp()
    service = NewsclipService(
        ProviderRegistry((throttled, healthy)),
        http,
        FakeExtractor(),
        network_sleep=lambda _seconds: pytest.fail("no in-process wait"),
    )

    response = service.search_many("rates")

    assert http.calls == 1
    assert [result.headline for result in response.results] == ["healthy one"]
    assert response.sources[0].state is SourceSearchState.UNAVAILABLE
    assert response.sources[0].reason is SourceSearchReason.RATE_LIMITED
    assert response.sources[1].state is SourceSearchState.OK


@pytest.mark.parametrize(
    ("state", "result_count", "reason"),
    [
        (SourceSearchState.OK, 0, SourceSearchReason.TRANSPORT),
        (SourceSearchState.UNAVAILABLE, 0, None),
        (SourceSearchState.UNAVAILABLE, 1, SourceSearchReason.TRANSPORT),
        (
            SourceSearchState.UNAVAILABLE,
            0,
            SourceSearchReason.SESSION_REQUIRED,
        ),
        (
            SourceSearchState.NEEDS_ATTENTION,
            0,
            SourceSearchReason.TRANSPORT,
        ),
    ],
)
def test_source_report_rejects_inconsistent_failure_contracts(
    state: SourceSearchState,
    result_count: int,
    reason: SourceSearchReason | None,
) -> None:
    with pytest.raises(ValidationError):
        SourceSearchReport(
            provider="fixture",
            state=state,
            result_count=result_count,
            reason=reason,
        )


def test_source_report_rejects_inconsistent_missing_publication_counts() -> None:
    with pytest.raises(ValidationError, match="cannot exceed"):
        SourceSearchReport(
            provider="fixture",
            state=SourceSearchState.OK,
            result_count=1,
            missing_published_count=2,
        )
    with pytest.raises(ValidationError, match="zero result counts"):
        SourceSearchReport(
            provider="fixture",
            state=SourceSearchState.UNAVAILABLE,
            result_count=0,
            missing_published_count=1,
            reason=SourceSearchReason.TRANSPORT,
        )


def test_unsearchable_query_is_a_request_fault_not_a_provider_outage() -> None:
    """The caller's query failed, so no surface may blame the provider route.

    Before this, the CLI answered "provider transport failed" with a hint to run
    'newsclip doctor' — sending someone to diagnose a healthy provider — and a
    script retrying on transport errors would retry a query that can never work.
    """

    rejecting = SearchProvider("rejecting", error=UnsearchableQueryError("q"))

    with pytest.raises(UnsearchableQueryError):
        _service(rejecting).search_many("the and of")

    assert classify_error(UnsearchableQueryError("q")) == (PublicErrorCategory.USAGE, 2)
    # The same query yields the same empty token set, so no retry wrapper may
    # spend attempts on it.
    assert UnsearchableQueryError("q").retryable is False
    envelope = public_error(UnsearchableQueryError("unsearchable_query"))
    assert envelope is not None
    assert envelope.public_dict() == {
        "ok": False,
        "retryable": False,
        "action": "none",
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "reason": "unsearchable_query",
    }


def test_one_unsearchable_source_never_speaks_for_the_whole_batch() -> None:
    """Containment is unchanged: only the rejecting source reports the fault."""

    rejecting = SearchProvider("rejecting", error=UnsearchableQueryError("q"))
    healthy = SearchProvider("healthy", [_result("healthy", "one")])

    response = _service(rejecting, healthy).search_many("markets")
    reports = {report.provider: report for report in response.sources}

    assert [str(r.url) for r in response.results] == ["https://healthy.test/one"]
    assert reports["rejecting"].state is SourceSearchState.UNAVAILABLE
    # Not CONTRACT: the provider is healthy and its page contract intact, so an
    # operator must not be sent hunting for parser drift.
    assert reports["rejecting"].reason is SourceSearchReason.UNSEARCHABLE_QUERY
    assert reports["healthy"].state is SourceSearchState.OK


def test_a_mixed_failure_batch_keeps_the_generic_aggregate() -> None:
    """One source rejecting the query does not make it the batch's story."""

    rejecting = SearchProvider("rejecting", error=UnsearchableQueryError("q"))
    timing_out = SearchProvider(
        "timing-out",
        error=ProviderTransportError("slow", category=TransportFailure.TIMEOUT),
    )

    with pytest.raises(ProviderTransportError) as caught:
        _service(rejecting, timing_out).search_many("markets")

    assert not isinstance(caught.value, UnsearchableQueryError)
    assert str(caught.value) == "search failed for all selected providers"


def test_source_report_rejects_coverage_claims_on_a_failed_source() -> None:
    """A source that returned nothing cannot describe how far back it searched."""

    with pytest.raises(ValidationError, match="claim search coverage"):
        SourceSearchReport(
            provider="fixture",
            state=SourceSearchState.UNAVAILABLE,
            result_count=0,
            reason=SourceSearchReason.TRANSPORT,
            coverage_start=datetime(2026, 7, 21, tzinfo=UTC),
        )


def test_coverage_start_round_trips_only_for_a_provider_that_claims_one() -> None:
    """The field is additive: a provider that makes no claim serializes null.

    Removing the key for those providers would change a shape clients already
    handle, so the disclosure is carried as an explicit "no claim" instead.
    """

    window = SearchProvider(
        "window",
        [_result("window", "one")],
        coverage_start=datetime(2026, 7, 21, 10, 34, tzinfo=UTC),
    )
    archive = SearchProvider("archive", [_result("archive", "two")])

    response = _service(window, archive).search_many("markets")
    reports = {report.provider: report for report in response.sources}

    assert reports["window"].coverage_start == datetime(2026, 7, 21, 10, 34, tzinfo=UTC)
    assert reports["window"].public_dict()["coverage_start"] == "2026-07-21T10:34:00Z"
    assert reports["archive"].coverage_start is None
    assert reports["archive"].public_dict()["coverage_start"] is None


def test_session_gated_source_needs_attention_without_blocking_others() -> None:
    gated = SearchProvider("gated", requires_session=True)
    public = SearchProvider("public", [_result("public", "one")])

    response = _service(gated, public).search_many("markets")

    assert [item.provider for item in response.results] == ["public"]
    assert [source.state for source in response.sources] == [
        SourceSearchState.NEEDS_ATTENTION,
        SourceSearchState.OK,
    ]
    assert response.sources[0].reason is SourceSearchReason.SESSION_REQUIRED
    assert gated.queries == []


def test_search_many_auto_acquires_each_gated_source_at_most_once() -> None:
    class GateStore:
        ready = False

        def get_valid_session(self, provider: str, account_key: str = "default"):
            if not self.ready:
                raise SessionRequiredError("fixture session required")
            return object()

    store = GateStore()
    gated = SearchProvider(
        "gated",
        [_result("gated", "one")],
        requires_session=True,
    )
    acquisitions: list[str] = []

    def acquire(provider: str) -> None:
        acquisitions.append(provider)
        store.ready = True

    response = _service(gated, sessions=store).search_many(
        "markets",
        acquire_session=acquire,
    )

    assert [item.provider for item in response.results] == ["gated"]
    assert acquisitions == ["gated"]
    assert gated.queries == ["markets"]


def test_public_search_opportunistically_reuses_a_verified_session() -> None:
    marker = object()

    class WarmStore:
        def get_valid_session(self, provider: str, account_key: str = "default"):
            assert provider == "public"
            return marker

    class ObservingProvider(SearchProvider):
        observed_session = None

        def search(self, http, session, query: str, filters: SearchFilters):
            self.observed_session = session
            return super().search(http, session, query, filters)

    public = ObservingProvider("public", [_result("public", "one")])

    response = _service(public, sessions=WarmStore()).search_many("markets")

    assert [item.provider for item in response.results] == ["public"]
    assert public.observed_session is marker


def test_broken_session_preflight_is_partial_provider_failure() -> None:
    class BrokenStore:
        def get_valid_session(self, provider: str, account_key: str = "default"):
            raise PersistenceError("fixture state failure")

    gated = SearchProvider("gated", requires_session=True)
    public = SearchProvider("public", [_result("public", "one")])

    response = _service(gated, public, sessions=BrokenStore()).search_many(
        "markets",
        acquire_session=lambda provider: pytest.fail("must not acquire"),
    )

    assert [item.provider for item in response.results] == ["public"]
    assert [source.state for source in response.sources] == [
        SourceSearchState.UNAVAILABLE,
        SourceSearchState.OK,
    ]
    assert response.sources[0].reason is SourceSearchReason.PERSISTENCE


def test_all_selected_failures_prioritize_session_required() -> None:
    unavailable = SearchProvider(
        "offline",
        error=ProviderTransportError("fixture outage"),
    )
    gated = SearchProvider("gated", requires_session=True)

    with pytest.raises(SessionRequiredError, match="explicit login"):
        _service(unavailable, gated).search_many("markets")


@pytest.mark.parametrize(
    ("error", "state", "reason"),
    [
        (
            OperatorActionRequiredError("fixture action"),
            SourceSearchState.NEEDS_ATTENTION,
            SourceSearchReason.OPERATOR_ACTION,
        ),
        (
            SessionRequiredError("fixture session"),
            SourceSearchState.NEEDS_ATTENTION,
            SourceSearchReason.SESSION_REQUIRED,
        ),
        (
            ProviderTransportError(
                "fixture timeout", category=TransportFailure.TIMEOUT
            ),
            SourceSearchState.UNAVAILABLE,
            SourceSearchReason.TIMEOUT,
        ),
        (
            ProviderTransportError("fixture dns", category=TransportFailure.DNS),
            SourceSearchState.UNAVAILABLE,
            SourceSearchReason.DNS,
        ),
        (
            ProviderContractError("fixture contract"),
            SourceSearchState.UNAVAILABLE,
            SourceSearchReason.CONTRACT,
        ),
        (
            PersistenceError("fixture persistence"),
            SourceSearchState.UNAVAILABLE,
            SourceSearchReason.PERSISTENCE,
        ),
    ],
)
def test_partial_failure_reports_a_typed_reason(
    error: Exception,
    state: SourceSearchState,
    reason: SourceSearchReason,
) -> None:
    failing = SearchProvider("failing", error=error)
    public = SearchProvider("public", [_result("public", "one")])

    response = _service(failing, public).search_many("markets")

    assert response.sources[0].state is state
    assert response.sources[0].reason is reason
    assert response.sources[1].reason is None


def test_all_selected_failures_prioritize_operator_action() -> None:
    action = SearchProvider(
        "action",
        error=OperatorActionRequiredError("fixture action required"),
    )
    gated = SearchProvider("gated", requires_session=True)

    with pytest.raises(OperatorActionRequiredError, match="action required"):
        _service(gated, action).search_many("markets")


def test_all_persistence_failures_preserve_persistence_category() -> None:
    first = SearchProvider("first", error=PersistenceError("fixture persistence"))
    second = SearchProvider("second", error=PersistenceError("fixture persistence"))

    with pytest.raises(PersistenceError, match="fixture persistence"):
        _service(first, second).search_many("markets")


@pytest.mark.parametrize(
    "category",
    [TransportFailure.TIMEOUT, TransportFailure.DNS],
)
def test_agreeing_transport_failures_preserve_category(
    category: TransportFailure,
) -> None:
    first = SearchProvider(
        "first", error=ProviderTransportError("fixture one", category=category)
    )
    second = SearchProvider(
        "second", error=ProviderTransportError("fixture two", category=category)
    )

    with pytest.raises(ProviderTransportError) as raised:
        _service(first, second).search_many("markets")

    assert raised.value.category is category


@pytest.mark.parametrize(
    "category",
    [TransportFailure.RATE_LIMITED, TransportFailure.PROVIDER_ERROR],
)
def test_provider_answered_refusals_stay_generic_in_the_aggregate(
    category: TransportFailure,
) -> None:
    """The naming is for the per-source reports, not the published contract.

    Those reports are what the outer watchdog reads. Widening the aggregate
    category would push these into the public envelope's smaller category set
    for no operator benefit, so a unanimous refusal still reports as the
    generic transport failure.
    """

    first = SearchProvider(
        "first", error=ProviderTransportError("fixture one", category=category)
    )
    second = SearchProvider(
        "second", error=ProviderTransportError("fixture two", category=category)
    )

    with pytest.raises(ProviderTransportError) as raised:
        _service(first, second).search_many("markets")

    assert raised.value.category is TransportFailure.TRANSPORT


def test_mixed_failures_collapse_to_generic_transport() -> None:
    timeout = SearchProvider(
        "timeout",
        error=ProviderTransportError(
            "fixture timeout", category=TransportFailure.TIMEOUT
        ),
    )
    dns = SearchProvider(
        "dns",
        error=ProviderTransportError("fixture dns", category=TransportFailure.DNS),
    )

    with pytest.raises(ProviderTransportError) as raised:
        _service(timeout, dns).search_many("markets")

    assert raised.value.category is TransportFailure.TRANSPORT


def test_explicit_sources_are_deduplicated_in_caller_order() -> None:
    alpha = SearchProvider("alpha", [_result("alpha", "one")])
    beta = SearchProvider("beta", [_result("beta", "one")])

    response = _service(alpha, beta).search_many(
        "markets",
        provider_keys=("beta", "beta", "alpha"),
    )

    assert [source.provider for source in response.sources] == ["beta", "alpha"]


def test_search_rejects_result_not_owned_by_reporting_provider() -> None:
    provider = SearchProvider(
        "alpha",
        [_result("alpha", "foreign", url="https://foreign.test/article")],
    )

    with pytest.raises(ProviderContractError, match="invalid result ownership"):
        _service(provider).search("alpha", "markets")


class StatusHttp:
    def __init__(self, status: int) -> None:
        self.status = status

    def get(self, url, *, session=None, timeout: float = 40) -> RawFetch:
        is_bloomberg_api = "/nemo-next/api/search/query" in url
        if is_bloomberg_api:
            page = (
                int(url.rsplit("page=", 1)[-1].split("&", 1)[0])
                if "page=" in url
                else 1
            )
            body = (
                f'{{"results": [], "queryMetadata": {{}}, "page": {page}, "total": 0}}'
            ).encode()
        else:
            body = (
                b'<html><body><div data-trackable="search-no-results" '
                b'data-testid="search-no-results" '
                b'data-component="search-no-results">No results</div></body></html>'
            )
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=self.status,
            content_type="application/json" if is_bloomberg_api else "text/html",
            retrieved_at=NOW,
            raw_html=body,
        )


@pytest.mark.parametrize(
    "provider",
    [FTProvider(), WSJProvider(), BloombergProvider()],
)
def test_provider_search_distinguishes_http_failure_from_valid_empty(provider) -> None:
    with pytest.raises(ProviderTransportError, match="HTTP 503"):
        provider.search(StatusHttp(503), None, "rates", SearchFilters())

    assert provider.search(StatusHttp(200), None, "rates", SearchFilters()) == []


def test_source_report_counts_results_withheld_for_unknown_date() -> None:
    """A date bound drops undated results before the pager counts them, so the
    source reports them rather than reading as an exhaustive answer."""

    dated = _result("alpha", "dated", published=datetime(2026, 7, 18, tzinfo=UTC))
    provider = PagedSearchProvider(
        "alpha",
        {
            None: ProviderSearchPage(
                results=(dated,),
                next_url="https://alpha.test/search?page=2",
                undated_excluded_count=2,
            ),
            "https://alpha.test/search?page=2": ProviderSearchPage(
                results=(), undated_excluded_count=1
            ),
        },
    )

    response = _service(provider).search_many(
        "bank",
        SearchFilters(limit=5, published_after=datetime(2026, 7, 1, tzinfo=UTC)),
    )

    (source,) = response.sources
    assert source.state is SourceSearchState.OK
    assert source.result_count == 1
    assert source.missing_published_count == 0
    assert source.undated_excluded_count == 3
    assert source.public_dict()["undated_excluded_count"] == 3


def test_failed_source_report_cannot_claim_withheld_results() -> None:
    with pytest.raises(ValidationError, match="zero result counts"):
        SourceSearchReport(
            provider="fixture",
            state=SourceSearchState.UNAVAILABLE,
            result_count=0,
            undated_excluded_count=1,
            reason=SourceSearchReason.TRANSPORT,
        )


def test_only_a_date_bound_withholds_undated_results() -> None:
    bounded = SearchFilters(published_before=datetime(2026, 7, 1, tzinfo=UTC))

    assert bounded.excludes_undated(None)
    assert not bounded.excludes_undated(datetime(2026, 6, 1, tzinfo=UTC))
    assert not SearchFilters().excludes_undated(None)


def test_provider_defense_survives_federation_and_response_roundtrip():
    from newsclip.errors import ProviderDefenseError
    from newsclip.models import SearchResponse

    refused = SearchProvider("refused", error=ProviderDefenseError("private response"))
    response = _service(refused, SearchProvider("healthy")).search_many("rates")
    source = SearchResponse.model_validate_json(response.model_dump_json()).sources[0]
    assert source.reason == "provider_defense"
    assert source.state is SourceSearchState.UNAVAILABLE
    assert "private response" not in response.model_dump_json()
