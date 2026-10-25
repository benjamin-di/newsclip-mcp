from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from newsclip.errors import OperatorActionRequiredError, ProviderContractError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import (
    AccessState,
    ExtractedArticle,
    RawFetch,
    SearchFilters,
    SessionArtifact,
    SessionDisposition,
)
from newsclip.providers.ft import FTLoginRecipe, FTProvider, normalize_content_url

NOW = datetime(2026, 7, 17, tzinfo=UTC)


def _ft_provider(*, missing_published_fetch_limit: int | None = None) -> FTProvider:
    """FT provider; override date-recovery budget when a test needs multi-fetch."""
    provider = FTProvider()
    if missing_published_fetch_limit is None:
        return provider
    search = provider.spec.search.model_copy(
        update={"missing_published_fetch_limit": missing_published_fetch_limit}
    )
    provider.spec = provider.spec.model_copy(update={"search": search})
    return provider


ARTICLE_ID = "11111111-1111-4111-8111-111111111111"
ARTICLE_URL = f"https://www.ft.com/content/{ARTICLE_ID}"
FIXTURES = Path(__file__).parent / "fixtures" / "ft"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _fetch(
    name: str,
    *,
    final_url: str = ARTICLE_URL,
    status: int = 200,
    session_cookie_present: bool = False,
) -> RawFetch:
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=final_url,
        http_status=status,
        content_type="text/html; charset=utf-8",
        retrieved_at=NOW,
        session_cookie_present=session_cookie_present,
        raw_html=_fixture(name),
    )


def _assess(name: str, **fetch_options: object):
    fetch = _fetch(name, **fetch_options)
    extraction = TrafilaturaExtractor().extract(fetch)
    return FTProvider().assess(ARTICLE_URL, fetch, extraction), extraction


def test_provider_preserves_the_public_login_recipe_type() -> None:
    assert isinstance(FTProvider().login_recipe, FTLoginRecipe)


def test_account_security_reset_is_terminal_not_expired_authentication() -> None:
    fetch = _fetch(
        "account_security_reset.html",
        final_url="https://www.ft.com/barrier/concurrency",
        session_cookie_present=True,
    )
    provider = FTProvider()
    assessment = provider.assess(
        ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
    )
    assert assessment.reason == "account_alert"
    assert not assessment.promotable

    class Http:
        calls = 0

        def get(self, url, **kwargs):
            self.calls += 1
            return fetch

    http = Http()
    with pytest.raises(OperatorActionRequiredError) as caught:
        provider.fetch(http, None, ARTICLE_URL)
    assert caught.value.reason_code == "account_alert"
    assert http.calls == 1
    with pytest.raises(OperatorActionRequiredError):
        provider.login_recipe.verify_fetch(fetch)


@pytest.mark.parametrize(
    "final_url",
    [ARTICLE_URL, "https://example.test/barrier/concurrency"],
)
def test_account_reset_copy_outside_ft_security_barrier_is_not_terminal(
    final_url: str,
) -> None:
    assessment, _ = _assess("account_security_reset.html", final_url=final_url)
    assert assessment.reason != "account_alert"


@pytest.mark.parametrize(
    ("fixture", "fetch_options", "expected"),
    [
        ("full.html", {}, AccessState.FULL),
        ("brief_full.html", {}, AccessState.FULL),
        ("teaser.html", {}, AccessState.TEASER),
        (
            "auth.html",
            {"final_url": "https://accounts.ft.com/login"},
            AccessState.AUTH_REQUIRED,
        ),
        (
            "auth.html",
            {
                "final_url": "https://accounts.ft.com/login",
                "status": 403,
            },
            AccessState.AUTH_REQUIRED,
        ),
        (
            # Concurrent-session wall parks on /barrier/* with generic HTML; path
            # prefix must classify AUTH_REQUIRED rather than identity mismatch.
            "full.html",
            {"final_url": "https://www.ft.com/barrier/concurrency"},
            AccessState.AUTH_REQUIRED,
        ),
        (
            # FT's in-place concurrent-session revocation: the article URL with
            # the anonymous header over the barrier.
            "signed_out.html",
            {"session_cookie_present": True},
            AccessState.AUTH_REQUIRED,
        ),
        ("interstitial.html", {}, AccessState.BLOCKED),
        (
            "long_nonarticle.html",
            {"session_cookie_present": True},
            AccessState.UNKNOWN,
        ),
        ("wrong_canonical.html", {}, AccessState.UNKNOWN),
        ("malformed_metadata.html", {}, AccessState.UNKNOWN),
        ("http_error.html", {"status": 503}, AccessState.UNKNOWN),
    ],
)
def test_assessment_fixture_matrix(
    fixture: str, fetch_options: dict[str, object], expected: AccessState
) -> None:
    assessment, _ = _assess(fixture, **fetch_options)

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)
    if fetch_options.get("final_url") == "https://www.ft.com/barrier/concurrency":
        assert assessment.reason == "authentication_required"
        assert "authentication_page" in assessment.negative_markers


@pytest.mark.parametrize(
    "fixture",
    [
        "teaser.html",
        "auth.html",
        "signed_out.html",
        "interstitial.html",
        "long_nonarticle.html",
        "wrong_canonical.html",
        "malformed_metadata.html",
        "http_error.html",
    ],
)
def test_session_named_cookie_cannot_promote_negative_fixture(fixture: str) -> None:
    options: dict[str, object] = {"session_cookie_present": True}
    if fixture == "auth.html":
        options["final_url"] = "https://accounts.ft.com/login"
    if fixture == "http_error.html":
        options["status"] = 503

    assessment, _ = _assess(fixture, **options)

    assert assessment.access_state is not AccessState.FULL


def test_signed_out_page_proves_session_dead_but_teaser_stays_inconclusive() -> None:
    recipe = FTProvider().login_recipe

    signed_out = recipe.verify_fetch(
        _fetch("signed_out.html", session_cookie_present=True)
    )
    teaser = recipe.verify_fetch(_fetch("teaser.html", session_cookie_present=True))

    assert signed_out.access_state is AccessState.AUTH_REQUIRED
    assert signed_out.disposition is SessionDisposition.DEAD
    # A subscriber can still meet a barrier (e.g. a premium-only article).
    assert teaser.access_state is AccessState.TEASER
    assert teaser.disposition is SessionDisposition.INCONCLUSIVE


@pytest.mark.parametrize("fixture", ["wrong_canonical.html", "interstitial.html"])
def test_word_count_alone_cannot_override_identity_or_block(fixture: str) -> None:
    fetch = _fetch(fixture, session_cookie_present=True)
    extraction = ExtractedArticle(
        body_markdown="generated " * 10_000,
        metadata={"title": "Generated headline"},
        word_count=10_000,
    )

    assessment = FTProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is not AccessState.FULL


def test_brief_article_passes_on_structure_not_word_threshold() -> None:
    assessment, extraction = _assess("brief_full.html")

    assert extraction.word_count < 100
    assert assessment.access_state is AccessState.FULL
    assert "newsarticle_jsonld" in assessment.structural_signals
    assert "article_body_structure" in assessment.structural_signals


def test_json_ld_timestamp_overrides_date_only_extractor_metadata() -> None:
    extraction = TrafilaturaExtractor().extract(_fetch("full.html"))

    assert extraction.metadata["date"] == "2026-07-16T09:30:00Z"


def test_reasons_and_signals_are_normalized_and_redaction_safe() -> None:
    assessment, _ = _assess("teaser.html")
    serialized = json.dumps(assessment.model_dump(mode="json"))

    assert assessment.reason == "paywall_teaser"
    assert assessment.negative_markers == ("paywall",)
    assert "generated preview sentence" not in serialized.lower()
    assert "subscribe to unlock" not in serialized.lower()


@pytest.mark.parametrize(
    ("status", "title", "marker", "expected"),
    [
        (403, "Security Verification", True, True),
        (403, "  Security   Verification  ", True, True),
        (403, "Security Verification", False, False),
        (403, "Access denied", True, False),
        (401, "Security Verification", True, False),
    ],
)
def test_ft_response_retry_requires_the_exact_security_fingerprint(
    status: int,
    title: str,
    marker: bool,
    expected: bool,
) -> None:
    marker_html = '<div id="challenge-error-text"></div>' if marker else ""
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=status,
        content_type="text/html",
        retrieved_at=NOW,
        raw_html=(
            f"<html><head><title>{title}</title></head>"
            f"<body>{marker_html}</body></html>"
        ).encode(),
    )

    assert FTProvider().retry_response(fetch) is expected


def test_http_plane_challenge_is_classified_as_a_challenge() -> None:
    """The HTTP edge surface must reach challenge handling, not a bare 403."""

    assessment, _ = _assess("challenge_http.html", status=403)

    assert assessment.access_state is AccessState.BLOCKED
    assert assessment.reason == "interactive_challenge"
    assert assessment.negative_markers == ("interactive_challenge",)
    assert FTProvider().is_interactive_challenge(_fetch("challenge_http.html")) is True


def test_http_plane_challenge_stays_retryable_once() -> None:
    """Classification is additive: the bounded single replay is unchanged."""

    fetch = _fetch("challenge_http.html", status=403)

    assert FTProvider().retry_response(fetch) is True


class SearchHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.timeouts: list[float] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        self.timeouts.append(timeout)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            raw_html=_fixture("search_results.html"),
        )


class MissingDateSearchHttp(SearchHttp):
    def __init__(
        self,
        *,
        detail_status: int = 200,
        detail_final_url: str = ARTICLE_URL,
        detail_content_type: str | None = "text/html",
        detail_html: bytes | None = None,
    ) -> None:
        super().__init__()
        self.detail_status = detail_status
        self.detail_final_url = detail_final_url
        self.detail_content_type = detail_content_type
        self.detail_html = _fixture("full.html") if detail_html is None else detail_html
        self.detail_timeouts: list[float] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        if url.startswith("https://www.ft.com/search?"):
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                raw_html=_fixture("search_results_missing_date.html"),
            )
        self.detail_timeouts.append(timeout)
        return RawFetch(
            requested_url=url,
            final_url=self.detail_final_url,
            http_status=self.detail_status,
            content_type=self.detail_content_type,
            retrieved_at=NOW,
            raw_html=self.detail_html,
        )


def test_search_uses_live_shaped_result_list_and_strict_ft_urls() -> None:
    http = SearchHttp()

    results = FTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert http.urls == ["https://www.ft.com/search?q=bank+capital"]
    assert http.timeouts == [10]
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.ft.com/content/22222222-2222-4222-8222-222222222222",
    ]
    assert [result.headline for result in results] == [
        "Fixture bank capital plans",
        "Second fixture result",
    ]
    assert [result.published for result in results] == [
        datetime(2026, 7, 16, 9, tzinfo=UTC),
        datetime(2026, 7, 15, 9, tzinfo=UTC),
    ]


def test_search_recovers_missing_publication_date_from_matching_article() -> None:
    http = MissingDateSearchHttp()

    results = FTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert http.urls == [
        "https://www.ft.com/search?q=bank+capital",
        ARTICLE_URL,
    ]
    assert http.detail_timeouts == [10]
    assert [result.published for result in results] == [
        datetime(2026, 7, 16, 9, 30, tzinfo=UTC),
        datetime(2026, 7, 15, 9, tzinfo=UTC),
    ]


def test_search_applies_publication_bounds_after_date_recovery() -> None:
    results = FTProvider().search(
        MissingDateSearchHttp(),
        None,
        "bank capital",
        SearchFilters(published_after=datetime(2026, 7, 16, 9, 15, tzinfo=UTC)),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL]


def test_search_recovers_date_from_article_meta_without_json_ld() -> None:
    detail_html = f"""
        <html><head>
          <link rel="canonical" href="{ARTICLE_URL}">
          <meta property="article:published_time"
                content="2026-07-16T09:45:00Z">
        </head></html>
    """.encode()

    results = FTProvider().search(
        MissingDateSearchHttp(detail_html=detail_html),
        None,
        "bank capital",
        SearchFilters(limit=10),
    )

    assert results[0].published == datetime(2026, 7, 16, 9, 45, tzinfo=UTC)


@pytest.mark.parametrize(
    "http",
    [
        MissingDateSearchHttp(detail_status=503),
        MissingDateSearchHttp(detail_content_type="application/json"),
        MissingDateSearchHttp(
            detail_final_url=(
                "https://www.ft.com/content/22222222-2222-4222-8222-222222222222"
            )
        ),
        MissingDateSearchHttp(
            detail_html=_fixture("full.html").replace(
                b'"datePublished": "2026-07-16T09:30:00Z"',
                b'"datePublished": "not-a-date"',
            )
        ),
    ],
    ids=["http-error", "non-html", "wrong-identity", "invalid-date"],
)
def test_search_preserves_undated_result_when_recovery_is_untrusted(
    http: MissingDateSearchHttp,
) -> None:
    results = FTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert len(results) == 2
    assert results[0].published is None


def test_search_date_bounds_exclude_result_when_recovery_fails() -> None:
    results = FTProvider().search(
        MissingDateSearchHttp(detail_status=503),
        None,
        "bank capital",
        SearchFilters(published_after=datetime(2026, 7, 1, tzinfo=UTC)),
    )

    assert [result.headline for result in results] == ["Second fixture result"]
    page = FTProvider().search_page(
        MissingDateSearchHttp(detail_status=503),
        None,
        "bank capital",
        SearchFilters(published_after=datetime(2026, 7, 1, tzinfo=UTC)),
    )
    assert [result.headline for result in page.results] == ["Second fixture result"]
    assert page.undated_excluded_count == 1
    unbounded = FTProvider().search_page(
        MissingDateSearchHttp(detail_status=503),
        None,
        "bank capital",
        SearchFilters(),
    )
    assert unbounded.undated_excluded_count == 0


def test_search_preserves_undated_result_after_recovery_transport_error() -> None:
    class TransportErrorHttp(MissingDateSearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            if not url.startswith("https://www.ft.com/search?"):
                raise ProviderContractError("supplemental fetch failed")
            return super().get(url, **kwargs)

    results = FTProvider().search(
        TransportErrorHttp(), None, "bank capital", SearchFilters(limit=10)
    )

    assert results[0].published is None


class SequentialMissingDateHttp:
    def __init__(self, count: int = 5) -> None:
        self.ids = [
            f"{index}" * 8 + "-1111-4111-8111-111111111111"
            for index in range(1, count + 1)
        ]
        self.urls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        if url.startswith("https://www.ft.com/search?"):
            items = "".join(
                f'<li><a class="js-teaser-heading-link" '
                f'href="/content/{article_id}">Result {index}</a></li>'
                for index, article_id in enumerate(self.ids, 1)
            )
            body = f'<ul class="search-results__list">{items}</ul>'.encode()
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="text/html",
                retrieved_at=NOW,
                raw_html=body,
            )

        article_id = url.rsplit("/", 1)[-1]
        index = self.ids.index(article_id) + 1
        detail = f"""
            <html><head>
              <link rel="canonical" href="{url}">
              <script type="application/ld+json">{{
                "@type": "NewsArticle",
                "headline": "Result {index}",
                "datePublished": "2026-07-{index:02d}T09:00:00Z"
              }}</script>
            </head></html>
        """.encode()
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            raw_html=detail,
        )


def test_search_recovers_dates_sequentially_with_bounded_stable_results() -> None:
    http = SequentialMissingDateHttp()

    # Default product budget is one recovery hop (warm latency / 429 edge).
    results = _ft_provider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert [result.headline for result in results] == [
        "Result 1",
        "Result 2",
        "Result 3",
        "Result 4",
        "Result 5",
    ]
    recovered_days = [
        result.published.day if result.published else None for result in results
    ]
    assert recovered_days == [
        1,
        None,
        None,
        None,
        None,
    ]
    assert http.urls[1:] == [
        f"https://www.ft.com/content/{http.ids[0]}",
    ]


def test_search_recovers_multiple_dates_when_fetch_limit_allows() -> None:
    http = SequentialMissingDateHttp()

    results = _ft_provider(missing_published_fetch_limit=3).search(
        http, None, "bank capital", SearchFilters(limit=10)
    )

    recovered_days = [
        result.published.day if result.published else None for result in results
    ]
    assert recovered_days == [1, 2, 3, None, None]
    assert http.urls[1:] == [
        f"https://www.ft.com/content/{article_id}" for article_id in http.ids[:3]
    ]


@pytest.mark.parametrize(
    "failure",
    ["not-found", "non-html", "wrong-identity", "invalid-date"],
)
def test_search_continues_after_article_specific_missing_date_failure(
    failure: str,
) -> None:
    class FirstMissing(SequentialMissingDateHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            if url.endswith(self.ids[0]):
                if failure == "not-found":
                    return fetch.model_copy(update={"http_status": 404})
                if failure == "non-html":
                    return fetch.model_copy(update={"content_type": "application/json"})
                if failure == "wrong-identity":
                    return fetch.model_copy(
                        update={
                            "final_url": f"https://www.ft.com/content/{self.ids[1]}"
                        }
                    )
                return fetch.model_copy(
                    update={
                        "raw_html": fetch.raw_html.replace(
                            b'"datePublished": "2026-07-01T09:00:00Z"',
                            b'"datePublished": "not-a-date"',
                        )
                    }
                )
            return fetch

    http = FirstMissing(count=3)

    results = _ft_provider(missing_published_fetch_limit=3).search(
        http, None, "bank capital", SearchFilters(limit=10)
    )

    recovered = [
        result.published.day if result.published else None for result in results
    ]
    assert recovered == [None, 2, 3]
    assert len(http.urls) == 4


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (429, b"rate limited"),
        (503, b"upstream unavailable"),
        (
            403,
            b"<html><head><title>Security Verification</title></head>"
            b"<body><div id='challenge-error-text'></div></body></html>",
        ),
    ],
    ids=["rate-limit", "server-error", "repeated-security"],
)
def test_search_stops_date_recovery_after_provider_level_response(
    status: int,
    body: bytes,
) -> None:
    class ProviderFailure(SequentialMissingDateHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            if not url.startswith("https://www.ft.com/search?"):
                return fetch.model_copy(
                    update={"http_status": status, "raw_html": body}
                )
            return fetch

    http = ProviderFailure(count=3)

    results = FTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert all(result.published is None for result in results)
    assert len(http.urls) == 2


def test_search_stops_date_recovery_after_transport_exhaustion() -> None:
    class TransportFailure(SequentialMissingDateHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            if not url.startswith("https://www.ft.com/search?"):
                self.urls.append(url)
                raise ProviderContractError("supplemental transport failed")
            return super().get(url, **kwargs)

    http = TransportFailure(count=3)

    results = FTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert all(result.published is None for result in results)
    assert len(http.urls) == 2


def test_search_only_recovers_candidates_within_unfiltered_limit() -> None:
    http = SequentialMissingDateHttp()

    results = _ft_provider(missing_published_fetch_limit=3).search(
        http, None, "bank capital", SearchFilters(limit=2)
    )

    assert [result.headline for result in results] == ["Result 1", "Result 2"]
    assert set(http.urls[1:]) == {
        f"https://www.ft.com/content/{http.ids[0]}",
        f"https://www.ft.com/content/{http.ids[1]}",
    }


def test_search_applies_aware_publication_bounds() -> None:
    results = FTProvider().search(
        SearchHttp(),
        None,
        "bank capital",
        SearchFilters(published_after=datetime(2026, 7, 16, tzinfo=UTC)),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL]


def test_search_selector_drift_is_not_reported_as_empty_success() -> None:
    class DriftedSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "raw_html": b"<html><body><main>Changed page</main></body></html>"
                }
            )

    with pytest.raises(ProviderContractError, match="neither results nor empty"):
        FTProvider().search(DriftedSearchHttp(), None, "bank capital", SearchFilters())


def test_search_filters_reject_naive_or_reversed_date_bounds() -> None:
    with pytest.raises(ValueError, match="timezone"):
        SearchFilters(published_after=datetime(2026, 7, 16))
    with pytest.raises(ValueError, match="published_after"):
        SearchFilters(
            published_after=datetime(2026, 7, 17, tzinfo=UTC),
            published_before=datetime(2026, 7, 16, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "raw",
    [
        "http://www.ft.com/content/11111111-1111-4111-8111-111111111111",
        "https://evil.test/content/11111111-1111-4111-8111-111111111111",
        "https://www.ft.com.evil.test/content/11111111-1111-4111-8111-111111111111",
        "https://www.ft.com/content/not-a-uuid",
        "https://www.ft.com/content/11111111-1111-4111-8111-111111111111/extra",
    ],
)
def test_url_normalization_rejects_unowned_or_malformed_urls(raw: str) -> None:
    assert normalize_content_url(raw) is None


def test_url_normalization_canonicalizes_owned_relative_url() -> None:
    assert (
        normalize_content_url(
            "/content/11111111-1111-4111-8111-111111111111?source=fixture"
        )
        == ARTICLE_URL
    )
