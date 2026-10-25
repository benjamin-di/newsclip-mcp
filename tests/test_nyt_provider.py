"""NYT provider offline gates, ported from the WSJ matrix plus the meter cases.

Every assertion in ``test_wsj_provider.py`` applies unchanged: identity plus
positive structure gate a FULL, and neither a session-named cookie nor a raw
word count can promote a negative fixture. Three assertions are NYT-specific and
are the reason this suite is not a copy. NYT is metered where every other paid
provider is a hard paywall, so a logged-out client can receive a complete,
identity-matching article that satisfies every other FULL condition. See
docs/NYT_PROVIDER_PLAN.md sections 4 and 8.1.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from newsclip.challenge_transport import ChallengeAwareHttpClient
from newsclip.errors import (
    ProviderContractError,
    ProviderTransportError,
    TransportFailure,
)
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import (
    AccessState,
    ExtractedArticle,
    PortableCookie,
    RawFetch,
    SearchFilters,
    SessionArtifact,
)
from newsclip.providers import NYTProvider, ProviderRegistry, WSJProvider
from newsclip.providers.nyt import NYTLoginRecipe, article_id, normalize_article_url

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "2026/07/17/business/fixture-lenders-raise-capital.html"
ARTICLE_URL = f"https://www.nytimes.com/{ARTICLE_ID}"
FIXTURES = Path(__file__).parent / "fixtures" / "nyt"


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _fetch(
    name: str,
    *,
    final_url: str = ARTICLE_URL,
    status: int = 200,
    session_cookie_present: bool = True,
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
    return NYTProvider().assess(ARTICLE_URL, fetch, extraction), extraction


def test_provider_preserves_the_public_login_recipe_type() -> None:
    assert NYTProvider().login_recipe is None
    assert isinstance(
        NYTProvider(verification_url=ARTICLE_URL).login_recipe,
        NYTLoginRecipe,
    )


@pytest.mark.parametrize(
    ("fixture", "fetch_options", "expected"),
    [
        ("full.html", {}, AccessState.FULL),
        ("verification_full.html", {}, AccessState.FULL),
        ("teaser.html", {}, AccessState.TEASER),
        (
            "auth.html",
            {"final_url": "https://myaccount.nytimes.com/auth/login"},
            AccessState.AUTH_REQUIRED,
        ),
        ("interstitial.html", {}, AccessState.BLOCKED),
        ("wrong_canonical.html", {}, AccessState.UNKNOWN),
        ("malformed_metadata.html", {}, AccessState.UNKNOWN),
        ("http_error.html", {"status": 503}, AccessState.UNKNOWN),
        (
            "metered_full_no_session.html",
            {"session_cookie_present": False},
            AccessState.UNKNOWN,
        ),
    ],
)
def test_assessment_fixture_matrix(
    fixture: str, fetch_options: dict[str, object], expected: AccessState
) -> None:
    assessment, _ = _assess(fixture, **fetch_options)

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)


# --- NYT-specific: the meter (plan section 4) --------------------------------


def test_metered_full_article_without_a_session_cannot_promote() -> None:
    """The single most important test in this suite.

    A complete, identity-matching, well-over-floor article body is a genuinely
    reachable logged-out state on NYT. It must not read as paid access.
    """

    assessment, extraction = _assess(
        "metered_full_no_session.html", session_cookie_present=False
    )

    assert extraction.word_count > 250
    assert assessment.identity_match is True
    assert "article_word_floor" in assessment.structural_signals
    assert "article_paragraph_floor" in assessment.structural_signals
    assert assessment.access_state is AccessState.UNKNOWN
    assert assessment.reason == "metered_without_session"
    assert assessment.promotable is False


def test_the_same_metered_body_is_full_once_a_session_is_observed() -> None:
    """The guard keys on the session, not on anything about the body."""

    assessment, _ = _assess("metered_full_no_session.html", session_cookie_present=True)

    assert assessment.access_state is AccessState.FULL
    assert assessment.promotable is True


def test_metered_full_article_without_a_session_cannot_certify_a_candidate() -> None:
    recipe = NYTLoginRecipe(verification_url=ARTICLE_URL)

    verification = recipe.verify_fetch(
        _fetch("metered_full_no_session.html", session_cookie_present=False)
    )

    assert verification.verified is False
    assert verification.access_state is AccessState.UNKNOWN
    assert verification.reason == "metered_without_session"


# --- Ported WSJ matrix -------------------------------------------------------


def test_assessment_reports_a_closed_http_failure_class() -> None:
    assessment, _ = _assess("http_error.html", status=401)

    assert assessment.reason == "http_unauthorized"


@pytest.mark.parametrize(
    "fixture",
    [
        "teaser.html",
        "auth.html",
        "interstitial.html",
        "wrong_canonical.html",
        "malformed_metadata.html",
        "http_error.html",
    ],
)
def test_session_named_cookie_cannot_promote_negative_fixture(fixture: str) -> None:
    options: dict[str, object] = {"session_cookie_present": True}
    if fixture == "auth.html":
        options["final_url"] = "https://myaccount.nytimes.com/auth/login"
    if fixture == "http_error.html":
        options["status"] = 503

    assessment, _ = _assess(fixture, **options)

    assert assessment.access_state is not AccessState.FULL


@pytest.mark.parametrize("fixture", ["wrong_canonical.html", "interstitial.html"])
def test_word_count_alone_cannot_override_identity_or_block(fixture: str) -> None:
    fetch = _fetch(fixture, session_cookie_present=True)
    extraction = ExtractedArticle(
        body_markdown="generated " * 10_000,
        metadata={"title": "Generated headline"},
        word_count=10_000,
    )

    assessment = NYTProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is not AccessState.FULL


def test_challenge_outranks_a_successful_status_and_a_session() -> None:
    assessment, _ = _assess("interstitial.html", session_cookie_present=True)

    assert assessment.access_state is AccessState.BLOCKED
    assert assessment.reason == "interactive_challenge"
    assert assessment.negative_markers == ("interactive_challenge",)


def test_reasons_and_signals_are_normalized_and_redaction_safe() -> None:
    assessment, _ = _assess("teaser.html")
    serialized = json.dumps(assessment.model_dump(mode="json"))

    assert assessment.reason == "paywall_teaser"
    assert "generated preview sentence" not in serialized.lower()
    assert "subscribe to continue reading" not in serialized.lower()


# --- Search ------------------------------------------------------------------


class SearchHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []

    def get(
        self, url: str, *, session: SessionArtifact | None = None, timeout: float = 40
    ) -> RawFetch:
        self.urls.append(url)
        self.sessions.append(session)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            raw_html=_fixture("search_results.html"),
        )


class StaticSearchHttp(SearchHttp):
    def __init__(
        self,
        raw_html: bytes,
        *,
        status: int = 200,
        content_type: str | None = "text/html",
    ) -> None:
        super().__init__()
        self.raw_html = raw_html
        self.status = status
        self.content_type = content_type

    def get(
        self, url: str, *, session: SessionArtifact | None = None, timeout: float = 40
    ) -> RawFetch:
        fetch = super().get(url, session=session, timeout=timeout)
        return fetch.model_copy(
            update={
                "http_status": self.status,
                "content_type": self.content_type,
                "raw_html": self.raw_html,
            }
        )


def test_search_keeps_only_owned_articles_and_dates_them_from_the_url() -> None:
    http = SearchHttp()

    results = NYTProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert http.urls == ["https://www.nytimes.com/search?query=bank+capital"]
    # The Times Topics link, the Athletic story, and the Spanish edition story
    # are all rejected by the identity pattern.
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.nytimes.com/interactive/2026/05/13/business/economy/"
        "fixture-interactive-explainer.html",
    ]
    assert [result.headline for result in results] == [
        "Fixture lenders raise capital",
        "Fixture interactive explainer",
    ]
    # No date-recovery fetches: the publication date comes out of the URL.
    assert [result.published for result in results] == [
        datetime(2026, 7, 17, tzinfo=UTC),
        datetime(2026, 5, 13, tzinfo=UTC),
    ]
    assert all(result.provider == "nyt" for result in results)

    filtered = NYTProvider().search(
        http,
        None,
        "bank capital",
        SearchFilters(published_after=datetime(2026, 7, 1, tzinfo=UTC)),
    )
    assert [str(result.url) for result in filtered] == [ARTICLE_URL]


def test_public_search_never_attaches_the_paid_article_session() -> None:
    http = SearchHttp()

    NYTProvider().search(
        http,
        _session_artifact(),
        "bank capital",
        SearchFilters(limit=10),
    )

    assert http.sessions == [None]


def test_a_results_region_with_no_owned_articles_is_an_honest_empty() -> None:
    class UnownedSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "raw_html": b"""
                    <html><body><main>
                      <div data-testid="search-results">
                        <div data-testid="search-bodega-result">
                          <a href="/athletic/1234567/2026/07/17/only-sports/">
                            Only sports
                          </a>
                        </div>
                      </div>
                    </main></body></html>
                    """
                }
            )

    assert (
        NYTProvider().search(UnownedSearchHttp(), None, "sports", SearchFilters()) == []
    )


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
        NYTProvider().search(DriftedSearchHttp(), None, "bank capital", SearchFilters())


def test_search_maps_the_exact_nyt_200_server_error_to_provider_error() -> None:
    http = StaticSearchHttp(_fixture("search_server_error.html"))

    with pytest.raises(ProviderTransportError) as captured:
        NYTProvider().search(http, None, "markets", SearchFilters())

    assert captured.value.category is TransportFailure.PROVIDER_ERROR
    assert http.urls == ["https://www.nytimes.com/search?query=markets"]


@pytest.mark.parametrize(
    "raw_html",
    [
        b"""
        <html><head><title>Server Error - The New York Times</title></head>
        <body><main><h1>Server Error details</h1></main></body></html>
        """,
        b"""
        <html><head><title>Temporary Server Error - The New York Times</title></head>
        <body><main><h1>Server Error</h1></main></body></html>
        """,
    ],
)
def test_search_does_not_generalize_nearby_error_copy(raw_html: bytes) -> None:
    with pytest.raises(ProviderContractError, match="neither results nor empty"):
        NYTProvider().search(
            StaticSearchHttp(raw_html),
            None,
            "markets",
            SearchFilters(),
        )


def test_search_keeps_http_503_as_provider_error() -> None:
    http = StaticSearchHttp(_fixture("search_server_error.html"), status=503)

    with pytest.raises(ProviderTransportError) as captured:
        NYTProvider().search(http, None, "markets", SearchFilters())

    assert captured.value.category is TransportFailure.PROVIDER_ERROR
    assert len(http.urls) == 1


def test_search_server_error_after_challenge_is_not_retried() -> None:
    primary = StaticSearchHttp(
        b"<html><body>DataDome challenge</body></html>",
        status=403,
    )
    fallback = StaticSearchHttp(_fixture("search_server_error.html"))
    http = ChallengeAwareHttpClient(
        "nyt",
        primary,
        is_challenge=lambda fetch: fetch.http_status == 403,
        browser_fallback=fallback,
    )

    with pytest.raises(ProviderTransportError) as captured:
        NYTProvider().search(http, None, "markets", SearchFilters())

    assert captured.value.category is TransportFailure.PROVIDER_ERROR
    assert len(primary.urls) == 1
    assert len(fallback.urls) == 1


# --- URL identity (plan section 6) -------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        # Wrong scheme, unowned host, and suffix-confusable host.
        "http://www.nytimes.com/2026/07/17/business/fixture-lenders-raise-capital.html",
        "https://evil.test/2026/07/17/business/fixture-lenders-raise-capital.html",
        "https://www.nytimes.com.evil.test/2026/07/17/business/fixture-story.html",
        "//evil.test/2026/07/17/business/fixture-lenders-raise-capital.html",
        # Every deliberate section exclusion.
        "https://www.nytimes.com/athletic/1234567/2026/07/17/fixture-sports-story/",
        "https://www.nytimes.com/es/2026/07/17/espanol/fixture-spanish-story.html",
        "https://www.nytimes.com/live/2026/07/17/world/fixture-live-blog",
        "https://www.nytimes.com/card/2026/07/17/briefing/fixture-card.html",
        "https://www.nytimes.com/article/fixture-evergreen-explainer.html",
        "https://www.nytimes.com/interactive/polls/2026/07/17/us/fixture-poll.html",
        # Shapes that are not articles at all.
        "https://www.nytimes.com/search?query=banks",
        "https://www.nytimes.com/2026/07/17/business/fixture-no-extension",
        "https://www.nytimes.com/2026/7/17/business/fixture-unpadded-date.html",
    ],
)
def test_url_normalization_rejects_unowned_or_excluded_urls(raw: str) -> None:
    assert normalize_article_url(raw) is None


def test_url_normalization_canonicalizes_owned_relative_url() -> None:
    assert (
        normalize_article_url(
            "/2026/07/17/business/fixture-lenders-raise-capital.html"
            "?searchResultPosition=1"
        )
        == ARTICLE_URL
    )
    assert article_id(ARTICLE_URL) == ARTICLE_ID


def test_interactives_are_owned_because_they_share_the_article_dom() -> None:
    interactive = (
        "https://www.nytimes.com/interactive/2026/05/13/business/economy/"
        "fixture-interactive-explainer.html"
    )

    assert normalize_article_url(interactive) == interactive


def test_registering_nyt_leaves_wsj_routing_and_assessment_intact() -> None:
    registry = ProviderRegistry((WSJProvider(), NYTProvider()))

    wsj_url = "https://www.wsj.com/finance/banks-rally-capital-1a2b3c4d"
    assert registry.for_url(wsj_url).key == "wsj"
    assert registry.for_url(ARTICLE_URL).key == "nyt"

    wsj_full = (Path(__file__).parent / "fixtures" / "wsj" / "full.html").read_bytes()
    fetch = RawFetch(
        requested_url=wsj_url,
        final_url=wsj_url,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=wsj_full,
    )
    wsj = registry.get("wsj")
    assessment = wsj.assess(wsj_url, fetch, TrafilaturaExtractor().extract(fetch))
    assert assessment.access_state is AccessState.FULL


class FixtureHttp:
    def __init__(self, name: str) -> None:
        self.name = name

    def get(
        self, url: str, *, session: SessionArtifact | None = None, timeout: float = 40
    ) -> RawFetch:
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=_fixture(self.name),
        )


def _session_artifact() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="nyt",
        created_at=NOW,
        verified_at=NOW,
        cookies=(PortableCookie(name="NYT-S", value="value", domain=".nytimes.com"),),
    )


def test_recipe_verifier_uses_full_assessment_not_cookie_name() -> None:
    recipe = NYTLoginRecipe(verification_url=ARTICLE_URL)
    artifact = _session_artifact()

    verified = recipe.verify(FixtureHttp("verification_full.html"), artifact)
    teaser = recipe.verify(FixtureHttp("teaser.html"), artifact)

    assert verified.verified is True
    assert verified.access_state is AccessState.FULL
    assert teaser.verified is False
    assert teaser.access_state is AccessState.TEASER


def test_recipe_requires_owned_verification_url() -> None:
    with pytest.raises(ValueError, match="owned article URL"):
        NYTLoginRecipe(verification_url="https://evil.test/2026/07/17/x/y.html")
