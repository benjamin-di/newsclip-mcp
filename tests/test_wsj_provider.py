"""WSJ provider offline gates (F2–F7-equivalent) and recipe classification.

WSJ is registered in the default composition root after its W4.3–W4.6 live
promotion. These retained regression gates keep the FT discipline: identity
plus positive structure gate a FULL, and neither a session-named cookie nor a
raw word count can promote a negative fixture.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from lxml import html

from newsclip.articles import build_article
from newsclip.challenge_transport import ChallengeAwareHttpClient
from newsclip.configured_provider import ConfiguredProvider
from newsclip.errors import ProviderContractError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import (
    AccessState,
    ExtractedArticle,
    PortableCookie,
    RawFetch,
    SearchFilters,
    SessionArtifact,
)
from newsclip.providers import FTProvider, ProviderRegistry, WSJProvider
from newsclip.providers.wsj import WSJLoginRecipe, article_id, normalize_article_url

NOW = datetime(2026, 7, 17, tzinfo=UTC)
ARTICLE_ID = "1a2b3c4d"
ARTICLE_URL = f"https://www.wsj.com/finance/banks-rally-capital-{ARTICLE_ID}"
FIXTURES = Path(__file__).parent / "fixtures" / "wsj"


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
    return WSJProvider().assess(ARTICLE_URL, fetch, extraction), extraction


def test_provider_preserves_the_public_login_recipe_type() -> None:
    assert WSJProvider().login_recipe is None
    assert isinstance(
        WSJProvider(verification_url=ARTICLE_URL).login_recipe,
        WSJLoginRecipe,
    )


@pytest.mark.parametrize(
    ("fixture", "fetch_options", "expected"),
    [
        ("full.html", {}, AccessState.FULL),
        ("brief_full.html", {}, AccessState.TEASER),
        ("teaser.html", {}, AccessState.TEASER),
        (
            "auth.html",
            {"final_url": "https://sso.accounts.dowjones.com/login"},
            AccessState.AUTH_REQUIRED,
        ),
        ("interstitial.html", {}, AccessState.BLOCKED),
        ("datadome.html", {"status": 401}, AccessState.BLOCKED),
        ("long_nonarticle.html", {"session_cookie_present": True}, AccessState.UNKNOWN),
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


def test_assessment_reports_a_closed_http_failure_class() -> None:
    assessment, _ = _assess("http_error.html", status=401)

    assert assessment.reason == "http_unauthorized"


@pytest.mark.parametrize("container", ["object", "list", "graph"])
@pytest.mark.parametrize("type_array", [False, True])
def test_opinion_article_metadata_is_recognized(
    container: str, type_array: bool
) -> None:
    # The September 14 watchdog capture has OpinionNewsArticle alongside
    # WebPage metadata. Use only generated prose from the existing fixture.
    fetch = _fetch("full.html", session_cookie_present=True)
    document = html.fromstring(fetch.raw_html)
    script = document.xpath("//script[@type='application/ld+json']")[0]
    metadata = json.loads(script.text)
    metadata["@type"] = ["OpinionNewsArticle"] if type_array else "OpinionNewsArticle"
    payload = {
        "object": metadata,
        "list": [{"@type": "WebPage"}, metadata],
        "graph": {"@graph": [{"@type": "WebPage"}, metadata]},
    }[container]
    script.text = json.dumps(payload)
    fetch = fetch.model_copy(update={"raw_html": html.tostring(document)})
    extraction = TrafilaturaExtractor().extract(fetch)

    assessment = WSJProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.promotable
    assert assessment.identity_match
    assert {"newsarticle_jsonld", "jsonld_headline"}.issubset(
        assessment.structural_signals
    )
    # The shared default still requires NewsArticle; only WSJ opts in.
    default = ConfiguredProvider(WSJProvider().spec)
    assert not default.assess(ARTICLE_URL, fetch, extraction).promotable
    assert default.assessment_policy_version != WSJProvider().assessment_policy_version
    verification = WSJLoginRecipe(verification_url=ARTICLE_URL).verify_fetch(fetch)
    assert verification.verified
    assert verification.access_state is assessment.access_state
    # Extraction reads the same accepted JSON-LD, so the article keeps its
    # aware publication time instead of trafilatura's date-only guess.
    assert extraction.metadata["date"] == "2026-07-16T09:30:00Z"
    article = build_article(
        WSJProvider(),
        fetch,
        extraction,
        assessment,
        extractor_name="trafilatura",
        extractor_version="fixture",
    )
    assert article.published == datetime(2026, 7, 16, 9, 30, tzinfo=UTC)


def test_extraction_reads_every_json_ld_type_a_provider_accepts() -> None:
    import newsclip.providers.builtins  # noqa: F401 - registers every provider
    from newsclip.assessment import ARTICLE_JSONLD_TYPES

    pending: list[type[ConfiguredProvider]] = [ConfiguredProvider]
    checked = 0
    while pending:
        provider_type = pending.pop()
        pending.extend(provider_type.__subclasses__())
        assert set(provider_type._jsonld_article_types) <= set(ARTICLE_JSONLD_TYPES), (
            provider_type.__name__
        )
        checked += 1
    assert checked > 5


@pytest.mark.parametrize(
    "fixture",
    [
        "initial_excerpt.html",
        "teaser.html",
        "wrong_canonical.html",
        "interstitial.html",
        "malformed_metadata.html",
    ],
)
def test_opinion_type_preserves_content_and_identity_gates(fixture: str) -> None:
    fetch = _fetch(fixture, session_cookie_present=True)
    fetch = fetch.model_copy(
        update={
            "raw_html": fetch.raw_html.replace(
                b'"NewsArticle"', b'"OpinionNewsArticle"'
            )
        }
    )
    extraction = TrafilaturaExtractor().extract(fetch)

    assert not WSJProvider().assess(ARTICLE_URL, fetch, extraction).promotable
    assert not WSJLoginRecipe(verification_url=ARTICLE_URL).verify_fetch(fetch).verified


@pytest.mark.parametrize("article_type", ["WebPage", "Article", "opinionnewsarticle"])
def test_non_news_metadata_still_cannot_prove_an_article(article_type: str) -> None:
    fetch = _fetch("full.html", session_cookie_present=True)
    fetch = fetch.model_copy(
        update={
            "raw_html": fetch.raw_html.replace(
                b'"NewsArticle"', json.dumps(article_type).encode()
            )
        }
    )
    extraction = TrafilaturaExtractor().extract(fetch)

    assert not WSJProvider().assess(ARTICLE_URL, fetch, extraction).promotable


def test_metadata_valid_initial_excerpt_cannot_be_promoted() -> None:
    assessment, extraction = _assess(
        "initial_excerpt.html", session_cookie_present=True
    )

    assert extraction.word_count == 98
    assert assessment.identity_match
    assert "newsarticle_jsonld" in assessment.structural_signals
    assert assessment.access_state is AccessState.TEASER
    assert not assessment.promotable


@pytest.mark.parametrize("expands", [True, False])
def test_same_document_readiness_waits_for_full_body_and_rejects_persistent_excerpt(
    expands: bool,
) -> None:
    from newsclip.browser_readiness import (
        ReadinessTerminalState,
        sample_semantic_snapshot,
    )
    from newsclip.composition import _browser_readiness_evaluator

    provider = WSJProvider()
    extractor = TrafilaturaExtractor()
    evaluate_fetch = _browser_readiness_evaluator(provider, extractor)
    initial = _fetch("initial_excerpt.html", session_cookie_present=True)
    full = _fixture("full.html")

    class HydratingPage:
        url = ARTICLE_URL
        now = 0.0

        def wait_for_timeout(self, milliseconds):
            self.now += milliseconds / 1000

        def content(self):
            payload = full if expands and self.now >= 1 else initial.raw_html
            return payload.decode()

    page = HydratingPage()
    sampled = sample_semantic_snapshot(
        page,
        initial_content=initial.raw_html,
        readiness=provider.spec.browser_retrieval.semantic_readiness,
        evaluator=lambda url, content: evaluate_fetch(
            initial.model_copy(update={"raw_html": content})
        ),
        monotonic_clock=lambda: page.now,
    )
    final_fetch = initial.model_copy(update={"raw_html": sampled.content})
    final = provider.assess(ARTICLE_URL, final_fetch, extractor.extract(final_fetch))
    if expands:
        assert sampled.stabilized
        assert sampled.terminal_state is ReadinessTerminalState.STABILIZED
        assert final.promotable
        assert final.word_count >= 250
        assert sampled.content_change_count == 1
        assert 1.5 <= page.now < 8
    else:
        assert not sampled.stabilized
        assert sampled.terminal_state is ReadinessTerminalState.NON_PROMOTABLE_TIMEOUT
        assert final.access_state is AccessState.TEASER
        assert final.word_count == 98
        assert page.now == 8


@pytest.mark.parametrize(
    "fixture",
    [
        "teaser.html",
        "auth.html",
        "interstitial.html",
        "datadome.html",
        "long_nonarticle.html",
        "wrong_canonical.html",
        "malformed_metadata.html",
        "http_error.html",
    ],
)
def test_session_named_cookie_cannot_promote_negative_fixture(fixture: str) -> None:
    options: dict[str, object] = {"session_cookie_present": True}
    if fixture == "auth.html":
        options["final_url"] = "https://sso.accounts.dowjones.com/login"
    if fixture == "http_error.html":
        options["status"] = 503
    if fixture == "datadome.html":
        options["status"] = 401

    assessment, _ = _assess(fixture, **options)

    assert assessment.access_state is not AccessState.FULL


@pytest.mark.parametrize(
    "fixture", ["wrong_canonical.html", "interstitial.html", "datadome.html"]
)
def test_word_count_alone_cannot_override_identity_or_block(fixture: str) -> None:
    fetch = _fetch(
        fixture,
        status=401 if fixture == "datadome.html" else 200,
        session_cookie_present=True,
    )
    extraction = ExtractedArticle(
        body_markdown="generated " * 10_000,
        metadata={"title": "Generated headline"},
        word_count=10_000,
    )

    assessment = WSJProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is not AccessState.FULL


def test_brief_article_without_completeness_proof_is_withheld() -> None:
    assessment, extraction = _assess("brief_full.html")

    assert extraction.word_count < 100
    # Metadata-valid briefs are indistinguishable from the observed opening
    # excerpt. Conservatively reject both until an independent proof exists.
    assert assessment.access_state is AccessState.TEASER
    assert "newsarticle_jsonld" in assessment.structural_signals
    assert "article_body_structure" in assessment.structural_signals


def test_challenge_prose_in_article_body_still_fails_content_closed() -> None:
    body = _fixture("full.html").replace(
        b"</article>",
        b"<p>The report quotes instructions to press and hold a control.</p></article>",
    )
    fetch = RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html; charset=utf-8",
        retrieved_at=NOW,
        raw_html=body,
    )

    assessment = WSJProvider().assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is AccessState.BLOCKED
    assert assessment.reason == "interactive_challenge"


def test_reasons_and_signals_are_normalized_and_redaction_safe() -> None:
    assessment, _ = _assess("teaser.html")
    serialized = json.dumps(assessment.model_dump(mode="json"))

    assert assessment.reason == "paywall_teaser"
    assert assessment.negative_markers == ("paywall",)
    assert "generated preview sentence" not in serialized.lower()
    assert "subscribe to continue reading" not in serialized.lower()


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


def test_datadome_search_uses_the_approved_browser_fallback() -> None:
    class DatadomeSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "http_status": 401,
                    "raw_html": _fixture("datadome.html"),
                }
            )

    provider = WSJProvider()
    primary = DatadomeSearchHttp()
    browser = SearchHttp()
    client = ChallengeAwareHttpClient(
        provider.key,
        primary,
        is_challenge=provider.is_interactive_challenge,
        browser_fallback=browser,
    )

    results = provider.search(
        client,
        None,
        "bank capital",
        SearchFilters(limit=10),
    )

    search_url = "https://www.wsj.com/search?query=bank+capital"
    assert primary.urls == [search_url]
    assert browser.urls == [search_url]
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.wsj.com/markets/second-fixture-result-2b3c4d5e",
    ]


def test_search_uses_result_list_and_strict_wsj_urls() -> None:
    http = SearchHttp()

    results = WSJProvider().search(http, None, "bank capital", SearchFilters(limit=10))

    assert http.urls == ["https://www.wsj.com/search?query=bank+capital"]
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.wsj.com/markets/second-fixture-result-2b3c4d5e",
    ]
    assert [result.published for result in results] == [
        datetime(2026, 7, 16, 9, tzinfo=UTC),
        datetime(2026, 7, 15, 9, tzinfo=UTC),
    ]
    assert all(result.provider == "wsj" for result in results)

    filtered = WSJProvider().search(
        http,
        None,
        "bank capital",
        SearchFilters(published_before=datetime(2026, 7, 16, tzinfo=UTC)),
    )
    assert [str(result.url) for result in filtered] == [
        "https://www.wsj.com/markets/second-fixture-result-2b3c4d5e"
    ]


def test_public_search_never_attaches_the_paid_article_session() -> None:
    http = SearchHttp()

    WSJProvider().search(
        http,
        _session_artifact(),
        "bank capital",
        SearchFilters(limit=10),
    )

    assert http.sessions == [None]


def test_search_fallback_selectors_preserve_document_order() -> None:
    class MixedMarkupSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "raw_html": b"""
                    <html><body><main>
                      <article>
                        <a href="/finance/banking/provider-rank-one-11111111">
                          Rank one
                        </a>
                      </article>
                      <article><div class="headline">
                        <a href="/finance/banking/provider-rank-two-22222222">
                          <style>.headline { display: block; }</style>
                          Rank two
                        </a>
                      </div></article>
                    </main></body></html>
                    """
                }
            )

    results = WSJProvider().search(
        MixedMarkupSearchHttp(), None, "banks", SearchFilters()
    )

    assert [result.headline for result in results] == ["Rank one", "Rank two"]


def test_search_supports_current_flexcard_markup_without_embedded_css() -> None:
    class CurrentSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "raw_html": b"""
                    <html><body><main>
                      <script id="__NEXT_DATA__" type="application/json">
                        {"props":{"pageProps":{"searchResults":[{
                          "articleUrl":"https://www.wsj.com/finance/banking/european-bank-deal-a10ec4bc",
                          "timestamp":"2026-07-18T14:30:00Z"
                        }]}}}
                      </script>
                      <a data-testid="flexcard-headline"
                         href="/finance/banking/european-bank-deal-a10ec4bc?mod=Searchresults&amp;pos=1">
                        <style>.headline { display: block; }</style>
                        <div>Europe's Biggest Banking Deal</div>
                      </a>
                      <a data-testid="flexcard-headline"
                         href="/world/unrelated-trending-story-deadbeef?mod=search_trendingnow_article_pos1">
                        <div>Unrelated Trending Story</div>
                      </a>
                    </main></body></html>
                    """
                }
            )

    results = WSJProvider().search(
        CurrentSearchHttp(), None, "European banks", SearchFilters()
    )

    assert [result.headline for result in results] == ["Europe's Biggest Banking Deal"]
    assert [str(result.url) for result in results] == [
        "https://www.wsj.com/finance/banking/european-bank-deal-a10ec4bc"
    ]
    assert [result.published for result in results] == [
        datetime(2026, 7, 18, 14, 30, tzinfo=UTC)
    ]

    excluded = WSJProvider().search(
        CurrentSearchHttp(),
        None,
        "European banks",
        SearchFilters(published_after=datetime(2026, 7, 19, tzinfo=UTC)),
    )

    assert excluded == []


def test_search_ignores_malformed_embedded_publication_data() -> None:
    class MalformedSearchHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            fetch = super().get(url, **kwargs)
            return fetch.model_copy(
                update={
                    "raw_html": b"""
                    <html><body><main>
                      <script id="__NEXT_DATA__" type="application/json">
                        {broken
                      </script>
                      <a data-testid="flexcard-headline"
                         href="/finance/banking/european-bank-deal-a10ec4bc?mod=Searchresults&amp;pos=1">
                        <div>Europe's Biggest Banking Deal</div>
                      </a>
                    </main></body></html>
                    """
                }
            )

    results = WSJProvider().search(
        MalformedSearchHttp(), None, "European banks", SearchFilters()
    )

    assert len(results) == 1
    assert results[0].published is None


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
        WSJProvider().search(DriftedSearchHttp(), None, "bank capital", SearchFilters())


@pytest.mark.parametrize(
    "raw",
    [
        "http://www.wsj.com/finance/banks-rally-capital-1a2b3c4d",
        "https://evil.test/finance/banks-rally-capital-1a2b3c4d",
        "https://www.wsj.com.evil.test/finance/banks-rally-capital-1a2b3c4d",
        "https://www.wsj.com/finance/no-hex-suffix",
        "https://www.wsj.com/client/login-1a2b3c4d",
        "https://www.wsj.com/video/clip-1a2b3c4d",
        "//evil.test/finance/banks-rally-capital-1a2b3c4d",
    ],
)
def test_url_normalization_rejects_unowned_or_malformed_urls(raw: str) -> None:
    assert normalize_article_url(raw) is None


def test_url_normalization_canonicalizes_owned_relative_url() -> None:
    assert (
        normalize_article_url("/finance/banks-rally-capital-1a2b3c4d?mod=search")
        == ARTICLE_URL
    )
    assert article_id(ARTICLE_URL) == ARTICLE_ID


def test_registering_wsj_keeps_ft_assessment_green_and_routes_urls() -> None:
    registry = ProviderRegistry((FTProvider(), WSJProvider()))

    ft_url = "https://www.ft.com/content/11111111-1111-4111-8111-111111111111"
    assert registry.for_url(ft_url).key == "ft"
    assert registry.for_url(ARTICLE_URL).key == "wsj"

    # FT still assesses its own full fixture after WSJ registration (W4.6).
    ft_full = (Path(__file__).parent / "fixtures" / "ft" / "full.html").read_bytes()
    fetch = RawFetch(
        requested_url=ft_url,
        final_url=ft_url,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=ft_full,
    )
    ft = registry.get("ft")
    assessment = ft.assess(ft_url, fetch, TrafilaturaExtractor().extract(fetch))
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
        provider="wsj",
        created_at=NOW,
        verified_at=NOW,
        cookies=(PortableCookie(name="fixture", value="value", domain=".wsj.com"),),
    )


def test_recipe_verifier_uses_full_assessment_not_cookie_name() -> None:
    recipe = WSJLoginRecipe(verification_url=ARTICLE_URL)
    artifact = _session_artifact()

    verified = recipe.verify(FixtureHttp("verification_full.html"), artifact)
    short = recipe.verify(FixtureHttp("initial_excerpt.html"), artifact)
    teaser = recipe.verify(FixtureHttp("teaser.html"), artifact)

    assert verified.verified is True
    assert verified.access_state is AccessState.FULL
    assert short.verified is False
    assert short.access_state is AccessState.TEASER
    assert short.reason == "paywall_teaser"
    assert teaser.verified is False
    assert teaser.access_state is AccessState.TEASER


def test_recipe_requires_owned_verification_url() -> None:
    with pytest.raises(ValueError, match="owned article URL"):
        WSJLoginRecipe(verification_url="https://evil.test/x-1a2b3c4d")


@pytest.mark.parametrize(
    ("fixture", "final_url", "state"),
    [
        (
            "auth.html",
            "https://sso.accounts.dowjones.com/login",
            AccessState.AUTH_REQUIRED,
        ),
        ("datadome.html", ARTICLE_URL, AccessState.BLOCKED),
    ],
)
def test_readiness_stops_once_auth_or_challenge_verdict_is_stable(
    fixture: str, final_url: str, state: AccessState
) -> None:
    """Rendering more of an auth wall or challenge cannot promote it, so the
    sampler ends after the stability window instead of the 8s timeout."""

    from newsclip.browser_readiness import (
        ReadinessTerminalState,
        sample_semantic_snapshot,
    )
    from newsclip.composition import _browser_readiness_evaluator

    provider = WSJProvider()
    extractor = TrafilaturaExtractor()
    evaluate_fetch = _browser_readiness_evaluator(provider, extractor)
    fetch = _fetch(fixture, final_url=final_url, session_cookie_present=True)
    assessment = provider.assess(ARTICLE_URL, fetch, extractor.extract(fetch))
    assert assessment.access_state is state

    class StaticPage:
        url = final_url
        now = 0.0

        def wait_for_timeout(self, milliseconds):
            self.now += milliseconds / 1000

        def content(self):
            return fetch.raw_html.decode()

    page = StaticPage()
    readiness = provider.spec.browser_retrieval.semantic_readiness
    assert readiness is not None
    sampled = sample_semantic_snapshot(
        page,
        initial_content=fetch.raw_html,
        readiness=readiness,
        evaluator=lambda url, content: evaluate_fetch(
            fetch.model_copy(update={"raw_html": content})
        ),
        monotonic_clock=lambda: page.now,
    )

    assert sampled.terminal_state is ReadinessTerminalState.NON_PROMOTABLE_SETTLED
    assert not sampled.stabilized
    assert readiness.stable_seconds <= page.now < readiness.stable_seconds + 0.2


def test_readiness_keeps_waiting_through_teaser_and_transient_auth_wall() -> None:
    """A teaser is never settled (entitlement resolves late), and a brief auth
    verdict that changes within the stability window does not end sampling."""

    from newsclip.browser_readiness import (
        ReadinessTerminalState,
        sample_semantic_snapshot,
    )
    from newsclip.composition import _browser_readiness_evaluator

    provider = WSJProvider()
    extractor = TrafilaturaExtractor()
    evaluate_fetch = _browser_readiness_evaluator(provider, extractor)
    initial = _fetch("teaser.html", session_cookie_present=True)
    frames = [(0.0, "teaser.html"), (3.0, "auth.html"), (3.3, "full.html")]

    class Page:
        url = ARTICLE_URL
        now = 0.0

        def wait_for_timeout(self, milliseconds):
            self.now += milliseconds / 1000

        def content(self):
            name = [name for start, name in frames if self.now >= start][-1]
            return _fixture(name).decode()

    page = Page()
    readiness = provider.spec.browser_retrieval.semantic_readiness
    assert readiness is not None
    sampled = sample_semantic_snapshot(
        page,
        initial_content=initial.raw_html,
        readiness=readiness,
        evaluator=lambda url, content: evaluate_fetch(
            initial.model_copy(update={"raw_html": content})
        ),
        monotonic_clock=lambda: page.now,
    )

    assert sampled.terminal_state is ReadinessTerminalState.STABILIZED
    assert page.now > 3.3
