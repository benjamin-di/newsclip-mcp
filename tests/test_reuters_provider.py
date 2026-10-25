"""Offline contracts for Reuters sitemap search and public articles."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock
from urllib.parse import parse_qs, urlsplit

import pytest

from newsclip.errors import (
    ProviderContractError,
    ProviderDefenseError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters, SessionArtifact
from newsclip.provider_config import load_provider_spec
from newsclip.providers.registry import ProviderRegistry
from newsclip.providers.reuters import (
    ReutersProvider,
    article_id,
    normalize_article_url,
)
from newsclip.service import NewsclipService

NOW = datetime(2026, 7, 21, 2, tzinfo=UTC)
ARTICLE_URL = (
    "https://www.reuters.com/business/energy/"
    "grid-operator-warns-potential-rolling-blackouts-2026-07-21"
)
SECOND_URL = (
    "https://www.reuters.com/world/us/regional-grid-warning-continues-2026-07-20"
)
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
NEWS_NS = "http://www.google.com/schemas/sitemap-news/0.9"


def _article_html(*, canonical: str = ARTICLE_URL, body: bool = True) -> bytes:
    article = (
        "<article><p>"
        + "Verified Reuters reporting provides substantive fixture evidence. " * 30
        + "</p></article>"
        if body
        else "<main>Reuters section page without an article body.</main>"
    )
    return f"""
    <html><head>
      <title>Grid operator warns of rolling blackouts | Reuters</title>
      <link rel="canonical" href="{canonical}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Grid operator warns of rolling blackouts",
          "datePublished":"2026-07-21T01:16:24Z"}}
      </script>
    </head><body>{article}</body></html>
    """.encode()


def _fetch(body: bytes, *, status: int = 200) -> RawFetch:
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=status,
        content_type="text/html; charset=utf-8",
        retrieved_at=NOW,
        raw_html=body,
    )


def test_article_identity_is_strict_and_canonical() -> None:
    assert normalize_article_url(ARTICLE_URL + "?rpc=fixture") == ARTICLE_URL
    assert (
        normalize_article_url(ARTICLE_URL.replace("www.reuters.com", "reuters.com"))
        == ARTICLE_URL
    )
    assert (
        normalize_article_url("https://www.reuters.com/video/story-2026-07-21/") is None
    )
    assert (
        normalize_article_url("https://www.reuters.com/authors/name-2026-07-21/")
        is None
    )
    assert article_id(ARTICLE_URL) == (
        "business/energy/grid-operator-warns-potential-rolling-blackouts-2026-07-21"
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (_article_html(), AccessState.FULL),
        (_article_html(canonical=SECOND_URL), AccessState.UNKNOWN),
        (_article_html(body=False), AccessState.UNKNOWN),
        (
            b"<html><body><script src='https://ct.captcha-delivery.com/i.js'>"
            b"</script></body></html>",
            AccessState.BLOCKED,
        ),
    ],
)
def test_assessment_fails_closed_without_identity_and_structure(
    body: bytes,
    expected: AccessState,
) -> None:
    fetch = _fetch(body)
    assessment = ReutersProvider().assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)


def test_datadome_challenge_precedes_generic_http_status() -> None:
    fetch = _fetch(
        b"<html><body>Please enable JS and disable any ad blocker</body></html>",
        status=401,
    )

    assessment = ReutersProvider().assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is AccessState.BLOCKED
    assert assessment.reason == "interactive_challenge"
    assert assessment.negative_markers == ("interactive_challenge",)


def test_provider_challenge_classifier_reuses_the_assessment_contract() -> None:
    provider = ReutersProvider()
    challenge = _fetch(
        b"<html><body>Please enable JS and disable any ad blocker</body></html>",
        status=401,
    )

    assert provider.is_interactive_challenge(challenge) is True
    assert provider.is_interactive_challenge(_fetch(_article_html())) is False
    assert (
        provider.is_interactive_challenge(
            challenge.model_copy(update={"content_type": "application/json"})
        )
        is False
    )


_CHALLENGE_FIXTURE = (
    Path(__file__).parent / "fixtures" / "reuters" / "challenge-datadome.html"
)
_DEVICE_CHECK_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "reuters"
    / "challenge-datadome-device-check.html"
)


class _FixedHttp:
    """Primary transport that always answers with one canned fetch."""

    def __init__(self, fetch: RawFetch) -> None:
        self.result = fetch
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.calls.append(url)
        return self.result

    def get_for_check(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        # Satisfies SingleNavigationBrowserRetriever so the provider-check
        # (single-navigation) escalation path accepts this fake.
        return self.get(url, session=session, timeout=timeout)


class _BrowserPlane:
    """The narrowest fake of the retrieval plane the escalation binds to."""

    def __init__(self, result: RawFetch) -> None:
        self._client = _FixedHttp(result)
        self.bound: list[str] = []

    def for_provider(self, provider: str, *, role: object = None) -> _FixedHttp:
        self.bound.append(provider)
        return self._client

    def allows_http_fallback(self, provider: str) -> bool:
        # The declared capability, not a challenge resolver, must be what
        # enables the Reuters escalation.
        return False

    def release(self) -> None:
        pass

    def close(self) -> None:
        pass

    @property
    def browser_calls(self) -> list[str]:
        return self._client.calls


def _challenge_fetch() -> RawFetch:
    return _fetch(_CHALLENGE_FIXTURE.read_bytes(), status=401)


def test_challenge_fixture_matches_the_declared_classifier() -> None:
    provider = ReutersProvider()
    assert provider.is_interactive_challenge(_challenge_fetch()) is True


def test_device_check_interstitial_escalates_like_the_captcha() -> None:
    # The 10-09 refusal served the Device Check, not the slider; curl cannot
    # run it, so it must still classify as a challenge and reach the browser.
    fetch = _fetch(_DEVICE_CHECK_FIXTURE.read_bytes(), status=401)
    assert ReutersProvider().is_interactive_challenge(fetch) is True


def test_reuters_may_only_wait_out_datadome() -> None:
    from newsclip.challenge_catalog import build_promoted_mechanics
    from newsclip.challenges import ChallengeVendor
    from newsclip.providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS

    registration = BUILTIN_PROVIDER_REGISTRATIONS["reuters"]
    assert registration.approved_challenge_vendors == {ChallengeVendor.DATADOME}
    assert registration.passive_challenge_vendors == {ChallengeVendor.DATADOME}
    mechanics = build_promoted_mechanics(
        registration.approved_challenge_vendors,
        passive_vendors=registration.passive_challenge_vendors,
    )
    assert mechanics[ChallengeVendor.DATADOME].passive_only is True


def test_challenge_escalates_once_to_the_browser_and_never_arms(
    tmp_path,  # noqa: ANN001
) -> None:
    """R8: curl challenged and browser full — the provider is serving.

    Arming would suppress a provider that is demonstrably answering, so the
    escalated retrieval must complete FULL with no defense record, and the
    rot signal must name the provider.
    """

    from newsclip.defense import DefenseState

    plane = _BrowserPlane(_fetch(_article_html()))
    defense = DefenseState(tmp_path / "defense")
    rot: list[tuple[str, str | None]] = []
    refused = _challenge_fetch().model_copy(update={"serving_transport": "safari2601"})
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _FixedHttp(refused),
        TrafilaturaExtractor(),
        browser_retriever=plane,
        defense=defense,
        on_challenge_escalation_served=lambda provider, served_by: rot.append(
            (provider, served_by)
        ),
    )

    article = service.get(ARTICLE_URL)

    assert article.headline == "Grid operator warns of rolling blackouts"
    assert article.word_count > 100
    assert plane.browser_calls == [ARTICLE_URL]
    assert defense.status("reuters") is None
    # The signal names the profile that was actually refused, not the
    # definition's — after a promotion the two differ.
    assert rot == [("reuters", "safari2601")]


def test_challenged_browser_leg_fails_closed_and_arms_as_before(
    tmp_path,  # noqa: ANN001
) -> None:
    """R8: curl challenged and browser challenged — the edge is deciding
    what we are. Fail closed and arm exactly as today; no rot is recorded."""

    from newsclip.defense import DefenseState

    plane = _BrowserPlane(_challenge_fetch())
    defense = DefenseState(tmp_path / "defense")
    rot: list[tuple[str, str | None]] = []
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _FixedHttp(_challenge_fetch()),
        TrafilaturaExtractor(),
        browser_retriever=plane,
        defense=defense,
        on_challenge_escalation_served=lambda provider, served_by: rot.append(
            (provider, served_by)
        ),
    )

    with pytest.raises(ProviderDefenseError):
        service.get(ARTICLE_URL)

    assert plane.browser_calls == [ARTICLE_URL]
    assert defense.status("reuters") is not None
    assert rot == []


def test_standing_rot_sends_the_read_straight_to_the_browser(
    tmp_path,  # noqa: ANN001
) -> None:
    """The refused profile is not asked again while the rot signal stands."""

    from newsclip.defense import DefenseState

    plane = _BrowserPlane(_fetch(_article_html()))
    primary = _FixedHttp(_challenge_fetch())
    rot: list[tuple[str, str | None]] = []
    asked: list[str] = []

    def browser_first(provider: str) -> bool:
        asked.append(provider)
        return True

    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        primary,
        TrafilaturaExtractor(),
        browser_retriever=plane,
        defense=DefenseState(tmp_path / "defense"),
        on_challenge_escalation_served=lambda provider, served_by: rot.append(
            (provider, served_by)
        ),
        transport_browser_first=browser_first,
    )

    article = service.get(ARTICLE_URL)

    assert article.word_count > 100
    assert primary.calls == []
    assert plane.browser_calls == [ARTICLE_URL]
    assert "reuters" in asked
    # No primary fetch was refused, so there is no new rot to record.
    assert rot == []


def test_standing_rot_leaves_sitemap_search_on_http(tmp_path) -> None:  # noqa: ANN001
    from newsclip.defense import DefenseState

    plane = _BrowserPlane(_fetch(_article_html()))
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _SitemapThenChallengeHttp(),
        TrafilaturaExtractor(),
        browser_retriever=plane,
        defense=DefenseState(tmp_path / "defense"),
        transport_browser_first=lambda _provider: True,
    )

    results = service.search("reuters", "oil prices Iran war")

    assert [result.headline for result in results] == [_CHECK_TITLE]
    assert plane.browser_calls == []


_CHECK_URL = (
    "https://www.reuters.com/business/energy/"
    "why-oil-prices-havent-gone-crazy-despite-5-months-us-iran-war-2026-07-20"
)
_CHECK_TITLE = "Why oil prices haven't gone crazy despite 5 months of US-Iran war"


class _SitemapThenChallengeHttp:
    """The sitemap keeps answering while every article fetch is challenged.

    Exactly the measured 07-30/08-01 shape: search survives a fingerprint
    rot event that refuses the retrieval leg.
    """

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        if "news-sitemap" in url:
            offset = int(parse_qs(urlsplit(url).query)["from"][0])
            entries = (
                [_entry(_CHECK_URL + "/", _CHECK_TITLE, NOW - timedelta(minutes=30))]
                if offset == 0
                else []
            )
            return RawFetch(
                requested_url=url,
                final_url=url,
                http_status=200,
                content_type="application/xml; charset=utf-8",
                retrieved_at=NOW,
                raw_html=_sitemap(entries),
            )
        return _challenge_fetch().model_copy(
            update={"requested_url": url, "final_url": url}
        )


def test_provider_check_canary_escalates_and_reports_ok(
    tmp_path,  # noqa: ANN001
) -> None:
    """The guard canary rides the same escalation on its single navigation."""

    from newsclip.defense import DefenseState

    served = _fetch(
        _article_html(canonical=_CHECK_URL).replace(
            b"Grid operator warns of rolling blackouts",
            _CHECK_TITLE.encode(),
        )
    ).model_copy(update={"requested_url": _CHECK_URL, "final_url": _CHECK_URL})
    plane = _BrowserPlane(served)
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _SitemapThenChallengeHttp(),
        TrafilaturaExtractor(),
        browser_retriever=plane,
        defense=DefenseState(tmp_path / "defense"),
    )

    result = service.provider_check("reuters")

    assert result.ok is True
    assert plane.browser_calls == [_CHECK_URL]


def test_composed_rot_recorder_records_declared_providers_only(
    tmp_path,  # noqa: ANN001
    monkeypatch,  # noqa: ANN001
) -> None:
    """The real recorder writes the TOML pin, and only for declarations."""

    from newsclip.composition import _transport_rot_recorder
    from newsclip.provider_config import load_builtin_provider_specs
    from newsclip.transport_pins import TransportPinStore

    specs = {spec.key: spec for spec in load_builtin_provider_specs()}
    record = _transport_rot_recorder(tmp_path, specs)

    # A promoted runtime pin is what actually served, so that is what rots.
    record("reuters", "chrome146")
    record("economist", "chrome")  # resolver escalation: never a rot signal
    record("unknown-provider", "chrome")  # unregistered keys are ignored

    store = TransportPinStore(tmp_path / "transport-pins")
    reuters = store.load("reuters")
    assert reuters is not None
    assert reuters.rot_profile == "chrome146"
    assert store.load("economist") is None

    # An unknown or absent serving transport falls back to the declaration
    # rather than recording a name nothing can act on.
    record("reuters", None)
    fallback = store.load("reuters")
    assert fallback is not None
    assert fallback.rot_profile == "safari2601"

    # The write must never break the retrieval it rides on.
    monkeypatch.setattr(
        TransportPinStore,
        "record_rot",
        lambda self, provider, *, profile: (_ for _ in ()).throw(OSError("disk")),
    )
    _transport_rot_recorder(tmp_path, specs)("reuters", "safari2601")


def test_unmarked_unauthorized_response_keeps_http_classification() -> None:
    fetch = _fetch(b"<html><body>Unauthorized</body></html>", status=401)

    assessment = ReutersProvider().assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is AccessState.UNKNOWN
    assert assessment.reason == "http_unauthorized"
    assert assessment.negative_markers == ("http_error",)


_STORY_COLLECTION_XPATH = '//ul[@data-testid="StoryCollection"]'
_TEASER_SENTENCE = (
    "A wholly unrelated USAID story teases from the related rail and must never "
    "reach a verified body. "
)
_BODY_SENTENCE = "Verified Reuters reporting provides substantive fixture evidence. "


def _rail_html(*, articles: int = 1) -> bytes:
    """Mirror the live DOM: a related-story rail outside the article element.

    Reuters renders ``div[data-testid=MediaStoryCard]`` inside
    ``ul[data-testid=StoryCollection]``, a sibling of the page's single
    ``<article>``, and rotates which story it teases — which is why byte-stable
    article content produced 1005 then 996 words live.

    ``articles=0`` keeps the body in a non-article container, the shape of a page
    the scope is meant to refuse; ``articles=2`` is the drift case.
    """

    paragraphs = "".join(
        f'<div data-testid="paragraph-{index}"><p>{_BODY_SENTENCE * 8}</p></div>'
        for index in range(6)
    )
    body = (
        f"<article>{paragraphs}</article>" * articles
        if articles
        else f'<div data-testid="Article">{paragraphs}</div>'
    )
    return f"""
    <html><head>
      <title>Grid operator warns of rolling blackouts | Reuters</title>
      <link rel="canonical" href="{ARTICLE_URL}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Grid operator warns of rolling blackouts",
          "datePublished":"2026-07-21T01:16:24Z"}}
      </script>
    </head><body><div class="shell">
      {body}
      <ul data-testid="StoryCollection">
        <li><div data-testid="MediaStoryCard"><p>
          {_TEASER_SENTENCE * 4}
        </p></div></li>
      </ul>
    </div></body></html>
    """.encode()


def test_extraction_scope_bounds_the_body_to_the_declared_subtree() -> None:
    provider = ReutersProvider()
    fetch = _fetch(_rail_html())
    extractor = TrafilaturaExtractor()

    assert provider.extraction_scope == ("//article",)
    scoped = extractor.extract(fetch, scope_xpath=provider.extraction_scope)

    assert _BODY_SENTENCE.strip() in scoped.body_markdown
    assert "USAID" not in scoped.body_markdown
    assert provider.assess(ARTICLE_URL, fetch, scoped).promotable

    # The rail is extractable content, not something trafilatura would discard
    # anyway, so its absence above is the scope boundary doing the work.
    rail_only = extractor.extract(fetch, scope_xpath=(_STORY_COLLECTION_XPATH,))
    assert "USAID" in rail_only.body_markdown

    # Metadata stays full-document: Reuters keeps datePublished and the headline
    # outside <article>, and build_article depends on them.
    assert scoped.metadata["date"] == "2026-07-21T01:16:24Z"
    assert scoped.metadata["title"] == "Grid operator warns of rolling blackouts"


@pytest.mark.parametrize("articles", [0, 2])
def test_unresolved_extraction_scope_fails_closed(articles: int) -> None:
    """Zero or several matches yield no body, so assessment cannot promote.

    Zero is a page whose body is not in an ``<article>``; unscoped, the rail is
    the only thing trafilatura can find and the foreign teaser becomes the body.
    Two is provider drift; unscoped, both articles are silently concatenated. An
    allowlist refuses both instead of guessing which element was meant.
    """

    fetch = _fetch(_rail_html(articles=articles))
    provider = ReutersProvider()
    extractor = TrafilaturaExtractor()

    unscoped = extractor.extract(fetch)
    extraction = extractor.extract(fetch, scope_xpath=provider.extraction_scope)

    assert ("USAID" in unscoped.body_markdown) is (articles == 0)
    assert unscoped.word_count > 0
    assert extraction.body_markdown == ""
    assert extraction.word_count == 0
    assessment = provider.assess(ARTICLE_URL, fetch, extraction)
    assert not assessment.promotable
    assert assessment.access_state is AccessState.UNKNOWN
    assert "markdown_body" not in assessment.structural_signals


def _entry(url: str, title: str, published: datetime) -> str:
    return f"""
    <url><loc>{url}</loc><news:news>
      <news:title>{title}</news:title>
      <news:publication_date>{published.isoformat()}</news:publication_date>
    </news:news></url>
    """


def _sitemap(entries: list[str]) -> bytes:
    return (
        f'<urlset xmlns="{SITEMAP_NS}" xmlns:news="{NEWS_NS}">'
        + "".join(entries)
        + "</urlset>"
    ).encode()


class SitemapHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []
        self.final_url: str | None = None
        self.content_type = "application/xml; charset=utf-8"
        self.invalid_schema = False

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        self.sessions.append(session)
        offset = int(parse_qs(urlsplit(url).query)["from"][0])
        if self.invalid_schema:
            body = b"<changed/>"
        elif offset == 0:
            entries = [
                _entry(
                    ARTICLE_URL + "/",
                    "Grid operator warns of rolling blackouts",
                    NOW - timedelta(minutes=30),
                ),
                *(
                    _entry(
                        (
                            "https://www.reuters.com/world/fixture/"
                            f"unrelated-item-{index}-2026-07-21/"
                        ),
                        f"Unrelated current item {index}",
                        NOW - timedelta(minutes=index + 31),
                    )
                    for index in range(49)
                ),
            ]
            body = _sitemap(entries)
        else:
            body = _sitemap(
                [
                    _entry(
                        SECOND_URL + "/",
                        "Regional grid warning continues",
                        datetime(2026, 7, 20, 20, tzinfo=UTC),
                    )
                ]
            )
        return RawFetch(
            requested_url=url,
            final_url=self.final_url or url,
            http_status=200,
            content_type=self.content_type,
            retrieved_at=NOW,
            raw_html=body,
        )


def test_search_ranks_current_sitemap_matches_and_omits_session() -> None:
    http = SitemapHttp()

    results = ReutersProvider().search(
        http,
        SessionArtifact.model_construct(),
        "grid blackouts",
        SearchFilters(limit=2),
    )

    assert str(results[0].url) == ARTICLE_URL
    assert results[0].published == NOW - timedelta(minutes=30)
    assert ARTICLE_URL in {str(result.url) for result in results}
    offsets = sorted(int(parse_qs(urlsplit(url).query)["from"][0]) for url in http.urls)
    assert offsets == [0, 50, 100, 150, 200, 250, 300, 350]
    assert parse_qs(urlsplit(http.urls[0]).query)["outputType"] == ["xml"]
    assert all(session is None for session in http.sessions)


def test_search_ranking_is_independent_of_page_completion_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ReutersProvider()
    newest_url = (
        "https://www.reuters.com/world/us/new-federal-reserve-decision-2026-07-24"
    )
    older_url = (
        "https://www.reuters.com/world/us/old-federal-reserve-decision-2026-07-20"
    )

    def entries(page: int) -> list[tuple[str, str, datetime]]:
        page_start = NOW - timedelta(hours=page)
        return [
            (
                (
                    "https://www.reuters.com/world/fixture/"
                    f"unrelated-{page}-{index}-2026-07-21"
                ),
                f"Unrelated item {page} {index}",
                page_start - timedelta(minutes=index),
            )
            for index in range(50)
        ]

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        page = offset // 50
        page_entries = entries(page)
        if page == 7:
            page_entries[0] = (
                older_url,
                "Federal Reserve decision",
                NOW - timedelta(hours=7),
            )
        if page == 0:
            time.sleep(0.05)
            page_entries[0] = (
                newest_url,
                "Federal Reserve decision",
                NOW + timedelta(hours=1),
            )
        return page_entries

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    results = provider.search(
        SitemapHttp(),
        None,
        "Federal Reserve decision",
        SearchFilters(limit=1),
    )

    assert [str(result.url) for result in results] == [newest_url]


def test_search_allows_non_chronological_sitemap_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ReutersProvider()

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        page = offset // 50
        page_start = NOW - timedelta(hours=page)
        entries = [
            (
                (
                    "https://www.reuters.com/world/fixture/"
                    f"unordered-{page}-{index}-2026-07-21"
                ),
                f"Unordered item {page} {index}",
                page_start - timedelta(minutes=index),
            )
            for index in range(50)
        ]
        if page == 0:
            entries[0], entries[-1] = entries[-1], entries[0]
            entries[1] = (
                ARTICLE_URL,
                "Grid blackouts",
                page_start,
            )
        return entries

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    results = provider.search(
        SitemapHttp(),
        None,
        "grid blackouts",
        SearchFilters(limit=1),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL]


def test_newer_partial_match_does_not_hide_deeper_perfect_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ReutersProvider()
    perfect_url = (
        "https://www.reuters.com/world/us/federal-reserve-policy-decision-2026-07-21"
    )

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        page = offset // 50
        page_start = NOW - timedelta(hours=page)
        entries = [
            (
                (
                    "https://www.reuters.com/world/fixture/"
                    f"unrelated-{page}-{index}-2026-07-21"
                ),
                f"Unrelated item {page} {index}",
                page_start - timedelta(minutes=index),
            )
            for index in range(50)
        ]
        if page == 0:
            entries[0] = (
                ARTICLE_URL,
                "Federal decision",
                page_start,
            )
        if page == 7:
            entries[0] = (
                perfect_url,
                "Federal Reserve policy decision",
                page_start,
            )
        return entries

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    results = provider.search(
        SitemapHttp(),
        None,
        "Federal Reserve decision",
        SearchFilters(limit=1),
    )

    assert [str(result.url) for result in results] == [perfect_url]


def test_search_request_endpoint_comes_from_adapter_definition() -> None:
    spec = load_provider_spec("reuters")
    search = type(spec.search).model_validate(
        {
            "kind": "adapter",
            "endpoint": "https://www.reuters.com/configured-news-sitemap/",
        }
    )
    provider = ReutersProvider(spec=spec.model_copy(update={"search": search}))
    http = SitemapHttp()

    provider.search(http, None, "grid blackouts", SearchFilters(limit=1))

    assert http.urls
    assert all(
        url.startswith("https://www.reuters.com/configured-news-sitemap/?")
        for url in http.urls
    )


def test_federated_search_page_uses_the_sitemap_adapter() -> None:
    http = SitemapHttp()
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        http,
        TrafilaturaExtractor(),
    )

    response = service.search_many(
        "grid blackouts",
        SearchFilters(limit=2),
        provider_keys=("reuters",),
    )

    assert str(response.results[0].url) == ARTICLE_URL
    assert ARTICLE_URL in {str(result.url) for result in response.results}
    assert response.sources[0].state.value == "ok"
    assert all("query" not in parse_qs(urlsplit(url).query) for url in http.urls)

    with pytest.raises(ProviderContractError, match="does not expose continuation"):
        ReutersProvider().search_page(
            SitemapHttp(),
            None,
            "grid blackouts",
            SearchFilters(limit=2),
            next_url="https://www.reuters.com/continuation",
        )


def test_search_discloses_the_window_it_could_actually_reach() -> None:
    """A moving-window provider reports its trailing edge, not just a count.

    Without it, an honest one-result answer reads as "Reuters has almost
    nothing" instead of "Reuters was only searchable for the last ten hours".
    """

    http = SitemapHttp()
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        http,
        TrafilaturaExtractor(),
    )

    response = service.search_many(
        "grid blackouts",
        SearchFilters(limit=2),
        provider_keys=("reuters",),
    )
    report = response.sources[0]

    # The oldest entry the fixture window carries, across all fetched offsets.
    assert report.coverage_start == datetime(2026, 7, 20, 20, tzinfo=UTC)
    assert report.coverage_start <= min(
        result.published for result in response.results if result.published
    )
    assert report.public_dict()["coverage_start"] == "2026-07-20T20:00:00Z"


def test_coverage_start_counts_only_entries_the_provider_owns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unowned sitemap entry cannot extend the claimed reach.

    Reuters' feed carries video and section URLs the identity pattern rejects.
    Search can never return them, so dating coverage by one would claim reach
    the answer never had.
    """

    provider = ReutersProvider()

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        if offset:
            return []
        return [
            (ARTICLE_URL, "Grid blackouts", NOW - timedelta(hours=2)),
            # Rejected by the identity pattern, and much older.
            (
                "https://www.reuters.com/video/grid-report-2026-07-01",
                "Grid report video",
                NOW - timedelta(days=20),
            ),
        ]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    page = provider.search_page(SitemapHttp(), None, "grid", SearchFilters(limit=5))

    assert page.coverage_start == NOW - timedelta(hours=2)


def test_coverage_start_uses_sitemap_stamps_not_reconciled_dates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A re-stamped old story does not widen the searchable window.

    Reconciliation moves such an entry's published date years back, but the
    window only ever reached the sitemap stamp.
    """

    provider = ReutersProvider()

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        if offset:
            return []
        return [
            (
                "https://www.reuters.com/world/china/grid-investment-review-2024-06-14",
                "Grid investment review",
                NOW - timedelta(hours=2),
            )
        ]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    page = provider.search_page(SitemapHttp(), None, "grid", SearchFilters(limit=5))

    assert page.coverage_start == NOW - timedelta(hours=2)
    assert page.results[0].published == datetime(2024, 6, 14, tzinfo=UTC)


def test_federated_pager_keeps_ranked_results_beyond_the_first_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ReutersProvider()
    fetched_offsets: list[int] = []

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        fetched_offsets.append(offset)
        return [
            (
                (
                    "https://www.reuters.com/world/fixture/"
                    f"pagination-result-{offset + index}-2026-07-21"
                ),
                f"Pagination result {offset + index}",
                NOW - timedelta(minutes=offset + index),
            )
            for index in range(50)
        ]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)
    service = NewsclipService(
        ProviderRegistry((provider,)),
        SitemapHttp(),
        TrafilaturaExtractor(),
    )
    pager = service.search_pager(
        "pagination result",
        SearchFilters(limit=20),
        provider_keys=("reuters",),
    )

    first = pager.next_batch(20)
    second = pager.next_batch(20)

    assert len(first.results) == 20
    assert len(second.results) == 20
    assert first.has_more
    assert second.has_more
    assert {str(result.url) for result in first.results}.isdisjoint(
        str(result.url) for result in second.results
    )
    assert sorted(fetched_offsets) == [0, 50, 100, 150, 200, 250, 300, 350]


def test_search_waits_for_dispatched_sitemap_workers_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = ReutersProvider()
    started = Barrier(8)
    lock = Lock()
    active_workers = 0

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        nonlocal active_workers
        del http
        with lock:
            active_workers += 1
        try:
            started.wait(timeout=1)
            if offset == 0:
                raise ProviderTransportError("fixture sitemap failure")
            time.sleep(0.1)
            return []
        finally:
            with lock:
                active_workers -= 1

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    with pytest.raises(ProviderTransportError, match="fixture sitemap failure"):
        provider.search(
            SitemapHttp(),
            None,
            "fixture",
            SearchFilters(limit=1),
        )

    assert active_workers == 0


def test_function_word_matches_never_qualify_a_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reproduce the live census: only informative tokens may score.

    "of" alone matched 23 of 400 window entries for "Strait of Hormuz", and
    recency then promoted the newest of them — an outfielder abbreviation.
    """

    provider = ReutersProvider()
    strait_url = (
        "https://www.reuters.com/world/middle-east/"
        "tanker-traffic-through-the-strait-slows-2026-07-21"
    )
    function_word_url = (
        "https://www.reuters.com/sports/baseball/"
        "white-sox-reinstate-of-everson-pereira-2026-07-21"
    )

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        if offset:
            return []
        return [
            # Newest, so recency would promote it if "of" scored at all.
            (
                function_word_url,
                "White Sox reinstate OF Everson Pereira",
                NOW,
            ),
            (
                strait_url,
                "Tanker traffic through the strait slows",
                NOW - timedelta(hours=4),
            ),
        ]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    results = provider.search(
        SitemapHttp(),
        None,
        "Strait of Hormuz",
        SearchFilters(limit=10),
    )

    assert [str(result.url) for result in results] == [strait_url]


def test_slug_date_tokens_do_not_qualify_a_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trailing slug date is metadata, so its tokens cannot score.

    Every entry in a one-day window shares them, so scoring them makes any
    query carrying a year or a bare number match the whole window at score 1.
    Headline digits stay scoreable, because there a number is content.
    """

    provider = ReutersProvider()
    model_url = "https://www.reuters.com/business/aerospace/boeing-737-order-2026-07-21"

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        if offset:
            return []
        return [
            (
                "https://www.reuters.com/world/fixture/"
                f"unrelated-item-{index}-2026-07-21",
                f"Unrelated item {index}",
                NOW - timedelta(minutes=index),
            )
            for index in range(5)
        ] + [(model_url, "Boeing wins 737 order", NOW - timedelta(hours=9))]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    def urls(query: str) -> list[str]:
        return [
            str(result.url)
            for result in provider.search(
                SitemapHttp(), None, query, SearchFilters(limit=10)
            )
        ]

    # "21" and "2026" appear only as slug dates here, so nothing may qualify.
    assert urls("outlook for 21 July") == []
    assert urls("outlook 2026") == []
    assert urls("737 order") == [model_url]


def test_restamped_entries_sink_to_their_slug_publish_day(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A re-stamped sitemap date is clamped to the immutable slug day.

    Reuters rewrites ``news:publication_date`` on re-publish, so a 2024 story
    can carry a 2026 stamp and top ``sort=newest``. The slug date is validated
    by the identity pattern and never changes.
    """

    provider = ReutersProvider()
    restamped_url = (
        "https://www.reuters.com/world/china/grid-investment-review-2024-06-14"
    )
    same_day_url = "https://www.reuters.com/world/us/grid-demand-record-2026-07-21"
    across_midnight_url = (
        "https://www.reuters.com/world/europe/grid-interconnector-deal-2026-07-20"
    )
    same_day_stamp = NOW - timedelta(hours=3)
    across_midnight_stamp = datetime(2026, 7, 21, 1, 30, tzinfo=UTC)

    def sitemap_page(http, *, offset: int):  # noqa: ANN001
        del http
        if offset:
            return []
        return [
            (restamped_url, "Grid investment review", NOW - timedelta(minutes=1)),
            (same_day_url, "Grid demand record", same_day_stamp),
            (across_midnight_url, "Grid interconnector deal", across_midnight_stamp),
        ]

    monkeypatch.setattr(provider, "_sitemap_page", sitemap_page)

    results = provider.search(SitemapHttp(), None, "grid", SearchFilters(limit=10))
    published = {str(result.url): result.published for result in results}

    # The 773-day re-stamp is replaced by the slug day at midnight UTC, so the
    # newest sitemap entry now sorts last.
    assert published[restamped_url] == datetime(2024, 6, 14, tzinfo=UTC)
    assert [str(result.url) for result in results][-1] == restamped_url
    # Same-day and one-day-tolerance entries keep their intraday sitemap time.
    assert published[same_day_url] == same_day_stamp
    assert published[across_midnight_url] == across_midnight_stamp

    # The reconciled instant is what date filters see, so the re-stamped story
    # no longer passes a 2026 published_after.
    recent = provider.search(
        SitemapHttp(),
        None,
        "grid",
        SearchFilters(limit=10, published_after=datetime(2026, 1, 1, tzinfo=UTC)),
    )
    assert restamped_url not in {str(result.url) for result in recent}
    assert same_day_url in {str(result.url) for result in recent}


def test_search_date_filter_and_stop_words_fail_closed() -> None:
    results = ReutersProvider().search(
        SitemapHttp(),
        None,
        "grid",
        SearchFilters(published_after=datetime(2026, 7, 21, tzinfo=UTC)),
    )
    assert [str(result.url) for result in results] == [ARTICLE_URL]

    with pytest.raises(UnsearchableQueryError, match="unsearchable_query"):
        ReutersProvider().search(SitemapHttp(), None, "the and", SearchFilters())


def test_search_rejects_redirect_schema_and_media_type_drift() -> None:
    redirected = SitemapHttp()
    redirected.final_url = "https://www.reuters.com/arc/outboundfeeds/news-sitemap/"
    with pytest.raises(ProviderContractError, match="identity"):
        ReutersProvider().search(redirected, None, "grid", SearchFilters())

    schema = SitemapHttp()
    schema.invalid_schema = True
    with pytest.raises(ProviderContractError, match="root schema"):
        ReutersProvider().search(schema, None, "grid", SearchFilters())

    wrong_type = SitemapHttp()
    wrong_type.content_type = "text/html"
    with pytest.raises(ProviderTransportError, match="non-XML"):
        ReutersProvider().search(wrong_type, None, "grid", SearchFilters())


def test_candidate_probe_arms_nothing_and_writes_no_observation(
    tmp_path,  # noqa: ANN001
) -> None:
    """R8: a refused candidate is a measurement, not a defense episode.

    Routed through the ordinary client, every hourly refusal would arm and
    re-double the cooldown, containing a provider the escalation is
    demonstrably serving. This fixture is the guard against that inversion.
    """

    from contextlib import nullcontext

    from newsclip.defense import DefenseState
    from newsclip.incidents import IncidentStore
    from newsclip.provenance import BuildIdentity, BuildIdentitySource

    defense = DefenseState(tmp_path / "defense")
    incidents = IncidentStore(
        tmp_path / "incidents",
        build_identity=BuildIdentity(
            revision="a" * 40,
            dirty=False,
            source_fingerprint="a" * 64,
            source=BuildIdentitySource.ENVIRONMENT,
        ),
    )
    candidates: list[str] = []

    def candidate_client(profile: str):  # noqa: ANN202
        candidates.append(profile)
        return nullcontext(_FixedHttp(_challenge_fetch()))

    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _FixedHttp(_challenge_fetch()),
        TrafilaturaExtractor(),
        defense=defense,
        incidents=incidents,
        candidate_client_factory=candidate_client,
    )

    served = service.probe_transport_candidate("reuters", "chrome146")

    # The candidate spoke its own fingerprint on its own client.
    assert candidates == ["chrome146"]
    assert served is False
    # And the refusal armed nothing: no record, and the gate stays open.
    assert defense.status("reuters") is None
    assert defense.gate("reuters").allowed is True
    # No capsule either: a measurement is not review evidence.
    assert not list(incidents.root.glob("incident-*"))


def test_candidate_probe_reports_a_serving_candidate(
    tmp_path,  # noqa: ANN001
) -> None:
    from contextlib import nullcontext

    from newsclip.defense import DefenseState

    served_fetch = _fetch(
        _article_html(canonical=_CHECK_URL).replace(
            b"Grid operator warns of rolling blackouts",
            _CHECK_TITLE.encode(),
        )
    ).model_copy(
        update={
            "requested_url": _CHECK_URL,
            "final_url": _CHECK_URL,
        }
    )
    defense = DefenseState(tmp_path / "defense")
    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _FixedHttp(_challenge_fetch()),
        TrafilaturaExtractor(),
        defense=defense,
        candidate_client_factory=lambda profile: nullcontext(_FixedHttp(served_fetch)),
    )

    assert service.probe_transport_candidate("reuters", "chrome146") is True
    # A passing measurement is still only a measurement: it clears nothing
    # and records nothing in the defense state either way.
    assert defense.status("reuters") is None


def test_candidate_probe_refuses_names_outside_the_allowlist(
    tmp_path,  # noqa: ANN001
) -> None:
    from newsclip.errors import UsageError

    service = NewsclipService(
        ProviderRegistry((ReutersProvider(),)),
        _FixedHttp(_challenge_fetch()),
        TrafilaturaExtractor(),
        candidate_client_factory=lambda profile: pytest.fail(
            "an unlisted candidate must never reach a transport"
        ),
    )

    with pytest.raises(UsageError):
        service.probe_transport_candidate("reuters", "firefox147")
