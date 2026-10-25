"""Offline Economist identity, search, and paid-article contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from newsclip.challenge_transport import ChallengeAwareHttpClient
from newsclip.errors import ProviderDefenseError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters, SessionArtifact
from newsclip.providers.economist import (
    EconomistLoginRecipe,
    EconomistProvider,
    article_id,
    normalize_article_url,
)

NOW = datetime(2026, 7, 21, tzinfo=UTC)
ARTICLE_URL = (
    "https://www.economist.com/business/2026/07/16/"
    "how-sk-hynix-became-the-king-of-advanced-memory-chips"
)
SECOND_URL = (
    "https://www.economist.com/technology/2024/10/24/"
    "memory-chips-could-be-the-next-bottleneck-for-ai"
)
FIXTURES = Path(__file__).parent / "fixtures/economist"


def _article_html(
    *,
    canonical: str = ARTICLE_URL,
    paywall: bool = False,
    article: bool = True,
) -> bytes:
    paragraphs = "".join(
        f"<p>Paragraph {index} "
        + "Substantive Economist fixture reporting supports the full article gate. "
        * 18
        + "</p>"
        for index in range(5)
    )
    body = (
        f"<article><h1>Fixture chip report</h1>{paragraphs}</article>"
        if article
        else "<main><h1>Business landing page</h1></main>"
    )
    if paywall:
        body = (
            "<article><h1>Fixture chip report</h1><p>Short preview.</p>"
            "<teg-inline-wall><h4>Already have an account?</h4>"
            "<a>Log in</a></teg-inline-wall></article>"
        )
    return f"""
    <html><head>
      <title>Fixture chip report</title>
      <link rel="canonical" href="{canonical}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Fixture chip report","datePublished":"2026-07-16T12:00:00Z"}}
      </script>
    </head><body><main>{body}</main></body></html>
    """.encode()


def _fetch(
    body: bytes,
    *,
    final_url: str = ARTICLE_URL,
    status: int = 200,
) -> RawFetch:
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=final_url,
        http_status=status,
        content_type="text/html; charset=utf-8",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=body,
    )


def test_article_identity_is_strict_and_canonical() -> None:
    assert normalize_article_url(ARTICLE_URL + "?utm_source=fixture") == ARTICLE_URL
    assert (
        normalize_article_url(ARTICLE_URL.replace("www.economist.com", "economist.com"))
        == ARTICLE_URL
    )
    assert (
        normalize_article_url("https://www.economist.com/search/2026/07/16/x") is None
    )
    assert (
        normalize_article_url("http://www.economist.com/business/2026/07/16/x") is None
    )
    assert article_id(ARTICLE_URL) == (
        "business/2026/07/16/how-sk-hynix-became-the-king-of-advanced-memory-chips"
    )


@pytest.mark.parametrize(
    ("body", "final_url", "status", "expected"),
    [
        (_article_html(), ARTICLE_URL, 200, AccessState.FULL),
        (_article_html(paywall=True), ARTICLE_URL, 200, AccessState.TEASER),
        (_article_html(article=False), ARTICLE_URL, 200, AccessState.UNKNOWN),
        (_article_html(canonical=SECOND_URL), ARTICLE_URL, 200, AccessState.UNKNOWN),
        (
            b"<html><body><iframe src='https://captcha-delivery.com/x'></iframe></body></html>",
            ARTICLE_URL,
            200,
            AccessState.BLOCKED,
        ),
        (
            b"<html><body><form><input type='password'></form></body></html>",
            "https://myaccount.economist.com/s/login",
            200,
            AccessState.AUTH_REQUIRED,
        ),
        (
            (FIXTURES / "auth.html").read_bytes(),
            "https://myaccount.economist.com/s/login",
            200,
            AccessState.AUTH_REQUIRED,
        ),
        (_article_html(), ARTICLE_URL, 503, AccessState.UNKNOWN),
    ],
)
def test_assessment_fails_closed_without_full_paid_structure(
    body: bytes,
    final_url: str,
    status: int,
    expected: AccessState,
) -> None:
    fetch = _fetch(body, final_url=final_url, status=status)
    extraction = TrafilaturaExtractor().extract(fetch)

    assessment = EconomistProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)


class SearchHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        self.sessions.append(session)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=200,
            content_type="text/html; charset=utf-8",
            retrieved_at=NOW,
            raw_html=f"""
            <html><body><main><ol>
              <li><div><h2><a href="{ARTICLE_URL}">Chip king</a></h2>
                <time>Jul 16th 2026</time></div></li>
              <li><div><h2><a href="{SECOND_URL}">Memory bottleneck</a></h2>
                <time>Oct 24th 2024</time></div></li>
              <li><h2><a href="https://foreign.test/story">Foreign result</a></h2></li>
            </ol></main></body></html>
            """.encode(),
        )


class ChallengeHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []
        self.body = (FIXTURES / "cloudflare-interstitial.html").read_bytes()

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        del timeout
        self.urls.append(url)
        self.sessions.append(session)
        return RawFetch(
            requested_url=url,
            final_url=url,
            http_status=403,
            content_type="text/html; charset=utf-8",
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=self.body,
        )


def test_search_uses_rendered_result_list_dates_and_verified_session() -> None:
    http = SearchHttp()
    session = SessionArtifact.model_construct()

    results = EconomistProvider().search(
        http,
        session,
        "memory chips",
        SearchFilters(limit=10),
    )

    assert http.urls == ["https://www.economist.com/search?q=memory+chips"]
    assert http.sessions == [session]
    assert [str(result.url) for result in results] == [ARTICLE_URL, SECOND_URL]
    assert [result.headline for result in results] == ["Chip king", "Memory bottleneck"]
    assert results[0].published == datetime(2026, 7, 16, tzinfo=UTC)


@pytest.mark.parametrize(
    "fixture", ["cloudflare-interstitial.html", "datadome-interstitial.html"]
)
def test_search_escalates_an_interstitial_once_to_browser_html(fixture: str) -> None:
    provider = EconomistProvider()
    primary = ChallengeHttp()
    primary.body = (FIXTURES / fixture).read_bytes()
    browser = SearchHttp()
    session = SessionArtifact.model_construct()
    client = ChallengeAwareHttpClient(
        "economist",
        primary,
        is_challenge=provider.is_interactive_challenge,
        browser_fallback=browser,
    )

    results = provider.search(
        client,
        session,
        "memory chips",
        SearchFilters(limit=10),
    )

    expected_url = "https://www.economist.com/search?q=memory+chips"
    assert primary.urls == [expected_url]
    assert primary.sessions == [session]
    assert browser.urls == [expected_url]
    assert browser.sessions == [session]
    assert [str(result.url) for result in results] == [ARTICLE_URL, SECOND_URL]


def test_cloudflare_interstitial_is_blocked_content_evidence() -> None:
    fetch = _fetch((FIXTURES / "cloudflare-interstitial.html").read_bytes(), status=403)
    provider = EconomistProvider()

    assert provider.is_interactive_challenge(fetch) is True
    assessment = provider.assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is AccessState.BLOCKED
    assert assessment.reason == "interactive_challenge"


def test_datadome_search_refusal_is_defense_without_an_approved_fallback() -> None:
    provider = EconomistProvider()
    fetch = _fetch((FIXTURES / "datadome-interstitial.html").read_bytes(), status=403)
    calls = []

    class RecordedHttp:
        def get(self, url, **kwargs):
            calls.append(url)
            return fetch

    client = ChallengeAwareHttpClient(
        "economist",
        RecordedHttp(),
        is_challenge=provider.is_interactive_challenge,
        browser_fallback=None,
    )
    with pytest.raises(ProviderDefenseError) as failure:
        provider.search(client, None, "markets", SearchFilters(limit=1))
    assert failure.value.fetch is fetch
    assert calls == ["https://www.economist.com/search?q=markets"]
    assert (
        provider.assess(
            ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
        ).access_state
        is AccessState.BLOCKED
    )


def test_datadome_script_alone_on_an_article_is_not_a_challenge() -> None:
    fetch = _fetch(
        _article_html().replace(
            b"</body>",
            b'<script src="https://ct.captcha-delivery.com/i.js"></script></body>',
        )
    )
    assert EconomistProvider().is_interactive_challenge(fetch) is False


def test_search_filters_known_publication_dates() -> None:
    results = EconomistProvider().search(
        SearchHttp(),
        None,
        "memory chips",
        SearchFilters(published_after=datetime(2026, 1, 1, tzinfo=UTC)),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL]


def test_provider_exposes_only_an_explicit_verification_recipe() -> None:
    assert EconomistProvider().login_recipe is None
    assert isinstance(
        EconomistProvider(verification_url=ARTICLE_URL).login_recipe,
        EconomistLoginRecipe,
    )
