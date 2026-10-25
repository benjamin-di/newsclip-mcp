"""Offline contracts for AP News sitemap search and public articles."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.errors import (
    ProviderContractError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters, SessionArtifact
from newsclip.providers.ap import (
    ApProvider,
    article_id,
    normalize_article_url,
)

NOW = datetime(2026, 7, 28, 2, tzinfo=UTC)
ARTICLE_ID = "religious-liberty-lawsuit-" + "a" * 32
ARTICLE_URL = f"https://apnews.com/article/{ARTICLE_ID}"
SECOND_URL = "https://apnews.com/article/grid-warning-" + "b" * 32
ENDPOINT = "https://apnews.com/news-sitemap-content.xml"
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
NEWS_NS = "http://www.google.com/schemas/sitemap-news/0.9"


def test_cloudflare_interstitial_is_classified_from_retained_structure() -> None:
    source = (
        Path(__file__).parent / "fixtures/ap/cloudflare-interstitial.html"
    ).read_bytes()
    provider = ApProvider()
    fetch = _fetch(source, status=403)
    assert provider.is_interactive_challenge(fetch)
    assert (
        provider.assess(
            ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
        ).reason
        == "interactive_challenge"
    )
    for ordinary in (
        b"<title>Just a moment...</title><article>Ordinary story</article>",
        b"<title>Cloudflare news</title>"
        b"<script src='/cdn-cgi/challenge-platform/asset'></script>",
        b"<article>Reporting about Cloudflare and Just a moment...</article>",
    ):
        assert not provider.is_interactive_challenge(_fetch(ordinary))


@pytest.mark.parametrize("sitemap", [False, True])
def test_ap_browser_fallback_preserves_cleared_article_and_xml(tmp_path, sitemap):
    from patchright.sync_api import sync_playwright

    from newsclip.browser_retrieval import PatchrightBrowserRetriever
    from newsclip.browser_runtime import LeaseManager, PatchrightMintContext
    from newsclip.challenge_resolver import ChallengeResolver
    from newsclip.challenge_transport import ChallengeAwareHttpClient
    from newsclip.challenges import ChallengeMode, ChallengeVendor
    from newsclip.cloudflare_interstitial import CloudflareInterstitialMechanic
    from newsclip.provider_config import BrowserRetrievalSpec

    url = ENDPOINT if sitemap else ARTICLE_URL
    payload = (
        (
            f'<urlset xmlns="{SITEMAP_NS}"><url><loc>{ARTICLE_URL}</loc></url></urlset>'
        ).encode()
        if sitemap
        else _article_html()
    )
    challenge = b"""<title>Just a moment...</title><script>
      // /cdn-cgi/challenge-platform/fixture-only
      setTimeout(() => location.reload(), 250);
    </script>"""
    primary_calls = []
    navigations = []
    observed = []
    provider = ApProvider()

    class Resolver(ChallengeResolver):
        def resolve(self, browser, mode):
            return super().resolve(
                PatchrightMintContext(browser.page.context, browser.page), mode
            )

    class Primary:
        def get(self, requested, **kwargs):
            assert kwargs.get("session") is None
            primary_calls.append(requested)
            return _fetch(challenge, status=403).model_copy(
                update={"requested_url": url, "final_url": url}
            )

    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)

        def factory(**kwargs):
            context = chromium.new_context()

            def route_request(route):
                assert route.request.url == url
                navigations.append(url)
                first = len(navigations) == 1
                route.fulfill(
                    status=403 if first else 200,
                    content_type="text/html"
                    if first or not sitemap
                    else "application/xml",
                    body=challenge if first else payload,
                )

            context.route("**/*", route_request)
            return context

        mechanic = CloudflareInterstitialMechanic(wall_budget_seconds=3)
        retriever = PatchrightBrowserRetriever(
            challenge_mode=ChallengeMode.AUTO,
            context_factory=factory,
            profile_resolver=lambda *_: tmp_path / "profile",
            lease_manager=LeaseManager(tmp_path / "leases"),
            policies={
                "ap": BrowserRetrievalSpec(
                    article_settle_seconds=0, network_idle_timeout_seconds=0
                )
            },
            challenge_resolvers={
                "ap": Resolver({ChallengeVendor.CLOUDFLARE_INTERSTITIAL: mechanic})
            },
        )
        try:
            client = ChallengeAwareHttpClient(
                "ap",
                Primary(),
                is_challenge=provider.is_interactive_challenge,
                browser_fallback=retriever.for_provider("ap"),
                on_challenge_observed=lambda fetch: observed.append(fetch.http_status),
            )
            fetched = client.get(url)
            assert fetched.http_status == 200
            assert not fetched.session_cookie_present
            assert primary_calls == [url]
            assert navigations == [url, url]  # one navigation and one native reload
            # The browser recovered: the challenge is a timing fact, not an incident.
            assert observed == []
            if sitemap:
                assert fetched.raw_html == payload
                assert fetched.content_type == "application/xml"
            else:
                assert provider.assess(
                    url, fetched, TrafilaturaExtractor().extract(fetched)
                ).promotable
        finally:
            retriever.close()
            chromium.close()


def _article_html(*, canonical: str = ARTICLE_URL, body: bool = True) -> bytes:
    story = (
        '<div class="RichTextStoryBody RichTextBody"><p>'
        + "Verified AP reporting provides substantive fixture evidence. " * 30
        + "</p></div>"
        if body
        else "<p>AP hub page without a story body.</p>"
    )
    return f"""
    <html><head>
      <title>Judge rules against interfaith group | AP News</title>
      <link rel="canonical" href="{canonical}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Judge rules against interfaith group",
          "datePublished":"2026-07-27T21:43:39Z"}}
      </script>
    </head><body><main class="Page-main">{story}</main></body></html>
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


def _entry(url: str, title: str, published: datetime | None) -> str:
    news_title = f"<news:title>{title}</news:title>" if title else ""
    news_published = (
        f"<news:publication_date>{published.isoformat()}</news:publication_date>"
        if published
        else ""
    )
    return (
        f"<url><loc>{url}</loc><news:news>{news_title}{news_published}"
        "</news:news></url>"
    )


def _sitemap(entries: list[str]) -> bytes:
    return (
        f'<urlset xmlns="{SITEMAP_NS}" xmlns:news="{NEWS_NS}">'
        + "".join(entries)
        + "</urlset>"
    ).encode()


def _default_entries() -> list[str]:
    return [
        _entry(
            ARTICLE_URL,
            "Judge rules against interfaith group in lawsuit",
            NOW - timedelta(minutes=30),
        ),
        _entry(
            SECOND_URL,
            "Grid warning continues into a second day",
            NOW - timedelta(hours=30),
        ),
        _entry(
            "https://apnews.com/projects/days-disrupted-after-iran-war/",
            "Days disrupted after Iran war",
            NOW - timedelta(minutes=5),
        ),
        _entry(
            "https://apnews.com/hub/donald-trump",
            "Donald Trump hub",
            NOW - timedelta(minutes=6),
        ),
    ]


class SitemapHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []
        self.final_url: str | None = None
        self.content_type = "text/xml;charset=UTF-8"
        self.body: bytes | None = None
        self.status = 200

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
        body = self.body if self.body is not None else _sitemap(_default_entries())
        return RawFetch(
            requested_url=url,
            final_url=self.final_url or url,
            http_status=self.status,
            content_type=self.content_type,
            retrieved_at=NOW,
            raw_html=body,
        )


def test_article_identity_is_strict_and_canonical() -> None:
    assert normalize_article_url(ARTICLE_URL + "?utm_source=fixture") == ARTICLE_URL
    assert (
        normalize_article_url(ARTICLE_URL.replace("apnews.com", "www.apnews.com"))
        == ARTICLE_URL
    )
    assert article_id(ARTICLE_URL) == ARTICLE_ID

    rejected = [
        "https://apnews.com/projects/days-disrupted-after-iran-war/",
        "https://apnews.com/hub/donald-trump",
        # 31-hex suffix is not an article id.
        "https://apnews.com/article/short-id-" + "a" * 31,
        "https://apnews.com/video/story-" + "c" * 32,
    ]
    for url in rejected:
        assert normalize_article_url(url) is None


def test_search_is_anonymous_ranked_and_drops_zero_overlap() -> None:
    http = SitemapHttp()
    results = ApProvider().search(
        http,
        None,
        "interfaith lawsuit judge",
        SearchFilters(),
    )

    assert http.urls == [ENDPOINT]
    assert http.sessions == [None]
    assert [str(result.url) for result in results] == [ARTICLE_URL]
    assert results[0].headline == "Judge rules against interfaith group in lawsuit"
    assert results[0].published == NOW - timedelta(minutes=30)


def test_search_ranks_higher_overlap_before_recency() -> None:
    http = SitemapHttp()
    results = ApProvider().search(http, None, "grid warning", SearchFilters())

    # SECOND_URL matches both tokens and outranks any fresher single-token hit.
    assert [str(result.url) for result in results] == [SECOND_URL]


def test_search_date_filter_and_stop_words_fail_closed() -> None:
    results = ApProvider().search(
        SitemapHttp(),
        None,
        "grid warning",
        SearchFilters(published_after=NOW - timedelta(hours=1)),
    )
    assert results == []

    with pytest.raises(UnsearchableQueryError, match="unsearchable_query"):
        ApProvider().search(SitemapHttp(), None, "of the and", SearchFilters())


def test_search_discloses_the_window_it_could_actually_reach() -> None:
    """AP's sitemap is a moving window too, so it must state its trailing edge.

    A live sample spanned 47 hours across 445 entries, so a story from three
    days ago is simply unreachable — a fact a bare result count cannot convey.
    Only owned entries count: the old hub URL below is not an article, so
    claiming its date as coverage would overstate the reach search really had.
    """

    http = SitemapHttp()
    http.body = _sitemap(
        [
            *_default_entries(),
            _entry(
                "https://apnews.com/hub/ancient-hub",
                "Ancient hub page that is not an article",
                NOW - timedelta(days=9),
            ),
        ]
    )

    page = ApProvider().search_page(http, None, "grid warning", SearchFilters())

    assert page.coverage_start == NOW - timedelta(hours=30)
    assert page.results
    assert page.coverage_start <= min(
        result.published for result in page.results if result.published
    )


def test_search_page_exposes_no_continuation() -> None:
    page = ApProvider().search_page(
        SitemapHttp(),
        None,
        "interfaith lawsuit",
        SearchFilters(),
    )
    assert page.next_url is None
    assert [str(result.url) for result in page.results] == [ARTICLE_URL]

    with pytest.raises(ProviderContractError, match="continuation"):
        ApProvider().search_page(
            SitemapHttp(),
            None,
            "interfaith lawsuit",
            SearchFilters(),
            next_url=ENDPOINT,
        )


def test_sitemap_entry_schema_is_strict() -> None:
    missing_title = SitemapHttp()
    missing_title.body = _sitemap([_entry(ARTICLE_URL, "", NOW - timedelta(minutes=1))])
    with pytest.raises(ProviderContractError, match="entry schema"):
        ApProvider().search(missing_title, None, "judge", SearchFilters())

    missing_published = SitemapHttp()
    missing_published.body = _sitemap([_entry(ARTICLE_URL, "Judge rules", None)])
    with pytest.raises(ProviderContractError, match="entry schema"):
        ApProvider().search(missing_published, None, "judge", SearchFilters())

    wrong_root = SitemapHttp()
    wrong_root.body = b"<changed/>"
    with pytest.raises(ProviderContractError, match="root schema"):
        ApProvider().search(wrong_root, None, "judge", SearchFilters())


def test_sitemap_transport_failures_are_typed() -> None:
    non_xml = SitemapHttp()
    non_xml.content_type = "text/html; charset=utf-8"
    with pytest.raises(ProviderTransportError, match="non-XML"):
        ApProvider().search(non_xml, None, "judge", SearchFilters())

    oversize = SitemapHttp()
    oversize.body = b"<urlset>" + b" " * 2_000_001
    with pytest.raises(ProviderTransportError, match="size limit"):
        ApProvider().search(oversize, None, "judge", SearchFilters())

    unavailable = SitemapHttp()
    unavailable.status = 503
    with pytest.raises(ProviderTransportError, match="HTTP 503"):
        ApProvider().search(unavailable, None, "judge", SearchFilters())

    malformed = SitemapHttp()
    malformed.body = b"<urlset"
    with pytest.raises(ProviderTransportError, match="malformed XML"):
        ApProvider().search(malformed, None, "judge", SearchFilters())


def test_sitemap_redirect_identity_mismatch_fails_closed() -> None:
    redirected = SitemapHttp()
    redirected.final_url = "https://apnews.com/sitemap.xml"
    with pytest.raises(ProviderContractError, match="identity"):
        ApProvider().search(redirected, None, "judge", SearchFilters())

    with_query = SitemapHttp()
    with_query.final_url = ENDPOINT + "?page=2"
    with pytest.raises(ProviderContractError, match="identity"):
        ApProvider().search(with_query, None, "judge", SearchFilters())


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (_article_html(), AccessState.FULL),
        (_article_html(canonical=SECOND_URL), AccessState.UNKNOWN),
        (_article_html(body=False), AccessState.UNKNOWN),
    ],
)
def test_assessment_closes_on_story_body_without_article_element(
    body: bytes,
    expected: AccessState,
) -> None:
    fetch = _fetch(body)
    assessment = ApProvider().assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)
