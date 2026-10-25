"""Synthetic Axios contracts: public identity, complete prose and recent discovery."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape

import pytest

from newsclip.archive import ArchiveStore
from newsclip.errors import (
    ContentNotFullError,
    ProviderContractError,
    ProviderTransportError,
    UnsearchableQueryError,
)
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters
from newsclip.providers import ProviderRegistry
from newsclip.providers.axios import AxiosProvider
from newsclip.providers.base import ProviderNativeExtractionState
from newsclip.service import NewsclipService

NOW = datetime(2026, 9, 7, 12, tzinfo=UTC)
URL = "https://www.axios.com/2026/09/06/energy-prices-fall"
LOCAL = "https://www.axios.com/local/cleveland/2026/09/07/road-safety-study"
ENDPOINT = "https://www.axios.com/sitemaps/news.xml"
INTRO = "Energy prices fell after officials published the new national supply report."


def article_html(
    *,
    url=URL,
    paywalled=False,
    gate="",
    truncate=False,
    duplicate=False,
    intro=INTRO,
    intro_html=None,
):
    bullet = (
        "Independent researchers reviewed the evidence "
        "and published their detailed findings."
    )
    nested = "The final survey includes households from every participating region."
    end = "What comes next: The next public report is expected on Friday."
    story = {
        "permalink": url,
        "is_paywalled": paywalled,
        "blocks": {
            "blocks": [
                {"type": "unstyled", "text": intro},
                {"type": "unordered-list-item", "text": bullet},
                {"type": "unordered-list-item", "text": nested},
                {"type": "unstyled", "text": end},
            ]
        },
    }
    ending = (
        "<p><strong>What comes next:</strong> "
        "The next public report is expected on Friday.</p>"
    )
    rendered_intro = intro if intro_html is None else intro_html
    body = f"""<div data-cy="story-body"><div>
      <p>{rendered_intro}</p><div id="piano-wall">{gate}</div>
      <span class="gated-content" data-cy="story-go-deeper-content">
      <ul><li><a href="https://example.org/report">{bullet}</a>
        <ul><li>{nested}</li></ul></li></ul>
      {"" if truncate else ending}
      </span></div></div>"""
    return f'''<html><head><title>Energy prices fall</title>
      <link rel="canonical" href="{url}">
      <script type="application/ld+json">{
        json.dumps(
            {
                "@type": "NewsArticle",
                "headline": "Energy prices fall",
                "datePublished": "2026-09-06T12:00:00Z",
                "isAccessibleForFree": False,
                "url": url,
                "author": {"@type": "Person", "name": "Fixture Reporter"},
            }
        )
    }</script>
      <script id="__NEXT_DATA__" type="application/json">{
        json.dumps(
            {
                "props": {"pageProps": {"data": {"story": story}}},
            }
        )
    }</script></head><body><main>{body}{body if duplicate else ""}</main>
      <aside><p>UNRELATED RAIL MUST NEVER ENTER THE ARCHIVE.</p></aside>
      </body></html>'''.encode()


def fetch(body=None, *, url=URL, status=200, content_type="text/html"):
    return RawFetch(
        requested_url=url,
        final_url=url,
        http_status=status,
        content_type=content_type,
        retrieved_at=NOW,
        raw_html=body if body is not None else article_html(url=url),
    )


class Http:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, session=None, timeout=40):
        assert session is None
        self.calls.append(url)
        return self.response


@pytest.mark.parametrize("url", [URL, LOCAL])
def test_identity_normalizes_public_national_and_local(url):
    provider = AxiosProvider()
    assert provider.normalize_url(url + "?utm_source=test#section") == url
    assert provider.normalize_url(url.replace("www.axios.com", "axios.com")) == url
    assert provider.article_id(url) == url.removeprefix("https://www.axios.com/")
    assert provider.login_recipe is None


@pytest.mark.parametrize(
    "url",
    [
        "https://www.axios.com/",
        "https://www.axios.com/results?q=energy",
        "https://www.axios.com/pro/deals/2026/09/06/story",
        "https://www.axios.com/newsletters/fixture",
        "https://www.axios.com/local/cleveland",
        "https://www.axios.com.evil.test/2026/09/06/story",
        "https://user@www.axios.com/2026/09/06/story",
        "https://www.axios.com:444/2026/09/06/story",
    ],
)
def test_non_article_urls_are_not_owned(url):
    assert AxiosProvider().normalize_url(url) is None


def test_short_full_article_preserves_links_nested_bullets_and_ending():
    native = AxiosProvider().native_extraction(URL, fetch())
    assert native.state is ProviderNativeExtractionState.VALID
    assert native.assessment.promotable
    assert native.extraction.word_count < 100
    body = native.extraction.body_markdown
    assert "- [Independent researchers" in body
    assert "](https://example.org/report)" in body
    assert "\n  - The final survey" in body
    assert "**What comes next:**" in body
    assert body.endswith("expected on Friday.")
    assert "UNRELATED" not in body


@pytest.mark.parametrize(
    "tag,marker",
    [("strong", "**"), ("b", "**"), ("em", "*"), ("i", "*")],
)
def test_inline_emphasis_preserves_semantic_edge_whitespace(tag, marker):
    separator = INTRO.replace("national supply", f"national<{tag}> </{tag}>supply")
    separated = AxiosProvider().native_extraction(
        URL, fetch(article_html(intro_html=separator))
    )
    assert separated.state is ProviderNativeExtractionState.VALID
    assert "national supply" in separated.extraction.body_markdown

    emphasized = INTRO.replace(
        "new national supply", f"new<{tag}> national </{tag}>supply"
    )
    rendered = AxiosProvider().native_extraction(
        URL, fetch(article_html(intro_html=emphasized))
    )
    assert rendered.state is ProviderNativeExtractionState.VALID
    assert f"new {marker}national{marker} supply" in rendered.extraction.body_markdown


@pytest.mark.parametrize("tag", ["strong", "b", "em", "i"])
def test_empty_inline_emphasis_does_not_invent_whitespace(tag):
    joined = INTRO.replace("national supply", "nationalsupply")
    empty = INTRO.replace("national supply", f"national<{tag}></{tag}>supply")
    native = AxiosProvider().native_extraction(
        URL, fetch(article_html(intro=joined, intro_html=empty))
    )
    assert native.state is ProviderNativeExtractionState.VALID
    assert "nationalsupply" in native.extraction.body_markdown
    assert "national supply" not in native.extraction.body_markdown


def test_native_identity_versions_axios_rendering_and_assessment():
    provider = AxiosProvider()
    native = provider.native_extraction(URL, fetch())
    assert native.extractor_name == "axios-dom"
    assert native.extractor_version.startswith("2+")
    assert provider.assessment_policy_version.endswith("-axios-public-v2")


@pytest.mark.parametrize(
    "gate",
    [
        '<div id="piano-container" data-piano-active="true"></div>',
        '<div id="piano-container"><iframe src="https://example.org/gate"></iframe></div>',
        '<div id="paywall-fallback-container">Sign up to continue reading</div>',
        '<div id="piano-spinner"></div>',
    ],
)
def test_gate_beats_complete_hidden_body_and_public_payload(gate):
    raw = fetch(article_html(gate=gate))
    provider = AxiosProvider()
    result = provider.assess(URL, raw, TrafilaturaExtractor().extract(raw))
    assert result.access_state is AccessState.TEASER
    assert (
        provider.native_extraction(URL, raw).state
        is ProviderNativeExtractionState.ABSENT
    )


def test_empty_piano_mount_is_not_a_gate():
    raw = fetch(article_html(gate='<div id="piano-container"></div>'))
    assert AxiosProvider().native_extraction(URL, raw).assessment.promotable


def test_relative_links_remain_links():
    raw = fetch(
        article_html().replace(b"https://example.org/report", b"/2026/09/05/report")
    )
    native = AxiosProvider().native_extraction(URL, raw)
    assert (
        "](https://www.axios.com/2026/09/05/report)" in native.extraction.body_markdown
    )


@pytest.mark.parametrize("paywalled", [True, None, "false"])
def test_public_story_requires_explicit_false(paywalled):
    raw = fetch(article_html(paywalled=paywalled))
    assert (
        not AxiosProvider()
        .assess(URL, raw, TrafilaturaExtractor().extract(raw))
        .promotable
    )


@pytest.mark.parametrize("mutation", ["final", "canonical", "payload", "json", "body"])
def test_identity_and_evidence_fail_closed(mutation):
    body = article_html()
    if mutation == "canonical":
        body = body.replace(f'href="{URL}"'.encode(), f'href="{LOCAL}"'.encode())
    elif mutation == "payload":
        body = body.replace(
            f'"permalink": "{URL}"'.encode(), f'"permalink": "{LOCAL}"'.encode()
        )
    elif mutation == "json":
        body = body.replace(b'"is_paywalled": false', b'"is_paywalled": broken')
    elif mutation == "body":
        body = body.replace(b'data-cy="story-body"', b'data-cy="hub"')
    raw = fetch(body)
    if mutation == "final":
        raw = raw.model_copy(update={"final_url": LOCAL})
    assert (
        AxiosProvider().native_extraction(URL, raw).state
        is not ProviderNativeExtractionState.VALID
    )


@pytest.mark.parametrize("options", [{"truncate": True}, {"duplicate": True}])
def test_payload_cannot_rescue_truncated_or_ambiguous_dom(options):
    native = AxiosProvider().native_extraction(URL, fetch(article_html(**options)))
    assert native.state is not ProviderNativeExtractionState.VALID


def test_cloudflare_needs_the_observed_combination():
    provider = AxiosProvider()
    challenge = (
        b"<title>Just a moment...</title>"
        b"<script src='/cdn-cgi/challenge-platform/test'></script>"
    )
    raw = fetch(challenge, status=403)
    assert provider.is_interactive_challenge(raw)
    assert (
        provider.assess(URL, raw, TrafilaturaExtractor().extract(raw)).access_state
        is AccessState.BLOCKED
    )
    assert not provider.is_interactive_challenge(
        fetch(b"<title>Just a moment...</title>")
    )
    assert not provider.is_interactive_challenge(
        fetch(b"<p>A report about Cloudflare</p>")
    )


def sitemap(entries=None):
    entries = (
        entries
        if entries is not None
        else [
            (URL, "Energy prices fall", "2026-09-06T12:00:00Z"),
            (LOCAL, "Researchers study road safety", "2026-09-07T10:00:00Z"),
            (URL + "?utm_source=copy", "Energy prices fall", "2026-09-07T11:00:00Z"),
            (
                "https://www.axios.com/pro/deals",
                "Energy prices",
                "2020-01-01T12:00:00Z",
            ),
        ]
    )
    body = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">'
    for url, title, published in entries:
        body += (
            f"<url><loc>{escape(url)}</loc><news:news>"
            f"<news:title>{escape(title)}</news:title>"
            f"<news:publication_date>{published}</news:publication_date>"
            "</news:news></url>"
        )
    return (body + "</urlset>").encode()


def test_sitemap_search_is_recent_anonymous_deduplicated_and_ranked():
    http = Http(fetch(sitemap(), url=ENDPOINT, content_type="application/xml"))
    provider = AxiosProvider()
    page = provider.search_page(http, None, "energy prices study", SearchFilters())
    assert [str(r.url) for r in page.results] == [URL, LOCAL]
    assert page.coverage_start == datetime(2026, 9, 6, 12, tzinfo=UTC)
    assert http.calls == [ENDPOINT]
    assert (
        str(provider.search(http, None, "cleveland", SearchFilters())[0].url) == LOCAL
    )
    assert not provider.search(http, None, "2026 09 local", SearchFilters())
    assert not provider.search(http, None, "unrelated", SearchFilters())
    assert not provider.search(
        http,
        None,
        "energy",
        SearchFilters(published_after=datetime(2026, 9, 7, tzinfo=UTC)),
    )
    assert len(provider.search(http, None, "energy study", SearchFilters(limit=1))) == 1


def test_stopword_only_query_rejects_before_network():
    http = Http(None)
    with pytest.raises(UnsearchableQueryError):
        AxiosProvider().search(http, None, "the and of", SearchFilters())
    assert not http.calls


def test_canary_query_survives_its_pinned_article_aging_out():
    # A healthy current feed need not discuss the pinned gas-price story.
    raw = fetch(
        sitemap([(LOCAL, "Congress approves city spending", NOW.isoformat())]),
        url=ENDPOINT,
        content_type="application/xml",
    )
    provider = AxiosProvider()
    assert provider.search(Http(raw), None, provider.check.query, SearchFilters())


def test_canary_checks_full_article_when_healthy_feed_has_no_query_matches():
    provider = AxiosProvider()
    article_url = str(provider.check.canonical_url)

    class CanaryHttp:
        def __init__(self):
            self.calls = []

        def get(self, url, *, session=None, timeout=40):
            assert session is None
            self.calls.append(url)
            if url == ENDPOINT:
                return fetch(
                    sitemap(
                        [(LOCAL, "Researchers study road safety", NOW.isoformat())]
                    ),
                    url=ENDPOINT,
                    content_type="application/xml",
                )
            assert url == article_url
            return fetch(article_html(url=article_url), url=article_url)

    http = CanaryHttp()
    service = NewsclipService(
        ProviderRegistry([provider]),
        http,
        TrafilaturaExtractor(),
        network_sleep=lambda _: None,
    )
    try:
        result = service.provider_check("axios")
        assert result.ok
        assert result.search_result_count == 0
        assert http.calls == [ENDPOINT, article_url]
    finally:
        service.close()


@pytest.mark.parametrize(
    "body,kind",
    [
        (b"<broken", ProviderTransportError),
        (b"<urlset/>", ProviderContractError),
        (sitemap([(URL, "", "2026-09-06T12:00:00Z")]), ProviderContractError),
        (sitemap([(URL, "headline", "not-a-date")]), ProviderContractError),
        (b" " * 2_000_001, ProviderTransportError),
    ],
)
def test_sitemap_invalid_payload_fails_closed(body, kind):
    with pytest.raises(kind):
        AxiosProvider().search(
            Http(fetch(body, url=ENDPOINT, content_type="application/xml")),
            None,
            "energy",
            SearchFilters(),
        )


@pytest.mark.parametrize(
    "update,kind",
    [
        ({"final_url": "https://www.axios.com/sitemap.xml"}, ProviderContractError),
        ({"requested_url": "https://example.org/"}, ProviderContractError),
        ({"http_status": 503}, ProviderTransportError),
        ({"content_type": "text/html"}, ProviderTransportError),
    ],
)
def test_sitemap_response_contract(update, kind):
    raw = fetch(sitemap(), url=ENDPOINT, content_type="application/xml").model_copy(
        update=update
    )
    with pytest.raises(kind):
        AxiosProvider().search(Http(raw), None, "energy", SearchFilters())


def test_service_archive_export_reextract_and_rejection(tmp_path):
    provider = AxiosProvider()
    registry = ProviderRegistry([provider])
    extractor = TrafilaturaExtractor()
    archive = ArchiveStore(
        tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
    )
    http = Http(fetch())
    service = NewsclipService(
        registry, http, extractor, archive=archive, network_sleep=lambda _: None
    )
    try:
        output = tmp_path / "article.md"
        article = service.save(URL, out=output)
        assert article.body_markdown in output.read_text()
        assert article.provider == "axios"
        assert service.archive_get(article.id).body_markdown == article.body_markdown
        assert service.reextract(article.id).body_markdown == article.body_markdown
        http.response = fetch(article_html(truncate=True))
        with pytest.raises(ContentNotFullError):
            service.save(URL)
        assert service.archive_get(article.id).body_markdown == article.body_markdown
    finally:
        service.close()
