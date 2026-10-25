"""Offline contracts for the Guardian Open Platform provider."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from lxml import html

from newsclip.errors import ProviderContractError, ProviderTransportError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters, SessionArtifact
from newsclip.providers.guardian import (
    GuardianProvider,
    article_id,
    normalize_article_url,
)

NOW = datetime(2026, 7, 28, 2, tzinfo=UTC)
CONTENT_ID = "business/2026/jun/11/ecb-eurozone-interest-rates-iran-war-inflation"
ARTICLE_URL = f"https://www.theguardian.com/{CONTENT_ID}"
SEARCH_ENDPOINT = "https://content.guardianapis.com/search"
ITEM_URL_PREFIX = f"https://content.guardianapis.com/{CONTENT_ID}"
KEY_SENTINEL = "API_KEY_SENTINEL"
BODY_HTML = (
    "<p>The European Central Bank raised eurozone borrowing costs on Thursday, "
    "citing the Iran war's pressure on energy prices. "
    + "Substantive licensed reporting continues at article length. " * 25
    + 'It quoted a source saying "</script>" in passing prose.</p>'
)


def _item_payload(
    *,
    status: str = "ok",
    content_id: str = CONTENT_ID,
    web_url: str = ARTICLE_URL,
    body: str | None = BODY_HTML,
) -> dict:
    fields: dict = {
        "headline": "ECB raises eurozone interest rates as Iran war stokes inflation",
        "byline": "Phillip Inman",
        "firstPublicationDate": "2026-06-11T12:18:30Z",
    }
    if body is not None:
        fields["body"] = body
    return {
        "response": {
            "status": status,
            "content": {
                "id": content_id,
                "webUrl": web_url,
                "webTitle": (
                    "ECB raises eurozone interest rates as Iran war stokes inflation"
                ),
                "webPublicationDate": "2026-06-11T12:18:30Z",
                "fields": fields,
            },
        }
    }


def _search_payload() -> dict:
    return {
        "response": {
            "status": "ok",
            "results": [
                {
                    "webUrl": ARTICLE_URL,
                    "webTitle": "ECB raises eurozone interest rates",
                    "webPublicationDate": "2026-06-11T12:18:30Z",
                },
                {
                    "webUrl": (
                        "https://www.theguardian.com/business/2025/oct/30/"
                        "ecb-interest-rates-eurozone-inflation"
                    ),
                    "webTitle": "ECB holds rates",
                    "webPublicationDate": "2025-10-30T13:17:09Z",
                },
                {
                    # Unowned path shapes are dropped, not promoted.
                    "webUrl": "https://www.theguardian.com/business/ng-interactive",
                    "webTitle": "Interactive",
                    "webPublicationDate": "2026-06-01T00:00:00Z",
                },
            ],
        }
    }


class ApiHttp:
    """Fake transport returning canned Guardian API JSON."""

    def __init__(self, payload: dict | None = None) -> None:
        self.payload = payload
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []
        self.status = 200
        self.content_type = "application/json; charset=utf-8"
        self.final_url: str | None = None

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
        payload = self.payload
        if payload is None:
            payload = _search_payload() if "/search?" in url else _item_payload()
        return RawFetch(
            requested_url=url,
            final_url=self.final_url or url,
            http_status=self.status,
            content_type=self.content_type,
            retrieved_at=NOW,
            raw_html=json.dumps(payload).encode("utf-8"),
        )


def test_article_identity_accepts_alphabetic_months_only() -> None:
    assert normalize_article_url(ARTICLE_URL + "?utm_source=fixture") == ARTICLE_URL
    assert (
        normalize_article_url(
            ARTICLE_URL.replace("www.theguardian.com", "theguardian.com")
        )
        == ARTICLE_URL
    )
    # The content id is the path minus its leading slash, round-tripping §2.1.
    assert article_id(ARTICLE_URL) == CONTENT_ID

    rejected = [
        # Numeric month segments never occur on Guardian article paths.
        "https://www.theguardian.com/business/2026/06/11/ecb-eurozone-rates",
        "https://www.theguardian.com/business",
        "https://www.theguardian.com/",
    ]
    for url in rejected:
        assert normalize_article_url(url) is None


def test_search_maps_api_results_and_honours_filters() -> None:
    http = ApiHttp()
    results = GuardianProvider().search(http, None, "ECB rates", SearchFilters())

    assert http.sessions == [None]
    assert len(http.urls) == 1
    assert http.urls[0].startswith(f"{SEARCH_ENDPOINT}?")
    assert KEY_SENTINEL not in http.urls[0]
    assert [str(result.url) for result in results] == [
        ARTICLE_URL,
        "https://www.theguardian.com/business/2025/oct/30/"
        "ecb-interest-rates-eurozone-inflation",
    ]
    assert results[0].headline == "ECB raises eurozone interest rates"
    assert results[0].published == datetime(2026, 6, 11, 12, 18, 30, tzinfo=UTC)

    bounded = GuardianProvider().search(
        ApiHttp(),
        None,
        "ECB rates",
        SearchFilters(published_after=datetime(2026, 1, 1, tzinfo=UTC)),
    )
    assert [str(result.url) for result in bounded] == [ARTICLE_URL]


def test_search_fails_closed_on_schema_and_transport_drift() -> None:
    not_ok = ApiHttp({"response": {"status": "error", "results": []}})
    with pytest.raises(ProviderContractError, match="schema"):
        GuardianProvider().search(not_ok, None, "ECB", SearchFilters())

    non_json = ApiHttp()
    non_json.content_type = "text/html"
    with pytest.raises(ProviderTransportError, match="non-JSON"):
        GuardianProvider().search(non_json, None, "ECB", SearchFilters())

    unavailable = ApiHttp()
    unavailable.status = 503
    with pytest.raises(ProviderTransportError, match="HTTP 503"):
        GuardianProvider().search(unavailable, None, "ECB", SearchFilters())

    redirected = ApiHttp()
    redirected.final_url = "https://content.guardianapis.com/search?q=other"
    with pytest.raises(ProviderContractError, match="identity"):
        GuardianProvider().search(redirected, None, "ECB", SearchFilters())

    with pytest.raises(ProviderContractError, match="continuation"):
        GuardianProvider().search_page(
            ApiHttp(),
            None,
            "ECB",
            SearchFilters(),
            next_url=SEARCH_ENDPOINT,
        )


def test_fetch_composes_a_full_assessable_document() -> None:
    http = ApiHttp()
    provider = GuardianProvider()
    fetch = provider.fetch(http, None, ARTICLE_URL)

    # The API call carries the content id; the key travels in a header the
    # provider never sees, so no URL anywhere may contain it.
    assert http.urls[0].startswith(f"{ITEM_URL_PREFIX}?")
    assert all(KEY_SENTINEL not in url for url in http.urls)
    assert str(fetch.requested_url) == ARTICLE_URL
    assert str(fetch.final_url) == ARTICLE_URL
    assert KEY_SENTINEL not in str(fetch.requested_url)
    assert KEY_SENTINEL not in str(fetch.final_url)
    assert KEY_SENTINEL not in fetch.raw_html.decode("utf-8")

    assessment = provider.assess(
        ARTICLE_URL,
        fetch,
        TrafilaturaExtractor().extract(fetch),
    )
    assert assessment.access_state is AccessState.FULL
    assert assessment.promotable is True
    assert str(assessment.canonical_url) == ARTICLE_URL


def test_fetch_embeds_the_raw_payload_without_script_breakout() -> None:
    fetch = GuardianProvider().fetch(ApiHttp(), None, ARTICLE_URL)
    document_text = fetch.raw_html.decode("utf-8")
    document = html.fromstring(document_text)

    payload_nodes = document.xpath("//script[@id='guardian-api-payload']")
    assert len(payload_nodes) == 1
    embedded = payload_nodes[0].text
    # The payload rides along verbatim except for the deterministic "<"
    # escaping that keeps quoted "</script>" prose inside the element (§8.5).
    raw = json.dumps(_item_payload())
    assert embedded == raw.replace("<", "&lt;")
    assert "</script>" in raw  # the fixture body genuinely carries the hazard
    # The article body itself is publisher HTML inside one <article> element.
    articles = document.xpath("//article")
    assert len(articles) == 1
    assert "European Central Bank" in articles[0].text_content()


def test_fetch_fails_closed_on_api_drift() -> None:
    provider = GuardianProvider()

    not_ok = ApiHttp(_item_payload(status="error"))
    with pytest.raises(ProviderContractError, match="schema"):
        provider.fetch(not_ok, None, ARTICLE_URL)

    wrong_id = ApiHttp(_item_payload(content_id="world/2026/jun/11/other-story"))
    with pytest.raises(ProviderContractError, match="identity mismatch"):
        provider.fetch(wrong_id, None, ARTICLE_URL)

    wrong_web_url = ApiHttp(
        _item_payload(web_url="https://www.theguardian.com/world/2026/jun/11/other")
    )
    with pytest.raises(ProviderContractError, match="identity mismatch"):
        provider.fetch(wrong_web_url, None, ARTICLE_URL)

    missing_body = ApiHttp(_item_payload(body=None))
    with pytest.raises(ProviderContractError, match="article body"):
        provider.fetch(missing_body, None, ARTICLE_URL)

    with pytest.raises(ValueError, match="owned article URL"):
        provider.fetch(ApiHttp(), None, "https://www.theguardian.com/business")


def test_search_page_counts_undated_results_withheld_by_date_bound() -> None:
    payload = _search_payload()
    payload["response"]["results"][1]["webPublicationDate"] = None
    bounded = GuardianProvider().search_page(
        ApiHttp(payload),
        None,
        "ECB rates",
        SearchFilters(published_after=datetime(2020, 1, 1, tzinfo=UTC)),
    )
    unbounded = GuardianProvider().search_page(
        ApiHttp(payload), None, "ECB rates", SearchFilters()
    )

    assert [str(result.url) for result in bounded.results] == [ARTICLE_URL]
    assert bounded.undated_excluded_count == 1
    assert len(unbounded.results) == 2
    assert unbounded.undated_excluded_count == 0
