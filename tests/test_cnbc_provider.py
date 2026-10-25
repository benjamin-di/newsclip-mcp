"""Offline contracts for CNBC's public search and article path."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from newsclip.errors import ProviderContractError, ProviderTransportError
from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import AccessState, RawFetch, SearchFilters, SessionArtifact
from newsclip.provider_config import load_provider_spec
from newsclip.providers.cnbc import CNBCProvider, article_id, normalize_article_url

NOW = datetime(2026, 7, 21, tzinfo=UTC)
ARTICLE_URL = (
    "https://www.cnbc.com/2026/07/20/jpmorgan-chase-ceo-jamie-dimon-market-risk.html"
)
SECOND_URL = "https://www.cnbc.com/2026/07/19/second-fixture-story.html"


def _article_html(*, canonical: str = ARTICLE_URL, body: bool = True) -> bytes:
    article = (
        "<div class='ArticleBody-articleBody'><p>"
        + "Verified CNBC reporting provides substantive fixture evidence. " * 30
        + "</p></div>"
        if body
        else "<main>Market landing page without an article body.</main>"
    )
    return f"""
    <html><head>
      <title>Fixture CNBC report</title>
      <link rel="canonical" href="{canonical}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Fixture CNBC report","datePublished":"2026-07-20T23:01:01Z"}}
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
    assert normalize_article_url(ARTICLE_URL + "?utm_source=fixture") == ARTICLE_URL
    assert (
        normalize_article_url(ARTICLE_URL.replace("www.cnbc.com", "cnbc.com"))
        == ARTICLE_URL
    )
    assert (
        normalize_article_url("https://www.cnbc.com/video/2026/07/20/test.html") is None
    )
    assert normalize_article_url("http://www.cnbc.com/2026/07/20/test.html") is None
    assert article_id(ARTICLE_URL) == (
        "2026/07/20/jpmorgan-chase-ceo-jamie-dimon-market-risk.html"
    )


@pytest.mark.parametrize(
    ("body", "status", "expected"),
    [
        (_article_html(), 200, AccessState.FULL),
        (_article_html(canonical=SECOND_URL), 200, AccessState.UNKNOWN),
        (_article_html(body=False), 200, AccessState.UNKNOWN),
        (
            b"<html><body><div data-test='ArticleGate'>Subscribe</div></body></html>",
            200,
            AccessState.TEASER,
        ),
        (
            b"<html><title>Access Denied</title><body>Reference #1</body></html>",
            200,
            AccessState.BLOCKED,
        ),
    ],
)
def test_assessment_fails_closed_without_identity_and_structure(
    body: bytes,
    status: int,
    expected: AccessState,
) -> None:
    fetch = _fetch(body, status=status)
    extraction = TrafilaturaExtractor().extract(fetch)

    assessment = CNBCProvider().assess(ARTICLE_URL, fetch, extraction)

    assert assessment.access_state is expected
    assert assessment.promotable is (expected is AccessState.FULL)


class SearchHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.sessions: list[SessionArtifact | None] = []
        self.final_url: str | None = None
        self.content_type = "application/json; charset=utf-8"
        self.malformed = False
        self.totalresults = 22

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        self.urls.append(url)
        self.sessions.append(session)
        offset = int(parse_qs(urlsplit(url).query)["endindex"][0])
        if self.malformed:
            payload: object = {"metadata": {}, "results": "changed"}
        elif offset == 0:
            payload = {
                "metadata": {
                    "totalresults": self.totalresults,
                    "pagesize": 20,
                },
                "results": [
                    {
                        "cn:liveURL": (
                            "https://www.cnbc.com/video/2026/07/20/fixture.html"
                        ),
                        "cn:title": "Video is not an article",
                        "datePublished": "2026-07-20T20:00:00+0000",
                    },
                    *(
                        {
                            "cn:liveURL": ARTICLE_URL,
                            "cn:title": "  Jamie Dimon fixture headline  ",
                            "summary": " Concise fixture summary. ",
                            "datePublished": "2026-07-20T23:01:01+0000",
                        }
                        for _ in range(19)
                    ),
                ],
            }
        else:
            payload = {
                "metadata": {
                    "totalresults": self.totalresults,
                    "pagesize": 20,
                },
                "results": [
                    {
                        "cn:liveURL": SECOND_URL,
                        "cn:title": "Second fixture story",
                        "description": "Older fixture summary.",
                        "datePublished": "2026-07-19T12:00:00Z",
                    },
                    {
                        "cn:liveURL": "https://foreign.test/story",
                        "cn:title": "Foreign result",
                        "datePublished": "2026-07-19T11:00:00Z",
                    },
                ],
            }
        return RawFetch(
            requested_url=url,
            final_url=self.final_url or url,
            http_status=200,
            content_type=self.content_type,
            retrieved_at=NOW,
            raw_html=json.dumps(payload).encode(),
        )


def test_search_uses_public_json_paginates_deduplicates_and_omits_session() -> None:
    http = SearchHttp()

    results = CNBCProvider().search(
        http,
        SessionArtifact.model_construct(),
        "bank capital",
        SearchFilters(limit=2),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL, SECOND_URL]
    assert [result.headline for result in results] == [
        "Jamie Dimon fixture headline",
        "Second fixture story",
    ]
    assert results[0].snippet == "Concise fixture summary."
    assert results[1].published == datetime(2026, 7, 19, 12, tzinfo=UTC)
    assert len(http.urls) == 2
    assert parse_qs(urlsplit(http.urls[0]).query)["query"] == ["bank capital"]
    assert parse_qs(urlsplit(http.urls[1]).query)["endindex"] == ["20"]
    assert http.sessions == [None, None]


def test_search_request_endpoint_comes_from_adapter_definition() -> None:
    spec = load_provider_spec("cnbc")
    search = type(spec.search).model_validate(
        {
            "kind": "adapter",
            "endpoint": "https://api.queryly.com/cnbc/configured.json",
        }
    )
    provider = CNBCProvider(spec=spec.model_copy(update={"search": search}))
    http = SearchHttp()

    provider.search(http, None, "bank capital", SearchFilters(limit=1))

    assert http.urls[0].startswith("https://api.queryly.com/cnbc/configured.json?")


def test_search_date_bound_stops_pagination() -> None:
    http = SearchHttp()

    results = CNBCProvider().search(
        http,
        None,
        "banks",
        SearchFilters(published_after=datetime(2026, 7, 20, 21, tzinfo=UTC)),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL]
    assert len(http.urls) == 1


def test_search_short_middle_page_ends_without_invalid_continuation() -> None:
    http = SearchHttp()
    http.totalresults = 60

    results = CNBCProvider().search(
        http,
        None,
        "banks",
        SearchFilters(limit=30),
    )

    assert [str(result.url) for result in results] == [ARTICLE_URL, SECOND_URL]
    assert len(http.urls) == 2
    assert parse_qs(urlsplit(http.urls[-1]).query)["endindex"] == ["20"]


def test_search_rejects_redirect_schema_and_media_type_drift() -> None:
    redirected = SearchHttp()
    redirected.final_url = "https://api.queryly.com/cnbc/json.aspx?query=changed"
    with pytest.raises(ProviderContractError, match="search"):
        CNBCProvider().search(redirected, None, "banks", SearchFilters())

    malformed = SearchHttp()
    malformed.malformed = True
    with pytest.raises(ProviderContractError, match="schema"):
        CNBCProvider().search(malformed, None, "banks", SearchFilters())

    wrong_type = SearchHttp()
    wrong_type.content_type = "text/html"
    with pytest.raises(ProviderTransportError, match="non-JSON"):
        CNBCProvider().search(wrong_type, None, "banks", SearchFilters())
