from __future__ import annotations

from datetime import UTC, datetime

import pytest

from newsclip.articles import parse_aware_datetime
from newsclip.assessment import search_json_object
from newsclip.configured_provider import ConfiguredProvider
from newsclip.errors import (
    ProviderContractError,
    ProviderTransportError,
    TransportFailure,
)
from newsclip.models import RawFetch, SearchFilters, SessionArtifact
from newsclip.provider_config import ProviderDefinitionError, load_provider_spec
from newsclip.providers import BloombergProvider, FTProvider, WSJProvider

NOW = datetime(2026, 7, 20, tzinfo=UTC)
PROVIDERS = (FTProvider(), WSJProvider(), BloombergProvider())
HTML_PROVIDERS = (FTProvider(), WSJProvider())
EMPTY_BODY = b"""
<html><body><main>
  <div data-trackable="search-no-results"
       data-testid="search-no-results"
       data-component="search-no-results">No results</div>
</main></body></html>
"""


class SearchHttp:
    def __init__(
        self,
        *,
        status: int = 200,
        content_type: str | None = "text/html",
        body: bytes = EMPTY_BODY,
        final_url: str | None = None,
    ) -> None:
        self.status = status
        self.content_type = content_type
        self.body = body
        self.final_url = final_url

    def get(
        self,
        url: str,
        *,
        session: SessionArtifact | None = None,
        timeout: float = 40,
    ) -> RawFetch:
        return RawFetch(
            requested_url=url,
            final_url=self.final_url or url,
            http_status=self.status,
            content_type=self.content_type,
            retry_after=30 if self.status == 429 else None,
            retrieved_at=NOW,
            session_cookie_present=session is not None,
            raw_html=self.body,
        )


def test_search_json_object_accepts_only_an_explicit_object_envelope() -> None:
    fetch = SearchHttp(
        content_type="application/json; charset=utf-8",
        body=b'{"results": []}',
    ).get("https://example.test/search")

    assert search_json_object(fetch) == {"results": []}


@pytest.mark.parametrize(
    ("status", "content_type", "body", "error", "message"),
    [
        (503, "application/json", b"{}", ProviderTransportError, "HTTP 503"),
        (200, None, b"{}", ProviderTransportError, "non-JSON"),
        (200, "text/html", b"{}", ProviderTransportError, "non-JSON"),
        (200, "application/json", b"{", ProviderTransportError, "malformed JSON"),
        (200, "application/json", b"[]", ProviderContractError, "must be an object"),
    ],
)
def test_search_json_object_rejects_transport_and_envelope_drift(
    status: int,
    content_type: str | None,
    body: bytes,
    error: type[Exception],
    message: str,
) -> None:
    fetch = SearchHttp(
        status=status,
        content_type=content_type,
        body=body,
    ).get("https://example.test/search")

    with pytest.raises(error, match=message):
        search_json_object(fetch)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-07-23T12:30:00Z", datetime(2026, 7, 23, 12, 30, tzinfo=UTC)),
        (
            "2026-07-23T14:30:00+02:00",
            datetime.fromisoformat("2026-07-23T14:30:00+02:00"),
        ),
        ("2026-07-23T12:30:00", None),
        ("not-a-date", None),
        ("", None),
        (None, None),
        (123, None),
    ],
)
def test_parse_aware_datetime_accepts_only_aware_iso_strings(
    value: object,
    expected: datetime | None,
) -> None:
    assert parse_aware_datetime(value) == expected


def test_generic_html_search_rejects_an_adapter_definition() -> None:
    provider = ConfiguredProvider(load_provider_spec("cnbc"))

    with pytest.raises(ProviderDefinitionError, match="HTML search"):
        provider.search(
            SearchHttp(),
            None,
            "capital",
            SearchFilters(),
        )


@pytest.mark.parametrize("provider", PROVIDERS, ids=lambda provider: provider.key)
@pytest.mark.parametrize("status", (429, 503))
def test_search_rejects_terminal_non_success_status(provider, status: int) -> None:
    with pytest.raises(ProviderTransportError):
        provider.search(
            SearchHttp(status=status),
            None,
            "capital",
            SearchFilters(),
        )


@pytest.mark.parametrize("provider", HTML_PROVIDERS, ids=lambda provider: provider.key)
@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("application/json", b"{}"),
        ("text/html", b""),
    ],
)
def test_search_rejects_non_html_or_unparseable_success(
    provider, content_type: str, body: bytes
) -> None:
    with pytest.raises(ProviderTransportError):
        provider.search(
            SearchHttp(content_type=content_type, body=body),
            None,
            "capital",
            SearchFilters(),
        )


@pytest.mark.parametrize("provider", HTML_PROVIDERS, ids=lambda provider: provider.key)
def test_search_preserves_genuine_empty_results(provider) -> None:
    results = provider.search(SearchHttp(), None, "absent", SearchFilters())

    assert results == []


@pytest.mark.parametrize("provider", HTML_PROVIDERS, ids=lambda provider: provider.key)
def test_search_rejects_unscoped_empty_text(provider) -> None:
    body = b"""
    <html><body>
      <script>const emptyCopy = "No results";</script>
      <main>Changed search markup</main>
    </body></html>
    """

    with pytest.raises(ProviderContractError, match="neither results nor empty"):
        provider.search(SearchHttp(body=body), None, "capital", SearchFilters())


def test_search_rejects_redirected_homepage_results() -> None:
    body = b"""
    <html><body><article>
      <a href="/finance/banking/unrelated-homepage-story-a10ec4bc">
        Unrelated homepage story
      </a>
    </article></body></html>
    """

    with pytest.raises(ProviderContractError, match="identity mismatch"):
        WSJProvider().search(
            SearchHttp(body=body, final_url="https://www.wsj.com/"),
            None,
            "capital",
            SearchFilters(),
        )


def test_html_search_extracts_and_validates_next_page() -> None:
    first = b"""
    <html><body>
      <ul class="search-results__list"><li>
        <a class="js-teaser-heading-link"
           href="/content/11111111-1111-4111-8111-111111111111">First</a>
      </li></ul>
      <a href="?q=capital&amp;page=2&amp;sort=relevance&amp;isFirstView=true">
        <span>Next page</span>
      </a>
    </body></html>
    """

    page = FTProvider().search_page(
        SearchHttp(body=first), None, "capital", SearchFilters()
    )

    assert [result.headline for result in page.results] == ["First"]
    assert page.next_url == (
        "https://www.ft.com/search?q=capital&page=2&sort=relevance&isFirstView=true"
    )


@pytest.mark.parametrize(
    "href",
    [
        "https://evil.test/search?q=capital&page=2",
        "?q=different&page=2",
        "?q=capital&page=3",
        "?q=capital&page=not-a-number",
    ],
)
def test_html_search_rejects_untrusted_or_skipped_next_page(href: str) -> None:
    body = f"""
    <html><body>
      <ul class="search-results__list"><li>
        <a class="js-teaser-heading-link"
           href="/content/11111111-1111-4111-8111-111111111111">First</a>
      </li></ul>
      <a href="{href}"><span>Next page</span></a>
    </body></html>
    """.encode()

    with pytest.raises(ProviderContractError, match="continuation"):
        FTProvider().search_page(
            SearchHttp(body=body), None, "capital", SearchFilters()
        )


def test_html_search_follows_pages_until_limit() -> None:
    first = b"""
    <html><body>
      <ul class="search-results__list"><li>
        <a class="js-teaser-heading-link"
           href="/content/11111111-1111-4111-8111-111111111111">First</a>
      </li></ul>
      <a href="?q=capital&amp;page=2"><span>Next page</span></a>
    </body></html>
    """
    second = b"""
    <html><body><ul class="search-results__list"><li>
      <a class="js-teaser-heading-link"
         href="/content/22222222-2222-4222-8222-222222222222">Second</a>
    </li></ul></body></html>
    """

    class PagedHttp(SearchHttp):
        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            body = second if "page=2" in url else first
            return SearchHttp(body=body).get(url, **kwargs)

    results = FTProvider().search(PagedHttp(), None, "capital", SearchFilters(limit=2))

    assert [result.headline for result in results] == ["First", "Second"]


def test_paginated_search_preserves_global_metadata_fetch_budget() -> None:
    ids = [f"{index}" * 8 + "-1111-4111-8111-111111111111" for index in range(1, 5)]

    def page_body(page: int) -> bytes:
        start = (page - 1) * 2
        links = "".join(
            f'<li><a class="js-teaser-heading-link" href="/content/{article_id}">'
            f"Result {index + 1}</a></li>"
            for index, article_id in enumerate(ids[start : start + 2], start=start)
        )
        next_link = (
            '<a href="?q=capital&amp;page=2"><span>Next page</span></a>'
            if page == 1
            else ""
        )
        return (
            f'<html><body><ul class="search-results__list">{links}</ul>'
            f"{next_link}</body></html>"
        ).encode()

    class MetadataPagedHttp(SearchHttp):
        def __init__(self) -> None:
            super().__init__()
            self.article_calls: list[str] = []

        def get(self, url: str, **kwargs) -> RawFetch:  # noqa: ANN003
            if "/search?" in url:
                page = 2 if "page=2" in url else 1
                return SearchHttp(body=page_body(page)).get(url, **kwargs)
            self.article_calls.append(url)
            return SearchHttp(status=404, body=b"").get(url, **kwargs)

    http = MetadataPagedHttp()
    provider = FTProvider()
    search = provider.spec.search.model_copy(
        update={"missing_published_fetch_limit": 3}
    )
    provider.spec = provider.spec.model_copy(update={"search": search})
    results = provider.search(http, None, "capital", SearchFilters(limit=4))

    assert len(results) == 4
    assert http.article_calls == [
        f"https://www.ft.com/content/{article_id}" for article_id in ids[:3]
    ]


def test_search_identity_uses_the_requested_scheme_default_port() -> None:
    spec = FTProvider().spec
    search_payload = spec.search.model_dump(mode="python")
    search_payload["endpoint"] = "http://www.ft.com/search"
    search = type(spec.search).model_validate(search_payload)
    provider = ConfiguredProvider(spec.model_copy(update={"search": search}))

    assert (
        provider.search(
            SearchHttp(final_url="http://www.ft.com:80/search?q=capital"),
            None,
            "capital",
            SearchFilters(),
        )
        == []
    )
    with pytest.raises(ProviderContractError, match="identity mismatch"):
        provider.search(
            SearchHttp(final_url="http://www.ft.com:443/search?q=capital"),
            None,
            "capital",
            SearchFilters(),
        )


# Distinguish a provider's explicit HTTP refusal from a transport failure.
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (429, TransportFailure.RATE_LIMITED),
        (403, TransportFailure.PROVIDER_ERROR),
        (500, TransportFailure.PROVIDER_ERROR),
        (502, TransportFailure.PROVIDER_ERROR),
    ],
)
def test_provider_answered_refusal_is_named_not_collapsed_into_transport(
    status: int, expected: TransportFailure
) -> None:
    for provider in HTML_PROVIDERS:
        with pytest.raises(ProviderTransportError) as raised:
            provider.search(SearchHttp(status=status), None, "capital", SearchFilters())
        assert raised.value.category is expected


def test_unusable_body_from_a_healthy_status_still_reports_transport() -> None:
    """Only the status carries the provider's instruction.

    A 200 whose body is not usable HTML is a route/content fault, not the
    provider refusing, so it must keep reporting TRANSPORT.
    """

    provider = FTProvider()
    with pytest.raises(ProviderTransportError) as raised:
        provider.search(
            SearchHttp(content_type="application/pdf"),
            None,
            "capital",
            SearchFilters(),
        )
    assert raised.value.category is TransportFailure.TRANSPORT
