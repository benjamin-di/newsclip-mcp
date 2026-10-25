"""The Guardian provider over the publisher's licensed Open Platform API."""

from __future__ import annotations

import json
from html import escape
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from pydantic import HttpUrl

from ..articles import parse_aware_datetime
from ..configured_provider import ConfiguredProvider, normalize_url, provider_article_id
from ..contracts import HttpClient
from ..errors import ProviderContractError, ProviderTransportError
from ..models import (
    ProviderSearchPage,
    RawFetch,
    SearchFilters,
    SearchResult,
    SessionArtifact,
)
from ..provider_config import ProviderSpec, load_provider_spec

_SEARCH_TIMEOUT_SECONDS = 10
_FETCH_TIMEOUT_SECONDS = 20
_PAGE_SIZE = 50
_MAX_RESPONSE_BYTES = 5_000_000
_ITEM_FIELDS = "body,byline,headline,firstPublicationDate"


class GuardianProvider(ConfiguredProvider):
    """Search and retrieval both speak to ``content.guardianapis.com``.

    theguardian.com is never scraped: robots.txt reserves the site for the
    publisher's own terms, while the Open Platform API is the licensed channel
    the registered key was issued for (robots policy verified 2026-07-28).
    The API key itself is attached as a host-scoped request header by the HTTP
    client, so it exists in no URL this module ever builds.
    """

    def __init__(self, *, spec: ProviderSpec | None = None) -> None:
        selected_spec = spec or load_provider_spec("guardian")
        if selected_spec.key != "guardian":
            raise ValueError("Guardian provider requires its own definition")
        super().__init__(selected_spec)
        self._search = selected_spec.require_adapter_search()
        endpoint = urlsplit(str(self._search.endpoint))
        if endpoint.path != "/search" or endpoint.query or endpoint.fragment:
            raise ValueError("Guardian search endpoint must be the API /search root")
        self._api_root = f"{endpoint.scheme}://{endpoint.netloc}"

    def search(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
    ) -> list[SearchResult]:
        page = self.search_page(http, session, query, filters)
        return list(page.results[: filters.limit])

    def search_page(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        query: str,
        filters: SearchFilters,
        *,
        next_url: str | None = None,
        metadata_fetch_budget: int | None = None,
    ) -> ProviderSearchPage:
        if next_url is not None:
            raise ProviderContractError("Guardian search does not expose continuation")
        del session
        del metadata_fetch_budget
        if not query.strip():
            raise ProviderContractError("Guardian search query has no searchable terms")
        endpoint = str(self._search.endpoint)
        search_url = f"{endpoint}?{urlencode({'q': query, 'page-size': _PAGE_SIZE})}"
        fetch = http.get(search_url, session=None, timeout=_SEARCH_TIMEOUT_SECONDS)
        _validate_api_response(fetch)
        _validate_search_identity(str(fetch.final_url), query, endpoint=endpoint)
        payload = _api_payload(fetch)
        results_value = payload.get("results")
        if not isinstance(results_value, list):
            raise ProviderContractError("Guardian search response schema changed")
        candidates: list[SearchResult] = []
        seen: set[str] = set()
        undated_excluded = 0
        for item in results_value:
            if not isinstance(item, dict):
                raise ProviderContractError("Guardian search result schema changed")
            web_url = item.get("webUrl")
            headline = item.get("webTitle")
            if not isinstance(web_url, str) or not isinstance(headline, str):
                raise ProviderContractError("Guardian search result schema changed")
            normalized = self.normalize_url(web_url)
            headline = " ".join(headline.split())
            if normalized is None or not headline or normalized in seen:
                continue
            seen.add(normalized)
            published = parse_aware_datetime(item.get("webPublicationDate"))
            if not filters.includes_published(published):
                undated_excluded += filters.excludes_undated(published)
                continue
            candidates.append(
                SearchResult(
                    provider=self.key,
                    url=HttpUrl(normalized),
                    headline=headline,
                    published=published,
                )
            )
        return ProviderSearchPage(
            results=tuple(candidates), undated_excluded_count=undated_excluded
        )

    def fetch(
        self,
        http: HttpClient,
        session: SessionArtifact | None,
        url: str,
    ) -> RawFetch:
        del session
        if not self.owns_url(url):
            raise ValueError(f"{self.key} fetch requires an owned article URL")
        content_id = self.article_id(url)
        if content_id is None:
            raise ValueError(f"{self.key} fetch requires an owned article URL")
        item_url = (
            f"{self._api_root}/{content_id}?{urlencode({'show-fields': _ITEM_FIELDS})}"
        )
        fetch = http.get(item_url, session=None, timeout=_FETCH_TIMEOUT_SECONDS)
        _validate_api_response(fetch)
        payload = _api_payload(fetch)
        content = payload.get("content")
        if not isinstance(content, dict):
            raise ProviderContractError("Guardian content response schema changed")
        if content.get("id") != content_id:
            raise ProviderContractError("Guardian content identity mismatch")
        web_url = content.get("webUrl")
        web_title = content.get("webTitle")
        fields = content.get("fields")
        if (
            not isinstance(web_url, str)
            or not isinstance(web_title, str)
            or not web_title.strip()
            or not isinstance(fields, dict)
        ):
            raise ProviderContractError("Guardian content response schema changed")
        if self.normalize_url(web_url) != self.normalize_url(url):
            raise ProviderContractError("Guardian content identity mismatch")
        body = fields.get("body")
        if not isinstance(body, str) or not body.strip():
            raise ProviderContractError("Guardian content omitted the article body")
        published = content.get("webPublicationDate")
        first_published = fields.get("firstPublicationDate")
        date_published = (
            first_published
            if parse_aware_datetime(first_published) is not None
            else published
        )
        document = _compose_document(
            web_url=web_url,
            web_title=web_title,
            byline=fields.get("byline"),
            date_published=date_published,
            body=body,
            raw_payload=fetch.raw_html,
        )
        return RawFetch(
            requested_url=HttpUrl(url),
            final_url=HttpUrl(web_url),
            http_status=fetch.http_status,
            content_type="text/html; charset=utf-8",
            retrieved_at=fetch.retrieved_at,
            # Carried from the API fetch this document was composed from:
            # the transport that served the payload is the transport that
            # served the article, and dropping it would archive as
            # indistinguishable from a row stored before provenance existed.
            serving_transport=fetch.serving_transport,
            raw_html=document,
        )


def _compose_document(
    *,
    web_url: str,
    web_title: str,
    byline: object,
    date_published: object,
    body: str,
    raw_payload: bytes,
) -> bytes:
    """Build one deterministic HTML document from the publisher's response.

    The raw API bytes ride along verbatim except that ``<`` becomes ``&lt;``,
    so prose containing ``</script>`` cannot terminate the carrier element and
    the archived document remains an auditable function of the Guardian's own
    response.
    """

    json_ld: dict[str, Any] = {
        "@context": "https://schema.org",
        "@type": "NewsArticle",
        "headline": web_title,
    }
    if isinstance(date_published, str) and date_published.strip():
        json_ld["datePublished"] = date_published.strip()
    if isinstance(byline, str) and byline.strip():
        json_ld["author"] = [{"@type": "Person", "name": byline.strip()}]
    json_ld_text = json.dumps(json_ld, ensure_ascii=False).replace("<", "\\u003c")
    payload_text = raw_payload.decode("utf-8", errors="replace").replace("<", "&lt;")
    document = (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head>\n'
        '<meta charset="utf-8">\n'
        f"<title>{escape(web_title)}</title>\n"
        f'<link rel="canonical" href="{escape(web_url, quote=True)}">\n'
        f'<script type="application/ld+json">{json_ld_text}</script>\n'
        "</head><body>\n"
        f"<article>{body}</article>\n"
        '<script type="application/json" id="guardian-api-payload">'
        f"{payload_text}</script>\n"
        "</body></html>\n"
    )
    return document.encode("utf-8")


def _validate_api_response(fetch: RawFetch) -> None:
    if not 200 <= fetch.http_status < 300:
        raise ProviderTransportError(f"provider API returned HTTP {fetch.http_status}")
    if len(fetch.raw_html) > _MAX_RESPONSE_BYTES:
        raise ProviderTransportError("provider API response exceeded the size limit")
    media_type = (fetch.content_type or "").partition(";")[0].strip().lower()
    if media_type != "application/json":
        raise ProviderTransportError("provider API returned non-JSON content")


def _validate_search_identity(final_url: str, query: str, *, endpoint: str) -> None:
    try:
        parsed = urlsplit(final_url)
        expected = urlsplit(endpoint)
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        port = parsed.port or 443
        expected_port = expected.port or 443
    except ValueError as error:
        raise ProviderContractError("invalid provider API response URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected.hostname
        or parsed.path.rstrip("/") != expected.path.rstrip("/")
        or parsed.fragment
        or parsed.username
        or parsed.password
        or port != expected_port
        or parameters.get("q") != [query]
    ):
        raise ProviderContractError("provider API response identity mismatch")


def _api_payload(fetch: RawFetch) -> dict[str, Any]:
    try:
        document = json.loads(fetch.raw_html)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderContractError("Guardian API returned malformed JSON") from error
    response = document.get("response") if isinstance(document, dict) else None
    if not isinstance(response, dict) or response.get("status") != "ok":
        raise ProviderContractError("Guardian API response schema changed")
    return response


def normalize_article_url(raw: str) -> str | None:
    return normalize_url(load_provider_spec("guardian"), raw)


def article_id(url: str) -> str | None:
    return provider_article_id(load_provider_spec("guardian"), url)


def build_guardian_provider(
    spec: ProviderSpec, verification_url: str | None
) -> GuardianProvider:
    if verification_url is not None:
        raise RuntimeError("Guardian registration cannot receive a verification URL")
    return GuardianProvider(spec=spec)


__all__ = [
    "GuardianProvider",
    "article_id",
    "build_guardian_provider",
    "normalize_article_url",
]
