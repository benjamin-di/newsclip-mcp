"""Shared, provider-neutral primitives for strict article assessment."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Literal

from lxml import etree, html
from pydantic import HttpUrl

from .articles import parse_aware_datetime
from .errors import ProviderContractError, ProviderTransportError, TransportFailure
from .models import AccessState, ArticleAssessment, ExtractedArticle, RawFetch

JsonLdState = Literal["news_article", "absent", "non_article", "malformed"]


def search_status_failure(status: int) -> TransportFailure:
    """Name a refusal the provider itself returned, by its instruction.

    429 is the provider asking for less traffic; anything else non-2xx is the
    provider failing or refusing. Neither is a route fault, so neither reports
    as TRANSPORT.
    """

    if status == 429:
        return TransportFailure.RATE_LIMITED
    return TransportFailure.PROVIDER_ERROR


def document(raw_html: bytes) -> html.HtmlElement | None:
    try:
        return html.fromstring(raw_html)
    except (etree.ParserError, ValueError, TypeError):
        return None


def search_document(fetch: RawFetch) -> html.HtmlElement:
    """Require a successful, parseable HTML search response."""

    if not 200 <= fetch.http_status < 300:
        raise ProviderTransportError(
            f"provider search returned HTTP {fetch.http_status}",
            category=search_status_failure(fetch.http_status),
        )
    if fetch.content_type is not None:
        media_type = fetch.content_type.partition(";")[0].strip().lower()
        if media_type not in {"text/html", "application/xhtml+xml"}:
            raise ProviderTransportError("provider search returned non-HTML content")
    parsed = document(fetch.raw_html)
    if parsed is None:
        raise ProviderTransportError("provider search response could not be parsed")
    return parsed


def search_json_object(fetch: RawFetch) -> Mapping[str, object]:
    """Require a successful JSON search response with an object envelope."""

    if not 200 <= fetch.http_status < 300:
        raise ProviderTransportError(
            f"provider search returned HTTP {fetch.http_status}",
            category=search_status_failure(fetch.http_status),
        )
    media_type = (fetch.content_type or "").partition(";")[0].strip().lower()
    if media_type != "application/json":
        raise ProviderTransportError("provider search returned non-JSON content")
    try:
        payload = json.loads(fetch.raw_html)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderTransportError(
            "provider search returned malformed JSON"
        ) from error
    if not isinstance(payload, Mapping):
        raise ProviderContractError("provider search JSON must be an object")
    return payload


def canonical_urls(
    parsed: html.HtmlElement,
    normalizer: Callable[[str], str | None],
) -> list[str]:
    candidates: list[str] = []
    values = parsed.xpath(
        "//link[contains(concat(' ', normalize-space(@rel), ' '), "
        "' canonical ')]/@href | "
        "//meta[translate(@property, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', "
        "'abcdefghijklmnopqrstuvwxyz')='og:url']/@content"
    )
    for value in values:
        normalized = normalizer(str(value))
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates


#: Every JSON-LD article type any provider's assessment accepts. Extraction
#: reads article metadata through this one selector, so a page a provider
#: accepts (WSJ's ``OpinionNewsArticle``) also yields its ``datePublished``.
#: Each provider's assessment still accepts only its own declared subset.
ARTICLE_JSONLD_TYPES: tuple[str, ...] = ("NewsArticle", "OpinionNewsArticle")


def news_article_json_ld(
    parsed: html.HtmlElement,
    *,
    article_types: tuple[str, ...] = ("NewsArticle",),
) -> tuple[dict[str, object] | None, JsonLdState]:
    """Return explicitly accepted article metadata and a parser diagnostic."""

    scripts: Iterable[str] = parsed.xpath(
        "//script[translate(@type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', "
        "'abcdefghijklmnopqrstuvwxyz')='application/ld+json']/text()"
    )
    saw_script = False
    saw_valid_document = False
    for script in scripts:
        saw_script = True
        try:
            payload = json.loads(script)
        except (json.JSONDecodeError, TypeError):
            continue
        saw_valid_document = True
        candidates: list[object] = payload if isinstance(payload, list) else [payload]
        if isinstance(payload, dict) and isinstance(payload.get("@graph"), list):
            candidates.extend(payload["@graph"])
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            types = candidate.get("@type")
            normalized_types = [types] if isinstance(types, str) else types
            if isinstance(normalized_types, list) and any(
                accepted in normalized_types for accepted in article_types
            ):
                return candidate, "news_article"
    if not saw_script:
        return None, "absent"
    if saw_valid_document:
        return None, "non_article"
    return None, "malformed"


def metadata_has_headline(extraction: ExtractedArticle) -> bool:
    return any(
        isinstance(extraction.metadata.get(key), str)
        and bool(extraction.metadata[key].strip())
        for key in ("title", "headline")
    )


def search_result_published(anchor: html.HtmlElement) -> datetime | None:
    """Parse an aware publication timestamp from an anchor's result container."""

    containers = anchor.xpath("ancestor-or-self::*[self::article or self::li][1]")
    container = containers[0] if containers else anchor
    values = container.xpath(
        ".//time[@datetime][1]/@datetime | .//*[@itemprop='datePublished'][1]/@content"
    )
    for value in values:
        parsed = parse_aware_datetime(value)
        if parsed is not None:
            return parsed
    return None


def assessment(
    state: AccessState,
    extraction: ExtractedArticle,
    fetch: RawFetch,
    *,
    reason: str,
    provider_article_id: str | None = None,
    canonical_url: str | None = None,
    identity_match: bool = False,
    negative_markers: Iterable[str] = (),
    structural_signals: Iterable[str] = (),
) -> ArticleAssessment:
    return ArticleAssessment(
        access_state=state,
        provider_article_id=provider_article_id,
        canonical_url=HttpUrl(canonical_url) if canonical_url is not None else None,
        identity_match=identity_match,
        negative_markers=tuple(negative_markers),
        structural_signals=tuple(structural_signals),
        word_count=extraction.word_count,
        session_cookie_present=fetch.session_cookie_present,
        reason=reason,
    )
