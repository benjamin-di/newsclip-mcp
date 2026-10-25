"""Offline HTML-to-Markdown extraction."""

from __future__ import annotations

import re
from email.message import Message
from functools import cache
from typing import Any

from lxml import etree, html

from .articles import parse_aware_datetime
from .assessment import ARTICLE_JSONLD_TYPES, news_article_json_ld
from .models import ExtractedArticle, RawFetch

_NEWSCLIP_EXTRACTION_REVISION = 4
_META_SNIFF_BYTES = 4096
_META_CHARSET = re.compile(
    rb"""<meta\b[^>]*?(?:\s|["';])charset\s*=\s*["']?\s*([a-z0-9._:+-]+)""",
    re.IGNORECASE,
)


@cache
def _extractor_version() -> str:
    from importlib.metadata import version as distribution_version

    return (
        f"newsclip-r{_NEWSCLIP_EXTRACTION_REVISION}"
        f"+trafilatura-{distribution_version('trafilatura')}"
    )


class TrafilaturaExtractor:
    """Extract a Markdown candidate while retaining only serializable metadata."""

    name = "trafilatura"

    # This identity covers both the dependency and Newsclip's extraction policy.
    # Bump the Newsclip revision whenever changes here can alter stored output.
    @property
    def version(self) -> str:
        return _extractor_version()

    def extract(
        self,
        fetch: RawFetch,
        *,
        scope_xpath: tuple[str, ...] | None = None,
    ) -> ExtractedArticle:
        """Extract a body, optionally bounded to a provider-declared subtree.

        ``scope_xpath`` bounds only the *body*. Metadata stays full-document
        because a provider's JSON-LD is normally outside the article element —
        Reuters keeps ``datePublished`` and the headline in
        ``script#fusion-metadata`` in the page head — and scoping it would strip
        the evidence ``build_article`` depends on.
        """

        source = _decode_source(fetch)
        body_source = (
            source if scope_xpath is None else _scoped_source(source, scope_xpath)
        )
        body_markdown = "" if body_source is None else _body(body_source, fetch)
        metadata = _metadata(source, str(fetch.final_url))
        return ExtractedArticle(
            body_markdown=body_markdown,
            metadata=metadata,
            word_count=len(body_markdown.split()),
        )


def _decode_source(fetch: RawFetch) -> str:
    candidates = (
        _content_type_charset(fetch.content_type),
        _meta_charset(fetch.raw_html),
        "utf-8",
    )
    for charset in dict.fromkeys(candidates):
        if charset is None:
            continue
        try:
            return fetch.raw_html.decode(charset, errors="replace")
        except LookupError:
            continue
    return fetch.raw_html.decode("utf-8", errors="replace")


def _content_type_charset(content_type: str | None) -> str | None:
    if content_type is None:
        return None
    message = Message()
    message["content-type"] = content_type
    return message.get_content_charset()


def _meta_charset(raw_html: bytes) -> str | None:
    match = _META_CHARSET.search(raw_html[:_META_SNIFF_BYTES])
    if match is None:
        return None
    return match.group(1).decode("ascii").lower()


def _body(source: str, fetch: RawFetch) -> str:
    import trafilatura

    body = trafilatura.extract(
        source,
        url=str(fetch.final_url),
        output_format="markdown",
        include_comments=False,
        include_formatting=True,
        include_links=True,
        favor_precision=True,
    )
    return (body or "").strip()


def _scoped_source(source: str, scope_xpath: tuple[str, ...]) -> str | None:
    """Return the single in-scope subtree as a standalone document, or ``None``.

    ``None`` means the scope did not resolve to exactly one element, and the
    caller turns it into an empty body. Zero matches is the existing
    non-article-page case, which assessment already fails closed on the missing
    ``markdown_body`` signal. Multiple matches is provider drift — a second
    ``<article>`` appearing on the page — and failing loudly there is the point
    of an allowlist: the alternative is silently extracting from whichever
    element happens to be first.

    The subtree is re-serialized inside a minimal document because trafilatura
    reads a page, not a fragment; handing it a bare subtree changes how it
    resolves the body.
    """

    try:
        document = html.fromstring(source)
    except (etree.ParserError, ValueError, TypeError):
        return None
    matches = [
        node
        for expression in scope_xpath
        for node in document.xpath(expression)
        if isinstance(node, etree._Element)
    ]
    if len(matches) != 1:
        return None
    subtree = etree.tostring(matches[0], encoding="unicode", method="html")
    return f"<html><body>{subtree}</body></html>"


def _metadata(source: str, url: str) -> dict[str, Any]:
    import trafilatura

    document = trafilatura.extract_metadata(source, default_url=url)
    metadata: dict[str, Any] = {}
    if document is not None:
        for key in (
            "title",
            "author",
            "date",
            "categories",
            "tags",
            "description",
            "url",
        ):
            value = getattr(document, key, None)
            if isinstance(value, str) and value.strip():
                metadata[key] = value.strip()
            elif isinstance(value, list):
                clean = [str(item).strip() for item in value if str(item).strip()]
                if clean:
                    metadata[key] = clean

    # FT's JSON-LD is useful metadata even when trafilatura omits a field. It is
    # evidence for assessment only when the provider independently validates it.
    news_article = _news_article_json_ld(source)
    if news_article is not None:
        headline = news_article.get("headline")
        if "title" not in metadata and isinstance(headline, str) and headline.strip():
            metadata["title"] = headline.strip()
        if "author" not in metadata:
            authors = _json_ld_authors(news_article.get("author"))
            if authors:
                metadata["author"] = authors
        published = news_article.get("datePublished")
        if parse_aware_datetime(published) is not None:
            metadata["date"] = str(published).strip()
        section = news_article.get("articleSection")
        if (
            "categories" not in metadata
            and isinstance(section, str)
            and section.strip()
        ):
            metadata["categories"] = section.strip()
    return metadata


def _news_article_json_ld(source: str) -> dict[str, Any] | None:
    try:
        document = html.fromstring(source)
    except (etree.ParserError, ValueError, TypeError):
        return None
    # The shared selector every provider assessment uses, over the union of
    # their accepted types: an opinion page WSJ accepts keeps its metadata.
    article, _state = news_article_json_ld(document, article_types=ARTICLE_JSONLD_TYPES)
    return article


def _json_ld_authors(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    authors: list[str] = []
    for item in values:
        if isinstance(item, str) and item.strip():
            authors.append(item.strip())
        elif isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name.strip():
                authors.append(name.strip())
    return authors
