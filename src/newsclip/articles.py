"""Pure construction of accepted public articles from assessed evidence."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .errors import ContentNotFullError
from .models import (
    Article,
    ArticleAssessment,
    ExtractedArticle,
    ExtractionMeta,
    RawFetch,
)

if TYPE_CHECKING:
    from .providers.base import Provider


def build_article(
    provider: Provider,
    fetch: RawFetch,
    extraction: ExtractedArticle,
    assessment: ArticleAssessment,
    *,
    extractor_name: str,
    extractor_version: str,
) -> Article:
    """Build one accepted public article from independently assessed evidence."""

    if not assessment.promotable:
        raise ContentNotFullError(assessment.reason)
    if assessment.provider_article_id is None or assessment.canonical_url is None:
        raise ContentNotFullError("full assessment omitted article identity")

    metadata = extraction.metadata
    headline = _metadata_text(metadata, "title", "headline")
    if not headline:
        raise ContentNotFullError("full assessment omitted headline metadata")
    authors = _metadata_authors(metadata.get("author") or metadata.get("authors"))
    section = _metadata_text(metadata, "section", "categories") or None
    published = parse_aware_datetime(metadata.get("date") or metadata.get("published"))
    return Article(
        id=f"{provider.key}:{assessment.provider_article_id}",
        provider_article_id=assessment.provider_article_id,
        url=fetch.final_url,
        canonical_url=assessment.canonical_url,
        provider=provider.key,
        headline=headline,
        authors=authors,
        published=published,
        section=section,
        word_count=extraction.word_count,
        body_markdown=extraction.body_markdown,
        retrieved_at=fetch.retrieved_at,
        extraction=ExtractionMeta(
            extractor_name=extractor_name,
            extractor_version=extractor_version,
            raw_sha256=hashlib.sha256(fetch.raw_html).hexdigest(),
            assessment_schema_version=1,
            policy_version=provider.assessment_policy_version,
        ),
    )


def _metadata_text(metadata: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                if str(item).strip():
                    return str(item).strip()
    return ""


def _metadata_authors(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(str(part).strip() for part in value if str(part).strip())
    return ()


def parse_aware_datetime(value: object) -> datetime | None:
    """Parse an ISO timestamp only when it contains timezone information."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
