"""Strict extraction of Bloomberg's embedded Next.js story document."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..assessment import document
from ..models import ExtractedArticle

_NARRATIVE_COMPONENTS = frozenset(
    {
        "paragraph",
        "heading",
        "blockquote",
        "list",
        "tabularData",
    }
)
_IGNORED_COMPONENTS = frozenset(
    {
        "ad",
        "embed",
        "image",
        "inline-newsletter",
        "media",
    }
)
_DOCUMENT_TYPES = frozenset({"doc", "document"})
_EXTRACTION_SOURCE = "bloomberg_next_story"


class BloombergStoryState(StrEnum):
    """Closed parse result for an embedded Bloomberg story."""

    ABSENT = "absent"
    INVALID = "invalid"
    VALID = "valid"


@dataclass(frozen=True)
class BloombergStoryCandidate:
    """Provider-native story body plus identity and reproducibility facts."""

    extraction: ExtractedArticle
    canonical_url: str
    headline: str
    body_sha256: str
    narrative_block_count: int
    paragraph_count: int
    paragraph_character_counts: tuple[int, ...]
    narrative_character_counts: tuple[int, ...]


@dataclass(frozen=True)
class BloombergStoryResult:
    """Typed structured-story result; invalid never falls back silently."""

    state: BloombergStoryState
    reason: str
    candidate: BloombergStoryCandidate | None = None

    def __post_init__(self) -> None:
        if (self.state is BloombergStoryState.VALID) != (self.candidate is not None):
            raise ValueError("Bloomberg story state and candidate are inconsistent")


def extract_bloomberg_story(raw_html: bytes) -> BloombergStoryResult:
    """Extract one complete, recognized story document from ``__NEXT_DATA__``."""

    parsed = document(raw_html)
    if parsed is None:
        return BloombergStoryResult(
            state=BloombergStoryState.ABSENT,
            reason="html_document_absent",
        )
    scripts = parsed.xpath("//script[@id='__NEXT_DATA__']/text()")
    if not scripts:
        return BloombergStoryResult(
            state=BloombergStoryState.ABSENT,
            reason="next_data_absent",
        )
    if len(scripts) != 1:
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="next_data_ambiguous",
        )
    try:
        payload = json.loads(scripts[0])
    except (json.JSONDecodeError, TypeError, RecursionError):
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="next_data_invalid",
        )
    story = _nested_dict(payload, "props", "pageProps", "story")
    if story is None:
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="story_object_missing",
        )
    canonical_url = _clean_string(story.get("seoCanonical"))
    headline = _clean_string(story.get("headline"))
    if canonical_url is None or headline is None:
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="story_identity_missing",
        )
    body = story.get("body")
    if not isinstance(body, dict) or body.get("type") not in _DOCUMENT_TYPES:
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="story_body_root_invalid",
        )
    content = body.get("content")
    if not isinstance(content, list):
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="story_body_content_invalid",
        )

    rendered: list[str] = []
    narrative_blocks = 0
    paragraph_character_counts: list[int] = []
    narrative_character_counts: list[int] = []
    for component in content:
        if not isinstance(component, dict):
            return BloombergStoryResult(
                state=BloombergStoryState.INVALID,
                reason="story_component_invalid",
            )
        component_type = component.get("type")
        if not isinstance(component_type, str):
            return BloombergStoryResult(
                state=BloombergStoryState.INVALID,
                reason="story_component_type_missing",
            )
        if component_type in _IGNORED_COMPONENTS:
            if _text_values(component):
                return BloombergStoryResult(
                    state=BloombergStoryState.INVALID,
                    reason="ignored_component_contains_text",
                )
            continue
        if component_type not in _NARRATIVE_COMPONENTS:
            if _text_values(component):
                return BloombergStoryResult(
                    state=BloombergStoryState.INVALID,
                    reason="unknown_text_component",
                )
            continue
        block = _render_component(component_type, component)
        if not block:
            continue
        rendered.append(block)
        narrative_blocks += 1
        # Bloomberg carries most of a market wrap inside one list or table
        # block, so body size has to be measured per narrative block, not per
        # paragraph. Paragraph counts stay available as the narrower fact.
        block_characters = len(_normalized_text(component))
        narrative_character_counts.append(block_characters)
        if component_type == "paragraph":
            paragraph_character_counts.append(block_characters)

    body_markdown = "\n\n".join(rendered).strip()
    if not body_markdown:
        return BloombergStoryResult(
            state=BloombergStoryState.INVALID,
            reason="story_body_empty",
        )
    authors = _authors(story.get("authors"))
    metadata: dict[str, Any] = {
        "title": headline,
        "url": canonical_url,
        "_newsclip_source": _EXTRACTION_SOURCE,
    }
    published = _clean_string(story.get("publishedAt"))
    if published is not None:
        metadata["date"] = published
    if authors:
        metadata["author"] = authors
    canonical_body = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return BloombergStoryResult(
        state=BloombergStoryState.VALID,
        reason="story_valid",
        candidate=BloombergStoryCandidate(
            extraction=ExtractedArticle(
                body_markdown=body_markdown,
                metadata=metadata,
                word_count=len(body_markdown.split()),
            ),
            canonical_url=canonical_url,
            headline=headline,
            body_sha256=hashlib.sha256(canonical_body).hexdigest(),
            narrative_block_count=narrative_blocks,
            paragraph_count=len(paragraph_character_counts),
            paragraph_character_counts=tuple(paragraph_character_counts),
            narrative_character_counts=tuple(narrative_character_counts),
        ),
    )


def is_bloomberg_story_extraction(extraction: ExtractedArticle) -> bool:
    """Return whether an extraction came from the strict embedded-story path."""

    return extraction.metadata.get("_newsclip_source") == _EXTRACTION_SOURCE


def _render_component(component_type: str, component: dict[str, object]) -> str:
    if component_type == "list":
        items = _nodes_of_type(component, "listItem")
        values = [_normalized_text(item) for item in items]
        return "\n".join(f"- {value}" for value in values if value)
    if component_type == "tabularData":
        cells = _nodes_of_type(component, "cell")
        values = [_normalized_text(cell) for cell in cells]
        return "\n".join(f"- {value}" for value in values if value)

    value = _normalized_text(component)
    if not value:
        return ""
    if component_type == "heading":
        level = 2
        data = component.get("data")
        if isinstance(data, dict) and isinstance(data.get("level"), int):
            level = min(max(data["level"], 2), 6)
        return f"{'#' * level} {value}"
    if component_type == "blockquote":
        return "\n".join(f"> {line}" for line in value.splitlines())
    return value


def _normalized_text(value: object) -> str:
    return " ".join("".join(_text_values(value)).split())


def _text_values(value: object) -> list[str]:
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(_text_values(item))
        return values
    if not isinstance(value, dict):
        return []
    if value.get("type") == "text" and isinstance(value.get("value"), str):
        return [value["value"]]
    return _text_values(value.get("content"))


def _nodes_of_type(value: object, expected: str) -> list[dict[str, object]]:
    if isinstance(value, list):
        nodes: list[dict[str, object]] = []
        for item in value:
            nodes.extend(_nodes_of_type(item, expected))
        return nodes
    if not isinstance(value, dict):
        return []
    if value.get("type") == expected:
        return [value]
    return _nodes_of_type(value.get("content"), expected)


def _nested_dict(value: object, *path: str) -> dict[str, object] | None:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _clean_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    return cleaned or None


def _authors(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    authors: list[str] = []
    for item in value:
        if isinstance(item, str):
            name = _clean_string(item)
        elif isinstance(item, dict):
            name = _clean_string(item.get("name"))
        else:
            name = None
        if name is not None and name not in authors:
            authors.append(name)
    return authors


__all__ = [
    "BloombergStoryCandidate",
    "BloombergStoryResult",
    "BloombergStoryState",
    "extract_bloomberg_story",
    "is_bloomberg_story_extraction",
]
