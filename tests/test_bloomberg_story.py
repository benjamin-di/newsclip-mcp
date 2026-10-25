from __future__ import annotations

import json

import pytest

from newsclip.providers.bloomberg_story import (
    BloombergStoryState,
    extract_bloomberg_story,
    is_bloomberg_story_extraction,
)

ARTICLE_URL = "https://www.bloomberg.com/news/articles/2026-07-24/generated-story"


def _text(value: str) -> dict[str, object]:
    return {"type": "text", "value": value}


def _component(component_type: str, value: str) -> dict[str, object]:
    return {"type": component_type, "content": [_text(value)]}


def _html(
    content: list[object],
    *,
    body_type: str = "document",
    story_update: dict[str, object] | None = None,
) -> bytes:
    story: dict[str, object] = {
        "id": "GENERATED-STORY-ID",
        "seoCanonical": ARTICLE_URL,
        "headline": "Generated Bloomberg Fixture",
        "publishedAt": "2026-07-24T06:00:00Z",
        "authors": [{"name": "Fixture Author"}, {"name": "Fixture Editor"}],
        "body": {"type": body_type, "content": content},
    }
    story.update(story_update or {})
    payload = {"props": {"pageProps": {"story": story}}}
    return (
        "<html><head><script id='__NEXT_DATA__' type='application/json'>"
        f"{json.dumps(payload)}</script></head><body></body></html>"
    ).encode()


def test_extracts_recognized_story_components_in_source_order() -> None:
    result = extract_bloomberg_story(
        _html(
            [
                {"type": "inline-newsletter", "data": {"id": "fixture"}},
                {
                    "type": "paragraph",
                    "data": {"value": "Non-narrative component metadata."},
                    "content": [_text("First generated paragraph.")],
                },
                {
                    "type": "heading",
                    "data": {"level": 3},
                    "content": [_text("Generated heading")],
                },
                {
                    "type": "blockquote",
                    "content": [
                        _component("paragraph", "Generated quotation."),
                    ],
                },
                {
                    "type": "list",
                    "content": [
                        _component("listItem", "First generated item."),
                        _component("listItem", "Second generated item."),
                    ],
                },
                {
                    "type": "tabularData",
                    "content": [
                        {
                            "type": "row",
                            "content": [
                                _component("cell", "Generated cell one."),
                                _component("cell", "Generated cell two."),
                            ],
                        }
                    ],
                },
                {
                    "type": "ad",
                    "data": {
                        "position": "body",
                        "value": "Non-narrative advertisement metadata.",
                    },
                },
                {"type": "media", "data": {"id": "generated-image"}},
            ]
        )
    )

    assert result.state is BloombergStoryState.VALID
    assert result.reason == "story_valid"
    candidate = result.candidate
    assert candidate is not None
    assert candidate.canonical_url == ARTICLE_URL
    assert candidate.headline == "Generated Bloomberg Fixture"
    assert candidate.narrative_block_count == 5
    assert candidate.paragraph_count == 1
    assert candidate.paragraph_character_counts == (26,)
    assert candidate.extraction.body_markdown == (
        "First generated paragraph.\n\n"
        "### Generated heading\n\n"
        "> Generated quotation.\n\n"
        "- First generated item.\n"
        "- Second generated item.\n\n"
        "- Generated cell one.\n"
        "- Generated cell two."
    )
    assert candidate.extraction.metadata == {
        "title": "Generated Bloomberg Fixture",
        "url": ARTICLE_URL,
        "_newsclip_source": "bloomberg_next_story",
        "date": "2026-07-24T06:00:00Z",
        "author": ["Fixture Author", "Fixture Editor"],
    }
    assert is_bloomberg_story_extraction(candidate.extraction) is True
    assert len(candidate.body_sha256) == 64


def test_body_fingerprint_is_stable_for_equivalent_json_key_order() -> None:
    first = extract_bloomberg_story(
        _html([_component("paragraph", "Generated narrative.")])
    )
    second = extract_bloomberg_story(
        _html(
            [
                {
                    "content": [{"value": "Generated narrative.", "type": "text"}],
                    "type": "paragraph",
                }
            ]
        )
    )

    assert first.candidate is not None
    assert second.candidate is not None
    assert first.candidate.body_sha256 == second.candidate.body_sha256


@pytest.mark.parametrize(
    ("raw_html", "state", "reason"),
    [
        (
            b"<html><body>Generated document without Next data.</body></html>",
            BloombergStoryState.ABSENT,
            "next_data_absent",
        ),
        (
            b"<html><head><script id='__NEXT_DATA__'>{</script></head></html>",
            BloombergStoryState.INVALID,
            "next_data_invalid",
        ),
        (
            (
                b"<html><head><script id='__NEXT_DATA__'>{}</script>"
                b"<script id='__NEXT_DATA__'>{}</script></head></html>"
            ),
            BloombergStoryState.INVALID,
            "next_data_ambiguous",
        ),
        (
            b"<html><head><script id='__NEXT_DATA__'>{}</script></head></html>",
            BloombergStoryState.INVALID,
            "story_object_missing",
        ),
    ],
)
def test_distinguishes_absent_from_invalid_payloads(
    raw_html: bytes,
    state: BloombergStoryState,
    reason: str,
) -> None:
    result = extract_bloomberg_story(raw_html)

    assert result.state is state
    assert result.reason == reason
    assert result.candidate is None


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (
            [_component("interactive-chart", "Generated chart description.")],
            "unknown_text_component",
        ),
        (
            [_component("inline-newsletter", "Generated newsletter copy.")],
            "ignored_component_contains_text",
        ),
        ([{"type": "paragraph", "content": []}], "story_body_empty"),
        ([{"content": [_text("Generated text.")]}], "story_component_type_missing"),
    ],
)
def test_rejects_text_that_cannot_be_losslessly_classified(
    content: list[object],
    reason: str,
) -> None:
    result = extract_bloomberg_story(_html(content))

    assert result.state is BloombergStoryState.INVALID
    assert result.reason == reason
    assert result.candidate is None


def test_rejects_unrecognized_document_root() -> None:
    result = extract_bloomberg_story(
        _html([_component("paragraph", "Generated narrative.")], body_type="page")
    )

    assert result.state is BloombergStoryState.INVALID
    assert result.reason == "story_body_root_invalid"
