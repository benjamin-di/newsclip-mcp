"""Lossless rendering of Axios's scoped public article prose.

The ordinary precision extractor drops link-heavy Axios bullets. Render the
observed DOM instead; the embedded Draft.js blocks only verify completeness,
never supply text missing from the page or override an access gate.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from lxml import html

from ..assessment import document
from ..models import RawFetch

_PROSE_TYPES = {
    "unstyled",
    "unordered-list-item",
    "ordered-list-item",
    "blockquote",
    "header-one",
    "header-two",
    "header-three",
    "header-four",
}
_IGNORED_TYPES = {"keep-reading", "embed", "atomic"}


def story_document(fetch: RawFetch) -> tuple[html.HtmlElement, dict[str, Any]]:
    parsed = document(fetch.raw_html)
    if parsed is None:
        raise ValueError("axios_document_missing")
    scripts = parsed.xpath("//script[@id='__NEXT_DATA__']/text()")
    if len(scripts) != 1:
        raise ValueError("axios_story_ambiguous")
    try:
        story = json.loads(scripts[0])["props"]["pageProps"]["data"]["story"]
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise ValueError("axios_story_invalid") from error
    if not isinstance(story, dict) or not isinstance(story.get("permalink"), str):
        raise ValueError("axios_story_invalid")
    return parsed, story


def render_story(parsed: html.HtmlElement, story: dict[str, Any]) -> str:
    bodies = parsed.xpath("//*[@data-cy='story-body']")
    if len(bodies) != 1:
        raise ValueError("axios_body_ambiguous")
    bodies[0].make_links_absolute(story["permalink"], resolve_base_href=False)
    body = _render(bodies[0]).strip()
    # All textual narrative blocks must occur in order in the rendered body.
    # This catches truncated previews without imposing a long-story word floor.
    try:
        blocks = story["blocks"]["blocks"]
    except (KeyError, TypeError) as error:
        raise ValueError("axios_blocks_missing") from error
    if not isinstance(blocks, list) or not blocks:
        raise ValueError("axios_blocks_missing")
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", body)
    plain = re.sub(r"\\([\\`*\[\]_])", r"\1", plain)
    remaining = _words(plain)
    count = 0
    for block in blocks:
        if not isinstance(block, dict):
            raise ValueError("axios_block_invalid")
        kind = block.get("type")
        if not isinstance(kind, str):
            raise ValueError("axios_block_invalid")
        if kind in _IGNORED_TYPES:
            continue
        text = block.get("text")
        if kind not in _PROSE_TYPES or not isinstance(text, str):
            raise ValueError("axios_block_unsupported")
        expected = _words(text)
        if not expected:
            continue
        offset = remaining.find(expected)
        if offset < 0:
            raise ValueError("axios_body_incomplete")
        remaining = remaining[offset + len(expected) :]
        count += 1
    if not count or not body:
        raise ValueError("axios_body_missing")
    return body


def _words(value: str) -> str:
    return " ".join(re.findall(r"\w+", value.casefold()))


def _text(value: str | None) -> str:
    return re.sub(r"([\\`*\[\]_])", r"\\\1", re.sub(r"\s+", " ", value or ""))


def _emphasis(content: str, marker: str) -> str:
    """Preserve visible edge whitespace outside CommonMark delimiters."""

    core = content.strip()
    if not core:
        return " " if content else ""
    leading = " " if content[0].isspace() else ""
    trailing = " " if content[-1].isspace() else ""
    return f"{leading}{marker}{core}{marker}{trailing}"


def _render(node: html.HtmlElement, depth: int = 0) -> str:
    tag = node.tag
    if not isinstance(tag, str) or tag in {
        "script",
        "style",
        "noscript",
        "iframe",
        "button",
        "img",
        "svg",
    }:
        return ""
    if node.get("data-cy") == "mid-story-ad":
        return ""
    if tag in {"ul", "ol"}:
        lines = []
        for index, child in enumerate(node, 1):
            if child.tag != "li":
                raise ValueError("axios_list_unsupported")
            marker = f"{index}." if tag == "ol" else "-"
            content = _render(child, depth + 1).strip()
            lines.append(f"{'  ' * depth}{marker} {content}")
        return "\n" + "\n".join(lines) + "\n\n"
    if tag == "br":
        return "\n"
    content = _text(node.text) + "".join(
        _render(child, depth) + _text(child.tail) for child in node
    )
    if tag in {"strong", "b"}:
        return _emphasis(content, "**")
    if tag in {"em", "i"}:
        return _emphasis(content, "*")
    if tag == "a":
        href = node.get("href", "")
        parsed = urlsplit(href)
        if parsed.scheme in {"https", "http"} and parsed.hostname:
            href = href.replace("(", "%28").replace(")", "%29").replace(" ", "%20")
            return f"[{content}]({href})"
        return content
    if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
        return f"\n\n{'#' * int(tag[1])} {content.strip()}\n\n"
    if tag == "blockquote":
        return (
            "\n\n"
            + "\n".join("> " + line for line in content.strip().splitlines())
            + "\n\n"
        )
    if tag in {"p", "div", "figure", "figcaption"}:
        return "\n\n" + content.strip() + "\n\n" if content.strip() else ""
    if tag not in {"span", "li", "u", "sup", "sub"}:
        raise ValueError("axios_body_element_unsupported")
    return content
