from __future__ import annotations

from datetime import UTC, datetime

import pytest

from newsclip.extraction import TrafilaturaExtractor
from newsclip.models import RawFetch

ARTICLE_URL = "https://fixture.test/articles/charset"
NOW = datetime(2026, 7, 28, tzinfo=UTC)
WINDOWS_TEXT = (
    "Café’s résumé explains euro-area markets – with correctly decoded punctuation. "
)


def _fetch(
    *,
    content_type: str | None,
    meta: str,
    encoding: str = "windows-1252",
) -> RawFetch:
    source = f"""
    <html><head>
      {meta}
      <title>Café’s market résumé</title>
      <link rel="canonical" href="{ARTICLE_URL}">
    </head><body><main><article>
      <h1>Café’s market résumé</h1>
      <p>{WINDOWS_TEXT * 12}</p>
    </article></main></body></html>
    """
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type=content_type,
        retrieved_at=NOW,
        raw_html=source.encode(encoding),
    )


@pytest.mark.parametrize(
    ("content_type", "meta"),
    [
        (
            'text/html; charset="Windows-1252"',
            '<meta charset="utf-8">',
        ),
        (
            "text/html",
            '<meta charset="windows-1252">',
        ),
        (
            "text/html; charset=unknown-fixture-encoding",
            (
                '<meta http-equiv="Content-Type" '
                'content="text/html; charset=windows-1252">'
            ),
        ),
    ],
)
def test_extraction_uses_header_then_meta_charset(
    content_type: str,
    meta: str,
) -> None:
    extraction = TrafilaturaExtractor().extract(
        _fetch(content_type=content_type, meta=meta)
    )

    assert "Café’s résumé" in extraction.body_markdown
    assert extraction.metadata["title"] == "Café’s market résumé"
    assert "\ufffd" not in extraction.body_markdown
    assert "\ufffd" not in extraction.metadata["title"]


@pytest.mark.parametrize("content_type", ("text/html", None))
def test_extraction_falls_back_to_utf8_without_a_declaration(
    content_type: str | None,
) -> None:
    extraction = TrafilaturaExtractor().extract(
        _fetch(
            content_type=content_type,
            meta="",
            encoding="utf-8",
        )
    )

    assert "Café’s résumé" in extraction.body_markdown
    assert "\ufffd" not in extraction.body_markdown
