from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from newsclip.browser_runtime import ObservedNavigation
from newsclip.browser_verification import (
    capture_verification_fetch,
    verification_fetch_from_snapshot,
)
from newsclip.errors import ProviderTransportError
from newsclip.providers.wsj import WSJLoginRecipe

NOW = datetime(2026, 7, 23, tzinfo=UTC)
ARTICLE_URL = "https://www.wsj.com/finance/fixture-story-1a2b3c4d"
FIXTURES = Path(__file__).parent / "fixtures" / "wsj"


def _page(url: str, html: str = "<html><body>fixture</body></html>") -> object:
    return SimpleNamespace(url=url, content=lambda: html)


def test_capture_preserves_only_observed_navigation_facts() -> None:
    observed = ObservedNavigation(
        status=206,
        response_url=f"{ARTICLE_URL}#response-fragment",
        content_type="text/html; charset=utf-8",
    )

    fetch = capture_verification_fetch(
        ARTICLE_URL,
        observed,
        _page(f"{ARTICLE_URL}#page-fragment"),
        retrieved_at=NOW,
        session_cookie_present=True,
    )

    assert str(fetch.requested_url) == ARTICLE_URL
    assert str(fetch.final_url) == observed.response_url
    assert fetch.http_status == 206
    assert fetch.content_type == "text/html; charset=utf-8"
    assert fetch.retrieved_at == NOW
    assert fetch.session_cookie_present is True
    assert fetch.raw_html == b"<html><body>fixture</body></html>"


def test_precaptured_snapshot_preserves_only_observed_navigation_facts() -> None:
    observed = ObservedNavigation(
        status=206,
        response_url=f"{ARTICLE_URL}#response-fragment",
        content_type="text/html; charset=utf-8",
    )

    fetch = verification_fetch_from_snapshot(
        ARTICLE_URL,
        observed,
        document_url=f"{ARTICLE_URL}#page-fragment",
        raw_html=b"<html><body>bounded fixture</body></html>",
        retrieved_at=NOW,
        session_cookie_present=True,
    )

    assert str(fetch.final_url) == observed.response_url
    assert fetch.http_status == 206
    assert fetch.raw_html == b"<html><body>bounded fixture</body></html>"


def test_precaptured_snapshot_rejects_a_different_document() -> None:
    with pytest.raises(ProviderTransportError, match="document changed"):
        verification_fetch_from_snapshot(
            ARTICLE_URL,
            ObservedNavigation(200, ARTICLE_URL, "text/html"),
            document_url=f"{ARTICLE_URL}?replacement=1",
            raw_html=b"<html><body>stale fixture</body></html>",
            retrieved_at=NOW,
            session_cookie_present=True,
        )


def test_capture_treats_default_and_explicit_ports_as_the_same_document() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, None)
    explicit_port = ARTICLE_URL.replace(
        "https://www.wsj.com", "https://www.wsj.com:443"
    )

    fetch = capture_verification_fetch(
        ARTICLE_URL,
        observed,
        _page(explicit_port),
        retrieved_at=NOW,
        session_cookie_present=False,
    )

    assert fetch.content_type is None


@pytest.mark.parametrize("status", (True, 99, 600))
def test_capture_rejects_invalid_status(status: object) -> None:
    with pytest.raises(ProviderTransportError, match="status"):
        capture_verification_fetch(
            ARTICLE_URL,
            ObservedNavigation(status, ARTICLE_URL, "text/html"),  # type: ignore[arg-type]
            _page(ARTICLE_URL),
            retrieved_at=NOW,
            session_cookie_present=False,
        )


def test_capture_rejects_a_different_current_document() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "text/html")

    with pytest.raises(ProviderTransportError, match="document changed"):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            _page(f"{ARTICLE_URL}?replacement=1"),
            retrieved_at=NOW,
            session_cookie_present=False,
        )


def test_capture_rejects_document_replacement_during_content_read() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "text/html")
    page = SimpleNamespace(url=ARTICLE_URL)

    def content() -> str:
        page.url = "https://www.wsj.com/finance/replacement-1a2b3c4d"
        return "<html><body>stale fixture</body></html>"

    page.content = content

    with pytest.raises(ProviderTransportError, match="document changed"):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            page,
            retrieved_at=NOW,
            session_cookie_present=False,
        )


def test_capture_rejects_explicit_non_html_response() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "application/json")

    with pytest.raises(ProviderTransportError, match="not HTML"):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            _page(ARTICLE_URL),
            retrieved_at=NOW,
            session_cookie_present=False,
        )


@pytest.mark.parametrize(
    ("page", "message"),
    (
        (SimpleNamespace(url=ARTICLE_URL), "unavailable"),
        (SimpleNamespace(url=ARTICLE_URL, content=lambda: b"not text"), "invalid"),
    ),
)
def test_capture_rejects_unavailable_or_invalid_content(
    page: object,
    message: str,
) -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "text/html")

    with pytest.raises(ProviderTransportError, match=message):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            page,
            retrieved_at=NOW,
            session_cookie_present=False,
        )


def test_capture_maps_content_read_failure_to_transport_error() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "text/html")

    def content() -> str:
        raise RuntimeError("fixture page disappeared")

    with pytest.raises(ProviderTransportError, match="capture failed"):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            SimpleNamespace(url=ARTICLE_URL, content=content),
            retrieved_at=NOW,
            session_cookie_present=False,
        )


def test_capture_maps_invalid_response_metadata_to_transport_error() -> None:
    observed = ObservedNavigation(200, ARTICLE_URL, "text/html")

    with pytest.raises(ProviderTransportError, match="metadata is invalid"):
        capture_verification_fetch(
            ARTICLE_URL,
            observed,
            _page(ARTICLE_URL),
            retrieved_at=NOW.replace(tzinfo=None),
            session_cookie_present=False,
        )


def test_recipe_verification_preserves_observed_non_success_status() -> None:
    fetch = capture_verification_fetch(
        ARTICLE_URL,
        ObservedNavigation(403, ARTICLE_URL, "text/html"),
        _page(
            ARTICLE_URL,
            (FIXTURES / "verification_full.html").read_text(encoding="utf-8"),
        ),
        retrieved_at=NOW,
        session_cookie_present=True,
    )

    verification = WSJLoginRecipe(verification_url=ARTICLE_URL).verify_fetch(fetch)

    assert verification.verified is False
    assert verification.reason == "http_forbidden"
    assert verification.verified_at == NOW


@pytest.mark.parametrize(
    ("fixture_name", "reason"),
    (
        ("teaser.html", "paywall_teaser"),
        ("initial_excerpt.html", "paywall_teaser"),
    ),
)
def test_recipe_verification_rejects_teaser_and_short_body(
    fixture_name: str,
    reason: str,
) -> None:
    fetch = capture_verification_fetch(
        ARTICLE_URL,
        ObservedNavigation(200, ARTICLE_URL, "text/html"),
        _page(
            ARTICLE_URL,
            (FIXTURES / fixture_name).read_text(encoding="utf-8"),
        ),
        retrieved_at=NOW,
        session_cookie_present=True,
    )

    verification = WSJLoginRecipe(verification_url=ARTICLE_URL).verify_fetch(fetch)

    assert verification.verified is False
    assert verification.reason == reason
