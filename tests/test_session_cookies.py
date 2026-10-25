from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
    is_challenge_vendor_cookie,
    normalize_browser_cookie_export,
    normalize_cookie_import,
)

NOW = datetime(2026, 7, 23, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()


def _cookie(**updates: object) -> dict[str, object]:
    cookie: dict[str, object] = {
        "name": "session",
        "value": "SESSION_VALUE",
        "domain": ".example.com",
        "path": "/content",
        "expires": FUTURE,
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
    }
    cookie.update(updates)
    return cookie


def test_cookie_error_taxonomy_remains_value_error_compatible() -> None:
    assert issubclass(SessionCookieError, ValueError)
    assert issubclass(SessionCookiesMissing, SessionCookieError)
    assert issubclass(SessionCookieFormatError, SessionCookieError)


def test_cookie_codec_preserves_the_portable_schema() -> None:
    normalized = normalize_cookie_import(
        [_cookie()],
        allowed_domains=frozenset({"example.com"}),
        now=NOW,
    )

    assert normalized[0].model_dump() == {
        "name": "session",
        "value": "SESSION_VALUE",
        "domain": ".example.com",
        "path": "/content",
        "expires": FUTURE,
        "secure": True,
        "http_only": True,
        "same_site": "Lax",
    }


@pytest.mark.parametrize(
    "payload",
    (
        None,
        (_cookie(),),
        ["not-an-object"],
        [{"name": "session"}],
        [_cookie(value=1)],
        [_cookie(domain=".other.example")],
        [_cookie(path="content")],
        [_cookie(expires="tomorrow")],
        [_cookie(expires=True)],
        [_cookie(secure="true")],
        [_cookie(httpOnly=1)],
        [_cookie(sameSite="Sometimes")],
        [
            _cookie(
                expires=(NOW - timedelta(seconds=1)).timestamp(),
                secure="true",
            )
        ],
    ),
)
def test_cookie_import_classifies_malformed_input(
    payload: object,
) -> None:
    with pytest.raises(SessionCookieFormatError):
        normalize_cookie_import(
            payload,
            allowed_domains=frozenset({"example.com"}),
            now=NOW,
        )


@pytest.mark.parametrize(
    "payload",
    (
        [],
        [_cookie(expires=(NOW - timedelta(seconds=1)).timestamp())],
    ),
)
def test_cookie_import_classifies_absent_or_expired_input(
    payload: object,
) -> None:
    with pytest.raises(SessionCookiesMissing):
        normalize_cookie_import(
            payload,
            allowed_domains=frozenset({"example.com"}),
            now=NOW,
        )


def test_browser_export_ignores_third_party_state_and_keeps_provider_state() -> None:
    normalized = normalize_browser_cookie_export(
        [_cookie(), _cookie(name="analytics", domain=".analytics.test")],
        allowed_domains=frozenset({"example.com"}),
        now=NOW,
    )

    assert [cookie.name for cookie in normalized] == ["session"]


@pytest.mark.parametrize("payload", ([], [_cookie(domain=".other.example")]))
def test_browser_export_classifies_missing_provider_state(payload: object) -> None:
    with pytest.raises(SessionCookiesMissing):
        normalize_browser_cookie_export(
            payload,
            allowed_domains=frozenset({"example.com"}),
            now=NOW,
        )


@pytest.mark.parametrize(
    "payload",
    (
        None,
        (_cookie(),),
        ["not-an-object"],
        [{"domain": 1}],
        [_cookie(secure="true")],
    ),
)
def test_browser_export_classifies_malformed_state(payload: object) -> None:
    with pytest.raises(SessionCookieFormatError):
        normalize_browser_cookie_export(
            payload,
            allowed_domains=frozenset({"example.com"}),
            now=NOW,
        )


@pytest.mark.parametrize(
    "payload",
    (
        {"cookies": [_cookie()], "origins": "not-a-list"},
        {"cookies": [_cookie()], "origins": [{"origin": "https://example.com"}]},
        {
            "artifact": {"cookies": [_cookie()]},
            "origins": [{"origin": "https://example.com"}],
        },
        {"artifact": "not-an-object", "cookies": [_cookie()]},
    ),
)
def test_cookie_import_rejects_ambiguous_storage_state(payload: object) -> None:
    with pytest.raises(SessionCookieFormatError):
        normalize_cookie_import(
            payload,
            allowed_domains=frozenset({"example.com"}),
            now=NOW,
        )


@pytest.mark.parametrize(
    "name",
    [
        "_px2",
        "_px3",
        "_pxhd",
        "_pxvid",
        "_pxde",
        "pxcts",
        "PXCTS",
        "datadome",
        "cf_clearance",
        "__cf_bm",
    ],
)
def test_challenge_vendor_cookies_are_recognized(name: str) -> None:
    """Recognize known challenge-cookie names independently of their values."""

    assert is_challenge_vendor_cookie(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "session",
        "pxu_session",  # a bare "px" prefix must not be enough
        "proxy_token",
        "bb_session",
        "_gcl_au",
        "cfid",
        "sid",
        "access_token",
    ],
)
def test_publisher_cookies_are_not_mistaken_for_defense_cookies(name: str) -> None:
    """A false positive here silently discards a real credential, so the
    predicate is deliberately tighter than the detection-only one in
    `bloomberg_auth`, which matches a bare `px` prefix."""

    assert is_challenge_vendor_cookie(name) is False
