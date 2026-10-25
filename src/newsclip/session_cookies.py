"""Strict, provider-neutral normalization for portable session cookies."""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime

from pydantic import ValidationError

from .models import PortableCookie, SameSite


class SessionCookieError(ValueError):
    """Base class for safe cookie-codec failures."""


class SessionCookiesMissing(SessionCookieError):
    """No provider-owned, usable browser session cookies were available."""


class SessionCookieFormatError(SessionCookieError):
    """Cookie input was present but structurally malformed."""


#: Cookie names issued by challenge vendors rather than by the publisher.
#: These carry no session authority: they attest that *one particular host*
#: — its address, its browser fingerprint — was found acceptable. Only the
#: PerimeterX names are evidenced (2026-07-28, a Bloomberg promotion), but
#: the reason is structural rather than vendor-specific, so the DataDome and
#: Cloudflare names are included on the same principle.
#:
#: Deliberately tighter than `bloomberg_auth._is_perimeterx_cookie`, which
#: matches a bare ``px`` prefix. That predicate only asks whether a defense
#: left a mark, where a false positive costs nothing; here a false positive
#: silently discards a real credential.
_CHALLENGE_VENDOR_COOKIE_NAMES = frozenset(
    {
        "pxcts",  # PerimeterX, the one name without the underscore prefix
        "datadome",
        "cf_clearance",
    }
)
_CHALLENGE_VENDOR_COOKIE_PREFIXES = ("_px", "__cf")


def is_challenge_vendor_cookie(name: str) -> bool:
    """Whether a cookie belongs to a bot-defense vendor, not the publisher."""

    lowered = name.strip().casefold()
    return lowered in _CHALLENGE_VENDOR_COOKIE_NAMES or lowered.startswith(
        _CHALLENGE_VENDOR_COOKIE_PREFIXES
    )


def normalize_cookie_import(
    payload: object,
    *,
    allowed_domains: frozenset[str],
    now: datetime,
) -> tuple[PortableCookie, ...]:
    """Normalize Cookie-Editor, browser, or Newsclip cookies into schema v1."""

    raw_cookies: object = payload
    if isinstance(payload, Mapping):
        _reject_storage_origins(payload)
        # A stored Newsclip session is itself a portable artifact. Accept its
        # nested cookie list directly so a verified generation can recover a
        # different state root without a secret-bearing conversion file.
        artifact = payload.get("artifact")
        if "artifact" in payload and not isinstance(artifact, Mapping):
            raise SessionCookieFormatError("session artifact must be an object")
        if isinstance(artifact, Mapping):
            payload = artifact
            _reject_storage_origins(payload)
        raw_cookies = payload.get("cookies")
    if not isinstance(raw_cookies, list):
        raise SessionCookieFormatError("cookie import must contain a cookie list")

    cookies: list[PortableCookie] = []
    for item in raw_cookies:
        normalized = _normalize_cookie(
            item,
            allowed_domains=allowed_domains,
            now=now,
        )
        if normalized is not None:
            cookies.append(normalized)
    if not cookies:
        raise SessionCookiesMissing("cookie import contains no usable cookies")
    return tuple(cookies)


def normalize_browser_cookie_export(
    payload: object,
    *,
    allowed_domains: frozenset[str],
    now: datetime,
) -> tuple[PortableCookie, ...]:
    """Select recipe-owned browser cookies, then normalize them strictly."""

    if not isinstance(payload, list):
        raise SessionCookieFormatError("browser cookie export must be a cookie list")
    selected: list[object] = []
    for item in payload:
        if not isinstance(item, Mapping):
            raise SessionCookieFormatError("browser cookie entry must be an object")
        domain = item.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            raise SessionCookieFormatError("browser cookie domain must be non-empty")
        if cookie_domain_allowed(domain, allowed_domains):
            selected.append(item)
    if not selected:
        raise SessionCookiesMissing("browser exported no provider-owned cookies")
    return normalize_cookie_import(
        selected,
        allowed_domains=allowed_domains,
        now=now,
    )


def _normalize_cookie(
    item: object,
    *,
    allowed_domains: frozenset[str],
    now: datetime,
) -> PortableCookie | None:
    if not isinstance(item, Mapping):
        raise SessionCookieFormatError("cookie entry must be an object")
    for key in ("name", "value", "domain"):
        if key not in item:
            raise SessionCookieFormatError(f"cookie entry is missing {key}")
    name = item["name"]
    value = item["value"]
    domain = item["domain"]
    if not isinstance(name, str) or not name.strip():
        raise SessionCookieFormatError("cookie name must be non-empty")
    if not isinstance(value, str):
        raise SessionCookieFormatError("cookie value must be a string")
    if not isinstance(domain, str) or not domain.strip():
        raise SessionCookieFormatError("cookie domain must be non-empty")
    if not cookie_domain_allowed(domain, allowed_domains):
        raise SessionCookieFormatError("cookie domain is not allowed")

    raw_expiry = item.get("expires", item.get("expirationDate"))
    expired = False
    expires: float | None
    if raw_expiry in (None, -1, 0, "") and not isinstance(raw_expiry, bool):
        expires = None
    elif (
        isinstance(raw_expiry, (int, float))
        and not isinstance(raw_expiry, bool)
        and math.isfinite(raw_expiry)
    ):
        expires = float(raw_expiry)
        expired = expires <= now.timestamp()
    else:
        raise SessionCookieFormatError("cookie expiry is invalid")

    same_site = _same_site(item.get("sameSite"))
    try:
        cookie = PortableCookie(
            name=name.strip(),
            value=value,
            domain=domain.strip(),
            path=item.get("path") or "/",
            expires=expires,
            secure=_strict_bool(item.get("secure", False), "secure"),
            http_only=_strict_bool(
                item.get("httpOnly", item.get("http_only", False)), "httpOnly"
            ),
            same_site=same_site,
        )
    except ValidationError:
        raise SessionCookieFormatError("cookie fields are invalid") from None
    return None if expired else cookie


def _same_site(value: object) -> SameSite | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SessionCookieFormatError("cookie SameSite is invalid")
    normalized = value.strip().lower().replace("_", "-")
    mapping: dict[str, SameSite | None] = {
        "strict": "Strict",
        "lax": "Lax",
        "none": "None",
        "no-restriction": "None",
        "unspecified": None,
        "": None,
    }
    if normalized not in mapping:
        raise SessionCookieFormatError("cookie SameSite is invalid")
    return mapping[normalized]


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise SessionCookieFormatError(f"cookie {field} must be boolean")
    return value


def _reject_storage_origins(payload: Mapping[object, object]) -> None:
    if "origins" not in payload:
        return
    origins = payload["origins"]
    if not isinstance(origins, list):
        raise SessionCookieFormatError("storage-state origins must be a list")
    if origins:
        raise SessionCookieFormatError(
            "storage-state origins are not portable cookie state"
        )


def cookie_domain_allowed(domain: str, allowed_domains: frozenset[str]) -> bool:
    candidate = domain.strip().lower().lstrip(".")
    return any(
        candidate == allowed.lower().lstrip(".")
        or candidate.endswith(f".{allowed.lower().lstrip('.')}")
        for allowed in allowed_domains
    )


__all__ = [
    "SessionCookieError",
    "SessionCookieFormatError",
    "SessionCookiesMissing",
    "cookie_domain_allowed",
    "is_challenge_vendor_cookie",
    "normalize_browser_cookie_export",
    "normalize_cookie_import",
]
