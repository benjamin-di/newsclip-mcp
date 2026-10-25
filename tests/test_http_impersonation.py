"""The HTTP fingerprint allowlist stays real, versioned and current."""

from __future__ import annotations

import re
from typing import get_args

import pytest
from curl_cffi.requests import BrowserTypeLiteral
from pydantic import ValidationError

from newsclip.models import (
    DEFAULT_HTTP_IMPERSONATION,
    HTTP_IMPERSONATION_PROFILES,
    ProviderCapabilities,
)
from newsclip.provider_config import load_builtin_provider_specs

_INSTALLED = frozenset(get_args(BrowserTypeLiteral))
_DESKTOP_CHROME = re.compile(r"^chrome(\d+)$")


def test_every_allowlisted_profile_is_an_installed_curl_cffi_target() -> None:
    """A curl_cffi upgrade that drops a target fails here, not on a live read."""

    assert HTTP_IMPERSONATION_PROFILES <= _INSTALLED


def test_no_allowlisted_profile_is_an_unversioned_chrome_alias() -> None:
    """``chrome`` silently follows the library; chrome146 aged under it."""

    assert "chrome" not in HTTP_IMPERSONATION_PROFILES
    with pytest.raises(ValidationError):
        ProviderCapabilities.model_validate({"http_impersonate": "chrome"})


def test_default_is_the_newest_installed_desktop_chrome_target() -> None:
    """Upgrading curl_cffi must move the default deliberately.

    FT's session routes cannot be re-pinned at runtime, so the default is the
    only fingerprint they ever present. Leaving it behind the library's newest
    Chrome target is how a refused fingerprint stays in service.
    """

    installed_majors = [
        int(match.group(1))
        for name in _INSTALLED
        if (match := _DESKTOP_CHROME.match(name)) is not None
    ]
    default = _DESKTOP_CHROME.match(DEFAULT_HTTP_IMPERSONATION)

    assert default is not None
    assert int(default.group(1)) == max(installed_majors)


def test_session_providers_resolve_to_the_default_profile() -> None:
    session_specs = [
        spec
        for spec in load_builtin_provider_specs()
        if spec.capabilities.session_kind != "none"
    ]

    assert session_specs
    assert {spec.capabilities.http_impersonate for spec in session_specs} == {
        DEFAULT_HTTP_IMPERSONATION
    }
