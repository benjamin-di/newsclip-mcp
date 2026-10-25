"""Canonical validation for public account identifiers."""

from __future__ import annotations

import re

ACCOUNT_KEY_PATTERN = r"^[a-zA-Z0-9_-]{1,64}$"
_ACCOUNT_KEY = re.compile(ACCOUNT_KEY_PATTERN)


def is_account_key(value: object) -> bool:
    """Return whether *value* is a bounded, path-safe account key."""

    return isinstance(value, str) and _ACCOUNT_KEY.fullmatch(value) is not None


def require_account_key(value: object) -> str:
    """Return a valid account key or raise a stable boundary error."""

    if not is_account_key(value):
        raise ValueError("invalid account key")
    assert isinstance(value, str)
    return value


__all__ = ["ACCOUNT_KEY_PATTERN", "is_account_key", "require_account_key"]
