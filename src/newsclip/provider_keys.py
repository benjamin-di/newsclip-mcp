"""Canonical validation for provider identifiers."""

from __future__ import annotations

import re

PROVIDER_KEY_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
_PROVIDER_KEY = re.compile(PROVIDER_KEY_PATTERN)


def is_provider_key(value: object) -> bool:
    """Return whether *value* is safe and valid at every provider boundary."""

    return isinstance(value, str) and _PROVIDER_KEY.fullmatch(value) is not None
