"""Optional installation-specific integration, absent from standalone builds."""

from __future__ import annotations

from functools import cache
from importlib import import_module
from types import ModuleType


@cache
def local_extensions() -> ModuleType | None:
    try:
        return import_module("newsclip.local_extensions")
    except ModuleNotFoundError as error:
        if error.name != "newsclip.local_extensions":
            raise
        return None
