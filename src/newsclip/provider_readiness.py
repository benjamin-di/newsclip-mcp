"""Inert browser prerequisites; no credential or account access."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

# Public compatibility imports; these checks do not read credentials.
from .credential_readiness import (
    check_credential_readiness as check_credential_readiness,
)
from .credential_readiness import (
    vision_auth_available as vision_auth_available,
)

if TYPE_CHECKING:
    from patchright.sync_api import PlaywrightContextManager


def sync_playwright() -> PlaywrightContextManager:
    """Lazy alias for Patchright's entry point; keeps startup free of its import."""

    from patchright.sync_api import sync_playwright as patchright_sync_playwright

    return patchright_sync_playwright()


def browser_engine_available() -> bool:
    """Return whether Patchright's configured Chromium executable is installed."""

    try:
        with sync_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
            return executable.is_file() and os.access(executable, os.X_OK)
    except Exception:
        return False


def native_input_available() -> bool:
    """Return whether real X11 input events can be synthesized on this host.

    Checks the XTEST client library rather than a display: the display is
    created per operation, but a missing library makes native input
    impossible for the whole process.
    """

    try:
        import ctypes.util

        return ctypes.util.find_library("Xtst") is not None
    except Exception:  # noqa: BLE001 - absence is the only answer that matters
        return False
