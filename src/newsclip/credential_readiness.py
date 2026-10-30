"""Inert provider login prerequisite checks shared by doctor and acquisition."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from shutil import which
from typing import TYPE_CHECKING, cast

from signin_window.automation.secrets import OpSecretReader, load_credential_reader

from .maintenance import credential_reader_factory, planner_configured
from .models import LoginRequirement, ProviderReadiness
from .vision_cli import VisionProvider, vision_environment

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


def vision_auth_available(provider: VisionProvider) -> bool:
    """Ask the selected CLI for local login status, without a model request.

    A local grant is a prerequisite, not proof that a remote service will
    accept it. Never emit status output (which may contain account details).
    Use the same restricted environment as the actual vision child.
    """
    command = (
        [provider, "login", "status"]
        if provider == "codex"
        else [provider, "auth", "status", "--json"]
    )
    try:
        result = subprocess.run(
            command,
            env=vision_environment(provider),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            return False
        if provider == "claude":
            status = json.loads(result.stdout)
            return isinstance(status, dict) and status.get("loggedIn") is True
        return True
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False


def check_credential_readiness(
    provider: str,
    *,
    require_vision: bool = False,
    require_native_input: bool = False,
    vision_provider: VisionProvider | None = None,
) -> ProviderReadiness:
    """Check credential-mint tools without reading a secret or contacting a provider.

    With an explicitly configured planner factory, planning needs no local CLI;
    its reachability is not probed here.
    """

    missing: list[LoginRequirement] = []
    selected_reader = credential_reader_factory()
    if selected_reader:
        try:
            if not load_credential_reader(selected_reader).available:
                missing.append(LoginRequirement.CREDENTIAL_READER)
        except Exception:
            missing.append(LoginRequirement.CREDENTIAL_READER)
    else:
        if which("op") is None:
            missing.append(LoginRequirement.OP_CLI)
        # The reader's own identity: a 1Password Connect server or a service account.
        if not OpSecretReader().has_token:
            missing.append(LoginRequirement.OP_SERVICE_TOKEN)
    if require_vision and (
        not planner_configured() or os.environ.get("NEWSCLIP_VISION_PLANNER") == "local"
    ):
        selected = (
            vision_provider
            or os.environ.get("AGENT_PROVIDER", "codex").strip().casefold()
        )
        if selected not in {"codex", "claude"} or which(selected) is None:
            missing.append(LoginRequirement.VISION_CLI)
        elif not vision_auth_available(cast(VisionProvider, selected)):
            missing.append(LoginRequirement.VISION_AUTH)
    if require_native_input and not native_input_available():
        missing.append(LoginRequirement.NATIVE_INPUT)
    return ProviderReadiness(provider=provider, missing=tuple(missing))


__all__ = [
    "browser_engine_available",
    "check_credential_readiness",
    "native_input_available",
]
