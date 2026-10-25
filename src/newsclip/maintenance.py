"""Explicit, account-scoped maintenance configuration.

Site policy stays in Newsclip. Planner implementations and credential references
are supplied by an operator; importing this module performs no maintenance.
"""

from __future__ import annotations

import importlib
import json
import os

from pydantic import Field
from signin_window.state import read_private_file

from .models import FrozenModel
from .tenancy import application_root


class ProviderSettings(FrozenModel):
    credential_reference: str | None = Field(
        default=None, pattern=r"^op://[^/\r\n{}]+/[^/\r\n{}]+$"
    )
    api_key_reference: str | None = None


class MaintenanceSettings(FrozenModel):
    version: int = Field(default=1, ge=1, le=1)
    providers: dict[str, ProviderSettings] = Field(default_factory=dict)


def settings() -> MaintenanceSettings:
    """Read this user's settings; never fall back to another user's references."""
    path = application_root("NEWSCLIP_CONFIG_HOME", ".config") / "maintenance.json"
    try:
        payload = read_private_file(path, max_bytes=65536)
    except FileNotFoundError:
        return MaintenanceSettings()
    return MaintenanceSettings.model_validate(json.loads(payload))


def provider_settings(key: str, payload: dict) -> dict:
    configured = settings().providers.get(key)
    if configured is None:
        return payload
    if "session" in payload and configured.credential_reference:
        payload["session"]["secret_ref"] = configured.credential_reference
    if configured.api_key_reference and "search" in payload:
        payload["search"]["api_key_ref"] = configured.api_key_reference
    return payload


def planner_configured() -> bool:
    return bool(os.environ.get("NEWSCLIP_VISION_PLANNER", "").strip())


def vision_planner():
    """Load an explicitly selected planner, independent of credential access.

    ``local`` selects the bounded local CLI adapter. ``module:factory`` selects
    a zero-argument factory installed by an operator. No backend is discovered
    implicitly; deployments can keep their runner transport outside Newsclip.
    """
    selected = os.environ.get("NEWSCLIP_VISION_PLANNER", "").strip()
    if not selected:
        return None
    if selected == "local":
        from .vision_planning import LocalCliVisionPlanner

        return LocalCliVisionPlanner()
    module, separator, attribute = selected.partition(":")
    if not separator or not module or not attribute.isidentifier():
        raise ValueError("NEWSCLIP_VISION_PLANNER must be local or module:factory")
    planner = getattr(importlib.import_module(module), attribute)()
    if not callable(getattr(planner, "plan", None)):
        raise ValueError("configured vision planner must implement plan")
    return planner
