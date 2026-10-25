"""Shared browser-profile identity and launch ownership."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from uuid import UUID

from .account_keys import require_account_key
from .browser_runtime import (
    BrowserLaunchConfig,
    PatchrightMintContext,
    PatchrightRuntime,
)
from .provider_keys import is_provider_key


class BrowserProfileManager:
    """Resolve and open durable profiles for every authenticated provider."""

    def __init__(
        self,
        root: Path,
        *,
        runtime: PatchrightRuntime,
        launch_configs: Mapping[str, BrowserLaunchConfig],
    ) -> None:
        self.root = Path(root)
        self._runtime = runtime
        self._launch_configs = dict(launch_configs)

    def path(
        self, provider: str, account_key: str, *, profile_id: UUID | None = None
    ) -> Path:
        if not is_provider_key(provider):
            raise ValueError("invalid provider key")
        account = require_account_key(account_key)
        if profile_id is not None:
            account = f"{account}--{UUID(str(profile_id)).hex}"
        return self.root / provider / account

    def open(
        self,
        provider: str,
        account_key: str,
        *,
        require_virtual_display: bool,
        profile_id: UUID | None = None,
    ) -> AbstractContextManager[PatchrightMintContext]:
        profile = self.path(provider, account_key, profile_id=profile_id)
        try:
            launch_config = self._launch_configs[provider]
        except KeyError:
            raise ValueError(
                f"browser launch configuration is unavailable: {provider}"
            ) from None
        return self._runtime.open(
            profile,
            require_virtual_display=require_virtual_display,
            launch_config=launch_config,
        )


__all__ = ["BrowserProfileManager"]
