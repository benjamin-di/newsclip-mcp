from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from newsclip.browser_profiles import BrowserProfileManager
from newsclip.browser_runtime import BrowserLaunchConfig, PatchrightRuntime


def test_profile_manager_owns_path_and_launch_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = PatchrightRuntime()
    launch = BrowserLaunchConfig(
        locale="en-US",
        timezone_id="America/New_York",
        accept_language="en-US,en;q=0.9",
        args=("--fixture",),
    )
    captured: dict[str, object] = {}

    @contextmanager
    def opened(
        profile: Path,
        *,
        require_virtual_display: bool,
        launch_config: BrowserLaunchConfig,
    ):
        captured.update(
            profile=profile,
            require_virtual_display=require_virtual_display,
            launch_config=launch_config,
        )
        yield object()

    monkeypatch.setattr(runtime, "open", opened)
    profiles = BrowserProfileManager(
        tmp_path / "profiles",
        runtime=runtime,
        launch_configs={"bloomberg": launch},
    )

    expected = tmp_path / "profiles/bloomberg/account_01"
    assert profiles.path("bloomberg", "account_01") == expected
    with profiles.open(
        "bloomberg",
        "account_01",
        require_virtual_display=True,
    ):
        pass

    assert captured == {
        "profile": expected,
        "require_virtual_display": True,
        "launch_config": launch,
    }


def test_profile_manager_rejects_unknown_launch_and_unsafe_identity(
    tmp_path: Path,
) -> None:
    profiles = BrowserProfileManager(
        tmp_path / "profiles",
        runtime=PatchrightRuntime(),
        launch_configs={},
    )

    with pytest.raises(ValueError, match="launch configuration is unavailable"):
        profiles.open("ft", "default", require_virtual_display=False)
    with pytest.raises(ValueError, match="invalid provider key"):
        profiles.path("FT", "default")
    with pytest.raises(ValueError, match="invalid account key"):
        profiles.path("ft", "../escape")
