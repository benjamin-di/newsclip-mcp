"""News runtime errors and legacy paths over shared profile ownership."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from signin_window.automation import profiles as shared

from .surface import BrowserRuntimeError, InfrastructureCategory


def _call(function, *args, **kwargs) -> Any:
    try:
        return function(*args, **kwargs)
    except shared.ProfileError as error:
        raise BrowserRuntimeError(
            InfrastructureCategory(error.category.value)
        ) from error


def singleton_snapshot(profile: Path) -> dict[str, str]:
    return _call(shared.singleton_snapshot, profile)


def singleton_owner(snapshot: dict[str, str]) -> tuple[str, int] | None:
    return _call(shared.singleton_owner, snapshot)


def preserve_singletons(profile: Path, snapshot: dict[str, str]) -> None:
    _call(
        shared.preserve_singletons,
        profile,
        snapshot,
        recovery_directory=".newsclip-singleton-recovery",
    )


def prune_browser_metrics(profile: Path) -> None:
    shared.prune_browser_metrics(profile)


def prepare_profile(profile: Path) -> bool:
    return _call(
        shared.prepare_profile,
        profile,
        recovery_directory=".newsclip-singleton-recovery",
    )


class OwnedBrowserProcess:
    def __init__(self, process: shared.OwnedBrowserProcess) -> None:
        self._process = process

    @classmethod
    def capture(cls, profile: Path) -> OwnedBrowserProcess | None:
        process = _call(shared.OwnedBrowserProcess.capture, profile)
        return cls(process) if process is not None else None

    @property
    def forced(self) -> bool:
        return self._process.forced

    def exited(self, timeout: float = 0) -> bool:
        return self._process.exited(timeout)

    def stop_if_alive(self) -> bool:
        return _call(self._process.stop_if_alive)

    def close(self) -> None:
        self._process.close()
