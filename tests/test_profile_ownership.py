"""A Python lease holder dying must not authorize stealing a live browser."""

from __future__ import annotations

import os
import select
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from newsclip.browser_runtime.profile_ownership import (
    OwnedBrowserProcess,
    prepare_profile,
)
from newsclip.browser_runtime.surface import BrowserRuntimeError


def singleton(profile: Path, pid: int, hostname: str | None = None) -> None:
    profile.mkdir(exist_ok=True)
    (profile / "SingletonLock").symlink_to(f"{hostname or socket.gethostname()}-{pid}")
    (profile / "SingletonSocket").symlink_to("/tmp/absent-newsclip-test/socket")
    (profile / "SingletonCookie").symlink_to("test-cookie")


def test_dead_local_browser_recovers_only_singleton_artifacts(tmp_path: Path) -> None:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait(timeout=5)
    singleton(tmp_path, child.pid)
    cookies = tmp_path / "Cookies"
    cookies.write_bytes(b"DO_NOT_REPLACE_SESSION")

    assert prepare_profile(tmp_path) is True

    assert not (tmp_path / "SingletonLock").is_symlink()
    assert cookies.read_bytes() == b"DO_NOT_REPLACE_SESSION"
    assert (tmp_path / ".newsclip-singleton-recovery/SingletonLock").is_symlink()
    assert prepare_profile(tmp_path) is False


def _metrics(profile: Path) -> tuple[Path, Path, Path, Path]:
    metrics = profile / "BrowserMetrics"
    metrics.mkdir(parents=True, exist_ok=True)
    old = metrics / "BrowserMetrics-6700AAAA-1.pma"
    old.write_bytes(b"histograms")
    deferred = profile / "DeferredBrowserMetrics"
    deferred.mkdir(exist_ok=True)
    pending = deferred / "BrowserMetrics-6700BBBB-2.pma"
    pending.write_bytes(b"histograms")
    outside = profile.parent / f"{profile.name}-outside.pma"
    outside.write_bytes(b"not ours")
    (metrics / "linked.pma").symlink_to(outside)
    spare = profile / "BrowserMetrics-spare.pma"
    spare.write_bytes(b"spare")
    return old, pending, outside, spare


@pytest.mark.parametrize("owner", ["none", "dead"])
def test_launch_preparation_prunes_only_browser_metrics(
    tmp_path: Path, owner: str
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    if owner == "dead":
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait(timeout=5)
        singleton(profile, child.pid)
    cookies = profile / "Default" / "Cookies"
    cookies.parent.mkdir()
    cookies.write_bytes(b"DO_NOT_REPLACE_SESSION")
    old, pending, outside, spare = _metrics(profile)

    assert prepare_profile(profile) is (owner == "dead")

    assert not old.exists()
    assert not pending.exists()
    assert (profile / "BrowserMetrics" / "linked.pma").is_symlink()
    # Session state, the reused spare file and symlinks (and their targets)
    # stay intact.
    assert cookies.read_bytes() == b"DO_NOT_REPLACE_SESSION"
    assert outside.read_bytes() == b"not ours"
    assert spare.read_bytes() == b"spare"


def test_a_live_owner_keeps_its_metrics(tmp_path: Path) -> None:
    singleton(tmp_path, os.getpid())
    old, pending, _outside, _spare = _metrics(tmp_path)

    with pytest.raises(BrowserRuntimeError, match="profile_in_use"):
        prepare_profile(tmp_path)

    assert old.exists()
    assert pending.exists()


def test_foreign_container_owner_is_not_assumed_dead(tmp_path: Path) -> None:
    singleton(tmp_path, 123, "removed-container")

    with pytest.raises(BrowserRuntimeError, match="profile_owner_unverified"):
        prepare_profile(tmp_path)

    assert os.readlink(tmp_path / "SingletonLock") == "removed-container-123"
    assert not (tmp_path / ".newsclip-singleton-recovery").exists()


def test_parent_exit_does_not_make_its_surviving_browser_stale(tmp_path: Path) -> None:
    # Separate parent deliberately exits without waiting for its browser.
    parent = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import subprocess, sys
p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(p.pid)
""",
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    pid = int(parent.stdout)
    try:
        singleton(tmp_path, pid)
        with pytest.raises(BrowserRuntimeError, match="profile_in_use"):
            prepare_profile(tmp_path)
        assert (tmp_path / "SingletonLock").is_symlink()
    finally:
        os.kill(pid, 9)


def test_unexpected_singleton_file_is_preserved(tmp_path: Path) -> None:
    singleton(tmp_path, 123, "unknown")
    (tmp_path / "SingletonSocket").unlink()
    (tmp_path / "SingletonSocket").write_text("unexpected file")
    with pytest.raises(BrowserRuntimeError):
        prepare_profile(tmp_path)
    assert (tmp_path / "SingletonSocket").read_text() == "unexpected file"


def test_owned_browser_is_reaped_when_driver_cleanup_fails(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; print('ready', flush=True); time.sleep(60)",
            f"--user-data-dir={tmp_path}",
        ],
        stdout=subprocess.PIPE,
    )
    try:
        # Exercise cleanup of a started child, not its interpreter startup.
        assert child.stdout is not None
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline() == b"ready\n"
        singleton(tmp_path, child.pid)
        owner = OwnedBrowserProcess.capture(tmp_path)
        assert owner is not None
        try:
            assert owner.stop_if_alive() is True
            assert owner.exited()
        finally:
            owner.close()
        child.wait(timeout=5)
        assert prepare_profile(tmp_path) is True
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        assert child.stdout is not None
        child.stdout.close()


def test_live_unrelated_pid_is_never_adopted_or_signalled(tmp_path: Path) -> None:
    singleton(tmp_path, os.getpid())
    with pytest.raises(BrowserRuntimeError, match="profile_owner_unverified"):
        OwnedBrowserProcess.capture(tmp_path)


def test_profile_symlink_is_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    profile = tmp_path / "profile"
    profile.symlink_to(actual, target_is_directory=True)
    with pytest.raises(BrowserRuntimeError, match="profile_invalid"):
        prepare_profile(profile)


@pytest.mark.parametrize(
    "reason",
    [
        "profile_invalid",
        "profile_in_use",
        "profile_owner_unverified",
        "profile_exit_unconfirmed",
    ],
)
def test_profile_fault_is_a_nonretryable_local_repair(reason: str) -> None:
    from newsclip.errors import PersistenceError
    from newsclip.results import public_error

    result = public_error(PersistenceError(reason))
    assert result is not None
    assert result.category == "persistence"
    assert result.reason == reason
    assert result.retryable is False
    assert result.action == "repair_local_infrastructure"
