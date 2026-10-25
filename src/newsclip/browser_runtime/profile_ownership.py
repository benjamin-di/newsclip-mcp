"""Linux Chromium ownership, separate from the Python caller's profile lease.

Call prepare_profile only while holding the existing durable-profile lease.
Neither a free flock nor a missing socket in this container proves that a
browser in another PID/mount namespace is dead. Foreign owners require the
host recovery command. Never remove a profile or its session data here;
only Chromium's metrics files, which are not session state, are pruned.
"""

from __future__ import annotations

import os
import select
import signal
import socket
import threading
from contextlib import suppress
from pathlib import Path

from .surface import BrowserRuntimeError, InfrastructureCategory

_SINGLETONS = ("SingletonSocket", "SingletonCookie", "SingletonLock")
_METRICS_DIRECTORIES = ("BrowserMetrics", "DeferredBrowserMetrics")


def singleton_snapshot(profile: Path) -> dict[str, str]:
    if profile.is_symlink() or not profile.is_dir():
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID)
    result = {}
    for name in _SINGLETONS:
        path = profile / name
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID) from error
        if len(target) > 4096:
            raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID)
        result[name] = target
    return result


def singleton_owner(snapshot: dict[str, str]) -> tuple[str, int] | None:
    target = snapshot.get("SingletonLock")
    if target is None:
        return None
    host, separator, value = target.rpartition("-")
    if not separator or not host or not value.isascii() or not value.isdecimal():
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_OWNER_UNVERIFIED)
    pid = int(value)
    if pid <= 1 or pid > 2**31 - 1:
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_OWNER_UNVERIFIED)
    return host, pid


def _process_fields(pid: int) -> list[str] | None:
    try:
        # comm can contain spaces and parentheses; fields start after its last ).
        return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    except FileNotFoundError:
        return None
    except (OSError, IndexError) as error:
        raise BrowserRuntimeError(
            InfrastructureCategory.PROFILE_OWNER_UNVERIFIED
        ) from error


def preserve_singletons(profile: Path, snapshot: dict[str, str]) -> None:
    """Compare-and-move only symlinks; keep one bounded previous recovery.

    The caller must prove owner death and hold the profile lease throughout.
    The lock moves last, so interruption cannot authorize an unverified owner.
    """
    if singleton_snapshot(profile) != snapshot:
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_OWNER_UNVERIFIED)
    backup = profile / ".newsclip-singleton-recovery"
    if backup.is_symlink():
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID)
    backup.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backup, 0o700)
    for name in _SINGLETONS:
        destination = backup / name
        if destination.exists() and not destination.is_symlink():
            raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID)
    for name in _SINGLETONS:
        if name in snapshot:
            os.replace(profile / name, backup / name)


def prune_browser_metrics(profile: Path) -> None:
    """Drop Chromium's persistent histogram files; they are not session state.

    Chromium writes a ``.pma`` file per browser run under ``BrowserMetrics``
    and only uploads (and removes) them with UMA reporting, which this
    runtime never enables, so they grew to gigabytes per retained profile.
    Call only once no browser owns the profile. Only regular files directly
    inside the two metrics directories are removed; symlinks are never
    followed and nothing else in the profile is touched. Best effort.
    """
    for name in _METRICS_DIRECTORIES:
        directory = profile / name
        try:
            if directory.is_symlink() or not directory.is_dir():
                continue
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):
                        with suppress(OSError):
                            os.unlink(entry.path)
        except OSError:
            continue


def prepare_profile(profile: Path) -> bool:
    """Recover a dead local owner, or refuse before Chromium can steal a profile."""
    snapshot = singleton_snapshot(profile)
    owner = singleton_owner(snapshot)
    if owner is None:
        prune_browser_metrics(profile)
        return False
    host, pid = owner
    if host != socket.gethostname():
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_OWNER_UNVERIFIED)
    fields = _process_fields(pid)
    if fields is not None and fields[0] not in {"Z", "X"}:
        raise BrowserRuntimeError(InfrastructureCategory.PROFILE_IN_USE)
    preserve_singletons(profile, snapshot)
    prune_browser_metrics(profile)
    return True


class OwnedBrowserProcess:
    """A pidfd binds shutdown to the exact browser we launched, despite PID reuse."""

    def __init__(self, descriptor: int) -> None:
        self._descriptor = descriptor
        self._lock = threading.Lock()
        self.forced = False

    @classmethod
    def capture(cls, profile: Path) -> OwnedBrowserProcess | None:
        owner = singleton_owner(singleton_snapshot(profile))
        if owner is None:
            return None
        hostname, pid = owner
        if hostname != socket.gethostname() or not hasattr(os, "pidfd_open"):
            raise BrowserRuntimeError(InfrastructureCategory.PROFILE_OWNER_UNVERIFIED)
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return None
        except OSError as error:
            raise BrowserRuntimeError(
                InfrastructureCategory.PROFILE_OWNER_UNVERIFIED
            ) from error
        instance = cls(descriptor)
        try:
            fields = _process_fields(pid)
            if fields is None or instance.exited():
                instance.close()
                return None
            args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            expected = os.fsencode(f"--user-data-dir={profile}")
            # Chromium may rewrite argv into one space-joined process title.
            # Match the whole profile argument with boundaries in that form;
            # ordinary processes retain the NUL-separated argv form.
            matches_profile = expected in args or (
                len([arg for arg in args if arg]) == 1
                and b" " + expected + b" " in b" " + args[0] + b" "
            )
            if not matches_profile or not _descends_from_caller(int(fields[1])):
                raise BrowserRuntimeError(
                    InfrastructureCategory.PROFILE_OWNER_UNVERIFIED
                )
            # A reused PID cannot pass inspection after the pidfd's owner exited.
            if instance.exited():
                instance.close()
                return None
            return instance
        except BaseException:
            instance.close()
            raise

    def exited(self, timeout: float = 0) -> bool:
        return bool(select.select([self._descriptor], [], [], timeout)[0])

    def stop_if_alive(self) -> bool:
        """Bounded TERM/KILL of this owned browser only; callable by a watchdog."""
        with self._lock:
            if self.exited():
                return self.forced
            self.forced = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    signal.pidfd_send_signal(self._descriptor, sig)
                except ProcessLookupError:
                    return True
                if self.exited(2):
                    return True
            raise BrowserRuntimeError(InfrastructureCategory.BROWSER_CLEANUP_FAILED)

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def _descends_from_caller(parent: int) -> bool:
    for _ in range(32):
        if parent == os.getpid():
            return True
        if parent <= 1:
            break
        fields = _process_fields(parent)
        if fields is None:
            break
        parent = int(fields[1])
    return False
