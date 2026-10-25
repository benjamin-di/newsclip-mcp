"""Fail-closed headed-Chromium virtual-display selection."""

from __future__ import annotations

import atexit
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Callable, MutableMapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from signin_window.browser import browser_environment

from .events import DisplayClass, SurfaceMode

DEFAULT_DISPLAY_NUMBER = 109
_LOCAL_X11_SOCKET_ROOT = Path("/tmp/.X11-unix")
_DISPLAY_PROBE_TIMEOUT_SECONDS = 0.5
_DOCKER_REMOVE_TIMEOUT_SECONDS = 15
_DOCKER_RUN_TIMEOUT_SECONDS = 300
DOCKER_IMAGE = os.environ.get(
    "NEWSCLIP_XVFB_DOCKER_IMAGE", "mcr.microsoft.com/playwright:v1.52.0-noble"
)


class InfrastructureCategory(StrEnum):
    VIRTUAL_DISPLAY_UNAVAILABLE = "virtual_display_unavailable"
    SYSTEM_DISPLAY_REJECTED = "system_display_rejected"
    BWRAP_UNAVAILABLE = "bwrap_unavailable"
    BROWSER_STARTUP_FAILED = "browser_startup_failed"
    BROWSER_STARTUP_TARGET_CLOSED = "browser_startup_target_closed"
    BROWSER_CLEANUP_FAILED = "browser_cleanup_failed"
    NATIVE_INPUT_UNAVAILABLE = "native_input_unavailable"
    PROFILE_INVALID = "profile_invalid"
    PROFILE_IN_USE = "profile_in_use"
    PROFILE_OWNER_UNVERIFIED = "profile_owner_unverified"
    PROFILE_EXIT_UNCONFIRMED = "profile_exit_unconfirmed"
    DIAGNOSTIC_WRITE_FAILED = "diagnostic_write_failed"


class BrowserRuntimeError(RuntimeError):
    """A bounded runtime failure with no driver or environment text."""

    def __init__(self, category: InfrastructureCategory) -> None:
        self.category = category
        super().__init__(category.value)

    @property
    def profile_ownership_failure(self) -> bool:
        return self.category in {
            InfrastructureCategory.PROFILE_INVALID,
            InfrastructureCategory.PROFILE_IN_USE,
            InfrastructureCategory.PROFILE_OWNER_UNVERIFIED,
            InfrastructureCategory.PROFILE_EXIT_UNCONFIRMED,
        }


@dataclass
class SurfaceHandle:
    """One selected virtual surface and the resources that own it."""

    mode: SurfaceMode
    display_class: DisplayClass
    display: str
    pid: int | None = None
    container_id: str | None = None
    socket_dir: Path | None = None
    display_lease: _DisplayLease | None = None
    host_process: subprocess.Popen[bytes] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def close(self) -> None:
        if self.container_id:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", self.container_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=_DOCKER_REMOVE_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                pass
            finally:
                self.container_id = None
        if self.host_process is not None:
            _stop_host_xvfb(self.host_process)
            self.host_process = None
            self.pid = None
        elif self.pid:
            with suppress(OSError):
                os.kill(self.pid, signal.SIGTERM)
            self.pid = None
        if self.display_lease is not None:
            self.display_lease.close()
            self.display_lease = None


@dataclass
class _DisplayLease:
    number: int
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


_ACTIVE: SurfaceHandle | None = None


def _stop_host_xvfb(process: subprocess.Popen[bytes]) -> None:
    """Terminate and reap one owned host Xvfb before its lease is released."""

    if process.poll() is None:
        with suppress(OSError):
            process.terminate()
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        with suppress(OSError):
            process.kill()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=5)


def _display_number(environment: MutableMapping[str, str] | None = None) -> int:
    environ = environment if environment is not None else os.environ
    raw = environ.get("NEWSCLIP_XVFB_DISPLAY", str(DEFAULT_DISPLAY_NUMBER))
    try:
        number = int(raw)
    except ValueError:
        number = DEFAULT_DISPLAY_NUMBER
    if number < 50 or number > 9999:
        raise BrowserRuntimeError(InfrastructureCategory.SYSTEM_DISPLAY_REJECTED)
    return number


def display_is_usable(display: str | None = None) -> bool:
    """Return whether an X11 socket or remote X server accepts clients."""

    candidate = display if display is not None else os.environ.get("DISPLAY", "")
    if candidate.startswith(":") and candidate[1:].split(".")[0].isdigit():
        display_number = int(candidate[1:].split(".")[0])
        return _unix_display_is_usable(_LOCAL_X11_SOCKET_ROOT, display_number)
    if ":" in candidate and not candidate.startswith(":"):
        host, _, suffix = candidate.partition(":")
        try:
            remote_display_number = int(suffix.split(".")[0])
        except ValueError:
            return False
        try:
            with socket.create_connection(
                (host or "127.0.0.1", 6000 + remote_display_number),
                timeout=_DISPLAY_PROBE_TIMEOUT_SECONDS,
            ):
                return True
        except OSError:
            return False
    return False


def _unix_display_is_usable(socket_root: Path, display_number: int) -> bool:
    """Return whether the local X11 socket accepts a bounded connection."""

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(_DISPLAY_PROBE_TIMEOUT_SECONDS)
            client.connect(str(socket_root / f"X{display_number}"))
    except OSError:
        return False
    return True


def is_system_desktop_display(
    display: str | None = None,
    *,
    environment: MutableMapping[str, str] | None = None,
) -> bool:
    """Classify low local display numbers as physical desktop sessions."""

    environ = environment if environment is not None else os.environ
    candidate = display if display is not None else environ.get("DISPLAY", "")
    if not candidate.startswith(":"):
        return False
    try:
        number = int(candidate[1:].split(".")[0])
    except ValueError:
        return False
    managed = _display_number(environ)
    return number < 50 and number != managed


def _start_host_xvfb(
    number: int | None,
    *,
    environment: MutableMapping[str, str] | None = None,
) -> SurfaceHandle | None:
    environ = environment if environment is not None else os.environ
    executable = shutil.which("Xvfb")
    if executable is None:
        return None
    if number is not None and is_system_desktop_display(
        f":{number}", environment=environ
    ):
        raise BrowserRuntimeError(InfrastructureCategory.SYSTEM_DISPLAY_REJECTED)
    lease = _acquire_host_display(number, environ)
    if lease is None:
        return None
    display = f":{lease.number}"
    process: subprocess.Popen[bytes] | None = None
    handed_off = False
    try:
        # A live socket without the matching private lease belongs to another
        # process. Never attach an ordinary host invocation to that surface.
        if display_is_usable(display):
            return None
        process = subprocess.Popen(
            [
                executable,
                display,
                "-screen",
                "0",
                "1280x800x24",
                "-ac",
                "-nolisten",
                "tcp",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=browser_environment(environ),
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if display_is_usable(display):
                handed_off = True
                return SurfaceHandle(
                    SurfaceMode.HOST_XVFB,
                    DisplayClass.VIRTUAL_LOCAL,
                    display,
                    pid=process.pid,
                    display_lease=lease,
                    host_process=process,
                )
            if process.poll() is not None:
                return None
            time.sleep(0.2)
        return None
    except OSError:
        return None
    finally:
        if not handed_off:
            if process is not None:
                _stop_host_xvfb(process)
            lease.close()


def ensure_virtual_display(
    *, environment: MutableMapping[str, str] | None = None
) -> SurfaceHandle:
    """Select managed virtual display then host Xvfb; never pure headless."""

    environ = environment if environment is not None else os.environ
    display = environ.get("DISPLAY", "")
    if (
        environ.get("NEWSCLIP_VIRTUAL_DISPLAY") == "1"
        and display_is_usable(display)
        and not is_system_desktop_display(display, environment=environ)
    ):
        environ["NEWSCLIP_TIMING_SURFACE"] = SurfaceMode.MANAGED_VIRTUAL.value
        return SurfaceHandle(
            SurfaceMode.MANAGED_VIRTUAL,
            DisplayClass.VIRTUAL_REMOTE
            if not display.startswith(":")
            else DisplayClass.VIRTUAL_LOCAL,
            display,
        )
    if display and is_system_desktop_display(display, environment=environ):
        if environ.get("NEWSCLIP_DENY_SYSTEM_DISPLAY") == "1":
            raise BrowserRuntimeError(InfrastructureCategory.SYSTEM_DISPLAY_REJECTED)
        environ.pop("DISPLAY", None)

    global _ACTIVE
    if _ACTIVE is not None and display_is_usable(_ACTIVE.display):
        environ["DISPLAY"] = _ACTIVE.display
        environ["NEWSCLIP_VIRTUAL_DISPLAY"] = "1"
        environ["NEWSCLIP_DENY_SYSTEM_DISPLAY"] = "1"
        environ["NEWSCLIP_TIMING_SURFACE"] = _ACTIVE.mode.value
        return _ACTIVE
    if _ACTIVE is not None:
        stale = _ACTIVE
        _ACTIVE = None
        stale.close()
    handle = _start_host_xvfb(
        _display_number(environ) if "NEWSCLIP_XVFB_DISPLAY" in environ else None,
        environment=environ,
    )
    if handle is None:
        raise BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)
    environ["DISPLAY"] = handle.display
    environ["NEWSCLIP_VIRTUAL_DISPLAY"] = "1"
    environ["NEWSCLIP_DENY_SYSTEM_DISPLAY"] = "1"
    environ["NEWSCLIP_TIMING_SURFACE"] = handle.mode.value
    _ACTIVE = handle
    atexit.register(handle.close)
    return handle


def docker_cli_usable() -> bool:
    """Return whether Docker exists and its daemon accepts commands."""

    executable = shutil.which("docker")
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _prepare_socket_root(socket_root: Path) -> None:
    """Accept an existing root-owned X11 directory only when it is sticky.

    Docker creates socket entries as root. The host user may therefore be able
    to use, but not chmod, a previously created mount directory. Fail closed if
    its actual mode is anything other than the standard world-writable sticky
    X11 mode.
    """

    descriptor: int | None = None
    try:
        socket_root.mkdir(mode=0o1777, parents=True, exist_ok=True)
        descriptor = os.open(
            socket_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fchmod(descriptor, 0o1777)
        except OSError as chmod_error:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o1777:
                raise BrowserRuntimeError(
                    InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
                ) from chmod_error
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o1777:
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            )
    except BrowserRuntimeError:
        raise
    except OSError as error:
        raise BrowserRuntimeError(
            InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _prepare_display_lease_root(lease_root: Path) -> None:
    descriptor: int | None = None
    try:
        lease_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            lease_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid():
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            )
        os.fchmod(descriptor, 0o700)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            )
    except BrowserRuntimeError:
        raise
    except OSError as error:
        raise BrowserRuntimeError(
            InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _display_lease_root(environment: MutableMapping[str, str]) -> Path:
    return Path(
        environment.get(
            "NEWSCLIP_XVFB_LEASE_DIR",
            str(Path.home() / ".local/state/newsclip/xvfb-leases"),
        )
    ).expanduser()


def _try_acquire_display_lease(
    candidates: Sequence[int],
    *,
    lease_root: Path,
    display_is_live: Callable[[int], bool],
) -> _DisplayLease | None:
    try:
        import fcntl
    except ImportError as error:  # pragma: no cover - Xvfb leasing is Linux-only
        raise BrowserRuntimeError(
            InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
        ) from error

    _prepare_display_lease_root(lease_root)
    for number in candidates:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                lease_root / f"display-{number}.lock",
                os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                0o600,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise OSError("display lease is not a private regular file")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                descriptor = None
                continue
            if display_is_live(number):
                os.close(descriptor)
                descriptor = None
                continue
            return _DisplayLease(number=number, descriptor=descriptor)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            continue
    return None


def _acquire_host_display(
    number: int | None,
    environment: MutableMapping[str, str],
) -> _DisplayLease | None:
    """Lease a free host display; an explicit number remains exclusive."""

    return _try_acquire_display_lease(
        (number,) if number is not None else _display_candidates(environment),
        lease_root=_display_lease_root(environment),
        display_is_live=lambda candidate: _unix_display_is_usable(
            _LOCAL_X11_SOCKET_ROOT,
            candidate,
        ),
    )


def _display_candidates(environment: MutableMapping[str, str]) -> Sequence[int]:
    if "NEWSCLIP_XVFB_DISPLAY" in environment:
        return (_display_number(environment),)
    minimum = 1000
    count = 9000
    start = minimum + (os.getpid() % count)
    return tuple(
        minimum + ((start - minimum + offset) % count) for offset in range(count)
    )


def _acquire_docker_display(
    environment: MutableMapping[str, str] | None = None,
) -> _DisplayLease:
    """Lease one high display number without colliding with another live gate."""

    environ = environment if environment is not None else os.environ
    socket_root = Path(
        environ.get(
            "NEWSCLIP_XVFB_SOCKET_DIR",
            str(Path.home() / ".local/state/newsclip/xvfb-x11"),
        )
    ).expanduser()

    lease = _try_acquire_display_lease(
        _display_candidates(environ),
        lease_root=_display_lease_root(environ),
        display_is_live=lambda number: _unix_display_is_usable(socket_root, number),
    )
    if lease is None:
        raise BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)
    return lease


def _start_docker_xvfb_socket(number: int) -> SurfaceHandle | None:
    if not docker_cli_usable():
        return None
    socket_root = Path(
        os.environ.get(
            "NEWSCLIP_XVFB_SOCKET_DIR",
            str(Path.home() / ".local/state/newsclip/xvfb-x11"),
        )
    ).expanduser()
    _prepare_socket_root(socket_root)
    name = f"newsclip-xvfb-{number}-{os.getpid()}"
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_DOCKER_REMOVE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    socket_path = socket_root / f"X{number}"
    with suppress(OSError):
        socket_path.unlink()
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-v",
                f"{socket_root}:/tmp/.X11-unix",
                DOCKER_IMAGE,
                "bash",
                "-lc",
                (
                    "chmod 1777 /tmp/.X11-unix; "
                    f"rm -f /tmp/.X11-unix/X{number} /tmp/.X{number}-lock; "
                    f"exec Xvfb :{number} -screen 0 1280x800x24 -ac -nolisten tcp"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=_DOCKER_RUN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    container_id = result.stdout.strip() or name
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if _unix_display_is_usable(socket_root, number):
            return SurfaceHandle(
                SurfaceMode.DOCKER_XVFB_BWRAP,
                DisplayClass.VIRTUAL_LOCAL,
                f":{number}",
                container_id=container_id,
                socket_dir=socket_root,
            )
        time.sleep(0.25)
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_DOCKER_REMOVE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return None


def build_bwrap_xvfb_command(
    argv: Sequence[str], *, socket_dir: Path, display: str
) -> list[str]:
    """Build a secret-free argv; the child inherits secrets via environment."""

    executable = shutil.which("bwrap")
    if executable is None:
        raise BrowserRuntimeError(InfrastructureCategory.BWRAP_UNAVAILABLE)
    command = [
        executable,
        "--dev-bind",
        "/",
        "/",
        "--bind",
        str(socket_dir),
        "/tmp/.X11-unix",
        "--setenv",
        "DISPLAY",
        display,
        "--setenv",
        "NEWSCLIP_VIRTUAL_DISPLAY",
        "1",
        "--setenv",
        "NEWSCLIP_DENY_SYSTEM_DISPLAY",
        "1",
        "--setenv",
        "NEWSCLIP_INSIDE_BWRAP_XVFB",
        "1",
        "--setenv",
        "NEWSCLIP_TIMING_SURFACE",
        SurfaceMode.DOCKER_XVFB_BWRAP.value,
        "--",
        sys.executable,
        "-u",
        *argv,
    ]
    return command


def maybe_reexec_for_virtual_display(
    argv: Sequence[str] | None = None,
    *,
    required: bool,
) -> int | None:
    """Prepare Xvfb or run this invocation under Docker-Xvfb plus bwrap."""

    if not required or os.environ.get("NEWSCLIP_INSIDE_BWRAP_XVFB") == "1":
        return None
    try:
        ensure_virtual_display()
        return None
    except BrowserRuntimeError as error:
        if error.category is not InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE:
            raise
    if shutil.which("bwrap") and docker_cli_usable():
        lease = _acquire_docker_display()
        try:
            handle = _start_docker_xvfb_socket(lease.number)
        except OSError as error:
            lease.close()
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            ) from error
        except BaseException:
            lease.close()
            raise
        if handle is None:
            lease.close()
        else:
            handle.display_lease = lease
        if handle is not None and handle.socket_dir is not None:
            try:
                command = build_bwrap_xvfb_command(
                    list(argv) if argv is not None else list(sys.argv),
                    socket_dir=handle.socket_dir,
                    display=handle.display,
                )
                return subprocess.run(command, check=False).returncode
            finally:
                handle.close()
    raise BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)
