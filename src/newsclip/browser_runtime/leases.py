"""Ranked process-safe leases for session, attempt, and durable profiles."""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from enum import IntEnum
from pathlib import Path

from ..account_keys import require_account_key
from ..provider_keys import is_provider_key
from ..timing import TimingStep, timing_step


class LeaseKind(IntEnum):
    SESSION_GENERATION = 10
    PROVIDER_ATTEMPT = 20
    DURABLE_PROFILE = 30


_LEASE_TIMING_STEPS = {
    LeaseKind.PROVIDER_ATTEMPT: TimingStep.ATTEMPT_LEASE_WAIT,
    LeaseKind.DURABLE_PROFILE: TimingStep.PROFILE_LEASE_WAIT,
}


class LeaseBusyError(TimeoutError):
    """A lease could not be acquired within its bounded wait."""


class LockOrderError(RuntimeError):
    """A caller attempted to acquire leases out of canonical order."""


_STATE = threading.local()


def _stack() -> list[LeaseKind]:
    stack = getattr(_STATE, "lease_stack", None)
    if stack is None:
        stack = []
        _STATE.lease_stack = stack
    return stack


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


@contextmanager
def ordered_file_lease(
    path: Path,
    *,
    kind: LeaseKind,
    timeout_seconds: float = 30,
) -> Iterator[None]:
    """Acquire one regular, non-symlink lock file at the requested rank."""

    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("invalid lease timeout")
    held = _stack()
    if held and kind <= held[-1]:
        raise LockOrderError("lease order must be session -> attempt -> profile")

    path = Path(path)
    _private_directory(path.parent)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    acquired = False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("lease target is not a regular file")
        os.fchmod(descriptor, 0o600)
        step = _LEASE_TIMING_STEPS.get(kind)
        with timing_step(step) if step is not None else nullcontext():
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LeaseBusyError("lease acquisition timed out") from None
                    time.sleep(min(0.1, max(0.001, timeout / 10)))
        held.append(kind)
        try:
            yield
        finally:
            released = held.pop()
            if released is not kind:
                raise LockOrderError("lease release order was corrupted")
    finally:
        if acquired:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class HeldProfileLease:
    """Exclusive profile flock held across multiple browser retrievals.

    Unlike :func:`ordered_file_lease`, this does not remain on the thread-local
    lease stack after acquisition — keep-alive browsers hold the lock for their
    full lifetime. Owners must release it before acquiring a lower-ranked
    session or attempt lease.
    """

    def __init__(self, path: Path, *, timeout_seconds: float = 30) -> None:
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("invalid lease timeout")
        held = _stack()
        if held and held[-1] >= LeaseKind.DURABLE_PROFILE:
            raise LockOrderError("lease order must be session -> attempt -> profile")
        path = Path(path)
        _private_directory(path.parent)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
        self._acquired = False
        try:
            if not stat.S_ISREG(os.fstat(self._descriptor).st_mode):
                raise OSError("lease target is not a regular file")
            os.fchmod(self._descriptor, 0o600)
            with timing_step(TimingStep.PROFILE_LEASE_WAIT):
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        self._acquired = True
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise LeaseBusyError(
                                "lease acquisition timed out"
                            ) from None
                        time.sleep(min(0.1, max(0.001, timeout / 10)))
        except BaseException:
            os.close(self._descriptor)
            raise

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        self._descriptor = -1
        if self._acquired:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            self._acquired = False
        with suppress(OSError):
            os.close(descriptor)


class LeaseManager:
    """Create account-global attempt and path-specific profile leases."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def attempt(
        self,
        provider: str,
        account_key: str,
        *,
        timeout_seconds: float = 30,
    ):
        if not is_provider_key(provider):
            raise ValueError("invalid provider key")
        account_key = require_account_key(account_key)
        account_id = hashlib.sha256(account_key.encode("utf-8")).hexdigest()[:16]
        return ordered_file_lease(
            self.root / f"{provider}-attempt-{account_id}.lock",
            kind=LeaseKind.PROVIDER_ATTEMPT,
            timeout_seconds=timeout_seconds,
        )

    def profile(self, profile: Path, *, timeout_seconds: float = 30):
        profile_id = hashlib.sha256(
            str(Path(profile).expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:16]
        return ordered_file_lease(
            self.root / f"profile-{profile_id}.lock",
            kind=LeaseKind.DURABLE_PROFILE,
            timeout_seconds=timeout_seconds,
        )

    def hold_profile(
        self, profile: Path, *, timeout_seconds: float = 10
    ) -> HeldProfileLease:
        """Acquire a long-lived profile flock for a keep-alive browser."""

        profile_id = hashlib.sha256(
            str(Path(profile).expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:16]
        return HeldProfileLease(
            self.root / f"profile-{profile_id}.lock",
            timeout_seconds=timeout_seconds,
        )
