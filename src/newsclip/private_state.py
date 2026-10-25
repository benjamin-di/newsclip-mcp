"""Durable, private on-disk state shared by the maintenance actors.

Both the provider guard's holds and the keeper's credential budget are brakes:
state whose loss silently re-permits an action that was meant to be spent. They
therefore need the same durability, and writing it twice invites the two copies
to drift apart — which is exactly what happened before this module existed.

Durability here means the replacement survives power loss: the payload is
fsynced, renamed atomically, and the containing directory is fsynced so the
rename itself is durable.
"""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class PrivateStateError(OSError):
    """A private state file could not be read, written, or locked."""


class PrivateStateBusyError(PrivateStateError):
    """Another process owns the requested private-state lock."""


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_private_write(path: Path, payload: bytes) -> None:
    """Replace ``path`` with ``payload`` durably, at mode 0600."""

    if path.is_symlink():
        raise PrivateStateError(f"{path.name} is not a regular private file")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        fsync_directory(path.parent)
    except OSError as error:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise PrivateStateError(f"{path.name} write failed") from error


@contextmanager
def exclusive_lock(path: Path, *, timeout_seconds: float) -> Iterator[None]:
    """Hold an advisory exclusive lock for the duration of the block.

    Read-modify-write on shared state needs one writer at a time. Without this
    two processes can each read the same prior value and each believe their own
    update landed.
    """

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, stat.S_IRWXU)
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as error:
        # Includes a symlinked lock path, which O_NOFOLLOW rejects here.
        raise PrivateStateError(f"{path.name} lock failed") from error
    acquired = False
    try:
        # Only acquisition is translated. Wrapping the caller's block too would
        # relabel an unrelated failure inside it as a locking failure.
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise PrivateStateError(f"{path.name} is not a regular private file")
            os.fchmod(descriptor, 0o600)
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise PrivateStateBusyError(
                            f"{path.name} is locked by another process"
                        ) from None
                    time.sleep(0.05)
        except PrivateStateError:
            raise
        except OSError as error:
            raise PrivateStateError(f"{path.name} lock failed") from error
        yield
    finally:
        if acquired:
            with _suppressed(errno.EBADF):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def _suppressed(*codes: int) -> Iterator[None]:
    try:
        yield
    except OSError as error:  # pragma: no cover - defensive unlock path
        if error.errno not in codes:
            raise


__all__ = [
    "PrivateStateBusyError",
    "PrivateStateError",
    "atomic_private_write",
    "exclusive_lock",
    "fsync_directory",
]
