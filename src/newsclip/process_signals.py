"""Process-level termination handling for the long-running entry points.

Python's default SIGTERM disposition ends the process without unwinding: no
``finally`` block or ``atexit`` hook runs, so a keeper, ops or MCP process
stopped by its container (or by GNU ``timeout``) left its Chromium running and
its profile ``SingletonLock`` stale. Converting SIGTERM into ``SystemExit``
lets the existing browser close paths run; the supervisor's SIGKILL remains
the hard bound.
"""

from __future__ import annotations

import signal
import threading
from collections.abc import Sequence
from types import FrameType

#: Conventional exit status of a process ended by SIGTERM.
SIGTERM_EXIT_STATUS = 128 + signal.SIGTERM

#: GNU ``timeout``'s status when it ended the command: 124 after the TERM, or
#: 128+KILL when the command was still running ``--kill-after`` seconds later.
TIMED_OUT_EXIT_STATUSES = frozenset({124, 128 + signal.SIGKILL})


def under_timeout(argv: Sequence[str], seconds: float) -> list[str]:
    """Bound ``argv`` with GNU ``timeout``, which signals its whole process group.

    ``subprocess.run(timeout=...)`` kills only the direct child, stranding the
    display and browser processes a CLI operation started (and their profile
    ``SingletonLock``). TERM first lets the child's own close paths run.
    """

    return ["timeout", "--signal=TERM", "--kill-after=30", f"{seconds:g}", *argv]


def _terminate(signum: int, frame: FrameType | None) -> None:
    # A repeated TERM must not interrupt the cleanup the first one started.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(SIGTERM_EXIT_STATUS)


def exit_on_sigterm() -> None:
    """Unwind on SIGTERM, unless the process already chose a disposition.

    Must run in the main thread (signal handlers can only be set there);
    servers such as uvicorn install their own handler while serving and
    re-raise the captured signal into this one after a graceful shutdown.
    """

    if threading.current_thread() is not threading.main_thread():
        return
    if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
        return
    signal.signal(signal.SIGTERM, _terminate)


__all__ = [
    "SIGTERM_EXIT_STATUS",
    "TIMED_OUT_EXIT_STATUSES",
    "exit_on_sigterm",
    "under_timeout",
]
