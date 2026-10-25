"""SIGTERM must unwind so atexit/finally close browsers and profile locks."""

from __future__ import annotations

import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from newsclip.process_signals import (
    SIGTERM_EXIT_STATUS,
    TIMED_OUT_EXIT_STATUSES,
    under_timeout,
)

_CHILD = textwrap.dedent(
    """
    import atexit, os, signal, sys, time
    from pathlib import Path
    from newsclip.process_signals import exit_on_sigterm

    marker = Path(sys.argv[1])
    if sys.argv[2] == "preset":
        signal.signal(signal.SIGTERM, lambda *_: os._exit(7))
    exit_on_sigterm()

    def close():
        # Cleanup outlives a repeated TERM; only SIGKILL bounds it.
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.2)
        with marker.open("a") as handle:
            handle.write("atexit\\n")

    atexit.register(close)
    try:
        print("ready", flush=True)
        time.sleep(30)
    finally:
        with marker.open("a") as handle:
            handle.write("finally\\n")
    """
)


def _terminate_child(tmp_path: Path, mode: str) -> tuple[int, str]:
    marker = tmp_path / "marker"
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(marker), mode],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "ready"
        child.send_signal(signal.SIGTERM)
        status = child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
    return status, marker.read_text() if marker.exists() else ""


def test_sigterm_runs_finally_and_atexit_cleanup(tmp_path: Path) -> None:
    status, marker = _terminate_child(tmp_path, "default")

    assert status == SIGTERM_EXIT_STATUS
    assert marker == "finally\natexit\n"


def test_an_existing_sigterm_disposition_is_respected(tmp_path: Path) -> None:
    status, marker = _terminate_child(tmp_path, "preset")

    assert status == 7
    assert marker == ""


def test_only_the_main_thread_installs_the_handler() -> None:
    import threading

    from newsclip.process_signals import exit_on_sigterm

    before = signal.getsignal(signal.SIGTERM)
    worker = threading.Thread(target=exit_on_sigterm)
    worker.start()
    worker.join()

    assert signal.getsignal(signal.SIGTERM) is before


def test_console_script_uses_the_unwinding_entry_point() -> None:
    import tomllib

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    scripts = tomllib.loads(pyproject.read_text())["project"]["scripts"]

    assert scripts["newsclip"] == "newsclip.cli:run"


_PARENT_WITH_GRANDCHILD = textwrap.dedent(
    """
    import subprocess, sys, time
    from pathlib import Path

    grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(sys.argv[1]).write_text(str(grandchild.pid))
    time.sleep(60)
    """
)


def _running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"


def test_under_timeout_ends_the_whole_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"

    parent = [sys.executable, "-c", _PARENT_WITH_GRANDCHILD, str(pid_file)]
    completed = subprocess.run(
        under_timeout(parent, 1),
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode in TIMED_OUT_EXIT_STATUSES
    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while _running(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _running(grandchild)
