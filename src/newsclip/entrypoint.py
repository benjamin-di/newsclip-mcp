"""Select the complete local CLI only when its optional runtime is installed."""

from importlib.util import find_spec


def run() -> None:
    from .process_signals import exit_on_sigterm

    exit_on_sigterm()
    if all(
        find_spec(name) is not None
        for name in ("signin_window", "patchright", "curl_cffi", "lxml", "trafilatura")
    ):
        from .cli import run as invoke
    else:
        from .remote_cli import run as invoke

    invoke()
