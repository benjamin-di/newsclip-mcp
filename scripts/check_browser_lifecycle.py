"""Credential-free Chromium shutdown/reopen check with inert local content."""

from __future__ import annotations

import json
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

from newsclip.browser_runtime import (
    BrowserRuntimeError,
    LeaseManager,
    PatchrightRuntime,
    RuntimeTrace,
    maybe_reexec_for_virtual_display,
)


def main() -> int:
    delegated = maybe_reexec_for_virtual_display(sys.argv, required=True)
    if delegated is not None:
        return delegated
    with tempfile.TemporaryDirectory(prefix="newsclip-lifecycle-") as directory:
        root = Path(directory)
        profile = root / "profile"
        trace = root / "browser.jsonl"
        runtime = PatchrightRuntime(
            trace=RuntimeTrace(trace, run_id="lifecycle-fixture")
        )
        leases = LeaseManager(root / "locks")
        with (
            leases.profile(profile),
            runtime.open(profile, require_virtual_display=True) as browser,
        ):
            browser.page.set_content("<p>inert local lifecycle fixture</p>")
            browser.context.add_cookies(
                [
                    {
                        "name": "fixture",
                        "value": "preserved",
                        "domain": "fixture.invalid",
                        "path": "/",
                        "expires": 4102444800,
                    }
                ]
            )
        assert not (profile / "SingletonLock").is_symlink()

        original_launch = runtime._launch
        restorers = []

        def failing_launch(path, config):
            manager, context = original_launch(path, config)
            originals = (context.close, manager.stop)
            restorers.extend(originals)

            def fail():
                raise RuntimeError("inert cleanup failure")

            context.close = fail
            manager.stop = fail
            return manager, context

        runtime._launch = failing_launch
        try:
            with leases.profile(profile):
                try:
                    with runtime.open(profile, require_virtual_display=True) as browser:
                        browser.page.set_content(
                            "<p>successful read before cleanup failure</p>"
                        )
                except BrowserRuntimeError as error:
                    assert str(error) == "browser_cleanup_failed"
                else:
                    raise AssertionError("cleanup failure was hidden")
        finally:
            runtime._launch = original_launch
            for restore in restorers:
                with suppress(Exception):
                    restore()

        with (
            leases.profile(profile),
            runtime.open(profile, require_virtual_display=True) as browser,
        ):
            assert any(
                c["name"] == "fixture" and c["value"] == "preserved"
                for c in browser.context.cookies()
            )
        closed = [
            json.loads(line)["facts"]
            for line in trace.read_text().splitlines()
            if json.loads(line)["event"] == "browser_closed"
        ]
        assert len(closed) == 3
        assert all(event["browser_exit_confirmed"] for event in closed)
        assert closed[1]["forced_termination"] is True
        assert set(closed[1]["cleanup_failures"]) == {"context_close", "driver_stop"}
        print(
            json.dumps(
                {
                    "ok": True,
                    "graceful_close": True,
                    "failed_close_reaped": True,
                    "reopen_preserved_cookies": True,
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
