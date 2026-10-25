"""Two simultaneous user browsers must never share a native input surface."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier

from newsclip.browser_runtime import PatchrightRuntime
from newsclip.browser_runtime.surface import ensure_virtual_display


def main() -> None:
    ensure_virtual_display()
    started, clicked = Barrier(2), Barrier(2)
    with TemporaryDirectory(prefix="newsclip-isolation-") as directory:

        def exercise(user: str):
            runtime = PatchrightRuntime()
            with runtime.open(
                Path(directory) / user, require_virtual_display=True
            ) as browser:
                browser.page.set_content(
                    "<button id='action' "
                    "onclick=\"this.textContent='clicked'\">ready</button>"
                )
                started.wait(timeout=30)
                if user == "alice":
                    browser.native_click(("#action",))
                clicked.wait(timeout=30)
                result = browser._display, browser.page.locator("#action").inner_text()
            runtime.close()
            return result

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(exercise, ("alice", "bob")))
        assert results[0][0] and results[1][0] and results[0][0] != results[1][0]
        assert results[0][1] == "clicked" and results[1][1] == "ready"
    print(
        "OK: simultaneous user browsers have isolated native input and clean shutdown"
    )


if __name__ == "__main__":
    main()
