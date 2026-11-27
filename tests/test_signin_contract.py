"""Application integration uses the installed library's supported API only."""

import ast
from pathlib import Path


def test_no_private_signin_window_imports_in_product():
    root = Path(__file__).resolve().parents[1] / "src" / "newsclip"
    failures = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("signin_window")
            ):
                failures.extend(
                    f"{path.name}:{node.lineno}:{alias.name}"
                    for alias in node.names
                    if alias.name.startswith("_")
                )
    assert not failures, failures


def test_human_signin_nyt_does_not_certify_logged_out_metered_session(
    tmp_path: Path, monkeypatch
) -> None:
    """Logged-out NYT metered pages must never trigger verification or promotion."""
    import threading
    import time
    from datetime import UTC, datetime, timedelta

    import patchright.sync_api as patchright_sync
    import signin_window.automation.profiles as sw_profiles
    import signin_window.automation.runtime as sw_runtime

    from newsclip.connection_controls import ConnectionControls
    from newsclip.provider_config import load_provider_spec
    from newsclip.providers.nyt import NYTProvider
    from newsclip.sessions import SessionStore
    from newsclip.signin import human_signin

    state_home = tmp_path / "state"
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(state_home))
    user_root = state_home / "users" / "alice"
    controls = ConnectionControls(user_root)
    revision = controls.begin("nyt", "default")

    fixture_html = (
        Path(__file__).parent / "fixtures" / "nyt" / "verification_full.html"
    ).read_text(encoding="utf-8")
    verification_url = (
        "https://www.nytimes.com/2026/07/17/business/fixture-lenders-raise-capital.html"
    )
    provider = NYTProvider(verification_url=verification_url)
    spec = load_provider_spec("nyt")
    future = (datetime.now(UTC) + timedelta(days=30)).timestamp()

    class FakeRequest:
        def is_navigation_request(self) -> bool:
            return True

    class FakeResponse:
        def __init__(self, url: str, status: int, frame: object) -> None:
            self.url = url
            self.status = status
            self.frame = frame
            self.headers = {"content-type": "text/html; charset=utf-8"}
            self.request = FakeRequest()

    class FakePage:
        def __init__(self) -> None:
            self.main_frame = object()
            self.url = "about:blank"
            self._handlers: dict[str, list] = {}
            self.goto_urls: list[str] = []
            self.polls = 0
            self.cookie_jar: list[dict[str, object]] = [
                {
                    "name": "nyt-a",
                    "value": "anon-id",
                    "domain": ".nytimes.com",
                    "path": "/",
                    "expires": future,
                },
                {
                    "name": "nyt-s-present",
                    "value": "0",
                    "domain": ".nytimes.com",
                    "path": "/",
                    "expires": future,
                },
            ]

        def on(self, event: str, handler) -> None:
            self._handlers.setdefault(event, []).append(handler)

        def emit_response(self, url: str, status: int = 200) -> None:
            resp = FakeResponse(url, status, self.main_frame)
            for handler in self._handlers.get("response", []):
                handler(resp)

        def goto(self, url: str, **_kwargs) -> None:
            self.goto_urls.append(url)
            self.url = url
            self.emit_response(url, 200)

        def content(self) -> str:
            return fixture_html

        def evaluate(self, expr: str, *_args):
            if expr == "navigator.userAgent":
                return "FixtureUA/1.0"
            return self.content()

        def is_closed(self) -> bool:
            return False

        def wait_for_timeout(self, _ms: int) -> None:
            self.polls += 1
            if self.polls == 1:
                # User bounces onto www.nytimes.com logged out (no NYT-S).
                self.url = "https://www.nytimes.com/"
                self.emit_response(self.url, 200)
            elif self.polls == 3:
                # Must not have navigated to verification_url yet!
                assert verification_url not in self.goto_urls
                # Now user finishes signing in and receives NYT-S.
                self.cookie_jar.append(
                    {
                        "name": "NYT-S",
                        "value": "fixture-subscriber-token",
                        "domain": ".nytimes.com",
                        "path": "/",
                        "expires": future,
                    }
                )

    page = FakePage()

    class FakeContext:
        def __init__(self) -> None:
            self.pages = [page]

        def route(self, _pattern, _handler) -> None:
            pass

        def cookies(self):
            return list(page.cookie_jar)

        def close(self) -> None:
            pass

    class FakeChromium:
        def launch_persistent_context(self, *_args, **_kwargs):
            return FakeContext()

    class FakePlaywright:
        chromium = FakeChromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeWindow:
        params = {
            "user": "alice",
            "provider": "nyt",
            "account_key": "default",
            "connection_revision": revision,
        }
        cancelled = threading.Event()
        deadline = time.monotonic() + 30
        finished: list[str] = []

        def env(self) -> dict[str, str]:
            return {}

        def waiting(self, _host: str) -> None:
            pass

        def at(self, _host: str) -> None:
            pass

        def saving(self) -> None:
            pass

        def finish(self, status: str) -> None:
            self.finished.append(status)

    store = SessionStore(user_root, recipes={"nyt": provider.login_recipe}, http=None)

    class FakeService:
        _sessions = store

        def close(self) -> None:
            pass

    class FakeRegistry:
        def get(self, _key: str):
            return provider

    monkeypatch.setattr(patchright_sync, "sync_playwright", lambda: FakePlaywright())
    monkeypatch.setattr(sw_profiles.OwnedBrowserProcess, "capture", lambda _p: None)
    monkeypatch.setattr(sw_runtime, "close_owned_browser", lambda *a, **k: None)
    monkeypatch.setattr("signin_window.browser.harden_sync", lambda _c: None)

    window = FakeWindow()
    human_signin(
        window,
        registry=FakeRegistry(),
        spec_loader=lambda _k: spec,
        service_factory=lambda **_k: FakeService(),
    )

    assert window.finished == ["connected"]
    assert page.goto_urls.count(verification_url) == 1


def test_human_signin_ignores_3xx_survives_transient_errors_and_unlatches_verifying(
    tmp_path: Path, monkeypatch
) -> None:
    """3xx responses, transient errors, and failed checks must not break sign-in."""
    import threading
    import time
    from datetime import UTC, datetime, timedelta

    import patchright.sync_api as patchright_sync
    import signin_window.automation.profiles as sw_profiles
    import signin_window.automation.runtime as sw_runtime
    from patchright.sync_api import Error as PlaywrightError

    from newsclip.connection_controls import ConnectionControls
    from newsclip.errors import ProviderTransportError
    from newsclip.provider_config import load_provider_spec
    from newsclip.providers.economist import EconomistProvider
    from newsclip.sessions import SessionStore
    from newsclip.signin import human_signin

    state_home = tmp_path / "state"
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(state_home))
    user_root = state_home / "users" / "alice"
    controls = ConnectionControls(user_root)
    revision = controls.begin("economist", "default")

    verification_url = (
        "https://www.economist.com/business/2026/07/16/"
        "how-sk-hynix-became-the-king-of-advanced-memory-chips"
    )
    paragraphs = "".join(
        "<p>Substantive Economist fixture reporting proves paid article access. "
        + "Verified words preserve the same full-content assessment boundary. " * 20
        + "</p>"
        for _ in range(5)
    )
    full_html = f"""
    <html><head>
      <title>Fixture Economist report</title>
      <link rel="canonical" href="{verification_url}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Fixture Economist report"}}
      </script>
    </head><body><main><article>
      <h1>Fixture Economist report</h1>{paragraphs}
    </article></main></body></html>
    """
    teaser_html = f"""
    <html><head><title>Fixture Economist report</title>
      <link rel="canonical" href="{verification_url}">
    </head><body><main><article><h1>Fixture Economist report</h1>
      <p>Short preview.</p><teg-inline-wall>Log in</teg-inline-wall>
    </article></main></body></html>
    """

    provider = EconomistProvider(verification_url=verification_url)
    spec = load_provider_spec("economist")
    future = (datetime.now(UTC) + timedelta(days=30)).timestamp()

    class FakeRequest:
        def is_navigation_request(self) -> bool:
            return True

    class FakeResponse:
        def __init__(self, url: str, status: int, frame: object) -> None:
            self.url = url
            self.status = status
            self.frame = frame
            self.headers = {"content-type": "text/html; charset=utf-8"}
            self.request = FakeRequest()

    class FakePage:
        def __init__(self) -> None:
            self.main_frame = object()
            self.url = "about:blank"
            self._handlers: dict[str, list] = {}
            self.goto_urls: list[str] = []
            self.polls = 0
            self.logged_in = False
            self.transient_stage = 0
            self.cookie_jar: list[dict[str, object]] = [
                {
                    "name": "ec_anon",
                    "value": "fixture",
                    "domain": ".economist.com",
                    "path": "/",
                    "expires": future,
                }
            ]

        def on(self, event: str, handler) -> None:
            self._handlers.setdefault(event, []).append(handler)

        def emit_response(self, url: str, status: int = 200) -> None:
            resp = FakeResponse(url, status, self.main_frame)
            for handler in self._handlers.get("response", []):
                handler(resp)

        def goto(self, url: str, **_kwargs) -> None:
            self.goto_urls.append(url)
            self.url = url
            if url == verification_url:
                # Emit a 200 then a 302 redirect response (302 must be ignored).
                self.emit_response(url, 200)
                self.emit_response(url, 302)
            else:
                self.emit_response(url, 200)

        def content(self) -> str:
            if self.transient_stage == 1:
                self.transient_stage = 2
                raise ProviderTransportError("execution context destroyed")
            if self.transient_stage == 2:
                self.transient_stage = 3
                raise PlaywrightError("Execution context was destroyed")
            return full_html if self.logged_in else teaser_html

        def evaluate(self, expr: str, *_args):
            if expr == "navigator.userAgent":
                return "FixtureUA/1.0"
            return self.content()

        def is_closed(self) -> bool:
            return False

        def wait_for_timeout(self, _ms: int) -> None:
            self.polls += 1
            if self.polls == 1:
                # Land on www.economist.com before signing in -> triggers teaser check.
                self.url = "https://www.economist.com/"
                self.emit_response(self.url, 200)
                self.transient_stage = 1
            elif self.polls == 4:
                # Transient non-HTTP URL during navigation must not crash loop.
                self.url = "about:blank"
            elif self.polls == 5:
                # User navigates back to login page -> must unlatch verifying!
                self.url = str(spec.require_auth().login_url)
                self.emit_response(self.url, 200)
            elif self.polls == 6:
                # User signs in and returns to www.economist.com.
                self.logged_in = True
                self.url = "https://www.economist.com/"
                self.emit_response(self.url, 200)

    page = FakePage()

    class FakeContext:
        def __init__(self) -> None:
            self.pages = [page]

        def route(self, _pattern, _handler) -> None:
            pass

        def cookies(self):
            return list(page.cookie_jar)

        def close(self) -> None:
            pass

    class FakeChromium:
        def launch_persistent_context(self, *_args, **_kwargs):
            return FakeContext()

    class FakePlaywright:
        chromium = FakeChromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeWindow:
        params = {
            "user": "alice",
            "provider": "economist",
            "account_key": "default",
            "connection_revision": revision,
        }
        cancelled = threading.Event()
        deadline = time.monotonic() + 30
        finished: list[str] = []

        def env(self) -> dict[str, str]:
            return {}

        def waiting(self, _host: str) -> None:
            pass

        def at(self, _host: str) -> None:
            pass

        def saving(self) -> None:
            pass

        def finish(self, status: str) -> None:
            self.finished.append(status)

    store = SessionStore(
        user_root, recipes={"economist": provider.login_recipe}, http=None
    )

    class FakeService:
        _sessions = store

        def close(self) -> None:
            pass

    class FakeRegistry:
        def get(self, _key: str):
            return provider

    monkeypatch.setattr(patchright_sync, "sync_playwright", lambda: FakePlaywright())
    monkeypatch.setattr(sw_profiles.OwnedBrowserProcess, "capture", lambda _p: None)
    monkeypatch.setattr(sw_runtime, "close_owned_browser", lambda *a, **k: None)
    monkeypatch.setattr("signin_window.browser.harden_sync", lambda _c: None)

    window = FakeWindow()
    human_signin(
        window,
        registry=FakeRegistry(),
        spec_loader=lambda _k: spec,
        service_factory=lambda **_k: FakeService(),
    )

    assert window.finished == ["connected"]
    # Verification URL was visited twice: once before login (failed teaser),
    # and again after returning from login.
    assert page.goto_urls.count(verification_url) == 2
