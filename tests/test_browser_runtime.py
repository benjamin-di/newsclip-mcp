from __future__ import annotations

import ast
import json
import multiprocessing
import socket
import stat
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from signin_window.automation import pointer as x11_pointer_module

from newsclip.browser_runtime import runtime as runtime_module
from newsclip.browser_runtime import surface as surface_module
from newsclip.browser_runtime.events import (
    AttemptPurpose,
    AuthEvidenceFamily,
    AuthPhase,
    BrowserClosedEvent,
    BrowserFailedEvent,
    BrowserFailureCategory,
    BrowserFailurePhase,
    BrowserMode,
    BrowserOperation,
    DisplayClass,
    HCaptchaRoundEvent,
    IdentityHandoffEvent,
    PerimeterXHoldEvent,
    ReadinessCoverageBucket,
    ReadinessTerminalState,
    RouteClass,
    RuntimeTrace,
    SurfaceMode,
    SurfaceSelectedEvent,
)
from newsclip.browser_runtime.leases import (
    LeaseBusyError,
    LeaseKind,
    LeaseManager,
    LockOrderError,
    ordered_file_lease,
)
from newsclip.browser_runtime.runtime import (
    BrowserLaunchConfig,
    ObservedNavigation,
    PasskeyMode,
    PatchrightMintContext,
    PatchrightRuntime,
    _browser_major,
    _failure_category,
)
from newsclip.browser_runtime.surface import (
    BrowserRuntimeError,
    InfrastructureCategory,
    SurfaceHandle,
    ensure_virtual_display,
    maybe_reexec_for_virtual_display,
)
from newsclip.browser_runtime.x11_pointer import (
    NativePointerUnavailable,
    X11Pointer,
)
from newsclip.vision_planning import VisualPlan

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class _FakeCFunction:
    def __init__(self, implementation) -> None:  # noqa: ANN001
        self.implementation = implementation
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):  # noqa: ANN002, ANN204
        return self.implementation(*args)


def _hold_attempt_lease(lock_root: str, ready, release) -> None:
    manager = LeaseManager(Path(lock_root))
    with manager.attempt("fixture", "same-account", timeout_seconds=2):
        ready.set()
        release.wait(10)


def test_runtime_trace_is_closed_redacted_and_private(tmp_path: Path) -> None:
    path = tmp_path / "traces" / "events.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-1")

    with pytest.raises(ValidationError):
        trace.write(  # type: ignore[arg-type]
            {
                "event": "surface_selected",
                "mode": "managed_virtual",
                "display_class": "virtual_local",
                "profile_path": "/private/PROFILE_SENTINEL",
            }
        )
    assert not path.exists()

    trace.write(
        SurfaceSelectedEvent(
            mode=SurfaceMode.MANAGED_VIRTUAL,
            display_class=DisplayClass.VIRTUAL_LOCAL,
        )
    )
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["sequence"] == 1
    assert row["facts"] == {
        "display_class": "virtual_local",
        "mode": "managed_virtual",
    }
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "PROFILE_SENTINEL" not in path.read_text(encoding="utf-8")


def test_runtime_event_models_reject_unknown_values_and_fields() -> None:
    with pytest.raises(ValidationError):
        SurfaceSelectedEvent.model_validate(
            {
                "mode": "pure_headless",
                "display_class": "virtual_local",
            }
        )


def test_attempt_observation_and_action_ledger_is_correlated_and_pre_dispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="semantic-runtime")

    class Page:
        url = "https://accounts.ft.com/login"

        def goto(self, url: str, **kwargs) -> None:  # noqa: ANN003
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            assert rows[-1]["event"] == "semantic_action_started"
            self.url = url

    browser = PatchrightMintContext(SimpleNamespace(), Page(), trace=trace)

    with browser.attempt("ft", AttemptPurpose.LOGIN):
        browser.record_auth_observation(
            phase=AuthPhase.PASSWORD,
            state_code="password_visible",
            observation_id="password_visible",
            evidence_families=(AuthEvidenceFamily.SELECTOR,),
            route_class=RouteClass.PUBLISHER_AUTH,
            selector_error=False,
        )
        browser.navigate("https://accounts.ft.com/private?secret=sentinel")

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "attempt_started",
        "auth_observation",
        "semantic_action_started",
        "semantic_action_finished",
        "attempt_finished",
    ]
    attempt_ids = {
        row["facts"]["attempt_id"] for row in rows if "attempt_id" in row["facts"]
    }
    assert len(attempt_ids) == 1
    assert rows[-1]["facts"] == {
        "attempt_id": next(iter(attempt_ids)),
        "last_phase": "password",
        "last_navigation": rows[-2]["facts"]["navigation"],
        "capture_failure": None,
        "outcome": "success",
        "provider": "ft",
    }
    assert rows[1]["facts"]["control_cardinality"] == "not_checked"
    assert "sentinel" not in path.read_text(encoding="utf-8")


def test_runtime_trace_records_one_closed_readiness_terminal(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="readiness-terminal")
    browser = PatchrightMintContext(
        SimpleNamespace(),
        SimpleNamespace(),
        trace=trace,
    )

    with browser.attempt("bloomberg", AttemptPurpose.RETRIEVE):
        browser.record_semantic_readiness_terminal(
            state=ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT,
            word_count=495,
            coverage_bucket=ReadinessCoverageBucket.FROM_75_TO_89,
            content_change_count=2,
            last_content_change_ms=180,
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "attempt_started",
        "semantic_readiness_terminal",
        "attempt_finished",
    ]
    assert rows[1]["facts"] == {
        "attempt_id": rows[0]["facts"]["attempt_id"],
        "content_change_count": 2,
        "coverage_bucket": "from_75_to_89",
        "last_content_change_ms": 180,
        "provider": "bloomberg",
        "state": "promotable_incomplete_timeout",
        "word_count": 495,
    }
    assert "PRIVATE_ARTICLE_SENTINEL" not in path.read_text(encoding="utf-8")


def test_failed_semantic_action_conservatively_records_ambiguous_dispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="failed-semantic")

    class Page:
        url = "https://accounts.ft.com/login"

        def goto(self, url: str, **kwargs) -> None:  # noqa: ANN003
            raise RuntimeError("PRIVATE_SENTINEL")

    browser = PatchrightMintContext(SimpleNamespace(), Page(), trace=trace)

    with (
        pytest.raises(RuntimeError, match="PRIVATE_SENTINEL"),
        browser.attempt("ft", AttemptPurpose.LOGIN),
    ):
        browser.navigate("https://accounts.ft.com/private")

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    action = next(row for row in rows if row["event"] == "semantic_action_finished")
    assert action["facts"]["dispatched"] is True
    assert action["facts"]["result"] == "unknown"
    assert rows[-1]["facts"]["outcome"] == "error"
    assert "PRIVATE_SENTINEL" not in path.read_text(encoding="utf-8")


def test_auth_and_challenge_mutations_record_before_ambiguous_failures(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="auth-mutations")

    class Keyboard:
        def press(self, key: str) -> None:
            raise RuntimeError("PRIVATE_KEY_SENTINEL")

    class Page:
        url = "https://accounts.google.com/challenge"
        keyboard = Keyboard()

    class Context:
        def clear_cookies(self) -> None: ...

        def add_cookies(self, cookies) -> None:  # noqa: ANN001
            raise RuntimeError("PRIVATE_COOKIE_SENTINEL")

    browser = PatchrightMintContext(Context(), Page(), trace=trace)

    with browser.attempt("bloomberg", AttemptPurpose.LOGIN):
        with pytest.raises(RuntimeError, match="PRIVATE_KEY_SENTINEL"):
            browser.press_page("Enter")
        with pytest.raises(RuntimeError, match="PRIVATE_COOKIE_SENTINEL"):
            browser.replace_cookies([{"name": "PRIVATE_COOKIE_SENTINEL"}])
        with pytest.raises(RuntimeError, match="PRIVATE_CHALLENGE_SENTINEL"):
            browser.dispatch_challenge_action(
                lambda: (_ for _ in ()).throw(
                    RuntimeError("PRIVATE_CHALLENGE_SENTINEL")
                )
            )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    started = [
        row["facts"]["action"]
        for row in rows
        if row["event"] == "semantic_action_started"
    ]
    finished = [
        row["facts"] for row in rows if row["event"] == "semantic_action_finished"
    ]
    assert started == ["press", "replace_cookies", "challenge_action"]
    assert all(item["dispatched"] is True for item in finished)
    assert all(item["result"] == "unknown" for item in finished)
    rendered = path.read_text(encoding="utf-8")
    assert "PRIVATE_KEY_SENTINEL" not in rendered
    assert "PRIVATE_COOKIE_SENTINEL" not in rendered
    assert "PRIVATE_CHALLENGE_SENTINEL" not in rendered


def test_timeout_is_closed_at_action_and_attempt_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "traces/runtime.jsonl"
    trace = RuntimeTrace(path, run_id="timeout-semantic")

    class Page:
        url = "https://accounts.ft.com/login"

        def goto(self, url: str, **kwargs) -> None:  # noqa: ANN003
            raise TimeoutError("PRIVATE_TIMEOUT_SENTINEL")

    browser = PatchrightMintContext(SimpleNamespace(), Page(), trace=trace)
    with pytest.raises(TimeoutError), browser.attempt("ft", AttemptPurpose.LOGIN):
        browser.navigate("https://accounts.ft.com/private")

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    action = next(row for row in rows if row["event"] == "semantic_action_finished")
    assert action["facts"]["result"] == "timeout"
    assert rows[-1]["facts"]["outcome"] == "timeout"
    assert "PRIVATE_TIMEOUT_SENTINEL" not in path.read_text(encoding="utf-8")


def test_runtime_trace_serializes_concurrent_event_sequences(tmp_path: Path) -> None:
    path = tmp_path / "traces" / "concurrent.jsonl"
    trace = RuntimeTrace(path, run_id="concurrent-runtime")
    event = SurfaceSelectedEvent(
        mode=SurfaceMode.MANAGED_VIRTUAL,
        display_class=DisplayClass.VIRTUAL_LOCAL,
    )
    threads = [threading.Thread(target=trace.write, args=(event,)) for _ in range(20)]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)

    assert not any(thread.is_alive() for thread in threads)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["sequence"] for row in rows] == list(range(1, 21))


def test_runtime_failure_screenshot_never_overwrites_existing_artifact(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    screenshot_path = path.with_suffix(".failure.png")
    screenshot_path.parent.mkdir(parents=True)
    screenshot_path.write_bytes(b"existing")
    trace = RuntimeTrace(path, run_id="runtime-no-overwrite")

    with pytest.raises(FileExistsError):
        trace.write_failure_screenshot(b"replacement")

    assert screenshot_path.read_bytes() == b"existing"


@pytest.mark.parametrize("label", ("../escape", "UPPER", "space label", ""))
def test_runtime_screenshot_label_is_closed(label: str, tmp_path: Path) -> None:
    trace = RuntimeTrace(tmp_path / "traces" / "runtime.jsonl", run_id="runtime-label")

    with pytest.raises(ValueError, match="label"):
        trace.write_screenshot(label, b"png")

    assert list(tmp_path.rglob("*.png")) == []


def test_x11_pointer_maps_viewport_geometry_and_delivers_xtest_events(
    monkeypatch,
) -> None:
    motion_events: list[tuple[object, ...]] = []
    button_events: list[tuple[object, ...]] = []
    closed: list[object] = []

    def query_pointer(*args) -> int:  # noqa: ANN002
        args[4]._obj.value = 0
        args[5]._obj.value = 0
        return 1

    x11 = SimpleNamespace(
        XOpenDisplay=_FakeCFunction(lambda _name: 101),
        XCloseDisplay=_FakeCFunction(lambda display: closed.append(display) or 0),
        XDefaultScreen=_FakeCFunction(lambda _display: 0),
        XDisplayWidth=_FakeCFunction(lambda _display, _screen: 1280),
        XRootWindow=_FakeCFunction(lambda _display, _screen: 1),
        XQueryPointer=_FakeCFunction(query_pointer),
        XFlush=_FakeCFunction(lambda _display: 0),
    )
    xtst = SimpleNamespace(
        XTestQueryExtension=_FakeCFunction(lambda *_args: 1),
        XTestFakeMotionEvent=_FakeCFunction(
            lambda *args: motion_events.append(args) or 1
        ),
        XTestFakeButtonEvent=_FakeCFunction(
            lambda *args: button_events.append(args) or 1
        ),
    )
    monkeypatch.setattr(
        x11_pointer_module.ctypes,
        "CDLL",
        lambda name: x11 if name == "libX11.so.6" else xtst,
    )
    monkeypatch.setenv("DISPLAY", ":109")

    class Page:
        def evaluate(self, _expression: str) -> dict[str, float]:
            return {
                "screenX": 0,
                "screenY": 0,
                "outerWidth": 1280,
                "outerHeight": 800,
                "innerWidth": 1280,
                "innerHeight": 720,
                "screenWidth": 1280,
            }

    pointer = X11Pointer(Page())
    pointer.move(100, 200, steps=2)
    pointer.down()
    pointer.up()
    pointer.close()
    pointer.close()

    assert [(event[2], event[3]) for event in motion_events] == [
        (50, 140),
        (100, 280),
    ]
    assert [(event[1], event[2]) for event in button_events] == [
        (1, True),
        (1, False),
    ]
    assert closed == [101]


def test_virtual_challenge_pointer_is_native_closed_and_typed(monkeypatch) -> None:
    closed = 0

    class Pointer:
        def close(self) -> None:
            nonlocal closed
            closed += 1

    pointer = Pointer()
    page = SimpleNamespace(mouse=object())
    browser = PatchrightMintContext(SimpleNamespace(), page)
    monkeypatch.setenv("NEWSCLIP_VIRTUAL_DISPLAY", "1")
    monkeypatch.setattr(runtime_module, "X11Pointer", lambda selected: pointer)

    with browser.challenge_pointer() as selected:
        assert selected is pointer
    assert closed == 1

    def unavailable(_page):  # noqa: ANN001, ANN202
        raise NativePointerUnavailable("PRIVATE_X11_SENTINEL")

    monkeypatch.setattr(runtime_module, "X11Pointer", unavailable)
    with (
        pytest.raises(BrowserRuntimeError) as caught,
        browser.challenge_pointer(),
    ):
        pass
    assert caught.value.category is InfrastructureCategory.NATIVE_INPUT_UNAVAILABLE
    assert "PRIVATE_X11_SENTINEL" not in str(caught.value)

    monkeypatch.setattr(runtime_module, "X11Pointer", lambda selected: pointer)
    with (
        pytest.raises(BrowserRuntimeError) as caught,
        browser.challenge_pointer(),
    ):
        raise NativePointerUnavailable("PRIVATE_MOTION_SENTINEL")
    assert closed == 2
    assert caught.value.category is InfrastructureCategory.NATIVE_INPUT_UNAVAILABLE
    assert "PRIVATE_MOTION_SENTINEL" not in str(caught.value)


def test_desktop_challenge_pointer_prefers_native_x11_with_cdp_fallback(
    monkeypatch,
) -> None:
    driver_pointer = object()
    closed = 0

    class Pointer:
        def close(self) -> None:
            nonlocal closed
            closed += 1

    native = Pointer()
    browser = PatchrightMintContext(
        SimpleNamespace(),
        SimpleNamespace(mouse=driver_pointer),
    )
    monkeypatch.delenv("NEWSCLIP_VIRTUAL_DISPLAY", raising=False)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(runtime_module, "X11Pointer", lambda selected: native)

    with browser.challenge_pointer() as selected:
        assert selected is native
    assert closed == 1

    def unavailable(_page):  # noqa: ANN001, ANN202
        raise NativePointerUnavailable("PRIVATE_X11_DESKTOP_SENTINEL")

    monkeypatch.setattr(runtime_module, "X11Pointer", unavailable)
    with browser.challenge_pointer() as selected:
        assert selected is driver_pointer

    monkeypatch.delenv("DISPLAY", raising=False)
    with browser.challenge_pointer() as selected:
        assert selected is driver_pointer


def test_fill_all_visible_uses_bounded_controlled_input_fill() -> None:
    actions: list[object] = []

    class Locator:
        def count(self) -> int:
            return 1

        def nth(self, index: int):
            assert index == 0
            return self

        def is_visible(self) -> bool:
            return True

        def fill(self, value: str, *, timeout: int) -> None:
            actions.append(("fill", value, timeout))

        def type(self, value: str, *, delay: int, timeout: int) -> None:
            actions.append(("type", value, delay, timeout))

        def dispatch_event(self, event: str) -> None:
            actions.append(("dispatch", event))

        def click(self) -> None:  # pragma: no cover - regression guard
            raise AssertionError("covered input must not use pointer actionability")

    locator = Locator()
    page = SimpleNamespace(frames=[], locator=lambda selector: locator)
    browser = PatchrightMintContext(SimpleNamespace(), page)

    filled = browser.fill_all_visible(("input[name='email']",), "secret")

    assert filled == 1
    assert actions == [
        ("fill", "", 8_000),
        ("type", "secret", 55, 8_000),
        ("dispatch", "change"),
        ("dispatch", "blur"),
    ]
    assert browser.last_operation is BrowserOperation.FILL_ALL_VISIBLE


def test_secret_fill_skips_matching_controls_in_cross_origin_frames() -> None:
    actions: list[tuple[str, str]] = []

    class Handle:
        def __init__(self, origin: str) -> None:
            self.origin = origin

        def click(self) -> None:
            actions.append((self.origin, "click"))

        def fill(self, value: str) -> None:
            actions.append((self.origin, value))

    class Locator:
        def __init__(self, handle: Handle) -> None:
            self.handle = handle

        def count(self) -> int:
            return 1

        def nth(self, index: int):
            assert index == 0
            return self

        def is_visible(self) -> bool:
            return True

        def element_handle(self) -> Handle:
            return self.handle

    class Frame:
        def __init__(self, url: str) -> None:
            self.url = url
            self.handle = Handle(url)

        def locator(self, selector: str) -> Locator:
            assert selector == "input[type='password']"
            return Locator(self.handle)

    evil = Frame("https://evil.test/login")
    allowed = Frame("https://accounts.ft.com/login")
    page = SimpleNamespace(frames=[evil, allowed])
    browser = PatchrightMintContext(SimpleNamespace(), page)

    browser.fill(
        ("input[type='password']",),
        "SECRET_SENTINEL",
        allowed_origins=frozenset({"https://accounts.ft.com"}),
    )

    assert actions == [
        ("https://accounts.ft.com/login", "click"),
        ("https://accounts.ft.com/login", "SECRET_SENTINEL"),
    ]


def test_secret_fill_rejects_redirect_after_locator_resolution() -> None:
    actions: list[str] = []

    class Handle:
        def click(self) -> None:
            actions.append("click")

        def fill(self, value: str) -> None:
            actions.append(value)

    class Frame:
        url = "https://accounts.ft.com/login"

        def locator(self, selector: str):
            frame = self

            class Locator:
                def count(self) -> int:
                    return 1

                def nth(self, index: int):
                    assert index == 0
                    return self

                def is_visible(self) -> bool:
                    return True

                def element_handle(self) -> Handle:
                    frame.url = "https://evil.test/login"
                    return Handle()

            return Locator()

    frame = Frame()
    browser = PatchrightMintContext(
        SimpleNamespace(),
        SimpleNamespace(frames=[frame]),
    )

    with pytest.raises(RuntimeError, match="visible control"):
        browser.fill(
            ("input[type='password']",),
            "SECRET_SENTINEL",
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )

    assert actions == []


def test_native_click_uses_visible_geometry_and_always_releases(monkeypatch) -> None:
    events: list[object] = []

    class Pointer:
        def move(self, x: float, y: float, *, steps: int) -> None:
            events.append((x, y, steps))

        def down(self) -> None:
            events.append("down")

        def up(self) -> None:
            events.append("up")

    class Locator:
        def count(self) -> int:
            return 1

        def nth(self, index: int):
            assert index == 0
            return self

        def is_visible(self) -> bool:
            return True

        def bounding_box(self) -> dict[str, float]:
            return {"x": 20, "y": 30, "width": 100, "height": 40}

    class Page:
        mouse = Pointer()

        def locator(self, selector: str) -> Locator:
            assert selector == "button"
            return Locator()

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert milliseconds == 60

    monkeypatch.delenv("NEWSCLIP_VIRTUAL_DISPLAY", raising=False)
    # Force CDP mouse: native X11 needs a real display + page.evaluate geometry.
    monkeypatch.delenv("DISPLAY", raising=False)
    browser = PatchrightMintContext(SimpleNamespace(), Page())

    browser.native_click(("button",))

    assert events == [(70.0, 50.0, 8), "down", "up"]
    assert browser.last_operation is BrowserOperation.MOUSE_CLICK

    class FailingPage(Page):
        def wait_for_timeout(self, milliseconds: int) -> None:
            raise RuntimeError("fixture wait failure")

    events.clear()
    browser = PatchrightMintContext(SimpleNamespace(), FailingPage())
    with pytest.raises(RuntimeError, match="fixture wait failure"):
        browser.native_click(("button",))
    assert events[-2:] == ["down", "up"]


def test_product_browser_boundaries_exclude_legacy_workarounds() -> None:
    product_root = REPOSITORY_ROOT / "src/newsclip"
    product_source = "\n".join(
        path.read_text(encoding="utf-8") for path in product_root.rglob("*.py")
    )
    for forbidden in (
        "NEWSCLIP_FT_RISK_BUMP",
        "navigator.webdriver",
        "force_remint",
        "ProfileSessionStore",
        "ProfileSessionArtifact",
        "BrowserSessionMinter",
    ):
        assert forbidden not in product_source

    # Native HTMLFormElement.prototype.submit is intentional only for FT
    # enter-email advance (passkey/WebAuthn hang under virtual display). CAPTCHA
    # password continuation and other product modules must not reintroduce it.
    for path in product_root.rglob("*.py"):
        if "HTMLFormElement.prototype.submit" not in path.read_text(encoding="utf-8"):
            continue
        assert path.relative_to(product_root) == Path("providers/ft_auth.py"), path

    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (product_root / "browser_runtime").rglob("*.py")
    ).lower()
    for provider_fact in ("accounts.ft.com", "ftsession", "wsj.com", "bloomberg.com"):
        assert provider_fact not in runtime_source

    mechanic_source = (product_root / "hcaptcha.py").read_text(encoding="utf-8")
    for policy_fact in ("ft_auth", "password-form", "secret_ref", "SessionStore"):
        assert policy_fact not in mechanic_source


def test_product_and_product_tests_never_import_bench() -> None:
    roots = (REPOSITORY_ROOT / "src/newsclip", REPOSITORY_ROOT / "tests")
    for root in roots:
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert all(
                        alias.name != "bench" and not alias.name.startswith("bench.")
                        for alias in node.names
                    )
                elif isinstance(node, ast.ImportFrom):
                    assert node.module != "bench" and not (
                        node.module or ""
                    ).startswith("bench.")


def test_runtime_event_models_reject_free_text() -> None:
    with pytest.raises(ValidationError):
        BrowserClosedEvent.model_validate(
            {
                "browser_mode": "headed_virtual",
                "profile_generation": "retained",
                "duration": "under_1s",
                "cleanup_ok": True,
                "note": "ARBITRARY_SENTINEL",
            }
        )


def test_ranked_leases_enforce_canonical_order_and_private_modes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "locks"
    session_path = root / "session.lock"
    manager = LeaseManager(root)
    profile = tmp_path / "profile"

    with (
        ordered_file_lease(session_path, kind=LeaseKind.SESSION_GENERATION),
        manager.attempt("fixture", "private-account"),
        manager.profile(profile),
    ):
        assert True

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in root.iterdir())
    assert "private-account" not in " ".join(path.name for path in root.iterdir())

    with (
        manager.profile(profile),
        pytest.raises(LockOrderError),
        manager.attempt("fixture", "private-account"),
    ):
        pass

    with manager.attempt("news_wire", "private-account"):
        pass
    with pytest.raises(ValueError, match="invalid provider key"):
        manager.attempt("news.wire", "private-account")
    with pytest.raises(ValueError, match="invalid account key"):
        manager.attempt("fixture", "../private-account")


def test_attempt_lease_times_out_then_recovers_after_worker_death(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_attempt_lease,
        args=(str(tmp_path / "locks"), ready, release),
    )
    process.start()
    assert ready.wait(5)
    manager = LeaseManager(tmp_path / "locks")
    with (
        pytest.raises(LeaseBusyError),
        manager.attempt("fixture", "same-account", timeout_seconds=0.05),
    ):
        pass

    process.terminate()
    process.join(timeout=5)
    assert not process.is_alive()
    with manager.attempt("fixture", "same-account", timeout_seconds=1):
        pass


def test_virtual_display_selection_is_managed_then_host_and_fails_closed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(surface_module, "display_is_usable", lambda display=None: True)
    managed = ensure_virtual_display(
        environment={"DISPLAY": ":109", "NEWSCLIP_VIRTUAL_DISPLAY": "1"}
    )
    assert managed.mode is SurfaceMode.MANAGED_VIRTUAL

    host = SurfaceHandle(
        SurfaceMode.HOST_XVFB,
        DisplayClass.VIRTUAL_LOCAL,
        ":109",
    )
    monkeypatch.setattr(surface_module, "_start_host_xvfb", lambda *a, **k: host)
    environment: dict[str, str] = {}
    assert ensure_virtual_display(environment=environment) is host
    assert environment["NEWSCLIP_DENY_SYSTEM_DISPLAY"] == "1"

    surface_module._ACTIVE = None
    monkeypatch.setattr(surface_module, "_start_host_xvfb", lambda *a, **k: None)
    with pytest.raises(BrowserRuntimeError) as caught:
        ensure_virtual_display(environment={})
    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE


def test_default_host_displays_are_independently_leased(tmp_path, monkeypatch):
    environment = {"NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases")}
    monkeypatch.setattr(surface_module, "_LOCAL_X11_SOCKET_ROOT", tmp_path / "sockets")
    first = surface_module._acquire_host_display(None, environment)
    second = surface_module._acquire_host_display(None, environment)
    try:
        assert first is not None and second is not None
        assert first.number != second.number
        assert 1000 <= first.number <= 9999
        assert 1000 <= second.number <= 9999
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()


def test_host_xvfb_lease_prevents_concurrent_reuse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_DISPLAY": "2109",
        "OP_SERVICE_ACCOUNT_TOKEN": "synthetic-operator",
    }
    display_live = False
    processes = []

    class FakeProcess:
        def __init__(self) -> None:
            nonlocal display_live
            self.pid = 4200 + len(processes)
            self.running = True
            display_live = True

        def poll(self):
            return None if self.running else 0

        def terminate(self) -> None:
            nonlocal display_live
            self.running = False
            display_live = False

        def kill(self) -> None:
            self.terminate()

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == 5
            self.running = False
            return 0

    def start_process(*_args, **_kwargs):
        assert "OP_SERVICE_ACCOUNT_TOKEN" not in _kwargs["env"]
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(surface_module.shutil, "which", lambda _name: "/usr/bin/Xvfb")
    monkeypatch.setattr(
        surface_module,
        "display_is_usable",
        lambda _display=None: display_live,
    )
    monkeypatch.setattr(
        surface_module,
        "_LOCAL_X11_SOCKET_ROOT",
        tmp_path / "sockets",
    )
    monkeypatch.setattr(surface_module.subprocess, "Popen", start_process)

    owner = surface_module._start_host_xvfb(2109, environment=environment)
    assert owner is not None
    assert owner.display_lease is not None

    borrower = surface_module._start_host_xvfb(2109, environment=environment)
    assert borrower is None
    assert len(processes) == 1

    owner.close()
    replacement = surface_module._start_host_xvfb(2109, environment=environment)
    assert replacement is not None
    assert len(processes) == 2
    replacement.close()


def test_dead_active_host_xvfb_releases_lease_before_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_DISPLAY": "2109",
    }
    display_live = False
    processes = []

    class FakeProcess:
        def __init__(self) -> None:
            nonlocal display_live
            self.pid = 4300 + len(processes)
            self.running = True
            display_live = True

        def poll(self):
            return None if self.running else 0

        def terminate(self) -> None:
            nonlocal display_live
            self.running = False
            display_live = False

        def kill(self) -> None:
            self.terminate()

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == 5
            self.running = False
            return 0

        def crash(self) -> None:
            nonlocal display_live
            self.running = False
            display_live = False

    def start_process(*_args, **_kwargs):
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(surface_module.shutil, "which", lambda _name: "/usr/bin/Xvfb")
    monkeypatch.setattr(
        surface_module,
        "display_is_usable",
        lambda _display=None: display_live,
    )
    monkeypatch.setattr(
        surface_module,
        "_LOCAL_X11_SOCKET_ROOT",
        tmp_path / "sockets",
    )
    monkeypatch.setattr(surface_module.subprocess, "Popen", start_process)
    monkeypatch.setattr(surface_module.atexit, "register", lambda _callback: None)
    surface_module._ACTIVE = None

    try:
        owner = ensure_virtual_display(environment=environment)
        assert owner.display_lease is not None
        processes[0].crash()

        replacement = ensure_virtual_display(
            environment={
                "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
                "NEWSCLIP_XVFB_DISPLAY": "2109",
            }
        )

        assert replacement is not owner
        assert len(processes) == 2
        assert owner.display_lease is None
        assert owner.host_process is None
        assert owner.pid is None
        assert replacement.display_lease is not None
        assert surface_module._ACTIVE is replacement
    finally:
        if surface_module._ACTIVE is not None:
            surface_module._ACTIVE.close()
        surface_module._ACTIVE = None


def test_host_xvfb_rejects_an_unleased_live_display(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_DISPLAY": "2109",
    }
    socket_root = tmp_path / "sockets"
    socket_root.mkdir()
    socket_path = socket_root / "X2109"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen()
    monkeypatch.setattr(surface_module, "_LOCAL_X11_SOCKET_ROOT", socket_root)
    monkeypatch.setattr(surface_module.shutil, "which", lambda _name: "/usr/bin/Xvfb")

    try:
        assert surface_module._start_host_xvfb(2109, environment=environment) is None
    finally:
        listener.close()


def test_host_xvfb_is_reaped_before_its_display_lease_is_released() -> None:
    events: list[str] = []

    class FakeProcess:
        pid = 4210

        def poll(self):
            return None

        def terminate(self) -> None:
            events.append("terminate")

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == 5
            events.append("wait")
            return 0

    lease = SimpleNamespace(close=lambda: events.append("lease"))
    handle = SurfaceHandle(
        SurfaceMode.HOST_XVFB,
        DisplayClass.VIRTUAL_LOCAL,
        ":2109",
        pid=4210,
        display_lease=lease,
        host_process=FakeProcess(),
    )

    handle.close()

    assert events == ["terminate", "wait", "lease"]


def test_local_display_requires_a_live_x11_socket(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_root = tmp_path / "x11"
    socket_root.mkdir()
    socket_path = socket_root / "X2109"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen()
    monkeypatch.setattr(surface_module, "_LOCAL_X11_SOCKET_ROOT", socket_root)

    assert surface_module.display_is_usable(":2109") is True

    listener.close()
    assert socket_path.exists()
    assert surface_module.display_is_usable(":2109") is False

    def unavailable_socket(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise OSError("fixture socket exhaustion")

    monkeypatch.setattr(surface_module.socket, "socket", unavailable_socket)
    assert surface_module.display_is_usable(":2109") is False


def test_root_owned_sticky_socket_directory_is_accepted(monkeypatch, tmp_path) -> None:
    socket_root = tmp_path / "x11"
    socket_root.mkdir()
    socket_root.chmod(0o1777)

    def denied_chmod(path, mode) -> None:  # noqa: ANN001
        raise PermissionError("fixture owner mismatch")

    real_fstat = surface_module.os.fstat
    monkeypatch.setattr(surface_module.os, "fchmod", denied_chmod)
    monkeypatch.setattr(
        surface_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_uid=0,
            st_mode=real_fstat(descriptor).st_mode,
        ),
    )

    surface_module._prepare_socket_root(socket_root)


def test_non_sticky_unowned_socket_directory_fails_closed(
    monkeypatch, tmp_path
) -> None:
    socket_root = tmp_path / "x11"
    socket_root.mkdir()
    socket_root.chmod(0o755)

    def denied_chmod(path, mode) -> None:  # noqa: ANN001
        raise PermissionError("fixture owner mismatch")

    monkeypatch.setattr(surface_module.os, "fchmod", denied_chmod)

    with pytest.raises(BrowserRuntimeError) as caught:
        surface_module._prepare_socket_root(socket_root)

    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE


def test_sticky_unowned_socket_directory_fails_closed(monkeypatch, tmp_path) -> None:
    socket_root = tmp_path / "x11"
    socket_root.mkdir()
    socket_root.chmod(0o1777)

    def denied_chmod(path, mode) -> None:  # noqa: ANN001
        raise PermissionError("fixture owner mismatch")

    monkeypatch.setattr(surface_module.os, "fchmod", denied_chmod)

    with pytest.raises(BrowserRuntimeError) as caught:
        surface_module._prepare_socket_root(socket_root)

    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE


def test_socket_directory_symlink_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o1777)
    socket_root = tmp_path / "x11"
    socket_root.symlink_to(target, target_is_directory=True)

    with pytest.raises(BrowserRuntimeError) as caught:
        surface_module._prepare_socket_root(socket_root)

    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
    assert stat.S_IMODE(target.stat().st_mode) == 0o1777


def test_docker_display_lease_prevents_concurrent_reuse(tmp_path: Path) -> None:
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_SOCKET_DIR": str(tmp_path / "sockets"),
        "NEWSCLIP_XVFB_DISPLAY": "2109",
    }
    first = surface_module._acquire_docker_display(environment)

    with pytest.raises(BrowserRuntimeError) as caught:
        surface_module._acquire_docker_display(environment)

    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
    first.close()
    replacement = surface_module._acquire_docker_display(environment)
    assert replacement.number == 2109
    replacement.close()


def test_default_docker_display_avoids_legacy_shared_number(tmp_path: Path) -> None:
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_SOCKET_DIR": str(tmp_path / "sockets"),
    }

    lease = surface_module._acquire_docker_display(environment)

    assert 1000 <= lease.number <= 9999
    lease.close()


def test_docker_display_lease_skips_live_socket_but_reclaims_stale_socket(
    tmp_path: Path,
) -> None:
    socket_root = tmp_path / "sockets"
    socket_root.mkdir()
    socket_path = socket_root / "X2109"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen()
    environment = {
        "NEWSCLIP_XVFB_LEASE_DIR": str(tmp_path / "leases"),
        "NEWSCLIP_XVFB_SOCKET_DIR": str(socket_root),
        "NEWSCLIP_XVFB_DISPLAY": "2109",
    }

    with pytest.raises(BrowserRuntimeError) as caught:
        surface_module._acquire_docker_display(environment)
    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE

    listener.close()
    assert socket_path.exists()
    lease = surface_module._acquire_docker_display(environment)
    assert lease.number == 2109
    lease.close()


def test_docker_xvfb_waits_until_the_socket_accepts_clients(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_root = tmp_path / "sockets"
    monkeypatch.setenv("NEWSCLIP_XVFB_SOCKET_DIR", str(socket_root))
    monkeypatch.setattr(surface_module, "docker_cli_usable", lambda: True)
    readiness = iter((False, True))
    probes: list[tuple[Path, int]] = []
    commands: list[tuple[str, float | None]] = []

    def probe(root: Path, number: int) -> bool:
        probes.append((root, number))
        return next(readiness)

    def run(command, **kwargs):  # noqa: ANN001, ANN202
        commands.append((command[1], kwargs.get("timeout")))
        stdout = "fixture-container\n" if command[1] == "run" else ""
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(surface_module, "_unix_display_is_usable", probe)
    monkeypatch.setattr(surface_module.subprocess, "run", run)
    monkeypatch.setattr(surface_module.time, "sleep", lambda _seconds: None)

    handle = surface_module._start_docker_xvfb_socket(2109)

    assert handle is not None
    assert handle.container_id == "fixture-container"
    assert probes == [(socket_root, 2109), (socket_root, 2109)]
    assert commands == [("rm", 15), ("run", 300)]


@pytest.mark.parametrize("timed_out_command", ("rm", "run"))
def test_docker_xvfb_timeout_fails_surface_acquisition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    timed_out_command: str,
) -> None:
    monkeypatch.setenv("NEWSCLIP_XVFB_SOCKET_DIR", str(tmp_path / "sockets"))
    monkeypatch.setattr(surface_module, "docker_cli_usable", lambda: True)
    commands: list[tuple[str, float | None]] = []

    def run(command, **kwargs):  # noqa: ANN001, ANN202
        commands.append((command[1], kwargs.get("timeout")))
        if command[1] == timed_out_command:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(surface_module.subprocess, "run", run)

    assert surface_module._start_docker_xvfb_socket(2109) is None
    assert commands == (
        [("rm", 15)] if timed_out_command == "rm" else [("rm", 15), ("run", 300)]
    )


def test_virtual_display_fallback_reports_docker_run_timeout_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("NEWSCLIP_XVFB_SOCKET_DIR", str(tmp_path / "sockets"))
    monkeypatch.setattr(
        surface_module,
        "ensure_virtual_display",
        lambda: (_ for _ in ()).throw(
            BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)
        ),
    )
    monkeypatch.setattr(surface_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(surface_module, "docker_cli_usable", lambda: True)
    events: list[str] = []
    lease = SimpleNamespace(number=2109, close=lambda: events.append("lease"))
    monkeypatch.setattr(surface_module, "_acquire_docker_display", lambda: lease)

    def run(command, **kwargs):  # noqa: ANN001, ANN202
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(surface_module.subprocess, "run", run)

    with pytest.raises(BrowserRuntimeError) as caught:
        maybe_reexec_for_virtual_display(["newsclip", "login"], required=True)

    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
    assert events == ["lease"]


def test_docker_xvfb_cleanup_timeout_still_releases_display_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    lease = SimpleNamespace(close=lambda: events.append("lease"))
    handle = SurfaceHandle(
        SurfaceMode.DOCKER_XVFB_BWRAP,
        DisplayClass.VIRTUAL_LOCAL,
        ":2109",
        container_id="fixture-container",
        display_lease=lease,
    )

    def run(command, **kwargs):  # noqa: ANN001, ANN202
        assert command == ["docker", "rm", "-f", "fixture-container"]
        assert kwargs["timeout"] == 15
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(surface_module.subprocess, "run", run)

    handle.close()

    assert handle.container_id is None
    assert handle.display_lease is None
    assert events == ["lease"]


def test_docker_xvfb_readiness_cleanup_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("NEWSCLIP_XVFB_SOCKET_DIR", str(tmp_path / "sockets"))
    monkeypatch.setattr(surface_module, "docker_cli_usable", lambda: True)
    monkeypatch.setattr(surface_module, "_unix_display_is_usable", lambda *_args: False)
    monotonic = iter((0.0, 9.0))
    monkeypatch.setattr(surface_module.time, "monotonic", lambda: next(monotonic))
    commands: list[tuple[str, float | None]] = []

    def run(command, **kwargs):  # noqa: ANN001, ANN202
        commands.append((command[1], kwargs.get("timeout")))
        if len(commands) == 3:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        stdout = "fixture-container\n" if command[1] == "run" else ""
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(surface_module.subprocess, "run", run)

    assert surface_module._start_docker_xvfb_socket(2109) is None
    assert commands == [("rm", 15), ("run", 300), ("rm", 15)]


def test_system_display_is_rejected_when_denial_is_explicit(monkeypatch) -> None:
    surface_module._ACTIVE = None
    monkeypatch.setattr(surface_module, "_start_host_xvfb", lambda *a, **k: None)
    environment = {
        "DISPLAY": ":0",
        "NEWSCLIP_DENY_SYSTEM_DISPLAY": "1",
    }

    with pytest.raises(BrowserRuntimeError) as caught:
        ensure_virtual_display(environment=environment)

    assert caught.value.category is InfrastructureCategory.SYSTEM_DISPLAY_REJECTED
    assert environment["DISPLAY"] == ":0"


def test_docker_bwrap_is_last_virtual_surface_not_pure_headless(monkeypatch) -> None:
    surface_module._ACTIVE = None
    monkeypatch.setattr(
        surface_module,
        "ensure_virtual_display",
        lambda: (_ for _ in ()).throw(
            BrowserRuntimeError(InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE)
        ),
    )
    monkeypatch.setattr(surface_module, "docker_cli_usable", lambda: True)
    monkeypatch.setattr(surface_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    lease = SimpleNamespace(number=109, close=lambda: None)
    monkeypatch.setattr(surface_module, "_acquire_docker_display", lambda: lease)
    handle = SurfaceHandle(
        SurfaceMode.DOCKER_XVFB_BWRAP,
        DisplayClass.VIRTUAL_LOCAL,
        ":109",
        container_id=None,
        socket_dir=Path("/tmp/isolated-x11"),
    )
    monkeypatch.setattr(surface_module, "_start_docker_xvfb_socket", lambda _n: handle)
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(list(command))
        return SimpleNamespace(returncode=17)

    monkeypatch.setattr(surface_module.subprocess, "run", run)

    assert maybe_reexec_for_virtual_display(["newsclip", "login"], required=True) == 17
    assert calls[0][0] == "/usr/bin/bwrap"
    assert "--bind" in calls[0]
    assert "pure_headless" not in " ".join(calls[0])


class FakePage:
    url = "about:blank"

    def __init__(self, *, screenshot_error: bool = False) -> None:
        self.screenshot_error = screenshot_error
        self.screenshot_calls: list[dict[str, object]] = []

    def evaluate(self, script: str):
        raise ValueError("provider failure")

    def wait_for_timeout(self, milliseconds: int) -> None: ...

    def screenshot(self, **kwargs):  # noqa: ANN003, ANN202
        self.screenshot_calls.append(kwargs)
        if self.screenshot_error:
            raise RuntimeError("fixture screenshot failure")
        return b"\x89PNG\r\n\x1a\nfixture"


class FakeContext:
    def __init__(
        self,
        *,
        close_error: bool = False,
        page: FakePage | None = None,
    ) -> None:
        self.pages = [page or FakePage()]
        self.close_error = close_error
        self.closed = 0

    def close(self) -> None:
        self.closed += 1
        if self.close_error:
            raise RuntimeError("PRIVATE_DRIVER_CLOSE_SENTINEL")


def test_optional_browser_version_observation_never_breaks_startup() -> None:
    class ExplodingVersion:
        @property
        def browser(self):
            raise RuntimeError("version unavailable")

    assert _browser_major(ExplodingVersion()) is None


def test_runtime_closes_every_terminal_path_and_preserves_primary_failure(
    tmp_path: Path,
) -> None:
    context = FakeContext(close_error=True)
    runtime = PatchrightRuntime(context_factory=lambda **_kwargs: context)

    with (
        pytest.raises(ValueError, match="provider failure"),
        runtime.open(tmp_path / "profile", require_virtual_display=False),
    ):
        raise ValueError("provider failure")
    assert context.closed == 1

    clean_failure = FakeContext(close_error=True)
    runtime = PatchrightRuntime(context_factory=lambda **_kwargs: clean_failure)
    with (
        pytest.raises(BrowserRuntimeError) as caught,
        runtime.open(tmp_path / "profile-2", require_virtual_display=False),
    ):
        pass
    assert caught.value.category is InfrastructureCategory.BROWSER_CLEANUP_FAILED


def test_keep_alive_runtime_discards_failed_context_before_relaunch(
    tmp_path: Path,
) -> None:
    contexts: list[FakeContext] = []

    def factory(**_kwargs) -> FakeContext:
        context = FakeContext()
        contexts.append(context)
        return context

    runtime = PatchrightRuntime(context_factory=factory)
    profile = tmp_path / "profile"

    with (
        pytest.raises(ValueError, match="operation failed"),
        runtime.open(
            profile,
            require_virtual_display=False,
            keep_alive=True,
        ),
    ):
        raise ValueError("operation failed")

    assert contexts[0].closed == 1
    assert runtime._kept == {}
    with runtime.open(
        profile,
        require_virtual_display=False,
        keep_alive=True,
    ):
        pass
    assert len(contexts) == 2
    assert contexts[1].closed == 0
    with (
        pytest.raises(ValueError, match="reused operation failed"),
        runtime.open(
            profile,
            require_virtual_display=False,
            keep_alive=True,
        ),
    ):
        raise ValueError("reused operation failed")
    assert contexts[1].closed == 1
    assert runtime._kept == {}


def test_held_profile_lease_release_is_idempotent(tmp_path: Path) -> None:
    manager = LeaseManager(tmp_path / "locks")
    profile = tmp_path / "profile"
    lease = manager.hold_profile(profile)

    lease.release()
    lease.release()

    with manager.profile(profile, timeout_seconds=0):
        pass

    with (
        manager.profile(profile, timeout_seconds=0),
        pytest.raises(LockOrderError, match="lease order"),
    ):
        manager.hold_profile(profile, timeout_seconds=0)


def test_runtime_trace_failure_does_not_prevent_browser_startup(
    tmp_path: Path,
) -> None:
    launches = 0
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-write-failure")
    durable_write = trace._write
    writes = 0

    def fail_first_write(event) -> None:  # noqa: ANN001
        nonlocal writes
        writes += 1
        if writes == 1:
            raise OSError("fixture trace failure")
        durable_write(event)

    trace._write = fail_first_write  # type: ignore[method-assign]

    def context_factory(**kwargs):  # noqa: ANN003, ANN202
        nonlocal launches
        launches += 1
        return FakeContext()

    runtime = PatchrightRuntime(
        context_factory=context_factory,
        trace=trace,
    )

    with runtime.open(tmp_path / "profile", require_virtual_display=False):
        pass

    assert launches == 1
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "diagnostic_health",
        "browser_closed",
    ]
    assert rows[0]["facts"]["event_write_failures"] == 1


def test_runtime_trace_records_bounded_last_operation_on_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-failure")
    context = FakeContext()
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: context,
        trace=trace,
    )

    with (
        pytest.raises(ValueError, match="provider failure"),
        runtime.open(tmp_path / "profile", require_virtual_display=False) as browser,
    ):
        browser.evaluate("fixture")

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "diagnostic_artifact",
        "browser_failed",
        "browser_closed",
    ]
    assert rows[2]["facts"] == {
        "browser_mode": "headed_desktop",
        "category": "unclassified",
        "operation": "evaluate",
        "phase": "operation",
        "profile_generation": "retained",
    }
    assert context.closed == 1


def test_runtime_trace_records_only_bounded_hcaptcha_round_facts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-challenge")
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: FakeContext(),
        trace=trace,
    )

    with (
        runtime.open(
            tmp_path / "profile",
            require_virtual_display=False,
        ) as browser,
        browser.attempt("ft", AttemptPurpose.LOGIN),
    ):
        browser.record_hcaptcha_round(
            round_index=2,
            family="motion",
            visual_plan=VisualPlan(
                kind="point",
                points=({"x": 0.25, "y": 0.75},),
            ),
            action_dispatched=True,
            submit_control_clicked=False,
            accepted=False,
            acceptance_source="none",
            frame_open=True,
            vendor_accepted=False,
            generation_changed=True,
            terminal_reason="round_budget_exhausted",
        )
        browser.retain_failed_hcaptcha_round_images(
            round_index=2,
            before=b"before png",
            after=b"after png",
        )
        browser.record_hcaptcha_attempt_finished(
            rounds_attempted=2,
            surface_misses=3,
            accepted=False,
            acceptance_source="none",
            last_vendor_outcome="rejected",
            terminal_reason="surface_missing",
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "attempt_started",
        "hcaptcha_round",
        "diagnostic_artifact",
        "diagnostic_artifact",
        "hcaptcha_attempt_finished",
        "attempt_finished",
        "browser_closed",
    ]
    attempt_id = rows[1]["facts"]["attempt_id"]
    assert rows[2]["facts"] == {
        "accepted": False,
        "acceptance_source": "none",
        "action_dispatched": True,
        "attempt_id": attempt_id,
        "family": "motion",
        "frame_open": True,
        "generation_changed": True,
        "plan": "point",
        "provider": "ft",
        "round": 2,
        "submit_control_clicked": False,
        "terminal_reason": "round_budget_exhausted",
        "vendor_outcome": "rejected",
        "vendor_accepted": False,
        "visual_plan": {
            "grid": None,
            "indices": [],
            "kind": "point",
            "paths": [],
            "points": [{"x": 0.25, "y": 0.75}],
        },
    }
    assert rows[5]["facts"] == {
        "acceptance_source": "none",
        "accepted": False,
        "attempt_id": attempt_id,
        "last_vendor_outcome": "rejected",
        "provider": "ft",
        "rounds_attempted": 2,
        "surface_miss_bucket": "three_or_more",
        "terminal_reason": "surface_missing",
    }
    assert path.with_suffix(".hcaptcha-2-before.png").read_bytes() == b"before png"
    assert path.with_suffix(".hcaptcha-2-after.png").read_bytes() == b"after png"


def test_hcaptcha_round_rejects_inconsistent_enriched_facts() -> None:
    with pytest.raises(ValidationError, match="visual plan kind"):
        HCaptchaRoundEvent(
            round=1,
            family="semantic_grid",
            plan="grid",
            visual_plan=VisualPlan(
                kind="point",
                points=({"x": 0.5, "y": 0.5},),
            ),
            accepted=False,
            frame_open=True,
            vendor_accepted=None,
        )


def test_runtime_trace_records_only_bounded_credential_callback_facts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-callback")
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: FakeContext(),
        trace=trace,
    )

    with runtime.open(
        tmp_path / "profile",
        require_virtual_display=False,
    ) as browser:
        browser.record_credential_callback(
            sequence=1,
            credential_present=True,
            challenge_token_present=False,
            status_class="client_error",
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "credential_callback",
        "browser_closed",
    ]
    assert rows[1]["facts"] == {
        "challenge_token_present": False,
        "credential_present": True,
        "sequence": 1,
        "status_class": "client_error",
    }


def test_runtime_trace_correlates_identity_handoff_facts(tmp_path: Path) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-identity")
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: FakeContext(),
        trace=trace,
    )

    with (
        runtime.open(
            tmp_path / "profile",
            require_virtual_display=False,
        ) as browser,
        browser.attempt("bloomberg", AttemptPurpose.LOGIN),
    ):
        browser.record_identity_handoff(
            checkpoint="callback_wait",
            credential_action="google_password_submit",
            identity_callback_complete=False,
            identity_page_closed=True,
            identity_exit_reason="identity_context_closed",
            parent_state="publisher_auth",
            callback_confirmed=False,
            publisher_auth_cookie_present=False,
            challenge_cookie_present=True,
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "attempt_started",
        "identity_handoff",
        "attempt_finished",
        "browser_closed",
    ]
    assert rows[2]["facts"] == {
        "attempt_id": rows[1]["facts"]["attempt_id"],
        "callback_clearance_cookie_present": None,
        "callback_confirmed": False,
        "callback_probe_status": None,
        "challenge_cookie_present": True,
        "checkpoint": "callback_wait",
        "credential_action": "google_password_submit",
        "identity_callback_complete": False,
        "identity_page_closed": True,
        "identity_page_state": None,
        "identity_exit_reason": "identity_context_closed",
        "parent_state": "publisher_auth",
        "paid_auth_cookie_present": None,
        "paid_probe_access_state": None,
        "paid_probe_outcome": None,
        "paid_probe_stabilized": None,
        "provider": "bloomberg",
        "publisher_auth_cookie_present": False,
        "entitlement_confirmed": None,
        "verification_full": None,
    }


def test_runtime_trace_records_the_paid_probe_verdict_it_observed(
    tmp_path: Path,
) -> None:
    """The failure category collapses non-teaser verdicts; the fact must survive."""

    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-paid-probe")
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: FakeContext(),
        trace=trace,
    )

    with (
        runtime.open(
            tmp_path / "profile",
            require_virtual_display=False,
        ) as browser,
        browser.attempt("bloomberg", AttemptPurpose.LOGIN),
    ):
        browser.record_identity_handoff(
            checkpoint="paid_probe",
            credential_action=None,
            identity_callback_complete=None,
            identity_page_closed=None,
            parent_state="publisher_content",
            callback_confirmed=False,
            publisher_auth_cookie_present=None,
            challenge_cookie_present=True,
            paid_probe_outcome="interrupted",
            entitlement_confirmed=False,
            paid_auth_cookie_present=False,
            paid_probe_access_state="teaser",
            paid_probe_stabilized=True,
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    facts = rows[2]["facts"]
    assert facts["checkpoint"] == "paid_probe"
    assert facts["paid_probe_access_state"] == "teaser"
    assert facts["paid_probe_stabilized"] is True
    assert facts["challenge_cookie_present"] is True
    assert facts["identity_exit_reason"] is None


def test_identity_handoff_rejects_paid_probe_verdicts_on_identity_checkpoints() -> None:
    with pytest.raises(ValidationError, match="paid probe facts"):
        IdentityHandoffEvent(
            attempt_id="attempt-" + "8" * 32,
            provider="bloomberg",
            checkpoint="callback_retry",
            credential_action="google_totp_submit",
            identity_callback_complete=False,
            identity_page_closed=True,
            parent_state="publisher_auth",
            callback_confirmed=False,
            publisher_auth_cookie_present=False,
            paid_probe_access_state="teaser",
        )


def test_identity_handoff_rejects_an_exit_reason_on_the_paid_probe() -> None:
    with pytest.raises(ValidationError, match="identity result facts"):
        IdentityHandoffEvent(
            attempt_id="attempt-" + "9" * 32,
            provider="bloomberg",
            checkpoint="paid_probe",
            parent_state="publisher_content",
            paid_probe_outcome="interrupted",
            identity_exit_reason="callback_complete",
        )


def test_identity_handoff_rejects_result_facts_on_error_checkpoint() -> None:
    with pytest.raises(ValidationError, match="error handoff"):
        IdentityHandoffEvent(
            attempt_id="attempt-" + "7" * 32,
            provider="bloomberg",
            checkpoint="identity_error",
            credential_action="google_password_submit",
            parent_state="publisher_auth",
            publisher_auth_cookie_present=False,
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        IdentityHandoffEvent(
            attempt_id="attempt-" + "7" * 32,
            provider="bloomberg",
            checkpoint="identity_error",
            identity_page_state="open",
            parent_state="publisher_auth",
            publisher_auth_cookie_present=False,
            exception_message="private credential value",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        PerimeterXHoldEvent(
            attempt_id="attempt-" + "7" * 32,
            provider="bloomberg",
            hold_index=1,
            pointer_backend="cdp",
            duration_bucket="under_1s",
            release_reason="interrupted",
            generation_relation="unavailable",
            final_surface_state="unknown",
            coordinates="10,20",  # type: ignore[call-arg]
        )


def test_runtime_trace_records_paid_probe_and_perimeterx_hold(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-paid-hold")
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: FakeContext(),
        trace=trace,
    )

    with (
        runtime.open(
            tmp_path / "profile",
            require_virtual_display=False,
        ) as browser,
        browser.attempt("bloomberg", AttemptPurpose.LOGIN),
    ):
        browser.record_identity_handoff(
            checkpoint="paid_probe",
            credential_action=None,
            identity_callback_complete=None,
            identity_page_closed=None,
            parent_state="publisher_auth",
            callback_confirmed=True,
            publisher_auth_cookie_present=None,
            paid_probe_outcome="complete",
            entitlement_confirmed=True,
            paid_auth_cookie_present=True,
            verification_full=False,
        )
        browser.record_perimeterx_hold(
            hold_index=1,
            pointer_backend="x11",
            duration_seconds=2.5,
            release_reason="completed",
            post_settle_acceptance_source="none",
            retry_invited=False,
            control_still_present=True,
            generation_relation="same",
            final_surface_state="completed_control_present",
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows[2:4]] == [
        "identity_handoff",
        "perimeterx_hold",
    ]
    assert rows[2]["facts"]["paid_probe_outcome"] == "complete"
    assert rows[2]["facts"]["verification_full"] is False
    assert rows[3]["facts"] == PerimeterXHoldEvent(
        attempt_id=rows[1]["facts"]["attempt_id"],
        provider="bloomberg",
        hold_index=1,
        pointer_backend="x11",
        duration_bucket="1s_10s",
        release_reason="completed",
        post_settle_acceptance_source="none",
        retry_invited=False,
        control_still_present=True,
        generation_relation="same",
        final_surface_state="completed_control_present",
    ).model_dump(mode="json", exclude={"event"})


def test_runtime_failure_captures_private_unredacted_screenshot(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-screenshot")
    context = FakeContext()
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: context,
        trace=trace,
    )

    with (
        pytest.raises(ValueError, match="provider failure"),
        runtime.open(tmp_path / "profile", require_virtual_display=False),
    ):
        raise ValueError("provider failure")

    screenshot_path = path.with_suffix(".failure.png")
    assert screenshot_path.read_bytes() == b"\x89PNG\r\n\x1a\nfixture"
    assert stat.S_IMODE(screenshot_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(screenshot_path.stat().st_mode) == 0o600
    assert context.pages[0].screenshot_calls == [{"full_page": False, "timeout": 5_000}]


def test_runtime_context_captures_named_diagnostic_screenshot(tmp_path: Path) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-diagnostic")
    context = FakeContext()
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: context,
        trace=trace,
    )

    with runtime.open(
        tmp_path / "profile",
        require_virtual_display=False,
    ) as browser:
        assert browser.capture_diagnostic_screenshot("px-1-before") is True

    screenshot_path = path.with_suffix(".px-1-before.png")
    assert screenshot_path.read_bytes() == b"\x89PNG\r\n\x1a\nfixture"
    assert stat.S_IMODE(screenshot_path.stat().st_mode) == 0o600
    assert context.pages[0].screenshot_calls == [{"full_page": False, "timeout": 2_000}]


def test_runtime_context_suffixes_repeated_diagnostic_checkpoints(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-repeated-diagnostic")
    context = FakeContext()
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: context,
        trace=trace,
    )

    with runtime.open(
        tmp_path / "profile",
        require_virtual_display=False,
    ) as browser:
        assert browser.capture_diagnostic_screenshot("px-1-before") is True
        assert browser.capture_diagnostic_screenshot("px-1-before") is True

    assert path.with_suffix(".px-1-before.png").exists()
    assert path.with_suffix(".px-1-before-2.png").exists()


def test_runtime_unique_screenshot_suffix_preserves_label_bound(
    tmp_path: Path,
) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-long-diagnostic")
    label = "a" * 64

    first = trace.write_unique_screenshot(label, b"first")
    second = trace.write_unique_screenshot(label, b"second")

    assert first.name == f"runtime.{label}.png"
    assert second.name == f"runtime.{'a' * 62}-2.png"
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"


def test_runtime_screenshot_failure_preserves_primary_error(tmp_path: Path) -> None:
    path = tmp_path / "traces" / "runtime.jsonl"
    trace = RuntimeTrace(path, run_id="runtime-screenshot-failure")
    context = FakeContext(page=FakePage(screenshot_error=True))
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: context,
        trace=trace,
    )

    with (
        pytest.raises(ValueError, match="provider failure"),
        runtime.open(tmp_path / "profile", require_virtual_display=False),
    ):
        raise ValueError("provider failure")

    assert not path.with_suffix(".failure.png").exists()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event"] for row in rows] == [
        "browser_started",
        "diagnostic_health",
        "diagnostic_artifact",
        "browser_failed",
        "browser_closed",
    ]
    assert rows[1]["facts"]["screenshot_capture_failures"] == 1


def test_observational_evaluate_retries_navigation_context_race() -> None:
    class RacingPage:
        def __init__(self) -> None:
            self.calls = 0
            self.waits: list[int] = []

        def evaluate(self, expression: str):
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("Execution context was destroyed during navigation")
            return {"state": "ready"}

        def wait_for_timeout(self, milliseconds: int) -> None:
            self.waits.append(milliseconds)

    page = RacingPage()
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.evaluate("fixture") == {"state": "ready"}
    assert page.calls == 3
    assert page.waits == [250, 500]
    assert browser.last_operation is BrowserOperation.EVALUATE


def test_observational_evaluate_tolerates_bounded_post_submit_navigation() -> None:
    class NavigatingPage:
        def __init__(self) -> None:
            self.calls = 0
            self.waits: list[int] = []

        def evaluate(self, expression: str):
            self.calls += 1
            if self.calls < 5:
                raise RuntimeError("Execution context was destroyed during navigation")
            return {"state": "callback_ready"}

        def wait_for_timeout(self, milliseconds: int) -> None:
            self.waits.append(milliseconds)

    page = NavigatingPage()
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.evaluate("fixture") == {"state": "callback_ready"}
    assert page.calls == 5
    assert page.waits == [250, 500, 1_000, 1_250]


def test_visibility_wait_retries_navigation_context_race() -> None:
    class Locator:
        def __init__(self) -> None:
            self.calls = 0

        def count(self) -> int:
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Execution context was destroyed during navigation")
            return True

    locator = Locator()
    waits: list[int] = []
    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: locator,
        wait_for_timeout=waits.append,
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.wait_for_visible(("button",), timeout_seconds=1) is True
    assert locator.calls == 2
    assert waits == [250]
    assert browser.last_operation is BrowserOperation.WAIT


def test_visibility_wait_retries_detached_frame_race() -> None:
    class Locator:
        def __init__(self) -> None:
            self.calls = 0

        def count(self) -> int:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Frame was detached")
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            return True

    locator = Locator()
    waits: list[int] = []
    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: locator,
        wait_for_timeout=waits.append,
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.wait_for_visible(("button",), timeout_seconds=1) is True
    assert locator.calls == 2
    assert waits == [250]
    assert browser.last_operation is BrowserOperation.WAIT


def test_visibility_wait_does_not_hide_target_closure() -> None:
    class Locator:
        def count(self) -> int:
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            raise RuntimeError("Target closed")

    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: Locator(),
        wait_for_timeout=lambda milliseconds: None,
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    with pytest.raises(RuntimeError, match="Target closed"):
        browser.wait_for_visible(("button",), timeout_seconds=1)


def test_hidden_wait_requires_the_visible_control_to_disappear() -> None:
    class Locator:
        def __init__(self) -> None:
            self.calls = 0

        def count(self) -> int:
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            self.calls += 1
            return self.calls < 3

    locator = Locator()
    waits: list[int] = []
    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: locator,
        wait_for_timeout=waits.append,
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.wait_for_hidden(("dialog",), timeout_seconds=1) is True
    assert locator.calls == 3
    assert waits == [250, 250]
    assert browser.last_operation is BrowserOperation.WAIT


def test_committed_navigation_uses_bounded_response_readiness() -> None:
    calls: list[tuple[str, str, int]] = []

    class Page:
        def goto(self, url: str, *, wait_until: str, timeout: int) -> None:
            calls.append((url, wait_until, timeout))

    browser = PatchrightMintContext(SimpleNamespace(), Page())

    browser.navigate_committed(
        "https://fixture.test/login",
        timeout_seconds=30,
    )

    assert calls == [("https://fixture.test/login", "commit", 30_000)]
    assert browser.last_operation is BrowserOperation.NAVIGATE


def test_observed_navigation_retains_main_response_facts() -> None:
    calls: list[tuple[str, str, int]] = []

    class Page:
        def goto(self, url: str, *, wait_until: str, timeout: int) -> object:
            calls.append((url, wait_until, timeout))
            return SimpleNamespace(
                status=302,
                url="https://fixture.test/final",
                headers={"content-type": "text/html; charset=utf-8"},
            )

    browser = PatchrightMintContext(SimpleNamespace(), Page())

    observed = browser.navigate_observed(
        "https://fixture.test/start",
        timeout_seconds=12.5,
    )

    assert observed == ObservedNavigation(
        status=302,
        response_url="https://fixture.test/final",
        content_type="text/html; charset=utf-8",
    )
    assert calls == [("https://fixture.test/start", "commit", 12_500)]
    assert browser.last_operation is BrowserOperation.NAVIGATE


def test_observed_navigation_rejects_missing_main_response() -> None:
    page = SimpleNamespace(goto=lambda *args, **kwargs: None)
    browser = PatchrightMintContext(SimpleNamespace(), page)

    with pytest.raises(RuntimeError, match="no response"):
        browser.navigate_observed(
            "https://fixture.test/article",
            timeout_seconds=30,
        )


def test_observed_navigation_keeps_sub_millisecond_timeout_bounded() -> None:
    timeouts: list[int] = []

    def goto(url: str, *, wait_until: str, timeout: int) -> object:
        timeouts.append(timeout)
        return SimpleNamespace(
            status=200,
            url=url,
            headers={},
        )

    browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace(goto=goto))

    browser.navigate_observed(
        "https://fixture.test/article",
        timeout_seconds=0.0001,
    )

    assert timeouts == [1]


@pytest.mark.parametrize("timeout", (0, -1, float("inf"), float("nan")))
def test_observed_navigation_requires_finite_positive_timeout(
    timeout: float,
) -> None:
    browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace())

    with pytest.raises(ValueError, match="timeout"):
        browser.navigate_observed(
            "https://fixture.test/article",
            timeout_seconds=timeout,
        )


@pytest.mark.parametrize("timeout", (0, -1, float("inf"), float("nan")))
def test_committed_navigation_requires_finite_positive_timeout(
    timeout: float,
) -> None:
    browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace())

    with pytest.raises(ValueError, match="timeout"):
        browser.navigate_committed(
            "https://fixture.test/login",
            timeout_seconds=timeout,
        )


def test_page_replacement_preserves_context_and_closes_previous_page() -> None:
    class Page:
        def __init__(self) -> None:
            self.closed = 0

        def close(self) -> None:
            self.closed += 1

    previous = Page()
    replacement = Page()
    context = SimpleNamespace(new_page=lambda: replacement)
    browser = PatchrightMintContext(context, previous)

    browser.replace_page()

    assert browser.page is replacement
    assert previous.closed == 1
    assert browser.last_operation is BrowserOperation.REPLACE_PAGE


def test_sibling_page_facade_preserves_runtime_diagnostics(tmp_path: Path) -> None:
    trace = RuntimeTrace(tmp_path / "traces" / "runtime.jsonl", run_id="sibling")
    context = SimpleNamespace()
    original = SimpleNamespace()
    popup = FakePage()
    browser = PatchrightMintContext(context, original, trace=trace)

    sibling = browser.for_page(popup)

    assert sibling.context is context
    assert sibling.page is popup
    assert sibling.capture_diagnostic_screenshot("google-failure") is True
    assert (
        tmp_path / "traces" / "runtime.google-failure.png"
    ).read_bytes() == b"\x89PNG\r\n\x1a\nfixture"


def test_optional_control_uses_mouse_geometry_without_navigation_wait() -> None:
    calls: list[tuple[object, ...]] = []

    class Locator:
        def count(self) -> int:
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            return True

        def bounding_box(self) -> dict[str, float]:
            return {"x": 10, "y": 20, "width": 40, "height": 20}

        def click(self, **kwargs) -> None:
            raise AssertionError("locator click must not own consent navigation")

    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: Locator(),
        mouse=SimpleNamespace(
            move=lambda x, y, **kwargs: calls.append(("move", x, y, kwargs)),
            click=lambda x, y: calls.append(("click", x, y)),
        ),
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.click_optional(("button",)) is True
    assert calls == [
        ("move", 30.0, 30.0, {"steps": 4}),
        ("click", 30.0, 30.0),
    ]
    assert browser.last_operation is BrowserOperation.CLICK_OPTIONAL


def test_optional_control_treats_frame_detachment_as_not_clickable() -> None:
    class DetachedLocator:
        def count(self) -> int:
            return 1

        def nth(self, index: int):
            return self

        def is_visible(self) -> bool:
            return True

        def bounding_box(self):
            raise RuntimeError("fixture frame detached")

    page = SimpleNamespace(
        frames=[],
        locator=lambda selector: DetachedLocator(),
    )
    browser = PatchrightMintContext(SimpleNamespace(), page)

    assert browser.click_optional(("button",)) is False
    assert browser.last_operation is BrowserOperation.CLICK_OPTIONAL


@pytest.mark.parametrize(
    ("mode", "present"),
    [
        (PasskeyMode.EMPTY_PRESENT, True),
        (PasskeyMode.NON_PRESENT, False),
    ],
)
def test_passkey_mode_maps_to_a_closed_virtual_authenticator_contract(
    mode: PasskeyMode, present: bool
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class Session:
        def send(self, method: str, params: dict[str, object]) -> None:
            calls.append((method, params))

    context = SimpleNamespace(new_cdp_session=lambda page: Session())
    browser = PatchrightMintContext(context, SimpleNamespace())

    assert browser.suppress_passkeys(mode) is True
    assert calls[0] == ("WebAuthn.enable", {"enableUI": False})
    options = calls[1][1]["options"]
    assert options == {
        "protocol": "ctap2",
        "transport": "internal",
        "hasResidentKey": present,
        "hasUserVerification": True,
        "automaticPresenceSimulation": present,
        "isUserVerified": present,
    }


def test_observational_evaluate_does_not_retry_nontransient_failure() -> None:
    class BrokenPage:
        def __init__(self) -> None:
            self.calls = 0

        def evaluate(self, expression: str):
            self.calls += 1
            raise SyntaxError("fixture script error")

        def wait_for_timeout(self, milliseconds: int) -> None:
            raise AssertionError("nontransient failure must not wait")

    page = BrokenPage()
    browser = PatchrightMintContext(SimpleNamespace(), page)

    with pytest.raises(SyntaxError, match="fixture script error"):
        browser.evaluate("fixture")

    assert page.calls == 1


def test_browser_failure_event_rejects_unbounded_operation() -> None:
    with pytest.raises(ValidationError):
        BrowserFailedEvent.model_validate(
            {
                "browser_mode": "headed_virtual",
                "profile_generation": "retained",
                "phase": BrowserFailurePhase.OPERATION,
                "category": BrowserFailureCategory.API_ERROR,
                "operation": "provider DOM secret",
            }
        )
    assert BrowserOperation.EVALUATE.value == "evaluate"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (
            RuntimeError("Execution context was destroyed during navigation"),
            BrowserFailureCategory.CONTEXT_REPLACED,
        ),
        (RuntimeError("Frame was detached"), BrowserFailureCategory.CONTEXT_REPLACED),
        (RuntimeError("Target closed"), BrowserFailureCategory.TARGET_CLOSED),
        (TimeoutError(), BrowserFailureCategory.TIMEOUT),
        (SyntaxError(), BrowserFailureCategory.SCRIPT_ERROR),
        (RuntimeError("opaque"), BrowserFailureCategory.UNCLASSIFIED),
    ],
)
def test_browser_failure_category_is_closed(error, expected) -> None:  # noqa: ANN001
    assert _failure_category(error) is expected


def test_runtime_startup_failure_is_typed_and_profile_is_private(
    tmp_path: Path,
) -> None:
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("PRIVATE_DRIVER_START_SENTINEL")
        )
    )
    profile = tmp_path / "profile"

    with (
        pytest.raises(BrowserRuntimeError) as caught,
        runtime.open(profile, require_virtual_display=False),
    ):
        pass

    assert caught.value.category is InfrastructureCategory.BROWSER_STARTUP_FAILED
    assert "PRIVATE_DRIVER_START_SENTINEL" not in str(caught.value)
    assert stat.S_IMODE(profile.stat().st_mode) == 0o700


def test_runtime_target_closed_during_startup_has_its_own_category(
    tmp_path: Path,
) -> None:
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("Target closed")
        )
    )

    with (
        pytest.raises(BrowserRuntimeError) as caught,
        runtime.open(
            tmp_path / "profile-target-closed",
            require_virtual_display=False,
        ),
    ):
        pass

    assert caught.value.category is InfrastructureCategory.BROWSER_STARTUP_TARGET_CLOSED


def test_runtime_refuses_foreign_profile_owner_before_launch(tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "SingletonLock").symlink_to("removed-container-1145")
    launched = []

    def launch(**_kwargs):
        launched.append(True)
        return FakeContext()

    runtime = PatchrightRuntime(context_factory=launch)
    with (
        pytest.raises(BrowserRuntimeError, match="profile_owner_unverified"),
        runtime.open(profile, require_virtual_display=False),
    ):
        pass
    assert not launched


def test_cleanup_diagnostic_names_the_failed_step_without_driver_text(
    tmp_path: Path,
) -> None:
    class CleanupFailureContext(FakeContext):
        def close(self) -> None:
            raise RuntimeError("PRIVATE_CLEANUP_DETAIL")

    trace = tmp_path / "trace.jsonl"
    runtime = PatchrightRuntime(
        context_factory=lambda **_: CleanupFailureContext(),
        trace=RuntimeTrace(trace, run_id="cleanup-failure"),
    )
    with (
        pytest.raises(BrowserRuntimeError, match="browser_cleanup_failed"),
        runtime.open(tmp_path / "profile", require_virtual_display=False),
    ):
        pass
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    closed = next(row["facts"] for row in records if row["event"] == "browser_closed")
    assert closed["cleanup_ok"] is False
    assert closed["cleanup_failures"] == ["context_close"]
    assert "PRIVATE_CLEANUP_DETAIL" not in trace.read_text()


def test_runtime_page_startup_failure_is_typed_and_context_closes(
    tmp_path: Path,
) -> None:
    class PageFailureContext(FakeContext):
        def __init__(self) -> None:
            super().__init__()
            self.pages = []

        def new_page(self):
            raise RuntimeError("PRIVATE_PAGE_START_SENTINEL")

    context = PageFailureContext()
    runtime = PatchrightRuntime(context_factory=lambda **_kwargs: context)

    with (
        pytest.raises(BrowserRuntimeError) as caught,
        runtime.open(tmp_path / "profile-page", require_virtual_display=False),
    ):
        pass

    assert caught.value.category is InfrastructureCategory.BROWSER_STARTUP_FAILED
    assert "PRIVATE_PAGE_START_SENTINEL" not in str(caught.value)
    assert context.closed == 1


def test_runtime_rejects_required_virtual_mode_before_launch(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("NEWSCLIP_VIRTUAL_DISPLAY", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    calls = 0

    def factory(**_kwargs):
        nonlocal calls
        calls += 1
        return FakeContext()

    runtime = PatchrightRuntime(context_factory=factory)
    with (
        pytest.raises(BrowserRuntimeError) as caught,
        runtime.open(tmp_path / "profile", require_virtual_display=True),
    ):
        pass
    assert caught.value.category is InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
    assert calls == 0


def test_virtual_runtime_adds_proven_xvfb_rendering_arguments(
    tmp_path: Path, monkeypatch
) -> None:
    options: dict[str, object] = {}

    def factory(**kwargs):  # noqa: ANN003
        options.update(kwargs)
        return FakeContext()

    monkeypatch.setattr(
        PatchrightRuntime,
        "_browser_mode",
        staticmethod(lambda required: BrowserMode.HEADED_VIRTUAL),
    )
    runtime = PatchrightRuntime(context_factory=factory)

    with runtime.open(
        tmp_path / "profile",
        require_virtual_display=True,
        launch_config=BrowserLaunchConfig(args=("--provider-argument",)),
    ):
        pass

    assert options["args"] == [
        "--provider-argument",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-position=0,0",
        "--window-size=1280,800",
        "--use-gl=angle",
        "--use-angle=swiftshader-webgl",
        "--enable-webgl",
        "--ignore-gpu-blocklist",
        "--disable-software-rasterizer",
    ]


def test_every_handoff_fact_the_event_carries_is_accepted_by_the_recorder() -> None:
    """The recorder must forward every fact the event models.

    `_record_identity_handoff` swallows exceptions so diagnostics can never
    change authentication behaviour, which means a keyword the recorder does
    not accept raises TypeError into that guard and disappears. Two releases
    shipped fields the event validated and the recorder silently dropped
    (0.3.17, 0.3.18); the run they were added to diagnose produced nothing.
    """

    import inspect

    from newsclip.browser_runtime.events import IdentityHandoffEvent
    from newsclip.browser_runtime.runtime import PatchrightMintContext

    accepted = set(
        inspect.signature(PatchrightMintContext.record_identity_handoff).parameters
    ) - {"self"}
    modelled = set(IdentityHandoffEvent.model_fields) - {
        "event",
        "attempt_id",
        "provider",
    }

    assert modelled <= accepted, f"recorder drops: {sorted(modelled - accepted)}"


def test_incident_snapshot_keeps_current_attempt_after_long_process_history(tmp_path):
    path = tmp_path / "runtime.jsonl"
    current = (
        b'{"event":"attempt_started","facts":{"attempt_id":"attempt-current"}}\n'
        b'{"event":"diagnostic_artifact","facts":{"attempt_id":"attempt-current"}}\n'
    )
    path.write_bytes(b"{}\n" * 400_000 + current)
    trace = RuntimeTrace(path, run_id="long-lived")
    assert trace.incident_snapshot("attempt-current") == current
    assert trace.incident_snapshot("attempt-missing") is None


def test_browser_open_reports_profile_contents_without_claiming_authentication(
    tmp_path: Path,
) -> None:
    from newsclip.live_reporting import collect_live_evidence

    trace = RuntimeTrace(
        tmp_path / "traces/wsj/browser-profile.jsonl", run_id="browser-profile"
    )
    profile = tmp_path / "profile"
    runtime = PatchrightRuntime(
        context_factory=lambda **kwargs: FakeContext(),
        trace=trace,
    )
    with (
        runtime.open(profile, require_virtual_display=False) as browser,
        browser.attempt("wsj", "retrieve"),
    ):
        pass
    (profile / "Local State").write_text("fixture browser state")
    with (
        runtime.open(profile, require_virtual_display=False) as browser,
        browser.attempt("wsj", "retrieve"),
    ):
        pass
    attempts = collect_live_evidence(tmp_path / "traces").attempts
    assert {attempt.profile_state for attempt in attempts} == {"new", "existing"}
