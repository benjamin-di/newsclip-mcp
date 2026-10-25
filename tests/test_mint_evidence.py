from __future__ import annotations

import json
from pathlib import Path

import pytest

from newsclip.browser_runtime.events import RuntimeTrace


@pytest.mark.parametrize("provider", ["ft", "economist"])
@pytest.mark.parametrize("capture_fails", [False, True])
def test_failed_attempt_captures_terminal_evidence_before_unwinding(
    tmp_path, provider, capture_fails
):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext

    def screenshot(**kwargs):
        if capture_fails:
            raise RuntimeError("private screenshot error")
        return b"private failure viewport"

    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="failed-attempt")
    browser = PatchrightMintContext(
        SimpleNamespace(), SimpleNamespace(screenshot=screenshot), trace=trace
    )
    original = RuntimeError("original acquisition failure")
    with (
        pytest.raises(RuntimeError) as caught,
        trace.acquisition(provider),
        browser.attempt(provider, "login"),
    ):
        attempt_id = browser._attempt.attempt_id
        raise original
    assert caught.value is original
    events = [record.event for record in read_runtime_file(path).records]
    artifact = next(event for event in events if event.event == "diagnostic_artifact")
    finished = next(event for event in events if event.event == "attempt_finished")
    assert events.index(artifact) < events.index(finished)
    assert artifact.attempt_id == attempt_id
    assert artifact.provider == provider
    assert artifact.terminal
    if capture_fails:
        assert artifact.omission == "capture_failed"
        assert artifact.path is None
    else:
        assert (tmp_path / artifact.path).read_bytes() == b"private failure viewport"


@pytest.mark.parametrize("authority", [False, True])
def test_probe_failure_preserves_closed_cause_without_downgrade(tmp_path, authority):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from newsclip.errors import BrowserAuthorityChangedError, ProviderTransportError
    from newsclip.models import AccessState, ArticleAssessment, SessionDisposition
    from newsclip.service import NewsclipService
    from newsclip.timing import (
        TimingOperation,
        TimingRecorder,
        TimingTransport,
        read_timing_file,
        set_timing_content_assessment,
    )

    def fail(*args):
        if authority:
            raise BrowserAuthorityChangedError()
        raise ProviderTransportError("private-driver-sentinel")

    service = SimpleNamespace(_verification_client=lambda _: nullcontext(None))
    provider = SimpleNamespace(key="wsj", login_recipe=SimpleNamespace(verify=fail))
    recorder = TimingRecorder(tmp_path / "timings")
    with recorder.operation(
        TimingOperation.SAVE, provider="wsj", transport=TimingTransport.BROWSER
    ) as operation:
        set_timing_content_assessment(
            ArticleAssessment(
                access_state=AccessState.TEASER,
                reason="paywall_teaser",
                identity_match=True,
                word_count=91,
                session_cookie_present=True,
            )
        )
        assert NewsclipService._classify_session(
            service, provider, object()
        ).disposition is (SessionDisposition.INCONCLUSIVE)
    finished = read_timing_file(operation.path).finished
    assert finished.content_assessment.session_probe.failure_reason == (
        "authority_changed" if authority else "transport_error"
    )
    assert "private-driver-sentinel" not in operation.path.read_text()


def test_read_snapshot_is_linked_to_its_timing_operation(tmp_path):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext
    from newsclip.timing import TimingOperation, TimingRecorder, TimingTransport

    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="read-snapshot")
    browser = PatchrightMintContext(
        SimpleNamespace(),
        SimpleNamespace(screenshot=lambda **kwargs: b"private-viewport"),
        trace=trace,
    )
    with (
        TimingRecorder(tmp_path / "timings").operation(
            TimingOperation.SAVE, provider="wsj", transport=TimingTransport.BROWSER
        ) as operation,
        browser.attempt("wsj", "retrieve"),
    ):
        assert browser.capture_diagnostic_screenshot("content-snapshot")
    artifact = next(
        record.event
        for record in read_runtime_file(path).records
        if record.event.event == "diagnostic_artifact"
    )
    assert artifact.operation_id == operation.operation_id
    assert (tmp_path / artifact.path).is_file()


def test_form_is_captured_before_first_fill_and_callback_only_after_leaving_auth(
    tmp_path,
):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext

    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="transition-evidence")
    values, snapshots = [], []

    def screenshot(**kwargs):
        snapshots.append(tuple(values))
        return b"private-viewport"

    browser = PatchrightMintContext(
        SimpleNamespace(), SimpleNamespace(screenshot=screenshot), trace=trace
    )
    locator = SimpleNamespace(click=lambda: None, fill=values.append)
    browser._with_visible_locator = lambda selectors, action, **kwargs: action(locator)
    with (
        pytest.raises(RuntimeError),
        trace.acquisition("ft"),
        browser.attempt("ft", "login"),
    ):
        browser.fill(("fixture",), "username-sentinel")
        browser.fill(("fixture",), "password-sentinel")
        observe = dict(
            phase="callback",
            state_code="transition",
            observation_id=None,
            evidence_families=("path",),
            selector_error=False,
        )
        browser.record_auth_observation(**observe, route_class="publisher_auth")
        values.clear()
        browser.record_auth_observation(**observe, route_class="publisher_content")
        browser.record_auth_observation(**observe, route_class="publisher_content")
        raise RuntimeError("fixture callback failed after transition")
    assert snapshots == [(), (), ()]
    artifacts = [
        record.event
        for record in read_runtime_file(path).records
        if record.event.event == "diagnostic_artifact"
    ]
    assert [event.label for event in artifacts] == [
        "auth-form-ready",
        "auth-callback",
        "attempt-failure",
    ]
    assert all((tmp_path / event.path).is_file() for event in artifacts)
    assert "sentinel" not in path.read_text()


@pytest.mark.parametrize("closed", [True, False])
def test_unavailable_page_and_failed_capture_have_distinct_omissions(tmp_path, closed):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext

    path = tmp_path / "trace.jsonl"

    def screenshot(**kwargs):
        assert not closed
        raise RuntimeError("private driver failure")

    trace = RuntimeTrace(path, run_id="capture-evidence")
    browser = PatchrightMintContext(
        SimpleNamespace(),
        SimpleNamespace(is_closed=lambda: closed, screenshot=screenshot),
        trace=trace,
    )
    assert not browser.capture_diagnostic_screenshot("failure")
    event = read_runtime_file(path).records[-1].event
    assert event.omission == ("page_unavailable" if closed else "capture_failed")
    assert "private driver" not in path.read_text()


def test_oversized_artifacts_report_size_limit_without_writing_partial_data(tmp_path):
    from types import SimpleNamespace

    from newsclip.browser_runtime.events import read_runtime_file
    from newsclip.browser_runtime.runtime import PatchrightMintContext

    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="oversized-evidence")
    assert trace.try_write_unique_screenshot("input", b"x" * (57 * 1024 * 1024)) is None
    browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace(), trace=trace)
    with browser.attempt("ft", "login"):
        assert (
            trace.write_challenge_instruction(
                "input",
                "x" * 16385,
                provider="ft",
                attempt_id=browser._attempt.attempt_id,
            )
            is None
        )
    omissions = [
        record.event.omission
        for record in read_runtime_file(path).records
        if record.event.event == "diagnostic_artifact"
    ]
    assert omissions == ["artifact_too_large", "artifact_too_large"]
    assert not list(tmp_path.glob("*.png")) and not list(tmp_path.glob("*.txt"))


def test_artifact_budget_omission_is_distinct_from_storage_failure(
    tmp_path, monkeypatch
):
    path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(path, run_id="omission-evidence")
    for _ in range(30):
        trace.try_write_unique_screenshot("input", b"image", provider="ft")
    assert trace.try_write_unique_screenshot("input", b"image", provider="ft") is None

    def fail(*args):
        raise OSError("private fixture path must not reach redacted events")

    monkeypatch.setattr(trace, "write_unique_screenshot", fail)
    assert (
        trace.try_write_unique_screenshot(
            "failure", b"image", provider="ft", terminal=True
        )
        is None
    )
    trace.flush_health()
    facts = [
        json.loads(line)["facts"]
        for line in path.read_text().splitlines()
        if json.loads(line)["event"] == "diagnostic_artifact"
    ]
    assert [fact["omission"] for fact in facts if fact["omission"]] == [
        "budget_exhausted",
        "write_failed",
    ]
    assert "private fixture" not in path.read_text()


def test_terminal_images_have_reserved_capacity(tmp_path: Path) -> None:
    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    with pytest.raises(RuntimeError), trace.acquisition("ft"):
        images = [
            trace.try_write_unique_screenshot("input", b"image", provider="ft")
            for _ in range(32)
        ]
        assert sum(path is not None for path in images) == 30
        terminal = trace.try_write_unique_screenshot(
            "failure", b"terminal", provider="ft", terminal=True
        )
        assert terminal is not None
        raise RuntimeError("preserve")
    assert terminal.read_bytes() == b"terminal"


def test_success_deletes_only_its_own_evidence_after_publication(
    tmp_path: Path,
) -> None:
    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    with pytest.raises(RuntimeError), trace.acquisition("ft"):
        failed = trace.try_write_unique_screenshot("input", b"failed", provider="ft")
        raise RuntimeError("prior attempt")
    with trace.acquisition("ft"):
        success = trace.try_write_unique_screenshot("input", b"new", provider="ft")
        assert success is not None and success.exists()
        assert failed is not None and failed.exists()
        # Leaving this scope represents successful browser close and publication.
    assert failed.exists()
    assert not success.exists()
    records = [json.loads(line) for line in trace._path.read_text().splitlines()]
    assert [
        row["facts"]["stage"]
        for row in records
        if row["event"] == "acquisition_evidence"
    ] == ["started", "failed", "started", "published", "artifacts_discarded"]


def test_diagnostic_loss_keeps_evidence_without_replacing_success(
    tmp_path: Path,
) -> None:
    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    with trace.acquisition("ft"):
        image = trace.try_write_unique_screenshot("input", b"image", provider="ft")
        trace.note_diagnostic_loss("screenshot_capture", provider="ft")
    assert image is not None and image.exists()


def test_cleanup_failure_does_not_turn_published_session_into_failed_mint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    with trace.acquisition("ft"):
        image = trace.try_write_unique_screenshot("input", b"image", provider="ft")
        original = Path.unlink

        def fail_owned(path, *args, **kwargs):
            if path == image:
                raise OSError("fixture full filesystem")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_owned)
    assert image is not None and image.exists()


def test_scope_budget_is_shared_by_its_browser_attempts(tmp_path: Path) -> None:
    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    with trace.acquisition("ft"):
        for number in range(30):
            assert (
                trace.try_write_unique_screenshot(
                    "input",
                    b"image",
                    provider="ft",
                    attempt_id=f"attempt-{number:032x}",
                )
                is not None
            )
        assert (
            trace.try_write_unique_screenshot(
                "input", b"extra", provider="ft", attempt_id="attempt-" + "f" * 32
            )
            is None
        )


def test_closed_read_attempt_releases_its_in_memory_artifact_index(
    tmp_path: Path,
) -> None:
    from newsclip.browser_runtime.events import (
        AttemptFinishedEvent,
        AttemptStartedEvent,
    )

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    attempt_id = "attempt-" + "b" * 32
    assert trace.try_write(
        AttemptStartedEvent(attempt_id=attempt_id, provider="wsj", purpose="retrieve")
    )
    image = trace.try_write_unique_screenshot(
        "failure", b"image", provider="wsj", attempt_id=attempt_id
    )
    assert image is not None
    assert attempt_id in trace._artifact_usage
    assert trace.try_write(
        AttemptFinishedEvent(
            attempt_id=attempt_id,
            provider="wsj",
            outcome="error",
            last_phase="profile",
        )
    )

    # The evidence stays on disk; only the long-lived process index is freed.
    assert image.read_bytes() == b"image"
    assert attempt_id not in trace._artifact_usage
    assert attempt_id not in trace._artifacts


def test_failed_atomic_publication_exposes_no_partial_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import newsclip.browser_runtime.events as events

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")

    def interrupted(*args):
        raise OSError("interrupted before publication")

    monkeypatch.setattr(events.os, "link", interrupted)
    assert trace.try_write_unique_screenshot("input", b"partial", provider="ft") is None
    assert not list(tmp_path.glob("*.png"))
    assert not list(tmp_path.glob("*.partial"))


@pytest.mark.parametrize(
    "failed_event", ["semantic_action_started", "semantic_action_finished"]
)
def test_intent_write_failure_stops_dispatch_but_result_write_failure_does_not_undo_it(
    tmp_path: Path, failed_event: str
) -> None:
    from types import SimpleNamespace

    from newsclip.browser_runtime.runtime import PatchrightMintContext
    from newsclip.browser_runtime.surface import BrowserRuntimeError

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace(), trace=trace)
    original = trace._write
    actions = []

    def fail_selected(event):
        if event.event == failed_event:
            raise OSError("fixture disk full")
        original(event)

    trace._write = fail_selected
    with trace.acquisition("ft"), browser.attempt("ft", "login"):
        if failed_event == "semantic_action_started":
            with pytest.raises(BrowserRuntimeError, match="diagnostic_write_failed"):
                browser.dispatch_challenge_action(lambda: actions.append("clicked"))
            assert actions == []
        else:
            browser.dispatch_challenge_action(lambda: actions.append("clicked"))
            assert actions == ["clicked"]


def test_incomplete_acquisition_cannot_become_complete_evidence(tmp_path: Path) -> None:
    from newsclip.browser_runtime.events import AcquisitionEvidenceEvent
    from newsclip.live_reporting import collect_live_evidence

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    trace.write(
        AcquisitionEvidenceEvent(
            operation_id="op-" + "a" * 32,
            provider="ft",
            stage="started",
            evidence_complete=True,
        )
    )
    evidence = collect_live_evidence(tmp_path)
    assert evidence.runtime.event_counts["invalid_trace"] == 1
    assert evidence.acquisitions[0].stage == "started"


def test_process_exit_after_dispatch_preserves_input_and_ambiguous_intent(
    tmp_path: Path,
):
    import subprocess
    import sys

    from newsclip.live_reporting import collect_live_evidence

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from newsclip.browser_runtime.events import RuntimeTrace
from newsclip.browser_runtime.runtime import PatchrightMintContext
trace = RuntimeTrace(Path(sys.argv[1]) / 'trace.jsonl', run_id='crash-test')
browser = PatchrightMintContext(SimpleNamespace(), SimpleNamespace(), trace=trace)
with trace.acquisition('ft'), browser.attempt('ft', 'login'):
    trace.try_write_unique_screenshot('input', b'complete input', provider='ft')
    browser.dispatch_challenge_action(lambda: os._exit(17))
""",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 17, result.stderr.decode()
    assert (tmp_path / "trace.input.png").read_bytes() == b"complete input"
    evidence = collect_live_evidence(tmp_path)
    assert evidence.attempts[0].outcome == "incomplete"
    assert evidence.attempts[0].last_action_dispatched == "not_observed"
    assert evidence.runtime.event_counts["invalid_trace"] == 1


def test_concurrent_success_does_not_delete_an_active_failed_attempt(tmp_path: Path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    trace = RuntimeTrace(tmp_path / "trace.jsonl", run_id="evidence-test")
    ready = Barrier(2, timeout=5)
    published = Barrier(2, timeout=5)

    def failed_attempt():
        with pytest.raises(RuntimeError), trace.acquisition("ft"):
            image = trace.try_write_unique_screenshot("input", b"failed", provider="ft")
            ready.wait()
            published.wait()
            assert image is not None and image.exists()
            raise RuntimeError("fixture failure")
        return image

    def successful_attempt():
        with trace.acquisition("ft"):
            image = trace.try_write_unique_screenshot(
                "input", b"success", provider="ft"
            )
            ready.wait()
        assert image is not None and not image.exists()
        published.wait()

    with ThreadPoolExecutor(max_workers=2) as pool:
        failure = pool.submit(failed_attempt)
        success = pool.submit(successful_attempt)
        success.result(timeout=10)
        assert failure.result(timeout=10).exists()


@pytest.mark.parametrize("mode", [None, "warm", "cold"])
def test_live_gate_retains_successful_login_images_until_outer_verdict(
    tmp_path, monkeypatch, mode
):
    from newsclip.composition import build_auth_service

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_TRACE_HOME", str(tmp_path / "trace"))
    monkeypatch.setenv(
        "NEWSCLIP_INVOCATION_ID", "cli-fixture" if mode is None else "live-fixture"
    )
    if mode is None:
        monkeypatch.delenv("NEWSCLIP_LIVE_MODE", raising=False)
    else:
        monkeypatch.setenv("NEWSCLIP_LIVE_MODE", mode)
    service = build_auth_service()
    try:
        trace = service._browser_retriever._runtime._trace
        with trace.acquisition("ft"):
            path = trace.try_write_unique_screenshot(
                "paid-proof", b"private proof", provider="ft"
            )
        # Serialization or the following article check can fail after login.
        # The outer live gate owns successful-provider cleanup at that point.
        assert path is not None and path.exists() is (mode is not None)
    finally:
        service.close()
