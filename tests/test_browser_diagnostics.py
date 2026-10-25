from __future__ import annotations

from types import SimpleNamespace

import pytest

from newsclip.browser_runtime.events import RuntimeTrace
from newsclip.browser_runtime.runtime import PatchrightMintContext
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.challenges import ChallengeDetection, ChallengeMode, ChallengeVendor
from newsclip.datadome import DataDomeSliderMechanic
from newsclip.live_reporting import collect_live_evidence


@pytest.mark.parametrize("scenario", ["restricted", "pending", "delayed_slider"])
@pytest.mark.parametrize("capture_fails", [False, True])
def test_challenge_evidence_preserves_policy_and_first_surface(
    tmp_path, monkeypatch, scenario, capture_fails
):
    # Inert page state, not a reconstruction of the publisher's private rule.
    page = SimpleNamespace(ticks=0.0, dragged=False, frames=[], captures=[])
    page.wait_for_timeout = lambda ms: setattr(page, "ticks", page.ticks + ms / 1000)

    def screenshot(**kwargs):
        page.captures.append(page.ticks)
        if capture_fails:
            raise RuntimeError("fixture screenshot unavailable")
        return b"fixture image"

    page.screenshot = screenshot
    page.mouse = SimpleNamespace(
        move=lambda *args, **kwargs: None,
        down=lambda: None,
        up=lambda: setattr(page, "dragged", True),
    )
    page.goto = lambda *args, **kwargs: SimpleNamespace(
        status=403,
        url="https://publisher.test/article?token=SECRET_SENTINEL",
        headers={"set-cookie": "SECRET_SENTINEL"},
    )

    def detector(browser):
        cleared = page.dragged or (scenario == "pending" and page.ticks >= 2)
        return ChallengeDetection(
            vendor="none" if cleared else "datadome",
            state="none" if cleared else "interactive",
        )

    def geometry(page):
        if scenario != "delayed_slider" or page.ticks < 1 or page.dragged:
            return None
        return (
            {"x": 0, "y": 0, "width": 20, "height": 20},
            {"x": 0, "y": 0, "width": 200, "height": 20},
        )

    monkeypatch.setattr("newsclip.datadome._find_slider_geometry", geometry)
    monkeypatch.setattr(
        "signin_window.automation.resolver.time.monotonic", lambda: page.ticks
    )
    mechanic = DataDomeSliderMechanic(
        wall_budget_seconds=10, clock=lambda: page.ticks, sleep=lambda seconds: None
    )
    resolver = ChallengeResolver(
        {ChallengeVendor.DATADOME: mechanic}, detector=detector
    )
    path = tmp_path / "wsj" / "browser-fixture.jsonl"
    trace = RuntimeTrace(path, run_id="browser-fixture", retain_success_artifacts=True)
    browser = PatchrightMintContext(None, page, trace=trace, profile_state="new")
    with browser.attempt("wsj", "login"):
        browser.navigate("https://publisher.test/article?code=SECRET_SENTINEL")
        resolution = resolver.resolve(browser, ChallengeMode.AUTO)
    evidence = collect_live_evidence(tmp_path)
    attempt = evidence.attempts[0]
    terminal = evidence.challenge_resolutions[0]
    assert resolution.status.value == (
        "blocked" if scenario == "restricted" else "cleared"
    )
    assert terminal.status == resolution.status
    assert terminal.actionable_observed is (scenario == "delayed_slider")
    assert terminal.surface_observations > 1
    assert terminal.elapsed_ms is not None
    assert attempt.challenge_action_count == (1 if scenario == "delayed_slider" else 0)
    assert attempt.last_navigation.status == 403
    assert attempt.last_navigation.destination == "requested_origin"
    assert attempt.profile_state == "new"
    assert page.captures == [0.0]  # first blocking state only, never every poll
    assert "SECRET_SENTINEL" not in path.read_text()
    artifact = evidence.diagnostic_artifacts[0]
    assert artifact.label == "challenge-first"
    assert (artifact.omission is not None) is capture_fails
    assert not evidence.runtime.event_counts.get("invalid_trace")


def test_navigation_failure_keeps_original_error_and_unknown_response(tmp_path):
    original = RuntimeError("fixture navigation failed")

    def goto(*args, **kwargs):
        raise original

    page = SimpleNamespace(goto=goto, screenshot=lambda **kwargs: b"fixture")
    trace = RuntimeTrace(
        tmp_path / "wsj" / "browser-failure.jsonl", run_id="browser-failure"
    )
    browser = PatchrightMintContext(None, page, trace=trace)
    with pytest.raises(RuntimeError) as caught, browser.attempt("wsj", "login"):
        browser.navigate("https://publisher.test/?code=SECRET_SENTINEL")
    assert caught.value is original
    attempt = collect_live_evidence(tmp_path).attempts[0]
    assert attempt.outcome.value == "error"
    assert attempt.last_navigation.status is None
    assert attempt.last_navigation.destination == "unknown"
    assert attempt.profile_state == "unknown"


def test_navigation_metadata_failure_does_not_change_success(tmp_path):
    class Response:
        @property
        def status(self):
            raise RuntimeError("fixture metadata unavailable")

    page = SimpleNamespace(goto=lambda *args, **kwargs: Response())
    trace = RuntimeTrace(tmp_path / "wsj" / "browser-loss.jsonl", run_id="browser-loss")
    browser = PatchrightMintContext(None, page, trace=trace)
    with browser.attempt("wsj", "login"):
        browser.navigate("https://publisher.test/")
    evidence = collect_live_evidence(tmp_path)
    assert evidence.attempts[0].outcome.value == "success"
    assert evidence.attempts[0].last_navigation.status is None
    assert evidence.runtime.event_write_failures == 1


@pytest.mark.parametrize("rejected", [False, True])
def test_interrupted_challenge_dispatch_is_not_reported_as_zero(tmp_path, rejected):
    from newsclip.browser_runtime.events import (
        AttemptStartedEvent,
        SemanticActionFinishedEvent,
        SemanticActionStartedEvent,
    )

    trace = RuntimeTrace(
        tmp_path / "wsj/browser-partial.jsonl", run_id="browser-partial"
    )
    attempt_id = "attempt-" + "a" * 32
    trace.write(
        AttemptStartedEvent(attempt_id=attempt_id, provider="wsj", purpose="login")
    )
    trace.write(
        SemanticActionStartedEvent(
            attempt_id=attempt_id,
            action_id=1,
            sequence=1,
            action="challenge_action",
            pre_observation_code="unknown",
        )
    )
    if rejected:
        trace.write(
            SemanticActionFinishedEvent(
                attempt_id=attempt_id,
                action_id=1,
                dispatched=False,
                result="rejected",
            )
        )
    attempt = collect_live_evidence(tmp_path).attempts[0]
    assert attempt.outcome == "incomplete"
    assert attempt.challenge_action_count == (0 if rejected else 1)


def test_passive_retrieval_observation_does_not_add_an_action_gate(
    tmp_path, monkeypatch
):
    trace = RuntimeTrace(tmp_path / "wsj/browser-loss.jsonl", run_id="browser-loss")
    monkeypatch.setattr(trace, "try_write", lambda *args, **kwargs: False)
    browser = PatchrightMintContext(None, SimpleNamespace(), trace=trace)
    result = SimpleNamespace(status=200, url="https://publisher.test/")
    with browser.attempt("wsj", "retrieve"):
        assert (
            browser.observe_navigation("https://publisher.test/", lambda: result)
            is result
        )


def test_passive_navigation_failure_preserves_original_error(tmp_path):
    trace = RuntimeTrace(tmp_path / "wsj/browser-loss.jsonl", run_id="browser-loss")
    browser = PatchrightMintContext(
        None, SimpleNamespace(screenshot=lambda **kwargs: b"fixture"), trace=trace
    )
    original = RuntimeError("fixture navigation failed")

    def navigate():
        raise original

    with pytest.raises(RuntimeError) as caught, browser.attempt("wsj", "retrieve"):
        browser.observe_navigation("https://publisher.test/", navigate)
    assert caught.value is original
    attempt = collect_live_evidence(tmp_path).attempts[0]
    assert attempt.last_navigation.status is None
    assert attempt.last_navigation.destination == "unknown"
