"""Inert browser regressions for task identity during slow planning."""

import time
from types import SimpleNamespace

import pytest
from patchright.sync_api import sync_playwright

from newsclip.browser_runtime.events import RuntimeTrace, read_runtime_file
from newsclip.browser_runtime.runtime import PatchrightMintContext
from newsclip.challenges import ChallengeAcceptance, ChallengeAcceptanceSource
from newsclip.hcaptcha import HCaptchaVisualMechanic, _ActionBoundary
from newsclip.vision_planning import VisualPlan


@pytest.fixture(scope="module")
def chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


def test_next_advances_the_task_without_claiming_acceptance(chromium):
    context = chromium.new_context()
    context.route(
        "**/*",
        lambda route: route.fulfill(
            content_type="text/html",
            body="<button>Skip</button><button id='submit'>Next</button>",
        ),
    )
    try:
        page = context.new_page()
        page.set_content(
            "<iframe src='https://fixture.hcaptcha.invalid/?frame=challenge'></iframe>"
        )
        frame = page.frames[-1]
        frame.wait_for_selector("#submit")
        frame.evaluate("""() => {
          window.clicks = [];
          window.accepted = false;
          document.addEventListener('click', event => {
            if (event.target.tagName !== 'BUTTON') return;
            window.clicks.push(event.target.textContent);
            if (event.target.textContent === 'Next') {
              event.target.textContent = 'Verify';
            } else if (event.target.textContent === 'Verify') {
              window.accepted = true;
            }
          });
        }""")

        class Probe:
            def observe(self):
                accepted = frame.evaluate("() => window.accepted")
                return ChallengeAcceptance(
                    accepted=accepted,
                    source=ChallengeAcceptanceSource.EXISTING_FORM_FIELD
                    if accepted
                    else ChallengeAcceptanceSource.NONE,
                )

        mechanic = HCaptchaVisualMechanic(planner=SimpleNamespace())
        probe = Probe()

        def advance(*, expired=False):
            deadline = time.monotonic() + (-1 if expired else 5)
            return mechanic._wait_and_click_submit(
                page,
                frame,
                deadline=deadline,
                acceptance=probe,
                boundary=_ActionBoundary(
                    lambda: None, lambda: deadline - time.monotonic()
                ),
            )

        assert not advance(expired=True)
        assert frame.evaluate("() => window.clicks") == []
        assert advance()
        assert not probe.observe().accepted
        assert frame.evaluate("() => window.clicks") == ["Next"]
        assert advance()
        assert probe.observe().accepted
        assert not advance()
        assert frame.evaluate("() => window.clicks") == ["Next", "Verify"]
    finally:
        context.close()


@pytest.mark.parametrize("change", ["animation", "task_node", "asset", "frame"])
def test_planner_can_only_act_on_its_original_task(
    chromium, change, monkeypatch, tmp_path
):
    page = chromium.new_page()
    clicks = []
    click = page.mouse.click

    def observed_click(*args, **kwargs):
        clicks.append("fixture-click")
        return click(*args, **kwargs)

    monkeypatch.setattr(page.mouse, "click", observed_click)
    fixture = """
      <div class='challenge-view' style='width:200px;height:200px;background:white'>
        <h2 class='prompt-text'>Click the moving object</h2>
        <div class='task-image'>
          <img width='60' height='60'
            src='data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'>
        </div>
        <button>Verify</button>
      </div>
    """
    page.route(
        "**/*", lambda route: route.fulfill(content_type="text/html", body=fixture)
    )
    try:
        page.set_content(
            "<iframe width='300' height='300' src='https://fixture.hcaptcha.invalid/?frame=challenge'></iframe>"
        )
        frame = page.frames[-1]
        frame.wait_for_selector(".task-image img")
        frame.evaluate("""() => {
          window.accepted = false;
          document.addEventListener('click', () => {
            window.accepted = true;
          });
        }""")

        class Probe:
            def observe(self):
                accepted = (
                    not frame.is_detached()
                    and frame.evaluate("() => window.accepted") is True
                )
                return ChallengeAcceptance(
                    accepted=accepted,
                    source=ChallengeAcceptanceSource.EXISTING_FORM_FIELD
                    if accepted
                    else ChallengeAcceptanceSource.NONE,
                )

        class Planner:
            def plan(self, image, **kwargs):
                if change == "animation":
                    frame.evaluate(
                        "() => document.querySelector('img').style.transform = "
                        "'translateX(20px)'"
                    )
                elif change == "task_node":
                    frame.evaluate("""() => {
                      const node = document.querySelector('.task-image');
                      node.replaceWith(node.cloneNode(true));
                    }""")
                elif change == "asset":
                    frame.evaluate(
                        "() => document.querySelector('img').src += '#replacement'"
                    )
                else:
                    page.evaluate("""() => {
                      const node = document.querySelector('iframe');
                      node.replaceWith(node.cloneNode(true));
                    }""")
                return VisualPlan(kind="point", points=({"x": 0.5, "y": 0.5},))

        trace_path = tmp_path / "evidence.jsonl"
        trace = RuntimeTrace(trace_path, run_id="inert-browser-evidence")
        browser = PatchrightMintContext(page.context, page, trace=trace)
        try:
            with trace.acquisition("ft"):
                with browser.attempt("ft", "login"):
                    result = HCaptchaVisualMechanic(
                        planner=Planner(), max_rounds=1
                    ).solve(browser, Probe())
                page.close()
                if not result.accepted:
                    raise RuntimeError("fixture mint did not obtain acceptance")
        except RuntimeError as error:
            assert str(error) == "fixture mint did not obtain acceptance"
        assert result.accepted is (change == "animation")
        assert clicks == (["fixture-click"] if change == "animation" else [])
        records = read_runtime_file(trace_path).records
        artifacts = [
            record.event
            for record in records
            if record.event.event == "diagnostic_artifact"
        ]
        assert artifacts and all(event.omission is None for event in artifacts)
        if result.accepted:
            assert not list(tmp_path.glob("*.png"))
        else:
            terminal = next(
                event for event in artifacts if event.label == "hcaptcha-failure"
            )
            assert (
                (tmp_path / terminal.path).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
            )
            assert any(event.label.endswith("input-0") for event in artifacts)
            assert all((tmp_path / event.path).is_file() for event in artifacts)
    finally:
        page.close()
