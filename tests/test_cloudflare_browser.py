"""Inert Cloudflare checkbox contracts; all requests terminate in fixtures."""

import json

import pytest
from patchright.sync_api import sync_playwright

from newsclip.browser_runtime.events import RuntimeTrace, read_runtime_file
from newsclip.browser_runtime.runtime import PatchrightMintContext
from newsclip.challenge_resolver import ChallengeResolutionStatus, ChallengeResolver
from newsclip.challenges import ChallengeMode, ChallengeVendor
from newsclip.cloudflare_interstitial import CloudflareInterstitialMechanic


@pytest.fixture(scope="module")
def chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


@pytest.mark.parametrize(
    "condition, expected_actions, cleared",
    [
        ("clears", 1, True),
        ("clears_with_passive_datadome", 1, True),
        ("replaced_by_interactive_datadome", 1, False),
        ("persists", 1, False),
        ("hidden", 0, False),
        ("disabled", 0, False),
        ("checked", 0, False),
        ("foreign", 0, False),
        ("detect_only", 0, False),
        ("multiple", 0, False),
        ("stale", 0, False),
    ],
)
def test_closed_shadow_checkbox_requires_native_clearance(
    chromium, tmp_path, monkeypatch, condition, expected_actions, cleared
):
    context = chromium.new_context()
    host = "foreign.invalid" if condition == "foreign" else "challenges.cloudflare.com"
    checkbox = (
        '<label><input type="checkbox" '
        + {"hidden": "hidden", "disabled": "disabled", "checked": "checked"}.get(
            condition, ""
        )
        + ">Verify you are human</label>"
    )
    widget = """<div id='widget'></div><script>
      const root = document.querySelector('#widget').attachShadow({mode:'closed'});
      root.innerHTML = CHECKBOX;
      root.querySelector('input').addEventListener('click', () => {
        parent.postMessage('checkbox-click', '*');
      });
    </script>"""
    widget = widget.replace("CHECKBOX", json.dumps(checkbox))
    if condition == "multiple":
        widget = widget.replace(json.dumps(checkbox), json.dumps(checkbox + checkbox))
    context.route(
        "**/*", lambda route: route.fulfill(content_type="text/html", body=widget)
    )
    trace_path = tmp_path / "trace.jsonl"
    trace = RuntimeTrace(trace_path, run_id="inert-cloudflare")
    try:
        page = context.new_page()
        page.set_content(
            "<title>Just a moment...</title><div id='challenge'></div>"
            "<!-- /cdn-cgi/challenge-platform/ -->"
        )
        page.evaluate(
            """({host, clears, passiveAsset, interactiveReplacement}) => {
              window.clicks = 0;
              window.addEventListener('message', e => {
                if (e.data !== 'checkbox-click') return;
                window.clicks++;
                if (clears) {
                  document.title = 'Article';
                  document.body.innerHTML = '<article>Fixture article</article>';
                  if (passiveAsset || interactiveReplacement) {
                    const script = document.createElement('script');
                    script.type = 'application/json';
                    script.textContent = JSON.stringify({provider:'datadome'});
                    document.body.appendChild(script);
                  }
                  if (interactiveReplacement) {
                    const challenge = document.createElement('div');
                    challenge.dataset.captchaProvider = 'datadome';
                    challenge.style.cssText = 'width:300px;height:100px';
                    challenge.textContent = 'Verify you are human';
                    document.body.appendChild(challenge);
                  }
                }
              });
              document.querySelector('#challenge').attachShadow({mode:'closed'})
                .innerHTML = `<iframe width='300' height='80'
                  src='https://${host}/cdn-cgi/challenge-platform/widget'></iframe>`;
            }""",
            {
                "host": host,
                "clears": condition
                in {
                    "clears",
                    "clears_with_passive_datadome",
                    "replaced_by_interactive_datadome",
                },
                "passiveAsset": condition == "clears_with_passive_datadome",
                "interactiveReplacement": condition
                == "replaced_by_interactive_datadome",
            },
        )
        page.locator("iframe").wait_for(timeout=3000)
        page.frames[-1].wait_for_load_state()
        browser = PatchrightMintContext(context, page, trace=trace)
        if condition == "stale":
            capture = browser.capture_diagnostic_screenshot

            def replace_before_dispatch(*args, **kwargs):
                captured = capture(*args, **kwargs)
                page.frames[-1].locator('input[type="checkbox"]').evaluate(
                    "element => element.replaceWith(element.cloneNode(true))"
                )
                return captured

            monkeypatch.setattr(
                browser, "capture_diagnostic_screenshot", replace_before_dispatch
            )
        resolver = ChallengeResolver(
            {
                ChallengeVendor.CLOUDFLARE_INTERSTITIAL: CloudflareInterstitialMechanic(
                    wall_budget_seconds=2
                )
            }
        )
        with trace.acquisition("economist"), browser.attempt("economist", "retrieve"):
            result = resolver.resolve(
                browser,
                ChallengeMode.DETECT_ONLY
                if condition == "detect_only"
                else ChallengeMode.AUTO,
            )
            if expected_actions or condition == "stale":
                assert list(tmp_path.glob("*.png"))
        assert (result.status is ChallengeResolutionStatus.CLEARED) is cleared
        assert page.evaluate("() => window.clicks") == expected_actions
        actions = [
            row.event
            for row in read_runtime_file(trace_path).records
            if row.event.event == "semantic_action_started"
        ]
        # Stale input is recorded before its ambiguous dispatch error and is
        # never redirected to the replacement control or retried.
        assert len(actions) == (1 if condition == "stale" else expected_actions)
    finally:
        context.close()
