from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from patchright.sync_api import Page, sync_playwright

from newsclip.challenge_catalog import build_challenge_resolver
from newsclip.challenge_detection import (
    detect_challenge,
    detect_challenge_for_reads,
)
from newsclip.challenge_resolver import ChallengeResolutionStatus
from newsclip.challenges import ChallengeMode, ChallengeState, ChallengeVendor


class EvaluationBrowser:
    def __init__(self, page: Page) -> None:
        self.page = page

    def evaluate(self, script: str) -> object:
        return self.page.evaluate(script)


@pytest.fixture(scope="module")
def detector_page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser.new_page()
        finally:
            browser.close()


def test_detector_recognizes_full_page_datadome_slider(detector_page: Page) -> None:
    detector_page.route(
        "https://geo.captcha-delivery.com/**",
        lambda route: route.fulfill(
            status=200,
            content_type="text/html",
            body="""
                <!doctype html>
                <html><body>
                  <div class="sliderContainer"
                       style="width:300px;height:40px">
                    <div class="slider" style="width:40px;height:40px"></div>
                  </div>
                </body></html>
            """,
        ),
    )
    detector_page.goto("https://geo.captcha-delivery.com/captcha/?initialCid=fixture")

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.DATADOME
    assert detection.state is ChallengeState.INTERACTIVE
    assert any("captcha-delivery" in frame.url for frame in detector_page.frames)


@pytest.mark.parametrize(
    ("position", "expected_state"),
    [
        ("top:20px", ChallengeState.INTERACTIVE),
        ("top:-9999px", ChallengeState.ASSET_ONLY),
    ],
)
def test_detector_requires_hcaptcha_frames_to_intersect_the_viewport(
    detector_page: Page,
    position: str,
    expected_state: ChallengeState,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        f"""
        <!doctype html>
        <html><body>
          <iframe
            src="https://newassets.hcaptcha.com/captcha/v1/test?frame=challenge"
            srcdoc="<body><div class='challenge-view'>Fixture</div></body>"
            style="position:absolute;left:20px;{position};width:300px;height:180px">
          </iframe>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.HCAPTCHA
    assert detection.state is expected_state


def test_native_fallback_sees_interactive_frame_inside_open_shadow_root(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <div id="challenge-host"></div>
          <script>
            const root = document.querySelector('#challenge-host')
              .attachShadow({mode: 'open'});
            root.innerHTML = `
              <iframe src="https://geo.captcha-delivery.com/captcha/fixture"
                style="width:300px;height:180px"></iframe>`;
          </script>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.DATADOME
    assert detection.state is ChallengeState.INTERACTIVE


def test_detector_does_not_treat_article_prose_as_a_challenge(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article style="width:600px;height:400px">
            <h1>Bot defenses evolve</h1>
            <p>The displayed instruction was: Verify you are human.</p>
          </article>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


def test_detector_honors_non_element_article_identity(detector_page: Page) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><head>
          <meta property="og:type" content="article">
        </head><body>
          <main style="width:600px;height:400px">
            <div class="publisher-copy">
              The quoted button said: Complete the captcha.
            </div>
          </main>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


def test_detector_does_not_treat_perimeterx_prose_as_a_control(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article style="width:600px;height:400px">
            <h1>Phone shortcut guide</h1>
            <p>Press and hold the side button to continue.</p>
          </article>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


def test_detector_requires_perimeterx_text_to_be_a_vendor_backed_control(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <script src="data:text/javascript,void%200%3B%2F%2Fperimeterx"></script>
          <button style="width:240px;height:50px">Press &amp; Hold</button>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.PERIMETERX
    assert detection.state is ChallengeState.INTERACTIVE


def test_detector_does_not_promote_text_from_a_hidden_stale_perimeterx_root(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <div id="px-captcha" style="display:none"></div>
          <article style="width:600px;height:400px">
            <button style="width:240px;height:50px">
              Press and hold the side button
            </button>
          </article>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.PERIMETERX
    assert detection.state is ChallengeState.ASSET_ONLY


def test_detector_preserves_structural_generic_interstitials(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <main style="width:600px;height:400px">
            <h1>Verify you are human</h1>
            <p>Complete the check to continue.</p>
          </main>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.UNSUPPORTED
    assert detection.state is ChallengeState.INTERACTIVE


def test_detector_distinguishes_cloudflare_interstitial_from_turnstile(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html>
          <head><title>Just a moment...</title></head>
          <body>
            <main><p id="challenge-error-text">Enable JavaScript and cookies.</p></main>
            <script>
              window._cf_chl_opt = {cType: 'managed'};
              const path = '/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1';
            </script>
          </body>
        </html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.CLOUDFLARE_INTERSTITIAL
    assert detection.state is ChallengeState.INTERACTIVE


def test_cloudflare_interstitial_passes_end_to_end_without_an_action(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html>
          <head><title>Just a moment...</title></head>
          <body>
            <main><p id="challenge-error-text">Enable JavaScript and cookies.</p></main>
            <script>
              window._cf_chl_opt = {cType: 'fixture'};
              const path = '/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1';
              setTimeout(() => {
                document.title = 'Economist search';
                document.body.innerHTML =
                  '<main><ol><li>Search result</li></ol></main>';
              }, 250);
            </script>
          </body>
        </html>
        """
    )
    resolver = build_challenge_resolver({ChallengeVendor.CLOUDFLARE_INTERSTITIAL})

    result = resolver.resolve(EvaluationBrowser(detector_page), ChallengeMode.AUTO)

    assert result.status is ChallengeResolutionStatus.CLEARED
    assert detector_page.title() == "Economist search"
    assert detector_page.locator("main ol li").inner_text() == "Search result"


_DEVICE_CHECK = (
    Path(__file__).parent
    / "fixtures"
    / "reuters"
    / "challenge-datadome-device-check.html"
).read_text()


def _serve_device_check(page: Page, frame_body: str) -> None:
    page.route(
        "https://ct.captcha-delivery.com/**",
        lambda route: route.fulfill(
            status=200, content_type="application/javascript", body=""
        ),
    )
    page.route(
        "https://geo.captcha-delivery.com/**",
        lambda route: route.fulfill(
            status=200, content_type="text/html", body=frame_body
        ),
    )


def _passive_datadome_resolver():
    return build_challenge_resolver(
        {ChallengeVendor.DATADOME}, passive_vendors={ChallengeVendor.DATADOME}
    )


def test_passive_datadome_awaits_the_device_check_end_to_end(
    detector_page: Page,
) -> None:
    _serve_device_check(
        detector_page,
        "<!doctype html><html><body><h1>Verifying the device...</h1></body></html>",
    )
    detector_page.goto("about:blank")
    # The real page reloads the article once its frame accepts the device.
    detector_page.set_content(
        _DEVICE_CHECK.replace(
            "</body>",
            """<script>
              setTimeout(() => {
                document.title = 'Reuters article';
                document.body.innerHTML =
                  '<article><h1>Headline</h1><p>Body</p></article>';
              }, 1000);
            </script></body>""",
        )
    )
    assert detect_challenge(EvaluationBrowser(detector_page)).state is (
        ChallengeState.INTERACTIVE
    )

    result = _passive_datadome_resolver().resolve(
        EvaluationBrowser(detector_page), ChallengeMode.AUTO
    )

    assert result.status is ChallengeResolutionStatus.CLEARED
    assert detector_page.locator("article h1").inner_text() == "Headline"


def test_passive_datadome_refuses_a_slider_quickly(detector_page: Page) -> None:
    _serve_device_check(
        detector_page,
        """<!doctype html><html><body>
          <div class="sliderContainer" style="width:300px;height:40px">
            <div class="slider" style="width:40px;height:40px"></div>
          </div>
        </body></html>""",
    )
    detector_page.goto("about:blank")
    detector_page.set_content(_DEVICE_CHECK)
    detector_page.frame_locator("iframe").locator(".slider").wait_for()
    started = time.monotonic()

    result = _passive_datadome_resolver().resolve(
        EvaluationBrowser(detector_page), ChallengeMode.AUTO
    )

    assert result.status is ChallengeResolutionStatus.BLOCKED
    assert time.monotonic() - started < 10


def test_detector_does_not_promote_cloudflare_asset_on_an_article(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html>
          <head><title>Subscriber article</title></head>
          <body>
            <article><h1>Cloudflare explains challenge passage</h1></article>
            <script src="/cdn-cgi/challenge-platform/scripts/jsd/api.js"></script>
          </body>
        </html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


def test_detector_preserves_modal_challenge_over_a_mounted_article(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article style="width:600px;height:400px">
            <h1>Subscriber article</h1>
            <p>The article remains mounted behind the blocking overlay.</p>
          </article>
          <div role="dialog" aria-modal="true"
               style="position:fixed;inset:0;background:white">
            <h2>Verify you are human</h2>
          </div>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.UNSUPPORTED
    assert detection.state is ChallengeState.INTERACTIVE


def test_detector_ignores_named_challenge_prose_inside_an_article(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article style="width:600px;height:400px">
            <section class="challenge-analysis">
              The displayed instruction was: Verify you are human.
            </section>
          </article>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


@pytest.mark.parametrize("detector", [detect_challenge, detect_challenge_for_reads])
def test_detector_treats_the_invisible_recaptcha_badge_as_an_asset(
    detector_page: Page,
    detector,  # noqa: ANN001
) -> None:
    # AP article pages carry this badge; it asked nobody for anything, yet it
    # armed provider defense on served articles (2026-09-29).
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article><h1>Served article</h1><p>Body text.</p></article>
          <div class="grecaptcha-badge"
               style="position:fixed;bottom:14px;right:0;width:256px;height:60px">
            <div class="grecaptcha-logo">
              <iframe title="reCAPTCHA" width="256" height="60"
                src="https://www.google.com/recaptcha/api2/anchor?ar=1&k=fixture&size=invisible"></iframe>
            </div>
          </div>
        </body></html>
        """
    )

    detection = detector(EvaluationBrowser(detector_page))

    assert detection.state is not ChallengeState.INTERACTIVE


def test_detector_still_sees_a_checkbox_recaptcha(detector_page: Page) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <iframe title="reCAPTCHA" width="304" height="78"
            src="https://www.google.com/recaptcha/api2/anchor?ar=1&k=fixture&size=normal"></iframe>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.RECAPTCHA
    assert detection.state is ChallengeState.INTERACTIVE


def test_detector_keeps_passive_datadome_assets_noninteractive(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <script type="application/json">{"provider":"datadome"}</script>
          <main style="width:600px;height:400px">Sign in</main>
        </body></html>
        """
    )

    detection = detect_challenge(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.DATADOME
    assert detection.state is ChallengeState.ASSET_ONLY


def test_read_detector_matches_native_shadow_root_detection(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <div id="challenge-host"></div>
          <script>
            const root = document.querySelector('#challenge-host')
              .attachShadow({mode: 'open'});
            root.innerHTML = `
              <iframe src="https://geo.captcha-delivery.com/captcha/fixture"
                style="width:300px;height:180px"></iframe>`;
          </script>
        </body></html>
        """
    )

    detection = detect_challenge_for_reads(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.DATADOME
    assert detection.state is ChallengeState.INTERACTIVE


def test_read_detector_keeps_clean_article_pages_clean(
    detector_page: Page,
) -> None:
    detector_page.goto("about:blank")
    detector_page.set_content(
        """
        <!doctype html>
        <html><body>
          <article style="width:600px;height:400px">
            <h1>Fixture headline</h1>
            <p>Fixture body prose without any challenge surface.</p>
          </article>
        </body></html>
        """
    )

    detection = detect_challenge_for_reads(EvaluationBrowser(detector_page))

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE


class _CountingLocator:
    def __init__(self, count: int) -> None:
        self._count = count

    def count(self) -> int:
        return self._count


class _CountingBrowser:
    """Stub page counting locator roundtrips behind a clean JS verdict."""

    def __init__(self, prefilter_count: int) -> None:
        self.page = self
        self.locator_selectors: list[str] = []
        self._prefilter_count = prefilter_count

    def evaluate(self, script: str) -> object:
        return {"vendor": "none", "state": "none"}

    def locator(self, selector: str) -> _CountingLocator:
        self.locator_selectors.append(selector)
        if len(self.locator_selectors) == 1:
            return _CountingLocator(self._prefilter_count)
        return _CountingLocator(0)


def test_read_detector_uses_one_roundtrip_when_no_native_surface_exists() -> None:
    browser = _CountingBrowser(prefilter_count=0)

    detection = detect_challenge_for_reads(browser)

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE
    assert len(browser.locator_selectors) == 1


def test_read_detector_runs_the_full_sweep_when_the_prefilter_matches() -> None:
    browser = _CountingBrowser(prefilter_count=3)

    detection = detect_challenge_for_reads(browser)

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE
    assert len(browser.locator_selectors) > 1


def test_auth_detector_never_prefilters_the_native_sweep() -> None:
    browser = _CountingBrowser(prefilter_count=0)

    detection = detect_challenge(browser)

    assert detection.vendor is ChallengeVendor.NONE
    assert detection.state is ChallengeState.NONE
    assert len(browser.locator_selectors) > 1
