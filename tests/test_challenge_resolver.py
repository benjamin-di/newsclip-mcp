from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from newsclip.acquisition import ChallengeMode
from newsclip.challenge_detection import (
    DETECTION_SCRIPT,
    ChallengeDetectionError,
    detect_challenge,
)
from newsclip.challenge_resolver import (
    ChallengeBlockReason,
    ChallengeResolutionStatus,
    ChallengeResolver,
    StableSurfaceClearProbe,
)
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeAcceptanceSource,
    ChallengeDetection,
    ChallengeInfrastructureError,
    ChallengeMechanicError,
    ChallengeState,
    ChallengeVendor,
)


class Browser:
    def __init__(self) -> None:
        self.clear = False


class Mechanic:
    vendor = ChallengeVendor.DATADOME

    def __init__(self, action: Callable[[object, ChallengeAcceptanceProbe], None]):
        self._action = action
        self.calls = 0

    def solve(
        self, browser: object, acceptance: ChallengeAcceptanceProbe
    ) -> ChallengeAcceptance:
        self.calls += 1
        self._action(browser, acceptance)
        return acceptance.observe()


class AcceptedProbe:
    def observe(self) -> ChallengeAcceptance:
        return ChallengeAcceptance(
            accepted=True,
            source=ChallengeAcceptanceSource.EXISTING_FORM_FIELD,
        )


def detection(vendor: ChallengeVendor, state: ChallengeState) -> ChallengeDetection:
    return ChallengeDetection(vendor=vendor, state=state)


def test_detection_rejects_malformed_or_incoherent_results() -> None:
    class RawBrowser:
        def __init__(self, raw: object) -> None:
            self.raw = raw

        def evaluate(self, script: str) -> object:
            assert "recaptchaInteractive" in script
            assert "turnstileInteractive" in script
            assert "cloudflareInterstitial" in script
            assert "verify you are human" in script
            return self.raw

    with pytest.raises(ChallengeDetectionError):
        detect_challenge(RawBrowser(None))
    with pytest.raises(ChallengeDetectionError):
        detect_challenge(RawBrowser({"vendor": "none", "state": "interactive"}))
    with pytest.raises(ValidationError):
        detection(ChallengeVendor.DATADOME, ChallengeState.NONE)


def test_detector_evaluation_failure_is_challenge_infrastructure() -> None:
    class FailingBrowser:
        def evaluate(self, script: str) -> object:
            raise RuntimeError("fixture execution context disappeared")

    with pytest.raises(
        ChallengeInfrastructureError, match="detector evaluation"
    ) as caught:
        detect_challenge(FailingBrowser())

    assert isinstance(caught.value, ChallengeDetectionError)


def test_interactive_surfaces_take_precedence_over_stale_solved_markers() -> None:
    assert DETECTION_SCRIPT.index("if (hcaptchaInteractive)") < DETECTION_SCRIPT.index(
        "if (hcaptchaSolved)"
    )
    assert DETECTION_SCRIPT.index("if (turnstileInteractive)") < (
        DETECTION_SCRIPT.index("if (hcaptchaSolved)")
    )
    assert DETECTION_SCRIPT.index("if (cloudflareInterstitial)") < (
        DETECTION_SCRIPT.index("if (turnstileInteractive)")
    )


@pytest.mark.parametrize(
    "vendor", [ChallengeVendor.RECAPTCHA, ChallengeVendor.TURNSTILE]
)
def test_detector_preserves_known_unsupported_vendor_identity(
    vendor: ChallengeVendor,
) -> None:
    class RawBrowser:
        def evaluate(self, script: str) -> object:
            return {"vendor": vendor.value, "state": "interactive"}

    assert detect_challenge(RawBrowser()).vendor is vendor


@pytest.mark.parametrize(
    ("visible_selector", "vendor"),
    (
        (
            'iframe[src*="hcaptcha.com"][src*="frame=challenge"]',
            ChallengeVendor.HCAPTCHA,
        ),
        ('iframe[src*="captcha-delivery"]', ChallengeVendor.DATADOME),
        ("#px-captcha", ChallengeVendor.PERIMETERX),
        ('.g-recaptcha:not([data-size="invisible"])', ChallengeVendor.RECAPTCHA),
        (".cf-turnstile", ChallengeVendor.TURNSTILE),
        ('[data-visible-challenge="true"]', ChallengeVendor.UNSUPPORTED),
    ),
)
def test_native_locator_fallback_preserves_vendor_identity(
    visible_selector: str,
    vendor: ChallengeVendor,
) -> None:
    class Locator:
        def __init__(self, visible: bool) -> None:
            self.visible = visible

        def count(self) -> int:
            return int(self.visible)

        def nth(self, index: int) -> Locator:
            assert index == 0
            return self

        def is_visible(self) -> bool:
            return self.visible

        def bounding_box(self) -> dict[str, float] | None:
            if not self.visible:
                return None
            return {"x": 10, "y": 10, "width": 100, "height": 100}

    class Page:
        def locator(self, selector: str) -> Locator:
            return Locator(selector == visible_selector)

        def evaluate(self, script: str) -> dict[str, float]:
            return {"width": 1280, "height": 800}

    class BrowserWithNativeSurface:
        page = Page()

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

    result = detect_challenge(BrowserWithNativeSurface())

    assert result.vendor is vendor
    assert result.state is ChallengeState.INTERACTIVE


def test_native_locator_failure_is_never_reclassified_as_no_challenge() -> None:
    class BrokenPage:
        def locator(self, selector: str) -> object:
            raise RuntimeError("fixture locator failure")

    class BrowserWithBrokenFallback:
        page = BrokenPage()

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

    with pytest.raises(ChallengeDetectionError, match="native-locator"):
        detect_challenge(BrowserWithBrokenFallback())


def test_native_locator_context_replacement_retries_passive_detection() -> None:
    class Page:
        def __init__(self) -> None:
            self.calls = 0

        def locator(self, selector: str) -> object:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("Execution context was destroyed during navigation")
            return Locator()

    class Locator:
        def count(self) -> int:
            return 0

    class NavigatingBrowser:
        def __init__(self) -> None:
            self.page = Page()
            self.evaluations = 0

        def evaluate(self, script: str) -> object:
            self.evaluations += 1
            return {"vendor": "none", "state": "none"}

    browser = NavigatingBrowser()

    result = detect_challenge(browser)

    assert result == detection(ChallengeVendor.NONE, ChallengeState.NONE)
    assert browser.evaluations == 2


def test_detect_only_never_invokes_a_mechanic() -> None:
    mechanic = Mechanic(lambda browser, acceptance: None)
    resolver = ChallengeResolver(
        {ChallengeVendor.DATADOME: mechanic},
        detector=lambda browser: detection(
            ChallengeVendor.DATADOME, ChallengeState.INTERACTIVE
        ),
    )

    result = resolver.resolve(Browser(), ChallengeMode.DETECT_ONLY)

    assert result.status is ChallengeResolutionStatus.BLOCKED
    assert result.reason is ChallengeBlockReason.DETECT_ONLY
    assert mechanic.calls == 0


def test_resolver_requires_stable_clearance_and_rechecks_after_mechanic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = Browser()
    now = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.resolver.time.monotonic", lambda: now[0]
    )

    def detector(raw_browser: object) -> ChallengeDetection:
        assert isinstance(raw_browser, Browser)
        if raw_browser.clear:
            return detection(ChallengeVendor.NONE, ChallengeState.NONE)
        return detection(ChallengeVendor.DATADOME, ChallengeState.INTERACTIVE)

    def clear(raw_browser: object, acceptance: ChallengeAcceptanceProbe) -> None:
        assert isinstance(raw_browser, Browser)
        raw_browser.clear = True
        assert acceptance.observe().accepted is False
        now[0] = 0.5

    mechanic = Mechanic(clear)
    resolver = ChallengeResolver(
        {ChallengeVendor.DATADOME: mechanic}, detector=detector
    )

    result = resolver.resolve(browser, ChallengeMode.AUTO)

    assert result.status is ChallengeResolutionStatus.CLEARED
    assert result.acceptance is not None and result.acceptance.accepted
    assert result.acceptance.source is ChallengeAcceptanceSource.SURFACE_CLEAR


def test_surface_clear_requires_time_and_resets_on_detector_disagreement() -> None:
    browser = Browser()
    browser.clear = True
    now = [0.0]

    def detector(raw_browser: object) -> ChallengeDetection:
        assert isinstance(raw_browser, Browser)
        if raw_browser.clear:
            return detection(ChallengeVendor.NONE, ChallengeState.NONE)
        return detection(ChallengeVendor.RECAPTCHA, ChallengeState.INTERACTIVE)

    probe = StableSurfaceClearProbe(
        browser,
        ChallengeVendor.DATADOME,
        detector=detector,
        clock=lambda: now[0],
    )

    assert probe.observe().accepted is False
    assert probe.observe().accepted is False
    now[0] = 0.49
    assert probe.observe().accepted is False
    now[0] = 0.5
    assert probe.observe().accepted is True

    browser.clear = False
    assert probe.observe().accepted is False
    browser.clear = True
    now[0] = 1.0
    assert probe.observe().accepted is False


@pytest.mark.parametrize(
    "vendor,state",
    [
        (ChallengeVendor.DATADOME, ChallengeState.ASSET_ONLY),
        (ChallengeVendor.RECAPTCHA, ChallengeState.ASSET_ONLY),
        (ChallengeVendor.HCAPTCHA, ChallengeState.SOLVED),
    ],
)
def test_stable_clearance_accepts_another_vendors_noninteractive_assets(
    vendor: ChallengeVendor, state: ChallengeState
) -> None:
    now = [0.0]
    probe = StableSurfaceClearProbe(
        Browser(),
        ChallengeVendor.CLOUDFLARE_INTERSTITIAL,
        detector=lambda _: detection(vendor, state),
        clock=lambda: now[0],
    )
    assert not probe.observe().accepted
    now[0] = 0.49
    assert not probe.observe().accepted
    now[0] = 0.5
    assert probe.observe().accepted


def test_unknown_passive_vendor_is_not_clearance_proof() -> None:
    now = [0.0]
    probe = StableSurfaceClearProbe(
        Browser(),
        ChallengeVendor.CLOUDFLARE_INTERSTITIAL,
        detector=lambda _: detection(
            ChallengeVendor.UNSUPPORTED, ChallengeState.ASSET_ONLY
        ),
        clock=lambda: now[0],
    )
    assert not probe.observe().accepted
    now[0] = 1
    assert not probe.observe().accepted


@pytest.mark.parametrize("duration", [0.0, -1.0, float("inf"), float("nan"), 5.1])
def test_surface_clear_rejects_invalid_stability_windows(duration: float) -> None:
    with pytest.raises(ValueError, match="duration"):
        StableSurfaceClearProbe(
            Browser(),
            ChallengeVendor.DATADOME,
            minimum_clear_seconds=duration,
        )


def test_resolver_rejects_unconfirmed_or_unconfigured_interactive_challenges() -> None:
    interactive = lambda browser: detection(  # noqa: E731
        ChallengeVendor.DATADOME, ChallengeState.INTERACTIVE
    )
    mechanic = Mechanic(lambda browser, acceptance: None)
    result = ChallengeResolver(
        {ChallengeVendor.DATADOME: mechanic}, detector=interactive
    ).resolve(Browser(), ChallengeMode.AUTO)
    unsupported = ChallengeResolver(
        {},
        detector=lambda browser: detection(
            ChallengeVendor.RECAPTCHA, ChallengeState.INTERACTIVE
        ),
    ).resolve(Browser(), ChallengeMode.AUTO)

    assert result.reason is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
    assert unsupported.reason is ChallengeBlockReason.UNSUPPORTED


def test_resolver_distinguishes_mechanic_and_infrastructure_failures() -> None:
    interactive = lambda browser: detection(  # noqa: E731
        ChallengeVendor.DATADOME, ChallengeState.INTERACTIVE
    )

    def mechanic_failure(*_args: object) -> None:
        raise ChallengeMechanicError("bounded solve failed")

    failed = ChallengeResolver(
        {ChallengeVendor.DATADOME: Mechanic(mechanic_failure)},
        detector=interactive,
    ).resolve(Browser(), ChallengeMode.AUTO)

    def infrastructure_failure(*_args: object) -> None:
        raise ChallengeInfrastructureError("planner unavailable")

    with pytest.raises(ChallengeInfrastructureError, match="planner unavailable"):
        ChallengeResolver(
            {ChallengeVendor.DATADOME: Mechanic(infrastructure_failure)},
            detector=interactive,
        ).resolve(Browser(), ChallengeMode.AUTO)

    assert failed.reason is ChallengeBlockReason.MECHANIC_FAILED


def test_resolver_normalizes_unexpected_detector_and_mechanic_failures() -> None:
    def broken_detector(browser: object) -> ChallengeDetection:
        raise RuntimeError("fixture detector failure")

    with pytest.raises(ChallengeInfrastructureError, match="detection failed"):
        ChallengeResolver({}, detector=broken_detector).resolve(
            Browser(), ChallengeMode.AUTO
        )

    with pytest.raises(ChallengeInfrastructureError, match="detection failed"):
        ChallengeResolver(
            {},
            detector=lambda browser: {"vendor": "none", "state": "none"},  # type: ignore[arg-type,return-value]
        ).resolve(Browser(), ChallengeMode.AUTO)

    def broken_mechanic(*_args: object) -> None:
        raise RuntimeError("fixture browser failure")

    with pytest.raises(ChallengeInfrastructureError, match="operationally"):
        ChallengeResolver(
            {ChallengeVendor.DATADOME: Mechanic(broken_mechanic)},
            detector=lambda browser: detection(
                ChallengeVendor.DATADOME, ChallengeState.INTERACTIVE
            ),
        ).resolve(Browser(), ChallengeMode.AUTO)


@pytest.mark.parametrize(
    ("vendor", "state"),
    [
        (ChallengeVendor.NONE, ChallengeState.NONE),
        (ChallengeVendor.HCAPTCHA, ChallengeState.INTERACTIVE),
    ],
)
def test_resolver_normalizes_acceptance_probe_failures(
    vendor: ChallengeVendor,
    state: ChallengeState,
) -> None:
    class FailingProbe:
        def observe(self) -> ChallengeAcceptance:
            raise RuntimeError("fixture probe failure")

    with pytest.raises(ChallengeInfrastructureError, match="acceptance probe"):
        ChallengeResolver(
            {}, detector=lambda browser: detection(vendor, state)
        ).resolve(Browser(), ChallengeMode.AUTO, acceptance=FailingProbe())


def test_resolver_rejects_an_acceptance_probe_returning_the_wrong_type() -> None:
    class MalformedProbe:
        def observe(self) -> ChallengeAcceptance:
            return {"accepted": True, "source": "existing_form_field"}  # type: ignore[return-value]

    with pytest.raises(ChallengeInfrastructureError, match="acceptance probe"):
        ChallengeResolver(
            {},
            detector=lambda browser: detection(
                ChallengeVendor.NONE, ChallengeState.NONE
            ),
        ).resolve(Browser(), ChallengeMode.AUTO, acceptance=MalformedProbe())


def test_passive_result_can_carry_provider_native_acceptance() -> None:
    resolver = ChallengeResolver(
        {},
        detector=lambda browser: detection(ChallengeVendor.NONE, ChallengeState.NONE),
    )

    result = resolver.resolve(Browser(), ChallengeMode.AUTO, acceptance=AcceptedProbe())

    assert result.status is ChallengeResolutionStatus.NOT_PRESENT
    assert result.allows_continuation
    assert result.acceptance is not None and result.acceptance.accepted


def test_native_acceptance_needs_no_mechanic_even_in_detect_only_mode() -> None:
    resolver = ChallengeResolver(
        {},
        detector=lambda browser: detection(
            ChallengeVendor.HCAPTCHA, ChallengeState.INTERACTIVE
        ),
    )

    result = resolver.resolve(
        Browser(), ChallengeMode.DETECT_ONLY, acceptance=AcceptedProbe()
    )

    assert result.status is ChallengeResolutionStatus.CLEARED
    assert result.acceptance is not None and result.acceptance.accepted


def test_native_acceptance_cannot_clear_a_different_vendor() -> None:
    resolver = ChallengeResolver(
        {},
        detector=lambda browser: detection(
            ChallengeVendor.RECAPTCHA, ChallengeState.INTERACTIVE
        ),
    )

    result = resolver.resolve(
        Browser(),
        ChallengeMode.AUTO,
        acceptance=AcceptedProbe(),
        acceptance_vendor=ChallengeVendor.HCAPTCHA,
    )

    assert result.status is ChallengeResolutionStatus.BLOCKED
    assert result.reason is ChallengeBlockReason.UNSUPPORTED


def test_resolver_rejects_misbound_mechanics() -> None:
    with pytest.raises(ValueError, match="wrong vendor"):
        ChallengeResolver({ChallengeVendor.HCAPTCHA: Mechanic(lambda *_: None)})
