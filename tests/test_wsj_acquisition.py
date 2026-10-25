from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from patchright.sync_api import TimeoutError as PatchrightTimeoutError

from newsclip.acquisition import (
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    ChallengeMode,
    MintFailureCategory,
    MintFailureStage,
)
from newsclip.browser_runtime import MouseTarget, ObservedNavigation, PasskeyMode
from newsclip.challenge_resolver import ChallengeResolver, StableSurfaceClearProbe
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeInfrastructureError,
    ChallengeVendor,
)
from newsclip.datadome import DataDomeSliderMechanic
from newsclip.login import LoginInfrastructureError
from newsclip.models import MintOutcome
from newsclip.provider_config import load_provider_spec
from newsclip.providers.wsj import WSJLoginRecipe
from newsclip.providers.wsj_auth import WSJAcquisitionAdapter
from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()
ARTICLE_URL = "https://www.wsj.com/finance/fixture-story-1a2b3c4d"
FIXTURES = Path(__file__).parent / "fixtures" / "wsj"


class FakeSecrets:
    def __init__(self) -> None:
        self.fields: list[str] = []

    def fill(self, browser, *, field: str, **kwargs) -> None:
        self.fields.append(field)


class UnavailableSecrets(FakeSecrets):
    def fill(self, browser, *, field: str, **kwargs) -> None:
        raise LoginInfrastructureError("fixture unavailable")


class FakeDataDome:
    vendor = ChallengeVendor.DATADOME

    def __init__(
        self,
        *,
        accepted: bool = True,
        settle: Callable[[], None] | None = None,
    ) -> None:
        self.accepted = accepted
        self._settle = settle if settle is not None else lambda: None
        self.calls = 0

    def solve(self, browser, acceptance) -> ChallengeAcceptance:
        self.calls += 1
        if self.accepted:
            browser.challenge_vendor = "none"
            browser.challenge_state = "none"
            acceptance.observe()
            self._settle()
        return acceptance.observe()


class UnavailableDataDome:
    vendor = ChallengeVendor.DATADOME

    def solve(self, browser, acceptance) -> ChallengeAcceptance:  # noqa: ARG002
        raise ChallengeInfrastructureError("fixture dependency unavailable")


class NullLocator:
    def count(self) -> int:
        return 0


class FakePage:
    frames: list[object] = []

    def __init__(self, html: str) -> None:
        self._html = html
        self.url = "about:blank"

    def content(self) -> str:
        return self._html

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class FakeBrowser:
    def __init__(
        self,
        observations: list[dict[str, bool]],
        *,
        cookies: list[dict[str, object]] | None = None,
        challenge_vendor: str = "none",
        challenge_state: str = "none",
        challenge_on_navigate: bool = False,
        consent_results: list[bool] | None = None,
        cookie_snapshots: list[list[dict[str, object]]] | None = None,
        article_html: str | None = None,
    ) -> None:
        self.observations = list(observations)
        self.last = observations[-1] if observations else {}
        self.cookie_values = list(cookies or [])
        self.cookie_snapshots = [
            list(snapshot) for snapshot in (cookie_snapshots or [])
        ]
        self.page = FakePage(
            article_html
            if article_html is not None
            else (FIXTURES / "verification_full.html").read_text(encoding="utf-8")
        )
        self.challenge_vendor = challenge_vendor
        self.challenge_state = challenge_state
        self.challenge_on_navigate = challenge_on_navigate
        self.consent_results = list(consent_results or [])
        self.actions: list[str] = []
        self.waits: list[float] = []
        self.current_url = "about:blank"

    def navigate(self, url: str) -> None:
        self.actions.append("navigate")
        self.current_url = url
        self.page.url = url
        if self.challenge_on_navigate:
            self.challenge_vendor = "datadome"
            self.challenge_state = "interactive"

    def navigate_observed(
        self,
        url: str,
        *,
        timeout_seconds: float,
    ) -> ObservedNavigation:
        assert timeout_seconds == 30
        self.navigate(url)
        return ObservedNavigation(200, url, "text/html")

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        assert mode is PasskeyMode.EMPTY_PRESENT
        self.actions.append("passkeys")
        return True

    def click_optional(self, selectors) -> bool:
        return self.consent_results.pop(0) if self.consent_results else False

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)

    def evaluate(self, script: str):
        if "datadomeAsset" in script:
            return {
                "vendor": self.challenge_vendor,
                "state": self.challenge_state,
            }
        if self.observations:
            self.last = self.observations.pop(0)
        return self.last

    def cookies(self) -> list[dict[str, object]]:
        if self.cookie_snapshots:
            self.cookie_values = self.cookie_snapshots.pop(0)
        return list(self.cookie_values)

    def user_agent(self) -> str:
        return "FixtureBrowser/1.0"

    def mouse_target(self, selectors) -> MouseTarget:
        self.actions.append("geometry")
        return MouseTarget(5, 5)

    def mouse_click(self, target: MouseTarget) -> None:
        self.actions.append("mouse")


def _cookie() -> dict[str, object]:
    return {
        "name": "djcs_session",
        "value": "SESSION_VALUE",
        "domain": ".wsj.com",
        "path": "/",
        "expires": FUTURE,
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
    }


def _dowjones_cookie() -> dict[str, object]:
    return {
        **_cookie(),
        "name": "djcs_handoff",
        "domain": ".dowjones.com",
    }


def _adapter(
    tmp_path: Path,
    *,
    secrets: FakeSecrets | None = None,
    datadome: FakeDataDome | None = None,
) -> WSJAcquisitionAdapter:
    return WSJAcquisitionAdapter(
        recipe=WSJLoginRecipe(verification_url=ARTICLE_URL),
        secrets=secrets,
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.DATADOME: datadome} if datadome is not None else {}
        ),
        clock=lambda: NOW,
    )


@pytest.mark.parametrize(
    ("error_type", "outcome", "category"),
    (
        (
            SessionCookiesMissing,
            MintOutcome.UNKNOWN_FLOW,
            MintFailureCategory.SESSION_MISSING,
        ),
        (
            SessionCookieFormatError,
            MintOutcome.INFRASTRUCTURE_ERROR,
            MintFailureCategory.INFRASTRUCTURE,
        ),
    ),
)
def test_wsj_cookie_export_failures_have_stable_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[SessionCookieError],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise error_type("fixture cookie failure")

    monkeypatch.setattr(
        "newsclip.providers.wsj_auth.normalize_browser_cookie_export", fail
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._candidate(
            FakeBrowser([{"authenticated": True}], cookies=[_cookie()]),
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is category


@pytest.mark.parametrize(
    "defect", ("missing_control", "unknown_observation", "cookie_proof")
)
def test_wsj_auth_surface_contract_is_owned_by_wsj(defect: str, tmp_path: Path) -> None:
    spec = load_provider_spec("wsj")
    auth = spec.require_auth()
    session = spec.require_session()
    if defect == "missing_control":
        controls = dict(auth.controls)
        controls.pop("password")
        auth = auth.model_copy(update={"controls": controls})
    elif defect == "unknown_observation":
        observations = dict(auth.observations)
        observations["provider_private_state"] = next(iter(observations.values()))
        auth = auth.model_copy(update={"observations": observations})
    else:
        session = session.model_copy(update={"session_cookie_name_prefixes": ()})
    selected = spec.model_copy(update={"auth": auth, "session": session})

    with pytest.raises(ValueError, match="authentication|cookie"):
        WSJAcquisitionAdapter(
            recipe=WSJLoginRecipe(verification_url=ARTICLE_URL),
            challenge_resolver=ChallengeResolver({}),
            spec=selected,
        )


def test_wsj_retained_profile_rehydrates_without_secrets(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser([{"authenticated": True}], cookies=[_cookie()])

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert candidate.candidate_verification_mode is (
        CandidateVerificationMode.BROWSER_PAID_PROBE
    )
    assert candidate.evidence.session_proof_observed is False
    assert candidate.verification_fetch is not None
    assert candidate.artifact.user_agent == "FixtureBrowser/1.0"
    assert secrets.fields == []
    assert browser.actions == ["navigate", "passkeys", "navigate"]


def test_wsj_rehydrate_waits_for_delayed_auth0_controls(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {},
            {},
            {"username_visible": True},
        ]
    )

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is None
    assert secrets.fields == []
    assert browser.waits[-2:] == [0.25, 0.25]


def test_wsj_entry_preserves_late_consent_settle(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [{"username_visible": True}],
        consent_results=[False, True],
    )

    candidate = _adapter(tmp_path).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is None
    assert browser.waits == [0.25, 0.5]


def test_wsj_rehydrate_readiness_timeout_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(
        "newsclip.providers.wsj_auth.time.monotonic",
        lambda: next(ticks),
    )
    browser = FakeBrowser([{}, {}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path).rehydrate_profile(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.PROFILE
    assert caught.value.evidence.category is MintFailureCategory.TIMEOUT
    assert browser.waits[-1] == 0.25


def test_wsj_direct_mint_waits_for_delayed_auth0_controls(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {},
            {},
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert secrets.fields == ["username", "password"]
    assert browser.actions[:2] == ["navigate", "passkeys"]


def test_wsj_maps_challenge_infrastructure_to_retryable_failure(
    tmp_path: Path,
) -> None:
    browser = FakeBrowser(
        [],
        challenge_vendor="datadome",
        challenge_state="interactive",
    )
    adapter = WSJAcquisitionAdapter(
        recipe=WSJLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.DATADOME: UnavailableDataDome()}
        ),
        clock=lambda: NOW,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter._resolve_challenge(browser, ChallengeMode.AUTO)

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE


def test_wsj_form_wins_over_retained_cookie(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [{"password_visible": True, "authenticated": True}],
        cookies=[_cookie()],
    )

    assert (
        _adapter(tmp_path).rehydrate_profile(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )
        is None
    )


def test_wsj_credentials_use_mouse_and_observed_mode(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert secrets.fields == ["username", "password"]
    assert browser.actions == ["geometry", "mouse", "geometry", "mouse", "navigate"]


def test_wsj_callback_waits_for_provider_cookie(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookie_snapshots=[
            [
                {
                    **_cookie(),
                    "name": "consent",
                }
            ],
            [_cookie()],
        ],
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert secrets.fields == ["username", "password"]
    assert browser.waits.count(0.25) >= 3


def test_wsj_artifact_preserves_dowjones_handoff_cookie(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_cookie(), _dowjones_cookie()],
    )

    candidate = _adapter(tmp_path, secrets=FakeSecrets()).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert {cookie.domain for cookie in candidate.artifact.cookies} == {
        ".wsj.com",
        ".dowjones.com",
    }


def test_wsj_paid_probe_context_handles_datadome_before_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.resolver.time.monotonic", lambda: now[0]
    )
    datadome = FakeDataDome(settle=lambda: now.__setitem__(0, 0.5))
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
        challenge_on_navigate=True,
    )

    candidate = _adapter(
        tmp_path, secrets=FakeSecrets(), datadome=datadome
    ).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert datadome.calls == 1


class TimedOutNavigationBrowser(FakeBrowser):
    def __init__(self, *args, committed: bool, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.committed = committed

    def navigate(self, url: str) -> None:
        self.actions.append("navigate")
        self.current_url = (
            url if self.committed else "https://sso.accounts.dowjones.com/u/login"
        )
        self.page.url = self.current_url
        raise PatchrightTimeoutError("fixture navigation timeout")


def test_wsj_paid_probe_rejects_timeout_without_observed_response(
    tmp_path: Path,
) -> None:
    browser = TimedOutNavigationBrowser(
        [{"authenticated": True}],
        committed=True,
    )

    with pytest.raises(PatchrightTimeoutError):
        _adapter(tmp_path)._settle_verification_context(
            browser,
            ChallengeMode.DETECT_ONLY,
        )

    assert browser.actions == ["navigate"]
    assert browser.waits == []


def test_wsj_paid_probe_requires_full_article_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(
        "newsclip.providers.wsj_auth.time.monotonic",
        lambda: next(ticks),
    )
    browser = FakeBrowser(
        [{"authenticated": True}],
        article_html=(FIXTURES / "initial_excerpt.html").read_text(encoding="utf-8"),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._settle_verification_context(
            browser,
            ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL
    assert browser.actions == ["navigate", "navigate"]


def test_wsj_paid_probe_uses_observed_non_success_status(tmp_path: Path) -> None:
    browser = FakeBrowser([{"authenticated": True}])
    browser.current_url = ARTICLE_URL
    browser.page.url = ARTICLE_URL

    adapter = _adapter(tmp_path)
    fetch = adapter._browser_article_fetch(
        browser,
        ObservedNavigation(403, ARTICLE_URL, "text/html"),
    )

    assert fetch.http_status == 403
    assert not adapter._recipe.verify_fetch(fetch).verified


def test_wsj_paid_probe_propagates_off_target_navigation_timeout(
    tmp_path: Path,
) -> None:
    browser = TimedOutNavigationBrowser(
        [{"authenticated": True}],
        committed=False,
    )

    with pytest.raises(PatchrightTimeoutError):
        _adapter(tmp_path)._settle_verification_context(
            browser,
            ChallengeMode.DETECT_ONLY,
        )


def test_wsj_paid_probe_context_detect_only_stops_on_datadome(
    tmp_path: Path,
) -> None:
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
        challenge_on_navigate=True,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=FakeSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.CHALLENGE_BLOCKED


def test_wsj_secret_delivery_failure_is_distinct(tmp_path: Path) -> None:
    browser = FakeBrowser([{"username_visible": True}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=UnavailableSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.SECRET_DELIVERY_FAILED


def test_wsj_blocks_an_unconfigured_captcha_vendor_before_credentials(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [{"username_visible": True}],
        challenge_vendor="recaptcha",
        challenge_state="interactive",
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert secrets.fields == []


def test_wsj_datadome_runs_only_in_auto_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.resolver.time.monotonic", lambda: now[0]
    )
    datadome = FakeDataDome(settle=lambda: now.__setitem__(0, 0.5))
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
        challenge_vendor="datadome",
        challenge_state="interactive",
    )

    candidate = _adapter(
        tmp_path, secrets=FakeSecrets(), datadome=datadome
    ).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert datadome.calls == 1


class SliderLocator:
    def __init__(
        self,
        box: dict[str, float] | None,
        *,
        visible: bool = True,
    ) -> None:
        self.box = box
        self.visible = visible

    def count(self) -> int:
        return 1

    def nth(self, index: int) -> SliderLocator:
        return self

    def is_visible(self) -> bool:
        return self.visible

    def bounding_box(self) -> dict[str, float] | None:
        return self.box


class SliderFrame:
    def __init__(
        self,
        *,
        url: str = "https://geo.captcha-delivery.com/captcha/",
        visible: bool = True,
        x: float = 10,
    ) -> None:
        self.url = url
        self.visible = visible
        self.x = x

    def locator(self, selector: str) -> SliderLocator:
        if "Container" in selector or selector == ".sliderbg":
            return SliderLocator(
                {"x": self.x, "y": 10, "width": 300, "height": 40},
                visible=self.visible,
            )
        return SliderLocator(
            {"x": self.x, "y": 10, "width": 40, "height": 40},
            visible=self.visible,
        )


class SliderMouse:
    def __init__(self, page) -> None:
        self.page = page
        self.down_calls = 0
        self.up_calls = 0
        self.moves: list[tuple[float, float, int]] = []

    def move(self, x: float, y: float, *, steps: int) -> None:
        self.moves.append((x, y, steps))

    def down(self) -> None:
        self.down_calls += 1

    def up(self) -> None:
        self.up_calls += 1
        self.page.frames = []


class SliderPage:
    def __init__(self) -> None:
        self.frames = [SliderFrame()]
        self.mouse = SliderMouse(self)

    def wait_for_timeout(self, milliseconds: float) -> None: ...

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


def test_datadome_mechanic_is_bounded_mouse_only() -> None:
    page = SliderPage()

    class SliderBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            if self.page.frames:
                return {"vendor": "datadome", "state": "interactive"}
            return {"vendor": "datadome", "state": "asset_only"}

    browser = SliderBrowser()
    mechanic = DataDomeSliderMechanic(
        wall_budget_seconds=10,
        max_drags=1,
        sleep=lambda _seconds: None,
    )

    result = mechanic.solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.DATADOME,
            clock=itertools.count(step=0.25).__next__,
        ),
    )

    assert result.accepted is True
    assert page.mouse.down_calls == 1
    assert page.mouse.up_calls == 1


def test_datadome_skips_detached_hidden_and_lookalike_frames() -> None:
    class DetachedFrame:
        url = "https://detached.captcha-delivery.com/captcha/"

        def locator(self, selector: str) -> SliderLocator:
            raise RuntimeError("fixture frame detached")

    class GeometrylessFrame(SliderFrame):
        def locator(self, selector: str) -> SliderLocator:
            return SliderLocator(None)

    page = SliderPage()
    page.frames = [
        DetachedFrame(),
        GeometrylessFrame(),
        SliderFrame(visible=False),
        SliderFrame(url="https://captcha-delivery.com.evil.test/captcha/", x=50),
        SliderFrame(url="https://visible.captcha-delivery.com/captcha/", x=100),
    ]

    class SliderBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            if self.page.frames:
                return {"vendor": "datadome", "state": "interactive"}
            return {"vendor": "datadome", "state": "asset_only"}

    browser = SliderBrowser()
    result = DataDomeSliderMechanic(
        wall_budget_seconds=10,
        max_drags=1,
        sleep=lambda _seconds: None,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.DATADOME,
            clock=itertools.count(step=0.25).__next__,
        ),
    )

    assert result.accepted is True
    assert page.mouse.down_calls == 1
    assert page.mouse.moves[0] == (120.0, 30.0, 8)


def test_datadome_does_not_call_an_unhydrated_interactive_wall_clear() -> None:
    class WaitingPage:
        frames: list[object] = []
        mouse = SliderMouse(None)

        def wait_for_timeout(self, milliseconds: float) -> None: ...

    class WaitingBrowser:
        page = WaitingPage()

        def evaluate(self, script: str):
            return {"vendor": "datadome", "state": "interactive"}

    ticks = iter((0.0, 0.1, 0.6, 1.1))
    mechanic = DataDomeSliderMechanic(
        wall_budget_seconds=1,
        max_drags=1,
        clock=lambda: next(ticks),
        sleep=lambda _seconds: None,
    )

    browser = WaitingBrowser()
    result = mechanic.solve(
        browser,
        StableSurfaceClearProbe(browser, ChallengeVendor.DATADOME),
    )

    assert result.accepted is False


def test_passive_datadome_fails_closed_on_a_slider_without_input() -> None:
    page = SliderPage()

    class SliderBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            return {"vendor": "datadome", "state": "interactive"}

    browser = SliderBrowser()
    ticks = itertools.count(step=0.25)
    result = DataDomeSliderMechanic(
        wall_budget_seconds=15,
        max_drags=0,
        clock=ticks.__next__,
        sleep=lambda _seconds: None,
    ).solve(browser, StableSurfaceClearProbe(browser, ChallengeVendor.DATADOME))

    assert result.accepted is False
    assert page.mouse.down_calls == 0
    assert page.mouse.moves == []
    # It stops at the first slider rather than waiting out the budget.
    assert next(ticks) < 2


def test_passive_datadome_awaits_a_device_check_that_clears_itself() -> None:
    class DeviceCheckPage:
        frames: list[object] = []
        mouse = SliderMouse(None)
        waits = 0

        def wait_for_timeout(self, milliseconds: float) -> None:
            self.waits += 1

        def locator(self, selector: str) -> NullLocator:
            return NullLocator()

    page = DeviceCheckPage()

    class DeviceCheckBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            # Interactive for the first second, then the article reloads.
            if page.waits < 4:
                return {"vendor": "datadome", "state": "interactive"}
            return {"vendor": "datadome", "state": "asset_only"}

    browser = DeviceCheckBrowser()
    clock = itertools.count(step=0.25).__next__
    result = DataDomeSliderMechanic(
        wall_budget_seconds=15,
        max_drags=0,
        clock=clock,
        sleep=lambda _seconds: None,
    ).solve(
        browser,
        StableSurfaceClearProbe(browser, ChallengeVendor.DATADOME, clock=clock),
    )

    assert result.accepted is True
    assert page.mouse.down_calls == 0
