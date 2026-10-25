from __future__ import annotations

import itertools
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lxml import html

from newsclip.acquisition import (
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    ChallengeMode,
    CredentialAction,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from newsclip.browser_readiness import (
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from newsclip.browser_runtime import (
    IdentityExitReason,
    MouseTarget,
    ObservedNavigation,
    PasskeyMode,
    PatchrightMintContext,
)
from newsclip.challenge_resolver import (
    ChallengeResolutionStatus,
    ChallengeResolver,
    StableSurfaceClearProbe,
)
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeDetection,
    ChallengeInfrastructureError,
    ChallengeVendor,
)
from newsclip.identity.google import GoogleIdentityResult
from newsclip.login import LoginInfrastructureError
from newsclip.models import AccessState, MintOutcome, RawFetch
from newsclip.perimeterx import (
    PerimeterXHoldMechanic,
    _generation,
    _hold_control,
    _hold_release_signal,
    _HoldReleaseReason,
)
from newsclip.provider_config import load_provider_spec
from newsclip.providers.bloomberg import BloombergLoginRecipe
from newsclip.providers.bloomberg_auth import (
    BloombergAcquisitionAdapter,
    _BrowserPaidProof,
    _CallbackRetry,
)
from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
)
from newsclip.timing import (
    StepFinishedEvent,
    TimingOperation,
    TimingRecorder,
    TimingStep,
    TimingTransport,
    read_timing_file,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()
ARTICLE_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-16/"
    "fixture-chipmaker-beats-estimates"
)
FIXTURE = Path(__file__).parent / "fixtures/bloomberg/full.html"
FIXTURES = FIXTURE.parent


def _full_fetch() -> RawFetch:
    return RawFetch(
        requested_url=ARTICLE_URL,
        final_url=ARTICLE_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=FIXTURE.read_bytes(),
    )


def _snapshot_with_full_bootstrap(rendered_fixture: str) -> str:
    """Pair one rendered state with the same complete delivered story payload."""

    full_document = html.fromstring(FIXTURE.read_bytes())
    values = [
        " ".join(paragraph.text_content().split())
        for paragraph in full_document.xpath("//article/p")
    ]
    payload = {
        "props": {
            "pageProps": {
                "story": {
                    "seoCanonical": ARTICLE_URL,
                    "headline": "Fixture Chipmaker Beats Estimates",
                    "body": {
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "value": value}],
                            }
                            for value in values
                        ],
                    },
                }
            }
        }
    }
    rendered = html.fromstring((FIXTURES / rendered_fixture).read_bytes())
    script = html.Element("script", id="__NEXT_DATA__", type="application/json")
    script.text = json.dumps(payload)
    rendered.xpath("//head")[0].append(script)
    return html.tostring(rendered, encoding="unicode")


class FakeResponse:
    status = 200


class NullLocator:
    def count(self) -> int:
        return 0


class NullPage:
    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class NullBrowserSurface:
    page = NullPage()


class ParentPage:
    def __init__(self, url: str = "https://www.bloomberg.com/account/signin") -> None:
        self.url = url

    def is_closed(self) -> bool:
        return False

    def wait_for_timeout(self, milliseconds: float) -> None: ...

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class FullPage(ParentPage):
    frames: list[object] = []

    def goto(self, url: str, **kwargs) -> FakeResponse:
        self.url = url
        return FakeResponse()

    def content(self) -> str:
        return FIXTURE.read_text(encoding="utf-8")


class FakeBrowser:
    def __init__(self) -> None:
        self.page = FullPage("about:blank")
        self.identity_handoffs: list[dict[str, object]] = []
        self.readiness_terminals: list[dict[str, object]] = []

    def navigate(self, url: str) -> None:
        self.page.url = url

    def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
        assert timeout_seconds == 30
        self.navigate(url)

    def navigate_loaded(self, url: str, *, timeout_seconds: float) -> None:
        assert timeout_seconds == 60
        self.page.goto(url, wait_until="domcontentloaded", timeout=60_000)

    def navigate_observed(
        self,
        url: str,
        *,
        timeout_seconds: float,
    ) -> ObservedNavigation:
        assert timeout_seconds == 60
        response = self.page.goto(url, wait_until="commit", timeout=60_000)
        return ObservedNavigation(response.status, self.page.url, "text/html")

    def replace_page(self) -> None:
        self.page = FullPage("about:blank")

    def for_page(self, page: object) -> FakeBrowser:
        self.page = page  # type: ignore[assignment]
        return self

    def wait_for_visible(
        self,
        selectors: tuple[str, ...],
        *,
        timeout_seconds: float,
    ) -> bool:
        return True

    def click_optional(self, selectors: tuple[str, ...]) -> bool:
        return False

    def evaluate(self, script: str):
        return {"vendor": "none", "state": "none"}

    def wait(self, seconds: float) -> None: ...

    def cookies(self) -> list[dict[str, object]]:
        return [_cookie()]

    def user_agent(self) -> str:
        return "FixtureBrowser/1.0"

    def record_identity_handoff(self, **facts: object) -> None:
        self.identity_handoffs.append(facts)

    def record_semantic_readiness_terminal(self, **facts: object) -> None:
        self.readiness_terminals.append(facts)

    def capture_diagnostic_screenshot(
        self,
        label: str,
        *,
        timeout_ms: int,
    ) -> bool:
        return True


class FakeSecrets:
    def __init__(self) -> None:
        self.fields: list[str] = []

    def fill(self, browser, *, field: str, **kwargs) -> None:
        self.fields.append(field)


class UnavailableSecrets(FakeSecrets):
    def fill(self, browser, *, field: str, **kwargs) -> None:
        raise LoginInfrastructureError("fixture unavailable")


class UnavailablePerimeterX:
    vendor = ChallengeVendor.PERIMETERX

    def solve(self, browser, acceptance) -> ChallengeAcceptance:  # noqa: ARG002
        raise ChallengeInfrastructureError("fixture dependency unavailable")


class GooglePage:
    def __init__(self) -> None:
        self.url = "https://accounts.google.com/v3/signin/challenge"
        self.keyboard = type("Keyboard", (), {"press": lambda self, key: None})()

    def is_closed(self) -> bool:
        return False

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class GoogleBrowser:
    def __init__(
        self,
        observations: list[dict[str, bool]],
        *,
        parent: ParentPage,
        complete_after_click: int,
        challenge_vendor: str = "none",
        challenge_state: str = "none",
    ) -> None:
        self.page = GooglePage()
        self.parent = parent
        self.observations = list(observations)
        self.last = observations[-1]
        self.complete_after_click = complete_after_click
        self.challenge_vendor = challenge_vendor
        self.challenge_state = challenge_state
        self.clicks = 0
        self.targets: list[tuple[str, ...]] = []

    def evaluate(self, script: str):
        if "datadomeAsset" in script:
            return {
                "vendor": self.challenge_vendor,
                "state": self.challenge_state,
            }
        if self.observations:
            self.last = self.observations.pop(0)
        return self.last

    def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
        self.targets.append(selectors)
        return MouseTarget(10, 10)

    def mouse_click(self, target: MouseTarget) -> None:
        self.clicks += 1
        if self.clicks >= self.complete_after_click:
            self.parent.url = "https://www.bloomberg.com/markets"

    def wait(self, seconds: float) -> None: ...


def _cookie() -> dict[str, object]:
    return {
        "name": "_user-token",
        "value": "CURRENT_SESSION_VALUE",
        "domain": ".bloomberg.com",
        "path": "/",
        "expires": FUTURE,
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
    }


def _adapter(
    tmp_path: Path,
    *,
    secrets: FakeSecrets | None = None,
    perimeterx: UnavailablePerimeterX | None = None,
) -> BloombergAcquisitionAdapter:
    return BloombergAcquisitionAdapter(
        recipe=BloombergLoginRecipe(verification_url=ARTICLE_URL),
        secrets=secrets,
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.PERIMETERX: perimeterx} if perimeterx is not None else {}
        ),
        clock=lambda: NOW,
        monotonic_clock=itertools.count(step=0.1).__next__,
    )


def _cleared_callback(cleared: bool):
    """A clearance-probe result standing in for the real observation."""

    from newsclip.providers.bloomberg_auth import _CallbackClearance

    return _CallbackClearance(
        cleared=cleared,
        probe_status=404 if cleared else 403,
        clearance_cookie_present=cleared,
    )


def _google_result(
    action: CredentialAction = CredentialAction.NONE,
    *,
    exit_reason: IdentityExitReason = IdentityExitReason.IDENTITY_PAGE_CLOSED,
) -> GoogleIdentityResult:
    return GoogleIdentityResult(
        credential_action=action,
        callback_complete=False,
        identity_page_closed=False,
        exit_reason=exit_reason,
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
def test_bloomberg_cookie_export_failures_have_stable_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[SessionCookieError],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise error_type("fixture cookie failure")

    monkeypatch.setattr(
        "newsclip.providers.bloomberg_auth.normalize_browser_cookie_export", fail
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._candidate(
            FakeBrowser(),
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            callback_confirmed=True,
            verification_fetch=_full_fetch(),
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is category


@pytest.mark.parametrize(
    "defect",
    (
        "missing_control",
        "unknown_observation",
        "callback_paths",
        "post_callback_urls",
    ),
)
def test_bloomberg_auth_surface_contract_is_owned_by_bloomberg(
    defect: str, tmp_path: Path
) -> None:
    spec = load_provider_spec("bloomberg")
    auth = spec.require_auth()
    if defect == "missing_control":
        controls = dict(auth.controls)
        controls.pop("totp")
        auth = auth.model_copy(update={"controls": controls})
    elif defect == "unknown_observation":
        observations = dict(auth.observations)
        observations["provider_private_state"] = next(iter(observations.values()))
        auth = auth.model_copy(update={"observations": observations})
    elif defect == "callback_paths":
        auth = auth.model_copy(update={"auth_path_prefixes": ()})
    else:
        auth = auth.model_copy(update={"post_callback_urls": ()})
    selected = spec.model_copy(update={"auth": auth})

    with pytest.raises(ValueError, match="authentication"):
        BloombergAcquisitionAdapter(
            recipe=BloombergLoginRecipe(verification_url=ARTICLE_URL),
            challenge_resolver=ChallengeResolver({}),
            spec=selected,
        )


def test_bloomberg_profile_rehydrate_proves_full_without_secrets(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        FakeBrowser(),
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert candidate.candidate_verification_mode is (
        CandidateVerificationMode.BROWSER_PAID_PROBE
    )
    assert candidate.artifact.user_agent == "FixtureBrowser/1.0"
    assert secrets.fields == []


def test_bloomberg_profile_rehydrate_waits_for_delayed_full_dom(
    tmp_path: Path,
) -> None:
    teaser = _snapshot_with_full_bootstrap("teaser.html")
    full = _snapshot_with_full_bootstrap("full.html")

    class HydratingPage(FullPage):
        def __init__(self) -> None:
            super().__init__("about:blank")
            self.snapshots = iter((teaser, full))
            self.latest = teaser
            self.content_reads = 0

        def content(self) -> str:
            self.content_reads += 1
            self.latest = next(self.snapshots, self.latest)
            return self.latest

    class HydratingBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.page = HydratingPage()

    secrets = FakeSecrets()
    browser = HydratingBrowser()

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.verification_fetch.raw_html == full.encode()
    assert browser.page.content_reads >= 2
    assert secrets.fields == []


def test_bloomberg_paid_teaser_preserves_authority_as_inconclusive(
    tmp_path: Path,
) -> None:
    teaser = _snapshot_with_full_bootstrap("teaser.html")

    class TeaserPage(FullPage):
        def content(self) -> str:
            return teaser

    class TeaserBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.page = TeaserPage("about:blank")

    secrets = FakeSecrets()

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets).rehydrate_profile(
            TeaserBrowser(),
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL
    assert secrets.fields == []


def test_bloomberg_promotable_partial_dom_completes_paid_proof(
    tmp_path: Path,
) -> None:
    """A partly rendered but entitled article is proof, and stays cheap.

    This previously failed closed as ``paid_probe/timeout``. Requiring the DOM to
    cover the delivered story made cold minting impossible on a shape Bloomberg
    serves routinely, and on this rehydration path it discarded a usable session
    and forced an avoidable credential submission. Entitlement is still tested:
    the neighbouring teaser case pairs the same complete payload with a rendered
    teaser and is refused.
    """

    document = html.fromstring(_snapshot_with_full_bootstrap("full.html"))
    paragraphs = document.xpath("//article/p")
    paragraphs[-1].text = paragraphs[-2].text
    partial = html.tostring(document, encoding="unicode")

    class PartialPage(FullPage):
        def content(self) -> str:
            return partial

    class PartialBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.page = PartialPage("about:blank")

    secrets = FakeSecrets()
    browser = PartialBrowser()

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.verification_fetch.raw_html == partial.encode()
    assert secrets.fields == []
    assert browser.readiness_terminals[-1]["state"] is ReadinessTerminalState.STABILIZED
    assert (
        browser.readiness_terminals[-1]["coverage_bucket"]
        is ReadinessCoverageBucket.FROM_75_TO_89
    )


def test_bloomberg_full_dom_without_final_paid_cookie_is_inconclusive(
    tmp_path: Path,
) -> None:
    class ExpiringCookieBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.cookie_reads = 0

        def cookies(self) -> list[dict[str, object]]:
            self.cookie_reads += 1
            return [_cookie()] if self.cookie_reads < 3 else []

    secrets = FakeSecrets()

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets).rehydrate_profile(
            ExpiringCookieBrowser(),
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.TIMEOUT
    assert secrets.fields == []


def test_bloomberg_explicit_auth_wall_allows_credential_mint(
    tmp_path: Path,
) -> None:
    signin_url = "https://www.bloomberg.com/account/signin"

    class AuthPage(FullPage):
        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.url = signin_url
            return FakeResponse()

        def content(self) -> str:
            return (FIXTURES / "auth.html").read_text(encoding="utf-8")

    class AuthBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.page = AuthPage("about:blank")

    secrets = FakeSecrets()

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        AuthBrowser(),
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is None
    assert secrets.fields == []


def test_bloomberg_guest_profile_skips_article_probe_before_mint(
    tmp_path: Path, monkeypatch
) -> None:
    class GuestBrowser(FakeBrowser):
        def cookies(self) -> list[dict[str, object]]:
            return []

    adapter = _adapter(tmp_path)
    monkeypatch.setattr(
        adapter,
        "_browser_full_fetch",
        lambda *args, **kwargs: pytest.fail("guest profile must not probe article"),
    )

    candidate = adapter.rehydrate_profile(
        GuestBrowser(),
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is None


def test_bloomberg_maps_challenge_infrastructure_to_retryable_failure(
    tmp_path: Path,
) -> None:
    class ChallengeBrowser(FakeBrowser):
        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(
            tmp_path,
            perimeterx=UnavailablePerimeterX(),
        )._resolve_challenge(ChallengeBrowser(), ChallengeMode.AUTO)

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE


def test_bloomberg_reloads_once_after_unconfirmed_stale_challenge(
    tmp_path: Path,
) -> None:
    class StalePerimeterX:
        vendor = ChallengeVendor.PERIMETERX

        def __init__(self) -> None:
            self.calls = 0

        def solve(self, browser, acceptance) -> ChallengeAcceptance:  # noqa: ANN001
            self.calls += 1
            return acceptance.observe()

    class ReloadPage(FullPage):
        def __init__(self) -> None:
            super().__init__("about:blank")
            self.challenge = False
            self.visits: list[str] = []

        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.visits.append(url)
            self.challenge = len(self.visits) == 1
            return super().goto(url, **kwargs)

    class ReloadBrowser(FakeBrowser):
        def __init__(self) -> None:
            self.page = ReloadPage()

        def evaluate(self, script: str):
            return {
                "vendor": "perimeterx" if self.page.challenge else "none",
                "state": "interactive" if self.page.challenge else "none",
            }

    mechanic = StalePerimeterX()
    adapter = BloombergAcquisitionAdapter(
        recipe=BloombergLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({ChallengeVendor.PERIMETERX: mechanic}),
        clock=lambda: NOW,
    )
    browser = ReloadBrowser()

    verification_fetch = adapter._browser_full_fetch(browser, ChallengeMode.AUTO)

    assert verification_fetch is not None
    assert verification_fetch.http_status == 200
    assert mechanic.calls == 1
    assert browser.page.visits == [ARTICLE_URL, ARTICLE_URL]


def test_bloomberg_secret_delivery_failure_is_distinct(
    tmp_path: Path, monkeypatch
) -> None:
    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.context = Context()
            self.page = NullPage()
            self.identity_handoffs: list[dict[str, object]] = []

        def navigate_committed(self, url: str, *, timeout_seconds: float) -> None: ...

        def replace_page(self) -> None:
            self.page = NullPage()

        def for_page(self, page: object) -> PatchrightMintContext:
            return PatchrightMintContext(self.context, page)

        def wait(self, seconds: float) -> None: ...

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            pytest.fail("parent passkey suppression must not race login hydration")

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            return True

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            return False

        def record_identity_handoff(self, **facts: object) -> None:
            self.identity_handoffs.append(facts)

    adapter = _adapter(tmp_path, secrets=UnavailableSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: NullPage())

    def unavailable(*args, **kwargs):  # noqa: ANN002, ANN003
        raise LoginInfrastructureError("fixture unavailable")

    monkeypatch.setattr(adapter._google_identity, "drive", unavailable)

    browser = LoginBrowser()
    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.SECRET_DELIVERY_FAILED
    assert browser.identity_handoffs == [
        {
            "checkpoint": "identity_error",
            "credential_action": None,
            "identity_callback_complete": None,
            "identity_page_closed": None,
            "identity_exit_reason": None,
            "parent_state": "unavailable",
            "callback_confirmed": None,
            "publisher_auth_cookie_present": False,
            "challenge_cookie_present": None,
            "identity_page_state": "unavailable",
        }
    ]


@pytest.mark.parametrize("closure_point", ["navigation", "challenge", "hydration"])
def test_bloomberg_discards_warmup_page_and_recovers_closed_login_surface(
    tmp_path: Path, monkeypatch, closure_point: str
) -> None:
    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(FakeBrowser):
        def __init__(self, login_url: str) -> None:
            super().__init__()
            self.context = Context()
            self.login_url = login_url
            self.navigations: list[tuple[str, float]] = []
            self.login_attempts = 0
            self.replacements = 0
            self.visible_attempts = 0
            self.challenge_checks = 0

        def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
            self.navigations.append((url, timeout_seconds))
            if url == self.login_url:
                self.login_attempts += 1
                if closure_point == "navigation" and self.login_attempts == 1:
                    raise RuntimeError("Target closed")
            self.page.url = url

        def replace_page(self) -> None:
            self.replacements += 1
            self.page = FullPage("about:blank")

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            self.visible_attempts += 1
            if closure_point == "hydration" and self.visible_attempts == 1:
                raise RuntimeError("Target closed")
            return True

        def evaluate(self, script: str) -> object:
            self.challenge_checks += 1
            if closure_point == "challenge" and self.challenge_checks == 2:
                raise RuntimeError("Target page, context or browser has been closed")
            return {"vendor": "none", "state": "none"}

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            assert mode is PasskeyMode.NON_PRESENT
            return True

    secrets = FakeSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    browser = LoginBrowser(str(adapter._auth.login_url))
    google_drives = 0
    monkeypatch.setattr(adapter, "_open_google_popup", lambda _browser: object())

    def drive_google(*args, **kwargs):  # noqa: ANN002, ANN003
        nonlocal google_drives
        google_drives += 1
        return _google_result()

    monkeypatch.setattr(adapter._google_identity, "drive", drive_google)
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: True)
    monkeypatch.setattr(adapter, "_settle_after_google", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        adapter, "_browser_full_fetch", lambda *args, **kwargs: _full_fetch()
    )

    candidate = adapter.mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert browser.login_attempts == 2
    assert browser.replacements == 2
    assert browser.navigations == [
        ("https://www.bloomberg.com/", 30),
        (browser.login_url, 30),
        (browser.login_url, 30),
    ]
    assert google_drives == 1
    assert secrets.fields == []


@pytest.mark.parametrize("failure_point", ["replacement", "retry_navigation"])
def test_bloomberg_preflight_recovery_failure_stops_before_secrets(
    tmp_path: Path, monkeypatch, failure_point: str
) -> None:
    class LoginBrowser(FakeBrowser):
        def __init__(self, login_url: str) -> None:
            super().__init__()
            self.login_url = login_url
            self.login_attempts = 0
            self.replacements = 0

        def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
            if url == self.login_url:
                self.login_attempts += 1
                if self.login_attempts == 1:
                    raise RuntimeError("Target page has been closed")
                raise RuntimeError("replacement navigation unavailable")
            self.page.url = url

        def replace_page(self) -> None:
            self.replacements += 1
            if failure_point == "replacement" and self.replacements == 1:
                raise RuntimeError("replacement unavailable")
            self.page = FullPage("about:blank")

    secrets = FakeSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    browser = LoginBrowser(str(adapter._auth.login_url))
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: pytest.fail("credential flow must not start"),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE
    assert browser.replacements == (1 if failure_point == "replacement" else 2)
    assert browser.login_attempts == (0 if failure_point == "replacement" else 2)
    assert secrets.fields == []


def test_bloomberg_nonclosure_login_failure_does_not_replace_page(
    tmp_path: Path, monkeypatch
) -> None:
    class LoginBrowser(FakeBrowser):
        def __init__(self, login_url: str) -> None:
            super().__init__()
            self.login_url = login_url
            self.login_attempts = 0
            self.replacements = 0

        def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
            if url == self.login_url:
                self.login_attempts += 1
                raise RuntimeError("navigation unavailable")
            self.page.url = url

        def replace_page(self) -> None:
            self.replacements += 1
            if self.replacements > 1:
                pytest.fail("non-closure failure must not replace the login page")
            self.page = FullPage("about:blank")

    secrets = FakeSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    browser = LoginBrowser(str(adapter._auth.login_url))
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: pytest.fail("credential flow must not start"),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE
    assert browser.login_attempts == 1
    assert browser.replacements == 1
    assert secrets.fields == []


@pytest.mark.parametrize("timeouts", [1, 2])
def test_bloomberg_login_surface_timeout_renavigates_the_same_page_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timeouts: int,
) -> None:
    class LoginBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.login_attempts = 0
            self.replacements = 0

        def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
            self.login_attempts += 1
            self.page.url = url

        def replace_page(self) -> None:
            self.replacements += 1
            self.page = FullPage("about:blank")

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    surface_attempts = 0

    def wait_for_surface(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
        nonlocal surface_attempts
        surface_attempts += 1
        if surface_attempts <= timeouts:
            raise AcquisitionFailure(
                MintOutcome.TIMEOUT,
                MintFailureEvidence(
                    stage=MintFailureStage.CREDENTIAL,
                    category=MintFailureCategory.TIMEOUT,
                ),
            )

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    browser = LoginBrowser()
    monkeypatch.setattr(adapter, "_wait_for_google_login_surface", wait_for_surface)

    if timeouts == 2:
        with pytest.raises(AcquisitionFailure) as caught:
            adapter._prepare_google_login_surface(
                browser,
                ChallengeMode.DETECT_ONLY,  # type: ignore[arg-type]
            )
        assert caught.value.outcome is MintOutcome.TIMEOUT
    else:
        adapter._prepare_google_login_surface(
            browser,
            ChallengeMode.DETECT_ONLY,  # type: ignore[arg-type]
        )

    assert browser.login_attempts == 2
    assert browser.replacements == 0
    assert surface_attempts == 2


def test_google_login_surface_waits_for_hydrated_continue_control(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == 30_000

    class PopupInfo:
        value = Popup()

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            return None

    class Page(NullPage):
        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            return PopupInfo()

    class HydratingBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.visible_attempts = 0
            self.challenge_checks = 0
            self.clicks = 0
            self.waits: list[float] = []
            self.captures: list[str] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            assert selectors in (
                spec.auth.control("cookie_accept"),
                spec.auth.control("terms_accept"),
            )
            return False

        def evaluate(self, script: str) -> object:
            self.challenge_checks += 1
            return {"vendor": "none", "state": "none"}

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            assert 0 < timeout_seconds <= 1
            self.visible_attempts += 1
            return self.visible_attempts >= 3

        def native_click(self, selectors: tuple[str, ...]) -> None:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            self.clicks += 1

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 5_000
            self.captures.append(label)
            return True

    browser = HydratingBrowser()
    adapter = _adapter(tmp_path)

    adapter._wait_for_google_login_surface(  # type: ignore[arg-type]
        browser,
        ChallengeMode.DETECT_ONLY,
    )
    popup = adapter._open_google_popup(browser)  # type: ignore[arg-type]

    assert isinstance(popup, Popup)
    assert browser.visible_attempts == 3
    assert browser.challenge_checks == 3
    assert browser.clicks == 1
    assert browser.waits == [5]
    assert browser.captures == ["google-launch-before"]


def test_google_login_surface_accepts_scoped_bloomberg_terms_once(
    tmp_path: Path,
) -> None:
    class TermsBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.terms_checks = 0
            self.terms_clicks = 0
            self.hidden_checks = 0

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            if selectors == spec.auth.control("cookie_accept"):
                return False
            assert selectors == spec.auth.control("terms_accept")
            self.terms_checks += 1
            if self.terms_checks == 1:
                self.terms_clicks += 1
                return True
            return False

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "terms_accept"
            )
            assert timeout_seconds == 5
            self.hidden_checks += 1
            return True

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            return True

    browser = TermsBrowser()

    _adapter(tmp_path)._wait_for_google_login_surface(  # type: ignore[arg-type]
        browser,
        ChallengeMode.DETECT_ONLY,
    )

    assert browser.terms_checks == 2
    assert browser.terms_clicks == 1
    assert browser.hidden_checks == 1


def test_google_login_surface_accepts_cookie_preferences_once(
    tmp_path: Path,
) -> None:
    class CookieBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.cookie_checks = 0
            self.cookie_clicks = 0
            self.hidden_checks = 0
            self.terms_checks = 0

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            if selectors == spec.auth.control("cookie_accept"):
                self.cookie_checks += 1
                if self.cookie_checks == 1:
                    self.cookie_clicks += 1
                    return True
                return False
            assert selectors == spec.auth.control("terms_accept")
            self.terms_checks += 1
            return False

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "cookie_accept"
            )
            assert timeout_seconds == 5
            self.hidden_checks += 1
            return True

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            return True

    browser = CookieBrowser()

    _adapter(tmp_path)._wait_for_google_login_surface(  # type: ignore[arg-type]
        browser,
        ChallengeMode.DETECT_ONLY,
    )

    assert browser.cookie_checks == 2
    assert browser.cookie_clicks == 1
    assert browser.hidden_checks == 1
    assert browser.terms_checks == 1


def test_google_login_surface_never_proceeds_while_terms_remain_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CoveredBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.terms_clicks = 0
            self.hidden_checks = 0

        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            if selectors == spec.auth.control("cookie_accept"):
                return False
            assert selectors == spec.auth.control("terms_accept")
            self.terms_clicks += 1
            return True

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "terms_accept"
            )
            assert timeout_seconds == 5
            self.hidden_checks += 1
            return False

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            pytest.fail("covered Google control must not be treated as ready")

    clock = iter((0.0, 1.0, 91.0))
    monkeypatch.setattr(
        "newsclip.providers.bloomberg_auth.time.monotonic",
        lambda: next(clock),
    )
    browser = CoveredBrowser()

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._wait_for_google_login_surface(  # type: ignore[arg-type]
            browser,
            ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.TIMEOUT
    assert browser.terms_clicks == 1
    assert browser.hidden_checks == 1


def test_google_popup_retries_once_after_clearing_late_terms_modal(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == 30_000

    class PopupInfo:
        value = Popup()

        def __init__(self, *, fail: bool) -> None:
            self.fail = fail

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            if self.fail:
                raise TimeoutError("late terms modal covered launch control")

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.popup_attempts += 1
            return PopupInfo(fail=self.popup_attempts == 1)

    class LateTermsBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.terms_clicks = 0
            self.hidden_waits = 0
            self.waits: list[float] = []
            self.captures: list[str] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            if selectors == spec.auth.control("cookie_accept"):
                return False
            assert selectors == spec.auth.control("terms_accept")
            self.terms_clicks += 1
            return True

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            self.hidden_waits += 1
            return True

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            return True

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 5_000
            self.captures.append(label)
            return True

    browser = LateTermsBrowser()

    popup = _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert isinstance(popup, Popup)
    assert browser.page.popup_attempts == 2
    assert browser.launch_clicks == 2
    assert browser.terms_clicks == 1
    assert browser.hidden_waits == 1
    assert browser.waits == [5, 20]
    assert browser.captures == [
        "google-launch-before",
        "google-launch-timeout-1",
    ]


def test_google_popup_retries_once_after_clearing_late_cookie_overlay(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == 30_000

    class PopupInfo:
        value = Popup()

        def __init__(self, *, fail: bool) -> None:
            self.fail = fail

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            if self.fail:
                raise TimeoutError("late cookie overlay covered launch control")

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.popup_attempts += 1
            return PopupInfo(fail=self.popup_attempts == 1)

    class LateCookieBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.cookie_clicks = 0
            self.hidden_waits = 0
            self.waits: list[float] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "cookie_accept"
            )
            self.cookie_clicks += 1
            return True

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "cookie_accept"
            )
            assert timeout_seconds == 5
            self.hidden_waits += 1
            return True

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            return True

    browser = LateCookieBrowser()

    popup = _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert isinstance(popup, Popup)
    assert browser.page.popup_attempts == 2
    assert browser.launch_clicks == 2
    assert browser.cookie_clicks == 1
    assert browser.hidden_waits == 1
    assert browser.waits == [5, 20]


def test_google_popup_allows_third_launch_after_sequential_known_overlays(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == 30_000

    class PopupInfo:
        value = Popup()

        def __init__(self, *, fail: bool) -> None:
            self.fail = fail

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            if self.fail:
                raise TimeoutError("known Bloomberg overlay covered launch control")

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.popup_attempts += 1
            return PopupInfo(fail=self.popup_attempts < 3)

    class SequentialOverlayBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.cookie_checks = 0
            self.terms_checks = 0
            self.hidden_waits = 0
            self.waits: list[float] = []
            self.captures: list[str] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            if selectors == spec.auth.control("cookie_accept"):
                self.cookie_checks += 1
                return self.cookie_checks == 1
            assert selectors == spec.auth.control("terms_accept")
            self.terms_checks += 1
            return True

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            self.hidden_waits += 1
            return True

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            return True

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 5_000
            self.captures.append(label)
            return True

    browser = SequentialOverlayBrowser()
    secrets = FakeSecrets()

    popup = _adapter(tmp_path, secrets=secrets)._open_google_popup(  # type: ignore[arg-type]
        browser
    )

    assert isinstance(popup, Popup)
    assert browser.page.popup_attempts == 3
    assert browser.launch_clicks == 3
    assert browser.cookie_checks == 2
    assert browser.terms_checks == 1
    assert browser.hidden_waits == 2
    assert browser.waits == [5, 20, 5]
    assert browser.captures == [
        "google-launch-before",
        "google-launch-timeout-1",
        "google-launch-timeout-2",
    ]
    assert secrets.fields == []


def test_google_popup_does_not_use_third_launch_without_second_overlay(
    tmp_path: Path,
) -> None:
    class PopupInfo:
        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            raise TimeoutError("launch control produced no popup")

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.popup_attempts += 1
            return PopupInfo()

    class NoSecondOverlayBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.waits: list[float] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            return False

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            return True

    browser = NoSecondOverlayBrowser()
    secrets = FakeSecrets()

    with pytest.raises(TimeoutError, match="produced no popup"):
        _adapter(tmp_path, secrets=secrets)._open_google_popup(  # type: ignore[arg-type]
            browser
        )

    assert browser.page.popup_attempts == 2
    assert browser.launch_clicks == 2
    assert browser.waits == [5, 20]
    assert secrets.fields == []


def test_google_popup_does_not_retry_while_cookie_overlay_remains_visible(
    tmp_path: Path,
) -> None:
    class PopupInfo:
        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            raise TimeoutError("late cookie overlay covered launch control")

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.popup_attempts += 1
            return PopupInfo()

    class CoveredBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.hidden_waits = 0
            self.waits: list[float] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "cookie_accept"
            )
            return True

        def wait_for_hidden(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            self.hidden_waits += 1
            return False

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            pytest.fail("covered OAuth control must not be clicked again")

    browser = CoveredBrowser()

    with pytest.raises(TimeoutError, match="late cookie overlay"):
        _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert browser.page.popup_attempts == 1
    assert browser.launch_clicks == 1
    assert browser.hidden_waits == 1
    assert browser.waits == [5]


def test_google_popup_load_failure_is_not_retried_as_a_launch_failure(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            raise TimeoutError("popup document did not load")

    class PopupInfo:
        value = Popup()

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            return None

    class Page(NullPage):
        def __init__(self) -> None:
            self.popup_attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            self.popup_attempts += 1
            return PopupInfo()

    class Browser:
        def __init__(self) -> None:
            self.page = Page()
            self.launch_clicks = 0
            self.terms_checks = 0
            self.waits: list[float] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            self.launch_clicks += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            self.terms_checks += 1
            return True

    browser = Browser()

    with pytest.raises(TimeoutError, match="popup document did not load"):
        _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert browser.page.popup_attempts == 1
    assert browser.launch_clicks == 1
    assert browser.terms_checks == 0
    assert browser.waits == [5]


def test_google_popup_retries_once_when_visible_handler_is_still_hydrating(
    tmp_path: Path,
) -> None:
    class Popup:
        def wait_for_load_state(self, state: str, *, timeout: int) -> None:
            assert state == "domcontentloaded"
            assert timeout == 30_000

    class PopupInfo:
        value = Popup()

        def __init__(self, *, fail: bool) -> None:
            self.fail = fail

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:  # noqa: ANN002
            if self.fail:
                raise TimeoutError("visible launch handler not ready")

    class Page(NullPage):
        def __init__(self) -> None:
            self.attempts = 0

        def expect_popup(self, *, timeout: int) -> PopupInfo:
            assert timeout == 15_000
            self.attempts += 1
            return PopupInfo(fail=self.attempts == 1)

    class Browser:
        def __init__(self) -> None:
            self.page = Page()
            self.launches = 0
            self.waits: list[float] = []

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            assert selectors == load_provider_spec("bloomberg").auth.control(
                "google_continue"
            )
            self.launches += 1

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            spec = load_provider_spec("bloomberg")
            assert selectors in (
                spec.auth.control("cookie_accept"),
                spec.auth.control("terms_accept"),
            )
            return False

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            assert timeout_seconds == 5
            return True

    browser = Browser()

    popup = _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert isinstance(popup, Popup)
    assert browser.page.attempts == 2
    assert browser.launches == 2
    assert browser.waits == [5, 20]


def test_google_popup_does_not_retry_native_input_failure(tmp_path: Path) -> None:
    class Page(NullPage):
        def __init__(self) -> None:
            self.attempts = 0

        @contextmanager
        def expect_popup(self, *, timeout: int):  # noqa: ANN202
            self.attempts += 1
            yield object()

    class Browser:
        def __init__(self) -> None:
            self.page = Page()
            self.waits: list[float] = []
            self.terms_checks = 0

        def wait(self, seconds: float) -> None:
            self.waits.append(seconds)

        def native_click(self, selectors: tuple[str, ...]) -> None:
            raise RuntimeError("native input unavailable")

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            self.terms_checks += 1
            return False

    browser = Browser()

    with pytest.raises(RuntimeError, match="native input unavailable"):
        _adapter(tmp_path)._open_google_popup(browser)  # type: ignore[arg-type]

    assert browser.page.attempts == 1
    assert browser.terms_checks == 0
    assert browser.waits == [5]


def test_google_launch_checkpoint_failure_is_best_effort(tmp_path: Path) -> None:
    class Browser:
        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            raise RuntimeError("diagnostic storage unavailable")

    _adapter(tmp_path)._capture_google_checkpoint(  # type: ignore[arg-type]
        Browser(),
        "google-launch-before",
    )


def test_google_login_surface_timeout_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class StuckBrowser(NullBrowserSurface):
        def evaluate(self, script: str) -> object:
            return {"vendor": "none", "state": "none"}

        def click_optional(self, selectors: tuple[str, ...]) -> bool:
            return False

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            return False

    clock = iter((0.0, 30.0, 60.0, 91.0))
    monkeypatch.setattr(
        "newsclip.providers.bloomberg_auth.time.monotonic",
        lambda: next(clock),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._wait_for_google_login_surface(
            StuckBrowser(),  # type: ignore[arg-type]
            ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.TIMEOUT


def test_verified_auto_submit_is_recorded_as_credential_mint(
    tmp_path: Path, monkeypatch
) -> None:
    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.context = Context()

        def navigate(self, url: str) -> None:
            self.page.url = url

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            assert mode is PasskeyMode.NON_PRESENT
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    callback_timeouts: list[float] = []
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(
            CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT
        ),
    )
    monkeypatch.setattr(
        adapter,
        "_wait_parent_callback",
        lambda _page, *, timeout_seconds: (
            callback_timeouts.append(timeout_seconds) or True
        ),
    )
    monkeypatch.setattr(adapter, "_settle_after_google", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        adapter, "_browser_full_fetch", lambda *args, **kwargs: _full_fetch()
    )
    recorder = TimingRecorder(tmp_path / "timings")

    with recorder.operation(
        TimingOperation.LOGIN,
        provider="bloomberg",
        transport=TimingTransport.BROWSER,
    ) as operation:
        browser = LoginBrowser()
        candidate = adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert (
        candidate.evidence.credential_action
        is CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT
    )
    assert candidate.evidence.callback_confirmed is True
    assert candidate.evidence.session_proof_observed is False
    assert candidate.verification_fetch == _full_fetch()
    assert callback_timeouts == [25]
    assert browser.identity_handoffs == [
        {
            "checkpoint": "identity_return",
            "credential_action": "google_password_auto_submit",
            "identity_callback_complete": False,
            "identity_page_closed": False,
            "identity_exit_reason": "identity_page_closed",
            "parent_state": "publisher_auth",
            "callback_confirmed": None,
            "publisher_auth_cookie_present": True,
            "challenge_cookie_present": False,
        },
        {
            "checkpoint": "callback_wait",
            "credential_action": "google_password_auto_submit",
            "identity_callback_complete": False,
            "identity_page_closed": False,
            "identity_exit_reason": "identity_page_closed",
            "parent_state": "publisher_auth",
            "callback_confirmed": True,
            "publisher_auth_cookie_present": True,
            "challenge_cookie_present": False,
        },
        {
            "checkpoint": "paid_probe",
            "credential_action": None,
            "identity_callback_complete": None,
            "identity_page_closed": None,
            "parent_state": "publisher_auth",
            "callback_confirmed": True,
            "publisher_auth_cookie_present": None,
            "challenge_cookie_present": False,
            "paid_probe_outcome": "complete",
            "entitlement_confirmed": True,
            "paid_auth_cookie_present": True,
            "paid_probe_access_state": None,
            "paid_probe_stabilized": None,
            "verification_full": True,
        },
    ]
    assert operation.path is not None
    run = read_timing_file(operation.path)
    steps = {
        event.step
        for record in run.records
        if isinstance((event := record.event), StepFinishedEvent)
    }
    assert {
        TimingStep.LOGIN_FRONTDOOR,
        TimingStep.BROWSER_WARMUP,
        TimingStep.PROVIDER_TRANSITION_WAIT,
        TimingStep.IDENTITY_FLOW,
        TimingStep.CALLBACK,
        TimingStep.PAID_PROBE,
        TimingStep.COOKIE_EXPORT,
    } <= steps


@pytest.mark.parametrize("closed", [False, True])
def test_identity_error_records_popup_state(tmp_path: Path, closed: bool) -> None:
    class IdentityPage:
        def is_closed(self) -> bool:
            return closed

    identity_browser = type("IdentityBrowser", (), {"page": IdentityPage()})()

    assert _adapter(tmp_path)._identity_page_state(identity_browser).value == (
        "closed" if closed else "open"
    )


@pytest.mark.parametrize("entitlement_confirmed", [False, True])
def test_paid_probe_records_cookie_without_full_article(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entitlement_confirmed: bool,
) -> None:
    class LoginBrowser(FakeBrowser):
        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        adapter,
        "_settle_after_google",
        lambda *args, **kwargs: entitlement_confirmed,
    )
    monkeypatch.setattr(adapter, "_browser_full_fetch", lambda *args, **kwargs: None)

    browser = LoginBrowser()
    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL
    assert browser.identity_handoffs[-1] == {
        "checkpoint": "paid_probe",
        "credential_action": None,
        "identity_callback_complete": None,
        "identity_page_closed": None,
        "parent_state": "publisher_auth",
        "callback_confirmed": True,
        "publisher_auth_cookie_present": None,
        "challenge_cookie_present": False,
        "paid_probe_outcome": "complete",
        "entitlement_confirmed": entitlement_confirmed,
        "paid_auth_cookie_present": True,
        "paid_probe_access_state": None,
        "paid_probe_stabilized": None,
        "verification_full": False,
    }


def test_paid_probe_retains_the_verdict_a_teaser_failure_would_discard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """article_not_full and timeout collapse four verdicts into two categories.

    The observed access state and content stability are captured before the
    fail-closed branch, so a signed-out teaser stays separable from an
    auth-required page, a block, or an unstable render.
    """

    class LoginBrowser(FakeBrowser):
        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: True)
    monkeypatch.setattr(adapter, "_settle_after_google", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        adapter,
        "_browser_paid_proof",
        lambda *args, **kwargs: _BrowserPaidProof(
            fetch=_full_fetch(),
            access_state=AccessState.TEASER,
            verified=False,
            stabilized=True,
            paid_auth_cookie_present=False,
        ),
    )

    browser = LoginBrowser()
    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL
    probe = browser.identity_handoffs[-1]
    assert probe["checkpoint"] == "paid_probe"
    assert probe["paid_probe_outcome"] == "interrupted"
    assert probe["paid_probe_access_state"] == AccessState.TEASER.value
    assert probe["paid_probe_stabilized"] is True


def test_paid_probe_records_interruption_before_failure_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LoginBrowser(FakeBrowser):
        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: True)

    def interrupt_probe(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("private paid probe failure")

    monkeypatch.setattr(adapter, "_settle_after_google", interrupt_probe)

    browser = LoginBrowser()
    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE
    assert browser.identity_handoffs[-1] == {
        "checkpoint": "paid_probe",
        "credential_action": None,
        "identity_callback_complete": None,
        "identity_page_closed": None,
        "parent_state": "publisher_auth",
        "callback_confirmed": True,
        "publisher_auth_cookie_present": None,
        "challenge_cookie_present": False,
        "paid_probe_outcome": "interrupted",
        "entitlement_confirmed": None,
        "paid_auth_cookie_present": True,
        "paid_probe_access_state": None,
        "paid_probe_stabilized": None,
        "verification_full": None,
    }
    assert "private paid probe failure" not in repr(browser.identity_handoffs)


@pytest.mark.parametrize("page_closed", [True, False])
@pytest.mark.parametrize(
    "callback, paid", [(True, True), (False, False), (False, True), (True, False)]
)
def test_context_closed_handoff_waits_once_without_reopening_popup(
    tmp_path: Path, monkeypatch, callback, paid, page_closed
) -> None:
    from types import SimpleNamespace

    class Browser(FakeBrowser):
        def __init__(self):
            super().__init__()
            self.context = SimpleNamespace(
                new_cdp_session=lambda page: SimpleNamespace(send=lambda *args: None)
            )

        def navigate(self, url):
            self.page.url = url

        def suppress_passkeys(self, mode):
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    opened = []
    waits = []
    monkeypatch.setattr(
        adapter, "_open_google_popup", lambda browser: opened.append(1) or object()
    )
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(
            CredentialAction.GOOGLE_TOTP_SUBMIT
        ).model_copy(
            update={
                "identity_page_closed": page_closed,
                "exit_reason": IdentityExitReason.IDENTITY_CONTEXT_CLOSED,
            }
        ),
    )
    monkeypatch.setattr(
        adapter,
        "_wait_parent_callback",
        lambda *args, **kwargs: waits.append(kwargs["timeout_seconds"]) or callback,
    )
    monkeypatch.setattr(
        adapter,
        "_retry_google_callback",
        lambda *args, **kwargs: pytest.fail(
            "ambiguous closed-context handoff must not reopen identity"
        ),
    )
    monkeypatch.setattr(
        adapter, "_settle_after_google", lambda *args, **kwargs: callback
    )
    monkeypatch.setattr(
        adapter,
        "_browser_full_fetch",
        lambda *args, **kwargs: _full_fetch() if paid else None,
    )
    if paid:
        candidate = adapter.mint_credentials(
            Browser(), account_key="default", challenge_mode=ChallengeMode.DETECT_ONLY
        )
        assert candidate.evidence.callback_confirmed
        assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    else:
        with pytest.raises(AcquisitionFailure) as caught:
            adapter.mint_credentials(
                Browser(),
                account_key="default",
                challenge_mode=ChallengeMode.DETECT_ONLY,
            )
        assert caught.value.evidence.category is (
            MintFailureCategory.ARTICLE_NOT_FULL
            if callback
            else MintFailureCategory.CALLBACK_NOT_CONFIRMED
        )
    assert opened == [1]
    assert len(waits) == 1


def test_paid_entitlement_and_full_article_confirm_closed_popup_callback(
    tmp_path: Path, monkeypatch
) -> None:
    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.context = Context()

        def navigate(self, url: str) -> None:
            self.page.url = url

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        adapter,
        "_resolve_google_callback_challenge",
        lambda *args, **kwargs: _cleared_callback(True),
    )
    monkeypatch.setattr(
        adapter,
        "_retry_google_callback",
        lambda *args, **kwargs: _CallbackRetry(
            exit_reason=IdentityExitReason.DECLINED,
            identity_page_closed=True,
        ),
    )
    monkeypatch.setattr(adapter, "_settle_after_google", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        adapter, "_browser_full_fetch", lambda *args, **kwargs: _full_fetch()
    )

    browser = LoginBrowser()
    candidate = adapter.mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert candidate.evidence.callback_confirmed is True
    assert browser.identity_handoffs[-1]["checkpoint"] == "paid_probe"
    assert browser.identity_handoffs[-1]["callback_confirmed"] is False
    assert browser.identity_handoffs[-1]["entitlement_confirmed"] is True
    assert browser.identity_handoffs[-1]["verification_full"] is True


def test_callback_retry_handoff_reports_the_replays_own_facts(
    tmp_path: Path, monkeypatch
) -> None:
    """The retry checkpoint must describe the replay, not the earlier popup.

    ``_google_result`` leaves the first popup incomplete and open. A replay that
    completes on a closed surface has to be visible as such, otherwise a
    stranded retry is indistinguishable from one that was never attempted.
    """

    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.context = Context()

        def navigate(self, url: str) -> None:
            self.page.url = url

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        adapter,
        "_resolve_google_callback_challenge",
        lambda *args, **kwargs: _cleared_callback(True),
    )
    monkeypatch.setattr(
        adapter,
        "_retry_google_callback",
        lambda *args, **kwargs: _CallbackRetry(
            exit_reason=IdentityExitReason.CALLBACK_COMPLETE,
            identity_page_closed=True,
        ),
    )
    monkeypatch.setattr(adapter, "_settle_after_google", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        adapter, "_browser_full_fetch", lambda *args, **kwargs: _full_fetch()
    )

    browser = LoginBrowser()
    adapter.mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    handoffs = {
        str(handoff["checkpoint"]): handoff for handoff in browser.identity_handoffs
    }
    first = handoffs["identity_return"]
    assert first["identity_callback_complete"] is False
    assert first["identity_page_closed"] is False
    assert (
        first["identity_exit_reason"] == IdentityExitReason.IDENTITY_PAGE_CLOSED.value
    )
    retry = handoffs["callback_retry"]
    assert retry["identity_callback_complete"] is True
    assert retry["identity_page_closed"] is True
    # The exit reason must describe the replay, not carry the first popup's
    # forward. A stale reason here is what the 2026-07-25 cold trace recorded.
    assert retry["identity_exit_reason"] == IdentityExitReason.CALLBACK_COMPLETE.value
    assert retry["identity_exit_reason"] != first["identity_exit_reason"]
    # The attempt's credential action stays monotonic across checkpoints.
    assert retry["credential_action"] == CredentialAction.GOOGLE_TOTP_SUBMIT.value


def test_unresolved_callback_px_stops_before_cached_google_retry(
    tmp_path: Path, monkeypatch
) -> None:
    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class LoginBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.context = Context()

        def navigate(self, url: str) -> None:
            self.page.url = url

        def suppress_passkeys(self, mode: PasskeyMode) -> bool:
            return True

    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: object())
    monkeypatch.setattr(
        adapter._google_identity,
        "drive",
        lambda *args, **kwargs: _google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
    )
    monkeypatch.setattr(adapter, "_wait_parent_callback", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        adapter,
        "_resolve_google_callback_challenge",
        lambda *args, **kwargs: _cleared_callback(False),
    )
    monkeypatch.setattr(
        adapter,
        "_retry_google_callback",
        lambda *args, **kwargs: pytest.fail("blocked PX must prevent GIS replay"),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter.mint_credentials(
            LoginBrowser(),
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.CHALLENGE_BLOCKED


def test_google_settle_hydrates_paid_cookie_via_account_surface(
    tmp_path: Path,
) -> None:
    class SettlePage(FullPage):
        def __init__(self) -> None:
            super().__init__("https://www.bloomberg.com/account/signin")
            self.visits: list[str] = []

        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.url = url
            self.visits.append(url)
            return FakeResponse()

    class SettleBrowser(NullBrowserSurface):
        def __init__(self) -> None:
            self.page = SettlePage()

        @property
        def current_url(self) -> str:
            return self.page.url

        def wait(self, seconds: float) -> None: ...

        def evaluate(self, script: str):
            return {"vendor": "none", "state": "none"}

        def navigate_loaded(self, url: str, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 60
            self.page.goto(url, wait_until="domcontentloaded", timeout=60_000)

        def cookies(self) -> list[dict[str, str]]:
            if self.page.url.endswith("/account/profile"):
                return [{"name": "_user-token"}]
            return [{"name": "session_id"}]

    browser = SettleBrowser()

    settled = _adapter(tmp_path)._settle_after_google(
        browser,
        challenge_mode=ChallengeMode.DETECT_ONLY,  # type: ignore[arg-type]
    )

    assert settled is True
    assert browser.page.visits == [
        "https://www.bloomberg.com/",
        "https://www.bloomberg.com/account/profile",
    ]


def test_google_callback_resolves_late_px_before_cached_retry(
    tmp_path: Path, monkeypatch
) -> None:
    class CallbackPage(ParentPage):
        def __init__(self) -> None:
            super().__init__()
            self.visits: list[str] = []

        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.url = url
            self.visits.append(url)
            return type("Response", (), {"status": 404})()

    parent = CallbackPage()
    browser = FakeBrowser()
    clock = [0.0]
    statuses = iter(
        (
            ChallengeResolutionStatus.NON_INTERACTIVE,
            ChallengeResolutionStatus.CLEARED,
            ChallengeResolutionStatus.NOT_PRESENT,
        )
    )
    waits: list[float] = []
    adapter = _adapter(tmp_path)
    monkeypatch.setattr(
        "newsclip.providers.bloomberg_auth.time.monotonic", lambda: clock[0]
    )

    def resolve(*args, **kwargs):  # noqa: ANN002, ANN003
        status = next(statuses)
        return type("Resolution", (), {"status": status, "reason": None})()

    def wait(seconds: float) -> None:
        waits.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(adapter, "_resolve_challenge", resolve)
    monkeypatch.setattr(browser, "wait", wait)

    observed: list = []
    clearance = adapter._resolve_google_callback_challenge(
        browser,
        original=parent,
        challenge_mode=ChallengeMode.AUTO,
        observe=observed.append,
    )

    assert clearance.cleared is True
    assert browser.page is parent
    assert parent.visits == [
        "https://login.bloomberg.com/api/login/google-auth",
        "https://www.bloomberg.com/account/signin",
    ]
    assert waits == [0.5, 1, 2]


def test_google_callback_opens_first_party_px_surface_then_restores_signin(
    tmp_path: Path, monkeypatch
) -> None:
    class CallbackPage(ParentPage):
        def __init__(self) -> None:
            super().__init__()
            self.visits: list[str] = []

        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.url = url
            self.visits.append(url)
            status = 403 if self.visits.count(url) == 1 else 404
            return type("Response", (), {"status": status})()

    page = CallbackPage()
    browser = FakeBrowser()
    browser.page = page
    statuses = iter(
        (
            ChallengeResolutionStatus.NOT_PRESENT,
            ChallengeResolutionStatus.CLEARED,
            ChallengeResolutionStatus.NOT_PRESENT,
        )
    )
    adapter = _adapter(tmp_path)

    def resolve(*args, **kwargs):  # noqa: ANN002, ANN003
        status = next(statuses)
        return type("Resolution", (), {"status": status, "reason": None})()

    monkeypatch.setattr(adapter, "_resolve_challenge", resolve)

    observed: list = []
    clearance = adapter._resolve_google_callback_challenge(
        browser,
        original=page,
        challenge_mode=ChallengeMode.AUTO,
        observe=observed.append,
    )

    assert clearance.cleared is True
    assert page.visits == [
        "https://login.bloomberg.com/api/login/google-auth",
        "https://login.bloomberg.com/api/login/google-auth",
        "https://www.bloomberg.com/account/signin",
    ]


def test_google_callback_does_not_treat_server_error_as_px_clearance(
    tmp_path: Path, monkeypatch
) -> None:
    class CallbackPage(ParentPage):
        def goto(self, url: str, **kwargs) -> FakeResponse:
            self.url = url
            status = 500 if url.endswith("/google-auth") else 200
            return type("Response", (), {"status": status})()

    page = CallbackPage()
    browser = FakeBrowser()
    browser.page = page
    statuses = iter(
        (
            ChallengeResolutionStatus.NOT_PRESENT,
            ChallengeResolutionStatus.NOT_PRESENT,
        )
    )
    adapter = _adapter(tmp_path)

    def resolve(*args, **kwargs):  # noqa: ANN002, ANN003
        status = next(statuses)
        return type("Resolution", (), {"status": status, "reason": None})()

    monkeypatch.setattr(adapter, "_resolve_challenge", resolve)

    observed: list = []
    clearance = adapter._resolve_google_callback_challenge(
        browser,
        original=page,
        challenge_mode=ChallengeMode.AUTO,
        observe=observed.append,
    )

    assert clearance.cleared is False
    # The status is retained so a server fault stays distinguishable from a
    # defense that re-blocked an accepted browser.
    assert clearance.probe_status == 500


def _paid_proof_browser(raw_html: bytes) -> FakeBrowser:
    """A FakeBrowser whose verification page serves exactly this document."""

    class Page(FullPage):
        def content(self) -> str:
            return raw_html.decode("utf-8")

    class Browser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__()
            self.page = Page("about:blank")

    return Browser()


def test_paid_probe_records_why_its_readiness_sampler_stopped(
    tmp_path: Path,
) -> None:
    """Retrieval records this terminal; the paid probe reported only stabilized.

    Without it a static incomplete render and a body that never settles are the
    same fact, which is what forced a code dig to explain a cold failure.
    """

    browser = _paid_proof_browser(FIXTURE.read_bytes())

    fetch = _adapter(tmp_path)._browser_full_fetch(browser, ChallengeMode.AUTO)

    assert fetch is not None
    assert browser.readiness_terminals == [
        {
            "state": ReadinessTerminalState.STABILIZED,
            "word_count": browser.readiness_terminals[0]["word_count"],
            "coverage_bucket": ReadinessCoverageBucket.UNAVAILABLE,
            "content_change_count": 0,
            "last_content_change_ms": browser.readiness_terminals[0][
                "last_content_change_ms"
            ],
        }
    ]
    assert isinstance(browser.readiness_terminals[0]["word_count"], int)
    assert browser.readiness_terminals[0]["word_count"] > 250


def test_paid_probe_records_a_non_promotable_readiness_terminal(
    tmp_path: Path,
) -> None:
    browser = _paid_proof_browser((FIXTURES / "teaser.html").read_bytes())

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._browser_full_fetch(browser, ChallengeMode.AUTO)

    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL
    assert len(browser.readiness_terminals) == 1
    terminal = browser.readiness_terminals[0]
    assert terminal["state"] is ReadinessTerminalState.NON_PROMOTABLE_TIMEOUT
    assert terminal["content_change_count"] == 0


def test_paid_probe_readiness_recording_never_changes_the_outcome(
    tmp_path: Path,
) -> None:
    """A browser without the recorder still completes its paid proof."""

    class Browser(_paid_proof_browser(FIXTURE.read_bytes()).__class__):
        def record_semantic_readiness_terminal(self, **facts: object) -> None:
            raise RuntimeError("diagnostic sink unavailable")

    fetch = _adapter(tmp_path)._browser_full_fetch(Browser(), ChallengeMode.AUTO)

    assert fetch is not None


def test_bloomberg_credential_mint_clears_guest_auth_but_keeps_px(
    tmp_path: Path,
) -> None:
    cookies = [
        {"name": "session_id", "value": "GUEST", "domain": ".bloomberg.com"},
        {"name": "_user-token", "value": "OLD", "domain": ".bloomberg.com"},
        {"name": "_pxhd", "value": "DEVICE", "domain": "www.bloomberg.com"},
        {"name": "country_code", "value": "US", "domain": ".bloomberg.com"},
        {"name": "session_id", "value": "OTHER", "domain": ".example.com"},
    ]

    class Browser:
        restored: list[dict[str, str]] = []
        storage_cleared = False

        def cookies(self) -> list[dict[str, str]]:
            return cookies

        def replace_cookies(self, values: list[dict[str, str]]) -> None:
            self.restored = values

        def clear_storage(self) -> None:
            self.storage_cleared = True

    browser = Browser()

    cleared = _adapter(tmp_path)._clear_bloomberg_auth_keep_px(
        browser  # type: ignore[arg-type]
    )

    assert cleared == 2
    restored = {(cookie["domain"], cookie["name"]) for cookie in browser.restored}
    assert restored == {
        ("www.bloomberg.com", "_pxhd"),
        (".bloomberg.com", "country_code"),
        (".example.com", "session_id"),
    }
    assert browser.storage_cleared is True


@pytest.mark.parametrize(
    ("cookies", "expected"),
    [
        ([("_pxhd", "www.bloomberg.com")], True),
        ([("px_session", ".bloomberg.com")], True),
        ([("_perimeterx", "bloomberg.com")], True),
        ([("pxid", ".example.test")], False),
        ([("_px3", "accounts.google.com")], False),
        ([("country_code", ".bloomberg.com")], False),
        ([("pxid", ".example.test"), ("_pxhd", "www.bloomberg.com")], True),
    ],
    ids=[
        "provider_host",
        "provider_parent_domain",
        "provider_apex",
        "unrelated_domain",
        "identity_host",
        "provider_non_px",
        "unrelated_beside_provider",
    ],
)
def test_challenge_cookie_presence_is_scoped_to_the_provider(
    tmp_path: Path,
    cookies: list[tuple[str, str]],
    expected: bool,
) -> None:
    """A px-prefixed cookie elsewhere is not challenge-vendor reputation."""

    class Browser:
        def cookies(self) -> list[dict[str, object]]:
            return [{"name": name, "domain": domain} for name, domain in cookies]

    present = _adapter(tmp_path)._challenge_cookie_present(
        Browser()  # type: ignore[arg-type]
    )

    assert present is expected


def test_challenge_cookie_presence_is_unknown_when_cookies_are_unreadable(
    tmp_path: Path,
) -> None:
    """An unreadable jar is not the same fact as an absent cookie."""

    class Browser:
        def cookies(self) -> list[dict[str, object]]:
            raise RuntimeError("cookie read failed")

    present = _adapter(tmp_path)._challenge_cookie_present(
        Browser()  # type: ignore[arg-type]
    )

    assert present is None


class ReplayPopupPage:
    """A replayed GIS popup that opens on Google's account chooser."""

    def __init__(self) -> None:
        self.url = "https://accounts.google.com/v3/signin/accountchooser"

    def is_closed(self) -> bool:
        return False

    def add_init_script(self, script: str) -> None: ...

    def wait_for_timeout(self, milliseconds: float) -> None: ...

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class ReplayPopupBrowser:
    def __init__(self, page: ReplayPopupPage, observations: list[dict[str, bool]]):
        self.page = page
        self.observations = list(observations)
        self.last: dict[str, bool] = {}

    @property
    def current_url(self) -> str:
        return self.page.url

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        return True

    def add_init_script(self, script: str) -> None: ...

    def evaluate(self, script: str):
        if "datadomeAsset" in script:
            return {"vendor": "none", "state": "none"}
        if self.observations:
            self.last = self.observations.pop(0)
        return self.last

    def wait(self, seconds: float) -> None: ...


def test_google_callback_retry_traverses_the_replayed_account_chooser(
    tmp_path: Path, monkeypatch
) -> None:
    """Reproducer: a replayed popup opens on the chooser and must not strand.

    Both retained Bloomberg cold failures (2026-07-24 and 2026-07-25) recorded a
    single ``account_chooser`` observation in the callback phase and no secret
    resolve, so the one callback-recovery path could never confirm. The 2026-07-22
    successes that needed the same recovery did select the cached account.
    """

    parent = ParentPage()
    popup = ReplayPopupBrowser(ReplayPopupPage(), [{"account_chooser": True}, {}])

    class Browser:
        page = parent

        def for_page(self, page: object) -> ReplayPopupBrowser:
            return popup

    class ChoiceSecrets(FakeSecrets):
        def __init__(self) -> None:
            super().__init__()
            self.matched_fields: list[str] = []

        def click_matching_choice(self, browser, *, field: str, **kwargs) -> bool:
            self.matched_fields.append(field)
            # Selecting the cached account lets Bloomberg consume the posted
            # identity, so the parent leaves its auth route.
            parent.url = "https://www.bloomberg.com/markets"
            return True

    secrets = ChoiceSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    monkeypatch.setattr(
        adapter, "_open_google_popup", lambda browser: ReplayPopupPage()
    )

    retried = adapter._retry_google_callback(
        Browser(),  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert retried.exit_reason is IdentityExitReason.CALLBACK_COMPLETE
    assert retried.callback_complete is True
    assert retried.identity_page_closed is False
    assert secrets.matched_fields == ["username"]
    # The replay must never resolve or resubmit a password or TOTP code.
    assert secrets.fields == []


def test_google_callback_retry_never_escapes_as_a_local_infrastructure_fault(
    tmp_path: Path, monkeypatch
) -> None:
    """A closure while selecting the account must not abort the mint.

    Selecting the account is what navigates the popup, so this closure is the
    likely shape of a *successful* selection. Letting it escape reported the
    mint as local_infrastructure, which misdirects the operator, authorizes a
    rerun, and skips the paid-proof salvage.
    """

    parent = ParentPage()
    popup = ReplayPopupBrowser(ReplayPopupPage(), [{"account_chooser": True}])

    class Browser:
        page = parent

        def for_page(self, page: object) -> ReplayPopupBrowser:
            return popup

    class ClosingSecrets(FakeSecrets):
        def click_matching_choice(self, browser, *, field: str, **kwargs) -> bool:
            raise RuntimeError(
                "Execution context was destroyed, most likely because of a navigation"
            )

    adapter = _adapter(tmp_path, secrets=ClosingSecrets())
    monkeypatch.setattr(
        adapter, "_open_google_popup", lambda browser: ReplayPopupPage()
    )

    retried = adapter._retry_google_callback(
        Browser(),  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert retried.exit_reason is IdentityExitReason.IDENTITY_CONTEXT_CLOSED
    # A lost surface is not a completed callback.
    assert retried.callback_complete is False


def test_google_callback_retry_uses_cached_state_without_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()

    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class Browser:
        def __init__(self) -> None:
            self.context = Context()
            self.page = parent

        def for_page(self, page):  # noqa: ANN001, ANN201
            return page

    class RetryPage(GooglePage):
        def wait_for_timeout(self, milliseconds: float) -> None: ...

        def evaluate(self, script: str):
            return {"vendor": "none", "state": "none"}

    secrets = FakeSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: RetryPage())

    def resume_cached(google, **kwargs) -> IdentityExitReason:  # noqa: ANN001, ARG001
        parent.url = "https://www.bloomberg.com/markets"
        return IdentityExitReason.CALLBACK_COMPLETE

    monkeypatch.setattr(
        adapter._google_identity,
        "resume_cached_callback",
        resume_cached,
    )

    retried = adapter._retry_google_callback(
        Browser(),  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert retried.exit_reason is IdentityExitReason.CALLBACK_COMPLETE
    assert secrets.fields == []


def test_google_callback_retry_delegates_without_reading_secrets(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()

    class Session:
        def send(self, method: str, params: dict[str, object]) -> None: ...

    class Context:
        def new_cdp_session(self, page) -> Session:  # noqa: ANN001
            return Session()

    class Browser:
        def __init__(self) -> None:
            self.context = Context()
            self.page = parent

        def for_page(self, page):  # noqa: ANN001, ANN201
            return page

    class RetryPage(GooglePage):
        def wait_for_timeout(self, milliseconds: float) -> None: ...

        def evaluate(self, script: str):
            return {"vendor": "none", "state": "none"}

    class MatchingSecrets(FakeSecrets):
        matched_fields: list[str]

        def __init__(self) -> None:
            super().__init__()
            self.matched_fields = []

        def click_matching_choice(self, browser, *, field: str, **kwargs) -> bool:
            self.matched_fields.append(field)
            return True

    secrets = MatchingSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    monkeypatch.setattr(adapter, "_open_google_popup", lambda browser: RetryPage())
    monkeypatch.setattr(
        adapter._google_identity,
        "resume_cached_callback",
        lambda *args, **kwargs: IdentityExitReason.DECLINED,
    )

    retried = adapter._retry_google_callback(
        Browser(),  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert retried.exit_reason is IdentityExitReason.DECLINED
    assert secrets.matched_fields == []
    assert secrets.fields == []


def test_google_callback_retry_without_a_popup_reports_no_identity_page(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()

    class Browser:
        page = parent

        def for_page(self, page: object) -> object:  # pragma: no cover
            raise AssertionError("a failed popup launch must not attach a surface")

    adapter = _adapter(tmp_path, secrets=FakeSecrets())

    def refuse(browser: object) -> object:
        raise RuntimeError("popup recovery exhausted")

    monkeypatch.setattr(adapter, "_open_google_popup", refuse)

    retried = adapter._retry_google_callback(
        Browser(),  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert retried.callback_complete is False
    assert retried.exit_reason is IdentityExitReason.IDENTITY_PAGE_CLOSED
    assert retried.identity_page_closed is True


@pytest.mark.parametrize(
    "url",
    [
        "https://www.bloomberg.com/account/signin",
        "https://www.bloomberg.com/account/login",
        "https://www.bloomberg.com/account/signin/callback",
        "https://www.bloomberg.com.evil.test/markets",
        "https://bloomberg-lookalike.example.com/markets",
    ],
)
def test_google_parent_transition_rejects_auth_routes_and_lookalikes(
    url: str,
    tmp_path: Path,
) -> None:
    assert _adapter(tmp_path)._parent_left_auth(ParentPage(url)) is False


def test_google_parent_transition_accepts_real_non_auth_route(tmp_path: Path) -> None:
    assert (
        _adapter(tmp_path)._parent_left_auth(
            ParentPage("https://www.bloomberg.com/markets")
        )
        is True
    )


def test_google_parent_transition_uses_configured_auth_paths(tmp_path: Path) -> None:
    base = load_provider_spec("bloomberg")
    auth = base.auth.model_copy(update={"auth_path_prefixes": ("/custom-auth",)})
    spec = base.model_copy(update={"auth": auth})
    adapter = BloombergAcquisitionAdapter(
        recipe=BloombergLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({}),
        spec=spec,
        clock=lambda: NOW,
    )

    assert (
        adapter._parent_left_auth(
            ParentPage("https://www.bloomberg.com/custom-auth/callback")
        )
        is False
    )
    assert (
        adapter._parent_left_auth(
            ParentPage("https://www.bloomberg.com/account/signin")
        )
        is True
    )


class PXLocator:
    def count(self) -> int:
        return 1

    def nth(self, index: int) -> PXLocator:
        return self

    def is_visible(self) -> bool:
        return True

    def bounding_box(self) -> dict[str, float]:
        return {"x": 10, "y": 10, "width": 100, "height": 40}


def _raw_challenge_detection(browser: object) -> ChallengeDetection:
    return ChallengeDetection.model_validate(browser.evaluate("fixture"))  # type: ignore[attr-defined]


class PXPage:
    url = "https://www.bloomberg.com/"
    frames: list[object] = []

    def __init__(self) -> None:
        self.interactive = True
        self.mouse = type(
            "Mouse",
            (),
            {
                "move": lambda self, x, y, steps: None,
                "down": lambda self: None,
                "up": lambda _self: setattr(self, "interactive", False),
            },
        )()

    def locator(self, selector: str) -> PXLocator:
        return PXLocator()

    def wait_for_timeout(self, milliseconds: float) -> None: ...


def test_perimeterx_prefers_the_interactive_hold_control_over_its_container() -> None:
    class Locator:
        def __init__(self, *, visible: bool, name: str) -> None:
            self.visible = visible
            self.name = name

        def count(self) -> int:
            return 1

        def nth(self, index: int) -> Locator:
            return self

        def is_visible(self) -> bool:
            return self.visible

    button = Locator(visible=True, name="button")
    container = Locator(visible=True, name="container")
    missing = Locator(visible=False, name="missing")

    class Page(NullPage):
        frames: list[object] = []

        def locator(self, selector: str) -> Locator:
            if selector == "button:has-text('Press & Hold')":
                return button
            if selector == "#px-captcha":
                return container
            return missing

    root, control = _hold_control(Page())

    assert isinstance(root, Page)
    assert control is button


def test_perimeterx_waits_for_generic_hold_widget_hydration() -> None:
    class GenericLocator(PXLocator):
        def __init__(self, *, visible: bool) -> None:
            self.visible = visible

        def is_visible(self) -> bool:
            return self.visible

    class HydratingPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.control = GenericLocator(visible=True)
            self.instruction_checks = 0

        def locator(self, selector: str) -> PXLocator:
            if selector == "#px-captcha":
                return self.control
            return GenericLocator(visible=False)

    def inner_text(*, timeout: int) -> str:
        assert timeout == 1_000
        page.instruction_checks += 1
        return "Press & Hold" if page.instruction_checks >= 2 else ""

    page = HydratingPage()
    page.control.inner_text = inner_text  # type: ignore[attr-defined]

    assert _hold_control(page) == (None, None)
    root, control = _hold_control(page)
    assert root is page
    assert isinstance(control, GenericLocator)


def test_perimeterx_generation_tracks_document_identity() -> None:
    root = type("Root", (), {"url": "https://fixture.test/challenge"})()
    replacement = type("Root", (), {"url": root.url})()

    before = _generation(root)
    after = _generation(root)

    assert before == after
    assert _generation(replacement) != before


def test_perimeterx_transient_missing_geometry_does_not_consume_hold() -> None:
    class TransientLocator(PXLocator):
        def __init__(self) -> None:
            self.box_calls = 0

        def bounding_box(self) -> dict[str, float] | None:
            self.box_calls += 1
            if self.box_calls == 1:
                return None
            return super().bounding_box()

    class TransientPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.control = TransientLocator()

        def locator(self, selector: str) -> PXLocator:
            return self.control

    page = TransientPage()

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            return {
                "vendor": "perimeterx",
                "state": "interactive" if page.interactive else "asset_only",
            }

    ticks = itertools.count(step=0.1)
    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=10,
        max_holds=1,
        hold_seconds=0.1,
        clock=lambda: next(ticks),
        sleep=lambda _seconds: None,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is True
    assert page.control.box_calls == 2


def test_perimeterx_hold_is_generation_bounded() -> None:
    page = PXPage()
    screenshots: list[str] = []
    moves: list[tuple[float, float, int]] = []
    pointer_scope: list[str] = []
    holds: list[dict[str, object]] = []

    class Pointer:
        def move(self, x: float, y: float, *, steps: int) -> None:
            moves.append((x, y, steps))

        def down(self) -> None: ...

        def up(self) -> None:
            page.interactive = False

    pointer = Pointer()

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 750
            screenshots.append(label)
            return True

        @contextmanager
        def challenge_pointer(self):  # noqa: ANN202
            pointer_scope.append("open")
            try:
                yield pointer
            finally:
                pointer_scope.append("closed")

        def evaluate(self, script: str):
            return {
                "vendor": "perimeterx",
                "state": "interactive" if page.interactive else "asset_only",
            }

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    ticks = itertools.count(step=0.1)
    mechanic = PerimeterXHoldMechanic(
        wall_budget_seconds=10,
        max_holds=1,
        hold_seconds=2,
        clock=lambda: next(ticks),
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    )

    browser = PXBrowser()
    result = mechanic.solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is True
    assert len(moves) > 19
    assert moves[0][2] == 3
    assert all(move[2] == 1 for move in moves[1:])
    assert pointer_scope == ["open", "closed"]
    assert any(label.startswith("px-1-before-") for label in screenshots)
    assert any(label.startswith("px-1-down-") for label in screenshots)
    assert any(label.startswith("px-1-pre-up-timeout-") for label in screenshots)
    assert any(label.startswith("px-1-released-timeout-") for label in screenshots)
    assert any(label.startswith("px-1-after") for label in screenshots)
    assert len(holds) == 1
    assert holds[0] == {
        "hold_index": 1,
        "pointer_backend": "other",
        "duration_seconds": pytest.approx(holds[0]["duration_seconds"]),
        "release_reason": "accepted",
        "post_settle_acceptance_source": "surface_clear",
        "retry_invited": False,
        "control_still_present": True,
        "generation_relation": "same",
        "final_surface_state": "cleared",
    }


def test_perimeterx_interrupted_hold_emits_one_terminal_event() -> None:
    page = PXPage()
    holds: list[dict[str, object]] = []

    def fail_release(_mouse) -> None:  # noqa: ANN001
        raise RuntimeError("private pointer failure")

    page.mouse = type(
        "Mouse",
        (),
        {
            "move": lambda self, x, y, steps: None,
            "down": lambda self: None,
            "up": fail_release,
        },
    )()

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    browser = PXBrowser()
    with pytest.raises(RuntimeError, match="private pointer failure"):
        PerimeterXHoldMechanic(
            wall_budget_seconds=2,
            max_holds=1,
            hold_seconds=0.1,
            clock=itertools.count(step=0.1).__next__,
            sleep=lambda _seconds: None,
            random_source=lambda: 0.5,
        ).solve(
            browser,
            StableSurfaceClearProbe(
                browser,
                ChallengeVendor.PERIMETERX,
                detector=_raw_challenge_detection,
                clock=itertools.count(step=0.5).__next__,
            ),
        )

    assert len(holds) == 1
    assert holds[0]["release_reason"] == "interrupted"
    assert holds[0]["post_settle_acceptance_source"] is None
    assert holds[0]["retry_invited"] is None
    assert holds[0]["control_still_present"] is None
    assert holds[0]["generation_relation"] == "unavailable"
    assert holds[0]["final_surface_state"] == "unknown"
    assert "private pointer failure" not in repr(holds)


def test_perimeterx_records_explicit_rejection_and_changed_generation() -> None:
    class VisibleControl(PXLocator):
        def inner_text(self, *, timeout: int) -> str:
            return "PRESS & HOLD"

    class MissingControl(PXLocator):
        def count(self) -> int:
            return 0

    class RejectionBody(PXLocator):
        def __init__(self) -> None:
            self.reads = 0

        def inner_text(self, *, timeout: int) -> str:
            self.reads += 1
            return (
                "Please try again\nPRESS & HOLD" if self.reads >= 5 else "PRESS & HOLD"
            )

    class ReplacementFrame:
        url = "https://www.bloomberg.com/replacement"

        def __init__(self) -> None:
            self.control = VisibleControl()

        def locator(self, selector: str) -> PXLocator:
            return self.control

    class ChangingPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.body = RejectionBody()
            self.control = VisibleControl()
            self.frames = []
            self.replacement = ReplacementFrame()

            def release(_mouse) -> None:  # noqa: ANN001
                self.frames = [self.replacement]

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": lambda self: None,
                    "up": release,
                },
            )()

        def locator(self, selector: str) -> PXLocator:
            if selector == "body":
                return self.body
            return self.control if not self.frames else MissingControl()

    page = ChangingPage()
    holds: list[dict[str, object]] = []

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=10,
        max_holds=1,
        hold_seconds=5,
        clock=itertools.count(step=0.25).__next__,
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    assert len(holds) == 1
    assert holds[0]["release_reason"] == "rejected"
    assert holds[0]["retry_invited"] is True
    assert holds[0]["control_still_present"] is True
    assert holds[0]["generation_relation"] == "changed"
    assert holds[0]["final_surface_state"] == "rejected"


def test_perimeterx_releases_when_the_visible_challenge_completes() -> None:
    class Body(PXLocator):
        def __init__(self) -> None:
            self.reads = 0

        def inner_text(self, *, timeout: int) -> str:
            assert timeout == 250
            self.reads += 1
            if self.reads < 2:
                return "Press & Hold"
            return "Human Challenge completed, please wait"

    class Control(PXLocator):
        def inner_text(self, *, timeout: int) -> str:
            assert timeout == 250
            return "PRESS & HOLD"

    class CompletingPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.body = Body()
            self.control = Control()
            self.releases = 0

            def release(_mouse) -> None:  # noqa: ANN001
                self.releases += 1
                self.interactive = False

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": lambda self: None,
                    "up": release,
                },
            )()

        def locator(self, selector: str) -> PXLocator:
            return self.body if selector == "body" else self.control

    page = CompletingPage()
    screenshots: list[str] = []

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 750
            screenshots.append(label)
            return True

        def evaluate(self, script: str):
            return {
                "vendor": "perimeterx",
                "state": "interactive" if page.interactive else "asset_only",
            }

    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=10,
        max_holds=1,
        hold_seconds=9,
        clock=itertools.count(step=0.1).__next__,
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is True
    assert page.releases == 1
    # Completion text is ignored for the residual-completion grace window, then
    # honored on a later poll once the hold has been under evaluation.
    assert page.body.reads >= 2
    assert any(label.startswith("px-1-before-") for label in screenshots)
    assert any(label.startswith("px-1-down-") for label in screenshots)
    assert any(label.startswith("px-1-pre-up-completed-") for label in screenshots)
    assert any(label.startswith("px-1-released-completed-") for label in screenshots)
    assert any(label.startswith("px-1-after") for label in screenshots)


def test_perimeterx_ignores_residual_completion_text_during_grace() -> None:
    """Stale completion copy from a prior hold must not end a fresh press early."""

    class ResidualBody(PXLocator):
        def inner_text(self, *, timeout: int) -> str:
            assert timeout == 250
            return "Human Challenge completed, please wait\nPRESS & HOLD"

    class ResidualControl(PXLocator):
        def inner_text(self, *, timeout: int) -> str:
            assert timeout == 250
            return "PRESS & HOLD"

    class ResidualPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.body = ResidualBody()
            self.control = ResidualControl()
            self.releases = 0
            self.clock_value = 0.0

            def release(_mouse) -> None:  # noqa: ANN001
                self.releases += 1
                self.release_at = self.clock_value

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": lambda self: None,
                    "up": release,
                },
            )()
            self.release_at = 0.0

        def locator(self, selector: str) -> PXLocator:
            return self.body if selector == "body" else self.control

    page = ResidualPage()
    clock_values = itertools.count(step=0.1)

    def clock() -> float:
        page.clock_value = next(clock_values)
        return page.clock_value

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            return True

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

    result = PerimeterXHoldMechanic(
        wall_budget_seconds=8,
        max_holds=1,
        hold_seconds=5,
        clock=clock,
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        PXBrowser(),
        StableSurfaceClearProbe(
            PXBrowser(),
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    assert page.releases == 1
    # Residual completion must wait out the grace window before release.
    assert page.release_at >= 2.0


def test_perimeterx_represses_when_completion_leaves_hold_control() -> None:
    """A checkmark that returns to Press & Hold must consume another hold."""

    class ToggleBody(PXLocator):
        def __init__(self) -> None:
            self.phase = "hold"
            self.reads = 0

        def inner_text(self, *, timeout: int) -> str:
            self.reads += 1
            # After a few polls past the residual-completion grace window, emit
            # completion so the first hold releases as COMPLETED while the
            # hold control remains visible.
            if self.phase == "complete" or self.reads >= 5:
                self.phase = "complete"
                return "Human Challenge completed, please wait"
            return "PRESS & HOLD"

    class ToggleControl(PXLocator):
        def is_visible(self) -> bool:
            return True

        def inner_text(self, *, timeout: int) -> str:
            return "PRESS & HOLD"

    class TogglePage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.body = ToggleBody()
            self.control = ToggleControl()
            self.downs = 0
            self.releases = 0
            self.clock_value = 0.0

            def down(_mouse) -> None:  # noqa: ANN001
                self.downs += 1
                # Fresh hold starts without completion signal.
                self.body.phase = "hold"
                self.body.reads = 0

            def release(_mouse) -> None:  # noqa: ANN001
                self.releases += 1
                # After settle the hold control remains, so the mechanic must
                # re-press with remaining budget instead of closing the generation.
                self.body.phase = "hold"
                self.body.reads = 0

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": down,
                    "up": release,
                },
            )()

        def locator(self, selector: str) -> PXLocator:
            if selector == "body":
                return self.body
            if selector in {
                "button:has-text('Press & Hold')",
                "button:has-text('Press and Hold')",
                "[role='button']:has-text('Press & Hold')",
                "[role='button']:has-text('Press and Hold')",
                "#px-captcha",
                "[data-px-captcha]",
            }:
                return self.control
            return PXLocator()

    page = TogglePage()
    holds: list[dict[str, object]] = []
    clock_values = itertools.count(step=0.25)

    def clock() -> float:
        page.clock_value = next(clock_values)
        return page.clock_value

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            return True

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=40,
        max_holds=2,
        hold_seconds=5,
        clock=clock,
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    assert page.downs == 2
    assert page.releases == 2
    assert [hold["hold_index"] for hold in holds] == [1, 2]
    assert all(hold["release_reason"] == "completed" for hold in holds)
    assert all(
        hold["final_surface_state"] == "completed_control_present" for hold in holds
    )
    assert all(hold["generation_relation"] == "same" for hold in holds)


def test_perimeterx_returns_control_when_document_generation_stays_stale() -> None:
    page = PXPage()
    waits: list[float] = []
    releases = 0

    def release(_mouse) -> None:  # noqa: ANN001
        nonlocal releases
        releases += 1

    page.mouse = type(
        "Mouse",
        (),
        {
            "move": lambda self, x, y, steps: None,
            "down": lambda self: None,
            "up": release,
        },
    )()
    page.wait_for_timeout = lambda milliseconds: waits.append(milliseconds)  # type: ignore[method-assign]

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

    ticks = itertools.count(step=0.1)
    mechanic = PerimeterXHoldMechanic(
        wall_budget_seconds=10,
        max_holds=1,
        hold_seconds=0.1,
        clock=lambda: next(ticks),
        sleep=lambda _seconds: None,
    )

    browser = PXBrowser()
    result = mechanic.solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    assert releases == 1
    assert waits
    assert all(wait == 250 for wait in waits)


def test_perimeterx_keeps_holding_through_processing_spinner() -> None:
    """Text-scoped control goes dark while the spinner runs; keep the hold."""

    class SpinnerControl(PXLocator):
        def __init__(self) -> None:
            self.text_reads = 0

        def is_visible(self) -> bool:
            # After the first poll the Press & Hold label is replaced by the
            # processing spinner, so a has-text locator reports not-visible.
            return self.text_reads <= 1

        def inner_text(self, *, timeout: int) -> str:
            self.text_reads += 1
            return "PRESS & HOLD" if self.text_reads <= 1 else ""

    class SpinnerBody(PXLocator):
        def inner_text(self, *, timeout: int) -> str:
            # Spinner root may be an iframe without the parent page copy.
            return ""

    class SpinnerPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.control = SpinnerControl()
            self.body = SpinnerBody()
            self.releases = 0
            self.release_times: list[float] = []
            self.clock_value = 0.0

            def release(_mouse) -> None:  # noqa: ANN001
                self.releases += 1
                self.release_times.append(self.clock_value)

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": lambda self: None,
                    "up": release,
                },
            )()

        def locator(self, selector: str) -> PXLocator:
            if selector == "body":
                return self.body
            if selector in {
                "button:has-text('Press & Hold')",
                "button:has-text('Press and Hold')",
                "[role='button']:has-text('Press & Hold')",
                "[role='button']:has-text('Press and Hold')",
            }:
                return self.control
            if selector in {"#px-captcha", "[data-px-captcha]"}:
                return self.control
            return PXLocator()

    page = SpinnerPage()
    screenshots: list[str] = []
    holds: list[dict[str, object]] = []
    clock_values = itertools.count(step=0.1)

    def clock() -> float:
        page.clock_value = next(clock_values)
        return page.clock_value

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            assert timeout_ms == 750
            screenshots.append(label)
            return True

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=5,
        max_holds=1,
        hold_seconds=1.0,
        clock=clock,
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    assert page.releases == 1
    # Invisible / empty control text alone must not end the hold early: the
    # pointer stays down until the configured hold budget elapses.
    assert page.control.text_reads > 2
    assert page.release_times and page.release_times[0] >= 1.0
    assert any(label.startswith("px-1-before-") for label in screenshots)
    assert any(label.startswith("px-1-released-timeout-") for label in screenshots)
    assert _hold_release_signal(page, page.control) is None
    assert len(holds) == 1
    assert holds[0]["release_reason"] == "timeout"
    assert holds[0]["final_surface_state"] == "spinner_or_loading"


def test_perimeterx_retries_same_generation_after_rejection() -> None:
    class RejectingBody(PXLocator):
        def __init__(self) -> None:
            self.phase = "initial"

        def inner_text(self, *, timeout: int) -> str:
            if self.phase == "initial":
                # Residual rejection text from a prior attempt sits on the
                # surface before the new hold is evaluated.
                return "Please try again\nPRESS & HOLD"
            if self.phase == "processing":
                return "PRESS & HOLD"
            return "Please try again\nPRESS & HOLD"

    class RejectingControl(PXLocator):
        def is_visible(self) -> bool:
            return True

        def inner_text(self, *, timeout: int) -> str:
            return "PRESS & HOLD"

    class RejectingPage(PXPage):
        def __init__(self) -> None:
            super().__init__()
            self.body = RejectingBody()
            self.control = RejectingControl()
            self.releases = 0
            self.downs = 0

            def down(_mouse) -> None:  # noqa: ANN001
                self.downs += 1
                # Clear residual rejection once the new press begins.
                self.body.phase = "processing"

            def release(_mouse) -> None:  # noqa: ANN001
                self.releases += 1
                self.body.phase = "rejected"

            self.mouse = type(
                "Mouse",
                (),
                {
                    "move": lambda self, x, y, steps: None,
                    "down": down,
                    "up": release,
                },
            )()

        def locator(self, selector: str) -> PXLocator:
            if selector == "body":
                return self.body
            return self.control

    page = RejectingPage()
    screenshots: list[str] = []
    holds: list[dict[str, object]] = []

    class PXBrowser:
        def __init__(self) -> None:
            self.page = page

        def capture_diagnostic_screenshot(
            self,
            label: str,
            *,
            timeout_ms: int,
        ) -> bool:
            screenshots.append(label)
            return True

        def evaluate(self, script: str):
            return {"vendor": "perimeterx", "state": "interactive"}

        def record_perimeterx_hold(self, **facts: object) -> None:
            holds.append(facts)

    ticks = itertools.count(step=0.05)
    browser = PXBrowser()
    result = PerimeterXHoldMechanic(
        wall_budget_seconds=20,
        max_holds=2,
        hold_seconds=2.0,
        clock=lambda: next(ticks),
        sleep=lambda _seconds: None,
        random_source=lambda: 0.5,
    ).solve(
        browser,
        StableSurfaceClearProbe(
            browser,
            ChallengeVendor.PERIMETERX,
            detector=_raw_challenge_detection,
            clock=itertools.count(step=0.5).__next__,
        ),
    )

    assert result.accepted is False
    # Residual rejection text must not abort the first press immediately, and
    # the same generation must be re-pressed after the provider invites retry.
    assert page.downs == 2
    assert page.releases == 2
    assert any(label.startswith("px-1-released-") for label in screenshots)
    assert any(label.startswith("px-2-released-") for label in screenshots)
    assert _hold_release_signal(page, page.control) is _HoldReleaseReason.REJECTED
    assert len(holds) == 2
    assert all(hold["retry_invited"] is True for hold in holds)
    assert all(hold["final_surface_state"] == "rejected" for hold in holds)


def test_a_blocked_callback_records_what_the_probe_saw(monkeypatch) -> None:
    """`cleared=False` alone cannot say why.

    A defense that re-blocked a browser it had just accepted, one that never
    issued a clearance token, and an endpoint answering something unexpected
    all produced the same `challenge_blocked` verdict with no way to tell them
    apart. Acceptance followed by an endpoint's 403 needs its own evidence.
    """

    from newsclip.providers.bloomberg_auth import _PERIMETERX_CLEARANCE_COOKIES

    # A device cookie is issued while blocking, so it must not read as trust.
    assert "_pxhd" not in _PERIMETERX_CLEARANCE_COOKIES
    assert "_px3" in _PERIMETERX_CLEARANCE_COOKIES

    blocked = _cleared_callback(False)
    assert blocked.cleared is False
    assert blocked.probe_status == 403
    assert blocked.clearance_cookie_present is False


def test_the_clearance_observation_is_reported_before_the_restore(
    tmp_path: Path, monkeypatch
) -> None:
    """The reading must be taken while the context is still alive.

    0.3.17 recorded it after the probe's restore navigation and its challenge
    sweep, which run against a context the settle loop may already have lost:
    the cookie read failed, the best-effort recorder swallowed it, and a run
    that reached the probe produced no observation at all.
    """

    class CallbackPage(ParentPage):
        def __init__(self) -> None:
            super().__init__()
            self.probes = 0

        def goto(self, url: str, **kwargs) -> object:
            self.url = url
            if url.endswith("/google-auth"):
                self.probes += 1
                if self.probes == 1:
                    return type("Response", (), {"status": 403})()
            # The settle loop losing the context is the case that produced no
            # observation at all.
            raise RuntimeError("target closed")

    page = CallbackPage()
    browser = FakeBrowser()
    browser.page = page
    adapter = _adapter(tmp_path)

    monkeypatch.setattr(
        adapter,
        "_resolve_challenge",
        lambda *args, **kwargs: type(
            "Resolution",
            (),
            {"status": ChallengeResolutionStatus.CLEARED, "reason": None},
        )(),
    )

    seen: list = []
    with pytest.raises(RuntimeError, match="target closed"):
        adapter._resolve_google_callback_challenge(
            browser,
            original=page,
            challenge_mode=ChallengeMode.AUTO,
            observe=seen.append,
        )

    assert len(seen) == 1
    assert seen[0].probe_status == 403
    assert seen[0].cleared is False


class _TracePage:
    """Minimal page the handoff recorder can read parent state from."""

    url = "https://login.bloomberg.com/"

    def is_closed(self) -> bool:
        return False

    def wait_for_timeout(self, milliseconds: int) -> None: ...


class _TraceContext:
    def __init__(self) -> None:
        self.pages = [_TracePage()]

    def cookies(self) -> list[dict[str, object]]:
        return []

    def close(self) -> None: ...


def test_clearance_facts_reach_the_trace_file(tmp_path: Path) -> None:
    """End to end through the real recorder, not a stand-in.

    The adapter builds a fact dict and the runtime recorder takes explicit
    keywords, so a fact the event models but the recorder does not accept
    raises TypeError into `_record_identity_handoff`'s deliberate catch-all
    and vanishes. Twice that shipped. A stub recorder cannot catch it — this
    drives the real one and reads the trace back off disk.
    """

    import json

    from newsclip.browser_runtime.events import (
        AttemptPurpose,
        IdentityHandoffCheckpoint,
        RuntimeTrace,
    )
    from newsclip.browser_runtime.runtime import PatchrightRuntime
    from newsclip.providers.bloomberg_auth import _CallbackClearance

    path = tmp_path / "traces" / "runtime.jsonl"
    runtime = PatchrightRuntime(
        context_factory=lambda **_kwargs: _TraceContext(),
        trace=RuntimeTrace(path, run_id="runtime-clearance"),
    )
    adapter = _adapter(tmp_path)

    with (
        runtime.open(tmp_path / "profile", require_virtual_display=False) as browser,
        browser.attempt("bloomberg", AttemptPurpose.LOGIN),
    ):
        adapter._record_identity_handoff(
            browser,
            original=browser.page,
            checkpoint=IdentityHandoffCheckpoint.CALLBACK_RETRY,
            identity_result=_google_result(CredentialAction.GOOGLE_TOTP_SUBMIT),
            callback_confirmed=False,
            clearance=_CallbackClearance(
                cleared=False,
                probe_status=403,
                clearance_cookie_present=False,
            ),
        )

    rows = [json.loads(line) for line in path.read_text().splitlines()]
    handoffs = [row for row in rows if row["event"] == "identity_handoff"]
    assert len(handoffs) == 1, "the handoff was swallowed before reaching the trace"
    assert handoffs[0]["facts"]["callback_probe_status"] == 403
    assert handoffs[0]["facts"]["callback_clearance_cookie_present"] is False
