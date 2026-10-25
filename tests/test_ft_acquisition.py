from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

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
from newsclip.browser_runtime import (
    MouseTarget,
    ObservedNavigation,
    PasskeyMode,
    PatchrightMintContext,
)
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceSource,
    ChallengeInfrastructureError,
    ChallengeVendor,
)
from newsclip.login import LoginInfrastructureError
from newsclip.models import MintOutcome
from newsclip.provider_config import load_provider_spec
from newsclip.providers.ft_auth import (
    _SESSION_CALLBACK_TIMEOUT_SECONDS,
    FTAcquisitionAdapter,
    FTAuthRequest,
    FTNativeTokenProbe,
    FTNetworkObserver,
    FTSubmitLedger,
)
from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()


class FakeRequest:
    method = "POST"
    url = "https://accounts.ft.com/login"

    def __init__(self, post_data: str) -> None:
        self.post_data = post_data


class FakeResponse:
    def __init__(self, request: FakeRequest, status: int) -> None:
        self.request = request
        self.status = status


class NullLocator:
    def count(self) -> int:
        return 0


class FakePage:
    def __init__(self) -> None:
        self.handlers: dict[str, list[Callable[[object], None]]] = {}
        self.url = "https://www.ft.com/"

    def content(self) -> str:
        return "<html><body>Fixture article</body></html>"

    def on(self, event: str, handler: Callable[[object], None]) -> None:
        self.handlers.setdefault(event, []).append(handler)

    def remove_listener(self, event: str, handler: Callable[[object], None]) -> None:
        self.handlers[event].remove(handler)

    def emit(self, event: str, value: object) -> None:
        for handler in tuple(self.handlers.get(event, ())):
            handler(value)

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()


class FakeBrowser:
    def __init__(
        self,
        observations: list[dict[str, bool]],
        *,
        cookies: list[dict[str, object]] | None = None,
        native_acceptance: dict[str, object] | None = None,
        on_submit: Callable[[FakeBrowser, int], None] | None = None,
        on_wait: Callable[[FakeBrowser, int], None] | None = None,
        on_optional_click: Callable[[FakeBrowser, tuple[str, ...]], bool] | None = None,
        geometry_available: bool = True,
        challenge_vendor: str = "none",
        challenge_state: str = "none",
    ) -> None:
        self.observations = list(observations)
        self._last_observation = observations[-1] if observations else {}
        self.cookie_values = list(cookies or [])
        self.native_acceptance = native_acceptance or {
            "accepted": False,
            "source": "none",
        }
        self.on_submit = on_submit
        self.on_wait = on_wait
        self.waits = 0
        self.on_optional_click = on_optional_click
        self.optional_clicks: list[tuple[str, ...]] = []
        self.geometry_available = geometry_available
        self.challenge_vendor = challenge_vendor
        self.challenge_state = challenge_state
        self.page = FakePage()
        self.actions: list[str] = []
        self.submissions = 0

    def navigate(self, url: str) -> None:
        self.actions.append("navigate")

    def navigate_observed(
        self, url: str, *, timeout_seconds: float
    ) -> ObservedNavigation:
        self.navigate(url)
        self.page.url = url
        return ObservedNavigation(200, url, "text/html")

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        assert mode is PasskeyMode.EMPTY_PRESENT
        self.actions.append("suppress_passkeys")
        return True

    def click_optional(self, selectors) -> bool:
        normalized = tuple(selectors)
        self.optional_clicks.append(normalized)
        if self.on_optional_click is not None:
            return self.on_optional_click(self, normalized)
        return False

    def wait(self, seconds: float) -> None:
        self.waits += 1
        if self.on_wait:
            self.on_wait(self, self.waits)

    def evaluate(self, expression: str):
        if "exact_widget_api" in expression:
            return self.native_acceptance
        if "datadomeAsset" in expression:
            return {
                "vendor": self.challenge_vendor,
                "state": self.challenge_state,
            }
        # FT enter-email native form submit bypass (does not consume observations).
        if (
            "HTMLFormElement.prototype.submit" in expression
            or "email-form" in expression
        ):
            self.actions.append("native_form_submit")
            return "submitted"
        if self.observations:
            self._last_observation = self.observations.pop(0)
        return self._last_observation

    def cookies(self) -> list[dict[str, object]]:
        return list(self.cookie_values)

    def user_agent(self) -> str:
        return "FixtureBrowser/1.0"

    def mouse_target(self, selectors) -> MouseTarget:
        self.actions.append("geometry")
        if not self.geometry_available:
            raise RuntimeError("fixture geometry unavailable")
        return MouseTarget(10, 20)

    def mouse_click(self, target: MouseTarget) -> None:
        self.actions.append("mouse_click")
        self.submissions += 1
        if self.on_submit:
            self.on_submit(self, self.submissions)

    def click(self, selectors) -> None:
        # Username Next uses Playwright click; password still uses mouse_click
        # (pointer path). Keep submission accounting on mouse_click only so
        # fixture on_submit handlers model the token-bearing password POST.
        self.actions.append("click")

    def press(self, selectors, key: str) -> None:
        self.actions.append(f"press:{key}")


class FakeSecrets:
    def __init__(self) -> None:
        self.fields: list[str] = []
        self.all_visible: list[bool] = []

    def fill(
        self,
        browser,
        *,
        field: str,
        all_visible: bool = False,
        **kwargs,
    ) -> None:
        self.fields.append(field)
        self.all_visible.append(all_visible)


class UnavailableSecrets(FakeSecrets):
    def fill(self, browser, *, field: str, **kwargs) -> None:
        raise LoginInfrastructureError("fixture unavailable")


class AcceptedMechanic:
    vendor = ChallengeVendor.HCAPTCHA

    def __init__(self) -> None:
        self.calls = 0

    def solve(self, browser, acceptance) -> ChallengeAcceptance:
        self.calls += 1
        browser.native_acceptance = {
            "accepted": True,
            "source": "existing_form_field",
        }
        return acceptance.observe()


class UnavailableHCaptchaMechanic:
    vendor = ChallengeVendor.HCAPTCHA

    def solve(self, browser, acceptance) -> ChallengeAcceptance:  # noqa: ARG002
        raise ChallengeInfrastructureError("fixture planner unavailable")


def _session_cookie() -> dict[str, object]:
    return {
        "name": "FTSession_fixture",
        "value": "SESSION_VALUE",
        "domain": ".ft.com",
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
    mechanic: AcceptedMechanic | None = None,
) -> FTAcquisitionAdapter:
    return FTAcquisitionAdapter(
        secrets=secrets,
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.HCAPTCHA: mechanic} if mechanic is not None else {}
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
def test_ft_cookie_export_failures_have_stable_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[SessionCookieError],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise error_type("fixture cookie failure")

    monkeypatch.setattr(
        "newsclip.providers.ft_auth.normalize_browser_cookie_export", fail
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._candidate(
            FakeBrowser([], cookies=[_session_cookie()]),
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is category


@pytest.mark.parametrize(
    "defect", ("missing_control", "unknown_observation", "cookie_proof", "token_probe")
)
def test_ft_auth_surface_contract_is_owned_by_ft(defect: str, tmp_path: Path) -> None:
    spec = load_provider_spec("ft")
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
    elif defect == "token_probe":
        auth = auth.model_copy(update={"token_probe": None})
    else:
        session = session.model_copy(update={"session_cookie_name_prefixes": ()})
    selected = spec.model_copy(update={"auth": auth, "session": session})

    with pytest.raises(ValueError, match="authentication|cookie"):
        FTAcquisitionAdapter(
            challenge_resolver=ChallengeResolver({}),
            spec=selected,
        )


def _emit_auth(
    browser: FakeBrowser,
    *,
    token: bool,
    status: int = 200,
) -> None:
    token_value = "T" * 40 if token else ""
    request = FakeRequest(f"password=p&h-captcha-response={token_value}")
    browser.page.emit("request", request)
    browser.page.emit("response", FakeResponse(request, status))


def test_acceptance_schema_is_closed_and_internally_consistent() -> None:
    with pytest.raises(ValidationError):
        ChallengeAcceptance(accepted=True, source="none")
    with pytest.raises(ValidationError):
        ChallengeAcceptance(accepted=False, source="surface_clear")
    with pytest.raises(ValidationError):
        ChallengeAcceptance(accepted=True, source="invented")
    with pytest.raises(ValidationError):
        ChallengeAcceptance(
            accepted=True,
            source="exact_widget_api",
            token_length=40,
        )


def test_native_probe_accepts_only_bounded_owned_sources(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [],
        native_acceptance={
            "accepted": True,
            "source": "exact_widget_api",
        },
    )
    assert FTNativeTokenProbe(browser).observe() == ChallengeAcceptance(
        accepted=True,
        source=ChallengeAcceptanceSource.EXACT_WIDGET_API,
    )
    browser.native_acceptance = {
        "accepted": True,
        "source": "surface_clear",
    }
    assert FTNativeTokenProbe(browser).observe() == ChallengeAcceptance(
        accepted=False,
        source=ChallengeAcceptanceSource.NONE,
    )


@pytest.mark.parametrize(
    "native_acceptance",
    [
        None,
        {"accepted": "true", "source": "exact_widget_api"},
        {"accepted": True, "source": "unknown"},
    ],
)
def test_native_probe_maps_evaluation_and_contract_failures_to_infrastructure(
    native_acceptance: dict[str, object] | None,
) -> None:
    class ProbeBrowser(FakeBrowser):
        def evaluate(self, script: str):
            if native_acceptance is None:
                raise RuntimeError("fixture execution context disappeared")
            return native_acceptance

    with pytest.raises(ChallengeInfrastructureError, match="native challenge"):
        FTNativeTokenProbe(ProbeBrowser([])).observe()


def test_ft_maps_native_probe_failure_to_retryable_challenge_failure(
    tmp_path: Path,
) -> None:
    class ProbeBrowser(FakeBrowser):
        def evaluate(self, script: str):
            if "datadomeAsset" in script:
                return {"vendor": "none", "state": "none"}
            raise RuntimeError("fixture execution context disappeared")

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._resolve_challenge(ProbeBrowser([]), ChallengeMode.AUTO)

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE


def test_ft_maps_challenge_infrastructure_to_retryable_failure(
    tmp_path: Path,
) -> None:
    browser = FakeBrowser(
        [],
        challenge_vendor="hcaptcha",
        challenge_state="interactive",
    )
    adapter = FTAcquisitionAdapter(
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.HCAPTCHA: UnavailableHCaptchaMechanic()}
        ),
        clock=lambda: NOW,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter._resolve_challenge(browser, ChallengeMode.AUTO)

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE


def test_request_linked_observer_attributes_response_and_token() -> None:
    page = FakePage()
    ledger = FTSubmitLedger()
    callback_facts: list[dict[str, object]] = []
    observer = FTNetworkObserver(
        page,
        ledger,
        record_callback=lambda **facts: callback_facts.append(facts),
    )
    observer.attach()
    ledger.claim_submit(1)
    observer.set_sequence(1)
    first = FakeRequest("password=p&h-captcha-response=")
    page.emit("request", first)
    ledger.claim_submit(2)
    observer.set_sequence(2)
    second = FakeRequest("password=p&h-captcha-response=" + "T" * 40)
    page.emit("request", second)
    page.emit("response", FakeResponse(first, 502))
    page.emit("response", FakeResponse(second, 200))

    assert observer.requests_for(1)[0].token_present is False
    assert observer.requests_for(1)[0].credential_present is True
    assert observer.requests_for(2)[0].token_present is True
    assert observer.requests_for(2)[0].credential_present is True
    assert observer.has_upstream_error(1) is True
    assert observer.has_upstream_error(2) is False
    assert ledger.token_post_claimed is True
    assert observer.has_successful_token_callback(1) is False
    assert observer.has_successful_token_callback(2) is True
    assert callback_facts == [
        {
            "sequence": 1,
            "credential_present": True,
            "challenge_token_present": False,
            "status_class": "server_error",
        },
        {
            "sequence": 2,
            "credential_present": True,
            "challenge_token_present": True,
            "status_class": "success",
        },
    ]


def test_request_observer_classifies_encoded_values_without_retaining_them() -> None:
    page = FakePage()
    ledger = FTSubmitLedger()
    observer = FTNetworkObserver(page, ledger)
    observer.attach()
    ledger.claim_submit(1)
    observer.set_sequence(1)

    request = FakeRequest("password=p%40ssword&h-captcha-response=" + "%41" * 21)
    page.emit("request", request)

    assert observer.requests == [
        FTAuthRequest(
            sequence=1,
            method="POST",
            credential_present=True,
            token_present=True,
        )
    ]
    assert all(not hasattr(fact, "post_data") for fact in observer.requests)


def test_retained_profile_session_wins_over_accounts_form(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [{"password_visible": True, "authenticated": True}],
        cookies=[_session_cookie()],
    )

    candidate = _adapter(tmp_path).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert (
        candidate.candidate_verification_mode
        is CandidateVerificationMode.BROWSER_PAID_PROBE
    )
    assert candidate.verification_fetch is not None
    assert candidate.evidence.session_proof_observed is False
    assert candidate.artifact.user_agent == "FixtureBrowser/1.0"
    assert browser.actions[:2] == ["navigate", "navigate"]


@pytest.mark.parametrize(
    ("fixture", "status", "verified"),
    [("full.html", 200, True), ("teaser.html", 200, False), ("full.html", 403, False)],
)
def test_browser_candidate_requires_independent_full_response_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    status: int,
    verified: bool,
) -> None:
    adapter = _adapter(tmp_path)
    browser = FakeBrowser([{}], cookies=[_session_cookie()])
    url = adapter._recipe.verification_url
    body = (Path(__file__).parent / "fixtures" / "ft" / fixture).read_text()
    body = body.replace("11111111-1111-4111-8111-111111111111", url.rsplit("/", 1)[-1])
    monkeypatch.setattr(browser.page, "content", lambda: body)

    def navigate(target: str, *, timeout_seconds: float) -> ObservedNavigation:
        browser.page.url = target
        return ObservedNavigation(status, target, "text/html")

    monkeypatch.setattr(browser, "navigate_observed", navigate)
    candidate = adapter._candidate(
        browser,
        account_key="default",
        mode=AcquisitionMode.CREDENTIAL_MINT,
        credential_action=CredentialAction.PASSWORD_SUBMIT,
    )
    assert candidate.verification_fetch is not None
    assert candidate.evidence.session_proof_observed is False
    proof = adapter._recipe.verify_fetch(candidate.verification_fetch)
    assert proof.verified is verified


def test_retained_profile_rehydrates_without_secret_resolution(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [{"authenticated": True}],
        cookies=[_session_cookie()],
    )

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert secrets.fields == []


def test_detect_only_blocks_before_invoking_hcaptcha_mechanic(tmp_path: Path) -> None:
    mechanic = AcceptedMechanic()
    browser = FakeBrowser(
        [{"username_visible": True}],
        challenge_vendor="hcaptcha",
        challenge_state="interactive",
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, mechanic=mechanic).rehydrate_profile(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert mechanic.calls == 0


def test_session_cookie_proof_uses_the_provider_definition(tmp_path: Path) -> None:
    base = load_provider_spec("ft")
    session = base.session.model_copy(
        update={"session_cookie_name_prefixes": ("configured_session",)}
    )
    spec = base.model_copy(update={"session": session})
    adapter = FTAcquisitionAdapter(
        challenge_resolver=ChallengeResolver({}),
        spec=spec,
        clock=lambda: NOW,
    )

    assert adapter._has_ft_session(
        [{"name": "configured_session_123", "domain": ".ft.com"}]
    )
    assert not adapter._has_ft_session(
        [{"name": "FTSession_legacy", "domain": ".ft.com"}]
    )


def test_password_submit_geometry_precedes_claim_and_dispatch(tmp_path: Path) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [{"password_visible": True}],
        geometry_available=False,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE
    assert browser.actions[-1] == "geometry"
    assert browser.submissions == 0
    assert secrets.fields == ["password"]


def test_secret_delivery_failure_has_a_distinct_bounded_category(
    tmp_path: Path,
) -> None:
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


def test_username_and_password_use_resolved_pointer_submission(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        if submit == 1:
            _emit_auth(browser, token=False)
            browser.cookie_values = [_session_cookie()]

    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
        ],
        on_submit=on_submit,
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert secrets.fields == ["username", "password"]
    # Email uses single-field fill(); password still uses fill_all_visible.
    assert secrets.all_visible == [False, True]
    assert browser.actions == [
        "native_form_submit",
        "geometry",
        "mouse_click",
        "navigate",
    ]
    assert browser.submissions == 1


def test_password_transition_allows_a_bounded_slow_provider_response(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        if submit == 1:
            _emit_auth(browser, token=False)
            browser.cookie_values = [_session_cookie()]

    browser = FakeBrowser(
        [
            *({"username_visible": True} for _ in range(42)),
            {"password_visible": True},
            {"authenticated": True},
        ],
        on_submit=on_submit,
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert secrets.fields == ["username", "password"]
    assert browser.submissions == 1
    assert "native_form_submit" in browser.actions


def test_password_submit_waits_for_native_hcaptcha_acceptance(tmp_path: Path) -> None:
    def on_wait(browser: FakeBrowser, wait: int) -> None:
        if wait == 3:
            browser.native_acceptance = {
                "accepted": True,
                "source": "existing_form_field",
            }

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        assert submit == 1
        _emit_auth(browser, token=True)
        browser.cookie_values = [_session_cookie()]

    browser = FakeBrowser(
        [{"password_visible": True}, {"authenticated": True}],
        on_submit=on_submit,
        on_wait=on_wait,
        challenge_vendor="hcaptcha",
        challenge_state="asset_only",
    )

    candidate = _adapter(tmp_path, secrets=FakeSecrets()).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert candidate.evidence.callback_confirmed is True
    assert browser.waits >= 3
    assert browser.submissions == 1


def test_password_challenge_settle_has_a_bounded_injection_grace(
    tmp_path: Path,
) -> None:
    browser = FakeBrowser([])

    _adapter(tmp_path)._settle_password_challenge(browser, ChallengeMode.AUTO)

    assert browser.waits == 15


def test_sequence_one_token_race_suppresses_second_submit(tmp_path: Path) -> None:
    def on_submit(browser: FakeBrowser, submit: int) -> None:
        assert submit == 1
        _emit_auth(browser, token=True)
        browser.cookie_values = [_session_cookie()]

    browser = FakeBrowser(
        [{"password_visible": True}, {"authenticated": True}],
        on_submit=on_submit,
    )

    candidate = _adapter(tmp_path, secrets=FakeSecrets()).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert candidate.evidence.callback_confirmed is True
    assert browser.actions[-3:] == ["geometry", "mouse_click", "navigate"]
    assert browser.submissions == 1


def test_success_response_waits_for_asynchronous_session_cookie(tmp_path: Path) -> None:
    def on_wait(browser: FakeBrowser, wait: int) -> None:
        if wait == 3:
            browser.cookie_values = [_session_cookie()]

    browser = FakeBrowser(
        [
            {"password_visible": True},
            {"password_visible": True},
            {"authenticated": True},
        ],
        on_wait=on_wait,
    )
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    network.attach()
    network.set_sequence(1)
    _emit_auth(browser, token=False, status=200)

    try:
        candidate = _adapter(tmp_path)._await_session(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
            ledger=ledger,
            network=network,
        )
    finally:
        network.detach()

    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert candidate.evidence.callback_confirmed is False
    assert browser.waits >= 3


def test_transient_captcha_rejection_waits_for_interactive_challenge(
    tmp_path: Path,
) -> None:
    mechanic = AcceptedMechanic()

    def on_wait(browser: FakeBrowser, wait: int) -> None:
        if wait == 2:
            browser.challenge_state = "interactive"

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        assert submit == 1
        _emit_auth(browser, token=True)
        browser.cookie_values = [_session_cookie()]
        browser.challenge_vendor = "none"
        browser.challenge_state = "none"

    browser = FakeBrowser(
        [
            {"password_visible": True, "captcha_rejected": True},
            {"password_visible": True, "captcha_rejected": True},
            {"authenticated": True},
        ],
        on_submit=on_submit,
        on_wait=on_wait,
        challenge_vendor="hcaptcha",
        challenge_state="asset_only",
    )
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    network.attach()
    network.set_sequence(1)
    _emit_auth(browser, token=False, status=200)

    try:
        candidate = _adapter(tmp_path, mechanic=mechanic)._await_session(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
            ledger=ledger,
            network=network,
        )
    finally:
        network.detach()

    assert candidate.evidence.callback_confirmed is True
    assert mechanic.calls == 1
    assert browser.submissions == 1


def test_post_login_passkey_offer_is_declined_before_session_export(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    passkey_skip = adapter._auth.control("passkey_skip")

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        assert submit == 1
        _emit_auth(browser, token=True)

    def on_optional_click(browser: FakeBrowser, selectors: tuple[str, ...]) -> bool:
        if selectors != passkey_skip:
            return False
        browser.cookie_values = [_session_cookie()]
        return True

    browser = FakeBrowser(
        [{"password_visible": True}, {"authenticated": True}],
        on_submit=on_submit,
        on_optional_click=on_optional_click,
    )

    candidate = adapter.mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate.evidence.callback_confirmed is True
    assert passkey_skip in browser.optional_clicks


@pytest.mark.parametrize("cookie_before_offer", [False, True])
def test_passkey_offer_after_long_challenge_is_declined_before_deadline_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cookie_before_offer: bool,
) -> None:
    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    passkey_skip = adapter._auth.control("passkey_skip")
    passkey_ready = False
    passkey_declined = False
    challenge_finished = False

    def on_optional_click(browser: FakeBrowser, selectors: tuple[str, ...]) -> bool:
        nonlocal passkey_declined
        if selectors != passkey_skip or not passkey_ready:
            return False
        passkey_declined = True
        browser.cookie_values = [_session_cookie()]
        return True

    def on_wait(_browser: FakeBrowser, _wait: int) -> None:
        nonlocal passkey_ready
        if challenge_finished:
            passkey_ready = True

    browser = FakeBrowser(
        [{}],
        on_optional_click=on_optional_click,
        on_wait=on_wait,
    )
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    network.attach()
    network.set_sequence(1)
    _emit_auth(browser, token=True, status=302)
    times = iter((0.0, 1.0, _SESSION_CALLBACK_TIMEOUT_SECONDS + 1.0))
    monkeypatch.setattr(
        "newsclip.providers.ft_auth.time.monotonic", lambda: next(times)
    )

    def resolve_challenge(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal challenge_finished
        challenge_finished = True
        if cookie_before_offer:
            browser.cookie_values = [_session_cookie()]
        raise AcquisitionFailure(
            MintOutcome.CHALLENGE_BLOCKED,
            MintFailureEvidence(
                stage=MintFailureStage.CHALLENGE,
                category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
            ),
        )

    monkeypatch.setattr(adapter, "_resolve_challenge", resolve_challenge)

    try:
        candidate = adapter._await_session(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
            ledger=ledger,
            network=network,
        )
    finally:
        network.detach()

    assert candidate.evidence.callback_confirmed is True
    assert passkey_declined
    assert browser.optional_clicks[-1] == passkey_skip


def test_callback_passkey_transition_tolerates_bounded_context_replacement(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path, secrets=FakeSecrets())
    passkey_skip = adapter._auth.control("passkey_skip")

    class ContextRaceBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{}],
                on_optional_click=self._click_passkey,
            )
            self.context_failures = 4
            self.passkey_ready = False
            self.context_waits: list[int] = []
            page = SimpleNamespace(
                evaluate=self._page_evaluate,
                wait_for_timeout=self._page_wait,
            )
            self._runtime_observer = PatchrightMintContext(
                SimpleNamespace(),
                page,
            )

        def _click_passkey(
            self,
            _browser: FakeBrowser,
            selectors: tuple[str, ...],
        ) -> bool:
            if selectors != passkey_skip or not self.passkey_ready:
                return False
            self.cookie_values = [_session_cookie()]
            return True

        def _page_evaluate(self, expression: str):
            if self.context_failures:
                self.context_failures -= 1
                raise RuntimeError("Execution context was destroyed during navigation")
            return super().evaluate(expression)

        def _page_wait(self, milliseconds: int) -> None:
            self.context_waits.append(milliseconds)
            self.passkey_ready = True

        def evaluate(self, expression: str):
            return self._runtime_observer.evaluate(expression)

    browser = ContextRaceBrowser()
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    network.attach()
    network.set_sequence(1)
    _emit_auth(browser, token=True, status=302)

    try:
        candidate = adapter._await_session(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
            ledger=ledger,
            network=network,
        )
    finally:
        network.detach()

    assert candidate.evidence.callback_confirmed is True
    assert browser.context_failures == 0
    assert browser.context_waits == [250, 500, 1_000, 1_250]
    assert passkey_skip in browser.optional_clicks


def test_native_acceptance_allows_one_sequence_two_submit(tmp_path: Path) -> None:
    mechanic = AcceptedMechanic()

    def on_submit(browser: FakeBrowser, submit: int) -> None:
        if submit == 1:
            _emit_auth(browser, token=False)
            browser.challenge_vendor = "hcaptcha"
            browser.challenge_state = "interactive"
        else:
            _emit_auth(browser, token=True)
            browser.cookie_values = [_session_cookie()]
            browser.challenge_vendor = "none"
            browser.challenge_state = "none"

    browser = FakeBrowser(
        [
            {"password_visible": True},
            {"authenticated": True},
        ],
        on_submit=on_submit,
    )

    candidate = _adapter(
        tmp_path,
        secrets=FakeSecrets(),
        mechanic=mechanic,
    ).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert candidate.evidence.callback_confirmed is True
    assert mechanic.calls == 1
    assert browser.submissions == 2


def test_upstream_error_never_retries_submit(tmp_path: Path) -> None:
    def on_submit(browser: FakeBrowser, submit: int) -> None:
        _emit_auth(browser, token=False, status=502)

    browser = FakeBrowser(
        [{"password_visible": True}, {"password_visible": True}],
        on_submit=on_submit,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=FakeSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.TRANSPORT
    assert browser.submissions == 1


def test_callback_timeout_classifies_an_inert_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = FakeBrowser([{"authenticated": False}])
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    times = iter((0.0, 1.0, _SESSION_CALLBACK_TIMEOUT_SECONDS + 1.0))
    monkeypatch.setattr(
        "newsclip.providers.ft_auth.time.monotonic", lambda: next(times)
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._await_session(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
            ledger=ledger,
            network=network,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.CALLBACK
    assert caught.value.evidence.category is MintFailureCategory.CALLBACK_NOT_CONFIRMED


def test_callback_timeout_classifies_a_pending_auth_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser = FakeBrowser([{"authenticated": False}])
    ledger = FTSubmitLedger()
    ledger.claim_submit(1)
    network = FTNetworkObserver(browser.page, ledger)
    network.attach()
    network.set_sequence(1)
    browser.page.emit("request", FakeRequest("password=p&h-captcha-response="))
    times = iter((0.0, 1.0, _SESSION_CALLBACK_TIMEOUT_SECONDS + 1.0))
    monkeypatch.setattr(
        "newsclip.providers.ft_auth.time.monotonic", lambda: next(times)
    )

    try:
        with pytest.raises(AcquisitionFailure) as caught:
            _adapter(tmp_path)._await_session(
                browser,
                account_key="default",
                challenge_mode=ChallengeMode.AUTO,
                ledger=ledger,
                network=network,
            )
    finally:
        network.detach()

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.TRANSPORT
    assert caught.value.evidence.category is MintFailureCategory.TRANSPORT_FAILURE
