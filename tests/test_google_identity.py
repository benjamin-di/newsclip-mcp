from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from newsclip.acquisition import (
    AcquisitionFailure,
    ChallengeMode,
    CredentialAction,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from newsclip.browser_runtime import (
    IdentityExitReason,
    MouseTarget,
    PasskeyMode,
    PatchrightMintContext,
)
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.identity.google import (
    GoogleIdentityConfig,
    GoogleIdentityDriver,
    GoogleIdentityObservation,
    GoogleIdentityStep,
    google_identity_step,
)
from newsclip.login import LoginInfrastructureError
from newsclip.models import MintOutcome
from newsclip.provider_config import load_provider_spec
from newsclip.providers.bloomberg import BloombergLoginRecipe
from newsclip.timing import TimingOperation, TimingRecorder, TimingTransport

ARTICLE_URL = (
    "https://www.bloomberg.com/news/articles/2026-07-16/"
    "fixture-chipmaker-beats-estimates"
)
_GOOGLE_CONTROLS = (
    "account_choices",
    "alternate",
    "consent",
    "email",
    "email_submit",
    "password",
    "password_choice",
    "password_submit",
    "totp",
    "totp_choice",
    "totp_submit",
    "use_another",
)


class NullLocator:
    def count(self) -> int:
        return 0


class ParentPage:
    def __init__(self, url: str = "https://www.bloomberg.com/account/signin") -> None:
        self.url = url

    def is_closed(self) -> bool:
        return False

    def wait_for_timeout(self, milliseconds: float) -> None: ...


class GooglePage:
    def __init__(self) -> None:
        self.url = "https://accounts.google.com/v3/signin/challenge"
        self.keyboard = type("Keyboard", (), {"press": lambda self, key: None})()

    def is_closed(self) -> bool:
        return False

    def locator(self, selector: str) -> NullLocator:
        return NullLocator()

    def add_init_script(self, script: str) -> None: ...


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

    @property
    def current_url(self) -> str:
        return self.page.url

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        assert mode is PasskeyMode.NON_PRESENT
        return True

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


class FakeSecrets:
    def __init__(self) -> None:
        self.fields: list[str] = []

    def fill(self, browser, *, field: str, **kwargs) -> None:
        self.fields.append(field)


class GoogleDriverHarness:
    def __init__(
        self,
        *,
        secrets: FakeSecrets | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        spec = load_provider_spec("bloomberg")
        auth = spec.require_auth()
        recipe = BloombergLoginRecipe(verification_url=ARTICLE_URL)
        self.driver = GoogleIdentityDriver(
            GoogleIdentityConfig(
                provider_key="bloomberg",
                controls={name: auth.control(name) for name in _GOOGLE_CONTROLS},
                observations=dict(auth.observations),
                secret_ref=recipe.secret_ref,
                allowed_origins=recipe.allowed_origins,
                identity_hosts=auth.identity_hosts,
            ),
            secrets=secrets or FakeSecrets(),
            clock=clock,
        )

    def drive(
        self,
        google: PatchrightMintContext,
        *,
        original: ParentPage,
        challenge_mode: ChallengeMode,
    ) -> CredentialAction:
        def callback_complete() -> bool:
            parsed = urlsplit(original.url)
            path = parsed.path.lower().rstrip("/") or "/"
            return (
                parsed.hostname == "www.bloomberg.com"
                and not path.startswith("/account/signin")
                and not path.startswith("/account/login")
            )

        def resolve_challenge(browser: PatchrightMintContext) -> None:
            resolution = ChallengeResolver({}).resolve(browser, challenge_mode)
            if not resolution.allows_continuation:
                raise AcquisitionFailure(
                    MintOutcome.CHALLENGE_BLOCKED,
                    MintFailureEvidence(
                        stage=MintFailureStage.CHALLENGE,
                        category=MintFailureCategory.CHALLENGE_BLOCKED,
                    ),
                )

        return self.driver.drive(
            google,
            callback_complete=callback_complete,
            resolve_challenge=resolve_challenge,
        ).credential_action


def _adapter(
    tmp_path: Path,
    *,
    secrets: FakeSecrets | None = None,
    clock: Callable[[], float] | None = None,
) -> GoogleDriverHarness:
    del tmp_path
    return GoogleDriverHarness(secrets=secrets, clock=clock)


def test_google_identity_result_reports_only_bounded_completion_facts(
    tmp_path: Path,
) -> None:
    parent = ParentPage("https://www.bloomberg.com/markets")
    google = GoogleBrowser(
        [{}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path)

    result = harness.driver.drive(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: True,
        resolve_challenge=lambda browser: pytest.fail(
            "completed callback must not dispatch challenge handling"
        ),
    )

    assert result.credential_action is CredentialAction.NONE
    assert result.callback_complete is True
    assert result.identity_page_closed is False
    assert result.exit_reason is IdentityExitReason.CALLBACK_COMPLETE
    assert set(result.model_dump()) == {
        "credential_action",
        "callback_complete",
        "identity_page_closed",
        "exit_reason",
    }


def test_google_identity_separates_a_closed_page_from_a_closed_context(
    tmp_path: Path,
) -> None:
    """Both exits report identity_page_closed; only one is post-submit ambiguous."""

    parent = ParentPage()

    class ClosedPopup(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__([{}], parent=parent, complete_after_click=99)
            self.page.is_closed = lambda: True  # type: ignore[method-assign]

    closed = _adapter(tmp_path).driver.drive(
        ClosedPopup(),  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: pytest.fail(
            "a closed identity page must not dispatch challenge handling"
        ),
    )

    assert closed.identity_page_closed is True
    assert closed.exit_reason is IdentityExitReason.IDENTITY_PAGE_CLOSED

    class DestroyedContext(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__([{}], parent=parent, complete_after_click=99)

        def evaluate(self, script: str):
            raise RuntimeError("Target page, context or browser has been closed")

    destroyed = _adapter(tmp_path).driver.drive(
        DestroyedContext(),  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert destroyed.identity_page_closed is True
    assert destroyed.exit_reason is IdentityExitReason.IDENTITY_CONTEXT_CLOSED


@pytest.mark.parametrize(
    "closed, lifecycle_error", [(True, True), (False, True), (True, False)]
)
def test_post_totp_observation_loss_preserves_one_submit(
    closed: bool, lifecycle_error: bool
) -> None:
    from newsclip.challenge_detection import ChallengeDetectionError

    harness = GoogleDriverHarness()
    browser = GoogleBrowser(
        [{"totp_visible": True}], parent=ParentPage(), complete_after_click=99
    )
    popup_closed = False
    browser.page.is_closed = lambda: popup_closed
    observations = 0

    def resolve(raw_browser):
        nonlocal observations, popup_closed
        observations += 1
        if observations == 2:
            popup_closed = closed
            try:
                raise RuntimeError(
                    "Execution context was destroyed"
                    if lifecycle_error
                    else "unrelated fixture failure"
                )
            except RuntimeError as error:
                raise ChallengeDetectionError("fixture observation failed") from error

    if lifecycle_error:
        result = harness.driver.drive(
            browser, callback_complete=lambda: False, resolve_challenge=resolve
        )
        assert result.exit_reason is IdentityExitReason.IDENTITY_CONTEXT_CLOSED
        assert not result.callback_complete
        assert result.credential_action is CredentialAction.GOOGLE_TOTP_SUBMIT
        assert result.identity_page_closed is closed
    else:
        with pytest.raises(ChallengeDetectionError):
            harness.driver.drive(
                browser, callback_complete=lambda: False, resolve_challenge=resolve
            )
    assert harness.driver._secrets.fields == ["totp"]
    assert browser.clicks == 1


def test_google_identity_config_rejects_partial_driver_surfaces(
    tmp_path: Path,
) -> None:
    payload = _adapter(tmp_path).driver.config.model_dump(mode="python")
    payload["controls"].pop("totp")

    with pytest.raises(ValueError, match="controls do not match"):
        GoogleIdentityConfig.model_validate(payload)


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (
            {"account_chooser": True, "email_visible": True},
            GoogleIdentityStep.ACCOUNT_CHOOSER,
        ),
        (
            {"email_visible": True, "password_visible": True},
            GoogleIdentityStep.EMAIL,
        ),
        (
            {"password_visible": True, "totp_visible": True},
            GoogleIdentityStep.PASSWORD,
        ),
        (
            {"totp_visible": True, "totp_choice": True},
            GoogleIdentityStep.TOTP,
        ),
        (
            {"totp_choice": True, "password_choice": True},
            GoogleIdentityStep.TOTP_CHOICE,
        ),
        (
            {"password_choice": True, "alternate_visible": True},
            GoogleIdentityStep.PASSWORD_CHOICE,
        ),
        (
            {"alternate_visible": True, "consent_visible": True},
            GoogleIdentityStep.ALTERNATE,
        ),
        ({"consent_visible": True}, GoogleIdentityStep.CONSENT),
        ({}, GoogleIdentityStep.IDLE),
    ],
)
def test_google_identity_step_classifier_preserves_control_precedence(
    flags: dict[str, bool], expected: GoogleIdentityStep
) -> None:
    assert (
        google_identity_step(GoogleIdentityObservation.model_validate(flags))
        is expected
    )


@pytest.mark.parametrize(
    ("observations", "clicks", "fields", "action"),
    [
        (
            [
                {"account_chooser": True},
                {"email_visible": True},
                {"password_visible": True},
                {"consent_visible": True},
            ],
            4,
            ["username", "password"],
            CredentialAction.GOOGLE_PASSWORD_SUBMIT,
        ),
        (
            [{"password_visible": True}, {"consent_visible": True}],
            2,
            ["password"],
            CredentialAction.GOOGLE_PASSWORD_SUBMIT,
        ),
        (
            [{"totp_visible": True}],
            1,
            ["totp"],
            CredentialAction.GOOGLE_TOTP_SUBMIT,
        ),
        (
            [{"consent_visible": True}],
            1,
            [],
            CredentialAction.NONE,
        ),
    ],
)
def test_google_cached_states_are_action_derived(
    tmp_path: Path,
    observations: list[dict[str, bool]],
    clicks: int,
    fields: list[str],
    action: CredentialAction,
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    google = GoogleBrowser(
        observations,
        parent=parent,
        complete_after_click=clicks,
    )

    result = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert result is action
    assert google.clicks == clicks
    assert secrets.fields == fields


def test_google_credential_action_never_downgrades_after_totp(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    google = GoogleBrowser(
        [{"totp_visible": True}, {"password_visible": True}],
        parent=parent,
        complete_after_click=2,
    )

    result = _adapter(tmp_path, secrets=secrets).drive(
        google,  # type: ignore[arg-type]
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert result is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp", "password"]


def test_google_success_is_identical_with_timing_enabled_or_disabled(
    tmp_path: Path,
) -> None:
    def run(*, timed: bool):
        parent = ParentPage()
        secrets = FakeSecrets()
        google = GoogleBrowser(
            [
                {"email_visible": True},
                {"password_visible": True},
                {"consent_visible": True},
            ],
            parent=parent,
            complete_after_click=3,
        )
        adapter = _adapter(tmp_path, secrets=secrets)

        if timed:
            with TimingRecorder(tmp_path / "timings").operation(
                TimingOperation.LOGIN,
                provider="bloomberg",
                transport=TimingTransport.BROWSER,
            ):
                action = adapter.drive(
                    google,
                    original=parent,
                    challenge_mode=ChallengeMode.DETECT_ONLY,
                )
        else:
            action = adapter.drive(
                google,
                original=parent,
                challenge_mode=ChallengeMode.DETECT_ONLY,
            )
        return action, list(secrets.fields), google.clicks, list(google.targets)

    without_timing = run(timed=False)
    with_timing = run(timed=True)

    assert with_timing == without_timing
    assert without_timing[0] is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert without_timing[1] == ["username", "password"]
    assert without_timing[2] == 3
    assert len(without_timing[3]) == 3


def test_google_failure_is_identical_with_timing_enabled_or_disabled(
    tmp_path: Path,
) -> None:
    def run(*, timed: bool):
        parent = ParentPage()
        secrets = FakeSecrets()
        google = GoogleBrowser(
            [{"email_visible": True}, {"credential_rejected": True}],
            parent=parent,
            complete_after_click=99,
        )
        adapter = _adapter(tmp_path, secrets=secrets)

        try:
            if timed:
                with TimingRecorder(tmp_path / "timings").operation(
                    TimingOperation.LOGIN,
                    provider="bloomberg",
                    transport=TimingTransport.BROWSER,
                ):
                    adapter.drive(
                        google,
                        original=parent,
                        challenge_mode=ChallengeMode.DETECT_ONLY,
                    )
            else:
                adapter.drive(
                    google,
                    original=parent,
                    challenge_mode=ChallengeMode.DETECT_ONLY,
                )
        except AcquisitionFailure as failure:
            return (
                failure.outcome,
                failure.evidence.stage,
                failure.evidence.category,
                list(secrets.fields),
                google.clicks,
                list(google.targets),
            )
        pytest.fail("credential rejection must fail")

    without_timing = run(timed=False)
    with_timing = run(timed=True)

    assert with_timing == without_timing
    assert without_timing[:3] == (
        MintOutcome.CREDENTIAL_REJECTED,
        MintFailureStage.CREDENTIAL,
        MintFailureCategory.CREDENTIAL_REJECTED,
    )
    assert without_timing[3] == ["username"]
    assert without_timing[4] == 1
    assert len(without_timing[5]) == 1


def test_google_password_redrive_reuses_seated_field_once(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    clock = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.google.time.monotonic", lambda: clock[0]
    )

    class SlowGoogle(GoogleBrowser):
        def wait(self, seconds: float) -> None:
            if seconds == 0.4:
                clock[0] += 11

    google = SlowGoogle(
        [
            {"password_visible": True},
            {"password_visible": True},
            {"consent_visible": True},
        ],
        parent=parent,
        complete_after_click=3,
    )

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert secrets.fields == ["password"]
    assert google.clicks == 3


def test_google_flow_blocks_unconfigured_captcha_before_secret_fill(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    google = GoogleBrowser(
        [{"email_visible": True}],
        parent=parent,
        complete_after_click=1,
        challenge_vendor="recaptcha",
        challenge_state="interactive",
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets).drive(
            google,
            original=parent,
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert secrets.fields == []


def test_google_password_fill_can_auto_submit_directly_to_parent(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class AutoSubmitSecrets(FakeSecrets):
        def fill(self, browser, *, field: str, **kwargs) -> None:
            super().fill(browser, field=field, **kwargs)
            if field == "password":
                parent.url = "https://www.bloomberg.com/markets"

    secrets = AutoSubmitSecrets()
    google = GoogleBrowser(
        [{"password_visible": True}],
        parent=parent,
        complete_after_click=99,
    )

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT
    assert secrets.fields == ["password"]
    assert google.clicks == 0


def test_google_password_auto_submit_can_continue_through_consent(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class AutoSubmitGoogle(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"password_visible": True}, {"consent_visible": True}],
                parent=parent,
                complete_after_click=1,
            )
            self.password_filled = False

        def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
            if self.password_filled:
                self.password_filled = False
                raise RuntimeError("password control disappeared after fill")
            return super().mouse_target(selectors)

    google = AutoSubmitGoogle()

    class AutoSubmitSecrets(FakeSecrets):
        def fill(self, browser, *, field: str, **kwargs) -> None:
            super().fill(browser, field=field, **kwargs)
            if field == "password":
                google.password_filled = True

    secrets = AutoSubmitSecrets()
    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_AUTO_SUBMIT
    assert secrets.fields == ["password"]
    assert google.clicks == 1


def test_google_email_transition_can_repeat_without_refill_or_resubmit(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"email_visible": True},
            {"email_visible": True},
            {"password_visible": True},
            {"consent_visible": True},
        ],
        parent=parent,
        complete_after_click=3,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert secrets.fields == ["username", "password"]
    assert google.clicks == 3


def test_google_password_transition_can_repeat_without_early_redrive(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"password_visible": True},
            {"password_visible": True},
            {"password_visible": True},
            {"consent_visible": True},
        ],
        parent=parent,
        complete_after_click=2,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert secrets.fields == ["password"]
    assert google.clicks == 2


def test_google_specific_second_factor_choices_precede_broad_consent(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {
                "alternate_visible": True,
                "consent_visible": True,
                "unsupported_second_factor": True,
            },
            {"totp_choice": True, "consent_visible": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=3,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.clicks == 3


def test_google_totp_choice_precedes_password_on_multi_method_chooser(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"password_choice": True, "totp_choice": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=2,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.targets[0] == load_provider_spec("bloomberg").auth.control(
        "totp_choice"
    )


def test_google_config_recognizes_current_authenticator_choice() -> None:
    spec = load_provider_spec("bloomberg")

    assert "get a verification code" in spec.auth.observations["totp_choice"].any_text
    assert (
        "phone or tablet to get a security code"
        in spec.auth.observations["totp_choice"].any_text
    )
    assert any(
        "Get a verification code" in selector
        for selector in spec.auth.control("totp_choice")
    )
    assert any(
        "security code" in selector for selector in spec.auth.control("totp_choice")
    )
    assert "[data-challengetype='6']" in spec.auth.control("totp_choice")


def test_google_verify_method_chooser_prefers_authenticator_over_phone_passkey(
    tmp_path: Path,
) -> None:
    """Phone/passkey options must not fail closed when Authenticator is listed."""

    parent = ParentPage()
    google = GoogleBrowser(
        [
            {
                "unsupported_second_factor": True,
                "totp_choice": True,
                "consent_visible": True,
            },
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=2,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.targets[0] == load_provider_spec("bloomberg").auth.control(
        "totp_choice"
    )


def test_google_identity_step_up_allows_second_authenticator_code(
    tmp_path: Path,
) -> None:
    """A second 'Verify it's you' Authenticator challenge may consume one more code."""

    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"totp_visible": True},
            {"totp_visible": True},  # residual after first submit
            {"totp_choice": True, "unsupported_second_factor": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=3,
    )
    secrets = FakeSecrets()
    ticks = itertools.count(start=0.0, step=20.0)
    import newsclip.providers.bloomberg_auth as bloomberg_auth

    original = bloomberg_auth.time.monotonic
    bloomberg_auth.time.monotonic = lambda: next(ticks)  # type: ignore[assignment]
    try:
        action = _adapter(tmp_path, secrets=secrets).drive(
            google,
            original=parent,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )
    finally:
        bloomberg_auth.time.monotonic = original  # type: ignore[assignment]

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp", "totp"]


def test_google_totp_choice_transition_does_not_click_twice(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"totp_choice": True},
            {"totp_choice": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=2,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.clicks == 2


def test_google_totp_submit_waits_for_popup_transition_without_reusing_code(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class SettlingGoogle(GoogleBrowser):
        waits = 0

        def wait(self, seconds: float) -> None:
            self.waits += 1
            if self.waits == 2:
                parent.url = "https://www.bloomberg.com/markets"

    google = SettlingGoogle(
        [{"totp_visible": True}, {"totp_visible": True}],
        parent=parent,
        complete_after_click=99,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.clicks == 1


def test_google_totp_uses_step_specific_mouse_target(tmp_path: Path) -> None:
    parent = ParentPage()

    class TargetedGoogle(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"totp_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def mouse_click(self, target: MouseTarget) -> None:
            self.clicks += 1
            parent.url = "https://www.bloomberg.com/account/onboarding"

    google = TargetedGoogle()
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.targets == [
        load_provider_spec("bloomberg").auth.control("totp_submit")
    ]


def test_google_totp_target_closed_is_provisional_submit_success(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class ClosingPage(GooglePage):
        closed = False

        def is_closed(self) -> bool:
            return self.closed

    class ClosingGoogle(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"totp_visible": True}],
                parent=parent,
                complete_after_click=99,
            )
            self.page = ClosingPage()
            self.submits: list[MouseTarget] = []

        def mouse_click(self, target: MouseTarget) -> None:
            self.submits.append(target)
            self.page.closed = True
            raise RuntimeError("Target closed")

    google = ClosingGoogle()
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.targets == [
        load_provider_spec("bloomberg").auth.control("totp_submit")
    ]
    assert google.submits == [MouseTarget(10, 10)]


def test_google_totp_context_replacement_after_mouse_dispatch_never_falls_back(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class NavigatingGoogle(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"totp_visible": True}],
                parent=parent,
                complete_after_click=99,
            )
            self.presses: list[tuple[tuple[str, ...], str]] = []

        def mouse_click(self, target: MouseTarget) -> None:
            self.clicks += 1
            raise RuntimeError(
                "Execution context was destroyed, most likely because of a navigation"
            )

        def press(self, selectors: tuple[str, ...], key: str) -> None:
            self.presses.append((selectors, key))

        def wait(self, seconds: float) -> None:
            parent.url = "https://www.bloomberg.com/markets"

    google = NavigatingGoogle()
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.targets == [
        load_provider_spec("bloomberg").auth.control("totp_submit")
    ]
    assert google.clicks == 1
    assert google.presses == []


def test_google_ambiguous_totp_submit_never_consumes_a_second_code(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()

    class StuckGoogle(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"totp_visible": True}, {"totp_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def mouse_click(self, target: MouseTarget) -> None:
            self.clicks += 1
            raise RuntimeError(
                "Execution context was destroyed, most likely because of a navigation"
            )

        def press(self, selectors: tuple[str, ...], key: str) -> None:
            pytest.fail("ambiguous submit must not dispatch an Enter fallback")

        def wait(self, seconds: float) -> None:
            clock.now += 31

    google = StuckGoogle()
    secrets = FakeSecrets()

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=secrets, clock=clock).drive(
            google,
            original=parent,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert caught.value.evidence.stage is MintFailureStage.CALLBACK
    assert caught.value.evidence.category is MintFailureCategory.CALLBACK_NOT_CONFIRMED
    assert secrets.fields == ["totp"]
    assert google.clicks == 1


def test_google_consent_target_closed_waits_for_verified_parent_callback(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class PopupClosingConsent(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"consent_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def click(self, selectors: tuple[str, ...]) -> None:
            parent.url = "https://www.bloomberg.com/markets"
            raise RuntimeError("Target page, context or browser has been closed")

        def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
            raise RuntimeError("Target page, context or browser has been closed")

    action = _adapter(tmp_path, secrets=FakeSecrets()).drive(
        PopupClosingConsent(),
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.NONE


def test_google_consent_click_exception_without_transition_fails_closed(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class StuckConsent(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"consent_visible": True}, {"consent_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def click(self, selectors: tuple[str, ...]) -> None:
            raise RuntimeError("click interrupted")

        def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
            raise ValueError("click interrupted")

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=FakeSecrets()).drive(
            StuckConsent(),
            original=parent,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.evidence.stage is MintFailureStage.CALLBACK
    assert caught.value.evidence.category is MintFailureCategory.CONTROL_MISSING


def test_google_popup_closure_between_poll_and_observation_recovers_callback(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class TargetClosedError(RuntimeError):
        pass

    class ClosingAfterConsent(GoogleBrowser):
        observations_taken = 0

        def __init__(self) -> None:
            super().__init__(
                [{"consent_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def evaluate(self, script: str):
            self.observations_taken += 1
            if self.observations_taken == 2:
                parent.url = "https://www.bloomberg.com/markets"
                raise TargetClosedError("Target page has been closed")
            return super().evaluate(script)

        def click(self, selectors: tuple[str, ...]) -> None: ...

    action = _adapter(tmp_path, secrets=FakeSecrets()).drive(
        ClosingAfterConsent(),
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.NONE


def test_google_popup_closure_during_post_consent_wait_recovers_callback(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class TargetClosedError(RuntimeError):
        pass

    class ClosingDuringWait(GoogleBrowser):
        def __init__(self) -> None:
            super().__init__(
                [{"consent_visible": True}],
                parent=parent,
                complete_after_click=99,
            )

        def click(self, selectors: tuple[str, ...]) -> None: ...

        def wait(self, seconds: float) -> None:
            parent.url = "https://www.bloomberg.com/markets"
            raise TargetClosedError("Target page has been closed")

    action = _adapter(tmp_path, secrets=FakeSecrets()).drive(
        ClosingDuringWait(),
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.NONE


def test_google_alternate_transition_allows_chooser_to_hydrate(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    google = GoogleBrowser(
        [
            {"alternate_visible": True},
            {"alternate_visible": True},
            {"totp_choice": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=3,
    )
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.clicks == 3


def test_google_authenticator_choice_has_specific_text_fallback(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class RolelessChoiceGoogle(GoogleBrowser):
        phrases: list[str]

        def __init__(self) -> None:
            super().__init__(
                [{"totp_choice": True}, {"totp_visible": True}],
                parent=parent,
                complete_after_click=2,
            )
            self.phrases = []

        def click(self, selectors: tuple[str, ...]) -> None:
            raise RuntimeError("no semantic role on current Google row")

        def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
            if selectors == load_provider_spec("bloomberg").auth.control("totp_choice"):
                raise RuntimeError("no semantic role on current Google row")
            return super().mouse_target(selectors)

        def click_matching_text(self, selectors: tuple[str, ...], value: str) -> bool:
            self.phrases.append(value)
            if value != "google authenticator":
                return False
            self.clicks += 1
            return True

    google = RolelessChoiceGoogle()
    secrets = FakeSecrets()

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert google.phrases == ["google authenticator"]
    assert google.clicks == 2


def test_google_passkey_overlay_refills_replaced_password_control_once(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    clock = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.google.time.monotonic", lambda: clock[0]
    )

    class PasskeyGoogle(GoogleBrowser):
        advanced = False
        password_settle_waits = 0

        def wait(self, seconds: float) -> None:
            if seconds == 0.4 and not self.advanced:
                clock[0] += 11
                self.advanced = True
            if seconds == 0.5:
                self.password_settle_waits += 1
                if self.password_settle_waits == 2:
                    clock[0] += 11

    google = PasskeyGoogle(
        [
            {"password_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"password_choice": True},
            {"password_visible": True},
            {"password_visible": True},
        ],
        parent=parent,
        complete_after_click=4,
    )

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert secrets.fields == ["password", "password"]
    assert google.clicks == 4


def test_google_allows_distinct_post_password_authenticator_transition(
    tmp_path: Path, monkeypatch
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    clock = [0.0]
    monkeypatch.setattr(
        "signin_window.automation.google.time.monotonic", lambda: clock[0]
    )

    class TwoPhaseGoogle(GoogleBrowser):
        transition_waits = 0

        def wait(self, seconds: float) -> None:
            if seconds == 0.4:
                self.transition_waits += 1
                if self.transition_waits in {1, 3, 4}:
                    clock[0] += 11

    google = TwoPhaseGoogle(
        [
            {"password_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"password_choice": True},
            {"password_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"totp_choice": True},
            {"totp_visible": True},
        ],
        parent=parent,
        complete_after_click=7,
    )

    action = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["password", "password", "totp"]
    assert google.clicks == 7


def test_google_password_click_failure_becomes_typed_control_missing(
    tmp_path: Path,
) -> None:
    parent = ParentPage()

    class MissingSubmitGoogle(GoogleBrowser):
        def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
            raise RuntimeError("submit control unavailable")

    google = MissingSubmitGoogle(
        [{"password_visible": True}, {"password_visible": True}],
        parent=parent,
        complete_after_click=99,
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=FakeSecrets()).drive(
            google,
            original=parent,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert caught.value.evidence.category is MintFailureCategory.CONTROL_MISSING


def test_google_post_totp_passkey_allows_another_alternate_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After TOTP, a passkey 'More ways' surface must still be clickable."""

    parent = ParentPage()
    secrets = FakeSecrets()
    elapsed = 0.0

    class AdvancingGoogle(GoogleBrowser):
        def wait(self, seconds: float) -> None:
            nonlocal elapsed
            elapsed += 11

    monkeypatch.setattr(
        "signin_window.automation.google.time.monotonic",
        lambda: elapsed,
    )
    # Exercise both password/passkey alternates before TOTP, then prove that a
    # third, post-TOTP alternate can complete the flow. Without the post-TOTP
    # budget this raises SECOND_FACTOR_REQUIRED before click six.
    google = AdvancingGoogle(
        [
            {"password_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"password_visible": True},
            {"password_visible": True, "alternate_visible": True},
            {"totp_visible": True},
            {"alternate_visible": True},
        ],
        parent=parent,
        complete_after_click=6,
    )
    adapter = _adapter(tmp_path, secrets=secrets)

    result = adapter.drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert result is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["password", "totp"]
    assert google.clicks == 6


def test_google_signed_out_chooser_clicks_use_another_and_polls_hydration(
    tmp_path: Path,
) -> None:
    """Residual account-chooser state after 'Use another account' must not fail."""

    parent = ParentPage()
    secrets = FakeSecrets()
    # Signed-out accounts are excluded from username matching; the flow must
    # click Use another account, then tolerate a residual chooser observation
    # while the email control hydrates.
    google = GoogleBrowser(
        [
            {"account_chooser": True},
            {"account_chooser": True},
            {"email_visible": True},
            {"password_visible": True},
            {"consent_visible": True},
        ],
        parent=parent,
        complete_after_click=4,
    )
    secrets.click_matching_choice = (  # type: ignore[method-assign]
        lambda *args, **kwargs: False
    )

    result = _adapter(tmp_path, secrets=secrets).drive(
        google,
        original=parent,
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert result is CredentialAction.GOOGLE_PASSWORD_SUBMIT
    assert secrets.fields == ["username", "password"]
    # use_another + email submit + password submit + consent
    assert google.clicks == 4


def test_google_cached_callback_can_submit_consent_without_secrets(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    google = GoogleBrowser(
        [{"consent_visible": True}],
        parent=parent,
        complete_after_click=1,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: parent.url.endswith("/markets"),
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.CALLBACK_COMPLETE
    assert secrets.fields == []


class ChoiceSecrets(FakeSecrets):
    """Records chooser selections separately from credential fills."""

    def __init__(
        self,
        *,
        matches: bool = True,
        raises: BaseException | None = None,
    ) -> None:
        super().__init__()
        self.matched_fields: list[str] = []
        self._matches = matches
        self._raises = raises

    def click_matching_choice(self, browser, *, field: str, **kwargs) -> bool:
        self.matched_fields.append(field)
        if self._raises is not None:
            raise self._raises
        return self._matches


class SteppingClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_google_cached_callback_selects_cached_account_without_credentials(
    tmp_path: Path,
) -> None:
    """A replayed popup normally opens on the chooser; it must be traversable.

    Selecting the exact cached account reads only the username reference. The
    replay must never resolve or submit a password or TOTP code a second time.
    """

    parent = ParentPage()
    secrets = ChoiceSecrets()
    google = GoogleBrowser(
        [{"account_chooser": True}, {}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: bool(secrets.matched_fields),
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.CALLBACK_COMPLETE
    assert secrets.matched_fields == ["username"]
    assert secrets.fields == []


def test_google_cached_callback_refuses_an_unmatched_account_chooser(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = ChoiceSecrets(matches=False)
    google = GoogleBrowser(
        [{"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.DECLINED
    assert secrets.matched_fields == ["username"]
    assert secrets.fields == []


def test_google_cached_callback_refuses_a_chooser_without_a_matcher(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = FakeSecrets()
    google = GoogleBrowser(
        [{"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.DECLINED
    assert secrets.fields == []


def test_google_cached_callback_selects_the_chooser_at_most_once(
    tmp_path: Path,
) -> None:
    parent = ParentPage()
    secrets = ChoiceSecrets()
    google = GoogleBrowser(
        [{"account_chooser": True}, {"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets, clock=SteppingClock())

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.DECLINED
    assert secrets.matched_fields == ["username"]
    assert secrets.fields == []


@pytest.mark.parametrize(
    "observation",
    [{"password_visible": True}, {"totp_visible": True}],
    ids=["password", "totp"],
)
def test_google_cached_callback_never_resubmits_password_or_totp(
    tmp_path: Path,
    observation: dict[str, bool],
) -> None:
    parent = ParentPage()
    secrets = ChoiceSecrets()
    google = GoogleBrowser([observation], parent=parent, complete_after_click=99)
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.DECLINED
    assert secrets.matched_fields == []
    assert secrets.fields == []


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError(
            "Execution context was destroyed, most likely because of a navigation"
        ),
        RuntimeError("Target page, context or browser has been closed"),
    ],
    ids=["context_destroyed", "target_closed"],
)
def test_google_cached_callback_treats_a_closure_at_selection_as_ended(
    tmp_path: Path,
    error: BaseException,
) -> None:
    """A closure while selecting the account must not become a local fault.

    Selecting the account is what navigates the popup, so the selection may
    well have landed. The replay ends and the external publisher proof decides.
    """

    parent = ParentPage()
    secrets = ChoiceSecrets(raises=error)
    google = GoogleBrowser(
        [{"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.IDENTITY_CONTEXT_CLOSED
    assert secrets.matched_fields == ["username"]
    assert secrets.fields == []


def test_google_cached_callback_declines_on_an_ordinary_selection_error(
    tmp_path: Path,
) -> None:
    """A tile that will not click is a declined replay, not a local fault."""

    parent = ParentPage()
    secrets = ChoiceSecrets(raises=RuntimeError("locator click timed out"))
    google = GoogleBrowser(
        [{"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    outcome = harness.driver.resume_cached_callback(
        google,  # type: ignore[arg-type]
        callback_complete=lambda: False,
        resolve_challenge=lambda browser: None,
    )

    assert outcome is IdentityExitReason.DECLINED
    assert secrets.fields == []


def test_google_cached_callback_surfaces_a_secret_delivery_fault(
    tmp_path: Path,
) -> None:
    """The flow read this same reference moments ago, so a fault now is real."""

    parent = ParentPage()
    secrets = ChoiceSecrets(
        raises=LoginInfrastructureError("1Password service token is unavailable")
    )
    google = GoogleBrowser(
        [{"account_chooser": True}],
        parent=parent,
        complete_after_click=99,
    )
    harness = _adapter(tmp_path, secrets=secrets)

    with pytest.raises(LoginInfrastructureError):
        harness.driver.resume_cached_callback(
            google,  # type: ignore[arg-type]
            callback_complete=lambda: False,
            resolve_challenge=lambda browser: None,
        )

    assert secrets.fields == []


@pytest.mark.parametrize("boundary", ["observation", "settle", "repoll"])
@pytest.mark.parametrize("closed", [False, True])
def test_post_totp_document_loss_hands_off_without_another_code(boundary, closed):
    """Bloomberg's GIS document can disappear before its parent callback lands."""
    parent = ParentPage()

    class TransitioningGoogle(GoogleBrowser):
        waits = 0
        lost = False

        def __init__(self):
            super().__init__(
                [{"totp_visible": True}], parent=parent, complete_after_click=99
            )
            self.page.is_closed = lambda: self.lost and closed

        def lose_document(self):
            self.lost = True
            raise RuntimeError(
                "Execution context was destroyed, most likely because of a navigation"
            )

        def evaluate(self, script):
            if boundary == "observation" and self.clicks:
                self.lose_document()
            return super().evaluate(script)

        def wait(self, seconds):
            self.waits += 1
            if (boundary == "settle" and self.waits == 1) or (
                boundary == "repoll" and self.waits == 2
            ):
                self.lose_document()

    browser = TransitioningGoogle()
    secrets = FakeSecrets()
    result = GoogleDriverHarness(secrets=secrets).driver.drive(
        browser, callback_complete=lambda: False, resolve_challenge=lambda _: None
    )
    assert result.exit_reason is IdentityExitReason.IDENTITY_CONTEXT_CLOSED
    assert result.identity_page_closed is closed
    assert not result.callback_complete
    assert result.credential_action is CredentialAction.GOOGLE_TOTP_SUBMIT
    assert secrets.fields == ["totp"]
    assert browser.clicks == 1


def test_post_totp_unrelated_wait_error_is_not_callback_evidence():
    parent = ParentPage()

    class FailingGoogle(GoogleBrowser):
        def wait(self, seconds):
            raise RuntimeError("unrelated fixture failure")

    browser = FailingGoogle(
        [{"totp_visible": True}], parent=parent, complete_after_click=99
    )
    secrets = FakeSecrets()
    with pytest.raises(RuntimeError, match="unrelated fixture failure"):
        GoogleDriverHarness(secrets=secrets).driver.drive(
            browser, callback_complete=lambda: False, resolve_challenge=lambda _: None
        )
    assert secrets.fields == ["totp"]
    assert browser.clicks == 1


def test_open_document_loss_before_totp_is_not_callback_evidence():
    browser = GoogleBrowser([{}], parent=ParentPage(), complete_after_click=99)
    secrets = FakeSecrets()

    def fail_observation(_):
        raise RuntimeError("Execution context was destroyed")

    with pytest.raises(RuntimeError, match="Execution context was destroyed"):
        GoogleDriverHarness(secrets=secrets).driver.drive(
            browser,
            callback_complete=lambda: False,
            resolve_challenge=fail_observation,
        )
    assert secrets.fields == []
    assert browser.clicks == 0
