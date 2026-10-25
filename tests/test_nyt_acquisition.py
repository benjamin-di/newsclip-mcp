"""NYT acquisition gates, faking the browser rather than the network.

The NYT-specific weight is on the session predicate. NYT sets both NYT-S (the
durable subscriber authority) and nyt-s-present (a boolean hint, observed with
value "0" while unauthenticated). The shared prefix mechanism would accept the
hint, and because NYT is metered an anonymous browser can also render a complete
article — together a path from a logged-out page load to a certified paid
session. See docs/NYT_PROVIDER_PLAN.md section 8.1.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.acquisition import (
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    ChallengeMode,
    MintFailureCategory,
    MintFailureStage,
)
from newsclip.browser_runtime import MouseTarget, ObservedNavigation, PasskeyMode
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.challenges import (
    ChallengeAcceptance,
    ChallengeInfrastructureError,
    ChallengeVendor,
)
from newsclip.login import LoginInfrastructureError
from newsclip.models import MintOutcome
from newsclip.provider_config import load_provider_spec
from newsclip.providers.nyt import NYTLoginRecipe
from newsclip.providers.nyt_auth import NYTAcquisitionAdapter
from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()
ARTICLE_URL = (
    "https://www.nytimes.com/2026/07/17/business/fixture-lenders-raise-capital.html"
)
FIXTURES = Path(__file__).parent / "fixtures" / "nyt"


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
        article_html: str | None = None,
    ) -> None:
        self.observations = list(observations)
        self.last = observations[-1] if observations else {}
        self.cookie_values = list(cookies or [])
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
        return list(self.cookie_values)

    def user_agent(self) -> str:
        return "FixtureBrowser/1.0"

    def mouse_target(self, selectors) -> MouseTarget:
        self.actions.append("geometry")
        return MouseTarget(5, 5)

    def mouse_click(self, target: MouseTarget) -> None:
        self.actions.append("mouse")


def _authority_cookie(**overrides: object) -> dict[str, object]:
    return {
        "name": "NYT-S",
        "value": "SESSION_VALUE",
        "domain": ".nytimes.com",
        "path": "/",
        "expires": FUTURE,
        "secure": True,
        "httpOnly": True,
        "sameSite": "Lax",
        **overrides,
    }


def _anonymous_jar() -> list[dict[str, object]]:
    """Exactly what an anonymous NYT page load leaves behind."""

    return [
        _authority_cookie(name="nyt-s-present", value="0"),
        _authority_cookie(name="nyt-a", value="anonymous"),
        _authority_cookie(name="nyt-geo", value="US"),
    ]


def _adapter(
    *,
    secrets: FakeSecrets | None = None,
    datadome: FakeDataDome | None = None,
) -> NYTAcquisitionAdapter:
    return NYTAcquisitionAdapter(
        recipe=NYTLoginRecipe(verification_url=ARTICLE_URL),
        secrets=secrets,
        challenge_resolver=ChallengeResolver(
            {ChallengeVendor.DATADOME: datadome} if datadome is not None else {}
        ),
        clock=lambda: NOW,
    )


# --- NYT-specific: the nyt-s-present trap (plan section 8.1) -----------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("nyt-s-present", "0"),
        ("nyt-s-present", "1"),
        ("NYT-S-PRESENT", "1"),
        ("nyt-session", "value"),
        ("NYT-S", ""),
    ],
)
def test_only_an_exact_nonempty_nyt_s_satisfies_the_session_predicate(
    name: str, value: str
) -> None:
    adapter = _adapter()

    assert (
        adapter._has_provider_cookie([_authority_cookie(name=name, value=value)])
        is False
    )
    assert adapter._has_provider_cookie([_authority_cookie()]) is True


def test_the_authority_cookie_must_come_from_an_allowed_domain() -> None:
    adapter = _adapter()

    assert (
        adapter._has_provider_cookie(
            [_authority_cookie(domain="nytimes.com.evil.test")]
        )
        is False
    )
    assert (
        adapter._has_provider_cookie([_authority_cookie(domain="nytimes.com")]) is True
    )


def test_an_anonymous_jar_cannot_certify_a_candidate_even_with_a_full_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of the exact predicate.

    The browser carries nyt-s-present=0 and renders a complete, identity-matching
    article — the metered state — and still must not export a paid session.
    """

    ticks = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(
        "newsclip.providers.nyt_auth.time.monotonic",
        lambda: next(ticks),
    )
    browser = FakeBrowser(
        [{"authenticated": True}],
        cookies=_anonymous_jar(),
        article_html=(FIXTURES / "metered_full_no_session.html").read_text(
            encoding="utf-8"
        ),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter()._candidate(
            browser,
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert caught.value.evidence.stage is MintFailureStage.PAID_PROBE
    assert caught.value.evidence.category is MintFailureCategory.ARTICLE_NOT_FULL


def test_the_paid_probe_reports_the_authority_cookie_not_a_nonempty_jar() -> None:
    """capture_verification_fetch must not read `bool(cookies)` for NYT.

    An anonymous NYT page load always leaves nyt-a and friends behind, so a
    non-empty jar is not session evidence here.
    """

    def _probe(cookies: list[dict[str, object]]):
        browser = FakeBrowser([], cookies=cookies)
        observed = browser.navigate_observed(ARTICLE_URL, timeout_seconds=30)
        return _adapter()._browser_article_fetch(browser, observed)

    anonymous = _probe(_anonymous_jar())
    authenticated = _probe([*_anonymous_jar(), _authority_cookie()])

    assert anonymous.session_cookie_present is False
    assert authenticated.session_cookie_present is True


def test_a_definition_configuring_cookie_prefixes_is_rejected() -> None:
    spec = load_provider_spec("nyt")
    session = spec.require_session().model_copy(
        update={"session_cookie_name_prefixes": ("nyt-s",)}
    )

    with pytest.raises(ValueError, match="exact session cookie name"):
        NYTAcquisitionAdapter(
            recipe=NYTLoginRecipe(verification_url=ARTICLE_URL),
            challenge_resolver=ChallengeResolver({}),
            spec=spec.model_copy(update={"session": session}),
        )


def test_the_shipped_definition_configures_no_cookie_prefixes() -> None:
    assert (
        load_provider_spec("nyt").require_session().session_cookie_name_prefixes == ()
    )


# --- Auth surface contract ---------------------------------------------------


@pytest.mark.parametrize("defect", ("missing_control", "unknown_observation"))
def test_nyt_auth_surface_contract_is_owned_by_nyt(defect: str) -> None:
    spec = load_provider_spec("nyt")
    auth = spec.require_auth()
    if defect == "missing_control":
        controls = dict(auth.controls)
        controls.pop("password")
        auth = auth.model_copy(update={"controls": controls})
    else:
        observations = dict(auth.observations)
        observations["provider_private_state"] = next(iter(observations.values()))
        auth = auth.model_copy(update={"observations": observations})

    with pytest.raises(ValueError, match="authentication"):
        NYTAcquisitionAdapter(
            recipe=NYTLoginRecipe(verification_url=ARTICLE_URL),
            challenge_resolver=ChallengeResolver({}),
            spec=spec.model_copy(update={"auth": auth}),
        )


# --- Flow ---------------------------------------------------------------------


def test_retained_profile_rehydrates_without_secrets() -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser([{"authenticated": True}], cookies=[_authority_cookie()])

    candidate = _adapter(secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert candidate.candidate_verification_mode is (
        CandidateVerificationMode.BROWSER_PAID_PROBE
    )
    assert candidate.verification_fetch is not None
    assert candidate.artifact.user_agent == "FixtureBrowser/1.0"
    assert [cookie.name for cookie in candidate.artifact.cookies] == ["NYT-S"]
    assert secrets.fields == []
    assert browser.actions == ["navigate", "passkeys", "navigate"]


def test_rehydrate_returns_none_when_credentials_are_required() -> None:
    browser = FakeBrowser([{"username_visible": True}])

    assert (
        _adapter().rehydrate_profile(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )
        is None
    )


def test_credential_mint_submits_email_then_password_in_order() -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_authority_cookie()],
    )

    candidate = _adapter(secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert secrets.fields == ["username", "password"]
    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert browser.actions == [
        "geometry",
        "mouse",
        "geometry",
        "mouse",
        "navigate",
    ]


def test_a_remembered_account_resumes_at_the_password_step() -> None:
    """A retained profile puts NYT's login at the password step.

    The page still shows the remembered address in a visible but READ-ONLY
    field. `username_visible` now selects on editability, so that decoration
    reads false and the flow reaches the password step with no
    mutual-exclusion guard — the observation carries the distinction instead
    of the branch.

    Filling the read-only address is what blocked on actionability until
    Playwright times out on a read-only field. That the
    observation truly reads false on this page shape is pinned separately by
    the `nyt-password_step` auth-surface fixture; this pins what the flow does
    once it does.
    """

    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_authority_cookie()],
    )

    candidate = _adapter(secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert secrets.fields == ["password"]  # never touches the read-only email
    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT


def test_an_ambiguous_step_attempts_the_username_rather_than_skipping_it() -> None:
    """Both fields editable is not a shape either NYT step is known to serve.

    If one ever is, failing toward *attempting* the username costs a redundant
    fill. Failing the other way skips a step that was required and strands the
    flow at a password box it can never satisfy — which is the direction the
    earlier guard chose, and exactly how the email step broke.
    """

    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True, "password_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_authority_cookie()],
    )

    _adapter(secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert secrets.fields == ["username", "password"]


def test_a_fresh_login_still_fills_the_username_first() -> None:
    """The resume path must not weaken the normal two-step flow."""

    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True},
            {"password_visible": True},
            {"authenticated": True},
            {"authenticated": True},
        ],
        cookies=[_authority_cookie()],
    )

    _adapter(secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert secrets.fields == ["username", "password"]


def test_a_second_factor_is_a_typed_terminal_not_a_retry() -> None:
    browser = FakeBrowser([{"username_visible": True, "second_factor": True}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(secrets=FakeSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.SECOND_FACTOR_REQUIRED
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is (
        MintFailureCategory.SECOND_FACTOR_REQUIRED
    )


@pytest.mark.parametrize(
    ("observation", "outcome", "category"),
    [
        (
            {"account_alert": True},
            MintOutcome.ACCOUNT_ALERT,
            MintFailureCategory.ACCOUNT_ALERT,
        ),
        (
            {"credential_rejected": True},
            MintOutcome.CREDENTIAL_REJECTED,
            MintFailureCategory.CREDENTIAL_REJECTED,
        ),
    ],
)
def test_terminal_observations_have_stable_typed_classification(
    observation: dict[str, bool],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    browser = FakeBrowser([{"username_visible": True, **observation}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(secrets=FakeSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.CREDENTIAL
    assert caught.value.evidence.category is category


def test_secret_delivery_failure_is_classified_not_swallowed() -> None:
    browser = FakeBrowser([{"username_visible": True}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(secrets=UnavailableSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.category is (
        MintFailureCategory.SECRET_DELIVERY_FAILED
    )


def test_an_unsolved_datadome_challenge_blocks_rather_than_continues() -> None:
    browser = FakeBrowser(
        [{"username_visible": True}],
        challenge_vendor="datadome",
        challenge_state="interactive",
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(
            secrets=FakeSecrets(), datadome=FakeDataDome(accepted=False)
        ).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.CHALLENGE_BLOCKED


def test_challenge_infrastructure_failure_is_not_a_provider_verdict() -> None:
    browser = FakeBrowser(
        [{"username_visible": True}],
        challenge_vendor="datadome",
        challenge_state="interactive",
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(
            secrets=FakeSecrets(), datadome=UnavailableDataDome()
        ).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.INFRASTRUCTURE


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
def test_cookie_export_failures_have_stable_classification(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[SessionCookieError],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise error_type("fixture cookie failure")

    monkeypatch.setattr(
        "newsclip.providers.nyt_auth.normalize_browser_cookie_export", fail
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter()._candidate(
            FakeBrowser([{"authenticated": True}], cookies=[_authority_cookie()]),
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is category


def test_readiness_timeout_is_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((0.0, 0.1, 30.1))
    monkeypatch.setattr(
        "newsclip.providers.nyt_auth.time.monotonic",
        lambda: next(ticks),
    )
    browser = FakeBrowser([{}, {}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter().rehydrate_profile(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.PROFILE
    assert caught.value.evidence.category is MintFailureCategory.TIMEOUT
