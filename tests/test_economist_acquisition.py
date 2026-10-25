from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
    AuthEvidenceFamily,
    AuthPhase,
    MouseTarget,
    ObservedNavigation,
    RouteClass,
)
from newsclip.challenge_resolver import ChallengeResolver
from newsclip.login import LoginInfrastructureError
from newsclip.models import MintOutcome
from newsclip.provider_config import load_provider_spec
from newsclip.providers import economist_auth as economist_auth_module
from newsclip.providers.economist import EconomistLoginRecipe
from newsclip.providers.economist_auth import (
    EconomistAcquisitionAdapter,
    EconomistLoginObservation,
)
from newsclip.session_cookies import (
    SessionCookieError,
    SessionCookieFormatError,
    SessionCookiesMissing,
)

NOW = datetime(2026, 7, 21, tzinfo=UTC)
FUTURE = (NOW + timedelta(days=30)).timestamp()
ARTICLE_URL = (
    "https://www.economist.com/business/2026/07/16/"
    "how-sk-hynix-became-the-king-of-advanced-memory-chips"
)


def _full_article_html() -> str:
    paragraphs = "".join(
        "<p>Substantive Economist fixture reporting proves paid article access. "
        + "Verified words preserve the same full-content assessment boundary. " * 20
        + "</p>"
        for _ in range(5)
    )
    return f"""
    <html><head>
      <title>Fixture Economist report</title>
      <link rel="canonical" href="{ARTICLE_URL}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Fixture Economist report"}}
      </script>
    </head><body><main><article>
      <h1>Fixture Economist report</h1>{paragraphs}
    </article></main></body></html>
    """


@pytest.mark.parametrize("full", [True, False])
def test_cloudflare_clearance_with_passive_assets_preserves_paid_assessment(
    tmp_path: Path, full: bool
) -> None:
    from uuid import uuid4

    from patchright.sync_api import sync_playwright

    from newsclip.browser_retrieval import PatchrightBrowserRetriever
    from newsclip.browser_runtime import LeaseManager
    from newsclip.browser_runtime.runtime import PatchrightMintContext
    from newsclip.challenges import ChallengeVendor
    from newsclip.cloudflare_interstitial import CloudflareInterstitialMechanic
    from newsclip.extraction import TrafilaturaExtractor
    from newsclip.models import PortableCookie, SessionArtifact
    from newsclip.provider_config import BrowserRetrievalSpec
    from newsclip.providers.economist import EconomistProvider

    article = (_full_article_html() if full else _teaser_html()).replace(
        "</head>",
        '<script type="application/json">{"provider":"datadome"}</script></head>',
    )
    challenge = """<title>Just a moment...</title><script>
      // /cdn-cgi/challenge-platform/inert-fixture
      setTimeout(() => location.reload(), 100);
    </script>"""
    navigations: list[str] = []

    class Resolver(ChallengeResolver):
        def resolve(self, browser, mode):
            return super().resolve(
                PatchrightMintContext(browser.page.context, browser.page), mode
            )

    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)

        def factory(**kwargs):
            context = chromium.new_context()

            def route_request(route):
                assert route.request.url == ARTICLE_URL
                navigations.append(route.request.url)
                first = len(navigations) == 1
                route.fulfill(
                    status=403 if first else 200,
                    content_type="text/html",
                    body=challenge if first else article,
                )

            context.route("**/*", route_request)
            return context

        mechanic = CloudflareInterstitialMechanic(wall_budget_seconds=2)
        retriever = PatchrightBrowserRetriever(
            challenge_mode=ChallengeMode.AUTO,
            context_factory=factory,
            profile_resolver=lambda *_: tmp_path / "profile",
            lease_manager=LeaseManager(tmp_path / "leases"),
            policies={"economist": BrowserRetrievalSpec()},
            challenge_resolvers={
                "economist": Resolver(
                    {ChallengeVendor.CLOUDFLARE_INTERSTITIAL: mechanic}
                )
            },
        )
        session = SessionArtifact(
            generation_id=uuid4(),
            provider="economist",
            created_at=NOW,
            verified_at=NOW,
            cookies=(
                PortableCookie(name="session", value="inert", domain=".economist.com"),
            ),
        )
        try:
            fetch = retriever.for_provider("economist").get(
                ARTICLE_URL, session=session
            )
            assert fetch.http_status == 200
            assert fetch.session_cookie_present
            assert navigations == [ARTICLE_URL, ARTICLE_URL]
            assessment = EconomistProvider().assess(
                ARTICLE_URL, fetch, TrafilaturaExtractor().extract(fetch)
            )
            assert assessment.promotable is full
            if full:
                assert assessment.identity_match
            else:
                assert assessment.access_state.value == "teaser"
                assert assessment.reason == "paywall_teaser"
        finally:
            retriever.close()
            chromium.close()


def _teaser_html() -> str:
    return f"""
    <html><head><title>Fixture Economist report</title>
      <link rel="canonical" href="{ARTICLE_URL}">
      <script type="application/ld+json">
        {{"@context":"https://schema.org","@type":"NewsArticle",
          "headline":"Fixture Economist report"}}
      </script>
    </head><body><main><article><h1>Fixture Economist report</h1>
      <p>Short preview.</p><teg-inline-wall>Log in</teg-inline-wall>
    </article></main></body></html>
    """


class FakeSecrets:
    def __init__(self) -> None:
        self.fields: list[str] = []

    def fill(self, browser, *, field: str, **kwargs) -> None:  # noqa: ANN001
        self.fields.append(field)


class UnavailableSecrets(FakeSecrets):
    def fill(self, browser, *, field: str, **kwargs) -> None:  # noqa: ANN001
        raise LoginInfrastructureError("fixture unavailable")


class FakeLocator:
    def __init__(self, visible: bool) -> None:
        self._visible = visible

    def count(self) -> int:
        return int(self._visible)

    def nth(self, index: int) -> FakeLocator:
        assert index == 0
        return self

    def is_visible(self) -> bool:
        return self._visible

    def bounding_box(self) -> dict[str, float] | None:
        if not self._visible:
            return None
        return {"x": 10, "y": 10, "width": 300, "height": 180}


class FakePage:
    frames: list[object] = []

    def __init__(self, html: str, browser: FakeBrowser) -> None:
        self.html = html
        self.browser = browser
        self.url = "about:blank"

    def content(self) -> str:
        return self.html

    def locator(self, selector: str) -> FakeLocator:
        visible = (
            self.browser.challenge_state == "interactive"
            and "captcha-delivery" in selector
        )
        return FakeLocator(visible)

    def evaluate(self, script: str) -> dict[str, float]:
        return {"width": 1280, "height": 800}


class FakeBrowser:
    def __init__(
        self,
        observations: list[dict[str, bool]],
        *,
        cookies: list[dict[str, object]] | None = None,
        article_html: str | None = None,
        challenge_vendor: str = "none",
        challenge_state: str = "none",
        consent_results: list[bool] | None = None,
    ) -> None:
        self.observations = list(observations)
        self.last = observations[-1] if observations else {}
        self.cookie_values = list(cookies or [])
        self.challenge_vendor = challenge_vendor
        self.challenge_state = challenge_state
        self.page = FakePage(article_html or _full_article_html(), self)
        self.consent_results = list(consent_results or [])
        self.actions: list[str] = []
        self.waits: list[float] = []
        self.current_url = "about:blank"

    def navigate(self, url: str) -> None:
        self.actions.append(f"navigate:{url}")
        self.current_url = url
        self.page.url = url

    def navigate_observed(
        self,
        url: str,
        *,
        timeout_seconds: float,
    ) -> ObservedNavigation:
        assert timeout_seconds == 30
        self.navigate(url)
        return ObservedNavigation(200, url, "text/html")

    def click_optional(self, selectors) -> bool:  # noqa: ANN001
        return self.consent_results.pop(0) if self.consent_results else False

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)

    def evaluate(self, script: str):  # noqa: ANN201
        if "datadomeAsset" in script:
            return {
                "vendor": self.challenge_vendor,
                "state": self.challenge_state,
            }
        if self.observations:
            self.last = self.observations.pop(0)
        return self.last

    def next_observation(self) -> dict[str, bool]:
        if self.observations:
            self.last = self.observations.pop(0)
        return self.last

    def cookies(self) -> list[dict[str, object]]:
        return list(self.cookie_values)

    def user_agent(self) -> str:
        return "FixtureBrowser/1.0"

    def mouse_target(self, selectors) -> MouseTarget:  # noqa: ANN001
        self.actions.append("geometry")
        return MouseTarget(5, 5)

    def mouse_click(self, target: MouseTarget) -> None:
        self.actions.append("mouse")


def _cookie(*, value: str = "SESSION_VALUE") -> dict[str, object]:
    return {
        "name": "blaize_session",
        "value": value,
        "domain": ".economist.com",
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
) -> EconomistAcquisitionAdapter:
    return FixtureEconomistAdapter(
        recipe=EconomistLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({}),
        secrets=secrets,
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
def test_economist_cookie_export_failures_have_stable_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[SessionCookieError],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    def fail(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise error_type("fixture cookie failure")

    monkeypatch.setattr(
        "newsclip.providers.economist_auth.normalize_browser_cookie_export", fail
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._candidate(
            FakeBrowser([], cookies=[_cookie()]),
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is category


@pytest.mark.parametrize("defect", ("missing_control", "unknown_observation"))
def test_economist_auth_surface_contract_is_owned_by_economist(
    defect: str, tmp_path: Path
) -> None:
    spec = load_provider_spec("economist")
    auth = spec.require_auth()
    if defect == "missing_control":
        controls = dict(auth.controls)
        controls.pop("password")
        auth = auth.model_copy(update={"controls": controls})
    else:
        observations = dict(auth.observations)
        observations["provider_private_state"] = next(iter(observations.values()))
        auth = auth.model_copy(update={"observations": observations})
    selected = spec.model_copy(update={"auth": auth})

    with pytest.raises(ValueError, match="authentication"):
        EconomistAcquisitionAdapter(
            recipe=EconomistLoginRecipe(verification_url=ARTICLE_URL),
            challenge_resolver=ChallengeResolver({}),
            spec=selected,
        )


class FixtureEconomistAdapter(EconomistAcquisitionAdapter):
    def _observe(self, browser: FakeBrowser) -> EconomistLoginObservation:
        return EconomistLoginObservation.model_validate(browser.next_observation())


def test_retained_profile_requires_paid_article_proof_without_secrets(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser([{"authenticated": True}], cookies=[_cookie()])

    candidate = _adapter(tmp_path, secrets=secrets).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
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
    assert browser.actions == [
        "navigate:https://www.economist.com/api/auth/login",
        f"navigate:{ARTICLE_URL}",
    ]


def test_visible_login_form_returns_to_bounded_password_mint(tmp_path: Path) -> None:
    browser = FakeBrowser([{"username_visible": True, "password_visible": True}])

    candidate = _adapter(tmp_path).rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is None


def test_rehydrate_retries_transient_entry_document_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    browser = FakeBrowser([{"authenticated": True}], cookies=[_cookie()])
    attempts = 0

    def resolve(browser, mode) -> None:  # noqa: ANN001
        nonlocal attempts
        del browser, mode
        attempts += 1
        if attempts == 1:
            raise economist_auth_module._TransientNavigation

    monkeypatch.setattr(adapter, "_resolve_challenge", resolve)

    candidate = adapter.rehydrate_profile(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.DETECT_ONLY,
    )

    assert candidate is not None
    assert candidate.evidence.mode is AcquisitionMode.PROFILE_REHYDRATE
    assert attempts == 3
    assert browser.actions[-1] == f"navigate:{ARTICLE_URL}"


def test_entry_document_replacement_remains_deadline_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    browser = FakeBrowser([])
    monotonic = iter((0.0, 46.0))
    monkeypatch.setattr(
        economist_auth_module.time,
        "monotonic",
        lambda: next(monotonic),
    )
    monkeypatch.setattr(adapter, "_settle_consent", lambda browser: None)
    monkeypatch.setattr(
        adapter,
        "_resolve_challenge",
        lambda browser, mode: (_ for _ in ()).throw(
            economist_auth_module._TransientNavigation
        ),
    )

    with pytest.raises(AcquisitionFailure) as caught:
        adapter._open_login_entry(
            browser,
            ChallengeMode.DETECT_ONLY,
            failure_stage=MintFailureStage.PROFILE,
        )

    assert caught.value.outcome is MintOutcome.TIMEOUT
    assert caught.value.evidence.stage is MintFailureStage.PROFILE
    assert browser.waits == []


def test_same_page_credentials_are_filled_once_then_mouse_submitted(
    tmp_path: Path,
) -> None:
    secrets = FakeSecrets()
    browser = FakeBrowser(
        [
            {"username_visible": True, "password_visible": True},
            {"authenticated": True},
        ],
        cookies=[_cookie()],
    )

    candidate = _adapter(tmp_path, secrets=secrets).mint_credentials(
        browser,
        account_key="default",
        challenge_mode=ChallengeMode.AUTO,
    )

    assert secrets.fields == ["username", "password"]
    assert browser.actions[:2] == ["geometry", "mouse"]
    assert browser.actions[-1] == f"navigate:{ARTICLE_URL}"
    assert candidate.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
    assert candidate.evidence.credential_action is CredentialAction.PASSWORD_SUBMIT


def test_callback_retries_one_transient_document_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    observations: list[EconomistLoginObservation | Exception] = [
        RuntimeError("Execution context was destroyed during navigation"),
        EconomistLoginObservation(authenticated=True),
    ]
    monkeypatch.setattr(adapter, "_resolve_challenge", lambda browser, mode: None)

    def observe(browser) -> EconomistLoginObservation:  # noqa: ANN001
        result = observations.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(adapter, "_observe", observe)

    observation = adapter._wait_for_authenticated(
        FakeBrowser([]), ChallengeMode.DETECT_ONLY
    )

    assert observation.authenticated is True
    assert observations == []


def test_callback_retries_one_wrapped_blank_document_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    blank_document = AcquisitionFailure(
        MintOutcome.UNKNOWN_FLOW,
        MintFailureEvidence(
            stage=MintFailureStage.CREDENTIAL,
            category=MintFailureCategory.UNKNOWN,
        ),
    )
    observations: list[EconomistLoginObservation | AcquisitionFailure] = [
        blank_document,
        EconomistLoginObservation(authenticated=True),
    ]
    monkeypatch.setattr(adapter, "_resolve_challenge", lambda browser, mode: None)

    def observe(browser) -> EconomistLoginObservation:  # noqa: ANN001
        result = observations.pop(0)
        if isinstance(result, AcquisitionFailure):
            raise result
        return result

    monkeypatch.setattr(adapter, "_observe", observe)

    observation = adapter._wait_for_authenticated(
        FakeBrowser([]), ChallengeMode.DETECT_ONLY
    )

    assert observation.authenticated is True
    assert observations == []


def test_callback_does_not_mask_repeated_unknown_observation_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    attempts = 0
    monkeypatch.setattr(adapter, "_resolve_challenge", lambda browser, mode: None)

    def observe(browser) -> EconomistLoginObservation:  # noqa: ANN001
        nonlocal attempts
        attempts += 1
        raise AcquisitionFailure(
            MintOutcome.UNKNOWN_FLOW,
            MintFailureEvidence(
                stage=MintFailureStage.CREDENTIAL,
                category=MintFailureCategory.UNKNOWN,
            ),
        )

    monkeypatch.setattr(adapter, "_observe", observe)

    with pytest.raises(AcquisitionFailure) as caught:
        adapter._wait_for_authenticated(FakeBrowser([]), ChallengeMode.DETECT_ONLY)

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert attempts == 2


def test_provider_origin_callback_defers_authority_to_paid_probe(
    tmp_path: Path,
) -> None:
    adapter = EconomistAcquisitionAdapter(
        recipe=EconomistLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({}),
        clock=lambda: NOW,
    )
    callback = ObservationBrowser(
        ObservationPage(set()),
        "https://www.economist.com/api/auth/callback/salesforce",
    )

    observation = adapter._observe(callback)  # type: ignore[arg-type]

    assert observation.authenticated is True


@pytest.mark.parametrize(
    ("observation", "outcome", "category"),
    [
        (
            {"second_factor": True},
            MintOutcome.SECOND_FACTOR_REQUIRED,
            MintFailureCategory.SECOND_FACTOR_REQUIRED,
        ),
        (
            {"credential_rejected": True},
            MintOutcome.CREDENTIAL_REJECTED,
            MintFailureCategory.CREDENTIAL_REJECTED,
        ),
        (
            {"account_alert": True},
            MintOutcome.ACCOUNT_ALERT,
            MintFailureCategory.ACCOUNT_ALERT,
        ),
    ],
)
def test_unsupported_or_terminal_login_states_fail_closed(
    tmp_path: Path,
    observation: dict[str, bool],
    outcome: MintOutcome,
    category: MintFailureCategory,
) -> None:
    browser = FakeBrowser([observation])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is outcome
    assert caught.value.evidence.category is category


@pytest.mark.parametrize("clears", [True, False])
def test_paid_probe_handles_datadome_passage_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clears: bool
) -> None:
    from newsclip import challenge_catalog
    from newsclip.challenges import ChallengeVendor
    from newsclip.datadome import DataDomeSliderMechanic
    from newsclip.providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS

    # Exercise the registered capability and real mechanic with a shorter
    # test-only budget. A blank challenge may clear passively or stay blocked.
    monkeypatch.setitem(
        challenge_catalog._PROMOTED_MECHANICS,
        ChallengeVendor.DATADOME,
        lambda: DataDomeSliderMechanic(wall_budget_seconds=2),
    )
    browser = FakeBrowser(
        [],
        cookies=[_cookie()],
        challenge_vendor="datadome",
        challenge_state="interactive",
    )
    passage_waits = []

    def wait_for_timeout(milliseconds):
        passage_waits.append(milliseconds)
        time.sleep(milliseconds / 1000)
        if clears and len(passage_waits) >= 2:
            browser.challenge_vendor = "none"
            browser.challenge_state = "none"

    browser.page.wait_for_timeout = wait_for_timeout
    secrets = FakeSecrets()
    adapter = _adapter(tmp_path, secrets=secrets)
    adapter._challenge_resolver = challenge_catalog.build_challenge_resolver(
        BUILTIN_PROVIDER_REGISTRATIONS["economist"].approved_challenge_vendors
    )

    def candidate():
        return adapter._candidate(
            browser,
            account_key="default",
            mode=AcquisitionMode.CREDENTIAL_MINT,
            challenge_mode=ChallengeMode.AUTO,
            credential_action=CredentialAction.PASSWORD_SUBMIT,
        )

    if clears:
        result = candidate()
        assert result.verification_fetch is not None
        assert adapter._recipe.verify_fetch(result.verification_fetch).verified
        assert passage_waits
    else:
        with pytest.raises(AcquisitionFailure) as caught:
            candidate()
        assert caught.value.evidence.category is MintFailureCategory.CHALLENGE_BLOCKED
        assert passage_waits
    assert secrets.fields == []
    assert browser.actions == [f"navigate:{ARTICLE_URL}"]


@pytest.mark.parametrize("initial_status,final_status", [(403, 200), (200, 403)])
def test_paid_probe_tracks_response_replaced_by_challenge_passage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_status: int,
    final_status: int,
) -> None:
    from patchright.sync_api import sync_playwright

    from newsclip.browser_runtime.runtime import PatchrightMintContext

    monkeypatch.setattr(economist_auth_module, "_PAID_PROBE_TIMEOUT_SECONDS", 1)
    with sync_playwright() as playwright:
        chromium = playwright.chromium.launch(headless=True)
        context = chromium.new_context()
        visits = []

        def response(route):
            if route.request.url != ARTICLE_URL:
                route.abort()
                return
            visits.append(route.request.url)
            route.fulfill(
                status=initial_status if len(visits) == 1 else final_status,
                content_type="text/html",
                body=_full_article_html(),
            )

        context.route("**/*", response)
        context.add_cookies(
            [{"name": "blaize_session", "value": "fixture-session", "url": ARTICLE_URL}]
        )
        page = context.new_page()
        browser = PatchrightMintContext(context, page)
        adapter = _adapter(tmp_path)

        def passage(browser, mode):
            if len(visits) == 1:
                browser.page.reload(wait_until="domcontentloaded")

        monkeypatch.setattr(adapter, "_resolve_challenge", passage)
        try:
            if final_status == 200:
                fetch = adapter._settle_verification_context(
                    browser, ChallengeMode.AUTO
                )
                assert fetch.http_status == 200
                assert adapter._recipe.verify_fetch(fetch).verified
            else:
                with pytest.raises(AcquisitionFailure) as caught:
                    adapter._settle_verification_context(browser, ChallengeMode.AUTO)
                assert (
                    caught.value.evidence.category
                    is MintFailureCategory.ARTICLE_NOT_FULL
                )
            # One requested navigation and one provider-owned challenge reload;
            # verification must never issue another GET to recover the status.
            assert visits == [ARTICLE_URL, ARTICLE_URL]
        finally:
            context.close()
            chromium.close()


def test_unregistered_interactive_challenge_fails_closed_in_auto_mode(
    tmp_path: Path,
) -> None:
    browser = FakeBrowser(
        [], challenge_vendor="datadome", challenge_state="interactive"
    )

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE
    assert caught.value.evidence.category is MintFailureCategory.CHALLENGE_BLOCKED


def test_shadow_visible_challenge_uses_shared_detector_authority(
    tmp_path: Path,
) -> None:
    class ShadowChallengeBrowser(FakeBrowser):
        def evaluate(self, script: str):  # noqa: ANN201
            if "datadomeAsset" in script:
                return {"vendor": "none", "state": "none"}
            return super().evaluate(script)

    browser = ShadowChallengeBrowser([], challenge_state="interactive")

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.AUTO,
        )

    assert caught.value.outcome is MintOutcome.CHALLENGE_BLOCKED
    assert caught.value.evidence.stage is MintFailureStage.CHALLENGE


def test_unavailable_secret_is_redacted_infrastructure_failure(tmp_path: Path) -> None:
    browser = FakeBrowser([{"username_visible": True, "password_visible": True}])

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path, secrets=UnavailableSecrets()).mint_credentials(
            browser,
            account_key="default",
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.INFRASTRUCTURE_ERROR
    assert caught.value.evidence.category is MintFailureCategory.SECRET_DELIVERY_FAILED


def test_paid_probe_rejects_logged_out_teaser(tmp_path: Path) -> None:
    browser = FakeBrowser(
        [],
        cookies=[_cookie()],
        article_html=_teaser_html(),
    )
    browser.current_url = ARTICLE_URL
    browser.page.url = ARTICLE_URL

    adapter = _adapter(tmp_path)
    fetch = adapter._browser_article_fetch(
        browser,
        ObservedNavigation(200, ARTICLE_URL, "text/html"),
    )

    assert not adapter._recipe.verify_fetch(fetch).verified


def test_paid_probe_uses_observed_non_success_status(tmp_path: Path) -> None:
    browser = FakeBrowser([], cookies=[_cookie()])
    browser.current_url = ARTICLE_URL
    browser.page.url = ARTICLE_URL

    adapter = _adapter(tmp_path)
    fetch = adapter._browser_article_fetch(
        browser,
        ObservedNavigation(503, ARTICLE_URL, "text/html"),
    )

    assert fetch.http_status == 503
    assert not adapter._recipe.verify_fetch(fetch).verified


@pytest.mark.parametrize("cookies", [[], [_cookie(value="")]])
def test_paid_probe_cannot_export_an_empty_session(
    tmp_path: Path,
    cookies: list[dict[str, object]],
) -> None:
    browser = FakeBrowser([], cookies=cookies)

    with pytest.raises(AcquisitionFailure) as caught:
        _adapter(tmp_path)._candidate(
            browser,
            account_key="default",
            mode=AcquisitionMode.PROFILE_REHYDRATE,
            challenge_mode=ChallengeMode.DETECT_ONLY,
        )

    assert caught.value.outcome is MintOutcome.UNKNOWN_FLOW
    assert caught.value.evidence.stage is MintFailureStage.SESSION
    assert caught.value.evidence.category is MintFailureCategory.SESSION_MISSING


class ObservationLocator:
    def __init__(
        self,
        *,
        visible: bool,
        body_text: str = "",
    ) -> None:
        self._visible = visible
        self._body_text = body_text

    @property
    def first(self) -> ObservationLocator:
        return self

    def count(self) -> int:
        return int(self._visible)

    def nth(self, index: int) -> ObservationLocator:
        assert index == 0
        return self

    def is_visible(self) -> bool:
        return self._visible

    def inner_text(self, *, timeout: int) -> str:
        assert timeout == 2_000
        return self._body_text


class ObservationPage:
    frames: list[object] = []

    def __init__(self, visible_selectors: set[str], body_text: str = "") -> None:
        self._visible_selectors = visible_selectors
        self._body_text = body_text

    def locator(self, selector: str) -> ObservationLocator:
        if selector == "body":
            return ObservationLocator(visible=True, body_text=self._body_text)
        return ObservationLocator(visible=selector in self._visible_selectors)


class InvalidSelectorPage(ObservationPage):
    def locator(self, selector: str) -> ObservationLocator:
        if selector != "body":
            raise ValueError("PRIVATE_SELECTOR_ERROR")
        return super().locator(selector)


class ObservationBrowser:
    def __init__(self, page: ObservationPage, current_url: str) -> None:
        self.page = page
        self.current_url = current_url


def test_native_locator_observation_handles_shadow_controls_and_rendered_errors(
    tmp_path: Path,
) -> None:
    adapter = EconomistAcquisitionAdapter(
        recipe=EconomistLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({}),
        clock=lambda: NOW,
    )
    form = ObservationBrowser(
        ObservationPage(
            {"input[name='username']", "input[type='password']"},
            "Incorrect email or password",
        ),
        "https://myaccount.economist.com/s/login",
    )
    recorded: list[dict[str, object]] = []
    form.record_auth_observation = (  # type: ignore[attr-defined]
        lambda **facts: recorded.append(facts)
    )

    form_observation = adapter._observe(form)  # type: ignore[arg-type]

    assert form_observation.username_visible is True
    assert form_observation.password_visible is True
    assert form_observation.credential_rejected is True
    assert form_observation.authenticated is False
    assert recorded == [
        {
            "phase": AuthPhase.ENTRY,
            "state_code": "credential_rejected",
            "observation_id": "credential_rejected",
            "evidence_families": (AuthEvidenceFamily.TEXT,),
            "route_class": RouteClass.PUBLISHER_AUTH,
            "selector_error": False,
        }
    ]

    authenticated = ObservationBrowser(
        ObservationPage(set()),
        "https://www.economist.com/",
    )

    authenticated_observation = adapter._observe(  # type: ignore[arg-type]
        authenticated
    )

    assert authenticated_observation.authenticated is True
    assert authenticated_observation.username_visible is False
    assert authenticated_observation.password_visible is False


def test_native_locator_selector_error_is_recorded_and_fails_closed(
    tmp_path: Path,
) -> None:
    adapter = EconomistAcquisitionAdapter(
        recipe=EconomistLoginRecipe(verification_url=ARTICLE_URL),
        challenge_resolver=ChallengeResolver({}),
        clock=lambda: NOW,
    )
    browser = ObservationBrowser(
        InvalidSelectorPage(set()),
        "https://myaccount.economist.com/s/login",
    )
    recorded: list[dict[str, object]] = []
    browser.record_auth_observation = (  # type: ignore[attr-defined]
        lambda **facts: recorded.append(facts)
    )

    with pytest.raises(AcquisitionFailure) as captured:
        adapter._observe(browser)  # type: ignore[arg-type]

    assert captured.value.evidence.category is MintFailureCategory.UNKNOWN
    assert recorded == [
        {
            "phase": AuthPhase.ENTRY,
            "state_code": "selector_error",
            "observation_id": None,
            "evidence_families": (AuthEvidenceFamily.NONE,),
            "route_class": RouteClass.PUBLISHER_AUTH,
            "selector_error": True,
        }
    ]
