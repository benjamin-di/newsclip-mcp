"""NYT retained-profile acquisition with DataDome handoff and an exact NYT-S gate."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import ValidationError

from ..acquisition import (
    AcquisitionEvidence,
    AcquisitionFailure,
    AcquisitionMode,
    CandidateVerificationMode,
    ChallengeMode,
    CredentialAction,
    FlowCandidate,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from ..auth_ui import (
    AuthSelectorEvaluationError,
    build_auth_observation_script,
    observe_auth_ui,
)
from ..browser_runtime import (
    AuthPhase,
    ObservedNavigation,
    PasskeyMode,
)
from ..browser_verification import capture_verification_fetch
from ..challenge_resolver import (
    ChallengeResolution,
    ChallengeResolutionStatus,
    ChallengeResolver,
)
from ..challenges import ChallengeInfrastructureError
from ..contracts import AuthBrowserSession, LoginRecipe, SecretFiller
from ..login import LoginInfrastructureError, credential_filler
from ..models import FrozenModel, MintOutcome, PortableCookie, RawFetch, SessionArtifact
from ..provider_config import ProviderSpec, load_provider_spec, validate_auth_surface
from ..session_cookies import (
    SessionCookieFormatError,
    SessionCookiesMissing,
    normalize_browser_cookie_export,
)
from ..timing import TimingStep, timing_step

# NYT sets two similarly named cookies: NYT-S, the durable subscriber authority,
# and nyt-s-present, a boolean hint observed with value "0" on an anonymous
# request. The shared prefix mechanism matches on `name.startswith(prefix)` and
# treats any non-empty value as proof, so a "nyt-s" prefix would accept
# nyt-s-present=0 — and because NYT is metered, an anonymous browser can also
# render a complete article. Together those would form a path from a logged-out
# page load to a certified paid session. Match the authority cookie exactly.
_SESSION_COOKIE_NAME = "nyt-s"


class NYTLoginObservation(FrozenModel):
    username_visible: bool = False
    password_visible: bool = False
    second_factor: bool = False
    credential_rejected: bool = False
    account_alert: bool = False
    authenticated: bool = False


class NYTAcquisitionAdapter:
    provider = "nyt"

    def __init__(
        self,
        *,
        recipe: LoginRecipe,
        secrets: SecretFiller | None = None,
        challenge_resolver: ChallengeResolver,
        clock: Callable[[], datetime] | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("nyt")
        auth = selected_spec.require_auth()
        session = selected_spec.require_session()
        if selected_spec.key != self.provider:
            raise ValueError("NYT acquisition requires the NYT provider definition")
        validate_auth_surface(
            auth,
            expected_controls={
                "username",
                "password",
                "username_submit",
                "password_submit",
                "consent",
            },
            required_observations=set(NYTLoginObservation.model_fields),
            token_probe="forbidden",
        )
        # The inverse of every other provider's check. Configuring prefixes here
        # would not take effect — this adapter never reads them — so accepting
        # the definition would imply a session proof that is not enforced.
        if session.session_cookie_name_prefixes:
            raise ValueError(
                "NYT authentication requires an exact session cookie name, not prefixes"
            )
        if recipe.provider != selected_spec.key:
            raise ValueError("NYT acquisition recipe/provider mismatch")
        self._recipe = recipe
        self._auth = auth
        self._publisher_hosts = selected_spec.identity.allowed_hosts
        self._auth_hosts = tuple(
            sorted(
                {
                    urlsplit(str(auth.login_url)).hostname or "",
                    *(
                        urlsplit(origin).hostname or ""
                        for origin in self._recipe.allowed_origins
                    ),
                }
            )
        )
        self._cookie_domains = session.allowed_cookie_domains
        self._observe_script = build_auth_observation_script(self._auth.observations)
        self._secrets = secrets or credential_filler()
        self._challenge_resolver = challenge_resolver
        self._clock = clock or (lambda: datetime.now(UTC))

    def rehydrate_profile(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate | None:
        try:
            observation = self._open_login_entry(
                browser,
                challenge_mode,
                failure_stage=MintFailureStage.PROFILE,
            )
            if observation.username_visible or observation.password_visible:
                return None
            if observation.authenticated:
                return self._candidate(
                    browser,
                    account_key=account_key,
                    mode=AcquisitionMode.PROFILE_REHYDRATE,
                    challenge_mode=challenge_mode,
                )
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.PROFILE,
                MintFailureCategory.SESSION_MISSING,
            )
        except AcquisitionFailure:
            raise
        except Exception as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.PROFILE,
                MintFailureCategory.INFRASTRUCTURE,
            ) from error

    def mint_credentials(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate:
        try:
            self._resolve_challenge(browser, challenge_mode)
            observation = self._observe(browser, phase=AuthPhase.ENTRY)
            if not observation.username_visible and not observation.password_visible:
                observation = self._open_login_entry(
                    browser,
                    challenge_mode,
                    failure_stage=MintFailureStage.CREDENTIAL,
                )
            self._terminal(observation)
            # NYT's login is two steps, and each renders the other step's field
            # as a visible but READ-ONLY decoy. Both observations therefore
            # select on editability rather than presence (see nyt.toml), which
            # is the same property `fill` requires — so each reads true only on
            # the step that is actually live, and no mutual-exclusion guard is
            # needed to tell them apart.
            #
            # An earlier guard did that job by making password_visible dominant.
            # It cured the read-only *username* at the password step and created
            # the mirror defect at the email step, where the read-only password
            # decoy suppressed the username step entirely and the fill blocked
            # for 30s (2026-07-28 cold gate, reported as
            # credential_infrastructure). Testing the property directly retires
            # both. If a step ever presents an editable username again, this
            # merely runs the username step a second time — a retry, not a skip.
            if observation.username_visible:
                with timing_step(TimingStep.USERNAME, provider=self.provider):
                    self._secrets.fill(
                        browser,
                        secret_ref=self._recipe.secret_ref,
                        field="username",
                        selectors=self._auth.control("username"),
                        allowed_origins=self._recipe.allowed_origins,
                    )
                    self._mouse_submit(browser, self._auth.control("username_submit"))
                    observation = self._wait_for(
                        browser, "password_visible", challenge_mode
                    )
            if not observation.password_visible:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.CONTROL_MISSING,
                )
            with timing_step(TimingStep.PASSWORD, provider=self.provider):
                self._secrets.fill(
                    browser,
                    secret_ref=self._recipe.secret_ref,
                    field="password",
                    selectors=self._auth.control("password"),
                    allowed_origins=self._recipe.allowed_origins,
                )
                self._mouse_submit(browser, self._auth.control("password_submit"))
            with timing_step(TimingStep.CALLBACK, provider=self.provider):
                observation = self._wait_for(
                    browser,
                    "authenticated",
                    challenge_mode,
                    require_provider_cookie=True,
                )
            if not observation.authenticated:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.SESSION,
                    MintFailureCategory.SESSION_MISSING,
                )
            return self._candidate(
                browser,
                account_key=account_key,
                mode=AcquisitionMode.CREDENTIAL_MINT,
                credential_action=CredentialAction.PASSWORD_SUBMIT,
                challenge_mode=challenge_mode,
            )
        except AcquisitionFailure:
            raise
        except LoginInfrastructureError as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECRET_DELIVERY_FAILED,
            ) from error
        except Exception as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.INFRASTRUCTURE,
            ) from error

    def _wait_for(
        self,
        browser: AuthBrowserSession,
        signal: str,
        challenge_mode: ChallengeMode,
        *,
        require_provider_cookie: bool = False,
    ) -> NYTLoginObservation:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            browser.wait(0.25)
            self._resolve_challenge(browser, challenge_mode)
            observation = self._observe(
                browser,
                phase=(
                    AuthPhase.CALLBACK
                    if signal == "authenticated"
                    else AuthPhase.PASSWORD
                ),
            )
            self._terminal(observation)
            if getattr(observation, signal) and (
                not require_provider_cookie
                or self._has_provider_cookie(browser.cookies())
            ):
                return observation
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.CREDENTIAL,
            MintFailureCategory.TIMEOUT,
        )

    def _open_login_entry(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
        *,
        failure_stage: MintFailureStage,
    ) -> NYTLoginObservation:
        with timing_step(TimingStep.LOGIN_FRONTDOOR, provider=self.provider):
            browser.navigate(str(self._auth.login_url))
        browser.suppress_passkeys(PasskeyMode.EMPTY_PRESENT)
        self._settle_consent(browser)
        return self._wait_for_entry(
            browser,
            challenge_mode,
            failure_stage=failure_stage,
        )

    def _wait_for_entry(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
        *,
        failure_stage: MintFailureStage,
    ) -> NYTLoginObservation:
        """Wait for one actionable login state without reading a secret."""

        deadline = time.monotonic() + 30
        while True:
            if browser.click_optional(self._auth.control("consent")):
                browser.wait(0.5)
            self._resolve_challenge(browser, challenge_mode)
            observation = self._observe(
                browser,
                phase=(
                    AuthPhase.PROFILE
                    if failure_stage is MintFailureStage.PROFILE
                    else AuthPhase.ENTRY
                ),
            )
            self._terminal(observation)
            if observation.username_visible or observation.password_visible:
                return observation
            if observation.authenticated and self._has_provider_cookie(
                browser.cookies()
            ):
                return observation
            if time.monotonic() >= deadline:
                break
            browser.wait(0.25)
        raise _failure(
            MintOutcome.TIMEOUT,
            failure_stage,
            MintFailureCategory.TIMEOUT,
        )

    def _resolve_challenge(
        self,
        browser: AuthBrowserSession,
        mode: ChallengeMode,
    ) -> ChallengeResolution:
        try:
            resolution = self._challenge_resolver.resolve(browser, mode)
        except ChallengeInfrastructureError as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.INFRASTRUCTURE,
            ) from error
        if not resolution.allows_continuation:
            raise _failure(
                MintOutcome.CHALLENGE_BLOCKED,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.CHALLENGE_BLOCKED,
            )
        return resolution

    @staticmethod
    def _mouse_submit(browser: AuthBrowserSession, selectors: tuple[str, ...]) -> None:
        target = browser.mouse_target(selectors)
        browser.mouse_click(target)

    def _settle_consent(self, browser: AuthBrowserSession) -> None:
        for _ in range(12):
            if browser.click_optional(self._auth.control("consent")):
                browser.wait(0.5)
                return
            browser.wait(0.25)

    def _observe(
        self,
        browser: AuthBrowserSession,
        *,
        phase: AuthPhase,
    ) -> NYTLoginObservation:
        try:
            raw = observe_auth_ui(
                browser,
                self._observe_script,
                self._auth.observations,
                phase=phase,
                publisher_hosts=self._publisher_hosts,
                auth_hosts=self._auth_hosts,
                identity_hosts=self._auth.identity_hosts,
            )
            return NYTLoginObservation.model_validate(raw)
        except (AuthSelectorEvaluationError, ValidationError) as error:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            ) from error

    @staticmethod
    def _terminal(observation: NYTLoginObservation) -> None:
        if observation.account_alert:
            raise _failure(
                MintOutcome.ACCOUNT_ALERT,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.ACCOUNT_ALERT,
            )
        if observation.second_factor:
            raise _failure(
                MintOutcome.SECOND_FACTOR_REQUIRED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.SECOND_FACTOR_REQUIRED,
            )
        if observation.credential_rejected:
            raise _failure(
                MintOutcome.CREDENTIAL_REJECTED,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.CREDENTIAL_REJECTED,
            )

    def _candidate(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        mode: AcquisitionMode,
        credential_action: CredentialAction = CredentialAction.NONE,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate:
        # Being on an nytimes.com origin is not session proof, and neither is a
        # rendered full article: the meter can grant one anonymously. Seed the
        # approved paid context and prove it the same way retrieval will, under
        # the same bounded DataDome policy used during the credential steps.
        with timing_step(TimingStep.PAID_PROBE, provider=self.provider):
            verification_fetch = self._settle_verification_context(
                browser, challenge_mode
            )
        with timing_step(TimingStep.COOKIE_EXPORT, provider=self.provider):
            now = self._now()
            try:
                cookies = normalize_browser_cookie_export(
                    browser.cookies(),
                    allowed_domains=self._recipe.allowed_cookie_domains,
                    now=now,
                )
            except SessionCookiesMissing as error:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.SESSION,
                    MintFailureCategory.SESSION_MISSING,
                ) from error
            except SessionCookieFormatError as error:
                raise _failure(
                    MintOutcome.INFRASTRUCTURE_ERROR,
                    MintFailureStage.SESSION,
                    MintFailureCategory.INFRASTRUCTURE,
                ) from error
            user_agent = browser.user_agent()
        if not any(_is_session_cookie(cookie) for cookie in cookies):
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.SESSION,
                MintFailureCategory.SESSION_MISSING,
            )
        return FlowCandidate(
            artifact=SessionArtifact(
                generation_id=uuid4(),
                provider=self.provider,
                account_key=account_key,
                created_at=now,
                verified_at=now,
                user_agent=user_agent,
                cookies=cookies,
            ),
            candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
            evidence=AcquisitionEvidence(
                mode=mode,
                credential_action=credential_action,
            ),
            verification_fetch=verification_fetch,
        )

    def _settle_verification_context(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> RawFetch:
        observed = self._navigate_verification_context(browser)
        deadline = time.monotonic() + 30
        authenticated = False
        reloaded = False
        while time.monotonic() < deadline:
            browser.wait(0.25)
            resolution = self._resolve_challenge(browser, challenge_mode)
            if resolution.status is ChallengeResolutionStatus.CLEARED:
                observed = self._navigate_verification_context(browser)
            observation = self._observe(browser, phase=AuthPhase.VERIFICATION)
            self._terminal(observation)
            if observation.authenticated:
                authenticated = True
                browser.wait(1)
                fetch = self._browser_article_fetch(browser, observed)
                if self._recipe.verify_fetch(fetch).verified:
                    return fetch
                if not reloaded:
                    observed = self._navigate_verification_context(browser)
                    reloaded = True
        if authenticated:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.PAID_PROBE,
                MintFailureCategory.ARTICLE_NOT_FULL,
            )
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.SESSION,
            MintFailureCategory.TIMEOUT,
        )

    def _navigate_verification_context(
        self,
        browser: AuthBrowserSession,
    ) -> ObservedNavigation:
        return browser.navigate_observed(
            self._recipe.verification_url,
            timeout_seconds=30,
        )

    def _browser_article_fetch(
        self,
        browser: AuthBrowserSession,
        observed: ObservedNavigation,
    ) -> RawFetch:
        # The provider's own assessment treats a full body without an observed
        # session cookie as the metered case, so report the authority cookie
        # rather than "the jar is non-empty" — an anonymous NYT page load always
        # leaves nyt-a, nyt-geo and friends behind.
        return capture_verification_fetch(
            self._recipe.verification_url,
            observed,
            browser.page,
            retrieved_at=self._now(),
            session_cookie_present=self._has_provider_cookie(browser.cookies()),
        )

    def _has_provider_cookie(self, cookies: Sequence[Mapping[str, object]]) -> bool:
        return any(
            (host := str(cookie.get("domain", "")).lower().lstrip("."))
            and any(
                host == domain or host.endswith(f".{domain}")
                for domain in self._cookie_domains
            )
            and str(cookie.get("name", "")).lower() == _SESSION_COOKIE_NAME
            and bool(str(cookie.get("value", "")))
            for cookie in cookies
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise LoginInfrastructureError("login clock must be timezone aware")
        return now


def _is_session_cookie(cookie: PortableCookie) -> bool:
    return cookie.name.lower() == _SESSION_COOKIE_NAME and bool(cookie.value)


def _failure(
    outcome: MintOutcome,
    stage: MintFailureStage,
    category: MintFailureCategory,
) -> AcquisitionFailure:
    return AcquisitionFailure(
        outcome,
        MintFailureEvidence(stage=stage, category=category),
    )


def build_nyt_auth_adapter(
    recipe: LoginRecipe,
    spec: ProviderSpec,
    challenge_resolver: ChallengeResolver,
) -> NYTAcquisitionAdapter:
    return NYTAcquisitionAdapter(
        recipe=recipe,
        challenge_resolver=challenge_resolver,
        spec=spec,
    )


__all__ = [
    "NYTAcquisitionAdapter",
    "NYTLoginObservation",
    "build_nyt_auth_adapter",
]
