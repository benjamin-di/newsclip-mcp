"""Economist same-page Salesforce password acquisition.

The provider's login form is rendered inside open Salesforce shadow roots.
Patchright locators pierce those roots for both observation and secret delivery
without reading field values. Only registered challenge mechanics may run;
every identity factor other than a password fails closed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

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
    parse_auth_observation,
    record_auth_observation,
)
from ..browser_runtime import (
    AuthPhase,
    ObservedNavigation,
)
from ..browser_verification import MainDocumentResponse, capture_verification_fetch
from ..challenge_resolver import ChallengeResolution, ChallengeResolver
from ..challenges import ChallengeInfrastructureError
from ..contracts import AuthBrowserSession, LoginRecipe, SecretFiller
from ..login import LoginInfrastructureError, OpSecretFiller
from ..models import FrozenModel, MintOutcome, RawFetch, SessionArtifact
from ..provider_config import ProviderSpec, load_provider_spec, validate_auth_surface
from ..session_cookies import (
    SessionCookieFormatError,
    SessionCookiesMissing,
    normalize_browser_cookie_export,
)
from ..timing import TimingStep, timing_step

_ENTRY_TIMEOUT_SECONDS = 30
_CALLBACK_TIMEOUT_SECONDS = 45
_PAID_PROBE_TIMEOUT_SECONDS = 30


class EconomistLoginObservation(FrozenModel):
    username_visible: bool = False
    password_visible: bool = False
    second_factor: bool = False
    credential_rejected: bool = False
    account_alert: bool = False
    authenticated: bool = False


class _TransientNavigation(RuntimeError):
    """The provider replaced the document during a bounded callback poll."""


class EconomistAcquisitionAdapter:
    provider = "economist"

    def __init__(
        self,
        *,
        recipe: LoginRecipe,
        challenge_resolver: ChallengeResolver,
        secrets: SecretFiller | None = None,
        clock: Callable[[], datetime] | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("economist")
        auth = selected_spec.require_auth()
        selected_spec.require_session()
        if selected_spec.key != self.provider:
            raise ValueError("Economist acquisition requires the Economist definition")
        validate_auth_surface(
            auth,
            expected_controls={"username", "password", "submit", "consent"},
            required_observations=set(EconomistLoginObservation.model_fields),
            token_probe="forbidden",
        )
        if recipe.provider != selected_spec.key:
            raise ValueError("Economist acquisition recipe/provider mismatch")
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
        self._secrets = secrets or OpSecretFiller()
        self._challenge_resolver = challenge_resolver
        self._clock = clock or (lambda: datetime.now(UTC))
        self._observation_phase = AuthPhase.ENTRY

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
            if not observation.authenticated:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.PROFILE,
                    MintFailureCategory.SESSION_MISSING,
                )
            return self._candidate(
                browser,
                account_key=account_key,
                mode=AcquisitionMode.PROFILE_REHYDRATE,
                challenge_mode=challenge_mode,
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
            observation = self._observe_for_phase(browser, AuthPhase.ENTRY)
            if not (observation.username_visible and observation.password_visible):
                observation = self._open_login_entry(
                    browser,
                    challenge_mode,
                    failure_stage=MintFailureStage.CREDENTIAL,
                )
            self._terminal(observation)
            if not (observation.username_visible and observation.password_visible):
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.CONTROL_MISSING,
                )
            with timing_step(TimingStep.USERNAME, provider=self.provider):
                self._secrets.fill(
                    browser,
                    secret_ref=self._recipe.secret_ref,
                    field="username",
                    selectors=self._auth.control("username"),
                    allowed_origins=self._recipe.allowed_origins,
                )
            with timing_step(TimingStep.PASSWORD, provider=self.provider):
                self._secrets.fill(
                    browser,
                    secret_ref=self._recipe.secret_ref,
                    field="password",
                    selectors=self._auth.control("password"),
                    allowed_origins=self._recipe.allowed_origins,
                )
                self._mouse_submit(browser, self._auth.control("submit"))
            with timing_step(TimingStep.CALLBACK, provider=self.provider):
                self._wait_for_authenticated(browser, challenge_mode)
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

    def _open_login_entry(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
        *,
        failure_stage: MintFailureStage,
    ) -> EconomistLoginObservation:
        with timing_step(TimingStep.LOGIN_FRONTDOOR, provider=self.provider):
            browser.navigate(str(self._auth.login_url))
        self._settle_consent(browser)
        deadline = time.monotonic() + _ENTRY_TIMEOUT_SECONDS
        while True:
            try:
                self._resolve_challenge(browser, challenge_mode)
                observation = self._observe_for_phase(
                    browser,
                    (
                        AuthPhase.PROFILE
                        if failure_stage is MintFailureStage.PROFILE
                        else AuthPhase.ENTRY
                    ),
                )
            except _TransientNavigation:
                if time.monotonic() >= deadline:
                    break
                browser.wait(0.25)
                continue
            self._terminal(observation)
            if observation.authenticated or (
                observation.username_visible and observation.password_visible
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

    def _wait_for_authenticated(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> EconomistLoginObservation:
        deadline = time.monotonic() + _CALLBACK_TIMEOUT_SECONDS
        observation_retry_available = True
        while time.monotonic() < deadline:
            try:
                browser.wait(0.25)
                self._resolve_challenge(browser, challenge_mode)
                observation = self._observe_for_phase(browser, AuthPhase.CALLBACK)
            except _TransientNavigation:
                continue
            except AcquisitionFailure as error:
                if (
                    observation_retry_available
                    and error.outcome is MintOutcome.UNKNOWN_FLOW
                    and error.evidence.stage is MintFailureStage.CREDENTIAL
                    and error.evidence.category is MintFailureCategory.UNKNOWN
                ):
                    # Salesforce can briefly expose a blank replacement document
                    # after submit. Retry one opaque observation fault inside the
                    # existing callback deadline; repeated faults remain terminal.
                    observation_retry_available = False
                    continue
                raise
            except Exception as error:
                if _context_replaced(error):
                    continue
                raise
            self._terminal(observation)
            if observation.authenticated:
                return observation
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.CALLBACK,
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
            if _context_replaced(error):
                raise _TransientNavigation from error
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
        browser.mouse_click(browser.mouse_target(selectors))

    def _settle_consent(self, browser: AuthBrowserSession) -> None:
        for _ in range(12):
            if browser.click_optional(self._auth.control("consent")):
                browser.wait(0.5)
                return
            browser.wait(0.25)

    def _observe(
        self,
        browser: AuthBrowserSession,
    ) -> EconomistLoginObservation:
        phase = self._observation_phase
        try:
            parsed = urlsplit(browser.current_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            path = parsed.path.lower()
            authenticated_spec = self._auth.observations["authenticated"]
            if host in authenticated_spec.required_hosts and not any(
                path.startswith(prefix.lower())
                for prefix in authenticated_spec.excluded_path_prefixes
            ):
                # The provider-origin callback is only a transition signal.
                # _candidate still requires a FULL paid article before any
                # session can be persisted.
                callback_states = {
                    name: name == "authenticated" for name in self._auth.observations
                }
                callback_families = {
                    name: (["host_class"] if value else [])
                    for name, value in callback_states.items()
                }
                snapshot = parse_auth_observation(
                    {
                        "states": callback_states,
                        "families": callback_families,
                        "selector_error": False,
                    },
                    self._auth.observations,
                    current_url=browser.current_url,
                    publisher_hosts=self._publisher_hosts,
                    auth_hosts=self._auth_hosts,
                    identity_hosts=self._auth.identity_hosts,
                )
                return EconomistLoginObservation.model_validate(
                    record_auth_observation(browser, snapshot, phase=phase)
                )

            roots = (browser.page,)
            selector_cache: dict[str, bool] = {}

            def visible(selector: str) -> bool:
                if selector not in selector_cache:
                    selector_cache[selector] = _visible_in_roots(roots, selector)
                return selector_cache[selector]

            text = _rendered_text(roots)
            raw: dict[str, bool] = {}
            families: dict[str, list[str]] = {}
            for name, spec in self._auth.observations.items():
                # This evaluator is a second implementation of the observation
                # contract, walking shadow roots rather than one document, and
                # it does not implement `editable_selectors`. Count the field as
                # configured evidence anyway: a spec that declares only editable
                # evidence then evaluates false here rather than defaulting to
                # "no evidence configured, so true", which would be a silently
                # wrong observation instead of a visibly missing one.
                evidence_configured = bool(
                    spec.any_selectors
                    or spec.editable_selectors
                    or spec.any_text
                    or spec.any_path_contains
                )
                evidence = not evidence_configured or any(
                    visible(selector) for selector in spec.any_selectors
                )
                evidence = evidence or any(
                    marker.casefold() in text for marker in spec.any_text
                )
                evidence = evidence or any(
                    marker.lower() in path for marker in spec.any_path_contains
                )
                raw[name] = bool(
                    evidence
                    and (
                        not spec.required_selectors
                        or any(
                            visible(selector) for selector in spec.required_selectors
                        )
                    )
                    and (
                        not spec.required_text
                        or any(
                            marker.casefold() in text for marker in spec.required_text
                        )
                    )
                    and (not spec.required_hosts or host in spec.required_hosts)
                    and (
                        not spec.required_host_suffixes
                        or any(
                            host == suffix or host.endswith(f".{suffix}")
                            for suffix in spec.required_host_suffixes
                        )
                    )
                    and host not in spec.excluded_hosts
                    and not any(
                        path.startswith(prefix.lower())
                        for prefix in spec.excluded_path_prefixes
                    )
                    and all(not visible(selector) for selector in spec.absent_selectors)
                )
                matched: list[str] = []
                if raw[name] and (
                    spec.any_selectors
                    or spec.required_selectors
                    or spec.absent_selectors
                ):
                    matched.append("selector")
                if raw[name] and (spec.any_text or spec.required_text):
                    matched.append("text")
                if raw[name] and spec.any_path_contains:
                    matched.append("path")
                if raw[name] and (
                    spec.required_hosts
                    or spec.required_host_suffixes
                    or spec.excluded_hosts
                ):
                    matched.append("host_class")
                families[name] = matched
            snapshot = parse_auth_observation(
                {
                    "states": raw,
                    "families": families,
                    "selector_error": False,
                },
                self._auth.observations,
                current_url=browser.current_url,
                publisher_hosts=self._publisher_hosts,
                auth_hosts=self._auth_hosts,
                identity_hosts=self._auth.identity_hosts,
            )
            return EconomistLoginObservation.model_validate(
                record_auth_observation(browser, snapshot, phase=phase)
            )
        except AuthSelectorEvaluationError as error:
            states = {name: False for name in self._auth.observations}
            families = {name: [] for name in self._auth.observations}
            snapshot = parse_auth_observation(
                {
                    "states": states,
                    "families": families,
                    "selector_error": True,
                },
                self._auth.observations,
                current_url=browser.current_url,
                publisher_hosts=self._publisher_hosts,
                auth_hosts=self._auth_hosts,
                identity_hosts=self._auth.identity_hosts,
            )
            record_auth_observation(browser, snapshot, phase=phase)
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            ) from error
        except Exception as error:
            if _context_replaced(error):
                raise _TransientNavigation from error
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            ) from error

    def _observe_for_phase(
        self, browser: AuthBrowserSession, phase: AuthPhase
    ) -> EconomistLoginObservation:
        previous = self._observation_phase
        self._observation_phase = phase
        try:
            return self._observe(browser)
        finally:
            self._observation_phase = previous

    @staticmethod
    def _terminal(observation: EconomistLoginObservation) -> None:
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
        challenge_mode: ChallengeMode,
        credential_action: CredentialAction = CredentialAction.NONE,
    ) -> FlowCandidate:
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
            if not any(cookie.value for cookie in cookies):
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.SESSION,
                    MintFailureCategory.SESSION_MISSING,
                )
            user_agent = browser.user_agent()
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
        with MainDocumentResponse(browser.page) as document:
            observed = self._navigate_verification_context(browser)
            deadline = time.monotonic() + _PAID_PROBE_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                browser.wait(0.25)
                self._resolve_challenge(browser, challenge_mode)
                response = document.select(None)
                current = (
                    observed
                    if response is None
                    else ObservedNavigation(
                        response.status,
                        response.url,
                        response.headers.get("content-type"),
                    )
                )
                fetch = self._browser_article_fetch(browser, current)
                document.assert_current(response)
                if self._recipe.verify_fetch(fetch).verified:
                    return fetch
        raise _failure(
            MintOutcome.UNKNOWN_FLOW,
            MintFailureStage.PAID_PROBE,
            MintFailureCategory.ARTICLE_NOT_FULL,
        )

    def _navigate_verification_context(
        self,
        browser: AuthBrowserSession,
    ) -> ObservedNavigation:
        return browser.navigate_observed(
            self._recipe.verification_url,
            timeout_seconds=_PAID_PROBE_TIMEOUT_SECONDS,
        )

    def _browser_article_fetch(
        self,
        browser: AuthBrowserSession,
        observed: ObservedNavigation,
    ) -> RawFetch:
        return capture_verification_fetch(
            self._recipe.verification_url,
            observed,
            browser.page,
            retrieved_at=self._now(),
            session_cookie_present=bool(browser.cookies()),
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise LoginInfrastructureError("login clock must be timezone aware")
        return now


def _visible_in_roots(roots: tuple[Any, ...], selector: str) -> bool:
    """Use Patchright's native open-shadow and frame-aware locator engine."""

    try:
        for root in roots:
            locator = root.locator(selector)
            for index in range(locator.count()):
                if locator.nth(index).is_visible():
                    return True
    except Exception as error:
        if _context_replaced(error):
            raise
        raise AuthSelectorEvaluationError(
            "authentication selector evaluation failed"
        ) from error
    return False


def _rendered_text(roots: tuple[Any, ...]) -> str:
    """Read rendered body labels once without scripts, fields, or hidden sources."""

    fragments: list[str] = []
    for root in roots:
        body = root.locator("body")
        if body.count():
            fragments.append(str(body.first.inner_text(timeout=2_000)))
    return "\n".join(fragments).casefold()


def _context_replaced(error: BaseException) -> bool:
    """Recognize only Patchright's transient navigation error classes."""

    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain and len(chain) < 6:
        chain.append(current)
        current = current.__cause__ or current.__context__
    material = " ".join(f"{type(item).__name__} {item}".lower() for item in chain)
    return any(
        marker in material
        for marker in (
            "execution context",
            "context was destroyed",
            "frame was detached",
            "frame detached",
            "most likely because of a navigation",
        )
    )


def _failure(
    outcome: MintOutcome,
    stage: MintFailureStage,
    category: MintFailureCategory,
) -> AcquisitionFailure:
    return AcquisitionFailure(
        outcome,
        MintFailureEvidence(stage=stage, category=category),
    )


def build_economist_auth_adapter(
    recipe: LoginRecipe,
    spec: ProviderSpec,
    challenge_resolver: ChallengeResolver,
) -> EconomistAcquisitionAdapter:
    return EconomistAcquisitionAdapter(
        recipe=recipe,
        challenge_resolver=challenge_resolver,
        spec=spec,
    )


__all__ = [
    "EconomistAcquisitionAdapter",
    "EconomistLoginObservation",
    "build_economist_auth_adapter",
]
