"""Bloomberg retained-profile Google OAuth and PX acquisition."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NamedTuple
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
from ..browser_readiness import (
    BrowserReadinessObservation,
    BrowserSemanticSnapshot,
    ReadinessCoverageBucket,
    readiness_coverage_bucket,
    sample_semantic_snapshot,
)
from ..browser_runtime import (
    IdentityExitReason,
    IdentityHandoffCheckpoint,
    IdentityPageState,
    IdentityParentState,
    PaidProbeOutcome,
)
from ..browser_verification import (
    capture_verification_fetch,
    verification_fetch_from_snapshot,
)
from ..challenge_resolver import (
    ChallengeBlockReason,
    ChallengeResolution,
    ChallengeResolutionStatus,
    ChallengeResolver,
)
from ..challenges import ChallengeInfrastructureError
from ..contracts import AuthBrowserSession, LoginRecipe, SecretFiller
from ..extraction import TrafilaturaExtractor
from ..identity.google import (
    GoogleIdentityConfig,
    GoogleIdentityDriver,
    GoogleIdentityObservation,
    GoogleIdentityResult,
)
from ..login import LoginInfrastructureError, OpSecretFiller
from ..models import AccessState, MintOutcome, RawFetch, SessionArtifact
from ..provider_config import ProviderSpec, load_provider_spec, validate_auth_surface
from ..session_cookies import (
    SessionCookieFormatError,
    SessionCookiesMissing,
    normalize_browser_cookie_export,
)
from ..timing import TimingStep, timing_step
from .bloomberg import BloombergProvider

_BLOOMBERG_PAID_AUTH_COOKIES = frozenset({"_user-token", "octagon-jwtToken"})
_BLOOMBERG_SOFT_AUTH_COOKIES = frozenset(
    {
        "session_id",
        "session_key",
        "_session_id_backup",
        "_reg-csrf",
        "_reg-csrf-token",
        "__stripe_sid",
    }
)
_BLOOMBERG_STRONG_AUTH_COOKIES = frozenset(
    {
        "_user-token",
        "_user-id",
        "_user-data",
        "_user-role",
        "_breg-user",
        "_breg-uid",
        "octagon-jwtToken",
    }
)
_BLOOMBERG_AUTH_COOKIE_PARTS = (
    "session",
    "user-token",
    "user-id",
    "user-data",
    "user-role",
    "breg",
    "jwt",
    "csrf",
)
_BLOOMBERG_GOOGLE_AUTH_ENDPOINT = "https://login.bloomberg.com/api/login/google-auth"
#: PerimeterX cookies that carry clearance rather than device identity.
#: ``_pxhd`` is deliberately absent: it is issued while blocking.
_PERIMETERX_CLEARANCE_COOKIES = frozenset({"_px3", "_px", "_pxcts", "_pxvid"})


class _CallbackClearance(NamedTuple):
    """What the Google-callback clearance probe observed."""

    cleared: bool
    probe_status: int | None
    clearance_cookie_present: bool | None


_BLOOMBERG_ONBOARDING_CONTROLS = (
    "button:has-text('Skip')",
    "a:has-text('Skip')",
    "button:has-text('Not now')",
    "button:has-text('No thanks')",
    "button:has-text('Next')",
    "button:has-text('Continue')",
)
_GOOGLE_CALLBACK_SETTLE_SECONDS = 25
_BLOOMBERG_NAVIGATION_COMMIT_SECONDS = 30
_BLOOMBERG_LOGIN_HYDRATION_SECONDS = 90
_BLOOMBERG_GOOGLE_LAUNCH_SETTLE_SECONDS = 5
_BLOOMBERG_GOOGLE_LAUNCH_RETRY_SETTLE_SECONDS = 20
_GOOGLE_IDENTITY_CONTROLS = (
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


@dataclass(frozen=True)
class _BrowserPaidProof:
    fetch: RawFetch
    access_state: AccessState
    verified: bool
    stabilized: bool
    paid_auth_cookie_present: bool


@dataclass(frozen=True)
class _CallbackRetry:
    """The replay's own outcome, separate from the first identity result."""

    exit_reason: IdentityExitReason
    identity_page_closed: bool

    @property
    def callback_complete(self) -> bool:
        """Only the publisher predicate firing inside the replay counts."""

        return self.exit_reason is IdentityExitReason.CALLBACK_COMPLETE


class BloombergAcquisitionAdapter:
    provider = "bloomberg"

    def __init__(
        self,
        *,
        recipe: LoginRecipe,
        secrets: SecretFiller | None = None,
        challenge_resolver: ChallengeResolver,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("bloomberg")
        auth = selected_spec.require_auth()
        session = selected_spec.require_session()
        if selected_spec.key != self.provider:
            raise ValueError(
                "Bloomberg acquisition requires the Bloomberg provider definition"
            )
        validate_auth_surface(
            auth,
            expected_controls={
                "account_choices",
                "alternate",
                "consent",
                "cookie_accept",
                "email",
                "email_submit",
                "google_continue",
                "password",
                "password_choice",
                "password_submit",
                "terms_accept",
                "totp",
                "totp_choice",
                "totp_submit",
                "use_another",
            },
            required_observations=set(GoogleIdentityObservation.model_fields),
            token_probe="forbidden",
            require_auth_paths=True,
        )
        if not auth.post_callback_urls:
            raise ValueError("Bloomberg authentication requires post-callback URLs")
        if recipe.provider != selected_spec.key:
            raise ValueError("Bloomberg acquisition recipe/provider mismatch")
        readiness = selected_spec.browser_retrieval.semantic_readiness
        if readiness is None:
            raise ValueError(
                "Bloomberg authentication requires semantic browser readiness"
            )
        selected_secrets = secrets or OpSecretFiller()
        self._recipe = recipe
        self._auth = auth
        self._cookie_domains = session.allowed_cookie_domains
        self._challenge_resolver = challenge_resolver
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._readiness = readiness
        self._verification_provider = BloombergProvider(spec=selected_spec)
        self._verification_extractor = TrafilaturaExtractor()
        self._google_identity = GoogleIdentityDriver(
            GoogleIdentityConfig(
                provider_key=self.provider,
                controls={
                    name: auth.control(name) for name in _GOOGLE_IDENTITY_CONTROLS
                },
                observations=dict(auth.observations),
                secret_ref=recipe.secret_ref,
                allowed_origins=recipe.allowed_origins,
                identity_hosts=auth.identity_hosts,
            ),
            secrets=selected_secrets,
        )

    def rehydrate_profile(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate | None:
        try:
            # Do not seed a fresh profile with a guest/paywall article before
            # the OAuth front door. Browser retrieval makes the paid browser
            # marker, rather than an HTTP-only probe, the rehydration signal.
            if not self._paid_auth_cookie_present(browser):
                return None
            verification_fetch = self._browser_full_fetch(
                browser,
                challenge_mode,
                allow_auth_required=True,
            )
            if verification_fetch is None:
                return None
            return self._candidate(
                browser,
                account_key=account_key,
                mode=AcquisitionMode.PROFILE_REHYDRATE,
                callback_confirmed=False,
                verification_fetch=verification_fetch,
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
        original = None
        try:
            with timing_step(TimingStep.LOGIN_FRONTDOOR, provider=self.provider):
                try:
                    with timing_step(
                        TimingStep.BROWSER_WARMUP,
                        provider=self.provider,
                    ):
                        browser.navigate_committed(
                            "https://www.bloomberg.com/",
                            timeout_seconds=_BLOOMBERG_NAVIGATION_COMMIT_SECONDS,
                        )
                        browser.wait(3.5)
                        self._resolve_challenge(browser, challenge_mode)
                except AcquisitionFailure:
                    raise
                except Exception:
                    pass
                self._clear_bloomberg_auth_keep_px(browser)
                # Bloomberg's homepage can commit but remain perpetually
                # loading under Xvfb. Preserve its context/PX state, but never
                # reuse that poisoned page for the sign-in application.
                browser.replace_page()
                with timing_step(
                    TimingStep.PROVIDER_TRANSITION_WAIT,
                    provider=self.provider,
                ):
                    self._prepare_google_login_surface(browser, challenge_mode)
                    original = browser.page
                    popup = self._open_google_popup(browser)
            google = browser.for_page(popup)
            try:
                with timing_step(TimingStep.IDENTITY_FLOW, provider=self.provider):
                    identity_result = self._google_identity.drive(
                        google,
                        callback_complete=lambda: self._parent_left_auth(original),
                        resolve_challenge=lambda identity_browser: (
                            self._resolve_identity_challenge(
                                identity_browser, challenge_mode
                            )
                        ),
                    )
                    self._record_identity_handoff(
                        browser,
                        original=original,
                        checkpoint=IdentityHandoffCheckpoint.IDENTITY_RETURN,
                        identity_result=identity_result,
                    )
                    credential_action = identity_result.credential_action
            except BaseException:
                self._record_identity_handoff(
                    browser,
                    original=original,
                    checkpoint=IdentityHandoffCheckpoint.IDENTITY_ERROR,
                    identity_browser=google,
                )
                google.capture_diagnostic_screenshot(
                    "google-failure",
                    timeout_ms=5_000,
                )
                raise
            # GIS closes its popup before Bloomberg has necessarily consumed
            # the posted ID token. A fresh Xvfb profile can take much longer
            # than five seconds to reach /account/onboarding; do not race that
            # exchange with a second OAuth attempt.
            with timing_step(TimingStep.CALLBACK, provider=self.provider):
                callback_confirmed = self._wait_parent_callback(
                    original, timeout_seconds=_GOOGLE_CALLBACK_SETTLE_SECONDS
                )
                self._record_identity_handoff(
                    browser,
                    original=original,
                    checkpoint=IdentityHandoffCheckpoint.CALLBACK_WAIT,
                    identity_result=identity_result,
                    callback_confirmed=callback_confirmed,
                )
                if (
                    not callback_confirmed
                    and identity_result.exit_reason
                    is not IdentityExitReason.IDENTITY_CONTEXT_CLOSED
                ):
                    # Bloomberg can answer the GIS credential exchange with a
                    # PerimeterX block document on the parent page. Clear that
                    # callback boundary before replaying the cached Google state;
                    # otherwise the retry repeats the same blocked POST and never
                    # receives the paid token.
                    clearance = self._resolve_google_callback_challenge(
                        browser,
                        original=original,
                        challenge_mode=challenge_mode,
                        observe=lambda observed: self._record_identity_handoff(
                            browser,
                            original=original,
                            checkpoint=IdentityHandoffCheckpoint.CALLBACK_RETRY,
                            identity_result=identity_result,
                            callback_confirmed=False,
                            clearance=observed,
                        ),
                    )
                    if not clearance.cleared:
                        raise _failure(
                            MintOutcome.CHALLENGE_BLOCKED,
                            MintFailureStage.CHALLENGE,
                            MintFailureCategory.CHALLENGE_BLOCKED,
                        )
                    retry = self._retry_google_callback(
                        browser,
                        original=original,
                        challenge_mode=challenge_mode,
                    )
                    callback_confirmed = self._wait_parent_callback(
                        original, timeout_seconds=_GOOGLE_CALLBACK_SETTLE_SECONDS
                    )
                    self._record_identity_handoff(
                        browser,
                        original=original,
                        checkpoint=IdentityHandoffCheckpoint.CALLBACK_RETRY,
                        # Report the replay's own completion, page state, and
                        # exit reason; the first identity result describes the
                        # earlier popup and would misattribute a stranded retry
                        # to it.
                        identity_result=identity_result.model_copy(
                            update={
                                "callback_complete": retry.callback_complete,
                                "identity_page_closed": retry.identity_page_closed,
                                "exit_reason": retry.exit_reason,
                            }
                        ),
                        callback_confirmed=callback_confirmed,
                    )
            entitlement_confirmed: bool | None = None
            verification_fetch: RawFetch | None = None
            entitlement_reached = False
            verification_reached = False
            paid_probe_complete = False
            paid_proof: _BrowserPaidProof | None = None

            def keep_proof(observed: _BrowserPaidProof) -> None:
                nonlocal paid_proof
                paid_proof = observed

            try:
                with timing_step(TimingStep.PAID_PROBE, provider=self.provider):
                    entitlement_confirmed = self._settle_after_google(
                        browser, challenge_mode=challenge_mode
                    )
                    entitlement_reached = True
                    verification_fetch = self._browser_full_fetch(
                        browser,
                        challenge_mode,
                        on_proof=keep_proof,
                    )
                    verification_reached = True
                paid_probe_complete = True
            finally:
                self._record_paid_probe(
                    browser,
                    original=original,
                    outcome=(
                        PaidProbeOutcome.COMPLETE
                        if paid_probe_complete
                        else PaidProbeOutcome.INTERRUPTED
                    ),
                    callback_confirmed=callback_confirmed,
                    entitlement_confirmed=(
                        entitlement_confirmed if entitlement_reached else None
                    ),
                    verification_full=(
                        verification_fetch is not None if verification_reached else None
                    ),
                    proof=paid_proof,
                )
            if verification_fetch is None:
                if not callback_confirmed and not entitlement_confirmed:
                    self._capture_google_checkpoint(
                        browser, "identity-callback-failure"
                    )
                    raise _failure(
                        MintOutcome.UNKNOWN_FLOW,
                        MintFailureStage.CALLBACK,
                        MintFailureCategory.CALLBACK_NOT_CONFIRMED,
                    )
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.PAID_PROBE,
                    MintFailureCategory.ARTICLE_NOT_FULL,
                )
            mode = (
                AcquisitionMode.CREDENTIAL_MINT
                if credential_action is not CredentialAction.NONE
                else AcquisitionMode.PROFILE_REHYDRATE
            )
            return self._candidate(
                browser,
                account_key=account_key,
                mode=mode,
                credential_action=credential_action,
                callback_confirmed=True,
                verification_fetch=verification_fetch,
            )
        except AcquisitionFailure as failure:
            if original is not None and failure.evidence.stage in {
                MintFailureStage.CREDENTIAL,
                MintFailureStage.CALLBACK,
                MintFailureStage.TRANSPORT,
            }:
                try:
                    verification_fetch = self._browser_full_fetch(
                        browser, challenge_mode
                    )
                    if verification_fetch is not None:
                        return self._candidate(
                            browser,
                            account_key=account_key,
                            mode=AcquisitionMode.PROFILE_REHYDRATE,
                            callback_confirmed=False,
                            verification_fetch=verification_fetch,
                            refresh_failure=failure.evidence,
                        )
                except Exception:
                    pass
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

    def _prepare_google_login_surface(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> None:
        """Acquire the pre-secret login surface with one failure-specific retry."""

        for attempt in range(2):
            try:
                browser.navigate_committed(
                    str(self._auth.login_url),
                    timeout_seconds=_BLOOMBERG_NAVIGATION_COMMIT_SECONDS,
                )
                self._resolve_challenge(browser, challenge_mode)
                self._wait_for_google_login_surface(browser, challenge_mode)
                return
            except Exception as error:
                if attempt:
                    raise
                if self._target_closed(error):
                    browser.replace_page()
                    continue
                if self._login_surface_timeout(error):
                    continue
                raise
        raise AssertionError("Bloomberg login surface retry exhausted")

    def _wait_for_google_login_surface(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> None:
        deadline = time.monotonic() + _BLOOMBERG_LOGIN_HYDRATION_SECONDS
        while True:
            self._resolve_challenge(browser, challenge_mode)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _failure(
                    MintOutcome.TIMEOUT,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.TIMEOUT,
                )
            if self._settle_bloomberg_login_overlay(browser) is not None:
                continue
            control = self._auth.control("google_continue")
            if browser.wait_for_visible(
                control,
                timeout_seconds=min(1, remaining),
            ):
                return

    def _browser_full_fetch(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
        *,
        allow_auth_required: bool = False,
        on_proof: Callable[[_BrowserPaidProof], None] | None = None,
    ) -> RawFetch | None:
        proof = self._browser_paid_proof(browser, challenge_mode)
        if on_proof is not None:
            # Retain the observed verdict for diagnostics before any fail-closed
            # branch discards it. Diagnostic evidence must never change
            # authentication behavior, so a failed handoff is dropped.
            with suppress(Exception):
                on_proof(proof)
        if proof.stabilized and proof.verified and proof.paid_auth_cookie_present:
            return proof.fetch
        if (
            allow_auth_required
            and proof.stabilized
            and proof.access_state is AccessState.AUTH_REQUIRED
        ):
            return None
        if proof.access_state is AccessState.BLOCKED:
            raise _failure(
                MintOutcome.CHALLENGE_BLOCKED,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.CHALLENGE_BLOCKED,
            )
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.PAID_PROBE,
            (
                MintFailureCategory.ARTICLE_NOT_FULL
                if proof.access_state is AccessState.TEASER
                else MintFailureCategory.TIMEOUT
            ),
        )

    def _browser_paid_proof(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> _BrowserPaidProof:
        observed = browser.navigate_observed(
            self._recipe.verification_url,
            timeout_seconds=60,
        )
        browser.wait(1)
        resolution = self._resolve_challenge(
            browser,
            challenge_mode,
            allow_navigation_retry=True,
        )
        if (
            resolution.status is ChallengeResolutionStatus.CLEARED
            or resolution.reason is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
        ):
            observed = browser.navigate_observed(
                self._recipe.verification_url,
                timeout_seconds=60,
            )
            browser.wait(1)
            self._resolve_challenge(browser, challenge_mode)
        session_cookie_present = bool(browser.cookies())
        initial_fetch = capture_verification_fetch(
            self._recipe.verification_url,
            observed,
            browser.page,
            retrieved_at=self._now(),
            session_cookie_present=session_cookie_present,
        )
        sampled = sample_semantic_snapshot(
            browser.page,
            initial_content=initial_fetch.raw_html,
            readiness=self._readiness,
            evaluator=lambda current_url, content: self._snapshot_readiness(
                verification_fetch_from_snapshot(
                    self._recipe.verification_url,
                    observed,
                    document_url=current_url,
                    raw_html=content,
                    retrieved_at=self._now(),
                    session_cookie_present=session_cookie_present,
                )
            ),
            monotonic_clock=self._monotonic_clock,
        )
        self._record_readiness_terminal(browser, sampled)
        fetch = verification_fetch_from_snapshot(
            self._recipe.verification_url,
            observed,
            document_url=sampled.document_url,
            raw_html=sampled.content,
            retrieved_at=self._now(),
            session_cookie_present=session_cookie_present,
        )
        verification = self._recipe.verify_fetch(fetch)
        return _BrowserPaidProof(
            fetch=fetch,
            access_state=verification.access_state,
            verified=verification.verified,
            stabilized=sampled.stabilized,
            paid_auth_cookie_present=self._paid_auth_cookie_present(browser),
        )

    @staticmethod
    def _record_readiness_terminal(
        browser: AuthBrowserSession,
        sampled: BrowserSemanticSnapshot,
    ) -> None:
        """Retain why the paid probe's sampler stopped.

        Retrieval already records this; without it the paid probe reports only
        ``stabilized``, which cannot separate an incomplete render from a body
        that never settled, and a static page reports the same value as a
        churning one.
        """

        recorder = getattr(browser, "record_semantic_readiness_terminal", None)
        if not callable(recorder):
            return
        try:
            recorder(
                state=sampled.terminal_state,
                word_count=(
                    sampled.observation.word_count
                    if sampled.observation is not None
                    else 0
                ),
                coverage_bucket=(
                    sampled.observation.coverage_bucket
                    if sampled.observation is not None
                    else ReadinessCoverageBucket.UNAVAILABLE
                ),
                content_change_count=sampled.content_change_count,
                last_content_change_ms=sampled.last_content_change_ms,
            )
        except Exception:
            # Diagnostic evidence must never change authentication behavior.
            return

    def _snapshot_readiness(self, fetch: RawFetch) -> BrowserReadinessObservation:
        extraction = self._verification_extractor.extract(
            fetch, scope_xpath=self._verification_provider.extraction_scope
        )
        assessment = self._verification_provider.assess(
            str(fetch.requested_url),
            fetch,
            extraction,
        )
        completeness = self._verification_provider.browser_paid_proof_complete(
            fetch,
            extraction,
            assessment,
        )
        conclusive = (
            completeness.complete
            or assessment.access_state is AccessState.AUTH_REQUIRED
        )
        fingerprint = hashlib.sha256(
            (assessment.access_state.value + "\0" + extraction.body_markdown).encode(
                "utf-8"
            )
        ).hexdigest()
        return BrowserReadinessObservation(
            ready=conclusive,
            assessment_promotable=assessment.promotable,
            content_fingerprint=fingerprint,
            word_count=assessment.word_count,
            coverage_bucket=readiness_coverage_bucket(completeness.coverage),
        )

    def _settle_after_google(
        self,
        browser: AuthBrowserSession,
        *,
        challenge_mode: ChallengeMode,
    ) -> bool:
        """Hydrate Bloomberg's paid marker after GIS writes soft state first."""

        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            for configured_target in self._auth.post_callback_urls:
                try:
                    target = str(configured_target)
                    browser.navigate_loaded(target, timeout_seconds=60)
                    browser.wait(1.4)
                    resolution = self._resolve_challenge(
                        browser,
                        challenge_mode,
                        allow_navigation_retry=True,
                    )
                    if (
                        resolution.status is ChallengeResolutionStatus.CLEARED
                        or resolution.reason
                        is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
                    ):
                        browser.navigate_loaded(target, timeout_seconds=60)
                        browser.wait(1)
                        self._resolve_challenge(browser, challenge_mode)
                    if "/account/onboarding" in browser.current_url:
                        for _step in range(4):
                            if not browser.click_optional(
                                _BLOOMBERG_ONBOARDING_CONTROLS
                            ):
                                break
                            browser.wait(0.8)
                except AcquisitionFailure:
                    raise
                except Exception:
                    continue
                if self._paid_auth_cookie_present(browser):
                    return True
            browser.wait(1)
        return self._paid_auth_cookie_present(browser)

    def _resolve_google_callback_challenge(
        self,
        browser: AuthBrowserSession,
        *,
        original,
        challenge_mode: ChallengeMode,
        observe: Callable[[_CallbackClearance], None],
    ) -> _CallbackClearance:
        """Resolve a PX surface emitted by Bloomberg's Google-auth callback.

        Returns what the probe observed, not just whether it cleared: a bare
        ``False`` cannot tell a defense that re-blocked an accepted browser
        from one that never issued a clearance token, and those need different
        remedies.
        """

        hold_dispatched = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            resolution = self._resolve_challenge(
                browser,
                challenge_mode,
                allow_navigation_retry=True,
            )
            if (
                resolution.status is ChallengeResolutionStatus.CLEARED
                or resolution.reason is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
            ):
                hold_dispatched = True
                break
            if resolution.status is ChallengeResolutionStatus.NOT_PRESENT:
                break
            browser.wait(0.5)

        # The callback is a background POST. Bloomberg returns its PX block as
        # JSON there, so no control is mounted on the opener. A credential-free
        # GET to the same first-party endpoint renders the provider's bounded
        # challenge surface and scopes the resulting clearance to
        # login.bloomberg.com. Always restore the sign-in page before the
        # cached Google replay.
        cleared = False
        # Bound before the probe so the observation survives a failure inside
        # it: the restore navigation in `finally` runs against a context the
        # settle loop may already have lost, and an unbound name there would
        # mask the real error with a NameError.
        status: int | None = None
        callback = browser.for_page(original)
        try:
            observed = callback.navigate_observed(
                _BLOOMBERG_GOOGLE_AUTH_ENDPOINT,
                timeout_seconds=60,
            )
            callback.wait(1)
            status = observed.status
            if status in {404, 405}:
                cleared = True
            elif status == 403:
                if not hold_dispatched:
                    resolution = self._resolve_challenge(
                        browser,
                        challenge_mode,
                        allow_navigation_retry=True,
                    )
                    hold_dispatched = (
                        resolution.status is ChallengeResolutionStatus.CLEARED
                        or resolution.reason
                        is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
                    )
                if hold_dispatched:
                    settle_deadline = time.monotonic() + 45
                    while time.monotonic() < settle_deadline:
                        observed = callback.navigate_observed(
                            _BLOOMBERG_GOOGLE_AUTH_ENDPOINT,
                            timeout_seconds=60,
                        )
                        callback.wait(1)
                        status = observed.status
                        if status in {404, 405}:
                            cleared = True
                            break
                        if status != 403:
                            break
                        callback.wait(1)
        finally:
            # Observed before the restore below, and in `finally` so a probe
            # that threw still reports what it saw. The restore navigation and
            # its challenge sweep run against a context the settle loop may
            # already have lost; a reading taken after them is the one that
            # gets dropped, which is why 0.3.17 recorded nothing.
            clearance = _CallbackClearance(
                cleared=cleared,
                probe_status=status,
                clearance_cookie_present=self._clearance_cookie_present(browser),
            )
            observe(clearance)
            callback.navigate_loaded(
                str(self._auth.login_url),
                timeout_seconds=60,
            )
            callback.wait(2)
            self._resolve_challenge(browser, challenge_mode)
        return clearance

    @staticmethod
    def _paid_auth_cookie_present(browser: AuthBrowserSession) -> bool:
        try:
            names = {str(cookie.get("name") or "") for cookie in browser.cookies()}
        except Exception:
            return False
        return bool(names.intersection(_BLOOMBERG_PAID_AUTH_COOKIES))

    def _clearance_cookie_present(self, browser: AuthBrowserSession) -> bool | None:
        """Whether the defense issued a clearance token, not merely a device id.

        ``_pxhd`` identifies the device and is set even while blocking; only a
        clearance cookie means the browser was trusted. Reporting "a px cookie
        exists" would call an unbroken block a success.
        """

        try:
            names = {str(cookie.get("name") or "") for cookie in browser.cookies()}
        except Exception:
            return None
        return any(name.casefold() in _PERIMETERX_CLEARANCE_COOKIES for name in names)

    @staticmethod
    def _is_perimeterx_cookie(name: str) -> bool:
        lowered = name.casefold()
        return (
            lowered.startswith("_px")
            or lowered.startswith("px")
            or "perimeter" in lowered
        )

    def _provider_cookie(self, cookie: dict[str, object]) -> bool:
        """Whether one cookie belongs to this provider's configured domains."""

        domain = str(cookie.get("domain") or "").lstrip(".").casefold()
        return any(
            domain == allowed or domain.endswith(f".{allowed}")
            for allowed in self._cookie_domains
        )

    def _challenge_cookie_present(self, browser: AuthBrowserSession) -> bool | None:
        """Report only whether PerimeterX left a named cookie, never a value.

        Scoped to the provider's own domains: an unrelated ``px``-prefixed
        cookie elsewhere in the profile would otherwise report challenge-vendor
        reputation the vendor never granted, which is exactly the distinction
        this fact exists to carry.
        """

        try:
            existing = browser.cookies()
        except Exception:
            return None
        return any(
            self._is_perimeterx_cookie(str(cookie.get("name") or ""))
            for cookie in existing
            if self._provider_cookie(cookie)
        )

    def _clear_bloomberg_auth_keep_px(self, browser: AuthBrowserSession) -> int:
        """Clear Bloomberg guest/paid auth while retaining PX reputation."""

        try:
            existing = browser.cookies()
        except Exception:
            return 0
        keep: list[dict[str, object]] = []
        cleared = 0
        for cookie in existing:
            name = str(cookie.get("name") or "")
            is_bloomberg = self._provider_cookie(cookie)
            lowered = name.casefold()
            is_px = self._is_perimeterx_cookie(name)
            is_auth = (
                name in _BLOOMBERG_SOFT_AUTH_COOKIES
                or name in _BLOOMBERG_STRONG_AUTH_COOKIES
                or any(part in lowered for part in _BLOOMBERG_AUTH_COOKIE_PARTS)
            )
            if is_bloomberg and is_auth and not is_px:
                cleared += 1
                continue
            keep.append(cookie)
        try:
            browser.replace_cookies(keep)
            browser.clear_storage()
        except Exception:
            return 0
        return cleared

    def _retry_google_callback(
        self,
        browser: AuthBrowserSession,
        *,
        original,
        challenge_mode: ChallengeMode,
    ) -> _CallbackRetry:
        """Retry GIS once with cached Google state and no secret resubmission."""

        try:
            popup = self._open_google_popup(browser)
            google = browser.for_page(popup)
        except Exception:
            # No replay surface was ever mounted, so no identity page is open.
            return _CallbackRetry(
                exit_reason=IdentityExitReason.IDENTITY_PAGE_CLOSED,
                identity_page_closed=True,
            )
        exit_reason = self._google_identity.resume_cached_callback(
            google,
            callback_complete=lambda: self._parent_left_auth(original),
            resolve_challenge=lambda identity_browser: self._resolve_identity_challenge(
                identity_browser,
                challenge_mode,
            ),
        )
        return _CallbackRetry(
            exit_reason=exit_reason,
            identity_page_closed=(
                self._identity_page_state(google) is IdentityPageState.CLOSED
            ),
        )

    def _resolve_identity_challenge(
        self,
        browser: AuthBrowserSession,
        mode: ChallengeMode,
    ) -> None:
        self._resolve_challenge(browser, mode)

    def _resolve_challenge(
        self,
        browser: AuthBrowserSession,
        mode: ChallengeMode,
        *,
        allow_navigation_retry: bool = False,
    ) -> ChallengeResolution:
        try:
            resolution = self._challenge_resolver.resolve(browser, mode)
        except ChallengeInfrastructureError as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.INFRASTRUCTURE,
            ) from error
        navigation_retry_allowed = (
            allow_navigation_retry
            and mode is ChallengeMode.AUTO
            and resolution.reason is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
        )
        if not resolution.allows_continuation and not navigation_retry_allowed:
            raise _failure(
                MintOutcome.CHALLENGE_BLOCKED,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.CHALLENGE_BLOCKED,
            )
        return resolution

    def _open_google_popup(self, browser: AuthBrowserSession):
        # The server-rendered control can become visible before Bloomberg's
        # login bundle attaches its popup handler on higher-latency routes.
        browser.wait(_BLOOMBERG_GOOGLE_LAUNCH_SETTLE_SECONDS)
        self._capture_google_checkpoint(browser, "google-launch-before")
        page = browser.page
        # Launch the provider-owned OAuth boundary through the headed surface;
        # Google credential submits keep their existing locator actions.
        for attempt in range(3):
            try:
                with page.expect_popup(timeout=15_000) as popup_info:
                    browser.native_click(self._auth.control("google_continue"))
            except Exception as error:
                if attempt == 2 or not self._popup_timeout(error):
                    raise
                self._capture_google_checkpoint(
                    browser,
                    f"google-launch-timeout-{attempt + 1}",
                )
                overlay_state = self._settle_bloomberg_login_overlay(browser)
                if overlay_state is False:
                    raise
                # One ordinary retry covers a visible-but-unhydrated handler.
                # A third click is permitted only when the second click exposed
                # and successfully dismissed another known Bloomberg overlay.
                if attempt == 1 and overlay_state is not True:
                    raise
                if not browser.wait_for_visible(
                    self._auth.control("google_continue"),
                    timeout_seconds=5,
                ):
                    raise
                browser.wait(
                    _BLOOMBERG_GOOGLE_LAUNCH_RETRY_SETTLE_SECONDS
                    if attempt == 0
                    else _BLOOMBERG_GOOGLE_LAUNCH_SETTLE_SECONDS
                )
                continue
            popup = popup_info.value
            popup.wait_for_load_state("domcontentloaded", timeout=30_000)
            return popup
        raise AssertionError("Bloomberg popup recovery exhausted")  # pragma: no cover

    def _settle_bloomberg_terms(
        self,
        browser: AuthBrowserSession,
    ) -> bool | None:
        control = self._auth.control("terms_accept")
        if not browser.click_optional(control):
            return None
        return browser.wait_for_hidden(control, timeout_seconds=5)

    def _settle_bloomberg_login_overlay(
        self,
        browser: AuthBrowserSession,
    ) -> bool | None:
        control = self._auth.control("cookie_accept")
        if browser.click_optional(control):
            return browser.wait_for_hidden(control, timeout_seconds=5)
        return self._settle_bloomberg_terms(browser)

    @staticmethod
    def _capture_google_checkpoint(
        browser: AuthBrowserSession,
        label: str,
    ) -> None:
        capture = getattr(browser, "capture_diagnostic_screenshot", None)
        if not callable(capture):
            return
        try:
            capture(label, timeout_ms=5_000)
        except Exception:
            # Diagnostic evidence must never change authentication behavior.
            return

    def _parent_left_auth(self, page) -> bool:
        return self._parent_handoff_state(page) is IdentityParentState.PUBLISHER_CONTENT

    def _parent_handoff_state(self, page) -> IdentityParentState:
        try:
            if page.is_closed():
                return IdentityParentState.CLOSED
            parsed = urlsplit(page.url)
            host = (parsed.hostname or "").lower().rstrip(".")
            path = parsed.path.lower().rstrip("/") or "/"
            provider_host = any(
                host == domain or host.endswith(f".{domain}")
                for domain in self._cookie_domains
            )
            if not provider_host:
                return IdentityParentState.OTHER
            if any(path.startswith(prefix) for prefix in self._auth.auth_path_prefixes):
                return IdentityParentState.PUBLISHER_AUTH
            return IdentityParentState.PUBLISHER_CONTENT
        except Exception:
            return IdentityParentState.UNAVAILABLE

    def _record_identity_handoff(
        self,
        browser: AuthBrowserSession,
        *,
        original,
        checkpoint: IdentityHandoffCheckpoint,
        identity_result: GoogleIdentityResult | None = None,
        identity_browser: AuthBrowserSession | None = None,
        callback_confirmed: bool | None = None,
        clearance: _CallbackClearance | None = None,
    ) -> None:
        recorder = getattr(browser, "record_identity_handoff", None)
        if not callable(recorder):
            return
        try:
            facts: dict[str, object] = {
                "checkpoint": checkpoint.value,
                "credential_action": (
                    identity_result.credential_action.value
                    if identity_result is not None
                    else None
                ),
                "identity_callback_complete": (
                    identity_result.callback_complete
                    if identity_result is not None
                    else None
                ),
                "identity_page_closed": (
                    identity_result.identity_page_closed
                    if identity_result is not None
                    else None
                ),
                "identity_exit_reason": (
                    identity_result.exit_reason.value
                    if identity_result is not None
                    else None
                ),
                "parent_state": self._parent_handoff_state(original).value,
                "callback_confirmed": callback_confirmed,
                "publisher_auth_cookie_present": self._paid_auth_cookie_present(
                    browser
                ),
                "challenge_cookie_present": self._challenge_cookie_present(browser),
            }
            if clearance is not None:
                facts["callback_probe_status"] = clearance.probe_status
                facts["callback_clearance_cookie_present"] = (
                    clearance.clearance_cookie_present
                )
            if checkpoint is IdentityHandoffCheckpoint.IDENTITY_ERROR:
                facts["identity_page_state"] = self._identity_page_state(
                    identity_browser
                ).value
            recorder(**facts)
        except Exception:
            # Diagnostic evidence must never change authentication behavior.
            return

    def _record_paid_probe(
        self,
        browser: AuthBrowserSession,
        *,
        original,
        outcome: PaidProbeOutcome,
        callback_confirmed: bool,
        entitlement_confirmed: bool | None,
        verification_full: bool | None,
        proof: _BrowserPaidProof | None,
    ) -> None:
        recorder = getattr(browser, "record_identity_handoff", None)
        if not callable(recorder):
            return
        try:
            recorder(
                checkpoint=IdentityHandoffCheckpoint.PAID_PROBE.value,
                credential_action=None,
                identity_callback_complete=None,
                identity_page_closed=None,
                parent_state=self._parent_handoff_state(original).value,
                callback_confirmed=callback_confirmed,
                publisher_auth_cookie_present=None,
                challenge_cookie_present=self._challenge_cookie_present(browser),
                paid_probe_outcome=outcome.value,
                entitlement_confirmed=entitlement_confirmed,
                paid_auth_cookie_present=self._paid_auth_cookie_present(browser),
                # The failure category collapses every non-teaser verdict into
                # a timeout. Retain what the verification page actually was and
                # whether its content had settled.
                paid_probe_access_state=(
                    proof.access_state.value if proof is not None else None
                ),
                paid_probe_stabilized=(proof.stabilized if proof is not None else None),
                verification_full=verification_full,
            )
        except Exception:
            # Diagnostic evidence must never change authentication behavior.
            return

    @staticmethod
    def _identity_page_state(
        identity_browser: AuthBrowserSession | None,
    ) -> IdentityPageState:
        if identity_browser is None:
            return IdentityPageState.UNAVAILABLE
        try:
            return (
                IdentityPageState.CLOSED
                if identity_browser.page.is_closed()
                else IdentityPageState.OPEN
            )
        except Exception:
            return IdentityPageState.UNAVAILABLE

    def _wait_parent_callback(self, page, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._parent_left_auth(page):
                return True
            try:
                page.wait_for_timeout(250)
            except Exception:
                return False
        return self._parent_left_auth(page)

    @staticmethod
    def _target_closed(error: BaseException) -> bool:
        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain and len(chain) < 6:
            chain.append(current)
            name = type(current).__name__.casefold()
            message = str(current).casefold()
            if (
                "targetclosed" in name
                or ("target" in message and "closed" in message)
                or "page, context or browser has been closed" in message
            ):
                return True
            current = current.__cause__ or current.__context__
        return False

    @staticmethod
    def _login_surface_timeout(error: BaseException) -> bool:
        """Recognize only this adapter's bounded pre-secret timeout."""

        return (
            isinstance(error, AcquisitionFailure)
            and error.outcome is MintOutcome.TIMEOUT
            and error.evidence.stage is MintFailureStage.CREDENTIAL
            and error.evidence.category is MintFailureCategory.TIMEOUT
        )

    @staticmethod
    def _popup_timeout(error: BaseException) -> bool:
        """Recognize a bounded popup-event timeout without retrying input faults."""

        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain and len(chain) < 6:
            chain.append(current)
            if (
                isinstance(current, TimeoutError)
                or "timeout" in type(current).__name__.casefold()
            ):
                return True
            current = current.__cause__ or current.__context__
        return False

    def _candidate(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        mode: AcquisitionMode,
        callback_confirmed: bool,
        verification_fetch: RawFetch,
        credential_action: CredentialAction = CredentialAction.NONE,
        refresh_failure: MintFailureEvidence | None = None,
    ) -> FlowCandidate:
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
                callback_confirmed=callback_confirmed,
            ),
            verification_fetch=verification_fetch,
            refresh_failure=refresh_failure,
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise LoginInfrastructureError("login clock must be timezone aware")
        return now


def _failure(
    outcome: MintOutcome,
    stage: MintFailureStage,
    category: MintFailureCategory,
) -> AcquisitionFailure:
    return AcquisitionFailure(
        outcome,
        MintFailureEvidence(stage=stage, category=category),
    )


def build_bloomberg_auth_adapter(
    recipe: LoginRecipe,
    spec: ProviderSpec,
    challenge_resolver: ChallengeResolver,
) -> BloombergAcquisitionAdapter:
    return BloombergAcquisitionAdapter(
        recipe=recipe,
        challenge_resolver=challenge_resolver,
        spec=spec,
    )
