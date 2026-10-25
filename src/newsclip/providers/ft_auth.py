"""FT-owned retained-profile acquisition and native hCaptcha handoff."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
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
from ..browser_verification import MainDocumentResponse, capture_verification_fetch
from ..challenge_resolver import (
    ChallengeBlockReason,
    ChallengeResolution,
    ChallengeResolver,
)
from ..challenges import (
    ChallengeAcceptance,
    ChallengeAcceptanceProbe,
    ChallengeAcceptanceSource,
    ChallengeInfrastructureError,
    ChallengeState,
    ChallengeVendor,
)
from ..contracts import AuthBrowserSession, LoginRecipe, SecretFiller
from ..login import LoginInfrastructureError, OpSecretFiller
from ..models import FrozenModel, MintOutcome, SessionArtifact
from ..provider_config import (
    ProviderDefinitionError,
    ProviderSpec,
    load_provider_spec,
    validate_auth_surface,
)
from ..session_cookies import (
    SessionCookieFormatError,
    SessionCookiesMissing,
    normalize_browser_cookie_export,
)
from ..timing import TimingStep, timing_step
from .ft import FTLoginRecipe

# The canonical script returns only a boolean and bounded source. It reads no
# unscoped widget, creates no field, mutates no DOM, and never returns a token
# or length. Bench builds its probe from this template instead of maintaining
# another browser script.
_NATIVE_TOKEN_PROBE_TEMPLATE = r"""
() => {
  const form = document.querySelector(__PASSWORD_FORM_SELECTOR__);
  if (!form) return {accepted: false, source: 'none'};
  const fields = form.querySelectorAll(__RESPONSE_FIELD_SELECTOR__);
  for (const field of fields) {
    if (String(field.value || '').trim().length > 20) {
      return {accepted: true, source: 'existing_form_field'};
    }
  }
  let widgets = Array.from(form.querySelectorAll(__WIDGET_SELECTOR__));
  if (!widgets.length) {
    const passwordForms = document.querySelectorAll(__PASSWORD_FORM_SELECTOR__);
    const external = Array.from(
      document.querySelectorAll(__WIDGET_SELECTOR__)
    ).filter((widget) => {
      const owner = widget.closest('form');
      return !owner || owner === form;
    });
    if (passwordForms.length === 1 && external.length === 1) {
      widgets = external;
    }
  }
  for (const widget of widgets) {
    const widgetId = String(
      widget.getAttribute('data-hcaptcha-widget-id') || ''
    );
    if (!widgetId) continue;
    try {
      if (window.hcaptcha && window.hcaptcha.getResponse) {
        const response = window.hcaptcha.getResponse(widgetId);
        if (String(response || '').trim().length > 20) {
          return {accepted: true, source: 'exact_widget_api'};
        }
      }
    } catch (_) {}
  }
  return {accepted: false, source: 'none'};
}
"""


def build_ft_native_token_probe_script(spec: ProviderSpec) -> str:
    probe = spec.require_auth().token_probe
    if probe is None:
        raise ProviderDefinitionError("FT requires native token probe selectors")
    return (
        _NATIVE_TOKEN_PROBE_TEMPLATE.replace(
            "__PASSWORD_FORM_SELECTOR__", json.dumps(probe.password_form_selector)
        )
        .replace(
            "__RESPONSE_FIELD_SELECTOR__", json.dumps(probe.response_field_selector)
        )
        .replace("__WIDGET_SELECTOR__", json.dumps(probe.widget_selector))
    )


_PASSWORD_CHALLENGE_POLL_SECONDS = 0.25
_PASSWORD_CHALLENGE_SETTLE_POLLS = 112
_PASSWORD_CHALLENGE_INJECTION_GRACE_POLLS = 16
# Must outlive hCaptcha visual solve (default wall budget 360s) plus a short
# post-token settle; a short deadline races successful captcha solves into
# CALLBACK_NOT_CONFIRMED before the token-bearing re-submit.
_SESSION_CALLBACK_TIMEOUT_SECONDS = 420
_POST_CALLBACK_SETTLE_POLLS = 20
_FT_HOME_URL = "https://www.ft.com/"


class FTLoginObservation(FrozenModel):
    username_visible: bool = False
    password_visible: bool = False
    captcha_rejected: bool = False
    second_factor: bool = False
    credential_rejected: bool = False
    account_alert: bool = False
    authenticated: bool = False


class FTNativeTokenProbe(ChallengeAcceptanceProbe):
    """Observe only the password form's existing native response ownership."""

    def __init__(
        self,
        browser: AuthBrowserSession,
        *,
        script: str | None = None,
    ) -> None:
        self._browser = browser
        self._script = (
            build_ft_native_token_probe_script(load_provider_spec("ft"))
            if script is None
            else script
        )

    def observe(self) -> ChallengeAcceptance:
        try:
            raw = self._browser.evaluate(self._script)
            if not isinstance(raw, Mapping):
                raise ValueError("invalid native token probe")
            accepted = raw.get("accepted")
            source_value = raw.get("source")
            if not isinstance(accepted, bool) or not isinstance(source_value, str):
                raise ValueError("invalid native token probe fields")
            source = ChallengeAcceptanceSource(source_value)
            if source not in {
                ChallengeAcceptanceSource.EXACT_WIDGET_API,
                ChallengeAcceptanceSource.EXISTING_FORM_FIELD,
            }:
                return ChallengeAcceptance(
                    accepted=False,
                    source=ChallengeAcceptanceSource.NONE,
                )
            return ChallengeAcceptance(accepted=accepted, source=source)
        except ChallengeInfrastructureError:
            raise
        except Exception as error:
            raise ChallengeInfrastructureError(
                "FT native challenge acceptance probe failed"
            ) from error


@dataclass(frozen=True, slots=True)
class FTAuthRequest:
    sequence: int
    method: str
    credential_present: bool | None
    token_present: bool | None


@dataclass(frozen=True, slots=True)
class FTAuthResponse:
    sequence: int
    status: int | None


class FTSubmitLedger:
    """One credential action and one token-bearing POST per logical attempt."""

    def __init__(self) -> None:
        self.sequence = 0
        self.token_post_claimed = False
        self.token_post_violation = False

    def claim_submit(self, sequence: int) -> None:
        if sequence not in {1, 2} or sequence != self.sequence + 1:
            raise AcquisitionFailure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureEvidence(
                    stage=MintFailureStage.CREDENTIAL,
                    category=MintFailureCategory.INFRASTRUCTURE,
                ),
            )
        if sequence == 2 and self.token_post_claimed:
            raise AcquisitionFailure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureEvidence(
                    stage=MintFailureStage.CHALLENGE,
                    category=MintFailureCategory.CALLBACK_NOT_CONFIRMED,
                ),
            )
        self.sequence = sequence

    def observe_token_post(self) -> None:
        if self.token_post_claimed:
            self.token_post_violation = True
            return
        self.token_post_claimed = True


class FTNetworkObserver:
    """Request-linked redacted facts for POST/PUT FT authentication traffic."""

    def __init__(
        self,
        page,
        ledger: FTSubmitLedger,
        *,
        record_callback: Callable[..., None] | None = None,
    ) -> None:
        self._page = page
        self._ledger = ledger
        self._record_callback = record_callback
        self._active_sequence = 0
        self._request_facts: dict[int, FTAuthRequest] = {}
        self.requests: list[FTAuthRequest] = []
        self.responses: list[FTAuthResponse] = []
        self._attached = False

    def attach(self) -> None:
        if self._attached:
            return
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._attached = True

    def set_sequence(self, sequence: int) -> None:
        self._active_sequence = sequence

    def detach(self) -> None:
        remove = getattr(self._page, "remove_listener", None)
        if callable(remove) and self._attached:
            remove("request", self._on_request)
            remove("response", self._on_response)
        self._attached = False

    def requests_for(self, sequence: int) -> tuple[FTAuthRequest, ...]:
        return tuple(item for item in self.requests if item.sequence == sequence)

    def has_upstream_error(self, sequence: int) -> bool:
        return any(
            response.sequence == sequence
            and response.status is not None
            and response.status >= 500
            for response in self.responses
        )

    def has_successful_token_callback(self, sequence: int) -> bool:
        """Return bounded proof that FT accepted credentials plus hCaptcha."""

        token_request = any(
            request.sequence == sequence
            and request.credential_present is True
            and request.token_present is True
            for request in self.requests
        )
        accepted_response = any(
            response.sequence == sequence
            and response.status is not None
            and 200 <= response.status < 400
            for response in self.responses
        )
        return token_request and accepted_response

    def _on_request(self, request) -> None:
        try:
            method = str(getattr(request, "method", "")).upper()
            url = str(getattr(request, "url", ""))
            if not _is_ft_auth_request(url, method) or not self._active_sequence:
                return
            post_data = str(getattr(request, "post_data", "") or "")
            credential_present = _password_present(post_data)
            token_present = _captcha_token_present(post_data)
            sequence = self._active_sequence
            facts = FTAuthRequest(
                sequence=sequence,
                method=method,
                credential_present=credential_present,
                token_present=token_present,
            )
            self._request_facts[id(request)] = facts
            self.requests.append(facts)
            if token_present:
                self._ledger.observe_token_post()
            post_data = ""
        except Exception:
            return

    def _on_response(self, response) -> None:
        try:
            request = getattr(response, "request", None)
            request_facts = self._request_facts.get(id(request))
            if request_facts is None:
                return
            status = getattr(response, "status", None)
            normalized_status = int(status) if status is not None else None
            self.responses.append(
                FTAuthResponse(
                    sequence=request_facts.sequence,
                    status=normalized_status,
                )
            )
            if self._record_callback is not None:
                self._record_callback(
                    sequence=request_facts.sequence,
                    credential_present=request_facts.credential_present,
                    challenge_token_present=request_facts.token_present,
                    status_class=_http_status_class(normalized_status),
                )
        except Exception:
            return


class FTAcquisitionAdapter:
    provider = "ft"

    def __init__(
        self,
        *,
        recipe: LoginRecipe | None = None,
        secrets: SecretFiller | None = None,
        challenge_resolver: ChallengeResolver,
        clock: Callable[[], datetime] | None = None,
        spec: ProviderSpec | None = None,
    ) -> None:
        selected_spec = spec or load_provider_spec("ft")
        auth = selected_spec.require_auth()
        session = selected_spec.require_session()
        if selected_spec.key != self.provider:
            raise ValueError("FT acquisition requires the FT provider definition")
        validate_auth_surface(
            auth,
            expected_controls={
                "username",
                "password",
                "username_submit",
                "password_submit",
                "consent",
                "passkey_skip",
            },
            required_observations=set(FTLoginObservation.model_fields),
            token_probe="required",
        )
        if not session.session_cookie_name_prefixes:
            raise ValueError("FT authentication requires session cookie prefixes")
        self._recipe = recipe or FTLoginRecipe(spec=selected_spec)
        if self._recipe.provider != selected_spec.key:
            raise ValueError("FT acquisition recipe/provider mismatch")
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
        self._session_cookie_prefixes = session.session_cookie_name_prefixes
        self._observe_script = build_auth_observation_script(self._auth.observations)
        self._token_probe_script = build_ft_native_token_probe_script(selected_spec)
        self._secrets = secrets or OpSecretFiller()
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
            with timing_step(TimingStep.LOGIN_FRONTDOOR, provider=self.provider):
                # The proven FT virtual-display route establishes first-party
                # state on www.ft.com before crossing to accounts.ft.com.
                browser.navigate(_FT_HOME_URL)
                self._settle_consent(browser)
                browser.wait(1.5)
                browser.navigate(str(self._auth.login_url))
            browser.suppress_passkeys(PasskeyMode.EMPTY_PRESENT)
            self._settle_consent(browser)
            self._resolve_challenge(browser, challenge_mode)
            observation = self._observe(browser, phase=AuthPhase.PROFILE)
            self._raise_terminal(observation)
            # The retained profile is only a candidate: SessionStore still
            # proves paid FULL access before persisting it.  Prefer that
            # provider-owned session signal over the accounts page's form —
            # FT can render the username form while an independently valid
            # FTSession cookie remains usable on www.ft.com.
            if self._has_ft_session(browser.cookies()):
                return self._candidate(
                    browser,
                    account_key=account_key,
                    mode=AcquisitionMode.PROFILE_REHYDRATE,
                )
            if observation.username_visible or observation.password_visible:
                return None
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
            return self._mint_credentials(
                browser,
                account_key=account_key,
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

    def _mint_credentials(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
    ) -> FlowCandidate:
        # Dead rehydrate leaves ftsession* on the retained profile. Those cookies
        # make _await_session believe a session exists before the password POST
        # registers, raising session_missing in <1s (live 2026-07-22 after
        # enter-email form.submit fix). Clear only session cookies so mint starts
        # clean while other account affinity cookies can remain.
        self._clear_ft_session_cookies(browser)
        self._resolve_challenge(browser, challenge_mode)
        observation = self._observe(browser)
        self._raise_terminal(observation)
        if not observation.password_visible:
            if not observation.username_visible:
                with timing_step(TimingStep.LOGIN_FRONTDOOR, provider=self.provider):
                    browser.navigate(str(self._auth.login_url))
                self._settle_consent(browser)
                self._resolve_challenge(browser, challenge_mode)
                observation = self._observe(browser)
                self._raise_terminal(observation)
            if not observation.username_visible:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CREDENTIAL,
                    MintFailureCategory.CONTROL_MISSING,
                )
            # Cookie modals can re-appear after navigation/challenge; dismiss
            # again immediately before typing into the username control.
            self._settle_consent(browser)
            with timing_step(TimingStep.USERNAME, provider=self.provider):
                # Single-field fill() commits the email for HTML5 validation;
                # fill_all_visible+type has left the enter-email step painted
                # with a value while Next still no-ops (live 2026-07-22).
                self._secrets.fill(
                    browser,
                    secret_ref=self._recipe.secret_ref,
                    field="username",
                    selectors=self._auth.control("username"),
                    allowed_origins=self._recipe.allowed_origins,
                    all_visible=False,
                )
                # Consent can arrive while the secret is resolved. Settle it
                # again before submitting the controlled login form.
                self._settle_consent(browser)
                self._submit_username(browser)
                observation = self._wait_for_password(browser, challenge_mode)

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
                all_visible=True,
            )

        # Pre-submit settle is best-effort only. Successful live mints often
        # exhaust this window without native acceptance, then solve hCaptcha
        # during post-submit await (challenge ~50s). Do not fail closed here.
        self._settle_password_challenge(browser, challenge_mode)

        ledger = FTSubmitLedger()
        network = FTNetworkObserver(
            browser.page,
            ledger,
            record_callback=getattr(browser, "record_credential_callback", None),
        )
        network.attach()
        try:
            with timing_step(TimingStep.PASSWORD, provider=self.provider):
                target = browser.mouse_target(self._auth.control("password_submit"))
                ledger.claim_submit(1)
                network.set_sequence(1)
                browser.mouse_click(target)
            with timing_step(TimingStep.CALLBACK, provider=self.provider):
                return self._await_session(
                    browser,
                    account_key=account_key,
                    challenge_mode=challenge_mode,
                    ledger=ledger,
                    network=network,
                )
        finally:
            network.detach()

    def _await_session(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        challenge_mode: ChallengeMode,
        ledger: FTSubmitLedger,
        network: FTNetworkObserver,
    ) -> FlowCandidate:
        deadline = time.monotonic() + _SESSION_CALLBACK_TIMEOUT_SECONDS
        second_submit_used = False
        captcha_rejection_visible = False
        post_callback_grace_used = False
        while time.monotonic() < deadline:
            browser.wait(0.25)
            if browser.click_optional(self._auth.control("passkey_skip")):
                browser.wait(0.5)
            observation = self._observe(browser, phase=AuthPhase.CALLBACK)
            captcha_rejection_visible = observation.captcha_rejected
            self._raise_terminal(observation)
            if ledger.token_post_violation:
                raise _failure(
                    MintOutcome.UNKNOWN_FLOW,
                    MintFailureStage.CHALLENGE,
                    MintFailureCategory.CALLBACK_NOT_CONFIRMED,
                )
            if network.has_upstream_error(ledger.sequence):
                raise _failure(
                    MintOutcome.INFRASTRUCTURE_ERROR,
                    MintFailureStage.TRANSPORT,
                    MintFailureCategory.TRANSPORT_FAILURE,
                )
            try:
                resolution = self._resolve_challenge(browser, challenge_mode)
            except AcquisitionFailure as error:
                if (
                    error.evidence.category
                    is not MintFailureCategory.CALLBACK_NOT_CONFIRMED
                    or not network.has_successful_token_callback(ledger.sequence)
                ):
                    raise
                # FT removes the password-form token probe while navigating to
                # its post-login passkey offer. The resolver therefore cannot
                # reconfirm native form ownership even though the redacted
                # request/response pair proves the callback was accepted.
                self._settle_post_callback(browser)
                if not self._has_ft_session(browser.cookies()):
                    raise
                return self._candidate(
                    browser,
                    account_key=account_key,
                    mode=AcquisitionMode.CREDENTIAL_MINT,
                    credential_action=CredentialAction.PASSWORD_SUBMIT,
                    callback_confirmed=True,
                )
            # A long-running hCaptcha solve can finish after the callback
            # deadline and land directly on FT's post-login passkey offer.
            # Give that already-confirmed callback one bounded transition
            # grace; this never resubmits credentials or extends a challenge.
            if ledger.token_post_claimed and not post_callback_grace_used:
                post_callback_grace_used = True
                self._settle_post_callback(browser)
            elif browser.click_optional(self._auth.control("passkey_skip")):
                browser.wait(0.5)
            acceptance = resolution.acceptance
            if self._has_ft_session(browser.cookies()):
                # Session cookies are product proof. Token-post observation is
                # best-effort telemetry: after a long captcha solve the network
                # observer may miss the token-bearing POST even though FT has
                # already issued ftsession cookies.
                requests = tuple(network.requests)
                if (
                    not requests
                    and not second_submit_used
                    and not ledger.token_post_claimed
                ):
                    # Residual profile cookies without a mint POST must not win
                    # on the first poll (live: 0.5s session_missing after Sign
                    # in while still on the password form). Keep waiting for a
                    # POST or a real session transition; deadline handles hang.
                    continue
                return self._candidate(
                    browser,
                    account_key=account_key,
                    mode=AcquisitionMode.CREDENTIAL_MINT,
                    credential_action=CredentialAction.PASSWORD_SUBMIT,
                    callback_confirmed=ledger.token_post_claimed,
                )
            if observation.captcha_rejected and (
                acceptance is None or not acceptance.accepted
            ):
                # FT can paint rejection text before the hCaptcha iframe
                # becomes interactive. Preserve the single-submit attempt and
                # let the bounded callback window observe the real surface.
                continue
            if (
                acceptance is not None
                and acceptance.accepted
                and not ledger.token_post_claimed
            ):
                # Prefer auto-session after captcha; only re-submit once if the
                # widget accepted but cookies are not yet present.
                browser.wait(2.0)
                if self._has_ft_session(browser.cookies()):
                    continue
                if second_submit_used:
                    raise _failure(
                        MintOutcome.CHALLENGE_BLOCKED,
                        MintFailureStage.CHALLENGE,
                        MintFailureCategory.CALLBACK_NOT_CONFIRMED,
                    )
                # Re-observe after the long captcha solve: the pre-challenge
                # observation may not show the password form, and captcha UI
                # often clears the field.
                post_challenge = self._observe(browser, phase=AuthPhase.CALLBACK)
                if post_challenge.password_visible:
                    with timing_step(TimingStep.PASSWORD, provider=self.provider):
                        self._secrets.fill(
                            browser,
                            secret_ref=self._recipe.secret_ref,
                            field="password",
                            selectors=self._auth.control("password"),
                            allowed_origins=self._recipe.allowed_origins,
                        )
                # Always advance past the first credential submit sequence.
                next_sequence = min(2, max(1, ledger.sequence + 1))
                if next_sequence <= ledger.sequence:
                    next_sequence = 2
                target = browser.mouse_target(self._auth.control("password_submit"))
                ledger.claim_submit(next_sequence)
                network.set_sequence(next_sequence)
                browser.mouse_click(target)
                second_submit_used = True
                continue
        if captcha_rejection_visible:
            raise _failure(
                MintOutcome.CHALLENGE_BLOCKED,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.CHALLENGE_BLOCKED,
            )
        requests = network.requests_for(ledger.sequence)
        if not requests:
            raise _failure(
                MintOutcome.TIMEOUT,
                MintFailureStage.CALLBACK,
                MintFailureCategory.CALLBACK_NOT_CONFIRMED,
            )
        if not any(
            response.sequence == ledger.sequence for response in network.responses
        ):
            raise _failure(
                MintOutcome.TIMEOUT,
                MintFailureStage.TRANSPORT,
                MintFailureCategory.TRANSPORT_FAILURE,
            )
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.SESSION,
            MintFailureCategory.TIMEOUT,
        )

    def _settle_post_callback(self, browser: AuthBrowserSession) -> None:
        """Observe FT's delayed passkey/session transition after a token POST."""

        passkey_skip = self._auth.control("passkey_skip")
        for _ in range(_POST_CALLBACK_SETTLE_POLLS):
            if browser.click_optional(passkey_skip):
                browser.wait(0.5)
                if self._has_ft_session(browser.cookies()):
                    return
            # FT can issue a cookie before its accounts-host passkey offer.
            # Let that transition finish before leaving for paid verification;
            # cookie presence alone must not short-circuit the optional step.
            observation = self._observe(browser, phase=AuthPhase.CALLBACK)
            self._raise_terminal(observation)
            if observation.authenticated and self._has_ft_session(browser.cookies()):
                return
            browser.wait(0.25)

    def _candidate(
        self,
        browser: AuthBrowserSession,
        *,
        account_key: str,
        mode: AcquisitionMode,
        credential_action: CredentialAction = CredentialAction.NONE,
        callback_confirmed: bool = False,
    ) -> FlowCandidate:
        # FT's edge risk cookie is scoped to the content host and bound to the
        # browser user agent. Visiting the approved paid probe before export
        # lets the portable jar carry that context into ordinary HTTP reads.
        with timing_step(TimingStep.PAID_PROBE, provider=self.provider):
            with MainDocumentResponse(browser.page) as document:
                observed = browser.navigate_observed(
                    self._recipe.verification_url, timeout_seconds=40
                )
                browser.wait(5)
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
                verification_fetch = capture_verification_fetch(
                    self._recipe.verification_url,
                    current,
                    browser.page,
                    retrieved_at=self._now(),
                    session_cookie_present=self._has_ft_session(browser.cookies()),
                )
                document.assert_current(response)
            capture = getattr(browser, "capture_diagnostic_screenshot", None)
            if callable(capture):
                with suppress(Exception):
                    capture("paid-proof", timeout_ms=2_000)
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
        if not any(
            cookie.name.lower().startswith(prefix)
            for cookie in cookies
            for prefix in self._session_cookie_prefixes
        ):
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.SESSION,
                MintFailureCategory.SESSION_MISSING,
            )
        artifact = SessionArtifact(
            generation_id=uuid4(),
            provider=self.provider,
            account_key=account_key,
            created_at=now,
            verified_at=now,
            user_agent=user_agent,
            cookies=cookies,
        )
        return FlowCandidate(
            artifact=artifact,
            candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
            verification_fetch=verification_fetch,
            evidence=AcquisitionEvidence(
                mode=mode,
                credential_action=credential_action,
                callback_confirmed=callback_confirmed,
            ),
        )

    def _resolve_challenge(
        self,
        browser: AuthBrowserSession,
        mode: ChallengeMode,
    ) -> ChallengeResolution:
        probe = FTNativeTokenProbe(browser, script=self._token_probe_script)
        try:
            resolution = self._challenge_resolver.resolve(
                browser,
                mode,
                acceptance=probe,
                acceptance_vendor=ChallengeVendor.HCAPTCHA,
            )
        except ChallengeInfrastructureError as error:
            raise _failure(
                MintOutcome.INFRASTRUCTURE_ERROR,
                MintFailureStage.CHALLENGE,
                MintFailureCategory.INFRASTRUCTURE,
            ) from error
        if not resolution.allows_continuation:
            category = (
                MintFailureCategory.CALLBACK_NOT_CONFIRMED
                if resolution.reason is ChallengeBlockReason.ACCEPTANCE_UNCONFIRMED
                else MintFailureCategory.CHALLENGE_BLOCKED
            )
            raise _failure(
                MintOutcome.CHALLENGE_BLOCKED,
                MintFailureStage.CHALLENGE,
                category,
            )
        return resolution

    def _settle_password_challenge(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> None:
        """Let FT's password-form hCaptcha produce native acceptance evidence.

        Bounded pre-submit wait only. Live successes (e.g. 2026-07-22 08:01Z)
        often exhaust this window without acceptance, then clear hCaptcha in
        post-submit await — so this method must not fail closed.
        """

        with timing_step(TimingStep.PROVIDER_TRANSITION_WAIT, provider=self.provider):
            for poll in range(_PASSWORD_CHALLENGE_SETTLE_POLLS):
                resolution = self._resolve_challenge(browser, challenge_mode)
                acceptance = resolution.acceptance
                if acceptance is not None and acceptance.accepted:
                    return
                detection = resolution.detection
                if detection.vendor is not ChallengeVendor.HCAPTCHA and (
                    detection.state is not ChallengeState.NONE
                    or poll + 1 >= _PASSWORD_CHALLENGE_INJECTION_GRACE_POLLS
                ):
                    return
                browser.wait(_PASSWORD_CHALLENGE_POLL_SECONDS)

    def _clear_ft_session_cookies(self, browser: AuthBrowserSession) -> None:
        """Drop ftsession* cookies from a retained profile before credential mint."""

        try:
            existing = browser.cookies()
        except Exception:
            return
        keep: list[dict[str, object]] = []
        cleared = 0
        for cookie in existing:
            name = str(cookie.get("name") or "").lower()
            if any(name.startswith(prefix) for prefix in self._session_cookie_prefixes):
                cleared += 1
                continue
            keep.append(cookie)
        if cleared == 0:
            return
        try:
            browser.replace_cookies(keep)
        except Exception:
            return

    def _settle_consent(self, browser: AuthBrowserSession) -> None:
        # Cold/ephemeral profiles often show the "Cookies on FT Sites" modal
        # with a bare "Accept" CTA. Poll long enough for the dialog to paint.
        for _ in range(40):
            if browser.click_optional(self._auth.control("consent")):
                browser.wait(0.5)
                # A second dismiss is a no-op when the modal already closed.
                browser.click_optional(self._auth.control("consent"))
                browser.wait(0.25)
                return
            browser.wait(0.25)

    def _submit_username(self, browser: AuthBrowserSession) -> None:
        """Advance the enter-email step to the password form.

        Live accounts.ft.com ``#email-form`` registers a capture-phase submit
        handler that tries WebAuthn/passkey first and only calls
        ``emailForm.submit()`` in its ``catch``. When
        ``navigator.credentials.get()`` hangs (common under virtual-display
        with WebAuthn disabled), Next never reaches the password step — failure
        screenshots still show a filled email + Next (2026-07-22).

        ``HTMLFormElement.prototype.submit()`` bypasses submit listeners and
        POSTs the enter-email form directly. Fall back to click / Enter / mouse.
        """

        try:
            result = browser.evaluate(
                """() => {
  const form = document.getElementById('email-form');
  const email = document.getElementById('enter-email')
    || document.querySelector('input[name="email"]');
  if (!form || !email) return 'missing';
  if (!String(email.value || '').trim()) return 'empty';
  HTMLFormElement.prototype.submit.call(form);
  return 'submitted';
}"""
            )
            if result == "submitted":
                return
        except Exception:
            pass
        submit = self._auth.control("username_submit")
        email = self._auth.control("username")
        try:
            browser.click(submit)
            return
        except Exception:
            pass
        try:
            browser.press(email, "Enter")
            return
        except Exception:
            pass
        target = browser.mouse_target(submit)
        browser.mouse_click(target)

    def _wait_for_password(
        self,
        browser: AuthBrowserSession,
        challenge_mode: ChallengeMode,
    ) -> FTLoginObservation:
        # FT can take longer than ten seconds to replace the username form;
        # keep one submit action and extend only this bounded observation window.
        # One mid-window retry covers a missed Next (HTML5 validation / pointer
        # miss) without burning a second credential mint.
        email = self._auth.control("username")
        submit = self._auth.control("username_submit")
        for poll in range(80):
            browser.wait(0.25)
            self._resolve_challenge(browser, challenge_mode)
            observation = self._observe(browser, phase=AuthPhase.PASSWORD)
            self._raise_terminal(observation)
            if observation.password_visible:
                return observation
            if poll == 12 and observation.username_visible:
                try:
                    browser.press(email, "Enter")
                except Exception:
                    try:
                        browser.click(submit)
                    except Exception:
                        with suppress(Exception):
                            browser.mouse_click(browser.mouse_target(submit))
        raise _failure(
            MintOutcome.TIMEOUT,
            MintFailureStage.CREDENTIAL,
            MintFailureCategory.TIMEOUT,
        )

    def _observe(
        self,
        browser: AuthBrowserSession,
        *,
        phase: AuthPhase = AuthPhase.ENTRY,
    ) -> FTLoginObservation:
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
            return FTLoginObservation.model_validate(raw)
        except (AuthSelectorEvaluationError, ValidationError) as error:
            raise _failure(
                MintOutcome.UNKNOWN_FLOW,
                MintFailureStage.CREDENTIAL,
                MintFailureCategory.UNKNOWN,
            ) from error

    @staticmethod
    def _raise_terminal(observation: FTLoginObservation) -> None:
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

    def _has_ft_session(self, cookies: Sequence[Mapping[str, object]]) -> bool:
        return any(
            str(cookie.get("name", "")).lower().startswith(prefix)
            for cookie in cookies
            for prefix in self._session_cookie_prefixes
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


def _is_ft_auth_request(url: str, method: str) -> bool:
    if method not in {"POST", "PUT"}:
        return False
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host != "ft.com" and not host.endswith(".ft.com"):
        return False
    path = parsed.path.lower()
    return any(
        marker in path
        for marker in (
            "/login",
            "/authenticate",
            "/sessions",
            "/id/",
            "enter-password",
            "enter-email",
        )
    )


def _captcha_token_present(post_data: str) -> bool | None:
    return _encoded_form_value_present(
        post_data,
        marker="h-captcha-response=",
        minimum_length=21,
    )


def _password_present(post_data: str) -> bool | None:
    return _encoded_form_value_present(
        post_data,
        marker="password=",
        minimum_length=1,
    )


def _encoded_form_value_present(
    post_data: str,
    *,
    marker: str,
    minimum_length: int,
) -> bool | None:
    """Classify an encoded form field without decoding or retaining its value."""

    if not post_data:
        return None
    if marker not in post_data:
        return False if "=" in post_data else None
    start = post_data.index(marker) + len(marker)
    end = post_data.find("&", start)
    if end < 0:
        end = len(post_data)
    return end - start >= minimum_length


def _http_status_class(status: int | None) -> str:
    if status is None or status < 100 or status > 599:
        return "unknown"
    return (
        "informational"
        if status < 200
        else "success"
        if status < 300
        else "redirection"
        if status < 400
        else "client_error"
        if status < 500
        else "server_error"
    )


def build_ft_auth_adapter(
    recipe: LoginRecipe,
    spec: ProviderSpec,
    challenge_resolver: ChallengeResolver,
) -> FTAcquisitionAdapter:
    return FTAcquisitionAdapter(
        recipe=recipe,
        challenge_resolver=challenge_resolver,
        spec=spec,
    )
