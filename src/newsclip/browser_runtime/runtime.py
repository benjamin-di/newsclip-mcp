"""Persistent Patchright context lifecycle and provider-neutral primitives."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from ..acquisition import CredentialAction
from ..browser_readiness import (
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from ..challenge_resolver import ChallengeResolution
from ..challenges import ChallengeAcceptanceSource, ChallengeMode
from ..models import AccessState, CaptureFailure, RetrievalDiagnostics
from ..timing import (
    TimingStep,
    set_timing_browser_major,
    timing_step,
)
from ..visual_plans import VisualPlan
from .events import (
    ActionResult,
    ArtifactOmission,
    AttemptFinishedEvent,
    AttemptOutcome,
    AttemptPurpose,
    AttemptStartedEvent,
    AuthEvidenceFamily,
    AuthObservationEvent,
    AuthPhase,
    BrowserClosedEvent,
    BrowserFailedEvent,
    BrowserFailureCategory,
    BrowserFailurePhase,
    BrowserMode,
    BrowserOperation,
    BrowserStartedEvent,
    ChallengeResolutionEvent,
    CredentialCallbackEvent,
    HCaptchaAttemptFinishedEvent,
    HCaptchaAttemptTerminalReason,
    HCaptchaCheckpointEvent,
    HCaptchaPlanKind,
    HCaptchaPromptFamily,
    HCaptchaRoundEvent,
    HCaptchaTerminalReason,
    HCaptchaVendorOutcome,
    HttpStatusClass,
    IdentityExitReason,
    IdentityHandoffCheckpoint,
    IdentityHandoffEvent,
    IdentityPageState,
    IdentityParentState,
    NavigationEvidence,
    PaidProbeOutcome,
    PerimeterXFinalSurfaceState,
    PerimeterXGenerationRelation,
    PerimeterXHoldEvent,
    PerimeterXHoldReleaseReason,
    PerimeterXPointerBackend,
    ProfileGeneration,
    RouteClass,
    RuntimeTrace,
    SemanticActionFinishedEvent,
    SemanticActionStartedEvent,
    SemanticReadinessTerminalEvent,
    duration_bucket,
    hcaptcha_surface_miss_bucket,
)
from .profile_ownership import OwnedBrowserProcess, prepare_profile
from .surface import (
    BrowserRuntimeError,
    InfrastructureCategory,
    display_is_usable,
    is_system_desktop_display,
)
from .x11_pointer import NativePointerUnavailable, X11Pointer


@dataclass(frozen=True, slots=True)
class MouseTarget:
    x: float
    y: float


class _SurfacePointer(Protocol):
    def move(self, x: float, y: float, *, steps: int = 1) -> None: ...

    def down(self) -> None: ...

    def up(self) -> None: ...


@dataclass(frozen=True, slots=True)
class BrowserLaunchConfig:
    locale: str | None = None
    timezone_id: str | None = None
    accept_language: str | None = None
    channel: str | None = None
    args: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ObservedNavigation:
    """Main-document response facts retained at browser commit."""

    status: int
    response_url: str
    content_type: str | None


@dataclass(slots=True)
class _AttemptState:
    attempt_id: str
    provider: str
    purpose: AttemptPurpose
    last_phase: AuthPhase = AuthPhase.UNKNOWN
    last_observation_code: str = "unknown"
    action_sequence: int = 0
    evidence_started: bool = False
    form_captured: bool = False
    callback_captured: bool = False
    failure_captured: bool = False
    challenge_captured: bool = False
    challenge_started: float | None = None
    actionable_observed: bool | None = None
    surface_observations: int = 0
    last_navigation: NavigationEvidence | None = None
    capture_failure: CaptureFailure | None = None


_VIRTUAL_DISPLAY_ARGS = (
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-position=0,0",
    "--window-size=1280,800",
    "--use-gl=angle",
    "--use-angle=swiftshader-webgl",
    "--enable-webgl",
    "--ignore-gpu-blocklist",
    "--disable-software-rasterizer",
)
_OBSERVATIONAL_EVALUATE_DELAYS_MS = (0, 250, 500, 1_000, 1_250)


class PasskeyMode(StrEnum):
    """Provider-selected behavior for an empty virtual authenticator."""

    EMPTY_PRESENT = "empty_present"
    NON_PRESENT = "non_present"


class PatchrightMintContext:
    """Typed access to the proven Patchright page and persistent context."""

    def __init__(
        self,
        context: Any,
        page: Any,
        *,
        trace: RuntimeTrace | None = None,
        profile_state: Literal["new", "existing", "unknown"] = "unknown",
    ) -> None:
        self.context = context
        self.page = page
        self.last_operation = BrowserOperation.INITIALIZED
        self._webauthn_session: Any | None = None
        self._trace = trace
        self._attempt: _AttemptState | None = None
        self._profile_state = profile_state

    @contextmanager
    def attempt(
        self,
        provider: str,
        purpose: AttemptPurpose | str,
        *,
        profile_scope: Literal["public", "account", "unknown"] = "unknown",
    ) -> Iterator[PatchrightMintContext]:
        """Correlate closed semantic evidence for one provider browser attempt."""

        if self._attempt is not None:
            raise RuntimeError("browser attempts cannot be nested")
        state = _AttemptState(
            attempt_id=f"attempt-{uuid4().hex}",
            provider=provider,
            purpose=AttemptPurpose(purpose),
        )
        self._attempt = state
        state.evidence_started = self._record(
            AttemptStartedEvent(
                attempt_id=state.attempt_id,
                provider=provider,
                purpose=state.purpose,
                profile_state=self._profile_state,
                profile_scope=profile_scope,
            )
        )
        outcome = AttemptOutcome.SUCCESS
        try:
            if (
                self._trace is not None
                and not state.evidence_started
                and state.purpose
                in {AttemptPurpose.LOGIN, AttemptPurpose.PROFILE_REHYDRATE}
            ):
                raise BrowserRuntimeError(
                    InfrastructureCategory.DIAGNOSTIC_WRITE_FAILED
                )
            yield self
        except BaseException as error:
            outcome = (
                AttemptOutcome.TIMEOUT
                if _failure_category(error) is BrowserFailureCategory.TIMEOUT
                else AttemptOutcome.ERROR
            )
            # Capture before clearing the attempt identity or allowing outer
            # cleanup to navigate/close the failed surface. Runtime teardown
            # still retains its own final-context capture as a fallback.
            if not state.failure_captured:
                self.capture_diagnostic_screenshot("attempt-failure", timeout_ms=5_000)
            raise
        finally:
            self._record(
                AttemptFinishedEvent(
                    attempt_id=state.attempt_id,
                    provider=state.provider,
                    outcome=outcome,
                    last_phase=state.last_phase,
                    last_navigation=state.last_navigation,
                    capture_failure=state.capture_failure,
                )
            )
            self._attempt = None

    def record_capture_failure(self, failure: CaptureFailure) -> None:
        if self._attempt is not None:
            self._attempt.capture_failure = failure

    def record_auth_observation(
        self,
        *,
        phase: AuthPhase | str,
        state_code: str,
        observation_id: str | None,
        evidence_families: tuple[AuthEvidenceFamily | str, ...],
        route_class: RouteClass | str,
        selector_error: bool,
    ) -> None:
        state = self._attempt
        if state is None:
            return
        selected_phase = AuthPhase(phase)
        state.last_phase = selected_phase
        state.last_observation_code = state_code
        self._record(
            AuthObservationEvent(
                attempt_id=state.attempt_id,
                provider=state.provider,
                phase=selected_phase,
                state_code=state_code,
                observation_id=observation_id,
                evidence_families=tuple(
                    AuthEvidenceFamily(value) for value in evidence_families
                ),
                route_class=RouteClass(route_class),
                selector_error=selector_error,
            )
        )
        if (
            selected_phase is AuthPhase.CALLBACK
            and route_class == RouteClass.PUBLISHER_CONTENT
            and not state.callback_captured
        ):
            state.callback_captured = True
            self.capture_diagnostic_screenshot("auth-callback")

    def record_challenge_started(self) -> None:
        state = self._attempt
        if state is None or self._trace is None:
            return
        state.challenge_started = time.perf_counter()
        state.actionable_observed = None
        state.surface_observations = 0
        if not state.challenge_captured:
            state.challenge_captured = True
            self.capture_diagnostic_screenshot("challenge-first")

    def record_challenge_surface(self, *, actionable: bool) -> None:
        """Accumulate observations already made by a mechanic, without polling."""

        state = self._attempt
        if state is not None and state.challenge_started is not None:
            state.actionable_observed = bool(state.actionable_observed or actionable)
            state.surface_observations = min(65535, state.surface_observations + 1)

    def record_challenge_resolution(
        self,
        *,
        resolution: ChallengeResolution,
        mode: ChallengeMode,
        capability: str,
    ) -> None:
        state = self._attempt
        if state is None:
            return
        self._record(
            ChallengeResolutionEvent.model_validate(
                {
                    **resolution.model_dump(),
                    "attempt_id": state.attempt_id,
                    "provider": state.provider,
                    "mode": mode,
                    "capability": capability,
                    "elapsed_ms": (
                        max(0, (time.perf_counter() - state.challenge_started) * 1000)
                        if state.challenge_started is not None
                        else None
                    ),
                    "actionable_observed": state.actionable_observed,
                    "surface_observations": state.surface_observations,
                }
            )
        )
        state.challenge_started = None
        state.actionable_observed = None
        state.surface_observations = 0

    def record_semantic_readiness_terminal(
        self,
        *,
        state: ReadinessTerminalState,
        word_count: int,
        coverage_bucket: ReadinessCoverageBucket,
        content_change_count: int,
        last_content_change_ms: int,
    ) -> None:
        """Append one closed readiness result for the active retrieval attempt."""

        attempt = self._attempt
        if attempt is None:
            return
        self._record(
            SemanticReadinessTerminalEvent(
                attempt_id=attempt.attempt_id,
                provider=attempt.provider,
                state=state,
                word_count=word_count,
                coverage_bucket=coverage_bucket,
                content_change_count=content_change_count,
                last_content_change_ms=last_content_change_ms,
            )
        )

    def _record(self, event) -> bool:  # noqa: ANN001
        if self._trace is None:
            return True
        provider = self._attempt.provider if self._attempt is not None else None
        try:
            return self._trace.try_write(event, provider=provider)
        except Exception:
            # Observability must not replace a provider or browser outcome.
            return False

    def _dispatch_action(
        self,
        operation: BrowserOperation,
        dispatch: Callable[[], Any],
        *,
        navigation_url: str | None = None,
    ) -> Any:
        state = self._attempt
        if state is None:
            return dispatch()
        state.action_sequence += 1
        action_id = state.action_sequence
        recorded = self._record(
            SemanticActionStartedEvent(
                attempt_id=state.attempt_id,
                action_id=action_id,
                action=operation,
                sequence=action_id,
                pre_observation_code=state.last_observation_code,
            )
        )
        if (not recorded or not state.evidence_started) and (
            operation is BrowserOperation.CHALLENGE_ACTION
            or state.purpose in {AttemptPurpose.LOGIN, AttemptPurpose.PROFILE_REHYDRATE}
        ):
            raise BrowserRuntimeError(InfrastructureCategory.DIAGNOSTIC_WRITE_FAILED)
        started = time.perf_counter()
        try:
            result = dispatch()
        except BaseException as error:
            # Once the dispatch callable is entered, an exception cannot prove
            # that the browser performed no partial mutation. Record the safe
            # conservative fact so ambiguous post-submit failures never look
            # retryable merely because the driver raised late.
            self._record(
                SemanticActionFinishedEvent(
                    attempt_id=state.attempt_id,
                    action_id=action_id,
                    dispatched=True,
                    result=(
                        ActionResult.TIMEOUT
                        if _failure_category(error) is BrowserFailureCategory.TIMEOUT
                        else ActionResult.UNKNOWN
                    ),
                    navigation=(
                        self._navigation_evidence(None, navigation_url, started)
                        if navigation_url is not None
                        else None
                    ),
                )
            )
            raise
        self._record(
            SemanticActionFinishedEvent(
                attempt_id=state.attempt_id,
                action_id=action_id,
                dispatched=result is not False,
                result=(
                    ActionResult.UNKNOWN
                    if result is not False
                    else ActionResult.REJECTED
                ),
                navigation=(
                    self._navigation_evidence(result, navigation_url, started)
                    if navigation_url is not None
                    else None
                ),
            )
        )
        return result

    def observe_navigation(self, url: str, dispatch: Callable[[], Any]) -> Any:
        """Observe retrieval's existing navigation without adding an action gate."""

        started = time.perf_counter()
        response = None
        try:
            response = dispatch()
            return response
        finally:
            with suppress(Exception):
                if self._attempt is not None:
                    self._attempt.last_navigation = self._navigation_evidence(
                        response, url, started
                    )

    def _navigation_evidence(
        self, response: Any, requested_url: str, started: float
    ) -> NavigationEvidence | None:
        try:
            status = getattr(response, "status", None)
            final = _browser_origin(
                getattr(response, "response_url", None) or getattr(response, "url", "")
            )
            requested = _browser_origin(requested_url)
            evidence = NavigationEvidence(
                status=status if type(status) is int and 100 <= status <= 599 else None,
                destination=(
                    "requested_origin" if final == requested else "other_origin"
                )
                if final and requested
                else "unknown",
                elapsed_ms=max(0, (time.perf_counter() - started) * 1000),
            )
        except Exception:
            if self._trace is not None:
                with suppress(Exception):
                    self._trace.note_diagnostic_loss(
                        "event_write",
                        provider=self._attempt.provider if self._attempt else None,
                    )
            evidence = NavigationEvidence(
                elapsed_ms=max(0, (time.perf_counter() - started) * 1000)
            )
        if self._attempt is not None:
            self._attempt.last_navigation = evidence
        return evidence

    @property
    def current_url(self) -> str:
        return self.page.url

    def navigate(self, url: str) -> None:
        self.last_operation = BrowserOperation.NAVIGATE
        self._dispatch_action(
            BrowserOperation.NAVIGATE,
            lambda: self.page.goto(url, wait_until="domcontentloaded"),
            navigation_url=url,
        )

    def navigate_loaded(self, url: str, *, timeout_seconds: float) -> None:
        """Navigate to a DOM-ready document within a bounded provider timeout."""

        timeout_ms = _navigation_timeout_ms(timeout_seconds)
        self.last_operation = BrowserOperation.NAVIGATE
        self._dispatch_action(
            BrowserOperation.NAVIGATE,
            lambda: self.page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            ),
            navigation_url=url,
        )

    def navigate_committed(self, url: str, *, timeout_seconds: float) -> None:
        """Navigate until the response commits without awaiting a perpetual DOM."""

        timeout_ms = _navigation_timeout_ms(timeout_seconds)
        self.last_operation = BrowserOperation.NAVIGATE
        self._dispatch_action(
            BrowserOperation.NAVIGATE,
            lambda: self.page.goto(
                url,
                wait_until="commit",
                timeout=timeout_ms,
            ),
            navigation_url=url,
        )

    def navigate_observed(
        self,
        url: str,
        *,
        timeout_seconds: float,
    ) -> ObservedNavigation:
        """Navigate to document commit and retain only observed response facts."""

        timeout_ms = _navigation_timeout_ms(timeout_seconds)
        self.last_operation = BrowserOperation.NAVIGATE

        def observe() -> ObservedNavigation:
            response = self.page.goto(
                url,
                wait_until="commit",
                timeout=timeout_ms,
            )
            if response is None:
                raise RuntimeError("browser navigation produced no response")
            status = getattr(response, "status", None)
            response_url = getattr(response, "url", None)
            if not isinstance(status, int) or isinstance(status, bool):
                raise RuntimeError("browser response status is unavailable")
            if not isinstance(response_url, str) or not response_url:
                raise RuntimeError("browser response URL is unavailable")
            headers = getattr(response, "headers", None)
            content_type: str | None = None
            if isinstance(headers, Mapping):
                raw_content_type = headers.get("content-type")
                if raw_content_type is not None:
                    if not isinstance(raw_content_type, str):
                        raise RuntimeError("browser response content type is invalid")
                    content_type = raw_content_type
            return ObservedNavigation(
                status=status,
                response_url=response_url,
                content_type=content_type,
            )

        observed = self._dispatch_action(
            BrowserOperation.NAVIGATE, observe, navigation_url=url
        )
        if not isinstance(observed, ObservedNavigation):  # pragma: no cover
            raise RuntimeError("browser navigation observation is unavailable")
        return observed

    def replace_page(self) -> None:
        """Replace a potentially poisoned page while preserving its context."""

        self.last_operation = BrowserOperation.REPLACE_PAGE

        def replace_current() -> None:
            previous = self.page
            replacement = self.context.new_page()
            self.page = replacement
            with suppress(Exception):
                previous.close()

        self._dispatch_action(BrowserOperation.REPLACE_PAGE, replace_current)

    def for_page(self, page: Any) -> PatchrightMintContext:
        """Create a sibling page facade that retains this run's diagnostics."""

        sibling = PatchrightMintContext(
            self.context, page, trace=self._trace, profile_state=self._profile_state
        )
        sibling._attempt = self._attempt
        return sibling

    def fill(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> None:
        self.last_operation = BrowserOperation.FILL

        def type_value(locator) -> None:
            self._capture_credential_form()
            # Prefer Playwright fill() so special characters and framework
            # input handlers receive a single committed value (type()+delay can
            # leave React-controlled password fields out of sync with FT).
            locator.click()
            locator.fill(value)

        self._dispatch_action(
            BrowserOperation.FILL,
            lambda: self._with_visible_locator(
                selectors,
                type_value,
                allowed_origins=allowed_origins,
            ),
        )

    def fill_all_visible(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> int:
        """Fill every visible match for one combined selector without DOM mutation."""

        self.last_operation = BrowserOperation.FILL_ALL_VISIBLE

        def fill_visible() -> int:
            filled = 0
            for candidate in self._visible_locators(
                selectors,
                combined=True,
                allowed_origins=allowed_origins,
            ):
                self._capture_credential_form()
                candidate.fill("", timeout=8_000)
                candidate.type(value, delay=55, timeout=8_000)
                candidate.dispatch_event("change")
                candidate.dispatch_event("blur")
                filled += 1
            if not filled:
                raise RuntimeError("no configured visible control was found")
            return filled

        return int(
            self._dispatch_action(BrowserOperation.FILL_ALL_VISIBLE, fill_visible)
        )

    def click(self, selectors: tuple[str, ...]) -> None:
        self.last_operation = BrowserOperation.CLICK
        self._dispatch_action(
            BrowserOperation.CLICK,
            lambda: self._with_visible_locator(
                selectors,
                lambda locator: locator.click(timeout=10_000, no_wait_after=True),
            ),
        )

    def press(self, selectors: tuple[str, ...], key: str) -> None:
        """Send one key to a visible control (e.g. Enter to submit a form field)."""

        self.last_operation = BrowserOperation.PRESS
        self._dispatch_action(
            BrowserOperation.PRESS,
            lambda: self._with_visible_locator(
                selectors,
                lambda locator: locator.press(key, timeout=10_000),
            ),
        )

    def press_page(self, key: str) -> None:
        """Send one page-level key through the semantic action ledger."""

        self.last_operation = BrowserOperation.PRESS
        self._dispatch_action(
            BrowserOperation.PRESS,
            lambda: self.page.keyboard.press(key),
        )

    def mouse_target(self, selectors: tuple[str, ...]) -> MouseTarget:
        """Resolve geometry before provider code claims an authentication submit."""

        self.last_operation = BrowserOperation.MOUSE_TARGET
        locator = self._visible_locator(selectors)
        if locator is None:
            raise RuntimeError("visible control geometry unavailable")
        box = locator.bounding_box()
        if not box or box["width"] <= 0 or box["height"] <= 0:
            raise RuntimeError("visible control geometry unavailable")
        return MouseTarget(
            x=float(box["x"] + box["width"] / 2),
            y=float(box["y"] + box["height"] / 2),
        )

    def mouse_click(self, target: MouseTarget) -> None:
        self.last_operation = BrowserOperation.MOUSE_CLICK

        def click_target() -> None:
            self.page.mouse.move(target.x, target.y, steps=4)
            self.page.mouse.click(target.x, target.y)

        self._dispatch_action(BrowserOperation.MOUSE_CLICK, click_target)

    def native_click(self, selectors: tuple[str, ...]) -> None:
        """Click one visible control through the selected headed surface."""

        self.last_operation = BrowserOperation.MOUSE_CLICK

        def click_native() -> None:
            locator = self._visible_locator(selectors)
            if locator is None:
                raise RuntimeError("no configured visible control was found")
            box = locator.bounding_box()
            if not box or box["width"] <= 0 or box["height"] <= 0:
                raise RuntimeError("visible control geometry unavailable")
            x = float(box["x"] + box["width"] / 2)
            y = float(box["y"] + box["height"] / 2)
            with self.challenge_pointer() as pointer:
                pointer.move(x, y, steps=8)
                pointer.down()
                try:
                    self.page.wait_for_timeout(60)
                finally:
                    pointer.up()

        self._dispatch_action(BrowserOperation.MOUSE_CLICK, click_native)

    def click_matching_text(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        excluded_text: tuple[str, ...] = (),
        allowed_origins: frozenset[str] | None = None,
    ) -> bool:
        """Click a visible choice containing a JIT value without returning it."""

        self.last_operation = BrowserOperation.CLICK_MATCHING_TEXT

        def click_match() -> bool:
            needle = value.strip().casefold()
            if not needle:
                return False
            excluded = tuple(item.casefold() for item in excluded_text)
            for candidate in self._visible_locators(
                selectors,
                allowed_origins=allowed_origins,
            ):
                label = str(candidate.inner_text()).casefold()
                if needle not in label or any(item in label for item in excluded):
                    continue
                candidate.click(timeout=10_000, no_wait_after=True)
                return True
            return False

        return bool(
            self._dispatch_action(BrowserOperation.CLICK_MATCHING_TEXT, click_match)
        )

    def wait_for_visible(
        self,
        selectors: tuple[str, ...],
        *,
        timeout_seconds: float = 10,
    ) -> bool:
        """Wait for a configured control without reading or returning its text."""

        self.last_operation = BrowserOperation.WAIT
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._visible_locator_while_navigating(selectors) is not None:
                return True
            self.page.wait_for_timeout(250)
        return self._visible_locator_while_navigating(selectors) is not None

    def wait_for_hidden(
        self,
        selectors: tuple[str, ...],
        *,
        timeout_seconds: float = 10,
    ) -> bool:
        """Wait until no configured control remains visible."""

        self.last_operation = BrowserOperation.WAIT
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._visible_locator_while_navigating(selectors) is None:
                return True
            self.page.wait_for_timeout(250)
        return self._visible_locator_while_navigating(selectors) is None

    def record_hcaptcha_round(
        self,
        *,
        round_index: int,
        family: str,
        visual_plan: VisualPlan,
        action_dispatched: bool,
        submit_control_clicked: bool,
        accepted: bool,
        acceptance_source: str,
        frame_open: bool,
        vendor_accepted: bool | None,
        generation_changed: bool | None,
        terminal_reason: str | None,
    ) -> None:
        """Append only bounded hCaptcha outcome facts to the runtime trace."""

        if self._trace is None:
            return
        state = self._attempt
        try:
            event = HCaptchaRoundEvent(
                attempt_id=state.attempt_id if state is not None else None,
                provider=state.provider if state is not None else None,
                round=round_index,
                family=HCaptchaPromptFamily(family),
                plan=HCaptchaPlanKind(visual_plan.kind.value),
                visual_plan=visual_plan,
                action_dispatched=action_dispatched,
                submit_control_clicked=submit_control_clicked,
                accepted=accepted,
                acceptance_source=ChallengeAcceptanceSource(acceptance_source),
                frame_open=frame_open,
                vendor_accepted=vendor_accepted,
                vendor_outcome=(
                    HCaptchaVendorOutcome.NOT_OBSERVED
                    if vendor_accepted is None
                    else HCaptchaVendorOutcome.ACCEPTED
                    if vendor_accepted
                    else HCaptchaVendorOutcome.REJECTED
                ),
                generation_changed=generation_changed,
                terminal_reason=(
                    HCaptchaTerminalReason(terminal_reason)
                    if terminal_reason is not None
                    else None
                ),
            )
        except Exception:
            self._trace.note_diagnostic_loss(
                "event_write",
                provider=state.provider if state is not None else None,
            )
            return
        self._record(event)

    def retain_failed_hcaptcha_round_images(
        self,
        *,
        round_index: int,
        before: bytes,
        after: bytes | None,
    ) -> None:
        """Retain private challenge images without changing solver behavior."""

        if self._trace is None or not 1 <= round_index <= 8:
            return
        provider = self._attempt.provider if self._attempt is not None else None
        self._trace.try_write_unique_screenshot(
            f"hcaptcha-{round_index}-before",
            before,
            provider=provider,
        )
        if after is not None:
            self._trace.try_write_unique_screenshot(
                f"hcaptcha-{round_index}-after",
                after,
                provider=provider,
            )

    def record_hcaptcha_checkpoint(
        self,
        *,
        round_index: int,
        stage: str,
        family: str,
        planner: str,
        elapsed_ms: float,
        planning_call: int = 1,
        images: tuple[bytes, ...] = (),
        instruction: str | None = None,
        visual_plan: VisualPlan | None = None,
        task_current: bool | None = None,
        task_identity_sha256: str | None = None,
        task_geometry: tuple[float, float, float, float] | None = None,
    ) -> None:
        trace, state = self._trace, self._attempt
        if trace is None or state is None:
            return
        try:
            prefix = (
                f"hc-{state.attempt_id[8:24]}-{round_index}-{planning_call}-{stage}"
            )
            paths: list[str] = []
            for index, data in enumerate(images):
                path = trace.try_write_unique_screenshot(
                    f"{prefix}-{index}",
                    data,
                    provider=state.provider,
                    attempt_id=state.attempt_id,
                )
                if path is not None:
                    paths.append(path.name)
            if instruction:
                path = trace.write_challenge_instruction(
                    prefix,
                    instruction,
                    provider=state.provider,
                    attempt_id=state.attempt_id,
                )
                if path is not None:
                    paths.append(path.name)
            self._record(
                HCaptchaCheckpointEvent.model_validate(
                    {
                        "attempt_id": state.attempt_id,
                        "provider": state.provider,
                        "round": round_index,
                        "planning_call": planning_call,
                        "stage": stage,
                        "family": family,
                        "planner": planner,
                        "elapsed_ms": elapsed_ms,
                        "task_sha256": hashlib.sha256(images[-1]).hexdigest()
                        if images
                        else None,
                        "visual_plan": visual_plan,
                        "task_current": task_current,
                        "task_identity_sha256": task_identity_sha256,
                        "task_geometry": task_geometry,
                        "images_requested": len(images),
                        "instruction_requested": bool(instruction),
                        "artifacts_complete": len(paths)
                        == len(images) + bool(instruction),
                        "artifacts": tuple(paths),
                    }
                )
            )
        except Exception:
            trace.note_diagnostic_loss("event_write", provider=state.provider)

    def record_hcaptcha_attempt_finished(
        self,
        *,
        rounds_attempted: int,
        surface_misses: int,
        accepted: bool,
        acceptance_source: str,
        last_vendor_outcome: str,
        terminal_reason: str,
    ) -> None:
        """Append exactly one bounded terminal fact for the active solve."""

        state = self._attempt
        if self._trace is None or state is None:
            return
        try:
            event = HCaptchaAttemptFinishedEvent(
                attempt_id=state.attempt_id,
                provider=state.provider,
                rounds_attempted=rounds_attempted,
                surface_miss_bucket=hcaptcha_surface_miss_bucket(surface_misses),
                accepted=accepted,
                acceptance_source=ChallengeAcceptanceSource(acceptance_source),
                last_vendor_outcome=HCaptchaVendorOutcome(last_vendor_outcome),
                terminal_reason=HCaptchaAttemptTerminalReason(terminal_reason),
            )
        except Exception:
            self._trace.note_diagnostic_loss(
                "event_write",
                provider=state.provider,
            )
            return
        self._record(event)

    def record_credential_callback(
        self,
        *,
        sequence: int,
        credential_present: bool | None,
        challenge_token_present: bool | None,
        status_class: str,
    ) -> None:
        """Append only bounded credential callback facts to the runtime trace."""

        if self._trace is None:
            return
        try:
            event = CredentialCallbackEvent(
                sequence=sequence,
                credential_present=credential_present,
                challenge_token_present=challenge_token_present,
                status_class=HttpStatusClass(status_class),
            )
        except Exception:
            self._trace.note_diagnostic_loss("event_write")
            return
        self._record(event)

    def record_identity_handoff(
        self,
        *,
        checkpoint: str,
        credential_action: str | None,
        identity_callback_complete: bool | None,
        identity_page_closed: bool | None,
        identity_page_state: str | None = None,
        identity_exit_reason: str | None = None,
        parent_state: str,
        callback_confirmed: bool | None,
        publisher_auth_cookie_present: bool | None,
        challenge_cookie_present: bool | None = None,
        callback_probe_status: int | None = None,
        callback_clearance_cookie_present: bool | None = None,
        paid_probe_outcome: str | None = None,
        entitlement_confirmed: bool | None = None,
        paid_auth_cookie_present: bool | None = None,
        paid_probe_access_state: str | None = None,
        paid_probe_stabilized: bool | None = None,
        verification_full: bool | None = None,
    ) -> None:
        """Append one bounded publisher/identity handoff checkpoint."""

        state = self._attempt
        if self._trace is None or state is None:
            return
        try:
            event = IdentityHandoffEvent(
                attempt_id=state.attempt_id,
                provider=state.provider,
                checkpoint=IdentityHandoffCheckpoint(checkpoint),
                credential_action=(
                    CredentialAction(credential_action)
                    if credential_action is not None
                    else None
                ),
                identity_callback_complete=identity_callback_complete,
                identity_page_closed=identity_page_closed,
                identity_page_state=(
                    IdentityPageState(identity_page_state)
                    if identity_page_state is not None
                    else None
                ),
                identity_exit_reason=(
                    IdentityExitReason(identity_exit_reason)
                    if identity_exit_reason is not None
                    else None
                ),
                parent_state=IdentityParentState(parent_state),
                callback_confirmed=callback_confirmed,
                publisher_auth_cookie_present=publisher_auth_cookie_present,
                challenge_cookie_present=challenge_cookie_present,
                callback_probe_status=callback_probe_status,
                callback_clearance_cookie_present=callback_clearance_cookie_present,
                paid_probe_outcome=(
                    PaidProbeOutcome(paid_probe_outcome)
                    if paid_probe_outcome is not None
                    else None
                ),
                entitlement_confirmed=entitlement_confirmed,
                paid_auth_cookie_present=paid_auth_cookie_present,
                paid_probe_access_state=(
                    AccessState(paid_probe_access_state)
                    if paid_probe_access_state is not None
                    else None
                ),
                paid_probe_stabilized=paid_probe_stabilized,
                verification_full=verification_full,
            )
        except Exception:
            self._trace.note_diagnostic_loss(
                "event_write",
                provider=state.provider,
            )
            return
        self._record(event)

    def record_perimeterx_hold(
        self,
        *,
        hold_index: int,
        pointer_backend: str,
        duration_seconds: float,
        release_reason: str,
        post_settle_acceptance_source: str | None,
        retry_invited: bool | None,
        control_still_present: bool | None,
        generation_relation: str,
        final_surface_state: str,
    ) -> None:
        """Append one bounded terminal fact for a started PerimeterX hold."""

        state = self._attempt
        if self._trace is None or state is None:
            return
        try:
            event = PerimeterXHoldEvent(
                attempt_id=state.attempt_id,
                provider=state.provider,
                hold_index=hold_index,
                pointer_backend=PerimeterXPointerBackend(pointer_backend),
                duration_bucket=duration_bucket(duration_seconds),
                release_reason=PerimeterXHoldReleaseReason(release_reason),
                post_settle_acceptance_source=(
                    ChallengeAcceptanceSource(post_settle_acceptance_source)
                    if post_settle_acceptance_source is not None
                    else None
                ),
                retry_invited=retry_invited,
                control_still_present=control_still_present,
                generation_relation=PerimeterXGenerationRelation(generation_relation),
                final_surface_state=PerimeterXFinalSurfaceState(final_surface_state),
            )
        except Exception:
            self._trace.note_diagnostic_loss(
                "event_write",
                provider=state.provider,
            )
            return
        self._record(event)

    def click_optional(self, selectors: tuple[str, ...]) -> bool:
        self.last_operation = BrowserOperation.CLICK_OPTIONAL

        def click_if_present() -> bool:
            try:
                locator = self._visible_locator(selectors)
                if locator is None:
                    return False
                box = locator.bounding_box()
                if not box or box["width"] <= 0 or box["height"] <= 0:
                    return False
                x = float(box["x"] + box["width"] / 2)
                y = float(box["y"] + box["height"] / 2)
                self.page.mouse.move(x, y, steps=4)
                self.page.mouse.click(x, y)
            except Exception:
                return False
            return True

        return bool(
            self._dispatch_action(BrowserOperation.CLICK_OPTIONAL, click_if_present)
        )

    def suppress_passkeys(self, mode: PasskeyMode) -> bool:
        self.last_operation = BrowserOperation.SUPPRESS_PASSKEYS
        present = mode is PasskeyMode.EMPTY_PRESENT

        def configure() -> bool:
            self._webauthn_session = self.context.new_cdp_session(self.page)
            self._webauthn_session.send("WebAuthn.enable", {"enableUI": False})
            self._webauthn_session.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": present,
                        "hasUserVerification": True,
                        "automaticPresenceSimulation": present,
                        "isUserVerified": present,
                    }
                },
            )
            return True

        return bool(
            self._dispatch_action(BrowserOperation.SUPPRESS_PASSKEYS, configure)
        )

    def evaluate(self, expression: str) -> object:
        self.last_operation = BrowserOperation.EVALUATE
        for attempt, delay_ms in enumerate(
            _OBSERVATIONAL_EVALUATE_DELAYS_MS,
            start=1,
        ):
            if delay_ms:
                self.page.wait_for_timeout(delay_ms)
            try:
                return self.page.evaluate(expression)
            except Exception as error:
                if (
                    attempt == len(_OBSERVATIONAL_EVALUATE_DELAYS_MS)
                    or _failure_category(error)
                    is not BrowserFailureCategory.CONTEXT_REPLACED
                ):
                    raise
        raise AssertionError("evaluate retry loop exhausted")  # pragma: no cover

    def add_init_script(self, script: str) -> None:
        """Install one provider-owned script before its next document loads."""

        self.last_operation = BrowserOperation.INIT_SCRIPT
        self._dispatch_action(
            BrowserOperation.INIT_SCRIPT,
            lambda: self.page.add_init_script(script),
        )

    def cookies(self) -> list[dict[str, object]]:
        self.last_operation = BrowserOperation.COOKIES
        return self.context.cookies()

    def replace_cookies(self, cookies: list[dict[str, object]]) -> None:
        """Replace the retained context's portable cookie set."""

        self.last_operation = BrowserOperation.REPLACE_COOKIES

        def replace_all() -> None:
            self.context.clear_cookies()
            if cookies:
                self.context.add_cookies(cookies)

        self._dispatch_action(BrowserOperation.REPLACE_COOKIES, replace_all)

    def clear_storage(self) -> None:
        """Clear page-local browser storage without exposing the raw page."""

        self.last_operation = BrowserOperation.CLEAR_STORAGE
        self._dispatch_action(
            BrowserOperation.CLEAR_STORAGE,
            lambda: self.page.evaluate(
                """
                () => {
                  try { localStorage.clear(); } catch (_) {}
                  try { sessionStorage.clear(); } catch (_) {}
                }
                """
            ),
        )

    def dispatch_challenge_action(self, dispatch: Callable[[], Any]) -> Any:
        """Record one challenge mutation before handing control to its mechanic."""

        self.last_operation = BrowserOperation.CHALLENGE_ACTION
        return self._dispatch_action(BrowserOperation.CHALLENGE_ACTION, dispatch)

    def user_agent(self) -> str:
        value = self.evaluate("() => navigator.userAgent")
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError("browser user agent is unavailable")
        return value.strip()

    def wait(self, seconds: float) -> None:
        self.last_operation = BrowserOperation.WAIT
        self.page.wait_for_timeout(seconds * 1000)

    def capture_diagnostic_screenshot(
        self,
        label: str,
        *,
        timeout_ms: int = 2_000,
    ) -> bool:
        """Best-effort diagnostic capture that never changes operation state."""

        if self._trace is None:
            return False
        provider = self._attempt.provider if self._attempt is not None else None
        omission = ArtifactOmission.CAPTURE_FAILED
        try:
            is_closed = getattr(self.page, "is_closed", None)
            if callable(is_closed) and is_closed():
                omission = ArtifactOmission.PAGE_UNAVAILABLE
                raise RuntimeError("diagnostic page unavailable")
            screenshot = self.page.screenshot(
                full_page=False,
                timeout=timeout_ms,
            )
        except Exception:
            self._trace.record_artifact(
                label,
                omission=omission,
                provider=provider,
                attempt_id=self._attempt.attempt_id if self._attempt else None,
                terminal=label.endswith("failure") or label == "paid-proof",
            )
            return False
        captured = (
            self._trace.try_write_unique_screenshot(
                label,
                screenshot,
                provider=provider,
                attempt_id=self._attempt.attempt_id if self._attempt else None,
                terminal=label.endswith("failure") or label == "paid-proof",
            )
            is not None
        )
        if captured and label.endswith("failure") and self._attempt is not None:
            self._attempt.failure_captured = True
        return captured

    def capture_incident_evidence(
        self, label: str = "content-snapshot", *, timeout_ms: int = 2_000
    ) -> RetrievalDiagnostics:
        """Preserve this response's terminal view for assessment after teardown."""
        screenshot = None
        status: Literal["captured", "capture_failed", "too_large"] = "capture_failed"
        try:
            screenshot = self.page.screenshot(full_page=False, timeout=timeout_ms)
            if not isinstance(screenshot, bytes) or not screenshot:
                screenshot = None
            elif len(screenshot) > 4 * 1024 * 1024:
                screenshot = None
                status = "too_large"
            else:
                status = "captured"
        except Exception:
            pass
        if self._trace is not None:
            provider = self._attempt.provider if self._attempt else None
            attempt_id = self._attempt.attempt_id if self._attempt else None
            if screenshot is not None:
                self._trace.try_write_unique_screenshot(
                    label,
                    screenshot,
                    provider=provider,
                    attempt_id=attempt_id,
                    terminal=True,
                )
            else:
                self._trace.record_artifact(
                    label,
                    omission=ArtifactOmission.CAPTURE_FAILED,
                    provider=provider,
                    attempt_id=attempt_id,
                    terminal=True,
                )
        if screenshot is not None and label.endswith("failure") and self._attempt:
            self._attempt.failure_captured = True
        return RetrievalDiagnostics(
            screenshot_status=status,
            screenshot=screenshot,
            trace=(
                self._trace.incident_snapshot(
                    self._attempt.attempt_id if self._attempt else None
                )
                if self._trace
                else None
            ),
        )

    def _capture_credential_form(self) -> None:
        state = self._attempt
        if (
            state is not None
            and state.purpose is AttemptPurpose.LOGIN
            and not state.form_captured
        ):
            # One capture before the first fill; never recapture a filled form.
            state.form_captured = True
            self.capture_diagnostic_screenshot("auth-form-ready")

    @contextmanager
    def challenge_pointer(self) -> Iterator[_SurfacePointer]:
        """Yield native X11 input when available for challenge holds.

        Virtual-display runs require X11 (a678ad8): CDP mouse is rejected by
        PerimeterX more often. Headed desktop also prefers X11 when DISPLAY is
        set, falling back to the browser debug-protocol mouse only when native
        input cannot be opened.
        """

        require_native = os.environ.get("NEWSCLIP_VIRTUAL_DISPLAY") == "1"
        prefer_native = require_native or bool(os.environ.get("DISPLAY", "").strip())
        if prefer_native:
            pointer: X11Pointer | None = None
            try:
                pointer = X11Pointer(self.page)
            except NativePointerUnavailable as error:
                if require_native:
                    raise BrowserRuntimeError(
                        InfrastructureCategory.NATIVE_INPUT_UNAVAILABLE
                    ) from error
            else:
                try:
                    yield pointer
                except NativePointerUnavailable as error:
                    raise BrowserRuntimeError(
                        InfrastructureCategory.NATIVE_INPUT_UNAVAILABLE
                    ) from error
                finally:
                    pointer.close()
                return
        yield self.page.mouse

    def _with_visible_locator(
        self,
        selectors: tuple[str, ...],
        action: Callable[[Any], None],
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> None:
        locator = self._visible_locator(
            selectors,
            allowed_origins=allowed_origins,
        )
        if locator is None:
            raise RuntimeError("no configured visible control was found")
        action(locator)

    def _visible_locator(
        self,
        selectors: tuple[str, ...],
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> Any | None:
        return next(
            self._visible_locators(
                selectors,
                allowed_origins=allowed_origins,
            ),
            None,
        )

    def _visible_locators(
        self,
        selectors: tuple[str, ...],
        *,
        combined: bool = False,
        allowed_origins: frozenset[str] | None = None,
    ) -> Iterator[Any]:
        roots = getattr(self.page, "frames", None) or (self.page,)
        for root in roots:
            if (
                allowed_origins is not None
                and _browser_origin(getattr(root, "url", "")) not in allowed_origins
            ):
                continue
            selected = (", ".join(selectors),) if combined else selectors
            for selector in selected:
                locator = root.locator(selector)
                for index in range(locator.count()):
                    candidate = locator.nth(index)
                    if not candidate.is_visible():
                        continue
                    if allowed_origins is None:
                        yield candidate
                        continue
                    # A Locator can retarget after navigation. An ElementHandle
                    # is bound to this exact document: a redirect detaches it
                    # and the secret application fails instead of following the
                    # selector onto an untrusted origin.
                    handle = candidate.element_handle()
                    if handle is None:
                        continue
                    if _browser_origin(getattr(root, "url", "")) in allowed_origins:
                        yield handle

    def _visible_locator_while_navigating(
        self, selectors: tuple[str, ...]
    ) -> Any | None:
        """Treat a transient document replacement as not-yet-visible."""

        try:
            return self._visible_locator(selectors)
        except Exception as error:
            if _failure_category(error) is not BrowserFailureCategory.CONTEXT_REPLACED:
                raise
            return None


@dataclass
class _KeptContext:
    profile: Path
    manager: Any
    context: Any
    browser: PatchrightMintContext
    browser_mode: BrowserMode
    profile_generation: ProfileGeneration
    started_monotonic: float
    on_forced_close: Callable[[Path], Callable[[], None] | None] | None
    process: OwnedBrowserProcess | None = None


def _navigation_timeout_ms(timeout_seconds: float) -> int:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("navigation timeout must be positive")
    return max(1, math.ceil(timeout_seconds * 1000))


class PatchrightRuntime:
    """Create and close one persistent context; own no provider policy.

    When ``keep_alive`` is true, the launched context stays open for reuse by
    later ``open`` calls on the same profile until ``close_kept`` / ``close``.
    Callers that keep a durable profile open must hold the profile lease for
    the full kept lifetime (Chromium ProcessSingleton).
    """

    def __init__(
        self,
        *,
        context_factory: Callable[..., object] | None = None,
        trace: RuntimeTrace | None = None,
    ) -> None:
        self._context_factory = context_factory
        self._trace = trace
        self._kept: dict[str, _KeptContext] = {}

    def close(self) -> None:
        """Close every keep-alive context owned by this runtime."""

        for key in list(self._kept):
            self.close_kept(Path(key))
        if self._trace is not None:
            self._trace.flush_health()

    def close_kept(self, profile: Path, *, notify_owner: bool = True) -> None:
        """Close one keep-alive context and invalidate its registered owner."""

        key = str(Path(profile))
        kept = self._kept.pop(key, None)
        if kept is None:
            return
        release_owner: Callable[[], None] | None = None
        if notify_owner and kept.on_forced_close is not None:
            with suppress(Exception):
                release_owner = kept.on_forced_close(kept.profile)
        try:
            self._shutdown_context(
                kept.manager,
                kept.context,
                browser_mode=kept.browser_mode,
                profile_generation=kept.profile_generation,
                started_monotonic=kept.started_monotonic,
                primary_failure=False,
                process=kept.process,
            )
        finally:
            if release_owner is not None:
                with suppress(Exception):
                    release_owner()

    @contextmanager
    def open(
        self,
        profile: Path,
        *,
        require_virtual_display: bool,
        profile_generation: ProfileGeneration = ProfileGeneration.RETAINED,
        launch_config: BrowserLaunchConfig | None = None,
        keep_alive: bool = False,
        on_forced_close: (Callable[[Path], Callable[[], None] | None] | None) = None,
    ) -> Iterator[PatchrightMintContext]:
        browser_mode = self._browser_mode(require_virtual_display)
        profile = Path(profile)
        if profile.is_symlink():
            raise BrowserRuntimeError(InfrastructureCategory.PROFILE_INVALID)
        profile.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(profile, 0o700)

        key = str(profile)
        kept = self._kept.get(key)
        if kept is not None and keep_alive:
            try:
                yield kept.browser
            except BaseException as error:
                self._capture_failure_screenshot(kept.browser)
                self._write_failure(
                    kept.browser_mode,
                    kept.profile_generation,
                    kept.browser,
                    error,
                    opened=True,
                )
                self._close_failed_kept(key)
                raise
            return
        if kept is not None:
            self.close_kept(profile)

        # Drop a different kept profile before launching another (one live
        # Chromium identity at a time per runtime is enough for product reads).
        if self._kept:
            for other in list(self._kept):
                self.close_kept(Path(other))

        started = time.monotonic()
        manager = None
        context = None
        browser = None
        process = None
        opened = False
        primary_failure = False
        keep = False
        try:
            profile_state: Literal["new", "existing", "unknown"] = "unknown"
            with suppress(OSError):
                profile_state = "existing" if next(profile.iterdir(), None) else "new"
            recovered_singleton = prepare_profile(profile)
            if self._trace is not None:
                self._trace.try_write(
                    BrowserStartedEvent(
                        browser_mode=browser_mode,
                        profile_generation=profile_generation,
                        recovered_local_singleton=recovered_singleton,
                    )
                )
            selected_launch = launch_config or BrowserLaunchConfig()
            if browser_mode is BrowserMode.HEADED_VIRTUAL:
                selected_launch = replace(
                    selected_launch,
                    args=tuple(
                        dict.fromkeys((*selected_launch.args, *_VIRTUAL_DISPLAY_ARGS))
                    ),
                )
            with timing_step(TimingStep.BROWSER_OPEN):
                manager, context = self._launch(
                    profile,
                    selected_launch,
                )
                if self._context_factory is None:
                    process = OwnedBrowserProcess.capture(profile)
                major = _browser_major(context)
                if major is not None:
                    set_timing_browser_major(major)
                pages = list(getattr(context, "pages", []))
                page = pages[0] if pages else context.new_page()
            opened = True
            browser = PatchrightMintContext(
                context, page, trace=self._trace, profile_state=profile_state
            )
            if keep_alive:
                self._kept[key] = _KeptContext(
                    profile=profile,
                    manager=manager,
                    context=context,
                    browser=browser,
                    browser_mode=browser_mode,
                    profile_generation=profile_generation,
                    started_monotonic=started,
                    on_forced_close=on_forced_close,
                    process=process,
                )
                keep = True
                manager = None
                context = None
            yield browser
        except BrowserRuntimeError as error:
            primary_failure = True
            self._capture_failure_screenshot(browser)
            self._write_failure(
                browser_mode,
                profile_generation,
                browser,
                error,
                opened=opened,
            )
            if keep:
                self._close_failed_kept(key)
                keep = False
            raise
        except BaseException as error:
            primary_failure = True
            self._capture_failure_screenshot(browser)
            self._write_failure(
                browser_mode,
                profile_generation,
                browser,
                error,
                opened=opened,
            )
            if keep:
                self._close_failed_kept(key)
                keep = False
            if not opened:
                category = (
                    InfrastructureCategory.BROWSER_STARTUP_TARGET_CLOSED
                    if _failure_category(error) is BrowserFailureCategory.TARGET_CLOSED
                    else InfrastructureCategory.BROWSER_STARTUP_FAILED
                )
                raise BrowserRuntimeError(category) from error
            raise
        finally:
            if not keep:
                self._shutdown_context(
                    manager,
                    context,
                    browser_mode=browser_mode,
                    profile_generation=profile_generation,
                    started_monotonic=started,
                    primary_failure=primary_failure,
                    process=process,
                )

    def _close_failed_kept(self, key: str) -> None:
        kept = self._kept.pop(key, None)
        if kept is None:
            return
        self._shutdown_context(
            kept.manager,
            kept.context,
            browser_mode=kept.browser_mode,
            profile_generation=kept.profile_generation,
            started_monotonic=kept.started_monotonic,
            primary_failure=True,
            process=kept.process,
        )

    def _shutdown_context(
        self,
        manager: Any,
        context: Any,
        *,
        browser_mode: BrowserMode,
        profile_generation: ProfileGeneration,
        started_monotonic: float,
        primary_failure: bool,
        process: OwnedBrowserProcess | None = None,
    ) -> None:
        if manager is None and context is None:
            if self._trace is not None:
                self._trace.flush_health()
            return
        cleanup_ok = True
        cleanup_error = None
        failures: list[Literal["context_close", "driver_stop", "browser_exit"]] = []
        exit_confirmed = None
        forced = False

        def stop_browser() -> None:
            try:
                if process is not None:
                    process.stop_if_alive()
            except Exception:
                failures.append("browser_exit")

        # Driver close has no public timeout. A pidfd watchdog can end only
        # this invocation's browser if the close RPC stalls; it never calls
        # the thread-affine browser API from another thread.
        watchdog = threading.Timer(10, stop_browser) if process is not None else None
        if watchdog is not None:
            watchdog.daemon = True
            watchdog.start()
        with timing_step(TimingStep.BROWSER_CLOSE):
            try:
                closers: dict[
                    Literal["context_close", "driver_stop"], Callable[[], Any] | None
                ] = {
                    "context_close": getattr(context, "close", None),
                    "driver_stop": getattr(manager, "stop", None),
                }
                for step, closer in closers.items():
                    if closer is None:
                        continue
                    try:
                        closer()
                    except Exception as error:
                        cleanup_ok = False
                        failures.append(step)
                        cleanup_error = cleanup_error or error
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                    watchdog.join(timeout=5)
                if process is not None:
                    try:
                        process.stop_if_alive()
                        exit_confirmed = process.exited()
                        forced = process.forced
                    except Exception as error:
                        failures.append("browser_exit")
                        cleanup_error = cleanup_error or error
                        exit_confirmed = False
                    finally:
                        process.close()
                    if forced or not exit_confirmed:
                        cleanup_ok = False
        if self._trace is not None and (manager is not None or context is not None):
            try:
                event = BrowserClosedEvent(
                    browser_mode=browser_mode,
                    profile_generation=profile_generation,
                    duration=duration_bucket(time.monotonic() - started_monotonic),
                    cleanup_ok=cleanup_ok,
                    cleanup_failures=tuple(dict.fromkeys(failures)),
                    browser_exit_confirmed=exit_confirmed,
                    forced_termination=forced,
                )
            except Exception:
                self._trace.note_diagnostic_loss("event_write")
            else:
                self._trace.try_write(event)
            self._trace.flush_health()
        if not cleanup_ok and not primary_failure:
            logging.getLogger(__name__).warning(
                "browser cleanup failed: steps=%s exit_confirmed=%s forced=%s",
                ",".join(dict.fromkeys(failures)),
                exit_confirmed,
                forced,
            )
            raise BrowserRuntimeError(
                InfrastructureCategory.PROFILE_EXIT_UNCONFIRMED
                if exit_confirmed is False
                else InfrastructureCategory.BROWSER_CLEANUP_FAILED
            ) from cleanup_error

    def _capture_failure_screenshot(
        self,
        browser: PatchrightMintContext | None,
    ) -> None:
        if browser is None:
            return
        browser.capture_diagnostic_screenshot("failure", timeout_ms=5_000)

    def _write_failure(
        self,
        browser_mode: BrowserMode,
        profile_generation: ProfileGeneration,
        browser: PatchrightMintContext | None,
        error: BaseException,
        *,
        opened: bool,
    ) -> None:
        if self._trace is None:
            return
        try:
            event = BrowserFailedEvent(
                browser_mode=browser_mode,
                profile_generation=profile_generation,
                phase=(
                    BrowserFailurePhase.OPERATION
                    if opened
                    else BrowserFailurePhase.STARTUP
                ),
                operation=(
                    browser.last_operation
                    if browser is not None
                    else BrowserOperation.INITIALIZED
                ),
                category=_failure_category(error),
            )
        except Exception:
            self._trace.note_diagnostic_loss("event_write")
            return
        self._trace.try_write(event)

    def _launch(self, profile: Path, config: BrowserLaunchConfig):
        options: dict[str, object] = {
            "user_data_dir": str(profile),
            "headless": False,
            "no_viewport": True,
        }
        if config.locale:
            options["locale"] = config.locale
        if config.timezone_id:
            options["timezone_id"] = config.timezone_id
        if config.accept_language:
            options["extra_http_headers"] = {"Accept-Language": config.accept_language}
        if config.channel:
            options["channel"] = config.channel
        if config.args:
            options["args"] = list(config.args)
        if self._context_factory is not None:
            context = self._context_factory(**options)
            return None, context
        from patchright.sync_api import sync_playwright

        manager = sync_playwright().start()
        try:
            context = manager.chromium.launch_persistent_context(
                str(profile),
                headless=False,
                no_viewport=True,
                locale=config.locale,
                timezone_id=config.timezone_id,
                extra_http_headers=(
                    {"Accept-Language": config.accept_language}
                    if config.accept_language
                    else None
                ),
                channel=config.channel,
                args=list(config.args) or None,
            )
        except Exception:
            manager.stop()
            raise
        return manager, context

    @staticmethod
    def _browser_mode(require_virtual_display: bool) -> BrowserMode:
        if not require_virtual_display:
            return BrowserMode.HEADED_DESKTOP
        display = os.environ.get("DISPLAY", "")
        if (
            os.environ.get("NEWSCLIP_VIRTUAL_DISPLAY") != "1"
            or not display_is_usable(display)
            or is_system_desktop_display(display)
        ):
            raise BrowserRuntimeError(
                InfrastructureCategory.VIRTUAL_DISPLAY_UNAVAILABLE
            )
        return BrowserMode.HEADED_VIRTUAL


def _failure_category(error: BaseException) -> BrowserFailureCategory:
    """Collapse a driver/provider exception chain into a closed safe category."""

    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain and len(chain) < 6:
        chain.append(current)
        current = current.__cause__ or current.__context__
    material = " ".join(f"{type(item).__name__} {item}".lower() for item in chain)
    if any(
        marker in material
        for marker in (
            "execution context",
            "context was destroyed",
            "frame was detached",
        )
    ):
        return BrowserFailureCategory.CONTEXT_REPLACED
    if any(
        marker in material
        for marker in ("target closed", "page closed", "browser has been closed")
    ):
        return BrowserFailureCategory.TARGET_CLOSED
    if "timeout" in material:
        return BrowserFailureCategory.TIMEOUT
    if "syntaxerror" in material or "unexpected token" in material:
        return BrowserFailureCategory.SCRIPT_ERROR
    return BrowserFailureCategory.UNCLASSIFIED


def _browser_origin(url: object) -> str:
    if not isinstance(url, str):
        return ""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return ""
    host = parsed.hostname.lower()
    default_port = (parsed.scheme == "https" and port == 443) or (
        parsed.scheme == "http" and port == 80
    )
    port_suffix = "" if port is None or default_port else f":{port}"
    return f"{parsed.scheme}://{host}{port_suffix}"


def _browser_major(context: object) -> int | None:
    try:
        owner = getattr(context, "browser", None)
        if callable(owner):
            owner = owner()
        value = getattr(owner, "version", None)
        if callable(value):
            value = value()
        match = re.search(r"\b(\d{1,3})(?:\.\d+)+", str(value or ""))
        return int(match.group(1)) if match else None
    except Exception:
        # Optional timing metadata must never break browser startup.
        return None
