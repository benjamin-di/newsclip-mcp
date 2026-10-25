"""Pure projection of validated runtime traces into bounded report evidence.

File loading and trace validation belong to live_reporting. This module consumes
records only; it cannot dispatch browser actions or persist reports.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import Field, model_validator

from .browser_runtime.events import (
    AcquisitionEvidenceEvent,
    ActionResult,
    AttemptFinishedEvent,
    AttemptOutcome,
    AttemptPurpose,
    AttemptStartedEvent,
    AuthObservationEvent,
    AuthPhase,
    BrowserFailedEvent,
    BrowserFailureCategory,
    BrowserOperation,
    ChallengeResolutionEvent,
    DiagnosticArtifactEvent,
    DiagnosticHealthEvent,
    HCaptchaAttemptFinishedEvent,
    HCaptchaCheckpointEvent,
    HCaptchaRoundEvent,
    HttpAttemptEvent,
    IdentityHandoffEvent,
    NavigationEvidence,
    PerimeterXFinalSurfaceState,
    PerimeterXHoldEvent,
    PerimeterXHoldReleaseReason,
    RuntimeEvent,
    RuntimeRun,
    SemanticActionFinishedEvent,
    SemanticActionStartedEvent,
    SemanticReadinessTerminalEvent,
)
from .models import CaptureFailure, FrozenModel
from .provider_keys import PROVIDER_KEY_PATTERN

_MAX_HTTP_ATTEMPTS = 128
_MAX_HCAPTCHA_ATTEMPTS = 32
_MAX_HCAPTCHA_ROUNDS = 32
_MAX_HCAPTCHA_CHECKPOINTS = 512
_MAX_IDENTITY_HANDOFFS = 32
_MAX_PERIMETERX_HOLDS = 96


class RuntimeEvidence(FrozenModel):
    event_counts: dict[str, int] = Field(default_factory=dict)
    failed_open_challenge_rounds: int = Field(default=0, ge=0)
    challenge_blocked: bool = False
    browser_failure_categories: tuple[BrowserFailureCategory, ...] = ()
    event_write_failures: int = Field(default=0, ge=0)
    screenshot_capture_failures: int = Field(default=0, ge=0)
    screenshot_write_failures: int = Field(default=0, ge=0)
    unattributed_event_write_failures: int = Field(default=0, ge=0)
    unattributed_screenshot_capture_failures: int = Field(default=0, ge=0)
    unattributed_screenshot_write_failures: int = Field(default=0, ge=0)
    unattributed_invalid_traces: int = Field(default=0, ge=0)


class RuntimeProviderEvidence(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    event_counts: dict[str, int] = Field(default_factory=dict)
    failed_open_challenge_rounds: int = Field(default=0, ge=0)
    challenge_blocked: bool = False
    browser_failure_categories: tuple[BrowserFailureCategory, ...] = ()
    event_write_failures: int = Field(default=0, ge=0)
    screenshot_capture_failures: int = Field(default=0, ge=0)
    screenshot_write_failures: int = Field(default=0, ge=0)


class LiveAttemptEvidence(FrozenModel):
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    purpose: AttemptPurpose
    outcome: AttemptOutcome | Literal["incomplete"]
    last_phase: AuthPhase
    observation_codes: tuple[str, ...] = ()
    terminal_observation_code: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    action_count: int = Field(default=0, ge=0)
    profile_state: Literal["new", "existing", "unknown"] = "unknown"
    profile_scope: Literal["public", "account", "unknown"] = "unknown"
    capture_failure: CaptureFailure | None = None
    challenge_action_count: int | None = Field(default=None, ge=0)
    last_navigation: NavigationEvidence | None = None
    last_action: BrowserOperation | None = None
    last_action_pre_observation_code: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    last_action_dispatched: bool | Literal["not_observed"] | None = None
    last_action_result: ActionResult | Literal["not_observed"] | None = None

    @model_validator(mode="after")
    def validate_last_action(self) -> LiveAttemptEvidence:
        action_present = self.last_action is not None
        if action_present != (self.last_action_pre_observation_code is not None):
            raise ValueError("last action projection is incomplete")
        if not action_present and (
            self.last_action_dispatched is not None
            or self.last_action_result is not None
        ):
            raise ValueError("last action result has no started action")
        if action_present and (
            self.last_action_dispatched is None or self.last_action_result is None
        ):
            raise ValueError("last action completion is incomplete")
        if (self.last_action_dispatched == "not_observed") is not (
            self.last_action_result == "not_observed"
        ):
            raise ValueError("last action observation state is inconsistent")
        return self


@dataclass(frozen=True)
class RuntimeTraceEvidence:
    """One loaded trace; a missing run explicitly records invalid input."""

    path_provider: str | None
    run: RuntimeRun | None


@dataclass(frozen=True)
class RuntimeProjection:
    """Named runtime fields for the existing report and snapshot contracts."""

    runtime: RuntimeEvidence
    attempts: tuple[LiveAttemptEvidence, ...]
    runtime_by_provider: tuple[RuntimeProviderEvidence, ...]
    hcaptcha_rounds: tuple[HCaptchaRoundEvent, ...]
    hcaptcha_attempts: tuple[HCaptchaAttemptFinishedEvent, ...]
    identity_handoffs: tuple[IdentityHandoffEvent, ...]
    perimeterx_holds: tuple[PerimeterXHoldEvent, ...]
    http_attempts: tuple[HttpAttemptEvent, ...]
    hcaptcha_checkpoints: tuple[HCaptchaCheckpointEvent, ...]
    acquisitions: tuple[AcquisitionEvidenceEvent, ...]
    diagnostic_artifacts: tuple[DiagnosticArtifactEvent, ...]
    challenge_resolutions: tuple[ChallengeResolutionEvent, ...]


def project_runtime_evidence(
    traces: Iterable[RuntimeTraceEvidence],
) -> RuntimeProjection:
    """Project ordered, validated traces without performing I/O.

    Trace boundaries matter: the last verdict per provider/vendor wins within
    each trace; a clear in another trace cannot erase a recorded failure.
    """
    builder = _RuntimeProjectionBuilder()
    for trace in traces:
        builder.add_trace(trace)
    return builder.finish()


class _RuntimeProjectionBuilder:
    """Own aggregation state for exactly one projection call."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.diagnostic_artifacts: deque[DiagnosticArtifactEvent] = deque(maxlen=1024)
        self.challenge_resolutions: deque[ChallengeResolutionEvent] = deque(maxlen=512)
        self.hcaptcha_checkpoints: deque[HCaptchaCheckpointEvent] = deque(
            maxlen=_MAX_HCAPTCHA_CHECKPOINTS
        )
        self.acquisitions: deque[AcquisitionEvidenceEvent] = deque(maxlen=128)
        self.pending_acquisitions: dict[str, str] = {}
        self.provider_counts: dict[str, Counter[str]] = {}
        self.attempts: dict[str, dict[str, object]] = {}
        self.hcaptcha_rounds: deque[HCaptchaRoundEvent] = deque(
            maxlen=_MAX_HCAPTCHA_ROUNDS
        )
        self.hcaptcha_attempts: deque[HCaptchaAttemptFinishedEvent] = deque(
            maxlen=_MAX_HCAPTCHA_ATTEMPTS
        )
        self.pending_hcaptcha_attempts: set[str] = set()
        self.identity_handoffs: deque[IdentityHandoffEvent] = deque(
            maxlen=_MAX_IDENTITY_HANDOFFS
        )
        self.perimeterx_holds: deque[PerimeterXHoldEvent] = deque(
            maxlen=_MAX_PERIMETERX_HOLDS
        )
        self.http_attempts: list[HttpAttemptEvent] = []
        self.failed_open_challenge_rounds = 0
        self.provider_failed_open_challenge_rounds: Counter[str] = Counter()
        self.challenge_blocked = False
        self.provider_challenge_blocked: dict[str, bool] = {}
        self.browser_failure_categories: set[BrowserFailureCategory] = set()
        self.provider_browser_failure_categories: dict[
            str, set[BrowserFailureCategory]
        ] = {}
        self.health_counts: Counter[str] = Counter()
        self.provider_health_counts: dict[str, Counter[str]] = {}
        self.unattributed_health_counts: Counter[str] = Counter()
        self.unattributed_invalid_traces = 0

    def add_trace(self, trace: RuntimeTraceEvidence) -> None:
        path_provider = trace.path_provider
        if trace.run is None:
            _record_invalid_trace(self.counts, self.provider_counts, path_provider)
            if path_provider is None:
                self.unattributed_invalid_traces += 1
            return
        # Keep the last state per vendor without one vendor masking another.
        file_challenge_states: dict[tuple[str | None, str], bool] = {}
        for record in trace.run.records:
            self._add_event(record.event, path_provider, file_challenge_states)
        self.challenge_blocked = self.challenge_blocked or any(
            file_challenge_states.values()
        )
        for (challenge_provider, _vendor), blocked in file_challenge_states.items():
            if challenge_provider is not None:
                self.provider_challenge_blocked[challenge_provider] = (
                    self.provider_challenge_blocked.get(challenge_provider, False)
                    or blocked
                )

    def _add_event(
        self,
        runtime_event: RuntimeEvent,
        path_provider: str | None,
        file_challenge_states: dict[tuple[str | None, str], bool],
    ) -> None:
        event = runtime_event.event
        event_provider = _runtime_event_provider(
            path_provider=path_provider,
            runtime_event=runtime_event,
            attempts=self.attempts,
        )
        self.counts[event] += 1
        if event_provider is not None:
            self.provider_counts.setdefault(event_provider, Counter())[event] += 1
        _aggregate_attempt_event(self.attempts, runtime_event)
        try:
            if isinstance(runtime_event, DiagnosticArtifactEvent):
                self.diagnostic_artifacts.append(runtime_event)
            elif isinstance(runtime_event, ChallengeResolutionEvent):
                self.challenge_resolutions.append(runtime_event)
            elif isinstance(runtime_event, HCaptchaCheckpointEvent):
                self.hcaptcha_checkpoints.append(runtime_event)
                self.pending_hcaptcha_attempts.add(runtime_event.attempt_id)
            elif isinstance(runtime_event, AcquisitionEvidenceEvent):
                self.acquisitions.append(runtime_event)
                if runtime_event.stage == "started":
                    self.pending_acquisitions[runtime_event.operation_id] = (
                        runtime_event.provider
                    )
                elif runtime_event.stage in {"failed", "published"}:
                    self.pending_acquisitions.pop(runtime_event.operation_id, None)
            elif isinstance(runtime_event, HCaptchaRoundEvent):
                hcaptcha_round = runtime_event
                self.hcaptcha_rounds.append(hcaptcha_round)
                if hcaptcha_round.attempt_id is not None:
                    self.pending_hcaptcha_attempts.add(hcaptcha_round.attempt_id)
                round_blocked = (
                    not hcaptcha_round.accepted
                    and hcaptcha_round.frame_open
                    and hcaptcha_round.vendor_accepted is not True
                )
                file_challenge_states[event_provider, "hcaptcha"] = round_blocked
                if round_blocked:
                    self.failed_open_challenge_rounds += 1
                    if event_provider is not None:
                        self.provider_failed_open_challenge_rounds[event_provider] += 1
            elif isinstance(runtime_event, HCaptchaAttemptFinishedEvent):
                self.hcaptcha_attempts.append(runtime_event)
                self.pending_hcaptcha_attempts.discard(runtime_event.attempt_id)
            elif isinstance(runtime_event, HttpAttemptEvent):
                if len(self.http_attempts) >= _MAX_HTTP_ATTEMPTS:
                    raise ValueError("HTTP attempt evidence is unbounded")
                self.http_attempts.append(runtime_event)
            elif isinstance(runtime_event, IdentityHandoffEvent):
                self.identity_handoffs.append(runtime_event)
            elif isinstance(runtime_event, PerimeterXHoldEvent):
                self.perimeterx_holds.append(runtime_event)
                # A hold that ends rejected, or leaves its control mounted
                # after the local mechanic finished, is an unaccepted
                # challenge exactly as an unaccepted hCaptcha round is. A
                # hold with no verdict writes nothing, so it cannot erase
                # what an earlier hold in the same attempt established.
                hold_blocked = _perimeterx_hold_blocked(runtime_event)
                if hold_blocked is not None:
                    file_challenge_states[event_provider, "perimeterx"] = hold_blocked
                if hold_blocked:
                    self.failed_open_challenge_rounds += 1
                    if event_provider is not None:
                        self.provider_failed_open_challenge_rounds[event_provider] += 1
            elif isinstance(runtime_event, DiagnosticHealthEvent):
                selected_counts = {
                    "event_write_failures": runtime_event.event_write_failures,
                    "screenshot_capture_failures": (
                        runtime_event.screenshot_capture_failures
                    ),
                    "screenshot_write_failures": (
                        runtime_event.screenshot_write_failures
                    ),
                }
                self.health_counts.update(selected_counts)
                health_provider = runtime_event.provider or path_provider
                if health_provider is None:
                    self.unattributed_health_counts.update(selected_counts)
                else:
                    self.provider_health_counts.setdefault(
                        health_provider, Counter()
                    ).update(selected_counts)
            elif isinstance(runtime_event, BrowserFailedEvent):
                selected = runtime_event.category
                self.browser_failure_categories.add(selected)
                if event_provider is not None:
                    self.provider_browser_failure_categories.setdefault(
                        event_provider, set()
                    ).add(selected)
        except ValueError:
            _record_invalid_trace(
                self.counts,
                self.provider_counts,
                event_provider or path_provider,
            )

    def _summarize_attempts(self) -> tuple[LiveAttemptEvidence, ...]:
        summarized: list[LiveAttemptEvidence] = []
        for attempt_id, facts in self.attempts.items():
            try:
                codes = facts.get("observation_codes", set())
                terminal_code = facts.get("terminal_observation_code")
                action_count = facts.get("action_count", 0)
                last_action = facts.get("last_action")
                last_action_pre_observation_code = facts.get(
                    "last_action_pre_observation_code"
                )
                last_action_dispatched = facts.get(
                    "last_action_dispatched",
                    "not_observed" if last_action is not None else None,
                )
                last_action_result = facts.get(
                    "last_action_result",
                    "not_observed" if last_action is not None else None,
                )
                if (
                    not isinstance(codes, set)
                    or terminal_code is not None
                    and not isinstance(terminal_code, str)
                    or not isinstance(action_count, int)
                    or last_action is not None
                    and not isinstance(last_action, str)
                    or last_action_pre_observation_code is not None
                    and not isinstance(last_action_pre_observation_code, str)
                    or last_action_dispatched is not None
                    and not isinstance(last_action_dispatched, bool | str)
                    or last_action_result is not None
                    and not isinstance(last_action_result, str)
                ):
                    raise TypeError("invalid aggregate attempt evidence")
                projected_dispatched: bool | Literal["not_observed"] | None
                if isinstance(last_action_dispatched, bool):
                    projected_dispatched = last_action_dispatched
                elif last_action_dispatched == "not_observed":
                    projected_dispatched = "not_observed"
                else:
                    projected_dispatched = None
                projected_result: ActionResult | Literal["not_observed"] | None
                if last_action_result == "not_observed":
                    projected_result = "not_observed"
                elif isinstance(last_action_result, str):
                    projected_result = ActionResult(last_action_result)
                else:
                    projected_result = None
                summarized.append(
                    LiveAttemptEvidence(
                        attempt_id=attempt_id,
                        provider=str(facts["provider"]),
                        purpose=AttemptPurpose(str(facts["purpose"])),
                        outcome=(
                            AttemptOutcome(str(facts["outcome"]))
                            if "outcome" in facts
                            else "incomplete"
                        ),
                        last_phase=AuthPhase(str(facts.get("last_phase", "unknown"))),
                        observation_codes=tuple(sorted(codes)),
                        terminal_observation_code=terminal_code,
                        action_count=action_count,
                        profile_state=cast(
                            Literal["new", "existing", "unknown"],
                            facts.get("profile_state", "unknown"),
                        ),
                        profile_scope=cast(
                            Literal["public", "account", "unknown"],
                            facts.get("profile_scope", "unknown"),
                        ),
                        capture_failure=cast(
                            CaptureFailure | None, facts.get("capture_failure")
                        ),
                        challenge_action_count=cast(
                            int | None, facts.get("challenge_action_count")
                        ),
                        last_navigation=cast(
                            NavigationEvidence | None, facts.get("last_navigation")
                        ),
                        last_action=(
                            BrowserOperation(last_action)
                            if last_action is not None
                            else None
                        ),
                        last_action_pre_observation_code=(
                            last_action_pre_observation_code
                        ),
                        last_action_dispatched=projected_dispatched,
                        last_action_result=projected_result,
                    )
                )
            except (KeyError, TypeError, ValueError):
                attempt_provider = facts.get("provider")
                _record_invalid_trace(
                    self.counts,
                    self.provider_counts,
                    (
                        attempt_provider
                        if isinstance(attempt_provider, str)
                        and re.fullmatch(PROVIDER_KEY_PATTERN, attempt_provider)
                        else None
                    ),
                )
        return tuple(sorted(summarized, key=lambda item: item.attempt_id))

    def _correlate(self, summarized_attempts: tuple[LiveAttemptEvidence, ...]) -> None:
        for acquisition_provider in self.pending_acquisitions.values():
            _record_invalid_trace(
                self.counts, self.provider_counts, acquisition_provider
            )
        attempt_providers = {
            attempt.attempt_id: attempt.provider for attempt in summarized_attempts
        }
        for attempt_id in self.pending_hcaptcha_attempts:
            provider = attempt_providers.get(attempt_id)
            self.counts["missing_hcaptcha_terminal"] += 1
            if provider is not None:
                self.provider_counts.setdefault(provider, Counter())[
                    "missing_hcaptcha_terminal"
                ] += 1
        valid_rounds: deque[HCaptchaRoundEvent] = deque(maxlen=_MAX_HCAPTCHA_ROUNDS)
        for round_event in self.hcaptcha_rounds:
            if (
                round_event.attempt_id is not None
                and attempt_providers.get(round_event.attempt_id)
                != round_event.provider
            ):
                _record_invalid_trace(
                    self.counts, self.provider_counts, round_event.provider
                )
                continue
            valid_rounds.append(round_event)
        self.hcaptcha_rounds = valid_rounds
        observed_checkpoints = {
            (item.attempt_id, item.round, item.stage)
            for item in self.hcaptcha_checkpoints
            if item.artifacts_complete
        }
        for round_event in self.hcaptcha_rounds:
            if not all(
                (round_event.attempt_id, round_event.round, stage)
                in observed_checkpoints
                for stage in ("input", "planned")
            ):
                self.counts["missing_hcaptcha_checkpoint"] += 1
                if round_event.provider is not None:
                    self.provider_counts.setdefault(round_event.provider, Counter())[
                        "missing_hcaptcha_checkpoint"
                    ] += 1
        valid_hcaptcha_attempts: deque[HCaptchaAttemptFinishedEvent] = deque(
            maxlen=_MAX_HCAPTCHA_ATTEMPTS
        )
        for terminal in self.hcaptcha_attempts:
            if attempt_providers.get(terminal.attempt_id) != terminal.provider:
                _record_invalid_trace(
                    self.counts, self.provider_counts, terminal.provider
                )
                continue
            valid_hcaptcha_attempts.append(terminal)
        self.hcaptcha_attempts = valid_hcaptcha_attempts
        valid_handoffs: deque[IdentityHandoffEvent] = deque(
            maxlen=_MAX_IDENTITY_HANDOFFS
        )
        for handoff in self.identity_handoffs:
            if attempt_providers.get(handoff.attempt_id) != handoff.provider:
                _record_invalid_trace(
                    self.counts, self.provider_counts, handoff.provider
                )
                continue
            valid_handoffs.append(handoff)
        self.identity_handoffs = valid_handoffs
        valid_perimeterx_holds: deque[PerimeterXHoldEvent] = deque(
            maxlen=_MAX_PERIMETERX_HOLDS
        )
        for hold in self.perimeterx_holds:
            if attempt_providers.get(hold.attempt_id) != hold.provider:
                _record_invalid_trace(self.counts, self.provider_counts, hold.provider)
                continue
            valid_perimeterx_holds.append(hold)
        self.perimeterx_holds = valid_perimeterx_holds

    def finish(self) -> RuntimeProjection:
        summarized_attempts = self._summarize_attempts()
        self._correlate(summarized_attempts)
        runtime = RuntimeEvidence(
            event_counts=dict(sorted(self.counts.items())),
            failed_open_challenge_rounds=self.failed_open_challenge_rounds,
            challenge_blocked=self.challenge_blocked,
            browser_failure_categories=tuple(
                sorted(self.browser_failure_categories, key=lambda item: item.value)
            ),
            event_write_failures=self.health_counts["event_write_failures"],
            screenshot_capture_failures=self.health_counts[
                "screenshot_capture_failures"
            ],
            screenshot_write_failures=self.health_counts["screenshot_write_failures"],
            unattributed_event_write_failures=self.unattributed_health_counts[
                "event_write_failures"
            ],
            unattributed_screenshot_capture_failures=self.unattributed_health_counts[
                "screenshot_capture_failures"
            ],
            unattributed_screenshot_write_failures=self.unattributed_health_counts[
                "screenshot_write_failures"
            ],
            unattributed_invalid_traces=self.unattributed_invalid_traces,
        )
        all_provider_keys = (
            self.provider_counts.keys() | self.provider_health_counts.keys()
        )
        runtime_by_provider = tuple(
            RuntimeProviderEvidence(
                provider=provider,
                event_counts=dict(
                    sorted(self.provider_counts.get(provider, Counter()).items())
                ),
                failed_open_challenge_rounds=self.provider_failed_open_challenge_rounds[
                    provider
                ],
                challenge_blocked=self.provider_challenge_blocked.get(provider, False),
                browser_failure_categories=tuple(
                    sorted(
                        self.provider_browser_failure_categories.get(provider, set()),
                        key=lambda item: item.value,
                    )
                ),
                event_write_failures=self.provider_health_counts.get(
                    provider, Counter()
                )["event_write_failures"],
                screenshot_capture_failures=self.provider_health_counts.get(
                    provider, Counter()
                )["screenshot_capture_failures"],
                screenshot_write_failures=self.provider_health_counts.get(
                    provider, Counter()
                )["screenshot_write_failures"],
            )
            for provider in sorted(all_provider_keys)
        )
        return RuntimeProjection(
            runtime=runtime,
            attempts=summarized_attempts,
            runtime_by_provider=runtime_by_provider,
            hcaptcha_rounds=tuple(self.hcaptcha_rounds),
            hcaptcha_attempts=tuple(self.hcaptcha_attempts),
            identity_handoffs=tuple(self.identity_handoffs),
            perimeterx_holds=tuple(self.perimeterx_holds),
            http_attempts=tuple(self.http_attempts),
            hcaptcha_checkpoints=tuple(self.hcaptcha_checkpoints),
            acquisitions=tuple(self.acquisitions),
            diagnostic_artifacts=tuple(self.diagnostic_artifacts),
            challenge_resolutions=tuple(self.challenge_resolutions),
        )


def _perimeterx_hold_blocked(hold: PerimeterXHoldEvent) -> bool | None:
    """Report whether one hold left the challenge unaccepted.

    ``None`` means the hold carries no verdict at all. An interrupted hold has
    no post-settle facts, so it must not overwrite what an earlier hold in the
    same attempt already established. A cleared surface is acceptance;
    everything else ended with the vendor still refusing or still asking.
    """

    if hold.release_reason is PerimeterXHoldReleaseReason.INTERRUPTED:
        return None
    if hold.final_surface_state is PerimeterXFinalSurfaceState.CLEARED:
        return False
    return (
        hold.release_reason is PerimeterXHoldReleaseReason.REJECTED
        or hold.final_surface_state
        in {
            PerimeterXFinalSurfaceState.REJECTED,
            PerimeterXFinalSurfaceState.COMPLETED_CONTROL_PRESENT,
        }
    )


def _record_invalid_trace(
    counts: Counter[str],
    provider_counts: dict[str, Counter[str]],
    provider: str | None,
) -> None:
    counts["invalid_trace"] += 1
    if provider is not None:
        provider_counts.setdefault(provider, Counter())["invalid_trace"] += 1


def _runtime_event_provider(
    *,
    path_provider: str | None,
    runtime_event: RuntimeEvent,
    attempts: dict[str, dict[str, object]],
) -> str | None:
    if path_provider is not None:
        return path_provider
    provider = getattr(runtime_event, "provider", None)
    if isinstance(provider, str) and re.fullmatch(PROVIDER_KEY_PATTERN, provider):
        return provider
    attempt_id = getattr(runtime_event, "attempt_id", None)
    if isinstance(attempt_id, str):
        attempt = attempts.get(attempt_id)
        if attempt is not None:
            attempt_provider = attempt.get("provider")
            if isinstance(attempt_provider, str) and re.fullmatch(
                PROVIDER_KEY_PATTERN, attempt_provider
            ):
                return attempt_provider
    return None


def _aggregate_attempt_event(
    attempts: dict[str, dict[str, object]],
    runtime_event: RuntimeEvent,
) -> None:
    if isinstance(runtime_event, AttemptStartedEvent):
        attempts[runtime_event.attempt_id] = {
            "provider": runtime_event.provider,
            "purpose": runtime_event.purpose.value,
            "observation_codes": set(),
            "action_count": 0,
            "profile_state": runtime_event.profile_state,
            "profile_scope": runtime_event.profile_scope,
            "challenge_action_count": 0,
        }
        return
    attempt_id = getattr(runtime_event, "attempt_id", None)
    if not isinstance(attempt_id, str):
        return
    attempt = attempts.get(attempt_id)
    if attempt is None:
        return
    if isinstance(runtime_event, AttemptFinishedEvent):
        attempt["outcome"] = runtime_event.outcome.value
        attempt["last_phase"] = runtime_event.last_phase.value
        attempt["capture_failure"] = runtime_event.capture_failure
        if runtime_event.last_navigation is not None:
            attempt["last_navigation"] = runtime_event.last_navigation
    elif isinstance(runtime_event, AuthObservationEvent):
        codes = attempt["observation_codes"]
        assert isinstance(codes, set)
        codes.add(runtime_event.state_code)
        attempt["terminal_observation_code"] = runtime_event.state_code
        attempt["last_phase"] = runtime_event.phase.value
    elif isinstance(runtime_event, SemanticReadinessTerminalEvent):
        codes = attempt["observation_codes"]
        assert isinstance(codes, set)
        codes.add(runtime_event.state.value)
        attempt["terminal_observation_code"] = runtime_event.state.value
    elif isinstance(runtime_event, SemanticActionStartedEvent):
        attempt["last_action_id"] = runtime_event.action_id
        attempt["last_action"] = runtime_event.action.value
        attempt["last_action_pre_observation_code"] = runtime_event.pre_observation_code
        attempt.pop("last_action_dispatched", None)
        attempt.pop("last_action_result", None)
        if runtime_event.action is BrowserOperation.CHALLENGE_ACTION:
            count = attempt["challenge_action_count"]
            assert isinstance(count, int)
            attempt["challenge_action_count"] = count + 1
    elif isinstance(runtime_event, SemanticActionFinishedEvent):
        attempt["last_action_dispatched"] = runtime_event.dispatched
        attempt["last_action_result"] = runtime_event.result.value
        if runtime_event.navigation is not None:
            attempt["last_navigation"] = runtime_event.navigation
        if runtime_event.dispatched:
            action_count = attempt["action_count"]
            assert isinstance(action_count, int)
            attempt["action_count"] = action_count + 1
        elif attempt.get("last_action") == BrowserOperation.CHALLENGE_ACTION:
            count = attempt["challenge_action_count"]
            assert isinstance(count, int)
            attempt["challenge_action_count"] = count - 1
