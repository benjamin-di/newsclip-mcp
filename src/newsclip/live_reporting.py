"""Private, closed reporting contracts for provider live acceptance."""

from __future__ import annotations

import fcntl
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, TypeAdapter, model_validator

from .acquisition import AcquisitionMode, MintFailureCategory, MintFailureStage
from .browser_runtime.events import (
    AcquisitionEvidenceEvent,
    AttemptOutcome,
    AttemptPurpose,
    AttemptStartedEvent,
    ChallengeResolutionEvent,
    DiagnosticArtifactEvent,
    HCaptchaAttemptFinishedEvent,
    HCaptchaCheckpointEvent,
    HCaptchaRoundEvent,
    HttpAttemptEvent,
    HttpOperationRole,
    HttpRetryReason,
    HttpRouteMode,
    IdentityHandoffEvent,
    PerimeterXHoldEvent,
    RuntimeRun,
    read_runtime_file,
)
from .challenge_resolver import ChallengeResolutionStatus
from .challenges import ChallengeVendor
from .errors import TransportFailure
from .live_diagnostics import (
    DiagnosisAction,
    DiagnosisReason,
    DiagnosticFacts,
    EvidenceStrength,
    LiveDiagnosis,
    LiveDiagnosisSummary,
    ReproductionKind,
    classify_live_failure,
)
from .models import AccessState, FrozenModel
from .provenance import (
    SourceIdentity,
    SourceIdentityError,
)
from .provenance import (
    build_source_identity as _build_source_identity,
)
from .provider_keys import PROVIDER_KEY_PATTERN
from .runtime_projection import (
    _MAX_HCAPTCHA_ATTEMPTS,
    _MAX_HCAPTCHA_CHECKPOINTS,
    _MAX_HCAPTCHA_ROUNDS,
    _MAX_HTTP_ATTEMPTS,
    _MAX_IDENTITY_HANDOFFS,
    _MAX_PERIMETERX_HOLDS,
    RuntimeTraceEvidence,
    project_runtime_evidence,
)
from .runtime_projection import LiveAttemptEvidence as LiveAttemptEvidence
from .runtime_projection import RuntimeEvidence as RuntimeEvidence
from .runtime_projection import RuntimeProviderEvidence as RuntimeProviderEvidence
from .timing import (
    ContentAssessmentEvidence,
    IncidentEvidence,
    StepFinishedEvent,
    TimingOperation,
    TimingOutcome,
    TimingRun,
    TimingRunMode,
    TimingStep,
    TimingTransport,
)


def _application_version() -> str:
    from . import __version__

    return __version__


_INVOCATION_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_ARTIFACT_PART = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DIAGNOSTIC_CONTRACT_VERSION = 7


class LiveReportPersistenceError(RuntimeError):
    """A private live report or baseline could not be persisted safely."""


class LiveReportOutcome(StrEnum):
    INCOMPLETE = "incomplete"
    SUCCESS = "success"
    FAILURE = "failure"


class LiveExitClass(StrEnum):
    INCOMPLETE = "incomplete"
    PASSED = "passed"
    DISPLAY_UNAVAILABLE = "display_unavailable"
    WARM_PREFLIGHT = "warm_preflight"
    PYTEST_START = "pytest_start"
    PYTEST_FAILURE = "pytest_failure"
    TIMING_EVIDENCE = "timing_evidence"
    DIAGNOSTIC_EVIDENCE = "diagnostic_evidence"
    ARTIFACT_CLEANUP = "artifact_cleanup"
    INTERNAL = "internal"


class EnvironmentIdentity(FrozenModel):
    python: str = Field(pattern=r"^[0-9]+\.[0-9]+$")
    application: str = Field(min_length=1, max_length=32)
    browser: Literal["chromium"] | None = None
    browser_majors: tuple[int, ...] = ()
    surface: str = Field(min_length=1, max_length=64)


class LiveOperationEvidence(FrozenModel):
    operation_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    acquisition_mode: AcquisitionMode | None = None
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    mode: TimingRunMode
    operation: TimingOperation
    transport: TimingTransport | None = None
    browser_fallback_attempted: bool | None = None
    browser_first: bool | None = None
    outcome: Literal["success", "error", "timeout", "censored"]
    last_step: TimingStep | None = None
    failure_stage: MintFailureStage | None = None
    failure_category: MintFailureCategory | None = None
    assessment_reached: bool = False
    content_assessment: ContentAssessmentEvidence | None = None
    incident: IncidentEvidence | None = None
    observation_codes: tuple[str, ...] = ()
    action_count: int = Field(default=0, ge=0)
    duration_ms: float = Field(ge=0, allow_inf_nan=False)


class EvidenceGap(StrEnum):
    MISSING_RESPONSE_CAPTURE = "missing_response_capture"
    MISSING_DECISIVE_IMAGE = "missing_decisive_image"
    MISSING_HCAPTCHA_CHECKPOINT = "missing_hcaptcha_checkpoint"
    DIAGNOSTIC_LOSS = "diagnostic_loss"
    INCOMPLETE_ATTEMPT = "incomplete_attempt"
    INVALID_RUNTIME_TRACE = "invalid_runtime_trace"
    MISSING_BROWSER_TRACE = "missing_browser_trace"
    MISSING_CONTENT_ASSESSMENT = "missing_content_assessment"
    MISSING_HCAPTCHA_TERMINAL = "missing_hcaptcha_terminal"
    MISSING_HTTP_ATTEMPT = "missing_http_attempt"
    MISSING_SESSION_PROBE = "missing_session_probe"


class LiveProviderDiagnosis(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    evidence_complete: bool = True
    missing_evidence: tuple[EvidenceGap, ...] = ()
    diagnosis: LiveDiagnosisSummary = LiveDiagnosisSummary()

    @model_validator(mode="after")
    def validate_evidence_state(self) -> LiveProviderDiagnosis:
        if self.evidence_complete == bool(self.missing_evidence):
            raise ValueError("provider evidence completeness is inconsistent")
        return self


class ArtifactSummary(FrozenModel):
    timing_files: int = Field(default=0, ge=0)
    runtime_files: int = Field(default=0, ge=0)
    screenshots: int = Field(default=0, ge=0)
    references: tuple[str, ...] = ()


class HttpAttemptSummary(FrozenModel):
    attempt_count: int = Field(default=0, ge=0)
    shared_affinity_attempts: int = Field(default=0, ge=0)
    overflow_ephemeral_attempts: int = Field(default=0, ge=0)
    authenticated_affinity_attempts: int = Field(default=0, ge=0)
    contention_attempts: int = Field(default=0, ge=0)
    statuses: tuple[Annotated[int, Field(ge=100, le=599)], ...] = ()
    retry_reasons: tuple[HttpRetryReason, ...] = ()
    transport_failures: tuple[TransportFailure, ...] = ()
    datadome_header_observed: bool = False
    datadome_cookie_observed: bool = False

    @model_validator(mode="after")
    def validate_attempt_totals(self) -> HttpAttemptSummary:
        route_total = (
            self.shared_affinity_attempts
            + self.overflow_ephemeral_attempts
            + self.authenticated_affinity_attempts
        )
        if route_total != self.attempt_count:
            raise ValueError("HTTP route counts are inconsistent")
        if self.contention_attempts > self.attempt_count:
            raise ValueError("HTTP contention count is inconsistent")
        if len(self.retry_reasons) != self.attempt_count:
            raise ValueError("HTTP retry count is inconsistent")
        if len(self.statuses) + len(self.transport_failures) != self.attempt_count:
            raise ValueError("HTTP outcome counts are inconsistent")
        return self


_BASELINE_HTTP_ALIASES = {"reuters_http": "http_summary"}


def _normalize_legacy_http_fields(
    raw: object,
    aliases: Mapping[str, str],
) -> object:
    if not isinstance(raw, dict):
        return raw
    normalized = dict(raw)
    for legacy, current in aliases.items():
        if legacy not in normalized:
            continue
        if current in normalized:
            raise ValueError(f"conflicting legacy and current HTTP field: {current}")
        normalized[current] = normalized.pop(legacy)
    return normalized


class LastSuccessComparison(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    mode: TimingRunMode
    operation: TimingOperation
    prior_invocation_id: str | None = Field(default=None, pattern=_INVOCATION_PATTERN)
    same_source: bool | None = None
    changed_paths: tuple[str, ...] = ()
    prior_terminal_observation_codes: tuple[str, ...] = ()
    current_terminal_observation_codes: tuple[str, ...] = ()
    stable_observation_changed: bool | None = None
    prior_http: HttpAttemptSummary | None = None
    current_http: HttpAttemptSummary | None = None
    http_changed: bool | None = None
    prior_content_assessment: ContentAssessmentEvidence | None = None
    current_content_assessment: ContentAssessmentEvidence | None = None
    content_assessment_changed: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def read_legacy_http_fields(cls, raw: object) -> object:
        return _normalize_legacy_http_fields(
            raw,
            {
                "prior_reuters_http": "prior_http",
                "current_reuters_http": "current_http",
                "reuters_http_changed": "http_changed",
            },
        )


class LiveReport(FrozenModel):
    schema_version: Literal[1, 2] = 2
    diagnostic_artifacts: tuple[DiagnosticArtifactEvent, ...] = Field(
        default=(), max_length=1024
    )
    challenge_resolutions: tuple[ChallengeResolutionEvent, ...] = Field(
        default=(), max_length=512
    )
    hcaptcha_checkpoints: tuple[HCaptchaCheckpointEvent, ...] = Field(
        default=(), max_length=_MAX_HCAPTCHA_CHECKPOINTS
    )
    acquisitions: tuple[AcquisitionEvidenceEvent, ...] = Field(
        default=(), max_length=128
    )
    diagnostic_contract_version: int = Field(default=1, ge=1, le=7)
    invocation_id: str = Field(pattern=_INVOCATION_PATTERN)
    mode: TimingRunMode
    providers: tuple[Annotated[str, Field(pattern=PROVIDER_KEY_PATTERN)], ...]
    successful_providers: tuple[
        Annotated[str, Field(pattern=PROVIDER_KEY_PATTERN)], ...
    ] = ()
    started_at: AwareDatetime
    completed_at: AwareDatetime | None = None
    outcome: LiveReportOutcome
    exit_class: LiveExitClass
    provenance: SourceIdentity
    environment: EnvironmentIdentity
    operations: tuple[LiveOperationEvidence, ...] = ()
    attempts: tuple[LiveAttemptEvidence, ...] = ()
    hcaptcha_attempts: tuple[HCaptchaAttemptFinishedEvent, ...] = Field(
        default=(),
        max_length=_MAX_HCAPTCHA_ATTEMPTS,
    )
    hcaptcha_rounds: tuple[HCaptchaRoundEvent, ...] = Field(
        default=(),
        max_length=_MAX_HCAPTCHA_ROUNDS,
    )
    identity_handoffs: tuple[IdentityHandoffEvent, ...] = Field(
        default=(),
        max_length=_MAX_IDENTITY_HANDOFFS,
    )
    perimeterx_holds: tuple[PerimeterXHoldEvent, ...] = Field(
        default=(),
        max_length=_MAX_PERIMETERX_HOLDS,
    )
    http_attempts: tuple[HttpAttemptEvent, ...] = Field(
        default=(),
        max_length=_MAX_HTTP_ATTEMPTS,
    )
    runtime: RuntimeEvidence = RuntimeEvidence()
    runtime_by_provider: tuple[RuntimeProviderEvidence, ...] = ()
    comparisons: tuple[LastSuccessComparison, ...] = ()
    provider_diagnoses: tuple[LiveProviderDiagnosis, ...] = ()
    diagnosis: LiveDiagnosisSummary = LiveDiagnosisSummary()
    artifacts: ArtifactSummary = ArtifactSummary()

    @model_validator(mode="after")
    def validate_provider_results(self) -> LiveReport:
        if len(set(self.providers)) != len(self.providers):
            raise ValueError("live report providers must be unique")
        if len(set(self.successful_providers)) != len(self.successful_providers):
            raise ValueError("successful live report providers must be unique")
        if not set(self.successful_providers).issubset(self.providers):
            raise ValueError("successful providers must belong to the live report")
        diagnosed = tuple(item.provider for item in self.provider_diagnoses)
        if len(set(diagnosed)) != len(diagnosed):
            raise ValueError("provider diagnoses must be unique")
        if not set(diagnosed).issubset(self.providers):
            raise ValueError("provider diagnoses must belong to the live report")
        runtime_providers = tuple(item.provider for item in self.runtime_by_provider)
        if len(set(runtime_providers)) != len(runtime_providers):
            raise ValueError("provider runtime summaries must be unique")
        if not set(runtime_providers).issubset(self.providers):
            raise ValueError(
                "provider runtime summaries must belong to the live report"
            )
        if not {attempt.provider for attempt in self.http_attempts}.issubset(
            self.providers
        ):
            raise ValueError("HTTP attempts must belong to the live report")
        challenge_providers = {
            round_event.provider
            for round_event in self.hcaptcha_rounds
            if round_event.provider is not None
        }
        if not challenge_providers.issubset(self.providers):
            raise ValueError("hCaptcha rounds must belong to the live report")
        attempt_providers = {
            attempt.attempt_id: attempt.provider for attempt in self.attempts
        }
        linked: tuple[DiagnosticArtifactEvent | ChallengeResolutionEvent, ...] = (
            *self.diagnostic_artifacts,
            *self.challenge_resolutions,
        )
        for item in linked:
            if item.provider is not None and item.provider not in self.providers:
                raise ValueError("diagnostic evidence must belong to the live report")
            if (
                item.attempt_id is not None
                and attempt_providers.get(item.attempt_id) != item.provider
            ):
                raise ValueError("diagnostic attempt correlation is invalid")
        for checkpoint in self.hcaptcha_checkpoints:
            if attempt_providers.get(checkpoint.attempt_id) != checkpoint.provider:
                raise ValueError("hCaptcha checkpoint attempt correlation is invalid")
        if any(item.provider not in self.providers for item in self.acquisitions):
            raise ValueError("acquisition evidence must belong to the live report")
        for round_event in self.hcaptcha_rounds:
            if round_event.attempt_id is None:
                continue
            if attempt_providers.get(round_event.attempt_id) != round_event.provider:
                raise ValueError("hCaptcha round attempt correlation is invalid")
        for terminal in self.hcaptcha_attempts:
            if terminal.provider not in self.providers:
                raise ValueError("hCaptcha attempt must belong to the live report")
            if attempt_providers.get(terminal.attempt_id) != terminal.provider:
                raise ValueError("hCaptcha attempt correlation is invalid")
        for handoff in self.identity_handoffs:
            if handoff.provider not in self.providers:
                raise ValueError("identity handoff must belong to the live report")
            if attempt_providers.get(handoff.attempt_id) != handoff.provider:
                raise ValueError("identity handoff attempt correlation is invalid")
        for hold in self.perimeterx_holds:
            if hold.provider not in self.providers:
                raise ValueError("PerimeterX hold must belong to the live report")
            if attempt_providers.get(hold.attempt_id) != hold.provider:
                raise ValueError("PerimeterX hold attempt correlation is invalid")
        return self


class LiveEvidenceSnapshot(FrozenModel):
    """One immutable read of the current invocation's structured evidence."""

    diagnostic_artifacts: tuple[DiagnosticArtifactEvent, ...] = Field(
        default=(), max_length=1024
    )
    challenge_resolutions: tuple[ChallengeResolutionEvent, ...] = Field(
        default=(), max_length=512
    )

    hcaptcha_checkpoints: tuple[HCaptchaCheckpointEvent, ...] = Field(
        default=(), max_length=_MAX_HCAPTCHA_CHECKPOINTS
    )
    acquisitions: tuple[AcquisitionEvidenceEvent, ...] = Field(
        default=(), max_length=128
    )
    operations: tuple[LiveOperationEvidence, ...] = ()
    attempts: tuple[LiveAttemptEvidence, ...] = ()
    hcaptcha_attempts: tuple[HCaptchaAttemptFinishedEvent, ...] = Field(
        default=(),
        max_length=_MAX_HCAPTCHA_ATTEMPTS,
    )
    hcaptcha_rounds: tuple[HCaptchaRoundEvent, ...] = Field(
        default=(),
        max_length=_MAX_HCAPTCHA_ROUNDS,
    )
    identity_handoffs: tuple[IdentityHandoffEvent, ...] = Field(
        default=(),
        max_length=_MAX_IDENTITY_HANDOFFS,
    )
    perimeterx_holds: tuple[PerimeterXHoldEvent, ...] = Field(
        default=(),
        max_length=_MAX_PERIMETERX_HOLDS,
    )
    http_attempts: tuple[HttpAttemptEvent, ...] = Field(
        default=(),
        max_length=_MAX_HTTP_ATTEMPTS,
    )
    runtime: RuntimeEvidence = RuntimeEvidence()
    runtime_by_provider: tuple[RuntimeProviderEvidence, ...] = ()


class LiveProviderSuccess(FrozenModel):
    schema_version: Literal[1] = 1
    invocation_id: str = Field(pattern=_INVOCATION_PATTERN)
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    mode: TimingRunMode
    operations: tuple[TimingOperation, ...]
    completed_at: AwareDatetime


class LiveSuccessBaseline(FrozenModel):
    schema_version: Literal[1, 2, 3] = 3
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    mode: TimingRunMode
    operation: TimingOperation
    completed_at: AwareDatetime
    invocation_id: str = Field(pattern=_INVOCATION_PATTERN)
    source: SourceIdentity
    environment: EnvironmentIdentity
    terminal_observation_codes: tuple[str, ...] = ()
    http_summary: HttpAttemptSummary | None = None
    content_assessment: ContentAssessmentEvidence | None = None

    @model_validator(mode="before")
    @classmethod
    def read_legacy_http_field(cls, raw: object) -> object:
        return _normalize_legacy_http_fields(raw, _BASELINE_HTTP_ALIASES)


_SUCCESS_ADAPTER: TypeAdapter[LiveProviderSuccess] = TypeAdapter(LiveProviderSuccess)


def build_source_identity(repository: Path) -> SourceIdentity:
    """Preserve the live-report error contract around shared provenance."""

    try:
        return _build_source_identity(repository)
    except SourceIdentityError as error:
        raise LiveReportPersistenceError(str(error)) from error


def environment_identity(
    *, surface: str, runs: Sequence[TimingRun] = ()
) -> EnvironmentIdentity:
    browser_majors = tuple(
        sorted(
            {
                finished.browser_major
                for run in runs
                if (finished := run.finished) is not None
                and finished.browser_major is not None
            }
        )
    )
    return EnvironmentIdentity(
        python=f"{sys.version_info.major}.{sys.version_info.minor}",
        application=_application_version(),
        browser=(
            "chromium"
            if any(
                run.started.transport
                in {TimingTransport.BROWSER, TimingTransport.MIXED}
                for run in runs
            )
            else None
        ),
        browser_majors=browser_majors,
        surface=surface,
    )


class LiveReportStore:
    """Atomically maintain one invocation report and durable success summaries."""

    def __init__(
        self,
        *,
        report_path: Path,
        baseline_root: Path,
        invocation_id: str,
        mode: TimingRunMode,
        providers: Sequence[str],
        source: SourceIdentity,
        started_at: datetime,
    ) -> None:
        self.report_path = Path(report_path)
        self.baseline_root = Path(baseline_root)
        self.invocation_id = invocation_id
        self.mode = mode
        self.providers = tuple(providers)
        self.source = source
        self.started_at = started_at

    def initialize(self, *, surface: str) -> LiveReport:
        report = LiveReport(
            diagnostic_contract_version=_DIAGNOSTIC_CONTRACT_VERSION,
            invocation_id=self.invocation_id,
            mode=self.mode,
            providers=self.providers,
            started_at=self.started_at,
            outcome=LiveReportOutcome.INCOMPLETE,
            exit_class=LiveExitClass.INCOMPLETE,
            provenance=self.source,
            environment=environment_identity(surface=surface),
        )
        self._write_report(report)
        return report

    def finalize(
        self,
        *,
        outcome: LiveReportOutcome,
        exit_class: LiveExitClass,
        surface: str,
        runs: Sequence[TimingRun] = (),
        trace_root: Path,
        evidence: LiveEvidenceSnapshot | None = None,
        comparisons: Sequence[LastSuccessComparison] = (),
        successful_providers: Iterable[str] = (),
        now: datetime | None = None,
    ) -> LiveReport:
        selected_evidence = evidence or collect_live_evidence(
            trace_root=trace_root,
            runs=runs,
        )
        selected_comparisons = tuple(comparisons)
        successful = frozenset(successful_providers)
        if not successful.issubset(self.providers):
            raise LiveReportPersistenceError(
                "successful provider is outside the live invocation"
            )
        provider_diagnoses = _provider_diagnoses(
            diagnostic_artifacts=selected_evidence.diagnostic_artifacts,
            challenge_resolutions=selected_evidence.challenge_resolutions,
            diagnostic_contract_version=_DIAGNOSTIC_CONTRACT_VERSION,
            providers=self.providers,
            successful_providers=successful,
            operations=selected_evidence.operations,
            attempts=selected_evidence.attempts,
            runtime_by_provider=selected_evidence.runtime_by_provider,
            runtime=selected_evidence.runtime,
            http_attempts=selected_evidence.http_attempts,
            comparisons=selected_comparisons,
            run_failed=outcome is LiveReportOutcome.FAILURE,
        )
        report = LiveReport(
            diagnostic_artifacts=selected_evidence.diagnostic_artifacts,
            challenge_resolutions=selected_evidence.challenge_resolutions,
            diagnostic_contract_version=_DIAGNOSTIC_CONTRACT_VERSION,
            invocation_id=self.invocation_id,
            mode=self.mode,
            providers=self.providers,
            successful_providers=tuple(
                provider for provider in self.providers if provider in successful
            ),
            started_at=self.started_at,
            completed_at=now or datetime.now(UTC),
            outcome=outcome,
            exit_class=exit_class,
            provenance=self.source,
            environment=environment_identity(surface=surface, runs=runs),
            operations=selected_evidence.operations,
            attempts=selected_evidence.attempts,
            hcaptcha_rounds=selected_evidence.hcaptcha_rounds,
            hcaptcha_attempts=selected_evidence.hcaptcha_attempts,
            hcaptcha_checkpoints=selected_evidence.hcaptcha_checkpoints,
            acquisitions=selected_evidence.acquisitions,
            identity_handoffs=selected_evidence.identity_handoffs,
            perimeterx_holds=selected_evidence.perimeterx_holds,
            http_attempts=selected_evidence.http_attempts,
            runtime=selected_evidence.runtime,
            runtime_by_provider=selected_evidence.runtime_by_provider,
            comparisons=selected_comparisons,
            provider_diagnoses=provider_diagnoses,
            diagnosis=_aggregate_provider_diagnoses(
                provider_diagnoses,
                successful_providers=successful,
                run_failed=outcome is LiveReportOutcome.FAILURE,
            ),
            artifacts=_artifact_summary(trace_root, runs),
        )
        self._write_report(report)
        return report

    def compare_and_promote(
        self,
        *,
        runs: Sequence[TimingRun],
        successful_providers: Iterable[str],
        evidence: LiveEvidenceSnapshot,
        surface: str,
        now: datetime | None = None,
    ) -> tuple[LastSuccessComparison, ...]:
        completed_at = now or datetime.now(UTC)
        environment = environment_identity(surface=surface, runs=runs)
        comparisons: list[LastSuccessComparison] = []
        successful = frozenset(successful_providers)
        current_runs = {
            (run.started.provider, run.started.operation): run
            for run in runs
            if run.invocation_id == self.invocation_id
            and run.started.run_mode is self.mode
        }
        terminal_codes = _terminal_codes_by_provider(evidence.attempts)
        complete_providers = {
            provider
            for provider, gaps in self.evidence_gaps(evidence).items()
            if not gaps
        }
        for run in current_runs.values():
            finished = run.finished
            http_summary = _http_summary(
                run.started.provider,
                run.started.operation,
                evidence.http_attempts,
            )
            path = self._baseline_path(run.started.provider, run.started.operation)
            with _exclusive_lock(path.with_suffix(".lock")):
                prior = _read_baseline(path)
                comparisons.append(
                    _comparison(
                        provider=run.started.provider,
                        mode=self.mode,
                        operation=run.started.operation,
                        current=self.source,
                        prior=prior,
                        current_terminal_observation_codes=terminal_codes.get(
                            run.started.provider, ()
                        ),
                        current_http=http_summary,
                        current_content_assessment=(
                            finished.content_assessment
                            if finished is not None
                            else None
                        ),
                    )
                )
                if (
                    run.started.provider not in successful
                    or run.started.provider not in complete_providers
                    or finished is None
                    or finished.outcome is not TimingOutcome.SUCCESS
                ):
                    continue
                baseline = LiveSuccessBaseline(
                    provider=run.started.provider,
                    mode=self.mode,
                    operation=run.started.operation,
                    completed_at=completed_at,
                    invocation_id=self.invocation_id,
                    source=self.source,
                    environment=environment,
                    terminal_observation_codes=terminal_codes.get(
                        run.started.provider, ()
                    ),
                    http_summary=http_summary,
                    content_assessment=finished.content_assessment,
                )
                _atomic_private_write(
                    path,
                    baseline.model_dump_json(indent=2).encode("utf-8") + b"\n",
                )
        return tuple(
            sorted(
                comparisons,
                key=lambda item: (item.provider, item.operation.value),
            )
        )

    def evidence_gaps(
        self,
        evidence: LiveEvidenceSnapshot,
    ) -> dict[str, tuple[EvidenceGap, ...]]:
        """Return provider-scoped completeness gaps for one collected snapshot."""

        runtime_lookup = {item.provider: item for item in evidence.runtime_by_provider}
        return {
            provider: provider_evidence_gaps(
                diagnostic_artifacts=evidence.diagnostic_artifacts,
                diagnostic_contract_version=_DIAGNOSTIC_CONTRACT_VERSION,
                provider=provider,
                operations=tuple(
                    item for item in evidence.operations if item.provider == provider
                ),
                attempts=tuple(
                    item for item in evidence.attempts if item.provider == provider
                ),
                global_runtime=evidence.runtime,
                runtime=runtime_lookup.get(
                    provider,
                    RuntimeProviderEvidence(provider=provider),
                ),
                http_attempts=evidence.http_attempts,
            )
            for provider in self.providers
        }

    def _baseline_path(self, provider: str, operation: TimingOperation) -> Path:
        return (
            self.baseline_root / provider / self.mode.value / f"{operation.value}.json"
        )

    def _write_report(self, report: LiveReport) -> None:
        _atomic_private_write(
            self.report_path,
            report.model_dump_json(indent=2).encode("utf-8") + b"\n",
        )


def record_live_provider_success(
    root: Path,
    *,
    invocation_id: str,
    provider: str,
    mode: TimingRunMode,
    operations: Sequence[TimingOperation],
) -> Path:
    marker = LiveProviderSuccess(
        invocation_id=invocation_id,
        provider=provider,
        mode=mode,
        operations=tuple(operations),
        completed_at=datetime.now(UTC),
    )
    path = Path(root) / f"{provider}.json"
    _atomic_private_write(
        path,
        marker.model_dump_json(indent=2).encode("utf-8") + b"\n",
    )
    return path


def read_live_provider_successes(
    root: Path, *, invocation_id: str, mode: TimingRunMode
) -> tuple[LiveProviderSuccess, ...]:
    successes: list[LiveProviderSuccess] = []
    for path in sorted(Path(root).glob("*.json")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            marker = _SUCCESS_ADAPTER.validate_json(path.read_bytes())
        except (OSError, ValueError):
            continue
        if marker.invocation_id == invocation_id and marker.mode is mode:
            successes.append(marker)
    return tuple(successes)


def _validated_incident(run: TimingRun, trace_root: Path) -> IncidentEvidence | None:
    from .incidents import IncidentPersistenceError, IncidentStore
    from .provenance import BuildIdentity

    incident = run.finished.incident if run.finished is not None else None
    if (
        incident is None
        or incident.incident_id is None
        or (incident.omission is not None and incident.response_role != "primary")
    ):
        return incident
    assert incident.incident_id is not None
    root = trace_root / run.started.provider / "incidents"
    try:
        if root.parent.is_symlink() or root.is_symlink():
            raise ValueError("incident root is unsafe")
        store = IncidentStore(
            root,
            build_identity=BuildIdentity(
                revision=run.started.build_revision,
                dirty=run.started.build_dirty,
                source_fingerprint=run.started.build_source_fingerprint,
                source=run.started.build_identity_source,
                unavailable_reason=run.started.build_identity_unavailable_reason,
            ),
        )
        capsule = store.load(incident.incident_id)
        # A paid probe is a GET captured inside a login operation. Accept only
        # that declared terminal proof, correlated to this exact invocation;
        # unrelated operation captures must still fail closed.
        login_probe = (
            run.started.operation is TimingOperation.LOGIN
            and capsule.operation is TimingOperation.GET
            and run.finished is not None
            and run.finished.failure_stage is MintFailureStage.PAID_PROBE
            and run.finished.failure_category
            in {
                MintFailureCategory.CHALLENGE_BLOCKED,
                MintFailureCategory.ACCOUNT_ALERT,
            }
            and capsule.diagnostic_id == run.records[0].invocation_id
        )
        if (
            capsule.provider != run.started.provider
            or (capsule.operation is not run.started.operation and not login_probe)
            or capsule.build_identity != store.build_identity
            or store.capture_path(capsule) is None
        ):
            raise ValueError("incident does not match operation evidence")
        store.load_context(capsule)
    except (IncidentPersistenceError, OSError, ValueError):
        return incident.model_copy(update={"omission": "invalid_capture"})
    return incident


def _operation_evidence(
    runs: Sequence[TimingRun],
    trace_root: Path,
) -> tuple[LiveOperationEvidence, ...]:
    evidence: list[LiveOperationEvidence] = []
    for run in runs:
        finished = run.finished
        last_step = next(
            (
                record.event.step
                for record in reversed(run.records)
                if isinstance(record.event, StepFinishedEvent)
            ),
            None,
        )
        duration_ns = (
            finished.duration_ns if finished is not None else run.records[-1].elapsed_ns
        )
        assessment_reached = any(
            isinstance(record.event, StepFinishedEvent)
            and record.event.step is TimingStep.ASSESS
            and record.event.outcome is TimingOutcome.SUCCESS
            for record in run.records
        )
        evidence.append(
            LiveOperationEvidence(
                operation_id=run.operation_id,
                acquisition_mode=finished.acquisition_mode
                if finished is not None
                else None,
                provider=run.started.provider,
                mode=run.started.run_mode,
                operation=run.started.operation,
                transport=run.started.transport,
                browser_fallback_attempted=(
                    finished.browser_fallback_attempted if finished else None
                ),
                browser_first=finished.browser_first if finished else None,
                outcome=(
                    finished.outcome.value if finished is not None else "censored"
                ),
                last_step=last_step,
                failure_stage=(
                    finished.failure_stage if finished is not None else None
                ),
                failure_category=(
                    finished.failure_category if finished is not None else None
                ),
                assessment_reached=assessment_reached,
                incident=_validated_incident(run, trace_root),
                content_assessment=(
                    finished.content_assessment if finished is not None else None
                ),
                duration_ms=duration_ns / 1_000_000,
            )
        )
    return tuple(
        sorted(evidence, key=lambda item: (item.provider, item.operation.value))
    )


def _load_runtime_traces(trace_root: Path) -> Iterable[RuntimeTraceEvidence]:
    """Load validated files and retain invalid-input attribution for projection."""
    trace_root = Path(trace_root)
    attempt_ids: set[str] = set()
    for path in sorted(trace_root.rglob("*.jsonl")):
        if path.is_symlink() or not path.is_file():
            continue
        path_provider = _trace_provider(trace_root, path)
        try:
            run = read_runtime_file(path)
            _validate_runtime_run_path(
                run,
                path_provider=path_provider,
                existing_attempt_ids=frozenset(attempt_ids),
            )
        except (OSError, UnicodeError, ValueError):
            yield RuntimeTraceEvidence(path_provider=path_provider, run=None)
            continue
        attempt_ids.update(
            record.event.attempt_id
            for record in run.records
            if isinstance(record.event, AttemptStartedEvent)
        )
        yield RuntimeTraceEvidence(path_provider=path_provider, run=run)


def _validate_runtime_run_path(
    run: RuntimeRun,
    *,
    path_provider: str | None,
    existing_attempt_ids: frozenset[str],
) -> None:
    attempt_providers: dict[str, str] = {}
    for record in run.records:
        runtime_event = record.event
        if isinstance(runtime_event, AttemptStartedEvent):
            if runtime_event.attempt_id in existing_attempt_ids:
                raise ValueError("runtime attempt ID appears in multiple files")
            attempt_providers[runtime_event.attempt_id] = runtime_event.provider
        event_provider = getattr(runtime_event, "provider", None)
        attempt_id = getattr(runtime_event, "attempt_id", None)
        if event_provider is None and isinstance(attempt_id, str):
            event_provider = attempt_providers.get(attempt_id)
        _validate_provider_path(
            path_provider,
            event_provider,
            "runtime event",
        )


def _validate_provider_path(
    path_provider: str | None,
    event_provider: str | None,
    event_name: str,
) -> None:
    if (
        path_provider is not None
        and event_provider is not None
        and path_provider != event_provider
    ):
        raise ValueError(f"{event_name} provider/path mismatch")


def collect_live_evidence(
    trace_root: Path,
    *,
    runs: Sequence[TimingRun] = (),
) -> LiveEvidenceSnapshot:
    """Read one bounded snapshot for gate, comparison, and report decisions."""

    projection = project_runtime_evidence(_load_runtime_traces(trace_root))
    return LiveEvidenceSnapshot(
        diagnostic_artifacts=projection.diagnostic_artifacts,
        challenge_resolutions=projection.challenge_resolutions,
        operations=_operation_evidence(runs, trace_root),
        attempts=projection.attempts,
        hcaptcha_attempts=projection.hcaptcha_attempts,
        hcaptcha_rounds=projection.hcaptcha_rounds,
        hcaptcha_checkpoints=projection.hcaptcha_checkpoints,
        acquisitions=projection.acquisitions,
        identity_handoffs=projection.identity_handoffs,
        perimeterx_holds=projection.perimeterx_holds,
        http_attempts=projection.http_attempts,
        runtime=projection.runtime,
        runtime_by_provider=projection.runtime_by_provider,
    )


def _trace_provider(trace_root: Path, path: Path) -> str | None:
    try:
        relative = path.relative_to(trace_root)
    except ValueError:
        return None
    if len(relative.parts) < 2:
        return None
    provider = relative.parts[0]
    return provider if re.fullmatch(PROVIDER_KEY_PATTERN, provider) else None


def _terminal_codes_by_provider(
    attempts: Sequence[LiveAttemptEvidence],
) -> dict[str, tuple[str, ...]]:
    codes: dict[str, set[str]] = {}
    for attempt in attempts:
        if attempt.terminal_observation_code is not None:
            codes.setdefault(attempt.provider, set()).add(
                attempt.terminal_observation_code
            )
    return {provider: tuple(sorted(values)) for provider, values in codes.items()}


def _provider_diagnoses(
    *,
    diagnostic_artifacts: Sequence[DiagnosticArtifactEvent] = (),
    challenge_resolutions: Sequence[ChallengeResolutionEvent] = (),
    diagnostic_contract_version: int,
    providers: Sequence[str],
    successful_providers: frozenset[str],
    operations: Sequence[LiveOperationEvidence],
    attempts: Sequence[LiveAttemptEvidence],
    runtime: RuntimeEvidence,
    runtime_by_provider: Sequence[RuntimeProviderEvidence],
    http_attempts: Sequence[HttpAttemptEvent],
    comparisons: Sequence[LastSuccessComparison],
    run_failed: bool,
) -> tuple[LiveProviderDiagnosis, ...]:
    runtime_lookup = {item.provider: item for item in runtime_by_provider}
    results: list[LiveProviderDiagnosis] = []
    for provider in providers:
        provider_operations = tuple(
            item for item in operations if item.provider == provider
        )
        provider_attempts = tuple(
            item for item in attempts if item.provider == provider
        )
        provider_http_attempts = tuple(
            item for item in http_attempts if item.provider == provider
        )
        provider_runtime = runtime_lookup.get(
            provider,
            RuntimeProviderEvidence(provider=provider),
        )
        provider_comparisons = tuple(
            item for item in comparisons if item.provider == provider
        )
        missing_evidence = provider_evidence_gaps(
            diagnostic_artifacts=diagnostic_artifacts,
            diagnostic_contract_version=diagnostic_contract_version,
            provider=provider,
            operations=provider_operations,
            attempts=provider_attempts,
            global_runtime=runtime,
            runtime=provider_runtime,
            http_attempts=provider_http_attempts,
        )
        results.append(
            LiveProviderDiagnosis(
                provider=provider,
                evidence_complete=not missing_evidence,
                missing_evidence=missing_evidence,
                diagnosis=classify_live_failure(
                    _diagnostic_facts(
                        challenge_resolutions=challenge_resolutions,
                        operations=provider_operations,
                        attempts=provider_attempts,
                        runtime=provider_runtime,
                        comparisons=provider_comparisons,
                        run_failed=run_failed and provider not in successful_providers,
                        http_attempts=provider_http_attempts,
                    )
                ),
            )
        )
    return tuple(results)


def provider_evidence_gaps(
    *,
    diagnostic_artifacts: Sequence[DiagnosticArtifactEvent] = (),
    diagnostic_contract_version: int,
    provider: str,
    operations: Sequence[LiveOperationEvidence],
    attempts: Sequence[LiveAttemptEvidence],
    global_runtime: RuntimeEvidence,
    runtime: RuntimeProviderEvidence,
    http_attempts: Sequence[HttpAttemptEvent],
) -> tuple[EvidenceGap, ...]:
    gaps: set[EvidenceGap] = set()
    if any(attempt.capture_failure is not None for attempt in attempts):
        gaps.add(EvidenceGap.MISSING_RESPONSE_CAPTURE)
    if diagnostic_contract_version >= 7:
        for operation in operations:
            if operation.outcome == "success":
                continue
            incident = operation.incident
            content = operation.content_assessment
            if (
                incident is not None
                and (
                    incident.omission is not None
                    or incident.capture_failure is not None
                )
            ) or (
                operation.transport is TimingTransport.HTTP
                and content is not None
                and content.access_state is not AccessState.FULL
                and incident is None
            ):
                gaps.add(EvidenceGap.MISSING_RESPONSE_CAPTURE)
    if (
        runtime.event_counts.get("invalid_trace", 0)
        or global_runtime.unattributed_invalid_traces
    ):
        gaps.add(EvidenceGap.INVALID_RUNTIME_TRACE)
    if any(attempt.outcome == "incomplete" for attempt in attempts):
        gaps.add(EvidenceGap.INCOMPLETE_ATTEMPT)
    browser_failure_expected = any(
        operation.outcome != "success"
        and operation.transport in {TimingTransport.BROWSER, TimingTransport.MIXED}
        for operation in operations
    )
    valid_runtime_events = sum(
        count
        for event, count in runtime.event_counts.items()
        if event != "invalid_trace"
    )
    if browser_failure_expected and valid_runtime_events == 0:
        gaps.add(EvidenceGap.MISSING_BROWSER_TRACE)
    if diagnostic_contract_version >= 2:
        diagnostic_loss = any(
            (
                runtime.event_write_failures,
                runtime.screenshot_capture_failures,
                runtime.screenshot_write_failures,
                global_runtime.unattributed_event_write_failures,
                global_runtime.unattributed_screenshot_capture_failures,
                global_runtime.unattributed_screenshot_write_failures,
            )
        )
        if diagnostic_loss:
            gaps.add(EvidenceGap.DIAGNOSTIC_LOSS)
        if provider == "ft" and runtime.event_counts.get(
            "missing_hcaptcha_terminal", 0
        ):
            gaps.add(EvidenceGap.MISSING_HCAPTCHA_TERMINAL)
        expected_roles: set[HttpOperationRole] = set()
        for operation in operations:
            if operation.transport is not TimingTransport.HTTP:
                continue
            if operation.operation is TimingOperation.SEARCH:
                expected_roles.add(HttpOperationRole.SEARCH)
            elif (
                operation.operation
                in {
                    TimingOperation.GET,
                    TimingOperation.SAVE,
                }
                # A standing rot signal skips the HTTP leg by design (R8).
                and not operation.browser_first
            ):
                expected_roles.add(HttpOperationRole.FETCH)
        observed_roles = {
            attempt.role for attempt in http_attempts if attempt.provider == provider
        }
        if not expected_roles.issubset(observed_roles):
            gaps.add(EvidenceGap.MISSING_HTTP_ATTEMPT)
    if diagnostic_contract_version >= 3:
        for operation in operations:
            if operation.operation not in {
                TimingOperation.GET,
                TimingOperation.SAVE,
            }:
                continue
            content = operation.content_assessment
            if operation.assessment_reached and content is None:
                gaps.add(EvidenceGap.MISSING_CONTENT_ASSESSMENT)
                continue
            if (
                content is not None
                and not (
                    content.access_state is AccessState.FULL and content.identity_match
                )
                and content.session_probe is None
            ):
                gaps.add(EvidenceGap.MISSING_SESSION_PROBE)
    if diagnostic_contract_version >= 4 and runtime.event_counts.get(
        "missing_hcaptcha_checkpoint", 0
    ):
        gaps.add(EvidenceGap.MISSING_HCAPTCHA_CHECKPOINT)
    if diagnostic_contract_version >= 6:
        images = tuple(
            artifact
            for artifact in diagnostic_artifacts
            if artifact.provider == provider
            and artifact.kind == "screenshot"
            and (artifact.terminal or artifact.label == "content-snapshot")
            and artifact.path is not None
        )
        failed_operations = tuple(op for op in operations if op.outcome != "success")
        if failed_operations or not operations:
            for attempt in attempts:
                if attempt.outcome in {"error", "timeout", "incomplete"} and not any(
                    image.attempt_id == attempt.attempt_id for image in images
                ):
                    gaps.add(EvidenceGap.MISSING_DECISIVE_IMAGE)
        for operation in failed_operations:
            content = operation.content_assessment
            content_failure = (
                operation.transport in {TimingTransport.BROWSER, TimingTransport.MIXED}
                and content is not None
                and not (
                    content.access_state is AccessState.FULL and content.identity_match
                )
            )
            login_failure = operation.operation is TimingOperation.LOGIN and bool(
                attempts
            )
            if (content_failure or login_failure) and not any(
                operation.operation_id is not None
                and image.operation_id == operation.operation_id
                for image in images
            ):
                gaps.add(EvidenceGap.MISSING_DECISIVE_IMAGE)
    return tuple(sorted(gaps, key=lambda item: item.value))


def _aggregate_provider_diagnoses(
    diagnoses: Sequence[LiveProviderDiagnosis],
    *,
    successful_providers: frozenset[str],
    run_failed: bool,
) -> LiveDiagnosisSummary:
    if not run_failed:
        return classify_live_failure(DiagnosticFacts(run_failed=False))
    failed = tuple(
        item.diagnosis
        for item in diagnoses
        if item.provider not in successful_providers
    )
    if not failed:
        return classify_live_failure(DiagnosticFacts(run_failed=False))
    if all(item == failed[0] for item in failed[1:]):
        return failed[0]
    return LiveDiagnosisSummary(
        diagnosis=LiveDiagnosis.UNKNOWN,
        evidence_strength=EvidenceStrength.INCONCLUSIVE,
        reason_codes=(DiagnosisReason.CONFLICTING_EVIDENCE,),
        repairable=False,
        next_action=DiagnosisAction.INSPECT_CLOSED_EVIDENCE,
    )


def _terminal_http_datadome_defense_observed(
    *,
    operations: Sequence[LiveOperationEvidence],
    attempts: Sequence[LiveAttemptEvidence],
    http_attempts: Sequence[HttpAttemptEvent],
) -> bool:
    terminal_roles: set[tuple[str, HttpOperationRole]] = set()
    for operation in operations:
        if operation.outcome == "success":
            continue
        if (
            operation.operation is TimingOperation.SEARCH
            and operation.last_step is TimingStep.PROVIDER_SEARCH
        ):
            terminal_roles.add((operation.provider, HttpOperationRole.SEARCH))
        elif (
            operation.operation in {TimingOperation.GET, TimingOperation.SAVE}
            and operation.last_step is TimingStep.FETCH
        ):
            terminal_roles.add((operation.provider, HttpOperationRole.FETCH))

    browser_roles: set[tuple[str, HttpOperationRole]] = set()
    for attempt in attempts:
        if attempt.purpose is AttemptPurpose.SEARCH:
            browser_roles.add((attempt.provider, HttpOperationRole.SEARCH))
        elif attempt.purpose is AttemptPurpose.RETRIEVE:
            browser_roles.add((attempt.provider, HttpOperationRole.FETCH))

    return any(
        attempt.status is not None
        and 400 <= attempt.status < 500
        and attempt.datadome_header_present
        and attempt.datadome_cookie_present
        and (attempt.provider, attempt.role) in terminal_roles
        and (attempt.provider, attempt.role) not in browser_roles
        for attempt in http_attempts
    )


def _diagnostic_facts(
    *,
    challenge_resolutions: Sequence[ChallengeResolutionEvent] = (),
    operations: Sequence[LiveOperationEvidence],
    attempts: Sequence[LiveAttemptEvidence],
    runtime: RuntimeEvidence | RuntimeProviderEvidence,
    comparisons: Sequence[LastSuccessComparison],
    run_failed: bool,
    http_attempts: Sequence[HttpAttemptEvent] = (),
) -> DiagnosticFacts:
    failure_categories = tuple(
        sorted(
            {
                operation.failure_category
                for operation in operations
                if operation.failure_category is not None
            },
            key=lambda item: item.value,
        )
    )
    failed_attempts = tuple(
        attempt for attempt in attempts if attempt.outcome is not AttemptOutcome.SUCCESS
    )
    failed_ids = {attempt.attempt_id for attempt in failed_attempts}
    terminal_resolutions = {
        event.attempt_id: event
        for event in challenge_resolutions
        if event.attempt_id in failed_ids
    }
    terminal_observation_codes = {
        attempt.terminal_observation_code
        for attempt in failed_attempts
        if attempt.terminal_observation_code is not None
    }
    observation_codes = tuple(
        sorted(
            terminal_observation_codes
            or {
                code
                for attempt in failed_attempts
                for code in attempt.observation_codes
            }
        )
    )
    comparable_sources = {
        comparison.same_source
        for comparison in comparisons
        if comparison.same_source is not None
    }
    source_changed = (
        True
        if False in comparable_sources
        else False
        if comparable_sources == {True}
        else None
    )

    def content_assessment_regressed(
        comparison: LastSuccessComparison,
    ) -> bool:
        prior = comparison.prior_content_assessment
        current = comparison.current_content_assessment
        return (
            comparison.content_assessment_changed is True
            and prior is not None
            and current is not None
            and prior.access_state is AccessState.FULL
            and prior.identity_match
            and not (
                current.access_state is AccessState.FULL and current.identity_match
            )
        )

    return DiagnosticFacts(
        terminal_datadome_blocked=any(
            event.status is ChallengeResolutionStatus.BLOCKED
            and event.detection.vendor is ChallengeVendor.DATADOME
            for event in terminal_resolutions.values()
        ),
        terminal_cloudflare_blocked=any(
            event.status is ChallengeResolutionStatus.BLOCKED
            and event.detection.vendor
            in {ChallengeVendor.CLOUDFLARE_INTERSTITIAL, ChallengeVendor.TURNSTILE}
            for event in terminal_resolutions.values()
        ),
        observation_codes=observation_codes,
        failure_categories=failure_categories,
        browser_failure_categories=runtime.browser_failure_categories,
        failed_open_challenge_rounds=(
            runtime.failed_open_challenge_rounds if runtime.challenge_blocked else 0
        ),
        http_datadome_defense_observed=_terminal_http_datadome_defense_observed(
            operations=operations,
            attempts=attempts,
            http_attempts=http_attempts,
        ),
        source_changed=source_changed,
        behavior_changed=any(
            operation.outcome != "success" for operation in operations
        ),
        stable_observation_changed=any(
            comparison.stable_observation_changed is True
            or content_assessment_regressed(comparison)
            for comparison in comparisons
        ),
        run_failed=run_failed,
    )


def diagnostic_facts_for_report(
    report: LiveReport,
    *,
    provider: str | None = None,
    reproduced: ReproductionKind | None = None,
) -> DiagnosticFacts:
    """Rebuild closed classifier facts from a validated aggregate report."""

    operations = report.operations
    attempts = report.attempts
    runtime: RuntimeEvidence | RuntimeProviderEvidence = report.runtime
    comparisons = report.comparisons
    http_attempts = report.http_attempts
    run_failed = report.outcome is LiveReportOutcome.FAILURE
    if provider is not None:
        operations = tuple(item for item in operations if item.provider == provider)
        attempts = tuple(item for item in attempts if item.provider == provider)
        comparisons = tuple(item for item in comparisons if item.provider == provider)
        http_attempts = tuple(
            item for item in http_attempts if item.provider == provider
        )
        runtime = next(
            (item for item in report.runtime_by_provider if item.provider == provider),
            report.runtime
            if report.providers == (provider,)
            else RuntimeProviderEvidence(provider=provider),
        )
        run_failed = run_failed and provider not in report.successful_providers
    return _diagnostic_facts(
        challenge_resolutions=report.challenge_resolutions,
        operations=operations,
        attempts=attempts,
        runtime=runtime,
        comparisons=comparisons,
        run_failed=run_failed,
        http_attempts=http_attempts,
    ).model_copy(update={"reproduced": reproduced})


def diagnosis_for_provider(
    report: LiveReport,
    provider: str,
    *,
    reproduced: ReproductionKind | None = None,
) -> LiveDiagnosisSummary:
    """Return one provider's diagnosis, including compatibility with old reports."""

    if reproduced is None:
        existing = next(
            (
                item.diagnosis
                for item in report.provider_diagnoses
                if item.provider == provider
            ),
            None,
        )
        if existing is not None:
            return existing
    return classify_live_failure(
        diagnostic_facts_for_report(
            report,
            provider=provider,
            reproduced=reproduced,
        )
    )


def _artifact_summary(trace_root: Path, runs: Sequence[TimingRun]) -> ArtifactSummary:
    trace_root = Path(trace_root)
    runtime_files = tuple(
        path
        for path in trace_root.rglob("*.jsonl")
        if path.is_file() and not path.is_symlink()
    )
    screenshots = tuple(
        path
        for path in trace_root.rglob("*.png")
        if path.is_file() and not path.is_symlink()
    )
    instructions = tuple(
        path
        for path in trace_root.rglob("*.txt")
        if path.is_file() and not path.is_symlink() and ".hc-" in path.name
    )
    incidents = tuple(
        path
        for name in ("incident.json", "context.json", "capture.html")
        for path in trace_root.glob(f"*/incidents/incident-*/{name}")
        if path.is_file()
        and not any(parent.is_symlink() for parent in (path, *path.parents))
    )
    references = tuple(
        sorted(
            {
                relative.as_posix()
                for path in (*runtime_files, *screenshots, *instructions, *incidents)
                if _safe_artifact_reference(relative := path.relative_to(trace_root))
            }
        )
    )
    return ArtifactSummary(
        timing_files=len({run.path for run in runs}),
        runtime_files=len(runtime_files),
        screenshots=len(screenshots),
        references=references,
    )


def _http_summary(
    provider: str,
    operation: TimingOperation,
    attempts: Sequence[HttpAttemptEvent],
) -> HttpAttemptSummary | None:
    role = {
        TimingOperation.LOGIN: HttpOperationRole.VERIFICATION,
        TimingOperation.SEARCH: HttpOperationRole.SEARCH,
        TimingOperation.GET: HttpOperationRole.FETCH,
        TimingOperation.SAVE: HttpOperationRole.FETCH,
    }[operation]
    selected = tuple(
        attempt
        for attempt in attempts
        if attempt.provider == provider and attempt.role is role
    )
    if not selected:
        return None
    return HttpAttemptSummary(
        attempt_count=len(selected),
        shared_affinity_attempts=sum(
            attempt.route_mode is HttpRouteMode.SHARED_AFFINITY for attempt in selected
        ),
        overflow_ephemeral_attempts=sum(
            attempt.route_mode is HttpRouteMode.OVERFLOW_EPHEMERAL
            for attempt in selected
        ),
        authenticated_affinity_attempts=sum(
            attempt.route_mode is HttpRouteMode.AUTHENTICATED_AFFINITY
            for attempt in selected
        ),
        contention_attempts=sum(attempt.contention for attempt in selected),
        statuses=tuple(
            sorted(attempt.status for attempt in selected if attempt.status is not None)
        ),
        retry_reasons=tuple(
            sorted(
                (attempt.retry_reason for attempt in selected),
                key=lambda item: item.value,
            )
        ),
        transport_failures=tuple(
            sorted(
                (
                    attempt.transport_failure
                    for attempt in selected
                    if attempt.transport_failure is not None
                ),
                key=lambda item: item.value,
            )
        ),
        datadome_header_observed=any(
            attempt.datadome_header_present for attempt in selected
        ),
        datadome_cookie_observed=any(
            attempt.datadome_cookie_present for attempt in selected
        ),
    )


def _comparison(
    *,
    provider: str,
    mode: TimingRunMode,
    operation: TimingOperation,
    current: SourceIdentity,
    prior: LiveSuccessBaseline | None,
    current_terminal_observation_codes: tuple[str, ...] = (),
    current_http: HttpAttemptSummary | None = None,
    current_content_assessment: ContentAssessmentEvidence | None = None,
) -> LastSuccessComparison:
    if prior is None:
        return LastSuccessComparison(
            provider=provider,
            mode=mode,
            operation=operation,
            current_terminal_observation_codes=current_terminal_observation_codes,
            current_http=current_http,
            current_content_assessment=current_content_assessment,
        )
    current_paths = {entry.path: entry.sha256 for entry in current.source_manifest}
    prior_paths = {entry.path: entry.sha256 for entry in prior.source.source_manifest}
    changed = tuple(
        sorted(
            path
            for path in current_paths.keys() | prior_paths.keys()
            if current_paths.get(path) != prior_paths.get(path)
        )
    )
    return LastSuccessComparison(
        provider=provider,
        mode=mode,
        operation=operation,
        prior_invocation_id=prior.invocation_id,
        same_source=current.source_fingerprint == prior.source.source_fingerprint,
        changed_paths=changed,
        prior_terminal_observation_codes=prior.terminal_observation_codes,
        current_terminal_observation_codes=current_terminal_observation_codes,
        stable_observation_changed=(
            current_terminal_observation_codes != prior.terminal_observation_codes
            if current_terminal_observation_codes and prior.terminal_observation_codes
            else None
        ),
        prior_http=prior.http_summary,
        current_http=current_http,
        http_changed=(
            current_http != prior.http_summary
            if current_http is not None and prior.http_summary is not None
            else None
        ),
        prior_content_assessment=prior.content_assessment,
        current_content_assessment=current_content_assessment,
        content_assessment_changed=(
            current_content_assessment != prior.content_assessment
            if current_content_assessment is not None
            and prior.content_assessment is not None
            else None
        ),
    )


def _read_baseline(path: Path) -> LiveSuccessBaseline | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        payload = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    # Normalize before validating so an alias conflict stays distinguishable:
    # pydantic would fold it into a ValidationError that is indistinguishable
    # from ordinary schema drift, and a swallowed conflict is what previously
    # degraded a conflicted baseline to "no baseline".
    try:
        normalized = _normalize_legacy_http_fields(payload, _BASELINE_HTTP_ALIASES)
    except ValueError as error:
        raise LiveReportPersistenceError(
            "live baseline has conflicting legacy and current HTTP fields"
        ) from error
    try:
        return LiveSuccessBaseline.model_validate(normalized)
    except ValueError:
        return None


def _safe_artifact_reference(path: Path) -> bool:
    return all(_ARTIFACT_PART.fullmatch(part) for part in path.parts)


@contextmanager
def _exclusive_lock(path: Path):
    _ensure_private_directory(path.parent)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + 2.0
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise LiveReportPersistenceError(
                        "live baseline lock is busy"
                    ) from None
                time.sleep(0.05)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise LiveReportPersistenceError("live baseline lock failed") from error
    assert descriptor is not None
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_private_write(path: Path, payload: bytes) -> None:
    _ensure_private_directory(path.parent)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise LiveReportPersistenceError(
            "private live evidence write failed"
        ) from error


def _ensure_private_directory(path: Path) -> None:
    try:
        missing: list[Path] = []
        candidate = path
        while not candidate.exists():
            missing.append(candidate)
            candidate = candidate.parent
        if candidate.is_symlink():
            raise OSError("private live evidence directory is invalid")
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        if path.is_symlink() or not path.is_dir():
            raise OSError("private live evidence directory is invalid")
        os.chmod(path, 0o700)
    except OSError as error:
        raise LiveReportPersistenceError(
            "private live evidence directory is unavailable"
        ) from error
