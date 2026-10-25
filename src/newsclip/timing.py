"""Closed, best-effort timing evidence for product operations."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext, suppress
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import AwareDatetime, Field, TypeAdapter, field_validator, model_validator

from .acquisition import (
    AcquisitionMode,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from .models import (
    INCIDENT_ID_PATTERN,
    AccessState,
    ArticleAssessment,
    CaptureFailure,
    FrozenModel,
    RecoveryStatus,
    SessionVerification,
)
from .provenance import (
    BuildIdentity,
    BuildIdentitySource,
    BuildIdentityUnavailableReason,
    legacy_build_identity,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_IDENTIFIER = re.compile(_IDENTIFIER_PATTERN)
_DEFAULT_RETENTION = 200
_ABANDONED_TRACE_SECONDS = 24 * 3600


def _application_version() -> str:
    from . import __version__

    return __version__


class TimingOperation(StrEnum):
    LOGIN = "login"
    SEARCH = "search"
    GET = "get"
    SAVE = "save"


class TimingStep(StrEnum):
    SESSION_LOAD = "session_load"
    SESSION_ACQUIRE = "session_acquire"
    PROVIDER_SEARCH = "provider_search"
    FETCH = "fetch"
    EXTRACT = "extract"
    ASSESS = "assess"
    BUILD_ARTICLE = "build_article"
    ARCHIVE = "archive"
    EXPORT = "export"
    ARTIFACT_VERIFY = "artifact_verify"
    ATTEMPT_LEASE_WAIT = "attempt_lease_wait"
    PROFILE_LEASE_WAIT = "profile_lease_wait"
    BROWSER_OPEN = "browser_open"
    BROWSER_CLOSE = "browser_close"
    PROFILE_REHYDRATE = "profile_rehydrate"
    CREDENTIAL_FLOW = "credential_flow"
    SESSION_VERIFY = "session_verify"
    SESSION_PERSIST = "session_persist"
    LOGIN_FRONTDOOR = "login_frontdoor"
    USERNAME = "username"
    PASSWORD = "password"
    SECOND_FACTOR = "second_factor"
    SECRET_RESOLVE = "secret_resolve"
    CREDENTIAL_APPLY = "credential_apply"
    IDENTITY_FLOW = "identity_flow"
    PROVIDER_TRANSITION_WAIT = "provider_transition_wait"
    CHALLENGE = "challenge"
    CALLBACK = "callback"
    PAID_PROBE = "paid_probe"
    COOKIE_EXPORT = "cookie_export"
    BROWSER_WARMUP = "browser_warmup"
    ARTICLE_NAVIGATION = "article_navigation"
    #: A verification-role navigation (session probe, paid proof), kept apart
    #: so it is not read as a second article navigation attempt.
    VERIFICATION_NAVIGATION = "verification_navigation"
    CONTENT_READ = "content_read"


class TimingOutcome(StrEnum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


class TimingTransport(StrEnum):
    HTTP = "http"
    BROWSER = "browser"
    MIXED = "mixed"


class TimingRunMode(StrEnum):
    PRODUCT = "product"
    WARM = "warm"
    COLD = "cold"


class TimingSurface(StrEnum):
    NONE = "none"
    MANAGED_VIRTUAL = "managed_virtual"
    HOST_XVFB = "host_xvfb"
    DOCKER_XVFB_BWRAP = "docker_xvfb_bwrap"
    UNKNOWN_VIRTUAL = "unknown_virtual"


class AssessmentReasonCode(StrEnum):
    """Approved content and verification reasons safe for durable evidence."""

    ARTICLE_IDENTITY_MISMATCH = "article_identity_mismatch"
    ACCOUNT_ALERT = "account_alert"
    AUTHENTICATION_REQUIRED = "authentication_required"
    FULL_ARTICLE_VERIFIED = "full_article_verified"
    HTTP_CLIENT_ERROR = "http_client_error"
    HTTP_ERROR = "http_error"
    HTTP_FORBIDDEN = "http_forbidden"
    HTTP_RATE_LIMITED = "http_rate_limited"
    HTTP_REDIRECT_ERROR = "http_redirect_error"
    HTTP_SERVER_ERROR = "http_server_error"
    HTTP_UNAUTHORIZED = "http_unauthorized"
    INSUFFICIENT_ARTICLE_STRUCTURE = "insufficient_article_structure"
    INTERACTIVE_CHALLENGE = "interactive_challenge"
    INVALID_HTML = "invalid_html"
    PAYWALL_TEASER = "paywall_teaser"
    UNAVAILABLE = "unavailable"
    VERIFICATION_BODY_TOO_SHORT = "verification_body_too_short"


def _closed_reason(reason: object) -> AssessmentReasonCode:
    """Map arbitrary provider detail to one approved durable reason."""

    if not isinstance(reason, str):
        return AssessmentReasonCode.UNAVAILABLE
    try:
        return AssessmentReasonCode(reason)
    except ValueError:
        return AssessmentReasonCode.UNAVAILABLE


class SessionProbeOutcome(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    VERIFIED = "verified"
    SESSION_DEAD = "session_dead"
    INCONCLUSIVE = "inconclusive"
    TRANSPORT_ERROR = "transport_error"
    #: No probe ran: the same session generation verified in this process
    #: within the reuse window, which already classifies a teaser.
    REUSED_VERIFIED = "reused_verified"


class SessionProbeEvidence(FrozenModel):
    outcome: SessionProbeOutcome
    access_state: AccessState | None = None
    reason: AssessmentReasonCode | None = None
    failure_reason: Literal["authority_changed", "transport_error"] | None = None

    @field_validator("reason", mode="before")
    @classmethod
    def close_reason(cls, reason: object) -> AssessmentReasonCode | None:
        return None if reason is None else _closed_reason(reason)

    @model_validator(mode="after")
    def validate_observation(self) -> SessionProbeEvidence:
        if (
            self.failure_reason is not None
            and self.outcome is not SessionProbeOutcome.TRANSPORT_ERROR
        ):
            raise ValueError("session probe failure reason requires a transport error")
        if (self.access_state is None) != (self.reason is None):
            raise ValueError("session probe observation fields are incomplete")
        observed = self.outcome in {
            SessionProbeOutcome.VERIFIED,
            SessionProbeOutcome.SESSION_DEAD,
            SessionProbeOutcome.INCONCLUSIVE,
        }
        if observed != (self.access_state is not None):
            raise ValueError("session probe observation is incomplete")
        return self


class ContentAssessmentEvidence(FrozenModel):
    access_state: AccessState
    reason: AssessmentReasonCode
    identity_match: bool
    word_count: int = Field(ge=0)
    session_cookie_present: bool
    session_probe: SessionProbeEvidence | None = None

    @field_validator("reason", mode="before")
    @classmethod
    def close_reason(cls, reason: object) -> AssessmentReasonCode:
        return _closed_reason(reason)

    @model_validator(mode="after")
    def validate_probe(self) -> ContentAssessmentEvidence:
        if (
            self.access_state is AccessState.FULL
            and self.identity_match
            and self.session_probe is not None
        ):
            raise ValueError(
                "promotable target assessment cannot carry a session probe"
            )
        return self


class OperationStartedEvent(FrozenModel):
    event: Literal["operation_started"] = "operation_started"
    operation: TimingOperation
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    run_mode: TimingRunMode
    transport: TimingTransport
    app_version: str = Field(min_length=1, max_length=32, pattern=r"^[0-9A-Za-z.+-]+$")
    build_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")
    build_dirty: bool | None = None
    build_source_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    build_identity_source: BuildIdentitySource = BuildIdentitySource.LEGACY
    build_identity_unavailable_reason: BuildIdentityUnavailableReason | None = (
        BuildIdentityUnavailableReason.LEGACY_RECORD
    )
    surface: TimingSurface

    @model_validator(mode="after")
    def validate_build_identity(self) -> OperationStartedEvent:
        BuildIdentity(
            revision=self.build_revision,
            dirty=self.build_dirty,
            source_fingerprint=self.build_source_fingerprint,
            source=self.build_identity_source,
            unavailable_reason=self.build_identity_unavailable_reason,
        )
        return self


class StepStartedEvent(FrozenModel):
    event: Literal["step_started"] = "step_started"
    step_id: int = Field(ge=1)
    parent_step_id: int | None = Field(default=None, ge=1)
    step: TimingStep
    attempt: int = Field(ge=1)
    provider: str | None = Field(default=None, pattern=PROVIDER_KEY_PATTERN)


class StepFinishedEvent(FrozenModel):
    event: Literal["step_finished"] = "step_finished"
    step_id: int = Field(ge=1)
    step: TimingStep
    attempt: int = Field(ge=1)
    outcome: TimingOutcome
    duration_ns: int = Field(ge=0)


class IncidentEvidence(FrozenModel):
    """Closed reference to private response evidence; never contains page data."""

    incident_id: str | None = Field(default=None, pattern=INCIDENT_ID_PATTERN)
    response_role: Literal["primary", "terminal", "unknown"] = "unknown"
    capture_failure: CaptureFailure | None = None
    omission: (
        Literal[
            "not_configured", "write_failed", "capture_too_large", "invalid_capture"
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def require_reference(self) -> IncidentEvidence:
        if (
            self.incident_id is None
            and self.omission is None
            and self.capture_failure is None
        ):
            raise ValueError(
                "incident evidence requires a reference, omission, or capture failure"
            )
        return self


class RecoveryHandoffEvidence(FrozenModel):
    request_id: str | None = Field(default=None, pattern=r"^recovery-[a-f0-9]{32}$")
    status: RecoveryStatus | None = None
    omission: Literal["handoff_failed", "resolution_failed"] | None = None

    @model_validator(mode="after")
    def require_reference_or_omission(self) -> RecoveryHandoffEvidence:
        if self.request_id is None:
            if self.omission is None or self.status is not None:
                raise ValueError("recovery handoff needs evidence or an omission")
        elif self.status is None or self.omission is not None:
            raise ValueError("recovery reference needs its stored status")
        return self


class OperationFinishedEvent(FrozenModel):
    event: Literal["operation_finished"] = "operation_finished"
    operation: TimingOperation
    outcome: TimingOutcome
    duration_ns: int = Field(ge=0)
    acquisition_mode: AcquisitionMode | None = None
    failure_stage: MintFailureStage | None = None
    failure_category: MintFailureCategory | None = None
    browser_major: int | None = Field(default=None, ge=1, le=999)
    content_assessment: ContentAssessmentEvidence | None = None
    incident: IncidentEvidence | None = None
    browser_fallback_attempted: bool | None = None
    #: The HTTP leg was skipped on purpose because a standing R8 rot signal
    #: sends reads straight to the browser. Distinguishes "no HTTP attempt by
    #: design" from a lost HTTP attempt trace.
    browser_first: bool | None = None
    recovery: RecoveryHandoffEvidence | None = None

    @model_validator(mode="after")
    def validate_failure(self) -> OperationFinishedEvent:
        if (self.failure_stage is None) != (self.failure_category is None):
            raise ValueError("timing failure stage and category must appear together")
        if self.outcome is TimingOutcome.SUCCESS and self.failure_stage is not None:
            raise ValueError(
                "successful timing operation cannot carry failure evidence"
            )
        if self.content_assessment is not None and self.operation not in {
            TimingOperation.GET,
            TimingOperation.SAVE,
        }:
            raise ValueError(
                "content assessment belongs only to get or save operations"
            )
        return self


TimingEvent = Annotated[
    OperationStartedEvent
    | StepStartedEvent
    | StepFinishedEvent
    | OperationFinishedEvent,
    Field(discriminator="event"),
]


class TimingRecord(FrozenModel):
    schema_version: Literal[1] = 1
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    invocation_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    sequence: int = Field(ge=1)
    occurred_at: AwareDatetime
    elapsed_ns: int = Field(ge=0)
    event: TimingEvent


_RECORD_ADAPTER: TypeAdapter[TimingRecord] = TypeAdapter(TimingRecord)


class TimingRun(FrozenModel):
    """One validated timing trace reconstructed from a JSONL file."""

    path: Path
    records: tuple[TimingRecord, ...]

    @model_validator(mode="after")
    def validate_sequence(self) -> TimingRun:
        if not self.records:
            raise ValueError("timing run must contain at least one record")
        first = self.records[0]
        if not isinstance(first.event, OperationStartedEvent):
            raise ValueError("timing run must start with operation_started")
        if [record.sequence for record in self.records] != list(
            range(1, len(self.records) + 1)
        ):
            raise ValueError("timing record sequence is not contiguous")
        if any(
            record.operation_id != first.operation_id
            or record.invocation_id != first.invocation_id
            for record in self.records
        ):
            raise ValueError("timing run correlation changed within one file")
        if any(
            later.elapsed_ns < earlier.elapsed_ns
            for earlier, later in zip(self.records, self.records[1:], strict=False)
        ):
            raise ValueError("timing elapsed time moved backwards")
        active: dict[int, tuple[StepStartedEvent, int]] = {}
        seen_step_ids: set[int] = set()
        attempts: Counter[tuple[TimingStep, str | None]] = Counter()
        for index, record in enumerate(self.records[1:], start=1):
            event = record.event
            if isinstance(event, OperationStartedEvent):
                raise ValueError("timing run contains multiple operation starts")
            if isinstance(event, StepStartedEvent):
                if event.step_id in seen_step_ids:
                    raise ValueError("timing step ID was reused")
                if (
                    event.parent_step_id is not None
                    and event.parent_step_id not in active
                ):
                    raise ValueError("timing parent step is not active")
                attempt_key = (event.step, event.provider)
                attempts[attempt_key] += 1
                if event.attempt != attempts[attempt_key]:
                    raise ValueError("timing step attempt is not contiguous")
                seen_step_ids.add(event.step_id)
                active[event.step_id] = (event, record.elapsed_ns)
                continue
            if isinstance(event, StepFinishedEvent):
                started = active.pop(event.step_id, None)
                if started is None:
                    raise ValueError("timing step finished without a start")
                start_event, start_elapsed_ns = started
                if (
                    event.step is not start_event.step
                    or event.attempt != start_event.attempt
                    or event.duration_ns != record.elapsed_ns - start_elapsed_ns
                ):
                    raise ValueError("timing step finish does not match its start")
                continue
            if index != len(self.records) - 1:
                raise ValueError("operation_finished must be the final record")
            if event.operation is not first.event.operation:
                raise ValueError("timing operation changed within one file")
            if event.duration_ns != record.elapsed_ns:
                raise ValueError("operation duration does not match elapsed time")
            if active:
                raise ValueError("finished timing operation has active steps")
        return self

    @property
    def operation_id(self) -> str:
        return self.records[0].operation_id

    @property
    def invocation_id(self) -> str | None:
        return self.records[0].invocation_id

    @property
    def started(self) -> OperationStartedEvent:
        event = self.records[0].event
        assert isinstance(event, OperationStartedEvent)
        return event

    @property
    def finished(self) -> OperationFinishedEvent | None:
        event = self.records[-1].event
        return event if isinstance(event, OperationFinishedEvent) else None

    @property
    def active_steps(self) -> tuple[StepStartedEvent, ...]:
        active: dict[int, StepStartedEvent] = {}
        for record in self.records:
            event = record.event
            if isinstance(event, StepStartedEvent):
                active[event.step_id] = event
            elif isinstance(event, StepFinishedEvent):
                active.pop(event.step_id, None)
        return tuple(active.values())


class TimingRecorder:
    """Create lazy private traces without making telemetry a product dependency."""

    def __init__(
        self,
        root: Path,
        *,
        invocation_id: str | None = None,
        run_mode: TimingRunMode = TimingRunMode.PRODUCT,
        retention: int = _DEFAULT_RETENTION,
        build_revision: str | None = None,
        build_dirty: bool | None = None,
        build_identity: BuildIdentity | None = None,
        surface: TimingSurface | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        utc_now: Callable[[], datetime] | None = None,
    ) -> None:
        if retention < 1:
            raise ValueError("timing retention must be positive")
        resolved_invocation = invocation_id or os.environ.get("NEWSCLIP_INVOCATION_ID")
        if resolved_invocation is not None and not _IDENTIFIER.fullmatch(
            resolved_invocation
        ):
            resolved_invocation = None
        self.root = Path(root)
        self.invocation_id = resolved_invocation
        self.run_mode = run_mode
        self.retention = retention
        raw_revision = build_revision or os.environ.get("NEWSCLIP_BUILD_REVISION")
        legacy_revision = (
            raw_revision
            if raw_revision is not None
            and re.fullmatch(r"[0-9a-f]{7,64}", raw_revision)
            else None
        )
        selected_identity = build_identity or legacy_build_identity(
            legacy_revision,
            build_dirty if build_dirty is not None else _environment_dirty(),
        )
        self.build_revision = selected_identity.revision
        self.build_dirty = selected_identity.dirty
        self.build_source_fingerprint = selected_identity.source_fingerprint
        self.build_identity_source = selected_identity.source
        self.build_identity_unavailable_reason = selected_identity.unavailable_reason
        self.surface = surface or _environment_surface()
        self._monotonic_ns = monotonic_ns
        self._utc_now = utc_now or (lambda: datetime.now(UTC))

    def operation(
        self,
        operation: TimingOperation,
        *,
        provider: str,
        transport: TimingTransport,
    ) -> TimingOperationContext:
        if not is_provider_key(provider):
            raise ValueError("invalid timing provider key")
        return TimingOperationContext(
            recorder=self,
            operation=operation,
            provider=provider,
            transport=transport,
        )


class _OperationState:
    def __init__(
        self,
        *,
        recorder: TimingRecorder,
        operation: TimingOperation,
        provider: str,
        transport: TimingTransport,
    ) -> None:
        self.recorder = recorder
        self.operation = operation
        self.provider = provider
        self.transport = transport
        self.operation_id = f"op-{uuid4().hex}"
        self.started_ns = 0
        self.path: Path | None = None
        self.sequence = 0
        self.next_step_id = 0
        self.attempts: Counter[tuple[TimingStep, str | None]] = Counter()
        self.acquisition_mode: AcquisitionMode | None = None
        self.failure: MintFailureEvidence | None = None
        self.browser_major: int | None = None
        self.content_assessment: ContentAssessmentEvidence | None = None
        self.incident: IncidentEvidence | None = None
        self.browser_fallback_attempted = False
        self.browser_first = False
        self.recovery: RecoveryHandoffEvidence | None = None
        self.invocation_id = _ACTIVE_INVOCATION.get() or recorder.invocation_id
        self.write_failed = False
        self.lock = threading.Lock()
        self.trace_descriptor: int | None = None

    def start(self) -> None:
        timestamp = self.recorder._utc_now().strftime("%Y%m%dT%H%M%S.%fZ")
        directory = self.recorder.root / self.operation.value / self.provider
        self.path = directory / f"{timestamp}-{self.operation_id}.jsonl"
        self._open_trace()
        with self.lock:
            self.started_ns = self.recorder._monotonic_ns()
            self._write_locked(
                OperationStartedEvent(
                    operation=self.operation,
                    provider=self.provider,
                    run_mode=self.recorder.run_mode,
                    transport=self.transport,
                    app_version=_application_version(),
                    build_revision=self.recorder.build_revision,
                    build_dirty=self.recorder.build_dirty,
                    build_source_fingerprint=(self.recorder.build_source_fingerprint),
                    build_identity_source=self.recorder.build_identity_source,
                    build_identity_unavailable_reason=(
                        self.recorder.build_identity_unavailable_reason
                    ),
                    surface=self.recorder.surface,
                ),
                now_ns=self.started_ns,
            )
        self._prune(directory)

    def finish(self, outcome: TimingOutcome) -> None:
        try:
            try:
                with self.lock:
                    if (
                        self.failure is not None
                        and self.failure.category is MintFailureCategory.TIMEOUT
                    ):
                        outcome = TimingOutcome.TIMEOUT
                    now_ns = self.recorder._monotonic_ns()
                    self._write_locked(
                        OperationFinishedEvent(
                            operation=self.operation,
                            outcome=outcome,
                            duration_ns=now_ns - self.started_ns,
                            acquisition_mode=self.acquisition_mode,
                            failure_stage=(
                                self.failure.stage
                                if outcome is not TimingOutcome.SUCCESS and self.failure
                                else None
                            ),
                            failure_category=(
                                self.failure.category
                                if outcome is not TimingOutcome.SUCCESS and self.failure
                                else None
                            ),
                            browser_major=self.browser_major,
                            content_assessment=self.content_assessment,
                            incident=self.incident,
                            browser_fallback_attempted=self.browser_fallback_attempted,
                            # Only when true: ordinary records stay unchanged.
                            browser_first=self.browser_first or None,
                            recovery=self.recovery,
                        ),
                        now_ns=now_ns,
                    )
            except Exception:
                self.write_failed = True
        finally:
            self._close_trace()

    def begin_step(
        self,
        step: TimingStep,
        provider: str | None,
        parent_step_id: int | None,
    ) -> tuple[int, int, int]:
        if provider is not None and not is_provider_key(provider):
            raise ValueError("invalid timing provider key")
        with self.lock:
            self.next_step_id += 1
            step_id = self.next_step_id
            key = (step, provider)
            self.attempts[key] += 1
            attempt = self.attempts[key]
            started_ns = self.recorder._monotonic_ns()
            self._write_locked(
                StepStartedEvent(
                    step_id=step_id,
                    parent_step_id=parent_step_id,
                    step=step,
                    attempt=attempt,
                    provider=provider,
                ),
                now_ns=started_ns,
            )
        return step_id, attempt, started_ns

    def finish_step(
        self,
        *,
        step_id: int,
        step: TimingStep,
        attempt: int,
        started_ns: int,
        outcome: TimingOutcome,
    ) -> None:
        with self.lock:
            now_ns = self.recorder._monotonic_ns()
            self._write_locked(
                StepFinishedEvent(
                    step_id=step_id,
                    step=step,
                    attempt=attempt,
                    outcome=outcome,
                    duration_ns=now_ns - started_ns,
                ),
                now_ns=now_ns,
            )

    def _write_locked(self, event: TimingEvent, *, now_ns: int) -> None:
        """Write one event while ``self.lock`` establishes timeline order."""

        descriptor = self.trace_descriptor
        if self.write_failed or self.path is None or descriptor is None:
            return
        try:
            sequence = self.sequence + 1
            record = TimingRecord(
                operation_id=self.operation_id,
                invocation_id=self.invocation_id,
                sequence=sequence,
                occurred_at=self.recorder._utc_now(),
                elapsed_ns=now_ns - self.started_ns,
                event=event,
            )
            encoded = (
                json.dumps(
                    record.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("timing trace write made no progress")
                view = view[written:]
        except Exception:
            self.write_failed = True
            return
        self.sequence = sequence

    def _open_trace(self) -> None:
        assert self.path is not None
        descriptor: int | None = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
            descriptor = os.open(
                self.path,
                os.O_APPEND
                | os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("timing trace target is not a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            self.write_failed = True
            return
        self.trace_descriptor = descriptor

    def _close_trace(self) -> None:
        descriptor = self.trace_descriptor
        if descriptor is None:
            return
        self.trace_descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            self.write_failed = True
        try:
            os.close(descriptor)
        except OSError:
            self.write_failed = True

    def _prune(self, directory: Path) -> None:
        if self.write_failed:
            return
        try:
            paths = sorted(directory.glob("*.jsonl"), reverse=True)
            for path in paths[self.recorder.retention :]:
                self._prune_trace(path)
        except OSError:
            self.write_failed = True

    @staticmethod
    def _prune_trace(path: Path) -> None:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return
        acquired = False
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("timing trace target is not a regular file")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                return
            # The writer holds the lock for its whole operation, so a free
            # lock on an unfinished trace means its process died. Keep it a
            # day for the interrupted-run story, then let the cap reclaim it.
            if _timing_trace_finished(path) or (
                time.time() - os.fstat(descriptor).st_mtime > _ABANDONED_TRACE_SECONDS
            ):
                path.unlink(missing_ok=True)
        finally:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _timing_trace_finished(path: Path) -> bool:
    try:
        return read_timing_file(path).finished is not None
    except (OSError, UnicodeError, ValueError):
        return False


_ACTIVE_OPERATION: ContextVar[_OperationState | None] = ContextVar(
    "newsclip_active_timing_operation", default=None
)
_ACTIVE_INVOCATION: ContextVar[str | None] = ContextVar(
    "newsclip_timing_invocation", default=None
)
_ACTIVE_STEP_STACK: ContextVar[tuple[int, ...]] = ContextVar(
    "newsclip_active_timing_steps", default=()
)


def current_timing_operation_id() -> str | None:
    """Correlate private acquisition evidence without depending on a trace file."""
    state = _ACTIVE_OPERATION.get()
    return state.operation_id if state is not None else None


class TimingOperationContext(AbstractContextManager["TimingOperationContext"]):
    def __init__(
        self,
        *,
        recorder: TimingRecorder,
        operation: TimingOperation,
        provider: str,
        transport: TimingTransport,
    ) -> None:
        self._state = _OperationState(
            recorder=recorder,
            operation=operation,
            provider=provider,
            transport=transport,
        )
        self._operation_token: Token[_OperationState | None] | None = None
        self._step_token: Token[tuple[int, ...]] | None = None
        self._entered = False

    @property
    def operation_id(self) -> str:
        return self._state.operation_id

    @property
    def path(self) -> Path | None:
        return self._state.path

    @property
    def write_failed(self) -> bool:
        return self._state.write_failed

    def __enter__(self) -> TimingOperationContext:
        if self._entered:
            raise RuntimeError("timing operation contexts cannot be reused")
        self._entered = True
        self._state.start()
        self._operation_token = _ACTIVE_OPERATION.set(self._state)
        self._step_token = _ACTIVE_STEP_STACK.set(())
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            self._state.finish(_outcome(exc_value))
        finally:
            assert self._step_token is not None
            assert self._operation_token is not None
            _ACTIVE_STEP_STACK.reset(self._step_token)
            _ACTIVE_OPERATION.reset(self._operation_token)
        return None


class _TimingStepContext(AbstractContextManager[None]):
    def __init__(
        self,
        state: _OperationState,
        step: TimingStep,
        provider: str | None,
    ) -> None:
        self._state = state
        self._step = step
        self._provider = provider
        self._step_id = 0
        self._attempt = 0
        self._started_ns = 0
        self._stack_token: Token[tuple[int, ...]] | None = None

    def __enter__(self) -> None:
        stack = _ACTIVE_STEP_STACK.get()
        parent_step_id = stack[-1] if stack else None
        self._step_id, self._attempt, self._started_ns = self._state.begin_step(
            self._step,
            self._provider,
            parent_step_id,
        )
        self._stack_token = _ACTIVE_STEP_STACK.set((*stack, self._step_id))
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            self._state.finish_step(
                step_id=self._step_id,
                step=self._step,
                attempt=self._attempt,
                started_ns=self._started_ns,
                outcome=_outcome(exc_value),
            )
        finally:
            assert self._stack_token is not None
            _ACTIVE_STEP_STACK.reset(self._stack_token)
        return None


def timing_step(
    step: TimingStep,
    *,
    provider: str | None = None,
) -> AbstractContextManager[None]:
    """Time a closed step when called inside an active product operation."""

    state = _ACTIVE_OPERATION.get()
    if state is None:
        return nullcontext()
    return _TimingStepContext(state, step, provider)


def current_timing_operation() -> TimingOperation | None:
    state = _ACTIVE_OPERATION.get()
    return state.operation if state is not None else None


def set_timing_incident(evidence: IncidentEvidence) -> None:
    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.incident = evidence


def current_timing_incident() -> IncidentEvidence | None:
    """Return evidence belonging to this operation, never another request."""
    state = _ACTIVE_OPERATION.get()
    return state.incident if state is not None else None


def record_timing_browser_fallback() -> None:
    """Observe the existing fallback dispatch within its owning operation."""
    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.browser_fallback_attempted = True


def record_timing_browser_first() -> None:
    """Observe a read sent straight to the browser by a standing rot signal."""
    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.browser_fallback_attempted = True
        state.browser_first = True


def set_timing_recovery(evidence: RecoveryHandoffEvidence) -> None:
    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.recovery = evidence


def set_timing_acquisition_mode(mode: AcquisitionMode) -> None:
    """Attach proven acquisition evidence to the active operation, if any."""

    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.acquisition_mode = mode


def set_timing_failure(failure: MintFailureEvidence) -> None:
    """Attach closed acquisition failure evidence to the active operation."""

    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.failure = failure


def set_timing_browser_major(major: int) -> None:
    """Attach the closed browser major version to the active operation."""

    if major < 1 or major > 999:
        return
    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.browser_major = major


def clear_timing_content_assessment() -> None:
    """Start a new bounded target attempt without retaining stale facts."""

    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.content_assessment = None


def set_timing_content_assessment(assessment: ArticleAssessment) -> None:
    """Attach the latest target assessment without retaining article content."""

    state = _ACTIVE_OPERATION.get()
    if state is not None:
        state.content_assessment = content_assessment_evidence(assessment)


def content_assessment_evidence(
    assessment: ArticleAssessment,
) -> ContentAssessmentEvidence:
    """Close one assessment for timing, incident, and controller contracts."""

    return ContentAssessmentEvidence(
        access_state=assessment.access_state,
        reason=_closed_reason(assessment.reason),
        identity_match=assessment.identity_match,
        word_count=assessment.word_count,
        session_cookie_present=assessment.session_cookie_present,
    )


def current_timing_session_probe(
    assessment: ArticleAssessment, *, provider: str, operation: TimingOperation
) -> SessionProbeEvidence | None:
    """Reuse an observed probe only for the matching current target verdict."""

    state = _ACTIVE_OPERATION.get()
    if (
        state is None
        or state.provider != provider
        or state.operation is not operation
        or state.content_assessment is None
        or assessment.promotable
    ):
        return None
    observed = state.content_assessment
    target = content_assessment_evidence(assessment)
    if observed.model_copy(update={"session_probe": None}) != target:
        return None
    return observed.session_probe


def set_timing_session_probe(
    outcome: SessionProbeOutcome,
    verification: SessionVerification | None = None,
    *,
    failure_reason: Literal["authority_changed", "transport_error"] | None = None,
) -> None:
    """Attach a closed lazy-probe result to the latest non-full target."""

    state = _ACTIVE_OPERATION.get()
    if state is None or state.content_assessment is None:
        return
    if verification is None:
        probe = SessionProbeEvidence(outcome=outcome, failure_reason=failure_reason)
    else:
        probe = SessionProbeEvidence(
            outcome=outcome,
            access_state=verification.access_state,
            reason=_closed_reason(verification.reason),
        )
    state.content_assessment = state.content_assessment.model_copy(
        update={"session_probe": probe}
    )


@contextmanager
def timing_invocation(invocation_id: str) -> Iterator[None]:
    """Correlate operations for one CLI, MCP, or live-gate invocation."""

    if not _IDENTIFIER.fullmatch(invocation_id):
        raise ValueError("invalid timing invocation ID")
    token = _ACTIVE_INVOCATION.set(invocation_id)
    try:
        yield
    finally:
        _ACTIVE_INVOCATION.reset(token)


def current_timing_invocation_id() -> str | None:
    """Return the active or inherited closed diagnostic correlation ID."""

    value = _ACTIVE_INVOCATION.get() or os.environ.get("NEWSCLIP_INVOCATION_ID")
    return value if value is not None and _IDENTIFIER.fullmatch(value) else None


def read_timing_file(path: Path) -> TimingRun:
    records: list[TimingRecord] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            records.append(_RECORD_ADAPTER.validate_json(line))
    return TimingRun(path=Path(path), records=tuple(records))


def iter_timing_runs(
    root: Path,
    *,
    invocation_id: str | None = None,
) -> Iterator[TimingRun]:
    """Yield selected validated runs; schema drift in that selection is an error."""

    if invocation_id is not None and not _IDENTIFIER.fullmatch(invocation_id):
        raise ValueError("invalid timing invocation ID")
    timing_root = Path(root)
    paths = (
        path
        for operation in TimingOperation
        for path in (timing_root / operation.value).glob("*/*.jsonl")
    )
    for path in sorted(paths):
        if (
            invocation_id is not None
            and _raw_timing_invocation_id(path) != invocation_id
        ):
            continue
        yield read_timing_file(path)


def _raw_timing_invocation_id(path: Path) -> str | None:
    """Read only routing metadata before validating a selected timing run."""

    with Path(path).open("r", encoding="utf-8") as handle:
        first_line = handle.readline()
    payload = json.loads(first_line)
    if not isinstance(payload, dict):
        return None
    value = payload.get("invocation_id")
    return value if isinstance(value, str) else None


def _outcome(error: BaseException | None) -> TimingOutcome:
    if error is None:
        return TimingOutcome.SUCCESS
    if isinstance(error, TimeoutError):
        return TimingOutcome.TIMEOUT
    for attribute in ("category", "outcome"):
        value = getattr(error, attribute, None)
        if getattr(value, "value", value) == "timeout":
            return TimingOutcome.TIMEOUT
    return TimingOutcome.ERROR


def _environment_dirty() -> bool | None:
    value = os.environ.get("NEWSCLIP_BUILD_DIRTY")
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _environment_surface() -> TimingSurface:
    value = os.environ.get("NEWSCLIP_TIMING_SURFACE")
    try:
        return TimingSurface(value) if value else TimingSurface.NONE
    except ValueError:
        return TimingSurface.UNKNOWN_VIRTUAL
