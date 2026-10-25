"""Closed, redacted schemas for optional durable browser-runtime traces."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import AwareDatetime, Field, TypeAdapter, model_validator
from signin_window.automation.auth import AuthEvidenceFamily as AuthEvidenceFamily
from signin_window.automation.auth import AuthPhase as AuthPhase
from signin_window.automation.auth import IdentityExitReason as IdentityExitReason
from signin_window.automation.auth import RouteClass as RouteClass
from signin_window.automation.events import (
    HCaptchaAttemptTerminalReason as HCaptchaAttemptTerminalReason,
)
from signin_window.automation.events import HCaptchaPlanKind as HCaptchaPlanKind
from signin_window.automation.events import HCaptchaPromptFamily as HCaptchaPromptFamily
from signin_window.automation.events import (
    HCaptchaSurfaceMissBucket as HCaptchaSurfaceMissBucket,
)
from signin_window.automation.events import (
    HCaptchaTerminalReason as HCaptchaTerminalReason,
)
from signin_window.automation.events import (
    HCaptchaVendorOutcome as HCaptchaVendorOutcome,
)

from ..acquisition import CredentialAction
from ..browser_readiness import (
    ReadinessCoverageBucket,
    ReadinessTerminalState,
)
from ..challenge_resolver import ChallengeResolution
from ..challenges import ChallengeAcceptanceSource, ChallengeMode
from ..errors import TransportFailure
from ..models import AccessState, CaptureFailure, FrozenModel
from ..visual_plans import VisualPlan


class SurfaceMode(StrEnum):
    MANAGED_VIRTUAL = "managed_virtual"
    HOST_XVFB = "host_xvfb"
    DOCKER_XVFB_BWRAP = "docker_xvfb_bwrap"


class DisplayClass(StrEnum):
    VIRTUAL_LOCAL = "virtual_local"
    VIRTUAL_REMOTE = "virtual_remote"


class BrowserMode(StrEnum):
    HEADED_DESKTOP = "headed_desktop"
    HEADED_VIRTUAL = "headed_virtual"


class BrowserOperation(StrEnum):
    INITIALIZED = "initialized"
    NAVIGATE = "navigate"
    REPLACE_PAGE = "replace_page"
    REPLACE_COOKIES = "replace_cookies"
    CLEAR_STORAGE = "clear_storage"
    INIT_SCRIPT = "init_script"
    CHALLENGE_ACTION = "challenge_action"
    FILL = "fill"
    FILL_ALL_VISIBLE = "fill_all_visible"
    PRESS = "press"
    CLICK = "click"
    MOUSE_TARGET = "mouse_target"
    MOUSE_CLICK = "mouse_click"
    CLICK_MATCHING_TEXT = "click_matching_text"
    CLICK_OPTIONAL = "click_optional"
    SUPPRESS_PASSKEYS = "suppress_passkeys"
    EVALUATE = "evaluate"
    COOKIES = "cookies"
    WAIT = "wait"


class BrowserFailurePhase(StrEnum):
    STARTUP = "startup"
    OPERATION = "operation"


class BrowserFailureCategory(StrEnum):
    CONTEXT_REPLACED = "context_replaced"
    TARGET_CLOSED = "target_closed"
    TIMEOUT = "timeout"
    SCRIPT_ERROR = "script_error"
    API_ERROR = "api_error"
    UNCLASSIFIED = "unclassified"


class IdentityHandoffCheckpoint(StrEnum):
    IDENTITY_RETURN = "identity_return"
    IDENTITY_ERROR = "identity_error"
    CALLBACK_WAIT = "callback_wait"
    CALLBACK_RETRY = "callback_retry"
    PAID_PROBE = "paid_probe"


class IdentityParentState(StrEnum):
    PUBLISHER_AUTH = "publisher_auth"
    PUBLISHER_CONTENT = "publisher_content"
    CLOSED = "closed"
    OTHER = "other"
    UNAVAILABLE = "unavailable"


class IdentityPageState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    UNAVAILABLE = "unavailable"


class PaidProbeOutcome(StrEnum):
    COMPLETE = "complete"
    INTERRUPTED = "interrupted"


class PerimeterXPointerBackend(StrEnum):
    X11 = "x11"
    CDP = "cdp"
    OTHER = "other"


class PerimeterXHoldReleaseReason(StrEnum):
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"


class PerimeterXGenerationRelation(StrEnum):
    SAME = "same"
    CHANGED = "changed"
    UNAVAILABLE = "unavailable"


class PerimeterXFinalSurfaceState(StrEnum):
    CLEARED = "cleared"
    COMPLETED_CONTROL_PRESENT = "completed_control_present"
    REJECTED = "rejected"
    SPINNER_OR_LOADING = "spinner_or_loading"
    UNKNOWN = "unknown"


class HttpStatusClass(StrEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    SUCCESS = "success"
    REDIRECTION = "redirection"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"


class HttpOperationRole(StrEnum):
    SEARCH = "search"
    FETCH = "fetch"
    VERIFICATION = "verification"
    OTHER = "other"


class HttpRouteMode(StrEnum):
    SHARED_AFFINITY = "shared_affinity"
    OVERFLOW_EPHEMERAL = "overflow_ephemeral"
    AUTHENTICATED_AFFINITY = "authenticated_affinity"


class HttpRetryReason(StrEnum):
    NONE = "none"
    TRANSPORT = "transport"
    STATUS = "status"
    PROVIDER_RESPONSE = "provider_response"


class HttpAttemptOutcome(StrEnum):
    RESPONSE = "response"
    TRANSPORT_ERROR = "transport_error"


class ProfileGeneration(StrEnum):
    RETAINED = "retained"
    TEST_ISOLATED = "test_isolated"


class DurationBucket(StrEnum):
    UNDER_1S = "under_1s"
    S1_TO_10 = "1s_10s"
    S10_TO_60 = "10s_60s"
    M1_TO_5 = "1m_5m"
    OVER_5M = "over_5m"


class AttemptPurpose(StrEnum):
    LOGIN = "login"
    PROFILE_REHYDRATE = "profile_rehydrate"
    VERIFICATION = "verification"
    SEARCH = "search"
    RETRIEVE = "retrieve"


class AttemptOutcome(StrEnum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


class ControlCardinality(StrEnum):
    NOT_CHECKED = "not_checked"
    ABSENT = "absent"
    SINGLE = "single"
    MULTIPLE = "multiple"


class ActionResult(StrEnum):
    TRANSITIONED = "transitioned"
    CALLBACK_SUCCESS = "callback_success"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class AttemptStartedEvent(FrozenModel):
    event: Literal["attempt_started"] = "attempt_started"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    purpose: AttemptPurpose
    profile_state: Literal["new", "existing", "unknown"] = "unknown"
    profile_scope: Literal["public", "account", "unknown"] = "unknown"


class NavigationEvidence(FrozenModel):
    """Response metadata only; never URLs, headers, or authentication material."""

    status: int | None = Field(default=None, ge=100, le=599)
    destination: Literal["requested_origin", "other_origin", "unknown"] = "unknown"
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)


class AttemptFinishedEvent(FrozenModel):
    event: Literal["attempt_finished"] = "attempt_finished"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    outcome: AttemptOutcome
    last_phase: AuthPhase
    last_navigation: NavigationEvidence | None = None
    capture_failure: CaptureFailure | None = None


class SemanticReadinessTerminalEvent(FrozenModel):
    """Bounded final state for one same-document readiness sampler."""

    event: Literal["semantic_readiness_terminal"] = "semantic_readiness_terminal"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    state: ReadinessTerminalState
    word_count: int = Field(ge=0, le=1_000_000)
    coverage_bucket: ReadinessCoverageBucket
    content_change_count: int = Field(ge=0, le=65_535)
    last_content_change_ms: int = Field(ge=0, le=120_000)


class AuthObservationEvent(FrozenModel):
    event: Literal["auth_observation"] = "auth_observation"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    phase: AuthPhase
    state_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    observation_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    control_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    evidence_families: tuple[AuthEvidenceFamily, ...]
    control_cardinality: ControlCardinality = ControlCardinality.NOT_CHECKED
    route_class: RouteClass
    selector_error: bool = False


class SemanticActionStartedEvent(FrozenModel):
    event: Literal["semantic_action_started"] = "semantic_action_started"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    action_id: int = Field(ge=1)
    action: BrowserOperation
    sequence: int = Field(ge=1)
    pre_observation_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    control_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")


class SemanticActionFinishedEvent(FrozenModel):
    event: Literal["semantic_action_finished"] = "semantic_action_finished"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    action_id: int = Field(ge=1)
    dispatched: bool
    result: ActionResult
    navigation: NavigationEvidence | None = None


class SurfaceSelectedEvent(FrozenModel):
    event: Literal["surface_selected"] = "surface_selected"
    mode: SurfaceMode
    display_class: DisplayClass


class BrowserStartedEvent(FrozenModel):
    event: Literal["browser_started"] = "browser_started"
    browser_mode: BrowserMode
    profile_generation: ProfileGeneration
    recovered_local_singleton: bool = False


class BrowserClosedEvent(FrozenModel):
    event: Literal["browser_closed"] = "browser_closed"
    browser_mode: BrowserMode
    profile_generation: ProfileGeneration
    duration: DurationBucket
    cleanup_ok: bool
    cleanup_failures: tuple[
        Literal["context_close", "driver_stop", "browser_exit"], ...
    ] = ()
    browser_exit_confirmed: bool | None = None
    forced_termination: bool = False


class BrowserFailedEvent(FrozenModel):
    event: Literal["browser_failed"] = "browser_failed"
    browser_mode: BrowserMode
    profile_generation: ProfileGeneration
    phase: BrowserFailurePhase
    operation: BrowserOperation
    category: BrowserFailureCategory


class HCaptchaRoundEvent(FrozenModel):
    event: Literal["hcaptcha_round"] = "hcaptcha_round"
    attempt_id: str | None = Field(
        default=None,
        pattern=r"^attempt-[0-9a-f]{32}$",
    )
    provider: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_]{0,31}$",
    )
    round: int = Field(ge=1, le=8)
    family: HCaptchaPromptFamily
    plan: HCaptchaPlanKind
    visual_plan: VisualPlan | None = None
    action_dispatched: bool = False
    submit_control_clicked: bool = False
    accepted: bool
    acceptance_source: ChallengeAcceptanceSource | None = None
    frame_open: bool
    vendor_accepted: bool | None
    vendor_outcome: HCaptchaVendorOutcome | None = None
    generation_changed: bool | None = None
    terminal_reason: HCaptchaTerminalReason | None = None

    @model_validator(mode="after")
    def validate_closed_facts(self) -> HCaptchaRoundEvent:
        if (self.attempt_id is None) is not (self.provider is None):
            raise ValueError("hCaptcha provider and attempt correlation must agree")
        if (
            self.visual_plan is not None
            and self.visual_plan.kind.value != self.plan.value
        ):
            raise ValueError("hCaptcha visual plan kind is inconsistent")
        if self.acceptance_source is not None and self.accepted is (
            self.acceptance_source is ChallengeAcceptanceSource.NONE
        ):
            raise ValueError("hCaptcha acceptance source is inconsistent")
        expected_vendor = (
            HCaptchaVendorOutcome.NOT_OBSERVED
            if self.vendor_accepted is None
            else HCaptchaVendorOutcome.ACCEPTED
            if self.vendor_accepted
            else HCaptchaVendorOutcome.REJECTED
        )
        if (
            self.vendor_outcome is not None
            and self.vendor_outcome is not expected_vendor
        ):
            raise ValueError("hCaptcha vendor outcome is inconsistent")
        if (
            self.terminal_reason is HCaptchaTerminalReason.NATIVE_ACCEPTED
            and not self.accepted
        ):
            raise ValueError("hCaptcha accepted terminal reason is inconsistent")
        if not self.action_dispatched and (
            self.submit_control_clicked or self.generation_changed is not None
        ):
            raise ValueError("hCaptcha undispatched action has post-action facts")
        return self


class HCaptchaAttemptFinishedEvent(FrozenModel):
    event: Literal["hcaptcha_attempt_finished"] = "hcaptcha_attempt_finished"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    rounds_attempted: int = Field(ge=0, le=8)
    surface_miss_bucket: HCaptchaSurfaceMissBucket
    accepted: bool
    acceptance_source: ChallengeAcceptanceSource
    last_vendor_outcome: HCaptchaVendorOutcome
    terminal_reason: HCaptchaAttemptTerminalReason

    @model_validator(mode="after")
    def validate_terminal_facts(self) -> HCaptchaAttemptFinishedEvent:
        if self.accepted is (self.acceptance_source is ChallengeAcceptanceSource.NONE):
            raise ValueError("hCaptcha attempt acceptance source is inconsistent")
        if self.accepted is not (
            self.terminal_reason is HCaptchaAttemptTerminalReason.ACCEPTED
        ):
            raise ValueError("hCaptcha attempt terminal reason is inconsistent")
        if (
            self.terminal_reason is HCaptchaAttemptTerminalReason.SURFACE_MISSING
            and self.surface_miss_bucket is HCaptchaSurfaceMissBucket.NONE
        ):
            raise ValueError("hCaptcha surface terminal has no misses")
        return self


class HCaptchaCheckpointEvent(FrozenModel):
    """Durable pre-action evidence, including rounds interrupted before verdict."""

    event: Literal["hcaptcha_checkpoint"] = "hcaptcha_checkpoint"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    round: int = Field(ge=1, le=8)
    planning_call: int = Field(default=1, ge=1, le=2)
    stage: Literal["input", "planned", "validity", "outcome"]
    family: HCaptchaPromptFamily
    planner: Literal["codex", "claude", "unknown"] = "unknown"
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)
    task_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    visual_plan: VisualPlan | None = None
    task_current: bool | None = None
    task_identity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    task_geometry: tuple[float, float, float, float] | None = None
    planner_model: Literal["unknown"] = "unknown"
    images_requested: int = Field(default=0, ge=0, le=2)
    instruction_requested: bool = False
    artifacts_complete: bool = True
    artifacts: tuple[str, ...] = Field(default=(), max_length=4)

    @model_validator(mode="after")
    def validate_artifacts(self) -> HCaptchaCheckpointEvent:
        if self.task_geometry is not None and (
            not all(math.isfinite(value) for value in self.task_geometry)
            or self.task_geometry[2] <= 0
            or self.task_geometry[3] <= 0
        ):
            raise ValueError("invalid challenge task geometry")
        if any(
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,159}", p) for p in self.artifacts
        ):
            raise ValueError("invalid challenge artifact reference")
        return self


class AcquisitionEvidenceEvent(FrozenModel):
    event: Literal["acquisition_evidence"] = "acquisition_evidence"
    operation_id: str = Field(pattern=r"^op-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    stage: Literal[
        "started",
        "credential_ready",
        "failed",
        "published",
        "artifacts_discarded",
        "artifacts_retained",
    ]
    evidence_complete: bool
    retention_reason: (
        Literal["diagnostic_loss", "cleanup_failed", "caller_owns_retention"] | None
    ) = None

    @model_validator(mode="after")
    def validate_retention(self) -> AcquisitionEvidenceEvent:
        if (self.stage == "artifacts_retained") != (self.retention_reason is not None):
            raise ValueError("retained acquisition artifacts require a reason")
        return self


class ArtifactOmission(StrEnum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    ARTIFACT_TOO_LARGE = "artifact_too_large"
    PAGE_UNAVAILABLE = "page_unavailable"
    CAPTURE_FAILED = "capture_failed"
    WRITE_FAILED = "write_failed"


class DiagnosticArtifactEvent(FrozenModel):
    """One private artifact reference or a closed explanation for its absence."""

    event: Literal["diagnostic_artifact"] = "diagnostic_artifact"
    operation_id: str | None = Field(default=None, pattern=r"^op-[0-9a-f]{32}$")
    attempt_id: str | None = Field(default=None, pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,31}$")
    kind: Literal["screenshot", "instruction"] = "screenshot"
    label: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    path: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,255}$")
    omission: ArtifactOmission | None = None
    terminal: bool = False

    @model_validator(mode="after")
    def validate_disposition(self) -> DiagnosticArtifactEvent:
        if (self.path is None) == (self.omission is None):
            raise ValueError("artifact requires a reference or an omission reason")
        return self


class ChallengeResolutionEvent(ChallengeResolution):
    """The resolver's own terminal facts, without reclassifying its outcome."""

    event: Literal["challenge_resolution"] = "challenge_resolution"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    mode: ChallengeMode
    capability: Literal[
        "detect_only", "unsupported", "passive_wait", "interactive_mechanic"
    ]
    elapsed_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    actionable_observed: bool | None = None
    surface_observations: int = Field(default=0, ge=0, le=65535)


class HttpAttemptEvent(FrozenModel):
    event: Literal["http_attempt"] = "http_attempt"
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    role: HttpOperationRole
    policy_attempt: int = Field(ge=1, le=2)
    retry_reason: HttpRetryReason
    impersonate: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    route_mode: HttpRouteMode
    contention: bool
    outcome: HttpAttemptOutcome
    status: int | None = Field(default=None, ge=100, le=599)
    transport_failure: TransportFailure | None = None
    duration_ms: float = Field(ge=0, allow_inf_nan=False)
    datadome_header_present: bool = False
    datadome_cookie_present: bool = False
    route_request_index: int | None = Field(default=None, ge=1)
    route_id: str | None = Field(default=None, pattern=r"^http-route-[0-9a-f]{16}$")
    session_generation_fingerprint: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{12}$"
    )
    # Whole-jar comparisons, not a claim about the Cookie header for this URL.
    request_cookies_changed: bool | None = None
    response_cookies_changed: bool | None = None
    redirected: bool | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> HttpAttemptEvent:
        response = self.outcome is HttpAttemptOutcome.RESPONSE
        if response != (self.status is not None):
            raise ValueError("HTTP response outcome/status is inconsistent")
        if response == (self.transport_failure is not None):
            raise ValueError("HTTP transport outcome/category is inconsistent")
        return self


class IdentityHandoffEvent(FrozenModel):
    event: Literal["identity_handoff"] = "identity_handoff"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    checkpoint: IdentityHandoffCheckpoint
    credential_action: CredentialAction | None = None
    identity_callback_complete: bool | None = None
    identity_page_closed: bool | None = None
    identity_page_state: IdentityPageState | None = None
    identity_exit_reason: IdentityExitReason | None = None
    parent_state: IdentityParentState
    callback_confirmed: bool | None = None
    publisher_auth_cookie_present: bool | None = None
    # Challenge-vendor reputation is independent of publisher authority, so a
    # defense that never trusted the browser stays separable from a publisher
    # that never issued one.
    challenge_cookie_present: bool | None = None
    # What the callback-clearance probe actually saw. `cleared=False` used to
    # report `challenge_blocked` for three different situations: the defense
    # re-blocked a browser it had just accepted, it never issued a clearance
    # token at all, or the endpoint answered something the probe does not
    # treat as clearance. They need different remedies, so the status and
    # whether a clearance token existed are recorded rather than inferred.
    callback_probe_status: int | None = Field(default=None, ge=100, le=599)
    callback_clearance_cookie_present: bool | None = None
    paid_probe_outcome: PaidProbeOutcome | None = None
    entitlement_confirmed: bool | None = None
    paid_auth_cookie_present: bool | None = None
    paid_probe_access_state: AccessState | None = None
    paid_probe_stabilized: bool | None = None
    verification_full: bool | None = None

    @model_validator(mode="after")
    def validate_checkpoint(self) -> IdentityHandoffEvent:
        identity_result_present = all(
            value is not None
            for value in (
                self.credential_action,
                self.identity_callback_complete,
                self.identity_page_closed,
            )
        )
        if self.checkpoint is IdentityHandoffCheckpoint.IDENTITY_ERROR:
            if any(
                value is not None
                for value in (
                    self.credential_action,
                    self.identity_callback_complete,
                    self.identity_page_closed,
                    self.identity_exit_reason,
                    self.callback_confirmed,
                    self.paid_probe_outcome,
                    self.entitlement_confirmed,
                    self.paid_auth_cookie_present,
                    self.paid_probe_access_state,
                    self.paid_probe_stabilized,
                    self.verification_full,
                )
            ):
                raise ValueError("identity error handoff has result facts")
            return self
        if self.checkpoint is IdentityHandoffCheckpoint.PAID_PROBE:
            if identity_result_present or any(
                value is not None
                for value in (
                    self.credential_action,
                    self.identity_callback_complete,
                    self.identity_page_closed,
                    self.identity_page_state,
                    self.identity_exit_reason,
                    self.publisher_auth_cookie_present,
                )
            ):
                raise ValueError("paid probe handoff has identity result facts")
            if self.paid_probe_outcome is None:
                raise ValueError("paid probe handoff has no outcome")
            if self.paid_probe_outcome is PaidProbeOutcome.COMPLETE and any(
                value is None
                for value in (
                    self.callback_confirmed,
                    self.entitlement_confirmed,
                    self.paid_auth_cookie_present,
                    self.verification_full,
                )
            ):
                raise ValueError("completed paid probe facts are incomplete")
            return self
        if not identity_result_present:
            raise ValueError("identity handoff result is incomplete")
        if self.publisher_auth_cookie_present is None:
            raise ValueError("identity handoff cookie fact is missing")
        if any(
            value is not None
            for value in (
                self.identity_page_state,
                self.paid_probe_outcome,
                self.entitlement_confirmed,
                self.paid_auth_cookie_present,
                self.paid_probe_access_state,
                self.paid_probe_stabilized,
                self.verification_full,
            )
        ):
            raise ValueError("identity handoff has paid probe facts")
        callback_checkpoint = self.checkpoint in {
            IdentityHandoffCheckpoint.CALLBACK_WAIT,
            IdentityHandoffCheckpoint.CALLBACK_RETRY,
        }
        if callback_checkpoint != (self.callback_confirmed is not None):
            raise ValueError("identity callback checkpoint is inconsistent")
        return self


class PerimeterXHoldEvent(FrozenModel):
    event: Literal["perimeterx_hold"] = "perimeterx_hold"
    attempt_id: str = Field(pattern=r"^attempt-[0-9a-f]{32}$")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    hold_index: int = Field(ge=1, le=3)
    pointer_backend: PerimeterXPointerBackend
    duration_bucket: DurationBucket
    release_reason: PerimeterXHoldReleaseReason
    post_settle_acceptance_source: ChallengeAcceptanceSource | None = None
    retry_invited: bool | None = None
    control_still_present: bool | None = None
    generation_relation: PerimeterXGenerationRelation
    final_surface_state: PerimeterXFinalSurfaceState

    @model_validator(mode="after")
    def validate_release(self) -> PerimeterXHoldEvent:
        post_settle_facts = (
            self.post_settle_acceptance_source,
            self.retry_invited,
            self.control_still_present,
        )
        if self.release_reason is PerimeterXHoldReleaseReason.INTERRUPTED:
            if any(value is not None for value in post_settle_facts):
                raise ValueError("interrupted hold has post-settle facts")
            if (
                self.generation_relation is not PerimeterXGenerationRelation.UNAVAILABLE
                or self.final_surface_state is not PerimeterXFinalSurfaceState.UNKNOWN
            ):
                raise ValueError("interrupted hold has a final surface")
            return self
        if any(value is None for value in post_settle_facts):
            raise ValueError("settled hold facts are incomplete")
        return self


class CredentialCallbackEvent(FrozenModel):
    event: Literal["credential_callback"] = "credential_callback"
    sequence: int = Field(ge=1, le=2)
    credential_present: bool | None
    challenge_token_present: bool | None
    status_class: HttpStatusClass


class DiagnosticHealthEvent(FrozenModel):
    """Bounded disclosure that one or more diagnostic artifacts were lost."""

    event: Literal["diagnostic_health"] = "diagnostic_health"
    provider: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_]{0,31}$",
    )
    event_write_failures: int = Field(default=0, ge=0, le=65_535)
    screenshot_capture_failures: int = Field(default=0, ge=0, le=65_535)
    screenshot_write_failures: int = Field(default=0, ge=0, le=65_535)

    @model_validator(mode="after")
    def validate_loss_present(self) -> DiagnosticHealthEvent:
        if (
            self.event_write_failures
            + self.screenshot_capture_failures
            + self.screenshot_write_failures
            == 0
        ):
            raise ValueError("diagnostic health event must report a loss")
        return self


RuntimeEvent = Annotated[
    AttemptStartedEvent
    | AttemptFinishedEvent
    | SemanticReadinessTerminalEvent
    | AuthObservationEvent
    | SemanticActionStartedEvent
    | SemanticActionFinishedEvent
    | SurfaceSelectedEvent
    | BrowserStartedEvent
    | HCaptchaRoundEvent
    | HCaptchaAttemptFinishedEvent
    | HCaptchaCheckpointEvent
    | AcquisitionEvidenceEvent
    | DiagnosticArtifactEvent
    | ChallengeResolutionEvent
    | HttpAttemptEvent
    | IdentityHandoffEvent
    | PerimeterXHoldEvent
    | CredentialCallbackEvent
    | DiagnosticHealthEvent
    | BrowserFailedEvent
    | BrowserClosedEvent,
    Field(discriminator="event"),
]
_EVENT_ADAPTER: TypeAdapter[RuntimeEvent] = TypeAdapter(RuntimeEvent)
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SCREENSHOT_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PROVIDER = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class RuntimeRecord(FrozenModel):
    """One validated record from the durable runtime JSONL wire format."""

    schema_version: Literal[1] = 1
    run_id: str = Field(pattern=_RUN_ID.pattern)
    sequence: int = Field(ge=1)
    occurred_at: AwareDatetime
    event: RuntimeEvent

    @model_validator(mode="before")
    @classmethod
    def unpack_wire_event(cls, raw: object) -> object:
        if not isinstance(raw, dict) or "facts" not in raw:
            return raw
        facts = raw.get("facts")
        if not isinstance(facts, dict) or "event" in facts:
            return raw
        normalized = {
            key: value for key, value in raw.items() if key not in {"event", "facts"}
        }
        normalized["event"] = {"event": raw.get("event"), **facts}
        return normalized


_RECORD_ADAPTER: TypeAdapter[RuntimeRecord] = TypeAdapter(RuntimeRecord)


class RuntimeRun(FrozenModel):
    """One runtime trace whose envelope and attempt ledger are coherent."""

    path: Path
    records: tuple[RuntimeRecord, ...]

    @model_validator(mode="after")
    def validate_contract(self) -> RuntimeRun:
        if not self.records:
            raise ValueError("runtime trace must contain at least one record")
        first = self.records[0]
        if [record.sequence for record in self.records] != list(
            range(1, len(self.records) + 1)
        ):
            raise ValueError("runtime record sequence is not contiguous")
        if any(record.run_id != first.run_id for record in self.records):
            raise ValueError("runtime run ID changed within one file")

        active_attempts: dict[str, str] = {}
        finished_attempts: set[str] = set()
        next_action_ids: dict[str, int] = {}
        active_actions: dict[str, int] = {}
        readiness_attempts: set[str] = set()
        for record in self.records:
            event = record.event
            if isinstance(event, AttemptStartedEvent):
                if (
                    event.attempt_id in active_attempts
                    or event.attempt_id in finished_attempts
                ):
                    raise ValueError("runtime attempt ID was reused")
                active_attempts[event.attempt_id] = event.provider
                next_action_ids[event.attempt_id] = 1
                continue

            attempt_id = getattr(event, "attempt_id", None)
            if attempt_id is not None:
                provider = active_attempts.get(attempt_id)
                if provider is None:
                    raise ValueError("runtime event references an inactive attempt")
                event_provider = getattr(event, "provider", provider)
                if event_provider != provider:
                    raise ValueError("runtime attempt provider changed")

            if isinstance(event, SemanticActionStartedEvent):
                if event.attempt_id in active_actions:
                    raise ValueError("runtime semantic actions overlap")
                expected = next_action_ids[event.attempt_id]
                if event.action_id != expected or event.sequence != expected:
                    raise ValueError(
                        "runtime semantic action sequence is not contiguous"
                    )
                active_actions[event.attempt_id] = event.action_id
                next_action_ids[event.attempt_id] = expected + 1
            elif isinstance(event, SemanticActionFinishedEvent):
                if active_actions.get(event.attempt_id) != event.action_id:
                    raise ValueError(
                        "runtime semantic action finish does not match its start"
                    )
                del active_actions[event.attempt_id]
            elif isinstance(event, SemanticReadinessTerminalEvent):
                if event.attempt_id in readiness_attempts:
                    raise ValueError(
                        "runtime attempt has multiple readiness terminal events"
                    )
                readiness_attempts.add(event.attempt_id)
            elif isinstance(event, AttemptFinishedEvent):
                if event.attempt_id in active_actions:
                    raise ValueError("runtime attempt finished with an active action")
                del active_attempts[event.attempt_id]
                finished_attempts.add(event.attempt_id)
        return self


def read_runtime_file(path: Path) -> RuntimeRun:
    """Read and validate one complete runtime trace before deriving evidence."""

    records: list[RuntimeRecord] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            records.append(_RECORD_ADAPTER.validate_json(line))
    return RuntimeRun(path=Path(path), records=tuple(records))


def duration_bucket(seconds: float) -> DurationBucket:
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("duration must be finite and non-negative")
    if seconds < 1:
        return DurationBucket.UNDER_1S
    if seconds < 10:
        return DurationBucket.S1_TO_10
    if seconds < 60:
        return DurationBucket.S10_TO_60
    if seconds < 300:
        return DurationBucket.M1_TO_5
    return DurationBucket.OVER_5M


def hcaptcha_surface_miss_bucket(count: int) -> HCaptchaSurfaceMissBucket:
    if count < 0:
        raise ValueError("hCaptcha surface misses must be non-negative")
    if count == 0:
        return HCaptchaSurfaceMissBucket.NONE
    if count == 1:
        return HCaptchaSurfaceMissBucket.ONE
    if count == 2:
        return HCaptchaSurfaceMissBucket.TWO
    return HCaptchaSurfaceMissBucket.THREE_OR_MORE


@dataclass
class _AcquisitionEvidence:
    operation_id: str
    provider: str
    complete: bool = True


class RuntimeTrace:
    """Append validated runtime events; sequence advances only after fsync."""

    def __init__(
        self, path: Path, *, run_id: str, retain_success_artifacts: bool = False
    ) -> None:
        self._retain_success_artifacts = retain_success_artifacts
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid runtime trace run id")
        self._path = Path(path)
        self._run_id = run_id
        self._sequence = 0
        self._lock = threading.Lock()
        self._attempt_providers: dict[str, str] = {}
        self._pending_health: dict[str | None, dict[str, int]] = {}
        self._artifact_lock = threading.Lock()
        self._artifact_usage: dict[str, tuple[int, int]] = {}
        self._artifacts: dict[str, list[Path]] = {}
        self._acquisition: ContextVar[_AcquisitionEvidence | None] = ContextVar(
            "runtime_acquisition", default=None
        )

    def incident_snapshot(self, attempt_id: str | None) -> bytes | None:
        """Bounded current-attempt prefix, independent of process lifetime."""
        try:
            with self._lock:
                descriptor = os.open(
                    self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                )
                with os.fdopen(descriptor, "rb") as stream:
                    metadata = os.fstat(stream.fileno())
                    if not stat.S_ISREG(metadata.st_mode):
                        return None
                    offset = max(0, metadata.st_size - 1024 * 1024)
                    stream.seek(offset)
                    payload = stream.read(1024 * 1024)
            if offset:
                _, _, payload = payload.partition(b"\n")
            lines = payload.splitlines(keepends=True)
            if attempt_id is None:
                return None
            for index, line in enumerate(lines):
                row = json.loads(line)
                if (
                    row.get("event") == "attempt_started"
                    and row.get("facts", {}).get("attempt_id") == attempt_id
                ):
                    return b"".join(lines[index:])
            # An individual attempt larger than the cap remains explicitly
            # unavailable; never claim a truncated action ledger is complete.
            return None
        except (OSError, ValueError, AttributeError):
            return None

    @contextmanager
    def acquisition(self, provider: str) -> Iterator[None]:
        """Own evidence until the caller has closed browsers and published proof."""
        from ..timing import current_timing_operation_id

        if self._acquisition.get() is not None:
            raise RuntimeError("diagnostic acquisitions cannot be nested")
        state = _AcquisitionEvidence(
            current_timing_operation_id() or f"op-{uuid4().hex}", provider
        )
        token = self._acquisition.set(state)

        def record(stage, retention_reason=None):
            return self.try_write(
                AcquisitionEvidenceEvent(
                    operation_id=state.operation_id,
                    provider=provider,
                    stage=stage,
                    evidence_complete=state.complete,
                    retention_reason=retention_reason,
                )
            )

        try:
            record("started")
            try:
                yield
            except BaseException:
                record("failed")
                raise
            else:
                # No successful completion record means retain, even if session
                # publication itself succeeded. Diagnostic loss never undoes it.
                if record("published"):
                    if not state.complete:
                        record("artifacts_retained", "diagnostic_loss")
                    elif self._retain_success_artifacts:
                        record("artifacts_retained", "caller_owns_retention")
                    elif self.discard_attempt_artifacts(state.operation_id):
                        record("artifacts_discarded")
                    else:
                        record("artifacts_retained", "cleanup_failed")
        finally:
            self.flush_health()
            self._acquisition.reset(token)
            with self._artifact_lock:
                self._artifacts.pop(state.operation_id, None)
                self._artifact_usage.pop(state.operation_id, None)

    def _artifact_key(self, provider: str | None, attempt_id: str | None) -> str:
        scope = self._acquisition.get()
        if scope is not None and provider in {None, scope.provider}:
            return scope.operation_id
        return attempt_id or provider or "unattributed"

    def require_write_ready(self, provider: str) -> None:
        scope = self._acquisition.get()
        if (
            scope is None
            or scope.provider != provider
            or not self.try_write(
                AcquisitionEvidenceEvent(
                    operation_id=scope.operation_id,
                    provider=provider,
                    stage="credential_ready",
                    evidence_complete=scope.complete,
                )
            )
        ):
            raise OSError("credential diagnostic ledger unavailable")

    def write_failure_screenshot(self, screenshot: bytes) -> Path:
        """Persist one private, unredacted PNG beside this run's event trace."""

        return self.write_screenshot("failure", screenshot)

    def write_screenshot(self, label: str, screenshot: bytes) -> Path:
        """Persist one named private PNG beside this run's event trace."""

        return self._write_artifact(label, screenshot, suffix="png")

    def _write_artifact(self, label: str, data: bytes, *, suffix: str) -> Path:

        if not _SCREENSHOT_LABEL.fullmatch(label):
            raise ValueError("invalid runtime screenshot label")
        if not isinstance(data, bytes) or not data:
            raise ValueError("failure screenshot must contain bytes")
        path = self._path.with_suffix(f".{label}.{suffix}")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self._run_id}-",
            suffix=".partial",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("runtime screenshot target is not a regular file")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Link publishes a fully written artifact without replacing an
            # existing checkpoint. A crash can leave only an unlisted .partial.
            os.link(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return path

    def write_unique_screenshot(self, label: str, screenshot: bytes) -> Path:
        """Persist every repeated checkpoint without overwriting prior evidence."""

        occurrence = 1
        while True:
            if occurrence == 1:
                candidate = label
            else:
                suffix = f"-{occurrence}"
                candidate = f"{label[: 64 - len(suffix)]}{suffix}"
            try:
                return self.write_screenshot(candidate, screenshot)
            except FileExistsError:
                occurrence += 1

    def try_write_unique_screenshot(
        self,
        label: str,
        screenshot: bytes,
        *,
        provider: str | None = None,
        attempt_id: str | None = None,
        terminal: bool = False,
    ) -> Path | None:
        """Persist a screenshot without allowing diagnostic I/O to affect behavior."""

        omission = ArtifactOmission.WRITE_FAILED
        path = None
        try:
            key = self._artifact_key(provider, attempt_id)
            with self._artifact_lock:
                count, size = self._artifact_usage.get(key, (0, 0))
                # Reserve both slots and bytes for the last observable page.
                limit, byte_limit = (32, 64) if terminal else (30, 56)
                if len(screenshot) > byte_limit * 1024 * 1024:
                    omission = ArtifactOmission.ARTIFACT_TOO_LARGE
                elif (
                    count >= limit or size + len(screenshot) > byte_limit * 1024 * 1024
                ):
                    omission = ArtifactOmission.BUDGET_EXHAUSTED
                else:
                    path = self.write_unique_screenshot(label, screenshot)
                    self._artifact_usage[key] = (count + 1, size + len(screenshot))
                    self._artifacts.setdefault(key, []).append(path)
        except Exception:
            pass
        self.record_artifact(
            label,
            path=path,
            omission=omission if path is None else None,
            provider=provider,
            attempt_id=attempt_id,
            terminal=terminal,
        )
        return path

    def record_artifact(
        self,
        label: str,
        *,
        path: Path | None = None,
        omission: ArtifactOmission | None = None,
        provider: str | None = None,
        attempt_id: str | None = None,
        terminal: bool = False,
        kind: Literal["screenshot", "instruction"] = "screenshot",
    ) -> None:
        from ..timing import current_timing_operation_id

        scope = self._acquisition.get()
        provider = provider or (scope.provider if scope is not None else None)
        if omission is not None:
            self.note_diagnostic_loss(
                "event_write"
                if kind == "instruction"
                else "screenshot_capture"
                if omission
                in {ArtifactOmission.PAGE_UNAVAILABLE, ArtifactOmission.CAPTURE_FAILED}
                else "screenshot_write",
                provider=provider,
            )
        try:
            self.try_write(
                DiagnosticArtifactEvent(
                    operation_id=(
                        scope.operation_id
                        if scope is not None
                        else current_timing_operation_id()
                    ),
                    attempt_id=attempt_id,
                    provider=provider,
                    label=label,
                    path=path.name if path is not None else None,
                    omission=omission,
                    terminal=terminal,
                    kind=kind,
                )
            )
        except Exception:
            self.note_diagnostic_loss("event_write", provider=provider)

    def write_challenge_instruction(
        self, label: str, instruction: str, *, attempt_id: str, provider: str
    ) -> Path | None:
        """Private task text; never placed in redacted events or model stdout."""
        path = None
        omission = ArtifactOmission.WRITE_FAILED
        try:
            encoded = instruction.encode("utf-8")
            if len(encoded) > 16_384:
                omission = ArtifactOmission.ARTIFACT_TOO_LARGE
            if not 0 < len(encoded) <= 16_384:
                raise ValueError("challenge instruction is not bounded")
            with self._artifact_lock:
                path = self._write_artifact(label, encoded, suffix="txt")
                key = self._artifact_key(provider, attempt_id)
                self._artifacts.setdefault(key, []).append(path)
        except Exception:
            pass
        self.record_artifact(
            label,
            path=path,
            omission=omission if path is None else None,
            provider=provider,
            attempt_id=attempt_id,
            kind="instruction",
        )
        return path

    def discard_attempt_artifacts(self, attempt_id: str) -> bool:
        """Only the owner of a fully published mint may discard its evidence."""
        try:
            with self._artifact_lock:
                for path in self._artifacts.get(attempt_id, ()):
                    path.unlink(missing_ok=True)
                self._artifacts.pop(attempt_id, None)
                self._artifact_usage.pop(attempt_id, None)
            return True
        except OSError:
            scope = self._acquisition.get()
            self.note_diagnostic_loss(
                "screenshot_write", provider=scope.provider if scope else None
            )
            return False

    def write(self, event: RuntimeEvent) -> None:
        validated = _EVENT_ADAPTER.validate_python(event)
        with self._lock:
            self._write(validated)

    def try_write(
        self,
        event: RuntimeEvent,
        *,
        provider: str | None = None,
    ) -> bool:
        """Write evidence safely, retaining a bounded health fact on failure."""

        try:
            validated = _EVENT_ADAPTER.validate_python(event)
        except Exception:
            self.note_diagnostic_loss("event_write", provider=provider)
            return False
        finished_attempt_id = (
            validated.attempt_id
            if isinstance(validated, AttemptFinishedEvent)
            else None
        )
        try:
            return self._try_write_locked(validated, provider, finished_attempt_id)
        finally:
            if finished_attempt_id is not None:
                # A closed read-path attempt never writes again; its files stay
                # on disk, only the in-memory budget and index are released.
                # Acquisition-owned artifacts are keyed by operation instead.
                with self._artifact_lock:
                    self._artifacts.pop(finished_attempt_id, None)
                    self._artifact_usage.pop(finished_attempt_id, None)

    def _try_write_locked(
        self,
        validated: RuntimeEvent,
        provider: str | None,
        finished_attempt_id: str | None,
    ) -> bool:
        with self._lock:
            inferred_provider = provider or self._event_provider(validated)
            if isinstance(validated, AttemptStartedEvent):
                self._attempt_providers[validated.attempt_id] = validated.provider
            if not self._flush_health_locked():
                self._increment_health_locked("event_write", inferred_provider)
                if finished_attempt_id is not None:
                    self._attempt_providers.pop(finished_attempt_id, None)
                return False
            try:
                self._write(validated)
            except Exception:
                self._increment_health_locked("event_write", inferred_provider)
                if finished_attempt_id is not None:
                    self._attempt_providers.pop(finished_attempt_id, None)
                return False
            if finished_attempt_id is not None:
                self._attempt_providers.pop(finished_attempt_id, None)
        return True

    def note_diagnostic_loss(
        self,
        category: Literal[
            "event_write",
            "screenshot_capture",
            "screenshot_write",
        ],
        *,
        provider: str | None = None,
    ) -> None:
        """Queue one bounded loss counter for the next healthy trace write."""

        with self._lock:
            self._increment_health_locked(category, provider)

    def flush_health(self) -> bool:
        """Attempt to persist all queued health counters."""

        with self._lock:
            return self._flush_health_locked()

    def _event_provider(self, event: RuntimeEvent) -> str | None:
        provider = getattr(event, "provider", None)
        if provider is not None:
            return provider
        attempt_id = getattr(event, "attempt_id", None)
        if attempt_id is None:
            return None
        return self._attempt_providers.get(attempt_id)

    def _increment_health_locked(
        self,
        category: str,
        provider: str | None,
    ) -> None:
        scope = self._acquisition.get()
        if scope is not None and provider in {None, scope.provider}:
            scope.complete = False
        if provider is not None and not _PROVIDER.fullmatch(provider):
            provider = None
        counts = self._pending_health.setdefault(
            provider,
            {
                "event_write": 0,
                "screenshot_capture": 0,
                "screenshot_write": 0,
            },
        )
        counts[category] = min(counts[category] + 1, 65_535)

    def _flush_health_locked(self) -> bool:
        for provider in sorted(
            tuple(self._pending_health),
            key=lambda value: value or "",
        ):
            counts = self._pending_health[provider]
            event = DiagnosticHealthEvent(
                provider=provider,
                event_write_failures=counts["event_write"],
                screenshot_capture_failures=counts["screenshot_capture"],
                screenshot_write_failures=counts["screenshot_write"],
            )
            try:
                self._write(event)
            except Exception:
                return False
            del self._pending_health[provider]
        return True

    def _write(self, event: RuntimeEvent) -> None:
        next_sequence = self._sequence + 1
        payload = {
            "schema_version": 1,
            "run_id": self._run_id,
            "sequence": next_sequence,
            "occurred_at": datetime.now(UTC).isoformat(),
            "event": event.event,
            "facts": event.model_dump(mode="json", exclude={"event"}),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._path.parent, 0o700)
        descriptor = os.open(
            self._path,
            os.O_APPEND
            | os.O_CREAT
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("runtime trace target is not a regular file")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "ab", closefd=False) as handle:
                handle.write(encoded.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        self._sequence = next_sequence
