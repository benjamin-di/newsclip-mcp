"""Closed result contract for one bounded provider health sequence."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from .models import AccessState, FrozenModel, SessionDisposition
from .provider_keys import PROVIDER_KEY_PATTERN
from .timing import AssessmentReasonCode

_INCIDENT_ID_PATTERN = r"^incident-[0-9a-f]{24}$"


class ProviderCheckFailure(StrEnum):
    SESSION_REQUIRED = "session_required"
    OPERATOR_ACTION = "operator_action"
    SEARCH_TRANSPORT = "search_transport"
    SEARCH_CONTRACT = "search_contract"
    EXPECTED_RESULT_MISSING = "expected_result_missing"
    RETRIEVAL_TRANSPORT = "retrieval_transport"
    PROVIDER_DEFENSE = "provider_defense"
    SESSION_DEAD = "session_dead"
    CONTENT_NOT_FULL = "content_not_full"
    LOCAL_STATE = "local_state"


class ProviderCheckResult(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    ok: bool
    failure: ProviderCheckFailure | None = None
    search_result_count: int = Field(default=0, ge=0)
    #: Whether the first search page ranked the pinned canary URL, when the
    #: provider requires it. ``False`` is a non-durable advisory: the canary
    #: aged out of search, but retrieval still decides the verdict. ``None``
    #: means search did not complete or the provider does not require it.
    canary_in_search: bool | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    access_state: AccessState | None = None
    reason: AssessmentReasonCode | None = None
    identity_match: bool | None = None
    word_count: int | None = Field(default=None, ge=0)
    session_disposition: SessionDisposition | None = None
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    defense_observation: Literal["suppressed", "observed"] | None = None
    defense_retry_after_seconds: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )

    @model_validator(mode="after")
    def validate_outcome(self) -> ProviderCheckResult:
        if self.defense_observation is not None and (
            self.failure is not ProviderCheckFailure.PROVIDER_DEFENSE
            or self.defense_retry_after_seconds is None
        ):
            raise ValueError("defense observation requires bounded containment")
        if (
            self.defense_retry_after_seconds is not None
            and self.defense_observation is None
        ):
            raise ValueError("defense containment requires an observation kind")
        if self.ok != (self.failure is None):
            raise ValueError("provider-check success and failure are inconsistent")
        assessment_fields = (
            self.access_state,
            self.reason,
            self.identity_match,
            self.word_count,
        )
        if any(value is not None for value in assessment_fields) and any(
            value is None for value in assessment_fields
        ):
            raise ValueError("provider-check assessment is incomplete")
        if self.ok and (
            self.access_state is not AccessState.FULL or self.identity_match is not True
        ):
            raise ValueError("provider-check success requires full matching content")
        if self.ok and self.incident_id is not None:
            raise ValueError("provider-check success cannot name an incident")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class ProviderCheckObservation(FrozenModel):
    """The last guarded canary that actually contacted one provider."""

    schema_version: Literal[1] = 1
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    checked_at: AwareDatetime
    check: ProviderCheckResult

    @model_validator(mode="after")
    def validate_provider(self) -> ProviderCheckObservation:
        if self.provider != self.check.provider:
            raise ValueError("provider-check observation is inconsistent")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")
