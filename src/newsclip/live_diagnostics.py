"""Pure, closed classification for live-provider evidence."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .acquisition import MintFailureCategory
from .browser_runtime.events import BrowserFailureCategory
from .models import FrozenModel


class LiveDiagnosis(StrEnum):
    CODE_DEFECT = "code_defect"
    PROVIDER_CONTRACT_DRIFT = "provider_contract_drift"
    CONTENT_CONTRACT_DRIFT = "content_contract_drift"
    PROVIDER_DEFENSE = "provider_defense"
    ACCOUNT_ACTION = "account_action"
    PROVIDER_AVAILABILITY = "provider_availability"
    LOCAL_INFRASTRUCTURE = "local_infrastructure"
    UNKNOWN = "unknown"


class EvidenceStrength(StrEnum):
    DIRECT = "direct"
    COMPARATIVE = "comparative"
    REPRODUCED = "reproduced"
    INCONCLUSIVE = "inconclusive"


class ReproductionKind(StrEnum):
    CODE_DEFECT = "code_defect"
    PROVIDER_CONTRACT_DRIFT = "provider_contract_drift"
    CONTENT_CONTRACT_DRIFT = "content_contract_drift"
    INFRASTRUCTURE_CODE_DEFECT = "infrastructure_code_defect"


class DiagnosisReason(StrEnum):
    CLASSIFICATION_PENDING = "classification_pending"
    NO_FAILURE_OBSERVED = "no_failure_observed"
    ACCOUNT_STATE_OBSERVED = "account_state_observed"
    PROVIDER_DEFENSE_OBSERVED = "provider_defense_observed"
    PROVIDER_AVAILABILITY_OBSERVED = "provider_availability_observed"
    LOCAL_INFRASTRUCTURE_OBSERVED = "local_infrastructure_observed"
    REPRODUCED_CODE_DEFECT = "reproduced_code_defect"
    REPRODUCED_PROVIDER_CONTRACT_DRIFT = "reproduced_provider_contract_drift"
    REPRODUCED_CONTENT_CONTRACT_DRIFT = "reproduced_content_contract_drift"
    SOURCE_AND_OUTCOME_CHANGED = "source_and_outcome_changed"
    # Retained so archived reports remain parseable. New reports use the
    # non-causal SOURCE_AND_OUTCOME_CHANGED reason.
    CODE_REGRESSION_SUSPECTED = "code_regression_suspected"
    EXTERNAL_CHANGE_SUSPECTED = "external_change_suspected"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class DiagnosisAction(StrEnum):
    NONE = "none"
    INSPECT_CLOSED_EVIDENCE = "inspect_closed_evidence"
    OPERATOR_ACTION = "operator_action"
    COOLDOWN_OR_REVIEW = "cooldown_or_review"
    RETRY_LATER = "retry_later"
    REPAIR_ENVIRONMENT = "repair_environment"
    CREATE_REPAIR_WORKTREE = "create_repair_worktree"
    CREATE_FIXTURE = "create_fixture"


class DiagnosticFacts(FrozenModel):
    observation_codes: tuple[str, ...] = ()
    failure_categories: tuple[MintFailureCategory, ...] = ()
    browser_failure_categories: tuple[BrowserFailureCategory, ...] = ()
    failed_open_challenge_rounds: int = Field(default=0, ge=0)
    http_datadome_defense_observed: bool = False
    terminal_cloudflare_blocked: bool = False
    terminal_datadome_blocked: bool = False
    reproduced: ReproductionKind | None = None
    source_changed: bool | None = None
    behavior_changed: bool = False
    stable_observation_changed: bool = False
    run_failed: bool = True


class LiveDiagnosisSummary(FrozenModel):
    diagnosis: LiveDiagnosis = LiveDiagnosis.UNKNOWN
    evidence_strength: EvidenceStrength = EvidenceStrength.INCONCLUSIVE
    reason_codes: tuple[DiagnosisReason, ...] = (
        DiagnosisReason.CLASSIFICATION_PENDING,
    )
    repairable: bool = False
    next_action: DiagnosisAction = DiagnosisAction.INSPECT_CLOSED_EVIDENCE


_ACCOUNT_STATES = frozenset(
    {
        "account_alert",
        "consent_visible",
        "credential_rejected",
        "second_factor",
        "unsupported_second_factor",
    }
)
_ACCOUNT_FAILURES = frozenset(
    {
        MintFailureCategory.ACCOUNT_ALERT,
        MintFailureCategory.CREDENTIAL_REJECTED,
        MintFailureCategory.SECOND_FACTOR_REQUIRED,
    }
)
_LOCAL_FAILURES = frozenset(
    {
        MintFailureCategory.CLEANUP_FAILED,
        MintFailureCategory.INFRASTRUCTURE,
        MintFailureCategory.SECRET_DELIVERY_FAILED,
    }
)


def classify_live_failure(facts: DiagnosticFacts) -> LiveDiagnosisSummary:
    """Classify the same validated facts identically without model judgment."""

    observation_codes = frozenset(facts.observation_codes)
    failure_categories = frozenset(facts.failure_categories)
    if not facts.run_failed:
        return _result(
            LiveDiagnosis.UNKNOWN,
            EvidenceStrength.DIRECT,
            DiagnosisReason.NO_FAILURE_OBSERVED,
            DiagnosisAction.NONE,
        )
    if observation_codes & _ACCOUNT_STATES or failure_categories & _ACCOUNT_FAILURES:
        return _result(
            LiveDiagnosis.ACCOUNT_ACTION,
            EvidenceStrength.DIRECT,
            DiagnosisReason.ACCOUNT_STATE_OBSERVED,
            DiagnosisAction.OPERATOR_ACTION,
        )
    if (
        facts.http_datadome_defense_observed
        or facts.terminal_cloudflare_blocked
        or facts.terminal_datadome_blocked
        or facts.failed_open_challenge_rounds > 0
        or MintFailureCategory.CHALLENGE_BLOCKED in failure_categories
    ):
        return _result(
            LiveDiagnosis.PROVIDER_DEFENSE,
            EvidenceStrength.DIRECT,
            DiagnosisReason.PROVIDER_DEFENSE_OBSERVED,
            DiagnosisAction.COOLDOWN_OR_REVIEW,
        )
    if facts.reproduced is not None:
        mapping = {
            ReproductionKind.CODE_DEFECT: (
                LiveDiagnosis.CODE_DEFECT,
                DiagnosisReason.REPRODUCED_CODE_DEFECT,
            ),
            ReproductionKind.INFRASTRUCTURE_CODE_DEFECT: (
                LiveDiagnosis.CODE_DEFECT,
                DiagnosisReason.REPRODUCED_CODE_DEFECT,
            ),
            ReproductionKind.PROVIDER_CONTRACT_DRIFT: (
                LiveDiagnosis.PROVIDER_CONTRACT_DRIFT,
                DiagnosisReason.REPRODUCED_PROVIDER_CONTRACT_DRIFT,
            ),
            ReproductionKind.CONTENT_CONTRACT_DRIFT: (
                LiveDiagnosis.CONTENT_CONTRACT_DRIFT,
                DiagnosisReason.REPRODUCED_CONTENT_CONTRACT_DRIFT,
            ),
        }
        diagnosis, reason = mapping[facts.reproduced]
        return _result(
            diagnosis,
            EvidenceStrength.REPRODUCED,
            reason,
            DiagnosisAction.CREATE_REPAIR_WORKTREE,
            repairable=True,
        )

    local_failure = bool(failure_categories & _LOCAL_FAILURES)
    availability_failure = (
        MintFailureCategory.TRANSPORT_FAILURE in failure_categories
        or not observation_codes
        and (
            MintFailureCategory.TIMEOUT in failure_categories
            or BrowserFailureCategory.TIMEOUT in facts.browser_failure_categories
        )
    )
    if local_failure and availability_failure:
        return _result(
            LiveDiagnosis.UNKNOWN,
            EvidenceStrength.INCONCLUSIVE,
            DiagnosisReason.CONFLICTING_EVIDENCE,
            DiagnosisAction.INSPECT_CLOSED_EVIDENCE,
        )
    if local_failure:
        return _result(
            LiveDiagnosis.LOCAL_INFRASTRUCTURE,
            EvidenceStrength.DIRECT,
            DiagnosisReason.LOCAL_INFRASTRUCTURE_OBSERVED,
            DiagnosisAction.REPAIR_ENVIRONMENT,
        )
    if availability_failure:
        return _result(
            LiveDiagnosis.PROVIDER_AVAILABILITY,
            EvidenceStrength.DIRECT,
            DiagnosisReason.PROVIDER_AVAILABILITY_OBSERVED,
            DiagnosisAction.RETRY_LATER,
        )
    if facts.source_changed is True and facts.behavior_changed:
        return _result(
            LiveDiagnosis.UNKNOWN,
            EvidenceStrength.COMPARATIVE,
            DiagnosisReason.SOURCE_AND_OUTCOME_CHANGED,
            DiagnosisAction.CREATE_FIXTURE,
        )
    if facts.source_changed is False and facts.stable_observation_changed:
        return _result(
            LiveDiagnosis.UNKNOWN,
            EvidenceStrength.COMPARATIVE,
            DiagnosisReason.EXTERNAL_CHANGE_SUSPECTED,
            DiagnosisAction.CREATE_FIXTURE,
        )
    return _result(
        LiveDiagnosis.UNKNOWN,
        EvidenceStrength.INCONCLUSIVE,
        DiagnosisReason.INSUFFICIENT_EVIDENCE,
        DiagnosisAction.INSPECT_CLOSED_EVIDENCE,
    )


def _result(
    diagnosis: LiveDiagnosis,
    strength: EvidenceStrength,
    reason: DiagnosisReason,
    action: DiagnosisAction,
    *,
    repairable: bool = False,
) -> LiveDiagnosisSummary:
    return LiveDiagnosisSummary(
        diagnosis=diagnosis,
        evidence_strength=strength,
        reason_codes=(reason,),
        repairable=repairable,
        next_action=action,
    )


__all__ = [
    "DiagnosticFacts",
    "DiagnosisAction",
    "DiagnosisReason",
    "EvidenceStrength",
    "LiveDiagnosis",
    "LiveDiagnosisSummary",
    "ReproductionKind",
    "classify_live_failure",
]
