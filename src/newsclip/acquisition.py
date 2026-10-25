"""Typed internal contracts for warm-first session acquisition."""

from __future__ import annotations

from enum import StrEnum

from pydantic import model_validator

from .challenges import ChallengeMode as ChallengeMode
from .models import (
    AccessState,
    FrozenModel,
    MintOutcome,
    RawFetch,
    SessionArtifact,
    SessionDisposition,
    SessionHealth,
    SessionVerification,
)


def verification_verdict(
    verification: SessionVerification,
) -> SessionDisposition:
    """Classify probes without turning provider trouble into login trouble.

    Only an authenticated full article proves success, while an explicit
    authentication wall proves the session dead. A teaser may be article-
    specific or transient, so it and every other result are inconclusive and
    must preserve the existing session generation.
    """

    return verification.disposition


def session_wide_verdict(
    verification: SessionVerification,
    *,
    target_access_state: AccessState,
) -> SessionDisposition:
    """Correlate the pinned probe with an independently requested target.

    One teaser stays inconclusive because it may be article-specific. The
    verification article is not the requested target, so when both fall short
    the shortfall is session-wide: the session is live but is not delivering
    paid content. An operator resolves that by promoting a session, not by
    waiting for the current one to prove itself.

    Only this correlated call site can reach the verdict; a lone probe keeps
    using :func:`verification_verdict` and cannot downgrade a session.
    """

    disposition = verification.disposition
    if (
        disposition is SessionDisposition.INCONCLUSIVE
        and verification.access_state is AccessState.TEASER
        and target_access_state is AccessState.TEASER
    ):
        return SessionDisposition.NOT_ENTITLED
    return disposition


class AcquisitionMode(StrEnum):
    """How an authenticated session was demonstrably obtained."""

    ARTIFACT_REUSE = "artifact_reuse"
    PROFILE_REHYDRATE = "profile_rehydrate"
    CREDENTIAL_MINT = "credential_mint"


class CandidateVerificationMode(StrEnum):
    """How an in-flow browser candidate proves paid session authority."""

    HTTP_PROBE = "http_probe"
    BROWSER_PAID_PROBE = "browser_paid_probe"


class CredentialAction(StrEnum):
    """The strongest provider-owned credential action actually observed."""

    NONE = "none"
    PASSWORD_SUBMIT = "password_submit"
    GOOGLE_PASSWORD_SUBMIT = "google_password_submit"
    GOOGLE_PASSWORD_AUTO_SUBMIT = "google_password_auto_submit"
    GOOGLE_TOTP_SUBMIT = "google_totp_submit"


class MintFailureStage(StrEnum):
    PROFILE = "profile"
    CHALLENGE = "challenge"
    CREDENTIAL = "credential"
    CALLBACK = "callback"
    SESSION = "session"
    PAID_PROBE = "paid_probe"
    TRANSPORT = "transport"
    CLEANUP = "cleanup"
    UNKNOWN = "unknown"


class MintFailureCategory(StrEnum):
    CONTROL_MISSING = "control_missing"
    CHALLENGE_BLOCKED = "challenge_blocked"
    CREDENTIAL_REJECTED = "credential_rejected"
    SECOND_FACTOR_REQUIRED = "second_factor_required"
    ACCOUNT_ALERT = "account_alert"
    CALLBACK_NOT_CONFIRMED = "callback_not_confirmed"
    SESSION_MISSING = "session_missing"
    ARTICLE_NOT_FULL = "article_not_full"
    TIMEOUT = "timeout"
    #: A probe that completed but could not decide. Distinct from
    #: TRANSPORT_FAILURE on purpose: the request worked, so retrying the
    #: network changes nothing, and conflating the two hid an unentitled
    #: Bloomberg session behind "transport failure" for eight days.
    INCONCLUSIVE = "inconclusive"
    TRANSPORT_FAILURE = "transport_failure"
    CLEANUP_FAILED = "cleanup_failed"
    SECRET_DELIVERY_FAILED = "secret_delivery_failed"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class AcquisitionEvidence(FrozenModel):
    """Frozen facts derived from actions, never from caller intent."""

    mode: AcquisitionMode
    credential_action: CredentialAction = CredentialAction.NONE
    callback_confirmed: bool = False
    session_proof_observed: bool = False

    @model_validator(mode="after")
    def validate_mode(self) -> AcquisitionEvidence:
        credential_action = self.credential_action is not CredentialAction.NONE
        if self.mode is AcquisitionMode.CREDENTIAL_MINT and not credential_action:
            raise ValueError("credential_mint requires an observed credential action")
        if self.mode is not AcquisitionMode.CREDENTIAL_MINT and credential_action:
            raise ValueError("warm acquisition cannot carry a credential action")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class MintFailureEvidence(FrozenModel):
    """Bounded failure evidence safe for public and durable output."""

    stage: MintFailureStage
    category: MintFailureCategory

    @property
    def reason_code(self) -> str:
        return f"{self.stage.value}_{self.category.value}"

    def public_dict(self) -> dict[str, str]:
        return self.model_dump(mode="json")


class FlowCandidate(FrozenModel):
    """Non-persistable browser-flow output awaiting provider FULL proof."""

    artifact: SessionArtifact
    candidate_verification_mode: CandidateVerificationMode
    evidence: AcquisitionEvidence
    verification_fetch: RawFetch | None = None
    refresh_failure: MintFailureEvidence | None = None

    @model_validator(mode="after")
    def validate_session_proof(self) -> FlowCandidate:
        if self.evidence.session_proof_observed:
            raise ValueError("flow candidate cannot claim verified session proof")
        browser_proof = (
            self.candidate_verification_mode
            is CandidateVerificationMode.BROWSER_PAID_PROBE
        )
        if browser_proof != (self.verification_fetch is not None):
            raise ValueError(
                "browser-paid candidate requires exactly one verification fetch"
            )
        if (
            self.refresh_failure is not None
            and self.evidence.mode is AcquisitionMode.CREDENTIAL_MINT
        ):
            raise ValueError("failed refresh cannot report credential_mint")
        return self


class AcquiredSession(FrozenModel):
    """Internal verified artifact plus the action-derived acquisition facts."""

    artifact: SessionArtifact
    evidence: AcquisitionEvidence
    refresh_failure: MintFailureEvidence | None = None


class LoginResult(FrozenModel):
    """Redacted explicit-login result exposed by the service and CLI."""

    health: SessionHealth
    acquisition: AcquisitionEvidence
    refresh_failure: MintFailureEvidence | None = None

    def public_dict(self) -> dict[str, object]:
        value = self.health.public_dict()
        value["acquisition"] = self.acquisition.public_dict()
        value["refresh_failure"] = (
            self.refresh_failure.public_dict() if self.refresh_failure else None
        )
        return value


class AcquisitionFailure(RuntimeError):
    """Typed provider-flow failure with no raw DOM or exception text."""

    def __init__(
        self,
        outcome: MintOutcome,
        evidence: MintFailureEvidence,
    ) -> None:
        self.outcome = outcome
        self.evidence = evidence
        super().__init__(evidence.reason_code)
