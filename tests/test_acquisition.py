from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from newsclip.acquisition import (
    AcquisitionEvidence,
    AcquisitionMode,
    CandidateVerificationMode,
    CredentialAction,
    FlowCandidate,
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
    session_wide_verdict,
    verification_verdict,
)
from newsclip.models import (
    AccessState,
    PortableCookie,
    RawFetch,
    SessionArtifact,
    SessionDisposition,
    SessionVerification,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)


def _artifact() -> SessionArtifact:
    return SessionArtifact(
        generation_id=uuid4(),
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
        cookies=(
            PortableCookie(
                name="session",
                value="private-cookie",
                domain=".fixture.test",
                expires=(NOW + timedelta(days=1)).timestamp(),
            ),
        ),
    )


def _verification_fetch() -> RawFetch:
    return RawFetch(
        requested_url="https://fixture.test/article",
        final_url="https://fixture.test/article",
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=b"<article>fixture paid proof</article>",
    )


def test_acquisition_evidence_is_action_derived_and_closed() -> None:
    credential = AcquisitionEvidence(
        mode=AcquisitionMode.CREDENTIAL_MINT,
        credential_action=CredentialAction.PASSWORD_SUBMIT,
        callback_confirmed=False,
        session_proof_observed=True,
    )

    assert credential.public_dict() == {
        "mode": "credential_mint",
        "credential_action": "password_submit",
        "callback_confirmed": False,
        "session_proof_observed": True,
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AcquisitionEvidence.model_validate(
            {**credential.model_dump(), "force_remint": True}
        )
    with pytest.raises(ValidationError, match="credential action"):
        AcquisitionEvidence(
            mode=AcquisitionMode.ARTIFACT_REUSE,
            credential_action=CredentialAction.PASSWORD_SUBMIT,
        )
    with pytest.raises(ValidationError, match="observed credential action"):
        AcquisitionEvidence(mode=AcquisitionMode.CREDENTIAL_MINT)


def test_flow_candidate_cannot_claim_session_proof_before_core_verification() -> None:
    with pytest.raises(ValidationError, match="cannot claim verified session proof"):
        FlowCandidate(
            artifact=_artifact(),
            candidate_verification_mode=CandidateVerificationMode.HTTP_PROBE,
            evidence=AcquisitionEvidence(
                mode=AcquisitionMode.PROFILE_REHYDRATE,
                session_proof_observed=True,
            ),
        )


def test_browser_paid_candidate_requires_exactly_one_verification_fetch() -> None:
    with pytest.raises(ValidationError, match="requires exactly one"):
        FlowCandidate(
            artifact=_artifact(),
            candidate_verification_mode=CandidateVerificationMode.BROWSER_PAID_PROBE,
            evidence=AcquisitionEvidence(mode=AcquisitionMode.PROFILE_REHYDRATE),
        )
    with pytest.raises(ValidationError, match="requires exactly one"):
        FlowCandidate(
            artifact=_artifact(),
            candidate_verification_mode=CandidateVerificationMode.HTTP_PROBE,
            evidence=AcquisitionEvidence(mode=AcquisitionMode.PROFILE_REHYDRATE),
            verification_fetch=_verification_fetch(),
        )


def test_mint_failure_evidence_exposes_only_bounded_enums() -> None:
    failure = MintFailureEvidence(
        stage=MintFailureStage.CHALLENGE,
        category=MintFailureCategory.CHALLENGE_BLOCKED,
    )

    assert failure.reason_code == "challenge_challenge_blocked"
    assert failure.public_dict() == {
        "stage": "challenge",
        "category": "challenge_blocked",
    }
    with pytest.raises(ValidationError):
        MintFailureEvidence.model_validate(
            {
                "stage": "challenge",
                "category": "challenge_blocked",
                "exception": "PRIVATE_EXCEPTION_SENTINEL",
            }
        )


def _verification(
    *,
    access_state: AccessState,
    verified: bool = False,
    reason: str = "fixture",
) -> SessionVerification:
    return SessionVerification(
        verified=verified,
        access_state=access_state,
        reason=reason,
        verified_at=datetime(2026, 7, 25, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("probe_state", "verified", "target_state", "expected"),
    (
        (
            AccessState.TEASER,
            False,
            AccessState.TEASER,
            SessionDisposition.NOT_ENTITLED,
        ),
        # One shortfall stays article-specific and must not downgrade.
        (
            AccessState.TEASER,
            False,
            AccessState.FULL,
            SessionDisposition.INCONCLUSIVE,
        ),
        (
            AccessState.UNKNOWN,
            False,
            AccessState.TEASER,
            SessionDisposition.INCONCLUSIVE,
        ),
        # Direct authentication evidence still outranks the correlation.
        (
            AccessState.AUTH_REQUIRED,
            False,
            AccessState.TEASER,
            SessionDisposition.DEAD,
        ),
        (
            AccessState.FULL,
            True,
            AccessState.FULL,
            SessionDisposition.VERIFIED,
        ),
    ),
)
def test_session_wide_verdict_needs_two_independent_shortfalls(
    probe_state: AccessState,
    verified: bool,
    target_state: AccessState,
    expected: SessionDisposition,
) -> None:
    verdict = session_wide_verdict(
        _verification(access_state=probe_state, verified=verified),
        target_access_state=target_state,
    )

    assert verdict is expected


def test_lone_probe_verdict_cannot_reach_the_session_wide_state() -> None:
    """The uncorrelated call site must keep preserving the generation."""

    verdict = verification_verdict(_verification(access_state=AccessState.TEASER))

    assert verdict is SessionDisposition.INCONCLUSIVE


def test_a_blocked_target_cannot_reach_the_session_wide_state() -> None:
    """Defense evidence is not entitlement evidence, in either position."""

    assert (
        session_wide_verdict(
            _verification(access_state=AccessState.BLOCKED),
            target_access_state=AccessState.TEASER,
        )
        is SessionDisposition.INCONCLUSIVE
    )
    assert (
        session_wide_verdict(
            _verification(access_state=AccessState.TEASER),
            target_access_state=AccessState.BLOCKED,
        )
        is SessionDisposition.INCONCLUSIVE
    )
