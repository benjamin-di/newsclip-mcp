"""Repeated inconclusive probes require review, without diagnosing entitlement.

The keeper bounds repeated probes and retains a daily canary escape. Neither a
repeated teaser nor an unavailable canary proves that an account needs repair.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from newsclip.acquisition import (
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from newsclip.errors import ProviderTransportError
from newsclip.keeper_outcomes import KeeperOutcomeStore
from newsclip.models import AccessState, SessionHealth, SessionStatus
from newsclip.provider_check import ProviderCheckResult
from newsclip.session_keeper import (
    CredentialBudget,
    KeeperAction,
    KeeperPolicy,
    SessionKeeper,
)

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)

#: The reason code an inconclusive paid probe must carry — distinct from a
#: genuine transport failure, so the two can be told apart in the streak.
INCONCLUSIVE_REASON = MintFailureEvidence(
    stage=MintFailureStage.PAID_PROBE,
    category=MintFailureCategory.INCONCLUSIVE,
).reason_code


class _NoGuard:
    def peek(self, provider: str) -> None:
        return None


class _InconclusiveSessions:
    """Reproduces the Bloomberg fixture: the probe never resolves."""

    def __init__(self) -> None:
        self.logins = 0

    def defense_pending(self, provider_key: str) -> bool:
        return False

    def requires_session_for_provider(self, provider_key: str) -> bool:
        del provider_key
        return True

    def provider_check(self, provider_key: str):  # noqa: ANN202
        raise AssertionError("a session provider must not be watched")

    def session_status(self, provider_key: str) -> SessionHealth:
        # Verified long ago, so upkeep considers it stale and tries to renew.
        return SessionHealth(
            provider=provider_key,
            status=SessionStatus.VERIFIED,
            last_verified_at=datetime(2026, 7, 20, tzinfo=UTC),
        )

    def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
        self.logins += 1
        raise ProviderTransportError(INCONCLUSIVE_REASON)


def _keeper(tmp_path: Path, sessions: _InconclusiveSessions) -> SessionKeeper:
    return SessionKeeper(
        guard=_NoGuard(),
        sessions=sessions,
        budget=CredentialBudget(tmp_path / "budget", utc_now=lambda: NOW),
        readiness_probe=lambda provider: None,
        policy=KeeperPolicy(),
        utc_now=lambda: NOW,
        outcomes=KeeperOutcomeStore(tmp_path / "outcomes", utc_now=lambda: NOW),
    )


def test_inconclusive_probe_has_its_own_reason_code() -> None:
    """It must be distinguishable from a real network failure."""

    transport = MintFailureEvidence(
        stage=MintFailureStage.PAID_PROBE,
        category=MintFailureCategory.TRANSPORT_FAILURE,
    ).reason_code
    assert transport != INCONCLUSIVE_REASON
    assert INCONCLUSIVE_REASON == "paid_probe_inconclusive"


def test_a_single_inconclusive_probe_stays_a_retryable_failure(
    tmp_path: Path,
) -> None:
    """Per-attempt caution is preserved: one teaser is not a verdict."""

    sessions = _InconclusiveSessions()
    keeper = _keeper(tmp_path, sessions)
    result = keeper.keep("bloomberg", allow_credential_mint=False)
    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.reason_code == INCONCLUSIVE_REASON


def test_an_inconclusive_streak_escalates_to_verification_review(
    tmp_path: Path,
) -> None:
    """The eight-day Bloomberg loop must end in an actionable escalation."""

    sessions = _InconclusiveSessions()
    keeper = _keeper(tmp_path, sessions)

    for _ in range(3):
        keeper.keep("bloomberg", allow_credential_mint=False)
    probes_before = sessions.logins

    result = keeper.keep("bloomberg", allow_credential_mint=False)
    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "session_verification_unresolved"
    assert result.needs_attention is True
    # It also stops paying for a probe that cannot resolve anything.
    assert sessions.logins == probes_before


def test_escalation_does_not_fire_for_ordinary_transport_failures(
    tmp_path: Path,
) -> None:
    """A flaky network must keep retrying, not be relabelled a dead session."""

    transport_reason = MintFailureEvidence(
        stage=MintFailureStage.PAID_PROBE,
        category=MintFailureCategory.TRANSPORT_FAILURE,
    ).reason_code

    class _FlakySessions(_InconclusiveSessions):
        def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
            self.logins += 1
            raise ProviderTransportError(transport_reason)

    sessions = _FlakySessions()
    keeper = _keeper(tmp_path, sessions)
    for _ in range(5):
        result = keeper.keep("bloomberg", allow_credential_mint=False)
    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.reason_code == transport_reason


def test_a_recovered_session_resets_the_streak(tmp_path: Path) -> None:
    """Escalation must not latch: one good renewal clears the history."""

    class _RecoveringSessions(_InconclusiveSessions):
        def __init__(self) -> None:
            super().__init__()
            self.recovered = False

        def session_status(self, provider_key: str) -> SessionHealth:
            if self.recovered:
                return SessionHealth(
                    provider=provider_key,
                    status=SessionStatus.VERIFIED,
                    last_verified_at=NOW,
                )
            return super().session_status(provider_key)

        def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
            self.logins += 1
            if self.recovered:
                return SessionHealth(
                    provider=provider_key, status=SessionStatus.VERIFIED
                )
            raise ProviderTransportError(INCONCLUSIVE_REASON)

    sessions = _RecoveringSessions()
    keeper = _keeper(tmp_path, sessions)
    # Cross the escalation threshold before the external promotion. Historical
    # failure state must not override current verified authority.
    for _ in range(3):
        keeper.keep("bloomberg", allow_credential_mint=False)

    sessions.recovered = True
    # External promotion fires the same positive-verification event as login.
    # Merely seeing a young timestamp in a later keeper tick is not proof.
    keeper._outcomes.verified("bloomberg")
    assert keeper.keep("bloomberg", allow_credential_mint=False).action is (
        KeeperAction.FRESH
    )

    # Streak cleared: a later inconclusive run starts counting again.
    sessions.recovered = False
    result = keeper.keep("bloomberg", allow_credential_mint=False)
    assert result.action is KeeperAction.RENEWAL_FAILED


@pytest.mark.parametrize("reason", ["paywall_teaser", "insufficient_article_structure"])
def test_retained_bloomberg_probe_shape_is_inconclusive_not_dead(
    reason: str,
) -> None:
    """An identity-matched teaser with a cookie is inconclusive in isolation.

    Only the repeated-failure policy may downgrade its session generation.
    """

    from newsclip.acquisition import verification_verdict
    from newsclip.models import AccessState, SessionDisposition, SessionVerification

    verification = SessionVerification(
        verified=False,
        access_state=AccessState.TEASER,
        reason=reason,
        verified_at=NOW,
    )
    assert verification_verdict(verification) is SessionDisposition.INCONCLUSIVE
    # And the shape that WOULD prove death is distinct, so the escalation
    # never fires where a real downgrade already handles it.
    dead = SessionVerification(
        verified=False,
        access_state=AccessState.AUTH_REQUIRED,
        reason="authentication_required",
        verified_at=NOW,
    )
    assert verification_verdict(dead) is SessionDisposition.DEAD


def test_alternating_reasons_still_accumulate(tmp_path: Path) -> None:
    """Alternating inconclusive and transport failures still form a streak."""

    transport_reason = MintFailureEvidence(
        stage=MintFailureStage.PAID_PROBE,
        category=MintFailureCategory.TRANSPORT_FAILURE,
    ).reason_code

    class _AlternatingSessions(_InconclusiveSessions):
        def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
            self.logins += 1
            reason = INCONCLUSIVE_REASON if self.logins % 2 else transport_reason
            raise ProviderTransportError(reason)

    sessions = _AlternatingSessions()
    keeper = _keeper(tmp_path, sessions)
    # 1 inconclusive, 2 transport, 3 inconclusive, 4 transport, 5 inconclusive
    for _ in range(5):
        keeper.keep("bloomberg", allow_credential_mint=False)
    probes_before = sessions.logins

    result = keeper.keep("bloomberg", allow_credential_mint=False)
    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "session_verification_unresolved"
    assert sessions.logins == probes_before


def test_escalation_holds_and_does_not_flap(tmp_path: Path) -> None:
    """Once escalated it must STAY escalated while the condition persists.

    The first implementation keyed on the previous outcome's reason, so the
    escalation itself (session_verification_unresolved) stopped matching and the
    keeper went straight back to probing — an alternation, not a stop.
    """

    sessions = _InconclusiveSessions()
    keeper = _keeper(tmp_path, sessions)
    for _ in range(3):
        keeper.keep("bloomberg", allow_credential_mint=False)
    probes_before = sessions.logins

    for _ in range(4):
        result = keeper.keep("bloomberg", allow_credential_mint=False)
        assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
        assert result.reason_code == "session_verification_unresolved"
    assert sessions.logins == probes_before  # never probes again


def test_escalation_canary_accepts_full_article_aged_out_of_search(
    tmp_path: Path,
) -> None:
    """A FULL canary whose URL aged out of search still contradicts the latch.

    The search advisory is not a failure; only retrieval decides, so the
    escalation admits its one renewal exactly as for a ranked canary.
    """

    class _AgedCanarySessions(_InconclusiveSessions):
        def provider_check(self, provider_key: str) -> ProviderCheckResult:
            return ProviderCheckResult(
                provider=provider_key,
                ok=True,
                search_result_count=20,
                canary_in_search=False,
                http_status=200,
                access_state=AccessState.FULL,
                reason="full_article_verified",
                identity_match=True,
                word_count=900,
            )

    sessions = _AgedCanarySessions()
    keeper = _keeper(tmp_path, sessions)
    for _ in range(3):
        keeper.keep("bloomberg", allow_credential_mint=False)
    probes_before = sessions.logins

    result = keeper.keep("bloomberg", allow_credential_mint=False)

    assert result.action is KeeperAction.RENEWAL_FAILED
    assert sessions.logins == probes_before + 1
