"""Keeper outcome persistence and the honest session-health derivation.

Guards the stale-verified deception fix (ARCHITECTURE, session upkeep): a session
whose renewals fail must stop reading as plain "verified", and consumers must
be able to rely on the derived `health` field being present.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.errors import PersistenceError
from newsclip.keeper_outcomes import (
    DEGRADED_FAILURE_STREAK,
    KeeperOutcome,
    KeeperOutcomeStore,
    enrich_session_health,
)
from newsclip.models import SessionHealth, SessionHealthState, SessionStatus
from newsclip.session_keeper import KeeperAction, KeeperResult

NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def _result(action: KeeperAction, reason: str | None = None) -> KeeperResult:
    return KeeperResult(
        provider="wsj",
        action=action,
        status=SessionStatus.VERIFIED,
        reason_code=reason,
    )


def _store(tmp_path: Path) -> KeeperOutcomeStore:
    return KeeperOutcomeStore(tmp_path / "session-keeper", utc_now=lambda: NOW)


def _health(
    status: SessionStatus = SessionStatus.VERIFIED,
    verified_ago_hours: float | None = 1.0,
) -> SessionHealth:
    verified_at = (
        NOW - timedelta(hours=verified_ago_hours)
        if verified_ago_hours is not None
        else None
    )
    return SessionHealth(provider="wsj", status=status, last_verified_at=verified_at)


# --- store: streak accounting under the lock --------------------------------


def test_failure_streak_increments_and_resets(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for expected in (1, 2, 3):
        outcome = store.record(
            _result(KeeperAction.RENEWAL_FAILED, "paid_probe_transport_failure"),
            max_age_hours=12,
        )
        assert outcome.consecutive_renewal_failures == expected
    outcome = store.record(_result(KeeperAction.RENEWED), max_age_hours=12)
    assert outcome.consecutive_renewal_failures == 0


def test_held_and_cooldown_leave_streak_unchanged(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(_result(KeeperAction.RENEWAL_FAILED, "x_y"), max_age_hours=12)
    outcome = store.record(_result(KeeperAction.HELD), max_age_hours=12)
    assert outcome.consecutive_renewal_failures == 1
    outcome = store.record(_result(KeeperAction.COOLDOWN), max_age_hours=12)
    assert outcome.consecutive_renewal_failures == 1


def test_escalation_canary_spends_once_per_window(tmp_path: Path) -> None:
    """One spend per 24h wall-clock, recorded before any dispatch could run.

    Deliberately not refunded or reset by anything: a session flapping
    through several latches in one day is a fact a person should see.
    """

    clock = {"now": NOW}
    store = KeeperOutcomeStore(
        tmp_path / "session-keeper", utc_now=lambda: clock["now"]
    )
    # No outcome history means no streak, so budget cannot be minted from
    # nothing — fails closed.
    assert store.spend_escalation_canary("wsj") is False
    store.record(_result(KeeperAction.RENEWAL_FAILED, "x_y"), max_age_hours=12)
    assert store.spend_escalation_canary("wsj") is True
    assert store.spend_escalation_canary("wsj") is False
    clock["now"] = NOW + timedelta(hours=25)
    assert store.spend_escalation_canary("wsj") is True


def test_escalation_canary_spend_from_the_future_fails_open(tmp_path: Path) -> None:
    """A spend stamped ahead of the wall clock is skew, not a fresh canary.

    Honoring it would latch the escalation until the clock caught up; the
    provider guard's incident canary already fails open the same way.
    """

    clock = {"now": NOW + timedelta(hours=6)}
    store = KeeperOutcomeStore(
        tmp_path / "session-keeper", utc_now=lambda: clock["now"]
    )
    store.record(_result(KeeperAction.RENEWAL_FAILED, "x_y"), max_age_hours=12)
    assert store.spend_escalation_canary("wsj") is True
    clock["now"] = NOW  # the wall clock stepped back six hours
    assert store.spend_escalation_canary("wsj") is True
    # The fresh spend is honored normally within its own window.
    assert store.spend_escalation_canary("wsj") is False


def test_recording_an_outcome_preserves_the_canary_spend(tmp_path: Path) -> None:
    """`record` rebuilds the outcome; the budget stamp must ride through —
    including through the successful renewal the canary itself admitted."""

    store = _store(tmp_path)
    store.record(_result(KeeperAction.RENEWAL_FAILED, "x_y"), max_age_hours=12)
    assert store.spend_escalation_canary("wsj") is True
    store.record(_result(KeeperAction.RENEWED), max_age_hours=12)
    loaded = store.load("wsj")
    assert loaded is not None
    assert loaded.consecutive_renewal_failures == 0
    assert loaded.last_escalation_canary_at == NOW


def test_roundtrip_persists_policy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record(_result(KeeperAction.FRESH), max_age_hours=6)
    loaded = store.load("wsj")
    assert loaded is not None
    assert loaded.max_age_hours == 6
    assert loaded.action == "fresh"


def test_budget_files_are_not_outcomes(tmp_path: Path) -> None:
    """The budget's wsj.json must never be parsed as an outcome."""
    store = _store(tmp_path)
    store.root.mkdir(parents=True, exist_ok=True)
    (store.root / "wsj.json").write_text('{"attempts": []}')
    assert store.load("wsj") is None


def test_malformed_outcome_is_a_persistence_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.root.mkdir(parents=True, exist_ok=True)
    (store.root / "wsj.outcome.json").write_text("not json")
    with pytest.raises(PersistenceError):
        store.load("wsj")


def test_invalid_provider_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(PersistenceError):
        _store(tmp_path).load("../escape")


def test_missing_renewal_evidence_does_not_erase_observed_failure(
    tmp_path: Path,
) -> None:
    store = KeeperOutcomeStore(
        tmp_path / "session-keeper", incident_root=tmp_path / "incidents"
    )
    store.record(_result(KeeperAction.FRESH), max_age_hours=12)
    failed = _result(KeeperAction.RENEWAL_FAILED, "provider_defense").model_copy(
        update={"incident_id": "incident-" + "a" * 24}
    )
    store.record(failed, max_age_hours=12)
    observed = store.load("wsj")
    assert observed.action == "renewal_failed"
    assert observed.consecutive_renewal_failures == 1
    assert observed.incident_id == failed.incident_id
    assert observed.renewal_reason_code == "provider_defense"


def test_legacy_outcome_retains_failure_history(tmp_path: Path) -> None:
    store = _store(tmp_path)
    prior = store.record(
        _result(KeeperAction.RENEWAL_FAILED, "provider_defense"), max_age_hours=12
    )
    (store.root / "wsj.outcome.json").write_text(
        prior.model_dump_json(
            exclude={
                "incident_id",
                "diagnostic_id",
                "schema_version",
                "renewal_reason_code",
                "observation_revision",
                "applied_revision",
                "verified_revision",
                "keeper_observed",
            }
        )
    )
    current = store.record(_result(KeeperAction.FRESH), max_age_hours=12)
    assert current.consecutive_renewal_failures == 1
    assert current.incident_id is None
    assert current.renewal_reason_code == "provider_defense"
    assert (
        enrich_session_health(_health(), current, now=NOW).last_renewal_error
        == "provider_defense"
    )


# --- derivation: the stale-verified deception ends --------------------------


def _outcome(
    failures: int, action: str = "renewal_failed", max_age_hours: float = 12
) -> KeeperOutcome:
    return KeeperOutcome(
        provider="wsj",
        action=action,
        reason_code="paid_probe_transport_failure"
        if action in {"renewal_failed", "operator_action_required"}
        else None,
        recorded_at=NOW,
        consecutive_renewal_failures=failures,
        max_age_hours=max_age_hours,
    )


def test_fresh_within_policy_age() -> None:
    enriched = enrich_session_health(_health(), _outcome(0, action="fresh"), now=NOW)
    assert enriched.health is SessionHealthState.FRESH
    assert enriched.verified_age_seconds == pytest.approx(3600.0)
    assert enriched.consecutive_renewal_failures == 0
    assert enriched.last_renewal_error is None


def test_stale_beyond_policy_age() -> None:
    enriched = enrich_session_health(
        _health(verified_ago_hours=13), _outcome(0, action="fresh"), now=NOW
    )
    assert enriched.health is SessionHealthState.STALE


def test_degraded_by_failure_streak_while_still_verified() -> None:
    """The Bloomberg case: verified 8 days ago, renewal failing hourly."""
    enriched = enrich_session_health(
        _health(verified_ago_hours=1),
        _outcome(DEGRADED_FAILURE_STREAK),
        now=NOW,
    )
    assert enriched.health is SessionHealthState.DEGRADED
    assert enriched.last_renewal_error == "paid_probe_transport_failure"


def test_degraded_by_age_without_observed_failures() -> None:
    enriched = enrich_session_health(
        _health(verified_ago_hours=4 * 12 + 1), _outcome(0, action="fresh"), now=NOW
    )
    assert enriched.health is SessionHealthState.DEGRADED


def test_non_verified_status_is_degraded() -> None:
    enriched = enrich_session_health(
        _health(status=SessionStatus.REQUIRED, verified_ago_hours=None),
        None,
        now=NOW,
    )
    assert enriched.health is SessionHealthState.DEGRADED
    assert enriched.verified_age_seconds is None


def test_no_outcome_uses_default_policy() -> None:
    """Enrichment must work before the keeper has ever run."""
    enriched = enrich_session_health(_health(verified_ago_hours=1), None, now=NOW)
    assert enriched.health is SessionHealthState.FRESH
    assert enriched.consecutive_renewal_failures == 0


def test_operator_action_reason_surfaces_as_renewal_error() -> None:
    enriched = enrich_session_health(
        _health(),
        _outcome(0, action="operator_action_required"),
        now=NOW,
    )
    assert enriched.last_renewal_error == "paid_probe_transport_failure"


# --- keeper integration: every keep() records --------------------------------


class _RecordingOutcomes:
    def __init__(self) -> None:
        self.recorded: list[tuple[KeeperResult, float]] = []

    def load(self, provider: str) -> None:
        return None

    def record(self, result: KeeperResult, *, max_age_hours: float) -> KeeperOutcome:
        self.recorded.append((result, max_age_hours))
        return KeeperOutcome(
            provider=result.provider,
            action=result.action.value,
            recorded_at=NOW,
            max_age_hours=max_age_hours,
        )


def test_keeper_records_every_verdict(tmp_path: Path) -> None:
    from newsclip.provider_guard import ProviderHold
    from newsclip.session_keeper import (
        CredentialBudget,
        KeeperPolicy,
        SessionKeeper,
    )

    class _HeldGuard:
        def current_hold_health(self, provider: str):
            return None

        def peek(self, provider: str) -> ProviderHold | None:
            return object()  # type: ignore[return-value]

    class _Sessions:
        def session_status(self, provider_key: str) -> SessionHealth:
            raise AssertionError("held provider must not read session state")

        def login(self, provider_key: str, **kwargs: object) -> SessionHealth:
            raise AssertionError("held provider must not log in")

    outcomes = _RecordingOutcomes()
    keeper = SessionKeeper(
        guard=_HeldGuard(),
        sessions=_Sessions(),
        budget=CredentialBudget(tmp_path / "budget", utc_now=lambda: NOW),
        readiness_probe=lambda provider: None,
        policy=KeeperPolicy(max_age_hours=7),
        utc_now=lambda: NOW,
        outcomes=outcomes,
    )
    result = keeper.keep("wsj", allow_credential_mint=False)
    assert result.action is KeeperAction.HELD
    assert outcomes.recorded == [(result, 7)]


def test_an_old_session_without_a_keeper_is_stale_not_degraded() -> None:
    """A workstation runs no keeper, so age alone proves nothing is failing.

    Observed 2026-07-28: a laptop Bloomberg session last verified six days
    earlier returned a full 866-word article while `newsclip health` called
    it degraded. The deep-age rule means "the keeper has not managed to renew
    this for several windows" — which presupposes a keeper. With no outcome
    history there is none, so the session is merely overdue.
    """

    health = _health(verified_ago_hours=6 * 24)
    enriched = enrich_session_health(health, None, now=NOW)
    assert enriched.health is SessionHealthState.STALE
    assert enriched.consecutive_renewal_failures == 0
    assert enriched.last_renewal_error is None


def test_the_same_age_with_keeper_evidence_is_degraded() -> None:
    """Where a keeper does run, an age several windows deep still degrades."""

    enriched = enrich_session_health(
        _health(verified_ago_hours=6 * 24), _outcome(0, action="fresh"), now=NOW
    )
    assert enriched.health is SessionHealthState.DEGRADED


def test_age_only_fresh_does_not_erase_observed_failure(tmp_path):
    store = _store(tmp_path)
    store.record(
        _result(KeeperAction.RENEWAL_FAILED, "paid_probe_inconclusive"),
        max_age_hours=12,
    )
    fresh = store.record(_result(KeeperAction.FRESH), max_age_hours=12)
    assert fresh.consecutive_renewal_failures == 1
    assert fresh.consecutive_inconclusive == 1
