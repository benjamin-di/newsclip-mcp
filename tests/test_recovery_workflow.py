"""Incident sequences across persistence, keeper, and the local watcher.

External authority is fake; scheduling, reservation, recovery, and reporting
are the real implementations, driven by the same controllable UTC clock.
"""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_session_keeper import (
    NOW,
    FakeGuard,
    RecoverySessions,
    _check,
    _recovery_keeper,
)

from newsclip.errors import ContentNotFullError, SessionRequiredError
from newsclip.models import RecoveryStatus
from newsclip.provider_check import ProviderCheckObservation
from newsclip.recovery import RecoveryStore
from newsclip.recovery_watch import RecoveryWatch, _run


def _workflow(tmp_path, sessions=None):
    keeper, sessions, store, record, budget = _recovery_keeper(tmp_path, sessions)
    clock = SimpleNamespace(now=NOW)
    store._now = lambda: clock.now
    keeper._utc_now = lambda: clock.now
    return keeper, sessions, store, record, budget, clock


def _request(store, sessions, suffix):
    return store.request(
        "ft",
        generation_id=sessions.generation,
        url=f"https://www.ft.com/content/{suffix}",
        incident_id=None,
        diagnostic_id=f"mcp-{suffix}",
    )


def _watch(store, keeper, clock):
    return RecoveryWatch(
        store,
        ("ft",),
        allow_credentials=True,
        runner=lambda provider, allow, timeout: keeper.keep(
            provider, allow_credential_mint=allow, recovery_only=True
        ).public_dict(),
        utc_now=lambda: clock.now,
    )


def _complete_tick(watcher):
    assert watcher.tick() == []
    assert set(watcher.active) == {"ft"}
    watcher.active["ft"].result(timeout=5)
    outcomes = watcher.tick()
    assert len(outcomes) == 1
    assert not watcher.active
    return outcomes[0]


def test_spent_prior_episodes_resume_original_article_at_window_expiry(tmp_path):
    keeper, sessions, store, _, budget, clock = _workflow(tmp_path)
    prior_ids = []
    for index in range(3):
        keeper._diagnostic_id = f"cli-prior-{index}"
        recovered = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
        assert recovered.recovery.article_verified
        assert recovered.recovery.episode_attempts == 1
        prior_ids.append(recovered.recovery.request_id)
        clock.now += timedelta(minutes=20)
        target = _request(store, sessions, f"episode-{index + 1}")

    assert target.health.attempts == 3
    assert target.health.episode_attempts == 0
    blocked = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    waiting = store.load("ft")
    assert waiting.health.status is RecoveryStatus.PENDING
    assert waiting.health.reason == "recovery_budget_spent"
    assert waiting.health.next_attempt_at == NOW + timedelta(days=1)
    assert blocked.next_action.value == "wait_for_recovery"
    assert len(sessions.article_checks) == 3

    # A newly constructed store/worker proves the scheduled continuation is
    # durable and does not depend on a reader creating another request.
    restarted = RecoveryStore(store.root, utc_now=lambda: clock.now)
    keeper._recovery_store = restarted
    watcher = _watch(restarted, keeper, clock)
    try:
        assert watcher.tick() == []
        assert not watcher.active
        clock.now = NOW + timedelta(days=1)
        keeper._diagnostic_id = "cli-window-resumed"
        outcome = _complete_tick(watcher)
    finally:
        watcher.close()
    final = restarted.load("ft")
    assert final.health.request_id == target.health.request_id
    assert final.health.request_id not in prior_ids
    assert final.health.status is RecoveryStatus.SUCCEEDED
    assert final.health.attempts == final.health.episode_attempts == 1
    assert sessions.article_checks[-1] == str(target.url)
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
    assert outcome["overall_state"] == "healthy"
    assert outcome.get("next_action") is None
    assert [attempt.diagnostic_id for attempt in final.health.recent_attempts] == [
        "cli-prior-0",
        "cli-prior-1",
        "cli-prior-2",
        "cli-window-resumed",
    ]


def test_legacy_failed_budget_latch_migrates_and_wakes_without_guessing_history(
    tmp_path,
):
    keeper, sessions, store, original, _, clock = _workflow(tmp_path)
    legacy = original.model_dump(mode="json")
    legacy["schema_version"] = 1
    legacy["health"].update(
        status="failed",
        attempts=3,
        reason="recovery_budget_spent",
        next_attempt_at=None,
    )
    for field in (
        "episode_attempts",
        "budget_reset_at",
        "incident_id",
        "recent_attempts",
    ):
        legacy["health"].pop(field)
    (store.root / "ft.json").write_text(json.dumps(legacy))
    watcher = _watch(store, keeper, clock)
    try:
        assert watcher.tick() == []
        assert not watcher.active
        migrated = store.load("ft")
        assert migrated.schema_version == 2
        assert migrated.health.episode_attempts is None
        assert migrated.health.next_attempt_at == NOW + timedelta(days=1)
        waiting = keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
        assert waiting.overall_state.value == "waiting"
        assert waiting.next_action.value == "wait_for_recovery"
        assert not waiting.recovery.article_verified
        clock.now += timedelta(days=1)
        _complete_tick(watcher)
    finally:
        watcher.close()
    final = store.load("ft")
    assert final.health.request_id == original.health.request_id
    assert final.health.episode_attempts is None
    assert final.health.attempts == 1
    assert final.health.article_verified
    assert sessions.article_checks == [str(original.url)]
    assert sessions.logins == []


def test_crash_after_explicit_session_loss_persists_stage_and_never_replays_login(
    tmp_path, monkeypatch
):
    sessions = RecoverySessions(article_failure=SessionRequiredError("session_missing"))
    keeper, sessions, store, original, budget, _ = _workflow(tmp_path, sessions)
    login = sessions.login

    class ProcessExit(BaseException):
        pass

    def crash_login(*args, **kwargs):
        assert store.load("ft").session_required is True
        raise ProcessExit

    monkeypatch.setattr(sessions, "login", crash_login)
    keeper._diagnostic_id = "cli-before-crash"
    with pytest.raises(ProcessExit):
        keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    interrupted = store.load("ft")
    assert interrupted.health.status is RecoveryStatus.RUNNING
    assert interrupted.session_required
    assert interrupted.health.attempts == 1
    monkeypatch.setattr(sessions, "login", login)
    keeper._diagnostic_id = "cli-reconcile-crash"
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.recovery.status is RecoveryStatus.FAILED
    assert not result.recovery.article_verified
    assert sessions.article_checks == [str(original.url), str(original.url)]
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
    assert store.load("ft").health.attempts == 1
    assert (
        store.load("ft").health.recent_attempts[0].diagnostic_id == "cli-before-crash"
    )


def test_heal_instructions_obey_backoff_proof_consumption_and_provider_cap(tmp_path):
    sessions = RecoverySessions(article_failure=ContentNotFullError("paywall_teaser"))
    keeper, sessions, store, _, budget, clock = _workflow(tmp_path, sessions)
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)

    def proof():
        keeper._guard = FakeGuard(
            observation=ProviderCheckObservation(
                provider="ft",
                checked_at=clock.now,
                check=_check(ok=True, provider="ft"),
            )
        )

    clock.now += timedelta(seconds=1)
    proof()
    blocked = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert blocked.recovery_blocker == "recovery_backoff"
    assert blocked.next_action.value == "wait_for_recovery"
    assert len(sessions.article_checks) == 1
    clock.now = NOW + timedelta(minutes=20)
    ready = keeper.inspect_recovery("ft")
    assert ready.recovery_blocker == "ready"
    assert ready.next_action.value == "wait_for_recovery"
    keeper.keep("ft", allow_credential_mint=False, reconcile_failed_recovery=True)
    assert len(sessions.article_checks) == 2

    clock.now += timedelta(minutes=20)
    repeated = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert repeated.recovery_blocker == "provider_check_required"
    assert repeated.next_action.value == "review_recovery"
    assert len(sessions.article_checks) == 2
    proof()
    keeper.keep("ft", allow_credential_mint=False, reconcile_failed_recovery=True)
    assert len(sessions.article_checks) == 3
    clock.now += timedelta(minutes=20)
    proof()
    exhausted = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert exhausted.recovery_blocker == "recovery_budget_spent"
    assert exhausted.next_action.value == "review_recovery"
    assert exhausted.recovery_retry_at == NOW + timedelta(days=1)
    assert len(sessions.article_checks) == 3
    assert store.load("ft").health.attempts == 3
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0


def test_malformed_worker_output_settles_failed_and_requests_review(
    tmp_path, monkeypatch
):
    keeper, sessions, store, _, _, clock = _workflow(tmp_path)
    monkeypatch.setattr(
        "newsclip.recovery_watch.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=b"PRIVATE broken output", returncode=1
        ),
    )
    watcher = RecoveryWatch(
        store, ("ft",), allow_credentials=True, runner=_run, utc_now=lambda: clock.now
    )
    try:
        outcome = _complete_tick(watcher)
        assert outcome == {
            "provider": "ft",
            "action": "recovery_worker_failed",
            "exit_code": 1,
        }
        assert watcher.tick() == []
        assert not watcher.active
    finally:
        watcher.close()
    failed = store.load("ft")
    assert failed.health.status is RecoveryStatus.FAILED
    assert failed.health.reason == "recovery_worker_failed"
    assert failed.health.attempts == 0
    result = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert result.recovery_blocker == "review_recovery"
    assert result.next_action.value == "review_recovery"
    assert sessions.article_checks == sessions.logins == []


def test_dispatch_history_is_bounded_across_episodes_without_losing_recent_ids(
    tmp_path,
):
    keeper, sessions, store, _, _, clock = _workflow(tmp_path)
    for index in range(8):
        keeper._diagnostic_id = f"cli-episode-{index}"
        result = keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
        assert result.recovery.article_verified
        if index != 7:
            clock.now += timedelta(days=1)
            _request(store, sessions, f"history-{index}")
    history = store.load("ft").health.recent_attempts
    assert [item.diagnostic_id for item in history] == [
        f"cli-episode-{i}" for i in range(2, 8)
    ]
    assert len({item.request_id for item in history}) == 6
    assert all(
        item.completed_at is not None and item.article_verified for item in history
    )


@pytest.mark.parametrize(
    "reason", ["account_action", "recovery_worker_failed", "interrupted_reconciliation"]
)
def test_current_safe_authority_and_new_proof_can_resolve_historical_failure(
    tmp_path, reason
):
    from newsclip.models import SessionStatus

    keeper, sessions, store, _, budget, clock = _workflow(tmp_path)
    record = store.claim("ft", "cli-old-failure")
    store.finish(record, reason=reason)
    clock.now += timedelta(days=2)
    keeper._guard = FakeGuard(
        observation=ProviderCheckObservation(
            provider="ft",
            checked_at=clock.now,
            check=_check(ok=True, provider="ft"),
        )
    )
    # Current account action must still stop even a newer positive canary.
    sessions.status = SessionStatus.OPERATOR_ACTION
    denied = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert denied.next_action.value == "review_account"
    assert sessions.article_checks == []
    sessions.status = SessionStatus.VERIFIED
    outcome = keeper.keep(
        "ft", allow_credential_mint=False, reconcile_failed_recovery=True
    )
    assert outcome.recovery.article_verified
    assert len(sessions.article_checks) == 1
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
