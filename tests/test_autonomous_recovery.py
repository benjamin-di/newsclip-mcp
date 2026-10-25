"""Bounded unattended recovery across actual store, keeper and watcher paths."""

from datetime import timedelta
from uuid import uuid4

import pytest
from test_recovery_workflow import _complete_tick, _watch, _workflow
from test_session_keeper import FakeGuard, RecoverySessions, _check

from newsclip.errors import (
    BrowserAuthorityChangedError,
    ContentNotFullError,
    OperatorActionRequiredError,
    ProviderContractError,
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
    TransportFailure,
    retryable_read_reason,
)
from newsclip.models import RecoveryStatus, SessionStatus
from newsclip.provider_check import ProviderCheckFailure, ProviderCheckObservation
from newsclip.recovery import RecoveryStore


def _proof(keeper, at, *, ok=True):
    keeper._guard = FakeGuard(
        observation=ProviderCheckObservation(
            provider="ft",
            checked_at=at,
            check=_check(
                ok=ok,
                provider="ft",
                failure=None if ok else ProviderCheckFailure.CONTENT_NOT_FULL,
            ),
        )
    )


@pytest.mark.parametrize(
    "category",
    [TransportFailure.TIMEOUT, TransportFailure.DNS, TransportFailure.PROVIDER_ERROR],
)
def test_transient_read_retries_once_without_canary_or_credentials(tmp_path, category):
    sessions = RecoverySessions(
        article_failure=ProviderTransportError("temporary read", category=category)
    )
    keeper, sessions, store, original, budget, clock = _workflow(tmp_path, sessions)
    failed = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    due = clock.now + timedelta(minutes=20)
    assert failed.automatic_recovery_action == "retry_article"
    assert failed.automatic_recovery_due_at == due
    assert failed.overall_state.value == "waiting"
    assert not failed.needs_attention
    assert failed.next_action.value == "wait_for_recovery"
    sessions.article_failure = None
    watcher = _watch(store, keeper, clock)
    try:
        clock.now = due - timedelta(seconds=1)
        assert watcher.tick() == []
        assert not watcher.active
        clock.now = due
        outcome = _complete_tick(watcher)
    finally:
        watcher.close()
    final = store.load("ft")
    assert final.health.status is RecoveryStatus.SUCCEEDED
    assert final.health.episode_attempts == final.health.attempts == 2
    assert final.reconciliation_started
    assert final.last_reconciliation_check_at is None
    assert outcome["overall_state"] == "healthy"
    assert sessions.article_checks == [str(original.url)] * 2
    assert sessions.logins == sessions.checks == []
    assert budget.attempts_today("ft") == 0


@pytest.mark.parametrize(
    "error",
    [
        ProviderTransportError("ordinary transport"),
        ProviderTransportError(
            "not retryable", category=TransportFailure.TIMEOUT, retryable=False
        ),
        ProviderContractError("read_timeout", category=TransportFailure.TIMEOUT),
        ProviderDefenseError("read_timeout"),
        BrowserAuthorityChangedError(),
        OperatorActionRequiredError("account_action"),
        RuntimeError("unknown"),
    ],
)
def test_unsupported_failures_cannot_become_automatic_retries_even_with_healthy_proof(
    tmp_path, error
):
    assert retryable_read_reason(error) is None
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path, RecoverySessions(article_failure=error)
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    clock.now += timedelta(minutes=20)
    _proof(keeper, clock.now)
    keeper.keep("ft", allow_credential_mint=False)
    assert sessions.article_checks == [str(original.url)]
    assert sessions.logins == []
    assert store.load("ft").health.status is RecoveryStatus.FAILED
    assert keeper.inspect_recovery("ft").automatic_recovery_action == "review"


@pytest.mark.parametrize("proof_kind", ["missing", "stale", "future", "failed"])
def test_ambiguous_content_waits_for_proof_without_watcher_probes(tmp_path, proof_kind):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    failure_time = clock.now
    clock.now += timedelta(minutes=20)
    if proof_kind != "missing":
        _proof(
            keeper,
            failure_time
            if proof_kind == "stale"
            else clock.now + timedelta(seconds=1)
            if proof_kind == "future"
            else clock.now,
            ok=proof_kind != "failed",
        )
    watched = _watch(store, keeper, clock)
    try:
        assert watched.tick() == []
        assert not watched.active
    finally:
        watched.close()
    result = keeper.keep("ft", allow_credential_mint=False)
    assert result.automatic_recovery_action == "wait_for_provider_check"
    assert result.automatic_recovery_due_at == (
        None if proof_kind == "failed" else failure_time + timedelta(hours=25)
    )
    assert sessions.article_checks == [str(original.url)]
    assert sessions.logins == sessions.checks == []


def test_daily_proof_is_consumed_automatically_once_and_shared_with_direct_retry(
    tmp_path,
):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    clock.now += timedelta(minutes=20)
    _proof(keeper, clock.now)
    sessions.article_failure = ProviderTransportError(
        "temporary", category=TransportFailure.TIMEOUT
    )
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.recovery.status is RecoveryStatus.FAILED
    assert result.automatic_recovery_action == "review"
    assert result.next_action.value == "review_recovery"
    assert store.load("ft").last_reconciliation_check_at == clock.now
    clock.now += timedelta(minutes=20)
    _proof(keeper, clock.now)
    keeper.keep("ft", allow_credential_mint=True)
    watcher = _watch(store, keeper, clock)
    try:
        assert watcher.tick() == []
        assert not watcher.active
    finally:
        watcher.close()
    assert sessions.article_checks == [str(original.url)] * 2
    assert sessions.logins == sessions.checks == []


def test_initial_serving_transient_request_reserves_one_read_only_followup(tmp_path):
    keeper, sessions, _, _, budget, clock = _workflow(tmp_path)
    store = RecoveryStore(tmp_path / "serving-recovery", utc_now=lambda: clock.now)
    keeper._recovery_store = store
    record = store.request(
        "ft",
        generation_id=sessions.generation,
        url="https://www.ft.com/content/initial-timeout",
        incident_id=None,
        diagnostic_id="mcp-initial",
        read_failure_reason="read_timeout",
    )
    assert record.reconciliation_started
    assert record.health.episode_attempts == 0
    assert record.health.next_attempt_at == clock.now + timedelta(minutes=20)
    sessions.article_failure = SessionRequiredError("session_missing")
    clock.now += timedelta(minutes=20)
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.recovery.status is RecoveryStatus.FAILED
    assert result.recovery.episode_attempts == 1
    assert not store.automatic_retry_available(store.load("ft"))
    assert sessions.logins == []

    assert budget.attempts_today("ft") == 0


def test_same_unresolved_url_never_refunds_allowance_on_day_or_generation_change(
    tmp_path,
):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(
            article_failure=ProviderTransportError(
                "temporary", category=TransportFailure.TIMEOUT
            )
        ),
    )
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    clock.now += timedelta(minutes=20)
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    after_retry = store.load("ft")
    assert after_retry.health.episode_attempts == 2
    clock.now += timedelta(days=2)
    sessions.generation = uuid4()
    requested = store.request(
        "ft",
        generation_id=sessions.generation,
        url=str(original.url),
        incident_id=None,
        diagnostic_id="mcp-repeat",
        read_failure_reason="read_timeout",
    )
    assert requested.health.request_id == original.health.request_id
    assert requested.generation_id == original.generation_id
    assert requested.health.episode_attempts == 2
    assert not store.automatic_retry_available(requested)
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert sessions.article_checks == [str(original.url)] * 2
    assert sessions.logins == []


def test_reserved_automatic_retry_survives_restart_and_cannot_replay_after_crash(
    tmp_path,
):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(
            article_failure=ProviderTransportError(
                "temporary", category=TransportFailure.TIMEOUT
            )
        ),
    )
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    clock.now += timedelta(minutes=20)
    with store.operation("ft"):
        claimed = store.claim_read_retry("ft", "cli-crashed")
        assert claimed is not None
        assert (
            keeper.keep(
                "ft", allow_credential_mint=True, recovery_only=True
            ).action.value
            == "busy"
        )
    keeper._recovery_store = RecoveryStore(store.root, utc_now=lambda: clock.now)
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.recovery.reason == "interrupted_reconciliation"
    assert result.automatic_recovery_action == "review"
    assert result.recovery.episode_attempts == 2
    assert result.recovery.recent_attempts[-1].diagnostic_id == "cli-crashed"
    assert sessions.article_checks == [str(original.url)]
    assert sessions.logins == []


@pytest.mark.parametrize("guard", ["hold", "defense", "account", "cooldown"])
def test_current_guards_block_automatic_read_without_consumption_or_false_stall(
    tmp_path, guard
):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(
            article_failure=ProviderTransportError(
                "temporary", category=TransportFailure.TIMEOUT
            )
        ),
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    clock.now += timedelta(hours=2)
    if guard == "hold":
        keeper._guard = FakeGuard(hold=object())
    elif guard == "defense":
        sessions.contained_until = clock.now + timedelta(hours=1)
    elif guard == "account":
        sessions.status = SessionStatus.OPERATOR_ACTION
    else:
        sessions.retry_not_before = clock.now + timedelta(hours=1)
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert not result.automatic_recovery_stalled
    assert result.automatic_recovery_action in {"blocked", "retry_article"}
    assert store.load("ft").health.episode_attempts == 1
    assert sessions.article_checks == [str(original.url)]
    assert sessions.logins == []
    if guard == "cooldown":
        assert store.load("ft").health.next_attempt_at == sessions.retry_not_before
        watcher = _watch(store, keeper, clock)
        try:
            assert watcher.tick() == []
            assert not watcher.active
        finally:
            watcher.close()


def test_budget_wait_survives_restart_then_runs_once_at_reset(tmp_path):
    keeper, sessions, store, _, _, clock = _workflow(tmp_path)
    for index in range(2):
        keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
        clock.now += timedelta(minutes=20)
        target = store.request(
            "ft",
            generation_id=sessions.generation,
            url=f"https://www.ft.com/content/next-{index}",
            incident_id=None,
            diagnostic_id=None,
        )
    sessions.article_failure = ProviderTransportError(
        "temporary", category=TransportFailure.TIMEOUT
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    failed = store.load("ft")
    assert failed.health.attempts == 3 and failed.health.episode_attempts == 1
    keeper._recovery_store = RecoveryStore(store.root, utc_now=lambda: clock.now)
    before = keeper.inspect_recovery("ft")
    assert before.automatic_recovery_due_at == failed.health.budget_reset_at
    assert not before.automatic_recovery_stalled
    clock.now = failed.health.budget_reset_at
    sessions.article_failure = None
    watcher = _watch(keeper._recovery_store, keeper, clock)
    try:
        _complete_tick(watcher)
    finally:
        watcher.close()
    final = store.load("ft")
    assert final.health.request_id == target.health.request_id
    assert final.health.attempts == 1 and final.health.episode_attempts == 2
    assert final.health.article_verified
    assert sessions.logins == []


def test_stalled_deadlines_are_read_only_and_distinguish_worker_from_missing_monitor(
    tmp_path,
):
    keeper, sessions, store, _, _, clock = _workflow(
        tmp_path,
        RecoverySessions(
            article_failure=ProviderTransportError(
                "temporary", category=TransportFailure.TIMEOUT
            )
        ),
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    state_path = store.root / "ft.json"
    before = state_path.read_bytes()
    clock.now += timedelta(minutes=36, seconds=1)
    stalled = keeper.inspect_recovery("ft")
    assert stalled.automatic_recovery_stalled
    assert stalled.next_action.value == "review_recovery"
    assert "watcher" in stalled.repair_hint
    assert state_path.read_bytes() == before

    keeper2, _, store2, _, _, clock2 = _workflow(
        tmp_path / "monitor",
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    keeper2.keep("ft", allow_credential_mint=False, recovery_only=True)
    clock2.now += timedelta(hours=25, minutes=16, seconds=1)
    before2 = (store2.root / "ft.json").read_bytes()
    missing = keeper2.inspect_recovery("ft")
    assert missing.automatic_recovery_stalled
    assert "daily monitor" in missing.repair_hint
    _proof(keeper2, clock2.now + timedelta(days=365))
    assert keeper2.inspect_recovery("ft").automatic_recovery_stalled
    _proof(keeper2, clock2.now, ok=False)
    assert not keeper2.inspect_recovery("ft").automatic_recovery_stalled
    assert (store2.root / "ft.json").read_bytes() == before2


def test_legacy_unknown_episode_history_never_grants_automatic_action(tmp_path):
    keeper, sessions, store, original, _, clock = _workflow(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    record = store.load("ft")
    store._write(
        record.model_copy(
            update={
                "health": record.health.model_copy(update={"episode_attempts": None})
            }
        )
    )
    clock.now += timedelta(minutes=20)
    _proof(keeper, clock.now)
    keeper.keep("ft", allow_credential_mint=False)
    assert sessions.article_checks == [str(original.url)]
    assert keeper.inspect_recovery("ft").automatic_recovery_action == "review"
