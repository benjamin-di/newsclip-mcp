"""Durable handoff invariants: traffic and restarts never refund an action."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from newsclip.errors import PersistenceError
from newsclip.models import RecoveryStatus
from newsclip.private_state import PrivateStateBusyError, PrivateStateError
from newsclip.recovery import RecoveryBusyError, RecoveryStore

NOW = datetime(2026, 9, 6, tzinfo=UTC)
URL = "https://www.bloomberg.com/news/articles/2026-09-06/fixture"


def request(store, generation=None, *, incident="incident-" + "a" * 24):
    return store.request(
        "bloomberg",
        generation_id=generation,
        url=URL,
        incident_id=incident,
        diagnostic_id="mcp-fixture",
    )


def test_concurrent_requests_preserve_first_evidence(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    first = request(store, uuid4())
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(
            pool.map(
                lambda _: request(store, uuid4(), incident="incident-" + "b" * 24),
                range(32),
            )
        )
    assert all(record == first for record in records)
    assert (tmp_path / "bloomberg.json").stat().st_mode & 0o777 == 0o600


def test_restart_reconciles_once_without_refunding_attempt(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    request(store)
    with store.operation("bloomberg"):
        first = store.claim("bloomberg", "cli-first")
        assert first.health.attempts == 1
        assert store.load("bloomberg").health.status is RecoveryStatus.RUNNING
    restarted = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    with restarted.operation("bloomberg"):
        recovered = restarted.claim("bloomberg", "cli-reconcile")
        assert recovered.reconciliation_started
        assert recovered.attempt_diagnostic_id == "cli-first"
        assert recovered.health.diagnostic_id == "cli-reconcile"
        assert recovered.health.attempts == 1
    with restarted.operation("bloomberg"):
        assert restarted.claim("bloomberg", "cli-again") is None
    final = restarted.load("bloomberg")
    assert final.health.reason == "interrupted_reconciliation"
    assert final.health.attempts == 1
    assert request(restarted) == final


def test_operation_lock_spans_independent_store_instances(tmp_path):
    store = RecoveryStore(tmp_path)
    with (
        store.operation("bloomberg"),
        pytest.raises(RecoveryBusyError),
        RecoveryStore(tmp_path).operation("bloomberg"),
    ):
        pytest.fail("second worker acquired active provider")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (PrivateStateBusyError("another owner"), RecoveryBusyError),
        (PrivateStateBusyError("contention message changed"), RecoveryBusyError),
        (
            PrivateStateError("bloomberg.operation.lock is locked by another process"),
            PersistenceError,
        ),
        (PrivateStateError("lock unavailable"), PersistenceError),
    ],
)
def test_operation_classifies_lock_errors_by_type(
    tmp_path, monkeypatch, error, expected
):
    @contextmanager
    def failing_lock(*args, **kwargs):
        raise error
        yield  # pragma: no cover

    monkeypatch.setattr("newsclip.recovery.exclusive_lock", failing_lock)
    with (
        pytest.raises(expected) as caught,
        RecoveryStore(tmp_path).operation("bloomberg"),
    ):
        pytest.fail("failed lock entered the operation")
    assert caught.value.__cause__ is error


@pytest.mark.parametrize(
    "error",
    [PrivateStateBusyError("nested lock busy"), PrivateStateError("write failed")],
)
def test_operation_body_failure_is_not_operation_lock_contention(tmp_path, error):
    store = RecoveryStore(tmp_path)
    with pytest.raises(PersistenceError) as caught, store.operation("bloomberg"):
        raise error
    assert caught.value.__cause__ is error
    # The failed operation still relinquishes its lock.
    with RecoveryStore(tmp_path).operation("bloomberg"):
        pass


def test_new_generations_do_not_refund_provider_window_or_cooldown(tmp_path):
    now = NOW
    store = RecoveryStore(tmp_path, utc_now=lambda: now)
    for expected in (1, 2, 3):
        request(store, uuid4())
        with store.operation("bloomberg"):
            claimed = store.claim("bloomberg", "cli-fixture")
            assert claimed.health.attempts == expected
            store.finish(
                claimed, reason=None, session_verified=True, article_verified=True
            )
        following = request(store, uuid4())
        assert following.health.next_attempt_at == now + timedelta(minutes=20)
        assert store.claim("bloomberg", None) is None
        now += timedelta(minutes=20)
    assert store.claim("bloomberg", None) is None
    assert store.load("bloomberg").health.reason == "recovery_budget_spent"
    now += timedelta(days=1)
    request(store, uuid4())
    assert store.claim("bloomberg", None).health.attempts == 1


def test_terminal_content_failure_deduplicates_same_generation(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    generation = uuid4()
    request(store, generation)
    record = store.claim("bloomberg", None)
    store.session_verified(record)
    assert store.load("bloomberg").health.session_verified
    final = store.finish(record, reason="content_not_full", session_verified=True)
    assert not final.health.article_verified
    assert request(store, generation) == final
    assert store.claim("bloomberg", None) is None


def test_full_check_proof_is_newer_single_use_and_keeps_attempt_budget(tmp_path):
    now = NOW
    store = RecoveryStore(tmp_path, utc_now=lambda: now)
    request(store, uuid4())
    first = store.claim("bloomberg", "cli-first")
    now += timedelta(minutes=20)
    failed = store.finish(first, reason="content_not_full", session_verified=True)
    assert failed.last_failed_at == now

    assert (
        store.claim_verified_reconciliation(
            "bloomberg", "cli-stale", verified_check_at=NOW
        )
        is None
    )
    now += timedelta(minutes=20)
    checked_at = now
    second = store.claim_verified_reconciliation(
        "bloomberg", "cli-second", verified_check_at=checked_at
    )
    assert second is not None
    assert second.reconciliation_started
    assert second.health.attempts == 2
    assert second.last_reconciliation_check_at == checked_at

    # The observation was consumed before any provider I/O.
    store.finish(second, reason="content_not_full", session_verified=True)
    assert (
        store.claim_verified_reconciliation(
            "bloomberg", "cli-repeat", verified_check_at=checked_at
        )
        is None
    )

    now += timedelta(minutes=20)
    third = store.claim_verified_reconciliation(
        "bloomberg", "cli-third", verified_check_at=now
    )
    assert third is not None
    assert third.health.attempts == 3
    store.finish(third, reason="content_not_full", session_verified=True)
    now += timedelta(minutes=20)
    assert (
        store.claim_verified_reconciliation(
            "bloomberg", "cli-over-budget", verified_check_at=now
        )
        is None
    )


def test_stale_completion_cannot_replace_new_request(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    request(store, uuid4())
    record = store.claim("bloomberg", None)
    store.finish(record, reason=None, session_verified=True, article_verified=True)
    next_record = request(store, uuid4())
    with pytest.raises(PersistenceError, match="changed"):
        store.finish(record, reason="late_failure")
    assert store.load("bloomberg") == next_record


def test_deferral_does_not_consume_attempt(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    request(store)
    store.defer("bloomberg", until=NOW + timedelta(hours=1), reason="provider_defense")
    assert store.claim("bloomberg", None) is None
    assert store.load("bloomberg").health.attempts == 0


@pytest.mark.parametrize("payload", [b"broken", b"x" * 16385])
def test_malformed_or_oversized_state_never_becomes_empty_state(tmp_path, payload):
    (tmp_path / "bloomberg.json").write_bytes(payload)
    with pytest.raises(PersistenceError):
        request(RecoveryStore(tmp_path))


def test_read_only_health_does_not_create_state(tmp_path):
    root = tmp_path / "absent"
    assert RecoveryStore(root).load("bloomberg") is None
    assert not root.exists()


def test_worker_failure_cannot_replace_claimed_or_newer_work(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    first = request(store, uuid4())
    claimed = store.claim("bloomberg", "cli-first")
    store.worker_failed("bloomberg", first.health.request_id)
    assert store.load("bloomberg") == claimed
    store.finish(claimed, reason="fixture_failed")
    newer = request(store, uuid4())
    store.worker_failed("bloomberg", first.health.request_id)
    assert store.load("bloomberg") == newer
    with store.operation("bloomberg"):
        store.worker_failed("bloomberg", newer.health.request_id)
    assert store.load("bloomberg") == newer


def test_exact_article_proof_settles_failure_without_inventing_login_proof(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    first = request(store, uuid4())
    claimed = store.claim("bloomberg", "cli-first")
    assert store.article_verified("bloomberg", URL, verified_at=NOW) is None
    failed = store.finish(claimed, reason="fixture_failed")
    assert (
        store.article_verified("bloomberg", URL + "-different", verified_at=NOW) is None
    )
    assert (
        store.article_verified("bloomberg", URL, verified_at=NOW - timedelta(seconds=1))
        is None
    )
    assert store.load("bloomberg") == failed
    resolved = store.article_verified(
        "bloomberg", URL, verified_at=NOW, diagnostic_id="mcp-proof"
    )
    assert resolved.health.status.value == "succeeded"
    assert resolved.health.article_verified
    assert not resolved.health.session_verified
    assert resolved.health.request_id == first.health.request_id
    assert resolved.health.diagnostic_id == "mcp-proof"
    assert resolved.attempt_diagnostic_id == "cli-first"


def test_article_success_without_recovery_creates_no_state(tmp_path):
    store = RecoveryStore(tmp_path / "absent")
    assert store.article_verified("bloomberg", URL, verified_at=NOW) is None
    assert not store.root.exists()
