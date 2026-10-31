from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from multiprocessing import get_context
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from newsclip.cli import app
from newsclip.errors import ProviderTransportError
from newsclip.models import AccessState, ProviderCapabilities, SessionDisposition
from newsclip.provenance import BuildIdentity, BuildIdentitySource
from newsclip.provider_check import ProviderCheckFailure, ProviderCheckResult
from newsclip.provider_guard import (
    AcknowledgementReport,
    GuardAcknowledgement,
    GuardAction,
    GuardResult,
    ProviderGuard,
    ProviderGuardPersistenceError,
    ProviderGuardStore,
    ProviderHold,
)
from newsclip.providers import ProviderRegistry

NOW = datetime(2026, 7, 24, tzinfo=UTC)


def _identity() -> BuildIdentity:
    return BuildIdentity(
        revision="a" * 40,
        dirty=False,
        source_fingerprint="a" * 64,
        source=BuildIdentitySource.ENVIRONMENT,
    )


class _Provider:
    key = "ft"
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=True,
        session_kind="cookie",
    )


class _AnonymousProvider:
    key = "ft"
    capabilities = ProviderCapabilities(
        requires_session_for_retrieve=False,
        session_kind="none",
    )


def _check(
    *,
    failure: ProviderCheckFailure | None,
    disposition: SessionDisposition | None = None,
    incident_id: str | None = None,
) -> ProviderCheckResult:
    if failure is None:
        return ProviderCheckResult(
            provider="ft",
            ok=True,
            search_result_count=1,
            http_status=200,
            access_state=AccessState.FULL,
            reason="full_article_verified",
            identity_match=True,
            word_count=500,
        )
    assessed = failure in {
        ProviderCheckFailure.CONTENT_NOT_FULL,
        ProviderCheckFailure.PROVIDER_DEFENSE,
        ProviderCheckFailure.SESSION_DEAD,
    }
    return ProviderCheckResult(
        provider="ft",
        ok=False,
        failure=failure,
        search_result_count=1,
        http_status=200 if assessed else None,
        access_state=(
            AccessState.BLOCKED
            if failure is ProviderCheckFailure.PROVIDER_DEFENSE
            else (AccessState.TEASER if assessed else None)
        ),
        reason=(
            "interactive_challenge"
            if failure is ProviderCheckFailure.PROVIDER_DEFENSE
            else ("paywall_teaser" if assessed else None)
        ),
        identity_match=(
            False
            if failure is ProviderCheckFailure.PROVIDER_DEFENSE
            else (True if assessed else None)
        ),
        word_count=8 if assessed else None,
        session_disposition=disposition,
        incident_id=incident_id,
    )


def _guard(
    tmp_path: Path,
    *,
    lock_timeout_seconds: float = 2,
) -> tuple[ProviderGuard, ProviderGuardStore]:
    store = ProviderGuardStore(
        tmp_path / "provider-guard",
        build_identity=_identity(),
        diagnostic_id="cli-guard-fixture",
        utc_now=lambda: NOW,
        lock_timeout_seconds=lock_timeout_seconds,
    )
    return (
        ProviderGuard(
            registry=ProviderRegistry((_Provider(),)),
            store=store,
        ),
        store,
    )


def _hold_process_guard_lock(root: str, entered, release) -> None:  # noqa: ANN001
    store = ProviderGuardStore(
        Path(root),
        build_identity=_identity(),
        lock_timeout_seconds=2,
    )
    with store.locked("ft"):
        entered.set()
        assert release.wait(timeout=3)


@pytest.mark.parametrize(
    ("failure", "action", "held"),
    (
        (None, GuardAction.HEALTHY, False),
        (ProviderCheckFailure.PROVIDER_DEFENSE, GuardAction.PROVIDER_HOLD, True),
        (
            ProviderCheckFailure.SESSION_DEAD,
            GuardAction.SESSION_PROMOTION_REQUIRED,
            True,
        ),
        (
            ProviderCheckFailure.OPERATOR_ACTION,
            GuardAction.OPERATOR_ACTION,
            True,
        ),
        (
            ProviderCheckFailure.LOCAL_STATE,
            GuardAction.LOCAL_REPAIR_REQUIRED,
            True,
        ),
    ),
)
def test_guard_classifies_and_persists_only_durable_outcomes(
    tmp_path: Path,
    failure: ProviderCheckFailure | None,
    action: GuardAction,
    held: bool,
) -> None:
    guard, store = _guard(tmp_path)

    result = guard.run("ft", lambda: _check(failure=failure))

    assert result.action is action
    assert (result.hold_id is not None) is held
    with store.locked("ft"):
        retained = store.load_locked("ft")
        observation = store.load_observation_locked("ft")
    assert (retained is not None) is held
    assert observation is not None
    assert observation.checked_at == NOW
    assert observation.check == result.check
    assert oct((store.root / "ft.check.json").stat().st_mode & 0o777) == "0o600"
    if retained is not None:
        assert retained.action is action
        assert retained.diagnostic_id == "cli-guard-fixture"
        assert retained.build_identity == _identity()
        assert oct((store.root / "ft.json").stat().st_mode & 0o777) == "0o600"
    assert oct(store.root.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize(
    "failure",
    (
        ProviderCheckFailure.SEARCH_TRANSPORT,
        ProviderCheckFailure.RETRIEVAL_TRANSPORT,
    ),
)
def test_transport_failure_is_rechecked_on_the_next_scheduled_run(
    tmp_path: Path,
    failure: ProviderCheckFailure,
) -> None:
    guard, store = _guard(tmp_path)
    calls = 0

    def check_provider() -> ProviderCheckResult:
        nonlocal calls
        calls += 1
        return _check(failure=failure)

    first = guard.run("ft", check_provider)
    second = guard.run("ft", check_provider)

    assert first.action is GuardAction.TRANSIENT_FAILURE
    assert second.action is GuardAction.TRANSIENT_FAILURE
    assert calls == 2
    with store.locked("ft"):
        assert store.load_locked("ft") is None
        observation = store.load_observation_locked("ft")
    assert observation is not None
    assert observation.check.failure is failure


def test_existing_hold_suppresses_provider_io_until_exact_acknowledgement(
    tmp_path: Path,
) -> None:
    guard, _ = _guard(tmp_path)
    first = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert first.hold_id is not None

    held = guard.run(
        "ft",
        lambda: pytest.fail("held guard must not invoke the provider"),
    )
    stale = guard.acknowledge("ft", hold_id=f"guard-{'0' * 32}")
    still_held = guard.run(
        "ft",
        lambda: pytest.fail("stale acknowledgement must not clear the hold"),
    )
    acknowledged = guard.acknowledge("ft", hold_id=first.hold_id)
    recovered = guard.run("ft", lambda: _check(failure=None))

    assert held.hold_id == first.hold_id
    assert stale.acknowledged is False
    assert stale.current_hold_id == first.hold_id
    assert still_held.hold_id == first.hold_id
    assert acknowledged.acknowledged is True
    assert acknowledged.current_hold_id is None
    assert recovered.action is GuardAction.HEALTHY


def test_existing_hold_does_not_refresh_the_last_actual_check(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)
    first = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )

    held = guard.run(
        "ft",
        lambda: pytest.fail("held guard must not invoke the provider"),
    )
    observation = guard.last_check("ft")

    assert held.hold_id == first.hold_id
    assert observation is not None
    assert observation.checked_at == NOW
    assert observation.check == first.check


def test_content_incident_is_held_for_operator_review(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)
    incident_id = f"incident-{'c' * 24}"

    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.VERIFIED,
            incident_id=incident_id,
        ),
    )

    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert result.incident_id == incident_id
    assert result.hold_id is not None


def test_content_failure_waits_for_positive_session_evidence(tmp_path: Path) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.INCONCLUSIVE,
        ),
    )

    assert result.action is GuardAction.WAIT_FOR_SESSION_EVIDENCE
    assert result.hold_id is not None


def test_session_wide_shortfall_asks_for_promotion_not_more_waiting(
    tmp_path: Path,
) -> None:
    guard, _ = _guard(tmp_path)

    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.NOT_ENTITLED,
        ),
    )

    assert result.action is GuardAction.SESSION_PROMOTION_REQUIRED
    assert result.hold_id is not None


def test_anonymous_content_incident_does_not_require_session_evidence(
    tmp_path: Path,
) -> None:
    store = ProviderGuardStore(
        tmp_path / "provider-guard",
        build_identity=_identity(),
        diagnostic_id="cli-guard-fixture",
        utc_now=lambda: NOW,
    )
    guard = ProviderGuard(
        registry=ProviderRegistry((_AnonymousProvider(),)),
        store=store,
    )
    incident_id = f"incident-{'d' * 24}"

    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            incident_id=incident_id,
        ),
    )

    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert result.incident_id == incident_id
    assert result.hold_id is not None


def test_provider_lock_prevents_concurrent_checks(tmp_path: Path) -> None:
    first_guard, _ = _guard(tmp_path)
    second_guard, _ = _guard(tmp_path, lock_timeout_seconds=0.05)
    entered = threading.Event()
    release = threading.Event()
    first_result: list[GuardResult] = []

    def slow_check() -> ProviderCheckResult:
        entered.set()
        assert release.wait(timeout=2)
        return _check(failure=None)

    worker = threading.Thread(
        target=lambda: first_result.append(first_guard.run("ft", slow_check))
    )
    worker.start()
    assert entered.wait(timeout=2)
    second = second_guard.run(
        "ft",
        lambda: pytest.fail("concurrent guard must not invoke the provider"),
    )
    release.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert first_result[0].action is GuardAction.HEALTHY
    assert second.action is GuardAction.CHECK_IN_PROGRESS
    assert second.check is None
    assert second.hold_id is None


def test_provider_lock_is_process_safe(tmp_path: Path) -> None:
    context = get_context("fork")
    entered = context.Event()
    release = context.Event()
    root = tmp_path / "provider-guard"
    worker = context.Process(
        target=_hold_process_guard_lock,
        args=(str(root), entered, release),
    )
    worker.start()
    try:
        assert entered.wait(timeout=2)
        guard, _ = _guard(tmp_path, lock_timeout_seconds=0.05)
        result = guard.run(
            "ft",
            lambda: pytest.fail("cross-process lock must suppress provider I/O"),
        )
    finally:
        release.set()
        worker.join(timeout=3)

    assert worker.exitcode == 0
    assert result.action is GuardAction.CHECK_IN_PROGRESS
    assert result.check is None


def test_corrupt_hold_fails_closed_without_provider_io(tmp_path: Path) -> None:
    guard, store = _guard(tmp_path)
    store.root.mkdir(mode=0o700)
    (store.root / "ft.json").write_text("not-json", encoding="utf-8")

    result = guard.run(
        "ft",
        lambda: pytest.fail("invalid hold must suppress provider I/O"),
    )

    assert result.action is GuardAction.LOCAL_REPAIR_REQUIRED
    assert result.hold_id is None


def test_corrupt_check_observation_is_reported_as_unreadable_state(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    store.root.mkdir(mode=0o700)
    (store.root / "ft.check.json").write_text("not-json", encoding="utf-8")

    with pytest.raises(
        ProviderGuardPersistenceError,
        match="provider check observation is invalid",
    ):
        guard.last_check("ft")


def test_check_observation_write_failure_makes_the_guard_fail_locally(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    store.root.mkdir(mode=0o700)
    (store.root / "ft.check.json").symlink_to(tmp_path / "missing")

    result = guard.run("ft", lambda: _check(failure=None))

    assert result.action is GuardAction.LOCAL_REPAIR_REQUIRED
    assert result.check is not None
    assert result.check.ok is True


def test_dangling_hold_symlink_fails_closed_without_provider_io(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    store.root.mkdir(mode=0o700)
    (store.root / "ft.json").symlink_to(tmp_path / "missing")

    result = guard.run(
        "ft",
        lambda: pytest.fail("symlinked hold must suppress provider I/O"),
    )

    assert result.action is GuardAction.LOCAL_REPAIR_REQUIRED
    assert result.hold_id is None


def test_hold_write_and_clear_fsync_the_state_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Durability now lives in the shared private-state helper, so observe it
    # there: the invariant is that the rename itself is made durable.
    import signin_window.state as private_state

    import newsclip.provider_guard as provider_guard

    guard, store = _guard(tmp_path)
    synced: list[Path] = []
    real_fsync = private_state.fsync_directory

    def observe(path: Path) -> None:
        synced.append(path)
        real_fsync(path)

    monkeypatch.setattr(private_state, "fsync_directory", observe)
    monkeypatch.setattr(provider_guard, "_fsync_directory", observe)
    result = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert result.hold_id is not None
    guard.acknowledge("ft", hold_id=result.hold_id)

    assert synced.count(store.root) >= 2


class _CliService:
    def __init__(self, check: ProviderCheckResult) -> None:
        self.check = check
        self.closed = False

    def requires_browser_for_provider(self, provider: str) -> bool:
        del provider
        return False

    def provider_check(self, provider: str) -> ProviderCheckResult:
        del provider
        return self.check

    def close(self) -> None:
        self.closed = True


class _CliGuard:
    def peek_before_check(self, provider: str) -> object:
        del provider
        return None

    def run(self, provider: str, check_provider) -> GuardResult:  # noqa: ANN001
        check = check_provider()
        return GuardResult(
            provider=provider,
            check=check,
            action=GuardAction.HEALTHY,
            diagnostic_id="cli-guard-fixture",
        )


def test_provider_guard_cli_runs_one_guarded_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _CliService(_check(failure=None))
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", _CliGuard)

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 0
    payload = json.loads(invocation.stdout)
    assert payload["action"] == "healthy"
    assert payload["guarded"] is True
    assert payload["diagnostic_id"] == "cli-guard-fixture"
    assert "url" not in invocation.stdout.lower()
    assert service.closed is True


def test_provider_guard_cli_closes_unclassified_check_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive = "/private/provider-check/internal-state.json"

    class FailingService:
        closed = False

        def requires_browser_for_provider(self, provider: str) -> bool:
            del provider
            return False

        def provider_check(self, provider: str) -> ProviderCheckResult:
            del provider
            raise RuntimeError(sensitive)

        def close(self) -> None:
            self.closed = True

    service = FailingService()
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", _CliGuard)

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 5
    assert json.loads(invocation.stderr) == {
        "category": "transport",
        "exit_code": 5,
        "message": "provider transport failed",
        "ok": False,
        "retryable": True,
        "action": "retry_later",
    }
    assert sensitive not in invocation.stderr
    assert service.closed is True


def test_provider_guard_cli_prepares_the_display_before_the_guard_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child re-runs this command and must be able to take the same lock."""

    events: list[str] = []

    class BrowserService(_CliService):
        def requires_browser_for_provider(self, provider: str) -> bool:
            del provider
            return True

        def provider_check(self, provider: str) -> ProviderCheckResult:
            events.append("check")
            return super().provider_check(provider)

    class OrderedGuard(_CliGuard):
        def run(self, provider: str, check_provider) -> GuardResult:  # noqa: ANN001
            events.append("lock")
            return super().run(provider, check_provider)

    service = BrowserService(_check(failure=None))
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", OrderedGuard)
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, **kwargs: events.append("display"),
    )

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 0
    assert events == ["display", "lock", "check"]
    assert service.closed is True


def test_provider_guard_cli_closes_the_service_when_the_child_owns_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-execution exits the parent; its service must not leak."""

    class BrowserService(_CliService):
        def requires_browser_for_provider(self, provider: str) -> bool:
            del provider
            return True

    service = BrowserService(_check(failure=None))
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", _CliGuard)

    def reexec(argv, **kwargs) -> None:  # noqa: ANN001
        del argv, kwargs
        raise typer.Exit(code=3)

    monkeypatch.setattr("newsclip.cli._prepare_virtual_display", reexec)

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 3
    assert invocation.stdout == ""
    assert service.closed is True


def test_provider_guard_cli_reports_a_hold_without_provider_or_display_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hold_id = f"guard-{'4' * 32}"

    class HeldGuard:
        def peek_before_check(self, provider: str) -> object:
            del provider
            return "held"

        def run(self, provider: str, check_provider) -> GuardResult:  # noqa: ANN001
            del check_provider
            return GuardResult(
                provider=provider,
                action=GuardAction.PROVIDER_HOLD,
                hold_id=hold_id,
                diagnostic_id="cli-guard-fixture",
            )

    def unexpected_service() -> None:
        raise AssertionError("held provider must not construct the service")

    monkeypatch.setattr("newsclip.cli.build_auth_service", unexpected_service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", HeldGuard)
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, **kwargs: (_ for _ in ()).throw(
            AssertionError("held provider must not prepare a display")
        ),
    )

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 1
    payload = json.loads(invocation.stdout)
    assert payload["action"] == "provider_hold"
    assert payload["hold_id"] == hold_id


def test_provider_guard_peek_reads_a_hold_and_defers_every_other_verdict(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path, lock_timeout_seconds=0.1)

    assert guard.peek("ft") is None

    result = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    held = guard.peek("ft")
    assert held is not None
    assert held.hold_id == result.hold_id

    # peek_before_check classifies nothing: run() owns the in-progress and
    # local-repair verdicts, so contention and unreadable state both surface.
    with store.locked("ft"), pytest.raises(ProviderGuardPersistenceError):
        guard.peek_before_check("ft")

    (store.root / "ft.json").write_bytes(b"not-json")
    with pytest.raises(ProviderGuardPersistenceError):
        guard.peek("ft")
    with pytest.raises(ProviderGuardPersistenceError):
        guard.peek_before_check("ft")


def test_advisory_reads_do_not_wait_for_an_in_flight_check(tmp_path: Path) -> None:
    """Health and the keeper read state while a guarded check holds the lock.

    Every state file is replaced by an atomic rename, so an unlocked reader
    sees a complete document; contention is not unreadable local state.
    """

    guard, store = _guard(tmp_path, lock_timeout_seconds=0.05)
    held = guard.run(
        "ft", lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE)
    )

    with store.locked("ft"):
        current = guard.peek("ft")
        observation = guard.last_check("ft")
        due = guard.incident_canary_due("ft")

    assert current is not None
    assert current.hold_id == held.hold_id
    assert observation is not None
    assert observation.check.failure is ProviderCheckFailure.PROVIDER_DEFENSE
    assert due is True


def test_advisory_reads_see_no_state_as_absence(tmp_path: Path) -> None:
    guard, store = _guard(tmp_path)

    assert guard.peek("ft") is None
    assert guard.last_check("ft") is None
    assert not store.root.exists()


def test_advisory_reads_refuse_a_symlinked_root(tmp_path: Path) -> None:
    guard, store = _guard(tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    store.root.symlink_to(target)

    with pytest.raises(ProviderGuardPersistenceError):
        guard.peek("ft")
    with pytest.raises(ProviderGuardPersistenceError):
        guard.last_check("ft")


def test_provider_guard_acknowledge_requires_and_passes_exact_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hold_id = f"guard-{'1' * 32}"

    class AcknowledgeGuard:
        def peek(self, provider: str):
            return None

        def acknowledge_and_check(self, provider: str, *, hold_id: str, check_provider):
            return AcknowledgementReport(
                acknowledgement=GuardAcknowledgement(
                    provider=provider,
                    requested_hold_id=hold_id,
                    acknowledged=True,
                ),
                follow_up=GuardResult(
                    provider=provider,
                    check=_check(failure=None),
                    action=GuardAction.HEALTHY,
                ),
            )

    monkeypatch.setattr("newsclip.cli.build_provider_guard", AcknowledgeGuard)

    invocation = CliRunner().invoke(
        app,
        [
            "provider-guard-acknowledge",
            "--provider",
            "ft",
            "--hold-id",
            hold_id,
            "--json",
        ],
    )

    assert invocation.exit_code == 0
    payload = json.loads(invocation.stdout)
    assert payload["acknowledgement"]["acknowledged"] is True
    assert payload["acknowledgement"]["requested_hold_id"] == hold_id
    assert payload["follow_up"]["action"] == "healthy"
    assert "url" not in invocation.stdout.lower()


def test_provider_guard_acknowledge_fails_for_stale_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = f"guard-{'1' * 32}"
    current = f"guard-{'2' * 32}"

    class StaleGuard:
        def peek(self, provider: str):
            return None

        def acknowledge_and_check(self, provider: str, *, hold_id: str, check_provider):
            return AcknowledgementReport(
                acknowledgement=GuardAcknowledgement(
                    provider=provider,
                    requested_hold_id=hold_id,
                    acknowledged=False,
                    current_hold_id=current,
                ),
            )

    monkeypatch.setattr("newsclip.cli.build_provider_guard", StaleGuard)

    invocation = CliRunner().invoke(
        app,
        [
            "provider-guard-acknowledge",
            "--provider",
            "ft",
            "--hold-id",
            requested,
            "--json",
        ],
    )

    assert invocation.exit_code == 1
    payload = json.loads(invocation.stdout)
    assert payload["acknowledgement"]["current_hold_id"] == current
    assert payload["follow_up"] is None


def test_acknowledge_and_check_leaves_fresh_evidence(tmp_path: Path) -> None:
    """R10: a successful acknowledgement implies one guarded re-measurement."""

    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert held.hold_id is not None

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=held.hold_id,
        check_provider=lambda: _check(failure=None),
    )

    assert report.acknowledgement.acknowledged is True
    assert report.follow_up is not None
    assert report.follow_up.action is GuardAction.HEALTHY
    assert report.follow_up_error is None
    assert guard.peek("ft") is None
    observation = guard.last_check("ft")
    assert observation is not None
    assert observation.check.ok is True


def test_acknowledge_and_check_stale_id_touches_no_provider(tmp_path: Path) -> None:
    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=f"guard-{'0' * 32}",
        check_provider=lambda: pytest.fail(
            "a stale acknowledgement must not re-measure"
        ),
    )

    assert report.acknowledgement.acknowledged is False
    assert report.follow_up is None
    assert report.follow_up_error is None
    current = guard.peek("ft")
    assert current is not None
    assert current.hold_id == held.hold_id


def test_acknowledge_and_check_failure_never_unacknowledges(tmp_path: Path) -> None:
    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert held.hold_id is not None

    def failing_check() -> ProviderCheckResult:
        raise ProviderTransportError("provider guard check failed")

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=held.hold_id,
        check_provider=failing_check,
    )

    assert report.acknowledgement.acknowledged is True
    assert report.follow_up is None
    assert report.follow_up_error == "transport"
    assert guard.peek("ft") is None


def test_acknowledge_and_check_reholds_on_durable_failure(tmp_path: Path) -> None:
    """A follow-up that classifies durably re-holds; both facts are reported."""

    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert held.hold_id is not None

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=held.hold_id,
        check_provider=lambda: _check(
            failure=ProviderCheckFailure.PROVIDER_DEFENSE,
        ),
    )

    assert report.acknowledgement.acknowledged is True
    assert report.follow_up is not None
    assert report.follow_up.action is GuardAction.PROVIDER_HOLD
    assert report.follow_up.hold_id is not None
    assert report.follow_up.hold_id != held.hold_id
    current = guard.peek("ft")
    assert current is not None
    assert current.hold_id == report.follow_up.hold_id


def test_acknowledge_and_check_vanished_hold_reports_plainly(tmp_path: Path) -> None:
    guard, _store = _guard(tmp_path)

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=f"guard-{'3' * 32}",
        check_provider=lambda: pytest.fail("a vanished hold must not re-measure"),
    )

    assert report.acknowledgement.acknowledged is False
    assert report.acknowledgement.current_hold_id is None
    assert report.follow_up is None
    assert report.follow_up_error is None


def test_acknowledge_and_check_reduces_public_errors_to_categories(
    tmp_path: Path,
) -> None:
    from newsclip.errors import ProviderDefenseError

    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    assert held.hold_id is not None

    def defended_check() -> ProviderCheckResult:
        raise ProviderDefenseError("edge refused", provider="ft")

    report = guard.acknowledge_and_check(
        "ft",
        hold_id=held.hold_id,
        check_provider=defended_check,
    )

    assert report.acknowledgement.acknowledged is True
    assert report.follow_up_error == "provider_defense"
    assert guard.peek("ft") is None


def test_every_public_error_category_fits_the_follow_up_pattern() -> None:
    import re

    from newsclip.provider_guard import _FOLLOW_UP_ERROR_PATTERN
    from newsclip.results import PublicErrorCategory

    for category in PublicErrorCategory:
        assert re.fullmatch(_FOLLOW_UP_ERROR_PATTERN, category.value) is not None


def test_provider_guard_acknowledge_follow_up_error_still_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hold_id = f"guard-{'1' * 32}"

    class FollowUpFailedGuard:
        def peek(self, provider: str):
            return None

        def acknowledge_and_check(self, provider: str, *, hold_id: str, check_provider):
            return AcknowledgementReport(
                acknowledgement=GuardAcknowledgement(
                    provider=provider,
                    requested_hold_id=hold_id,
                    acknowledged=True,
                ),
                follow_up_error="transport",
            )

    monkeypatch.setattr("newsclip.cli.build_provider_guard", FollowUpFailedGuard)

    invocation = CliRunner().invoke(
        app,
        [
            "provider-guard-acknowledge",
            "--provider",
            "ft",
            "--hold-id",
            hold_id,
            "--json",
        ],
    )

    assert invocation.exit_code == 0
    payload = json.loads(invocation.stdout)
    assert payload["acknowledgement"]["acknowledged"] is True
    assert payload["follow_up_error"] == "transport"


_INCIDENT = f"incident-{'a' * 24}"


def _guard_with_clock(
    tmp_path: Path,
) -> tuple[ProviderGuard, ProviderGuardStore, dict[str, datetime]]:
    clock = {"now": NOW}
    store = ProviderGuardStore(
        tmp_path / "provider-guard",
        build_identity=_identity(),
        diagnostic_id="cli-guard-fixture",
        utc_now=lambda: clock["now"],
        lock_timeout_seconds=2,
    )
    return (
        ProviderGuard(registry=ProviderRegistry((_Provider(),)), store=store),
        store,
        clock,
    )


def _incident_check(incident_id: str = _INCIDENT) -> ProviderCheckResult:
    return _check(
        failure=ProviderCheckFailure.CONTENT_NOT_FULL,
        disposition=SessionDisposition.VERIFIED,
        incident_id=incident_id,
    )


def _open_incident_hold(guard: ProviderGuard) -> GuardResult:
    result = guard.run("ft", _incident_check)
    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert result.hold_id is not None
    return result


def test_incident_canary_clears_on_full_and_records_evidence(tmp_path: Path) -> None:
    """R9: only a FULL canary clears, and its evidence lands in the observation."""

    guard, store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    clock["now"] = NOW + timedelta(hours=1)

    result = guard.run_incident_review_canary("ft", lambda: _check(failure=None))

    assert result.action is GuardAction.HEALTHY
    assert guard.peek("ft") is None
    observation = guard.last_check("ft")
    assert observation is not None
    assert observation.check.ok is True
    assert observation.checked_at == NOW + timedelta(hours=1)
    with store.locked("ft"):
        state = store.load_incident_canary_locked("ft")
    assert state is not None
    assert state.last_canary_at == NOW + timedelta(hours=1)
    assert state.last_auto_clear_at == NOW + timedelta(hours=1)


def test_aged_canary_hold_clears_on_full_retrieval(tmp_path: Path) -> None:
    """An old expected_result_missing hold clears on the daily canary.

    The check now reports a FULL article whose canary merely aged out of
    search as healthy with an advisory; that is the FULL proof the
    incident-review hold waits for, and the advisory creates no new hold.
    """

    guard, _store, clock = _guard_with_clock(tmp_path)
    held = guard.run(
        "ft",
        lambda: ProviderCheckResult(
            provider="ft",
            ok=False,
            failure=ProviderCheckFailure.EXPECTED_RESULT_MISSING,
            incident_id=_INCIDENT,
        ),
    )
    assert held.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    clock["now"] = NOW + timedelta(hours=1)
    aged = _check(failure=None).model_copy(update={"canary_in_search": False})

    result = guard.run_incident_review_canary("ft", lambda: aged)

    assert result.action is GuardAction.HEALTHY
    assert guard.peek("ft") is None
    observation = guard.last_check("ft")
    assert observation is not None
    assert observation.check.canary_in_search is False
    assert observation.check.search_result_count == 1
    assert guard.run("ft", lambda: aged).action is GuardAction.HEALTHY
    assert guard.peek("ft") is None


def test_incident_canary_failure_leaves_hold_and_fresh_evidence(
    tmp_path: Path,
) -> None:
    guard, _store, clock = _guard_with_clock(tmp_path)
    held = _open_incident_hold(guard)
    clock["now"] = NOW + timedelta(hours=2)

    result = guard.run_incident_review_canary("ft", _incident_check)

    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert result.hold_id == held.hold_id
    current = guard.peek("ft")
    assert current is not None
    assert current.hold_id == held.hold_id
    observation = guard.last_check("ft")
    assert observation is not None
    assert observation.checked_at == NOW + timedelta(hours=2)


@pytest.mark.parametrize(
    "failure",
    (ProviderCheckFailure.SESSION_REQUIRED, ProviderCheckFailure.SESSION_DEAD),
)
def test_incident_canary_session_failure_hands_the_hold_to_renewal(
    tmp_path: Path, failure: ProviderCheckFailure
) -> None:
    """A dead or missing session supersedes the content verdict.

    Keeping the incident hold blocked the keeper renewal that is now the
    remedy, so nothing could clear it. The replacement is the session class
    that verified renewal clears; FULL content is still required afterwards.
    """

    guard, _store, clock = _guard_with_clock(tmp_path)
    held = _open_incident_hold(guard)
    clock["now"] = NOW + timedelta(hours=1)

    result = guard.run_incident_review_canary(
        "ft",
        lambda: _check(failure=failure, disposition=SessionDisposition.DEAD),
    )

    assert result.action is GuardAction.SESSION_PROMOTION_REQUIRED
    assert result.hold_id is not None and result.hold_id != held.hold_id
    current = guard.peek("ft")
    assert current is not None
    assert current.hold_id == result.hold_id
    assert current.action is GuardAction.SESSION_PROMOTION_REQUIRED
    assert current.failure is failure
    target = guard.session_evidence_target("ft")
    assert target == result.hold_id
    assert guard.clear_session_evidence("ft", hold_id=target) is not None
    assert guard.peek("ft") is None


@pytest.mark.parametrize(
    ("failure", "disposition"),
    (
        (ProviderCheckFailure.CONTENT_NOT_FULL, SessionDisposition.VERIFIED),
        (ProviderCheckFailure.SEARCH_CONTRACT, None),
        (ProviderCheckFailure.EXPECTED_RESULT_MISSING, None),
    ),
)
def test_uncaptured_content_failure_is_still_incident_review(
    tmp_path: Path,
    failure: ProviderCheckFailure,
    disposition: SessionDisposition | None,
) -> None:
    """The hold class follows the failure, not whether capture succeeded.

    An operator hold would forfeit the daily FULL canary that clears a
    content/search review, for want of a best-effort capsule.
    """

    guard, _store, clock = _guard_with_clock(tmp_path)

    held = guard.run("ft", lambda: _check(failure=failure, disposition=disposition))

    assert held.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert held.incident_id is None
    current = guard.peek("ft")
    assert current is not None
    assert current.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert current.incident_id is None
    clock["now"] = NOW + timedelta(hours=1)
    cleared = guard.run_incident_review_canary("ft", lambda: _check(failure=None))
    assert cleared.action is GuardAction.HEALTHY
    assert guard.peek("ft") is None


def test_incident_review_hold_rejects_an_unrelated_failure() -> None:
    with pytest.raises(ValueError, match="incident is inconsistent"):
        ProviderHold(
            hold_id=f"guard-{'5' * 32}",
            provider="ft",
            occurred_at=NOW,
            action=GuardAction.INCIDENT_REVIEW_REQUIRED,
            failure=ProviderCheckFailure.PROVIDER_DEFENSE,
            build_identity=_identity(),
        )


def test_incident_canary_runs_at_most_once_per_day(tmp_path: Path) -> None:
    guard, _store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    contacts = 0

    def counted_check() -> ProviderCheckResult:
        nonlocal contacts
        contacts += 1
        return _incident_check()

    clock["now"] = NOW + timedelta(hours=1)
    guard.run_incident_review_canary("ft", counted_check)
    clock["now"] = NOW + timedelta(hours=5)
    blocked = guard.run_incident_review_canary(
        "ft",
        lambda: pytest.fail("a second canary within 24h must not contact"),
    )
    clock["now"] = NOW + timedelta(hours=25, minutes=30)
    guard.run_incident_review_canary("ft", counted_check)

    assert contacts == 2
    assert blocked.action is GuardAction.INCIDENT_REVIEW_REQUIRED


def test_flapping_provider_waits_a_full_day_after_an_auto_clear(
    tmp_path: Path,
) -> None:
    """R9: a hold that re-opens inside the window stays held for review."""

    guard, _store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)

    clock["now"] = NOW + timedelta(hours=1)
    cleared = guard.run_incident_review_canary("ft", lambda: _check(failure=None))
    assert cleared.action is GuardAction.HEALTHY

    # The flap: the next ordinary check re-opens the hold with new evidence.
    clock["now"] = NOW + timedelta(hours=2)
    reopened = guard.run("ft", lambda: _incident_check(f"incident-{'b' * 24}"))
    assert reopened.action is GuardAction.INCIDENT_REVIEW_REQUIRED

    clock["now"] = NOW + timedelta(hours=10)
    held = guard.run_incident_review_canary(
        "ft",
        lambda: pytest.fail("a flapping provider stays held inside the window"),
    )
    assert held.action is GuardAction.INCIDENT_REVIEW_REQUIRED

    clock["now"] = NOW + timedelta(hours=26)
    recleared = guard.run_incident_review_canary("ft", lambda: _check(failure=None))
    assert recleared.action is GuardAction.HEALTHY


def test_incident_canary_budget_is_consumed_before_dispatch(tmp_path: Path) -> None:
    """A canary that crashes mid-flight still contacted the provider (R9)."""

    guard, _store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    clock["now"] = NOW + timedelta(hours=1)

    def crashing_check() -> ProviderCheckResult:
        raise RuntimeError("mid-flight crash after provider contact")

    with pytest.raises(RuntimeError):
        guard.run_incident_review_canary("ft", crashing_check)

    clock["now"] = NOW + timedelta(hours=5)
    blocked = guard.run_incident_review_canary(
        "ft",
        lambda: pytest.fail("a crashed canary must still consume the budget"),
    )
    assert blocked.action is GuardAction.INCIDENT_REVIEW_REQUIRED


def test_incident_canary_fails_closed_on_unreadable_state(tmp_path: Path) -> None:
    guard, store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    (store.root / "ft.incident-canary.json").write_bytes(b"not-json")
    clock["now"] = NOW + timedelta(hours=1)

    result = guard.run_incident_review_canary(
        "ft",
        lambda: pytest.fail("unreadable canary state must not contact"),
    )

    assert result.action is GuardAction.LOCAL_REPAIR_REQUIRED


def test_incident_canary_is_allowed_exactly_at_the_interval(tmp_path: Path) -> None:
    guard, _store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    contacts = 0

    def counted_check() -> ProviderCheckResult:
        nonlocal contacts
        contacts += 1
        return _incident_check()

    clock["now"] = NOW + timedelta(hours=1)
    guard.run_incident_review_canary("ft", counted_check)
    clock["now"] = NOW + timedelta(hours=25)
    guard.run_incident_review_canary("ft", counted_check)

    assert contacts == 2


def test_incident_canary_due_is_a_cheap_advisory_read(tmp_path: Path) -> None:
    guard, store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)

    assert guard.incident_canary_due("ft") is True
    clock["now"] = NOW + timedelta(hours=1)
    guard.run_incident_review_canary("ft", _incident_check)
    clock["now"] = NOW + timedelta(hours=5)
    assert guard.incident_canary_due("ft") is False
    clock["now"] = NOW + timedelta(hours=26)
    assert guard.incident_canary_due("ft") is True

    (store.root / "ft.incident-canary.json").write_bytes(b"not-json")
    assert guard.incident_canary_due("ft") is True


def test_incident_canary_due_at_names_the_next_permitted_canary(
    tmp_path: Path,
) -> None:
    guard, store, clock = _guard_with_clock(tmp_path)
    _open_incident_hold(guard)
    assert guard.incident_canary_due_at("ft") is None

    clock["now"] = NOW + timedelta(hours=1)
    guard.run_incident_review_canary("ft", _incident_check)
    clock["now"] = NOW + timedelta(hours=5)
    assert guard.incident_canary_due_at("ft") == NOW + timedelta(hours=25)
    assert guard.incident_canary_due("ft") is False

    clock["now"] = NOW + timedelta(hours=25)
    assert guard.incident_canary_due_at("ft") is None

    (store.root / "ft.incident-canary.json").write_bytes(b"not-json")
    assert guard.incident_canary_due_at("ft") is None


def test_incident_canary_leaves_other_hold_classes_untouched(tmp_path: Path) -> None:
    guard, _store = _guard(tmp_path)
    held = guard.run(
        "ft",
        lambda: _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )

    result = guard.run_incident_review_canary(
        "ft",
        lambda: pytest.fail("only incident-review holds permit a canary"),
    )

    assert result.action is GuardAction.PROVIDER_HOLD
    assert result.hold_id == held.hold_id


def test_incident_canary_without_hold_is_an_ordinary_guarded_check(
    tmp_path: Path,
) -> None:
    guard, _store = _guard(tmp_path)

    result = guard.run_incident_review_canary("ft", lambda: _check(failure=None))

    assert result.action is GuardAction.HEALTHY
    observation = guard.last_check("ft")
    assert observation is not None
    assert observation.check.ok is True


def test_on_demand_run_keeps_the_held_short_circuit_for_incidents(
    tmp_path: Path,
) -> None:
    guard, _store = _guard(tmp_path)
    held = _open_incident_hold(guard)

    result = guard.run(
        "ft",
        lambda: pytest.fail("on-demand checks stay held"),
    )

    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert result.hold_id == held.hold_id


def test_provider_guard_scheduled_flag_routes_to_the_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class ScheduledGuard:
        def peek_before_check(self, provider: str) -> object:
            del provider
            return None

        def run(self, provider: str, check_provider) -> GuardResult:  # noqa: ANN001
            calls.append("run")
            return GuardResult(
                provider=provider,
                check=check_provider(),
                action=GuardAction.HEALTHY,
            )

        def run_incident_review_canary(
            self,
            provider: str,
            check_provider,  # noqa: ANN001
        ) -> GuardResult:
            calls.append("canary")
            return GuardResult(
                provider=provider,
                check=check_provider(),
                action=GuardAction.HEALTHY,
            )

    service = _CliService(_check(failure=None))
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", ScheduledGuard)

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--scheduled", "--json"],
    )

    assert invocation.exit_code == 0
    assert calls == ["canary"]
    assert json.loads(invocation.stdout)["action"] == "healthy"


def test_acknowledgement_surfaces_guard_storage_failure(tmp_path: Path) -> None:
    guard, store = _guard(tmp_path)
    store.root.mkdir(mode=0o700)
    (store.root / "ft.json").write_text("not-json", encoding="utf-8")

    with pytest.raises(ProviderGuardPersistenceError, match="hold is invalid"):
        guard.acknowledge("ft", hold_id=f"guard-{'1' * 32}")


def test_provider_guard_cli_reports_unreadable_state_as_a_local_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable hold is a guard verdict, not a bare persistence error."""

    guard, store = _guard(tmp_path)
    store.root.mkdir(parents=True, exist_ok=True)
    (store.root / "ft.json").write_bytes(b"not-json")

    def unexpected_service() -> None:
        raise AssertionError("unreadable state must not construct the service")

    monkeypatch.setattr("newsclip.cli.build_auth_service", unexpected_service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", lambda: guard)
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, **kwargs: (_ for _ in ()).throw(
            AssertionError("unreadable state must not prepare a display")
        ),
    )

    invocation = CliRunner().invoke(
        app,
        ["provider-guard", "--provider", "ft", "--json"],
    )

    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["action"] == "local_repair_required"


def test_provider_guard_cli_reports_contention_without_browser_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A concurrent check must not consume a display lease to learn it lost."""

    guard, store = _guard(tmp_path, lock_timeout_seconds=0.1)

    def unexpected_service() -> None:
        raise AssertionError("a contended check must not construct the service")

    monkeypatch.setattr("newsclip.cli.build_auth_service", unexpected_service)
    monkeypatch.setattr("newsclip.cli.build_provider_guard", lambda: guard)
    monkeypatch.setattr(
        "newsclip.cli._prepare_virtual_display",
        lambda argv, **kwargs: (_ for _ in ()).throw(
            AssertionError("a contended check must not prepare a display")
        ),
    )

    with store.locked("ft"):
        invocation = CliRunner().invoke(
            app,
            ["provider-guard", "--provider", "ft", "--json"],
        )

    assert invocation.exit_code == 1
    assert json.loads(invocation.stdout)["action"] == "check_in_progress"


@pytest.mark.parametrize("kind", ["observed", "suppressed"])
def test_bounded_defense_does_not_create_an_unrecoverable_hold(tmp_path, kind):
    guard, _store = _guard(tmp_path)
    healthy = guard.run("ft", lambda: _check(failure=None))
    previous = guard.last_check("ft")
    check = _check(failure=ProviderCheckFailure.PROVIDER_DEFENSE).model_copy(
        update={"defense_observation": kind, "defense_retry_after_seconds": 1200.0}
    )
    result = guard.run("ft", lambda: check)
    assert healthy.action is GuardAction.HEALTHY
    assert result.action is GuardAction.TRANSIENT_FAILURE
    assert guard.peek("ft") is None
    if kind == "suppressed":
        assert guard.last_check("ft") == previous
    else:
        assert guard.last_check("ft").check == check
    assert guard.run("ft", lambda: _check(failure=None)).action is GuardAction.HEALTHY


def test_defense_hold_preserves_original_incident_reference(tmp_path):
    guard, _ = _guard(tmp_path)
    incident_id = "incident-" + "a" * 24
    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.PROVIDER_DEFENSE, incident_id=incident_id
        ),
    )
    assert result.incident_id == incident_id
    assert guard.peek("ft").incident_id == incident_id


def test_missing_incident_cannot_be_published_as_a_durable_reference(tmp_path):
    guard, store = _guard(tmp_path)
    store.incident_root = tmp_path / "incidents"
    result = guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.PROVIDER_DEFENSE,
            incident_id="incident-" + "a" * 24,
        ),
    )
    assert result.action is GuardAction.LOCAL_REPAIR_REQUIRED
    assert guard.peek("ft") is None


def test_suppressed_incident_canary_preserves_last_actual_page_observation(tmp_path):
    guard, _ = _guard(tmp_path)
    guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.VERIFIED,
            incident_id="incident-" + "b" * 24,
        ),
    )
    previous = guard.last_check("ft")
    suppressed = ProviderCheckResult(
        provider="ft",
        ok=False,
        failure=ProviderCheckFailure.PROVIDER_DEFENSE,
        defense_observation="suppressed",
        defense_retry_after_seconds=1200,
    )
    result = guard.run_incident_review_canary("ft", lambda: suppressed)
    assert result.action is GuardAction.INCIDENT_REVIEW_REQUIRED
    assert guard.last_check("ft") == previous


def test_current_hold_diagnostics_preserve_source_incident_and_canary_budget(tmp_path):
    guard, store, clock = _guard_with_clock(tmp_path)
    opened = _open_incident_hold(guard)
    original = guard.peek("ft")
    clock["now"] = NOW + timedelta(hours=1)
    latest_incident = "incident-" + "b" * 24
    guard.run_incident_review_canary("ft", lambda: _incident_check(latest_incident))
    before = {p.name: p.read_bytes() for p in store.root.glob("*.json")}
    with store.locked("ft"):
        health = guard.current_hold_health("ft")
    assert health.hold_id == opened.hold_id
    assert health.incident_id == original.incident_id
    assert health.incident_id != latest_incident
    assert health.held_operation == "provider_check"
    assert health.last_canary_at == clock["now"]
    assert health.next_eligible_canary_at == NOW + timedelta(hours=25)
    assert before == {p.name: p.read_bytes() for p in store.root.glob("*.json")}
    assert guard.peek("ft") == original
    clock["now"] = NOW + timedelta(hours=25)
    assert guard.current_hold_health("ft").next_eligible_canary_at == clock["now"]
    guard.run_incident_review_canary("ft", lambda: _check(failure=None))
    assert guard.current_hold_health("ft") is None


def test_current_hold_diagnostics_fail_on_corrupt_cadence_and_isolate_users(tmp_path):
    alice, store, _ = _guard_with_clock(tmp_path / "alice")
    bob, _, _ = _guard_with_clock(tmp_path / "bob")
    _open_incident_hold(alice)
    assert alice.current_hold_health("ft") is not None
    assert bob.current_hold_health("ft") is None
    (store.root / "ft.incident-canary.json").write_bytes(b"not-json")
    with pytest.raises(ProviderGuardPersistenceError):
        alice.current_hold_health("ft")
