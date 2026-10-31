"""Behavioural tests for the scheduled session keeper.

The keeper is the only unattended actor permitted to submit credentials, so
these tests pin the bounds rather than the happy path: what it refuses to
touch, when it may spend an attempt, and that a crashed attempt still counts.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.acquisition import (
    AcquisitionEvidence,
    AcquisitionMode,
    ChallengeMode,
    CredentialAction,
    LoginResult,
)
from newsclip.errors import (
    OperatorActionRequiredError,
    PersistenceError,
    ProviderTransportError,
    SessionRequiredError,
)
from newsclip.keeper_outcomes import KeeperOutcome, KeeperOutcomeStore
from newsclip.models import (
    AccessState,
    LoginRequirement,
    ProviderReadiness,
    SessionHealth,
    SessionStatus,
)
from newsclip.provider_check import (
    ProviderCheckFailure,
    ProviderCheckObservation,
    ProviderCheckResult,
)
from newsclip.session_keeper import (
    CredentialBudget,
    KeeperAction,
    KeeperPolicy,
    KeeperResult,
    SessionKeeper,
)

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


class FakeGuard:
    def __init__(
        self,
        hold: object | None = None,
        observation: ProviderCheckObservation | None = None,
    ) -> None:
        self.hold = hold
        self.observation = observation

    def peek(self, provider: str) -> object | None:
        del provider
        return self.hold

    def current_hold_health(self, provider: str):
        return None

    def last_check(self, provider: str) -> ProviderCheckObservation | None:
        del provider
        return self.observation

    def incident_canary_due_at(self, provider: str) -> datetime | None:
        del provider
        return getattr(self, "canary_due_at", None)


class FakeSessions:
    def __init__(
        self,
        *,
        status: SessionStatus = SessionStatus.VERIFIED,
        last_verified_at: datetime | None = NOW,
        retry_not_before: datetime | None = None,
        failure: Exception | None = None,
        needs_credentials: bool = False,
        renewed_status: SessionStatus = SessionStatus.VERIFIED,
        acquired_mode: AcquisitionMode = AcquisitionMode.CREDENTIAL_MINT,
        requires_session: bool = True,
        check_result: ProviderCheckResult | None = None,
    ) -> None:
        self.acquired_mode = acquired_mode
        self.status = status
        self.last_verified_at = last_verified_at
        self.retry_not_before = retry_not_before
        self.failure = failure
        self.needs_credentials = needs_credentials
        self.renewed_status = renewed_status
        self.logins: list[bool] = []
        self.challenge_modes: list[ChallengeMode] = []
        self.requires_session = requires_session
        self.check_result = check_result
        self.checks: list[str] = []

    def defense_pending(self, provider_key: str) -> bool:
        return False

    def defense_contained_until(self, provider_key: str) -> datetime | None:
        return None

    def requires_session_for_provider(self, provider_key: str) -> bool:
        del provider_key
        return self.requires_session

    def provider_check(self, provider_key: str) -> ProviderCheckResult:
        self.checks.append(provider_key)
        if self.check_result is None:
            raise AssertionError("provider_check called without a configured result")
        return self.check_result

    def session_status(self, provider_key: str) -> SessionHealth:
        return SessionHealth(
            provider=provider_key,
            account_key="default",
            status=self.status,
            last_verified_at=self.last_verified_at,
            retry_not_before=self.retry_not_before,
        )

    def login(
        self,
        provider_key: str,
        *,
        headless: bool = False,
        allow_credential_mint: bool = True,
        challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
    ) -> object:
        del headless
        self.logins.append(allow_credential_mint)
        self.challenge_modes.append(challenge_mode)
        # Warm tiers exhausted: this is what acquisition reports when it would
        # have to submit credentials but was refused permission.
        if self.needs_credentials and not allow_credential_mint:
            raise SessionRequiredError("credential_mint_not_permitted")
        if self.failure is not None:
            raise self.failure
        self.status = self.renewed_status
        self.last_verified_at = NOW
        # A real login cannot reach the credential tier when it is refused.
        mode = (
            self.acquired_mode
            if allow_credential_mint
            else AcquisitionMode.ARTIFACT_REUSE
        )
        return LoginResult(
            health=self.session_status(provider_key),
            acquisition=AcquisitionEvidence(
                mode=mode,
                credential_action=(
                    CredentialAction.PASSWORD_SUBMIT
                    if mode is AcquisitionMode.CREDENTIAL_MINT
                    else CredentialAction.NONE
                ),
            ),
        )


def _keeper(
    tmp_path: Path,
    *,
    guard: FakeGuard | None = None,
    sessions: FakeSessions | None = None,
    readiness: ProviderReadiness | None = None,
    policy: KeeperPolicy | None = None,
    now: datetime = NOW,
    diagnostic_id: str | None = None,
    outcomes: KeeperOutcomeStore | None = None,
    transport_pins: object | None = None,
    http_challenges: object | None = None,
) -> tuple[SessionKeeper, FakeSessions, CredentialBudget]:
    resolved_sessions = sessions or FakeSessions()
    budget = CredentialBudget(tmp_path / "session-keeper", utc_now=lambda: now)
    keeper = SessionKeeper(
        guard=guard or FakeGuard(),
        sessions=resolved_sessions,
        budget=budget,
        readiness_probe=lambda provider: (
            readiness
            if readiness is not None
            else ProviderReadiness(provider=provider, missing=())
        ),
        policy=policy or KeeperPolicy(),
        utc_now=lambda: now,
        diagnostic_id=diagnostic_id,
        outcomes=outcomes,
        transport_pins=transport_pins,
        http_challenges=http_challenges,
    )
    return keeper, resolved_sessions, budget


def test_a_blocking_hold_provider_is_never_touched(tmp_path: Path) -> None:
    """Every hold class except the session-evidence ones stops the keeper dead.

    A bare object stands in for an unreadable/unknown hold: the gate fails
    closed, so a future hold kind is never mistaken for a renewable one.
    """

    from newsclip.provider_guard import GuardAction

    class _Hold:
        action = GuardAction.PROVIDER_HOLD

    for hold in (_Hold(), "held"):
        keeper, sessions, _ = _keeper(tmp_path, guard=FakeGuard(hold=hold))

        result = keeper.keep("ft", allow_credential_mint=True)

        assert result.action is KeeperAction.HELD
        assert result.needs_attention is True
        assert sessions.logins == []


def test_a_fresh_session_costs_no_provider_request(tmp_path: Path) -> None:
    keeper, sessions, _ = _keeper(tmp_path)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.FRESH
    assert result.usable is True
    assert sessions.logins == []


def test_renewal_failure_retains_incident_through_serving_success_and_pruning(
    tmp_path, monkeypatch
):
    from test_incidents import URL, _assessment, _fetch, _identity

    import newsclip.incidents as incidents
    from newsclip.composition import _protected_incidents
    from newsclip.defense import DefenseState
    from newsclip.errors import ProviderDefenseError
    from newsclip.incidents import IncidentStore
    from newsclip.keeper_outcomes import enrich_session_health
    from newsclip.timing import TimingOperation

    monkeypatch.setattr(incidents, "_MAX_INCIDENTS_PER_PROVIDER", 2)
    store = IncidentStore(
        tmp_path / "incidents",
        build_identity=_identity(),
        protected_incidents=lambda provider: _protected_incidents(
            tmp_path, provider, _identity()
        ),
    )
    capsule = store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(),
        assessment=_assessment(),
    )
    error = ProviderDefenseError("fixture challenge", provider="ft")
    error.incident_id = capsule.incident_id
    outcomes = KeeperOutcomeStore(tmp_path / "session-keeper", incident_root=store.root)
    keeper, sessions, _ = _keeper(
        tmp_path,
        sessions=FakeSessions(
            last_verified_at=NOW - timedelta(hours=48), failure=error
        ),
        outcomes=outcomes,
        diagnostic_id="cli-renewal-fixture",
    )
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.public_dict()["incident_id"] == capsule.incident_id
    assert result.next_action.value == "review_provider"
    assert sessions.logins == [False]
    assert not result.credential_attempt
    # An unrelated FULL serving read clears defense, not failed renewal proof.
    defense = DefenseState(tmp_path / "provider-defense", incident_root=store.root)
    defense.arm("ft", origin="retrieval")
    defense.attach_incident("ft", capsule.incident_id)
    defense.clear("ft")
    outcomes.record(
        KeeperResult(provider="ft", action=KeeperAction.FRESH), max_age_hours=12
    )
    for i in range(6):
        store.record_assessed_retrieval(
            provider="ft",
            operation=TimingOperation.GET,
            fetch=_fetch(url=URL + f"?new={i}"),
            assessment=_assessment(),
        )
    assert store.evidence_health(capsule.incident_id).status == "complete"
    health = enrich_session_health(
        sessions.session_status("ft"), outcomes.load("ft"), now=NOW
    )
    assert health.public_dict()["renewal_incident_id"] == capsule.incident_id
    assert health.public_dict()["renewal_diagnostic_id"] == "cli-renewal-fixture"
    outcomes.verified("ft")
    assert outcomes.load("ft").incident_id is None
    store.record_assessed_retrieval(
        provider="ft",
        operation=TimingOperation.GET,
        fetch=_fetch(url=URL + "?after-renewal"),
        assessment=_assessment(),
    )
    assert store.evidence_health(capsule.incident_id).status == "missing"


def test_article_only_canary_preserves_failed_session_renewal(tmp_path):
    from test_provider_guard import _check, _guard

    from newsclip.keeper_outcomes import enrich_session_health
    from newsclip.models import SessionDisposition

    outcomes = KeeperOutcomeStore(tmp_path / "session-keeper")
    incident_id = "incident-" + "a" * 24
    outcomes.record(
        KeeperResult(
            provider="ft",
            action=KeeperAction.RENEWAL_FAILED,
            reason_code="provider_defense",
            incident_id=incident_id,
        ),
        max_age_hours=12,
    )
    guard, _ = _guard(tmp_path)
    guard.run(
        "ft",
        lambda: _check(
            failure=ProviderCheckFailure.CONTENT_NOT_FULL,
            disposition=SessionDisposition.VERIFIED,
            incident_id="incident-" + "b" * 24,
        ),
    )
    sessions = FakeSessions(
        last_verified_at=NOW - timedelta(hours=48),
        check_result=_check(failure=None),
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions, guard=guard, outcomes=outcomes)
    before = sessions.last_verified_at
    result = keeper.keep("ft", allow_credential_mint=False)
    assert result.action is KeeperAction.CHECKED
    assert sessions.logins == []
    assert sessions.last_verified_at == before
    assert sessions.checks == ["ft"]
    assert result.public_dict()["overall_state"] == "needs_attention"
    assert result.public_dict()["next_action"] == "review_provider"
    assert result.renewal_unresolved
    stored = outcomes.load("ft")
    assert stored.incident_id == incident_id
    assert stored.consecutive_renewal_failures == 1
    assert (
        enrich_session_health(
            sessions.session_status("ft"), stored, now=NOW
        ).last_renewal_error
        == "provider_defense"
    )


def test_a_stale_session_is_renewed_warm_when_mint_is_not_allowed(
    tmp_path: Path,
) -> None:
    sessions = FakeSessions(last_verified_at=NOW - timedelta(hours=48))
    keeper, sessions, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=False)

    assert result.action is KeeperAction.RENEWED
    assert result.credential_attempt is False
    assert sessions.logins == [False]


def test_credentials_are_spent_only_where_the_host_can_finish_the_login(
    tmp_path: Path,
) -> None:
    """A missing solver escalates instead of burning an attempt."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        needs_credentials=True,
    )
    keeper, sessions, budget = _keeper(
        tmp_path,
        sessions=sessions,
        readiness=ProviderReadiness(
            provider="ft",
            missing=(LoginRequirement.VISION_CLI,),
        ),
    )

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.credential_attempt is False
    assert sessions.logins == [False]
    assert budget.attempts_today("ft") == 0


def test_a_ready_host_spends_one_attempt_and_then_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        needs_credentials=True,
    )
    keeper, sessions, budget = _keeper(tmp_path, sessions=sessions)
    renewed_attempts: list[bool] = []
    original_renewed = keeper._renewed

    def renewed(provider: str, *, credential_attempt: bool) -> KeeperResult:
        renewed_attempts.append(credential_attempt)
        return original_renewed(provider, credential_attempt=credential_attempt)

    monkeypatch.setattr(keeper, "_renewed", renewed)

    first = keeper.keep("ft", allow_credential_mint=True)
    sessions.status = SessionStatus.REQUIRED
    sessions.last_verified_at = None
    second = keeper.keep("ft", allow_credential_mint=True)

    assert first.action is KeeperAction.RENEWED
    assert first.credential_attempt is True
    assert renewed_attempts == [True]
    # The day's attempt is spent: that is a wait, not a person's problem.
    assert second.action is KeeperAction.COOLDOWN
    assert second.reason_code == "credential_budget_spent"
    assert second.needs_attention is False
    assert second.credential_attempt is False
    assert budget.attempts_today("ft") == 1
    assert sessions.logins == [False, True, False]


def test_a_warm_renewal_spends_nothing(tmp_path: Path) -> None:
    """The budget counts submissions, so a warm repair costs it nothing."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        acquired_mode=AcquisitionMode.PROFILE_REHYDRATE,
    )
    keeper, _, budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.RENEWED
    assert result.credential_attempt is False
    assert budget.attempts_today("ft") == 0


def test_the_budget_is_written_before_dispatch(tmp_path: Path) -> None:
    """A login that dies mid-flight must still consume its attempt."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        needs_credentials=True,
        failure=RuntimeError("crashed after submitting"),
    )
    keeper, _, budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.RENEWAL_FAILED
    assert budget.attempts_today("ft") == 1


def test_a_terminal_login_verdict_escalates_rather_than_retrying(
    tmp_path: Path,
) -> None:
    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        needs_credentials=True,
        failure=OperatorActionRequiredError(
            "account_alert",
            provider="ft",
            reason_code="account_alert",
        ),
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "account_alert"
    assert result.needs_attention is True


def test_an_operator_action_status_is_not_retried(tmp_path: Path) -> None:
    sessions = FakeSessions(status=SessionStatus.OPERATOR_ACTION)
    keeper, sessions, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert sessions.logins == []


def test_an_unexpired_cooldown_is_left_alone(tmp_path: Path) -> None:
    sessions = FakeSessions(
        status=SessionStatus.COOLDOWN,
        retry_not_before=NOW + timedelta(minutes=10),
    )
    keeper, sessions, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.COOLDOWN
    assert sessions.logins == []


def test_attempts_outside_the_window_no_longer_count(tmp_path: Path) -> None:
    """Yesterday's attempt must not hold today's budget shut."""

    root = tmp_path / "session-keeper"
    yesterday = CredentialBudget(root, utc_now=lambda: NOW - timedelta(hours=48))
    yesterday.reserve("ft", limit=1)

    today = CredentialBudget(root, utc_now=lambda: NOW)

    assert yesterday.attempts_today("ft") == 1
    assert today.attempts_today("ft") == 0


def test_a_malformed_budget_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "session-keeper"
    root.mkdir(parents=True)
    (root / "ft.json").write_bytes(b"not-json")
    budget = CredentialBudget(root, utc_now=lambda: NOW)

    with pytest.raises(PersistenceError):
        budget.attempts_today("ft")


def test_a_budget_timestamp_without_timezone_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "session-keeper"
    root.mkdir(parents=True)
    (root / "ft.json").write_text('{"attempts": ["2026-07-30T11:00:00"]}')
    budget = CredentialBudget(root, utc_now=lambda: NOW)

    with pytest.raises(PersistenceError):
        budget.next_attempt_at("ft", limit=1)
    with pytest.raises(PersistenceError):
        budget.reserve("ft", limit=1)


def test_the_budget_file_is_private(tmp_path: Path) -> None:
    budget = CredentialBudget(tmp_path / "session-keeper", utc_now=lambda: NOW)
    budget.reserve("ft", limit=1)

    assert oct((budget.root / "ft.json").stat().st_mode & 0o777) == "0o600"
    assert oct(budget.root.stat().st_mode & 0o777) == "0o700"


def test_only_a_bounded_reason_code_reaches_the_scheduler_log(
    tmp_path: Path,
) -> None:
    """A provider message must not ride out on the keeper's result."""

    leak = "password=CORRECTHORSE from https://provider.test/login"
    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        failure=OperatorActionRequiredError(leak, provider="ft"),
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code is None
    assert "CORRECTHORSE" not in str(result.public_dict())


def test_local_infrastructure_failure_is_transient_not_an_escalation(
    tmp_path: Path,
) -> None:
    """A busy profile lease must not page a human."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        failure=SessionRequiredError("profile_infrastructure"),
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.reason_code == "profile_infrastructure"


def test_refusing_to_mint_asks_for_a_human_instead(tmp_path: Path) -> None:
    """Warm cannot repair it and credentials are not permitted here."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        needs_credentials=True,
    )
    keeper, sessions, budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=False)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "credential_mint_not_permitted"
    assert sessions.logins == [False]
    assert budget.attempts_today("ft") == 0


class _CliKeeper:
    def __init__(self, action: KeeperAction) -> None:
        self.action = action

    def keep(
        self,
        provider: str,
        *,
        allow_credential_mint: bool,
        ignore_escalation: bool = False,
        recovery_only: bool = False,
        reconcile_failed_recovery: bool = False,
    ) -> object:
        del (
            allow_credential_mint,
            ignore_escalation,
            recovery_only,
            reconcile_failed_recovery,
        )
        from newsclip.session_keeper import KeeperResult

        return KeeperResult(provider=provider, action=self.action)


class _CliService:
    def __init__(self) -> None:
        self.closed = False

    def requires_browser_for_provider(self, provider: str) -> bool:
        del provider
        return False

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("action", "exit_code"),
    (
        (KeeperAction.FRESH, 0),
        (KeeperAction.RENEWED, 0),
        # A cooldown is the system waiting as designed, not a page-worthy
        # event; alerting on it would train an operator to ignore alerts.
        (KeeperAction.COOLDOWN, 0),
        (KeeperAction.HELD, 1),
        (KeeperAction.OPERATOR_ACTION_REQUIRED, 1),
        (KeeperAction.RENEWAL_FAILED, 1),
    ),
)
def test_keeper_cli_exits_nonzero_only_when_a_human_is_needed(
    monkeypatch: pytest.MonkeyPatch,
    action: KeeperAction,
    exit_code: int,
) -> None:
    from typer.testing import CliRunner

    from newsclip.cli import app

    service = _CliService()
    monkeypatch.setattr("newsclip.cli.build_auth_service", lambda: service)
    monkeypatch.setattr(
        "newsclip.cli.build_session_keeper",
        lambda sessions, policy=None: _CliKeeper(action),
    )

    invocation = CliRunner().invoke(app, ["auth", "keep", "ft", "--json"])

    assert invocation.exit_code == exit_code
    payload = json.loads(invocation.stdout)
    expected = {
        "provider": "ft",
        "action": action.value,
        "status": None,
        "stale": False,
        "credential_attempt": False,
        "reason_code": None,
        "diagnostic_id": None,
        "overall_state": "needs_attention"
        if exit_code
        else ("waiting" if action is KeeperAction.COOLDOWN else "healthy"),
    }
    # Outcomes needing a person also carry the call that fixes them, so the
    # alert built from this payload is actionable (R4). Healthy outcomes must
    # stay exactly as they were.
    if exit_code:
        assert payload.pop("next_action")
        assert payload.pop("repair_hint")
    assert payload == expected
    assert service.closed is True


def test_budget_writes_are_durable_across_power_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A spent attempt must not be lost to an undurable rename."""

    import signin_window.state as private_state

    synced: list[Path] = []
    real_fsync = private_state.fsync_directory

    def observe(path: Path) -> None:
        synced.append(path)
        real_fsync(path)

    monkeypatch.setattr(private_state, "fsync_directory", observe)
    budget = CredentialBudget(tmp_path / "session-keeper", utc_now=lambda: NOW)
    budget.reserve("ft", limit=1)

    assert budget.root in synced


def test_a_concurrent_holder_blocks_the_budget_rather_than_racing(
    tmp_path: Path,
) -> None:
    from newsclip.private_state import exclusive_lock

    root = tmp_path / "session-keeper"
    budget = CredentialBudget(
        root,
        utc_now=lambda: NOW,
        lock_timeout_seconds=0.1,
    )

    with (
        exclusive_lock(root / "ft.lock", timeout_seconds=1),
        pytest.raises(PersistenceError),
    ):
        budget.reserve("ft", limit=1)


def test_two_keepers_cannot_both_spend_one_window(tmp_path: Path) -> None:
    """Deciding and recording must share a lock, or the budget means nothing."""

    root = tmp_path / "session-keeper"
    first = CredentialBudget(root, utc_now=lambda: NOW)
    second = CredentialBudget(root, utc_now=lambda: NOW + timedelta(seconds=1))

    assert first.reserve("ft", limit=1) is True
    assert second.reserve("ft", limit=1) is False
    assert first.attempts_today("ft") == 1


def _reserve_in_child(root: str, moment_offset: int, result) -> None:  # noqa: ANN001
    budget = CredentialBudget(
        Path(root),
        utc_now=lambda: NOW + timedelta(seconds=moment_offset),
        lock_timeout_seconds=5,
    )
    result.value = 1 if budget.reserve("ft", limit=1) else 0


def test_concurrent_processes_cannot_both_claim_one_attempt(tmp_path: Path) -> None:
    """The demonstrated race: both keepers observed an unspent window."""

    from multiprocessing import get_context

    context = get_context("fork")
    root = str(tmp_path / "session-keeper")
    outcomes = [context.Value("i", -1) for _ in range(2)]
    workers = [
        context.Process(target=_reserve_in_child, args=(root, index, outcome))
        for index, outcome in enumerate(outcomes)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)

    granted = [outcome.value for outcome in outcomes]
    assert sorted(granted) == [0, 1]
    assert CredentialBudget(Path(root), utc_now=lambda: NOW).attempts_today("ft") == 1


def test_lock_translates_only_its_own_failures(tmp_path: Path) -> None:
    """A caller's error must not be relabelled as a locking failure."""

    from newsclip.private_state import PrivateStateError, exclusive_lock

    sentinel = ValueError("caller failed")
    with (
        pytest.raises(ValueError) as raised,
        exclusive_lock(tmp_path / "state" / "ft.lock", timeout_seconds=1),
    ):
        raise sentinel

    assert raised.value is sentinel

    symlinked = tmp_path / "state" / "linked.lock"
    symlinked.parent.mkdir(parents=True, exist_ok=True)
    symlinked.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(PrivateStateError), exclusive_lock(symlinked, timeout_seconds=1):
        pass  # pragma: no cover - acquisition must fail first


def test_a_spent_budget_waits_while_an_unusable_host_escalates(
    tmp_path: Path,
) -> None:
    """Both refuse the login; only one of them is a person's problem."""

    def sessions() -> FakeSessions:
        return FakeSessions(
            status=SessionStatus.REQUIRED,
            last_verified_at=None,
            needs_credentials=True,
        )

    spent, _, _ = _keeper(
        tmp_path / "spent",
        sessions=sessions(),
        policy=KeeperPolicy(credential_attempts_per_day=0),
    )
    unusable, _, _ = _keeper(
        tmp_path / "unusable",
        sessions=sessions(),
        readiness=ProviderReadiness(
            provider="ft",
            missing=(LoginRequirement.OP_CLI,),
        ),
    )

    # Zero per day is an operator decision, not a wait for the window.
    spent_result = spent.keep("ft", allow_credential_mint=True)
    unusable_result = unusable.keep("ft", allow_credential_mint=True)

    assert spent_result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert spent_result.reason_code == "credential_mint_not_permitted"
    assert unusable_result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert unusable_result.reason_code == "credential_host_not_ready"


def test_upkeep_settles_instead_of_renewing_every_cycle(tmp_path: Path) -> None:
    """Renewal has to advance the clock it is judged by.

    Otherwise a proven session looks equally stale for ever and upkeep
    re-proves it on every cycle, contacting the provider without end.
    """

    import test_sessions as store_fixtures

    clock = {"now": store_fixtures.NOW}
    adapter = store_fixtures.FakeAdapter(profile=tmp_path / "profiles/ft/default")
    store = store_fixtures._store(
        tmp_path / "state",
        adapter=adapter,
        clock=lambda: clock["now"],
    )
    store.explicit_login("ft")

    class _NoHolds:
        def current_hold_health(self, provider: str):
            return None

        def peek(self, provider: str) -> None:
            del provider
            return None

    class _Store:
        def defense_pending(self, provider_key: str) -> bool:
            return False

        def requires_session_for_provider(self, provider_key: str) -> bool:
            del provider_key
            return True

        def provider_check(self, provider_key: str):  # noqa: ANN202
            raise AssertionError("a session provider must not be watched")

        def session_status(self, provider_key: str):  # noqa: ANN202
            return store.status(provider_key)

        def login(
            self,
            provider_key: str,
            *,
            headless: bool = False,
            allow_credential_mint: bool = True,
            challenge_mode: ChallengeMode = ChallengeMode.DETECT_ONLY,
        ):  # noqa: ANN202
            del headless
            acquired = store.explicit_login(
                provider_key,
                allow_credential_mint=allow_credential_mint,
                challenge_mode=challenge_mode,
            )
            return LoginResult(
                health=store.status(provider_key),
                acquisition=acquired.evidence,
            )

    keeper = SessionKeeper(
        guard=_NoHolds(),
        sessions=_Store(),
        budget=CredentialBudget(tmp_path / "budget", utc_now=lambda: clock["now"]),
        readiness_probe=lambda provider: ProviderReadiness(
            provider=provider, missing=()
        ),
        policy=KeeperPolicy(max_age_hours=12),
        utc_now=lambda: clock["now"],
    )

    clock["now"] = store_fixtures.NOW + timedelta(hours=24)
    first = keeper.keep("ft", allow_credential_mint=False)
    clock["now"] += timedelta(hours=1)
    second = keeper.keep("ft", allow_credential_mint=False)

    assert first.action is KeeperAction.RENEWED
    # An hour later the session is still fresh: no further provider contact.
    assert second.action is KeeperAction.FRESH


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        # Bloomberg's real shape: a bounded code the error already carries.
        (
            ProviderTransportError("paid_probe_transport_failure"),
            "paid_probe_transport_failure",
        ),
        # No specific code, but the shared classifier still names the class.
        (ProviderTransportError(""), "transport"),
        # Recognized by nothing: labelled rather than left empty.
        (RuntimeError("something nobody anticipated"), "unclassified_error"),
    ),
)
def test_every_failure_is_named(
    tmp_path: Path,
    failure: Exception,
    expected: str,
) -> None:
    """A null reason makes a classified failure look like an unknown one."""

    sessions = FakeSessions(
        status=SessionStatus.REQUIRED,
        last_verified_at=None,
        failure=failure,
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=False)

    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.reason_code == expected


def test_a_failure_reports_where_the_session_ended_up(tmp_path: Path) -> None:
    """Acquisition can move a session on as it fails.

    Reproducing Bloomberg's shape against the real store drove it to a
    cooldown, while the read taken before the attempt still said verified.
    """

    class MovesWhileFailing(FakeSessions):
        def session_status(self, provider_key: str) -> SessionHealth:
            health = super().session_status(provider_key)
            # The first read is the one taken before the attempt.
            if self.logins:
                return health.model_copy(update={"status": SessionStatus.COOLDOWN})
            return health

    sessions = MovesWhileFailing(
        last_verified_at=NOW - timedelta(hours=48),
        failure=ProviderTransportError("paid_probe_transport_failure"),
    )
    keeper, sessions, _ = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("ft", allow_credential_mint=False)

    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.status is SessionStatus.COOLDOWN


def test_results_carry_the_runs_evidence_reference(tmp_path: Path) -> None:
    """A named outcome with no way back to its trace is hard to diagnose."""

    keeper, _, _ = _keeper(tmp_path, diagnostic_id="cli-abc123")

    result = keeper.keep("ft", allow_credential_mint=False)

    assert result.diagnostic_id == "cli-abc123"
    assert result.public_dict()["diagnostic_id"] == "cli-abc123"


def _escalated_store(
    tmp_path: Path, *, canary_spent_at: datetime | None = None
) -> KeeperOutcomeStore:
    """An outcome history for `bloomberg` that has already escalated."""

    root = tmp_path / "session-keeper"
    root.mkdir(parents=True, exist_ok=True)
    payload = KeeperOutcome(
        provider="bloomberg",
        action="operator_action_required",
        reason_code="session_verification_unresolved",
        recorded_at=NOW,
        consecutive_renewal_failures=8,
        consecutive_inconclusive=3,
        last_escalation_canary_at=canary_spent_at,
        max_age_hours=12.0,
    )
    (root / "bloomberg.outcome.json").write_text(
        json.dumps(payload.model_dump(mode="json"), sort_keys=True)
    )
    return KeeperOutcomeStore(root, utc_now=lambda: NOW)


def _escalated(
    tmp_path: Path,
    *,
    guard: FakeGuard | None = None,
    sessions: FakeSessions | None = None,
    canary_spent_at: datetime | None = None,
) -> tuple[SessionKeeper, FakeSessions]:
    keeper, sessions, _ = _keeper(
        tmp_path,
        sessions=sessions or FakeSessions(last_verified_at=NOW - timedelta(days=2)),
        guard=guard,
        outcomes=_escalated_store(tmp_path, canary_spent_at=canary_spent_at),
    )
    return keeper, sessions


def test_a_scheduled_cycle_does_not_renew_an_escalated_provider(
    tmp_path: Path,
) -> None:
    """The escalation exists to stop hourly probes that resolve nothing.

    Without contradicting evidence — here the canary itself reports the
    session is not serving — the latch holds and no renewal runs.
    """

    keeper, sessions = _escalated(
        tmp_path,
        sessions=FakeSessions(
            last_verified_at=NOW - timedelta(days=2),
            check_result=_check(
                ok=False,
                failure=ProviderCheckFailure.CONTENT_NOT_FULL,
                provider="bloomberg",
            ),
        ),
    )

    result = keeper.keep("bloomberg", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "session_verification_unresolved"
    assert sessions.checks == ["bloomberg"]
    assert sessions.logins == []


def test_an_explicit_repair_may_ignore_the_escalation(tmp_path: Path) -> None:
    """Only a renewal clears the escalation and the escalation stops the
    keeper renewing, so without this a repaired cause could never be proven
    (2026-07-28: Bloomberg's inconclusive run was a missing host library)."""

    keeper, sessions = _escalated(tmp_path)

    result = keeper.keep(
        "bloomberg", allow_credential_mint=True, ignore_escalation=True
    )

    assert result.action is KeeperAction.RENEWED
    assert sessions.logins != []


def test_ignoring_the_escalation_still_respects_a_blocking_hold(
    tmp_path: Path,
) -> None:
    """It relaxes one gate, not the brakes."""

    from newsclip.provider_guard import GuardAction

    class _Hold:
        action = GuardAction.PROVIDER_HOLD

    keeper, sessions = _escalated(tmp_path, guard=FakeGuard(hold=_Hold()))

    result = keeper.keep(
        "bloomberg", allow_credential_mint=True, ignore_escalation=True
    )

    assert result.action is KeeperAction.HELD
    assert sessions.logins == []


def test_contradicting_canary_evidence_lets_one_renewal_through_the_latch(
    tmp_path: Path,
) -> None:
    """A FULL guarded check disproves "unentitled" with live evidence.

    The 2026-08-06 Bloomberg escalation was a probe that could not read its
    page while the session served full articles; the only exit was a manual
    `ignore_escalation`. With contradicting evidence in hand the latch admits
    one renewal, and its success resets both streaks unattended.
    """

    keeper, sessions = _escalated(
        tmp_path,
        sessions=FakeSessions(
            last_verified_at=NOW - timedelta(days=2),
            check_result=_check(ok=True, provider="bloomberg"),
        ),
    )

    result = keeper.keep("bloomberg", allow_credential_mint=True)

    assert result.action is KeeperAction.RENEWED
    assert sessions.checks == ["bloomberg"]
    assert sessions.logins != []
    recorded = KeeperOutcomeStore(
        tmp_path / "session-keeper", utc_now=lambda: NOW
    ).load("bloomberg")
    assert recorded is not None
    assert recorded.consecutive_renewal_failures == 0
    assert recorded.consecutive_inconclusive == 0
    # The renewal it admitted does not refund the spend.
    assert recorded.last_escalation_canary_at is not None


def test_the_escalation_canary_spends_once_per_day(tmp_path: Path) -> None:
    """A spent window escalates without any provider contact at all."""

    keeper, sessions = _escalated(
        tmp_path,
        sessions=FakeSessions(
            last_verified_at=NOW - timedelta(days=2),
            check_result=_check(ok=True, provider="bloomberg"),
        ),
        canary_spent_at=NOW - timedelta(hours=1),
    )

    result = keeper.keep("bloomberg", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert result.reason_code == "session_verification_unresolved"
    assert sessions.checks == []
    assert sessions.logins == []


def test_a_crashed_canary_keeps_the_latch_and_the_spend(tmp_path: Path) -> None:
    """The budget is recorded before dispatch, never after.

    A check that dies mid-flight may still have contacted the provider; an
    unconsumed spend would retry into the latch on the next cycle.
    """

    class CrashingCheck(FakeSessions):
        def provider_check(self, provider_key: str) -> ProviderCheckResult:
            self.checks.append(provider_key)
            raise ProviderTransportError("route_unreachable")

    keeper, sessions = _escalated(
        tmp_path,
        sessions=CrashingCheck(last_verified_at=NOW - timedelta(days=2)),
    )

    result = keeper.keep("bloomberg", allow_credential_mint=True)

    assert result.action is KeeperAction.OPERATOR_ACTION_REQUIRED
    assert sessions.checks == ["bloomberg"]
    assert sessions.logins == []
    recorded = KeeperOutcomeStore(
        tmp_path / "session-keeper", utc_now=lambda: NOW
    ).load("bloomberg")
    assert recorded is not None
    assert recorded.last_escalation_canary_at == NOW


def _check(
    *,
    ok: bool,
    failure: ProviderCheckFailure | None = None,
    provider: str = "reuters",
) -> ProviderCheckResult:
    if ok:
        return ProviderCheckResult(
            provider=provider,
            ok=True,
            search_result_count=1,
            access_state=AccessState.FULL,
            reason="full_article_verified",
            identity_match=True,
            word_count=600,
        )
    return ProviderCheckResult(provider=provider, ok=False, failure=failure)


def test_a_sessionless_provider_is_watched_rather_than_renewed(
    tmp_path: Path,
) -> None:
    """A pinned transport decays with nothing in the product noticing.

    Reuters holds no session, so every session verb raises for it and it
    entered no cycle at all — which is why its fingerprint could rot for five
    days unreported. The cycle watches it instead.
    """

    sessions = FakeSessions(requires_session=False, check_result=_check(ok=True))
    keeper, _sessions, budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("reuters", allow_credential_mint=True)

    assert result.action is KeeperAction.CHECKED
    assert result.usable is True
    assert result.needs_attention is False
    assert sessions.checks == ["reuters"]
    # Nothing was renewed, and no credential was spent on a provider that has
    # no credentials to spend.
    assert sessions.logins == []
    assert budget.attempts_today("reuters") == 0


def test_a_watched_provider_that_stops_serving_asks_for_a_person(
    tmp_path: Path,
) -> None:
    sessions = FakeSessions(
        requires_session=False,
        check_result=_check(ok=False, failure=ProviderCheckFailure.CONTENT_NOT_FULL),
    )
    keeper, _sessions, _budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("reuters", allow_credential_mint=True)

    assert result.action is KeeperAction.CHECK_FAILED
    assert result.usable is False
    assert result.needs_attention is True
    assert result.reason_code == "content_not_full"
    hint = result.repair_hint
    assert hint is not None
    # The usual session repairs do not apply and would send the reader in a
    # circle; what drifted is the transport.
    assert "re-characterize" in hint
    assert "do not retry blindly" in hint
    assert "auth login" not in hint


def test_a_contained_provider_is_not_paged_for(tmp_path: Path) -> None:
    """Containment is the system waiting exactly as designed.

    `provider_check` gates on the defense record and never contacts a
    contained provider, so a watch cannot feed the edge it is watching. It
    must not page either: alerting on a working cooldown trains the reader to
    ignore the alerts that matter.
    """

    sessions = FakeSessions(
        requires_session=False,
        check_result=_check(ok=False, failure=ProviderCheckFailure.PROVIDER_DEFENSE),
    )
    keeper, _sessions, _budget = _keeper(tmp_path, sessions=sessions)

    result = keeper.keep("reuters", allow_credential_mint=True)

    assert result.action is KeeperAction.COOLDOWN
    assert result.needs_attention is False
    assert result.repair_hint is None


def test_a_hold_still_stops_a_watch(tmp_path: Path) -> None:
    """A sessionless provider gets no exemption from the repository's brake."""

    from newsclip.provider_guard import GuardAction

    class _Hold:
        action = GuardAction.PROVIDER_HOLD

    sessions = FakeSessions(requires_session=False, check_result=_check(ok=True))
    keeper, _sessions, _budget = _keeper(
        tmp_path,
        guard=FakeGuard(hold=_Hold()),
        sessions=sessions,
    )

    result = keeper.keep("reuters", allow_credential_mint=True)

    assert result.action is KeeperAction.HELD
    assert sessions.checks == []


def test_watch_drips_one_candidate_beside_the_check(tmp_path: Path) -> None:
    """R8: the drip rides the cycle that already runs, once per cycle."""

    dripped: list[str] = []

    class _Drip:
        def drip(self, provider: str) -> object:
            dripped.append(provider)
            return None

    keeper, sessions, _budget = _keeper(
        tmp_path,
        sessions=FakeSessions(requires_session=False, check_result=_check(ok=True)),
        transport_pins=_Drip(),
    )

    result = keeper.keep("reuters", allow_credential_mint=False)

    assert result.action is KeeperAction.CHECKED
    assert dripped == ["reuters"]
    assert sessions.checks == ["reuters"]


def test_a_failing_drip_never_changes_the_watch_verdict(tmp_path: Path) -> None:
    """The drip heals the fast path; the watch reports whether it serves."""

    class _BrokenDrip:
        def drip(self, provider: str) -> object:
            raise RuntimeError("pin state exploded")

    keeper, _sessions, _budget = _keeper(
        tmp_path,
        sessions=FakeSessions(requires_session=False, check_result=_check(ok=True)),
        transport_pins=_BrokenDrip(),
    )

    result = keeper.keep("reuters", allow_credential_mint=False)

    assert result.action is KeeperAction.CHECKED
    assert result.needs_attention is False


def test_watch_without_a_drip_behaves_exactly_as_before(tmp_path: Path) -> None:
    keeper, sessions, _budget = _keeper(
        tmp_path,
        sessions=FakeSessions(requires_session=False, check_result=_check(ok=True)),
    )

    assert keeper.keep("reuters", allow_credential_mint=False).action is (
        KeeperAction.CHECKED
    )
    assert sessions.checks == ["reuters"]


def test_keeper_supplies_approved_challenge_mode_to_both_acquisition_tiers(tmp_path):
    sessions = FakeSessions(needs_credentials=True, status=SessionStatus.REQUIRED)
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)
    keeper.keep("ft", allow_credential_mint=True)
    assert sessions.logins == [False, True]
    assert sessions.challenge_modes == [ChallengeMode.AUTO, ChallengeMode.AUTO]


def test_keeper_honors_detect_only_for_both_acquisition_tiers(tmp_path):
    sessions = FakeSessions(needs_credentials=True, status=SessionStatus.REQUIRED)
    keeper, _, _ = _keeper(tmp_path, sessions=sessions)
    keeper._challenge_mode = ChallengeMode.DETECT_ONLY
    keeper.keep("ft", allow_credential_mint=True)
    assert sessions.challenge_modes == [
        ChallengeMode.DETECT_ONLY,
        ChallengeMode.DETECT_ONLY,
    ]


class RecoverySessions(FakeSessions):
    def __init__(self, *, article_failure=None, **kwargs):
        super().__init__(**kwargs)
        from uuid import uuid4

        self.generation = uuid4()
        self.article_failure = article_failure
        self.article_checks = []
        self.session_checks = []
        self.contained_until = None

    def recovery_generation(self, provider):
        return self.generation

    def defense_contained_until(self, provider):
        return self.contained_until

    def verify_recovery_session(self, provider):
        self.session_checks.append(provider)

    def validate_recovery_url(self, provider, url):
        assert url.startswith("https://www.ft.com/content/")

    def verify_recovery_article(self, provider, url):
        self.article_checks.append(url)
        if self.article_failure:
            raise self.article_failure


def _recovery_keeper(tmp_path, sessions=None, *, session_required=False):
    from newsclip.recovery import RecoveryStore

    sessions = sessions or RecoverySessions()
    store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    keeper, _, budget = _keeper(tmp_path, sessions=sessions)
    keeper._recovery_store = store
    record = store.request(
        "ft",
        generation_id=sessions.generation,
        session_required=session_required,
        url="https://www.ft.com/content/fixture",
        incident_id=None,
        diagnostic_id="mcp-first",
    )
    return keeper, sessions, store, record, budget


def test_pending_failure_overrides_age_and_verifies_exact_article(tmp_path):
    keeper, sessions, store, record, budget = _recovery_keeper(tmp_path)
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.action is KeeperAction.CHECKED
    assert sessions.logins == []
    assert sessions.article_checks == [str(record.url)]
    assert not result.recovery.session_verified
    assert result.recovery.article_verified
    assert budget.attempts_today("ft") == 0
    assert (
        keeper.keep("ft", allow_credential_mint=True, recovery_only=True).action
        is KeeperAction.IDLE
    )
    assert sessions.logins == []


def test_broken_article_cannot_loop_login(tmp_path):
    from newsclip.errors import ContentNotFullError

    keeper, sessions, store, record, _ = _recovery_keeper(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.CHECK_FAILED
    assert not result.recovery.session_verified
    assert not result.recovery.article_verified
    for _ in range(3):
        keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert sessions.logins == []
    assert len(sessions.article_checks) == 1


def test_ops_heal_rechecks_failed_url_once_after_new_full_guard_proof(tmp_path):
    from newsclip.errors import ContentNotFullError

    keeper, sessions, store, record, budget = _recovery_keeper(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    failed = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert failed.recovery.status.value == "failed"
    assert sessions.article_checks == [str(record.url)]

    store._now = lambda: NOW + timedelta(minutes=20)
    keeper._utc_now = store._now
    keeper._guard = FakeGuard(
        observation=ProviderCheckObservation(
            provider="ft",
            checked_at=NOW + timedelta(minutes=20),
            check=_check(ok=True, provider="ft"),
        )
    )
    sessions.article_failure = None

    # Inspection is read-only; either the next scheduled owner or a manual
    # heal can consume this proof, with the same single reservation.
    inspected = keeper.inspect_recovery("ft")
    assert inspected.overall_state.value == "waiting"
    assert sessions.article_checks == [str(record.url)]

    healed = keeper.keep(
        "ft",
        allow_credential_mint=True,
        reconcile_failed_recovery=True,
    )
    assert healed.action is KeeperAction.CHECKED
    assert healed.recovery.article_verified
    assert healed.overall_state.value == "healthy"
    assert sessions.logins == []
    assert sessions.article_checks == [str(record.url), str(record.url)]
    assert store.load("ft").last_reconciliation_check_at == NOW + timedelta(minutes=20)
    assert budget.attempts_today("ft") == 0

    keeper.keep(
        "ft",
        allow_credential_mint=True,
        reconcile_failed_recovery=True,
    )
    assert sessions.article_checks == [str(record.url), str(record.url)]


def test_hourly_freshness_cannot_hide_unresolved_article_recovery(tmp_path):
    from newsclip.errors import ContentNotFullError

    keeper, sessions, store, _, _ = _recovery_keeper(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    failure = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    following = keeper.keep("ft", allow_credential_mint=True)
    assert following.action is KeeperAction.FRESH
    assert not following.needs_attention
    assert following.overall_state.value == "waiting"
    assert following.automatic_recovery_action == "wait_for_provider_check"
    assert following.recovery == failure.recovery
    assert "article" in following.repair_hint
    assert sessions.logins == []

    store.article_verified("ft", "https://www.ft.com/content/fixture", verified_at=NOW)
    settled = keeper.keep("ft", allow_credential_mint=True)
    assert not settled.needs_attention


def test_successful_serving_between_read_and_claim_is_not_a_failed_login(
    tmp_path, monkeypatch
):
    keeper, sessions, store, record, _ = _recovery_keeper(tmp_path)
    claim = store.claim

    def after_serving(provider, diagnostic_id):
        store.article_verified(provider, str(record.url), verified_at=NOW)
        return claim(provider, diagnostic_id)

    monkeypatch.setattr(store, "claim", after_serving)
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.action is KeeperAction.CHECKED
    assert result.recovery.article_verified
    assert not result.needs_attention
    assert sessions.logins == []


def test_hourly_cli_reports_waiting_for_automatic_proof_without_hiding_failure(
    tmp_path, monkeypatch
):
    from typer.testing import CliRunner

    from newsclip.cli import app
    from newsclip.errors import ContentNotFullError

    keeper, _, store, record, _ = _recovery_keeper(
        tmp_path,
        RecoverySessions(article_failure=ContentNotFullError("paywall_teaser")),
    )
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    monkeypatch.setattr("newsclip.cli.build_auth_service", _CliService)
    monkeypatch.setattr(
        "newsclip.cli.build_session_keeper", lambda *args, **kwargs: keeper
    )
    invocation = CliRunner().invoke(app, ["auth", "keep", "ft", "--json"])
    assert invocation.exit_code == 0
    payload = json.loads(invocation.stdout)
    assert payload["action"] == "fresh"
    assert payload["recovery"]["request_id"] == record.health.request_id
    assert payload["recovery"]["status"] == "failed"
    assert payload["overall_state"] == "waiting"
    assert payload["automatic_recovery_action"] == "wait_for_provider_check"
    assert "article" in payload["repair_hint"]


@pytest.mark.parametrize("deferred", [False, True])
def test_pending_recovery_preserves_scheduled_incident_canary(tmp_path, deferred):
    from types import SimpleNamespace

    from newsclip.provider_guard import GuardAction

    keeper, sessions, store, _, _ = _recovery_keeper(tmp_path)
    canaries = []

    class Guard(FakeGuard):
        def run_incident_review_canary(self, provider, check):
            canaries.append(provider)
            return SimpleNamespace(action=GuardAction.INCIDENT_REVIEW_REQUIRED)

    keeper._guard = Guard(SimpleNamespace(action=GuardAction.INCIDENT_REVIEW_REQUIRED))
    if deferred:
        store.defer("ft", until=NOW + timedelta(hours=1), reason="provider_held")
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert canaries == []
    keeper.keep("ft", allow_credential_mint=True)
    assert canaries == ["ft"]
    assert store.load("ft").health.attempts == 0
    assert sessions.logins == []


@pytest.mark.parametrize("recovery_only", [True, False])
def test_contended_guard_is_busy_not_a_recovery_worker_failure(tmp_path, recovery_only):
    """A guarded check in flight owns the guard lock; that is contention.

    Surfacing it as persistence made the watcher settle the request as
    ``recovery_worker_failed`` and park article recovery for review.
    """
    from newsclip.models import RecoveryStatus
    from newsclip.provider_guard import ProviderGuardBusyError

    keeper, sessions, store, _, budget = _recovery_keeper(tmp_path)

    class ContendedGuard(FakeGuard):
        def peek(self, provider):
            raise ProviderGuardBusyError("provider guard check is already running")

    keeper._guard = ContendedGuard()

    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=recovery_only)

    assert result.action is KeeperAction.BUSY
    assert result.public_dict()["action"] == "busy"
    record = store.load("ft")
    assert record.health.status is RecoveryStatus.PENDING
    assert record.health.attempts == 0
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0


@pytest.mark.parametrize(
    ("action", "canary_due_at", "expected"),
    [
        ("provider_hold", None, NOW + timedelta(hours=1)),
        ("operator_action", None, NOW + timedelta(hours=1)),
        ("incident_review_required", None, NOW + timedelta(hours=1)),
        (
            "incident_review_required",
            NOW + timedelta(minutes=30),
            NOW + timedelta(hours=1),
        ),
        (
            "incident_review_required",
            NOW + timedelta(hours=20),
            NOW + timedelta(hours=20),
        ),
    ],
)
def test_held_recovery_waits_for_the_event_that_could_clear_the_hold(
    tmp_path, action, canary_due_at, expected
):
    """A 20-minute deferral respawned a watcher child ~72 times a day.

    Only a scheduled keeper cycle (or an acknowledgement it then observes)
    can clear these holds, so the watcher waits at least one cycle, and for
    an incident-review hold until its next permitted canary.
    """
    from types import SimpleNamespace

    from newsclip.provider_guard import GuardAction

    keeper, sessions, store, _, _ = _recovery_keeper(tmp_path)
    guard = FakeGuard(SimpleNamespace(action=GuardAction(action)))
    guard.canary_due_at = canary_due_at
    keeper._guard = guard

    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)

    assert result.action is KeeperAction.HELD
    record = store.load("ft")
    assert record.health.reason == "provider_held"
    assert record.health.next_attempt_at == expected
    assert record.health.attempts == 0
    assert sessions.logins == []


def test_scheduled_cycle_releases_a_hold_deferral_once_the_hold_is_gone(tmp_path):
    from types import SimpleNamespace

    from newsclip.provider_guard import GuardAction

    keeper, sessions, store, record, _ = _recovery_keeper(tmp_path)
    keeper._guard = FakeGuard(SimpleNamespace(action=GuardAction.OPERATOR_ACTION))
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert store.load("ft").health.next_attempt_at == NOW + timedelta(hours=1)

    # Still held: the scheduled cycle keeps the deferral and claims nothing.
    held = keeper.keep("ft", allow_credential_mint=True)
    assert held.action is KeeperAction.COOLDOWN
    assert store.load("ft").health.next_attempt_at == NOW + timedelta(hours=1)
    assert store.load("ft").health.attempts == 0

    # The watcher does not shortcut the deferral on its own.
    keeper._guard = FakeGuard()
    waiting = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert waiting.action is KeeperAction.COOLDOWN
    assert store.load("ft").health.attempts == 0

    # Acknowledged: the next scheduled cycle recovers without waiting it out.
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.CHECKED
    assert sessions.article_checks == [str(record.url)]
    assert store.load("ft").health.attempts == 1


def test_interrupted_dispatch_only_reconciles_existing_session(tmp_path):
    keeper, sessions, store, record, budget = _recovery_keeper(tmp_path)
    store.claim("ft", "cli-interrupted")
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.recovery.article_verified
    assert sessions.logins == []
    assert sessions.session_checks == []
    assert len(sessions.article_checks) == 1
    assert budget.attempts_today("ft") == 0
    assert store.load("ft").health.attempts == 1


def test_stale_generation_failure_never_renews_newer_generation(tmp_path):
    from uuid import uuid4

    keeper, sessions, _, _, _ = _recovery_keeper(tmp_path)
    sessions.generation = uuid4()
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.recovery.article_verified
    assert sessions.logins == []
    assert sessions.session_checks == []
    assert len(sessions.article_checks) == 1


def test_defense_cooldown_precedes_recovery_claim(tmp_path):
    keeper, sessions, store, _, _ = _recovery_keeper(tmp_path)
    sessions.contained_until = NOW + timedelta(hours=1)
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.COOLDOWN
    assert store.load("ft").health.attempts == 0
    assert store.load("ft").health.next_attempt_at == sessions.contained_until
    assert sessions.logins == []
    assert sessions.article_checks == []


def test_provider_operation_lock_prevents_ops_and_keeper_duplicate(tmp_path):
    keeper, sessions, store, record, budget = _recovery_keeper(tmp_path)
    attempts_before = budget.attempts_today("ft")
    with store.operation("ft"):
        result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.BUSY
    assert sessions.logins == []
    assert sessions.article_checks == []
    assert sessions.checks == []
    assert store.load("ft") == record
    assert budget.attempts_today("ft") == attempts_before


def test_renamed_contention_preserves_keeper_budgets(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from newsclip.private_state import PrivateStateBusyError

    keeper, sessions, store, record, budget = _recovery_keeper(tmp_path)
    assert budget.reserve("ft", limit=2)
    attempts_before = budget.attempts_today("ft")

    @contextmanager
    def busy(*args, **kwargs):
        raise PrivateStateBusyError("operation already owned")
        yield  # pragma: no cover

    with monkeypatch.context() as patch:
        patch.setattr("newsclip.recovery.exclusive_lock", busy)
        result = keeper.keep("ft", allow_credential_mint=True)

    assert result.action is KeeperAction.BUSY
    assert not result.credential_attempt
    assert sessions.logins == []
    assert sessions.article_checks == []
    assert sessions.checks == []
    assert store.load("ft") == record
    assert budget.attempts_today("ft") == attempts_before == 1


def test_inconclusive_recovery_cannot_authorize_credentials(tmp_path):
    from newsclip.errors import ContentNotFullError

    keeper, sessions, _, _, budget = _recovery_keeper(
        tmp_path,
        RecoverySessions(
            needs_credentials=True,
            article_failure=ContentNotFullError("paywall_teaser"),
        ),
    )
    result = keeper.keep("ft", allow_credential_mint=True)
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
    assert result.recovery.article_verified is False


def test_proven_session_loss_uses_existing_credential_budget(tmp_path):
    keeper, sessions, _, _, budget = _recovery_keeper(
        tmp_path, RecoverySessions(needs_credentials=True), session_required=True
    )
    result = keeper.keep("ft", allow_credential_mint=True)
    assert sessions.logins == [False, True]
    assert budget.attempts_today("ft") == 1
    assert result.recovery.article_verified
    keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert sessions.logins == [False, True]


def test_retrieval_defense_never_enters_login_even_with_credential_authority(tmp_path):
    sessions = FakeSessions(last_verified_at=NOW - timedelta(days=2))
    sessions.defense_pending = lambda provider: True
    sessions.check_result = ProviderCheckResult(
        provider="ft",
        ok=False,
        failure=ProviderCheckFailure.PROVIDER_DEFENSE,
        defense_observation="suppressed",
        defense_retry_after_seconds=1200,
    )
    from test_provider_guard import _guard

    keeper, _, _budget = _keeper(tmp_path, sessions=sessions, guard=_guard(tmp_path)[0])
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.COOLDOWN
    assert sessions.logins == []
    assert sessions.checks == ["ft"]


@pytest.mark.parametrize("needs_credentials", [False, True])
def test_expired_authority_during_defense_has_a_bounded_renewal_exit(
    tmp_path, needs_credentials
):
    from contextlib import contextmanager

    from test_provider_guard import _check, _guard

    from newsclip.defense import BASE_COOLDOWN_SECONDS, DefenseState
    from newsclip.errors import ProviderDefenseError

    clock = [NOW]
    defense = DefenseState(tmp_path / "provider-defense", utc_now=lambda: clock[0])
    defense.arm("ft", origin="retrieval")
    guard, _ = _guard(tmp_path)
    guard.run("ft", lambda: _check(failure=ProviderCheckFailure.SESSION_REQUIRED))
    sessions = FakeSessions(
        last_verified_at=NOW - timedelta(days=2), needs_credentials=needs_credentials
    )
    sessions.defense_pending = lambda provider: defense.status(provider) is not None
    scopes = []

    @contextmanager
    def recovery_scope(provider):
        with defense.probe(provider) as decision:
            if not decision.allowed:
                raise ProviderDefenseError(
                    "cooldown",
                    provider=provider,
                    retry_after_seconds=decision.retry_after_seconds,
                )
            scopes.append(provider)
            yield

    sessions.session_recovery_scope = recovery_scope
    original_login = sessions.login

    def verified_login(*args, **kwargs):
        hold_id = guard.session_evidence_target("ft")
        result = original_login(*args, **kwargs)
        guard.clear_session_evidence("ft", hold_id=hold_id)
        return result

    def full_proof(provider):
        # The real service enters the same scope for the post-renewal check.
        with defense.probe(provider) as nested:
            assert nested.allowed
            defense.clear(provider)
            sessions.checks.append(provider)
            return _check(failure=None)

    sessions.login = verified_login
    sessions.provider_check = full_proof
    keeper, _, budget = _keeper(tmp_path, sessions=sessions, guard=guard)
    assert keeper.keep("ft", allow_credential_mint=True).action is KeeperAction.COOLDOWN
    assert sessions.logins == [] and scopes == []
    clock[0] += timedelta(seconds=BASE_COOLDOWN_SECONDS + 1)
    result = keeper.keep("ft", allow_credential_mint=True)
    assert result.action is KeeperAction.RENEWED
    assert sessions.logins == ([False, True] if needs_credentials else [False])
    assert scopes == ["ft"]
    # Only the additional FULL article check clears the original defense.
    assert sessions.checks == ["ft"]
    assert defense.status("ft") is None
    assert guard.peek("ft") is None
    assert keeper.keep("ft", allow_credential_mint=True).action is KeeperAction.FRESH
    assert scopes == ["ft"]
    assert budget.attempts_today("ft") == int(needs_credentials)


def test_defense_overlap_cannot_upgrade_a_warm_only_serving_recovery(tmp_path):
    from contextlib import nullcontext

    from test_provider_guard import _check, _guard

    from newsclip.errors import ContentNotFullError
    from newsclip.models import RecoveryStatus

    sessions = RecoverySessions(
        needs_credentials=True, article_failure=ContentNotFullError("paywall_teaser")
    )
    keeper, _, store, _, budget = _recovery_keeper(tmp_path, sessions=sessions)
    guard, _ = _guard(tmp_path)
    guard.run("ft", lambda: _check(failure=ProviderCheckFailure.SESSION_REQUIRED))
    keeper._guard = guard
    sessions.defense_pending = lambda provider: True
    sessions.session_recovery_scope = lambda provider: nullcontext()
    result = keeper.keep("ft", allow_credential_mint=True, recovery_only=True)
    assert result.action is KeeperAction.CHECK_FAILED
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
    assert store.load("ft").health.status is RecoveryStatus.FAILED


def test_article_only_recovery_preserves_failed_renewal_notification(tmp_path):
    keeper, sessions, _, _, _ = _recovery_keeper(tmp_path)
    outcomes = KeeperOutcomeStore(tmp_path / "session-keeper")
    keeper._outcomes = outcomes
    outcomes.record(
        KeeperResult(
            provider="ft",
            action=KeeperAction.RENEWAL_FAILED,
            reason_code="provider_defense",
            incident_id="incident-" + "a" * 24,
        ),
        max_age_hours=12,
    )
    result = keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    assert result.action is KeeperAction.CHECKED
    assert result.recovery.article_verified
    assert not result.recovery.session_verified
    assert sessions.logins == []
    assert result.needs_attention and result.renewal_unresolved
    assert outcomes.load("ft").consecutive_renewal_failures == 1


def test_renewal_without_verified_authority_remains_a_failure(tmp_path):
    outcomes = KeeperOutcomeStore(tmp_path / "session-keeper")
    sessions = FakeSessions(
        last_verified_at=NOW - timedelta(hours=48),
        renewed_status=SessionStatus.REQUIRED,
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions, outcomes=outcomes)
    result = keeper.keep("ft", allow_credential_mint=False)
    assert result.action is KeeperAction.RENEWAL_FAILED
    assert result.needs_attention
    assert outcomes.load("ft").consecutive_renewal_failures == 1
    assert not result.credential_attempt


def test_completed_recovery_does_not_hide_current_hold_or_touch_its_budget(tmp_path):
    from test_provider_guard import _guard_with_clock, _open_incident_hold

    keeper, sessions, recovery_store, _, budget = _recovery_keeper(tmp_path)
    completed = keeper.keep("ft", allow_credential_mint=False, recovery_only=True)
    assert completed.recovery.status == "succeeded"
    guard, guard_store, clock = _guard_with_clock(tmp_path / "guard")
    held = _open_incident_hold(guard)
    keeper._guard = guard
    before = {p.name: p.read_bytes() for p in guard_store.root.glob("*.json")}
    inspected = keeper.inspect_recovery("ft")
    payload = inspected.public_dict()
    assert payload["recovery"]["status"] == "succeeded"
    assert payload["current_hold"]["hold_id"] == held.hold_id
    assert payload["current_hold"]["incident_id"] == held.incident_id
    assert payload["current_hold"]["held_operation"] == "provider_check"
    assert payload["current_hold"]["last_canary_at"] is None
    assert inspected.current_hold.next_eligible_canary_at == clock["now"]
    assert sessions.article_checks == ["https://www.ft.com/content/fixture"]
    assert sessions.logins == []
    assert budget.attempts_today("ft") == 0
    assert before == {p.name: p.read_bytes() for p in guard_store.root.glob("*.json")}
    assert recovery_store.load("ft").health.status == "succeeded"
