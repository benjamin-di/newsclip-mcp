"""Delayed publishers cannot resurrect or erase superseded renewal evidence."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pytest
from test_session_keeper import NOW, FakeSessions, _keeper

from newsclip.errors import ProviderTransportError
from newsclip.keeper_outcomes import KeeperOutcomeStore, enrich_session_health
from newsclip.models import SessionHealth, SessionHealthState, SessionStatus
from newsclip.recovery import RecoveryStore
from newsclip.renewal_observation import observe_renewal, renewal_observation_point
from newsclip.service import NewsclipService
from newsclip.session_keeper import KeeperAction, KeeperResult


def failure(revision=None):
    return KeeperResult(
        provider="ft",
        action=KeeperAction.RENEWAL_FAILED,
        reason_code="provider_defense",
        status=SessionStatus.VERIFIED,
        incident_id="incident-" + "a" * 24,
        renewal_revision=revision,
    )


@pytest.mark.parametrize("prior_failure", [False, True])
def test_newer_verification_supersedes_delayed_keeper_failure(tmp_path, prior_failure):
    reached, release = Event(), Event()

    class PausingStore(KeeperOutcomeStore):
        pause = False

        def record(self, result, *, max_age_hours):
            if self.pause:
                self.pause = False
                reached.set()
                assert release.wait(5)
            return super().record(result, max_age_hours=max_age_hours)

    store = PausingStore(tmp_path / "outcomes", utc_now=lambda: NOW)
    if prior_failure:
        store.record(failure(), max_age_hours=12)
        store.spend_escalation_canary("ft")
    sessions = FakeSessions(
        last_verified_at=NOW - timedelta(days=1),
        failure=ProviderTransportError("synthetic failure"),
    )
    keeper, _, _ = _keeper(tmp_path, sessions=sessions, outcomes=store)
    keeper._recovery_store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: NOW)
    store.pause = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        task = pool.submit(keeper.keep, "ft", allow_credential_mint=False)
        try:
            assert reached.wait(5)
            sessions.failure = None
            sessions.last_verified_at = NOW
            store.verified("ft")
        finally:
            release.set()
        result = task.result(timeout=5)
    following = keeper.keep("ft", allow_credential_mint=False)
    assert not result.needs_attention and not following.needs_attention
    assert following.action is KeeperAction.FRESH
    assert len(sessions.logins) == 1
    outcome = store.load("ft")
    assert outcome.consecutive_renewal_failures == 0
    assert outcome.incident_id is None
    assert outcome.last_escalation_canary_at == (NOW if prior_failure else None)


def test_delayed_verification_callback_cannot_clear_newer_failure_or_hold(tmp_path):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    service = NewsclipService.__new__(NewsclipService)
    service._keeper_outcomes = store
    cleared = []
    service._on_session_verified = lambda provider, hold_id: cleared.append(hold_id)
    with observe_renewal("ft", store.issue_observation):
        with renewal_observation_point("ft"):
            pass  # older positive verification completed on this generation
        newer = store.issue_observation("ft")
        store.record(failure(newer), max_age_hours=12)
        service._session_evidence_verified("ft", hold_id="guard-" + "a" * 32)
    outcome = store.load("ft")
    assert outcome.consecutive_renewal_failures == 1
    assert outcome.incident_id == failure().incident_id
    assert cleared == []


def test_duplicate_failure_is_not_counted_twice_and_stale_success_cannot_reset_it(
    tmp_path,
):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    older = store.issue_observation("ft")
    newer = store.issue_observation("ft")
    store.record(failure(newer), max_age_hours=12)
    store.record(failure(newer), max_age_hours=12)
    store.record(
        KeeperResult(
            provider="ft",
            action=KeeperAction.RENEWED,
            status=SessionStatus.VERIFIED,
            renewal_revision=older,
        ),
        max_age_hours=12,
    )
    assert store.load("ft").consecutive_renewal_failures == 1
    assert "renewal_revision" not in failure(newer).public_dict()


def test_checkpoint_cannot_clear_an_intervening_unpublished_observation(tmp_path):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    checkpoint = store.issue_observation("ft")
    failure_revision = store.issue_observation("ft")
    assert not store.verified("ft", revision=checkpoint)
    store.record(failure(failure_revision), max_age_hours=12)
    assert store.load("ft").consecutive_renewal_failures == 1


def test_verification_watermark_does_not_invent_a_workstation_keeper_policy(tmp_path):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    assert store.verified("ft")
    outcome = store.load("ft")
    assert outcome.applied_revision == 1
    assert not outcome.keeper_observed
    assert not store.spend_escalation_canary("ft")
    health = enrich_session_health(
        SessionHealth(
            provider="ft",
            status=SessionStatus.VERIFIED,
            last_verified_at=NOW - timedelta(days=7),
        ),
        outcome,
        now=NOW,
    )
    assert health.health is SessionHealthState.STALE


@pytest.mark.parametrize("operation", ["import", "reuse", "failed_reuse"])
def test_real_session_observation_is_issued_before_releasing_authority_lock(
    tmp_path, operation
):
    from test_sessions import InconclusiveRecipe, _cookie_payload, _store

    from newsclip.private_state import PrivateStateBusyError, exclusive_lock

    root = tmp_path / "state"
    sessions = _store(root)
    if operation != "import":
        sessions.import_cookies("ft", _cookie_payload())
    if operation == "failed_reuse":
        sessions = _store(root, recipe=InconclusiveRecipe())
    observations = []

    def issue(provider):
        assert provider == "ft"
        with (
            pytest.raises(PrivateStateBusyError),
            exclusive_lock(root / "sessions/ft/default.lock", timeout_seconds=0),
        ):
            pytest.fail("session authority was released before stamping proof")
        observations.append(provider)
        return len(observations)

    with observe_renewal("ft", issue) as observation:
        if operation == "import":
            sessions.import_cookies("ft", _cookie_payload())
        elif operation == "failed_reuse":
            with pytest.raises(ProviderTransportError):
                sessions.explicit_login("ft", allow_credential_mint=False)
        else:
            sessions.explicit_login("ft", allow_credential_mint=False)
        assert observation.revision == 1
    assert observations == ["ft"]


def test_service_import_and_keeper_reuse_share_ordered_proof_on_one_generation(
    tmp_path,
):
    from test_service_cli import FakeExtractor, FakeHttp
    from test_sessions import _cookie_payload, _store

    from newsclip.providers import ProviderRegistry
    from newsclip.providers.ft import FTProvider

    sessions = _store(tmp_path / "sessions")
    outcomes = KeeperOutcomeStore(tmp_path / "outcomes")
    service = NewsclipService(
        ProviderRegistry((FTProvider(),)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
        keeper_outcomes=outcomes,
    )
    service.login("ft", cookie_payload=_cookie_payload())
    generation = sessions.get_valid_session("ft").generation_id
    assert outcomes.load("ft").applied_revision == 1
    keeper, _, _ = _keeper(tmp_path, sessions=service, outcomes=outcomes)
    result = keeper.keep("ft", allow_credential_mint=False)
    assert result.action is KeeperAction.RENEWED and not result.needs_attention
    assert outcomes.load("ft").applied_revision == 2
    assert outcomes.load("ft").keeper_observed
    assert sessions.get_valid_session("ft").generation_id == generation


def test_service_checkpoint_does_not_clear_failure_from_intervening_renewal(
    tmp_path, monkeypatch
):
    from test_service_cli import FakeExtractor, FakeHttp
    from test_sessions import _cookie_payload, _store

    from newsclip.providers import ProviderRegistry
    from newsclip.providers.ft import FTProvider

    sessions = _store(tmp_path / "sessions")
    sessions.import_cookies("ft", _cookie_payload())
    outcomes = KeeperOutcomeStore(tmp_path / "outcomes")
    service = NewsclipService(
        ProviderRegistry((FTProvider(),)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
        keeper_outcomes=outcomes,
    )

    def overlapping_proof(provider, artifact):
        # The checkpoint has loaded its snapshot. A later renewal on that
        # generation fails before this checkpoint returns its positive proof.
        revision = outcomes.issue_observation("ft")
        outcomes.record(failure(revision), max_age_hours=12)

    monkeypatch.setattr(service, "_verify_session_or_downgrade", overlapping_proof)
    service.session_checkpoint("ft")
    assert outcomes.load("ft").consecutive_renewal_failures == 1
    assert outcomes.load("ft").incident_id == failure().incident_id
