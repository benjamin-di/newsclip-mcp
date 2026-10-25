"""Ordered proof must survive its hold and recovery consumers."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from test_provider_guard import _check, _guard
from test_renewal_ordering import failure
from test_service_cli import FakeExtractor, FakeHttp
from test_session_keeper import NOW, RecoverySessions, _recovery_keeper
from test_sessions import _cookie_payload, _store

from newsclip.keeper_outcomes import KeeperOutcomeStore, RenewalDecision
from newsclip.models import SessionDisposition
from newsclip.provider_check import ProviderCheckFailure
from newsclip.provider_guard import GuardAction
from newsclip.providers import ProviderRegistry
from newsclip.providers.ft import FTProvider
from newsclip.renewal_observation import observe_renewal, renewal_observation_point
from newsclip.service import NewsclipService
from newsclip.session_keeper import KeeperAction, KeeperResult


@pytest.mark.parametrize("operation", ["import", "reuse", "checkpoint"])
@pytest.mark.parametrize("hold_change", ["unchanged", "replacement", "created"])
def test_verification_clears_only_its_original_hold(
    tmp_path, monkeypatch, operation, hold_change
):
    accepted, release = Event(), Event()

    class PausingStore(KeeperOutcomeStore):
        def verified(self, provider, *, revision=None):
            result = super().verified(provider, revision=revision)
            assert result
            accepted.set()
            assert release.wait(5)
            return result

    sessions = _store(tmp_path / "sessions")
    sessions.import_cookies("ft", _cookie_payload())
    outcomes = PausingStore(tmp_path / "outcomes")
    guard, _ = _guard(tmp_path)

    def make_hold():
        result = guard.run(
            "ft",
            lambda: _check(
                failure=ProviderCheckFailure.CONTENT_NOT_FULL,
                disposition=SessionDisposition.INCONCLUSIVE,
            ),
        )
        assert result.action is GuardAction.WAIT_FOR_SESSION_EVIDENCE
        return result.hold_id

    original = None if hold_change == "created" else make_hold()
    service = NewsclipService(
        ProviderRegistry((FTProvider(),)),
        FakeHttp(),
        FakeExtractor(),
        sessions=sessions,
        keeper_outcomes=outcomes,
        session_evidence_target=guard.session_evidence_target,
        on_session_verified=lambda provider, hold_id: guard.clear_session_evidence(
            provider, hold_id=hold_id
        ),
    )
    # Checkpoint dispatch is inert; imports/reuse exercise the real SessionStore.
    monkeypatch.setattr(service, "_verify_session_or_downgrade", lambda *args: None)

    def verify():
        if operation == "checkpoint":
            return service.session_checkpoint("ft")
        return service.login(
            "ft",
            cookie_payload=_cookie_payload() if operation == "import" else None,
            allow_credential_mint=False,
        )

    replacement = None
    with ThreadPoolExecutor(max_workers=1) as pool:
        task = pool.submit(verify)
        try:
            assert accepted.wait(5)
            if hold_change == "replacement":
                assert guard.acknowledge("ft", hold_id=original).acknowledged
            if hold_change != "unchanged":
                replacement = make_hold()
        finally:
            release.set()
        task.result(timeout=5)
    current = guard.peek("ft")
    if hold_change == "unchanged":
        assert current is None
    else:
        assert current.hold_id == replacement
    outcome = outcomes.load("ft")
    assert outcome.verified_revision == outcome.applied_revision > 0


@pytest.mark.parametrize(
    "overlap", ["none", "verified", "failed", "pending", "article_only", "held"]
)
def test_recovery_consumes_proof_instead_of_presentation_action(tmp_path, overlap):
    reached, release = Event(), Event()

    class PausingStore(KeeperOutcomeStore):
        pause = True

        def record(self, result, *, max_age_hours):
            if self.pause:
                self.pause = False
                reached.set()
                assert release.wait(5)
            return super().record(result, max_age_hours=max_age_hours)

    outcomes = PausingStore(tmp_path / "outcomes", utc_now=lambda: NOW)
    service = NewsclipService.__new__(NewsclipService)
    service._keeper_outcomes = outcomes
    service._on_session_verified = None

    def positive():
        with observe_renewal("ft", outcomes.issue_observation):
            with renewal_observation_point("ft"):
                pass
            service._session_evidence_verified("ft")

    class VerifyingSessions(RecoverySessions):
        def login(self, provider, **kwargs):
            # Shares the keeper's context, matching the service/authority path.
            with observe_renewal(provider, outcomes.issue_observation):
                with renewal_observation_point(provider):
                    acquired = super().login(provider, **kwargs)
                service._session_evidence_verified(provider)
                return acquired

    keeper, sessions, recovery, _, budget = _recovery_keeper(
        tmp_path, VerifyingSessions(), session_required=True
    )
    keeper._outcomes = outcomes
    with ThreadPoolExecutor(max_workers=1) as pool:
        task = pool.submit(
            keeper.keep, "ft", allow_credential_mint=False, recovery_only=True
        )
        try:
            assert reached.wait(5)
            if overlap in {"verified", "held"}:
                positive()
            elif overlap == "failed":
                revision = outcomes.issue_observation("ft")
                outcomes.record(failure(revision), max_age_hours=12)
            elif overlap == "pending":
                outcomes.issue_observation("ft")
            elif overlap == "article_only":
                outcomes.record(
                    KeeperResult(provider="ft", action=KeeperAction.CHECKED),
                    max_age_hours=12,
                )
            if overlap == "held":
                keeper._guard.hold = object()
        finally:
            release.set()
        result = task.result(timeout=5)
    success = overlap in {"none", "verified", "article_only"}
    assert result.recovery.article_verified is success
    assert result.recovery.session_verified is (success or overlap == "held")
    assert result.needs_attention is not success
    assert len(sessions.article_checks) == int(success)
    assert result.recovery.reason != "checked"
    assert result.recovery.status.value == ("succeeded" if success else "failed")
    assert recovery.load("ft").health.attempts == 1
    assert sessions.logins == [False]
    assert budget.attempts_today("ft") == 0
    assert "session_proof_verified" not in result.public_dict()
    if overlap == "failed":
        assert outcomes.load("ft").consecutive_renewal_failures == 1
        assert outcomes.load("ft").incident_id == failure().incident_id


def test_article_checked_and_legacy_actions_never_invent_session_proof(tmp_path):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    revision = store.issue_observation("ft")
    store.record(failure(revision), max_age_hours=12)
    checked = store.record(
        KeeperResult(provider="ft", action=KeeperAction.CHECKED), max_age_hours=12
    )
    assert checked.renewal_decision(revision) is RenewalDecision.UNRESOLVED
    assert checked.verified_revision == 0
    legacy = checked.model_copy(
        update={"schema_version": 2, "consecutive_renewal_failures": 0}
    )
    assert legacy.renewal_decision(revision) is RenewalDecision.UNRESOLVED
    assert store.verified("ft")
    assert KeeperOutcomeStore(store.root).load("ft").renewal_decision(revision) is (
        RenewalDecision.VERIFIED
    )


def test_newer_failure_after_positive_watermark_never_consumes_old_proof(tmp_path):
    store = KeeperOutcomeStore(tmp_path / "outcomes")
    assert store.verified("ft")
    revision = store.issue_observation("ft")
    store.record(failure(revision), max_age_hours=12)
    assert store.load("ft").renewal_decision(1) is RenewalDecision.SUPERSEDED
    assert store.load("ft").verified_revision == 1
