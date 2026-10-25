"""Actual serving handoff, persistent MCP transport, and worker convergence.

Only provider HTTP/session authority is fake. Reads, public envelopes, durable
state, worker scheduling, article assessment, and keeper decisions are real.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_service_cli import (
    ARTICLE_URL,
    NOW,
    CheckpointSessions,
    FakeExtractor,
    FakeHttp,
    FakeProvider,
)
from test_session_keeper import RecoverySessions, _keeper

from newsclip.archive import ArchiveStore
from newsclip.errors import (
    ProviderContractError,
    ProviderDefenseError,
    ProviderTransportError,
    TransportFailure,
)
from newsclip.models import ProviderCapabilities, RecoveryStatus
from newsclip.providers import ProviderRegistry
from newsclip.recovery import RecoveryStore
from newsclip.recovery_watch import RecoveryWatch
from newsclip.results import public_error
from newsclip.service import NewsclipService


def _serving(tmp_path, failure):
    clock = SimpleNamespace(now=NOW)

    class PaidProvider(FakeProvider):
        key = "ft"
        capabilities = ProviderCapabilities(requires_session_for_retrieve=True)

    class Transport(FakeHttp):
        def get(self, url, **kwargs):
            if failure[0] is not None:
                self.calls.append(url)
                raise failure[0]
            return super().get(url, **kwargs)

    session = CheckpointSessions()
    store = RecoveryStore(tmp_path / "recovery", utc_now=lambda: clock.now)
    registry = ProviderRegistry((PaidProvider(),))
    extractor = FakeExtractor()
    service = NewsclipService(
        registry,
        Transport(),
        extractor,
        archive=ArchiveStore(
            tmp_path / "archive.sqlite3", registry=registry, extractor=extractor
        ),
        sessions=session,
        recovery_store=store,
        wall_clock=lambda: clock.now,
    )
    return service, store, session, clock


@pytest.mark.parametrize("operation", ["get", "save"])
@pytest.mark.parametrize(
    "category",
    [TransportFailure.TIMEOUT, TransportFailure.DNS, TransportFailure.PROVIDER_ERROR],
)
def test_initial_transient_read_handoff_is_delayed_and_credential_free(
    tmp_path, operation, category
):
    failure = [ProviderTransportError("PRIVATE_NETWORK_DETAIL", category=category)]
    service, store, _, clock = _serving(tmp_path, failure)
    try:
        with pytest.raises(ProviderTransportError) as caught:
            getattr(service, operation)(ARTICLE_URL)
        record = store.load("ft")
        assert record.health.status is RecoveryStatus.PENDING
        assert record.health.next_attempt_at == clock.now + timedelta(minutes=20)
        assert record.health.episode_attempts == record.health.attempts == 0
        assert record.reconciliation_started
        assert not record.session_required
        envelope = public_error(caught.value).public_dict()
        assert envelope["action"] == "recovery_pending"
        assert envelope["recovery_id"] == record.health.request_id
        assert "PRIVATE_NETWORK_DETAIL" not in str(envelope)
        # Existing bounded HTTP policy makes two attempts in the caller;
        # durable handoff must not make a further immediate request.
        assert service._http.calls == [ARTICLE_URL, ARTICLE_URL]
    finally:
        service.close()


@pytest.mark.parametrize(
    "failure",
    [
        ProviderTransportError("generic"),
        ProviderTransportError(
            "permanent", category=TransportFailure.TIMEOUT, retryable=False
        ),
        ProviderTransportError("rate limit", category=TransportFailure.RATE_LIMITED),
        ProviderContractError("contract", category=TransportFailure.TIMEOUT),
        ProviderDefenseError("defense"),
    ],
)
def test_unsupported_serving_failures_do_not_schedule_reads(tmp_path, failure):
    service, store, _, _ = _serving(tmp_path, [failure])
    try:
        with pytest.raises(ProviderTransportError):
            service.get(ARTICLE_URL)
        assert store.load("ft") is None
        assert 1 <= len(service._http.calls) <= 2
        assert set(service._http.calls) == {ARTICLE_URL}
    finally:
        service.close()


def test_persistent_mcp_observes_recovery_from_independent_worker(tmp_path):
    pytest.importorskip("mcp")
    from starlette.testclient import TestClient

    from newsclip.mcp_server import build_http_app

    failure = [ProviderTransportError("fixture", category=TransportFailure.TIMEOUT)]
    service, store, session, clock = _serving(tmp_path, failure)
    builds = []

    def build():
        builds.append(True)
        return service

    worker_sessions = RecoverySessions()
    worker_sessions.generation = session.artifact.generation_id
    keeper, _, budget = _keeper(tmp_path, sessions=worker_sessions)
    # Independent store instance models serving and keeper sharing a volume.
    keeper._recovery_store = RecoveryStore(store.root, utc_now=lambda: clock.now)
    keeper._utc_now = lambda: clock.now

    def verify(provider, url):
        worker_sessions.article_checks.append(url)
        service.verify_recovery_article(provider, url)

    worker_sessions.verify_recovery_article = verify
    worker_sessions.validate_recovery_url = service.validate_recovery_url
    watcher = RecoveryWatch(
        keeper._recovery_store,
        ("ft",),
        allow_credentials=True,
        runner=lambda provider, allow, timeout: keeper.keep(
            provider, allow_credential_mint=allow, recovery_only=True
        ).public_dict(),
        utc_now=lambda: clock.now,
    )
    headers = {
        "Authorization": "Bearer fixture-token",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get", "arguments": {"url": ARTICLE_URL}},
    }
    try:
        with TestClient(
            build_http_app(service_factory=build, bearer_token="fixture-token"),
            base_url="http://127.0.0.1",
        ) as client:
            first = client.post("/mcp", headers=headers, json=call)
            assert first.status_code == 200
            assert first.json()["result"]["isError"] is True
            assert "recovery_pending" in first.text
            request_id = store.load("ft").health.request_id
            assert watcher.tick() == []
            assert not watcher.active
            clock.now += timedelta(minutes=20)
            failure[0] = None
            watcher.tick()
            watcher.active["ft"].result(timeout=5)
            outcomes = watcher.tick()
            assert outcomes[0]["overall_state"] == "healthy", outcomes
            final = store.load("ft")
            assert final.health.request_id == request_id
            assert final.health.article_verified
            assert final.health.episode_attempts == final.health.attempts == 1
            assert final.reconciliation_started
            assert worker_sessions.article_checks == [ARTICLE_URL]
            assert worker_sessions.logins == []
            assert budget.attempts_today("ft") == 0
            second = client.post("/mcp", headers=headers, json=call)
            assert second.status_code == 200
            assert second.json()["result"].get("isError") is not True
            assert len(builds) == 1
    finally:
        watcher.close()
        service.close()
