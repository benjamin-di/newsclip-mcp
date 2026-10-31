"""Native barriers and private evidence survive shared-reader continuations."""

from datetime import timedelta
from uuid import uuid4

import pytest
from test_mcp import FULL_URL, FakeExtractor, FakeHttp, PagedFakeProvider
from test_shared_connection_runtime import NOW
from test_shared_connection_runtime import readers as readers
from test_standalone import Recipe

from newsclip.composition import build_connection_reader, build_mcp_service
from newsclip.connection_controls import ConnectionControls
from newsclip.defense import BASE_COOLDOWN_SECONDS
from newsclip.errors import (
    ProviderDefenseError,
    ProviderTransportError,
    SessionRequiredError,
)
from newsclip.models import (
    AccessState,
    ArticleAssessment,
    PortableCookie,
    ProviderCapabilities,
    RawFetch,
    SearchFilters,
    SessionArtifact,
    SourceSearchState,
)
from newsclip.providers import ProviderRegistry
from newsclip.subscription_access import SubscriptionAccess
from newsclip.subscription_routing import SubscriptionRouting
from newsclip.tenancy import add_user
from newsclip.timing import TimingOperation


@pytest.fixture
def runtime(readers, accounts, tmp_path):
    owner, local, shared = readers

    class PaidPaged(PagedFakeProvider):
        login_recipe = Recipe()
        capabilities = ProviderCapabilities(
            session_kind="cookie",
            requires_session_for_search=True,
            requires_session_for_retrieve=True,
        )

    provider = PaidPaged(total=65)
    for service in readers:
        service._registry = ProviderRegistry((provider,))
        service._extractor = FakeExtractor()
        service._archive._registry = service._registry
        service._archive._extractor = service._extractor
        service._http = FakeHttp()
    for service in (owner, shared):
        service._sessions._store._recipes["fixture"] = Recipe()
        service._sessions._store._clock = lambda: NOW
    artifact = SessionArtifact(
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
        schema_version=2,
        browser_profile_id=uuid4(),
        generation_id=uuid4(),
        cookies=(
            PortableCookie(name="session", value="invented", domain="example.com"),
        ),
    )
    proof = RawFetch(
        requested_url=FULL_URL,
        final_url=FULL_URL,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        serving_transport="browser",
        session_cookie_present=True,
        raw_html=b"FULL",
    )
    shared._sessions._store.promote_browser_session(
        artifact, proof, expected_generation=None
    )
    access = SubscriptionAccess(tmp_path / "sharing", accounts[0])
    access.bootstrap(("fixture",))
    access.share("alice", "fixture", "bob", None)
    row, offers, _ = access.view("bob", "fixture")
    access.choose("bob", "fixture", "alice", row["revision"], dict(offers)["alice"])
    services = {"alice": owner, "bob": local}
    for actor, service in services.items():
        service._subscription_routing = SubscriptionRouting(
            actor,
            service,
            access,
            services.__getitem__,
            reader_factory=lambda **kwargs: shared,
        )
    return owner, local, shared, provider, artifact, proof


@pytest.mark.parametrize("shared_choice", [False, True])
def test_buffered_paid_search_rechecks_native_disconnect(runtime, shared_choice):
    owner, local, shared, provider, _, _ = runtime
    service = local if shared_choice else owner
    pager = service.search_pager("synthetic", SearchFilters(limit=1))
    assert len(pager.next_batch(1).results) == 1
    calls = list(provider.page_calls)
    ConnectionControls(owner._sessions._store.root).suspend("fixture")
    with pytest.raises(SessionRequiredError, match="connection_disconnected"):
        pager.next_batch(1)
    assert provider.page_calls == calls
    assert shared._sessions._store.root == owner._sessions._store.root


def test_buffered_paid_search_requires_new_search_after_reconnect(runtime):
    _, local, shared, provider, artifact, proof = runtime
    pager = local.search_pager("synthetic", SearchFilters(limit=1))
    assert pager.next_batch(1).results
    calls = list(provider.page_calls)
    replacement = artifact.model_copy(update={"generation_id": uuid4()})
    shared._sessions._store.promote_browser_session(
        replacement, proof, expected_generation=artifact.generation_id
    )
    with pytest.raises(SessionRequiredError, match="account_changed"):
        pager.next_batch(1)
    assert provider.page_calls == calls


@pytest.mark.parametrize("local_state", ["healthy", "contained", "corrupt"])
@pytest.mark.parametrize("owner_contained", [False, True])
def test_shared_search_reports_only_captured_owner_containment(
    runtime, local_state, owner_contained
):
    owner, local, shared, _, _, _ = runtime
    if owner_contained:
        record = owner._defense.arm("fixture", origin="retrieval")
        expected = record.active_until
    else:
        expected = None
    if local_state == "contained":
        local._defense.arm("fixture", origin="retrieval")
    elif local_state == "corrupt":
        path = local._defense._path("fixture")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("damaged synthetic state")
    pager = local.search_pager("synthetic", SearchFilters(limit=1))
    for _ in range(2):
        response = pager.next_batch(1)
        assert response.results
        assert len(response.sources) == 1
        assert response.sources[0].retrieval_contained_until == expected
    assert shared._defense.root == owner._defense.root


@pytest.mark.parametrize("local_state", ["healthy", "contained", "corrupt"])
def test_rejected_shared_source_preserves_healthy_federated_results(
    runtime, local_state
):
    _, local, _, paid, _, _ = runtime

    class Public(PagedFakeProvider):
        key = "healthy"
        capabilities = ProviderCapabilities(
            session_kind="none", requires_session_for_retrieve=False
        )

    public = Public(total=1)
    local._registry = ProviderRegistry((paid, public))
    access = local._subscription_routing.access
    grant = access.view("alice", "fixture")[0]["grants"]["bob"]
    access.revoke("alice", "fixture", "bob", grant)
    if local_state == "contained":
        local._defense.arm("fixture", origin="retrieval")
    elif local_state == "corrupt":
        path = local._defense._path("fixture")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("damaged synthetic state")
    response = local.search_pager("synthetic").next_batch(5)
    assert response.results and all(
        result.provider == "healthy" for result in response.results
    )
    reports = {report.provider: report for report in response.sources}
    assert reports["fixture"].state is not SourceSearchState.OK
    assert reports["fixture"].retrieval_contained_until is None
    assert reports["healthy"].state is SourceSearchState.OK
    assert paid.page_calls == [] and public.page_calls == [1]


@pytest.mark.parametrize("first_actor", ["alice", "bob", "carol"])
@pytest.mark.parametrize("recovery", ["clear", "expire"])
def test_search_refusal_cooldown_belongs_to_owner_across_recipients(
    readers, accounts, tmp_path, first_actor, recovery
):
    owner, local, _ = readers
    add_user(accounts[0], "carol", tmp_path / "carol.token")
    other = build_mcp_service(user="carol")
    services = {"alice": owner, "bob": local, "carol": other}
    now = [NOW]
    calls = []

    class SearchOverHttp(PagedFakeProvider):
        login_recipe = Recipe()

        def search_page(self, http, session, query, filters, **kwargs):
            http.get(FULL_URL, session=session)
            return super().search_page(http, session, query, filters, **kwargs)

    class RefusedHttp(FakeHttp):
        challenge = True

        def get(self, url, **kwargs):
            calls.append(url)
            if self.challenge:
                raise ProviderDefenseError(
                    "synthetic refused search", provider="fixture"
                )
            return super().get(url, **kwargs)

    http = RefusedHttp()
    registry = ProviderRegistry((SearchOverHttp(total=1),))

    def configure(service):
        service._registry = registry
        service._http = http
        service._sessions._store._recipes["fixture"] = Recipe()
        service._wall_clock = lambda: now[0]
        service._defense._utc_now = lambda: now[0]
        return service

    def factory(**kwargs):
        return configure(build_connection_reader(**kwargs))

    access = SubscriptionAccess(tmp_path / "refusal-sharing", accounts[0])
    access.bootstrap(("fixture",))
    routes = []
    try:
        for actor, service in services.items():
            configure(service)
            service._subscription_routing = SubscriptionRouting(
                actor, service, access, services.__getitem__, reader_factory=factory
            )
            routes.append(service._subscription_routing)
            if actor != "alice":
                access.share("alice", "fixture", actor, None)
                row, offers, _ = access.view(actor, "fixture")
                access.choose(
                    actor, "fixture", "alice", row["revision"], dict(offers)["alice"]
                )
        owner._defense.arm("fixture", origin="retrieval")
        order = [first_actor, *(actor for actor in services if actor != first_actor)]
        for actor in order * 2:
            with pytest.raises(ProviderTransportError):
                services[actor].search_pager("synthetic").next_batch(1)
            assert len(calls) == 1
        assert local._search_refused_until == other._search_refused_until == {}
        if recovery == "clear":
            owner._defense.clear("fixture")
        else:
            now[0] += timedelta(seconds=BASE_COOLDOWN_SECONDS + 1)
        http.challenge = False
        assert services[order[-1]].search_pager("synthetic").next_batch(1).results
        assert len(calls) == 2
    finally:
        for route in routes:
            route.close()
        other.close()


def test_shared_defense_evidence_is_private_and_retained_by_native_stores(runtime):
    owner, local, shared, provider, _, _ = runtime
    shared._defense.arm_observed("fixture", origin="retrieval")
    fetch = RawFetch(
        requested_url=FULL_URL,
        final_url=FULL_URL,
        http_status=403,
        content_type="text/html",
        retrieved_at=NOW,
        session_cookie_present=True,
        raw_html=b"<html>synthetic challenge</html>",
    )
    assessment = ArticleAssessment(
        access_state=AccessState.BLOCKED,
        identity_match=False,
        word_count=0,
        reason="interactive_challenge",
    )
    incident = shared._record_retrieval_incident(
        provider, TimingOperation.GET, fetch, assessment
    )
    assert incident is not None
    assert shared._defense.status("fixture").incident_id == incident
    assert owner._defense.status("fixture").incident_id is None
    assert owner.incident_evidence(incident).status == "missing"
    other = build_connection_reader(
        requester="carol", owner="alice", budget_owner=owner._network
    )
    try:
        assert other._defense.status("fixture").incident_id is None
        assert other.incident_evidence(incident).status == "missing"
    finally:
        other.close()

    def add_failures(start):
        for number in range(start, start + 51):
            another = fetch.model_copy(
                update={
                    "requested_url": FULL_URL + f"-failure-{number}",
                    "final_url": FULL_URL + f"-failure-{number}",
                    "raw_html": f"<html>synthetic failure {number}</html>".encode(),
                }
            )
            # The requester's ordinary reader can prune too, including after a
            # restart; protection cannot depend on one cached shared reader.
            local._incidents.record_assessed_retrieval(
                provider="fixture",
                operation=TimingOperation.GET,
                fetch=another,
                assessment=assessment,
            )

    add_failures(0)
    assert local.incident_evidence(incident).status != "missing"
    owner._defense.clear("fixture")
    add_failures(51)
    assert local.incident_evidence(incident).status == "missing"
