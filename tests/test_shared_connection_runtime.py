"""Requester output and selected-connection authority must remain independent."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest
from test_mcp import FULL_URL, FakeExtractor, FakeHttp, FakeProvider
from test_standalone import Recipe

from newsclip.browser_retrieval import PatchrightBrowserRetriever
from newsclip.browser_runtime import LeaseManager
from newsclip.composition import build_connection_reader, build_mcp_service
from newsclip.connection_controls import ConnectionControls
from newsclip.errors import SessionRequiredError
from newsclip.models import (
    PortableCookie,
    ProviderCapabilities,
    RawFetch,
    SessionArtifact,
)
from newsclip.provider_config import BrowserRetrievalSpec
from newsclip.providers import ProviderRegistry

NOW = datetime(2026, 10, 25, tzinfo=UTC)


@pytest.fixture
def readers(monkeypatch, tmp_path):
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_PROVIDER_ALLOWLIST", "cnbc")
    owner = build_mcp_service(user="alice")
    requester = build_mcp_service(user="bob")
    shared = build_connection_reader(
        requester="bob", owner="alice", budget_owner=owner._network
    )
    try:
        yield owner, requester, shared
    finally:
        shared.close()
        requester.close()
        owner.close()


def test_shared_runtime_retains_owner_native_state_and_requester_output(
    readers, tmp_path
):
    owner, requester, shared = readers
    owner_store, shared_store = owner._sessions._store, shared._sessions._store
    assert shared_store.root == owner_store.root == tmp_path / "state/users/alice"
    assert shared_store._profiles.root == owner_store._profiles.root
    assert (
        shared._archive.path
        == requester._archive.path
        == tmp_path / "data/users/bob/archive.sqlite3"
    )
    assert (
        shared_store._diagnostic_trace._path.parent
        == tmp_path / "state/users/bob/traces"
    )
    assert shared._incidents.root == requester._incidents.root
    assert not shared_store._adapters and not shared_store._credential_readiness_probes
    assert (
        shared._recovery_store is None
    )  # a reader cannot request credential acquisition for another user
    assert shared._network._limiters is owner._network._limiters
    assert shared._network._limiters is not requester._network._limiters


def test_cookie_read_and_save_use_owner_barrier_but_requester_archive(readers):
    owner, requester, shared = readers

    class Authenticated(FakeProvider):
        capabilities = ProviderCapabilities(
            session_kind="cookie", requires_session_for_retrieve=True
        )
        login_recipe = Recipe()

    provider = Authenticated()
    shared._registry = ProviderRegistry((provider,))
    shared._extractor = FakeExtractor()
    for service in (owner, requester, shared):
        service._archive._registry = shared._registry
        service._archive._extractor = shared._extractor

    class SelectedHttp(FakeHttp):
        def get(self, url, *, session=None, timeout=40):
            assert session is not None
            assert session.cookies[0].value == "invented"
            return super().get(url, session=session, timeout=timeout)

    shared._http = SelectedHttp()
    store = shared._sessions._store
    store._recipes["fixture"] = Recipe()
    store._clock = lambda: NOW
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
        requested_url="https://example.com/article",
        final_url="https://example.com/article",
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        serving_transport="browser",
        session_cookie_present=True,
        raw_html=b"FULL",
    )
    store.promote_browser_session(artifact, proof, expected_generation=None)
    # The requester can disconnect their own slot while using the owner's.
    ConnectionControls(requester._sessions._store.root).suspend("fixture")
    assert shared.get(FULL_URL).headline == "Fixture article"
    saved = shared.save(FULL_URL)
    assert requester.archive_get(saved.id).id == saved.id
    assert owner.archive_search("Fixture") == []
    # The connection's actual native barrier still fences shared readers.
    ConnectionControls(owner._sessions._store.root).suspend("fixture")
    with pytest.raises(SessionRequiredError, match="connection_disconnected"):
        shared.get(FULL_URL)
    assert requester.archive_get(saved.id).id == saved.id


@pytest.mark.skipif(
    os.environ.get("NEWSCLIP_SHARED_NATIVE") != "1",
    reason="explicit synthetic Chromium acceptance",
)
def test_native_profile_read_save_and_disconnect_keep_requester_isolated(readers):
    owner, requester, shared = readers
    seen = []

    class Site(BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            seen.append(cookie)
            body = (
                b"<html><body>FULL</body></html>"
                if "session=invented" in cookie
                else b"TEASER"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    site = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    thread = threading.Thread(target=site.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{site.server_port}/full-article"

    class BrowserRecipe(Recipe):
        provider = "cnbc"
        allowed_cookie_domains = frozenset({"127.0.0.1"})

    class BrowserProvider(FakeProvider):
        key = "cnbc"
        login_recipe = BrowserRecipe()
        capabilities = ProviderCapabilities(
            session_kind="cookie",
            requires_session_for_retrieve=True,
            retrieval_transport="browser",
        )

        def owns_url(self, candidate):
            return candidate == url

    shared._registry = ProviderRegistry((BrowserProvider(),))
    shared._extractor = FakeExtractor()
    for service in (owner, requester, shared):
        service._archive._registry = shared._registry
        service._archive._extractor = shared._extractor
    store = shared._sessions._store
    store._recipes["cnbc"] = BrowserRecipe()
    store._clock = lambda: NOW
    artifact = SessionArtifact(
        provider="cnbc",
        created_at=NOW,
        verified_at=NOW,
        schema_version=2,
        browser_profile_id=uuid4(),
        generation_id=uuid4(),
        cookies=(
            PortableCookie(
                name="session", value="invented", domain="127.0.0.1", expires=4102444800
            ),
        ),
    )
    proof = RawFetch(
        requested_url=url,
        final_url=url,
        http_status=200,
        content_type="text/html",
        retrieved_at=NOW,
        serving_transport="browser",
        session_cookie_present=True,
        raw_html=b"FULL",
    )
    store.promote_browser_session(artifact, proof, expected_generation=None)
    profiles = store._profiles
    controls = ConnectionControls(store.root)
    browser = PatchrightBrowserRetriever(
        runtime=profiles._runtime,
        policies={"cnbc": BrowserRetrievalSpec()},
        profile_resolver=profiles.path,
        lease_manager=LeaseManager(store.root / "locks"),
        authorize_session=lambda session: controls.require_active(session.provider),
        require_virtual_display=True,
        retain_profile=False,
    )
    shared._browser_retriever = browser
    try:
        ConnectionControls(requester._sessions._store.root).suspend("cnbc")
        assert shared.get(url).headline == "Fixture article"
        saved = shared.save(url)
        assert requester.archive_get(saved.id).id == saved.id
        assert owner.archive_search("Fixture") == []
        assert browser._held is None  # each request releases the actual owner profile
        profile = profiles.path(
            "cnbc", "default", profile_id=artifact.browser_profile_id
        )
        assert profile.is_dir()
        assert not (requester._sessions._store.root / "browser-profiles/cnbc").exists()
        assert seen and all("session=invented" in cookie for cookie in seen)
        peer = build_connection_reader(
            requester="carol", owner="alice", budget_owner=owner._network
        )
        peer._registry, peer._extractor = shared._registry, shared._extractor
        peer._archive._registry = shared._registry
        peer._archive._extractor = shared._extractor
        peer_store = peer._sessions._store
        peer_store._recipes["cnbc"] = BrowserRecipe()
        peer_store._clock = lambda: NOW
        peer._browser_retriever = PatchrightBrowserRetriever(
            runtime=peer_store._profiles._runtime,
            policies={"cnbc": BrowserRetrievalSpec()},
            profile_resolver=peer_store._profiles.path,
            lease_manager=LeaseManager(peer_store.root / "locks"),
            authorize_session=lambda session: controls.require_active(session.provider),
            require_virtual_display=True,
            retain_profile=False,
        )
        try:
            assert peer._network._limiters is shared._network._limiters
            with ThreadPoolExecutor(max_workers=2) as pool:
                reads = [pool.submit(reader.get, url) for reader in (shared, peer)]
                assert all(
                    read.result().headline == "Fixture article" for read in reads
                )
            assert peer.archive_search("Fixture") == []
            assert browser._held is None and peer._browser_retriever._held is None
            peer_trace = peer_store._diagnostic_trace._path
            assert "carol" in peer_trace.parts and "bob" not in peer_trace.parts
        finally:
            peer.close()
        controls.suspend("cnbc")
        count = len(seen)
        with pytest.raises(SessionRequiredError, match="connection_disconnected"):
            shared.get(url)
        assert len(seen) == count
        assert requester.archive_get(saved.id).id == saved.id
    finally:
        browser.close()
        site.shutdown()
        site.server_close()
        thread.join(timeout=5)
