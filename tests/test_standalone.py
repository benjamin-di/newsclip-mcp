"""Standalone user isolation, real archive behavior, and connection authority."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

pytest.importorskip("signin_window")
pytest.importorskip("fastmcp")

from starlette.testclient import TestClient  # noqa: E402
from test_mcp import FULL_URL, PagedFakeProvider, _service  # noqa: E402

from newsclip.composition import build_mcp_service  # noqa: E402
from newsclip.errors import OperatorActionRequiredError  # noqa: E402
from newsclip.models import (  # noqa: E402
    AccessState,
    PortableCookie,
    RawFetch,
    SessionArtifact,
    SessionVerification,
)
from newsclip.sessions import SessionStore  # noqa: E402
from newsclip.standalone import build_standalone_app  # noqa: E402
from newsclip.tenancy import add_user, load_users  # noqa: E402

NOW = datetime(2026, 10, 25, tzinfo=UTC)


def test_user_registry_contains_only_hashes_and_private_files(accounts, tmp_path):
    registry, tokens = accounts
    users = load_users(registry)
    assert len(users) == 2
    assert users[0].accepts(tokens[users[0].id])
    assert all(token not in registry.read_text() for token in tokens.values())
    assert stat.S_IMODE(registry.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "alice.token").stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="exists"):
        add_user(registry, "alice", tmp_path / "duplicate.token")
    add_user(registry, "alice", tmp_path / "rotated.token", rotate=True)
    alice = next(user for user in load_users(registry) if user.id == "alice")
    assert not alice.accepts(tokens["alice"])
    assert alice.accepts((tmp_path / "rotated.token").read_text().strip())


@pytest.mark.parametrize("name", ["../alice", "Alice", "a/b", "", "a%2fb", "a" * 49])
def test_user_paths_are_not_user_supplied_paths(tmp_path, name):
    with pytest.raises(ValueError):
        add_user(tmp_path / "users.json", name, tmp_path / "token")
    assert not (tmp_path / "token").exists()


def test_product_composition_isolates_complete_state(monkeypatch, tmp_path):
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_PROVIDER_ALLOWLIST", "cnbc")
    alice = build_mcp_service(user="alice")
    bob = build_mcp_service(user="bob")
    try:
        assert alice._archive.path == tmp_path / "data/users/alice/archive.sqlite3"
        assert bob._archive.path == tmp_path / "data/users/bob/archive.sqlite3"
        assert alice._sessions._store.root == tmp_path / "state/users/alice"
        assert bob._sessions._store.root == tmp_path / "state/users/bob"
    finally:
        alice.close()
        bob.close()


class Backend:
    def __init__(self):
        self.starts = []

    def start(self, layout="desktop", **params):
        self.starts.append(params)
        return {
            "id": "synthetic-window-id-123",
            "state": "waiting",
            "view_token": "synthetic-view-token-123",
        }

    def state(self, _identifier):
        return {"id": "synthetic-window-id-123", "state": "waiting"}

    def close(self, _identifier):
        pass


class ConnectProvider(PagedFakeProvider):
    login_recipe = SimpleNamespace(provider="fixture")


def make_app(accounts, tmp_path):
    registry, tokens = accounts
    backends = []

    def backend():
        value = Backend()
        backends.append(value)
        return value

    app = build_standalone_app(
        users_path=registry,
        public_url="http://127.0.0.1",
        login_token="synthetic-internal-token-at-least-32-characters",
        service_factory=lambda user: _service(tmp_path / user, ConnectProvider()),
        backend_factory=backend,
    )
    return app, tokens, backends


def test_tokens_cannot_cross_users_or_select_storage(accounts, tmp_path):
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        alice = {"Authorization": f"Bearer {tokens['alice']}"}
        bob = {"Authorization": f"Bearer {tokens['bob']}"}
        assert client.get("/health").status_code == 200
        assert client.post("/users/alice/api/providers", json={}).status_code == 401
        assert (
            client.post("/users/bob/api/providers", json={}, headers=alice).status_code
            == 401
        )
        assert (
            client.post(
                "/users/alice/api/save",
                json={"url": FULL_URL, "user": "bob"},
                headers=alice,
            ).status_code
            == 400
        )
        saved = client.post(
            "/users/alice/api/save", json={"url": FULL_URL}, headers=alice
        ).json()
        assert saved["ok"]
        article_id = saved["result"]["id"]
        own = client.post(
            "/users/alice/api/archive_get",
            json={"article_id": article_id},
            headers=alice,
        ).json()
        assert own["ok"]
        other = client.post(
            "/users/bob/api/archive_get", json={"article_id": article_id}, headers=bob
        ).json()
        assert not other["ok"]
        assert "body_markdown" not in json.dumps(other)
        assert (
            client.post(
                "/users/bob/api/archive_search", json={"query": "fixture"}, headers=bob
            ).json()["result"]
            == []
        )
        page = client.post(
            "/users/alice/api/search_start",
            json={"query": "fixture", "filters": {"limit": 2}},
            headers=alice,
        ).json()
        assert page["ok"]
        cursor = page["result"]["cursor"]
        assert not client.post(
            "/users/bob/api/search_next", json={"cursor": cursor}, headers=bob
        ).json()["ok"]
        assert client.post(
            "/users/alice/api/search_next",
            json={"cursor": cursor, "limit": 2},
            headers=alice,
        ).json()["ok"]


def test_connection_links_are_isolated_and_do_not_expose_sessions(accounts, tmp_path):
    app, tokens, backends = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        headers = {"Authorization": f"Bearer {tokens['alice']}"}
        result = client.post(
            "/users/alice/api/connect", json={"provider": "fixture"}, headers=headers
        ).json()
        assert result["ok"]
        url = result["result"]["url"]
        assert "/users/alice/connect/" in url
        page = client.get(url)
        assert page.status_code == 200
        assert page.headers["Cache-Control"] == "no-store"
        assert not any(token in page.text for token in tokens.values())
        assert client.get(url.replace("/alice/", "/bob/")).status_code == 404
        started = client.post(url + "/start", json={"layout": "desktop"})
        assert started.status_code == 200
        assert backends[0].starts == [{"user": "alice", "provider": "fixture"}]
        assert "cookies" not in started.text


@pytest.mark.parametrize(
    "extra_headers",
    [
        [("Host", "attacker.example.com")],
        [("Origin", "https://attacker.example.com")],
        [("Origin", "http://127.0.0.1"), ("Origin", "http://127.0.0.1")],
        [("Host", "127.0.0.1"), ("Host", "127.0.0.1")],
    ],
)
def test_request_authority_rejects_foreign_or_ambiguous_headers(
    accounts, tmp_path, extra_headers
):
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/users/alice/api/providers",
            json={},
            headers=[("Authorization", f"Bearer {tokens['alice']}"), *extra_headers],
        )
        assert response.status_code == 403


def test_token_rotation_revokes_running_application_access(accounts, tmp_path):
    app, tokens, _ = make_app(accounts, tmp_path)
    registry, _ = accounts
    with TestClient(app, base_url="http://127.0.0.1") as client:
        old = {"Authorization": f"Bearer {tokens['alice']}"}
        assert (
            client.post("/users/alice/api/providers", json={}, headers=old).status_code
            == 200
        )
        replacement = tmp_path / "replacement.token"
        add_user(registry, "alice", replacement, rotate=True)
        assert (
            client.post("/users/alice/api/providers", json={}, headers=old).status_code
            == 401
        )
        assert (
            client.post(
                "/users/alice/api/providers",
                json={},
                headers={"Authorization": f"Bearer {replacement.read_text().strip()}"},
            ).status_code
            == 200
        )


def test_diagnostic_overrides_remain_separate_per_user(monkeypatch, tmp_path):
    from newsclip.composition import _timing_root, _trace_root
    from newsclip.tenancy import user_scope

    monkeypatch.setenv("NEWSCLIP_TIMING_HOME", str(tmp_path / "timings"))
    monkeypatch.setenv("NEWSCLIP_TRACE_HOME", str(tmp_path / "traces"))
    for user in ("alice", "bob"):
        with user_scope(user):
            assert _timing_root(tmp_path) == tmp_path / "timings/users" / user
            assert _trace_root(tmp_path) == tmp_path / "traces/users" / user


class Recipe:
    provider = "fixture"
    allowed_cookie_domains = frozenset({"example.com"})

    def verify_fetch(self, fetch):
        return SessionVerification(
            verified=fetch.raw_html == b"FULL",
            access_state=AccessState.FULL
            if fetch.raw_html == b"FULL"
            else AccessState.TEASER,
            reason="synthetic",
            verified_at=NOW,
        )


def test_failed_or_stale_manual_signin_preserves_verified_generation(tmp_path):
    store = SessionStore(
        tmp_path,
        recipes={"fixture": Recipe()},
        http=SimpleNamespace(),
        clock=lambda: NOW,
    )
    candidate = SessionArtifact(
        schema_version=2,
        browser_profile_id=uuid4(),
        generation_id=uuid4(),
        provider="fixture",
        created_at=NOW,
        verified_at=NOW,
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
    assert store.current_generation("fixture") is None
    store.promote_browser_session(candidate, proof, expected_generation=None)
    replacement = candidate.model_copy(
        update={"generation_id": uuid4(), "browser_profile_id": uuid4()}
    )
    with pytest.raises(OperatorActionRequiredError):
        store.promote_browser_session(
            replacement,
            proof.model_copy(update={"raw_html": b"TEASER"}),
            expected_generation=candidate.generation_id,
        )
    with pytest.raises(OperatorActionRequiredError, match="changed"):
        store.promote_browser_session(replacement, proof, expected_generation=None)
    assert store.get_valid_session("fixture").generation_id == candidate.generation_id
