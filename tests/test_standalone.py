"""Standalone user isolation, real archive behavior, and connection authority."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

pytest.importorskip("signin_window")
pytest.importorskip("fastmcp")

from oidc_provider import Provider  # noqa: E402
from signin_window.oidc import OIDCConfig  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402
from test_mcp import FULL_URL, PagedFakeProvider, _service  # noqa: E402

from newsclip.composition import build_mcp_service  # noqa: E402
from newsclip.connections import ConnectionsConfig  # noqa: E402
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
from newsclip.tenancy import add_proxy_user, add_user, load_users  # noqa: E402

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
        assert alice._recovery_store.root == tmp_path / "state/users/alice/recovery"
        assert bob._recovery_store.root == tmp_path / "state/users/bob/recovery"
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


def make_app(
    accounts, tmp_path, *, public_url="http://127.0.0.1", browser_url="http://127.0.0.1"
):
    registry, tokens = accounts
    backends = []

    def backend():
        value = Backend()
        backends.append(value)
        return value

    provider = Provider()
    provider.tamper = {"person_id": "alice"}
    config = ConnectionsConfig(
        OIDCConfig(
            provider.issuer,
            "newsclip-ui",
            browser_url,
            tmp_path / "browser",
            required_group="example-users",
            cookie_name="__Host-newsclip-connections",
            allow_loopback_http=True,
        ),
        "person_id",
        {},
    )

    app = build_standalone_app(
        users_path=registry,
        public_url=public_url,
        login_token="synthetic-internal-token-at-least-32-characters",
        service_factory=lambda user: _service(tmp_path / user, ConnectProvider()),
        backend_factory=backend,
        connections_config=config,
        oidc_transport=provider.transport(),
    )
    app.state.oidc_provider = provider
    return app, tokens, backends


def browser_login(app, client, user="alice", suffix="", **claims):
    provider = app.state.oidc_provider
    provider.tamper = {"person_id": user, **claims}
    response = client.get("/connections/login" + suffix, follow_redirects=False)
    callback = urlsplit(
        provider.authorize(response.headers["location"], subject="subject-" + user)
    )
    result = client.get(callback.path + "?" + callback.query, follow_redirects=False)
    assert result.status_code == 303


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
        assert url.endswith("/connections/#fixture")
        assert result["result"]["expires_at"] is None
        assert client.get(url, follow_redirects=False).status_code == 303  # to sign-in
        browser_login(app, client)
        request = client.post(
            "/connections/start",
            data={"provider": "fixture"},
            headers={"origin": "http://127.0.0.1"},
            follow_redirects=False,
        )
        assert request.status_code == 303
        url = request.headers["location"]
        page = client.get(url)
        assert page.status_code == 200
        assert page.headers["Cache-Control"] == "no-store"
        assert not any(token in page.text for token in tokens.values())
        assert client.get(url.replace("/alice/", "/bob/")).status_code == 404
        started = client.post(
            url + "/start",
            json={"layout": "desktop"},
            headers={"origin": "http://127.0.0.1"},
        )
        assert started.status_code == 200
        assert backends[0].starts[0]["user"] == "alice"
        assert backends[0].starts[0]["provider"] == "fixture"
        assert backends[0].starts[0]["account_key"] == "default"
        assert len(backends[0].starts[0]["connection_revision"]) == 32
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


def test_proxy_identity_is_bound_to_dedicated_credential(
    accounts, tmp_path, monkeypatch
):
    proxy = "synthetic-proxy-secret-at-least-32-characters"
    monkeypatch.setenv("NEWSCLIP_TRUSTED_PROXY_TOKEN", proxy)
    monkeypatch.setenv("NEWSCLIP_TRUSTED_USER_HEADER", "X-Authenticated-User")
    add_proxy_user(accounts[0], "carol")
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        good = {"Authorization": f"Bearer {proxy}", "X-Authenticated-User": "alice"}
        assert client.post("/api/providers", json={}, headers=good).status_code == 200
        proxy_only = {**good, "X-Authenticated-User": "carol"}
        assert (
            client.post("/api/providers", json={}, headers=proxy_only).status_code
            == 200
        )
        assert (
            client.post(
                "/users/carol/api/providers",
                json={},
                headers={"Authorization": f"Bearer {proxy}"},
            ).status_code
            == 401
        )
        for headers in (
            {"Authorization": f"Bearer {proxy}"},
            {"X-Authenticated-User": "alice"},
            {**good, "Authorization": f"Bearer {tokens['alice']}"},
            {**good, "X-Authenticated-User": "unknown"},
            {**good, "X-Authenticated-User": "../bob"},
        ):
            assert (
                client.post("/api/providers", json={}, headers=headers).status_code
                == 401
            )
        assert (
            client.post("/users/bob/api/providers", json={}, headers=good).status_code
            == 401
        )
        duplicate = [
            ("Authorization", f"Bearer {proxy}"),
            ("X-Authenticated-User", "alice"),
            ("X-Authenticated-User", "bob"),
        ]
        assert (
            client.post("/api/providers", json={}, headers=duplicate).status_code == 401
        )
        # Native tokens remain bound to their explicit URL, with no proxy header.
        assert (
            client.post(
                "/users/alice/api/providers",
                json={},
                headers={"Authorization": f"Bearer {tokens['alice']}"},
            ).status_code
            == 200
        )


def test_public_prefix_is_used_in_links_and_origin_is_bare(accounts, tmp_path):
    registry, tokens = accounts
    app = build_standalone_app(
        users_path=registry,
        public_url="https://reader.example.com/newsclip",
        login_token="synthetic-internal-token-at-least-32-characters",
        service_factory=lambda user: _service(tmp_path / user, ConnectProvider()),
        backend_factory=Backend,
        connections_config=ConnectionsConfig(
            OIDCConfig(
                "https://identity.example.com",
                "newsclip-ui",
                "https://reader.example.com/newsclip",
                tmp_path / "browser",
                cookie_name="__Host-newsclip-connections",
                required_group="example-users",
            ),
            "person_id",
            {},
        ),
    )
    with TestClient(app, base_url="https://reader.example.com") as client:
        headers = {
            "Authorization": f"Bearer {tokens['alice']}",
            "Origin": "https://reader.example.com",
        }
        response = client.post(
            "/users/alice/api/connect", json={"provider": "fixture"}, headers=headers
        )
        assert response.status_code == 200
        assert response.json()["result"]["url"].startswith(
            "https://reader.example.com/newsclip/connections/#fixture"
        )
        headers["Origin"] += "/newsclip"
        assert (
            client.post(
                "/users/alice/api/providers", json={}, headers=headers
            ).status_code
            == 403
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/../other",
        "https://example.com/a//b",
        "https://example.com/%2e%2e",
        "https://example.com/prefix?secret=x",
        "https://user:pass@example.com/prefix",
    ],
)
def test_unsafe_public_prefixes_are_refused(url):
    from newsclip.standalone import validate_public_url

    with pytest.raises(ValueError):
        validate_public_url(url)
