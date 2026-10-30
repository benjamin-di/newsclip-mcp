"""OIDC browser ownership and the actual reader/maintenance publication boundary."""

import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from test_standalone import NOW, Recipe, browser_login, make_app

from newsclip.connection_controls import ConnectionControls
from newsclip.errors import (
    OperatorActionRequiredError,
    PersistenceError,
    SessionRequiredError,
)
from newsclip.models import (
    PortableCookie,
    RawFetch,
    SessionArtifact,
    SessionStatus,
    StoredSession,
)
from newsclip.sessions import SessionStore


def material():
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
    return candidate, proof


def store(root):
    return SessionStore(
        root, recipes={"fixture": Recipe()}, http=SimpleNamespace(), clock=lambda: NOW
    )


def connection(client, token):
    result = client.post(
        "/users/alice/api/connect",
        json={"provider": "fixture"},
        headers={"authorization": "Bearer " + token},
    ).json()
    assert result["ok"]
    return result["result"]["url"]


def owner_connection(client):
    result = client.post(
        "/connections/start",
        data={"provider": "fixture"},
        headers={"origin": "http://127.0.0.1"},
        follow_redirects=False,
    )
    assert result.status_code == 303
    return result.headers["location"]


def test_verified_browser_owner_is_independent_of_mcp_credentials(accounts, tmp_path):
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        handoff = connection(client, tokens["alice"])
        assert handoff.endswith("/connections/#fixture")
        signed_out = client.get(handoff, follow_redirects=False)
        assert signed_out.status_code == 303
        assert signed_out.headers["location"] == "/connections/login"
        assert (
            client.post(
                "/connections/start",
                data={"provider": "fixture"},
                headers={"authorization": "Bearer " + tokens["alice"]},
            ).status_code
            == 401
        )
        browser_login(app, client, "alice")
        url = owner_connection(client)
        client.cookies.clear()
        assert (
            client.get(
                url + "/state", headers={"authorization": "Bearer " + tokens["alice"]}
            ).status_code
            == 404
        )
        browser_login(app, client, "alice")
        page = client.get(url)
        assert page.status_code == 200 and '"autoStart": true' in page.text
        assert client.get("/connections/status").status_code == 200
        assert client.post("/users/alice/api/providers", json={}).status_code == 401
        browser_login(app, client, "bob")
        for suffix in ("", "/state", "/novnc/vnc.html", "/novnc/paste.js"):
            assert client.get(url + suffix).status_code == 404
        assert (
            client.post(
                url + "/start",
                json={"layout": "desktop"},
                headers={"origin": "http://127.0.0.1"},
            ).status_code
            == 404
        )
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect(
                url.replace("http://", "ws://") + "/vnc",
                headers={"origin": "http://127.0.0.1"},
            ),
        ):
            pytest.fail("another user's viewer must never open")


def test_link_request_never_pauses_or_supersedes_owner_attempt(accounts, tmp_path):
    app, tokens, backends = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        controls = app.state.connections.controls["alice"]
        initial = controls.status("fixture")
        connection(client, tokens["alice"])
        assert controls.status("fixture") == initial
        assert not controls.root.exists()
        browser_login(app, client)
        url = owner_connection(client)
        active = controls.status("fixture")
        link = app.state.connections.links["alice", "fixture"]
        for _ in range(3):
            connection(client, tokens["alice"])
        assert controls.status("fixture") == active
        assert app.state.connections.links["alice", "fixture"] is link
        assert client.get(url).status_code == 200
        assert backends[0].starts == []


def test_browser_origin_never_admits_mcp_or_native_api(accounts, tmp_path, monkeypatch):
    browser = "https://connect.example.com"
    api = "https://reader.example.com"
    monkeypatch.setenv("NEWSCLIP_MCP_PUBLIC_URL_ALIASES", api + ":8443/newsclip")
    app, tokens, backends = make_app(
        accounts, tmp_path, public_url=api + "/newsclip", browser_url=browser
    )
    with TestClient(app, base_url=browser) as client:
        bearer = {"authorization": "Bearer " + tokens["alice"]}
        result = client.post(
            api + "/users/alice/api/connect",
            json={"provider": "fixture"},
            headers=bearer,
        )
        assert result.status_code == 200
        assert result.json()["result"]["url"] == browser + "/connections/#fixture"
        browser_login(app, client)
        started = client.post(
            "/connections/start",
            data={"provider": "fixture"},
            headers={"origin": browser},
            follow_redirects=False,
        )
        assert started.status_code == 303
        viewer = started.headers["location"]
        assert viewer.startswith(browser + "/users/alice/connect/")
        assert client.get(viewer).status_code == 200
        assert (
            client.post(
                viewer + "/start",
                json={"layout": "desktop"},
                headers={"origin": browser},
            ).status_code
            == 200
        )
        assert len(backends[0].starts) == 1
        for path in ("/users/alice/api/providers", "/users/alice/mcp"):
            assert (
                client.post(browser + path, json={}, headers=bearer).status_code == 403
            )
        assert (
            client.post(
                api + "/users/alice/api/providers",
                json={},
                headers={**bearer, "origin": browser},
            ).status_code
            == 403
        )
        assert (
            client.post(
                api + "/users/alice/api/providers", json={}, headers=bearer
            ).status_code
            == 200
        )
        assert client.get(viewer.replace(browser, api)).status_code == 403
        assert client.get(api + "/connections/").status_code == 403
        assert client.get(browser + "/connections/").status_code == 200
        for authority, sent_origin in ((api + ":8443", None), (api, api + ":8443")):
            headers = {**bearer, **({"origin": sent_origin} if sent_origin else {})}
            assert (
                client.post(
                    authority + "/users/alice/api/providers", json={}, headers=headers
                ).status_code
                == 200
            )
        assert (
            client.post(
                api + ":8443/users/alice/api/providers",
                json={},
                headers={**bearer, "origin": browser},
            ).status_code
            == 403
        )
        assert (
            client.post(
                api + ":8444/users/alice/api/providers", json={}, headers=bearer
            ).status_code
            == 403
        )
        assert client.get(api + ":8443/connections/").status_code == 403
    monkeypatch.setenv("NEWSCLIP_MCP_PUBLIC_URL_ALIASES", browser)
    with pytest.raises(ValueError, match="browser origin"):
        make_app(accounts, tmp_path, public_url=api, browser_url=browser)


def test_stale_cancel_and_disconnect_forms_preserve_a_new_owner_attempt(
    accounts, tmp_path
):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client, suffix="?reauth=1")
        controls = app.state.connections.controls["alice"]
        stale = controls.status("fixture")["revision"]
        url = owner_connection(client)
        assert (
            client.post(
                url + "/start",
                json={"layout": "desktop"},
                headers={"origin": "http://127.0.0.1"},
            ).status_code
            == 200
        )
        snapshot = controls.status("fixture")
        link = app.state.connections.links["alice", "fixture"]
        for action in ("cancel", "disconnect"):
            assert (
                client.post(
                    "/connections/" + action,
                    data={"provider": "fixture", "revision": stale},
                    headers={"origin": "http://127.0.0.1"},
                    follow_redirects=False,
                ).status_code
                == 303
            )
            assert controls.status("fixture") == snapshot
            assert link.state in ("starting", "waiting") and not link.closed


def test_browser_actions_require_exact_origin_and_own_provider(accounts, tmp_path):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert (
            client.post("/connections/start", data={"provider": "fixture"}).status_code
            == 401
        )
        browser_login(app, client)
        assert (
            client.post("/connections/start", data={"provider": "fixture"}).status_code
            == 403
        )
        headers = {"origin": "http://127.0.0.1"}
        assert (
            client.post(
                "/connections/start", data={"provider": "unknown"}, headers=headers
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/connections/start",
                data={"provider": "fixture", "user": "bob"},
                headers=headers,
            ).status_code
            == 400
        )
        response = client.post(
            "/connections/start",
            data={"provider": "fixture"},
            headers=headers,
            follow_redirects=False,
        )
        assert (
            response.status_code == 303
            and "/users/alice/connect/" in response.headers["location"]
        )
        assert client.get(response.headers["location"]).status_code == 200


def test_disconnect_requires_fresh_authentication(accounts, tmp_path):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        # An older identity-provider session is not a fresh confirmation.
        browser_login(app, client, auth_time=int(time.time()) - 3600)
        controls = app.state.connections.controls["alice"]
        revision = controls.status("fixture")["revision"]
        response = client.post(
            "/connections/disconnect",
            data={"provider": "fixture", "revision": revision},
            headers={"origin": "http://127.0.0.1"},
            follow_redirects=False,
        )
        assert response.status_code == 303 and response.headers["location"].endswith(
            "login?reauth=1"
        )
        assert controls.status("fixture")["phase"] == 0
        # A sign-in the provider authenticated just now already is one.
        browser_login(app, client)
        response = client.post(
            "/connections/disconnect",
            data={"provider": "fixture", "revision": revision},
            headers={"origin": "http://127.0.0.1"},
            follow_redirects=False,
        )
        # Past the identity check: the outcome is the disconnect's own, not a sign-in.
        assert "reauth" not in response.headers.get("location", "")


def test_viewer_cancel_fences_the_final_writer(accounts, tmp_path):
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client)
        url = owner_connection(client)
        controls = app.state.connections.controls["alice"]
        revision = controls.status("fixture")["revision"]
        assert (
            client.post(
                url + "/cancel", headers={"origin": "http://127.0.0.1"}
            ).status_code
            == 204
        )
        with (
            pytest.raises(SessionRequiredError),
            controls.publication("fixture", "default", revision=revision),
        ):
            pytest.fail("cancelled human writer was admitted")
        assert controls.maintenance_blocker("fixture") is None


def test_expired_human_attempt_cannot_publish(tmp_path):
    clock = [NOW.timestamp()]
    controls = ConnectionControls(tmp_path, clock=lambda: clock[0])
    revision = controls.begin("fixture")
    clock[0] += 601
    with (
        pytest.raises(SessionRequiredError),
        controls.publication("fixture", "default", revision=revision),
    ):
        pytest.fail("expired human writer was admitted")
    assert controls.maintenance_blocker("fixture") is None


def test_interrupted_attempt_can_be_cancelled_without_in_memory_link(
    accounts, tmp_path
):
    app, tokens, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client)
        owner_connection(client)
        portal = app.state.connections
        controls = portal.controls["alice"]
        revision = controls.status("fixture")["revision"]
        portal.links.clear()
        assert "Your sign-in may still be finishing" in client.get("/connections/").text
        assert (
            client.post(
                "/connections/cancel",
                data={"provider": "fixture", "revision": revision},
                headers={"origin": "http://127.0.0.1"},
            ).status_code
            == 200
        )
        with (
            pytest.raises(SessionRequiredError),
            controls.publication("fixture", "default", revision=revision),
        ):
            pytest.fail("interrupted cancelled worker was admitted")
        assert controls.maintenance_blocker("fixture") is None


def test_already_running_maintenance_cannot_publish_over_human_attempt(tmp_path):
    current = store(tmp_path)
    accepted, proof = material()
    current.promote_browser_session(accepted, proof, expected_generation=None)
    current.connection_controls.begin("fixture")
    replacement, replacement_proof = material()
    with pytest.raises(SessionRequiredError):
        current.promote_browser_session(
            replacement,
            replacement_proof,
            expected_generation=accepted.generation_id,
        )
    assert current.get_valid_session("fixture").generation_id == accepted.generation_id


def test_saving_after_page_closure_and_restart_preserves_user_and_revision(tmp_path):
    current = store(tmp_path / "alice")
    other = store(tmp_path / "bob")
    candidate, proof = material()
    revision = current.connection_controls.begin("fixture")
    restarted = store(tmp_path / "alice")
    restarted.promote_browser_session(
        candidate, proof, expected_generation=None, connection_revision=revision
    )
    assert current.get_valid_session("fixture").generation_id == candidate.generation_id
    assert current.status("fixture").status is SessionStatus.VERIFIED
    with pytest.raises(SessionRequiredError):
        other.get_valid_session("fixture")


def test_disconnect_removes_only_own_authority_and_preserves_other_users(tmp_path):
    first, second = store(tmp_path / "alice"), store(tmp_path / "bob")
    candidate, proof = material()
    for selected in (first, second):
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        profile = (
            selected.root
            / "browser-profiles"
            / "fixture"
            / ("default--" + candidate.browser_profile_id.hex)
        )
        profile.mkdir(parents=True)
        (profile / "synthetic-cookies").write_text("synthetic private profile")
    first.disconnect("fixture")
    with pytest.raises(SessionRequiredError, match="connection_disconnected"):
        store(tmp_path / "alice").get_valid_session("fixture")
    assert second.get_valid_session("fixture").generation_id == candidate.generation_id
    assert not list((first.root / "browser-profiles" / "fixture").iterdir())
    raw = next((first.root / "sessions" / "fixture").glob("*.json")).read_text()
    assert "invented" not in raw
    assert first.status("fixture").failure_reason_code == "connection_disconnected"


def test_older_disconnect_never_drains_or_clears_a_new_verified_connection(tmp_path):
    selected = store(tmp_path)
    accepted, proof = material()
    selected.promote_browser_session(accepted, proof, expected_generation=None)
    first = selected.connection_controls.suspend("fixture")
    second = selected.connection_controls.suspend("fixture")
    selected.disconnect("fixture", connection_revision=second)
    revision = selected.connection_controls.begin("fixture")
    replacement, replacement_proof = material()
    selected.promote_browser_session(
        replacement,
        replacement_proof,
        expected_generation=None,
        connection_revision=revision,
    )
    store(tmp_path).disconnect(
        "fixture",
        connection_revision=first,
        drain=lambda: pytest.fail("stale disconnect drained the new browser"),
    )
    assert (
        selected.get_valid_session("fixture").generation_id == replacement.generation_id
    )
    assert selected.connection_controls.current("fixture", "default", revision)


def test_disconnect_completion_does_not_open_a_gap_in_newer_barrier(tmp_path):
    selected = store(tmp_path)
    first = selected.connection_controls.suspend("fixture")
    newer = []

    def during_drain():
        newer.append(selected.connection_controls.suspend("fixture"))

    selected.disconnect("fixture", connection_revision=first, drain=during_drain)
    assert selected.connection_controls.disconnect_current(
        "fixture", "default", newer[0]
    )
    with pytest.raises(SessionRequiredError):
        selected.connection_controls.begin("fixture")
    selected.disconnect("fixture", connection_revision=newer[0])
    assert selected.connection_controls.status("fixture")["phase"] == 1


def test_late_human_or_automatic_publish_cannot_undo_disconnect(tmp_path):
    selected = store(tmp_path)
    candidate, proof = material()
    revision = selected.connection_controls.begin("fixture")
    selected.disconnect("fixture")
    for human in (False, True):
        with pytest.raises(SessionRequiredError, match="connection_disconnected"):
            if human:
                selected.promote_browser_session(
                    candidate,
                    proof,
                    expected_generation=None,
                    connection_revision=revision,
                )
            else:
                selected._write(
                    "fixture",
                    "default",
                    StoredSession(status=SessionStatus.VERIFIED, artifact=candidate),
                )
    assert selected.connection_controls.status("fixture")["phase"] == 1


def test_only_a_new_verified_owner_reconnect_restores_admission(tmp_path):
    selected = store(tmp_path)
    candidate, proof = material()
    selected.disconnect("fixture")
    revision = selected.connection_controls.begin("fixture")
    assert selected.connection_controls.status("fixture")["phase"] == 3
    with pytest.raises(SessionRequiredError):
        selected.get_valid_session("fixture")
    with pytest.raises(OperatorActionRequiredError):
        selected.promote_browser_session(
            candidate,
            proof.model_copy(update={"raw_html": b"TEASER"}),
            expected_generation=None,
            connection_revision=revision,
        )
    assert selected.connection_controls.status("fixture")["phase"] == 3
    selected.promote_browser_session(
        candidate, proof, expected_generation=None, connection_revision=revision
    )
    assert (
        selected.get_valid_session("fixture").generation_id == candidate.generation_id
    )


def test_cancel_invalidates_candidate_without_erasing_previous_verified_authority(
    tmp_path,
):
    selected = store(tmp_path)
    candidate, proof = material()
    selected.promote_browser_session(candidate, proof, expected_generation=None)
    replacement = candidate.model_copy(
        update={"generation_id": uuid4(), "browser_profile_id": uuid4()}
    )
    revision = selected.connection_controls.begin("fixture")
    selected.connection_controls.cancel("fixture", "default", revision)
    with pytest.raises(SessionRequiredError):
        selected.promote_browser_session(
            replacement,
            proof,
            expected_generation=candidate.generation_id,
            connection_revision=revision,
        )
    assert (
        selected.get_valid_session("fixture").generation_id == candidate.generation_id
    )


def test_maintenance_never_resolves_credentials_for_disconnected_target(tmp_path):
    selected = store(tmp_path)
    selected.disconnect("fixture")
    with pytest.raises(SessionRequiredError, match="connection_disconnected"):
        selected.explicit_login("fixture")
    assert selected.status("fixture").status is SessionStatus.OPERATOR_ACTION
    assert selected.connection_controls.status("fixture")["phase"] == 1


def test_cleanup_failure_stays_blocked_and_can_be_retried(tmp_path):
    selected = store(tmp_path)
    profile = selected.root / "browser-profiles" / "fixture" / "default"
    profile.parent.mkdir(parents=True)
    profile.symlink_to(tmp_path / "unrelated")
    with pytest.raises(PersistenceError):
        selected.disconnect("fixture")
    assert selected.connection_controls.status("fixture")["phase"] == 2
    with pytest.raises(SessionRequiredError):
        store(tmp_path).get_valid_session("fixture")
    profile.unlink()
    selected.disconnect("fixture")
    assert selected.connection_controls.status("fixture")["phase"] == 1


def test_corrupt_controls_fail_closed(tmp_path):
    controls = ConnectionControls(tmp_path)
    controls.suspend("fixture")
    controls.path("fixture").write_text('"invalid"')
    with pytest.raises(PersistenceError):
        controls.require_active("fixture")
