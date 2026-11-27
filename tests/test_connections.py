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
        browser_login(app, client)
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


def test_aged_valid_session_completes_disconnect_without_reauth(accounts, tmp_path):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        portal = app.state.connections
        selected = store(portal.controls["alice"].root.parent)
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        portal.adapters["alice"]._service_ready()._sessions = selected
        # An aged but valid browser session completes disconnect directly.
        browser_login(app, client, auth_time=int(time.time()) - 3600)
        controls = portal.controls["alice"]
        revision = controls.status("fixture")["revision"]
        response = client.post(
            "/connections/disconnect",
            data={"provider": "fixture", "revision": revision},
            headers={"origin": "http://127.0.0.1"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/connections/"
        assert "reauth" not in response.headers["location"]
        assert controls.status("fixture")["phase"] == 1


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


def test_start_new_sign_in_layout_429_and_stuck_teardown(accounts, tmp_path):
    app, _, backends = make_app(accounts, tmp_path)
    origin = {"origin": "http://127.0.0.1"}
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client)
        first_url = owner_connection(client)
        assert (
            client.post(
                first_url + "/start", json={"layout": "phone"}, headers=origin
            ).status_code
            == 200
        )
        page = client.get("/connections/").text
        assert "Sign-in is in progress (mobile view)" in page
        assert "Continue sign-in" in page
        assert "Start new sign-in" in page

        # Unbound start (no replace) while an active viewer exists returns 409.
        first_id = first_url.rsplit("/", 1)[-1]
        unbound = client.post(
            "/connections/start",
            data={"provider": "fixture"},
            headers=origin,
            follow_redirects=False,
        )
        assert unbound.status_code == 409
        assert client.get(first_url + "/state").json()["state"] in (
            "starting",
            "waiting",
        )

        # Rate limit returns 429 and preserves active window and control revision.
        controls = app.state.connections.controls["alice"]
        before_rev = controls.status("fixture")["revision"]
        app.state.connections.relays["alice"].links_per_hour = 1
        limited = client.post(
            "/connections/start",
            data={"provider": "fixture", "replace": first_id},
            headers=origin,
            follow_redirects=False,
        )
        assert limited.status_code == 429
        assert controls.status("fixture")["revision"] == before_rev
        assert client.get(first_url + "/state").json()["state"] in (
            "starting",
            "waiting",
        )
        app.state.connections.relays["alice"].links_per_hour = 6

        # Stuck backend teardown returns 409, keeps revision, and closes candidate.
        backend = backends[0]
        orig_close = backend.close
        backend.close = lambda identifier, *, cancel_only=False: backend.closed.append(
            "stuck"
        )
        stuck = client.post(
            "/connections/start",
            data={"provider": "fixture", "replace": first_id},
            headers=origin,
            follow_redirects=False,
        )
        assert stuck.status_code == 409
        assert controls.status("fixture")["revision"] == before_rev
        assert (
            client.post(
                "/connections/start",
                data={"provider": "fixture", "replace": first_id},
                headers=origin,
                follow_redirects=False,
            ).status_code
            == 409
        )
        backend.close = orig_close
        rec_url = owner_connection(client)
        assert (
            client.post(
                rec_url + "/start", json={"layout": "desktop"}, headers=origin
            ).status_code
            == 200
        )
        # Stale replacement form fails even while newer viewer is layout-switching.
        active_link = app.state.connections.links["alice", "fixture"]
        assert (
            client.post(
                rec_url + "/cancel", json={"for_restart": True}, headers=origin
            ).status_code
            == 200
        )
        stale_replace = client.post(
            "/connections/start",
            data={"provider": "fixture", "replace": first_id},
            headers=origin,
            follow_redirects=False,
        )
        assert stale_replace.status_code == 409
        assert (
            client.post(
                rec_url + "/start", json={"layout": "phone"}, headers=origin
            ).status_code
            == 200
        )

        active_link.state = "saving"
        assert (
            client.post(
                "/connections/start",
                data={"provider": "fixture", "replace": active_link.id},
                headers=origin,
                follow_redirects=False,
            ).status_code
            == 409
        )
        assert "Saving connection" in client.get("/connections/").text


def test_access_status_reflects_fresh_stale_degraded_and_operator_action(
    accounts, tmp_path
):
    from datetime import timedelta

    from newsclip.keeper_outcomes import KeeperOutcome, KeeperOutcomeStore
    from newsclip.models import TerminalFailure

    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client, "alice")
        portal = app.state.connections
        service = portal.adapters["alice"]._service_ready()
        service._wall_clock = lambda: NOW
        selected = store(portal.controls["alice"].root.parent)
        service._sessions = selected
        outcomes = KeeperOutcomeStore(portal.controls["alice"].root.parent)
        service._keeper_outcomes = outcomes

        # 1. Fresh verified session -> Working
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        status = client.get("/connections/status").json()["providers"][0]
        assert status["access_status"] == "working"
        assert status["health"] == "fresh"
        page = client.get("/connections/").text
        assert "Working" in page
        assert "Check access" in page
        assert "Check all" in page

        # 2. Stale verified session (24h old) -> Needs check
        stale_artifact = candidate.model_copy(
            update={"verified_at": NOW - timedelta(hours=24)}
        )
        selected._write(
            "fixture",
            "default",
            StoredSession(status=SessionStatus.VERIFIED, artifact=stale_artifact),
        )
        # Provide a real verify() on the fixture login_recipe for live checkpoint.
        from newsclip.models import AccessState, SessionVerification

        service._registry.get("fixture").login_recipe.verify = lambda client, session: (
            SessionVerification(
                verified=True,
                access_state=AccessState.FULL,
                reason="full_article",
                verified_at=NOW,
            )
        )
        status = client.get("/connections/status").json()["providers"][0]
        assert status["access_status"] == "stale"
        assert status["health"] == "stale"
        assert "Needs check" in client.get("/connections/").text

        # 3. Degraded session (3 consecutive renewal failures) -> Degraded
        outcomes._write(
            KeeperOutcome(
                provider="fixture",
                action="renewal_failed",
                reason_code="paid_probe_failed",
                recorded_at=NOW,
                consecutive_renewal_failures=3,
                max_age_hours=12.0,
                incident_id="incident-" + "a" * 24,
            )
        )
        status = client.get("/connections/status").json()["providers"][0]
        assert status["access_status"] == "degraded"
        assert status["health"] == "degraded"
        assert status["consecutive_renewal_failures"] == 3
        page = client.get("/connections/").text
        assert "Degraded" in page
        assert "Automatic renewal failed 3 times" in page

        # 4. Operator action -> Action needed
        selected._write(
            "fixture",
            "default",
            StoredSession(
                status=SessionStatus.OPERATOR_ACTION,
                last_failure=TerminalFailure.ACCOUNT_ALERT,
                failure_reason_code="account_alert",
            ),
        )
        status = client.get("/connections/status").json()["providers"][0]
        assert status["access_status"] == "action_required"
        page = client.get("/connections/").text
        assert "Action needed" in page
        assert "account alert" in page


def test_live_check_access_updates_status_and_handles_failure_and_inconclusive(
    accounts, tmp_path
):
    from datetime import timedelta

    from newsclip.errors import ProviderTransportError

    clock = [NOW.timestamp()]
    app, _, _ = make_app(accounts, tmp_path)
    origin = {"origin": "http://127.0.0.1"}
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client, "alice")
        portal = app.state.connections
        portal.clock = lambda: clock[0]
        service = portal.adapters["alice"]._service_ready()
        service._wall_clock = lambda: NOW
        selected = store(portal.controls["alice"].root.parent)
        service._sessions = selected
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        # Start stale so a passing live check proves verified_at refresh.
        stale_artifact = candidate.model_copy(
            update={"verified_at": NOW - timedelta(hours=24)}
        )
        selected._write(
            "fixture",
            "default",
            StoredSession(status=SessionStatus.VERIFIED, artifact=stale_artifact),
        )
        # Provide a real verify() on the fixture login_recipe for live checkpoint.
        from newsclip.models import AccessState, SessionVerification

        service._registry.get("fixture").login_recipe.verify = lambda client, session: (
            SessionVerification(
                verified=True,
                access_state=AccessState.FULL,
                reason="full_article",
                verified_at=NOW,
            )
        )

        # 1. Passing live check refreshes verified_at -> Working
        resp = client.post(
            "/connections/check",
            data={"provider": "fixture"},
            headers=origin,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/connections/#fixture"
        portal.wait_checks()
        status = client.get("/connections/status").json()["providers"][0]
        assert status["access_status"] == "working"
        assert status["last_check"]["state"] == "passed"
        assert "Live check passed" in client.get("/connections/").text

        # 2. Inconclusive live check keeps session intact
        clock[0] += 60
        orig_checkpoint = service.session_checkpoint

        def inconclusive_checkpoint(provider):
            raise ProviderTransportError("temporary timeout")

        service.session_checkpoint = inconclusive_checkpoint
        assert (
            client.post(
                "/connections/check-all",
                content=b"",
                headers={
                    **origin,
                    "content-type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            ).status_code
            == 303
        )
        portal.wait_checks()
        status = client.get("/connections/status").json()["providers"][0]
        assert status["state"] == "connected"
        assert status["last_check"]["state"] == "inconclusive"
        assert "Live check was inconclusive" in client.get("/connections/").text

        # 3. Failing live check surfaces failure banner
        clock[0] += 60

        def failed_checkpoint(provider):
            selected.mark_required(provider)
            raise SessionRequiredError("session expired")

        service.session_checkpoint = failed_checkpoint
        assert (
            client.post(
                "/connections/check",
                data={"provider": "fixture"},
                headers=origin,
                follow_redirects=False,
            ).status_code
            == 303
        )
        portal.wait_checks()
        status = client.get("/connections/status").json()["providers"][0]
        assert status["state"] == "needs_signin"
        assert status["last_check"]["state"] == "failed"
        assert "Live check failed" in client.get("/connections/").text
        service.session_checkpoint = orig_checkpoint


def test_shared_subscription_card_shows_owner_access_health_without_private_ids(
    accounts, tmp_path
):
    from html import unescape

    from newsclip.keeper_outcomes import KeeperOutcome, KeeperOutcomeStore

    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        portal = app.state.connections
        alice_service = portal.adapters["alice"]._service_ready()
        alice_service._wall_clock = lambda: NOW
        selected = store(portal.controls["alice"].root.parent)
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        alice_service._sessions = selected
        outcomes = KeeperOutcomeStore(portal.controls["alice"].root.parent)
        alice_service._keeper_outcomes = outcomes

        access = portal.access
        access.share("alice", "fixture", "bob", None)
        row, offers, _ = access.view("bob", "fixture")
        grant = dict(offers)["alice"]
        access.choose("bob", "fixture", "alice", row["revision"], grant)

        browser_login(app, client, "bob")
        page = unescape(client.get("/connections/").text)
        assert "Using alice's subscription (Working)" in page

        # Degrade Alice's subscription with a private incident ID; Bob sees Degraded
        # without ever seeing Alice's private incident identifier.
        private_incident = "incident-" + "b" * 24
        outcomes._write(
            KeeperOutcome(
                provider="fixture",
                action="renewal_failed",
                reason_code="paid_probe_failed",
                recorded_at=NOW,
                consecutive_renewal_failures=3,
                max_age_hours=12.0,
                incident_id=private_incident,
            )
        )
        page = unescape(client.get("/connections/").text)
        assert "Using alice's subscription (Degraded)" in page
        assert private_incident not in page


def test_live_check_unexpected_exception_transitions_to_inconclusive(
    accounts, tmp_path
):
    clock = [NOW.timestamp()]
    app, _, _ = make_app(accounts, tmp_path)
    origin = {"origin": "http://127.0.0.1"}
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client, "alice")
        portal = app.state.connections
        portal.clock = lambda: clock[0]
        service = portal.adapters["alice"]._service_ready()
        service._wall_clock = lambda: NOW
        selected = store(portal.controls["alice"].root.parent)
        service._sessions = selected
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)

        def broken_checkpoint(_provider):
            raise RuntimeError("unexpected failure")

        service.session_checkpoint = broken_checkpoint
        resp = client.post(
            "/connections/check",
            data={"provider": "fixture"},
            headers=origin,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        portal.wait_checks()
        status = client.get("/connections/status").json()["providers"][0]
        assert status["last_check"]["state"] == "inconclusive"

        # Subsequent check after cooldown is not wedged and can succeed.
        clock[0] += 60
        service.session_checkpoint = lambda _provider: None
        resp = client.post(
            "/connections/check",
            data={"provider": "fixture"},
            headers=origin,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        portal.wait_checks()
        status = client.get("/connections/status").json()["providers"][0]
        assert status["last_check"]["state"] == "passed"


def test_viewer_cancel_preserves_saving_session_and_cancels_relay_first(
    accounts, tmp_path
):
    origin = {"origin": "http://127.0.0.1"}

    # 1. Link already in "saving" must not rotate control revision.
    app, _, backends = make_app(accounts, tmp_path / "already-saving")
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client)
        url = owner_connection(client)
        assert (
            client.post(
                url + "/start", json={"layout": "desktop"}, headers=origin
            ).status_code
            == 200
        )
        controls = app.state.connections.controls["alice"]
        revision = controls.status("fixture")["revision"]
        link = app.state.connections.links["alice", "fixture"]
        link.state = "saving"
        backends[0].window_state = "saving"

        assert client.post(url + "/cancel", headers=origin).status_code == 204
        assert controls.status("fixture")["revision"] == revision
        with controls.publication("fixture", "default", revision=revision):
            pass

    # 2. Link transitioning to "saving" on backend before cancel completes
    # must not rotate control revision.
    app2, _, backends2 = make_app(accounts, tmp_path / "race-saving")
    with TestClient(app2, base_url="http://127.0.0.1") as client:
        browser_login(app2, client)
        url = owner_connection(client)
        assert (
            client.post(
                url + "/start", json={"layout": "desktop"}, headers=origin
            ).status_code
            == 200
        )
        controls = app2.state.connections.controls["alice"]
        revision = controls.status("fixture")["revision"]
        link = app2.state.connections.links["alice", "fixture"]
        assert link.state in ("starting", "waiting")
        backends2[0].window_state = "saving"

        assert client.post(url + "/cancel", headers=origin).status_code == 204
        assert link.state == "saving"
        assert controls.status("fixture")["revision"] == revision
        with controls.publication("fixture", "default", revision=revision):
            pass

    # 3. Normal "waiting" cancel calls relay.cancel before controls.cancel.
    app3, _, _ = make_app(accounts, tmp_path / "normal-cancel")
    with TestClient(app3, base_url="http://127.0.0.1") as client:
        browser_login(app3, client)
        url = owner_connection(client)
        assert (
            client.post(
                url + "/start", json={"layout": "desktop"}, headers=origin
            ).status_code
            == 200
        )
        controls = app3.state.connections.controls["alice"]
        relay = app3.state.connections.relays["alice"]
        revision = controls.status("fixture")["revision"]
        events: list[str] = []
        orig_relay_cancel = relay.cancel
        orig_controls_cancel = controls.cancel

        def tracked_relay_cancel(*args, **kwargs):
            events.append("relay.cancel")
            return orig_relay_cancel(*args, **kwargs)

        def tracked_controls_cancel(*args, **kwargs):
            events.append("controls.cancel")
            return orig_controls_cancel(*args, **kwargs)

        relay.cancel = tracked_relay_cancel
        controls.cancel = tracked_controls_cancel

        assert client.post(url + "/cancel", headers=origin).status_code == 204
        assert events == ["relay.cancel", "controls.cancel"]
        assert controls.status("fixture")["revision"] != revision


def test_controls_cancel_and_suspend_offloaded_to_dispatcher(accounts, tmp_path):
    import asyncio

    app, _, _ = make_app(accounts, tmp_path)
    origin = {"origin": "http://127.0.0.1"}
    with TestClient(app, base_url="http://127.0.0.1") as client:
        browser_login(app, client)
        portal = app.state.connections
        controls = portal.controls["alice"]
        on_loop: list[tuple[str, bool]] = []

        orig_cancel = controls.cancel
        orig_suspend = controls.suspend

        def check_loop(name: str) -> None:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                on_loop.append((name, False))
            else:
                on_loop.append((name, True))

        def wrapped_cancel(*args, **kwargs):
            check_loop("cancel")
            return orig_cancel(*args, **kwargs)

        def wrapped_suspend(*args, **kwargs):
            check_loop("suspend")
            return orig_suspend(*args, **kwargs)

        controls.cancel = wrapped_cancel
        controls.suspend = wrapped_suspend

        # 1. Viewer /cancel offloads controls.cancel.
        url = owner_connection(client)
        assert client.post(url + "/cancel", headers=origin).status_code == 204

        # 2. Portal /connections/cancel offloads controls.cancel.
        owner_connection(client)
        revision = controls.status("fixture")["revision"]
        assert (
            client.post(
                "/connections/cancel",
                data={"provider": "fixture", "revision": revision},
                headers=origin,
                follow_redirects=False,
            ).status_code
            == 303
        )

        # 3. Portal /connections/disconnect offloads controls.suspend.
        selected = store(controls.root.parent)
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        portal.adapters["alice"]._service_ready()._sessions = selected
        revision = controls.status("fixture")["revision"]
        assert (
            client.post(
                "/connections/disconnect",
                data={"provider": "fixture", "revision": revision},
                headers=origin,
                follow_redirects=False,
            ).status_code
            == 303
        )

        assert on_loop == [("cancel", False), ("cancel", False), ("suspend", False)]
