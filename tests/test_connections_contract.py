"""Browser and sharing behavior retained while the connection adapter changes."""

import time
from html import unescape
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient
from test_connections import material, store
from test_standalone import browser_login, make_app

from newsclip.errors import SessionRequiredError

ORIGIN = "http://127.0.0.1"
ACTIONS = ("start", "cancel", "disconnect", "share", "unshare", "choose", "leave")


def snapshot(portal):
    return (
        {user: control.status("fixture") for user, control in portal.controls.items()},
        {user: portal.access.view(user, "fixture")[0] for user in ("alice", "bob")},
        dict(portal.links),
    )


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("authenticated", (False, True))
def test_sessionless_and_foreign_origin_actions_never_change_state(
    accounts, tmp_path, action, authenticated
):
    app, tokens, backends = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        if authenticated:
            browser_login(app, client)
        portal = app.state.connections
        before = snapshot(portal)
        origins = (None, "https://other.example.com", ORIGIN + ":8443", "null")
        if not authenticated:
            origins += (ORIGIN,)
        for origin in origins:
            # An API credential never substitutes for a browser session.
            headers = {"authorization": "Bearer " + tokens["alice"]}
            if origin:
                headers["origin"] = origin
            response = client.post(
                "/connections/" + action,
                data={"provider": "fixture"},
                headers=headers,
                follow_redirects=False,
            )
            assert response.status_code in (401, 403)
            if not authenticated and origin == ORIGIN:
                assert response.status_code == 401
            assert "location" not in response.headers
            assert snapshot(portal) == before
            assert all(not backend.starts for backend in backends)


@pytest.mark.parametrize("action", ("share", "disconnect"))
def test_step_up_returns_home_without_replaying_sensitive_action(
    accounts, tmp_path, action
):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        browser_login(app, client, auth_time=int(time.time()) - 3600)
        portal = app.state.connections
        selected = store(portal.controls["alice"].root.parent)
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        portal.adapters["alice"]._service_ready()._sessions = selected
        revision = portal.controls["alice"].status("fixture")["revision"]
        data = {"provider": "fixture", "revision": revision}
        if action == "share":
            data.update(member="bob", grant="new")
        before = snapshot(portal)
        denied = client.post(
            "/connections/" + action,
            data=data,
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert denied.status_code == 403 and "location" not in denied.headers
        assert 'href="/connections/login?reauth=1"' in denied.text
        assert "Nothing has changed yet" in denied.text
        assert snapshot(portal) == before

        # Follow the real OIDC exchange. Returning to Connections only displays
        # the current state; the original POST is never resumed or retained.
        start = client.get("/connections/login?reauth=1", follow_redirects=False)
        provider = app.state.oidc_provider
        provider.tamper = {"person_id": "alice"}
        callback = urlsplit(
            provider.authorize(start.headers["location"], subject="subject-alice")
        )
        confirmed = client.get(
            callback.path + "?" + callback.query, follow_redirects=False
        )
        assert confirmed.status_code == 303
        assert confirmed.headers["location"] == "/connections/"
        assert client.get(confirmed.headers["location"]).status_code == 200
        assert snapshot(portal) == before
        repeated = client.post(
            "/connections/" + action,
            data=data,
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert repeated.status_code == 303
        if action == "share":
            assert "bob" in portal.access.view("alice", "fixture")[0]["grants"]
        else:
            assert portal.controls["alice"].status("fixture")["phase"] == 1


def test_browser_share_choose_revoke_and_leave_keep_explicit_selection(
    accounts, tmp_path
):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        portal = app.state.connections
        selected = store(portal.controls["alice"].root.parent)
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        portal.adapters["alice"]._service_ready()._sessions = selected
        access = portal.access
        browser_login(app, client, "alice")
        page = client.get("/connections/")
        assert "Shared with" in page.text
        assert "Using my subscription." in page.text
        revision = portal.controls["alice"].status("fixture")["revision"]
        shared = client.post(
            "/connections/share",
            data={
                "provider": "fixture",
                "member": "bob",
                "grant": "new",
                "revision": revision,
            },
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert shared.status_code == 303
        # Offering access cannot switch the recipient's selected account.
        assert access.admit("bob", "fixture").owner == "bob"
        browser_login(app, client, "bob")
        assert "alice's subscription" in unescape(client.get("/connections/").text)
        row, offers, _ = access.view("bob", "fixture")
        grant = dict(offers)["alice"]
        chosen = client.post(
            "/connections/choose",
            data={
                "provider": "fixture",
                "owner": "alice",
                "selection_revision": row["revision"],
                "grant": grant,
            },
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert chosen.status_code == 303
        assert access.admit("bob", "fixture").owner == "alice"
        assert "Using alice's subscription." in unescape(
            client.get("/connections/").text
        )

        browser_login(app, client, "alice")
        revoked = client.post(
            "/connections/unshare",
            data={"provider": "fixture", "member": "bob", "grant": grant},
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert revoked.status_code == 303
        with pytest.raises(SessionRequiredError, match="^shared_access_removed$"):
            access.admit("bob", "fixture")
        browser_login(app, client, "bob")
        assert "selected shared access was removed" in client.get("/connections/").text
        # Recovering from revocation still requires an explicit selection.
        row = access.view("bob", "fixture")[0]
        own = client.post(
            "/connections/choose",
            data={
                "provider": "fixture",
                "owner": "bob",
                "selection_revision": row["revision"],
                "grant": "own",
            },
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert own.status_code == 303
        assert access.admit("bob", "fixture").owner == "bob"
        access.share("alice", "fixture", "bob", None)
        row, offers, _ = access.view("bob", "fixture")
        grant = dict(offers)["alice"]
        access.choose("bob", "fixture", "alice", row["revision"], grant)
        left = client.post(
            "/connections/leave",
            data={"provider": "fixture", "owner": "alice", "grant": grant},
            headers={"origin": ORIGIN},
            follow_redirects=False,
        )
        assert left.status_code == 303
        with pytest.raises(SessionRequiredError, match="^account_selection_needed$"):
            access.admit("bob", "fixture")
        assert "No subscription selected." in client.get("/connections/").text
