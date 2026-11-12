"""Actual shared renderer output, with synthetic ownership and no browser launch."""

import inspect
import json
import time
from dataclasses import replace
from html.parser import HTMLParser

import pytest

pytest.importorskip("signin_window")
pytest.importorskip("fastmcp")

from signin_window import connections as renderer  # noqa: E402
from signin_window.oidc import BrowserAuth  # noqa: E402
from signin_window.page import PageText  # noqa: E402
from signin_window.service import Window, build_app  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402
from test_connections import owner_connection  # noqa: E402
from test_connections_contract import snapshot  # noqa: E402
from test_standalone import browser_login, make_app  # noqa: E402

from newsclip import ui  # noqa: E402
from newsclip.build_identity import BUILD  # noqa: E402
from newsclip.signin import build_signin_app  # noqa: E402

ORIGIN = "http://127.0.0.1"


class IdentityFooters(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.footers = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "footer" and values.get("id") in (
            "connection-identity",
            "page-identity",
        ):
            self.footers.append(values)


def assert_identity(markup, factory, build=BUILD):
    footers = IdentityFooters(markup).footers
    compatible = (
        getattr(renderer, "PageIdentity", None) is not None
        and "identity" in inspect.signature(factory).parameters
    )
    assert len(footers) == int(compatible)
    if compatible:
        assert footers[0]["data-service"] == build.service
        assert footers[0]["data-version"] == build.version
        assert footers[0]["data-source-revision"] == build.source_revision
        assert footers[0]["title"] == "Source revision: " + build.source_revision
        assert "data-instance" not in footers[0]


def test_home_uses_installed_identity_despite_runtime_overrides(
    accounts, tmp_path, monkeypatch
):
    for name in ("VERSION", "VCS_REF", "GIT_COMMIT", "NEWSCLIP_VERSION"):
        monkeypatch.setenv(name, "runtime-identity-must-not-appear")
    app, _, backends = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        browser_login(app, client)
        before = snapshot(app.state.connections)
        response = client.get("/connections/")
        assert response.status_code == 200
        assert "News subscriptions" in response.text
        assert "Connect the subscription you want to use." in response.text
        assert 'action="/connections/start"' in response.text
        assert 'action="/connections/logout"' in response.text
        assert "runtime-identity-must-not-appear" not in response.text
        assert_identity(response.text, renderer.page)
        assert snapshot(app.state.connections) == before
        assert all(not backend.starts for backend in backends)


@pytest.mark.parametrize(
    ("case", "status", "message"),
    [
        ("sessionless", 401, "Your sign-in has ended"),
        ("foreign_origin", 403, ""),
        ("unmapped", 403, "Request refused"),
        ("step_up", 403, "Nothing has changed yet"),
        ("callback", 403, "We could not confirm your sign-in"),
        ("unavailable", 503, "Sign-in is unavailable"),
        ("logout", 200, "You are signed out of Connections"),
    ],
)
def test_auth_pages_keep_outcomes_and_connection_state(
    accounts, tmp_path, monkeypatch, case, status, message
):
    app, _, backends = make_app(accounts, tmp_path)
    portal = app.state.connections
    with TestClient(app, base_url=ORIGIN) as client:
        if case in ("foreign_origin", "step_up", "logout"):
            browser_login(app, client, auth_time=int(time.time()) - 3600)
        elif case == "unmapped":
            browser_login(app, client, "unregistered")
        before = snapshot(portal)
        if case == "callback":
            response = client.get("/connections/callback")
        elif case == "unavailable":

            async def unavailable():
                raise ValueError("synthetic unavailable issuer")

            monkeypatch.setattr(portal.auth.client, "load_server_metadata", unavailable)
            response = client.get("/connections/login")
        else:
            action = {"step_up": "share", "logout": "logout"}.get(case, "start")
            response = client.post(
                "/connections/" + action,
                data={
                    "provider": "fixture",
                    "member": "bob",
                    "grant": "new",
                    "revision": portal.controls["alice"].status("fixture")["revision"],
                },
                headers={
                    "origin": "https://other.example.com"
                    if case == "foreign_origin"
                    else ORIGIN
                },
                follow_redirects=False,
            )
        assert response.status_code == status
        assert message in response.text
        assert "location" not in response.headers
        if case == "foreign_origin":
            assert response.content == b""
        else:
            assert_identity(response.text, BrowserAuth)
        assert snapshot(portal) == before
        assert all(not backend.starts for backend in backends)


@pytest.mark.parametrize("case", ("ready", "expired", "unavailable", "other_owner"))
def test_relay_pages_keep_owner_checks_text_and_outcomes(accounts, tmp_path, case):
    app, _, backends = make_app(accounts, tmp_path)
    portal = app.state.connections
    with TestClient(app, base_url=ORIGIN) as client:
        browser_login(app, client)
        url = owner_connection(client)
        if case == "expired":
            url = url.rsplit("/", 1)[0] + "/" + "x" * 32
        elif case == "unavailable":
            link = portal.links["alice", "fixture"]
            portal.controls["alice"].cancel("fixture", "default", link.context.target)
        elif case == "other_owner":
            browser_login(app, client, "bob")
        before = snapshot(portal)
        response = client.get(url)
        assert response.status_code == (200 if case == "ready" else 404)
        if case == "other_owner":
            assert response.content == b""
        else:
            assert response.headers["cache-control"] == "no-store"
            assert_identity(response.text, PageText)
        if case == "ready":
            assert "Connect fixture to Newsclip" in response.text
            assert "device passkeys do not work in this remote window" in response.text
            assert "Choose the publisher account you intend to use." in response.text
            config = json.loads(
                response.text.split("const CONFIG = ", 1)[1].split(";</script>", 1)[0]
            )
            assert config["autoStart"] is True and config["reconnect"] is True
            assert config["returnUrl"] == "/connections/"
            assert config["noRetry"] == ["connected", "expired", "limited"]
            assert "Connection saved" in config["outcomes"]["connected"]
            assert "We could not confirm the connection" in config["outcomes"]["failed"]
            assert "Sign-in cancelled" in config["outcomes"]["cancelled"]
        elif case == "expired":
            assert "This link has expired" in response.text
            assert 'href="/connections/"' in response.text
        elif case == "unavailable":
            assert "This sign-in request is unavailable" in response.text
            assert "Connect fixture to Newsclip" not in response.text
        assert snapshot(portal) == before
        assert all(not backend.starts for backend in backends)


def test_direct_viewer_stamps_shell_and_preserves_native_files(
    accounts, tmp_path, monkeypatch
):
    native = (
        b"<!doctype html><title>Synthetic vendor viewer</title><div id=screen></div>"
    )
    novnc = tmp_path / "novnc"
    novnc.mkdir()
    (novnc / "vnc.html").write_bytes(native)
    monkeypatch.setenv("NOVNC_DIR", str(novnc))
    monkeypatch.delenv("NEWSCLIP_LOGIN_TOKEN_FILE", raising=False)
    monkeypatch.setenv("NEWSCLIP_LOGIN_TOKEN", "synthetic-internal-token-" + "x" * 32)

    def forbidden(*args, **kwargs):
        pytest.fail("rendering must never start a display or publisher runner")

    app = build_signin_app(runner=forbidden, users_path=accounts[0])
    windows = app.state.windows
    window = Window("synthetic-window", "desktop", 0, 0, float("inf"))
    window.waiting("publisher.example.com")
    monkeypatch.setattr(windows, "start_display", forbidden)
    monkeypatch.setattr(
        windows, "get", lambda identifier: window if identifier == window.id else None
    )
    with TestClient(app, base_url=ORIGIN) as client:
        path = "/view/" + window.id
        assert client.get(path).status_code == 404
        assert client.get(path + "?t=incorrect").status_code == 404
        assert client.get("/logins/" + window.id).status_code == 401
        response = client.get(path, params={"t": window.view_token})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"
        assert "Connect a news subscription" in response.text
        assert (
            "Sign in as you usually do. This page finishes by itself." in response.text
        )
        assert "import RFB from '/novnc/core/rfb.js'" in response.text
        assert_identity(response.text, build_app)
        assert client.get(path + "/state", params={"t": window.view_token}).json() == {
            "state": "waiting",
            "host": "publisher.example.com",
        }
        vendor = client.get("/novnc/vnc.html")
        assert vendor.status_code == 200 and vendor.content == native
        assert not IdentityFooters(vendor.text).footers


@pytest.mark.parametrize("revision", ("unknown", "a" * 40))
def test_host_fields_are_escaped_and_full_revision_is_retained(
    accounts, tmp_path, monkeypatch, revision
):
    build = replace(BUILD, version='8.9.0<&"', source_revision=revision)
    monkeypatch.setattr(ui, "BUILD", build)
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        browser_login(app, client)
        response = client.get("/connections/")
        assert response.status_code == 200
        assert_identity(response.text, renderer.page, build)
        assert build.version not in response.text
