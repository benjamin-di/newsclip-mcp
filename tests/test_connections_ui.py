"""Rendering contract tests for Newsclip Connections pages on signin-window 0.13."""

from __future__ import annotations

import json
from datetime import timedelta
from html.parser import HTMLParser

import pytest

pytest.importorskip("signin_window")
pytest.importorskip("fastmcp")

from starlette.testclient import TestClient  # noqa: E402
from test_connections import material, owner_connection, store  # noqa: E402
from test_standalone import NOW, browser_login, make_app  # noqa: E402

from newsclip.connections_ui import CONNECTIONS_STYLE  # noqa: E402
from newsclip.keeper_outcomes import KeeperOutcome, KeeperOutcomeStore  # noqa: E402
from newsclip.models import (  # noqa: E402
    SessionStatus,
    StoredSession,
    TerminalFailure,
)

ORIGIN = "http://127.0.0.1"
HTTPS_ORIGIN = "https://news.example.com"

SUITE_JSON = json.dumps(
    {
        "name": "Example",
        "endpoint": {
            "title": "Use with your AI assistant",
            "url": "https://tools.example.com/all/mcp",
            "help": "Add this address to your assistant once and sign in as yourself.",
        },
        "apps": [
            {
                "label": "Household",
                "url": "https://household.example.com/",
                "section": "Workspaces",
                "description": "Balances and spending",
            },
            {
                "label": "Newsclip",
                "url": f"{HTTPS_ORIGIN}/",
                "section": "Accounts",
                "description": "News subscriptions",
                "endpoint": True,
            },
            {
                "label": "Shop",
                "url": "https://shop.example.com/",
                "section": "Accounts",
                "description": "Orders and basket",
            },
        ],
    }
)


class _PageInspector(HTMLParser):
    def __init__(self, markup: str) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self.badges: list[tuple[str, str]] = []
        self.has_hero = False
        self.has_suite_switch = False
        self.has_endpoint = False
        self.has_facts = False
        self.has_rows = False
        self.suite_links: list[str] = []
        self._current_form: dict[str, object] | None = None
        self._in_badge_cls: str | None = None
        self._badge_text: list[str] = []
        self._in_suite_menu = False
        self.feed(markup)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k: (v or "") for k, v in attrs}
        classes = set(values.get("class", "").split())
        if tag == "section" and {"panel", "hero"} <= classes:
            self.has_hero = True
        if tag == "details" and "suite-switch" in classes:
            self.has_suite_switch = True
        if tag == "details" and "endpoint" in classes:
            self.has_endpoint = True
        if tag == "div" and "suite-menu" in classes:
            self._in_suite_menu = True
        if tag == "a" and self._in_suite_menu and "href" in values:
            self.suite_links.append(values["href"])
        if tag == "dl" and "facts" in classes:
            self.has_facts = True
        if tag == "ul" and "rows" in classes:
            self.has_rows = True
        if tag == "span" and "badge" in classes:
            self._in_badge_cls = values.get("class", "")
            self._badge_text = []
        if tag == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": values.get("method", "").lower(),
                "fields": {},
            }
        elif tag == "input" and self._current_form is not None:
            name = values.get("name", "")
            if name:
                fields = self._current_form["fields"]
                assert isinstance(fields, dict)
                fields[name] = values.get("value", "")

    def handle_data(self, data: str) -> None:
        if self._in_badge_cls is not None:
            self._badge_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        if tag == "span" and self._in_badge_cls is not None:
            self.badges.append((self._in_badge_cls, "".join(self._badge_text).strip()))
            self._in_badge_cls = None
            self._badge_text = []
        if tag == "div" and self._in_suite_menu:
            self._in_suite_menu = False


def test_app_stylesheet_reuses_shared_tokens_and_drops_custom_topbar():
    assert ":root{" not in CONNECTIONS_STYLE
    assert ".nc-topbar" not in CONNECTIONS_STYLE
    assert ".nc-pill" not in CONNECTIONS_STYLE
    assert ".nc-overview" not in CONNECTIONS_STYLE


def test_suite_switcher_and_endpoint_appear_only_when_configured(
    accounts, tmp_path, monkeypatch
):
    monkeypatch.delenv("SIGNIN_WINDOW_SUITE", raising=False)
    app_plain, _, _ = make_app(accounts, tmp_path / "plain", browser_url=HTTPS_ORIGIN)
    with TestClient(app_plain, base_url=HTTPS_ORIGIN) as client:
        browser_login(app_plain, client, "alice")
        resp = client.get("/connections/")
        assert resp.status_code == 200
        plain = _PageInspector(resp.text)
        assert plain.has_hero
        assert not plain.has_suite_switch
        assert not plain.has_endpoint

    monkeypatch.setenv("SIGNIN_WINDOW_SUITE", SUITE_JSON)
    app_suite, _, _ = make_app(accounts, tmp_path / "suite", browser_url=HTTPS_ORIGIN)
    with TestClient(app_suite, base_url=HTTPS_ORIGIN) as client:
        browser_login(app_suite, client, "alice")
        resp = client.get("/connections/")
        assert resp.status_code == 200
        with_suite = _PageInspector(resp.text)
        assert with_suite.has_hero
        assert with_suite.has_suite_switch
        assert with_suite.has_endpoint
        assert "https://household.example.com/" in with_suite.suite_links
        assert "https://shop.example.com/" in with_suite.suite_links
        assert "https://tools.example.com/all/mcp" in resp.text

        # Unmapped user 403 page shows neither the switcher nor the assistant address.
        browser_login(app_suite, client, "unregistered")
        denied = client.get("/connections/")
        assert denied.status_code == 403
        denied_view = _PageInspector(denied.text)
        assert not denied_view.has_suite_switch
        assert not denied_view.has_endpoint
        assert "/all/mcp" not in denied.text
        assert any(cls == "badge bad" for cls, _ in denied_view.badges)
        assert any(
            form["action"] == "/connections/logout" and form["method"] == "post"
            for form in denied_view.forms
        )


def test_reworked_states_emit_expected_badge_tones_forms_and_kit_structure(
    accounts, tmp_path
):
    app, _, _ = make_app(accounts, tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        browser_login(app, client, "alice")
        portal = app.state.connections
        service = portal.adapters["alice"]._service_ready()
        service._wall_clock = lambda: NOW
        selected = store(portal.controls["alice"].root.parent)
        service._sessions = selected
        outcomes = KeeperOutcomeStore(portal.controls["alice"].root.parent)
        service._keeper_outcomes = outcomes

        # 1. Not connected -> neutral badge, Connect form with exact fields, logout form
        not_conn = _PageInspector(client.get("/connections/").text)
        assert not_conn.has_hero
        assert any(
            cls == "badge" and text == "Not connected" for cls, text in not_conn.badges
        )
        assert any(
            f["action"] == "/connections/start"
            and f["method"] == "post"
            and f["fields"] == {"provider": "fixture"}
            for f in not_conn.forms
        )
        assert any(
            f["action"] == "/connections/logout" and f["method"] == "post"
            for f in not_conn.forms
        )

        # 2. Connected & Working -> ok badge, facts, rows, check & disconnect forms
        candidate, proof = material()
        selected.promote_browser_session(candidate, proof, expected_generation=None)
        revision = portal.controls["alice"].status("fixture")["revision"]
        working = _PageInspector(client.get("/connections/").text)
        assert working.has_facts
        assert working.has_rows
        assert any(
            cls == "badge ok" and text == "Working" for cls, text in working.badges
        )
        assert any(
            f["action"] == "/connections/check"
            and f["method"] == "post"
            and f["fields"] == {"provider": "fixture"}
            for f in working.forms
        )
        assert any(
            f["action"] == "/connections/check-all" and f["method"] == "post"
            for f in working.forms
        )
        assert any(
            f["action"] == "/connections/disconnect"
            and f["method"] == "post"
            and f["fields"] == {"provider": "fixture", "revision": revision}
            for f in working.forms
        )

        # 3. Stale -> warn badge
        stale_artifact = candidate.model_copy(
            update={"verified_at": NOW - timedelta(hours=24)}
        )
        selected._write(
            "fixture",
            "default",
            StoredSession(status=SessionStatus.VERIFIED, artifact=stale_artifact),
        )
        stale = _PageInspector(client.get("/connections/").text)
        assert any(
            cls == "badge warn" and text == "Needs check" for cls, text in stale.badges
        )

        # 4. Degraded -> bad badge
        outcomes._write(
            KeeperOutcome(
                provider="fixture",
                action="renewal_failed",
                reason_code="paid_probe_failed",
                recorded_at=NOW,
                consecutive_renewal_failures=3,
                max_age_hours=12.0,
            )
        )
        degraded = _PageInspector(client.get("/connections/").text)
        assert any(
            cls == "badge bad" and text == "Degraded" for cls, text in degraded.badges
        )

        # 5. Operator action -> bad badge
        selected._write(
            "fixture",
            "default",
            StoredSession(
                status=SessionStatus.OPERATOR_ACTION,
                last_failure=TerminalFailure.CREDENTIAL_REJECTED,
                failure_reason_code="credential_rejected",
            ),
        )
        action_needed = _PageInspector(client.get("/connections/").text)
        assert any(
            cls == "badge bad" and text == "Action needed"
            for cls, text in action_needed.badges
        )

        # 6. Connecting -> info pulsing badge + Cancel form with revision
        owner_connection(client)
        conn_rev = portal.controls["alice"].status("fixture")["revision"]
        connecting = _PageInspector(client.get("/connections/").text)
        assert any(
            "badge" in cls and "info" in cls and text == "Sign-in open"
            for cls, text in connecting.badges
        )
        assert any(
            f["action"] == "/connections/cancel"
            and f["method"] == "post"
            and f["fields"] == {"provider": "fixture", "revision": conn_rev}
            for f in connecting.forms
        )


def test_error_pages_render_kit_card_and_pass_suite(accounts, tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNIN_WINDOW_SUITE", SUITE_JSON)
    app, _, _ = make_app(accounts, tmp_path, browser_url=HTTPS_ORIGIN)
    origin = {"origin": HTTPS_ORIGIN}
    with TestClient(app, base_url=HTTPS_ORIGIN) as client:
        browser_login(app, client, "alice")
        portal = app.state.connections

        # 409 sharing conflict page
        conflict = client.post(
            "/connections/choose",
            data={
                "provider": "fixture",
                "owner": "alice",
                "selection_revision": "0" * 32,
                "grant": "own",
            },
            headers=origin,
        )
        assert conflict.status_code == 409
        conflict_view = _PageInspector(conflict.text)
        assert conflict_view.has_suite_switch
        assert any(cls == "badge warn" for cls, _ in conflict_view.badges)

        # 429 rate-limited page
        portal.relays["alice"].links_per_hour = 0
        limited = client.post(
            "/connections/start",
            data={"provider": "fixture"},
            headers=origin,
        )
        assert limited.status_code == 429
        limited_view = _PageInspector(limited.text)
        assert limited_view.has_suite_switch
        assert any(cls == "badge warn" for cls, _ in limited_view.badges)


def test_account_controlled_text_is_escaped(accounts, tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNIN_WINDOW_SUITE", SUITE_JSON)
    app, _, _ = make_app(accounts, tmp_path, browser_url=HTTPS_ORIGIN)
    with TestClient(app, base_url=HTTPS_ORIGIN) as client:
        browser_login(app, client, "alice")
        portal = app.state.connections
        orig_identity = portal.auth.identity

        def malicious_identity(request):
            data = orig_identity(request)
            if data is None:
                return None
            return {
                **data,
                "name": '<script>alert("xss")</script>',
                "label": "<img src=x onerror=alert(1)>",
            }

        monkeypatch.setattr(portal.auth, "identity", malicious_identity)
        resp = client.get("/connections/")
        assert resp.status_code == 200
        assert "<script>alert(" not in resp.text
        assert "<img src=x" not in resp.text
        assert "&lt;img src=x onerror=alert(1)&gt;" in resp.text


def test_reserved_relay_honours_library_reservations():
    from newsclip.connections import _ReservedRelay

    relay = _ReservedRelay(object(), "https://news.example.com/w", max_links=1)
    reservation = relay.reserve("ft")
    link = relay.create("ft", reservation=reservation)
    assert link.key == "ft"
    assert relay._reserved_slots == 0
    with pytest.raises(ValueError):
        relay.create("ft", reservation=relay.reserve("wsj"), reserved=True)
