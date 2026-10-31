"""Hosted reads and continuation authority use the captured owner, never archives."""

import pytest
from starlette.testclient import TestClient
from test_mcp import FULL_URL, FakeHttp, FakeProvider, _service
from test_standalone import browser_login, make_app

from newsclip.errors import SessionRequiredError
from newsclip.models import ProviderCapabilities, SearchFilters
from newsclip.results import public_error
from newsclip.subscription_access import SubscriptionAccess
from newsclip.subscription_routing import SubscriptionRouting


class Paid(FakeProvider):
    login_recipe = object()
    capabilities = ProviderCapabilities(requires_session_for_retrieve=False)


def test_reads_and_pager_use_selected_owner_but_keep_private_archive(
    accounts, tmp_path
):
    access = SubscriptionAccess(tmp_path / "sharing", accounts[0])
    access.bootstrap(("fixture",))
    services = {name: _service(tmp_path / name, Paid()) for name in ("alice", "bob")}
    targets = []

    def reader_factory(*, requester, owner, budget_owner):
        assert requester == "bob" and owner == "alice"
        reader = _service(tmp_path / "bob", Paid())

        # Distinct transport proves selection without a local fallback.
        class Http(FakeHttp):
            def get(self, *args, **kwargs):
                targets.append(owner)
                return super().get(*args, **kwargs)

        reader._http = Http()
        return reader

    routing = SubscriptionRouting(
        "bob",
        services["bob"],
        access,
        services.__getitem__,
        reader_factory=reader_factory,
    )
    services["bob"]._subscription_routing = routing
    try:
        access.share("alice", "fixture", "bob", None)
        row, offers, _ = access.view("bob", "fixture")
        access.choose("bob", "fixture", "alice", row["revision"], dict(offers)["alice"])
        article = services["bob"].save(FULL_URL)
        assert targets == ["alice"]
        assert services["bob"].archive_get(article.id).id == article.id
        assert services["alice"].archive_search("Fixture") == []
        pager = services["bob"].search_pager("Fixture", SearchFilters(limit=1))
        assert pager._readers["fixture"] is routing.reader("fixture")
        assert pager.next_batch(1).results
        grant = access.view("alice", "fixture")[0]["grants"]["bob"]
        access.revoke("alice", "fixture", "bob", grant)
        with pytest.raises(SessionRequiredError, match="shared_access_removed"):
            services["bob"].get(FULL_URL)
        with pytest.raises(SessionRequiredError, match="shared_access_removed"):
            pager.next_batch(1)
        assert services["bob"].archive_get(article.id).id == article.id
    finally:
        routing.close()
        for service in services.values():
            service.close()


def test_management_forms_require_browser_identity_origin_and_own_authority(
    accounts, tmp_path
):
    app, tokens, _ = make_app(accounts, tmp_path)
    access = app.state.connections.access
    access.share("alice", "fixture", "bob", None)
    with TestClient(app, base_url="http://127.0.0.1") as browser:
        row, offers, _ = access.view("bob", "fixture")
        form = {
            "provider": "fixture",
            "owner": "alice",
            "selection_revision": row["revision"],
            "grant": dict(offers)["alice"],
        }
        bearer = {
            "authorization": "Bearer " + tokens["bob"],
            "origin": "http://127.0.0.1",
        }
        assert (
            browser.post("/connections/choose", data=form, headers=bearer).status_code
            == 401
        )
        browser_login(app, browser, "bob")
        page = browser.get("/connections/").text
        assert "Use this subscription" in page and "Shared with" in page
        assert (
            browser.post(
                "/connections/choose",
                data=form,
                headers={"origin": "https://attacker.example"},
            ).status_code
            == 403
        )
        good = {"origin": "http://127.0.0.1"}
        assert (
            browser.post(
                "/connections/choose", data=form, headers=good, follow_redirects=False
            ).status_code
            == 303
        )
        assert access.admit("bob", "fixture").owner == "alice"
        assert (
            browser.post(
                "/connections/choose", data=form, headers=good, follow_redirects=False
            ).status_code
            == 409
        )
        # Recipient cannot forge a disconnect or sharing action for the owner.
        assert (
            browser.post(
                "/connections/share",
                data={
                    "provider": "fixture",
                    "member": "alice",
                    "grant": "new",
                    "revision": "forged",
                },
                headers=good,
                follow_redirects=False,
            ).status_code
            == 409
        )
        assert (
            browser.post(
                "/connections/unshare",
                data={
                    "provider": "fixture",
                    "member": "bob",
                    "grant": form["grant"],
                },
                headers=good,
                follow_redirects=False,
            ).status_code
            == 409
        )
        assert (
            browser.post(
                "/connections/leave",
                data={
                    "provider": "fixture",
                    "owner": "alice",
                    "grant": form["grant"],
                },
                headers=good,
                follow_redirects=False,
            ).status_code
            == 303
        )
        with pytest.raises(SessionRequiredError, match="account_selection_needed"):
            access.admit("bob", "fixture")
        assert "No subscription selected" in browser.get("/connections/").text


@pytest.mark.parametrize(
    "reason", ["account_selection_needed", "shared_access_removed", "account_changed"]
)
def test_selection_errors_have_a_closed_action_to_open_connections(reason):
    result = public_error(SessionRequiredError(reason))
    assert result.reason == reason and result.action == "open_connections"
    assert reason in result.model_dump_json()


def test_corrupt_unrelated_record_preserves_healthy_page_controls(accounts, tmp_path):
    app, _tokens, _ = make_app(accounts, tmp_path)
    access = app.state.connections.access
    access.share("alice", "fixture", "bob", None)
    access.path("bob").write_text("synthetic damage")
    with TestClient(app, base_url="http://127.0.0.1") as browser:
        browser_login(app, browser, "alice")
        page = browser.get("/connections/")
        assert page.status_code == 200
        assert "Connect" in page.text and "Stop sharing" in page.text
        assert "Some shared offers are unavailable" in page.text


def test_each_decline_control_names_its_offer(accounts, tmp_path):
    from lxml import html

    from newsclip.connections import Connections
    from newsclip.tenancy import add_user

    add_user(accounts[0], "carol", tmp_path / "carol.token")
    access = SubscriptionAccess(tmp_path / "sharing", accounts[0])
    access.bootstrap(("fixture",))
    for owner in ("alice", "carol"):
        access.share(owner, "fixture", "bob", None)
    page = object.__new__(Connections)
    page.access, page.home = access, "/connections/"
    document = html.fromstring(
        page.sharing_body(
            "bob", "fixture", {"state": "needs_signin", "revision": "initial"}
        )
    )
    controls = document.xpath('//form[@action="/connections/leave"]')
    assert [" ".join(form.itertext()).strip() for form in controls] == [
        "Decline access from alice",
        "Decline access from carol",
    ]
