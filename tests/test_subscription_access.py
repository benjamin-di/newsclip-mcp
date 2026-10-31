"""Durable sharing authority and crash behavior with synthetic users."""

import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress

import pytest

from newsclip.errors import PersistenceError, SessionRequiredError
from newsclip.subscription_access import SubscriptionAccess
from newsclip.tenancy import add_user


@pytest.fixture
def access(accounts, tmp_path):
    value = SubscriptionAccess(tmp_path / "state", accounts[0])
    value.bootstrap(("fixture", "other"))
    return value


def select(access, actor, owner, provider="fixture"):
    row, offers, _ = access.view(actor, provider)
    grant = dict(offers).get(owner)
    access.choose(actor, provider, owner, row["revision"], grant)


def test_explicit_choices_per_publisher_leave_and_regrant(access):
    own = access.admit("bob", "fixture")
    access.share("alice", "fixture", "bob", None)
    assert access.admit("bob", "fixture") == own
    select(access, "bob", "alice")
    chosen = access.admit("bob", "fixture")
    assert chosen.owner == "alice"
    assert access.admit("bob", "other").owner == "bob"
    grant = access.view("alice", "fixture")[0]["grants"]["bob"]
    access.revoke("alice", "fixture", "bob", grant)
    with pytest.raises(SessionRequiredError, match="shared_access_removed"):
        access.admit("bob", "fixture")
    access.share("alice", "fixture", "bob", None)
    with pytest.raises(SessionRequiredError, match="shared_access_removed"):
        access.admit("bob", "fixture")
    with pytest.raises(SessionRequiredError):
        access.revalidate(chosen)
    select(access, "bob", "alice")
    grant = access.view("alice", "fixture")[0]["grants"]["bob"]
    access.revoke("alice", "fixture", "bob", grant, leaving=True)
    with pytest.raises(SessionRequiredError, match="account_selection_needed"):
        access.admit("bob", "fixture")
    select(access, "bob", "bob")
    assert access.admit("bob", "fixture").selected.revision != own.selected.revision


def test_lost_adopted_controls_are_not_rebuilt(access):
    access.path("bob").unlink()
    access.bootstrap(("fixture", "other"))
    with pytest.raises(PersistenceError):
        access.admit("bob", "fixture")
    assert not access.path("bob").exists()
    assert access.admit("alice", "fixture").owner == "alice"
    # Loss of the entire directory retains the separate adoption evidence.
    for path in access.root.iterdir():
        path.unlink()
    access.root.rmdir()
    with pytest.raises(PersistenceError, match="cannot be adopted"):
        access.bootstrap(("fixture", "other"))


def test_corrupt_unrelated_record_keeps_healthy_choices_and_revoke(access):
    access.share("alice", "fixture", "bob", None)
    grant = access.view("alice", "fixture")[0]["grants"]["bob"]
    access.path("bob").write_text("damaged")
    row, offers, unavailable = access.view("alice", "fixture")
    assert row["grants"]["bob"] == grant and not offers and unavailable
    access.revoke("alice", "fixture", "bob", grant)
    assert access.admit("alice", "fixture").owner == "alice"


def test_revoke_commits_before_failed_leave_selection_write(access, monkeypatch):
    access.share("alice", "fixture", "bob", None)
    select(access, "bob", "alice")
    grant = access.view("alice", "fixture")[0]["grants"]["bob"]
    write = access._write

    def interrupted(actor, *args):
        if actor == "bob":
            raise OSError("synthetic interrupted write")
        return write(actor, *args)

    monkeypatch.setattr(access, "_write", interrupted)
    with pytest.raises(OSError):
        access.revoke("alice", "fixture", "bob", grant, leaving=True)
    restarted = SubscriptionAccess(access.parent, access.users_path)
    restarted.bootstrap(("fixture", "other"))
    with pytest.raises(SessionRequiredError, match="shared_access_removed"):
        restarted.admit("bob", "fixture")


def test_concurrent_choice_and_revoke_cannot_preserve_authority(access):
    for _ in range(12):
        select(access, "bob", "bob")
        access.share("alice", "fixture", "bob", None)
        grant = access.view("alice", "fixture")[0]["grants"]["bob"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            chosen = pool.submit(select, access, "bob", "alice")
            revoked = pool.submit(access.revoke, "alice", "fixture", "bob", grant)
            revoked.result()
            with suppress(SessionRequiredError):
                chosen.result()
        with suppress(SessionRequiredError):
            assert access.admit("bob", "fixture").owner == "bob"


def test_membership_and_stale_forms_remain_authoritative(access):
    access.share("alice", "fixture", "bob", None)
    row, offers, _ = access.view("bob", "fixture")
    grant = dict(offers)["alice"]
    select(access, "bob", "alice")
    with pytest.raises(SessionRequiredError, match="account_changed"):
        access.choose("bob", "fixture", "bob", row["revision"], None)
    registry = json.loads(access.users_path.read_text())
    registry["users"] = [user for user in registry["users"] if user["id"] != "alice"]
    access.users_path.write_text(json.dumps(registry))
    with pytest.raises(SessionRequiredError, match="registered"):
        access.admit("bob", "fixture")
    # Recipients can still leave when an owner's application membership is removed.
    access.revoke("alice", "fixture", "bob", grant, leaving=True)


def test_new_user_gets_empty_grants_without_touching_enrolled_state(access, tmp_path):
    before = access.path("alice").read_bytes()
    add_user(access.users_path, "carol", tmp_path / "carol.token")
    access.bootstrap(("fixture", "other"))
    assert access.path("alice").read_bytes() == before
    assert access.admit("carol", "fixture").owner == "carol"
    assert access.view("carol", "fixture")[0]["grants"] == {}


def test_missing_provider_record_fails_instead_of_selecting_own(access):
    data = json.loads(access.path("bob").read_text())
    del data["providers"]["fixture"]
    access.path("bob").write_text(json.dumps(data))
    with pytest.raises(PersistenceError):
        access.admit("bob", "fixture")
