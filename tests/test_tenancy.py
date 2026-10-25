import json
import os

import pytest
from signin_window.state import PrivateStateError

from newsclip.tenancy import add_proxy_user, add_user, load_users


def test_proxy_users_have_no_native_authentication_capability(tmp_path):
    registry = tmp_path / "users.json"
    for name in ("alice", "bob"):
        add_proxy_user(registry, name)
    users = load_users(registry)
    assert [user.id for user in users] == ["alice", "bob"]
    assert all(
        not user.accepts(value)
        for user in users
        for value in ("", "alice", "None", "synthetic-token")
    )
    assert json.loads(registry.read_text())["users"][0]["token_sha256"] is None
    assert registry.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="exists"):
        add_proxy_user(registry, "alice")
    # Enabling a native token is an explicit administrative action.
    token_file = tmp_path / "alice.token"
    add_user(registry, "alice", token_file, rotate=True)
    assert next(user for user in load_users(registry) if user.id == "alice").accepts(
        token_file.read_text().strip()
    )
    assert (
        next(user for user in load_users(registry) if user.id == "bob").token_sha256
        is None
    )


@pytest.mark.parametrize("kind", ["fifo", "symlink", "oversized"])
def test_registry_cannot_block_or_redirect_authentication(tmp_path, kind):
    path = tmp_path / "users.json"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        target = tmp_path / "other"
        target.write_text('{"version":1,"users":[]}')
        path.symlink_to(target)
    else:
        path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(PrivateStateError):
        load_users(path)
