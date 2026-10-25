"""Synthetic standalone accounts shared by interface tests."""

import pytest

from newsclip.tenancy import add_user


@pytest.fixture
def accounts(tmp_path):
    registry = tmp_path / "users.json"
    tokens = {}
    for user in ("alice", "bob"):
        token_file = tmp_path / f"{user}.token"
        add_user(registry, user, token_file)
        tokens[user] = token_file.read_text().strip()
    return registry, tokens
