"""Synthetic standalone accounts shared by interface tests."""

import json

import pytest

from newsclip.tenancy import add_user


@pytest.fixture
def accounts(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    registry = tmp_path / "users.json"
    tokens = {}
    for user in ("alice", "bob"):
        token_file = tmp_path / f"{user}.token"
        add_user(registry, user, token_file)
        tokens[user] = token_file.read_text().strip()
    return registry, tokens


@pytest.fixture(autouse=True)
def synthetic_maintenance_config(tmp_path_factory, monkeypatch):
    # Tests must never resolve the developer's account configuration.
    root = tmp_path_factory.mktemp("synthetic-maintenance")
    (root / "maintenance.json").write_text(
        json.dumps(
            {
                "version": 1,
                "providers": {
                    key: {"credential_reference": f"op://Example/{key}"}
                    for key in ("ft", "wsj", "bloomberg", "economist", "nyt")
                }
                | {
                    "guardian": {
                        "api_key_reference": "op://Example/Guardian/credential"
                    }
                },
            }
        )
    )
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(root))
