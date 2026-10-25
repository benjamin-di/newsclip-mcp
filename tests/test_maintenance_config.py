"""Credential configuration must follow the selected account, including caches."""

import json

import pytest

from newsclip.provider_config import load_provider_spec
from newsclip.tenancy import user_scope


def test_provider_references_never_cross_account_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(tmp_path))
    for user in ("alice", "bob"):
        root = tmp_path / "users" / user
        root.mkdir(parents=True)
        (root / "maintenance.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "providers": {
                        "ft": {"credential_reference": f"op://Example/{user}"}
                    },
                }
            )
        )
    for user in ("alice", "bob", "alice", "other"):
        with user_scope(user):
            spec = load_provider_spec("ft")
            assert spec.session.secret_ref == (
                f"op://Example/{user}" if user != "other" else ""
            )
    assert load_provider_spec("ft").session.secret_ref == ""


def test_invalid_configuration_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(tmp_path))
    path = tmp_path / "maintenance.json"
    path.write_text('{"version":2,"providers":{}}')
    with pytest.raises(ValueError):
        load_provider_spec("ft")
