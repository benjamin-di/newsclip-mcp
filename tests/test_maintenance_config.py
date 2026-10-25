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


def test_custom_credential_backend_accepts_opaque_reference_without_op(
    tmp_path, monkeypatch
):
    import sys
    from types import ModuleType

    from signin_window.automation.secret_filler import CredentialFiller
    from signin_window.automation.secrets import SecretResolutionError

    from newsclip.credential_readiness import check_credential_readiness
    from newsclip.login import credential_filler

    class Reader:
        available = True

        def read_field(self, *args, **kwargs):
            pytest.fail("availability must not resolve a credential")

    module = ModuleType("example_backend")
    module.create = Reader
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("NEWSCLIP_CREDENTIAL_READER", "example_backend:create")
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(tmp_path))
    (tmp_path / "maintenance.json").write_text(
        json.dumps(
            {
                "version": 1,
                "providers": {"ft": {"credential_reference": "example:account"}},
            }
        )
    )
    assert load_provider_spec("ft").session.secret_ref == "example:account"
    assert check_credential_readiness("ft").missing == ()
    assert isinstance(credential_filler(), CredentialFiller)
    monkeypatch.setenv("NEWSCLIP_CREDENTIAL_READER", "absent_backend:create")
    assert any(
        x.value == "credential_reader" for x in check_credential_readiness("ft").missing
    )
    with pytest.raises(SecretResolutionError):
        credential_filler()
