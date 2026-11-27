"""Lazy credential_filler() construction and fail-closed minting tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from signin_window.automation.secrets import SecretResolutionError

from newsclip.challenge_resolver import ChallengeResolver
from newsclip.composition import build_auth_service, build_service
from newsclip.providers.bloomberg_auth import BloombergAcquisitionAdapter
from newsclip.providers.economist_auth import EconomistAcquisitionAdapter
from newsclip.providers.ft_auth import FTAcquisitionAdapter
from newsclip.providers.nyt_auth import NYTAcquisitionAdapter
from newsclip.providers.wsj_auth import WSJAcquisitionAdapter


def _stub_recipe(provider: str):
    return SimpleNamespace(
        provider=provider,
        allowed_origins=frozenset({"https://accounts.google.com"}),
        secret_ref="op://fixture/item",
    )


def _broken_reader_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NEWSCLIP_CREDENTIAL_READER", "absent_backend:create")
    monkeypatch.setenv("NEWSCLIP_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("NEWSCLIP_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("NEWSCLIP_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)


def test_auth_adapters_construct_lazily_when_credential_reader_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _broken_reader_env(monkeypatch, tmp_path)
    resolver = ChallengeResolver({})

    ft = FTAcquisitionAdapter(
        recipe=_stub_recipe("ft"),  # type: ignore[arg-type]
        challenge_resolver=resolver,
    )
    wsj = WSJAcquisitionAdapter(
        recipe=_stub_recipe("wsj"),  # type: ignore[arg-type]
        challenge_resolver=resolver,
    )
    economist = EconomistAcquisitionAdapter(
        recipe=_stub_recipe("economist"),  # type: ignore[arg-type]
        challenge_resolver=resolver,
    )
    nyt = NYTAcquisitionAdapter(
        recipe=_stub_recipe("nyt"),  # type: ignore[arg-type]
        challenge_resolver=resolver,
    )
    bloomberg = BloombergAcquisitionAdapter(
        recipe=_stub_recipe("bloomberg"),  # type: ignore[arg-type]
        challenge_resolver=resolver,
    )

    def forbidden_op(*args, **kwargs):
        raise AssertionError("must not fall back to ambient 1Password")

    monkeypatch.setattr("subprocess.run", forbidden_op)

    for adapter in (ft, wsj, economist, nyt):
        with pytest.raises(SecretResolutionError):
            adapter._secret_filler()

    with pytest.raises(SecretResolutionError):
        bloomberg._google_identity._secrets.fill(
            None,  # type: ignore[arg-type]
            secret_ref="op://fixture/item",
            field="email",
            selectors=("input",),
            allowed_origins=frozenset({"https://accounts.google.com"}),
        )


def test_build_service_and_build_auth_service_survive_broken_credential_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _broken_reader_env(monkeypatch, tmp_path)

    service = build_service()
    auth_service = build_auth_service()

    assert service is not None
    assert auth_service is not None
