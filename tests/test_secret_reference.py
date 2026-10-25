"""Offline contracts for the browser-free op:// secret reader."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from newsclip.secret_reference import OpSecretReader, SecretResolutionError

REFERENCE = "op://Example/Item/credential"


def test_read_uses_argv_no_shell_and_minimal_environment(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "SECRET_SENTINEL\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)
    reader = OpSecretReader(service_account_token="TOKEN_SENTINEL")

    assert reader.read(REFERENCE) == "SECRET_SENTINEL"
    assert captured["args"] == ["op", "inject"]
    assert captured["shell"] is False
    assert captured["check"] is True
    assert captured["capture_output"] is True
    assert captured["text"] is True
    assert captured["timeout"] == 30
    assert captured["input"] == f"{{{{ {REFERENCE} }}}}\n"
    assert set(captured["env"]) == {"OP_SERVICE_ACCOUNT_TOKEN", "PATH"}
    assert captured["env"]["OP_SERVICE_ACCOUNT_TOKEN"] == "TOKEN_SENTINEL"


def test_read_rejects_invalid_references_without_subprocess(monkeypatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        "newsclip.secret_reference.subprocess.run",
        lambda *args, **kwargs: calls.append(args),
    )
    reader = OpSecretReader(service_account_token="TOKEN_SENTINEL")

    for reference in (
        "vault/item/credential",
        "op://vault/item/{{credential}}",
        "op://vault/item\ncredential",
    ):
        with pytest.raises(SecretResolutionError, match="invalid"):
            reader.read(reference)
    assert calls == []


def test_read_requires_a_service_token(monkeypatch) -> None:
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
    calls: list[object] = []
    monkeypatch.setattr(
        "newsclip.secret_reference.subprocess.run",
        lambda *args, **kwargs: calls.append(args),
    )

    with pytest.raises(SecretResolutionError, match="token is unavailable"):
        OpSecretReader().read(REFERENCE)
    assert calls == []


def test_read_reports_an_empty_field_without_bootstrapping(monkeypatch) -> None:
    calls: list[object] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)
    reader = OpSecretReader(service_account_token="TOKEN_SENTINEL")

    with pytest.raises(SecretResolutionError, match="field was empty"):
        reader.read(REFERENCE)
    assert len(calls) == 1


def test_read_failure_never_escalates_to_another_identity(monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append(kwargs)
        raise subprocess.CalledProcessError(returncode=1, cmd=args)

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)
    reader = OpSecretReader(service_account_token="TOKEN_SENTINEL")
    with pytest.raises(SecretResolutionError, match="field resolution failed"):
        reader.read(REFERENCE)
    assert len(calls) == 1
    assert calls[0]["env"]["OP_SERVICE_ACCOUNT_TOKEN"] == "TOKEN_SENTINEL"
    assert calls[0]["input"] == "{{ " + REFERENCE + " }}\n"


def test_reader_rejects_a_nonpositive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        OpSecretReader(service_account_token="T", read_timeout_seconds=0)
