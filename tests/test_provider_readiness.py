"""Inert checks for provider login prerequisites."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from newsclip.provider_readiness import browser_engine_available


class _PlaywrightContext:
    def __init__(self, executable: str) -> None:
        self._executable = executable

    def __enter__(self) -> SimpleNamespace:
        chromium = SimpleNamespace(executable_path=self._executable)
        return SimpleNamespace(chromium=chromium)

    def __exit__(self, *_args: object) -> None:
        return None


def test_browser_engine_requires_an_executable_file(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "chromium"
    executable.touch(mode=0o700)
    monkeypatch.setattr(
        "newsclip.provider_readiness.sync_playwright",
        lambda: _PlaywrightContext(str(executable)),
    )

    assert browser_engine_available()

    executable.chmod(0o600)

    assert not browser_engine_available()


def test_browser_engine_unavailable_when_patchright_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail() -> None:
        raise RuntimeError("fixture driver failure")

    monkeypatch.setattr("newsclip.provider_readiness.sync_playwright", fail)

    assert not browser_engine_available()


def test_bloomberg_reports_missing_native_input(monkeypatch) -> None:
    """PerimeterX rejects debug-protocol input, so a host without the XTEST
    library cannot mint Bloomberg — and must say so rather than letting the
    click silently fail to register."""

    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement
    from newsclip.providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS

    monkeypatch.setattr(readiness, "native_input_available", lambda: False)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "token")
    probe = BUILTIN_PROVIDER_REGISTRATIONS["bloomberg"].check_credential_readiness
    assert probe is not None
    assert LoginRequirement.NATIVE_INPUT in probe().missing

    monkeypatch.setattr(readiness, "native_input_available", lambda: True)
    assert LoginRequirement.NATIVE_INPUT not in probe().missing


def test_providers_without_the_requirement_ignore_native_input(monkeypatch) -> None:
    """FT and NYT mint without PerimeterX-grade input; they must not be
    blocked by a library they do not need."""

    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement
    from newsclip.providers.builtins import BUILTIN_PROVIDER_REGISTRATIONS

    monkeypatch.setattr(readiness, "native_input_available", lambda: False)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "token")
    for provider in ("wsj", "nyt", "economist"):
        probe = BUILTIN_PROVIDER_REGISTRATIONS[provider].check_credential_readiness
        assert probe is not None
        assert LoginRequirement.NATIVE_INPUT not in probe().missing


@pytest.mark.parametrize("provider", ["codex", "claude"])
@pytest.mark.parametrize("logged_in", [True, False])
def test_vision_readiness_checks_local_auth_in_the_solver_environment(
    monkeypatch, provider, logged_in
):
    import subprocess

    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement

    calls = []
    monkeypatch.delenv("NEWSCLIP_AGENT_RUN_HOST", raising=False)
    monkeypatch.setenv("AGENT_PROVIDER", provider)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-secret")
    monkeypatch.setattr(readiness, "which", lambda _: "/fixture/bin")

    def status(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0 if logged_in else 1,
            stdout=b'{"loggedIn": true}' if logged_in else b'{"loggedIn": false}',
        )

    monkeypatch.setattr(readiness.subprocess, "run", status)
    result = readiness.check_credential_readiness("ft", require_vision=True)
    assert (LoginRequirement.VISION_AUTH in result.missing) is not logged_in
    command, options = calls[0]
    assert command == (
        [provider, "login", "status"]
        if provider == "codex"
        else [provider, "auth", "status", "--json"]
    )
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in options["env"]
    assert options["timeout"] == 5
    assert options["stdin"] == subprocess.DEVNULL


def test_vision_auth_unknown_and_malformed_status_fail_closed(monkeypatch):
    import subprocess

    import newsclip.credential_readiness as readiness

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("fixture", 5)

    monkeypatch.setattr(readiness.subprocess, "run", timeout)
    assert not readiness.vision_auth_available("codex")
    monkeypatch.setattr(
        readiness.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a, 0, stdout=b'{"loggedIn": false}'
        ),
    )
    assert not readiness.vision_auth_available("claude")


def test_explicit_vision_provider_preflights_the_image_challenge_solver(monkeypatch):
    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement

    monkeypatch.setenv("AGENT_PROVIDER", "codex")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-provider-authority")
    monkeypatch.setattr(readiness, "which", lambda _: "/fixture/bin")
    checked = []
    monkeypatch.setattr(
        readiness,
        "vision_auth_available",
        lambda provider: checked.append(provider) or False,
    )
    result = readiness.check_credential_readiness(
        "image_challenge",
        require_vision=True,
        vision_provider="claude",
    )
    assert checked == ["claude"]
    assert result.missing == (LoginRequirement.VISION_AUTH,)


def test_external_planner_needs_no_local_cli(monkeypatch) -> None:
    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement

    monkeypatch.setenv("NEWSCLIP_VISION_PLANNER", "example_backend:build_planner")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-secret")
    monkeypatch.setattr(
        readiness, "which", lambda name: "/fixture/bin" if name == "op" else None
    )

    def no_cli(*args, **kwargs):
        raise AssertionError("no local CLI is asked when external runner plans")

    monkeypatch.setattr(readiness.subprocess, "run", no_cli)

    result = readiness.check_credential_readiness("ft", require_vision=True)

    assert result.missing == ()

    monkeypatch.delenv("NEWSCLIP_VISION_PLANNER")
    result = readiness.check_credential_readiness("ft", require_vision=True)

    assert result.missing == (LoginRequirement.VISION_CLI,)


def test_a_connect_identity_satisfies_the_op_service_requirement(monkeypatch) -> None:
    """Connect is a reader identity without a service-account token."""

    import newsclip.credential_readiness as readiness
    from newsclip.models import LoginRequirement

    monkeypatch.delenv("NEWSCLIP_CREDENTIAL_READER", raising=False)
    monkeypatch.setattr(readiness, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
    assert (
        LoginRequirement.OP_SERVICE_TOKEN
        in readiness.check_credential_readiness("ft").missing
    )
    monkeypatch.setenv("OP_CONNECT_HOST", "http://connect.example.com:8080")
    monkeypatch.setenv("OP_CONNECT_TOKEN", "synthetic-connect")
    assert (
        LoginRequirement.OP_SERVICE_TOKEN
        not in readiness.check_credential_readiness("ft").missing
    )
