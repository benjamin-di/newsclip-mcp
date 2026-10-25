from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from newsclip.login import LoginInfrastructureError, OpSecretFiller
from newsclip.timing import (
    StepFinishedEvent,
    TimingOperation,
    TimingRecorder,
    TimingStep,
    TimingTransport,
    read_timing_file,
    timing_step,
)


class FakeBrowser:
    def __init__(self, url: str) -> None:
        self.url = url
        self.fills: list[tuple[tuple[str, ...], str]] = []
        self.matches: list[tuple[tuple[str, ...], str, tuple[str, ...]]] = []

    @property
    def current_url(self) -> str:
        return self.url

    def fill(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        allowed_origins: frozenset[str] | None = None,
    ) -> None:
        assert allowed_origins is not None
        assert self.url.startswith(tuple(f"{origin}/" for origin in allowed_origins))
        self.fills.append((selectors, value))

    def click_matching_text(
        self,
        selectors: tuple[str, ...],
        value: str,
        *,
        excluded_text: tuple[str, ...],
        allowed_origins: frozenset[str] | None = None,
    ) -> bool:
        assert allowed_origins is not None
        assert self.url.startswith(tuple(f"{origin}/" for origin in allowed_origins))
        self.matches.append((selectors, value, excluded_text))
        return True


def test_secret_fill_checks_origin_before_invoking_op(monkeypatch) -> None:
    browser = FakeBrowser("https://evil.test/login")
    calls: list[object] = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, "SECRET_SENTINEL\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    with pytest.raises(LoginInfrastructureError, match="origin"):
        filler.fill(
            browser,
            secret_ref="op://fixture/item",
            field="username",
            selectors=("input[name='email']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )

    assert calls == []
    assert browser.fills == []


def test_secret_fill_rechecks_origin_after_resolution(monkeypatch) -> None:
    browser = FakeBrowser("https://accounts.ft.com/login")
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    def change_origin(**kwargs) -> str:  # noqa: ARG001
        browser.url = "https://evil.test/login"
        return "SECRET_SENTINEL"

    monkeypatch.setattr(filler, "_read", change_origin)

    with pytest.raises(LoginInfrastructureError, match="origin"):
        filler.fill(
            browser,
            secret_ref="op://fixture/item",
            field="password",
            selectors=("input[name='password']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )

    assert browser.fills == []


def test_secret_fill_allows_same_origin_transition_during_resolution(
    monkeypatch,
) -> None:
    browser = FakeBrowser("https://accounts.ft.com/login")
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    def change_path(**kwargs) -> str:  # noqa: ARG001
        browser.url = "https://accounts.ft.com/password"
        return "SECRET_SENTINEL"

    monkeypatch.setattr(filler, "_read", change_path)

    filler.fill(
        browser,
        secret_ref="op://fixture/item",
        field="password",
        selectors=("input[name='password']",),
        allowed_origins=frozenset({"https://accounts.ft.com"}),
    )

    assert browser.fills == [(("input[name='password']",), "SECRET_SENTINEL")]


def test_secret_fill_uses_argv_no_shell_and_minimal_environment(monkeypatch) -> None:
    browser = FakeBrowser("https://accounts.ft.com/login")
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "SECRET_SENTINEL\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    filler.fill(
        browser,
        secret_ref="op://fixture/item",
        field="password",
        selectors=("input[name='password']",),
        allowed_origins=frozenset({"https://accounts.ft.com"}),
    )

    assert captured["args"] == ["op", "inject"]
    assert captured["shell"] is False
    assert captured["check"] is True
    assert captured["capture_output"] is True
    assert captured["text"] is True
    assert captured["timeout"] == 30
    assert captured["input"] == "{{ op://fixture/item/password }}\n"
    assert set(captured["env"]) == {"OP_SERVICE_ACCOUNT_TOKEN", "PATH"}
    assert captured["env"]["OP_SERVICE_ACCOUNT_TOKEN"] == "TOKEN_SENTINEL"
    assert browser.fills == [(("input[name='password']",), "SECRET_SENTINEL")]
    assert "SECRET_SENTINEL" not in repr(captured["args"])
    assert "op://fixture/item" not in repr(captured["args"])


def test_secret_fill_times_resolution_and_browser_application_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = FakeBrowser("https://accounts.ft.com/login")
    monkeypatch.setattr(
        "newsclip.secret_reference.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, "SECRET_SENTINEL\n", ""
        ),
    )
    recorder = TimingRecorder(tmp_path / "timings")

    with (
        recorder.operation(
            TimingOperation.LOGIN,
            provider="ft",
            transport=TimingTransport.BROWSER,
        ) as operation,
        timing_step(TimingStep.PASSWORD, provider="ft"),
    ):
        OpSecretFiller(service_account_token="TOKEN_SENTINEL").fill(
            browser,
            secret_ref="op://fixture/item",
            field="password",
            selectors=("input[name='password']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )

    assert operation.path is not None
    run = read_timing_file(operation.path)
    finished = [
        event.step
        for record in run.records
        if isinstance((event := record.event), StepFinishedEvent)
    ]
    assert finished == [
        TimingStep.SECRET_RESOLVE,
        TimingStep.CREDENTIAL_APPLY,
        TimingStep.PASSWORD,
    ]


def test_logical_totp_uses_one_password_generated_otp_field(monkeypatch) -> None:
    browser = FakeBrowser("https://accounts.google.com/signin")
    captured: dict[str, Any] = {}

    def fake_run(args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "123456\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)

    OpSecretFiller(service_account_token="TOKEN_SENTINEL").fill(
        browser,
        secret_ref="op://fixture/item",
        field="totp",
        selectors=("input[autocomplete='one-time-code']",),
        allowed_origins=frozenset({"https://accounts.google.com"}),
    )

    assert captured["input"] == (
        "{{ op://fixture/item/one-time password?attribute=otp }}\n"
    )
    assert browser.fills == [(("input[autocomplete='one-time-code']",), "123456")]


@pytest.mark.parametrize(
    "resolved_value",
    (
        "otpauth://totp/example?secret=NOT_A_CODE",
        "one-time password",
        "12345",
        "123456789",
    ),
)
def test_totp_uri_or_invalid_value_is_never_sent_to_browser(
    monkeypatch, resolved_value: str
) -> None:
    browser = FakeBrowser("https://accounts.google.com/signin")

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, f"{resolved_value}\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fake_run)

    with pytest.raises(LoginInfrastructureError, match="generated one-time code"):
        OpSecretFiller(service_account_token="TOKEN_SENTINEL").fill(
            browser,
            secret_ref="op://fixture/item",
            field="totp",
            selectors=("input[autocomplete='one-time-code']",),
            allowed_origins=frozenset({"https://accounts.google.com"}),
        )

    assert browser.fills == []


def test_failed_secret_delivery_never_uses_another_identity(monkeypatch) -> None:
    browser = FakeBrowser("https://accounts.google.com/signin")
    calls = []

    def failed(args, **kwargs):
        calls.append(kwargs["env"]["OP_SERVICE_ACCOUNT_TOKEN"])
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", failed)
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")
    with pytest.raises(LoginInfrastructureError, match="field resolution failed"):
        filler.fill(
            browser,
            secret_ref="op://Example/Item",
            field="username",
            selectors=("input[name='identifier']",),
            allowed_origins=frozenset({"https://accounts.google.com"}),
        )
    assert calls == ["TOKEN_SENTINEL"]
    assert browser.fills == []


@pytest.mark.parametrize("timeout", (0, -1, float("inf"), float("nan")))
def test_secret_fill_requires_a_finite_positive_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        OpSecretFiller(
            service_account_token="TOKEN_SENTINEL",
            read_timeout_seconds=timeout,
        )


@pytest.mark.parametrize(
    ("secret_ref", "field"),
    (
        ("vault/item", "password"),
        ("op://fixture/{{ item }}", "password"),
        ("op://fixture/item\nother", "password"),
        ("op://fixture/item", "recovery"),
    ),
)
def test_secret_fill_rejects_unclosed_references_before_subprocess(
    monkeypatch, secret_ref: str, field: str
) -> None:
    monkeypatch.setattr(
        "newsclip.secret_reference.subprocess.run",
        lambda *args, **kwargs: pytest.fail("subprocess must not run"),
    )

    with pytest.raises(LoginInfrastructureError, match="reference"):
        OpSecretFiller(service_account_token="TOKEN_SENTINEL").fill(
            FakeBrowser("https://accounts.ft.com/login"),
            secret_ref=secret_ref,
            field=field,  # type: ignore[arg-type]
            selectors=("input[type='password']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )


def test_cached_account_match_resolves_secret_jit_without_returning_it(
    monkeypatch,
) -> None:
    browser = FakeBrowser("https://accounts.google.com/signin")
    monkeypatch.setattr(
        "newsclip.secret_reference.subprocess.run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, "ACCOUNT_SENTINEL\n", ""
        ),
    )
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    matched = filler.click_matching_choice(
        browser,
        secret_ref="op://fixture/item",
        field="username",
        selectors=("div[data-identifier]",),
        excluded_text=("signed out",),
        allowed_origins=frozenset({"https://accounts.google.com"}),
    )

    assert matched is True
    assert browser.matches == [
        (("div[data-identifier]",), "ACCOUNT_SENTINEL", ("signed out",))
    ]


def test_cached_account_match_rechecks_origin_after_resolution(monkeypatch) -> None:
    browser = FakeBrowser("https://accounts.google.com/signin")
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    def change_origin(**kwargs) -> str:  # noqa: ARG001
        browser.url = "https://evil.test/signin"
        return "ACCOUNT_SENTINEL"

    monkeypatch.setattr(filler, "_read", change_origin)

    with pytest.raises(LoginInfrastructureError, match="origin"):
        filler.click_matching_choice(
            browser,
            secret_ref="op://fixture/item",
            field="username",
            selectors=("div[data-identifier]",),
            excluded_text=("signed out",),
            allowed_origins=frozenset({"https://accounts.google.com"}),
        )

    assert browser.matches == []


def test_cached_account_waits_for_hydrated_choice_before_reading_secret(
    monkeypatch,
) -> None:
    class HydratingBrowser(FakeBrowser):
        def __init__(self) -> None:
            super().__init__("https://accounts.google.com/signin")
            self.waits: list[tuple[tuple[str, ...], float]] = []

        def wait_for_visible(
            self,
            selectors: tuple[str, ...],
            *,
            timeout_seconds: float,
        ) -> bool:
            self.waits.append((selectors, timeout_seconds))
            return True

    calls = 0

    def resolve(args, **kwargs):  # noqa: ANN001
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(args, 0, "ACCOUNT_SENTINEL\n", "")

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", resolve)
    browser = HydratingBrowser()

    matched = OpSecretFiller(
        service_account_token="TOKEN_SENTINEL"
    ).click_matching_choice(
        browser,
        secret_ref="op://fixture/item",
        field="username",
        selectors=("div[data-identifier]",),
        excluded_text=("signed out",),
        allowed_origins=frozenset({"https://accounts.google.com"}),
    )

    assert matched is True
    assert browser.waits == [(("div[data-identifier]",), 10)]
    assert calls == 1


@pytest.mark.parametrize(
    "url",
    (
        "https://accounts.ft.com.evil.test/login",
        "https://user@accounts.ft.com/login",
        "https://accounts.ft.com:invalid/login",
        "https://[invalid/login",
        "javascript:alert(1)",
    ),
)
def test_secret_delivery_rejects_lookalike_or_unsafe_origins(url: str) -> None:
    filler = OpSecretFiller(service_account_token="TOKEN_SENTINEL")

    with pytest.raises(LoginInfrastructureError, match="origin"):
        filler.fill(
            FakeBrowser(url),
            secret_ref="op://fixture/item",
            field="password",
            selectors=("input[type='password']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )


def test_secret_delivery_maps_vault_failures_without_exposing_output(
    monkeypatch,
) -> None:
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(
            1, args[0], output="SECRET_SENTINEL", stderr="PRIVATE_SENTINEL"
        )

    monkeypatch.setattr("newsclip.secret_reference.subprocess.run", fail)

    with pytest.raises(LoginInfrastructureError) as caught:
        OpSecretFiller(service_account_token="TOKEN_SENTINEL").fill(
            FakeBrowser("https://accounts.ft.com/login"),
            secret_ref="op://fixture/item",
            field="password",
            selectors=("input[type='password']",),
            allowed_origins=frozenset({"https://accounts.ft.com"}),
        )

    assert "SECRET_SENTINEL" not in str(caught.value)
    assert "PRIVATE_SENTINEL" not in str(caught.value)
