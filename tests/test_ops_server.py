"""The ops MCP surface: fail-closed gating, async heal, CLI adaptation.

The ops surface: every repair verb is one authenticated tool call, the
flag without its dedicated bearer refuses to serve, and heal
returns immediately because a mint outlives gateway timeouts.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time

import pytest
from mcp_wire import call_tool, list_tools

from newsclip.ops_server import (
    OPS_TOOLS,
    CommandOutcome,
    OpsAdapter,
    _require_ops_environment,
    _run_cli,
)

# --- fail-closed gating (no mcp extra needed) -------------------------------


def test_ops_flag_without_dedicated_bearer_refuses(monkeypatch) -> None:
    monkeypatch.delenv("NEWSCLIP_OPS_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops-op-token")
    with pytest.raises(ValueError, match="dedicated"):
        _require_ops_environment(public_token=None)


def test_ops_bearer_must_differ_from_public(monkeypatch) -> None:
    monkeypatch.setenv("NEWSCLIP_OPS_BEARER_TOKEN", "same-token")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops-op-token")
    with pytest.raises(ValueError, match="differ"):
        _require_ops_environment(public_token="same-token")


def test_ops_stored_health_needs_no_credential_authority(monkeypatch) -> None:
    monkeypatch.setenv("NEWSCLIP_OPS_BEARER_TOKEN", "ops-bearer")
    monkeypatch.delenv("OP_SERVICE_ACCOUNT_TOKEN", raising=False)
    assert _require_ops_environment(public_token="public") == "ops-bearer"


def test_ops_environment_complete_returns_ops_bearer(monkeypatch) -> None:
    monkeypatch.setenv("NEWSCLIP_OPS_BEARER_TOKEN", "ops-bearer")
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops-op-token")
    assert _require_ops_environment(public_token="public") == "ops-bearer"


# --- CLI adaptation ----------------------------------------------------------


class RecordingRunner:
    def __init__(self, outcome: CommandOutcome | None = None) -> None:
        self.calls: list[tuple[list[str], bytes | None, float]] = []
        self.outcome = outcome or CommandOutcome(
            exit_code=0, stdout=json.dumps({"ok": True})
        )

    def __call__(
        self, args: list[str], stdin: bytes | None, timeout: float
    ) -> CommandOutcome:
        self.calls.append((args, stdin, timeout))
        return self.outcome


def test_provider_check_invokes_the_guard_cli() -> None:
    runner = RecordingRunner()
    adapter = OpsAdapter(runner=runner)
    result = adapter.provider_check("wsj")
    assert result["ok"] is True
    args, stdin, _ = runner.calls[0]
    assert args == ["provider-guard", "--provider", "wsj", "--json"]
    assert stdin is None


def test_promote_streams_payload_on_stdin_only() -> None:
    runner = RecordingRunner()
    adapter = OpsAdapter(runner=runner)
    adapter.promote("wsj", b'{"cookies": []}')
    args, stdin, _ = runner.calls[0]
    assert args == ["auth", "login", "wsj", "--import-stdin", "--json"]
    assert stdin == b'{"cookies": []}'
    # the secret must never appear in argv
    assert all("cookies" not in part for part in args)


def test_acknowledge_uses_compare_and_clear_cli() -> None:
    runner = RecordingRunner()
    adapter = OpsAdapter(runner=runner)
    adapter.acknowledge("ft", "guard-0123456789abcdef")
    args, _, _ = runner.calls[0]
    assert args == [
        "provider-guard-acknowledge",
        "--provider",
        "ft",
        "--hold-id",
        "guard-0123456789abcdef",
        "--json",
    ]


def test_payload_parses_last_json_line_and_never_echoes_raw() -> None:
    outcome = CommandOutcome(
        exit_code=1,
        stdout="warning: noisy line\n" + json.dumps({"action": "held"}),
    )
    payload = outcome.payload()
    assert payload == {"action": "held", "exit_code": 1}
    garbage = CommandOutcome(exit_code=1, stdout="RAW SECRET NOISE")
    assert garbage.payload() == {"exit_code": 1}


def test_payload_accepts_only_a_closed_error_envelope_from_stderr() -> None:
    incident_id = f"incident-{'a' * 24}"
    recovery_id = f"recovery-{'b' * 32}"
    envelope = {
        "ok": False,
        "category": "content_not_full",
        "exit_code": 4,
        "message": "content did not verify as full",
        "incident_id": incident_id,
        "recovery_id": recovery_id,
        "retryable": False,
        "action": "renewal_pending",
    }
    outcome = CommandOutcome(
        exit_code=4,
        stdout="",
        stderr="private diagnostic noise\n" + json.dumps(envelope),
    )

    assert outcome.payload() == envelope
    malformed = CommandOutcome(
        exit_code=4,
        stdout="",
        stderr=json.dumps(
            {"category": "content_not_full", "private": "SECRET_SENTINEL"}
        ),
    )
    assert malformed.payload() == {"exit_code": 4}
    mismatched = CommandOutcome(
        exit_code=5,
        stdout="",
        stderr=json.dumps(envelope),
    )
    assert mismatched.payload() == {"exit_code": 5}


def test_run_cli_round_trips_the_real_cli_error_contract(monkeypatch, tmp_path) -> None:
    for name in (
        "NEWSCLIP_STATE_HOME",
        "NEWSCLIP_DATA_HOME",
        "NEWSCLIP_TIMING_HOME",
        "NEWSCLIP_TRACE_HOME",
    ):
        monkeypatch.setenv(name, str(tmp_path / name.casefold()))

    envelope = {
        "ok": False,
        "category": "usage",
        "exit_code": 2,
        "message": "invalid request",
        "retryable": False,
        "action": "none",
    }
    private_provider = "privateproviderdetail"

    outcome = _run_cli(
        ["provider-guard", "--provider", private_provider, "--json"], None, 10
    )

    assert outcome.payload() == envelope
    assert private_provider not in outcome.stderr


def test_cli_timeout_returns_closed_error_envelope(monkeypatch) -> None:
    commands = []

    def time_out(args, **kwargs):
        commands.append(args)
        assert "timeout" not in kwargs
        return subprocess.CompletedProcess(args, 124, b"PRIVATE", b"PRIVATE")

    monkeypatch.setattr("newsclip.ops_server.subprocess.run", time_out)

    outcome = _run_cli(["provider-guard", "--provider", "wsj"], None, 600)

    # GNU timeout bounds the whole process group, browsers included.
    assert commands[0][:4] == ["timeout", "--signal=TERM", "--kill-after=30", "600"]
    assert commands[0][-3:] == ["provider-guard", "--provider", "wsj"]

    assert outcome.exit_code == 5
    assert outcome.payload() == {
        "ok": False,
        "category": "timeout",
        "exit_code": 5,
        "message": "provider transport failed",
        "retryable": True,
        "action": "retry_later",
    }


# --- async heal --------------------------------------------------------------


def test_heal_is_asynchronous_and_single_flight_per_provider() -> None:
    release = threading.Event()
    started = threading.Event()

    def blocking_runner(
        args: list[str], stdin: bytes | None, timeout: float
    ) -> CommandOutcome:
        started.set()
        release.wait(timeout=5)
        return CommandOutcome(exit_code=0, stdout=json.dumps({"action": "renewed"}))

    adapter = OpsAdapter(runner=blocking_runner)
    first = adapter.start_heal("wsj", allow_credential_mint=True)
    assert first == {"provider": "wsj", "status": "started"}
    assert started.wait(timeout=5)
    second = adapter.start_heal("wsj", allow_credential_mint=True)
    assert second == {"provider": "wsj", "status": "in_progress"}
    assert adapter.heal_state("wsj") == {"status": "in_progress"}
    release.set()
    for _ in range(200):
        state = adapter.heal_state("wsj")
        if state and state["status"] == "completed":
            break
        threading.Event().wait(0.01)
    assert state == {
        "status": "completed",
        "result": {"action": "renewed", "exit_code": 0},
    }
    # After completion a new heal may start.
    assert adapter.start_heal("wsj", allow_credential_mint=False)["status"] == (
        "started"
    )


def test_heal_mint_flag_controls_cli_argument() -> None:
    runner = RecordingRunner()
    adapter = OpsAdapter(runner=runner)
    adapter.start_heal("economist", allow_credential_mint=False)
    for _ in range(200):
        if runner.calls:
            break
        threading.Event().wait(0.01)
    args, _, _ = runner.calls[0]
    assert args == [
        "auth",
        "keep",
        "economist",
        "--json",
        "--reconcile-failed-recovery",
    ]
    adapter2 = OpsAdapter(runner=runner)
    adapter2.start_heal("wsj", allow_credential_mint=True)
    for _ in range(200):
        if len(runner.calls) > 1:
            break
        threading.Event().wait(0.01)
    assert runner.calls[1][0] == [
        "auth",
        "keep",
        "wsj",
        "--json",
        "--reconcile-failed-recovery",
        "--allow-credential-mint",
    ]


# --- tool registration (mcp extra) ------------------------------------------


def test_ops_server_registers_exactly_the_ops_tools() -> None:
    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.ops_server import build_ops_server

    server = build_ops_server(OpsAdapter(runner=RecordingRunner()))
    tools = anyio.run(list_tools, server)
    assert {tool["name"] for tool in tools} == set(OPS_TOOLS)


def test_slow_provider_check_does_not_block_concurrent_health(monkeypatch) -> None:
    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.health import FleetHealth
    from newsclip.ops_server import build_ops_server

    release = threading.Event()

    def slow_runner(
        args: list[str],
        stdin: bytes | None,
        timeout: float,
    ) -> CommandOutcome:
        release.wait(timeout=2)
        return CommandOutcome(exit_code=0, stdout=json.dumps({"ok": True}))

    monkeypatch.setattr(
        "newsclip.health.collect_fleet_health",
        lambda: FleetHealth(providers=()),
    )
    server = build_ops_server(OpsAdapter(runner=slow_runner))

    async def exercise() -> tuple[float, dict]:
        async def run_check() -> None:
            await call_tool(server, "provider_check", {"provider": "wsj"})

        started = time.monotonic()
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(run_check)
            await anyio.sleep(0)
            _, health = await call_tool(server, "health", {})
            elapsed = time.monotonic() - started
            release.set()
        return elapsed, health

    elapsed, health = anyio.run(exercise)

    assert elapsed < 0.5
    assert health == {"ok": True, "result": {"providers": []}}


def test_session_promote_rejects_ambiguous_and_oversized_input() -> None:
    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.ops_server import build_ops_server

    runner = RecordingRunner()
    server = build_ops_server(OpsAdapter(runner=runner))

    def call(arguments: dict) -> dict:
        result = anyio.run(lambda: server.call_tool("session_promote", arguments))
        assert result.is_error is True  # a refusal is a native tool error
        return result.structured_content

    both = call(
        {
            "provider": "wsj",
            "cookies_json": '[{"name": "a"}]',
            "op_reference": "op://v/i/f",
        }
    )
    assert both["ok"] is False and both["category"] == "usage"
    neither = call({"provider": "wsj"})
    assert neither["ok"] is False and neither["category"] == "usage"
    oversized = call({"provider": "wsj", "cookies_json": "x" * (1024 * 1024 + 1)})
    assert oversized["ok"] is False
    assert oversized["detail"] == "cookie payload exceeds 1 MiB"
    assert runner.calls == []  # nothing invalid ever reaches the CLI


def test_session_promote_accepts_string_or_parsed_export() -> None:
    """Transports may deliver the export decoded; both reach the CLI as JSON."""

    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.ops_server import build_ops_server

    runner = RecordingRunner()
    server = build_ops_server(OpsAdapter(runner=runner))
    anyio.run(
        lambda: call_tool(
            server,
            "session_promote",
            {"provider": "wsj", "cookies_json": [{"name": "a", "value": "b"}]},
        )
    )
    _, stdin, _ = runner.calls[0]
    assert stdin is not None
    assert json.loads(stdin) == [{"name": "a", "value": "b"}]


def test_cli_health_and_ops_health_share_one_snapshot(monkeypatch, tmp_path) -> None:
    """The operator over SSH and the agent over MCP get the same answer."""

    from typer.testing import CliRunner

    from newsclip.cli import app
    from newsclip.health import FleetHealth, ProviderHealth

    snapshot = FleetHealth(
        providers=(
            ProviderHealth(
                provider="wsj",
                session_backed=True,
                session={
                    "status": "verified",
                    "health": "degraded",
                    "consecutive_renewal_failures": 4,
                },
                readiness_missing=("vision_cli",),
            ),
        ),
    )
    monkeypatch.setattr("newsclip.cli.collect_fleet_health", lambda: snapshot)
    monkeypatch.setattr(
        "newsclip.health.collect_fleet_health", lambda: snapshot, raising=False
    )

    result = CliRunner().invoke(app, ["health", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["providers"][0]["session"]["health"] == "degraded"

    human = CliRunner().invoke(app, ["health"])
    assert "WSJ" in human.stdout and "serving=unknown" in human.stdout
    assert "session=verified renewal=failing" in human.stdout
    assert "renewal_failures=4" in human.stdout
    assert "missing=vision_cli" in human.stdout

    ops = OpsAdapter(runner=RecordingRunner())
    ops_payload = ops.health()
    assert ops_payload["providers"][0]["session"]["health"] == "degraded"
    assert "heal" in ops_payload["providers"][0]  # process-local layer added


def test_health_reports_how_often_a_provider_has_been_contained(monkeypatch) -> None:
    """A cooldown says "contained"; the arm count says whether it is relenting."""

    from typer.testing import CliRunner

    from newsclip.cli import app
    from newsclip.health import FleetHealth, ProviderHealth

    snapshot = FleetHealth(
        providers=(
            ProviderHealth(
                provider="reuters",
                defense={"active_until": "2026-07-28T18:34:50.736995Z"},
                defense_arms_24h=4,
            ),
        )
    )
    monkeypatch.setattr("newsclip.cli.collect_fleet_health", lambda: snapshot)

    human = CliRunner().invoke(app, ["health"])
    assert human.exit_code == 0
    assert "defense_until=2026-07-28T18:34:50.736995Z" in human.stdout
    assert "arms_24h=4" in human.stdout

    payload = json.loads(CliRunner().invoke(app, ["health", "--json"]).stdout)
    assert payload["providers"][0]["defense_arms_24h"] == 4


def test_health_does_not_present_overdue_renewal_as_an_article_outage(
    monkeypatch,
) -> None:
    from typer.testing import CliRunner

    from newsclip.cli import app
    from newsclip.health import (
        FleetHealth,
        ProviderHealth,
        ServingHealth,
        ServingStatus,
    )

    snapshot = FleetHealth(
        providers=(
            ProviderHealth(
                provider="bloomberg",
                serving=ServingHealth(status=ServingStatus.AVAILABLE),
                session_backed=True,
                session={"status": "verified", "health": "stale"},
            ),
        )
    )
    monkeypatch.setattr("newsclip.cli.collect_fleet_health", lambda: snapshot)

    human = CliRunner().invoke(app, ["health"])

    assert human.exit_code == 0
    assert "serving=available" in human.stdout
    assert "session=verified renewal=due" in human.stdout


def test_http_app_serves_ops_surface_fail_closed(monkeypatch, tmp_path) -> None:
    pytest.importorskip("anyio")
    pytest.importorskip("mcp")

    from newsclip.mcp_server import build_http_app

    monkeypatch.setenv("NEWSCLIP_MCP_OPS", "1")
    monkeypatch.setenv("NEWSCLIP_MCP_BEARER_TOKEN", "public-token")
    monkeypatch.delenv("NEWSCLIP_OPS_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops-op-token")
    with pytest.raises(ValueError, match="dedicated"):
        build_http_app()

    monkeypatch.setenv("NEWSCLIP_OPS_BEARER_TOKEN", "public-token")
    with pytest.raises(ValueError, match="differ"):
        build_http_app()

    monkeypatch.setenv("NEWSCLIP_OPS_BEARER_TOKEN", "ops-token")
    app = build_http_app()
    assert app is not None  # ops surface builds without the public service


_TIMEOUT_ENVELOPE = {
    "ok": False,
    "category": "timeout",
    "exit_code": 5,
    "message": "provider transport failed",
    "retryable": True,
    "action": "retry_later",
}


def test_failed_operator_command_is_a_native_tool_error() -> None:
    """A CLI error envelope becomes isError with the envelope as its payload."""

    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.ops_server import build_ops_server

    runner = RecordingRunner(
        CommandOutcome(exit_code=5, stdout=json.dumps(_TIMEOUT_ENVELOPE))
    )
    server = build_ops_server(OpsAdapter(runner=runner))

    for name, arguments in (
        ("provider_check", {"provider": "wsj"}),
        ("session_promote", {"provider": "wsj", "cookies_json": "[]"}),
        (
            "acknowledge_hold",
            {"provider": "wsj", "hold_id": "guard-0123456789abcdef"},
        ),
    ):
        result = anyio.run(server.call_tool, name, arguments)
        assert result.is_error is True, name
        assert result.structured_content == _TIMEOUT_ENVELOPE, name
        assert json.loads(result.content[0].text) == _TIMEOUT_ENVELOPE, name


def test_completed_guard_verdict_is_a_successful_result() -> None:
    """A check that ran and found a hold reports a verdict, not a failure."""

    pytest.importorskip("anyio")
    pytest.importorskip("mcp")
    import anyio

    from newsclip.ops_server import build_ops_server

    runner = RecordingRunner(
        CommandOutcome(exit_code=1, stdout=json.dumps({"action": "held"}))
    )
    server = build_ops_server(OpsAdapter(runner=runner))
    result = anyio.run(lambda: server.call_tool("provider_check", {"provider": "wsj"}))
    assert result.is_error is False
    assert result.structured_content == {
        "ok": True,
        "result": {"action": "held", "exit_code": 1},
    }


def test_fastmcp_client_raises_on_ops_failure_and_keeps_the_payload() -> None:
    """Over the wire: isError reaches clients, which raise by default."""

    pytest.importorskip("anyio")
    fastmcp = pytest.importorskip("fastmcp")
    import anyio
    from fastmcp.exceptions import ToolError

    from newsclip.ops_server import build_ops_server

    server = build_ops_server(OpsAdapter(runner=RecordingRunner()))

    async def exercise() -> None:
        async with fastmcp.Client(server) as client:
            with pytest.raises(ToolError) as raised:
                await client.call_tool("session_promote", {"provider": "wsj"})
            payload = json.loads(str(raised.value))
            assert payload["ok"] is False and payload["category"] == "usage"

            result = await client.call_tool(
                "session_promote", {"provider": "wsj"}, raise_on_error=False
            )
            assert result.is_error is True
            assert result.structured_content["category"] == "usage"

            ok = await client.call_tool("provider_check", {"provider": "wsj"})
            assert ok.is_error is False
            assert ok.structured_content == {
                "ok": True,
                "result": {"ok": True, "exit_code": 0},
            }

    anyio.run(exercise)
