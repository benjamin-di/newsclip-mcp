"""Public maintenance: bounded work, private results and durable cadence."""

import json
from contextlib import suppress
from pathlib import Path

import pytest
from typer.testing import CliRunner

from newsclip.cli import app
from newsclip.maintenance_cycle import run_maintenance_cycle


def fresh(args, **kwargs):
    return 0, {"provider": args[2], "action": "fresh", "overall_state": "healthy"}


def test_failed_provider_does_not_skip_others_or_disclose_raw_output(tmp_path):
    calls = []

    def run(args, **kwargs):
        calls.append(args[2])
        if args[2] == "wsj":
            return 0, {
                "provider": "wsj",
                "action": "fresh",
                "overall_state": "needs_attention",
                "reason_code": "SYNTHETIC_SECRET",
                "repair_hint": "SYNTHETIC_SECRET",
                "recovery": {
                    "status": "failed",
                    "reason": "content_not_full",
                    "attempts": 1,
                },
            }
        return fresh(args)

    result = run_maintenance_cycle(["ft", "wsj", "nyt"], root=tmp_path, runner=run)
    assert calls == ["ft", "wsj", "nyt"]
    assert result.needs_attention
    assert result.results[1]["reason_code"] == "unclassified"
    assert result.results[1]["recovery"]["reason"] == "content_not_full"
    assert "SYNTHETIC_SECRET" not in json.dumps(result.public_dict())


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"provider": "nyt", "action": "fresh", "overall_state": "healthy"},
        {"provider": "ft", "action": "unknown", "overall_state": "healthy"},
    ],
)
def test_malformed_or_cross_provider_result_fails_closed(tmp_path, bad):
    result = run_maintenance_cycle(
        ["ft"], root=tmp_path, runner=lambda *a, **k: (0, bad)
    )
    assert result.needs_attention
    assert result.results[0]["reason_code"] == "cli_output_invalid"


def test_timeout_is_classified_and_later_provider_still_runs(tmp_path):
    def run(args, **kwargs):
        return (124, {}) if args[2] == "ft" else fresh(args)

    result = run_maintenance_cycle(["ft", "wsj"], root=tmp_path, runner=run)
    assert result.results[0]["reason_code"] == "cli_timeout"
    assert result.results[1]["provider"] == "wsj"


def test_credential_authorization_is_explicit_and_never_applies_to_checks(tmp_path):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0] == "provider-guard":
            return 0, {"provider": args[2], "action": "healthy"}
        return fresh(args)

    run_maintenance_cycle(["ft"], root=tmp_path, runner=run)
    assert "--allow-credential-mint" not in calls[-1]
    run_maintenance_cycle(["ft"], root=tmp_path, runner=run, allow_credential_mint=True)
    assert "--allow-credential-mint" in calls[-1]
    run_maintenance_cycle(
        ["ft"], root=tmp_path, runner=run, mode="check", allow_credential_mint=True
    )
    assert "--allow-credential-mint" not in calls[-1]
    assert "--scheduled" in calls[-1]


def test_check_window_is_durable_and_reserved_before_io(tmp_path):
    calls = []
    starts = []

    def run(args, **kwargs):
        assert int((tmp_path / "provider-monitor-next-run-at").read_text()) == 86500
        calls.append(args)
        return 1, {"provider": args[2], "action": "provider_hold"}

    result = run_maintenance_cycle(
        ["ft"],
        root=tmp_path,
        mode="check",
        runner=run,
        now=lambda: 100,
        on_start=lambda: starts.append("started"),
    )
    assert result.ran and not result.needs_attention
    before = (tmp_path / "provider-monitor-next-run-at").read_bytes()
    result = run_maintenance_cycle(
        ["ft"],
        root=tmp_path,
        mode="check",
        runner=run,
        now=lambda: 101,
        on_start=lambda: starts.append("started"),
    )
    assert not result.ran
    assert len(calls) == len(starts) == 1
    assert (tmp_path / "provider-monitor-next-run-at").read_bytes() == before
    assert (tmp_path / "provider-monitor-next-run-at").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "action,attention",
    [
        ("operator_action", True),
        ("local_repair_required", True),
        ("session_promotion_required", True),
        ("transient_failure", False),
        ("wait_for_session_evidence", False),
        ("incident_review_required", False),
        ("SYNTHETIC_SECRET", True),
    ],
)
def test_guard_reports_operator_need_separately_from_automatic_waiting(
    tmp_path, action, attention
):
    result = run_maintenance_cycle(
        ["ft"],
        root=tmp_path,
        mode="check",
        runner=lambda *a, **k: (1, {"provider": "ft", "action": action}),
    )
    assert result.needs_attention is attention
    assert "SYNTHETIC_SECRET" not in json.dumps(result.public_dict())


def test_existing_check_reservation_is_not_reset_and_malformed_state_stops_io(tmp_path):
    marker = tmp_path / "provider-monitor-next-run-at"
    marker.write_text("20000\n")

    def forbidden(*a, **k):
        pytest.fail("reserved work must not contact providers")

    assert not run_maintenance_cycle(
        ["ft"], root=tmp_path, mode="check", runner=forbidden, now=lambda: 1
    ).ran
    marker.write_text("invalid\n")
    with pytest.raises(Exception, match="schedule"):
        run_maintenance_cycle(["ft"], root=tmp_path, mode="check", runner=forbidden)
    assert marker.read_text() == "invalid\n"


def test_cli_scopes_public_cycle_to_selected_user(tmp_path, monkeypatch):
    import newsclip.maintenance_cycle as module

    original = module.run_maintenance_cycle

    def run(providers, **kwargs):
        assert kwargs["root"] == tmp_path / "users" / "alice"
        return original(providers, **kwargs, runner=fresh)

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(module, "run_maintenance_cycle", run)
    result = CliRunner().invoke(
        app, ["--user", "alice", "maintenance-cycle", "--providers", "ft wsj", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["schema_version"] == 1
    assert len(data["results"]) == 2
    assert not (tmp_path / "maintenance-cycle.lock").exists()


def test_cycle_lease_survives_a_killed_invoker_until_its_child_finishes(tmp_path):
    import os
    import signal
    import subprocess
    import sys
    import time

    child_code = (
        "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]);\n"
        "while not p.exists(): time.sleep(.01)"
    )
    parent_code = """
import pathlib,subprocess,sys
from newsclip.maintenance_cycle import cycle_lease
root=pathlib.Path(sys.argv[1])
with cycle_lease(root) as descriptor:
    child=subprocess.Popen([sys.executable,'-c',sys.argv[2],str(root/'release')],pass_fds=(descriptor,))
    (root/'started').touch()
    child.wait()
"""
    next_code = """
import pathlib,sys
from newsclip.maintenance_cycle import cycle_lease
root=pathlib.Path(sys.argv[1])
with cycle_lease(root): (root/'entered').touch()
"""
    first = subprocess.Popen(
        [sys.executable, "-c", parent_code, str(tmp_path), child_code],
        start_new_session=True,
    )
    second = None
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / "started").exists():
            assert first.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.01)
        first.kill()
        first.wait(timeout=3)
        second = subprocess.Popen(
            [sys.executable, "-c", next_code, str(tmp_path)], start_new_session=True
        )
        time.sleep(0.2)
        assert not (tmp_path / "entered").exists()
        (tmp_path / "release").touch()
        assert second.wait(timeout=5) == 0
        assert (tmp_path / "entered").exists()
    finally:
        (tmp_path / "release").touch()
        for process in (first, second):
            if process is not None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)


@pytest.mark.parametrize(
    "name",
    [
        "recovery_backoff",
        "ready",
        "review_recovery",
        "automatic_retry_article",
        "automatic_wait_for_provider_check",
        "automatic_blocked",
        "automatic_review",
    ],
)
def test_recovery_contract_survives_public_projection(tmp_path, name):
    encoded = (
        Path(__file__).parent / "fixtures/maintenance/recovery-verdicts.json"
    ).read_text()
    # Identities are assembled from repeated characters, never captured from a run.
    for placeholder, value in {
        "SYNTHETIC_INCIDENT_ID": "incident-" + "c" * 24,
        "SYNTHETIC_RECOVERY_ID": "recovery-" + "b" * 32,
        "SYNTHETIC_DIAGNOSTIC_ID": "cli-" + "a" * 32,
    }.items():
        encoded = encoded.replace(placeholder, value)
    fixture = json.loads(encoded)[name]
    result = run_maintenance_cycle(
        [fixture["provider"]], root=tmp_path, runner=lambda *a, **k: (1, fixture)
    )
    actual = result.results[0]
    for key in (
        "status",
        "reason",
        "attempts",
        "episode_attempts",
        "budget_reset_at",
        "incident_id",
    ):
        if fixture["recovery"].get(key) is not None:
            assert actual["recovery"][key] == fixture["recovery"][key]
    assert "recent_attempts" not in actual["recovery"]
    assert actual.get("recovery_blocker") == fixture.get("recovery_blocker")
    assert actual["next_action"] == fixture["next_action"]
    assert "repair_hint" not in actual
    assert actual["needs_attention"]


@pytest.mark.parametrize("termination", ["term", "kill"])
def test_terminated_invocation_gives_its_child_a_graceful_shutdown(
    tmp_path, termination
):
    import subprocess
    import sys
    import time

    child_program = """
import pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1])
def stop(*args):
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    (root/'closed').touch()
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
(root/'ready').touch()
while True:time.sleep(.1)
"""
    parent_program = """
import pathlib,subprocess,sys
import newsclip.maintenance_cycle as cycle
from newsclip.process_signals import exit_on_sigterm
exit_on_sigterm()
root=pathlib.Path(sys.argv[1]);original=subprocess.Popen
# The stand-in runs in the separate group that the bounded provider child owns.
def spawn(args,**kwargs):
    kwargs['start_new_session']=True
    return original([*args[:4],sys.executable,'-c',sys.argv[2],str(root)],**kwargs)
cycle.subprocess.Popen=spawn
with cycle.cycle_lease(root) as descriptor:
    cycle.run_command(['auth','keep','ft'],timeout=1,lock_fd=descriptor)
"""
    parent = subprocess.Popen(
        [sys.executable, "-c", parent_program, str(tmp_path), child_program]
    )
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / "ready").exists():
            assert parent.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.01)
        (parent.terminate if termination == "term" else parent.kill)()
        parent.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not (tmp_path / "closed").exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=3)
