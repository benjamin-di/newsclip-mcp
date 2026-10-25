"""The recovery tick is local, bounded, and independent of slow providers."""

from datetime import UTC, datetime
from threading import Event

import pytest

from newsclip.recovery import RecoveryStore
from newsclip.recovery_watch import RecoveryWatch, _run

NOW = datetime(2026, 9, 6, tzinfo=UTC)


def test_healthy_tick_launches_nothing(tmp_path):
    store = RecoveryStore(tmp_path / "absent")
    calls = []
    watcher = RecoveryWatch(
        store,
        ("ft", "bloomberg"),
        allow_credentials=True,
        runner=lambda *args: calls.append(args),
    )
    try:
        assert watcher.tick() == []
        assert calls == []
        assert not watcher.active
        assert not store.root.exists()
    finally:
        watcher.close()


def test_slow_providers_are_bounded_and_do_not_block_the_tick(tmp_path):
    store = RecoveryStore(tmp_path, utc_now=lambda: NOW)
    providers = ("ft", "bloomberg", "wsj")
    for provider in providers:
        store.request(
            provider,
            generation_id=None,
            url=f"https://{provider}.test/article",
            incident_id=None,
            diagnostic_id=None,
        )
    release = Event()
    calls = []

    def run(provider, allow, timeout):
        calls.append((provider, allow, timeout))
        assert release.wait(5)
        with store.operation(provider):
            record = store.claim(provider, "cli-fixture")
            store.finish(
                record, reason=None, session_verified=True, article_verified=True
            )
        return {"provider": provider, "action": "renewed"}

    watcher = RecoveryWatch(store, providers, allow_credentials=True, runner=run)
    try:
        watcher.tick()
        assert len(watcher.active) == 2
        # No waiting on futures, no duplicated submission, no unbounded queue.
        assert watcher.tick() == []
        assert len(watcher.active) == 2
        release.set()
        for future in list(watcher.active.values()):
            future.result(timeout=5)
        assert len(watcher.tick()) == 2
        assert list(watcher.active) == ["wsj"]
        watcher.active["wsj"].result(timeout=5)
        assert len(watcher.tick()) == 1
        assert {provider for provider, _, _ in calls} == set(providers)
        assert all(allow and timeout == 900 for _, allow, timeout in calls)
    finally:
        release.set()
        watcher.close()


def test_corrupt_provider_state_does_not_stop_other_providers(tmp_path):
    (tmp_path / "ft.json").write_text("corrupt")
    watcher = RecoveryWatch(
        RecoveryStore(tmp_path), ("ft", "bloomberg"), allow_credentials=False
    )
    try:
        assert watcher.tick() == [
            {"provider": "ft", "action": "recovery_state_unreadable"}
        ]
        assert not watcher.active
    finally:
        watcher.close()


def test_child_command_is_bounded_and_raw_failure_output_is_never_logged(monkeypatch):
    import subprocess

    commands = []

    def run(args, **kwargs):
        commands.append(args)
        assert kwargs == {"capture_output": True, "check": False}
        return subprocess.CompletedProcess(
            args, 124, b"PRIVATE_STDOUT", b"PRIVATE_STDERR"
        )

    monkeypatch.setattr("newsclip.recovery_watch.subprocess.run", run)
    assert _run("ft", True, 20) == {
        "provider": "ft",
        "action": "recovery_worker_failed",
        "exit_code": 124,
    }
    assert commands[0][:4] == ["timeout", "--signal=TERM", "--kill-after=30", "20"]
    assert "--recovery-only" in commands[0]
    assert "--allow-credential-mint" in commands[0]


def test_exited_unclaimed_workers_stop_and_do_not_starve_other_providers(tmp_path):
    from newsclip.models import RecoveryStatus

    store = RecoveryStore(tmp_path)
    providers = ("ft", "bloomberg", "wsj")
    for provider in providers:
        store.request(
            provider,
            generation_id=None,
            url=f"https://{provider}.test/article",
            incident_id=None,
            diagnostic_id=None,
        )
    calls = []

    def run(provider, *_):
        calls.append(provider)
        return {"provider": provider, "action": "recovery_worker_failed"}

    watcher = RecoveryWatch(store, providers, allow_credentials=False, runner=run)
    try:
        for _ in range(4):
            watcher.tick()
            for future in tuple(watcher.active.values()):
                future.result(timeout=5)
        assert sorted(calls) == sorted(providers)
        for provider in providers:
            record = store.load(provider)
            assert record.health.status is RecoveryStatus.FAILED
            assert record.health.reason == "recovery_worker_failed"
            assert record.health.attempts == 0
    finally:
        watcher.close()


def test_busy_workers_rotate_without_failing_pending_requests(tmp_path):
    from newsclip.models import RecoveryStatus

    store = RecoveryStore(tmp_path)
    providers = ("ft", "bloomberg", "wsj")
    for provider in providers:
        store.request(
            provider,
            generation_id=None,
            url=f"https://{provider}.test/article",
            incident_id=None,
            diagnostic_id=None,
        )
    calls = []

    def run(provider, *_):
        calls.append(provider)
        return {"provider": provider, "action": "busy"}

    watcher = RecoveryWatch(store, providers, allow_credentials=False, runner=run)
    try:
        for _ in range(2):
            watcher.tick()
            for future in tuple(watcher.active.values()):
                future.result(timeout=5)
        assert "wsj" in calls
        assert all(
            store.load(p).health.status is RecoveryStatus.PENDING for p in providers
        )
    finally:
        watcher.close()


def test_watcher_entrypoint_uses_the_configured_account(monkeypatch, tmp_path):
    import newsclip.recovery_watch as module
    from newsclip.tenancy import current_user

    monkeypatch.setenv("NEWSCLIP_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("NEWSCLIP_USER", "alice")
    monkeypatch.setenv("NEWSCLIP_KEEPER_PROVIDERS", "ft")
    monkeypatch.setattr("newsclip.process_signals.exit_on_sigterm", lambda: None)
    observed = []

    class Watcher:
        def __init__(self, store, providers, **kwargs):
            observed.append(store.root)

        def tick(self):
            assert current_user() == "alice"
            raise SystemExit(0)

        def close(self):
            observed.append("closed")

    monkeypatch.setattr(module, "RecoveryWatch", Watcher)
    with pytest.raises(SystemExit):
        module.main()
    assert observed == [tmp_path / "users/alice/recovery", "closed"]
    assert current_user() is None
