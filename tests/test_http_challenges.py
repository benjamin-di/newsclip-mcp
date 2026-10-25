"""The log of HTTP legs a session provider's edge refused while the browser served."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsclip.http_challenges import (
    RETENTION,
    HttpChallengeError,
    HttpChallengeStore,
)

NOW = datetime(2026, 10, 19, 6, 0, tzinfo=UTC)


class _Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _store(tmp_path: Path, clock: _Clock) -> HttpChallengeStore:
    return HttpChallengeStore(tmp_path / "http-challenges", utc_now=clock)


def test_absent_log_reads_as_nothing_refused(tmp_path: Path) -> None:
    store = _store(tmp_path, _Clock(NOW))

    assert store.summary("ft") is None
    assert store.count_since("ft", NOW - timedelta(days=1)) == 0


def test_summary_reports_newest_profile_and_both_windows(tmp_path: Path) -> None:
    clock = _Clock(NOW - timedelta(days=3))
    store = _store(tmp_path, clock)
    store.record("ft", profile="chrome146")
    clock.now = NOW - timedelta(hours=2)
    store.record("ft", profile="chrome146")
    clock.now = NOW
    store.record("ft", profile="chrome150")

    summary = store.summary("ft")

    assert summary is not None
    assert summary.profile == "chrome150"
    assert summary.last_at == NOW
    assert summary.last_24h == 2
    assert summary.last_7d == 3
    assert store.count_since("ft", NOW - timedelta(days=1)) == 2


def test_events_older_than_retention_are_pruned_on_write(tmp_path: Path) -> None:
    clock = _Clock(NOW - RETENTION - timedelta(minutes=1))
    store = _store(tmp_path, clock)
    store.record("ft", profile="chrome146")
    clock.now = NOW
    assert store.summary("ft") is None

    store.record("ft", profile="chrome150")

    stored = json.loads((tmp_path / "http-challenges" / "ft.json").read_text())
    assert [event["profile"] for event in stored["events"]] == ["chrome150"]


def test_the_log_is_bounded(tmp_path: Path) -> None:
    clock = _Clock(NOW)
    store = _store(tmp_path, clock)
    for index in range(510):
        clock.now = NOW + timedelta(seconds=index)
        store.record("ft", profile="chrome146")

    summary = store.summary("ft")

    assert summary is not None
    assert summary.last_7d == 500


def test_private_file_modes(tmp_path: Path) -> None:
    store = _store(tmp_path, _Clock(NOW))
    store.record("ft", profile=None)

    root = tmp_path / "http-challenges"
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "ft.json").stat().st_mode & 0o777 == 0o600


def test_corrupt_log_raises_on_read_but_never_blocks_a_new_record(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, _Clock(NOW))
    root = tmp_path / "http-challenges"
    root.mkdir(mode=0o700)
    (root / "ft.json").write_text("{not json")

    with pytest.raises(HttpChallengeError):
        store.summary("ft")

    store.record("ft", profile="chrome150")
    summary = store.summary("ft")
    assert summary is not None
    assert summary.last_7d == 1


def test_a_log_naming_another_provider_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path, _Clock(NOW))
    store.record("ft", profile="chrome150")
    root = tmp_path / "http-challenges"
    (root / "wsj.json").write_bytes((root / "ft.json").read_bytes())

    with pytest.raises(HttpChallengeError, match="inconsistent"):
        store.summary("wsj")


def test_invalid_provider_keys_are_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path, _Clock(NOW))

    with pytest.raises(HttpChallengeError):
        store.record("../ft", profile=None)


def test_composed_recorder_logs_http_session_providers_only(tmp_path: Path) -> None:
    from newsclip.composition import _http_challenge_recorder
    from newsclip.provider_config import load_builtin_provider_specs

    specs = {spec.key: spec for spec in load_builtin_provider_specs()}
    record = _http_challenge_recorder(tmp_path, specs)

    record("ft", "chrome150")
    record("ft", "not-a-profile")  # unknown names are kept as unknown
    record("reuters", "safari2601")  # anonymous: R8's rot signal owns it
    record("economist", "chrome150")  # browser retrieval: resolver passage
    record("wsj", "chrome150")
    record("unknown-provider", "chrome150")

    store = HttpChallengeStore(tmp_path / "http-challenges")
    stored = json.loads((tmp_path / "http-challenges" / "ft.json").read_text())
    assert [event["profile"] for event in stored["events"]] == ["chrome150", None]
    for provider in ("reuters", "economist", "wsj"):
        assert store.summary(provider) is None


def test_composed_recorder_never_breaks_the_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from newsclip.composition import _http_challenge_recorder
    from newsclip.provider_config import load_builtin_provider_specs

    def fail(self: object, provider: str, *, profile: str | None) -> None:
        raise OSError("disk")

    monkeypatch.setattr(HttpChallengeStore, "record", fail)
    specs = {spec.key: spec for spec in load_builtin_provider_specs()}

    _http_challenge_recorder(tmp_path, specs)("ft", "chrome150")


def test_escalation_recorder_isolates_each_recorder() -> None:
    from newsclip.composition import _escalation_recorder

    calls: list[tuple[str, str | None]] = []

    def broken(provider: str, served_by: str | None) -> None:
        raise RuntimeError("rot store down")

    _escalation_recorder(broken, lambda *call: calls.append(call))("ft", "chrome150")

    assert calls == [("ft", "chrome150")]
