"""Bounded retention of the private browser-runtime trace directory."""

from __future__ import annotations

import os
from pathlib import Path

from newsclip.trace_retention import prune_runtime_traces

DAY = 24 * 3600
NOW = 1_800_000_000.0


def _age(path: Path, days: float) -> None:
    os.utime(path, (NOW - days * DAY, NOW - days * DAY))


def _run(root: Path, run_id: str, *, age_days: float, size: int = 10) -> list[Path]:
    paths = [
        root / f"{run_id}.jsonl",
        root / f"{run_id}.failure.png",
        root / f"{run_id}.hcaptcha-instruction.txt",
        root / f".{run_id}-abc.partial",
    ]
    for path in paths:
        path.write_bytes(b"x" * size)
        _age(path, age_days)
    return paths


def test_prunes_whole_expired_runs_and_keeps_recent_current_and_foreign(
    tmp_path: Path,
) -> None:
    expired = _run(tmp_path, "browser-" + "1" * 16, age_days=40)
    kept = _run(tmp_path, "browser-" + "2" * 16, age_days=10)
    current = _run(tmp_path, "browser-" + "3" * 16, age_days=90)
    mirror = tmp_path / "incidents" / ("incident-" + "0" * 24)
    mirror.mkdir(parents=True)
    (mirror / "incident.json").write_text("{}")
    _age(mirror / "incident.json", 400)
    unrelated = tmp_path / "live-report.json"
    unrelated.write_text("{}")
    _age(unrelated, 400)

    removed = prune_runtime_traces(
        tmp_path, current_run_id="browser-" + "3" * 16, now=NOW
    )

    assert removed == 1
    assert not any(path.exists() for path in expired)
    assert all(path.exists() for path in kept + current)
    # Incident mirrors and foreign files are never retention candidates.
    assert (mirror / "incident.json").exists()
    assert unrelated.exists()


def test_byte_cap_keeps_the_newest_runs_and_never_recent_activity(
    tmp_path: Path,
) -> None:
    active = _run(tmp_path, "browser-" + "a" * 16, age_days=0.5, size=100)
    newer = _run(tmp_path, "browser-" + "b" * 16, age_days=3, size=100)
    older = _run(tmp_path, "browser-" + "c" * 16, age_days=4, size=100)
    oldest_small = _run(tmp_path, "browser-" + "d" * 16, age_days=5, size=1)

    removed = prune_runtime_traces(
        tmp_path, current_run_id=None, now=NOW, max_bytes=800
    )

    # A run written within the minimum age may belong to a live process and
    # is kept even over the cap; once the cap is crossed every older run goes,
    # so retention is always the most recent contiguous span.
    assert removed == 2
    assert all(path.exists() for path in active + newer)
    assert not any(path.exists() for path in older + oldest_small)


def test_missing_or_symlinked_root_is_left_alone(tmp_path: Path) -> None:
    assert prune_runtime_traces(tmp_path / "missing", current_run_id=None) == 0
    target = tmp_path / "target"
    target.mkdir()
    expired = _run(target, "browser-" + "e" * 16, age_days=90)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    assert prune_runtime_traces(link, current_run_id=None, now=NOW) == 0
    assert all(path.exists() for path in expired)
