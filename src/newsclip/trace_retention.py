"""Bounded retention for the private browser-runtime trace directory.

Every service build opens one ``browser-<id>.jsonl`` trace, and failed browser
work leaves screenshots and challenge instructions beside it. Nothing else
removes them, so the directory grows with every CLI, keeper and MCP process.

Retention works on whole runs (a trace and its artifacts), never on single
files, so a retained run keeps its action ledger and images together. It
skips:

- the calling process's own run;
- any run written within ``min_age``: a live process appends to its trace on
  every browser attempt, and an acquisition's artifacts are younger than its
  bounded timeout, so recent activity is the ownership signal that also works
  across containers sharing the state mount;
- subdirectories, including the live-invocation ``incidents/`` mirror, whose
  capsules carry their own copies of the trace and screenshot bytes and are
  bounded by the incident store.

Pruning is best effort: diagnostic housekeeping never fails the product.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

#: ``browser-<16 hex>`` owns ``.jsonl``, ``.<label>.png``/``.txt`` and an
#: interrupted publisher's ``.browser-<16 hex>-*.partial`` temporary.
_RUN_FILE = re.compile(r"^\.?(browser-[0-9a-f]{16})[.-]")
DEFAULT_MAX_AGE_SECONDS = 30 * 24 * 3600
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_MIN_AGE_SECONDS = 2 * 24 * 3600


@dataclass
class _Run:
    paths: list[Path] = field(default_factory=list)
    size: int = 0
    newest: float = 0.0


def prune_runtime_traces(
    root: Path,
    *,
    current_run_id: str | None,
    now: float | None = None,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    min_age_seconds: float = DEFAULT_MIN_AGE_SECONDS,
) -> int:
    """Delete runs older than ``max_age`` or beyond the byte cap; return count."""

    try:
        if root.is_symlink() or not root.is_dir():
            return 0
        runs: dict[str, _Run] = {}
        with os.scandir(root) as entries:
            for entry in entries:
                match = _RUN_FILE.match(entry.name)
                if match is None or match.group(1) == current_run_id:
                    continue
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                run = runs.setdefault(match.group(1), _Run())
                run.paths.append(Path(entry.path))
                run.size += metadata.st_size
                run.newest = max(run.newest, metadata.st_mtime)
    except OSError:
        return 0
    moment = time.time() if now is None else now
    removed = 0
    retained = 0
    capped = False
    # Newest first: the byte cap keeps the most recent contiguous evidence.
    for run in sorted(runs.values(), key=lambda item: item.newest, reverse=True):
        age = moment - run.newest
        if age < min_age_seconds:
            retained += run.size
            continue
        capped = capped or retained + run.size > max_bytes
        if age <= max_age_seconds and not capped:
            retained += run.size
            continue
        for path in run.paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue
        removed += 1
    return removed


__all__ = [
    "DEFAULT_MAX_AGE_SECONDS",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MIN_AGE_SECONDS",
    "prune_runtime_traces",
]
