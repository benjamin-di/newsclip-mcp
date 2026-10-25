"""Bounded semantic readiness for one already-navigated browser document."""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .errors import ContentNotFullError
from .provider_config import BrowserSemanticReadinessSpec


class ReadinessTerminalState(StrEnum):
    """Closed reason why the same-document sampler stopped."""

    STABILIZED = "stabilized"
    NON_PROMOTABLE_TIMEOUT = "non_promotable_timeout"
    PROMOTABLE_INCOMPLETE_TIMEOUT = "promotable_incomplete_timeout"
    COMPLETE_UNSTABLE_TIMEOUT = "complete_unstable_timeout"
    #: A stable authentication or challenge verdict; waiting cannot promote it.
    NON_PROMOTABLE_SETTLED = "non_promotable_settled"


class ReadinessCoverageBucket(StrEnum):
    """Coarse rendered coverage without retaining article content."""

    UNAVAILABLE = "unavailable"
    UNDER_25 = "under_25"
    FROM_25_TO_49 = "from_25_to_49"
    FROM_50_TO_74 = "from_50_to_74"
    FROM_75_TO_89 = "from_75_to_89"
    AT_LEAST_90 = "at_least_90"


@dataclass(frozen=True)
class BrowserReadinessObservation:
    """Provider-owned readiness verdict for one rendered-page snapshot."""

    ready: bool
    assessment_promotable: bool
    content_fingerprint: str
    word_count: int
    coverage_bucket: ReadinessCoverageBucket
    #: The snapshot is a terminal non-promotable verdict (authentication or
    #: challenge). Once it holds for ``stable_seconds`` the sampler stops
    #: instead of polling to the timeout. A teaser is never settled, because
    #: entitlement can resolve late on the same document.
    settled: bool = False


@dataclass(frozen=True)
class BrowserSemanticSnapshot:
    """Latest bounded snapshot plus closed terminal readiness evidence."""

    document_url: str
    content: bytes
    observation: BrowserReadinessObservation | None
    stabilized: bool
    terminal_state: ReadinessTerminalState
    content_change_count: int
    last_content_change_ms: int


class SemanticReadinessRejected(ContentNotFullError):
    """Internal failure retaining the terminal same-document snapshot."""

    def __init__(self, snapshot: BrowserSemanticSnapshot) -> None:
        super().__init__("browser_semantic_readiness_timeout")
        self.snapshot = snapshot


SnapshotReadinessEvaluator = Callable[
    [str, bytes],
    BrowserReadinessObservation,
]
SnapshotTerminalObserver = Callable[[BrowserSemanticSnapshot], None]


def readiness_coverage_bucket(coverage: float | None) -> ReadinessCoverageBucket:
    """Collapse normalized provider coverage into a private bounded category."""

    if coverage is None:
        return ReadinessCoverageBucket.UNAVAILABLE
    if not math.isfinite(coverage) or not 0 <= coverage <= 1:
        raise ValueError("browser readiness coverage must be between zero and one")
    if coverage < 0.25:
        return ReadinessCoverageBucket.UNDER_25
    if coverage < 0.5:
        return ReadinessCoverageBucket.FROM_25_TO_49
    if coverage < 0.75:
        return ReadinessCoverageBucket.FROM_50_TO_74
    if coverage < 0.9:
        return ReadinessCoverageBucket.FROM_75_TO_89
    return ReadinessCoverageBucket.AT_LEAST_90


def sample_semantic_snapshot(
    page: Any,
    *,
    initial_content: bytes,
    readiness: BrowserSemanticReadinessSpec,
    evaluator: SnapshotReadinessEvaluator,
    monotonic_clock: Callable[[], float] | None = None,
) -> BrowserSemanticSnapshot:
    """Return the stable semantic result or the latest bounded observation."""

    clock = monotonic_clock or time.monotonic
    deadline = clock() + readiness.timeout_seconds
    content = initial_content
    raw_fingerprint: str | None = None
    observation: BrowserReadinessObservation | None = None
    stable_fingerprint: str | None = None
    stable_since: float | None = None
    observed_content_fingerprint: str | None = None
    content_change_count = 0
    last_content_change_at = clock()

    while True:
        current_url = str(page.url)
        current_raw_fingerprint = hashlib.sha256(
            current_url.encode("utf-8") + b"\0" + content
        ).hexdigest()
        if current_raw_fingerprint != raw_fingerprint:
            raw_fingerprint = current_raw_fingerprint
            observation = evaluator(current_url, content)

        now = clock()
        if (
            observation is not None
            and observation.content_fingerprint != observed_content_fingerprint
        ):
            if observed_content_fingerprint is not None:
                content_change_count += 1
            observed_content_fingerprint = observation.content_fingerprint
            last_content_change_at = now
        if observation is not None and (observation.ready or observation.settled):
            if observation.content_fingerprint != stable_fingerprint:
                stable_fingerprint = observation.content_fingerprint
                stable_since = now
            elif (
                stable_since is not None
                and now - stable_since >= readiness.stable_seconds
            ):
                return BrowserSemanticSnapshot(
                    document_url=current_url,
                    content=content,
                    observation=observation,
                    stabilized=observation.ready,
                    terminal_state=(
                        ReadinessTerminalState.STABILIZED
                        if observation.ready
                        else ReadinessTerminalState.NON_PROMOTABLE_SETTLED
                    ),
                    content_change_count=content_change_count,
                    last_content_change_ms=_bounded_elapsed_ms(
                        now - last_content_change_at
                    ),
                )
        else:
            stable_fingerprint = None
            stable_since = None

        remaining = deadline - now
        if remaining <= 0:
            terminal_state = ReadinessTerminalState.NON_PROMOTABLE_TIMEOUT
            if observation is not None and observation.ready:
                terminal_state = ReadinessTerminalState.COMPLETE_UNSTABLE_TIMEOUT
            elif observation is not None and observation.assessment_promotable:
                terminal_state = ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT
            return BrowserSemanticSnapshot(
                document_url=current_url,
                content=content,
                observation=observation,
                stabilized=False,
                terminal_state=terminal_state,
                content_change_count=content_change_count,
                last_content_change_ms=_bounded_elapsed_ms(
                    now - last_content_change_at
                ),
            )
        page.wait_for_timeout(min(readiness.poll_seconds, remaining) * 1000)
        content = page.content().encode("utf-8", "replace")


def await_semantic_snapshot(
    page: Any,
    *,
    initial_content: bytes,
    readiness: BrowserSemanticReadinessSpec,
    evaluator: SnapshotReadinessEvaluator,
    monotonic_clock: Callable[[], float] | None = None,
    terminal_observer: SnapshotTerminalObserver | None = None,
) -> bytes:
    """Return a stable snapshot or a genuinely non-promotable timeout."""

    sampled = sample_semantic_snapshot(
        page,
        initial_content=initial_content,
        readiness=readiness,
        evaluator=evaluator,
        monotonic_clock=monotonic_clock,
    )
    if terminal_observer is not None:
        with suppress(Exception):
            terminal_observer(sampled)
    if sampled.terminal_state in {
        ReadinessTerminalState.PROMOTABLE_INCOMPLETE_TIMEOUT,
        ReadinessTerminalState.COMPLETE_UNSTABLE_TIMEOUT,
    }:
        raise SemanticReadinessRejected(sampled)
    return sampled.content


def _bounded_elapsed_ms(seconds: float) -> int:
    return min(max(round(seconds * 1000), 0), 120_000)


__all__ = [
    "BrowserReadinessObservation",
    "BrowserSemanticSnapshot",
    "ReadinessCoverageBucket",
    "ReadinessTerminalState",
    "SemanticReadinessRejected",
    "SnapshotReadinessEvaluator",
    "SnapshotTerminalObserver",
    "await_semantic_snapshot",
    "readiness_coverage_bucket",
    "sample_semantic_snapshot",
]
