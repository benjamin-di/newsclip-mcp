"""Carry one renewal's ordering evidence through synchronous service calls.

The sequence is issued while the session authority lock is still held. It is
not a timestamp, session generation, credential reservation or provider retry.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class RenewalObservation:
    provider: str
    issue: Callable[[str], int]
    revision: int | None = None

    def stamp(self) -> None:
        self.revision = self.issue(self.provider)


_CURRENT: ContextVar[RenewalObservation | None] = ContextVar(
    "renewal_observation", default=None
)


def current_revision(provider: str) -> int | None:
    current = _CURRENT.get()
    return current.revision if current and current.provider == provider else None


@contextmanager
def observe_renewal(
    provider: str, issue: Callable[[str], int] | None
) -> Iterator[RenewalObservation | None]:
    current = _CURRENT.get()
    if current is not None and current.provider == provider:
        yield current
        return
    observation = RenewalObservation(provider, issue) if issue is not None else None
    token = _CURRENT.set(observation)
    try:
        yield observation
    finally:
        _CURRENT.reset(token)


@contextmanager
def renewal_observation_point(provider: str) -> Iterator[None]:
    """Stamp completion before releasing the enclosing session authority lock."""
    try:
        yield
    finally:
        current = _CURRENT.get()
        if current is not None and current.provider == provider:
            current.stamp()
