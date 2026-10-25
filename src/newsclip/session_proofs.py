"""Bounded in-process memory of recent positive session probes.

A teaser only needs the lazy session probe to answer one question: is the
session dead, or is this article outside the subscription? When the same
session generation proved paid access moments ago in this process, relaunching
a browser to prove it again answers nothing new. The memory is keyed by
provider, account and session generation, so a renewed or replaced session
never inherits an older proof, and it forgets a provider as soon as any path
proves its session dead.

Only a verified probe counts as proof. A FULL article does not: free-to-read
and metered articles are served FULL without session authority, so treating
one as proof would hide a dead session behind a ``not_entitled`` verdict.
The memory is never persisted and never authorizes promotion of content; it
only lets a teaser skip a redundant classification probe.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from uuid import UUID

from .models import SessionArtifact

#: How long a verified probe answers "is this session alive" for a later
#: teaser. Short relative to session lifetimes and the hourly keeper.
SESSION_PROOF_REUSE_SECONDS = 600.0
_CAPACITY = 64


class SessionProofMemory:
    def __init__(
        self,
        *,
        ttl_seconds: float = SESSION_PROOF_REUSE_SECONDS,
        capacity: int = _CAPACITY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0 or capacity < 1:
            raise ValueError("session proof memory must be bounded and positive")
        self._ttl = ttl_seconds
        self._capacity = capacity
        self._clock = clock
        self._lock = threading.Lock()
        self._proofs: OrderedDict[tuple[str, str, UUID], float] = OrderedDict()

    @staticmethod
    def _key(
        provider: str, session: SessionArtifact | None
    ) -> tuple[str, str, UUID] | None:
        if session is None or session.provider != provider:
            return None
        return (provider, session.account_key, session.generation_id)

    def record(self, provider: str, session: SessionArtifact | None) -> None:
        key = self._key(provider, session)
        if key is None:
            return
        with self._lock:
            self._proofs.pop(key, None)
            self._proofs[key] = self._clock()
            while len(self._proofs) > self._capacity:
                self._proofs.popitem(last=False)

    def recent(self, provider: str, session: SessionArtifact | None) -> bool:
        key = self._key(provider, session)
        if key is None:
            return False
        with self._lock:
            proved_at = self._proofs.get(key)
            if proved_at is None:
                return False
            age = self._clock() - proved_at
            if 0 <= age <= self._ttl:
                return True
            del self._proofs[key]
            return False

    def forget(self, provider: str) -> None:
        with self._lock:
            for key in [key for key in self._proofs if key[0] == provider]:
                del self._proofs[key]


__all__ = ["SESSION_PROOF_REUSE_SECONDS", "SessionProofMemory"]
