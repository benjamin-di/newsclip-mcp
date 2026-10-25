"""HTTP legs a session provider's edge refused while the browser served.

FT is a session provider that retrieves over HTTP and escalates a challenged
read to the browser. Readers never see such a refusal: the article arrives.
It is still the earliest sign that the HTTP fingerprint has aged — on
2026-10-19 FT's Cloudflare challenged chrome146 16/16 while chrome150 passed
16/16 from the same host — and for three weeks it surfaced only as renewal
pages, because the renewal probe has no browser leg to hide it.

Session routes stay outside the R8 runtime pin, so this records the fact and
changes nothing else: no transport selection, no defense arm, no request.
Health reports the counts; the keeper names the repair when a renewal is
challenged while recent reads were too.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, Field, ValidationError

from .errors import PersistenceError
from .models import FrozenModel
from .private_state import PrivateStateError, atomic_private_write, exclusive_lock
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

#: How far back the log keeps events. Health reports this window and 24 h.
RETENTION = timedelta(days=7)
#: A hard cap so a provider refusing every read cannot grow the file.
_MAX_EVENTS = 500
_MAX_STATE_BYTES = 128 * 1024
_LOCK_TIMEOUT_SECONDS = 5.0


class HttpChallengeError(PersistenceError):
    """The HTTP challenge log could not be read or committed safely."""


class HttpChallengeEvent(FrozenModel):
    at: AwareDatetime
    #: The impersonation profile the refused fetch presented, when known.
    profile: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"
    )


class HttpChallengeLog(FrozenModel):
    schema_version: Literal[1] = 1
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    events: tuple[HttpChallengeEvent, ...] = Field(default=(), max_length=_MAX_EVENTS)


class HttpChallengeSummary(FrozenModel):
    """What ops health shows: the latest profile refused, and how often."""

    profile: str | None
    last_at: AwareDatetime
    last_24h: int = Field(ge=0)
    last_7d: int = Field(ge=0)


class HttpChallengeStore:
    """Process-safe per-provider log under ``state/http-challenges``."""

    def __init__(
        self,
        root: Path,
        *,
        utc_now: Callable[[], datetime] | None = None,
        lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.root = Path(root)
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self._lock_timeout_seconds = lock_timeout_seconds

    def record(self, provider: str, *, profile: str | None) -> None:
        """Append one refusal. Unreadable prior state is replaced, not honored."""

        path = self._path(provider)
        now = self._utc_now()
        try:
            with exclusive_lock(
                path.with_suffix(".lock"),
                timeout_seconds=self._lock_timeout_seconds,
            ):
                try:
                    prior = self._load(provider)
                except HttpChallengeError:
                    prior = None
                kept = [
                    event
                    for event in (prior.events if prior is not None else ())
                    if now - RETENTION <= event.at <= now
                ]
                kept.append(HttpChallengeEvent(at=now, profile=profile))
                log = HttpChallengeLog(
                    provider=provider, events=tuple(kept[-_MAX_EVENTS:])
                )
                payload = (
                    json.dumps(
                        log.model_dump(mode="json"),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
                atomic_private_write(path, payload)
        except PrivateStateError as error:
            raise HttpChallengeError("HTTP challenge log write failed") from error

    def summary(self, provider: str) -> HttpChallengeSummary | None:
        """The retained window, or None when nothing was refused in it."""

        log = self._load(provider)
        if log is None:
            return None
        now = self._utc_now()
        recent = [event for event in log.events if now - RETENTION <= event.at <= now]
        if not recent:
            return None
        latest = max(recent, key=lambda event: event.at)
        return HttpChallengeSummary(
            profile=latest.profile,
            last_at=latest.at,
            last_24h=sum(1 for event in recent if now - event.at <= timedelta(days=1)),
            last_7d=len(recent),
        )

    def count_since(self, provider: str, since: datetime) -> int:
        log = self._load(provider)
        if log is None:
            return 0
        now = self._utc_now()
        return sum(1 for event in log.events if since <= event.at <= now)

    def _load(self, provider: str) -> HttpChallengeLog | None:
        path = self._path(provider)
        if path.is_symlink():
            raise HttpChallengeError("HTTP challenge log is invalid")
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise HttpChallengeError("HTTP challenge log is unreadable") from error
        if len(raw) > _MAX_STATE_BYTES:
            raise HttpChallengeError("HTTP challenge log is oversized")
        try:
            log = HttpChallengeLog.model_validate_json(raw)
        except ValidationError as error:
            raise HttpChallengeError("HTTP challenge log is invalid") from error
        if log.provider != provider:
            raise HttpChallengeError("HTTP challenge log is inconsistent")
        return log

    def _path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise HttpChallengeError("HTTP challenge provider key is invalid")
        return self.root / f"{provider}.json"


__all__ = [
    "RETENTION",
    "HttpChallengeError",
    "HttpChallengeEvent",
    "HttpChallengeLog",
    "HttpChallengeStore",
    "HttpChallengeSummary",
]
