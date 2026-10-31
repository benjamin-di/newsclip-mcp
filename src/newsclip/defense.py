"""One per-provider defense state machine: backoff is the heal.

Edge defenses (DataDome, Cloudflare, Turnstile) relent when traffic backs off
and escalate when it does not. Before this module the product did the
opposite: every caller retried straight into an active challenge, each hit
extending the block (the 2026-07-28 Reuters episode). This record makes the
product self-limiting:

- an observed challenge **arms** a cooldown (base 20 min, doubling per
  consecutive arm to a 6 h cap); a challenge from a request already in
  flight while the cooldown runs, before any canary, joins the episode
  without escalating it;
- while armed, retrieval **fails fast** with ``retry_after_seconds`` instead
  of touching the provider;
- on expiry exactly **one** caller proceeds as the canary (a short
  single-flight lease, compare-and-set under the state lock); competitors
  keep failing fast;
- only a **full-access retrieval success** clears the record — search
  succeeds *during* DataDome episodes and Bloomberg "success" can be a
  teaser, so anything less would be spoofable.

There is deliberately one state machine: article-fetch challenges and guard
canary failures feed the same record (ARCHITECTURE, "Provider containment
and repair"). Hold semantics
stay reserved for account-terminal and incident-review classes.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import get_ident
from typing import Any

from pydantic import Field, ValidationError

from .errors import PersistenceError
from .incidents import IncidentPersistenceError, protect_incident_reference
from .models import FrozenModel
from .private_state import (
    PrivateStateBusyError,
    PrivateStateError,
    atomic_private_write,
    exclusive_lock,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

_MAX_RECORD_BYTES = 16 * 1024
_LOCK_TIMEOUT_SECONDS = 5.0
_DAY = timedelta(hours=24)

#: First cooldown after an observed challenge.
BASE_COOLDOWN_SECONDS = 20 * 60
#: Ceiling for the doubling schedule.
MAX_COOLDOWN_SECONDS = 6 * 60 * 60
#: How long the expiry canary holds its single-flight claim before another
#: caller may try instead (covers a crashed canary).
PROBE_LEASE_SECONDS = 180.0


class DefenseRecord(FrozenModel):
    """The persisted containment state for one provider."""

    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    armed_at: datetime
    active_until: datetime
    #: Cooldown the *next* arm applies, seconds (already doubled).
    next_cooldown_seconds: float = Field(gt=0)
    #: Rolling-day arm timestamps retained for operator-visible history.
    arms: tuple[datetime, ...] = ()
    #: Bounded provenance token: which plane observed the challenge.
    origin: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    #: Single-flight expiry-canary claim; None when no canary is in flight.
    probe_lease_until: datetime | None = None
    incident_id: str | None = Field(default=None, pattern=r"^incident-[0-9a-f]{24}$")
    incident_owner: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,47}$")

    def arms_within_day(self, now: datetime) -> int:
        """Count arms in the rolling 24 h ending at ``now``.

        ``arm`` prunes to this same horizon as it writes, but a record written
        hours ago still carries entries that have since aged out, so a count an
        operator reads has to be taken against the reader's clock rather than
        the last writer's. One arm is an episode; several in a day is a
        provider that is not going to relent on its own.
        """

        horizon = now - _DAY
        return sum(1 for moment in self.arms if moment > horizon)

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


@dataclass(frozen=True)
class DefenseGateDecision:
    """What a retrieval attempt may do right now."""

    allowed: bool
    #: True when this caller proceeds as the post-expiry canary.
    canary: bool = False
    retry_after_seconds: float | None = None


@dataclass(frozen=True)
class DefenseArm:
    """What one observed challenge did to the record."""

    record: DefenseRecord
    #: True when this arm opened an episode rather than extending one. Only
    #: ``arm`` can answer this without a race: the caller would have to read
    #: the record and then write it, and two challenged callers reading "no
    #: record" would both believe they were first.
    first_of_episode: bool


class DefenseState:
    """Durable, locked defense records under the private state root."""

    def __init__(
        self,
        root: Path,
        *,
        utc_now: Callable[[], datetime] | None = None,
        incident_root: Path | None = None,
        incident_owner: str | None = None,
        lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.root = root
        self.incident_root = incident_root
        self.incident_owner = incident_owner
        self._probe_owners: ContextVar[frozenset[tuple[int, int, str]]] = ContextVar(
            "defense_probe_owners", default=frozenset()
        )
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self._lock_timeout_seconds = lock_timeout_seconds

    # -- gate -----------------------------------------------------------

    def gate(self, provider: str) -> DefenseGateDecision:
        """Decide, atomically, whether a retrieval may contact the provider."""

        with self._locked(provider):
            record = self._load_unlocked(provider)
            if record is None:
                return DefenseGateDecision(allowed=True)
            now = self._utc_now()
            if record.active_until > now:
                remaining = (record.active_until - now).total_seconds()
                return DefenseGateDecision(
                    allowed=False, retry_after_seconds=max(1.0, remaining)
                )
            lease = record.probe_lease_until
            if lease is not None and lease > now:
                remaining = (lease - now).total_seconds()
                return DefenseGateDecision(
                    allowed=False, retry_after_seconds=max(1.0, remaining)
                )
            # Expired: claim the single-flight canary under the same lock.
            self._write(
                provider,
                record.model_copy(
                    update={
                        # Reserve the next cooldown before dispatch. A crash,
                        # timeout, or teaser must not buy another attempt when
                        # the shorter in-flight lease expires.
                        "active_until": now
                        + timedelta(seconds=record.next_cooldown_seconds),
                        "probe_lease_until": now
                        + timedelta(seconds=PROBE_LEASE_SECONDS),
                    }
                ),
            )
            return DefenseGateDecision(allowed=True, canary=True)

    @contextmanager
    def probe(self, provider: str) -> Iterator[DefenseGateDecision]:
        """Keep the recovery probe exclusive even if it outlives its lease."""

        owner = (os.getpid(), get_ident(), provider)
        if owner in self._probe_owners.get():
            # Nested verification belongs to this exact synchronous operation;
            # copied thread contexts and forked processes are not owners.
            yield DefenseGateDecision(allowed=True, canary=True)
            return
        with ExitStack() as stack:
            if self._path(provider).exists():
                try:
                    stack.enter_context(
                        exclusive_lock(
                            self._path(provider).with_suffix(".probe.lock"),
                            timeout_seconds=0,
                        )
                    )
                except PrivateStateBusyError:
                    yield DefenseGateDecision(
                        allowed=False, retry_after_seconds=PROBE_LEASE_SECONDS
                    )
                    return
                except PrivateStateError as error:
                    raise PersistenceError(
                        "defense probe lock is unavailable"
                    ) from error
            decision = self.gate(provider)
            if decision.allowed:
                token = self._probe_owners.set(self._probe_owners.get() | {owner})
                stack.callback(self._probe_owners.reset, token)
            yield decision

    # -- transitions ----------------------------------------------------

    def arm(self, provider: str, *, origin: str) -> DefenseRecord:
        """Record one observed challenge; double a cooldown a canary re-tested."""

        return self.arm_observed(provider, origin=origin).record

    def arm_observed(self, provider: str, *, origin: str) -> DefenseArm:
        """Arm, and report whether this opened the episode.

        Callers that hold evidence use the distinction to retain a capsule for
        the first refusal of a configuration and none for the repeats after it:
        the first carries information, and a capsule per challenged canary
        would pile up through an episode.
        """

        with self._locked(provider):
            now = self._utc_now()
            prior = self._load_unlocked(provider)
            if (
                prior is not None
                and prior.active_until > now
                and prior.probe_lease_until is None
            ):
                # The cooldown is running and no expiry canary has been
                # dispatched since it was armed, so the gate has let nothing
                # through: this challenge came from a request already in
                # flight when the episode opened. It carries no evidence that
                # backing off failed, so it neither doubles nor extends the
                # cooldown, and it is not another arm in the day's history.
                # Only a canary's challenge (lease set by ``gate``) escalates.
                return DefenseArm(record=self._visible(prior), first_of_episode=False)
            horizon = now - _DAY
            arms = tuple(
                moment for moment in (prior.arms if prior else ()) if moment > horizon
            ) + (now,)
            if prior is None:
                cooldown = float(BASE_COOLDOWN_SECONDS)
            else:
                cooldown = min(prior.next_cooldown_seconds, float(MAX_COOLDOWN_SECONDS))
            record = DefenseRecord(
                provider=provider,
                armed_at=now,
                active_until=now + timedelta(seconds=cooldown),
                next_cooldown_seconds=min(cooldown * 2.0, float(MAX_COOLDOWN_SECONDS)),
                arms=arms,
                origin=origin,
                probe_lease_until=None,
                incident_id=prior.incident_id if prior else None,
                incident_owner=prior.incident_owner if prior else None,
            )
            self._write(provider, record)
        return DefenseArm(record=self._visible(record), first_of_episode=prior is None)

    def clear(self, provider: str) -> bool:
        """Remove containment after a full-access success. True if one existed."""

        # Cheap short-circuit: the common healthy path must not pay a lock.
        if not self._path(provider).exists():
            return False
        with self._locked(provider):
            path = self._path(provider)
            existed = path.exists()
            if existed:
                try:
                    path.unlink()
                except OSError as error:
                    raise PersistenceError("defense record removal failed") from error
        return existed

    def attach_incident(self, provider: str, incident_id: str) -> None:
        """Attach the first available capture without replacing episode evidence."""
        try:
            with (
                protect_incident_reference(self.incident_root, provider, incident_id),
                self._locked(provider),
            ):
                record = self._load_unlocked(provider)
                if record is not None and record.incident_id is None:
                    updated = record.model_dump()
                    updated["incident_id"] = incident_id
                    updated["incident_owner"] = self.incident_owner
                    self._write(provider, DefenseRecord.model_validate(updated))
        except (OSError, IncidentPersistenceError, ValueError) as error:
            raise PersistenceError("defense evidence publication failed") from error

    def status(self, provider: str) -> DefenseRecord | None:
        if not self._path(provider).exists():
            return None
        with self._locked(provider):
            record = self._load_unlocked(provider)
            return self._visible(record) if record is not None else None

    def _visible(self, record: DefenseRecord) -> DefenseRecord:
        """Account containment is shared; request evidence remains private."""
        if record.incident_owner == self.incident_owner:
            return record
        return record.model_copy(update={"incident_id": None, "incident_owner": None})

    # -- persistence ----------------------------------------------------

    @contextmanager
    def _locked(self, provider: str) -> Iterator[None]:
        try:
            with exclusive_lock(
                self._path(provider).with_suffix(".lock"),
                timeout_seconds=self._lock_timeout_seconds,
            ):
                yield
        except PrivateStateError as error:
            raise PersistenceError("defense state is unavailable") from error

    def _path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise PersistenceError("defense provider key is invalid")
        return self.root / f"{provider}.defense.json"

    def _write(self, provider: str, record: DefenseRecord) -> None:
        payload = json.dumps(record.model_dump(mode="json"), sort_keys=True).encode()
        try:
            atomic_private_write(self._path(provider), payload)
        except PrivateStateError as error:
            raise PersistenceError("defense record write failed") from error

    def _load_unlocked(self, provider: str) -> DefenseRecord | None:
        path = self._path(provider)
        if path.is_symlink():
            raise PersistenceError("defense record must be a regular file")
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PersistenceError("defense record is unreadable") from error
        if len(raw) > _MAX_RECORD_BYTES:
            raise PersistenceError("defense record is oversized")
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("defense record must be an object")
            current = {
                key: value
                for key, value in payload.items()
                if key in DefenseRecord.model_fields
            }
            return DefenseRecord.model_validate(current)
        except (ValueError, ValidationError) as error:
            raise PersistenceError("defense record is malformed") from error


__all__ = [
    "BASE_COOLDOWN_SECONDS",
    "MAX_COOLDOWN_SECONDS",
    "PROBE_LEASE_SECONDS",
    "DefenseArm",
    "DefenseGateDecision",
    "DefenseRecord",
    "DefenseState",
]
