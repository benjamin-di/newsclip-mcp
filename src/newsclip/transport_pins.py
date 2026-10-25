"""Runtime transport-pin state for providers with declared escalation (R8).

A pinned curl fingerprint is a measurement of an adaptive edge, and it
decays. This store carries what the deployment has measured since release:
the rot signal an escalation records when the pinned profile is refused
while the browser serves, and the runtime pin the keeper's slow drip
promotes once a candidate has proven itself. The TOML pin remains the
fallback whenever this state is absent, unreadable, or names a profile
outside the typed allowlist — automation may *select* among measured names,
never invent one.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, Field

from .errors import PersistenceError
from .models import HTTP_IMPERSONATION_PROFILES, FrozenModel
from .private_state import atomic_private_write, fsync_directory
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

_MAX_STATE_BYTES = 8 * 1024
_LOCK_TIMEOUT_SECONDS = 2.0
#: Upper bound on how long a cached pin answer may outlive a stamp that
#: failed to change. The drip promotes at most once an hour, so this only
#: bounds a theoretical stamp collision.
_MAX_CACHE_AGE_SECONDS = 60.0


class TransportPinState(FrozenModel):
    schema_version: Literal[1] = 1
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    #: The promoted runtime pin, or None when the TOML pin governs.
    active_profile: str | None = None
    pinned_at: AwareDatetime | None = None
    #: How many separate full passes promoted this pin. One pass cannot tell
    #: a good profile from a stochastic one, which is why promotion needs
    #: several (the 07-24 matrix rejected a profile for exactly that).
    passes_observed: int = Field(default=0, ge=0)
    #: Rot: the pinned profile was refused while the browser served (R8).
    rot_observed_at: AwareDatetime | None = None
    rot_profile: str | None = None
    #: The candidate the slow drip is currently measuring, and how many
    #: separate passes it has returned full. Promotion needs three.
    candidate_profile: str | None = None
    candidate_passes: int = Field(default=0, ge=0)
    #: When the last candidate was measured. The cadence bound lives in the
    #: state, not in the scheduler: `auth keep` and ops `heal` both reach
    #: the drip, so "one request per hour" has to be a property of the
    #: mechanism rather than of the timer that usually drives it.
    candidate_probed_at: AwareDatetime | None = None
    #: Candidates that failed their sweep since this rot signal opened. They
    #: are not retried until a human widens the allowlist or a new rot event
    #: resets the drip.
    exhausted_profiles: tuple[str, ...] = ()
    #: Set when every candidate has failed. The drip parks here: escalation
    #: stays the steady state and health names the human decision, rather
    #: than an hourly probe running forever with nothing left to find.
    pool_exhausted_at: AwareDatetime | None = None


class TransportPinError(PersistenceError):
    """Transport-pin state could not be read or committed safely."""


class TransportPinStore:
    """Process-safe per-provider pin state under ``state/transport-pins``."""

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

    def load(self, provider: str) -> TransportPinState | None:
        """Read the state, or None when absent. Invalid state raises."""

        path = self._state_path(provider)
        if path.is_symlink():
            raise TransportPinError("transport pin state is invalid")
        if not path.exists():
            return None
        try:
            if not path.is_file():
                raise TransportPinError("transport pin state is invalid")
            state = TransportPinState.model_validate_json(_read_bounded(path))
        except (OSError, ValueError) as error:
            raise TransportPinError("transport pin state is invalid") from error
        if state.provider != provider:
            raise TransportPinError("transport pin state is inconsistent")
        return state

    def record_rot(self, provider: str, *, profile: str) -> TransportPinState:
        """Record that ``profile`` was refused while the browser served.

        Rot is observed on *every* challenged fetch while the pin stays
        rotted, not once — the keeper's own watch re-escalates each cycle.
        So a repeat of the same signal must refresh the timestamp and
        nothing else: wiping the sweep would restart the drip hourly, and
        neither promotion nor pool exhaustion could ever be reached. Only a
        rot naming a *different* profile is a new event, and that resets the
        sweep because the pool's exclusions were computed against the old
        one.

        A rotted profile that is also the active runtime pin stops
        governing: a pin measured dead must not keep selecting the transport
        it was measured dead on. Unreadable prior state is replaced rather
        than honored — the rot signal is the fact the drip heals from, and a
        corrupt file must not suppress it.
        """

        with self._locked(provider):
            try:
                state = self.load(provider)
            except TransportPinError:
                state = None
            if state is None:
                state = TransportPinState(provider=provider)
            update: dict[str, object] = {
                "rot_observed_at": self._utc_now(),
                "rot_profile": profile,
            }
            if state.rot_profile != profile:
                update |= {
                    "candidate_profile": None,
                    "candidate_passes": 0,
                    "exhausted_profiles": (),
                    "pool_exhausted_at": None,
                }
            if state.active_profile == profile:
                update |= {
                    "active_profile": None,
                    "pinned_at": None,
                    "passes_observed": 0,
                }
            updated = state.model_copy(update=update)
            self._write_locked(provider, updated)
        return updated

    def promote(
        self,
        provider: str,
        *,
        profile: str,
        passes: int,
    ) -> TransportPinState:
        """Promote a measured candidate to the runtime pin.

        The allowlist is enforced here rather than trusted from the caller:
        this is the one place a name becomes the transport a real fetch uses,
        so an out-of-allowlist name must be refused at the boundary, not
        merely ignored later by the resolver.
        """

        if profile not in HTTP_IMPERSONATION_PROFILES:
            raise TransportPinError("transport pin profile is outside the allowlist")
        if passes < 1:
            raise TransportPinError("transport pin promotion requires observed passes")
        with self._locked(provider):
            updated = TransportPinState(
                provider=provider,
                active_profile=profile,
                pinned_at=self._utc_now(),
                passes_observed=passes,
            )
            self._write_locked(provider, updated)
        return updated

    def record_candidate_pass(
        self,
        provider: str,
        *,
        profile: str,
        promote_at: int,
    ) -> TransportPinState:
        """Count one full pass for a candidate, promoting on the third.

        Three passes rather than one because the 07-24 matrix rejected a
        profile for being stochastic, and a single pass cannot tell that
        apart from a good one.
        """

        if profile not in HTTP_IMPERSONATION_PROFILES:
            raise TransportPinError("transport pin profile is outside the allowlist")
        with self._locked(provider):
            state = self._load_or_blank(provider)
            now = self._utc_now()
            passes = (
                state.candidate_passes + 1 if state.candidate_profile == profile else 1
            )
            if passes >= promote_at:
                updated = TransportPinState(
                    provider=provider,
                    active_profile=profile,
                    pinned_at=now,
                    passes_observed=passes,
                )
            else:
                updated = state.model_copy(
                    update={
                        "candidate_profile": profile,
                        "candidate_passes": passes,
                        "candidate_probed_at": now,
                    }
                )
            self._write_locked(provider, updated)
        return updated

    def record_candidate_failure(
        self,
        provider: str,
        *,
        profile: str,
    ) -> TransportPinState:
        """Retire a candidate that did not serve. Its passes do not carry."""

        if profile not in HTTP_IMPERSONATION_PROFILES:
            raise TransportPinError("transport pin profile is outside the allowlist")
        with self._locked(provider):
            state = self._load_or_blank(provider)
            exhausted = tuple(
                sorted({*state.exhausted_profiles, profile}),
            )
            updated = state.model_copy(
                update={
                    "candidate_profile": None,
                    "candidate_passes": 0,
                    "candidate_probed_at": self._utc_now(),
                    "exhausted_profiles": exhausted,
                }
            )
            self._write_locked(provider, updated)
        return updated

    def record_pool_exhausted(self, provider: str) -> TransportPinState:
        """Park the drip: nothing measurable is left to try."""

        with self._locked(provider):
            state = self._load_or_blank(provider)
            if state.pool_exhausted_at is not None:
                return state
            updated = state.model_copy(
                update={
                    "candidate_profile": None,
                    "candidate_passes": 0,
                    "pool_exhausted_at": self._utc_now(),
                }
            )
            self._write_locked(provider, updated)
        return updated

    def _load_or_blank(self, provider: str) -> TransportPinState:
        try:
            state = self.load(provider)
        except TransportPinError:
            state = None
        return state or TransportPinState(provider=provider)

    def now(self) -> datetime:
        return self._utc_now()

    def state_path(self, provider: str) -> Path:
        """The file a resolver stats to detect a promotion without a restart."""

        return self._state_path(provider)

    def _write_locked(self, provider: str, state: TransportPinState) -> None:
        payload = (
            json.dumps(
                state.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        if len(payload) > _MAX_STATE_BYTES:
            raise TransportPinError("transport pin state exceeds its size limit")
        try:
            atomic_private_write(self._state_path(provider), payload)
        except PersistenceError:
            raise
        except OSError as error:
            raise TransportPinError("transport pin state write failed") from error

    @contextmanager
    def _locked(self, provider: str) -> Iterator[None]:
        if not is_provider_key(provider):
            raise TransportPinError("transport pin provider key is invalid")
        self._ensure_root()
        lock_path = self.root / f"{provider}.lock"
        descriptor: int | None = None
        acquired = False
        try:
            descriptor = os.open(
                lock_path,
                os.O_CREAT
                | os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("transport pin lock is not regular")
            os.fchmod(descriptor, 0o600)
            deadline = time.monotonic() + self._lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TransportPinError(
                            "transport pin state is contended"
                        ) from None
                    time.sleep(0.05)
            yield
        except TransportPinError:
            raise
        except OSError as error:
            raise TransportPinError("transport pin lock failed") from error
        finally:
            if descriptor is not None:
                try:
                    if acquired:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _state_path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise TransportPinError("transport pin provider key is invalid")
        return self.root / f"{provider}.json"

    def _ensure_root(self) -> None:
        try:
            if self.root.is_symlink():
                raise TransportPinError("transport pin root is invalid")
            existed = self.root.exists()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not self.root.is_dir():
                raise TransportPinError("transport pin root is invalid")
            os.chmod(self.root, 0o700)
            if not existed:
                fsync_directory(self.root.parent)
        except OSError as error:
            raise TransportPinError("transport pin root is unavailable") from error


#: How long a rot signal sends retrieval straight to the browser. Leading
#: every read with a profile the edge already refused is retrying into an
#: active defense: Reuters spent six days (2026-10-03 to 10-09) pairing a
#: refused curl request with a browser request from the same IP, then the
#: browser was challenged too. Once the window lapses one read re-tests the
#: pin; a fresh refusal renews the window, so recovery costs about one
#: refused request a week.
BROWSER_FIRST_WINDOW = timedelta(days=7)


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    stamp: tuple[int, int, int] | None
    profile: str | None
    rot_observed_at: datetime | None
    read_at: float


class TransportPinResolver:
    """Resolve the runtime pin per fetch, re-reading only when it changes.

    Reading once per process is not enough. Composition builds the
    impersonation map at construction, the serving MCP process caches one
    service for its lifetime, and the keeper promotes from a *different*
    container over a shared state mount — so a pin read at startup would
    leave the serving process on the rotted profile until someone restarted
    it, which is precisely where the fast path matters. The stat is one
    syscall per fetch against a file that changes at most a few times a week;
    the JSON parse happens only when the file actually moved.
    """

    def __init__(
        self,
        store: TransportPinStore,
        *,
        providers_by_host: Mapping[str, str],
        max_cache_age_seconds: float = _MAX_CACHE_AGE_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._providers_by_host = {
            host.lower(): provider for host, provider in providers_by_host.items()
        }
        self._max_cache_age_seconds = max_cache_age_seconds
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._cache: dict[str, _CacheEntry] = {}

    def for_host(self, host: str) -> str | None:
        """The promoted profile governing ``host``, or None for the TOML pin."""

        provider = self._providers_by_host.get(host.lower())
        if provider is None:
            return None
        return self.for_provider(provider)

    def for_provider(self, provider: str) -> str | None:
        return self._entry(provider).profile

    def browser_first(self, provider: str) -> bool:
        """Whether a standing rot signal should skip the refused HTTP leg.

        True only while no runtime pin has been promoted since the rot and
        the signal is younger than :data:`BROWSER_FIRST_WINDOW`. Unreadable
        or absent state answers False: the declared transport stays the
        default, exactly as for the pin itself.
        """

        entry = self._entry(provider)
        if entry.profile is not None or entry.rot_observed_at is None:
            return False
        age = self._store.now() - entry.rot_observed_at
        # A marker from the future is clock skew; treat it as fresh.
        return age < BROWSER_FIRST_WINDOW

    def _entry(self, provider: str) -> _CacheEntry:
        try:
            path = self._store.state_path(provider)
        except TransportPinError:
            return _CacheEntry(
                stamp=None, profile=None, rot_observed_at=None, read_at=0.0
            )
        stamp: tuple[int, int, int] | None
        try:
            info = os.stat(path)
            stamp = (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            stamp = None
        now = self._monotonic()
        with self._lock:
            cached = self._cache.get(provider)
            if (
                cached is not None
                and cached.stamp == stamp
                # A stamp can repeat in theory — the kernel's mtime clock is
                # coarse, two allowlist names share a length, and a freed
                # inode can be reused — so the cache also expires by age. At
                # the drip's hourly cadence this never fires in practice; it
                # bounds the worst case rather than the common one.
                and (now - cached.read_at) < self._max_cache_age_seconds
            ):
                return cached
        profile: str | None = None
        rot_observed_at: datetime | None = None
        if stamp is not None:
            try:
                state = self._store.load(provider)
            except TransportPinError:
                # Unreadable state falls back to the TOML pin rather than
                # failing the fetch: the definition's pin is always a valid
                # answer, and a corrupt runtime file must not take retrieval
                # down with it.
                state = None
            if state is not None:
                if state.active_profile in HTTP_IMPERSONATION_PROFILES:
                    profile = state.active_profile
                rot_observed_at = state.rot_observed_at
        entry = _CacheEntry(
            stamp=stamp,
            profile=profile,
            rot_observed_at=rot_observed_at,
            read_at=now,
        )
        with self._lock:
            self._cache[provider] = entry
        return entry


#: Separate full passes a candidate must return before it is promoted.
CANDIDATE_PROMOTION_PASSES = 3


#: Minimum wall time between two candidate measurements for one provider.
#: The keeper runs hourly, but `auth keep` and ops `heal` reach the same
#: code, so the interval is enforced here rather than assumed of the timer.
CANDIDATE_PROBE_INTERVAL_SECONDS = 3600.0


def drip_is_due(
    state: TransportPinState | None,
    *,
    now: datetime | None = None,
    min_interval_seconds: float = CANDIDATE_PROBE_INTERVAL_SECONDS,
) -> bool:
    """Whether a rot signal stands, the pool is open, and the cadence allows.

    The drip runs only to heal a measured rot. A healthy pin, no rot signal,
    or an exhausted pool all mean the keeper contacts nothing this cycle.
    """

    if state is None:
        return False
    if state.rot_observed_at is None or state.pool_exhausted_at is not None:
        return False
    if state.active_profile is not None:
        return False
    if state.candidate_probed_at is not None and now is not None:
        elapsed = (now - state.candidate_probed_at).total_seconds()
        # A marker from the future is clock skew; fail open rather than
        # letting one bad write suppress the drip until the clock catches up.
        if 0 <= elapsed < min_interval_seconds:
            return False
    return True


def next_candidate(
    state: TransportPinState | None,
    *,
    declared_profile: str,
) -> str | None:
    """The one profile to measure this cycle, or None when none is left.

    Selection is deterministic and narrow: an in-flight candidate keeps its
    turn until it passes or fails, and every other name is tried at most
    once per rot signal. The declared pin and the profile that just rotted
    are both excluded — re-measuring a profile the edge just refused is the
    burst probing this design exists to avoid.
    """

    if state is None:
        return None
    if state.candidate_profile is not None:
        return state.candidate_profile
    excluded = {
        declared_profile,
        *(name for name in (state.rot_profile,) if name is not None),
        *state.exhausted_profiles,
    }
    remaining = sorted(HTTP_IMPERSONATION_PROFILES - excluded)
    return remaining[0] if remaining else None


class DripOutcome(StrEnum):
    """What one cycle's drip did, for the keeper's outcome record."""

    IDLE = "idle"
    CANDIDATE_PASS = "candidate_pass"
    CANDIDATE_FAILED = "candidate_failed"
    PROMOTED = "promoted"
    POOL_EXHAUSTED = "pool_exhausted"


class TransportDrip:
    """Measure one candidate fingerprint per cycle while a rot signal stands.

    The whole point is smallness: one request per hour against the canary
    article, three passes before a promotion, and a full stop once the pin
    is healthy or the pool is spent. Cycling profiles on the refusal itself
    would be retrying into an active defense from the one IP every session
    is pinned to, which is what stays forbidden.
    """

    def __init__(
        self,
        store: TransportPinStore,
        *,
        declared_profiles: Mapping[str, str],
        probe: Callable[[str, str], bool],
        promote_at: int = CANDIDATE_PROMOTION_PASSES,
        min_interval_seconds: float = CANDIDATE_PROBE_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._declared_profiles = dict(declared_profiles)
        self._probe = probe
        self._promote_at = promote_at
        self._min_interval_seconds = min_interval_seconds

    def drip(self, provider: str) -> DripOutcome:
        declared = self._declared_profiles.get(provider)
        if declared is None:
            return DripOutcome.IDLE
        try:
            state = self._store.load(provider)
        except TransportPinError:
            # Unreadable state is a local fault, not a licence to probe.
            return DripOutcome.IDLE
        if not drip_is_due(
            state,
            now=self._store.now(),
            min_interval_seconds=self._min_interval_seconds,
        ):
            return DripOutcome.IDLE
        candidate = next_candidate(state, declared_profile=declared)
        if candidate is None:
            self._store.record_pool_exhausted(provider)
            return DripOutcome.POOL_EXHAUSTED
        if self._probe(provider, candidate):
            updated = self._store.record_candidate_pass(
                provider,
                profile=candidate,
                promote_at=self._promote_at,
            )
            if updated.active_profile == candidate:
                return DripOutcome.PROMOTED
            return DripOutcome.CANDIDATE_PASS
        self._store.record_candidate_failure(provider, profile=candidate)
        return DripOutcome.CANDIDATE_FAILED


def _read_bounded(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_STATE_BYTES:
            raise OSError("transport pin state is invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)


__all__ = [
    "BROWSER_FIRST_WINDOW",
    "CANDIDATE_PROBE_INTERVAL_SECONDS",
    "CANDIDATE_PROMOTION_PASSES",
    "DripOutcome",
    "TransportDrip",
    "TransportPinError",
    "TransportPinResolver",
    "TransportPinState",
    "TransportPinStore",
    "drip_is_due",
    "next_candidate",
]
