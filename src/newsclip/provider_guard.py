"""Process-safe provider monitoring with one durable hold per provider."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import AwareDatetime, Field, model_validator

from .errors import PersistenceError
from .incidents import IncidentPersistenceError, protect_incident_reference
from .models import FrozenModel, SessionDisposition
from .private_state import (
    PrivateStateError,
    atomic_private_write,
    fsync_directory,
)
from .provenance import BuildIdentity
from .provider_check import (
    ProviderCheckFailure,
    ProviderCheckObservation,
    ProviderCheckResult,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key
from .providers import Provider, ProviderRegistry

_HOLD_ID_PATTERN = r"^guard-[0-9a-f]{32}$"
_INCIDENT_ID_PATTERN = r"^incident-[0-9a-f]{24}$"
_DIAGNOSTIC_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_FOLLOW_UP_ERROR_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_MAX_HOLD_BYTES = 64 * 1024
_MAX_OBSERVATION_BYTES = 16 * 1024
_MAX_CANARY_STATE_BYTES = 4 * 1024
_LOCK_TIMEOUT_SECONDS = 2.0

#: One canary per provider per 24h under an incident-review hold, and one
#: auto-clear per 24h (R9). Both bounds live in the store, so whichever
#: scheduled cadence reaches the entry point, the provider sees at most one
#: daily request under a hold.
_INCIDENT_CANARY_INTERVAL_SECONDS = 24 * 3600.0


class GuardAction(StrEnum):
    HEALTHY = "healthy"
    TRANSIENT_FAILURE = "transient_failure"
    CHECK_IN_PROGRESS = "check_in_progress"
    PROVIDER_HOLD = "provider_hold"
    OPERATOR_ACTION = "operator_action"
    SESSION_PROMOTION_REQUIRED = "session_promotion_required"
    LOCAL_REPAIR_REQUIRED = "local_repair_required"
    WAIT_FOR_SESSION_EVIDENCE = "wait_for_session_evidence"
    INCIDENT_REVIEW_REQUIRED = "incident_review_required"


_DURABLE_ACTIONS = {
    GuardAction.PROVIDER_HOLD,
    GuardAction.OPERATOR_ACTION,
    GuardAction.SESSION_PROMOTION_REQUIRED,
    GuardAction.LOCAL_REPAIR_REQUIRED,
    GuardAction.WAIT_FOR_SESSION_EVIDENCE,
    GuardAction.INCIDENT_REVIEW_REQUIRED,
}

#: Failures whose durable remedy is incident review: the provider answered,
#: but its search contract or article content did not meet the check. The
#: class follows the failure, not whether evidence capture succeeded.
_INCIDENT_REVIEW_FAILURES = frozenset(
    {
        ProviderCheckFailure.SEARCH_CONTRACT,
        ProviderCheckFailure.EXPECTED_RESULT_MISSING,
        ProviderCheckFailure.CONTENT_NOT_FULL,
    }
)

#: Canary failures that name session renewal or promotion as the remedy.
_SESSION_EVIDENCE_FAILURES = frozenset(
    {
        ProviderCheckFailure.SESSION_REQUIRED,
        ProviderCheckFailure.SESSION_DEAD,
    }
)

#: Hold classes whose named remedy is session renewal or promotion. A positive
#: live verification of a session IS that remedy delivered, so these — and
#: only these — clear on verified session evidence (ARCHITECTURE, "Session
#: upkeep").
SESSION_EVIDENCE_ACTIONS = frozenset(
    {
        GuardAction.WAIT_FOR_SESSION_EVIDENCE,
        GuardAction.SESSION_PROMOTION_REQUIRED,
    }
)


class ProviderHold(FrozenModel):
    """The single durable reason scheduled checks are suppressed."""

    schema_version: Literal[1] = 1
    hold_id: str = Field(pattern=_HOLD_ID_PATTERN)
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    occurred_at: AwareDatetime
    action: GuardAction
    failure: ProviderCheckFailure
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    session_evidence_required: bool = False
    session_disposition: SessionDisposition | None = None
    diagnostic_id: str | None = Field(
        default=None,
        pattern=_DIAGNOSTIC_ID_PATTERN,
    )
    build_identity: BuildIdentity

    @model_validator(mode="after")
    def validate_hold(self) -> ProviderHold:
        if self.action not in _DURABLE_ACTIONS:
            raise ValueError("provider hold action is not durable")
        # An incident-review hold normally names its retained capsule, but
        # capture is best effort: a failed capture leaves the same review
        # class with evidence reported missing, not a different remedy.
        if (
            self.action is GuardAction.INCIDENT_REVIEW_REQUIRED
            and self.failure not in _INCIDENT_REVIEW_FAILURES
        ):
            raise ValueError("provider hold incident is inconsistent")
        if (
            self.action is GuardAction.INCIDENT_REVIEW_REQUIRED
            and self.failure is ProviderCheckFailure.CONTENT_NOT_FULL
            and self.session_evidence_required
            and self.session_disposition is not SessionDisposition.VERIFIED
        ):
            raise ValueError("content incident lacks verified session evidence")
        return self


class CurrentHoldHealth(FrozenModel):
    """Advisory current brake, independent of historical article recovery.

    Canary timestamps describe reservation and eligibility, never permission to
    dispatch. The guard rechecks under its lock before any provider contact.
    """

    hold_id: str = Field(pattern=_HOLD_ID_PATTERN)
    action: GuardAction
    failure: ProviderCheckFailure
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    held_operation: Literal["provider_check"] = "provider_check"
    occurred_at: AwareDatetime
    last_canary_at: AwareDatetime | None = None
    next_eligible_canary_at: AwareDatetime | None = None


class GuardResult(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    guarded: bool = True
    check: ProviderCheckResult | None = None
    action: GuardAction
    hold_id: str | None = Field(default=None, pattern=_HOLD_ID_PATTERN)
    incident_id: str | None = Field(default=None, pattern=_INCIDENT_ID_PATTERN)
    diagnostic_id: str | None = Field(
        default=None,
        pattern=_DIAGNOSTIC_ID_PATTERN,
    )

    @model_validator(mode="after")
    def validate_result(self) -> GuardResult:
        if self.check is not None and self.provider != self.check.provider:
            raise ValueError("provider guard result is inconsistent")
        if self.action not in _DURABLE_ACTIONS and self.hold_id is not None:
            raise ValueError("provider guard hold is inconsistent")
        if (
            self.action in _DURABLE_ACTIONS
            and self.action is not GuardAction.LOCAL_REPAIR_REQUIRED
            and self.hold_id is None
        ):
            raise ValueError("provider guard hold is missing")
        if self.incident_id is not None and (
            self.check is None or self.incident_id != self.check.incident_id
        ):
            raise ValueError("provider guard incident does not match its check")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class GuardAcknowledgement(FrozenModel):
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    requested_hold_id: str = Field(pattern=_HOLD_ID_PATTERN)
    acknowledged: bool
    current_hold_id: str | None = Field(default=None, pattern=_HOLD_ID_PATTERN)

    @model_validator(mode="after")
    def validate_acknowledgement(self) -> GuardAcknowledgement:
        if self.acknowledged and self.current_hold_id is not None:
            raise ValueError("acknowledged provider guard cannot remain held")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class AcknowledgementReport(FrozenModel):
    """Both facts an acknowledgement produces: the clear, then fresh evidence.

    Clearing a hold re-enables scheduled checks but leaves the last serving
    evidence as old as the hold made it, so health honestly reports `unknown`
    until something re-measures the provider (Economist sat there for a day,
    2026-08-01). The follow-up check is the action a reviewer should always
    take next; the guard performs it implicitly after a successful
    compare-and-clear. A follow-up failure never un-acknowledges — the clear
    stands and the failure is reported beside it. A follow-up that classifies
    a durable failure writes a fresh hold; "acknowledged, then immediately
    re-held" is the honest outcome when the condition still stands.
    """

    acknowledgement: GuardAcknowledgement
    follow_up: GuardResult | None = None
    follow_up_error: str | None = Field(
        default=None,
        pattern=_FOLLOW_UP_ERROR_PATTERN,
    )

    @model_validator(mode="after")
    def validate_report(self) -> AcknowledgementReport:
        if self.acknowledgement.acknowledged:
            if (self.follow_up is None) == (self.follow_up_error is None):
                raise ValueError(
                    "acknowledged report carries exactly one follow-up fact"
                )
        elif self.follow_up is not None or self.follow_up_error is not None:
            raise ValueError("unacknowledged report cannot carry a follow-up")
        return self

    def public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


class IncidentCanaryState(FrozenModel):
    """Cadence state for the one daily canary an incident-review hold permits.

    Kept beside the hold rather than on the observation because observations
    are overwritten by every guarded check, and the auto-clear bound must
    survive them (R9).
    """

    schema_version: Literal[1] = 1
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    last_canary_at: AwareDatetime | None = None
    last_auto_clear_at: AwareDatetime | None = None


class ProviderGuardPersistenceError(PersistenceError):
    """Provider guard state could not be read or committed safely."""


class ProviderGuardBusyError(ProviderGuardPersistenceError):
    """Another process already owns this provider's scheduled check."""


class ProviderGuardStore:
    """Private hold state serialized by one provider-scoped process lock."""

    def __init__(
        self,
        root: Path,
        *,
        build_identity: BuildIdentity,
        diagnostic_id: str | None = None,
        incident_root: Path | None = None,
        utc_now=None,
        lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.root = Path(root)
        self.incident_root = incident_root
        self.build_identity = build_identity
        if diagnostic_id is not None and not _valid_diagnostic_id(diagnostic_id):
            raise ValueError("provider guard diagnostic identifier is invalid")
        self.diagnostic_id = diagnostic_id
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        timeout = float(lock_timeout_seconds)
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("provider guard lock timeout is invalid")
        self._lock_timeout_seconds = timeout

    @contextmanager
    def locked(self, provider: str) -> Iterator[None]:
        if not is_provider_key(provider):
            raise ProviderGuardPersistenceError("provider guard key is invalid")
        self._ensure_root()
        descriptor: int | None = None
        acquired = False
        try:
            descriptor = os.open(
                self.root / f"{provider}.lock",
                os.O_CREAT
                | os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("provider guard lock is not regular")
            os.fchmod(descriptor, 0o600)
            deadline = time.monotonic() + self._lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ProviderGuardBusyError(
                            "provider guard check is already running"
                        ) from None
                    time.sleep(0.05)
            yield
        except ProviderGuardPersistenceError:
            raise
        except OSError as error:
            raise ProviderGuardPersistenceError("provider guard lock failed") from error
        finally:
            if descriptor is not None:
                try:
                    if acquired:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def load_locked(self, provider: str) -> ProviderHold | None:
        path = self._hold_path(provider)
        if path.is_symlink():
            raise ProviderGuardPersistenceError("provider guard hold is invalid")
        if not path.exists():
            return None
        try:
            if not path.is_file():
                raise ProviderGuardPersistenceError("provider guard hold is invalid")
            hold = ProviderHold.model_validate_json(_read_bounded_hold(path))
        except FileNotFoundError:
            # Cleared between the existence check and the open: an unlocked
            # reader sees the unlink as the absence it is.
            return None
        except (OSError, ValueError) as error:
            raise ProviderGuardPersistenceError(
                "provider guard hold is invalid"
            ) from error
        if hold.provider != provider:
            raise ProviderGuardPersistenceError("provider guard hold is inconsistent")
        return hold

    def load_observation_locked(
        self,
        provider: str,
    ) -> ProviderCheckObservation | None:
        path = self._observation_path(provider)
        if path.is_symlink():
            raise ProviderGuardPersistenceError("provider check observation is invalid")
        if not path.exists():
            return None
        try:
            if not path.is_file():
                raise ProviderGuardPersistenceError(
                    "provider check observation is invalid"
                )
            observation = ProviderCheckObservation.model_validate_json(
                _read_bounded(path, max_bytes=_MAX_OBSERVATION_BYTES)
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise ProviderGuardPersistenceError(
                "provider check observation is invalid"
            ) from error
        if observation.provider != provider:
            raise ProviderGuardPersistenceError(
                "provider check observation is inconsistent"
            )
        return observation

    def write_locked(
        self,
        *,
        provider: str,
        action: GuardAction,
        check: ProviderCheckResult,
        session_evidence_required: bool,
    ) -> ProviderHold:
        hold = ProviderHold(
            hold_id=f"guard-{uuid4().hex}",
            provider=provider,
            occurred_at=self._utc_now(),
            action=action,
            failure=_required_failure(check),
            incident_id=check.incident_id,
            session_evidence_required=session_evidence_required,
            session_disposition=check.session_disposition,
            diagnostic_id=self.diagnostic_id,
            build_identity=self.build_identity,
        )
        payload = (
            json.dumps(
                hold.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        if len(payload) > _MAX_HOLD_BYTES:
            raise ProviderGuardPersistenceError(
                "provider guard hold exceeds its size limit"
            )
        try:
            with protect_incident_reference(
                self.incident_root, provider, hold.incident_id
            ):
                _atomic_private_write(self._hold_path(provider), payload)
        except (OSError, IncidentPersistenceError, ValueError) as error:
            raise ProviderGuardPersistenceError(
                "provider evidence publication failed"
            ) from error
        return hold

    def write_observation_locked(
        self,
        *,
        provider: str,
        check: ProviderCheckResult,
    ) -> ProviderCheckObservation:
        observation = ProviderCheckObservation(
            provider=provider,
            checked_at=self._utc_now(),
            check=check,
        )
        payload = (
            json.dumps(
                observation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        if len(payload) > _MAX_OBSERVATION_BYTES:
            raise ProviderGuardPersistenceError(
                "provider check observation exceeds its size limit"
            )
        _atomic_private_write(self._observation_path(provider), payload)
        return observation

    def clear_locked(self, provider: str) -> None:
        path = self._hold_path(provider)
        try:
            if path.is_symlink():
                raise ProviderGuardPersistenceError("provider guard hold is invalid")
            path.unlink(missing_ok=True)
            _fsync_directory(self.root)
        except OSError as error:
            raise ProviderGuardPersistenceError(
                "provider guard hold clear failed"
            ) from error

    def now(self) -> datetime:
        return self._utc_now()

    def load_incident_canary_locked(
        self,
        provider: str,
    ) -> IncidentCanaryState | None:
        path = self._incident_canary_path(provider)
        if path.is_symlink():
            raise ProviderGuardPersistenceError("incident canary state is invalid")
        if not path.exists():
            return None
        try:
            if not path.is_file():
                raise ProviderGuardPersistenceError("incident canary state is invalid")
            state = IncidentCanaryState.model_validate_json(
                _read_bounded(path, max_bytes=_MAX_CANARY_STATE_BYTES)
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise ProviderGuardPersistenceError(
                "incident canary state is invalid"
            ) from error
        if state.provider != provider:
            raise ProviderGuardPersistenceError("incident canary state is inconsistent")
        return state

    def write_incident_canary_locked(
        self,
        *,
        provider: str,
        state: IncidentCanaryState,
    ) -> None:
        if state.provider != provider:
            raise ProviderGuardPersistenceError("incident canary state is inconsistent")
        payload = (
            json.dumps(
                state.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        if len(payload) > _MAX_CANARY_STATE_BYTES:
            raise ProviderGuardPersistenceError(
                "incident canary state exceeds its size limit"
            )
        _atomic_private_write(self._incident_canary_path(provider), payload)

    def _incident_canary_path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise ProviderGuardPersistenceError("provider guard key is invalid")
        return self.root / f"{provider}.incident-canary.json"

    def _hold_path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise ProviderGuardPersistenceError("provider guard key is invalid")
        return self.root / f"{provider}.json"

    def _observation_path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise ProviderGuardPersistenceError("provider guard key is invalid")
        return self.root / f"{provider}.check.json"

    def check_readable(self, provider: str) -> None:
        """Validate the key and root for a lock-free advisory read.

        Every state file is replaced by an atomic rename (or unlinked), so a
        reader without the lock sees either the old or the new complete
        document, never a torn write. Reads therefore need no lock; only the
        read-modify-write paths serialize. A missing root simply means no
        state has been written yet.
        """

        if not is_provider_key(provider):
            raise ProviderGuardPersistenceError("provider guard key is invalid")
        if self.root.is_symlink():
            raise ProviderGuardPersistenceError("provider guard root is invalid")

    def _ensure_root(self) -> None:
        try:
            if self.root.is_symlink():
                raise ProviderGuardPersistenceError("provider guard root is invalid")
            existed = self.root.exists()
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not self.root.is_dir():
                raise ProviderGuardPersistenceError("provider guard root is invalid")
            os.chmod(self.root, 0o700)
            if not existed:
                _fsync_directory(self.root.parent)
        except OSError as error:
            raise ProviderGuardPersistenceError(
                "provider guard root is unavailable"
            ) from error


class ProviderGuard:
    """Run at most one scheduled check and durably contain unsafe outcomes."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        store: ProviderGuardStore,
    ) -> None:
        self._registry = registry
        self._store = store

    def peek(self, provider: str) -> ProviderHold | None:
        """Report the stored hold without running a check or taking the lock.

        The authoritative read still happens under the lock inside :meth:`run`.
        This advisory read serves health, the keeper and recovery, which must
        not report local-state trouble merely because a guarded check (which
        holds the lock for its whole provider round trip) is in flight. Writes
        are atomic renames, so the read sees a complete old or new hold.

        Unreadable local state raises :class:`ProviderGuardPersistenceError`.
        """

        self._registry.get(provider)
        self._store.check_readable(provider)
        return self._store.load_locked(provider)

    def peek_before_check(self, provider: str) -> ProviderHold | None:
        """Report the stored hold under the lock, before a guarded check.

        Only for a caller about to prepare for :meth:`run`: contention and
        unreadable local state both raise
        :class:`ProviderGuardPersistenceError`. Neither is classified here:
        :meth:`run` owns that verdict and reports it as an in-progress check or
        a local repair requirement, so a caller must treat a raised peek as
        "prepare nothing" rather than as an error of its own.
        """

        self._registry.get(provider)
        with self._store.locked(provider):
            return self._store.load_locked(provider)

    def current_hold_health(self, provider: str) -> CurrentHoldHealth | None:
        """Read this user's current hold and cadence without writes or provider I/O.

        Atomic files give complete advisory reads without waiting behind a
        running check. A corrupt cadence must raise, not imply eligibility.
        """
        hold = self.peek(provider)
        if hold is None:
            return None
        state = (
            self._store.load_incident_canary_locked(provider)
            if hold.action is GuardAction.INCIDENT_REVIEW_REQUIRED
            else None
        )
        now = self._store.now()
        return CurrentHoldHealth(
            hold_id=hold.hold_id,
            action=hold.action,
            failure=hold.failure,
            incident_id=hold.incident_id,
            occurred_at=hold.occurred_at,
            last_canary_at=state.last_canary_at if state is not None else None,
            next_eligible_canary_at=(
                _incident_canary_not_before(state, now) or now
                if hold.action is GuardAction.INCIDENT_REVIEW_REQUIRED
                else None
            ),
        )

    def last_check(self, provider: str) -> ProviderCheckObservation | None:
        """Read the last completed guarded canary without provider I/O.

        Lock-free for the same reason as :meth:`peek`.
        """

        self._registry.get(provider)
        self._store.check_readable(provider)
        return self._store.load_observation_locked(provider)

    def incident_canary_due(self, provider: str) -> bool:
        """Whether a scheduled canary would contact the provider right now.

        Advisory, like :meth:`peek`: the authoritative gate runs under the
        lock inside :meth:`run_incident_review_canary`. This read only lets
        an hourly scheduler skip browser preparation for the 23 invocations
        a day the canary will suppress anyway. Unreadable state reads as due,
        so the real path — which fails closed before any provider contact —
        owns that verdict.
        """

        return self.incident_canary_due_at(provider) is None

    def incident_canary_due_at(self, provider: str) -> datetime | None:
        """When the next incident-review canary is permitted; None if now.

        The same advisory read as :meth:`incident_canary_due`, projected to a
        time so recovery can wait for the one event that could clear an
        incident hold instead of polling it. Unreadable state reads as due.
        """

        self._registry.get(provider)
        try:
            self._store.check_readable(provider)
            now = self._store.now()
            state = self._store.load_incident_canary_locked(provider)
        except ProviderGuardPersistenceError:
            return None
        return _incident_canary_not_before(state, now)

    def run(
        self,
        provider: str,
        check_provider: Callable[[], ProviderCheckResult],
    ) -> GuardResult:
        selected_provider = self._registry.get(provider)
        seen: list[ProviderCheckResult] = []
        try:
            with self._store.locked(provider):
                existing = self._store.load_locked(provider)
                if existing is not None:
                    return _held_result(existing)
                return self._check_and_classify_locked(
                    provider,
                    selected_provider,
                    check_provider,
                    seen,
                )
        except ProviderGuardBusyError:
            return GuardResult(
                provider=provider,
                action=GuardAction.CHECK_IN_PROGRESS,
                diagnostic_id=self._store.diagnostic_id,
            )
        except ProviderGuardPersistenceError:
            return _local_failure(
                provider,
                check=(seen[0] if seen and seen[0].provider == provider else None),
                diagnostic_id=self._store.diagnostic_id,
            )

    def run_incident_review_canary(
        self,
        provider: str,
        check_provider: Callable[[], ProviderCheckResult],
    ) -> GuardResult:
        """One bounded canary under an incident-review hold (R9).

        Scheduled surfaces call this instead of :meth:`run`; on-demand checks
        keep the held short-circuit, so the enforcement point itself never
        loosens. Unheld providers get the ordinary guarded check. Any other
        hold class returns its held result untouched.

        The canary self-bounds in the store: at most one per provider per
        24h, and none within 24h of an auto-clear — a provider that flapped
        back under hold inside the window stays held for review. Only a FULL
        check clears (invariant 5); the incident capsule is retained either
        way. A failed canary leaves the hold in place and its evidence in
        the observation.
        """

        selected_provider = self._registry.get(provider)
        seen: list[ProviderCheckResult] = []
        try:
            with self._store.locked(provider):
                existing = self._store.load_locked(provider)
                if existing is None:
                    return self._check_and_classify_locked(
                        provider,
                        selected_provider,
                        check_provider,
                        seen,
                    )
                if existing.action is not GuardAction.INCIDENT_REVIEW_REQUIRED:
                    return _held_result(existing)
                now = self._store.now()
                state = self._store.load_incident_canary_locked(provider)
                if state is not None and (
                    _within_canary_interval(state.last_canary_at, now)
                    or _within_canary_interval(state.last_auto_clear_at, now)
                ):
                    return _held_result(existing)
                # The canary budget is recorded before dispatch, never after
                # — the same doctrine as the credential budget. A check that
                # crashes mid-flight still contacted the provider, and an
                # unconsumed budget would retry into the hold on the next
                # cycle.
                self._store.write_incident_canary_locked(
                    provider=provider,
                    state=IncidentCanaryState(
                        provider=provider,
                        last_canary_at=now,
                        last_auto_clear_at=(
                            state.last_auto_clear_at if state else None
                        ),
                    ),
                )
                check = check_provider()
                seen.append(check)
                if check.provider != provider:
                    raise ProviderGuardPersistenceError(
                        "provider guard check returned another provider"
                    )
                if check.defense_observation != "suppressed":
                    self._store.write_observation_locked(
                        provider=provider,
                        check=check,
                    )
                if check.ok:
                    self._store.write_incident_canary_locked(
                        provider=provider,
                        state=IncidentCanaryState(
                            provider=provider,
                            last_canary_at=now,
                            last_auto_clear_at=now,
                        ),
                    )
                    self._store.clear_locked(provider)
                    return GuardResult(
                        provider=provider,
                        check=check,
                        action=GuardAction.HEALTHY,
                        diagnostic_id=self._store.diagnostic_id,
                    )
                if check.failure in _SESSION_EVIDENCE_FAILURES:
                    # The canary could not reach the content: the session is
                    # missing or dead. That supersedes the content verdict,
                    # and keeping the incident hold would block the keeper
                    # renewal that is now the remedy — nothing else would
                    # ever clear it. The replacement is the ordinary session
                    # class, which verified renewal clears; FULL content is
                    # still required before the provider reads healthy.
                    return self._write_hold_locked(provider, selected_provider, check)
                return _held_result(existing)
        except ProviderGuardBusyError:
            return GuardResult(
                provider=provider,
                action=GuardAction.CHECK_IN_PROGRESS,
                diagnostic_id=self._store.diagnostic_id,
            )
        except ProviderGuardPersistenceError:
            return _local_failure(
                provider,
                check=(seen[0] if seen and seen[0].provider == provider else None),
                diagnostic_id=self._store.diagnostic_id,
            )

    def _check_and_classify_locked(
        self,
        provider: str,
        selected_provider: Provider,
        check_provider: Callable[[], ProviderCheckResult],
        seen: list[ProviderCheckResult],
    ) -> GuardResult:
        check = check_provider()
        seen.append(check)
        if check.provider != provider:
            raise ProviderGuardPersistenceError(
                "provider guard check returned another provider"
            )
        # Suppression is a local scheduling decision, not a new page sample.
        if check.defense_observation != "suppressed":
            self._store.write_observation_locked(
                provider=provider,
                check=check,
            )
        action = self._classify(check)
        if action in _DURABLE_ACTIONS:
            return self._write_hold_locked(provider, selected_provider, check)
        return GuardResult(
            provider=provider,
            check=check,
            action=action,
            diagnostic_id=self._store.diagnostic_id,
        )

    def _write_hold_locked(
        self,
        provider: str,
        selected_provider: Provider,
        check: ProviderCheckResult,
    ) -> GuardResult:
        action = self._classify(check)
        if action not in _DURABLE_ACTIONS:
            raise ProviderGuardPersistenceError("provider guard hold is not durable")
        hold = self._store.write_locked(
            provider=provider,
            action=action,
            check=check,
            session_evidence_required=(
                selected_provider.capabilities.requires_session_for_retrieve
            ),
        )
        return GuardResult(
            provider=provider,
            check=check,
            action=action,
            hold_id=hold.hold_id,
            incident_id=hold.incident_id,
            diagnostic_id=hold.diagnostic_id,
        )

    def session_evidence_target(self, provider: str) -> str | None:
        """Capture the hold a forthcoming verification may supersede."""
        current = self.peek(provider)
        if current is None or current.action not in SESSION_EVIDENCE_ACTIONS:
            return None
        return current.hold_id

    def clear_session_evidence(
        self, provider: str, *, hold_id: str | None
    ) -> ProviderHold | None:
        """Clear a session-evidence hold because new evidence just verified.

        Called only from positive live session-verification events (mint,
        cookie promotion, checkpoint). Those holds name session renewal or
        promotion as their remedy; once a session positively verifies against
        the provider, keeping the hold blocks the keeper forever for a
        ceremony no judgement attends (the 2026-07-25 FT trap). Every other
        hold class — defense, operator, local-state, incident review — is
        untouched: verified session evidence says nothing about those.

        Returns the cleared hold, or None when nothing was cleared. The
        caller captures hold_id before verification starts. Compare-and-clear
        runs under the store lock; a hold created or replaced since that
        capture cannot be cleared by the older verification.
        """

        self._registry.get(provider)
        if hold_id is None:
            return None
        with self._store.locked(provider):
            current = self._store.load_locked(provider)
            if (
                current is None
                or current.hold_id != hold_id
                or current.action not in SESSION_EVIDENCE_ACTIONS
            ):
                return None
            self._store.clear_locked(provider)
        return current

    def acknowledge_and_check(
        self,
        provider: str,
        *,
        hold_id: str,
        check_provider: Callable[[], ProviderCheckResult],
    ) -> AcknowledgementReport:
        """Compare-and-clear one hold, then re-measure the provider once.

        The follow-up runs only after a successful acknowledgement and goes
        through ``run`` so its observation is the same durable evidence the
        health snapshot derives serving state from — an unguarded check would
        contact the provider and still leave health ``unknown``. Exceptions
        from the follow-up are reduced to a closed category rather than
        propagated, because a failed re-measurement must not read as a failed
        acknowledgement.
        """

        acknowledgement = self.acknowledge(provider, hold_id=hold_id)
        if not acknowledgement.acknowledged:
            return AcknowledgementReport(acknowledgement=acknowledgement)
        try:
            follow_up = self.run(provider, check_provider)
        except Exception as error:
            return AcknowledgementReport(
                acknowledgement=acknowledgement,
                follow_up_error=_follow_up_error_code(error),
            )
        return AcknowledgementReport(
            acknowledgement=acknowledgement,
            follow_up=follow_up,
        )

    def acknowledge(
        self,
        provider: str,
        *,
        hold_id: str,
    ) -> GuardAcknowledgement:
        self._registry.get(provider)
        _require_hold_id(hold_id)
        with self._store.locked(provider):
            current = self._store.load_locked(provider)
            if current is None or current.hold_id != hold_id:
                return GuardAcknowledgement(
                    provider=provider,
                    requested_hold_id=hold_id,
                    acknowledged=False,
                    current_hold_id=(current.hold_id if current is not None else None),
                )
            self._store.clear_locked(provider)
        return GuardAcknowledgement(
            provider=provider,
            requested_hold_id=hold_id,
            acknowledged=True,
        )

    def _classify(self, check: ProviderCheckResult) -> GuardAction:
        if check.ok:
            return GuardAction.HEALTHY
        failure = _required_failure(check)
        if failure in {
            ProviderCheckFailure.SEARCH_TRANSPORT,
            ProviderCheckFailure.RETRIEVAL_TRANSPORT,
        }:
            return GuardAction.TRANSIENT_FAILURE
        if failure is ProviderCheckFailure.PROVIDER_DEFENSE:
            # Only current, bounded retrieval containment is recoverable.
            # Legacy/unknown defense results keep the explicit-review brake.
            if check.defense_retry_after_seconds is not None:
                return GuardAction.TRANSIENT_FAILURE
            return GuardAction.PROVIDER_HOLD
        if failure is ProviderCheckFailure.OPERATOR_ACTION:
            return GuardAction.OPERATOR_ACTION
        if failure in {
            ProviderCheckFailure.SESSION_REQUIRED,
            ProviderCheckFailure.SESSION_DEAD,
        }:
            return GuardAction.SESSION_PROMOTION_REQUIRED
        if failure is ProviderCheckFailure.LOCAL_STATE:
            return GuardAction.LOCAL_REPAIR_REQUIRED
        if failure is ProviderCheckFailure.CONTENT_NOT_FULL:
            provider = self._registry.get(check.provider)
            if provider.capabilities.requires_session_for_retrieve:
                # Session-wide evidence names the remediation; waiting for a
                # session to prove itself cannot resolve one that is live but
                # unentitled.
                if check.session_disposition is SessionDisposition.NOT_ENTITLED:
                    return GuardAction.SESSION_PROMOTION_REQUIRED
                if check.session_disposition is not SessionDisposition.VERIFIED:
                    return GuardAction.WAIT_FOR_SESSION_EVIDENCE
        if failure in _INCIDENT_REVIEW_FAILURES:
            # Capture is best effort; a missing capsule must not turn a
            # content/search review (with its daily FULL canary) into an
            # operator hold that nothing but acknowledgement can clear.
            return GuardAction.INCIDENT_REVIEW_REQUIRED
        return GuardAction.OPERATOR_ACTION


def _incident_canary_not_before(
    state: IncidentCanaryState | None, now: datetime
) -> datetime | None:
    if state is None:
        return None
    interval = timedelta(seconds=_INCIDENT_CANARY_INTERVAL_SECONDS)
    pending = [
        marker + interval
        for marker in (state.last_canary_at, state.last_auto_clear_at)
        if marker is not None and _within_canary_interval(marker, now)
    ]
    return max(pending) if pending else None


def _within_canary_interval(marker: datetime | None, now: datetime) -> bool:
    if marker is None:
        return False
    elapsed = (now - marker).total_seconds()
    # A marker from the future is clock skew, not a fresh canary. Honoring it
    # would suppress the canary until the wall clock caught up — potentially
    # forever after one bad write — so it fails open instead: the cost is one
    # extra bounded canary after a backwards clock step, not a stuck hold.
    return 0 <= elapsed < _INCIDENT_CANARY_INTERVAL_SECONDS


def _follow_up_error_code(error: BaseException) -> str:
    """Reduce a follow-up failure to a closed category, never free text.

    The fallback also guards the report itself: this code is assigned inside
    an except block, and a category value that violated the field pattern
    would otherwise raise mid-recovery — after the hold is already cleared
    on disk.
    """

    from .results import classify_error

    mapped = classify_error(error)
    if mapped is None:
        return "follow_up_check_failed"
    category, _exit_code = mapped
    if re.fullmatch(_FOLLOW_UP_ERROR_PATTERN, category.value) is None:
        return "follow_up_check_failed"
    return category.value


def _held_result(hold: ProviderHold) -> GuardResult:
    return GuardResult(
        provider=hold.provider,
        check=ProviderCheckResult(
            provider=hold.provider,
            ok=False,
            failure=hold.failure,
            incident_id=hold.incident_id,
            session_disposition=hold.session_disposition,
        ),
        action=hold.action,
        hold_id=hold.hold_id,
        incident_id=hold.incident_id,
        diagnostic_id=hold.diagnostic_id,
    )


def _local_failure(
    provider: str,
    *,
    check: ProviderCheckResult | None = None,
    diagnostic_id: str | None = None,
) -> GuardResult:
    return GuardResult(
        provider=provider,
        check=(
            check
            or ProviderCheckResult(
                provider=provider,
                ok=False,
                failure=ProviderCheckFailure.LOCAL_STATE,
            )
        ),
        action=GuardAction.LOCAL_REPAIR_REQUIRED,
        diagnostic_id=diagnostic_id,
    )


def _required_failure(check: ProviderCheckResult) -> ProviderCheckFailure:
    if check.failure is None:
        raise ProviderGuardPersistenceError("provider guard failure is incomplete")
    return check.failure


def _require_hold_id(value: str) -> None:
    if (
        len(value) != len("guard-") + 32
        or not value.startswith("guard-")
        or any(character not in "0123456789abcdef" for character in value[6:])
    ):
        raise ValueError("provider guard hold identifier is invalid")


def _valid_diagnostic_id(value: str) -> bool:
    return (
        1 <= len(value) <= 128
        and value[0] in "abcdefghijklmnopqrstuvwxyz0123456789"
        and all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789._-"
            for character in value
        )
    )


def _read_bounded_hold(path: Path) -> bytes:
    return _read_bounded(path, max_bytes=_MAX_HOLD_BYTES)


def _read_bounded(path: Path, *, max_bytes: int) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise OSError("provider guard state is invalid")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise OSError("provider guard state is invalid")
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_private_write(path: Path, payload: bytes) -> None:
    """Write one hold durably, reporting failure in this module's terms."""

    try:
        atomic_private_write(path, payload)
    except PrivateStateError as error:
        raise ProviderGuardPersistenceError("provider guard hold write failed") from (
            error
        )


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)
