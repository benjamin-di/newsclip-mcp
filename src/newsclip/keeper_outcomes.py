"""Durable per-provider keeper outcomes, and the health they imply.

`session_status` used to answer "when did verification last succeed" and
nothing else, so a session whose renewals had failed hourly for days still
read as ``verified``. Consumers trusted that word and spent real retrieval
attempts against dead sessions (the 2026-07-28 Bloomberg audit finding).

The keeper is the one actor that knows renewal reality, but it runs in a
different process from the readers, so its last outcome — and the renewal
policy that gives "stale" a definition — must be persisted where readers can
see them. The derivation itself is a pure function so its edges are testable
without a filesystem.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, ValidationError, model_validator

from .acquisition import (
    MintFailureCategory,
    MintFailureEvidence,
    MintFailureStage,
)
from .errors import PersistenceError
from .incidents import IncidentPersistenceError, incident_retention_lock
from .models import (
    FrozenModel,
    SessionHealth,
    SessionHealthState,
    SessionStatus,
)
from .private_state import (
    PrivateStateError,
    atomic_private_write,
    exclusive_lock,
)
from .provider_keys import PROVIDER_KEY_PATTERN, is_provider_key

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from .session_keeper import KeeperResult

_MAX_OUTCOME_BYTES = 16 * 1024
_LOCK_TIMEOUT_SECONDS = 5.0

#: Renewal-failure streak at which a still-"verified" session is reported as
#: degraded. One failure is often transient; three consecutive scheduled
#: failures means the renewal path itself is broken.
DEGRADED_FAILURE_STREAK = 3

#: Fallback renewal policy when no keeper outcome has ever been recorded.
#: Matches the keeper's own default ``max_age_hours``.
DEFAULT_MAX_AGE_HOURS = 12.0

#: A verified session this many renewal periods past its policy age is
#: degraded even without observed failures: the keeper has evidently not
#: been able to renew it for several consecutive windows.
_DEGRADED_AGE_FACTOR = 4.0

#: The reason a probe that completed but could not prove entitlement
#: reports. Shared with the keeper so both sides agree on one token.
PAID_PROBE_INCONCLUSIVE = MintFailureEvidence(
    stage=MintFailureStage.PAID_PROBE,
    category=MintFailureCategory.INCONCLUSIVE,
).reason_code

#: How long one spent escalation canary suppresses the next. A hard
#: wall-clock bound, deliberately not reset by a successful renewal: the
#: canary exists to absorb a transient probe flake, and a session flapping
#: through several latches in one day is a fact a person should see.
_ESCALATION_CANARY_WINDOW = timedelta(hours=24)

#: Keeper actions that mean renewal worked (streak resets).
_RESET_ACTIONS = frozenset({"renewed"})
#: The one action that advances the failure streak.
_FAILURE_ACTION = "renewal_failed"
#: Actions whose reason explains why the session cannot self-renew.
_ERROR_ACTIONS = frozenset({"renewal_failed", "operator_action_required"})


class RenewalDecision(StrEnum):
    VERIFIED = "verified"
    UNRESOLVED = "unresolved"
    SUPERSEDED = "superseded"


class KeeperOutcome(FrozenModel):
    """The keeper's most recent verdict for one provider, plus its policy."""

    schema_version: Literal[1, 2, 3] = 3
    provider: str = Field(pattern=PROVIDER_KEY_PATTERN)
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    reason_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    credential_attempt: bool = False
    recorded_at: datetime
    consecutive_renewal_failures: int = Field(default=0, ge=0)
    #: Renewals that specifically could not prove entitlement. Counted apart
    #: from the general streak because the remedies differ: a run of these
    #: means the session is unentitled and needs promoting, while transport
    #: failures mean the route is unhealthy. Observed live on 2026-07-28,
    #: Bloomberg alternates between the two, so a check on the *latest* reason
    #: alone never accumulates. An unrelated failure preserves this count
    #: rather than resetting it; only a successful renewal clears it.
    consecutive_inconclusive: int = Field(default=0, ge=0)
    #: When the latched escalation last spent its one contradicting-evidence
    #: canary (the guarded check that may let a renewal through the latch).
    #: Budget state, not verdict state: preserved through every outcome so a
    #: crash mid-canary, or the renewal it admits, cannot refund the spend —
    #: the same doctrine as the credential budget.
    last_escalation_canary_at: datetime | None = None
    max_age_hours: float = Field(gt=0)
    incident_id: str | None = Field(default=None, pattern=r"^incident-[0-9a-f]{24}$")
    diagnostic_id: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$"
    )
    renewal_reason_code: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    observation_revision: int = Field(default=0, ge=0)
    applied_revision: int = Field(default=0, ge=0)
    # Positive proof is independent of the latest presentation action. Older
    # files default to no proof; never infer it from a CHECKED article result.
    verified_revision: int = Field(default=0, ge=0)
    # A verification watermark must survive even before the first keeper run.
    # It must not invent a keeper policy on a workstation that runs no keeper.
    keeper_observed: bool = True

    @model_validator(mode="after")
    def ordered_revisions(self) -> KeeperOutcome:
        if self.applied_revision > self.observation_revision:
            raise ValueError("applied renewal observation was never issued")
        if self.verified_revision > self.applied_revision:
            raise ValueError("verified renewal observation was never applied")
        return self

    def renewal_decision(self, revision: int) -> RenewalDecision:
        if (
            self.verified_revision >= revision
            and self.verified_revision == self.applied_revision
            and self.applied_revision == self.observation_revision
        ):
            return RenewalDecision.VERIFIED
        if self.applied_revision > revision:
            return RenewalDecision.SUPERSEDED
        return RenewalDecision.UNRESOLVED

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class KeeperOutcomeStore:
    """One durable outcome file per provider, updated read-modify-write.

    Shares the session-keeper state directory but never its budget files:
    outcomes are ``<provider>.outcome.json``, budgets ``<provider>.json``.
    The failure streak is computed under the same exclusive lock that writes
    it, so two concurrent keep invocations cannot both extend one streak from
    the same prior value.
    """

    def __init__(
        self,
        root: Path,
        *,
        utc_now: Callable[[], datetime] | None = None,
        lock_timeout_seconds: float = _LOCK_TIMEOUT_SECONDS,
        incident_root: Path | None = None,
    ) -> None:
        self.root = root
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self._lock_timeout_seconds = lock_timeout_seconds
        self._incident_root = incident_root

    def _watermark(self, provider: str) -> KeeperOutcome:
        return KeeperOutcome(
            provider=provider,
            action="idle",
            recorded_at=self._utc_now(),
            max_age_hours=DEFAULT_MAX_AGE_HOURS,
            keeper_observed=False,
        )

    def issue_observation(self, provider: str) -> int:
        """Order an observation before its authority lock is released."""
        with self._locked(provider):
            prior = self._load_unlocked(provider) or self._watermark(provider)
            revision = prior.observation_revision + 1
            self._write(
                prior.model_copy(
                    update={
                        "schema_version": 3,
                        "observation_revision": revision,
                    }
                )
            )
            return revision

    def _write(self, outcome: KeeperOutcome) -> None:
        try:
            atomic_private_write(
                self._path(outcome.provider), outcome.model_dump_json().encode()
            )
        except PrivateStateError as error:
            raise PersistenceError("keeper outcome write failed") from error

    def verified(self, provider: str, *, revision: int | None = None) -> bool:
        """Clear failure history only from a positive live verification event."""
        with self._locked(provider):
            prior = self._load_unlocked(provider) or self._watermark(provider)
            if revision is not None and revision > prior.observation_revision:
                raise PersistenceError(
                    "renewal verification observation was not issued"
                )
            revision = (
                revision if revision is not None else prior.observation_revision + 1
            )
            if (
                revision < prior.observation_revision
                or revision <= prior.applied_revision
            ):
                return False
            outcome = prior.model_copy(
                update={
                    "action": "checked",
                    "reason_code": None,
                    "credential_attempt": False,
                    "recorded_at": self._utc_now(),
                    "consecutive_renewal_failures": 0,
                    "consecutive_inconclusive": 0,
                    "incident_id": None,
                    "diagnostic_id": None,
                    "renewal_reason_code": None,
                    "schema_version": 3,
                    "observation_revision": revision,
                    "applied_revision": revision,
                    "verified_revision": revision,
                }
            )
            self._write(outcome)
            return True

    @contextmanager
    def _evidence_scope(self, provider: str, incident_id: str | None) -> Iterator[None]:
        if self._incident_root is None or incident_id is None:
            yield
            return
        try:
            # A diagnostic reference does not grant authority. Preserve the
            # observed verdict even when its capture is missing or corrupt.
            # Exclude pruning while publishing a reference to existing evidence.
            with incident_retention_lock(self._incident_root, provider):
                yield
        except (IncidentPersistenceError, PrivateStateError) as error:
            raise PersistenceError(
                "keeper renewal evidence lock is unavailable"
            ) from error

    def record(self, result: KeeperResult, *, max_age_hours: float) -> KeeperOutcome:
        provider = result.provider
        with self._evidence_scope(provider, result.incident_id), self._locked(provider):
            prior = self._load_unlocked(provider)
            issued = prior.observation_revision if prior else 0
            applied = prior.applied_revision if prior else 0
            revision = result.renewal_revision
            if revision is not None and revision > issued:
                raise PersistenceError("renewal outcome observation was not issued")
            renewal_event = result.action.value in {*_RESET_ACTIONS, *_ERROR_ACTIONS}
            if renewal_event and revision is None:
                revision = issued + 1
            if (
                revision is not None
                and prior is not None
                and (
                    revision <= applied
                    or (result.action.value in _RESET_ACTIONS and revision < issued)
                )
            ):
                # A service verification already applied this success, or a
                # newer observation superseded this delayed/replayed result.
                updated = prior.model_copy(
                    update={
                        "schema_version": 3,
                        "keeper_observed": True,
                        "max_age_hours": max_age_hours,
                    }
                )
                self._write(updated)
                return updated
            streak = prior.consecutive_renewal_failures if prior else 0
            verified_revision = prior.verified_revision if prior else 0
            inconclusive = prior.consecutive_inconclusive if prior else 0
            renewal_reason = (
                prior.renewal_reason_code
                or (prior.reason_code if prior.action in _ERROR_ACTIONS else None)
                if prior
                else None
            )
            incident_id = result.incident_id or (prior.incident_id if prior else None)
            diagnostic_id = (
                result.diagnostic_id
                if result.incident_id
                else prior.diagnostic_id
                if prior
                else None
            )
            if (
                result.action.value in _RESET_ACTIONS
                and result.status is SessionStatus.VERIFIED
            ):
                streak = 0
                inconclusive = 0
                incident_id = None
                diagnostic_id = None
                renewal_reason = None
                verified_revision = revision or 0
            elif result.action.value == _FAILURE_ACTION:
                streak += 1
                renewal_reason = result.reason_code
                if result.reason_code == PAID_PROBE_INCONCLUSIVE:
                    inconclusive += 1
            elif result.action.value == "operator_action_required":
                renewal_reason = result.reason_code
            outcome = KeeperOutcome(
                provider=provider,
                action=result.action.value,
                reason_code=result.reason_code,
                credential_attempt=result.credential_attempt,
                recorded_at=self._utc_now(),
                consecutive_renewal_failures=streak,
                consecutive_inconclusive=inconclusive,
                last_escalation_canary_at=(
                    prior.last_escalation_canary_at if prior else None
                ),
                max_age_hours=max_age_hours,
                incident_id=incident_id,
                diagnostic_id=diagnostic_id,
                renewal_reason_code=renewal_reason,
                observation_revision=max(issued, revision or 0),
                applied_revision=max(applied, revision or 0),
                verified_revision=verified_revision,
                keeper_observed=True,
            )
            payload = json.dumps(
                outcome.model_dump(mode="json"), sort_keys=True
            ).encode()
            try:
                atomic_private_write(self._path(provider), payload)
            except PrivateStateError as error:
                raise PersistenceError("keeper outcome write failed") from error
        return outcome

    def load(self, provider: str) -> KeeperOutcome | None:
        with self._locked(provider):
            return self._load_unlocked(provider)

    def spend_escalation_canary(self, provider: str) -> bool:
        """Claim the latched escalation's one daily canary, atomically.

        True means the caller may run one guarded check right now; the spend
        is recorded before any dispatch, under the same lock that decides it,
        so two keepers cannot both observe an unspent window (the credential
        budget's doctrine). False means the window is already spent — or no
        outcome exists, which cannot happen behind a real streak and fails
        closed rather than minting budget state from nothing.
        """

        with self._locked(provider):
            prior = self._load_unlocked(provider)
            if prior is None or not prior.keeper_observed:
                return False
            now = self._utc_now()
            spent_at = prior.last_escalation_canary_at
            # A spend stamped in the future is clock skew, not a fresh
            # canary: honoring it would latch the escalation until the wall
            # clock caught up. It fails open (the provider guard's canary
            # doctrine) — one extra bounded check, never a stuck latch.
            if (
                spent_at is not None
                and timedelta(0) <= now - spent_at < _ESCALATION_CANARY_WINDOW
            ):
                return False
            updated = prior.model_copy(
                update={"last_escalation_canary_at": now, "schema_version": 3}
            )
            payload = json.dumps(
                updated.model_dump(mode="json"), sort_keys=True
            ).encode()
            try:
                atomic_private_write(self._path(provider), payload)
            except PrivateStateError as error:
                raise PersistenceError("keeper outcome write failed") from error
            return True

    @contextmanager
    def _locked(self, provider: str) -> Iterator[None]:
        try:
            with exclusive_lock(
                self._path(provider).with_suffix(".lock"),
                timeout_seconds=self._lock_timeout_seconds,
            ):
                yield
        except PrivateStateError as error:
            raise PersistenceError("keeper outcome store is unavailable") from error

    def _path(self, provider: str) -> Path:
        if not is_provider_key(provider):
            raise PersistenceError("keeper outcome provider key is invalid")
        return self.root / f"{provider}.outcome.json"

    def _load_unlocked(self, provider: str) -> KeeperOutcome | None:
        path = self._path(provider)
        if path.is_symlink():
            raise PersistenceError("keeper outcome must be a regular file")
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PersistenceError("keeper outcome is unreadable") from error
        if len(raw) > _MAX_OUTCOME_BYTES:
            raise PersistenceError("keeper outcome is oversized")
        try:
            outcome = KeeperOutcome.model_validate(json.loads(raw))
            if outcome.provider != provider:
                raise ValueError("keeper outcome provider mismatch")
            return outcome
        except (ValueError, ValidationError) as error:
            raise PersistenceError("keeper outcome is malformed") from error


def enrich_session_health(
    health: SessionHealth,
    outcome: KeeperOutcome | None,
    *,
    now: datetime,
) -> SessionHealth:
    """Return ``health`` with derived freshness fields populated.

    The derivation is deliberately conservative: a session only reads
    ``fresh`` when it is positively verified within its renewal policy age.
    Anything the keeper cannot currently prove healthy — non-verified status,
    an unverifiable age, a renewal-failure streak, or an age several renewal
    windows deep — reads ``degraded`` so consumers route around it instead of
    trusting a stale "verified".

    Age alone only means "degraded" where something was supposed to renew it.
    The deep-age rule says "the keeper has evidently not managed to renew this
    for several windows", which presupposes a keeper. On a host that runs none
    — a workstation using the CLI directly — there is no outcome history, and
    an old session is simply overdue, not failing: a laptop Bloomberg session
    last verified six days earlier still returned a full article while being
    reported ``degraded``. Without keeper evidence the deep-age rule is
    therefore skipped, and age can raise ``stale`` but never ``degraded``.
    """

    max_age_hours = outcome.max_age_hours if outcome else DEFAULT_MAX_AGE_HOURS
    failures = outcome.consecutive_renewal_failures if outcome else 0
    last_renewal_error = (
        outcome.renewal_reason_code
        or (outcome.reason_code if outcome.action in _ERROR_ACTIONS else None)
        if outcome is not None
        else None
    )

    age_seconds: float | None = None
    if health.last_verified_at is not None:
        age_seconds = max(0.0, (now - health.last_verified_at).total_seconds())

    deeply_stale = (
        outcome is not None
        and outcome.keeper_observed
        and age_seconds is not None
        and age_seconds > _DEGRADED_AGE_FACTOR * max_age_hours * 3600.0
    )
    if (
        health.status is not SessionStatus.VERIFIED
        or age_seconds is None
        or failures >= DEGRADED_FAILURE_STREAK
        or deeply_stale
    ):
        state = SessionHealthState.DEGRADED
    elif age_seconds > max_age_hours * 3600.0:
        state = SessionHealthState.STALE
    else:
        state = SessionHealthState.FRESH

    return health.model_copy(
        update={
            "verified_age_seconds": age_seconds,
            "consecutive_renewal_failures": failures,
            "last_renewal_error": last_renewal_error,
            "renewal_incident_id": outcome.incident_id if outcome else None,
            "renewal_diagnostic_id": outcome.diagnostic_id if outcome else None,
            "health": state,
        }
    )


__all__ = [
    "DEFAULT_MAX_AGE_HOURS",
    "DEGRADED_FAILURE_STREAK",
    "KeeperOutcome",
    "KeeperOutcomeStore",
    "enrich_session_health",
]
